# afterbloom — context for future sessions

This document brings a new Claude session up to speed on what afterbloom is, why
it was built the way it was, and where the rough edges are. Read the code for
ground truth — this file is orientation, not API reference.

## Origin

The user evaluated [route96](https://github.com/v0l/route96) (a full-featured
Rust Blossom server) for a single use case: **a Blossom server that
auto-deletes uploaded blobs after 24 hours.**

Findings from that evaluation:

- route96 *does* support this natively (`delete_after_days: 1` in config.yaml,
  background sweeper at `src/background/file_deleter.rs`).
- But route96 is ~7,500 lines, requires MySQL/MariaDB, and ~70% is features
  the user doesn't need (NIP-96, Lightning payments, AI moderation, admin UI,
  image processing, content reporting).
- The MySQL requirement is a **choice, not a technical necessity** — sqlx is
  pinned to `mysql` features and `db.rs` uses MySQL-specific syntax
  (`INSERT IGNORE`, `ON DUPLICATE KEY UPDATE`, backticks).

Decision: build a minimal alternative focused on transient storage. The key
insight that made this small: **for an ephemeral-only server, you don't need a
database at all** — filesystem mtime is the expiration clock.

## What it is

A minimal [Blossom](https://github.com/hzrd149/blossom) server. Specifically:

- **BUD-01**: `GET /<sha256>`, `HEAD /<sha256>` (with HTTP Range support)
- **BUD-02**: `PUT /upload`, `DELETE /<sha256>`. `GET /list/<pubkey>` is
  intentionally **not** implemented (see "No public list endpoint" below).
- Nostr auth (kind `24242`) required for upload and delete. GET/HEAD are
  unauthenticated.

No database. No payments. No moderation. No image processing. ~1,000 LOC of
Rust.

## Design decisions and rationale

### Auth: required, any pubkey allowed

The user wanted permissionless uploads (any Nostr pubkey can upload) but not
truly anonymous — auth makes rate-limiting attribution possible and gates
delete. Spam from rotating keys is contained by the per-IP rate limiter.

### Storage: filesystem only, first-uploader-wins

```
data/
├── blobs/<sha256>           # actual file (mtime = expiration clock)
├── owners/<sha256>          # sidecar file containing the owner pubkey
└── tmp/                     # atomic-write staging
```

Single owner per blob. The first pubkey to upload a given hash becomes its
sole owner; subsequent uploads by other pubkeys return the existing descriptor
but create no claim and do **not** touch mtime (see "Why first-uploader-wins"
below). Only the owner can DELETE, and DELETE removes blob + sidecar
unconditionally and eagerly — no refcount to check.

### Why first-uploader-wins

GET is unauthenticated, so anyone can download any blob. Two attacks fall out
of a more permissive ownership model:

1. **TTL hijacking.** If re-uploading refreshes mtime regardless of who uploads,
   any third party can pin someone else's content indefinitely by re-uploading
   it every TTL-minus-epsilon. First-uploader-wins makes the mtime refresh only
   work for the owner.
2. **Recall denial.** If re-uploading grants co-ownership, a third party who
   downloaded then re-uploaded blocks the original uploader from forcing a
   delete (their symlink keeps the refcount > 0 until TTL). First-uploader-wins
   gives one party exclusive recall authority.

Trade-off: if two genuinely independent parties happen to upload the same
content, only the first gets a claim. For ephemeral storage of content-
addressed data this is fine — they uploaded the same bytes, the server has
one copy, and the "second" upload is semantically a no-op confirming the
content is already there.

### No public list endpoint

The Blossom spec defines `GET /list/<pubkey>` but afterbloom doesn't implement
it. For a 24h ephemeral server there's little point in advertising "here's
what pubkey X uploaded today" — everything is gone tomorrow. It would also
require a secondary index (pubkey → blobs), which the current sidecar layout
deliberately avoids. If you ever want LIST back, the simplest add is to walk
`owners/` and group by sidecar contents — or switch to a sqlite index.

### Why `mtime` and not a separate `expires_at`

For transient storage, "TTL since last touch" is the natural semantic. A
re-upload of an existing blob *by its owner* refreshes its mtime — this is
intentional "keep-alive by re-upload" behavior. Re-uploads by non-owners do
not touch mtime (see first-uploader-wins above). If you ever need fixed-
creation-time expiration, switch to reading creation time (e.g. via xattrs
or ctime) instead.

### Web framework: axum

Chosen over raw hyper because axum *is* hyper plus a router — for 5 routes
with method dispatch, path params, body limits, and middleware (CORS, tracing),
axum's source is shorter than the raw-hyper equivalent. Real cost is compile
time and ~30 extra crates, not runtime overhead.

If compile time ever becomes painful, swap to raw hyper is mechanical: handlers
stay almost identical, only `main.rs` dispatch needs hand-rolling.

### Cryptography: `secp256k1` 0.30 directly (no `nostr` crate)

The auth verifier is ~150 LOC and only needs:

- NIP-01 canonical event ID (sha256 of `[0, pubkey, created_at, kind, tags, content]`)
- BIP-340 schnorr verification

Pulling in the `nostr` crate would add a lot for very little benefit. **Note:**
the `schnorr` cargo feature on `secp256k1` was removed in 0.30+ — schnorr is
always built in. Don't add `features = ["schnorr"]`, it will fail to resolve.

## Architecture

```
src/
├── main.rs         # axum wiring, CLI args, CORS, body limit
├── config.rs       # TOML config loader (serde_derive)
├── state.rs        # AppState { cfg, storage, ratelimit }
├── auth.rs         # Nostr BUD-01: parse Authorization header, verify
│                   #   schnorr sig, check kind/expiration/action tags
├── storage.rs      # Storage::{put, get_path, stat, remove, sweep};
│                   #   owner sidecar files at owners/<sha256>
├── ratelimit.rs    # per-IP token bucket + per-IP byte budget
├── sweep.rs        # background task: storage.sweep() every interval
├── routes.rs       # all HTTP handlers
└── bin/mkauth.rs   # CLI helper that generates real Nostr auth events
                    #   for smoke testing with curl
```

## Key behaviors and gotchas

- **Owner re-upload extends TTL.** The owner re-uploading the same blob
  touches mtime. This is the documented "keep-alive" mechanism. Owners
  wanting deterministic expiry should not re-upload.
- **Non-owner re-uploads are no-ops.** A second pubkey uploading the same
  hash gets a successful response with the existing descriptor, but the
  server does not create any claim for them and does not refresh mtime.
- **DELETE is eager and exclusive.** Only the owner pubkey can delete; the
  blob and its owner sidecar are unlinked immediately. 403 if a non-owner
  tries; 404 if the blob doesn't exist.
- **Range requests** are supported for single ranges on GET and HEAD:
  `bytes=N-M`, `bytes=N-`, and suffix `bytes=-N`. Invalid/out-of-range
  returns 416 with `Content-Range: bytes */<size>`. Multi-range
  (`bytes=0-9,20-29`) is treated as unsupported and falls back to a full
  200 response — allowed by RFC 9110. See `parse_range` in `routes.rs`.
- **Auth event lifetime cap.** `max_auth_lifetime_seconds` (default 1h) caps
  how far in the future the auth event's `expiration` tag may be — prevents
  effectively-infinite tokens.
- **Rate limit GC is coarse.** In-memory map clears entries idle for 2h.
  For a public server you may want a real LRU.

## Smoke testing

The `mkauth` binary is a Nostr auth event generator for shell-based testing:

```sh
# Start server
cargo run -- --config config.toml &

# Compute payload hash, generate upload auth, PUT it
HASH=$(sha256sum payload.bin | cut -d' ' -f1)
SK=$(openssl rand -hex 32)
AUTH=$(./target/debug/mkauth $SK upload $HASH 2>/dev/null)
curl -X PUT http://127.0.0.1:8765/upload \
  -H "Authorization: $AUTH" \
  --data-binary "@payload.bin"

# Delete auth events must include the hash as an x tag.
AUTH=$(./target/debug/mkauth $SK delete $HASH 2>/dev/null)
curl -X DELETE http://127.0.0.1:8765/$HASH -H "Authorization: $AUTH"
```

`mkauth` prints the generated `sk`, `pub`, and full event JSON to stderr; the
base64 `Nostr <...>` header value goes to stdout.

Smoke flows validated end-to-end:
- upload → get → head → range get → wrong-action-rejected → owner delete →
  re-upload → wait for sweeper → 404
- two-pubkey scenario: alice upload → mallory upload (no claim, same mtime)
  → mallory delete (403) → alice delete (200, blob + sidecar gone)

## Config reference

`config.example.toml` documents every knob. Key ones:

- `ttl_seconds` — blob lifetime (default 86400 = 24h)
- `sweep_interval_seconds` — how often the sweeper runs (default 300)
- `max_upload_bytes` — per-request size cap, also enforced via `DefaultBodyLimit`
- `max_auth_lifetime_seconds` — how far future the auth `expiration` tag may be
- `[ratelimit]` — per-IP `uploads_burst`, `uploads_refill_per_minute`,
  `bytes_per_hour`

## Possible future work (not requested, just noted)

- LRU rate limit table
- Persistent rate-limit state across restarts
- BUD-04 mirror endpoint
- BUD-08 media metadata endpoint
- Optional auth on GET (per-blob private mode)
