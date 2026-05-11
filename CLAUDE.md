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

- **BUD-01**: `GET /<sha256>`, `HEAD /<sha256>`
- **BUD-02**: `PUT /upload`, `DELETE /<sha256>`, `GET /list/<pubkey>`
- Nostr auth (kind `24242`) required for upload, delete, list. GET/HEAD are
  unauthenticated.

No database. No payments. No moderation. No image processing. ~1,000 LOC of
Rust.

## Design decisions and rationale

### Auth: required, any pubkey allowed

The user wanted permissionless uploads (any Nostr pubkey can upload) but not
truly anonymous — auth makes rate-limiting attribution possible and lets the
delete/list endpoints work. Spam from rotating keys is contained by the per-IP
rate limiter.

### Storage: filesystem only, with symlinks for ownership

```
data/
├── blobs/<sha256>           # actual file (mtime = expiration clock)
├── owners/<pubkey>/<sha256> # symlink → ../../blobs/<sha256>
└── tmp/                     # atomic-write staging
```

The user explicitly approved "subdirs with symlinks" for the list endpoint
when asked. Rationale: list-by-pubkey becomes a `readdir` of
`owners/<pubkey>/` with no extra index. Multiple owners can hold the same
blob (Blossom is content-addressed) — the blob lives until the sweeper finds
it stale.

### Why `mtime` and not a separate `expires_at`

For transient storage, "TTL since last touch" is the natural semantic. A
re-upload of an existing blob refreshes its mtime — this is intentional
"keep-alive by re-upload" behavior. If you ever need fixed-creation-time
expiration, switch to reading creation time (e.g. via xattrs or ctime) instead.

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
├── storage.rs      # Storage::{put, get_path, stat, remove_owner,
│                   #   list_for_owner, sweep}; symlink management
├── ratelimit.rs    # per-IP token bucket + per-IP byte budget
├── sweep.rs        # background task: storage.sweep() every interval
├── routes.rs       # all HTTP handlers
└── bin/mkauth.rs   # CLI helper that generates real Nostr auth events
                    #   for smoke testing with curl
```

## Key behaviors and gotchas

- **Re-upload extends TTL.** Uploading the same blob touches mtime. This is
  the documented "keep-alive" mechanism. Users wanting deterministic expiry
  should not re-upload.
- **DELETE removes only the caller's symlink.** The actual blob persists
  until the sweeper detects no remaining symlinks AND it's stale. This means
  a DELETE with no other owners doesn't immediately free disk — it's lazy.
- **List requires same-pubkey auth.** The Blossom spec is ambiguous on
  whether `GET /list/<pubkey>` requires auth from that pubkey. afterbloom
  enforces it. Loosen in `routes.rs::list_owner` if public discoverability
  is wanted.
- **No range request support.** `accept-ranges: bytes` is advertised but the
  GET handler streams the whole file. Add `tower-http`'s `ServeFile` if
  needed.
- **Auth event lifetime cap.** `max_auth_lifetime_seconds` (default 1h) caps
  how far in the future the auth event's `expiration` tag may be — prevents
  effectively-infinite tokens.
- **Rate limit GC is coarse.** In-memory map clears entries idle for 2h.
  For a public server you may want a real LRU.
- **Linux-only.** `storage::symlink` is gated `#[cfg(unix)]`; the `#[cfg(not(unix))]`
  branch bails. Symlink ownership tracking won't work on Windows.

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

# Auth events for list/delete take no hash (or a hash)
AUTH=$(./target/debug/mkauth $SK list 2>/dev/null)
curl http://127.0.0.1:8765/list/<pubkey> -H "Authorization: $AUTH"
```

`mkauth` prints the generated `sk`, `pub`, and full event JSON to stderr; the
base64 `Nostr <...>` header value goes to stdout.

The full smoke flow validated end-to-end:
upload → get → head → list → wrong-action-rejected → delete → list-empty →
re-upload → wait for sweeper → 404.

## Config reference

`config.example.toml` documents every knob. Key ones:

- `ttl_seconds` — blob lifetime (default 86400 = 24h)
- `sweep_interval_seconds` — how often the sweeper runs (default 300)
- `max_upload_bytes` — per-request size cap, also enforced via `DefaultBodyLimit`
- `max_auth_lifetime_seconds` — how far future the auth `expiration` tag may be
- `[ratelimit]` — per-IP `uploads_burst`, `uploads_refill_per_minute`,
  `bytes_per_hour`

## Possible future work (not requested, just noted)

- Range request support (real `ServeFile` integration)
- LRU rate limit table
- Persistent rate-limit state across restarts
- BUD-04 mirror endpoint
- BUD-08 media metadata endpoint
- Optional auth on GET (per-blob private mode)
