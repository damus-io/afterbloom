# afterbloom

Minimal [Blossom](https://github.com/hzrd149/blossom) server for **transient** blobs.
Every blob auto-expires after a configurable TTL (default: 24 hours). No database —
the filesystem is the source of truth.

## Why

Most Blossom servers are designed for permanent storage and pull in databases,
payments, moderation, etc. afterbloom does one thing: accept blobs, serve them
for 24h, and delete them. Useful for ephemeral file sharing, scratch storage,
and short-lived attachments.

## Spec coverage

- [BUD-01](https://github.com/hzrd149/blossom/blob/master/buds/01.md): GET/HEAD `/<sha256>` (with HTTP Range support)
- [BUD-02](https://github.com/hzrd149/blossom/blob/master/buds/02.md): PUT `/upload`, DELETE `/<sha256>`. `GET /list/<pubkey>` is **not** implemented — afterbloom doesn't expose per-pubkey blob lists.
- Nostr auth (kind `24242`) is required for `upload` and `delete`.

## Storage layout

```
data/
├── blobs/<sha256>           # actual file (mtime = expiration clock)
└── owners/<pubkey>/<sha256> # symlink → ../../blobs/<sha256>
```

`owners/` is an internal per-pubkey reference count used by DELETE: each uploading
pubkey gets a symlink, and DELETE removes only the caller's symlink. The blob
itself is removed eagerly when the last symlink goes away. The sweeper deletes
any blob whose mtime is older than `ttl_seconds` and prunes dangling owner symlinks.

## Running

```sh
cp config.example.toml config.toml
cargo run --release -- --config config.toml
```
