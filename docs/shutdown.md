# Coordinated Shutdown

Long-running workers share a `Shutdown` token. A caller that wants coordinated
shutdown creates one token, starts tiles with `start_with_shutdown`, requests
shutdown, then joins every worker handle.

The legacy `Tile::start()` method still exists for prototypes, but production
paths should retain handles and use `start_with_shutdown`.

## Policy

- Ctrl-C on `server` closes the QUIC endpoint and stops accepting new
  connections.
- Existing QUIC connection tasks finish after the endpoint close propagates.
- Tile workers exit when shutdown is requested.
- Queue-processing tiles drain already queued items before exiting.
- `Bank` flushes its in-memory batch before exit.
- `Storage` writes and flushes each shred record before exit; current storage is
  append-only one-file-per-slot, does not fsync, and has no separate database
  checkpoint.
- The shutdown policy is stop-and-drain for already queued in-memory work, not a
  guarantee that new network input will keep being accepted after shutdown.

## Worker Supervision

Production-style tile pipelines should use `TileSupervisor` rather than storing
raw thread handles directly. The supervisor starts each critical tile, retains
the thread handle, and records per-tile health.

If a critical tile panics:

- the panic is captured when the supervisor is polled or joined;
- the tile health changes to unhealthy;
- the shared shutdown token is requested;
- the caller receives an error and should stop accepting production traffic.

The health registry exports simple metric text:

```text
rpkv2_tile_health{tile="deduper",critical="true"} 1
```

`1` means the tile is running or exited cleanly. `0` means the tile panicked.
This is intentionally dependency-free and can be served alongside the metrics
endpoint.

## Manual Check

```text
cargo run --bin demo -- --txns 10 --addr 127.0.0.1:4455 --key target/tmp/demo.key --pub target/tmp/demo.pub --store target/tmp/store
```

The demo starts the full tile chain, sends a small load batch, closes QUIC,
requests tile shutdown, joins all worker handles, and exits.
