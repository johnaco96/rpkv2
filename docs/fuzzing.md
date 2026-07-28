# Fuzzing

This repo includes a `cargo-fuzz` target for packet parser hardening.

```text
cargo fuzz run header_decode -- -max_total_time=30
```

The target feeds arbitrary bytes into:

- `Header::decode_from`
- `Header::payload`

The parser must reject malformed bytes with `Err`, never panic.

The seed corpus covers empty, short, exact-header-length, oversized, and random
inputs. Deterministic malformed parser cases also run in normal `cargo test`.
