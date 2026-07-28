# Crypto Build Modes

## Secure Default

The default build enables the `ed25519` feature and uses real Ed25519
verification/signing paths:

```text
cargo build
cargo test
```

Production and benchmark binaries require `ed25519`. If they are built with
`--no-default-features`, they fail at compile time instead of silently accepting
stub verification.

Protected binaries include:

- `server`
- `client`
- `bench_dgram`
- `bench_stream`
- `fast_tx`
- `fast_rx`

## Insecure Demo Mode

Stub verification is available only through the explicit `insecure_demo` feature
and only for demo-style builds:

```text
cargo build --no-default-features --features insecure_demo --bin demo
```

`insecure_demo` exists for local smoke tests where cryptographic authenticity is
not being evaluated. Do not use it for validators, benchmarks, public testing,
or any environment where packet authenticity matters.

## Expected Guardrail

This command is expected to fail:

```text
cargo build --no-default-features --bin server
```

The failure is intentional. It prevents production paths from compiling without
real Ed25519 verification.
