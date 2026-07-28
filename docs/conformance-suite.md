# Conformance Suite

Ticket 15.5 adds the first rpkv2 conformance suite for the declared custom
rpkv2 protocol target.

## Fixture Version

Fixtures live under:

```text
tests/fixtures/conformance/v1/
```

The `manifest.toml` file records:

- fixture version;
- compatibility target;
- required fixture classes;
- protocol versions;
- release gate policy.

Compatibility failures are release blocking. The conformance tests are ordinary
Cargo tests, so they run in CI with the existing `cargo test` gate.

## Covered Fixtures

The v1 suite covers:

- genesis/config fixture loading;
- public validator identities;
- transactions;
- blocks;
- votes;
- shreds;
- snapshots;
- propagation sender/receiver transport compatibility;
- transaction ingress validation and metering behavior;
- negative rejection of foreign or malformed protocol bytes.

## Current Limits

The target is custom rpkv2. The suite does not test against Solana, Agave,
Firedancer, Frankendancer, or any external live node/tool. If the compatibility
target changes, this suite must gain external known-good fixtures or interop
tests before any compatibility claim is made.
