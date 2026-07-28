# Runtime Modes

The server uses an explicit runtime mode to prevent
accidental unsafe launches.

## Modes

- `demo`: local experiments. Demo mode may use manual SPKI pins and may generate
  local ephemeral key files. Startup logs mark this mode as demo/insecure.
- `benchmark`: repeatable measurement tools. Benchmark mode is for benchmark
  binaries and raw UDP load generators only.
- `production`: configured validator startup. Production mode refuses unsafe
  defaults.

## Production Guardrails

Production mode requires:

- the real Ed25519 crypto feature;
- `insecure_demo` disabled;
- a config file;
- no ephemeral generated keys;
- metrics enabled;
- a nonempty peer registry;
- configured storage durability or explicit acknowledgement that the current
  append-file storage is unsafe demo storage.

The current storage implementation is still pilot/demo storage. Production mode
can only pass when the config explicitly acknowledges that storage risk through
`storage.allow_unsafe_demo_storage = true`; this is not a production-readiness
claim.

## Expected Startup Behavior

- `server --mode production` without `--config` fails before binding sockets or
  generating keys.
- `server --mode demo` remains easy for local use and logs the selected mode.
- `demo --mode demo` remains available and logs that demo mode is insecure.
- RPK and raw UDP benchmark binaries use `--mode benchmark` and reject
  production mode.

## Follow-Up

Before launch, release packaging should make `--mode production --config
<path>` the obvious deployment path and should keep demo/benchmark binaries out
of production service units.
