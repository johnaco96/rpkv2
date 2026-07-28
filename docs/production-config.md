# Production Config

`server` accepts an explicit production config:

```text
cargo run --bin server -- --config config/production.toml
```

To validate the config without binding sockets:

```text
cargo run --bin server -- --config config/production.toml --check-config
```

Validation happens before the server binds its QUIC socket.

When started with `--config`, the server requires mutual RPK authentication and
wires QUIC datagrams from authenticated validators into the validator tile
pipeline: packet parsing, per-peer rate limiting, deterministic replay dedupe,
Ed25519 verification, pack, bank batching, PoH hashing, shredding, shred
signing, and storage. No-config demo mode keeps the local echo behavior.

## Required Fields

```toml
format_version = 1

[local]
bind_address = "0.0.0.0:4433"
validator_id = "validator-a"
private_key_path = "keys/validator-a.key"
packet_signing_key_path = "keys/packet-signing.key"

[[peers]]
validator_id = "validator-b"
ed25519_verify_key_hex = "64_hex_characters_for_the_peer_packet_verify_key"
address = "127.0.0.1:4433"
revoked_spki_pin_paths = ["pins/validator-b-revoked.pub"]

[[peers.tls_spki_pins]]
path = "pins/validator-b-old.pub"
valid_until_unix_seconds = 1893456000

[[peers.tls_spki_pins]]
path = "pins/validator-b-new.pub"
valid_from_unix_seconds = 1893452400

[replay]
slot_window = 1024
capacity_per_slot = 131072

[queues]
raw = 8192
deduped = 8192
verified = 8192
packed = 8192
bank = 1024
poh = 1024
shred = 4096
signed = 4096

[rate_limits]
packets_per_second = 50000
bytes_per_second = 64000000

[storage]
directory = "store"
allow_unsafe_demo_storage = true
recovery_policy = "fail_startup"
flush_interval_records = 1
flush_interval_ms = 1
sync_data = true

[processing]
verifier_workers = 1
verifier_batch = 256
signer_batch = 256
signer_workers = 1
# verifier_affinity_base = 2

[metrics]
bind_address = "127.0.0.1:9100"

[gossip]
peer_ttl_seconds = 60

[[gossip.bootstrap_peers]]
validator_id = "validator-b"
gossip_address = "203.0.113.20:4434"
transaction_ingress_address = "203.0.113.20:4433"
repair_address = "203.0.113.20:4435"
```

## Validation Rules

- `format_version` defaults to `1` when omitted for compatibility with existing
  test configs. Any explicit value other than `1` is rejected before network
  start.
- `gossip` is optional. If omitted, the node remains static-peer only.
- `gossip.bootstrap_peers` are static discovery seeds. Each bootstrap validator
  id must already be present in the validator set; signed gossip announcements
  are still required before non-bootstrap peers are accepted dynamically.
- `gossip.peer_ttl_seconds` controls how long bootstrap contacts remain live
  without a newer signed announcement. It defaults to `60`.
- `local.private_key_path` must exist and contain a PKCS#8 private key. In
  configured validator mode, this key is used as the local transport RPK both
  for the server's presented identity and for client-side mutual
  authentication.
- `local.packet_signing_key_path` must exist and contain the local Ed25519
  packet-signing private key as 64 hex characters when running the configured
  server pipeline.
- Each peer must have a non-empty validator id.
- Each legacy peer `spki_pin_path`, when present, must exist and contain a PEM
  `PUBLIC KEY`.
- Each entry in `tls_spki_pins` must exist and contain a PEM `PUBLIC KEY`.
- `valid_from_unix_seconds` is inclusive.
- `valid_until_unix_seconds` is exclusive.
- If both validity values are present, `valid_from_unix_seconds` must be before
  `valid_until_unix_seconds`.
- At least one non-revoked TLS SPKI must be active for each peer at startup.
- A revoked SPKI is rejected even if it is also present in the active key list.
- Each peer Ed25519 verification key must be exactly 32 bytes encoded as 64 hex
  characters and must parse as an Ed25519 verifying key.
- Peer validator ids must be unique.
- Peer TLS SPKI pins must be unique unless an explicit future config option is
  added to permit shared identities.
- `address` is optional. When present, identity-aware clients use it as the
  expected network address for that validator.
- Queue sizes must be greater than zero.
- Replay slot window and rate limits must be greater than zero.
- `storage.allow_unsafe_demo_storage = true` is required because the current
  append-file storage is pilot-only. Production validator-grade storage is not
  implemented yet.
- `storage.recovery_policy` may be `fail_startup` or `quarantine_corrupt`.
  Production-like deployments should use `fail_startup` unless an operator has a
  documented repair plan for quarantined files.

## Validator Identity Binding

Production config builds a peer registry keyed by `validator_id`.

Each registry entry binds the validator id to:

- the active raw-public-key TLS SPKI pin set;
- the expected Ed25519 packet verification key;
- an optional network address constraint.

The identity-aware client path requires `--config` and `--peer-validator-id`.
It resolves the named validator, builds the TLS verifier from that validator's
SPKI pin, presents the local transport RPK from `local.private_key_path`, and
logs the validator id when connecting. Unknown validator ids, wrong SPKI pins,
unknown inbound client SPKIs, and duplicate identity config fail before a
connection is treated as trusted.

## TLS SPKI Rotation Runbook

Time values are Unix seconds in UTC. Nodes evaluate key validity once at startup
using their local system clock. Keep validator clocks synchronized with NTP and
choose overlap windows that are larger than expected clock skew plus deployment
time.

To rotate a validator TLS SPKI without a code change:

1. Generate the new validator TLS private key and SPKI pin out of band.
2. Distribute the new SPKI pin file to peers without removing the old pin.
3. Add both pins under the validator's `tls_spki_pins` list.
4. Set `valid_from_unix_seconds` on the new pin before the planned switchover.
5. Set `valid_until_unix_seconds` on the old pin after the planned switchover.
6. Restart peers during the overlap window.
7. After the cutoff, remove the old pin or leave it expired.

If a key is compromised, add its SPKI pin file to `revoked_spki_pin_paths` and
restart peers immediately. A revoked key is rejected even when it otherwise falls
inside a valid rotation window.

`spki_pin_path` remains supported for a single always-active peer pin. New
production rotations should use `tls_spki_pins` so cutovers can be staged in
config.

Do not commit private keys, peer pin files, wallet files, `.env` files, or cloud
credentials.
