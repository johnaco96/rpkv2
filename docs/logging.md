# Structured Logging

Production-facing logs use stable field names so incidents can be searched
without parsing message text:

- `validator_id`
- `peer_id`
- `connection_id`
- `slot`
- `packet_type`
- `reason`
- `tile`

Startup logs include a config summary without private keys, PEM contents,
wallets, or credentials. The server no longer prints SPKI PEM data into logs;
operators should distribute pins out of band.

## Rejection Logs

Rejection paths log concise reasons:

- `packet_too_short`
- `header_decode_failed`
- `ingress_queue_full`
- `queue_full`
- `replay`
- `bad_signature`
- `spki_pin_mismatch`
- peer rate-limit reasons such as `packet_rate` and `malformed_rate`

Noisy paths are rate-limited. Counters continue to increment even when repeated
logs are suppressed.

## Manual Check

Run the demo and inspect the structured fields:

```text
cargo run --bin demo -- --txns 10 --addr 127.0.0.1:4455 --metrics-addr 127.0.0.1:19100
```

Expected startup fields include `validator_id`, `bind_address`,
`metrics_address`, and `storage_dir`. Expected connection fields include
`connection_id` and `peer_id`.
