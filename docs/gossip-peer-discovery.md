# Gossip Peer Discovery

Ticket 15.2 adds the first rpkv2-native peer discovery contract and in-process
peer table.

This is not Solana gossip compatibility. It is a custom rpkv2 discovery
mechanism for a permissioned validator set.

## Mechanism

Nodes may start with static bootstrap peers from production config:

```toml
[gossip]
peer_ttl_seconds = 60

[[gossip.bootstrap_peers]]
validator_id = "validator-b"
gossip_address = "203.0.113.20:4434"
transaction_ingress_address = "203.0.113.20:4433"
repair_address = "203.0.113.20:4435"
```

Bootstrap peers are seeds only. They must already be known validators, and they
do not authorize arbitrary peer identities.

Dynamic peer updates use signed `PeerAnnouncement` messages. An announcement
contains:

- gossip wire version;
- validator id;
- monotonically increasing sequence number;
- gossip, transaction ingress, repair, and optional RPC contact information;
- expiration time;
- Ed25519 signature from the validator consensus voting key.

## Validation

A node accepts a gossip announcement only when:

- the message version is supported;
- the validator id exists in the validator set;
- the signature verifies against that validator's consensus voting key;
- the announcement has not expired;
- the sequence number is newer than the current peer-table entry;
- the encoded message does not exceed the configured maximum size.

Rejected messages are metered by reason so invalid or malicious gossip is
visible during operations.

## Current Limits

The current implementation provides message format, validation, bootstrap
loading, peer-table maintenance, expiry, and metrics text. Network transport for
periodic push/pull gossip is future work and must be added before gossip can be
used as a full production discovery plane.
