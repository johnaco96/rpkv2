# Validator Packet Signing Format

Validator packet signatures cover a canonical preimage, not the raw payload by
itself.

## Domain and Cluster

Every preimage starts with a length-delimited domain separator and cluster id:

```text
domain:    rpkv2.validator_packet.v1
cluster:   rpkv2.localnet
```

The domain separator prevents signatures created for one protocol context from
being reused as valid signatures in another context.

The cluster id prevents signatures created for one network from being replayed
as valid signatures on another network. The current default is `rpkv2.localnet`;
production deployments must treat the cluster id as part of the wire protocol
and configure it intentionally before launch.

## Canonical Preimage

The signed preimage is the concatenation of:

```text
domain_len:   2 bytes, big-endian
domain:       "rpkv2.validator_packet.v1"
cluster_len:  2 bytes, big-endian
cluster_id:   "rpkv2.localnet"
v:            1 byte
msg_type:     1 byte
flags:        2 bytes, big-endian
slot:         8 bytes, big-endian
nonce:        8 bytes, big-endian
key_id:       2 bytes, big-endian
payload_hash: 32 bytes, BLAKE3(payload)
```

`pubkey` and `signature` are excluded from the preimage. `pubkey` selects the
verification key, and `signature` cannot sign itself.

## Verification Rule

Receivers must reconstruct the preimage from the decoded header and received
payload, then verify `header.signature` using `header.pubkey`.

Mutating any signed header field or payload bytes invalidates the signature.
This includes:

- version
- message type
- flags
- slot
- nonce
- key id
- domain
- cluster id
- payload bytes

## Wire Header

Every validator packet starts with a fixed 118-byte header, followed by payload
bytes:

```text
offset  size  field
0       1     v
1       1     msg_type
2       2     flags, big-endian
4       8     slot, big-endian
12      8     nonce, big-endian
20      2     key_id, big-endian
22      32    pubkey
54      64    signature
118     ...   payload
```

`HEADER_LEN` is exactly `118`.

## Version, Message Types, and Flags

The only supported packet version is `1`. Receivers reject any other version.

Supported message types are:

```text
1 = transaction batch
2 = shred
3 = vote
```

Receivers reject any unknown message type.

Flags are a 16-bit field:

```text
bit 15      critical extension bit
bits 0..14  noncritical extension bits
```

The current protocol defines no supported flags. That means:

- unknown critical flags are rejected;
- unknown noncritical flags are also rejected for now;
- future noncritical flags may only be ignored after that behavior is explicitly
  documented and covered by compatibility tests.

## Replay Protection

Receivers maintain deterministic replay state keyed by:

```text
slot
nonce
validator identity
```

In the current packet format, the packet `pubkey` is used as the validator
identity dimension for replay tracking.

Replay protection is exact within the active slot window:

- a duplicate `(slot, nonce, validator identity)` is rejected;
- the same nonce from a different validator identity is allowed;
- slots older than the active window are rejected;
- stale slots are evicted as the observed head slot advances.

A Bloom filter may be used only as a front-filter hint. It is not final
authority, so Bloom false positives cannot drop otherwise valid packets.

Memory is bounded by:

```text
(replay_window + 1) * max_entries_per_slot
```

`ReplayFilter::stats()` exposes the current head slot, active slot count,
tracked entry count, configured bounds, replay drops, stale drops, capacity
drops, and Bloom-front-filter hits.

## Compatibility Note

This format changes compatibility with earlier benchmark/demo packets that only
carried zeroed or payload-only signature data. New senders must sign this
canonical preimage and pass the version/message-type/flag checks above.
