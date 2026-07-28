# Per-Peer Rate Limiting

Ingress applies a per-peer rate limit before packet data enters shared queues.
The current demo peer key is the QUIC remote socket address. Production
validator paths should replace that with the authenticated validator id as soon
as it is available from the TLS/peer registry binding.

## Default Limits

The default window is one second:

| Signal | Default |
| --- | --- |
| Packets | 50,000 per peer per window |
| Bytes | 64 MiB per peer per window |
| Malformed packets | 128 per peer per window |
| Invalid signatures | 128 per peer per window |
| Replays | 1,024 per peer per window |
| Throttle duration | 5 seconds |

## Decisions

When a peer exceeds a packet or byte limit, ingress drops that peer's newest
datagram while allowing other peers to keep flowing. Malformed packet events are
recorded at ingress. Replay events are recorded by the dedupe tile. Invalid
signature events are recorded by the verifier tile.

Rate-limit decisions are logged and counted. The limiter exports metric text:

```text
rpkv2_peer_packets_total{peer="127.0.0.1:4433"} 10
rpkv2_peer_bytes_total{peer="127.0.0.1:4433"} 3740
rpkv2_peer_malformed_total{peer="127.0.0.1:4433"} 0
rpkv2_peer_invalid_signatures_total{peer="127.0.0.1:4433"} 0
rpkv2_peer_replays_total{peer="127.0.0.1:4433"} 0
rpkv2_peer_throttled_total{peer="127.0.0.1:4433"} 0
```

## Risk

Remote socket address is only a temporary peer key. NAT, reconnects, and QUIC
connection migration can make address-based enforcement imprecise. The
production validator path must bind this limiter to authenticated validator ids
once identity is available at connection setup.
