# Transaction Ingress Compatibility

Ticket 15.4 defines the first rpkv2-native transaction ingress compatibility
layer.

This is not Solana TPU, JSON-RPC, or any other external chain API
compatibility. It accepts the rpkv2 transaction format documented in
`docs/transaction-format.md`.

## Interfaces

The shared ingress layer supports these source interfaces:

| Interface | Current contract |
| --- | --- |
| QUIC | Accepts encoded rpkv2 transactions carried by a QUIC-facing adapter. |
| UDP | Accepts encoded rpkv2 transactions carried by a UDP-facing adapter. |
| RPC | Accepts encoded rpkv2 transactions from a future rpkv2-native RPC adapter. A public HTTP/JSON API is not implemented in this ticket. |
| Local | Accepts an already decoded internal `Transaction` from local tooling or tests. |

All interfaces use the same validation path after ingress metering.

## Validation

Ingress accepts a submission only when:

- source rate limits allow the packet;
- encoded bytes decode as `TRANSACTION_VERSION = 1`;
- transaction structure is valid;
- required signatures verify over the canonical transaction preimage;
- the transaction has not expired at the current slot;
- the transaction has not already been accepted by the local ingress replay
  cache.

Invalid submissions are rejected with a structured reason:

- `rate_limited:<reason>`;
- `malformed:<reason>`;
- `invalid:<reason>`.

## Metrics

The ingress layer exposes counters for:

- accepted transactions;
- malformed submissions;
- invalid submissions;
- rate-limited submissions;
- submissions by interface: QUIC, UDP, RPC, and local.

It also appends source-level rate-limit metrics from the existing per-peer rate
limiter.

## Current Limits

- This is a shared compatibility and validation layer, not a complete QUIC,
  UDP, or RPC server.
- RPC is rpkv2-native future work. No Solana-compatible RPC surface exists.
- Source ids are supplied by adapters. Production adapters must bind source ids
  to authenticated peer identity or trusted local operator context.
- The ingress replay cache is in memory. Durable mempool/replay persistence is
  future work.
