# Block And Shred Propagation

Ticket 15.3 defines the first rpkv2-native block and shred propagation
compatibility layer. This is not Solana shred, Turbine, repair, or gossip
compatibility.

## Transport Contract

Propagation messages are encoded as signed rpkv2 envelopes that can be carried
over:

- QUIC datagrams for low-latency best-effort block/shred fanout;
- UDP packets for benchmark or constrained deployments that accept packet loss;
- streams for ordered delivery or larger repair responses.

The transport enum is part of sender planning. Message validation is transport
independent so the same bytes must decode and validate the same way over QUIC
datagrams, UDP packets, or streams.

## Message Types

The propagation wire format uses `PROPAGATION_VERSION = 1` and rejects unknown
versions.

| Message | Purpose | Required validation |
| --- | --- | --- |
| `BlockPropagation` | Push a produced block to a peer. | Envelope signature, known signer, signer equals block producer, producer is leader for slot, block integrity. |
| `ShredPropagation` | Push a data shred to a peer. | Envelope signature, known signer, signer equals producer, producer is leader for slot, shred integrity. |
| `RepairRequest` | Ask a peer for missing shred indices for a block. | Envelope signature, known requester, non-empty unique index list, bounded index count. |
| `RepairResponse` | Return requested shreds. | Envelope signature, known responder, bounded shred count, every shred passes integrity checks. |

Envelope signatures use the validator consensus voting key. The envelope signs
the message kind, version, signer, producer/requester fields, and encoded ledger
payload. The ledger object still carries its own integrity fields.

## Receiver Behavior

Receivers:

- reject malformed propagation messages;
- reject invalid signatures;
- reject block or shred production by non-leaders;
- reject corrupt shreds;
- store accepted blocks and shreds in the propagation store;
- attempt block reconstruction when repair responses fill missing shreds;
- expose propagation counters for accepted blocks, accepted shreds, repair
  requests, repair responses, invalid messages, invalid signatures, invalid
  leaders, corrupt shreds, and missing repair data.

## Repair Flow

1. Receiver detects missing shred indices for a known slot/block hash.
2. Receiver sends a signed `RepairRequest`.
3. Peer verifies the requester and returns available shreds.
4. Receiver verifies the signed `RepairResponse`.
5. Receiver stores the repaired shreds and reconstructs the block once the full
   shred set is available.

Repair responses do not fabricate data. Missing requested shreds are counted so
operators can see incomplete repair service.

## Current Limits

- Erasure coding is not implemented; only data shreds are reconstructable.
- The current implementation provides sender/receiver planning and validation,
  not a background network fanout service.
- The in-memory propagation store is a compatibility layer. Production
  integration should write accepted data into the durable blockstore.
- This is custom rpkv2 propagation, not Solana/Agave/Firedancer compatibility.
- The receiver metrics include invalid leaders as a distinct production
  rejection reason.
