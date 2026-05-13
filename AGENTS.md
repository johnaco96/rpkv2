# AGENTS.md

## Project

This is a Rust blockchain networking prototype using:

- Quinn/Rustls QUIC
- RFC 7250-style raw public key TLS authentication
- pinned SPKI verification
- replay-protected validator packet headers
- batched Ed25519 verification
- slot-based transaction batching
- PoH-style hashing
- shredding/signing/storage/fanout experiments

## Rules for AI agents

1. Do not rewrite unrelated files.
2. Work on a new branch for each task.
3. Prefer small, reviewable patches.
4. Do not modify TLS/RPK/QUIC authentication code unless the task explicitly says so.
5. Do not add dependencies unless necessary.
6. Do not commit private keys, PEM files, `.env` files, wallet files, or cloud credentials.
7. Every change must include:
   - files changed
   - why they changed
   - how to test
   - known risks
8. Code must pass:
   - cargo fmt
   - cargo build
   - cargo test
9. Benchmark changes must output CSV or JSON.
10. Do not claim production readiness.
