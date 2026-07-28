# Public Benchmark Security Checklist

This checklist is for temporary public cloud benchmarking only. It is not a
production validator operations guide.

## Required Controls

1. Use disposable cloud nodes dedicated to the benchmark window.
2. Apply restrictive firewall rules before cloning or running the benchmark.
3. Allow SSH only from a known admin IP.
4. Allow receiver UDP `9000` only from the sender node public IP.
5. Do not place wallet keys, validator identity keys, seed phrases, cloud
   credentials, or long-lived secrets on benchmark nodes.
6. Use synthetic benchmark keys only.
7. Use temporary least-privilege repository access and revoke it after testing.
8. Run benchmark commands as a normal user, not root.
9. Scan logs, CSVs, JSON summaries, and archives for accidental secrets before
   sharing.
10. Destroy the nodes and revoke temporary access after the benchmark.

## Minimal Firewall Shape

Receiver node inbound:

- TCP `22` from `<ADMIN_IP>/32`
- UDP `9000` from `<SENDER_PUBLIC_IP>/32`

Sender node inbound:

- TCP `22` from `<ADMIN_IP>/32`

No other public inbound ports are required for this benchmark path.

## Closure Checklist

- Export required CSV/JSON/log artifacts.
- Run a manual secret review before sharing artifacts.
- Remove temporary repository credentials and SSH keys.
- Terminate sender and receiver instances.
- Record teardown completion in benchmark notes.
