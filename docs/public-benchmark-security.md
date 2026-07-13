# Public benchmark security checklist

This checklist is for **public cloud benchmarking only**. It is defensive guidance to reduce operational risk while running short-lived, signed UDP performance tests.

## Scope and intent

- Use this guidance for temporary benchmark environments, not production validator operations.
- Keep benchmark infrastructure isolated from wallets, validator identities, and other sensitive environments.
- Prefer minimal access, minimal runtime, and rapid teardown.

## Required controls

1. **Use disposable cloud nodes**
   - Launch fresh instances for each test window.
   - Do not reuse long-lived hosts that may contain unrelated secrets.

2. **Apply restrictive firewall rules before use**
   - Allow only management and required benchmark traffic.
   - Deny all other unsolicited inbound access.

3. **Use SSH key-only access**
   - Disable password authentication where possible.
   - Limit SSH sources to a known admin IP.

4. **Do not place wallet/private/validator keys on benchmark nodes**
   - Never copy wallet seed phrases, validator identity files, or long-lived private keys.
   - Treat benchmark hosts as untrusted/ephemeral.

5. **Use temporary read-only GitHub repository access**
   - Use a dedicated account, deploy key, or short-lived token with least privilege.
   - Remove repository access immediately after the benchmark ends.

6. **Use synthetic benchmark keys only**
   - Generate test-only signing keys for packet benchmarks.
   - Do not reuse keys from devnet/testnet/mainnet validator workflows.

7. **Run as a normal user, not root**
   - Execute setup and benchmark commands with a non-root account.
   - Use privilege escalation only when explicitly required for package installation.

8. **Scan logs and archives for secrets before sharing**
   - Check `*.log`, `*.csv`, and compressed artifacts for accidental credentials.
   - Remove or redact any sensitive data before transfer or publication.

9. **Destroy nodes and revoke temporary access after testing**
   - Terminate both sender and receiver instances when validation is complete.
   - Revoke temporary SSH keys, tokens, and repository grants.

## Example firewall policy (two-node benchmark)

Use this as a baseline and adapt to your cloud provider controls:

- **Receiver node inbound**
  - `TCP 22` from `<ADMIN_IP>/32` only
  - `UDP 9000` from `<SENDER_PUBLIC_IP>/32` only
- **Sender node inbound**
  - `TCP 22` from `<ADMIN_IP>/32` only

No other public inbound ports are required for this benchmark path.

## Post-benchmark closure checklist

- Export required benchmark results.
- Run secret scan/review on logs and archives.
- Remove temporary repository credentials and SSH access.
- Destroy benchmark nodes.
- Record teardown completion in benchmark notes.
