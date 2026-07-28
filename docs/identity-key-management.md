# Identity And Key Management

Ticket 14.1 adds `identityctl`, an operator CLI for generating validator keys,
exporting public identity, and validating key/config consistency.

## Generate A Full Validator Identity

```powershell
cargo run --bin identityctl -- generate-validator-identity --validator-id validator-a --out-dir keys/validator-a
```

This creates:

- `transport.key`: private PKCS#8 transport key for TLS raw public key mode.
- `transport.pub`: public SPKI PEM for peer pinning.
- `packet-signing.key`: private Ed25519 packet signing seed as hex.
- `packet-signing.pub`: public Ed25519 packet verify key as hex.
- `consensus-voting.key`: private Ed25519 consensus voting seed as hex.
- `consensus-voting.pub`: public Ed25519 consensus verify key as hex.
- `identity-public.toml`: public identity export with no private key material.

Private files are never printed by default. The repo `.gitignore` already
ignores generated key and public key files such as `*.key`, `*.pem`, and
`*.pub`.

## Generate Individual Keys

```powershell
cargo run --bin identityctl -- generate-transport-key --out-dir keys/validator-a
cargo run --bin identityctl -- generate-packet-signing-key --out-dir keys/validator-a
cargo run --bin identityctl -- generate-consensus-voting-key --out-dir keys/validator-a
```

Use `--overwrite` only when intentionally replacing existing generated key
files.

## Export Public Material

```powershell
cargo run --bin identityctl -- print-public-identity --public-identity keys/validator-a/identity-public.toml
cargo run --bin identityctl -- print-public-key --kind transport-spki --private-key keys/validator-a/transport.key
cargo run --bin identityctl -- print-public-key --kind ed25519 --private-key keys/validator-a/packet-signing.key
```

The public identity export contains:

- validator id
- transport SPKI DER hex
- packet verify key hex
- consensus verify key hex
- generation timestamp

It must not contain private key paths, private PEM blocks, Ed25519 signing
seeds, wallet files, `.env` values, or cloud credentials.

## Validate Config Consistency

```powershell
cargo run --bin identityctl -- validate-config --config config/production.toml --public-identity keys/validator-a/identity-public.toml
```

Validation checks:

- the production config loads and passes normal config validation;
- `local.validator_id` matches the public identity;
- `local.private_key_path` exists and its derived SPKI matches the public
  identity export;
- peer SPKI pins and Ed25519 peer verify keys remain covered by normal
  production config validation.

Production config includes `local.packet_signing_key_path` for the configured
server pipeline. The consensus-voting private key path is still created by
`identityctl` for operator custody and future consensus-node signing
integration.
