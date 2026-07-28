# rpkv2 Conformance Fixtures v1

These fixtures target the custom rpkv2 protocol declared in
`docs/protocol-compatibility.md`.

Checked-in files contain public config, genesis state, and version metadata only.
Tests derive deterministic in-memory signing keys for transaction, vote,
propagation, and snapshot fixtures. Do not replace these fixtures with
production keys, PEM files, wallets, or credentials.
