# TLS/RPK Security Review

This review covers the raw-public-key TLS path used by the QUIC/RPK validator
prototype. It is a review artifact, not a production-readiness claim.

## Review Scope

- Server raw public key presentation.
- Client raw public key requirement.
- Exact SPKI comparison and timing risk.
- TLS 1.2 behavior.
- Signature verification assumptions.
- SNI and validator identity behavior.
- Raw key misbinding risk.
- Certificate-mode fallback behavior.
- Mutual validator identity on inbound server connections.

## Findings

| ID | Severity | Status | Finding | Evidence | Required action |
| --- | --- | --- | --- | --- | --- |
| TLS-RPK-001 | Blocking item closed for current RPK path | Closed | The mutual RPK handshake test asserts the negotiated protocol version is TLS 1.3. The verifier still rejects TLS 1.2 signatures defensively. | `tls::tests::mutual_rpk_handshake_succeeds_and_negotiates_tls13`; `src/tls.rs` rejects `verify_tls12_signature`; QUIC config is built through `quinn::crypto::rustls`. | Keep this test in CI and re-run it when TLS, Quinn, or rustls versions change. |
| TLS-RPK-002 | Blocking item closed for current RPK path | Closed | An end-to-end rustls handshake proves an RPK client rejects a standard X.509 TLS server. Verifier-level coverage also rejects certificate-mode fallback input. | `tls::tests::rpk_client_rejects_x509_server_end_to_end`; `tls::tests::identity_verifier_rejects_certificate_mode_fallback`. | Keep both negative tests in CI and add QUIC-level coverage if the RPK transport layer changes. |
| TLS-RPK-003 | Nonblocking for current prototype, blocking before adversarial multi-tenant deployment | Open | SPKI comparison uses normal slice equality. This is exact, but not constant-time. The compared value is a public SPKI pin rather than a secret, so timing leakage is acceptable for this prototype. | `IdentityPinVerifier::verifies_spki` compares `presented_spki == spki.as_slice()`. | Keep as accepted risk unless SPKI membership becomes sensitive. If needed, replace with constant-time equality over fixed hash digests. |
| TLS-RPK-004 | Nonblocking | Open | SNI is not bound to validator identity. The verifier ignores `server_name` and relies on selected validator id plus pinned SPKI. This avoids hostname PKI dependence, but SNI mismatch behavior is not operator-visible. | `verify_server_cert` receives `_server_name` and uses only SPKI pins. | Document that validator id and SPKI pin, not DNS name, are authoritative. Optionally log configured peer id and supplied SNI at debug level without secrets. |
| TLS-RPK-005 | Nonblocking | Open | Production packet signing and TLS identity are separate keys. This is intentional, but raw-key misbinding remains possible if operators configure mismatched validator ids, SPKI pins, and Ed25519 packet keys out of band. | `PeerRegistry` maps `validator_id` to active TLS SPKI pins and packet verify key, and rejects duplicate validator ids or duplicate SPKIs. | Add operational checklist requiring independent review of validator id, SPKI pin, and packet signing key during onboarding and rotation. |

## Reviewed Controls

- `build_server_rpk` serves a single SPKI-derived raw public key through
  `AlwaysResolvesServerRawPublicKeys`.
- Configured validator servers use `build_server_rpk_mutual`, which requires
  inbound peers to present raw public keys and resolves them through
  `PeerRegistry` before accepting validator traffic.
- Configured validator clients use
  `build_client_rpk_for_validator_with_identity`, which pins the remote
  validator SPKI and presents the local transport raw public key for mutual
  authentication.
- `IdentityPinVerifier::requires_raw_public_keys` returns `true`.
- `RawPublicKeyClientVerifier::requires_raw_public_keys` returns `true`.
- `IdentityPinVerifier` accepts only byte-exact configured SPKI pins.
- Unknown or wrong SPKI values are rejected and counted as unknown peer drops.
- `PeerRegistry` rejects duplicate validator ids and duplicate SPKI pins across
  validators.
- Multiple active SPKI pins per validator are supported for rotation windows.
- Revoked SPKI pins are rejected during config/registry construction.
- Standard TLS benchmark binaries are separate comparison tools and use
  `with_single_cert`; they are not the production RPK path.

## Test Evidence

- Wrong SPKI verifier test: `tls::tests::identity_verifier_rejects_wrong_spki`.
- Unknown validator test: `tls::tests::identity_client_config_rejects_unknown_validator`.
- Raw public key requirement test:
  `tls::tests::identity_verifier_requires_raw_public_keys`.
- Certificate-mode fallback unit test:
  `tls::tests::identity_verifier_rejects_certificate_mode_fallback`.
- Mutual RPK TLS 1.3 proof:
  `tls::tests::mutual_rpk_handshake_succeeds_and_negotiates_tls13`.
- Unknown inbound client RPK negative test:
  `tls::tests::mutual_rpk_rejects_unknown_client_spki`.
- End-to-end X.509 fallback negative test:
  `tls::tests::rpk_client_rejects_x509_server_end_to_end`.
- Duplicate SPKI misbinding tests:
  `identity::tests::duplicate_spki_fails` and
  `identity::tests::duplicate_spki_for_same_validator_fails`.

## Launch Gate

Production launch requires zero blocking TLS/RPK findings. At the time of this
review update, no blocking TLS/RPK findings remain in this document. The
nonblocking findings above remain tracked risks, and this document by itself is
not a production-readiness claim.
