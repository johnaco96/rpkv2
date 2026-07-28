use crate::{
    peer_rate_limit::{PeerLimitDecision, PeerLimitReason, PeerRateLimiter, PeerRateLimits},
    transaction::{Transaction, TransactionReplay},
};
use std::{fmt, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressInterface {
    Quic,
    Udp,
    Rpc,
    Local,
}

impl fmt::Display for IngressInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic => f.write_str("quic"),
            Self::Udp => f.write_str("udp"),
            Self::Rpc => f.write_str("rpc"),
            Self::Local => f.write_str("local"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressSource {
    pub interface: IngressInterface,
    pub source_id: String,
}

impl IngressSource {
    pub fn new(interface: IngressInterface, source_id: impl Into<String>) -> Self {
        Self {
            interface,
            source_id: source_id.into(),
        }
    }

    fn rate_limit_key(&self) -> String {
        format!("{}:{}", self.interface, self.source_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedTransaction {
    pub transaction: Transaction,
    pub transaction_id: [u8; 32],
    pub source: IngressSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressRejectReason {
    RateLimited(PeerLimitReason),
    Malformed(String),
    Invalid(String),
}

impl fmt::Display for IngressRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited(reason) => write!(f, "rate_limited:{reason}"),
            Self::Malformed(reason) => write!(f, "malformed:{reason}"),
            Self::Invalid(reason) => write!(f, "invalid:{reason}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedSubmission {
    pub source: IngressSource,
    pub reason: IngressRejectReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressOutcome {
    Accepted(AcceptedTransaction),
    Rejected(RejectedSubmission),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionIngressMetrics {
    pub accepted: u64,
    pub malformed: u64,
    pub invalid: u64,
    pub rate_limited: u64,
    pub quic_submissions: u64,
    pub udp_submissions: u64,
    pub rpc_submissions: u64,
    pub local_submissions: u64,
}

impl TransactionIngressMetrics {
    pub fn metrics_text(&self) -> String {
        format!(
            concat!(
                "rpkv2_transaction_ingress_accepted_total {}\n",
                "rpkv2_transaction_ingress_malformed_total {}\n",
                "rpkv2_transaction_ingress_invalid_total {}\n",
                "rpkv2_transaction_ingress_rate_limited_total {}\n",
                "rpkv2_transaction_ingress_submissions_total{{interface=\"quic\"}} {}\n",
                "rpkv2_transaction_ingress_submissions_total{{interface=\"udp\"}} {}\n",
                "rpkv2_transaction_ingress_submissions_total{{interface=\"rpc\"}} {}\n",
                "rpkv2_transaction_ingress_submissions_total{{interface=\"local\"}} {}\n",
            ),
            self.accepted,
            self.malformed,
            self.invalid,
            self.rate_limited,
            self.quic_submissions,
            self.udp_submissions,
            self.rpc_submissions,
            self.local_submissions
        )
    }
}

#[derive(Clone, Debug)]
pub struct TransactionIngress {
    limiter: PeerRateLimiter,
    replay: TransactionReplay,
    metrics: TransactionIngressMetrics,
}

impl TransactionIngress {
    pub fn new(limits: PeerRateLimits) -> Self {
        Self {
            limiter: PeerRateLimiter::new(limits),
            replay: TransactionReplay::default(),
            metrics: TransactionIngressMetrics::default(),
        }
    }

    pub fn production_defaults() -> Self {
        Self::new(PeerRateLimits::default())
    }

    pub fn submit_bytes(
        &mut self,
        source: IngressSource,
        bytes: &[u8],
        current_slot: u64,
    ) -> IngressOutcome {
        self.record_interface(source.interface);
        let key = source.rate_limit_key();
        if let PeerLimitDecision::Throttle(reason) = self.limiter.check_packet(&key, bytes.len()) {
            self.metrics.rate_limited = self.metrics.rate_limited.saturating_add(1);
            return IngressOutcome::Rejected(RejectedSubmission {
                source,
                reason: IngressRejectReason::RateLimited(reason),
            });
        }

        let transaction = match Transaction::decode(bytes) {
            Ok(transaction) => transaction,
            Err(e) => {
                self.limiter.record_malformed(&key);
                self.metrics.malformed = self.metrics.malformed.saturating_add(1);
                return IngressOutcome::Rejected(RejectedSubmission {
                    source,
                    reason: IngressRejectReason::Malformed(e.to_string()),
                });
            }
        };

        self.accept_decoded_transaction(source, transaction, current_slot)
    }

    pub fn submit_transaction(
        &mut self,
        source: IngressSource,
        transaction: Transaction,
        current_slot: u64,
    ) -> IngressOutcome {
        self.record_interface(source.interface);
        let key = source.rate_limit_key();
        let encoded_len = transaction.encode().len();
        if let PeerLimitDecision::Throttle(reason) = self.limiter.check_packet(&key, encoded_len) {
            self.metrics.rate_limited = self.metrics.rate_limited.saturating_add(1);
            return IngressOutcome::Rejected(RejectedSubmission {
                source,
                reason: IngressRejectReason::RateLimited(reason),
            });
        }

        self.accept_decoded_transaction(source, transaction, current_slot)
    }

    fn accept_decoded_transaction(
        &mut self,
        source: IngressSource,
        transaction: Transaction,
        current_slot: u64,
    ) -> IngressOutcome {
        let key = source.rate_limit_key();
        let transaction_id = transaction.transaction_id();
        match self.replay.accept(&transaction, current_slot) {
            Ok(()) => {
                self.metrics.accepted = self.metrics.accepted.saturating_add(1);
                IngressOutcome::Accepted(AcceptedTransaction {
                    transaction,
                    transaction_id,
                    source,
                })
            }
            Err(e) => {
                self.record_invalid_for_reason(&key, &e);
                IngressOutcome::Rejected(RejectedSubmission {
                    source,
                    reason: IngressRejectReason::Invalid(e.to_string()),
                })
            }
        }
    }

    pub fn submit_quic(
        &mut self,
        source_id: impl Into<String>,
        bytes: &[u8],
        current_slot: u64,
    ) -> IngressOutcome {
        self.submit_bytes(
            IngressSource::new(IngressInterface::Quic, source_id),
            bytes,
            current_slot,
        )
    }

    pub fn submit_udp(
        &mut self,
        source_id: impl Into<String>,
        bytes: &[u8],
        current_slot: u64,
    ) -> IngressOutcome {
        self.submit_bytes(
            IngressSource::new(IngressInterface::Udp, source_id),
            bytes,
            current_slot,
        )
    }

    pub fn submit_rpc(
        &mut self,
        source_id: impl Into<String>,
        bytes: &[u8],
        current_slot: u64,
    ) -> IngressOutcome {
        self.submit_bytes(
            IngressSource::new(IngressInterface::Rpc, source_id),
            bytes,
            current_slot,
        )
    }

    pub fn submit_local(
        &mut self,
        source_id: impl Into<String>,
        transaction: Transaction,
        current_slot: u64,
    ) -> IngressOutcome {
        self.submit_transaction(
            IngressSource::new(IngressInterface::Local, source_id),
            transaction,
            current_slot,
        )
    }

    pub fn metrics(&self) -> &TransactionIngressMetrics {
        &self.metrics
    }

    pub fn metrics_text(&self) -> String {
        let mut out = self.metrics.metrics_text();
        out.push_str(&self.limiter.metrics_text());
        out
    }

    fn record_interface(&mut self, interface: IngressInterface) {
        match interface {
            IngressInterface::Quic => {
                self.metrics.quic_submissions = self.metrics.quic_submissions.saturating_add(1)
            }
            IngressInterface::Udp => {
                self.metrics.udp_submissions = self.metrics.udp_submissions.saturating_add(1)
            }
            IngressInterface::Rpc => {
                self.metrics.rpc_submissions = self.metrics.rpc_submissions.saturating_add(1)
            }
            IngressInterface::Local => {
                self.metrics.local_submissions = self.metrics.local_submissions.saturating_add(1)
            }
        }
    }

    fn record_invalid_for_reason(&mut self, key: &str, error: &anyhow::Error) {
        self.metrics.invalid = self.metrics.invalid.saturating_add(1);
        let reason = error.to_string();
        if reason.contains("signature") {
            self.limiter.record_invalid_signature(key);
        } else if reason.contains("replayed transaction") {
            self.limiter.record_replay(key);
        } else {
            self.limiter.record_malformed(key);
        };
    }
}

pub fn tight_test_ingress() -> TransactionIngress {
    TransactionIngress::new(PeerRateLimits {
        window: Duration::from_secs(60),
        throttle_for: Duration::from_secs(60),
        max_packets_per_window: 2,
        max_bytes_per_window: 1_000_000,
        max_malformed_per_window: 1,
        max_invalid_signatures_per_window: 1,
        max_replays_per_window: 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Instruction, Transaction};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn signed_tx(nonce: u64) -> Transaction {
        let sender = key(1);
        let program = key(2);
        let mut tx = Transaction {
            account_keys: vec![pubkey(&sender), pubkey(&program)],
            required_signer_indices: vec![0],
            signatures: Vec::new(),
            recent_blockhash: [3u8; 32],
            nonce,
            fee: 5000,
            compute_limit: 100_000,
            expiration_slot: 10,
            instructions: vec![Instruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![7, 8, 9],
            }],
        };
        tx.sign_with_keys(&[(0, sender)]).unwrap();
        tx
    }

    #[test]
    fn client_submission_accepts_valid_transaction_bytes() {
        let mut ingress = TransactionIngress::production_defaults();
        let tx = signed_tx(1);
        let encoded = tx.encode();

        let outcome = ingress.submit_quic("client-a", &encoded, 1);

        let IngressOutcome::Accepted(accepted) = outcome else {
            panic!("valid transaction was rejected");
        };
        assert_eq!(accepted.transaction, tx);
        assert_eq!(accepted.source.interface, IngressInterface::Quic);
        assert_eq!(ingress.metrics().accepted, 1);
    }

    #[test]
    fn invalid_transaction_is_rejected_with_reason() {
        let mut ingress = TransactionIngress::production_defaults();
        let mut tx = signed_tx(1);
        tx.fee += 1;

        let outcome = ingress.submit_udp("client-a", &tx.encode(), 1);

        let IngressOutcome::Rejected(rejected) = outcome else {
            panic!("invalid transaction was accepted");
        };
        assert!(matches!(rejected.reason, IngressRejectReason::Invalid(_)));
        assert!(rejected.reason.to_string().contains("signature"));
        assert_eq!(ingress.metrics().invalid, 1);
    }

    #[test]
    fn malformed_submission_is_rejected_with_clear_reason() {
        let mut ingress = TransactionIngress::production_defaults();

        let outcome = ingress.submit_rpc("client-a", b"not-a-transaction", 1);

        let IngressOutcome::Rejected(rejected) = outcome else {
            panic!("malformed transaction was accepted");
        };
        assert!(matches!(rejected.reason, IngressRejectReason::Malformed(_)));
        assert!(rejected.reason.to_string().contains("magic"));
        assert_eq!(ingress.metrics().malformed, 1);
    }

    #[test]
    fn local_submission_uses_internal_transaction_format() {
        let mut ingress = TransactionIngress::production_defaults();
        let tx = signed_tx(2);

        let outcome = ingress.submit_local("operator-cli", tx, 1);

        assert!(matches!(outcome, IngressOutcome::Accepted(_)));
        assert_eq!(ingress.metrics().local_submissions, 1);
    }

    #[test]
    fn ingress_rate_limit_rejects_noisy_source_but_allows_other_source() {
        let mut ingress = tight_test_ingress();
        let first = signed_tx(1).encode();
        let second = signed_tx(2).encode();
        let third = signed_tx(3).encode();

        assert!(matches!(
            ingress.submit_quic("noisy", &first, 1),
            IngressOutcome::Accepted(_)
        ));
        assert!(matches!(
            ingress.submit_quic("noisy", &second, 1),
            IngressOutcome::Accepted(_)
        ));
        let outcome = ingress.submit_quic("noisy", &third, 1);
        assert!(matches!(
            outcome,
            IngressOutcome::Rejected(RejectedSubmission {
                reason: IngressRejectReason::RateLimited(PeerLimitReason::PacketRate),
                ..
            })
        ));

        let steady = signed_tx(4).encode();
        assert!(matches!(
            ingress.submit_quic("steady", &steady, 1),
            IngressOutcome::Accepted(_)
        ));
        assert_eq!(ingress.metrics().rate_limited, 1);
        assert!(
            ingress
                .metrics_text()
                .contains("rpkv2_transaction_ingress_rate_limited_total 1")
        );
    }

    #[test]
    fn replay_submission_is_rejected_and_metered() {
        let mut ingress = TransactionIngress::production_defaults();
        let tx = signed_tx(5);
        let encoded = tx.encode();

        assert!(matches!(
            ingress.submit_rpc("client-a", &encoded, 1),
            IngressOutcome::Accepted(_)
        ));
        let outcome = ingress.submit_rpc("client-a", &encoded, 1);

        let IngressOutcome::Rejected(rejected) = outcome else {
            panic!("replay was accepted");
        };
        assert!(rejected.reason.to_string().contains("replayed transaction"));
        assert_eq!(ingress.metrics().invalid, 1);
    }
}
