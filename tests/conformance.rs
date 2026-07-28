use ed25519_dalek::SigningKey;
use rpkv2::{
    consensus_messages::{BlockProposal, ConsensusMessage, ConsensusMessageVerifier, Vote},
    consensus_safety::ConsensusSafetyState,
    gossip::GOSSIP_VERSION,
    ledger::{LEDGER_VERSION, LedgerBlock, LedgerEntry, LedgerShred, TransactionBatch},
    propagation::{
        PROPAGATION_VERSION, PropagationMessage, PropagationOutcome, PropagationReceiver,
        PropagationTransport, ShredPropagation,
    },
    snapshot::{LedgerSnapshot, SNAPSHOT_VERSION},
    state::StateDb,
    transaction::{Instruction, TRANSACTION_VERSION, Transaction},
    transaction_ingress::{IngressOutcome, TransactionIngress},
    validator_set::{EpochSlot, ValidatorSet},
};
use std::str::FromStr;

const MANIFEST: &str = include_str!("fixtures/conformance/v1/manifest.toml");
const GENESIS: &str = include_str!("fixtures/conformance/v1/genesis.toml");
const VALIDATORS: &str = include_str!("fixtures/conformance/v1/validators.toml");

#[test]
fn conformance_fixture_manifest_is_versioned_and_release_blocking() {
    let manifest: toml::Value = toml::from_str(MANIFEST).unwrap();

    assert_eq!(manifest["fixture_version"].as_integer(), Some(1));
    assert_eq!(
        manifest["compatibility_target"].as_str(),
        Some("custom-rpkv2")
    );
    assert_eq!(
        manifest["release_gate"]["compatibility_failures_block_release"].as_bool(),
        Some(true)
    );
    assert_eq!(manifest["release_gate"]["run_in_ci"].as_bool(), Some(true));
    assert_eq!(
        manifest["versions"]["transaction"].as_integer(),
        Some(i64::from(TRANSACTION_VERSION))
    );
    assert_eq!(
        manifest["versions"]["ledger"].as_integer(),
        Some(i64::from(LEDGER_VERSION))
    );
    assert_eq!(
        manifest["versions"]["snapshot"].as_integer(),
        Some(i64::from(SNAPSHOT_VERSION))
    );
    assert_eq!(
        manifest["versions"]["consensus_message"].as_integer(),
        Some(1)
    );
    assert_eq!(
        manifest["versions"]["propagation"].as_integer(),
        Some(i64::from(PROPAGATION_VERSION))
    );
    assert_eq!(GOSSIP_VERSION, 1);
}

#[test]
fn conformance_fixtures_load_genesis_and_public_validator_identities() {
    let keys = FixtureKeys::new();

    let state = StateDb::from_genesis_toml_str(GENESIS).unwrap();
    let validators = ValidatorSet::from_toml_str(VALIDATORS).unwrap();

    assert_eq!(state.accounts().count(), 2);
    assert_eq!(validators.len(), 2);
    assert_eq!(
        validators
            .get(&validator_id("validator-a"))
            .unwrap()
            .consensus_voting_key,
        keys.validator_a.verifying_key().to_bytes()
    );
    assert_eq!(
        validators
            .get(&validator_id("validator-b"))
            .unwrap()
            .consensus_voting_key,
        keys.validator_b.verifying_key().to_bytes()
    );
}

#[test]
fn conformance_suite_accepts_declared_rpkv2_protocol_surfaces() {
    let state = StateDb::from_genesis_toml_str(GENESIS).unwrap();
    let validators = ValidatorSet::from_toml_str(VALIDATORS).unwrap();
    let keys = FixtureKeys::new();

    let transaction = fixture_transaction(&keys.transaction_signer, 1);
    let mut ingress = TransactionIngress::production_defaults();
    let accepted = ingress.submit_quic("client-a", &transaction.encode(), 1);
    assert!(matches!(accepted, IngressOutcome::Accepted(_)));

    let block = fixture_block(&transaction);
    let proposal = BlockProposal::sign(
        block.slot,
        validator_id("validator-a"),
        block.parent_hash,
        block.block_hash,
        block.entries[0].entry_hash,
        &keys.validator_a,
    );
    let vote = Vote::sign(
        block.slot,
        validator_id("validator-b"),
        block.block_hash,
        &keys.validator_b,
    );
    let decoded_proposal =
        ConsensusMessage::decode(&ConsensusMessage::BlockProposal(proposal.clone()).encode())
            .unwrap();
    let decoded_vote =
        ConsensusMessage::decode(&ConsensusMessage::Vote(vote.clone()).encode()).unwrap();
    let mut verifier = ConsensusMessageVerifier::new(&validators);
    match decoded_proposal {
        ConsensusMessage::BlockProposal(proposal) => {
            verifier.validate_block_proposal(&proposal).unwrap();
        }
        _ => panic!("decoded wrong consensus message kind"),
    }
    match decoded_vote {
        ConsensusMessage::Vote(vote) => {
            verifier.accept_vote(&vote).unwrap();
        }
        _ => panic!("decoded wrong consensus message kind"),
    }

    let shreds = LedgerShred::from_block(&block, 64).unwrap();
    let mut propagation = PropagationReceiver::new(&validators);
    for shred in &shreds {
        let message = PropagationMessage::Shred(
            ShredPropagation::sign(
                validator_id("validator-a"),
                shred.clone(),
                &keys.validator_a,
            )
            .unwrap(),
        );
        assert!(matches!(
            propagation
                .handle_encoded(&message.encode().unwrap())
                .unwrap(),
            PropagationOutcome::ShredAccepted { .. }
        ));
    }
    assert_eq!(propagation.metrics().shreds_received, shreds.len() as u64);

    let snapshot = LedgerSnapshot::create(
        block.slot,
        block.block_hash,
        &state,
        &validators,
        &ConsensusSafetyState::default(),
        [9u8; 64],
    )
    .unwrap();
    let decoded_snapshot = LedgerSnapshot::decode(&snapshot.encode().unwrap()).unwrap();
    assert_eq!(decoded_snapshot.snapshot_hash, snapshot.snapshot_hash);
    assert_eq!(
        decoded_snapshot.validator_set().unwrap().len(),
        validators.len()
    );
}

#[test]
fn conformance_suite_rejects_invalid_and_foreign_inputs() {
    let validators = ValidatorSet::from_toml_str(VALIDATORS).unwrap();
    let keys = FixtureKeys::new();
    let transaction = fixture_transaction(&keys.transaction_signer, 1);
    let block = fixture_block(&transaction);
    let mut ingress = TransactionIngress::production_defaults();

    let mut invalid_transaction = transaction.clone();
    invalid_transaction.fee += 1;
    assert!(matches!(
        ingress.submit_rpc("client-a", &invalid_transaction.encode(), 1),
        IngressOutcome::Rejected(_)
    ));
    assert!(ConsensusMessage::decode(b"solana-vote-wire-format").is_err());
    assert!(PropagationMessage::decode(b"solana-shred-wire-format").is_err());
    assert!(LedgerSnapshot::decode(b"solana-snapshot-format").is_err());

    let mut corrupt_shred = LedgerShred::from_block(&block, 64).unwrap().remove(0);
    corrupt_shred.payload[0] ^= 0xff;
    let message = PropagationMessage::Shred(
        ShredPropagation::sign(
            validator_id("validator-a"),
            corrupt_shred,
            &keys.validator_a,
        )
        .unwrap(),
    );
    let mut propagation = PropagationReceiver::new(&validators);
    assert!(propagation.handle_message(message).is_err());
    assert_eq!(propagation.metrics().corrupt_shreds, 1);
}

#[test]
fn conformance_sender_plans_transport_without_changing_wire_bytes() {
    let keys = FixtureKeys::new();
    let transaction = fixture_transaction(&keys.transaction_signer, 2);
    let block = fixture_block(&transaction);
    let shred = LedgerShred::from_block(&block, 128).unwrap().remove(0);
    let message = PropagationMessage::Shred(
        ShredPropagation::sign(validator_id("validator-a"), shred, &keys.validator_a).unwrap(),
    );
    let udp = rpkv2::propagation::PropagationSender::new(PropagationTransport::UdpPacket)
        .enqueue(
            validator_id("validator-b"),
            "127.0.0.1:9000".parse().unwrap(),
            &message,
        )
        .unwrap();
    let stream = rpkv2::propagation::PropagationSender::new(PropagationTransport::Stream)
        .enqueue(
            validator_id("validator-b"),
            "127.0.0.1:9000".parse().unwrap(),
            &message,
        )
        .unwrap();

    assert_eq!(udp.bytes, stream.bytes);
    assert_eq!(udp.target.transport, PropagationTransport::UdpPacket);
    assert_eq!(stream.target.transport, PropagationTransport::Stream);
}

struct FixtureKeys {
    validator_a: SigningKey,
    validator_b: SigningKey,
    transaction_signer: SigningKey,
}

impl FixtureKeys {
    fn new() -> Self {
        Self {
            validator_a: SigningKey::from_bytes(&[101u8; 32]),
            validator_b: SigningKey::from_bytes(&[102u8; 32]),
            transaction_signer: SigningKey::from_bytes(&[77u8; 32]),
        }
    }
}

fn fixture_transaction(signer: &SigningKey, nonce: u64) -> Transaction {
    let mut transaction = Transaction {
        account_keys: vec![signer.verifying_key().to_bytes(), [44u8; 32]],
        required_signer_indices: vec![0],
        signatures: Vec::new(),
        recent_blockhash: [55u8; 32],
        nonce,
        fee: 5000,
        compute_limit: 100_000,
        expiration_slot: 10,
        instructions: vec![Instruction {
            program_id_index: 1,
            account_indices: vec![0],
            data: vec![1, 2, 3, 4],
        }],
    };
    transaction.sign_with_keys(&[(0, signer.clone())]).unwrap();
    transaction
}

fn fixture_block(transaction: &Transaction) -> LedgerBlock {
    let batch = TransactionBatch::new(0, vec![transaction.encode()]).unwrap();
    let entry = LedgerEntry::new(0, [7u8; 32], vec![batch]).unwrap();
    LedgerBlock::new(
        EpochSlot::new(0, 0),
        [7u8; 32],
        validator_id("validator-a"),
        vec![entry],
        [8u8; 64],
    )
    .unwrap()
}

fn validator_id(id: &str) -> rpkv2::identity::ValidatorId {
    rpkv2::identity::ValidatorId::from_str(id).unwrap()
}
