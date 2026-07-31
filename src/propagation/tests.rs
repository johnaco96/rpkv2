use super::*;
use crate::{
    ledger::{LedgerEntry, TransactionBatch},
    validator_set::{ValidatorIdentityRecord, ValidatorSet},
};
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

fn validator_id(id: &str) -> ValidatorId {
    ValidatorId::from_str(id).unwrap()
}

fn hash(byte: u8) -> LedgerHash {
    [byte; HASH_LEN]
}

fn validator_set(a_key: &SigningKey, b_key: &SigningKey) -> ValidatorSet {
    let mut set = ValidatorSet::default();
    set.insert(ValidatorIdentityRecord {
        validator_id: validator_id("validator-a"),
        tls_spki_der: b"validator-a-spki".to_vec(),
        packet_signing_key: [11u8; 32],
        consensus_voting_key: pubkey(a_key),
        voting_weight: 1,
        activation: EpochSlot::new(0, 0),
        deactivation: None,
    })
    .unwrap();
    set.insert(ValidatorIdentityRecord {
        validator_id: validator_id("validator-b"),
        tls_spki_der: b"validator-b-spki".to_vec(),
        packet_signing_key: [12u8; 32],
        consensus_voting_key: pubkey(b_key),
        voting_weight: 1,
        activation: EpochSlot::new(0, 0),
        deactivation: None,
    })
    .unwrap();
    set
}

fn leader_block(slot: u64) -> LedgerBlock {
    let batch = TransactionBatch::new(0, vec![b"tx-a".to_vec()]).unwrap();
    let entry = LedgerEntry::new(0, hash(7), vec![batch]).unwrap();
    LedgerBlock::new(
        EpochSlot::new(0, slot),
        hash(7),
        validator_id("validator-a"),
        vec![entry],
        [9u8; SIGNATURE_LEN],
    )
    .unwrap()
}

#[test]
fn multi_node_propagation_accepts_valid_blocks_and_shreds() {
    let key_a = key(101);
    let key_b = key(102);
    let set = validator_set(&key_a, &key_b);
    let block = leader_block(0);
    let shreds = LedgerShred::from_block(&block, 32).unwrap();
    let block_message =
        PropagationMessage::Block(BlockPropagation::sign(block.clone(), &key_a).unwrap());
    let sender = PropagationSender::new(PropagationTransport::QuicDatagram);
    let outbound = sender
        .enqueue(
            validator_id("validator-b"),
            SocketAddr::from(([127, 0, 0, 1], 4433)),
            &block_message,
        )
        .unwrap();
    let mut receiver = PropagationReceiver::new(&set);

    assert_eq!(
        outbound.target.transport,
        PropagationTransport::QuicDatagram
    );
    assert!(matches!(
        receiver.handle_encoded(&outbound.bytes).unwrap(),
        PropagationOutcome::BlockAccepted(_)
    ));
    for shred in shreds {
        let message = PropagationMessage::Shred(
            ShredPropagation::sign(validator_id("validator-a"), shred, &key_a).unwrap(),
        );
        assert!(matches!(
            receiver.handle_encoded(&message.encode().unwrap()).unwrap(),
            PropagationOutcome::ShredAccepted { .. }
        ));
    }

    assert!(receiver.store().get_block(&block.block_hash).is_some());
    assert_eq!(receiver.metrics().blocks_received, 1);
    assert!(receiver.metrics().shreds_received > 0);
}

#[test]
fn corrupt_shred_is_rejected_and_metered() {
    let key_a = key(101);
    let key_b = key(102);
    let set = validator_set(&key_a, &key_b);
    let block = leader_block(0);
    let mut shred = LedgerShred::from_block(&block, 32).unwrap().remove(0);
    shred.payload[0] ^= 0xff;
    let message = PropagationMessage::Shred(
        ShredPropagation::sign(validator_id("validator-a"), shred, &key_a).unwrap(),
    );
    let mut receiver = PropagationReceiver::new(&set);

    assert!(receiver.handle_message(message).is_err());
    assert_eq!(receiver.metrics().corrupt_shreds, 1);
}

#[test]
fn missing_data_can_be_repaired_from_peer_response() {
    let key_a = key(101);
    let key_b = key(102);
    let set = validator_set(&key_a, &key_b);
    let block = leader_block(0);
    let shreds = LedgerShred::from_block(&block, 32).unwrap();
    let mut source_store = PropagationStore::default();
    for shred in &shreds {
        source_store.put_shred(shred.clone());
    }
    let mut source = PropagationReceiver::with_store(&set, source_store);
    let request = RepairRequest::sign(
        validator_id("validator-b"),
        block.slot,
        block.block_hash,
        vec![1],
        &key_b,
    )
    .unwrap();

    let response = match source
        .handle_message(PropagationMessage::RepairRequest(request))
        .unwrap()
    {
        PropagationOutcome::RepairRequestAccepted { requester, shreds } => {
            RepairResponse::sign(validator_id("validator-a"), requester, shreds, &key_a).unwrap()
        }
        other => panic!("unexpected repair request outcome: {other:?}"),
    };

    let mut sink = PropagationReceiver::new(&set);
    for shred in shreds.iter().filter(|shred| shred.index != 1) {
        sink.store.put_shred(shred.clone());
    }

    let outcome = sink
        .handle_message(PropagationMessage::RepairResponse(response))
        .unwrap();

    assert!(matches!(
        outcome,
        PropagationOutcome::RepairResponseAccepted {
            shreds: 1,
            reconstructed_block: Some(_)
        }
    ));
    assert!(sink.store().get_block(&block.block_hash).is_some());
    assert_eq!(sink.metrics().repair_responses_received, 1);
}

#[test]
fn non_leader_block_is_rejected() {
    let key_a = key(101);
    let key_b = key(102);
    let set = validator_set(&key_a, &key_b);
    let batch = TransactionBatch::new(0, vec![b"tx-b".to_vec()]).unwrap();
    let entry = LedgerEntry::new(0, hash(8), vec![batch]).unwrap();
    let block = LedgerBlock::new(
        EpochSlot::new(0, 0),
        hash(8),
        validator_id("validator-b"),
        vec![entry],
        [8u8; SIGNATURE_LEN],
    )
    .unwrap();
    let message = PropagationMessage::Block(BlockPropagation::sign(block, &key_b).unwrap());
    let mut receiver = PropagationReceiver::new(&set);

    assert!(receiver.handle_message(message).is_err());
    assert_eq!(receiver.metrics().invalid_leaders, 1);
}
