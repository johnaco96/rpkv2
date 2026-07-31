use crate::wire::Cursor as WireCursor;
use anyhow::{Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"rpkv2.transaction.v1";
const WIRE_MAGIC: &[u8; 4] = b"RPKT";
pub const TRANSACTION_VERSION: u8 = 1;
const HASH_LEN: usize = 32;
const PUBKEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const MAX_ACCOUNT_KEYS: usize = 64;
const MAX_SIGNERS: usize = 64;
const MAX_SIGNATURES: usize = 64;
const MAX_INSTRUCTIONS: usize = 64;
const MAX_INSTRUCTION_ACCOUNTS: usize = 64;
const MAX_INSTRUCTION_DATA_LEN: usize = 4096;
const MAX_COMPUTE_LIMIT: u64 = 10_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub program_id_index: u16,
    pub account_indices: Vec<u16>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionSignature {
    pub signer_index: u16,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub account_keys: Vec<[u8; 32]>,
    pub required_signer_indices: Vec<u16>,
    pub signatures: Vec<TransactionSignature>,
    pub recent_blockhash: [u8; 32],
    pub nonce: u64,
    pub fee: u64,
    pub compute_limit: u64,
    pub expiration_slot: u64,
    pub instructions: Vec<Instruction>,
}

impl Transaction {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(WIRE_MAGIC);
        out.push(TRANSACTION_VERSION);
        encode_core_fields(&mut out, self, true);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.expect(WIRE_MAGIC)?;
        let version = cursor.u8()?;
        if version != TRANSACTION_VERSION {
            bail!("unsupported transaction version: {version}");
        }

        let account_keys = cursor.pubkey_vec(MAX_ACCOUNT_KEYS)?;
        let required_signer_indices = cursor.u16_vec(MAX_SIGNERS)?;
        let signatures = cursor.signatures()?;
        let recent_blockhash = cursor.hash()?;
        let nonce = cursor.u64()?;
        let fee = cursor.u64()?;
        let compute_limit = cursor.u64()?;
        let expiration_slot = cursor.u64()?;
        let instructions = cursor.instructions()?;
        cursor.finish()?;

        let tx = Self {
            account_keys,
            required_signer_indices,
            signatures,
            recent_blockhash,
            nonce,
            fee,
            compute_limit,
            expiration_slot,
            instructions,
        };
        tx.validate_structure()?;
        Ok(tx)
    }

    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(DOMAIN);
        out.push(TRANSACTION_VERSION);
        encode_core_fields(&mut out, self, false);
        out
    }

    pub fn transaction_id(&self) -> [u8; 32] {
        let hash = blake3::hash(&self.signing_preimage());
        *hash.as_bytes()
    }

    pub fn validate_structure(&self) -> Result<()> {
        if self.account_keys.is_empty() {
            bail!("transaction must contain at least one account key");
        }
        if self.account_keys.len() > MAX_ACCOUNT_KEYS {
            bail!("transaction has too many account keys");
        }
        if self.required_signer_indices.is_empty() {
            bail!("transaction must contain at least one required signer");
        }
        if self.required_signer_indices.len() > MAX_SIGNERS {
            bail!("transaction has too many required signers");
        }
        if self.signatures.len() > MAX_SIGNATURES {
            bail!("transaction has too many signatures");
        }
        if self.recent_blockhash.iter().all(|byte| *byte == 0) {
            bail!("transaction recent_blockhash must not be all zeros");
        }
        if self.fee == 0 {
            bail!("transaction fee must be greater than zero");
        }
        if self.compute_limit == 0 || self.compute_limit > MAX_COMPUTE_LIMIT {
            bail!("transaction compute_limit is outside allowed bounds");
        }
        if self.instructions.is_empty() {
            bail!("transaction must contain at least one instruction");
        }
        if self.instructions.len() > MAX_INSTRUCTIONS {
            bail!("transaction has too many instructions");
        }

        let account_count = self.account_keys.len();
        let mut required = BTreeSet::new();
        for signer_index in &self.required_signer_indices {
            ensure_account_index(*signer_index, account_count, "required signer")?;
            if !required.insert(*signer_index) {
                bail!("duplicate required signer index: {signer_index}");
            }
        }

        let mut signed = BTreeSet::new();
        for signature in &self.signatures {
            ensure_account_index(signature.signer_index, account_count, "signature signer")?;
            if !required.contains(&signature.signer_index) {
                bail!(
                    "signature signer {} is not listed as a required signer",
                    signature.signer_index
                );
            }
            if !signed.insert(signature.signer_index) {
                bail!("duplicate signature for signer {}", signature.signer_index);
            }
        }
        if signed != required {
            bail!("transaction signatures do not exactly match required signers");
        }

        for instruction in &self.instructions {
            ensure_account_index(
                instruction.program_id_index,
                account_count,
                "instruction program id",
            )?;
            if instruction.account_indices.len() > MAX_INSTRUCTION_ACCOUNTS {
                bail!("instruction has too many account indices");
            }
            if instruction.data.len() > MAX_INSTRUCTION_DATA_LEN {
                bail!("instruction data is too large");
            }
            for account_index in &instruction.account_indices {
                ensure_account_index(*account_index, account_count, "instruction account")?;
            }
        }
        Ok(())
    }

    pub fn validate_at_slot(&self, current_slot: u64) -> Result<()> {
        self.validate_structure()?;
        if current_slot > self.expiration_slot {
            bail!(
                "transaction expired at slot {}, current slot {}",
                self.expiration_slot,
                current_slot
            );
        }
        self.verify_signatures()
    }

    pub fn verify_signatures(&self) -> Result<()> {
        self.validate_structure()?;
        let preimage = self.signing_preimage();
        for signature in &self.signatures {
            let key = self.account_keys[usize::from(signature.signer_index)];
            verify_signature(&key, &preimage, &signature.signature)?;
        }
        Ok(())
    }

    #[cfg(feature = "ed25519")]
    pub fn sign_with_keys(&mut self, keys: &[(u16, ed25519_dalek::SigningKey)]) -> Result<()> {
        use ed25519_dalek::Signer;

        self.signatures.clear();
        let preimage = self.signing_preimage();
        for signer_index in &self.required_signer_indices {
            let signing_key = keys
                .iter()
                .find(|(candidate, _)| candidate == signer_index)
                .map(|(_, key)| key)
                .ok_or_else(|| anyhow!("missing signing key for signer {signer_index}"))?;
            self.signatures.push(TransactionSignature {
                signer_index: *signer_index,
                signature: signing_key.sign(&preimage).to_bytes(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct TransactionReplay {
    accepted: BTreeMap<[u8; 32], u64>,
}

impl TransactionReplay {
    pub fn contains(&self, transaction: &Transaction) -> bool {
        self.accepted.contains_key(&transaction.transaction_id())
    }

    pub fn accept(&mut self, transaction: &Transaction, current_slot: u64) -> Result<()> {
        transaction.validate_at_slot(current_slot)?;
        let transaction_id = transaction.transaction_id();
        if self.accepted.contains_key(&transaction_id) {
            bail!("replayed transaction");
        }
        self.accepted.insert(transaction_id, current_slot);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }
}

fn encode_core_fields(out: &mut Vec<u8>, tx: &Transaction, include_signatures: bool) {
    encode_pubkey_vec(out, &tx.account_keys);
    encode_u16_vec(out, &tx.required_signer_indices);
    if include_signatures {
        encode_signatures(out, &tx.signatures);
    }
    out.extend_from_slice(&tx.recent_blockhash);
    out.extend_from_slice(&tx.nonce.to_be_bytes());
    out.extend_from_slice(&tx.fee.to_be_bytes());
    out.extend_from_slice(&tx.compute_limit.to_be_bytes());
    out.extend_from_slice(&tx.expiration_slot.to_be_bytes());
    encode_instructions(out, &tx.instructions);
}

fn encode_pubkey_vec(out: &mut Vec<u8>, keys: &[[u8; 32]]) {
    let len = u16::try_from(keys.len()).expect("too many account keys");
    out.extend_from_slice(&len.to_be_bytes());
    for key in keys {
        out.extend_from_slice(key);
    }
}

fn encode_u16_vec(out: &mut Vec<u8>, values: &[u16]) {
    let len = u16::try_from(values.len()).expect("too many u16 values");
    out.extend_from_slice(&len.to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_signatures(out: &mut Vec<u8>, signatures: &[TransactionSignature]) {
    let len = u16::try_from(signatures.len()).expect("too many signatures");
    out.extend_from_slice(&len.to_be_bytes());
    for signature in signatures {
        out.extend_from_slice(&signature.signer_index.to_be_bytes());
        out.extend_from_slice(&signature.signature);
    }
}

fn encode_instructions(out: &mut Vec<u8>, instructions: &[Instruction]) {
    let len = u16::try_from(instructions.len()).expect("too many instructions");
    out.extend_from_slice(&len.to_be_bytes());
    for instruction in instructions {
        out.extend_from_slice(&instruction.program_id_index.to_be_bytes());
        encode_u16_vec(out, &instruction.account_indices);
        let data_len = u32::try_from(instruction.data.len()).expect("instruction data too large");
        out.extend_from_slice(&data_len.to_be_bytes());
        out.extend_from_slice(&instruction.data);
    }
}

fn ensure_account_index(index: u16, account_count: usize, field: &str) -> Result<()> {
    if usize::from(index) >= account_count {
        bail!("{field} index {index} is outside account key list");
    }
    Ok(())
}

#[cfg(feature = "ed25519")]
fn verify_signature(pubkey: &[u8; 32], preimage: &[u8], signature: &[u8; 64]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| anyhow!("transaction signer key is invalid: {e}"))?;
    let signature = Signature::from_bytes(signature);
    key.verify(preimage, &signature)
        .map_err(|e| anyhow!("transaction signature is invalid: {e}"))?;
    Ok(())
}

#[cfg(not(feature = "ed25519"))]
fn verify_signature(_pubkey: &[u8; 32], _preimage: &[u8], _signature: &[u8; 64]) -> Result<()> {
    bail!("transaction signature verification requires the ed25519 feature")
}

struct Cursor<'a> {
    inner: WireCursor<'a>,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: WireCursor::new(bytes, "transaction"),
        }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        self.inner.expect(expected, "invalid transaction magic")
    }

    fn u8(&mut self) -> Result<u8> {
        self.inner.u8()
    }

    fn u16(&mut self) -> Result<u16> {
        self.inner.u16()
    }

    fn u32(&mut self) -> Result<u32> {
        self.inner.u32()
    }

    fn u64(&mut self) -> Result<u64> {
        self.inner.u64()
    }

    fn hash(&mut self) -> Result<[u8; 32]> {
        let bytes = self.take(HASH_LEN)?;
        Ok(bytes.try_into().expect("cursor returned exact hash length"))
    }

    fn pubkey_vec(&mut self, max: usize) -> Result<Vec<[u8; 32]>> {
        let len = usize::from(self.u16()?);
        if len > max {
            bail!("transaction account key count exceeds limit");
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            let bytes = self.take(PUBKEY_LEN)?;
            out.push(
                bytes
                    .try_into()
                    .expect("cursor returned exact pubkey length"),
            );
        }
        Ok(out)
    }

    fn u16_vec(&mut self, max: usize) -> Result<Vec<u16>> {
        let len = usize::from(self.u16()?);
        if len > max {
            bail!("transaction u16 vector exceeds limit");
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.u16()?);
        }
        Ok(out)
    }

    fn signatures(&mut self) -> Result<Vec<TransactionSignature>> {
        let len = usize::from(self.u16()?);
        if len > MAX_SIGNATURES {
            bail!("transaction signature count exceeds limit");
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            let signer_index = self.u16()?;
            let signature = self
                .take(SIGNATURE_LEN)?
                .try_into()
                .expect("cursor returned exact signature length");
            out.push(TransactionSignature {
                signer_index,
                signature,
            });
        }
        Ok(out)
    }

    fn instructions(&mut self) -> Result<Vec<Instruction>> {
        let len = usize::from(self.u16()?);
        if len > MAX_INSTRUCTIONS {
            bail!("transaction instruction count exceeds limit");
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            let program_id_index = self.u16()?;
            let account_indices = self.u16_vec(MAX_INSTRUCTION_ACCOUNTS)?;
            let data_len = usize::try_from(self.u32()?)
                .map_err(|_| anyhow!("instruction data length does not fit usize"))?;
            if data_len > MAX_INSTRUCTION_DATA_LEN {
                bail!("instruction data exceeds limit");
            }
            let data = self.take(data_len)?.to_vec();
            out.push(Instruction {
                program_id_index,
                account_indices,
                data,
            });
        }
        Ok(out)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        self.inner.take(len)
    }

    fn finish(&self) -> Result<()> {
        self.inner.finish()
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn instruction() -> Instruction {
        Instruction {
            program_id_index: 1,
            account_indices: vec![0],
            data: vec![7, 8, 9],
        }
    }

    fn unsigned_tx(sender_key: &SigningKey) -> Transaction {
        Transaction {
            account_keys: vec![pubkey(sender_key), pubkey(&key(2))],
            required_signer_indices: vec![0],
            signatures: Vec::new(),
            recent_blockhash: [3u8; 32],
            nonce: 42,
            fee: 5000,
            compute_limit: 100_000,
            expiration_slot: 10,
            instructions: vec![instruction()],
        }
    }

    fn signed_tx() -> (Transaction, SigningKey) {
        let sender = key(1);
        let mut tx = unsigned_tx(&sender);
        tx.sign_with_keys(&[(0, sender.clone())]).unwrap();
        (tx, sender)
    }

    #[test]
    fn transaction_encode_decode_roundtrip() {
        let (tx, _) = signed_tx();

        let decoded = Transaction::decode(&tx.encode()).unwrap();

        assert_eq!(decoded, tx);
    }

    #[test]
    fn malformed_transactions_are_rejected_deterministically() {
        assert!(Transaction::decode(&[]).is_err());
        assert!(Transaction::decode(b"RPKT\x02").is_err());

        let (mut tx, _) = signed_tx();
        tx.instructions[0].program_id_index = 9;

        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn valid_signature_is_deterministic() {
        let (tx, _) = signed_tx();

        tx.verify_signatures().unwrap();
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let (mut tx, _) = signed_tx();
        tx.fee += 1;

        assert!(tx.verify_signatures().is_err());
    }

    #[test]
    fn expired_transaction_is_rejected() {
        let (tx, _) = signed_tx();

        assert!(tx.validate_at_slot(11).is_err());
    }

    #[test]
    fn replay_transaction_is_rejected() {
        let (tx, _) = signed_tx();
        let mut replay = TransactionReplay::default();

        replay.accept(&tx, 1).unwrap();

        assert!(replay.accept(&tx, 1).is_err());
        assert_eq!(replay.len(), 1);
    }

    #[test]
    fn missing_required_signature_is_rejected() {
        let sender = key(1);
        let tx = unsigned_tx(&sender);

        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn duplicate_required_signer_is_rejected() {
        let sender = key(1);
        let mut tx = unsigned_tx(&sender);
        tx.required_signer_indices = vec![0, 0];

        assert!(tx.validate_structure().is_err());
    }
}
