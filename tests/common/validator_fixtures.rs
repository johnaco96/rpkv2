pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn verify_key_hex(seed: u8) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    hex(&signing_key.verifying_key().to_bytes())
}
