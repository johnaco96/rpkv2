#[cfg(feature = "ed25519")]
pub mod ed25519_backend {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// Verify a batch and return one result per input item.
    ///
    /// With `dalek_batch`, a successful batch check avoids individual
    /// verification. A failed batch is checked item by item so callers still
    /// receive precise results.
    pub fn verify_batch(keys: &[VerifyingKey], msgs: &[&[u8]], sigs: &[Signature]) -> Vec<bool> {
        assert_eq!(keys.len(), msgs.len());
        assert_eq!(msgs.len(), sigs.len());

        #[cfg(feature = "dalek_batch")]
        if ed25519_dalek::verify_batch(msgs, sigs, keys).is_ok() {
            return vec![true; keys.len()];
        }

        keys.iter()
            .zip(msgs)
            .zip(sigs)
            .map(|((key, msg), signature)| key.verify(msg, signature).is_ok())
            .collect()
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::ed25519_backend::verify_batch;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn batch_verification_returns_per_item_results() {
        let first = SigningKey::generate(&mut OsRng);
        let second = SigningKey::generate(&mut OsRng);
        let first_message = b"first message";
        let second_message = b"second message";
        let tampered_message = b"tampered message";

        let keys = vec![first.verifying_key(), second.verifying_key()];
        let signatures = vec![
            Signature::from_bytes(&first.sign(first_message).to_bytes()),
            Signature::from_bytes(&second.sign(second_message).to_bytes()),
        ];
        let messages = vec![first_message.as_slice(), tampered_message.as_slice()];

        assert_eq!(
            verify_batch(&keys, &messages, &signatures),
            vec![true, false]
        );
    }
}
