use anyhow::{anyhow, Result};
use bloomfilter::Bloom;
use std::time::{Duration, Instant};

/// Fixed header for stateless UDP “validator path”.
/// Layout (network byte order / big-endian):
///  v:1 | msg_type:1 | flags:2 | slot:8 | nonce:8 | key_id:2 | pubkey:32 | signature:64
/// Total = 1+1+2+8+8+2+32+64 = 118 bytes.
pub const HEADER_LEN: usize = 118;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub v: u8,
    pub msg_type: u8,
    pub flags: u16,
    pub slot: u64,
    pub nonce: u64,
    pub key_id: u16,
    pub pubkey: [u8; 32],
    pub signature: [u8; 64],
}

impl Default for Header {
    fn default() -> Self {
        Self {
            v: 1,
            msg_type: 0,
            flags: 0,
            slot: 0,
            nonce: 0,
            key_id: 0,
            pubkey: [0; 32],
            signature: [0; 64],
        }
    }
}

impl Header {
    /// Encode into `buf` (must be at least `HEADER_LEN` long).
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!(
                "encode_into: buffer too small (need {})",
                HEADER_LEN
            ));
        }
        buf[0] = self.v;
        buf[1] = self.msg_type;
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..12].copy_from_slice(&self.slot.to_be_bytes());
        buf[12..20].copy_from_slice(&self.nonce.to_be_bytes());
        buf[20..22].copy_from_slice(&self.key_id.to_be_bytes());
        buf[22..54].copy_from_slice(&self.pubkey);
        buf[54..118].copy_from_slice(&self.signature);
        Ok(HEADER_LEN)
    }

    /// Decode header from the start of `buf`. Returns (header, bytes_consumed).
    pub fn decode_from(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!(
                "decode_from: buffer too small (have {}, need {})",
                buf.len(),
                HEADER_LEN
            ));
        }
        let v = buf[0];
        let msg_type = buf[1];
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let slot = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let nonce = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        let key_id = u16::from_be_bytes(buf[20..22].try_into().unwrap());
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&buf[22..54]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[54..118]);

        Ok((
            Header {
                v,
                msg_type,
                flags,
                slot,
                nonce,
                key_id,
                pubkey,
                signature,
            },
            HEADER_LEN,
        ))
    }

    /// Return payload slice given the full datagram bytes.
    pub fn payload<'a>(buf: &'a [u8]) -> Result<&'a [u8]> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!("payload: buffer too small"));
        }
        Ok(&buf[HEADER_LEN..])
    }
}

/// Replay filter for (slot, nonce) tuples.
/// Uses a Bloom filter for compact membership and a moving "freshness" window.
pub struct ReplayFilter {
    bloom: Bloom<[u8; 32]>,
    capacity: usize,
    fp_rate: f64,
    head_slot: u64,
    window: u64,
    last_cleanup: Instant,
    cleanup_period: Duration,
}

impl ReplayFilter {
    /// Create a replay filter.
    ///
    /// * `capacity` — expected unique keys in the active window
    /// * `fp_rate` — false positive rate target (e.g. 1e-6)
    /// * `window` — how many slots behind the current head are considered fresh
    /// * `cleanup_ms` — how often to rebuild the Bloom filter
    pub fn new(capacity: usize, fp_rate: f64, window: u64, cleanup_ms: u64) -> Self {
        let bloom = Bloom::new_for_fp_rate(capacity, fp_rate);
        Self {
            bloom,
            capacity,
            fp_rate,
            head_slot: 0,
            window,
            last_cleanup: Instant::now(),
            cleanup_period: Duration::from_millis(cleanup_ms.max(1)),
        }
    }

    /// Returns true if we've seen `sig` before; otherwise inserts and returns false.
    pub fn seen_or_insert(&mut self, sig: [u8; 32]) -> bool {
        if self.bloom.check(&sig) {
            true
        } else {
            self.bloom.set(&sig);
            false
        }
    }

    #[inline]
    fn key32(slot: u64, nonce: u64) -> [u8; 32] {
        // 16 bytes of (slot||nonce) big-endian, rest zeroed to 32 bytes.
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&slot.to_be_bytes());
        out[8..16].copy_from_slice(&nonce.to_be_bytes());
        out
    }

    /// Returns true if (slot, nonce) is fresh and not seen before; inserts it.
    pub fn accept(&mut self, slot: u64, nonce: u64) -> bool {
        // Reject too-old slots quickly.
        if slot + self.window < self.head_slot {
            return false;
        }
        if slot > self.head_slot {
            self.head_slot = slot;
        }

        let k = Self::key32(slot, nonce);
        if self.bloom.check(&k) {
            // likely replay (or Bloom FP)
            false
        } else {
            self.bloom.set(&k);
            true
        }
    }

    /// Periodic cleanup hook — rebuild a fresh Bloom to drop very old keys.
    pub fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed() < self.cleanup_period {
            return;
        }
        self.bloom = Bloom::new_for_fp_rate(self.capacity, self.fp_rate);
        self.last_cleanup = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Header {
            v: 1,
            msg_type: 2,
            flags: 3,
            slot: 42,
            nonce: 9,
            key_id: 7,
            pubkey: [1u8; 32],
            signature: [2u8; 64],
        };
        let mut buf = vec![0u8; HEADER_LEN];
        let n = h.encode_into(&mut buf).unwrap();
        assert_eq!(n, HEADER_LEN);

        let (h2, used) = Header::decode_from(&buf).unwrap();
        assert_eq!(used, HEADER_LEN);
        assert_eq!(h, h2);
    }

    #[test]
    fn replay_filter_basic() {
        let mut rf = ReplayFilter::new(1 << 20, 1e-6, 1024, 100);
        assert!(rf.accept(100, 1));
        assert!(!rf.accept(100, 1)); // replay
        assert!(rf.accept(101, 1)); // new slot
        assert!(!rf.accept(10, 1)); // too old
    }
}
