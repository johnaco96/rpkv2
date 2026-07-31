use anyhow::{Result, anyhow, bail};

/// Bounds-checked reader shared by the project's binary wire formats.
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    context: &'static str,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8], context: &'static str) -> Self {
        Self {
            bytes,
            offset: 0,
            context,
        }
    }

    pub(crate) fn expect(&mut self, expected: &[u8], error: &'static str) -> Result<()> {
        if self.take(expected.len())? != expected {
            bail!(error);
        }
        Ok(())
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| anyhow!("{} contained an invalid fixed-width field", self.context))
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow!("{} length overflow", self.context))?;
        if end > self.bytes.len() {
            bail!("truncated {}", self.context);
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            bail!("{} has trailing bytes", self.context);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fixed_width_values_and_rejects_trailing_bytes() {
        let mut cursor = Cursor::new(&[7, 0, 2, 9], "test payload");
        assert_eq!(cursor.u8().unwrap(), 7);
        assert_eq!(cursor.u16().unwrap(), 2);
        assert!(cursor.finish().is_err());
        assert_eq!(cursor.u8().unwrap(), 9);
        cursor.finish().unwrap();
    }

    #[test]
    fn rejects_truncated_fields() {
        let mut cursor = Cursor::new(&[0, 1, 2], "test payload");
        assert!(cursor.u64().is_err());
    }
}
