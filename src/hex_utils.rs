use anyhow::{Result, anyhow, bail};

pub(crate) fn validate(field: &str, value: &str) -> Result<()> {
    if !value.len().is_multiple_of(2) {
        bail!("{field} must contain an even number of hex characters");
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{field} contains non-hex characters");
    }
    Ok(())
}

pub(crate) fn decode(field: &str, value: &str) -> Result<Vec<u8>> {
    validate(field, value)?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("validated hex is ASCII");
            u8::from_str_radix(digits, 16)
                .map_err(|_| anyhow!("{field} contains non-hex characters"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_mixed_case_hex() {
        assert_eq!(decode("value", "00aBff").unwrap(), [0x00, 0xab, 0xff]);
    }

    #[test]
    fn rejects_odd_non_hex_and_non_ascii_inputs() {
        assert!(validate("value", "abc").is_err());
        assert!(decode("value", "zz").is_err());
        assert!(decode("value", "é").is_err());
    }
}
