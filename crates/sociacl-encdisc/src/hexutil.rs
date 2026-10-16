use crate::error::EncDiscError;

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Lowercase hex only. Uppercase and odd lengths fail closed.
pub fn decode_hex(text: &str) -> Result<Vec<u8>, EncDiscError> {
    if text.len() % 2 != 0 {
        return Err(EncDiscError::BadKey);
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_nibble(bytes[index])?;
        let lo = hex_nibble(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

pub fn decode_hex_array<const N: usize>(text: &str) -> Result<[u8; N], EncDiscError> {
    let bytes = decode_hex(text)?;
    if bytes.len() != N {
        return Err(EncDiscError::BadKey);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, EncDiscError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(EncDiscError::BadKey),
    }
}
