use zeroize::Zeroizing;

use crate::error::EncDiscError;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of public bytes: hashes, signatures, and ciphertext.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    write_hex(&mut out, bytes);
    out
}

/// Lowercase hex of key material. The one `String` is wiped on drop.
pub fn encode_secret_hex(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(encode_hex(bytes))
}

/// Lowercase hex only. Uppercase and odd lengths fail closed.
pub fn decode_hex(text: &str) -> Result<Vec<u8>, EncDiscError> {
    let bytes = decode_secret_vec(text)?;
    Ok(bytes.to_vec())
}

/// Decoded key bytes. The `Vec` is wiped on drop.
pub fn decode_secret_vec(text: &str) -> Result<Zeroizing<Vec<u8>>, EncDiscError> {
    if text.len() % 2 != 0 {
        return Err(EncDiscError::BadKey);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() / 2));
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

/// Fixed-length decode whose `Vec` is wiped before the array is returned.
///
/// Kept for callers that still want a plain array. A key that must stay
/// wiped belongs in [`decode_secret_array`].
#[allow(dead_code)]
pub fn decode_hex_array<const N: usize>(text: &str) -> Result<[u8; N], EncDiscError> {
    let bytes = decode_secret_array::<N>(text)?;
    Ok(*bytes)
}

/// Fixed-length key bytes. The array is wiped on drop.
pub fn decode_secret_array<const N: usize>(text: &str) -> Result<Zeroizing<[u8; N]>, EncDiscError> {
    let bytes = decode_secret_vec(text)?;
    if bytes.len() != N {
        return Err(EncDiscError::BadKey);
    }
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn write_hex(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn hex_nibble(byte: u8) -> Result<u8, EncDiscError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(EncDiscError::BadKey),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_hex_array, decode_secret_array, encode_hex, encode_secret_hex};
    use zeroize::Zeroizing;

    #[test]
    fn secret_hex_round_trip_stays_in_zeroizing_storage() {
        let key = [0x11u8; 32];
        let hex: Zeroizing<String> = encode_secret_hex(&key);
        assert_eq!(hex.as_str(), encode_hex(&key));
        let back: Zeroizing<[u8; 32]> = decode_secret_array(hex.as_str()).unwrap();
        assert_eq!(back.as_slice(), &key);
        let plain: [u8; 32] = decode_hex_array(hex.as_str()).unwrap();
        assert_eq!(plain, key);
    }
}
