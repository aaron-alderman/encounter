use crate::{Result, fail};

pub(crate) fn nonce() -> Result<String> {
    let mut bytes = [0; 24];
    getrandom::getrandom(&mut bytes).map_err(|error| fail(error.to_string()))?;
    Ok(hex::encode(bytes))
}

pub(crate) fn uuid_v4() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| fail(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}
