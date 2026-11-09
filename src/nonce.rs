use crate::{Result, fail};

pub(crate) fn nonce() -> Result<String> {
    let mut bytes = [0; 24];
    getrandom::getrandom(&mut bytes).map_err(|error| fail(error.to_string()))?;
    Ok(hex::encode(bytes))
}
