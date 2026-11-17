use crate::{Result, process::Meter};
use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, pkcs8::DecodePrivateKey};
use zeroize::Zeroizing;

const MAX_MESSAGE_BYTES: usize = 16_384;

pub(crate) fn signing_key_from_pem(pem: &[u8]) -> Result<SigningKey> {
    let mut lines = std::str::from_utf8(pem)?.trim().lines();
    if lines.next() != Some("-----BEGIN PRIVATE KEY-----") || lines.next_back() != Some("-----END PRIVATE KEY-----") {
        return Err(crate::fail("Expected an Ed25519 PKCS#8 private key"));
    }
    let encoded = Zeroizing::new(lines.collect::<String>());
    let der = Zeroizing::new(Base64::decode_vec(&encoded).map_err(|_| crate::fail("Invalid private key encoding"))?);
    SigningKey::from_pkcs8_der(&der).map_err(|_| crate::fail("Expected an Ed25519 PKCS#8 private key"))
}

pub(crate) fn verify_ed25519(
    message: &str, public_key: &str, signature: &str, meter: &mut Meter,
) -> Result<bool> {
    verify_ed25519_with_limit(message, public_key, signature, meter, MAX_MESSAGE_BYTES)
}

pub(crate) fn verify_transit_ed25519(message: &str, public_key: &str, signature: &str, meter: &mut Meter) -> Result<bool> {
    verify_ed25519_with_limit(message, public_key, signature, meter, 65_536)
}

pub(crate) fn verify_publication_ed25519(message: &str, public_key: &str, signature: &str, meter: &mut Meter) -> Result<bool> {
    verify_ed25519_with_limit(message, public_key, signature, meter, 4 * 1024 * 1024)
}

fn verify_ed25519_with_limit(message: &str, public_key: &str, signature: &str, meter: &mut Meter, limit: usize) -> Result<bool> {
    if message.len() > limit {
        return Ok(false);
    }
    let (Some(key), Some(signature)) = (decode_hex::<32>(public_key), decode_hex::<64>(signature)) else {
        return Ok(false);
    };

    // Dalek accepts some noncanonical public-key encodings when decoding points.
    // Require canonical encodings for both the key and R, as in the Node host.
    let r = signature.first_chunk::<32>().expect("Ed25519 signature contains R");
    if !canonical_point(&key) || !canonical_point(r) {
        return Ok(false);
    }
    meter.charge(message.len() + 2_048)?;
    Ok(VerifyingKey::from_bytes(&key).is_ok_and(|key| {
        key.verify_strict(message.as_bytes(), &Signature::from_bytes(&signature)).is_ok()
    }))
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return None;
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes).ok()?;
    Some(bytes)
}

fn canonical_point(point: &[u8; 32]) -> bool {
    const FIELD_PRIME: [u8; 32] = {
        let mut prime = [0xff; 32];
        prime[0] = 0xed;
        prime[31] = 0x7f;
        prime
    };
    let mut y = *point;
    y[31] &= 0x7f;
    y.iter().rev().cmp(FIELD_PRIME.iter().rev()).is_lt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verifies_exact_utf8_bytes_and_charges_the_shared_meter() {
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let key = hex::encode(signing_key.verifying_key().as_bytes());
        let message = "Exact text · π\n";
        let signature = hex::encode(signing_key.sign(message.as_bytes()).to_bytes());
        let mut meter = Meter::new(message.len() + 2_048);
        assert!(verify_ed25519(message, &key, &signature, &mut meter).unwrap());
        assert!(verify_ed25519(message, &key, &signature, &mut meter).is_err());
        assert!(!verify_ed25519(message.trim_end(), &key, &signature, &mut Meter::new(20_000)).unwrap());
    }

    #[test]
    fn refuses_malformed_noncanonical_and_weak_inputs() {
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let key = hex::encode(signing_key.verifying_key().as_bytes());
        let message = "test";
        let signature = signing_key.sign(message.as_bytes()).to_bytes();
        let valid = hex::encode(signature);
        let identity = format!("01{}", "00".repeat(31));
        let noncanonical_y = format!("ed{}7f", "ff".repeat(30));
        let mut invalid_scalar = signature;
        invalid_scalar[32..].fill(0xff);
        let invalid_scalar = hex::encode(invalid_scalar);
        for (key, signature) in [
            (key.to_uppercase(), valid.clone()),
            (key.clone(), "00".repeat(63)),
            (key.clone(), format!("{}{}", &valid[..126], "zz")),
            (identity.clone(), format!("{}{}", identity, "00".repeat(32))),
            (noncanonical_y.clone(), valid.clone()),
            (key.clone(), format!("{}{}", noncanonical_y, &valid[64..])),
            (key.clone(), invalid_scalar),
        ] {
            assert!(!verify_ed25519(message, &key, &signature, &mut Meter::new(20_000)).unwrap());
        }
        let oversized = "é".repeat(MAX_MESSAGE_BYTES / 2 + 1);
        assert!(!verify_ed25519(&oversized, &key, &valid, &mut Meter::new(0)).unwrap());
    }
}
