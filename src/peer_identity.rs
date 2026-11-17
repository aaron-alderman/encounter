use crate::{Result, fail};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const SUITE: &str = "temple3.ed25519-sha256/v0.1";
const MAX_MESSAGE_BYTES: usize = 16_384;
const MAX_STATEMENT_DEPTH: usize = 16;

pub(crate) struct PeerIdentity {
    temple_id: String,
    actor: String,
    public_key: String,
    key_id: String,
    key: SigningKey,
}

impl PeerIdentity {
    pub(crate) fn read(seed_file: &Path, temple_id: &str, actor: &str) -> Result<Self> {
        if !is_token(temple_id) || !is_token(actor) {
            return Err(fail("invalid Temple or actor identifier"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(seed_file)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(fail("expected a private Temple seed file"));
        }

        let mut bytes = Vec::with_capacity(66);
        file.take(66).read_to_end(&mut bytes)?;
        let text = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        let mut seed = [0; 32];
        let valid = text.len() == 64
            && text
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            && hex::decode_to_slice(text, &mut seed).is_ok();
        bytes.fill(0);
        if !valid {
            return Err(fail(
                "Temple seed file must contain one lowercase 64-digit hex seed",
            ));
        }
        let key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        Self::from_key(key, temple_id, actor)
    }

    fn from_key(key: SigningKey, temple_id: &str, actor: &str) -> Result<Self> {
        let public_key = hex::encode(key.verifying_key().as_bytes());
        let key_bytes = serde_json::to_vec(&json!({"publicKey": public_key, "suite": SUITE}))?;
        let key_id = format!("key:sha256:{}", hex::encode(Sha256::digest(key_bytes)));
        Ok(Self {
            temple_id: temple_id.to_owned(),
            actor: actor.to_owned(),
            public_key,
            key_id,
            key,
        })
    }

    pub(crate) fn temple_id(&self) -> &str {
        &self.temple_id
    }

    pub(crate) fn actor(&self) -> &str {
        &self.actor
    }

    pub(crate) fn public_key(&self) -> &str {
        &self.public_key
    }

    pub(crate) fn sign_attestation(&self, slot: &str, statement: &Value) -> Result<Value> {
        if !is_token(slot) || !statement.is_object() {
            return Err(fail(
                "expected a Temple attestation slot and statement record",
            ));
        }
        let statement = canonical_ascii(statement, 0)?;
        let payload = json!({
            "actor": self.actor,
            "slot": slot,
            "statement": statement,
            "templeId": self.temple_id,
        });
        // Temple3 canonical JSON orders every object by UTF-8 key bytes. The
        // fixed fields below are already ordered and `canonical_ascii` sorts
        // the statement. ASCII strings meet Temple3's NFC requirement.
        let message = serde_json::to_vec(&json!({
            "domain": "temple3.signature/v0.1",
            "keyId": self.key_id,
            "payload": payload,
            "publicKey": self.public_key,
            "purpose": "attestation",
            "suite": SUITE,
        }))?;
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(fail("Temple attestation exceeds the signing limit"));
        }
        let signature = hex::encode(self.key.sign(&message).to_bytes());
        Ok(json!({
            "keyId": self.key_id,
            "kind": "temple3.signed/v0.1",
            "payload": payload,
            "publicKey": self.public_key,
            "purpose": "attestation",
            "signature": signature,
            "suite": SUITE,
        }))
    }
}

fn is_token(token: &str) -> bool {
    token.len() <= 128
        && token
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:/-".contains(&c))
}

fn canonical_ascii(value: &Value, depth: usize) -> Result<Value> {
    if depth > MAX_STATEMENT_DEPTH {
        return Err(fail("Temple attestation statement is nested too deeply"));
    }
    match value {
        Value::Object(fields) if fields.keys().all(|key| key.is_ascii()) => {
            let mut fields: Vec<_> = fields.iter().collect();
            fields.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
            let sorted = fields
                .into_iter()
                .map(|(key, value)| Ok((key.clone(), canonical_ascii(value, depth + 1)?)))
                .collect::<Result<_>>()?;
            Ok(Value::Object(sorted))
        }
        Value::Array(items) => items
            .iter()
            .map(|item| canonical_ascii(item, depth + 1))
            .collect::<Result<_>>()
            .map(Value::Array),
        Value::String(text) if text.is_ascii() => Ok(value.clone()),
        Value::Bool(_) | Value::Null => Ok(value.clone()),
        _ => Err(fail(
            "Temple attestation statements use ASCII JSON without numbers",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::{DirBuilderExt, symlink},
        path::PathBuf,
    };

    struct PrivateDirectory(PathBuf);

    impl Drop for PrivateDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_identity() -> PeerIdentity {
        PeerIdentity::from_key(
            SigningKey::from_bytes(&[42; 32]),
            "temple:coordinator",
            "field-coordinator",
        )
        .unwrap()
    }

    #[test]
    fn matches_the_temple3_appointment_attestation_fixture() {
        let identity = fixture_identity();
        let envelope = identity
            .sign_attestation(
                "operation-7",
                &json!({
                    "workflowId": "field-visit-1",
                    "recipientTempleId": "temple:site",
                    "appointmentId": "operation-1/case",
                    "kind": "proposal",
                    "time": "2026-11-17T02:00:00Z",
                    "revision": "7",
                }),
            )
            .unwrap();
        assert_eq!(
            identity.public_key(),
            "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61"
        );
        assert_eq!(
            envelope["keyId"],
            "key:sha256:b297f2036dbdb27007941edaca6af7746adc512ac8a77691e8a65d9b894ae87e"
        );
        assert_eq!(
            envelope["signature"],
            "7a613fb3f987f8a2cac5b480cbb1b4e5c6df77e9ae9af43de593c5de80c4c1817a0e93ae89891305b85a50f3c669bdbd201303be1f88e3e43a2f23f49eaaca02"
        );
        assert_eq!(envelope["purpose"], "attestation");
        assert_eq!(envelope["payload"]["actor"], identity.actor());
        assert_eq!(envelope["payload"]["templeId"], identity.temple_id());
    }

    #[test]
    fn refuses_inputs_outside_the_attestation_profile() {
        let identity = fixture_identity();
        for statement in [
            json!("not a record"),
            json!({"value": 1}),
            json!({"value": "é"}),
            json!({"value": "x".repeat(MAX_MESSAGE_BYTES)}),
        ] {
            assert!(
                identity
                    .sign_attestation("operation-7", &statement)
                    .is_err()
            );
        }
        assert!(
            identity
                .sign_attestation("invalid slot", &json!({}))
                .is_err()
        );
    }

    #[test]
    fn loads_only_a_private_regular_seed_file() {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let directory =
            std::env::temp_dir().join(format!("encounter-peer-seed-{}", hex::encode(nonce)));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let directory = PrivateDirectory(directory);
        let path = directory.0.join("seed");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        writeln!(file, "{}", "2a".repeat(32)).unwrap();
        let identity =
            PeerIdentity::read(&path, "temple:coordinator", "field-coordinator").unwrap();
        assert_eq!(identity.public_key(), fixture_identity().public_key());

        let link = directory.0.join("seed-link");
        symlink(&path, &link).unwrap();
        assert!(PeerIdentity::read(&link, identity.temple_id(), identity.actor()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(PeerIdentity::read(&path, identity.temple_id(), identity.actor()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        writeln!(file, "extra").unwrap();
        assert!(PeerIdentity::read(&path, identity.temple_id(), identity.actor()).is_err());
    }
}
