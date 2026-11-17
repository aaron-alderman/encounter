use crate::{Result, appdev_host_process::Supervisor, self_hosted_identity::decide,
    self_hosted_identity_provision::{destination, private_stage, publish, write_private}, workspace::transport::random};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey, pkcs8::{EncodePrivateKey, KeypairBytes}};
use serde_json::{Value, json};
use std::path::Path;
use zeroize::Zeroizing;

fn write_key(path: &Path, key: &SigningKey) -> Result<()> {
    let mut encoded = KeypairBytes::from(key);
    // PKCS#8 PrivateKeyInfo without an embedded public key matches OpenSSL readers.
    encoded.public_key = None;
    let der = encoded.to_pkcs8_der().map_err(|_| crate::fail("Cannot encode Ed25519 custody key"))?;
    let contents = Zeroizing::new(Base64::encode_string(der.as_bytes()));
    let pem = Zeroizing::new(format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", &*contents));
    write_private(path, pem.as_bytes())
}

fn provision(path: &Path) -> Result<Value> {
    let path = destination(path)?;
    let assignment = SigningKey::from_bytes(&Zeroizing::new(random::<32>()?));
    let runtime = SigningKey::from_bytes(&Zeroizing::new(random::<32>()?));
    let public = Base64UrlUnpadded::encode_string(runtime.verifying_key().as_bytes());
    let plan = decide("identity.productionCustody", json!(public))?;
    let (stage, directory) = private_stage(&path)?;
    write_key(&directory.join("assignment-private-key.pem"), &assignment)?;
    write_key(&directory.join("runtime-authority-private-key.pem"), &runtime)?;
    let selection = Zeroizing::new(Base64::encode_string(&*Zeroizing::new(random::<32>()?)));
    let consent = Zeroizing::new(Base64::encode_string(&*Zeroizing::new(random::<32>()?)));
    let interaction = Zeroizing::new(format!("{{\"workspaceSelection\":\"{}\",\"consent\":\"{}\"}}\n", &*selection, &*consent));
    write_private(&directory.join("interaction-secrets.json"), interaction.as_bytes())?;
    for (filename, field) in [("oauth-clients.json", "clients"), ("runtime-verification-keys.json", "keys"), ("runtime-workloads.json", "workloads")] {
        let mut bytes = serde_json::to_vec_pretty(&plan[field])?;
        bytes.push(b'\n');
        write_private(&directory.join(filename), &bytes)?;
    }
    publish(stage, &directory, &path, None)?;
    Ok(plan["receipt"].clone())
}

pub(crate) fn run(path: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", provision(path)?);
    Ok(())
}

#[cfg(test)]
#[test]
fn production_custody_is_exclusive_and_keeps_keys_and_scopes_bound() -> Result<()> {
    use crate::{appdev_host_process::Scratch, signature::signing_key_from_pem};
    use std::{fs, os::unix::fs::PermissionsExt};
    let fixture = Scratch::create(&std::env::temp_dir(), "production-custody-test-")?;
    let target = fixture.path().join("custody");
    let receipt = provision(&target)?;
    assert_eq!(receipt["status"], "provisioned");
    assert_eq!(receipt["files"].as_array().unwrap().len(), 6);
    assert!(provision(&target).is_err());
    for name in receipt["files"].as_array().unwrap() {
        assert_eq!(fs::metadata(target.join(name.as_str().unwrap()))?.permissions().mode() & 0o777, 0o600);
    }
    let assignment = signing_key_from_pem(&Zeroizing::new(fs::read(target.join("assignment-private-key.pem"))?))?;
    let runtime = signing_key_from_pem(&Zeroizing::new(fs::read(target.join("runtime-authority-private-key.pem"))?))?;
    assert_ne!(assignment.verifying_key(), runtime.verifying_key());
    let keys: Value = serde_json::from_slice(&fs::read(target.join("runtime-verification-keys.json"))?)?;
    assert_eq!(keys[receipt["runtimeKeyId"].as_str().unwrap()]["x"], Base64UrlUnpadded::encode_string(runtime.verifying_key().as_bytes()));
    let workloads: Value = serde_json::from_slice(&fs::read(target.join("runtime-workloads.json"))?)?;
    assert_eq!(workloads["workloads"][0]["scope"], receipt["preflightScope"]);
    Ok(())
}
