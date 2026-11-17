use crate::{Result, fail, process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::{self, Read}};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const INPUT_LIMIT: u64 = 16 * 1024;
const KEY_LIMIT: usize = 256;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_worker_assignment.encounter").to_owned()],
        &["workerAssignment.config", "workerAssignment.issue"], &BTreeSet::from([
            "kernel.invoke", "value.type", "number.isNatural", "number.calculate", "time.formatUtc",
            "text.matches", "json.stringify",
        ]), &mut Meter::new(100_000))
}

fn read_input() -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(INPUT_LIMIT as usize + 1));
    io::stdin().lock().take(INPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > INPUT_LIMIT { return Err(fail("Worker assignment input exceeds its byte bound")); }
    Ok(bytes)
}

pub(crate) fn config() -> Result<()> {
    let input = serde_json::from_slice(&read_input()?)?;
    policy()?.run("workerAssignment.config", input, &mut Meter::new(100_000))?;
    println!("true");
    Ok(())
}

fn issue_frame(input: &[u8]) -> Result<Value> {
    let (prefix, body) = input.split_first_chunk::<4>().ok_or_else(|| fail("Invalid worker assignment frame"))?;
    let header_len = u32::from_be_bytes(*prefix) as usize;
    let (request, der) = body.split_at_checked(header_len).ok_or_else(|| fail("Invalid worker assignment frame"))?;
    if der.is_empty() || der.len() > KEY_LIMIT { return Err(fail("Invalid worker assignment key length")); }
    let request = serde_json::from_slice(request)?;
    let planned = policy()?.run("workerAssignment.issue", request, &mut Meter::new(200_000))?;
    let protocol = planned["protocol"].as_str().ok_or_else(|| fail("Missing worker assignment protocol"))?;
    let payload = planned["payload"].as_str().ok_or_else(|| fail("Missing worker assignment payload"))?.as_bytes();
    let key = SigningKey::from_pkcs8_der(der).map_err(|_| fail("Worker assignment key must be Ed25519 PKCS#8"))?;
    let signature = key.sign(payload);
    Ok(json!({
        "protocol": protocol,
        "payload": Base64UrlUnpadded::encode_string(payload),
        "signature": Base64UrlUnpadded::encode_string(&signature.to_bytes()),
    }))
}

pub(crate) fn issue() -> Result<()> {
    let input = read_input()?;
    let proof = issue_frame(&input)?;
    drop(input);
    println!("{proof}");
    Ok(())
}

pub(super) fn admit_container(input: &[u8], launch: Value) -> Result<()> {
    let mut envelope: Value = serde_json::from_slice(input)
        .map_err(|_| fail("Container worker input must be one JSON envelope."))?;
    crate::compat_value::external(&envelope)?;
    let authority = if envelope["protocol"] == "sourcery.hosted/container-authoring-worker-input.v1" {
        let authority = observe_imported_authority(envelope.as_object_mut()
            .and_then(|wrapper| wrapper.shift_remove("importedAdmissionAuthority")))?;
        envelope = envelope["envelope"].take();
        authority
    } else { Value::Null };
    let malformed = || fail("The worker assignment proof is malformed.");
    let proof = envelope.as_object_mut().and_then(|row| row.shift_remove("assignment")).ok_or_else(malformed)?;
    let decode = |key, max| {
        let encoded = proof[key].as_str().filter(|value| value.len() <= max).ok_or_else(malformed)?;
        Base64UrlUnpadded::decode_vec(encoded).map_err(|_| malformed())
    };
    let payload = String::from_utf8(decode("payload", 4096)?).map_err(|_| malformed())?;
    let claims: Value = serde_json::from_str(&payload).map_err(|_| malformed())?;
    crate::compat_value::external(&claims)?;
    let key = launch["assignmentPublicJwk"]["x"].as_str().ok_or_else(malformed)?;
    let key = Base64UrlUnpadded::decode_vec(key).map_err(|_| malformed())?;
    let mut observation = launch;
    observation["publicKey"] = json!(hex::encode(key));
    observation["payload"] = json!(payload);
    observation["claims"] = claims;
    observation["proofProtocol"] = proof["protocol"].clone();
    observation["signature"] = json!(hex::encode(decode("signature", 1024)?));
    observation["envelope"] = envelope;
    observation["importedAuthority"] = authority;
    observation["nowMs"] = json!(u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?);
    let entry = "workerAssignment.containerAdmission";
    let policy = Programme::admit(&[include_str!("hosted_worker_assignment.encounter").to_owned()], entry,
        &BTreeSet::from(["kernel.invoke", "signature.ed25519.verify", "json.stringify", "json.canonical",
            "digest.sha256", "time.parseRfc3339", "number.calculate"]), &mut Meter::new(100_000))?;
    policy.run(entry, observation, &mut Meter::new(40_000_000))?;
    Ok(())
}

fn observe_imported_authority(authority: Option<Value>) -> Result<Value> {
    let malformed = || fail("Container imported-admission authority key binding is invalid.");
    let mut authority = authority.ok_or_else(malformed)?;
    if authority.is_null() { return Ok(Value::Null); }
    let Some(Value::String(seed)) = authority.get_mut("privateJwk").and_then(Value::as_object_mut)
        .and_then(|jwk| jwk.shift_remove("d")) else { return Err(malformed()); };
    let seed = Zeroizing::new(seed);
    let mut bytes = Zeroizing::new([0; 32]);
    if seed.len() != 43 || Base64UrlUnpadded::decode(&seed, &mut *bytes).map_err(|_| malformed())?.len() != 32 {
        return Err(malformed());
    }
    let key = SigningKey::from_bytes(&bytes);
    Ok(json!({
        "protocol": authority["protocol"], "issuer": authority["issuer"],
        "keyId": authority["keyId"], "audience": authority["audience"],
        "privatePublicJwk": authority["privateJwk"], "publicJwk": authority["publicJwk"],
        "derivedX": Base64UrlUnpadded::encode_string(key.verifying_key().as_bytes()),
    }))
}

#[cfg(test)]
#[test]
fn container_admission_binds_the_entire_signed_envelope() -> Result<()> {
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    let key = SigningKey::from_bytes(&[41; 32]);
    let target = json!({"tenantId":"ten_test","appId":"app_test","projectId":"prj_test",
        "workspaceId":"wsp_test","region":"test","storageNamespace":"tenants/ten_test/workspaces/wsp_test"});
    let target_digest = crate::rel::hash(serde_json::to_vec(&json!([
        "ten_test","app_test","prj_test","wsp_test","test","tenants/ten_test/workspaces/wsp_test"
    ]))?);
    let public = json!({"kty":"OKP","crv":"Ed25519","x":Base64UrlUnpadded::encode_string(key.verifying_key().as_bytes())});
    let launch = json!({"workerId":"worker.fixture","issuer":"issuer","audience":"audience","target":target,
        "assignmentPublicJwk":public});
    let mut envelope = json!({"protocol":"sourcery.hosted/authoring-worker.v1","requestId":"request",
        "target":target,"targetDigest":target_digest,"message":{"method":"tools/list"}});
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let request = serde_json::to_vec(&json!({"issuer":"issuer","audience":"audience","lifetimeMs":60000,
        "requestId":"request","workerId":"worker.fixture","targetDigest":target_digest,
        "envelopeDigest":crate::rel::hash(crate::compat_value::canonical_json(&envelope)?),"nowMs":now}))?;
    let mut frame = (request.len() as u32).to_be_bytes().to_vec();
    frame.extend(request);
    frame.extend(key.to_pkcs8_der().map_err(|_| fail("Cannot encode test assignment key"))?.as_bytes());
    envelope["assignment"] = issue_frame(&frame)?;
    admit_container(&serde_json::to_vec(&envelope)?, launch.clone())?;
    let mut private = public.clone();
    private["d"] = json!(Base64UrlUnpadded::encode_string(&key.to_bytes()));
    let wrapped = json!({"protocol":"sourcery.hosted/container-authoring-worker-input.v1","envelope":envelope,
        "importedAdmissionAuthority":{"protocol":"sourcery.hosted/container-imported-admission-authority.v1",
            "issuer":"issuer#imported-admission","keyId":"self-hosted-imported-admission-v1",
            "audience":"sourcery-imported-admission","privateJwk":private,"publicJwk":public}});
    admit_container(&serde_json::to_vec(&wrapped)?, launch.clone())?;
    let mut crossed = wrapped.clone();
    let other = SigningKey::from_bytes(&[42; 32]);
    let other_x = json!(Base64UrlUnpadded::encode_string(other.verifying_key().as_bytes()));
    let authority = &mut crossed["importedAdmissionAuthority"];
    authority["privateJwk"]["d"] = json!(Base64UrlUnpadded::encode_string(&other.to_bytes()));
    authority["privateJwk"]["x"] = other_x.clone();
    authority["publicJwk"]["x"] = other_x;
    assert!(admit_container(&serde_json::to_vec(&crossed)?, launch.clone()).unwrap_err().to_string()
        .contains("imported-admission authority is not bound"));
    let mut crossed = wrapped.clone();
    crossed["importedAdmissionAuthority"]["privateJwk"]["d"] = json!(Base64UrlUnpadded::encode_string(&other.to_bytes()));
    assert!(admit_container(&serde_json::to_vec(&crossed)?, launch.clone()).unwrap_err().to_string()
        .contains("imported-admission authority is not bound"));
    let mut crossed = wrapped.clone();
    crossed["importedAdmissionAuthority"]["issuer"] = json!("another-issuer");
    assert!(admit_container(&serde_json::to_vec(&crossed)?, launch.clone()).unwrap_err().to_string()
        .contains("imported-admission authority is not bound"));
    let mut crossed = wrapped;
    crossed["envelope"]["message"]["method"] = json!("tools/call");
    assert!(admit_container(&serde_json::to_vec(&crossed)?, launch).unwrap_err().to_string()
        .contains("not bound to this request"));
    Ok(())
}
