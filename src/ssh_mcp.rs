use crate::{Result, fail, platform_import_closure::read_bounded_observation, process::{Meter, Programme}};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, pkcs8::{DecodePrivateKey, DecodePublicKey}};
use serde_json::{Map, Value, json};
use std::{collections::BTreeSet, io::{self, Read}, time::{SystemTime, UNIX_EPOCH}};
use zeroize::Zeroizing;

pub(crate) fn run(operation: &str) -> Result<()> {
    if operation == "issue" {
        return issue();
    }
    let entry = match operation {
        "configure" => "sshMcp.configuration",
        "verify" => "sshMcp.verify",
        _ => return Err(fail("Unsupported SSH MCP decision")),
    };
    let input = read_bounded_observation(128 * 1024)?;
    let policy = Programme::admit(&[include_str!("ssh_mcp.encounter").to_owned()], entry,
        &BTreeSet::from(["kernel.invoke", "digest.sha256", "json.stringify", "number.calculate", "number.isNatural", "record.entries",
            "signature.ed25519.verify", "text.matches", "value.describe", "value.sort"]),
        &mut Meter::new(100_000))?;
    let mut meter = Meter::new(1_000_000);
    let result = if operation == "configure" {
        let keys = input["publicKeys"].as_object().ok_or_else(|| fail("Expected SSH MCP assertion public keys"))?
            .iter().map(|(id, pem)| Ok((id.clone(), json!(decode_public_key(pem)?))))
            .collect::<Result<Map<String, Value>>>()?;
        let config = json!({"keys":keys, "issuer":input["issuer"], "audience":input["audience"],
            "allowedScopes":input["allowedScopes"], "maximumLifetimeSeconds":input["maximumLifetimeSeconds"]});
        policy.run(entry, config.clone(), &mut meter)?;
        config
    } else {
        let token = input["token"].as_str().filter(|token| token.len() <= 16_384)
            .ok_or_else(|| fail("SSH MCP assertion is invalid."))?;
        let (payload, signature) = token.split_once('.').filter(|(payload, signature)| !payload.is_empty() && !signature.is_empty())
            .ok_or_else(|| fail("SSH MCP assertion is invalid."))?;
        let decode = |text| Base64UrlUnpadded::decode_vec(text).map_err(|_| fail("SSH MCP assertion encoding is invalid."));
        let body: Value = serde_json::from_slice(&decode(payload)?)
            .map_err(|_| fail("SSH MCP assertion payload is invalid."))?;
        crate::compat_value::external(&body)?;
        policy.run(entry, json!({"payload":payload, "signature":hex::encode(decode(signature)?), "body":body,
            "config":input["config"], "routeScopes":input["routeScopes"],
            "now":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()}), &mut meter)?
    };
    println!("{result}");
    Ok(())
}

fn issue() -> Result<()> {
    let mut frame = Zeroizing::new(Vec::new());
    io::stdin().lock().take(131_073).read_to_end(&mut frame)?;
    if frame.len() > 131_072 { return Err(fail("SSH MCP issuance frame exceeds its byte bound.")); }
    let response = issue_frame(&frame)?;
    drop(frame);
    println!("{response}");
    Ok(())
}

fn issue_frame(frame: &[u8]) -> Result<Value> {
    let (prefix, body) = frame.split_first_chunk::<4>().ok_or_else(|| fail("Invalid SSH MCP issuance frame."))?;
    let (observation, der) = body.split_at_checked(u32::from_be_bytes(*prefix) as usize)
        .ok_or_else(|| fail("Invalid SSH MCP issuance frame."))?;
    if der.is_empty() || der.len() > 256 { return Err(fail("Invalid SSH MCP issuance key length.")); }
    let key = SigningKey::from_pkcs8_der(der).map_err(|_| fail("SSH MCP issuance requires an Ed25519 PKCS#8 key."))?;
    let mut input: Value = serde_json::from_slice(observation)?;
    crate::compat_value::external(&input)?;
    let row = input.as_object_mut().ok_or_else(|| fail("Expected an SSH MCP issuance observation."))?;
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|error| fail(error.to_string()))?;
    row.insert("nonce".into(), json!(Base64UrlUnpadded::encode_string(&nonce)));
    row.insert("now".into(), json!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()));
    let entry = "sshMcp.brokerIssue";
    let policy = Programme::admit(&[include_str!("ssh_mcp.encounter").to_owned()], entry,
        &BTreeSet::from(["kernel.invoke", "digest.sha256", "json.canonical", "number.calculate", "number.isNatural",
            "record.entries", "record.fromEntries", "text.matches", "time.formatUtc", "value.sort"]),
        &mut Meter::new(100_000))?;
    let mut planned = policy.run(entry, input, &mut Meter::new(1_000_000))?;
    let payload = planned["payload"].as_str().ok_or_else(|| fail("Missing SSH MCP assertion payload."))?;
    let payload = Base64UrlUnpadded::encode_string(payload.as_bytes());
    let signature = key.sign(payload.as_bytes());
    let mut response = planned["response"].take();
    response["token"] = json!(format!("{payload}.{}", Base64UrlUnpadded::encode_string(&signature.to_bytes())));
    Ok(response)
}

fn decode_public_key(value: &Value) -> Result<String> {
    let pem = value.as_str().ok_or_else(|| fail("Expected an SSH MCP Ed25519 public key PEM"))?;
    let mut lines = pem.trim().lines();
    if lines.next() != Some("-----BEGIN PUBLIC KEY-----") || lines.next_back() != Some("-----END PUBLIC KEY-----") {
        return Err(fail("Expected an SSH MCP Ed25519 public key PEM"));
    }
    let der = Base64::decode_vec(&lines.collect::<String>()).map_err(|_| fail("Invalid SSH MCP public key encoding"))?;
    let key = VerifyingKey::from_public_key_der(&der).map_err(|_| fail("Expected an SSH MCP Ed25519 public key"))?;
    Ok(hex::encode(key.as_bytes()))
}

#[cfg(test)]
#[test]
fn broker_issuance_enforces_principal_policy_and_produces_verifiable_claims() -> Result<()> {
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    let key = SigningKey::from_bytes(&[7; 32]);
    let der = key.to_pkcs8_der().map_err(|_| fail("Cannot encode test signing key."))?;
    let fingerprint = format!("SHA256:{}", "A".repeat(43));
    let observation = json!({
        "account":"ubuntu", "sessionId":"ssh-mcp.fixture", "keyFingerprint":fingerprint,
        "scopes":["authoring.write","authoring.read"],
        "config":{
            "protocol":"sourcery.hosted/ssh-mcp-broker-config.v1", "keyId":"key.fixture",
            "issuer":"ssh-mcp.fixture", "audience":"http://127.0.0.1:8140/mcp",
            "privateKeyFile":"/protected/fixture.pem", "maximumLifetimeSeconds":120,
            "principals":[{"account":"ubuntu","keyFingerprints":[fingerprint],"scopes":["authoring.read","authoring.write"]}]
        }
    });
    let issue = |observation: &Value| -> Result<Value> {
        let bytes = serde_json::to_vec(observation)?;
        let mut frame = Zeroizing::new((bytes.len() as u32).to_be_bytes().to_vec());
        frame.extend(bytes);
        frame.extend_from_slice(der.as_bytes());
        issue_frame(&frame)
    };
    let response = issue(&observation)?;
    assert_eq!(response["protocol"], "sourcery.hosted/ssh-mcp-broker-response.v1");
    assert_eq!(response["scopes"], json!(["authoring.read","authoring.write"]));
    let token = response["token"].as_str().expect("broker returned token");
    let (payload, signature) = token.split_once('.').expect("signed token");
    let signature = Base64UrlUnpadded::decode_vec(signature).map_err(|_| fail("Invalid test signature encoding."))?;
    let body: Value = serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload)
        .map_err(|_| fail("Invalid test payload encoding."))?)?;
    let entry = "sshMcp.verify";
    let policy = Programme::admit(&[include_str!("ssh_mcp.encounter").to_owned()], entry,
        &BTreeSet::from(["kernel.invoke", "digest.sha256", "json.stringify", "number.calculate", "number.isNatural",
            "record.entries", "signature.ed25519.verify", "text.matches", "value.describe", "value.sort"]),
        &mut Meter::new(100_000))?;
    let claims = policy.run(entry, json!({"payload":payload,"signature":hex::encode(signature),"body":body,
        "config":{"keys":{"key.fixture":hex::encode(key.verifying_key().as_bytes())},"issuer":"ssh-mcp.fixture",
            "audience":"http://127.0.0.1:8140/mcp","allowedScopes":["authoring.read","authoring.write"],
            "maximumLifetimeSeconds":120},
        "routeScopes":null,"now":body["issuedAt"]}), &mut Meter::new(1_000_000))?;
    assert_eq!(claims["account"], "ubuntu");
    assert_eq!(claims["keyFingerprint"], fingerprint);
    assert_eq!(claims["expiresAt"].as_u64().unwrap() - claims["issuedAt"].as_u64().unwrap(), 120);
    for (field, value, reason) in [
        ("account", json!("other"), "not admitted"),
        ("keyFingerprint", json!(format!("SHA256:{}", "B".repeat(43))), "not admitted"),
        ("scopes", json!(["authoring.read","operations.execute"]), "exceed the principal policy"),
    ] {
        let mut crossed = observation.clone();
        crossed[field] = value;
        assert!(issue(&crossed).unwrap_err().to_string().contains(reason));
    }
    let mut forbidden = observation;
    forbidden["scopes"] = Value::Null;
    forbidden["config"]["principals"][0]["scopes"] = json!(["authoring.read", "operations.execute"]);
    assert!(issue(&forbidden).unwrap_err().to_string().contains("exceed the admitted SSH access policy"));
    Ok(())
}
