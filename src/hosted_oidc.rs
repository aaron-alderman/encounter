use crate::{Result, fail, platform_import_closure::read_bounded_observation, process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERIFY_ENTRIES: &[&str] = &[
    "hostedOidc.admit", "hostedOidc.jwksEndpoint", "hostedOidc.jwksDocument",
    "hostedOidc.cachedKeys", "hostedOidc.cacheEntry", "hostedOidc.select", "hostedOidc.signature",
];

pub(crate) fn run(operation: &str) -> Result<()> {
    let entries: &[&str] = match operation {
        "admit" => &["hostedOidc.admit"],
        "verify" => VERIFY_ENTRIES,
        _ => return Err(fail("Unsupported hosted OIDC decision.")),
    };
    let limit = if operation == "admit" { 64 * 1024 } else { 3 * 1024 * 1024 };
    let input = read_bounded_observation(limit)?;
    let result = evaluate(operation, entries, input, |uri, timeout| request_jwks(uri, timeout, None))?;
    println!("{result}");
    Ok(())
}

fn evaluate(operation: &str, entries: &[&str], input: Value,
    fetch: impl Fn(&str, Duration) -> Value) -> Result<Value> {
    let policy = Programme::admit_entries(&[include_str!("hosted_oidc.encounter").to_owned()], entries,
        &BTreeSet::from(["kernel.invoke", "json.stringify", "value.type", "number.calculate",
            "number.isNatural", "text.matches"]),
        &mut Meter::new(100_000))?;
    let mut meter = Meter::new(1_000_000);
    let token = CompactJwt::parse(&input["token"])?;
    let header = json!({"alg":token.header["alg"], "kid":token.header["kid"],
        "critical":!token.header["crit"].is_null()});
    let admission = || json!({"header":header, "audience":input["audience"],
        "issuers":input["issuers"], "endpoints":input["endpoints"],
        "claims":{"iss":token.claims["iss"], "aud":token.claims["aud"], "azp":token.claims["azp"]}});
    let issuer = policy.run("hostedOidc.admit", admission(), &mut meter)?;
    if operation == "admit" {
        return Ok(issuer);
    }
    let mut update = Value::Null;
    let result: Result<Value> = (|| {
        let cached = policy.run("hostedOidc.cachedKeys",
            json!({"issuer":issuer, "cache":input["cache"], "nowMs":now_ms()?}), &mut meter)?;
        let mut load = |meter: &mut Meter| -> Result<Value> {
            let observation = if input["localKeys"].is_null() {
                let endpoint = json!({"issuer":issuer, "endpoints":input["endpoints"], "timeoutMs":input["timeoutMs"]});
                let request = policy.run("hostedOidc.jwksEndpoint", endpoint, meter)?;
                let uri = request["uri"].as_str().ok_or_else(|| fail("Expected an admitted OIDC key endpoint"))?;
                let millis = request["timeoutMs"].as_u64().ok_or_else(|| fail("Expected an OIDC request deadline"))?;
                fetch(uri, Duration::from_millis(millis))
            } else {
                let document = json!({"keys":input["localKeys"]});
                json!({"exceeded":serde_json::to_vec(&document)?.len() > 1024 * 1024,
                    "available":true, "parsed":true, "document":document})
            };
            let keys = policy.run("hostedOidc.jwksDocument", observation, meter)?;
            update = policy.run("hostedOidc.cacheEntry",
                json!({"issuer":issuer, "keys":keys, "nowMs":now_ms()?, "ttlMs":input["ttlMs"]}), meter)?;
            Ok(keys)
        };
        let keys = if cached.is_null() { load(&mut meter)? } else { cached };
        let select = |keys, refreshed, meter: &mut Meter| policy.run("hostedOidc.select",
            json!({"header":header, "keys":keys, "refreshed":refreshed}), meter);
        let selected = select(keys, false, &mut meter)?;
        let selected = if selected["refresh"] == true {
            select(load(&mut meter)?, true, &mut meter)?
        } else {
            selected
        };
        let verification = token.verify_signature(&selected["key"]);
        let claims = &token.claims;
        let observation = json!({"keyValid":verification.is_ok(), "matched":verification.unwrap_or(false),
            "claims":{"sub":claims["sub"], "exp":claims["exp"], "nbf":claims["nbf"], "iat":claims["iat"]},
            "nowMs":now_ms()?});
        policy.run("hostedOidc.signature", observation, &mut meter)?;
        Ok(token.claims)
    })();
    match result {
        Ok(claims) => Ok(json!({"claims":claims, "cache":update})),
        Err(error) => {
            let Ok(diagnostic) = serde_json::from_str::<Value>(&error.to_string()) else { return Err(error); };
            Ok(json!({"error":diagnostic, "cache":update}))
        }
    }
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?)
}

fn request_jwks(uri: &str, timeout: Duration, trust_anchor: Option<&std::ffi::CStr>) -> Value {
    use crate::http_client::{self, BodyLimitExceeded, Request};
    let response = http_client::send(Request {
        url: uri, method: "GET", headers: &[("Accept", "application/json")], body: None,
        timeout, connect_timeout: timeout, limit: 1024 * 1024, resolve: None,
        trust_anchor, restoring: false,
    });
    match response {
        Ok(response) if (200..300).contains(&response.status) => {
            let document = serde_json::from_slice(&response.body)
                .ok().filter(|value| crate::compat_value::external(value).is_ok());
            json!({"exceeded":false, "available":true, "parsed":document.is_some(), "document":document})
        }
        Err(error) if error.is::<BodyLimitExceeded>() => json!({"exceeded":true}),
        _ => json!({"exceeded":false, "available":false}),
    }
}

struct CompactJwt<'a> {
    message: &'a [u8],
    signature: Vec<u8>,
    header: Value,
    claims: Value,
}

impl<'a> CompactJwt<'a> {
    fn parse(input: &'a Value) -> Result<Self> {
        let token = input.as_str().filter(|value| value.len() <= 16_384)
            .ok_or_else(|| malformed("OIDC token is malformed."))?;
        let (message, signature) = token.rsplit_once('.')
            .ok_or_else(|| malformed("OIDC token must be a three-segment compact JWT."))?;
        let (header, payload) = message.split_once('.')
            .filter(|(header, payload)| !header.is_empty() && !payload.is_empty() && !payload.contains('.')
                && !signature.is_empty())
            .ok_or_else(|| malformed("OIDC token must be a three-segment compact JWT."))?;
        let signature = Base64UrlUnpadded::decode_vec(signature)
            .map_err(|_| malformed("OIDC token signature is malformed."))?;
        Ok(Self {
            message: message.as_bytes(),
            signature,
            header: parse_object(header, "header")?,
            claims: parse_object(payload, "payload")?,
        })
    }

    fn verify_signature(&self, key: &Value) -> Result<bool> {
        use crate::self_hosted_identity_crypto::{verify_oidc_p256, verify_oidc_rsa};
        match self.header["alg"].as_str() {
            Some("RS256") => match (decode(&key["n"], 2732), decode(&key["e"], 11)) {
                (Some(modulus), Some(exponent)) => verify_oidc_rsa(&modulus, &exponent, self.message, &self.signature),
                _ => Err(fail("Invalid RSA public key")),
            },
            Some("ES256") => match (decode(&key["x"], 43), decode(&key["y"], 43)) {
                (Some(x), Some(y)) => verify_oidc_p256(&x, &y, self.message, &self.signature),
                _ => Err(fail("Invalid P-256 public key")),
            },
            _ => Err(fail("Expected an admitted hosted signature algorithm")),
        }
    }
}

fn parse_object(segment: &str, label: &str) -> Result<Value> {
    let bytes = Base64UrlUnpadded::decode_vec(segment)
        .map_err(|_| malformed(&format!("OIDC token {label} is malformed.")))?;
    let invalid = || malformed(&format!("OIDC token {label} is not a JSON object."));
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if !value.is_object() {
        return Err(invalid());
    }
    crate::compat_value::external(&value).map_err(|_| invalid())?;
    Ok(value)
}

fn malformed(message: &str) -> Box<dyn std::error::Error> {
    fail(json!({"code":"oidc-token-malformed","message":message}).to_string())
}

fn decode(value: &Value, limit: usize) -> Option<Vec<u8>> {
    let value = value.as_str().filter(|value| value.len() <= limit)?;
    Base64UrlUnpadded::decode_vec(value).ok()
}

#[cfg(test)]
#[test]
fn jwks_policy_checks_issuer_binding_and_document_bounds() -> Result<()> {
    let entries = ["hostedOidc.jwksEndpoint", "hostedOidc.jwksDocument"];
    let mut meter = Meter::new(1_000_000);
    let policy = Programme::admit_entries(
        &[include_str!("hosted_oidc.encounter").to_owned()],
        &entries,
        &BTreeSet::from(["kernel.invoke", "json.stringify", "number.calculate", "number.isNatural", "text.matches"]),
        &mut meter,
    )?;
    let issuer = "https://issuer.example";
    let uri = "https://keys.example/jwks?v=1";
    let endpoint = |issuer, uri| json!({"issuer":issuer, "jwksUri":uri});
    let observation = |endpoints| json!({"issuer":issuer, "endpoints":endpoints, "timeoutMs":5000});
    assert_eq!(policy.run(entries[0], observation(vec![endpoint(issuer, uri)]), &mut meter)?,
        json!({"uri":uri, "timeoutMs":5000}));
    for endpoints in [
        vec![endpoint("https://other.example", uri)],
        vec![endpoint(issuer, uri), endpoint(issuer, uri)],
        vec![endpoint(issuer, "http://127.0.0.1:8080/jwks")],
        vec![endpoint(issuer, "https://keys.example@other.example/jwks")],
    ] {
        assert!(policy.run(entries[0], observation(endpoints), &mut meter).is_err());
    }
    let document = |keys| json!({"available":true, "parsed":true, "document":{"keys":keys}});
    let key = json!({"kid":"fixture"});
    assert_eq!(policy.run(entries[1], document(vec![key.clone()]), &mut meter)?, json!([key]));
    assert!(policy.run(entries[1], document(vec![key; 129]), &mut meter).is_err());
    assert!(policy.run(entries[1], json!({"exceeded":true}), &mut meter).is_err());
    Ok(())
}

#[cfg(test)]
#[test]
fn jwks_policy_expires_cache_and_allows_one_refresh_on_missing_key() -> Result<()> {
    let entries = ["hostedOidc.cacheEntry", "hostedOidc.cachedKeys", "hostedOidc.select"];
    let mut meter = Meter::new(1_000_000);
    let policy = Programme::admit_entries(
        &[include_str!("hosted_oidc.encounter").to_owned()],
        &entries,
        &BTreeSet::from(["kernel.invoke", "json.stringify", "number.calculate", "number.isNatural"]),
        &mut meter,
    )?;
    let issuer = "https://issuer.example";
    let key = json!({"kid":"first", "alg":"RS256", "kty":"RSA"});
    let cache = policy.run(entries[0],
        json!({"issuer":issuer, "keys":[key], "nowMs":1000, "ttlMs":1000}), &mut meter)?;
    let lookup = |issuer, now_ms| json!({"issuer":issuer, "cache":cache, "nowMs":now_ms});
    assert_eq!(policy.run(entries[1], lookup(issuer, 1999), &mut meter)?, json!([key]));
    assert!(policy.run(entries[1], lookup(issuer, 2000), &mut meter)?.is_null());
    assert!(policy.run(entries[1], lookup("https://other.example", 1999), &mut meter)?.is_null());

    let select = |kid, refreshed| json!({"header":{"alg":"RS256", "kid":kid}, "keys":[key], "refreshed":refreshed});
    assert_eq!(policy.run(entries[2], select("first", false), &mut meter)?,
        json!({"key":key, "refresh":false}));
    assert_eq!(policy.run(entries[2], select("next", false), &mut meter)?,
        json!({"key":null, "refresh":true}));
    let error = policy.run(entries[2], select("next", true), &mut meter).unwrap_err();
    assert_eq!(serde_json::from_str::<Value>(&error.to_string())?["code"], "oidc-signing-key-missing");
    Ok(())
}

#[cfg(test)]
#[test]
fn verifies_and_rotates_jwks_over_trusted_https() -> Result<()> {
    use crate::self_hosted_identity_crypto::SigningKey;
    use std::{ffi::CString, fs, io, net::{Ipv4Addr, TcpListener}, os::unix::ffi::OsStrExt,
        process::Command, thread, time::Instant};

    let scratch = crate::appdev_host_process::Scratch::create(&std::env::temp_dir(), "encounter-oidc-")?;
    let trust_path = scratch.path().join("ca.pem");
    let key_path = scratch.path().join("localhost-key.pem");
    let generated = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout"])
        .arg(&key_path)
        .arg("-out")
        .arg(&trust_path)
        .output()?;
    if !generated.status.success() {
        return Err(fail(format!("Could not generate the localhost TLS fixture: {}",
            String::from_utf8_lossy(&generated.stderr))));
    }
    let certificate = fs::read_to_string(&trust_path)?;
    let private_key = fs::read(&key_path)?;
    let trust_anchor = CString::new(trust_path.as_os_str().as_bytes())?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let first = SigningKey::generate()?;
    let rotated = SigningKey::generate()?;
    let jwk = |kid, key: &SigningKey| {
        let (_, x, y) = key.private_parts();
        json!({"kid":kid, "alg":"ES256", "kty":"EC", "crv":"P-256",
            "x":Base64UrlUnpadded::encode_string(x), "y":Base64UrlUnpadded::encode_string(y)})
    };
    let documents = [json!({"keys":[jwk("first", &first)]}), json!({"keys":[jwk("rotated", &rotated)]})];
    let server = thread::spawn(move || -> std::result::Result<usize, String> {
        let deadline = Instant::now() + Duration::from_secs(6);
        for document in &documents {
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            };
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{document}",
                document.to_string().len());
            crate::certificate_tls::reply_fixture(socket, &certificate, &private_key, response.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        Ok(documents.len())
    });
    let issuer = "https://issuer.example";
    let endpoint = format!("https://localhost:{port}/keys");
    let claims = json!({"iss":issuer, "aud":"fixture", "sub":"operator", "exp":now_ms()? / 1000 + 120});
    let signed = |kid, key: &SigningKey| -> Result<String> {
        let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&json!({"alg":"ES256", "kid":kid}))?);
        let payload = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&claims)?);
        let message = format!("{header}.{payload}");
        Ok(format!("{message}.{}", Base64UrlUnpadded::encode_string(&key.sign(message.as_bytes())?)))
    };
    let fetches = std::cell::Cell::new(0);
    let verify = |token: &str, cache| evaluate("verify", VERIFY_ENTRIES, json!({
        "token":token, "cache":cache, "audience":"fixture", "issuers":[issuer],
        "endpoints":[{"issuer":issuer, "jwksUri":endpoint}], "ttlMs":60000, "timeoutMs":2000,
    }), |uri, timeout| {
        fetches.set(fetches.get() + 1);
        request_jwks(uri, timeout, Some(&trust_anchor))
    });
    let token = signed("first", &first)?;
    let verified = verify(&token, Value::Null)?;
    assert_eq!(verified["claims"], claims, "{verified}");
    assert_eq!(fetches.get(), 1);
    let cached = verify(&token, verified["cache"].clone())?;
    assert_eq!(cached["claims"], claims, "{cached}");
    assert!(cached["cache"].is_null());
    assert_eq!(fetches.get(), 1);
    let refreshed = verify(&signed("rotated", &rotated)?, verified["cache"].clone())?;
    assert_eq!(refreshed["claims"], claims, "{refreshed}");
    assert_eq!(refreshed["cache"]["keys"][0]["kid"], "rotated");
    assert_eq!(fetches.get(), 2);
    assert_eq!(server.join().expect("TLS fixture").map_err(fail)?, 2);
    Ok(())
}
