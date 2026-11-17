use crate::{Result, compat_value, fail, platform_import_closure::read_bounded_observation, process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis())?)
}

fn authenticate(socket: &Value, operation: &str, context: &mut Value) -> Result<()> {
    if !context.is_object() { return Err(fail("runtime-resource-grant-invalid")); }
    let socket = socket.as_str().filter(|socket| Path::new(socket).is_absolute())
        .ok_or_else(|| fail("runtime-resource-grant-invalid"))?;
    let evidence = crate::runtime_authority_client::authenticate_workload(
        Path::new(socket), operation, &context["scope"], &context["consumerId"])
        .map_err(|error| {
            if serde_json::from_str::<Value>(&error.to_string()).is_ok() { error }
            else { fail("runtime-resource-workload-identity") }
        })?;
    context["consumerId"] = evidence["consumerId"].clone();
    context["identityEvidenceHash"] = evidence["evidenceHash"].clone();
    Ok(())
}

pub(crate) fn issue() -> Result<()> {
    let _signals = crate::appdev_host_process::Supervisor::new();
    let input = read_bounded_observation(32_768)?;
    let event = json!({"consumerId":input["consumerId"], "bindingKey":input["bindingKey"]});
    match issue_grant(input.clone()) {
        Ok(proof) => { println!("{proof}"); Ok(()) }
        Err(error) => Err(retain_denial(input["postgres"].clone(), "issue", event, error)?),
    }
}

fn issue_grant(mut input: Value) -> Result<Value> {
    if !input.is_object() { return Err(fail("Invalid runtime grant issuance input")); }
    let authority_socket = input["authoritySocket"].take();
    authenticate(&authority_socket, "issue", &mut input)?;
    let policy = Programme::admit_entries(&[include_str!("runtime_grant_verify.encounter").to_owned()],
        &["runtimeGrant.scopeDigest", "runtimeGrant.issueClaims", "runtimeGrant.issueCoordinates"],
        &BTreeSet::from(["value.describe", "value.type", "record.entries", "json.canonical", "digest.sha256",
            "text.matches", "time.formatUtc"]), &mut Meter::new(100_000))?;
    let mut query = policy.run("runtimeGrant.issueCoordinates",
        json!({"bindingKey":input["bindingKey"], "resourceRef":input["resourceRef"]}), &mut Meter::new(200_000))?;
    query["expectedScopeHash"] = policy.run("runtimeGrant.scopeDigest", input["scope"].take(), &mut Meter::new(200_000))?;
    input["binding"] = read_binding(&input["postgres"], &query, &Value::Null).map_err(binding_failure)?;
    input["grantId"] = json!(format!("grant.{}", crate::nonce::uuid_v4()?));
    input["nowMs"] = json!(now_ms()?);
    let key_id = input["keyId"].clone();
    let public_key = input["publicKey"].clone();
    let postgres = input["postgres"].take();
    let socket = authority_socket.as_str().filter(|socket| Path::new(socket).is_absolute())
        .ok_or_else(|| fail("runtime-resource-grant-invalid"))?;
    let wire = policy.run("runtimeGrant.issueClaims", input, &mut Meter::new(200_000))?;
    let payload = Base64UrlUnpadded::encode_string(wire.as_str()
        .ok_or_else(|| fail("Missing canonical runtime grant payload"))?.as_bytes());
    let signature = crate::runtime_authority_client::sign_grant(Path::new(socket),
        key_id.as_str().ok_or_else(|| fail("runtime-resource-grant-invalid"))?, &payload)
        .map_err(|_| fail("runtime-resource-grant-signature"))?;
    let claims = verify(&json!({"keyId":key_id, "payload":payload, "signature":signature["signature"], "publicKey":public_key}), false, false)
        .map_err(|_| fail("runtime-resource-grant-signature"))?;
    crate::runtime_grant_audit::retain_grant_success(postgres, "issue", "issued", &claims)?;
    Ok(json!({"protocol":"sourcery.hosted/runtime-resource-grant.v1",
        "keyId":key_id, "payload":payload, "signature":signature["signature"]}))
}

fn retain_denial(postgres: Value, operation: &str, mut event: Value,
    error: Box<dyn std::error::Error>) -> Result<Box<dyn std::error::Error>> {
    let reason = error.to_string();
    if reason == "runtime-resource-grant-audit-unavailable" { return Ok(error); }
    let structured = serde_json::from_str::<Value>(&reason).unwrap_or(Value::Null);
    let code = structured["code"].as_str().unwrap_or_else(|| reason.split('|').next().unwrap_or_default());
    let code = if code.starts_with("runtime-resource-") || code.starts_with("self-hosted-storage-")
        || code.starts_with("self-hosted-workload-") || code.starts_with("self-hosted-runtime-authority-") {
        code
    } else { "runtime-resource-grant-invalid" };
    event["operation"] = json!(operation);
    event["outcome"] = json!("denied");
    event["denialCode"] = json!(code);
    crate::runtime_grant_audit::retain_grant_event(postgres, event)?;
    Ok(fail(format!("runtime-grant-denial-retained|{reason}")))
}

fn binding_failure(error: Box<dyn std::error::Error>) -> Box<dyn std::error::Error> {
    match error.to_string().as_str() {
        "runtime-resource-grant-not-current" | "runtime-resource-grant-revoked" => error,
        _ => fail("runtime-resource-grant-binding-unavailable"),
    }
}

fn read_binding(postgres: &Value, query: &Value, proof: &Value) -> Result<Value> {
    let coordinate = |field: &str| match &query[field] {
        Value::Null => Ok(""),
        Value::String(value) if !value.is_empty() && value.len() <= 512 => Ok(value.as_str()),
        _ => Err(fail("Invalid runtime binding lookup coordinate")),
    };
    let (key, resource, scope) = (coordinate("bindingKey")?, coordinate("resourceRef")?, coordinate("expectedScopeHash")?);
    if (key.is_empty() && resource.is_empty()) || scope.is_empty() {
        return Err(fail("Invalid runtime binding lookup coordinates"));
    }
    let config = crate::hosted_postgres::configure(postgres.clone())?;
    let text = |field: &str| config[field].as_str().ok_or_else(|| fail("Missing runtime binding PostgreSQL configuration"));
    let port = config["port"].as_u64().ok_or_else(|| fail("Missing runtime binding PostgreSQL port"))?;
    let connection = crate::postgres::Connection::open(std::path::Path::new(text("socketDirectory")?),
        u16::try_from(port)?, text("database")?, text("user")?)?;
    let candidates = if key.is_empty() {
        connection.document(c"SELECT COALESCE(jsonb_agg(binding), '[]'::jsonb) FROM (
            SELECT entry.value AS binding FROM public.sourcery_hosted_authority_state AS state
            CROSS JOIN LATERAL jsonb_each(state.state_document->'bindings') AS entry
            WHERE state.authority_key = 'sourcery.capability-bindings'
            AND entry.value->>'resourceRef' = $1 AND entry.value->>'scopeHash' = $2
            AND entry.value->>'status' = 'active' LIMIT 2
        ) AS matches", &[resource, scope], 256 * 1024)?
    } else {
        connection.document(c"SELECT COALESCE(jsonb_agg(binding), '[]'::jsonb) FROM (
            SELECT state_document #> ARRAY['bindings', $1] AS binding
            FROM public.sourcery_hosted_authority_state WHERE authority_key = 'sourcery.capability-bindings'
        ) AS matches WHERE jsonb_typeof(binding) = 'object'",
            &[key], 256 * 1024)?
    };
    let entry = "runtimeGrant.currentBinding";
    let policy = Programme::admit(&[include_str!("runtime_grant_verify.encounter").to_owned()], entry,
        &BTreeSet::new(), &mut Meter::new(100_000))?;
    policy.run(entry, json!({"query":query, "candidates":candidates, "proof":proof}), &mut Meter::new(200_000))
}

pub(crate) fn run(resolve: bool) -> Result<()> {
    let input = read_bounded_observation(32_768)?;
    println!("{}", verify(&input, resolve, false)?);
    Ok(())
}

pub(crate) fn resolve_current_binding() -> Result<()> {
    let _signals = crate::appdev_host_process::Supervisor::new();
    let input = read_bounded_observation(32_768)?;
    let mut event = json!({"consumerId":input["boundary"]["consumerId"]});
    match resolve_grant(input.clone(), &mut event) {
        Ok(resource) => { println!("{resource}"); Ok(()) }
        Err(error) => Err(retain_denial(input["postgres"].clone(), "resolve", event, error)?),
    }
}

fn resolve_grant(mut input: Value, event: &mut Value) -> Result<Value> {
    if !input.is_object() { return Err(fail("runtime-resource-grant-invalid")); }
    let socket = input["authoritySocket"].take();
    authenticate(&socket, "resolve", &mut input["boundary"])?;
    let proof = input["proof"].take();
    let keyring = input["keyring"].take();
    let entry = "runtimeGrant.admitProof";
    let policy = Programme::admit(&[include_str!("runtime_grant_verify.encounter").to_owned()], entry,
        &BTreeSet::from(["value.describe", "record.entries"]), &mut Meter::new(100_000))?;
    let within = |field: &str, limit: usize| proof[field].as_str().is_some_and(|text| text.encode_utf16().count() <= limit);
    let key = policy.run(entry, json!({"proof":proof, "keyring":keyring,
        "withinBounds":within("payload", 8192) && within("signature", 1024)}), &mut Meter::new(200_000))?;
    input["publicKey"] = key;
    input["keyId"] = proof["keyId"].clone();
    input["payload"] = proof["payload"].clone();
    input["signature"] = proof["signature"].clone();
    let claims = verify(&input, true, true)?;
    *event = json!({"consumerId":claims["consumerId"], "bindingKey":claims["bindingKey"],
        "grantId":claims["grantId"], "provider":claims["provider"]});
    let query = json!({"bindingKey":claims["bindingKey"], "resourceRef":claims["resourceRef"],
        "expectedScopeHash":claims["scopeHash"]});
    let binding = read_binding(&input["postgres"], &query, &claims).map_err(binding_failure)?;
    let resource = crate::hosted_reconciliation::resolve_current_grant(
        &input["storageRoot"], &input["boundary"]["scope"], &claims, &binding)
        .map_err(|error| {
            let reason = error.to_string();
            if reason.starts_with("self-hosted-storage-") { error }
            else { fail("self-hosted-storage-marker|The private storage resource could not be opened.") }
        })?;
    crate::runtime_grant_audit::retain_grant_success(input["postgres"].take(), "resolve", "resolved", &claims)?;
    Ok(json!({"claims":claims, "resource":resource}))
}

fn verify(input: &Value, resolve: bool, production: bool) -> Result<Value> {
    let malformed = || fail("The runtime resource grant is malformed.");
    let encoded = input["payload"].as_str().filter(|value| value.len() <= 8192).ok_or_else(malformed)?;
    let bytes = Base64UrlUnpadded::decode_vec(encoded).map_err(|_| malformed())?;
    let wire = std::str::from_utf8(&bytes).map_err(|_| malformed())?;
    let claims: Value = serde_json::from_str(wire).map_err(|_| malformed())?;
    compat_value::external(&claims)?;
    let signature = input["signature"].as_str().filter(|value| value.len() <= 1024)
        .and_then(|value| Base64UrlUnpadded::decode_vec(value).ok()).unwrap_or_default();
    let public_key = input["publicKey"].as_str().filter(|value| value.len() == 43)
        .and_then(|value| Base64UrlUnpadded::decode_vec(value).ok()).unwrap_or_default();
    let entry = if resolve { "runtimeGrant.resolve" } else { "runtimeGrant.verify" };
    let policy = Programme::admit(&[include_str!("runtime_grant_verify.encounter").to_owned()], entry,
        &BTreeSet::from(["signature.ed25519.verify", "value.describe", "record.entries", "json.canonical",
            "kernel.invoke", "digest.sha256", "number.calculate"]),
        &mut Meter::new(100_000))?;
    let timestamp = |field| chrono::DateTime::parse_from_rfc3339(claims[field].as_str()?).ok()
        .map(|date| date.timestamp_millis());
    let (issued, expires) = (timestamp("issuedAt"), timestamp("expiresAt"));
    let mut boundary = input["boundary"].clone();
    if resolve {
        if !boundary.is_object() { return Err(malformed()); }
        if production { boundary["nowMs"] = json!(now_ms()?); }
        let now = boundary["nowMs"].as_f64();
        boundary["clockValid"] = json!(now.is_some_and(f64::is_finite));
    }
    policy.run(entry, json!({"wire":wire, "claims":claims, "keyId":input["keyId"],
        "publicKey":hex::encode(public_key), "signature":hex::encode(signature), "boundary":boundary, "production":production,
        "timestamps":issued.is_some() && expires.is_some(), "issuedAtMs":issued, "expiresAtMs":expires}),
        &mut Meter::new(200_000))
}
