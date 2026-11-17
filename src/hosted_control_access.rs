use crate::{Result, appdev_host_process::Supervisor, compat_value, fail, hosted_postgres, postgres::Connection,
    process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use std::{collections::BTreeSet, ffi::CString, io::{self, Read}, path::Path, time::{Duration, SystemTime, UNIX_EPOCH}};

fn policy(entries: &[&str]) -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_control_access.encounter").to_owned(),
        include_str!("hosted_workspace_storage.encounter").to_owned(),
        include_str!("hosted_bearer.encounter").to_owned(), include_str!("hosted_revocation.encounter").to_owned(),
        include_str!("hosted_credential_issuance.encounter").to_owned()], entries,
        &BTreeSet::from(["kernel.invoke", "json.stringify", "value.type", "number.calculate", "number.isNatural",
            "text.trim", "text.split", "text.lowerCase", "text.matches", "http.decodePathSegment",
            "digest.sha256", "text.startsWith", "text.slice", "time.parseRfc3339", "record.put", "record.entries", "record.fromEntries", "value.string", "value.sort", "time.formatUtc"]),
        &mut Meter::new(200_000))
}

fn decide(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(12_000_000))
}

fn text<'a>(record: &'a Value, field: &str) -> Result<&'a str> {
    record[field].as_str().ok_or_else(|| fail(format!("Missing hosted control access field {field}")))
}

fn read_connection(options: Value) -> Result<Connection> {
    let config = hosted_postgres::configure(options)?;
    let timeout = config["connectionTimeoutMs"].as_u64().ok_or_else(|| fail("Missing hosted workspace connection timeout"))?;
    let port = config["port"].as_u64().ok_or_else(|| fail("Missing hosted workspace connection port"))?;
    Connection::open_readiness(Path::new(text(&config, "socketDirectory")?), u16::try_from(port)?,
        text(&config, "database")?, text(&config, "user")?, Duration::from_millis(timeout), None)
}

fn database_route(request: Value) -> Result<Value> {
    let policy = policy(&["workspaceRoute.coordinates", "workspaceRoute.databaseSnapshot"])?;
    let coordinates = decide(&policy, "workspaceRoute.coordinates", json!({
        "host":request["host"],"path":request["path"],"baseDomain":request["baseDomain"]
    }))?;
    let connection = read_connection(request["connection"].clone())?;
    let query = CString::new(include_str!("hosted_workspace_route.sql"))?;
    let principal = &request["principal"];
    let user = if principal["kind"] == "user" { principal["userId"].as_str().unwrap_or("") } else { "" };
    let authority = text(&request, "authorityKey")?;
    let snapshot = connection.document(&query, &[authority,
        text(&coordinates, "tenant")?, text(&coordinates, "app")?, text(&coordinates, "project")?,
        text(&coordinates, "workspace")?, user], 128 * 1024)?;
    decide(&policy, "workspaceRoute.databaseSnapshot", json!({
        "database":true, "snapshot":snapshot, "coordinates":coordinates, "principal":principal
    }))
}

fn verify_bearer(policy: &Programme, entry: &str, input: &Value, plan: &Value, mut snapshot: Value) -> Result<Value> {
    let digest = text(plan, "digest")?;
    let digest_matches = snapshot.get_mut("record").and_then(Value::as_object_mut)
        .and_then(|record| record.shift_remove("tokenDigest"))
        .and_then(|digest| digest.as_str().filter(|value| value.len() == 64).map(str::to_owned))
        .is_some_and(|stored| bool::from(digest.as_bytes().ct_eq(stored.as_bytes())));
    decide(policy, entry, json!({
        "kind":plan["kind"],"credentialId":plan["credentialId"],"snapshot":snapshot,
        "digestMatches":digest_matches,"mode":input["mode"],"nowMs":input["nowMs"]
    }))
}

fn database_bearer(request: Value) -> Result<Value> {
    let policy = policy(&["hostedBearer.plan", "hostedBearer.database"])?;
    let plan = bearer_plan(&policy, &request)?;
    let connection = read_connection(request["connection"].clone())?;
    bearer_at(&policy, &connection, request, &plan)
}

fn bearer_plan(policy: &Programme, request: &Value) -> Result<Value> {
    decide(policy, "hostedBearer.plan", json!({"token":request["token"],"mode":request["mode"]}))
}

fn bearer_at(policy: &Programme, connection: &Connection, mut request: Value, plan: &Value) -> Result<Value> {
    let kind = text(plan, "kind")?;
    let selected = text(plan, if kind == "session" { "digest" } else { "credentialId" })?;
    let query = CString::new(include_str!("hosted_bearer.sql"))?;
    let snapshot = connection.document(&query, &[text(&request, "authorityKey")?, kind, selected], 32 * 1024)?;
    request["nowMs"] = json!(u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?);
    verify_bearer(policy, "hostedBearer.database", &request, plan, snapshot)
}

fn audit_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| fail(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!("aud_{}", hex::encode(bytes)))
}

fn begin_authenticated_write(policy: &Programme, request: &mut Value) -> Result<(Connection, String)> {
    let plan = bearer_plan(policy, request)?;
    request["token"].take();
    let authority = text(request, "authorityKey")?.to_owned();
    let connection = hosted_postgres::begin_authority_write(request["connection"].take(), &authority)?;
    request["principal"] = bearer_at(policy, &connection, json!({"mode": request["mode"], "authorityKey": authority}), &plan)?;
    Ok((connection, authority))
}

fn database_issue(mut request: Value) -> Result<Value> {
    let policy = policy(&["hostedBearer.plan", "hostedBearer.database", "credentialIssuance.request",
        "credentialIssuance.snapshot", "credentialIssuance.record"])?;
    let (connection, authority) = begin_authenticated_write(&policy, &mut request)?;
    let mut input = request["input"].take();
    if !input.is_object() { return Err(fail("Missing hosted credential request")); }
    let now = SystemTime::now();
    input["mode"] = request["mode"].take();
    input["principal"] = request["principal"].take();
    input["nowMs"] = json!(u64::try_from(now.duration_since(UNIX_EPOCH)?.as_millis())?);
    let scope = decide(&policy, "credentialIssuance.request", input.clone())?;
    let query = CString::new(include_str!("hosted_credential_issuance.sql"))?;
    let coordinate = |name| scope[name].as_str().unwrap_or("");
    let snapshot = connection.document(&query, &[&authority, coordinate("tenantId"), coordinate("appId"),
        coordinate("projectId"), coordinate("workspaceId"), input["principal"]["userId"].as_str().unwrap_or("")], 32 * 1024)?;
    let revision = decide(&policy, "credentialIssuance.snapshot", snapshot.clone())?;
    let mut identity = [0_u8; 12];
    let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(&mut identity).map_err(|error| fail(error.to_string()))?;
    getrandom::getrandom(&mut *secret).map_err(|error| fail(error.to_string()))?;
    let id = format!("dvc_{}", hex::encode(identity));
    let token = zeroize::Zeroizing::new(format!("src_dev_{id}.{}", Base64UrlUnpadded::encode_string(&*secret)));
    let effect = decide(&policy, "credentialIssuance.record", json!({
        "scope":scope,"principal":input["principal"],"snapshot":snapshot,"id":id,"tokenDigest":crate::rel::hash(token.as_bytes()),
        "occurredAt":chrono::DateTime::<chrono::Utc>::from(now).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "auditId":audit_id()?
    }))?;
    let changed = connection.document(c"WITH changed AS (
        UPDATE public.sourcery_hosted_authority_state SET state_revision = state_revision + 1,
            state_document = jsonb_set(jsonb_set(jsonb_set(state_document, '{developerCredentials}',
                (state_document->'developerCredentials') || jsonb_build_array($3::jsonb)), '{audit}',
                (state_document->'audit') || jsonb_build_array($4::jsonb)), '{revision}', to_jsonb(state_revision + 1)),
            updated_at = CURRENT_TIMESTAMP
        WHERE authority_key = $1 AND state_revision = $2::bigint
            AND NOT EXISTS(SELECT FROM jsonb_array_elements(state_document->'developerCredentials') AS entry(item)
                WHERE item->>'id' = $3::jsonb->>'id' OR item->>'tokenDigest' = $3::jsonb->>'tokenDigest')
            AND NOT EXISTS(SELECT FROM jsonb_array_elements(state_document->'audit') AS entry(item)
                WHERE item->>'id' = $4::jsonb->>'id')
        RETURNING 1) SELECT to_jsonb(count(*)) FROM changed",
        &[&authority, &revision.to_string(), &effect["credential"].to_string(), &effect["audit"].to_string()], 1024)?;
    if changed != 1 { return Err(fail("Hosted credential issuance lost its locked authority revision")); }
    connection.command(c"COMMIT", c"COMMIT")?;
    Ok(json!({"token":token.as_str(),"credential":effect["public"]}))
}

fn database_revoke(mut request: Value) -> Result<Value> {
    let policy = policy(&["hostedBearer.plan", "hostedBearer.database", "hostedRevocation.target",
        "hostedRevocation.snapshot", "hostedRevocation.plan"])?;
    let (connection, authority) = begin_authenticated_write(&policy, &mut request)?;
    let target = decide(&policy, "hostedRevocation.target", request.clone())?;
    let collection = text(&target, "collection")?;
    let id = target["id"].as_str().unwrap_or("");
    let tenant = request["tenantId"].as_str().unwrap_or("");
    let user = text(&request["principal"], "userId")?;
    let query = CString::new(include_str!("hosted_revocation.sql"))?;
    let observed = connection.document(&query, &[&authority, collection, id, tenant, user], 32 * 1024)?;
    let revision = decide(&policy, "hostedRevocation.snapshot", observed.clone())?;
    request["record"] = observed["record"].clone();
    request["membership"] = observed["memberships"][0].clone();
    request["target"] = target.clone();
    request["auditId"] = json!(audit_id()?);
    request["occurredAt"] = json!(chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let effect = decide(&policy, "hostedRevocation.plan", request)?;
    let index = observed["position"].as_u64().ok_or_else(|| fail("Hosted revocation record has no array position"))?.to_string();
    let revision = revision.as_u64().ok_or_else(|| fail("Hosted revocation record has no revision"))?.to_string();
    let audit = effect["audit"].to_string();
    let revoked_at = effect["revokedAt"].to_string();
    let changed = connection.document(c"WITH changed AS (
        UPDATE public.sourcery_hosted_authority_state SET state_revision = state_revision + 1,
            state_document = jsonb_set(jsonb_set(jsonb_set(state_document, ARRAY[$3::text,$4::text,'revokedAt'], $5::jsonb),
                '{audit}', (state_document->'audit') || jsonb_build_array($6::jsonb)), '{revision}', to_jsonb(state_revision + 1)),
            updated_at = CURRENT_TIMESTAMP
        WHERE authority_key = $1 AND state_revision = $2::bigint AND state_document #>> ARRAY[$3::text,$4::text,'id'] = $7
            AND NOT EXISTS(SELECT FROM jsonb_array_elements(state_document->'audit') AS entry(item)
                WHERE item->>'id' = $6::jsonb->>'id')
        RETURNING 1) SELECT to_jsonb(count(*)) FROM changed",
        &[&authority, &revision, collection, &index, &revoked_at, &audit, id], 1024)?;
    if changed != 1 { return Err(fail("Hosted revocation lost its locked authority record")); }
    connection.command(c"COMMIT", c"COMMIT")?;
    Ok(effect["response"].clone())
}

fn memory_bearer(mut request: Value) -> Result<Value> {
    let policy = policy(&["hostedBearer.plan", "hostedBearer.verify"])?;
    let plan = decide(&policy, "hostedBearer.plan", json!({"token":request["token"],"mode":request["mode"]}))?;
    let snapshot = request["snapshot"].take();
    verify_bearer(&policy, "hostedBearer.verify", &request, &plan, snapshot)
}

pub(crate) fn run(operation: &str) -> Result<()> {
    let _signals = Supervisor::new();
    let limit = match operation {
        "route-database" | "bearer-database" | "revoke-database" | "issue-database" => 16 * 1024,
        "readiness" | "route-document" | "workspace-inventory" => 16 * 1024 * 1024,
        _ => 2 * 1024 * 1024,
    };
    let mut bytes = Vec::new();
    io::stdin().lock().take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit { return Err(fail("Hosted control access projection exceeds its input limit")); }
    let request: Value = serde_json::from_slice(&bytes)?;
    compat_value::external(&request)?;
    let output = match operation {
        "route-database" => database_route(request)?,
        "bearer-database" => database_bearer(request)?,
        "revoke-database" => database_revoke(request)?,
        "issue-database" => database_issue(request)?,
        "bearer-verify" => memory_bearer(request)?,
        _ => {
            let entry = match operation {
                "authorize" => "controlAccess.authorize",
                "readiness" => "controlAccess.readiness",
                "route-document" => "workspaceRoute.document",
                "workspace-inventory" => "workspaceRoute.inventory",
                "bearer-plan" => "hostedBearer.plan",
                "bearer-permissions" => "hostedBearer.permissions",
                "issue-request" => "credentialIssuance.request",
                "issue-record" => "credentialIssuance.record",
                "revoke-target" => "hostedRevocation.target",
                "revoke-plan" => "hostedRevocation.plan",
                _ => return Err(fail("Unsupported hosted control access operation")),
            };
            decide(&policy(&[entry])?, entry, request)?
        }
    };
    crate::http::check_interruption(false)?;
    println!("{output}");
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_postgres_route(database: &Connection, options: Value) -> Result<()> {
    let mut request = json!({
        "connection": options, "authorityKey": "sourcery.control-plane", "baseDomain": "hosted.test",
        "host": " ACME.HOSTED.TEST:443 ", "path": "/t/%61cme/a/revenue/p/forecast/w/dev/",
        "principal": {"kind": "user", "userId": "usr_alice"}
    });
    assert!(database_route(request.clone()).unwrap_err().to_string().contains("route-not-found"));
    let mut snapshot = json!({
        "schemaVersion": 1, "revision": 7, "identities": [{"id": "usr_alice"}],
        "tenants": [{"id": "ten_acme", "slug": "acme"}],
        "memberships": [{"tenantId": "ten_acme", "userId": "usr_alice", "role": "owner"}],
        "apps": [{"id": "app_revenue", "tenantId": "ten_acme", "slug": "revenue"}],
        "projects": [{"id": "prj_forecast", "tenantId": "ten_acme", "appId": "app_revenue", "slug": "forecast"}],
        "workspaces": [{"id": "wsp_dev", "tenantId": "ten_acme", "appId": "app_revenue", "projectId": "prj_forecast",
            "slug": "dev", "region": "au-west", "storageNamespace": "tenants/ten_acme/workspaces/wsp_dev"}],
        "sessions": [], "secrets": [], "developerCredentials": [], "audit": []
    });
    database.document(c"INSERT INTO public.sourcery_hosted_authority_state VALUES
        ('sourcery.control-plane', 7, $1::jsonb) RETURNING to_jsonb(state_revision)", &[&snapshot.to_string()], 1024)?;
    let route = database_route(request.clone())?;
    assert_eq!(route["workspaceId"], "wsp_dev");
    assert_eq!(route["canonicalPath"], "/t/acme/a/revenue/p/forecast/w/dev");
    request["principal"]["userId"] = json!("usr_other");
    assert!(database_route(request.clone()).unwrap_err().to_string().contains("forbidden"));
    request["principal"]["userId"] = json!("usr_alice");
    snapshot["workspaces"][0]["storageNamespace"] = json!("tenants/ten_crossed/workspaces/wsp_dev");
    database.document(c"UPDATE public.sourcery_hosted_authority_state SET state_document = $1::jsonb
        WHERE authority_key = 'sourcery.control-plane' RETURNING to_jsonb(state_revision)", &[&snapshot.to_string()], 1024)?;
    assert!(database_route(request.clone()).unwrap_err().to_string().contains("immutable tenant/workspace lineage"));
    database.command(c"UPDATE public.sourcery_hosted_authority_state SET state_revision = 8
        WHERE authority_key = 'sourcery.control-plane'", c"UPDATE 1")?;
    assert!(database_route(request).unwrap_err().to_string().contains("current, supported authority snapshot"));
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_postgres_bearer(database: &Connection, options: Value) -> Result<()> {
    let session = "src_session_disposable";
    let credential = "src_dev_dvc_personal.disposable";
    let mut request = json!({"connection":options,"authorityKey":"sourcery.bearer-fixture","mode":"personal-only","token":session});
    let mut document = json!({
        "schemaVersion": 2, "revision": 2, "identities": [{"id":"usr_bob"}],
        "tenants": [{"id":"ten_acme","slug":"acme"}],
        "memberships": [{"tenantId":"ten_acme","userId":"usr_bob","role":"developer","revokedAt":null}],
        "apps": [{"id":"app_revenue","tenantId":"ten_acme","slug":"revenue","deletedAt":null}],
        "projects": [{"id":"prj_forecast","tenantId":"ten_acme","appId":"app_revenue","slug":"forecast"}],
        "projectMemberships": [{"tenantId":"ten_acme","appId":"app_revenue","projectId":"prj_forecast",
            "userId":"usr_bob","role":"author","revokedAt":null}],
        "workspaces": [],
        "sessions": [{"id":"ses_disposable","userId":"usr_bob","tokenDigest":crate::rel::hash(session),
            "expiresAt":"2099-01-01T00:00:00.000Z","revokedAt":null}],
        "developerCredentials": [{"id":"dvc_personal","subjectUserId":"usr_bob","tenantId":"ten_acme",
            "appId":"app_revenue","projectId":"prj_forecast","workspaceId":null,"tokenDigest":crate::rel::hash(credential),
            "permissions":["authoring.write"],"expiresAt":"2099-01-01T00:00:00.000Z","revokedAt":null}],
        "secrets": [], "audit": []
    });
    assert!(database_bearer(request.clone()).unwrap_err().to_string().contains("session-invalid"));
    let save = |state: &Value| database.document(c"INSERT INTO public.sourcery_hosted_authority_state
        (authority_key, state_revision, state_document) VALUES ('sourcery.bearer-fixture', 2, $1::jsonb)
        ON CONFLICT (authority_key) DO UPDATE SET state_document = excluded.state_document
        RETURNING to_jsonb(state_revision)", &[&state.to_string()], 1024);
    save(&document)?;
    assert_eq!(database_bearer(request.clone())?, json!({"kind":"user","userId":"usr_bob","sessionId":"ses_disposable"}));
    request["token"] = json!(credential);
    assert_eq!(database_bearer(request.clone())?["permissions"], json!(["authoring.write"]));
    document["projectMemberships"][0]["role"] = json!("viewer");
    save(&document)?;
    assert!(database_bearer(request.clone()).unwrap_err().to_string().contains("credential-invalid"));
    document["developerCredentials"][0]["projectId"] = Value::Null;
    document["developerCredentials"][0]["scopeMode"] = json!("application-portfolio-v1");
    save(&document)?;
    assert_eq!(database_bearer(request.clone())?["grant"]["scope"], json!({"tenantId":"ten_acme","appId":"app_revenue"}));
    document["memberships"][0]["revokedAt"] = json!("2026-01-01T00:00:00.000Z");
    document["sessions"][0]["expiresAt"] = json!("2000-01-01T00:00:00.000Z");
    save(&document)?;
    assert!(database_bearer(request.clone()).unwrap_err().to_string().contains("credential-invalid"));
    request["token"] = json!(session);
    assert!(database_bearer(request.clone()).unwrap_err().to_string().contains("session-invalid"));

    document["sessions"][0]["expiresAt"] = json!("2099-01-01T00:00:00.000Z");
    document["memberships"][0]["revokedAt"] = Value::Null;
    document["projectMemberships"][0]["role"] = json!("author");
    save(&document)?;
    request["input"] = json!({"operation":"personal","tenantId":"ten_acme","appId":"app_revenue","projectId":"prj_forecast",
        "workspaceId":null,"name":" Fixture credential ","permissions":["secret.read"],"expiresInMs":60000});
    assert!(database_issue(request.clone()).unwrap_err().to_string().contains("credential-permissions-invalid"));
    request["input"]["permissions"] = json!(["authoring.write", "authoring.read", "authoring.write"]);
    let issued = database_issue(request.clone())?;
    assert_eq!(issued["credential"]["name"], "Fixture credential");
    assert_eq!(issued["credential"]["permissions"], json!(["authoring.read", "authoring.write"]));
    assert!(issued["credential"].get("tokenDigest").is_none());
    let mut verification = request.clone();
    verification["token"] = issued["token"].clone();
    assert_eq!(database_bearer(verification)?["credentialId"], issued["credential"]["id"]);
    let mut tenant_request = request.clone();
    tenant_request["input"]["operation"] = json!("tenant");
    tenant_request["input"]["permissions"] = json!(["secret.read"]);
    assert!(database_issue(tenant_request.clone()).unwrap_err().to_string().contains("developer-credentials-disabled"));
    tenant_request["mode"] = json!("enabled");
    tenant_request["input"]["expiresInMs"] = json!(31622400001_u64);
    assert!(database_issue(tenant_request.clone()).unwrap_err().to_string().contains("credential-ttl-invalid"));
    tenant_request["input"]["expiresInMs"] = json!(3600000);
    let tenant_issued = database_issue(tenant_request.clone())?;
    assert_eq!(tenant_issued["credential"]["permissions"], json!(["secret.read"]));
    assert!(tenant_issued["credential"].get("subjectUserId").is_none());
    tenant_request["token"] = tenant_issued["token"].clone();
    assert_eq!(database_bearer(tenant_request)?["credentialId"], tenant_issued["credential"]["id"]);
    database.command(c"UPDATE public.sourcery_hosted_authority_state
        SET state_document = jsonb_set(state_document, '{memberships,0,role}', to_jsonb('viewer'::text))
        WHERE authority_key = 'sourcery.bearer-fixture'", c"UPDATE 1")?;
    request["operation"] = json!("tenant-credential");
    request["tenantId"] = json!("ten_acme");
    request["id"] = json!("dvc_personal");
    assert!(database_revoke(request.clone()).unwrap_err().to_string().contains("forbidden"));
    request["operation"] = json!("personal-credential");
    let revoked = database_revoke(request.clone())?;
    assert_eq!(revoked["id"], "dvc_personal");
    assert!(revoked.get("tokenDigest").is_none() && revoked.get("subjectUserId").is_none());
    assert_eq!(database_revoke(request.clone())?["revokedAt"], revoked["revokedAt"]);

    request["operation"] = json!("session");
    assert_eq!(database_revoke(request.clone())?["id"], "ses_disposable");
    assert!(database_bearer(request).unwrap_err().to_string().contains("session-invalid"));
    let result = database.document(c"SELECT jsonb_build_object('row', state_revision,
        'document', state_document->'revision', 'audit', state_document->'audit')
        FROM public.sourcery_hosted_authority_state WHERE authority_key = 'sourcery.bearer-fixture'", &[], 8192)?;
    assert_eq!(result["row"], 7);
    assert_eq!(result["document"], 7);
    assert_eq!(result["audit"].as_array().unwrap().len(), 5);
    assert_eq!(result["audit"][0]["action"], "developerCredential.personal.created");
    assert_eq!(result["audit"][1]["action"], "developerCredential.created");
    assert_eq!(result["audit"][2]["action"], "developerCredential.personal.revoked");
    assert_eq!(result["audit"][4]["action"], "identity.session.revoked");
    assert_eq!(result["audit"][4]["actorId"], "usr_bob");
    Ok(())
}
