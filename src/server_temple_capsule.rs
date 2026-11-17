use crate::{Result, fail, process::{Meter, Programme}, sqlite::Db};
use base64ct::{Base64, Encoding};
use chrono::{DateTime, SecondsFormat};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::{self, Write}, path::Path};

pub(crate) const SOURCE: &str = include_str!("server_temple_capsule.encounter");
pub(crate) const MAX_PUBLICATION_DOCUMENT_BYTES: usize = 184 * 1024 * 1024;
const ENTRIES: &[&str] = &["capsule.schema", "capsule.manifest", "capsule.event",
    "capsule.object", "capsule.document", "capsule.inspection"];

pub(crate) const ED25519_SPKI_PREFIX: &[u8] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

pub(crate) fn public_key(pem: &str) -> Result<String> {
    let body = pem.trim().strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|pem| pem.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or_else(|| fail("Expected a Server Temple Ed25519 public key"))?;
    let body: String = body.chars().filter(|character| !character.is_ascii_whitespace()).collect();
    let bytes = Base64::decode_vec(&body)?;
    let key = bytes.strip_prefix(ED25519_SPKI_PREFIX).filter(|key| key.len() == 32)
        .ok_or_else(|| fail("Expected a Server Temple Ed25519 public key"))?;
    Ok(hex::encode(key))
}

fn one(db: &Db, sql: &str) -> Result<Value> {
    let mut rows = db.query(sql, &[])?;
    if rows.len() != 1 { return Err(fail("Expected one Server Temple capsule row")); }
    Ok(rows.pop().expect("one capsule row"))
}

pub(crate) fn inspect(path: &Path) -> Result<Value> {
    if !path.is_file() { return Err(fail("Expected a Server Temple capsule file")); }
    let db = Db::open_readonly(path)?;
    db.interrupt_on_stop()?;
    db.exec("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF; BEGIN;")?;
    Ok(inspect_database(&db)?.0)
}

pub(crate) fn inspect_database(db: &Db) -> Result<(Value, Value)> {
    let mut meter = Meter::new(100_000_000);
    let policy = Programme::admit_entries(&[SOURCE.to_owned()],
        ENTRIES, &BTreeSet::from(["json.parse", "json.canonical", "digest.sha256", "value.describe",
            "signature.ed25519.verify", "text.matches", "value.type"]), &mut meter)?;
    let mut run = |entry, input| {
        if crate::http::stopping() { return Err(fail("Server Temple capsule inspection interrupted")); }
        policy.run(entry, input, &mut meter)
    };
    let version = one(db, "PRAGMA user_version")?["user_version"].clone();
    let integrity = db.query("PRAGMA quick_check", &[])?.into_iter()
        .map(|row| row["quick_check"].clone()).collect::<Vec<_>>();
    run("capsule.schema", json!({"version":version,"integrity":integrity}))?;
    let mut row = one(db, "SELECT manifest_json, manifest_hash FROM temple_manifest WHERE singleton = 1")?;
    let manifest: Value = serde_json::from_str(row["manifest_json"].as_str().ok_or_else(|| fail("Expected a Temple manifest"))?)?;
    let public_key = public_key(manifest["identityPublicKey"].as_str().ok_or_else(|| fail("Expected a Temple public key"))?)?;
    let signature = Base64::decode_vec(manifest["signature"]["value"].as_str().ok_or_else(|| fail("Expected a Temple signature"))?)?;
    let timestamp = manifest["createdAt"].as_str().ok_or_else(|| fail("Expected Temple creation time"))?;
    let canonical = DateTime::parse_from_rfc3339(timestamp).is_ok_and(|date|
        date.to_utc().to_rfc3339_opts(SecondsFormat::Millis, true) == timestamp);
    row["canonicalTimestamp"] = json!(canonical);
    row["publicKey"] = json!(public_key);
    row["signature"] = json!(hex::encode(signature));
    let manifest = run("capsule.manifest", row)?;
    let mut journal = json!({"eventCount":0,"headHash":"0".repeat(64)});
    db.visit("SELECT sequence, event_id, kind, actor, occurred_at, payload_json, payload_hash, previous_hash, event_hash
        FROM journal_events ORDER BY sequence", &[], |row| {
        journal = run("capsule.event", json!({"prior":journal,"row":row}))?;
        Ok(())
    })?;
    let mut objects = 0;
    db.visit("SELECT rowid, object_hash, byte_length FROM objects ORDER BY object_hash", &[], |mut row| {
        let id = row["rowid"].as_i64().ok_or_else(|| fail("Expected a Temple object row identifier"))?;
        let (size, digest) = db.temple_object_digest(id)?;
        row["actualBytes"] = json!(size);
        row["actualDigest"] = json!(digest);
        run("capsule.object", row)?;
        objects += 1;
        Ok(())
    })?;
    let mut documents = |query| -> Result<usize> {
        let mut count = 0;
        db.visit(query, &[], |row| {
            if row["name"] == "server-plugin-publication" {
                let bytes = row["document"].as_str().ok_or_else(|| fail("Expected a retained Temple publication"))?.len();
                if bytes > MAX_PUBLICATION_DOCUMENT_BYTES { return Err(fail("Retained Temple publication exceeded its size limit")); }
                if crate::http::stopping() { return Err(fail("Server Temple capsule inspection interrupted")); }
                policy.run("capsule.document", row, &mut Meter::new(bytes * 3 + 100_000))?;
            } else {
                run("capsule.document", row)?;
            }
            count += 1;
            Ok(())
        })?;
        Ok(count)
    };
    let projections = documents("SELECT name, content_json AS document, content_hash AS digest FROM projections ORDER BY name")?;
    let messages = documents("SELECT envelope_json AS document, envelope_hash AS digest FROM bridge_messages ORDER BY message_id")?;
    let secrets = one(db, "SELECT count(*) AS count FROM secret_references")?["count"].clone();
    let inspection = run("capsule.inspection", json!({"version":version,"manifest":manifest,"journal":journal,
        "objects":objects,"projections":projections,"messages":messages,"secrets":secrets}))?;
    Ok((inspection, manifest["publicKey"].clone()))
}

pub(crate) fn run(path: &Path) -> Result<()> {
    writeln!(io::stdout().lock(), "{}", inspect(path)?)?;
    Ok(())
}
