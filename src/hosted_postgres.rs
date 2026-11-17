use crate::{Result, appdev_host_process::Supervisor, compat_value, fail, http,
    postgres::Connection, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::{self, Read}, path::Path, time::{Duration, Instant}};

const INPUT_LIMIT: u64 = 16 * 1024;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_postgres.encounter").to_owned()],
        &["hostedPostgres.config", "hostedPostgres.ready"],
        &BTreeSet::from(["kernel.invoke", "value.describe", "record.entries", "text.matches", "text.replace", "path.resolvePosix",
            "number.isNatural", "number.calculate"]), &mut Meter::new(200_000))
}

fn read_config(policy: &Programme) -> Result<Value> {
    let mut bytes = Vec::new();
    io::stdin().lock().take(INPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > INPUT_LIMIT { return Err(fail("Self-hosted PostgreSQL configuration exceeds its input bound")); }
    let request = serde_json::from_slice(&bytes)?;
    compat_value::external(&request)?;
    policy.run("hostedPostgres.config", request, &mut Meter::new(200_000))
}

pub(super) fn configure(options: Value) -> Result<Value> {
    policy()?.run("hostedPostgres.config", json!({"options":options}), &mut Meter::new(200_000))
}

pub(super) const JOURNAL_LIMIT: usize = 128 * 1024 * 1024;

pub(super) enum Journal {
    Capacity,
    RuntimeGrantAudit,
}

impl Journal {
    fn key(&self) -> &'static str {
        match self {
            Self::Capacity => "sourcery.capacity",
            Self::RuntimeGrantAudit => "sourcery.runtime-grant-audit",
        }
    }

    pub(super) fn initial(&self) -> &'static str {
        match self {
            Self::Capacity => r#"{"protocol":"sourcery-hosted-capacity-state/1","revision":0,"allocations":{},"reservations":{}}"#,
            Self::RuntimeGrantAudit => r#"{"protocol":"sourcery-runtime-grant-audit-state/1","revision":0,"events":[]}"#,
        }
    }
}

pub(super) fn begin_authority_write(options: Value, key: &str) -> Result<Connection> {
    let config = configure(options)?;
    let field = |name: &str| config[name].as_str().ok_or_else(|| fail("Missing hosted PostgreSQL write field"));
    let port = config["port"].as_u64().ok_or_else(|| fail("Missing hosted PostgreSQL write port"))?;
    let database = Connection::open_write(Path::new(field("socketDirectory")?), u16::try_from(port)?,
        field("database")?, field("user")?)?;

    // Take the existing session lock before BEGIN so each waiter gets a fresh serializable snapshot.
    database.document(c"SELECT jsonb_build_object('lock', pg_advisory_lock(hashtextextended($1, 0)))", &[key], 1024)?;
    database.command(c"BEGIN ISOLATION LEVEL SERIALIZABLE", c"BEGIN")?;
    Ok(database)
}

pub(super) struct JournalTransaction {
    database: Connection,
    key: &'static str,
    revision: u64,
}

impl JournalTransaction {
    pub(super) fn begin(journal: Journal, options: Value) -> Result<(Self, Value)> {
        let key = journal.key();
        let initial = journal.initial();
        let database = begin_authority_write(options, key)?;
        database.document(c"WITH inserted AS (
            INSERT INTO public.sourcery_hosted_authority_state (authority_key, state_revision, state_document)
            VALUES ($1, 0, $2::jsonb) ON CONFLICT (authority_key) DO NOTHING RETURNING 1)
            SELECT to_jsonb(count(*)) FROM inserted", &[key, initial], 1024)?;
        let mut row = database.document(c"SELECT jsonb_build_object('revision', state_revision, 'document', state_document)
            FROM public.sourcery_hosted_authority_state WHERE authority_key = $1 FOR UPDATE", &[key], JOURNAL_LIMIT)?;
        let revision = row["revision"].as_u64().ok_or_else(|| fail("Missing hosted PostgreSQL journal revision"))?;
        Ok((Self { database, key, revision }, row["document"].take()))
    }

    pub(super) fn revision(&self) -> Value { json!(self.revision) }

    pub(super) fn write_successor(&self, state: &Value) -> Result<()> {
        let next = state["revision"].as_u64()
            .filter(|next| self.revision.checked_add(1) == Some(*next))
            .ok_or_else(|| fail("Invalid hosted PostgreSQL successor revision"))?.to_string();
        let current = self.revision.to_string();
        let document = serde_json::to_string(state)?;
        if document.len() > JOURNAL_LIMIT { return Err(fail("Hosted PostgreSQL state exceeds its byte bound")); }
        let updated = self.database.document(c"WITH updated AS (
            UPDATE public.sourcery_hosted_authority_state
            SET state_revision = $2::bigint, state_document = $3::jsonb, updated_at = CURRENT_TIMESTAMP
            WHERE authority_key = $1 AND state_revision = $4::bigint RETURNING 1)
            SELECT to_jsonb(count(*)) FROM updated", &[self.key, &next, &document, &current], 1024)?;
        if updated != 1 { return Err(fail("Hosted PostgreSQL revision changed outside its journal lock")); }
        Ok(())
    }

    pub(super) fn commit(self) -> Result<()> { self.database.command(c"COMMIT", c"COMMIT") }
    pub(super) fn rollback(self) -> Result<()> { self.database.command(c"ROLLBACK", c"ROLLBACK") }
}

pub(crate) fn configuration() -> Result<()> {
    println!("{}", read_config(&policy()?)?);
    Ok(())
}

pub(crate) fn readiness() -> Result<()> {
    let _signals = Supervisor::new();
    let policy = policy()?;
    let config = read_config(&policy)?;
    println!("{}", check_readiness(&policy, config, None)?);
    Ok(())
}

pub(super) fn probe_readiness(options: &Value, deadline: Instant) -> Result<()> {
    let policy = policy()?;
    let config = policy.run("hostedPostgres.config", json!({"options": options}), &mut Meter::new(200_000))?;
    check_readiness(&policy, config, Some(deadline))?;
    Ok(())
}

fn check_readiness(policy: &Programme, config: Value, deadline: Option<Instant>) -> Result<Value> {
    let text = |field| config[field].as_str().ok_or_else(|| fail("Missing hosted PostgreSQL configuration field"));
    let port = config["port"].as_u64().ok_or_else(|| fail("Missing hosted PostgreSQL port"))?;
    let timeout = config["connectionTimeoutMs"].as_u64().ok_or_else(|| fail("Missing hosted PostgreSQL connection timeout"))?;
    let connection = Connection::open_readiness(Path::new(text("socketDirectory")?), u16::try_from(port)?,
        text("database")?, text("user")?, Duration::from_millis(timeout), deadline)?;
    connection.command(c"BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY", c"BEGIN")?;
    let observation = connection.document(c"SELECT pg_catalog.jsonb_build_object(
        'database', pg_catalog.current_database(), 'role', current_user,
        'version', pg_catalog.current_setting('server_version_num')::integer,
        'checksums', pg_catalog.current_setting('data_checksums'), 'inRecovery', pg_catalog.pg_is_in_recovery(),
        'unixSocket', pg_catalog.inet_server_addr() IS NULL,
        'readOnly', pg_catalog.current_setting('transaction_read_only'),
        'isolation', pg_catalog.current_setting('transaction_isolation'))", &[], 4096)
        .and_then(|mut observation| {
            if connection.server_version() >= 160_000 {
                observation["systemUser"] = connection.document(
                    c"SELECT pg_catalog.jsonb_build_object('systemUser', system_user)", &[], 4096)?["systemUser"].clone();
            }
            Ok(observation)
        });
    let rollback = connection.command(c"ROLLBACK", c"ROLLBACK");
    let observation = observation?;
    rollback?;
    let result = policy.run("hostedPostgres.ready", json!({"config":config, "observed":observation}), &mut Meter::new(200_000))?;
    http::check_interruption(false)?;
    Ok(result)
}

#[cfg(test)]
#[test]
fn readiness_binds_the_observed_transaction_and_database() -> Result<()> {
    let policy = policy()?;
    let config = policy.run("hostedPostgres.config", json!({"options":{
        "socketDirectory":"/var/run/postgresql", "database":"sourcery", "user":"sourcery"
    }}), &mut Meter::new(200_000))?;
    assert_eq!(config["socketDirectory"], "/run/postgresql");
    assert_eq!(config["port"], 5432);
    let observed = json!({"database":"sourcery","role":"sourcery","version":140000,
        "checksums":"on","inRecovery":false,"unixSocket":true,"readOnly":"on","isolation":"serializable"});
    let evaluate = |observed| policy.run("hostedPostgres.ready", json!({"config":config, "observed":observed}), &mut Meter::new(200_000));
    assert_eq!(evaluate(observed.clone())?["status"], "ready");
    let mut current = observed.clone();
    current["version"] = json!(180006);
    current["systemUser"] = json!("peer:fixture");
    assert_eq!(evaluate(current.clone())?["status"], "ready");
    for method in [Value::Null, json!("scram-sha-256:fixture")] {
        current["systemUser"] = method;
        assert!(evaluate(current.clone()).is_err());
    }
    for (key, crossed) in [("database", json!("other")), ("role", json!("other")), ("version", json!(139999)),
        ("checksums", json!("off")), ("inRecovery", json!(true)), ("unixSocket", json!(false)),
        ("readOnly", json!("off")), ("isolation", json!("read committed"))] {
        let mut invalid = observed.clone();
        invalid[key] = crossed;
        assert!(evaluate(invalid).is_err(), "{key}");
    }
    Ok(())
}
