use crate::{Result, appdev_host_process::Supervisor, fail, http, postgres::{Connection, unix_peer}, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, ffi::CStr, fs::{File, OpenOptions}, io, os::{fd::{AsRawFd, OwnedFd},
    unix::{fs::{MetadataExt, OpenOptionsExt}, net::UnixStream, process::CommandExt}}, path::Path, process::{Command, Stdio}, time::Duration};

const SOCKET: &str = "/run/postgresql";
const PORT: u16 = 5432;
const LOCK: &str = "/run/lock/sourcery-postgres-provision.lock";
const AUTH_OBSERVATION: &CStr = c"SELECT jsonb_build_object('systemUser', system_user)";
const HOST_OBSERVATION: &CStr = c"SELECT jsonb_build_object('currentUser', current_user, 'database', current_database(),
    'checksums', current_setting('data_checksums') = 'on', 'primary', NOT pg_is_in_recovery())";
const DATABASE_OBSERVATION: &CStr = c"SELECT (SELECT jsonb_build_object('owner', pg_get_userbyid(datdba),
    'encoding', pg_encoding_to_char(encoding), 'acceptsConnections', datallowconn, 'connect', has_database_privilege('sourcery', oid, 'CONNECT'),
    'temporary', has_database_privilege('sourcery', oid, 'TEMPORARY'), 'publicAccess', EXISTS (SELECT 1 FROM aclexplode(coalesce(datacl,
    acldefault('d', datdba))) WHERE grantee = 0)) FROM pg_database WHERE datname = 'sourcery')";
const DATABASE_PREFLIGHT: &CStr = c"SELECT coalesce((SELECT jsonb_build_object('encoding', pg_encoding_to_char(encoding),
    'acceptsConnections', datallowconn) FROM pg_database WHERE datname = 'sourcery'), 'null'::jsonb)";
const ROLE_OBSERVATION: &CStr = c"SELECT jsonb_build_object('login', rolcanlogin, 'superuser', rolsuper, 'createDatabase', rolcreatedb,
    'createRole', rolcreaterole, 'inherit', rolinherit, 'replication', rolreplication, 'bypassRls', rolbypassrls)
    FROM pg_roles WHERE rolname = 'sourcery'";
const SCHEMA_OBSERVATION: &CStr = c"SELECT jsonb_build_object('owner', pg_get_userbyid(nspowner),
    'publicCreate', EXISTS (SELECT 1 FROM aclexplode(coalesce(nspacl, acldefault('n', nspowner)))
    WHERE grantee = 0 AND privilege_type = 'CREATE')) FROM pg_namespace WHERE nspname = 'public'";

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("postgres_provision.encounter").to_owned()],
        &["postgres.provisionPlan", "postgres.role", "postgres.database", "postgres.schema", "postgres.receipt"],
        &BTreeSet::from(["number.calculate"]), &mut Meter::new(1_000_000))
}

fn decide(programme: &Programme, name: &str, facts: Value) -> Result<Value> {
    programme.run(name, facts, &mut Meter::new(1_000_000))
}

fn connect(socket: &Path, port: u16, database: &str, role: &str, server_uid: u32, write: bool) -> Result<Connection> {
    if socket.symlink_metadata()?.uid() != server_uid {
        return Err(fail("PostgreSQL socket directory is not owned by the expected server account"));
    }
    let connection = if write { Connection::open_write(socket, port, database, role)? }
        else { Connection::open(socket, port, database, role)? };
    if connection.peer_uid()? != server_uid { return Err(fail("PostgreSQL socket peer is not the expected server account")); }
    Ok(connection)
}

fn observed_host(connection: &Connection, local_account: &str) -> Result<Value> {
    let mut host = connection.document(HOST_OBSERVATION, &[], 4096)?;
    let version = connection.server_version();
    host["version"] = json!(version);
    // Servers before 16 have no SYSTEM_USER value. The admin phase on those
    // servers separately checks that the wrong OS account cannot use the app role.
    let authentication_reported = version >= 160_000;
    host["authReported"] = json!(authentication_reported);
    host["peerAuthenticated"] = if authentication_reported {
        json!(connection.document(AUTH_OBSERVATION, &[], 4096)?["systemUser"] == format!("peer:{local_account}"))
    } else { Value::Null };
    Ok(host)
}

fn transaction(connection: &Connection, work: impl FnOnce() -> Result<()>) -> Result<()> {
    connection.command(c"BEGIN", c"BEGIN")?;
    work()?;
    connection.command(c"COMMIT", c"COMMIT")
}

fn admin(socket: &Path, port: u16, server_uid: u32, account: &str) -> Result<Value> {
    let policy = policy()?;
    let administrative = connect(socket, port, "postgres", "postgres", server_uid, true)?;
    let mut host = observed_host(&administrative, account)?;
    host["database"] = administrative.document(DATABASE_PREFLIGHT, &[], 4096)?;
    let version = host["version"].clone();
    let operations = decide(&policy, "postgres.provisionPlan", host)?;
    for operation in operations.as_array().ok_or_else(|| fail("Missing PostgreSQL provisioning operations"))? {
        match operation.as_str() {
            Some("bound-role") => transaction(&administrative, || {
                administrative.command(c"DO $provision$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sourcery') THEN
                    CREATE ROLE sourcery LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
                    END IF; END $provision$", c"DO")?;
                administrative.command(c"ALTER ROLE sourcery LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS", c"ALTER ROLE")?;
                decide(&policy, "postgres.role", administrative.document(ROLE_OBSERVATION, &[], 4096)?)?;
                Ok(())
            })?,
            Some("create-database") => administrative.command(c"CREATE DATABASE sourcery ENCODING 'UTF8' TEMPLATE template0 OWNER sourcery", c"CREATE DATABASE")?,
            Some("bound-database") => transaction(&administrative, || {
                administrative.command(c"ALTER DATABASE sourcery OWNER TO sourcery", c"ALTER DATABASE")?;
                administrative.command(c"REVOKE ALL ON DATABASE sourcery FROM PUBLIC", c"REVOKE")?;
                administrative.command(c"GRANT CONNECT, TEMPORARY ON DATABASE sourcery TO sourcery", c"GRANT")?;
                decide(&policy, "postgres.database", administrative.document(DATABASE_OBSERVATION, &[], 4096)?)?;
                Ok(())
            })?,
            Some("bound-schema") => {
                let database = connect(socket, port, "sourcery", "postgres", server_uid, true)?;
                transaction(&database, || {
                    database.command(c"REVOKE CREATE ON SCHEMA public FROM PUBLIC", c"REVOKE")?;
                    database.command(c"ALTER SCHEMA public OWNER TO sourcery", c"ALTER SCHEMA")?;
                    decide(&policy, "postgres.schema", database.document(SCHEMA_OBSERVATION, &[], 4096)?)?;
                    Ok(())
                })?;
            }
            _ => return Err(fail("Unknown PostgreSQL provisioning operation")),
        }
    }
    let wrong_account_rejected = administrative.server_version() < 160_000
        && Connection::rejects_peer(socket, port, "sourcery", "sourcery")?;
    Ok(json!({"status":"provisioned","version":version,"wrongAccountRejected":wrong_account_rejected}))
}

fn peer(socket: &Path, port: u16, server_uid: u32, account: &str) -> Result<Value> {
    observed_host(&connect(socket, port, "sourcery", "sourcery", server_uid, false)?, account)
}

#[derive(Clone, Copy)]
struct Account { uid: u32, gid: u32 }

fn account(name: &CStr) -> Result<Account> {
    let info = unsafe { libc::getpwnam(name.as_ptr()).as_ref() }.ok_or_else(|| fail("Expected dedicated PostgreSQL OS accounts"))?;
    if info.pw_uid == 0 { return Err(fail("PostgreSQL service account must be unprivileged")); }
    Ok(Account { uid: info.pw_uid, gid: info.pw_gid })
}

fn lifecycle_lock() -> Result<File> {
    let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(LOCK)?;
    let metadata = lock.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
        return Err(fail("PostgreSQL lifecycle lock must be a protected root-owned file"));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("Another PostgreSQL provisioner holds the lifecycle lock"));
    }
    Ok(lock)
}

fn spawn_worker(supervisor: &mut Supervisor, phase: &'static str, identity: Account) -> Result<Value> {
    let (_supervisor_socket, worker_socket) = UnixStream::pair()?;
    let mut command = Command::new("/proc/self/exe");
    command.args(["provision-self-hosted-postgres-worker", phase]).env_clear()
        .env("LC_ALL", "C").uid(identity.uid).gid(identity.gid)
        .stdin(Stdio::from(OwnedFd::from(worker_socket)));
    let output = supervisor.capture("PostgreSQL provisioning worker", &mut command, Duration::from_secs(45), 4096)?;
    Ok(serde_json::from_slice(&output)?)
}

pub(crate) fn worker(phase: &str) -> Result<()> {
    let parent = unix_peer(libc::STDIN_FILENO)?;
    if parent.uid != 0 || parent.pid != unsafe { libc::getppid() } {
        return Err(fail("PostgreSQL provisioning worker requires its root supervisor socket"));
    }
    let postgres = account(c"postgres")?;
    let expected = match phase {
        "admin" => postgres,
        "peer" => account(c"sourcery")?,
        _ => return Err(fail("Unknown PostgreSQL provisioning phase")),
    };
    if unsafe { libc::geteuid() } != expected.uid || unsafe { libc::getegid() } != expected.gid {
        return Err(fail("PostgreSQL provisioning worker is running as the wrong Unix account"));
    }
    http::install_stop_signals()?;
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if parent.pid != unsafe { libc::getppid() } { return Err(fail("PostgreSQL provisioning supervisor exited")); }
    let result = match phase {
        "admin" => admin(Path::new(SOCKET), PORT, postgres.uid, "postgres")?,
        "peer" => peer(Path::new(SOCKET), PORT, postgres.uid, "sourcery")?,
        _ => unreachable!("validated PostgreSQL provisioning phase"),
    };
    println!("{result}");
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 { return Err(fail("Sourcery PostgreSQL provisioning requires root")); }
    let mut supervisor = Supervisor::new();
    let postgres = account(c"postgres")?;
    let sourcery = account(c"sourcery")?;
    if postgres.uid == sourcery.uid { return Err(fail("PostgreSQL administrative and application accounts must differ")); }
    let _lock = lifecycle_lock()?;
    let admin = spawn_worker(&mut supervisor, "admin", postgres)?;
    let peer = spawn_worker(&mut supervisor, "peer", sourcery)?;
    let receipt = decide(&policy()?, "postgres.receipt", json!({"admin":admin,"peer":peer}))?;
    println!("{receipt}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appdev_host_process::Scratch;
    use std::{fs, io::Write, thread, time::Instant};

    #[test]
    fn provisioning_policy_requires_checksums_primary_and_peer_evidence() -> Result<()> {
        let policy = policy()?;
        let mut observed = json!({"version":180_000,"checksums":true,"primary":true,"currentUser":"postgres",
            "authReported":true,"peerAuthenticated":true,"database":null});
        assert_eq!(decide(&policy, "postgres.provisionPlan", observed.clone())?,
            json!(["bound-role","create-database","bound-database","bound-schema"]));
        for key in ["checksums", "primary", "peerAuthenticated"] {
            observed[key] = json!(false);
            assert!(decide(&policy, "postgres.provisionPlan", observed.clone()).is_err());
            observed[key] = json!(true);
        }
        observed["version"] = json!(130_000);
        assert!(decide(&policy, "postgres.provisionPlan", observed).is_err());
        let old_peer = json!({"version":140_000,"database":"sourcery","currentUser":"sourcery","checksums":true,
            "primary":true,"authReported":false,"peerAuthenticated":null});
        let mut admin = json!({"status":"provisioned","version":140_000,"wrongAccountRejected":false});
        assert!(decide(&policy, "postgres.receipt", json!({"admin":admin,"peer":old_peer})).is_err());
        admin["wrongAccountRejected"] = json!(true);
        assert_eq!(decide(&policy, "postgres.receipt", json!({"admin":admin,"peer":old_peer}))?["authentication"], "unix-peer");
        Ok(())
    }

    #[test]
    #[ignore = "requires the installed PostgreSQL 18 server binaries and a disposable Unix socket"]
    fn provision_disposable_postgres_cluster() -> Result<()> {
        let binaries = Path::new("/usr/lib/postgresql/18/bin");
        let fixture = Scratch::create(&std::env::temp_dir(), "pg-")?;
        let data = fixture.path().join("data");
        let socket = fixture.path().join("socket");
        fs::create_dir(&socket)?;
        let uid = unsafe { libc::geteuid() };
        let user = unsafe { libc::getpwuid(uid).as_ref() }.ok_or_else(|| fail("Missing fixture Unix identity"))?;
        let user = unsafe { CStr::from_ptr(user.pw_name) }.to_str()?.to_owned();
        if !user.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) {
            return Err(fail("Invalid fixture Unix identity"));
        }
        let mut children = Supervisor::children();
        let mut init = Command::new(binaries.join("initdb"));
        init.arg("-D").arg(&data).args(["--username=postgres", "--auth-local=trust", "--auth-host=trust", "--no-sync", "--data-checksums"])
            .env("LC_ALL", "C").stdin(Stdio::null());
        children.capture("Initialize disposable PostgreSQL fixture", &mut init, Duration::from_secs(15), 8192)?;
        let auth = data.join("pg_hba.conf");
        fs::write(&auth, "local all all trust\n")?;
        fs::write(data.join("pg_ident.conf"), format!("fixture {user} postgres\nfixture {user} sourcery\n"))?;
        writeln!(OpenOptions::new().append(true).open(data.join("postgresql.conf"))?, "shared_buffers = 16MB")?;
        let mut postgres = Command::new(binaries.join("postgres"));
        postgres.arg("-D").arg(&data).arg("-k").arg(&socket).args(["-p", "5432", "-c", "listen_addresses="])
            .stdout(Stdio::null()).stdin(Stdio::null());
        let child = children.start("Start disposable PostgreSQL fixture", &mut postgres)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let ready = loop {
            if let Ok(connection) = connect(&socket, PORT, "postgres", "postgres", uid, false) { break connection; }
            if child.try_wait()?.is_some() || Instant::now() >= deadline { return Err(fail("PostgreSQL fixture did not become ready")); }
            thread::sleep(Duration::from_millis(50));
        };
        assert!(admin(&socket, PORT, uid, &user).unwrap_err().to_string().contains("Unix-peer"));
        assert!(ready.document(DATABASE_PREFLIGHT, &[], 4096)?.is_null());
        assert_eq!(ready.document(c"SELECT to_jsonb(count(*)) FROM pg_roles WHERE rolname = 'sourcery'", &[], 4096)?, 0);
        drop(ready);
        fs::write(&auth, "local all all peer map=fixture\n")?;
        if unsafe { libc::kill(child.id() as i32, libc::SIGHUP) } != 0 { return Err(io::Error::last_os_error().into()); }
        loop {
            let connection = connect(&socket, PORT, "postgres", "postgres", uid, false)?;
            if observed_host(&connection, &user)?["peerAuthenticated"] == true { break; }
            if child.try_wait()?.is_some() || Instant::now() >= deadline { return Err(fail("PostgreSQL fixture did not apply peer authentication")); }
            thread::sleep(Duration::from_millis(50));
        }
        for attempt in 0..2 {
            let provisioned = admin(&socket, PORT, uid, &user)?;
            let access = peer(&socket, PORT, uid, &user)?;
            let receipt = decide(&policy()?, "postgres.receipt", json!({"admin":provisioned,"peer":access}))?;
            assert_eq!(receipt["status"], "ready");
            assert_eq!(receipt["superuser"], false);
            assert_eq!(receipt["dataChecksums"], true);
            if attempt == 0 {
                let root = connect(&socket, PORT, "sourcery", "postgres", uid, true)?;
                root.command(c"ALTER ROLE sourcery SUPERUSER CREATEDB", c"ALTER ROLE")?;
                root.command(c"GRANT CREATE ON SCHEMA public TO PUBLIC", c"GRANT")?;
            }
        }
        assert!(Connection::rejects_peer(&socket, PORT, "sourcery", "pg_read_all_data")?);

        use crate::runtime_grant_audit::{Operation, postgres_transaction};
        let journal = Connection::open_write(&socket, PORT, "sourcery", "sourcery")?;
        journal.command(c"CREATE TABLE public.sourcery_hosted_authority_state (
            authority_key text PRIMARY KEY, state_revision bigint NOT NULL,
            state_document jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        )", c"CREATE TABLE")?;
        let postgres = json!({"socketDirectory":socket,"database":"sourcery","user":"sourcery"});
        let snapshot = || postgres_transaction(Operation::Snapshot, json!({"postgres":postgres}));
        assert_eq!(snapshot()?["events"], 0);
        let event = postgres_transaction(Operation::Append, json!({"postgres":postgres,"maximumEvents":100,
            "occurredAt":"2026-11-12T00:00:00.000Z","event":{"operation":"issue","outcome":"issued",
            "consumerId":"private-consumer","denialCode":"none"}}))?;
        assert_eq!(event["sequence"], 1);
        assert!(event.get("consumerId").is_none());
        let current = snapshot()?;
        assert_eq!(current["events"], 1);
        assert_eq!(current["headHash"], event["eventHash"]);
        journal.command(c"UPDATE public.sourcery_hosted_authority_state SET state_revision = 2", c"UPDATE 1")?;
        assert!(snapshot().unwrap_err().to_string().contains("crossed row/document revisions"));
        crate::hosted_capacity::verify_postgres_journal(postgres.clone())?;
        crate::hosted_control_access::verify_postgres_route(&journal, postgres.clone())?;
        crate::hosted_control_access::verify_postgres_bearer(&journal, postgres)?;
        Ok(())
    }
}
