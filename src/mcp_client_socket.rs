use crate::{Result, fail, http, image, mcp_authorization, mcp_client::{self, Resolver},
    mcp_project_socket::{connect, peer, receive, send, socket_parent}, rel, runtime_authority::Socket};
use serde_json::{Value, json};
use std::{io::{self, Write}, os::unix::net::UnixStream, path::{Path, PathBuf}, thread, time::Duration};

const PROTOCOL: &str = "encounter/hosted-mcp-client/1";
const REQUEST_LIMIT: usize = 16 * 1024;
const REPLY_LIMIT: usize = 96 * 1024;

fn release(pins: &[&str; 4], runtime: &str) -> Result<String> {
    if pins.iter().any(|pin| pin.len() != 64 || !pin.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))) {
        return Err(fail("Expected the four hosted MCP client release pins"));
    }
    Ok(rel::hash(format!("{PROTOCOL}:{runtime}:{}", pins.join(":"))))
}

pub(crate) struct Client {
    path: PathBuf,
    uid: u32,
    release: String,
}

impl Client {
    pub(crate) fn load(path: &Path, uid: u32, pins: &[&str; 4]) -> Result<Self> {
        Self::load_with_runtime(path, uid, pins, &image::runtime_pin()?)
    }

    pub(crate) fn load_with_runtime(path: &Path, uid: u32, pins: &[&str; 4], runtime: &str) -> Result<Self> {
        socket_parent(path, uid)?;
        let client = Self { path:path.to_owned(), uid, release:release(pins, runtime)? };
        if client.exchange(json!({"operation":"ready"}))?["ready"] != true {
            return Err(fail("Matched hosted MCP client resolver is unavailable"));
        }
        Ok(client)
    }

    fn exchange(&self, request: Value) -> Result<Value> {
        let mut stream = connect(&self.path, self.uid)?;
        send(&mut stream, json!({"protocol":PROTOCOL,"release":self.release,"request":request}), REQUEST_LIMIT)?;
        let mut reply: Value = serde_json::from_slice(&receive(&mut stream, REPLY_LIMIT, Duration::from_secs(7))?)?;
        if reply["protocol"] != PROTOCOL || reply["release"] != self.release {
            return Err(fail("Hosted MCP client resolver used a different release"));
        }
        Ok(reply["response"].take())
    }

    pub(crate) fn resolve(&self, client_id: &str, redirect_uri: &str) -> Result<Value> {
        let response = self.exchange(json!({"operation":"resolve","clientId":client_id,"redirectUri":redirect_uri}))?;
        if matches!(response["error"].as_str(), Some("invalid_client" | "invalid_redirect")) { return Ok(response); }
        if response["client"]["clientId"] != client_id || !response["redirectUri"].is_string() {
            return Err(fail("Invalid hosted MCP client resolver response"));
        }
        Ok(response)
    }
}

fn connection(mut stream: UnixStream, uid: u32, release: &str, resolver: &mut Resolver) -> Result<()> {
    peer(&stream, uid)?;
    let frame: Value = serde_json::from_slice(&receive(&mut stream, REQUEST_LIMIT, Duration::from_secs(1))?)?;
    if frame["protocol"] != PROTOCOL || frame["release"] != release {
        return Err(fail("Hosted MCP client resolver requires its matched release"));
    }
    let request = &frame["request"];
    let response = match request["operation"].as_str() {
        Some("ready") => json!({"ready":true}),
        Some("resolve") => resolver.resolve(request).unwrap_or_else(|error| {
            let reason = if error.is::<mcp_client::CallbackRefused>() { "invalid_redirect" } else { "invalid_client" };
            json!({"error":reason})
        }),
        _ => return Err(fail("Unsupported hosted MCP client operation")),
    };
    if http::stopping() { return Ok(()); }
    send(&mut stream, json!({"protocol":PROTOCOL,"release":release,"response":response}), REPLY_LIMIT)
}

pub(crate) fn serve(args: &[String]) -> Result<()> {
    let [socket, uid, clients, clients_pin, hosts, hosts_pin, schema, schema_pin, policy, policy_pin] = args else {
        return Err(fail("Expected a hosted MCP client socket, consumer UID, and pinned client, host, schema and policy files"));
    };
    let uid = uid.parse()?;
    let release = release(&[clients_pin, hosts_pin, schema_pin, policy_pin], &image::runtime_pin()?)?;
    let contract = mcp_authorization::load(Path::new(schema), schema_pin, Path::new(policy), policy_pin, None)?;
    let mut resolver = Resolver::load(Path::new(clients), clients_pin, Path::new(hosts), hosts_pin, contract)?;
    http::install_stop_signals()?;
    let (_socket, listener) = Socket::bind(socket.into(), 0o660)?;
    println!("Encounter hosted MCP client resolver ready");
    while !http::stopping() {
        match listener.accept() {
            Ok((stream, _)) => { let _ = connection(stream, uid, &release, &mut resolver); }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(crate) fn lookup(args: &[String]) -> Result<()> {
    let [socket, uid, clients, hosts, schema, policy] = args else {
        return Err(fail("Expected a hosted MCP client socket, resolver UID and four release pins"));
    };
    http::install_stop_signals()?;
    let client = Client::load(Path::new(socket), uid.parse()?, &[clients, hosts, schema, policy])?;
    let input = mcp_client::read_request()?;
    let id = input["clientId"].as_str().ok_or_else(|| fail("Missing hosted MCP client identity"))?;
    let redirect = input["redirectUri"].as_str().ok_or_else(|| fail("Missing hosted MCP client callback"))?;
    let result = client.resolve(id, redirect)?;
    if result["error"].is_string() { return Err(fail("Hosted MCP client or callback is unavailable")); }
    writeln!(io::stdout().lock(), "{result}")?;
    Ok(())
}
