use crate::{Result, compat_value, fail, http, process::{Meter, Programme}, server_temple_capsule, signature, sqlite::Db};
use base64ct::{Base64, Encoding};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::Write, net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream}};

pub(crate) struct Transit {
    policy: Programme,
    carrier: String,
    maximum_bytes: usize,
    url: String,
}

impl Transit {
    pub(crate) fn bind(config: Value) -> Result<(Self, TcpListener)> {
        let policy = Programme::admit_entries(&[include_str!("server_temple_transit.encounter").to_owned(),
            server_temple_capsule::SOURCE.to_owned()],
            &["transit.configure", "transit.route", "transit.error", "transit.incoming", "transit.peer",
                "transit.signature", "transit.deliver", "transit.reply", "transit.journal"],
            &BTreeSet::from(["value.type", "value.describe", "text.matches", "text.utf8Length", "record.entries",
                "record.put", "json.parse", "json.canonical", "digest.sha256", "number.isNatural", "number.calculate"]),
            &mut Meter::new(20_000_000))?;
        let plan = policy.run("transit.configure", config, &mut Meter::new(20_000_000))?;
        let host = required(&plan, "host")?;
        let port = u16::try_from(plan["port"].as_u64().ok_or_else(|| fail("Expected a Temple transit port"))?)?;
        let ip = match host {
            "127.0.0.1" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            "::1" => IpAddr::V6(Ipv6Addr::LOCALHOST),
            _ => return Err(fail("Expected a loopback Temple transit host")),
        };
        let listener = TcpListener::bind((ip, port))?;
        let authority = if host == "::1" { "[::1]" } else { host };
        let url = format!("http://{authority}:{}", listener.local_addr()?.port());
        let maximum_bytes = usize::try_from(plan["maximumBytes"].as_u64()
            .ok_or_else(|| fail("Expected a Temple transit byte limit"))?)?;
        let carrier = required(&plan, "carrier")?.to_owned();
        Ok((Self { policy, carrier, maximum_bytes, url }, listener))
    }

    fn evaluate(&self, entry: &str, input: Value) -> Result<Value> {
        self.policy.run(entry, input, &mut Meter::new(20_000_000))
    }

    pub(crate) fn description(&self) -> Value {
        json!({"protocol":"sourcery/temple-transit-http-server.v1","url":self.url,"maximumBytes":self.maximum_bytes})
    }

    pub(crate) fn maximum_bytes(&self) -> usize { self.maximum_bytes }

    pub(crate) fn route(&self, request: &http::Request) -> Result<Value> {
        self.evaluate("transit.route", json!({"path":request.path,"method":request.method}))
    }

    pub(crate) fn refusal(&self, error: &str) -> Result<Value> {
        self.evaluate("transit.error", json!(error))
    }

    pub(crate) fn receive(&self, db: &Db, signer: &SigningKey, identity: &Value, actor: &Value, body: &[u8],
        now: DateTime<Utc>) -> Result<Value> {
        let bundle: Value = serde_json::from_slice(body).map_err(|_| fail("Temple transit request is not valid JSON."))?;
        compat_value::external(&bundle)?;
        let envelope_time = canonical_time(&bundle["envelope"]["createdAt"]);
        let incoming = self.evaluate("transit.incoming", json!({
            "bundle":bundle,"templeId":identity["templeId"],"canonicalBundleTime":canonical_time(&bundle["createdAt"]).is_some(),
            "canonicalEnvelopeTime":envelope_time.is_some(),"ageMs":envelope_time.map(|time| (now-time).num_milliseconds()),
            "payloadShape":payload_shape(&bundle["envelope"]["payload"])
        }))?;
        let envelope = &incoming["envelope"];
        let projection = one(db, "SELECT content_json, content_hash FROM projections WHERE name = 'temple-federation-peers'", &[])?;
        let admissions = db.query("SELECT envelope_json, envelope_hash FROM bridge_messages
            WHERE status = 'admitted-human-approved' ORDER BY message_id", &[])?;
        let peer = self.evaluate("transit.peer", json!({"projection":projection,"admissions":admissions,"envelope":envelope}))?;
        let peer = server_temple_capsule::public_key(peer.as_str().ok_or_else(|| fail("Expected an admitted peer key"))?)
            .map_err(|_| fail("Invalid admitted peer key"))?;
        let signature = Base64::decode_vec(required(&envelope["signature"], "value")?)
            .map_err(|_| fail("Invalid Temple transit signature"))?;
        let verified = signature::verify_transit_ed25519(required(&incoming, "signedBytes")?, &peer,
            &hex::encode(signature), &mut Meter::new(100_000))?;
        self.evaluate("transit.signature", json!(verified))?;
        let id = envelope["messageId"].clone();
        let inbox = message(db, &id)?;
        let receipt = one(db, "SELECT message_id, direction, status, envelope_json, envelope_hash FROM bridge_messages
            WHERE direction = 'outbox' AND json_extract(envelope_json, '$.kind') = 'temple-delivery-receipt'
              AND json_extract(envelope_json, '$.payload.inReplyTo') = ?1 ORDER BY message_id LIMIT 2", &[id])?;
        let correlated = if envelope["kind"] == "temple-delivery-receipt" { message(db, &envelope["payload"]["inReplyTo"])? }
            else { Value::Null };
        let time = now.to_rfc3339_opts(SecondsFormat::Millis, true);
        let plan = self.evaluate("transit.deliver", json!({"incoming":incoming,"inbox":inbox,
            "receipt":receipt,"correlated":correlated,"templeId":identity["templeId"],"manifestHash":identity["manifestHash"],"now":time}))?;
        if let Some(bytes) = plan["priorSignedBytes"].as_str() {
            let signature = Base64::decode_vec(required(&plan["prior"]["signature"], "value")?)
                .map_err(|_| fail("Invalid retained Temple acknowledgement signature"))?;
            let local = hex::encode(signer.verifying_key().as_bytes());
            let verified = signature::verify_transit_ed25519(bytes, &local, &hex::encode(signature), &mut Meter::new(100_000))?;
            self.evaluate("transit.signature", json!(verified))?;
        }
        let signed = plan["signedBytes"].as_str()
            .map(|bytes| Base64::encode_string(&signer.sign(bytes.as_bytes()).to_bytes()));
        let reply = self.evaluate("transit.reply", json!({"plan":plan,"signature":signed,"carrier":self.carrier,"now":time}))?;
        let messages = reply["messages"].as_array().ok_or_else(|| fail("Expected admitted Temple transit messages"))?;
        for message in messages {
            let encoded = compat_value::canonical_json(&message["envelope"])?;
            db.query("INSERT INTO bridge_messages(message_id,direction,status,envelope_json,envelope_hash,created_at)
                VALUES (?1,?2,?3,?4,?5,?6)", &[message["messageId"].clone(),message["direction"].clone(),
                message["status"].clone(),json!(encoded),message["hash"].clone(),json!(time)])?;
        }
        let tail = one(db, "SELECT sequence, event_hash FROM journal_events ORDER BY sequence DESC LIMIT 1", &[])?;
        let sequence = tail["sequence"].as_u64().unwrap_or(0);
        let head = tail["event_hash"].as_str().map(str::to_owned).unwrap_or_else(|| "0".repeat(64));
        let rows = self.evaluate("transit.journal", json!({"events":reply["events"],"sequence":sequence,"head":head,"actor":actor,"now":time}))?;
        for row in rows.as_array().ok_or_else(|| fail("Expected Temple transit journal rows"))? {
            crate::server_temple_checkpoint::append_event(db, row)?;
        }
        Ok(reply["response"].clone())
    }
}

fn one(db: &Db, sql: &str, params: &[Value]) -> Result<Value> {
    let mut rows = db.query(sql, params)?;
    match rows.len() {
        0 => Ok(Value::Null),
        1 => Ok(rows.pop().expect("one Temple transit row")),
        _ => Err(fail("Ambiguous retained Temple transit evidence")),
    }
}

fn message(db: &Db, id: &Value) -> Result<Value> {
    one(db, "SELECT message_id, direction, status, envelope_json, envelope_hash FROM bridge_messages WHERE message_id = ?1",
        std::slice::from_ref(id))
}

fn required<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row[field].as_str().ok_or_else(|| fail("Expected Temple transit text"))
}

fn canonical_time(value: &Value) -> Option<DateTime<Utc>> {
    let text = value.as_str()?;
    let time = DateTime::parse_from_rfc3339(text).ok()?.to_utc();
    (time.to_rfc3339_opts(SecondsFormat::Millis, true) == text).then_some(time)
}

fn payload_shape(value: &Value) -> Value {
    let mut stack = vec![(value, 0)];
    let (mut depth, mut members, mut string_bytes) = (0, 0, 0);
    while let Some((value, level)) = stack.pop() {
        depth = depth.max(level);
        match value {
            Value::String(text) => string_bytes = string_bytes.max(text.len()),
            Value::Object(fields) => {
                members += fields.len();
                stack.extend(fields.values().map(|child| (child, level + 1)));
            }
            Value::Array(items) => {
                members += items.len();
                stack.extend(items.iter().map(|child| (child, level + 1)));
            }
            _ => {}
        }
    }
    json!({"depth":depth,"members":members,"stringBytes":string_bytes})
}

pub(crate) fn respond(stream: &mut TcpStream, status: u64, body: &Value, head: bool) -> Result<()> {
    let (line, allow) = match status {
        200 => ("200 OK", ""),
        400 => ("400 Bad Request", ""),
        403 => ("403 Forbidden", ""),
        404 => ("404 Not Found", ""),
        405 => ("405 Method Not Allowed", "Allow: POST\r\n"),
        413 => ("413 Content Too Large", ""),
        503 => ("503 Service Unavailable", ""),
        _ => return Err(fail("Unknown Temple transit status")),
    };
    let body = format!("{body}\n");
    write!(stream, "HTTP/1.1 {line}\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: private, no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: {}\r\n{allow}\r\n", body.len())?;
    if !head { stream.write_all(body.as_bytes())?; }
    Ok(())
}

#[cfg(test)]
#[test]
fn projected_peer_refusal_cannot_fall_through_to_legacy_admission() -> Result<()> {
    let (transit, _) = Transit::bind(json!({"protocol":"sourcery/temple-transit-http-config.v1"}))?;
    let digest = "a".repeat(64);
    let admission = json!({"protocol":"sourcery/temple-peer-admission.v1","peerTempleId":"temple.peer",
        "peerManifestHash":digest,"peerIdentityPublicKey":"fixture key","authorityGranted":false,"privateStateShared":false});
    let encoded = compat_value::canonical_json(&admission)?;
    let mut input = json!({"projection":null,"envelope":{"fromTempleId":"temple.peer","fromManifestHash":digest},
        "admissions":[{"envelope_json":encoded,"envelope_hash":crate::rel::hash(&encoded)}]});
    assert_eq!(transit.evaluate("transit.peer", input.clone())?, "fixture key");
    for status in ["suspended", "revoked"] {
        let content = json!({"protocol":"sourcery/temple-federation-control.v1",
            "peers":{"temple.peer":{"status":status,"manifestHash":digest,"identityPublicKey":"fixture key",
                "authorityGranted":false,"privateStateShared":false}}});
        let encoded = compat_value::canonical_json(&content)?;
        input["projection"] = json!({"content_json":encoded,"content_hash":crate::rel::hash(&encoded)});
        assert!(transit.evaluate("transit.peer", input.clone()).is_err());
    }
    Ok(())
}
