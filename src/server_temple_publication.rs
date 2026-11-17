use crate::{Result, compat_value, fail, http, process::{Meter, Programme}, rel, server_temple_capsule, signature};
use base64ct::{Base64, Encoding};
use chrono::{DateTime, SecondsFormat};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{collections::{BTreeMap, BTreeSet}, net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream}, time::{Duration, Instant}};

const MAX_ARTIFACT_BYTES: usize = 48 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;

pub(crate) struct Publication {
    policy: Programme,
    origin: String,
    public_host: String,
    local_host: String,
    manifest: Value,
    key_fingerprint: String,
    active: Option<Catalogue>,
}

struct Catalogue {
    expires_ms: i64,
    catalogue: Value,
    artifacts: BTreeMap<String, Vec<u8>>,
}

fn time_ms(value: &Value) -> Option<i64> {
    let text = value.as_str()?;
    let time = DateTime::parse_from_rfc3339(text).ok()?.to_utc();
    (time.to_rfc3339_opts(SecondsFormat::Millis, true) == text).then(|| time.timestamp_millis())
}

fn required<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name].as_str().ok_or_else(|| fail("Expected Server Temple publication text"))
}

fn canonical_host(origin: &str) -> Result<&str> {
    let (protocol, authority) = origin.split_once("://").ok_or_else(|| fail("Expected a publication origin"))?;
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, suffix) = ipv6.split_once(']').ok_or_else(|| fail("Invalid publication IPv6 origin"))?;
        if host.parse::<Ipv6Addr>()?.to_string() != host { return Err(fail("Expected canonical publication IPv6 origin")); }
        (host, suffix.strip_prefix(':'))
    } else {
        authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port)))
    };
    if let Some(port) = port {
        let parsed = port.parse::<u16>()?;
        if parsed == 0 || parsed.to_string() != port
            || (protocol == "https" && parsed == 443) || (protocol == "http" && parsed == 80) {
            return Err(fail("Expected a canonical publication port"));
        }
    }
    if !host.contains(':') && host.trim_end_matches('.').rsplit('.').next().is_some_and(|label|
        label.bytes().all(|byte| byte.is_ascii_digit())) && host.parse::<Ipv4Addr>().ok().is_none_or(|ip| ip.to_string() != host)
    {
        return Err(fail("Expected a canonical publication IPv4 origin"));
    }
    Ok(authority)
}

impl Publication {
    pub(crate) fn bind(config: Value, now_ms: i64) -> Result<(Self, TcpListener)> {
        let policy = Programme::admit_entries(&[include_str!("server_temple_publication.encounter").to_owned()],
            &["templePublication.configure", "templePublication.route", "templePublication.identity", "templePublication.catalogue"],
            &BTreeSet::from(["value.type", "value.describe", "number.isNatural", "number.calculate",
                "text.matches", "text.match", "time.formatUtc"]), &mut Meter::new(20_000_000))?;
        let pending = time_ms(&config["publication"]["expiresAt"]);
        let plan = policy.run("templePublication.configure", json!({"config":config,"nowMs":now_ms,
            "pendingExpiresMs":pending,"validPendingTime":pending.is_some()}), &mut Meter::new(20_000_000))?;
        let port = u16::try_from(plan["port"].as_u64().ok_or_else(|| fail("Expected a publication port"))?)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
        listener.set_nonblocking(true)?;
        let local_host = listener.local_addr()?.to_string();
        let origin = plan["origin"].as_str().map(str::to_owned).unwrap_or_else(|| format!("http://{local_host}"));
        let public_host = canonical_host(&origin)?.to_owned();
        Ok((Self { policy, origin, public_host, local_host, manifest:Value::Null, key_fingerprint:String::new(),
            active:None }, listener))
    }

    fn evaluate(&self, entry: &str, input: Value) -> Result<Value> {
        self.policy.run(entry, input, &mut Meter::new(20_000_000))
    }

    pub(crate) fn description(&self) -> Value {
        json!({"origin":self.origin,"localOrigin":format!("http://{}",self.local_host)})
    }

    pub(crate) fn load(&mut self, manifest: &Value, row: Value, signer: &SigningKey, now_ms: i64) -> Result<()> {
        self.manifest = serde_json::from_str(required(manifest, "manifest_json")?)?;
        let key = signer.verifying_key();
        let public_key = hex::encode(key.as_bytes());
        let der = [server_temple_capsule::ED25519_SPKI_PREFIX, key.as_bytes()].concat();
        self.key_fingerprint = format!("sha256:{}", rel::hash(der));
        self.identity_body(now_ms)?;
        if row.is_null() { return Ok(()); }
        let encoded = required(&row, "content_json")?;
        if encoded.len() > server_temple_capsule::MAX_PUBLICATION_DOCUMENT_BYTES {
            return Err(fail("Retained Temple publication exceeded its size limit"));
        }
        if row["content_hash"] != rel::hash(encoded) {
            return Err(fail("Retained Temple publication changed during custody startup"));
        }
        let mut content: Value = serde_json::from_str(encoded)?;
        compat_value::external(&content)?;
        if content["origin"] != self.origin { return Ok(()); }
        let catalogue = content["catalogue"].take();
        let mut unsigned = catalogue.clone();
        let signature = unsigned.as_object_mut().and_then(|row| row.shift_remove("signature"))
            .ok_or_else(|| fail("Retained plugin catalogue requires a signature"))?;
        let signature = Base64::decode_vec(signature.as_str().ok_or_else(|| fail("Invalid retained plugin signature"))?)?;
        if !signature::verify_publication_ed25519(&compat_value::canonical_json_compact(&unsigned)?,
            &public_key, &hex::encode(signature), &mut Meter::new(5 * 1024 * 1024))? {
            return Err(fail("Retained plugin catalogue signature differs from the Temple identity"));
        }
        let expires_ms = time_ms(&catalogue["expiresAt"]);
        let retained = content["artifacts"].take();
        let retained = retained.as_array().filter(|rows| rows.len() <= 200)
            .ok_or_else(|| fail("Invalid retained Temple plugin inventory"))?;
        let mut artifacts = BTreeMap::new();
        let mut observations = Vec::new();
        let mut total = 0;
        for artifact in retained {
            if http::stopping() { return Err(fail("Server Temple publication interrupted")); }
            let name = required(artifact, "fileName")?;
            let encoded = required(artifact, "content")?;
            if encoded.len() > MAX_ARTIFACT_BYTES.div_ceil(3) * 4 {
                return Err(fail("Retained Temple plugin exceeded its size limit"));
            }
            let bytes = Base64::decode_vec(encoded)?;
            total += bytes.len();
            if bytes.len() > MAX_ARTIFACT_BYTES || total > MAX_TOTAL_BYTES {
                return Err(fail("Retained Temple plugin publication exceeded its size limit"));
            }
            let bundle: Value = serde_json::from_slice(&bytes)?;
            let dependencies: Vec<_> = match bundle["dependencies"].as_array() {
                Some(items) => items.iter().map(|dependency| dependency["subject"].clone()).collect(),
                None if bundle["dependencies"].is_null() => Vec::new(),
                None => return Err(fail("Invalid retained Temple plugin dependencies")),
            };
            observations.push(json!({"name":name,"sha256":rel::hash(&bytes),"bytes":bytes.len(),
                "bundleHash":bundle["bundleHash"],"id":bundle["plugin"]["subject"],
                "pluginName":bundle["plugin"]["name"],"dependencies":dependencies}));
            if artifacts.insert(name.to_owned(), bytes).is_some() { return Err(fail("Duplicate retained Temple plugin file")); }
        }
        self.evaluate("templePublication.catalogue", json!({"origin":self.origin,"templeId":self.manifest["templeId"],
            "catalogue":catalogue,"protocol":content["protocol"],"revision":row["revision"],"nowMs":now_ms,
            "expiresMs":expires_ms,"validExpiry":expires_ms.is_some(),"artifacts":observations}))?;
        self.active = Some(Catalogue { expires_ms:expires_ms.ok_or_else(|| fail("Invalid Temple publication expiry"))?,
            catalogue, artifacts });
        Ok(())
    }

    fn identity_body(&self, now_ms: i64) -> Result<Value> {
        self.evaluate("templePublication.identity", json!({"manifest":self.manifest,"origin":self.origin,
            "keyFingerprint":self.key_fingerprint,"nowMs":now_ms}))
    }

    pub(crate) fn respond(&self, stream: &mut TcpStream, request: &http::Request, signer: &SigningKey, now_ms: i64) -> Result<()> {
        let head = request.method == "HEAD";
        let route = self.evaluate("templePublication.route", json!({"method":request.method,"path":request.path,
            "host":request.headers.get("host"),"publicHost":self.public_host,"localHost":self.local_host,
            "published":self.active.is_some(),"expiresMs":self.active.as_ref().map(|active| active.expires_ms),"nowMs":now_ms}))?;
        match route["kind"].as_str() {
            Some("error") => respond_json(stream, route["status"].as_u64().ok_or_else(|| fail("Expected a Temple publication status"))?,
                &json!({"error":route["error"]}), head),
            Some("identity") => {
                let mut body = self.identity_body(now_ms)?;
                let bytes = compat_value::canonical_json_compact(&body)?;
                body["signature"] = json!(Base64::encode_string(&signer.sign(bytes.as_bytes()).to_bytes()));
                respond_json(stream, 200, &body, head)
            }
            Some("health") => respond_json(stream, 200, &json!({"status":"ready","kind":"ServerTemple",
                "templeId":self.manifest["templeId"],"cataloguePublished":self.active.is_some()}), head),
            Some("catalogue") => respond_json(stream, 200, &self.active.as_ref()
                .ok_or_else(|| fail("Missing admitted Temple catalogue"))?.catalogue, head),
            Some("artifact") => match self.active.as_ref().and_then(|active| active.artifacts.get(route["name"].as_str()?)) {
                Some(bytes) => respond(stream, 200, bytes, head),
                None => respond_json(stream, 404, &json!({"error":"not-published"}), head),
            },
            _ => Err(fail("Unknown Server Temple publication route")),
        }
    }
}

pub(crate) fn respond_json(stream: &mut TcpStream, status: u64, body: &Value, head: bool) -> Result<()> {
    respond(stream, status, format!("{body}\n").as_bytes(), head)
}

fn respond(stream: &mut TcpStream, status: u64, bytes: &[u8], head: bool) -> Result<()> {
    let line = match status {
        200 => "200 OK", 400 => "400 Bad Request", 404 => "404 Not Found", 405 => "405 Method Not Allowed",
        421 => "421 Misdirected Request", 503 => "503 Service Unavailable",
        _ => return Err(fail("Unknown Temple publication status")),
    };
    let header = format!("HTTP/1.1 {line}\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", bytes.len());
    let deadline = Instant::now() + Duration::from_secs(5);
    http::write_temple_bytes(stream, header.as_bytes(), deadline)?;
    if !head { http::write_temple_bytes(stream, bytes, deadline)?; }
    Ok(())
}

#[cfg(test)]
#[test]
fn public_catalogue_requires_the_exact_host_and_a_current_offer() -> Result<()> {
    let origin = "https://publisher.test";
    let (publication, _) = Publication::bind(json!({"publicOrigin":origin}), 100)?;
    let mut input = json!({"method":"GET","path":"/temple/plugins/catalogue.json","host":"other.test",
        "publicHost":"publisher.test","localHost":"127.0.0.1:6000","published":true,"nowMs":100,"expiresMs":101});
    assert_eq!(publication.evaluate("templePublication.route", input.clone())?["status"], 421);
    input["host"] = json!("publisher.test");
    assert_eq!(publication.evaluate("templePublication.route", input.clone())?["kind"], "catalogue");
    input["method"] = json!("POST");
    assert_eq!(publication.evaluate("templePublication.route", input.clone())?["status"], 405);
    input["method"] = json!("GET");
    input["expiresMs"] = json!(100);
    assert_eq!(publication.evaluate("templePublication.route", input)?["status"], 503);
    assert!(Publication::bind(json!({"publicOrigin":origin,"publication":{
        "expiresAt":"2026-11-12T00:00:00.000Z"}}), 100).is_err());
    Ok(())
}
