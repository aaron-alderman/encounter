use crate::{Result, compat_value, fail, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::{self, Read}, net::IpAddr};

pub(crate) fn run(operation: &str) -> Result<()> {
    let entry = match operation {
        "surface" => "hostedHttp.surface",
        "edge-client" => "hostedHttp.edgeClient",
        "control-entry" => "hostedHttp.controlEntry",
        "direct-loopback" => "hostedHttp.directLoopback",
        "direct-loopback-scopes" => "hostedHttp.directLoopbackScopes",
        "local-proxy-headers" => "hostedHttp.localProxyHeaders",
        "development-reload" => "hostedRelease.developmentReload",
        "development-cutover" => "hostedRelease.developmentCutover",
        "local-readiness" => return probe_local_readiness(),
        "local-boot-envelope" => "hostedHttp.localBootEnvelope",
        "readiness" => "hostedReadiness.response",
        "semantic-supply" => "hostedReadiness.semanticSupply",
        "authoring-worker" => "hostedReadiness.authoringWorker",
        "capability-binding" => "hostedReadiness.capabilityBinding",
        _ => return Err(fail("Unsupported hosted HTTP route operation")),
    };
    let limit = if operation == "readiness" { 16 * 1024 * 1024 } else { 128 * 1024 };
    let mut bytes = Vec::new();
    io::stdin().lock().take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("Hosted HTTP route input exceeds its byte bound")); }
    let mut input: Value = serde_json::from_slice(&bytes)?;
    compat_value::external(&input)?;
    if operation == "edge-client" {
        let forwarded = input["forwarded"].as_str().unwrap_or_default();
        input = json!({
            "peer": ip_observation(input["peer"].as_str().unwrap_or_default()),
            "forwarded": ip_observation(forwarded), "forwardedPresent": !forwarded.is_empty(),
            "forwardedList": forwarded.contains(','), "repeated": input["forwarded"].is_array(),
            "trustProxy": input["trustProxy"],
        });
    }
    let mut sources = vec![include_str!("hosted_http_route.encounter").to_owned(),
        include_str!("hosted_readiness.encounter").to_owned()];
    if matches!(operation, "local-proxy-headers" | "development-reload" | "development-cutover") {
        sources.push(include_str!("hosted_release_identity.encounter").to_owned());
    }
    let policy = Programme::admit(&sources, entry,
        &BTreeSet::from(["kernel.invoke", "text.startsWith", "text.lowerCase", "text.split", "text.trim", "text.matches",
            "text.slice", "record.put", "http.decodePathSegment", "record.entries", "record.fromEntries",
            "value.describe", "value.type", "number.isNatural", "number.calculate"]),
        &mut Meter::new(100_000))?;
    println!("{}", policy.run(entry, input, &mut Meter::new(400_000))?);
    Ok(())
}

fn ip_observation(address: &str) -> Option<String> {
    let address = address.trim();
    let address = address.strip_prefix("::ffff:").unwrap_or(address);
    let literal = address.split_once('%').map_or(address, |(literal, _)| literal);
    let parsed = literal.parse::<IpAddr>().ok()?;
    if let Some((_, zone)) = address.split_once('%') {
        if !parsed.is_ipv6() || zone.is_empty() || !zone.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)) {
            return None;
        }
    }
    Some(address.to_ascii_lowercase())
}

fn probe_local_readiness() -> Result<()> {
    use crate::http;
    use serde_json::json;
    use std::time::Duration;
    let input = crate::platform_import_closure::read_bounded_observation(4096)?;
    let mut meter = Meter::new(100_000);
    let policy = Programme::admit_entries(&[include_str!("hosted_http_route.encounter").to_owned()],
        &["hostedHttp.localReadinessPlan", "hostedHttp.localReadinessResult"],
        &BTreeSet::from(["number.isNatural", "number.calculate"]), &mut meter)?;
    let plan = policy.run("hostedHttp.localReadinessPlan", input, &mut meter)?;
    let port = plan["port"].as_u64().and_then(|port| u16::try_from(port).ok())
        .ok_or_else(|| fail("Expected an admitted readiness port"))?;
    let target = plan["target"].as_str().ok_or_else(|| fail("Expected a readiness request target"))?;
    let limit = plan["maximumBytes"].as_u64().ok_or_else(|| fail("Expected a readiness response bound"))?;
    let request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let observation = (|| -> Result<u16> {
        let mut stream = http::LoopbackReply::open(port, request.as_bytes(), Duration::from_millis(750))?;
        let (status, headers) = http::read_response_head(&mut stream)?;
        http::copy_response_body(&mut stream, &headers, &mut io::sink(), limit)?;
        Ok(status)
    })();
    println!("{}", policy.run("hostedHttp.localReadinessResult",
        json!({"status":observation.ok()}), &mut meter)?);
    Ok(())
}
