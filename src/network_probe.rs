use crate::{Result, fail, http};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet}, fs::{self, File}, io::{self, BufRead, BufReader, Read},
    net::Ipv4Addr, path::Path, time::{Duration, Instant},
};

const PROBE_LIMIT: u64 = 8 * 1024 * 1024;
const LISTENER_DEADLINE: Duration = Duration::from_secs(5);

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Listener { address: String, inode: u64 }

fn check(deadline: Instant) -> Result<()> {
    if http::stopping() || crate::appdev_host_process::interruption().is_some() {
        return Err(fail("Network listener scan interrupted"));
    }
    if Instant::now() >= deadline { return Err(fail("Network listener scan timed out")); }
    Ok(())
}

fn listeners(proc: &Path, ports: &BTreeSet<u16>, deadline: Instant) -> Result<BTreeMap<u16, Vec<Listener>>> {
    let mut found = BTreeMap::<_, Vec<_>>::new();
    for (path, ipv4) in [("net/tcp", true), ("net/tcp6", false)] {
        let table = match File::open(proc.join(path)) {
            Ok(table) => table,
            Err(error) if !ipv4 && error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for line in BufReader::new(table).lines().skip(1) {
            check(deadline)?;
            let line = line?;
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.get(3) != Some(&"0A") { continue; }
            let (address, port) = fields.get(1).and_then(|field| field.split_once(':'))
                .ok_or_else(|| fail("Malformed kernel TCP listener coordinate"))?;
            let port = u16::from_str_radix(port, 16)?;
            if !ports.contains(&port) { continue; }
            let address = if ipv4 { Ipv4Addr::from(u32::from_str_radix(address, 16)?.to_ne_bytes()).to_string() }
                else { address.to_owned() };
            let inode = fields.get(9).ok_or_else(|| fail("Missing kernel TCP listener inode"))?.parse()?;
            found.entry(port).or_default().push(Listener { address, inode });
        }
    }
    for values in found.values_mut() { values.sort_unstable(); }
    Ok(found)
}

fn socket_inode(path: &Path) -> Option<u64> {
    let link = fs::read_link(path).ok()?;
    link.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

fn observe(proc: &Path, ports: &BTreeSet<u16>) -> Result<BTreeMap<u16, Value>> {
    if ports.is_empty() { return Ok(BTreeMap::new()); }
    let deadline = Instant::now() + LISTENER_DEADLINE;
    let before = listeners(proc, ports, deadline)?;
    let mut owners = BTreeMap::<_, BTreeSet<String>>::new();
    for entries in before.values() {
        if let [listener] = entries.as_slice() && listener.address == "127.0.0.1" && listener.inode != 0 {
            owners.insert(listener.inode, BTreeSet::new());
        }
    }
    if !owners.is_empty() {
        for process in fs::read_dir(proc)? {
            check(deadline)?;
            let process = process?;
            if !process.file_name().to_str().is_some_and(|name| name.parse::<u32>().is_ok()) { continue; }
            let path = process.path();
            let descriptors = match fs::read_dir(path.join("fd")) {
                Ok(descriptors) => descriptors,
                Err(error) if matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound) => continue,
                Err(error) => return Err(error.into()),
            };
            let mut cgroup = None;
            for descriptor in descriptors {
                check(deadline)?;
                let descriptor = match descriptor {
                    Ok(descriptor) => descriptor,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                };
                let fd = descriptor.path();
                let Some(inode) = socket_inode(&fd) else { continue; };
                let Some(groups) = owners.get_mut(&inode) else { continue; };
                let group = cgroup.get_or_insert_with(|| {
                    let mut text = String::new();
                    if let Ok(file) = File::open(path.join("cgroup"))
                        && file.take(8193).read_to_string(&mut text).is_ok() && text.len() <= 8192 {
                        return text.trim().to_owned();
                    }
                    String::new()
                });
                if socket_inode(&fd) == Some(inode) { groups.insert(group.clone()); }
            }
        }
    }
    if before != listeners(proc, ports, deadline)? {
        return Err(fail("Network listeners changed during ownership verification"));
    }
    Ok(before.into_iter().map(|(port, entries)| {
        (port, json!(entries.into_iter().map(|listener| json!({
            "address":listener.address,"owners":owners.get(&listener.inode).cloned().unwrap_or_default()
        })).collect::<Vec<_>>()))
    }).collect())
}

pub(crate) fn listener_evidence(ports: &BTreeSet<u16>) -> Result<BTreeMap<u16, Value>> {
    observe(Path::new("/proc"), ports)
}

pub(crate) fn health(port: u16, host: &str, path: &str) -> Result<(u16, Vec<u8>)> {
    if host.is_empty() || !host.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".:-".contains(&byte))
        || !path.starts_with('/') || path.starts_with("//") || path.contains(['#', '\\'])
        || !path.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(fail("Invalid authored Network health request"));
    }
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n");
    let mut reply = http::LoopbackReply::open(port, request.as_bytes(), Duration::from_millis(2500))?;
    let (line, headers) = http::read_header_lines(&mut reply)?;
    let mut parts = line.splitn(3, ' ');
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(fail("Invalid Network health response version"));
    }
    let status = parts.next().filter(|text| text.len() == 3 && text.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| fail("Invalid Network health response status"))?.parse()?;
    if status != 200 { return Ok((status, Vec::new())); }
    if http::single_header(&headers, "content-encoding")?.is_some_and(|value| !value.eq_ignore_ascii_case("identity")) {
        return Err(fail("Unsupported Network health encoding"));
    }
    let transfer = http::single_header(&headers, "transfer-encoding")?;
    let length = http::single_header(&headers, "content-length")?;
    let mut body = Vec::new();
    match (transfer, length) {
        (Some(value), None) if value.eq_ignore_ascii_case("chunked") =>
            http::copy_chunked(&mut reply, &mut body, PROBE_LIMIT, false)?,
        (None, Some(value)) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            let length = value.parse::<u64>()?;
            if length > PROBE_LIMIT { return Err(fail("Network health response exceeds its size limit")); }
            http::copy_exact(&mut reply, &mut body, length)?;
        }
        (None, None) => { reply.take(PROBE_LIMIT+1).read_to_end(&mut body)?; }
        _ => return Err(fail("Invalid Network health response framing")),
    }
    if body.len() as u64 > PROBE_LIMIT { return Err(fail("Network health response exceeds its size limit")); }
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener, thread};

    #[test]
    fn native_listener_evidence_reports_kernel_socket_and_cgroup() -> Result<()> {
        let fixture = crate::appdev_host_process::Scratch::create(&std::env::temp_dir(), "network-proc-")?;
        let root = fixture.path();
        fs::create_dir(root.join("net"))?;
        for (process, service) in [("42", "first.service"), ("43", "second.service")] {
            fs::create_dir_all(root.join(process).join("fd"))?;
            fs::write(root.join(process).join("cgroup"), format!("0::/system.slice/{service}\n"))?;
            std::os::unix::fs::symlink("socket:[12345]", root.join(process).join("fd/5"))?;
        }
        let table = root.join("net/tcp");
        fs::write(&table, "header\n0: 0100007F:6677 00000000:0000 0A 00:00 00:0 0 1000 0 12345\n")?;
        let ports = BTreeSet::from([0x6677]);
        let result = observe(root, &ports)?;
        assert_eq!(result[&0x6677], json!([{"address":"127.0.0.1",
            "owners":["0::/system.slice/first.service","0::/system.slice/second.service"]}]));
        fs::write(root.join("net/tcp6"),
            "header\n0: 00000000000000000000000000000000:6677 00000000000000000000000000000000:0000 0A 00:00 00:0 0 1000 0 55555\n")?;
        assert_eq!(observe(root, &ports)?[&0x6677].as_array().unwrap().len(), 2);

        let real = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = real.local_addr()?.port();
        let evidence = listener_evidence(&BTreeSet::from([port]))?;
        assert_eq!(evidence[&port][0]["address"], "127.0.0.1");
        assert!(evidence[&port][0]["owners"].as_array().is_some_and(|owners| !owners.is_empty()));
        Ok(())
    }

    #[test]
    fn native_health_checks_framing_and_never_follows_redirects() -> Result<()> {
        let request = |response: &'static [u8]| -> Result<(u16, Vec<u8>)> {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            let server = thread::spawn(move || -> io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                assert_eq!(line, "GET /ready HTTP/1.1\r\n");
                line.clear();
                reader.read_line(&mut line)?;
                assert_eq!(line, "Host: fixture-ready\r\n");
                stream.write_all(response)
            });
            let result = health(port, "fixture-ready", "/ready");
            server.join().expect("health fixture failed")?;
            result
        };
        assert_eq!(request(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nready\r\n0\r\n\r\n")?,
            (200, b"ready".to_vec()));
        assert_eq!(request(b"HTTP/1.1 302 Found\r\nLocation: /other\r\n\r\n")?, (302, vec![]));
        assert!(request(b"HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n").is_err());
        assert!(request(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        Ok(())
    }
}
