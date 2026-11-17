// A dedicated Linux device window with inherited kernel TCP restrictions.
use crate::{Result, fail, rel::Facts};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt}, process::CommandExt},
    },
    path::Path,
    process::Command,
    sync::Arc,
    thread,
    time::Duration,
};

const CONNECT_TCP: u64 = 1 << 1;
const CREATE_RULESET_VERSION: libc::c_uint = 1;
const RULE_NET_PORT: libc::c_uint = 2;

#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct NetPort {
    allowed_access: u64,
    port: u64,
}

struct Gateway<'a> {
    origin: &'a str,
    port: u16,
    hosts: Vec<&'a str>,
    address: Option<Ipv4Addr>,
}

fn dns_label(label: &str, max: usize) -> bool {
    let bytes = label.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.len() <= max
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn gateway(facts: &Facts) -> Result<Gateway<'_>> {
    let origin = facts.one("window", "origin")?;
    let (authority, port_text) = origin.rsplit_once(':')
        .ok_or_else(|| fail("expected a device gateway with an explicit port"))?;
    let port = port_text.parse::<u16>()?;
    if port < 1024 || port_text != port.to_string() {
        return Err(fail("expected a canonical unprivileged device gateway port"));
    }
    let mut hosts = Vec::new();
    let mut address = None;
    match facts.one("window", "version")? {
        "encounter/device-window/1" if facts.0.len() == 2 && authority == "http://127.0.0.1" => {
        }
        "encounter/device-window/2" => {
            let domain = authority.strip_prefix("https://board.").and_then(|suffix| suffix.strip_suffix(".test"))
                .filter(|label| dns_label(label, 31))
                .ok_or_else(|| fail("expected a private HTTPS device gateway on a .test domain"))?;
            let app_hosts = facts.values("window", "appHost");
            let addresses = facts.values("window", "gatewayIpv4");
            address = match addresses.as_slice() {
                [] => None,
                [value] => Some(value.parse::<Ipv4Addr>().ok().filter(private_gateway)
                    .ok_or_else(|| fail("expected a loopback or private IPv4 gateway address"))?),
                _ => return Err(fail("expected one device gateway address")),
            };
            if !(20000..=39999).contains(&port) || !(1..=32).contains(&app_hosts.len())
                || facts.0.len() != app_hosts.len() + addresses.len() + 2
            {
                return Err(fail("expected a private ingress port and a bounded device app host list"));
            }
            hosts.push(authority.strip_prefix("https://").expect("validated HTTPS authority"));
            let suffix = format!(".{domain}.test");
            for host in app_hosts {
                let valid = host.strip_suffix(&suffix)
                    .is_some_and(|label| label != "board" && dns_label(label, 63));
                if !valid || hosts.contains(&host) {
                    return Err(fail("expected a distinct app host under the device gateway domain"));
                }
                hosts.push(host);
            }
        }
        _ => return Err(fail("unsupported device window contract")),
    }
    Ok(Gateway { origin, port, hosts, address })
}

fn private_gateway(address: &Ipv4Addr) -> bool {
    *address == Ipv4Addr::LOCALHOST || address.is_private()
}

fn gateway_address(gateway: &Gateway<'_>) -> Result<SocketAddr> {
    if let Some(address) = gateway.address {
        return Ok((address, gateway.port).into());
    }
    (gateway.hosts[0], gateway.port).to_socket_addrs()?
        .find(|socket| matches!(socket, SocketAddr::V4(address) if private_gateway(address.ip())))
        .ok_or_else(|| fail("the device gateway must resolve to loopback or private IPv4"))
}

fn relay_flow(mut client: TcpStream, upstream: SocketAddr, hosts: &[String]) -> io::Result<()> {
    let timeout = Some(Duration::from_secs(3));
    client.set_read_timeout(timeout)?;
    client.set_write_timeout(timeout)?;
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting)?;
    let mut methods = [0; 255];
    let methods = &mut methods[..usize::from(greeting[1])];
    client.read_exact(methods)?;
    if greeting[0] != 5 || !methods.contains(&0) {
        return client.write_all(&[5, 255]);
    }
    client.write_all(&[5, 0])?;
    let mut request = [0; 5];
    client.read_exact(&mut request)?;
    // SOCKS5 CONNECT accepts only a registered hostname and the gateway port.
    if request[..4] != [5, 1, 0, 3] {
        return client.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    let mut name = [0; 255];
    let name = &mut name[..usize::from(request[4])];
    client.read_exact(name)?;
    let mut port = [0; 2];
    client.read_exact(&mut port)?;
    if !hosts.iter().any(|host| host.as_bytes() == name) || u16::from_be_bytes(port) != upstream.port() {
        return client.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    let Ok(mut server) = TcpStream::connect_timeout(&upstream, Duration::from_secs(3)) else {
        return client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    };
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    let mut browser_read = client.try_clone()?;
    let mut upstream_write = server.try_clone()?;
    thread::scope(|scope| {
        scope.spawn(|| {
            let _ = io::copy(&mut browser_read, &mut upstream_write);
            let _ = upstream_write.shutdown(Shutdown::Write);
        });
        let _ = io::copy(&mut server, &mut client);
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
    });
    Ok(())
}

fn serve_relay(listener: TcpListener, upstream: SocketAddr, hosts: Vec<String>) {
    let hosts = Arc::new(hosts);
    let mut workers = Vec::<thread::JoinHandle<()>>::new();
    for client in listener.incoming() {
        let Ok(client) = client else { break; };
        workers.retain(|worker| !worker.is_finished());
        if workers.len() >= 64 { continue; }
        let hosts = Arc::clone(&hosts);
        if let Ok(worker) = thread::Builder::new().spawn(move || { let _ = relay_flow(client, upstream, &hosts); }) {
            workers.push(worker);
        }
    }
}

fn network_rules(port: u16) -> Result<OwnedFd> {
    let abi = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<Ruleset>(), 0usize, CREATE_RULESET_VERSION)
    };
    if abi < 4 { return Err(fail("the device window requires Linux Landlock TCP support")); }
    let attributes = Ruleset { handled_access_fs: 0, handled_access_net: CONNECT_TCP };
    let fd = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, &attributes, std::mem::size_of::<Ruleset>(), 0u32)
    };
    if fd < 0 { return Err(io::Error::last_os_error().into()); }
    let rules = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let allow = NetPort { allowed_access: CONNECT_TCP, port: u64::from(port) };
    if unsafe { libc::syscall(libc::SYS_landlock_add_rule, rules.as_raw_fd(), RULE_NET_PORT, &allow, 0u32) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(rules)
}

pub fn open(config: &Path, profile: &Path, renderer: &Path) -> Result<()> {
    let facts = Facts::read(config)?;
    let gateway = gateway(&facts)?;
    let renderer = renderer.canonicalize()?;
    if !renderer.is_file() { return Err(fail("expected a renderer executable")); }
    DirBuilder::new().mode(0o700).recursive(true).create(profile)?;
    let profile = profile.canonicalize()?;
    let metadata = profile.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err(fail("expected a private renderer profile owned by this account"));
    }
    let lock = OpenOptions::new().write(true).create(true).truncate(false)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(profile.join("encounter-window.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("the device window profile is already in use"));
    }
    match fs::symlink_metadata(profile.join("SingletonLock")) {
        Ok(_) => return Err(fail("the profile already belongs to a Chromium instance")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }

    let mut command = Command::new(renderer);
    command.arg(format!("--app={}/", gateway.origin))
        .arg(format!("--user-data-dir={}", profile.display()))
        .args(["--no-first-run", "--disable-background-networking", "--disable-extensions",
            "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]);
    let relay = if gateway.hosts.is_empty() {
        command.args(["--no-proxy-server", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE *.localhost"]);
        None
    } else {
        let upstream = gateway_address(&gateway)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        command.arg(format!("--proxy-server=socks5://{}", listener.local_addr()?))
            .args(["--proxy-bypass-list=<-loopback>", "--host-resolver-rules=MAP * ~NOTFOUND"]);
        Some((listener, upstream))
    };
    let port = match &relay {
        Some((listener, _)) => listener.local_addr()?.port(),
        None => gateway.port,
    };
    let rules = network_rules(port)?;
    // The child inherits the rules before executing the renderer. Only syscalls
    // run between fork and exec, and the parent keeps Chromium's own sandbox enabled.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                || libc::syscall(libc::SYS_landlock_restrict_self, rules.as_raw_fd(), 0u32) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut renderer = command.spawn()?;
    if let Some((listener, upstream)) = relay {
        let hosts = gateway.hosts.into_iter().map(str::to_owned).collect();
        if let Err(error) = thread::Builder::new().spawn(move || serve_relay(listener, upstream, hosts)) {
            let _ = renderer.kill();
            let _ = renderer.wait();
            return Err(error.into());
        }
    }
    let status = renderer.wait()?;
    if !status.success() { return Err(fail(format!("device renderer exited with {status}"))); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: &str = r#"
("window", "version", "encounter/device-window/2")
("window", "origin", "https://board.life-board.test:24640")
("window", "appHost", "temple.life-board.test")
("window", "appHost", "super-crm.life-board.test")
"#;

    #[test]
    fn private_window_resolves_only_registered_gateway_hosts() {
        let facts = Facts::parse(PRIVATE).unwrap();
        let window = gateway(&facts).unwrap();
        assert_eq!(window.port, 24640);
        assert_eq!(window.origin, "https://board.life-board.test:24640");
        assert_eq!(window.hosts, ["board.life-board.test", "temple.life-board.test", "super-crm.life-board.test"]);
        assert_eq!(window.address, None);
        let pinned = Facts::parse(&format!("{PRIVATE}(\"window\", \"gatewayIpv4\", \"192.168.1.12\")\n")).unwrap();
        let window = gateway(&pinned).unwrap();
        assert_eq!(gateway_address(&window).unwrap(), "192.168.1.12:24640".parse().unwrap());
    }

    #[test]
    fn private_window_rejects_invalid_authorities_and_hosts() {
        for (from, to) in [
            ("https://", "http://"),
            ("24640", "024640"),
            ("24640", "44640"),
            ("temple.life-board.test", "temple.other.test"),
            ("temple.life-board.test", "*.life-board.test"),
            ("temple.life-board.test", "board.life-board.test"),
            ("temple.life-board.test", "super-crm.life-board.test"),
            ("temple.life-board.test", "temple.life-board.test, EXCLUDE *"),
        ] {
            let valid = Facts::parse(&PRIVATE.replace(from, to))
                .is_ok_and(|facts| gateway(&facts).is_ok());
            assert!(!valid, "accepted {to}");
        }
        for address in ["0.0.0.0", "127.0.0.2", "198.51.100.2"] {
            let facts = Facts::parse(&format!("{PRIVATE}(\"window\", \"gatewayIpv4\", \"{address}\")\n")).unwrap();
            assert!(gateway(&facts).is_err(), "accepted {address}");
        }
    }

    #[test]
    fn loopback_window_keeps_its_contract() {
        let facts = Facts::parse(r#"
("window", "version", "encounter/device-window/1")
("window", "origin", "http://127.0.0.1:24370")
"#).unwrap();
        let window = gateway(&facts).unwrap();
        assert_eq!(window.port, 24370);
        assert!(window.hosts.is_empty());
    }
}
