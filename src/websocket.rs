use crate::{Result, fail, http::Request};
use base64ct::{Base64, Encoding};
use std::{io::{self, Read, Write}, net::TcpStream, os::fd::AsRawFd, sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc}, thread, time::Duration};

const BROWSER_PING_MS: libc::c_int = 30_000;

#[link(name = ":libcrypto.so.3")]
unsafe extern "C" { fn SHA1(data: *const u8, len: usize, digest: *mut u8) -> *mut u8; }

pub struct Peer {
    tx: mpsc::SyncSender<String>,
    pub event_stream: bool,
    active: Arc<AtomicBool>,
}

impl Peer {
    pub fn active(&self) -> bool { self.active.load(Ordering::Acquire) }

    pub fn publish(&self, message: String) -> Result<()> {
        self.tx.try_send(message)?;
        Ok(())
    }
}

pub fn upgrade(stream: &mut TcpStream, request: &Request) -> Result<Peer> {
    handshake(stream, request)?;
    let mut peer = stream.try_clone()?;
    let (tx, rx) = mpsc::sync_channel::<String>(32);
    let active = Arc::new(AtomicBool::new(true));
    let connection = Arc::clone(&active);
    thread::spawn(move || {
        let _ = serve_peer(&mut peer, rx);
        connection.store(false, Ordering::Release);
    });
    Ok(Peer { tx, active, event_stream: false })
}

pub fn event_stream(stream: &mut TcpStream) -> Result<Peer> {
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-store\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n")?;
    let mut socket = stream.try_clone()?;
    let (tx, rx) = mpsc::sync_channel::<String>(32);
    let active = Arc::new(AtomicBool::new(true));
    let connection = Arc::clone(&active);
    thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(210);
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_secs(10)) {
                Ok(message) => {
                    let terminal = message.starts_with("event: done\n");
                    if socket.write_all(message.as_bytes()).is_err() || terminal { break; }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if socket.write_all(b": keepalive\n\n").is_err() { break; }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        connection.store(false, Ordering::Release);
    });
    Ok(Peer { tx, active, event_stream: true })
}

pub fn handshake(stream: &mut TcpStream, request: &Request) -> Result<()> {
    let header = |name| request.headers.get(name).map(String::as_str).unwrap_or("");
    let key = header("sec-websocket-key");
    if request.method != "GET" || !header("upgrade").eq_ignore_ascii_case("websocket")
        || !header("connection").split(',').any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        || header("sec-websocket-version") != "13"
        || !Base64::decode_vec(key).is_ok_and(|bytes| bytes.len() == 16)
    {
        return Err(fail("invalid WebSocket upgrade"));
    }
    let accept = accept_key(key)?;
    // Browser effects wait for a reply to each frame. Send short writes promptly.
    stream.set_nodelay(true)?;
    write!(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n")?;
    Ok(())
}

pub(crate) fn accept_key(key: &str) -> Result<String> {
    let input = format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let mut digest = [0u8; 20];
    if unsafe { SHA1(input.as_ptr(), input.len(), digest.as_mut_ptr()) }.is_null() {
        return Err(fail("WebSocket handshake digest failed"));
    }
    Ok(Base64::encode_string(&digest))
}

pub fn frame(stream: &mut TcpStream, opcode: u8, body: &[u8]) -> Result<()> {
    if body.len() <= 125 {
        stream.write_all(&[0x80 | opcode, body.len() as u8])?;
    } else if let Ok(size) = u16::try_from(body.len()) {
        let size = size.to_be_bytes();
        stream.write_all(&[0x80 | opcode, 126, size[0], size[1]])?;
    } else {
        stream.write_all(&[0x80 | opcode, 127])?;
        stream.write_all(&(body.len() as u64).to_be_bytes())?;
    }
    stream.write_all(body)?;
    Ok(())
}

pub fn read_text(stream: &mut TcpStream, limit: usize) -> Result<Option<String>> {
    read_message(stream, limit, None)
}

pub fn read_browser_text(stream: &mut TcpStream, limit: usize) -> Result<Option<String>> {
    read_message(stream, limit, Some(BROWSER_PING_MS))
}

fn wait_for_input(stream: &mut TcpStream, ping_ms: libc::c_int) -> Result<()> {
    // Wait before starting a frame so an idle ping cannot interrupt a partial read.
    let mut socket = libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    loop {
        let ready = unsafe { libc::poll(&mut socket, 1, ping_ms) };
        if ready > 0 { return Ok(()); }
        if ready == 0 {
            frame(stream, 9, &[])?;
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted { return Err(error.into()); }
        }
    }
}

// Return after a control frame so a guest relay can continue servicing its other source.
pub fn read_guest_text(stream: &mut TcpStream, limit: usize) -> Result<Option<String>> {
    match read_guest_frame(stream, limit, false)? {
        Some((1, bytes)) => Ok(Some(String::from_utf8(bytes)?)),
        Some(_) => Ok(Some(String::new())),
        None => Ok(None),
    }
}

fn read_message(stream: &mut TcpStream, limit: usize, ping_ms: Option<libc::c_int>) -> Result<Option<String>> {
    loop {
        if let Some(ping_ms) = ping_ms { wait_for_input(stream, ping_ms)?; }
        match read_guest_frame(stream, limit, false)? {
            Some((1, bytes)) => return Ok(Some(String::from_utf8(bytes)?)),
            Some(_) => {}
            None => return Ok(None),
        }
    }
}

pub fn read_guest_frame(stream: &mut TcpStream, limit: usize, binary: bool) -> Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0; 2];
    stream.read_exact(&mut header)?;
    let size = header[1] & 127;
    if header[1] & 128 == 0 || !(matches!(header[0], 0x81 | 0x88..=0x8a) || (binary && header[0] == 0x82))
        || (header[0] >= 0x88 && size > 125) {
        return Err(fail("unsupported browser WebSocket frame"));
    }
    let length = match size {
        126 => {
            let mut bytes = [0; 2];
            stream.read_exact(&mut bytes)?;
            u16::from_be_bytes(bytes) as u64
        }
        127 => {
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes)?;
            u64::from_be_bytes(bytes)
        }
        value => u64::from(value),
    };
    if length > limit as u64 { return Err(fail("browser frame size limit")); }
    let mut key = [0; 4];
    stream.read_exact(&mut key)?;
    let mut body = vec![0; length as usize];
    stream.read_exact(&mut body)?;
    for (index, byte) in body.iter_mut().enumerate() { *byte ^= key[index % 4]; }
    match header[0] {
        0x81 | 0x82 => return Ok(Some((header[0] & 0x0f, body))),
        0x88 => { frame(stream, 8, &body)?; return Ok(None); }
        0x89 => frame(stream, 10, &body)?,
        _ => {}
    }
    Ok(Some((0, Vec::new())))
}

fn serve_peer(stream: &mut TcpStream, rx: mpsc::Receiver<String>) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut last_ping = std::time::Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(text) => frame(stream, 1, text.as_bytes())?,
            Err(mpsc::RecvTimeoutError::Disconnected) => { frame(stream, 8, &[])?; return Ok(()); }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if last_ping.elapsed() >= Duration::from_secs(15) {
            frame(stream, 9, &[])?;
            last_ping = std::time::Instant::now();
        }
        let mut head = [0; 2];
        match stream.peek(&mut head) {
            Ok(0) => return Ok(()),
            Ok(1) => continue,
            Ok(_) => {}
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(error) => return Err(error.into()),
        }
        stream.read_exact(&mut head)?;
        if !matches!(head[0], 0x88..=0x8a) || head[1] & 0x80 == 0 || head[1] & 0x7f > 125 {
            frame(stream, 8, &[0x03, 0xea])?;
            return Ok(());
        }
        let mut key = [0; 4];
        stream.read_exact(&mut key)?;
        let mut body = vec![0; (head[1] & 0x7f) as usize];
        stream.read_exact(&mut body)?;
        for (i, byte) in body.iter_mut().enumerate() { *byte ^= key[i % 4]; }
        match head[0] {
            0x88 => { frame(stream, 8, &body)?; return Ok(()); }
            0x89 => frame(stream, 10, &body)?,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, io::{BufRead, BufReader}, net::TcpListener};

    #[test]
    fn browser_upgrade_enables_prompt_writes_and_preserves_wire_frames() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let (mut server, _) = listener.accept()?;
        server.set_nodelay(false)?;
        let request = Request {
            method: "GET".into(),
            path: "/_encounter/browser".into(),
            headers: BTreeMap::from([
                ("upgrade".into(), "websocket".into()),
                ("connection".into(), "Upgrade".into()),
                ("sec-websocket-version".into(), "13".into()),
                ("sec-websocket-key".into(), "dGhlIHNhbXBsZSBub25jZQ==".into()),
            ]),
            body: Vec::new(),
        };
        handshake(&mut server, &request)?;
        assert!(server.nodelay()?);
        let mut reader = BufReader::new(client);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line)?, 0);
            headers.push_str(&line);
            if line == "\r\n" { break; }
        }
        assert_eq!(headers, concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\nConnection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        ));
        frame(&mut server, 1, b"ready")?;
        let mut wire = [0; 7];
        reader.read_exact(&mut wire)?;
        assert_eq!(&wire, b"\x81\x05ready");
        Ok(())
    }

    #[test]
    fn idle_browser_ping_preserves_the_next_application_message() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let (mut server, _) = listener.accept()?;
        server.set_read_timeout(Some(Duration::from_secs(2)))?;
        let reader = thread::spawn(move || {
            read_message(&mut server, 64, Some(25)).expect("read browser WebSocket message")
        });

        let mut ping = [0; 2];
        client.read_exact(&mut ping)?;
        assert_eq!(ping, [0x89, 0]);
        client.write_all(&[0x8a, 0x80, 1, 2, 3, 4])?;
        client.write_all(&[0x81, 0x82, 1, 2, 3, 4, b'o' ^ 1, b'k' ^ 2])?;
        assert_eq!(reader.join().expect("WebSocket reader panicked").as_deref(), Some("ok"));
        Ok(())
    }
}
