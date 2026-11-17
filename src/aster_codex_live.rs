//! Native WebSocket transport to the existing Codex Desktop Unix control socket.
use crate::{Result, fail, websocket};
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use std::{io::{BufRead, BufReader, Read, Write}, net::TcpStream, os::{fd::AsRawFd, unix::net::UnixStream}, path::Path, time::Duration};

const FRAME: usize = 8 * 1024 * 1024;

pub struct Desktop {
    input: BufReader<UnixStream>,
    request: u64,
}

impl Desktop {
    pub fn connect(socket: &Path) -> Result<Self> {
        let mut socket = UnixStream::connect(socket)?;
        socket.set_read_timeout(Some(Duration::from_secs(4)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| fail("Unable to create WebSocket key"))?;
        let key = Base64::encode_string(&nonce);
        write!(socket, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n")?;
        let mut connection = Self { input: BufReader::new(socket), request: 0 };
        let mut response = String::new();
        let mut headers = (&mut connection.input).take(8192);
        headers.read_line(&mut response)?;
        if !response.starts_with("HTTP/1.1 101 ") { return Err(fail("Desktop socket rejected WebSocket")); }
        let accept = websocket::accept_key(&key)?;
        let mut verified = false;
        loop {
            response.clear();
            if headers.read_line(&mut response)? == 0 { return Err(fail("Incomplete WebSocket handshake")); }
            if response == "\r\n" { break; }
            if let Some((name, value)) = response.split_once(':') && name.eq_ignore_ascii_case("sec-websocket-accept") {
                verified = value.trim() == accept;
            }
        }
        if !verified { return Err(fail("Invalid Desktop socket handshake")); }
        connection.call("initialize", json!({"clientInfo":{"name":"aster_codex","title":"Aster Codex","version":"1"}}), |_| Ok(()))?;
        connection.send(json!({"method":"initialized"}))?;
        Ok(connection)
    }

    fn write(&mut self, opcode: u8, bytes: &[u8]) -> Result<()> {
        let mut mask = [0; 4];
        getrandom::getrandom(&mut mask).map_err(|_| fail("Unable to mask WebSocket request"))?;
        let mut header = vec![0x80 | opcode];
        if bytes.len() < 126 { header.push(0x80 | bytes.len() as u8); }
        else {
            let size = u16::try_from(bytes.len())?;
            header.push(0x80 | 126);
            header.extend_from_slice(&size.to_be_bytes());
        }
        header.extend_from_slice(&mask);
        let packet: Vec<_> = bytes.iter().enumerate().map(|(i, byte)| byte ^ mask[i % 4]).collect();
        self.input.get_mut().write_all(&header)?;
        self.input.get_mut().write_all(&packet)?;
        Ok(())
    }

    fn send(&mut self, value: Value) -> Result<()> { self.write(1, &serde_json::to_vec(&value)?) }

    pub fn next(&mut self) -> Result<Value> {
        let mut message = Vec::new();
        let mut started = false;
        loop {
            let mut header = [0; 2];
            self.input.read_exact(&mut header)?;
            let final_part = header[0] & 0x80 != 0;
            let opcode = header[0] & 0x0f;
            if header[0] & 0x70 != 0 || header[1] & 0x80 != 0 { return Err(fail("Invalid Desktop frame flags")); }
            let size = match header[1] {
                126 => { let mut length = [0; 2]; self.input.read_exact(&mut length)?; u16::from_be_bytes(length) as u64 }
                127 => { let mut length = [0; 8]; self.input.read_exact(&mut length)?; u64::from_be_bytes(length) }
                size => size as u64,
            };
            if size > (FRAME - message.len()) as u64 { return Err(fail("Desktop frame exceeds limit")); }
            if opcode >= 8 {
                if !final_part || size > 125 { return Err(fail("Invalid Desktop control frame")); }
                let mut control = [0; 125];
                self.input.read_exact(&mut control[..size as usize])?;
                match opcode {
                    8 => return Err(fail("Desktop socket closed")),
                    9 => self.write(10, &control[..size as usize])?,
                    10 => {}
                    _ => return Err(fail("Unexpected Desktop control frame")),
                }
                continue;
            }
            if opcode != if started { 0 } else { 1 } { return Err(fail("Unexpected Desktop frame type")); }
            let from = message.len();
            message.resize(from + size as usize, 0);
            self.input.read_exact(&mut message[from..])?;
            if final_part { return Ok(serde_json::from_slice(&message)?); }
            started = true;
        }
    }

    pub fn ready(&self, browser: &TcpStream) -> Result<bool> {
        if !self.input.buffer().is_empty() { return Ok(true); }
        let peer_closed = libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR;
        let mut watched = [
            libc::pollfd { fd: self.input.get_ref().as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: browser.as_raw_fd(), events: peer_closed, revents: 0 },
        ];
        // The borrowed sockets remain open for the duration of the poll call.
        if unsafe { libc::poll(watched.as_mut_ptr(), 2, 12_000) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if watched[1].revents & peer_closed != 0 { return Err(fail("Browser closed the live view")); }
        Ok(watched[0].revents != 0)
    }

    pub fn call(&mut self, method: &str, params: Value, mut event: impl FnMut(Value) -> Result<()>) -> Result<Value> {
        self.request += 1;
        let id = self.request;
        self.send(json!({"id":id,"method":method,"params":params}))?;
        for _ in 0..512 {
            let message = self.next()?;
            if message["id"].as_u64() == Some(id) && message.get("method").is_none() {
                return message.get("result").cloned().ok_or_else(|| fail("Desktop refused request"));
            }
            if message.get("id").is_none() { event(message)?; }
        }
        Err(fail("Desktop did not acknowledge request"))
    }

    pub fn read_thread(&mut self, thread: &str) -> Result<Value> {
        let result = self.call("thread/read", json!({"threadId":thread}), |_| Ok(()))?;
        if result["thread"]["id"] != thread { return Err(fail("Desktop returned a different thread")); }
        Ok(result["thread"].clone())
    }

    pub fn latest_turn(&mut self, thread: &str) -> Result<Value> {
        let result = self.call("thread/turns/list",
            json!({"threadId":thread,"limit":1,"sortDirection":"desc","itemsView":"notLoaded"}), |_| Ok(()))?;
        Ok(result["data"].get(0).cloned().unwrap_or(Value::Null))
    }
}
