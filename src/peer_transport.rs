use crate::{Result, fail, http, websocket};
use base64ct::{Base64, Encoding};
use serde_json::Value;
use std::{
    io::{self, BufReader, Read, Write},
    net::{Ipv4Addr, TcpStream},
    time::{Duration, Instant},
};

pub(crate) const PATH: &str = "/_encounter/peer";
pub(crate) const LIMIT: usize = 16_384;
const TIMEOUT: Duration = Duration::from_secs(3);

struct Connection {
    stream: TcpStream,
    deadline: Instant,
}

impl Connection {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline.checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "peer exchange deadline exceeded"))
    }
}

impl Read for Connection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}

impl Write for Connection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> { self.stream.flush() }
}

/// One signed envelope and one acknowledgement over a pinned loopback route.
/// The declared application verifies the peer and correlates the acknowledgement.
pub(crate) fn exchange(port: u16, envelope: &Value) -> Result<Value> {
    if port == 0 || !envelope.is_object() {
        return Err(fail("expected a pinned peer port and envelope"));
    }
    let body = serde_json::to_vec(envelope)?;
    if body.len() > LIMIT { return Err(fail("peer envelope exceeds size limit")); }

    let deadline = Instant::now() + TIMEOUT;
    let address = (Ipv4Addr::LOCALHOST, port).into();
    let stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    let mut connection = Connection { stream, deadline };
    let mut challenge = [0; 16];
    getrandom::getrandom(&mut challenge).map_err(|_| fail("peer upgrade entropy unavailable"))?;
    let key = Base64::encode_string(&challenge);
    write!(connection, "GET {PATH} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\n\
        Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")?;
    let mut response = BufReader::new(connection);
    let (status, headers) = http::read_head(&mut response)?;
    let accept = websocket::accept_key(&key)?;
    let upgrade = headers.get("upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection = headers.get("connection").is_some_and(|value| {
        value.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    });
    if !status.starts_with("HTTP/1.1 101 ") || !upgrade || !connection
        || headers.get("sec-websocket-accept") != Some(&accept)
        || ["sec-websocket-extensions", "sec-websocket-protocol", "content-length", "transfer-encoding"]
            .iter().any(|header| headers.contains_key(*header))
    {
        return Err(fail("peer refused WebSocket upgrade"));
    }
    send_request(response.get_mut(), &body)?;
    read_response(&mut response)
}

fn send_request(stream: &mut impl Write, body: &[u8]) -> Result<()> {
    let mut mask = [0; 4];
    getrandom::getrandom(&mut mask).map_err(|_| fail("peer frame entropy unavailable"))?;
    let mut frame = Vec::with_capacity(body.len() + 8);
    frame.push(0x81);
    if body.len() <= 125 {
        frame.push(0x80 | body.len() as u8);
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(body.iter().enumerate().map(|(index, byte)| byte ^ mask[index % mask.len()]));
    stream.write_all(&frame)?;
    Ok(())
}

fn read_response(reader: &mut impl Read) -> Result<Value> {
    let mut header = [0; 2];
    reader.read_exact(&mut header)?;
    if header[0] != 0x81 || header[1] & 0x80 != 0 {
        return Err(fail("expected an unmasked peer acknowledgement"));
    }
    let size = match header[1] {
        126 => {
            let mut extended = [0; 2];
            reader.read_exact(&mut extended)?;
            let size = usize::from(u16::from_be_bytes(extended));
            if size < 126 { return Err(fail("nonminimal peer frame length")); }
            size
        }
        127 => return Err(fail("peer acknowledgement exceeds size limit")),
        size => usize::from(size),
    };
    if size > LIMIT { return Err(fail("peer acknowledgement exceeds size limit")); }
    let mut body = vec![0; size];
    reader.read_exact(&mut body)?;
    let response: Value = serde_json::from_slice(&body)?;
    if !response.is_null() && !response.is_object() {
        return Err(fail("expected a peer acknowledgement or refusal"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{net::TcpListener, thread};

    fn peer(respond: impl FnOnce(&mut TcpStream, &http::Request) + Send + 'static, envelope: &Value) -> Result<Value> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = http::read(&mut stream).unwrap();
            assert_eq!(request.path, PATH);
            assert_eq!(request.headers["host"], format!("127.0.0.1:{port}"));
            assert!(!request.headers.contains_key("origin"));
            respond(&mut stream, &request);
        });
        let response = exchange(port, envelope);
        server.join().unwrap();
        response
    }

    #[test]
    fn masked_envelope_and_unmasked_acknowledgement_round_trip() {
        let envelope = json!({"attestation": "a".repeat(200)});
        let expected = envelope.clone();
        let receipt = json!({"receipt": "b".repeat(200)});
        let ack = serde_json::to_string(&receipt).unwrap();
        let response = peer(move |stream, request| {
            websocket::handshake(stream, request).unwrap();
            let text = websocket::read_text(stream, LIMIT).unwrap().unwrap();
            assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), expected);
            websocket::frame(stream, 1, ack.as_bytes()).unwrap();
        }, &envelope).unwrap();
        assert_eq!(response, receipt);
    }

    #[test]
    fn explicit_null_acknowledgement_is_a_refusal() {
        let response = peer(|stream, request| {
            websocket::handshake(stream, request).unwrap();
            websocket::read_text(stream, LIMIT).unwrap().unwrap();
            websocket::frame(stream, 1, b"null").unwrap();
        }, &json!({})).unwrap();
        assert_eq!(response, Value::Null);
    }

    #[test]
    fn refuses_wrong_upgrade_challenge_before_sending_envelope() {
        let response = peer(|stream, _| {
            write!(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                Connection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n").unwrap();
            assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        }, &json!({}));
        assert!(response.unwrap_err().to_string().contains("refused WebSocket upgrade"));
    }

    #[test]
    fn refuses_masked_fragmented_nonminimal_and_oversized_responses() {
        for bytes in [[0x81, 0x80, 0, 0], [0x01, 0, 0, 0], [0x81, 126, 0, 4], [0x81, 126, 0x40, 1]] {
            assert!(read_response(&mut bytes.as_slice()).is_err());
        }
    }
}
