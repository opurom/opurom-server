//! RFC 6455 WebSocket: a bounded frame codec, the server handshake and a
//! small client-side helper.
//!
//! The codec is deliberately bounded: a frame payload is capped at
//! [`MAX_FRAME_PAYLOAD`] and an assembled message at [`MAX_MESSAGE_BYTES`],
//! so a hostile peer cannot make the server allocate without limit. The
//! server never sends masked frames and always requires masked client
//! frames, exactly as RFC 6455 section 5.1 demands.
//!
//! Honest scope: no `permessage-deflate`, no extensions, no subprotocol
//! negotiation and no client certificates over the WebSocket.

use std::io::{self, Read, Write};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha1::{Digest, Sha1};

use crate::http::{Method, Request};

/// The RFC 6455 handshake GUID.
pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The WebSocket protocol version this implementation speaks.
pub const WS_VERSION: &str = "13";

/// Maximum payload of a single frame (1 MiB).
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

/// Maximum size of one assembled message (8 MiB).
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum payload of a control frame; RFC 6455 fixes this at 125 bytes.
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// The WebSocket frame opcodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    /// The numeric opcode, as it appears on the wire.
    pub fn from_u8(raw: u8) -> Option<Opcode> {
        match raw {
            0x0 => Some(Opcode::Continuation),
            0x1 => Some(Opcode::Text),
            0x2 => Some(Opcode::Binary),
            0x8 => Some(Opcode::Close),
            0x9 => Some(Opcode::Ping),
            0xA => Some(Opcode::Pong),
            _ => None,
        }
    }

    /// The numeric opcode, as it appears on the wire.
    pub fn as_u8(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }

    /// Control frames are never fragmented and are never masked by a server.
    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }
}

/// One WebSocket frame.
#[derive(Clone, Debug)]
pub struct Frame {
    pub fin: bool,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

/// A WebSocket error. Errors are values; no failure aborts the process.
#[derive(Debug)]
pub enum WsError {
    Io(io::Error),
    Protocol(&'static str),
    FrameTooLarge,
    MessageTooLarge,
    Handshake(String),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::Io(err) => write!(f, "websocket io error: {}", err),
            WsError::Protocol(reason) => write!(f, "websocket protocol error: {}", reason),
            WsError::FrameTooLarge => write!(f, "websocket frame exceeds the size limit"),
            WsError::MessageTooLarge => write!(f, "websocket message exceeds the size limit"),
            WsError::Handshake(reason) => write!(f, "websocket handshake failed: {}", reason),
        }
    }
}

impl std::error::Error for WsError {}

impl From<io::Error> for WsError {
    fn from(err: io::Error) -> WsError {
        WsError::Io(err)
    }
}

/// One application-level WebSocket message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Close { code: u16, reason: String },
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

/// The `Sec-WebSocket-Accept` value for a client key: base64(SHA-1(key + GUID)).
pub fn accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    BASE64.encode(hasher.finalize())
}

/// The `Sec-WebSocket-Key` of a request, when the request is an upgrade.
pub fn upgrade_key(request: &Request) -> Option<&str> {
    if request.method != Method::Get {
        return None;
    }
    let upgrade = request.header("Upgrade")?;
    if !upgrade.trim().eq_ignore_ascii_case("websocket") {
        return None;
    }
    let connection = request.header("Connection")?;
    if !connection
        .split(',')
        .any(|value| value.trim().eq_ignore_ascii_case("upgrade"))
    {
        return None;
    }
    let version = request.header("Sec-WebSocket-Version")?;
    if version.trim() != WS_VERSION {
        return None;
    }
    let key = request.header("Sec-WebSocket-Key")?.trim();
    if key.is_empty() {
        return None;
    }
    Some(key)
}

/// The 101 answer of a successful WebSocket handshake.
pub fn handshake_response(key: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(key)
    )
    .into_bytes()
}

/// Encode one frame. `mask` is `None` for a server frame and `Some` for a
/// masked client frame.
pub fn encode_frame(opcode: Opcode, payload: &[u8], fin: bool, mask: Option<[u8; 4]>) -> Vec<u8> {
    let masked = mask.is_some();
    let length = payload.len();
    let mut out = Vec::with_capacity(length + 14);
    out.push(if fin { 0x80 } else { 0x00 } | opcode.as_u8());
    if length < 126 {
        out.push(if masked {
            length as u8 | 0x80
        } else {
            length as u8
        });
    } else if length <= u16::MAX as usize {
        out.push(if masked { 126 | 0x80 } else { 126 });
        out.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        out.push(if masked { 127 | 0x80 } else { 127 });
        out.extend_from_slice(&(length as u64).to_be_bytes());
    }
    match mask {
        Some(mask) => {
            out.extend_from_slice(&mask);
            out.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % 4]),
            );
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// Read one frame. The declared length is checked against the size limits
/// before any buffer is allocated, so a hostile length cannot exhaust memory.
pub fn read_frame<R: Read>(reader: &mut R, expect_mask: bool) -> Result<Frame, WsError> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header)?;
    let fin = header[0] & 0x80 != 0;
    if header[0] & 0x70 != 0 {
        return Err(WsError::Protocol("a reserved bit is set"));
    }
    let opcode = Opcode::from_u8(header[0] & 0x0f).ok_or(WsError::Protocol("unknown opcode"))?;
    let masked = header[1] & 0x80 != 0;
    let length = match header[1] & 0x7f {
        126 => {
            let mut raw = [0u8; 2];
            reader.read_exact(&mut raw)?;
            usize::from(u16::from_be_bytes(raw))
        }
        127 => {
            let mut raw = [0u8; 8];
            reader.read_exact(&mut raw)?;
            let value = u64::from_be_bytes(raw);
            if value > MAX_FRAME_PAYLOAD as u64 {
                return Err(WsError::FrameTooLarge);
            }
            value as usize
        }
        other => other as usize,
    };
    if length > MAX_FRAME_PAYLOAD {
        return Err(WsError::FrameTooLarge);
    }
    if opcode.is_control() {
        if !fin {
            return Err(WsError::Protocol("a control frame is fragmented"));
        }
        if length > MAX_CONTROL_PAYLOAD {
            return Err(WsError::Protocol("a control frame payload is too long"));
        }
    }
    if expect_mask && !masked {
        return Err(WsError::Protocol("a client frame is not masked"));
    }
    let mut mask = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut payload)?;
    }
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Frame {
        fin,
        opcode,
        payload,
    })
}

/// Split a close payload into its status code and reason.
pub fn parse_close(payload: &[u8]) -> (u16, String) {
    if payload.len() >= 2 {
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        let reason = String::from_utf8_lossy(&payload[2..]).into_owned();
        (code, reason)
    } else {
        (1005, String::new())
    }
}

/// Assemble fragmented messages into one message.
#[derive(Debug)]
struct MessageReader {
    fragment_opcode: Option<Opcode>,
    fragment_buffer: Vec<u8>,
}

impl MessageReader {
    fn new() -> MessageReader {
        MessageReader {
            fragment_opcode: None,
            fragment_buffer: Vec::new(),
        }
    }

    /// Read the next message, reassembling continuation frames.
    fn next<R: Read>(&mut self, reader: &mut R, expect_mask: bool) -> Result<WsMessage, WsError> {
        loop {
            let frame = read_frame(reader, expect_mask)?;
            let opcode = frame.opcode;
            let fin = frame.fin;
            match opcode {
                Opcode::Continuation => {
                    if self.fragment_opcode.is_none() {
                        return Err(WsError::Protocol("a continuation frame has no start frame"));
                    }
                    if self.fragment_buffer.len() + frame.payload.len() > MAX_MESSAGE_BYTES {
                        return Err(WsError::MessageTooLarge);
                    }
                    self.fragment_buffer.extend_from_slice(&frame.payload);
                    if fin {
                        let kind = self.fragment_opcode.take().unwrap_or(Opcode::Binary);
                        let payload = std::mem::take(&mut self.fragment_buffer);
                        return build_message(kind, payload);
                    }
                }
                Opcode::Text | Opcode::Binary => {
                    if self.fragment_opcode.is_some() {
                        return Err(WsError::Protocol(
                            "a data frame started before the previous one finished",
                        ));
                    }
                    if frame.payload.len() > MAX_MESSAGE_BYTES {
                        return Err(WsError::MessageTooLarge);
                    }
                    if fin {
                        return build_message(opcode, frame.payload);
                    }
                    self.fragment_opcode = Some(opcode);
                    self.fragment_buffer = frame.payload;
                }
                Opcode::Ping => return Ok(WsMessage::Ping(frame.payload)),
                Opcode::Pong => return Ok(WsMessage::Pong(frame.payload)),
                Opcode::Close => {
                    let (code, reason) = parse_close(&frame.payload);
                    return Ok(WsMessage::Close { code, reason });
                }
            }
        }
    }
}

/// Build one message from a complete data frame.
fn build_message(opcode: Opcode, payload: Vec<u8>) -> Result<WsMessage, WsError> {
    match opcode {
        Opcode::Text => match String::from_utf8(payload) {
            Ok(text) => Ok(WsMessage::Text(text)),
            Err(_) => Err(WsError::Protocol("a text frame is not valid UTF-8")),
        },
        _ => Ok(WsMessage::Binary(payload)),
    }
}

/// The server-side channel a WebSocket handler works with.
pub trait WsChannel {
    /// Read the next message. A ping is answered with a pong automatically.
    fn recv(&mut self) -> Result<WsMessage, WsError>;
    /// Send one text message.
    fn send_text(&mut self, text: &str) -> Result<(), WsError>;
    /// Send one binary message.
    fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError>;
    /// Send one pong frame.
    fn send_pong(&mut self, payload: &[u8]) -> Result<(), WsError>;
    /// Send one close frame.
    fn send_close(&mut self, code: u16, reason: &str) -> Result<(), WsError>;
}

/// The byte source of a server channel: the bytes the HTTP parser already
/// buffered, then the connection itself.
struct ChannelIo<'a, S: Read + Write> {
    stream: &'a mut S,
    prefix: Vec<u8>,
    position: usize,
}

impl<S: Read + Write> Read for ChannelIo<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.position >= self.prefix.len() {
            self.prefix.clear();
            self.position = 0;
            let mut chunk = [0u8; 4096];
            let read = self.stream.read(&mut chunk)?;
            if read == 0 {
                return Ok(0);
            }
            self.prefix.extend_from_slice(&chunk[..read]);
        }
        let available = self.prefix.len() - self.position;
        let count = available.min(buf.len());
        buf[..count].copy_from_slice(&self.prefix[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

impl<S: Read + Write> Write for ChannelIo<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// A server-side WebSocket channel over one connection.
pub struct ServerChannel<'a, S: Read + Write> {
    io: ChannelIo<'a, S>,
    messages: MessageReader,
}

impl<'a, S: Read + Write> ServerChannel<'a, S> {
    /// Build a channel over `stream`. `prefix` holds the bytes the HTTP
    /// parser already read from the socket.
    pub fn new(stream: &'a mut S, prefix: Vec<u8>) -> ServerChannel<'a, S> {
        ServerChannel {
            io: ChannelIo {
                stream,
                prefix,
                position: 0,
            },
            messages: MessageReader::new(),
        }
    }

    /// Write one unmasked server frame.
    fn send_frame(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), WsError> {
        let frame = encode_frame(opcode, payload, true, None);
        self.io.write_all(&frame)?;
        self.io.flush()?;
        Ok(())
    }
}

impl<S: Read + Write> WsChannel for ServerChannel<'_, S> {
    fn recv(&mut self) -> Result<WsMessage, WsError> {
        loop {
            let message = self.messages.next(&mut self.io, true)?;
            match message {
                WsMessage::Ping(payload) => {
                    self.send_frame(Opcode::Pong, &payload)?;
                }
                other => return Ok(other),
            }
        }
    }

    fn send_text(&mut self, text: &str) -> Result<(), WsError> {
        self.send_frame(Opcode::Text, text.as_bytes())
    }

    fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError> {
        self.send_frame(Opcode::Binary, data)
    }

    fn send_pong(&mut self, payload: &[u8]) -> Result<(), WsError> {
        self.send_frame(Opcode::Pong, payload)
    }

    fn send_close(&mut self, code: u16, reason: &str) -> Result<(), WsError> {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        self.send_frame(Opcode::Close, &payload)
    }
}

/// The client-side half of the WebSocket subset.
pub mod client {
    use super::{accept_key, encode_frame, read_frame, MessageReader, Opcode, WsError, WsMessage};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    /// A client-side WebSocket connection over one TCP socket.
    #[derive(Debug)]
    pub struct WebSocketClient {
        reader: BufReader<TcpStream>,
        writer: TcpStream,
        messages: MessageReader,
    }

    impl WebSocketClient {
        /// Connect to `addr` and perform the RFC 6455 handshake for `path`.
        pub fn connect(addr: &str, path: &str) -> Result<WebSocketClient, WsError> {
            let stream = TcpStream::connect(addr)?;
            let mut writer = stream.try_clone()?;
            let key = super::random_key()?;
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: {}\r\n\r\n",
                path, addr, key, super::WS_VERSION
            );
            writer.write_all(request.as_bytes())?;
            writer.flush()?;

            let mut reader = BufReader::new(stream);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                let read = reader.read_line(&mut line)?;
                if read == 0 {
                    return Err(WsError::Handshake(
                        "the connection closed during the handshake".to_string(),
                    ));
                }
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                head.push_str(trimmed);
                head.push('\n');
            }

            let status = head.lines().next().unwrap_or_default();
            if !status.starts_with("HTTP/1.1 101") {
                return Err(WsError::Handshake(format!(
                    "the server answered {}",
                    status
                )));
            }
            let accept = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.trim().eq_ignore_ascii_case("Sec-WebSocket-Accept"))
                .map(|(_, value)| value.trim().to_string())
                .ok_or_else(|| {
                    WsError::Handshake(
                        "the handshake answer has no Sec-WebSocket-Accept header".to_string(),
                    )
                })?;
            if accept != accept_key(&key) {
                return Err(WsError::Handshake(
                    "the Sec-WebSocket-Accept value does not match the key".to_string(),
                ));
            }

            Ok(WebSocketClient {
                reader,
                writer,
                messages: MessageReader::new(),
            })
        }

        /// Send one masked text frame.
        pub fn send_text(&mut self, text: &str) -> Result<(), WsError> {
            self.send(Opcode::Text, text.as_bytes())
        }

        /// Send one masked binary frame.
        pub fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError> {
            self.send(Opcode::Binary, data)
        }

        /// Send one masked ping frame.
        pub fn send_ping(&mut self, payload: &[u8]) -> Result<(), WsError> {
            self.send(Opcode::Ping, payload)
        }

        /// Send one masked pong frame.
        pub fn send_pong(&mut self, payload: &[u8]) -> Result<(), WsError> {
            self.send(Opcode::Pong, payload)
        }

        /// Send one masked close frame.
        pub fn send_close(&mut self, code: u16, reason: &str) -> Result<(), WsError> {
            let mut payload = code.to_be_bytes().to_vec();
            payload.extend_from_slice(reason.as_bytes());
            self.send(Opcode::Close, &payload)
        }

        /// Read one raw frame, without assembling fragments.
        pub fn recv_frame(&mut self) -> Result<super::Frame, WsError> {
            read_frame(&mut self.reader, false)
        }

        /// Write already-built frames to the socket. This is how a test
        /// sends a frame the normal helpers do not build, for example an
        /// unmasked one or an oversized length.
        pub fn write_frames(&mut self, frames: &[Vec<u8>]) {
            for frame in frames {
                self.writer.write_all(frame).expect("the frame is written");
            }
            self.writer.flush().expect("the frames are flushed");
        }

        /// Read the next message, assembling fragmented frames.
        pub fn recv(&mut self) -> Result<WsMessage, WsError> {
            self.messages.next(&mut self.reader, false)
        }

        /// Send one masked frame.
        fn send(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), WsError> {
            let mask = super::random_bytes(4)?;
            let mask = [mask[0], mask[1], mask[2], mask[3]];
            let frame = encode_frame(opcode, payload, true, Some(mask));
            self.writer.write_all(&frame)?;
            self.writer.flush()?;
            Ok(())
        }
    }
}

/// Random bytes from the operating system, used for keys and masks.
fn random_bytes(length: usize) -> Result<Vec<u8>, WsError> {
    let mut buffer = vec![0u8; length];
    getrandom::getrandom(&mut buffer)
        .map_err(|err| WsError::Io(io::Error::other(err.to_string())))?;
    Ok(buffer)
}

/// A random `Sec-WebSocket-Key`: 16 random bytes in base64.
fn random_key() -> Result<String, WsError> {
    Ok(BASE64.encode(random_bytes(16)?))
}
