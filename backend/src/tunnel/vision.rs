use std::io::{self, Read as _, Write as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rand::RngCore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::BoxStream;

pub const VISION_CMD_CONTINUE: u8 = 0x00;
pub const VISION_CMD_END: u8 = 0x01;
pub const VISION_CMD_DIRECT: u8 = 0x02;

const VISION_MAX_RECORD: usize = 8192;
const VISION_MAX_CONTENT: usize = VISION_MAX_RECORD - 21;
const VISION_LONG_PAD_MIN: usize = 900;
const VISION_LONG_PAD_SPAN: usize = 500;
const VISION_SHORT_PAD_MAX: usize = 256;
const VISION_PACKET_FILTER_COUNT: usize = 8;
const MAX_OUTER_TLS_CIPHERTEXT: usize = 16384 + 256;

const TLS_HANDSHAKE_HDR_CLIENT: [u8; 2] = [0x16, 0x03];
const TLS_APP_DATA_PREFIX: [u8; 3] = [0x17, 0x03, 0x03];

pub fn encode_flow(flow: &str) -> Vec<u8> {
    if flow.is_empty() {
        return Vec::new();
    }
    let fb = flow.as_bytes();
    let mut out = Vec::with_capacity(2 + fb.len());
    out.push(0x0a); // field 1, wire type 2
    write_varint(&mut out, fb.len() as u64);
    out.extend_from_slice(fb);
    out
}

pub fn decode_flow(raw: &[u8]) -> Result<String, String> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    let mut idx = 0usize;
    let mut flow_out = String::new();
    while idx < raw.len() {
        let (key, n) = read_varint(&raw[idx..]).ok_or_else(|| "invalid addons key".to_string())?;
        idx += n;
        let wire_type = key & 0x07;
        match wire_type {
            0 => {
                let (_, vn) =
                    read_varint(&raw[idx..]).ok_or_else(|| "invalid addons varint".to_string())?;
                idx += vn;
            }
            1 => {
                if idx + 8 > raw.len() {
                    return Err("addons fixed64 truncated".to_string());
                }
                idx += 8;
            }
            2 => {
                let (length, m) = read_varint(&raw[idx..])
                    .ok_or_else(|| "invalid addons length".to_string())?;
                idx += m;
                let length = length as usize;
                if idx + length > raw.len() {
                    return Err("addons field truncated".to_string());
                }
                let val = &raw[idx..idx + length];
                idx += length;
                if key == 0x0a {
                    flow_out = String::from_utf8(val.to_vec()).map_err(|e| e.to_string())?;
                }
            }
            5 => {
                if idx + 4 > raw.len() {
                    return Err("addons fixed32 truncated".to_string());
                }
                idx += 4;
            }
            _ => {
                return Err(format!("unsupported addons wire type {}", wire_type));
            }
        }
    }
    Ok(flow_out)
}

fn write_varint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0u64;
    let mut s = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None;
            }
            return Some((x | ((b as u64) << s), i + 1));
        }
        x |= ((b & 0x7f) as u64) << s;
        s += 7;
    }
    None
}

fn calc_vision_padding(content_len: usize, long_pad: bool) -> usize {
    let mut b = [0u8; 2];
    rand::rng().fill_bytes(&mut b);
    let rnd = u16::from_be_bytes(b) as usize;
    let pad = if long_pad && content_len < VISION_LONG_PAD_MIN {
        let target = VISION_LONG_PAD_MIN + (rnd % VISION_LONG_PAD_SPAN);
        target.saturating_sub(content_len)
    } else {
        rnd % VISION_SHORT_PAD_MAX
    };
    let max_pad = VISION_MAX_RECORD.saturating_sub(21 + content_len);
    pad.min(max_pad)
}

fn build_vision_frame_into(
    buf: &mut Vec<u8>,
    user_uuid: &[u8; 16],
    wrote_uuid: &mut bool,
    content: &[u8],
    cmd: u8,
    pad_len: usize,
) {
    let prefix_len = if *wrote_uuid { 0 } else { 16 };
    let total_len = prefix_len + 5 + content.len() + pad_len;
    let start = buf.len();
    buf.resize(start + total_len, 0);
    let mut off = start;
    if !*wrote_uuid {
        buf[off..off + 16].copy_from_slice(user_uuid);
        *wrote_uuid = true;
        off += 16;
    }
    buf[off] = cmd;
    buf[off + 1..off + 3].copy_from_slice(&(content.len() as u16).to_be_bytes());
    buf[off + 3..off + 5].copy_from_slice(&(pad_len as u16).to_be_bytes());
    off += 5;
    buf[off..off + content.len()].copy_from_slice(content);
    off += content.len();
    if pad_len > 0 {
        rand::rng().fill_bytes(&mut buf[off..off + pad_len]);
    }
}

/// Record-by-record outer TLS wrapper around `rustls::Connection` + `TcpStream`
/// that supports clean half-duplex transition to raw TCP for XTLS Vision `0x02` (`CommandPaddingDirect`).
pub struct RustlsSpliceStream {
    tcp: TcpStream,
    tls: rustls::Connection,
    read_raw_buf: Vec<u8>,
    read_raw_pos: usize,
    read_plain_buf: Vec<u8>,
    read_plain_pos: usize,
    write_cipher_buf: Vec<u8>,
    write_cipher_pos: usize,
    pending_write_len: usize,
    write_raw_passthrough: bool,
    read_raw_passthrough: bool,
    sent_close_notify: bool,
    eof: bool,
}

impl RustlsSpliceStream {
    pub async fn accept(tcp: TcpStream, cfg: Arc<rustls::ServerConfig>) -> io::Result<Self> {
        let sc = rustls::ServerConnection::new(cfg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut s = Self::new(tcp, rustls::Connection::Server(sc));
        s.complete_handshake().await?;
        Ok(s)
    }

    pub async fn connect(
        tcp: TcpStream,
        cfg: Arc<rustls::ClientConfig>,
        server_name: ServerName<'static>,
    ) -> io::Result<Self> {
        let cc = rustls::ClientConnection::new(cfg, server_name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut s = Self::new(tcp, rustls::Connection::Client(cc));
        s.complete_handshake().await?;
        Ok(s)
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.tls.alpn_protocol()
    }

    fn new(tcp: TcpStream, tls: rustls::Connection) -> Self {
        Self {
            tcp,
            tls,
            read_raw_buf: Vec::with_capacity(65536),
            read_raw_pos: 0,
            read_plain_buf: Vec::with_capacity(32768),
            read_plain_pos: 0,
            write_cipher_buf: Vec::with_capacity(65536 + 128),
            write_cipher_pos: 0,
            pending_write_len: 0,
            write_raw_passthrough: false,
            read_raw_passthrough: false,
            sent_close_notify: false,
            eof: false,
        }
    }

    async fn complete_handshake(&mut self) -> io::Result<()> {
        let mut out_buf = Vec::with_capacity(4096);
        while self.tls.is_handshaking() {
            while self.tls.wants_write() {
                out_buf.clear();
                self.tls.write_tls(&mut out_buf)?;
                if !out_buf.is_empty() {
                    self.tcp.write_all(&out_buf).await?;
                }
            }
            self.tcp.flush().await?;
            if !self.tls.is_handshaking() {
                break;
            }
            let mut hdr = [0u8; 5];
            self.tcp.read_exact(&mut hdr).await?;
            let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if rlen > MAX_OUTER_TLS_CIPHERTEXT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "outer TLS handshake record exceeds maximum length",
                ));
            }
            let mut rec = Vec::with_capacity(5 + rlen);
            rec.extend_from_slice(&hdr);
            rec.resize(5 + rlen, 0);
            self.tcp.read_exact(&mut rec[5..]).await?;

            let mut cur = io::Cursor::new(&rec[..]);
            while (cur.position() as usize) < rec.len() {
                let n = self.tls.read_tls(&mut cur)?;
                if n == 0 {
                    break;
                }
                let state = self
                    .tls
                    .process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let avail = state.plaintext_bytes_to_read();
                if avail > 0 {
                    let start = self.read_plain_buf.len();
                    self.read_plain_buf.resize(start + avail, 0);
                    let got = self.tls.reader().read(&mut self.read_plain_buf[start..])?;
                    self.read_plain_buf.truncate(start + got);
                }
            }
        }
        while self.tls.wants_write() {
            out_buf.clear();
            self.tls.write_tls(&mut out_buf)?;
            if !out_buf.is_empty() {
                self.tcp.write_all(&out_buf).await?;
            }
        }
        self.tcp.flush().await
    }

    pub fn enable_raw_write(&mut self) {
        self.write_raw_passthrough = true;
    }

    pub fn enable_raw_read(&mut self) {
        self.read_raw_passthrough = true;
    }

    fn drain_tls_writes(&mut self) -> io::Result<()> {
        while self.tls.wants_write() {
            let n = self.tls.write_tls(&mut self.write_cipher_buf)?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }

    fn poll_flush_cipher_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_cipher_pos < self.write_cipher_buf.len() {
            match Pin::new(&mut self.tcp)
                .poll_write(cx, &self.write_cipher_buf[self.write_cipher_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "rustls splice write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => self.write_cipher_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_cipher_buf.clear();
        self.write_cipher_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for RustlsSpliceStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_plain_pos < this.read_plain_buf.len() {
                let avail = &this.read_plain_buf[this.read_plain_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.read_plain_pos += n;
                if this.read_plain_pos >= this.read_plain_buf.len() {
                    this.read_plain_buf.clear();
                    this.read_plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if this.read_raw_passthrough {
                if this.read_raw_pos < this.read_raw_buf.len() {
                    let avail = &this.read_raw_buf[this.read_raw_pos..];
                    let n = avail.len().min(buf.remaining());
                    buf.put_slice(&avail[..n]);
                    this.read_raw_pos += n;
                    if this.read_raw_pos >= this.read_raw_buf.len() {
                        this.read_raw_buf.clear();
                        this.read_raw_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.tcp).poll_read(cx, buf);
            }

            if this.eof {
                return Poll::Ready(Ok(()));
            }

            let raw_avail = this.read_raw_buf.len() - this.read_raw_pos;
            if raw_avail >= 5 {
                let base = this.read_raw_pos;
                let rlen =
                    u16::from_be_bytes([this.read_raw_buf[base + 3], this.read_raw_buf[base + 4]])
                        as usize;
                if rlen > MAX_OUTER_TLS_CIPHERTEXT {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "outer TLS record length overflow",
                    )));
                }
                if raw_avail >= 5 + rlen {
                    let rec_end = base + 5 + rlen;
                    this.read_raw_pos = rec_end;
                    let mut cur = io::Cursor::new(&this.read_raw_buf[base..rec_end]);
                    let mut peer_closed = false;
                    while (cur.position() as usize) < (5 + rlen) {
                        let n = this.tls.read_tls(&mut cur)?;
                        if n == 0 {
                            break;
                        }
                        let state = this
                            .tls
                            .process_new_packets()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        let plain_n = state.plaintext_bytes_to_read();
                        if plain_n > 0 {
                            let start = this.read_plain_buf.len();
                            this.read_plain_buf.resize(start + plain_n, 0);
                            let got = this.tls.reader().read(&mut this.read_plain_buf[start..])?;
                            this.read_plain_buf.truncate(start + got);
                        }
                        if state.peer_has_closed() {
                            peer_closed = true;
                        }
                    }
                    if this.read_raw_pos == this.read_raw_buf.len() {
                        this.read_raw_buf.clear();
                        this.read_raw_pos = 0;
                    }
                    if this.read_plain_pos < this.read_plain_buf.len() {
                        let avail = &this.read_plain_buf[this.read_plain_pos..];
                        let direct = avail.len().min(buf.remaining());
                        buf.put_slice(&avail[..direct]);
                        this.read_plain_pos += direct;
                        if this.read_plain_pos >= this.read_plain_buf.len() {
                            this.read_plain_buf.clear();
                            this.read_plain_pos = 0;
                        }
                        if peer_closed && this.read_plain_pos >= this.read_plain_buf.len() {
                            this.eof = true;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    if peer_closed {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
            }

            if this.read_raw_pos > 0 {
                this.read_raw_buf.copy_within(this.read_raw_pos.., 0);
                let rem = this.read_raw_buf.len() - this.read_raw_pos;
                this.read_raw_buf.truncate(rem);
                this.read_raw_pos = 0;
            }

            let mut tmp = [0u8; 32768];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.tcp).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        this.eof = true;
                        if this.read_raw_pos == this.read_raw_buf.len() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "outer TLS record truncated on EOF",
                        )));
                    }
                    this.read_raw_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RustlsSpliceStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_cipher_pos < this.write_cipher_buf.len() {
            match this.poll_flush_cipher_buf(cx) {
                Poll::Ready(Ok(())) => {
                    if this.pending_write_len > 0 {
                        let written = std::mem::replace(&mut this.pending_write_len, 0);
                        return Poll::Ready(Ok(written));
                    }
                }
                Poll::Ready(Err(e)) => {
                    this.pending_write_len = 0;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_raw_passthrough {
            return Pin::new(&mut this.tcp).poll_write(cx, buf);
        }
        let batch_len = buf.len().min(65536);
        this.write_cipher_buf.clear();
        this.write_cipher_pos = 0;
        this.tls.writer().write_all(&buf[..batch_len])?;
        if let Err(e) = this.drain_tls_writes() {
            return Poll::Ready(Err(e));
        }
        this.pending_write_len = batch_len;
        match this.poll_flush_cipher_buf(cx) {
            Poll::Ready(Ok(())) => {
                let written = std::mem::replace(&mut this.pending_write_len, 0);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_raw_passthrough && this.tls.wants_write() {
            if let Err(e) = this.drain_tls_writes() {
                return Poll::Ready(Err(e));
            }
        }
        match this.poll_flush_cipher_buf(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        }
        this.pending_write_len = 0;
        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_raw_passthrough && !this.sent_close_notify {
            match this.poll_flush_cipher_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    this.pending_write_len = 0;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
            this.pending_write_len = 0;
            this.sent_close_notify = true;
            this.tls.send_close_notify();
            let _ = this.drain_tls_writes();
        }
        match this.poll_flush_cipher_buf(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        }
        this.pending_write_len = 0;
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}

pub enum VisionInner {
    Boxed(BoxStream),
    Reality(Box<super::reality::RealityTlsStream<TcpStream>>),
    Rustls(Box<RustlsSpliceStream>),
}

impl VisionInner {
    pub fn into_box_stream(self) -> BoxStream {
        match self {
            Self::Boxed(s) => s,
            Self::Reality(s) => s,
            Self::Rustls(s) => s,
        }
    }

    fn supports_splice(&self) -> bool {
        matches!(self, Self::Reality(_) | Self::Rustls(_))
    }

    fn enable_raw_write(&mut self) {
        match self {
            Self::Boxed(_) => {}
            Self::Reality(s) => s.enable_raw_write(),
            Self::Rustls(s) => s.enable_raw_write(),
        }
    }

    fn enable_raw_read(&mut self) {
        match self {
            Self::Boxed(_) => {}
            Self::Reality(s) => s.enable_raw_read(),
            Self::Rustls(s) => s.enable_raw_read(),
        }
    }

    fn poll_read_inner(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Boxed(s) => Pin::new(s).poll_read(cx, buf),
            Self::Reality(s) => Pin::new(s).poll_read(cx, buf),
            Self::Rustls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }

    fn poll_write_inner(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            Self::Boxed(s) => Pin::new(s).poll_write(cx, buf),
            Self::Reality(s) => Pin::new(s).poll_write(cx, buf),
            Self::Rustls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Boxed(s) => Pin::new(s).poll_flush(cx),
            Self::Reality(s) => Pin::new(s).poll_flush(cx),
            Self::Rustls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Boxed(s) => Pin::new(s).poll_shutdown(cx),
            Self::Reality(s) => Pin::new(s).poll_shutdown(cx),
            Self::Rustls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Xray `XtlsFilterTls` state shared across read and write directions of a single Vision stream.
#[derive(Default)]
struct VisionFilterState {
    packets_to_filter: usize,
    is_tls12_or_above: bool,
    is_tls: bool,
    enable_xtls: bool,
    cipher: u16,
    server_hello_buf: Vec<u8>,
    server_hello_target_len: usize,
}

impl VisionFilterState {
    fn new() -> Self {
        Self {
            packets_to_filter: VISION_PACKET_FILTER_COUNT,
            ..Default::default()
        }
    }

    fn filter_packet(&mut self, data: &[u8]) {
        if data.is_empty() || self.packets_to_filter == 0 {
            return;
        }
        self.packets_to_filter = self.packets_to_filter.saturating_sub(1);

        if self.server_hello_target_len > 0 && self.server_hello_buf.len() < self.server_hello_target_len {
            let need = self.server_hello_target_len - self.server_hello_buf.len();
            let take = need.min(data.len());
            self.server_hello_buf.extend_from_slice(&data[..take]);
            self.try_parse_server_hello();
            return;
        }

        if data.len() >= 6 && data[0..2] == TLS_HANDSHAKE_HDR_CLIENT {
            if (1..=3).contains(&data[2]) && data[5] == 0x01 {
                self.is_tls12_or_above = true;
                self.is_tls = true;
            } else if data[2] == 0x03 && data[5] == 0x02 {
                self.is_tls12_or_above = true;
                self.is_tls = true;
                let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                let target = (5 + rec_len).min(16389);
                self.server_hello_target_len = target;
                self.server_hello_buf.clear();
                let take = target.min(data.len());
                self.server_hello_buf.extend_from_slice(&data[..take]);
                self.try_parse_server_hello();
            }
        }
    }

    fn try_parse_server_hello(&mut self) {
        let buf = &self.server_hello_buf;
        if buf.len() < 44 {
            return;
        }
        let sid_len = buf[43] as usize;
        let cipher_pos = 44 + sid_len;
        if buf.len() < cipher_pos + 3 {
            return;
        }
        self.cipher = u16::from_be_bytes([buf[cipher_pos], buf[cipher_pos + 1]]);
        // Exclude TLS_AES_128_CCM_8_SHA256 (0x1305) per Xray Vision spec
        let cipher_ok = (0x1301..=0x1304).contains(&self.cipher);
        if buf.len() < self.server_hello_target_len {
            return;
        }
        let ext_len_pos = cipher_pos + 3;
        if buf.len() < ext_len_pos + 2 {
            self.server_hello_target_len = 0;
            self.server_hello_buf.clear();
            return;
        }
        let exts_len = u16::from_be_bytes([buf[ext_len_pos], buf[ext_len_pos + 1]]) as usize;
        let mut pos = ext_len_pos + 2;
        let end = (pos + exts_len).min(buf.len());
        let mut is_tls13 = false;
        while pos + 4 <= end {
            let et = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let el = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;
            if pos + el > end {
                break;
            }
            if et == 0x002b && el == 2 && buf[pos..pos + 2] == [0x03, 0x04] {
                is_tls13 = true;
                break;
            }
            pos += el;
        }
        if is_tls13 && cipher_ok {
            self.enable_xtls = true;
            self.packets_to_filter = 0;
        }
        self.server_hello_target_len = 0;
        self.server_hello_buf.clear();
    }
}

/// Finds the byte offset of the first inner TLS 1.3 ApplicationData record (`[0x17, 0x03, 0x03]`)
/// when coalesced behind TLS Handshake (`0x16`) or ChangeCipherSpec (`0x14`) records.
fn find_tls_appdata_boundary(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    if buf.starts_with(&TLS_APP_DATA_PREFIX) {
        return Some(0);
    }
    let mut pos = 0usize;
    while pos + 5 <= buf.len() {
        let ct = buf[pos];
        let v_maj = buf[pos + 1];
        let v_min = buf[pos + 2];
        if v_maj != 0x03 || !(1..=3).contains(&v_min) {
            return None;
        }
        if ct == 0x17 && v_min == 0x03 {
            return Some(pos);
        }
        if ct != 0x14 && ct != 0x16 {
            return None;
        }
        let rlen = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if rlen > 16640 || pos + 5 + rlen > buf.len() {
            return None;
        }
        pos += 5 + rlen;
    }
    None
}

pub struct VisionStream {
    inner: VisionInner,
    user_uuid: [u8; 16],
    wrote_uuid: bool,
    filter: VisionFilterState,
    write_direct: bool,
    pending_raw_write_switch: bool,
    write_buf: Vec<u8>,
    write_pos: usize,
    pending_write_len: usize,
    read_uuid: bool,
    read_direct: bool,
    read_raw_buf: Vec<u8>,
    read_raw_pos: usize,
    read_plain_buf: Vec<u8>,
    read_plain_pos: usize,
    eof: bool,
}

impl VisionStream {
    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            match self
                .inner
                .poll_write_inner(cx, &self.write_buf[self.write_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    self.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        if self.pending_raw_write_switch {
            self.pending_raw_write_switch = false;
            self.inner.enable_raw_write();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_plain_pos < this.read_plain_buf.len() {
                let avail = &this.read_plain_buf[this.read_plain_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.read_plain_pos += n;
                if this.read_plain_pos >= this.read_plain_buf.len() {
                    this.read_plain_buf.clear();
                    this.read_plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if this.read_direct {
                if this.read_raw_pos < this.read_raw_buf.len() {
                    let avail = &this.read_raw_buf[this.read_raw_pos..];
                    let n = avail.len().min(buf.remaining());
                    buf.put_slice(&avail[..n]);
                    this.read_raw_pos += n;
                    if this.read_raw_pos >= this.read_raw_buf.len() {
                        this.read_raw_buf.clear();
                        this.read_raw_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                return this.inner.poll_read_inner(cx, buf);
            }

            if this.eof {
                return Poll::Ready(Ok(()));
            }

            let need_hdr = (if this.read_uuid { 0 } else { 16 }) + 5;
            let raw_avail = this.read_raw_buf.len() - this.read_raw_pos;
            if raw_avail >= need_hdr {
                if !this.read_uuid
                    && this.read_raw_buf[this.read_raw_pos..this.read_raw_pos + 16]
                        != this.user_uuid
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vision user uuid mismatch",
                    )));
                }
                let hdr_off = this.read_raw_pos + if this.read_uuid { 0 } else { 16 };
                let cmd = this.read_raw_buf[hdr_off];
                if cmd != VISION_CMD_CONTINUE && cmd != VISION_CMD_END && cmd != VISION_CMD_DIRECT {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid vision command",
                    )));
                }
                let content_len = u16::from_be_bytes([
                    this.read_raw_buf[hdr_off + 1],
                    this.read_raw_buf[hdr_off + 2],
                ]) as usize;
                let pad_len = u16::from_be_bytes([
                    this.read_raw_buf[hdr_off + 3],
                    this.read_raw_buf[hdr_off + 4],
                ]) as usize;
                let total_frame = need_hdr + content_len + pad_len;
                if raw_avail >= total_frame {
                    this.read_uuid = true;
                    let content_start = hdr_off + 5;
                    let content_end = content_start + content_len;
                    this.read_raw_pos += total_frame;
                    if cmd == VISION_CMD_END {
                        this.read_direct = true;
                    } else if cmd == VISION_CMD_DIRECT {
                        this.read_direct = true;
                        this.inner.enable_raw_read();
                    }
                    if content_len > 0 {
                        let content_slice = &this.read_raw_buf[content_start..content_end];
                        this.filter.filter_packet(content_slice);
                        let direct = content_slice.len().min(buf.remaining());
                        if direct > 0 {
                            buf.put_slice(&content_slice[..direct]);
                        }
                        if direct < content_slice.len() {
                            this.read_plain_buf.clear();
                            this.read_plain_buf
                                .extend_from_slice(&content_slice[direct..]);
                            this.read_plain_pos = 0;
                        }
                        if this.read_raw_pos == this.read_raw_buf.len() {
                            this.read_raw_buf.clear();
                            this.read_raw_pos = 0;
                            if this.read_raw_buf.capacity() > 256 * 1024 {
                                this.read_raw_buf.shrink_to(65536);
                            }
                        }
                        if direct > 0 {
                            return Poll::Ready(Ok(()));
                        }
                    } else if this.read_raw_pos == this.read_raw_buf.len() {
                        this.read_raw_buf.clear();
                        this.read_raw_pos = 0;
                        if this.read_raw_buf.capacity() > 256 * 1024 {
                            this.read_raw_buf.shrink_to(65536);
                        }
                    }
                    continue;
                }
            }

            if this.read_raw_pos > 0 {
                this.read_raw_buf.copy_within(this.read_raw_pos.., 0);
                let rem = this.read_raw_buf.len() - this.read_raw_pos;
                this.read_raw_buf.truncate(rem);
                this.read_raw_pos = 0;
                if this.read_raw_buf.capacity() > 256 * 1024 && rem < 16384 {
                    this.read_raw_buf.shrink_to(65536);
                }
            }

            let mut tmp = [0u8; 32768];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match this.inner.poll_read_inner(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        this.eof = true;
                        if this.read_raw_pos == this.read_raw_buf.len() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vision frame truncated on EOF",
                        )));
                    }
                    this.read_raw_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_pos < this.write_buf.len() {
            match this.poll_drain_write(cx) {
                Poll::Ready(Ok(())) => {
                    if this.pending_write_len > 0 {
                        let written = std::mem::replace(&mut this.pending_write_len, 0);
                        return Poll::Ready(Ok(written));
                    }
                }
                Poll::Ready(Err(e)) => {
                    this.pending_write_len = 0;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_direct {
            return this.inner.poll_write_inner(cx, buf);
        }

        let mut max_take = buf.len().min(VISION_MAX_CONTENT);
        if this.filter.is_tls {
            if let Some(app_off) = find_tls_appdata_boundary(&buf[..max_take]) {
                if app_off > 0 {
                    // Reshape: emit handshake/CCS records in their own CONTINUE frame first so
                    // `[0x17, 0x03, 0x03]` begins cleanly on the next frame boundary.
                    max_take = app_off;
                }
            }
        }

        let chunk = &buf[..max_take];
        this.filter.filter_packet(chunk);

        let is_appdata_start =
            this.filter.is_tls && chunk.len() >= 3 && chunk[..3] == TLS_APP_DATA_PREFIX;
        let cmd = if is_appdata_start {
            this.write_direct = true;
            if this.filter.enable_xtls && this.inner.supports_splice() {
                this.pending_raw_write_switch = true;
                VISION_CMD_DIRECT
            } else {
                VISION_CMD_END
            }
        } else if this.filter.packets_to_filter == 0 && !this.filter.is_tls {
            this.write_direct = true;
            VISION_CMD_END
        } else {
            VISION_CMD_CONTINUE
        };

        let long_pad = this.filter.is_tls && cmd == VISION_CMD_CONTINUE;
        let pad_len = calc_vision_padding(max_take, long_pad);
        this.write_buf.clear();
        this.write_pos = 0;
        this.pending_write_len = max_take;
        build_vision_frame_into(
            &mut this.write_buf,
            &this.user_uuid,
            &mut this.wrote_uuid,
            chunk,
            cmd,
            pad_len,
        );
        match this.poll_drain_write(cx) {
            Poll::Ready(Ok(())) => {
                let written = std::mem::replace(&mut this.pending_write_len, 0);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        }
        this.pending_write_len = 0;
        this.inner.poll_flush_inner(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        }
        this.pending_write_len = 0;
        this.inner.poll_shutdown_inner(cx)
    }
}

pub fn append_initial_camouflage(buf: &mut Vec<u8>, user_uuid: &[u8; 16]) {
    let mut wrote_uuid = false;
    let pad_len = calc_vision_padding(0, true);
    build_vision_frame_into(
        buf,
        user_uuid,
        &mut wrote_uuid,
        &[],
        VISION_CMD_CONTINUE,
        pad_len,
    );
}

pub fn wrap_vision_inner_started(inner: VisionInner, user_uuid: [u8; 16]) -> BoxStream {
    Box::new(VisionStream {
        inner,
        user_uuid,
        wrote_uuid: true,
        filter: VisionFilterState::new(),
        write_direct: false,
        pending_raw_write_switch: false,
        write_buf: Vec::with_capacity(VISION_MAX_RECORD + 64),
        write_pos: 0,
        pending_write_len: 0,
        read_uuid: false,
        read_direct: false,
        read_raw_buf: Vec::with_capacity(65536),
        read_raw_pos: 0,
        read_plain_buf: Vec::with_capacity(32768),
        read_plain_pos: 0,
        eof: false,
    })
}

pub fn wrap_vision_stream_started(inner: BoxStream, user_uuid: [u8; 16]) -> BoxStream {
    wrap_vision_inner_started(VisionInner::Boxed(inner), user_uuid)
}

pub fn wrap_vision_inner(
    inner: VisionInner,
    user_uuid: [u8; 16],
    send_initial_camouflage: bool,
) -> BoxStream {
    let mut wrote_uuid = false;
    let mut write_buf = Vec::with_capacity(VISION_MAX_RECORD + 64);
    if send_initial_camouflage {
        let pad_len = calc_vision_padding(0, true);
        build_vision_frame_into(
            &mut write_buf,
            &user_uuid,
            &mut wrote_uuid,
            &[],
            VISION_CMD_CONTINUE,
            pad_len,
        );
    }
    Box::new(VisionStream {
        inner,
        user_uuid,
        wrote_uuid,
        filter: VisionFilterState::new(),
        write_direct: false,
        pending_raw_write_switch: false,
        write_buf,
        write_pos: 0,
        pending_write_len: 0,
        read_uuid: false,
        read_direct: false,
        read_raw_buf: Vec::with_capacity(32768),
        read_raw_pos: 0,
        read_plain_buf: Vec::new(),
        read_plain_pos: 0,
        eof: false,
    })
}

pub fn wrap_vision_stream(
    inner: BoxStream,
    user_uuid: [u8; 16],
    send_initial_camouflage: bool,
) -> BoxStream {
    wrap_vision_inner(VisionInner::Boxed(inner), user_uuid, send_initial_camouflage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct ThrottledStream {
        inner: tokio::io::DuplexStream,
        write_step: usize,
        yield_next_write: bool,
    }

    impl AsyncRead for ThrottledStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ThrottledStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.yield_next_write {
                self.yield_next_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.yield_next_write = true;
            let cap = buf.len().min(self.write_step.max(1));
            Pin::new(&mut self.inner).poll_write(cx, &buf[..cap])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn vision_stream_preserves_order_under_backpressure() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let uuid = [0x42u8; 16];
        let mut writer = wrap_vision_stream(
            Box::new(ThrottledStream {
                inner: a,
                write_step: 13,
                yield_next_write: true,
            }),
            uuid,
            true,
        );
        let mut reader = wrap_vision_stream(Box::new(b), uuid, false);

        let chunks: Vec<Vec<u8>> = (0..12)
            .map(|i| vec![(i + 1) as u8; 120 + i * 37])
            .collect();
        let expected: Vec<u8> = chunks.iter().flatten().copied().collect();

        let write_task = tokio::spawn(async move {
            for c in chunks {
                writer.write_all(&c).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        write_task.await.unwrap();
        assert_eq!(received, expected);
    }

    #[test]
    fn decode_flow_skips_unknown_varint_and_fixed_fields() {
        let mut buf = vec![0x10, 0x01, 0x1d, 1, 2, 3, 4]; // field 2 varint=1, field 3 fixed32
        buf.extend_from_slice(&encode_flow("xtls-rprx-vision"));
        buf.extend_from_slice(&[0x21, 1, 2, 3, 4, 5, 6, 7, 8]); // field 4 fixed64
        assert_eq!(decode_flow(&buf).unwrap(), "xtls-rprx-vision");
    }

    #[tokio::test]
    async fn vision_splices_inner_tls13_over_outer_reality_without_double_encryption() {
        use super::super::reality::{
            reality_accept_stream, reality_connect_stream, RealityClientConfig, RealityReplayCache,
            RealityServerConfig,
        };
        use tokio::net::TcpListener;
        use x25519_dalek::{PublicKey, StaticSecret};

        // Generate self-signed cert for inner TLS 1.3 server
        let mut params = rcgen::CertificateParams::new(vec!["inner.example.com".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(kp.serialize_der()),
        );

        let provider = super::super::fast_crypto_provider();
        let inner_srv_cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der)
                .unwrap(),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let inner_cli_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let srv_priv = [0x31u8; 32];
        let srv_pub = *PublicKey::from(&StaticSecret::from(srv_priv)).as_bytes();
        let r_srv_cfg = Arc::new(RealityServerConfig {
            private_key: srv_priv,
            short_ids: vec![(vec![0xaa, 0xbb, 0, 0, 0, 0, 0, 0], 2)],
            server_names: vec!["www.cloudflare.com".to_string()],
            dest: String::new(),
            max_time_diff_ms: 180_000,
            mldsa65_seed: String::new(),
            replay_cache: Arc::new(RealityReplayCache::new()),
        });
        let r_cli_cfg = RealityClientConfig {
            server_name: "www.cloudflare.com".to_string(),
            public_key: srv_pub,
            short_id: vec![0xaa, 0xbb],
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string()],
            mldsa65_verify: String::new(),
            spider_x: String::new(),
            spider_y: Vec::new(),
        };

        let uuid = [0x99u8; 16];
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();

        let srv_task = tokio::spawn(async move {
            let (tcp, _) = ln.accept().await.unwrap();
            let r_stream = reality_accept_stream(tcp, &r_srv_cfg).await.unwrap().unwrap();
            let vision_srv = wrap_vision_inner(VisionInner::Reality(Box::new(r_stream)), uuid, true);
            let acceptor = tokio_rustls::TlsAcceptor::from(inner_srv_cfg);
            let mut inner_tls = acceptor.accept(vision_srv).await.unwrap();
            let mut req = vec![0u8; 64 * 1024];
            inner_tls.read_exact(&mut req).await.unwrap();
            inner_tls.write_all(&req).await.unwrap();
            inner_tls.flush().await.unwrap();
            inner_tls.shutdown().await.unwrap();
        });

        let tcp_cli = TcpStream::connect(addr).await.unwrap();
        let r_cli_stream = reality_connect_stream(tcp_cli, &r_cli_cfg).await.unwrap();
        let vision_cli = wrap_vision_inner(VisionInner::Reality(Box::new(r_cli_stream)), uuid, true);
        let connector = tokio_rustls::TlsConnector::from(inner_cli_cfg);
        let sni = ServerName::try_from("inner.example.com".to_string()).unwrap();
        let mut inner_cli_tls = connector.connect(sni, vision_cli).await.unwrap();

        let payload: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
        inner_cli_tls.write_all(&payload).await.unwrap();
        inner_cli_tls.flush().await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        inner_cli_tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        let _ = inner_cli_tls.shutdown().await;
        srv_task.await.unwrap();
    }
}
