use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use super::vless_enc::TaskedDuplex;
use super::BoxStream;
use crate::model::{MUX_TYPE_H2MUX, MUX_TYPE_SMUX, MUX_TYPE_YAMUX};

pub const PORT_CONTROL: u16 = 0;
pub const PORT_APPLICATION: u16 = 1;
pub const PORT_SING_MUX: u16 = 2;

pub const APP_STREAM_PREFACE: &[u8; 22] = b"veilink-application/3\0";
pub const SING_MUX_PREFACE: &[u8; 19] = b"veilink-sing-mux/1\0";

// ============================================================================
// Genuine Xray-core XUDP Packet Framing (common/xudp + common/protocol)
// ============================================================================

pub const XUDP_STATUS_NEW: u8 = 0x01;
pub const XUDP_STATUS_KEEP: u8 = 0x02;
pub const XUDP_STATUS_END: u8 = 0x03;
pub const XUDP_STATUS_KEEPALIVE: u8 = 0x04;

pub const XUDP_OPT_DATA: u8 = 0x01;
pub const XUDP_OPT_ERROR: u8 = 0x02;

pub const XUDP_NET_TCP: u8 = 0x01;
pub const XUDP_NET_UDP: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedXudpPacket<'a> {
    pub session_id: u16,
    pub status: u8,
    pub option: u8,
    pub target: Option<(String, u16)>,
    pub global_id: Option<[u8; 8]>,
    pub payload: &'a [u8],
    pub frame_len: usize,
}

pub fn compute_xudp_global_id(peer: SocketAddr, base_key: &[u8; 32]) -> [u8; 8] {
    let label = format!("udp:{}", peer);
    let hash = blake3::keyed_hash(base_key, label.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    out
}

fn append_xray_port_then_address(buf: &mut Vec<u8>, host: &str, port: u16) -> Result<(), String> {
    buf.extend_from_slice(&port.to_be_bytes());
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(0x03);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if host.is_empty() || host.len() > 253 {
            return Err("invalid XUDP domain length".to_string());
        }
        buf.push(0x02);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

fn parse_xray_port_then_address(buf: &[u8]) -> Result<(String, u16, usize), String> {
    if buf.len() < 4 {
        return Err("XUDP address truncated".to_string());
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    match buf[2] {
        0x01 => {
            if buf.len() < 7 {
                return Err("XUDP IPv4 address truncated".to_string());
            }
            let ip = IpAddr::from([buf[3], buf[4], buf[5], buf[6]]);
            Ok((ip.to_string(), port, 7))
        }
        0x02 => {
            let dlen = buf[3] as usize;
            if dlen == 0 || buf.len() < 4 + dlen {
                return Err("XUDP domain truncated".to_string());
            }
            let domain = std::str::from_utf8(&buf[4..4 + dlen])
                .map_err(|_| "invalid XUDP UTF-8 domain".to_string())?
                .to_string();
            Ok((domain, port, 4 + dlen))
        }
        0x03 => {
            if buf.len() < 19 {
                return Err("XUDP IPv6 address truncated".to_string());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[3..19]);
            let ip = IpAddr::from(octets);
            Ok((ip.to_string(), port, 19))
        }
        other => Err(format!("invalid XUDP address family 0x{:02x}", other)),
    }
}

pub fn encode_xudp_new(
    session_id: u16,
    host: &str,
    port: u16,
    payload: &[u8],
    global_id: Option<[u8; 8]>,
) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err("XUDP payload exceeds 65535 bytes".to_string());
    }
    let mut meta = Vec::with_capacity(32 + host.len());
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(XUDP_STATUS_NEW);
    meta.push(XUDP_OPT_DATA);
    meta.push(XUDP_NET_UDP);
    append_xray_port_then_address(&mut meta, host, port)?;
    if let Some(gid) = global_id {
        meta.extend_from_slice(&gid);
    }
    if meta.len() > 267 {
        return Err("XUDP metadata exceeds 267 bytes".to_string());
    }
    let mut out = Vec::with_capacity(2 + meta.len() + 2 + payload.len());
    out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn encode_xudp_keep(session_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(XUDP_STATUS_KEEP);
    out.push(XUDP_OPT_DATA);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn encode_xudp_end(session_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(XUDP_STATUS_END);
    out.push(0x00);
    out
}

pub fn decode_xudp_packet(frame: &[u8]) -> Result<DecodedXudpPacket<'_>, String> {
    if frame.len() < 6 {
        return Err("XUDP frame shorter than 6 bytes".to_string());
    }
    let meta_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    if !(4..=267).contains(&meta_len) {
        return Err(format!("invalid XUDP metadata length {}", meta_len));
    }
    if frame.len() < 2 + meta_len {
        return Err("XUDP metadata truncated".to_string());
    }
    let meta = &frame[2..2 + meta_len];
    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];
    if (option & XUDP_OPT_ERROR) != 0 {
        return Err("XUDP error option set".to_string());
    }

    let mut target = None;
    let mut global_id = None;
    match status {
        XUDP_STATUS_NEW => {
            if meta.len() < 5 {
                return Err("XUDP New metadata missing network".to_string());
            }
            let net = meta[4];
            if net != XUDP_NET_UDP && net != XUDP_NET_TCP {
                return Err(format!("unsupported XUDP network 0x{:02x}", net));
            }
            let (host, port, used) = parse_xray_port_then_address(&meta[5..])?;
            target = Some((host, port));
            let rem = &meta[5 + used..];
            if rem.len() >= 8 {
                let mut gid = [0u8; 8];
                gid.copy_from_slice(&rem[..8]);
                global_id = Some(gid);
            }
        }
        XUDP_STATUS_KEEP | XUDP_STATUS_END | XUDP_STATUS_KEEPALIVE => {
            if status == XUDP_STATUS_KEEP && meta.len() >= 9 && meta[4] == XUDP_NET_UDP {
                if let Ok((host, port, _)) = parse_xray_port_then_address(&meta[5..]) {
                    target = Some((host, port));
                }
            }
        }
        other => return Err(format!("unknown XUDP session status 0x{:02x}", other)),
    }

    let mut cursor = 2 + meta_len;
    let payload = if (option & XUDP_OPT_DATA) != 0 {
        if frame.len() < cursor + 2 {
            return Err("XUDP OptionData missing payload length".to_string());
        }
        let plen = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]) as usize;
        cursor += 2;
        if frame.len() < cursor + plen {
            return Err("XUDP payload truncated".to_string());
        }
        let s = &frame[cursor..cursor + plen];
        cursor += plen;
        s
    } else {
        &[][..]
    };

    Ok(DecodedXudpPacket {
        session_id,
        status,
        option,
        target,
        global_id,
        payload,
        frame_len: cursor,
    })
}

// ============================================================================
// Genuine sing-mux Protocol & Sub-Stream Headers (smux v2 / yamux / h2mux)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingMuxProto {
    Smux = 0,
    Yamux = 1,
    H2Mux = 2,
}

impl SingMuxProto {
    pub fn from_mux_type(s: &str) -> Option<Self> {
        match s {
            MUX_TYPE_SMUX => Some(Self::Smux),
            MUX_TYPE_YAMUX => Some(Self::Yamux),
            MUX_TYPE_H2MUX => Some(Self::H2Mux),
            _ => None,
        }
    }

    pub fn from_wire_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Smux),
            1 => Some(Self::Yamux),
            2 => Some(Self::H2Mux),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smux => MUX_TYPE_SMUX,
            Self::Yamux => MUX_TYPE_YAMUX,
            Self::H2Mux => MUX_TYPE_H2MUX,
        }
    }
}

pub async fn write_sing_mux_stream_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    host: &str,
    port: u16,
    is_udp: bool,
) -> Result<(), String> {
    let mut buf = Vec::with_capacity(8 + host.len());
    let flags: u16 = if is_udp { 0x0001 } else { 0x0000 };
    buf.extend_from_slice(&flags.to_be_bytes());
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(0x04);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if host.is_empty() || host.len() > 253 {
            return Err("invalid sing-mux target host".to_string());
        }
        buf.push(0x03);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    buf.extend_from_slice(&port.to_be_bytes());
    w.write_all(&buf).await.map_err(|e| e.to_string())?;
    w.flush().await.map_err(|e| e.to_string())
}

pub async fn read_sing_mux_stream_request<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<(String, u16, bool), String> {
    let mut head = [0u8; 3];
    r.read_exact(&mut head).await.map_err(|e| e.to_string())?;
    let flags = u16::from_be_bytes([head[0], head[1]]);
    let is_udp = (flags & 0x0001) != 0;
    let host = match head[2] {
        0x01 => {
            let mut v4 = [0u8; 4];
            r.read_exact(&mut v4).await.map_err(|e| e.to_string())?;
            IpAddr::from(v4).to_string()
        }
        0x04 => {
            let mut v6 = [0u8; 16];
            r.read_exact(&mut v6).await.map_err(|e| e.to_string())?;
            IpAddr::from(v6).to_string()
        }
        0x03 => {
            let mut dlen = [0u8; 1];
            r.read_exact(&mut dlen).await.map_err(|e| e.to_string())?;
            let n = dlen[0] as usize;
            if n == 0 || n > 253 {
                return Err("invalid sing-mux domain length".to_string());
            }
            let mut dbuf = vec![0u8; n];
            r.read_exact(&mut dbuf).await.map_err(|e| e.to_string())?;
            String::from_utf8(dbuf).map_err(|_| "invalid sing-mux domain".to_string())?
        }
        other => return Err(format!("invalid sing-mux address type 0x{:02x}", other)),
    };
    let mut port_b = [0u8; 2];
    r.read_exact(&mut port_b).await.map_err(|e| e.to_string())?;
    let port = u16::from_be_bytes(port_b);
    Ok((host, port, is_udp))
}

pub async fn write_sing_mux_stream_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    err_msg: Option<&str>,
) -> Result<(), String> {
    match err_msg {
        None => {
            w.write_all(&[0x00]).await.map_err(|e| e.to_string())?;
        }
        Some(msg) => {
            let mb = msg.as_bytes();
            let take = mb.len().min(1024);
            let mut out = Vec::with_capacity(3 + take);
            out.push(0x01);
            out.extend_from_slice(&(take as u16).to_be_bytes());
            out.extend_from_slice(&mb[..take]);
            w.write_all(&out).await.map_err(|e| e.to_string())?;
        }
    }
    w.flush().await.map_err(|e| e.to_string())
}

pub async fn read_sing_mux_stream_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<(), String> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status).await.map_err(|e| e.to_string())?;
    if status[0] == 0x00 {
        return Ok(());
    }
    let mut len_b = [0u8; 2];
    r.read_exact(&mut len_b).await.map_err(|e| e.to_string())?;
    let n = u16::from_be_bytes(len_b) as usize;
    if n > 4096 {
        return Err("sing-mux error message too long".to_string());
    }
    let mut msg = vec![0u8; n];
    if n > 0 {
        r.read_exact(&mut msg).await.map_err(|e| e.to_string())?;
    }
    Err(format!(
        "sing-mux rejected stream: {}",
        String::from_utf8_lossy(&msg)
    ))
}

// ============================================================================
// Genuine xtaci/smux v2 Wire Multiplexer
// Header: [ver:1B=2][cmd:1B][length:2B LE][stream_id:4B LE]
// cmdUPD payload (8B): [consumed:4B LE][window:4B LE]
// ============================================================================

const SMUX_VERSION: u8 = 2;
const SMUX_CMD_SYN: u8 = 0;
const SMUX_CMD_FIN: u8 = 1;
const SMUX_CMD_PSH: u8 = 2;
const SMUX_CMD_NOP: u8 = 3;
const SMUX_CMD_UPD: u8 = 4;
const SMUX_INIT_WINDOW: u32 = 2 * 1024 * 1024;
const SMUX_MAX_FRAME_DATA: usize = 32 * 1024;

type SmuxFrame = (u8, u32, Vec<u8>);
type SmuxPermitFut = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<mpsc::OwnedPermit<SmuxFrame>, mpsc::error::SendError<()>>,
            > + Send,
    >,
>;

struct SmuxPeerWindow {
    sent_bytes: u32,
    peer_consumed: u32,
    peer_window: u32,
    closed: bool,
    write_waker: Option<std::task::Waker>,
}

impl SmuxPeerWindow {
    fn new() -> Self {
        Self {
            sent_bytes: 0,
            peer_consumed: 0,
            peer_window: SMUX_INIT_WINDOW,
            closed: false,
            write_waker: None,
        }
    }

    fn available(&self) -> usize {
        let inflight = self.sent_bytes.wrapping_sub(self.peer_consumed);
        self.peer_window.saturating_sub(inflight) as usize
    }
}

struct SmuxStreamEntry {
    in_tx: mpsc::Sender<Option<Vec<u8>>>,
    win: Arc<Mutex<SmuxPeerWindow>>,
    fin_sent: Arc<AtomicBool>,
    peer_fin: Arc<AtomicBool>,
}

struct SmuxSubStream {
    id: u32,
    ctrl_tx: mpsc::UnboundedSender<SmuxFrame>,
    data_tx: mpsc::Sender<SmuxFrame>,
    permit_fut: Option<SmuxPermitFut>,
    streams: Arc<Mutex<HashMap<u32, SmuxStreamEntry>>>,
    in_rx: mpsc::Receiver<Option<Vec<u8>>>,
    win: Arc<Mutex<SmuxPeerWindow>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    local_consumed: u32,
    last_ack_consumed: u32,
    eof: bool,
    fin_sent: Arc<AtomicBool>,
    peer_fin: Arc<AtomicBool>,
}

impl Drop for SmuxSubStream {
    fn drop(&mut self) {
        if !self.fin_sent.swap(true, Ordering::AcqRel) {
            let _ = self.ctrl_tx.send((SMUX_CMD_FIN, self.id, Vec::new()));
        }
        if self.peer_fin.load(Ordering::Acquire) {
            self.streams.lock().unwrap().remove(&self.id);
        }
    }
}

impl AsyncRead for SmuxSubStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        loop {
            if this.read_pos < this.read_buf.len() {
                let avail = &this.read_buf[this.read_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.read_pos += n;
                if this.read_pos >= this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                this.local_consumed = this.local_consumed.wrapping_add(n as u32);
                if this.local_consumed.wrapping_sub(this.last_ack_consumed)
                    >= (SMUX_INIT_WINDOW / 4)
                {
                    let mut upd = Vec::with_capacity(8);
                    upd.extend_from_slice(&this.local_consumed.to_le_bytes());
                    upd.extend_from_slice(&SMUX_INIT_WINDOW.to_le_bytes());
                    if this.ctrl_tx.send((SMUX_CMD_UPD, this.id, upd)).is_ok() {
                        this.last_ack_consumed = this.local_consumed;
                    }
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.in_rx.poll_recv(cx) {
                Poll::Ready(Some(Some(chunk))) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    this.read_buf = chunk;
                    this.read_pos = 0;
                }
                Poll::Ready(Some(None)) | Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SmuxSubStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.fin_sent.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux stream closed",
            )));
        }

        let chunk_cap = {
            let mut g = this.win.lock().unwrap();
            if g.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "smux peer closed stream",
                )));
            }
            let avail = g.available();
            if avail == 0 {
                g.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            avail.min(SMUX_MAX_FRAME_DATA).min(buf.len())
        };

        loop {
            if let Some(ref mut fut) = this.permit_fut {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        this.permit_fut = None;
                        permit.send((SMUX_CMD_PSH, this.id, buf[..chunk_cap].to_vec()));
                        let mut g = this.win.lock().unwrap();
                        g.sent_bytes = g.sent_bytes.wrapping_add(chunk_cap as u32);
                        return Poll::Ready(Ok(chunk_cap));
                    }
                    Poll::Ready(Err(_)) => {
                        this.permit_fut = None;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "smux session closed",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            match this.data_tx.clone().try_reserve_owned() {
                Ok(permit) => {
                    permit.send((SMUX_CMD_PSH, this.id, buf[..chunk_cap].to_vec()));
                    let mut g = this.win.lock().unwrap();
                    g.sent_bytes = g.sent_bytes.wrapping_add(chunk_cap as u32);
                    return Poll::Ready(Ok(chunk_cap));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    this.permit_fut = Some(Box::pin(this.data_tx.clone().reserve_owned()));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "smux session closed",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fin_sent.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        // Flush any in-flight data reservation first so FIN is strictly ordered after all PSH frames!
        if let Some(ref mut fut) = this.permit_fut {
            match fut.as_mut().poll(cx) {
                Poll::Ready(_) => {
                    this.permit_fut = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        match this.data_tx.try_send((SMUX_CMD_FIN, this.id, Vec::new())) {
            Ok(()) => {
                this.fin_sent.store(true, Ordering::Release);
                if this.peer_fin.load(Ordering::Acquire) {
                    this.streams.lock().unwrap().remove(&this.id);
                }
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                this.permit_fut = Some(Box::pin(this.data_tx.clone().reserve_owned()));
                if let Some(ref mut fut) = this.permit_fut {
                    if let Poll::Ready(Ok(permit)) = fut.as_mut().poll(cx) {
                        this.permit_fut = None;
                        permit.send((SMUX_CMD_FIN, this.id, Vec::new()));
                        this.fin_sent.store(true, Ordering::Release);
                        if this.peer_fin.load(Ordering::Acquire) {
                            this.streams.lock().unwrap().remove(&this.id);
                        }
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                this.fin_sent.store(true, Ordering::Release);
                Poll::Ready(Ok(()))
            }
        }
    }
}

fn build_smux_substream(
    id: u32,
    ctrl_tx: mpsc::UnboundedSender<SmuxFrame>,
    data_tx: mpsc::Sender<SmuxFrame>,
    streams: &Arc<Mutex<HashMap<u32, SmuxStreamEntry>>>,
    send_syn_first: bool,
) -> Result<BoxStream, String> {
    let (in_tx, in_rx) = mpsc::channel(512);
    let win = Arc::new(Mutex::new(SmuxPeerWindow::new()));
    let fin_sent = Arc::new(AtomicBool::new(false));
    let peer_fin = Arc::new(AtomicBool::new(false));
    streams.lock().unwrap().insert(
        id,
        SmuxStreamEntry {
            in_tx,
            win: win.clone(),
            fin_sent: fin_sent.clone(),
            peer_fin: peer_fin.clone(),
        },
    );
    if send_syn_first && ctrl_tx.send((SMUX_CMD_SYN, id, Vec::new())).is_err() {
        streams.lock().unwrap().remove(&id);
        return Err("smux SYN channel closed".to_string());
    }
    let mut init_upd = Vec::with_capacity(8);
    init_upd.extend_from_slice(&0u32.to_le_bytes());
    init_upd.extend_from_slice(&SMUX_INIT_WINDOW.to_le_bytes());
    let _ = ctrl_tx.send((SMUX_CMD_UPD, id, init_upd));
    Ok(Box::new(SmuxSubStream {
        id,
        ctrl_tx,
        data_tx,
        permit_fut: None,
        streams: streams.clone(),
        in_rx,
        win,
        read_buf: Vec::new(),
        read_pos: 0,
        local_consumed: 0,
        last_ack_consumed: 0,
        eof: false,
        fin_sent,
        peer_fin,
    }))
}

fn append_smux_frame(batch: &mut Vec<u8>, (cmd, sid, payload): SmuxFrame) {
    batch.push(SMUX_VERSION);
    batch.push(cmd);
    batch.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    batch.extend_from_slice(&sid.to_le_bytes());
    batch.extend_from_slice(&payload);
}

fn spawn_smux_engine(
    stream: BoxStream,
    accept_tx: Option<mpsc::Sender<BoxStream>>,
) -> (
    mpsc::UnboundedSender<SmuxFrame>,
    mpsc::Sender<SmuxFrame>,
    Arc<Mutex<HashMap<u32, SmuxStreamEntry>>>,
    Arc<AtomicBool>,
) {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<SmuxFrame>();
    let (data_tx, mut data_rx) = mpsc::channel::<SmuxFrame>(1024);
    let streams: Arc<Mutex<HashMap<u32, SmuxStreamEntry>>> = Arc::new(Mutex::new(HashMap::new()));
    let closed = Arc::new(AtomicBool::new(false));

    let closed_w = closed.clone();
    let streams_w = streams.clone();
    let write_task = tokio::spawn(async move {
        let mut batch = Vec::with_capacity(131072);
        loop {
            let first = tokio::select! {
                biased;
                c = ctrl_rx.recv() => c,
                d = data_rx.recv() => d,
            };
            let Some(frame) = first else {
                break;
            };
            batch.clear();
            append_smux_frame(&mut batch, frame);
            while batch.len() < 98304 {
                if let Ok(cf) = ctrl_rx.try_recv() {
                    append_smux_frame(&mut batch, cf);
                } else if let Ok(df) = data_rx.try_recv() {
                    append_smux_frame(&mut batch, df);
                } else {
                    break;
                }
            }
            if wr.write_all(&batch).await.is_err() || wr.flush().await.is_err() {
                break;
            }
        }
        closed_w.store(true, Ordering::Relaxed);
        let entries: Vec<SmuxStreamEntry> =
            streams_w.lock().unwrap().drain().map(|(_, v)| v).collect();
        for e in entries {
            let wk = {
                let mut g = e.win.lock().unwrap();
                g.closed = true;
                g.write_waker.take()
            };
            if let Some(w) = wk {
                w.wake();
            }
        }
        let _ = wr.shutdown().await;
    });

    let ctrl_keep = ctrl_tx.clone();
    let closed_ka = closed.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            if closed_ka.load(Ordering::Relaxed)
                || ctrl_keep.send((SMUX_CMD_NOP, 0, Vec::new())).is_err()
            {
                break;
            }
        }
    });

    let ctrl_r = ctrl_tx.clone();
    let data_r = data_tx.clone();
    let streams_r = streams.clone();
    let closed_r = closed.clone();
    let write_abort = write_task.abort_handle();
    tokio::spawn(async move {
        let mut hdr = [0u8; 8];
        loop {
            let Ok(Ok(_)) =
                tokio::time::timeout(Duration::from_secs(35), rd.read_exact(&mut hdr)).await
            else {
                break;
            };
            let ver = hdr[0];
            let cmd = hdr[1];
            let flen = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
            let sid = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            if ver != SMUX_VERSION {
                break;
            }
            let mut body = vec![0u8; flen];
            if flen > 0 {
                if tokio::time::timeout(Duration::from_secs(15), rd.read_exact(&mut body))
                    .await
                    .map_or(true, |r| r.is_err())
                {
                    break;
                }
            }
            match cmd {
                SMUX_CMD_SYN => {
                    if let Some(ref acc) = accept_tx {
                        if let Ok(sub) = build_smux_substream(
                            sid,
                            ctrl_r.clone(),
                            data_r.clone(),
                            &streams_r,
                            false,
                        ) {
                            if acc.send(sub).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                SMUX_CMD_PSH => {
                    let tx_opt = streams_r
                        .lock()
                        .unwrap()
                        .get(&sid)
                        .map(|e| e.in_tx.clone());
                    if let Some(tx) = tx_opt {
                        let _ = tx.send(Some(body)).await;
                    }
                }
                SMUX_CMD_FIN => {
                    let in_tx_opt = {
                        let mut g = streams_r.lock().unwrap();
                        let mut remove_now = false;
                        let tx = g.get(&sid).map(|e| {
                            e.peer_fin.store(true, Ordering::Release);
                            remove_now = e.fin_sent.load(Ordering::Acquire);
                            e.in_tx.clone()
                        });
                        if remove_now {
                            g.remove(&sid);
                        }
                        tx
                    };
                    if let Some(tx) = in_tx_opt {
                        let _ = tx.send(None).await;
                    }
                }
                SMUX_CMD_UPD => {
                    if body.len() == 8 {
                        let consumed = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                        let window = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                        let win_opt = streams_r.lock().unwrap().get(&sid).map(|e| e.win.clone());
                        if let Some(w) = win_opt {
                            let wk = {
                                let mut g = w.lock().unwrap();
                                g.peer_consumed = consumed;
                                g.peer_window = window.max(1024);
                                g.write_waker.take()
                            };
                            if let Some(waker) = wk {
                                waker.wake();
                            }
                        }
                    }
                }
                SMUX_CMD_NOP => {}
                _ => break,
            }
        }
        closed_r.store(true, Ordering::Relaxed);
        write_abort.abort();
        let entries: Vec<SmuxStreamEntry> =
            streams_r.lock().unwrap().drain().map(|(_, v)| v).collect();
        for e in entries {
            let wk = {
                let mut g = e.win.lock().unwrap();
                g.closed = true;
                g.write_waker.take()
            };
            if let Some(w) = wk {
                w.wake();
            }
            let _ = e.in_tx.try_send(None);
        }
    });

    (ctrl_tx, data_tx, streams, closed)
}

// ============================================================================
// HTTP/2 Sub-Stream Helper for h2mux
// ============================================================================

async fn h2mux_send_data(send: &mut h2::SendStream<Bytes>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let want = data.len().min(65536);
        send.reserve_capacity(want);
        let cap = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(c)) if c > 0 => c.min(data.len()),
            _ => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "h2mux closed")),
        };
        send.send_data(Bytes::copy_from_slice(&data[..cap]), false)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;
        data = &data[cap..];
    }
    Ok(())
}

fn wrap_h2mux_stream(mut recv: h2::RecvStream, mut send: h2::SendStream<Bytes>) -> BoxStream {
    let (local_s, peer_s) = tokio::io::duplex(256 * 1024);
    let (mut pr, mut pw) = tokio::io::split(peer_s);
    let (wf_tx, mut wf_rx) = tokio::sync::watch::channel(false);

    let w_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut clean = false;
        loop {
            match pr.read(&mut buf).await {
                Ok(0) => {
                    clean = true;
                    let _ = send.send_data(Bytes::new(), true);
                    break;
                }
                Ok(n) => {
                    if h2mux_send_data(&mut send, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !clean {
            let _ = wf_tx.send(true);
            send.send_reset(h2::Reason::CANCEL);
        }
    });

    let w_abort = w_task.abort_handle();
    let r_task = tokio::spawn(async move {
        let mut read_errored = false;
        loop {
            tokio::select! {
                _ = wf_rx.changed() => {
                    if *wf_rx.borrow() {
                        read_errored = true;
                        break;
                    }
                }
                res = recv.data() => {
                    match res {
                        Some(Ok(chunk)) => {
                            let _ = recv.flow_control().release_capacity(chunk.len());
                            if !chunk.is_empty() && pw.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) => {
                            read_errored = true;
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
        if read_errored {
            w_abort.abort();
        }
        let _ = pw.shutdown().await;
    });

    Box::new(TaskedDuplex::new(local_s, vec![w_task, r_task]))
}

// ============================================================================
// Unified SingMuxOpener (Gateway) & Responder (Client)
// ============================================================================

enum SingMuxOpenerInner {
    Smux {
        ctrl_tx: mpsc::UnboundedSender<SmuxFrame>,
        data_tx: mpsc::Sender<SmuxFrame>,
        streams: Arc<Mutex<HashMap<u32, SmuxStreamEntry>>>,
        next_id: AtomicU32,
        closed: Arc<AtomicBool>,
    },
    Yamux {
        open_tx: mpsc::Sender<oneshot::Sender<Result<BoxStream, String>>>,
        closed: Arc<AtomicBool>,
    },
    H2Mux {
        sender: tokio::sync::Mutex<h2::client::SendRequest<Bytes>>,
        closed: Arc<AtomicBool>,
    },
}

pub struct SingMuxOpener {
    pub proto: SingMuxProto,
    inner: SingMuxOpenerInner,
}

impl SingMuxOpener {
    pub async fn new(stream: BoxStream, proto: SingMuxProto) -> Result<Arc<Self>, String> {
        let inner = match proto {
            SingMuxProto::Smux => {
                let (ctrl_tx, data_tx, streams, closed) = spawn_smux_engine(stream, None);
                SingMuxOpenerInner::Smux {
                    ctrl_tx,
                    data_tx,
                    streams,
                    next_id: AtomicU32::new(1),
                    closed,
                }
            }
            SingMuxProto::Yamux => {
                let mut cfg = yamux::Config::default();
                cfg.set_read_after_close(true);
                let mut conn =
                    yamux::Connection::new(stream.compat(), cfg, yamux::Mode::Client);
                let (open_tx, mut open_rx) =
                    mpsc::channel::<oneshot::Sender<Result<BoxStream, String>>>(128);
                let closed = Arc::new(AtomicBool::new(false));
                let closed_c = closed.clone();
                tokio::spawn(async move {
                    let mut pending_req: Option<oneshot::Sender<Result<BoxStream, String>>> = None;
                    let _ = std::future::poll_fn(|cx| -> Poll<()> {
                        loop {
                            match conn.poll_next_inbound(cx) {
                                Poll::Ready(Some(Ok(_unexpected))) => continue,
                                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                                    return Poll::Ready(());
                                }
                                Poll::Pending => break,
                            }
                        }
                        loop {
                            if pending_req.is_none() {
                                match open_rx.poll_recv(cx) {
                                    Poll::Ready(Some(req)) => pending_req = Some(req),
                                    Poll::Ready(None) => return Poll::Ready(()),
                                    Poll::Pending => break,
                                }
                            }
                            if let Some(reply) = pending_req.take() {
                                match conn.poll_new_outbound(cx) {
                                    Poll::Ready(Ok(s)) => {
                                        let _ = reply.send(Ok(Box::new(s.compat())));
                                    }
                                    Poll::Ready(Err(e)) => {
                                        let _ = reply.send(Err(e.to_string()));
                                        return Poll::Ready(());
                                    }
                                    Poll::Pending => {
                                        pending_req = Some(reply);
                                        break;
                                    }
                                }
                            }
                        }
                        Poll::Pending
                    })
                    .await;
                    closed_c.store(true, Ordering::Relaxed);
                });
                SingMuxOpenerInner::Yamux { open_tx, closed }
            }
            SingMuxProto::H2Mux => {
                let mut builder = h2::client::Builder::new();
                builder
                    .initial_window_size(4 * 1024 * 1024)
                    .initial_connection_window_size(16 * 1024 * 1024);
                let (sender, h2_conn) =
                    tokio::time::timeout(Duration::from_secs(10), builder.handshake(stream))
                        .await
                        .map_err(|_| "h2mux handshake timeout".to_string())?
                        .map_err(|e| format!("h2mux handshake: {}", e))?;
                let closed = Arc::new(AtomicBool::new(false));
                let closed_c = closed.clone();
                tokio::spawn(async move {
                    let _ = h2_conn.await;
                    closed_c.store(true, Ordering::Relaxed);
                });
                SingMuxOpenerInner::H2Mux {
                    sender: tokio::sync::Mutex::new(sender),
                    closed,
                }
            }
        };
        Ok(Arc::new(Self { proto, inner }))
    }

    pub fn is_closed(&self) -> bool {
        match &self.inner {
            SingMuxOpenerInner::Smux {
                closed, data_tx, ..
            } => closed.load(Ordering::Relaxed) || data_tx.is_closed(),
            SingMuxOpenerInner::Yamux { closed, open_tx } => {
                closed.load(Ordering::Relaxed) || open_tx.is_closed()
            }
            SingMuxOpenerInner::H2Mux { closed, .. } => closed.load(Ordering::Relaxed),
        }
    }

    async fn open_raw_substream(&self) -> Result<BoxStream, String> {
        match &self.inner {
            SingMuxOpenerInner::Smux {
                ctrl_tx,
                data_tx,
                streams,
                next_id,
                closed,
            } => {
                if closed.load(Ordering::Relaxed) {
                    return Err("smux session closed".to_string());
                }
                let sid = next_id.fetch_add(2, Ordering::Relaxed);
                build_smux_substream(sid, ctrl_tx.clone(), data_tx.clone(), streams, true)
            }
            SingMuxOpenerInner::Yamux { open_tx, closed } => {
                if closed.load(Ordering::Relaxed) {
                    return Err("yamux session closed".to_string());
                }
                let (tx, rx) = oneshot::channel();
                open_tx
                    .send(tx)
                    .await
                    .map_err(|_| "yamux driver closed".to_string())?;
                tokio::time::timeout(Duration::from_secs(8), rx)
                    .await
                    .map_err(|_| "yamux open outbound timeout".to_string())?
                    .map_err(|_| "yamux open outbound cancelled".to_string())?
            }
            SingMuxOpenerInner::H2Mux { sender, closed } => {
                if closed.load(Ordering::Relaxed) {
                    return Err("h2mux session closed".to_string());
                }
                let ready = {
                    let g = sender.lock().await;
                    g.clone()
                }
                .ready()
                .await
                .map_err(|e| format!("h2mux ready: {}", e))?;
                let req = http::Request::builder()
                    .method("POST")
                    .uri("http://sing-mux/")
                    .body(())
                    .map_err(|e| e.to_string())?;
                let mut ready_mut = ready;
                let (resp_fut, send_body) = ready_mut
                    .send_request(req, false)
                    .map_err(|e| format!("h2mux send_request: {}", e))?;
                {
                    let mut g = sender.lock().await;
                    *g = ready_mut;
                }
                let resp = tokio::time::timeout(Duration::from_secs(8), resp_fut)
                    .await
                    .map_err(|_| "h2mux response timeout".to_string())?
                    .map_err(|e| format!("h2mux response: {}", e))?;
                if resp.status().as_u16() != 200 {
                    return Err(format!("h2mux unexpected status {}", resp.status()));
                }
                Ok(wrap_h2mux_stream(resp.into_body(), send_body))
            }
        }
    }

    pub async fn open_tcp_substream(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<BoxStream, String> {
        let mut sub = self.open_raw_substream().await?;
        write_sing_mux_stream_request(&mut sub, target_host, target_port, false).await?;
        tokio::time::timeout(
            Duration::from_secs(8),
            read_sing_mux_stream_response(&mut sub),
        )
        .await
        .map_err(|_| "sing-mux stream response timeout".to_string())??;
        Ok(sub)
    }
}

pub async fn serve_sing_mux_responder<F>(
    stream: BoxStream,
    proto: SingMuxProto,
    on_substream: F,
) where
    F: Fn(BoxStream) + Send + Sync + 'static,
{
    let on_substream = Arc::new(on_substream);
    match proto {
        SingMuxProto::Smux => {
            let (acc_tx, mut acc_rx) = mpsc::channel::<BoxStream>(128);
            let (_ctrl_tx, _data_tx, _streams, _closed) = spawn_smux_engine(stream, Some(acc_tx));
            while let Some(sub) = acc_rx.recv().await {
                let cb = on_substream.clone();
                cb(sub);
            }
        }
        SingMuxProto::Yamux => {
            let mut cfg = yamux::Config::default();
            cfg.set_read_after_close(true);
            let mut conn =
                yamux::Connection::new(stream.compat(), cfg, yamux::Mode::Server);
            while let Some(Ok(y_stream)) =
                std::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await
            {
                let cb = on_substream.clone();
                cb(Box::new(y_stream.compat()));
            }
        }
        SingMuxProto::H2Mux => {
            let mut builder = h2::server::Builder::new();
            builder
                .initial_window_size(4 * 1024 * 1024)
                .initial_connection_window_size(16 * 1024 * 1024)
                .max_concurrent_streams(512);
            let Ok(Ok(mut h2_conn)) =
                tokio::time::timeout(Duration::from_secs(10), builder.handshake(stream)).await
            else {
                return;
            };
            while let Some(Ok((req, mut respond))) = h2_conn.accept().await {
                let cb = on_substream.clone();
                tokio::spawn(async move {
                    let Ok(resp) = http::Response::builder().status(200).body(()) else {
                        return;
                    };
                    let Ok(send_body) = respond.send_response(resp, false) else {
                        return;
                    };
                    let sub = wrap_h2mux_stream(req.into_body(), send_body);
                    cb(sub);
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xudp_new_keep_end_roundtrip_and_strict_validation() {
        let gid = compute_xudp_global_id("192.0.2.10:54321".parse().unwrap(), &[0x42; 32]);
        let new_pkt = encode_xudp_new(7, "dns.google", 53, b"query-1", Some(gid)).unwrap();
        let dec1 = decode_xudp_packet(&new_pkt).unwrap();
        assert_eq!(dec1.session_id, 7);
        assert_eq!(dec1.status, XUDP_STATUS_NEW);
        assert_eq!(dec1.option, XUDP_OPT_DATA);
        assert_eq!(dec1.target, Some(("dns.google".to_string(), 53)));
        assert_eq!(dec1.global_id, Some(gid));
        assert_eq!(dec1.payload, b"query-1");

        let keep_pkt = encode_xudp_keep(7, b"query-2");
        let dec2 = decode_xudp_packet(&keep_pkt).unwrap();
        assert_eq!(dec2.session_id, 7);
        assert_eq!(dec2.status, XUDP_STATUS_KEEP);
        assert_eq!(dec2.payload, b"query-2");

        let end_pkt = encode_xudp_end(7);
        let dec3 = decode_xudp_packet(&end_pkt).unwrap();
        assert_eq!(dec3.status, XUDP_STATUS_END);
        assert!(dec3.payload.is_empty());

        // Invalid OptionError (0x02) must be rejected instead of returning raw unparsed bytes
        assert!(decode_xudp_packet(&[0x00, 0x04, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01, 0xff]).is_err());
    }

    #[tokio::test]
    async fn genuine_smux_yamux_and_h2mux_multiplex_concurrent_streams() {
        for proto in [SingMuxProto::Smux, SingMuxProto::Yamux, SingMuxProto::H2Mux] {
            let (srv_carrier, cli_carrier) = tokio::io::duplex(256 * 1024);
            let responder = tokio::spawn(async move {
                serve_sing_mux_responder(Box::new(cli_carrier), proto, |mut sub| {
                    tokio::spawn(async move {
                        let (host, port, is_udp) =
                            read_sing_mux_stream_request(&mut sub).await.unwrap();
                        assert!(!is_udp);
                        assert_eq!(host, "internal.service.local");
                        assert_eq!(port, 8080);
                        write_sing_mux_stream_response(&mut sub, None).await.unwrap();
                        let (mut r, mut w) = tokio::io::split(sub);
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                        let _ = w.shutdown().await;
                    });
                })
                .await;
            });

            let opener = SingMuxOpener::new(Box::new(srv_carrier), proto)
                .await
                .unwrap();

            let mut handles = Vec::new();
            for i in 0..8usize {
                let op = opener.clone();
                handles.push(tokio::spawn(async move {
                    let s = op
                        .open_tcp_substream("internal.service.local", 8080)
                        .await
                        .unwrap();
                    let msg: Vec<u8> = (0..(3 * 1024 * 1024 + i * 4096))
                        .map(|k| ((k + i) % 251) as u8)
                        .collect();
                    let expected = msg.clone();
                    let (mut rd, mut wr) = tokio::io::split(s);
                    let w_jh = tokio::spawn(async move {
                        wr.write_all(&msg).await.unwrap();
                        wr.shutdown().await.unwrap();
                    });
                    let mut got = Vec::with_capacity(expected.len());
                    rd.read_to_end(&mut got).await.unwrap();
                    w_jh.await.unwrap();
                    assert_eq!(got.len(), expected.len(), "len mismatch on {:?}", proto);
                    assert_eq!(got, expected, "mismatch on {:?}", proto);
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
            drop(opener);
            let _ = tokio::time::timeout(Duration::from_secs(2), responder).await;
        }
    }
}
