use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::model::{Binding, LocalTLS};
use super::BoxStream;

const H3_STREAM_TYPE_CONTROL: u64 = 0x00;
const H3_FRAME_SETTINGS: u64 = 0x04;
const H3_FRAME_HEADERS: u64 = 0x01;
const HY2_FRAME_TCP_REQUEST: u64 = 0x401;
const HY2_PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub struct QuicBidiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _conn: quinn::Connection,
    _endpoint: Option<quinn::Endpoint>,
}

impl AsyncRead for QuicBidiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBidiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(io::Error::from)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::from)
    }
}

pub fn build_quic_server_config(local: &LocalTLS) -> Result<quinn::ServerConfig, String> {
    let (certs, key) = load_cert_and_key(&local.cert_pem, &local.key_pem)?;
    let provider = super::fast_crypto_provider();
    let mut tls_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    tls_cfg.max_early_data_size = u32::MAX;

    let quic_tls = QuicServerConfig::try_from(tls_cfg).map_err(|e| e.to_string())?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(32u32.into());
    if let Ok(idle) = Duration::from_secs(45).try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    server_cfg.transport_config(Arc::new(transport));
    Ok(server_cfg)
}

pub fn build_quic_client_config(local: &LocalTLS) -> Result<quinn::ClientConfig, String> {
    let provider = super::fast_crypto_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?;

    let roots: Arc<rustls::RootCertStore> = if !local.ca_pem.trim().is_empty() {
        let mut roots = rustls::RootCertStore::empty();
        let mut reader = io::BufReader::new(local.ca_pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| e.to_string())?;
            roots.add(cert).map_err(|e| e.to_string())?;
        }
        if roots.is_empty() {
            return Err("no valid CA certificates found in ca_pem".to_string());
        }
        Arc::new(roots)
    } else {
        static DEFAULT_ROOTS: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
        DEFAULT_ROOTS
            .get_or_init(|| {
                let mut store = rustls::RootCertStore::empty();
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                Arc::new(store)
            })
            .clone()
    };
    let mut tls_cfg = builder.with_root_certificates(roots).with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let quic_tls = QuicClientConfig::try_from(tls_cfg).map_err(|e| e.to_string())?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(32u32.into());
    if let Ok(idle) = Duration::from_secs(45).try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    client_cfg.transport_config(Arc::new(transport));
    Ok(client_cfg)
}

pub fn load_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let mut cert_reader = io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse cert pem: {}", e))?;
    if certs.is_empty() {
        return Err("no certificates found in cert_pem".to_string());
    }
    let mut key_reader = io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("parse key pem: {}", e))?
        .ok_or_else(|| "no private key found in key_pem".to_string())?;
    Ok((certs, key))
}

pub async fn hy2_connect(
    remote_addr: SocketAddr,
    local: &LocalTLS,
    binding: &Binding,
    gw_addr: &str,
) -> Result<BoxStream, String> {
    let client_cfg = build_quic_client_config(local)?;
    let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let udp_sock = {
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(bind_addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| e.to_string())?;
        let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
        sock.bind(&bind_addr.into()).map_err(|e| e.to_string())?;
        std::net::UdpSocket::from(sock)
    };
    let mut quic_ep = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        udp_sock,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| e.to_string())?;
    quic_ep.set_default_client_config(client_cfg);

    let sni = if !gw_addr.trim().is_empty() {
        gw_addr.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };

    let connecting = quic_ep
        .connect(remote_addr, &sni)
        .map_err(|e| e.to_string())?;
    let conn = tokio::time::timeout(Duration::from_secs(10), connecting)
        .await
        .map_err(|_| "hy2 connect timeout".to_string())?
        .map_err(|e| format!("hy2 connect: {}", e))?;

    start_h3_control_streams(&conn).await?;

    // 1. Auth stream
    let (mut auth_send, mut auth_recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let pad = random_padding(32, 96);
    let req_headers = encode_qpack_field_section(&[
        (":method", "POST"),
        (":scheme", "https"),
        (":path", "/auth"),
        (":authority", "hysteria"),
        ("hysteria-auth", binding.uuid.trim()),
        ("hysteria-cc-rx", "auto"),
        ("hysteria-padding", &pad),
    ]);
    write_h3_frame(&mut auth_send, H3_FRAME_HEADERS, &req_headers).await?;
    let _ = auth_send.finish();

    let (ftype, fpayload) = read_h3_frame(&mut auth_recv).await?;
    if ftype != H3_FRAME_HEADERS {
        return Err(format!("expected H3 HEADERS frame, got {}", ftype));
    }
    let resp_headers = decode_qpack_field_section(&fpayload)?;
    let status = resp_headers
        .iter()
        .find(|(k, _)| k == ":status")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if status != "233" {
        return Err(format!("hysteria2 auth rejected with status {:?}", status));
    }

    // 2. TCP tunnel stream
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let addr = format!("{}:0", binding.domain.trim());
    let req_pad = random_padding(16, 64);
    let mut req_buf = Vec::with_capacity(16 + addr.len() + req_pad.len());
    append_varint(&mut req_buf, HY2_FRAME_TCP_REQUEST);
    append_varint(&mut req_buf, addr.len() as u64);
    req_buf.extend_from_slice(addr.as_bytes());
    append_varint(&mut req_buf, req_pad.len() as u64);
    req_buf.extend_from_slice(req_pad.as_bytes());
    send.write_all(&req_buf).await.map_err(|e| e.to_string())?;

    let mut status_byte = [0u8; 1];
    recv.read_exact(&mut status_byte)
        .await
        .map_err(|e| e.to_string())?;
    let msg_len = read_varint(&mut recv).await? as usize;
    if msg_len > 4096 {
        return Err("hy2 response message too long".to_string());
    }
    let mut msg_buf = vec![0u8; msg_len];
    if msg_len > 0 {
        recv.read_exact(&mut msg_buf)
            .await
            .map_err(|e| e.to_string())?;
    }
    let pad_len = read_varint(&mut recv).await? as usize;
    if pad_len > 4096 {
        return Err("hy2 response padding too long".to_string());
    }
    if pad_len > 0 {
        let mut pad_buf = vec![0u8; pad_len];
        recv.read_exact(&mut pad_buf)
            .await
            .map_err(|e| e.to_string())?;
    }
    if status_byte[0] != 0x00 {
        return Err(format!(
            "hy2 tcp request rejected: {}",
            String::from_utf8_lossy(&msg_buf)
        ));
    }

    Ok(Box::new(QuicBidiStream {
        send,
        recv,
        _conn: conn,
        _endpoint: Some(quic_ep),
    }))
}

pub async fn hy2_accept_connection(
    conn: quinn::Connection,
    _local: &LocalTLS,
    bindings: &[Binding],
) -> Result<(BoxStream, Binding), String> {
    start_h3_control_streams(&conn).await?;

    // 1. Auth stream
    let (mut auth_send, mut auth_recv) = conn.accept_bi().await.map_err(|e| e.to_string())?;
    let (ftype, fpayload) = read_h3_frame(&mut auth_recv).await?;
    if ftype != H3_FRAME_HEADERS {
        return Err(format!("expected H3 HEADERS frame, got {}", ftype));
    }
    let headers = decode_qpack_field_section(&fpayload)?;
    let method = headers
        .iter()
        .find(|(k, _)| k == ":method")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let path = headers
        .iter()
        .find(|(k, _)| k == ":path")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let auth_val = headers
        .iter()
        .find(|(k, _)| k == "hysteria-auth")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if method != "POST" || path != "/auth" || auth_val.is_empty() {
        return Err("invalid hysteria2 auth request".to_string());
    }

    let mut matched_binding: Option<Binding> = None;
    for b in bindings {
        let cand = b.uuid.trim().as_bytes();
        let got = auth_val.trim().as_bytes();
        if cand.len() == got.len() && cand.ct_eq(got).unwrap_u8() == 1 {
            matched_binding = Some(b.clone());
            break;
        }
    }
    let binding = match matched_binding {
        Some(b) => b,
        None => {
            let resp = encode_qpack_field_section(&[(":status", "404")]);
            let _ = write_h3_frame(&mut auth_send, H3_FRAME_HEADERS, &resp).await;
            let _ = auth_send.finish();
            return Err("hysteria2 auth uuid mismatch".to_string());
        }
    };

    let resp_pad = random_padding(32, 96);
    let resp_headers = encode_qpack_field_section(&[
        (":status", "233"),
        ("hysteria-udp", "false"),
        ("hysteria-cc-rx", "auto"),
        ("hysteria-padding", &resp_pad),
    ]);
    write_h3_frame(&mut auth_send, H3_FRAME_HEADERS, &resp_headers).await?;
    let _ = auth_send.finish();

    // 2. TCP tunnel stream
    let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| e.to_string())?;
    let req_type = read_varint(&mut recv).await?;
    if req_type != HY2_FRAME_TCP_REQUEST {
        return Err(format!("unexpected hy2 stream type 0x{:x}", req_type));
    }
    let addr_len = read_varint(&mut recv).await? as usize;
    if addr_len == 0 || addr_len > 2048 {
        return Err("invalid hy2 address length".to_string());
    }
    let mut addr_buf = vec![0u8; addr_len];
    recv.read_exact(&mut addr_buf)
        .await
        .map_err(|e| e.to_string())?;
    let pad_len = read_varint(&mut recv).await? as usize;
    if pad_len > 4096 {
        return Err("hy2 request padding too long".to_string());
    }
    if pad_len > 0 {
        let mut pad_buf = vec![0u8; pad_len];
        recv.read_exact(&mut pad_buf)
            .await
            .map_err(|e| e.to_string())?;
    }

    let addr_str = String::from_utf8_lossy(&addr_buf);
    let host = addr_str
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&addr_str);
    if !host.eq_ignore_ascii_case(binding.domain.trim()) {
        let mut err_resp = vec![0x01, 0x00, 0x00];
        let _ = send.write_all(&err_resp).await;
        err_resp.clear();
        return Err(format!("hy2 domain mismatch: got {}", host));
    }

    let ok_pad = random_padding(16, 48);
    let mut ok_resp = Vec::with_capacity(4 + ok_pad.len());
    ok_resp.push(0x00); // status OK
    append_varint(&mut ok_resp, 0); // empty message
    append_varint(&mut ok_resp, ok_pad.len() as u64);
    ok_resp.extend_from_slice(ok_pad.as_bytes());
    send.write_all(&ok_resp).await.map_err(|e| e.to_string())?;

    Ok((
        Box::new(QuicBidiStream {
            send,
            recv,
            _conn: conn,
            _endpoint: None,
        }),
        binding,
    ))
}

async fn start_h3_control_streams(conn: &quinn::Connection) -> Result<(), String> {
    let mut uni = conn.open_uni().await.map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(8);
    append_varint(&mut buf, H3_STREAM_TYPE_CONTROL);
    append_varint(&mut buf, H3_FRAME_SETTINGS);
    append_varint(&mut buf, 0);
    uni.write_all(&buf).await.map_err(|e| e.to_string())?;

    let conn_clone = conn.clone();
    tokio::spawn(async move {
        while let Ok(mut recv) = conn_clone.accept_uni().await {
            tokio::spawn(async move {
                let mut discard = [0u8; 1024];
                while let Ok(Some(n)) = recv.read(&mut discard).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    Ok(())
}

async fn write_h3_frame(
    send: &mut quinn::SendStream,
    frame_type: u64,
    payload: &[u8],
) -> Result<(), String> {
    let mut buf = Vec::with_capacity(16 + payload.len());
    append_varint(&mut buf, frame_type);
    append_varint(&mut buf, payload.len() as u64);
    buf.extend_from_slice(payload);
    send.write_all(&buf).await.map_err(|e| e.to_string())
}

async fn read_h3_frame(recv: &mut quinn::RecvStream) -> Result<(u64, Vec<u8>), String> {
    let frame_type = read_varint(recv).await?;
    let length = read_varint(recv).await? as usize;
    if length > 64 * 1024 {
        return Err(format!("H3 frame too large: {}", length));
    }
    let mut payload = vec![0u8; length];
    if length > 0 {
        recv.read_exact(&mut payload)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok((frame_type, payload))
}

fn encode_qpack_field_section(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00]; // Required Insert Count = 0, Delta Base = 0
    for (name, value) in headers {
        let nb = name.to_ascii_lowercase();
        let nb = nb.as_bytes();
        let vb = value.as_bytes();
        // Literal Field Line With Literal Name (pattern 0010_0xxx, N=0, H=0, 3-bit prefix)
        encode_prefixed_int(&mut out, 0x20, 3, nb.len());
        out.extend_from_slice(nb);
        // Value string (H=0, 7-bit prefix)
        encode_prefixed_int(&mut out, 0x00, 7, vb.len());
        out.extend_from_slice(vb);
    }
    out
}

fn decode_qpack_field_section(data: &[u8]) -> Result<Vec<(String, String)>, String> {
    if data.len() < 2 {
        return Err("QPACK field section too short".to_string());
    }
    let mut pos = 0usize;
    let (_, n1) = decode_prefixed_int(&data[pos..], 8)?;
    pos += n1;
    let (_, n2) = decode_prefixed_int(&data[pos..], 7)?;
    pos += n2;

    let mut out = Vec::new();
    while pos < data.len() {
        let b = data[pos];
        if (b & 0xe0) == 0x20 {
            if (b & 0x08) != 0 {
                return Err("QPACK Huffman name not supported".to_string());
            }
            let (nlen, used) = decode_prefixed_int(&data[pos..], 3)?;
            pos += used;
            if pos + nlen > data.len() {
                return Err("QPACK name truncated".to_string());
            }
            let name = String::from_utf8_lossy(&data[pos..pos + nlen]).to_ascii_lowercase();
            pos += nlen;
            if pos >= data.len() {
                return Err("QPACK missing value".to_string());
            }
            if (data[pos] & 0x80) != 0 {
                return Err("QPACK Huffman value not supported".to_string());
            }
            let (vlen, vused) = decode_prefixed_int(&data[pos..], 7)?;
            pos += vused;
            if pos + vlen > data.len() {
                return Err("QPACK value truncated".to_string());
            }
            let value = String::from_utf8_lossy(&data[pos..pos + vlen]).to_string();
            pos += vlen;
            out.push((name, value));
        } else {
            return Err(format!("unsupported QPACK representation 0x{:02x}", b));
        }
    }
    Ok(out)
}

fn encode_prefixed_int(out: &mut Vec<u8>, mask: u8, prefix_bits: u8, mut val: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if val < max_prefix {
        out.push(mask | (val as u8));
        return;
    }
    out.push(mask | (max_prefix as u8));
    val -= max_prefix;
    while val >= 128 {
        out.push(((val & 0x7f) as u8) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

fn decode_prefixed_int(buf: &[u8], prefix_bits: u8) -> Result<(usize, usize), String> {
    if buf.is_empty() {
        return Err("empty buffer for prefixed int".to_string());
    }
    let max_prefix = (1usize << prefix_bits) - 1;
    let mut val = (buf[0] as usize) & max_prefix;
    if val < max_prefix {
        return Ok((val, 1));
    }
    let mut shift = 0u32;
    let mut idx = 1usize;
    while idx < buf.len() {
        let b = buf[idx];
        idx += 1;
        val += ((b & 0x7f) as usize) << shift;
        if (b & 0x80) == 0 {
            return Ok((val, idx));
        }
        shift += 7;
        if shift > 28 {
            return Err("QPACK integer overflow".to_string());
        }
    }
    Err("truncated QPACK integer".to_string())
}

pub fn append_varint(out: &mut Vec<u8>, v: u64) {
    if v <= 63 {
        out.push(v as u8);
    } else if v <= 16383 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v <= 1073741823 {
        out.extend_from_slice(&((v as u32) | 0x80000000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000000000000000).to_be_bytes());
    }
}

pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64, String> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first).await.map_err(|e| e.to_string())?;
    let prefix = first[0] >> 6;
    let len = 1usize << prefix;
    let mut val = (first[0] & 0x3f) as u64;
    if len > 1 {
        let mut rest = [0u8; 7];
        r.read_exact(&mut rest[..len - 1])
            .await
            .map_err(|e| e.to_string())?;
        for &b in &rest[..len - 1] {
            val = (val << 8) | (b as u64);
        }
    }
    Ok(val)
}

fn random_padding(min_len: usize, max_len: usize) -> String {
    let span = max_len.saturating_sub(min_len).max(1);
    let mut b = [0u8; 2];
    rand::rng().fill_bytes(&mut b);
    let n = min_len + (u16::from_be_bytes(b) as usize % span);
    let mut raw = vec![0u8; n];
    rand::rng().fill_bytes(&mut raw);
    raw.into_iter()
        .map(|x| HY2_PADDING_CHARS[(x as usize) % HY2_PADDING_CHARS.len()] as char)
        .collect()
}
