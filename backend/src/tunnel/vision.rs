use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::BoxStream;

const VISION_CMD_CONTINUE: u8 = 0x00;
const VISION_CMD_DIRECT: u8 = 0x01;
const VISION_CMD_DIRECT_ALT: u8 = 0x02;
const VISION_MAX_CONTENT: usize = 16 * 1024;
const VISION_LONG_PAD_MIN: usize = 900;
const VISION_LONG_PAD_SPAN: usize = 500;
const VISION_SHORT_PAD_MAX: usize = 256;
const VISION_PADDED_CHUNK_MAX: usize = 8;

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
    while idx < raw.len() {
        let (key, n) = read_varint(&raw[idx..]).ok_or_else(|| "invalid addons key".to_string())?;
        idx += n;
        let wire_type = key & 0x07;
        if wire_type != 2 {
            return Err(format!("unsupported addons wire type {}", wire_type));
        }
        let (length, m) =
            read_varint(&raw[idx..]).ok_or_else(|| "invalid addons length".to_string())?;
        idx += m;
        let length = length as usize;
        if idx + length > raw.len() {
            return Err("addons field truncated".to_string());
        }
        let val = &raw[idx..idx + length];
        idx += length;
        if key == 0x0a {
            return String::from_utf8(val.to_vec()).map_err(|e| e.to_string());
        }
    }
    Ok(String::new())
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

fn calc_vision_padding(content_len: usize, first: bool) -> usize {
    let mut b = [0u8; 2];
    rand::rng().fill_bytes(&mut b);
    let rnd = u16::from_be_bytes(b) as usize;
    if first && content_len < VISION_LONG_PAD_MIN {
        let target = VISION_LONG_PAD_MIN + (rnd % VISION_LONG_PAD_SPAN);
        if target > content_len {
            return target - content_len;
        }
    }
    rnd % VISION_SHORT_PAD_MAX
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

pub struct VisionStream {
    inner: BoxStream,
    user_uuid: [u8; 16],
    wrote_uuid: bool,
    padded_chunks: usize,
    write_direct: bool,
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
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..]) {
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
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            if this.eof {
                return Poll::Ready(Ok(()));
            }

            let need_hdr = (if this.read_uuid { 0 } else { 16 }) + 5;
            let raw_avail = this.read_raw_buf.len() - this.read_raw_pos;
            if raw_avail >= need_hdr {
                let hdr_off = this.read_raw_pos + if this.read_uuid { 0 } else { 16 };
                let cmd = this.read_raw_buf[hdr_off];
                if cmd != VISION_CMD_CONTINUE
                    && cmd != VISION_CMD_DIRECT
                    && cmd != VISION_CMD_DIRECT_ALT
                {
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
                    if cmd == VISION_CMD_DIRECT || cmd == VISION_CMD_DIRECT_ALT {
                        this.read_direct = true;
                    }
                    if content_len > 0 {
                        let content_slice = &this.read_raw_buf[content_start..content_end];
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
                        }
                        if direct > 0 {
                            return Poll::Ready(Ok(()));
                        }
                    } else if this.read_raw_pos == this.read_raw_buf.len() {
                        this.read_raw_buf.clear();
                        this.read_raw_pos = 0;
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
            match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
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
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let n = buf.len().min(VISION_MAX_CONTENT);
        this.padded_chunks += 1;
        let cmd = if this.padded_chunks >= VISION_PADDED_CHUNK_MAX {
            this.write_direct = true;
            VISION_CMD_DIRECT
        } else {
            VISION_CMD_CONTINUE
        };
        let pad_len = calc_vision_padding(n, !this.wrote_uuid);
        this.write_buf.clear();
        this.write_pos = 0;
        this.pending_write_len = n;
        build_vision_frame_into(
            &mut this.write_buf,
            &this.user_uuid,
            &mut this.wrote_uuid,
            &buf[..n],
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
        if let Poll::Pending = this.poll_drain_write(cx) {
            return Poll::Pending;
        }
        this.pending_write_len = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Pending = this.poll_drain_write(cx) {
            return Poll::Pending;
        }
        this.pending_write_len = 0;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub fn wrap_vision_stream(
    inner: BoxStream,
    user_uuid: [u8; 16],
    send_initial_camouflage: bool,
) -> BoxStream {
    let mut wrote_uuid = false;
    let mut padded_chunks = 0usize;
    let mut write_buf = Vec::with_capacity(VISION_MAX_CONTENT + 512);
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
        padded_chunks = 1;
    }
    Box::new(VisionStream {
        inner,
        user_uuid,
        wrote_uuid,
        padded_chunks,
        write_direct: false,
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
}
