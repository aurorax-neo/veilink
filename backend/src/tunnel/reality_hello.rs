use rand::RngCore;

const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn pick_grease(seed: u8) -> u16 {
    GREASE_VALUES[(seed as usize) & 0x0f]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintProfile {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Edge,
}

impl FingerprintProfile {
    pub fn parse(s: &str) -> Self {
        let lower = s.trim().to_ascii_lowercase();
        if lower.starts_with("firefox") {
            Self::Firefox
        } else if lower.starts_with("safari") {
            Self::Safari
        } else if lower.starts_with("ios") {
            Self::Ios
        } else if lower.starts_with("edge") {
            Self::Edge
        } else {
            Self::Chrome
        }
    }
}

pub struct BuiltClientHello {
    pub record: Vec<u8>,
    pub session_id_record_offset: usize,
}

pub fn build_client_hello(
    profile: FingerprintProfile,
    sni: &str,
    client_random: &[u8; 32],
    session_id_placeholder: &[u8; 32],
    x25519_pub: &[u8; 32],
    alpn: &[&str],
) -> BuiltClientHello {
    let mut rng_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut rng_bytes);
    let g_cipher = pick_grease(rng_bytes[0]);
    let g_ext1 = pick_grease(rng_bytes[1]);
    let mut g_ext2 = pick_grease(rng_bytes[2]);
    if g_ext2 == g_ext1 {
        g_ext2 = pick_grease(rng_bytes[2].wrapping_add(1));
    }
    let g_group = pick_grease(rng_bytes[3]);
    let g_vers = pick_grease(rng_bytes[4]);

    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(client_random);
    body.push(32);
    let sid_body_offset = body.len();
    body.extend_from_slice(session_id_placeholder);

    let ciphers: Vec<u16> = match profile {
        FingerprintProfile::Chrome | FingerprintProfile::Edge => vec![
            g_cipher, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        FingerprintProfile::Firefox => vec![
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
            0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        FingerprintProfile::Safari | FingerprintProfile::Ios => vec![
            g_cipher, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
            0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
        ],
    };
    put_u16(&mut body, (ciphers.len() * 2) as u16);
    for c in ciphers {
        put_u16(&mut body, c);
    }
    body.extend_from_slice(&[0x01, 0x00]);

    let exts = match profile {
        FingerprintProfile::Chrome | FingerprintProfile::Edge => {
            build_chrome_extensions(sni, x25519_pub, alpn, g_ext1, g_ext2, g_group, g_vers)
        }
        FingerprintProfile::Firefox => build_firefox_extensions(sni, x25519_pub, alpn),
        FingerprintProfile::Safari | FingerprintProfile::Ios => {
            build_safari_extensions(sni, x25519_pub, alpn, g_ext1, g_ext2, g_group, g_vers)
        }
    };
    put_u16(&mut body, exts.len() as u16);
    body.extend_from_slice(&exts);

    let total_with_hs_header = 4 + body.len();
    if matches!(
        profile,
        FingerprintProfile::Chrome | FingerprintProfile::Edge
    ) && (256..512).contains(&total_with_hs_header)
    {
        let exts_len_pos = body.len() - exts.len() - 2;
        let needed = 512usize.saturating_sub(total_with_hs_header);
        let pad_payload_len = needed.saturating_sub(4);
        put_u16(&mut body, 0x0015);
        put_u16(&mut body, pad_payload_len as u16);
        body.resize(body.len() + pad_payload_len, 0);
        let new_exts_len = (body.len() - exts_len_pos - 2) as u16;
        body[exts_len_pos..exts_len_pos + 2].copy_from_slice(&new_exts_len.to_be_bytes());
    }

    let mut record = Vec::with_capacity(5 + 4 + body.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    put_u16(&mut record, (4 + body.len()) as u16);
    record.push(0x01);
    put_u24(&mut record, body.len() as u32);
    let session_id_record_offset = record.len() + sid_body_offset;
    record.extend_from_slice(&body);

    BuiltClientHello {
        record,
        session_id_record_offset,
    }
}

pub fn patch_session_id(hello: &mut BuiltClientHello, encrypted_sid: &[u8; 32]) {
    let off = hello.session_id_record_offset;
    hello.record[off..off + 32].copy_from_slice(encrypted_sid);
}

fn build_chrome_extensions(
    sni: &str,
    x25519_pub: &[u8; 32],
    alpn: &[&str],
    g_ext1: u16,
    g_ext2: u16,
    g_group: u16,
    g_vers: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(320);
    write_ext(&mut out, g_ext1, &[]);
    write_ext_sni(&mut out, sni);
    write_ext(&mut out, 0x0017, &[]);
    write_ext(&mut out, 0xff01, &[0x00]);
    write_ext_supported_groups(&mut out, &[g_group, 0x001d, 0x0017, 0x0018]);
    write_ext(&mut out, 0x000b, &[0x01, 0x00]);
    write_ext(&mut out, 0x0023, &[]);
    write_ext_alpn(&mut out, alpn);
    write_ext(&mut out, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);
    write_ext_sig_algs(
        &mut out,
        &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807,
        ],
    );
    write_ext(&mut out, 0x0012, &[]);
    write_ext_key_share(&mut out, Some(g_group), x25519_pub);
    write_ext(&mut out, 0x002d, &[0x01, 0x01]);
    write_ext_supported_versions(&mut out, &[g_vers, 0x0304, 0x0303]);
    write_ext(&mut out, 0027, &[0x02, 0x00, 0x02]);
    write_ext(&mut out, g_ext2, &[0x00]);
    out
}

fn build_firefox_extensions(sni: &str, x25519_pub: &[u8; 32], alpn: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(280);
    write_ext_sni(&mut out, sni);
    write_ext(&mut out, 0x0017, &[]);
    write_ext(&mut out, 0xff01, &[0x00]);
    write_ext_supported_groups(&mut out, &[0x001d, 0x0017, 0x0018, 0x0019]);
    write_ext(&mut out, 0x000b, &[0x01, 0x00]);
    write_ext(&mut out, 0x0023, &[]);
    write_ext_alpn(&mut out, alpn);
    write_ext(&mut out, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);
    write_ext_key_share(&mut out, None, x25519_pub);
    write_ext_supported_versions(&mut out, &[0x0304, 0x0303]);
    write_ext_sig_algs(
        &mut out,
        &[
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807,
        ],
    );
    write_ext(&mut out, 0x002d, &[0x01, 0x01]);
    write_ext(&mut out, 0x001c, &[0x40, 0x01]);
    out
}

fn build_safari_extensions(
    sni: &str,
    x25519_pub: &[u8; 32],
    alpn: &[&str],
    g_ext1: u16,
    g_ext2: u16,
    g_group: u16,
    g_vers: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(280);
    write_ext(&mut out, g_ext1, &[]);
    write_ext_sni(&mut out, sni);
    write_ext(&mut out, 0x0017, &[]);
    write_ext(&mut out, 0xff01, &[0x00]);
    write_ext_supported_groups(&mut out, &[g_group, 0x001d, 0x0017, 0x0018, 0x0019]);
    write_ext(&mut out, 0x000b, &[0x01, 0x00]);
    write_ext_alpn(&mut out, alpn);
    write_ext(&mut out, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);
    write_ext_sig_algs(
        &mut out,
        &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807,
        ],
    );
    write_ext(&mut out, 0x0012, &[]);
    write_ext_key_share(&mut out, Some(g_group), x25519_pub);
    write_ext(&mut out, 0x002d, &[0x01, 0x01]);
    write_ext_supported_versions(&mut out, &[g_vers, 0x0304, 0x0303]);
    write_ext(&mut out, g_ext2, &[0x00]);
    out
}

fn write_ext(out: &mut Vec<u8>, ext_type: u16, payload: &[u8]) {
    put_u16(out, ext_type);
    put_u16(out, payload.len() as u16);
    out.extend_from_slice(payload);
}

fn write_ext_sni(out: &mut Vec<u8>, sni: &str) {
    let host = sni.as_bytes();
    if host.is_empty() {
        return;
    }
    let mut payload = Vec::with_capacity(5 + host.len());
    put_u16(&mut payload, (3 + host.len()) as u16);
    payload.push(0x00);
    put_u16(&mut payload, host.len() as u16);
    payload.extend_from_slice(host);
    write_ext(out, 0x0000, &payload);
}

fn write_ext_alpn(out: &mut Vec<u8>, alpn: &[&str]) {
    if alpn.is_empty() {
        return;
    }
    let mut list = Vec::new();
    for proto in alpn {
        let b = proto.as_bytes();
        if !b.is_empty() && b.len() <= 255 {
            list.push(b.len() as u8);
            list.extend_from_slice(b);
        }
    }
    if list.is_empty() {
        return;
    }
    let mut payload = Vec::with_capacity(2 + list.len());
    put_u16(&mut payload, list.len() as u16);
    payload.extend_from_slice(&list);
    write_ext(out, 0x0010, &payload);
}

fn write_ext_supported_groups(out: &mut Vec<u8>, groups: &[u16]) {
    let mut payload = Vec::with_capacity(2 + groups.len() * 2);
    put_u16(&mut payload, (groups.len() * 2) as u16);
    for &g in groups {
        put_u16(&mut payload, g);
    }
    write_ext(out, 0x000a, &payload);
}

fn write_ext_sig_algs(out: &mut Vec<u8>, algs: &[u16]) {
    let mut payload = Vec::with_capacity(2 + algs.len() * 2);
    put_u16(&mut payload, (algs.len() * 2) as u16);
    for &a in algs {
        put_u16(&mut payload, a);
    }
    write_ext(out, 0x000d, &payload);
}

fn write_ext_supported_versions(out: &mut Vec<u8>, versions: &[u16]) {
    let mut payload = Vec::with_capacity(1 + versions.len() * 2);
    payload.push((versions.len() * 2) as u8);
    for &v in versions {
        put_u16(&mut payload, v);
    }
    write_ext(out, 0x002b, &payload);
}

fn write_ext_key_share(out: &mut Vec<u8>, grease_group: Option<u16>, x25519_pub: &[u8; 32]) {
    let mut entries = Vec::with_capacity(44);
    if let Some(gg) = grease_group {
        put_u16(&mut entries, gg);
        put_u16(&mut entries, 1);
        entries.push(0x00);
    }
    put_u16(&mut entries, 0x001d);
    put_u16(&mut entries, 32);
    entries.extend_from_slice(x25519_pub);

    let mut payload = Vec::with_capacity(2 + entries.len());
    put_u16(&mut payload, entries.len() as u16);
    payload.extend_from_slice(&entries);
    write_ext(out, 0x0033, &payload);
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u24(out: &mut Vec<u8>, v: u32) {
    out.push(((v >> 16) & 0xff) as u8);
    out.push(((v >> 8) & 0xff) as u8);
    out.push((v & 0xff) as u8);
}
