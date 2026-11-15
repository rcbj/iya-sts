// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Which hosts a destination may name (`AuditExport.bareHost()`,
//! `isMetadata()`, `isPrivate()`, `ipv4Of()`, `ipv6Bytes()`, `mappedV4()`,
//! `isIp()`, and `OutboundTls.isLoopbackHost()`), read as Node reads them:
//! by text, so a leading zero (`01.2.3.4`) is a number and not octal, and
//! RFC 6598's `100.64.0.0/10` counts as private. Cloud metadata is refused
//! in every mode, including while private destinations are allowed.

/// `bareHost()`: brackets, a zone id and a trailing dot removed, lower
/// case.
#[tracing::instrument(level = "debug")]
pub fn bare_host(host: &str) -> String {
    let mut text = host.trim();
    text = text.strip_prefix('[').unwrap_or(text);
    text = text.strip_suffix(']').unwrap_or(text);
    let text = match text.find('%') {
        Some(cut) => &text[..cut],
        None => text,
    };
    let text = text.strip_suffix('.').unwrap_or(text);
    text.to_lowercase()
}

/// `OutboundTls.isLoopbackHost()`: `localhost`, `127.0.0.0/8`, `::1`.
#[tracing::instrument(level = "debug")]
pub fn is_loopback_host(host: &str) -> bool {
    let mut h = host;
    h = h.strip_prefix('[').unwrap_or(h);
    h = h.strip_suffix(']').unwrap_or(h);
    let h = h.to_lowercase();
    if h == "localhost" || h == "::1" {
        return true;
    }
    let parts: Vec<&str> = h.split('.').collect();
    parts.len() == 4
        && parts[0] == "127"
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
        })
}

/// `ipv4Of()`: four octets of a dotted address, or of an IPv4-mapped
/// literal (`::ffff:a.b.c.d`).
#[tracing::instrument(level = "debug")]
pub fn ipv4_of(host: &str) -> Option<[u16; 4]> {
    let mapped = host.strip_prefix("::ffff:").unwrap_or(host);
    let parts: Vec<&str> = mapped.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u16; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty()
            || part.len() > 3
            || !part.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let n: u16 = part.parse().ok()?;
        if n > 255 {
            return None;
        }
        out[i] = n;
    }
    Some(out)
}

/// `isIp()`: a dotted address, or anything with a colon.
#[tracing::instrument(level = "debug")]
pub fn is_ip(host: &str) -> bool {
    ipv4_of(host).is_some() || host.contains(':')
}

/// `ipv6Bytes()`: the sixteen bytes of an IPv6 literal, or `None`.
#[tracing::instrument(level = "debug")]
pub fn ipv6_bytes(host: &str) -> Option<[u8; 16]> {
    let text = host.split('%').next().unwrap_or("");
    if !text.contains(':') {
        return None;
    }
    let halves: Vec<&str> = text.split("::").collect();
    if halves.len() > 2 {
        return None;
    }
    let parse = |side: &str| -> Option<Vec<u16>> {
        if side.is_empty() {
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        for group in side.split(':') {
            if group.contains('.') {
                let v4 = ipv4_of(group)?;
                out.push((v4[0] << 8) | v4[1]);
                out.push((v4[2] << 8) | v4[3]);
                continue;
            }
            if group.is_empty()
                || group.len() > 4
                || !group.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return None;
            }
            out.push(u16::from_str_radix(group, 16).ok()?);
        }
        Some(out)
    };
    let left = parse(halves[0])?;
    let right = if halves.len() == 2 {
        parse(halves[1])?
    } else {
        Vec::new()
    };
    let missing = 8i64 - left.len() as i64 - right.len() as i64;
    if halves.len() == 1 && missing != 0 {
        return None;
    }
    if halves.len() == 2 && missing < 0 {
        return None;
    }
    let mut groups = left;
    groups.extend(std::iter::repeat_n(0u16, missing.max(0) as usize));
    groups.extend(right);
    if groups.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        bytes[i * 2] = (g >> 8) as u8;
        bytes[i * 2 + 1] = (g & 0xff) as u8;
    }
    Some(bytes)
}

/// `mappedV4()`: the dotted address inside `::ffff:a.b.c.d`, or `''`.
fn mapped_v4(bytes: &[u8; 16]) -> String {
    let prefix = bytes[..10].iter().all(|b| *b == 0)
        && bytes[10] == 0xff
        && bytes[11] == 0xff;
    if !prefix {
        return String::new();
    }
    bytes[12..]
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// `isMetadata()`: a cloud metadata name or `169.254.169.254`.
#[tracing::instrument(level = "debug")]
pub fn is_metadata(host: &str) -> bool {
    let name = bare_host(host);
    for one in [
        "metadata.google.internal",
        "metadata.azure.com",
        "instance-data",
        "instance-data.ec2.internal",
    ] {
        if name == one || name.ends_with(&format!(".{}", one)) {
            return true;
        }
    }
    ipv4_of(&name) == Some([169, 254, 169, 254])
}

/// `isPrivate()`: loopback, link-local, private, carrier-grade NAT or
/// unspecified; a name that is not an address is not.
#[tracing::instrument(level = "debug")]
pub fn is_private(host: &str) -> bool {
    let name = bare_host(host);
    if let Some(v4) = ipv4_of(&name) {
        let (a, b) = (v4[0], v4[1]);
        return a == 0
            || a == 10
            || a == 127
            || (a == 169 && b == 254)
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 100 && (64..=127).contains(&b));
    }
    if !name.contains(':') {
        return false;
    }
    let Some(bytes) = ipv6_bytes(&name) else {
        return false;
    };
    let mapped = mapped_v4(&bytes);
    if !mapped.is_empty() {
        return is_private(&mapped);
    }
    let all_zero = bytes.iter().all(|b| *b == 0);
    let looped =
        !all_zero && bytes[15] == 1 && bytes[..15].iter().all(|b| *b == 0);
    let ula = (bytes[0] & 0xfe) == 0xfc;
    let link = bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
    all_zero || looped || ula || link
}
