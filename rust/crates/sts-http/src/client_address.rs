// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Whose request this is — a port of `common/client_address.js`: the
//! client's address, whether forwarded headers are believed, and the CDN
//! edge that must carry this deployment's secret (#1336).
//!
//! * `global.trustProxy` off: the socket's peer.
//! * On, with no `global.trustedProxies`: the LEFT-MOST `X-Forwarded-For`
//!   entry in development — the old rule, kept — and the peer in product,
//!   which believes nobody without a list (ASVS 5.0.0 4.1.3, 15.3.4).
//! * On, with ranges, from a peer outside them: the peer.
//! * On, with ranges, from a trusted peer: walking from the RIGHT, the
//!   first entry that is not a trusted proxy.
//!
//! A request from an address in `global.edgeProxies` must carry
//! `X-Origin-Verify` equal to `global.edgeSecret` (or to the secret whose
//! `sha256:<hex>` is configured), compared in constant time; the header is
//! taken off the request either way.
//!
//! **WHAT REPLACED WHAT.** Node parses each range list into a
//! `net.BlockList` cached against the setting's text; here a list is
//! parsed per request, which is a handful of comparisons. The peer is the
//! socket address the listener puts in the request's extensions
//! ([`Peer`]); a request worker's "from the front process" case does not
//! exist in one process.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// The connection's peer, put in a request's extensions by the listener.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub IpAddr);

const EDGE_SECRET_HEADER: &str = "x-origin-verify";

/// `normalise()`: an IPv4-mapped IPv6 address as its IPv4 form.
fn normalise(address: &str) -> String {
    let text = address.trim();
    let lower = text.to_ascii_lowercase();
    if let Some(v4) = lower.strip_prefix("::ffff:") {
        if v4.parse::<std::net::Ipv4Addr>().is_ok() {
            return v4.to_string();
        }
    }
    text.to_string()
}

/// One parsed range.
#[derive(Clone, Copy, Debug)]
struct Range {
    base: IpAddr,
    bits: u32,
}

fn parse_ranges(entries: &[String], setting: &str) -> Vec<Range> {
    let mut out = Vec::new();
    for entry in entries {
        let (address, bits) = match entry.split_once('/') {
            Some((a, b)) => (normalise(a), Some(b)),
            None => (normalise(entry), None),
        };
        let Ok(ip) = address.parse::<IpAddr>() else {
            tracing::warn!(
                "client_address: \"{}\" in {} is not an address or a CIDR \
                 range and is ignored.",
                entry,
                setting
            );
            continue;
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let bits = match bits.map(|b| b.parse::<u32>()) {
            None => max,
            Some(Ok(b)) if b <= max => b,
            _ => {
                tracing::warn!(
                    "client_address: \"{}\" in {} is not an address or a \
                     CIDR range and is ignored.",
                    entry,
                    setting
                );
                continue;
            }
        };
        out.push(Range { base: ip, bits });
    }
    out
}

fn bits_of(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn in_ranges(address: &str, ranges: &[Range]) -> bool {
    let Ok(ip) = normalise(address).parse::<IpAddr>() else {
        return false;
    };
    ranges.iter().any(|r| {
        if r.base.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let width = if ip.is_ipv4() { 32 } else { 128 };
        if r.bits == 0 {
            return true;
        }
        let shift = width - r.bits;
        (bits_of(ip) >> shift) == (bits_of(r.base) >> shift)
    })
}

/// The settings the rules read.
#[derive(Clone, Debug, Default)]
pub struct AddressRules {
    /// `global.trustProxy`.
    pub trust_proxy: bool,
    /// `global.trustedProxies`.
    pub trusted_proxies: Vec<String>,
    /// `mode.requiresTrustedProxyRanges()`.
    pub requires_ranges: bool,
    /// `global.edgeProxies`.
    pub edge_proxies: Vec<String>,
    /// `global.edgeSecret`.
    pub edge_secret: String,
}

fn forwarded_for(headers: &HeaderMap) -> Vec<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(',')
        .map(normalise)
        .filter(|s| !s.is_empty())
        .collect()
}

impl AddressRules {
    /// `peerIsTrustedProxy()`.
    fn peer_is_trusted(&self, peer: &str) -> bool {
        let ranges =
            parse_ranges(&self.trusted_proxies, "global.trustedProxies");
        if self.trusted_proxies.is_empty() {
            return !self.requires_ranges;
        }
        in_ranges(peer, &ranges)
    }

    /// `forwardedBelieved()`: whether `X-Forwarded-*` are believed.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn forwarded_believed(&self, peer: Option<&Peer>) -> bool {
        if !self.trust_proxy {
            return false;
        }
        let peer = peer
            .map(|p| normalise(&p.0.to_string()))
            .unwrap_or_default();
        self.peer_is_trusted(&peer)
    }

    /// `clientAddressOf()`: the address a request came from.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn client_address(
        &self,
        peer: Option<&Peer>,
        headers: &HeaderMap,
    ) -> String {
        let peer = peer
            .map(|p| normalise(&p.0.to_string()))
            .unwrap_or_default();
        let or_unknown = |s: &str| {
            if s.is_empty() {
                "unknown".to_string()
            } else {
                s.to_string()
            }
        };
        let chain = forwarded_for(headers);
        if !self.trust_proxy {
            return or_unknown(&peer);
        }
        if self.trusted_proxies.is_empty() {
            if self.requires_ranges {
                return or_unknown(&peer);
            }
            return chain.first().cloned().unwrap_or_else(|| or_unknown(&peer));
        }
        let ranges =
            parse_ranges(&self.trusted_proxies, "global.trustedProxies");
        if !in_ranges(&peer, &ranges) {
            return or_unknown(&peer);
        }
        for entry in chain.iter().rev() {
            if !in_ranges(entry, &ranges) {
                return entry.clone();
            }
        }
        chain.first().cloned().unwrap_or_else(|| or_unknown(&peer))
    }

    /// `edgeRefused()`: a request from a CDN edge without this
    /// deployment's secret. The secret header is removed either way.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn edge_refused(
        &self,
        peer: Option<&Peer>,
        headers: &mut HeaderMap,
    ) -> bool {
        if self.edge_proxies.is_empty() {
            return false;
        }
        let given = headers
            .get(EDGE_SECRET_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        headers.remove(EDGE_SECRET_HEADER);
        let ranges = parse_ranges(&self.edge_proxies, "global.edgeProxies");
        let peer = peer
            .map(|p| normalise(&p.0.to_string()))
            .unwrap_or_default();
        if !in_ranges(&peer, &ranges) {
            return false;
        }
        let secret = self.edge_secret.as_str();
        if secret.is_empty() || given.is_empty() {
            return true;
        }
        let digest_form = secret.strip_prefix("sha256:").filter(|h| {
            h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
        });
        let held = match digest_form {
            Some(hex) => {
                let mine: String = sts_crypto::jws_alg::Hash::Sha256
                    .digest(given.as_bytes())
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                sts_crypto::secrets::constant_time_equals(
                    mine.as_bytes(),
                    hex.to_ascii_lowercase().as_bytes(),
                )
            }
            None => sts_crypto::secrets::constant_time_equals(
                given.as_bytes(),
                secret.as_bytes(),
            ),
        };
        !held
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn peer(s: &str) -> Peer {
        Peer(s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])))
    }

    #[test]
    fn the_right_most_untrusted_entry_is_the_client() {
        let rules = AddressRules {
            trust_proxy: true,
            trusted_proxies: vec!["10.0.0.0/8".into()],
            ..AddressRules::default()
        };
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 2.2.2.2, 10.1.1.1"),
        );
        assert_eq!(
            rules.client_address(Some(&peer("10.0.0.5")), &h),
            "2.2.2.2"
        );
        assert_eq!(rules.client_address(Some(&peer("8.8.8.8")), &h), "8.8.8.8");
    }

    #[test]
    fn with_no_list_development_believes_the_left_most_entry() {
        let mut rules = AddressRules {
            trust_proxy: true,
            ..AddressRules::default()
        };
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 2.2.2.2"),
        );
        assert_eq!(rules.client_address(Some(&peer("9.9.9.9")), &h), "1.1.1.1");
        rules.requires_ranges = true;
        assert_eq!(rules.client_address(Some(&peer("9.9.9.9")), &h), "9.9.9.9");
    }
}
