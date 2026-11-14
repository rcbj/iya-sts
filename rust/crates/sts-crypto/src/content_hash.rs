// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Digests that are not a signature's: the ones an HTTP layer computes
//! over a body it sends.
//!
//! **SHA-1 HERE IS AN IDENTIFIER, NEVER A SECURITY CONTROL.** Express
//! names every body it sends with a weak `ETag` built from the SHA-1 of
//! the bytes (the `etag` package, `W/"<length>-<base64 of SHA-1>"`), and a
//! browser revalidates a cached copy by sending that name back. Nothing
//! is signed with it and nothing is trusted because of it; a collision
//! costs a cache a stale copy. It is here rather than in `sts-http`
//! because every digest this service computes is this crate's (the root
//! `CLAUDE.md`'s crypto rule, held by `sts-guards`).

/// The SHA-1 of `data` (`crypto.createHash('sha1')` as the `etag`
/// package calls it).
#[tracing::instrument(level = "trace", skip_all)]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    openssl::sha::sha1(data)
}

#[cfg(test)]
mod tests {
    use super::sha1;

    #[test]
    fn sha1_of_the_empty_string_is_the_well_known_one() {
        let hex: String =
            sha1(b"").iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }
}
