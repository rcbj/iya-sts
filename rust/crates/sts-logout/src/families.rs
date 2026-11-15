// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE FAMILIES (`buildFamilies()`): one entry per kind of live thing this
//! service holds, in the order a person should READ them — the session
//! first, because everything else on the page either hangs off it or was
//! issued by it. A FAMILY IS ONE ROW HERE AND THAT IS THE EXTENSION POINT
//! (`logout/CLAUDE.md`); its `collect` and `terminate` are
//! [`crate::Logout`]'s, by id.
//!
//! **THE READING ORDER AND THE ENDING ORDER ARE NOT THE SAME ORDER.**
//! `end_order` puts the federated lists first, the credentials next, and
//! the SESSION LAST, because the lists the relying parties are told from
//! live on the session; a family without one sorts to the end, beside the
//! sessions — so state it.
//!
//! The prose is Node's, word for word: three surfaces print it.

/// One family's description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Family {
    pub id: &'static str,
    pub end_order: u32,
    /// A row whose session this act ends is ended with it, ticked or not
    /// (#432).
    pub ends_with_session: bool,
    pub label: &'static str,
    pub protocol: &'static str,
    pub spec: &'static str,
    pub what: &'static str,
}

/// The families in the order a person reads them.
pub const FAMILIES: &[Family] = &[
    Family {
        id: "session",
        end_order: 90,
        ends_with_session: false,
        label: "Browser sign-on session",
        protocol: "Authentication service",
        spec: "Not a protocol. The session this service holds and the three \
               browser protocols share.",
        what: "The cookie from /authn/login. OAuth 2.0 / OIDC, \
               WS-Federation, SAML 2.0 and the admin console all read THIS \
               session, which is why signing out of one signs out of all of \
               them — and why a row here takes the three lists below with \
               it.",
    },
    Family {
        id: "oidc-rp",
        end_order: 10,
        ends_with_session: false,
        label: "OpenID Connect relying parties",
        protocol: "OAuth 2.0 / OIDC",
        spec: "OpenID Connect Front-Channel Logout 1.0 and Back-Channel \
               Logout 1.0",
        what: "The clients this session was issued an authorization \
               response for. Ending one sends that relying party a \
               front-channel notification at its registered \
               frontchannel_logout_uri, POSTs a signed Logout Token to its \
               registered backchannel_logout_uri, and forgets it here; the \
               tokens it already holds are a separate row, because a \
               notified relying party that kept a live refresh token is not \
               signed out.",
    },
    Family {
        id: "wsfed-rp",
        end_order: 11,
        ends_with_session: false,
        label: "WS-Federation relying parties",
        protocol: "WS-Federation",
        spec: "WS-Federation 1.2 section 13.2.4",
        what: "The realms this session signed into. Ending one sends that \
               realm a wsignoutcleanup1.0 request — the same one \
               wsignout1.0 sends, built by the same function in wsfed.js — \
               as a one-pixel image, with the URL printed beside it so a \
               failed ping can be seen rather than guessed at.",
    },
    Family {
        id: "saml2-sp",
        end_order: 12,
        ends_with_session: false,
        label: "SAML 2.0 service providers",
        protocol: "SAML 2.0",
        spec: "saml-profiles-2.0-os section 4.4, Single Logout",
        what: "The service providers this session signed into, each with a \
               signed LogoutRequest built for it. They are LINKS and not an \
               automatic fan-out, which is /saml2/slo's own decision \
               reused rather than reconsidered: a WS-Federation cleanup is \
               an idempotent GET that works as an image, and a \
               LogoutRequest is a signed message a service provider \
               ANSWERS. Firing those into hidden frames would claim a \
               federation-wide logout this service cannot observe.",
    },
    Family {
        id: "federation-partner",
        end_order: 13,
        ends_with_session: false,
        label: "Federation partners",
        protocol: "Federation",
        spec: "saml-profiles-2.0-os section 4.4.3; OpenID Connect \
               RP-Initiated Logout 1.0; WS-Federation 1.2 section 13.2.4",
        what: "The foreign identity provider this session was signed in \
               THROUGH. Ending it offers the partner's own sign-out — a \
               signed LogoutRequest, an RP-Initiated Logout redirect with \
               the partner's ID Token as id_token_hint, or wsignout1.0 — \
               as a link or a form on the page, because it is the \
               person's browser that goes there. SAML 1.1 and OAuth 2.0 \
               define no sign-out, so a partner of either is never told.",
    },
    Family {
        id: "oauth-grant",
        end_order: 19,
        ends_with_session: false,
        label: "OAuth grants (Grant Management)",
        protocol: "OAuth 2.0 / OIDC",
        spec: "Grant Management for OAuth 2.0 (the revocation a client's \
               DELETE performs)",
        what: "The grants a client was handed a grant_id for. A grant \
               outlives the tokens issued under it — a client can name it \
               in its next authorization request — so a sign-out that \
               revoked the tokens and left the grant would have left the \
               thing a client renews from. Ending one removes it from the \
               register and revokes every token recorded under it.",
    },
    Family {
        id: "token",
        end_order: 20,
        ends_with_session: false,
        label: "Tokens",
        protocol: "OAuth 2.0 / OIDC",
        spec: "RFC 7009 for the revocation; RFC 9700 section 2.2.2 for why a \
               sign-out is one of the moments to perform it",
        what: "Every access token, refresh token and ID Token this service \
               still holds a record of for this identity and has not \
               already revoked. Ending one adds its jti to the ONE \
               revocation set — the same set /oauth2/revoke and the console \
               write to — so /oauth2/introspect reports it inactive on the \
               next call. A token this registry has forgotten to its cap \
               cannot be listed and is the reason a global logout is not a \
               promise about tokens issued long ago.",
    },
    Family {
        id: "code",
        end_order: 21,
        ends_with_session: false,
        label: "Authorization codes",
        protocol: "OAuth 2.0 / OIDC",
        spec: "RFC 6749 section 4.1.2",
        what: "Codes issued to a client and not yet redeemed. For their \
               five minutes each one is a live credential that mints a \
               whole token set, so a sign-out that revoked the tokens and \
               left these behind would have left the thing that makes more \
               of them. They are shown by a HANDLE and never by their \
               value: a code on a web page is a code in a browser history.",
    },
    Family {
        id: "vci-code",
        end_order: 22,
        ends_with_session: false,
        label: "Credential Offer pre-authorized codes",
        protocol: "OpenID4VCI",
        spec: "OpenID for Verifiable Credential Issuance 1.0 section 4.1.1",
        what: "Pre-authorized codes from a Credential Offer made for this \
               person. Each is redeemable once at the token endpoint for an \
               access token that issues a credential, so it is a live \
               credential in the same sense an authorization code is, and \
               it is shown by a handle for the same reason.",
    },
    Family {
        id: "wallet-signin",
        end_order: 25,
        ends_with_session: false,
        label: "Wallet sign-ins not yet collected",
        protocol: "OpenID4VP",
        spec: "OpenID for Verifiable Presentations 1.0 section 8.2",
        what: "A wallet has presented a credential for this person to sign \
               a browser in, and that browser has not yet come back for \
               the session. Ending it means the browser is told a sign-out \
               withdrew it and nobody is signed in.",
    },
    Family {
        id: "wallet-credential",
        end_order: 26,
        ends_with_session: false,
        label: "Wallet credentials that can sign this person in",
        protocol: "OpenID4VP",
        spec: "draft-ietf-oauth-status-list (the bit a disown sets); \
               W3C Bitstring Status List",
        what: "Verifiable credentials this realm issued for this person, \
               which their wallet can present at /authn/wallet to sign in. \
               Ending one DISOWNS it: every credential issued to that \
               wallet key for this person up to now stops signing anybody \
               in here, and its status list entry is set INVALID so other \
               verifiers can learn it. The credential itself stays in the \
               wallet and still verifies; a credential issued after the \
               sign-out, on a fresh sign-in, signs in again.",
    },
    Family {
        id: "gnap",
        end_order: 27,
        ends_with_session: true,
        label: "GNAP grants",
        protocol: "GNAP",
        spec: "RFC 9635 section 5.4 (the revocation, performed for the \
               person); RFC 9767 for what a resource server sees after",
        what: "Grants this person approved to a GNAP client instance, and \
               the access tokens issued under them. Ending one revokes \
               every token the grant issued and finalizes the grant, as the \
               client's own revocation does: introspection answers \
               inactive from then, a continuation is refused, and CAEP \
               session-revoked names the grant to any receiver that \
               subscribed. A grant approved on a session this sign-out ends \
               ends with it.",
    },
    Family {
        id: "uma",
        end_order: 27,
        ends_with_session: true,
        label: "UMA persisted claims tokens",
        protocol: "UMA 2.0",
        spec: "UMA 2.0 Grant for OAuth 2.0 Authorization, section 3.3.3 \
               (the PCT)",
        what: "Handles a client holds so that the claims gathered about \
               this person need not be gathered again. Ending one makes the \
               client ask for them afresh; the RPTs already issued are \
               access tokens and end with those.",
    },
    Family {
        id: "ldap",
        end_order: 23,
        ends_with_session: false,
        label: "Directory connections",
        protocol: "LDAP",
        spec: "RFC 4511 section 4.2",
        what: "Connections to the embedded directory — 389 and LDAPS 636 \
               alike — bound as this person. A Bind sets the authorization \
               state of a CONNECTION and it lasts until the next Bind or an \
               Unbind, so in LDAP the connection IS the session and closing \
               it is the only sign-out the protocol has. What the client \
               sees is its socket closing mid-conversation. An UNSOLICITED \
               NOTICE OF DISCONNECTION (section 4.4.1) would be the polite \
               form and node-ldapjs has no way to send one — it is a \
               submodule this repository uses unmodified.",
    },
    Family {
        id: "krb5",
        end_order: 24,
        ends_with_session: false,
        label: "Kerberos tickets",
        protocol: "Kerberos v5",
        spec: "None — Kerberos defines no logout, no session and no \
               revocation. KDC_ERR_TGT_REVOKED (20) is a registered code \
               (RFC 4120 section 7.5.9) whose text says what is meant, but \
               the specification defines no mechanism that emits it; this \
               is an invention using it.",
        what: "A ticket-granting ticket is an encrypted blob in somebody's \
               cache and there is no list of them here — there could not be \
               one on a real KDC either, which is deliberate: a KDC keeps \
               no state about the tickets it has issued, and that is what \
               lets one be replicated read-only. A ticket is valid because \
               it decrypts and its endtime has not passed, and a service \
               never contacts the KDC to accept one, so SHORT LIFETIMES are \
               the whole revocation model Kerberos has. What a KDC does see \
               is the next TGS-REQ, so a sign-out records an INSTANT on the \
               principal and a request presenting a ticket authenticated \
               before it is refused KDC_ERR_TGT_REVOKED. IT DOES NOT REACH \
               A SERVICE TICKET ALREADY IN A CACHE: accepting one never \
               contacts this KDC, which is a fact about Kerberos rather \
               than a gap here. A fresh AS-REQ succeeds, because signing \
               out is not being locked out — and its ticket is accepted \
               while every ticket from before the sign-out, renewed or \
               not, stays refused until the latest one could still be \
               valid.",
    },
    Family {
        id: "issued",
        end_order: 99,
        ends_with_session: false,
        label: "Issued, disowned, and beyond recall",
        protocol: "SAML 2.0, SAML 1.1, WS-Trust, WS-Federation, OpenID4VCI, \
                   SPIFFE",
        spec: "Nothing to cite for the recall: no specification here \
               defines a way to take one back. CAEP and SAML Single Logout \
               are what carry the news where a channel exists.",
        what: "Assertions, service tickets, verifiable credentials and \
               X509-SVIDs already issued for this person. Ending one marks \
               it revoked IN THIS SERVICE'S OWN RECORD and reaches nobody: \
               a relying party validates a SAML assertion's signature and \
               its conditions and asks nobody, a Kerberos service decrypts \
               a ticket with its own key, an X509-SVID verifies against a \
               bundle — so the credential goes on working out there until \
               it expires. What the mark buys is that this sign-out can SAY \
               what it disowned, that CAEP carries it to any receiver that \
               subscribed, and that Single Logout carries it for the \
               assertions that came from a browser profile. They are here \
               so that a global logout says both what it reached and what \
               it did not.",
    },
];

/// The families in the order they are ENDED: a stable sort of the reading
/// order by `end_order`.
#[tracing::instrument(level = "trace")]
pub fn in_ending_order() -> Vec<&'static Family> {
    let mut out: Vec<&'static Family> = FAMILIES.iter().collect();
    out.sort_by_key(|f| f.end_order);
    out
}

/// The family of an id.
#[tracing::instrument(level = "trace")]
pub fn by_id(id: &str) -> Option<&'static Family> {
    FAMILIES.iter().find(|f| f.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_ends_after_everything_that_hangs_off_it() {
        let order: Vec<&str> = in_ending_order().iter().map(|f| f.id).collect();
        assert_eq!(order.first(), Some(&"oidc-rp"));
        assert_eq!(order[order.len() - 2], "session");
        assert_eq!(order.last(), Some(&"issued"));
        assert_eq!(FAMILIES[0].id, "session");
        assert_eq!(FAMILIES.len(), 16);
    }
}
