// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT THE SIGN-OUT READS AND ENDS, EACH A TRAIT: `logout.ts`'s
//! `LogoutDeps`, one trait per module it reads (rule 3m — every row is read
//! live from the module that OWNS that thing, and every termination is a
//! call into that same module), named and shaped as Node's calls are, so
//! the vectors (`tests/tools/logout-vectors.js`) answer each port from
//! what Node's answered and the Rust test checks the same calls were made
//! in the same order with the same arguments.
//!
//! WHO FILLS EACH PORT, and what answers it until then
//! ([`crate::wiring`] is the runtime's answer):
//!
//! | Port | Node module | In Rust |
//! |---|---|---|
//! | [`AuthnPort`] | `authn/authn.ts` | `sts-authn`'s `Sessions` ([`crate::wiring::SessionsPort`]) |
//! | [`StatsPort`] | `common/admin_stats.js` | `sts-oauth`'s token register for the tokens; the artifact register is the identity register's slice |
//! | [`FrontChannelPort`] | `oauth-oidc/frontchannel_logout.ts` | the OAuth slice (part two) |
//! | [`BackchannelPort`] | `oauth-oidc/backchannel_logout.ts` | the OAuth slice (part two) |
//! | [`WsFedPort`] | `ws-federation/wsfed.ts` | the WS-Federation phase |
//! | [`Saml2Port`] | `saml/saml2_sso.ts` | the SAML phase |
//! | [`FederationSloPort`] | `federation/federation_slo.ts` | the federation phase |
//! | [`OAuth2Port`] | `oauth-oidc/oauth2.ts` (codes, the issuer) | the OAuth slice |
//! | [`Oid4vcPort`] | `oid4vc/vc_offers.ts`, `vc_verifier.ts`, `vc_issued.ts` | phase 9 |
//! | [`Krb5Port`] | `kerberos/krb5_principals.js` | the Kerberos phase |
//! | [`LdapPort`] | `ldap/ldap_server.js` (the connection mirror) | the LDAP wire's phase |
//! | [`GnapPort`] | `gnap/gnap_revocation.ts` | the GNAP phase |
//! | [`GrantsPort`] | `oauth-oidc/grant_management.ts` | the OAuth slice |
//! | [`UmaPort`] | `uma/uma_store.ts` (required lazily) | the UMA phase |
//! | [`HostPort`] | `config`, `mode`, `audit`, the directory's subject resolver, `cluster_secrets`, `cell_sessions`, `provider_commands` | `sts-core`, the runtime |
//!
//! Every argument and answer is Node's JSON where Node's is JSON. A
//! request is [`Asked`] and a response [`Reply`]: what the doors read of
//! express's `req` and write on its `res`.

use serde_json::{Map, Value};

/// What a sign-out door reads of the request (express's `req`).
#[derive(Debug, Clone, Default)]
pub struct Asked {
    /// The session core's view of the request: the cookie, the address,
    /// the account set's marks (#561).
    pub request: sts_authn::ports::Request,
    /// `req.query`, as express parsed it.
    pub query: Map<String, Value>,
    /// The headers, by lower-cased name.
    pub headers: Vec<(String, String)>,
    /// `baseUrlOf(req)`: the public base and the ambient realm's prefix.
    pub base: String,
    /// `cors.ownOrigins(req)`: the origins this service answers on.
    pub own_origins: Vec<String>,
}

impl Asked {
    /// `req.headers[name]`, or ''.
    // A hot path: a handful of reads per request; no span.
    pub fn header(&self, name: &str) -> String {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    /// `String(req.query[name] || '')`.
    // A hot path: a handful of reads per request; no span.
    pub fn query_text(&self, name: &str) -> String {
        sts_authn::js::or_empty(self.query.get(name))
    }
}

/// What a sign-out door writes on the response (express's `res`): the
/// cookies, appended in order, and any header (`Clear-Site-Data`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reply {
    pub cookies: Vec<String>,
    pub headers: Vec<(String, String)>,
}

/// `authn/authn.ts`: the sign-on session, which this module never touches
/// itself — every end goes through `endSessionById()`.
pub trait AuthnPort: Send + Sync {
    /// `sessionWindowOn()`.
    fn session_window_on(&self) -> bool;
    /// `sessionsHeldUnder(username, subject)`: `None` is an unread page.
    fn sessions_held_under(
        &self,
        username: &str,
        subject: &str,
    ) -> Option<Vec<Value>>;
    /// `sessionsMatching(() => true)`: every session; `None` is unread.
    fn sessions_matching(&self) -> Option<Vec<Value>>;
    /// `sessionById(id)`.
    fn session_by_id(&self, id: &str) -> Option<Value>;
    /// `sessionView(session)`: the `Session` concept (#1579).
    fn session_view(&self, session: &Value) -> Value;
    /// `sessionStartedAt(session)`: the FIRST authentication, epoch ms.
    fn session_started_at(&self, session: &Value) -> f64;
    /// `endSessionById(id, via, initiatingEntity)`: whether one ended.
    fn end_session_by_id(&self, id: &str, via: &str, entity: &str) -> bool;
    /// `noteSessionChanged(session)`: the row written back as given.
    fn note_session_changed(&self, session: &Value);
    /// `multipleAccounts()` (#561).
    fn multiple_accounts(&self) -> bool;
    /// `hintAccountKey(req, key)`.
    fn hint_account_key(&self, asked: &Asked, key: &str);
    /// `hintAccount(req, hint)`.
    fn hint_account(&self, asked: &Asked, hint: &Value);
    /// `sessionOf(req)`.
    fn session_of(&self, asked: &Asked) -> Option<Value>;
    /// `signedInAccounts(req)`: `{ key, sub, username, displayName,
    /// current, sid }` per account.
    fn signed_in_accounts(&self, asked: &Asked) -> Vec<Value>;
    /// `afterAccountSignOut(req, res)`.
    fn after_account_sign_out(&self, asked: &Asked, reply: &mut Reply);
    /// `clearSessionCookie(res)`.
    fn clear_session_cookie(&self, reply: &mut Reply);
    /// `clearSiteDataAfterSignOut(req, res)`.
    fn clear_site_data_after_sign_out(&self, asked: &Asked, reply: &mut Reply);
    /// The arrival session `/logout` is a front door for (`ARRIVAL_PATHS`,
    /// minted by Node's middleware before the route runs): minted for a
    /// browser with no `sts_session`, slid for one with a live arrival.
    /// Not a call of `logout.ts`'s, so the vectors do not see it.
    fn arrival(&self, asked: &Asked, reply: &mut Reply);
    /// `beginAuthentication(opts)`: where the browser goes to sign in.
    fn begin_authentication(
        &self,
        opts: &Value,
        asked: Option<&Asked>,
    ) -> String;
    /// `lastAuthenticatedAt(session)`: epoch SECONDS, 0 for none.
    fn last_authenticated_at(&self, session: &Value) -> f64;
    /// `sessionNamesFactor(session, factor)` (#722).
    fn session_names_factor(&self, session: &Value, factor: &Value) -> bool;
}

/// `common/admin_stats.js`: the identity keys, and the token and artifact
/// register with its ONE revocation set.
pub trait StatsPort: Send + Sync {
    /// `holderKeyOf(username, sub)`, each as Node passed it (a member that
    /// may be missing is null).
    fn holder_key_of(&self, username: &Value, sub: &Value) -> String;
    /// `identityKeyOf(name)`.
    fn identity_key_of(&self, name: &str) -> String;
    /// `holdingsOf(keys)`: key -> `{ tokens, artifacts }`.
    fn holdings_of(&self, keys: &[String]) -> Map<String, Value>;
    /// `revoke(jti, why, opts)`: true the first time.
    fn revoke(&self, jti: &str, why: &str, opts: &Value) -> bool;
    /// `artifactByKey(key)`.
    fn artifact_by_key(&self, key: &str) -> Option<Value>;
    /// `revokeArtifact(record, why)`: true the first time.
    fn revoke_artifact(&self, record: &Value, why: &str) -> bool;
}

/// `oauth-oidc/frontchannel_logout.ts`.
pub trait FrontChannelPort: Send + Sync {
    /// `clientsOf(session)`: the relying parties on the session.
    fn clients_of(&self, session: &Value) -> Vec<Value>;
    /// `notificationsFor(session, issuer)`: `{ clientId, url, uri,
    /// sessionRequired, why }` per relying party.
    fn notifications_for(&self, session: &Value, issuer: &str) -> Vec<Value>;
    /// `render(notifications)`: the iframes and their table.
    fn render(&self, notifications: &[Value]) -> String;
    /// `frameOriginsOf(notifications)`.
    fn frame_origins_of(&self, notifications: &[Value]) -> Vec<String>;
}

/// `oauth-oidc/backchannel_logout.ts` (3aq). A Logout Token for a session
/// that ENDS is sent by the session's end (`dropSession()`); only a
/// relying party forgotten on a session that stays is planned here.
pub trait BackchannelPort: Send + Sync {
    /// `mark()`: where the delivery register stands.
    fn mark(&self) -> Value;
    /// `plan(session, { via, clients, issuer, trigger })`: the deliveries.
    fn plan(&self, session: &Value, opts: &Value) -> Vec<Value>;
    /// `dispatch(planned)`.
    fn dispatch(&self, planned: &[Value]);
    /// `deliveriesFor(sessionIds, mark)`.
    fn deliveries_for(
        &self,
        session_ids: &[String],
        mark: &Value,
    ) -> Vec<Value>;
    /// `summarize(rows)`: a sentence, or ''.
    fn summarize(&self, rows: &[Value]) -> String;
    /// `render(rows)`: the deliveries' table, or ''.
    fn render(&self, rows: &[Value]) -> String;
}

/// `ws-federation/wsfed.ts`.
pub trait WsFedPort: Send + Sync {
    /// `cleanupTargetsFor(session)`: `{ realm, url }` per address.
    fn cleanup_targets_for(&self, session: &Value) -> Vec<Value>;
}

/// `saml/saml2_sso.ts`.
pub trait Saml2Port: Send + Sync {
    /// `logoutTargetsFor(session)`: `{ entityId, url, from }` per SP.
    fn logout_targets_for(&self, session: &Value) -> Vec<Value>;
}

/// `federation/federation_slo.ts` (#167).
pub trait FederationSloPort: Send + Sync {
    /// `canTellPartner(held)`: `{ ok, why }`.
    fn can_tell_partner(&self, held: &Value) -> Value;
    /// `partnerLogoutFor(session, base)`: `{ ok, why, target }`.
    fn partner_logout_for(&self, session: &Value, base: &str) -> Value;
    /// `renderPartnerLogouts(targets)`.
    fn render_partner_logouts(&self, targets: &[Value]) -> String;
}

/// `oauth-oidc/oauth2.ts`: the authorization codes and the issuer.
pub trait OAuth2Port: Send + Sync {
    /// `outstandingCodesFor(key)`: `{ code, clientId, redirectUri, scope,
    /// issuedAt, expiresAt, sessionId }` per code.
    fn outstanding_codes_for(&self, key: &str) -> Vec<Value>;
    /// `dropCode(code)`.
    fn drop_code(&self, code: &str);
    /// `issuerOf(base)`.
    fn issuer_of(&self, base: &str) -> String;
}

/// `oid4vc/`: the pre-authorized codes, the wallet sign-ins awaiting their
/// browser, and the wallet sign-in register.
pub trait Oid4vcPort: Send + Sync {
    /// `vcOffers.preAuthorizedCodes.forEachDigest()`, as the list of
    /// `[digest, record]` it walks.
    fn pre_authorized_codes(&self) -> Vec<(String, Value)>;
    /// `vcOffers.preAuthorizedCodes.deleteDigest(digest)`.
    fn delete_pre_authorized_code(&self, digest: &str);
    /// `vcVerifier.signInsAwaitingCollection()`.
    fn sign_ins_awaiting_collection(&self) -> Vec<Value>;
    /// `vcVerifier.withdrawSignIn(state, why)`.
    fn withdraw_sign_in(&self, state: &str, why: &str) -> bool;
    /// `vcIssued.rowsForSubject(subject)`.
    fn rows_for_subject(&self, subject: &str) -> Vec<Value>;
    /// `vcIssued.disown(key, why)`.
    fn disown(&self, key: &str, why: &str) -> bool;
}

/// `kerberos/krb5_principals.js`: the sign-out instant (`kerberos/
/// CLAUDE.md`).
pub trait Krb5Port: Send + Sync {
    /// `REALM`: the ambient realm's Kerberos realm name.
    fn realm(&self) -> String;
    /// `kerberosRealmOf()`: `{ enabled, … }`.
    fn kerberos_realm_of(&self) -> Value;
    /// `signedOutAt(names, realm)`: an ISO instant, or null.
    fn signed_out_at(&self, names: &[String], realm: &str) -> Value;
    /// `find(names, realm)`: the principal, or null.
    fn find(&self, names: &[String], realm: &str) -> Value;
    /// `signOut(names, realm)`: `{ name, realm, signedOutAt }`, or null.
    fn sign_out(&self, names: &[String], realm: &str) -> Value;
}

/// `ldap/ldap_server.js`: the bound connections, which may be another
/// node's (#46).
pub trait LdapPort: Send + Sync {
    /// `boundConnections()`.
    fn bound_connections(&self) -> Vec<Value>;
    /// `dropConnectionsFor(key)`: the connections closed or instructed.
    fn drop_connections_for(&self, key: &str) -> Vec<Value>;
    /// `signOutAcrossCluster(key)`: `{ at }`, or null.
    fn sign_out_across_cluster(&self, key: &str) -> Value;
}

/// `gnap/gnap_revocation.ts` (#432).
pub trait GnapPort: Send + Sync {
    /// `grantsByKey(keys)`: key -> grants.
    fn grants_by_key(&self, keys: &[String]) -> Map<String, Value>;
    /// `isLive(grant)`.
    fn is_live(&self, grant: &Value) -> bool;
    /// `grantsHeldBy(key)`: the live grants.
    fn grants_held_by(&self, key: &str) -> Vec<Value>;
    /// `liveTokensOf(grant)`.
    fn live_tokens_of(&self, grant: &Value) -> Vec<Value>;
    /// `endGrant(grant, opts)`.
    fn end_grant(&self, grant: &Value, opts: &Value) -> bool;
}

/// `oauth-oidc/grant_management.ts` (#142).
pub trait GrantsPort: Send + Sync {
    /// `list()`: every grant in the register.
    fn list(&self) -> Vec<Value>;
    /// `revoke(grantId, key, by, initiatingEntity)`: `{ ok, clientId,
    /// revoked }`.
    fn revoke(
        &self,
        grant_id: &str,
        key: &str,
        by: &str,
        entity: &str,
    ) -> Value;
}

/// `uma/uma_store.ts` (#1168), which Node requires lazily.
pub trait UmaPort: Send + Sync {
    /// `pctsOf(subject)`.
    fn pcts_of(&self, subject: &str) -> Vec<Value>;
    /// `deletePct(key, true)`.
    fn delete_pct(&self, key: &str) -> bool;
}

/// Everything else `logout.ts` asks: the settings, the mode, the audit
/// log, the directory's subject resolver, the cluster secret a sealed
/// result is MACed under, the cells, the OpenID Provider Commands, the
/// origins this service answers on, and the clock.
pub trait HostPort: Send + Sync {
    /// `config.value(key)`, in the ambient realm.
    fn setting(&self, key: &str) -> Value;
    /// `mode.opensTestControls()`.
    fn opens_test_controls(&self) -> bool;
    /// `mode.verifiesCredentials()`.
    fn verifies_credentials(&self) -> bool;
    /// `audit.audit(row)`.
    fn audit(&self, row: &Value);
    /// `audit.failure(code, row)`.
    fn audit_failure(&self, code: &str, row: &Value);
    /// `helpers.subjectForName(name)`.
    fn subject_for_name(&self, name: &str) -> String;
    /// `helpers.nameForSubject(subject)`.
    fn name_for_subject(&self, subject: &str) -> String;
    /// `clusterSecrets.get('logout-result')`, as bytes.
    fn result_secret(&self) -> Vec<u8>;
    /// `cell_sessions.subjectTerminated(realmId, key)` (#98 D6).
    fn subject_terminated(&self, realm: &str, key: &str);
    /// `provider_commands.personSignedOut(key)`, where loaded (#151).
    fn person_signed_out(&self, key: &str);
    /// `realms.currentId()`.
    fn realm_id(&self) -> String;
    /// `realms.currentPrefix()`.
    fn realm_prefix(&self) -> String;
    /// `Date.now()`.
    fn now_ms(&self) -> f64;
}
