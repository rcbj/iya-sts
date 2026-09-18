// @ts-check
'use strict';
//
// File: oauth2_bcp.js
//
// ===========================================================================
// RFC 9700 — OAuth 2.0 Security Best Current Practice — AS A MODE.
//
// In development mode this service is a mock: it checks no end user's
// password, and with this mode off it accepts any client secret (product mode
// is a different axis — `common/mode.js`). None of that changes here. What
// this file adds is
// the OTHER half of what a client author needs — a server that refuses exactly
// what RFC 9700 says a conforming authorization server must refuse, so that the
// client's error paths can be exercised against something that behaves like the
// real deployment it will meet in production.
//
// It is a MODE rather than a rewrite, and the contract is worth stating in one
// sentence because everything below depends on it:
//
//   * `oauth2.rfc9700` OFF (the default) — every endpoint behaves EXACTLY as it
//     did before this file existed. Not "almost"; nothing in here runs.
//   * `oauth2.rfc9700` ON — every requirement in REQUIREMENTS below whose
//     `enforced` is 'yes' or 'detected' is enforced, and the metadata documents
//     stop advertising what the mode would refuse.
//
// ---------------------------------------------------------------------------
// WHY IT IS A FLAG AT ALL, given that RFC 9700 is a list of MUSTs.
//
// Because a client is exercised by BOTH answers. A wallet or a debugger that
// only ever meets a permissive server has never run its "the authorization
// server refused my redirect_uri" path, and one that only ever meets a strict
// server cannot reproduce the loose behaviour it is trying to detect. The
// existing callers of this service are the second kind: the debugger's own
// default flow uses an unregistered redirect_uri, no PKCE and — in one pane —
// the implicit grant, all of which RFC 9700 refuses. Turning that on
// unconditionally would not make those callers compliant, it would make them
// stop working with no explanation at the point of use.
//
// So the flag defaults OFF and every refusal it introduces names RFC 9700 and
// the section, because a 400 that says only "invalid_request" is the reason a
// person goes looking at their own code for a decision this server made.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3 in CLAUDE.md).
//
// It registers no route, so its position in the require order does not
// matter, and it requires only libraries — `common/` modules, `client_auth.js`,
// `oauth21.js`, `sender_constraints.js` and `cluster/`'s claims — none of
// which requires it back, so it cannot join a cycle (each require below says
// why). `oauth2.js` requires IT — never the other way round — which is what
// keeps this file free of the authorization server's state: the
// registered-client record and the authorization code record are PASSED IN.
// There is deliberately no second copy of `registeredClients` here (the
// one-store rule that keeps WS-Federation out of a session store of its own).
//
// ---------------------------------------------------------------------------
// THE SPLIT WITH `oauth2.js`, which is the same split `authn.js` has.
//
// This module decides YES or NO and says why. It never touches `res`. What a
// refusal LOOKS like is OAuth's business and stays in `oauth2.js`: a bad
// redirect_uri is answered on this server (400) because redirecting an error to
// an unvalidated URI is the open redirector RFC 9700 section 2.1 forbids, while
// everything else is reported to the client at a redirect_uri that has already
// been validated. Getting that order wrong is not a style question — it is the
// difference between a compliant server and an open redirector with a
// compliance flag.
//
// ---------------------------------------------------------------------------
// THE REQUIREMENT THAT IS NOT A CHECK: TLS ON THE CONNECTION ITSELF.
//
// "Authorization responses MUST NOT be sent over unencrypted connections"
// (section 2.1) has two halves. The half about the REDIRECT TARGET is a check
// like the others: an `http` redirect_uri is refused unless it is a native
// application's loopback address, which is section 2.6's exception.
//
// The half about the connection the authorization request arrived on cannot be
// a check, because by the time any code here runs the request has already
// arrived over whatever it arrived over — refusing it would tell a client its
// request was insecure using the same insecure channel. It is a property of the
// SOCKET, so it is settled where the socket is bound: `global.https` — whose
// default is this mode's own flag — makes the main port an HTTPS listener
// carrying the same certificate LDAPS 636 already serves, and
// then there is no unencrypted connection for an authorization response to be
// sent over. That is also why `oauth2.rfc9700` is restart-only: a bound socket
// is decided before the service is listening.
//
// So that row in the table reports the DEPLOYMENT rather than a decision made
// per request, and it reports it either way — `deployment` when this port is
// TLS and `no` with the reason when somebody has turned `global.https` off to
// run the checks over plain http. That case is deliberately reachable: a client
// that cannot be taught to trust a certificate regenerated on every start
// should still be able to exercise everything else in here. What it must not be
// is quiet. A compliance mode that let a requirement go unenforced without
// saying so would be the most misleading thing in this repository.
//
// ---------------------------------------------------------------------------
// WHAT THIS DOES NOT COVER — stated so the flag is not read as "RFC 9700
// compliant" full stop.
//
// The whole of the BCP's section 2 is here except for the items below. Section
// 2.1 (redirect-based flows), 2.1.1 (the authorization code grant), 2.1.2 (the
// implicit grant), 2.2/2.2.1 (token replay prevention), 2.2.2 (refresh tokens),
// 2.3 (access token privilege restriction), 2.4 (the password grant), 2.5
// (client authentication) and 2.6 (the other recommendations) all have rows in
// the table, including the ones this server already satisfied.
//
// NOT here: Pushed Authorization Requests (RFC 9126, `par.js`, 2026-09-13) and
// Resource Indicators (RFC 8707), which are FEATURES in every mode rather than
// constraints this mode enforces — `resource` is read for every grant and the
// protected endpoints refuse a token addressed elsewhere in both modes
// (oauth-oidc/CLAUDE.md 3f and 3ah). Client authentication at
// `/oauth2/introspect` is not this mode's either: an RFC 9701 JWT request
// authenticates in every mode and a JSON one in product mode (3ai).
// `/oauth2/revoke` authenticates nobody. And the requirements RFC 9700 places
// on the CLIENT stay the client's — this service can detect several of them
// and fix none.
// ===========================================================================

const crypto = require('crypto');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and error_codes.js and nothing else here, so it cannot join a
// cycle, and it registers no route, so its position is not a position at all.
const realms = require('../common/realms');
const { log } = require('../common/helpers');
const config = require('../common/config');
// applications.js registers no route and requires nothing from oauth-oidc/, so
// this closes no cycle and moves nothing in the router. It is here for the
// three per-client settings this file resolves — the refresh idle window, the
// refresh lifetime a revoked family is remembered for, and revoke-on-logout.
const applications = require('../common/applications');
// HOW a client proves who it is — all six methods, verified. A library like
// this one: it registers nothing and requires `common/` libraries, mtls.js and
// the two assertion-grant libraries, none of which requires this file, so
// requiring it here cannot create a cycle. The split is the usual
// one — that file is the protocol and this file is the policy: it says whether
// what arrived PROVES the client, and this says whether the client had to prove
// anything. A LIBRARY REQUIRING A LIBRARY, which is why this is a plain require
// and not one of admin_stats.js's inverted slots (rule 3e's test).
const clientAuth = require('./client_auth');
// OAUTH 2.1 MODE, which IMPLIES this one (2026-09-13). A LEAF requiring only
// helpers.js and config.js, so this require closes no cycle — and it is here
// for the two places this mode has to step aside for a client that follows
// OAuth 2.1 to the letter (the token request's redirect_uri, and the fallback
// to oauth2.redirectUris), plus the refusals 2.1 adds at the checks already
// in this file. `oauth-oidc/CLAUDE.md` rule 3ah.
const oauth21 = require('./oauth21');
// PRODUCT MODE IMPLIES THIS MODE (2026-09-17) — `enabled()` below. A leaf
// beneath `config`: `mode.js` requires config and bunyan and nothing else, so
// this require closes no cycle and moves no route.
const mode = require('../common/mode');
// THE FIVE SETTINGS THAT ASK FOR MORE THAN EITHER SPECIFICATION DOES (#34,
// 2026-09-15). A leaf requiring helpers.js, config.js and oauth21.js, so this
// closes no cycle — and it must never require this file back, because
// `dpop.js` requires it too and `dpop.js` is below this one. It is here for
// ONE question: whether refresh tokens rotate, which is no longer the same
// question as whether this mode is on.
const senderConstraints = require('./sender_constraints');
// The redirect allowlist's one question this file needs answered — is a URI a
// native app's private-use one. validation.js requires config.js, zod and
// error_codes.js and nothing here, so this closes no cycle.
const validation = require('../common/validation');
// SEVERAL NODES AGAINST ONE STORE (2026-09-14, #46): the atomic "once" a
// rotated refresh token is redeemed through, and the capability table this
// file declares `oauth.refresh-rotation` in. Both are libraries; the claims
// module requires `config`, `realms`, `error_codes` and the table, and
// `persistence.js` only LAZILY, so `dpop.js` — which requires this file —
// stays out of any cycle. `error_codes.js` is a leaf.
const clusterClaims = require('../cluster/cluster_claims');
const capabilities = require('../cluster/cluster_capabilities');
const errorCodes = require('../common/error_codes');

// ---------------------------------------------------------------------------
// THE TABLE.
//
// One row per normative statement this mode has an opinion about, and it is the
// single source for three things: the checks below cite an id from it, the
// `GET /oauth2/rfc9700` view is built from it, and the coverage note on
// /admin/sts-metadata was written from it. A requirement that is not in here is
// not enforced, which is exactly what a reader wants to be able to establish.
//
// `enforced` is one of:
//   'yes'      — this server refuses the request when the mode is on
//   'detected' — this server cannot MAKE the client comply, but it can see a
//                violation and refuse it; the requirement is the client's
//   'deployment' — true because of how this service is LISTENING rather than
//                because of a check: nothing per-request could establish it.
//   'no'       — not enforced, and `note` says why. There is one row that can
//                report this, and only when somebody has turned `global.https`
//                off; its reasoning is in the header above.
//   'always'   — true whether the mode is on or off, because it was already
//                true before this file existed. These are the rows that say
//                what the service already did, and they are here so that
//                nobody has to read the code to find out.
//
// Most rows are cited by `requirement:` on the refusal they produce. Five are
// not, and that is right rather than an omission — a requirement met by DOING
// something has no refusal to hang a citation on. `redirect-no-patterns` is a
// property of the comparison (there is no pattern syntax to refuse WITH),
// `redirect-loopback-port` is an ACCEPTANCE and never refuses anything,
// `prefer-code` is what is left once `no-implicit` has refused the rest,
// `refresh-rotation` is an action taken after a successful refresh, and
// `no-cors-at-authorize` is a header withheld. Do not invent a check to give
// one of them a citation.
// ---------------------------------------------------------------------------
const REQUIREMENTS = [
  // --- section 2.1 — redirect URIs ----------------------------------------
  { id: 'redirect-exact-match', section: '2.1, 4.1.3', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Compare redirect_uri to the registered URIs by exact string match',
    note: 'Simple string comparison per RFC 3986 section 6.2.1 — no ' +
          'normalisation, no trailing-slash forgiveness, no case folding of ' +
          'the path. The registered set is the client\'s own redirect_uris ' +
          'when it registered any (RFC 7591), and the oauth2.redirectUris ' +
          'setting otherwise.' },

  { id: 'redirect-no-patterns', section: '2.1', level: 'MUST NOT',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'No wildcard, prefix or pattern matching of redirect URIs',
    note: 'There is no pattern syntax in the comparison at all, which is the ' +
          'only way to be sure of this one: a matcher that supports patterns ' +
          'and is configured not to use them is one configuration mistake ' +
          'away from an open redirector.' },

  { id: 'redirect-loopback-port', section: '2.1, 4.1.3', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Allow a variable port on a native application\'s loopback ' +
           'redirect URI',
    note: 'RFC 8252 section 7.3: a native app cannot reserve a port, so the ' +
          'port is the one component that may differ. Everything else — ' +
          'scheme, host, path, query, fragment — must still match exactly, ' +
          'and the host must be the same loopback literal. Turning ' +
          'oauth2.loopbackPortWildcard off makes this server NON-compliant ' +
          'on purpose, so that a native-app client can be shown failing ' +
          'against a server that got this wrong.' },

  { id: 'no-open-redirector', section: '2.1', level: 'MUST NOT',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Do not forward the browser to an arbitrary URI',
    note: 'An authorization error is reported to the redirect_uri only AFTER ' +
          'that URI has been matched against the registered set; otherwise ' +
          'it is reported here, as a 400. The end_session_endpoint\'s ' +
          'post_logout_redirect_uri is matched the same way — without the ' +
          'mode it is an open redirector, which is what /oauth2/logout has ' +
          'always been and now says.' },

  // --- section 4.11.2 — the authorization server as an open redirector -----
  { id: 'no-redirect-invalid-combination', section: '4.11.2', level: 'MUST NOT',
    appliesTo: 'authorization server', enforced: 'yes',
    title:
      'Do not redirect for an invalid client_id / redirect_uri combination',
    note: 'RFC 6749 section 4.1.2.1, which 4.11.2 cites. A request naming NO ' +
          'client_id has no client the redirect_uri could belong to, and ' +
          'this service used to report that BY REDIRECTING to the URI — the ' +
          'one thing that paragraph forbids. It is answered here now, as a ' +
          '400, above the point where any error could be redirected. An ' +
          'unknown-but-present client_id is deliberately not refused: this ' +
          'service issues to any client_id that asks, and the COMBINATION is ' +
          'what redirect-exact-match checks — a registered client against ' +
          'its own URIs and an unregistered one against the configured list.' },

  { id: 'authenticate-before-redirect', section: '4.11.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Authenticate the user before redirecting them',
    note: 'THE PART THAT SURVIVES EVEN WHEN EVERY REDIRECT URI IS ' +
          'REGISTERED, which is why it is a separate row from the ' +
          'exact-match one. An attacker sends a victim to a legitimate ' +
          'client\'s authorization request with something wrong in it and ' +
          'the authorization server bounces them to that client\'s ' +
          'registered redirect_uri carrying attacker-chosen state — nobody ' +
          'signed in, nobody clicked, and the hop through a trusted server ' +
          'is the whole value of it. So an error is automatically redirected ' +
          'only when there is a SESSION; otherwise the person is shown the ' +
          'client, the destination and the error, and follows a link if they ' +
          'choose to, which is the same section\'s "inform the user and rely ' +
          'on the user to make the correct decision". TWO EXCEPTIONS, both ' +
          'from the specification rather than convenience: prompt=none, ' +
          'which the section names — silent authentication exists to be ' +
          'answered with no interaction and login_required is the answer it ' +
          'exists to produce — and a refusal coming back from the sign-in ' +
          'screen, where the person is present and has just decided. A ' +
          'SUCCESS is never affected: reaching one means a session exists, ' +
          'which means the user was authenticated first.' },

  { id: 'redirect-only-to-trusted', section: '4.11.2', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Automatically redirect only to a trusted redirect URI',
    note: 'The trust signal here is REGISTRATION, and it is the only one ' +
          'this service has: a URI on the client\'s own entry or in the ' +
          'oauth2.redirectUris setting is one somebody put there, and ' +
          'anything else is refused before there is an error to report ' +
          '(redirect-exact-match). What the BCP suggests beyond that — URI ' +
          'analytics, reputation of the content behind the URI — is not ' +
          'something a mock can do or should pretend to: a service that ' +
          'claimed to have judged the credibility of a destination would be ' +
          'teaching a client author that somebody had.' },

  { id: 'client-not-an-open-redirector', section: '4.11.1', level: 'MUST NOT',
    appliesTo: 'client', enforced: 'no',
    title: 'A client must not expose an open redirector either',
    note: 'NOT THIS SERVICE\'S TO DO. A client\'s redirect endpoint that ' +
          'forwards onward to a URL from its own `state` is the mirror of ' +
          'the attack the row above closes, and it is on the other side of ' +
          'the redirect. It is in this table because a requirement left out ' +
          'of a compliance report reads as one that was met. What this ' +
          'service can do is the half it owns: it will not forward a browser ' +
          'to a URI nobody registered, and it will not forward one at all ' +
          'before somebody has signed in.' },

  // One of the two rows whose answer is not a constant (`tls-everywhere` is
  // the other): it describes the socket this service is listening on, which is
  // settled at startup rather than per request. Both fields are functions for
  // that reason, and `state()` calls them — keeping the table the single
  // source rather than moving half of this row's meaning into the view that
  // renders it.
  { id: 'response-over-tls', section: '2.1', level: 'MUST NOT',
    appliesTo: 'authorization server',
    enforced: function () {
      log.debug("Entering enforced().");
      log.debug("Leaving enforced().");
      return mainPortIsTls() ? 'deployment' : 'no';
    },
    title: 'Do not send an authorization response over an unencrypted ' +
           'connection',
    note: function () {
      log.debug("Entering response-over-tls.note().");
      if (mainPortIsTls()) {
        log.debug("Leaving response-over-tls.note().");
        return 'The redirect TARGET must not be http off the loopback (see ' +
               'http-scheme-refused), ' +
               'and the connection the response goes out over is TLS: ' +
               'global.https is on, so the main port is an HTTPS listener ' +
               'serving the same self-signed certificate LDAPS 636 uses — ' +
               'one pair per start, so a caller trusts this ' +
               'service once. It is not a check and could not be one: a ' +
               'request has already arrived by the time any code here runs, ' +
               'so this is settled by the socket rather than decided per ' +
               'request.';
      }
      log.debug("Leaving response-over-tls.note().");
      return 'HALF ENFORCED, and the half that is not has been turned off ' +
             'deliberately: the redirect TARGET must not be http off the ' +
             'loopback (see http-scheme-refused), but global.https is off, ' +
             'so ' +
             '/oauth2/authorize is reachable over plain http and an ' +
             'authorization response goes back over an unencrypted ' +
             'connection. That is a reachable case on purpose — a client ' +
             'that cannot be taught to trust a certificate regenerated on ' +
             'every start should still be able to exercise the rest of this ' +
             'mode — and turning global.https on (which is what ' +
             'oauth2.rfc9700 does by default) is what closes it.';
    } },

  // --- section 2.6 — TLS, and what a reverse proxy changes -----------------
  { id: 'tls-everywhere', section: '2.6', level: 'MUST',
    appliesTo: 'authorization server and client',
    enforced: function () {
      log.debug("Entering enforced().");
      log.debug("Leaving enforced().");
      return mainPortIsTls() ? 'deployment' : 'no';
    },
    title: 'Use TLS for OAuth communications, end to end',
    enforcedNote: true,
    note: function () {
      log.debug("Entering tls-everywhere.note().");
      if (mainPortIsTls()) {
        log.debug("Leaving tls-everywhere.note().");
        return 'global.https is on, so every endpoint here — the ' +
               'authorization endpoint, the token endpoint, both discovery ' +
               'documents, and the resource server at /oauth2/userinfo and ' +
               'the three credential endpoints — is on one TLS listener. END ' +
               'TO END is then true of everything inside this process; what ' +
               'it cannot be true of is a hop this service cannot see, which ' +
               'is the reverse-proxy case below.';
      }
      log.debug("Leaving tls-everywhere.note().");
      return 'NOT ENFORCED: global.https is off, so this service answers ' +
             'OAuth over plain HTTP. That is the default because it is a ' +
             'mock reached from a browser on a laptop and a self-signed ' +
             'certificate regenerated every start is a real cost to pay ' +
             'before anything works. Turn global.https on — which RFC 9700 ' +
             'mode does by default — and every endpoint moves to TLS ' +
             'together, on the certificate LDAPS 636 already serves.';
    } },

  { id: 'proxy-headers-not-trusted', section: '2.6', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Do not believe a forwarded header unless a proxy really set it',
    note: 'The application\'s half of section 2.6\'s reverse-proxy ' +
          'paragraph. X-Forwarded-Proto and X-Forwarded-Host decide what ' +
          'this service thinks its own issuer, endpoints and DPoP `htu` are ' +
          '— and with nothing in front of it they are ordinary request ' +
          'headers any client can set. So they are believed only when ' +
          'global.trustProxy says a proxy is there, which is OFF by default. ' +
          'That is a CHANGE: dpop.js used to honour them unconditionally ' +
          'while baseUrlOf() ignored them, so two functions in one service ' +
          'disagreed about whether a forwarded header was believable — and ' +
          'the htu one had teeth, because a client that chooses the expected ' +
          'htu can replay a proof captured at another endpoint by naming it. ' +
          'GET /tls/forwarded shows what a request carried and what was ' +
          'believed of it.' },

  { id: 'no-certificate-header', section: '2.6', level: 'MUST NOT',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Never read a client certificate out of a header',
    note: 'A proxy that terminates mTLS forwards the certificate in a header ' +
          '— X-Client-Cert, X-Forwarded-Client-Cert, X-SSL-Client-Cert and a ' +
          'dozen vendor spellings — and an application that believed one ' +
          'would accept a certificate anybody can forge, since a header ' +
          'costs nothing to write. THIS SERVICE READS NONE OF THEM, in ' +
          'either mode: RFC 8705 binding and mTLS client authentication both ' +
          'read the certificate off the TLS handshake itself. The cost is ' +
          'real and is stated rather than hidden — a proxy terminating mTLS ' +
          'in front of this service cannot pass the certificate through — ' +
          'and /tls/forwarded lists the ones a request carried so that ' +
          'ignoring them is visible rather than silent.' },

  { id: 'proxy-sanitizes-headers', section: '2.6', level: 'MUST',
    appliesTo: 'reverse proxy', enforced: 'no',
    title: 'A reverse proxy strips inbound security-sensitive headers before ' +
           'forwarding',
    note: 'NOT THIS SERVICE\'S TO DO, and it is in the table for the reason ' +
          'the two client-side nonce rows are: a requirement left out of a ' +
          'compliance report reads as one that was met. A proxy that sets ' +
          'X-Forwarded-Proto without first REMOVING the one the client sent ' +
          'lets any client reach past it. What this service can do about it ' +
          'is not believe those headers unless told to ' +
          '(proxy-headers-not-trusted) and show what arrived ' +
          '(/tls/forwarded); it cannot make the hop in front of it behave. ' +
          'The same is true of protecting the proxy-to-application ' +
          'connection against eavesdropping, injection and replay — that is ' +
          'a deployment decision about a link this process has no view of.' },

  { id: 'http-scheme-refused', section: '2.6', level: 'MUST NOT',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Do not allow an http redirect URI except for a native-app ' +
           'loopback redirect',
    note: 'https everywhere else — or a native application\'s PRIVATE-USE ' +
          'scheme (RFC 8252 section 7.1, com.example.app:/cb), which this ' +
          'endpoint accepts in every mode since 2026-09-13 and matches by ' +
          'exact string like any other registered URI. A scheme with no ' +
          'period in it is refused in every mode (common/validation.js ' +
          'redirectUriProblem()): it is not named for a domain, and it is ' +
          'what localhost:3000/cb typed without http:// parses as. Until ' +
          'that date this note said a private-use scheme was refused whether ' +
          'the mode was on or off, which was a limitation of the mock rather ' +
          'than a position on the specification.' },

  // --- section 2.1.1 — the authorization code grant -----------------------
  { id: 'pkce-public-clients', section: '2.1.1', level: 'MUST',
    appliesTo: 'client (enforced by this server)', enforced: 'yes',
    title: 'A public client must use PKCE',
    note: 'A client is taken to be CONFIDENTIAL only when it registered here ' +
          'with a token_endpoint_auth_method other than "none" — RFC 7591 ' +
          'section 2 makes client_secret_basic the default, so a ' +
          'registration that omits the member is confidential. Everything ' +
          'else, including every client_id this service has never seen ' +
          'registered, is treated as public and must send a code_challenge.' },

  { id: 'pkce-confidential-clients', section: '2.1.1', level: 'SHOULD',
    appliesTo: 'client (observed by this server)', enforced: 'detected',
    title: 'A confidential client should use PKCE',
    note: 'A SHOULD is not refused: a registered confidential client that ' +
          'omits code_challenge is answered, and the omission is logged and ' +
          'counted. Refusing it would make this server stricter than the ' +
          'specification, which is its own kind of wrong for a mock a client ' +
          'is calibrated against.' },

  { id: 'pkce-s256', section: '2.1.1', level: 'SHOULD',
    appliesTo: 'client (enforced by this server)', enforced: 'yes',
    title: 'Use a code challenge method that does not expose the verifier — ' +
           'S256',
    note: 'code_challenge_method=plain is refused and the metadata stops ' +
          'advertising it, because the two have to agree: advertising a ' +
          'method that would be refused is the drift the discovery documents ' +
          'exist to prevent. S256 challenges are also checked to be 43 ' +
          'characters of base64url, which is what SHA-256 produces and ' +
          'nothing else does.' },

  { id: 'pkce-supported', section: '2.1.1', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Support PKCE',
    note: 'Both methods have been verified at the token endpoint since long ' +
          'before this mode existed. The mode narrows what is ACCEPTED; it ' +
          'does not add the support.' },

  { id: 'pkce-enforce-verifier', section: '2.1.1', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Enforce code_verifier when a code_challenge was supplied',
    note: 'Also independent of the mode: a code minted with a challenge ' +
          'cannot be redeemed without a verifier that hashes to it, and ' +
          'never could be here.' },

  { id: 'pkce-downgrade', section: '2.1.1, 4.8.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Prevent PKCE downgrade — reject a code_verifier when no ' +
           'code_challenge was sent',
    note: 'Without the mode a stray code_verifier is ignored, which is how ' +
          'the downgrade works: an attacker who strips code_challenge from ' +
          'the authorization request can then supply any verifier at the ' +
          'token endpoint and be told nothing is wrong.' },

  { id: 'pkce-detect-support', section: '2.1.1', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Give clients a way to detect PKCE support',
    note: 'code_challenge_methods_supported is in both discovery documents, ' +
          'mode or no mode. What the mode changes is its CONTENT: S256 ' +
          'alone, since plain would be refused.' },

  { id: 'pkce-advertise-methods', section: '2.1.1', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Advertise code_challenge_methods_supported in Authorization ' +
           'Server Metadata',
    note: 'RFC 8414 and the OpenID Provider Configuration are one document ' +
          'extended here, so both carry it and cannot disagree.' },

  { id: 'transaction-specific', section: '2.1.1', level: 'MUST',
    appliesTo: 'client (detected by this server)', enforced: 'detected',
    title: 'code_challenge and nonce must be transaction-specific',
    note: 'A real authorization server cannot generally tell a reused ' +
          'challenge from a fresh one. This one can, because it is a mock ' +
          'and remembers: a code_challenge or nonce presented again AFTER ' +
          'the code issued for its earlier presentation was redeemed is a ' +
          'second transaction reusing a first transaction\'s value, and is ' +
          'refused. Presenting it again BEFORE that — a reloaded browser ' +
          'tab, a retried request — is the same transaction and is allowed, ' +
          'which is the distinction a bare "seen before" check gets wrong.' },

  { id: 'transaction-bound', section: '2.1.1', level: 'MUST',
    appliesTo: 'client and authorization server', enforced: 'yes',
    title: 'PKCE and nonce values must be bound to the client and the ' +
           'user-agent transaction',
    note: 'The server half was already true: the challenge, the nonce and ' +
          'the browser session are all carried ON the authorization code ' +
          'rather than in anything the client sends back. The mode adds the ' +
          'two checks RFC 6749 section 4.1.3 asks for and this service did ' +
          'not make — that the redeeming client is the client the code was ' +
          'issued to, and that the redirect_uri is present and identical at ' +
          'the token endpoint — plus a refusal when one client presents a ' +
          'value another client is using.' },

  { id: 'nonce-required', section: '2.1.1, 4.5.3.2', level: 'MUST',
    appliesTo: 'client (enforced by this server)', enforced: 'yes',
    title: 'An OIDC response carrying an id_token must carry a nonce',
    note: 'OpenID Connect Core requires it for the implicit and hybrid flows ' +
          'already. In this mode it is required whenever the response_type ' +
          'names id_token, since the nonce is what makes code injection ' +
          'detectable for a client that has no PKCE.' },

  // --- section 2.1.2 — the implicit grant ---------------------------------
  { id: 'no-implicit', section: '2.1.2', level: 'SHOULD NOT',
    appliesTo: 'client (enforced by this server)', enforced: 'yes',
    title: 'Do not use the implicit grant or any response type issuing an ' +
           'access token',
    note: 'response_type values naming `token` — token, code token, id_token ' +
          'token, code id_token token — are refused with ' +
          'unsupported_response_type, and the metadata stops advertising ' +
          'them and drops the implicit grant type. `id_token` and `code ' +
          'id_token` remain: they issue no access token from the ' +
          'authorization endpoint, which is the property section 2.1.2 is ' +
          'about.' },

  { id: 'prefer-code', section: '2.1.2', level: 'SHOULD',
    appliesTo: 'client', enforced: 'yes',
    title: 'Use response_type=code',
    note: 'What is left once the token-bearing response types are gone. The ' +
          'consequence is worth seeing rather than reading: with the mode ' +
          'on, the debugger\'s implicit pane gets a protocol error instead ' +
          'of an access token in a fragment.' },

  // --- section 2.2 / 2.2.1 — token replay prevention -----------------------
  { id: 'sender-constrained-tokens', section: '2.2, 2.2.1', level: 'SHOULD',
    appliesTo: 'authorization server and resource server',
    // #34 (2026-09-15): 'detected' until an operator asks for more. The
    // section is a SHOULD and this mode does not turn the settings on, so a
    // reader of this report sees the difference between "observed" and
    // "required" rather than one word covering both.
    enforced: function () {
      log.debug("Entering the sender-constrained-tokens enforcement report.");
      const required = !!config.value('oauth2.accessTokenRequireDpop') ||
                       !!config.value('oauth2.accessTokenRequireMtls');
      log.debug("Leaving the sender-constrained-tokens enforcement report.");
      return required ? 'yes' : 'detected';
    },
    title: 'Sender-constrain access tokens (mTLS or DPoP)',
    note: 'BOTH mechanisms the section names are implemented — DPoP (RFC ' +
          '9449) in full, and RFC 8705 certificate-bound tokens (see ' +
          'mtls-bound-tokens) — and both are advertised. Whether a token is ' +
          'BOUND is the CLIENT\'s decision by default, because it binds by ' +
          'sending a proof or by making the connection with a certificate, ' +
          'so this is observed and logged rather than refused: every token ' +
          'issued without either gets a line saying a bearer token went out. ' +
          '**SINCE 2026-09-15 (#34) AN OPERATOR MAY REQUIRE IT**, with ' +
          'oauth2.accessTokenRequireDpop or oauth2.accessTokenRequireMtls — ' +
          'off unless set, and not turned on by this mode, because the ' +
          'section is a SHOULD and this service exists to exercise Bearer ' +
          'clients too. With one on, every surface that accepts a presented ' +
          'access token refuses one that is not constrained, the management ' +
          'API and the embedded debugger included. The refusal is at the ' +
          'RESOURCE: the token endpoint goes on issuing bearer tokens, which ' +
          'is what lets a client be tested against being refused.' },

  { id: 'mtls-bound-tokens', section: '2.2, 2.2.1', level: 'SHOULD',
    appliesTo: 'authorization server',
    enforced: function () {
      log.debug("Entering enforced().");
      log.debug("Leaving enforced().");
      return mainPortIsTls() ? 'yes' : 'no';
    },
    title: 'Offer certificate-bound access tokens (RFC 8705)',
    note: function () {
      log.debug("Entering mtls-bound-tokens.note().");
      if (mainPortIsTls()) {
        log.debug("Leaving mtls-bound-tokens.note().");
        return 'The main listener ASKS for a client certificate and never ' +
               'requires one, so a Token Request made with one is answered ' +
               'with a token carrying cnf["x5t#S256"] — the SHA-256 of the ' +
               'certificate\'s DER — and the four protected endpoints check ' +
               'it. The refresh token is bound too, or the long-lived half ' +
               'of the grant would stay a bearer credential that mints bound ' +
               'tokens for whoever holds it. An UNVERIFIED certificate still ' +
               'binds: RFC 8705 section 3 binds to the certificate, and ' +
               'explicitly permits a self-signed one — the proof is that the ' +
               'same key completed the handshake, not that a CA vouched for ' +
               'it. What is NOT here is section 2, mutual-TLS client ' +
               'AUTHENTICATION, where the certificate replaces the secret.';
      }
      log.debug("Leaving mtls-bound-tokens.note().");
      return 'NOT AVAILABLE in this deployment, and it is a property of the ' +
             'listener rather than a decision: the token endpoint is on the ' +
             'main port, that port is plain HTTP (global.https is off), and ' +
             'there is no TLS handshake to read a client certificate from. ' +
             'The metadata does not advertise ' +
             'tls_client_certificate_bound_access_tokens either, because a ' +
             'client reads that as a promise. Turn global.https on — which ' +
             'RFC 9700 mode does by default — and this becomes yes. DPoP is ' +
             'unaffected and works on either listener.';
    } },

  { id: 'proof-of-possession-validated', section: '2.2', level: 'MUST',
    appliesTo: 'resource server', enforced: 'always',
    title: 'The resource server validates the proof of possession',
    note: 'At `presentedAccessToken()` in dpop.js, which is the SINGLE check ' +
          '/oauth2/userinfo and the three credential endpoints share — a ' +
          'second one beside it would be a fourth caller nobody updated. A ' +
          'DPoP-bound token gets all twelve section 4.3 proof checks and the ' +
          'jkt compared against the token\'s cnf; a certificate-bound one ' +
          'gets the connection\'s certificate thumbprinted again and ' +
          'compared. A bound token presented as a plain Bearer is refused ' +
          'rather than accepted, which is the single most likely way to ' +
          'implement DPoP and gain nothing from it. True with the mode off.' },

  { id: 'proof-replay-prevented', section: '2.2', level: 'MUST',
    appliesTo: 'resource server', enforced: 'always',
    title: 'The resource server prevents replay of the proof',
    note: 'RFC 9449 section 11.1: every proof\'s `jti` is remembered for the ' +
          'window a proof is accepted in, and a repeat is refused — so a ' +
          'proof captured off the wire cannot be used a second time even ' +
          'within its own freshness window. Turning on the server-supplied ' +
          'nonce (/dpop/nonce-mode) narrows that window to one this server ' +
          'chose. A certificate binding needs no replay defence of its own: ' +
          'the proof is the TLS handshake, which cannot be replayed without ' +
          'the private key.' },

  // --- section 2.2.2 — refresh tokens --------------------------------------
  { id: 'refresh-rotation', section: '2.2.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Refresh tokens for public clients must be sender-constrained or ' +
           'rotated',
    note: 'ROTATION, for every client rather than only public ones — this ' +
          'server cannot authenticate a client it did not register, so ' +
          '"public" is the safe reading of an unknown one. Redeeming a ' +
          'refresh token REVOKES it, through the same set /oauth2/revoke ' +
          'writes to, so the retired token also reports inactive at ' +
          '/oauth2/introspect. **ROTATION IS NO LONGER THIS MODE\'S ALONE ' +
          '(#34, 2026-09-15)**: oauth2.refreshTokenRotation does the same ' +
          'thing with both modes off, and the replay detection beside it ' +
          'comes with it, because rotation without replay detection is ' +
          'bookkeeping nobody reads. What stays behind the mode is the rest ' +
          'of what this row\'s neighbours check — the idle timeout, the ' +
          'client binding, the scope narrowing. With neither the mode nor ' +
          'that setting, a refresh token is reusable until it expires — ' +
          'twenty-four hours later on the default oauth2.refreshTokenTtlS, ' +
          'and for as long as that setting says — which is the state this ' +
          'requirement exists about. The section\'s OTHER answer, a ' +
          'sender-constrained refresh token, is what ' +
          'oauth2.refreshTokenRequireDpop and oauth2.refreshTokenRequireMtls ' +
          'require; neither is on unless an operator says so, and neither ' +
          'specification asks for them.' },

  { id: 'refresh-replay-family', section: '2.2.2, 4.14.2', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Detect refresh token replay and revoke the whole chain',
    note: 'A rotated-away refresh token presented again means the chain has ' +
          'been copied — and nothing here can tell whether the legitimate ' +
          'client or the attacker is the one holding it, which is exactly ' +
          'why the answer is to invalidate BOTH. Every refresh token ' +
          'descended from the same original grant is revoked, and the ' +
          'refusal says how many and why. Two things are deliberate: the ' +
          'family is remembered by ISSUANCE, so a chain twenty refreshes ' +
          'long is still one family; and the access tokens already minted ' +
          'from it are left alone, because they expire in an hour and ' +
          'revoking them would hide which credential the client actually ' +
          'lost.' },

  { id: 'refresh-risk-assessment', section: '2.2.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Assess the risk before issuing a refresh token',
    note: 'A PROCESS REQUIREMENT, so what it can honestly mean in code is a ' +
          'policy written down rather than a check. The policy: a refresh ' +
          'token is issued only where a grant has an END-USER behind it, ' +
          'which is why client_credentials sets withRefresh false (RFC 6749 ' +
          'section 4.4.3 says it SHOULD NOT get one — there is no resource ' +
          'owner to be absent, so the long-lived credential buys nothing a ' +
          'fresh client_credentials call would not), and why the ' +
          'authorization endpoint\'s implicit responses have never carried ' +
          'one. Every refresh token that IS issued is rotated, bound to its ' +
          'client, bound to its scope and resource servers, and expires on ' +
          'inactivity — which is the assessment this deployment made.' },

  { id: 'refresh-not-guessable', section: '2.2.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'A refresh token must not be guessable, forgeable or modifiable',
    note: 'Every refresh token here is an RS256 JWT signed with this ' +
          'service\'s key and carrying a `jti` of 16 random bytes from ' +
          'crypto.randomBytes — so guessing one is guessing 128 bits, and ' +
          'forging or modifying one means signing with a key that is ' +
          'generated per start and never leaves the process. The refresh ' +
          'grant VERIFIES that signature before it reads a single claim, ' +
          'which is what makes the client binding, the scope and the ' +
          'resource list on it worth anything at all. True with the mode ' +
          'off; it is a property of how the token is built rather than a ' +
          'policy.' },

  { id: 'refresh-protected-in-transit', section: '2.2.2', level: 'MUST',
    appliesTo: 'authorization server and client',
    enforced: function () {
      log.debug("Entering enforced().");
      log.debug("Leaving enforced().");
      return mainPortIsTls() ? 'deployment' : 'no';
    },
    title: 'Protect refresh tokens in transit and in storage',
    note: function () {
      log.debug("Entering note().");
      log.debug("Leaving note().");
      return (mainPortIsTls()
        ? 'IN TRANSIT: global.https is on, so a refresh token is only ever ' +
          'handed over and presented on a TLS connection. '
        : 'IN TRANSIT: NOT protected — global.https is off, so a refresh ' +
          'token crosses a plain HTTP connection to reach its client and ' +
          'again on every refresh. Turn that on, which RFC 9700 mode does by ' +
          'default. ') +
        'IN STORAGE: there is none to protect. This service keeps no copy of ' +
        'a refresh token — it is a signed JWT verified on presentation, so ' +
        'what is held here is the revocation set (jtis, not tokens) and the ' +
        'console\'s registry of what was issued. The client\'s storage is ' +
        'the client\'s problem and no server can do anything about it, which ' +
        'is why sender-constraining exists.';
    } },

  { id: 'refresh-bound-to-scope-and-resources', section: '2.2.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A refresh token is bound to the authorized scope and resource ' +
           'servers',
    note: 'The scope was on the token from the beginning and a refresh may ' +
          'narrow it and never widen it (scope-not-widened). THE RESOURCE ' +
          'SERVERS WERE NOT, and their absence was a hole rather than an ' +
          'omission: an access token narrowed to one resource server with ' +
          'RFC 8707 could be REFRESHED into one carrying this service\'s ' +
          'default audience, which is wider than what was authorized — a ' +
          'grant widening itself by being renewed. The refresh token now ' +
          'carries `resources`, the refreshed access token takes its ' +
          'audience from them, and a refresh asking for one the grant does ' +
          'not carry is refused with invalid_target. A NARROWED refresh ' +
          'narrows the ACCESS token only: the rotated refresh token carries ' +
          'the scope and resources of the one presented (RFC 6749 section 6, ' +
          'in both modes since 2026-09-13), so narrowing once does not ' +
          'shrink the grant for good. Without the mode a refresh may still ' +
          'WIDEN the access token\'s scope — the check that refuses it is ' +
          'this mode\'s.' },

  { id: 'refresh-idle-timeout', section: '2.2.2', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A refresh token expires after a period of client inactivity',
    note: 'Measured from the last time any token in the CHAIN was redeemed, ' +
          'not from issuance — so a client that refreshes regularly keeps ' +
          'its grant indefinitely and one that stops is cut off, which is ' +
          'the difference between an idle timeout and the absolute expiry ' +
          'the token already carries. The window is ' +
          'oauth2.refreshIdleSeconds because the section says the period is ' +
          'deployment-dependent; 0 turns it off without touching the rest of ' +
          'the mode. It REFUSES rather than revoking the family: an idle ' +
          'chain is a client that went away, not a chain that was copied, ' +
          'and treating the two alike would make the replay refusal — which ' +
          'says something serious — indistinguishable from an afternoon off.' },

  { id: 'refresh-revoked-on-logout', section: '2.2.2', level: 'MAY',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Revoke refresh tokens after a security event, such as a sign-out',
    note: 'Ending a browser sign-on session revokes every refresh token ' +
          'issued ON it, through the same set /oauth2/revoke writes to, so ' +
          'introspection reports them inactive at once. It matters more than ' +
          'a MAY suggests: without it, signing out drops a cookie and leaves ' +
          'a THIRTY-DAY credential in the client\'s hands, and a person who ' +
          'signed out of a shared browser has every reason to believe ' +
          'otherwise. Done at authn.js\'s endSession(), which is the single ' +
          'place /oauth2/logout and WS-Federation\'s wsignout1.0 both end a ' +
          'session — a revocation at each would be two that could come to ' +
          'disagree. ACCESS tokens are deliberately left alone: they expire ' +
          'in an hour, and revoking them would take away the evidence of ' +
          'what the session did. A password change is the section\'s other ' +
          'example and this service has no password to change.' },

  { id: 'refresh-client-binding', section: '2.2.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A refresh token may only be used by the client it was issued to',
    note: 'RFC 6749 section 6 makes client_id REQUIRED on a refresh request ' +
          'from a public client and requires the authorization server to ' +
          'check it. This service read the client_id off the TOKEN and never ' +
          'compared it with the one presenting it, so any client could ' +
          'redeem any refresh token it got hold of.' },

  // --- section 2.3 — access token privilege restriction --------------------
  { id: 'scope-not-widened', section: '2.3', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A refresh must not grant a scope that was never authorized',
    note: 'RFC 6749 section 6: the requested scope must not include any ' +
          'scope the original grant did not carry. Without the mode this ' +
          'server took the scope off the refresh REQUEST verbatim, so a ' +
          'client could ask for `openid admin` on a token granted `openid` ' +
          'and be given it — privilege escalation by typing, which is the ' +
          'opposite of section 2.3\'s "restricted to the minimum required".' },

  { id: 'audience-restricted', section: '2.3', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Audience-restrict access tokens to a specific resource server',
    note: 'Every access token carries `aud`, and always did — but until ' +
          'Resource Indicators (RFC 8707) were implemented it was always the ' +
          'SAME audience, <base>/resource, which is a restriction that is ' +
          'true and buys nothing: one audience that never varies restricts a ' +
          'token to everything this service protects. A client can now name ' +
          'the resource server it wants with `resource`, at the ' +
          'authorization endpoint and again at the token endpoint, and the ' +
          'token names that instead. Repeating it asks for the "small set" ' +
          'this section allows where one is impractical. It is a FEATURE ' +
          'rather than a mode behaviour: a request that sends no `resource` ' +
          'is unaffected in either mode.' },

  { id: 'audience-rejected-by-rs', section: '2.3', level: 'MUST',
    appliesTo: 'resource server', enforced: 'always',
    title: 'A resource server refuses a token issued for another audience',
    note: 'Checked at the same single point the proof-of-possession is, so ' +
          'all four protected endpoints get it. Two things about HOW are ' +
          'deliberate. It applies only to a token this service ISSUED — the ' +
          '`aud` of a token signed by somebody else is a string this service ' +
          'cannot check and was never the audience of anyway, the same ' +
          'judgement made about a foreign cnf. And what counts as "this ' +
          'resource server" is the PATH rather than the whole URL: every ' +
          'token minted here carries <base>/resource where the base is ' +
          'whatever URL the minting request arrived on, so a whole-URL ' +
          'comparison would refuse a token minted at localhost and presented ' +
          'at 127.0.0.1 — while what the check is FOR, a token narrowed to ' +
          'somebody else by `resource`, always has a different path.' },

  { id: 'least-privilege-scope', section: '2.3', level: 'SHOULD',
    appliesTo: 'authorization server and client', enforced: 'detected',
    title: 'Restrict token privileges to the minimum, by scope and ' +
           'authorization_details',
    note: 'The parts this server can ENFORCE are enforced and have rows of ' +
          'their own: a refresh may not widen a scope (scope-not-widened), ' +
          'and the audience is restrictable to one resource server or a ' +
          'small set (audience-restricted). What is left is which scopes a ' +
          'client asks for, which is the client\'s decision — and this ' +
          'service deliberately grants a scope it does not advertise rather ' +
          'than refusing it, because half its callers are testing what an ' +
          'unknown scope does. A scope outside scopes_supported is LOGGED as ' +
          'the least-privilege observation it is. RFC 9396 ' +
          'authorization_details is the finer-grained mechanism the section ' +
          'points at and is implemented for OID4VCI, where a wallet names ' +
          'the credential and even the subset of claims it wants.' },

  // --- section 2.4 — the password grant ------------------------------------
  { id: 'no-ropc', section: '2.4', level: 'MUST NOT',
    appliesTo: 'authorization server and client', enforced: 'yes',
    title: 'The resource owner password credentials grant must not be used',
    note: 'grant_type=password is refused with unsupported_grant_type and ' +
          'drops out of grant_types_supported in both discovery documents. ' +
          'It is the one grant RFC 9700 rules out outright: it hands the ' +
          'user\'s password to the client, it cannot carry a second factor — ' +
          'no WebAuthn, no step-up, nothing a browser does — and there is no ' +
          'way to make it safe. POST /oauth2/register also REFUSES a client ' +
          'that asks to be registered for it (invalid_client_metadata), ' +
          'because a registration recording a grant the token endpoint will ' +
          'always refuse is the discovery document\'s promise broken in the ' +
          'other direction. This service still offers the grant by default, ' +
          'because a client with code for it needs somewhere to run that ' +
          'code — and that is the whole reason the refusal is a mode rather ' +
          'than a deletion.' },

  // --- section 2.5 — client authentication ---------------------------------
  { id: 'client-authentication', section: '2.5', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Authenticate confidential clients where credentials can be issued',
    note: 'THE ONE PLACE THIS SERVICE CHECKS A CREDENTIAL, and only where it ' +
          'can: section 2.5 conditions the requirement on a process for ' +
          'issuing them existing (see client-credential-issuance). So a ' +
          'client whose entry says it is confidential — a ' +
          'token_endpoint_auth_method other than "none", which RFC 7591 ' +
          'section 2 makes the default for a registration that omits it — ' +
          'must authenticate, by whichever of the SIX methods its entry ' +
          'declares, and all six are genuinely verified. A client with no ' +
          'credential on its entry to check against is left alone rather ' +
          'than refused: there is nothing to compare, and inventing a ' +
          'refusal would be theatre. So is a client_id this service has ' +
          'never seen. Note what none of it extends to: no password of any ' +
          'END USER is checked here, in this mode or any other.' },

  { id: 'client-secret-brute-force', section: '2.5', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'A client secret that is checked is not checked unthrottled',
    note: 'OAuth 2.1 section 2.4.1 says it outright and this mode is where a ' +
          'secret starts being checked, so it is reported here too. Since ' +
          '2026-09-13, wherever the token endpoint REFUSES a client secret ' +
          '(this mode, OAuth 2.1 mode, product mode) the failure is counted ' +
          'per realm, per client_id AND client address together — so nobody ' +
          'elsewhere can lock a client out — and past ' +
          'security.rateLimitPerIdentity failures in ' +
          'security.rateLimitWindowS the request is answered 429 with ' +
          'Retry-After before the secret is looked at. A success is never ' +
          'counted.' },

  { id: 'client-credential-issuance', section: '2.5', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Have a process for issuing client credentials',
    note: 'POST /oauth2/register (RFC 7591) is it, and it is what makes the ' +
          'requirement above applicable at all — section 2.5 asks for ' +
          'authentication where issuing credentials is FEASIBLE, and a ' +
          'server with no way to issue them has a defensible answer. A ' +
          'registration mints a client_secret; a client that would rather be ' +
          'asymmetric registers `jwks` instead, or has a certificate subject ' +
          'DN or thumbprint put on its entry. The credentials live on that ' +
          'entry in the directory, which is the one store (see ' +
          '/admin/applications) — and `jwks_uri` is RECORDED AND NEVER ' +
          'FOLLOWED, because fetching a URL somebody registered in order to ' +
          'verify a credential is a server-side request forgery with a ' +
          'specification citation attached. True with the mode off, since ' +
          'the endpoint is always there.' },

  { id: 'asymmetric-client-auth', section: '2.5', level: 'RECOMMENDED',
    appliesTo: 'client (observed by this server)', enforced: 'detected',
    title: 'Prefer asymmetric client authentication',
    note: 'ALL THREE ASYMMETRIC METHODS ARE VERIFIED — private_key_jwt ' +
          'against the client\'s registered jwks (full RFC 7523 section 3: ' +
          'signature, iss and sub both the client, audience, expiry, and a ' +
          'jti remembered until the assertion expires so a replay is ' +
          'refused), and RFC 8705 section 2\'s tls_client_auth and ' +
          'self_signed_tls_client_auth against the certificate the ' +
          'connection was made with. An assertion nominating an HMAC alg for ' +
          'private_key_jwt is refused rather than verified with the public ' +
          'key as a secret, which is the classic JWT forgery and one anybody ' +
          'can perform. This used to say the assertion was ACCEPTED AND NOT ' +
          'VERIFIED, which was worse than not offering the method: a client ' +
          'author came away believing a check had happened. What is still ' +
          'only DETECTED is the preference itself — a client that ' +
          'authenticates with a shared secret is answered and logged as the ' +
          'RECOMMENDED it did not follow, because a SHOULD refused is a ' +
          'server stricter than its specification.' },

  // --- section 2.6 — the other recommendations -----------------------------
  { id: 'no-cors-at-authorize', section: '2.6', level: 'MUST NOT',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'CORS must not be supported at the authorization endpoint',
    note: 'This service sends CORS headers to the origins it calls its ' +
          'own and to those an application lists in appCorsOrigin, which ' +
          'is right for the token, userinfo and metadata endpoints an ' +
          'in-browser client fetches and wrong at the authorization ' +
          'endpoint, which a browser NAVIGATES to. In this mode the headers ' +
          'are withheld from /oauth2/authorize for every origin. ' +
          'Nothing legitimate breaks: a navigation is not a cross-origin ' +
          'fetch and never carried them.' },

  { id: 'publish-as-metadata', section: '2.6', level: 'RECOMMENDED',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Publish Authorization Server Metadata (RFC 8414)',
    note: 'At the well-known path, with the issuer-path form beside it, ' +
          'genuinely signed, and extended into the OpenID Provider ' +
          'Configuration from the same object so the two cannot disagree. ' +
          'True with the mode off as well.' },

  { id: 'metadata-security-capabilities', section: '2.6', level: 'SHOULD',
    appliesTo: 'authorization server and client', enforced: 'always',
    title: 'Publish security capabilities so clients need not hard-code them',
    note: 'This is what section 2.6 is really asking for, and it is the half ' +
          'a bare "publish metadata" row misses. Every capability a client ' +
          'would otherwise compile in is in the document: ' +
          'code_challenge_methods_supported (the one the BCP names outright ' +
          '— there is NO other signal that PKCE is available, so a server ' +
          'that supports it and does not advertise it will never be asked ' +
          'for it), dpop_signing_alg_values_supported, ' +
          'token_endpoint_auth_methods_supported built from the methods that ' +
          'are actually verified, tls_client_certificate_bound_access_tokens ' +
          'where the deployment can do it, and ' +
          'authorization_response_iss_parameter_supported so a client may ' +
          'REQUIRE the RFC 9207 parameter. All of it is true with the mode ' +
          'off; what the mode changes is the CONTENT, and it narrows the ' +
          'document at the same moment it narrows the endpoint.' },

  { id: 'metadata-per-server', section: '2.6', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'A distinct document per authorization server, and endpoints ' +
           'discovered from it',
    note: 'The path component both discovery shapes carry selects a PROFILE ' +
          '— see /admin/authorization-servers — so one process publishes as ' +
          'many authorization servers as somebody configures, each with its ' +
          'own endpoints, capabilities and issuer. That serves the two ' +
          'things section 2.6 wants metadata FOR beyond mere publication: ' +
          'endpoint misconfiguration (point a profile\'s token_endpoint ' +
          'elsewhere and a client that hard-coded the path will not notice) ' +
          'and key rotation and agility (jwks_uri, on a service that ' +
          'regenerates its signing key every start, so a client that cached ' +
          'a key already fails here). ANY member is settable, including one ' +
          'this service has never heard of. A path nobody configured ' +
          'publishes the ordinary document, so this changed nothing for ' +
          'existing callers.' },

  { id: 'metadata-drift-reported', section: '2.6', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'A document that does not describe this service says so',
    note: 'NOT A REQUIREMENT OF THE BCP — it is this repository\'s own, and ' +
          'it is here because the row above would otherwise be a licence to ' +
          'mislead. A profile can advertise anything, including capabilities ' +
          'this server does not have, which is exactly how a client that ' +
          'ignores the metadata is caught. So every surface computes the ' +
          'DRIFT: which overridden members disagree with the document this ' +
          'service would build, and which removals hide something real. A ' +
          'mock that let somebody publish a misleading document is useful; ' +
          'one that did it quietly is a trap.' },

  { id: 'no-client-id-confusion', section: '2.6, 4.13', level: 'SHOULD NOT',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'A client must not be able to choose a client_id that ' +
           'impersonates a user',
    note: 'POST /oauth2/register GENERATES the client_id ' +
          '(oauth2.registeredClientIdPrefix, sts-client- by default, then ' +
          'random) and ignores any the request proposes, so a client cannot ' +
          'pick its own identifier at all — which is the strongest form of ' +
          'this and is true with the mode off. Note what it does NOT cover: ' +
          'a client_id that never registered is whatever string a caller put ' +
          'in the query, because this service issues to any client_id that ' +
          'asks, so the SEPARATION below rather than this row is what a ' +
          'resource server should rely on.' },

  { id: 'client-subject-separated', section: '4.13', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A resource server can tell a client credential from a resource ' +
           'owner\'s',
    note: 'The section\'s MUST: where client and user identifiers could be ' +
          'confused, the authorization server must provide another mechanism ' +
          'for telling them apart. There is one in each mode and they are ' +
          'different mechanisms, which is worth being exact about because a ' +
          'resource server has to be told which one it is reading.\n\nWITH ' +
          'THE MODE OFF, `sub` EQUALS `client_id` on a client_credentials ' +
          'token and on nothing else this service issues — RFC 9700 suggests ' +
          'that comparison itself, and it needs no invented claim and no ' +
          'convention. It is weak in one way the section names: the two ' +
          'identifiers still share a namespace, so a client_id that LOOKS ' +
          'like a subject is possible for any client that never ' +
          'registered.\n\nWITH THE MODE ON, they get SEPARATE NAMESPACES ' +
          'instead: a client\'s subject is urn:sts:client:<id> beside a ' +
          'person\'s urn:uuid:<entryUUID>, so the two cannot collide however ' +
          'a client is named — the SHOULD above it, done properly. That ' +
          'makes `sub` no longer equal to `client_id`, so a resource server ' +
          'written against the comparison must read the PREFIX instead. Both ' +
          'facts are stated here rather than one being described as the ' +
          'mechanism, because a resource server that tested for the wrong ' +
          'one would conclude that a client credential was a person\'s.' },

  { id: 'no-307-redirect', section: '4.12', level: 'MUST NOT',
    appliesTo: 'authorization server', enforced: 'always',
    title:
      'Never use a 307 redirect after a request that may carry credentials',
    note: 'A 307 PRESERVES the method and the body, so a browser would ' +
          'repeat the POST — username and password included — to wherever ' +
          'the redirect points, which after a sign-in is a URL the calling ' +
          'protocol composed. The authorization server would be handing the ' +
          'user\'s password to the client with nobody doing anything wrong. ' +
          'This service has never emitted a 307 or a 308 anywhere; what it ' +
          'emitted after the sign-in POST was a 302, whose behaviour after a ' +
          'POST is historically ambiguous — every browser turns it into a ' +
          'GET and no specification says it must. It is a 303 now, which ' +
          'says so, at authn.js\'s returnToCaller() (the single funnel both ' +
          'the password and the WebAuthn steps leave through) and at ' +
          'WS-Federation\'s own screen. NOT mode-gated: no client can tell ' +
          'the difference, so gating it would leave the default deployment ' +
          'with the ambiguous one and buy nobody an exercise.' },

  // --- section 4.17 — attacks on in-browser communication flows ------------
  { id: 'no-browser-messaging', section: '4.17', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'This service performs no in-browser communication at all',
    note: 'THE SECTION IS CONDITIONAL — "if the implementation uses ' +
          'in-browser communication" — and the condition is false here, ' +
          'which is a fact worth establishing rather than assuming. Audited: ' +
          'nothing in this service calls postMessage, listens for a message ' +
          'event, opens a BroadcastChannel or a MessageChannel, touches ' +
          'window.opener or window.parent, or renders an iframe. There are ' +
          'exactly four scripts served from here — the WebAuthn ceremony, ' +
          'two form auto-posters and the API explorer — and none of them ' +
          'does any of it. So there is no message for a wildcard target ' +
          'origin to leak to and no incoming message whose sender could go ' +
          'unverified: the requirements below cannot be violated because the ' +
          'mechanism is not present, which is a different claim from their ' +
          'being met and is why this row exists.' },

  { id: 'web-message-refused', section: '4.17', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A response mode this server does not perform is refused, not ' +
           'ignored',
    note: 'The mode this section is about is `web_message` — ' +
          'postMessage-based, and what SPAs use for silent renewal in a ' +
          'hidden iframe. This service does not perform it, and until now a ' +
          'client asking for it got a 302 and sat waiting for a message that ' +
          'never arrived: the identical silent failure `form_post` had while ' +
          'it was advertised and missing, and the reason that one was worth ' +
          'fixing. `response_mode` is now checked against what THIS ' +
          'authorization server advertises in response_modes_supported, so ' +
          'the document and the endpoint cannot disagree and a server ' +
          'configured to offer only form_post refuses the other two at its ' +
          'own endpoint. Not gated on this mode: the default document ' +
          'advertises everything this service does, so a request that would ' +
          'have worked still works.' },

  { id: 'browser-message-origins', section: '4.17.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'no',
    title: 'Exact origin matching, and never a wildcard target origin',
    note: 'NOT APPLICABLE, and recorded rather than omitted because a ' +
          'requirement missing from a compliance report reads as one that ' +
          'was met. If `web_message` is ever added here, this is what it ' +
          'costs: the target origin of every postMessage must be the ' +
          'client\'s REGISTERED origin matched exactly — never "*", which ' +
          'broadcasts an authorization code to whatever document happens to ' +
          'be listening — and the exact-match machinery for that already ' +
          'exists (redirect-exact-match), because a registered redirect_uri ' +
          'is where a client\'s trusted origin comes from. The section also ' +
          'says every other authorization-response protection applies ' +
          'unchanged: the code stays single use and PKCE-bound, `iss` still ' +
          'goes on the response, and the redirect_uri is still matched.' },

  { id: 'client-verifies-message-sender', section: '4.17.2', level: 'MUST',
    appliesTo: 'client', enforced: 'no',
    title: 'A client must verify the sender origin of an incoming message',
    note: 'The other half, and it is the client\'s: a listener that does not ' +
          'compare event.origin against the authorization server it expects ' +
          'will accept an authorization response from any document that can ' +
          'reach it, which is how an injected message becomes an injected ' +
          'code. Nothing this service can do about it — and nothing it can ' +
          'even observe, since the check happens in the client. It is here ' +
          'for the same reason the two nonce rows are.' },

  { id: 'no-framing', section: '4.14', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'No page here can be framed — sign-in, authorization or error',
    note: 'Clickjacking: a page framed invisibly over another one collects a ' +
          'click the person meant for something else, and on a sign-in ' +
          'screen or an authorization page that click IS the decision. BOTH ' +
          'countermeasures are on every response — X-Frame-Options: DENY for ' +
          'the browsers that still read it, and CSP Level 2\'s ' +
          'frame-ancestors \'none\', which is the one that actually governs. ' +
          'Two rather than one because the first is obsolete and the second ' +
          'is not universally old enough to rely on alone, and the cost of ' +
          'both is a header.' },

  { id: 'framing-clause-undroppable', section: '4.14', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'A page that relaxes the policy cannot drop the framing clause',
    note: 'THE TRAP, and it caught this service twice. `frame-ancestors` has ' +
          'NO FALLBACK from `default-src`, so a response setting ' +
          '`Content-Security-Policy: default-src \'none\'` and nothing else ' +
          'is framable as far as CSP is concerned — the page works, the ' +
          'script runs, and the protection is quietly gone. Five routes here ' +
          'relax the policy to load a named script and each SETS THE WHOLE ' +
          'HEADER, so each could have left the clause out. They go through ' +
          'app.js\'s contentSecurityPolicy() now, which re-adds the framing ' +
          'clauses whatever the caller asks for — a caller cannot turn them ' +
          'off, deliberately, because no page in an authorization server ' +
          'should be framable.' },

  { id: 'framing-on-error-pages', section: '4.14', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Including the error pages this service did not write',
    note: 'The section names error pages specifically, and this is where the ' +
          'second catch was: EXPRESS\'S OWN 404 HANDLER REPLACES the ' +
          'Content-Security-Policy with `default-src \'none\'` on its way ' +
          'out, so every unrouted path — every typo, every probe — came back ' +
          'with the framing clause gone and only the obsolete header behind ' +
          'it. Nothing in this repository could have shown that, because the ' +
          'header this service set was correct; it was replaced afterwards ' +
          'by the framework. The policy is re-checked when the response is ' +
          'flushed and the base put back if the clause is missing. The test ' +
          'is "does it still carry the clause" rather than "is it the value ' +
          'I set", so the five legitimate relaxations are untouched. The 404 ' +
          'BODY is deliberately left exactly as Express writes it: `Cannot ' +
          'GET /path` is how the parent project\'s tests tell an unrouted ' +
          'path from an endpoint legitimately answering 404, and a prettier ' +
          '404 here would break that distinction silently.' },

  { id: 'framing-device-pages', section: '4.14', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'And the device authorization pages, if there were any',
    note: 'There are none: this service implements no device authorization ' +
          'grant, so there is no user_code page to frame. It is a row rather ' +
          'than an omission because the section names those pages and a ' +
          'reader checking this table against it should find the answer ' +
          'rather than a gap. If that grant is ever added, its pages are ' +
          'covered by the two rows above without anybody doing anything — ' +
          'which is the point of the policy being a service-wide default ' +
          'that a relaxation cannot weaken.' },

  // --- section 4.3 — token leakage through the browser --------------------
  { id: 'no-token-in-query', section: '2.6, 4.3.2', level: 'MUST NOT',
    appliesTo: 'authorization server and resource server', enforced: 'yes',
    title: 'Do not accept an access token in a URI query parameter',
    note: 'RFC 6750 section 2.3\'s query-parameter form has never been READ ' +
          'here — the token comes from the Authorization header and nowhere ' +
          'else, so one in the query was always simply ignored. IGNORED IS ' +
          'NOT REFUSED, and that is what the mode adds: a client sending ' +
          '?access_token= got a 401 saying a token was required, which is ' +
          'true, unhelpful, and sends somebody looking at their credential ' +
          'rather than at where they put it. Now the query is inspected ONLY ' +
          'to refuse it, and the refusal says why — a URL goes into browser ' +
          'history, the address bar, server logs and the Referer of anything ' +
          'the page then fetches, so a token in one is a token in all of ' +
          'them. The token is never echoed back: it has already been ' +
          'somewhere it should not be.' },

  { id: 'no-token-in-url-response', section: '4.3.2', level: 'MUST NOT',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Do not put an access token in a URI query on the way back either',
    note: 'The other direction, and it was always right: a bare ' +
          'authorization code goes in the QUERY and anything carrying a ' +
          'token goes in the FRAGMENT, which a browser never sends to a ' +
          'server. RFC 9700 mode refuses the token-bearing response types ' +
          'outright (no-implicit), so in that mode the question does not ' +
          'arise — but the rule holds in both, because this service exists ' +
          'to serve those flows when asked.' },

  { id: 'form-post-response-mode', section: '4.3.2', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Offer form_post, so the response need not be in a URL at all',
    note: 'IMPLEMENTED, and it was advertised and missing for a long time ' +
          'before that — every request got a 302 whatever response_mode it ' +
          'asked for, so a client that requested form_post sat waiting for a ' +
          'POST that never arrived. The response now travels in a form body, ' +
          'which is in no URL, no history entry and no Referer, and that is ' +
          'true of the ERROR responses too: a client that asked for ' +
          'form_post and got its failure in a query string has had the ' +
          'failure put in browser history. The page is the same shape ' +
          'WS-Federation\'s is — a real form with a real button, plus a ' +
          'separate script that submits it — because script-src is \'none\' ' +
          'here and with the script blocked the button IS the mechanism. ' +
          'Available in both modes: a safety feature offered only in ' +
          'compliance mode would be backwards.' },

  { id: 'referrer-policy', section: '4.3.1', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Set a Referrer-Policy, and keep third-party content off the ' +
           'result pages',
    note: 'Every response from this service carries Referrer-Policy: ' +
          'no-referrer, which is the strongest of them — the header the ' +
          'section is about is suppressed entirely rather than trimmed. And ' +
          'the pages a browser lands on here contain NO third-party resource ' +
          'and no external link: the content security policy is default-src ' +
          '\'none\' with img-src limited to \'self\' and data:, so a ' +
          'third-party resource could not load if one were added by ' +
          'accident. That is the belt and the braces, and the reason both ' +
          'are here is that the policy is a header somebody can drop and the ' +
          'CSP is not.' },

  { id: 'code-in-history-useless', section: '4.3.1', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A code exposed through browser history must not be reusable',
    note: 'THE SAME TWO MECHANISMS the code-injection rows describe, cited ' +
          'here because section 4.3 arrives at them from a different ' +
          'direction: a code in the address bar is a code somebody can read ' +
          'off a shared screen or a synced history. It is single use with ' +
          'the replay relaxation off (code-single-use), a second ' +
          'presentation revokes what the first bought (code-replay-revokes), ' +
          'it is bound to the client that got it (code-client-bound), and it ' +
          'is useless without the PKCE verifier that never left the client ' +
          '(pkce-public-clients). form_post keeps it out of the URL in the ' +
          'first place.' },

  { id: 'tokens-are-secrets', section: '4.3.3', level: 'MUST',
    appliesTo: 'resource server', enforced: 'no',
    title: 'A resource server treats access tokens as secrets, and stores ' +
           'none in plaintext',
    note: 'NOT TRUE HERE, AND DELIBERATELY SO — which is exactly the kind of ' +
          'thing this table exists to say out loud. This service KEEPS every ' +
          'token it issues, in memory and in full, and prints them on ' +
          '/admin/tokens: that is what makes the console able to show a ' +
          'person the JWT they just received, and it is the same decision ' +
          '/krb5/principals makes about the Kerberos passwords. A real ' +
          'resource server must do the opposite. What IS true: nothing here ' +
          'writes a token to disk, the audit log redacts access_token and ' +
          'eight other query keys so a token never reaches a row, and the ' +
          'store dies with the process. Do not copy this part.' },

  // --- what was already here ----------------------------------------------
  { id: 'iss-parameter', section: '2.1, 4.4', level: 'MUST',
    appliesTo: 'client (supported by this server)', enforced: 'always',
    title: 'Mix-up defence — the authorization response identifies the issuer',
    note: 'RFC 9207: every authorization response here carries iss, errors ' +
          'included, and both discovery documents advertise ' +
          'authorization_response_iss_parameter_supported so a client knows ' +
          'it may REQUIRE it. That predates this mode and is not conditional ' +
          'on it.' },

  // --- section 4.5 — authorization code injection and replay ---------------
  { id: 'code-single-use', section: '4.5', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'An authorization code is single use, and is invalidated by its ' +
           'first use',
    note: 'The code is deleted where it is redeemed, and always was. What ' +
          'the MODE changes is the one deliberate relaxation on top of that, ' +
          'documented where `redeemedCodes` is declared in oauth2.js: ' +
          'without the mode, an IDENTICAL repeat of a Token Request is ' +
          'answered with the tokens it already got — the same set, down to ' +
          'the jti, so nothing is minted twice — because "your code_verifier ' +
          'does not match" turning into "already-used code" on the next ' +
          'attempt is the wrong answer at exactly the moment somebody is ' +
          'acting on the right one. RFC 6749 section 4.1.2 says a real ' +
          'server refuses that, so in this mode it does, and the refusal ' +
          'says how long ago the code was redeemed and by which client.' },

  { id: 'code-replay-revokes', section: '4.5', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A code used twice revokes everything it bought',
    note: 'RFC 6749 section 10.5: on a second presentation the authorization ' +
          'server SHOULD revoke the tokens previously issued for that code. ' +
          'So the access token, the refresh token and the ID Token from the ' +
          'first redemption are revoked through the same set /oauth2/revoke ' +
          'writes to, and the refusal says how many. The reasoning is the ' +
          'refresh chain\'s (refresh-replay-family): a code presented twice ' +
          'means one of the two holders is not the client, and nothing here ' +
          'can tell which — so the answer is to invalidate what it bought ' +
          'rather than to guess.' },

  { id: 'code-client-bound', section: '4.5', level: 'SHOULD',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'An authorization code is bound to the client it was issued to',
    note: 'THE SAME CHECK `transaction-bound` describes, cited here because ' +
          'the BCP raises it twice from two directions — as a property of ' +
          'the code in section 4.5 and as the binding of the PKCE and nonce ' +
          'values in section 2.1.1. There is one check and it is in ' +
          'checkTokenRequest(): the client_id presenting the code must be ' +
          'the client_id it was issued to. Without the mode this service ' +
          'read the client off the CODE and never compared it with the one ' +
          'presenting it.' },

  { id: 'nonce-validated-by-client', section: '2.1.1, 4.5.3.2', level: 'MUST',
    appliesTo: 'client', enforced: 'no',
    title: 'The client must validate the nonce in the ID Token from the ' +
           'token endpoint',
    note: 'NOT ENFORCEABLE FROM HERE, and saying so is the useful part: ' +
          'whether a client compares the nonce it sent with the one it got ' +
          'back happens inside the client, and no observation this server ' +
          'can make distinguishes a client that checks from one that does ' +
          'not. What this server can do is the half that IS its own — the ID ' +
          'Token carries the nonce from the authorization request, always, ' +
          'and the mode refuses a request that asks for an id_token without ' +
          'one (nonce-required). And it can give a client author a way to ' +
          'find out: `oauth2.breakIdTokenNonce` puts a DELIBERATELY WRONG ' +
          'nonce in the ID Token, so a client that accepts the result is a ' +
          'client that is not checking. That switch is off by default, is ' +
          'not part of this mode, and every token it spoils is logged as ' +
          'spoiled.' },

  { id: 'no-token-use-before-nonce-check', section: '4.5.3.2',
    level: 'MUST NOT',
    appliesTo: 'client', enforced: 'no',
    title: 'The client must not use any token until nonce validation has ' +
           'succeeded',
    note: 'Also unobservable from here, and for a stronger reason than the ' +
          'row above: this is about the ORDER of two things a client does ' +
          'with tokens it already holds, and the authorization server is not ' +
          'present for either. It is in this table because a requirement ' +
          'left out of a compliance report reads as one that was met.' }
];

// ---------------------------------------------------------------------------
// The settings, read PER CALL rather than captured (see the runtime rule in
// config.js): a `const` here is the one thing /admin/config could not change,
// and it would fail in the direction that looks like the console is broken.
// ---------------------------------------------------------------------------
// ON FOR EITHER FLAG. `oauth2.oauth21` implies this mode: OAuth 2.1 is OAuth
// 2.0 with the best current practices applied, and every row in REQUIREMENTS
// is one of those. So a realm carrying only `oauth2.oauth21` gets every check
// here as well as oauth21.js's own, and `state()` says which flag did it.
// WHAT TURNS THIS MODE ON: the setting, OAuth 2.1 mode (which is a superset),
// and — since 2026-09-17 — PRODUCT MODE, which implies it.
//
// **PRODUCT MODE IMPLIES IT BECAUSE THAT IS WHAT LETS A PUBLIC CLIENT IN.**
// Product mode used to refuse any client that did not authenticate, so there
// were no public clients and nothing to protect them. It allows one now, and
// the thing a public client is held to instead of a credential is this mode:
// PKCE with S256, an exactly matched redirect URI, a challenge that cannot be
// replayed, no token from the authorization endpoint. `common/mode.js`'s
// `enforcesOauthSecurityBcp()` carries the argument.
//
// **A REALM CANNOT TURN IT OFF IN PRODUCT MODE.** `oauth2.rfc9700` is
// `realmRuntime`, so a realm may turn this mode ON while the process is not in
// it; the product-mode term is the process's and is a FLOOR — `||`, never
// `&&`. A realm able to opt out would be a realm whose public clients had
// neither a credential nor the rules that replace one.
function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
  return !!config.value('oauth2.rfc9700') || oauth21.enabled() ||
         mode.enforcesOauthSecurityBcp();
}

// OAuth 2.1 section 8.4.2 makes the wildcard a MUST, so that mode ignores the
// setting that can turn it off — see oauth21.js's `loopback-any-port` row.
function loopbackPortWildcard() {
  log.debug("Entering loopbackPortWildcard().");
  log.debug("Leaving loopbackPortWildcard().");
  return !!config.value('oauth2.loopbackPortWildcard') ||
         oauth21.loopbackAnyPort();
}

// Whether the port `/oauth2/authorize` answers on is a TLS listener. Read from
// the setting rather than from a request, because it is the same answer for
// every request this process will ever serve — `global.https` is restart-only,
// since a socket is bound before anything is listening.
function mainPortIsTls() {
  log.debug("Entering mainPortIsTls().");
  log.debug("Leaving mainPortIsTls().");
  return !!config.value('global.https');
}

function configuredRedirectUris() {
  log.debug("Entering configuredRedirectUris().");
  const list = config.value('oauth2.redirectUris');
  log.debug("Leaving configuredRedirectUris().");
  return Array.isArray(list) ? list : [];
}

// ---------------------------------------------------------------------------
// WHO THE REGISTERED URIs BELONG TO.
//
// A client that registered through RFC 7591 and declared redirect_uris is
// judged against ITS OWN list and nothing else — that is what registration
// means, and falling back to the global list for such a client would let any
// URI somebody put in the setting stand in for one the client never registered.
//
// Everything else — an unregistered client_id, which is the ordinary case for a
// debugger pointed at this service — is judged against `oauth2.redirectUris`.
// That setting is EMPTY by default, so turning the mode on with nothing
// configured refuses every authorization request. That is the honest outcome
// rather than an unhelpful one: the refusal names the setting and the
// registration endpoint, so the next step is on the page rather than in the
// source.
// ---------------------------------------------------------------------------
function registeredUrisFor(client) {
  log.debug("Entering registeredUrisFor().");
  if (client && Array.isArray(client.redirect_uris) &&
      client.redirect_uris.length) {
    log.debug("Leaving registeredUrisFor(). " + client.redirect_uris.length +
              " URI(s) from this client's own entry.");
    return { list: client.redirect_uris.map(String),
             source: 'this client\'s own entry in the application registry ' +
                     '(ou=applications, attribute oauthRedirectUri)' };
  }
  // OAuth 2.1 section 2.3.1: a client registers ITS OWN complete redirect URI,
  // and a list every client may use is the opposite of that — so that mode
  // answers with nothing to match and `checkRedirectUri()` refuses by name.
  if (oauth21.enabled()) {
    log.debug("Leaving registeredUrisFor(). OAuth 2.1 mode reads no fallback.");
    return { list: [], source: 'this client\'s own entry (OAuth 2.1 mode ' +
                               'does not read oauth2.redirectUris)' };
  }
  const list = configuredRedirectUris();
  log.debug("Leaving registeredUrisFor(). " + list.length + " URI(s) from " +
      "oauth2.redirectUris.");
  return { list: list, source: 'the oauth2.redirectUris setting' };
}

// Only "none" — or nothing at all — says public. The DEFAULTING is not done
// here any more: `applications.clientConfigOf()` knows whether an application
// arrived through RFC 7591 (where section 2 makes client_secret_basic the
// default for an omitted member) or was created by hand (where an omission says
// nothing), and it is the only place both facts are. What is left here is the
// reading of the answer, and its direction: an unstated method is treated as
// PUBLIC, because requiring PKCE of a confidential client is a SHOULD honoured
// early while exempting a public one is the MUST in section 2.1.1 gone.
//
// It follows that setting `oauthTokenEndpointAuthMethod` on an entry — from the
// console, the management API or ldapmodify — is what makes a client
// confidential or public here, which is exactly the switch a client author
// needs in order to exercise both halves of section 2.1.1 against one
// client_id.
function isConfidential(client) {
  log.debug("Entering isConfidential().");
  if (!client) {
    log.debug("Leaving isConfidential().");
    return false;
  }
  const method = String(client.token_endpoint_auth_method || '').trim();
  log.debug("Leaving isConfidential().");
  return method !== '' && method !== 'none';
}

// ---------------------------------------------------------------------------
// DECLARED PUBLIC — AND WHY IT IS NOT `!isConfidential()` (2026-09-17).
//
// `isConfidential()` above answers "can this server SEE this client to be
// confidential", and it answers no for a client whose registration declares no
// method at all. That is the right answer for the PKCE rule it was written
// for: RFC 9700 section 2.1.1 requires PKCE of every client the server cannot
// see to be confidential, and a client that declared nothing is one of those.
//
// **IT IS THE WRONG ANSWER FOR "MUST THIS CLIENT AUTHENTICATE", AND THE
// DIFFERENCE IS A HOLE.** RFC 7591 section 2 says an omitted
// `token_endpoint_auth_method` means `client_secret_basic` — so a client that
// declared nothing is CONFIDENTIAL for that question, and product mode must
// require a credential of it. Reading `!isConfidential()` there would let a
// client that never declared itself public through with none, which is a good
// deal more than "public clients are allowed" and is exactly what
// `tests/public_clients_product.js` section 0b exists to catch. (It caught it:
// the first version of the product-mode gate asked `!isConfidential()`.)
//
// So PUBLIC, for authentication, is an EXPLICIT `none` and nothing else. The
// two functions are not redundant and neither is a replacement for the other;
// the header above `observeClientAuthentication()` says they must agree about
// a client that DECLARED a method, and they do — it is only the undeclared
// case they read differently, because only one of them has RFC 7591's default
// to apply.
function declaredPublic(registered) {
  log.debug("Entering declaredPublic().");
  if (!registered || !registered.known) {
    // Not registered here at all. Not public — unknown, which is a different
    // fact every caller already handles for itself.
    log.debug("Leaving declaredPublic(). No registration.");
    return false;
  }
  const method = String(registered.token_endpoint_auth_method || '').trim();
  log.debug("Leaving declaredPublic().");
  return method === 'none';
}

function parseUri(value) {
  log.debug("Entering parseUri().");
  try {
    log.debug("Leaving parseUri().");
    return new URL(String(value));
  } catch (e) {
    log.debug("Caught in parseUri(): " + ((e && e.message) || e));
    log.debug("Leaving parseUri().");
    // Not a URL. Every caller treats that as "no match", which is the same
    // answer it would get from a URI that parses and matches nothing.
    return null;
  }
}

// RFC 8252 section 7.3 names 127.0.0.1 and ::1 and says a client SHOULD use the
// IP literal rather than the name; RFC 9700 section 2.1 says "localhost". All
// three are accepted as loopback, because refusing the spelling the shorter
// document uses would refuse the example most people copy.
function isLoopbackHost(hostname) {
  log.debug("Entering isLoopbackHost().");
  const host = String(hostname || '').toLowerCase();
  log.debug("Leaving isLoopbackHost().");
  return host === '127.0.0.1' || host === '::1' || host === '[::1]' ||
         host === 'localhost';
}

// ---------------------------------------------------------------------------
// THE COMPARISON, and it is deliberately dull.
//
// Exact string equality first, which is the whole of section 2.1 for every
// client that is not a native application. The loopback branch below is the ONE
// exception the specification carves out, and note what it does not do: it does
// not normalise, does not ignore a trailing slash, does not fold case in the
// path and has no pattern syntax to be configured with. Every one of those is a
// convenience somebody would ask for and each is a way for a redirect_uri that
// was not registered to be accepted.
// ---------------------------------------------------------------------------
function uriMatches(registered, presented) {
  log.debug("Entering uriMatches().");
  if (registered === presented) {
    log.debug("Leaving uriMatches().");
    return { ok: true, how: 'exact string match' };
  }
  if (!loopbackPortWildcard()) {
    log.debug("Leaving uriMatches().");
    return { ok: false };
  }
  const a = parseUri(registered);
  const b = parseUri(presented);
  if (!a || !b) {
    log.debug("Leaving uriMatches().");
    return { ok: false };
  }
  // Both ends must be loopback and must be the SAME loopback literal: a
  // registration for http://127.0.0.1/cb does not authorise
  // http://localhost/cb, because those are different names even though they
  // resolve alike, and treating them as one is a pattern match wearing a
  // different hat.
  if (!isLoopbackHost(a.hostname) ||
      a.hostname.toLowerCase() !== b.hostname.toLowerCase()) {
    log.debug("Leaving uriMatches().");
    return { ok: false };
  }
  if (a.protocol !== b.protocol || a.pathname !== b.pathname ||
      a.search !== b.search || a.hash !== b.hash) {
    log.debug("Leaving uriMatches().");
    return { ok: false };
  }
  log.debug("Leaving uriMatches().");
  return { ok: true, how: 'loopback match with a variable port (RFC 8252 ' +
                          'section 7.3)' };
}

// ---------------------------------------------------------------------------
// THE REDIRECT URI CHECK. Its refusal is the one that must NOT be reported to
// the redirect_uri, so it is a separate call from checkAuthorizationRequest()
// below rather than one more clause inside it — see the header.
// ---------------------------------------------------------------------------
function checkRedirectUri(opts) {
  log.debug("Entering checkRedirectUri(). redirect_uri=" + opts.redirectUri);
  if (!enabled()) {
    log.debug("Leaving checkRedirectUri(). RFC 9700 mode is off.");
    return { ok: true };
  }
  const presented = String(opts.redirectUri || '');
  const parsed = parseUri(presented);
  if (!parsed) {
    log.debug("Leaving checkRedirectUri(). It does not parse as a URI.");
    return { ok: false, errorCode: 'STS-OAUTH-0119', error: 'invalid_request',
             requirement: 'redirect-exact-match',
             description: 'RFC 9700 section 2.1: redirect_uri must be an ' +
                          'absolute URI. ' +
                          '"' + presented + '" does not parse as one.' };
  }
  // Section 2.6, checked BEFORE the registry: an http URI that is not a
  // loopback address is refused whether or not somebody registered it, because
  // the registration is not what makes it safe.
  if (parsed.protocol === 'http:' && !isLoopbackHost(parsed.hostname)) {
    log.debug("Leaving checkRedirectUri(). http, and not a loopback address.");
    return { ok: false, errorCode: 'STS-OAUTH-0120', error: 'invalid_request',
             requirement: 'http-scheme-refused',
             description: 'RFC 9700 section 2.6: an authorization server ' +
                          'must not allow a redirect URI using the http ' +
                          'scheme, except for a native application ' +
                          'redirecting to a loopback address (127.0.0.1, ' +
                          '[::1] or localhost). ' +
                          '"' + presented + '" is neither.' };
  }
  const registered = registeredUrisFor(opts.client);
  if (!registered.list.length && oauth21.enabled()) {
    const unregistered = oauth21.registeredClientRefusal(opts.client,
                                                         opts.clientId);
    log.debug("Leaving checkRedirectUri(). OAuth 2.1 mode: no redirect URI " +
              "of the client's own.");
    return unregistered;
  }
  if (!registered.list.length) {
    log.debug("Leaving checkRedirectUri(). Nothing is registered to compare " +
              "against.");
    return { ok: false, errorCode: 'STS-OAUTH-0121', error: 'invalid_request',
             requirement: 'redirect-exact-match',
             description: 'RFC 9700 section 2.1 requires redirect_uri to be ' +
                          'compared by exact string match against the URIs ' +
                          'registered for this client, and none are ' +
                          'registered. Add this URI to the ' +
                          'oauth2.redirectUris setting (/admin/oauth2, or ' +
                          'POST /admin-api/config), or register the client ' +
                          'with its redirect_uris at POST /oauth2/register.' };
  }
  let matched = null;
  for (let i = 0; i < registered.list.length && !matched; i++) {
    const result = uriMatches(registered.list[i], presented);
    if (result.ok) {
      matched = { uri: registered.list[i], how: result.how };
    }
  }
  if (!matched) {
    log.debug("Leaving checkRedirectUri(). No registered URI matches.");
    return { ok: false, errorCode: 'STS-OAUTH-0122', error: 'invalid_request',
             requirement: 'redirect-exact-match',
             description: 'RFC 9700 section 2.1: redirect_uri must match one ' +
                          'of the URIs registered for this client by exact ' +
                          'string comparison (RFC 3986 section 6.2.1). ' +
                          '"' + presented + '" matches none ' +
                              'of the ' +
                          registered.list.length + ' in ' + registered.source +
                          ': ' +
                          registered.list.join(', ') + '.' };
  }
  log.debug("Leaving checkRedirectUri(). Accepted by " + matched.how + ".");
  return { ok: true, matched: matched.uri, how: matched.how };
}

// The same comparison for RP-Initiated Logout's post_logout_redirect_uri, which
// without this mode is the plainest open redirector in this service: it
// forwards the browser to any absolute http(s) URL in a query parameter, with
// no session and no client involved. A registered client's own
// post_logout_redirect_uris are used when the request names one; otherwise the
// setting is, on the ground that somebody who listed a URI as a place this
// server may return a browser to has said the same thing about it either way.
function checkPostLogoutRedirectUri(opts) {
  log.debug("Entering checkPostLogoutRedirectUri().");
  if (!enabled()) {
    log.debug("Leaving checkPostLogoutRedirectUri(). RFC 9700 mode is off.");
    return { ok: true };
  }
  const client = opts.client;
  const declared = client && Array.isArray(client.post_logout_redirect_uris)
    ? client.post_logout_redirect_uris.map(String) : [];
  const presented = String(opts.target || '');
  // A PRIVATE-USE ADDRESS IS BELIEVED ONLY WHEN A CLIENT VOUCHES FOR IT
  // (2026-09-13). Sign-out needs no client at all, so a service-wide list that
  // admitted a protocol handler would be a redirector to it with nobody
  // accountable for the entry; the address has to be on the entry of the client
  // this request names. OAuth 2.1 mode goes further and reads no service-wide
  // list for ANY address, for the reason registeredUrisFor() gives.
  const privateUse = validation.isPrivateUseRedirect(presented);
  if (!declared.length && (privateUse || oauth21.enabled())) {
    log.debug("Leaving checkPostLogoutRedirectUri(). No client vouches for " +
              "it.");
    return privateUse
      ? { ok: false, errorCode: 'STS-OAUTH-0290', error: 'invalid_request',
          requirement: 'no-open-redirector',
          description: 'RFC 9700 section 2.1: "' + presented + '" is a ' +
                       'native application\'s private-use address, and one ' +
                       'is followed after a sign-out only when the client ' +
                       'this request names (client_id) registered it as a ' +
                       'post_logout_redirect_uri. ' +
                       (client && client.known
                         ? 'That client has registered none.'
                         : 'This request names no client this service ' +
                           'holds.') }
      : { ok: false, errorCode: 'STS-OAUTH-0286', error: 'invalid_request',
          requirement: 'registered-client-required',
          description: 'OAuth 2.1 (' + oauth21.DRAFT + ') section 2.3.1: a ' +
                       'post_logout_redirect_uri is followed only when the ' +
                       'client this request names registered it, and ' +
                       (client && client.known
                         ? 'that client has registered none'
                         : 'this request names no client this service ' +
                           'holds') + '. The service-wide ' +
                       'oauth2.redirectUris list is not read in this mode.' };
  }
  // Same rule as the redirect URIs: the attribute is the list, however it got
  // onto the entry.
  const list = declared.length ? declared : configuredRedirectUris();
  const found = list.some(function (uri) {
    return uriMatches(uri, presented).ok;
  });
  if (!found) {
    log.debug("Leaving checkPostLogoutRedirectUri(). Not registered.");
    return { ok: false, errorCode: 'STS-OAUTH-0123', error: 'invalid_request',
             requirement: 'no-open-redirector',
             description: 'RFC 9700 section 2.1: an authorization server ' +
                          'must not forward the browser to an arbitrary URI. ' +
                          '"' + presented + '" ' +
                              'is not among the ' +
                          (list.length ?
                           list.length + ' registered URI(s): ' +
                           list.join(', ')
                                       : 'registered URIs, and none are ' +
                                         'registered') + '.' };
  }
  log.debug("Leaving checkPostLogoutRedirectUri(). Accepted.");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// TRANSACTION VALUES — what makes "transaction-specific" checkable.
//
// A code_challenge or a nonce is remembered from the moment a code is issued
// for it until the code's own lifetime is over, together with the client it
// belonged to and whether that code was redeemed. Two things are then refusals
// rather than guesses:
//
//   * the value coming back for a NEW authorization request after the earlier
//     code was redeemed — that transaction is finished, so this is a second one
//     reusing its value
//   * the value arriving from a DIFFERENT client_id, which is not a reuse
//     question at all: a challenge one client is using cannot be a challenge
//     another client chose freshly
//
// What is deliberately NOT refused is the same value arriving again while the
// earlier code is still unredeemed. That is a reloaded tab or a retried request
// — the same transaction — and refusing it is how a check like this comes to be
// turned off by the people it was meant to help.
//
// Bounded, because it is a Map on a long-running process: entries are dropped
// once the code they belong to could no longer be redeemed, and the whole store
// is capped. A forgotten value is a check not made, never a false refusal.
// ---------------------------------------------------------------------------
//
// BOTH NUMBERS ARE READ FROM SETTINGS SINCE 2026-09-12, AND THE FIRST ONE IS
// NOT A SETTING OF ITS OWN. `TRANSACTION_TTL_MS` said "twice an authorization
// code's life" in a comment while oauth2.js held the code's life in a constant
// of its own, which is a match nothing kept. It is now computed from
// `oauth2.authorizationCodeTtlS` — the SAME row the code's expiry is read from
// — so moving one moves both. `oauth2.maxPendingTransactions` is the cap, and
// dropping the oldest when it is reached stays the policy: a forgotten
// transaction value is a reuse check NOT made, never a false refusal and never
// a credential accepted twice, because the code itself is single use
// independently of this store. That is the difference from the assertion
// replay caches, which refuse rather than forget.
const TRANSACTION_TTL_MS = 10 * 60 *
                           1000;   // the DEFAULT: twice a five-minute code
const MAX_TRANSACTIONS = 500;                // the DEFAULT of the cap

function transactionTtlMs() {
  log.debug("Entering transactionTtlMs().");
  const seconds = Number(config.value('oauth2.authorizationCodeTtlS'));
  log.debug("Leaving transactionTtlMs().");
  return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) * 2000 :
         TRANSACTION_TTL_MS;
}

function maxTransactions() {
  log.debug("Entering maxTransactions().");
  const count = Number(config.value('oauth2.maxPendingTransactions'));
  log.debug("Leaving maxTransactions().");
  return isFinite(count) && count > 0 ? Math.floor(count) : MAX_TRANSACTIONS;
}
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// 'pkce:x' / 'nonce:x' -> record
const transactions = realms.map({ persist: 'oauth2_bcp.transactions' });

function forgetStaleTransactions() {
  log.debug("Entering forgetStaleTransactions().");
  const now = Date.now();
  transactions.forEach(function (record, key) {
    if (record.forget < now) {
      transactions.delete(key);
    }
  });
  // Still too many? Drop the oldest. Map preserves insertion order, so the
  // first keys are the oldest, and losing the oldest is losing the check least
  // likely to still matter.
  while (transactions.size > maxTransactions()) {
    const oldest = transactions.keys().next();
    if (oldest.done) {
      break;
    }
    transactions.delete(oldest.value);
  }
  log.debug("Leaving forgetStaleTransactions(). " + transactions.size + " " +
      "remembered.");
}

function transactionKeys(query) {
  log.debug("Entering transactionKeys().");
  const keys = [];
  if (query.code_challenge) {
    keys.push({ key: 'pkce:' + String(query.code_challenge),
                what: 'code_challenge' });
  }
  if (query.nonce) {
    keys.push({ key: 'nonce:' + String(query.nonce), what: 'nonce' });
  }
  log.debug("Leaving transactionKeys().");
  return keys;
}

// Called immediately before a code is minted, which is the only moment the
// answer is meaningful: the same request runs through the authorization
// endpoint TWICE (once before the sign-in screen and once on the way back), and
// a check at the top of the endpoint would refuse every request for reusing its
// own value between the two passes.
function checkTransactionValues(opts) {
  log.debug("Entering checkTransactionValues().");
  if (!enabled()) {
    log.debug("Leaving checkTransactionValues(). RFC 9700 mode is off.");
    return { ok: true };
  }
  const clientId = String(opts.clientId || '');
  const found = transactionKeys(opts.query);
  for (let i = 0; i < found.length; i++) {
    const record = transactions.get(found[i].key);
    if (!record || record.forget < Date.now()) {
      continue;
    }
    if (record.clientId !== clientId) {
      log.debug("Leaving checkTransactionValues(). " + found[i].what + " " +
          "belongs to another client.");
      return { ok: false, errorCode: 'STS-OAUTH-0124', error: 'invalid_request',
               requirement: 'transaction-bound',
               description: 'RFC 9700 section 2.1.1: the ' + found[i].what +
                            ' ' +
                            'must be bound to the client and user-agent ' +
                            'transaction. This one was already used by ' +
                            'client "' + record.clientId + '" and cannot ' +
                            'also be a fresh value chosen by ' +
                            '"' + clientId + '".' };
    }
    if (record.redeemed) {
      log.debug("Leaving checkTransactionValues(). " + found[i].what + " was " +
          "reused after redemption.");
      return { ok: false, errorCode: 'STS-OAUTH-0125', error: 'invalid_request',
               requirement: 'transaction-specific',
               description: 'RFC 9700 section 2.1.1: the ' + found[i].what +
                            ' ' +
                            'must be transaction-specific. This value was ' +
                            'used for an authorization code that has already ' +
                            'been redeemed, so this is a second transaction ' +
                            'reusing a first one\'s value. Generate a fresh ' +
                            'one per request.' };
    }
  }
  log.debug("Leaving checkTransactionValues(). Nothing reused.");
  return { ok: true };
}

// `completed` says the transaction is already over at the moment it is
// remembered, which is true of a response that carries no authorization code:
// an id_token returned straight from the authorization endpoint is the whole of
// that transaction, so its nonce is spent there and then. Leaving it open would
// mean nonce reuse was never detectable in the one flow where the nonce is the
// only protection there is.
function rememberTransactionValues(opts) {
  log.debug("Entering rememberTransactionValues().");
  if (!enabled()) {
    log.debug("Leaving rememberTransactionValues(). RFC 9700 mode is off.");
    return;
  }
  const forget = Date.now() + transactionTtlMs();
  transactionKeys(opts.query).forEach(function (entry) {
    transactions.set(entry.key, { clientId: String(opts.clientId || ''),
                                  redeemed: !!opts.completed, forget: forget });
  });
  forgetStaleTransactions();
  log.debug("Leaving rememberTransactionValues().");
}

// The other end of it: the token endpoint says which transaction is over. The
// record is the authorization code's own, so the challenge and the nonce come
// from what was authorized rather than from what the Token Request claims.
function noteRedeemed(record) {
  log.debug("Entering noteRedeemed().");
  if (!enabled() || !record) {
    log.debug("Leaving noteRedeemed(). Nothing to mark.");
    return;
  }
  transactionKeys(record).forEach(function (entry) {
    const known = transactions.get(entry.key);
    if (known) {
      known.redeemed = true;
      // THROUGH THE STORE, because this mark is REPLAY PROTECTION and not
      // bookkeeping. `transactions` is `realms.map({persist})` and its journal
      // sees `set()`, never a field stamped on the object it handed out — so a
      // redemption marked in place is a code that is spent in this process and
      // unspent in every other one.
      transactions.set(entry.key, known);
    }
  });
  log.debug("Leaving noteRedeemed().");
}

// ---------------------------------------------------------------------------
// THE AUTHORIZATION REQUEST — everything that may be reported to a redirect_uri
// that has already been validated. Returns the FIRST refusal, because a client
// fixing two problems finds the second one on the next attempt and a client
// shown two at once usually reads only the first anyway.
// ---------------------------------------------------------------------------
function checkAuthorizationRequest(opts) {
  log.debug("Entering checkAuthorizationRequest().");
  if (!enabled()) {
    log.debug("Leaving checkAuthorizationRequest(). RFC 9700 mode is off.");
    return { ok: true };
  }
  const query = opts.query || {};
  const types = opts.types || [];
  const client = opts.client;

  // Section 2.1.2 — no access token from the authorization endpoint.
  if (types.indexOf('token') >= 0) {
    log.debug("Leaving checkAuthorizationRequest(). The response type issues " +
              "an access token.");
    return { ok: false, errorCode: 'STS-OAUTH-0126',
             error: 'unsupported_response_type', requirement: 'no-implicit',
             description: 'RFC 9700 section 2.1.2: clients should not use ' +
                          'the implicit grant or any other response type ' +
                          'that issues an access token from the ' +
                          'authorization endpoint. Use response_type=code' +
                          (types.indexOf('id_token') >= 0 ?
                           ' or code id_token' : '') + '.' };
  }

  // OAUTH 2.1 — PKCE FOR CONFIDENTIAL CLIENTS TOO, and the method REQUIRED.
  // Asked FIRST and only in that mode, because it is stricter than the block
  // below in both directions: section 7.5.1.1 makes PKCE a MUST whatever the
  // client is, bar a confidential one relying on the OpenID Connect nonce —
  // and "confidential" there means a credential this service can CHECK, not a
  // method declared with nothing behind it. See oauth21.js's pkceDecision().
  if (oauth21.enabled()) {
    const pkce = oauth21.pkceDecision({
      query: query, types: types,
      confidential: isConfidential(client) && !!credentialOnFile(client)
    });
    if (!pkce.ok) {
      log.debug("Leaving checkAuthorizationRequest(). OAuth 2.1 PKCE (" +
                pkce.requirement + ").");
      return pkce;
    }
  }

  // Section 2.1.1 — PKCE. Required of every client this server cannot see to be
  // confidential; a SHOULD, and therefore a log line rather than a refusal, for
  // the ones it can. Not asked in OAuth 2.1 mode, which answered above.
  if (types.indexOf('code') >= 0 && !query.code_challenge &&
      !oauth21.enabled()) {
    if (!isConfidential(client)) {
      log.debug("Leaving checkAuthorizationRequest(). A public client sent " +
                "no code_challenge.");
      return { ok: false, errorCode: 'STS-OAUTH-0127', error: 'invalid_request',
               requirement: 'pkce-public-clients',
               description: 'RFC 9700 section 2.1.1: public clients must use ' +
                            'PKCE (RFC 7636). Send code_challenge and ' +
                            'code_challenge_method=S256. A client registered ' +
                            'here with a token_endpoint_auth_method other ' +
                            'than "none" is treated as confidential, for ' +
                            'which PKCE is RECOMMENDED rather than required.' };
    }
    log.warn('RFC 9700 section 2.1.1: confidential client "' +
             (query.client_id || '') +
             '" sent no code_challenge. PKCE is RECOMMENDED for confidential ' +
             'clients; the request is answered, and this is the SHOULD it ' +
             'did not follow.');
  }

  if (query.code_challenge) {
    const method = String(query.code_challenge_method || 'plain');
    if (method !== 'S256') {
      log.debug("Leaving checkAuthorizationRequest(). code_challenge_method=" +
                method + ".");
      return { ok: false, errorCode: 'STS-OAUTH-0128', error: 'invalid_request',
               requirement: 'pkce-s256',
               description: 'RFC 9700 section 2.1.1: use a code challenge ' +
                            'method that does not expose the verifier. S256 ' +
                            'is currently the only one, and it is the only ' +
                            'value code_challenge_methods_supported ' +
                            'advertises in this mode. ' +
                            '"' + method + '" is refused.' };
    }
    // What SHA-256 through base64url produces and nothing else does. A verifier
    // sent as a challenge — the mistake `plain` makes easy — is almost never 43
    // characters, so this catches it at the authorization request rather than
    // leaving it to fail as a mismatch at the token endpoint.
    if (!/^[A-Za-z0-9_-]{43}$/.test(String(query.code_challenge))) {
      log.debug("Leaving checkAuthorizationRequest(). The S256 challenge is " +
                "not 43 base64url characters.");
      return { ok: false, errorCode: 'STS-OAUTH-0129', error: 'invalid_request',
               requirement: 'pkce-s256',
               description: 'RFC 7636 section 4.2: an S256 code_challenge is ' +
                            'the base64url encoding, without padding, of the ' +
                            'SHA-256 of the code_verifier — 43 characters. ' +
                            'This one ' +
                            'is ' + String(query.code_challenge).length + '.' };
    }
  }

  // Section 4.5.3.2 — the nonce is what makes code injection detectable for a
  // client relying on OIDC rather than on PKCE, so a response carrying an
  // id_token has to have one to bind.
  if (types.indexOf('id_token') >= 0 && !query.nonce) {
    log.debug("Leaving checkAuthorizationRequest(). An id_token was asked " +
              "for with no nonce.");
    return { ok: false, errorCode: 'STS-OAUTH-0130', error: 'invalid_request',
             requirement: 'nonce-required',
             description: 'RFC 9700 section 2.1.1: the OpenID Connect nonce ' +
                          'must be transaction-specific and bound to the ' +
                          'user-agent transaction, and a response_type ' +
                          'naming id_token must carry one — it is what a ' +
                          'client validates the id_token against to detect ' +
                          'an injected code.' };
  }

  log.debug("Leaving checkAuthorizationRequest(). Nothing refused.");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// SECTION 2.4 — the resource owner password credentials grant.
//
// The one grant RFC 9700 rules out outright, and the only check in this module
// that looks at nothing but the grant type. It is refused with
// `unsupported_grant_type` rather than `invalid_grant`, because the request is
// not malformed and the credential is not wrong: this server will not perform
// that grant at all, which is what that error code means and what the metadata
// now says by leaving `password` out of grant_types_supported.
// ---------------------------------------------------------------------------
function checkGrantType(grant) {
  log.debug("Entering checkGrantType(). grant=" + grant);
  if (!enabled() || grant !== 'password') {
    log.debug("Leaving checkGrantType(). Nothing to refuse.");
    return { ok: true };
  }
  log.debug("Leaving checkGrantType(). The password grant is refused.");
  return { ok: false, errorCode: 'STS-OAUTH-0131',
           error: 'unsupported_grant_type', requirement: 'no-ropc',
           description: 'RFC 9700 section 2.4: the resource owner password ' +
                        'credentials grant MUST NOT be used. It gives the ' +
                        'client the End-User\'s password, it cannot carry a ' +
                        'second factor, and there is no way to make it safe. ' +
                        'Use the authorization code grant with PKCE.' };
}

// ---------------------------------------------------------------------------
// DYNAMIC CLIENT REGISTRATION, checked against the same rules the endpoints
// enforce.
//
// This is the other direction of the promise a discovery document makes. The
// token endpoint refuses `grant_type=password` (section 2.4) and the
// authorization endpoint refuses a response type that issues an access token
// (section 2.1.2) — so a registration that RECORDED either would hand a client
// a document saying it may use a grant this server will always refuse. RFC 7591
// section 3.2.1 lets the server reject metadata it will not honour, and
// `invalid_client_metadata` is the error section 3.2.2 gives for it.
//
// Refusing at registration rather than quietly dropping the value is
// deliberate. RFC 7591 permits either — the server may return different
// metadata from what was asked for — and a client that registered for
// `password` and got back a registration without it would have to compare the
// two documents field by field to notice. The refusal names the member and the
// section.
//
// The redirect URIs are checked here too, against the same scheme rule the
// authorization endpoint applies, because a registration is the one moment a
// client is TELLING this server what its URIs are: catching `http://` here
// means the client author finds out at registration rather than at the first
// authorization request, which is a different afternoon.
// ---------------------------------------------------------------------------
function checkClientRegistration(metadata) {
  log.debug("Entering checkClientRegistration().");
  if (!enabled()) {
    log.debug("Leaving checkClientRegistration(). RFC 9700 mode is off.");
    return { ok: true };
  }
  const meta = metadata || {};
  const grants = Array.isArray(meta.grant_types) ?
                 meta.grant_types.map(String) : [];
  if (grants.indexOf('password') >= 0) {
    log.debug("Leaving checkClientRegistration(). It asked for the password " +
              "grant.");
    return { ok: false, errorCode: 'STS-OAUTH-0132',
             error: 'invalid_client_metadata', requirement: 'no-ropc',
             description: 'RFC 9700 section 2.4: the resource owner password ' +
                          'credentials grant MUST NOT be used, so this ' +
                          'server will not register a client for it. It ' +
                          'hands the End-User\'s password to the client, it ' +
                          'cannot carry a second factor — no WebAuthn, no ' +
                          'step-up, nothing a browser does — and there is no ' +
                          'way to make it safe. Register for ' +
                          'authorization_code and use PKCE.' };
  }
  if (grants.indexOf('implicit') >= 0) {
    log.debug("Leaving checkClientRegistration(). It asked for the implicit " +
              "grant.");
    return { ok: false, errorCode: 'STS-OAUTH-0133',
             error: 'invalid_client_metadata', requirement: 'no-implicit',
             description: 'RFC 9700 section 2.1.2: the implicit grant issues ' +
                          'an access token from the authorization endpoint, ' +
                          'where it travels through the browser and lands in ' +
                          'history, logs and referrers. This server refuses ' +
                          'those response types, so it will not register a ' +
                          'client for the grant either. Register for ' +
                          'authorization_code.' };
  }
  const responses = Array.isArray(meta.response_types) ?
                    meta.response_types.map(String) : [];
  const withToken = responses.filter(function (one) {
    return one.split(/\s+/).indexOf('token') >= 0;
  });
  if (withToken.length) {
    log.debug("Leaving checkClientRegistration(). A response type issues an " +
              "access token.");
    return { ok: false, errorCode: 'STS-OAUTH-0134',
             error: 'invalid_client_metadata', requirement: 'no-implicit',
             description: 'RFC 9700 section 2.1.2: a response type that ' +
                          'issues an access token from the authorization ' +
                          'endpoint is refused there, so it is refused here ' +
                          '— registering for ' +
                          '"' + withToken.join('", "') + '" ' +
                          'would record a permission this server will never ' +
                          'honour. `code` and `code id_token` issue no ' +
                          'access token from that endpoint and are ' +
                          'registrable.' };
  }
  // PRODUCT MODE: A PUBLIC CLIENT MAY NOT REGISTER FOR client_credentials
  // (2026-09-17). OAuth 2.1 refuses the same combination in its own mode
  // (`oauth21.registrationRefusal()`, just below), and product mode refuses it
  // for the reason the token endpoint does: RFC 6749 section 4.4 defines that
  // grant for a client that HAS credentials. Written here rather than by
  // loosening OAuth 2.1's gate, because it is a PRODUCT-MODE rule and not part
  // of the BCP — plain `oauth2.rfc9700` mode is unchanged, and a reader who
  // found this under OAuth 2.1's function would conclude the opposite.
  //
  // THE REGISTRATION DOOR IS NOT THE ONLY DOOR. A client can be created from
  // `/admin/applications`, `/admin-api` or an `ldapmodify`, none of which
  // comes through here, which is why the token endpoint refuses the grant as
  // well rather than trusting this.
  if (mode.requiresConfidentialClientAuthentication() &&
      String(meta.token_endpoint_auth_method || '').trim() === 'none' &&
      grants.indexOf('client_credentials') >= 0) {
    log.debug("Leaving checkClientRegistration(). Product mode: " +
              "client_credentials for a public client.");
    return { ok: false, errorCode: 'STS-OAUTH-0552',
             error: 'invalid_client_metadata',
             requirement: 'client-credentials-confidential-only',
             description: 'RFC 6749 section 4.4: the client credentials ' +
                          'grant is for a client that HAS credentials, and ' +
                          'this registration asks for it with ' +
                          'token_endpoint_auth_method="none". In product ' +
                          'mode a public client may register for the ' +
                          'authorization code and refresh grants; declare a ' +
                          'confidential token_endpoint_auth_method to use ' +
                          'the client credentials grant.' };
  }

  // OAuth 2.1's own registration mirrors — SAML client authentication and a
  // public client asking for client_credentials.
  const stricter = oauth21.registrationRefusal(meta);
  if (stricter) {
    log.debug("Leaving checkClientRegistration(). OAuth 2.1 (" +
              stricter.requirement + ").");
    return stricter;
  }
  const uris = Array.isArray(meta.redirect_uris) ?
               meta.redirect_uris.map(String) : [];
  for (let i = 0; i < uris.length; i++) {
    const parsed = parseUri(uris[i]);
    if (!parsed) {
      log.debug("Leaving checkClientRegistration().");
      return { ok: false, errorCode: 'STS-OAUTH-0135',
               error: 'invalid_redirect_uri',
               requirement: 'redirect-exact-match',
               description: 'RFC 9700 section 2.1: a redirect URI must be an ' +
                            'absolute URI. "' +
                            uris[i] + '" is not one.' };
    }
    if (parsed.protocol === 'http:' && !isLoopbackHost(parsed.hostname)) {
      log.debug("Leaving checkClientRegistration(). An http redirect URI off " +
                "the loopback.");
      return { ok: false, errorCode: 'STS-OAUTH-0136',
               error: 'invalid_redirect_uri',
               requirement: 'http-scheme-refused',
               description: 'RFC 9700 section 2.6: an authorization server ' +
                            'must not allow a redirect URI using the http ' +
                            'scheme, except for a native application ' +
                            'redirecting to a loopback address. ' +
                            '"' + uris[i] + '" ' +
                            'is neither, and registering it would record a ' +
                            'URI the authorization endpoint would then ' +
                            'refuse.' };
    }
  }
  log.debug("Leaving checkClientRegistration(). Nothing refused.");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// SECTION 2.5 — client authentication, and the ONE place this service checks a
// credential.
//
// In development mode, everywhere else it deliberately checks none: any
// password signs anybody in, any bind succeeds, any client secret is accepted
// (product mode is a different axis — `common/mode.js`). Section 2.5 is not a
// blanket "authenticate clients" — it is conditioned on it being *feasible* to
// have a process for issuing credentials, and this service has one at
// POST /oauth2/register, which mints a client_secret and hands it back. For a
// client that went through it, the secret is on file and checking it is
// possible; for a client_id this service has never seen there is nothing to
// check, and a refusal invented for one would be theatre rather than
// compliance.
//
// So the rule is narrow and its edges are the interesting part:
//
//   * REGISTERED and CONFIDENTIAL — the credential its method names must be
//     presented and must verify. Confidential means a
//     token_endpoint_auth_method other than "none", with RFC 7591 section 2's
//     default (client_secret_basic) applying when the registration omitted it.
//     This is the same test isConfidential() makes for the PKCE rule, and it
//     must stay one function: a client that is public for PKCE and
//     confidential for authentication would be exempt from both.
//   * REGISTERED and PUBLIC — nothing to authenticate with, by definition. A
//     secret sent anyway is ignored rather than refused; RFC 6749 section 3.2.1
//     asks the server not to rely on one, not to reject one. (OAuth 2.1 mode
//     does refuse it — its section 3.2.2, in `oauth21.js`.)
//   * REGISTERED and CONFIDENTIAL with NOTHING ON FILE for its method — not
//     refused (see `credentialOnFile()` below); a half-configured client, and
//     the log line says so. Every one of the six methods is VERIFIED when there
//     is something to verify against; the assertion methods used to be
//     accepted unverified, and `asymmetric-client-auth` records that change.
//   * NOT REGISTERED — untouched, in this mode as in any other.
//
// The comparisons are timing-safe and they live in `client_auth.js` with the
// rest of the mechanics. On a mock whose Kerberos passwords are printed on a
// web page that is close to decorative, and they are written that way anyway:
// somebody will copy them.
// ---------------------------------------------------------------------------

// WHETHER A CONFIDENTIAL CLIENT HAS ANYTHING ON FILE TO CHECK ITS METHOD
// AGAINST. One function, because the observation and the policy below it and
// OAuth 2.1's PKCE exemption all ask it — and they were two inline copies of
// one expression until 2026-09-13, which is the shape that disagrees the first
// time a method is added.
function credentialOnFile(registered) {
  log.debug("Entering credentialOnFile().");
  if (!registered || !isConfidential(registered)) {
    log.debug("Leaving credentialOnFile(). Not a confidential client.");
    return false;
  }
  const method = String(registered.token_endpoint_auth_method).trim();
  const have =
    (clientAuth.SYMMETRIC_METHODS.indexOf(method) >= 0 &&
     registered.client_secret) ||
    (method === 'private_key_jwt' && (registered.jwks || registered.jwks_uri ||
                                      registered.assertion_jwks)) ||
    // RFC 7522 section 2.2. The two SAML attributes and NEITHER of the three
    // above: a client holding a JWT key pair and no SAML certificate has
    // nothing on file for this method, which is the whole point of the two
    // sets being separate.
    (method === 'saml2_bearer' && (registered.saml_signing_certificate ||
                                   registered.saml_assertion_certificate)) ||
    // RFC 8705 section 2.1 ALWAYS has something to check since 2026-09-13:
    // a certificate this realm issued to the application needs nothing
    // registered, so a `tls_client_auth` client is never "confidential with
    // nothing on file" — which is what let one through unauthenticated in
    // RFC 9700 mode when it had no subject DN.
    method === 'tls_client_auth' ||
    // Section 2.2 as well: a client that DECLARED a certificate method is held
    // to it (`mtls.declaredRefusal()`), so "nothing on file" must not be the
    // quiet pass it is for a half-configured secret client — `client_auth.js`
    // refuses it by name (STS-OAUTH-0015), which is the sentence that says
    // what to register.
    method === 'self_signed_tls_client_auth';
  log.debug("Leaving credentialOnFile().");
  return !!have;
}

// ASYNCHRONOUS BECAUSE clientAuth.verify() IS, which is because a
// `private_key_jwt` assertion may be signed with one of the eleven
// post-quantum algorithms this service advertises for client authentication —
// seconds of computation on the thread that owns every listener here. See
// common/worker.js. What this function DECIDES is unchanged: the policy is
// still this module's and the mechanics are still client_auth.js's.
// ---------------------------------------------------------------------------
// WHAT THIS REQUEST DEMONSTRATED ABOUT THE CLIENT — AN OBSERVATION, NEVER A
// REFUSAL (2026-09-05).
//
// `checkClientAuthentication()` below is POLICY: it decides whether this
// client was REQUIRED to authenticate and refuses it if it did not. This is
// the FACT underneath that decision — did the client, on this request,
// present a credential that verified — and it is a different question with a
// different audience.
//
// **IT EXISTS BECAUSE THE ROLE GATE ASKS A QUESTION RFC 9700 MODE DOES NOT.**
// `ALL_AUTHENTICATED_APPLICATIONS` and `ALL_UNAUTHENTICATED_APPLICATIONS` are
// about what the client IS, and that is true whether or not this service has
// been asked to enforce the BCP. A mock with `oauth2.rfc9700` off still knows
// perfectly well that a client sent a matching secret; refusing to notice
// would make those two roles unusable in the default configuration, which is
// the configuration almost everything here runs in.
//
// **THE FOUR "no" ANSWERS ARE KEPT APART**, because they are four different
// facts and a caller that collapsed them would report the wrong one:
//
//   * no entry here at all — this service has never seen the client_id;
//   * a PUBLIC client — `token_endpoint_auth_method` is `none` or absent, so
//     there is nothing to prove and not proving it is correct. This is the one
//     that ALL_UNAUTHENTICATED_APPLICATIONS is actually about;
//   * confidential with NOTHING ON FILE to check against — half-configured,
//     which `checkClientAuthentication()` deliberately does not refuse;
//   * confidential, credential presented, and it did not verify.
//
// Only the fourth is a failure. The others are all "no" and none of them is a
// fault, which is why this function has no `ok` field at all — an `ok` would
// invite a caller to treat a public client as a problem.
//
// **IT IS NOT MODE-GATED AND IT IS NOT FREE.** For a confidential client it
// performs the same verification `checkClientAuthentication()` performs, so a
// token request from one now does that work whether or not the BCP mode is on.
// That is affordable here — it is one signature check on a request that is
// about to mint several — and the alternative was a third state, "we did not
// look", which every caller would have had to decide what to do about.
// ---------------------------------------------------------------------------
async function observeClientAuthentication(opts) {
  log.debug("Entering observeClientAuthentication(). client=" +
            (opts.clientId || '?'));
  const registered = opts.registered;
  if (!registered || !registered.known) {
    log.debug("Leaving observeClientAuthentication(). No entry here.");
    return { authenticated: false, method: '', errorCode: 'STS-OAUTH-0193',
             why: 'this service has no entry for this client, so there was ' +
                  'nothing to authenticate it against.' };
  }
  // AN ENTRY THAT DECLARES NO METHOD IS NOT A PUBLIC CLIENT, and until
  // 2026-09-18 this said it was: the two cases shared one branch and one
  // sentence — "declares none (or none at all)" — while product mode's gate
  // (`declaredPublic()`) reads an omission as RFC 7591 section 2's
  // client_secret_basic and REFUSES it. So the refusal a person read called
  // their client public in the same line that refused it for not being
  // public. The observation is unchanged (neither presented a credential and
  // neither authenticated); what differs is the sentence and the code, so
  // the refusal says which field to set.
  if (!isConfidential(registered) &&
      String(registered.token_endpoint_auth_method || '').trim() === '') {
    log.debug("Leaving observeClientAuthentication(). No method declared.");
    return { authenticated: false, method: 'none', errorCode: 'STS-OAUTH-0553',
             why: 'its entry declares NO token_endpoint_auth_method. ' +
                  'Development mode reads that as a public client; product ' +
                  'mode reads it as RFC 7591 section 2\'s default, ' +
                  'client_secret_basic, so it must present a credential, ' +
                  'and it presented none. Set the application\'s ' +
                  'oauthTokenEndpointAuthMethod to "none" for a public ' +
                  'client (held to PKCE), or give it a credential and the ' +
                  'method that presents it.' };
  }
  if (!isConfidential(registered)) {
    log.debug("Leaving observeClientAuthentication(). A public client.");
    return { authenticated: false, method: 'none', errorCode: 'STS-OAUTH-0194',
             why: 'this is a PUBLIC client: its entry declares ' +
                  'token_endpoint_auth_method="none", so it has no ' +
                  'credential to present and presenting none is correct.' };
  }
  const method = String(registered.token_endpoint_auth_method).trim();
  const haveCredential = credentialOnFile(registered);
  if (!haveCredential) {
    log.debug("Leaving observeClientAuthentication(). Confidential with " +
              "nothing on file.");
    return { authenticated: false, method: method, errorCode: 'STS-OAUTH-0195',
             why: 'this client is configured as confidential ' +
                  '(token_endpoint_auth_method=' + method + ') and has ' +
                  'nothing on its entry to verify that method against, so ' +
                  'nothing could be checked.' };
  }
  const checked = await clientAuth.verify({
    method: method,
    clientId: opts.clientId,
    request: opts.request,
    audiences: opts.audiences || [],
    // OAuth 2.1 mode's issuer-as-sole-audience rule — the issuer, or empty.
    strictAudience: opts.strictAudience || '',
    presentedSecret: opts.clientSecret,
    assertion: opts.assertion,
    assertionType: opts.assertionType,
    clientSecret: registered.client_secret,
    jwks: registered.jwks,
    jwksUri: registered.jwks_uri,
    // What this service ISSUED this client from its own certificate
    // authority. See client_auth.js: two attributes, ORed, because both were
    // arranged deliberately.
    assertionJwks: registered.assertion_jwks,
    // RFC 7522's two, for `saml2_bearer`. Separate members rather than a
    // fallback into the three above: `saml_assertion_grant.js` verifies only
    // against these, and merging them would be the crossing its header
    // refuses.
    samlSigningCertificate: registered.saml_signing_certificate,
    samlAssertionCertificate: registered.saml_assertion_certificate,
    samlAssertionCertificateChain: registered.saml_assertion_certificate_chain,
    subjectDn: registered.tls_client_auth_subject_dn,
    // RFC 8705 section 2.1.2's five, read off the config by member name, and
    // the entry's identifier for the implicit mapping (2026-09-13).
    tlsSubjects: registered,
    applicationIdentifier: registered.identifier,
    certificateThumbprint: registered.certificate_thumbprint
  });
  if (!checked.ok) {
    log.debug("Leaving observeClientAuthentication(). It did not verify.");
    return { authenticated: false, method: method, why: checked.description,
             errorCode: checked.errorCode || 'STS-OAUTH-0137' };
  }
  log.debug("Leaving observeClientAuthentication(). Authenticated by " +
            method + ".");
  return { authenticated: true, method: method, alg: checked.alg || '',
           why: 'it authenticated with ' + method + '.' };
}

async function checkClientAuthentication(opts) {
  log.debug("Entering checkClientAuthentication().");
  const registered = opts.registered;
  if (!enabled() || !registered || !registered.known) {
    log.debug("Leaving checkClientAuthentication(). " +
              (enabled() ? "This client has no entry here." : "RFC 9700 mode " +
                  "is off."));
    return { ok: true };
  }
  if (!isConfidential(registered)) {
    log.debug("Leaving checkClientAuthentication(). The client is public.");
    return { ok: true };
  }
  const method = String(registered.token_endpoint_auth_method).trim();

  // A confidential client with NOTHING ON FILE to check against is not refused:
  // there is nothing to compare, and inventing a refusal for one would be
  // theatre — the same reasoning that leaves a client_id this service has never
  // seen alone. It happens for an application created by hand and given a
  // method but no credential, which is a half-configured client rather than a
  // wrong one, and the log line says which.
  const haveCredential = credentialOnFile(registered);
  if (!haveCredential) {
    log.warn('RFC 9700 section 2.5: client "' + (opts.clientId || '(unnamed)') +
             '" ' +
             'is configured as confidential ' +
             '(token_endpoint_auth_method=' + method + ') ' +
             'and has nothing on its entry to verify that method against, so ' +
             'there is nothing to check. Give it the credential that method ' +
             'needs on /admin/applications — a client_secret, a jwks, a ' +
             'subject DN or a certificate thumbprint.');
    log.debug("Leaving checkClientAuthentication(). Confidential with no " +
              "credential on file.");
    return { ok: true };
  }

  // The mechanics are `client_auth.js`'s and the POLICY is this module's, which
  // is the same split every other check here follows. What this file decides is
  // whether authentication is REQUIRED of this client at all (section 2.5's
  // "where feasible"); what that file decides is whether what arrived proves
  // it.
  const checked = await clientAuth.verify({
    method: method,
    clientId: opts.clientId,
    request: opts.request,
    audiences: opts.audiences || [],
    // OAuth 2.1 mode's issuer-as-sole-audience rule — the issuer, or empty.
    strictAudience: opts.strictAudience || '',
    presentedSecret: opts.clientSecret,
    assertion: opts.assertion,
    assertionType: opts.assertionType,
    clientSecret: registered.client_secret,
    jwks: registered.jwks,
    jwksUri: registered.jwks_uri,
    // What this service ISSUED this client from its own certificate
    // authority. See client_auth.js: two attributes, ORed, because both were
    // arranged deliberately.
    assertionJwks: registered.assertion_jwks,
    // RFC 7522's two, for `saml2_bearer`. Separate members rather than a
    // fallback into the three above: `saml_assertion_grant.js` verifies only
    // against these, and merging them would be the crossing its header
    // refuses.
    samlSigningCertificate: registered.saml_signing_certificate,
    samlAssertionCertificate: registered.saml_assertion_certificate,
    samlAssertionCertificateChain: registered.saml_assertion_certificate_chain,
    subjectDn: registered.tls_client_auth_subject_dn,
    // RFC 8705 section 2.1.2's five, read off the config by member name, and
    // the entry's identifier for the implicit mapping (2026-09-13).
    tlsSubjects: registered,
    applicationIdentifier: registered.identifier,
    certificateThumbprint: registered.certificate_thumbprint
  });
  if (!checked.ok) {
    log.debug("Leaving checkClientAuthentication(). The client did not " +
              "authenticate.");
    return { ok: false, errorCode: checked.errorCode || 'STS-OAUTH-0137',
             error: 'invalid_client', requirement: 'client-authentication',
             description: 'RFC 9700 section 2.5: this client\'s entry in the ' +
                          'application registry declares ' +
                          'token_endpoint_auth_method=' + method + ', ' +
                          'so it must authenticate — ' +
                          'and ' + checked.description };
  }

  // RECOMMENDED, so it is a line in the log and not a refusal. It is worth
  // writing every time rather than once: the point of the recommendation is
  // that a shared secret is a credential the SERVER also holds, and a log that
  // said so only on the first request would leave the fact where nobody looks.
  if (!clientAuth.isAsymmetric(method)) {
    log.info('RFC 9700 section 2.5: client "' + (opts.clientId || '(unnamed)') +
             '" ' +
             'authenticated with a SHARED SECRET (' + method + '). ' +
             'Asymmetric client authentication is what that section ' +
             'RECOMMENDS — private_key_jwt, or one of the RFC 8705 ' +
             'certificate methods — because this server is holding a copy of ' +
             'that secret on behalf of the client, and a public key would be ' +
             'worth nothing to anybody who read it. ' +
             'All ' + clientAuth.ASYMMETRIC_METHODS.length + ' ' +
             'asymmetric methods are verified ' +
             'here: ' + clientAuth.ASYMMETRIC_METHODS.join(', ') + '.');
  } else {
    log.info('RFC 9700 section 2.5: client "' + (opts.clientId || '(unnamed)') +
             '" ' +
             'authenticated ASYMMETRICALLY (' + method +
             (checked.alg ? ', alg=' + checked.alg : '') + '), which is what ' +
             'that section recommends. This server holds no secret of this ' +
             'client\'s.');
  }
  log.debug("Leaving checkClientAuthentication(). Authenticated by " + method +
            ".");
  return { ok: true, method: method };
}

// ---------------------------------------------------------------------------
// SECTION 2.2.2 — REFRESH TOKENS, which is where most of this iteration's
// substance is.
//
// A refresh token here is a signed JWT with a `jti` (encrypted to its realm
// since 2026-09-12 — `refresh_token_crypto.js`), and until this mode
// existed it was reusable for the whole of its life — twenty-four hours on the
// default `oauth2.refreshTokenTtlS`, and thirty days before that setting
// existed: redeeming one minted a new one and left the old one working. Section
// 2.2.2 requires public clients' refresh tokens to be sender-constrained OR
// rotated, and this server cannot authenticate a client it did not register —
// so ROTATION is applied to every client, which is the safe reading of an
// unknown one.
//
// Rotation alone is only half of it. The reason a rotated token is worth
// remembering rather than merely revoking is REPLAY DETECTION: a retired token
// coming back means the chain has been copied, and nothing here can tell
// whether the legitimate client or the attacker is holding it — which is
// precisely why the answer is to invalidate both. So the lineage is kept: every
// refresh token minted from another belongs to its parent's FAMILY, and a
// replay revokes the family.
//
// Three decisions in that are load-bearing.
//
// **The family is remembered by ISSUANCE, not by chain-walking at check time.**
// A chain twenty refreshes long is one family, one lookup and one revocation
// pass. Walking parent pointers on a replay would work too, until a client
// refreshed often enough for the walk to be the slowest thing at the endpoint.
//
// **ACCESS tokens are not revoked with the family.** They expire in an hour,
// and revoking them would take away the evidence — the console's token list is
// how somebody sees what the lost credential was used for. The refresh chain is
// what section 2.2.2 is about and it is what gets invalidated.
//
// **This module never revokes anything itself.** It returns the jtis and
// `oauth2.js` calls `stats.revoke()`, which is the one revocation set
// /oauth2/revoke and the console also write to. That keeps the one-store rule
// intact and keeps this module's own rule — it decides, the protocol acts.
//
// Bounded like the transaction store: a family is forgotten once every token in
// it is past a refresh token's own lifetime, and the store is capped. A
// forgotten family is a check not made, never a false refusal.
// ---------------------------------------------------------------------------
// How long a family is remembered for, which must be at least as long as the
// tokens in it live. It was `30 * 24 * 3600 * 1000` with a comment saying it
// matched `REFRESH_TOKEN_TTL` in oauth2.js — and that constant is now the
// runtime setting `oauth2.refreshTokenTtlS`, so a fixed number here would have
// been a comment claiming a match that nothing kept. Read per issuance, like
// everything else that reads a setting.
//
// A FLOOR OF ONE HOUR, and it is not a tolerance being generous. The window is
// evaluated when a refresh token is MINTED, so lowering the setting cannot
// shorten a window already granted, but raising it after a mint could leave a
// family forgotten while its tokens are still presentable — and a forgotten
// family is a check not made rather than a false refusal (see the header
// above), which is the safe direction but is also the check silently not
// happening. An hour of slack costs one Map entry and keeps the ordinary case
// — somebody dropping the lifetime to a minute to watch a rotation — from
// discarding the very bookkeeping they are trying to watch.
function refreshFamilyWindowMs() {
  log.debug("Entering refreshFamilyWindowMs().");
  log.debug("Leaving refreshFamilyWindowMs().");
  // The SERVICE-WIDE value on purpose, not a per-client one: this window
  // decides how long the family bookkeeping is KEPT, and a family may hold
  // tokens from more than one client. The longest lifetime any client could
  // have is what would be safe to use here, and the service-wide value is
  // the closest thing to it that does not mean scanning every application on
  // every sweep. A client configured with a LONGER lifetime than the default
  // therefore loses its replay bookkeeping early, which is the safe
  // direction — the check stops happening rather than refusing wrongly — and
  // is the same trade-off the hour of slack below already makes.
  return Math.max(config.value('oauth2.refreshTokenTtlS') * 1000, 3600 * 1000);
}
// ---------------------------------------------------------------------------
// THE CAP IS `oauth2.maxRefreshTokenFamilies` SINCE 2026-09-12, AND WHAT IS
// DROPPED WHEN IT IS REACHED CHANGED WITH IT.
//
// It dropped the OLDEST entry whatever it was — so a busy realm forgot the
// bookkeeping of refresh tokens that were still presentable, and a copied
// chain's replay went undetected as a replay. The item-6 rule for the
// assertion caches is "never forget a live entry; refuse instead", and it
// cannot be applied here word for word: this is called AFTER the token is
// signed and handed to the grant, and refusing to ISSUE a refresh token
// because the bookkeeping is full would turn a busy service into one that
// signs nobody in. So the trade is stated rather than hidden, in three steps:
//
//   1. EXPIRED entries go first — they are presentable nowhere.
//   2. Then ROTATED ones, oldest first. A rotated token has already been
//      REVOKED through `stats.revoke()`, so a replay of it is still refused;
//      what forgetting its record loses is the FAMILY revocation that
//      replay would otherwise trigger. That is the smallest loss available.
//   3. Only when every remembered token is live and unrotated is the oldest
//      of those forgotten, with a warning naming the setting. Its next
//      redemption starts a new family rather than extending the old one, and
//      a later replay of it is still refused as revoked.
//
// `MAX_REFRESH_TOKENS` is the default, kept under its old name.
// ---------------------------------------------------------------------------
const MAX_REFRESH_TOKENS = 2000;

function maxRefreshTokens() {
  log.debug("Entering maxRefreshTokens().");
  const count = Number(config.value('oauth2.maxRefreshTokenFamilies'));
  log.debug("Leaving maxRefreshTokens().");
  return isFinite(count) && count > 0 ? Math.floor(count) : MAX_REFRESH_TOKENS;
}
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// jti -> { family, clientId, rotated, forget }
//
// TOMBSTONED AND MERGED (2026-09-14, #46): a forgotten record's delete leaves a
// tombstone so an older copy cannot be written back, and `rotated` only moves
// forward — a node that had not yet heard of a rotation must not write the
// record back as unrotated, which would make the replay it marks undetectable.
const refreshTokens = realms.map({
  persist: 'oauth2_bcp.refreshTokens', tombstone: true,
  mergeRow: function (mine, theirs) {
    log.debug("Entering mergeRow().");
    log.debug("Leaving mergeRow().");
    if (!mine || !theirs || typeof mine !== 'object') {
      return mine || theirs;
    }
    return Object.assign({}, mine,
                         { rotated: !!(mine.rotated || theirs.rotated) });
  }
});
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// family -> { clientId, forget, lastUsedAt } — no `members` array since #46
// (see `membersOf()`); a row restored from an older build may still carry one.
const refreshFamilies = realms.map({ persist: 'oauth2_bcp.refreshFamilies' });

function forgetStaleRefreshTokens() {
  log.debug("Entering forgetStaleRefreshTokens().");
  const now = Date.now();
  refreshTokens.forEach(function (record, jti) {
    if (record.forget < now) {
      refreshTokens.delete(jti);
    }
  });
  refreshFamilies.forEach(function (family, id) {
    if (family.forget < now) {
      refreshFamilies.delete(id);
    }
  });
  const cap = maxRefreshTokens();
  if (refreshTokens.size > cap) {
    // Step 2: retired tokens, oldest first (a Map iterates in insertion order).
    const rotated = [];
    refreshTokens.forEach(function (record, jti) {
      if (record.rotated) rotated.push(jti);
    });
    for (let i = 0; i < rotated.length && refreshTokens.size > cap; i++) {
      refreshTokens.delete(rotated[i]);
    }
  }
  let droppedLive = 0;
  while (refreshTokens.size > cap) {
    // Step 3: the oldest live one, loudly.
    const oldest = refreshTokens.keys().next();
    if (oldest.done) {
      break;
    }
    refreshTokens.delete(oldest.value);
    droppedLive++;
  }
  if (droppedLive) {
    log.warn('RFC 9700 mode: ' + droppedLive + ' LIVE refresh token ' +
             'record(s) were forgotten because ' +
             'oauth2.maxRefreshTokenFamilies (' + cap + ') ' +
             'is full of unexpired, unrotated tokens. Those tokens still ' +
             'work and a replay of a rotated one is still refused as ' +
             'revoked, but a replay will no longer revoke its whole family. ' +
             'Raise the setting.');
  }
  log.debug("Leaving forgetStaleRefreshTokens(). " + refreshTokens.size + " " +
      "remembered in " +
            refreshFamilies.size + " family/families.");
}

// ---------------------------------------------------------------------------
// THE FAMILY ACROSS NODES (2026-09-14, #46) — three things were wrong, and
// each is the store converging where the rule needed it to agree.
//
//   1. **A CHILD WHOSE PARENT THIS NODE HAD NOT HEARD OF STARTED A FAMILY OF
//      ITS OWN.** The family was found by looking the parent's jti up here, so
//      a parent record not yet replicated (or dropped by the cap) split the
//      chain, and a later replay revoked half of it. So the family id now
//      travels IN THE REFRESH TOKEN (`FAMILY_CLAIM`, RFC 9700 mode only, inside
//      the JWE where no client reads it), and `familyForIssuance()` prefers
//      what the parent's own token says.
//   2. **`family.members.push()` LOST MEMBERS.** The family row is written
//      whole, so two nodes each adding a child wrote back two arrays with one
//      child each, and the last writer won. Membership is no longer stored as
//      an array: every token's OWN record (`refreshTokens`, one key per jti)
//      names its family, and `membersOf()` derives the list. Two nodes writing
//      two different keys cannot lose either. A `members` array on a row
//      restored from an older build is still read.
//   3. **A REPLAY REVOKED THE MEMBERS ONE NODE KNEW.** A child minted on
//      another node in the same instant is in nobody's list yet. So a replay
//      now also revokes the FAMILY BY ID — a claim in the scope
//      `oauth.refresh-family-revoked`, which every node sees at once — and
//      `spendRefreshToken()` refuses any token whose family carries it. The
//      member nobody listed is refused at its first use instead of at the
//      replay, which is the same outcome one request later.
// ---------------------------------------------------------------------------
const FAMILY_CLAIM = 'refresh_family';

// The family a refresh token about to be minted belongs to. `parentFamily` is
// the presented token's own `refresh_family` claim, where it has one.
function familyForIssuance(jti, parentJti, parentFamily) {
  log.debug("Entering familyForIssuance().");
  const parent = parentJti ? refreshTokens.get(String(parentJti)) : null;
  // The root's own jti names the family. It needs no randomness of its own and
  // it makes a family identifiable in a log line without a second lookup.
  const familyId = String(parentFamily || '') ||
                   (parent && parent.family) || String(jti);
  log.debug("Leaving familyForIssuance(). family=" + familyId);
  return familyId;
}

// Every jti this node knows to be in a family: the per-token records, and a
// legacy `members` array where a restored row still carries one.
function membersOf(familyId, alsoJti) {
  log.debug("Entering membersOf().");
  const wanted = String(familyId || '');
  const out = new Set();
  if (alsoJti) {
    out.add(String(alsoJti));
  }
  if (wanted) {
    refreshTokens.forEach(function (record, jti) {
      if (record && record.family === wanted) {
        out.add(String(jti));
      }
    });
    const family = refreshFamilies.get(wanted);
    if (family && Array.isArray(family.members)) {
      family.members.forEach(function (jti) {
        out.add(String(jti));
      });
    }
  }
  log.debug("Leaving membersOf(). " + out.size + " member(s).");
  return Array.from(out);
}

// Called from refreshToken() in oauth2.js — the single function that mints one,
// which is why there is no per-grant call site to forget. `parentJti` is empty
// for the root of a family (any grant minting its first refresh token) and is
// the presented token's jti on a refresh; `parentFamily` is that token's own
// `refresh_family` claim.
function noteRefreshIssued(jti, parentJti, clientId, parentFamily) {
  log.debug("Entering noteRefreshIssued(). jti=" + jti + ", parent=" +
            (parentJti || '(root)'));
  // ROTATION IS NO LONGER THE MODE'S ALONE (#34, 2026-09-15): the bookkeeping
  // runs whenever rotation is required, which is either compliance mode OR
  // `oauth2.refreshTokenRotation`. Everything else in this file still asks
  // `enabled()`, because everything else in this file is an RFC 9700 rule.
  if (!senderConstraints.rotationRequired() || !jti) {
    log.debug("Leaving noteRefreshIssued(). " +
              (senderConstraints.rotationRequired() ? "No jti."
                                                    : "Rotation is off."));
    return;
  }
  const familyId = familyForIssuance(jti, parentJti, parentFamily);
  const forget = Date.now() + refreshFamilyWindowMs();
  refreshTokens.set(String(jti),
                    { family: familyId, clientId: String(clientId || ''),
                                   rotated: false, forget: forget });
  const known = refreshFamilies.get(familyId);
  // NO `members` ARRAY IS WRITTEN — see (2) above. What the row still holds
  // is the family's clock, and a lost update of either field between two
  // nodes costs a few seconds of it rather than a member.
  const family = known
    ? Object.assign({}, known, { forget: forget })
    : { clientId: String(clientId || ''), forget: forget,
        // When any token in this chain was last redeemed, for the IDLE
        // timeout. Measured on the FAMILY rather than on each token, because
        // the requirement is about a client that has gone quiet and a client
        // that refreshes hourly has not — per-token it would be an absolute
        // lifetime wearing a different name.
        lastUsedAt: Date.now() };
  refreshFamilies.set(familyId, family);
  forgetStaleRefreshTokens();
  log.debug("Leaving noteRefreshIssued(). Family " + familyId + ".");
}

// How long a family revoked by a replay stays revoked: as long as any member
// minted before the revocation could still be presented. The window is the
// family bookkeeping's own, and the client's lifetime where it is longer.
function familyRevocationTtlMs(clientId) {
  log.debug("Entering familyRevocationTtlMs().");
  const perClient = Number(applications.settingFor(String(clientId || ''),
                                                   'oauth2.refreshTokenTtlS',
                                                   config));
  const skew = Number(config.value('oauth2.clockSkewS'));
  log.debug("Leaving familyRevocationTtlMs().");
  return Math.max(refreshFamilyWindowMs(),
                  isFinite(perClient) ? perClient * 1000 : 0) +
         (isFinite(skew) ? skew * 1000 : 0);
}

// Revokes a family BY ID, for every node at once. Resolves whether the mark is
// in place; never rejects. A mark that could not be written is logged — the
// members this node knew are still revoked by the caller.
function revokeFamily(familyId, clientId) {
  log.debug("Entering revokeFamily(). family=" + familyId);
  if (!familyId) {
    log.debug("Leaving revokeFamily(). No family.");
    return Promise.resolve(false);
  }
  log.debug("Leaving revokeFamily(). Claiming the mark.");
  return clusterClaims.claim({
    scope: 'oauth.refresh-family-revoked', value: String(familyId),
    ttlMs: familyRevocationTtlMs(clientId)
  }).then(function (answer) {
    if (answer.ok || answer.reason === 'used') {
      return true;
    }
    log.error(errorCodes.tag('STS-OAUTH-0518') + 'RFC 9700 mode: refresh ' +
              'family ' + familyId + ' could not be revoked by id, because ' +
              'the claim store could not be asked (' + (answer.why || '') +
              '). The members this node knows are revoked; one minted on ' +
              'another node at the same moment may not be.');
    return false;
  });
}

// ---------------------------------------------------------------------------
// THE REDEMPTION OF A ROTATED REFRESH TOKEN, ONCE ACROSS THE CLUSTER (#46).
//
// **WHAT WAS WRONG.** `noteRefreshRotated()` marks the presented token after
// the new set is minted, and `checkRefreshRequest()` refuses a token carrying
// the mark. The mark is a write to a store that reaches another node a moment
// later — and even in one process the mint is an `await` — so two
// redemptions of one token at once both found it unrotated and both were
// issued a fresh chain: the copied-chain case section 2.2.2 exists to catch,
// uncaught.
//
// **WHAT IT IS NOW.** Asked by the refresh grant immediately before the mint,
// after every other refusal:
//
//   * a token whose family carries the revoked-by-id mark is refused
//     (`STS-OAUTH-0517`) and itself revoked;
//   * the token is then spent through `cluster_claims.claim()`, and a claim
//     already held is a REPLAY, answered exactly as the local one is — the
//     family revoked (by id as well as by the members known here) and
//     `STS-OAUTH-0516`;
//   * a store that cannot be asked refuses (`STS-OAUTH-0518`), because a
//     rotated token this service cannot prove unspent is not one it may
//     redeem;
//   * the claim is bound to the response, so a mint that fails gives the
//     token back.
//
// Resolves `{ ok: true }` or a refusal in `checkRefreshRequest()`'s shape,
// with `revoke` and, for a server error, `status: 500`. Never rejects. A no-op
// while rotation is not required (neither compliance mode nor
// `oauth2.refreshTokenRotation`), where a refresh token is reusable by design.
// ---------------------------------------------------------------------------
async function spendRefreshToken(opts) {
  log.debug("Entering spendRefreshToken().");
  if (!senderConstraints.rotationRequired()) {
    log.debug("Leaving spendRefreshToken(). Rotation is off.");
    return { ok: true };
  }
  const o = opts || {};
  const claims = o.claims || {};
  const jti = String(claims.jti || '');
  if (!jti) {
    log.debug("Leaving spendRefreshToken(). No jti to spend.");
    return { ok: true };
  }
  const known = refreshTokens.get(jti);
  const familyId = String((known && known.family) || claims[FAMILY_CLAIM] ||
                          '');
  const clientId = String(claims.client_id || '');
  if (familyId) {
    let revoked = false;
    try {
      revoked = await clusterClaims.isClaimed({
        scope: 'oauth.refresh-family-revoked', value: familyId
      });
    } catch (e) {
      log.debug("Caught in spendRefreshToken(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-OAUTH-0518') + 'RFC 9700 mode: whether ' +
                'refresh family ' + familyId + ' was revoked could not be ' +
                'asked: ' + ((e && e.message) || e) + '. The refresh is ' +
                'refused.');
      log.debug("Leaving spendRefreshToken(). The store failed.");
      return storeRefusal();
    }
    if (revoked) {
      log.warn('RFC 9700 section 2.2.2: refresh token ' + jti + ' belongs ' +
               'to family ' + familyId + ', which a replay has already ' +
               'revoked. Refused, and revoked itself.');
      log.debug("Leaving spendRefreshToken(). The family was revoked.");
      return { ok: false, errorCode: 'STS-OAUTH-0517', error: 'invalid_grant',
               requirement: 'refresh-replay-family',
               family: familyId, clientId: clientId,
               revoke: membersOf(familyId, jti),
               description: 'RFC 9700 section 2.2.2: this refresh token ' +
                            'descends from a grant whose refresh chain was ' +
                            'revoked after a refresh token in it was ' +
                            'presented twice. Start a new authorization ' +
                            'request.' };
    }
  }
  const expiresMs = Number(claims.exp) * 1000;
  const skew = Number(config.value('oauth2.clockSkewS'));
  const answer = await clusterClaims.claim({
    scope: 'oauth.refresh', value: jti,
    ttlMs: (isFinite(expiresMs) ? Math.max(0, expiresMs - Date.now())
                                : refreshFamilyWindowMs()) +
           (isFinite(skew) ? skew * 1000 : 0)
  });
  if (answer.ok) {
    clusterClaims.releaseUnlessSucceeded(o.res, answer.handle);
    log.debug("Leaving spendRefreshToken(). Spent.");
    return { ok: true, handle: answer.handle };
  }
  if (answer.reason !== 'used') {
    log.error(errorCodes.tag('STS-OAUTH-0518') + 'RFC 9700 mode: refresh ' +
              'token ' + jti + ' could not be spent, because the claim store ' +
              'could not be asked (' + (answer.why || '') + '). Refused.');
    log.debug("Leaving spendRefreshToken(). The store failed.");
    return storeRefusal();
  }
  const members = membersOf(familyId, jti);
  log.warn('RFC 9700 section 2.2.2: refresh token ' + jti + ' was redeemed ' +
           'by another request at the same moment, on this node or another. ' +
           'Revoking family ' + (familyId || '(unknown)') + ' by id and the ' +
           members.length + ' member(s) known here — a refresh token ' +
           'redeemed twice means the chain has been copied.');
  log.debug("Leaving spendRefreshToken(). A concurrent replay.");
  return { ok: false, errorCode: 'STS-OAUTH-0516', error: 'invalid_grant',
           requirement: 'refresh-replay-family',
           family: familyId, clientId: clientId, revoke: members,
           description: 'RFC 9700 section 2.2.2: this refresh token was ' +
                        'already redeemed. Presenting it again means the ' +
                        'chain has been copied, and this server cannot tell ' +
                        'the legitimate holder from the attacker — so the ' +
                        'refresh tokens descended from the original grant ' +
                        'have been revoked. Start a new authorization ' +
                        'request.' };
}

function storeRefusal() {
  log.debug("Entering storeRefusal().");
  log.debug("Leaving storeRefusal().");
  return { ok: false, errorCode: 'STS-OAUTH-0518', error: 'server_error',
           status: 500, requirement: 'refresh-once', revoke: [],
           description: 'This authorization server could not record that ' +
                        'the refresh token is being redeemed, so it has not ' +
                        'redeemed it. The token has not been spent; retry.' };
}

// The presented token has just been redeemed, so it is retired. `oauth2.js`
// revokes it; this records that the retirement was a ROTATION, which is what
// makes the difference between "revoked" and "replayed" reportable later.
function noteRefreshRotated(jti) {
  log.debug("Entering noteRefreshRotated(). jti=" + jti);
  if (!senderConstraints.rotationRequired() || !jti) {
    log.debug("Leaving noteRefreshRotated(). Nothing to mark.");
    return;
  }
  const known = refreshTokens.get(String(jti));
  if (known) {
    known.rotated = true;
    // THROUGH THE STORE, for noteRedeemed()'s reason: this is the mark that
    // makes a re-presented refresh token a detected REPLAY, and a mark that
    // does not leave this process is a rotated token another one still accepts.
    refreshTokens.set(String(jti), known);
    // The chain has just been used, which is what the idle timeout measures
    // from. Recorded HERE — at the successful redemption — rather than when the
    // request arrived, so a run of refused attempts cannot keep a chain alive.
    const family = refreshFamilies.get(known.family);
    if (family) {
      family.lastUsedAt = Date.now();
      refreshFamilies.set(known.family, family);
    }
  }
  log.debug("Leaving noteRefreshRotated(). " + (known ? "Marked." : "It was " +
      "not one of ours."));
}

function scopeSet(scope) {
  log.debug("Entering scopeSet().");
  log.debug("Leaving scopeSet().");
  return String(scope || '').split(/\s+/).filter(Boolean);
}

// THIS FUNCTION ANSWERS TWO DIFFERENT QUESTIONS SINCE #34 (2026-09-15), and
// they are switched by different things:
//
//   * the REPLAY of a rotated token, which belongs to rotation and therefore
//     runs whenever `senderConstraints.rotationRequired()` — a service with
//     `oauth2.refreshTokenRotation` on and neither mode on rotates, so it must
//     detect the replay that rotation is FOR. Rotation without replay
//     detection is bookkeeping nobody reads;
//   * the idle timeout, the client binding and the scope check below it, which
//     are RFC 9700 section 2.2.2 and 2.3 rules and stay on `enabled()`.
//
// Keeping them in one function is deliberate: they are all "what this server
// thinks of the refresh token being presented", and a second entry point would
// be two orders for a caller to get right.
function checkRefreshRequest(opts) {
  log.debug("Entering checkRefreshRequest().");
  if (!enabled() && !senderConstraints.rotationRequired()) {
    log.debug("Leaving checkRefreshRequest(). Neither mode nor rotation.");
    return { ok: true };
  }
  const claims = opts.claims || {};
  const body = opts.body || {};
  const presentedClient = String(opts.clientId || '');
  const known = refreshTokens.get(String(claims.jti || ''));

  // Replay first, because it is the most specific thing that can be true of a
  // token and because the ordinary revocation check below would otherwise
  // answer it with "the refresh token was revoked" — accurate, and silent about
  // the fact that a copy of the chain is in circulation.
  if (known && known.rotated) {
    // DERIVED, not read off the family row — see `membersOf()` (#46).
    const members = membersOf(known.family, claims.jti);
    log.warn('RFC 9700 section 2.2.2: refresh token ' + claims.jti + ' was ' +
             'already redeemed and has been presented again. Revoking ' +
             'all ' + members.length + ' ' +
             'refresh token(s) in ' +
             'family ' + known.family + ' — a replayed refresh ' +
             'token means the chain has been copied, and there is no way to ' +
             'tell which holder is the legitimate one.');
    log.debug("Leaving checkRefreshRequest(). Replay detected.");
    return { ok: false, errorCode: 'STS-OAUTH-0138', error: 'invalid_grant',
             requirement: 'refresh-replay-family',
             // So the grant can revoke the family BY ID as well (#46).
             family: known.family, clientId: String(claims.client_id || ''),
             revoke: members,
             description: 'RFC 9700 section 2.2.2: this refresh token was ' +
                          'already redeemed. Presenting it again means the ' +
                          'chain has been copied, and this server cannot ' +
                          'tell the legitimate holder from the attacker — so ' +
                          'all ' + members.length + ' refresh token(s) ' +
                          'descended from the original grant have been ' +
                          'revoked. Start a new authorization request.' };
  }

  // Everything from here down is an RFC 9700 rule rather than a consequence of
  // rotation, so a service rotating because `oauth2.refreshTokenRotation` is
  // on and neither mode is stops here. It rotates and detects a replay; it
  // does not acquire an idle timeout, a client binding it never had, or a
  // scope check, none of which the operator asked for by asking for rotation.
  if (!enabled()) {
    log.debug("Leaving checkRefreshRequest(). Rotation only.");
    return { ok: true };
  }

  // RFC 9700 section 2.2.2's lifetime paragraph: a refresh token SHOULD expire
  // after a period of client INACTIVITY. Measured from the last time any token
  // in this chain was redeemed, so a client that refreshes regularly keeps its
  // grant and one that stops is cut off — which is the difference between an
  // idle timeout and the absolute expiry the token already carries.
  //
  // It is a REFUSAL and not a family revocation: an idle chain is a client that
  // went away, not a chain that was copied, and treating the two alike would
  // make the replay refusal — which says something serious — indistinguishable
  // from an afternoon off.
  // PER CLIENT: the presented client's own `oauthRefreshIdleSeconds` where it
  // has one. A deployment giving a background job a long idle window and a
  // browser client a short one is the ordinary case this serves.
  const idleSeconds = applications.settingFor(presentedClient,
                                             'oauth2.refreshIdleSeconds',
                                             config);
  if (idleSeconds > 0 && known && known.family) {
    const family = refreshFamilies.get(known.family);
    const idleFor = family ?
                    Math.round((Date.now() - (family.lastUsedAt || 0)) / 1000) :
                    0;
    if (family && idleFor > idleSeconds) {
      log.debug("Leaving checkRefreshRequest(). The chain has been idle for " +
                idleFor + "s.");
      return { ok: false, errorCode: 'STS-OAUTH-0139', error: 'invalid_grant',
               requirement: 'refresh-idle-timeout',
               description: 'RFC 9700 section 2.2.2: this refresh token\'s ' +
                            'grant has been unused ' +
                            'for ' + idleFor + ' seconds and this ' +
                            'server expires one ' +
                            'after ' + idleSeconds + ' ' +
                            '(oauth2.refreshIdleSeconds). It is an ' +
                            'INACTIVITY timeout rather than the token\'s own ' +
                            'expiry, so a client that refreshes regularly is ' +
                            'never affected by it. Start a new authorization ' +
                            'request.' };
    }
  }

  // RFC 6749 section 6: client_id is REQUIRED from a public client and the
  // server must check the token was issued to whoever is presenting it.
  if (!presentedClient) {
    log.debug("Leaving checkRefreshRequest(). No client_id came with the " +
              "refresh.");
    return { ok: false, errorCode: 'STS-OAUTH-0140', error: 'invalid_request',
             requirement: 'refresh-client-binding',
             description: 'RFC 6749 section 6: client_id is required on a ' +
                          'refresh request, so that this server can check ' +
                          'the refresh token is being used by the client it ' +
                          'was issued to.' };
  }
  if (claims.client_id && claims.client_id !== presentedClient) {
    log.debug("Leaving checkRefreshRequest(). A different client is " +
              "presenting it.");
    return { ok: false, errorCode: 'STS-OAUTH-0141', error: 'invalid_grant',
             requirement: 'refresh-client-binding',
             description: 'RFC 9700 section 2.2.2: this refresh token was ' +
                          'issued to client "' +
                          claims.client_id + '" and is being presented by "' +
                          presentedClient +
                          '". A refresh token may only be used by the client ' +
                          'it belongs to.' };
  }

  // Section 2.3, by way of RFC 6749 section 6: a refresh may narrow the scope
  // and must never widen it.
  if (body.scope !== undefined && body.scope !== null &&
      String(body.scope) !== '') {
    const granted = scopeSet(claims.scope);
    const asked = scopeSet(body.scope);
    const extra = asked.filter(function (one) {
      return granted.indexOf(one) < 0;
    });
    if (extra.length) {
      log.debug("Leaving checkRefreshRequest(). The requested scope is wider " +
                "than the grant.");
      return { ok: false, errorCode: 'STS-OAUTH-0142', error: 'invalid_scope',
               requirement: 'scope-not-widened',
               description: 'RFC 9700 section 2.3: an access token\'s ' +
                            'privileges must be restricted to the minimum ' +
                            'required, and RFC 6749 section 6 says a refresh ' +
                            'must not request a scope the original grant did ' +
                            'not carry. This grant carries ' +
                            '"' + (claims.scope || '') + '" ' +
                            'and the request asks additionally ' +
                            'for: ' + extra.join(', ') + '.' };
    }
  }

  log.debug("Leaving checkRefreshRequest(). Nothing refused.");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// SECTION 2.2.2's OTHER lifetime rule: an authorization server MAY revoke
// refresh tokens after a security event, and the examples the section gives are
// a password change and a LOGOUT.
//
// Logout is the one this service has. `authn.js` owns the single session store
// both protocols end a session through, so it asks this whether to act — the
// policy is here with the rest of the mode, and the finding and revoking is
// there, where the session and the token registry are.
//
// Why it matters more than it looks: without it, signing out drops a cookie and
// leaves a long-lived credential in the client's hands (twenty-four hours on
// the default `oauth2.refreshTokenTtlS`, thirty days at that setting's
// ceiling). A person who signs out
// of a shared browser has every reason to believe that ended their session, and
// on this service it ended the half that was visible.
// ---------------------------------------------------------------------------
// PER CLIENT since 2026-08-27: `oauthRevokeRefreshOnLogout` on the application
// entry overrules the setting for that client alone. The caller asks ONCE PER
// TOKEN rather than once per sign-out, because the answer is now a property of
// whoever the token was issued to — a session may hold refresh tokens for three
// clients, and two of them agreeing to be revoked says nothing about the third.
//
// `enabled()` still gates it, so with RFC 9700 mode off this answers false for
// every client whatever their entry says, exactly as it did.
function revokeRefreshOnLogout(clientId) {
  log.debug("Entering revokeRefreshOnLogout().");
  log.debug("Leaving revokeRefreshOnLogout().");
  return enabled() &&
    !!applications.settingFor(clientId || '', 'oauth2.revokeRefreshOnLogout',
                              config);
}

// Section 2.2 / 2.2.1, and it refuses nothing: whether an access token is
// sender-constrained is the CLIENT's decision, since it binds by sending a
// proof. Logged at issuance so that "this server issued a bearer token" is a
// fact somebody can find, rather than an absence they have to notice.
function noteTokenBinding(opts) {
  log.debug("Entering noteTokenBinding().");
  const info = opts || {};
  if (!enabled()) {
    log.debug("Leaving noteTokenBinding().");
    return;
  }
  // Section 2.3's least-privilege observation, which is not a refusal for the
  // reason `least-privilege-scope` gives: half the callers of this service are
  // testing what an unadvertised scope does, and refusing one would remove
  // that.
  const advertised = ['openid', 'profile', 'email', 'offline_access'];
  const unknown = String(info.scope || '').split(/\s+/).filter(Boolean)
    .filter(function (one) { return advertised.indexOf(one) < 0; });
  if (unknown.length) {
    log.info('RFC 9700 section 2.3: an access token was issued for client "' +
             (info.clientId || '(unnamed)') + '" carrying scope(s) this ' +
             'server does not advertise in ' +
             'scopes_supported: ' + unknown.join(', ') + '. ' +
             'Granted anyway — a scope nobody advertises is exactly what a ' +
             'client tests here — and noted, because least privilege is ' +
             'about what a token can do and not only about how long it lasts.');
  }
  if (info.jkt || info.certificateBound) {
    log.debug("Leaving noteTokenBinding().");
    return;
  }
  log.info('RFC 9700 section 2.2: an access token was issued to client "' +
           (info.clientId || '(unnamed)') + '" with no sender constraint — a ' +
           'bearer token, which anybody who obtains it can use. TWO ' +
           'mechanisms are on offer here: DPoP (RFC 9449, advertised as ' +
           'dpop_signing_alg_values_supported — send a proof) and RFC 8705 ' +
           'certificate binding (advertised as ' +
           'tls_client_certificate_bound_access_tokens when the main port is ' +
           'TLS — make the connection with a client certificate). This is a ' +
           'SHOULD and is not refused.');
  log.debug("Leaving noteTokenBinding().");
}

// ---------------------------------------------------------------------------
// SECTION 4.5 — a code presented a second time.
//
// The code itself is gone by then: `oauth2.js` deletes it where it is redeemed
// and always has. What is left is the REPLAY RELAXATION described where
// `redeemedCodes` is declared — an identical repeat gets its own tokens back
// rather than an error — and this is what turns that off, because RFC 6749
// section 4.1.2 says a real authorization server refuses it.
//
// It also does the SHOULD beside it (section 10.5): everything that code bought
// is revoked. The reasoning is the refresh chain's, one step earlier — a code
// presented twice means two holders, one of them is not the client, and nothing
// here can tell which, so the answer is to invalidate rather than to guess.
//
// The jtis are passed IN and the revocation is `oauth2.js`'s, for the reason
// `checkRefreshRequest()` gives: this module decides and the protocol acts, and
// `stats.revoke()` is the one set /oauth2/revoke and the console write to.
// ---------------------------------------------------------------------------
function checkCodeReplay(opts) {
  log.debug("Entering checkCodeReplay().");
  if (!enabled()) {
    log.debug("Leaving checkCodeReplay(). RFC 9700 mode is off; the " +
              "relaxation stands.");
    return { ok: true };
  }
  const info = opts || {};
  const jtis = (info.issuedJtis || []).filter(Boolean);
  log.warn('RFC 9700 section 4.5: authorization code presented a second time ' +
           'by client "' +
           (info.clientId || '(none)') + '", ' + (info.secondsAgo || 0) + ' ' +
           'second(s) after it was redeemed. Refusing it, and revoking ' +
           'the ' + jtis.length + ' ' +
           'token(s) it bought (RFC 6749 section 10.5).');
  log.debug("Leaving checkCodeReplay(). Refused, with " + jtis.length + " " +
      "token(s) to revoke.");
  return {
    ok: false, errorCode: 'STS-OAUTH-0143', error: 'invalid_grant',
    requirement: 'code-single-use', revoke: jtis,
    description: 'RFC 9700 section 4.5: an authorization code is single use. ' +
                 'This one was ' +
                 'redeemed ' + (info.secondsAgo || 0) + ' second(s) ago by ' +
                                                        'client "' +
                 (info.clientId || '(none)') + '". A code presented twice ' +
                 'means two holders and this server cannot tell which of ' +
                 'them is the client, so the ' +
                 jtis.length + ' token(s) it bought have been revoked as ' +
                 'well (RFC 6749 section 10.5). Start a new authorization ' +
                 'request.'
  };
}

// ---------------------------------------------------------------------------
// SECTION 4.11.2 — THE AUTHORIZATION SERVER AS AN OPEN REDIRECTOR.
//
// Refusing an unregistered `redirect_uri` (section 2.1) closes most of it: this
// service will not forward a browser to a URI nobody registered. What is left
// is the part that survives even when every URI IS registered, and the BCP is
// unusually specific about it:
//
//   "The authorization server MUST always authenticate the user first and, with
//    the exception of the silent authentication use case, prompt the user for
//    credentials when needed, BEFORE redirecting the user."
//
// The attack it closes needs no invalid URI at all. An attacker sends a victim
// to a legitimate client's authorization request with something wrong in it —
// an unsupported `response_type`, a missing parameter — and the authorization
// server bounces them straight to that client's registered redirect_uri
// carrying attacker-chosen `state`. Nobody signed in, nobody clicked, and the
// hop through a trusted authorization server is the whole value of it.
//
// So in this mode an error is only AUTOMATICALLY redirected when the person is
// already authenticated. Otherwise they are shown what is about to happen and
// have to choose it — which is the same section's "the authorization server MAY
// inform the user and rely on the user to make the correct decision", and is
// what makes this server stop being usable as a redirector by somebody who has
// not signed in.
//
// TWO EXCEPTIONS, and both are in the specification rather than convenience:
//
//   * SILENT AUTHENTICATION. `prompt=none` exists to be answered without any
//     interaction, and `login_required` is the answer it exists to produce — an
//     interstitial there would break the one flow whose entire contract is that
//     nothing is shown. The section names this exception itself.
//   * A REFUSAL COMING BACK FROM THE SIGN-IN SCREEN (`authn_error`). The person
//     was at the screen and pressed Cancel, so they are present and have just
//     made a decision; asking them to confirm the consequence of it would be a
//     second question about the same answer.
//
// A SUCCESS is never affected. Reaching one means a session exists, which means
// the person was authenticated first, which is exactly what the MUST asks for.
// ---------------------------------------------------------------------------
function redirectPolicyFor(opts) {
  log.debug("Entering redirectPolicyFor().");
  const info = opts || {};
  log.debug("Entering redirectPolicyFor(). hasSession=" + !!info.hasSession);
  if (!enabled()) {
    log.debug("Leaving redirectPolicyFor(). RFC 9700 mode is off.");
    log.debug("Leaving redirectPolicyFor().");
    return { redirect: true };
  }
  if (info.hasSession) {
    log.debug("Leaving redirectPolicyFor(). The person is authenticated, so " +
              "the error goes back.");
    log.debug("Leaving redirectPolicyFor().");
    return { redirect: true };
  }
  if (String(info.prompt || '').split(/\s+/).indexOf('none') >= 0) {
    log.debug("Leaving redirectPolicyFor(). prompt=none is the " +
              "silent-authentication exception.");
    log.debug("Leaving redirectPolicyFor().");
    return { redirect: true, why: 'silent authentication (prompt=none)' };
  }
  if (info.fromSignIn) {
    log.debug("Leaving redirectPolicyFor(). The person just declined at the " +
              "sign-in screen.");
    log.debug("Leaving redirectPolicyFor().");
    return { redirect: true, why: 'the person declined at the sign-in screen ' +
                                  'a moment ago' };
  }
  log.debug("Leaving redirectPolicyFor(). Nobody is authenticated; the error " +
            "is shown, not sent.");
  log.debug("Leaving redirectPolicyFor().");
  return {
    redirect: false, requirement: 'authenticate-before-redirect',
    why: 'RFC 9700 section 4.11.2: an authorization server MUST authenticate ' +
         'the user before redirecting them. Nobody is signed in on this ' +
         'browser, so this error is being SHOWN rather than bounced to the ' +
         'client — otherwise anybody could use this authorization server to ' +
         'forward a browser to a client\'s registered redirect_uri, carrying ' +
         'parameters they chose, with no interaction at all.'
  };
}

// Section 4.11.2 and RFC 6749 section 4.1.2.1: an INVALID COMBINATION of
// client_id and redirect_uri must not be redirected anywhere. A missing
// client_id is the plainest such combination — there is no client for the URI
// to belong to — and this service used to report it BY REDIRECTING to the URI,
// which is the one thing that paragraph forbids.
//
// An unknown-but-present client_id is deliberately NOT refused here: this
// service issues to any client_id that asks, and the combination is checked
// where it can be, in `checkRedirectUri()` — a registered client is judged
// against its own URIs and an unregistered one against the configured list.
function checkClientIdPresent(clientId) {
  log.debug("Entering checkClientIdPresent().");
  if (!enabled() || String(clientId || '').trim()) {
    log.debug("Leaving checkClientIdPresent().");
    return { ok: true };
  }
  log.debug("Leaving checkClientIdPresent(). No client_id.");
  log.debug("Leaving checkClientIdPresent().");
  return { ok: false, errorCode: 'STS-OAUTH-0144', error: 'invalid_request',
           requirement: 'no-redirect-invalid-combination',
           description: 'RFC 9700 section 4.11.2, citing RFC 6749 section ' +
                        '4.1.2.1: an authorization server must not ' +
                        'automatically redirect the user agent for an ' +
                        'invalid combination of client_id and redirect_uri. ' +
                        'This request names no client_id at all, so there is ' +
                        'no client the redirect_uri could belong to — and ' +
                        'reporting that BY redirecting to the URI is exactly ' +
                        'what that paragraph forbids. It is answered here ' +
                        'instead.' };
}

// Section 2.6: CORS must not be supported at the authorization endpoint. Asked
// by common/cors.js, which decides CORS and has no business knowing
// which of this service's paths is an authorization endpoint — that knowledge
// belongs to the OAuth side, which is here.
//
// The token, userinfo, metadata and JWKS endpoints keep their headers: an
// in-browser client fetches those with XHR and needs them. The authorization
// endpoint is NAVIGATED to, so nothing legitimate ever read them there.
function corsForbidden(req) {
  log.debug("Entering corsForbidden().");
  if (!enabled()) {
    log.debug("Leaving corsForbidden().");
    return false;
  }
  const path = String((req && (req.path || req.url)) || '').split('?')[0];
  log.debug("Leaving corsForbidden().");
  return path === '/oauth2/authorize';
}

// ---------------------------------------------------------------------------
// THE TOKEN REQUEST. Three checks, and two of them are RFC 6749 section 4.1.3
// rather than RFC 9700 — they are here because section 2.1.1's "bound to the
// client and user-agent transaction" is what they implement and because this
// service did not make them.
//
// What is NOT checked here: whether the code was issued with a challenge at
// all. A code minted before the mode was turned on has none, and refusing it at
// the token endpoint would answer a request that was correct when it started
// with a message about a policy that arrived in between. The authorization
// endpoint is where PKCE is required; this endpoint's job is that a
// code_verifier cannot be smuggled in where no challenge was. OAuth 2.1 mode
// is the exception and refuses such a code at the token endpoint too
// (section 4.1.3) — `oauth21.tokenCodeRefusal()`, asked by `oauth2.js`.
// ---------------------------------------------------------------------------
function checkTokenRequest(opts) {
  log.debug("Entering checkTokenRequest().");
  if (!enabled()) {
    log.debug("Leaving checkTokenRequest(). RFC 9700 mode is off.");
    return { ok: true };
  }
  const record = opts.record || {};
  const body = opts.body || {};
  const presentedClient = String((opts.client && opts.client.client_id) || '');

  if (!record.code_challenge && body.code_verifier) {
    log.debug("Leaving checkTokenRequest(). A code_verifier arrived for a " +
              "code with no challenge.");
    return { ok: false, errorCode: 'STS-OAUTH-0145', error: 'invalid_grant',
             requirement: 'pkce-downgrade',
             description: 'RFC 9700 section 4.8.2: this authorization code ' +
                          'was issued without a code_challenge, so a Token ' +
                          'Request carrying a code_verifier is rejected. ' +
                          'Accepting it is the PKCE downgrade attack — it ' +
                          'lets an attacker who stripped code_challenge from ' +
                          'the authorization request present any verifier ' +
                          'here and be told nothing is wrong.' };
  }

  if (record.client_id && presentedClient &&
      record.client_id !== presentedClient) {
    log.debug("Leaving checkTokenRequest(). A different client is redeeming " +
              "the code.");
    return { ok: false, errorCode: 'STS-OAUTH-0146', error: 'invalid_grant',
             requirement: 'transaction-bound',
             description: 'RFC 6749 section 4.1.3: this authorization code ' +
                          'was issued to client ' +
                          '"' + record.client_id + '" and is being redeemed ' +
                                                   'by "' +
                          presentedClient + '".' };
  }

  // RFC 6749 section 4.1.3 makes redirect_uri REQUIRED at the token endpoint
  // when it was in the authorization request, which it always is here. Without
  // the mode this service compares it only when the client bothered to send it.
  // OAUTH 2.1 REMOVED IT (section 10.2): PKCE binds the code instead, so a
  // client following 2.1 alone never sends one, and that mode asks for it only
  // of a code minted under the OpenID Connect nonce exemption — which has no
  // PKCE and for which this is still the binding. When it IS sent it must
  // still be identical, which oauth2.js checks in every mode.
  if (record.redirect_uri && !body.redirect_uri &&
      oauth21.tokenRedirectUriRequired(record)) {
    log.debug("Leaving checkTokenRequest(). No redirect_uri came with the " +
              "code.");
    return { ok: false, errorCode: 'STS-OAUTH-0147', error: 'invalid_grant',
             requirement: 'transaction-bound',
             description: 'RFC 6749 section 4.1.3: redirect_uri is required ' +
                          'in the Token Request when it was present in the ' +
                          'authorization request, and must be identical. It ' +
                          'is missing.' };
  }

  log.debug("Leaving checkTokenRequest(). Nothing refused.");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// THE METADATA. A discovery document is a promise the endpoints have to keep,
// so what the mode refuses is what the mode must stop advertising: a client
// configured from `response_types_supported` and then refused for using one of
// its values has been misled by this server, not by its own code.
//
// The object is mutated in place and returned, because it is built fresh per
// request in asMetadata() and there is nothing to share.
// ---------------------------------------------------------------------------
function applyToMetadata(metadata) {
  log.debug("Entering applyToMetadata().");
  if (!enabled()) {
    log.debug("Leaving applyToMetadata(). RFC 9700 mode is off.");
    return metadata;
  }
  if (Array.isArray(metadata.response_types_supported)) {
    metadata.response_types_supported =
        metadata.response_types_supported.filter(function (type) {
      return String(type).split(/\s+/).indexOf('token') < 0;
    });
  }
  if (Array.isArray(metadata.grant_types_supported)) {
    // `implicit` (section 2.1.2) and `password` (section 2.4) both come out. A
    // metadata document is a promise the endpoint has to keep, and the token
    // endpoint now refuses both — a client configured from a list that still
    // named them would be misled by this server rather than by its own code.
    metadata.grant_types_supported = metadata.grant_types_supported.filter(
        function (grant) {
      return grant !== 'implicit' && grant !== 'password';
    });
  }
  // S256 only, since `plain` is refused at the authorization endpoint. This is
  // also the member RFC 9700 section 2.1.1 names as how a client detects PKCE
  // support at all, so it must not be emptied — only narrowed.
  metadata.code_challenge_methods_supported = ['S256'];
  // And what OAuth 2.1 mode refuses on top — saml2_bearer client
  // authentication. A no-op unless that mode is on.
  oauth21.applyToMetadata(metadata);
  log.debug("Leaving applyToMetadata(). The mode narrowed three members.");
  return metadata;
}

// What GET /oauth2/rfc9700 publishes, and what a test reads to find out whether
// the mode is on without having to infer it from a refusal.
function state() {
  log.debug("Entering state().");
  const on = enabled();
  const view = {
    rfc: 'RFC 9700 — Best Current Practice for OAuth 2.0 Security',
    url: 'https://www.rfc-editor.org/rfc/rfc9700',
    enabled: on,
    what_it_means: on
      ? 'The requirements below marked enforced=yes are enforced, the ' +
        'discovery documents no longer advertise what would be refused, and ' +
        'every URL they carry — the issuer included — names the scheme this ' +
        'port actually answers on, which is ' +
        (mainPortIsTls() ? 'https.' : 'http, because global.https has been ' +
                                      'turned off.')
      : 'Nothing below is being enforced. This service behaves as the ' +
        'permissive mock it is, which is the default. Set oauth2.rfc9700 to ' +
        'turn the mode on.',
    // WHICH FLAG turned it on. `oauth2.oauth21` implies this mode, and without
    // this member a realm carrying only that one would read here as enforcing
    // everything with `oauth2.rfc9700: false` beside it.
    enabled_by: !on ? '' : (config.value('oauth2.rfc9700') ? 'oauth2.rfc9700'
                                                           : 'oauth2.oauth21'),
    settings: {
      'oauth2.rfc9700': !!config.value('oauth2.rfc9700'),
      'oauth2.oauth21': oauth21.enabled(),
      'oauth2.redirectUris': configuredRedirectUris(),
      'oauth2.loopbackPortWildcard': loopbackPortWildcard(),
      'global.https': mainPortIsTls(),
      // Not part of this mode and reported beside it anyway: a client author
      // reading this page to find out what it is talking to needs to know that
      // the ID Tokens are being spoiled on purpose, and this is the page they
      // are reading.
      'oauth2.breakIdTokenNonce': !!config.value('oauth2.breakIdTokenNonce'),
      // #34 (2026-09-15). Reported here for the reason the row above is:
      // a client author reading this page is trying to find out what this
      // server will do to their request, and four of these five turn a SHOULD
      // into a refusal. None of them is part of this mode, and the mode turns
      // none of them on.
      'oauth2.refreshTokenRotation':
        !!config.value('oauth2.refreshTokenRotation'),
      'oauth2.refreshTokenRequireDpop':
        !!config.value('oauth2.refreshTokenRequireDpop'),
      'oauth2.refreshTokenRequireMtls':
        !!config.value('oauth2.refreshTokenRequireMtls'),
      'oauth2.accessTokenRequireDpop':
        !!config.value('oauth2.accessTokenRequireDpop'),
      'oauth2.accessTokenRequireMtls':
        !!config.value('oauth2.accessTokenRequireMtls')
    },
    // The same five as one block, with what turned rotation on — the console
    // page and both reports read this rather than each deciding for itself.
    sender_constraints: senderConstraints.state(),
    // Reported beside the settings because it is the one thing here that a
    // caller cannot infer from its own request: it already knows what scheme it
    // used, and what it wants to know is whether that was the only option.
    authorization_endpoint_scheme: mainPortIsTls() ? 'https' : 'http',
    scope: 'Section 2.1 (redirect-based flows), 2.1.1 (authorization code ' +
           'grant) and 2.1.2 (implicit grant). Pushed Authorization ' +
           'Requests (RFC 9126) and resource indicators are features in ' +
           'every mode rather than rows of this one.',
    transactions_remembered: transactions.size,
    client_assertions_remembered: clientAuth.assertionsRemembered(),
    client_authentication_methods_verified: clientAuth.METHODS,
    refresh_tokens_remembered: refreshTokens.size,
    refresh_families: refreshFamilies.size,
    requirements: REQUIREMENTS.map(function (requirement) {
      // `enforced` and `note` may be functions — see the response-over-tls row,
      // whose answer describes the socket rather than a decision.
      const enforced = typeof requirement.enforced === 'function'
        ? requirement.enforced() : requirement.enforced;
      const note = typeof requirement.note === 'function'
        ? requirement.note() : requirement.note;
      return {
        id: requirement.id,
        section: 'RFC 9700 ' + requirement.section,
        level: requirement.level,
        applies_to: requirement.appliesTo,
        title: requirement.title,
        enforced: enforced,
        note: note
      };
    })
  };
  log.debug("Leaving state(). enabled=" + on);
  return view;
}

// #46: a rotated refresh token is redeemed once across the cluster and a
// replay revokes its family by id (`spendRefreshToken()`); the hosted
// surfaces' renewal is single-flight across nodes in `common/oidc_rp.ts`,
// which this row names too. At require time — see cluster/CLAUDE.md.
capabilities.provide('oauth.refresh-rotation');

module.exports = {
  REQUIREMENTS: REQUIREMENTS,
  enabled: enabled,
  isConfidential: isConfidential,
  declaredPublic: declaredPublic,
  credentialOnFile: credentialOnFile,
  checkGrantType: checkGrantType,
  checkClientAuthentication: checkClientAuthentication,
  observeClientAuthentication: observeClientAuthentication,
  checkClientRegistration: checkClientRegistration,
  checkRefreshRequest: checkRefreshRequest,
  noteRefreshIssued: noteRefreshIssued,
  noteRefreshRotated: noteRefreshRotated,
  // #46: the family a refresh token is minted into (and the claim that
  // carries it), the once-across-the-cluster redemption, and revoking a
  // family by id.
  FAMILY_CLAIM: FAMILY_CLAIM,
  familyForIssuance: familyForIssuance,
  // #34: re-exported so that `oauth2.js` asks ONE name whether refresh tokens
  // rotate, whatever turned it on. The answer lives in sender_constraints.js,
  // which this file may require and which may never require this file back.
  rotationRequired: senderConstraints.rotationRequired,
  spendRefreshToken: spendRefreshToken,
  revokeFamily: revokeFamily,
  revokeRefreshOnLogout: revokeRefreshOnLogout,
  noteTokenBinding: noteTokenBinding,
  corsForbidden: corsForbidden,
  checkRedirectUri: checkRedirectUri,
  checkPostLogoutRedirectUri: checkPostLogoutRedirectUri,
  checkAuthorizationRequest: checkAuthorizationRequest,
  checkClientIdPresent: checkClientIdPresent,
  redirectPolicyFor: redirectPolicyFor,
  checkTransactionValues: checkTransactionValues,
  rememberTransactionValues: rememberTransactionValues,
  checkTokenRequest: checkTokenRequest,
  checkCodeReplay: checkCodeReplay,
  noteRedeemed: noteRedeemed,
  applyToMetadata: applyToMetadata,
  state: state
};
