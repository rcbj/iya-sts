'use strict';
//
// File: scim_auth.ts
//
// ---------------------------------------------------------------------------
// WHO IS ASKING AT THE SCIM ENDPOINTS, AND WHAT THEY MAY DO.
//
// This is the FIRST surface in this service that refuses a caller who presents
// nothing, and the reason it is this one is the reason SCIM was worth having at
// all: /scim/v2 is the only family here whose purpose is to WRITE. Every other
// endpoint answers a question about somebody — issue this person a token, seal
// this ticket, tell me who signed in. These create and DELETE accounts, in a
// directory that fifteen other things then read. A surface that does that and
// asks nobody's name is the one place in a permissive mock where "permissive"
// stops being a teaching device and starts being a hole somebody copies.
//
// **IN DEVELOPMENT MODE IT IS STILL PERMISSIVE, AND THAT IS THE WHOLE
// DESIGN.** Nothing here is a lock there; it is a turnstile. (In product mode
// the three "Anybody" sentences that follow do not hold as written —
// passwords are verified, Digest is not offered and HOBA registration is
// confined; scim/CLAUDE.md, the 2026-09-12 audit.) Anybody may get an access
// token from this service's own token endpoint with any grant, asking for
// whatever scope they like. Anybody may present Basic with any username and any
// password but one. Anybody may register a HOBA public key and then
// authenticate with it. What changed is that a caller must now SAY who they are
// through one of the schemes RFC 7644 section 2 names, and — for the OAuth ones
// — hold the scope for what they are about to do. That is exactly the shape a
// real deployment has, which is what makes a client's authentication and
// authorization paths runnable here; it is not a claim that this service checks
// anybody.
//
// ---------------------------------------------------------------------------
// WHAT THE SPECIFICATION ACTUALLY SAYS, BECAUSE IT IS SHORTER THAN PEOPLE
// EXPECT.
//
// RFC 7644 section 2: "The SCIM protocol is based upon HTTP and does not itself
// define a SCIM-specific scheme for authentication and authorization. SCIM
// depends on the use of Transport Layer Security (TLS) and/or standard HTTP
// authentication and authorization schemes as per [RFC7235]." So there is no
// SCIM credential to implement and no SCIM login to get wrong. What that
// section does is NAME six ways of doing it — TLS client authentication, HOBA,
// bearer tokens, proof-of-possession tokens, cookies, and HTTP Basic (which it
// discourages, in those words) — and then state the only two normative
// sentences in it:
//
//   * "a SCIM service provider SHALL indicate supported HTTP authentication
//     schemes via the 'WWW-Authenticate' header".  That is `challenges()` below
//     and the 401 every refusal here carries. It is a SHALL, so a 401 with no
//     challenge would be non-conforming — and, more to the point, useless: a
//     client that is told it failed and not what to send next cannot proceed.
//
//   * the provider "MUST be able to map the authenticated client to an access
//     control policy in order to determine the client's authorization to
//     retrieve and update SCIM resources".  This service HAS such a policy and
//     it is two lines long, which is the honest amount for a mock: an OAuth
//     credential may do what its scopes say, and every other scheme may do
//     everything. Both halves are published on GET /scim and on /admin/scim
//     rather than left to be discovered by a client that expected the second
//     half to be narrower.
//
// RFC 7643 section 5 is the other half: `authenticationSchemes` in the
// ServiceProviderConfig, whose `type` has five canonical values — `oauth`,
// `oauth2`, `oauthbearertoken`, `httpbasic`, `httpdigest`. Note what that list
// is NOT: it is not the same list as section 2's six, and three of the schemes
// section 2 names have no canonical value at all. How that is squared is in
// `schemesForConfig()` below and it is the one place where the two documents
// disagree with each other rather than with this service.
//
// ---------------------------------------------------------------------------
// THE TABLE IS THE WHOLE MODULE.
//
// `SCHEMES` is the single source for four surfaces that would otherwise drift:
//
//   * the WWW-Authenticate challenge on every 401 (the SHALL above),
//   * `authenticationSchemes` in the ServiceProviderConfig,
//   * what GET /scim tells a person,
//   * what /admin/scim and GET /admin-api/scim report, including the per-scheme
//     counters.
//
// A scheme is a row. Turning one off is a `config.js` row, so it disappears
// from the challenge and from the published document together — which is the
// property that matters, because a client reads a published scheme as a promise
// and a challenge as an instruction, and a server that advertised Digest while
// refusing every Digest request would be lying in both places at once.
//
// **DO NOT ADD A SCHEME THAT IS NOT IN RFC 7644 SECTION 2.** Every row here is
// something that section names. The temptation is API keys and a shared header,
// which is what most provisioning integrations actually use in the field; it is
// not in the specification, a client built against it here would interoperate
// with nothing, and this service already has six ways in.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS ARE LOAD-BEARING.
//
// **THE BEARER CHECK IS `dpop.presentedAccessToken()` AND NOT A SECOND ONE.**
// That function is the single check /oauth2/userinfo and the three OID4VCI
// credential endpoints already share, and it carries a great deal that is easy
// to leave out of a fresh implementation: the RFC 9449 proof and its nonce
// handshake, the RFC 8705 certificate binding, the RFC 9700 refusal of a token
// in a query string, and the audience check. Writing a fifth one here would be
// a fifth thing nobody updates. What it does NOT do is speak SCIM: it answers
// the request itself, with an OAuth-shaped `{error, error_description}` body,
// and a SCIM client is entitled to an RFC 7644 section 3.12 Error object. So it
// is called with a CAPTURING response object and what it would have said is
// translated. See `attemptBearer()`, where that shim is written out; it is a
// workaround and is commented as one rather than left to look like a design.
//
// **ONLY THE OAUTH SCHEMES CARRY SCOPES.** A Basic credential has none, a
// client certificate has none, a HOBA signature has none. The access control
// policy therefore reads: an OAuth credential may do what `scim:read` and
// `scim:write` say it may, and every other accepted credential may do both.
// That is a real policy rather than an absence of one, and it has a consequence
// worth stating where somebody will read it: a caller who cannot get the scope
// can simply use Basic instead. Which is why every scheme has its own switch —
// a deployment exercising a client's scope handling turns the other five off,
// and then the only way in is the one being tested.
//
// **WHICH SCHEMES COUNT AS AN AUTHENTICATION, AND WHICH DO NOT.** `recorded` on
// the row decides, and the rule is the one this service already applies
// everywhere: `stats.recordAuthentication()` is called at the moment a
// credential is ACCEPTED, and not again while that same act continues.
//
//   * Basic, Digest and HOBA are RECORDED. Each presents a credential on every
//     request, and accepting it is an act of authentication exactly as a
//     WS-Trust UsernameToken is. So SCIM became the fifteenth family to reach
//     that funnel — SPIFFE is the sixteenth and arrived after it — its callers
//     appear on /admin/users, and the directory seeds an entry for them like
//     any other.
//   * A BEARER OR DPoP token is NOT recorded. The credential behind it was
//     accepted when the token was issued — at the authorization endpoint, or at
//     the token endpoint for a grant with no user — and recording it again here
//     would count one sign-in once per provisioning request. Same reasoning
//     that keeps the token endpoint from counting an application sighting the
//     authorization endpoint already counted.
//   * A SESSION COOKIE is NOT recorded, for the same reason: `authn.js` already
//     recorded that sign-in, and the cookie is that session continuing.
//   * A CLIENT CERTIFICATE is NOT recorded here either, and this one is the
//     interesting one. `tls_server.js` records a certificate on
//     `secureConnection` and explicitly not per request, because one connection
//     carrying six requests is one authentication and not six. A per-request
//     record here would undo that decision from the other end.
//
// **NOTHING IN THIS FILE TOUCHES `res`.** It decides; `scim.ts` answers, in
// SCIM's own error shape and with the headers this module hands back. Same
// split `oauth2_bcp.js` has with `oauth2.js`, and it is what makes the whole of
// this testable without a socket. The one exception proves it:
// `attemptBearer()` gives `presentedAccessToken()` a FAKE response to write
// into, precisely so that the real one is untouched.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND IT REGISTERS NOTHING.
//
// It requires `helpers.js`, `config.js`, `dpop.js`, `mtls.js`,
// `admin_stats.js`, `authn.js`, `tls_server.js` and `ldap_server.js` — and the
// leaves listed beside each require below — and none of those requires it back,
// so it cannot join a cycle. `authn.js`, `tls_server.js` and `ldap_server.js`
// are the only ones worth a sentence: they register routes, so requiring them
// from a module read EARLIER than they are would move those routes in the
// express router. (Since #50's R1 that is true of the two JavaScript ones
// only: `authn.ts` registers nothing when required, and
// `common/protocol_stack.ts` registers its routes at 8.) But `scim.ts`, the
// only thing that requires this file, already sits after all three in the
// require order (`common/protocol_stack.ts`), so nothing moves. That is rule
// 3e's test applied rather than a slot added by analogy: there is no cycle and
// no route moves, so these are plain requires.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ScimAuth` takes every module it used to require (the logger and the
// helpers it read, `config`, `mode`, the verifiers, the directory, the gate,
// the cluster claims) and the four challenge stores through its constructor,
// as `ScimAuthDeps`. `tls_client_certificates.js`, required lazily before,
// arrives as a loader function and is still required only when it is asked
// for.
//
// What stays at module scope, and why:
//
//   * THE FOUR STORES (`digestNonces`, `digestCounts`, `hobaChallenges`,
//     `hobaSeen`) are still declared here as `realms.map()`, in the order they
//     always were, because a store becomes per realm at its declaration —
//     `tests/realm_isolation.js` reads three of these declarations.
//   * THE SCHEME TABLE is built by the instance (`buildSchemes()`), because
//     each row's `attempt` and `challenge` are its methods, and
//     `DIGEST_ALGORITHMS` is filtered by it for the same reason it always was
//     filtered at require time: the warning names what this build lacks.
//   * `capabilities.provide()` still runs at require time. The require-time
//     log line names the instance's schemes, so since #50's R2 it is logged
//     by `ScimAuth.wire()`, when the instance is installed.
//
// Since #50's R2 the composition root builds the instance and installs it
// here. The module still exports every old name, as FACADES forwarding to
// that instance (and getters for `SCHEMES` and `DIGEST_ALGORITHMS`), because
// `scim.ts`, `admin-ui/crypto_metadata.ts` and the tests are not converted
// and require it by those names; a process without the root builds a default
// when this module loads. `ScimAuth` is exported for the root.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
// One signer, one verifier and one constant-time comparison for the whole
// service since 2026-08-27.
import stsCrypto = require('../common/crypto');
// The credential verifier and the mode. Both LEAVES (rule 3): they register
// nothing and require nothing here.
import credentials = require('../common/credentials');
import mode = require('../common/mode');

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// The challenge and replay stores below are per trust realm. A LEAF.
import realms = require('../common/realms');
import dpop = require('../oauth-oidc/dpop');
import mtls = require('../oauth-oidc/mtls');
import stats = require('../common/admin_stats');
import authn = require('../authn/authn');
// THE ACCESS GATE, which `xacml/xacml_access_pep.ts` arms at 23c. A LEAF
// (rule 3): it registers nothing and, with no decider installed, `check()`
// answers "allowed" — so a process without the XACML family behaves exactly as
// this file did before the gate existed, which is `npm test` and the parent
// project's in-process jobs.
import accessGate = require('../common/access_gate');
import tlsServer = require('../tls/tls_server');
import directory = require('../ldap/ldap_server');
// Every refusal below carries an STS-SCIM-* code, attached to the refusal value
// under the non-enumerable Symbol errorCodes.mark() uses; scim.ts marks the
// response with it. See common/error_codes.js. A leaf.
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
// For the one refusal here that is not a refusal of the REQUEST — a verified
// client certificate the revocation policy will not accept as a credential —
// which has no response of its own to be marked on. `audit.js` requires only
// `helpers`, `config` and the registry, so it closes no cycle.
import audit = require('../common/audit');
// ONCE ACROSS THE CLUSTER (2026-09-14, #46 section 5): a Digest nonce count
// and a HOBA signature are spent through an atomic claim, and the table
// active-active mode is held to. Both LIBRARIES; `cluster_claims.js` requires
// `persistence.js` lazily, so neither closes a cycle.
import clusterClaims = require('../cluster/cluster_claims');
// WHICH CLIENTS MAY HOLD THE SCIM SCOPES (#110), asked again of every token.
import scopePolicy = require('../common/scope_policy');
import capabilities = require('../cluster/cluster_capabilities');

// `mtls.js` is required for its place in the require order and nothing of it
// is called here; this reference keeps TypeScript from eliding the require.
void mtls;

// The nonces this server has issued. Bounded, because the value comes off a
// challenge anybody can ask for by making an unauthenticated request, and
// persisted since 2026-09-14 — see the last block of this note.
//
// **THE BOUND IS `scim.maxDigestNonces` SINCE 2026-09-12** (2000, the old
// constant, is its default). Evicting a nonce that has not expired does NOT
// re-open a replay: its nonce-count record goes with it, so the next credential
// naming that nonce is refused as one this server never issued (with
// stale=true, so a conforming client simply retries). What a low bound costs is
// a legitimate client's nonce vanishing under load, which is a retry and never
// an acceptance.
//
// **PER TRUST REALM SINCE 2026-09-12.** `/scim/v2` is realm-prefixed and each
// realm's directory is its own, and this was one Map for the process: a nonce
// issued in one realm was accepted as one this server issued in every other,
// and — the half with a consequence — one realm's unauthenticated challenges
// counted against the SAME cap, so a caller hammering `/realm/acme/scim/v2`
// could evict the nonce a client of the default realm was about to answer.
// ---------------------------------------------------------------------------
// **PERSISTED SINCE 2026-09-14 (#46 section 5)**, where this said "in memory
// and NOT persisted: a nonce outliving the process that issued it buys a
// Digest client nothing". That was true of a restart and false of every other
// process: `/scim/v2` FANS OUT across request workers (`request_pool.js`), so
// in one dispatched container a challenge issued by one worker was answered at
// another, which had never issued it — `stale=true`, a fresh nonce from THAT
// worker, and the retry landing on a third. Across containers it was every
// request. So the nonce is a persisted row and the read barrier makes it
// visible wherever the answer lands.
//
// **THE NONCE COUNTS ARE NOT IN THE ROW.** They were a `Set` on the record,
// which does not survive JSON, and a count written back into a replicated row
// is last writer wins — two nodes each adding their `nc` keep one. So the row
// is `{ at }`, the counts this process has seen are `digestCounts` below (the
// fast refusal, no round trip), and the count is SPENT through
// `cluster_claims.js` before a credential is accepted (`spendPresented()`),
// which is what decides a replay presented at two nodes at once.
// ---------------------------------------------------------------------------
const digestNonces = realms.map({ persist: 'scim.digestNonces',
                                  retain: 'age' });
// nonce -> the nonce-counts this process has accepted. Per realm for
// `digestNonces`'s reason. It was not persisted (see above) until
// 2026-09-18 — below.
//
// BOUNDED TWICE (2026-09-18). The ROWS are held to scim.maxDigestNonces like
// the nonces — a nonce another process issued arrives here with no row in
// `digestNonces` to be evicted with, so without its own bound this map
// outgrew the one it shadows. And each SET is held to MAX_COUNTS_PER_NONCE:
// a client increments nc on every request under one nonce, so a busy one
// grew a set a string at a time for the nonce's whole life. At that many the
// nonce is forgotten, and the client's next request is answered stale=true
// with a fresh nonce, which RFC 7616 section 3.3 has it handle.
//
// **AND PERSISTED SINCE 2026-09-18**, as `scim.digestCounts`, so that a
// restarted process still refuses a count it accepted before the restart
// without a round trip; the claim remains what decides between two live
// processes. A row is an ARRAY of counts — a Set does not survive JSON — and
// it is written back whole through the store on every accepted count, which
// is what journals it.
const digestCounts = realms.map({ persist: 'scim.digestCounts',
                                  retain: 'age' });
const MAX_COUNTS_PER_NONCE = 1024;

// The challenges this server has issued, and the (kid, challenge, nonce)
// triples it has already seen. Both bounded: a challenge is something anybody
// can ask for by making an unauthenticated request. The challenges are
// persisted and the triples are not — see the last block of this note.
//
// **BOTH BOUNDS ARE SETTINGS SINCE 2026-09-12** — `scim.maxHobaChallenges`
// (2000) and `scim.maxHobaSeen` (5000), the old constants as their defaults —
// and the second is the one where a bound can re-open a replay, so it is no
// longer a Set. Forgetting a (kid, challenge, nonce) triple while its challenge
// is still live would accept that exact signature a second time. So the seen
// store maps each triple to its CHALLENGE, and evicting a triple also forgets
// the challenge: the copied credential is then refused as naming a challenge
// this server did not issue. The cost is that a client legitimately reusing
// that challenge is sent a fresh one, which RFC 7486 clients already handle.
// Expired triples go first, because forgetting one of those costs nothing.
//
// **BOTH PER TRUST REALM SINCE 2026-09-12**, for the digest nonces' reason and
// with one more that is HOBA's own: the replay set is the thing that must not
// be evictable by somebody else, and a process-wide one let a second realm's
// traffic push a live (kid, challenge, nonce) triple out — at which point this
// file's own rule forgets the challenge too, so the harm is a refusal rather
// than a replay, but it is a refusal one realm inflicted on another.
//
// **THE CHALLENGES ARE PERSISTED SINCE 2026-09-14 (#46 section 5)**, for
// `digestNonces`'s reason: a challenge issued by one worker or node and
// answered at another was "not one this server issued". The row is the
// issue time and nothing else. **THE SEEN SET IS NOT**: it is this process's
// fast refusal, and a signature presented at two nodes at once is decided by
// the claim `spendPresented()` makes, which is atomic where a replicated Set
// is last writer wins. **It is persisted since 2026-09-18** all the same
// (`scim.hobaSeen`), so a restarted process's fast refusal survives the
// restart; the claim is still what decides between two live processes.
const hobaChallenges = realms.map({ persist: 'scim.hobaChallenges',
                                    retain: 'age' });
const hobaSeen = realms.map({ persist: 'scim.hobaSeen', retain: 'age' });

// ---------------------------------------------------------------------------
// THE FOUR STORES ABOVE, DESCRIBED TO `/admin/caches` (#74, rule 3ap). Every
// time here is milliseconds; a nonce or challenge is shown digested, because
// until it expires it is still a thing a client may present.
// ---------------------------------------------------------------------------
function scimSeconds(key: string): number {
  helpers.log.debug("Entering scimSeconds().");
  helpers.log.debug("Leaving scimSeconds().");
  return Number(config.value(key)) || 0;
}

const digestNoncesCount = cacheRegistry.register({
  name: 'scim.digest-nonces',
  title: 'SCIM Digest nonces',
  description: 'The HTTP Digest challenges /scim/v2 has handed out ' +
    '(RFC 7616), so a response names one this service issued.',
  owner: 'scim/scim_auth.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a nonce this service issued, so the response was checked',
  settings: ['scim.maxDigestNonces', 'scim.digestNonceSeconds'],
  maxEntries: function (): number | null {
    return scimSeconds('scim.maxDigestNonces') || null;
  },
  bound: 'Enforced: scim.maxDigestNonces per realm, the oldest dropped; a ' +
    'client using it is answered stale=true with a fresh one.',
  lifetime: function (): string {
    return 'scim.digestNonceSeconds (' +
      scimSeconds('scim.digestNonceSeconds') + ' s) after it was issued, ' +
      'then oldest first past the limit.';
  },
  // What `issueDigestNonce()` drops before it issues one, in every realm,
  // WITH the nonce's counts (`forgetDigestNonce()`'s pair) (#49 P5).
  eject: function (now: number): number {
    let total = 0;
    realms.list().forEach(function (r: any): void {
      realms.run(r, function (): void {
        const ttl = scimSeconds('scim.digestNonceSeconds') * 1000;
        const nonces = digestNonces.realmMap(r.id);
        const counts = digestCounts.realmMap(r.id);
        const gone: unknown[] = [];
        nonces.forEach(function (record: any, key: unknown): void {
          if (!record || now - Number(record.at) > ttl) {
            gone.push(key);
          }
        });
        gone.forEach(function (key: unknown): void {
          nonces.delete(key);
          counts.delete(key);
        });
        total += gone.length;
      });
    });
    return total;
  },
  entries: function (): unknown[] {
    const ttl = scimSeconds('scim.digestNonceSeconds') * 1000;
    return cacheRegistry.realmMapRows(realms, digestNonces,
      function (record: any, nonce: unknown): object {
        return { key: cacheRegistry.digestKey(nonce),
                 validUntil: Number(record && record.at) + ttl };
      });
  }
});

const digestCountsCount = cacheRegistry.register({
  name: 'scim.digest-nonce-counts',
  title: 'SCIM Digest nonce counts',
  description: 'The nonce-count (nc) values already accepted under each ' +
    'Digest nonce, so one response cannot be sent twice.',
  owner: 'scim/scim_auth.ts',
  scope: 'realm',
  kind: 'replay',
  hitMeaning: 'a nonce count already used, so the request was refused',
  settings: ['scim.maxDigestNonces'],
  maxEntries: function (): number {
    return Number(config.value('scim.maxDigestNonces'));
  },
  bound: 'Enforced: scim.maxDigestNonces nonces per realm, the oldest ' +
    'dropped (the nonce is then stale, and the client is handed a new ' +
    'one); and ' + MAX_COUNTS_PER_NONCE + ' counts per nonce, after which ' +
    'the nonce is retired the same way.',
  lifetime: function (): string {
    return 'Forgotten with its nonce. Persisted, so a restarted ' +
      'process still refuses a count it accepted; the claim a spend ' +
      'makes is what decides a replay across live nodes.';
  },
  // Counts whose nonce is gone — it can never be presented again (#49 P5).
  eject: function (now: number): number {
    let total = 0;
    realms.list().forEach(function (r: any): void {
      const nonces = digestNonces.realmMap(r.id);
      total += cacheRegistry.mapEjector(digestCounts.realmMap(r.id),
        function (counts: unknown, nonce: unknown): boolean {
          return !nonces.has(nonce);
        })(now);
    });
    return total;
  },
  entries: function (): unknown[] {
    const ttl = scimSeconds('scim.digestNonceSeconds') * 1000;
    const out: unknown[] = [];
    realms.list().forEach(function (r: { id: string }): void {
      const nonces = digestNonces.realmMap(r.id);
      digestCounts.realmMap(r.id).forEach(function (counts: unknown,
                                                    nonce: string): void {
        const record = nonces.get(nonce);
        out.push({ realm: r.id,
                   key: cacheRegistry.digestKey(nonce) + ' — ' +
                     (Array.isArray(counts) ? counts.length : 0) +
                     ' count(s)',
                   validUntil: record ? Number(record.at) + ttl : null,
                   valid: !!record,
                   basis: record ? 'time' : 'its nonce' });
      });
    });
    return out;
  }
});

const hobaChallengesCount = cacheRegistry.register({
  name: 'scim.hoba-challenges',
  title: 'SCIM HOBA challenges',
  description: 'The HOBA challenges /scim/v2 has handed out (RFC 7486), so ' +
    'a signature names one this service issued.',
  owner: 'scim/scim_auth.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a challenge this service issued, so the signature was checked',
  settings: ['scim.maxHobaChallenges', 'scim.hobaMaxAgeSeconds'],
  maxEntries: function (): number | null {
    return scimSeconds('scim.maxHobaChallenges') || null;
  },
  bound: 'Enforced: scim.maxHobaChallenges per realm, the oldest dropped; a ' +
    'client using it is sent a fresh challenge.',
  lifetime: function (): string {
    return 'scim.hobaMaxAgeSeconds (' +
      scimSeconds('scim.hobaMaxAgeSeconds') + ' s) after it was issued, ' +
      'then oldest first past the limit.';
  },
  // What `issueHobaChallenge()` drops before it issues one (#49 P5).
  eject: cacheRegistry.realmMapEjector(realms, hobaChallenges,
    function (at: unknown, challenge: unknown, now: number): boolean {
      return now - Number(at) > scimSeconds('scim.hobaMaxAgeSeconds') * 1000;
    }),
  entries: function (): unknown[] {
    const ttl = scimSeconds('scim.hobaMaxAgeSeconds') * 1000;
    return cacheRegistry.realmMapRows(realms, hobaChallenges,
      function (issuedAt: unknown, challenge: unknown): object {
        return { key: cacheRegistry.digestKey(challenge),
                 validUntil: Number(issuedAt) + ttl };
      });
  }
});

const hobaSeenCount = cacheRegistry.register({
  name: 'scim.hoba-signatures',
  title: 'SCIM HOBA signatures',
  description: 'Each (kid, challenge, nonce) a HOBA signature arrived with, ' +
    'so a copied credential is refused.',
  owner: 'scim/scim_auth.ts',
  scope: 'realm',
  kind: 'replay',
  hitMeaning: 'a signature already seen, so the request was refused',
  settings: ['scim.maxHobaSeen'],
  maxEntries: function (): number | null {
    return scimSeconds('scim.maxHobaSeen') || null;
  },
  bound: 'Enforced: scim.maxHobaSeen per realm, the oldest dropped with the ' +
    'challenge it was made for, so it cannot be replayed against a live one.',
  lifetime: function (): string {
    return 'Until its challenge expires; past the limit, the oldest go ' +
      'with their challenge.';
  },
  // Triples whose challenge is gone: "their triples can never be presented
  // again", the rule the bound already applies (#49 P5).
  eject: function (now: number): number {
    let total = 0;
    realms.list().forEach(function (r: any): void {
      const challenges = hobaChallenges.realmMap(r.id);
      total += cacheRegistry.mapEjector(hobaSeen.realmMap(r.id),
        function (challenge: unknown): boolean {
          return !challenges.has(challenge);
        })(now);
    });
    return total;
  },
  entries: function (): unknown[] {
    const ttl = scimSeconds('scim.hobaMaxAgeSeconds') * 1000;
    const out: unknown[] = [];
    realms.list().forEach(function (r: { id: string }): void {
      const challenges = hobaChallenges.realmMap(r.id);
      hobaSeen.realmMap(r.id).forEach(function (challenge: string,
                                                triple: string): void {
        const issuedAt = challenges.get(challenge);
        out.push({ realm: r.id, key: cacheRegistry.digestKey(triple),
                   validUntil: issuedAt === undefined
                     ? null : Number(issuedAt) + ttl,
                   valid: issuedAt !== undefined,
                   basis: issuedAt === undefined ? 'its challenge' : 'time' });
      });
    });
    return out;
  }
});

// A decision: an accepted credential (`ok: true`) or a refusal value.
type Decision = Record<string, any>;

// One row of the scheme table. See "THE SCHEMES" below.
interface SchemeRow {
  id: string;
  type: string;
  canonical: boolean;
  name: string;
  setting: string;
  primary?: boolean;
  scoped: boolean;
  recorded: boolean;
  spec: string;
  specUri: string;
  description: string;
  attempt: ((req: any, ctx: any) => Decision | null) | null;
  challenge: ((req: any, opts?: any) => string | string[]) | null;
}

// A digest algorithm: its RFC 7616 token and node's hash name.
interface DigestAlgorithm {
  token: string;
  hash: string;
}

// What the four stores above are, as far as this module uses them.
interface ChallengeStore {
  get(key: string): any;
  set(key: string, value: any): unknown;
  has(key: string): boolean;
  delete(key: string): unknown;
  keys(): IterableIterator<string>;
  forEach(fn: (value: any, key: string) => void): void;
  readonly size: number;
}

interface ScimAuthDeps {
  log: typeof helpers.log;
  crypto: typeof crypto;
  stsCrypto: typeof stsCrypto;
  credentials: typeof credentials;
  mode: typeof mode;
  baseUrlOf: typeof helpers.baseUrlOf;
  parseBody: typeof helpers.parseBody;
  hasScope: typeof helpers.hasScope;
  capturingResponse: typeof helpers.capturingResponse;
  capturedDescription: typeof helpers.capturedDescription;
  config: typeof config;
  dpop: typeof dpop;
  stats: typeof stats;
  authn: typeof authn;
  accessGate: typeof accessGate;
  tlsServer: typeof tlsServer;
  directory: typeof directory;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  clusterClaims: typeof clusterClaims;
  scopePolicy: typeof scopePolicy;
  // `common/tls_client_certificates.js`, required when first asked for — see
  // attemptClientCertificate().
  loadTlsClientCertificates(): { checkSocket(socket: any): any };
  digestNonces: ChallengeStore;
  digestCounts: ChallengeStore;
  hobaChallenges: ChallengeStore;
  hobaSeen: ChallengeStore;
}

class ScimAuth {
  // The scheme table and the digest algorithms this build can compute. Both
  // built once, by the constructor — see the header.
  readonly SCHEMES: SchemeRow[];
  readonly DIGEST_ALGORITHMS: DigestAlgorithm[];

  constructor(private readonly deps: ScimAuthDeps) {
    deps.log.debug("Entering ScimAuth.constructor().");
    this.SCHEMES = this.buildSchemes();
    this.DIGEST_ALGORITHMS = this.filterDigestAlgorithms();
    deps.log.debug("Leaving ScimAuth.constructor().");
  }

  // THE WORK LOADING THIS MODULE USED TO DO WITH ITS OWN INSTANCE (#50, R2),
  // run by `common/instance_slot.ts` once for whichever instance is
  // installed: the log line naming the schemes the instance offers.
  static wire(instance: ScimAuth): void {
    helpers.log.debug("Entering ScimAuth.wire().");
    helpers.log.info('scim: the SCIM endpoints authenticate through ' +
      instance.enabledSchemes().map(function (row) {
        return row.name;
      }).join(', ') +
      (instance.authRequired() ? '. A credential is REQUIRED' :
        '. A credential is OPTIONAL (authentication is off)') +
      (instance.permissive()
        ? '; every one of them is permissive, '
        : '; each one is verified (product mode), ') +
      'and the access control policy is on GET /scim.');
    helpers.log.debug("Leaving ScimAuth.wire().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): ScimAuthDeps {
    helpers.log.debug("Entering ScimAuth.defaultDeps().");
    helpers.log.debug("Leaving ScimAuth.defaultDeps().");
    return {
      log: helpers.log,
      crypto: crypto,
      stsCrypto: stsCrypto,
      credentials: credentials,
      mode: mode,
      baseUrlOf: helpers.baseUrlOf,
      parseBody: helpers.parseBody,
      hasScope: helpers.hasScope,
      capturingResponse: helpers.capturingResponse,
      capturedDescription: helpers.capturedDescription,
      config: config,
      dpop: dpop,
      stats: stats,
      authn: authn,
      accessGate: accessGate,
      tlsServer: tlsServer,
      directory: directory,
      errorCodes: errorCodes,
      audit: audit,
      clusterClaims: clusterClaims,
      scopePolicy: scopePolicy,
      loadTlsClientCertificates: function loadTlsClientCertificates() {
        helpers.log.debug("Entering loadTlsClientCertificates().");
        helpers.log.debug("Leaving loadTlsClientCertificates().");
        return require('../common/tls_client_certificates');
      },
      digestNonces: digestNonces,
      digestCounts: digestCounts,
      hobaChallenges: hobaChallenges,
      hobaSeen: hobaSeen
    };
  }

  // ---------------------------------------------------------------------------
  // THE SETTINGS, READ WHERE THEY ARE USED.
  //
  // Every one of them is `runtime: true` in config.js, which is only true
  // because each is read through a function called per request rather than
  // captured in a `const` at require time. That is the rule that file's header
  // states and the one that is easiest to break by accident — a captured value
  // is the single thing /admin/config cannot reach, and it fails in the
  // direction that looks like the console is broken.
  // ---------------------------------------------------------------------------
  authRequired() {
    const { log, mode } = this.deps;
    log.debug("Entering ScimAuth.authRequired().");
    log.debug("Leaving ScimAuth.authRequired().");
    // THE MODE, since 2026-09-06, where this read `scim.authRequired`.
    return mode.gatesScim();
  }

  authDiscovery() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.authDiscovery().");
    log.debug("Leaving ScimAuth.authDiscovery().");
    return config.value('scim.authDiscovery') === true;
  }

  realm() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.realm().");
    log.debug("Leaving ScimAuth.realm().");
    // It goes into a header value, so quotes and anything outside printable
    // ASCII are taken out rather than trusted. node's setHeader THROWS on a
    // non-ASCII value and a quote would close the quoted-string early — either
    // way a typo in a configuration field would turn the one response that
    // explains what to send into a 500, which is the worst place in this module
    // to have one.
    return String(config.value('scim.authRealm') || 'SCIM')
      .replace(/[^\x20-\x7E]/g, '').replace(/"/g, '').trim() || 'SCIM';
  }

  scopeRead() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.scopeRead().");
    log.debug("Leaving ScimAuth.scopeRead().");
    return String(config.value('scim.scopeRead') || 'scim:read');
  }

  scopeWrite() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.scopeWrite().");
    log.debug("Leaving ScimAuth.scopeWrite().");
    return String(config.value('scim.scopeWrite') || 'scim:write');
  }

  private digestPassword() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.digestPassword().");
    log.debug("Leaving ScimAuth.digestPassword().");
    return String(config.value('scim.digestPassword') || '');
  }

  // Read straight through since 2026-09-12. They were `Number(...) || 300` and
  // `|| 600`, which turned a configured value the table accepted into a
  // different one without saying so; the rows carry `min: 1` now, so config.js
  // refuses the one value that fallback was quietly rewriting.
  private digestNonceSeconds() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.digestNonceSeconds().");
    log.debug("Leaving ScimAuth.digestNonceSeconds().");
    return config.value('scim.digestNonceSeconds');
  }

  private hobaMaxAgeSeconds() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.hobaMaxAgeSeconds().");
    log.debug("Leaving ScimAuth.hobaMaxAgeSeconds().");
    return config.value('scim.hobaMaxAgeSeconds');
  }

  private schemeOn(key) {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.schemeOn().");
    log.debug("Leaving ScimAuth.schemeOn().");
    return config.value(key) !== false;
  }

  // ---------------------------------------------------------------------------
  // **HTTP DIGEST IS NOT OFFERED IN PRODUCT MODE (2026-09-12), WHATEVER
  // `scim.authDigest` SAYS.** The reason is arithmetic rather than policy: an
  // RFC 7616 response is a hash over `username:realm:password`, so the SERVER
  // must hold either the password or that exact hash (H(A1)) to check one.
  // Product mode stores a person's password as a salted scrypt hash in
  // `userPassword`, from which neither can be computed — which is the point of
  // storing it that way. So the only Digest this service can perform is the one
  // it has: every user sharing `scim.digestPassword`, which is a password
  // printed in this repository's configuration table and would authenticate ANY
  // name to an endpoint that creates and deletes accounts.
  //
  // Storing H(A1) per person beside the scrypt hash was considered and not
  // done: it is a password-equivalent (whoever reads it authenticates as the
  // person), it is MD5 or SHA-256 without a work factor, and it is bound to one
  // realm string so changing `scim.authRealm` would invalidate every one. That
  // is a weaker store than the one product mode exists to have.
  // ---------------------------------------------------------------------------
  // WHETHER A PRESENTED CREDENTIAL IS CHECKED, for the start-up lines here
  // and in `scim.ts`. Both said "every scheme is permissive" in every mode
  // until #70, which was untrue in product mode: a Basic password is checked
  // against the entry's hash, a HOBA key must have been registered by its
  // signed-in owner, and Digest is not offered at all.
  permissive(): boolean {
    const { log, mode } = this.deps;
    log.debug("Entering ScimAuth.permissive().");
    log.debug("Leaving ScimAuth.permissive().");
    return !mode.verifiesCredentials();
  }

  private digestAllowedByMode() {
    const { log, mode } = this.deps;
    log.debug("Entering ScimAuth.digestAllowedByMode().");
    log.debug("Leaving ScimAuth.digestAllowedByMode().");
    return !mode.verifiesCredentials();
  }

  private schemeAvailable(row) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.schemeAvailable().");
    if (!this.schemeOn(row.setting)) {
      log.debug("Leaving ScimAuth.schemeAvailable().");
      return false;
    }
    if (row.id === 'digest' && !this.digestAllowedByMode()) {
      log.debug("Leaving ScimAuth.schemeAvailable().");
      return false;
    }
    log.debug("Leaving ScimAuth.schemeAvailable().");
    return true;
  }

  // The one refused password, exactly as the password grant, WS-Trust, the
  // WS-Federation sign-in screen and every LDAP bind refuse it. It is what
  // keeps a 401 reachable on a scheme that otherwise accepts anything — and
  // note that Digest needs no such exception, because there the password is
  // really checked.
  static readonly REFUSED_PASSWORD = 'invalid';

  // ---------------------------------------------------------------------------
  // THE SCHEMES.
  //
  // `type` is the RFC 7643 section 5 canonical value, or '' where the scheme
  // has none — see `schemesForConfig()` for what happens to those. `attempt`
  // returns null when the request is not using this scheme at all, and
  // otherwise a decision. `challenge` is what goes in WWW-Authenticate, and a
  // row with none is a scheme a client cannot be INVITED to use (a cookie is
  // not something a server can ask for in a challenge, and a certificate is
  // asked for by the TLS handshake or not at all).
  //
  // The ORDER is the order they are tried and the order they are advertised,
  // and it is deliberate: the two token schemes first because they are the ones
  // with an access control policy behind them, then the two password schemes,
  // then the two that need no Authorization header at all.
  // ---------------------------------------------------------------------------
  private buildSchemes(): SchemeRow[] {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.buildSchemes().");
    const rows: SchemeRow[] = [
      {
        id: 'bearer',
        type: 'oauthbearertoken',
        canonical: true,
        name: 'OAuth 2.0 Bearer Token',
        setting: 'scim.authBearer',
        primary: true,
        scoped: true,
        recorded: false,
        spec: 'RFC 6750',
        specUri: 'https://www.rfc-editor.org/rfc/rfc6750',
        description:
          'An access token issued by this service\'s own authorization ' +
          'server, presented as "Authorization: Bearer <token>". Any grant ' +
          'will do — authorization code, client credentials, password, ' +
          'refresh, device, token exchange — but the SCIM scopes are issued ' +
          'only to a client whose oauthAllowedScope declares them, in every ' +
          'mode. The token must carry the read scope to read and the write ' +
          'scope to write, its client must still declare that scope, it ' +
          'must be one THIS service signed, must not have ' +
          'been revoked, and must not have been narrowed by RFC 8707 to a ' +
          'different resource.',
        attempt: this.attemptBearer.bind(this),
        challenge: this.bearerChallenge.bind(this)
      },
      {
        id: 'dpop',
        type: 'oauth2',
        canonical: true,
        name: 'OAuth 2.0 DPoP (proof-of-possession) token',
        setting: 'scim.authBearer',
        scoped: true,
        recorded: false,
        spec: 'RFC 9449',
        specUri: 'https://www.rfc-editor.org/rfc/rfc9449',
        description:
          'The proof-of-possession token RFC 7644 section 2 names, in the ' +
          'shape this service already issues: an access token bound to a key ' +
          '(cnf.jkt), presented as "Authorization: DPoP <token>" with a ' +
          'fresh DPoP proof over the method and URL. An RFC 8705 ' +
          'certificate-bound token is the other proof-of-possession form and ' +
          'is honoured on the same path. Handled by the same check as the ' +
          'Bearer row — they are one credential with two ways of being held ' +
          '— and listed separately because a client reading this document is ' +
          'entitled to know the bound form is understood.',
        attempt: null,
        challenge: null
      },
      {
        id: 'basic',
        type: 'httpbasic',
        canonical: true,
        name: 'HTTP Basic',
        setting: 'scim.authBasic',
        scoped: false,
        recorded: true,
        spec: 'RFC 7617',
        specUri: 'https://www.rfc-editor.org/rfc/rfc7617',
        description:
          'Any username and any password, exactly as every LDAP bind here ' +
          'succeeds — with the single exception of the password "invalid", ' +
          'which is refused so that a 401 stays reachable. RFC 7644 section ' +
          '2 DISCOURAGES this scheme, in those words, because it rests on a ' +
          'relatively static symmetric secret; it is implemented anyway ' +
          'because it is what a provisioning client most often meets and its ' +
          '401 handling is worth being able to run. No password is checked, ' +
          'so what this authenticates is a NAME, and that name is what the ' +
          'audit log records.',
        attempt: this.attemptBasic.bind(this),
        challenge: this.basicChallenge.bind(this)
      },
      {
        id: 'digest',
        type: 'httpdigest',
        canonical: true,
        name: 'HTTP Digest',
        setting: 'scim.authDigest',
        scoped: false,
        recorded: true,
        spec: 'RFC 7616',
        specUri: 'https://www.rfc-editor.org/rfc/rfc7616',
        description:
          'The one scheme here where the password really is checked, and it ' +
          'cannot not be: the response is a hash over the password, so a ' +
          'server that accepted anything would not be performing the ' +
          'exchange at all. So it does what Kerberos does for the same ' +
          'reason — ANY username authenticates and every one of them shares ' +
          'one password (scim.digestPassword). SHA-256, SHA-512-256 and MD5 ' +
          'are all offered, in that order, with the -sess variants; qop is ' +
          'auth. A wrong password is a 401, a stale nonce is a 401 with ' +
          'stale=true, and a replayed nonce count is a 401 — three negatives ' +
          'that are otherwise hard to provoke.',
        attempt: this.attemptDigest.bind(this),
        challenge: this.digestChallenge.bind(this)
      },
      {
        id: 'hoba',
        type: 'hoba',
        canonical: false,
        name: 'HOBA (HTTP Origin-Bound Authentication)',
        setting: 'scim.authHoba',
        scoped: false,
        recorded: true,
        spec: 'RFC 7486',
        specUri: 'https://www.rfc-editor.org/rfc/rfc7486',
        description:
          'The signature-based scheme RFC 7644 section 2 names, and the only ' +
          'one of the six with no password anywhere in it. A client ' +
          'registers a public key at /.well-known/hoba/register — anybody ' +
          'may, this service registers everybody — and then signs the ' +
          'server\'s challenge together with the origin, the realm and its ' +
          'own key id and nonce. THE SIGNATURE IS REALLY VERIFIED, for the ' +
          'reason the Digest password really is checked: a signature check ' +
          'that passes anything is not the scheme. RSA with SHA-256 ' +
          '(algorithm 0) only.',
        attempt: this.attemptHoba.bind(this),
        challenge: this.hobaChallenge.bind(this)
      },
      {
        id: 'cookie',
        type: 'httpcookie',
        canonical: false,
        name: 'Session cookie',
        setting: 'scim.authCookie',
        scoped: false,
        recorded: false,
        spec: 'RFC 7644 section 2 ("Cookies")',
        specUri: 'https://www.rfc-editor.org/rfc/rfc7644#section-2',
        description:
          'The browser sign-on session this service already has — the one ' +
          '/authn/login establishes and WS-Federation shares — offered here ' +
          'because section 2 names it: "clients may assert HTTP cookies over ' +
          'TLS that contain an authentication state understood by the SCIM ' +
          'service provider". It is what makes a SCIM call from a page on ' +
          'this service work with no second credential. There is no ' +
          'challenge for it: a server cannot ask for a cookie in ' +
          'WWW-Authenticate, so it is used when it is there and never ' +
          'demanded.',
        attempt: this.attemptCookie.bind(this),
        challenge: null
      },
      {
        id: 'clientcert',
        type: 'tlsclientauth',
        canonical: false,
        name: 'TLS client certificate',
        setting: 'scim.authClientCert',
        scoped: false,
        recorded: false,
        spec: 'RFC 8446 / RFC 5280',
        specUri: 'https://www.rfc-editor.org/rfc/rfc8446',
        description:
          'Mutual TLS, the first scheme RFC 7644 section 2 names. Available ' +
          'only where this request arrived over TLS with a certificate that ' +
          'VERIFIED against an anchor somebody POSTed to /tls/trust — so on ' +
          'the main port only when it is bound as HTTPS (global.https, which ' +
          'oauth2.rfc9700 turns on). The identity is the subject in RFC 4514 ' +
          'form, which is the same string /admin/users and the directory ' +
          'already file a certificate under. It is not recorded again here: ' +
          'tls_server.js records a certificate once per CONNECTION on ' +
          'purpose, and counting it per request would undo that from the ' +
          'other end.',
        attempt: this.attemptClientCertificate.bind(this),
        challenge: null
      }
    ];
    log.debug("Leaving ScimAuth.buildSchemes().");
    return rows;
  }

  private schemeById(id) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.schemeById().");
    log.debug("Leaving ScimAuth.schemeById().");
    return this.SCHEMES.filter((row) => { return row.id === id; })[0] || null;
  }

  enabledSchemes() {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.enabledSchemes().");
    log.debug("Leaving ScimAuth.enabledSchemes().");
    return this.SCHEMES.filter((row) => {
      return this.schemeAvailable(row);
    });
  }

  // ---------------------------------------------------------------------------
  // THE CHALLENGES.
  //
  // RFC 7644 section 2's one SHALL. Every refusal from this module carries
  // them, and they are built from the same table the ServiceProviderConfig is,
  // so a scheme that is offered is one a client can actually use and a scheme
  // that is turned off vanishes from both at once.
  //
  // Two schemes have no challenge and that is not an omission: a server cannot
  // ask for a cookie in WWW-Authenticate, and a client certificate is asked for
  // by the TLS handshake or not at all. Both are still published in the
  // ServiceProviderConfig, which is where a client is meant to read them.
  // ---------------------------------------------------------------------------
  private bearerChallenge() {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.bearerChallenge().");
    log.debug("Leaving ScimAuth.bearerChallenge().");
    return 'Bearer realm="' + this.realm() + '", scope="' +
           this.scopeRead() + ' ' + this.scopeWrite() + '"';
  }

  private basicChallenge() {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.basicChallenge().");
    log.debug("Leaving ScimAuth.basicChallenge().");
    // charset="UTF-8" is RFC 7617 section 2.1: without it a client has no way
    // to know how to encode a non-ASCII password, and the two obvious guesses
    // disagree.
    return 'Basic realm="' + this.realm() + '", charset="UTF-8"';
  }

  private hobaChallenge(req) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.hobaChallenge().");
    log.debug("Leaving ScimAuth.hobaChallenge().");
    return 'HOBA challenge="' + this.issueHobaChallenge() + '", max-age="' +
           this.hobaMaxAgeSeconds() + '", realm="' + this.realm() + '"';
  }

  // One challenge per algorithm, strongest first — RFC 7616 section 3.7 says a
  // server MAY send several and SHOULD order them that way, and a client takes
  // the first it understands. MD5 is last and is offered at all because the
  // installed base of Digest clients that speak nothing else is most of it.
  private digestChallenge(req, opts?) {
    const { log, crypto } = this.deps;
    log.debug("Entering ScimAuth.digestChallenge().");
    const stale = !!(opts && opts.stale);
    const nonce = this.issueDigestNonce();
    const opaque = crypto.randomBytes(8).toString('hex');
    const out = this.digestAlgorithms().map((row) => {
      return 'Digest realm="' + this.realm() + '", qop="auth", algorithm=' +
        row.token +
        ', nonce="' + nonce + '", opaque="' + opaque + '", charset=UTF-8' +
        (stale ? ', stale=true' : '');
    });
    log.debug("Leaving ScimAuth.digestChallenge(). " + out.length +
              " challenge(s).");
    return out;
  }

  // Every challenge a caller could act on, in table order. Returned as an ARRAY
  // because express sets one header per element and RFC 7235 allows either that
  // or one comma-joined value — and the array form is the one that survives a
  // Digest challenge, whose value contains commas of its own.
  challenges(req, opts?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.challenges().");
    const out = [];
    this.enabledSchemes().forEach((row) => {
      if (!row.challenge) {
        return;
      }
      const built = row.challenge(req, opts);
      if (Array.isArray(built)) {
        built.forEach((one) => { out.push(one); });
        return;
      }
      if (built) {
        out.push(built);
      }
    });
    log.debug("Leaving ScimAuth.challenges(). " + out.length +
              " challenge(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // A REFUSAL, IN THE SHAPE `scim.ts` NEEDS.
  //
  // This module never touches `res` — see the header — so a refusal is a value:
  // the status, the RFC 7644 section 3.12 `scimType` where one applies (for
  // these two statuses none does, which is why it is null and not invented),
  // the prose, and the headers the answer must carry. `scim.ts` turns it into a
  // SCIM Error object, because what a refusal LOOKS like is protocol knowledge
  // and stays in the protocol module.
  // ---------------------------------------------------------------------------
  // The code for the condition a refusal below records. Non-enumerable, so the
  // refusal object is exactly what it was to anything that reads its members.
  private coded(code, result?) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ScimAuth.coded().");
    log.debug("Leaving ScimAuth.coded().");
    return errorCodes.mark(result, code);
  }

  private refusal(status, detail?, headers?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.refusal().");
    log.debug("Leaving ScimAuth.refusal().");
    return { ok: false, status: status, scimType: null, detail: detail,
             headers: headers || {} };
  }

  // error-code: none — the signature; every caller wraps it in coded()
  private unauthenticated(req, detail?, extra?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.unauthenticated().");
    const headers = Object.assign(
      { 'WWW-Authenticate': this.challenges(req, extra) },
      (extra && extra.headers) || {});
    log.debug("Leaving ScimAuth.unauthenticated().");
    // error-code: none — the helper itself; every caller wraps it in coded()
    return this.refusal(401, detail, headers);
  }

  // ---------------------------------------------------------------------------
  // THE SCHEME OF AN Authorization HEADER, WITHOUT PARSING THE REST OF IT.
  //
  // Read once, at the top of authenticate(), so that a request carrying a
  // credential this service does not offer is told THAT rather than being told
  // a credential is required — "you sent Negotiate and I speak Bearer, Basic,
  // Digest and HOBA" is an answer somebody can act on in one step.
  // ---------------------------------------------------------------------------
  private authorizationScheme(req) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.authorizationScheme().");
    const header = String((req.headers &&
                           req.headers['authorization']) || '').trim();
    if (!header) {
      log.debug("Leaving ScimAuth.authorizationScheme().");
      return '';
    }
    log.debug("Leaving ScimAuth.authorizationScheme().");
    return header.split(/\s+/)[0].toLowerCase();
  }

  // ---------------------------------------------------------------------------
  // OAUTH 2.0 — BEARER AND DPoP.
  //
  // THE CAPTURING RESPONSE, WHICH IS A WORKAROUND AND IS WRITTEN OUT AS ONE.
  //
  // `dpop.presentedAccessToken()` is the single access-token check the four
  // protected endpoints in this service share, and it is worth every line of
  // what follows to reuse it rather than write a fifth: it carries the RFC 9449
  // proof and the 401/DPoP-Nonce handshake, the RFC 8705 certificate binding,
  // the RFC 9700 refusal of a token in the query string, and the RFC 8707
  // audience check. A second implementation would be a second thing to update
  // and would be a version behind within a release.
  //
  // What it will not do is speak SCIM. It ANSWERS the request itself, with an
  // OAuth `{error, error_description}` body — and a SCIM client is owed an RFC
  // 7644 section 3.12 Error object with the status as a string. So it is handed
  // a response object that records instead of writing, and what it would have
  // said is translated into a refusal here. The HEADERS it set are kept
  // verbatim, which is the part that matters most: DPoP-Nonce and the
  // `use_dpop_nonce` challenge are how a wallet learns to retry, and dropping
  // them would leave a conforming client unable to proceed with no error to
  // point at.
  // ---------------------------------------------------------------------------
  private attemptBearer(req, ctx?) {
    const { log, capturingResponse, capturedDescription, dpop, stats,
            errorCodes } = this.deps;
    log.debug("Entering ScimAuth.attemptBearer().");
    const scheme = this.authorizationScheme(req);
    if (scheme !== 'bearer' && scheme !== 'dpop') {
      log.debug("Leaving ScimAuth.attemptBearer(). This request carries no " +
                "OAuth " +
                "credential.");
      return null;
    }

    const shim = capturingResponse();
    const presented = dpop.presentedAccessToken(req, shim.res, 'the SCIM ' +
        'endpoints');
    if (!presented) {
      log.debug("Leaving ScimAuth.attemptBearer(). The shared access token " +
                "check " +
                "refused it.");
      // The shared check marks its own code on the stand-in it answered; that
      // is the specific condition, and this one is only the fallback.
      return this.coded(errorCodes.codeOf(shim.res) || 'STS-SCIM-0030',
        this.refusal(shim.captured.status || 401,
        capturedDescription(shim.captured) ||
        'This access token could not be accepted.', shim.captured.headers));
    }

    // The row it counts as. One credential, two ways of holding it: the DPoP
    // row exists so that a client reading the ServiceProviderConfig can see the
    // bound form is understood, and this is where the two rejoin.
    const row = presented.scheme === 'dpop' ? 'dpop' : 'bearer';
    const claims = presented.claims || {};

    // The same four checks /oauth2/userinfo makes, and for the same reason it
    // makes them rather than accepting a foreign token the way the OID4VCI
    // credential endpoints do: this is not a resource somebody else's
    // authorization server can speak for. A scope is a permission, and a
    // permission read off a token nobody verified is a permission its holder
    // wrote for themselves.
    if (!presented.verified) {
      log.debug("Leaving ScimAuth.attemptBearer(). The token is not one this " +
                "service " +
                "signed.");
      return this.coded('STS-SCIM-0031', this.refusal(401,
        'This access token was not issued by this service, or its signature ' +
        'does not verify against the key at /oauth2/jwks. Unlike the OID4VCI ' +
        'credential endpoints, which accept a token from a separate ' +
        'authorization server, these endpoints cannot: the scope on a token ' +
        'nobody verified is a permission its holder wrote for themselves. ' +
        'Get a token from this service\'s token endpoint with any grant.',
        { 'WWW-Authenticate': this.challenges(req) }));
    }
    if (claims.typ !== 'Bearer') {
      log.debug("Leaving ScimAuth.attemptBearer(). That is " +
                "a " + claims.typ + " token.");
      return this.coded('STS-SCIM-0032', this.refusal(401,
        'This is a "' + (claims.typ || 'unknown') + '" token, not an access ' +
        'token. Every token this service issues is signed with the same key, ' +
        'so the typ claim is the only thing that tells a refresh token or an ' +
        'ID Token apart from the access token these endpoints need.',
        { 'WWW-Authenticate': this.challenges(req) }));
    }
    if (stats.isRevoked(claims.jti)) {
      log.debug("Leaving ScimAuth.attemptBearer(). The token was revoked.");
      return this.coded('STS-SCIM-0033', this.refusal(401,
        'This access token was revoked — at /oauth2/revoke, from the admin ' +
        'console, or by being rotated. Introspection reports it inactive and ' +
        'these endpoints answer the same way; a revocation only some ' +
        'endpoints honoured would be worse than none.',
        { 'WWW-Authenticate': this.challenges(req) }));
    }

    // WHOSE token it is. A client_credentials token has no user behind it,
    // which is not a problem for provisioning — it is the ordinary shape for it
    // — so the client_id is the principal and `isClient` says why the name
    // looks like an application. `username` is what every user-bearing grant
    // here carries alongside `sub`, and it is the form the audit log and
    // /admin/users file people under.
    const isClient = !claims.username && !claims.sub;
    const principal = String(claims.username || claims.sub ||
                             claims.client_id || '').trim();

    log.debug("Leaving ScimAuth.attemptBearer(). " + row + " for " +
              (principal || '(unnamed)') + ".");
    return {
      ok: true,
      scheme: row,
      principal: principal,
      isClient: isClient,
      scopes: String(claims.scope || ''),
      clientId: String(claims.client_id || ''),
      sub: String(claims.sub || ''),
      jti: String(claims.jti || ''),
      note: 'access token' + (row === 'dpop' ? ', DPoP-bound' : '') +
            (presented.jkt ?
              ' (jkt ' + presented.jkt.slice(0, 12) + '...)' : '')
    };
  }

  // ---------------------------------------------------------------------------
  // HTTP BASIC (RFC 7617).
  //
  // IN DEVELOPMENT MODE: any username, any password but one. That is the LDAP
  // bind rule stated again, and the exception is the same reserved value:
  // `invalid` is refused so that a 401 is reachable on a scheme which otherwise
  // cannot produce one. Note what is NOT checked there — the password — which
  // is why what this authenticates is a name and why the row says so in the
  // ServiceProviderConfig rather than leaving a reader to assume a check
  // happened. In product mode the password is verified (see the call below).
  // ---------------------------------------------------------------------------
  private attemptBasic(req, ctx?) {
    const { log, credentials, mode, errorCodes } = this.deps;
    log.debug("Entering ScimAuth.attemptBasic().");
    if (this.authorizationScheme(req) !== 'basic') {
      log.debug("Leaving ScimAuth.attemptBasic(). Not a Basic credential.");
      return null;
    }
    const header = String(req.headers['authorization'] || '');
    const encoded = header.replace(/^\s*Basic\s+/i, '').trim();
    let decoded = '';
    try {
      decoded = Buffer.from(encoded, 'base64').toString('utf8');
    } catch (e) {
      // Not base64. Reported as a refusal rather than as a missing credential,
      // because the client did present one and the difference is what it has to
      // fix.
      log.debug("Caught in ScimAuth.attemptBasic(): " +
                ((e && e.message) || e));
      log.debug("Leaving ScimAuth.attemptBasic(). The credential is not " +
                "base64.");
      return this.coded('STS-SCIM-0034', this.unauthenticated(req,
        'The Basic credential is not base64 (RFC 7617 section ' +
        '2): ' + e.message));
    }
    const cut = decoded.indexOf(':');
    if (cut < 0) {
      log.debug("Leaving ScimAuth.attemptBasic(). There is no colon in it.");
      return this.coded('STS-SCIM-0035', this.unauthenticated(req,
        'A Basic credential is base64(user-id ":" password) — RFC 7617 ' +
        'section 2. What arrived carries no colon, so there is no way to ' +
        'tell where the username ends.'));
    }
    const username = decoded.slice(0, cut).trim();
    const password = decoded.slice(cut + 1);
    if (!username) {
      log.debug("Leaving ScimAuth.attemptBasic(). The username is empty.");
      return this.coded('STS-SCIM-0036', this.unauthenticated(req,
        'The Basic credential names nobody. This service checks no password, ' +
        'so the username is the whole of what it authenticates and an empty ' +
        'one authenticates nothing.'));
    }
    // THE CREDENTIAL (2026-09-06). One call, both modes. In development this is
    // exactly what the branch it replaced did — refuse the reserved string,
    // accept everything else including an empty password — and in product mode
    // it verifies against the hashed `userPassword` on the person's entry.
    const early = req[ScimAuth.BASIC_VERDICT];
    const checked = (early && early.username === username &&
                     early.digest === crypto.createHash('sha256')
                       .update(password).digest('hex'))
      ? early.checked
      : credentials.verify(username, password, { via: 'SCIM HTTP Basic',
                                                 door: 'scim' });
    if (!checked.ok) {
      log.debug("Leaving ScimAuth.attemptBasic(). The credential was " +
                "refused: " +
                checked.reason);
      // The verifier's own code for WHY (common/credentials.ts), or this one.
      return this.coded(errorCodes.codeOf(checked) || 'STS-SCIM-0037',
        this.unauthenticated(req, checked.reason === 'reserved-refusal'
        ? 'The password "' + ScimAuth.REFUSED_PASSWORD +
          '" is refused on purpose — the ' +
          'same reserved value the OAuth password grant, WS-Trust, the ' +
          'WS-Federation sign-in screen and every LDAP bind here refuse. In ' +
          'development mode every other password is accepted, including no ' +
          'password at all. Nothing else about this request was wrong.'
        // ONE SENTENCE FOR EVERY OTHER FAILURE, which is the account
        // enumeration answer avoided: "no such user" and "wrong password" must
        // not be distinguishable to a caller. The reason is in the log.
        : 'Authentication failed. In product mode a Basic credential is ' +
          'verified against the hashed userPassword on the person\'s ' +
          'directory entry, and a person with none cannot authenticate at ' +
          'all.'));
    }
    log.debug("Leaving ScimAuth.attemptBasic(). " + username + " is accepted.");
    return {
      ok: true, scheme: 'basic', principal: username, isClient: false,
      scopes: '',
      // An app password is said so (#101).
      note: checked.reason === 'app-password' && checked.appPassword
        ? 'HTTP Basic (an app password, "' + checked.appPassword.name +
          '", was verified)'
        : mode.verifiesCredentials()
        ? 'HTTP Basic (the password was verified)'
        : 'HTTP Basic (no password was checked)'
    };
  }

  // ---------------------------------------------------------------------------
  // HTTP DIGEST (RFC 7616), WHICH IS THE ONE SCHEME HERE THAT CHECKS A PASSWORD
  // IN DEVELOPMENT MODE — AND CANNOT NOT. (In product mode Basic is verified
  // too, and Digest is not offered at all: see `digestAllowedByMode()`.)
  //
  // This is the Kerberos argument, made again for the same reason. The digest
  // response is a hash OVER the password, so a server that accepted any
  // response would not be performing the exchange at all: nothing would be
  // exercised at the client end either, since a client's digest code is exactly
  // the part that computes that hash. So this does what the KDC does — ANY
  // username authenticates, and every one of them shares one password
  // (`scim.digestPassword`, `password!` by default, which is the same value
  // KRB5_USER_PASSWORD defaults to so that a tester has one fact to remember).
  //
  // That makes three negatives reachable that no other scheme here can produce:
  // a wrong password (401), an expired nonce (401 with `stale=true`, which a
  // conforming client retries silently and a hand-written one usually does
  // not), and a REPLAYED nonce count (401, no stale — the credential was valid
  // and has been seen before, which is a different sentence and deserves a
  // different answer).
  //
  // The algorithms are offered strongest first because RFC 7616 section 3.7
  // says so and because a client takes the first it understands. MD5 is last
  // and is offered at all because most of the installed base of Digest clients
  // speaks nothing else; it is not a recommendation, and the page says so.
  // ---------------------------------------------------------------------------
  static readonly DIGEST_CANDIDATES: readonly DigestAlgorithm[] = [
    { token: 'SHA-256', hash: 'sha256' },
    { token: 'SHA-512-256', hash: 'sha512-256' },
    { token: 'MD5', hash: 'md5' }
  ];

  private filterDigestAlgorithms(): DigestAlgorithm[] {
    const { log, crypto } = this.deps;
    log.debug("Entering ScimAuth.filterDigestAlgorithms().");
    const out = ScimAuth.DIGEST_CANDIDATES.filter(function (row) {
      // Checked against the openssl this process actually has rather than
      // assumed. `sha512-256` is missing from some builds and `md5` from a
      // FIPS one, and a challenge naming an algorithm this process cannot
      // compute would be an instruction a client follows into a 500.
      const available = crypto.getHashes().indexOf(row.hash) >= 0;
      if (!available) {
        log.warn('scim: this node build cannot compute ' + row.hash +
                 ', so HTTP Digest will not offer ' + row.token +
                 '. The remaining algorithms are unaffected.');
      }
      return available;
    });
    log.debug("Leaving ScimAuth.filterDigestAlgorithms().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHAT IS OFFERED, WHICH IS WHAT THIS BUILD CAN COMPUTE LESS WHAT A
  // DEPLOYMENT HAS TURNED OFF (2026-09-12). `scim.digestMd5` drops MD5: RFC
  // 7616 section 3.7 keeps it for backward compatibility and says nothing in
  // favour of it, and a deployment whose clients speak SHA-256 has no reason to
  // leave a collision-broken hash on offer. On by default, because the
  // installed base of Digest clients is mostly MD5 and that is what this
  // service always offered. `DIGEST_ALGORITHMS` stays the table of what this
  // BUILD can compute, for `admin-ui/crypto_metadata.ts`; this is what a
  // challenge carries and a credential may use.
  // ---------------------------------------------------------------------------
  private digestAlgorithms() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.digestAlgorithms().");
    const md5 = config.value('scim.digestMd5') !== false;
    log.debug("Leaving ScimAuth.digestAlgorithms().");
    return this.DIGEST_ALGORITHMS.filter((row) => {
      return md5 || row.token !== 'MD5';
    });
  }

  // The Set of counts for a nonce, made on first use — a nonce another process
  // issued arrives with none.
  // The counts accepted under a nonce, as a Set to ask. The stored row is an
  // array (see the declaration), so this is a copy: a count is added through
  // addCount(), which writes the row back and so journals it.
  private countsOf(nonce) {
    const { log, digestCounts } = this.deps;
    log.debug("Entering ScimAuth.countsOf().");
    const stored = digestCounts.get(nonce);
    if (stored) {
      digestCountsCount.hit();
    } else {
      digestCountsCount.miss();
    }
    log.debug("Leaving ScimAuth.countsOf().");
    return new Set(Array.isArray(stored) ? stored.map(String) : []);
  }

  // One accepted count recorded; answers how many the nonce now has.
  private addCount(nonce, nc) {
    const { log, digestCounts } = this.deps;
    log.debug("Entering ScimAuth.addCount().");
    const stored = digestCounts.get(nonce);
    const list = Array.isArray(stored) ? stored.map(String) : [];
    if (!stored) {
      cacheRegistry.makeRoom(digestCounts, this.maxDigestNonces(),
                             { counter: digestCountsCount });
    }
    if (list.indexOf(String(nc)) < 0) {
      list.push(String(nc));
    }
    digestCounts.set(nonce, list);
    log.debug("Leaving ScimAuth.addCount(). " + list.length + " count(s).");
    return list.length;
  }

  private forgetDigestNonce(nonce) {
    const { log, digestNonces, digestCounts } = this.deps;
    log.debug("Entering ScimAuth.forgetDigestNonce().");
    digestNonces.delete(nonce);
    digestCounts.delete(nonce);
    log.debug("Leaving ScimAuth.forgetDigestNonce().");
  }

  private maxDigestNonces() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.maxDigestNonces().");
    log.debug("Leaving ScimAuth.maxDigestNonces().");
    return config.value('scim.maxDigestNonces');
  }

  private issueDigestNonce() {
    const { log, crypto, digestNonces } = this.deps;
    log.debug("Entering ScimAuth.issueDigestNonce().");
    const now = Date.now();
    const ttl = this.digestNonceSeconds() * 1000;
    const expired = [];
    digestNonces.forEach((record, key) => {
      if (now - record.at > ttl) {
        expired.push(key);
      }
    });
    expired.forEach((key) => {
      this.forgetDigestNonce(key);
    });
    while (digestNonces.size >= this.maxDigestNonces()) {
      // The oldest first. A Map iterates in insertion order, so the first key
      // is the least recently issued.
      this.forgetDigestNonce(digestNonces.keys().next().value);
    }
    const nonce = crypto.randomBytes(18).toString('base64');
    // `{ at }` only — the counts are not in the row (see the declaration).
    digestNonces.set(nonce, { at: now });
    log.debug("Leaving ScimAuth.issueDigestNonce(). " + digestNonces.size +
              " nonce(s) " +
        "outstanding.");
    return nonce;
  }

  // The auth-params of a credential, for the two schemes here that have any:
  // Digest and HOBA. RFC 7235 section 2.1 gives them one grammar, so this reads
  // both — RFC 7616 section 3.4 allows each value to be a quoted string or a
  // bare token, and which of the two a given parameter uses differs between
  // implementations (`algorithm` and `nc` are conventionally bare and `qop` is
  // sent both ways), so both forms are read for every parameter rather than per
  // parameter. Getting that wrong reads `qop` as `"auth"` with the quotes
  // included, which then matches nothing.
  private authParams(header) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.authParams().");
    const out: Record<string, any> = {};
    const text = String(header || '')
      .replace(/^\s*[A-Za-z][A-Za-z0-9_-]*\s+/, '');
    const pattern = /([a-zA-Z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))/g;
    let match = pattern.exec(text);
    while (match) {
      out[match[1].toLowerCase()] = match[2] !== undefined
        ? match[2].replace(/\\(.)/g, '$1')
        : match[3];
      match = pattern.exec(text);
    }
    log.debug("Leaving ScimAuth.authParams(). " + Object.keys(out).length +
              " " +
        "parameter(s).");
    return out;
  }

  private digestHash(algorithmToken, text?) {
    const { log, crypto } = this.deps;
    log.debug("Entering ScimAuth.digestHash().");
    const base = String(algorithmToken || 'MD5').replace(/-sess$/i, '')
                                                .toUpperCase();
    const row = this.digestAlgorithms().filter((candidate) => {
      return candidate.token === base;
    })[0];
    if (!row) {
      log.debug("Leaving ScimAuth.digestHash().");
      return null;
    }
    log.debug("Leaving ScimAuth.digestHash().");
    return crypto.createHash(row.hash).update(text, 'utf8').digest('hex');
  }

  private attemptDigest(req, ctx?) {
    const { log, stsCrypto, mode, config, digestNonces } = this.deps;
    log.debug("Entering ScimAuth.attemptDigest().");
    if (this.authorizationScheme(req) !== 'digest') {
      log.debug("Leaving ScimAuth.attemptDigest(). Not a Digest credential.");
      return null;
    }
    const params = this.authParams(req.headers['authorization']);
    const algorithm = String(params.algorithm || 'MD5');
    const session = /-sess$/i.test(algorithm);

    // Refused rather than ignored. RFC 7616 section 3.4.4 makes `userhash` the
    // client saying "the username above is H(user:realm)", and a server that
    // read it as a plain username would authenticate somebody called
    // `3d78...` — a name nobody has, silently. This service never sends
    // `userhash=true` in a challenge, which is how it declares it cannot do
    // this; a client that sends it anyway is told so.
    if (String(params.userhash || '').toLowerCase() === 'true') {
      log.debug("Leaving ScimAuth.attemptDigest(). userhash was asked for.");
      return this.coded('STS-SCIM-0038', this.unauthenticated(req,
        'This credential sets userhash=true (RFC 7616 section 3.4.4), and ' +
        'this server does not support it — which is why its challenges never ' +
        'carry userhash=true. It would have to find the user by the hash of ' +
        'their name, and a directory that creates every name it is shown has ' +
        'nothing to search. Send the username in the clear.'));
    }
    if (this.digestHash(algorithm, '') === null) {
      log.debug("Leaving ScimAuth.attemptDigest(). Unknown " +
                "algorithm " + algorithm + ".");
      return this.coded('STS-SCIM-0039', this.unauthenticated(req,
        'This credential names algorithm=' + algorithm +
        ' and this server offers ' +
        this.digestAlgorithms().map((row) => { return row.token; }).join(', ') +
        ' (each also with the -sess variant). The challenge lists what it ' +
        'will accept.' +
        (config.value('scim.digestMd5') === false && /^md5/i.test(algorithm)
          ? ' MD5 is turned off on this service (scim.digestMd5).' : '')));
    }
    const qop = String(params.qop || '').toLowerCase();
    if (qop && qop !== 'auth') {
      // auth-int is the other RFC 7616 quality of protection and is
      // deliberately not offered: it hashes the entity body, and the body this
      // service sees has been through the express text parser and re-encoded,
      // so an integrity check computed here could disagree with what was
      // actually sent for reasons that have nothing to do with the credential.
      // A check that is wrong occasionally and silently is worse than one that
      // is absent and says so.
      log.debug("Leaving ScimAuth.attemptDigest(). qop=" + qop + " is not " +
                "offered.");
      return this.coded('STS-SCIM-0040', this.unauthenticated(req,
        'This credential asks for qop=' + qop + ' and this server offers ' +
        'qop="auth" only. auth-int hashes the entity body, and the body this ' +
        'service sees has already been decoded and re-encoded by its own ' +
        'parser — an integrity check computed over that could disagree with ' +
        'what was sent, which is a worse answer than not offering it.'));
    }
    const username = String(params.username || '').trim();
    if (!username || !params.nonce || !params.response) {
      log.debug("Leaving ScimAuth.attemptDigest(). It is missing a required " +
                "parameter.");
      return this.coded('STS-SCIM-0041', this.unauthenticated(req,
        'A Digest credential needs at least username, realm, nonce, uri and ' +
        'response (RFC 7616 section 3.4), and with qop=auth it needs cnonce ' +
        'and nc as well. What arrived is missing one of them.'));
    }

    const record = digestNonces.get(String(params.nonce));
    if (record) {
      digestNoncesCount.hit();
    } else {
      digestNoncesCount.miss();
    }
    if (!record) {
      log.debug("Leaving ScimAuth.attemptDigest(). The nonce is not one this " +
                "server " +
                "issued.");
      return this.coded('STS-SCIM-0042', this.unauthenticated(req,
        'This nonce is not one this server issued, or it has already been ' +
        'forgotten. A fresh challenge is on this response with stale=true, ' +
        'which RFC 7616 section 3.3 says a client should retry with the same ' +
        'credentials rather than asking a person again.',
        { stale: true }));
    }
    if (Date.now() - record.at > this.digestNonceSeconds() * 1000) {
      this.forgetDigestNonce(String(params.nonce));
      log.debug("Leaving ScimAuth.attemptDigest(). The nonce is stale.");
      return this.coded('STS-SCIM-0043', this.unauthenticated(req,
        'This nonce is older than ' + this.digestNonceSeconds() + ' seconds ' +
        '(scim.digestNonceSeconds). The challenge on this response carries ' +
        'stale=true, so retry it with the same credentials.',
        { stale: true }));
    }

    // qop=auth requires a nonce count, and the count is what makes a Digest
    // credential single-use. A repeat is refused WITHOUT stale=true,
    // deliberately: stale means "your credential was fine, ask me again", and a
    // replay is the opposite claim.
    if (qop === 'auth') {
      const nc = String(params.nc || '');
      const cnonce = String(params.cnonce || '');
      if (!nc || !cnonce) {
        log.debug("Leaving ScimAuth.attemptDigest(). qop=auth with no nc or " +
                  "cnonce.");
        return this.coded('STS-SCIM-0044', this.unauthenticated(req,
          'With qop=auth a credential must carry both cnonce and nc (RFC ' +
          '7616 section 3.4). Without the nonce count there is nothing to ' +
          'stop the same credential being replayed, which is most of what ' +
          'the nonce is for.'));
      }
      if (this.countsOf(String(params.nonce)).has(nc)) {
        log.debug("Leaving ScimAuth.attemptDigest(). nc=" + nc +
                  " has been used already.");
        return this.coded('STS-SCIM-0045', this.unauthenticated(req,
          'This nonce count (nc=' + nc + ') has been used with this nonce ' +
          'already. That is a replay, and it is refused WITHOUT stale=true — ' +
          'stale would mean the credential was fine and should be retried, ' +
          'and this one has been seen before. Increment nc.'));
      }
    }

    // RFC 7616 section 3.4.6: A2 is method ":" uri, where uri is the
    // request-target the CLIENT put in the credential. It is compared with what
    // actually arrived, because a credential computed over a different URI is
    // one that was minted for a different request — which is exactly what a
    // replay across endpoints looks like.
    const uri = String(params.uri || '');
    const target = String(req.originalUrl || req.url || '');
    if (uri && uri !== target) {
      log.debug("Leaving ScimAuth.attemptDigest(). The uri does not match " +
                "the request.");
      return this.coded('STS-SCIM-0046', this.unauthenticated(req,
        'The uri in this credential is ' +
        '"' + uri + '" and this request was for "' +
        target +
        '". RFC 7616 section 3.4.6 hashes the request-target into the ' +
        'response, so the two have to be the same string — a credential ' +
        'computed over a different URI was minted for a different request.'));
    }

    const password = this.digestPassword();
    let ha1 = this.digestHash(algorithm,
                              username + ':' + this.realm() + ':' + password);
    if (session) {
      // RFC 7616 section 3.4.2: the -sess variants fold the nonces into A1, so
      // that the long-term secret is hashed once per session rather than once
      // per request.
      ha1 = this.digestHash(algorithm,
                       ha1 + ':' + params.nonce + ':' + (params.cnonce || ''));
    }
    const ha2 = this.digestHash(
      algorithm, String(req.method || 'GET').toUpperCase() + ':' + uri);
    const expected = qop === 'auth'
      ? this.digestHash(algorithm, ha1 + ':' + params.nonce + ':' +
                        params.nc + ':' + params.cnonce + ':auth:' + ha2)
      : this.digestHash(algorithm, ha1 + ':' + params.nonce + ':' + ha2);

    const given = String(params.response || '').toLowerCase();
    const same = stsCrypto.constantTimeEquals(given, expected);
    if (!same) {
      log.debug("Leaving ScimAuth.attemptDigest(). The response hash does " +
                "not match.");
      // **THE PASSWORD IS NAMED ONLY WHERE THE TEST CONTROLS ARE OPEN
      // (2026-09-12).** It was printed in every 401, which on a development
      // service is the point — a tester has one fact to remember — and on any
      // other is a shared credential handed to whoever sends a wrong one.
      return this.coded('STS-SCIM-0047', this.unauthenticated(req,
        'The digest response does not match. This is the one scheme here ' +
        'where the password is really checked — it has to be, since the ' +
        'response IS a hash over it — so every user shares one ' +
        'password' + (mode.opensTestControls()
          ? ', which is "' + (password ? password : '(empty)') + '" unless ' +
            'scim.digestPassword has been changed. Any username works with it.'
          : ' (scim.digestPassword). It is not repeated here.')));
    }
    if (qop === 'auth') {
      const held = this.addCount(String(params.nonce), String(params.nc));
      if (held >= MAX_COUNTS_PER_NONCE) {
        // The per-nonce bound (see the declaration): this credential is
        // accepted, and the nonce is retired so the next one is stale.
        this.forgetDigestNonce(String(params.nonce));
        digestCountsCount.evicted(1);
      }
    }

    // RFC 7616 section 3.5, the Authentication-Info response header. It is what
    // lets a client authenticate the SERVER, and leaving it out is the
    // commonest way to implement Digest and give a client nothing to verify.
    const rspauth = qop === 'auth'
      ? this.digestHash(algorithm, ha1 + ':' + params.nonce + ':' +
                        params.nc + ':' + params.cnonce + ':auth:' +
                        this.digestHash(algorithm, ':' + uri))
      : '';

    log.debug("Leaving ScimAuth.attemptDigest(). " + username + " is " +
              "accepted.");
    // WHAT IS SPENT ACROSS THE CLUSTER, and only with qop=auth: without a nonce
    // count RFC 7616 lets a nonce be reused until it expires, which is what
    // this door has always allowed. The claim lives as long as the nonce could.
    return this.withSpend({
      ok: true, scheme: 'digest', principal: username, isClient: false,
      scopes: '',
      headers: rspauth
        ? { 'Authentication-Info': 'qop=auth, rspauth="' + rspauth +
                                   '", cnonce="' +
                                   params.cnonce + '", nc=' + params.nc }
        : {},
      note: 'HTTP Digest (' + algorithm +
            '), and the password really was checked'
    }, qop === 'auth' ? {
      scope: 'scim.digest-nonce-count',
      value: String(params.nonce) + '\n' + String(params.nc),
      ttlMs: Math.max(1000, this.digestNonceSeconds() * 1000 -
                            (Date.now() - record.at)),
      code: 'STS-SCIM-0076',
      detail: 'This nonce count (nc=' + params.nc +
              ') has been used with this ' +
              'nonce already, at another node of this service. That is a ' +
              'replay, and it is refused WITHOUT stale=true. Increment nc.'
    } : null);
  }

  // ---------------------------------------------------------------------------
  // HOBA — HTTP ORIGIN-BOUND AUTHENTICATION (RFC 7486).
  //
  // The third scheme RFC 7644 section 2 names, and the only one of the six with
  // no password anywhere in it: the client holds a key pair, registers the
  // public half once, and thereafter signs a challenge this server issued
  // together with the origin, the realm, its key id and a nonce of its own.
  // Nothing shared, so nothing to leak.
  //
  // **THE SIGNATURE IS REALLY VERIFIED**, which is the same decision the Digest
  // password really being checked is, and for the same reason: a signature
  // check that passes anything is not the scheme, and the part of a client this
  // exercises IS the signing. What is permissive is the REGISTRATION — in
  // development mode anybody may register a key for any name, exactly as any
  // name authenticates everywhere else there. The turnstile, not the lock.
  // Outside development it is confined (2026-09-12): see `registerHobaKey()`.
  //
  // Two details of RFC 7486 are easy to get wrong and both are written out
  // below: the TBS blob is length-prefixed with a COLON and the fields are
  // concatenated with nothing between them (so `3:abc` and not `3:abc.`), and
  // the origin carries an explicit PORT even when it is the scheme's default,
  // because the specification says there is no default. Get either wrong and
  // every signature fails with nothing to look at — both ends are computing
  // over different bytes.
  //
  // The registered algorithms are 0 (RSA-SHA256) and 1 (RSA-SHA1). Only 0 is
  // accepted, and that is a refusal with a reason rather than a gap: SHA-1
  // signatures are the thing nobody should be building a client around in 2026,
  // and this service publishes what it will not do rather than letting it be
  // discovered.
  // ---------------------------------------------------------------------------
  static readonly HOBA_ALG_RSA_SHA256 = '0';

  private maxHobaChallenges() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.maxHobaChallenges().");
    log.debug("Leaving ScimAuth.maxHobaChallenges().");
    return config.value('scim.maxHobaChallenges');
  }

  private maxHobaSeen() {
    const { log, config } = this.deps;
    log.debug("Entering ScimAuth.maxHobaSeen().");
    log.debug("Leaving ScimAuth.maxHobaSeen().");
    return config.value('scim.maxHobaSeen');
  }

  private issueHobaChallenge() {
    const { log, crypto, hobaChallenges } = this.deps;
    log.debug("Entering ScimAuth.issueHobaChallenge().");
    const now = Date.now();
    const ttl = this.hobaMaxAgeSeconds() * 1000;
    hobaChallenges.forEach((at, key) => {
      if (now - at > ttl) {
        hobaChallenges.delete(key);
      }
    });
    while (hobaChallenges.size >= this.maxHobaChallenges()) {
      hobaChallenges.delete(hobaChallenges.keys().next().value);
    }
    const challenge = crypto.randomBytes(16).toString('base64url');
    hobaChallenges.set(challenge, now);
    log.debug("Leaving ScimAuth.issueHobaChallenge(). " + hobaChallenges.size +
              " " +
        "outstanding.");
    return challenge;
  }

  // The web origin, RFC 7486 section 4: scheme, authority and port, with the
  // port ALWAYS present because that specification gives it no default. Built
  // from baseUrlOf() so that it agrees with every other URL this service
  // publishes — including behind a proxy, where `global.trustProxy` decides
  // whether the forwarded headers are believed. A client computing the origin
  // from the URL it dialled and a server computing it from the socket are the
  // commonest reason a HOBA signature does not verify, so this is one decision
  // and not two.
  private hobaOrigin(req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering ScimAuth.hobaOrigin().");
    const base = String(baseUrlOf(req) || '');
    const match = /^([a-z]+):\/\/([^/:]+)(?::(\d+))?/i.exec(base);
    if (!match) {
      log.debug("Leaving ScimAuth.hobaOrigin(). The base URL could not be " +
                "read.");
      return base;
    }
    const port = match[3] ||
      (match[1].toLowerCase() === 'https' ? '443' : '80');
    log.debug("Leaving ScimAuth.hobaOrigin(). " + match[1] + "://" +
              match[2] + ":" + port);
    return match[1].toLowerCase() + '://' + match[2] + ':' + port;
  }

  // RFC 7486 section 5's to-be-signed blob. Each field is preceded by the
  // number of octets in it and a colon, and the six are concatenated with
  // nothing between them. The realm may be empty and is still present as `0:`,
  // which is the case a hand-written client most often drops.
  private hobaTbs(fields) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.hobaTbs().");
    log.debug("Leaving ScimAuth.hobaTbs().");
    return fields.map((value) => {
      const text = String(value === undefined || value === null ? '' : value);
      return Buffer.byteLength(text, 'utf8') + ':' + text;
    }).join('');
  }

  // ---------------------------------------------------------------------------
  // WHERE A REGISTERED KEY LIVES, WHICH IS THE DIRECTORY AND NOT A MAP.
  //
  // The same decision applications.js and the SPIFFE registry made: the store
  // is `ou=users`, so a registered key is visible in an `ldapsearch`, on
  // /admin/users and in the entry every other family here already writes to. A
  // Map beside the directory would have been fifteen lines shorter and would
  // have been the one credential in this service that nothing else could see.
  //
  // The value is `<kid> <base64 DER>` in a multi-valued `hobaPublicKey` — this
  // service's own attribute name, like `scimExternalId` and the `x509*` ones,
  // because nothing standard carries a HOBA client public key.
  //
  // **THE MERGE DROPS THE THREE OPERATIONAL ATTRIBUTES**, for the reason
  // scim_map.ts's NOT_STORED does: writePerson() REPLACES the attribute set,
  // and `entryDN` is synthesised on every read rather than stored — carrying it
  // through would write a stored copy of the DN, which is a second definition
  // of one fact and the one that goes stale on a rename.
  // ---------------------------------------------------------------------------
  static readonly HOBA_ATTRIBUTE = 'hobaPublicKey';
  static readonly NOT_STORED = ['entrydn', 'createtimestamp',
                                'modifytimestamp'];

  private mergeableAttributes(entry) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.mergeableAttributes().");
    const out: Record<string, any> = {};
    Object.keys((entry && entry.attributes) || {}).forEach((name) => {
      if (ScimAuth.NOT_STORED.indexOf(String(name).toLowerCase()) >= 0) {
        return;
      }
      const value = entry.attributes[name];
      out[name] = Array.isArray(value) ? value.slice(0) : [String(value)];
    });
    log.debug("Leaving ScimAuth.mergeableAttributes().");
    return out;
  }

  // The username an entry answers to. `uid` first and the naming value second,
  // which is the pair existingUserEntry() matches on — an entry named by a
  // certificate's `cn` has no `uid` until somebody signs in with that name.
  private usernameOfEntry(entry) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.usernameOfEntry().");
    const attributes = (entry && entry.attributes) || {};
    const uid = Object.keys(attributes).filter((name) => {
      return name.toLowerCase() === 'uid';
    })[0];
    if (uid && attributes[uid] && attributes[uid].length) {
      log.debug("Leaving ScimAuth.usernameOfEntry().");
      return String(attributes[uid][0]);
    }
    const rdn = String((entry && entry.dn) || '').split(',')[0];
    log.debug("Leaving ScimAuth.usernameOfEntry().");
    return rdn.indexOf('=') >= 0 ? rdn.slice(rdn.indexOf('=') + 1) : rdn;
  }

  private hobaKeysOf(entry) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.hobaKeysOf().");
    const attributes = (entry && entry.attributes) || {};
    const name = Object.keys(attributes).filter((key) => {
      return key.toLowerCase() === ScimAuth.HOBA_ATTRIBUTE.toLowerCase();
    })[0];
    log.debug("Leaving ScimAuth.hobaKeysOf().");
    return name ? (attributes[name] || []).map(String) : [];
  }

  // Find the entry that registered this key id. A scan, because a key id is
  // chosen by the client and there is nothing to index it by — the directory is
  // schemaless and this service does not maintain indexes on invented
  // attributes. Bounded by ldap.maxEntries like every other sweep here.
  private entryForHobaKid(kid) {
    const { log, directory } = this.deps;
    log.debug("Entering ScimAuth.entryForHobaKid(). kid=" + kid);
    const wanted = String(kid) + ' ';
    let found = null;
    directory.allPersons().forEach((entry) => {
      if (found) {
        return;
      }
      const hit = this.hobaKeysOf(entry).filter((value) => {
        return value.indexOf(wanted) === 0;
      })[0];
      if (hit) {
        found = { entry: entry, der: hit.slice(wanted.length) };
      }
    });
    log.debug("Leaving ScimAuth.entryForHobaKid(). " +
              (found ? 'Found ' + found.entry.dn : 'No ' +
        'such key.'));
    return found;
  }

  private attemptHoba(req, ctx?) {
    const { log, crypto, errorCodes, hobaChallenges, hobaSeen } = this.deps;
    log.debug("Entering ScimAuth.attemptHoba().");
    if (this.authorizationScheme(req) !== 'hoba') {
      log.debug("Leaving ScimAuth.attemptHoba(). Not a HOBA credential.");
      return null;
    }
    const params = this.authParams(req.headers['authorization']);
    const parts = String(params.result || '').split('.');
    if (parts.length !== 4) {
      log.debug("Leaving ScimAuth.attemptHoba(). The result is not four " +
                "fields.");
      return this.coded('STS-SCIM-0048', this.unauthenticated(req,
        'A HOBA credential is result="kid.challenge.nonce.sig", four ' +
        'base64url fields separated by full stops (RFC 7486 section 6). What ' +
        'arrived ' +
        'has ' + parts.length + '.'));
    }
    const kid = parts[0];
    const challenge = parts[1];
    const nonce = parts[2];
    let signature = null;
    try {
      signature = Buffer.from(parts[3], 'base64url');
    } catch (e) {
      // Not base64url. Named as such rather than reported as a bad signature,
      // which would send somebody looking at their key.
      log.debug("Caught in ScimAuth.attemptHoba(): " +
                ((e && e.message) || e));
      log.debug("Leaving ScimAuth.attemptHoba(). The signature is not " +
                "base64url.");
      return this.coded('STS-SCIM-0049',
        this.unauthenticated(req,
                        'The signature field is not base64url: ' + e.message));
    }

    const issuedAt = hobaChallenges.get(challenge);
    if (issuedAt === undefined) {
      hobaChallengesCount.miss();
    } else {
      hobaChallengesCount.hit();
    }
    if (issuedAt === undefined) {
      log.debug("Leaving ScimAuth.attemptHoba(). The challenge is not one " +
                "this server " +
                "issued.");
      return this.coded('STS-SCIM-0050', this.unauthenticated(req,
        'This challenge is not one this server issued, or it has been ' +
        'forgotten. A fresh one is in the WWW-Authenticate header on this ' +
        'response; RFC 7486 section 5 lets a client reuse a challenge until ' +
        'its max-age runs out, which here ' +
        'is ' + this.hobaMaxAgeSeconds() + ' ' +
            'seconds.'));
    }
    if (Date.now() - issuedAt > this.hobaMaxAgeSeconds() * 1000) {
      hobaChallenges.delete(challenge);
      log.debug("Leaving ScimAuth.attemptHoba(). The challenge has expired.");
      return this.coded('STS-SCIM-0051', this.unauthenticated(req,
        'This challenge is older than its max-age ' +
        'of ' + this.hobaMaxAgeSeconds() +
        ' seconds (scim.hobaMaxAgeSeconds). A fresh one is on this response.'));
    }

    // The replay check, and it is on the CLIENT's nonce rather than on the
    // challenge: the specification means a challenge to be reused until it
    // expires, so refusing a repeated challenge would refuse conforming
    // clients. A repeated (kid, challenge, nonce) is a copied credential, which
    // is a different thing and is what a nonce is for.
    const triple = kid + '.' + challenge + '.' + nonce;
    const seenBefore = hobaSeen.has(triple);
    if (seenBefore) {
      hobaSeenCount.hit();
    } else {
      hobaSeenCount.miss();
    }
    if (seenBefore) {
      log.debug("Leaving ScimAuth.attemptHoba(). That signature has been " +
                "seen before.");
      return this.coded('STS-SCIM-0052', this.unauthenticated(req,
        'This exact credential has been presented before (same key id, ' +
        'challenge and nonce). The challenge may be reused until its max-age ' +
        'runs out, but the nonce is what makes each signature single-use — ' +
        'generate a fresh one per request.'));
    }

    const registered = this.entryForHobaKid(kid);
    if (!registered) {
      log.debug("Leaving ScimAuth.attemptHoba(). No key is registered under " +
                "that kid.");
      return this.coded('STS-SCIM-0053', this.unauthenticated(req,
        'No public key is registered here under the key id "' + kid + '". ' +
        'Register one with a form-encoded POST to /.well-known/hoba/register ' +
        'carrying pub=<PEM public key> and username=<who it is for> (RFC ' +
        '7486 section 7). Anybody may register any key for any name, exactly ' +
        'as any name authenticates everywhere else in this service.'));
    }

    let key = null;
    try {
      key = crypto.createPublicKey({
        key: Buffer.from(registered.der, 'base64'), format: 'der', type: 'spki'
      });
    } catch (e) {
      // The stored key cannot be read. That is this service's fault rather than
      // the caller's, and saying so is what stops somebody debugging their
      // client over a broken registration.
      log.debug("Caught in ScimAuth.attemptHoba(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SCIM-0054') +
                'scim: the HOBA key stored on ' + registered.entry.dn + ' ' +
                    'under kid ' + kid +
                ' could not be read back: ' + e.message);
      log.debug("Leaving ScimAuth.attemptHoba(). The stored key is " +
                "unreadable.");
      return this.coded('STS-SCIM-0054', this.unauthenticated(req,
        'The key registered under that id cannot be read back by this server ' +
        '(' +
        e.message +
        '). Register it again.'));
    }

    const tbs = this.hobaTbs([nonce, ScimAuth.HOBA_ALG_RSA_SHA256,
                              this.hobaOrigin(req), this.realm(),
                              kid, challenge]);
    let verified = false;
    try {
      verified = crypto.verify('sha256', Buffer.from(tbs, 'utf8'), key,
                               signature);
    } catch (e) {
      // A malformed signature makes verify() throw rather than return false.
      // Treated as a refusal, because from the caller's side the two are one
      // answer: this did not verify.
      log.debug("Caught in ScimAuth.attemptHoba(): " +
                ((e && e.message) || e));
      log.debug("Leaving ScimAuth.attemptHoba(). The signature could not be " +
                "checked: " +
                e.message);
      verified = false;
    }
    if (!verified) {
      log.debug("Leaving ScimAuth.attemptHoba(). The signature does not " +
                "verify.");
      return this.coded('STS-SCIM-0055', this.unauthenticated(req,
        'This HOBA signature does not verify against the key registered ' +
        'under "' + kid + '". ' +
        'The to-be-signed blob is RFC 7486 section 5\'s: each field prefixed ' +
        'with its length in octets and a colon, concatenated with nothing ' +
        'between them, in the order nonce, algorithm, origin, realm, kid, ' +
        'challenge. This server computed it over origin "' +
        this.hobaOrigin(req) + '" and realm "' + this.realm() +
        '" — note that the ' +
        'origin carries an explicit port even when it is the default, ' +
        'because RFC 7486 gives it none.'));
    }

    if (hobaSeen.size >= this.maxHobaSeen()) {
      // Expired challenges first: their triples can never be presented again.
      hobaSeen.forEach((seenChallenge, seenTriple) => {
        if (!hobaChallenges.has(seenChallenge)) {
          hobaSeen.delete(seenTriple);
        }
      });
    }
    while (hobaSeen.size >= this.maxHobaSeen()) {
      const oldest = hobaSeen.keys().next().value;
      // The challenge dies with the triple — see the declaration above.
      hobaChallenges.delete(hobaSeen.get(oldest));
      hobaSeen.delete(oldest);
    }
    hobaSeen.set(triple, challenge);

    const username = this.usernameOfEntry(registered.entry);
    log.debug("Leaving ScimAuth.attemptHoba(). " + username + " is accepted.");
    return this.withSpend({
      ok: true, scheme: 'hoba', principal: username, isClient: false,
      scopes: '',
      note: 'HOBA, RSA-SHA256 over the RFC 7486 blob (kid ' + kid + ')'
    }, {
      scope: 'scim.hoba-signature',
      value: triple,
      ttlMs: Math.max(1000, this.hobaMaxAgeSeconds() * 1000 -
                            (Date.now() - issuedAt)),
      code: 'STS-SCIM-0077',
      detail: 'This exact credential has been presented before (same key id, ' +
              'challenge and nonce), at another node of this service. The ' +
              'nonce is what makes each signature single-use — generate a ' +
              'fresh one per request.'
    });
  }

  // ---------------------------------------------------------------------------
  // THE SESSION COOKIE.
  //
  // RFC 7644 section 2's "Cookies": a client may assert an HTTP cookie carrying
  // an authentication state the service provider understands. This service has
  // exactly one such state — the browser sign-on session /authn/login creates
  // and WS-Federation shares — so this is that session, read through the same
  // `sessionOf()` every other reader uses. It is what makes a fetch() from a
  // page on this service work with no second credential.
  //
  // It is tried only when there is no Authorization header, which is not an
  // optimisation: a request that carries a credential is asking to be judged on
  // that credential, and quietly falling back to a cookie when it fails would
  // mean a client testing its bearer token error path getting a 200.
  // ---------------------------------------------------------------------------
  private attemptCookie(req, ctx?) {
    const { log, authn } = this.deps;
    log.debug("Entering ScimAuth.attemptCookie().");
    if (this.authorizationScheme(req)) {
      log.debug("Leaving ScimAuth.attemptCookie(). This request carries an " +
                "Authorization header.");
      return null;
    }
    const session = authn.sessionOf(req);
    if (!session) {
      log.debug("Leaving ScimAuth.attemptCookie(). There is no session.");
      return null;
    }
    const username =
      String((session.user && session.user.username) || '').trim();
    if (!username) {
      log.debug("Leaving ScimAuth.attemptCookie(). The session names nobody.");
      return null;
    }
    log.debug("Leaving ScimAuth.attemptCookie(). The session belongs " +
              "to " + username +
              ".");
    return {
      ok: true, scheme: 'cookie', principal: username, isClient: false,
      scopes: '',
      sessionId: String(session.id || ''),
      note: 'the browser sign-on session (' + (session.acr || 'no acr') + ')'
    };
  }

  // ---------------------------------------------------------------------------
  // THE TLS CLIENT CERTIFICATE.
  //
  // The first scheme RFC 7644 section 2 names. Available only where this
  // request arrived over TLS and the certificate VERIFIED — which means
  // `global.https` is on, so the main port asks every connection for one, and
  // the chain ends at an anchor somebody POSTed to /tls/trust or, for a
  // certificate this service issued, at the service Root
  // (`tls.trustIssuedClientCertificates`; see tls/CLAUDE.md).
  //
  // **VERIFIED IS WHERE THE CHECKING STARTS, and no directory entry has to
  // exist.** Since 2026-09-12 revocation is consulted as well, and since
  // 2026-09-13 a chain to the service Root is taken only where
  // `common/tls_client_certificates.js` says the leaf is an identity — both
  // below. At these endpoints a verified certificate authenticates a caller who
  // may then write to the directory. It was the first place in this service
  // where a certificate was a credential rather than an observation;
  // `GET /tls/sign-in`, the XACML gates and RFC 8705 client authentication have
  // joined it since, and it is still worth knowing before turning
  // `scim.authClientCert` on in a deployment that had assumed otherwise.
  //
  // The identity is the subject in RFC 4514 form — the same string
  // tls_server.js records and the directory files a certificate under, through
  // the same function, because two spellings of one DN is two people.
  // ---------------------------------------------------------------------------
  private attemptClientCertificate(req, ctx?) {
    const { log, tlsServer, errorCodes, audit,
            loadTlsClientCertificates } = this.deps;
    log.debug("Entering ScimAuth.attemptClientCertificate().");
    if (this.authorizationScheme(req)) {
      log.debug("Leaving ScimAuth.attemptClientCertificate(). This request " +
                "carries an " +
                "Authorization header.");
      return null;
    }
    const socket = req.socket || req.connection;
    if (!socket || typeof socket.getPeerCertificate !== 'function') {
      log.debug("Leaving ScimAuth.attemptClientCertificate(). This is not a " +
                "TLS " +
                "connection.");
      return null;
    }
    if (socket.authorized !== true) {
      // A certificate that did not verify is not a refusal here: the request
      // may be perfectly good under another scheme, and the main port asks for
      // a certificate without requiring one. It is simply not this credential.
      log.debug("Leaving ScimAuth.attemptClientCertificate(). No certificate " +
                "verified " +
                "on this connection.");
      return null;
    }
    // REVOCATION, CONSULTED (2026-09-12). `common/app.js` computed the verdict
    // before any route; a certificate the policy refuses is NOT THIS
    // CREDENTIAL, for exactly the reason an unverified one above is not — the
    // request may still authenticate under another scheme, and if nothing does,
    // the gate's own refusal answers it. The refusal of the CERTIFICATE is
    // recorded here so an operator finds it beside its code rather than
    // inferring it from a 401.
    const revocation = req.certificateRevocation || null;
    if (revocation && revocation.refused) {
      audit.failure(errorCodes.codeOf(revocation) || 'STS-PKI-0118', {
        protocol: 'SCIM', channel: 'http', target: req.originalUrl || req.url,
        summary: 'a verified client certificate was not accepted as a SCIM ' +
                 'credential: ' + revocation.why,
        outcome: 'refused'
      });
      log.debug("Leaving ScimAuth.attemptClientCertificate(). Refused on " +
                "revocation.");
      return null;
    }
    // NOT EVERY CHAIN TO THIS SERVICE'S OWN ROOT IS A CREDENTIAL (2026-09-13).
    // The listeners trust that Root for the TLS client certificates the user
    // portal issues, and every key pair this service ever issued chains to it;
    // `common/tls_client_certificates.js` says which of them is an identity,
    // and in which realm. One that is not is NOT THIS CREDENTIAL, for the
    // reason an unverified one above is not — the request may still
    // authenticate under another scheme. Required lazily, like
    // `mtls.peerVerified()` does.
    let gate = null;
    try {
      gate = loadTlsClientCertificates().checkSocket(socket);
    } catch (e) {
      // No certificate authority in this process, so nothing here was issued by
      // one and there is nothing to refuse.
      log.debug("Caught in ScimAuth.attemptClientCertificate(): " +
                ((e && e.message) || e));
      gate = null;
    }
    if (gate && !gate.ok) {
      log.info('scim: a verified client certificate was not taken as a SCIM ' +
               'credential: ' + gate.why + '.');
      log.debug("Leaving ScimAuth.attemptClientCertificate(). Not an " +
                "identity here.");
      return null;
    }
    const certificate = socket.getPeerCertificate();
    if (!certificate || !certificate.subject) {
      log.debug("Leaving ScimAuth.attemptClientCertificate(). There is no " +
                "peer " +
                "certificate.");
      return null;
    }
    const subject = tlsServer.dnRfc4514(certificate.subject);
    if (!subject) {
      log.debug("Leaving ScimAuth.attemptClientCertificate(). The subject is " +
                "empty.");
      return null;
    }
    log.debug("Leaving ScimAuth.attemptClientCertificate(). " + subject +
              " is accepted.");
    return {
      ok: true, scheme: 'clientcert', principal: subject, isClient: false,
      scopes: '',
      note:
        'a client certificate that verified against an anchor from /tls/trust' +
            (certificate.fingerprint256 ?
             ' (' + certificate.fingerprint256 + ')' : '')
    };
  }

  // ---------------------------------------------------------------------------
  // REGISTERING A HOBA PUBLIC KEY (RFC 7486 section 7).
  //
  // The specification puts this at /.well-known/hoba/register and makes it a
  // form-encoded POST carrying `pub`, and it answers with `Hobareg: regok`. Two
  // things about it are this service's own and are marked as such on GET /scim:
  //
  //   * WHO the key is for. In RFC 7486 the registration happens inside an
  //     already-authenticated context — the person is signed in and is adding a
  //     credential to the account they are signed in to. Here there is usually
  //     no such context, so `username` is a parameter, with the browser session
  //     used when there is one and no username given. In development mode
  //     anybody may register any key for any name, which is the same statement
  //     as "every LDAP bind succeeds". Outside it (2026-09-12) a key may be
  //     added only to the EXISTING account the caller's sign-on session is, and
  //     a kid already registered to another account is refused in every mode —
  //     see scim/CLAUDE.md, the 2026-09-12 audit.
  //   * The key is stored ON THE PERSON'S DIRECTORY ENTRY, so it is visible in
  //     an ldapsearch and on /admin/users like everything else about them. If
  //     the name is new the entry is created through `createUser()` — the same
  //     door the console's form, the management API and SCIM itself use —
  //     because there must not be a fifth way to put somebody in ou=users.
  //
  // `registerHobaKey()` returns a value rather than answering: `scim.ts` owns
  // the response, here as everywhere else in this module.
  // ---------------------------------------------------------------------------
  registerHobaKey(req) {
    const { log, crypto, stsCrypto, mode, parseBody, authn, directory,
            errorCodes } = this.deps;
    log.debug("Entering ScimAuth.registerHobaKey().");
    if (!this.schemeOn('scim.authHoba')) {
      log.debug("Leaving ScimAuth.registerHobaKey(). HOBA is turned off.");
      return this.coded('STS-SCIM-0063', { ok: false, status: 501,
        detail: 'HOBA is turned off on this service (scim.authHoba). The ' +
                'route ' +
                'is registered, which is why this is a 501 and not a 404.' });
    }
    const body = parseBody(req) || {};
    const pem = String(body.pub || '').trim();
    if (!pem) {
      log.debug("Leaving ScimAuth.registerHobaKey(). There was no key.");
      return this.coded('STS-SCIM-0064', { ok: false, status: 400,
        detail: 'A registration carries pub=<PEM public key> (RFC 7486 ' +
                'section 7), form-encoded. Nothing else in the body is ' +
                'required by ' +
                'this service.' });
    }
    let key = null;
    try {
      key = crypto.createPublicKey(pem);
    } catch (e) {
      // Not a key. The message from openssl is passed through, because it is
      // usually specific enough to fix the request in one go.
      log.debug("Caught in ScimAuth.registerHobaKey(): " +
                ((e && e.message) || e));
      log.debug("Leaving ScimAuth.registerHobaKey(). The key could not be " +
                "read.");
      return this.coded('STS-SCIM-0065', { ok: false, status: 400,
        detail: 'That public key could not be read: ' + e.message + '. It ' +
                'should be a PEM SubjectPublicKeyInfo block — the ' +
                '"-----BEGIN PUBLIC KEY-----" one, not a certificate and not ' +
                'a private ' +
                'key.' });
    }
    if (key.asymmetricKeyType !== 'rsa') {
      log.debug("Leaving ScimAuth.registerHobaKey(). It is " +
                "a " + key.asymmetricKeyType +
          " " +
          "key.");
      return this.coded('STS-SCIM-0066', { ok: false, status: 400,
        detail: 'That is a ' + key.asymmetricKeyType + ' key, and RFC 7486 ' +
                'registers two signature algorithms — 0 (RSA-SHA256) and 1 ' +
                '(RSA-SHA1) — so there is no algorithm number for anything ' +
                'else. This service accepts 0 only: SHA-1 is not something ' +
                'to be building a client around, and publishing that refusal ' +
                'is ' +
                'better than leaving it to be discovered.' });
    }

    const der = key.export({ format: 'der', type: 'spki' });
    // The key id. RFC 7486 lets the client choose one and gives `kidtype` for
    // saying what it is; a hash of the key itself is the default here for the
    // reason the signing key's `kid` is derived from its material in helpers.js
    // — two keys cannot then claim one id.
    const kid = String(body.kid || '').trim() ||
      stsCrypto.certificateThumbprint(der, { truncate: 22 });
    if (/[.\s]/.test(kid)) {
      log.debug("Leaving ScimAuth.registerHobaKey(). The kid carries a " +
                "separator.");
      return this.coded('STS-SCIM-0067', { ok: false, status: 400,
        detail: 'A key id cannot contain a full stop or whitespace: the ' +
                'credential is "kid.challenge.nonce.sig" and a kid carrying ' +
                'a ' +
                'full stop could not be read back out of it.' });
    }

    const session = authn.sessionOf(req);
    const username = String(body.username ||
      (session && session.user && session.user.username) || '').trim();
    // WHO IS ASKING, which the rest of this function decides nothing on in
    // development and everything on in product. A session somebody DECLINED to
    // authenticate in (`authenticated: false`) is nobody, for this purpose.
    const signedInAs = (session && session.user &&
                        session.authenticated !== false)
      ? String(session.user.username || '').trim() : '';
    if (!username) {
      log.debug("Leaving ScimAuth.registerHobaKey(). Nobody was named.");
      return this.coded('STS-SCIM-0068', { ok: false, status: 400,
        detail: 'This registration names nobody. RFC 7486 registers a key ' +
                'against an already-authenticated account; there is rarely ' +
                'one here, so send username=<who this key is for>, or ' +
                'register ' +
                'from a browser that has signed in at /authn/login.' });
    }

    let entry = directory.existingUserEntry(username);

    // ---------------------------------------------------------------------
    // **ADDING A KEY TO SOMEBODY'S ACCOUNT IS SIGNING IN AS THEM
    // (2026-09-12).** Registration was open to anybody for any name, and a
    // registered HOBA key authenticates at /scim/v2 as that person — so in any
    // deployment where a person's account is worth anything, this endpoint was
    // account takeover in one unauthenticated POST. RFC 7486 section 7
    // registers a key INSIDE an already-authenticated context; this service had
    // no such context and made the name a parameter. Two refusals, each through
    // the predicate that names its question:
    //
    //   * `mode.opensTestControls()` — outside development, a key may be added
    //     to an EXISTING account only by somebody whose sign-on session is that
    //     account. Development keeps the open registration, on purpose: it is
    //     how a client's HOBA code is exercised without a sign-in flow first.
    //   * `mode.autoCreates()` — outside development, a registration never
    //     CREATES an account. A name nobody provisioned is an unknown name,
    //     which is rule 2 of common/mode.js; the refusal says where accounts
    //     come from.
    // ---------------------------------------------------------------------
    if (entry && !mode.opensTestControls() &&
        signedInAs.toLowerCase() !== username.toLowerCase()) {
      log.debug("Leaving ScimAuth.registerHobaKey(). " + username +
                " exists and the caller is " +
                (signedInAs ? signedInAs : 'not signed in') + ".");
      return this.coded('STS-SCIM-0069', { ok: false, status: 403,
        detail: 'A HOBA key authenticates as the account it is registered ' +
                'to, so a key may be added to an existing account only by ' +
                'that account\'s owner. Sign in as ' +
                username + ' at /authn/login and register from that browser ' +
                'session, or have an administrator provision the credential. ' +
                'This is refused outside development mode (global.mode).' });
    }
    if (!entry && !mode.autoCreates()) {
      log.debug("Leaving ScimAuth.registerHobaKey(). No such account, and " +
                "none is " +
                "created.");
      return this.coded('STS-SCIM-0070', { ok: false, status: 404,
        detail: 'There is no account named ' + username + ', and in product ' +
                'mode a key registration does not create one (global.mode). ' +
                'Provision the person first — the console, /admin-api/users, ' +
                'SCIM or an LDAP add — and register the key while signed in ' +
                'as ' +
                'them.' });
    }

    // ---------------------------------------------------------------------
    // **ONE KEY ID, ONE ACCOUNT, IN EVERY MODE (2026-09-12).** The lookup that
    // authenticates a HOBA credential (`entryForHobaKid()`) takes the FIRST
    // entry holding a kid, so a kid registered on a second account made
    // authentication depend on directory order — and let one registration
    // shadow another person's key, or be shadowed by it. A kid is
    // caller-chosen, which is why this is a refusal rather than a thing that
    // cannot happen; the derived default already could not collide.
    // ---------------------------------------------------------------------
    const holder = this.entryForHobaKid(kid);
    if (holder && (!entry || holder.entry.dn !== entry.dn)) {
      log.debug("Leaving ScimAuth.registerHobaKey(). The kid is registered " +
                "to " +
                holder.entry.dn + ".");
      return this.coded('STS-SCIM-0071', { ok: false, status: 409,
        detail: 'The key id "' + kid + '" is already registered to another ' +
                'account, and a HOBA credential names its key by id alone — ' +
                'two accounts under one id would make which of them a ' +
                'signature authenticates depend on directory order. Choose ' +
                'another kid, or omit it and one is derived from the key.' });
    }

    if (!entry) {
      const made = directory.createUser(username, {
        origin: 'hoba', channel: 'http', protocol: 'SCIM',
        note: 'created by a HOBA key registration'
      });
      if (!made.ok) {
        log.debug("Leaving ScimAuth.registerHobaKey(). The entry could not " +
                  "be created.");
        return this.coded(errorCodes.codeOf(made) || 'STS-SCIM-0072',
          { ok: false, status: made.existing ? 409 : 400,
          detail: (made.errors || []).join(' ') });
      }
      entry = directory.readPerson(made.dn);
    }
    if (!entry) {
      log.debug("Leaving ScimAuth.registerHobaKey(). The entry vanished " +
                "between two " +
                "reads.");
      return this.coded('STS-SCIM-0073', { ok: false, status: 500,
        detail: 'The directory entry for ' + username +
                ' could not be read back.' });
    }

    const attributes = this.mergeableAttributes(entry);
    const existingName = Object.keys(attributes).filter((name) => {
      return name.toLowerCase() === ScimAuth.HOBA_ATTRIBUTE.toLowerCase();
    })[0] || ScimAuth.HOBA_ATTRIBUTE;
    const values = (attributes[existingName] || []).filter((value) => {
      // A second registration under one key id REPLACES rather than
      // accumulating. The alternative is an entry that grows a value per
      // registration and a lookup that finds whichever came first, which is the
      // trap applyVcAttributes()'s second rule is about.
      return String(value).indexOf(kid + ' ') !== 0;
    });
    values.push(kid + ' ' + der.toString('base64'));
    attributes[existingName] = values;

    const written = directory.writePerson(entry.dn, attributes);
    if (!written.ok) {
      log.debug("Leaving ScimAuth.registerHobaKey(). The write " +
                "failed: " + written.reason);
      return this.coded(errorCodes.codeOf(written) || 'STS-SCIM-0074',
        { ok: false, status: written.reason === 'full' ? 507 : 400,
        detail: 'The key could not be written to ' + entry.dn + ' (' +
                written.reason + ').' });
    }

    log.info('scim: a HOBA public key was registered for ' + username + ' at ' +
             entry.dn +
             ' under kid ' + kid + '. ' + (mode.opensTestControls()
               ? 'Nothing was checked about who registered it — see GET /scim.'
               : 'It was registered by ' + (signedInAs || username) + ', ' +
                   'signed in.'));
    log.debug("Leaving ScimAuth.registerHobaKey(). kid=" + kid);
    return {
      ok: true, status: 201,
      // RFC 7486 section 7's own signal that the registration completed. The
      // body is this service's: the specification defines none, and a client
      // that has just registered a key wants to be told the id it will have to
      // send.
      headers: { 'Hobareg': 'regok' },
      body: {
        kid: kid, username: username, dn: entry.dn,
        algorithm: ScimAuth.HOBA_ALG_RSA_SHA256,
        attribute: ScimAuth.HOBA_ATTRIBUTE,
        note: 'Registered. ' + (mode.opensTestControls()
                ? 'Nothing about this registration was authenticated, and ' +
                  'the key is '
                : 'The registration was made from ' + username + '\'s own ' +
                    'session, and the key is ') +
              'on the directory entry — an ldapsearch and /admin/users show ' +
              'it. Authenticate with Authorization: HOBA ' +
              'result="kid.challenge.nonce.sig".'
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE DECISION.
  //
  // `need` is 'read', 'write' or 'none' — the last being the discovery
  // endpoints, which are open unless `scim.authDiscovery` says otherwise. That
  // default is the bootstrapping argument /tls/trust already makes: the
  // ServiceProviderConfig is where a client READS which schemes exist, so
  // requiring a credential to fetch it means a client must already know the
  // answer to the question it is asking. A deployment that wants everything
  // shut can have that, and it is one setting away.
  //
  // The order of what follows is load-bearing:
  //
  //   1. A CREDENTIAL THAT WAS PRESENTED AND FAILED IS ALWAYS A REFUSAL, even
  //      when authentication is not required. A client testing its
  //      expired-token path must not get a 200 because the endpoint would also
  //      have accepted nobody.
  //   2. A credential that was presented and worked is used, even when
  //      authentication is not required — so the audit log and /Me have
  //      somebody to name.
  //   3. Only then does "is authentication required" decide what happens to a
  //      request carrying nothing.
  // ---------------------------------------------------------------------------
  authenticate(req, need?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.authenticate(). need=" + need);
    const wanted = String(need || 'none');
    const first = this.presentedDecision(req, wanted);
    if (first.final) {
      log.debug("Leaving ScimAuth.authenticate(). Decided on what was " +
                "presented.");
      return first.final;
    }
    log.debug("Leaving ScimAuth.authenticate().");
    return this.settleDecision(req, wanted, first.decision);
  }

  // ---------------------------------------------------------------------------
  // authenticateSpent(req, need) — `authenticate()`, with the credential SPENT
  // ACROSS THE CLUSTER before it is accepted (2026-09-14, #46 section 5).
  //
  // A Digest nonce count and a HOBA (kid, challenge, nonce) are single-use, and
  // the checks in `attemptDigest()` and `attemptHoba()` are this process's own
  // memory — exact on one process, and on several a replay presented at two
  // nodes at once is accepted by both. So a decision that carries a spend (the
  // `SPEND` symbol, `withSpend()`) is claimed through `cluster_claims.js` here,
  // BEFORE the session and the policy run, so a replay mints no session: `used`
  // is the scheme's own replay refusal, `store` is a 500 (see
  // `spendPresented()`) — a credential this service cannot prove unspent is not
  // one it accepts. With no shared store the claim is this process's memory, as
  // atomic as the Set it stands behind.
  //
  // `scim.ts` calls this; `authenticate()` stays synchronous for the callers
  // that read a decision in one tick, and does everything else identically.
  // ---------------------------------------------------------------------------
  authenticateSpent(req, need?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.authenticateSpent(). need=" + need);
    const wanted = String(need || 'none');
    log.debug("Leaving ScimAuth.authenticateSpent(). Verifying a Basic " +
              "password off the thread first, if one was presented.");
    return this.verifyBasicOffThread(req).then(() => {
      const first = this.presentedDecision(req, wanted);
      if (first.final) {
        return first.final;
      }
      return this.spendPresented(req, first.decision).then((refused) => {
        return refused || this.settleDecision(req, wanted, first.decision);
      });
    });
  }

  // ---------------------------------------------------------------------------
  // A BASIC PASSWORD, VERIFIED IN THE WORKER POOL (2026-09-21).
  //
  // `attemptBasic()` is synchronous, so in product mode it hashed the password
  // with scrypt ON THE REQUEST THREAD — about 70ms at the default cost, in
  // which this worker answered nothing else. The asynchronous path
  // (`authenticateSpent()`, which `scim.ts` takes) now asks
  // `credentials.verifyAsync()` first, which is the same check with the hash
  // done in the worker pool, and leaves the verdict on the request for
  // `attemptBasic()` to use. It keeps the username and a SHA-256 of the
  // password beside the verdict — never the password — so a verdict is only
  // used for the credential it was reached for. Only when the Basic scheme is
  // enabled: a disabled scheme must cost nothing and record nothing, exactly
  // as before. The synchronous `authenticate()` is unchanged.
  // ---------------------------------------------------------------------------
  static readonly BASIC_VERDICT: unique symbol = Symbol('scim.basicVerdict');

  private basicPairOf(req) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.basicPairOf().");
    const header = String(req.headers['authorization'] || '');
    const decoded = Buffer.from(header.replace(/^\s*Basic\s+/i, '').trim(),
                                'base64').toString('utf8');
    const cut = decoded.indexOf(':');
    const username = cut < 0 ? '' : decoded.slice(0, cut).trim();
    log.debug("Leaving ScimAuth.basicPairOf().");
    return username ? { username: username,
                        password: decoded.slice(cut + 1) } : null;
  }

  private verifyBasicOffThread(req) {
    const { log, credentials } = this.deps;
    log.debug("Entering ScimAuth.verifyBasicOffThread().");
    if (this.authorizationScheme(req) !== 'basic' ||
        !this.enabledSchemes().some((row) => { return row.id === 'basic'; })) {
      log.debug("Leaving ScimAuth.verifyBasicOffThread(). Not Basic.");
      return Promise.resolve(null);
    }
    const pair = this.basicPairOf(req);
    if (!pair) {
      log.debug("Leaving ScimAuth.verifyBasicOffThread(). Malformed; " +
                "attemptBasic() says why.");
      return Promise.resolve(null);
    }
    log.debug("Leaving ScimAuth.verifyBasicOffThread(). Handed to the pool.");
    // `door: 'scim'` (#101), the synchronous path's, so the two agree.
    return credentials.verifyAsync(pair.username, pair.password,
                                   { via: 'SCIM HTTP Basic', door: 'scim' })
      .then((checked) => {
        Object.defineProperty(req, ScimAuth.BASIC_VERDICT, {
          value: { username: pair.username,
                   digest: crypto.createHash('sha256').update(pair.password)
                     .digest('hex'),
                   checked: checked },
          enumerable: false });
        return null;
      }, (error) => {
        // THE POOL FAILED, not the password: leave no verdict, and
        // `attemptBasic()` verifies on the thread exactly as it always did.
        log.debug("Caught in ScimAuth.verifyBasicOffThread(): " +
                  ((error && error.message) || error));
        return null;
      });
  }

  // The spend a decision carries. NON-ENUMERABLE, under a Symbol, for the
  // reason `errorCodes.mark()` uses one: `req.scimAuth` is the decision, the
  // monitor and the audit row read it, and nothing about it serialises
  // differently.
  static readonly SPEND: unique symbol = Symbol('scim.spend');

  private withSpend(decision, spend?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.withSpend().");
    if (spend) {
      Object.defineProperty(decision, ScimAuth.SPEND,
                            { value: spend, enumerable: false });
    }
    log.debug("Leaving ScimAuth.withSpend().");
    return decision;
  }

  // Resolves null when the credential was spent here (or spends nothing), or
  // the refusal to answer with.
  private spendPresented(req, decision?) {
    const { log, errorCodes, clusterClaims } = this.deps;
    log.debug("Entering ScimAuth.spendPresented().");
    const spend = decision && decision[ScimAuth.SPEND];
    if (!spend) {
      log.debug("Leaving ScimAuth.spendPresented(). Nothing to spend.");
      return Promise.resolve(null);
    }
    log.debug("Leaving ScimAuth.spendPresented(). Claiming.");
    return clusterClaims.claim({ scope: spend.scope, value: spend.value,
                                 ttlMs: spend.ttlMs }).then((res) => {
      if (res.ok) {
        return null;
      }
      if (res.reason === 'used') {
        log.info('scim: a ' + decision.scheme + ' credential was refused ' +
                 'as a replay another process had already accepted.');
        return this.coded(spend.code, this.unauthenticated(req, spend.detail));
      }
      log.error(errorCodes.tag('STS-SCIM-0078') + 'scim: a ' +
                decision.scheme + ' credential could not be proved unspent (' +
                res.why + '); it is refused.');
      // 500 and not 503: RFC 7644 section 3.12's list of statuses has no 503,
      // and scim.ts sends anything off it as 500 anyway (STS-SCIM-0075).
      return this.coded('STS-SCIM-0078', {
        ok: false, status: 500, scimType: null,
        detail: 'This ' + decision.scheme +
                ' credential could not be checked ' +
                'against the credentials already used, because the store ' +
                'that records them could not be asked. It is refused rather ' +
                'than accepted unchecked. Retry with a fresh one.'
      });
    });
  }

  // THE FIRST HALF: which scheme spoke, and whether the request is already
  // decided — a presented credential refused, or nothing presented. Answers
  // `{ final }` or `{ decision }`, the accepted credential.
  private presentedDecision(req, wanted?) {
    const { log, mode } = this.deps;
    log.debug("Entering ScimAuth.presentedDecision().");
    let decision = null;
    const rows = this.enabledSchemes();
    for (let i = 0; i < rows.length && !decision; i++) {
      if (!rows[i].attempt) {
        continue;
      }
      decision = rows[i].attempt(req, { need: wanted });
    }

    if (decision && !decision.ok) {
      log.debug("Leaving ScimAuth.presentedDecision(). A credential was " +
                "presented and " +
                "refused.");
      return { final: decision };
    }

    if (!decision) {
      const scheme = this.authorizationScheme(req);
      const mustAuthenticate = this.authRequired() &&
                               (wanted !== 'none' || this.authDiscovery());
      if (!mustAuthenticate) {
        log.debug("Leaving ScimAuth.presentedDecision(). Nothing was " +
                  "presented and " +
                  "nothing is required.");
        return { final: {
          ok: true, scheme: 'anonymous', principal: '', anonymous: true,
          scopes: '', isClient: false,
          note: this.authRequired()
            ? 'a discovery endpoint, which is open (scim.authDiscovery)'
            : 'authentication is turned off' } };
      }
      if (scheme === 'digest' && this.schemeOn('scim.authDigest') &&
          !this.digestAllowedByMode()) {
        log.debug("Leaving ScimAuth.presentedDecision(). Digest is not " +
                  "offered in " +
                  "product mode.");
        return { final: this.coded('STS-SCIM-0056', this.unauthenticated(req,
          'HTTP Digest is not offered in product mode. RFC 7616 requires the ' +
          'server to hold each password or its digest hash, and this service ' +
          'holds a person\'s password only as a salted scrypt hash, from ' +
          'which neither can be computed; the one Digest it could perform ' +
          'would share scim.digestPassword across every user. Use a Bearer ' +
          'token, HTTP Basic over TLS, HOBA or a client certificate — the ' +
          'WWW-Authenticate headers list them.')) };
      }
      if (scheme) {
        log.debug("Leaving ScimAuth.presentedDecision(). The scheme " + scheme +
                  " is not offered here.");
        return { final: this.coded('STS-SCIM-0057', this.unauthenticated(req,
          'This request carries an "' + scheme +
          '" credential and this service offers ' +
          this.enabledSchemes().map((row) => { return row.name; }).join(', ') +
          '. The WWW-Authenticate headers on this response say what to ' +
          'send.')) };
      }
      log.debug("Leaving ScimAuth.presentedDecision(). Nothing was presented.");
      return { final: this.coded('STS-SCIM-0058', this.unauthenticated(req,
        'These endpoints create, change and delete accounts, and they now ' +
        'require a credential. ' +
        (mode.verifiesCredentials()
          ? 'Any of the schemes in the WWW-Authenticate headers will do: an ' +
            'access token from this service\'s own token endpoint with the ' +
            '"' + this.scopeRead() + '" ' +
                'or "' +
            this.scopeWrite() + '" scope, a directory person\'s username and ' +
            'password over Basic, a HOBA key registered by its signed-in ' +
            'owner, or a verified client certificate. '
          : 'Any of the schemes in the WWW-Authenticate headers will do, and ' +
            'every one of them is permissive: an access token from this ' +
            'service\'s own token endpoint with the "' +
            this.scopeRead() + '" or "' + this.scopeWrite() +
            '" scope, any username ' +
            'with any password but one over Basic, any username over Digest ' +
            'with the shared password, or a HOBA key anybody may register. ') +
        'The ServiceProviderConfig at /scim/v2/ServiceProviderConfig ' +
        'lists them, and it is readable without a credential for that ' +
        'reason.')) };
    }
    log.debug("Leaving ScimAuth.presentedDecision(). Accepted.");
    return { decision: decision };
  }

  // THE SECOND HALF: the scope, the funnel, the session and the policy, for a
  // credential that was accepted.
  private settleDecision(req, wanted?, decision?) {
    const { log, hasScope, accessGate, errorCodes, scopePolicy } = this.deps;
    log.debug("Entering ScimAuth.settleDecision().");

    // Accepted. The access control policy, which is two lines and is published
    // in both of them: an OAuth credential may do what its scopes say, and
    // anything else may do both. RFC 7644 section 2's MUST is that a provider
    // be ABLE to map an authenticated client to such a policy — not that the
    // policy be elaborate.
    const row = this.schemeById(decision.scheme);
    if (row && row.scoped && wanted !== 'none') {
      const required = wanted === 'write' ? this.scopeWrite() :
        this.scopeRead();
      if (!hasScope(decision.scopes, required)) {
        log.debug("Leaving ScimAuth.settleDecision(). The token " +
                  "lacks " + required + ".");
        const challenge = (decision.scheme === 'dpop' ? 'DPoP' : 'Bearer') +
          ' realm="' + this.realm() + '", error="insufficient_scope", ' +
          'error_description="this operation needs ' +
          'the ' + required + ' scope", scope="' + required + '"';
        log.debug("Leaving ScimAuth.settleDecision().");
        return this.coded('STS-SCIM-0059', {
          ok: false, status: 403, scimType: null,
          detail: 'This operation needs the "' + required + '" scope and the ' +
                  'access token was issued ' +
                  'with ' +
                  (decision.scopes ? '"' + decision.scopes + '"' : 'no ' +
                  'scope at ' +
                  'all') + '. Ask for it at the authorization or token ' +
                  'endpoint, as a client whose oauthAllowedScope declares ' +
                  'it. Reads need ' +
                  '"' + this.scopeRead() + '" and writes need "' +
                  this.scopeWrite() +
                  '"; one does not imply the other, deliberately, so that a ' +
                  'client\'s handling of a read-only credential is something ' +
                  'you can actually produce here.',
          headers: { 'WWW-Authenticate': [challenge] }
        });
      }
      // AND THE CLIENT STILL DECLARES IT (#110, 2026-09-22). The token
      // endpoint issues a SCIM scope only to a client whose
      // `oauthAllowedScope` lists it; asked again here, on every call, so an
      // allowance removed from a client stops the tokens it already holds
      // rather than waiting for them to expire.
      if (!scopePolicy.declares(decision.clientId, required)) {
        log.debug("Leaving ScimAuth.settleDecision(). The client no longer " +
                  "declares " + required + ".");
        const withdrawn = (decision.scheme === 'dpop' ? 'DPoP' : 'Bearer') +
          ' realm="' + this.realm() + '", error="insufficient_scope", ' +
          'error_description="the client does not declare ' + required +
          '", scope="' + required + '"';
        return this.coded('STS-SCIM-0079', {
          ok: false, status: 403, scimType: null,
          detail: 'This access token carries "' + required + '", and the ' +
                  'client it was issued to, "' + (decision.clientId || '') +
                  '", does not declare that scope in its oauthAllowedScope. ' +
                  'A SCIM scope is honoured only while the client declares ' +
                  'it, so removing it from the application cuts off tokens ' +
                  'already issued.',
          headers: { 'WWW-Authenticate': [withdrawn] }
        });
      }
    }

    // The authentication funnel, for the schemes that present a credential per
    // request. See the header for why a bearer token, a session cookie and a
    // client certificate are NOT recorded here — each was already recorded
    // where it was accepted, and counting it again would report one act as
    // many.
    if (row && row.recorded && decision.principal) {
      this.recordAuthentication(decision, row);
    }

    // -------------------------------------------------------------------------
    // THE SESSION, AND THEN THE POLICY (2026-09-06).
    //
    // Both are here rather than at the eleven route handlers for this
    // function's whole reason to exist: it is the ONE place a SCIM credential
    // is accepted, so a surface added tomorrow gets both without its author
    // having to know they exist. Eleven call sites would be ten that do and one
    // that does not.
    //
    // **THE SESSION IS `authn.startSession()` AND NOT A REGISTER OF THIS
    // FILE'S.** That function owns every session this service holds — the
    // console draws them, `logout.js` ends them, CAEP observes them — and a
    // second store for API callers would be a second answer to "is somebody
    // signed in", which is the thing rule 3m exists to prevent. What makes it
    // work for a per-request credential is `detail.key`: a call whose key
    // matches a live session TOUCHES it rather than minting one, so a
    // provisioning client doing a thousand PATCHes leaves one row and not a
    // thousand.
    //
    // `cookie: false` because a SCIM client is not a browser — see
    // startSession().
    const session = this.sessionFor(decision);

    // THE POLICY. The subject is the session's person, never anything off the
    // request — a PDP deciding faithfully about a subject the caller nominated
    // is broken access control with extra steps.
    //
    // **IT RUNS AFTER THE SCOPE CHECK AND NOT INSTEAD OF IT.** RFC 7644 section
    // 2's mapping from an authenticated client to a policy is this file's own
    // and stays exactly as it was; the gate is the layer ABOVE it, and on an
    // unedited service it permits — the built-in policy asks for a role only
    // where somebody has required one. So this changes nothing until a
    // deployment writes a rule, which is the contract every mode here follows.
    const answer = accessGate.check({
      resource: accessGate.RESOURCE.SCIM,
      action: wanted === 'write' ? accessGate.ACTION.WRITE
                                 : accessGate.ACTION.READ,
      subject: { name: (session && session.user && session.user.username) ||
                       decision.principal || '',
                 authenticated: !decision.anonymous,
                 sessionId: session ? session.id : null },
      context: { method: req.method, path: req.originalUrl || req.url,
                 scheme: decision.scheme }
    });
    if (!answer.allowed) {
      log.info('scim: the access policy refused ' + req.method + ' ' +
               (req.originalUrl || req.url) + ' for ' +
               (decision.principal || '(nobody)') + '. ' + answer.why);
      log.debug("Leaving ScimAuth.settleDecision().");
      return this.coded(errorCodes.codeOf(answer) || 'STS-SCIM-0060', {
        ok: false, status: 403, scimType: null,
        detail: 'The access policy refused this request. ' + answer.why +
                ' This is a POLICY decision rather than a missing ' +
                'credential: the credential presented was accepted. The ' +
                'document is on /admin/xacml and xacml.enforceAccess turns ' +
                'the whole layer off.'
      });
    }

    log.debug("Leaving ScimAuth.settleDecision(). " + decision.scheme +
              " for " +
              (decision.principal || '(nobody)') + ".");
    return decision;
  }

  // The session for an accepted SCIM credential. Separated from the funnel
  // above only because it is eight lines of hashing and a call, and the funnel
  // is already the longest function in this file.
  //
  // **AN ANONYMOUS DECISION GETS NO SESSION**, which is not a special case: it
  // means authentication is off — unreachable since 2026-09-06 — or this is the
  // open discovery endpoint, so nobody authenticated and there is nothing to
  // hold a session for. It returns null and the policy is asked about an
  // unauthenticated subject — which the built-in policy refuses only if
  // somebody has turned `requireAuthenticated` into a requirement for this
  // surface.
  private sessionFor(decision) {
    const { log, crypto, authn, errorCodes } = this.deps;
    log.debug("Entering ScimAuth.sessionFor().");
    if (!decision || decision.anonymous || !decision.principal) {
      log.debug("Leaving ScimAuth.sessionFor(). Nobody authenticated.");
      return null;
    }
    try {
      // **THE KEY IS THE SCHEME AND THE PRINCIPAL, NOT THE CREDENTIAL.** Two
      // things point the same way. `authenticate()` never keeps what was
      // presented — a bearer token reaching a register would be a second place
      // to steal one from, which is why `logout.js` refuses to put an
      // authorization code in a row id — so there is nothing here to hash. And
      // the right unit is the CLIENT rather than the credential: a client that
      // refreshes its token mid-run is the same client on the same surface, and
      // keying on the token would give it a second row and leave the first
      // sitting there until it expired.
      //
      // It is still hashed, because the principal can be a DN or an email and a
      // session id is printed on `/admin/sessions` and in audit rows.
      const key = crypto.createHash('sha256')
        .update('scim ' + String(decision.scheme || '') + ' ' +
                String(decision.principal || ''))
        .digest('hex').slice(0, 24);
      const session = authn.startSession(
        { set: () => {}, req: null }, decision.principal,
        ['pwd'], '1', 'SCIM',
        { key: key, cookie: false,
          summary: decision.principal + ' authenticated at /scim/v2 over ' +
                   decision.scheme + '; session created',
          note: 'A SCIM credential was presented and accepted. This session ' +
                'is a RECORD that it was, not a thing that can be presented ' +
                'in ' +
                'its place: every SCIM request authenticates again.' });
      log.debug("Leaving ScimAuth.sessionFor(). " +
                (session ? session.id : 'none') + ".");
      return session;
    } catch (error) {
      // Nothing about recording a session may be able to fail an authentication
      // — the same guarantee recordAuthentication() gives one line up.
      log.debug("Caught in ScimAuth.sessionFor(): " +
                ((error && error.message) || error));
      log.error(errorCodes.tag('STS-SCIM-0061') +
                'scim: a session could not be recorded and the request is ' +
                'unaffected: ' + error.message);
      log.debug("Leaving ScimAuth.sessionFor(). It threw.");
      return null;
    }
  }

  // One accepted credential, at the single funnel every other family here
  // passes. Wrapped, because nothing about recording an authentication may be
  // able to fail one — the same guarantee the directory observer inside that
  // function already gives.
  private recordAuthentication(decision, row?) {
    const { log, stats, errorCodes } = this.deps;
    log.debug("Entering ScimAuth.recordAuthentication() for SCIM.");
    try {
      stats.recordAuthentication({
        presented: decision.principal,
        protocol: 'SCIM',
        method: row.name,
        // RFC 8176. Stated only where something really was checked: Digest
        // hashes the password so `pwd` is honest, HOBA verifies a signature so
        // `sig` is, and Basic checks nothing in development mode, so it states
        // nothing (in either mode) — where nothing was stated, nothing is
        // written onto the entry, which is applyAuthenticationFactors()'s rule.
        amr: row.id === 'digest' ? ['pwd'] : (row.id === 'hoba' ? ['sig'] : []),
        note: decision.note || ''
      });
    } catch (e) {
      log.debug("Caught in ScimAuth.recordAuthentication(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-SCIM-0062') +
               'scim: an accepted credential could not be recorded: ' +
               e.message);
    }
    log.debug("Leaving ScimAuth.recordAuthentication() for SCIM.");
  }

  // ---------------------------------------------------------------------------
  // THE ServiceProviderConfig'S `authenticationSchemes`, IN TWO HALVES — AND
  // THE REASON IT IS TWO IS THAT THE TWO SPECIFICATIONS DISAGREE WITH EACH
  // OTHER.
  //
  // RFC 7644 section 2 names six ways to authenticate. RFC 7643 section 5 gives
  // `authenticationSchemes.type` five CANONICAL VALUES — oauth, oauth2,
  // oauthbearertoken, httpbasic, httpdigest — and three of section 2's six have
  // no value in that list at all: there is nothing to call a client
  // certificate, a cookie or HOBA. That is not this service's problem to solve
  // and it will not pretend it does not exist:
  //
  //   * The four rows with a canonical value go through SCIMMY.Config, which
  //     ENFORCES that list (its ServiceProviderConfig definition carries the
  //     five as canonicalValues and its coercion throws on anything else). So
  //     the library validates them, which is what it is here for.
  //   * The three without one are appended to the SERIALISED document by
  //     `scim.ts`, carrying an honest type of their own. RFC 7643 section 7
  //     calls canonical values "suggested" and a service provider may publish
  //     others; a client matching on the canonical five finds the ones it
  //     knows, and one reading the whole array finds a name, a description and
  //     a specUri for the rest.
  //
  // Both halves are built from the SAME table by the two functions below, so
  // the document cannot advertise a scheme that is turned off nor omit one that
  // is on. Do not "simplify" this by dropping the three: a
  // ServiceProviderConfig that listed four of the seven ways in would be the
  // most misleading document this service publishes, and it is the first thing
  // a SCIM client reads.
  //
  // `primary` is set on the bearer row and NOT passed through SCIMMY.Config:
  // scimmy's definition of the sub-attributes does not include it (RFC 7643's
  // example in section 8.5 carries it, its schema definition does not) and an
  // unknown sub-attribute throws. It is added during serialisation with the
  // rest.
  // ---------------------------------------------------------------------------
  private schemeDocument(row, base?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.schemeDocument().");
    const out: Record<string, any> = {
      type: row.type,
      name: row.name,
      description: row.description,
      specUri: row.specUri
    };
    // ONLY WHEN THERE IS A BASE URL, and this is not tidiness.
    // `documentationUri` is a `reference` attribute with referenceTypes
    // ["external"] in RFC 7643's schema, so scimmy's coercion requires an
    // absolute URL and THROWS on a path — and this function is called at
    // require time as well, when there is no request to build a URL from and
    // therefore no honest value to give it. A throw there takes the whole
    // service down over an optional member.
    if (base) {
      out.documentationUri = base + '/scim';
    }
    log.debug("Leaving ScimAuth.schemeDocument().");
    return out;
  }

  schemesForConfig(base?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.schemesForConfig().");
    const out = this.enabledSchemes().filter((row) => { return row.canonical; })
      .map((row) => { return this.schemeDocument(row, base); });
    log.debug("Leaving ScimAuth.schemesForConfig(). " + out.length +
              " canonical " +
        "scheme(s).");
    return out;
  }

  schemesBeyondTheCanonicalList(base?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.schemesBeyondTheCanonicalList().");
    const out = this.enabledSchemes()
      .filter((row) => { return !row.canonical; })
      .map((row) => { return this.schemeDocument(row, base); });
    log.debug("Leaving ScimAuth.schemesBeyondTheCanonicalList(). " +
              out.length + " " +
        "scheme(s).");
    return out;
  }

  // Which published scheme is `primary`, by id, so that serialisation can mark
  // it without a second opinion about which one it is.
  primarySchemeId() {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.primarySchemeId().");
    const row = this.enabledSchemes().filter((candidate) => {
      return candidate.primary;
    })[0];
    log.debug("Leaving ScimAuth.primarySchemeId().");
    return row ? row.id : '';
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS SURFACE IS, AS DATA.
  //
  // Read by GET /scim, by /admin/scim and by GET /admin-api/scim, all three
  // through scim.ts's description() — so the console page and the JSON cannot
  // disagree with the challenge a client actually gets, because all of it is
  // this one table.
  // ---------------------------------------------------------------------------
  describe(req?) {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.describe() for SCIM authentication.");
    const out = {
      required: this.authRequired(),
      discoveryOpen: !this.authDiscovery(),
      realm: this.realm(),
      scopes: { read: this.scopeRead(), write: this.scopeWrite() },
      hobaRegistration: '/.well-known/hoba/register',
      digestAlgorithms: this.digestAlgorithms().map((row) => {
        return row.token;
      }),
      schemes: this.SCHEMES.map((row) => {
        return {
          id: row.id,
          type: row.type,
          canonical: !!row.canonical,
          name: row.name,
          enabled: this.schemeAvailable(row),
          // Why an ON setting is not an offered scheme, where that is the case.
          refusedByMode: row.id === 'digest' && this.schemeOn(row.setting) &&
                         !this.digestAllowedByMode()
            ? 'HTTP Digest needs the server to hold each password or its RFC ' +
              '7616 hash, and product mode holds only a scrypt hash; the ' +
              'shared scim.digestPassword is not a credential a deployment ' +
              'can offer.'
            : '',
          setting: row.setting,
          primary: !!row.primary,
          scoped: !!row.scoped,
          recorded: !!row.recorded,
          challenged: !!row.challenge,
          spec: row.spec,
          specUri: row.specUri,
          description: row.description
        };
      }),
      policy: [
        'An OAuth credential — a Bearer or DPoP access token — may do what ' +
        'its scopes say: "' +
        this.scopeRead() + '" to read and "' + this.scopeWrite() +
        '" to write. Neither ' +
        'implies the other, so that a client\'s handling of a read-only ' +
        'credential is something this service can actually produce.',

        'EVERY OTHER SCHEME MAY DO BOTH. Basic, Digest, HOBA, a session ' +
        'cookie and a client certificate carry no scopes, so the policy for ' +
        'them is the whole surface. That is worth reading twice: a caller ' +
        'who cannot get a scope can use Basic instead, which is why each ' +
        'scheme has a switch of its own — a deployment exercising scope ' +
        'handling turns the other five off.',

        'RFC 7644 section 2 requires a provider to be ABLE to map an ' +
        'authenticated client to an access control policy. This is that ' +
        'policy. It is two lines because this service authenticates nobody ' +
        'in the sense that matters — it is a turnstile, not a lock.',

        'A SCOPE IS TIED TO A CLIENT (#110). The SCIM scopes are issued only ' +
        'to a client whose oauthAllowedScope declares them, in both modes, ' +
        'and a token is honoured only while its client still declares the ' +
        'scope it uses — so removing the declaration cuts off tokens ' +
        'already issued (STS-SCIM-0079).'
      ]
    };
    log.debug("Leaving ScimAuth.describe(). " + out.schemes.length +
              " scheme(s).");
    return out;
  }

  // The counters' vocabulary, so that /admin/scim can draw a row per scheme
  // including the zeroes — the same rule the operations table follows, and for
  // the same reason: "does this server do Digest" is answered by a row saying 0
  // and not by an absence.
  schemeIds() {
    const { log } = this.deps;
    log.debug("Entering ScimAuth.schemeIds().");
    log.debug("Leaving ScimAuth.schemeIds().");
    return this.SCHEMES.map((row) => { return row.id; }).concat(['anonymous']);
  }

}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ScimAuth>(
  'scim/scim_auth',
  () => new ScimAuth(ScimAuth.defaultDeps()),
  ScimAuth.wire,
  helpers.log);

// DECLARED AT REQUIRE TIME, for `cluster/cluster.js`'s reason: the Digest
// nonces and HOBA challenges are persisted stores, and a nonce count or a
// signature is spent through a claim in `authenticateSpent()`, which `scim.ts`
// calls.
capabilities.provide('scim.challenge-state');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  ScimAuth: ScimAuth,
  installInstance: (instance: ScimAuth): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // Built by the instance's constructor, so read from it when asked.
  get SCHEMES(): SchemeRow[] {
    helpers.log.debug("Entering SCHEMES().");
    helpers.log.debug("Leaving SCHEMES().");
    return slot.get().SCHEMES;
  },
  // The two algorithm tables, for `admin-ui/crypto_metadata.ts`.
  // DIGEST_ALGORITHMS is already filtered by what this node build can actually
  // compute, which is exactly what that page should report — a console that
  // listed SHA-512-256 on a build without it would be naming an algorithm no
  // challenge will ever offer.
  get DIGEST_ALGORITHMS(): DigestAlgorithm[] {
    helpers.log.debug("Entering DIGEST_ALGORITHMS().");
    helpers.log.debug("Leaving DIGEST_ALGORITHMS().");
    return slot.get().DIGEST_ALGORITHMS;
  },
  HOBA_ALG_RSA_SHA256: ScimAuth.HOBA_ALG_RSA_SHA256,
  REFUSED_PASSWORD: ScimAuth.REFUSED_PASSWORD,
  authRequired: slot.forward('authRequired'),
  permissive: slot.forward('permissive'),
  authDiscovery: slot.forward('authDiscovery'),
  realm: slot.forward('realm'),
  scopeRead: slot.forward('scopeRead'),
  scopeWrite: slot.forward('scopeWrite'),
  challenges: slot.forward('challenges'),
  authenticate: slot.forward('authenticate'),
  authenticateSpent: slot.forward('authenticateSpent'),
  registerHobaKey: slot.forward('registerHobaKey'),
  schemesForConfig: slot.forward('schemesForConfig'),
  schemesBeyondTheCanonicalList: slot.forward('schemesBeyondTheCanonicalList'),
  primarySchemeId: slot.forward('primarySchemeId'),
  describe: slot.forward('describe'),
  schemeIds: slot.forward('schemeIds')
};
