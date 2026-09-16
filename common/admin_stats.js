// @ts-check
'use strict';
//
// File: admin_stats.js
//
// ---------------------------------------------------------------------------
// What this service has done since it started, and the two things an operator
// of it can change: which tokens are invalid, and what custom claims every new
// token carries.
//
// It is a LIBRARY, not a protocol module — like dpop.js it registers no route,
// so its position in the require order does not matter and it cannot be the
// reason a route is missing. The console (`admin-ui/`, `admin-core/`) renders
// what is in here; this file holds the state and none of the HTML, which is
// the split that lets the counters be read by a test over JSON without going
// near a page.
//
// It requires only helpers.js and a handful of libraries that never require it
// back — realms, config, audit, the error-code table, the replication fan-in,
// the application registry, the federation release filter and roles — each
// argued where it is required below, and deliberately: it is called from
// app.js's call log, from helpers.js's signJwt(), from both
// assertion builders, from the KDC and from the credential issuer, which
// between them are most of the service. Anything it required, all of those
// would then require transitively, and the cycles rule 2 of the architecture
// exists to avoid would be one careless import away.
//
// Three things are worth knowing before reading further.
//
// **In development mode everything here is in memory and dies with the
// process.** That is the same choice the signing key makes there (regenerated
// on every start) and for the same reason: a statistics file that outlived the
// key that signed the tokens it describes would be actively misleading. Where
// the key persists — product mode on a postgres store — the stores declared
// `persist` below are written down with the rest of the minted state
// (persistence/CLAUDE.md).
//
// **The registries are bounded.** A long-running instance issuing tokens in a
// loop must not become a memory leak, so the token, assertion, ticket and
// credential registries have caps and drop their oldest entries. What was
// dropped is COUNTED and shown on the page: a silent truncation would turn "12
// tokens issued" into a number that quietly means something else.
//
// **Revocation lives here rather than in oauth2.js, where it was written.** The
// admin console revokes tokens and so does RFC 7009's /oauth2/revoke, and two
// sets of revoked jtis would each look correct alone and never see each other —
// the same failure the single session store exists to prevent. There is one
// set, and introspection, UserInfo, the refresh grant and this console all
// consult it.
// ---------------------------------------------------------------------------

const { log, setJwtRecorder, userFor, nameForSubject, subjectForName,
        LEGACY_SUBJECT_PREFIX } = require('./helpers');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and the error-code table and nothing else here, so it cannot join a
// cycle and it registers no route, so its position is not a position at all.
const realms = require('./realms');
// WHAT OTHER PROCESSES COUNTED, for the fan-in in snapshot(). A LIBRARY
// (rule 3): it registers no route and requires only `config` and `realms`, so
// requiring it here closes no cycle and moves nothing. With one process it
// answers an empty array and every number this file reports is unchanged.
const replication = require('../persistence/persistence_replication');
// The audit log. A one-way require and it must stay one: audit.js requires
// helpers.js, config.js, realms.js, the error-code table and the replication
// fan-in and nothing else in this repository, precisely so that this file —
// which most of the service already requires — can call it without dragging a
// graph behind it.
//
// It is called from ONE place in here, recordAuthentication() below, and that
// is the point: that function is already the single funnel every one of the
// sixteen protocol families passes through at the moment a credential is
// accepted, so the audit log gets its authentication events from one line
// rather than from sixteen call sites, the seventeenth of which would be the
// one nobody adds. It is also the only place in this service that has already
// normalised the identity, which is what lets an audit row and a /admin/users
// row name the same person.
const audit = require('./audit');
// The registry of failure codes, a LEAF. The wrapped calls below that swallow a
// throw log it with one; a refused claim-set change carries its code on the
// audit row and, NON-ENUMERABLY, on the result a caller serialises.
const errorCodes = require('./error_codes');
// THE FEDERATION RELEASE FILTER, and it is a plain require in the ordinary
// direction rather than a hook. Rule 3e's test both ways round: that module
// registers no route, and it requires only helpers.js, config.js, realms.js,
// audit.js, the error-code table and applications.js — none of which requires
// this file — so nothing about requiring it from here closes a cycle or moves
// a route, and a slot would cost a reader an indirection for nothing. It is the
// same argument applications.js is required under, a few lines below.
const federation = require('./../federation/federation');
// For one value: `oauth2.clockSkewS`, the allowance the OAuth endpoints apply
// when they read back a token this service signed. It is read HERE so that the
// state a console screen reports is the state the endpoints will act on — a
// page saying "valid" about a token /oauth2/introspect calls inactive (or the
// reverse) is worse than a page with no state column at all, because it is
// believed. config.js requires nothing from this repository, so this is a plain
// require in the ordinary direction and closes no cycle (rule 3b).
const config = require('./config');
// The application registry — what was on the OTHER side of an authentication.
// See the note where it is called, below, for why this is a plain require and
// not the fifth inverted hook on this module.
const applications = require('./applications');

// When this process started answering. Everything on the metrics page is
// "since" this instant, and the page prints it, because a rate with no window
// is a number with no meaning.
const STARTED_AT = Date.now();

// ---------------------------------------------------------------------------
// The caps.
//
// Chosen to be far above any interactive or test use of this service and far
// below anything that would trouble a node heap. Each registry counts what it
// dropped so the page can say "5,000 shown, 812 forgotten" instead of implying
// 5,000 is all there ever were.
// ---------------------------------------------------------------------------
const MAX_TOKENS = 5000;
const MAX_ARTIFACTS = 5000;
const MAX_CALL_PATHS = 500;
const MAX_USERS = 2000;

// How many authentication events one user keeps. The users page shows a
// person's history and a person signing in repeatedly is the normal case here —
// a test loop can sign the same name in a thousand times — so the events are
// capped per user rather than in total, and what was dropped is counted on the
// record so the page can say "the most recent 50 of 1,204" instead of implying
// there were 50.
const MAX_EVENTS_PER_USER = 50;

// ---------------------------------------------------------------------------
// Endpoint call statistics.
//
// Keyed by METHOD and the ROUTE PATTERN Express matched
// ("/oauth2/register/:client_id"), not by the URL that was requested —
// otherwise every registered client id would get a row of its own and the table
// would be unbounded and unreadable. A request that matched no route has no
// pattern, so its path is used as-is; that IS unbounded (anyone can request any
// path), which is what MAX_CALL_PATHS bounds.
// ---------------------------------------------------------------------------
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// "GET /path" -> the row below
const calls = realms.map({ persist: 'admin_stats.calls', merge: 'own' });

// ---------------------------------------------------------------------
// THE COUNTERS THAT ARE NOT IN THE MAPS, PER TRUST REALM.
//
// The tables above are realm-partitioned; these five numbers describe them, and
// a counter left process-wide would count every realm's calls beside a list
// holding one realm's rows. The metrics page shows both, and the two would
// disagree by however many realms are running — which reads as a bug in the
// page rather than as what it is.
//
// `realms.obj(factory)` is a plain object per realm, so `nums.callTotal++`
// works exactly as the bindings it replaced did.
//
// **`usersForgotten` IS IN HERE AS OF 2026-08-25, AND IT DELIBERATELY WAS NOT
// UNTIL THEN.** The argument for leaving it out was that the identity register
// below mirrors the embedded directory, and the directory was shared by every
// realm — so a per-realm counter would have described a per-realm list that did
// not exist. **The directory became a SUBTREE PER REALM on 2026-08-25**
// (`ldap/CLAUDE.md`), which retired the premise rather than the reasoning: the
// register follows the directory, so both it and the counter describing it are
// partitioned now. This is the shape to look for anywhere else something was
// left process-wide "because the directory is shared" — that sentence was true
// for one day.
// ---------------------------------------------------------------------
const nums = realms.obj(function () {
  return { callTotal: 0, callPathsDropped: 0, tokensForgotten: 0,
           tokensWithoutJti: 0, artifactsForgotten: 0, usersForgotten: 0,
           // How many artifacts this realm has EVER recorded, which is not
           // `artifacts.length` and must not be confused with it: the array is
           // capped and shifts from the front, so its length falls back. This
           // only ever rises, and it is what gives every artifact a key of its
           // own — see recordArtifact(). A Kerberos ticket carries no
           // identifier anybody can quote, so without this there would be
           // nothing to address the row by, and /admin/tokens/set could not
           // open one.
           artifactsRecorded: 0 };
}, { persist: 'admin_stats.nums', merge: 'own' });



const UNMATCHED_BUCKET = '(other unmatched paths)';

function callRow(method, path) {
  log.debug("Entering callRow().");
  const key = method + ' ' + path;
  let row = calls.get(key);
  if (row) {
    log.debug("Leaving callRow().");
    return row;
  }
  row = { method: method, path: path, count: 0, totalMs: 0, maxMs: 0,
          statuses: {}, lastAt: 0, lastStatus: 0, matched: true };
  calls.set(key, row);
  log.debug("Leaving callRow().");
  return row;
}

// Called from app.js's call log, once per answered request. `matched` says
// whether Express found a route: an unmatched path is a 404 and is interesting
// exactly once, which is why it is the one that gets collapsed when the table
// is full.
function recordCall(call) {
  log.debug("Entering recordCall(). " + call.method + " " + call.path + " -> " +
            call.status);
  let path = call.path;
  let matched = !!call.matched;
  if (!matched && calls.size >= MAX_CALL_PATHS) {
    // Collapse rather than grow without limit. Counted, and named on the page,
    // so the collapse is visible rather than a table that mysteriously stops
    // growing.
    nums.callPathsDropped++;
    path = UNMATCHED_BUCKET;
  }
  const row = callRow(call.method, path);
  row.matched = row.matched && matched;
  row.count++;
  row.totalMs += call.durationMs || 0;
  if ((call.durationMs || 0) > row.maxMs) row.maxMs = call.durationMs || 0;
  const bucket = String(Math.floor((call.status || 0) / 100)) + 'xx';
  row.statuses[bucket] = (row.statuses[bucket] || 0) + 1;
  row.lastAt = Date.now();
  row.lastStatus = call.status || 0;
  nums.callTotal++;
  // -------------------------------------------------------------------------
  // PUT THE ROW BACK, AND IT IS NOT A NO-OP (2026-09-09).
  //
  // `callRow()` calls `calls.set()` only when a path is FIRST SEEN. Every
  // increment above mutates the object it handed back, and a mutation is
  // invisible to the journalling view `realms.map()` returns for a store with a
  // persist handle — so nothing is marked dirty, no flush is scheduled, and the
  // row in `sts_changes` keeps the count it had when the path was created.
  //
  // With one process that was harmless: the map IS the answer, and the store
  // only had to survive a restart. With request workers it is not, because
  // `/admin/metrics` sums this process's rows with what the OTHERS wrote — and
  // what they wrote was one row each, at count 0. Every worker's traffic after
  // the first call on a path was invisible to every other worker, for ever.
  //
  // Measured: three probes of `/healthcheck` across three workers, and the
  // metrics page still reporting the count from before them 45 seconds later.
  // It looked like a convergence lag and no amount of waiting would have fixed
  // it — there was nothing on its way.
  //
  // **THE COST IS A SCHEDULED FLUSH PER REQUEST AND IT IS BOUNDED BY THE
  // SCHEDULER RATHER THAN BY THIS LINE.** `schedule()` starts a timer only when
  // none is pending and `flush()` runs one at a time, so a burst of requests
  // coalesces into one write of the handful of rows that actually moved. A
  // service already writing (a bulk load, a sign-in) pays nothing extra — the
  // flush was happening anyway and carries a few more rows.
  // -------------------------------------------------------------------------
  calls.set(call.method + ' ' + path, row);
  log.debug("Leaving recordCall(). " + nums.callTotal + " call(s) recorded " +
                                                        "in total.");
}

// ---------------------------------------------------------------------------
// The tokens.
//
// Every JWT this service signs through helpers.signJwt() lands here — access
// tokens, id_tokens, refresh tokens, the signed UserInfo response and the
// OID4VP Request Object — because that function is the single place they are
// minted. The credential formats sign directly with jsonwebtoken and are
// recorded separately (recordCredential below); WS-Trust's JWT does the same.
//
// The record deliberately keeps the CLAIMS and not the token: the console lists
// what was issued to whom and until when, and a page holding thousands of
// signed bearer credentials in a form a browser will render is a page that
// leaks them. The jti is what the console acts on, and the jti is enough.
// ---------------------------------------------------------------------------
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// jti (or a synthetic key) -> the record below
const tokens = realms.map({ persist: 'admin_stats.tokens' });



// What `typ` means, in the vocabulary the console and RFC 7009 use. Every token
// this server issues is a JWT signed with the realm's own keys, so `typ` is the
// only thing that tells them apart — the same fact UserInfo relies on.
const KIND_BY_TYP = {
  'Bearer': 'access_token',
  'ID': 'id_token',
  'Refresh': 'refresh_token',
  'UserInfo': 'userinfo_response',
  'oauth-authz-req+jwt': 'request_object',
  // A GNAP access token in either JWT format (RFC 9767), signed through
  // signJwt() like every other token here so it is counted and revocable.
  'GNAP': 'gnap_access_token'
};

// The three the console offers to invalidate, which are the three the user of
// this service can actually present again. A signed UserInfo response is a
// reply, not a credential, and revoking one would mean nothing.
const REVOCABLE_KINDS = ['access_token', 'id_token', 'refresh_token',
                         'gnap_access_token'];

// Every kind a JWT can be recorded under, read off the table above rather than
// written out again — the tokens page's filter offers exactly these, and a
// filter listing a kind that can no longer be issued (or missing one that can)
// is a filter that quietly returns nothing.
const TOKEN_KINDS = Object.keys(KIND_BY_TYP)
                          .map(function (typ) { return KIND_BY_TYP[typ]; });

function kindOfTyp(typ) {
  log.debug("Entering kindOfTyp().");
  log.debug("Leaving kindOfTyp().");
  return KIND_BY_TYP[String(typ || '')] ||
         ('other (typ=' + (typ || 'none') + ')');
}

// Installed into helpers.js at require time — see the comment on setJwtRecorder
// there for why the direction is inverted. The signed token is passed in and
// deliberately not kept.
//
// `context` is the third parameter signJwt() offers and is what ties a token to
// the browser session it was issued under. It cannot be read off the payload,
// and that is the whole reason it exists: no token this service issues carries
// a session identifier — OIDC's `sid` claim is for front-channel logout and
// inventing one here would change what every client receives to make a console
// page easier to write. So the issuer states it out of band instead. A caller
// that says nothing (the credential issuer, WS-Trust's JWT) leaves both fields
// empty, which the users page reports as "not through a browser session" rather
// than as unknown.
function recordJwt(payload, signed, context) {
  log.debug("Entering recordJwt(). typ=" + (payload.typ || '(none)'));
  const issuedUnder = context || {};
  const kind = kindOfTyp(payload.typ);
  // A token with no jti cannot be revoked and cannot be looked up, so it gets a
  // synthetic key that sorts with the others and is marked unrevocable on the
  // page. The signed UserInfo response is the one that arrives this way.
  let key = payload.jti;
  if (!key) {
    nums.tokensWithoutJti++;
    key = 'no-jti-' + nums.tokensWithoutJti;
  }
  const record = {
    key: key,
    jti: payload.jti || '',
    kind: kind,
    typ: payload.typ || '',
    revocable: !!payload.jti && REVOCABLE_KINDS.indexOf(kind) >= 0,
    sub: payload.sub || '',
    // WHO SAID IT, which is this service under whichever base URL the request
    // arrived on — `oauth2.issuer` is empty by default precisely so that one
    // process answers correctly as localhost, as `sts` on a compose network and
    // through a published port. It is kept because it is the only thing in this
    // record that can tell an audience naming a PARTY from one naming this
    // service itself: a refresh token is addressed to the token endpoint and an
    // access token nobody named a resource for carries `<base>/resource`, and
    // `user_graph.js` would otherwise draw a box for each of them. Nothing can
    // be derived here instead — the base is a property of the REQUEST, and by
    // the time a page reads this record there is no request to ask.
    iss: payload.iss || '',
    // `username` on an access or refresh token, `preferred_username` on an ID
    // Token: the two carry the same person under different names because that
    // is what their respective specifications call the claim, and a console
    // column that read only one of them would show a dash for every ID Token.
    username: payload.username || payload.preferred_username || '',
    client_id: payload.client_id || payload.azp || payload.aud || '',
    // WHAT THIS TOKEN IS ADDRESSED TO, as its own fact. `client_id` above falls
    // back to the `aud` when nothing better names the client, which is right
    // for the tokens page's one party column and loses the audience entirely on
    // every token that DOES name its client — which is every token an RFC 8693
    // exchange issues, where the audience is the whole point.
    // `credential_graph.js` draws the resource a credential was issued to
    // reach, so it needs the audience whether or not a client_id sits beside
    // it. An array is joined rather than kept: `aud` may be one or several (RFC
    // 7519 section 4.1.3) and one string is what every reader of this record
    // already expects.
    audience: Array.isArray(payload.aud) ? payload.aud.join(' ')
                                         : String(payload.aud || ''),
    scope: payload.scope || '',
    // jkt rather than the whole cnf: the thumbprint is the binding, and it is
    // what makes a row on the page say "DPoP" honestly rather than by guessing.
    jkt: (payload.cnf && payload.cnf.jkt) || '',
    iat: payload.iat || 0,
    nbf: payload.nbf || 0,
    exp: payload.exp || 0,
    // The browser sign-on session this token was issued under, and the grant
    // that issued it. Empty for everything that had no session behind it — the
    // two direct grants, the pre-authorized code, a token exchange — which is a
    // fact about the token rather than a gap in the recording.
    sessionId: issuedUnder.sessionId || '',
    // AND WHETHER ANYBODY AUTHENTICATED FOR THAT SESSION (2026-09-05), beside
    // it and for exactly the reason it is here: the REFRESH grant has no
    // session and no cookie, so what it can say about the person is what this
    // registry remembers. Without it the second generation of a token issued
    // on an unauthenticated session would be judged as though somebody had
    // signed in, which is the one way this feature could quietly leak.
    //
    // `!== false` at the write as well as at the read, so a caller that says
    // nothing means "authenticated" — which is what every caller that existed
    // before this field meant.
    sessionAuthenticated: issuedUnder.sessionAuthenticated !== false,
    // WHICH TOKEN RESPONSE THIS CAME BACK IN (2026-09-05), and it is the reason
    // /admin/tokens lists SETS rather than credentials. OAuth 2.0 and OIDC are
    // the only families here that hand back several credentials at once — an
    // access token, an ID Token and a refresh token out of one code redemption,
    // an access token and an ID Token out of one implicit response — and until
    // this field existed there was nothing joining the three but a timestamp
    // three rows apart. Every other family issues one thing per act, so a row
    // with no set id is a set of one, which is the honest shape rather than a
    // gap.
    //
    // It CANNOT be derived, and that is why it is stated out of band exactly as
    // `sessionId` above is. Two clients redeeming two codes for the same person
    // at the same client in the same millisecond produce six tokens that agree
    // on every field this record holds; a heuristic over sub/client/issuedAt
    // would merge them, and the page would report a set that was never issued.
    // The two OAuth issuance sites mint one id and pass it to every token they
    // produce — see oauth2.js's tokenSet() and issueAuthorizationResponse() —
    // so the grouping is a FACT the issuer stated rather than a guess this file
    // made.
    //
    // A REFRESH PRODUCES A NEW SET, not a bigger one. What a set is is one
    // RESPONSE, so the second generation of a grant is its own row with its own
    // issued instant and its own expiries; what joins the generations is the
    // refresh lineage oauth2_bcp.js keeps and /admin/tokens/credential draws,
    // which is a different relation and is drawn as one.
    setId: issuedUnder.setId || '',
    grant: issuedUnder.grant || '',
    issuedAt: Date.now(),
    revoked: false,
    revokedAt: 0,
    revokedVia: '',
    // Recorded because it decides what the "sessions" figure means; see
    // sessionsFromArtifacts().
    length: String(signed || '').length
  };
  if (tokens.size >= MAX_TOKENS) {
    // Map iterates in insertion order, so the first key is the oldest.
    const oldest = tokens.keys().next().value;
    tokens.delete(oldest);
    nums.tokensForgotten++;
  }
  tokens.set(key, record);
  log.debug("Leaving recordJwt(). " + tokens.size + " token(s) held, " +
      nums.tokensForgotten + " " +
      "forgotten.");
}

setJwtRecorder(recordJwt);

// ---------------------------------------------------------------------------
// Revocation, for the whole service.
//
// The set holds jtis rather than token records because a jti can be revoked
// whose record has already been forgotten to the cap, and because RFC 7009 lets
// a caller revoke a token this registry never saw (one issued before a restart,
// say). It is the set that is authoritative; the record's `revoked` flag is a
// convenience for the page and is kept in step here.
//
// PER TRUST REALM since 2026-08-25, and it read "for the whole service" until
// then. Two things were wrong with one set. The metrics page prints
// `tokens.revoked` beside `tokens.held`, which comes from a per-realm map, so
// one realm's revocation count appeared under every realm — the exact
// disagreement the counters block near the top of this file exists to prevent.
// And `POST /oauth2/revoke` under one realm could kill a jti issued by another,
// which is a cross-realm WRITE in the one family whose realm support is
// documented as `full`. Nothing legitimate crossed: a jti only ever appears in
// the realm whose signing key minted it, so within a realm every read and write
// here answers exactly as it did.
//
// A Set has no facade in `realms.js` — `map()`, `arr()` and `obj()` are the
// three — so this is `keyed()`, the general case, and the reads below are
// spelled `revokedJtis` because of it.
// ---------------------------------------------------------------------------
// A MAP AND NOT A SET, AND ONLY BECAUSE A SET CANNOT BE PERSISTED (2026-09-07).
// The value is always `true` and nothing reads it — what this holds is
// membership. It was `realms.keyed(() => new Set())`, which meant a revocation
// never left the process that made it: with a request worker pool, a token
// revoked through /admin-api introspected as ACTIVE on any other worker,
// because that worker had never been told. `realms.map({persist})` is the
// declaration that makes a store replicate, and a Set has no such declaration.
const revokedJtis = realms.map({ persist: 'admin_stats.revokedJtis' });

function revoke(jti, via) {
  log.debug("Entering revoke(). jti=" + jti);
  if (!jti) {
    log.debug("Leaving revoke(). There was no jti to revoke.");
    return false;
  }
  const first = !revokedJtis.has(jti);
  revokedJtis.set(jti, true);
  const record = tokens.get(jti);
  if (record) {
    record.revoked = true;
    record.revokedAt = record.revokedAt || Date.now();
    record.revokedVia = record.revokedVia || (via || 'unstated');
    // THROUGH THE STORE. `revokedJtis` above is what ENFORCES the revocation
    // and it is journalled by its own `set()`; this record is what the console
    // and `/admin-api/tokens` DRAW, and a field stamped in place never leaves
    // this process — so the token would read as revoked on one worker and live
    // on the next, which is the one report an operator must be able to trust.
    tokens.set(jti, record);
  }
  log.info('admin: the token with jti ' + jti + ' is revoked (' +
           (via || 'unstated') + '). ' +
           revokedJtis.size + ' revoked in total.');
  log.debug("Leaving revoke(). " + (first ? "It is newly revoked." : "It was " +
      "already revoked."));
  return first;
}

// Un-revoking is NOT something an authorization server can do — RFC 7009 has no
// such operation and a real deployment could not offer one, because a resource
// server may already have cached the refusal. It is here because this service
// exists to be experimented with, and having to restart it to get back to a
// working token turns a two-second test into a two-minute one. The console
// labels it NON-SPEC for exactly that reason.
function restore(jti) {
  log.debug("Entering restore(). jti=" + jti);
  const was = revokedJtis.delete(jti);
  const record = tokens.get(jti);
  if (record) {
    record.revoked = false;
    record.revokedAt = 0;
    record.revokedVia = '';
    // Through the store, for revoke()'s reason above and in this direction too.
    tokens.set(jti, record);
  }
  log.info('admin: the token with jti ' + jti + ' is no longer revoked ' +
                                                '(NON-SPEC).');
  log.debug("Leaving restore(). " + (was ? "It had been revoked." : "It had " +
      "not been revoked."));
  return was;
}

function isRevoked(jti) {
  log.debug("Entering isRevoked().");
  log.debug("Leaving isRevoked().");
  return !!jti && revokedJtis.has(jti);
}

function revokedCount() {
  log.debug("Entering revokedCount().");
  log.debug("Leaving revokedCount().");
  return revokedJtis.size;
}

// ---------------------------------------------------------------------------
// The artifacts that are not JWTs: assertions, tickets and credentials.
//
// One shape for all three, because the metrics page asks the same three
// questions of each — how many, how many still valid, and whose. `expiresAt` is
// a millisecond epoch or 0 for "no expiry was stated", which is the honest
// answer for a couple of them rather than pretending to an expiry of now.
// ---------------------------------------------------------------------------
// PER TRUST REALM. `realms.arr()` is a array that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain array it replaced. See common/realms.js.
const artifacts = realms.arr({ persist: 'admin_stats.artifacts',
                               merge: 'own' });

// ---------------------------------------------------------------------------
// THE ARTIFACT KEY CARRIES THE PROCESS THAT MINTED IT (2026-09-08).
//
// `key` used to be `artifact-<n>` off `nums.artifactsRecorded`, and that
// counter is `merge: 'own'` — one per process. So two processes both mint
// `artifact-3`, and once the issued list fans in (see allArtifacts()) the
// merged table holds two different credentials under one handle:
// `artifactByKey()` returns whichever comes first, and the Revoke button on
// one row acts on the other. A per-process tag makes the handle mean one row
// again. It is opaque to every caller — nothing parses it, and the console and
// the management API both take it from the list they were given.
// ---------------------------------------------------------------------------
const ARTIFACT_TAG = process.pid.toString(36) +
                     Date.now().toString(36).slice(-4);

// ---------------------------------------------------------------------------
// AND A REGISTER OF WHAT HAS BEEN REVOKED, WHICH THE COMMENT BELOW USED TO
// ARGUE AGAINST (2026-09-08).
//
// That argument was right and its premise expired. It ran: nothing ever asks
// this service about an artifact, so a set outliving the record would answer a
// question nobody can ask, and the flag ON the record is enough. What it took
// for granted is that the record is HERE — and with request workers it very
// often is not. `artifacts` is `merge: 'own'`, so the row a console shows may
// belong to another process's segment and be a COPY; marking that copy revoked
// changed nothing anybody would ever read again, and the register went on
// reporting the credential valid. `sts_admin_api_operations` caught it exactly:
// "the register should now report the assertion revoked; it reads valid".
//
// It is a plain `realms.map` — `replace` merge, not `own` — because a
// revocation is a whole-valued fact about one credential rather than an
// accumulator, so the later write winning is exactly right.
// ---------------------------------------------------------------------------
const revokedArtifacts =
    realms.map({ persist: 'admin_stats.revokedArtifacts' });

// The mark on one artifact, wherever it was made. `null` when nothing has
// revoked it.
function artifactRevocation(record) {
  log.debug("Entering artifactRevocation().");
  if (!record || !record.key) {
    log.debug("Leaving artifactRevocation().");
    return null;
  }
  log.debug("Leaving artifactRevocation().");
  // THE REGISTER IS THE ONLY SOURCE, and it was a SECOND source for an hour —
  // which resurrected revocations that had been undone. The flag on a record is
  // this process's own copy of the answer: the worker that revoked an artifact
  // has `revoked: true` in its own `merge: 'own'` segment for ever, and that
  // segment is what the fan-in serves to everybody. So a restore made on any
  // OTHER worker deleted the shared row and cleared its own copy, and the
  // original worker's row then answered "revoked" again through the fallback.
  // `sts_admin_api_operations` reported it exactly: "after both restores the
  // assertion should be valid again; it reads revoked."
  //
  // There is no mode in which this loses anything: `revokeArtifact()` writes
  // the register on every path, and `realms.map()` is an ordinary in-process
  // Map when nothing is being persisted.
  return revokedArtifacts.get(record.key) || null;
}

// One artifact with the revocation overlaid, so that a row from another
// process's segment says who revoked it and when rather than only that it is
// in the revoked state.
function withRevocation(record) {
  log.debug("Entering withRevocation().");
  const mark = artifactRevocation(record);
  if (!mark) {
    if (!record || !record.revoked) {
      log.debug("Leaving withRevocation().");
      return record;
    }
    log.debug("Leaving withRevocation().");
    // ITS OWN FLAG SAYS REVOKED AND THE REGISTER DOES NOT, which means another
    // process has since restored it. The register wins — see
    // artifactRevocation() — and the row is drawn without the stale mark so
    // that the state and the "revoked by" line cannot disagree.
    return Object.assign({}, record,
                         { revoked: false, revokedAt: 0, revokedVia: '' });
  }
  log.debug("Leaving withRevocation().");
  return Object.assign({}, record, { revoked: true, revokedAt: mark.at,
                                     revokedVia: mark.via });
}


function recordArtifact(kind, detail) {
  log.debug("Entering recordArtifact().");
  nums.artifactsRecorded += 1;
  // `key` is THIS SERVICE'S handle on the row and never the protocol's — the
  // protocol's is `id`, and a Kerberos ticket has none at all. The two are kept
  // apart deliberately: `identifier` is what somebody can quote back at this
  // service (a jti, an AssertionID) and is what /admin/tokens/credential looks
  // a lineage up by, while this is only ever a way of naming ONE ROW of the
  // issued register — which is what /admin/tokens/set needs to open a set of
  // one. It matches the shape the token store already had, where the key is the
  // jti or a synthetic `no-jti-N`, so both halves of the merged list are
  // addressable the same way.
  const record = Object.assign({ kind: kind, issuedAt: Date.now(), expiresAt: 0,
                                 subject: '',
                                 key: 'artifact-' + ARTIFACT_TAG + '-' +
                                      nums.artifactsRecorded }, detail);
  artifacts.push(record);
  if (artifacts.length > MAX_ARTIFACTS) {
    artifacts.shift();
    nums.artifactsForgotten++;
  }
  log.debug("Leaving recordArtifact().");
  return record;
}

// A SAML assertion, 2.0 or 1.1. Called from the two builders rather than from
// their callers: WS-Trust, WS-Federation and anything added later all go
// through them, so this counts every assertion instead of every assertion
// somebody remembered to count.
function recordAssertion(version, detail) {
  log.debug("Entering recordAssertion(). version=" + version + ", subject=" +
            (detail.subject || '?'));
  const record = recordArtifact('SAML ' + version, {
    id: detail.id || '',
    subject: detail.subject || '',
    audience: detail.audience || '',
    expiresAt: detail.expiresAt || 0,
    signed: detail.signed !== false
  });
  log.debug("Leaving recordAssertion(). " + artifacts.length + " artifact(s) " +
      "held.");
  return record;
}

// A Kerberos ticket. `kind` is 'TGT' or 'service ticket' — the distinction the
// metrics page makes, because a TGT IS the Kerberos session and a service
// ticket is one use of it, so counting them together would report the wrong
// thing twice.
function recordTicket(kind, detail) {
  log.debug("Entering recordTicket(). kind=" + kind + ", client=" +
            (detail.client || '?'));
  const record = recordArtifact('Kerberos ' + kind, {
    subject: detail.client || '',
    realm: detail.realm || '',
    service: detail.service || '',
    etype: detail.etype || '',
    expiresAt: detail.expiresAt || 0
  });
  log.debug("Leaving recordTicket(). " + artifacts.length +
            " artifact(s) held.");
  return record;
}

// A SPIFFE SVID, X.509 or JWT.
//
// A FOURTH artifact family rather than rows under `token`, and the distinction
// is not cosmetic. A JWT-SVID is a JWS and would sit perfectly well among the
// JWTs — but an X509-SVID is a certificate, the two are issued by the same act
// against the same registration entry, and splitting them would put one half of
// SPIFFE on the tokens page and the other half nowhere. More to the point:
// **neither is revocable here**, where every kind under `token` is. `signJwt()`
// is not the funnel for a JWT-SVID either, and cannot be — it signs with the
// STS key, and a JWT-SVID is signed by the trust domain's JWT authority — so
// this is the funnel, called from spiffe_workload.js and spiffe_api.js at the
// moment each SVID is minted.
function recordSvid(kind, detail) {
  log.debug("Entering recordSvid(). kind=" + kind + ", subject=" +
            (detail.subject || '?'));
  const record = recordArtifact('SVID (' + kind + ')', {
    subject: detail.subject || '',
    entryId: detail.entryId || '',
    audience: (detail.audiences || []).join(' '),
    serial: detail.serial || '',
    hint: detail.hint || '',
    expiresAt: detail.expiresAt || 0
  });
  // -----------------------------------------------------------------------
  // AND THE DIRECTORY, FOR AN X509-SVID. See noteCertificateIssued() below for
  // why an ISSUANCE reaches the observer at all, given that being issued a
  // credential is not authenticating with one.
  // -----------------------------------------------------------------------
  if (kind === 'X.509' && detail.certificate) {
    noteCertificateIssued(detail.subject, detail.certificate, detail);
  }
  log.debug("Leaving recordSvid(). " + artifacts.length + " artifact(s) held.");
  return record;
}

// ---------------------------------------------------------------------------
// AN ISSUED CERTIFICATE IS AN IDENTITY IN THE DIRECTORY, WHICH IS A DIFFERENT
// CLAIM FROM "IT AUTHENTICATED" AND THE TWO MUST NOT MERGE.
//
// Until now the directory grew an entry for a SPIFFE identity at exactly three
// points, all of them an acceptance: an X509-SVID over mutual TLS at the SPIRE
// Server API, an agent attesting, and a JWT-SVID verified at ValidateJWTSVID.
// Being ISSUED an SVID was deliberately not one of them, and the argument was
// sound as far as it went — a workload that collects a certificate has proved
// nothing, and /admin/users answers "who has authenticated here".
//
// What it left out is that this trust domain's whole output is CERTIFICATES,
// and a directory that could not say which identities hold one — nor what the
// current one is, nor whether the identity has since been shut off — could not
// answer the question somebody points an LDAP client at a SPIFFE mock to ask.
// So an issuance now reaches the observer too, and it is told which of the two
// it is:
//
//   * `event: 'authentication'` — a credential was ACCEPTED. Counted on this
//     page, an audit row, the whole existing path, unchanged.
//   * `event: 'issuance'` — a certificate was MINTED for this identity. It
//     creates or updates the directory entry and writes the certificate onto
//     it, and it does NOTHING ELSE: no `authentications` count, no audit
//     `authentication` row, and no protocol row. An issuance that inflated the
//     authentication count would make /admin/users's central number mean two
//     things at once, and an agent holding a stream open re-mints every
//     half-lifetime — so a workload left running overnight would read as having
//     authenticated four hundred times. What the identity DOES get on that page
//     is the row `recordArtifact()` above already gives it: an SVID with no
//     authentication behind it, which the page counts under "seen only as a
//     subject" and which is the honest answer.
//
// THE FUNNEL IS recordSvid() ABOVE, which the five X509-SVID mints already
// call, and that is the same argument recordAuthentication() makes for itself:
// one place rather than five, and a sixth mint added later that forgets to call
// it is a mint with no artifact row either — so the omission shows on
// /admin/metrics rather than being silent in the directory alone.
//
// WHAT IS NOT COVERED, and each is a decision rather than a gap:
//
//   * A JWT-SVID. It is not a certificate; it has no subject, issuer, serial or
//     validity in the sense these attributes hold, and the identity behind one
//     reaches the directory anyway when it is VALIDATED at ValidateJWTSVID,
//     which is an acceptance.
//   * The SPIRE Server API's OWN server SVID, minted in spiffe_grpc.js to bind
//     the mutual-TLS port. It never reaches this function because that call
//     site records no artifact either, and it must not: filing this service's
//     own listener among the people is the mistake didPlan() already refuses
//     for `/did/generate?method=web`.
//   * A downstream CA from NewDownstreamX509CA. It is an intermediate belonging
//     to whoever asked for it, not an identity in this trust domain, and
//     spiffe_ca.js deliberately does not add it to this service's authorities
//     either.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A SECURITY KEY WAS ENROLLED FOR SOMEBODY (2026-09-06).
//
// The FOURTH kind of event `setUserObserver()` carries, beside
// `authentication`, `issuance` and `credential-status` — and it is here for the
// reason the second one is: **being given a credential is not authenticating
// with one**, and the directory has to know about the person either way.
//
// Before this, a WebAuthn key enrolled for somebody who had never signed in
// left this service holding a working credential for a person it could not
// list. For a PASSWORDLESS key that is the whole account, because the key is
// the only credential it will ever have.
//
// **IT COUNTS NO AUTHENTICATION**, exactly as `issuance` does not. Nobody
// authenticated by enrolling a key, and counting it would inflate the one
// number /admin/users is about. What the person gets is an entry and a row
// marked as seen without having authenticated, which is the honest answer.
// ---------------------------------------------------------------------------
// IS THERE ALREADY AN IDENTITY BY THIS NAME? Asked by the WebAuthn enrolment
// door in product mode, which must not enrol a key for somebody who does not
// exist — that would create them, and creating objects because something
// referenced them is exactly what product mode removes.
//
// It answers about THIS REGISTER rather than about the directory, and the two
// can differ: a person seeded into the directory who has never authenticated is
// not here. That is the conservative direction for this caller — it refuses an
// enrolment it could have allowed, rather than allowing one that creates
// somebody — and the refusal names the fix.
function knownUser(username) {
  log.debug("Entering knownUser().");
  const identity = identityOf(username);
  if (!identity.key) {
    log.debug("Leaving knownUser().");
    return false;
  }
  log.debug("Leaving knownUser().");
  return !!users.get(identity.key);
}

function noteWebauthnEnrolled(username) {
  log.debug("Entering noteWebauthnEnrolled(). username=" + (username || '?'));
  const identity = identityOf(username);
  if (!identity.key || !userObserver) {
    log.debug("Leaving noteWebauthnEnrolled(). " +
              (identity.key ? "There is no directory." :
               "There is no identity."));
    return;
  }
  try {
    userObserver({
      event: 'enrolment',
      key: identity.key, name: identity.name, realm: identity.realm,
      presented: identity.form,
      protocol: 'WebAuthn',
      method: 'security key enrolled',
      isClient: false, sub: '',
      amr: [], acr: '',
      linkedTo: ''
    });
  } catch (e) {
    // The tail must not wag the dog — the same rule signJwt()'s recorder
    // follows. An enrolment that succeeded must not be undone because the
    // directory could not be told about it.
    log.error(errorCodes.tag('STS-REG-0039') +
              'admin: the directory could not be told that a security key ' +
              'was enrolled for ' + identity.key + ': ' + e.message);
  }
  log.debug("Leaving noteWebauthnEnrolled().");
}

function noteCertificateIssued(subject, certificate, detail) {
  log.debug("Entering noteCertificateIssued(). subject=" + (subject || '?'));
  const identity = identityOf(subject);
  if (!identity.key || !userObserver) {
    log.debug("Leaving noteCertificateIssued(). " +
              (identity.key ? "There is no directory." :
               "There is no identity."));
    return;
  }
  const info = detail || {};
  try {
    userObserver({
      event: 'issuance',
      key: identity.key, name: identity.name, realm: identity.realm,
      presented: identity.form,
      protocol: 'SPIFFE',
      method: 'X509-SVID issued',
      isClient: false, sub: '',
      amr: [], acr: '',
      // NOT `certificate`, which the observer already reads as "the identity IS
      // this DN" and routes to certificatePlan(). Every SVID this trust domain
      // mints carries the SAME subject — `spiffe.svidSubject`, `C=US,O=SPIRE` —
      // so that route would fold every workload in the domain onto one entry
      // named for `O=SPIRE`. The identity here is the SPIFFE ID; the
      // certificate is a FACT ABOUT it, which is what the different key says.
      issuedCertificate: certificate,
      entryId: info.entryId || '',
      hint: info.hint || '',
      linkedTo: ''
    });
  } catch (e) {
    // The same rule the observer call in recordAuthentication() follows, and
    // here it matters more: this runs inside a gRPC handler that has already
    // minted a certificate the caller is owed, and a throw would turn a
    // successful issuance into an Unknown status.
    log.error(errorCodes.tag('STS-REG-0039') +
              'the user observer threw on an issuance and was ignored; the ' +
              'SVID itself is unaffected: ' + e.message);
  }
  log.debug("Leaving noteCertificateIssued().");
}

// ---------------------------------------------------------------------------
// AND THE OTHER END OF IT: AN IDENTITY WHOSE CREDENTIALS HAVE BEEN SHUT OFF.
//
// SPIFFE HAS NO REVOCATION and this does not invent one — `GET /spiffe` says so
// outright and the Workload API's `crl` field stays empty because empty is the
// conforming value. What this records is the three things in the registry that
// DO end an identity's ability to hold a credential here, which is the honest
// nearest thing: a registration entry deleted, an agent banned, an agent
// deleted. `spiffe_registry.js` is what calls it, at the point each of those
// happens, and the directory writes a status onto the entry rather than
// removing it — the record of an identity that USED to be issued certificates
// is the whole reason somebody would look.
//
// It goes through the observer for the reason everything else here does: this
// file cannot require ldap_server.js (that module requires this one, and a
// cycle in node hands back exports that are undefined), and a second slot for
// three calls would cost a reader an indirection that rule 3e says to spend
// only where a require would close a cycle or move a route. This one is the
// SAME slot with a third `event`.
// ---------------------------------------------------------------------------
function recordCredentialStatus(subject, status, detail) {
  log.debug("Entering recordCredentialStatus(). subject=" + (subject || '?') +
            ", status=" + status);
  const identity = identityOf(subject);
  if (!identity.key || !userObserver) {
    log.debug("Leaving recordCredentialStatus(). " +
              (identity.key ? "There is no directory." :
               "There is no identity."));
    return;
  }
  const info = detail || {};
  try {
    userObserver({
      event: 'credential-status',
      key: identity.key, name: identity.name, realm: identity.realm,
      presented: identity.form,
      protocol: 'SPIFFE',
      method: String(status),
      credentialStatus: String(status),
      // Why, in the words the page prints. It is written as a sentence rather
      // than as a code because it is the only thing on the entry that explains
      // a status a reader did not expect, and "entry-deleted" would need a
      // table nobody has.
      credentialStatusReason: String(info.reason || ''),
      isClient: false, sub: '', amr: [], acr: '', linkedTo: ''
    });
  } catch (e) {
    // As above: a ban or a delete has already happened and must not be undone
    // by a directory that could not write it down.
    log.error(errorCodes.tag('STS-REG-0039') +
              'the user observer threw on a credential status change and was ' +
              'ignored; the change itself stands: ' + e.message);
  }
  log.debug("Leaving recordCredentialStatus().");
}

// A verifiable credential, in whichever of the three formats was asked for.
function recordCredential(format, detail) {
  log.debug("Entering recordCredential(). format=" + format);
  const record = recordArtifact('Credential (' + format + ')', {
    subject: detail.subject || '',
    configId: detail.configId || '',
    expiresAt: detail.expiresAt || 0
  });
  log.debug("Leaving recordCredential(). " + artifacts.length + " " +
      "artifact(s) held.");
  return record;
}

// ---------------------------------------------------------------------------
// SCIM, WHICH IS COUNTED HERE AND NOT ON /admin/metrics.
//
// Every other family in this service is counted twice on purpose and in two
// different senses: an endpoint CALL (app.js's log, by matched route) and an
// ARTIFACT (a token, an assertion, a ticket). SCIM produces no artifact — a
// provisioned person is an LDAP entry and the directory already reports those —
// so what is worth counting is the SHAPE of what a provisioning client did:
// which operation, on which resource type, and whether it was refused.
//
// **It is deliberately NOT folded into snapshot().** The /scim routes are
// already in that reply, counted by path like every other endpoint, and a
// second total beside them would be one act counted twice in one document — the
// same mistake rule 3c warns about for audit rows. So this is its own reply,
// read by /admin/scim and by GET /admin-api/scim, and /admin/metrics is
// untouched.
//
// **THE VOCABULARY IS A TABLE**, the way audit.js's CATEGORIES and ACTIONS are,
// and for the same reason: the console's breakdown and the management API's
// `operations` member are both built from it, so an operation cannot be
// performed and go unreported, nor be reported and never occur. A new operation
// is a row here and a `recordScim()` call, and nothing else.
// ---------------------------------------------------------------------------
const SCIM_OPERATIONS = [
  { operation: 'create', label: 'Create', method: 'POST',
    what: 'A resource was created (RFC 7644 section 3.3).' },
  { operation: 'list', label: 'List', method: 'GET',
    what:
      'A collection was queried (section 3.4.2), with or without a filter.' },
  { operation: 'read', label: 'Read', method: 'GET',
    what: 'One resource was retrieved by id (section 3.4.1).' },
  { operation: 'search', label: 'Search', method: 'POST',
    what: 'A query sent as a POST to .search (section 3.4.3), which is what ' +
          'a client uses when its filter is too long for a URL.' },
  { operation: 'replace', label: 'Replace', method: 'PUT',
    what: 'A whole resource was replaced (section 3.5.1).' },
  { operation: 'modify', label: 'Modify', method: 'PATCH',
    what: 'A PATCH was applied (section 3.5.2). The operation a provisioning ' +
          'client uses most, and the one whose path grammar is hardest to ' +
          'get right — which is why this service does not implement it ' +
          'itself.' },
  { operation: 'delete', label: 'Delete', method: 'DELETE',
    what: 'A resource was deleted (section 3.6).' },
  { operation: 'bulk', label: 'Bulk', method: 'POST',
    what: 'A BulkRequest was applied (section 3.7). The operations INSIDE it ' +
          'are counted individually as well, so one bulk of five creates is ' +
          'one bulk row and five create rows — which is the honest reading ' +
          'and is said on the page, because a reader adding the column up ' +
          'will otherwise find it does not tally.' },
  { operation: 'discovery', label: 'Discovery', method: 'GET',
    what: 'ServiceProviderConfig, ResourceTypes or Schemas (section 4). What ' +
          'a client reads before it does anything else, and the one thing ' +
          'here that touches no directory entry.' }
];

const SCIM_RESOURCE_TYPES = ['User', 'Group', 'Bulk', 'ServiceProviderConfig',
                             'ResourceType', 'Schema', 'Self'];

// ---------------------------------------------------------------------------
// THE COUNTERS ARE PER TRUST REALM, AND THEY WERE NOT UNTIL 2026-09-06.
//
// This was a plain object beside a file in which everything else — the endpoint
// calls, the token registry, the artifact list, the identity register, the
// revocation set, the claim sets — is declared `realms.map()`, `realms.arr()`
// or `realms.obj()`. It was the third store found process-wide for a reason
// that had stopped being true, and `tests/realm_isolation.js`'s header says
// that a third one belongs in that file rather than in one of its own, so the
// guard is there beside the other two.
//
// What being process-wide produced was not an error. `/scim/v2` is realm-
// prefixed like every other endpoint here and writes into a directory that has
// been a SUBTREE PER REALM since 2026-08-25, so a provisioning client working
// in `/realm/acme` created entries in acme and was counted in the default
// realm's totals — a page under one realm reporting traffic that happened in
// another, beside a directory count that was correctly partitioned. Exactly
// the shape of disagreement that test was written about.
//
// `realms.obj(factory)` rather than `realms.map()` because this is a record of
// SCALARS and dictionaries read by name (`scimCounts.total++`), which is the
// case that facade's own comment describes.
// ---------------------------------------------------------------------------

// HOW MANY REQUESTS THE MONITOR REMEMBERS INDIVIDUALLY. The tallies are
// unbounded — they are integers — but the `recent` ring is one object per
// request and would otherwise grow without limit on a service being load
// tested. Fifty because the question it answers is "what just happened", which
// nobody asks about the four-hundredth-most-recent call; the durable record of
// anything older is the audit log, which has a settable cap of its own.
const SCIM_RECENT = 50;

// HOW MANY DISTINCT CALLERS ARE REMEMBERED. A cap for the same reason and a
// sharper one: the principal is whatever the caller typed — Basic here accepts
// any username — so an unbounded table is a store somebody else decides the
// size of. Past the cap the tallies still count every call; it is only the
// per-client BREAKDOWN that stops growing, and the page says so rather than
// quietly under-reporting.
const SCIM_MAX_CLIENTS = 200;

function freshScimCounts() {
  log.debug("Entering freshScimCounts().");
  log.debug("Leaving freshScimCounts().");
  return {
    total: 0,
    ok: 0,
    failed: 0,
    firstAt: 0,
    lastAt: 0,
    byOperation: {},
    byResourceType: {},
    byStatus: {},
    // The status CLASS as well as the code, because "how much of this is 4xx"
    // is the question somebody actually arrives with and summing a table of
    // eleven codes in their head is how they get it wrong.
    byStatusClass: {},
    // Keyed by the `scimType` from RFC 7644 section 3.12, with '(none)' for a
    // refusal that carried no such code — a 404 has none, and a table that
    // silently dropped those would report far fewer failures than there were.
    byScimType: {},
    // WHICH AUTHENTICATION SCHEME GOT IN. Keyed by scim_auth.js's scheme ids,
    // plus `anonymous` for a request nothing authenticated (a discovery call
    // with `scim.authDiscovery` off) and `refused` for one that never got past
    // the gate. The VOCABULARY is not here, deliberately:
    // it belongs to scim_auth.js, this module cannot require that one (it
    // requires this), and the console draws the full list of schemes from the
    // surface description it already reads. So this is a plain tally and the
    // zeroes are supplied by the page — which is the same division /admin/scim
    // already has between the counters and the surface.
    byAuthScheme: {},
    // ONE ROW PER OPERATION, which is the breakdown `byOperation` cannot be.
    // That table is a single integer per operation and answers "how many
    // PATCHes"; this one answers "how many of them worked, and how long did
    // they take" — and those are the two halves of the question somebody has
    // when a provisioning client is slow or is failing on one verb only.
    detail: {},
    // WHO IS CALLING. Keyed by the authenticated principal, which is
    // scim_auth.js's `principal` — a username for the five user-bearing
    // schemes, a `client_id` for a Bearer token minted for an application, and
    // an RFC 4514 subject DN for a client certificate. A caller nothing
    // authenticated has no row here at all and is counted in `anonymous`;
    // one the gate turned away is counted in `refused`, because attributing a
    // refusal to a name the caller merely CLAIMED would be this page asserting
    // an identity the service declined to believe.
    clients: {},
    // Set when the client table stopped growing at SCIM_MAX_CLIENTS. Reported
    // rather than hidden: a truncated breakdown that does not say it is
    // truncated is a breakdown somebody will read as the whole list.
    clientsCapped: false,
    anonymous: 0,
    refused: 0,
    // Latency and response size, in aggregate. `ms` is a SUM and is divided by
    // `total` when it is drawn — kept as a sum because a running mean loses the
    // ability to answer any other question about the same numbers.
    ms: 0,
    maxMs: 0,
    bytes: 0,
    // THE LAST FEW REQUESTS, INDIVIDUALLY. Newest first. Everything else here
    // is an aggregate, and an aggregate cannot answer "what did the call that
    // just failed actually look like" — which is the first thing anybody asks.
    recent: []
  };
}

const scimCounts = realms.obj(freshScimCounts,
                              { persist: 'admin_stats.scimCounts',
                                merge: 'own' });

function bump(table, key) {
  log.debug("Entering bump().");
  const name = String(key || '(none)');
  table[name] = (table[name] || 0) + 1;
  log.debug("Leaving bump().");
}

// The per-operation row, created on first use. Not pre-seeded from
// SCIM_OPERATIONS because the ZEROES are supplied by the reader out of that
// same table — which is how an operation that has never been called still
// appears on the page, and how one that is called under a name the table has
// not heard of appears too rather than being dropped.
function scimDetailRow(table, operation) {
  log.debug("Entering scimDetailRow().");
  const name = String(operation || '(none)');
  if (!table[name]) {
    table[name] = { calls: 0, ok: 0, failed: 0, ms: 0, maxMs: 0, bytes: 0 };
  }
  log.debug("Leaving scimDetailRow().");
  return table[name];
}

// ---------------------------------------------------------------------------
// One SCIM request, recorded where it is ANSWERED rather than where it arrives
// — the same rule recordAuthentication() follows about a credential being
// accepted. A request that never reached a handler is an endpoint call and is
// counted as one by app.js; a request this module counts is one the SCIM
// implementation had an opinion about.
//
// It cannot throw. It is called from inside request handlers whose failure mode
// would otherwise be a provisioning client seeing a 500 because a counter was
// unhappy, which is the same guarantee audit() gives and for the same reason.
//
// **EVERYTHING IS READ BEFORE ANYTHING IS WRITTEN**, which is the rule
// `xacml/xacml_monitor.js`'s `record()` states at length and had to learn the
// hard way: a caller whose object throws on a property access — a getter, a
// Proxy, a half-built object — otherwise leaves the row with the call counted
// and no bucket, and the page's own arithmetic stops reconciling permanently
// with nothing to say why. Half a count is worse than no count, because it is
// indistinguishable from a real request.
// ---------------------------------------------------------------------------
function recordScim(detail) {
  log.debug("Entering recordScim().");
  try {
    const info = detail || {};
    const now = Date.now();

    // --- read ------------------------------------------------------------
    const operation = String(info.operation || '(none)');
    const resourceType = String(info.resourceType || '(none)');
    const status = String(info.status || '(none)');
    const statusClass = /^[1-5]/.test(status) ? status.charAt(0) + 'xx' :
                        '(none)';
    const ok = !!info.ok;
    const scimType = String(info.scimType || '');
    const scheme = String(info.authScheme || 'anonymous');
    // A duration this module did not measure is ABSENT rather than zero. A
    // call site that forgot to stamp the request would otherwise pull the mean
    // down towards nothing, which is the one way a latency figure can be wrong
    // and look healthy.
    const ms = Number.isFinite(Number(info.ms)) && Number(info.ms) >= 0
      ? Number(info.ms) : null;
    const bytes = Number.isFinite(Number(info.bytes)) && Number(info.bytes) >= 0
      ? Number(info.bytes) : 0;
    const principal = String(info.principal || '').trim();
    const isClient = !!info.isClient;
    const method = String(info.method || '');
    const path = String(info.path || '');
    // `refused` is scim.js's word for a caller the GATE turned away, and it is
    // the one case where there is a name on the request and this page must not
    // use it. See the comment on `clients` above.
    const wasRefusedAtTheGate = scheme === 'refused';
    const named = !!principal && !wasRefusedAtTheGate && scheme !== 'anonymous';

    // --- write -----------------------------------------------------------
    scimCounts.total++;
    if (ok) {
      scimCounts.ok++;
    } else {
      scimCounts.failed++;
    }
    if (!scimCounts.firstAt) {
      scimCounts.firstAt = now;
    }
    scimCounts.lastAt = now;
    bump(scimCounts.byOperation, operation);
    bump(scimCounts.byResourceType, resourceType);
    bump(scimCounts.byStatus, status);
    bump(scimCounts.byStatusClass, statusClass);
    bump(scimCounts.byAuthScheme, scheme);
    if (!ok) {
      bump(scimCounts.byScimType, scimType);
    }
    if (wasRefusedAtTheGate) {
      scimCounts.refused++;
    } else if (!named) {
      scimCounts.anonymous++;
    }

    const row = scimDetailRow(scimCounts.detail, operation);
    row.calls += 1;
    if (ok) {
      row.ok += 1;
    } else {
      row.failed += 1;
    }
    row.bytes += bytes;
    scimCounts.bytes += bytes;
    if (ms !== null) {
      row.ms += ms;
      scimCounts.ms += ms;
      if (ms > row.maxMs) {
        row.maxMs = ms;
      }
      if (ms > scimCounts.maxMs) {
        scimCounts.maxMs = ms;
      }
    }

    if (named) {
      const clients = scimCounts.clients;
      let client = clients[principal];
      if (!client && Object.keys(clients).length >= SCIM_MAX_CLIENTS) {
        // THE TALLIES ABOVE ARE ALREADY COUNTED. Only the breakdown stops, and
        // the flag is what stops the page claiming this is everybody.
        scimCounts.clientsCapped = true;
      } else {
        if (!client) {
          client = { principal: principal,
                     // 'application' when the credential named a client_id and
                     // no user — scim_auth.js's own `isClient`, carried here
                     // rather than guessed at from the shape of the name.
                     kind: isClient ? 'application' : 'identity',
                     schemes: {}, resourceTypes: {},
                     calls: 0, ok: 0, failed: 0,
                     firstAt: now, lastAt: now,
                     lastOperation: '', lastStatus: '' };
          clients[principal] = client;
        }
        client.calls += 1;
        if (ok) {
          client.ok += 1;
        } else {
          client.failed += 1;
        }
        bump(client.schemes, scheme);
        bump(client.resourceTypes, resourceType);
        client.lastAt = now;
        client.lastOperation = operation;
        client.lastStatus = status;
        // A caller that authenticated as an application ONCE is an
        // application, and the last answer wins rather than the first: an
        // entry that changed kind is a name being used two ways, and the
        // recent reading is the one that explains what is happening now.
        client.kind = isClient ? 'application' : 'identity';
      }
    }

    scimCounts.recent.unshift({
      at: now, operation: operation, resourceType: resourceType,
      status: status, ok: ok, scimType: scimType, scheme: scheme,
      principal: named ? principal : '', ms: ms, bytes: bytes,
      method: method, path: path });
    if (scimCounts.recent.length > SCIM_RECENT) {
      scimCounts.recent.length = SCIM_RECENT;
    }
  } catch (e) {
    // Swallowed on purpose: a counter must never be able to fail a provisioning
    // request. Logged rather than ignored, because a counter that stopped
    // counting silently would make this page quietly wrong.
    log.warn(errorCodes.tag('STS-REG-0040') + 'scim: a request could not be ' +
                                              'counted: ' + e.message);
  }
  log.debug("Leaving recordScim().");
}

// The counters, with the two vocabularies beside them so that a caller can draw
// every row — including the ones at zero, which are the interesting ones for
// somebody asking "does this server support PATCH".
//
// THIS IS THE SUMMARY AND `scimMonitorSnapshot()` BELOW IS THE WHOLE THING.
// Two views over ONE store rather than two stores: `/admin/scim` is about the
// SURFACE — what SCIM here is, what it will and will not do, which LDAP
// attribute each member is — and carries the headline counts because a surface
// page with no evidence that anything ever called it is a page about a
// hypothesis. `/admin/scim/monitor` is about the TRAFFIC. Neither can disagree
// with the other, because there is one set of numbers underneath both.
function scimSnapshot() {
  log.debug("Entering scimSnapshot().");
  const operations = SCIM_OPERATIONS.map(function (row) {
    return { operation: row.operation, label: row.label, method: row.method,
             what: row.what,
             count: scimCounts.byOperation[row.operation] || 0 };
  });
  const resourceTypes = SCIM_RESOURCE_TYPES.map(function (name) {
    return { resourceType: name, count: scimCounts.byResourceType[name] || 0 };
  });
  const out = {
    total: scimCounts.total,
    ok: scimCounts.ok,
    failed: scimCounts.failed,
    firstAt: scimCounts.firstAt,
    lastAt: scimCounts.lastAt,
    operations: operations,
    resourceTypes: resourceTypes,
    byStatus: Object.assign({}, scimCounts.byStatus),
    byScimType: Object.assign({}, scimCounts.byScimType),
    byAuthScheme: Object.assign({}, scimCounts.byAuthScheme)
  };
  log.debug("Leaving scimSnapshot(). " + out.total + " request(s) counted.");
  return out;
}

// ---------------------------------------------------------------------------
// EVERYTHING /admin/scim/monitor AND GET /admin-api/scim/monitor DRAW, out of
// ONE call so that the page and the JSON cannot disagree — the rule every view
// in this console follows.
//
// Three things in here are worth knowing before reading a number off it.
//
//   * **A CLIENT IS AN AUTHENTICATED PRINCIPAL AND NOT A CONNECTION.** SCIM is
//     stateless HTTP: there is no session, no registration and nothing to be
//     "connected". So `clients.distinct` is how many different names have
//     successfully authenticated since this process started, which is the only
//     honest reading of "how many clients" here. It never goes down, because a
//     provisioning client that has stopped calling is indistinguishable from
//     one that is between calls.
//   * **A REFUSED CALLER IS NOT A CLIENT.** The gate's refusals are counted in
//     `authentication.refused` and appear in no client row, even when the
//     credential carried a name. Attributing traffic to an identity this
//     service declined to believe is the one mistake a page like this can make
//     that would matter.
//   * **THE OPERATION TABLE DOES NOT TALLY WITH `calls`, ON PURPOSE.** One
//     `POST /scim/v2/Bulk` carrying five creates is one `bulk` row AND five
//     `create` rows, because each of the five really is performed. The page
//     says so where a reader would otherwise add the column up.
// ---------------------------------------------------------------------------
function scimMonitorSnapshot() {
  log.debug("Entering scimMonitorSnapshot().");
  const detail = scimCounts.detail;

  // Every operation this server implements, with the ones nothing has called
  // at zero — SCIM_OPERATIONS is the vocabulary, exactly as it is for
  // scimSnapshot() — and then anything counted under a name that table has not
  // heard of, which is how a new operation becomes VISIBLE rather than being
  // silently dropped.
  const known = {};
  const operations = SCIM_OPERATIONS.map(function (row) {
    known[row.operation] = true;
    return scimOperationRow(row.operation, row.label, row.method, row.what,
                            detail[row.operation]);
  });
  Object.keys(detail).sort().forEach(function (name) {
    if (!known[name]) {
      operations.push(scimOperationRow(name, name, '', 'Counted under a name ' +
        'admin_stats.js\'s SCIM_OPERATIONS does not list. It is shown rather ' +
        'than dropped, because a table that quietly discarded it would make ' +
        'the column stop adding up with no way to find out why.',
        detail[name]));
    }
  });

  const resourceTypes = SCIM_RESOURCE_TYPES.map(function (name) {
    return { resourceType: name,
             count: scimCounts.byResourceType[name] || 0 };
  });
  Object.keys(scimCounts.byResourceType).sort().forEach(function (name) {
    if (SCIM_RESOURCE_TYPES.indexOf(name) < 0) {
      resourceTypes.push({ resourceType: name,
                           count: scimCounts.byResourceType[name] });
    }
  });

  const clientRows = Object.keys(scimCounts.clients).map(function (name) {
    const row = scimCounts.clients[name];
    return { principal: row.principal, kind: row.kind,
             calls: row.calls, ok: row.ok, failed: row.failed,
             schemes: Object.keys(row.schemes).sort(),
             resourceTypes: Object.keys(row.resourceTypes).sort(),
             firstAt: row.firstAt, lastAt: row.lastAt,
             lastOperation: row.lastOperation, lastStatus: row.lastStatus };
  }).sort(function (a, b) {
    // Busiest first, and most recent as the tie-break: the two orders somebody
    // reading a traffic page wants, and neither of them is alphabetical.
    return b.calls - a.calls || b.lastAt - a.lastAt;
  });

  const applications = clientRows.filter(function (row) {
    return row.kind === 'application';
  }).length;

  const out = {
    // THE HEADLINE FIGURES. `calls` is every request the SCIM implementation
    // had an opinion about, which INCLUDES the ones its own gate refused — a
    // 401 is a call this service answered, and a "requests" figure that
    // omitted them would be smaller than the access log for no stated reason.
    calls: scimCounts.total,
    ok: scimCounts.ok,
    failed: scimCounts.failed,
    // Percent, to one decimal, and NULL rather than 100 when nothing has been
    // called. A success rate of 100% on zero requests is the most misleading
    // number this page could print.
    successRate: scimCounts.total
      ? Math.round((scimCounts.ok / scimCounts.total) * 1000) / 10 : null,
    firstAt: scimCounts.firstAt,
    lastAt: scimCounts.lastAt,
    // WHEN THE COUNTING STARTED, which is when this process did. A count with
    // no epoch on it is a count somebody will read as all-time.
    since: STARTED_AT,
    latency: {
      // The SUM is kept and the mean is derived, so that a caller can compute
      // anything else it wants from the same two numbers.
      totalMs: scimCounts.ms,
      averageMs: scimCounts.total
        ? Math.round((scimCounts.ms / scimCounts.total) * 10) / 10 : null,
      maxMs: scimCounts.maxMs
    },
    // What went back over the wire, in bytes. Useful for exactly one question
    // and it is a common one: whether a client is listing the whole directory
    // on every poll.
    bytesOut: scimCounts.bytes,
    authentication: {
      // AUTHENTICATED PRINCIPALS, not connections. See the header.
      distinct: clientRows.length,
      applications: applications,
      identities: clientRows.length - applications,
      // Calls nothing authenticated: the discovery endpoints, which are open
      // unless `scim.authDiscovery` says otherwise.
      anonymous: scimCounts.anonymous,
      // Calls the gate turned away. Deliberately not attributed to a client.
      refused: scimCounts.refused,
      capped: !!scimCounts.clientsCapped,
      cap: SCIM_MAX_CLIENTS,
      byScheme: Object.assign({}, scimCounts.byAuthScheme)
    },
    operations: operations,
    resourceTypes: resourceTypes,
    byStatus: Object.assign({}, scimCounts.byStatus),
    byStatusClass: Object.assign({}, scimCounts.byStatusClass),
    byScimType: Object.assign({}, scimCounts.byScimType),
    clients: clientRows,
    recent: scimCounts.recent.slice(),
    recentCap: SCIM_RECENT,
    // The trust realm these counters are for. They are PER REALM, like the
    // directory SCIM writes into.
    realm: { id: realms.currentId(),
             name: realms.current() ? realms.current().name : '' }
  };
  log.debug("Leaving scimMonitorSnapshot(). " + out.calls + " request(s), " +
            clientRows.length + " client(s).");
  return out;
}

function scimOperationRow(operation, label, method, what, counted) {
  log.debug("Entering scimOperationRow().");
  const row = counted ||
              { calls: 0, ok: 0, failed: 0, ms: 0, maxMs: 0, bytes: 0 };
  log.debug("Leaving scimOperationRow().");
  return {
    operation: operation, label: label, method: method, what: what,
    count: row.calls, ok: row.ok, failed: row.failed,
    // NULL rather than 0 when nothing has been called, for the reason
    // `successRate` is: an average over no samples is not zero, it is absent,
    // and a table of 0.0ms rows would read as a service answering instantly.
    averageMs: row.calls ? Math.round((row.ms / row.calls) * 10) / 10 : null,
    maxMs: row.calls ? row.maxMs : null,
    bytes: row.bytes
  };
}

// FOR THE TESTS, and named so that it cannot be mistaken for an operator
// control. There is deliberately no button on the console that calls it, for
// the reason `xacml_monitor.js` gives about its own: a console that could zero
// its own monitoring would make every number on the page a number somebody
// might have reset, and the audit log — which is the durable record of what
// SCIM was asked to do — cannot be reset either.
//
// It clears THIS REALM'S counters and not every realm's, because that is what
// a `realms.obj()` store means: a test asserting a count runs inside the realm
// it made the calls in, and one that reached across realms would be able to
// pass while the isolation was broken.
function resetScimForTests() {
  log.debug("Entering resetScimForTests().");
  const fresh = freshScimCounts();
  Object.keys(fresh).forEach(function (key) {
    scimCounts[key] = fresh[key];
  });
  log.debug("Leaving resetScimForTests().");
}

// ---------------------------------------------------------------------------
// The people this service has authenticated.
//
// Every userid presented to it as part of a correct protocol interaction lands
// here: the name typed at either sign-in screen, the one on a password grant,
// the subject of a UsernameToken, the client principal in a Kerberos AS-REQ or
// an accepted AP-REQ, and the subject of an exchanged token. "Correct" is doing
// work in that sentence — a request that was refused records nothing, so this
// registry is a list of identities that got somewhere rather than of names that
// were tried. The one deliberate inclusion that is not a person is
// `client_credentials`, which is recorded and flagged as a CLIENT: it produces
// tokens with a subject and no human, and leaving it out would make the users
// page disagree with the tokens page.
//
// **Identity is keyed on the LOCAL NAME, and that is a decision with a visible
// consequence.** The same person reaches this service under four spellings —
// `alice` at the login screen, `urn:uuid:<entryUUID>` as the `sub` of every
// token, `alice` as a SAML subject, `alice@STS.MOCK` as a Kerberos principal —
// and a page showing four rows for one name would be a worse answer than one
// row, since the whole premise of this mock is that the name you type is who
// you are in every protocol at once. So the prefix and the realm are stripped
// for the key and KEPT on the record, and every form seen is listed on the
// page. What that costs: two genuinely different people called `alice` in two
// Kerberos realms are one row here. The realms column is what makes that
// visible rather than silent, and no such collapse happens across case —
// `Alice` and `alice` stay two, because nothing in this service treats them as
// one.
//
// Persisted and dropped exactly as the other stores here are — see the header.
// ---------------------------------------------------------------------------

// The subject form this service issued until 2026-09-14, still READ — a
// refresh token, a stored record or another instance's token carries it — and
// never written. It was derived from `userFor()` so that a change there could
// not leave this file stripping a prefix nothing produces; that change has now
// happened, and the form this file has to go on recognising is written down in
// `helpers.js` beside the function that stopped producing it.
//
// **A `urn:uuid:` SUBJECT IS RESOLVED RATHER THAN STRIPPED**: it is a
// directory entry's `entryUUID`, and `helpers.nameForSubject()` asks the
// directory whose it is. One that names nobody here — another instance's, a
// deleted person's — is kept whole as its own key, and `ldap_server.js`
// refuses to create an entry named after it.
const SUBJECT_PREFIX = LEGACY_SUBJECT_PREFIX;

// PER TRUST REALM, since 2026-08-25 and for the reason the counters block above
// gives: this register is the list of people a realm has SEEN, and the people a
// realm HOLDS are its own subtree of the directory. While it was one Map every
// realm's console listed every other realm's users — `/admin/users` under
// `/realm/acme` showed somebody who had only ever signed in to the default
// realm — and that realm's own directory reader then reported their entry as
// missing, because in that realm it genuinely was. Two pages of one console
// disagreeing, which is the failure this file's comments warn about twice.
//
// **THE CAP IS NOW PER REALM**, in the same one line, the way `tokens` and
// `artifacts` already were: MAX_USERS identities in each. Deliberate, and the
// opposite of the choice `ldap_server.js` makes for `ldap.maxEntries`, which
// stays process-wide — there the cap protects ONE store every realm writes
// into, and here each realm has a store of its own, so a shared cap would let a
// busy realm evict a quiet realm's people.
// local name -> the record below
const users = realms.map({ persist: 'admin_stats.users', merge: 'own' });

// Does this identity begin `<attributetype>=`? That is the one shape
// identityOf() below must not split at an '@'. Deliberately strict — a type is
// a letter followed by letters, digits and hyphens, which is what RFC 4512
// allows — so that it cannot match a name somebody typed at a sign-in screen.
const DN_SHAPED = /^[A-Za-z][A-Za-z0-9-]*=/;

// And is it a DECENTRALIZED IDENTIFIER? The same question as the one above,
// asked for the same reason and about a different shape:
// `did:web:sts.example.com%3A8443` and `did:jwk:eyJrdHkiOi…` are single opaque
// identifiers, and the ':' separators are part of the syntax rather than a name
// and a realm. Splitting one at an '@' would be splitting inside a
// method-specific id — a did:web whose domain carries a userinfo component, or
// a base64url payload that happens to decode with one — and the part before it
// names nothing.
//
// It matters here because the Decentralized Identity endpoints present
// identities of exactly this shape: an ldp_vc names its subject `did:jwk:…`,
// the OID4VP Verifier reports whatever DID presented to it, and /did/generate
// mints one. RFC 3986 says the method name is lowercase ALPHA and DIGIT; the
// `i` flag is here because this test is deciding how to file a person and not
// validating a DID.
const DID_SHAPED = /^did:[a-z0-9]+:/i;

// A presented identity, split into the part that identifies a person here and
// the parts that merely say where it was presented. Without entering/leaving
// logs: it is called for every token and artifact on every users page view, so
// a pair of lines here would be most of the log.
function identityOf(value) {
  log.debug("Entering identityOf().");
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    log.debug("Leaving identityOf().");
    return { key: '', name: '', realm: '', form: '' };
  }
  let rest = text;
  let realm = '';
  if (rest.indexOf(SUBJECT_PREFIX) === 0) rest = rest.slice(
      SUBJECT_PREFIX.length);
  if (/^urn:uuid:/i.test(rest)) {
    const named = nameForSubject(rest);
    if (!named) {
      log.debug("Leaving identityOf(). A subject naming nobody here.");
      return { key: rest, name: rest, realm: '', form: text,
               unresolved: true };
    }
    // THE NAME THE DIRECTORY HOLDS IS THE KEY, and it is not split again: it
    // is already what `autoCreateUser()` filed the person under, a DN or a
    // DID included.
    log.debug("Leaving identityOf(). A subject, resolved.");
    return { key: named, name: named, realm: '', form: text };
  }
  // A Kerberos principal. The LAST '@' splits it, because a principal name may
  // itself contain one (a UPN-shaped account name is ordinary in a Windows
  // realm) and the realm never does.
  //
  // This applies to every identity and not only to Kerberos ones, which has one
  // consequence to know about rather than discover: a person who types an
  // e-mail address at the login screen is filed under the part before the '@',
  // with the domain shown in the Realms column. On this service that is usually
  // what was meant — the same person's Kerberos principal would land in the
  // same row — and where it is not, the column says which domains have been
  // folded together.
  //
  // A DN is the exception, and it has to be: an X.509 subject or an LDAP bind
  // DN routinely carries `emailAddress=alice@example.com`, where the '@' is
  // inside an attribute VALUE and the text after it is a mail domain rather
  // than a realm. Splitting there produced a key ending
  // `...,emailAddress=alice` — a DN that names nothing, and one the directory
  // would then build an entry from. So a value that begins with an attribute
  // type and an '=' is taken whole. Nothing else here can look like that: a
  // username, a `urn:` subject and a mail address all fail the test, and a
  // Kerberos principal cannot contain '=' before its first character run ends.
  //
  // A DID is the other exception and arrives from the Decentralized Identity
  // endpoints; see DID_SHAPED above for why it is taken whole.
  const at = (DN_SHAPED.test(rest) || DID_SHAPED.test(rest)) ? -1 :
              rest.lastIndexOf('@');
  if (at > 0) {
    realm = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  log.debug("Leaving identityOf().");
  return { key: rest, name: rest, realm: realm, form: text };
}

// Just the key, for the many places that only need to ask "is this the same
// person".
function identityKeyOf(value) {
  log.debug("Entering identityKeyOf().");
  log.debug("Leaving identityKeyOf().");
  return identityOf(value).key;
}

// ---------------------------------------------------------------------------
// THE KEY OF A RECORD THAT CARRIES A NAME AND A SUBJECT (2026-09-14).
//
// A token record, a session and a pre-authorized code each keep the NAME the
// person had when it was made and — for a person — their `urn:uuid:` subject.
// Filed by the name, a rename split one person into two rows: everything made
// before it under the old name, which no longer names anybody, and everything
// after under the new one. The subject names the ENTRY, so where it resolves
// it decides; a subject naming nobody (the entry is gone) and a record with
// none fall back to the name, which is all such a record ever had.
// ---------------------------------------------------------------------------
function holderKeyOf(username, sub) {
  log.debug("Entering holderKeyOf().");
  const subject = String(sub || '');
  if (/^urn:uuid:/i.test(subject)) {
    const identity = identityOf(subject);
    if (identity.key && !identity.unresolved) {
      log.debug("Leaving holderKeyOf(). By subject.");
      return identity.key;
    }
  }
  log.debug("Leaving holderKeyOf(). By name.");
  return identityKeyOf(username || subject);
}

// ---------------------------------------------------------------------------
// A RENAMED PERSON KEEPS THEIR ROW (2026-09-14). The register is keyed by the
// name, so `ldap_server.js`'s rename moves the record from the old key to the
// new one, merged into a row the new name may already have. Called by the
// directory's modifyDN handler for a person entry, and a no-op for anything
// this register never saw.
// ---------------------------------------------------------------------------
function renameIdentity(from, to) {
  log.debug("Entering renameIdentity().");
  const oldKey = identityKeyOf(from);
  const newKey = identityKeyOf(to);
  const moved = oldKey && newKey && oldKey !== newKey ? users.get(oldKey)
                                                      : null;
  if (!moved) {
    log.debug("Leaving renameIdentity(). Nothing to move.");
    return false;
  }
  const existing = users.get(newKey);
  users.delete(oldKey);
  if (!existing) {
    moved.key = newKey;
    moved.name = newKey;
    users.set(newKey, moved);
    log.debug("Leaving renameIdentity(). Moved.");
    return true;
  }
  ['forms', 'realms', 'protocols'].forEach(function (member) {
    Object.keys(moved[member] || {}).forEach(function (name) {
      const value = moved[member][name];
      existing[member] = existing[member] || {};
      existing[member][name] = typeof value === 'number'
        ? (existing[member][name] || 0) + value
        : (existing[member][name] || value);
    });
  });
  existing.authentications = (existing.authentications || 0) +
                             (moved.authentications || 0);
  existing.firstAt = Math.min(existing.firstAt || Infinity,
                              moved.firstAt || Infinity);
  if (existing.firstAt === Infinity) {
    existing.firstAt = 0;
  }
  existing.lastAt = Math.max(existing.lastAt || 0, moved.lastAt || 0);
  existing.events = (moved.events || []).concat(existing.events || [])
    .sort(function (a, b) { return (a.at || 0) - (b.at || 0); });
  existing.eventsForgotten = (existing.eventsForgotten || 0) +
                             (moved.eventsForgotten || 0);
  while (existing.events.length > MAX_EVENTS_PER_USER) {
    existing.events.shift();
    existing.eventsForgotten++;
  }
  users.set(newKey, existing);
  log.debug("Leaving renameIdentity(). Merged.");
  return true;
}

// ---------------------------------------------------------------------------
// The one hook ldap_server.js needs, and the reason it is a hook rather than a
// require.
//
// The embedded LDAP directory grows an entry for every person who authenticates
// to this service, through any of the protocol families —
// recordAuthentication() below is the single funnel all of them already go
// through at the moment the credential is ACCEPTED, so one observer here is one
// place and not one per family.
//
// But ldap_server.js requires THIS file (it needs identityOf's normalisation,
// so that `alice`, `urn:uuid:<entryUUID>` and `alice@REALM` seed one entry and
// not three), so this file cannot require it back: a cycle in node hands back a
// half-initialised module whose exports are undefined, and the symptom arrives
// later as something that is not a function. So the direction is inverted, the
// same way helpers.js's setJwtRecorder is — this file offers a slot, and
// ldap_server.js installs itself in it at ITS require time.
//
// The observer is called for its side effect only and its return value is
// ignored: a directory must never be able to stop an authentication being
// recorded, still less to fail the authentication itself.
// ---------------------------------------------------------------------------
let userObserver = null;

function setUserObserver(fn) {
  log.debug("Entering setUserObserver().");
  userObserver = fn;
  log.debug("A user observer was installed; every identity that " +
            "authenticates will now be offered to it.");
  log.debug("Leaving setUserObserver().");
}

function userRecord(identity) {
  log.debug("Entering userRecord().");
  let record = users.get(identity.key);
  if (record) {
    log.debug("Leaving userRecord().");
    return record;
  }
  if (users.size >= MAX_USERS) {
    // Map iterates in insertion order, so the first key is the least recently
    // FIRST SEEN — not the least recently active. Chosen because it needs no
    // sweep and because a registry of 2,000 distinct usernames on a mock is
    // already a load generator rather than a person, and the page says how many
    // went.
    const oldest = users.keys().next().value;
    users.delete(oldest);
    nums.usersForgotten++;
  }
  record = {
    key: identity.key, name: identity.name,
    forms: {}, realms: {}, protocols: {},
    events: [], eventsForgotten: 0,
    authentications: 0, firstAt: 0, lastAt: 0,
    // Set by the one call site that knows it is not a person; see the note
    // above.
    isClient: false
  };
  users.set(identity.key, record);
  log.debug("Leaving userRecord().");
  return record;
}

// ---------------------------------------------------------------------------
// SOMEBODY WHO EXISTS AND HAS NOT AUTHENTICATED HERE, ADDED 2026-08-27 FOR
// PERSISTENCE, AND THE DISTINCTION IT DRAWS IS THE WHOLE POINT OF IT.
//
// Until the directory could be written down, everybody in this register got
// here by authenticating, and `/admin/users` could say "these are the people
// this service knows" and "these are the people who signed in" with one list.
// A RESTORED DIRECTORY BREAKS THAT. Its people exist — they are entries, they
// are searchable over 389, SCIM will read them, a token issued to them carries
// their attributes — and not one of them has authenticated in THIS process.
//
// The bug this fixes was found by restarting: the directory came back with
// twenty entries and `/admin/users` reported `known: 0`, because that page has
// never read the directory. It reads THIS register. So a restore has to fill
// it, and the sentence it fills it with has to be the true one:
//
//   `authentications: 0`, `restored: true`, and `authenticated` FALSE on the
//   row — which is what keeps `authenticatedHere` counting sign-ins rather
//   than people.
//
// **THE COUNTS ARE DELIBERATELY NOT RESTORED**, and that is not an omission to
// be tidied up later. How many times somebody signed in, when they first did,
// which protocols they used and every event in their drill-down are STATISTICS
// about a process, and this service's statistics have always been per process —
// `/admin/metrics` starts at zero on every start and is documented as doing so.
// What persists is what somebody typed; what resets is what this process
// counted. Restoring the counts would make `/admin/metrics` disagree with
// `/admin/users` about how many authentications this process has seen.
// ---------------------------------------------------------------------------
function noteKnownIdentity(name, how) {
  log.debug("Entering noteKnownIdentity(). how=" + how);
  const identity = identityOf(name);
  if (!identity.key) {
    log.debug("Leaving noteKnownIdentity(). There was no identity in it.");
    return null;
  }
  if (users.has(identity.key)) {
    // Already here, which means they have authenticated — during this process's
    // startup, or just now. **THIS EARLY RETURN IS LOAD-BEARING ON THE
    // AUTHENTICATION PATH**: `recordAuthentication()` builds the record before
    // it calls the user observer, and that observer reaches `createUser()`,
    // which calls this. Without the check, somebody signing in for the first
    // time would be marked as not having signed in. The live record is always
    // the better one and must never be overwritten with a blank.
    log.debug("Leaving noteKnownIdentity(). Already known.");
    return users.get(identity.key);
  }
  const record = userRecord(identity);
  // WHY this record exists without a sign-in behind it: `restored` off a
  // persistent store, `created` because somebody made the person by hand.
  // userRows() reads it and nothing else does.
  record.knownBy = how === 'restored' ? 'restored' : 'created';
  log.debug("Leaving noteKnownIdentity().");
  return record;
}

// One successful authentication. `detail` says what happened in the vocabulary
// the page prints:
//
//   presented   the identity exactly as it arrived (the key is derived from it)
//   protocol    the family, which is what the page groups by
//   method      how, within that family — "the sign-in screen (password + a
//               security key)", "AS-REQ with PA-ENC-TIMESTAMP", "UsernameToken"
//   sessionId   the browser sign-on session this created or ran on, when there is
//               one. It is what lets the drill-down put tokens under a session.
//   amr/acr, client_id, note, isClient — all optional, all shown where present.
//               amr and acr are also handed to the user observer, which is how
//               the directory comes to know that a sign-in had two factors.
//
// It returns the record so a caller can log what it now knows, and it NEVER
// throws on a missing field: a statistics call that could fail an
// authentication would be the tail wagging the dog, the same rule signJwt()'s
// recorder follows.
function recordAuthentication(detail) {
  log.debug("Entering recordAuthentication().");
  const info = detail || {};
  log.debug("Entering recordAuthentication(). protocol=" +
            (info.protocol || '?') +
            ", presented=" + (info.presented || '?'));
  const identity = identityOf(info.presented);
  if (!identity.key) {
    log.debug("Leaving recordAuthentication(). There was no identity to " +
              "record.");
    log.debug("Leaving recordAuthentication().");
    return null;
  }
  const now = Date.now();
  const record = userRecord(identity);
  record.forms[identity.form] = (record.forms[identity.form] || 0) + 1;
  if (identity.realm) record.realms[identity.realm] =
      (record.realms[identity.realm] || 0) + 1;
  if (info.isClient) record.isClient = true;
  const protocol = String(info.protocol || 'unstated');
  if (!record.protocols[protocol]) {
    record.protocols[protocol] = { protocol: protocol, count: 0, methods: {},
                                   firstAt: now, lastAt: 0 };
  }
  const family = record.protocols[protocol];
  const method = String(info.method || 'unstated');
  // The embedded LDAP directory, if it is loaded. Wrapped for the same reason
  // the JWT recorder is: a throw out here would fail the request that was
  // accepting a credential, which is the tail wagging the dog. It is given the
  // NORMALISED identity rather than `presented`, so that the three spellings of
  // one person seed one entry.
  // **THE DIRECTORY IS TOLD FIRST (2026-09-14)**, before the event and the
  // audit row below, where it used to be told last. A person's `sub` is their
  // entry's `entryUUID` now, so the entry an authentication creates has to
  // exist before anything here writes the subject down — and before
  // `authn.startSession()` asks for it. The observer still cannot fail the
  // authentication: it is caught exactly as it was.
  if (userObserver) {
    try {
      userObserver({
        // WHICH OF THE THREE THINGS HAPPENED. The observer used to be offered
        // one kind of event and needed no discriminator; it is now offered
        // three (see noteCertificateIssued() above), and an absent `event` has
        // to keep meaning this one — an older copy of ldap_server.js that does
        // not read the field must go on behaving exactly as it did.
        event: 'authentication',
        key: identity.key, name: identity.name, realm: identity.realm,
        presented: identity.form, protocol: protocol, method: method,
        isClient: record.isClient, sub: info.sub || '',
        // HOW they authenticated, in RFC 8176's vocabulary, passed through
        // untouched for the same reason `certificate` is: this file counts and
        // the directory decides what to do about it. It is what lets an entry
        // record that a second factor was used — a WebAuthn ceremony after a
        // password arrives here as ["pwd","hwk"], and the same ceremony used as
        // the PRIMARY credential arrives as ["hwk"] alone, which is one factor
        // and must not be flagged as two. Most families set neither: a Kerberos
        // AS-REQ and a UsernameToken have no amr to state, and an entry with no
        // factors recorded is the honest answer for them rather than a default.
        amr: info.amr || [], acr: info.acr || '',
        // Passed through untouched, and only `tls/tls_server.js` sets it: a
        // client certificate's identity IS a DN, so the entry the directory
        // seeds for it is not `uid=<name>` and the facts that go in it —
        // issuer, serial, validity — are on the certificate rather than in
        // anything this file holds. It rides on the observer rather than on a second hook because
        // this is already the funnel, and a second call at the certificate
        // sighting would be a second thing to keep right. Nothing here reads
        // it.
        certificate: info.certificate || null,
        // WHOSE identity this one belongs to, where the caller knows and only
        // where it does. It exists for one shape: a DECENTRALIZED IDENTIFIER,
        // which names nobody by itself, arriving from the Credential Endpoint
        // where the access token has already said who the credential is about.
        // The directory folds such a DID onto that person's entry instead of
        // creating a second one named by a digest of it.
        //
        // NORMALISED like `key` is, and through the same function: the caller
        // has whatever the token carried — `alice` or `urn:uuid:<entryUUID>`
        // — and passing it through raw would link the DID to a person filed
        // under a name nothing else here uses, which is the split this whole
        // funnel exists to prevent.
        //
        // Empty for every other family, and that is not an omission to fill in
        // later: a name-shaped identity IS the person, so a link from it to
        // itself would say nothing.
        linkedTo: info.linkedTo ? identityKeyOf(info.linkedTo) : '',
        // WHAT A FOREIGN IDENTITY PROVIDER SAID ABOUT THEM, where a federated
        // sign-in is what brought us here. Only `federation/federation_sp.js`
        // sets it, and it is passed through UNTOUCHED for exactly the reason
        // `certificate` above is: this file counts, and the directory decides
        // what to do about it. Nothing here reads it.
        //
        // It is a FIELD ON THIS PAYLOAD rather than a fourth `event` or a sixth
        // slot, and that is rule 3e's test applied rather than skipped. A new
        // event would be wrong on its own terms — this IS an authentication,
        // and filing it as something else would take a federated sign-in off
        // /admin/users, which is precisely where somebody looks for one. A new
        // slot would be an indirection bought for nothing: `certificate` and
        // `linkedTo` already established that a family with an extra fact about
        // the identity puts it here, and this is the third.
        //
        // The attributes inside it are ALREADY MAPPED to this directory's own
        // names — federation_map.js owns that vocabulary — so nothing here or
        // in ldap_server.js has to know what a `urn:oid:` name is.
        federation: info.federation || null
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-REG-0039') +
                'the user observer threw and was ignored; the authentication ' +
                'itself is unaffected: ' + e.message);
    }
  }
  // The subject, now that the entry exists: the caller's where it gave one, and
  // otherwise the directory's — '' for a client, for somebody the directory
  // declined to create, and in a process with no directory.
  const subject = info.sub ||
    (record.isClient ? '' : subjectForName(identity.key));
  family.count++;
  family.methods[method] = (family.methods[method] || 0) + 1;
  family.lastAt = now;
  record.authentications++;
  record.firstAt = record.firstAt || now;
  record.lastAt = now;
  record.events.push({
    at: now, protocol: protocol, method: method, presented: identity.form,
    realm: identity.realm || '', sub: subject,
    client_id: info.client_id || '',
    amr: (info.amr || []).join(', '), acr: info.acr || '',
    sessionId: info.sessionId || '', note: info.note || ''
  });
  if (record.events.length > MAX_EVENTS_PER_USER) {
    record.events.shift();
    record.eventsForgotten++;
  }
  log.info('admin: ' + identity.key + ' authenticated through ' + protocol +
      ' ' +
      '(' + method +
           '). ' + record.authentications + ' time(s) so far; ' + users.size +
      ' ' +
               'user(s) known.');
  // The audit log's authentication event. Here rather than at every call site
  // for the reason given at the require above, and here rather than at
  // the TOP of this function because the row must mean "a credential was
  // accepted" — an identity that could not be read is not an authentication and
  // gets no row, which is the early return above.
  //
  // audit.audit() cannot throw; see its header. Nothing about recording an
  // authentication may be able to fail one.
  audit.audit({
    action: 'authentication',
    actor: identity.key,
    actorForm: identity.form,
    protocol: protocol,
    channel: 'internal',
    target: info.sessionId || '',
    summary: identity.key + ' authenticated through ' + protocol + ' (' +
             method + ')',
    detail: {
      method: method,
      presented: identity.form,
      realm: identity.realm || '',
      sub: subject,
      client_id: info.client_id || '',
      amr: (info.amr || []).join(', '),
      acr: info.acr || '',
      sessionId: info.sessionId || '',
      isClient: !!record.isClient,
      authenticationsSoFar: record.authentications,
      note: info.note || ''
    }
  });
  // THE APPLICATION on the other side of this authentication, where the caller
  // named one. A plain require in the ordinary direction rather than a fifth
  // hook (rule 3e): applications.js registers no route and requires only
  // libraries that never require this file (helpers, config, audit, realms,
  // roles, keystore and the like), so nothing about requiring it from here
  // closes a cycle or moves a route, and a slot would cost a reader an
  // indirection for nothing.
  //
  // This covers the grants where a client_id rides on the authentication —
  // client_credentials, the password grant, token exchange. It does NOT cover
  // the authorization code flow, and it cannot: the person is authenticated in
  // authn.js, which knows nothing about OAuth by design, so the client_id is
  // never in scope at this funnel. Those protocols call applications.seen()
  // where their own identifier is accepted; the header of that function says
  // so.
  //
  // Wrapped like the observer below and for the same reason.
  try {
    applications.recordAuthentication({
      client_id: info.client_id || '',
      protocol: protocol,
      sessionId: info.sessionId || '',
      user: identity.key,
      applicationKind: info.applicationKind || '',
      note: info.isClient
        ? 'authenticated as itself (the client IS the identity)'
        : 'a credential was accepted for this application'
    });
  } catch (e) {
    log.error(errorCodes.tag('STS-REG-0041') +
              'the application registry threw and was ignored; the ' +
              'authentication itself stands: ' + e.message);
  }
  log.debug("Leaving recordAuthentication(). " + users.size +
            " user(s) known.");
  log.debug("Leaving recordAuthentication().");
  return record;
}

// ---------------------------------------------------------------------------
// Custom claims.
//
// FIVE sets since 2026-08-26, one per place a claim can be put, because the
// five are genuinely different vocabularies and a single list would have to
// guess:
//
//   access_token   members of the OAuth 2.0 access token's claim set
//   id_token       members of the OIDC ID Token's claim set
//   userinfo       members of the OIDC UserInfo response (Core 5.3.2)
//   saml2          <saml:Attribute Name="..." NameFormat="...">
//   saml11         <saml:Attribute AttributeName="..." AttributeNamespace="...">
//
// ONE STORE, THREE PAGES. The first two are configured on /admin/claims, the
// third on /admin/userinfo-claims and the last two on /admin/saml-attributes,
// and that split is a fact about the CONSOLE rather than about this file:
// setClaimSet() is the one door onto all five, so a set is changed the same way
// and audited the same way whichever page or API operation reached it.
// JWT_CLAIM_SET_IDS, USERINFO_CLAIM_SET_IDS and SAML_CLAIM_SET_IDS below are
// what each page filters by, derived from `kind`.
//
// **THE THIRD IS THE ONE THAT IS NOT ISSUED.** An access token, an ID Token and
// both assertions are minted once and are then signed documents nothing here
// can reach inside. The UserInfo response is BUILT ON EVERY CALL, so a change
// to that set is visible to a client already holding a token — which is the one
// thing on this page that does not carry the "nothing already issued changes"
// warning, and is why it is worth having separately from the ID Token that
// carries the same person's claims.
//
// They are ADDITIVE. A configured claim is added to what the protocol already
// puts in the token; it never replaces one, and the reserved list below is what
// enforces that. The reason is that every reserved name is load-bearing
// somewhere in this service — an `exp` a person could set from a web form would
// produce tokens that fail to verify with no error message pointing back here,
// and a settable `scope` would silently change what UserInfo answers.
// ---------------------------------------------------------------------------
const RESERVED_JWT_CLAIMS = [
  'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'typ', 'cnf',
  'scope', 'client_id', 'azp', 'nonce', 'at_hash', 'c_hash', 'auth_time',
  'amr', 'acr', 'username', 'authorization_details', 'act',
  // OIDC Core 5.5's claims request, as the authorization endpoint understood
  // it. It rides in the access token for the reason `authorization_details`
  // does — the UserInfo endpoint has to know what the client asked for, and a
  // signed token is the one thing that reaches it — so a settable `claims`
  // would let a web form decide what a request asked for. See oauth2.js.
  'claims'
];

// PER TRUST REALM, AND IT WAS NOT UNTIL 2026-08-28.
//
// `realms.obj(factory)` builds one of these per realm, so `CLAIM_SETS[id]` is
// the ambient realm's table and every one of the readers below is unchanged
// and now realm-correct — the shape CLAUDE.md's realm rule 2 asks for: *a
// store becomes per realm at its declaration and nowhere else*.
//
// **IT WAS A PLAIN OBJECT, AND THAT WAS A LEAK RATHER THAN A SIMPLIFICATION.**
// A custom claim added at `/realm/acme/admin/claims` was added to the ONE
// table, so it was carried by every access token this process minted — the
// DEFAULT realm's included, and every other realm's — while each realm's
// console showed it as though it were that realm's own configuration. The
// other half of the same claim set was already per realm
// (`common/claim_attributes.js` holds the DIRECTORY ATTRIBUTES a set carries),
// so one set disagreed with itself about whether it belonged to a realm.
//
// The LABEL and the KIND are constants and are duplicated into every
// partition, which costs five strings per realm and keeps the table one shape:
// splitting the metadata from the state would have been two tables to keep in
// step, and the thing that goes wrong with two tables is a set in one and not
// the other.
//
// `CLAIM_SET_IDS` below reads `Object.keys()` off this, which the proxy
// answers from the ambient realm's partition — every partition carries the
// same five ids, because they come from this one factory.
function freshClaimSets() {
  log.debug("Entering freshClaimSets().");
  log.debug("Leaving freshClaimSets().");
  return {
    access_token: { label: 'OAuth 2.0 access token', kind: 'jwt', claims: [] },
    id_token: { label: 'OIDC ID Token', kind: 'jwt', claims: [] },
    userinfo: { label: 'OIDC UserInfo response', kind: 'userinfo', claims: [] },
    saml2: { label: 'SAML 2.0 Attribute', kind: 'saml2', claims: [] },
    saml11: { label: 'SAML 1.1 Attribute (WS-Federation)', kind: 'saml11',
              claims: [] }
  };
}

const CLAIM_SETS = realms.obj(freshClaimSets,
                              { persist: 'admin_stats.claimSets' });

// The prose that used to sit on the members of the literal above, kept because
// it is the reasoning for what is in the table rather than for how it is held:
//
//   `userinfo` IS THE FIFTH SET AND IT IS NOT A JWT SET even though its
//   content is JSON and its signed form is a JWT. `kind` answers one question
//   only: WHICH CONSOLE PAGE AND WHICH /admin-api RESOURCE CARRIES THIS SET.
//   The UserInfo response has a page of its own — /admin/userinfo-claims —
//   because the thing it configures is a different artefact from either token:
//   it is fetched rather than issued, it is re-read on every call so a change
//   is visible without a new sign-in, and OIDC Core 5.4 makes a SCOPE decide
//   half of what is in it, which is true of nothing else on this list. Giving
//   it `kind: 'jwt'` would have put it on /admin/claims automatically, which
//   is exactly the accident JWT_CLAIM_SET_IDS being DERIVED is meant to make
//   impossible in the other direction.
//
//   What it DOES share with a JWT set is the RESERVED LIST — see
//   setClaimSet(), which checks `reservedNames()` rather than `kind === 'jwt'`.
//   A UserInfo response carries `sub` (5.3.2, and a client MUST check it), and
//   when the client registered a `userinfo_signed_response_alg` the whole
//   thing is a JWT carrying `iss` and `aud` as well. Every name on that list is
//   load-bearing in at least one of the two shapes, so the list applies whole.
const CLAIM_SET_IDS = Object.keys(CLAIM_SETS);

// THE FIVE SETS ARE ONE STORE AND THREE CONSOLE PAGES, and these lists are
// what says which page a set is on: /admin/claims configures the two JWT sets,
// /admin/userinfo-claims the UserInfo one and /admin/saml-attributes the two
// SAML ones (the SAML split is 2026-08-24; before that, one page carried all
// four and a reader configuring an assertion had to read past two token sets
// to reach it).
//
// DERIVED FROM `kind` rather than typed out, for the reason NAV is derived from
// SECTIONS in admin-ui/admin.js: a set added to CLAIM_SETS and forgotten in a
// hand-written list would be a set with a store, an issuance path and no page
// to configure it on, and nothing would fail. `jwt` is the OAuth/OIDC half;
// everything else is an assertion. The STORE did not split and must not — one
// object, one setClaimSet(), one audit row per change, however many pages reach
// it.
const JWT_CLAIM_SET_IDS = CLAIM_SET_IDS.filter(function (id) {
  return CLAIM_SETS[id].kind === 'jwt';
});
// THE SAML LIST IS NOW A POSITIVE TEST AND IT HAD TO BECOME ONE. It was
// `kind !== 'jwt'` while there were exactly two kinds, and the day a third
// arrived that spelling would have swept the UserInfo set onto
// /admin/saml-attributes — a set with a page, a store and an issuance path,
// configured on a page about assertions, and nothing anywhere failing. A list
// derived by exclusion is only derived from what exists at the moment it is
// written; this one is derived from what the sets ARE.
const SAML_CLAIM_SET_IDS = CLAIM_SET_IDS.filter(function (id) {
  return CLAIM_SETS[id].kind === 'saml2' || CLAIM_SETS[id].kind === 'saml11';
});
const USERINFO_CLAIM_SET_IDS = CLAIM_SET_IDS.filter(function (id) {
  return CLAIM_SETS[id].kind === 'userinfo';
});

// The default namespace a SAML 1.1 attribute gets when the admin does not name
// one. It is the claim namespace every WS-Federation relying party already
// reads, which makes an attribute configured with just a name arrive somewhere
// useful instead of in a namespace nothing looks in.
const DEFAULT_SAML11_NAMESPACE =
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

// ---------------------------------------------------------------------------
// THE OTHER HALF OF A CLAIM SET, AND WHY IT ARRIVES THROUGH A SLOT.
//
// The claim-set pages offer two things per set: the typed claims below, and a
// SELECTION of LDAP attribute types whose values are read off the person's
// entry under ou=users. The selection and the reading live in
// claim_attributes.js, which cannot be required from here — it requires
// vc_claims.js, vc_claims.js requires THIS file, and the loop would hand back a
// half-initialised module whose exports are undefined. That is the cycle rule 2
// of the architecture exists for, and the symptom arrives later as something
// that is not a function.
//
// So the direction is inverted the same way setUserObserver() above and
// helpers.js's setJwtRecorder() are: this file offers the slot and
// claim_attributes.js fills it at ITS require time. What that buys is the whole
// point of doing it this way — NO ISSUANCE SITE CHANGED. oauth2.js's two calls
// to jwtClaims() and the two assertion builders' calls to samlAttributes() are
// the lines they always were, and the attribute claims arrive through them.
// Four edited call sites would have been four that drift and a fifth added
// later that nobody remembers.
//
// It stays null in a process that never loaded that module, and every set is
// then its typed claims alone — a smaller service, not a broken one.
// ---------------------------------------------------------------------------
let attributeResolver = null;

function setAttributeResolver(hooks) {
  log.debug("Entering setAttributeResolver().");
  attributeResolver = hooks || null;
  log.debug("A claim-attribute resolver was installed; the four claim sets " +
            "can now carry LDAP attributes read from the directory.");
  log.debug("Leaving setAttributeResolver().");
}

// Both wrapped, and for the reason the user observer is wrapped: a directory
// this service consults must never be able to fail the issuance it was
// consulted during. A token missing a configured claim is a bug somebody can
// see and diagnose; a token endpoint returning 500 because an entry was
// mid-write is a bug that looks like the token endpoint.
//
// Neither has an entering/leaving pair, deliberately: each runs once per token
// inside jwtClaims() or samlAttributes(), whose own pair already brackets it,
// and claim_attributes.js logs what it did on the other side of the call. Three
// pairs around one call would be most of what the log said about issuing a
// token.
function resolvedJwtClaims(id, context) {
  if (!attributeResolver || typeof attributeResolver.jwtClaims !== 'function') {
    return {};
  }
  try {
    return attributeResolver.jwtClaims(id, context) || {};
  } catch (e) {
    log.error(errorCodes.tag('STS-REG-0042') +
              'the claim-attribute resolver threw and was ignored; the token ' +
              'is issued without its attribute claims: ' + e.message);
    return {};
  }
}

function resolvedSamlAttributes(id, context) {
  log.debug("Entering resolvedSamlAttributes().");
  if (!attributeResolver ||
      typeof attributeResolver.samlAttributes !== 'function') {
    log.debug("Leaving resolvedSamlAttributes().");
    return [];
  }
  try {
    log.debug("Leaving resolvedSamlAttributes().");
    return attributeResolver.samlAttributes(id, context) || [];
  } catch (e) {
    log.error(errorCodes.tag('STS-REG-0042') +
              'the claim-attribute resolver threw and was ignored; the ' +
              'assertion is issued without its attribute claims: ' + e.message);
    log.debug("Leaving resolvedSamlAttributes().");
    return [];
  }
}

// ---------------------------------------------------------------------------
// A SECOND SLOT, AND WHY IT IS NOT A FIFTH HOOK ADDED BY ANALOGY.
//
// CLAUDE.md rule 3e says the hooks on this file are different problems rather
// than a pattern, and that another must not be added by analogy. The test it
// gives is the one that matters — a slot is what you reach
// for when a require would CLOSE A CYCLE or MOVE A ROUTE — and this one fails
// both ways round, which is why it is here:
//
//   * group_claims.js requires THIS file (for the claim-set ids, the reserved
//     names and identityKeyOf()), so a require in the other direction closes a
//     loop and hands back a half-initialised module.
//   * what it needs is the DIRECTORY's group membership, and only
//     ldap_server.js can answer that — required late in
//     `common/protocol_stack.js` (21), so any require reaching it drags every
//     /ldap route to the front of the express router that
//     /admin/sts-metadata is built by walking.
//
// What it buys is the same thing the attribute resolver above buys: NO
// ISSUANCE SITE CHANGED. oauth2.js's calls to jwtClaims() and the two assertion
// builders' calls to samlAttributes() are the lines they always were.
//
// It stays null in a process that never loaded that module, and every set is
// then its typed claims and its directory attributes alone — a smaller service,
// not a broken one.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE ROLES CLAIM, AND WHY IT IS A PLAIN REQUIRE WHERE THE GROUPS CLAIM NEEDED
// A SLOT.
//
// CLAUDE.md rule 3e says the hooks on this file are different problems rather
// than a pattern, that another must not be added by analogy, and that the
// group resolver is the one to check a new proposal
// against — it was added only after showing a require failed BOTH ways round.
//
// THE ROLES CLAIM FAILS NEITHER, so it does not get a slot:
//
//   * `common/roles.js` is a LEAF. It requires `helpers`, `config` and the
//     error-code table and nothing else in this repository, so requiring it
//     here cannot close a cycle — which is the whole of why `group_claims.js`
//     could not be required this way round: that file requires THIS one.
//   * It registers no route, so requiring it moves nothing in the router.
//
// The DIRECTORY still arrives at that module through a slot of its own that
// `ldap_server.js` fills, for the reason it always does — only that module can
// answer what is in `ou=roles`, and it is required late in the protocol stack.
//
// So the rule is honoured by doing the ordinary thing where the ordinary thing
// works, which is what the rule actually asks for. `audit.js` is required here
// the same way and for the same reason.
const roles = require('./roles');

let groupResolver = null;

function setGroupResolver(hooks) {
  log.debug("Entering setGroupResolver().");
  groupResolver = hooks || null;
  log.debug("A group-claim resolver was installed; tokens and assertions can " +
            "now carry the directory groups their subject is a member of.");
  log.debug("Leaving setGroupResolver().");
}

// Wrapped for the reason the two above are wrapped: a directory this service
// consults must never be able to fail the issuance it was consulted during.
function resolvedGroupClaims(id, context) {
  log.debug("Entering resolvedGroupClaims().");
  if (!groupResolver || typeof groupResolver.jwtClaims !== 'function') {
    log.debug("Leaving resolvedGroupClaims().");
    return {};
  }
  try {
    log.debug("Leaving resolvedGroupClaims().");
    return groupResolver.jwtClaims(id, context) || {};
  } catch (e) {
    log.error(errorCodes.tag('STS-REG-0043') +
              'the group-claim resolver threw and was ignored; the token is ' +
              'issued without its groups claim: ' + e.message);
    log.debug("Leaving resolvedGroupClaims().");
    return {};
  }
}

// The roles claim, wrapped for the reason every other directory read during an
// issuance is wrapped: a register this service consults must never be able to
// fail the issuance it was consulted during. `roles.js` already swallows its
// own store errors; this is the second net, and it costs nothing.
//
// **WHO THE CLAIM IS ABOUT is the subject of the token**, and where there is no
// person — a client_credentials grant — that is the CLIENT, which is exactly
// the case the role register exists to be able to answer. `authenticated` is
// true here because a token is being minted: whatever door this came through
// let them through it.
function resolvedRoleClaims(context) {
  log.debug("Entering resolvedRoleClaims().");
  const ctx = context || {};
  const username = String(ctx.username || ctx.subject || '');
  try {
    log.debug("Leaving resolvedRoleClaims().");
    return roles.claimFor(
      username
        ? { kind: 'user', name: username, authenticated: true }
        : { kind: 'application',
            name: String(ctx.client_id || ''), authenticated: true }) || {};
  } catch (e) {
    log.error(errorCodes.tag('STS-REG-0044') +
              'the role register threw and was ignored; the token is issued ' +
              'without its roles claim: ' + e.message);
    log.debug("Leaving resolvedRoleClaims().");
    return {};
  }
}

// The SAML half. ONE <Attribute> with several <AttributeValue> children rather
// than one element per role — the same rule `group_claims.js` states beside its
// own emitter, and the same defect it prevents: several elements with one Name
// is a relying party reading the first and silently seeing one role where the
// person holds four.
function resolvedRoleAttributes(id, context) {
  log.debug("Entering resolvedRoleAttributes().");
  const claim = resolvedRoleClaims(context);
  const names = Object.keys(claim);
  if (!names.length) {
    log.debug("Leaving resolvedRoleAttributes().");
    return [];
  }
  log.debug("Leaving resolvedRoleAttributes().");
  return names.map(function (name) {
    const attribute = { name: name, values: claim[name] };
    if (id === 'saml11') {
      attribute.namespace = DEFAULT_SAML11_NAMESPACE;
    }
    return attribute;
  });
}

function resolvedGroupAttributes(id, context) {
  log.debug("Entering resolvedGroupAttributes().");
  if (!groupResolver || typeof groupResolver.samlAttributes !== 'function') {
    log.debug("Leaving resolvedGroupAttributes().");
    return [];
  }
  try {
    log.debug("Leaving resolvedGroupAttributes().");
    return groupResolver.samlAttributes(id, context) || [];
  } catch (e) {
    log.error(errorCodes.tag('STS-REG-0043') +
              'the group-claim resolver threw and was ignored; the assertion ' +
              'is issued without its groups claim: ' + e.message);
    log.debug("Leaving resolvedGroupAttributes().");
    return [];
  }
}

// ---------------------------------------------------------------------------
// The placeholders a value may contain.
//
// Without them every configured claim would be a constant, and a constant claim
// cannot exercise the thing people actually want to test: that a claim carrying
// the signed-in user's identity reaches the relying party. The syntax is
// ${name} and an unknown name is left ALONE rather than replaced with the empty
// string — a claim that was meant to say "${dept}" and silently became "" is a
// bug that looks like a configuration mistake, and one that still says
// "${dept}" names itself.
// ---------------------------------------------------------------------------
const PLACEHOLDERS = ['username', 'sub', 'email', 'name', 'given_name',
                      'family_name',
                      'client_id', 'audience', 'now', 'iso'];

// Without entering/leaving logs, like b64u() in helpers.js: this runs once per
// custom claim per token and would drown the log it is supposed to be readable
// in.
function expandValue(value, context) {
  const ctx = context || {};
  return String(value == null ? '' : value).replace(
      /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, function (whole, name) {
    if (Object.prototype.hasOwnProperty.call(ctx, name) &&
        ctx[name] != null) return String(ctx[name]);
    if (name === 'now') return String(Math.floor(Date.now() / 1000));
    if (name === 'iso') return new Date().toISOString();
    // Deliberately unchanged: see the comment above.
    return whole;
  });
}

// ---------------------------------------------------------------------------
// A JWT claim value is not always a string, and a web form only produces
// strings.
//
// So a value is read as JSON when it unambiguously looks like JSON — an object,
// an array, a bare true/false/null, or a number — and as a string otherwise.
// That rule has one consequence worth stating rather than discovering: a claim
// whose value is genuinely the four characters `true` cannot be configured,
// because there is no way to tell the two apart from a text field. Wrapping it
// in quotes (`"true"`) is the escape, since that parses as the JSON string.
//
// SAML attribute values are never typed: the XML content model is text.
// ---------------------------------------------------------------------------
function typedValue(text) {
  log.debug("Entering typedValue().");
  const trimmed = String(text == null ? '' : text).trim();
  if (!/^[{\[]|^(true|false|null)$|^-?\d+(\.\d+)?([eE][-+]?\d+)?$/.test(
      trimmed)) {
    log.debug("Leaving typedValue().");
    return text;
  }
  try {
    log.debug("Leaving typedValue().");
    return JSON.parse(trimmed);
  } catch (e) {
    log.debug("Caught in typedValue(): " + ((e && e.message) || e));
    // It looked like JSON and is not — a half-typed array, most likely. The raw
    // text is what the admin typed and is what the claim gets, rather than an
    // error at issuance time in a place nobody is watching.
    log.debug("A claim value looked like JSON and did not parse; it is used " +
              "as text: " + trimmed);
    log.debug("Leaving typedValue().");
    return text;
  }
  log.debug("Leaving typedValue().");
}

// ---------------------------------------------------------------------------
// The audit row for a typed-claim change, and why it is here rather than in
// admin.js's four action branches.
//
// setClaimSet() is the single funnel all four of them pass through — add,
// remove, clear and replace all end here — so one call is one place, and four
// calls at the branches would be four that drift and a fifth branch added later
// with none. The same rule the authentication funnel follows, for the same
// reason.
//
// It shares the `claims.change` action with the attribute half in
// claim_attributes.js, because they are the same fact about the same page: this
// set changed. What differs is the detail, and `how` is what says which half.
//
// NO CLAIM VALUE IS EVER RECORDED — only names. A value here is whatever
// somebody typed into a web form on a service where people paste JWTs into web
// forms, and audit.js's header states that the log carries no credential. That
// sentence stays true because every call site keeps it, not because something
// central strips it.
// ---------------------------------------------------------------------------
function recordClaimSetChange(id, set, added, removed, count, ok, errors,
                              code) {
  log.debug("Entering recordClaimSetChange(). id=" + id + ", ok=" + ok);
  // No guard: audit.audit() is wrapped over there and cannot throw. A guard
  // would suggest to the next reader that this call is allowed to fail a
  // configuration change, and it is not.
  audit.audit({
    action: 'claims.change',
    outcome: ok ? 'success' : 'refused',
    // The condition a refusal was for; '' on a change that was made.
    errorCode: ok ? '' : (code || ''),
    actor: '',
    target: id,
    channel: 'http',
    summary: ok
      ? 'The ' + set.label + ' set now carries ' + count + ' typed claim(s)' +
        (added.length ? '; added ' + added.join(', ') : '') +
        (removed.length ? '; removed ' + removed.join(', ') : '') + '.'
      : 'A change to the ' + set.label + ' set was refused: ' +
        (errors || []).join(' '),
    detail: {
      set: id,
      how: 'claims',
      added: added.join(', '),
      removed: removed.join(', '),
      claimCount: count
    }
  });
  log.debug("Leaving recordClaimSetChange().");
}

// WHICH NAMES A SET REFUSES, asked of the SET rather than tested against one
// spelling of `kind`.
//
// It was `set.kind === 'jwt'` inline until the UserInfo set arrived, and that
// was a check no reader could add a fourth kind to correctly: the answer is not
// "is this a JWT" but "does this artefact have names this service sets itself".
// A UserInfo response does — `sub` is required by OIDC Core 5.3.2 and a client
// MUST verify it matches the ID Token's, and the signed form of the same
// response is a JWT carrying `iss`, `aud` and `exp` — so it refuses the same
// list. A SAML assertion does NOT: `exp` and `scope` collide with nothing in
// an <Attribute>, and refusing them there would tell a caller their call will
// fail when it will succeed.
function reservedNames(set) {
  log.debug("Entering reservedNames().");
  log.debug("Leaving reservedNames().");
  return (set.kind === 'jwt' || set.kind === 'userinfo') ? RESERVED_JWT_CLAIMS :
          [];
}

// Validate and install a whole set at once. Returns the errors rather than
// throwing, because the caller is a form handler that has to redisplay them.
function setClaimSet(id, entries) {
  log.debug("Entering setClaimSet(). id=" + id + ", " + (entries || []).length +
      " " +
      "entry/entries.");
  const set = CLAIM_SETS[id];
  if (!set) {
    log.debug("Leaving setClaimSet(). No such claim set.");
    return errorCodes.mark({ ok: false, errors: ['There is no claim set ' +
                                                 'called "' + id + '". ' +
        'The ' +
                                 CLAIM_SET_IDS.length + ' are: ' +
                                                 CLAIM_SET_IDS.join(', ') +
                                                 '.'] },
                           'STS-REG-0034');
  }
  const errors = [];
  const cleaned = [];
  const seen = new Set();
  // The condition the FIRST refusal was for, which is the one shown first.
  let code = '';
  (entries || []).forEach(function (entry, index) {
    const name = String((entry && entry.name) || '').trim();
    if (!name) {
      errors.push('Entry ' + (index + 1) + ' has no name.');
      code = code || 'STS-REG-0036';
      return;
    }
    if (reservedNames(set).indexOf(name) >= 0) {
      errors.push('"' + name + '" is a claim this service sets itself and ' +
                  'cannot be overridden. Custom claims are added to ' +
                  'a ' + (set.kind === 'userinfo' ? 'UserInfo ' +
                      'response' : 'token') +
                  ', never substituted into it.');
      code = code || 'STS-REG-0037';
      return;
    }
    if (seen.has(name)) {
      errors.push('"' + name + '" is configured twice; the later one would ' +
                  'win silently, so both are refused.');
      code = code || 'STS-REG-0038';
      return;
    }
    seen.add(name);
    const claim = { name: name,
                    value: String((entry && entry.value) != null ? entry.value :
                                  '') };
    if (set.kind === 'saml2' &&
        entry.nameFormat) claim.nameFormat = String(entry.nameFormat);
    if (set.kind === 'saml11') claim.namespace = String(
        entry.namespace || DEFAULT_SAML11_NAMESPACE);
    cleaned.push(claim);
  });
  if (errors.length) {
    recordClaimSetChange(id, set, [], [], set.claims.length, false, errors,
                         code);
    log.debug("Leaving setClaimSet(). Refused with " + errors.length + " " +
        "error(s); nothing changed.");
    return errorCodes.mark({ ok: false, errors: errors }, code);
  }
  const beforeNames = set.claims.map(function (claim) { return claim.name; });
  const afterNames = cleaned.map(function (claim) { return claim.name; });
  const added = afterNames.filter(function (name) {
    return beforeNames.indexOf(name) < 0;
  });
  const removed = beforeNames.filter(function (name) {
    return afterNames.indexOf(name) < 0;
  });
  // **ASSIGNED THROUGH THE STORE AND NOT INTO THE OBJECT IT HANDED BACK
  // (2026-09-07).** `CLAIM_SETS` is a `realms.obj()` proxy and it sees
  // TOP-LEVEL property writes; `set` is the inner object it returned, so
  // `set.claims = cleaned` mutated it behind the proxy's back. The store was
  // never marked dirty, so the change was never journalled, never flushed and
  // never replicated: the process that took the call had it and no other did.
  // A dispatched run measured that as a claim reported added and absent from
  // the set on the next read.
  //
  // Writing the whole member back through `CLAIM_SETS[id]` is what the proxy
  // is watching for, and it is the same shape `claim_attributes.js` already
  // uses (`selections[id] = wanted`).
  set.claims = cleaned;
  CLAIM_SETS[id] = set;
  log.info('admin: the ' + set.label + ' claim set now has ' + cleaned.length +
      ' ' +
      'custom claim(s): ' +
           (afterNames.join(', ') || '(none)'));
  recordClaimSetChange(id, set, added, removed, cleaned.length, true, []);
  log.debug("Leaving setClaimSet(). Installed " + cleaned.length +
            " claim(s).");
  return { ok: true, errors: [], claims: cleaned };
}

function claimSet(id) {
  log.debug("Entering claimSet().");
  const set = CLAIM_SETS[id];
  log.debug("Leaving claimSet().");
  return set ? set.claims.slice() : [];
}

// ---------------------------------------------------------------------------
// THE FEDERATION RELEASE POLICY, APPLIED TO AN OBJECT OF CLAIMS.
//
// Lifted out of jwtClaims() on 2026-08-26 rather than written a second time,
// and the reason is the one that lifts anything out of anything here: it now
// has a SECOND caller that is not a claim set. OIDC Core section 5.5's claims
// request reaches the UserInfo endpoint without passing through jwtClaims() at
// all — it is layer 3 of that response and the configured set is layer 1 — so a
// partner with a release list naming `email` could otherwise have ASKED for
// `birthdate` and been given it, which is precisely the hole a release list
// exists to close. The filter belongs to the fact "this audience may see these
// names", not to the mechanism that produced them.
//
// It REMOVES ONLY, and it cannot reach anything not in the object it is handed:
// not `sub`, not `iss`, not `exp`, none of which is an attribute about a person
// and every one of which is what makes the artefact verifiable at all.
// `federation/CLAUDE.md` argues that boundary.
//
// NO POLICY IS NOT AN EMPTY POLICY. `releaseFilterFor()` answers null for a
// partner with no release list, and null changes nothing.
//
// It stays HERE rather than moving to a library of its own because this module
// already requires `federation.js` and three of the four modules allowed to do
// so are named in rule 3o; a fifth requirer for one filter would be a require
// added by analogy, which is exactly what that rule refuses.
// ---------------------------------------------------------------------------
function applyClaimRelease(out, context, what) {
  log.debug("Entering applyClaimRelease().");
  const release = federation.releaseFilterFor(context);
  if (!release) {
    log.debug("Leaving applyClaimRelease().");
    return out;
  }
  const before = Object.keys(out);
  before.forEach(function (name) {
    if (!release.names.has(name)) delete out[name];
  });
  const kept = Object.keys(out);
  if (kept.length !== before.length) {
    log.info('admin: the federation relationship "' + release.id +
             '" releases ' +
             kept.length + ' of ' + before.length + ' ' + (what || 'claim(s)') +
             ' to this audience; ' +
             before.filter(function (n) { return !release.names.has(n); })
                   .join(', ') +
             ' withheld. The protocol\'s own claims are untouched.');
  }
  log.debug("Leaving applyClaimRelease().");
  return out;
}

// The custom claims for a JWT, expanded against this token's context and typed.
// Returns a plain object ready to be merged into a payload — and the merge at
// the call site is written so the protocol's own claims win, which is belt as
// well as the braces of the reserved list.
function jwtClaims(id, context) {
  log.debug("Entering jwtClaims(). id=" + id);
  // The directory attributes FIRST, so that a claim somebody typed by hand wins
  // over an attribute claim of the same name. Somebody who typed `email =
  // nobody@example.org` on the same page that has `mail` ticked has said
  // something specific, and the specific thing beats the general one. The rule
  // is stated on the page and in the API's reply rather than left to be
  // discovered: the two halves are one screen apart, and a silent precedence
  // rule is the kind of thing that gets diagnosed as a bug in the directory.
  //
  // Neither half can reach a reserved name. The typed ones are refused at
  // configuration time by setClaimSet() below, and the attribute ones cannot
  // collide by construction — no OIDC claim in that catalogue is a name this
  // service sets. The merge at the CALL SITE is the third defence: oauth2.js
  // assigns the protocol's own payload over this object, so a collision that
  // somehow got past both loses there.
  //
  // THREE LAYERS, and the groups claim is the bottom one. A name somebody typed
  // wins over an attribute they ticked, and both win over the groups claim,
  // which is the only one of the three nobody named on a page — it comes from a
  // setting and a directory. So somebody who typed `groups = none` or ticked an
  // attribute called `groups` has said something specific about THIS service,
  // and the specific thing beats the general one. Written as an assignment
  // ORDER here because a JWT payload is an object; samlAttributes() below has
  // to write the same rule as a filter, for the reason stated there.
  //
  // FOUR LAYERS NOW, and the roles claim is UNDER the groups claim rather than
  // beside it. Both come from a setting and a directory rather than from
  // anything somebody named on a page, so the precedence between the two only
  // matters when they are configured to the SAME name — which is a real
  // configuration (`groups.claimName` = `roles` is one of the spellings its own
  // row recommends trying) and therefore needs an answer rather than an
  // accident. The answer is that GROUPS WINS, because that claim has been here
  // longer and a client already parsing it must not have its meaning changed by
  // a feature arriving underneath it.
  const out = resolvedRoleClaims(context);
  Object.assign(out, resolvedGroupClaims(id, context));
  Object.assign(out, resolvedJwtClaims(id, context));
  claimSet(id).forEach(function (claim) {
    out[claim.name] = typedValue(expandValue(claim.value, context));
  });
  // ---------------------------------------------------------------------
  // AND THE FOURTH LAYER, WHICH ONLY EVER REMOVES: the federation release
  // policy for this audience, if there is one.
  //
  // It is LAST because it is a filter rather than a source — the three layers
  // above decide what this service would put in a token for anybody, and this
  // decides which of them a particular federation partner is allowed to see.
  // Applied before the three would mean the precedence rules ran over a list
  // that had already been cut, so a typed claim could lose to an attribute
  // claim purely because the typed one was filtered.
  //
  // WHAT IT CANNOT TOUCH is anything not in `out`: not `sub`, not `iss`, not
  // `exp`, none of which is an attribute about a person and every one of which
  // is what makes the token verifiable at all. `federation/CLAUDE.md` argues
  // that boundary rather than leaving it to be discovered here.
  //
  // NO POLICY IS NOT AN EMPTY POLICY. `releaseFilterFor()` answers null for a
  // partner with no release list, and null changes nothing — see its header,
  // where the difference is the whole point.
  // ---------------------------------------------------------------------
  applyClaimRelease(out, context, 'custom claim(s)');
  const names = Object.keys(out);
  if (names.length) {
    log.debug("jwtClaims(): adding " + names.length + " custom claim(s) to a " +
              id + ": " + names.join(', '));
  }
  log.debug("Leaving jwtClaims(). " + names.length + " claim(s).");
  return out;
}

// The custom attributes for a SAML assertion, in the shape each builder wants:
// saml2.js takes { name, nameFormat, value } and saml11.js takes { name,
// namespace, value }. Two shapes because the two specifications genuinely
// differ — SAML 1.1 splits the claim URI into a namespace and a name — and a
// single shape here would only push that difference into both builders.
function samlAttributes(id, context) {
  log.debug("Entering samlAttributes(). id=" + id);
  const typed = claimSet(id).map(function (claim) {
    const attribute = { name: claim.name,
                        value: expandValue(claim.value, context) };
    if (id === 'saml2' &&
        claim.nameFormat) attribute.nameFormat = claim.nameFormat;
    if (id === 'saml11') attribute.namespace = claim.namespace ||
                                               DEFAULT_SAML11_NAMESPACE;
    return attribute;
  });
  // The same precedence jwtClaims() applies, but it has to be written as a
  // FILTER rather than as an assignment order: an assertion is a list of
  // <Attribute> elements and not an object, so a duplicate name would not
  // overwrite anything — it would produce two elements with one name, and a
  // relying party reading the first would silently see whichever the builder
  // happened to emit first.
  const names =
      new Set(typed.map(function (attribute) { return attribute.name; }));
  const fromDirectory = resolvedSamlAttributes(id, context).filter(
      function (attribute) {
    return !names.has(attribute.name);
  });
  // The third layer, filtered against BOTH of the two above it — the same
  // precedence jwtClaims() writes as an assignment order, and it has to be a
  // filter here for the same reason the second layer does: two <Attribute>
  // elements with one Name is not an overwrite, it is a relying party reading
  // whichever the builder happened to emit first.
  fromDirectory.forEach(function (attribute) { names.add(attribute.name); });
  const fromGroups = resolvedGroupAttributes(id, context).filter(
      function (attribute) {
    return !names.has(attribute.name);
  });
  // The FIFTH layer and the lowest, filtered against all three above it, and
  // beneath the groups claim for the reason jwtClaims() gives: the two are the
  // only layers here nobody named on a page, they can be configured to the same
  // name, and the older of the two has to keep its meaning.
  fromGroups.forEach(function (attribute) { names.add(attribute.name); });
  const fromRoles = resolvedRoleAttributes(id, context).filter(
      function (attribute) {
    return !names.has(attribute.name);
  });
  let out = fromRoles.concat(fromGroups, fromDirectory, typed);
  // The same fourth layer jwtClaims() applies, and for the same reason it is
  // last: this decides which of the attributes this service would assert to
  // ANYBODY a particular federation partner is allowed to see. It removes only,
  // and it cannot reach the NameID, the Issuer, the Conditions or the
  // signature — none of which is in this list.
  const release = federation.releaseFilterFor(context);
  if (release) {
    const before = out.length;
    out = out.filter(function (attribute) {
      return release.names.has(attribute.name);
    });
    if (out.length !== before) {
      log.info('admin: the federation relationship "' + release.id + '" ' +
          'releases ' +
               out.length + ' of ' + before + ' custom attribute(s) to this ' +
               'audience. The assertion\'s own elements are untouched.');
    }
  }
  log.debug("Leaving samlAttributes(). " + out.length + " attribute(s), " +
            fromDirectory.length + " of them from the directory and " +
            fromGroups.length + " of them the groups claim.");
  return out;
}

// ---------------------------------------------------------------------------
// Reading the state back.
// ---------------------------------------------------------------------------
// WHAT A TOKEN'S STATE IS, AGAINST THE SAME CLOCK THE ENDPOINTS USE.
//
// `oauth2.clockSkewS` is passed to jwt.verify() as `clockTolerance` at every
// place this service reads back a token it signed — introspection, UserInfo,
// the refresh grant, token exchange, the DPoP-bound access token check — so it
// is applied here too, and for a reason worth stating rather than assuming.
// Without it, a token inside the allowance is REPORTED expired here and
// ACCEPTED there. That is not a cosmetic disagreement: this page is where
// somebody goes to find out why their client was refused, and a state column
// that contradicts the endpoint sends them to debug the wrong half. The
// console does not decide what expired means — `oauth2.js` does, and this
// reads the same setting.
//
// The skew widens the window in both directions, which is what a tolerance is:
// a token is expired only once it is past `exp` PLUS the allowance, and not yet
// valid only while it is before `nbf` MINUS it.
function tokenStateOf(record, nowMs) {
  log.debug("Entering tokenStateOf().");
  if (record.revoked || (record.jti && revokedJtis.has(record.jti))) {
    log.debug("Leaving tokenStateOf().");
    return 'revoked';
  }
  const skewMs = config.value('oauth2.clockSkewS') * 1000;
  if (record.exp && record.exp * 1000 + skewMs <= nowMs) {
    log.debug("Leaving tokenStateOf().");
    return 'expired';
  }
  if (record.nbf && record.nbf * 1000 - skewMs > nowMs) {
    log.debug("Leaving tokenStateOf().");
    return 'not yet valid';
  }
  if (!record.exp) {
    log.debug("Leaving tokenStateOf().");
    return 'no expiry stated';
  }
  log.debug("Leaving tokenStateOf().");
  return 'valid';
}

function tokenList() {
  log.debug("Entering tokenList().");
  const nowMs = Date.now();
  const out = [];
  tokens.forEach(function (record) {
    out.push(Object.assign({ state: tokenStateOf(record, nowMs) }, record));
  });
  // Newest first: the token somebody is debugging is the one they just got.
  out.sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  log.debug("Leaving tokenList(). " + out.length + " token(s).");
  return out;
}

// FOUR ANSWERS FOR AN ARTIFACT SINCE 2026-09-05, AND THE FOURTH REVERSED A
// DOCUMENTED DECISION.
//
// This function had three, and said so: "nothing that is not a JWT can be
// revoked here, so 'revoked' is not among them." That was a true statement
// about the WORLD — nothing consults this service when a SAML assertion or a
// Kerberos ticket is presented, so no mark here can stop one working — and it
// was the wrong statement about this REGISTER, which is what the function
// actually reports on.
//
// **WHAT THIS SERVICE KNOWS AND WHAT A RELYING PARTY WILL HONOUR ARE TWO
// DIFFERENT CLAIMS, AND MERGING THEM COST THE ONE THAT COULD BE TRUE.** An
// identity provider that has signed somebody out has a POSITION on every
// credential it issued them, and being unable to enforce it does not make it
// unavailable to say. Three things now depend on its being said:
//
//   * A global logout can report what it invalidated rather than only what it
//     could reach, which is what makes "everything for this person is dead" a
//     checkable claim instead of a hope.
//   * CAEP can carry it. `ssf/caep.js` transmits a Security Event Token the
//     moment a session is revoked, and a receiver that acts on one has been
//     told about an assertion this service considers dead — which is the
//     channel SAML and Kerberos do not have.
//   * SAML Single Logout can carry it for the assertions that came from a
//     browser profile.
//
// **WHAT HAS NOT CHANGED IS THE ONLY THING THAT MATTERED IN THE OLD
// SENTENCE.** A revoked assertion still verifies. A revoked service ticket
// still decrypts with the key its service holds. A revoked SVID still chains
// to the bundle. This service is not consulted and cannot become consulted, so
// a holder that was not TOLD goes on using it until it expires — and that is
// why `revocationReach` rides on every row of the issued list beside
// `revocable`: the two are different questions and one field answering both is
// how this got merged in the first place.
//
// IT DELIBERATELY DOES NOT APPLY `oauth2.clockSkewS`, and that is not the
// disagreement tokenStateOf() warns about. That setting exists so this page
// agrees with the endpoint that will read the token back, and there is no such
// endpoint for a SAML assertion or a Kerberos ticket: nothing here reads one of
// those back at all, so there is nothing to agree with, and an OAuth allowance
// silently stretching a ticket's lifetime on a page would be this service
// inventing a tolerance that its KDC (which has `krb5.clockSkew`, a different
// setting with a different owner) never applied.
//
// REVOKED BEATS EXPIRED, the way it does for a token: a credential this service
// has disowned is disowned whether or not its window has also closed, and
// reporting the expiry would hide the act.
function artifactStateOf(record, nowMs) {
  log.debug("Entering artifactStateOf().");
  // THE SHARED REGISTER FIRST: the flag on the record is this process's own
  // copy of the answer and is absent on a row that came through the fan-in.
  if (artifactRevocation(record)) {
    log.debug("Leaving artifactStateOf().");
    return 'revoked';
  }
  if (!record.expiresAt) {
    log.debug("Leaving artifactStateOf().");
    return 'no expiry stated';
  }
  log.debug("Leaving artifactStateOf().");
  return record.expiresAt <= nowMs ? 'expired' : 'valid';
}

// ---------------------------------------------------------------------------
// MARKING ONE ARTIFACT — AND THE REGISTER BESIDE THE RECORD THAT THIS COMMENT
// ONCE ARGUED AGAINST.
//
// **SUPERSEDED ON 2026-09-08**: the mark is written to `revokedArtifacts` (see
// the block above that store) as well as to the record, because with request
// workers the record a console acts on is often another process's copy. What
// follows is the original argument, kept because its premise is what expired.
//
// `revoke()` above keeps a per-realm register of revoked jtis as well as the
// flag on the record, and its comment says why: RFC 7009 lets a caller revoke a token
// this registry never saw, and a jti can be revoked whose record has already
// been dropped to `MAX_TOKENS`. The set is authoritative there because
// `/oauth2/introspect` asks it about tokens this file may no longer hold.
//
// **NOTHING EVER ASKS ABOUT AN ARTIFACT.** That is the whole property this
// service cannot change, and here it makes the design simpler rather than
// harder: there is no endpoint that could be handed an AssertionID, so a set
// outliving the record would answer a question nobody can ask. The flag on the
// record is the mark, and when the record is forgotten to `MAX_ARTIFACTS` so is
// the mark — which is correct, because at that point this service has no
// position on that credential to state.
// ---------------------------------------------------------------------------
function revokeArtifact(record, via) {
  log.debug("Entering revokeArtifact(). kind=" + (record && record.kind));
  if (!record || artifactRevocation(record)) {
    log.debug("Leaving revokeArtifact(). It was already revoked or absent.");
    return false;
  }
  record.revoked = true;
  record.revokedAt = Date.now();
  record.revokedVia = via || 'unstated';
  // AND INTO THE SHARED REGISTER, which is the half that survives this row
  // belonging to another process. See revokedArtifacts above.
  if (record.key) {
    revokedArtifacts.set(record.key,
                         { at: record.revokedAt, via: record.revokedVia });
  }
  log.info('admin: the ' + record.kind + ' ' +
           (record.id || '(no identifier)') +
           ' is marked revoked (' + (via || 'unstated') + '). THE HOLDER ' +
           'CANNOT BE TOLD: nothing consults this service when one is ' +
           'presented, so this is this service\'s own position and not an ' +
           'enforcement.');
  log.debug("Leaving revokeArtifact(). Marked.");
  return true;
}

function restoreArtifact(record) {
  log.debug("Entering restoreArtifact().");
  if (!record || !artifactRevocation(record)) {
    log.debug("Leaving restoreArtifact(). It was not revoked.");
    return false;
  }
  record.revoked = false;
  record.revokedAt = 0;
  record.revokedVia = '';
  if (record.key) {
    revokedArtifacts.delete(record.key);
  }
  log.debug("Leaving restoreArtifact(). Restored.");
  return true;
}

// THE ARTIFACT BY THE HANDLE THE ISSUED LIST GAVE IT. `key` rather than `id`,
// for the reason recordArtifact() gives: a Kerberos ticket has no identifier
// anybody can quote, and a console button has to be able to name every row.
function artifactByKey(key) {
  log.debug("Entering artifactByKey(). key=" + key);
  const wanted = String(key == null ? '' : key).trim();
  if (!wanted) {
    log.debug("Leaving artifactByKey(). Nothing was asked for.");
    return null;
  }
  // ACROSS EVERY PROCESS'S ROWS. The console offers Revoke on rows it drew
  // from the merged list, so looking the handle up in this process's segment
  // alone would 404 on most of them in a pool — and the key is unique per
  // process now (ARTIFACT_TAG), so a merged search cannot match the wrong one.
  const found = allArtifacts().filter(function (record) {
    return record.key === wanted;
  });
  log.debug("Leaving artifactByKey(). " + found.length + " match(es).");
  return found.length ? found[0] : null;
}

// EVERY ARTIFACT A PREDICATE PICKS, marked in one act — the artifact half of
// revokeWhere(), and separate from it for the reason the two state functions
// are separate: one store each, and a single function walking both would have
// to be told which kind of predicate it was given.
function revokeArtifactsWhere(predicate, via) {
  log.debug("Entering revokeArtifactsWhere().");
  let count = 0;
  // ACROSS EVERY PROCESS'S ROWS, not only this one's: a bulk revocation that
  // silently skipped the artifacts another worker issued would revoke a
  // different set from the one the caller was shown. `revokeArtifact()` writes
  // the shared register, so a row from the fan-in is marked properly even
  // though the copy it is marked on is thrown away with this list.
  allArtifacts().forEach(function (record) {
    if (artifactRevocation(record)) return;
    if (!predicate(record)) return;
    if (revokeArtifact(record, via)) count += 1;
  });
  log.debug("Leaving revokeArtifactsWhere(). Marked " + count +
            " artifact(s).");
  return count;
}

// ---------------------------------------------------------------------------
// EVERY PROCESS'S ARTIFACTS, IN ONE ARRAY (2026-09-08).
//
// `artifacts` is `merge: 'own'` — an append-only ARRAY, so each process keeps
// its own segment and what another one issued arrives through the replication
// fan-in rather than in this array. `metrics()` had always added the fan-in to
// its COUNT; the two functions that BUILD the list did not, so the number and
// the table disagreed. With request workers the table was simply wrong — a
// WS-Trust assertion issued on one worker was absent from `GET
// /admin-api/tokens` answered by another, which `sts_admin_api_operations`
// reported as an issuance that had left no row.
//
// **IT IS ONE FUNCTION BECAUSE FIXING ONE READER IS HOW THIS HAPPENED.**
// `artifactList()` was fanned in first and `issuedList()` — the one that
// endpoint actually calls — was still walking the bare array, so the failure
// did not move at all. Both go through here now.
//
// THE MUTATING READERS USE IT TOO, AND THAT NEEDED A SECOND CHANGE. A record
// from the fan-in is a COPY of another process's row, so marking it revoked
// here would once have been a no-op that looked like a revocation — which is
// exactly what shipped for a few hours, and what
// `sts_admin_api_operations` caught as "it reads valid". The mark lives in the
// shared `revokedArtifacts` register now rather than only on the record, so
// marking a copy is effective and every process sees it.
// ---------------------------------------------------------------------------
function allArtifacts() {
  log.debug("Entering allArtifacts().");
  let all = artifacts.slice(0);
  const others = replication.remoteRows('admin_stats.artifacts', undefined, '');
  if (!others.length) {
    log.debug("Leaving allArtifacts().");
    // THE ORDINARY CASE — one process — and it costs one array copy.
    return all;
  }
  others.forEach(function (rows) {
    if (Array.isArray(rows)) {
      all = all.concat(rows);
    }
  });
  log.debug("Leaving allArtifacts().");
  return all;
}

function artifactList() {
  log.debug("Entering artifactList().");
  const nowMs = Date.now();
  const out = allArtifacts().map(function (one) {
    const record = withRevocation(one);
    return Object.assign({ state: artifactStateOf(record, nowMs) }, record);
  }).sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  log.debug("Leaving artifactList(). " + out.length + " artifact(s), " +
            artifacts.length + " of them this process's own.");
  return out;
}

// ---------------------------------------------------------------------------
// Everything issued, in one list.
//
// The tokens page draws JWTs, SAML assertions and Kerberos tickets in a single
// table, and the merge happens HERE rather than there: which artifact belongs
// beside a token, and what "still valid" means for each, are statements about
// the state this file holds. admin.js renders what it is handed.
//
// The families keep their own fields — a ticket has an enc-type and no scope,
// an assertion has an audience and no client_id — and gain four in common,
// which are the four every row of that table needs whatever it is:
//
//   family        'token', 'assertion' or 'ticket'
//   state         against the same clock, from the two functions above
//   expiresAtMs   MILLISECONDS. A JWT's `exp` is seconds and an artifact's
//                 `expiresAt` is already milliseconds, and a single table cannot
//                 sort or compare two units. Getting this wrong reads as every
//                 token having expired in 1970.
//   identifier    the jti or the AssertionID — and the empty string for a Kerberos
//                 ticket, which genuinely has none to quote; see the page.
//
// OID4VCI credentials are recorded here too and are deliberately NOT in this
// list: they are counted on the metrics page and listed nowhere. That is a gap
// rather than a principle — a credential is as much an issued artifact as an
// assertion is — and closing it means adding a fourth entry to ISSUED_FAMILIES
// below and a column mapping in admin.js, not anything harder.
// ---------------------------------------------------------------------------
const ISSUED_FAMILIES = [
  { family: 'token', label: 'JWTs', kinds: TOKEN_KINDS,
    what: 'every JWT this service signs: access tokens, ID Tokens, refresh ' +
          'tokens, the signed UserInfo response and the OID4VP Request ' +
          'Object' },
  { family: 'assertion', label: 'SAML assertions', kinds: ['SAML 2.0', 'SAML ' +
      '1.1'],
    what: 'issued through WS-Trust (SAML 2.0 and SAML 1.1 token types) and ' +
          'through WS-Federation sign-in' },
  { family: 'ticket', label: 'Kerberos tickets',
    kinds: ['Kerberos TGT', 'Kerberos ' +
      'service ticket'],
    what: 'issued by the KDC over raw TCP and UDP 88 and over MS-KKDCP, and ' +
          'used by the Kerberos-protected service and by SPNEGO' },
  { family: 'svid', label: 'SPIFFE SVIDs',
    kinds: ['SVID (X.509)', 'SVID (JWT)'],
    what: 'issued over the SPIFFE Workload API and by the SPIRE Server ' +
          'API\'s SVID service. NONE OF THEM IS REVOCABLE from ' +
          '/admin/tokens, unlike every kind above it: SPIFFE has no ' +
          'revocation — the answer is a short lifetime and rotation — so a ' +
          'button there would be a lie of exactly the kind this console ' +
          'avoids' }
];

// kind -> family, for the artifacts. One map built from the structure above
// rather than a prefix test on the kind string, so the filter's list of kinds
// and the list this function admits cannot drift apart: a kind the filter
// offers and this map does not know would be a dropdown entry that always
// matches nothing.
const FAMILY_BY_ARTIFACT_KIND = {};
ISSUED_FAMILIES.forEach(function (entry) {
  if (entry.family === 'token') return;
  entry.kinds.forEach(function (kind) {
    FAMILY_BY_ARTIFACT_KIND[kind] = entry.family;
  });
});

function issuedList() {
  log.debug("Entering issuedList().");
  const nowMs = Date.now();
  const out = [];
  tokens.forEach(function (record) {
    out.push(Object.assign({}, record, {
      family: 'token',
      state: tokenStateOf(record, nowMs),
      expiresAtMs: record.exp ? record.exp * 1000 : 0,
      identifier: record.jti || '',
      // See the artifact branch below for what this answers and why it is not
      // `revocable`. A JWT revoked here is refused at /oauth2/introspect,
      // UserInfo and the refresh grant, which is a client-visible fact rather
      // than a note in this register.
      revocationReach: 'protocol'
    }));
  });
  allArtifacts().forEach(function (one) {
    const record = withRevocation(one);
    const family = FAMILY_BY_ARTIFACT_KIND[record.kind];
    // A credential, or a kind added to the registry and not to the structure
    // above. Skipped rather than shown under a family nothing can filter by.
    if (!family) return;
    out.push(Object.assign({}, record, {
      family: family,
      state: artifactStateOf(record, nowMs),
      expiresAtMs: record.expiresAt || 0,
      identifier: record.id || '',
      // Stated rather than left undefined, for the reason `revocable` below is:
      // every reader of this list asks the same question of every row, and a
      // member that is absent on three families out of four is a member every
      // one of them has to test for existence before testing for value. No
      // artifact belongs to a token response — OAuth is the only family here
      // that issues several credentials in one act — so the honest answer is
      // the empty one, and issuedSets() reads it as "a set of your own".
      setId: '',
      // REVOCABLE SINCE 2026-09-05, AND IT WAS `false` HERE UNTIL THAT DAY.
      // See artifactStateOf() for the argument. What decides it is whether this
      // service can HOLD A POSITION on the credential, which it can for
      // anything it issued and still remembers — and `revocationReach` below
      // carries the other half of the question, which used to be folded into
      // this one field and is the reason the two got confused.
      //
      // A row whose record has been dropped to `MAX_ARTIFACTS` is not here to
      // be revoked, which is the honest end of it: at that point this service
      // has no position on that credential to state.
      revocable: true,
      // WHAT A REVOCATION HERE ACTUALLY REACHES, and it is the field to read
      // before writing any sentence on any page about what a button does.
      //
      //   'protocol'    the revocation is HONOURED somewhere a client will
      //                 meet it: introspection reports the token inactive,
      //                 UserInfo refuses it, the refresh grant fails. Every
      //                 JWT is this.
      //   'record-only' this service's own position, and NOTHING ELSE. The
      //                 credential still verifies, still decrypts, still
      //                 chains — because nothing consults this service when it
      //                 is presented and nothing can be made to. Every
      //                 assertion, ticket and SVID is this.
      //
      // The second is not a lesser version of the first and must never be
      // drawn as one. It is what a global logout can SAY, what CAEP can
      // TRANSMIT, and what SAML Single Logout can carry for the assertions
      // that came from a browser profile — and for a WS-Trust assertion it is
      // the whole of what exists, because that protocol has no logout at all.
      revocationReach: 'record-only'
    }));
  });
  // THE ORDER THE ROWS WERE RECORDED IN, before the sort below destroys it, and
  // it is not the same thing as `issuedAt`. Both stores keep insertion order —
  // a Map iterates in it and the artifact array is pushed to — but `issuedAt`
  // is a millisecond, and the three tokens of one response are minted well
  // inside one. So sorting by the timestamp alone leaves the members of a set
  // in whatever order the sort happened to be stable in, and the set page would
  // print the refresh token above the access token that was issued before it.
  // issuedSets() sorts its members by this and gets issuance order exactly.
  out.forEach(function (row, index) { row.order = index; });
  // Newest first, across all three families together — the point of one table
  // is that a sign-in which produced an ID Token and a SAML assertion shows
  // both, next to each other, in the order they happened. Ties broken by the
  // ordinal above rather than left to the sort's stability, so two credentials
  // minted in the same millisecond are ALWAYS the later one first.
  out.sort(function (a, b) {
    return (b.issuedAt - a.issuedAt) || (b.order - a.order);
  });
  log.debug("Leaving issuedList(). " + out.length + " row(s) across " +
            ISSUED_FAMILIES.length + " family/families.");
  return out;
}

// ---------------------------------------------------------------------------
// THE SAME LIST, GROUPED INTO WHAT WAS ISSUED TOGETHER.
//
// **This is what /admin/tokens draws, and the reason it is a different list
// from the one above.** A person redeeming an authorization code gets back an
// access token, an ID Token and a refresh token in ONE reply, and a table that
// prints them as three rows makes the reader reassemble by eye the one thing
// the protocol handed over whole. OAuth 2.0 and OIDC are the ONLY families here
// that do that: a SAML assertion, a Kerberos ticket and an SVID are each one
// credential from one act, so each is a set of one and says so.
//
// A SET IS ONE RESPONSE AND NOT ONE GRANT. Refreshing produces a new set beside
// the old one rather than a fourth member of it — every credential in a set
// shares an issued instant and a grant, and a set that grew over an afternoon
// could say neither. What joins the generations of a grant is the refresh
// lineage, which is a different relation and is drawn as one at
// /admin/tokens/credential.
//
// THE SET'S OWN FIELDS ARE DERIVED AND THREE OF THEM ARE NOT WHAT A READER
// FIRST EXPECTS:
//
//   state          the state every member shares, or 'mixed'. A set whose
//                  access token has expired while its refresh token is still
//                  valid is neither expired nor valid, and reporting either
//                  would be this list deciding which member matters. `states`
//                  carries the breakdown, and the STATE FILTER matches a set
//                  when ANY member holds the state asked for — so filtering for
//                  'revoked' still finds the set a revoked access token is in,
//                  which is the row somebody looking for it wants.
//   expiresAtMs    the EARLIEST member's, which is when the set starts to come
//                  apart rather than when it is finished. `lastExpiresAtMs` is
//                  the other end. One column cannot carry both and the earlier
//                  one is the one somebody debugging a refused call needs.
//   issuedAt       the earliest member's, which is when the response was
//                  produced. They are within a millisecond of each other in
//                  practice; taking the earliest rather than the latest means
//                  the set sorts where its first credential did.
//
// `setKey` is what a page addresses a set BY, and it is not `setId`: a row with
// no set id is a set of its own and needs a handle too, so it gets `one:` and
// this service's own key for that row (a jti, `no-jti-N`,
// `artifact-<process tag>-N`). Every row therefore has one, including a
// Kerberos ticket, which is the family with no identifier of its own to quote.
// ---------------------------------------------------------------------------
function issuedSets() {
  log.debug("Entering issuedSets().");
  const rows = issuedList();
  const byKey = new Map();
  const order = [];
  rows.forEach(function (row) {
    const key = row.setId ? 'set:' + row.setId :
                'one:' + (row.key || row.identifier || '');
    let set = byKey.get(key);
    if (!set) {
      set = { setKey: key, setId: row.setId || '', members: [] };
      byKey.set(key, set);
      order.push(set);
    }
    set.members.push(row);
  });
  const out = order.map(function (set) {
    // Issuance order within the set, which is the order the token endpoint
    // minted them in: access token, then refresh token, then ID Token. See the
    // ordinal in issuedList() for why the timestamp cannot do this.
    const members = set.members.slice()
                               .sort(function (a, b) {
                                 return a.order - b.order;
                               });
    const first = members[0];
    const states = {};
    let shared = '';
    let mixed = false;
    let earliestIssued = 0;
    let earliestExpiry = 0;
    let latestExpiry = 0;
    let revocable = 0;
    let revoked = 0;
    members.forEach(function (row) {
      states[row.state] = (states[row.state] || 0) + 1;
      if (!shared) {
        shared = row.state;
      } else if (shared !== row.state) {
        mixed = true;
      }
      if (!earliestIssued ||
          row.issuedAt < earliestIssued) earliestIssued = row.issuedAt;
      // A member with NO expiry stated is skipped on both ends rather than
      // counted as zero: zero would make every set containing one look as
      // though it had already expired in 1970, which is the units bug
      // issuedList()'s `expiresAtMs` comment warns about, arrived at from the
      // other direction.
      if (row.expiresAtMs) {
        if (!earliestExpiry ||
            row.expiresAtMs < earliestExpiry) earliestExpiry = row.expiresAtMs;
        if (row.expiresAtMs > latestExpiry) latestExpiry = row.expiresAtMs;
      }
      if (row.revocable) revocable += 1;
      if (row.state === 'revoked') revoked += 1;
    });
    // The kinds IN ISSUANCE ORDER and de-duplicated. A set never holds two of a
    // kind today — one response carries at most one of each — but a duplicate
    // would print as `access_token + access_token` rather than being noticed,
    // and the check costs one lookup.
    const kinds = [];
    members.forEach(function (row) {
      if (kinds.indexOf(row.kind) < 0) kinds.push(row.kind);
    });
    return {
      setKey: set.setKey,
      setId: set.setId,
      // Whether this is a GROUP or a single credential standing in for one.
      // The page reads it to decide whether to say "3 credentials" or to draw
      // the row as the one thing it is, and a test reads it to assert that
      // nothing outside OAuth ever groups.
      grouped: members.length > 1,
      size: members.length,
      kinds: kinds,
      // The families present. One in every case that can occur — a set id is
      // minted by the OAuth issuance sites and nothing else records one — but
      // derived rather than assumed, so a family that starts grouping later
      // does not silently report itself as `token`.
      families: members.reduce(function (list, row) {
        if (list.indexOf(row.family) < 0) list.push(row.family);
        return list;
      }, []),
      family: first.family,
      state: mixed ? 'mixed' : shared,
      states: states,
      issuedAt: earliestIssued,
      expiresAtMs: earliestExpiry,
      lastExpiresAtMs: latestExpiry,
      // Taken from the FIRST member rather than merged, because every member of
      // a set was issued by one act to one party for one person: the access
      // token and the ID Token of one response disagree about `aud` by design
      // and about nothing else. The ID Token's audience is the client and the
      // access token's is the resource server, which is why the party column
      // reads `client_id` — see partyCell() — and why merging audiences here
      // would produce a party that was never named.
      username: first.username || '',
      sub: first.sub || '',
      client_id: first.client_id || '',
      audience: first.audience || '',
      scope: first.scope || '',
      sessionId: first.sessionId || '',
      sessionAuthenticated: first.sessionAuthenticated !== false,
      grant: first.grant || '',
      revocableCount: revocable,
      revokedCount: revoked,
      members: members
    };
  });
  log.debug("Leaving issuedSets(). " + out.length + " set(s) over " +
      rows.length + " " +
      "row(s).");
  return out;
}

// ONE SET, BY THE KEY THE LIST ABOVE GAVE IT. Null for a key nothing holds,
// which is the ORDINARY answer for a set old enough to have been dropped to
// `MAX_TOKENS` or `MAX_ARTIFACTS` — the caller says so rather than treating it
// as a mistake, exactly as issuedById() does.
function issuedSetByKey(setKey) {
  log.debug("Entering issuedSetByKey(). setKey=" + setKey);
  const wanted = String(setKey == null ? '' : setKey).trim();
  if (!wanted) {
    log.debug("Leaving issuedSetByKey(). Nothing was asked for.");
    return null;
  }
  const found =
      issuedSets().filter(function (set) { return set.setKey === wanted; });
  log.debug("Leaving issuedSetByKey(). " + found.length + " set(s) hold it.");
  return found.length ? found[0] : null;
}

// ---------------------------------------------------------------------------
// ONE ROW OF THAT LIST, BY THE IDENTIFIER THE PROTOCOL GAVE IT.
//
// The lookup `credential_graph.js` needs, and the reason it is here rather than
// a `filter()` over there: `issuedList()`'s row shape is this file's — the
// merged `family`, `identifier` and `expiresAtMs` members exist because the
// tokens page needed one table over four registers — and a caller doing its own
// walk would be a second place that decides a token's identifier is its `jti`
// and an artifact's is its `id`.
//
// It walks rather than indexing, and that is a deliberate non-optimisation:
// both stores are capped (`MAX_TOKENS`, `MAX_ARTIFACTS`) and an index would be
// a second copy of a key that is already the only thing joining these records
// to the delegation register. Null for an identifier neither store holds, which
// is the ORDINARY answer for anything old enough to have been dropped to a cap
// — the caller says so rather than treating it as a mistake.
// ---------------------------------------------------------------------------
function issuedById(identifier) {
  log.debug("Entering issuedById(). identifier=" + identifier);
  const wanted = String(identifier == null ? '' : identifier).trim();
  if (!wanted) {
    log.debug("Leaving issuedById(). Nothing was asked for.");
    return null;
  }
  const found = issuedList().filter(function (row) {
    return String(row.identifier || '') === wanted;
  });
  log.debug("Leaving issuedById(). " + found.length + " row(s) hold it.");
  return found.length ? found[0] : null;
}

// ---------------------------------------------------------------------------
// Reading the users back.
//
// The list is built from THREE sources and not one, which is the part worth
// understanding before changing it:
//
//   1. the authentication registry above — everyone who presented a credential;
//   2. every token's `sub`/`username`;
//   3. every artifact's subject.
//
// Sources 2 and 3 exist because an identity can be issued something here
// without ever having authenticated here: a token exchange presents somebody
// else's token, WS-Trust's OnBehalfOf names a delegated subject, and a Kerberos
// S4U2Self ticket is for a user who has not been near this KDC. Building the
// page from source 1 alone would list a subject in the tokens table and deny
// they exist on the users page, which is the kind of disagreement between two
// pages of one console that costs an afternoon. Such a row is marked
// `authenticated: false` and the page says what that means rather than leaving
// the reader to assume the recording is broken.
// ---------------------------------------------------------------------------

// A {name: count} object as the sorted array the page wants, commonest first.
function countedRows(counts, nameKey) {
  log.debug("Entering countedRows().");
  log.debug("Leaving countedRows().");
  return Object.keys(counts || {}).map(function (name) {
    const row = { count: counts[name] };
    row[nameKey] = name;
    return row;
  }).sort(function (a, b) { return b.count - a.count; });
}

// The empty shell every row starts as, whether it came from a real
// authentication or only from something issued. One function so that a row from
// source 2 has exactly the fields a row from source 1 has — a page that reads
// `row.protocols.length` must not have to ask where the row came from first.
function blankUserRow(identity) {
  log.debug("Entering blankUserRow().");
  log.debug("Leaving blankUserRow().");
  return {
    key: identity.key, name: identity.name, forms: {}, realms: {},
    protocols: {},
    authentications: 0, firstAt: 0, lastAt: 0, isClient: false,
    authenticated: false, events: [], eventsForgotten: 0,
    tokens: { issued: 0, valid: 0, expired: 0, revoked: 0, other: 0 },
    artifactKinds: {}, artifacts: 0, lastActivityAt: 0
  };
}

function userRows() {
  log.debug("Entering userRows().");
  const nowMs = Date.now();
  const rows = new Map();
  const rowFor = function (value) {
    log.debug("Entering rowFor().");
    const identity = identityOf(value);
    if (!identity.key) {
      log.debug("Leaving rowFor().");
      return null;
    }
    if (!rows.has(identity.key)) rows.set(identity.key, blankUserRow(identity));
    const row = rows.get(identity.key);
    row.forms[identity.form] = (row.forms[identity.form] || 0) + 1;
    if (identity.realm) row.realms[identity.realm] =
        (row.realms[identity.realm] || 0) + 1;
    log.debug("Leaving rowFor().");
    return row;
  };

  users.forEach(function (record) {
    const row = blankUserRow(record);
    // The registry's own counts win over anything reconstructed below: they
    // count authentications, and the forms map there was built one presentation
    // at a time.
    row.forms = Object.assign({}, record.forms);
    row.realms = Object.assign({}, record.realms);
    row.protocols = record.protocols;
    row.authentications = record.authentications;
    row.firstAt = record.firstAt;
    row.lastAt = record.lastAt;
    row.isClient = record.isClient;
    // FALSE for a record that got here WITHOUT a sign-in — restored from a
    // persistent store, or created by hand — and true for every record that
    // got here the way records always got here. See noteKnownIdentity() above:
    // such a person EXISTS and has not signed in, and one flag saying both
    // would make `authenticatedHere` count people rather than sign-ins.
    row.authenticated = !record.knownBy;
    row.knownBy = record.knownBy || 'authentication';
    // A copy: the page and the JSON reply both read this, and handing out the
    // live array would let a caller's sort or splice edit the registry.
    row.events = record.events.slice();
    row.eventsForgotten = record.eventsForgotten;
    row.lastActivityAt = record.lastAt;
    rows.set(record.key, row);
  });

  tokens.forEach(function (record) {
    // `username` first: it is the local name, and falling back to `sub` costs
    // nothing because identityOf() strips the prefix off it anyway.
    const row = rowFor(holderKeyOf(record.username, record.sub));
    if (!row) return;
    // Both spellings are recorded as forms when they differ, so the page can
    // show that this row's `sub` is what the tokens say.
    if (record.sub && record.username) {
      row.forms[record.sub] = (row.forms[record.sub] || 0) + 1;
    }
    row.tokens.issued++;
    const state = tokenStateOf(record, nowMs);
    if (state === 'valid') row.tokens.valid++;
    else if (state === 'expired') row.tokens.expired++;
    else if (state === 'revoked') row.tokens.revoked++;
    else row.tokens.other++;
    if (record.issuedAt > row.lastActivityAt) row.lastActivityAt =
        record.issuedAt;
  });

  // EVERY PROCESS'S — see allArtifacts(). A per-user count built from this
  // process's segment alone under-reports every identity another worker served.
  allArtifacts().forEach(function (record) {
    const row = rowFor(record.subject);
    if (!row) return;
    row.artifacts++;
    row.artifactKinds[record.kind] = (row.artifactKinds[record.kind] || 0) + 1;
    if (record.issuedAt > row.lastActivityAt) row.lastActivityAt =
        record.issuedAt;
  });

  const out = Array.from(rows.values()).map(function (row) {
    return Object.assign({}, row, {
      forms: countedRows(row.forms, 'form'),
      realms: countedRows(row.realms, 'realm'),
      artifactKinds: countedRows(row.artifactKinds, 'kind'),
      protocols: Object.keys(row.protocols).map(function (name) {
        const family = row.protocols[name];
        // `firstAt` as well as `lastAt` since 2026-08-26: `user_graph.js` puts
        // the families of one person in the order they STARTED, so that the
        // sign-in everything else rests on is read before the exchanges that
        // quote it, and `lastAt` orders them by whichever was busiest most
        // recently instead.
        return { protocol: family.protocol, count: family.count,
                 firstAt: family.firstAt, lastAt: family.lastAt,
                 methods: countedRows(family.methods, 'method') };
      }).sort(function (a, b) { return b.lastAt - a.lastAt; })
    });
  });
  // Most recently active first, which on a mock is nearly always the person
  // being debugged right now.
  out.sort(function (a, b) { return b.lastActivityAt - a.lastActivityAt; });
  log.debug("Leaving userRows(). " + out.length + " user(s), " +
            out.filter(function (r) { return r.authenticated; }).length + " " +
                "authenticated here.");
  return out;
}

// One user, with everything issued to them. The tokens keep their session id,
// which is what the drill-down groups by; the artifacts keep their own fields,
// because a ticket has an enc-type and an assertion has an audience and
// flattening the two would lose the half of each that is worth reading.
function userDetail(key) {
  log.debug("Entering userDetail(). key=" + key);
  const wanted = String(key || '');
  const row = userRows().filter(function (r) { return r.key === wanted; })[0] ||
              null;
  if (!row) {
    log.debug("Leaving userDetail(). No such user.");
    return null;
  }
  const nowMs = Date.now();
  const theirTokens = [];
  tokens.forEach(function (record) {
    if (holderKeyOf(record.username, record.sub) !== wanted) return;
    theirTokens.push(Object.assign({ state: tokenStateOf(record, nowMs) },
                                   record));
  });
  theirTokens.sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  // ACROSS EVERY PROCESS'S ROWS — see allArtifacts(). This was the LAST reader
  // still walking the bare array, and it was the one that mattered most: this
  // is what `logout.js`'s `issued` family collects, so a credential another
  // worker issued was not among the things a global sign-out could end. The
  // symptom was one row that would not go away — `sts_global_logout` reported
  // "7 were live and 1 still are", the survivor a Kerberos ticket-granting
  // ticket whose artifact stayed `valid` because nothing had offered it for
  // revocation. The SAML assertions beside it revoked correctly, which is what
  // made it look like a Kerberos problem for a day.
  const theirArtifacts = allArtifacts().filter(function (record) {
    return identityKeyOf(record.subject) === wanted;
  }).map(function (one) {
    const record = withRevocation(one);
    return Object.assign({ state: artifactStateOf(record, nowMs) }, record);
  }).sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  log.debug("Leaving userDetail(). " + theirTokens.length + " token(s), " +
            theirArtifacts.length + " artifact(s).");
  return { user: row, tokens: theirTokens, artifacts: theirArtifacts };
}

// The session a token was issued under, by jti. The refresh grant is what needs
// it: a refreshed token belongs to the same sign-on session as the refresh
// token that bought it, and that link exists nowhere on the wire — the refresh
// token carries no session identifier, so without this the second generation of
// every token would appear under "no session" and a session's token list would
// quietly stop growing.
function sessionIdOfJti(jti) {
  log.debug("Entering sessionIdOfJti().");
  const record = jti ? tokens.get(jti) : null;
  log.debug("Leaving sessionIdOfJti().");
  return (record && record.sessionId) || '';
}

// AND WHETHER THAT SESSION WAS AUTHENTICATED, by the same jti and for the same
// reason: a refresh is a back-channel request with no cookie, so the only
// record of who was behind the original sign-in is this one. A jti this
// registry has never seen answers `true`, which is the same "an absent answer
// means what it always meant" rule the field itself is written under — and the
// permissive answer is the right default here because the alternative would
// refuse a client holding a perfectly good refresh token from a process that
// restarted.
function sessionAuthenticatedOfJti(jti) {
  log.debug("Entering sessionAuthenticatedOfJti().");
  const record = jti ? tokens.get(jti) : null;
  log.debug("Leaving sessionAuthenticatedOfJti().");
  return !record || record.sessionAuthenticated !== false;
}

// Revoke every token matching a predicate, and say how many. Used by the
// console's "revoke every access token" and "revoke everything for this
// subject" buttons, which exist because revoking one jti at a time is not how
// anybody tests a resource server's behaviour when its tokens go bad.
function revokeWhere(predicate, via) {
  log.debug("Entering revokeWhere().");
  let count = 0;
  tokens.forEach(function (record) {
    if (!record.revocable || record.revoked) return;
    if (!predicate(record)) return;
    if (revoke(record.jti, via)) count++;
  });
  log.debug("Leaving revokeWhere(). Revoked " + count + " token(s).");
  return count;
}

// ---------------------------------------------------------------------------
// Sessions derived from what was issued.
//
// This is a DEFINITION, not a measurement, so it is written down: a subject has
// an artifact-derived session in a protocol family when that family has issued
// it at least one artifact that is still valid — unexpired, and unrevoked where
// revocation exists. It is not the same thing as the browser sign-on session
// the console reports beside it, and the two disagree in both directions on
// purpose:
//
//   * a client_credentials access token has no human and no browser behind it,
//     so it is a session here and nothing at all there;
//   * a signed-in browser that has been issued nothing yet is a session there
//     and nothing here;
//   * a Kerberos client never touches the browser session at all.
//
// A TGT is counted as the Kerberos session and a service ticket is not, because
// that is what they are: the TGT is the credential the session consists of.
// ---------------------------------------------------------------------------
const OAUTH_SESSION_KINDS = ['access_token', 'id_token', 'refresh_token'];

function sessionsFromArtifacts() {
  log.debug("Entering sessionsFromArtifacts().");
  const nowMs = Date.now();
  const families = new Map();
  const add = function (family, subject) {
    log.debug("Entering add().");
    if (!subject) {
      log.debug("Leaving add().");
      return;
    }
    if (!families.has(family)) families.set(family, new Set());
    families.get(family).add(subject);
    log.debug("Leaving add().");
  };
  tokens.forEach(function (record) {
    if (OAUTH_SESSION_KINDS.indexOf(record.kind) < 0) return;
    if (tokenStateOf(record, nowMs) !== 'valid') return;
    add('OAuth 2.0 / OIDC', record.sub || record.username);
  });
  allArtifacts().forEach(function (record) {
    if (record.expiresAt && record.expiresAt <= nowMs) return;
    // A DISOWNED CREDENTIAL IS NOT A LIVE SESSION, which is the claim
    // `logout.js` already makes about the same rows on `/admin/sessions`. It
    // could not be made here until the mark moved into a register every
    // process can see.
    if (artifactRevocation(record)) return;
    if (record.kind === 'SAML 2.0') add('SAML 2.0 (WS-Trust, WS-Federation)',
                                        record.subject);
    else if (record.kind === 'SAML 1.1') add('SAML 1.1 (WS-Federation)',
                                             record.subject);
    else if (record.kind === 'Kerberos TGT') add('Kerberos (a TGT is the ' +
                                                 'session)', record.subject);
    else if (record.kind.indexOf('Credential (') === 0) add('OID4VCI ' +
        'credentials', record.subject);
  });
  const everyone = new Set();
  const rows = [];
  families.forEach(function (subjects, family) {
    subjects.forEach(function (s) { everyone.add(s); });
    rows.push({ family: family, subjects: subjects.size,
                who: Array.from(subjects).sort() });
  });
  rows.sort(function (a, b) { return b.subjects - a.subjects; });
  log.debug("Leaving sessionsFromArtifacts(). " + rows.length + " " +
      "family/families, " +
            everyone.size + " distinct subject(s).");
  return { families: rows, distinctSubjects: everyone.size };
}

// ---------------------------------------------------------------------------
// The whole picture, computed on demand.
//
// On demand rather than kept up to date incrementally, and that is the
// important choice: "valid" and "expired" are functions of the clock, so a
// counter incremented at issuance would be wrong a second later and would need
// a sweeper to stay right. Counting 5,000 records per page view costs nothing.
// ---------------------------------------------------------------------------
function snapshot() {
  log.debug("Entering snapshot().");
  const nowMs = Date.now();

  const byKind = new Map();
  tokens.forEach(function (record) {
    if (!byKind.has(record.kind)) {
      byKind.set(record.kind,
                 { kind: record.kind, issued: 0, valid: 0, expired: 0,
                                revoked: 0, notYetValid: 0, noExpiry: 0, bound:
                                                                           0 });
    }
    const row = byKind.get(record.kind);
    row.issued++;
    if (record.jkt) row.bound++;
    const state = tokenStateOf(record, nowMs);
    if (state === 'valid') row.valid++;
    else if (state === 'expired') row.expired++;
    else if (state === 'revoked') row.revoked++;
    else if (state === 'not yet valid') row.notYetValid++;
    else row.noExpiry++;
  });

  const artifactKinds = new Map();
  // EVERY PROCESS'S, because `metrics()` reports this table beside a `held`
  // count that has been fanned in since the day it was written — so walking
  // the bare array here made the total and its breakdown disagree.
  allArtifacts().forEach(function (record) {
    if (!artifactKinds.has(record.kind)) {
      artifactKinds.set(record.kind,
                        { kind: record.kind, issued: 0, valid: 0, expired: 0,
                          noExpiry: 0 });
    }
    const row = artifactKinds.get(record.kind);
    row.issued++;
    if (!record.expiresAt) row.noExpiry++;
    else if (record.expiresAt > nowMs) row.valid++;
    else row.expired++;
  });

  const knownUsers = userRows();

  const callRows = Array.from(calls.values())
                        .sort(function (a, b) { return b.count - a.count; });
  const statusTotals = {};
  callRows.forEach(function (row) {
    Object.keys(row.statuses).forEach(function (bucket) {
      statusTotals[bucket] = (statusTotals[bucket] || 0) + row.statuses[bucket];
    });
  });

  // -------------------------------------------------------------------------
  // AND WHAT THE OTHER PROCESSES COUNTED.
  //
  // These stores are declared `merge: 'own'` — each process writes only its own
  // tally and never adopts another's into memory — because `nums.callTotal++`
  // is an INCREMENT and not an assignment, so a last-writer-wins row would
  // report roughly one process's traffic while looking perfectly plausible.
  // That is the worst kind of wrong number: one nobody has any reason to
  // doubt.
  //
  // So the fan-in is HERE, in the one function that reports any of it, and it
  // is a plain sum. With one process `remoteRows()` answers an empty array and
  // every number below is exactly what it has always been.
  // -------------------------------------------------------------------------
  const theirNums = replication.remoteRows('admin_stats.nums', undefined, '');
  function alsoElsewhere(field) {
    log.debug("Entering alsoElsewhere().");
    log.debug("Leaving alsoElsewhere().");
    return theirNums.reduce(function (n, theirs) {
      return n + Number((theirs || {})[field] || 0);
    }, 0);
  }
  // THE PATHS ANOTHER PROCESS SERVED AND THIS ONE DID NOT. A load balancer
  // sending /oauth2/token to one container and /admin to another would
  // otherwise make each console show half the endpoint list.
  // -------------------------------------------------------------------------
  // AND THE PER-PATH ROWS ARE MERGED TOO, WHICH THEY WERE NOT UNTIL 2026-09-08.
  //
  // The comment below this block used to say the rows stayed this process's:
  // the tiles were summed, the TABLE was not, and `pathsElsewhere` was offered
  // so a reader could tell. That was an argument from EFFORT — "merging
  // per-status histograms per path across processes is real work for a table
  // whose point is what this instance sees" — and it does not survive being
  // read next to the tiles beside it, which have always been service-wide. One
  // page cannot mean two things by "how many".
  //
  // It was measurable rather than theoretical: twelve probes of `/healthcheck`
  // across three request workers moved the table by FOUR, consistently and
  // permanently, while `calls.total` moved by twelve. `admin_api` reported it
  // as "the metrics page counted 3 calls against 1 before 3 were made".
  //
  // The merge is by METHOD AND PATH, which is the key the store already uses,
  // and it sums exactly the fields that are sums. `maxMs` takes the larger and
  // `lastAt`/`lastStatus` the later, because those are not sums and adding
  // them would be a number with no meaning at all.
  // -------------------------------------------------------------------------
  const merged = new Map();
  callRows.forEach(function (row) {
    merged.set(row.method + ' ' + row.path, Object.assign({}, row, {
      statuses: Object.assign({}, row.statuses)
    }));
  });
  const theirPaths = replication.remoteKeys('admin_stats.calls');
  theirPaths.forEach(function (key) {
    replication.remoteRows('admin_stats.calls', undefined, key)
      .forEach(function (theirRow) {
        if (!theirRow || !theirRow.path) {
          return;
        }
        Object.keys(theirRow.statuses || {}).forEach(function (bucket) {
          statusTotals[bucket] = (statusTotals[bucket] || 0) +
                                 theirRow.statuses[bucket];
        });
        const id = (theirRow.method || '') + ' ' + theirRow.path;
        const mine = merged.get(id);
        if (!mine) {
          merged.set(id, Object.assign({}, theirRow, {
            statuses: Object.assign({}, theirRow.statuses)
          }));
          return;
        }
        mine.count += Number(theirRow.count || 0);
        mine.totalMs += Number(theirRow.totalMs || 0);
        mine.maxMs = Math.max(mine.maxMs || 0, Number(theirRow.maxMs || 0));
        if (Number(theirRow.lastAt || 0) > Number(mine.lastAt || 0)) {
          mine.lastAt = theirRow.lastAt;
          mine.lastStatus = theirRow.lastStatus;
        }
        Object.keys(theirRow.statuses || {}).forEach(function (bucket) {
          mine.statuses[bucket] = (mine.statuses[bucket] || 0) +
                                  theirRow.statuses[bucket];
        });
      });
  });
  const mergedRows = Array.from(merged.values()).sort(function (a, b) {
    return b.count - a.count;
  });
  // WHAT THIS PROCESS ALONE SERVED, kept because the two numbers answer
  // different questions and a reader troubleshooting one worker wants the
  // second. `pathsElsewhere` keeps its old meaning: paths nobody here served.
  const extraPaths = mergedRows.filter(function (row) {
    return !callRows.some(function (mine) {
      return mine.method === row.method && mine.path === row.path;
    });
  }).length;

  const result = {
    startedAt: STARTED_AT,
    uptimeMs: nowMs - STARTED_AT,
    now: nowMs,
    calls: { total: nums.callTotal + alsoElsewhere('callTotal'),
             // `paths` counts every path anybody served. THE ROWS ARE MERGED
             // — see the block above — so this table means the same thing as the tiles beside
             // it, which it did not until 2026-09-08. `pathsHere` and
             // `pathsElsewhere` still split the same list, because a reader
             // troubleshooting ONE worker wants to know which of these rows it
             // served itself.
             paths: mergedRows.length,
             pathsHere: callRows.length,
             pathsElsewhere: extraPaths,
             byStatusClass: statusTotals,
             pathsCollapsed: nums.callPathsDropped +
                             alsoElsewhere('callPathsDropped'),
             rows: mergedRows },
    // TOKENS ARE `merge: 'replace'` AND ARE THEREFORE ALREADY MERGED — a token
    // is minted by one process and the register is keyed by jti, so the row IS
    // the value and coordination has already put every process's tokens in
    // this map. That is also why a revocation in another process reaches this
    // one: it is a write to the same row rather than a tally of its own.
    tokens: { held: tokens.size,
              forgotten: nums.tokensForgotten +
                         alsoElsewhere('tokensForgotten'),
              cap: MAX_TOKENS,
              revoked: revokedJtis.size, byKind: Array.from(byKind.values()) },
    // ARTIFACTS ARE `merge: 'own'`, because the register is an append-only
    // ARRAY rather than a keyed map — so what another process issued is in the
    // fan-in and not in this array.
    artifacts: { held: artifacts.length + replication
                   .remoteRows('admin_stats.artifacts', undefined, '')
                   .reduce(function (n, rows) {
                     return n + (Array.isArray(rows) ? rows.length : 0);
                   }, 0),
                 heldHere: artifacts.length,
                 forgotten: nums.artifactsForgotten +
                            alsoElsewhere('artifactsForgotten'),
                 cap: MAX_ARTIFACTS,
                 byKind: Array.from(artifactKinds.values()) },
    // Counted, not listed: the whole list is what /admin/users is for, and
    // repeating it inside every metrics reply would make the two disagree the
    // first time one of them changed.
    users: { known: knownUsers.length, cap: MAX_USERS,
             forgotten: nums.usersForgotten + alsoElsewhere('usersForgotten'),
             authenticatedHere: knownUsers.filter(
                 function (r) { return r.authenticated; }).length,
             clients: knownUsers.filter(function (
                 r) { return r.isClient; }).length,
             authentications: knownUsers.reduce(function (n, r) {
               return n + r.authentications;
             }, 0) },
    sessions: sessionsFromArtifacts(),
    claims: CLAIM_SET_IDS.map(function (id) {
      return { id: id, label: CLAIM_SETS[id].label,
               count: CLAIM_SETS[id].claims.length,
               claims: CLAIM_SETS[id].claims.slice() };
    })
  };
  log.debug("Leaving snapshot(). " + result.calls.total + " call(s), " +
            result.tokens.held +
            " token(s), " + result.artifacts.held + " artifact(s).");
  return result;
}

module.exports = {
  STARTED_AT: STARTED_AT,
  MAX_TOKENS: MAX_TOKENS,
  MAX_ARTIFACTS: MAX_ARTIFACTS,
  MAX_USERS: MAX_USERS,
  MAX_EVENTS_PER_USER: MAX_EVENTS_PER_USER,
  CLAIM_SET_IDS: CLAIM_SET_IDS,
  JWT_CLAIM_SET_IDS: JWT_CLAIM_SET_IDS,
  SAML_CLAIM_SET_IDS: SAML_CLAIM_SET_IDS,
  USERINFO_CLAIM_SET_IDS: USERINFO_CLAIM_SET_IDS,
  reservedNames: reservedNames,
  CLAIM_SETS: CLAIM_SETS,
  RESERVED_JWT_CLAIMS: RESERVED_JWT_CLAIMS,
  PLACEHOLDERS: PLACEHOLDERS,
  DEFAULT_SAML11_NAMESPACE: DEFAULT_SAML11_NAMESPACE,
  REVOCABLE_KINDS: REVOCABLE_KINDS,
  TOKEN_KINDS: TOKEN_KINDS,
  ISSUED_FAMILIES: ISSUED_FAMILIES,
  recordCall: recordCall,
  recordAuthentication: recordAuthentication,
  noteWebauthnEnrolled: noteWebauthnEnrolled,
  knownUser: knownUser,
  setUserObserver: setUserObserver,
  noteKnownIdentity: noteKnownIdentity,
  identityOf: identityOf,
  identityKeyOf: identityKeyOf,
  holderKeyOf: holderKeyOf,
  renameIdentity: renameIdentity,
  userRows: userRows,
  userDetail: userDetail,
  sessionIdOfJti: sessionIdOfJti,
  sessionAuthenticatedOfJti: sessionAuthenticatedOfJti,
  recordAssertion: recordAssertion,
  recordTicket: recordTicket,
  recordCredential: recordCredential,
  recordSvid: recordSvid,
  recordCredentialStatus: recordCredentialStatus,
  SCIM_OPERATIONS: SCIM_OPERATIONS,
  SCIM_RESOURCE_TYPES: SCIM_RESOURCE_TYPES,
  recordScim: recordScim,
  scimSnapshot: scimSnapshot,
  // The traffic view over the SAME counters, for /admin/scim/monitor and
  // GET /admin-api/scim/monitor. Two views over one store, which is why
  // the surface page and the monitoring page cannot disagree.
  scimMonitorSnapshot: scimMonitorSnapshot,
  // Exported for the tests only. There is no console control that calls
  // it; see the comment on the function.
  resetScimForTests: resetScimForTests,
  SCIM_RECENT: SCIM_RECENT,
  SCIM_MAX_CLIENTS: SCIM_MAX_CLIENTS,
  revoke: revoke,
  restore: restore,
  revokeWhere: revokeWhere,
  revokeArtifact: revokeArtifact,
  restoreArtifact: restoreArtifact,
  artifactByKey: artifactByKey,
  revokeArtifactsWhere: revokeArtifactsWhere,
  isRevoked: isRevoked,
  revokedCount: revokedCount,
  claimSet: claimSet,
  setClaimSet: setClaimSet,
  // Filled by claim_attributes.js at its require time; see the note above it.
  // The inversion is what keeps the four issuance sites unchanged.
  setAttributeResolver: setAttributeResolver,
  setGroupResolver: setGroupResolver,
  jwtClaims: jwtClaims,
  samlAttributes: samlAttributes,
  // The release filter on its own, for the ONE caller that produces claims
  // without going through a claim set — the UserInfo endpoint's answer to a
  // section 5.5 claims request. See the header above it for why that caller
  // must not be exempt.
  applyClaimRelease: applyClaimRelease,
  expandValue: expandValue,
  tokenList: tokenList,
  artifactList: artifactList,
  issuedList: issuedList,
  issuedSets: issuedSets,
  issuedSetByKey: issuedSetByKey,
  issuedById: issuedById,
  snapshot: snapshot
};
