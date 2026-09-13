'use strict';
//
// File: request_routing.js
//
// ===========================================================================
// WHICH WORKER A REQUEST GOES TO, AND THE TWO WAYS OF GETTING IT WRONG.
//
// `common/request_pool.js` sends a request to a worker and the policy is two
// decisions: **is this path dispatched at all**, and **does it hold affinity or
// fan out**. Both are prefix questions over a URL, and both fail SILENTLY when
// they are wrong — a request routed to the wrong worker is answered, correctly
// shaped, out of a store that does not have what it needed. Nothing throws.
//
// The policy, stated once so this file has something to be measured against:
//
//   * `/scim/v2`, `/xacml` and `/admin-api` FAN OUT. Each carries its own
//     credential on every request and names its own target, so nothing about
//     one request has to be remembered to answer the next.
//   * **EVERYTHING ELSE DISPATCHED HOLDS AFFINITY** — every protocol family,
//     the admin console and the user portal — because a browser flow spans
//     several requests whose state lives in the worker that made it.
//   * **`/admin/ldap/*` IS THE CONSOLE AND NOT LDAP.** The directory's own
//     protocol is a raw socket, dispatched as an OPERATION and fanned out;
//     its console pages are pages, and are routed like every other page under
//     `/admin`.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS RATHER THAN OVER HTTP.
//
// Both predicates are pure functions of a URL and a settings value, so a test
// over HTTP would have to stand up a pool of real workers, drive traffic, and
// then infer the routing from which worker's log mentioned it — which is how
// this policy was checked by hand, and it is why the `/admin` bug below took a
// deliberate experiment to see rather than being obvious. Choosing the settings
// is the thing a running service cannot be asked to do on demand.
//
// ---------------------------------------------------------------------------
// THE BUG THIS FILE EXISTS FOR, WHICH WAS FOUND WHILE WRITING THE POLICY.
//
// `dispatched()` matched a bare prefix — `pathOnly.indexOf(prefix) === 0` — so
// **`/admin` also matched `/admin-api`**. Naming the console in the dispatch
// list therefore dragged the management API along with it, onto the AFFINITY
// side of the routing, and the two surfaces are the clearest example in the
// service of things that must route oppositely: one is a browser session and
// the other is a credential presented per call. It matched on a prefix, so
// nothing was ever refused and no log line said anything was unusual.
//
// The rule is that a path prefix ends at a SEGMENT BOUNDARY, and the
// assertions below are written to fail if it ever stops doing so.
// ===========================================================================

const pool = require('../common/request_pool');
const config = require('../common/config');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'request_routing',
  level: process.env.LOG_LEVEL || 'info' });

// The two settings this file drives, saved and restored around every section —
// they are process-wide and every later file in the run reads through them.
// See tests/CLAUDE.md's rule about process-wide state.
function withSettings(dispatch, fanout, fn) {
  log.debug("Entering withSettings().");
  const hadDispatch = process.env.STS_WORKERS_DISPATCH;
  const hadFanout = process.env.STS_WORKERS_FANOUT;
  process.env.STS_WORKERS_DISPATCH = dispatch;
  process.env.STS_WORKERS_FANOUT = fanout;
  try {
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    if (hadDispatch === undefined) {
      delete process.env.STS_WORKERS_DISPATCH;
    } else {
      process.env.STS_WORKERS_DISPATCH = hadDispatch;
    }
    if (hadFanout === undefined) {
      delete process.env.STS_WORKERS_FANOUT;
    } else {
      process.env.STS_WORKERS_FANOUT = hadFanout;
    }
  }
}

// ---------------------------------------------------------------------------
// NOTHING IS DISPATCHED UNTIL SOMEBODY ASKS, which is the safety property the
// whole pool rests on: it is landable before the state channel exists only
// because the default routes nothing anywhere.
// ---------------------------------------------------------------------------
function checkTheDefaultIsInert(t) {
  log.debug("Entering checkTheDefaultIsInert().");
  t.log.info('=== with no dispatch list, nothing goes to a worker ===');
  withSettings('', '/scim,/xacml,/admin-api', function () {
    ['/oauth2/authorize', '/scim/v2/Users', '/admin', '/admin-api/config',
     '/portal', '/xacml/pdp'].forEach(function (url) {
      t.check(pool.dispatched(url) === false,
              'nothing is dispatched by default: ' + url,
              String(pool.dispatched(url)));
    });
  });
  log.debug("Leaving checkTheDefaultIsInert().");
}

// ---------------------------------------------------------------------------
// THE SEGMENT BOUNDARY. This is the section the file was written for.
// ---------------------------------------------------------------------------
function checkThePrefixEndsAtASegment(t) {
  log.debug("Entering checkThePrefixEndsAtASegment().");
  t.log.info('=== a prefix ends at a segment boundary ===');
  withSettings('/admin', '/scim,/xacml,/admin-api', function () {
    t.check(pool.dispatched('/admin') === true,
            'naming /admin dispatches /admin itself', 'yes');
    t.check(pool.dispatched('/admin/users') === true,
            'and everything under it', 'yes');
    t.check(pool.dispatched('/admin/ldap/directory') === true,
            'including the directory pages, which are console pages', 'yes');

    t.check(pool.dispatched('/admin-api/config') === false,
            'AND IT DOES NOT DISPATCH /admin-api. This is the bug the file ' +
            'exists for: a bare prefix match made naming the console drag ' +
            'the management API onto the affinity side of the routing, and ' +
            'the two are the clearest case in the service of surfaces that ' +
            'must route oppositely',
            String(pool.dispatched('/admin-api/config')));
    t.check(pool.dispatched('/administrator') === false,
            'nor a path that merely starts with the same letters',
            String(pool.dispatched('/administrator')));
  });
  log.debug("Leaving checkThePrefixEndsAtASegment().");
}

// ---------------------------------------------------------------------------
// THE POLICY ITSELF, asserted as a table so a change to it is a change to this
// list rather than to an argument spread over several checks.
// ---------------------------------------------------------------------------
function checkTheRoutingPolicy(t) {
  log.debug("Entering checkTheRoutingPolicy().");
  t.log.info('=== affinity for everything except the three that fan out ===');
  const DISPATCH = '/oauth2,/saml2,/saml11,/wsfed,/wstrust,/authn,/portal,' +
                   '/admin,/admin-api,/scim,/xacml,/federation,/ssf';
  const FANOUT = '/scim,/xacml,/admin-api';

  // [url, expected fanout?, why]
  const CASES = [
    ['/scim/v2/Users', true, 'SCIM carries its own credential per call'],
    ['/xacml/pdp', true, 'a decision request names its own subject'],
    ['/admin-api/config', true, 'the management API is a credential per call'],
    ['/admin-api', true, 'and the bare path is the same surface'],

    ['/admin', false, 'the console is a browser session'],
    ['/admin/users', false, 'and every page under it'],
    ['/admin/ldap/directory', false,
     'INCLUDING THE DIRECTORY PAGES. They are the console, not LDAP — the ' +
     'directory\'s own protocol is a raw socket dispatched as an operation, ' +
     'and these are pages somebody reads while signed in'],
    ['/admin/ldap/service', false, 'and the socket status page likewise'],
    ['/portal', false, 'the user portal is a browser session'],
    ['/portal/applications', false, 'and every page under it'],
    ['/oauth2/authorize', false, 'the authorization endpoint carries a flow'],
    ['/oauth2/token', false, 'and the token endpoint redeems what it minted'],
    ['/authn/login', false, 'the sign-in screen IS the flow'],
    ['/saml2/sso', false, 'a SAML browser profile spans requests'],
    ['/saml11/sso', false, 'as does the 1.1 one'],
    ['/wsfed', false, 'WS-Federation is a passive requestor flow'],
    ['/wstrust', false, 'WS-Trust carries a requester credential'],
    ['/federation/acs/abc', false, 'a federated assertion lands mid-flow'],
    ['/ssf/streams', false, 'a stream is agreed and then delivered against']
  ];

  withSettings(DISPATCH, FANOUT, function () {
    CASES.forEach(function (one) {
      const url = one[0];
      const wantFanout = one[1];
      t.check(pool.dispatched(url) === true,
              'dispatched at all: ' + url, String(pool.dispatched(url)));
      t.check(pool.fansOut(url) === wantFanout,
              (wantFanout ? 'FANS OUT: ' : 'HOLDS AFFINITY: ') + url +
              ' — ' + one[2],
              String(pool.fansOut(url)));
    });
  });
  log.debug("Leaving checkTheRoutingPolicy().");
}

// ---------------------------------------------------------------------------
// THE REALM SEGMENT IS NOT PART OF THE DECISION, which is what keeps the
// dispatch list from being the first thing in this service that has to name
// every realm.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `*` IS HOW "EVERY PROTOCOL RUNS IN THE POOL" IS SAID, and `/tls` is the one
// thing it does not reach.
// ---------------------------------------------------------------------------
function checkDispatchEverything(t) {
  log.debug("Entering checkDispatchEverything().");
  t.log.info('=== "*" dispatches every path except what cannot move ===');
  withSettings('*', '/scim,/xacml,/admin-api', function () {
    ['/oauth2/authorize', '/saml2/sso', '/saml11/sso', '/wsfed', '/wstrust',
     '/scim/v2/Users', '/admin', '/admin-api/config', '/portal', '/xacml/pdp',
     '/krb5/principals', '/spiffe/bundle', '/ssf/streams', '/federation/acs/x',
     '/logout', '/'].forEach(function (url) {
      t.check(pool.dispatched(url) === true,
              '"*" dispatches ' + url, String(pool.dispatched(url)));
    });

    t.check(pool.dispatched('/tls') === false,
            'AND NOT /tls, whatever the list says. Its whole content is what ' +
            'the SERVER saw of the connection the request arrived on, and ' +
            'proxied it would describe the unix socket between the front ' +
            'process and a worker — which is not a fact about the caller',
            String(pool.dispatched('/tls')));
    t.check(pool.dispatched('/tls/trust') === false,
            'nor anything under it', String(pool.dispatched('/tls/trust')));

    // ---------------------------------------------------------------------
    // AND SPIFFE **IS** DISPATCHED, which is an assertion about a fix rather
    // than about a default (2026-09-08).
    //
    // For an hour it was not: SPIFFE's authority was two module arrays in the
    // process that binds its four sockets, so a worker answering the bundle
    // endpoint published keys that verified none of the SVIDs actually issued,
    // and pinning the three prefixes to that process was the first fix. The
    // second fix was the right one — `spiffe_ca.js` shares the authority, so
    // every process answers the same bundle — and these lines are what stops
    // the first one being reintroduced by somebody meeting the symptom again.
    // `tests/spiffe_authority.js` holds the sharing itself.
    // ---------------------------------------------------------------------
    ['/spiffe', '/spiffe/bundle', '/admin-api/spiffe',
     '/admin/spiffe'].forEach(function (url) {
      t.check(pool.dispatched(url) === true,
              'and "*" dispatches ' + url + ' — the SPIFFE authority is ' +
              'SHARED, so any process answers the same bundle and a rotation ' +
              'from any of them is the service\'s',
              String(pool.dispatched(url)));
    });
    t.check(pool.fansOut('/admin-api/spiffe') === true,
            'and the management API half still fans out with the rest of it',
            String(pool.fansOut('/admin-api/spiffe')));
    t.check(pool.fansOut('/admin/spiffe') === false,
            'while the console page holds affinity with the rest of /admin',
            String(pool.fansOut('/admin/spiffe')));

    // ---------------------------------------------------------------------
    // A WRITE TO ONE RESOURCE IS PINNED, EVEN ON A FANOUT PATH (2026-09-08).
    //
    // `PATCH /scim/v2/Groups/{id}` is read-modify-write over a whole entry, so
    // two of them on two workers lose a member — measured as two groups
    // holding 99 of 100, with no dangling references. A collection is still
    // fanned out, because keying a create on its path would serialise every
    // `POST /scim/v2/Users` through one worker.
    // ---------------------------------------------------------------------
    t.check(pool.mutationKeyOf({ method: 'PATCH' },
                               '/scim/v2/Groups/abc') === 'r:/scim/v2/Groups/abc',
            'a write to one SCIM resource is keyed on that resource',
            pool.mutationKeyOf({ method: 'PATCH' }, '/scim/v2/Groups/abc'));
    t.check(pool.mutationKeyOf({ method: 'PATCH' },
              '/realm/acme/scim/v2/Groups/abc') ===
              'r:/realm/acme/scim/v2/Groups/abc',
            'AND IN A REALM, which is where the bulk-load jobs run — the ' +
            'pool routes on req.originalUrl, which keeps the realm prefix',
            pool.mutationKeyOf({ method: 'PATCH' },
                               '/realm/acme/scim/v2/Groups/abc'));
    t.check(pool.mutationKeyOf({ method: 'POST' }, '/scim/v2/Users') === '',
            'while a COLLECTION write still fans out: keying a create on its ' +
            'path would put the whole load on one worker',
            JSON.stringify(pool.mutationKeyOf({ method: 'POST' },
                                              '/scim/v2/Users')));
    // ---------------------------------------------------------------------
    // A CREDENTIAL IS AN AFFINITY KEY (2026-09-08), and this is the half that
    // makes a provisioning client fast rather than the half that makes it
    // correct.
    //
    // Fanning out is right for a surface whose every request carries its own
    // credential — and that is not the same as SPREADING one client's calls
    // across workers, which makes each request wait for the last one to reach
    // the store. Measured on sequential SCIM creates: 16.2ms each spread,
    // 3.7ms each when the credential keeps them together.
    // ---------------------------------------------------------------------
    const withCred = { method: 'POST',
                       headers: { authorization: 'Basic abc' } };
    const other = { method: 'POST', headers: { authorization: 'Basic zzz' } };
    const key = pool.mutationKeyOf(withCred, '/scim/v2/Users');
    t.check(key.indexOf('c:') === 0,
            'a fanout write carrying a credential is keyed on that ' +
            'credential, so one client keeps landing on the worker that ' +
            'already holds its writes', key);
    t.check(key === pool.mutationKeyOf(withCred, '/scim/v2/Users'),
            'and the key is STABLE for one credential — an affinity key that ' +
            'moved would spread the client again and buy nothing', key);
    t.check(key !== pool.mutationKeyOf(other, '/scim/v2/Users'),
            'while a different credential gets a different worker, so this ' +
            'is locality and not a funnel', 'differs');
    t.check(key.indexOf('abc') < 0 && key.indexOf('Basic') < 0,
            'AND THE KEY IS NOT THE HEADER. It is hashed, because a routing ' +
            'key lives in a Map for the life of the process and a Basic ' +
            'credential has no business being there', key);
    t.check(pool.mutationKeyOf({ method: 'POST', headers: {} },
                               '/scim/v2/Users') === '',
            'a request with no credential is spread exactly as before',
            JSON.stringify(pool.mutationKeyOf({ method: 'POST', headers: {} },
                                              '/scim/v2/Users')));
    t.check(pool.mutationKeyOf({ method: 'PATCH',
                                 headers: { authorization: 'Basic abc' } },
                               '/scim/v2/Groups/g1') === 'r:/scim/v2/Groups/g1',
            'and a write to ONE RESOURCE still wins over the credential — ' +
            'two clients patching one group must meet on one worker, which ' +
            'is the serialisation that keeps their appends from losing each ' +
            'other',
            pool.mutationKeyOf({ method: 'PATCH',
                                 headers: { authorization: 'Basic abc' } },
                               '/scim/v2/Groups/g1'));

    t.check(pool.mutationKeyOf({ method: 'GET' }, '/scim/v2/Groups/abc') === '',
            'and a READ is untouched — a reader that must see a write is ' +
            'what the barrier is for; this is about two writers',
            JSON.stringify(pool.mutationKeyOf({ method: 'GET' },
                                              '/scim/v2/Groups/abc')));

    // The fanout policy is unchanged by "*": it is a different question.
    t.check(pool.fansOut('/scim/v2/Users') === true,
            'and "*" does not change WHICH of them fan out', 'yes');
    t.check(pool.fansOut('/oauth2/authorize') === false,
            'nor which hold affinity', 'no');
  });
  log.debug("Leaving checkDispatchEverything().");
}

function checkTheRealmIsTransparent(t) {
  log.debug("Entering checkTheRealmIsTransparent().");
  t.log.info('=== a realm prefix does not change the routing ===');
  withSettings('/scim,/admin', '/scim,/xacml,/admin-api', function () {
    t.check(pool.dispatched('/realm/acme/scim/v2/Users') === true,
            'a realmed path is dispatched exactly as the bare one is', 'yes');
    t.check(pool.fansOut('/realm/acme/scim/v2/Users') === true,
            'and fans out exactly as the bare one does', 'yes');
    t.check(pool.fansOut('/realm/acme/admin/users') === false,
            'and a realmed console page holds affinity exactly as the bare ' +
            'one does — the realm is not a routing decision', 'no');
  });
  log.debug("Leaving checkTheRealmIsTransparent().");
}

// ---------------------------------------------------------------------------
// WHAT A REQUEST IS STUCK TO. The cookie is the obvious key and it is not
// enough: the hops that most need affinity happen before there is a session.
// ---------------------------------------------------------------------------
function checkTheAffinityKey(t) {
  log.debug("Entering checkTheAffinityKey().");
  t.log.info('=== the affinity key: cookie first, then the flow ===');

  const withCookie = { headers: { cookie: 'a=1; sts_session=SESS1; b=2' },
                       url: '/admin/users', originalUrl: '/admin/users' };
  t.check(pool.affinityKeyOf(withCookie) === 's:SESS1',
          'the session cookie is the key when there is one, whatever else is ' +
          'in the header', pool.affinityKeyOf(withCookie));

  // THE SPELLINGS ARE THE HANDLERS' OWN. This assertion said `authn_id` when it
  // was written, because that is what the POST BODY carries — the REDIRECT
  // carries `authn`, so the key was never extracted and every browser flow
  // fanned out. It was found by driving a real authorization code flow, not by
  // reading the pool.
  const flow = { headers: {},
                 url: '/authn/login?authn=PEND9&foo=bar',
                 originalUrl: '/authn/login?authn=PEND9&foo=bar' };
  t.check(pool.affinityKeyOf(flow) === 'authn:PEND9',
          'A PENDING AUTHENTICATION RECORD IS A KEY. This is the hop that ' +
          'breaks without it: /oauth2/authorize mints the record in one ' +
          'worker\'s memory and redirects here, and a second hop routed by ' +
          'load finds nothing',
          pool.affinityKeyOf(flow));

  const both = { headers: { cookie: 'sts_session=SESS2' },
                 url: '/oauth2/consent?consent=C7',
                 originalUrl: '/oauth2/consent?consent=C7' };
  t.check(pool.affinityKeyOf(both) === 's:SESS2',
          'the cookie WINS over a flow id, because a request carrying both ' +
          'is a browser that is already signed in and the session outlives ' +
          'the flow', pool.affinityKeyOf(both));

  const artifact = { headers: {}, url: '/saml11/artifact?SAMLart=AA%2FBB',
                     originalUrl: '/saml11/artifact?SAMLart=AA%2FBB' };
  t.check(pool.affinityKeyOf(artifact) === 'SAMLart:AA/BB',
          'a SAML artifact is a key, and is decoded — the same artifact must ' +
          'reach the same worker however it was escaped on the wire',
          pool.affinityKeyOf(artifact));

  // ---------------------------------------------------------------------
  // THE POOL'S OWN COOKIE, which is what actually holds a browser flow
  // together — see request_pool.js. Reading flow ids out of the URL cannot
  // pin the FORM POST, because that hop carries its identifier in the BODY and
  // the front process does not parse bodies.
  // ---------------------------------------------------------------------
  const pooled = { headers: { cookie: 'sts_pool=4242' },
                   url: '/authn/login', originalUrl: '/authn/login' };
  t.check(pool.affinityKeyOf(pooled) === 'p:4242',
          'the pool cookie is a key, and it is what pins a form POST — the ' +
          'hop whose identifier is in the body and therefore invisible here',
          pool.affinityKeyOf(pooled));

  // THE SIGN-ON SESSION WINS OVER THE PIN, because `learn()` binds `s:<id>` to
  // the worker whose answer set that cookie — so it resolves by LOOKUP to the
  // worker that holds the session, where the pin is only a fallback for a
  // binding this process has lost.
  const bothCookies = { headers: { cookie: 'sts_pool=4242; sts_session=SESS3' },
                        url: '/admin', originalUrl: '/admin' };
  t.check(pool.affinityKeyOf(bothCookies) === 's:SESS3',
          'and the sign-on session still wins over it, because it is bound ' +
          'to the worker that minted it rather than hashed to an arbitrary one',
          pool.affinityKeyOf(bothCookies));

  // And with no pin the session is still the key — a browser that never got a
  // pin because the response that signed it in deliberately did not carry one.
  const sessionOnly = { headers: { cookie: 'sts_session=SESS4' },
                        url: '/admin', originalUrl: '/admin' };
  t.check(pool.affinityKeyOf(sessionOnly) === 's:SESS4',
          'a session with no pin is still a key',
          pool.affinityKeyOf(sessionOnly));


  const bare = { headers: {}, url: '/oauth2/authorize?client_id=x',
                 originalUrl: '/oauth2/authorize?client_id=x' };
  t.check(pool.affinityKeyOf(bare) === '',
          'and a request carrying NONE of them has no key — it is the first ' +
          'hop of a flow, so it fans out and the pool binds whatever that ' +
          'worker mints', JSON.stringify(pool.affinityKeyOf(bare)));

  const empty = { headers: { cookie: 'sts_session=' },
                  url: '/admin', originalUrl: '/admin' };
  t.check(pool.affinityKeyOf(empty) === '',
          'an EMPTY cookie is no key either — a sign-out clears it, and ' +
          'binding the empty string would pin every signed-out request to ' +
          'one worker', JSON.stringify(pool.affinityKeyOf(empty)));
  log.debug("Leaving checkTheAffinityKey().");
}

// ---------------------------------------------------------------------------
// OPERATIONS: the half that is not HTTP, OUT OF THE SAME SETTING AS THE PATHS.
//
// `workers.operations` was a second setting until 2026-09-12 and the
// distinction it drew was artificial — a dispatched thing is a dispatched
// thing. There is one list now and **an entry says what it is by its shape**: a
// leading slash is a path prefix, anything else is an operation kind, `*` is
// everything.
//
// That makes this section's job specific: the two halves must READ THE SAME
// LIST and must not see each other's entries. A path leaking into
// `operationKinds()` would dispatch an operation nobody named; an operation
// kind leaking into `dispatchPrefixes()` would be matched against `req.url`,
// where `ldap` would quietly match `/ldapsomething`.
// ---------------------------------------------------------------------------
function checkOperations(t) {
  log.debug("Entering checkOperations().");
  t.log.info('=== operations and paths come out of one setting ===');
  const had = process.env.STS_WORKERS_DISPATCH;
  try {
    delete process.env.STS_WORKERS_DISPATCH;
    t.check(pool.operationDispatched('ldap.search') === false,
            'NOTHING is dispatched by default, of either kind',
            String(pool.operationDispatched('ldap.search')));

    process.env.STS_WORKERS_DISPATCH = 'ldap';
    t.check(pool.operationDispatched('ldap.search') === true,
            'naming the family dispatches its operations', 'yes');
    t.check(pool.operationDispatched('ldap.add') === true,
            'all of them', 'yes');
    t.check(pool.operationDispatched('krb5.asreq') === false,
            'and only that family', 'no');

    process.env.STS_WORKERS_DISPATCH = 'ldap.search';
    t.check(pool.operationDispatched('ldap.search') === true,
            'a single operation can be named on its own, which is how a ' +
            'store this size gets moved a piece at a time', 'yes');
    t.check(pool.operationDispatched('ldap.add') === false,
            'without taking its siblings with it — the reads can move before ' +
            'the writes do', 'no');

    // ---------------------------------------------------------------------
    // THE TWO HALVES OF ONE LIST, WHICH IS THE WHOLE OF WHAT THE MERGE HAD TO
    // GET RIGHT. Mixed together, each must see only its own kind.
    // ---------------------------------------------------------------------
    process.env.STS_WORKERS_DISPATCH = '/scim,ldap,/admin-api';
    t.check(pool.operationDispatched('ldap.search') === true,
            'a mixed list dispatches the operation kind in it', 'yes');
    t.check(JSON.stringify(pool.dispatchPrefixes()) ===
            JSON.stringify(['/scim', '/admin-api']),
            'and the PATH half sees only the paths (' +
            pool.dispatchPrefixes().join(', ') + ')',
            'an operation kind reaching the prefix list is matched against ' +
            'req.url, where "ldap" would match /ldapsomething');
    t.check(JSON.stringify(pool.operationKinds()) === JSON.stringify(['ldap']),
            'and the OPERATION half sees only the kinds (' +
            pool.operationKinds().join(', ') + ')',
            'a path reaching the kind list would dispatch an operation ' +
            'family nobody named');

    // ---------------------------------------------------------------------
    // AND `*` IS EVERYTHING, WHICH IS THE ONE BEHAVIOUR THE MERGE CHANGED.
    //
    // It meant "every path" and means "everything". A wildcard that quietly
    // excluded a whole class of work would be the artificial distinction
    // surviving the settings it was named after — an operator who wants paths
    // and not operations names the paths, which is what the list is for.
    // ---------------------------------------------------------------------
    process.env.STS_WORKERS_DISPATCH = '*';
    t.check(pool.operationDispatched('ldap.search') === true,
            '"*" reaches operations and not only paths', 'yes');
    t.check(pool.dispatchPrefixes().indexOf('*') >= 0,
            'and is still in the path half, where dispatched() reads it',
            'the wildcard fell out of the prefix list, so "*" would dispatch ' +
            'no path at all');
  } finally {
    if (had === undefined) {
      delete process.env.STS_WORKERS_DISPATCH;
    } else {
      process.env.STS_WORKERS_DISPATCH = had;
    }
  }
  log.debug("Leaving checkOperations().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheDefaultIsInert(t);
  checkThePrefixEndsAtASegment(t);
  checkTheRoutingPolicy(t);
  checkDispatchEverything(t);
  checkTheRealmIsTransparent(t);
  checkTheAffinityKey(t);
  checkOperations(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_routing',
  describe: 'which worker a request goes to: what is dispatched, what fans ' +
            'out, and what a request is stuck to',
  run: run
};
