// @ts-check
'use strict';
//
// File: server.js
//
//
// The entry point of this identity service.
//
// It began as a small WS-Trust 1.4 STS mock for the OAuth2/OIDC Debugger's
// test suite, and the comment that opened this file described that STS. It is
// now a mock — and, in `product` mode, a deployable — identity service in
// every protocol family the root CLAUDE.md's *Overview* lists; README.md is
// the substantive description, `docs/` the user-facing one, and the WS-Trust
// behaviour this header used to describe is `ws-trust/CLAUDE.md`'s.
//
// Config via env:
//   CONFIG_FILE  the configuration module to load, chosen the same way as for the
//                api and client services (e.g. ./env/local.js). It supplies
//                EVERY setting this service has — env/docker-tests.js is what
//                the containerized test stack uses.
//
// The settings themselves are not listed here any more, because a
// list in a comment is a list that goes stale: `config.js` is the table, and it
// carries each setting's name, its environment variable, its default, what it
// does, and whether changing it while the service runs does anything.
// /admin/config renders that table with the effective value of each and where
// it came from, and `GET /admin-api/config` answers the same thing over JSON.
//
// An ENVIRONMENT VARIABLE STILL BEATS THE FILE, which is what keeps every
// container and test that set one working unchanged: STS_PORT, STS_ISSUER,
// KRB5_REALM and the rest all still do exactly what they did. STS_ISSUER is the
// one that grew: it was a single value serving as the SAML assertion issuer,
// the WS-Trust token issuer and the WS-Federation entityID, which are three
// different things that shared a default. They are now saml.issuer,
// wstrust.issuer and wsfed.entityId, all three still fed by STS_ISSUER when it
// is set.
//
// Logging: everything this mock does is written to the log at DEBUG level —
// every endpoint call (path, request headers and body, response headers and
// body, status code and elapsed time), and every SAML assertion, JWT and SD-JWT
// VC both BEFORE and AFTER it was signed or encrypted. Every appconfig file in
// env/ runs at info; STS_LOG_LEVEL=debug is the run that asks for all of it.
//
// ---------------------------------------------------------------------------
// This file is now the SHELL only: it loads the modules and listens. It used to
// be all 4,489 lines of the service, which is why the split happened — eight
// protocol families in one file meant no way to see what was in it short of
// reading it. What each directory holds is the root CLAUDE.md's *Where things
// are*; the module list that stood here named root-level files that moved into
// directories on 2026-08-23.
//
// **A composition root registers every endpoint** (rule 1). Until #50's R1
// (2026-09-16) requiring a module registered its endpoints — each did
// `app.get(...)` at its top level against the shared app from
// `common/app.js`, which kept every handler exactly where it was written
// instead of re-indented inside a wrapper. A module converted to TypeScript
// now exports `registerRoutes(app)` and registers nothing when required; the
// JavaScript ones still register at their require. Both orders — the
// requires and the `register()` calls, interleaved as they always ran — live
// in `common/protocol_stack.ts` (below); the root CLAUDE.md's table says what
// each position depends on. sts_metadata.js is last on purpose: it reads the
// router to list what everything else registered, and while it re-reads it
// per request, being last means it is never the reason a route is missing.
// ---------------------------------------------------------------------------

// FIRST, and before any module that reads the appconfig file. Every module now
// lives in a subdirectory, so a relative CONFIG_FILE — `./env/local.js`, which
// is what the documented invocation and the Dockerfile's ENV both say — no
// longer resolves against the package root from where those modules sit. This
// makes it absolute once, in place, so every direct reader agrees. See
// common/config_file.js.
// A TREE WHOSE TYPESCRIPT IS NOT COMPILED IS REFUSED, BEFORE ANYTHING ELSE
// (#50). TypeScript here is compiled only inside an image build, so a checkout
// cannot run the service; this says so instead of a "Cannot find module"
// from the first converted module. See `common/compiled_tree.js`.
require('./common/compiled_tree').refuseUncompiledTree('node server.js');
require('./common/config_file').resolveConfigFile();

const http = require('http');
const https = require('https');
const app = require('./common/app');
// `warmPqKeys` joins the three destructured names for one call in announce()
// below; `realms` for the id of the realm it warms. Both modules are already
// loaded by this line — app.js requires realms, and helpers is this line —
// so neither adds a require to the order.
const { log, PORT, HOST, warmPqKeys } = require('./common/helpers');
const realms = require('./common/realms');
const config = require('./common/config');
// A LIBRARY, rule 3's shape: it registers no route and its position in the
// require order is not a position at all. It is named here for one thing — the
// drain in shutdown() below — and it is already loaded by then, because
// common/crypto.js requires it. See common/worker_pool.js.
const workerPool = require('./common/worker_pool');
// ---------------------------------------------------------------------------
// AND THE SECOND POOL, WHICH IS A DIFFERENT KIND OF WORKER.
//
// `worker_pool.js` above forks children that run a JOB TABLE — four leaf
// computations. `request_pool.js` forks children that run THE SERVICE: each
// loads the same protocol stack in the same order, binds no protocol port, and
// answers HTTP on a unix socket this process proxies to. It is required here
// for its lifecycle only; the middleware that uses it is installed in app.js,
// because that is where the order it has to sit in is decided.
// ---------------------------------------------------------------------------
const requestPool = require('./common/request_pool');
// THE VERSION, M.N.O. A LIBRARY and a LEAF: it registers no route and requires
// nothing from this repository, so its position in the require order is not a
// position and it can never close a cycle. `load()` prefers the record the
// image build stamped and computes one only in a checkout — so a container
// reports the build it came from and restarting it does not renumber it. See
// common/version.js and CLAUDE.md, *Versioning*.
const version = require('./common/version');
// The registry of failure codes, a LEAF. Every failure this file reports is
// either about to end the process or is a listener that did not come up, and
// each is logged with its code at the front — see common/error_codes.js.
const errorCodes = require('./common/error_codes');
const APP_VERSION = version.load();

// ---------------------------------------------------------------------------
// WHERE THIS SERVICE WRITES ITSELF DOWN — #4a, AND THE FIRST TIME IT EVER HAS.
//
// A LIBRARY, rule 3's shape: it registers no route, so this line adds nothing
// to /admin/sts-metadata and its position in the ROUTE order is not a position
// at all. Its position in the REQUIRE order is one, for two reasons:
//
//   * Requiring it is what fills `config.js`'s override-store slot (rule 3q),
//     so a setting changed through the console before this line ran would be
//     changed and not written down. Nothing changes a setting during module
//     load, so this is true on purpose rather than by luck — the same argument
//     claim_attributes.js's line below makes for its own slot.
//   * It subscribes to `realms.onChange()`, and a realm defined by an
//     appconfig file during the load of a module below this one would
//     otherwise not be written down.
//
// **IT DOES NOT OPEN ANYTHING HERE.** Opening a Postgres pool is asynchronous
// and a `require` cannot wait, so the store is opened and READ from
// `persistence.start()` at the foot of this file (through
// `common/service_state.ts`) — before the HTTP listener binds and before the
// socket owners start. That makes it one more module whose real work happens
// outside require time, and the only one that must go FIRST among them: what
// it restores is what the others are about to serve.
//
// In the default memory mode all of that is a no-op and this service behaves
// exactly as it did before 2026-08-27, which is the whole compatibility story
// and is why no job in the parent project's test suite had to be told about
// any of this.
// ---------------------------------------------------------------------------
const persistence = require('./persistence/persistence');

// ---------------------------------------------------------------------------
// EVERY PROTOCOL MODULE, IN THE ORDER THAT IS THE ROUTE ORDER.
//
// That sequence moved to `common/protocol_stack.ts` on 2026-09-07 and the
// reason is that it acquired a SECOND READER: a request worker loads the same
// stack, registers the same routes in the same order, and binds none of the
// sockets. Two copies of the order would be two answers to "which handler
// wins" — see that file's header.
//
// The modules whose `listen()` is called below come back from it, because
// this file needs the handles. Loading the stack registered their HTTP views
// and started nothing. (`tlsServer` is among them and owns no socket since
// 2026-09-16; its `listen()` is still a startup step — see announce().)
// ---------------------------------------------------------------------------
const stack = require('./common/protocol_stack');
const krb5 = stack.krb5;
const krb5Service = stack.krb5Service;
const tlsServer = stack.tlsServer;
const ldapServer = stack.ldapServer;
const spiffeServer = stack.spiffeServer;
const debuggerServer = stack.debuggerServer;
// THE SERVICE PROVIDER METADATA REFRESHER (#37 follow-up): a library the
// stack already loaded (this require is a cache hit and moves no route), whose
// timer is started from announce() — this process's listen path, never a
// request worker's.
const spMetadata = require('./saml/sp_metadata');

// ---------------------------------------------------------------------------
// THE MAIN LISTENER, and the one decision made about it before it binds.
//
// `global.https` — whose default is `oauth2.rfc9700` or `oauth2.oauth21`, so
// either mode brings it with it, and which every appconfig file in `env/` sets
// — makes this an HTTPS listener instead of a plain one. It is not a second
// certificate: `tls_server.js` generates ONE key pair per start, certified
// under this service's Root, and the directory's LDAPS 636 and the debugger's
// listener serve it too, so a caller trusts this service once. That module
// has been required above by the time this runs, which is what makes the key
// available here without moving anything in the require order.
//
// Two things follow and neither is hidden.
//
// **There is then no plain listener in this process at all.** `POST /tls/trust`
// and `GET /tls/server-certificate` are on this port on purpose — they are what
// a caller reaches BEFORE it trusts anything — so with HTTPS on, the first
// fetch of the certificate has to be made without verifying it (`curl -k`).
// That is the ordinary bootstrap for a service whose certificate is regenerated
// every start, and it is said here, on /tls, and in the startup line below
// rather than left to be discovered as a handshake failure.
//
// **The scheme every document here advertises follows the socket by itself.**
// `baseUrlOf()` builds every issuer, endpoint and metadata URL from
// `req.protocol` and the Host header, which is what already makes one process
// answer correctly as localhost, as sts on a compose network and through a
// published port. An https.Server sets `req.protocol` to https, so the RFC 8414
// document, the OpenID Provider Configuration, the OID4VCI and OID4VP metadata,
// the federation metadata and the DID document all move together and none of
// them had to be told. Do not "fix" this by pinning a scheme anywhere: a
// hardcoded https is wrong on the default plain listener, and a document whose
// endpoints disagree with the port they were fetched from is the failure this
// derivation exists to prevent.
// ---------------------------------------------------------------------------
const useHttps = config.value('global.https');

function announce() {
  log.debug('Entering announce().');
  // ---------------------------------------------------------------------
  // THE DEFAULT REALM'S POST-QUANTUM KEYS, WARMED ONCE THE PORT IS OPEN.
  //
  // `helpers.js` watches `realms.onChange(… 'create')` and warms a realm's
  // eleven post-quantum keys as it is made — which was `5d9b51b`'s whole
  // point, that a realm should not pay for its keys inside the first request
  // that needs them. **THE DEFAULT REALM IS NEVER CREATED**: it exists
  // implicitly, so it never fired that watcher and kept the lazy behaviour
  // the commit set out to remove.
  //
  // What that cost was measured rather than guessed. The first
  // `/oauth2/jwks` fetch made all eleven keys inside the request, two of them
  // SLH-DSA — 297ms and 2.3s here uninstrumented, 1.9s and 14.7s under
  // NODE_V8_COVERAGE, a 6.4x factor — so under coverage on a two-core CI
  // runner the first caller waited for the lot. `tests/vendored/
  // sts_userinfo_protected.js` gives up on a request after 90s and did,
  // intermittently, in about half of the coverage runs on `main`. The
  // service was never wrong; the work was simply in the wrong place.
  //
  // IT IS HERE AND NOT AT REQUIRE TIME, which matters: `workers.count`'s own
  // description promises that nothing is forked until the first post-quantum
  // job, so that the parent project's in-process Kerberos jobs, this
  // repository's own `npm test` and `node env/generate_defaults.js` never pay
  // for a pool they will not use. Warming from `helpers.js` would have broken
  // that for every one of them. A process that has bound a socket is a
  // SERVICE, and a service is exactly the thing that will be asked for a
  // JWKS.
  //
  // NOT AWAITED, and failure is not fatal. The port is already open; this is
  // work moved off the first request's path, not a precondition for
  // answering. `warmPqKeys()` logs its own failure and the keys are still
  // made on first use if this does not finish — the slow path is the one
  // that existed before, which is a fallback rather than a fault.
  warmPqKeys(realms.DEFAULT_ID);
  // THE VERSION FIRST, before the endpoint tour below, because it is the one
  // line in this banner that answers a question about the PROCESS rather than
  // about a URL — and it is the line somebody scrolls a container's log back
  // to find when two instances behave differently. buildInfo() says whether the
  // record was stamped at build time or computed just now, which is the
  // difference between an artifact and a checkout and is not guessable from the
  // number.
  log.info('mock-sts version ' + APP_VERSION.version + ' (' +
           version.buildInfo(APP_VERSION) + ').');
  log.info('WS-Trust STS mock listening on ' + (useHttps ? 'https' : 'http') +
           '://' + HOST + ':' + PORT +
           ' (WS-Trust issuer ' + config.value('wstrust.issuer') +
           '); POST SOAP RST to /sts');
  if (useHttps) {
    log.info('This port is HTTPS (global.https' +
             (config.value('oauth2.oauth21') ?
              ', which OAuth 2.1 mode turned on' :
              (config.value('oauth2.rfc9700') ?
               ', which RFC 9700 mode turned on' : '')) +
             '), served with the same certificate LDAPS 636 uses. It is ' +
             tlsServer.certificateProvenance() +
             '. Fetch it from /tls/server-certificate and trust it — and ' +
             'fetch it WITHOUT verification the first time (curl -k), ' +
             'because with this on there is no plain port left to fetch it ' +
             'from.');
    log.info('It also ASKS for a client certificate and never requires one ' +
             '(RFC 8705): a Token Request made with one gets an access token ' +
             'bound to it — cnf["x5t#S256"] — which the protected endpoints ' +
             'then check. A request with none is unaffected.');
  }
  log.info('The front page is at / — what this service is, the project on ' +
           'GitHub, its issues, the documentation site, and the admin ' +
           'console on this instance. Every endpoint is listed inside the ' +
           'console, at /admin/sts-metadata.');
  log.info('RFC 8414 metadata at /.well-known/oauth-authorization-server; ' +
           'OpenID Provider Configuration at ' +
           '/.well-known/openid-configuration; JWKS at /oauth2/jwks');
  log.info('OID4VCI issuer metadata at ' +
           '/.well-known/openid-credential-issuer; credential endpoint at ' +
           '/oid4vci/credential');
  log.info('Issuer-initiated (OID4VCI H.1): the issuer web page is at ' +
           '/issuer; it builds a Credential Offer and sends the browser to ' +
           'the wallet.');
  log.info('Authentication service at /authn/login (the sign-in screen every ' +
           'protocol here sends a person to) and /authn/webauthn (its second ' +
           'factor).');
  log.info('Mock authorization server endpoints: /oauth2/authorize ' +
           '(redirects to /authn/login when there is no session), ' +
           '/oauth2/token, /oauth2/userinfo, /oauth2/introspect, ' +
           '/oauth2/revoke, /oauth2/register, /oauth2/logout');
  log.info('WS-Federation passive requestor at /wsfed (wsignin1.0 / ' +
           'wsignout1.0); metadata at ' +
           '/FederationMetadata/2007-06/FederationMetadata.xml; a mock ' +
           'relying party that verifies the sign-in response is at /wsfed/rp.');
  log.info('Every endpoint call, and every token or assertion before and ' +
           'after it was signed, is written to this log at debug level.');
  log.info('A SPNEGO-protected page (RFC 4559 over RFC 4178) is advertised ' +
           'at /spnego and lives at /spnego/protected; ?mic=require, ' +
           '?mech=none and ?mutual=off make the negotiation fail in one ' +
           'specific way each.');
  log.info('Every protocol, every endpoint and every specification this ' +
           'service implements is listed at /admin/sts-metadata (add ' +
           '?format=json for the machine-readable form, or use the Download ' +
           'button on the page). It is a console page, so it is behind ' +
           'the console gate like the rest of /admin — a sign-on session and ' +
           'one of two roles, unconditionally since global.mode replaced ' +
           'admin.authRequired on 2026-09-06; it was at ' +
           '/sts-metadata until 2026-08-24.');
  log.info('The management API is at /admin-api — every /admin control over ' +
           'JSON, with its OpenAPI 3.1 document at /admin-api/openapi.json ' +
           'and an explorer that calls it at /admin/api-explorer. It takes ' +
           'an OAuth 2.0 access token audienced to it, carrying admin:read ' +
           'to read and admin:write to change anything ' +
           '(adminApi.authRequired).');
  log.info('The admin console is at /admin: /admin/metrics counts every ' +
           'call, token, assertion, ticket and session; /admin/tokens lists ' +
           'every JWT, SAML assertion and Kerberos ticket issued and ' +
           'invalidates access tokens, ID Tokens and refresh tokens (only ' +
           'those three can be); /admin/claims adds custom claims to future ' +
           'tokens and /admin/saml-attributes to future assertions. It is ' +
           'NOT protected — nothing in this service is — so do not put this ' +
           'port on a public address.');
  // The KDC's sockets are started here rather than at require time so that a
  // failure to bind (port 88 is privileged) is reported by a running service
  // instead of preventing it from starting at all. GET /krb5/principals says
  // what this KDC knows; GET /admin/sts-metadata cannot see a raw socket, so
  // the listener has its own entry there.
  const kdcListeners = krb5.listen();
  // THE KDC'S TCP LISTENER TAKES THE PROXY PROTOCOL FROM HERE, not from
  // `krb5_kdc.js`: a require there would put `common/proxy_protocol.ts` into
  // the parent project's Kerberos COPY set (`kerberos/CLAUDE.md`). Installing
  // after `listen()` returned is not a race — `listen()` is synchronous up to
  // the bind, and a `connection` event is delivered from the event loop,
  // after this line. UDP is not covered: a datagram has no stream to put a
  // header at the front of.
  proxyProtocol.install(kdcListeners.tcp, {
    label: 'the KDC (TCP ' + kdcListeners.port + ')', channel: 'kerberos' });
  kdcListeners.whenReady.then(function (ready) {
    log.info('krb5: the KDC is reachable on TCP and UDP ' + ready.port + '; ' +
             'MS-KKDCP at /KdcProxy; GET /krb5/principals lists what it ' +
             'knows.');
  }).catch(function (err) {
    // Reported rather than thrown: the rest of this service is still useful,
    // and a silent failure to bind would surface later as a KDC that never
    // answers.
    log.error(errorCodes.tag('STS-CORE-0029') + 'krb5: the KDC could not ' +
                                                'start: ' + err.message);
  });
  krb5Service.listen();
  // The LDAP directory's socket, started here for the same reason the KDC's is.
  // GET /admin/ldap/service says what it is and GET /admin/ldap/directory shows
  // every entry in it;
  // GET /admin/sts-metadata cannot see a raw socket, so the listener has its
  // own entry there beside the KDC's.
  const ldapListener = ldapServer.listen();
  ldapListener.whenReady.then(function (ready) {
    log.info('ldap: the directory is reachable on TCP ' + ready.port +
             ' with base DN ' + ready.baseDn + (ready.ldapsListening
               ? ', and over LDAPS on ' + ready.ldapsPort + ' with the same ' +
                 'certificate the HTTPS listeners serve (fetch it from ' +
                 '/tls/server-certificate and trust it; it is regenerated on ' +
                 'every start)'
               : ', and NOT over LDAPS — ' + (ready.ldapsError ||
                 'it never bound') + ', which leaves the plain listener and ' +
                 'the rest of this service untouched') +
             '. Every bind succeeds except the password "invalid"; GET ' +
             '/admin/ldap/service describes it and GET /admin/ldap/directory ' +
             'lists every entry. Both are admin console pages and behind its ' +
             'gate; /admin-api mirrors them and is not.');
  }).catch(function (err) {
    // Reported rather than thrown, exactly as the KDC's failure is: the rest of
    // this service is still useful, and a silent failure to bind would surface
    // later as a directory that never answers.
    log.error(errorCodes.tag('STS-CORE-0030') + 'ldap: the directory could ' +
                                                'not start: ' + err.message);
  });
  // WHAT IS ATTESTED ON THE WORKLOAD API, READ RATHER THAN ASSERTED (#40,
  // 2026-09-21). This banner ended with *NOTHING HERE IS ATTESTED: any caller
  // that reaches the Workload API gets any identity in the trust domain* —
  // true until #40's fourth phase, and false afterwards, because the Unix
  // socket attests its caller the way a SPIRE agent does. A startup line that
  // OVERSTATES what a service checks is the worse error of the two, so this
  // one asks `spiffe_server` for the state and says what it finds: the
  // native peer-credentials module is compiled only in an image build, so a
  // development process that has none serves the socket unattested and says
  // exactly that. A caller over TCP has no peer process to ask and is not
  // attested either way — `spiffe/CLAUDE.md` argues both.
  function workloadAttestationSentence() {
    log.debug("Entering workloadAttestationSentence().");
    let state = null;
    try {
      state = spiffeServer.workloadAttestationState();
    } catch (e) {
      // An older build, or no instance: the line says less rather than
      // claiming either answer.
      log.debug("Caught in workloadAttestationSentence(): " +
                ((e && e.message) || e));
      state = null;
    }
    if (!state) {
      log.debug("Leaving workloadAttestationSentence(). Unknown.");
      return 'What is attested on the Workload API is on that page.';
    }
    if (!state.nativeModule) {
      log.debug("Leaving workloadAttestationSentence(). Unattested.");
      return 'NOTHING IS ATTESTED on the Workload API here: this build has ' +
             'no peer-credentials module (' +
             String(state.problem || 'not built') + '), so any caller that ' +
             'reaches it gets any identity in the trust domain.';
    }
    const on = (state.attestors || []).filter(function (one) {
      return one && one.enabled;
    }).map(function (one) {
      return one.type;
    });
    log.debug("Leaving workloadAttestationSentence(). Attested.");
    return 'A caller on the Workload API\'s UNIX SOCKET is ATTESTED (' +
           (on.length ? on.join(', ') : 'no attestor enabled') + '); one ' +
           'over TCP is not, and gets any identity in the trust domain.';
  }

  // The SPIFFE gRPC listeners — the Workload API and the SPIRE Server API, a
  // Unix socket and a TCP port each, per realm that has SPIFFE turned on —
  // started here for the reason the other sockets are. GET /spiffe describes
  // all three surfaces and reports whether each socket bound;
  // GET /admin/sts-metadata cannot see one, so they are described by hand
  // there beside the KDC's and the directory's.
  const spiffeListeners = spiffeServer.listen();
  spiffeListeners.whenReady.then(function (ready) {
    const up = ready.workload.concat(ready.api)
      .filter(function (b) { return b.listening; });
    const down = ready.workload.concat(ready.api)
      .filter(function (b) { return !b.listening; });
    log.info('spiffe: the trust domain ' + config.value('spiffe.trustDomain') +
             ' is served by ' + up.length + ' gRPC listener(s)' +
             (up.length ? ' — ' + up.map(function (b) { return b.address; })
               .join(', ') : '') +
             (down.length ? ', and ' + down.length + ' did NOT bind (' +
               down.map(function (b) { return b.address + ': ' + b.error; })
               .join('; ') + '), which leaves the rest of this service ' +
               'untouched' : '') +
             '. The trust bundle is at ' + spiffeServer.BUNDLE_PATH +
             ' and GET /spiffe says what is and is not checked. ' +
             workloadAttestationSentence());
  }).catch(function (err) {
    // Reported rather than thrown, exactly as the other three are.
    log.error(errorCodes.tag('STS-CORE-0031') +
              'spiffe: the SPIFFE listeners could not start: ' + err.message);
  });
  // THE PLAIN-HTTP REVOCATION LISTENER (2026-09-13): `/pki/` and nothing else,
  // because RFC 5280 section 8 and RFC 5019 section 5 put CRL and OCSP
  // addresses on http:// — see pki/pki_service.ts. Recorded rather than
  // thrown, for the reason every raw listener here is.
  require('./pki/pki_service').listen().whenReady.then(function (ready) {
    if (ready.port) {
      log.info('pki: the revocation endpoints are also on plain HTTP port ' +
               ready.port + ' (/pki/ only), which is the address every ' +
               'certificate this service issues names for its CRL, its OCSP ' +
               'responder and its issuer\'s certificate.');
    }
  }).catch(function (err) {
    log.error(errorCodes.tag('STS-CORE-0043') + 'pki: the plain-HTTP ' +
              'revocation listener could not start: ' + err.message + '. ' +
              'Every http:// CRL and OCSP address in this service\'s ' +
              'certificates will answer nothing.');
  });
  // THE EMBEDDED PROTOCOL DEBUGGER (2026-09-13): its own listener, then its
  // api child. Recorded rather than thrown like every socket here — and a
  // debugger that is not embedded, or not installed, says why on
  // /admin/debugger and costs the rest of the service nothing.
  debuggerServer.listen().whenReady.then(function (ready) {
    if (ready.port) {
      log.info('debugger: the identity protocol debugger is on port ' +
               ready.port + ', for console administrators signed in ' +
               'through this service. /admin/debugger reports it.');
    }
  }).catch(function (err) {
    log.error(errorCodes.tag('STS-DBG-0016') + 'debugger: the listener ' +
              'could not start: ' + err.message);
  });
  // THE TWO TLS LISTENERS WERE DELETED ON 2026-09-16 (8443 and 9443). What
  // they did that was worth keeping now happens on THIS port: a client
  // certificate is asked for and never required, whatever arrives is recorded,
  // and GET /tls/sign-in turns a verified one into a session. `listen()` was
  // kept so that this call site and the tests did not have to change on the
  // same day the sockets went; it binds nothing, and still restores the stored
  // trust anchors and re-applies the context to the registered listeners.
  tlsServer.listen();
  // A scheduler job and not a socket (#49 P5), registered here where its
  // timer used to start: the job saml2.sp-metadata-refresh, once for the
  // cluster, on the leader (see sp_metadata.ts).
  spMetadata.startRefresher();
  log.info('tls: this port asks every connection for a client certificate ' +
           'and requires none, so presenting one is the client\'s decision. ' +
           'GET /tls/sign-in signs the holder of a verified one in; the token ' +
           'endpoint binds a token to it (RFC 8705); /tls shows the ' +
           'certificate this service presents. The client truststore starts ' +
           'EMPTY — POST the issuing CA to /tls/trust — because the CA it has ' +
           'to verify is usually generated in a browser minutes before the ' +
           'connection.');
  log.debug('Leaving announce().');
}

// ---------------------------------------------------------------------------
// SHUTTING DOWN, WHICH BEFORE 2026-08-27 THIS SERVICE DID NOT HAVE TO DO.
//
// It held nothing worth keeping, so a `docker stop` or a Ctrl-C could simply
// end the process and did. Now the directory, the realm registry and the
// runtime appconfig overrides may be on their way to a disk or a database, so
// there is a last flush to perform — and in ldif mode a change made in the last
// `persistence.writeDelay` milliseconds is only in memory until it happens.
//
// SIGTERM is what `docker stop`, Kubernetes and systemd send; SIGINT is Ctrl-C.
// `kill -9` sends SIGKILL, which cannot be trapped by anything, and what that
// costs is stated in `persistence.writeDelay`'s own description rather than
// hidden.
//
// The handler is installed ONCE for both signals and is idempotent: a second
// signal while the flush is in flight must not start a second one, which is
// what `stopping` is for. A person pressing Ctrl-C twice because the first
// press seemed not to work is the ordinary case, not the exotic one.
// ---------------------------------------------------------------------------
let stopping = false;

function shutdown(signal) {
  log.debug('Entering shutdown(). signal=' + signal);
  if (stopping) {
    log.info('sts: a second ' + signal + ' arrived while shutting down; ' +
             'still finishing the last write.');
    log.debug('Leaving shutdown(). Already stopping.');
    return;
  }
  stopping = true;
  log.info('sts: ' + signal + ' received. Flushing anything not yet written ' +
           'down, then exiting. Sessions, tokens, codes, artifacts and ' +
           'tickets are not persisted and are going with this process, which ' +
           'is what they have always done.');
  // THE COMPUTATION POOL IS DRAINED rather than killed: a child
  // part way through an SLH-DSA signature is answering a request this process
  // still has open, and thirteen seconds of computation thrown away is a
  // request that gets nothing back. It gives them five seconds and kills what
  // is left, which costs nothing — a worker holds no state. It resolves rather
  // than rejects for the same reason persistence.stop() does: the only move
  // left here is to exit, and a rejection would replace the sentence that says
  // what was flushed with a stack trace. See common/worker_pool.js.
  // ---------------------------------------------------------------------
  // THE REQUEST WORKERS GO FIRST, AND THE ORDER IS A DEPENDENCY RATHER THAN A
  // PREFERENCE: a request worker that is still finishing a response may be
  // waiting on a post-quantum signature from the COMPUTATION pool, so draining
  // that pool first would fail the job the request is blocked on and turn a
  // clean shutdown into a truncated answer.
  // ---------------------------------------------------------------------
  // The debugger's api child first: it is not a worker of either pool and
  // holds nothing worth draining, and an orphan would keep its socket.
  // The scheduler first of all: no job may start while the process drains.
  // A run in progress is left to finish or be fenced out; its claim lapses
  // and the next leader takes it over.
  require('./cluster/scheduler').stop();
  debuggerServer.close().catch(function (e) {
    log.debug('Caught in shutdown(): ' + ((e && e.message) || e));
  }).then(function () {
    return requestPool.stop();
  }).then(function (drained) {
    if (drained.stopped || drained.killed) {
      log.info('sts: ' + drained.stopped + ' request worker(s) finished and ' +
               drained.killed + ' had to be killed.');
    }
    return workerPool.stop();
  }).then(function (drained) {
    if (drained.stopped || drained.killed) {
      log.info('sts: ' + drained.stopped + ' worker process(es) finished and ' +
               drained.killed + ' had to be killed.');
    }
    return persistence.stop();
  }).then(function () {
    log.info('sts: stopped.');
    process.exit(0);
  }).catch(function (err) {
    // stop() already logs its own failure and does not reject in the ordinary
    // case; this exists so that an unexpected one still ends the process
    // rather than leaving it hanging with no listener and no explanation.
    log.error(errorCodes.tag('STS-CORE-0033') + 'sts: the shutdown flush ' +
                                                'failed: ' + err.message);
    process.exit(1);
  });
  log.debug('Leaving shutdown().');
}

process.on('SIGTERM', function () { shutdown('SIGTERM'); });
process.on('SIGINT', function () { shutdown('SIGINT'); });

// ---------------------------------------------------------------------------
// AND THE ORDER OF THE LAST TWO THINGS THIS FILE DOES, WHICH IS A DEPENDENCY.
//
// `persistence.start()` opens the store, applies any saved runtime appconfig
// overrides, re-creates the trust realms that were defined last time, and
// replaces each realm's seeded directory with what was written down. THEN the
// listener binds.
//
// It has to be that way round, and not for tidiness: between binding and
// restoring, this service would answer `/oauth2/authorize` out of a seeded
// directory, `/admin/applications` out of an empty registry and
// `/federation/acs/{id}` out of a register with no relationships in it — and
// that last one is a security surface, where "the relationship is not
// configured yet" and "the relationship is disabled" are the same refusal for a
// caller and very different facts. A restore that lands halfway through a
// federated sign-in is not a race anybody should have to think about, so there
// is no window in which it can happen.
//
// **A CONFIGURED STORE THAT CANNOT BE OPENED OR READ STOPS THE SERVICE, AND
// THIS PARAGRAPH SAID THE OPPOSITE UNTIL 2026-08-28.**
//
// It used to say that start() caught its own failures, fell back to memory and
// resolved — that a Postgres container which was not up yet left a mock
// running with its seeded directory rather than a container that exited, and
// that refusing to start because a database blinked would be the one failure
// mode a mock must not have.
//
// The half of that which was right is still right and is still the behaviour:
// a store that breaks WHILE RUNNING is recorded and the service carries on
// answering — see flush(), which puts the dirty bits back and retries on the
// next change. What was wrong was doing the same thing at STARTUP, because the
// two states are not alike. A running service that loses its database has
// already restored everything it was going to restore and is still telling the
// truth about what it holds. A service that never opened the store is
// answering out of a SEEDED directory while presenting itself as the one that
// was configured — every endpoint works, the console draws, and the realms,
// applications and federation partners somebody creates are thrown away by the
// next restart, which is the restart they will do because they expected the
// work to survive it.
//
// So: `persistence.mode=memory`, the default, reaches none of this and behaves
// exactly as it always has. Any OTHER mode is a statement that this process is
// supposed to persist, and a process that cannot keep that statement exits
// non-zero and says which setting to look at, rather than running as something
// it is not. The compose file's `depends_on: condition: service_healthy` is
// what stops that being a startup race, and it was already there.
//
// A NON-ZERO EXIT rather than a throw: this is the last thing an operator
// sees, and an unhandled rejection would print a stack trace over the sentence
// that says what to do about it.
// ---------------------------------------------------------------------------
// The credential verifier, for the product-mode bootstrap below. A LEAF
// (rule 3) that registers no route, so this require adds nothing to the router.
const credentials = require('./common/credentials');
// The console roles, for the bootstrap administrator below. A LIBRARY (rule 3)
// that the protocol stack has already loaded, so this is a cache hit that
// registers no route.
const adminRbac = require('./admin-ui/admin_rbac');
// The keystore, for the product-mode key material. A LEAF (rule 3).
const keystore = require('./common/keystore');
// The startup steps, shared with a request worker. See that file.
const serviceState = require('./common/service_state');
// The PROXY protocol v2 reader, a LIBRARY (rule 3): installed on the main
// listener in bind() and on the KDC's TCP listener in announce(), and asked
// once, below, whether this process may start at all. See that file.
const proxyProtocol = require('./common/proxy_protocol');
const clientHello = require('./tls/client_hello');

// ---------------------------------------------------------------------------
// THIS PROCESS'S STATE, IN THE ONE ORDER THERE IS.
//
// The steps — the store, the signing keys, what this process minted,
// coordination and (since 2026-09-11) the certificate authority — moved to
// `common/service_state.ts` on 2026-09-07, because a REQUEST WORKER has to run
// exactly the same steps in exactly the same order. Each step's argument is
// in that file, where it has always been.
// ---------------------------------------------------------------------------
serviceState.start().then(function (both) {
  const started = both.started;
  // THE PROXY PROTOCOL WITH NOBODY TRUSTED (2026-09-14, #46): refused here,
  // after the store restored any runtime `global.trustedProxies` and before
  // anything binds, for the reason `startupProblem()` gives — such a process
  // either refuses every client or lets any caller name any address.
  const proxyProblem = proxyProtocol.startupProblem();
  if (proxyProblem) {
    log.fatal(errorCodes.tag('STS-PROXY-0009') + 'sts: NOT STARTING. ' +
              proxyProblem);
    process.exit(1);
  }
  if (started.mode !== 'memory') {
    const mintedStatus = persistence.mintedStatus();
    log.info('sts: persistence is ' + started.mode + '. The embedded ' +
             'directory, the trust realm registry and any runtime setting ' +
             'changes are written down and were restored at startup. ' +
             (mintedStatus.persisting
               // THE SENTENCE THIS REPLACED SAID "NOTHING THIS SERVICE MINTS
               // is persisted in any mode", and it was true until product mode
               // learned to keep its signing keys. It is kept below WORD FOR
               // WORD for the configuration it is still true of, because the
               // half-remembered version of this — "the mock persists tokens
               // now" — is worse than either version.
               ? 'AND SO IS WHAT IT MINTS: sessions, tokens, codes, ' +
                 'artifacts, Kerberos tickets, the counters and the audit ' +
                 'log, each row encrypted under the same key-encryption key ' +
                 'as the signing keys. ' + both.minted.restored + ' row(s) ' +
                 'were restored. This is PRODUCT mode on a ' + started.mode +
                 ' store; development mode persists none of it, because the ' +
                 'signing key is regenerated on every start there and a ' +
                 'restored token would verify against nothing.'
               : 'NOTHING THIS SERVICE MINTS is persisted in this ' +
                 'configuration — the signing key is regenerated on every ' +
                 'start, so a token that outlived it would verify against ' +
                 'nothing. Product mode on a postgres store persists all of ' +
                 'it' + (mintedStatus.unsupportedReason
                          ? '; here, ' + mintedStatus.unsupportedReason : '') +
                 '.'));
  }
  // THE PRODUCT-MODE BOOTSTRAP, AFTER THE STORE AND BEFORE THE LISTENER.
  //
  // After, because a persisted directory is restored by `persistence.start()`
  // and a deployment whose administrator is in that store must not get a second
  // account created beside them — the check is "does anybody hold a
  // credential", and before the restore the answer would always be no.
  //
  // Before the listener binds, so that the service is reachable the moment it
  // answers rather than for however long it takes somebody to read the log.
  //
  // It does nothing in development mode and nothing in a realm where somebody
  // already holds a credential; see credentials.bootstrap().
  // THE BOOTSTRAP ADMINISTRATOR FIRST (2026-09-13): `admin.bootstrapUsername`
  // in the default realm, made if absent, in both console roles, and forced to
  // change its password at its first sign-in. `credentials.bootstrap()` below
  // then gives that account its generated password in product mode. See
  // admin-ui/admin_rbac.ts's seedBootstrapAdministrator().
  //
  // **ONCE FOR THE CLUSTER, SINCE 2026-09-14 (#46 section 8).** Several nodes
  // cold-started against one empty store each seeded the account and each
  // printed a password, and only the last writer's worked — or none, when a
  // node's seed landed after another node's password. Both steps now run
  // inside `credentials.bootstrapOnce()`, one claim per realm: the node that
  // wins does them after catching up with the store, and every other node
  // does neither and says which node is. It is awaited below, before the
  // request workers start, so the listener still binds only after it ran.
  const bootstrapUsername = config.value('admin.bootstrapUsername');
  const otherRealms = realms.list().filter(function (realm) {
    return realm.id !== realms.DEFAULT_ID;
  });
  const bootstrapped = realms.run(realms.DEFAULT_REALM, function () {
    return credentials.bootstrapOnce(realms.DEFAULT_ID, function () {
      adminRbac.seedBootstrapAdministrator();
      // A CONSOLE NOBODY CAN ENTER IS SAID HERE, ONCE (#103): product mode
      // never opens it to whoever signs in, so a realm left with no bootstrap
      // administrator and an empty roster is logged under STS-ADMIN-0798
      // rather than discovered by being refused.
      adminRbac.reportClosedConsole();
      return credentials.bootstrap({ username: bootstrapUsername });
    });
  }).then(function () {
    // AND EVERY TRUST REALM THIS PROCESS STARTED WITH (2026-09-14, #32): each
    // has an administrator of its own, confined to it. A realm created while
    // running is given one by the create action itself; this is for a realm
    // restored from the store that predates the feature, or whose account was
    // removed. Both steps are idempotent, exactly as they are for the default
    // realm above — and one realm at a time, each under its own claim.
    return otherRealms.reduce(function (chain, realm) {
      return chain.then(function () {
        return realms.run(realm, function () {
          return credentials.bootstrapOnce(realm.id, function () {
            adminRbac.seedBootstrapAdministrator(realm.id);
            adminRbac.reportClosedConsole(realm.id);
            return credentials.bootstrap({ username: bootstrapUsername });
          });
        });
      });
    }, Promise.resolve());
  });

  // ---------------------------------------------------------------------
  // THE REQUEST WORKERS, AND THEY COME UP BEFORE THE LISTENER DOES.
  //
  // A FOURTH asynchronous step in this chain, and it is here for the reason
  // the three above it are here rather than at a require: forking a request
  // worker means loading the whole protocol stack in a child, seeding its
  // directory and generating a realm's keys, which takes seconds and cannot
  // be awaited from a `require`.
  //
  // **BEFORE `bind()` is the whole point.** The computation pool above is
  // LAZY — it forks on the first post-quantum job, because a process that
  // never signs one must not pay for a pool. This one is EAGER, because the
  // cost is paid per WORKER rather than per job: forking on the first request
  // would make that request wait for the entire service to load. Here nobody
  // is waiting, because this process is not answering yet.
  //
  // It never rejects. A pool that could not start is reported loudly and the
  // front process handles every request itself, which is what
  // `workers.requestCount = 0` means — a slow service rather than none.
  // ---------------------------------------------------------------------
  // EVERY PROCESS PRESENTS AND PINS THE SAME CERTIFICATE. Handed over before
  // the pool forks anything — see request_pool.js's setServerCertificate() for
  // why it travels this way round, and tls_server.js for what went wrong when
  // each worker made its own.
  // **THE CHAIN AND THE ANCHOR TRAVEL WITH IT (2026-09-11), AND LEAVING THEM
  // BEHIND WAS A REAL FAILURE RATHER THAN AN OMISSION.** A worker was handed
  // the leaf and the key and nothing else, so it had no chain to present and
  // — worse — `trustAnchorPems()` fell back to asking `common/pki.js` for the
  // Root, which in a worker is a Root that worker built itself. The certificate
  // came from the front process and the anchor came from the worker, they were
  // from different hierarchies, and `/portal` and `/admin` failed their own
  // back channel with `unable to get local issuer certificate`. Both halves
  // have to come from the process that made the certificate.
  const tlsMaterial = tlsServer.serverCertificate();
  requestPool.setServerCertificate({ certPem: tlsMaterial.certPem,
                                     keyPem: tlsMaterial.privateKeyPem,
                                     chainPem: tlsMaterial.chainPem,
                                     trustAnchorPem:
                                       tlsMaterial.trustAnchorPem,
                                     // The other leaves the socket presents
                                     // (#248), public like the chain.
                                     extraCertPems: tlsServer
                                       .presentedCertificatePems()
                                       .slice(1) });
  // THE BBS PAIR IS NOT HANDED OVER HERE ANY MORE (2026-09-22, #49 P5): it is
  // a member of each realm's key set, so it reaches the workers in the key
  // sets the pool already sends (`keystore.sharedAll()`), and was made per
  // realm on first use. The bootstrap is still awaited first — a bootstrap
  // that throws is fatal at startup.
  // EVERY PRODUCT REALM'S FIRST KRBTGT KEY (#169, 2026-09-23), after the
  // bootstrap and before the request workers fork or the listener binds, so a
  // KDC has its random krbtgt key before its first request — made once for
  // the cluster, under a claim per realm, by whichever node wins it. Never
  // rejects: a realm left without a key refuses at its KDC and says why.
  const krbtgtReady = bootstrapped.then(function () {
    return require('./kerberos/krb5_krbtgt_rotation').ensureAll();
  }).then(function (made) {
    (made || []).forEach(function (one) {
      if (one && one.ok === false) {
        log.warn('sts: trust realm "' + (one.realm || 'default') + '" has ' +
                 'no krbtgt key yet (' + (one.why || 'see above') + '); its ' +
                 'KDC refuses until one is made.');
      }
    });
    return made;
  });
  return krbtgtReady.then(function () {
    // THE MAIL CHANNEL (#63): in PRODUCT, a realm whose configured transport
    // cannot be built — a missing SDK, an unreadable secret, `capture` — is
    // a service that would promise reset links it cannot send, and it does
    // not start. Asked here, after the store restored every realm's settings
    // and before anything forks or binds. Development answers '' whatever it
    // finds (common/mail.ts, startupProblem()).
    return require('./common/mail').startupProblem();
  }).then(function (mailProblem) {
    if (mailProblem) {
      // error-code: none — the problem's own STS-MAIL code leads the message
      log.fatal(mailProblem + ' The service is NOT STARTING.');
      process.exit(1);
    }
    return requestPool.start().then(function (pool) {
      if (pool.wanted) {
        log.info('sts: ' + pool.started + ' of ' + pool.wanted + ' request ' +
                 'worker(s) are serving' +
                 // Per pool, when the hosted surfaces have workers of their
                 // own — see common/request_pool.js's two-pools block.
                 ((pool.pools || []).some(function (one) {
                   return one.pool !== 'protocol' && one.wanted;
                 })
                   ? ' (' + pool.pools.map(function (one) {
                     return one.started + ' of ' + one.wanted + ' ' + one.pool;
                   }).join(', ') + ')'
                   : '') +
                 (requestPool.dispatchPrefixes().length
                   ? '; dispatching ' +
                     requestPool.dispatchPrefixes().join(', ')
                   : '. NOTHING IS DISPATCHED TO THEM — workers.dispatch is ' +
                     'empty, so every request is still handled here') + '.');
      }
      // -------------------------------------------------------------------
      // THE SCHEDULER (2026-09-22, #49), AND IT STARTS HERE AND NOWHERE
      // EARLIER. Every periodic job in this service — the session-expiry
      // sweep, the CRL directory refresh — is registered with it when its
      // module loads, and nothing runs until this line: after the store, the
      // keys, the minted rows, coordination and the certificate authority are
      // restored, which is the whole of an active-passive standby's reason to
      // wait, and never in a request worker, which starts it in per-process
      // mode for itself. A front process campaigns for `ops.scheduler`; with
      // clustering off it leads at once. See cluster/scheduler.ts.
      // -------------------------------------------------------------------
      require('./cluster/scheduler').start('front');
      bind();
    });
  });
}).catch(function (err) {
  // Both kinds of failure arrive here and both are fatal: a store that was
  // configured and could not be opened or read, and a programming error in the
  // restore path. They are not told apart on purpose — either way this process
  // was told to persist and cannot, and the difference is in the message
  // start() built rather than in what is done about it.
  // THE KEYSTORE'S FAILURES ARRIVE HERE TOO SINCE 2026-09-06, and they need a
  // different sentence: a store that cannot be opened and a signing key that
  // cannot be DECRYPTED are both fatal, and only one of them is about the
  // database. Told apart on the message rather than on a flag, because
  // keystore.js writes a complete explanation and this only has to choose which
  // paragraph follows it.
  // A CLUSTER REFUSAL (2026-09-14, #46) carries its whole explanation — which
  // mode, which setting, which node differs — and neither paragraph below is
  // about it: the store opened and the keys are fine. See cluster/cluster.js.
  if (/STS-CLUSTER-\d{4}/.test(err.message || '')) {
    // error-code: none — the refusal's own STS-CLUSTER code leads err.message
    log.fatal(err.message + ' The service is NOT STARTING.');
    process.exit(1);
  }
  if (/key material|key-encryption key|signing key|minted state/i.test(
      err.message || '')) {
    log.fatal(errorCodes.tag('STS-CORE-0035') + 'sts: NOT STARTING. ' +
              err.message +
              '\n\nThis service will not generate a replacement signing key ' +
              'and carry on. Doing that would silently stop every token, ' +
              'assertion and signed document it has ever issued from ' +
              'verifying — at somebody else\'s relying party, with nothing ' +
              'in any log here to point at. Fix the key-encryption key ' +
              '(keys.kekProvider=' + require('./common/config').value(
                  'keys.kekProvider') +
              '), or set keys.source=generated to accept a new key on every ' +
              'start, which is what development mode does.');
    process.exit(1);
  }
  log.fatal(errorCodes.tag('STS-CORE-0036') + 'sts: NOT STARTING. ' +
            err.message +
            '\n\nThis service is configured to persist (persistence.mode=' +
            persistence.mode() + '), so it will not run without its store: a ' +
            'process answering out of a seeded directory while presenting ' +
            'itself as the one that was configured loses everything anybody ' +
            'does with it at the next restart. Fix the store, or set ' +
            'persistence.mode=memory (STS_PERSISTENCE_MODE) to run without ' +
            'one — which is the default and what this service did before ' +
            'persistence existed.');
  process.exit(1);
});

// Built rather than started above, because the two shapes differ only in this
// one expression and writing the whole announcement twice is how the two
// versions of it come to say different things.
function bind() {
log.debug("Entering bind().");
if (useHttps) {
  const serverCert = tlsServer.serverCertificate();
  const mainServer = https.createServer(Object.assign({
    cert: serverCert.certPem,
    key: serverCert.privateKeyPem,
    // THE CLIENT TRUSTSTORE, THE ONE /tls/trust FILLS (2026-09-06; it
    // covered 8443 and 9443 too until they were deleted on 2026-09-16).
    // Passed at creation AND kept current by the registration below, because
    // anchors arrive at runtime — the CA a caller presents a
    // client certificate from does not exist anywhere until somebody POSTs it.
    //
    // WHAT IT CHANGES AND WHAT IT DOES NOT. Before this, `socket.authorized`
    // was false for every client certificate ever presented on this port,
    // because there was no `ca` to build a path to; a certificate could be
    // thumbprinted and bound to a token and never RECOGNISED. That was right
    // while RFC 8705 binding was the only reader — it binds to the certificate
    // and does not care who vouched for it — and it stopped being right when
    // the remote XACML PEP arrived, because that caller's DN has to resolve to
    // a directory entry, a group and a role, and none of that may rest on a
    // certificate nobody issued.
    ca: tlsServer.clientTruststoreOptions().ca,
    // RFC 8705 — certificate-bound access tokens. The token endpoint is on this
    // listener, so a certificate has to be ASKED FOR here or there is never one
    // to bind to. Asked for, never required — and since the 9443 listener was
    // deleted on 2026-09-16, no HTTPS listener in this service requires one.
    //
    // `rejectUnauthorized: false` looks like a hole and is not. A certificate
    // that built no chain to a trusted anchor is still thumbprinted and still
    // binds the token, because RFC 8705 section 3 binds to the CERTIFICATE and
    // explicitly permits a self-signed one — the proof is that the same key
    // completed this handshake, not that a CA vouched for it. Requiring
    // verification would also make the feature unreachable, since the
    // truststore at /tls/trust starts empty by design.
    requestCert: true,
    rejectUnauthorized: false
  // `tls.minVersion` and `tls.ciphers` (2026-09-12), from the module that
  // states them for every TLS listener — at creation as well as on every
  // truststore change, so the first handshake is held to the same floor as the
  // hundredth.
  }, tlsServer.protocolOptions()), app);
  // REGISTERED SO THAT A LATER `POST /tls/trust` REACHES THIS LISTENER TOO.
  // `tls_server.js` owns the anchors and applies them to every listener it
  // knows about; this is how the one it did not create becomes one of them. It
  // is a registration rather than a require in the other direction because
  // this file requires that module, not the other way round.
  tlsServer.trustClientCertificatesOn(mainServer,
                                      'the main port (' + PORT + ')');
  // AND SO THAT A CLIENT CERTIFICATE PRESENTED HERE IS WRITTEN DOWN
  // (2026-09-16). The sighting hung on the 8443 and 9443 listeners'
  // `secureConnection` until they were deleted, so the main port — where every
  // certificate that authenticates a client, a remote PEP or a SCIM caller
  // actually arrives — recorded nothing, and /admin/tls looked quiet while
  // they came in. It also logs a failed handshake, which is otherwise
  // invisible: the far end sees a closed socket and this log said nothing.
  tlsServer.observeConnectionsOn(mainServer,
                                 'the main port (' + PORT + ')');
  // THE LEAVES THIS PORT PRESENTS GO ON THIS NODE'S CLUSTER ROW (#248), and
  // again whenever the listener is re-issued: the SAML identity provider's
  // metadata publishes the back channel's certificate, and behind a balancer
  // that is every live node's (`cluster/cluster.js`). A no-op outside a
  // cluster — nothing reads the row. Required here, where it is first needed,
  // like the listener's other late wiring.
  const clusterMembership = require('./cluster/cluster');
  clusterMembership.setListenerCertificates(
    tlsServer.presentedCertificatePems());
  tlsServer.onServerCertificateChange(function () {
    clusterMembership.setListenerCertificates(
      tlsServer.presentedCertificatePems());
  });
  // THE CLIENT'S JA4 TLS FINGERPRINT (#62 P0, 2026-09-22), read off the
  // ClientHello before the TLS engine takes the socket — see
  // tls/client_hello.ts. Installed BEFORE the PROXY protocol below, so that
  // one's wrapper is the outer one and this reads a socket whose header is
  // already gone.
  clientHello.install(mainServer, { label: 'the main port (' + PORT + ')' });
  // The PROXY protocol header comes off BEFORE the TLS handshake — see
  // common/proxy_protocol.ts. A no-op with global.proxyProtocol off.
  proxyProtocol.install(mainServer, { label: 'the main port (' + PORT + ')',
                                      channel: 'http' });
  mainServer.listen(PORT, HOST, announce);
} else {
  // `http.createServer(app)` rather than `app.listen()`, which is the same
  // thing with the server object hidden — and the PROXY protocol has to be
  // installed on that object before it listens.
  const plainServer = http.createServer(app);
  proxyProtocol.install(plainServer, { label: 'the main port (' + PORT + ')',
                                       channel: 'http' });
  plainServer.listen(PORT, HOST, announce);
}
log.debug("Leaving bind().");
}
