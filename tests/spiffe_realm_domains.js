'use strict';
//
// File: tests/spiffe_realm_domains.js
//
// ===========================================================================
// A TRUST DOMAIN PER REALM, AND A SOCKET PER REALM (2026-09-12).
//
// Until this date SPIFFE was the one family in this service with NO realm
// discriminator at all: `realms.realmSupport()` reported it `none`, and the
// reason was two facts rather than one. The trust domain was a module constant
// read once at require time — `spiffe_ca.js`'s own header carried the argument
// — and the four gRPC sockets answered in the default realm because nothing
// entered a realm for them.
//
// Both are reversed now, at rcbj's instruction, and the instruction named the
// shape: *a common root domain + a unique issuer for each domain*, and *for
// the SPIFFE service, a unique IP will be used*. So a realm created here is
// given `<realm>.<the process's trust domain>`, and a realm whose SPIFFE is
// turned on binds sockets of its own.
//
// ---------------------------------------------------------------------------
// WHY THIS IS IN PROCESS, WHICH IS THIS DIRECTORY'S ONE RULE.
//
// Every claim here is about a SOCKET THIS SERVICE BINDS, and no stack publishes
// a realm's — `docker-compose.yml` publishes no SPIFFE port at all, not even
// the default realm's 8092 and 8181, on the argument `tests/CLAUDE.md` makes
// about the directory's own port. So the choice is between binding them here,
// in the process the assertions are already in, and inventing a stack whose
// whole content is a second realm.
//
// **AND THE ONE THING THAT COULD NOT BE ASSERTED OVER HTTP EITHER WAY**: that
// a call arriving on one realm's socket is answered in THAT realm. Over gRPC
// there is no path segment to carry a realm — the method name is fixed by the
// Workload API specification — so the endpoint address is the discriminator,
// and what that means is a property of the handler table this file can reach
// and a client cannot.
// ===========================================================================

const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');
const fs = require('fs');

const config = require('../common/config');
const realms = require('../common/realms');
const ca = require('../spiffe/spiffe_ca');
const spiffeId = require('../spiffe/spiffe_id');
const server = require('../spiffe/spiffe_server');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'spiffe_realm_domains',
  level: process.env.LOG_LEVEL || 'info' });

// Two realms, LEFT STANDING for `tests/spiffe_pki.js`'s reason: removing one
// takes its PKI branch with it and the next file in the run is entitled to
// find the default realm as it was. The ids are distinctive so that a stack
// somebody kept can be read afterwards.
const REALM_A = 'spiffe-domains-a';
const REALM_B = 'spiffe-domains-b';

// A directory of this run's own for the realms' Unix sockets. The seeded
// paths are under `/tmp/spire-agent/public/<realm>/`, which is right for a
// deployment and wrong for a test: a run that crashed would leave sockets in
// the place a real client looks.
const SOCKET_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-spiffe-realms-'));

function makeRealm(t, id, overrides) {
  log.debug("Entering makeRealm().");
  const made = realms.create({ id: id, name: id,
                               overrides: overrides || {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving makeRealm().");
    return null;
  }
  log.debug("Leaving makeRealm().");
  return made.realm;
}

// A free TCP port, found the way every other test here finds one: bind zero,
// read what the kernel gave, close. There is a race with anything else on the
// machine and it is the same race every port-using test in this repository
// runs; what it buys is that this file does not need a fixed port nobody else
// may have.
function freePort() {
  log.debug("Entering freePort().");
  const net = require('net');
  log.debug("Leaving freePort().");
  return new Promise(function (resolve, reject) {
    const srv = net.createServer();
    srv.on('error', reject);
    // `listen()` is ASYNCHRONOUS and `address()` is null until it has fired,
    // which is what the first version of this got wrong — `Cannot read
    // properties of null (reading 'port')`, in a helper whose whole job is
    // one number.
    srv.listen(0, '127.0.0.1', function () {
      const port = srv.address().port;
      srv.close(function () { resolve(port); });
    });
  });
}

// One `FetchX509Bundles` call over a Unix socket, with the security header the
// Workload API requires. The proto definitions come from `spiffe_grpc.js` so
// that the client and the server are loaded from ONE copy of the vendored
// `.proto` files — a second load here would be a second answer to what the
// wire format is, which is the trap that module's own header records.
function fetchBundlesOver(socketPath) {
  log.debug("Entering fetchBundlesOver().");
  const rpc = require('../spiffe/spiffe_grpc');
  const client = new (rpc.grpc.makeGenericClientConstructor(
    rpc.SERVICES.workload, 'SpiffeWorkloadAPI'))(
      'unix://' + socketPath, rpc.grpc.credentials.createInsecure());
  const metadata = new rpc.grpc.Metadata();
  metadata.set(rpc.SECURITY_HEADER, 'true');
  log.debug("Leaving fetchBundlesOver().");
  return new Promise(function (resolve, reject) {
    const stream = client.FetchX509Bundles({}, metadata);
    let answered = false;
    stream.on('data', function (message) {
      answered = true;
      // ONE message is all this needs: the stream stays open and re-sends on
      // rotation, which is the Workload API's contract and not this file's
      // subject.
      resolve(message);
      stream.cancel();
      client.close();
    });
    stream.on('error', function (err) {
      if (!answered) {
        reject(err);
      }
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  // -------------------------------------------------------------------------
  // 1. A REALM IS BORN WITH A TRUST DOMAIN OF ITS OWN, UNDER THE COMMON ROOT.
  // -------------------------------------------------------------------------
  t.log.info('=== the seeded trust domain ===');
  const root = ca.processTrustDomain();
  const realmA = makeRealm(t, REALM_A);
  if (!realmA) {
    log.debug("Leaving run().");
    return;
  }
  // THE REALM'S DOMAIN IS ITS TRUST DOMAIN since 2026-09-18; it was
  // `<realm>.<the process's trust domain>` until then. Created with no domain
  // of its own, the realm's is `<realm>.<global.domain>`.
  const domainA = realms.domainOf(REALM_A);
  t.equal(domainA, REALM_A + '.' + realms.domainOf(realms.DEFAULT_ID),
          'a realm created without a domain is given <realm>.<global.domain>');
  t.equal(realmA.overrides['spiffe.trustDomain'], domainA,
          'a realm is CREATED with its DOMAIN as its trust domain — unique ' +
          'because the domain is, which is the reason this sits beside the ' +
          'entityID and the providerID in realms.js rather than in a getter');
  t.equal(realmA.overrides['spiffe.enabled'], false,
          'AND WITH SPIFFE OFF, because turning it on BINDS SOCKETS: a realm ' +
          'that bound two listeners merely by existing would make ' +
          'POST /admin-api/realms/create an operation that opens ports');
  t.check(String(realmA.overrides['spiffe.workloadSocket'] || '')
            .indexOf('/' + REALM_A + '/') > 0,
          'and with a Workload API socket path of its own — two realms ' +
          'cannot bind one path, and an inherited one would fail to bind or, ' +
          'on a stale socket, take it away from the realm that had it',
          String(realmA.overrides['spiffe.workloadSocket']));

  t.equal(ca.trustDomain(REALM_A), domainA,
          'the CA answers with the realm\'s own domain — it read a module ' +
          'constant captured at require time until 2026-09-12, which is the ' +
          'whole of why SPIFFE was `none` in realms.realmSupport()');
  t.equal(ca.trustDomain(), root,
          'and the default realm is unchanged, which is the property every ' +
          'client of this service already depends on');

  // A realm may name its own outright — it does not have to sit under this
  // root, and a realm deliberately sharing another's is a thing worth being
  // able to build on a mock.
  const realmB = makeRealm(t, REALM_B,
                           { 'spiffe.trustDomain': 'named.example.test' });
  if (!realmB) {
    log.debug("Leaving run().");
    return;
  }
  t.equal(ca.trustDomain(REALM_B), 'named.example.test',
          'a realm created with a trust domain of its own KEEPS it — the ' +
          'caller\'s overrides win over the seeded ones, exactly as they do ' +
          'for an entityID');

  // -------------------------------------------------------------------------
  // 2. THE NAME IS FIXED WHEN THE AUTHORITIES ARE BUILT, AND THE DISAGREEMENT
  //    IS REPORTED RATHER THAN ACTED ON.
  // -------------------------------------------------------------------------
  t.log.info('=== fixed at build, and the drift ===');
  await ca.ready(REALM_A);
  const built = ca.state(REALM_A);
  t.equal(built.trustDomain, domainA,
          'the realm\'s authorities are built under its own domain');
  t.equal(built.trustDomainDrift, null,
          'and nothing has drifted yet');

  const moved = realms.setOverride(REALM_A, 'spiffe.trustDomain',
                                   'moved.example.test');
  t.check(moved.ok,
          'spiffe.trustDomain may be SET ON A REALM — it is restart-only for ' +
          'the process, because the process builds its authorities at ' +
          'startup, and a realm builds its own when it is turned on',
          (moved.errors || []).join(' '));
  t.equal(ca.trustDomain(REALM_A), domainA,
          'but the BUILT name goes on being used, because every certificate ' +
          'this realm has issued names it — changing it underneath would be ' +
          'the silent disagreement config.js exists to prevent');
  const drift = ca.state(REALM_A).trustDomainDrift;
  t.check(!!drift && drift.configured === 'moved.example.test' &&
          drift.built === domainA,
          'AND THE DISAGREEMENT IS PUBLISHED rather than hidden — a page ' +
          'showing one of the two would be the same defect wearing a report',
          JSON.stringify(drift));
  realms.setOverride(REALM_A, 'spiffe.trustDomain', domainA);

  // -------------------------------------------------------------------------
  // 3. AN SVID NAMES THE REALM'S OWN TRUST DOMAIN, AND THE OTHER REALM'S
  //    BUNDLE DOES NOT VERIFY IT.
  // -------------------------------------------------------------------------
  t.log.info('=== what an SVID says ===');
  await ca.ready(REALM_B);
  const idA = spiffeId.make(ca.trustDomain(REALM_A), '/workload/probe');
  const svidA = await ca.mintX509Svid(idA, { realm: REALM_A });
  const certA = new nodeCrypto.X509Certificate(svidA.certificatePem);
  t.check(String(certA.subjectAltName || '').indexOf(idA) >= 0,
          'the SVID minted in realm A carries realm A\'s trust domain in its ' +
          'URI subjectAltName',
          String(certA.subjectAltName));

  const jwtA = await ca.mintJwtSvid(idA, ['probe'], { realm: REALM_A });
  const checkedHere = await ca.validateJwtSvid(jwtA.token, 'probe',
                                               { realm: REALM_A });
  t.check(checkedHere.ok,
          'and a JWT-SVID minted in realm A verifies in realm A',
          checkedHere.ok ? checkedHere.spiffeId : checkedHere.reason);

  const checkedThere = await ca.validateJwtSvid(jwtA.token, 'probe',
                                                { realm: REALM_B });
  t.check(!checkedThere.ok,
          'AND IT DOES NOT VERIFY IN REALM B — which is the whole claim: two ' +
          'realms are two trust domains with two authorities, and a bundle ' +
          'fetched from one says nothing about what the other issued',
          checkedThere.ok ? 'it verified' : checkedThere.reason);

  // -------------------------------------------------------------------------
  // 4. THE SOCKETS. A REALM WITH SPIFFE OFF HAS NONE; TURNING IT ON BINDS
  //    ITS OWN, ON ITS OWN ADDRESS.
  // -------------------------------------------------------------------------
  t.log.info('=== a socket per realm ===');
  t.equal(server.realmsListening().length, 0,
          'nothing is listening before listen() — this process is a test ' +
          'runner and binds no socket until it is asked to');

  // The realm's own addresses: loopback, a free port, and sockets in this
  // run's temporary directory.
  const portA = await freePort();
  realms.setOverride(REALM_A, 'spiffe.grpcHost', '127.0.0.1');
  realms.setOverride(REALM_A, 'spiffe.workloadPort', portA);
  realms.setOverride(REALM_A, 'spiffe.serverPort', 0);
  realms.setOverride(REALM_A, 'spiffe.workloadSocket',
                     path.join(SOCKET_DIR, 'a.sock'));
  // The DEFAULT realm binds nothing in this run: `listen()` would otherwise
  // take 8092 and 8181 on the machine this is running on, which is the one
  // thing a unit test must never do.
  config.setOverride('spiffe.workloadPort', 0);
  config.setOverride('spiffe.serverPort', 0);
  config.setOverride('spiffe.workloadSocketEnabled', false);
  config.setOverride('spiffe.serverSocketEnabled', false);

  await server.listen().whenReady;
  t.check(server.realmsListening().indexOf('') >= 0,
          'the default realm always has an entry, even with every listener ' +
          'turned off — its sockets stay bound across spiffe.enabled ' +
          'because a socket that vanished reads as a service that stopped',
          JSON.stringify(server.realmsListening()));
  t.check(server.realmsListening().indexOf(REALM_A) < 0,
          'and a realm with SPIFFE OFF has no listeners at all');

  // **A REALM WITH NO `spiffe.enabled` ROW AT ALL HAS NONE EITHER**, which is
  // a different claim from the one above and the one that matters for a realm
  // created before this feature existed or restored from an older store.
  // Reading the EFFECTIVE value would inherit the process's `true` and give
  // every such realm a pair of listeners, a key generation and — since they
  // would all inherit `spiffe.grpcHost` of 0.0.0.0 — a refused bind, on the
  // next start.
  delete realmB.overrides['spiffe.enabled'];
  await server.reconcile();
  t.check(server.realmsListening().indexOf(REALM_B) < 0,
          'a realm carrying no spiffe.enabled row of its own has no ' +
          'listeners either — a realm OPTS IN, and the seeded `false` is ' +
          'what makes that visible rather than what makes it true',
          JSON.stringify(server.realmsListening()));
  realmB.overrides['spiffe.enabled'] = false;

  const on = realms.setOverride(REALM_A, 'spiffe.enabled', true);
  t.check(on.ok, 'spiffe.enabled is set on the realm',
          (on.errors || []).join(' '));
  // `realms.onChange()` fired synchronously; the binding it started is not
  // synchronous, so the reconcile is awaited explicitly here rather than
  // slept on.
  await server.reconcile();

  t.check(server.realmsListening().indexOf(REALM_A) >= 0,
          'TURNING IT ON BINDS THAT REALM\'S SOCKETS — no restart, because ' +
          'realms.setOverride() fires realms.onChange() and spiffe_server.js ' +
          'reconciles what is bound with what configuration asks for',
          JSON.stringify(server.realmsListening()));
  const boundA = server.bindings().workload.filter(function (b) {
    return b.realm === REALM_A;
  });
  t.check(boundA.some(function (b) {
            return b.listening && b.address === '127.0.0.1:' + portA;
          }),
          'on the ADDRESS the realm names — spiffe.grpcHost on the realm is ' +
          'what keeps two realms apart on one machine, because the endpoint ' +
          'address is the only thing a SPIFFE client has to name a tenant with',
          JSON.stringify(boundA.map(function (b) {
            return b.address + (b.listening ? '' : ' (' + b.error + ')');
          })));
  t.check(boundA.some(function (b) {
            return b.listening && b.address.indexOf('unix://') === 0;
          }),
          'and on a Unix socket of its own',
          JSON.stringify(boundA.map(function (b) { return b.address; })));

  // -------------------------------------------------------------------------
  // 4b. AND A CALL ON THAT SOCKET IS ANSWERED IN THAT REALM.
  //
  // **THIS IS THE ASSERTION THE WHOLE FEATURE IS FOR, and it is the one that
  // cannot be made anywhere else.** Binding a socket per realm is worth nothing
  // if the handler behind it answers in the default realm, and a reader cannot
  // tell the two apart from the outside: the call succeeds either way and hands
  // back a bundle. What names the realm is the KEY of the map
  // `FetchX509Bundles` returns — a trust domain ID — so a wrong answer here is
  // `spiffe://example.org` where `spiffe://spiffe-domains-a.example.org`
  // belongs.
  //
  // A REAL gRPC CLIENT over the realm's own Unix socket, rather than calling
  // the handler table: what is under test is the wrapping `spiffe_server.js`
  // does when it builds that realm's server, and calling the handlers
  // directly would skip exactly that.
  // -------------------------------------------------------------------------
  t.log.info('=== a call on the realm\'s socket is in the realm ===');
  const bundles = await fetchBundlesOver(path.join(SOCKET_DIR, 'a.sock'));
  t.check(!!bundles.bundles[spiffeId.trustDomainId(ca.trustDomain(REALM_A))],
          'FetchX509Bundles on realm A\'s Workload API socket answers with ' +
          'realm A\'s trust domain — the handler table is the same one the ' +
          'default realm uses, entered through realms.run() for the realm ' +
          'whose socket the call arrived on',
          Object.keys(bundles.bundles || {}).join(', '));
  t.check(!bundles.bundles[spiffeId.trustDomainId(ca.trustDomain())],
          'AND NOT WITH THE DEFAULT REALM\'S, which is the answer every ' +
          'version of this service before 2026-09-12 would have given from ' +
          'any socket it had',
          Object.keys(bundles.bundles || {}).join(', '));

  // -------------------------------------------------------------------------
  // 4c. AND THE REALM SURVIVES BEING DISPATCHED TO A WORKER.
  //
  // **TWO FEATURES LANDED ON THE SAME DAY AND THEY MEET HERE.** SPIFFE's gRPC
  // methods became dispatchable operations — the front process keeps the
  // socket and the framing and a worker runs the handler — the same week a
  // realm got sockets of its own. A worker has no socket, so it has no way to
  // recover which realm the call arrived in: without the realm on what
  // crosses, every dispatched call would be answered in the DEFAULT realm.
  //
  // **AND NOTHING WOULD FAIL.** An SVID would be minted, signed by the wrong
  // realm's authority, in the wrong trust domain, and the caller would find
  // out when it presented one somewhere that checks. That is why this is
  // asserted on the SEAM — `methodRequest()` is what the front process sends
  // and `performMethod()` is what the worker runs — rather than left to a
  // protocol job that would need a pool, two realms and a socket each.
  //
  // `tests/spiffe_operations.js` owns the rest of that seam; this is the one
  // claim about it that belongs to the realm.
  // -------------------------------------------------------------------------
  t.log.info('=== the realm crosses to a worker ===');
  const rpc = require('../spiffe/spiffe_grpc');
  const crossed = structuredClone(realms.run(realms.get(REALM_A), function () {
    return rpc.methodRequest({ request: {}, spiffeCaller: null });
  }));
  t.equal(crossed.realm, REALM_A,
          'what the front process sends a worker names the realm the call ' +
          'arrived in — the socket is the discriminator and a worker has no ' +
          'socket');

  // **`ValidateJWTSVID` IS THE METHOD BECAUSE IT IS UNARY AND ITS ANSWER NAMES
  // THE TRUST DOMAIN.** Only the unary methods register with the worker table
  // — `unary()` is the one wrapper that calls `register()` — and this one
  // takes a JWT-SVID and says whether it verifies, which it can only do
  // against the authority of the realm it is running in. So a wrong realm
  // here is not a subtle difference in a log line: it is a token that
  // verifies or does not.
  //
  // The token is realm A's, minted in section 3. Run as realm A it verifies;
  // run as realm B — which is what a worker answering in the default realm
  // amounts to — it does not.
  const validated = await realms.run(realms.get(REALM_B), function () {
    return rpc.performMethod('workload', 'ValidateJWTSVID',
      { request: { audience: 'probe', svid: jwtA.token },
        caller: null, realm: REALM_A });
  });
  t.check(validated && validated.ok === true,
          'performMethod() answers a real unary method for realm A while the ' +
          'process is standing in realm B — which is the worker\'s position ' +
          'exactly: it has no socket and only the operation says which realm',
          JSON.stringify(validated && (validated.ok ? 'ok' : validated.error)));
  t.check(validated && validated.reply &&
          String(validated.reply.spiffe_id || '')
            .indexOf(ca.trustDomain(REALM_A)) > 0,
          'and the answer is REALM A\'S — the SVID verifies against realm ' +
          'A\'s authority, which is the one thing a call answered in the ' +
          'wrong realm could not produce',
          JSON.stringify(validated && validated.reply &&
                         validated.reply.spiffe_id));

  const elsewhere = await realms.run(realms.get(REALM_A), function () {
    return rpc.performMethod('workload', 'ValidateJWTSVID',
      { request: { audience: 'probe', svid: jwtA.token },
        caller: null, realm: REALM_B });
  });
  t.check(!elsewhere || elsewhere.ok !== true ||
          !(elsewhere.reply && elsewhere.reply.spiffe_id),
          'AND THE SAME TOKEN WITH REALM B ON THE OPERATION IS NOT VALIDATED ' +
          '— the assertion above would pass just as well if the realm were ' +
          'being ignored and the ambient one used, so this is the half that ' +
          'says the operation decided it',
          JSON.stringify(elsewhere && (elsewhere.ok ? elsewhere.reply
                                                    : elsewhere.error)));

  // -------------------------------------------------------------------------
  // 5. TWO REALMS MAY NOT SHARE AN ADDRESS, AND THE REFUSAL SAYS SO.
  // -------------------------------------------------------------------------
  t.log.info('=== one address, one realm ===');
  realms.setOverride(REALM_B, 'spiffe.grpcHost', '127.0.0.1');
  realms.setOverride(REALM_B, 'spiffe.workloadPort', portA);
  realms.setOverride(REALM_B, 'spiffe.serverPort', 0);
  realms.setOverride(REALM_B, 'spiffe.workloadSocket',
                     path.join(SOCKET_DIR, 'b.sock'));
  realms.setOverride(REALM_B, 'spiffe.enabled', true);
  await server.reconcile();
  const boundB = server.bindings().workload.filter(function (b) {
    return b.realm === REALM_B;
  });
  const refused = boundB.filter(function (b) {
    return !b.listening && b.address === '127.0.0.1:' + portA;
  })[0];
  t.check(!!refused && /already answers on/.test(refused.error),
          'a second realm asking for the SAME address is refused by NAME — ' +
          'grpc-js would say "Failed to bind", which is what a port taken by ' +
          'another process says too, and the two need different things doing ' +
          'about them',
          refused ? refused.error : JSON.stringify(boundB));
  t.check(boundB.some(function (b) {
            return b.listening && b.address.indexOf('unix://') === 0;
          }),
          'while its own Unix socket still binds — one address refused is ' +
          'not the realm\'s SPIFFE taken away, and GET /spiffe reports each ' +
          'listener separately for exactly this reason');

  server.close();
  t.equal(server.realmsListening().length, 0,
          'and close() takes every realm\'s listeners down');
  try {
    fs.rmSync(SOCKET_DIR, { recursive: true, force: true });
  } catch (e) {
    // A socket the kernel still holds. Nothing depends on the directory
    // having gone, and leaving it is a temporary directory rather than a
    // failure of anything under test.
    t.log.debug('could not remove ' + SOCKET_DIR + ': ' + e.message);
  }
  config.clearOverride('spiffe.workloadPort');
  config.clearOverride('spiffe.serverPort');
  config.clearOverride('spiffe.workloadSocketEnabled');
  config.clearOverride('spiffe.serverSocketEnabled');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_realm_domains',
  describe: 'a trust domain and a set of gRPC sockets per trust realm, and ' +
            'the two things that must not be shared: a name and an address',
  run: run
};
