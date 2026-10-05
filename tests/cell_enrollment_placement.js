// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cell_enrollment_placement.js
//
// ---------------------------------------------------------------------------
// CERTIFICATE ENROLLMENT IN A SERVICE DEPLOYED AS CELLS (#98 D10). What the
// three enrollment families mint is stamped with the cell that minted it,
// and a request that reaches another cell is sent to the one that holds what
// it is about BEFORE anything is verified, counted or spent. In process, with
// the cell map, the key the locator's tag is made with, and the placement
// helpers and channel replaced by stubs — nothing is dialled and nothing is
// relayed; the test reads WHERE each request would have gone:
//
//   A. an EAB key id and a SCEP challenge id carry the minting cell's tag,
//      and still name their entry with it (and without it, single-cell);
//   B. every ACME identifier is stamped, inside `ID_PATTERN`;
//   C. a Replay-Nonce is valid only in the cell that issued it — and a
//      single-cell service's nonces are what they always were;
//   D. ACME's placement: a `kid` goes to the account's cell, a newAccount to
//      its EAB entry's home (a person) or the key's minting cell (an
//      application), a newAccount by key alone and a renewal-info to the
//      cell a fan-out finds holding it — 503 STS-CELL-0100 when a cell
//      cannot be asked — a revokeCert by certificate key to the home of the
//      person the certificate names; a relayed request and a single-cell
//      service are placed nowhere;
//   E. the entry a certificate's urn:sts: subjectAltName names is read
//      without verifying it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'cell_enrollment_placement', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const RUN = nodeCrypto.randomBytes(3).toString('hex');

const CELLS = [
  { id: 'usw2', jurisdiction: 'us', url: 'https://usw2.cells.test:8446',
    self: false },
  { id: 'cac1', jurisdiction: 'ca', url: 'https://cac1.cells.test:8446',
    self: false }
];

// The stubbed world: which cell this process is, and whether it is one of
// several at all.
const world = { here: 'usw2', multi: true };

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(typeof value === 'string' ? value
                                               : JSON.stringify(value))
    .toString('base64url');
}

// Replaces the cell map and the locator's key with the stubbed world, and
// answers the function that puts them back.
function installWorld(cells, keystore, cellLocator) {
  log.debug("Entering installWorld().");
  const saved = {
    isMulti: cells.isMulti, id: cells.id, all: cells.all, get: cells.get,
    peers: cells.peers, keyedDigest: keystore.keyedDigest
  };
  cells.isMulti = function () {
    return world.multi;
  };
  cells.id = function () {
    return world.here;
  };
  cells.all = function () {
    return CELLS;
  };
  cells.get = function (id) {
    return CELLS.filter(function (one) {
      return one.id === id;
    })[0] || null;
  };
  cells.peers = function () {
    return CELLS.filter(function (one) {
      return one.id !== world.here;
    });
  };
  keystore.keyedDigest = function (label, text) {
    return nodeCrypto.createHmac('sha256', 'cell-test-' + RUN)
      .update(String(label) + '\n' + String(text)).digest('base64url');
  };
  cellLocator.reset();
  log.debug("Leaving installWorld().");
  return function restore() {
    log.debug("Entering restore().");
    Object.keys(saved).forEach(function (name) {
      if (name === 'keyedDigest') {
        keystore.keyedDigest = saved[name];
      } else {
        cells[name] = saved[name];
      }
    });
    world.here = 'usw2';
    world.multi = true;
    cellLocator.reset();
    log.debug("Leaving restore().");
  };
}

// A response that records what was sent.
function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = {
    statusCode: 200, headers: {}, body: null, headersSent: false,
    status: function (code) {
      res.statusCode = code;
      return res;
    },
    set: function (name, value) {
      res.headers[String(name).toLowerCase()] = value;
      return res;
    },
    append: function (name, value) {
      res.headers[String(name).toLowerCase()] = value;
      return res;
    },
    type: function (value) {
      res.headers['content-type'] = value;
      return res;
    },
    send: function (body) {
      res.body = body;
      res.headersSent = true;
      return res;
    },
    end: function () {
      res.headersSent = true;
      return res;
    }
  };
  log.debug("Leaving fakeRes().");
  return res;
}

function fakeReq(method, reqPath, body) {
  log.debug("Entering fakeReq().");
  const headers = { host: 'sts.cells.test',
                    'content-type': 'application/jose+json' };
  log.debug("Leaving fakeReq().");
  return {
    method: method, path: reqPath, url: '/enroll/acme' + reqPath,
    originalUrl: '/enroll/acme' + reqPath, protocol: 'https',
    headers: headers, body: body === undefined ? undefined
                                               : JSON.stringify(body),
    get: function (name) {
      return headers[String(name).toLowerCase()];
    }
  };
}

// A flattened JWS whose signature is never checked: placement reads the
// protected header and the payload and nothing else.
function unsignedJws(header, payload) {
  log.debug("Entering unsignedJws().");
  log.debug("Leaving unsignedJws().");
  return { protected: b64u(header),
           payload: payload === null ? '' : b64u(payload),
           signature: b64u('not checked here') };
}

function publicJwk(publicKey) {
  log.debug("Entering publicJwk().");
  const full = publicKey.export({ format: 'jwk' });
  log.debug("Leaving publicJwk().");
  return { kty: full.kty, crv: full.crv, x: full.x, y: full.y };
}

function checkCredentialIds(t, core, cellLocator) {
  log.debug("Entering checkCredentialIds().");
  t.log.info('=== A. an EAB key id and a SCEP challenge id carry the cell ' +
             '===');
  const instance = new core.CertEnrollment(core.CertEnrollment.defaultDeps());
  const kid = instance.credentialId('eab', { kind: 'person', id: 'alice' });
  t.equal(cellLocator.locate(kid), 'usw2', 'an EAB key id is stamped with ' +
          'the cell that minted it');
  const named = core.entryOfCredentialId('eab', kid);
  t.check(named && named.kind === 'person' && named.id === 'alice',
          'and still names its entry', JSON.stringify(named));
  const hex = nodeCrypto.randomBytes(8).toString('hex');
  const scep = 'scep-a-' + b64u('app-' + RUN) + '-' + hex +
               cellLocator.tagOf('cac1');
  const app = core.entryOfCredentialId('scep', scep);
  t.check(app && app.kind === 'application' && app.id === 'app-' + RUN,
          'a SCEP challenge id minted in another cell names its application',
          JSON.stringify(app));
  t.equal(cellLocator.elsewhere(scep), 'cac1', 'and says which cell');
  t.check(!core.entryOfCredentialId('eab', 'eab-p-' + b64u('alice') + '-' +
                                    hex + 'abcdefghijk'),
          'a tail that is not a whole tag is refused as malformed');
  world.multi = false;
  const plain = instance.credentialId('eab', { kind: 'person', id: 'alice' });
  world.multi = true;
  t.check(/^eab-p-[A-Za-z0-9_-]+-[0-9a-f]{16}$/.test(plain) &&
          !!core.entryOfCredentialId('eab', plain),
          'a single-cell service mints the identifier it always did', plain);
  log.debug("Leaving checkCredentialIds().");
}

function checkAcmeIds(t, store, cellLocator) {
  log.debug("Entering checkAcmeIds().");
  t.log.info('=== B. every ACME identifier is stamped ===');
  const account = store.createAccount({ jwk: { kty: 'EC' },
                                        thumbprint: 'cell-tp-' + RUN });
  t.equal(cellLocator.locate(account.id), 'usw2', 'an account id carries ' +
          'the cell that created it');
  t.check(/^[A-Za-z0-9_-]{8,64}$/.test(account.id), 'inside the path ' +
          'pattern every ACME route holds an id to', account.id);
  log.debug("Leaving checkAcmeIds().");
}

function checkNonces(t, jws) {
  log.debug("Entering checkNonces().");
  t.log.info('=== C. a Replay-Nonce is valid only where it was issued ===');
  const nonce = jws.mintNonce('', 300);
  t.check(jws.checkNonce(nonce, '').ok, 'a nonce is accepted in the cell ' +
          'that issued it');
  world.here = 'cac1';
  const elsewhere = jws.checkNonce(nonce, '');
  t.check(!elsewhere.ok && elsewhere.reason === 'forged', 'and refused in ' +
          'another, so the owning cell answers badNonce with one of its own',
          JSON.stringify(elsewhere));
  world.here = 'usw2';
  world.multi = false;
  const single = jws.mintNonce('', 300);
  world.here = 'cac1';
  t.check(jws.checkNonce(single, '').ok, 'a single-cell service folds no ' +
          'cell into its nonce');
  world.here = 'usw2';
  world.multi = true;
  log.debug("Leaving checkNonces().");
}

async function checkAcmePlacement(t, acme, jws, helpers, cellLocator,
                                  realPlacement, errorCodes) {
  log.debug("Entering checkAcmePlacement().");
  t.log.info('=== D. where an ACME request is served ===');
  const calls = [];
  let peerAnswer = function () {
    return Promise.resolve({ held: false });
  };
  const placement = {
    relayIfElsewhere: function (req, res, value, reason) {
      calls.push({ how: 'artifact', value: value, reason: reason });
      return cellLocator.elsewhere(value) !== '';
    },
    relayToHome: function (req, res, realmId, kind, value, reason) {
      calls.push({ how: 'home', kind: kind, value: value, reason: reason });
      return Promise.resolve(true);
    },
    serialisedBody: realPlacement.serialisedBody
  };
  const channel = {
    registerOp: function () {
      return undefined;
    },
    call: function (cell, name, body) {
      return peerAnswer(cell, name, body);
    },
    relay: function (req, res, cell, opts) {
      calls.push({ how: 'relay', cell: cell, reason: opts.reason });
      return Promise.resolve();
    }
  };
  const server = new acme.Acme(Object.assign(acme.Acme.defaultDeps(), {
    cellPlacement: placement, cellChannel: channel }));
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicJwk(pair.publicKey);
  const thumbprint = jws.checkAccountKey(jwk, 'ES256').thumbprint;

  // 1. A kid names the account's cell.
  world.here = 'cac1';
  const otherAccount = cellLocator.stamp(nodeCrypto.randomBytes(15)
    .toString('base64url'));
  world.here = 'usw2';
  calls.length = 0;
  let req = fakeReq('POST', '/new-order', unsignedJws({
    alg: 'ES256', nonce: 'n', url: 'https://sts.cells.test/enroll/acme/' +
    'new-order', kid: 'https://sts.cells.test/enroll/acme/account/' +
    otherAccount }, { identifiers: [] }));
  let answered = await server.placeRequest(req, fakeRes());
  t.check(answered && calls.length === 1 && calls[0].how === 'artifact' &&
          calls[0].value === otherAccount,
          'a request signed by an account in another cell is sent there',
          JSON.stringify(calls));

  // 2. A newAccount with a person's EAB key goes to their home.
  const newAccount = function (kid) {
    const r = fakeReq('POST', '/new-account', null);
    const url = helpers.baseUrlOf(r) + '/enroll/acme/new-account';
    r.body = JSON.stringify(unsignedJws({ alg: 'ES256', nonce: 'n',
      url: url, jwk: jwk }, kid === null ? { termsOfServiceAgreed: true } : {
      termsOfServiceAgreed: true,
      externalAccountBinding: unsignedJws({ alg: 'HS256', kid: kid, url: url },
                                          jwk) }));
    return r;
  };
  const hex = nodeCrypto.randomBytes(8).toString('hex');
  calls.length = 0;
  answered = await server.placeRequest(newAccount('eab-p-' + b64u('carol') +
    '-' + hex + cellLocator.tagOf('usw2')), fakeRes());
  t.check(answered && calls.length === 1 && calls[0].how === 'home' &&
          calls[0].kind === 'name' && calls[0].value === 'carol',
          'a newAccount under a person\'s EAB key goes to their home cell',
          JSON.stringify(calls));

  // 3. An application's EAB key goes to the cell that minted it.
  const appKid = 'eab-a-' + b64u('app-' + RUN) + '-' + hex +
                 cellLocator.tagOf('cac1');
  calls.length = 0;
  answered = await server.placeRequest(newAccount(appKid), fakeRes());
  t.check(answered && calls.length === 1 && calls[0].how === 'artifact' &&
          calls[0].value === appKid,
          'an application\'s EAB key goes to the cell that minted it',
          JSON.stringify(calls));

  // 4. A newAccount by key alone asks every other cell.
  peerAnswer = function (cell, name, body) {
    return Promise.resolve({ held: name === 'acme-held' &&
                                   body.kind === 'thumbprint' &&
                                   body.value === thumbprint &&
                                   cell === 'cac1' });
  };
  calls.length = 0;
  answered = await server.placeRequest(newAccount(null), fakeRes());
  t.check(answered && calls.length === 1 && calls[0].how === 'relay' &&
          calls[0].cell === 'cac1',
          'a newAccount naming only its key is sent to the cell that holds ' +
          'the account (RFC 8555 section 7.3.1)', JSON.stringify(calls));

  peerAnswer = function () {
    return Promise.resolve({ held: false });
  };
  calls.length = 0;
  answered = await server.placeRequest(newAccount(null), fakeRes());
  t.check(!answered && calls.length === 0, 'and served here when no cell ' +
          'holds it', JSON.stringify(calls));

  peerAnswer = function () {
    return Promise.reject(new Error('unreachable'));
  };
  const refused = fakeRes();
  answered = await server.placeRequest(newAccount(null), refused);
  t.check(answered && refused.statusCode === 503 &&
          errorCodes.codeOf(refused) === 'STS-CELL-0100' &&
          !!refused.headers['replay-nonce'],
          'and refused 503 STS-CELL-0100, with a Replay-Nonce, when a cell ' +
          'cannot be asked', refused.statusCode + ' ' +
          errorCodes.codeOf(refused));

  // 5. renewal-info for a certificate nobody here issued asks the others.
  peerAnswer = function (cell, name, body) {
    return Promise.resolve({ held: body.kind === 'certId' &&
                                   cell === 'cac1' });
  };
  calls.length = 0;
  const certId = b64u('aki-' + RUN) + '.' + b64u('\u0001serial');
  answered = await server.placeRequest(fakeReq('GET', '/renewal-info/' +
                                               certId), fakeRes());
  t.check(answered && calls.length === 1 && calls[0].how === 'relay' &&
          calls[0].cell === 'cac1', 'a renewal-info request is sent to the ' +
          'cell that issued the certificate (RFC 9773)',
          JSON.stringify(calls));

  // 6. A relayed request, and a single-cell service, are placed nowhere.
  calls.length = 0;
  req = fakeReq('POST', '/new-order', unsignedJws({
    alg: 'ES256', nonce: 'n', url: 'https://x/', kid: 'https://x/enroll/' +
    'acme/account/' + otherAccount }, {}));
  req.stsCellRelay = { from: 'cac1' };
  answered = await server.placeRequest(req, fakeRes());
  t.check(!answered && calls.length === 0, 'a request already relayed is ' +
          'served where it arrived (one hop)');
  delete req.stsCellRelay;
  world.multi = false;
  answered = await server.placeRequest(req, fakeRes());
  world.multi = true;
  t.check(!answered && calls.length === 0, 'and a single-cell service ' +
          'places nothing');
  log.debug("Leaving checkAcmePlacement().");
  return { server: server, calls: calls, newAccount: newAccount };
}

async function checkCertificates(t, core, x509, keys, placed) {
  log.debug("Entering checkCertificates().");
  t.log.info('=== E. the entry a certificate names, read and not believed ' +
             '===');
  const pair = await keys.generateKeyPair('ec-p256');
  const issued = await x509.issueCertificate({
    subject: [{ name: 'CN', value: 'bob' }],
    subjectPublicKey: pair.publicPem,
    signatureAlg: x509.defaultSignatureAlgorithm(
      await keys.describePublicPem(pair.publicPem)),
    profile: 'tls-client',
    issuer: { privateKeyPem: pair.privatePem, keyAlg: 'ec-p256' },
    extensions: {
      subjectAltName: { present: true, critical: false,
                        names: [{ kind: 'uri',
                                  value: 'urn:sts:person:bob' }] }
    }
  });
  const named = core.entryNamedByCertificate(issued.pem);
  t.check(named && named.kind === 'person' && named.id === 'bob',
          'a certificate\'s urn:sts:person: subjectAltName names its entry',
          JSON.stringify(named));
  t.equal(core.entryNamedByCertificate('not a certificate'), null,
          'and bytes that are no certificate name nobody');

  const der = Buffer.from(String(issued.pem)
    .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const req = fakeReq('POST', '/revoke-cert', null);
  const cert = new nodeCrypto.X509Certificate(issued.pem);
  const jwk = publicJwk(cert.publicKey);
  req.body = JSON.stringify(unsignedJws({ alg: 'ES256', nonce: 'n',
    url: 'https://x/enroll/acme/revoke-cert', jwk: jwk },
    { certificate: der.toString('base64url') }));
  placed.calls.length = 0;
  const answered = await placed.server.placeRequest(req, fakeRes());
  t.check(answered && placed.calls.length === 1 &&
          placed.calls[0].how === 'home' && placed.calls[0].value === 'bob',
          'a revokeCert signed by the certificate\'s key goes to the home ' +
          'of the person it names', JSON.stringify(placed.calls));
  log.debug("Leaving checkCertificates().");
}

async function run(t) {
  log.debug("Entering run().");
  const cells = require(path.join(ROOT, 'common', 'cells'));
  const keystore = require(path.join(ROOT, 'common', 'keystore'));
  const cellLocator = require(path.join(ROOT, 'common', 'cell_locator'));
  const realPlacement = require(path.join(ROOT, 'common', 'cell_placement'));
  const errorCodes = require(path.join(ROOT, 'common', 'error_codes'));
  const helpers = require(path.join(ROOT, 'common', 'helpers'));
  const core = require(path.join(ROOT, 'common', 'cert_enrollment'));
  const jws = require(path.join(ROOT, 'acme', 'acme_jws'));
  const store = require(path.join(ROOT, 'acme', 'acme_store'));
  const acme = require(path.join(ROOT, 'acme', 'acme'));
  const x509 = require(path.join(ROOT, 'common', 'vendored', 'x509'));
  const keys = require(path.join(ROOT, 'common', 'vendored', 'key_material'));
  const restore = installWorld(cells, keystore, cellLocator);
  try {
    checkCredentialIds(t, core, cellLocator);
    checkAcmeIds(t, store, cellLocator);
    checkNonces(t, jws);
    const placed = await checkAcmePlacement(t, acme, jws, helpers,
                                            cellLocator, realPlacement,
                                            errorCodes);
    await checkCertificates(t, core, x509, keys, placed);
  } finally {
    restore();
    // THE MONITOR'S COUNTERS ARE THE PROCESS'S, and the in-process suite is
    // one process: the ACME requests driven above were still counted when
    // `cert_enrollment.js` ran next and asserted ACME's counters empty.
    const monitor = require(path.join(ROOT, 'common', 'enrollment_monitor'));
    ['acme', 'est', 'scep'].forEach(function (family) {
      monitor.resetForTests(family);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_enrollment_placement',
  describe: 'ACME, EST and SCEP in a service deployed as cells: what they ' +
            'mint names its cell, a Replay-Nonce is valid only where it was ' +
            'issued, and a request is sent where it is held before anything ' +
            'is verified or spent (#98 D10)',
  run: run
};
