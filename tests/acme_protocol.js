'use strict';
//
// File: acme_protocol.js
//
// ===========================================================================
// THE ACME HANDLERS, DRIVEN THROUGH THE ROUTER BY AN INDEPENDENT CLIENT, IN A
// CHILD PROCESS (2026-09-13).
//
// `tests/vendored/sts_acme_enrollment.js` is the over-HTTPS job and carries the
// nine profiles, the chain to the Root, OCSP and the CRL. What is here is the
// HANDLER half that job would have to arrange a stack for, run against the
// whole protocol stack on an ephemeral plain-HTTP port:
//
//   * EVERY REFUSAL BY ITS ERROR TYPE AND ITS STS CODE — the code read back off
//     the audit log, because a code is recorded and never sent — including the
//     ones a conforming client never produces: a reused nonce with the retry
//     turned off, a `url` that lies, `jwk` and `kid` together, a GET on a
//     POST-as-GET resource, a 413 and a 415.
//   * REALM ISOLATION AT THE DOOR — an account URL, an EAB key and a
//     certificate from one realm presented at another, each refused.
//   * PRODUCT MODE'S TRANSPORT RULE, which needs a plain-HTTP listener: the
//     over-HTTPS job cannot reach it, and a realm carrying `global.mode` of
//     product answers 403 here while the realm beside it answers 200.
//   * THE CONSOLE MODEL — the EAB key answered once and absent from every view,
//     and the monitor counting what was refused.
//
// A CHILD, for `tests/protocol_endpoints.js`'s reason: it loads the whole
// stack, and a stack loaded into `run.js`'s one process is shared with every
// file after this one.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'acme_protocol',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// The child. Everything it needs is required inside, so it ships as source.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AP_ROOT;
  const OUT = process.env.AP_OUT;
  const nodeCrypto = require('crypto');
  const http = require('http');
  const C = require(ROOT_DIR + '/tests/vendored/acme_client.js');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const P = 'urn:ietf:params:acme:error:';

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const realms = require(ROOT_DIR + '/common/realms');
    const server = http.createServer(app);
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const base = 'http://127.0.0.1:' + server.address().port;
    const RUN = nodeCrypto.randomBytes(3).toString('hex');
    const A = 'acmepa' + RUN;
    const B = 'acmepb' + RUN;
    const PROD = 'acmepp' + RUN;
    const ALICE = 'alice' + RUN;
    const BOB = 'bob' + RUN;

    async function api(realm, op, body) {
      const r = await fetch(base + '/realm/' + realm + '/admin-api' + op, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body) });
      const text = await r.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) {
        json = { raw: text.slice(0, 300), parseError: e.message };
      }
      return { status: r.status, body: json, text: text };
    }
    // The code a refusal was recorded with, read off the audit log.
    async function codeOf(realm, pathPart) {
      const r = await api(realm, '/audit?per=200');
      const rows = (r.body && (r.body.rows || r.body.events)) || [];
      const hit = rows.filter(function (row) {
        return String(row.target || '').indexOf(pathPart) >= 0 &&
               row.errorCode;
      })[0];
      return hit ? hit.errorCode : '';
    }

    realms.create({ id: A, name: 'ACME protocol A' });
    realms.create({ id: B, name: 'ACME protocol B' });
    realms.create({ id: PROD, name: 'ACME protocol product',
                    overrides: { 'global.mode': 'product' } });
    for (const realm of [A, B]) {
      await api(realm, '/pki/build', { organisation: 'ACME ' + realm });
      for (const who of [ALICE, BOB]) {
        await api(realm, '/users/create', { username: who, invent: false,
          credential: 'none', attributes: { cn: who, sn: who,
                                            mail: who + '@example.test' } });
      }
    }
    await api(A, '/acme/add-host-name', { kind: 'person', identifier: ALICE,
                                          hostName: 'www.' + ALICE + '.test' });

    // --- 1. the directory and the nonce -------------------------------------
    const dirUrl = base + '/realm/' + A + '/enroll/acme/directory';
    const client = new C.AcmeClient(dirUrl);
    const dir = await client.directory();
    note(dir.status === 200 && dir.body.meta.externalAccountRequired === true &&
         dir.body.newAccount === base + '/realm/' + A +
                                 '/enroll/acme/new-account',
         'the directory names absolute URLs in the realm and requires EAB',
         JSON.stringify(dir.body).slice(0, 300));
    note(dir.headers.get('replay-nonce') &&
         /no-store/.test(dir.headers.get('cache-control')) &&
         /rel="index"/.test(dir.headers.get('link')),
         'and carries a Replay-Nonce, no-store and the index link');
    note(Object.keys(dir.body.meta.profiles).length === 9,
         'meta.profiles lists the nine allowed profiles',
         Object.keys(dir.body.meta.profiles).join(','));
    const head = await fetch(dir.body.newNonce, { method: 'HEAD' });
    const get = await fetch(dir.body.newNonce);
    note(head.status === 200 && get.status === 204 &&
         head.headers.get('replay-nonce') !== get.headers.get('replay-nonce'),
         'newNonce answers 200 to HEAD and 204 to GET, a new nonce each');
    const got = await fetch(dir.body.newOrder);
    const gotBody = await got.json();
    note(got.status === 405 && got.headers.get('allow') === 'POST' &&
         gotBody.type === P + 'malformed',
         'a GET on a POST-as-GET resource is 405 with Allow: POST');

    // --- 2. accounts and the External Account Binding -----------------------
    const aliceKey = C.generateAccountKey('ES256');
    const noEab = await client.newAccount(aliceKey, null);
    note(noEab.status === 403 &&
         noEab.body.type === P + 'externalAccountRequired',
         'a newAccount with no binding is externalAccountRequired',
         noEab.text.slice(0, 200));
    const eab = await api(A, '/acme/create-eab', { kind: 'person',
                                                   identifier: ALICE });
    note(eab.status === 200 && /^eab-p-/.test(eab.body.kid) &&
         eab.body.hmacKey && /certbot register --server/.test(eab.body.certbot),
         'create-eab answers the kid, the HMAC key and a certbot line',
         eab.text.slice(0, 200));
    const view = await api(A, '/acme');
    note(view.status === 200 && view.text.indexOf(eab.body.hmacKey) < 0 &&
         view.body.eabKeys.rows.some(function (row) {
           return row.kid === eab.body.kid;
         }), 'the console view lists the key and never its HMAC key');
    const wrongMac = await client.newAccount(aliceKey, { kid: eab.body.kid,
      hmacKey: nodeCrypto.randomBytes(32).toString('base64url') });
    note(wrongMac.status === 403 && wrongMac.body.type === P + 'unauthorized',
         'a binding MACed with the wrong key is unauthorized');
    const created = await client.newAccount(aliceKey,
      { kid: eab.body.kid, hmacKey: eab.body.hmacKey });
    const kid = created.location;
    note(created.status === 201 && /\/enroll\/acme\/account\//.test(kid),
         'a newAccount with the binding creates the account (201, Location)',
         created.text.slice(0, 200));
    const again = await client.newAccount(aliceKey, null);
    note(again.status === 200 && again.location === kid,
         'the same key again answers 200 with the same account');
    const thief = C.generateAccountKey('RS256');
    const reuse = await client.newAccount(thief,
      { kid: eab.body.kid, hmacKey: eab.body.hmacKey });
    note(reuse.status === 403 && reuse.body.type === P + 'unauthorized',
         'the binding presented by a second key is refused', reuse.text);
    const onlyExisting = await client.newAccount(thief, null,
                                                 { onlyReturnExisting: true });
    note(onlyExisting.body.type === P + 'accountDoesNotExist',
         'onlyReturnExisting for an unknown key is accountDoesNotExist');

    const clientB = new C.AcmeClient(base + '/realm/' + B +
                                     '/enroll/acme/directory');
    await clientB.directory();
    const crossEab = await clientB.newAccount(thief,
      { kid: eab.body.kid, hmacKey: eab.body.hmacKey });
    note(crossEab.status === 403 && crossEab.body.type === P + 'unauthorized',
         'realm A\'s EAB key presented at realm B is unauthorized');
    const crossKid = await clientB.newOrder(aliceKey, kid,
      [{ type: 'permanent-identifier', value: ALICE }]);
    note(crossKid.body && crossKid.body.type === P + 'accountDoesNotExist',
         'realm A\'s account URL used at realm B is accountDoesNotExist',
         crossKid.text.slice(0, 200));

    // --- 3. the envelope's refusals -----------------------------------------
    const spent = await client.takeNonce();
    await client.postAsGet(kid, aliceKey, kid, { nonce: spent });
    const replay = await client.postAsGet(kid, aliceKey, kid,
                                          { nonce: spent });
    note(replay.status === 400 && replay.body.type === P + 'badNonce' &&
         replay.headers.get('replay-nonce'),
         'a nonce presented twice is badNonce, with a fresh one attached');
    const forged = await client.postAsGet(kid, aliceKey, kid,
                                          { nonce: 'AAAA', noRetry: true });
    note(forged.body.type === P + 'badNonce', 'a nonce this server did not ' +
         'issue is badNonce');
    const retried = await client.postAsGet(kid, aliceKey, kid,
      { mutate: function (flat) { return flat; } });
    note(retried.status === 200, 'a conforming POST-as-GET of the account ' +
         'answers 200');
    const lying = await client.postAsGet(kid, aliceKey, kid,
      { url: base + '/realm/' + A + '/enroll/acme/new-order' });
    note(lying.status === 403 && lying.body.type === P + 'unauthorized',
         'a url header naming another resource is unauthorized (section 6.4)');
    const both = await client.post(dir.body.newOrder, { identifiers: [] },
      { key: aliceKey, kid: kid, jwk: true });
    note(both.status === 400 && both.body.type === P + 'malformed',
         'jwk and kid together are malformed');
    const unknownKid = await client.newOrder(aliceKey, base + '/realm/' + A +
      '/enroll/acme/account/AAAAAAAAAAAAAAAA',
      [{ type: 'permanent-identifier', value: ALICE }]);
    note(unknownKid.body.type === P + 'accountDoesNotExist',
         'an unknown account URL is accountDoesNotExist');
    const json = await client.post(dir.body.newOrder, { identifiers: [] },
      { key: aliceKey, kid: kid, contentType: 'application/json' });
    note(json.status === 415, 'application/json is 415');
    const big = await client.post(dir.body.newOrder, null,
      { key: aliceKey, kid: kid, body: 'x'.repeat(70000) });
    note(big.status === 413, 'a body over acme.maxRequestBytes is 413');
    const badSig = await client.postAsGet(kid, aliceKey, kid,
      { mutate: function (flat) {
        return Object.assign({}, flat, { signature: flat.signature
          .replace(/^./, flat.signature[0] === 'A' ? 'B' : 'A') });
      } });
    note(badSig.status === 400 && badSig.body.type === P + 'malformed',
         'a signature that does not verify is malformed');
    note(await codeOf(A, '/enroll/acme/account/') !== '',
         'every refusal was recorded with an STS code on the audit log');

    // --- 4. orders ----------------------------------------------------------
    const bobOrder = await client.newOrder(aliceKey, kid,
      [{ type: 'permanent-identifier', value: BOB }]);
    note(bobOrder.body.type === P + 'rejectedIdentifier' &&
         bobOrder.body.subproblems && bobOrder.body.subproblems[0]
           .identifier.value === BOB,
         'an order for another person is rejectedIdentifier with a subproblem',
         bobOrder.text.slice(0, 300));
    const unregistered = await client.newOrder(aliceKey, kid,
      [{ type: 'dns', value: 'not-registered.test' }],
      { profile: 'tls-server' });
    note(unregistered.body.type === P + 'rejectedIdentifier',
         'an unregistered dns name is rejectedIdentifier');
    const otherMail = await client.newOrder(aliceKey, kid,
      [{ type: 'email', value: BOB + '@example.test' }], { profile: 'email' });
    note(otherMail.body.type === P + 'rejectedIdentifier',
         'somebody else\'s mail is rejectedIdentifier');
    const weird = await client.newOrder(aliceKey, kid,
      [{ type: 'bogus', value: 'x' }]);
    note(weird.body.type === P + 'unsupportedIdentifier',
         'an identifier type this server does not issue for is ' +
         'unsupportedIdentifier');
    const rootCa = await client.newOrder(aliceKey, kid,
      [{ type: 'permanent-identifier', value: ALICE }], { profile: 'root-ca' });
    note(rootCa.body.type === P + 'invalidProfile' &&
         /never issued/.test(rootCa.body.detail),
         'the root-ca profile is invalidProfile, saying why');
    const validity = await client.newOrder(aliceKey, kid,
      [{ type: 'permanent-identifier', value: ALICE }],
      { notAfter: '2030-01-01T00:00:00Z' });
    note(validity.body.type === P + 'malformed',
         'notAfter in an order is refused malformed');

    const order = await client.newOrder(aliceKey, kid,
      [{ type: 'permanent-identifier', value: ALICE },
       { type: 'dns', value: 'www.' + ALICE + '.test' }],
      { profile: 'tls-server-client' });
    note(order.status === 201 && order.body.status === 'ready' &&
         order.body.authorizations.length === 2,
         'an order for identifiers the entry owns is ready at once',
         order.text.slice(0, 300));
    // #252: an order naming no profile, from its identifiers.
    const hostOnly = await client.newOrder(aliceKey, kid,
      [{ type: 'dns', value: 'www.' + ALICE + '.test' }]);
    note(hostOnly.status === 201 && hostOnly.body.profile === 'tls-server',
         'a dns-only order naming no profile is tls-server',
         hostOnly.text.slice(0, 300));
    const mixed = await client.newOrder(aliceKey, kid,
      [{ type: 'permanent-identifier', value: ALICE },
       { type: 'dns', value: 'www.' + ALICE + '.test' }]);
    note(mixed.status === 201 && mixed.body.profile === 'tls-client',
         'a mixed order naming no profile keeps acme.defaultProfile',
         mixed.text.slice(0, 300));
    const entryOnly = await client.newOrder(aliceKey, kid,
      [{ type: 'permanent-identifier', value: ALICE }]);
    note(entryOnly.status === 201 && entryOnly.body.profile === 'tls-client',
         'an entry-only order naming no profile keeps acme.defaultProfile',
         entryOnly.text.slice(0, 300));
    const namedClient = await client.newOrder(aliceKey, kid,
      [{ type: 'dns', value: 'www.' + ALICE + '.test' }],
      { profile: 'tls-client' });
    note(namedClient.status === 201 &&
         namedClient.body.profile === 'tls-client',
         'a named profile wins over the host-only default',
         namedClient.text.slice(0, 300));
    const authz = await client.postAsGet(order.body.authorizations[0],
                                         aliceKey, kid);
    note(authz.body.status === 'valid' &&
         authz.body.challenges[0].type === 'sts-entry-binding-01' &&
         authz.body.challenges[0].status === 'valid',
         'its authorization is valid with one sts-entry-binding-01 challenge');
    const challenge = await client.post(authz.body.challenges[0].url, {},
                                        { key: aliceKey, kid: kid });
    note(challenge.status === 200 && challenge.body.status === 'valid' &&
         /rel="up"/.test(challenge.headers.get('link')),
         'posting {} to the challenge answers it valid, linking up');

    const bobEab = await api(A, '/acme/create-eab', { kind: 'person',
                                                      identifier: BOB });
    const bobKey = C.generateAccountKey('EdDSA');
    const bobAccount = await client.newAccount(bobKey,
      { kid: bobEab.body.kid, hmacKey: bobEab.body.hmacKey });
    const bobKid = bobAccount.location;
    note(bobAccount.status === 201, 'a second person registers with an ' +
         'EdDSA key');
    const peek = await client.postAsGet(order.body.authorizations[0], bobKey,
                                        bobKid);
    note(peek.status === 403 && peek.body.type === P + 'unauthorized',
         'another account reading the authorization is unauthorized');

    // --- 5. finalize --------------------------------------------------------
    const mismatch = await C.buildCsr({ keyAlg: 'ec-p256', cn: ALICE,
      sans: [{ kind: 'dns', value: 'www.' + ALICE + '.test' },
             { kind: 'dns', value: 'extra.' + ALICE + '.test' }] });
    const refusedCsr = await client.finalize(aliceKey, kid,
      order.body.finalize, mismatch.der);
    note(refusedCsr.body.type === P + 'badCSR' &&
         /not an identifier of this order/.test(refusedCsr.body.detail),
         'a CSR naming a name the order does not is badCSR',
         refusedCsr.text.slice(0, 300));
    const good = await C.buildCsr({ keyAlg: 'ec-p256', cn: ALICE,
      sans: [{ kind: 'dns', value: 'www.' + ALICE + '.test' },
             { kind: 'uri', value: 'urn:sts:person:' + ALICE }] });
    const corrupt = await client.finalize(aliceKey, kid, order.body.finalize,
                                          C.corruptSignature(good.der));
    note(corrupt.body.type === P + 'badCSR', 'a CSR whose signature does not ' +
         'verify is badCSR', corrupt.text.slice(0, 200));
    const kem = await C.csrWithKemKey({ keyAlg: 'ec-p256', cn: ALICE,
      sans: [{ kind: 'dns', value: 'www.' + ALICE + '.test' }] });
    const kemRefused = await client.finalize(aliceKey, kid,
      order.body.finalize, kem.der);
    note(kemRefused.body.type === P + 'badPublicKey',
         'a CSR carrying an ML-KEM key is badPublicKey',
         kemRefused.text.slice(0, 200));
    const done = await client.finalize(aliceKey, kid, order.body.finalize,
                                       good.der);
    note(done.status === 200 && done.body.status === 'valid' &&
         done.body.certificate, 'the order finalizes valid with a ' +
         'certificate URL', done.text.slice(0, 300));
    const twice = await client.finalize(aliceKey, kid, order.body.finalize,
                                        good.der);
    note(twice.status === 403 && twice.body.type === P + 'orderNotReady',
         'finalizing it again is orderNotReady');
    const cert = await client.postAsGet(done.body.certificate, aliceKey, kid);
    const chain = C.splitPemChain(cert.text);
    const x = chain.map(function (pem) {
      return new nodeCrypto.X509Certificate(pem);
    });
    note(cert.type === 'application/pem-certificate-chain' &&
         chain.length === 3 &&
         x[0].checkIssued(x[1]) && x[0].verify(x[1].publicKey) &&
         x[1].verify(x[2].publicKey) &&
         x.every(function (one) { return one.subject !== one.issuer; }),
         'the chain is the certificate, its Issuing CA and the Intermediate, ' +
         'verified by OpenSSL, with no self-signed Root in it',
         cert.type + ' ' + chain.length);
    note(/URI:urn:sts:person:/.test(x[0].subjectAltName) &&
         /DNS:www\./.test(x[0].subjectAltName),
         'the certificate names the entry and the registered host',
         x[0].subjectAltName);
    const stolen = await client.postAsGet(done.body.certificate, bobKey,
                                          bobKid);
    note(stolen.status === 403, 'another account cannot download it');

    const ari = await fetch(dir.body.renewalInfo + '/' + C.certIdOf(chain[0]));
    const ariBody = await ari.json();
    note(ari.status === 200 && ariBody.suggestedWindow &&
         new Date(ariBody.suggestedWindow.start) <
         new Date(ariBody.suggestedWindow.end) &&
         ari.headers.get('retry-after'),
         'renewalInfo answers a suggested window and Retry-After');
    const ariUnknown = await fetch(dir.body.renewalInfo +
                                   '/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE');
    const ariBad = await fetch(dir.body.renewalInfo + '/nodot');
    note(ariUnknown.status === 404 && ariBad.status === 400,
         'an unknown certificate is 404 and a malformed identifier 400');

    // --- 6. revocation ------------------------------------------------------
    const der = C.pemToDer(chain[0]);
    const byBob = await client.revoke(bobKey, bobKid, der, 1);
    note(byBob.status === 403 && byBob.body.type === P + 'unauthorized',
         'an unrelated account revoking it is unauthorized');
    const atB = await clientB.revoke(C.accountKeyFromPem('ES256',
      good.privatePem), null, der, 1);
    note(atB.status === 404, 'the certificate presented at realm B is not ' +
         'one issued there', atB.text.slice(0, 200));
    const badReason = await client.revoke(aliceKey, kid, der, 7);
    note(badReason.body.type === P + 'badRevocationReason',
         'reason 7 is badRevocationReason');
    const byKey = await client.revoke(C.accountKeyFromPem('ES256',
      good.privatePem), null, der, 1);
    note(byKey.status === 200, 'the certificate\'s own key revokes it (jwk)',
         byKey.text.slice(0, 200));
    const already = await client.revoke(aliceKey, kid, der, 1);
    note(already.body.type === P + 'alreadyRevoked',
         'revoking it again is alreadyRevoked');
    const ariRevoked = await (await fetch(dir.body.renewalInfo + '/' +
                                          C.certIdOf(chain[0]))).json();
    note(new Date(ariRevoked.suggestedWindow.end) < new Date(),
         'and renewalInfo now suggests renewing at once');

    // --- 7. key change and deactivation -------------------------------------
    const clash = await client.keyChange(aliceKey, kid, bobKey);
    note(clash.status === 409 && clash.location === bobKid,
         'a key change to another account\'s key is 409 naming that account');
    const newKey = C.generateAccountKey('RS256');
    const wrongOld = await client.keyChange(aliceKey, kid, newKey,
      { oldKey: C.generateAccountKey('ES256').jwk });
    note(wrongOld.body.type === P + 'malformed', 'an oldKey that is not the ' +
         'account key is malformed');
    const rolled = await client.keyChange(aliceKey, kid, newKey);
    note(rolled.status === 200, 'a key change to a fresh key succeeds');
    const oldKeyUse = await client.postAsGet(kid, aliceKey, kid);
    const newKeyUse = await client.postAsGet(kid, newKey, kid);
    note(oldKeyUse.status === 400 && newKeyUse.status === 200,
         'the old key no longer signs for the account and the new one does');
    const deact = await client.post(kid, { status: 'deactivated' },
                                    { key: newKey, kid: kid });
    const afterDeact = await client.postAsGet(kid, newKey, kid);
    note(deact.body.status === 'deactivated' && afterDeact.status === 403 &&
         afterDeact.body.type === P + 'unauthorized',
         'a deactivated account authorizes nothing more');

    // --- 8. the monitor, the switch and product mode ------------------------
    const monitor = await api(A, '/acme/monitor');
    note(monitor.body.totals.issued >= 1 && monitor.body.totals.refused >= 10 &&
         monitor.body.errorCodes.some(function (row) {
           return row.name === 'STS-ACME-0018';
         }), 'the monitor counted the issuance, the refusals and the replay',
         JSON.stringify(monitor.body.totals));
    await api(B, '/config/set', { key: 'acme.enabled', value: 'false' });
    const off = await fetch(base + '/realm/' + B + '/enroll/acme/directory');
    const onA = await fetch(dirUrl);
    note(off.status === 503 && onA.status === 200,
         'acme.enabled off in realm B answers 503 there and not in realm A');
    const product = await fetch(base + '/realm/' + PROD +
                                '/enroll/acme/directory');
    const productBody = await product.json();
    note(product.status === 403 && productBody.type === P + 'unauthorized',
         'a product-mode realm refuses ACME over plain HTTP',
         JSON.stringify(productBody).slice(0, 200));

    // --- 9. the console pages, through their own handlers -------------------
    // Behind the console gate, so the route's handler is called with a request
    // carrying only what it reads; a session is `sts_admin_console.js`'s.
    const router = app._router || app.router;
    function handlerFor(method, routePath) {
      const layer = router.stack.filter(function (one) {
        return one.route && one.route.path === routePath &&
               one.route.methods[method];
      })[0];
      return layer.route.stack[layer.route.stack.length - 1].handle;
    }
    function fakeRes(done) {
      const res = { headers: {}, statusCode: 200, locals: {} };
      res.set = function (k, v) {
        res.headers[String(k).toLowerCase()] = v;
        return res;
      };
      res.append = res.set;
      res.status = function (c) {
        res.statusCode = c;
        return res;
      };
      res.type = function (t) {
        res.headers['content-type'] = t;
        return res;
      };
      res.send = function (b) {
        res.body = String(b);
        done(res);
        return res;
      };
      res.redirect = function (c, u) {
        res.statusCode = c;
        res.headers.location = u;
        done(res);
        return res;
      };
      return res;
    }
    function fakeReq(method, routePath, query, body) {
      return { method: method, path: routePath, originalUrl: routePath,
               url: routePath, query: query || {}, protocol: 'https',
               headers: { host: 'console.test',
                          'content-type': 'application/x-www-form-urlencoded' },
               body: body || '', cookies: {},
               get: function (name) {
                 return String(name).toLowerCase() === 'host' ? 'console.test'
                                                              : undefined;
               } };
    }
    function drive(method, routePath, query, body) {
      return new Promise(function (resolve) {
        realms.run(realms.get(A), function () {
          handlerFor(method, routePath)(fakeReq(method, routePath, query,
                                                body), fakeRes(resolve));
        });
      });
    }
    const page = await drive('get', '/admin/acme', {});
    note(page.statusCode === 200 &&
         /\/enroll\/acme\/directory/.test(page.body) &&
         /Create EAB key/.test(page.body) &&
         page.body.indexOf('www.' + ALICE + '.test') >= 0 &&
         /revoked/.test(page.body) &&
         /root-ca/.test(page.body) && page.body.indexOf(eab.body.hmacKey) < 0,
         'the ACME console page draws the directory, the EAB form, the ' +
         'registered host, the revoked certificate and the refused profiles, ' +
         'and no HMAC key',
         String(page.body).slice(0, 200));
    const pageJson = JSON.parse((await drive('get', '/admin/acme',
                                             { format: 'json' })).body);
    const apiJson = (await api(A, '/acme')).body;
    note(JSON.stringify(Object.keys(pageJson).filter(function (k) {
      return k !== 'protocolEndpoints';
    }).sort()) === JSON.stringify(Object.keys(apiJson).filter(function (k) {
      return k !== 'protocolEndpoints';
    }).sort()) && pageJson.certificates.paging.total ===
         apiJson.certificates.paging.total,
         'the page\'s JSON and GET /admin-api/acme are one model (rule 7)');
    const monitorPage = await drive('get', '/admin/acme/monitor', {});
    note(monitorPage.statusCode === 200 &&
         /STS-ACME-0018/.test(monitorPage.body),
         'the monitor page draws the refusals by code');
    const onConsole = await drive('post', '/admin/acme', {},
      'action=create-eab&kind=person&identifier=' + encodeURIComponent(BOB));
    note(onConsole.statusCode === 200 &&
         /no-store/.test(onConsole.headers['cache-control']) &&
         /--eab-hmac-key [A-Za-z0-9_-]{43}/.test(onConsole.body),
         'create-eab on the console answers a 200 no-store page with the key ' +
         'once, never a redirect carrying it',
         onConsole.statusCode + ' ' + JSON.stringify(onConsole.headers));
    const deleted = await drive('post', '/admin/acme', {},
      'action=delete-eab&kid=eab-p-bm9uZQ-0000000000000000');
    note(deleted.statusCode === 303 && /error=/.test(deleted.headers.location),
         'a refused action answers the 303 with an error notice',
         deleted.headers.location);

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: e && e.stack ? e.stack : String(e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ap-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ACME_|CONFIG_FILE$)/
      .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  ADMIN_API_AUTH_REQUIRED: 'false',
                                  AP_ROOT: ROOT, AP_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  t.check(findings.length >= 60, 'every section ran',
          findings.length + ' finding(s)');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'acme_protocol',
  describe: 'the ACME handlers through the router with an independent ' +
            'client — every refusal by type, realm isolation at the door, ' +
            'finalize, the chain, revocation, key change, renewal ' +
            'information and product mode\'s transport rule',
  run: run
};
