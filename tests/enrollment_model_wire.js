// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/enrollment_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT ACME, EST AND SCEP ANSWER, HELD BYTE FOR BYTE (#1579 item 6).
//
// The request shapes, the answers' members, the error types and statuses,
// the media types and the registers each of the three enrollment protocols
// reads come from `models/enrollment/*.tsp` since #1579. Before the switch
// they were written by hand in `acme/acme_jws.ts`, `acme/acme.ts`,
// `est/est.ts`, `scep/scep.ts` and `scep/scep_cms.ts`, and the switch was to
// change NOTHING a client sees: the model describes and validates the wire,
// it does not reshape it. So this records what the hand-written version
// answered, in `tests/enrollment_model_wire.snapshot.json`, and holds every
// later build to it: a scripted conversation with every ACME resource — its
// success and each refusal, the envelope's and every payload's — with every
// EST operation and with every SCEP operation, in development mode, with the
// family switched off, and in a product-mode realm over plain HTTP.
//
// What is recorded of each answer: the status, every header but the ones
// that are about the connection, and the body — parsed when it is JSON, as
// text when it is text. A PEM block is its label; an EST base64 body is the
// list of what it holds; a SCEP CertRep is its messageType, pkiStatus and
// failInfo; any other binary body is its length class.
//
// Values that differ from run to run are replaced by a placeholder: a
// Replay-Nonce, an instant, a port, a key's material and every random id
// (any run of 24 or more base64url characters with a digit or both cases in
// it). The comparison is of everything else, exactly.
//
// `ENROLLMENT_WIRE_PRINT=1 node tests/enrollment_model_wire.js` prints the
// snapshot instead of comparing it; that is how the file was written, from
// the tree before the switch, and how it is rewritten when the wire is MEANT
// to change.
//
// A CHILD PROCESS, as tests/oauth_model_wire.js runs one: the protocol stack
// and a listener are loaded once, fresh, and nothing leaks into the runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'enrollment_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'enrollment_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.EW_ROOT;
  const OUT = process.env.EW_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const C = require(ROOT_DIR + '/tests/protocol/acme_client.js');
  const E = require(ROOT_DIR + '/tests/protocol/est_client.js');
  const S = require(ROOT_DIR + '/tests/protocol/scep_client.js');
  const fs = require('fs');
  const record = { wire: [], problems: [] };
  const SKIPPED = ['date', 'connection', 'keep-alive', 'content-length',
                   'etag', 'transfer-encoding'];

  function headersOf(headers) {
    const kept = {};
    const names = [];
    headers.forEach(function (value, name) {
      names.push(name);
    });
    names.sort().forEach(function (name) {
      if (SKIPPED.indexOf(name) < 0) {
        kept[name] = headers.get(name);
      }
    });
    return kept;
  }

  // What an EST body holds: a certs-only message's certificates by subject,
  // a CSR attributes document's OIDs, a multipart's parts by type.
  function estBody(type, bytes) {
    try {
      if (/multipart\/mixed/.test(type)) {
        return { multipart: E.parseMultipart(type, bytes)
          .map(function (part) {
            return part.headers;
          }) };
      }
      const der = Buffer.from(bytes.toString('latin1').replace(/\s+/g, ''),
                              'base64');
      if (/certs-only/.test(type)) {
        return { certsOnly: E.parseCertsOnly(der).certificates
          .map(function (pem) {
          return new nodeCrypto.X509Certificate(pem).subject;
        }) };
      }
      if (/csrattrs/.test(type)) {
        return { csrattrs: E.parseCsrAttrs(der) };
      }
    } catch (e) {
      return { unreadable: String(e && e.message) };
    }
    return bytes.toString('utf8');
  }

  function bodyOf(type, bytes) {
    if (/json/.test(type)) {
      const text = bytes.toString('utf8');
      try {
        return JSON.parse(text);
      } catch (e) {
        return { unparsed: text };
      }
    }
    if (/^text\//.test(type) || /pem-certificate-chain/.test(type) || !type) {
      return bytes.toString('utf8');
    }
    return { binary: bytes.length > 0 };
  }

  async function step(family, mode, name, method, url, init) {
    const r = await fetch(url, Object.assign({ method: method }, init || {}));
    const bytes = Buffer.from(await r.arrayBuffer());
    const type = String(r.headers.get('content-type') || '');
    let body = bodyOf(type, bytes);
    if (family === 'est' && r.status === 200) {
      body = estBody(type, bytes);
    }
    const one = { family: family, mode: mode, step: name, method: method,
                  path: new URL(url).pathname, status: r.status,
                  headers: headersOf(r.headers), body: body };
    record.wire.push(one);
    return { status: r.status, headers: r.headers, bytes: bytes, body: body,
             one: one };
  }

  // An ACME answer the client library already read, recorded.
  function acmeStep(mode, name, url, answer) {
    let body = answer.body;
    if (body === null) {
      body = answer.text;
    }
    record.wire.push({ family: 'acme', mode: mode, step: name,
                       method: 'POST', path: new URL(url).pathname,
                       status: answer.status,
                       headers: headersOf(answer.headers), body: body });
    return answer;
  }

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
    const A = 'enrollw';
    const OFF = 'enrollwoff';
    const PROD = 'enrollwprod';
    const ALICE = 'alicew';
    const BOB = 'bobw';

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
        json = { raw: text.slice(0, 300) };
      }
      if (r.status !== 200) {
        record.problems.push(op + ' answered ' + r.status + ': ' +
                             text.slice(0, 300));
      }
      return json;
    }

    realms.create({ id: A, name: 'Enrollment wire' });
    realms.create({ id: OFF, name: 'Enrollment wire, switched off' });
    realms.create({ id: PROD, name: 'Enrollment wire, product',
                    overrides: { 'global.mode': 'product' } });
    for (const realm of [A, OFF]) {
      await api(realm, '/pki/build', { organisation: 'Wire ' + realm });
      for (const who of [ALICE, BOB]) {
        await api(realm, '/users/create', { username: who, invent: false,
          credential: 'none', attributes: { cn: who, sn: who,
                                            mail: who + '@example.test' } });
      }
      for (const key of ['est.attemptsPerAddress', 'acme.attemptsPerAddress',
                         'acme.attemptsPerIdentity']) {
        await api(realm, '/config/set', { key: key, value: '1000' });
      }
    }
    await api(A, '/acme/add-host-name', { kind: 'person', identifier: ALICE,
                                          hostName: 'www.' + ALICE + '.test' });
    for (const key of ['acme.enabled', 'est.enabled', 'scep.enabled']) {
      await api(OFF, '/config/set', { key: key, value: 'false' });
    }

    // =====================================================================
    // ACME.
    // =====================================================================
    const D = 'development';
    const acmeBase = base + '/realm/' + A + '/enroll/acme';
    const dirUrl = acmeBase + '/directory';
    const client = new C.AcmeClient(dirUrl);
    await step('acme', D, 'directory', 'GET', dirUrl);
    await client.directory();
    const dir = client.dir;
    await step('acme', D, 'directory, the wrong method', 'POST', dirUrl);
    await step('acme', D, 'newNonce, HEAD', 'HEAD', dir.newNonce);
    await step('acme', D, 'newNonce, GET', 'GET', dir.newNonce);
    await step('acme', D, 'newOrder, GET', 'GET', dir.newOrder);

    const aliceKey = C.generateAccountKey('ES256');
    acmeStep(D, 'newAccount with no binding', dir.newAccount,
             await client.newAccount(aliceKey, null));
    const eab = await api(A, '/acme/create-eab', { kind: 'person',
                                                   identifier: ALICE });
    const binding = { kid: eab.kid, hmacKey: eab.hmacKey };
    acmeStep(D, 'newAccount, the binding MACed with another key',
             dir.newAccount, await client.newAccount(aliceKey,
               { kid: eab.kid, hmacKey: nodeCrypto.randomBytes(32)
                 .toString('base64url') }));
    // Every payload member's shape, refused before the binding is read.
    const shapes = [
      ['contact not an array', { contact: 'mailto:a@example.test' }],
      ['contact too many', { contact: Array(11).fill('mailto:a@example.test') }],
      ['contact empty string', { contact: [''] }],
      ['contact not mailto', { contact: ['tel:+15555550100'] }],
      ['contact with header fields',
       { contact: ['mailto:a@example.test?subject=x'] }],
      ['termsOfServiceAgreed not boolean', { termsOfServiceAgreed: 'yes' }],
      ['onlyReturnExisting not boolean', { onlyReturnExisting: 1 }],
      ['externalAccountBinding not an object',
       { externalAccountBinding: 'x' }],
      ['externalAccountBinding not a flattened JWS',
       { externalAccountBinding: { protected: 'e30' } }]
    ];
    for (const shape of shapes) {
      acmeStep(D, 'newAccount, ' + shape[0], dir.newAccount,
               await client.post(dir.newAccount, shape[1],
                                 { key: aliceKey, jwk: true }));
    }
    acmeStep(D, 'newAccount, a binding header with a nonce',
             dir.newAccount, await client.newAccount(aliceKey,
               Object.assign({ extraHeader: { nonce: 'x' } }, binding)));
    acmeStep(D, 'newAccount, a binding signed with RS256',
             dir.newAccount, await client.newAccount(aliceKey,
               Object.assign({ alg: 'RS256' }, binding)));
    acmeStep(D, 'newAccount, a binding for another url',
             dir.newAccount, await client.newAccount(aliceKey,
               Object.assign({ url: dir.newOrder }, binding)));
    const created = acmeStep(D, 'newAccount with the binding',
                             dir.newAccount,
                             await client.newAccount(aliceKey, binding));
    const kid = created.location;
    acmeStep(D, 'newAccount, the same key again', dir.newAccount,
             await client.newAccount(aliceKey, null));
    const thief = C.generateAccountKey('RS256');
    acmeStep(D, 'newAccount, the binding spent', dir.newAccount,
             await client.newAccount(thief, binding));
    acmeStep(D, 'newAccount, onlyReturnExisting for an unknown key',
             dir.newAccount, await client.newAccount(thief, null,
               { onlyReturnExisting: true }));

    // The envelope.
    acmeStep(D, 'the media type', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, contentType: 'application/json' }));
    acmeStep(D, 'the size', dir.newOrder,
             await client.post(dir.newOrder, null,
               { key: aliceKey, kid: kid, body: 'x'.repeat(70000) }));
    acmeStep(D, 'a body that is not JSON', dir.newOrder,
             await client.post(dir.newOrder, null,
               { key: aliceKey, kid: kid, body: '{nope' }));
    acmeStep(D, 'a body that is an array', dir.newOrder,
             await client.post(dir.newOrder, null,
               { key: aliceKey, kid: kid, body: '[]' }));
    acmeStep(D, 'an unprotected header', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, mutate: function (flat) {
                 return Object.assign({ header: {} }, flat);
               } }));
    acmeStep(D, 'no signature', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, mutate: function (flat) {
                 return { protected: flat.protected, payload: flat.payload };
               } }));
    acmeStep(D, 'a member that is not a string', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, mutate: function (flat) {
                 return Object.assign({}, flat, { signature: 7 });
               } }));
    acmeStep(D, 'padded base64url', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, mutate: function (flat) {
                 return Object.assign({}, flat,
                                      { signature: flat.signature + '=' });
               } }));
    acmeStep(D, 'a header that is not JSON', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, mutate: function (flat) {
                 return Object.assign({}, flat, {
                   protected: Buffer.from('{x').toString('base64url') });
               } }));
    acmeStep(D, 'a header with crit', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, header: { crit: ['b64'] } }));
    acmeStep(D, 'a header with no url', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, mutate: function (flat) {
                 const header = JSON.parse(Buffer.from(flat.protected,
                                                       'base64url'));
                 delete header.url;
                 return Object.assign({}, flat, { protected: Buffer.from(
                   JSON.stringify(header)).toString('base64url') });
               } }));
    acmeStep(D, 'a header whose alg is too long', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid,
                 header: { alg: 'X'.repeat(40) } }));
    acmeStep(D, 'a header whose kid is not a string', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, header: { kid: 5 } }));
    acmeStep(D, 'alg none', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, header: { alg: 'none' } }));
    acmeStep(D, 'jwk and kid together', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey, kid: kid, jwk: true }));
    acmeStep(D, 'neither jwk nor kid', dir.newOrder,
             await client.post(dir.newOrder, { identifiers: [] },
               { key: aliceKey }));
    acmeStep(D, 'a jwk with a private member', dir.newAccount,
             await client.post(dir.newAccount, {},
               { key: aliceKey, header: { jwk: Object.assign({ d: 'AAAA' },
                                                             aliceKey.jwk) } }));
    acmeStep(D, 'a jwk that does not fit the alg', dir.newAccount,
             await client.post(dir.newAccount, {},
               { key: aliceKey, header: { jwk: thief.jwk } }));
    acmeStep(D, 'a nonce this server did not issue', kid,
             await client.postAsGet(kid, aliceKey, kid,
                                    { nonce: 'AAAA', noRetry: true }));
    const spent = await client.takeNonce();
    await client.postAsGet(kid, aliceKey, kid, { nonce: spent });
    acmeStep(D, 'a nonce presented twice', kid,
             await client.postAsGet(kid, aliceKey, kid, { nonce: spent }));
    acmeStep(D, 'no nonce', kid,
             await client.postAsGet(kid, aliceKey, kid, { nonce: null }));
    acmeStep(D, 'a url naming another resource', kid,
             await client.postAsGet(kid, aliceKey, kid,
                                    { url: dir.newOrder }));
    acmeStep(D, 'an unknown account', dir.newOrder,
             await client.newOrder(aliceKey, acmeBase +
               '/account/AAAAAAAAAAAAAAAA',
               [{ type: 'permanent-identifier', value: ALICE }]));
    acmeStep(D, 'a signature that does not verify', kid,
             await client.postAsGet(kid, aliceKey, kid,
               { mutate: function (flat) {
                 return Object.assign({}, flat, { signature: flat.signature
                   .replace(/^./, flat.signature[0] === 'A' ? 'B' : 'A') });
               } }));
    acmeStep(D, 'a payload that is not JSON', kid,
             await client.post(kid, { raw: Buffer.from('{x')
               .toString('base64url') }, { key: aliceKey, kid: kid }));
    acmeStep(D, 'a payload that is an array', kid,
             await client.post(kid, { raw: Buffer.from('[1]')
               .toString('base64url') }, { key: aliceKey, kid: kid }));

    // The account.
    acmeStep(D, 'the account, POST-as-GET', kid,
             await client.postAsGet(kid, aliceKey, kid));
    acmeStep(D, 'the account, a contact update', kid,
             await client.post(kid, { contact: ['mailto:' + ALICE +
                                                '@example.test'] },
                               { key: aliceKey, kid: kid }));
    acmeStep(D, 'the account, a status not deactivated', kid,
             await client.post(kid, { status: 'valid' },
                               { key: aliceKey, kid: kid }));
    acmeStep(D, 'the account, a status too long', kid,
             await client.post(kid, { status: 'x'.repeat(40) },
                               { key: aliceKey, kid: kid }));
    acmeStep(D, 'the account, contact not mailto', kid,
             await client.post(kid, { contact: ['https://example.test'] },
                               { key: aliceKey, kid: kid }));
    acmeStep(D, 'the account\'s orders', kid + '/orders',
             await client.postAsGet(kid + '/orders', aliceKey, kid));

    // Orders.
    const orderShapes = [
      ['identifiers missing', {}],
      ['identifiers empty', { identifiers: [] }],
      ['an identifier with another member',
       { identifiers: [{ type: 'dns', value: 'a.test', extra: 1 }] }],
      ['an identifier with an empty value',
       { identifiers: [{ type: 'dns', value: '' }] }],
      ['an identifier type too long',
       { identifiers: [{ type: 'x'.repeat(70), value: 'a' }] }],
      ['a profile that is not a string',
       { identifiers: [{ type: 'permanent-identifier', value: ALICE }],
         profile: 5 }],
      ['an empty profile',
       { identifiers: [{ type: 'permanent-identifier', value: ALICE }],
         profile: '' }],
      ['notAfter', { identifiers: [{ type: 'permanent-identifier',
                                     value: ALICE }],
                     notAfter: '2030-01-01T00:00:00Z' }],
      ['a replaces that is not a certificate identifier',
       { identifiers: [{ type: 'permanent-identifier', value: ALICE }],
         replaces: 'nodot' }],
      ['an unsupported identifier type',
       { identifiers: [{ type: 'bogus', value: 'x' }] }],
      ['a dns value that is not a host name',
       { identifiers: [{ type: 'dns', value: 'not a host' }] }],
      ['another person', { identifiers: [{ type: 'permanent-identifier',
                                           value: BOB }] }],
      ['an unregistered host', { identifiers: [{ type: 'dns',
                                                 value: 'nope.test' }],
                                 profile: 'tls-server' }],
      ['the root-ca profile', { identifiers: [{ type: 'permanent-identifier',
                                                value: ALICE }],
                                profile: 'root-ca' }],
      ['a profile nobody has', { identifiers: [{ type: 'permanent-identifier',
                                                 value: ALICE }],
                                 profile: 'nope' }]
    ];
    for (const shape of orderShapes) {
      acmeStep(D, 'newOrder, ' + shape[0], dir.newOrder,
               await client.post(dir.newOrder, shape[1],
                                 { key: aliceKey, kid: kid }));
    }
    const order = acmeStep(D, 'newOrder', dir.newOrder,
      await client.newOrder(aliceKey, kid,
        [{ type: 'permanent-identifier', value: ALICE },
         { type: 'dns', value: 'www.' + ALICE + '.test' }],
        { profile: 'tls-server-client' }));
    acmeStep(D, 'newOrder naming no profile', dir.newOrder,
             await client.newOrder(aliceKey, kid,
               [{ type: 'dns', value: 'www.' + ALICE + '.test' }]));
    const orderUrl = order.location;
    acmeStep(D, 'the order', orderUrl,
             await client.postAsGet(orderUrl, aliceKey, kid));
    const authzUrl = order.body.authorizations[0];
    const authz = acmeStep(D, 'the authorization', authzUrl,
                           await client.postAsGet(authzUrl, aliceKey, kid));
    acmeStep(D, 'the authorization, a status that is not deactivated',
             authzUrl, await client.post(authzUrl, { status: 'valid' },
                                         { key: aliceKey, kid: kid }));
    const challengeUrl = authz.body.challenges[0].url;
    acmeStep(D, 'the challenge', challengeUrl,
             await client.post(challengeUrl, {}, { key: aliceKey, kid: kid }));
    acmeStep(D, 'the challenge, POST-as-GET', challengeUrl,
             await client.postAsGet(challengeUrl, aliceKey, kid));

    // Finalize.
    const finalizeUrl = order.body.finalize;
    acmeStep(D, 'finalize, no csr', finalizeUrl,
             await client.post(finalizeUrl, {}, { key: aliceKey, kid: kid }));
    acmeStep(D, 'finalize, a csr that is not a string', finalizeUrl,
             await client.post(finalizeUrl, { csr: 5 },
                               { key: aliceKey, kid: kid }));
    acmeStep(D, 'finalize, a csr that is not base64url', finalizeUrl,
             await client.post(finalizeUrl, { csr: '!!' },
                               { key: aliceKey, kid: kid }));
    const extra = await C.buildCsr({ keyAlg: 'ec-p256', cn: ALICE,
      sans: [{ kind: 'dns', value: 'www.' + ALICE + '.test' },
             { kind: 'dns', value: 'extra.' + ALICE + '.test' }] });
    acmeStep(D, 'finalize, a CSR naming another name', finalizeUrl,
             await client.finalize(aliceKey, kid, finalizeUrl, extra.der));
    const good = await C.buildCsr({ keyAlg: 'ec-p256', cn: ALICE,
      sans: [{ kind: 'dns', value: 'www.' + ALICE + '.test' },
             { kind: 'uri', value: 'urn:sts:person:' + ALICE }] });
    acmeStep(D, 'finalize, a CSR whose signature does not verify',
             finalizeUrl, await client.finalize(aliceKey, kid, finalizeUrl,
               C.corruptSignature(good.der)));
    const done = acmeStep(D, 'finalize', finalizeUrl,
                          await client.finalize(aliceKey, kid, finalizeUrl,
                                                good.der));
    acmeStep(D, 'finalize again', finalizeUrl,
             await client.finalize(aliceKey, kid, finalizeUrl, good.der));
    const certUrl = done.body.certificate;
    const cert = acmeStep(D, 'the certificate', certUrl,
                          await client.postAsGet(certUrl, aliceKey, kid));
    const chain = C.splitPemChain(cert.text);
    const certId = C.certIdOf(chain[0]);
    await step('acme', D, 'renewalInfo', 'GET', dir.renewalInfo + '/' +
               certId);
    await step('acme', D, 'renewalInfo, an unknown certificate', 'GET',
               dir.renewalInfo + '/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE');
    await step('acme', D, 'renewalInfo, a malformed identifier', 'GET',
               dir.renewalInfo + '/nodot');
    await step('acme', D, 'renewalInfo, the wrong method', 'POST',
               dir.renewalInfo + '/nodot');
    acmeStep(D, 'newOrder replacing a certificate', dir.newOrder,
             await client.newOrder(aliceKey, kid,
               [{ type: 'permanent-identifier', value: ALICE }],
               { replaces: certId }));
    acmeStep(D, 'newOrder replacing it again', dir.newOrder,
             await client.newOrder(aliceKey, kid,
               [{ type: 'permanent-identifier', value: ALICE }],
               { replaces: certId }));

    // Revocation.
    const der = C.pemToDer(chain[0]);
    acmeStep(D, 'revokeCert, no certificate', dir.revokeCert,
             await client.post(dir.revokeCert, {},
                               { key: aliceKey, kid: kid }));
    acmeStep(D, 'revokeCert, a reason that is not an integer',
             dir.revokeCert, await client.post(dir.revokeCert,
               { certificate: C.b64u(der), reason: 1.5 },
               { key: aliceKey, kid: kid }));
    acmeStep(D, 'revokeCert, a reason out of range', dir.revokeCert,
             await client.post(dir.revokeCert,
               { certificate: Buffer.from(der).toString('base64url'),
                 reason: 5000 }, { key: aliceKey, kid: kid }));
    acmeStep(D, 'revokeCert, reason 7', dir.revokeCert,
             await client.revoke(aliceKey, kid, der, 7));
    acmeStep(D, 'revokeCert, a certificate this server did not issue',
             dir.revokeCert, await client.revoke(aliceKey, kid,
               C.pemToDer(chain[1]), 1));
    acmeStep(D, 'revokeCert by the certificate\'s key', dir.revokeCert,
             await client.revoke(C.accountKeyFromPem('ES256',
               good.privatePem), null, der, 1));
    acmeStep(D, 'revokeCert again', dir.revokeCert,
             await client.revoke(aliceKey, kid, der, 1));
    await step('acme', D, 'renewalInfo of a revoked certificate', 'GET',
               dir.renewalInfo + '/' + certId);

    // Key change.
    const bobEab = await api(A, '/acme/create-eab', { kind: 'person',
                                                      identifier: BOB });
    const bobKey = C.generateAccountKey('EdDSA');
    const bobAccount = acmeStep(D, 'newAccount, an EdDSA key',
      dir.newAccount, await client.newAccount(bobKey,
        { kid: bobEab.kid, hmacKey: bobEab.hmacKey }));
    const bobKid = bobAccount.location;
    acmeStep(D, 'another account reading the authorization', authzUrl,
             await client.postAsGet(authzUrl, bobKey, bobKid));
    acmeStep(D, 'another account reading the certificate', certUrl,
             await client.postAsGet(certUrl, bobKey, bobKid));
    acmeStep(D, 'keyChange to another account\'s key', dir.keyChange,
             await client.keyChange(aliceKey, kid, bobKey));
    const newKey = C.generateAccountKey('ES384');
    acmeStep(D, 'keyChange, an oldKey that is not the account key',
             dir.keyChange, await client.keyChange(aliceKey, kid, newKey,
               { oldKey: C.generateAccountKey('ES256').jwk }));
    acmeStep(D, 'keyChange, the inner payload with no account',
             dir.keyChange, await client.post(dir.keyChange,
               C.flattened(newKey, { alg: newKey.alg, jwk: newKey.jwk,
                                     url: dir.keyChange },
                           { oldKey: aliceKey.jwk }),
               { key: aliceKey, kid: kid }));
    acmeStep(D, 'keyChange, an inner oldKey with no kty', dir.keyChange,
             await client.post(dir.keyChange,
               C.flattened(newKey, { alg: newKey.alg, jwk: newKey.jwk,
                                     url: dir.keyChange },
                           { account: kid, oldKey: {} }),
               { key: aliceKey, kid: kid }));
    acmeStep(D, 'keyChange, the inner url another resource', dir.keyChange,
             await client.keyChange(aliceKey, kid, newKey,
                                    { innerUrl: dir.newOrder }));
    acmeStep(D, 'keyChange', dir.keyChange,
             await client.keyChange(aliceKey, kid, newKey));
    acmeStep(D, 'the old key', kid,
             await client.postAsGet(kid, aliceKey, kid));
    acmeStep(D, 'the authorization, deactivated', authzUrl,
             await client.post(authzUrl, { status: 'deactivated' },
                               { key: newKey, kid: kid }));
    acmeStep(D, 'the account, deactivated', kid,
             await client.post(kid, { status: 'deactivated' },
                               { key: newKey, kid: kid }));
    acmeStep(D, 'a deactivated account', kid,
             await client.postAsGet(kid, newKey, kid));

    await step('acme', 'switched off', 'directory', 'GET',
               base + '/realm/' + OFF + '/enroll/acme/directory');
    await step('acme', 'product', 'directory over plain HTTP', 'GET',
               base + '/realm/' + PROD + '/enroll/acme/directory');

    // =====================================================================
    // EST.
    // =====================================================================
    const est = base + '/realm/' + A + '/.well-known/est';
    const basic = E.basicHeader(ALICE, 'x');
    const pkcs10 = { 'Content-Type': 'application/pkcs10',
                     Authorization: basic };
    const estCsr = await C.buildCsr({ keyAlg: 'ec-p256', cn: ALICE, sans: [] });
    const csrBody = E.requestBody(estCsr.der);
    await step('est', D, 'cacerts', 'GET', est + '/cacerts');
    await step('est', D, 'cacerts, a query string', 'GET',
               est + '/cacerts?x=1');
    await step('est', D, 'cacerts, an unknown label', 'GET',
               est + '/nope/cacerts');
    await step('est', D, 'cacerts, a label', 'GET',
               est + '/tls-client/cacerts');
    await step('est', D, 'csrattrs', 'GET', est + '/csrattrs');
    await step('est', D, 'csrattrs, a label', 'GET',
               est + '/tls-server/csrattrs');
    await step('est', D, 'fullcmc', 'POST', est + '/fullcmc');
    await step('est', D, 'simpleenroll, the wrong method', 'GET',
               est + '/simpleenroll');
    await step('est', D, 'simpleenroll, no credential', 'POST',
               est + '/simpleenroll', { headers: {
                 'Content-Type': 'application/pkcs10' }, body: csrBody });
    await step('est', D, 'simpleenroll, a Bearer header', 'POST',
               est + '/simpleenroll', { headers: {
                 'Content-Type': 'application/pkcs10',
                 Authorization: 'Bearer abc' }, body: csrBody });
    await step('est', D, 'simpleenroll, a Basic header that is not base64',
               'POST', est + '/simpleenroll', { headers: {
                 'Content-Type': 'application/pkcs10',
                 Authorization: 'Basic !!!' }, body: csrBody });
    await step('est', D, 'simpleenroll, the wrong media type', 'POST',
               est + '/simpleenroll', { headers: {
                 'Content-Type': 'text/plain', Authorization: basic },
                 body: csrBody });
    await step('est', D, 'simpleenroll, base64 that is not', 'POST',
               est + '/simpleenroll', { headers: pkcs10, body: 'MII@@@' });
    await step('est', D, 'simpleenroll, a body that is no CSR', 'POST',
               est + '/simpleenroll', { headers: pkcs10,
                 body: Buffer.from('not a csr').toString('base64') });
    await step('est', D, 'simpleenroll, a refused profile', 'POST',
               est + '/kdc/simpleenroll', { headers: pkcs10, body: csrBody });
    await step('est', D, 'simpleenroll', 'POST', est + '/simpleenroll',
               { headers: pkcs10, body: csrBody });
    await step('est', D, 'simplereenroll', 'POST', est + '/simplereenroll',
               { headers: pkcs10, body: csrBody });
    await step('est', D, 'serverkeygen', 'POST', est + '/serverkeygen',
               { headers: pkcs10, body: csrBody });
    await step('est', D, 'nonce, GET', 'GET', est + '/nonce',
               { headers: { Authorization: basic } });
    await step('est', D, 'nonce, GET with no credential', 'GET',
               est + '/nonce');
    const fresh = { 'Content-Type':
                    'application/est-attestation-freshness+json',
                    Authorization: basic };
    const nonceBodies = [
      ['a length', { len: 32 }],
      ['not JSON', '{x'],
      ['an array', '[]'],
      ['a length too short', { len: 4 }],
      ['a length that is not an integer', { len: 8.5 }],
      ['another member', { other: 1 }],
      ['a type that is not an OID', { reqTypeInfo: { type: 'x' } }],
      ['a type with another member',
       { reqTypeInfo: { type: '1.2.3', other: 1 } }],
      ['a type', { reqTypeInfo: { type: '1.2.3', reqInfo: { a: 1 } } }]
    ];
    for (const one of nonceBodies) {
      await step('est', D, 'nonce, POST, ' + one[0], 'POST', est + '/nonce',
                 { headers: fresh, body: typeof one[1] === 'string' ? one[1]
                   : JSON.stringify(one[1]) });
    }
    await step('est', D, 'nonce, POST, another media type', 'POST',
               est + '/nonce', { headers: { 'Content-Type':
                 'application/json', Authorization: basic }, body: '{}' });
    await step('est', 'switched off', 'cacerts', 'GET',
               base + '/realm/' + OFF + '/.well-known/est/cacerts');
    await step('est', 'product', 'cacerts over plain HTTP', 'GET',
               base + '/realm/' + PROD + '/.well-known/est/cacerts');

    // =====================================================================
    // SCEP.
    // =====================================================================
    const scep = base + '/realm/' + A + '/enroll/scep';
    await step('scep', D, 'GetCACaps', 'GET', scep + '?operation=GetCACaps');
    await step('scep', D, 'GetCACaps, pkiclient.exe', 'GET',
               scep + '/pkiclient.exe?operation=GetCACaps');
    const caCert = await step('scep', D, 'GetCACert', 'GET',
                              scep + '?operation=GetCACert');
    const parsedCa = S.certsOnly(caCert.bytes);
    caCert.one.body = { certificates: parsedCa.certificates
      .map(function (pem) {
        return new nodeCrypto.X509Certificate(pem).subject;
      }) };
    const raPem = parsedCa.certificates.filter(function (pem) {
      return !new nodeCrypto.X509Certificate(pem).ca;
    })[0];
    await step('scep', D, 'GetNextCACert', 'GET',
               scep + '?operation=GetNextCACert');
    await step('scep', D, 'no operation', 'GET', scep);
    await step('scep', D, 'an unknown operation', 'GET',
               scep + '?operation=Nope');
    await step('scep', D, 'another parameter', 'GET',
               scep + '?operation=GetCACaps&x=1');
    await step('scep', D, 'an unknown profile', 'GET',
               scep + '/nope?operation=GetCACaps');
    await step('scep', D, 'a profile segment that is not a name', 'GET',
               scep + '/NO_PE?operation=GetCACaps');
    await step('scep', D, 'PKIOperation, the wrong media type', 'POST',
               scep + '?operation=PKIOperation', { headers: {
                 'Content-Type': 'text/plain' }, body: 'x' });
    await step('scep', D, 'PKIOperation, a body that is not CMS', 'POST',
               scep + '?operation=PKIOperation', { headers: {
                 'Content-Type': 'application/x-pki-message' },
                 body: Buffer.from('not cms') });
    await step('scep', D, 'PKIOperation, GET with no message', 'GET',
               scep + '?operation=PKIOperation');
    await step('scep', D, 'PKIOperation, GET with a message that is not ' +
               'base64', 'GET', scep + '?operation=PKIOperation&message=%21');
    const made = await api(A, '/scep/create-challenge', { kind: 'person',
      identifier: ALICE, profile: 'tls-client' });
    async function scepOp(name, challenge, extraOpts) {
      const key = S.rsaKey(2048);
      const certPem = S.selfSigned(key, ALICE);
      const der = S.signedMessage({
        content: S.envelope(S.csr(key, { commonName: ALICE,
                                         challenge: challenge }), raPem),
        signerCertPem: certPem, signerKeyPem: key.privateKeyPem,
        messageType: '19', transactionID: 'wire-' + name.replace(/\W/g, ''),
        senderNonce: nodeCrypto.randomBytes(16) });
      const answer = await step('scep', D, name, (extraOpts || {}).get
        ? 'GET' : 'POST', scep + '?operation=PKIOperation', (extraOpts || {})
        .get ? undefined : { headers: { 'Content-Type':
          'application/x-pki-message' }, body: der });
      if ((extraOpts || {}).get) {
        record.wire.pop();
        const r = await step('scep', D, name, 'GET',
                             scep + '?operation=PKIOperation&message=' +
                             encodeURIComponent(der.toString('base64')));
        return r;
      }
      return answer;
    }
    function certRep(answer) {
      try {
        const rep = S.readCertRep(answer.bytes, raPem);
        answer.one.body = { messageType: rep.messageType,
                            pkiStatus: rep.pkiStatus,
                            failInfo: rep.failInfoName,
                            signatureVerifies: rep.signatureVerifies };
      } catch (e) {
        answer.one.body = { unreadable: String(e && e.message) };
      }
    }
    certRep(await scepOp('PKIOperation, a wrong challenge', 'nope.nope'));
    certRep(await scepOp('PKIOperation, PKCSReq', made.challenge));
    certRep(await scepOp('PKIOperation, PKCSReq spent again',
                         made.challenge));
    const madeGet = await api(A, '/scep/create-challenge', { kind: 'person',
      identifier: ALICE, profile: 'tls-client' });
    certRep(await scepOp('PKIOperation, PKCSReq over GET', madeGet.challenge,
                         { get: true }));
    await step('scep', 'switched off', 'GetCACaps', 'GET',
               base + '/realm/' + OFF + '/enroll/scep?operation=GetCACaps');
    await step('scep', 'product', 'GetCACaps over plain HTTP', 'GET',
               base + '/realm/' + PROD + '/enroll/scep?operation=GetCACaps');

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push(e && e.stack ? e.stack : String(e));
    fs.writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

// Walks a value: a volatile member's value is replaced by its name, a PEM
// block by its label.
function scrub(value, name) {
  log.debug("Entering scrub().");
  if (Array.isArray(value)) {
    const list = value.map(function (one) {
      return scrub(one, name);
    });
    log.debug("Leaving scrub().");
    return list;
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(function (key) {
      out[key] = scrub(value[key], key);
    });
    log.debug("Leaving scrub().");
    return out;
  }
  if (name === 'set-cookie' && typeof value === 'string') {
    log.debug("Leaving scrub(). A cookie.");
    return value.replace(/=[^;]*/, '=<cookie>');
  }
  if (['replay-nonce', 'nonce', 'key', 'hmacKey'].indexOf(name) >= 0 &&
      value) {
    log.debug("Leaving scrub(). A volatile member.");
    return '<' + name + '>';
  }
  if (typeof value === 'string' && value.indexOf('-----BEGIN ') >= 0) {
    log.debug("Leaving scrub(). PEM.");
    return value.replace(/-----BEGIN ([A-Z ]+)-----[\s\S]*?-----END \1-----/g,
                         '<pem:$1>');
  }
  log.debug("Leaving scrub().");
  return value;
}

// The run-to-run values, each replaced by a placeholder.
function normalise(record) {
  log.debug("Entering normalise().");
  const PATTERNS = [
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['httpdate', /[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT/g],
    ['port', /127\.0\.0\.1(:|%3A)\d+/g],
    ['epoch', /\b1[789]\d{8}\b/g],
    ['uptime', /up \d+ second\(s\)/g],
    // An ACME resource's id, which this service mints at random.
    ['id', /(?<=\/enroll\/acme\/(account|order|authz|challenge|cert)\/)[A-Za-z0-9_-]{8,64}/g],
    // RFC 9773's certificate identifier: two base64url parts.
    ['certid', /[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{6,}(?![A-Za-z0-9_.-])/g],
    // A serial number in hex, in a sentence.
    ['serial', /\b[0-9a-f]{16,}\b/g],
    // A random id: a digit, or both cases, in a long base64url run.
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*([0-9]|[A-Z][A-Za-z0-9_-]*[a-z]|[a-z][A-Za-z0-9_-]*[A-Z]))[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])/g]
  ];
  let out = JSON.stringify(scrub(record), null, 1);
  PATTERNS.forEach(function (pair) {
    out = out.replace(pair[1], '<' + pair[0] + '>');
  });
  log.debug("Leaving normalise().");
  return JSON.parse(out);
}

// Runs the child and answers its record, normalised, or null.
function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'enrollment-model-wire-' + process.pid +
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
                                  EW_ROOT: ROOT, EW_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in capture(): " + ((e && e.message) || e));
    log.debug("Leaving capture(). No record: exit " + result.status + " " +
              String(result.stderr || '').slice(-800));
    return null;
  }
  log.debug("Leaving capture().");
  return normalise(record);
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + '.' + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ': ' + JSON.stringify(b).slice(0, 300) + ' where ' +
    JSON.stringify(a).slice(0, 300) + ' was recorded';
}

// The recorded conversation, for `tests/model_enrollment.js` to hold every
// answer to the model.
function recorded() {
  log.debug("Entering recorded().");
  const out = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'));
  log.debug("Leaving recorded().");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const now = capture();
  if (!t.check(!!now, 'the child process reported')) {
    log.debug("Leaving run().");
    return;
  }
  t.check(now.problems.length === 0, 'the child ran to the end',
          now.problems.join('\n'));
  let before = null;
  try {
    before = recorded();
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    before = null;
  }
  if (!t.check(!!before, 'the recorded wire is in the tree', SNAPSHOT)) {
    log.debug("Leaving run().");
    return;
  }
  t.check(before.wire.length === now.wire.length,
          'the conversation has as many steps as recorded',
          now.wire.length + ' vs ' + before.wire.length);
  before.wire.forEach(function (one, i) {
    t.check(firstDifference(one, now.wire[i], 'wire') === null,
            one.family + ', ' + one.mode + ', ' + one.step +
            ' answers as recorded (' + one.status + ')',
            firstDifference(one, now.wire[i], 'wire'));
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.ENROLLMENT_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'enrollment_model_wire',
  describe: 'what ACME, EST and SCEP answer, byte for byte, against the ' +
            'record made before their request shapes, answers, error types ' +
            'and registers came from the model (#1579): every ACME ' +
            'resource\'s success and refusals, every EST and SCEP ' +
            'operation, switched off and in a product-mode realm',
  run: run,
  recorded: recorded
};
