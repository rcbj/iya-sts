'use strict';
//
// File: cluster_single_use_protocols.js
//
// ===========================================================================
// ISSUE #46 SECTION 2, THE NON-OAUTH HALF: A SINGLE-USE VALUE IS SPENT ONCE ON
// EVERY NODE, NOT ONCE PER NODE (2026-09-14).
//
// Each value below was spent by a check and a delete on a replicated map, which
// is once in one process and once PER PROCESS against one store — two nodes
// inside the replication window both accepted it. Each is now spent through
// `cluster/cluster_claims.js` after the in-memory check. What is held here, for
// every one of them:
//
//   1. a SAML 2.0 artifact and a SAML 1.1 artifact resolve once, and a node
//      still holding one is refused because another node resolved it;
//   2. an OpenID4VCI pre-authorized code redeems once, a c_nonce is spent once,
//      and Transaction Code failures share ONE budget however many nodes and
//      however stale each node's record;
//   3. a GNAP continuation access token, an interaction start link and a key
//      proof are spent once, and a continuation refused WITHOUT rotating its
//      token gives the claim back;
//   4. a Kerberos AP-REQ Authenticator is accepted once, and one refused
//      because the store could not be asked is accepted on the retry.
//
// **"ANOTHER NODE" IS THIS PROCESS WITH ITS MAP PUT BACK.** A node that has not
// yet applied the change log is exactly a process whose map still holds the
// value, so each case spends a value, restores the row the spend removed — the
// way a restore from the store would — and spends it again. The claim store is
// a STUB DRIVER with postgres's semantics (one winner per key, a lifetime, a
// release pinned to its reservation), installed as `persistence.clusterStore`,
// so the store path of `cluster_claims.js` is the one exercised.
//
// **EVERY REFUSAL HAS ITS CONTROL**: the same restore against an EMPTY store —
// what each node had before this — is accepted, so the refusal is the claim's
// and not some other check's. And a store that throws refuses (fail closed).
//
// **THE CHILD IS NOT FASTIDIOUSNESS**, for `tests/rfc9068_access_tokens.js`'s
// reason: loading the protocol stack into `run.js`'s one process builds a
// certificate authority and registers every route on the shared app.
//
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first: a second
// node that has not caught up cannot be arranged over HTTP against one
// service, and against two it is a race a job would win only sometimes. The
// live two-node run against a real postgres is recorded in cluster/CLAUDE.md.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'cluster_single_use_protocols',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.CSU_ROOT;
  const OUT = process.env.CSU_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.text !== undefined ? o.text
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
      if (method !== 'GET') {
        headers['content-type'] = o.text !== undefined ? 'text/xml'
          : 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // Not JSON (a SOAP envelope, a page); the text is what is read.
            parsed = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  // A claim store with postgres's semantics: one winner per key while the row
  // lives, an expired row replaced, a release pinned to its reservation.
  function sharedStore() {
    const rows = new Map();
    return {
      rows: rows,
      claimOnce: function (scope, realm, key, opts) {
        const k = scope + ' ' + realm + ' ' + key;
        const now = Date.now();
        const row = rows.get(k);
        if (row && row.expiresAt > now) {
          return Promise.resolve({ claimed: false, existing: {
            origin: 'another node', claimedAt: row.claimedAt,
            expiresAt: row.expiresAt } });
        }
        rows.set(k, { reservation: opts.reservation, claimedAt: now,
                      expiresAt: now + opts.ttlMs, scope: scope });
        return Promise.resolve({ claimed: true });
      },
      releaseClaim: function (scope, realm, key, reservation) {
        const k = scope + ' ' + realm + ' ' + key;
        const row = rows.get(k);
        if (row && row.reservation === reservation) {
          rows.delete(k);
          return Promise.resolve(true);
        }
        return Promise.resolve(false);
      },
      claimHeld: function (scope, realm, key) {
        const row = rows.get(scope + ' ' + realm + ' ' + key);
        return Promise.resolve(!!row && row.expiresAt > Date.now());
      },
      purgeClaims: function () {
        return Promise.resolve(0);
      }
    };
  }

  function brokenStore() {
    const refuse = function () {
      return Promise.reject(new Error('the database is not answering'));
    };
    return { claimOnce: refuse, releaseClaim: refuse, claimHeld: refuse,
             purgeClaims: function () { return Promise.resolve(0); } };
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const persistence = require(ROOT + '/persistence/persistence');
    const capabilities = require(ROOT + '/cluster/cluster_capabilities');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const applications = require(ROOT + '/common/applications');
    const offers = require(ROOT + '/oid4vc/vc_offers');
    const vcIssuer = require(ROOT + '/oid4vc/vc_issuer');
    const gnapStore = require(ROOT + '/gnap/gnap_store');
    const gnapProof = require(ROOT + '/gnap/gnap_proof');
    const gnap = require(ROOT + '/tests/vendored/gnap_client.js');
    const principals = require(ROOT + '/kerberos/krb5_principals.js');
    const krb5Service = require(ROOT + '/kerberos/krb5_service.js');
    const msgs = require(ROOT + '/kerberos/krb5_messages.js');
    const kcrypto = require(ROOT + '/kerberos/krb5_crypto.js');
    const gss = require(ROOT + '/kerberos/krb5_gss.js');

    let store = sharedStore();
    persistence.clusterStore = function () {
      return store;
    };
    const DEFAULT = realms.DEFAULT_REALM.id;

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;

    ['saml.artifacts-once', 'oid4vc.once', 'gnap.once',
     'kerberos.replay-cache'].forEach(function (id) {
      note(capabilities.isProvided(id), '0. the capability "' + id + '" is ' +
           'provided by the module the table names');
    });

    // ======================================================================
    // 1. SAML ARTIFACTS
    // ======================================================================
    const artifacts2 = realms.handleFor('saml2_sso.artifacts');
    const artifacts11 = realms.handleFor('saml11_sso.artifacts');
    const resolve2 = function (artifact) {
      return request(port, 'POST', '/saml2/ars', { text:
        '<soap:Envelope ' +
        'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
        '<soap:Body><samlp:ArtifactResolve ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" ' +
        'Version="2.0" IssueInstant="2026-09-14T00:00:00Z">' +
        '<saml:Issuer>https://sp.csu.example</saml:Issuer>' +
        '<samlp:Artifact>' + artifact + '</samlp:Artifact>' +
        '</samlp:ArtifactResolve></soap:Body></soap:Envelope>' });
    };
    const held2 = function () {
      return { expires: Date.now() + 300000,
               spEntityId: 'https://sp.csu.example',
               xml: '<samlp:Response ID="_csu-held-message"/>' };
    };
    const success2 = /status:Success/;
    artifacts2.restore(DEFAULT, 'CSU-A2', held2());
    let r = await resolve2('CSU-A2');
    note(success2.test(r.text) && /_csu-held-message/.test(r.text),
         '1a. a SAML 2.0 artifact resolves', r.text.slice(0, 300));
    r = await resolve2('CSU-A2');
    note(!success2.test(r.text), '1b. and a second resolution on the same ' +
         'node is refused by the map, as always', r.text.slice(0, 200));
    artifacts2.restore(DEFAULT, 'CSU-A2', held2());
    r = await resolve2('CSU-A2');
    note(/status:Requester/.test(r.text) && !/_csu-held-message/.test(r.text),
         '1c. A NODE STILL HOLDING THE ARTIFACT IS REFUSED, because another ' +
         'node already resolved it (the claim)', r.text.slice(0, 300));
    store = sharedStore();
    artifacts2.restore(DEFAULT, 'CSU-A2', held2());
    r = await resolve2('CSU-A2');
    note(success2.test(r.text), '1d. the control: the same restore against ' +
         'an empty claim store resolves — the refusal was the claim\'s',
         r.text.slice(0, 200));
    store = brokenStore();
    artifacts2.restore(DEFAULT, 'CSU-B2', held2());
    r = await resolve2('CSU-B2');
    note(/status:Responder/.test(r.text) && !/_csu-held-message/.test(r.text),
         '1e. a claim store that cannot be asked REFUSES (fail closed)',
         r.text.slice(0, 300));
    store = sharedStore();
    artifacts2.restore(DEFAULT, 'CSU-C2', held2());
    const both = await Promise.all([resolve2('CSU-C2'), resolve2('CSU-C2')]);
    note(both.filter(function (one) {
      return success2.test(one.text);
    }).length === 1, '1f. two concurrent resolutions of one artifact: ' +
         'exactly one succeeds');

    const resolve11 = function (artifact) {
      return request(port, 'POST', '/saml11/responder', { text:
        '<soap:Envelope ' +
        'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
        '<soap:Body><samlp:Request ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" ' +
        'MinorVersion="1" RequestID="_q1" ' +
        'IssueInstant="2026-09-14T00:00:00Z"><samlp:AssertionArtifact>' +
        artifact + '</samlp:AssertionArtifact></samlp:Request></soap:Body>' +
        '</soap:Envelope>' });
    };
    const held11 = function () {
      return { expires: Date.now() + 300000, rpId: '',
               assertion: '<saml:Assertion ' +
                 'xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ' +
                 'AssertionID="_csu-held-assertion"/>' };
    };
    const success11 = /samlp:Success/;
    artifacts11.restore(DEFAULT, 'CSU-A11', held11());
    r = await resolve11('CSU-A11');
    note(success11.test(r.text) && /_csu-held-assertion/.test(r.text),
         '1g. a SAML 1.1 artifact resolves', r.text.slice(0, 400));
    artifacts11.restore(DEFAULT, 'CSU-A11', held11());
    r = await resolve11('CSU-A11');
    note(/samlp:Requester/.test(r.text) && !/_csu-held-assertion/.test(r.text),
         '1h. A NODE STILL HOLDING THE 1.1 ARTIFACT IS REFUSED (the claim)',
         r.text.slice(0, 300));
    store = sharedStore();
    artifacts11.restore(DEFAULT, 'CSU-A11', held11());
    r = await resolve11('CSU-A11');
    note(success11.test(r.text), '1i. the control: against an empty claim ' +
         'store it resolves', r.text.slice(0, 200));
    store = brokenStore();
    artifacts11.restore(DEFAULT, 'CSU-B11', held11());
    r = await resolve11('CSU-B11');
    note(/samlp:Responder/.test(r.text) && !/_csu-held-assertion/.test(r.text),
         '1j. and a claim store that cannot be asked refuses', r.text.slice(0,
                                                                        300));
    store = sharedStore();

    // ======================================================================
    // 2. OPENID4VCI
    // ======================================================================
    const SECRET = 'csu-client-secret-0123456789abcdef';
    const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
    const client = { client_id: 'csu-client', client_secret: SECRET };
    ldap.createUser('csu-alice', { invent: false });
    applications.createApplication({ identifier: 'csu-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'csu-client', oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: [PRE_AUTH] } });
    const fakeReq = { protocol: 'http', headers: { host: '127.0.0.1:' + port },
                      get: function (n) {
                        return String(n).toLowerCase() === 'host' ?
                               '127.0.0.1:' + port : undefined;
                      } };
    const redeem = function (code, txCode) {
      return request(port, 'POST', '/oauth2/token', { form: Object.assign({
        grant_type: PRE_AUTH,
        'pre-authorized_code': code, tx_code: txCode }, client) });
    };
    let built = offers.buildCredentialOffer(fakeReq, ['IdentityCredential'],
                                            'cross-device');
    let copy = JSON.parse(JSON.stringify(
        offers.preAuthorizedCodes.get(built.preAuthorizedCode)));
    r = await redeem(built.preAuthorizedCode, built.txCode);
    note(r.status === 200 && r.json && r.json.access_token,
         '2a. a pre-authorized code redeems', r.status + ' ' +
         r.text.slice(0, 200));
    offers.preAuthorizedCodes.set(built.preAuthorizedCode, copy);
    r = await redeem(built.preAuthorizedCode, built.txCode);
    note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
         '2b. A NODE STILL HOLDING THE CODE IS REFUSED invalid_grant, ' +
         'because another node redeemed it (the claim)', r.status + ' ' +
         r.text.slice(0, 200));
    store = sharedStore();
    offers.preAuthorizedCodes.set(built.preAuthorizedCode, copy);
    r = await redeem(built.preAuthorizedCode, built.txCode);
    note(r.status === 200, '2c. the control: against an empty claim store ' +
         'the same restore redeems', r.status + ' ' + r.text.slice(0, 200));
    store = brokenStore();
    built = offers.buildCredentialOffer(fakeReq, ['IdentityCredential'],
                                        'cross-device');
    r = await redeem(built.preAuthorizedCode, built.txCode);
    note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
         '2d. a claim store that cannot be asked refuses the redemption',
         r.status + ' ' + r.text.slice(0, 200));
    store = sharedStore();

    // The Transaction Code budget, in product mode where it is counted.
    config.setOverride('global.mode', 'product');
    config.setOverride('oid4vci.txCodeMaxAttempts', 3);
    built = offers.buildCredentialOffer(fakeReq, ['IdentityCredential'],
                                        'cross-device');
    const code = built.preAuthorizedCode;
    const stale = JSON.parse(JSON.stringify(
        offers.preAuthorizedCodes.get(code)));
    const wrong = built.txCode === '1111' ? '2222' : '1111';
    const pair = await Promise.all([
      offers.checkTxCode(code, stale, wrong),
      offers.checkTxCode(code, stale, wrong)]);
    const lefts = pair.map(function (one) {
      return one.attemptsLeft;
    }).sort();
    note(JSON.stringify(lefts) === '[1,2]',
         '2e. TWO CONCURRENT WRONG CODES, EACH NODE READING A RECORD WITH NO ' +
         'FAILURES, ARE COUNTED AS TWO — not "one" twice',
         JSON.stringify(pair));
    const third = await offers.checkTxCode(code, stale, wrong);
    note(third.spent === true, '2f. and a third, on a node whose record ' +
         'still says zero, spends the code: one budget for the cluster',
         JSON.stringify(third));
    offers.preAuthorizedCodes.set(code, stale);
    r = await redeem(code, built.txCode);
    note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
         '2g. the RIGHT code on a node still holding the record is refused, ' +
         'because the budget spent the code everywhere', r.status + ' ' +
         r.text.slice(0, 200));
    store = sharedStore();
    const perNode = await offers.checkTxCode(code, stale, wrong);
    store = sharedStore();
    const otherNode = await offers.checkTxCode(code, stale, wrong);
    note(perNode.attemptsLeft === 2 && otherNode.attemptsLeft === 2,
         '2h. the control: a node with a claim store of its own counts from ' +
         'its own record, which is the N-times budget this closes',
         JSON.stringify([perNode, otherNode]));
    store = brokenStore();
    const uncounted = await offers.checkTxCode(code, stale, wrong);
    note(uncounted.store === true && uncounted.ok === false,
         '2i. a wrong code that cannot be counted is refused as uncountable',
         JSON.stringify(uncounted));
    store = sharedStore();
    config.clearOverride('oid4vci.txCodeMaxAttempts');
    config.clearOverride('global.mode');

    // The c_nonce.
    const proofWith = function (nonce) {
      return 'x.' + Buffer.from(JSON.stringify({ nonce: nonce }))
        .toString('base64url') + '.y';
    };
    await realms.run(realms.DEFAULT_REALM, async function () {
      vcIssuer.vciNonces.set('csu-nonce', Date.now() + 60000);
      let spent = await vcIssuer.spendProofNonces([proofWith('csu-nonce'),
                                                   proofWith('csu-nonce')]);
      note(spent.ok === true, '2j. a c_nonce quoted by every proof in a ' +
           'batch is spent once', JSON.stringify(spent));
      vcIssuer.vciNonces.set('csu-nonce', Date.now() + 60000);
      spent = await vcIssuer.spendProofNonces([proofWith('csu-nonce')]);
      note(spent.ok === false && spent.errorCode === 'STS-VC-0050',
           '2k. A NODE STILL HOLDING THE c_nonce IS REFUSED (the claim)',
           JSON.stringify(spent));
      store = sharedStore();
      vcIssuer.vciNonces.set('csu-nonce', Date.now() + 60000);
      spent = await vcIssuer.spendProofNonces([proofWith('csu-nonce')]);
      note(spent.ok === true, '2l. the control: against an empty store it is ' +
           'spent', JSON.stringify(spent));
      vcIssuer.vciNonces.set('csu-nonce-2', Date.now() + 60000);
      const racing = await Promise.all([
        vcIssuer.spendProofNonces([proofWith('csu-nonce-2')]),
        vcIssuer.spendProofNonces([proofWith('csu-nonce-2')])]);
      note(racing.filter(function (one) { return one.ok; }).length === 1,
           '2m. two concurrent Credential Requests quoting one c_nonce: ' +
           'exactly one spends it', JSON.stringify(racing));
      store = brokenStore();
      vcIssuer.vciNonces.set('csu-nonce-3', Date.now() + 60000);
      spent = await vcIssuer.spendProofNonces([proofWith('csu-nonce-3')]);
      note(spent.ok === false && spent.errorCode === 'STS-VC-0051',
           '2n. and a store that cannot be asked refuses',
           JSON.stringify(spent));
      store = sharedStore();
    });

    // ======================================================================
    // 3. GNAP
    // ======================================================================
    config.setOverride('gnap.continueWaitS', 0);
    const GRANT = base + '/gnap';
    const gnapClient = new gnap.Client({ key: gnap.newKey('ES256') });
    const grantBody = { access_token: { access: ['csu-read'] },
      client: { key: gnapClient.keyObject(),
                display: { name: 'csu', uri: 'https://client.csu.test/' } },
      interact: { start: ['app'] } };
    r = await gnapClient.send('POST', GRANT, { json: grantBody });
    const pending = r.json || {};
    note(r.status === 200 && pending.continue && pending.interact &&
         pending.interact.app, '3a. a GNAP grant request with the app start ' +
         'mode is pending', r.status + ' ' + r.text.slice(0, 300));
    if (pending.continue && pending.interact && pending.interact.app) {
      const T = pending.continue.access_token.value;
      const continuationRow = realms.handleFor('gnap.continuations');
      const tHash = gnapStore.digest(T);
      const tRow = JSON.parse(JSON.stringify(
          continuationRow.read(DEFAULT, tHash).value));
      const poll = function (token, json) {
        return gnapClient.send('POST', pending.continue.uri,
                               { token: token, json: json });
      };
      r = await poll(T, { unexpected: true });
      note(r.status === 400, '3b. a continuation refused WITHOUT rotating ' +
           'its token (a malformed body)', r.status + ' ' + r.text.slice(0,
                                                                     200));
      r = await poll(T);
      note(r.status === 200 && r.json && r.json.continue &&
           r.json.continue.access_token.value !== T,
           '3c. …GAVE ITS CLAIM BACK: the same token still continues, and ' +
           'the poll rotates it', r.status + ' ' + r.text.slice(0, 200));
      const T2 = r.json && r.json.continue &&
                 r.json.continue.access_token.value;
      continuationRow.restore(DEFAULT, tHash, tRow);
      r = await poll(T);
      note(r.status === 401 && r.json && r.json.error &&
           (r.json.error.code || r.json.error) === 'invalid_continuation',
           '3d. A NODE STILL HOLDING THE ROTATED TOKEN REFUSES IT ' +
           'invalid_continuation (the claim)', r.status + ' ' +
           r.text.slice(0, 200));
      store = sharedStore();
      continuationRow.restore(DEFAULT, tHash, tRow);
      r = await poll(T);
      note(r.status === 200, '3e. the control: against an empty claim store ' +
           'the same restore continues', r.status + ' ' + r.text.slice(0, 200));
      const T3 = r.json && r.json.continue &&
                 r.json.continue.access_token.value;
      store = brokenStore();
      r = await poll(T3);
      note(r.status === 401, '3f. a claim store that cannot be asked refuses ' +
           'the continuation', r.status + ' ' + r.text.slice(0, 200));
      store = sharedStore();
      note(!!T2, '3g. (the rotated tokens were issued)');

      // The start link.
      const appPath = new URL(pending.interact.app).pathname;
      const id = appPath.split('/').pop();
      const grants = realms.handleFor('gnap.grants');
      const interactionsRow = realms.handleFor('gnap.interactions');
      const grantId = interactionsRow.read(DEFAULT, 'app:' + id).value.grantId;
      const grantBefore = JSON.parse(JSON.stringify(
          grants.read(DEFAULT, grantId).value));
      const interactionBefore = JSON.parse(JSON.stringify(
          interactionsRow.read(DEFAULT, 'app:' + id).value));
      r = await request(port, 'GET', appPath);
      note(r.status === 303, '3h. the app start link is followed once',
           r.status + ' ' + r.text.slice(0, 200));
      grants.restore(DEFAULT, grantId, JSON.parse(JSON.stringify(grantBefore)));
      interactionsRow.restore(DEFAULT, 'app:' + id, interactionBefore);
      r = await request(port, 'GET', appPath);
      note(r.status === 400, '3i. A NODE STILL HOLDING THE UNUSED LINK ' +
           'REFUSES IT (the claim)', r.status + ' ' + r.text.slice(0, 200));
      store = sharedStore();
      grants.restore(DEFAULT, grantId, JSON.parse(JSON.stringify(grantBefore)));
      interactionsRow.restore(DEFAULT, 'app:' + id, interactionBefore);
      r = await request(port, 'GET', appPath);
      note(r.status === 303, '3j. the control: against an empty claim store ' +
           'the same restore is followed', r.status);
      store = sharedStore();
    }
    config.clearOverride('gnap.continueWaitS');

    await realms.run(realms.DEFAULT_REALM, async function () {
      const verified = { ok: true, replayKeys: ['httpsig|csu|nonce-1'] };
      let once = await gnapProof.spendProof(verified);
      note(once.ok === true, '3k. a key proof\'s replay key is spent',
           JSON.stringify(once));
      once = await gnapProof.spendProof(verified);
      note(once.ok === false && once.errorCode === 'STS-GNAP-0715',
           '3l. A PROOF ANOTHER NODE ACCEPTED IS REFUSED where this node\'s ' +
           'replay cache never saw it', JSON.stringify(once));
      store = brokenStore();
      once = await gnapProof.spendProof({ ok: true,
                                          replayKeys: ['jws|csu-sig'] });
      note(once.ok === false && once.errorCode === 'STS-GNAP-0716',
           '3m. and a store that cannot be asked refuses the proof',
           JSON.stringify(once));
      store = sharedStore();
    });

    // ======================================================================
    // 4. KERBEROS
    // ======================================================================
    const apReqFor = async function (clientName, cusec) {
      const service = principals.find(['HTTP', 'web.example.com']);
      const etype = 18;
      const profile = kcrypto.etypeById(etype);
      const serviceKey = await principals.longTermKey(service, etype);
      const sessionKey = kcrypto.randomBytes(profile.keyBytes);
      const now = new Date();
      const cname = { type: 1, name: [clientName] };
      const ticketPart = msgs.encEncTicketPart({
        flags: [], key: { etype: etype, key: sessionKey },
        crealm: principals.REALM, cname: cname,
        transited: { type: 1, contents: new Uint8Array(0) },
        authtime: now, starttime: now,
        endtime: new Date(now.getTime() + 3600000) });
      const authenticator = msgs.encAuthenticator({
        crealm: principals.REALM, cname: cname, cusec: cusec, ctime: now });
      const apReq = msgs.encApReq({
        apOptions: [],
        ticket: { realm: principals.REALM,
                  sname: { type: 3, name: ['HTTP', 'web.example.com'] },
                  encPart: { etype: etype, kvno: service.kvno,
                             cipher: await profile.encrypt(serviceKey,
                               kcrypto.KEY_USAGE.KDC_REP_TICKET,
                               ticketPart) } },
        authenticator: { etype: etype,
                         cipher: await profile.encrypt(sessionKey,
                           kcrypto.KEY_USAGE.AP_REQ_AUTH, authenticator) } });
      return gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq);
    };
    const replayOf = function (result) {
      return (result.checks || []).filter(function (c) {
        return c.name === 'not a replay';
      })[0] || {};
    };
    const cache = krb5Service.replayCache;
    const captured = await apReqFor('csu-victim', 424242);
    let accepted = await krb5Service.acceptRaw(captured, { record: false });
    note(accepted.ok === true, '4a. a genuine AP-REQ is accepted',
         JSON.stringify(replayOf(accepted)));
    const keysBefore = Array.from(cache.keys());
    keysBefore.forEach(function (k) {
      if (/csu-victim/.test(k)) {
        cache.delete(k);
      }
    });
    accepted = await krb5Service.acceptRaw(captured, { record: false });
    note(accepted.ok === false && accepted.errorCode === 'STS-KRB-0116' &&
         /another node/.test(String(replayOf(accepted).detail)),
         '4b. A REPLAY DELIVERED TO A NODE WHOSE CACHE NEVER SAW IT IS ' +
         'REFUSED (the claim)', JSON.stringify(replayOf(accepted)));
    store = sharedStore();
    Array.from(cache.keys()).forEach(function (k) {
      if (/csu-victim/.test(k)) {
        cache.delete(k);
      }
    });
    accepted = await krb5Service.acceptRaw(captured, { record: false });
    note(accepted.ok === true, '4c. the control: against an empty claim ' +
         'store that node accepts it — the refusal was the claim\'s',
         JSON.stringify(replayOf(accepted)));
    store = brokenStore();
    const fresh = await apReqFor('csu-retry', 515151);
    accepted = await krb5Service.acceptRaw(fresh, { record: false });
    const kept = Array.from(cache.keys()).some(function (k) {
      return /csu-retry/.test(k);
    });
    note(accepted.ok === false && accepted.errorCode === 'STS-KRB-0117' &&
         !kept, '4d. a claim store that cannot be asked refuses, and the ' +
         'cache forgets the Authenticator', JSON.stringify(replayOf(accepted)));
    store = sharedStore();
    accepted = await krb5Service.acceptRaw(fresh, { record: false });
    note(accepted.ok === true, '4e. so the retry once the store answers is ' +
         'accepted, not refused as a replay',
         JSON.stringify(replayOf(accepted)));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'cluster-single-use-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|GNAP_|SAML|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', CSU_ROOT: ROOT, CSU_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== SAML artifacts, OpenID4VCI, GNAP and Kerberos, spent once ' +
             'across the cluster (#46), in a child process ===');
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_single_use_protocols',
  describe: 'issue #46 section 2: SAML artifacts, OpenID4VCI codes, nonces ' +
            'and tx_code budget, GNAP continuation/start/proof, Kerberos ' +
            'Authenticators spent once across nodes',
  run: run
};
