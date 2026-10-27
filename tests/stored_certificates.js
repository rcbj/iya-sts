// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: stored_certificates.js
//
// ===========================================================================
// A CERTIFICATE FROM AN OUTSIDE AUTHORITY IS THE ONE ENTRY STORING IT
// (#1061, rcbj 2026-10-27).
//
// rcbj's rule: a certificate from an outside certificate authority — trusted
// through the Client Truststores — authenticates only if it verifies, passes
// the revocation check, and is byte for byte a leaf stored in
// `userCertificate` on EXACTLY ONE existing entry of the request's realm.
// Never by its common name or subject; never by creating or seeding an
// entry; a certificate stored on two entries is refused; a renewed
// certificate is stored again. `common/tls_client_certificates.js`'s
// `identityOf()` / `checkSocket()` with `{ stored: true }` is the one
// mapping; this file holds it, the directory's index under it, the
// console's /admin-api twin that stores one, and the doors over REAL
// handshakes:
//
//   S. THE MAPPING: the codec's index key; a stored certificate is its
//      person (and an application's, its application); one stored nowhere
//      — though its CN names a person who exists — is NOT_STORED; on two
//      entries STORED_TWICE; a renewed certificate with the same subject is
//      NOT_STORED; another realm's entry is not this realm's; without
//      `{ stored: true }` the answer is the old "not ours", with no lookup;
//      removed, it names nobody again.
//   A. THE ADMIN ACTIONS: add, list, add again (unchanged), garbage
//      (STS-ADMIN-0897), nobody (0898), already on another entry (0899),
//      remove one not held (0900), remove.
//   T. GET /tls/sign-in over a handshake: stored signs its person in;
//      not stored (STS-TLS-0054), stored twice (0055) and renewed start
//      nothing; no entry is seeded from the CN; refused on revocation
//      before anything is looked up.
//   U. THE SIGN-IN SCREEN: the stored certificate is offered as its person
//      and completes the sign-in; one stored nowhere is not offered and its
//      act is refused (STS-AUTHN-0468); stored twice (0469).
//   V. SCIM: stored is the person; not stored is not this credential (401,
//      STS-SCIM-0084 audited); stored twice (0085).
//   X. THE XACML GATES: stored on a member of xacml-users reaches GET
//      /xacml; not stored is refused (STS-XACML-0177), twice (0178); and
//      at the PEP gate, GET /xacml/pep/policies, a member of remote-peps
//      with its certificate stored is admitted, not stored is 0179, twice
//      0180.
//
// Shared Signals, WS-Trust and LDAP SASL EXTERNAL are held in their own
// files (`ssf_client_certificate.js`, `wstrust_client_certificate.js`,
// `ldap_sasl_external.js`).
//
// In a child process, for `authn_certificate_signin.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const https = require('https');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_STORED_CERTIFICATES_CHILD';
const MARK = 'STORED-CERTS-CHILD ';
const REALM = 'storedcerts';
const UA = 'Mozilla/5.0 (X11; Linux x86_64) storedcerts';
const CLIENT = 'storedcerts-client';
const SECRET = 'storedcerts-secret-0123456789abcdef';
const REDIRECT = 'https://rp.storedcerts.example/cb';

const CA_PEM = { value: '' };

const log = require('bunyan').createLogger({ name: 'stored_certificates',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

// One request on a connection of its own, presenting `cred` where given.
function request(port, method, urlPath, cred, jar, headers) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const sent = Object.assign({ 'user-agent': UA }, headers || {});
    if (jar && Object.keys(jar).length) {
      sent.cookie = Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
    }
    const req = https.request({ host: '127.0.0.1', port: port,
      path: String(urlPath).replace(/^https?:\/\/[^/]+/, ''), method: method,
      headers: sent, ca: CA_PEM.value,
      cert: cred ? cred.certPem : undefined,
      key: cred ? cred.keyPem : undefined, agent: false }, function (res) {
      (res.headers['set-cookie'] || []).forEach(function (line) {
        if (!jar) {
          return;
        }
        const pair = line.split(';')[0];
        const eq = pair.indexOf('=');
        jar[pair.slice(0, eq)] = pair.slice(eq + 1);
      });
      let body = '';
      res.on('data', function (chunk) {
        body += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(body);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: body,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in request(): " + e.message);
      resolve({ status: 0, headers: {}, text: '', json: null,
                error: e.message });
    });
    req.end();
  });
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const audit = require(ROOT + '/common/audit');
  const applications = require(ROOT + '/common/applications');
  const errorCodes = require(ROOT + '/common/error_codes');
  const tlsClient = require(ROOT + '/common/tls_client_certificates');
  const tls = require(ROOT + '/tls/tls_server');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const authn = require(ROOT + '/authn/authn');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const codec = require(ROOT + '/persistence/directory_codec');
  const screen = require('./tools/authn_screen');
  const testCa = require('./protocol/outbound_test_ca');
  const outsideCa = require('./tools/pep-credential.js');

  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };
  const markedSince = function (since, code) {
    log.debug("Entering markedSince().");
    log.debug("Leaving markedSince().");
    return marks.slice(since).indexOf(code) >= 0;
  };
  const audited = function (code) {
    log.debug("Entering audited(). " + code);
    log.debug("Leaving audited().");
    return audit.list().some(function (row) {
      return row && row.errorCode === code;
    });
  };

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };
  config.setOverride('oauth2.consentRequired', false);

  // THE PEOPLE. `scalice` exists and is what every certificate's CN names;
  // `scfrank` stores the certificate; `scbob` is the second holder.
  ['scalice', 'scfrank', 'scbob', 'scpep'].forEach(function (name) {
    ldap.createUser(name, { invent: false });
  });
  inRealm(function () {
    ldap.createUser('screalmfrank', { invent: false });
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
  });
  applications.createApplication({ identifier: 'scapp',
    protocols: ['oauth2'], fields: { oauthClientId: 'scapp' } });

  // THE OUTSIDE AUTHORITY'S CERTIFICATES, all CN=scalice: `first` is the
  // one stored, `renewed` the same subject under a new key, `pep` the
  // remote PEP's, `appCred` an application's.
  const mint = function (subject) {
    log.debug("Entering mint().");
    log.debug("Leaving mint().");
    return outsideCa.mint({ subject: subject, crlBase: '' });
  };
  const first = await mint('CN=scalice,O=Outside');
  const renewed = await mint('CN=scalice,O=Outside');
  const pepCred = await mint('CN=scpep,O=Outside');
  const appCred = await mint('CN=scapp,O=Outside');
  const added = tls.addAnchors([first, renewed, pepCred, appCred]
    .map(function (one) {
      return one.anchorPem;
    }).join(''));
  t.check(added && added.added === 4,
          'setup: the four outside Root CAs are in the client truststore',
          JSON.stringify(added));
  const derOf = function (minted) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return new nodeCrypto.X509Certificate(minted.leaf.pem).raw;
  };
  const shaOf = function (minted) {
    log.debug("Entering shaOf().");
    log.debug("Leaving shaOf().");
    return nodeCrypto.createHash('sha256').update(derOf(minted))
      .digest('hex');
  };
  // `revocation_status.fromSocket()`'s shape, as a request worker's shim
  // carries it.
  const input = function (minted, verified) {
    log.debug("Entering input().");
    log.debug("Leaving input().");
    return { leaf: derOf(minted),
             chain: [new nodeCrypto.X509Certificate(minted.issuing.pem).raw],
             verified: verified !== false };
  };

  // -------------------------------------------------------------------------
  // S. THE MAPPING
  // -------------------------------------------------------------------------
  const keys = codec.indexOf({ 'userCertificate;binary':
                               [derOf(first).toString('base64')] });
  t.check(codec.VALUE_INDEXED.indexOf('usercertificatesha256') >= 0 &&
          keys.valueKeys.some(function (one) {
            return String(one).indexOf(shaOf(first)) >= 0;
          }),
          'S1. the store indexes a stored certificate by the SHA-256 of its ' +
          'DER (usercertificatesha256)', JSON.stringify(keys.valueKeys));
  let seen = tlsClient.identityOf(input(first), { stored: true });
  t.check(!seen.accepted && seen.error === 'NOT_STORED' &&
          seen.outside === true,
          'S2. stored on no entry, it is NOT_STORED — though its CN names ' +
          'scalice, who exists', JSON.stringify(seen));
  const stored = adminActions.usersAction({ action: 'add-certificate',
    user: 'scfrank', certificate: first.leaf.pem },
  { actor: 'test', via: 'test' });
  t.check(stored.ok && stored.changed && stored.certificates.length === 1 &&
          stored.certificates[0].sha256 === shaOf(first),
          'A1. add-certificate stores it on scfrank\'s entry, and the list ' +
          'names it by its SHA-256', JSON.stringify(stored));
  seen = tlsClient.identityOf(input(first), { stored: true });
  t.check(seen.accepted && seen.stored === true && seen.kind === 'person' &&
          seen.username === 'scfrank' && seen.issuedHere === false &&
          tlsClient.stillHeld(seen),
          'S3. stored on scfrank, it is scfrank — not scalice, whom its CN ' +
          'names', JSON.stringify(seen));
  const bare = tlsClient.identityOf(input(first));
  t.check(!bare.accepted && !bare.issuedHere && bare.outside === undefined,
          'S4. asked without { stored: true } (RFC 8705, GNAP) it is the old ' +
          '"not ours", and no lookup is made', JSON.stringify(bare));
  seen = tlsClient.identityOf(input(renewed), { stored: true });
  t.check(!seen.accepted && seen.error === 'NOT_STORED',
          'S5. a renewed certificate, same subject, new key, is NOT_STORED ' +
          'until it is stored too', JSON.stringify(seen));
  seen = inRealm(function () {
    return tlsClient.identityOf(input(first), { stored: true });
  });
  t.check(!seen.accepted && seen.error === 'NOT_STORED' &&
          seen.realm === REALM,
          'S6. another realm is asked about its own entries: stored in the ' +
          'default realm, it is nobody in "' + REALM + '"',
          JSON.stringify(seen));
  t.check(!tlsClient.identityOf(input(first, false), { stored: true })
            .accepted,
          'S7. an unverified certificate is nobody, stored or not');
  const appStored = ldap.changeStoredCertificate('application', 'scapp',
                                                 { add: derOf(appCred) });
  seen = tlsClient.identityOf(input(appCred), { stored: true });
  t.check(appStored.ok && seen.accepted && seen.kind === 'application' &&
          seen.username === 'scapp',
          'S8. stored on an application\'s entry, it is that application',
          JSON.stringify(seen));

  // -------------------------------------------------------------------------
  // A. THE ADMIN ACTIONS
  // -------------------------------------------------------------------------
  const again = adminActions.usersAction({ action: 'add-certificate',
    user: 'scfrank', certificate: first.leaf.pem },
  { actor: 'test', via: 'test' });
  t.check(again.ok && again.changed === false &&
          again.certificates.length === 1,
          'A2. storing it again changes nothing', JSON.stringify(again));
  const garbage = adminActions.usersAction({ action: 'add-certificate',
    user: 'scfrank', certificate: 'not a certificate' },
  { actor: 'test', via: 'test' });
  t.check(!garbage.ok && errorCodes.codeOf(garbage) === 'STS-ADMIN-0897',
          'A3. what is not a certificate is STS-ADMIN-0897',
          JSON.stringify(garbage));
  const nobody = adminActions.usersAction({ action: 'add-certificate',
    user: 'scnobody', certificate: renewed.leaf.pem },
  { actor: 'test', via: 'test' });
  t.check(!nobody.ok && errorCodes.codeOf(nobody) === 'STS-ADMIN-0898' &&
          !ldap.existingUserEntry('scnobody'),
          'A4. a person with no entry is STS-ADMIN-0898, and none is made',
          JSON.stringify(nobody));
  const elsewhere = adminActions.usersAction({ action: 'add-certificate',
    user: 'scbob', certificate: first.leaf.pem },
  { actor: 'test', via: 'test' });
  t.check(!elsewhere.ok && errorCodes.codeOf(elsewhere) === 'STS-ADMIN-0899',
          'A5. a certificate stored on another entry is STS-ADMIN-0899',
          JSON.stringify(elsewhere));
  const notHeld = adminActions.usersAction({ action: 'remove-certificate',
    user: 'scfrank', sha256: shaOf(renewed) },
  { actor: 'test', via: 'test' });
  t.check(!notHeld.ok && errorCodes.codeOf(notHeld) === 'STS-ADMIN-0900',
          'A6. removing one the entry does not store is STS-ADMIN-0900',
          JSON.stringify(notHeld));
  const listed = adminActions.storedCertificatesOf('scfrank');
  t.check(listed.ok && listed.certificates.length === 1 &&
          /scalice/.test(listed.certificates[0].subject) &&
          /iya-sts test Issuing CA/.test(listed.certificates[0].issuer),
          'A7. GET /admin-api/users/certificates\'s answer lists the ' +
          'subject and issuer', JSON.stringify(listed));

  // THE TWO-ENTRY STATE, made the way only a directory write can make it.
  const twice = function (on) {
    log.debug("Entering twice().");
    const done = on
      ? ldap.changeStoredCertificate('person', 'scbob', { add: derOf(first) })
      : ldap.changeStoredCertificate('person', 'scbob',
                                     { remove: shaOf(first) });
    log.debug("Leaving twice().");
    return done;
  };
  twice(true);
  seen = tlsClient.identityOf(input(first), { stored: true });
  t.check(!seen.accepted && seen.error === 'STORED_TWICE',
          'S9. stored on two entries it is STORED_TWICE, and names nobody',
          JSON.stringify(seen));
  twice(false);

  // -------------------------------------------------------------------------
  // THE LISTENER: the main port's posture over the client truststore.
  // -------------------------------------------------------------------------
  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  CA_PEM.value = serverCa.certPem;
  const listener = https.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca,
    requestCert: true, rejectUnauthorized: false
  }, tls.protocolOptions()), app);
  tls.trustClientCertificatesOn(listener,
    'the stored_certificates listener', function () {
      log.debug("Entering the listener's certificateOf().");
      log.debug("Leaving the listener's certificateOf().");
      return { key: serverLeaf.key, cert: serverLeaf.cert };
    });
  await new Promise(function (ok) {
    listener.listen(0, '127.0.0.1', ok);
  });
  const port = listener.address().port;

  // -------------------------------------------------------------------------
  // T. GET /tls/sign-in
  // -------------------------------------------------------------------------
  let since = marks.length;
  let r = await request(port, 'GET', '/tls/sign-in', first, {});
  t.check(r.status === 200 && r.json && r.json.signedIn === true &&
          r.json.session && r.json.session.username === 'scfrank',
          'T1. the stored certificate signs scfrank in at /tls/sign-in',
          r.text.slice(0, 400));
  since = marks.length;
  r = await request(port, 'GET', '/tls/sign-in', renewed, {});
  t.check(r.status === 200 && r.json && r.json.signedIn === false &&
          r.json.session && r.json.session.refusedAsStored === 'NOT_STORED' &&
          markedSince(since, 'STS-TLS-0054'),
          'T2. the renewed certificate, CN=scalice and stored nowhere, ' +
          'starts nothing (STS-TLS-0054)', r.text.slice(0, 400));
  t.check(authn.sessionsOf('scalice').length === 0,
          'T3. and scalice, whom its CN names, has no session');
  const stranger = await mint('CN=scstranger,O=Outside');
  tls.addAnchors(stranger.anchorPem);
  r = await request(port, 'GET', '/tls/sign-in', stranger, {});
  t.check(r.json && r.json.signedIn === false &&
          !ldap.existingUserEntry('scstranger') &&
          !(ldap.locateEntry('cn=scstranger,' + ldap.usersDn()) || {})
            .stored,
          'T4. a certificate naming nobody here seeds no entry, at the ' +
          'handshake or at the sign-in', r.text.slice(0, 300));
  twice(true);
  since = marks.length;
  r = await request(port, 'GET', '/tls/sign-in', first, {});
  t.check(r.json && r.json.signedIn === false &&
          r.json.session.refusedAsStored === 'STORED_TWICE' &&
          markedSince(since, 'STS-TLS-0055'),
          'T5. stored on two entries it starts nothing (STS-TLS-0055)',
          r.text.slice(0, 400));
  twice(false);
  // A STORED CERTIFICATE WHOSE CRL CANNOT BE FETCHED, under hard-fail: its
  // revocation status cannot be established, so it is refused on
  // revocation — before the stored entry is asked about.
  const unreachable = await outsideCa.mint({ subject: 'CN=scfrank,O=Outside',
                                             crlBase: 'http://127.0.0.1:9' });
  tls.addAnchors(unreachable.anchorPem);
  ldap.changeStoredCertificate('person', 'scfrank',
                               { add: derOf(unreachable) });
  config.setOverride('pki.revocationCheck', 'hard-fail');
  try {
    r = await request(port, 'GET', '/tls/sign-in', unreachable, {});
  } finally {
    config.clearOverride('pki.revocationCheck');
  }
  t.check(r.json && r.json.signedIn === false &&
          r.json.session.refusedOnRevocation === true,
          'T6. a stored certificate refused on revocation (hard-fail, its ' +
          'CRL unreachable) starts nothing — revocation comes first',
          r.text.slice(0, 400));
  ldap.changeStoredCertificate('person', 'scfrank',
                               { remove: shaOf(unreachable) });

  // -------------------------------------------------------------------------
  // U. THE SIGN-IN SCREEN, in a realm whose entry stores the certificate
  // -------------------------------------------------------------------------
  const realmStored = inRealm(function () {
    return adminActions.usersAction({ action: 'add-certificate',
      user: 'screalmfrank', certificate: first.leaf.pem },
    { actor: 'test', via: 'test' });
  });
  t.check(realmStored.ok,
          'precondition: the same certificate stored on screalmfrank in "' +
          REALM + '" — a different realm, so not a second holder here',
          JSON.stringify(realmStored));
  const start = async function (cred) {
    log.debug("Entering start().");
    const jar = {};
    const sent = await request(port, 'GET', '/realm/' + REALM +
      '/oauth2/authorize?' + new URLSearchParams({ client_id: CLIENT,
        response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
        state: 's', nonce: 'n-' + Date.now() }).toString(), cred, jar);
    const at = String(sent.headers.location || '');
    const opened = await screen.open({ port: port, ca: CA_PEM.value,
      jar: jar, userAgent: UA, cert: cred && cred.certPem,
      key: cred && cred.keyPem, at: at });
    log.debug("Leaving start().");
    return { jar: jar, at: at, opened: opened };
  };
  const act = function (b, cred) {
    log.debug("Entering act().");
    log.debug("Leaving act().");
    return screen.submit({ port: port, ca: CA_PEM.value, jar: b.jar,
      userAgent: UA, cert: cred && cred.certPem, key: cred && cred.keyPem,
      at: b.at, opened: b.opened, fields: { action: 'certificate' } });
  };
  let b = await start(first);
  t.check(((b.opened.view || {}).certificate || {}).name === 'screalmfrank',
          'U1. the screen offers the stored certificate as its holder in ' +
          'this realm', JSON.stringify(b.opened.view &&
                                       b.opened.view.certificate));
  let done = await act(b, first);
  t.check(done.next === 'redirect' && inRealm(function () {
    return authn.sessionsOf('screalmfrank').length;
  }) === 1,
          'U2. and completes the sign-in as screalmfrank',
          done.apiStatus + ' ' + String(done.text).slice(0, 300));
  b = await start(renewed);
  since = marks.length;
  done = await act(b, renewed);
  t.check(!(b.opened.view || {}).certificate && done.apiStatus === 400 &&
          done.next === 'refused' && markedSince(since, 'STS-AUTHN-0468'),
          'U3. one stored on no entry is not offered, and its act is ' +
          'refused (STS-AUTHN-0468)', JSON.stringify(done.errors));
  inRealm(function () {
    ldap.createUser('screalmbob', { invent: false });
    ldap.changeStoredCertificate('person', 'screalmbob',
                                 { add: derOf(first) });
  });
  b = await start(first);
  since = marks.length;
  done = await act(b, first);
  t.check(!(b.opened.view || {}).certificate && done.next === 'refused' &&
          markedSince(since, 'STS-AUTHN-0469'),
          'U4. stored on two entries, it is not offered and is refused ' +
          '(STS-AUTHN-0469)', JSON.stringify(done.errors));

  // -------------------------------------------------------------------------
  // V. SCIM's client-certificate scheme
  // -------------------------------------------------------------------------
  r = await request(port, 'GET', '/scim/v2/Users?count=1', first);
  t.check(r.status === 200,
          'V1. the stored certificate is a SCIM credential', r.status + ' ' +
          r.text.slice(0, 300));
  r = await request(port, 'GET', '/scim/v2/Users?count=1', renewed);
  t.check(r.status === 401 && audited('STS-SCIM-0084'),
          'V2. one stored nowhere is not this credential: 401, ' +
          'STS-SCIM-0084 audited', r.status + ' ' + r.text.slice(0, 300));
  twice(true);
  r = await request(port, 'GET', '/scim/v2/Users?count=1', first);
  twice(false);
  t.check(r.status === 401 && audited('STS-SCIM-0085'),
          'V3. stored twice, 401 and STS-SCIM-0085 audited',
          r.status + ' ' + r.text.slice(0, 300));

  // -------------------------------------------------------------------------
  // X. THE XACML GATES
  // -------------------------------------------------------------------------
  const admit = function (group, member) {
    log.debug("Entering admit().");
    const answer = adminActions.groupsAction({ action: 'add-member',
      group: group, member: member });
    log.debug("Leaving admit().");
    return answer;
  };
  const inUsers = admit(String(config.value('roles.xacmlUserGroup')),
                        'scfrank');
  ldap.changeStoredCertificate('person', 'scpep', { add: derOf(pepCred) });
  const inPeps = admit(String(config.value('roles.remotePepGroup')),
                       'scpep');
  t.check(inUsers && inUsers.ok && inPeps && inPeps.ok,
          'precondition: scfrank holds XACML_USER and scpep REMOTE_PEPS',
          JSON.stringify([inUsers, inPeps]));
  r = await request(port, 'GET', '/xacml', first);
  t.check(r.status === 200,
          'X1. the stored certificate of an xacml-users member reaches GET ' +
          '/xacml', r.status + ' ' + r.text.slice(0, 300));
  since = marks.length;
  r = await request(port, 'GET', '/xacml', renewed);
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0177') &&
          /resolved to no entry/.test(r.text),
          'X2. one stored nowhere resolves to nobody: 403, STS-XACML-0177',
          r.status + ' ' + r.text.slice(0, 300));
  twice(true);
  since = marks.length;
  r = await request(port, 'GET', '/xacml', first);
  twice(false);
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0178'),
          'X3. stored twice, 403 and STS-XACML-0178', r.status);
  r = await request(port, 'GET', '/xacml/pep/policies', pepCred);
  t.check(r.status === 200,
          'X4. the remote PEP\'s stored certificate reaches GET ' +
          '/xacml/pep/policies', r.status + ' ' + r.text.slice(0, 300));
  since = marks.length;
  r = await request(port, 'GET', '/xacml/pep/policies', renewed);
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0179'),
          'X5. one stored nowhere is refused at the PEP gate ' +
          '(STS-XACML-0179)', r.status + ' ' + r.text.slice(0, 300));
  ldap.changeStoredCertificate('person', 'scbob', { add: derOf(pepCred) });
  since = marks.length;
  r = await request(port, 'GET', '/xacml/pep/policies', pepCred);
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0180'),
          'X6. the PEP\'s certificate stored on two entries is refused ' +
          '(STS-XACML-0180)', r.status);

  // -------------------------------------------------------------------------
  // AND TAKEN OFF
  // -------------------------------------------------------------------------
  const removed = adminActions.usersAction({ action: 'remove-certificate',
    user: 'scfrank', sha256: shaOf(first) }, { actor: 'test', via: 'test' });
  seen = tlsClient.identityOf(input(first), { stored: true });
  t.check(removed.ok && removed.changed && removed.certificates.length === 0 &&
          !seen.accepted && seen.error === 'NOT_STORED',
          'A8. remove-certificate takes it off, and from then on it names ' +
          'nobody', JSON.stringify([removed, seen]));

  await new Promise(function (ok) {
    listener.close(ok);
  });
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== a certificate from an outside authority is the one ' +
             'entry storing it (#1061) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'stored_certificates',
  describe: 'A certificate from an outside authority is the one entry ' +
            'storing it in userCertificate (#1061): the mapping and its ' +
            'index, the admin actions, and GET /tls/sign-in, the sign-in ' +
            'screen, SCIM and the XACML gates over real handshakes — ' +
            'stored, not stored, stored twice, renewed, revoked',
  run: run
};
