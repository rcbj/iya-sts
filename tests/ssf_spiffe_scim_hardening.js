'use strict';
//
// File: ssf_spiffe_scim_hardening.js
//
// ===========================================================================
// THE 2026-09-12 HARD-CODED-VALUE AUDIT, FOR SHARED SIGNALS, SPIFFE AND SCIM.
//
// One file for the three directories because every assertion here is the same
// kind of claim: a literal that used to decide something now either follows a
// setting, follows the mode, or was a defect in every mode and is fixed. Each
// section names the finding it holds, so a failure points at the change that
// regressed rather than at a directory.
//
// In process, no port except one short-lived temporary directory for the socket
// permissions. Everything a section overrides it puts back, because run.js runs
// every file in one process and a leaked `global.mode=product` would turn the
// next file's permissive paths into refusals.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const config = require('../common/config');
const realms = require('../common/realms');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'ssf_spiffe_scim_hardening',
  level: process.env.LOG_LEVEL || 'info' });

const REALM_A = 'hardening-a';
const REALM_B = 'hardening-b';

// Run `fn` with `global.mode` set process-wide, and put it back whatever
// happens. A realm override would not reach the default realm, which is where
// most of these modules answer when nothing enters a realm.
function inMode(value, fn) {
  log.debug("Entering inMode().");
  config.setOverride('global.mode', value);
  try {
    log.debug("Leaving inMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

function makeRealm(t, id, overrides) {
  log.debug("Entering makeRealm().");
  realms.remove(id);
  const made = realms.create({ id: id, name: id, overrides: overrides || {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving makeRealm().");
    return null;
  }
  log.debug("Leaving makeRealm().");
  return made.realm;
}

// A minimal but valid SPIFFE bundle document with one x509-svid key, built from
// a throwaway self-signed certificate so `checkBundleDocument()` accepts it.
function bundleDocumentWithKey() {
  log.debug("Entering bundleDocumentWithKey().");
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  jwk.use = 'jwt-svid';
  jwk.kid = 'hardening-' + crypto.randomBytes(4).toString('hex');
  log.debug("Leaving bundleDocumentWithKey().");
  return { keys: [jwk], spiffe_sequence: 1, spiffe_refresh_hint: 300 };
}

// ---------------------------------------------------------------------------
// 1. FEDERATED BUNDLES ARE A REALM'S OWN, AND NONE MAY SHADOW A SERVED DOMAIN.
// ---------------------------------------------------------------------------
async function federatedBundles(t) {
  log.debug("Entering federatedBundles().");
  t.log.info('=== federated bundles: per realm, and never a served trust ' +
             'domain ===');
  const ca = require('../spiffe/spiffe_ca');
  const a = makeRealm(t, REALM_A);
  const b = makeRealm(t, REALM_B);
  if (!a || !b) {
    log.debug("Leaving federatedBundles().");
    return;
  }
  const defaultDomain = ca.trustDomain('');
  const domainB = ca.trustDomain(REALM_B);
  const refusedDefault = realms.run(a, function () {
    return ca.setFederatedBundle(defaultDomain, bundleDocumentWithKey());
  });
  t.check(!refusedDefault.ok && /default/.test(refusedDefault.reason || ''),
          'realm A may NOT register a federated bundle named after the ' +
          'DEFAULT realm\'s trust domain — the defect was that its ' +
          'certificates were then believed as the default realm\'s identities',
          JSON.stringify(refusedDefault));
  const refusedSibling = realms.run(a, function () {
    return ca.setFederatedBundle(domainB, bundleDocumentWithKey());
  });
  t.check(!refusedSibling.ok && refusedSibling.reason.indexOf(REALM_B) >= 0,
          'nor one named after ANOTHER realm\'s trust domain, and the ' +
          'refusal names the realm that serves ' +
          'it', JSON.stringify(refusedSibling));
  const refusedOwn = realms.run(a, function () {
    return ca.setFederatedBundle(ca.trustDomain(REALM_A),
                                 bundleDocumentWithKey());
  });
  t.check(!refusedOwn.ok && /own trust domain/.test(refusedOwn.reason || ''),
          'nor its own, with the sentence about a domain not federating with ' +
          'itself', JSON.stringify(refusedOwn));

  const foreign = 'foreign-' + crypto.randomBytes(3).toString('hex') +
                  '.example';
  const accepted = realms.run(a, function () {
    return ca.setFederatedBundle(foreign, bundleDocumentWithKey());
  });
  t.check(accepted.ok, 'a genuinely foreign trust domain is still accepted',
          JSON.stringify(accepted));
  const seenInA = realms.run(a, function () {
    return ca.federatedBundles().map(function (e) { return e.trustDomain; });
  });
  const seenInB = realms.run(b, function () {
    return ca.federatedBundles().map(function (e) { return e.trustDomain; });
  });
  const seenInDefault = ca.federatedBundles('').map(function (e) {
    return e.trustDomain;
  });
  t.check(seenInA.indexOf(foreign) >= 0,
          'realm A holds the bundle it federated');
  t.check(seenInB.indexOf(foreign) < 0 && seenInDefault.indexOf(foreign) < 0,
          'AND NO OTHER REALM DOES — the store was process-wide, so one ' +
          'realm\'s federation was trusted in every realm',
          'B: ' + JSON.stringify(seenInB) + ' default: ' +
          JSON.stringify(seenInDefault));

  // A delete is never refused for a served name — it is the door a row an
  // older build wrote under one is taken off through — and a lookup of a
  // served name answers null in every realm whatever the store holds.
  t.check(realms.run(a, function () {
    return ca.deleteFederatedBundle(defaultDomain);
  }) === false, 'deleting a served name is not refused (nothing was there)');
  t.equal(realms.run(a,
                     function () { return ca.federatedBundle(defaultDomain); }),
          null, 'a lookup of a served name answers null');
  realms.run(a, function () { ca.deleteFederatedBundle(foreign); });
  log.debug("Leaving federatedBundles().");
}

// ---------------------------------------------------------------------------
// 12. A NEW REALM DOES NOT INHERIT THE DEFAULT REALM'S TCP LISTENERS OR ITS
//     SPIFFE ADMIN IDS (`spiffe.adminIds` — not the realm's own console
//     administrators, which are another roster).
// ---------------------------------------------------------------------------
function realmSeeding(t) {
  log.debug("Entering realmSeeding().");
  t.log.info('=== a realm is created without TCP gRPC listeners or ' +
             'administrators ===');
  config.setOverride('spiffe.adminIds', 'spiffe://example.org/admin');
  try {
    const made = makeRealm(t, REALM_B);
    if (!made) {
      log.debug("Leaving realmSeeding().");
      return;
    }
    const o = made.overrides || {};
    t.equal(o['spiffe.workloadPort'], 0,
            'spiffe.workloadPort is seeded 0 — it would otherwise be the ' +
            'default realm\'s 8092, which is already bound');
    t.equal(o['spiffe.serverPort'], 0, 'and spiffe.serverPort likewise');
    t.check(Object.prototype.hasOwnProperty.call(o, 'spiffe.adminIds') &&
            o['spiffe.adminIds'] === '',
            'spiffe.adminIds is seeded EMPTY rather than inheriting ids in ' +
            'another trust domain', JSON.stringify(o['spiffe.adminIds']));
    t.check(/\/hardening-b\//.test(String(o['spiffe.workloadSocket'] || '')),
            'the socket paths are still seeded per realm');
  } finally {
    config.clearOverride('spiffe.adminIds');
  }
  log.debug("Leaving realmSeeding().");
}

// ---------------------------------------------------------------------------
// 8. THE ROTATION PERIOD FOLLOWS THE SHORTEST LIFETIME SERVED.
// ---------------------------------------------------------------------------
function rotation(t) {
  log.debug("Entering rotation().");
  t.log.info('=== FetchX509SVID rotates at half the shortest lifetime served ' +
             '===');
  const workload = require('../spiffe/spiffe_workload');
  t.equal(workload.rotationPeriod(300), 150,
          'a five-minute SVID is re-sent every 150s, not every half of ' +
          'spiffe.svidTtl');
  t.equal(workload.rotationPeriod(40), 20,
          'below a minute it is still half — the old 30-second floor made ' +
          'the period longer than the lifetime');
  t.equal(workload.rotationPeriod(0),
          Math.floor(config.value('spiffe.svidTtl') / 2),
          'nothing served falls back to spiffe.svidTtl');
  t.equal(workload.rotationPeriod(1), 1, 'and the floor is one second');
  log.debug("Leaving rotation().");
}

// ---------------------------------------------------------------------------
// 10. NO SEED ENTRIES IN PRODUCT; 13 AND 14. THE CA SUBJECT AND KEY TYPE.
// ---------------------------------------------------------------------------
function registrySeed(t) {
  log.debug("Entering registrySeed().");
  t.log.info('=== the SPIFFE registry is not seeded in product mode ===');
  require('../ldap/ldap_server');
  const registry = require('../spiffe/spiffe_registry');
  const realm = makeRealm(t, REALM_A, { 'global.mode': 'product' });
  if (!realm) {
    log.debug("Leaving registrySeed().");
    return;
  }
  const made = realms.run(realm, function () {
    return registry.seed('hardening-a.example.org');
  });
  t.equal(made, 0, 'a product realm seeds no registration entries — three ' +
          'identities nobody configured, one selecting unix:uid:1000');
  t.equal(realms.run(realm, function () { return registry.entryCount(); }), 0,
          'and its registry is empty');
  log.debug("Leaving registrySeed().");
}

async function caSubjectAndKeyType(t) {
  log.debug("Entering caSubjectAndKeyType().");
  t.log.info('=== the downstream CA subject and the X509-SVID key type are ' +
             'settings ===');
  const ca = require('../spiffe/spiffe_ca');
  const realm = makeRealm(t, REALM_A, { 'spiffe.x509KeyType': 'ec-p384' });
  if (!realm) {
    log.debug("Leaving caSubjectAndKeyType().");
    return;
  }
  const domain = ca.trustDomain(REALM_A);
  const minted = await ca.mintX509Svid(
    'spiffe://' + domain + '/hardening', { realm: REALM_A });
  t.equal(minted.keyType, 'ec-p384',
          'an SVID minted FOR a realm from outside it takes THAT realm\'s ' +
          'spiffe.x509KeyType — it took the ambient (default) realm\'s');
  config.setOverride('spiffe.caSubject', 'CN=Acme SPIFFE {kind} ' +
                                         '({trustDomain}),O=Acme');
  try {
    const downstream = await realms.run(realm, function () {
      return ca.downstreamCa({ realm: REALM_A });
    });
    const text = new crypto.X509Certificate(downstream.certificatePem).subject;
    t.check(/Acme SPIFFE downstream CA/.test(text) &&
            !/O=sts\b|CN=sts SPIFFE/.test(text),
            'a downstream CA\'s subject comes from spiffe.caSubject, with ' +
            '{kind} and {trustDomain} filled in', text);
  } catch (e) {
    t.bad('downstreamCa() threw', e.message);
  } finally {
    config.clearOverride('spiffe.caSubject');
  }
  log.debug("Leaving caSubjectAndKeyType().");
}

// ---------------------------------------------------------------------------
// 11. THE SPIRE SERVER API SOCKET IS PRIVATE.
// ---------------------------------------------------------------------------
function socketPermissions(t) {
  log.debug("Entering socketPermissions().");
  t.log.info('=== socket directories and the private socket get stated modes ' +
             '===');
  const rpc = require('../spiffe/spiffe_grpc');
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-hard-'));
  const oldMask = process.umask(0);
  try {
    const privatePath = path.join(base, 'server', 'private', 'api.sock');
    rpc.prepareSocketPath(privatePath, true);
    const privMode = fs.statSync(path.dirname(privatePath)).mode & 0o777;
    t.equal(privMode.toString(8), '700',
            'a directory created for the SPIRE Server API socket is 0700, ' +
            'even under a umask of 0');
    const publicPath = path.join(base, 'agent', 'public', 'api.sock');
    rpc.prepareSocketPath(publicPath, false);
    const pubMode = fs.statSync(path.dirname(publicPath)).mode & 0o777;
    t.equal(pubMode.toString(8), '755',
            'the Workload API\'s is 0755 — reachable, never writable by ' +
            'others');
    fs.writeFileSync(privatePath, '');
    fs.chmodSync(privatePath, 0o666);
    t.check(rpc.restrictSocket(privatePath),
            'restrictSocket() reports success');
    t.equal((fs.statSync(privatePath).mode & 0o777).toString(8), '600',
            'and the private socket is 0600: only this uid can connect to ' +
            'the trusted `local` entity');
  } finally {
    process.umask(oldMask);
    fs.rmSync(base, { recursive: true, force: true });
  }
  log.debug("Leaving socketPermissions().");
}

// ---------------------------------------------------------------------------
// 4, 6 AND 7. THE SSF ISSUER HAS THE REALM PREFIX ONCE, AND THE LOOPBACK DIAL.
// ---------------------------------------------------------------------------
function ssfIssuer(t) {
  log.debug("Entering ssfIssuer().");
  t.log.info('=== the SSF issuer and endpoints carry a realm prefix exactly ' +
             'once ===');
  require('../common/app');
  const ssf = require('../ssf/ssf');
  const transport = require('../ssf/ssf_http');
  const realm = makeRealm(t, REALM_A);
  if (!realm) {
    log.debug("Leaving ssfIssuer().");
    return;
  }
  const req = { protocol: 'https', headers: { host: 'sts.example.com' },
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return name.toLowerCase() === 'host' ? 'sts.example.com' : '';
    } };
  const doc = realms.run(realm, function () { return ssf.metadata(req); });
  const prefix = realms.run(realm,
                            function () { return realms.currentPrefix(); });
  function once(value) {
    log.debug("Entering once().");
    log.debug("Leaving once().");
    return String(value).split(prefix).length === 2;
  }
  t.check(prefix && once(doc.issuer),
          'the issuer names the realm once', doc.issuer);
  t.check(once(doc.jwks_uri) && once(doc.configuration_endpoint) &&
          once(doc.verification_endpoint),
          'and so do jwks_uri and every endpoint — each was ' +
          '`…/realm/<id>/realm/<id>/…` until 2026-09-12',
          JSON.stringify([doc.jwks_uri, doc.configuration_endpoint]));

  config.setOverride('ssf.issuer', 'https://signals.example.com/');
  try {
    const pinned = realms.run(realm,
                              function () { return ssf.metadata(req).issuer; });
    t.equal(pinned, 'https://signals.example.com' + prefix,
            'a PROCESS-WIDE ssf.issuer is given the realm\'s prefix, so two ' +
            'realms are not two transmitters under one name');
    t.equal(ssf.metadata(req).issuer, 'https://signals.example.com',
            'and in the default realm it is used as it stands');
    realms.setOverride(REALM_A, 'ssf.issuer', 'urn:acme:signals');
    const own = realms.run(realms.get(REALM_A), function () {
      return ssf.metadata(req).issuer;
    });
    t.equal(own, 'urn:acme:signals',
            'a value the REALM carries is used verbatim');
  } finally {
    config.clearOverride('ssf.issuer');
  }

  const origin = transport.loopbackOrigin();
  t.check(origin.indexOf(require('../common/helpers').loopbackHost()) >= 0,
          'the internal push dials helpers.loopbackHost(), not a literal',
          origin);
  const noRequest = realms.run(realm,
                               function () { return transport.ownBaseUrl(); });
  t.check(once(noRequest) && noRequest.indexOf(origin) === 0,
          'with no request the base is the loopback origin in the ' +
          'listener\'s own scheme, prefixed once — it was http://localhost ' +
          'whatever global.https said', noRequest);
  log.debug("Leaving ssfIssuer().");
}

// ---------------------------------------------------------------------------
// 16. A FOREIGN RS256 SET IS "NOT VERIFIABLE HERE", NOT "INVALID".
// ---------------------------------------------------------------------------
function foreignSet(t) {
  log.debug("Entering foreignSet().");
  t.log.info('=== a SET is matched to a key by kid ===');
  const events = require('../ssf/ssf_events');
  t.equal(events.publicKeyForHeader({ alg: 'RS256',
                                      kid: 'somebody-elses-key' }), null,
          'an RS256 SET carrying a foreign kid resolves to NO key — it was ' +
          'checked against this service\'s RSA key and reported invalid');
  t.check(events.publicKeyForHeader({ alg: 'RS256' }) !== null,
          'one naming no kid is still tried against the RSA key');
  const verdict = events.verifySet('e30.e30.c2ln',
                                   { alg: 'RS256', kid: 'nope' });
  t.check(!verdict.verified && /not verifiable here/.test(verdict.note),
          'and verifySet() says so in its own words', verdict.note);
  log.debug("Leaving foreignSet().");
}

// ---------------------------------------------------------------------------
// 5. SUBJECTS USE REAL VALUES, AND PRODUCT INVENTS NONE.
// ---------------------------------------------------------------------------
function subjects(t) {
  log.debug("Entering subjects().");
  t.log.info('=== subject identifiers: real values win, product invents ' +
             'nothing ===');
  const subj = require('../ssf/ssf_subjects');
  const real = subj.subjectForUser('alice', 'email', 'https://i',
                                   { mail: 'alice@corp.test' });
  t.equal(real.email, 'alice@corp.test',
          'a real mail wins in development — it was <name>@example.com ' +
          'whatever the entry held');
  const devInvented = subj.subjectForUser('alice', 'email', 'https://i');
  t.equal(devInvented.email, 'alice@example.com',
          'development still invents where nothing is known');
  inMode('product', function () {
    const none = subj.subjectForUser('alice', 'email', 'https://i');
    t.equal(none.format, 'iss_sub',
            'product with no mail falls back to the issuer/subject pair');
    const did = subj.subjectForUser('alice', 'did', 'https://i');
    t.equal(did.format, 'iss_sub', 'and invents no did:example');
    const aliases = subj.subjectForUser('alice', 'aliases', 'https://i');
    t.equal(aliases.identifiers.length, 1, 'aliases carry no invented address');
    const kept = subj.subjectForUser('alice', 'email', 'https://i',
                                     { mail: 'a@corp.test' });
    t.equal(kept.email, 'a@corp.test', 'a real one is still used');
  });

  const risc = require('../ssf/risc');
  const row = { accountId: 'carol', sub: 'carol', iss: 'https://i',
                email: 'carol@corp.test' };
  config.setOverride('risc.subjectFormat', 'email');
  try {
    const s = risc.subjectFor(row,
                              'https://schemas.openid.net/secevent/risc/event-type/account-disabled');
    t.equal((s || {}).email, 'carol@corp.test',
            'RISC passes the mail its row holds — it passed the name alone');
  } finally {
    config.clearOverride('risc.subjectFormat');
  }
  inMode('product', function () {
    const noMail = risc.subjectFor({ accountId: 'dave', sub: 'dave', iss: 'x' },
      'https://schemas.openid.net/secevent/risc/event-type/identifier-changed');
    t.equal(noMail, null,
            'an identifier event about somebody with no address has NO ' +
            'subject in product, and transmit() refuses it — rather than an ' +
            'invented one');
    const receivers = require('../ssf/ssf_receivers');
    const entry = { claims: { sub_id: { format: 'email',
                                        email: 'erin@example.com' } } };
    t.check(!receivers.isAbout(entry, { username: 'erin' }),
            'the portal filter matches no invented address in product — it ' +
            'would be matching an address erin never held');
  });
  log.debug("Leaving subjects().");
}

// ---------------------------------------------------------------------------
// 2. SSF BASIC VERIFIES IN PRODUCT, AND CAN BE TURNED OFF.
// ---------------------------------------------------------------------------
function ssfBasic(t) {
  log.debug("Entering ssfBasic().");
  t.log.info('=== SSF HTTP Basic: verified in product, and a switch ===');
  const ssfAuth = require('../ssf/ssf_auth');
  function basic(user, pass) {
    log.debug("Entering basic().");
    log.debug("Leaving basic().");
    return { headers: { authorization: 'Basic ' +
      Buffer.from(user + ':' + pass).toString('base64') } };
  }
  const dev = ssfAuth.authenticate(basic('nobody-' + Date.now(), 'anything'),
                                   'write');
  t.check(dev.ok, 'development accepts any name with any password, as before',
          JSON.stringify(dev));
  inMode('product', function () {
    const prod = ssfAuth.authenticate(basic('nobody-' + Date.now(), 'anything'),
                                      'write');
    t.check(!prod.ok && prod.status === 401 &&
            /Authentication failed/.test(prod.description),
            'PRODUCT REFUSES AN UNVERIFIED BASIC CREDENTIAL — it never asked ' +
            'the mode, so any name with any password drove streams',
            JSON.stringify(prod));
  });
  // A CLIENT'S TOKEN OWNS A STREAM AS ITS client_id IN BOTH MODES
  // (2026-09-18): RFC 9700 mode — which product implies — gives a
  // client_credentials token `sub: urn:sts:client:<id>`, and a stream owned by
  // that string escaped the application's ssfAllowedEvents.
  t.check(ssfAuth.principalOfClaims({ sub: 'urn:sts:client:app1',
                                      client_id: 'app1' }) === 'app1',
          'an RFC 9700 client subject owns a stream as its client_id');
  t.check(ssfAuth.principalOfClaims({ sub: 'app1', client_id: 'app1' }) ===
            'app1', 'and so does a development-mode one');
  t.check(ssfAuth.principalOfClaims({ sub: 'urn:uuid:1234',
                                      client_id: 'app1' }) === 'urn:uuid:1234',
          'a PERSON\'s token is still the person');
  config.setOverride('ssf.authBasic', false);
  try {
    const off = ssfAuth.authenticate(basic('x', 'y'), 'read');
    t.check(!off.ok && /ssf\.authBasic/.test(off.description),
            'with ssf.authBasic off, Basic is refused naming the setting');
    t.check(ssfAuth.schemesForMetadata().every(function (row) {
      return row.spec_urn !== 'urn:ietf:rfc:7617';
    }), 'and authorization_schemes no longer advertises it');
  } finally {
    config.clearOverride('ssf.authBasic');
  }
  log.debug("Leaving ssfBasic().");
}

// ---------------------------------------------------------------------------
// 3, 17, 25. SCIM DIGEST IN PRODUCT, MD5, AND HOBA REGISTRATION.
// ---------------------------------------------------------------------------
function scimDigest(t) {
  log.debug("Entering scimDigest().");
  t.log.info('=== SCIM Digest is not offered in product mode; MD5 is off ' +
             'unless turned on (#182) ===');
  const scimAuth = require('../scim/scim_auth');
  const req = { headers: {}, method: 'GET', originalUrl: '/scim/v2/Users' };
  const devChallenges = scimAuth.challenges(req).join('\n');
  t.check(/Digest /.test(devChallenges), 'development offers Digest');
  t.check(devChallenges.indexOf('algorithm=MD5') < 0,
          'scim.digestMd5 is off by default, so no MD5 challenge (#182)');
  config.setOverride('scim.digestMd5', true);
  try {
    t.check(scimAuth.challenges(req).join('\n').indexOf('algorithm=MD5') >= 0,
            'scim.digestMd5 on adds the MD5 challenge, in development');
  } finally {
    config.clearOverride('scim.digestMd5');
  }
  inMode('product', function () {
    t.check(!/Digest /.test(scimAuth.challenges(req).join('\n')),
            'PRODUCT OFFERS NO DIGEST CHALLENGE — a scrypt-hashed password ' +
            'cannot check an RFC 7616 response, and the shared password is ' +
            'not a credential');
    const row = scimAuth.describe(req).schemes.filter(function (r) {
      return r.id === 'digest';
    })[0];
    t.check(row && !row.enabled && /scrypt/.test(row.refusedByMode),
            'and the description says why the ON setting is not an offer',
            JSON.stringify(row));
    const attempt = scimAuth.authenticate({ headers: { authorization:
      'Digest username="a", nonce="n", response="r", uri="/scim/v2/Users"' },
      method: 'GET', originalUrl: '/scim/v2/Users' }, 'read');
    t.check(!attempt.ok && /not offered in product mode/.test(attempt.detail) &&
            attempt.detail.indexOf(String(config.value(
                'scim.digestPassword'))) < 0,
            'a Digest credential is refused with that reason, and the shared ' +
            'password appears nowhere in it', attempt.detail);
  });
  log.debug("Leaving scimDigest().");
}

function scimHoba(t) {
  log.debug("Entering scimHoba().");
  t.log.info('=== HOBA registration is not account takeover outside ' +
             'development ===');
  const scimAuth = require('../scim/scim_auth');
  const authn = require('../authn/authn');
  const dir = require('../ldap/ldap_server');
  const pem = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    .publicKey.export({ type: 'spki', format: 'pem' });
  const victim = 'hoba-victim-' + crypto.randomBytes(3).toString('hex');
  dir.createUser(victim, { origin: 'test', channel: 'test', protocol: 'test' });
  function register(body) {
    log.debug("Entering register().");
    log.debug("Leaving register().");
    return scimAuth.registerHobaKey({
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(), method: 'POST' });
  }
  const originalSessionOf = authn.sessionOf;
  try {
    authn.sessionOf = function () {
      log.debug("Entering sessionOf().");
      log.debug("Leaving sessionOf().");
      return null;
    };
    inMode('product', function () {
      const taken = register({ pub: pem, username: victim });
      t.equal(taken.status, 403,
              'PRODUCT REFUSES A KEY FOR AN EXISTING ACCOUNT FROM SOMEBODY ' +
              'NOT SIGNED IN AS IT — one unauthenticated POST was a key that ' +
              'authenticates as the victim', JSON.stringify(taken));
      const nobody = register({ pub: pem, username: 'hoba-new-' + Date.now() });
      t.equal(nobody.status, 404,
              'and never creates an account for a name nobody provisioned');
      authn.sessionOf = function () {
        log.debug("Entering sessionOf().");
        log.debug("Leaving sessionOf().");
        return { user: { username: victim }, authenticated: true };
      };
      const own = register({ pub: pem, username: victim,
                             kid: 'hard-own-' + Date.now() });
      t.equal(own.status, 201, 'the owner, signed in, may register their own ' +
                               'key',
              JSON.stringify(own));
    });
    authn.sessionOf = function () {
      log.debug("Entering sessionOf().");
      log.debug("Leaving sessionOf().");
      return null;
    };
    const kid = 'hard-shared-' + Date.now();
    const first = register({ pub: pem, username: victim, kid: kid });
    t.equal(first.status, 201, 'development still registers openly');
    const other = 'hoba-other-' + crypto.randomBytes(3).toString('hex');
    const clash = register({ pub: pem, username: other, kid: kid });
    t.equal(clash.status, 409,
            'IN EVERY MODE a kid already registered to another account is ' +
            'refused — which account a signature authenticated depended on ' +
            'directory order', JSON.stringify(clash));
  } finally {
    authn.sessionOf = originalSessionOf;
  }
  log.debug("Leaving scimHoba().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await federatedBundles(t);
    realmSeeding(t);
    rotation(t);
    registrySeed(t);
    await caSubjectAndKeyType(t);
    socketPermissions(t);
    ssfIssuer(t);
    foreignSet(t);
    subjects(t);
    ssfBasic(t);
    scimDigest(t);
    scimHoba(t);
  } finally {
    realms.remove(REALM_A);
    realms.remove(REALM_B);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_spiffe_scim_hardening',
  describe: 'the 2026-09-12 audit of hard-coded values in ssf/, spiffe/ and ' +
            'scim/: per-realm federated bundles, product-mode refusals, and ' +
            'the literals that became settings',
  run: run
};
