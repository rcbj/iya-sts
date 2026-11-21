// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openpgp_keys.js
//
// ---------------------------------------------------------------------------
// A PERSON'S OpenPGP KEY, THE WEB KEY DIRECTORY AND ENCRYPTED MAIL (#1955 P6),
// in process. Every key and certificate is made HERE, at run time, by
// openpgp.js and openssl: none is in the repository.
//
//   1. THE WEB KEY DIRECTORY'S NAME: the draft's own example ("Joe.Doe" →
//      iy9q119eutrkn8s1mk4r39qejnbu3n5q) and z-base-32.
//   2. REGISTRATION: a v4 Ed25519 key, a v6 key and an RSA 3072 key register
//      on a proof of possession; a tampered signature, another text, a stale
//      signature, another person's key, a user id without the entry's
//      address, a revoked key, a secret key, a short RSA key, no challenge
//      and a replayed proof are each refused with their code.
//   3. PUBLICATION: nothing is answered until the person opts in and the
//      realm turns the directory on; then the binary key, by the register
//      and by the `l` parameter; the routes' headers, the policy file, a
//      malformed name and an unserved domain; withdrawal.
//   4. ENCRYPTED MAIL: PGP/MIME (RFC 3156) decrypts with the person's secret
//      key and carries the real subject inside under a neutral one; S/MIME
//      (RFC 8551) to an RSA and an EC certificate decrypts with openssl; a
//      queued message reaches the transport with its encryption; a required
//      message to a person without a key, and a chosen encryption that
//      cannot be kept, are refused.
//   5. THE LOST-KEY RETIRER: a token holding the key, reported lost, takes
//      it off the entry.
//   6. REALM ISOLATION: a challenge issued in one realm is none in another.
//
// The over-HTTP half — the Web Key Directory, `/account-api/openpgp` and
// `/admin-api/openpgp` — is `tests/protocol/sts_openpgp.js`.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const openpgp = require('openpgp');
const config = require('../common/config');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const stsCrypto = require('../common/crypto');
const keys = require('../common/openpgp_keys');
const tokens = require('../common/hardware_tokens');
const mail = require('../common/mail');
const mailTransports = require('../common/mail_transports');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'openpgp_keys',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const DOMAIN = 'p6-' + RUN + '.example.org';
const ALICE = 'pgp-alice-' + RUN;
const BOB = 'pgp-bob-' + RUN;
const CAROL = 'pgp-carol-' + RUN;
const OVERRIDDEN = ['openpgp.wkd', 'openpgp.wkdDomains',
                    'mail.encryptionRequired'];

function code(answer) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return errorCodes.codeOf(answer) || '';
}

function mailOf(name) {
  log.debug("Entering mailOf().");
  log.debug("Leaving mailOf().");
  return name + '@' + DOMAIN;
}

// A fresh key for an address, of one of openpgp.js's kinds.
async function keyFor(address, kind, date) {
  log.debug("Entering keyFor(). " + kind);
  const options = { userIDs: [{ name: 'P6 test', email: address }],
                    format: 'object', date: date || new Date() };
  if (kind === 'v6') {
    Object.assign(options, { type: 'curve25519', config: { v6Keys: true } });
  } else if (kind === 'rsa') {
    Object.assign(options, { type: 'rsa', rsaBits: 3072 });
  } else if (kind === 'rsa2048') {
    Object.assign(options, { type: 'rsa', rsaBits: 2048 });
  } else {
    Object.assign(options, { type: 'ecc', curve: 'curve25519Legacy' });
  }
  const made = await openpgp.generateKey(options);
  log.debug("Leaving keyFor().");
  return made;
}

// `gpg --clearsign`, as openpgp.js writes it.
async function clearsign(text, privateKey, date) {
  log.debug("Entering clearsign().");
  const out = await openpgp.sign({
    message: await openpgp.createCleartextMessage({ text: text + '\n' }),
    signingKeys: privateKey, date: date || new Date() });
  log.debug("Leaving clearsign().");
  return out;
}

// One person's challenge, issued and signed by a key.
async function proved(name, made, opts) {
  log.debug("Entering proved().");
  const o = opts || {};
  const issued = keys.issueChallenge(name, { actor: name, via: 'test' });
  const signed = await clearsign(o.text || issued.challenge.text,
                                 (o.signer || made).privateKey, o.date);
  const out = await keys.register(name, {
    publicKey: (o.publicKey || made.publicKey.armor()),
    signed: o.tamper ? signed.replace('Nonce:', 'Nonce: x') : signed },
    { actor: name, via: 'test' });
  log.debug("Leaving proved().");
  return { issued: issued, signed: signed, answer: out };
}

function checkName(t) {
  log.debug("Entering checkName().");
  t.log.info('=== 1. the Web Key Directory\'s name ===');
  t.equal(stsCrypto.wkdHash('Joe.Doe'), 'iy9q119eutrkn8s1mk4r39qejnbu3n5q',
          '1a. the draft\'s example: "Joe.Doe" hashes to ' +
          'iy9q119eutrkn8s1mk4r39qejnbu3n5q');
  t.equal(stsCrypto.wkdHash('joe.doe'), stsCrypto.wkdHash('JOE.DOE'),
          '1b. the local part is lower-cased first');
  // RFC 6189 section 5.1.6 / Zooko's examples: 0xF0BFC7 is "6n9hq".
  t.equal(stsCrypto.zBase32(Buffer.from([0xf0, 0xbf, 0xc7])), '6n9hq',
          '1c. z-base-32 of F0 BF C7 is 6n9hq');
  log.debug("Leaving checkName().");
}

async function checkRegistration(t) {
  log.debug("Entering checkRegistration().");
  t.log.info('=== 2. registration on a proof of possession ===');
  t.equal(code(await keys.register(ALICE, { publicKey: 'x', signed: 'y' },
                                   { actor: ALICE })), 'STS-OPENPGP-0012',
          '2a. no outstanding challenge is refused');
  const alice = await keyFor(mailOf(ALICE), 'v4');
  const tampered = await proved(ALICE, alice, { tamper: true });
  t.equal(code(tampered.answer), 'STS-OPENPGP-0008',
          '2b. a tampered signed message does not verify',
          JSON.stringify(tampered.answer.errors));
  const other = await proved(ALICE, alice, { text: 'something else' });
  t.equal(code(other.answer), 'STS-OPENPGP-0009',
          '2c. a signature over another text is refused');
  // A key made four hours ago, so that it may sign three hours ago.
  const old = await keyFor(mailOf(ALICE), 'v4',
                           new Date(Date.now() - 4 * 3600 * 1000));
  const stale = await proved(ALICE, old, {
    date: new Date(Date.now() - 3 * 3600 * 1000) });
  t.equal(code(stale.answer), 'STS-OPENPGP-0010',
          '2d. a signature made long before the challenge is refused ' +
          '(and so the key\'s own date allowed it)',
          JSON.stringify(stale.answer.errors));
  const mallory = await keyFor(mailOf(ALICE), 'v4');
  const wrongKey = await proved(ALICE, alice, { signer: mallory });
  t.equal(code(wrongKey.answer), 'STS-OPENPGP-0008',
          '2e. a challenge signed by another key than the one offered is ' +
          'refused');
  const elsewhere = await keyFor('someone@elsewhere.example', 'v4');
  t.equal(code((await proved(ALICE, elsewhere)).answer), 'STS-OPENPGP-0005',
          '2f. a key with no user id carrying the entry\'s address is ' +
          'refused');
  const revoked = await keyFor(mailOf(ALICE), 'v4');
  const revokedPub = (await openpgp.revokeKey({ key: revoked.privateKey,
                                                format: 'object' }))
    .publicKey;
  t.equal(code((await proved(ALICE, revoked, {
    publicKey: revokedPub.armor() })).answer), 'STS-OPENPGP-0003',
          '2g. a revoked key is refused');
  t.equal(code((await proved(ALICE, alice, {
    publicKey: alice.privateKey.armor() })).answer), 'STS-OPENPGP-0002',
          '2h. a SECRET key is refused, and not stored');
  const short = await keyFor(mailOf(ALICE), 'rsa2048');
  t.equal(code((await proved(ALICE, short)).answer), 'STS-OPENPGP-0004',
          '2i. an RSA key shorter than openpgp.minRsaBits is refused');
  t.check(!keys.view(ALICE).key, '2j. none of those left a key behind');
  const good = await proved(ALICE, alice);
  const fingerprint = alice.publicKey.getFingerprint();
  t.check(good.answer.ok && good.answer.fingerprint === fingerprint,
          '2k. a v4 Ed25519 key registers on its proof',
          JSON.stringify(good.answer));
  const view = keys.view(ALICE);
  t.check(view.key && view.key.fingerprint === fingerprint &&
          view.key.version === 4 && view.key.encryption &&
          !view.challenge && view.mailEncryption.openpgpUsable,
          '2l. the entry holds it, with an encryption key, and the ' +
          'challenge is spent', JSON.stringify(view.key));
  const replay = await keys.register(ALICE, {
    publicKey: alice.publicKey.armor(), signed: good.signed },
    { actor: ALICE });
  t.equal(code(replay), 'STS-OPENPGP-0012', '2m. the proof cannot be used ' +
          'again');
  const bob = await keyFor(mailOf(BOB), 'v6');
  const bobDone = (await proved(BOB, bob)).answer;
  t.check(bobDone.ok && keys.view(BOB).key.version === 6 &&
          keys.view(BOB).key.fingerprint.length === 64,
          '2n. a v6 key (RFC 9580) registers', JSON.stringify(bobDone));
  const carol = await keyFor(mailOf(CAROL), 'rsa');
  t.check((await proved(CAROL, carol)).answer.ok,
          '2o. an RSA 3072 key registers');
  log.debug("Leaving checkRegistration().");
  return { alice: alice, bob: bob, carol: carol };
}

// The Web Key Directory's routes, on a recording app.
function routesOf() {
  log.debug("Entering routesOf().");
  const routes = {};
  keys.registerRoutes({ get: function (p, h) {
    routes[p] = h;
  } });
  log.debug("Leaving routesOf().");
  return routes;
}

// One request to a route, answered.
function ask(handler, params, query, host) {
  log.debug("Entering ask().");
  return new Promise(function (resolve) {
    const res = { headers: {}, statusCode: 0 };
    res.set = function (k, v) {
      res.headers[String(k).toLowerCase()] = v;
      return res;
    };
    res.status = function (s) {
      res.statusCode = s;
      return res;
    };
    res.type = function (v) {
      res.headers['content-type'] = v;
      return res;
    };
    res.send = function (body) {
      res.body = body;
      log.debug("Leaving ask().");
      resolve(res);
      return res;
    };
    handler({ params: params, query: query || {}, hostname: host || '',
              headers: {} }, res);
  });
}

async function checkPublication(t, made) {
  log.debug("Entering checkPublication().");
  t.log.info('=== 3. the Web Key Directory ===');
  const routes = routesOf();
  const hash = stsCrypto.wkdHash(ALICE);
  const advanced = routes['/.well-known/openpgpkey/:domain/hu/:hash'];
  const policy = routes['/.well-known/openpgpkey/:domain/policy'];
  const direct = routes['/.well-known/openpgpkey/hu/:hash'];
  t.check(!!advanced && !!policy && !!direct &&
          !!routes['/.well-known/openpgpkey/policy'],
          '3a. the four paths are registered');
  let r = await ask(advanced, { domain: DOMAIN, hash: hash });
  t.equal(r.statusCode, 404, '3b. off by default: 404');
  config.setOverride('openpgp.wkd', true);
  config.setOverride('openpgp.wkdDomains', [DOMAIN]);
  r = await ask(advanced, { domain: DOMAIN, hash: hash });
  t.check(r.statusCode === 404 && r.headers['cache-control'] === 'no-store',
          '3c. on, but nobody opted in: 404, no-store');
  t.equal((await ask(policy, { domain: DOMAIN })).statusCode, 200,
          '3d. the policy file answers for a served domain');
  t.equal((await ask(policy, { domain: 'unserved.example' })).statusCode,
          404, '3e. and not for another');
  t.check(!(await keys.setPublication('pgp-nobody-' + RUN, true, {})).ok,
          '3f. nobody cannot publish');
  t.check((await keys.setPublication(ALICE, true, { actor: ALICE })).ok &&
          keys.view(ALICE).wkd.published, '3g. Alice opts in');
  r = await ask(advanced, { domain: DOMAIN, hash: hash });
  const back = r.statusCode === 200
    ? await openpgp.readKey({ binaryKey: new Uint8Array(r.body) }) : null;
  t.check(r.statusCode === 200 &&
          r.headers['content-type'] === 'application/octet-stream' &&
          r.headers['cache-control'] === 'no-store' && back &&
          back.getFingerprint() === made.alice.publicKey.getFingerprint() &&
          !back.isPrivate(),
          '3h. the advanced method answers her binary public key, ' +
          'octet-stream, no-store', String(r.statusCode));
  r = await ask(direct, { hash: hash }, {}, DOMAIN);
  t.equal(r.statusCode, 200, '3i. and so does the direct method, the ' +
          'domain being the host');
  t.equal((await ask(advanced, { domain: DOMAIN, hash: 'NOT-A-HASH' }))
    .statusCode, 404, '3j. a malformed name is 404');
  t.equal((await ask(advanced, { domain: DOMAIN,
                                 hash: stsCrypto.wkdHash(BOB) })).statusCode,
          404, '3k. Bob, who did not opt in, is not answered');
  keys.forgetForTests();
  r = await ask(advanced, { domain: DOMAIN, hash: hash }, { l: ALICE });
  t.equal(r.statusCode, 200, '3l. with the register forgotten (a ' +
          'development restart), the l parameter still finds her');
  t.equal((await ask(advanced, { domain: DOMAIN, hash: hash }, {
    l: BOB })).statusCode, 404, '3m. an l that does not hash to the name ' +
          'finds nobody');
  t.check((await keys.setPublication(ALICE, false, { actor: ALICE })).ok,
          '3n. she withdraws');
  t.equal((await ask(advanced, { domain: DOMAIN, hash: hash }, {
    l: ALICE })).statusCode, 404, '3o. and is answered no more');
  await keys.setPublication(ALICE, true, { actor: ALICE });
  log.debug("Leaving checkPublication().");
}

// The parts of a raw message: its headers and body, split once.
function split(raw) {
  log.debug("Entering split().");
  const text = Buffer.from(raw).toString('binary');
  const at = text.indexOf('\r\n\r\n');
  log.debug("Leaving split().");
  return { head: text.slice(0, at), body: text.slice(at + 4) };
}

function message(encryption) {
  log.debug("Entering message().");
  log.debug("Leaving message().");
  return { from: 'idp@' + DOMAIN, fromName: 'P6', to: mailOf(ALICE),
           subject: 'Réinitialisez votre mot de passe', text: 'the text',
           html: '<p>the html</p>', messageId: '<p6-' + RUN + '@' +
           DOMAIN + '>', date: new Date(), lang: 'fr',
           encryption: encryption };
}

function openssl(args, input) {
  log.debug("Entering openssl().");
  const out = childProcess.execFileSync('openssl', args, {
    input: input, stdio: ['pipe', 'pipe', 'pipe'] });
  log.debug("Leaving openssl().");
  return out;
}

// A self-signed S/MIME certificate naming an address, made now.
function smimeCertificate(dir, kind, address) {
  log.debug("Entering smimeCertificate(). " + kind);
  const key = path.join(dir, kind + '.key');
  const cert = path.join(dir, kind + '.pem');
  openssl(['req', '-x509', '-nodes', '-days', '2', '-subj', '/CN=p6 ' + kind,
           '-addext', 'subjectAltName=email:' + address,
           '-addext', 'extendedKeyUsage=emailProtection',
           '-keyout', key, '-out', cert].concat(kind === 'rsa'
             ? ['-newkey', 'rsa:2048']
             : ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256']));
  log.debug("Leaving smimeCertificate().");
  return { key: key, cert: cert, pem: fs.readFileSync(cert, 'utf8') };
}

async function checkMail(t, made) {
  log.debug("Entering checkMail().");
  t.log.info('=== 4. encrypted mail ===');
  const composer = new mailTransports.MailTransports(
    mailTransports.MailTransports.defaultDeps());
  t.check(keys.setMailEncryption(ALICE, 'openpgp', { actor: ALICE }).ok,
          '4a. Alice chooses OpenPGP');
  const plan = keys.encryptionFor(ALICE);
  t.equal(plan.kind, 'openpgp', '4b. and her mail is to be encrypted to ' +
          'her key');
  const raw = await composer.compose(message(Object.assign({}, plan, {
    outerSubject: 'A message from P6' })));
  const outer = split(raw);
  t.check(/Content-Type: multipart\/encrypted;\s+protocol="application\/pgp-encrypted"/
    .test(outer.head) && /^Subject: A message from P6$/m.test(outer.head) &&
          outer.head.indexOf('mot de passe') < 0 &&
          /Content-Type: application\/pgp-encrypted/.test(outer.body) &&
          /Version: 1/.test(outer.body),
          '4c. PGP/MIME: multipart/encrypted with the version part, under ' +
          'the neutral subject');
  const armored = (/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/
    .exec(outer.body) || [''])[0];
  let inner = '';
  try {
    const opened = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: armored }),
      decryptionKeys: made.alice.privateKey, format: 'binary' });
    inner = Buffer.from(opened.data).toString('utf8');
  } catch (e) {
    log.debug("Caught in checkMail(): " + ((e && e.message) || e));
    inner = '';
  }
  t.check(/protected-headers="?v1"?/.test(inner) &&
          /Subject: =\?UTF-8\?Q\?R=C3=A9initialisez/.test(inner) &&
          /the text/.test(inner) && /the html/.test(inner),
          '4d. it decrypts with her secret key to the message, the real ' +
          'subject protected inside', inner.slice(0, 120));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'p6-smime-'));
  try {
    for (const kind of ['rsa', 'ec']) {
      const c = smimeCertificate(dir, kind, mailOf(ALICE));
      t.check(keys.setSmimeCertificate(ALICE, c.pem, { actor: ALICE }).ok &&
              keys.setMailEncryption(ALICE, 'smime', { actor: ALICE }).ok,
              '4e. an ' + kind + ' S/MIME certificate naming her address ' +
              'is set, and S/MIME chosen');
      const smime = keys.encryptionFor(ALICE);
      const m = split(await composer.compose(message(Object.assign({},
        smime, { outerSubject: 'A message from P6' }))));
      t.check(/Content-Type: application\/pkcs7-mime;\s+smime-type=enveloped-data/
        .test(m.head) && /^Subject: A message from P6$/m.test(m.head),
              '4f. ' + kind + ': application/pkcs7-mime enveloped-data');
      const der = Buffer.from(m.body.replace(/\s+/g, ''), 'base64');
      let opened = '';
      try {
        opened = openssl(['cms', '-decrypt', '-inform', 'DER', '-inkey',
                          c.key, '-recip', c.cert], der).toString('utf8');
      } catch (e) {
        log.debug("Caught in checkMail(): " + ((e && e.message) || e));
        opened = '';
      }
      t.check(/protected-headers/.test(opened) && /the text/.test(opened),
              '4g. ' + kind + ': openssl cms -decrypt opens it',
              opened.slice(0, 80));
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const wrong = smimeCertificate(fs.mkdtempSync(path.join(os.tmpdir(),
    'p6-x-')), 'rsa', 'other@elsewhere.example');
  t.equal(code(keys.setSmimeCertificate(ALICE, wrong.pem, {})),
          'STS-OPENPGP-0018', '4h. a certificate naming another address is ' +
          'refused');
  // THE CHANNEL. A transport that records what it is handed.
  const seen = [];
  const recording = { build: async function () {
    return { name: 'smtp', close: function () {
      return undefined;
    }, send: async function (m) {
      seen.push(m);
      return { providerId: 'p6' };
    } };
  } };
  const channel = new mail.Mail(Object.assign(mail.Mail.defaultDeps(),
                                              { transports: recording }));
  keys.setMailEncryption(ALICE, 'openpgp', { actor: ALICE });
  const sent = channel.send({ username: ALICE, template: 'test-message',
    values: { username: ALICE, when: 'now', transport: 'p6' },
    actor: 'p6' });
  await sent.delivered;
  const handed = seen.filter(function (m) {
    return m.to === mailOf(ALICE);
  })[0];
  t.check(sent.ok && handed && handed.encryption &&
          handed.encryption.kind === 'openpgp' &&
          /test message/.test(handed.subject) &&
          !/test message/.test(handed.encryption.outerSubject),
          '4i. a queued message reaches the transport with its encryption ' +
          'and a neutral outer subject', JSON.stringify([sent.refused,
            handed && handed.encryption && handed.encryption.outerSubject]));
  config.setOverride('mail.encryptionRequired', ['test-message']);
  const refused = channel.send({ username: BOB, template: 'test-message',
    values: { username: BOB, when: 'now', transport: 'p6' }, actor: 'p6' });
  t.check(!refused.ok && refused.refused[0] &&
          refused.refused[0].code === 'STS-MAIL-0240',
          '4j. a required message to a person who chose no encryption is ' +
          'refused (STS-MAIL-0240)', JSON.stringify(refused.refused));
  config.clearOverride('mail.encryptionRequired');
  log.debug("Leaving checkMail().");
}

async function checkUnkept(t) {
  log.debug("Entering checkUnkept().");
  // Carol chooses OpenPGP; her key's information then says it expired,
  // as a key whose expiry passed after registration does.
  t.check(keys.setMailEncryption(CAROL, 'openpgp', { actor: CAROL }).ok,
          '4k. Carol chooses OpenPGP');
  const located = ldap.locateEntry(CAROL);
  const stored = located && located.stored;
  const info = JSON.parse(String(((stored && stored.attributes &&
    stored.attributes.stsopenpgpkeyinfo) || ['{}'])[0]));
  info.expiresAt = new Date(Date.now() - 1000).toISOString();
  stored.attributes.stsopenpgpkeyinfo = [JSON.stringify(info)];
  t.equal(keys.encryptionFor(CAROL).kind, 'unavailable',
          '4l. a chosen key that expired cannot be used');
  const out = mail.send({ username: CAROL, template: 'test-message',
    values: { username: CAROL, when: 'now', transport: 'p6' }, actor: 'p6' });
  t.check(!out.ok && out.refused[0] &&
          out.refused[0].code === 'STS-MAIL-0241',
          '4m. and her mail is refused rather than sent in the clear ' +
          '(STS-MAIL-0241)', JSON.stringify(out.refused));
  log.debug("Leaving checkUnkept().");
}

async function checkRetirer(t, made) {
  log.debug("Entering checkRetirer().");
  t.log.info('=== 5. the lost-key retirer ===');
  t.check(tokens.retirerKinds().indexOf('openpgp') >= 0,
          '5a. an openpgp retirer is installed');
  const fingerprint = made.bob.publicKey.getFingerprint();
  const recorded = tokens.recordAttested({ username: BOB, vendor: 'yubico',
    serial: 'p6-' + RUN, model: 'YubiKey 5',
    credential: { kind: 'openpgp', ref: fingerprint, label: 'OpenPGP' },
    evidence: { source: 'vendor-import' } });
  t.check(recorded.ok, '5b. a token holding Bob\'s key (as a later phase ' +
          'would record it)', JSON.stringify(recorded.errors));
  const lost = await tokens.markLost({ key: 'yubico/p6-' + RUN,
    actor: 'admin-' + RUN, via: 'api', initiatingEntity: 'admin' });
  t.check(lost.ok && lost.retired.some(function (r) {
    return r.kind === 'openpgp' && r.ok;
  }) && !keys.view(BOB).key,
          '5c. reported lost, the key is removed from his entry',
          JSON.stringify([lost.retired, lost.notRetired]));
  log.debug("Leaving checkRetirer().");
}

async function checkIsolation(t) {
  log.debug("Entering checkIsolation().");
  t.log.info('=== 6. realm isolation ===');
  const id = 'pgp-' + RUN;
  const created = realms.create({ id: id, name: id,
                                  description: 'Created by ' + __filename });
  if (!created.ok) {
    t.bad('could not create the realm "' + id + '"',
          (created.errors || []).join(' '));
    log.debug("Leaving checkIsolation().");
    return;
  }
  try {
    const issued = keys.issueChallenge(ALICE, { actor: ALICE });
    const alice = await keyFor(mailOf(ALICE), 'v4');
    const signed = await clearsign(issued.challenge.text, alice.privateKey);
    const answer = await realms.run(created.realm, async function () {
      ldap.createUser(ALICE, { invent: false,
                               attributes: { mail: mailOf(ALICE) } });
      return keys.register(ALICE, { publicKey: alice.publicKey.armor(),
                                    signed: signed }, { actor: ALICE });
    });
    t.equal(code(answer), 'STS-OPENPGP-0012', '6a. a challenge issued in ' +
            'one realm is none in another');
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving checkIsolation().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    [ALICE, BOB, CAROL].forEach(function (name) {
      ldap.createUser(name, { invent: false,
                              attributes: { mail: mailOf(name) } });
    });
    checkName(t);
    const made = await checkRegistration(t);
    await checkPublication(t, made);
    await checkMail(t, made);
    await checkUnkept(t);
    await checkRetirer(t, made);
    await checkIsolation(t);
  } finally {
    OVERRIDDEN.forEach(function (k) {
      config.clearOverride(k);
    });
    keys.forgetForTests();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'openpgp_keys',
  describe: '#1955 P6: OpenPGP key registration on a proof of possession, ' +
            'the Web Key Directory, PGP/MIME and S/MIME mail, required ' +
            'encryption, the lost-key retirer and realm isolation',
  run: run
};
