'use strict';
//
// File: kerberos_person_keys.js
//
// ===========================================================================
// A PERSON'S KERBEROS KEYS, DERIVED FROM THEIR OWN PASSWORD, AND A SERVICE
// PRINCIPAL'S RANDOM ONES (2026-09-12).
//
// `kerberos/krb5_person_keys.ts` is what lets a PRODUCT-mode KDC authenticate
// the directory's people: their keys are derived when a plaintext password is
// in hand (set, or verified at a sign-in), stored sealed on their own entry,
// and read by the KDC through `krb5_principals.js`'s key source. It also mints
// random keys for service principals and hands over an MIT keytab once.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first.
//
//   * **THE PRINCIPAL DATABASE IS BUILT AT REQUIRE TIME, in the mode the
//     process starts in**, and every stack in both suites runs development
//     mode — so a product-mode KDC can only be asked anything by starting one.
//     Those sections run in a CHILD node process with `STS_MODE=product`, the
//     arrangement `kerberos_product_mode.js` already has. No port and no
//     container: the child calls the KDC's `handleMessage()` with real AS-REQ
//     bytes and the acceptor's `acceptRaw()` with a real AP-REQ.
//   * **THE STORAGE CLAIMS ARE ABOUT WHAT IS ON AN ENTRY**, and the one door
//     that shows an entry faithfully withholds exactly the attribute being
//     asserted about. What is SEALED, what is BOUND to a name and a password
//     stamp, and that no audit row and no view carries a key, can only be read
//     from inside.
//   * **THE RFC 3962 VECTORS NEED A CHOSEN ITERATION COUNT**, which nothing
//     over the wire may name.
//
// Every AS-REQ is built here with the vendored codec and a key derived here,
// so the KDC runs every one of its checks against a client it did not write.
// The keytab is read by a READER WRITTEN IN THIS FILE, independently of
// `krb5_keytab.js`: a writer checked only by the reader beside it is an
// implementation agreeing with itself.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'kerberos_person_keys',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// AN INDEPENDENT KEYTAB READER. Written from MIT's `kt_file.c` layout, not from
// `krb5_keytab.js`, and deliberately in a different style so the two share no
// mistake by construction: a big-endian 0x0502 header, then int32-sized
// records, a negative size being a hole.
// ---------------------------------------------------------------------------
function independentKeytabRead(buf) {
  log.debug("Entering independentKeytabRead().");
  const out = [];
  if (buf[0] !== 0x05 || buf[1] !== 0x02) {
    throw new Error('not 0x0502');
  }
  let i = 2;
  const u16 = function () {
    log.debug("Entering u16().");
    const v = (buf[i] << 8) | buf[i + 1];
    i += 2;
    log.debug("Leaving u16().");
    return v;
  };

  const u32 = function () {
    log.debug("Entering u32().");
    const v = ((buf[i] << 24) >>> 0) + (buf[i + 1] << 16) + (buf[i +
        2] << 8) + buf[i + 3];
    i += 4;
    log.debug("Leaving u32().");
    return v >>> 0;
  };

  const str = function () {
    log.debug("Entering str().");
    const n = u16();
    const s = buf.slice(i, i + n);
    i += n;
    log.debug("Leaving str().");
    return s;
  };
  while (i < buf.length) {
    let size = u32();
    if (size & 0x80000000) {
      size = (~size + 1) >>> 0;
      i += size;
      continue;
    }
    const end = i + size;
    const n = u16();
    const realm = str().toString('latin1');
    const name = [];
    for (let k = 0; k < n; k++) {
      name.push(str().toString('latin1'));
    }
    const type = u32();
    const when = u32();
    let vno = buf[i];
    i += 1;
    const enctype = u16();
    const key = Buffer.from(str());
    if (end - i >= 4) {
      vno = u32();
    }
    i = end;
    out.push({ realm: realm, name: name, type: type, when: when, vno: vno,
               enctype: enctype, key: key.toString('hex') });
  }
  log.debug("Leaving independentKeytabRead().");
  return out;
}

// ---------------------------------------------------------------------------
// 1. STRING-TO-KEY THROUGH THE PATH THE STORED KEYS TAKE.
// ---------------------------------------------------------------------------
async function stringToKeyMatchesRfc3962(t) {
  log.debug("Entering stringToKeyMatchesRfc3962().");
  t.log.info('=== RFC 3962 Appendix B, through krb5_person_keys.deriveKey() ' +
             '===');
  const personKeys = require('../kerberos/krb5_person_keys');
  const iter = function (n) {
    log.debug("Entering iter().");
    log.debug("Leaving iter().");
    return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255,
                           n & 255]);
  };
  // RFC 3962 Appendix B: pass phrase "password", salt "ATHENA.MIT.EDUraeburn".
  const vectors = [
    { n: 1, k17: '42263c6e89f4fc28b8df68ee09799f15',
      k18: 'fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161' },
    { n: 2, k17: 'c651bf29e2300ac27fa469d693bdda13',
      k18: 'a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff' },
    { n: 1200, k17: '4c01cd46d632d01e6dbe230a01ed642a',
      k18: '55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a' }
  ];
  for (const v of vectors) {
    const k17 = Buffer.from(await personKeys.deriveKey(17, 'password',
      'ATHENA.MIT.EDUraeburn', iter(v.n))).toString('hex');
    const k18 = Buffer.from(await personKeys.deriveKey(18, 'password',
      'ATHENA.MIT.EDUraeburn', iter(v.n))).toString('hex');
    t.equal(k17, v.k17, 'AES128 string-to-key at ' + v.n + ' iteration(s) is ' +
        'RFC 3962\'s');
    t.equal(k18, v.k18, 'AES256 string-to-key at ' + v.n + ' iteration(s) is ' +
        'RFC 3962\'s');
  }
  log.debug("Leaving stringToKeyMatchesRfc3962().");
}

// ---------------------------------------------------------------------------
// 2. THE KEYTAB WRITER AGAINST AN INDEPENDENT READER.
// ---------------------------------------------------------------------------
function theKeytabRoundTrips(t) {
  log.debug("Entering theKeytabRoundTrips().");
  t.log.info('=== an MIT keytab, written here and read independently ===');
  const keytab = require('../kerberos/krb5_keytab');
  const k1 = nodeCrypto.randomBytes(32);
  const k2 = nodeCrypto.randomBytes(16);
  const bytes = keytab.writeKeytab([
    { realm: 'EXAMPLE.COM', components: ['HTTP', 'web.example.com'],
      timestamp: 1700000000,
      kvno: 7, etype: 18, key: k1 },
    { realm: 'EXAMPLE.COM', components: ['HTTP', 'web.example.com'],
      timestamp: 1700000000,
      kvno: 300, etype: 23, key: k2 }
  ]);
  const read = independentKeytabRead(bytes);
  t.equal(read.length, 2, 'the independent reader finds both entries');
  t.check(read[0].realm === 'EXAMPLE.COM' &&
          read[0].name.join('/') === 'HTTP/web.example.com' &&
          read[0].enctype === 18 && read[0].vno === 7 &&
          read[0].key === k1.toString('hex') &&
          read[0].type === 1 && read[0].when === 1700000000,
          'every field of the first entry is what was written', JSON.stringify(
              read[0]));
  t.check(read[1].vno === 300 && read[1].enctype === 23 &&
          read[1].key === k2.toString('hex'),
          'a kvno above 255 survives through the 32-bit field, which the ' +
          '8-bit one alone would have wrapped to 44', JSON.stringify(read[1]));
  // A HOLE — a deleted entry, negative size — is skipped by both readers.
  const hole = Buffer.alloc(4 + 10);
  hole.writeInt32BE(-10, 0);
  const holed = Buffer.concat([bytes.subarray(0, 2), hole, bytes.subarray(2)]);
  t.equal(independentKeytabRead(holed).length, 2, 'the independent reader ' +
                                                  'skips a hole');
  t.equal(keytab.readKeytab(holed).length, 2, 'and so does the module\'s own');
  let refused = false;
  try {
    keytab.readKeytab(bytes.subarray(0, bytes.length - 3));
  } catch (e) {
    refused = /truncated|runs past|ends before/.test(e.message);
  }
  t.check(refused, 'a truncated keytab is REFUSED rather than read half-way');
  log.debug("Leaving theKeytabRoundTrips().");
}

// ---------------------------------------------------------------------------
// 3. DEVELOPMENT MODE IS EXACTLY WHAT IT WAS.
// ---------------------------------------------------------------------------
async function developmentIsUnchanged(t) {
  log.debug("Entering developmentIsUnchanged().");
  t.log.info('=== development: the shared password, on-demand accounts, no ' +
             'derivation ===');
  const principals = require('../kerberos/krb5_principals.js');
  const personKeys = require('../kerberos/krb5_person_keys');
  const report = await driveAsExchange(principals.USER_PASSWORD, 'alice');
  t.check(report.ok === true, 'a development AS-REQ for alice with ' +
                              'krb5.userPassword gets a TGT',
          JSON.stringify(report));
  const fresh = 'devprobe' + Math.random().toString(36).slice(2, 8);
  const onDemand = await driveAsExchange(principals.USER_PASSWORD, fresh);
  t.check(onDemand.ok === true, 'a name nobody configured is still created ' +
                                'on demand',
          JSON.stringify(onDemand));
  const record = principals.find([fresh]);
  t.check(!!record && record.autoCreated === true &&
          record.directoryKeys === false &&
          record.password === principals.USER_PASSWORD,
          'and it is an ordinary on-demand account keyed from the shared ' +
          'password');
  t.check(personKeys.productKdc() === false, 'the register knows this is a ' +
                                             'development KDC');
  // A DIRECTORY THAT RECORDS EVERY CALL, so that "derives nothing" is asserted
  // against a register that COULD have — with no directory installed, the
  // observer returns before the mode is even asked. Put back afterwards to
  // exactly what was there, for tests/CLAUDE.md's slot rule.
  const before = personKeys.currentDirectory();
  const calls = [];
  const stub = {
    readPerson: function (n) {
      log.debug("Entering readPerson().");
      calls.push('read ' + n);
      log.debug("Leaving readPerson().");
      return { username: n, keys: '', info: '', passwordHash: '$scrypt$x' };
    },
    writePerson: function (n) {
      log.debug("Entering writePerson().");
      calls.push('write ' + n);
      log.debug("Leaving writePerson().");
      return true;
    },
    personKeyInfos: function () {
      log.debug("Entering personKeyInfos().");
      log.debug("Leaving personKeyInfos().");
      return [];
    },
    readService: function () {
      log.debug("Entering readService().");
      log.debug("Leaving readService().");
      return null;
    },
    writeService: function () {
      log.debug("Entering writeService().");
      log.debug("Leaving writeService().");
      return false;
    },
    serviceKeyInfos: function () {
      log.debug("Entering serviceKeyInfos().");
      log.debug("Leaving serviceKeyInfos().");
      return [];
    }
  };
  personKeys.setDirectory(stub);
  try {
    personKeys.observePassword('alice', 'Some-Password-123!', { event: 'set' });
    await personKeys.idle();
    t.check(calls.length === 0,
            'a password observed in development derives NOTHING and reads ' +
            'nothing — its KDC never reads a stored person key, so a key ' +
            'there would be password-equivalent material with no ' +
            'reader', JSON.stringify(calls));
  } finally {
    personKeys.setDirectory(before);
  }
  log.debug("Leaving developmentIsUnchanged().");
}

// An AS exchange in THIS process, against its own development KDC.
async function driveAsExchange(password, name) {
  log.debug("Entering driveAsExchange().");
  const principals = require('../kerberos/krb5_principals.js');
  const kdc = require('../kerberos/krb5_kdc.js');
  const msgs = require('../kerberos/krb5_messages.js');
  const kcrypto = require('../kerberos/krb5_crypto.js');
  const prim = require('../kerberos/krb5_primitives.js');
  const profile = kcrypto.etypeById(18);
  const key = await profile.stringToKey(password,
                                        prim.utf8(principals.REALM + name),
                                        null);
  const now = new Date();
  const cipher = await profile.encrypt(key,
    kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
    msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000));
  const bytes = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [{ type: msgs.PA_TYPE.ENC_TIMESTAMP,
               value: msgs.encEncryptedData({ etype: 18, cipher: cipher }) }],
    reqBody: { kdcOptions: [], cname: { type: 1, name: [name] },
               realm: principals.REALM,
               sname: { type: 2, name: ['krbtgt', principals.REALM] },
               till: new Date(Date.now() + 3600000), nonce: 4242, etypes: [18] }
  });
  const reply = await kdc.handleMessage(bytes);
  const id = msgs.identify(reply);
  if (id.applicationNumber === msgs.APPLICATION.KRB_ERROR) {
    const e = msgs.readKrbError(reply);
    log.debug("Leaving driveAsExchange().");
    return { ok: false, code: e.errorCode, eText: e.eText };
  }
  log.debug("Leaving driveAsExchange().");
  return { ok: true };
}

// ---------------------------------------------------------------------------
// 4. PRODUCT MODE, IN A CHILD PROCESS. The body below is serialised with
// toString() and run with `node -e`, so it is self-contained: every require is
// by the absolute root the parent hands it, and it reports one JSON document.
// ---------------------------------------------------------------------------
/* eslint-disable no-undef */
async function productChild() {
  const R = process.env.KP_ROOT;
  const out = { steps: {} };
  const keystore = require(R + '/common/keystore');
  keystore.reset();
  keystore.setStore({
    loadKeys: function () { return Promise.resolve([]); },
    saveKeys: function () { return Promise.resolve(); },
    deleteKeys: function () { return Promise.resolve(); }
  });
  await keystore.start();
  out.persists = keystore.persists();
  const config = require(R + '/common/config');
  const principals = require(R + '/kerberos/krb5_principals.js');
  const kdc = require(R + '/kerberos/krb5_kdc.js');
  const service = require(R + '/kerberos/krb5_service.js');
  const msgs = require(R + '/kerberos/krb5_messages.js');
  const kcrypto = require(R + '/kerberos/krb5_crypto.js');
  const prim = require(R + '/kerberos/krb5_primitives.js');
  const gss = require(R + '/kerberos/krb5_gss.js');
  const directory = require(R + '/ldap/ldap_server');
  const credentials = require(R + '/common/credentials');
  const personKeys = require(R + '/kerberos/krb5_person_keys');
  const audit = require(R + '/common/audit');
  const views = require(R + '/admin-core/admin_views');
  const actions = require(R + '/admin-core/admin_actions');
  const applications = require(R + '/common/applications');
  const cryptoLib = require(R + '/common/crypto');
  out.productKdc = personKeys.productKdc();
  out.sourceInstalled = principals.keySourceInstalled() &&
                        personKeys.installed();

  async function asReq(name, password, sname) {
    const etype = 18;
    const profile = kcrypto.etypeById(etype);
    const padata = [];
    let key = null;
    if (password !== null) {
      key = await profile.stringToKey(password,
                                      prim.utf8(principals.REALM + name), null);
      const now = new Date();
      const cipher = await profile.encrypt(key,
        kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
        msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000));
      padata.push({ type: msgs.PA_TYPE.ENC_TIMESTAMP,
                    value: msgs.encEncryptedData(
                        { etype: etype, cipher: cipher }) });
    }
    const target = sname || ['krbtgt', principals.REALM];
    const bytes = msgs.encKdcReq({
      msgType: msgs.MSG_TYPE.AS_REQ, padata: padata,
      reqBody: { kdcOptions: [], cname: { type: 1, name: [name] },
                 realm: principals.REALM,
                 sname: { type: target[0] === 'krbtgt' ? 2 : 3, name: target },
                 till: new Date(Date.now() + 3600000), nonce: 777, etypes: [
                   etype] }
    });
    const reply = await kdc.handleMessage(bytes);
    const id = msgs.identify(reply);
    if (id.applicationNumber === msgs.APPLICATION.KRB_ERROR) {
      const e = msgs.readKrbError(reply);
      return { ok: false, code: e.errorCode, eText: e.eText };
    }
    const rep = msgs.readKdcRep(reply);
    let enc = null;
    try {
      enc = msgs.readEncKdcRepPart(await profile.decrypt(key,
                                                         kcrypto.KEY_USAGE.AS_REP_ENCPART,
                                                         rep.encPart.cipher));
    } catch (e) {
      return { ok: false, code: -1, eText: 'the AS-REP did not decrypt under ' +
                                           'the client key: ' +
                                          e.message };
    }
    return { ok: true, rep: rep, enc: enc, nonce: enc.nonce };
  }

  // A REAL TGS-REQ: the ticket from an earlier exchange, in a PA-TGS-REQ whose
  // Authenticator is sealed under that exchange's session key and carries the
  // key-usage-6 checksum over the request body's own bytes. The ticket may be a
  // TGT or a ticket sealed under any principal's long-term key — which is what
  // makes the KDC choose that principal's key by the ticket's kvno.
  let tgsCounter = 0;
  async function tgsReq(earlier, clientName, sname) {
    tgsCounter += 1;
    const sessionKey = earlier.enc.key;
    const profile = kcrypto.etypeById(sessionKey.etype);
    const reqBody = { kdcOptions: [], realm: principals.REALM,
                      sname: { type: sname[0] === 'krbtgt' ? 2 :
                                     (sname.length > 1 ? 3 : 1),
                               name: sname },
                      till: new Date(Date.now() + 3600000),
                      nonce: 5000 + tgsCounter,
                      etypes: [18] };
    const raw = msgs.encKdcReqBody(reqBody);
    const cksum = await profile.checksum(sessionKey.key,
                                         kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM,
                                         raw);
    const auth = msgs.encAuthenticator({ crealm: principals.REALM,
      cname: { type: 1, name: [clientName] },
      cksum: { type: profile.checksumType, checksum: cksum },
      cusec: 1000 + tgsCounter, ctime: new Date() });
    const apReq = msgs.encApReq({ apOptions: [], ticket: earlier.rep.ticket,
      authenticator: { etype: sessionKey.etype,
                       cipher: await profile.encrypt(sessionKey.key,
                         kcrypto.KEY_USAGE.TGS_REQ_AUTH, auth) } });
    const bytes = msgs.encKdcReq({ msgType: msgs.MSG_TYPE.TGS_REQ,
      padata: [{ type: msgs.PA_TYPE.TGS_REQ, value: apReq }],
      reqBody: Object.assign({ raw: raw }, reqBody) });
    const reply = await kdc.handleMessage(bytes);
    if (msgs.identify(reply).applicationNumber === msgs.APPLICATION.KRB_ERROR) {
      const e = msgs.readKrbError(reply);
      return { ok: false, code: e.errorCode, eText: e.eText };
    }
    const rep = msgs.readKdcRep(reply);
    return { ok: true, kvno: rep.ticket.encPart.kvno };
  }

  const brief = function (r) {
    return { ok: r.ok, code: r.code, eText: r.eText,
             kvno: r.kvno !== undefined ? r.kvno
               : (r.rep ? r.rep.ticket.encPart.kvno : undefined) };
  };

  function entryOf(name) {
    const realms = require(R + '/common/realms');
    return realms.run(realms.DEFAULT_REALM, function () {
      return directory.existingUserEntry(name);
    });
  }

  // --- a person, a password, keys ---
  const PW = 'Correct-Horse-Battery-9!';
  const made = directory.createUser('kpalice', { invent: false });
  out.steps.created = made.ok;
  const set = credentials.setPassword('kpalice', PW);
  out.steps.set = set.ok;
  await personKeys.idle();
  const people = personKeys.listPeople();
  out.alice = people.filter(function (p) {
    return p.username === 'kpalice';
  })[0] || null;
  const stored = entryOf('kpalice');
  const rawKeys = (stored && stored.attributes.stskrb5keys) || [];
  out.storedSealed = rawKeys.length === 1 &&
                     String(rawKeys[0]).indexOf('$aesgcm$') === 0;
  out.storedClearMentionsKey = /"keys"/.test(String(rawKeys[0] || ''));
  const good = await asReq('kpalice', PW);
  out.goodAs = { ok: good.ok, code: good.code, eText: good.eText,
                 nonce: good.nonce };
  const bad = await asReq('kpalice', 'Wrong-Password-Entirely-1!');
  out.badAs = { ok: bad.ok, code: bad.code, eText: bad.eText };
  // THE SHARED DEVELOPMENT PASSWORD MUST BE NOTHING TO A DIRECTORY PERSON, and
  // the record the KDC keeps for them must carry no password and no key.
  const shared = await asReq('kpalice', principals.USER_PASSWORD);
  out.sharedAs = { ok: shared.ok, code: shared.code };
  const record = principals.find(['kpalice']);
  out.recordPassword = record ? record.password : 'no record';
  out.recordDirectoryKeys = record ? record.directoryKeys : null;
  out.recordJsonHasKeys = record ? /"keys"/.test(JSON.stringify(record)) : null;

  // The actual key bytes, from inside the seal, so the parent can look for
  // them.
  const opened = JSON.parse(keystore.open(String(rawKeys[0]), 'kerberos-keys'));
  out.keyMaterial = Object.keys(opened.keys)
                          .map(function (e) { return opened.keys[e]; });
  out.boundName = opened.name;

  // --- a person with a password and NO keys, then the upgrade on a verify ---
  directory.createUser('kpbob', { invent: false });
  config.setOverride('krb5.personKeys', 'false');
  credentials.setPassword('kpbob', PW);
  await personKeys.idle();
  const offAs = await asReq('kpbob', PW);
  out.offAs = { ok: offAs.ok, code: offAs.code, eText: offAs.eText };
  config.clearOverride('krb5.personKeys');
  const noKeys = await asReq('kpbob', PW);
  out.noKeysAs = { ok: noKeys.ok, code: noKeys.code, eText: noKeys.eText };
  const verified = await credentials.verifyAsync('kpbob', PW, { via: 'test' });
  out.bobVerified = verified.ok;
  await personKeys.idle();
  const upgraded = await asReq('kpbob', PW);
  out.upgradedAs = { ok: upgraded.ok, code: upgraded.code,
                     eText: upgraded.eText };
  const wrongVerify = await credentials.verifyAsync('kpcarol-nobody', PW,
                                                    { via: 'test' });
  out.nobodyVerified = wrongVerify.ok;
  const unknown = await asReq('kpnobody', PW);
  out.unknownAs = { ok: unknown.ok, code: unknown.code, eText: unknown.eText };

  // --- a password change bumps the kvno and the old password stops working ---
  const kvnoBefore = out.alice ? out.alice.kvno : null;
  // TWO TICKETS ISSUED BEFORE THE CHANGE: alice's own TGT (sealed under
  // krbtgt), and a ticket FOR alice — sealed under HER long-term key at kvno 3
  // — which is the one a password change would strand without a kept previous
  // version.
  const aliceTgt = await asReq('kpalice', PW);
  const toAlice3 = await asReq('kpbob', PW, ['kpalice']);
  out.toAlice3 = brief(toAlice3);
  const PW2 = 'Another-Strong-Pass-42?';
  credentials.setPassword('kpalice', PW2);
  await personKeys.idle();
  // AFTER THE CHANGE: both old tickets still open at the KDC, and what it
  // issues for alice now is under kvno 4.
  out.tgtAfterChange = brief(await tgsReq(aliceTgt, 'kpalice',
                                          ['krbtgt', principals.REALM]));
  out.toAlice3AfterChange = brief(await tgsReq(toAlice3, 'kpbob',
                                               ['krbtgt', principals.REALM]));
  const toAlice4 = await asReq('kpbob', PW, ['kpalice']);
  out.toAlice4 = brief(toAlice4);
  out.aliceRetainedAfterChange = (personKeys.listPeople().filter(function (p) {
    return p.username === 'kpalice';
  })[0] || {}).retained || null;
  const afterChange = personKeys.listPeople().filter(function (p) {
    return p.username === 'kpalice';
  })[0] || {};
  out.kvnoBefore = kvnoBefore;
  out.kvnoAfter = afterChange.kvno;
  const oldAs = await asReq('kpalice', PW);
  out.oldAs = { ok: oldAs.ok, code: oldAs.code, eText: oldAs.eText };
  const newAs = await asReq('kpalice', PW2);
  out.newAs = { ok: newAs.ok, code: newAs.code };

  // --- the stamp: a password written WITHOUT the observer (an LDAP modify, say) ---
  const realms = require(R + '/common/realms');
  realms.run(realms.DEFAULT_REALM, function () {
    const located = directory.existingUserEntry('kpalice');
    located.attributes.userpassword = [cryptoLib.hashSecret(
        'Planted-Elsewhere-77!')];
  });
  const staleAs = await asReq('kpalice', PW2);
  out.staleAs = { ok: staleAs.ok, code: staleAs.code, eText: staleAs.eText };
  // put a real password back through the door
  credentials.setPassword('kpalice', PW2 + 'x');
  await personKeys.idle();

  // --- the previous-version bounds: the count, the lifetime, and drop-now ---
  // kvno 5 now. krb5.retainedKeyVersions is 1, so 4 is kept and 3 is not.
  out.aliceKvno5 = (personKeys.listPeople().filter(function (p) {
    return p.username === 'kpalice';
  })[0] || {}).kvno;
  out.count3 = brief(await tgsReq(toAlice3, 'kpbob',
                                  ['krbtgt', principals.REALM]));
  out.count4 = brief(await tgsReq(toAlice4, 'kpbob',
                                  ['krbtgt', principals.REALM]));
  // A LIFETIME OF ONE SECOND reaches a version retired under the default one,
  // because the bound is read at every read ...
  config.setOverride('krb5.retainedKeyTtlS', '1');
  await new Promise(function (resolve) { setTimeout(resolve, 1300); });
  out.ttlExpired4 = brief(await tgsReq(toAlice4, 'kpbob',
                                       ['krbtgt', principals.REALM]));
  out.ttlListed = (personKeys.listPeople().filter(function (p) {
    return p.username === 'kpalice';
  })[0] || {}).retained || null;
  // ... and clearing it gives back only what the bound it was RETIRED under
  // still allows.
  config.clearOverride('krb5.retainedKeyTtlS');
  out.ttlRestored4 = brief(await tgsReq(toAlice4, 'kpbob',
                                        ['krbtgt', principals.REALM]));
  // DROP NOW, through the console's own action.
  const droppedPerson = actions.kerberosPrincipalsAction(
    { action: 'drop-previous-person-keys', username: 'kpalice' },
    { actor: 'test', via: 'api' });
  out.dropPerson = { ok: droppedPerson.ok, dropped: droppedPerson.dropped,
                     kvnos: droppedPerson.kvnos,
                     errors: droppedPerson.errors || null };
  out.afterDrop4 = brief(await tgsReq(toAlice4, 'kpbob',
                                      ['krbtgt', principals.REALM]));
  out.afterDropSignIn = brief(await asReq('kpalice', PW2 + 'x'));
  out.afterDropOldPassword = brief(await asReq('kpalice', PW2));
  out.afterDropListed = (personKeys.listPeople().filter(function (p) {
    return p.username === 'kpalice';
  })[0] || {}).retained || null;
  const droppedAgain = actions.kerberosPrincipalsAction(
    { action: 'drop-previous-person-keys', username: 'kpalice' },
    { actor: 'test', via: 'api' });
  out.dropAgain = { ok: droppedAgain.ok, dropped: droppedAgain.dropped };
  // The retained versions sit inside the seal and nowhere else.
  const aliceSealed = realms.run(realms.DEFAULT_REALM, function () {
    return directory.existingUserEntry('kpalice').attributes.stskrb5keyinfo;
  });
  out.infoHasKeys = /"keys"/.test(JSON.stringify(aliceSealed || ''));

  // --- a copied sealed value on somebody else's entry names the wrong person ---
  // The PASSWORD HASH is copied with it, so the stamp matches and the name
  // inside the seal is the only thing between bob's entry and alice's keys. The
  // request uses alice's SALT, which is what a client following PA-ETYPE-INFO2
  // would do if the KDC advertised the copied record's salt.
  const bobBefore = realms.run(realms.DEFAULT_REALM, function () {
    const b = directory.existingUserEntry('kpbob').attributes;
    return { keys: b.stskrb5keys, info: b.stskrb5keyinfo, pw: b.userpassword };
  });
  realms.run(realms.DEFAULT_REALM, function () {
    const a = directory.existingUserEntry('kpalice').attributes;
    const b = directory.existingUserEntry('kpbob').attributes;
    b.stskrb5keys = a.stskrb5keys.slice();
    b.userpassword = a.userpassword.slice();
  });
  const copiedKdc = await (async function () {
    const profile = kcrypto.etypeById(18);
    const key = await profile.stringToKey(PW2 + 'x',
                                          prim.utf8(
                                              principals.REALM + 'kpalice'),
                                          null);
    const now = new Date();
    const cipher = await profile.encrypt(key,
      kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
      msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000));
    const bytes = msgs.encKdcReq({ msgType: msgs.MSG_TYPE.AS_REQ,
      padata: [{ type: msgs.PA_TYPE.ENC_TIMESTAMP,
                 value: msgs.encEncryptedData({ etype: 18, cipher: cipher }) }],
      reqBody: { kdcOptions: [], cname: { type: 1, name: ['kpbob'] },
                 realm: principals.REALM,
                 sname: { type: 2, name: ['krbtgt', principals.REALM] },
                 till: new Date(Date.now() + 3600000), nonce: 9, etypes: [
                   18] } });
    const reply = await kdc.handleMessage(bytes);
    if (msgs.identify(reply).applicationNumber === msgs.APPLICATION.KRB_ERROR) {
      const e = msgs.readKrbError(reply);
      return { ok: false, code: e.errorCode, eText: e.eText };
    }
    return { ok: true };
  })();
  out.copiedAs = copiedKdc;
  realms.run(realms.DEFAULT_REALM, function () {
    const b = directory.existingUserEntry('kpbob').attributes;
    b.stskrb5keys = bobBefore.keys;
    b.userpassword = bobBefore.pw;
  });
  // --- and a CLEAR value planted while keys persist is refused ---
  realms.run(realms.DEFAULT_REALM, function () {
    const b = directory.existingUserEntry('kpbob').attributes;
    b.stskrb5keys = [JSON.stringify({ v: 1, name: 'kpbob',
                                      realm: principals.REALM, kvno: 9,
                                      salt: principals.REALM +
                                            'kpbob', stamp: 'x', keys: {} })];
  });
  out.plantedState = personKeys.personKeys('kpbob').state;

  // --- keys never in audit rows, in the views, or on the directory dump ---
  const auditText = JSON.stringify(audit.list());
  out.auditHasKey = out.keyMaterial.some(function (
      k) { return auditText.indexOf(k) >= 0; });
  out.auditHasPassword = auditText.indexOf(PW) >= 0 ||
                         auditText.indexOf(PW2) >= 0;
  out.auditHasDerivedRow = /krb5\.keys\.derived/.test(auditText);
  const viewText = JSON.stringify(views.kerberosPrincipalsJson({ query: {} }));
  out.viewHasKey = out.keyMaterial.some(function (
      k) { return viewText.indexOf(k) >= 0; }) ||
                   viewText.indexOf('$aesgcm$') >= 0;
  const dump = realms.run(realms.DEFAULT_REALM, function () {
    return JSON.stringify(directory.objectFor('kpalice'));
  });
  out.withheldHelper = personKeys.withheldValues('stskrb5keys', ['abc'])[0];

  // --- a service principal: create, keytab, KDC, acceptor, rotate ---
  const created = actions.kerberosPrincipalsAction(
    { action: 'create-service', spn: 'HTTP/web.example.com' },
    { actor: 'test', via: 'api' });
  out.createOk = created.ok;
  out.createErrors = created.errors || null;
  out.keytab = created.keytab || '';
  out.createKvno = created.kvno;
  const svcView = JSON.stringify(views.kerberosPrincipalsJson({ query: {} }));
  const appView = realms.run(realms.DEFAULT_REALM, function () {
    return JSON.stringify(applications.get('HTTP/web.example.com@' +
                                           principals.REALM));
  });
  out.appViewWithheld = /withheld: Kerberos key material/.test(appView);
  out.serviceAccount = principals.serviceAccount();
  // A SIGHTING REWRITES THE APPLICATION ENTRY FROM ITS RECORD, which is what
  // the KDC does on every ticket it issues for the SPN; the stored key must
  // survive.
  realms.run(realms.DEFAULT_REALM, function () {
    applications.seen({ identifier: 'HTTP/web.example.com@' + principals.REALM,
                        kind: 'kerberos-service', protocol: 'Kerberos v5',
                        note: 'a sighting in the test' });
  });
  out.keysSurviveSighting = !!personKeys.serviceKeys('HTTP/web.example.com');
  // A service ticket issued by the KDC in the AS exchange, straight to the SPN.
  // A FRESH password for bob: the password policy refuses his current one, and
  // the planted value above has to be replaced by a real derivation.
  const PW3 = 'Third-Distinct-Passw0rd#';
  out.bobReset = credentials.setPassword('kpbob', PW3).ok;
  await personKeys.idle();
  const svcTicket = await asReq('kpbob', PW3, ['HTTP', 'web.example.com']);
  out.svcTicket = { ok: svcTicket.ok, code: svcTicket.code,
                    eText: svcTicket.eText,
                    kvno: svcTicket.ok ? svcTicket.rep.ticket.encPart.kvno :
                          null };
  if (svcTicket.ok) {
    out.ticketCipherHex = Buffer.from(svcTicket.rep.ticket.encPart.cipher)
                                .toString('hex');
    out.ticketEtype = svcTicket.rep.ticket.encPart.etype;
    const sessionKey = svcTicket.enc.key;
    const authProfile = kcrypto.etypeById(sessionKey.etype);
    const makeApReq = async function (cusec) {
      const auth = msgs.encAuthenticator({ crealm: principals.REALM,
                                           cname: { type: 1, name: ['kpbob'] },
                                           cusec: cusec, ctime: new Date() });
      const apReq = msgs.encApReq({
        apOptions: [],
        ticket: svcTicket.rep.ticket,
        authenticator: { etype: sessionKey.etype,
                         cipher: await authProfile.encrypt(sessionKey.key,
                           kcrypto.KEY_USAGE.AP_REQ_AUTH, auth) }
      });
      return gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq);
    };
    const accepted = await service.acceptRaw(await makeApReq(123456),
                                             { record: false });
    out.acceptorOk = accepted.ok;
    out.acceptorFailed = (accepted.checks || []).filter(
        function (c) { return !c.ok; });
    // An AP-REQ for ANY service ticket, so a ticket issued at kvno 4 or 5 can
    // be presented beside the kvno-3 one. The acceptor's replay cache keys on
    // ctime and cusec, so every call carries a fresh cusec.
    let apCusec = 200000;
    const acceptTicket = async function (issued) {
      apCusec += 1;
      const key = issued.enc.key;
      const profile = kcrypto.etypeById(key.etype);
      const auth = msgs.encAuthenticator({ crealm: principals.REALM,
                                           cname: { type: 1, name: ['kpbob'] },
                                           cusec: apCusec, ctime: new Date() });
      const apReq = msgs.encApReq({ apOptions: [], ticket: issued.rep.ticket,
        authenticator: { etype: key.etype,
          cipher: await profile.encrypt(key.key, kcrypto.KEY_USAGE.AP_REQ_AUTH,
                                        auth) } });
      const answer = await service.acceptRaw(
        gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq),
        { record: false });
      const versionCheck = (answer.checks || []).filter(function (c) {
        return c.name === 'key version matches';
      })[0] || {};
      return { ok: answer.ok, errorCode: answer.errorCode || null,
               versionOk: versionCheck.ok,
               versionDetail: versionCheck.detail || '',
               failed: (answer.checks || []).filter(
                   function (c) { return !c.ok; })
                 .map(function (c) { return c.name + ': ' + c.detail; }) };
    };
    const rotated = actions.kerberosPrincipalsAction(
      { action: 'rotate-service', spn: 'HTTP/web.example.com' },
      { actor: 'test', via: 'api' });
    out.rotateOk = rotated.ok;
    out.rotateKvno = rotated.kvno;
    out.rotateKeytab = rotated.keytab || '';
    out.rotateKeytabKvnos = rotated.keytabKvnos || null;
    out.rotateRetained = rotated.retained || null;
    const afterRotate = await service.acceptRaw(await makeApReq(654321),
                                                { record: false });
    out.afterRotateOk = afterRotate.ok;
    out.afterRotateCode = afterRotate.errorCode || null;
    out.afterRotateFailed = (afterRotate.checks || []).filter(
        function (c) { return !c.ok; })
      .map(function (c) { return c.name + ': ' + c.detail; });
    // THE KDC NOW ISSUES UNDER kvno 4, and the acceptor takes both.
    const svc4 = await asReq('kpbob', PW3, ['HTTP', 'web.example.com']);
    out.svc4 = brief(svc4);
    out.accept3 = await acceptTicket(svcTicket);
    out.accept4 = svc4.ok ? await acceptTicket(svc4) : null;
    // THE KDC's TGS OPENS THE kvno-3 TICKET UNDER THE KEPT VERSION TOO.
    out.tgs3 = brief(await tgsReq(svcTicket, 'kpbob',
                                  ['krbtgt', principals.REALM]));
    // A SECOND ROTATION: kvno 5, and with one version kept the keytab holds 5
    // and 4 and not 3, and the kvno-3 ticket is refused.
    const rotated2 = actions.kerberosPrincipalsAction(
      { action: 'rotate-service', spn: 'HTTP/web.example.com' },
      { actor: 'test', via: 'api' });
    out.rotate2Kvno = rotated2.kvno;
    out.rotate2Keytab = rotated2.keytab || '';
    const svc5 = await asReq('kpbob', PW3, ['HTTP', 'web.example.com']);
    out.svc5 = brief(svc5);
    out.accept3After2 = await acceptTicket(svcTicket);
    out.accept4After2 = svc4.ok ? await acceptTicket(svc4) : null;
    out.tgs3After2 = brief(await tgsReq(svcTicket, 'kpbob',
                                        ['krbtgt', principals.REALM]));
    out.servicesListed = (personKeys.listServices().filter(function (s) {
      return s.spn === 'HTTP/web.example.com';
    })[0] || {}).retained || null;
    // DROP NOW, and kvno 4 goes the way kvno 3 did while 5 carries on.
    const droppedService = actions.kerberosPrincipalsAction(
      { action: 'drop-previous-service-keys', spn: 'HTTP/web.example.com' },
      { actor: 'test', via: 'api' });
    out.dropService = { ok: droppedService.ok, dropped: droppedService.dropped,
                        kvnos: droppedService.kvnos,
                        errors: droppedService.errors || null };
    out.accept4AfterDrop = svc4.ok ? await acceptTicket(svc4) : null;
    out.tgs4AfterDrop = svc4.ok
      ? brief(await tgsReq(svc4, 'kpbob', ['krbtgt', principals.REALM])) : null;
    out.accept5AfterDrop = svc5.ok ? await acceptTicket(svc5) : null;
    out.dropUnknown = actions.kerberosPrincipalsAction(
      { action: 'drop-previous-service-keys', spn: 'HTTP/nobody.example.com' },
      {}).ok;
  }
  out.svcViewHasKeytab = !!out.keytab &&
                         svcView.indexOf(out.keytab.slice(0, 40)) >= 0;
  const deleted = actions.kerberosPrincipalsAction(
    { action: 'delete-service', spn: 'HTTP/web.example.com' },
    { actor: 'test', via: 'api' });
  out.deleteOk = deleted.ok;
  out.afterDeleteFind = !!principals.find(['HTTP', 'web.example.com']);
  const again = actions.kerberosPrincipalsAction(
    { action: 'rotate-service', spn: 'HTTP/web.example.com' },
    { actor: 'test', via: 'api' });
  out.rotateAfterDelete = { ok: again.ok, errors: again.errors };
  out.krbtgtRefused = actions.kerberosPrincipalsAction(
    { action: 'create-service', spn: 'krbtgt/' + principals.REALM },
    {}).ok === false;
  out.unknownAction = actions.kerberosPrincipalsAction({ action: 'nope' },
                                                       {}).errors;
  const cleared = actions.kerberosPrincipalsAction(
    { action: 'clear-person-keys', username: 'kpbob' }, { actor: 'test' });
  out.clearOk = cleared.ok && cleared.cleared;
  const afterClear = await asReq('kpbob', PW3);
  out.afterClearAs = { ok: afterClear.ok, code: afterClear.code,
                       eText: afterClear.eText };
  const auditAll = JSON.stringify(audit.list());
  out.auditHasKeytab = !!out.keytab &&
                       auditAll.indexOf(out.keytab.slice(0, 40)) >= 0;
  out.auditHasDropRow = /admin\.krb5\.previous\.dropped/.test(auditAll);
  out.dumpHasKey = out.keyMaterial.some(function (
      k) { return dump.indexOf(k) >= 0; });
  return out;
}

/* eslint-enable no-undef */

function inAProductChild(t) {
  log.debug("Entering inAProductChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krb5-person-keys-'));
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  const outFile = path.join(dir, 'report.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const script = 'delete process.env.CONFIG_FILE;' +
    '(' + productChild.toString() + ')().then(function (r) ' +
    '{require("fs").writeFileSync(process.env.KP_OUT, JSON.stringify(r)); ' +
    'process.exit(0); }).catch(function (e) { ' +
    'require("fs").writeFileSync(process.env.KP_OUT, JSON.stringify({ ' +
    'crashed: e.stack || e.message })); process.exit(0); });';
  const run = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, {
      LOG_LEVEL: 'fatal', KP_ROOT: ROOT, KP_OUT: outFile,
      STS_MODE: 'product',
      KRB5_KRBTGT_PASSWORD: 'not-the-published-krbtgt-secret',
      STS_KEYS_SOURCE: 'persisted', STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: kekFile
    }),
    encoding: 'utf8', timeout: 180000
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAProductChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. The assertion below says
    // so.
    report = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // Best effort: a temporary directory left behind is litter, not a failure.
    log.debug("Caught in inAProductChild(): " + ((e && e.message) || e));
  }
  t.check(report !== null && !report.crashed, 'the product-mode child ran to ' +
                                              'the end',
          'exit ' + run.status + ' ' + (report && report.crashed) + ' ' +
          String(run.stderr || '').slice(0, 800));
  log.debug("Leaving inAProductChild().");
  return report;
}

function productModeAuthenticatesPeople(t, r) {
  log.debug("Entering productModeAuthenticatesPeople().");
  t.log.info('=== product mode: a person authenticates with their own ' +
             'password ===');
  t.check(r.productKdc === true && r.sourceInstalled === true &&
          r.persists === true,
          'the child is a product KDC with the key source installed and a ' +
          'persisting key-encryption ' +
          'key', JSON.stringify({ productKdc: r.productKdc,
                                                 sourceInstalled:
                                                   r.sourceInstalled,
                                                 persists: r.persists }));
  t.check(r.steps.created && r.steps.set, 'a person was created and given a ' +
                                          'password');
  t.check(!!r.alice && r.alice.kvno === 3 && r.alice.sealed === true &&
          r.alice.current === true &&
          r.alice.etypes.length === 5,
          'SETTING THE PASSWORD DERIVED KEYS: kvno krb5.kvno, every enctype, ' +
          'sealed, and matching the password', JSON.stringify(r.alice));
  t.check(r.storedSealed === true && r.storedClearMentionsKey === false,
          'the entry holds ONE sealed value and no key in the clear');
  t.equal(r.boundName, 'kpalice', 'the name is sealed WITH the keys');
  t.check(r.goodAs.ok === true && r.goodAs.nonce === 777,
          'A REAL AS-REQ WITH THE RIGHT PASSWORD GETS AN AS-REP whose ' +
          'enc-part decrypts under the key the CLIENT derived, nonce ' +
          'intact', JSON.stringify(r.goodAs));
  t.check(r.badAs.ok === false && r.badAs.code === 24,
          'the same request with a wrong password is KDC_ERR_PREAUTH_FAILED',
          JSON.stringify(r.badAs));
  t.check(r.sharedAs.ok === false && r.sharedAs.code === 24,
          'AND krb5.userPassword — the shared development password — IS ' +
          'REFUSED for a directory person', JSON.stringify(r.sharedAs));
  t.check(r.recordPassword === null && r.recordDirectoryKeys === true &&
          r.recordJsonHasKeys === false,
          'the principal record carries NO password and its serialised ' +
          '(persisted) form carries no ' +
          'key', JSON.stringify({ password: r.recordPassword,
                                              directoryKeys:
                                                r.recordDirectoryKeys,
                                              keysInJson:
                                                r.recordJsonHasKeys }));
  log.debug("Leaving productModeAuthenticatesPeople().");
}

function productModeRefusesAndUpgrades(t, r) {
  log.debug("Entering productModeRefusesAndUpgrades().");
  t.log.info('=== product mode: no keys, the upgrade on a verify, and the ' +
             'refusals ===');
  t.check(r.offAs.ok === false && r.offAs.code === 6 &&
          /krb5\.personKeys/.test(r.offAs.eText),
          'with krb5.personKeys off a person is refused, naming the setting',
          JSON.stringify(r.offAs));
  t.check(r.noKeysAs.ok === false && r.noKeysAs.code === 6 &&
          /no Kerberos keys yet - sign in once with the password, or reset it/.test(r.noKeysAs.eText),
          'A PERSON WITH A PASSWORD AND NO KEYS is refused ' +
          'KDC_ERR_C_PRINCIPAL_UNKNOWN with the sign-in-once ' +
          'e-text', JSON.stringify(r.noKeysAs));
  t.check(r.bobVerified === true && r.upgradedAs.ok === true,
          'A VERIFIED SIGN-IN DERIVES THE MISSING KEYS, and the next AS-REQ ' +
          'succeeds',
          JSON.stringify(r.upgradedAs));
  t.check(r.nobodyVerified === false && r.unknownAs.ok === false &&
          r.unknownAs.code === 6 &&
          /nobody by that name/.test(r.unknownAs.eText),
          'somebody not in the directory is unknown, and says so',
          JSON.stringify(r.unknownAs));
  t.check(r.kvnoBefore === 3 && r.kvnoAfter === 4,
          'A PASSWORD CHANGE ADDS ONE TO THE KVNO',
          r.kvnoBefore + ' -> ' + r.kvnoAfter);
  t.check(r.oldAs.ok === false && r.oldAs.code === 24,
          'and a ticket request with the OLD password is refused',
          JSON.stringify(r.oldAs));
  t.check(r.newAs.ok === true, 'while the new password works',
          JSON.stringify(r.newAs));
  t.check(r.staleAs.ok === false && r.staleAs.code === 6 &&
          /no longer has/.test(r.staleAs.eText),
          'A PASSWORD WRITTEN BEHIND THE OBSERVER\'S BACK makes the stored ' +
          'keys STALE, and the KDC refuses them rather than accepting a key ' +
          'for a password the entry no longer ' +
          'holds', JSON.stringify(r.staleAs));
  t.check(r.copiedAs.ok === false && r.copiedAs.code === 6,
          'a sealed value copied onto another person\'s entry — WITH that ' +
          'person\'s password hash, so the stamp matches — is refused: the ' +
          'name is inside the seal', JSON.stringify(r.copiedAs));
  t.equal(r.plantedState, 'unreadable',
          'and a CLEAR value planted while keys persist is refused as ' +
          'unreadable');
  log.debug("Leaving productModeRefusesAndUpgrades().");
}

function keysAreNeverShown(t, r) {
  log.debug("Entering keysAreNeverShown().");
  t.log.info('=== no key in an audit row, a view or a dump ===');
  t.check(Array.isArray(r.keyMaterial) && r.keyMaterial.length === 5,
          'the child read the real key bytes out of the seal to look for them');
  t.check(r.auditHasDerivedRow === true, 'the derivation IS audited');
  t.check(r.auditHasKey === false && r.auditHasPassword === false,
          'and no audit row carries a key or a password');
  t.check(r.viewHasKey === false, 'the console/API view carries no key and ' +
                                  'no ciphertext');
  t.check(r.dumpHasKey === false,
          'the directory entry as the console draws it carries no key in the ' +
          'clear');
  t.check(/withheld: Kerberos key material/.test(r.withheldHelper),
          'the dump and a search withhold the attribute');
  log.debug("Leaving keysAreNeverShown().");
}

function servicePrincipalsWork(t, r) {
  log.debug("Entering servicePrincipalsWork().");
  t.log.info('=== a service principal: keytab, KDC, acceptor, rotate, delete ' +
             '===');
  t.check(r.createOk === true && r.createKvno === 3 && r.keytab.length > 100,
          'create-service answers with a keytab at kvno krb5.kvno',
          JSON.stringify({ ok: r.createOk, errors: r.createErrors,
                           kvno: r.createKvno }));
  const entries = independentKeytabRead(Buffer.from(r.keytab, 'base64'));
  t.check(entries.length === 5 && entries.every(function (e) {
    return e.name.join('/') === 'HTTP/web.example.com' &&
           e.realm === 'EXAMPLE.COM' && e.vno === 3;
  }), 'THE KEYTAB PARSES WITH THE INDEPENDENT READER: five enctypes for the ' +
      'SPN at kvno 3',
     JSON.stringify(entries.map(function (e) { return [e.enctype, e.vno]; })));
  t.check(r.appViewWithheld === true, 'the application view withholds the ' +
                                      'stored key');
  t.check(r.keysSurviveSighting === true,
          'a sighting — which REPLACES the application entry from its record ' +
          '— keeps the stored key');
  t.check(r.serviceAccount.available === true &&
          r.serviceAccount.storedKey === true,
          'the acceptor\'s account — refused in product for its published ' +
          'password — is available once a key is stored for its ' +
          'SPN', JSON.stringify(r.serviceAccount));
  t.check(r.bobReset === true, 'a planted value is replaced by the next ' +
                               'password set');
  t.check(r.svcTicket.ok === true && r.svcTicket.kvno === 3,
          'the KDC issues a service ticket for the SPN under the stored ' +
          'key\'s kvno',
          JSON.stringify(r.svcTicket));
  if (r.ticketCipherHex) {
    t.check(r.acceptorOk === true, 'THE ACCEPTOR ACCEPTS A TICKET FOR IT',
            JSON.stringify(r.acceptorFailed));
    t.check(r.rotateOk === true && r.rotateKvno === 4, 'rotate-service moves ' +
                                                       'the kvno to 4');
    t.check(r.afterRotateOk === true,
            'AND A TICKET ISSUED UNDER THE PREVIOUS KEY IS STILL ACCEPTED ' +
            'after the rotation — the version it replaced is kept ' +
            '(krb5.retainedKeyVersions 1)',
            JSON.stringify({ code: r.afterRotateCode,
                             failed: r.afterRotateFailed }));
  }
  t.check(r.svcViewHasKeytab === false, 'the keytab is not in the view ' +
                                        'afterwards');
  t.check(r.auditHasKeytab === false, 'nor in any audit row');
  t.check(r.deleteOk === true && r.afterDeleteFind === false,
          'delete-service removes the key, and a product KDC then has no ' +
          'account for the SPN');
  t.check(r.rotateAfterDelete.ok === false, 'rotating a deleted principal is ' +
                                            'refused');
  t.check(r.krbtgtRefused === true, 'krbtgt/* is refused');
  t.check(Array.isArray(r.unknownAction) &&
          /Unknown action "nope"\. There are six: create-service, rotate-service, delete-service, clear-person-keys, drop-previous-service-keys, drop-previous-person-keys\./
            .test(r.unknownAction.join(' ')),
          'an unknown action gets the house sentence',
          JSON.stringify(r.unknownAction));
  t.check(r.clearOk === true && r.afterClearAs.ok === false &&
          r.afterClearAs.code === 6 &&
          /no Kerberos keys yet/.test(r.afterClearAs.eText),
          'clear-person-keys takes a person\'s keys away and the KDC says ' +
          'sign in once',
          JSON.stringify(r.afterClearAs));
  log.debug("Leaving servicePrincipalsWork().");
}

// ---------------------------------------------------------------------------
// 5. PREVIOUS KEY VERSIONS (2026-09-12). A password change and a rotation keep
// the version they replace, for tickets already issued under it — and nothing
// else: pre-authentication, issuance and the bounds are each asserted.
// ---------------------------------------------------------------------------
function previousPersonVersionsAreKept(t, r) {
  log.debug("Entering previousPersonVersionsAreKept().");
  t.log.info('=== previous key versions: a person ===');
  t.check(r.toAlice3.ok === true && r.toAlice3.kvno === 3,
          'before the password change the KDC issues a ticket FOR alice ' +
          'under her kvno 3',
          JSON.stringify(r.toAlice3));
  t.check(r.tgtAfterChange.ok === true,
          'a TGT issued before the password change still works in a TGS-REQ ' +
          'after it',
          JSON.stringify(r.tgtAfterChange));
  t.check(r.toAlice3AfterChange.ok === true,
          'A TICKET SEALED UNDER ALICE\'S PREVIOUS KEY (kvno 3) IS STILL ' +
          'OPENED BY THE KDC after her password moved to kvno ' +
          '4', JSON.stringify(r.toAlice3AfterChange));
  t.check(r.oldAs.ok === false && r.oldAs.code === 24,
          'while the OLD PASSWORD IS REFUSED at pre-authentication — a kept ' +
          'version is never a way in', JSON.stringify(r.oldAs));
  t.check(r.toAlice4.ok === true && r.toAlice4.kvno === 4,
          'and what the KDC ISSUES for alice now is under the current kvno ' +
          '4, never the kept one', JSON.stringify(r.toAlice4));
  t.check(Array.isArray(r.aliceRetainedAfterChange) &&
          r.aliceRetainedAfterChange.length === 1 &&
          r.aliceRetainedAfterChange[0].kvno === 3 &&
          r.aliceRetainedAfterChange[0].etypes.length === 5 &&
          !isNaN(Date.parse(r.aliceRetainedAfterChange[0].expiresAt)),
          'the people list shows the kept version: kvno, enctypes and expiry',
          JSON.stringify(r.aliceRetainedAfterChange));
  t.check(r.infoHasKeys === false,
          'and the public info attribute carries no key for it — the kept ' +
          'keys are inside the seal with the current ones');
  t.equal(r.aliceKvno5, 5, 'a further password change moves alice to kvno 5');
  t.check(r.count3.ok === false && r.count3.code === 44 &&
          /version 3/.test(String(r.count3.eText)) &&
          /keeps previous version 4/.test(String(r.count3.eText)),
          'THE COUNT BOUND: with krb5.retainedKeyVersions 1 only kvno 4 is ' +
          'kept, and a ticket under kvno 3 is refused KRB_AP_ERR_BADKEYVER ' +
          'naming what IS kept',
          JSON.stringify(r.count3));
  t.check(r.count4.ok === true, 'while the ticket under kvno 4 is still opened',
          JSON.stringify(r.count4));
  t.check(r.ttlExpired4.ok === false && r.ttlExpired4.code === 44,
          'THE LIFETIME BOUND: with krb5.retainedKeyTtlS at 1 and a second ' +
          'gone, the kvno-4 ticket is refused — the bound is read at the ' +
          'read, not only when the version was ' +
          'retired', JSON.stringify(r.ttlExpired4));
  t.check(Array.isArray(r.ttlListed) && r.ttlListed.length === 0,
          'and the list stops showing the expired version at once',
          JSON.stringify(r.ttlListed));
  t.check(r.ttlRestored4.ok === true,
          'clearing that override gives back only what the bound it was ' +
          'RETIRED under still allows, which here is the ' +
          'version', JSON.stringify(r.ttlRestored4));
  t.check(r.dropPerson.ok === true && r.dropPerson.dropped === 1 &&
          JSON.stringify(r.dropPerson.kvnos) === '[4]',
          'drop-previous-person-keys drops kvno 4',
          JSON.stringify(r.dropPerson));
  t.check(r.afterDrop4.ok === false && r.afterDrop4.code === 44,
          'AND THE kvno-4 TICKET IS REFUSED KRB_AP_ERR_BADKEYVER FROM THE ' +
          'NEXT REQUEST',
          JSON.stringify(r.afterDrop4));
  t.check(r.afterDropSignIn.ok === true,
          'while the current key — and so alice\'s sign-in with her current ' +
          'password — is untouched', JSON.stringify(r.afterDropSignIn));
  t.check(r.afterDropOldPassword.ok === false &&
          r.afterDropOldPassword.code === 24,
          'and her previous password is refused', JSON.stringify(
              r.afterDropOldPassword));
  t.check(Array.isArray(r.afterDropListed) && r.afterDropListed.length === 0 &&
          r.dropAgain.ok === true && r.dropAgain.dropped === 0,
          'the list shows nothing kept, and a second drop answers dropped: 0 ' +
          'rather than ' +
          'refusing',
          JSON.stringify({ listed: r.afterDropListed, again: r.dropAgain }));
  log.debug("Leaving previousPersonVersionsAreKept().");
}

function previousServiceVersionsAreKept(t, r) {
  log.debug("Entering previousServiceVersionsAreKept().");
  t.log.info('=== previous key versions: a service principal ===');
  if (!r.ticketCipherHex) {
    t.check(false, 'the service ticket needed for these assertions was issued');
    log.debug("Leaving previousServiceVersionsAreKept().");
    return;
  }
  const created = independentKeytabRead(Buffer.from(r.keytab, 'base64'));
  const rotated = independentKeytabRead(Buffer.from(r.rotateKeytab || '',
                                                    'base64'));
  const vnos = function (entries) {
    log.debug("Entering vnos().");
    log.debug("Leaving vnos().");
    return entries.map(function (e) { return e.vno; })
      .filter(function (v, i, all) { return all.indexOf(v) === i; }).sort();
  };
  t.check(rotated.length === 10 && JSON.stringify(vnos(rotated)) === '[3,4]' &&
          JSON.stringify(r.rotateKeytabKvnos) === '[4,3]',
          'THE ROTATION\'S KEYTAB CARRIES BOTH kvnos — five enctypes at 4 ' +
          'and five at 3 — read by the independent reader, as MIT\'s ktadd ' +
          'without -k leaves one',
          JSON.stringify({ vnos: vnos(rotated), count: rotated.length,
                           keytabKvnos: r.rotateKeytabKvnos }));
  const sameOld = created.every(function (old) {
    return rotated.some(function (e) {
      return e.vno === 3 && e.enctype === old.enctype && e.key === old.key;
    });
  });
  t.check(sameOld, 'and its kvno-3 entries are the SAME keys the create ' +
                   'handed over, not new ones');
  t.check(Array.isArray(r.rotateRetained) && r.rotateRetained.length === 1 &&
          r.rotateRetained[0].kvno === 3,
          'the rotate reply says which previous version is kept, and until ' +
          'when',
          JSON.stringify(r.rotateRetained));
  t.check(r.svc4.ok === true && r.svc4.kvno === 4,
          'the KDC issues a new ticket for the SPN under the current kvno 4',
          JSON.stringify(r.svc4));
  t.check(r.accept3 && r.accept3.ok === true &&
          /PREVIOUS version/.test(r.accept3.versionDetail),
          'THE ACCEPTOR ACCEPTS THE kvno-3 TICKET under the kept version, ' +
          'and says so',
          JSON.stringify(r.accept3));
  t.check(r.accept4 && r.accept4.ok === true, 'and the kvno-4 ticket under ' +
                                              'the current key',
          JSON.stringify(r.accept4));
  t.check(r.tgs3.ok === true,
          'the KDC\'s TGS-REQ opens the kvno-3 service ticket under the kept ' +
          'version too',
          JSON.stringify(r.tgs3));
  t.check(r.rotate2Kvno === 5 &&
          JSON.stringify(vnos(independentKeytabRead(
              Buffer.from(r.rotate2Keytab || '', 'base64')))) ===
            '[4,5]',
          'a second rotation keeps ONE version: its keytab holds kvno 5 and ' +
          '4, not 3',
          String(r.rotate2Kvno));
  t.check(r.svc5.ok === true && r.svc5.kvno === 5, 'and the KDC issues under ' +
                                                   'kvno 5',
          JSON.stringify(r.svc5));
  t.check(r.accept3After2 && r.accept3After2.ok === false &&
          r.accept3After2.errorCode === 'STS-KRB-0068' &&
          r.accept3After2.versionOk === false,
          'THE COUNT BOUND AT THE ACCEPTOR: the kvno-3 ticket is now refused ' +
          'KRB_AP_ERR_BADKEYVER', JSON.stringify(r.accept3After2));
  t.check(r.tgs3After2.ok === false && r.tgs3After2.code === 44,
          'and at the KDC', JSON.stringify(r.tgs3After2));
  t.check(r.accept4After2 && r.accept4After2.ok === true,
          'while the kvno-4 ticket is still accepted',
          JSON.stringify(r.accept4After2));
  t.check(Array.isArray(r.servicesListed) && r.servicesListed.length === 1 &&
          r.servicesListed[0].kvno === 4 &&
          r.servicesListed[0].etypes.length === 5,
          'the service list shows kvno 4 kept',
          JSON.stringify(r.servicesListed));
  t.check(r.dropService.ok === true && r.dropService.dropped === 1 &&
          JSON.stringify(r.dropService.kvnos) === '[4]',
          'drop-previous-service-keys drops kvno 4',
          JSON.stringify(r.dropService));
  t.check(r.accept4AfterDrop && r.accept4AfterDrop.ok === false &&
          r.accept4AfterDrop.errorCode === 'STS-KRB-0068',
          'AFTER THE DROP THE kvno-4 TICKET IS REFUSED KRB_AP_ERR_BADKEYVER ' +
          'at the acceptor',
          JSON.stringify(r.accept4AfterDrop));
  t.check(r.tgs4AfterDrop && r.tgs4AfterDrop.ok === false &&
          r.tgs4AfterDrop.code === 44,
          'and at the KDC', JSON.stringify(r.tgs4AfterDrop));
  t.check(r.accept5AfterDrop && r.accept5AfterDrop.ok === true,
          'while the current kvno 5 is untouched',
          JSON.stringify(r.accept5AfterDrop));
  t.check(r.dropUnknown === false, 'a drop for an SPN holding no stored key ' +
                                   'is refused');
  t.check(r.auditHasDropRow === true, 'the drops are audited');
  log.debug("Leaving previousServiceVersionsAreKept().");
}

module.exports = {
  name: 'kerberos_person_keys',
  describe: 'a directory person\'s Kerberos keys derived from their own ' +
            'password in product mode, and service principals with random ' +
            'keys and a keytab',
  run: async function (t) {
    log.debug("Entering run().");
    await stringToKeyMatchesRfc3962(t);
    theKeytabRoundTrips(t);
    await developmentIsUnchanged(t);
    const report = inAProductChild(t);
    if (!report || report.crashed) {
      log.debug("Leaving run().");
      return;
    }
    productModeAuthenticatesPeople(t, report);
    productModeRefusesAndUpgrades(t, report);
    keysAreNeverShown(t, report);
    servicePrincipalsWork(t, report);
    previousPersonVersionsAreKept(t, report);
    previousServiceVersionsAreKept(t, report);
    log.debug("Leaving run().");
  }
};
