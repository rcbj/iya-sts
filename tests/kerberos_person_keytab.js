'use strict';
//
// File: kerberos_person_keytab.js
//
// ===========================================================================
// A PERSON'S KEYTAB, DERIVED FROM A PASSWORD IN HAND (#59, 2026-09-22).
//
// `kerberos/krb5_person_keys.ts`'s `personKeytab()` makes an MIT keytab for a
// directory person from a password the caller has — the person's own,
// verified on `/portal/kerberos`, or one an administrator has just SET with
// "Reset password and download keytab" (`reset-person-keytab` on
// `/admin/kerberos/principals` and `/admin-api`). A stored key is never read
// back out: the key is derived again and COMPARED with the one the KDC holds.
//
// What this file holds, and why each part is here rather than over HTTP:
//
//   * **THE KEYTAB SIGNS IN.** Every keytab is read by an INDEPENDENT reader
//     written in this file, and its key — not the password — pre-authenticates
//     a real AS-REQ built here with the vendored codec, and opens the AS-REP.
//     That is `kinit -k` in miniature; the MIT client itself is driven by
//     `tests/vendored/sts_kerberos_keytab.js`.
//   * **PRODUCT MODE, IN A CHILD PROCESS**, because the principal database is
//     built at require time in the process's mode (kerberos_person_keys.js's
//     reason): the keytab from the right password at the current kvno and no
//     other; the wrong password refused (STS-KRB-0132) with nothing handed
//     over; nobody, a disabled account and a realm with no KDC refused before
//     anything is derived; the administrator's reset moving the kvno, making
//     the old password fail and the new one work, NOT forcing a change, and
//     spending an outstanding reset link; a generated password never returned;
//     neither-or-both and a policy-refused password changing nothing; and no
//     key, keytab or password in an audit row or in `personKerberosState()`.
//   * **DEVELOPMENT MODE, IN A SECOND CHILD**: the keytab is the development
//     KDC's key — the password on the principal record, `krb5.userPassword`
//     for every user — whatever password was typed, and it signs in.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'kerberos_person_keytab',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// AN INDEPENDENT KEYTAB READER, from MIT's `kt_file.c` layout rather than from
// `krb5_keytab.ts` — kerberos_person_keys.js's, for its reason.
// ---------------------------------------------------------------------------
function independentKeytabRead(buf) {
  log.debug("Entering independentKeytabRead().");
  const out = [];
  if (buf.length < 2 || buf[0] !== 0x05 || buf[1] !== 0x02) {
    log.debug("Leaving independentKeytabRead(). Not 0x0502.");
    throw new Error('not 0x0502');
  }
  let i = 2;
  const u16 = function () {
    log.debug("Entering u16().");
    const v = buf.readUInt16BE(i);
    i += 2;
    log.debug("Leaving u16().");
    return v;
  };
  const u32 = function () {
    log.debug("Entering u32().");
    const v = buf.readUInt32BE(i);
    i += 4;
    log.debug("Leaving u32().");
    return v;
  };
  const str = function () {
    log.debug("Entering str().");
    const n = u16();
    const s = buf.subarray(i, i + n);
    i += n;
    log.debug("Leaving str().");
    return s;
  };
  while (i < buf.length) {
    const size = buf.readInt32BE(i);
    i += 4;
    if (size < 0) {
      i += -size;
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
    u32();
    let vno = buf[i];
    i += 1;
    const enctype = u16();
    const key = Buffer.from(str());
    if (end - i >= 4) {
      vno = u32();
    }
    i = end;
    out.push({ realm: realm, name: name, type: type, vno: vno,
               enctype: enctype, key: key.toString('hex') });
  }
  log.debug("Leaving independentKeytabRead(). " + out.length + " entries.");
  return out;
}

// ---------------------------------------------------------------------------
// THE CHILD. Serialised with toString() and run with `node -e`, so it is
// self-contained; `KT_MODE` says which half it is.
// ---------------------------------------------------------------------------
/* eslint-disable no-undef */
async function keytabChild() {
  const R = process.env.KT_ROOT;
  const out = { steps: {} };
  const product = process.env.KT_MODE === 'product';
  const keystore = require(R + '/common/keystore');
  keystore.reset();
  keystore.setStore({
    loadKeys: function () { return Promise.resolve([]); },
    saveKeys: function () { return Promise.resolve(); },
    deleteKeys: function () { return Promise.resolve(); }
  });
  await keystore.start();
  const principals = require(R + '/kerberos/krb5_principals.js');
  const kdc = require(R + '/kerberos/krb5_kdc.js');
  const msgs = require(R + '/kerberos/krb5_messages.js');
  const kcrypto = require(R + '/kerberos/krb5_crypto.js');
  const prim = require(R + '/kerberos/krb5_primitives.js');
  const directory = require(R + '/ldap/ldap_server');
  const credentials = require(R + '/common/credentials');
  const personKeys = require(R + '/kerberos/krb5_person_keys');
  const audit = require(R + '/common/audit');
  const actions = require(R + '/admin-core/admin_actions');
  const views = require(R + '/admin-core/admin_views');
  const errorCodes = require(R + '/common/error_codes');
  const realms = require(R + '/common/realms');
  out.productKdc = personKeys.productKdc();
  out.realm = principals.REALM;
  out.kdcEtypes = principals.KDC_ETYPES.slice();

  // An AS exchange whose client key is GIVEN — a password's, or a keytab's.
  async function asWithKey(name, etype, key) {
    const profile = kcrypto.etypeById(etype);
    const now = new Date();
    const cipher = await profile.encrypt(key,
      kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
      msgs.encPaEncTsEnc(now, now.getMilliseconds() * 1000));
    const bytes = msgs.encKdcReq({
      msgType: msgs.MSG_TYPE.AS_REQ,
      padata: [{ type: msgs.PA_TYPE.ENC_TIMESTAMP,
                 value: msgs.encEncryptedData({ etype: etype,
                                                cipher: cipher }) }],
      reqBody: { kdcOptions: [], cname: { type: 1, name: [name] },
                 realm: principals.REALM,
                 sname: { type: 2, name: ['krbtgt', principals.REALM] },
                 till: new Date(Date.now() + 3600000), nonce: 4711,
                 etypes: [etype] }
    });
    const reply = await kdc.handleMessage(bytes);
    if (msgs.identify(reply).applicationNumber ===
        msgs.APPLICATION.KRB_ERROR) {
      const e = msgs.readKrbError(reply);
      return { ok: false, code: e.errorCode, eText: e.eText };
    }
    const rep = msgs.readKdcRep(reply);
    try {
      const enc = msgs.readEncKdcRepPart(await profile.decrypt(key,
        kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
      return { ok: enc.nonce === 4711, kvno: rep.encPart.kvno };
    } catch (e) {
      return { ok: false, code: -1, eText: 'the AS-REP did not open under ' +
                                            'the key: ' + e.message };
    }
  }

  async function asWithPassword(name, password) {
    const key = await kcrypto.etypeById(18).stringToKey(password,
      prim.utf8(principals.REALM + name), null);
    return asWithKey(name, 18, key);
  }

  // Sign in with every key of a keytab that is for `name`, and answer the
  // results by etype. The KEYTAB'S KEY is what pre-authenticates — no
  // password is involved.
  async function signInWithKeytab(name, b64) {
    const keytab = require(R + '/kerberos/krb5_keytab');
    const entries = keytab.readKeytab(Buffer.from(String(b64 || ''),
                                                  'base64'));
    const results = {};
    for (const one of entries) {
      results[one.etype] = await asWithKey(name, one.etype,
                                           Uint8Array.from(one.key));
    }
    return results;
  }

  const brief = function (r) {
    return { ok: !!(r && r.ok), code: r && r.code,
             codeOf: r ? errorCodes.codeOf(r) || '' : '',
             kvno: r && r.kvno, source: r && r.source,
             keytab: (r && r.keytab) || '', etypes: r && r.etypes,
             keytabKvnos: r && r.keytabKvnos, generated: r && r.generated,
             hasPassword: !!r && Object.prototype.hasOwnProperty.call(r,
                                                                'password'),
             passwordSet: r && r.passwordSet,
             errors: (r && r.errors) || null };
  };
  const reset = function (body) {
    return actions.kerberosPrincipalsAction(
      Object.assign({ action: 'reset-person-keytab' }, body),
      { actor: 'kt-admin', via: 'api' });
  };
  const kvnoOf = function (name) {
    const state = personKeys.personKerberosState(name);
    return state.keys ? state.keys.kvno : null;
  };

  const PW = 'Keytab-Owner-Passw0rd!-1';
  directory.createUser('ktowner', { invent: false });
  out.steps.set = credentials.setPassword('ktowner', PW).ok;
  await personKeys.idle();
  out.kvnoStart = kvnoOf('ktowner');

  // --- A. the person's own keytab, from their own password ---
  const own = await personKeys.personKeytab('ktowner', PW,
                                            { actor: 'ktowner',
                                              via: 'portal' });
  out.own = brief(own);
  out.ownSignIn = own.ok ? await signInWithKeytab('ktowner', own.keytab) : {};
  out.kvnoAfterOwn = kvnoOf('ktowner');
  out.passwordStillWorks = await asWithPassword('ktowner', PW);

  // --- B. the wrong password: refused, nothing handed over ---
  out.wrong = brief(await personKeys.personKeytab('ktowner',
                                                  'Not-The-Passw0rd!-9',
                                                  { via: 'portal' }));
  out.empty = brief(await personKeys.personKeytab('ktowner', '',
                                                  { via: 'portal' }));

  // --- C. refused before anything is derived ---
  out.nobody = brief(await personKeys.personKeytab('ktnobody', PW, {}));
  out.badName = brief(await personKeys.personKeytab('a/b', PW, {}));
  directory.createUser('ktlocked', { invent: false });
  credentials.setPassword('ktlocked', PW);
  await personKeys.idle();
  out.disableOk = credentials.setAccountDisabled('ktlocked', true).ok;
  out.disabled = brief(await personKeys.personKeytab('ktlocked', PW, {}));
  out.disabledReset = brief(await reset({ username: 'ktlocked',
                                          password: 'Some-New-Passw0rd!-4' }));
  const noKdcRealm = realms.create({ id: 'kt-nokdc', name: 'kt-nokdc',
                                     description: 'kerberos_person_keytab' });
  out.noKdcCreated = noKdcRealm.ok;
  if (noKdcRealm.ok) {
    out.noKdc = await realms.run(noKdcRealm.realm, async function () {
      return brief(await personKeys.personKeytab('ktowner', PW, {}));
    });
    out.noKdcState = realms.run(noKdcRealm.realm, function () {
      return personKeys.personKerberosState('ktowner');
    });
    realms.remove('kt-nokdc');
  }

  // --- D. the administrator's reset, with a typed password ---
  const PW2 = 'Admin-Chosen-Passw0rd!-2';
  credentials.setPasswordResetRequired('ktowner', true);
  const link = credentials.issuePasswordReset('ktowner');
  out.linkIssued = link.ok;
  const typed = await reset({ username: 'ktowner', password: PW2 });
  out.typed = brief(typed);
  out.typedSignIn = typed.ok ? await signInWithKeytab('ktowner',
                                                      typed.keytab) : {};
  out.kvnoAfterTyped = kvnoOf('ktowner');
  out.oldPasswordAfterTyped = await asWithPassword('ktowner', PW);
  out.newPasswordAfterTyped = await asWithPassword('ktowner', PW2);
  out.forcedAfterTyped = credentials.passwordResetRequired('ktowner');
  out.linkAfterTyped = link.ok
    ? credentials.checkPasswordReset('ktowner', link.token).ok : null;
  // THE FIRST KEYTAB, after the reset: its kvno is no longer current.
  out.ownAfterReset = own.ok ? await signInWithKeytab('ktowner', own.keytab)
                             : {};
  // And the person's own keytab from the NEW password, at the new kvno.
  out.ownAgain = brief(await personKeys.personKeytab('ktowner', PW2,
                                                     { via: 'portal' }));

  // --- E. a generated password, never returned ---
  const random = await reset({ username: 'ktowner', random: true });
  out.random = brief(random);
  out.randomSignIn = random.ok ? await signInWithKeytab('ktowner',
                                                        random.keytab) : {};
  out.kvnoAfterRandom = kvnoOf('ktowner');
  out.typedPasswordAfterRandom = await asWithPassword('ktowner', PW2);
  out.randomText = JSON.stringify(random);

  // --- F. refusals that change nothing ---
  const kvnoBeforeRefusals = kvnoOf('ktowner');
  const storedHash = function () {
    return realms.run(realms.DEFAULT_REALM, function () {
      const entry = directory.existingUserEntry('ktowner');
      return JSON.stringify(entry ? entry.attributes.userpassword : null);
    });
  };
  const hashBefore = storedHash();
  out.neither = brief(await reset({ username: 'ktowner' }));
  out.both = brief(await reset({ username: 'ktowner', password: PW2,
                                 random: true }));
  out.weak = brief(await reset({ username: 'ktowner', password: 'abc' }));
  // A TYPED PASSWORD ON THE PWNED PASSWORDS LIST (#237's side finding): the
  // range API is stubbed to list one made-up password, the screen is on,
  // and the reset must refuse it with the breach code and change nothing.
  if (product) {
    const config = require(R + '/common/config');
    const stsCrypto = require(R + '/common/crypto');
    const fedHttp = require(R + '/federation/federation_http');
    const BREACHED = 'Keytab-Breached-Passw0rd!-7';
    const bad = stsCrypto.pwnedPasswordDigest(BREACHED);
    const original = fedHttp.fetchPublished;
    fedHttp.fetchPublished = function (url) {
      const lines = ['0000000000000000000000000000000000A:3'];
      if (String(url).slice(-5) === bad.slice(0, 5)) {
        lines.push(bad.slice(5) + ':42');
      }
      return Promise.resolve({ ok: true, status: 200,
                               body: Buffer.from(lines.join('\r\n')) });
    };
    config.setOverride('risk.breachCheck', 'on');
    try {
      out.breached = brief(await reset({ username: 'ktowner',
                                         password: BREACHED }));
    } finally {
      fedHttp.fetchPublished = original;
      config.clearOverride('risk.breachCheck');
    }
  }
  out.nobodyReset = brief(await reset({ username: 'ktnobody',
                                        password: PW2 }));
  await personKeys.idle();
  out.kvnoUnchangedByRefusals = kvnoOf('ktowner') === kvnoBeforeRefusals;
  out.hashUnchangedByRefusals = hashBefore !== 'null' &&
    storedHash() === hashBefore;

  // --- G. nothing secret where it must not be ---
  const auditText = JSON.stringify(audit.list());
  const keytabs = [own.keytab, typed.keytab, random.keytab].filter(Boolean);
  out.auditHasKeytab = keytabs.some(function (k) {
    return auditText.indexOf(k.slice(0, 40)) >= 0;
  });
  out.auditHasPassword = [PW, PW2].some(function (p) {
    return auditText.indexOf(p) >= 0;
  });
  out.auditHasKeytabRow = /krb5\.keytab\.person/.test(auditText);
  out.auditHasResetRow = /admin\.password\.reset-keytab/.test(auditText);
  const stateText = JSON.stringify(personKeys.personKerberosState('ktowner'));
  out.stateHasSeal = stateText.indexOf('$aesgcm$') >= 0 ||
                     /"keys":\{"1[78]"/.test(stateText);
  out.state = personKeys.personKerberosState('ktowner');
  out.viewKerberos = (views.userDetailJson({ query: {} }, 'ktowner') ||
                      { json: {} }).json.kerberos || null;
  out.actions = actions.KERBEROS_PRINCIPAL_ACTIONS;
  out.unknownAction = actions.kerberosPrincipalsAction({ action: 'nope' },
                                                       {}).errors;

  // --- H. development: a configured fixture, keyed from its record ---
  if (!product) {
    const fixture = principals.find(['alice']);
    out.fixturePassword = fixture ? fixture.password : null;
    const alice = await personKeys.personKeytab('alice', 'whatever-typed',
                                                { via: 'portal' });
    out.alice = brief(alice);
    out.aliceSignIn = alice.ok ? await signInWithKeytab('alice',
                                                        alice.keytab) : {};
    out.userPassword = principals.USER_PASSWORD;
    out.expectedOwnKey = Buffer.from(await kcrypto.etypeById(18).stringToKey(
      principals.USER_PASSWORD, prim.utf8(principals.REALM + 'ktowner'),
      null)).toString('hex');
  }
  return out;
}
/* eslint-enable no-undef */

function inAChild(t, mode) {
  log.debug("Entering inAChild(). mode=" + mode);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krb5-keytab-'));
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
  const env = Object.assign(clean, {
    LOG_LEVEL: 'fatal', KT_ROOT: ROOT, KT_OUT: outFile, KT_MODE: mode
  });
  if (mode === 'product') {
    Object.assign(env, {
      STS_MODE: 'product',
      KRB5_KRBTGT_PASSWORD: 'not-the-published-krbtgt-secret',
      STS_KEYS_SOURCE: 'persisted', STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: kekFile
    });
  }
  const script = 'delete process.env.CONFIG_FILE;' +
    '(' + keytabChild.toString() + ')().then(function (r) ' +
    '{require("fs").writeFileSync(process.env.KT_OUT, JSON.stringify(r)); ' +
    'process.exit(0); }).catch(function (e) { ' +
    'require("fs").writeFileSync(process.env.KT_OUT, JSON.stringify({ ' +
    'crashed: e.stack || e.message })); process.exit(0); });';
  const run = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: env, encoding: 'utf8', timeout: 180000
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Said below.
    report = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // A temporary directory left behind is not the test's subject.
  }
  t.check(!!report && !report.crashed, 'the ' + mode + ' child ran to the ' +
          'end', report && report.crashed
            ? report.crashed : String(run.stderr || '').slice(-2000));
  log.debug("Leaving inAChild().");
  return report;
}

function everyEtypeSignedIn(results) {
  log.debug("Entering everyEtypeSignedIn().");
  const keys = Object.keys(results || {});
  log.debug("Leaving everyEtypeSignedIn().");
  return keys.length > 0 && keys.every(function (k) {
    return results[k].ok === true;
  });
}

function productAssertions(t, r) {
  log.debug("Entering productAssertions().");
  t.log.info('=== product: the keytab from a password in hand ===');
  t.check(r.productKdc === true, 'the child is a product KDC');
  const own = r.own.keytab
    ? independentKeytabRead(Buffer.from(r.own.keytab, 'base64')) : [];
  t.check(r.own.ok && r.own.source === 'password' &&
          r.own.kvno === r.kvnoStart,
          'the person\'s own keytab is made from their password, at their ' +
          'current kvno', JSON.stringify(r.own).slice(0, 400));
  t.check(own.length === r.kdcEtypes.length && own.every(function (e) {
    return e.realm === r.realm && e.name.join('/') === 'ktowner' &&
           e.type === 1 && e.vno === r.kvnoStart;
  }) && JSON.stringify(own.map(function (e) { return e.enctype; })) ===
        JSON.stringify(r.kdcEtypes),
          'THE INDEPENDENT READER finds one entry per enctype the KDC offers, ' +
          'all for ktowner@' + r.realm + ' at kvno ' + r.kvnoStart +
          ' and no other kvno', JSON.stringify(own.map(function (e) {
            return { vno: e.vno, etype: e.enctype };
          })));
  t.check(everyEtypeSignedIn(r.ownSignIn),
          'EVERY KEY IN IT PRE-AUTHENTICATES AN AS-REQ and opens the AS-REP — ' +
          'the keytab signs in with no password', JSON.stringify(r.ownSignIn));
  t.check(r.kvnoAfterOwn === r.kvnoStart && r.passwordStillWorks.ok,
          'and nothing about the account changed: same kvno, the password ' +
          'still signs in', JSON.stringify(r.passwordStillWorks));
  t.check(!r.wrong.ok && r.wrong.codeOf === 'STS-KRB-0132' &&
          !r.wrong.keytab,
          'a WRONG password is refused STS-KRB-0132 and no keytab is handed ' +
          'over', JSON.stringify(r.wrong));
  t.check(!r.empty.ok && r.empty.codeOf === 'STS-KRB-0132',
          'and so is no password at all', JSON.stringify(r.empty));
  t.check(!r.nobody.ok && r.nobody.codeOf === 'STS-KRB-0130' &&
          !r.badName.ok && r.badName.codeOf === 'STS-KRB-0130',
          'nobody by that name, and a name that is not a user principal, ' +
          'are refused STS-KRB-0130',
          JSON.stringify([r.nobody, r.badName]));
  t.check(r.disableOk && !r.disabled.ok &&
          r.disabled.codeOf === 'STS-KRB-0134',
          'a DISABLED account is refused STS-KRB-0134',
          JSON.stringify(r.disabled));
  t.check(!r.disabledReset.ok && r.disabledReset.codeOf === 'STS-KRB-0134' &&
          !r.disabledReset.passwordSet,
          'and the administrator\'s reset refuses it BEFORE setting a ' +
          'password', JSON.stringify(r.disabledReset));
  t.check(r.noKdcCreated && r.noKdc && !r.noKdc.ok &&
          r.noKdc.codeOf === 'STS-KRB-0128' && r.noKdcState &&
          r.noKdcState.kdc === false,
          'a trust realm with no KDC refuses STS-KRB-0128 and says it has ' +
          'no KDC', JSON.stringify([r.noKdc, r.noKdcState]));

  t.log.info('=== product: the administrator\'s reset ===');
  const typed = r.typed.keytab
    ? independentKeytabRead(Buffer.from(r.typed.keytab, 'base64')) : [];
  t.check(r.typed.ok && r.typed.passwordSet === true &&
          r.typed.generated === false && r.typed.kvno === r.kvnoStart + 1 &&
          r.kvnoAfterTyped === r.kvnoStart + 1,
          'a reset with a typed password SETS it and moves the kvno up by ' +
          'one', JSON.stringify(r.typed).slice(0, 400));
  t.check(typed.length > 0 && typed.every(function (e) {
    return e.vno === r.kvnoStart + 1;
  }) && JSON.stringify(r.typed.keytabKvnos) ===
        JSON.stringify([r.kvnoStart + 1]),
          'its keytab carries the NEW kvno only — not the version it ' +
          'retired', JSON.stringify(r.typed.keytabKvnos));
  t.check(everyEtypeSignedIn(r.typedSignIn), 'and it signs in',
          JSON.stringify(r.typedSignIn));
  t.check(!r.oldPasswordAfterTyped.ok &&
          r.oldPasswordAfterTyped.code === 24 &&
          r.newPasswordAfterTyped.ok,
          'the OLD password is refused KDC_ERR_PREAUTH_FAILED and the new ' +
          'one signs in', JSON.stringify([r.oldPasswordAfterTyped,
                                          r.newPasswordAfterTyped]));
  t.check(r.forcedAfterTyped === false,
          'the person is NOT made to change it at their next sign-in (a ' +
          'pending forced change was cleared) — that would end the keytab');
  t.check(r.linkIssued && r.linkAfterTyped === false,
          'an outstanding reset link is spent by the reset');
  t.check(Object.keys(r.ownAfterReset).length > 0 &&
          Object.keys(r.ownAfterReset).every(function (k) {
            return r.ownAfterReset[k].ok === false;
          }),
          'the keytab made from the OLD password no longer signs in',
          JSON.stringify(r.ownAfterReset));
  t.check(r.ownAgain.ok && r.ownAgain.kvno === r.kvnoStart + 1,
          'and the person\'s own keytab from the new password is at the new ' +
          'kvno', JSON.stringify(r.ownAgain).slice(0, 300));
  t.check(r.random.ok && r.random.generated === true &&
          r.random.hasPassword === false &&
          r.kvnoAfterRandom === r.kvnoStart + 2 &&
          everyEtypeSignedIn(r.randomSignIn),
          'a GENERATED password: the keytab signs in, the kvno moved again, ' +
          'and no `password` member is in the answer',
          JSON.stringify(r.random).slice(0, 400));
  t.check(!r.typedPasswordAfterRandom.ok,
          'and the password before it is refused',
          JSON.stringify(r.typedPasswordAfterRandom));
  t.check(!r.neither.ok && r.neither.codeOf === 'STS-ADMIN-0802' &&
          !r.both.ok && r.both.codeOf === 'STS-ADMIN-0802',
          'neither a password nor random, and both, are refused ' +
          'STS-ADMIN-0802', JSON.stringify([r.neither, r.both]));
  t.check(!r.weak.ok && !!r.weak.codeOf && !r.weak.keytab,
          'a password the policy refuses is refused, with its own code',
          JSON.stringify(r.weak));
  t.check(!!r.breached && !r.breached.ok &&
          r.breached.codeOf === 'STS-AUTHN-0222' && !r.breached.keytab,
          'a typed password on the Pwned Passwords list is refused with the ' +
          'breach code (STS-AUTHN-0222) — the screen\'s verdict reaches ' +
          'setPassword() (#237 side finding)', JSON.stringify(r.breached));
  t.check(!r.nobodyReset.ok && r.nobodyReset.codeOf === 'STS-KRB-0130',
          'a reset for nobody is refused by the register',
          JSON.stringify(r.nobodyReset));
  t.check(r.kvnoUnchangedByRefusals && r.hashUnchangedByRefusals,
          'and NONE of those refusals changed the password or the kvno');

  t.log.info('=== product: nothing secret where it must not be ===');
  t.check(r.auditHasKeytabRow && r.auditHasResetRow,
          'the keytabs and the reset are audited');
  t.check(!r.auditHasKeytab && !r.auditHasPassword,
          'and no audit row carries a keytab or a password');
  t.check(!r.stateHasSeal && r.state.kdc === true &&
          r.state.principal === 'ktowner@' + r.realm && !!r.state.keys &&
          r.state.keys.kvno === r.kvnoStart + 2,
          'personKerberosState() is the public half: principal and kvno, no ' +
          'key', JSON.stringify(r.state).slice(0, 400));
  t.check(!!r.viewKerberos && r.viewKerberos.principal === r.state.principal,
          'and the user page\'s JSON carries it as `kerberos`');
  t.check(r.actions.indexOf('reset-person-keytab') >= 0 &&
          /reset-person-keytab/.test(JSON.stringify(r.unknownAction)),
          'the action is listed, and named in the unknown-action sentence ' +
          'the parity jobs read');
  log.debug("Leaving productAssertions().");
}

function developmentAssertions(t, r) {
  log.debug("Entering developmentAssertions().");
  t.log.info('=== development: the development KDC\'s own key ===');
  t.check(r.productKdc === false, 'the child is a development KDC');
  const own = r.own.keytab
    ? independentKeytabRead(Buffer.from(r.own.keytab, 'base64')) : [];
  const aes256 = own.filter(function (e) { return e.enctype === 18; })[0];
  t.check(r.own.ok && r.own.source === 'development' && !!aes256 &&
          aes256.key === r.expectedOwnKey,
          'the keytab holds the key krb5.userPassword gives — what this KDC ' +
          'checks — and says `source: development`',
          JSON.stringify(r.own).slice(0, 300));
  t.check(everyEtypeSignedIn(r.ownSignIn), 'and it signs in',
          JSON.stringify(r.ownSignIn));
  t.check(r.alice.ok && r.alice.source === 'development' &&
          everyEtypeSignedIn(r.aliceSignIn) &&
          r.fixturePassword === r.userPassword,
          'a configured fixture (alice) gets the key of the password its ' +
          'principal record holds, whatever was typed, and it signs in',
          JSON.stringify(r.aliceSignIn));
  t.check(r.typed.ok && everyEtypeSignedIn(r.typedSignIn),
          'the administrator\'s reset answers a working keytab here too',
          JSON.stringify(r.typed).slice(0, 300));
  t.check(!r.nobody.ok && r.nobody.codeOf === 'STS-KRB-0130' &&
          !r.disabled.ok && r.disabled.codeOf === 'STS-KRB-0134',
          'nobody and a disabled account are refused as in product',
          JSON.stringify([r.nobody, r.disabled]));
  t.check(!r.auditHasKeytab && !r.auditHasPassword,
          'no audit row carries a keytab or a password');
  log.debug("Leaving developmentAssertions().");
}

module.exports = {
  name: 'kerberos_person_keytab',
  describe: 'a directory person\'s keytab, derived from a password in hand — ' +
            'their own on the portal, or one an administrator sets — read ' +
            'independently and used to sign in',
  run: async function (t) {
    log.debug("Entering run().");
    const product = inAChild(t, 'product');
    if (product && !product.crashed) {
      productAssertions(t, product);
    }
    const development = inAChild(t, 'development');
    if (development && !development.crashed) {
      developmentAssertions(t, development);
    }
    log.debug("Leaving run().");
  }
};
