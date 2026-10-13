// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kerberos_acceptor_key.js
//
// ===========================================================================
// THE ACCEPTOR'S OWN KEY IN A BASE INSTALLATION (2026-10-12).
//
// Product mode refuses the acceptor's password while it is empty or the one
// printed in this repository (STS-KRB-0060, STS-KRB-0061), which left a
// `docker compose up` with an SPNEGO sign-in that could not work. Product now
// keys the acceptor's SPN at random, sealed on its application entry, once —
// `kerberos/krb5_person_keys.ts`, `ensureAcceptorKeys()` and
// `acceptorKeyMissing()`; `kerberos/CLAUDE.md` argues it.
//
// WHY IN PROCESS: the principal database is built at require time in the mode
// the process starts in, and the claims are about what is on an entry and
// what a SECOND start does. Each case is a CHILD node process, the
// arrangement `kerberos_person_keys.js` has:
//
//   A. product, `KRB5_SERVICE_PRINCIPAL=HTTP/localhost`, the published
//      password: the startup pass keys the SPN (sealed, marked, no keytab in
//      any audit row), the KDC issues a ticket for it in a real AS exchange
//      and the acceptor accepts a real AP-REQ; a second pass makes nothing;
//      and a trust realm that turns Kerberos on afterwards is keyed when its
//      acceptor first asks.
//   B. product with a password of the operator's own: nothing is made, and a
//      key marked as the acceptor's, planted for the SPN, is not read — the
//      password builds the account — while an unmarked one still is.
//   C. development: nothing is made and the account is built from the
//      published password, as it always was.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'kerberos_acceptor_key',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/* eslint-disable no-undef */
// THE CHILD. Its source is handed to `node -e`, so it requires nothing from
// this file's scope; `AK_CASE` says which case it is.
async function acceptorChild() {
  const R = process.env.AK_ROOT;
  const which = process.env.AK_CASE;
  const out = { case: which };
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
  const service = require(R + '/kerberos/krb5_service.js');
  const msgs = require(R + '/kerberos/krb5_messages.js');
  const kcrypto = require(R + '/kerberos/krb5_crypto.js');
  const prim = require(R + '/kerberos/krb5_primitives.js');
  const gss = require(R + '/kerberos/krb5_gss.js');
  const directory = require(R + '/ldap/ldap_server');
  const credentials = require(R + '/common/credentials');
  const personKeys = require(R + '/kerberos/krb5_person_keys');
  const audit = require(R + '/common/audit');
  const realms = require(R + '/common/realms');
  const store = personKeys.currentDirectory();
  const spn = String(principals.acceptorAccount().spn);
  out.spn = spn;
  out.before = principals.acceptorAccount();

  function entry(identifier) {
    const got = store ? store.readService(identifier) : null;
    if (!got) {
      return null;
    }
    let info = null;
    try {
      info = JSON.parse(String(got.info || 'null'));
    } catch (e) {
      info = { unreadable: e.message };
    }
    return { keys: String(got.keys || ''), info: info };
  }

  async function asReq(name, password, sname) {
    const etype = 18;
    const profile = kcrypto.etypeById(etype);
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
                 value: msgs.encEncryptedData({ etype: etype,
                                                cipher: cipher }) }],
      reqBody: { kdcOptions: [], cname: { type: 1, name: [name] },
                 realm: principals.REALM, sname: { type: 3, name: sname },
                 till: new Date(Date.now() + 3600000), nonce: 4242,
                 etypes: [etype] }
    });
    const reply = await kdc.handleMessage(bytes);
    if (msgs.identify(reply).applicationNumber ===
        msgs.APPLICATION.KRB_ERROR) {
      const e = msgs.readKrbError(reply);
      return { ok: false, code: e.errorCode, eText: e.eText };
    }
    const rep = msgs.readKdcRep(reply);
    const enc = msgs.readEncKdcRepPart(await profile.decrypt(key,
      kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
    return { ok: true, rep: rep, enc: enc };
  }

  async function apReqFor(issued, name) {
    const key = issued.enc.key;
    const profile = kcrypto.etypeById(key.etype);
    const auth = msgs.encAuthenticator({ crealm: principals.REALM,
                                         cname: { type: 1, name: [name] },
                                         cusec: 31337, ctime: new Date() });
    const apReq = msgs.encApReq({ apOptions: [], ticket: issued.rep.ticket,
      authenticator: { etype: key.etype,
        cipher: await profile.encrypt(key.key, kcrypto.KEY_USAGE.AP_REQ_AUTH,
                                      auth) } });
    const answer = await service.acceptRaw(
      gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq),
      { record: false });
    return { ok: answer.ok,
             failed: (answer.checks || []).filter(function (c) {
               return !c.ok;
             }).map(function (c) { return c.name + ': ' + c.detail; }) };
  }

  // Whether a ticket's enc-part opens under the key the CONFIGURED password
  // derives — the account `krb5.servicePassword` builds.
  async function opensUnderPassword(ticket, password) {
    const profile = kcrypto.etypeById(ticket.encPart.etype);
    const parts = spn.split('/');
    const key = await profile.stringToKey(password, prim.utf8(
      principals.userSalt(principals.REALM, parts.slice(0, -1).join('') +
                          parts[parts.length - 1].split('.')[0])), null);
    try {
      await profile.decrypt(key, kcrypto.KEY_USAGE.KDC_REP_TICKET,
                            ticket.encPart.cipher);
      return true;
    } catch (e) {
      return false;
    }
  }

  const identifier = spn + '@' + principals.REALM;
  out.made = await personKeys.ensureAcceptorKeys();
  out.entry = entry(identifier);
  out.account = principals.serviceAccount();
  out.record = (function () {
    const r = principals.find(spn.split('/'));
    return r ? { directoryKeys: !!r.directoryKeys,
                 password: r.password === null ? null : 'set' } : null;
  })();

  if (which === 'product-default' || which === 'product-own') {
    const PW = 'Acceptor-Key-Test-Passw0rd#';
    out.personMade = directory.createUser('akalice', { invent: false }).ok;
    out.passwordSet = credentials.setPassword('akalice', PW).ok;
    await personKeys.idle();
    const ticket = await asReq('akalice', PW, spn.split('/'));
    out.ticket = { ok: ticket.ok, code: ticket.code, eText: ticket.eText,
                   kvno: ticket.ok ? ticket.rep.ticket.encPart.kvno : null };
    if (ticket.ok) {
      out.accepted = await apReqFor(ticket, 'akalice');
      out.opensUnderPublished = await opensUnderPassword(
        ticket.rep.ticket, 'service-account-password');
      out.opensUnderOwn = which === 'product-own'
        ? await opensUnderPassword(ticket.rep.ticket,
                                   process.env.KRB5_SERVICE_PASSWORD)
        : null;
    }
  }

  if (which === 'product-default') {
    // THE SECOND START: the store already holds the key.
    out.madeAgain = await personKeys.ensureAcceptorKeys();
    out.entryAgain = entry(identifier);
    const auditText = JSON.stringify(audit.list());
    out.auditHasKeytab = /"keytab"/.test(auditText) ||
                         auditText.indexOf('"BQI') >= 0;
    out.auditCreated = audit.list().filter(function (row) {
      return row.action === 'admin.krb5.service.created';
    }).map(function (row) {
      return { target: row.target, via: (row.detail || {}).via };
    });
    // A TRUST REALM THAT TURNS KERBEROS ON AFTER THE START: nothing ran at
    // startup for it, and its acceptor is keyed when it first asks.
    const made = realms.create({ id: 'ak-later', name: 'ak-later',
                                 description: 'kerberos_acceptor_key',
                                 overrides: { 'krb5.realm': 'LATER.TEST',
                                              'krb5.enabled': 'true' } });
    out.laterCreated = made.ok;
    if (made.ok) {
      realms.run(made.realm, function () {
        out.laterBefore = entry(spn + '@LATER.TEST');
        out.laterAccount = principals.serviceAccount();
        out.laterEntry = entry(spn + '@LATER.TEST');
      });
    }
  }

  if (which === 'product-own') {
    // AN UNMARKED KEY an operator created still wins over the password, as
    // it always did...
    const created = personKeys.createServicePrincipal(spn);
    out.operatorCreated = created.ok;
    out.operatorKeyRead = !!personKeys.serviceKeys(spn);
    // ...and the SAME key marked as the acceptor's generated one does not.
    const got = store.readService(identifier);
    const info = JSON.parse(String(got.info));
    info.generated = 'acceptor';
    out.marked = store.writeService(identifier, got.keys,
                                    JSON.stringify(info));
    out.markedKeyRead = !!personKeys.serviceKeys(spn);
    const r = principals.find(spn.split('/'));
    out.recordAfterMark = r ? { directoryKeys: !!r.directoryKeys } : null;
  }
  return out;
}
/* eslint-enable no-undef */

function inAChild(t, which, env) {
  log.debug("Entering inAChild(). " + which);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krb5-acceptor-key-'));
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
    '(' + acceptorChild.toString() + ')().then(function (r) ' +
    '{require("fs").writeFileSync(process.env.AK_OUT, JSON.stringify(r)); ' +
    'process.exit(0); }).catch(function (e) { ' +
    'require("fs").writeFileSync(process.env.AK_OUT, JSON.stringify({ ' +
    'crashed: e.stack || e.message })); process.exit(0); });';
  const run = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, {
      LOG_LEVEL: 'fatal', AK_ROOT: ROOT, AK_OUT: outFile, AK_CASE: which,
      STS_KEYS_SOURCE: 'persisted', STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: kekFile
    }, env),
    encoding: 'utf8', timeout: 180000
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one; the check below says so.
    report = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // Best effort: a temporary directory left behind is litter, not a failure.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  t.check(report !== null && !report.crashed,
          'the ' + which + ' child ran to the end',
          'exit ' + run.status + ' ' + (report && report.crashed) + ' ' +
          String(run.stderr || '').slice(0, 800));
  log.debug("Leaving inAChild().");
  return report || {};
}

function productKeysTheAcceptor(t) {
  log.debug("Entering productKeysTheAcceptor().");
  t.log.info('=== A. product, the published password: a random key ===');
  const r = inAChild(t, 'product-default', {
    STS_MODE: 'product', KRB5_SERVICE_PRINCIPAL: 'HTTP/localhost',
    KRB5_KRBTGT_PASSWORD: 'not-the-published-krbtgt-secret'
  });
  t.check(r.spn === 'HTTP/localhost' && r.before &&
          r.before.configured === false && r.before.passwordRefused === true,
          'the configured account is refused for its password alone',
          JSON.stringify(r.before));
  const made = (r.made || [])[0] || {};
  t.check(made.ok === true && made.made === true &&
          made.spn === 'HTTP/localhost' && made.kvno === 3,
          'THE STARTUP PASS KEYS THE ACCEPTOR\'S SPN at krb5.kvno',
          JSON.stringify(r.made));
  t.check(!!r.entry && r.entry.keys.indexOf('$aesgcm$') === 0 &&
          r.entry.info && r.entry.info.generated === 'acceptor' &&
          r.entry.info.sealed === true,
          'the key is sealed on the application entry and marked as the ' +
          'acceptor\'s', JSON.stringify(r.entry && r.entry.info));
  t.check(r.account && r.account.available === true &&
          r.account.storedKey === true && r.account.reason === '',
          'the acceptor\'s account is available under the stored key',
          JSON.stringify(r.account));
  t.check(r.record && r.record.directoryKeys === true &&
          r.record.password === null,
          'the KDC\'s record for the SPN is the stored key, with no password',
          JSON.stringify(r.record));
  t.check(r.ticket && r.ticket.ok === true && r.ticket.kvno === 3,
          'the KDC issues a ticket for HTTP/localhost in a real AS exchange',
          JSON.stringify(r.ticket));
  t.check(r.accepted && r.accepted.ok === true,
          'THE ACCEPTOR ACCEPTS A REAL AP-REQ FOR IT',
          JSON.stringify(r.accepted));
  t.check(r.opensUnderPublished === false,
          'and the ticket does not open under the published password\'s key');
  const again = (r.madeAgain || [])[0] || {};
  t.check(again.ok === true && again.made === false &&
          again.existing === true && !!r.entryAgain &&
          r.entryAgain.keys === r.entry.keys,
          'a second start makes nothing and replaces nothing',
          JSON.stringify(r.madeAgain));
  t.check(r.auditHasKeytab === false,
          'no audit row carries a keytab');
  t.check((r.auditCreated || []).some(function (row) {
    return row.target === 'HTTP/localhost@EXAMPLE.COM' &&
           row.via === 'startup';
  }), 'the creation is audited, through the startup pass',
          JSON.stringify(r.auditCreated));
  t.check(r.laterCreated === true && r.laterBefore === null &&
          r.laterAccount && r.laterAccount.available === true &&
          r.laterAccount.storedKey === true && !!r.laterEntry &&
          r.laterEntry.info.generated === 'acceptor',
          'A REALM THAT TURNS KERBEROS ON LATER is keyed when its acceptor ' +
          'first asks', JSON.stringify({ account: r.laterAccount,
                                         entry: r.laterEntry &&
                                                r.laterEntry.info }));
  log.debug("Leaving productKeysTheAcceptor().");
}

function anOperatorsPasswordWins(t) {
  log.debug("Entering anOperatorsPasswordWins().");
  t.log.info('=== B. product, a password of the operator\'s own ===');
  const OWN = 'an-operators-own-Passw0rd!';
  const r = inAChild(t, 'product-own', {
    STS_MODE: 'product', KRB5_SERVICE_PRINCIPAL: 'HTTP/localhost',
    KRB5_SERVICE_PASSWORD: OWN,
    KRB5_KRBTGT_PASSWORD: 'not-the-published-krbtgt-secret'
  });
  const made = (r.made || [])[0] || {};
  t.check(r.before && r.before.configured === true &&
          r.before.passwordRefused === false && made.made === false &&
          r.entry === null,
          'nothing is made: the password builds the account',
          JSON.stringify({ before: r.before, made: r.made }));
  t.check(r.account && r.account.available === true &&
          r.account.storedKey === false,
          'the acceptor\'s account is the configured one',
          JSON.stringify(r.account));
  t.check(r.ticket && r.ticket.ok === true && r.opensUnderOwn === true &&
          r.accepted && r.accepted.ok === true,
          'the ticket is sealed under the operator\'s password and accepted',
          JSON.stringify({ ticket: r.ticket, accepted: r.accepted }));
  t.check(r.operatorCreated === true && r.operatorKeyRead === true,
          'a key an operator created still wins over the password');
  t.check(r.marked === true && r.markedKeyRead === false &&
          r.recordAfterMark && r.recordAfterMark.directoryKeys === false,
          'A KEY MARKED AS THE ACCEPTOR\'S IS NOT READ while the password ' +
          'builds the account', JSON.stringify({ marked: r.marked,
                                                 read: r.markedKeyRead,
                                                 record: r.recordAfterMark }));
  log.debug("Leaving anOperatorsPasswordWins().");
}

function developmentIsUnchanged(t) {
  log.debug("Entering developmentIsUnchanged().");
  t.log.info('=== C. development: nothing is made ===');
  const r = inAChild(t, 'development', {});
  const made = (r.made || [])[0] || {};
  t.check(r.spn === 'HTTP/web.example.com' && made.made === false &&
          r.entry === null,
          'development makes no key for the acceptor',
          JSON.stringify({ spn: r.spn, made: r.made }));
  t.check(r.account && r.account.available === true &&
          r.account.storedKey === false && r.record &&
          r.record.directoryKeys === false && r.record.password === 'set',
          'the account is built from the published password, as before',
          JSON.stringify({ account: r.account, record: r.record }));
  log.debug("Leaving developmentIsUnchanged().");
}

module.exports = {
  name: 'kerberos_acceptor_key',
  describe: 'product mode keys the Kerberos acceptor\'s SPN at random when ' +
            'krb5.servicePassword is empty or published; an operator\'s ' +
            'own password wins; development is unchanged',
  run: function (t) {
    log.debug("Entering run().");
    productKeysTheAcceptor(t);
    anOperatorsPasswordWins(t);
    developmentIsUnchanged(t);
    log.debug("Leaving run().");
  }
};
