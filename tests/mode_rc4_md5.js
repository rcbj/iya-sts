'use strict';
//
// File: mode_rc4_md5.js
//
// ===========================================================================
// RC4-HMAC IN KERBEROS AND MD5 IN SCIM DIGEST ARE DEVELOPMENT'S (#182).
//
// Product honoured two broken algorithms after #181: `krb5.enctypes`'s
// default gave every krbtgt, service and person an rc4-hmac key (RFC 8429
// deprecates it), and `scim.digestMd5` was ON by default (RFC 7616 keeps MD5
// for backward compatibility only). Both now go through #104's machinery
// under `mode.usesBrokenAlgorithms()`:
//
//   * `scim.digestMd5` carries the `onlyWhile` marker and is OFF by default
//     (the default is the product value); product offers no Digest at all.
//   * `krb5.enctypes` carries it on the ELEMENT `23` (`onlyWhileValues` over
//     a csv row), so the default keeps RC4 for development and product reads
//     the list without it — and every place a key is chosen, derived or used
//     asks `principals.etypePermitted()`, so a realm switched to product
//     under a database built in development uses no RC4 key either.
//
// Two CHILD PROCESSES, each its own KDC:
//
//   A. PRODUCT from the start (`STS_MODE=product`, a persisted keystore):
//      the list in force; the krbtgt's etypes and its RC4 key refused; the
//      write refusals (STS-CORE-0103); a person's stored keys and keytab and
//      a new service principal's keytab without RC4; real AS exchanges —
//      only 23 refused KDC_ERR_ETYPE_NOSUPP, 23-then-18 answered with 18, 18
//      alone a TGT; TGS exchanges — only 23 refused, an RC4 subkey refused;
//      the acceptor refusing an RC4 initiator subkey (STS-KRB-0158) and
//      accepting an AES one; FAST armor with an RC4 subkey refused unarmored
//      (STS-KRB-0159).
//   B. DEVELOPMENT, SWITCHED TO PRODUCT AT RUN TIME AND BACK: RC4 honoured
//      (a TGT over 23, the krbtgt's RC4 key derived); then, with that key in
//      the cache, product refuses it, lists no 23, refuses the AS exchange;
//      and back in development it all works again. SCIM: MD5 not offered by
//      default, offered once turned on, read as off in product with it still
//      stored (STS-CORE-0106, once).
//
// The clients are `tests/vendored/krb5_wire.js`'s, over an in-process
// transport that hands each message to `kdc.handleMessage()`. The same over
// TCP 88, and MIT kinit, is `tests/vendored/sts_kerberos_rc4.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'mode_rc4_md5',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/* eslint-disable no-undef */
// THE PRODUCT CHILD'S PROGRAM. Serialised with toString() and run with
// `node -e`, which the code style exempts from the Entering/Leaving lines.
async function productChild() {
  const R = process.env.MR_ROOT;
  const out = {};
  const keystore = require(R + '/common/keystore');
  keystore.reset();
  keystore.setStore({
    loadKeys: function () { return Promise.resolve([]); },
    saveKeys: function () { return Promise.resolve(); },
    deleteKeys: function () { return Promise.resolve(); }
  });
  await keystore.start();
  const config = require(R + '/common/config');
  const mode = require(R + '/common/mode');
  const errorCodes = require(R + '/common/error_codes');
  const principals = require(R + '/kerberos/krb5_principals.js');
  const kdc = require(R + '/kerberos/krb5_kdc.js');
  const service = require(R + '/kerberos/krb5_service.js');
  const directory = require(R + '/ldap/ldap_server');
  const credentials = require(R + '/common/credentials');
  const personKeys = require(R + '/kerberos/krb5_person_keys');
  const actions = require(R + '/admin-core/admin_actions');
  const wire = require(R + '/tests/vendored/krb5_wire.js');
  // The code each refusal carries is RECORDED, never sent: the KDC hangs it
  // on the reply under a Symbol for its transport to write down, and this
  // transport reads it there.
  const recorded = [];
  const inproc = { label: 'in-process', send: async function (bytes) {
    const reply = await kdc.handleMessage(bytes);
    Object.getOwnPropertySymbols(reply).forEach(function (sym) {
      if (reply[sym] && reply[sym].code) {
        recorded.push(reply[sym].code);
      }
    });
    return reply;
  } };
  const REALM = principals.REALM;

  out.inForce = mode.valueInForce('krb5.enctypes');
  out.kdcEtypes = principals.KDC_ETYPES.slice();
  out.permitted = [principals.etypePermitted(23),
                   principals.etypePermitted(18)];
  const krbtgt = principals.find(['krbtgt', REALM], REALM);
  out.krbtgtEtypes = krbtgt ? principals.supportedEtypes(krbtgt) : null;
  try {
    await principals.longTermKey(krbtgt, 23);
    out.krbtgtRc4 = 'derived';
  } catch (e) {
    out.krbtgtRc4 = /product mode/.test(e.message) ? 'refused' : e.message;
  }

  // --- the writes ---
  const md5 = config.setOverride('scim.digestMd5', true);
  out.md5Write = { ok: md5.ok, code: errorCodes.codeOf(md5),
                   text: (md5.errors || []).join(' ') };
  out.md5WriteOff = config.checkWriteCode('scim.digestMd5', 'false');
  out.encAllowed = [mode.allowsValue('krb5.enctypes', ['18', '23']),
                    mode.allowsValue('krb5.enctypes', ['18', '20'])];
  out.md5InForce = mode.valueInForce('scim.digestMd5');

  // --- a person, their keys and their keytab ---
  const PW = 'Rc4-Product-Passw0rd#182';
  out.created = directory.createUser('rc4alice', { invent: false }).ok;
  out.set = credentials.setPassword('rc4alice', PW).ok;
  await personKeys.idle();
  const alice = personKeys.listPeople().filter(function (p) {
    return p.username === 'rc4alice';
  })[0] || null;
  out.aliceEtypes = alice ? alice.etypes.map(function (e) {
    return e.etype;
  }) : null;
  const tab = await personKeys.personKeytab('rc4alice', PW,
                                           { actor: 'rc4alice' });
  out.keytabEtypes = tab.ok ? tab.etypes : 'refused ' + JSON.stringify(tab);
  const svc = actions.kerberosPrincipalsAction(
    { action: 'create-service', spn: 'HTTP/rc4svc.example.com' },
    { actor: 'test', via: 'api' });
  out.serviceKeytabEtypes = svc.ok && svc.keytab ?
    wire.readKeytab(Buffer.from(svc.keytab, 'base64')).map(function (e) {
      return e.etype;
    }) : 'refused ' + JSON.stringify(svc.errors || svc);

  // --- AS exchanges ---
  const brief = function (r) {
    const e = (r.second && r.second.error) || (r.first && r.first.error);
    return { tgt: !!r.tgt, code: e ? e.code : null,
             eText: e ? e.eText : '', etype: r.info ? r.info.etype : null,
             replyEtype: r.tgt ? r.tgt.replyEtype : null };
  };
  const only = await wire.asExchange(inproc, REALM, 'rc4alice',
                                     { password: PW, etypes: [23] });
  out.asOnly23 = brief(only);
  out.asFirst23 = brief(await wire.asExchange(inproc, REALM, 'rc4alice',
                        { password: PW, etypes: [23, 18] }));
  const aes = await wire.asExchange(inproc, REALM, 'rc4alice',
                                    { password: PW, etypes: [18] });
  out.asAes = brief(aes);

  // --- TGS exchanges, for the acceptor's service ---
  const spn = Array.isArray(service.SERVICE_PRINCIPAL) ?
    service.SERVICE_PRINCIPAL : String(service.SERVICE_PRINCIPAL).split('/');
  const sname = { type: 3, name: spn };
  if (aes.tgt) {
    const tgsBrief = function (r) {
      return { ok: r.ok, code: r.ok ? null : r.error.code,
               eText: r.ok ? '' : r.error.eText };
    };
    out.tgsOnly23 = tgsBrief(await wire.tgsExchange(inproc, aes.tgt, sname,
                                                    null, { etypes: [23] }));
    out.tgsSubkey23 = tgsBrief(await wire.tgsExchange(inproc, aes.tgt,
      sname, null, { subkeyEtype: 23 }));
    const ticket = await wire.tgsExchange(inproc, aes.tgt, sname);
    out.tgsAes = tgsBrief(ticket);

    // --- the acceptor ---
    if (ticket.ok) {
      const rc4 = await wire.apRequest(ticket, { subkeyEtype: 23 });
      const refused = await service.acceptRaw(rc4.token, { record: false });
      out.acceptRc4 = { ok: refused.ok, errorCode: refused.errorCode };
      const good = await wire.apRequest(ticket);
      const accepted = await service.acceptRaw(good.token, { record: false });
      out.acceptAes = { ok: accepted.ok, errorCode: accepted.errorCode };
    }

    // --- FAST armor ---
    const none = async function () {
      return [];
    };
    const fast = await wire.fastAsExchange(inproc, REALM, 'rc4alice',
                                           aes.tgt, none, { subkeyEtype: 23 });
    out.fastRc4 = { ok: fast.ok, armored: fast.armored, code: fast.code,
                    eText: fast.eText };
    const fastAes = await wire.fastAsExchange(inproc, REALM, 'rc4alice',
                                              aes.tgt, none, {});
    out.fastAes = { ok: fastAes.ok, armored: fastAes.armored,
                    code: fastAes.code };
  }
  out.codes = ['STS-KRB-0156', 'STS-KRB-0157', 'STS-KRB-0159'].filter(
    function (code) {
      return recorded.indexOf(code) >= 0;
    });
  return out;
}

// THE DEVELOPMENT CHILD'S PROGRAM, switched to product and back.
async function developmentChild() {
  const R = process.env.MR_ROOT;
  const out = {};
  const config = require(R + '/common/config');
  const mode = require(R + '/common/mode');
  const principals = require(R + '/kerberos/krb5_principals.js');
  const kdc = require(R + '/kerberos/krb5_kdc.js');
  const scimAuth = require(R + '/scim/scim_auth');
  const wire = require(R + '/tests/vendored/krb5_wire.js');
  const inproc = { label: 'in-process', send: function (bytes) {
    return kdc.handleMessage(bytes);
  } };
  const REALM = principals.REALM;
  const PW = String(config.value('krb5.userPassword'));
  const krbtgt = principals.find(['krbtgt', REALM], REALM);
  const brief = function (r) {
    const e = (r.second && r.second.error) || (r.first && r.first.error);
    return { tgt: !!r.tgt, code: e ? e.code : null,
             eText: e ? e.eText : '',
             replyEtype: r.tgt ? r.tgt.replyEtype : null };
  };
  const req = { headers: {}, method: 'GET', originalUrl: '/scim/v2/Users' };
  const md5Offered = function () {
    return scimAuth.challenges(req).join('\n').indexOf('algorithm=MD5') >= 0;
  };
  const observe = async function (label) {
    const o = {};
    o.kdcEtypes = principals.KDC_ETYPES.slice();
    o.krbtgtEtypes = principals.supportedEtypes(krbtgt);
    try {
      await principals.longTermKey(krbtgt, 23);
      o.krbtgtRc4 = 'derived';
    } catch (e) {
      o.krbtgtRc4 = /product mode/.test(e.message) ? 'refused' : e.message;
    }
    o.asOnly23 = brief(await wire.asExchange(inproc, REALM, 'rc4dev',
                       { password: PW, etypes: [23] }));
    o.md5InForce = mode.valueInForce('scim.digestMd5');
    o.md5Offered = md5Offered();
    out[label] = o;
  };
  out.md5Default = md5Offered();
  const on = config.setOverride('scim.digestMd5', true);
  out.md5SetInDevelopment = on.ok;
  await observe('development');
  config.setOverride('global.mode', 'product');
  await observe('product');
  await observe('productAgain');
  config.setOverride('global.mode', 'development');
  await observe('developmentAgain');
  return out;
}
/* eslint-enable no-undef */

function inAChild(program, env, label, t) {
  log.debug("Entering inAChild(). " + label);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode-rc4-md5-'));
  const outFile = path.join(dir, 'report.json');
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|SCIM_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const script = 'delete process.env.CONFIG_FILE;' +
    '(' + program.toString() + ')().then(function (r) ' +
    '{require("fs").writeFileSync(process.env.MR_OUT, JSON.stringify(r)); ' +
    'process.exit(0); }).catch(function (e) { ' +
    'require("fs").writeFileSync(process.env.MR_OUT, JSON.stringify({ ' +
    'crashed: e.stack || e.message })); process.exit(0); });';
  const run = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, { LOG_LEVEL: 'warn', STS_LOG_LEVEL: 'warn',
                                MR_ROOT: ROOT, MR_OUT: outFile },
                       env(kekFile)),
    encoding: 'utf8', timeout: 240000, cwd: ROOT,
    maxBuffer: 64 * 1024 * 1024
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one; said below.
    report = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // A temporary directory left behind is litter, not a failure.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  t.check(report !== null && !report.crashed, 'the ' + label + ' child ran ' +
          'to the end', 'exit ' + run.status + ' ' +
          (report && report.crashed) + ' ' +
          String(run.stderr || '').slice(-1200));
  log.debug("Leaving inAChild().");
  return { report: report || {}, stdout: String(run.stdout || '') };
}

function inProduct(t) {
  log.debug("Entering inProduct().");
  t.log.info('=== A. a product KDC: no rc4-hmac anywhere ===');
  const got = inAChild(productChild, function (kekFile) {
    log.debug("Entering env().");
    log.debug("Leaving env().");
    return { STS_MODE: 'product',
             KRB5_KRBTGT_PASSWORD: 'not-the-published-krbtgt-secret-182',
             KRB5_SERVICE_PASSWORD: 'not-the-published-service-secret-182',
             STS_KEYS_SOURCE: 'persisted', STS_KEYS_KEK_PROVIDER: 'file',
             STS_KEYS_KEK_FILE: kekFile };
  }, 'product', t);
  const r = got.report;
  const j = JSON.stringify;
  t.check(j(r.inForce) === j(['18', '17', '20', '19']) &&
          j(r.kdcEtypes) === j([18, 17, 20, 19]),
          'the list in force, and the KDC\'s, is the default without 23',
          j([r.inForce, r.kdcEtypes]));
  t.check(r.permitted && r.permitted[0] === false && r.permitted[1] === true,
          'etypePermitted(): 23 no, 18 yes', j(r.permitted));
  t.check(j(r.krbtgtEtypes) === j([18, 17, 20, 19]) &&
          r.krbtgtRc4 === 'refused',
          'the krbtgt offers no RC4 and no RC4 key is derived for it',
          j([r.krbtgtEtypes, r.krbtgtRc4]));
  t.check(r.md5Write && !r.md5Write.ok &&
          r.md5Write.code === 'STS-CORE-0103' &&
          /product mode/.test(r.md5Write.text) && r.md5WriteOff === '',
          'scim.digestMd5 on is refused on write (STS-CORE-0103); off is ' +
          'accepted', j([r.md5Write, r.md5WriteOff]));
  t.check(r.encAllowed && r.encAllowed[0] === false &&
          r.encAllowed[1] === true && r.md5InForce === false,
          'krb5.enctypes naming 23 is not allowed, 18,20 is; ' +
          'scim.digestMd5 in force is off', j([r.encAllowed, r.md5InForce]));
  t.check(r.created && r.set && j(r.aliceEtypes) === j([18, 17, 20, 19]),
          'a person\'s derived keys carry no RC4 key', j(r.aliceEtypes));
  t.check(j(r.keytabEtypes) === j([18, 17, 20, 19]),
          'the person\'s keytab holds no RC4 key', j(r.keytabEtypes));
  t.check(Array.isArray(r.serviceKeytabEtypes) &&
          r.serviceKeytabEtypes.indexOf(23) < 0 &&
          r.serviceKeytabEtypes.indexOf(18) >= 0,
          'a new service principal\'s keytab holds no RC4 key',
          j(r.serviceKeytabEtypes));
  t.check(r.asOnly23 && !r.asOnly23.tgt && r.asOnly23.code === 14 &&
          /product mode/.test(r.asOnly23.eText),
          'an AS-REQ offering only rc4-hmac is KDC_ERR_ETYPE_NOSUPP, naming ' +
          'product mode', j(r.asOnly23));
  t.check(r.asFirst23 && r.asFirst23.tgt && r.asFirst23.etype === 18 &&
          r.asFirst23.replyEtype === 18,
          'offering rc4-hmac first then aes256, the exchange uses aes256',
          j(r.asFirst23));
  t.check(r.asAes && r.asAes.tgt, 'an AES AS exchange gets a TGT',
          j(r.asAes));
  t.check(r.tgsOnly23 && !r.tgsOnly23.ok && r.tgsOnly23.code === 14 &&
          /product mode/.test(r.tgsOnly23.eText),
          'a TGS-REQ offering only rc4-hmac is KDC_ERR_ETYPE_NOSUPP',
          j(r.tgsOnly23));
  t.check(r.tgsSubkey23 && !r.tgsSubkey23.ok && r.tgsSubkey23.code === 14 &&
          /subkey/.test(r.tgsSubkey23.eText),
          'a TGS-REQ whose Authenticator carries an RC4 subkey is refused',
          j(r.tgsSubkey23));
  t.check(r.tgsAes && r.tgsAes.ok, 'an AES TGS-REQ gets a service ticket',
          j(r.tgsAes));
  t.check(r.acceptRc4 && !r.acceptRc4.ok &&
          r.acceptRc4.errorCode === 'STS-KRB-0158' &&
          r.acceptAes && r.acceptAes.ok,
          'the acceptor refuses an RC4 initiator subkey (STS-KRB-0158) and ' +
          'accepts an AES one', j([r.acceptRc4, r.acceptAes]));
  t.check(r.fastRc4 && !r.fastRc4.ok && r.fastRc4.armored === false &&
          r.fastRc4.code === 14 && /armor subkey/.test(r.fastRc4.eText) &&
          r.fastAes && r.fastAes.armored === true,
          'FAST armor with an RC4 subkey is refused unarmored ' +
          '(KDC_ERR_ETYPE_NOSUPP); AES armor is accepted',
          j([r.fastRc4, r.fastAes]));
  t.check(j(r.codes) === j(['STS-KRB-0156', 'STS-KRB-0157',
                            'STS-KRB-0159']),
          'the refusals are recorded under STS-KRB-0156, 0157 and 0159',
          j(r.codes));
  log.debug("Leaving inProduct().");
}

function switched(t) {
  log.debug("Entering switched().");
  t.log.info('=== B. development, switched to product at run time, and ' +
             'back ===');
  const got = inAChild(developmentChild, function () {
    log.debug("Entering env().");
    log.debug("Leaving env().");
    return {};
  }, 'development', t);
  const r = got.report;
  const j = JSON.stringify;
  t.check(r.md5Default === false && r.md5SetInDevelopment === true,
          'SCIM Digest offers no MD5 by default in development, and ' +
          'scim.digestMd5 may be turned on there', j([r.md5Default,
                                                      r.md5SetInDevelopment]));
  [['development', 'development'], ['developmentAgain', 'back in development']]
    .forEach(function (pair) {
      const d = r[pair[0]] || {};
      t.check(d.kdcEtypes && d.kdcEtypes.indexOf(23) >= 0 &&
              d.krbtgtEtypes.indexOf(23) >= 0 && d.krbtgtRc4 === 'derived' &&
              d.asOnly23 && d.asOnly23.tgt && d.asOnly23.replyEtype === 23 &&
              d.md5InForce === true && d.md5Offered === true,
              pair[1] + ': RC4 is offered, derived and gets a TGT; MD5 is ' +
              'offered', j(d));
    });
  ['product', 'productAgain'].forEach(function (label) {
    const p = r[label] || {};
    t.check(p.kdcEtypes && p.kdcEtypes.indexOf(23) < 0 &&
            p.krbtgtEtypes.indexOf(23) < 0 && p.krbtgtRc4 === 'refused' &&
            p.asOnly23 && !p.asOnly23.tgt && p.asOnly23.code === 14,
            label + ': with the RC4 key still cached, the KDC offers no 23, ' +
            'uses no RC4 key and refuses an rc4-only AS-REQ',
            j(p));
    t.check(p.md5InForce === false,
            label + ': scim.digestMd5 still stored on is read as off',
            j(p.md5InForce));
  });
  const said = got.stdout.split('\n').filter(function (line) {
    return line.indexOf('STS-CORE-0106') >= 0 &&
           line.indexOf('scim.digestMd5') >= 0;
  }).length;
  t.check(said === 1, 'scim.digestMd5 ignored is logged ONCE ' +
          '(STS-CORE-0106)', said + ' line(s)');
  log.debug("Leaving switched().");
}

async function run(t) {
  log.debug("Entering run().");
  inProduct(t);
  switched(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'mode_rc4_md5',
  describe: '#182: rc4-hmac in krb5.enctypes and MD5 in SCIM Digest are ' +
            'development\'s — a product KDC derives, stores, offers and ' +
            'accepts no RC4 key (AS, TGS, acceptor, FAST, keytabs), also ' +
            'when switched to product at run time; scim.digestMd5 is off by ' +
            'default, refused on write and ignored on read in product',
  run: run
};
