'use strict';
//
// File: kerberos_principal_store.js
//
// ===========================================================================
// THE PRINCIPAL DATABASE ACROSS A RESTART AND ACROSS PROCESSES (2026-09-12).
//
// Two gaps `kerberos/CLAUDE.md` recorded as open and this file is the guard for
// closing them.
//
//   1. **A RESTORED ROW OVERRODE THE SETTINGS.** `krb5.principals` is persisted
//      and replicated, and a restore put back WHOLE rows — so a configured
//      account (krbtgt, the acceptor's account, every fixture) came back with
//      the password, salt, etypes and kvno it was written with, and a changed
//      `krb5.servicePassword` did not take effect. A process whose settings no
//      longer create an account (product mode after development, a refused
//      published password) had it put back anyway.
//   2. **TWO PROCESSES HANDED ONE RID TO TWO ACCOUNTS.** The allocator read one
//      above the highest RID in the local database, which two processes
//      creating accounts in the same instant both read.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first.
//
// Every claim below is correct on every endpoint for the whole life of the
// process that gets it wrong. A stale password restored over a configured one
// is visible only on the NEXT start, in a different process; a RID collision
// between two processes needs two processes racing a replication window, and
// what it produces is a PAC that verifies and names the wrong SID. None of that
// can be asked of a running service — `minted_persistence.js`'s clause exactly.
//
// Three sections, and each says what it rests on:
//
//   A. THE RULE AT THE BOUNDARY, in this process. The rule lives in the two
//      accessors `realms.sharedMap()` hands `persistence_minted.js`, which both
//      the startup restore and the replication applier call, so driving the
//      accessors drives both doors. It uses the real development database this
//      process built, and puts back everything it touches.
//   B. THE DOORS THEMSELVES, in a CHILD PROCESS in product mode. The database
//      is built at require time in the process's mode, and the minted store's
//      restore and applier need a key-encryption key and a driver — both
//      process-wide — so a child is the only honest place. It seals real rows,
//      restores them through `minted.restore()`, and replicates changes through
//      `minted.applyChange()`.
//   C. THE RID, in this process and in a child. Determinism across processes is
//      asserted by asking a SECOND process the same question.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const realms = require('../common/realms');
const principals = require('../kerberos/krb5_principals.js');

const ROOT = path.join(__dirname, '..');

// A deep copy through JSON, which is exactly what a stored row has been
// through: a Date becomes a string and the non-enumerable key cache is gone.
function asStored(record) {
  return JSON.parse(JSON.stringify(record));
}

function store() {
  return realms.handleFor('krb5.principals');
}

// ---------------------------------------------------------------------------
// A. THE RULE, AT THE ACCESSORS BOTH DOORS CALL.
// ---------------------------------------------------------------------------
function theRuleAtTheBoundary(t) {
  t.log.info('=== A. what a restored row may change, at the accessors ===');
  const handle = store();
  t.check(!!handle && typeof handle.restore === 'function' &&
          typeof handle.remove === 'function',
          'krb5.principals is a declared store with restore and remove accessors');
  if (!handle) {
    return;
  }
  const spn = ['HTTP', 'web.example.com'];
  const key = 'HTTP/web.example.com@EXAMPLE.COM';
  const web = principals.find(spn);
  t.check(!!web && principals.isConfigured(spn),
          'the acceptor\'s account is a CONFIGURED principal here');
  if (!web) {
    return;
  }
  const before = asStored(web);
  const wasSignedOut = web.signedOutAt;
  const suffix = String(process.pid) + Math.random().toString(36).slice(2, 6);
  const autoKey = 'store-probe-auto-' + suffix + '@EXAMPLE.COM';
  const personKey = 'store-probe-person-' + suffix + '@EXAMPLE.COM';
  const retiredKey = 'HTTP/retired-' + suffix + '.example.com@EXAMPLE.COM';
  try {
    // 1. A stale configured row: every config field different, and a sign-out.
    const stale = asStored(web);
    stale.password = 'a-password-from-before-' + suffix;
    stale.salt = 'EXAMPLE.COMsomethingelse';
    stale.etypes = [23];
    stale.kvno = 41;
    stale.type = 1;
    stale.okAsDelegate = !web.okAsDelegate;
    stale.allowedToDelegateTo = ['HTTP/anywhere.example.com'];
    stale.description = 'what this account used to be';
    stale.pac = Object.assign({}, stale.pac, { rid: 4242 });
    stale.signedOutAt = '2026-01-02T03:04:05.000Z';
    handle.restore('', key, stale);
    const held = principals.find(spn);
    t.check(held === web,
            'the configured record this process built is the one still held — ' +
            'the row was not put in its place');
    t.equal(JSON.stringify(Object.assign({}, asStored(held), { signedOutAt: null })),
            JSON.stringify(Object.assign({}, before, { signedOutAt: null })),
            'EVERY configuration field is what the settings built: password, salt, ' +
            'etypes, kvno, type, delegation, description and PAC identity');
    t.equal(principals.signedOutAt(spn) && principals.signedOutAt(spn).toISOString(),
            '2026-01-02T03:04:05.000Z',
            'AND THE RUNTIME STATE CAME FROM THE ROW — a sign-out made before the ' +
            'restart is still in force after it');

    // 2. A replicated clear of that sign-out reaches it too.
    const cleared = asStored(stale);
    cleared.signedOutAt = null;
    handle.restore('', key, cleared);
    t.equal(principals.signedOutAt(spn), null,
            'a replicated clearSignOut() clears it — the runtime field is taken ' +
            'both ways, not only when it is set');

    // 3. A row the settings do not configure and nothing made at runtime.
    handle.restore('', retiredKey, {
      name: ['HTTP', 'retired-' + suffix + '.example.com'], type: 3, realm: 'EXAMPLE.COM',
      password: 'retired-service-password', salt: 'x', etypes: [18], kvno: 3,
      autoCreated: false, directoryKeys: false, pac: { rid: 1100 }, signedOutAt: null
    });
    t.equal(principals.find(['HTTP', 'retired-' + suffix + '.example.com']), null,
            'A ROW CLAIMING TO BE CONFIGURED THAT THESE SETTINGS DO NOT CONFIGURE ' +
            'IS NOT RESTORED — the account a changed mode or a renamed SPN ' +
            'removed does not come back with its old password');

    // 4. An auto-created row: restored whole, and removable.
    const auto = {
      name: ['store-probe-auto-' + suffix], type: 1, realm: 'EXAMPLE.COM',
      password: 'whatever-it-was-made-with', salt: 'EXAMPLE.COMstore-probe',
      etypes: [18, 17], kvno: 7, autoCreated: true, directoryKeys: false,
      description: 'restored', pac: { rid: 99887766, groups: [513] },
      signedOutAt: '2026-02-03T04:05:06.000Z'
    };
    handle.restore('', autoKey, auto);
    const restoredAuto = principals.find(['store-probe-auto-' + suffix]);
    t.check(!!restoredAuto && restoredAuto.kvno === 7 &&
            restoredAuto.password === 'whatever-it-was-made-with' &&
            restoredAuto.pac.rid === 99887766,
            'an AUTO-CREATED row is restored whole — it exists nowhere but the store');
    t.check(!!restoredAuto && restoredAuto.keys instanceof Map,
            'and it is given a key cache on the way in');
    handle.remove('', autoKey);
    t.equal(principals.find(['store-probe-auto-' + suffix]), null,
            'and a replicated removal of a runtime-made principal is applied');

    // 5. A directory person: restored whole.
    handle.restore('', personKey, {
      name: ['store-probe-person-' + suffix], type: 1, realm: 'EXAMPLE.COM',
      password: null, salt: 'EXAMPLE.COMperson', etypes: [18], kvno: 5,
      autoCreated: false, directoryKeys: true, pac: { rid: 99887755 }, signedOutAt: null
    });
    const person = principals.all().filter(function (one) {
      return one.name.join('/') === 'store-probe-person-' + suffix;
    })[0];
    t.check(!!person && person.directoryKeys === true && person.kvno === 5,
            'a DIRECTORY-KEYED row is restored whole too');

    // 6. A configured key may not be removed by a stored removal.
    handle.remove('', key);
    t.check(principals.find(spn) === web,
            'A STORED REMOVAL OF A CONFIGURED PRINCIPAL IS REFUSED — the account ' +
            'exists because the settings build it');

    // 7. An auto-created row for a CONFIGURED key: the settings still win.
    const imposter = asStored(web);
    imposter.autoCreated = true;
    imposter.password = 'an-auto-created-password-' + suffix;
    handle.restore('', key, imposter);
    t.check(principals.find(spn) === web && web.password === before.password &&
            web.autoCreated === before.autoCreated,
            'a row calling itself auto-created does not get to replace a configured ' +
            'account — which rows are configured is this process\'s to say');

    // 8. Not a record at all.
    handle.restore('', key, null);
    t.check(principals.find(spn) === web, 'a null row changes nothing');

    // 9. A reconciler that throws applies nothing (common/realms.js's catch).
    const hostile = {};
    Object.defineProperty(hostile, 'name', {
      enumerable: true, get: function () { throw new Error('unreadable'); }
    });
    const hostileKey = 'store-probe-hostile-' + suffix + '@EXAMPLE.COM';
    handle.restore('', hostileKey, hostile);
    t.equal(principals.all().filter(function (one) {
      return one === hostile;
    }).length, 0,
    'A ROW THE RECONCILER CANNOT EVALUATE IS NOT APPLIED — fail closed, because ' +
    'the rule exists for rows that must not be believed');
  } finally {
    web.signedOutAt = wasSignedOut;
    // Put back through the accessor's unguarded twin: remove() on keys this
    // section made, which are runtime-made and therefore removable.
    handle.remove('', autoKey);
    handle.remove('', personKey);
  }
  t.check(principals.all().every(function (one) {
    return one.name.join('/').indexOf('store-probe-') === -1;
  }), 'and everything the section added is gone again');
}

// ---------------------------------------------------------------------------
// A CHILD PROCESS RUNNING A SCRIPT FILE, with this service's own environment
// variables cleared first so a developer's exports cannot make it pass. The
// script writes a JSON report; stdout is returned too, because two claims are
// about what was LOGGED.
// ---------------------------------------------------------------------------
function inAChild(env, script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krb5-store-'));
  const file = path.join(dir, 'child.js');
  const out = path.join(dir, 'report.json');
  fs.writeFileSync(file, script.replace(/__ROOT__/g, JSON.stringify(ROOT))
                               .replace(/__OUT__/g, JSON.stringify(out))
                               .replace(/__DIR__/g, JSON.stringify(dir)));
  const clean = {};
  Object.keys(process.env).forEach(function (k) {
    if (!/^(KRB5_|STS_|LDAP_|CONFIG_FILE$|ADMIN_API_)/.test(k)) {
      clean[k] = process.env[k];
    }
  });
  const result = childProcess.spawnSync(process.execPath, [file], {
    env: Object.assign(clean, { STS_LOG_LEVEL: 'warn' }, env),
    encoding: 'utf8', timeout: 120000, cwd: ROOT
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    // No report: the child failed before writing one, which the caller reports
    // through `status` and `stderr`.
    report = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // A temporary directory left behind is not a failed assertion.
    process.stderr.write('kerberos_principal_store: could not remove ' + dir + '\n');
  }
  return { status: result.status, stdout: result.stdout || '',
           stderr: result.stderr || '', report: report };
}

// ---------------------------------------------------------------------------
// B. THE TWO DOORS, IN PRODUCT MODE.
// ---------------------------------------------------------------------------
const DOORS_SCRIPT = `
'use strict';
delete process.env.CONFIG_FILE;
const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const ROOT = __ROOT__;
const kekFile = path.join(__DIR__, 'kek');
fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'), { mode: 0o600 });
process.env.STS_KEYS_KEK_FILE = kekFile;
const config = require(path.join(ROOT, 'common/config'));
const keystore = require(path.join(ROOT, 'common/keystore'));
const minted = require(path.join(ROOT, 'persistence/persistence_minted'));
const p = require(path.join(ROOT, 'kerberos/krb5_principals.js'));

const HANDLE = 'krb5.principals';
function b64(s) { return Buffer.from(String(s), 'utf8').toString('base64url'); }
const rows = new Map();
const driver = {
  origin: function () { return 'process-under-test'; },
  loadMinted: function () { return Promise.resolve(Array.from(rows.values())); },
  saveMinted: function () { return Promise.resolve(); },
  readMinted: function (handle, realm, key) { return Promise.resolve(rows.get(key) || null); },
  purgeMinted: function () { return Promise.resolve(0); }
};
function put(key, value) {
  rows.set(key, { handle: HANDLE, realm: '', key: key, writtenAt: Date.now(),
                  body: keystore.seal(JSON.stringify(value), 'minted-rows') });
}
function change(key) { return { key: b64(HANDLE) + '.' + b64(key), realm: '' }; }
function view(record) {
  return record ? { password: record.password, salt: record.salt, kvno: record.kvno,
                    etypes: record.etypes, description: record.description,
                    okAsDelegate: record.okAsDelegate, rid: record.pac && record.pac.rid,
                    signedOutAt: record.signedOutAt ? new Date(record.signedOutAt).toISOString() : null }
                : null;
}

(async function () {
  keystore.reset();
  keystore.setStore({ loadKeys: function () { return Promise.resolve([]); },
                      saveKeys: function () { return Promise.resolve(); },
                      deleteKeys: function () { return Promise.resolve(); } });
  await keystore.start();
  config.setOverride('persistence.minted', true);
  minted.setDriver(driver, 'postgres');

  const spnParts = String(config.value('krb5.servicePrincipal')).split('/');
  const spnKey = spnParts.join('/') + '@' + p.REALM;
  const krbtgtKey = 'krbtgt/' + p.REALM + '@' + p.REALM;
  const svc = p.find(spnParts);
  const krbtgt = p.find(['krbtgt', p.REALM]);
  const report = { enabled: minted.enabled(), mode: config.value('global.mode'),
                   configuredBefore: { svc: view(svc), krbtgt: view(krbtgt) } };

  const staleSvc = JSON.parse(JSON.stringify(svc));
  staleSvc.password = 'svc-then-SECRET-VALUE';
  staleSvc.salt = 'EXAMPLE.COMold-salt';
  staleSvc.kvno = 41;
  staleSvc.etypes = [23];
  staleSvc.description = 'what it used to be';
  staleSvc.signedOutAt = '2026-01-02T03:04:05.000Z';
  put(spnKey, staleSvc);
  const staleKrbtgt = JSON.parse(JSON.stringify(krbtgt));
  staleKrbtgt.password = 'krbtgt-then-SECRET-VALUE';
  put(krbtgtKey, staleKrbtgt);
  // A development run's fixture, left in the store: the golden case.
  put('alice@' + p.REALM, { name: ['alice'], type: 1, realm: p.REALM,
    password: 'password!', salt: p.REALM + 'alice', etypes: [18, 17, 23], kvno: 3,
    autoCreated: false, directoryKeys: false, pac: { rid: 1104 }, signedOutAt: null });
  put('dana@' + p.REALM, { name: ['dana'], type: 1, realm: p.REALM, password: null,
    salt: p.REALM + 'dana', etypes: [18], kvno: 4, autoCreated: false, directoryKeys: true,
    pac: { rid: 777001 }, signedOutAt: '2026-03-04T05:06:07.000Z' });
  put('erin@' + p.REALM, { name: ['erin'], type: 1, realm: p.REALM, password: null,
    salt: p.REALM + 'erin', etypes: [18], kvno: 4, autoCreated: false, directoryKeys: true,
    pac: { rid: 777001 }, signedOutAt: null });

  await minted.restore();
  const all = p.all();
  function held(name) {
    return all.filter(function (one) { return one.name.join('/') === name; })[0] || null;
  }
  report.afterRestore = {
    svcSame: p.find(spnParts) === svc,
    svc: view(p.find(spnParts)),
    krbtgt: view(p.find(['krbtgt', p.REALM])),
    alice: view(held('alice')),
    dana: view(held('dana')),
    erin: view(held('erin'))
  };

  // Another process signs the service account back in, writing its own record.
  const other = JSON.parse(JSON.stringify(staleSvc));
  other.password = 'svc-other-SECRET-VALUE';
  other.signedOutAt = null;
  put(spnKey, other);
  await minted.applyChange(change(spnKey));
  report.afterReplicatedClear = view(p.find(spnParts));

  // And stamps a sign-out on it.
  other.signedOutAt = '2026-05-06T07:08:09.000Z';
  put(spnKey, other);
  await minted.applyChange(change(spnKey));
  report.afterReplicatedSignOut = view(p.find(spnParts));

  // A removal of krbtgt arrives, and a removal of dana.
  rows.delete(krbtgtKey);
  await minted.applyChange(change(krbtgtKey));
  report.krbtgtAfterRemoval = view(p.find(['krbtgt', p.REALM]));
  rows.delete('dana@' + p.REALM);
  await minted.applyChange(change('dana@' + p.REALM));
  report.danaAfterRemoval = view(p.all().filter(function (one) { return one.name[0] === 'dana'; })[0]);

  fs.writeFileSync(__OUT__, JSON.stringify(report));
  process.exit(0);
})().catch(function (e) {
  process.stderr.write(String(e && e.stack || e));
  process.exit(3);
});
`;

function theDoorsInProductMode(t) {
  t.log.info('=== B. minted.restore() and minted.applyChange(), in product mode ===');
  const run = inAChild({
    STS_MODE: 'product',
    STS_KEYS_SOURCE: 'persisted',
    STS_KEYS_KEK_PROVIDER: 'file',
    KRB5_KRBTGT_PASSWORD: 'krbtgt-now-configured',
    KRB5_SERVICE_PASSWORD: 'svc-now-configured',
    KRB5_SERVICE_SALT: 'EXAMPLE.COMsvc-now'
  }, DOORS_SCRIPT);
  const r = run.report;
  t.check(r !== null, 'the product-mode child ran to the end',
          'exit ' + run.status + ': ' + run.stderr.slice(0, 600));
  if (!r) {
    return;
  }
  t.check(r.enabled === true && r.mode === 'product',
          'minted persistence is on in that child, so both doors are the real ones');
  const now = r.configuredBefore.svc;
  const svc = r.afterRestore.svc;
  t.check(r.afterRestore.svcSame, 'the restore kept the configured service record');
  t.check(!!svc && svc.password === 'svc-now-configured' &&
          svc.salt === 'EXAMPLE.COMsvc-now' && svc.kvno === now.kvno &&
          JSON.stringify(svc.etypes) === JSON.stringify(now.etypes) &&
          svc.description === now.description,
          'A RESTART DOES NOT UNDO A CHANGED krb5.servicePassword OR krb5.serviceSalt: ' +
          'the password, salt, kvno, etypes and description are the settings\'',
          JSON.stringify(svc));
  t.equal(svc && svc.signedOutAt, '2026-01-02T03:04:05.000Z',
          'while the sign-out the stored row carried survives the restart');
  t.equal(r.afterRestore.krbtgt && r.afterRestore.krbtgt.password, 'krbtgt-now-configured',
          'and the krbtgt key is the configured one, not the one in the store');
  t.equal(r.afterRestore.alice, null,
          'A DEVELOPMENT FIXTURE LEFT IN THE STORE IS NOT RESTORED INTO PRODUCT MODE — ' +
          'alice with the published password does not come back');
  t.check(!!r.afterRestore.dana && r.afterRestore.dana.kvno === 4 &&
          r.afterRestore.dana.signedOutAt === '2026-03-04T05:06:07.000Z',
          'a directory person is restored whole, sign-out included');
  t.check(!!r.afterRestore.erin && r.afterRestore.erin.rid === 777001,
          'a restored person whose RID another holds is still restored — nothing ' +
          'is renumbered');
  t.equal(r.afterReplicatedClear && r.afterReplicatedClear.signedOutAt, null,
          'ANOTHER PROCESS\'S clearSignOut() REACHES A CONFIGURED ACCOUNT');
  t.equal(r.afterReplicatedClear && r.afterReplicatedClear.password, 'svc-now-configured',
          'without bringing that process\'s password with it');
  t.equal(r.afterReplicatedSignOut && r.afterReplicatedSignOut.signedOutAt,
          '2026-05-06T07:08:09.000Z',
          'and another process\'s signOut() reaches it too');
  t.check(!!r.krbtgtAfterRemoval,
          'a replicated removal of krbtgt is refused, so this KDC still issues');
  t.equal(r.danaAfterRemoval, null,
          'while a replicated removal of a runtime-made principal is applied');

  t.check(run.stdout.indexOf('STS-KRB-0111') !== -1 &&
          /differs from what this process's settings build, in [^.]*password/
            .test(run.stdout),
          'THE DRIFT IS LOGGED as STS-KRB-0111, naming the fields that differed');
  t.check(run.stdout.indexOf('SECRET-VALUE') === -1 && run.stderr.indexOf('SECRET-VALUE') === -1,
          'and naming them only — no stored password appears in any log line');
  t.check(run.stdout.indexOf('STS-KRB-0112') !== -1 &&
          run.stdout.indexOf('alice@') !== -1,
          'the fixture that was not restored is logged as STS-KRB-0112');
  t.check(run.stdout.indexOf('STS-KRB-0113') !== -1,
          'the refused removal is logged as STS-KRB-0113');
  t.check(run.stdout.indexOf('STS-KRB-0114') !== -1,
          'and the two restored people sharing one RID are logged as STS-KRB-0114');
}

// ---------------------------------------------------------------------------
// C. THE RID IS THE NAME'S.
// ---------------------------------------------------------------------------
function theRidIsTheNames(t) {
  t.log.info('=== C. an on-demand RID is derived from the name ===');
  const suffix = String(process.pid) + Math.random().toString(36).slice(2, 6);
  const names = ['rid-a-' + suffix, 'rid-b-' + suffix, 'Rid-A-' + suffix];
  const here = names.map(function (name) { return principals.autoRidFor([name]); });
  t.check(here.every(function (rid) {
    return Number.isInteger(rid) && rid >= principals.AUTO_RID_BASE &&
           rid < principals.AUTO_RID_LIMIT;
  }), 'every derived RID is in [5000, 2^30)', JSON.stringify(here));
  t.equal(principals.AUTO_RID_LIMIT, 0x40000000,
          'the range ends at Active Directory\'s RID pool size');
  t.check(principals.AUTO_RID_BASE > 2104,
          'and starts above every configured RID, so none can be produced');
  t.equal(JSON.stringify(names.map(function (name) { return principals.autoRidFor([name]); })),
          JSON.stringify(here), 'asking twice gives the same answers');
  t.check(here[0] !== here[2],
          'names are case-sensitive here, so Alice and alice are two RIDs');

  const child = inAChild({}, `
    'use strict';
    delete process.env.CONFIG_FILE;
    const p = require(require('path').join(__ROOT__, 'kerberos/krb5_principals.js'));
    require('fs').writeFileSync(__OUT__, JSON.stringify(${JSON.stringify(names)}.map(function (n) {
      return p.autoRidFor([n]);
    })));
    process.exit(0);
  `);
  t.equal(JSON.stringify(child.report), JSON.stringify(here),
          'A SECOND PROCESS COMPUTES THE SAME RIDS FOR THE SAME NAMES, with no ' +
          'coordination — the concurrent creation that collided before',
          'exit ' + child.status + ': ' + child.stderr.slice(0, 300));

  const created = principals.findOrCreateUser([names[0]]);
  t.equal(created && created.pac.rid, here[0],
          'the account created on demand is given exactly that RID');
  t.equal(principals.autoRidFor([names[0]]), here[0],
          'and an account holding its own slot does not push its own name off it — ' +
          'a second process asking about a name the first has already replicated ' +
          'still gets the same answer');
  created.pac.rid = 7777;
  try {
    t.equal(principals.findOrCreateUser([names[0]]).pac.rid, 7777,
            'AN EXISTING ACCOUNT KEEPS WHATEVER RID IT HAS — nothing renumbers');
  } finally {
    created.pac.rid = here[0];
  }

  // The probe: another principal on the slot a new name hashes to.
  const holder = principals.findOrCreateUser([names[1]]);
  const wasRid = holder.pac.rid;
  const third = 'rid-c-' + suffix;
  const slot = principals.autoRidFor([third]);
  holder.pac.rid = slot;
  try {
    const next = slot + 1 === principals.AUTO_RID_LIMIT ? principals.AUTO_RID_BASE : slot + 1;
    t.equal(principals.autoRidFor([third]), next,
            'A SLOT A DIFFERENT PRINCIPAL HOLDS IS PROBED PAST, to the next one');
    const made = principals.findOrCreateUser([third]);
    t.equal(made && made.pac.rid, next, 'and that is the RID the account gets');
    t.check(made.pac.rid !== holder.pac.rid, 'so the two do not share a SID');
  } finally {
    holder.pac.rid = wasRid;
  }
}

module.exports = {
  name: 'kerberos_principal_store',
  describe: 'a restored principal cannot override the settings, and a runtime ' +
            'RID is the name\'s own',
  run: function (t) {
    theRuleAtTheBoundary(t);
    theDoorsInProductMode(t);
    theRidIsTheNames(t);
  }
};
