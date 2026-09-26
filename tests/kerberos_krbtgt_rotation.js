'use strict';
//
// File: kerberos_krbtgt_rotation.js
//
// ===========================================================================
// THE KRBTGT KEY, STORED AND ROTATED (#169).
//
// Each trust realm's krbtgt key was derived at startup from
// `krb5.krbtgtPassword` at a fixed kvno, never rotated, and kept no previous
// version. It is now a RANDOM key in product mode, sealed on the directory
// entry `krbtgt/<REALM>@<REALM>`, rotated by the `krb5.krbtgt-rotate` job and
// by hand, with the version a rotation replaces kept for the longest a TGT
// under it can live. This file holds that in three CHILD PROCESSES, each its
// own KDC, with `tests/vendored/krb5_wire.js`'s clients over an in-process
// transport that hands each message to `kdc.handleMessage()`:
//
//   A. PRODUCT, FIRST START (an ldif store and a key-encryption key file):
//      no key before the first start's creation, one after, at krb5.kvno,
//      sealed, audited, never a password; a TGT under it; a rotation keeping
//      the old version — the old TGT still accepted, a new one at kvno+1;
//      the schedule's timing (the pure decision, the job refusing to rotate
//      while the kept window is open, the four off reasons); FAST armor and
//      the FAST cookie under the previous kvno; a second rotation inside the
//      window keeping only the newest version (kvno-2 refused 44); the
//      lifetime bound (a one-second override refuses, clearing restores);
//      "rotate and invalidate" — every TGT refused 44, armor refused 44
//      (STS-KRB-0164), the cookie refused, the Shared Signals notice sent;
//      the two doors' refusals (no confirmation, no KDC); "drop previous
//      versions" through the service action; the jobs registered; and no key
//      in any view, audit row, application view or keytab.
//   B. PRODUCT, RESTARTED on the same store and key-encryption key: the
//      stored key and its kept version come back, and a TGT from before the
//      restart still works.
//   C. DEVELOPMENT: the krbtgt is the published password's (a TGT opens with
//      the password-derived key), the schedule is off and the manual job is
//      not; a rotation by hand keeps the password-derived version, so the
//      old TGT still works, and the new TGT no longer opens with the
//      password; "rotate and invalidate" refuses both.
//
// The same over the wire, against a running service, is
// `tests/vendored/sts_kerberos_krbtgt_rotation.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'kerberos_krbtgt_rotation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// THE CHILD. Selected by argv so this one file is both halves.
// ---------------------------------------------------------------------------
async function child(phase) {
  log.debug("Entering child(). " + phase);
  const out = { phase: phase };
  require(ROOT + '/common/app');
  const persistence = require(ROOT + '/persistence/persistence');
  const keystore = require(ROOT + '/common/keystore');
  const config = require(ROOT + '/common/config');
  const realms = require(ROOT + '/common/realms');
  const errorCodes = require(ROOT + '/common/error_codes');
  const audit = require(ROOT + '/common/audit');
  const applications = require(ROOT + '/common/applications');
  const principals = require(ROOT + '/kerberos/krb5_principals.js');
  const kdc = require(ROOT + '/kerberos/krb5_kdc.js');
  const directory = require(ROOT + '/ldap/ldap_server');
  const credentials = require(ROOT + '/common/credentials');
  const personKeys = require(ROOT + '/kerberos/krb5_person_keys');
  const rotation = require(ROOT + '/kerberos/krb5_krbtgt_rotation');
  const scheduler = require(ROOT + '/cluster/scheduler');
  const actions = require(ROOT + '/admin-core/admin_actions');
  const views = require(ROOT + '/admin-core/admin_views');
  const events = require(ROOT + '/ssf/ssf_events');
  const kcrypto = require(ROOT + '/kerberos/krb5_crypto.js');
  const prim = require(ROOT + '/kerberos/krb5_primitives.js');
  const asn1 = require(ROOT + '/kerberos/krb5_asn1.js');
  const wire = require(ROOT + '/tests/vendored/krb5_wire.js');
  const msgs = wire.msgs;
  // The two product phases run over an ldif store (the parent sets it), so a
  // restart has something to restore; development runs in memory.
  if (phase !== 'development') {
    await persistence.start();
  }
  await keystore.start();

  // THE CODE EACH REFUSAL CARRIES is recorded, never sent: the KDC hangs it
  // on the reply under a Symbol for its transport, and this transport reads
  // it there.
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
  const kvnoOf = function (tgt) {
    log.debug("Entering kvnoOf().");
    log.debug("Leaving kvnoOf().");
    return tgt ? tgt.ticket.encPart.kvno : null;
  };
  const tgs = async function (tgt, sname) {
    log.debug("Entering tgs().");
    const got = await wire.tgsExchange(inproc, tgt,
      { type: 2, name: sname.split('/') }, REALM);
    log.debug("Leaving tgs().");
    return got.ok ? { ok: true }
                  : { ok: false, code: got.error.code, eText: got.error.eText,
                      recorded: recorded[recorded.length - 1] };
  };
  const as = async function (name, password) {
    log.debug("Entering as().");
    const got = await wire.asExchange(inproc, REALM, name,
                                      { password: password });
    log.debug("Leaving as().");
    return got.tgt || { refused: got.second || got.first };
  };
  // Every krbtgt key value this child has seen, current and kept, for the
  // leak checks at the end.
  const seenKeys = new Set();
  const noteKeys = function () {
    log.debug("Entering noteKeys().");
    const answer = personKeys.krbtgtKeys() || { keys: [], retained: [] };
    (answer.keys || []).concat.apply(answer.keys || [],
      (answer.retained || []).map(function (one) {
        return one.keys;
      })).forEach(function (pair) {
      seenKeys.add(Buffer.from(pair[1]).toString('base64'));
    });
    log.debug("Leaving noteKeys().");
  };
  const encodeTgt = function (tgt) {
    log.debug("Entering encodeTgt().");
    log.debug("Leaving encodeTgt().");
    return { ticket: Buffer.from(msgs.encTicket(tgt.ticket)).toString('hex'),
             sessionKey: Buffer.from(tgt.sessionKey).toString('hex'),
             etype: tgt.etype, realm: tgt.realm, client: tgt.client };
  };
  const decodeTgt = function (saved) {
    log.debug("Entering decodeTgt().");
    log.debug("Leaving decodeTgt().");
    return { ticket: msgs.readTicket(asn1.readTlv(
               new Uint8Array(Buffer.from(saved.ticket, 'hex')), 0)),
             sessionKey: new Uint8Array(Buffer.from(saved.sessionKey, 'hex')),
             etype: saved.etype, realm: saved.realm, client: saved.client };
  };

  if (phase === 'restart') {
    const saved = JSON.parse(fs.readFileSync(process.env.KR_SAVED, 'utf8'));
    const state = personKeys.krbtgtState();
    out.restart = { source: state.source, kvno: state.kvno,
                    retained: state.retained.map(function (one) {
                      return one.kvno;
                    }) };
    out.restartOldTgs = await tgs(decodeTgt(saved.tgt), saved.spn);
    const fresh = await as(saved.user, saved.password);
    out.restartNewKvno = kvnoOf(fresh);
    log.debug("Leaving child(). restart");
    return out;
  }

  if (phase === 'development') {
    const state0 = personKeys.krbtgtState();
    out.devBefore = { source: state0.source, kvno: state0.kvno,
                      fromPassword: principals.krbtgtFromPassword };
    out.devOff = scheduler.scheduler.offReason(
      scheduler.job(rotation.ROTATE_JOB), '');
    out.devOffNow = scheduler.scheduler.offReason(
      scheduler.job(rotation.ROTATE_NOW_JOB), '');
    const devPassword = String(config.value('krb5.userPassword'));
    const tgt1 = await as('alice', devPassword);
    out.devTgt1Kvno = kvnoOf(tgt1);
    // The published password opens it: the property development keeps.
    const opens = async function (tgt) {
      log.debug("Entering opens().");
      try {
        const key = await kcrypto.etypeById(tgt.ticket.encPart.etype)
          .stringToKey(String(config.value('krb5.krbtgtPassword')),
                       prim.utf8(principals.userSalt(REALM, 'krbtgt')), null);
        await kcrypto.etypeById(tgt.ticket.encPart.etype).decrypt(key,
          kcrypto.KEY_USAGE.KDC_REP_TICKET, tgt.ticket.encPart.cipher);
        log.debug("Leaving opens(). It opens.");
        return true;
      } catch (e) {
        log.debug("Caught in opens(): " + ((e && e.message) || e));
        log.debug("Leaving opens(). It does not open.");
        // Not opening under the password's key IS the answer asked for.
        return false;
      }
    };
    out.devTgt1OpensWithPassword = await opens(tgt1);
    const rotated = await rotation.rotate('', { reason: 'requested',
                                                actor: 'tester', via: 'api' });
    out.devRotate = { ok: rotated.ok, kvno: rotated.kvno,
                      previousKvno: rotated.previousKvno,
                      retained: (rotated.retained || []).map(function (one) {
                        return one.kvno;
                      }) };
    out.devAfter = personKeys.krbtgtState().source;
    out.devOldTgs = await tgs(tgt1, 'HTTP/web.' + REALM.toLowerCase());
    const tgt2 = await as('alice', devPassword);
    out.devTgt2Kvno = kvnoOf(tgt2);
    out.devTgt2OpensWithPassword = await opens(tgt2);
    const gone = await rotation.rotate('', { invalidate: true,
                                             reason: 'invalidated' });
    out.devInvalidate = { ok: gone.ok, kvno: gone.kvno,
                          retained: (gone.retained || []).length };
    out.devTgs1After = await tgs(tgt1, 'HTTP/web.' + REALM.toLowerCase());
    out.devTgs2After = await tgs(tgt2, 'HTTP/web.' + REALM.toLowerCase());
    log.debug("Leaving child(). development");
    return out;
  }

  // ===== A. PRODUCT, FIRST START ==========================================
  const DAY = 86400000;
  out.fromPassword = principals.krbtgtFromPassword;
  const before = personKeys.krbtgtState();
  out.before = { source: before.source, kvno: before.kvno };
  out.ensured = await rotation.ensureAll();
  const made = personKeys.krbtgtState();
  out.made = { source: made.source, kvno: made.kvno, sealed: made.sealed,
               etypes: made.etypes.map(function (e) {
                 return e.etype;
               }) };
  out.reasonAfter = principals.krbtgtUnavailableReason();
  out.ensuredAgain = await personKeys.ensureKrbtgtKey('');
  noteKeys();

  const PW = 'Krbtgt-Rotation-Passw0rd#169';
  const USER = 'krbalice';
  const SPN = 'HTTP/svc169.' + REALM.toLowerCase();
  out.userMade = directory.createUser(USER, { invent: false }).ok;
  out.passwordSet = credentials.setPassword(USER, PW).ok;
  await personKeys.idle();
  const created = actions.kerberosPrincipalsAction(
    { action: 'create-service', spn: SPN }, { actor: 'tester', via: 'api' });
  out.serviceMade = !!created.ok;
  const tgt1 = await as(USER, PW);
  out.tgt1Kvno = kvnoOf(tgt1);
  out.tgs1 = await tgs(tgt1, SPN);

  // --- a rotation keeps the old version ---
  const fast = principals.preauthProvider();
  const cookieClient = { name: [USER] };
  const cookieAt3 = fast ? await fast.sealCookie(cookieClient,
                                                  { realm: REALM },
                                                  new Uint8Array(8)) : null;
  const rot1 = await rotation.rotate('', { reason: 'requested',
                                           actor: 'tester', via: 'api' });
  noteKeys();
  out.rot1 = { ok: rot1.ok, kvno: rot1.kvno, previousKvno: rot1.previousKvno,
               retained: (rot1.retained || []).map(function (one) {
                 return one.kvno;
               }) };
  out.tgs1AfterRot1 = await tgs(tgt1, SPN);
  const tgt2 = await as(USER, PW);
  out.tgt2Kvno = kvnoOf(tgt2);
  out.tgs2 = await tgs(tgt2, SPN);
  out.cookieAt3AfterRot1 = cookieAt3
    ? !!(await fast.openCookie(cookieClient, { realm: REALM,
                                               cookie: { value: cookieAt3 } }))
    : null;
  const armorOld = await wire.fastAsExchange(inproc, REALM, USER, tgt1,
    async function () { return []; });
  out.armorOld = { ok: armorOld.ok, armored: armorOld.armored,
                   code: armorOld.code };

  // --- the schedule's timing ---
  const now = Date.now();
  const interval = 180 * DAY;
  const d = function (state, at) {
    log.debug("Entering d().");
    log.debug("Leaving d().");
    const answer = rotation.decide(state, at, interval);
    return { due: answer.due, dueAt: answer.dueAt, first: !!answer.first };
  };
  out.decide = {
    young: d({ source: 'stored',
               rotatedAt: new Date(now - 10 * DAY).toISOString() }, now),
    old: d({ source: 'stored',
             rotatedAt: new Date(now - 181 * DAY).toISOString() }, now),
    oldButOpen: d({ source: 'stored',
                    rotatedAt: new Date(now - 181 * DAY).toISOString(),
                    windowOpenUntil: new Date(now + 3600000).toISOString() },
                  now),
    fromCreation: d({ source: 'stored', rotatedAt: '',
                      createdAt: new Date(now - 200 * DAY).toISOString() },
                    now),
    none: d({ source: 'none' }, now),
    password: d({ source: 'password' }, now)
  };
  out.decideYoungDueAt = now - 10 * DAY + interval;
  out.decideOpenDueAt = now + 3600000;
  const runNow = await rotation.rotateDue('', { nowMs: function () {
    return now;
  } });
  out.dueNow = { rotated: runNow.rotated, why: runNow.why || '' };
  // 181 days on, the rotation's kept window long past: due.
  const later = await rotation.rotateDue('', { nowMs: function () {
    return now + 181 * DAY;
  }, stillOwner: function () { return false; } });
  out.dueLater = { rotated: later.rotated, why: later.why || '' };
  out.offProduct = rotation.offReason('');
  config.setOverride('krb5.krbtgtRotationIntervalDays', 0);
  out.offInterval = rotation.offReason('');
  config.clearOverride('krb5.krbtgtRotationIntervalDays');
  config.setOverride('krb5.retainedKeyVersions', 0);
  out.offRetained = rotation.offReason('');
  config.clearOverride('krb5.retainedKeyVersions');
  const job = scheduler.job(rotation.ROTATE_JOB);
  const jobNow = scheduler.job(rotation.ROTATE_NOW_JOB);
  out.jobs = { rotate: job ? { kind: job.kind, scope: job.scope,
                               owner: job.owner } : null,
               now: jobNow ? { manualOnly: !!jobNow.manualOnly,
                               scope: jobNow.scope } : null,
               offRotate: job ? scheduler.scheduler.offReason(job, '') : 'x',
               offNow: jobNow ? scheduler.scheduler.offReason(jobNow, '')
                              : 'x' };

  // --- a second rotation inside the window keeps only the newest ---
  const cookieAt4 = fast ? await fast.sealCookie(cookieClient,
                                                  { realm: REALM },
                                                  new Uint8Array(8)) : null;
  const rot2 = await rotation.rotate('', { reason: 'requested' });
  noteKeys();
  out.rot2 = { ok: rot2.ok, kvno: rot2.kvno,
               retained: (rot2.retained || []).map(function (one) {
                 return one.kvno;
               }) };
  out.tgs1AfterRot2 = await tgs(tgt1, SPN);
  out.tgs2AfterRot2 = await tgs(tgt2, SPN);
  out.cookieAt4AfterRot2 = cookieAt4
    ? !!(await fast.openCookie(cookieClient, { realm: REALM,
                                               cookie: { value: cookieAt4 } }))
    : null;

  // --- the lifetime bound ---
  config.setOverride('krb5.retainedKeyTtlS', 1);
  await new Promise(function (resolve) {
    setTimeout(resolve, 1500);
  });
  out.tgs2Ttl1 = await tgs(tgt2, SPN);
  config.clearOverride('krb5.retainedKeyTtlS');
  out.tgs2TtlCleared = await tgs(tgt2, SPN);

  // --- rotate and invalidate, with the Shared Signals notice ---
  const notices = [];
  const Cls = rotation.KrbtgtRotation;
  const own = new Cls(Object.assign(Cls.defaultDeps(), {
    ssf: function () {
      return { kerberosTicketsInvalidated: function (n) {
        notices.push(n);
        return Promise.resolve({ sent: 0 });
      } };
    }
  }));
  const inv = await own.rotate('', { invalidate: true, reason: 'invalidated',
                                     actor: 'tester', via: 'api' });
  noteKeys();
  out.invalidate = { ok: inv.ok, kvno: inv.kvno, invalidated: inv.invalidated,
                     retained: (inv.retained || []).length };
  out.notices = notices;
  out.tgs2AfterInv = await tgs(tgt2, SPN);
  const armorGone = await wire.fastAsExchange(inproc, REALM, USER, tgt2,
    async function () { return []; });
  out.armorGone = { ok: armorGone.ok, armored: armorGone.armored,
                    code: armorGone.code,
                    recorded: recorded[recorded.length - 1] };
  out.cookieAt4AfterInv = cookieAt4
    ? !!(await fast.openCookie(cookieClient, { realm: REALM,
                                               cookie: { value: cookieAt4 } }))
    : null;
  const tgt3 = await as(USER, PW);
  out.tgt3Kvno = kvnoOf(tgt3);
  out.tgs3 = await tgs(tgt3, SPN);
  const row = events.EVENT_BY_URI[events.KERBEROS_TICKETS_INVALIDATED];
  out.eventRow = row ? row.generate({ realm: '', kerberos_realm: REALM,
                                      kvno: inv.kvno }) : null;

  // --- #245: an ordinary rotation that kept nothing is announced too ---
  // `rotateKrbtgt()` stood in for, so the realm's kvno does not move: once
  // keeping nothing (krb5.retainedKeyVersions 0), once keeping the version
  // it replaced, and once a first key that replaced nothing.
  const kept = [];
  const stand = function (result) {
    log.debug("Entering stand().");
    log.debug("Leaving stand().");
    return new Cls(Object.assign(Cls.defaultDeps(), {
      keys: function () {
        return { rotateKrbtgt: function () {
          return Promise.resolve(result);
        } };
      },
      ssf: function () {
        return { kerberosTicketsInvalidated: function (n) {
          kept.push(n);
          return Promise.resolve({ sent: 0 });
        } };
      }
    }));
  };
  await stand({ ok: true, kvno: 9, previousKvno: 8, retained: [],
                invalidated: false }).rotate('', { reason: 'requested' });
  await stand({ ok: true, kvno: 10, previousKvno: 9,
                retained: [{ kvno: 9 }], invalidated: false })
    .rotate('', { reason: 'requested' });
  await stand({ ok: true, kvno: 3, previousKvno: null, retained: [],
                invalidated: false }).rotate('', { reason: 'scheduled' });
  out.nothingRetained = kept.map(function (n) {
    return { kvno: n.kvno, reason: n.reason };
  });
  out.nothingRetainedRow = row ? row.generate({ realm: '',
    kerberos_realm: REALM, kvno: 9, reason: 'nothing-retained' }) : null;

  // --- the doors ---
  const refuse = function (result) {
    log.debug("Entering refuse().");
    log.debug("Leaving refuse().");
    return { ok: !!result.ok, code: errorCodes.codeOf(result) || '',
             text: (result.errors || []).join(' ') };
  };
  out.unconfirmed = refuse(actions.kerberosPrincipalsAction(
    { action: 'rotate-krbtgt-invalidate' }, { actor: 'tester', via: 'api' }));
  out.wrongWord = refuse(rotation.requestRotation('',
    { invalidate: true, confirm: 'yes' }));
  out.noKdc = refuse(rotation.requestRotation('no-such-realm-169', {}));
  const queued = actions.kerberosPrincipalsAction(
    { action: 'rotate-krbtgt' }, { actor: 'tester', via: 'api' });
  out.queued = { ok: queued.ok, runId: queued.runId || '',
                 queued: !!queued.queued };
  const queuedInv = actions.kerberosPrincipalsAction(
    { action: 'rotate-krbtgt-invalidate', confirm: 'invalidate' },
    { actor: 'tester', via: 'api' });
  out.queuedInv = { ok: queuedInv.ok, invalidate: !!queuedInv.invalidate };
  out.createKrbtgt = refuse(actions.kerberosPrincipalsAction(
    { action: 'create-service', spn: 'krbtgt/' + REALM },
    { actor: 'tester', via: 'api' }));
  out.rotateKrbtgtAsService = refuse(actions.kerberosPrincipalsAction(
    { action: 'rotate-service', spn: 'krbtgt/' + REALM },
    { actor: 'tester', via: 'api' }));

  // --- drop previous versions, through the service action ---
  await rotation.rotate('', { reason: 'requested' });
  noteKeys();
  const dropped = actions.kerberosPrincipalsAction(
    { action: 'drop-previous-service-keys', spn: 'krbtgt/' + REALM },
    { actor: 'tester', via: 'api' });
  out.dropped = { ok: dropped.ok, dropped: dropped.dropped,
                  retainedAfter: personKeys.krbtgtState().retained.length };

  // --- the view, and nothing leaks ---
  const viewJson = views.kerberosPrincipalsJson({ query: {} });
  out.view = viewJson.krbtgt ? { kvno: viewJson.krbtgt.kvno,
                                 source: viewJson.krbtgt.source,
                                 scheduled: viewJson.krbtgt.scheduled,
                                 nextDueAt: viewJson.krbtgt.nextDueAt,
                                 lastRotatedAt: viewJson.krbtgt.lastRotatedAt }
                             : null;
  out.krbtgtInServices = (viewJson.services || []).some(function (one) {
    return /^krbtgt\//.test(one.principal);
  });
  // A last rotation, kept, for the restart to find, and a TGT sealed under
  // the version it keeps.
  const tgt4 = await as(USER, PW);
  await rotation.rotate('', { reason: 'requested' });
  noteKeys();
  const finalState = personKeys.krbtgtState();
  out.final = { kvno: finalState.kvno,
                retained: finalState.retained.map(function (one) {
                  return one.kvno;
                }) };
  const texts = [JSON.stringify(audit.list()),
                 JSON.stringify(views.kerberosPrincipalsJson({ query: {} })),
                 realms.run(realms.DEFAULT_REALM, function () {
                   return JSON.stringify(applications.get(
                     personKeys.krbtgtIdentifier()));
                 }),
                 JSON.stringify(personKeys.krbtgtState()),
                 JSON.stringify(rotation.rotationView(''))];
  out.keysSeen = seenKeys.size;
  out.leaks = [];
  seenKeys.forEach(function (key) {
    texts.forEach(function (text, i) {
      if (text.indexOf(key) >= 0 ||
          text.indexOf(Buffer.from(key, 'base64').toString('hex')) >= 0) {
        out.leaks.push(i);
      }
    });
  });
  out.appWithheld = /withheld: Kerberos key material/.test(texts[2]);
  out.auditActions = audit.list().filter(function (one) {
    return /krbtgt/.test(String(one.action || ''));
  }).map(function (one) {
    return one.action;
  });
  fs.writeFileSync(process.env.KR_SAVED, JSON.stringify({
    tgt: encodeTgt(tgt4), spn: SPN, user: USER, password: PW,
    tgt4Kvno: kvnoOf(tgt4) }));
  await persistence.flush();
  log.debug("Leaving child(). first");
  return out;
}

if (process.argv[2] === '--child') {
  child(process.argv[3]).then(function (out) {
    fs.writeFileSync(process.env.KR_OUT, JSON.stringify(out));
    process.exit(0);
  }).catch(function (e) {
    fs.writeFileSync(process.env.KR_OUT,
                     JSON.stringify({ crashed: String(e && e.stack || e) }));
    process.exit(0);
  });
  return;
}

// ---------------------------------------------------------------------------
// THE PARENT.
// ---------------------------------------------------------------------------
function inAChild(t, phase, extra, label) {
  log.debug("Entering inAChild(). " + phase);
  const outFile = path.join(extra.dir, phase + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|SCIM_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const run = childProcess.spawnSync(process.execPath,
    [__filename, '--child', phase], {
      env: Object.assign(clean, { LOG_LEVEL: 'warn', STS_LOG_LEVEL: 'warn',
                                  KR_OUT: outFile,
                                  KR_SAVED: path.join(extra.dir,
                                                      'saved.json') },
                         extra.env),
      encoding: 'utf8', timeout: 300000, cwd: ROOT,
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
  t.check(report !== null && !report.crashed, 'the ' + label + ' child ran ' +
          'to the end', 'exit ' + run.status + ' ' +
          (report && report.crashed) + ' ' +
          String(run.stderr || '').slice(-1500));
  log.debug("Leaving inAChild().");
  return { report: report || {}, stdout: String(run.stdout || '') };
}

function productEnv(dir, kekFile) {
  log.debug("Entering productEnv().");
  log.debug("Leaving productEnv().");
  return { STS_MODE: 'product',
           // Set, and IGNORED in product since #169.
           KRB5_KRBTGT_PASSWORD: 'krbtgt-rotation-ignored-169',
           KRB5_SERVICE_PASSWORD: 'service-rotation-169',
           STS_KEYS_SOURCE: 'persisted', STS_KEYS_KEK_PROVIDER: 'file',
           STS_KEYS_KEK_FILE: kekFile, STS_PERSISTENCE_MODE: 'ldif',
           STS_PERSISTENCE_DATA_DIR: path.join(dir, 'store'),
           STS_PERSISTENCE_WRITE_DELAY: '0',
           STS_RISK_ASSESS_SIGN_INS: 'false' };
}

function product(t, dir, kekFile) {
  log.debug("Entering product().");
  t.log.info('=== A. product: a random krbtgt, rotated and invalidated ===');
  const r = inAChild(t, 'first', { dir: dir, env: productEnv(dir, kekFile) },
                     'product').report;
  const j = JSON.stringify;
  t.check(r.fromPassword === false && r.before &&
          r.before.source === 'none' && r.before.kvno === null,
          'A1. product derives no krbtgt from a password, and before the ' +
          'first start\'s creation none is stored', j([r.fromPassword,
                                                        r.before]));
  t.check(r.made && r.made.source === 'stored' && r.made.kvno === 3 &&
          r.made.sealed === true &&
          j(r.made.etypes) === j([18, 17, 20, 19]),
          'A2. ensureAll() makes one: stored, sealed, at krb5.kvno, one ' +
          'random key per enctype and no rc4-hmac', j(r.made));
  t.check(r.reasonAfter === '' && r.ensuredAgain &&
          r.ensuredAgain.existing === true,
          'A3. the KDC then has a krbtgt, and a second ensure makes nothing',
          j([r.reasonAfter, r.ensuredAgain]));
  t.check(r.userMade && r.passwordSet && r.serviceMade &&
          r.tgt1Kvno === 3 && r.tgs1 && r.tgs1.ok,
          'A4. a TGT is sealed under krbtgt kvno 3 and buys a service ticket',
          j([r.tgt1Kvno, r.tgs1]));
  t.check(r.rot1 && r.rot1.ok && r.rot1.kvno === 4 &&
          r.rot1.previousKvno === 3 && j(r.rot1.retained) === j([3]),
          'B1. a rotation: kvno 4, keeping kvno 3', j(r.rot1));
  t.check(r.tgs1AfterRot1 && r.tgs1AfterRot1.ok,
          'B2. THE OLD TGT STILL WORKS, through the previous kvno',
          j(r.tgs1AfterRot1));
  t.check(r.tgt2Kvno === 4 && r.tgs2 && r.tgs2.ok,
          'B3. a new TGT is at kvno 4', j([r.tgt2Kvno, r.tgs2]));
  t.check(r.armorOld && r.armorOld.armored === true,
          'B4. FAST armor sealed under the previous kvno is accepted (the ' +
          'answer is armored)', j(r.armorOld));
  t.check(r.cookieAt3AfterRot1 === true,
          'B5. a FAST cookie sealed under kvno 3 opens after the rotation',
          j(r.cookieAt3AfterRot1));
  const dec = r.decide || {};
  t.check(dec.young && !dec.young.due && dec.young.dueAt ===
          r.decideYoungDueAt && dec.old && dec.old.due &&
          dec.oldButOpen && !dec.oldButOpen.due &&
          dec.oldButOpen.dueAt === r.decideOpenDueAt &&
          dec.fromCreation && dec.fromCreation.due &&
          dec.none && dec.none.due && dec.none.first &&
          dec.password && !dec.password.due,
          'C1. the decision: a key 10 days old is due at 180, one 181 days ' +
          'old is due, NOT while the kept window is open (due at its end), ' +
          'age runs from creation when never rotated, a realm with no key ' +
          'is due at once, a password krbtgt is never due', j(dec));
  t.check(r.dueNow && r.dueNow.rotated === false &&
          /window/.test(r.dueNow.why),
          'C2. the job does not rotate a just-rotated key: the kept version ' +
          'is inside its window', j(r.dueNow));
  t.check(r.dueLater && r.dueLater.rotated === false &&
          /no longer owns/.test(r.dueLater.why),
          'C3. 181 days on it would, and asks stillOwner() before the act',
          j(r.dueLater));
  t.check(r.offProduct === '' && /krbtgtRotationIntervalDays is 0/.test(
    r.offInterval) && /retainedKeyVersions is 0/.test(r.offRetained),
          'C4. on in product; off with an interval of 0, and off with no ' +
          'previous version kept (an unannounced sign-out of everybody)',
          j([r.offProduct, r.offInterval, r.offRetained]));
  t.check(r.jobs && r.jobs.rotate && r.jobs.rotate.kind === 'cluster' &&
          r.jobs.rotate.scope === 'realm' &&
          r.jobs.rotate.owner === 'kerberos/krb5_krbtgt_rotation.ts' &&
          r.jobs.now && r.jobs.now.manualOnly && r.jobs.now.scope === 'realm' &&
          r.jobs.offRotate === '' && r.jobs.offNow === '',
          'C5. krb5.krbtgt-rotate is a realm-scoped cluster job and ' +
          'krb5.krbtgt-rotate-now a manual one, both on in product',
          j(r.jobs));
  t.check(r.rot2 && r.rot2.ok && r.rot2.kvno === 5 &&
          j(r.rot2.retained) === j([4]),
          'D1. a rotation by hand inside the window still happens, and keeps ' +
          'only the newest version (krb5.retainedKeyVersions 1)', j(r.rot2));
  t.check(r.tgs1AfterRot2 && !r.tgs1AfterRot2.ok &&
          r.tgs1AfterRot2.code === 44 &&
          r.tgs1AfterRot2.recorded === 'STS-KRB-0115',
          'D2. so the kvno-3 TGT is refused KRB_AP_ERR_BADKEYVER ' +
          '(STS-KRB-0115)', j(r.tgs1AfterRot2));
  t.check(r.tgs2AfterRot2 && r.tgs2AfterRot2.ok && r.cookieAt4AfterRot2,
          'D3. and the kvno-4 TGT and cookie still work',
          j([r.tgs2AfterRot2, r.cookieAt4AfterRot2]));
  t.check(r.tgs2Ttl1 && !r.tgs2Ttl1.ok && r.tgs2Ttl1.code === 44 &&
          r.tgs2TtlCleared && r.tgs2TtlCleared.ok,
          'E1. the lifetime bound: with a one-second window the kept ' +
          'version is refused, and clearing the override restores it',
          j([r.tgs2Ttl1, r.tgs2TtlCleared]));
  t.check(r.invalidate && r.invalidate.ok && r.invalidate.kvno === 6 &&
          r.invalidate.invalidated === true && r.invalidate.retained === 0,
          'F1. rotate and invalidate: kvno 6, nothing kept', j(r.invalidate));
  t.check(r.tgs2AfterInv && !r.tgs2AfterInv.ok && r.tgs2AfterInv.code === 44,
          'F2. every earlier TGT is refused KRB_AP_ERR_BADKEYVER',
          j(r.tgs2AfterInv));
  t.check(r.armorGone && r.armorGone.ok === false &&
          r.armorGone.armored === false && r.armorGone.code === 44 &&
          r.armorGone.recorded === 'STS-KRB-0164',
          'F3. FAST armor under a dropped krbtgt version is refused 44, ' +
          'unarmored (STS-KRB-0164)', j(r.armorGone));
  t.check(r.cookieAt4AfterInv === false,
          'F4. a cookie sealed under a dropped version opens to nothing — ' +
          'the clean refusal', j(r.cookieAt4AfterInv));
  t.check(r.tgt3Kvno === 6 && r.tgs3 && r.tgs3.ok,
          'F5. a fresh AS exchange gets a working TGT at kvno 6',
          j([r.tgt3Kvno, r.tgs3]));
  t.check(Array.isArray(r.notices) && r.notices.length === 1 &&
          r.notices[0].kvno === 6 && r.notices[0].kerberos_realm &&
          r.eventRow && r.eventRow.reason === 'invalidated' &&
          r.eventRow.kvno === 6,
          'F6. the invalidation is announced as this service\'s own ' +
          'kerberos-tickets-invalidated event', j([r.notices, r.eventRow]));
  t.check(Array.isArray(r.nothingRetained) &&
          JSON.stringify(r.nothingRetained) ===
            JSON.stringify([{ kvno: 9, reason: 'nothing-retained' }]) &&
          r.nothingRetainedRow &&
          r.nothingRetainedRow.reason === 'nothing-retained',
          'F7. an ORDINARY rotation that kept no previous version ' +
          '(krb5.retainedKeyVersions 0) is announced too, reason ' +
          'nothing-retained; one that kept it, and a first key, are not ' +
          '(#245)', j([r.nothingRetained, r.nothingRetainedRow]));
  t.check(r.unconfirmed && !r.unconfirmed.ok &&
          r.unconfirmed.code === 'STS-ADMIN-0610' &&
          r.wrongWord && r.wrongWord.code === 'STS-ADMIN-0610',
          'G1. rotate-krbtgt-invalidate without the typed word is refused ' +
          '(STS-ADMIN-0610)', j([r.unconfirmed, r.wrongWord]));
  t.check(r.noKdc && !r.noKdc.ok && r.noKdc.code === 'STS-KRB-0128',
          'G2. a realm with no KDC is refused (STS-KRB-0128)', j(r.noKdc));
  t.check(r.queued && r.queued.ok && r.queued.queued && r.queued.runId &&
          r.queuedInv && r.queuedInv.ok && r.queuedInv.invalidate,
          'G3. both actions QUEUE a run on the scheduler', j([r.queued,
                                                             r.queuedInv]));
  t.check(r.createKrbtgt && !r.createKrbtgt.ok &&
          r.rotateKrbtgtAsService && !r.rotateKrbtgtAsService.ok,
          'G4. krbtgt is still refused as a service principal (create, ' +
          'rotate-service): no keytab is ever made for it',
          j([r.createKrbtgt, r.rotateKrbtgtAsService]));
  t.check(r.dropped && r.dropped.ok && r.dropped.dropped === 1 &&
          r.dropped.retainedAfter === 0,
          'G5. drop-previous-service-keys takes the krbtgt and ends the ' +
          'window now', j(r.dropped));
  t.check(r.view && r.view.source === 'stored' && r.view.kvno === 7 &&
          r.view.scheduled === true && !!r.view.nextDueAt &&
          !!r.view.lastRotatedAt && r.krbtgtInServices === false,
          'H1. the view reports the kvno, the last rotation and the next ' +
          'due time, and the krbtgt is not a service row',
          j([r.view, r.krbtgtInServices]));
  t.check(r.keysSeen >= 5 && Array.isArray(r.leaks) && !r.leaks.length &&
          r.appWithheld,
          'H2. no krbtgt key, current or kept, is in the audit log, the ' +
          'console\'s JSON, the application view, the state or the rotation ' +
          'view', j([r.keysSeen, r.leaks, r.appWithheld]));
  t.check(Array.isArray(r.auditActions) &&
          r.auditActions.indexOf('krb5.krbtgt.created') >= 0 &&
          r.auditActions.indexOf('admin.krb5.krbtgt.rotated') >= 0 &&
          r.auditActions.indexOf('admin.krb5.krbtgt.invalidated') >= 0 &&
          r.auditActions.indexOf('krb5.krbtgt.rotated') >= 0,
          'H3. each act is audited: created, rotated (by the scheduler and ' +
          'by an administrator), invalidated', j(r.auditActions));
  log.debug("Leaving product().");
  return r;
}

function restart(t, dir, kekFile, first) {
  log.debug("Entering restart().");
  t.log.info('=== B. product, restarted on the same store ===');
  const r = inAChild(t, 'restart', { dir: dir, env: productEnv(dir, kekFile) },
                     'restarted product').report;
  const j = JSON.stringify;
  const final = (first && first.final) || {};
  t.check(r.restart && r.restart.source === 'stored' &&
          r.restart.kvno === final.kvno &&
          j(r.restart.retained) === j(final.retained),
          'I1. a restart restores the stored krbtgt key and its kept version',
          j([r.restart, final]));
  t.check(r.restartOldTgs && r.restartOldTgs.ok,
          'I2. a TGT from before the restart, under the kept version, still ' +
          'works', j(r.restartOldTgs));
  t.check(r.restartNewKvno === final.kvno,
          'I3. and a new TGT is sealed under the restored current key',
          j([r.restartNewKvno, final.kvno]));
  log.debug("Leaving restart().");
}

function development(t, dir) {
  log.debug("Entering development().");
  t.log.info('=== C. development: the published krbtgt, rotated by hand ===');
  const r = inAChild(t, 'development', { dir: dir, env: {} },
                     'development').report;
  const j = JSON.stringify;
  t.check(r.devBefore && r.devBefore.source === 'password' &&
          r.devBefore.kvno === 3 && r.devBefore.fromPassword === true,
          'J1. development derives krbtgt from krb5.krbtgtPassword',
          j(r.devBefore));
  t.check(/development mode/.test(r.devOff || '') && r.devOffNow === '',
          'J2. the schedule is off in development and the manual job is not',
          j([r.devOff, r.devOffNow]));
  t.check(r.devTgt1Kvno === 3 && r.devTgt1OpensWithPassword === true,
          'J3. a TGT opens with the key derived from the published password',
          j([r.devTgt1Kvno, r.devTgt1OpensWithPassword]));
  t.check(r.devRotate && r.devRotate.ok && r.devRotate.kvno === 4 &&
          r.devRotate.previousKvno === 3 &&
          j(r.devRotate.retained) === j([3]) && r.devAfter === 'stored',
          'J4. a rotation by hand stores a random key at kvno 4 and keeps ' +
          'the password-derived kvno 3', j([r.devRotate, r.devAfter]));
  t.check(r.devOldTgs && r.devOldTgs.ok,
          'J5. so the TGT sealed under the published key still works',
          j(r.devOldTgs));
  t.check(r.devTgt2Kvno === 4 && r.devTgt2OpensWithPassword === false,
          'J6. and a new TGT no longer opens with the password',
          j([r.devTgt2Kvno, r.devTgt2OpensWithPassword]));
  t.check(r.devInvalidate && r.devInvalidate.ok &&
          r.devInvalidate.kvno === 5 && r.devInvalidate.retained === 0 &&
          r.devTgs1After && r.devTgs1After.code === 44 &&
          r.devTgs2After && r.devTgs2After.code === 44,
          'J7. rotate and invalidate refuses both earlier TGTs 44',
          j([r.devInvalidate, r.devTgs1After, r.devTgs2After]));
  log.debug("Leaving development().");
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krbtgt-rotation-'));
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  try {
    const first = product(t, dir, kekFile);
    restart(t, dir, kekFile, first);
    development(t, dir);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A temporary directory left behind is litter, not a failure.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_krbtgt_rotation',
  describe: 'the krbtgt key (#169): random in product, rotated on the ' +
            'scheduler and by hand with the previous kvno kept for the TGT ' +
            'lifetime, rotate-and-invalidate, FAST armor and cookie across a ' +
            'rotation, the schedule\'s timing, the doors, no key anywhere, ' +
            'a restart, and development\'s published krbtgt',
  run: run
};
