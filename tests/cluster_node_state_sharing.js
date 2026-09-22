'use strict';
//
// File: cluster_node_state_sharing.js
//
// ===========================================================================
// STATE ONE NODE MADE AND ANOTHER NODE HAS TO READ (2026-09-14, #46).
//
// The suite's `cluster` mode — two single-process nodes behind a balancer
// that opens a new connection per request — found three things that were
// right in one process and wrong in two, each because the state never left the
// process that made it:
//
//   1. THE BBS KEY PAIR. Made per process and handed only to that process's
//      request workers, so `/bbs/keys/1` published a different key on each
//      node and a bbs-2023 proof issued through one did not verify against the
//      key resolved through the other (`ldp_vc_issuance`, `ldp_vc_refresh`,
//      `vc_did`). It was a declared cluster secret from then until 2026-09-22
//      (#49 P5); it is a member of each realm's key set now, which is what
//      this section holds.
//   2. THE PENDING ENROLMENTS. `credentials.js`'s pending TOTP secret,
//      pending recovery-code set and pending security-key challenge were
//      undeclared stores, so a setup begun on one node found nothing on the
//      next (`sts_portal_totp`, `sts_portal_backup_codes`,
//      `sts_portal_directory_attributes`, `sts_step_up`,
//      `sts_portal_backup_keys`). Now persisted — sealed rows.
//   3. THE PARTIES A SESSION SIGNED INTO. Recorded by an in-place edit of the
//      session object, which the store does not journal, so identity-provider
//      initiated SAML logout on the other node offered no LogoutRequest
//      (`sts_saml_encryption`). Now `authn.noteSessionChanged()` re-sets the
//      row.
//
// TWO REAL PROCESSES AND ONE STORE. Each "node" is a child process of this
// file, and the store they share is a JSON file behind a stub driver with the
// four functions the code under test calls (`saveMinted`, `readMinted`,
// `loadMinted`, `ensureSharedSecret`), under one key-encryption key file —
// which is what two containers against one postgres and one KEK are, minus the
// SQL. Node A makes; node B applies A's rows the way replication does
// (`persistence_minted.applyChange()`) and must be able to finish what A
// started. Every section carries its CONTROL, run in the same children: the
// same act without the fix, which must fail, so a pass means the fix and not
// the probe.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'cluster_node_state_sharing',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_TEST_NODE_STATE_CHILD';

// ---------------------------------------------------------------------------
// THE SHARED STORE: one JSON file, read and written whole per call. The
// children never run at once, so the file needs no lock.
// ---------------------------------------------------------------------------
function fileStore(file) {
  log.debug("Entering fileStore().");
  const read = function () {
    try {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      log.debug("Caught in read(): " + ((e && e.message) || e));
      return { minted: {}, secrets: {} };
    }
  };
  const write = function (db) {
    fs.writeFileSync(file, JSON.stringify(db));
  };
  const idOf = function (handle, realm, key) {
    return handle + '\n' + realm + '\n' + key;
  };
  log.debug("Leaving fileStore().");
  return {
    loadMinted: function () {
      return Promise.resolve(Object.values(read().minted));
    },
    saveMinted: function (upserts, deletes) {
      const db = read();
      (upserts || []).forEach(function (row) {
        db.minted[idOf(row.handle, row.realm, row.key)] = {
          handle: row.handle, realm: row.realm, key: row.key, body: row.body,
          written_ms: Date.now() };
      });
      (deletes || []).forEach(function (row) {
        delete db.minted[idOf(row.handle, row.realm, row.key)];
      });
      write(db);
      return Promise.resolve({ refused: [], merged: [] });
    },
    readMinted: function (handle, realm, key) {
      return Promise.resolve(read().minted[idOf(handle, realm, key)] || null);
    },
    ensureSharedSecret: function (name, material) {
      const db = read();
      if (!db.secrets[name]) {
        db.secrets[name] = material;
        write(db);
      }
      return Promise.resolve({ material: db.secrets[name] });
    },
    // What node B applies: every minted row as the change replication would
    // hand it — base64url(handle) + '.' + base64url(key).
    changes: function () {
      return Object.values(read().minted).map(function (row) {
        return { realm: row.realm,
                 key: Buffer.from(row.handle, 'utf8').toString('base64url') +
                      '.' +
                      Buffer.from(row.key, 'utf8').toString('base64url') };
      });
    },
    raw: function () {
      return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    }
  };
}

// A directory with just the hooks the three enrolments reach.
function fakeDirectory() {
  log.debug("Entering fakeDirectory().");
  const held = { totp: {}, codes: {}, keys: {} };
  log.debug("Leaving fakeDirectory().");
  return {
    held: held,
    readPassword: function () { return ''; },
    writePassword: function () { return true; },
    readTotp: function (name) { return held.totp[name] || ''; },
    writeTotp: function (name, value) {
      held.totp[name] = value;
      return true;
    },
    readBackupCodes: function (name) { return held.codes[name] || ''; },
    writeBackupCodes: function (name, value) {
      held.codes[name] = value;
      return true;
    },
    readWebauthn: function (name) { return held.keys[name] || []; },
    writeWebauthn: function (name, value) {
      held.keys[name] = value;
      return true;
    }
  };
}

// ---------------------------------------------------------------------------
// ONE NODE. `role` is 'a' (makes) or 'b' (applies and finishes).
// ---------------------------------------------------------------------------
async function node(role, storeFile, kekFile) {
  log.debug("Entering node(). role=" + role);
  const out = {};
  // SEVERAL PROCESSES ANSWERING ONE ADDRESS, in development mode, with a real
  // KEK: `persistence_minted.enabled()`'s third arm, which is what a cluster
  // node and a dispatched container both are.
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  process.env.STS_WORKERS_REQUEST_COUNT = '1';
  process.env.STS_WORKERS_DISPATCH = '*';
  const store = fileStore(storeFile);
  const keystore = require('../common/keystore');
  keystore.reset();
  keystore.setStore({
    loadKeys: function () { return Promise.resolve([]); },
    saveKeys: function () { return Promise.resolve(); },
    deleteKeys: function () { return Promise.resolve(); }
  });
  await keystore.start();
  out.sealed = keystore.sealed() && !keystore.hasEphemeralKek();
  const config = require('../common/config');
  config.setOverride('persistence.minted', true);

  // ---- 1. the BBS pair ----------------------------------------------------
  // A MEMBER OF THE REALM'S KEY SET since 2026-09-22 (#49 P5), where it was
  // the cluster secret `bbs-keypair`: it reaches every node and every worker
  // the way the set does, so what is asserted here is that it IS on the set,
  // travels in the serialised blob every node reads, and that the secret
  // table no longer carries it.
  const persistence = require('../persistence/persistence');
  const helpers = require('../common/helpers');
  const clusterSecrets = require('../cluster/cluster_secrets');
  persistence.clusterStore = function () { return store; };
  await clusterSecrets.start(keystore);
  const pair = await helpers.bbsKeyPair();
  out.bbsPublic = Buffer.from(pair.publicKey).toString('hex');
  const set = helpers.stsKeysFor();
  out.bbsOnSet = !!(set.bbsKey && Buffer.from(set.bbsKey.publicKey)
    .toString('hex') === out.bbsPublic);
  const blob = keystore.serialise(set);
  out.bbsInBlob = !!(blob.bbsKey && Buffer.from(blob.bbsKey.publicKey,
                                                'base64')
    .toString('hex') === out.bbsPublic);
  out.bbsUnit = helpers.signingUnitsOf(set).some(function (u) {
    return u.unit === helpers.BBS_UNIT;
  });
  out.bbsSecretGone = !clusterSecrets.describe().secrets.some(function (one) {
    return one.name === 'bbs-keypair';
  });

  // ---- 2 and 3: minted rows ----------------------------------------------
  const minted = require('../persistence/persistence_minted');
  minted.reset();
  minted.setDriver(store, 'postgres');
  out.mintedEnabled = minted.enabled();
  const credentials = require('../common/credentials');
  const directory = fakeDirectory();
  credentials.setDirectory(directory);
  const authn = require('../authn/authn');
  const totp = require('../common/totp');

  if (role === 'a') {
    const began = credentials.beginTotpEnrolment('alice');
    out.totpSecret = began.secret;
    const codes = credentials.beginBackupCodes('alice');
    out.codesHandle = codes.handle;
    out.firstCode = (codes.codes || [])[0] || '';
    const key = credentials.beginKeyEnrolment('alice', { role: 'mfa' });
    out.challenge = key.challenge;
    out.began = [began.ok, codes.ok, key.ok];

    // Two sessions, each written, then each given a SAML service provider
    // by an in-place edit — one told to the store, one not (the control).
    const far = Date.now() + 3600 * 1000;
    ['sid-told', 'sid-untold'].forEach(function (id) {
      authn.sessions.set(id, { id: id, chosen: true, authenticated: true,
                               authTime: 1, user: { username: 'alice' },
                               expires: far, lastSeenAt: Date.now() });
    });
    await minted.flush();
    ['sid-told', 'sid-untold'].forEach(function (id) {
      const session = authn.sessions.get(id);
      session.saml2ServiceProviders = { 'urn:sp:probe': { at: Date.now() } };
    });
    out.untoldDirty = minted.dirty();
    out.told = authn.noteSessionChanged(authn.sessions.get('sid-told'));
    out.goneRefused = authn.noteSessionChanged({ id: 'sid-never' }) ===
                      false && !authn.sessions.has('sid-never');
    await minted.flush();
    out.rawHoldsSecret = store.raw().indexOf(out.totpSecret) >= 0 ||
                         (out.firstCode &&
                          store.raw().indexOf(out.firstCode) >= 0);
  } else {
    const changes = store.changes();
    for (const change of changes) {
      await minted.applyChange(change);
    }
    out.applied = changes.length;
    const pendingTotp = credentials.pendingTotpFor('alice');
    out.totpSecret = pendingTotp ? pendingTotp.secret : '';
    if (pendingTotp) {
      const code = totp.codeAt(pendingTotp.secret, Date.now(),
                               { period: pendingTotp.period,
                                 digits: pendingTotp.digits,
                                 algorithm: pendingTotp.algorithm });
      const confirmed = credentials.confirmTotpEnrolment('alice', code);
      out.totpConfirmed = !!confirmed.ok &&
                          !!directory.held.totp.alice;
      out.totpGoneAfter = !credentials.pendingTotpFor('alice');
    }
    out.codesHandle = process.env.PROBE_HANDLE || '';
    const pendingCodes = credentials.pendingBackupCodesFor('alice',
                                                           out.codesHandle);
    out.codesPending = !!pendingCodes;
    if (pendingCodes) {
      const stored = credentials.confirmBackupCodes('alice', out.codesHandle);
      out.codesConfirmed = !!stored.ok && !!directory.held.codes.alice;
    }
    const pendingKey = credentials.pendingKeyEnrolmentFor('alice');
    out.challenge = pendingKey ? pendingKey.challenge : '';
    const told = authn.sessions.get('sid-told');
    const untold = authn.sessions.get('sid-untold');
    out.toldHasSp = !!(told && told.saml2ServiceProviders &&
                       told.saml2ServiceProviders['urn:sp:probe']);
    out.untoldHasSp = !!(untold && untold.saml2ServiceProviders &&
                         untold.saml2ServiceProviders['urn:sp:probe']);
    out.untoldPresent = !!untold;
    await minted.flush();
    out.deletesReachStore = store.raw().indexOf(
      'credentials.pendingTotp') < 0;
  }
  log.debug("Leaving node().");
  return out;
}

async function childMain() {
  log.debug("Entering childMain().");
  delete process.env.CONFIG_FILE;
  let result = {};
  try {
    result = await node(process.env.PROBE_ROLE, process.env.PROBE_STORE,
                        process.env.PROBE_KEK);
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    result = { threw: (e && e.stack) || String(e) };
  }
  fs.writeFileSync(process.env.PROBE_OUT, JSON.stringify(result));
  log.debug("Leaving childMain().");
  process.exit(0);
}

function runNode(t, role, dir, extra) {
  log.debug("Entering runNode(). role=" + role);
  const outFile = path.join(dir, 'out-' + role + '.json');
  const env = Object.assign({}, process.env, extra || {}, {
    PROBE_OUT: outFile, PROBE_ROLE: role,
    PROBE_STORE: path.join(dir, 'store.json'),
    PROBE_KEK: path.join(dir, 'kek'),
    LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000 });
  try {
    const result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    if (result.threw) {
      t.bad('node ' + role + ' threw', result.threw);
    }
    log.debug("Leaving runNode().");
    return result;
  } catch (e) {
    log.debug("Caught in runNode(): " + ((e && e.message) || e));
    t.bad('node ' + role + ' reported nothing',
          'status ' + child.status + ', signal ' + child.signal + ': ' +
          String(child.stderr || '').slice(-2000));
    log.debug("Leaving runNode().");
    return {};
  }
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-node-state-'));
  try {
    fs.writeFileSync(path.join(dir, 'kek'),
                     nodeCrypto.randomBytes(32).toString('base64'),
                     { encoding: 'utf8', mode: 0o600 });
    const a = runNode(t, 'a', dir);
    const b = runNode(t, 'b', dir, { PROBE_HANDLE: a.codesHandle || '' });

    t.log.info('=== 1. the BBS key is a member of the realm\'s key set ===');
    t.check(a.sealed && b.sealed && a.mintedEnabled && b.mintedEnabled,
            'both nodes hold the one real key-encryption key and write ' +
            'minted state — the arrangement a cluster node has',
            JSON.stringify({ a: [a.sealed, a.mintedEnabled],
                             b: [b.sealed, b.mintedEnabled] }));
    t.check(a.bbsOnSet && b.bbsOnSet && a.bbsInBlob && b.bbsInBlob,
            'THE BBS PAIR IS ON THE REALM\'S KEY SET AND IN THE BLOB EVERY ' +
            'NODE AND WORKER READS (#49 P5) — so it is agreed the way every ' +
            'member is, and rotates with the set',
            JSON.stringify({ a: [a.bbsOnSet, a.bbsInBlob],
                             b: [b.bbsOnSet, b.bbsInBlob] }));
    t.check(a.bbsUnit && b.bbsUnit,
            'and it is the signing unit bbs:BBS, with generations');
    t.check(a.bbsSecretGone && b.bbsSecretGone,
            'and the cluster secret bbs-keypair that carried it is gone');

    t.log.info('=== 2. an enrolment begun on A is finished on B ===');
    t.check((a.began || []).every(Boolean),
            'node A began a TOTP enrolment, a recovery-code set and a ' +
            'security-key enrolment', JSON.stringify(a.began));
    t.check(b.applied > 0, 'node B applied node A\'s rows',
            String(b.applied));
    t.check(!!a.totpSecret && a.totpSecret === b.totpSecret,
            'THE PENDING TOTP SECRET A SHOWED IS THE ONE B HOLDS — ' +
            '/portal/mfa draws the QR code on whichever node answers');
    t.check(b.totpConfirmed === true,
            'and a code from it CONFIRMS the enrolment on B');
    t.check(b.totpGoneAfter === true && b.deletesReachStore === true,
            'and the confirmation removed the pending row from the store too');
    t.check(b.codesPending === true && b.codesConfirmed === true,
            'THE PENDING RECOVERY-CODE SET A GENERATED IS CONFIRMED ON B');
    t.check(!!a.challenge && a.challenge === b.challenge,
            'THE SECURITY-KEY CHALLENGE A MINTED IS THE ONE B EXPECTS — ' +
            '/portal/keys arms the ceremony on whichever node answers');
    t.check(a.rawHoldsSecret === false,
            'and none of it reached the store in the clear: the TOTP secret ' +
            'and the codes are inside sealed rows');

    t.log.info('=== 3. a party a session signed into reaches every node ===');
    t.check(a.untoldDirty === false,
            'CONTROL: an in-place edit of a session journals nothing — the ' +
            'bug, observed before the fix is applied to it');
    t.check(a.told === true && b.toldHasSp === true,
            'A SERVICE PROVIDER RECORDED ON A AND TOLD TO THE STORE IS ON ' +
            'B\'S COPY — so B\'s /saml2/slo offers its LogoutRequest');
    t.check(b.untoldPresent === true && b.untoldHasSp === false,
            'CONTROL: the same edit NOT told to the store is absent on B, ' +
            'which is what identity-provider-initiated logout saw');
    t.check(a.goneRefused === true,
            'and noteSessionChanged() never creates a session that is not ' +
            'there — a session ended meanwhile stays ended');
    const sites = [
      ['saml/saml2_sso.ts', 'session.saml2ServiceProviders[ctx.spEntityId]'],
      ['saml/saml11_sso.ts', 'session.saml11RelyingParties[ctx.rpId]'],
      ['ws-federation/wsfed.ts', 'session.wsfedRealms[realm] = wreply;'],
      ['oauth-oidc/frontchannel_logout.ts', 'session.oidcClients[clientId]']
    ];
    const missing = sites.filter(function (site) {
      const text = fs.readFileSync(path.join(ROOT, site[0]), 'utf8');
      const at = text.indexOf(site[1]);
      return at < 0 ||
             text.slice(at, at + 1200).indexOf('noteSessionChanged(') < 0;
    }).map(function (site) { return site[0]; });
    t.equal(missing.join(', '), '',
            'EVERY PROTOCOL THAT RECORDS A PARTY ON THE SESSION TELLS THE ' +
            'STORE right after it — SAML 2.0, SAML 1.1, WS-Federation and ' +
            'Front-Channel Logout');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'cluster_node_state_sharing',
  describe: 'issue #46: the BBS key pair, pending enrolments and a ' +
            'session\'s signed-into parties, made on one node and read on ' +
            'another',
  run: run
};
