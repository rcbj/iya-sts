// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pkcs11_kek.js
//
// ===========================================================================
// A KEY-ENCRYPTION KEY IN A HARDWARE SECURITY MODULE (#1955 P8):
// `keys.kekProvider=pkcs11`, the key a non-extractable AES-256 object in a
// PKCS#11 token that wraps and unwraps every data key inside the HSM.
//
// In a CHILD PROCESS, for `kms_kek.js`'s reason (the keystore is the
// process's, and the sections restart it), against two modules:
//
//   * a FAKE binding (`tests/tools/fake-pkcs11.js`), always: handed to
//     `secrets.js` through `setSdkLoader()` as `pkcs11js`, doing what a
//     module does with node's own cryptography, and able to offer only some
//     mechanisms (a YubiHSM 2's) and to lose its device;
//   * SOFTHSM2, where the image has it — `softhsm2-util` on the PATH, its
//     module at STS_TEST_SOFTHSM_MODULE (or the Debian path), and pkcs11js
//     resolvable at STS_TEST_PKCS11JS (or `/opt/pkcs11js`). A token is
//     initialised in a temporary directory of its own. Where any of the three
//     is missing the SoftHSM half is SKIPPED and says so: it is not a pass.
//
// Asserted:
//   A. the round trip: the data-key row holds `$dekkms$1$pkcs11$…$g1.`, never
//      the key; a restart unwraps in the HSM and every value opens; the
//      report says the key is in a KMS; no KEK bytes are held.
//   B. the stored form is versioned: data keys wrapped with KWP (`k1`) still
//      open after the mechanism moves back to GCM, and new ones are `g1`.
//   C. a YubiHSM-shaped token (no GCM, no KWP): `auto` takes the CCM wrap
//      (`y1`); a wrapped key moved to another realm's row is refused by the
//      AAD digest the wrap carries, and the start stops.
//   D. a connector restart between two starts' operations is met by the next
//      operation, which reconnects once and succeeds; a device that stays
//      away refuses the start with STS-KEYS-0201.
//   E. the refusals: a PIN the token refuses (STS-KEYS-0205), a URI carrying
//      a PIN (0205), a key that is not there (0203), made when
//      keys.pkcs11GenerateKey is on, an EXTRACTABLE key (0203), a token label
//      no slot has (0202), no module configured (0202), no binding installed
//      (STS-KEYS-0045, the package to install), a mechanism the token does
//      not offer (0204), and `rotateKek()` refused with the previousKek* way.
//   F. the three positions: moving from a file key to the HSM through
//      keys.previousKek* (every data key re-wrapped), then from one HSM key
//      to another on a second token with its own PIN (a JSON PIN map); and
//      the CELL key in the HSM, whose data keys are wrapped under it.
//   G. SoftHSM2: GCM and KWP round trips across a restart, the generated key
//      non-extractable and sensitive in the token itself.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'pkcs11_kek',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.PK_ROOT;
  const OUT = process.env.PK_OUT;
  const DIR = process.env.PK_DIR;
  const fs = require('fs');
  const nodeCrypto = require('crypto');
  const childProcess = require('child_process');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const fake = require(ROOT + '/tests/tools/fake-pkcs11.js');

  // ------------------------------------------------------------- STORE
  const rows = new Map();
  const store = {
    loadKeys: function () {
      return Promise.resolve(Array.from(rows.entries()).map(function (p) {
        return { realm: p[0], material: p[1] };
      }));
    },
    loadKey: function (key) {
      return Promise.resolve(rows.has(key) ? rows.get(key) : null);
    },
    saveKeys: function (key, text) {
      rows.set(key, text);
      return Promise.resolve();
    },
    deleteKeys: function (key) {
      rows.delete(key);
      return Promise.resolve();
    },
    mergeKeys: function (key, text, merge) {
      return Promise.resolve().then(function () {
        const current = rows.has(key) ? rows.get(key) : null;
        const next = current === null ? text : merge(current);
        if (next !== null && next !== undefined) {
          rows.set(key, next);
        }
        return { material: rows.get(key) };
      });
    }
  };

  const pinFile = DIR + '/pin';
  fs.writeFileSync(pinFile, '1234', { mode: 0o600 });
  const kekFile = DIR + '/kek';
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';

  let binding = fake.fakeBinding();
  let loaderAnswer = function () {
    return binding;
  };
  function useHsm(uri, module) {
    process.env.STS_KEYS_KEK_PROVIDER = 'pkcs11';
    process.env.STS_KEYS_KEK_REF = uri;
    process.env.STS_KEYS_PKCS11_MODULE = module || '/fake/libfake-pkcs11.so';
    process.env.STS_KEYS_PKCS11_PIN_PROVIDER = 'file';
    process.env.STS_KEYS_PKCS11_PIN_REF = pinFile;
  }
  async function refusedWith(fn) {
    try {
      await fn();
    } catch (e) {
      const m = /STS-[A-Z0-9]+-\d{4}/g;
      const all = String((e && e.message) || e).match(m) || [];
      return all.join(' ') + ' :: ' + String((e && e.message) || e)
        .slice(0, 300);
    }
    return 'not refused';
  }

  (async function () {
    const secrets = require(ROOT + '/common/secrets');
    secrets.setSdkLoader(function (name) {
      if (name === 'pkcs11js') {
        return loaderAnswer();
      }
      throw new Error('Cannot find module \'' + name + '\'');
    });
    const keystore = require(ROOT + '/common/keystore');
    async function restart() {
      await keystore.settleAll();
      keystore.reset();
      secrets.forgetHsmTokens();
      keystore.setStore(store);
      await keystore.start();
    }

    // ------------------------------------------------------------ A
    binding.addSecretKey('sts-kek');
    useHsm('pkcs11:token=sts;object=sts-kek');
    await restart();
    const v1 = keystore.seal('alpha', 'minted-rows', undefined,
                             { realm: '' });
    await keystore.settleDeks();
    const row = rows.get('dek:service:default') || '';
    note(/\$dekkms\$1\$pkcs11\$[A-Za-z0-9_-]+\$g1\./.test(row),
         'A1. the data-key row holds the HSM\'s GCM wrap', row.slice(0, 200));
    const report = keystore.report();
    note(report.kekInKms === true && report.kekKms &&
         report.kekKms.provider === 'pkcs11',
         'A2. the report says the key is in a KMS',
         JSON.stringify(report.kekKms));
    const before = binding.state.calls.length;
    await restart();
    note(binding.state.calls.slice(before).indexOf('C_DecryptInit') >= 0,
         'A3. a restart asks the HSM to unwrap');
    note(keystore.open(v1, 'minted-rows') === 'alpha',
         'A4. and every value opens');

    // ------------------------------------------------------------ B
    rows.clear();
    process.env.STS_KEYS_PKCS11_MECHANISM = 'aes-key-wrap-pad';
    await restart();
    const vK = keystore.seal('kwp', 'minted-rows', undefined, { realm: '' });
    await keystore.settleDeks();
    const kRow = rows.get('dek:service:default') || '';
    note(/\$k1\./.test(kRow), 'B1. keys.pkcs11Mechanism=aes-key-wrap-pad ' +
         'wraps with KWP', kRow.slice(0, 200));
    delete process.env.STS_KEYS_PKCS11_MECHANISM;
    await restart();
    note(keystore.open(vK, 'minted-rows') === 'kwp',
         'B2. a KWP-wrapped data key still opens with the mechanism back at ' +
         'auto (GCM): the stored form names its own');
    keystore.seal('kwp2', 'minted-rows', undefined, { realm: 'r2' });
    await keystore.settleDeks();
    note(/\$g1\./.test(rows.get('dek:service:r2') || ''),
         'B3. and a new data key is wrapped with GCM');

    // ------------------------------------------------------------ C
    rows.clear();
    binding = fake.fakeBinding({ tokens: [{ label: 'yhsm', pin: '0001pw',
      mechs: [fake.CKM.YUBICO_CCM, fake.CKM.EC_GEN, fake.CKM.ECDSA] }] });
    binding.addSecretKey('wrap-kek', { keyType: 0xd9554200 + 42 });
    fs.writeFileSync(pinFile, '0001pw');
    useHsm('pkcs11:token=yhsm;object=wrap-kek');
    await restart();
    const vY = keystore.seal('yubi', 'minted-rows', undefined, { realm: '' });
    keystore.seal('other', 'minted-rows', undefined, { realm: 'r3' });
    await keystore.settleDeks();
    const yRow = rows.get('dek:service:default') || '';
    note(/\$y1\./.test(yRow), 'C1. a token with neither GCM nor KWP (a ' +
         'YubiHSM 2) wraps with CKM_YUBICO_AES_CCM_WRAP', yRow.slice(0, 200));
    await restart();
    note(keystore.open(vY, 'minted-rows') === 'yubi',
         'C2. and it unwraps at a restart');
    // A wrapped data key moved onto another realm's row.
    const moved = JSON.parse(yRow);
    const target = JSON.parse(rows.get('dek:service:r3'));
    const sourceList = moved.deks || moved.keys || [];
    const targetList = target.deks || target.keys || [];
    let movedOk = false;
    if (Array.isArray(sourceList) && Array.isArray(targetList) &&
        sourceList[0] && targetList[0]) {
      targetList[0].wrapped = sourceList[0].wrapped;
      rows.set('dek:service:r3', JSON.stringify(target));
      movedOk = true;
    }
    const cMoved = await refusedWith(restart);
    note(movedOk && /STS-KEYS-0091/.test(cMoved),
         'C3. a CCM-wrapped data key moved to another realm\'s row is ' +
         'refused by the AAD digest, and the start stops', cMoved);

    // ------------------------------------------------------------ D
    rows.clear();
    binding = fake.fakeBinding();
    binding.addSecretKey('sts-kek');
    fs.writeFileSync(pinFile, '1234');
    useHsm('pkcs11:token=sts;object=sts-kek');
    await restart();
    const vD = keystore.seal('delta', 'minted-rows', undefined,
                             { realm: '' });
    await keystore.settleDeks();
    // The connector restarts: the token this process holds lost every
    // session. The keystore restart reuses no token (forgetHsmTokens), so
    // the loss is met by the held token BEFORE the restart: a wrap of a new
    // data key on the same token.
    binding.loseDevice();
    keystore.seal('delta2', 'minted-rows', undefined, { realm: 'r4' });
    let dError = '';
    try {
      await keystore.settleDeks();
    } catch (e) {
      dError = String((e && e.message) || e);
    }
    const dRow = rows.get('dek:service:r4') || '';
    note(!dError && /\$g1\./.test(dRow),
         'D1. a connector restart is met by the next operation, which ' +
         'reconnects once and wraps', dError || dRow.slice(0, 120));
    await restart();
    note(keystore.open(vD, 'minted-rows') === 'delta',
         'D2. and the values open at the next start');
    binding.breakAlways(true);
    const dDown = await refusedWith(restart);
    note(/STS-KEYS-0202|STS-KEYS-0201/.test(dDown),
         'D3. a device that stays away refuses the start', dDown);
    binding.breakAlways(false);

    // ------------------------------------------------------------ E
    fs.writeFileSync(pinFile, '9999');
    const ePin = await refusedWith(restart);
    note(/STS-KEYS-0205/.test(ePin), 'E1. a PIN the token refuses stops the ' +
         'start', ePin);
    fs.writeFileSync(pinFile, '1234');
    useHsm('pkcs11:token=sts;object=sts-kek;pin-value=1234');
    const eUri = await refusedWith(restart);
    note(/STS-KEYS-0205/.test(eUri) && !/1234/.test(eUri.split('::')[1]),
         'E2. a URI carrying a PIN is refused, without repeating it', eUri);
    useHsm('pkcs11:token=sts;object=absent');
    const eAbsent = await refusedWith(restart);
    note(/STS-KEYS-0203/.test(eAbsent), 'E3. a key the token does not hold ' +
         'stops the start', eAbsent);
    process.env.STS_KEYS_PKCS11_GENERATE_KEY = 'true';
    rows.clear();
    await restart();
    const made = Array.from(binding.state.tokens[0].objects.values())
      .filter(function (o) {
        return o.attrs.get(0x3) && o.attrs.get(0x3).toString() === 'absent';
      })[0];
    note(made && made.attrs.get(0x162)[0] === 0 &&
         made.attrs.get(0x103)[0] === 1,
         'E4. with keys.pkcs11GenerateKey on it is made: sensitive and NOT ' +
         'extractable');
    delete process.env.STS_KEYS_PKCS11_GENERATE_KEY;
    binding.addSecretKey('leaky', { extractable: true });
    useHsm('pkcs11:token=sts;object=leaky');
    const eLeaky = await refusedWith(restart);
    note(/STS-KEYS-0203/.test(eLeaky) && /EXTRACTABLE/.test(eLeaky),
         'E5. an extractable key is refused', eLeaky);
    useHsm('pkcs11:token=nosuch;object=sts-kek');
    const eToken = await refusedWith(restart);
    note(/STS-KEYS-0202/.test(eToken), 'E6. a token label no slot has stops ' +
         'the start', eToken);
    useHsm('pkcs11:token=sts;object=sts-kek');
    process.env.STS_KEYS_PKCS11_MODULE = '';
    const eModule = await refusedWith(restart);
    note(/STS-KEYS-0202/.test(eModule), 'E7. no module configured stops the ' +
         'start', eModule);
    useHsm('pkcs11:token=sts;object=sts-kek');
    loaderAnswer = function () {
      throw new Error('Cannot find module \'pkcs11js\'');
    };
    const eSdk = await refusedWith(restart);
    note(/STS-KEYS-0045/.test(eSdk) && /pkcs11js/.test(eSdk),
         'E8. no binding installed names the package to install', eSdk);
    loaderAnswer = function () {
      return binding;
    };
    process.env.STS_KEYS_PKCS11_MECHANISM = 'yubico-aes-ccm-wrap';
    binding.state.tokens[0].mechs.delete(fake.CKM.YUBICO_CCM);
    const eMech = await refusedWith(restart);
    note(/STS-KEYS-0204/.test(eMech), 'E9. a mechanism the token does not ' +
         'offer stops the start', eMech);
    delete process.env.STS_KEYS_PKCS11_MECHANISM;
    rows.clear();
    await restart();
    const eRot = await keystore.rotateKek();
    note(eRot.ok === false && /previousKek/.test(eRot.why),
         'E10. rotateKek() is refused with the keys.previousKek* way',
         JSON.stringify(eRot));

    // ------------------------------------------------------------ F
    rows.clear();
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    delete process.env.STS_KEYS_KEK_REF;
    await restart();
    const vF = keystore.seal('file', 'minted-rows', undefined, { realm: '' });
    await keystore.settleDeks();
    useHsm('pkcs11:token=sts;object=sts-kek');
    process.env.STS_PREVIOUS_KEK_PROVIDER = 'file';
    process.env.STS_PREVIOUS_KEK_REF = kekFile;
    await restart();
    await keystore.settleDeks();
    note(keystore.open(vF, 'minted-rows') === 'file' &&
         /\$dekkms\$1\$pkcs11\$/.test(rows.get('dek:service:default') || ''),
         'F1. with the file key as the previous one, every data key is ' +
         're-wrapped in the HSM');
    delete process.env.STS_PREVIOUS_KEK_PROVIDER;
    delete process.env.STS_PREVIOUS_KEK_REF;
    // To ANOTHER token, with a PIN of its own: a JSON map of PINs.
    binding = fake.fakeBinding({ tokens: [{ label: 'sts', pin: '1234' },
                                          { label: 'new', pin: '5678' }] });
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    delete process.env.STS_KEYS_KEK_REF;
    rows.clear();
    binding.addSecretKey('sts-kek');
    binding.addSecretKey('new-kek', { slot: 1 });
    fs.writeFileSync(pinFile, JSON.stringify({ sts: '1234', new: '5678' }));
    useHsm('pkcs11:token=sts;object=sts-kek');
    await restart();
    const vF2 = keystore.seal('hsm-a', 'minted-rows', undefined,
                              { realm: '' });
    await keystore.settleDeks();
    useHsm('pkcs11:token=new;object=new-kek');
    process.env.STS_PREVIOUS_KEK_PROVIDER = 'pkcs11';
    process.env.STS_PREVIOUS_KEK_REF = 'pkcs11:token=sts;object=sts-kek';
    await restart();
    await keystore.settleDeks();
    const f3Row = rows.get('dek:service:default') || '';
    const newRef = Buffer.from('token=new;object=new-kek').toString(
      'base64url');
    note(keystore.open(vF2, 'minted-rows') === 'hsm-a' &&
         f3Row.indexOf('$dekkms$1$pkcs11$' + newRef + '$') >= 0,
         'F3. from one HSM key to another on a second token, its PIN from ' +
         'a JSON map: every data key re-wrapped under the new key',
         f3Row.slice(0, 200));
    delete process.env.STS_PREVIOUS_KEK_PROVIDER;
    delete process.env.STS_PREVIOUS_KEK_REF;
    // THE CELL KEY in the HSM (the second token).
    useHsm('pkcs11:token=sts;object=sts-kek');
    process.env.STS_CELL_KEK_PROVIDER = 'pkcs11';
    process.env.STS_CELL_KEK_REF = 'pkcs11:token=new;object=new-kek';
    rows.clear();
    await restart();
    note(keystore.hasCellKek(), 'F4. keys.cellKekProvider=pkcs11 is held as ' +
         'the cell key');
    const vCell = keystore.seal('cellular', 'minted-rows', 'cell',
                                { realm: '' });
    await keystore.settleDeks();
    const cellRows = Array.from(rows.keys()).filter(function (k) {
      return /^dek:cell\./.test(k);
    });
    const cellRow = cellRows.length ? rows.get(cellRows[0]) : '';
    note(cellRow.indexOf('$dekkms$1$pkcs11$' + newRef + '$') >= 0,
         'F5. and the cell\'s data keys are wrapped under the cell\'s HSM key',
         cellRows.join(',') + ' ' + String(cellRow).slice(0, 160));
    await restart();
    note(keystore.open(vCell, 'minted-rows') === 'cellular',
         'F6. and open at a restart');
    process.env.STS_CELL_KEK_REF = 'pkcs11:token=sts;object=sts-kek';
    const fSame = await refusedWith(restart);
    note(/STS-CELL-0011|STS-CELL-0012/.test(fSame),
         'F7. a cell key that is the service HSM key is refused', fSame);
    delete process.env.STS_CELL_KEK_PROVIDER;
    delete process.env.STS_CELL_KEK_REF;

    // ------------------------------------------------------------ G
    const softModule = process.env.STS_TEST_SOFTHSM_MODULE ||
                       '/usr/lib/softhsm/libsofthsm2.so';
    const pkcs11jsAt = process.env.STS_TEST_PKCS11JS ||
                       '/opt/pkcs11js/node_modules/pkcs11js';
    let haveUtil = false;
    try {
      childProcess.execFileSync('softhsm2-util', ['--version'],
                                { stdio: 'ignore' });
      haveUtil = true;
    } catch (e) {
      haveUtil = false;
    }
    let realBinding = null;
    try {
      realBinding = require(pkcs11jsAt);
    } catch (e) {
      realBinding = null;
    }
    if (!haveUtil || !fs.existsSync(softModule) || !realBinding) {
      note(true, 'G0. SKIPPED, NOT PASSED: no SoftHSM2 here (softhsm2-util ' +
           (haveUtil ? 'found' : 'missing') + ', module ' +
           (fs.existsSync(softModule) ? 'found' : 'missing') +
           ', pkcs11js ' + (realBinding ? 'found' : 'missing') + ')');
    } else {
      const conf = DIR + '/softhsm2.conf';
      fs.mkdirSync(DIR + '/tokens');
      fs.writeFileSync(conf, 'directories.tokendir = ' + DIR + '/tokens\n' +
                       'objectstore.backend = file\n');
      process.env.SOFTHSM2_CONF = conf;
      childProcess.execFileSync('softhsm2-util', ['--init-token', '--free',
        '--label', 'soft', '--so-pin', '5678', '--pin', '4321'],
        { stdio: 'ignore', env: process.env });
      loaderAnswer = function () {
        return realBinding;
      };
      fs.writeFileSync(pinFile, '4321');
      rows.clear();
      useHsm('pkcs11:token=soft;object=soft-kek', softModule);
      process.env.STS_KEYS_PKCS11_GENERATE_KEY = 'true';
      await restart();
      delete process.env.STS_KEYS_PKCS11_GENERATE_KEY;
      const vG = keystore.seal('soft', 'minted-rows', undefined,
                               { realm: '' });
      await keystore.settleDeks();
      note(/\$g1\./.test(rows.get('dek:service:default') || ''),
           'G1. SoftHSM2: auto wraps with GCM');
      await restart();
      note(keystore.open(vG, 'minted-rows') === 'soft',
           'G2. SoftHSM2: and unwraps at a restart');
      process.env.STS_KEYS_PKCS11_MECHANISM = 'aes-key-wrap-pad';
      await restart();
      const vGk = keystore.seal('soft-kwp', 'minted-rows', undefined,
                                { realm: 'g2' });
      await keystore.settleDeks();
      note(/\$k1\./.test(rows.get('dek:service:g2') || ''),
           'G3. SoftHSM2: KWP through C_WrapKey');
      delete process.env.STS_KEYS_PKCS11_MECHANISM;
      await restart();
      note(keystore.open(vGk, 'minted-rows') === 'soft-kwp' &&
           keystore.open(vG, 'minted-rows') === 'soft',
           'G4. SoftHSM2: both open at a restart');
      const listed = childProcess.execFileSync('softhsm2-util',
        ['--show-slots'], { encoding: 'utf8', env: process.env });
      void listed;
      const token = await secrets.openHsmToken(
        secrets.parsePkcs11Uri('pkcs11:token=soft;object=soft-kek'));
      const found = token.find([{ type: 0x3, value: 'soft-kek' }]);
      const a = token.attributes(found[0], [0x162, 0x103]);
      note(found.length === 1 && a.get(0x162)[0] === 0 &&
           a.get(0x103)[0] === 1,
           'G5. SoftHSM2: the generated key is not extractable and is ' +
           'sensitive, in the token itself');
    }
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-pkcs11-'));
  const out = path.join(dir, 'findings.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_(?!TEST_)|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', PK_ROOT: ROOT,
                                  PK_OUT: out, PK_DIR: dir }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), 'the child process reported its ' +
                                       'findings',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-1500))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pkcs11_kek',
  describe: 'a key-encryption key in a PKCS#11 HSM wrapping every data ' +
            'encryption key: GCM, KWP and the YubiHSM CCM wrap, a ' +
            'reconnect, the refusals, the three positions, and SoftHSM2 ' +
            'where the image has it',
  run: run
};
