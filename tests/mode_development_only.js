'use strict';
//
// File: mode_development_only.js
//
// ===========================================================================
// THE DEVELOPMENT-ONLY SETTINGS ARE IGNORED, AND REFUSED, IN PRODUCT (#104).
//
// Five settings exist to make this service wrong or loose on purpose, and
// product mode honoured four of them:
//
//   * `oauth2.breakIdTokenNonce` — a wrong nonce in every ID Token;
//   * `ssf.breakSetSignature`    — one character of every SET's signature
//                                  changed;
//   * `ssf.legacySubClaim`       — the `sub` claim RFC 8417 discourages;
//   * `spiffe.attestWorkloads` OFF — every Workload API caller handed every
//                                  registration entry;
//   * `spiffe.acceptAssertedSelectors` — already ignored in product by #40,
//                                  and not refused on write.
//
// Each row now carries `onlyWhile` naming a `common/mode.js` predicate, and
// this file holds them to both halves of the rule:
//
//   A. THE WRITE. In product a write of a value other than the default is
//      refused (STS-CORE-0103) by `config.setOverride()` and
//      `config.checkWrite()` — every console and API door writes through one
//      or the other — while `checkOverride()`, what a STORED value is restored
//      through, is not; the default is always accepted, and development
//      accepts both.
//   B. THE READ, which is the guard, because `global.mode` can be switched at
//      runtime with a value still stored. In a CHILD PROCESS, so that the
//      directory, the SSF signer and the SPIFFE registry it loads are nobody
//      else's: each switch is honoured in development — the ID Token's nonce
//      is spoiled, the SET does not verify and carries `sub`, asserted
//      selectors are believed, and a caller matching no entry is handed every
//      entry — and IGNORED in product with the same values still stored;
//      each ignored setting is logged ONCE, however often it is read
//      (STS-CORE-0106); and back in development the switches work again.
//   C. `mode.report()` carries the new requirements.
//
// The SPIRE Server API's `local` socket is `spiffe_local_socket.js`; the same
// refusals over HTTP are `tests/vendored/sts_development_only_settings.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'mode_development_only',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Each marked row and the value that is refused in product.
const MARKED = [
  { key: 'oauth2.breakIdTokenNonce', refused: true },
  { key: 'ssf.breakSetSignature', refused: true },
  { key: 'ssf.legacySubClaim', refused: true },
  { key: 'spiffe.acceptAssertedSelectors', refused: true },
  { key: 'spiffe.attestWorkloads', refused: false }
];

// THE CHILD'S PROGRAM: every read site, in development, in product with the
// values still stored, and back. Runs in the child only, which the code style
// exempts from the Entering/Leaving lines.
function childProgram(root) {
  const config = require(root + '/common/config');
  require(root + '/common/app');
  require(root + '/ldap/ldap_server');
  const oauth2 = require(root + '/oauth-oidc/oauth2');
  const events = require(root + '/ssf/ssf_events');
  const auth = require(root + '/spiffe/spiffe_auth');
  const workload = require(root + '/spiffe/spiffe_workload');
  const registry = require(root + '/spiffe/spiffe_registry');
  const ca = require(root + '/spiffe/spiffe_ca');
  const set = function (key, value) {
    const result = config.setOverride(key, value);
    if (!result.ok) {
      throw new Error('setting ' + key + ' was refused: ' +
                      result.errors.join(' '));
    }
  };
  const part = function (token, n) {
    return JSON.parse(Buffer.from(String(token).split('.')[n], 'base64url')
                        .toString('utf8'));
  };
  const observe = async function () {
    const idToken = await oauth2.idToken('https://sts.test',
      { client_id: 'mode-dev-only-client', username: 'alice',
        nonce: 'n-104' });
    const claims = events.buildSet({
      uri: events.SSF_PREFIX + 'verification', issuer: 'https://sts.test',
      audience: 'https://receiver.test',
      subject: { format: 'iss_sub', iss: 'https://i.example',
                 sub: 'u-104' } });
    const set = await events.signSet(claims);
    const verified = events.verifySet(set, part(set, 0));
    const entries = workload.entitledEntries(
      { selectors: [{ type: 'transport', value: 'no-match-104' }] });
    return { nonce: part(idToken, 1).nonce, sub: claims.sub || null,
             verified: !!verified.verified,
             attest: !!auth.attestWorkloads(),
             asserted: !!auth.acceptAssertedSelectors(),
             entries: entries.length };
  };
  (async function () {
    const out = {};
    try {
      set('spiffe.autoCreateEntries', false);
      // An entry the probe's selectors cannot match, so that "every entry"
      // and "the entries it matches" are different numbers.
      const td = ca.trustDomain();
      const made = registry.createEntry({
        spiffeId: 'spiffe://' + td + '/probe-104',
        parentId: 'spiffe://' + td + '/spire/server',
        selectors: [{ type: 'unix', value: 'uid:104' }] },
      'test', td, 'test');
      out.made = made.ok ? '' : (made.errors || []).join(' ');
      out.live = registry.allEntries().filter(function (entry) {
        return !entry.expired;
      }).length;
      out.devOff = await observe();
      ['oauth2.breakIdTokenNonce', 'ssf.breakSetSignature',
       'ssf.legacySubClaim', 'spiffe.acceptAssertedSelectors']
        .forEach(function (key) {
          set(key, true);
        });
      set('spiffe.attestWorkloads', false);
      out.devOn = await observe();
      set('global.mode', 'product');
      out.productOn = await observe();
      out.productAgain = await observe();
      set('global.mode', 'development');
      out.devAgain = await observe();
    } catch (e) {
      out.error = String((e && e.stack) || e);
    }
    process.stdout.write('RESULT ' + JSON.stringify(out) + '\n');
    process.exit(0);
  })();
}

function runChild() {
  log.debug("Entering runChild().");
  const script = 'delete process.env.CONFIG_FILE;\n(' +
    childProgram.toString() + ')(' + JSON.stringify(ROOT) + ');';
  const env = Object.assign({}, process.env, { STS_LOG_LEVEL: 'warn',
                                               LOG_LEVEL: 'warn' });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, ['-e', script],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024 });
  const stdout = String(child.stdout || '');
  const at = stdout.lastIndexOf('RESULT ');
  let result = null;
  if (at >= 0) {
    try {
      result = JSON.parse(stdout.slice(at + 'RESULT '.length).split('\n')[0]);
    } catch (e) {
      log.debug("Caught in runChild(): " + ((e && e.message) || e));
      result = null;
    }
  }
  log.debug("Leaving runChild().");
  return { result: result, stdout: stdout,
           stderr: String(child.stderr || ''), status: child.status };
}

function writes(t, config, errorCodes) {
  log.debug("Entering writes().");
  t.log.info('=== A. the write, in each mode ===');
  const set = function (key, value) {
    const result = config.setOverride(key, value);
    if (!result.ok) {
      throw new Error('setting ' + key + ' was refused: ' +
                      result.errors.join(' '));
    }
  };
  try {
    set('global.mode', 'product');
    MARKED.forEach(function (row) {
      const refused = config.setOverride(row.key, row.refused);
      t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-CORE-0103' &&
              (refused.errors || []).join(' ').indexOf(row.key) >= 0 &&
              /product mode/.test((refused.errors || []).join(' ')),
              'product: writing ' + row.key + '=' + row.refused + ' is ' +
              'refused with STS-CORE-0103, naming the setting',
              JSON.stringify(refused) + ' ' + errorCodes.codeOf(refused));
      t.check(!!config.checkWrite(row.key, row.refused) &&
              config.checkWriteCode(row.key, row.refused) === 'STS-CORE-0103',
              'product: and checkWrite(), which a console section asks ' +
              'before writing anything, refuses it too');
      t.check(config.checkOverride(row.key, row.refused) === null,
              'product: while checkOverride() — what a STORED value is ' +
              'restored through — does not');
      t.check(config.setOverride(row.key, !row.refused).ok,
              'product: writing the default (' + !row.refused + ') is ' +
              'accepted');
    });
    set('global.mode', 'development');
    MARKED.forEach(function (row) {
      t.check(config.setOverride(row.key, row.refused).ok &&
              config.checkWrite(row.key, row.refused) === null,
              'development: writing ' + row.key + '=' + row.refused +
              ' is accepted');
    });
  } finally {
    MARKED.concat([{ key: 'global.mode' }]).forEach(function (row) {
      config.clearOverride(row.key);
    });
  }
  log.debug("Leaving writes().");
}

function reads(t) {
  log.debug("Entering reads().");
  t.log.info('=== B. the read, in a child process ===');
  const child = runChild();
  const r = child.result;
  t.check(!!r && !r.error, 'the child ran every read site',
          (r && r.error) || ('exit ' + child.status + ' ' +
                             child.stderr.slice(-800)));
  if (!r || r.error) {
    log.debug("Leaving reads(). No result.");
    return;
  }
  t.check(r.live > 0 && !r.made,
          'there is a registration entry the probe cannot match',
          r.live + ' ' + r.made);
  t.check(r.devOff.nonce === 'n-104' && r.devOff.verified &&
          r.devOff.sub === null && r.devOff.attest && !r.devOff.asserted &&
          r.devOff.entries < r.live,
          'development, every switch at its default: the nonce as asked, a ' +
          'SET that verifies with no `sub`, and a caller handed only the ' +
          'entries its selectors match', JSON.stringify(r.devOff));
  t.check(/^broken-/.test(String(r.devOn.nonce)),
          'development: oauth2.breakIdTokenNonce spoils the ID Token\'s nonce',
          JSON.stringify(r.devOn));
  t.check(!r.devOn.verified,
          'development: ssf.breakSetSignature makes the SET fail to verify');
  t.check(r.devOn.sub === 'u-104',
          'development: ssf.legacySubClaim adds `sub` beside `sub_id`');
  t.check(r.devOn.asserted,
          'development: spiffe.acceptAssertedSelectors is believed');
  t.check(!r.devOn.attest && r.devOn.entries === r.live,
          'development: spiffe.attestWorkloads off hands a caller matching ' +
          'nothing every entry', JSON.stringify(r.devOn));
  [r.productOn, r.productAgain].forEach(function (p, i) {
    const when = i ? ' (read again)' : '';
    t.check(p.nonce === 'n-104',
            'product, the switch still stored: the ID Token carries the ' +
            'nonce the request asked for' + when, JSON.stringify(p));
    t.check(p.verified && p.sub === null,
            'product: the SET verifies and carries no `sub`' + when,
            JSON.stringify(p));
    t.check(!p.asserted, 'product: asserted selectors are not believed' +
            when);
    t.check(p.attest && p.entries === r.devOff.entries,
            'product: attestation is in force, and the caller is handed ' +
            'only the entries its selectors match' + when,
            JSON.stringify(p));
  });
  MARKED.forEach(function (row) {
    const lines = child.stdout.split('\n').filter(function (line) {
      return line.indexOf('STS-CORE-0106') >= 0 &&
             line.indexOf(row.key + ' is set') >= 0;
    });
    t.check(lines.length === 1,
            'product: ' + row.key + ' ignored is logged ONCE, with ' +
            'STS-CORE-0106, however often it is read',
            lines.length + ' line(s)');
  });
  t.check(/^broken-/.test(String(r.devAgain.nonce)) && !r.devAgain.verified &&
          r.devAgain.sub === 'u-104' && r.devAgain.asserted &&
          r.devAgain.entries === r.live,
          'back in development, every switch is honoured again',
          JSON.stringify(r.devAgain));
  log.debug("Leaving reads().");
}

function report(t, mode) {
  log.debug("Entering report().");
  t.log.info('=== C. mode.report() ===');
  const ids = mode.report().requirements.map(function (row) {
    return row.id;
  });
  ['deliberate-defects', 'spire-local-socket',
   'spiffe-workload-attestation'].forEach(function (id) {
    t.check(ids.indexOf(id) >= 0, 'mode.report() carries the ' + id +
            ' requirement', ids.join(', '));
  });
  t.check(['spoilsOnPurpose', 'servesUnattestedEntries',
           'trustsUnverifiedLocalSocket', 'believesAssertedSelectors']
            .every(function (name) {
              return typeof mode[name] === 'function';
            }), 'and the predicates exist');
  log.debug("Leaving report().");
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const mode = require('../common/mode');
  const errorCodes = require('../common/error_codes');
  writes(t, config, errorCodes);
  reads(t);
  report(t, mode);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'mode_development_only',
  describe: '#104: oauth2.breakIdTokenNonce, ssf.breakSetSignature, ' +
            'ssf.legacySubClaim, spiffe.acceptAssertedSelectors and ' +
            'spiffe.attestWorkloads off are honoured in development, ' +
            'ignored where they are read in product (logged once), and ' +
            'refused on write there',
  run: run
};
