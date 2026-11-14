// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/webauthn_captured_replay.js
//
// ===========================================================================
// A REGISTRATION CAPTURED FROM A REAL AUTHENTICATOR, REPLAYED THROUGH THE
// VERIFIER (#1114).
//
// Every other WebAuthn job here drives `webauthn_attestation_kit.js`, a
// software authenticator this repository wrote — so what it shows is that
// the verifier agrees with the kit, not that it agrees with an authenticator
// somebody else built. This job replays registrations CAPTURED from real
// authenticators, each a file `tests/fixtures/webauthn-captured/*.json`
// (the format is in `tests/CLAUDE.md`, *Captured WebAuthn registrations*):
// the creation options the browser was given, the PublicKeyCredential it
// answered, the settings the replay runs under, and the record expected.
// Each is put through `webauthn.verifyRegistration()` and
// `webauthn_attestation.assess()` in process, and every field `expected`
// names must match.
//
//   A. THE REPLAY ITSELF, proven over a SYNTHETIC registration this job
//      makes at run time with the kit and writes to a temporary directory
//      in the captured format — never into the captured directory, and
//      never committed: a replay that passes it, and one whose expectation
//      is altered that fails, so the comparison is not vacuous.
//   B. Every captured fixture, one check each. WITH NONE PRESENT THE JOB
//      PASSES AND SAYS IT RAN NONE — no real post-quantum authenticator's
//      registration has been captured yet, and none is invented here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const config = require('../common/config');
const webauthn = require('../authn/webauthn');
const attestation = require('../authn/webauthn_attestation');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({
  name: 'webauthn_captured_replay', level: process.env.LOG_LEVEL || 'info' });

/** Where captured registrations are dropped in. */
const CAPTURED = path.join(__dirname, 'fixtures', 'webauthn-captured');

// Whether `actual` holds every field `expected` names, with the same value:
// an object by its keys, an array element by element (and of the same
// length), anything else by `===`. Each difference is pushed onto `out` as
// a path and the two values.
function differences(expected, actual, at, out) {
  log.debug('Entering differences(). ' + at);
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) {
      out.push(at + ': expected ' + JSON.stringify(expected) + ', got ' +
               JSON.stringify(actual));
      log.debug('Leaving differences(). Array.');
      return out;
    }
    expected.forEach(function (one, i) {
      differences(one, actual[i], at + '[' + i + ']', out);
    });
    log.debug('Leaving differences(). Array.');
    return out;
  }
  if (expected && typeof expected === 'object') {
    if (!actual || typeof actual !== 'object') {
      out.push(at + ': expected an object, got ' + JSON.stringify(actual));
      log.debug('Leaving differences(). Object.');
      return out;
    }
    Object.keys(expected).forEach(function (key) {
      differences(expected[key], actual[key], at + '.' + key, out);
    });
    log.debug('Leaving differences(). Object.');
    return out;
  }
  if (expected !== actual) {
    out.push(at + ': expected ' + JSON.stringify(expected) + ', got ' +
             JSON.stringify(actual));
  }
  log.debug('Leaving differences().');
  return out;
}

// Applies a fixture's `settings` as one write (the RP ID list and
// `enterprise` may come together), and answers the keys to clear.
function applySettings(settings) {
  log.debug('Entering applySettings().');
  const given = settings && typeof settings === 'object' ? settings : {};
  const keys = Object.keys(given);
  const refused = [];
  config.withWriteBatch(given, function () {
    keys.forEach(function (key) {
      const answer = config.setOverride(key, given[key]);
      if (answer && answer.ok === false) {
        refused.push(key + ': ' + (answer.errors || []).join(' '));
      }
    });
  });
  log.debug('Leaving applySettings(). ' + keys.length);
  return { keys: keys, refused: refused };
}

/**
 * Replays one fixture through the verifier and the attestation assessment.
 *
 * @param fixture - the parsed file
 * @returns `{ ok, differences, verdict, attested }`
 */
async function replayOne(fixture) {
  log.debug('Entering replayOne().');
  const f = fixture || {};
  const options = f.options || {};
  const response = (f.response || {}).response || {};
  const applied = applySettings(f.settings);
  try {
    if (applied.refused.length) {
      log.debug('Leaving replayOne(). Settings refused.');
      return { ok: false, differences: ['settings refused: ' +
                                        applied.refused.join('; ')] };
    }
    const verdict = webauthn.verifyRegistration({
      attestationObject: String(response.attestationObject || ''),
      clientDataJSON: String(response.clientDataJSON || ''),
      expectedChallenge: String(options.challenge || ''),
      expectedOrigin: String(f.origin || ''),
      expectedRpId: String((options.rp || {}).id || ''),
      requireUserVerification:
        ((options.authenticatorSelection || {}).userVerification ===
         'required'),
      expectedAlgorithms: (options.pubKeyCredParams || []).map(
        function (p) {
          return Number(p && p.alg);
        })
    });
    // Only a ceremony whose own checks passed reaches the attestation, as
    // at every door.
    const attested = verdict.ok ? await attestation.assess(verdict) : null;
    const actual = {
      ok: !!(verdict.ok && attested && attested.ok),
      failed: verdict.failed || [],
      algorithm: verdict.algorithm, coseAlg: verdict.coseAlg,
      aaguid: verdict.aaguid,
      code: attested && !attested.ok
        ? String(require('../common/error_codes').codeOf(attested) || '')
        : '',
      attestation: attested ? attested.attestation : null
    };
    const found = differences(f.expected || {}, actual, 'expected', []);
    log.debug('Leaving replayOne(). ' + found.length + ' difference(s).');
    return { ok: found.length === 0, differences: found, verdict: verdict,
             attested: attested };
  } finally {
    applied.keys.slice().reverse().forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

/**
 * The fixtures of a directory, by file name; none where it does not exist.
 *
 * @param dir - the directory
 * @returns `[{ file, fixture }]`, or `[{ file, error }]` for one that is
 *   not JSON
 */
function fixturesIn(dir) {
  log.debug('Entering fixturesIn(). ' + dir);
  let names = [];
  try {
    names = fs.readdirSync(dir).filter(function (name) {
      return /\.json$/.test(name);
    }).sort();
  } catch (e) {
    // No directory is no fixture, which is the state the job expects
    // until a capture is dropped in.
    log.debug('Caught in fixturesIn(): ' + ((e && e.message) || e));
    names = [];
  }
  const out = names.map(function (name) {
    try {
      return { file: name, fixture: JSON.parse(
        fs.readFileSync(path.join(dir, name), 'utf8')) };
    } catch (e) {
      log.debug('Caught in fixturesIn(): ' + ((e && e.message) || e));
      return { file: name, error: String((e && e.message) || e) };
    }
  });
  log.debug('Leaving fixturesIn(). ' + out.length);
  return out;
}

// A SYNTHETIC registration in the captured format: an ES256 credential
// under a packed attestation from a root made now. Written to `dir`.
async function synthetic(dir) {
  log.debug('Entering synthetic().');
  const root = await kit.root('Synthetic Replay Vendor');
  const ctx = await kit.ceremony({ alg: -7 });
  const made = await kit.packed(ctx, root);
  const input = ctx.input(made);
  const fixture = {
    name: 'synthetic ES256 packed registration (made by the test kit)',
    captured: 'SYNTHETIC: webauthn_attestation_kit.js, at run time; not a ' +
              'real authenticator',
    origin: ctx.origin,
    options: {
      rp: { id: ctx.rpId, name: 'Synthetic' },
      challenge: ctx.challenge,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      attestation: 'direct',
      authenticatorSelection: { userVerification: 'preferred' }
    },
    settings: {
      'webauthn.attestationPolicy': 'verify-if-present',
      'webauthn.attestationTrustAnchors': root.pem
    },
    response: {
      id: ctx.credential.id.toString('base64url'),
      rawId: ctx.credential.id.toString('base64url'),
      type: 'public-key',
      response: { clientDataJSON: input.clientDataJSON,
                  attestationObject: input.attestationObject,
                  transports: ['usb'] },
      authenticatorAttachment: 'cross-platform'
    },
    expected: {
      ok: true, algorithm: 'ES256', coseAlg: -7, code: '',
      attestation: { format: 'packed', verified: true, trusted: true,
                     conveyance: 'direct', enterpriseDowngraded: false,
                     algorithms: { statement: 'ES256',
                                   postQuantum: false } }
    }
  };
  fs.writeFileSync(path.join(dir, 'synthetic-es256-packed.json'),
                   JSON.stringify(fixture, null, 2));
  log.debug('Leaving synthetic().');
  return fixture;
}

async function provesItself(t) {
  log.debug('Entering provesItself().');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wcr-'));
  try {
    await synthetic(dir);
    const found = fixturesIn(dir);
    const good = await replayOne(found[0] && found[0].fixture);
    const altered = JSON.parse(JSON.stringify(found[0].fixture));
    altered.expected.attestation.algorithms.statement = 'ML-DSA-65';
    const bad = await replayOne(altered);
    t.check(found.length === 1 && good.ok &&
            !bad.ok && bad.differences.length === 1 &&
            /algorithms\.statement/.test(bad.differences[0]),
            'A. a SYNTHETIC registration in the captured format, written to ' +
            'a temporary directory, replays and matches; the same one with ' +
            'its expectation altered does not',
            JSON.stringify([good.differences, bad.differences]));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug('Leaving provesItself().');
}

async function captured(t) {
  log.debug('Entering captured().');
  const found = fixturesIn(CAPTURED);
  if (!found.length) {
    t.check(true, 'B. no captured registration in ' +
            'tests/fixtures/webauthn-captured: ran none');
    log.debug('Leaving captured(). None.');
    return;
  }
  for (const one of found) {
    if (one.error) {
      t.check(false, 'B. ' + one.file + ' is JSON', one.error);
      continue;
    }
    const replayed = await replayOne(one.fixture);
    t.check(replayed.ok, 'B. ' + one.file + ' (' +
            String(one.fixture.name || 'unnamed') + ') replays as expected',
            replayed.differences.join('; '));
  }
  log.info('  ran ' + found.length + ' captured registration(s).');
  log.debug('Leaving captured().');
}

module.exports = {
  name: 'webauthn_captured_replay',
  describe: 'registrations captured from real authenticators, replayed ' +
            'through the verifier; passes and says so with none present ' +
            '(#1114)',
  replayOne: replayOne,
  run: async function (t) {
    log.debug('Entering run().');
    await provesItself(t);
    await captured(t);
    log.debug('Leaving run().');
  }
};
