#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/client-lab/verify-attestation.js
//
// ===========================================================================
// A CARD'S PIV ATTESTATION THROUGH THE SERVICE'S OWN VERIFIER (#2056), IN
// PROCESS: `common/piv_attestation.ts`'s `verify()`, as
// `tests/piv_attestation.js` calls it, over what `bin/lab-piv-attest` wrote
// — the attestation, the f9 certificate read off the card, the slot's
// public key — with that run's root as the realm's only PIV attestation
// anchor (`piv.attestationAnchors`).
//
// NOT A TEST and not in the lab: it needs the compiled service, so it runs
// in the TESTS image, with the lab's output directory mounted:
//
//   docker run --rm -v <dir>:/attest:ro iya-sts-npm-test:<tag> \
//     node tests/client-lab/verify-attestation.js /attest [profile[=want]...]
//
// It prints, as JSON, the facts Yubico's extensions decode to, every
// field the verifier reads, and the verdict for each profile asked
// (piv-auth and tls-client by default). `profile=ok` or `profile=STS-…`
// states the verdict expected, and the exit code is 2 when any differs
// (tests/client-lab/smoke.sh). It changes nothing in the verifier: a
// refusal is the answer, not something to work around.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..', '..');
const config = require(path.join(ROOT, 'common', 'config'));
const pki = require(path.join(ROOT, 'common', 'pki'));
const stsCrypto = require(path.join(ROOT, 'common', 'crypto'));
const errorCodes = require(path.join(ROOT, 'common', 'error_codes'));
const piv = require(path.join(ROOT, 'common', 'piv_attestation'));

const log = require('bunyan').createLogger({ name: 'verify-attestation',
  level: process.env.LOG_LEVEL || 'warn' });

const YUBICO = '1.3.6.1.4.1.41482.3.';
const WANTED = { '3': 'firmware', '7': 'serial', '8': 'PIN and touch policy',
                 '9': 'form factor', '10': 'FIPS' };

function read(dir, name) {
  log.debug("Entering read(). " + name);
  log.debug("Leaving read().");
  return fs.readFileSync(path.join(dir, name), 'utf8');
}

// What the slot certificate carries, field by field, beside what the
// verifier reads from it.
function describe(slotPem) {
  log.debug("Entering describe().");
  const der = pki.certificateBundle(slotPem).certificates[0].der;
  const cert = pki.attestationCertificateFacts(der);
  const present = {};
  // `attestationCertificateFacts()` keys the extensions by OID.
  for (const id of Object.keys(cert.extensions || {})) {
    if (id.indexOf(YUBICO) === 0) {
      present[id.slice(YUBICO.length)] = true;
    }
  }
  const missing = Object.keys(WANTED).filter(function (k) {
    return !present[k];
  }).map(function (k) {
    return YUBICO + k + ' (' + WANTED[k] + ')';
  });
  log.debug("Leaving describe().");
  return { subject: cert.subject, issuer: cert.issuer,
           yubicoExtensions: Object.keys(present).map(function (k) {
             return YUBICO + k;
           }),
           yubicoExtensionsMissing: missing,
           facts: stsCrypto.yubicoPivAttestationFacts(cert.extensions),
           subjectNamesASlot:
             /YubiKey PIV Attestation\s+([0-9a-f]{2})\b/i
               .test(String((cert.subject && cert.subject.CN) || '')) };
}

async function main() {
  log.debug("Entering main().");
  const dir = process.argv[2] || '/attest';
  const asked = process.argv.length > 3 ? process.argv.slice(3)
    : ['piv-auth', 'tls-client'];
  const profiles = asked.map(function (a) {
    return a.split('=')[0];
  });
  const wanted = {};
  for (const a of asked) {
    if (a.indexOf('=') > 0) {
      wanted[a.split('=')[0]] = a.split('=')[1];
    }
  }
  const rootPem = read(dir, 'root.pem');
  const f9Pem = read(dir, 'f9.pem');
  const slotPem = read(dir, 'attestation.pem');
  const publicKeyPem = read(dir, 'slot.pub');
  config.setOverride('piv.attestationAnchors', rootPem);
  const out = { describe: describe(slotPem), verdicts: {} };
  const statement = piv.statementFromPem(slotPem, f9Pem);
  out.statement = { ok: statement.ok, found: statement.found,
                    code: errorCodes.codeOf(statement) || '' };
  for (const profile of profiles) {
    const answer = await piv.verify({ statement: statement,
                                      publicKeyPem: publicKeyPem,
                                      profile: profile });
    out.verdicts[profile] = answer.ok
      ? { ok: true, facts: answer.facts }
      : { ok: false, code: errorCodes.codeOf(answer) || '',
          why: answer.why || answer.error };
  }
  config.clearOverride('piv.attestationAnchors');
  out.unexpected = Object.keys(wanted).filter(function (p) {
    const v = out.verdicts[p];
    return (v.ok ? 'ok' : v.code) !== wanted[p];
  }).map(function (p) {
    const v = out.verdicts[p];
    return p + ': wanted ' + wanted[p] + ', got ' + (v.ok ? 'ok' : v.code);
  });
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  log.debug("Leaving main().");
  return out.unexpected.length ? 2 : 0;
}

main().then(function (code) {
  process.exit(code);
}, function (e) {
  process.stderr.write(String((e && e.stack) || e) + '\n');
  process.exit(1);
});
