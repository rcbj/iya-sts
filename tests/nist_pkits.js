'use strict';
//
// File: nist_pkits.js
//
// ===========================================================================
// NIST PKITS AGAINST THE CERTIFICATE PATH VALIDATORS (#201, 2026-09-24).
//
// The Public Key Interoperability Test Suite (NIST, csrc.nist.gov/projects/
// pki-testing) — 249 path-validation tests with their subparts, in sixteen
// sections of PKITS.pdf: signatures, validity periods, name chaining, basic
// certificate revocation, self-issued certificates, basic constraints, key
// usage, CERTIFICATE POLICIES, requireExplicitPolicy, policy mappings,
// inhibitPolicyMapping, inhibitAnyPolicy, name constraints, distribution
// points, delta CRLs and private extensions. x509-limbo (`x509_limbo.js`)
// has no PKITS in it, and it is PKITS that holds RFC 5280 section 6.1's
// policy processing (`pki.pathPolicyOutcome()`) to an answer somebody else
// wrote down.
//
// NOTHING OF IT IS IN THIS REPOSITORY: the data carries every private key in
// a PKCS #12, so the tests image fetches it from csrc.nist.gov, pinned by
// SHA-256, with the test table BoringSSL's generator transcribed from the PDF
// (`tools/fetch-nist-pkits.sh`, `STS_NIST_PKITS_DIR`). Anywhere else this
// file FAILS naming that variable.
//
// THE DRIVERS.
//
//   anchors  `pki.verifyPathToAnchors()` with the subpart's four policy
//            inputs, the trust anchor the only anchor and every other
//            certificate an intermediate; then every certificate below the
//            anchor through the CRL route (`revocation_status
//            .crlInHandVerdict()`) with the test's CRLs in hand. A path is
//            accepted only when both say so — which is what a door that
//            validates and then consults revocation under hard-fail does.
//            Every subpart. The user-constrained-policy-set PKITS names is
//            compared on every accepted path.
//   signer   `pki.verifySignerChain()` with the test's certificates
//            registered as the chain, then the same CRL route. No caller
//            sets a policy input, so a subpart that sets one is an
//            exception here, answered by `anchors`.
//
// Not driven: the one-hop door (`verifyIssuedDirectly()`) — every PKITS path
// has an intermediate; and the two TLS drivers — the keys are in the PKCS #12
// this file does not open, and x509_limbo.js already puts OpenSSL's two
// postures to their own corpus.
//
// Every disagreement is an entry of `EXCEPTIONS` with its reason, or a
// failure; an exception that stops excusing anything fails too.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'nist_pkits',
  level: process.env.LOG_LEVEL || 'info' });

const TABLE_COMMIT = 'bc97b7a8e1952bab69fea961301a90e5ad3344e9';
// PKITS.pdf section 4's tests, and the subparts BoringSSL's table splits the
// ones with several recommended inputs into.
const TABLE_TESTS = 224;
const TABLE_SUBPARTS = 249;

// PKITS section 3.1: every test is run at a time inside every certificate's
// validity, and BoringSSL's harness uses the publication date.
const VALIDATION_TIME = Date.UTC(2011, 3, 15);

const POLICY_OIDS = {
  anyPolicy: '2.5.29.32.0',
  'NIST-test-policy-1': '2.16.840.1.101.3.2.1.48.1',
  'NIST-test-policy-2': '2.16.840.1.101.3.2.1.48.2',
  'NIST-test-policy-3': '2.16.840.1.101.3.2.1.48.3',
  'NIST-test-policy-6': '2.16.840.1.101.3.2.1.48.6'
};

const RealDate = Date;

// A case's clock, for the modules that read `Date` themselves (the CRL
// reader's freshness); restored in a `finally`.
async function atTime(ms, work) {
  log.debug("Entering atTime().");
  class CaseDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) {
        super(ms);
      } else {
        // @ts-ignore — a spread into Date's overloads.
        super(...args);
      }
    }

    static now() {
      return ms;
    }
  }
  global.Date = /** @type {any} */ (CaseDate);
  try {
    const out = await work();
    log.debug("Leaving atTime().");
    return out;
  } finally {
    global.Date = RealDate;
  }
}

// ---------------------------------------------------------------------------
// THE TABLE. Each test in pkits_testcases-inl.h is one block: a comment naming
// it, the certificate and CRL file names in path order (anchor first), the
// expected result, and the Set*() calls that change a default input.
// ---------------------------------------------------------------------------
function policySet(text) {
  log.debug("Entering policySet().");
  const out = String(text).split(',').map(function (name) {
    return name.trim();
  }).filter(Boolean).map(function (name) {
    if (!POLICY_OIDS[name]) {
      throw new Error('an unknown policy name in the table: ' + name);
    }
    return POLICY_OIDS[name];
  });
  log.debug("Leaving policySet().");
  return out;
}

function stringsOf(text) {
  log.debug("Entering stringsOf().");
  log.debug("Leaving stringsOf().");
  return (text.match(/"([^"]*)"/g) || []).map(function (q) {
    return q.slice(1, -1);
  });
}

function parseTable(source) {
  log.debug("Entering parseTable().");
  const cases = [];
  const blocks = source.split(/\n(?=\/\/ 4\.\d+\.\d+ )/);
  blocks.forEach(function (block) {
    const head = /^\/\/ (4\.\d+\.\d+) ([^\n]*)/.exec(block);
    if (!head || block.indexOf('WRAPPED_TYPED_TEST_P(') < 0) {
      return;
    }
    const certs = /certs\[\] = \{([^}]*)\}/.exec(block);
    const crls = /crls\[\] = \{([^}]*)\}/.exec(block);
    const should = /info\.should_validate = (true|false);/.exec(block);
    if (!certs || !crls || !should) {
      throw new Error('test ' + head[1] + ' did not parse');
    }
    const one = {
      number: head[1], name: head[2].trim(),
      certs: stringsOf(certs[1]), crls: stringsOf(crls[1]),
      shouldValidate: should[1] === 'true',
      policy: { initialPolicySet: [POLICY_OIDS.anyPolicy],
                initialExplicitPolicy: false,
                initialPolicyMappingInhibit: false,
                initialInhibitAnyPolicy: false },
      userConstrained: [POLICY_OIDS['NIST-test-policy-1']],
      nonDefaultInputs: false
    };
    let m = /SetInitialPolicySet\("([^"]*)"\)/.exec(block);
    if (m) {
      one.policy.initialPolicySet = policySet(m[1]);
      one.nonDefaultInputs = true;
    }
    m = /SetUserConstrainedPolicySet\("([^"]*)"\)/.exec(block);
    if (m) {
      one.userConstrained = policySet(m[1]);
    }
    if (/SetInitialExplicitPolicy\(true\)/.test(block)) {
      one.policy.initialExplicitPolicy = true;
      one.nonDefaultInputs = true;
    }
    if (/SetInitialPolicyMappingInhibit\(true\)/.test(block)) {
      one.policy.initialPolicyMappingInhibit = true;
      one.nonDefaultInputs = true;
    }
    if (/SetInitialInhibitAnyPolicy\(true\)/.test(block)) {
      one.policy.initialInhibitAnyPolicy = true;
      one.nonDefaultInputs = true;
    }
    cases.push(one);
  });
  log.debug("Leaving parseTable(). " + cases.length + " case(s).");
  return cases;
}

function loadCorpus() {
  log.debug("Entering loadCorpus().");
  const dir = process.env.STS_NIST_PKITS_DIR || '';
  if (!dir) {
    log.debug("Leaving loadCorpus(). No directory.");
    return { error: 'STS_NIST_PKITS_DIR is not set. PKITS is fetched into ' +
                    'the tests image when it is built ' +
                    '(tests/tools/fetch-nist-pkits.sh); run this file there, ' +
                    'with ./docker-npm-test.sh.' };
  }
  try {
    const commit = fs.readFileSync(path.join(dir, 'TABLE_COMMIT'), 'utf8')
      .trim();
    const cases = parseTable(fs.readFileSync(
      path.join(dir, 'pkits_testcases-inl.h'), 'utf8'));
    log.debug("Leaving loadCorpus().");
    return { dir: dir, commit: commit, cases: cases };
  } catch (e) {
    log.debug("Caught in loadCorpus(): " + ((e && e.message) || e));
    log.debug("Leaving loadCorpus(). Unreadable.");
    return { error: 'PKITS in ' + dir + ' could not be read: ' +
                    ((e && e.message) || e) };
  }
}

function fileOf(dir, kind, name) {
  log.debug("Entering fileOf().");
  log.debug("Leaving fileOf().");
  return fs.readFileSync(path.join(dir, kind, name +
                                   (kind === 'certs' ? '.crt' : '.crl')));
}

// ---------------------------------------------------------------------------
// REVOCATION, the same way for both drivers: every certificate below the
// anchor, against its issuer, with the test's CRLs in hand. `unknown` is a
// refusal, as it is under `pki.revocationCheck=hard-fail` (product's `auto`);
// a realm on soft-fail would accept a path whose lists could not be used.
// ---------------------------------------------------------------------------
async function revocationOf(chainDers, allDers, crls) {
  log.debug("Entering revocationOf().");
  const revocation = require('../common/revocation_status');
  for (let i = 0; i < chainDers.length - 1; i++) {
    const verdict = await atTime(VALIDATION_TIME, function () {
      return revocation.crlInHandVerdict({
        certificate: chainDers[i], issuer: chainDers[i + 1],
        others: allDers, crls: crls });
    });
    if (verdict.status !== 'good') {
      log.debug("Leaving revocationOf(). " + verdict.status + " at " + i);
      return { ok: false, check: 'revocation-' + verdict.status,
               why: 'certificate ' + i + ' is ' + verdict.status + ': ' +
                    verdict.why };
    }
  }
  log.debug("Leaving revocationOf(). Good.");
  return { ok: true };
}

function sameSet(a, b) {
  log.debug("Entering sameSet().");
  const x = a.slice(0).sort().join(',');
  const y = b.slice(0).sort().join(',');
  log.debug("Leaving sameSet().");
  return x === y;
}

async function driveAnchors(dir, one) {
  log.debug("Entering driveAnchors().");
  const pki = require('../common/pki');
  const ders = one.certs.map(function (name) {
    return fileOf(dir, 'certs', name);
  });
  const crls = one.crls.map(function (name) {
    return fileOf(dir, 'crls', name);
  });
  const anchor = pki.certificateFromDer(ders[0]);
  const v = await pki.verifyPathToAnchors(ders[ders.length - 1],
    ders.slice(1, -1), [anchor],
    { now: VALIDATION_TIME, policy: one.policy });
  if (!v.ok) {
    log.debug("Leaving driveAnchors(). The path.");
    return { ok: false, check: v.check || '', why: v.reason || '' };
  }
  const revoked = await revocationOf(v.chain.map(function (c) {
    return c.der;
  }), ders, crls);
  if (!revoked.ok) {
    log.debug("Leaving driveAnchors(). Revocation.");
    return revoked;
  }
  log.debug("Leaving driveAnchors().");
  return { ok: true, policies: v.policies || [] };
}

async function driveSigner(dir, one) {
  log.debug("Entering driveSigner().");
  const pki = require('../common/pki');
  const errorCodes = require('../common/error_codes');
  const pems = one.certs.map(function (name) {
    return pki.certificateFromDer(fileOf(dir, 'certs', name)).pem;
  });
  const crls = one.crls.map(function (name) {
    return fileOf(dir, 'crls', name);
  });
  const v = await atTime(VALIDATION_TIME, function () {
    return pki.verifySignerChain(undefined, {
      certificate: pems[pems.length - 1], chain: pems.slice(0, -1),
      source: 'the PKITS case' });
  });
  if (!v.ok) {
    log.debug("Leaving driveSigner(). The path.");
    return { ok: false, check: errorCodes.codeOf(v) || '', why: v.why || '' };
  }
  // The chain it validated, as it returns it for a registered root.
  const derOf = function (pem) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
  };
  const revoked = await revocationOf((v.chain || []).map(derOf),
                                     pems.map(derOf), crls);
  log.debug("Leaving driveSigner().");
  return revoked.ok ? { ok: true } : revoked;
}

// ---------------------------------------------------------------------------
// THE EXCEPTIONS: a PKITS expectation this service deliberately does not
// meet, or one a driver cannot put, each with its reason.
// ---------------------------------------------------------------------------
const EXCEPTIONS = [
  { id: 'dsa-is-not-accepted',
    drivers: ['anchors', 'signer'],
    reason: 'PKITS 4.1.4 and 4.1.5 are DSA paths. This service verifies no ' +
      'DSA certificate signature: FIPS 186-5 (2023) withdrew DSA for ' +
      'generating signatures, and the vendored engine does not implement ' +
      'it. A valid DSA path is refused, which fails closed; BoringSSL ' +
      'makes the same exception.',
    applies: function (one, v) {
      return !v.ok && one.shouldValidate &&
             (one.number === '4.1.4' || one.number === '4.1.5');
    } },
  { id: 'no-caller-sets-policy-inputs',
    drivers: ['signer'],
    reason: 'The subpart sets an initial policy input (initial-policy-set, ' +
      'initial-explicit-policy, initial-policy-mapping-inhibit or ' +
      'initial-inhibit-any-policy). No caller of verifySignerChain sets ' +
      'one — the defaults run — so the subpart is answered by the anchors ' +
      'driver, which passes the inputs to the same rules.',
    applies: function (one) { return one.nonDefaultInputs; } },
  { id: 'signer-leaf-may-sign',
    drivers: ['signer'],
    reason: 'An assertion signer must be a LEAF whose keyUsage, where it ' +
      'has one, permits digitalSignature (STS-PKI-0159). PKITS\'s end ' +
      'entity is a path\'s last certificate, CA or not, for any purpose.',
    applies: function (one, v) {
      return !v.ok && one.shouldValidate && v.check === 'STS-PKI-0159';
    } }
];

async function run(t) {
  log.debug("Entering run().");
  delete process.env.CONFIG_FILE;
  const loaded = loadCorpus();
  if (loaded.error) {
    t.bad('the NIST PKITS corpus is present', loaded.error);
    log.debug("Leaving run(). No corpus.");
    return;
  }
  t.equal(loaded.commit, TABLE_COMMIT, 'the PKITS table is BoringSSL\'s at ' +
          'the pinned commit');
  const numbers = {};
  loaded.cases.forEach(function (one) { numbers[one.number] = true; });
  t.equal(Object.keys(numbers).length, TABLE_TESTS, 'every PKITS test is in ' +
          'the table');
  t.equal(loaded.cases.length, TABLE_SUBPARTS, 'and every subpart');
  const drivers = { anchors: driveAnchors, signer: driveSigner };
  const used = {};
  const names = Object.keys(drivers);
  for (let d = 0; d < names.length; d++) {
    const driver = names[d];
    const counts = { cases: 0, agree: 0, excepted: 0, failed: 0,
                     byException: {} };
    const failures = [];
    for (let c = 0; c < loaded.cases.length; c++) {
      const one = loaded.cases[c];
      let v;
      try {
        v = await drivers[driver](loaded.dir, one);
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
        v = { ok: false, check: 'threw',
              why: 'the driver threw: ' + ((e && e.stack) || e) };
      }
      counts.cases++;
      let agrees = v.ok === one.shouldValidate;
      let why = v.why || '';
      if (agrees && v.ok && v.policies &&
          !sameSet(v.policies, one.userConstrained)) {
        agrees = false;
        why = 'the user-constrained-policy-set is ' +
              JSON.stringify(v.policies) + ', PKITS says ' +
              JSON.stringify(one.userConstrained);
      }
      if (agrees) {
        counts.agree++;
        continue;
      }
      const excuse = EXCEPTIONS.filter(function (ex) {
        return ex.drivers.indexOf(driver) >= 0 && ex.applies(one, v);
      })[0];
      if (excuse) {
        counts.excepted++;
        counts.byException[excuse.id] =
          (counts.byException[excuse.id] || 0) + 1;
        used[driver + ':' + excuse.id] = true;
        continue;
      }
      counts.failed++;
      failures.push(one.number + ' ' + one.name + ': PKITS expects ' +
                    (one.shouldValidate ? 'SUCCESS' : 'FAILURE') +
                    ', the validator answered ' +
                    (v.ok ? 'SUCCESS' : 'FAILURE') +
                    (why ? ' (' + String(why).slice(0, 300) + ')' : ''));
    }
    t.log.info('NIST PKITS, ' + driver + ': ' + counts.cases +
               ' subpart(s), ' + counts.agree + ' agree, ' + counts.excepted +
               ' documented exception(s) ' +
               JSON.stringify(counts.byException) + ', ' + counts.failed +
               ' failure(s).');
    t.check(failures.length === 0, driver + ': every disagreement with ' +
            'PKITS is a documented exception',
            failures.length + ' not: ' + failures.slice(0, 40).join(' | '));
  }
  EXCEPTIONS.forEach(function (ex) {
    ex.drivers.forEach(function (driver) {
      t.check(!!used[driver + ':' + ex.id], 'the exception "' + ex.id +
              '" still excuses a disagreement on the ' + driver + ' driver',
              'it matched nothing — the gap it records is closed, so it is ' +
              'removed or narrowed');
    });
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'nist_pkits',
  describe: '#201: NIST PKITS against pki.verifyPathToAnchors (with the ' +
            'policy inputs) and pki.verifySignerChain, revocation through ' +
            'the CRL route with the lists in hand',
  run: run,
  EXCEPTIONS: EXCEPTIONS
};
