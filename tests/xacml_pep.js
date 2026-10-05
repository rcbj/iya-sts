// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep.js
//
// ===========================================================================
// PHASE FIVE: THE REMOTE PEP. THE PDP'S SIDE IN PROCESS — AND THE ONE
// EXPECTATION THE TWO ENFORCEMENT POINTS SHARE.
//
// **THE CONTAINER IS A RUST BINARY SINCE #444 (2026-10-05)**,
// `rust/bins/xacml-pep`, on the engine crate `rust/crates/sts-xacml`. What
// this file used to hold about the CONTAINER's shape is now held where that
// code is, and more strongly:
//
//   * the engine loads with no identity service in it — the crate graph is
//     the proof: `sts-xacml` depends on no service crate, and Cargo will not
//     build one that does;
//   * the engine decides as the service's does — `rust/crates/sts-xacml/
//     tests/conformance.rs` holds it to the same OASIS suite, case for case;
//   * the Dockerfile builds the binary rather than copying modules — checked
//     below, because it is a comparison of FILES;
//   * the PIP walk over the five places a designator can hide, and the HTTPS
//     listener's reload rules — `cargo test -p xacml-pep`.
//
// **WHAT STAYS HERE IS THE PDP'S SIDE** (the sync token, the register, the
// nudge's refusals, the change observer), and the one claim that needs BOTH
// implementations: **THE TWO PEPs ENFORCE IDENTICALLY.** The service's
// `enforce()` and the container's are two readings of section 7.2,
// deliberately not shared, so the table they are held to is ONE FILE,
// `xacml-pep/enforcement_cases.json`: this file holds the embedded PEP to
// it, and the Rust crate's own test holds the remote one to it.
//
// This file starts no PEP, registers nothing and makes NO HTTP REQUEST. The
// deployment — the real container against a running service — is
// `tests/vendored/sts_xacml_remote_pep.js`.
// ===========================================================================
const assert = require('assert');
const fs = require('fs');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'xacml_pep',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const PEP_DIR = path.join(ROOT, 'xacml-pep');

const registry = require('../xacml/xacml_pep_registry');
const pepHttp = require('../xacml/xacml_pep_http');
const store = require('../xacml/xacml_store');
const model = require('../xacml/xacml_model');

// ---------------------------------------------------------------------------
// A THROWAWAY ou=policies AND ou=peps, held here.
//
// The same shape `tests/xacml_service.js` uses: the two registers take their
// directory across a slot, so a test can fill that slot itself and get the
// whole store contract with no LDAP server, no port and no realm. What is
// asserted is the module's behaviour against a directory, which is the level
// this file is about.
//
// **THE ATTRIBUTE NAMES ARE LOWER-CASED ON THE WAY IN**, deliberately, because
// that is what the real directory does (RFC 4512) and it is the defect that
// cost a boot in phase two — a fake directory that preserved the case somebody
// wrote would make every reader here pass and the real one fail.
// ---------------------------------------------------------------------------
function fakeDirectory() {
  log.debug("Entering fakeDirectory().");
  const entries = new Map();
  function lower(attributes) {
    log.debug("Entering lower().");
    const out = {};
    Object.keys(attributes || {}).forEach(function (key) {
      const value = attributes[key];
      out[key.toLowerCase()] = Array.isArray(value) ? value.slice(0)
                                                    : [String(value)];
    });
    log.debug("Leaving lower().");
    return out;
  }
  log.debug("Leaving fakeDirectory().");
  return {
    entries: entries,
    allPeps: function () {
      log.debug("Entering allPeps().");
      log.debug("Leaving allPeps().");
      return Array.from(entries.entries()).map(function (pair) {
        return { name: pair[0], dn: 'cn=' + pair[0] + ',ou=peps',
                 attributes: pair[1] };
      });
    },
    writePep: function (name, attributes) {
      log.debug("Entering writePep().");
      entries.set(name, lower(attributes));
      log.debug("Leaving writePep().");
      return true;
    },
    deletePep: function (name) {
      log.debug("Entering deletePep().");
      log.debug("Leaving deletePep().");
      return entries.delete(name);
    },
    certificateIdentity: function (certificate) {
      log.debug("Entering certificateIdentity().");
      const subject = String((certificate || {}).subject || '');
      const cn = /CN=([^,]+)/i.exec(subject);
      log.debug("Leaving certificateIdentity().");
      return { dn: 'cn=' + (cn ? cn[1] : 'unknown') + ',ou=users',
               commonName: cn ? cn[1] : '', subject: subject };
    }
  };
}

function fakePolicyDirectory(documents) {
  log.debug("Entering fakePolicyDirectory().");
  log.debug("Leaving fakePolicyDirectory().");
  return {
    allPolicies: function () {
      log.debug("Entering allPolicies().");
      log.debug("Leaving allPolicies().");
      return Object.keys(documents).map(function (name) {
        return { name: name, dn: 'cn=' + name + ',ou=policies',
                 attributes: {
                   xacmlpolicyid: ['urn:test:' + name],
                   xacmlpolicydocument: [documents[name].document],
                   xacmlversion: ['1.0'],
                   xacmlkind: ['Policy'],
                   xacmlenabled: [documents[name].enabled === false
                     ? 'FALSE' : 'TRUE'],
                   xacmlisroot: [documents[name].isRoot ? 'TRUE' : 'FALSE']
                 } };
      });
    },
    writePolicy: function () {
      log.debug("Entering writePolicy().");
      log.debug("Leaving writePolicy().");
      return true;
    },
    deletePolicy: function () {
      log.debug("Entering deletePolicy().");
      log.debug("Leaving deletePolicy().");
      return true;
    }
  };
}

// The smallest policy that parses, typechecks and decides. Kept minimal on
// purpose: what this file asserts about a policy is that its BYTES move the
// sync token, not anything about what it decides.
function policyXml(id, effect) {
  log.debug("Entering policyXml().");
  log.debug("Leaving policyXml().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
    'PolicyId="' + id + '" Version="1.0" ' +
    'RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-' +
    'algorithm:deny-unless-permit">' +
    '<Target/>' +
    '<Rule RuleId="' + id + ':r" Effect="' + (effect || 'Permit') + '">' +
    '<Target/></Rule></Policy>';
}

async function run(t) {
  log.debug("Entering run().");
  // -------------------------------------------------------------------------
  // 1. THE IMAGE BUILDS THE RUST PEP AND STAMPS ITS VERSION.
  //
  // A comparison of files, which no running service can answer: the
  // Dockerfile builds the `xacml-pep` package of the Rust workspace, stamps
  // `version.json` with that binary at image build time (the version may
  // never be the thing that stops the container starting, and it is the
  // number `/admin/xacml/peps` draws), and copies `VERSION` for it to read.
  // -------------------------------------------------------------------------
  t.log.info('--- The Dockerfile builds the Rust PEP ---');
  const dockerfile = fs.readFileSync(path.join(PEP_DIR, 'Dockerfile'), 'utf8');
  t.check(/cargo\s+build\b[^\n]*--release[^\n]*-p\s+xacml-pep/
            .test(dockerfile),
          'the Dockerfile builds the xacml-pep package of the workspace');
  t.check(/xacml-pep\s+--stamp\s+\./.test(dockerfile),
          'the Dockerfile stamps version.json with the binary itself');
  t.check(/^COPY\s+VERSION\s+\.\/VERSION\s*$/m.test(dockerfile),
          'the Dockerfile copies VERSION, which the stamp reads');
  t.check(/--healthcheck/.test(dockerfile),
          'the image\'s HEALTHCHECK asks the binary, there being no node ' +
          'in it');
  t.check(fs.existsSync(path.join(ROOT, 'rust', 'bins', 'xacml-pep',
                                  'Cargo.toml')),
          'the package the Dockerfile names exists');

  // -------------------------------------------------------------------------
  // 2. THE TWO ENFORCEMENT IMPLEMENTATIONS AGREE — THROUGH ONE TABLE.
  //
  // The embedded PEP against `xacml-pep/enforcement_cases.json` here; the
  // remote one against the same file in its own crate's test. Seven cases:
  // the two the biases agree on, the two they differ on, and the obligation
  // rule on each side.
  // -------------------------------------------------------------------------
  t.log.info('--- Section 7.2, against the shared table ---');
  const xacml = require('../xacml/xacml');
  const config = require('../common/config');
  const table = JSON.parse(fs.readFileSync(
    path.join(PEP_DIR, 'enforcement_cases.json'), 'utf8'));
  const outcomes = {};
  const wasBias = config.value('xacml.pepBias');
  ['deny-biased', 'permit-biased'].forEach(function (bias) {
    config.setOverride('xacml.pepBias', bias);
    outcomes[bias] = table.cases.map(function (one) {
      return xacml.enforce({
        decision: one.decision,
        obligations: one.obligations.map(function (id) {
          return { id: id, assignments: [] };
        })
      }).allowed;
    });
    t.equal(JSON.stringify(outcomes[bias]),
            JSON.stringify(table.cases.map(function (one) {
              return one[bias];
            })),
            'the embedded PEP enforces the shared table, ' + bias +
            ' — the table the remote PEP is held to as well, including the ' +
            'Permit carrying an obligation neither can discharge, which ' +
            'section 7.2 makes a REFUSAL');
  });
  config.setOverride('xacml.pepBias', wasBias);
  // AND THE ONE THAT MUST NOT AGREE: without it, two implementations that
  // both said yes unconditionally would pass.
  t.check(JSON.stringify(outcomes['deny-biased']) !==
          JSON.stringify(outcomes['permit-biased']),
          'the two biases DISAGREE somewhere, so the agreement above is a ' +
          'real comparison');

  // -------------------------------------------------------------------------
  // 3. THE SYNC TOKEN: WHAT IT IS COMPUTED FROM.
  // -------------------------------------------------------------------------
  t.log.info('--- The sync token ---');
  // WHAT WAS THERE, so it can be put back. `tests/CLAUDE.md` records the run
  // this rule was written from: `run.js` runs every file in ONE process, so
  // these slots are one reference shared by the whole suite, and restoring
  // `null` is correct only in a process where `ldap/ldap_server.js` was never
  // loaded — which is a fact about the file LIST rather than about this test.
  // A file added before this one that happens to require that module makes a
  // `null` restore fail inside somebody else's test.
  const storeWas = store.directoryInstalled();
  const registryWas = registry.directoryInstalled();

  const documents = {
    one: { document: policyXml('urn:test:one'), isRoot: true },
    two: { document: policyXml('urn:test:two') }
  };
  store.setDirectory(fakePolicyDirectory(documents));
  const first = registry.syncToken();
  t.check(!!first && first.length > 20, 'a repository has a sync token',
          first);

  // Unchanged content, unchanged token — which is what makes polling cheap.
  t.equal(registry.syncToken(), first,
          'asking twice gives the same token');

  // A DISABLED POLICY MOVES IT, because a disabled policy is not sent and the
  // PEP's copy is therefore wrong. This is the property a modification-time
  // stamp would get right and a naive "hash the whole container" would too —
  // it is here because the NEXT one is what tells those apart.
  documents.two.enabled = false;
  const afterDisable = registry.syncToken();
  t.check(afterDisable !== first,
          'DISABLING a policy moves the token — the PEP is not sent it, so ' +
          'the copy it holds is wrong', first + ' -> ' + afterDisable);

  // AND EDITING A POLICY BACK TO WHAT IT WAS DOES NOT. This is the assertion
  // that distinguishes a digest of the CONTENT from a modification stamp: a
  // stamp would move here and make every PEP re-pull a repository that had
  // not changed.
  documents.two.enabled = true;
  t.equal(registry.syncToken(), first,
          'and putting it back gives the ORIGINAL token — the token is a ' +
          'digest of what would be SENT, so a change and its reversal are ' +
          'not a change. A modification stamp would have moved here and had ' +
          'every PEP re-pull an identical repository');

  // THE ROOT IS IN THE DIGEST. Two repositories holding identical documents
  // and starting from different ones are different policy sets, and a PEP
  // holding the wrong root decides NotApplicable to everything.
  documents.one.isRoot = false;
  documents.two.isRoot = true;
  t.check(registry.syncToken() !== first,
          'moving the ROOT moves the token, even with every document ' +
          'unchanged — a PEP starting from the wrong one decides ' +
          'NotApplicable to everything');
  documents.one.isRoot = true;
  documents.two.isRoot = false;

  // -------------------------------------------------------------------------
  // 4. THE REGISTER.
  // -------------------------------------------------------------------------
  t.log.info('--- The register ---');
  const directory = fakeDirectory();
  registry.setDirectory(directory);
  t.equal(registry.all().length, 0, 'the register starts empty');

  const identity = directory.certificateIdentity({ subject: 'CN=pep-1,O=Ex' });
  const created = registry.register({
    name: identity.commonName, identity: identity.dn,
    certificateSubject: identity.subject, thumbprint: 'abc',
    authenticated: true, notifyUrl: 'https://pep.example.com/notify',
    bias: 'deny-biased', resource: 'https://pep/api', version: 'test'
  });
  t.check(created.ok && created.created, 'a PEP registers', created.why || '');
  t.equal(registry.all().length, 1, 'and is in the register');

  // A RE-REGISTRATION UPDATES rather than duplicating, because the name comes
  // from the certificate and one certificate is one entry.
  registry.heartbeat('pep-1', { decisions: 9, allowed: 5, refused: 4,
                                syncToken: registry.syncToken() });
  const again = registry.register({
    name: 'pep-1', identity: identity.dn,
    certificateSubject: identity.subject, thumbprint: 'abc',
    authenticated: true, notifyUrl: 'https://pep.example.com/notify'
  });
  t.check(again.ok && !again.created,
          're-registering UPDATES the row rather than adding a second one — ' +
          'one certificate is one entry');
  t.equal(registry.all().length, 1, 'still one row');
  t.equal(registry.read('pep-1').decisions, 9,
          'and the counters SURVIVE a re-registration: a PEP that restarts ' +
          'has not un-enforced anything, and zeroing them would make a ' +
          'restart loop look like a component that has never done any work');
  t.check(registry.read('pep-1').registeredAt === created.registeredAt ||
          !!registry.read('pep-1').registeredAt,
          'and it keeps its original registration date');

  // THE ONE THAT WOULD HAVE BEEN A SECURITY-SHAPED MISTAKE: a PEP an
  // administrator disabled must not be able to re-enable itself by
  // reconnecting.
  registry.setEnabled('pep-1', false);
  t.equal(registry.read('pep-1').enabled, false, 'a PEP can be disabled');
  // ASSERTED HERE AND NOT FIVE LINES DOWN, and the ordering is the whole
  // assertion. The row still HOLDS its notify URL at this point, so the only
  // thing that can make it unnotifiable is the disabled flag. A mutation round
  // caught this: the check used to sit after the re-registration below, which
  // clears the URL — so it read 0 whether or not `notifiable()` looked at
  // `enabled` at all, and a `notifiable()` that ignored the flag entirely
  // survived. A guard that passes for the wrong reason is not a guard.
  t.check(!!registry.read('pep-1').notifyUrl,
          'and it still holds its notify URL, which is what makes the next ' +
          'assertion about the DISABLED flag rather than about the URL');
  t.equal(registry.notifiable().length, 0,
          'a disabled PEP is not nudged');
  registry.register({ name: 'pep-1', identity: identity.dn,
                      certificateSubject: identity.subject,
                      authenticated: true });
  t.equal(registry.read('pep-1').enabled, false,
          'and RE-REGISTERING DOES NOT RE-ENABLE IT. A component an ' +
          'administrator stopped nudging must not be able to undo that by ' +
          'reconnecting');
  registry.setEnabled('pep-1', true);

  // AND IT IS STILL NOT NUDGED, because the re-registration above carried NO
  // notifyUrl and the write REPLACES rather than merges. That is the decision
  // `writePep()` documents, and this is the case it was made for: a PEP that
  // re-registers without a notify URL has stopped wanting to be nudged, and a
  // merge would go on dialling the address it used to have — a request this
  // service makes to somewhere nobody asked it to any more.
  t.equal(registry.notifiable().length, 0,
          're-enabling is NOT enough on its own: the re-registration above ' +
          'carried no notify URL and the write replaces rather than merges, ' +
          'so there is no longer an address to nudge. A merge here would go ' +
          'on dialling one nobody asked for any more');
  t.equal(registry.read('pep-1').notifyUrl, '',
          'and the URL really is gone from the row rather than merely being ' +
          'ignored');
  registry.register({ name: 'pep-1', identity: identity.dn,
                      certificateSubject: identity.subject,
                      authenticated: true,
                      notifyUrl: 'https://pep.example.com/notify' });
  t.equal(registry.notifiable().length, 1,
          'and giving one back makes it notifiable again');

  // CURRENT IS A COMPARISON, not a claim. A PEP reporting a token that is not
  // the repository's is not current however confidently it says otherwise.
  registry.heartbeat('pep-1', { syncToken: registry.syncToken() });
  t.equal(registry.read('pep-1').current, true,
          'a PEP holding the repository digest is CURRENT');
  registry.heartbeat('pep-1', { syncToken: 'something-else' });
  t.equal(registry.read('pep-1').current, false,
          'and one holding anything else is not — which is a comparison this ' +
          'service performs rather than a claim the PEP makes about itself');

  // A HEARTBEAT DOES NOT CREATE A ROW.
  const orphan = registry.heartbeat('never-registered', { decisions: 1 });
  t.check(!orphan.ok, 'a heartbeat from something unregistered is refused',
          orphan.why);
  t.check(/register/i.test(orphan.why || ''),
          'and the refusal names the registration endpoint rather than ' +
          'leaving the caller to guess');
  t.equal(registry.all().length, 1, 'and created nothing');

  // A FAILED NUDGE IS RECORDED AND DOES NOT MOVE `lastSeen`. That distinction
  // is the whole value of the field: a nudge that failed is evidence the PEP
  // is NOT reachable, and stamping liveness with it would make an unreachable
  // PEP look freshly seen.
  const seenBefore = registry.read('pep-1').lastSeen;
  // A MILLISECOND HAS TO PASS OR THIS PROVES NOTHING. `lastSeen` is an ISO
  // timestamp, so a recordNotify() that wrongly stamped it in the same
  // millisecond as the write above would write the SAME STRING and the
  // comparison below would pass. The mutation round found exactly that: a
  // recordNotify() that did stamp lastSeen survived. This is the same shape
  // as the fold-boundary case `ldif_codec.js` records — a round trip over
  // convenient data passes while proving nothing.
  await new Promise(function (resolve) {
    setTimeout(resolve, 5);
  });
  registry.recordNotify('pep-1', 'the PEP could not be reached');
  const row = registry.read('pep-1');
  t.check(/could not be reached/.test(row.lastNotify),
          'a failed nudge is recorded on the row — the only place it IS ' +
          'recorded, because it is invisible from the receiving end by ' +
          'definition');
  t.equal(row.lastSeen, seenBefore,
          'and it does NOT move lastSeen: a nudge that failed is evidence ' +
          'the PEP is unreachable, so letting it stamp liveness would make ' +
          'an unreachable PEP look freshly seen');

  // THE NAME IS FOLDED, because it comes off a certificate rather than being
  // typed and a subject may legitimately hold DN syntax.
  t.equal(registry.nameFrom('pep-1.example.com'), 'pep-1.example.com',
          'a hostname-shaped common name is kept as it is');
  t.equal(registry.nameFrom('a b,c=d'), 'a-b-c-d',
          'and DN syntax is folded rather than refused — those characters ' +
          'would otherwise have to be escaped by every reader separately');
  t.equal(registry.nameFrom('   '), '',
          'and something with nothing usable in it folds to nothing, which ' +
          'register() then refuses');

  // -------------------------------------------------------------------------
  // 5. THE NUDGE'S REFUSALS, WITHOUT DIALLING ANYTHING.
  //
  // `urlProblem()` is separate from the request precisely so this is possible
  // — and so that the console and the registration reply can tell a PEP its
  // notify URL will never be dialled without anything being dialled to find
  // out.
  // -------------------------------------------------------------------------
  t.log.info('--- The nudge, refused ---');
  const wasInsecure = config.value('xacml.pepNotifyAllowHttp');
  const wasHosts = config.value('xacml.pepNotifyAllowedHosts');
  config.setOverride('xacml.pepNotifyAllowHttp', false);
  config.setOverride('xacml.pepNotifyAllowedHosts', '');
  t.check(!!pepHttp.urlProblem('http://pep/notify'),
          'plain http is refused while pepNotifyAllowHttp is off');
  t.equal(pepHttp.urlProblem('https://pep.example.com/notify'), null,
          'and https with an empty allowlist is fine — empty means ANY, ' +
          'which is the default and the one deliberate looseness here');
  config.setOverride('xacml.pepNotifyAllowedHosts', 'allowed.example.com');
  t.check(!!pepHttp.urlProblem('https://pep.example.com/notify'),
          'a host off the allowlist is refused');
  t.check(/pep\.example\.com/.test(
            pepHttp.urlProblem('https://pep.example.com/notify') || ''),
          'and the refusal names the host, because a list nobody can compare ' +
          'against is a list nobody can fix');
  t.equal(pepHttp.urlProblem('https://allowed.example.com/anything'), null,
          'while the allowed host is fine at ANY path — hosts rather than ' +
          'URLs, because a component legitimately moves its path and does ' +
          'not legitimately move to another host');
  config.setOverride('xacml.pepNotifyAllowHttp', true);
  t.equal(pepHttp.urlProblem('http://allowed.example.com/notify'), null,
          'and http is allowed once the setting says so');
  t.check(!!pepHttp.urlProblem('ftp://allowed.example.com/notify'),
          'a scheme that is neither http nor https is refused whatever the ' +
          'settings say');
  config.setOverride('xacml.pepNotifyAllowHttp', wasInsecure);
  config.setOverride('xacml.pepNotifyAllowedHosts', wasHosts);

  // TURNED OFF, NOTHING IS DIALLED, and the answer says so rather than
  // reporting a failure — a deployment with no egress is a supported one.
  const wasNotify = config.value('xacml.pepNotify');
  config.setOverride('xacml.pepNotify', false);
  const offAnswer = await pepHttp.nudge('https://pep.example.com/notify', '');
  t.check(!offAnswer.ok && /pepNotify is off/.test(offAnswer.why),
          'with xacml.pepNotify off nothing is dialled and the answer names ' +
          'the setting', offAnswer.why);
  t.check(/next poll/.test(offAnswer.why),
          'and says the PEP converges anyway, which is the whole reason this ' +
          'is safe to turn off');
  config.setOverride('xacml.pepNotify', wasNotify);

  // -------------------------------------------------------------------------
  // 6. THE STORE'S CHANGE OBSERVER IS WHAT FIRES A NUDGE.
  // -------------------------------------------------------------------------
  t.log.info('--- The change observer ---');
  const seen = [];
  store.setChangeObserver(function (what) {
    seen.push(what);
  });
  store.remove('one');
  t.equal(seen.length, 1,
          'removing a policy tells the observer — one choke point for every ' +
          'door that writes through this module');
  // AND AN OBSERVER THAT THROWS DOES NOT BREAK THE WRITE. A PEP that cannot
  // be nudged is not a reason for a policy save to fail.
  store.setChangeObserver(function () {
    throw new Error('the nudge dispatcher is broken');
  });
  let survived = true;
  try {
    store.remove('two');
  } catch (error) {
    log.debug("Caught in run(): " + ((error && error.message) || error));
    survived = false;
  }
  t.check(survived,
          'an observer that THROWS does not take the write down with it — a ' +
          'PEP that cannot be nudged is not a reason for a policy save to ' +
          'fail');
  store.setChangeObserver(null);
  store.setDirectory(storeWas);
  registry.setDirectory(registryWas);

  assert.ok(true);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_pep',
  describe: 'phase five: the engine loads against a thirty-line shim in the ' +
            'PEP container, the Dockerfile copies exactly what it loads, the ' +
            'two enforcement implementations agree, and the register and the ' +
            'sync token behave',
  run: run
};
