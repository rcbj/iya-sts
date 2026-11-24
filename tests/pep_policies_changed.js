// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/pep_policies_changed.js
// ===========================================================================
// AN EMBEDDED PEP HEARS OF A CHANGE OVER SHARED SIGNALS (#2028, work item 5
// of #1206): `pep-policies-changed`.
//
// In a CHILD PROCESS with the whole stack, in the default realm: an
// application with a bound local PEP and a stream it owns, another
// application with a stream of its own, and a root PolicySet referencing one
// policy beside one nothing references. `ssf.pepPoliciesChanged()` is
// wrapped so each call is recorded and still sent.
//
//   C. THE CATALOGUE ROW: `pep-policies-changed` is in the `sts` family,
//      names a subject, and its generator keeps `pep`, `changed` (policies,
//      catalogue, nothing else) and `sync_token`.
//   P. A POLICY CHANGE: one the PEP is not sent tells nobody; one in its
//      closure is told once, naming `policies` and the scope's new token, on
//      the application's stream and not the other's; checking again with
//      nothing changed tells nobody.
//   K. THE CATALOGUE: enforcement switched on another application moves
//      the catalogue and not this PEP's scope: `catalogue` alone.
//   A. `ssfAllowedEvents`: an entry naming only `caep` withholds it (sent to
//      no stream) while this service's own subject-less events stay
//      allowed; the application's view lists the PEP in `pepEventsExcluded`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'pep_policies_changed',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.PPC_ROOT;
  const OUT = process.env.PPC_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const NS = 'urn:oasis:names:tc:xacml:3.0:core:schema:wd-17';
  const policy = function (id, mark) {
    return '<Policy xmlns="' + NS + '" PolicyId="' + id + '" Version="1.0" ' +
      'RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-' +
      'algorithm:deny-overrides"><Target/><Rule RuleId="' + id + ':' +
      (mark || 'r') + '" Effect="Permit"/></Policy>';
  };
  const policySet = function (id, refs) {
    return '<PolicySet xmlns="' + NS + '" PolicySetId="' + id + '" ' +
      'Version="1.0" PolicyCombiningAlgId="urn:oasis:names:tc:xacml:3.0:' +
      'policy-combining-algorithm:deny-overrides"><Target/>' +
      refs.map(function (ref) {
        return '<PolicyIdReference>' + ref + '</PolicyIdReference>';
      }).join('') + '</PolicySet>';
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const config = require(ROOT_DIR + '/common/config');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const serviceAccounts = require(ROOT_DIR + '/common/service_accounts');
    const peps = require(ROOT_DIR + '/xacml/xacml_pep_registry');
    const store = require(ROOT_DIR + '/xacml/xacml_store');
    const xacml = require(ROOT_DIR + '/xacml/xacml');
    const PepBinding = require(ROOT_DIR + '/xacml/xacml_pep_binding');
    const events = require(ROOT_DIR + '/ssf/ssf_events');
    const streams = require(ROOT_DIR + '/ssf/ssf_streams');
    const ssf = require(ROOT_DIR + '/ssf/ssf');
    const adminActions = require(ROOT_DIR + '/admin-core/admin_actions');
    const adminViews = require(ROOT_DIR + '/admin-core/admin_views');

    const stamp = Date.now().toString(36);
    const PEP = 'ppc-pep-' + stamp;
    const OWNER = 'ppc-owner-' + stamp;
    const APP = 'ppc-app-' + stamp;
    const OTHER = 'ppc-other-' + stamp;
    const URI = events.PEP_POLICIES_CHANGED;
    const settle = function () {
      return new Promise(function (r) { setImmediate(r); });
    };

    // -----------------------------------------------------------------------
    // C. THE CATALOGUE ROW.
    // -----------------------------------------------------------------------
    const row = events.EVENT_BY_URI[URI] || {};
    note(row.family === 'sts' && row.subject === 'required' &&
         events.supportedEventUris().indexOf(URI) >= 0,
         'C1. pep-policies-changed is this service\'s own, names a subject, ' +
         'and is offered', JSON.stringify({ family: row.family,
                                             subject: row.subject }));
    const made = row.generate({ pep: 'p', changed: ['catalogue', 'x',
      'policies'], sync_token: 't', policy: '<Policy/>' });
    note(JSON.stringify(made) === JSON.stringify({ pep: 'p',
      changed: ['policies', 'catalogue'], sync_token: 't' }),
         'C2. its payload is pep, changed (policies, catalogue, nothing ' +
         'else) and sync_token, and carries no policy', JSON.stringify(made));

    // -----------------------------------------------------------------------
    // The cast.
    // -----------------------------------------------------------------------
    [APP, OTHER].forEach(function (identifier) {
      applications.createApplication({ identifier: identifier,
        name: identifier, protocols: ['oauth2', 'ssf'] });
    });
    ldap.createUser(OWNER, { invent: false });
    ldap.createUser(PEP, { invent: false });
    ldap.addGroupMember(String(config.value('roles.remotePepGroup')), PEP);
    if (!serviceAccounts.of(PEP)) {
      serviceAccounts.set(PEP, { serviceAccount: true, owners: [OWNER] });
    }
    const bound = PepBinding.shared().set({ name: PEP, application: APP });
    note(bound.ok, 'the PEP is bound to ' + APP, JSON.stringify(bound));
    peps.register({ name: PEP, identity: 'uid=' + PEP, authenticated: true,
                    kind: 'embedded', application: APP, mode: 'local',
                    protocolVersion: 1, version: 't' });
    // THE REALM'S ROOT IS THIS TEST'S: the seeded one is unmarked first, as
    // set-root does.
    const prior = store.root();
    if (prior) {
      store.write(prior.name, prior.document, { isRoot: false,
                                                 enabled: prior.enabled });
    }
    store.write('ppc-shared-' + stamp, policy('urn:ppc:shared:' + stamp),
                { enabled: true });
    store.write('ppc-unrelated-' + stamp,
                policy('urn:ppc:unrelated:' + stamp), { enabled: true });
    store.write('ppc-root-' + stamp, policySet('urn:ppc:root:' + stamp,
      ['urn:ppc:shared:' + stamp]), { enabled: true, isRoot: true });
    await settle();
    const scope = peps.boundPull(APP);
    note(scope.policies.length === 2,
         'the application\'s scope is the root and the policy it references',
         scope.policies.map(function (one) { return one.name; }).join(' '));
    // The PEP holds that scope, as its heartbeat would say.
    peps.heartbeat(PEP, { syncToken: scope.token });
    xacml.checkPepPolicies('the test settles');
    const opened = {};
    [APP, OTHER].forEach(function (owner) {
      const one = streams.createStream(
        { delivery: { method: 'urn:ietf:rfc:8936' },
          events_requested: [URI] },
        { issuer: 'https://sts.test', principal: owner,
          audience: 'https://' + owner + '.test' });
      opened[owner] = one.ok ? one.stream.stream_id : '';
      note(one.ok && one.stream.events_delivered.indexOf(URI) >= 0,
           'a stream ' + owner + ' owns is agreed pep-policies-changed',
           JSON.stringify(one.errors || one.stream.events_delivered));
    });
    const calls = [];
    const real = ssf.pepPoliciesChanged;
    ssf.pepPoliciesChanged = function (notice) {
      const sent = real(notice);
      calls.push({ notice: notice, sent: sent });
      return sent;
    };

    // -----------------------------------------------------------------------
    // P. A POLICY CHANGE.
    // -----------------------------------------------------------------------
    store.write('ppc-unrelated-' + stamp,
                policy('urn:ppc:unrelated:' + stamp, 'r2'), { enabled: true });
    await settle();
    note(calls.length === 0,
         'P1. a change to a policy the PEP is not sent tells nobody',
         JSON.stringify(calls.map(function (one) { return one.notice; })));
    store.write('ppc-shared-' + stamp, policy('urn:ppc:shared:' + stamp, 'r2'),
                { enabled: true });
    await settle();
    const told = calls.splice(0);
    const fresh = peps.boundPull(APP).token;
    const delivered = told.length === 1 ? await told[0].sent : null;
    note(told.length === 1 && told[0].notice.pep === PEP &&
         told[0].notice.application === APP &&
         JSON.stringify(told[0].notice.changed) === '["policies"]' &&
         told[0].notice.syncToken === fresh && fresh !== scope.token,
         'P2. a change in its closure tells the PEP once, naming policies ' +
         'and the scope\'s new token',
         JSON.stringify(told.map(function (one) { return one.notice; })));
    note(delivered && delivered.sent === 1 && delivered.streams === 1,
         'P3. to the one stream its application owns, and not the other ' +
         'application\'s', JSON.stringify(delivered));
    const again = xacml.checkPepPolicies('nothing changed');
    await settle();
    note(again.length === 0 && calls.length === 0,
         'P4. checking again with nothing changed tells nobody',
         JSON.stringify(again));

    // -----------------------------------------------------------------------
    // K. THE CATALOGUE.
    // -----------------------------------------------------------------------
    const switched = await Promise.resolve(adminActions.applicationsAction(
      { action: 'fga-enable', application: OTHER }, undefined,
      { actor: 'test' }));
    await settle();
    await settle();
    const fromCatalogue = calls.splice(0);
    note(switched && switched.ok !== false && fromCatalogue.length === 1 &&
         JSON.stringify(fromCatalogue[0].notice.changed) === '["catalogue"]',
         'K1. enforcement switched on another application moves the ' +
         'catalogue and not this PEP\'s scope: catalogue alone',
         JSON.stringify([switched && (switched.errors || switched.ok),
           fromCatalogue.map(function (one) { return one.notice; })]));

    // -----------------------------------------------------------------------
    // A. ssfAllowedEvents.
    // -----------------------------------------------------------------------
    applications.updateApplication(APP, { attribute: 'ssfAllowedEvents',
                                          mode: 'add', value: 'caep' });
    const restriction = streams.allowedEventsFor(APP);
    note(!!restriction && !restriction.allowed[URI] &&
         !!restriction.allowed[events.SIGNING_KEY_ROTATED],
         'A1. an entry naming only caep withholds pep-policies-changed, ' +
         'and still allows this service\'s own events that name nobody',
         JSON.stringify(restriction && Object.keys(restriction.allowed)
           .filter(function (one) { return /iya:sts/.test(one); })));
    store.write('ppc-shared-' + stamp, policy('urn:ppc:shared:' + stamp, 'r3'),
                { enabled: true });
    await settle();
    const withheld = calls.splice(0);
    const none = withheld.length === 1 ? await withheld[0].sent : null;
    note(withheld.length === 1 && none && none.sent === 0,
         'A2. the change is decided and sent to no stream',
         JSON.stringify(none));
    const excluded = adminViews.pepEventsExcludedOf
      ? adminViews.pepEventsExcludedOf(APP, [PEP]) : null;
    note(JSON.stringify(excluded) === JSON.stringify([PEP]),
         'A3. the application\'s view lists the local PEP that will not hear ' +
         'of a change', JSON.stringify(excluded));
    ssf.pepPoliciesChanged = real;
    Object.keys(opened).forEach(function (owner) {
      if (opened[owner]) {
        streams.removeStream(opened[owner]);
      }
    });

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ppc-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  PPC_ROOT: ROOT, PPC_OUT: out }),
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
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pep_policies_changed',
  describe: 'an embedded PEP is told over Shared Signals when what it ' +
            'pulls changes: pep-policies-changed, to its application\'s ' +
            'streams, respecting ssfAllowedEvents (#2028)',
  run: run
};
