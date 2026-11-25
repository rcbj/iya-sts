// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/xacml_pep_scope.js
// ===========================================================================
// THE POLICY PULL SCOPED TO A BOUND APPLICATION (#2027, work item 4 of
// #1206): `PepRegistry.boundPull()`, over a repository written here.
//
//   A. AN APPLICATION THAT ENFORCES FINE-GRAINED AUTHORIZATION: its own
//      policy, as the root, and nothing it does not reference; never
//      another application's, the realm root, or the access and issuance
//      policies.
//   B. ONE THAT DOES NOT: the realm root and its closure, transitively, a
//      PolicySet reaching a PolicySet reaching a Policy; a reference to the
//      access policy, to another application's policy and to a disabled
//      policy left unresolved; a cycle followed once.
//   T. THE TOKEN: a change outside the closure leaves it; a change inside
//      it, the root moved, and enforcement switched each move it; the
//      scope's token is not the repository's.
//   C. `current` on a row: a local embedded PEP holding its scope's token
//      is current, holding the repository's it is not; a container is
//      compared with the repository's as before.
//
// The door (`GET /xacml/pep/policies?scope=bound-application`: who is
// answered, the 304 and the refusals) is `tests/protocol/
// sts_xacml_pep_scope.js`'s.
// ===========================================================================

const path = require('path');

const ROOT = path.join(__dirname, '..');
const NS = 'urn:oasis:names:tc:xacml:3.0:core:schema:wd-17';
const DENY = 'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:' +
             'deny-overrides';
const DENY_SET = 'urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:' +
                 'deny-overrides';

function policy(id) {
  return '<Policy xmlns="' + NS + '" PolicyId="' + id + '" Version="1.0" ' +
    'RuleCombiningAlgId="' + DENY + '"><Target/>' +
    '<Rule RuleId="' + id + ':r" Effect="Permit"/></Policy>';
}

function policySet(id, refs) {
  return '<PolicySet xmlns="' + NS + '" PolicySetId="' + id + '" ' +
    'Version="1.0" PolicyCombiningAlgId="' + DENY_SET + '"><Target/>' +
    refs.map(function (one) {
      return one.set
        ? '<PolicySetIdReference>' + one.id + '</PolicySetIdReference>'
        : '<PolicyIdReference>' + one.id + '</PolicyIdReference>';
    }).join('') + '</PolicySet>';
}

function row(name, id, document, extra) {
  return Object.assign({ name: name, id: id, document: document,
    kind: /^<PolicySet/.test(document) ? 'PolicySet' : 'Policy',
    version: '1.0', combiningAlgId: '', description: '', enabled: true,
    isRoot: false, application: null, role: null, orphanedAt: null,
    pepRoute: null }, extra || {});
}

async function run(t) {
  t.log.debug("Entering run().");
  const peps = require(ROOT + '/xacml/xacml_pep_registry');
  const PepRegistry = peps.PepRegistry;
  const rows = [
    row('root', 'urn:t:root', policySet('urn:t:root', [
      { id: 'urn:t:mid', set: true }, { id: 'urn:t:shared' },
      { id: 'urn:t:access' }, { id: 'urn:t:app-b' }, { id: 'urn:t:off' },
      { id: 'urn:t:missing' }]), { isRoot: true }),
    row('mid', 'urn:t:mid', policySet('urn:t:mid', [
      { id: 'urn:t:leaf' }, { id: 'urn:t:root', set: true }])),
    row('leaf', 'urn:t:leaf', policy('urn:t:leaf')),
    row('shared', 'urn:t:shared', policy('urn:t:shared')),
    row('unrelated', 'urn:t:unrelated', policy('urn:t:unrelated')),
    row('off', 'urn:t:off', policy('urn:t:off'), { enabled: false }),
    row('access-control', 'urn:t:access', policy('urn:t:access')),
    row('role-issuance', 'urn:t:issuance', policy('urn:t:issuance')),
    row('fga-app-a', 'urn:t:app-a', policy('urn:t:app-a'),
        { application: 'app-a' }),
    row('fga-app-b', 'urn:t:app-b', policy('urn:t:app-b'),
        { application: 'app-b' }),
    row('fga-app-a-old', 'urn:t:app-a', policy('urn:t:app-a-old'),
        { application: 'app-a', orphanedAt: '2026-01-01T00:00:00Z' })
  ];
  const enforcing = ['app-a', 'app-b'];
  const store = {
    all: function () {
      return rows.map(function (one) {
        return Object.assign({}, one);
      });
    },
    root: function () {
      return rows.filter(function (one) {
        return one.enabled && one.isRoot && !one.application;
      })[0] || null;
    }
  };
  const registry = new PepRegistry(Object.assign(PepRegistry.defaultDeps(), {
    store: store,
    enforcesFga: function (application) {
      return enforcing.indexOf(application) >= 0;
    }
  }));
  const names = function (pulled) {
    return pulled.policies.map(function (one) {
      return one.name;
    }).sort();
  };

  // -------------------------------------------------------------------------
  // A. AN APPLICATION THAT ENFORCES.
  // -------------------------------------------------------------------------
  const a = registry.boundPull('app-a');
  t.equal(JSON.stringify(names(a)), JSON.stringify(['fga-app-a']),
          'A1. an enforcing application is sent its own policy and nothing ' +
          'else: not the root, not another application\'s, not an orphan');
  t.check(a.source === 'application' && a.root === 'fga-app-a' &&
          a.policies[0].isRoot === true && a.policies[0].policyId ===
          'urn:t:app-a' && /urn:t:app-a"/.test(a.policies[0].document),
          'A2. its own policy is the one row marked root, with its document',
          JSON.stringify(a.policies.map(function (one) {
            return [one.name, one.isRoot];
          })));
  t.check(a.withheld.indexOf('access-control') >= 0 &&
          a.withheld.indexOf('role-issuance') >= 0,
          'A3. the access and issuance policies are named as withheld',
          a.withheld.join(' '));

  // -------------------------------------------------------------------------
  // B. ONE THAT DOES NOT ENFORCE: THE ROOT AND ITS CLOSURE.
  // -------------------------------------------------------------------------
  const c = registry.boundPull('app-c');
  t.equal(JSON.stringify(names(c)),
          JSON.stringify(['leaf', 'mid', 'root', 'shared']),
          'B1. an application that enforces nothing is sent the root and ' +
          'its closure, transitively (root -> mid -> leaf), and a cycle ' +
          'back to the root is followed once');
  t.check(c.source === 'root' && c.policies.filter(function (one) {
    return one.isRoot;
  }).map(function (one) {
    return one.name;
  }).join() === 'root',
          'B2. the realm root is the one row marked root', c.source);
  t.check(names(c).indexOf('access-control') < 0 &&
          names(c).indexOf('fga-app-b') < 0 && names(c).indexOf('off') < 0 &&
          names(c).indexOf('unrelated') < 0,
          'B3. a reference to the access policy, to another application\'s ' +
          'policy and to a disabled one is left unresolved, and an ' +
          'unreferenced policy is not sent', names(c).join(' '));

  // -------------------------------------------------------------------------
  // T. THE TOKEN.
  // -------------------------------------------------------------------------
  const tokenA = a.token;
  const tokenC = c.token;
  t.check(tokenA !== tokenC && tokenC !== registry.syncToken(),
          'T1. each scope has its own token, and neither is the ' +
          'repository\'s');
  const unrelated = rows.filter(function (one) {
    return one.name === 'unrelated';
  })[0];
  unrelated.document = policy('urn:t:unrelated-2');
  const repositoryMoved = registry.syncToken();
  t.check(registry.boundPull('app-c').token === tokenC &&
          registry.boundPull('app-a').token === tokenA,
          'T2. a policy outside the closure changes and neither scope\'s ' +
          'token moves (the repository\'s did)', repositoryMoved);
  rows.filter(function (one) {
    return one.name === 'fga-app-b';
  })[0].document = policy('urn:t:app-b-2');
  t.check(registry.boundPull('app-a').token === tokenA &&
          registry.boundPull('app-c').token === tokenC,
          'T3. another application\'s policy changes and neither moves');
  const leaf = rows.filter(function (one) {
    return one.name === 'leaf';
  })[0];
  leaf.document = policy('urn:t:leaf') + ' ';
  t.check(registry.boundPull('app-c').token !== tokenC &&
          registry.boundPull('app-a').token === tokenA,
          'T4. a policy in the closure changes and that scope\'s token ' +
          'moves, the other\'s does not');
  leaf.document = policy('urn:t:leaf');
  t.equal(registry.boundPull('app-c').token, tokenC,
          'T5. and putting it back gives the original token');
  enforcing.splice(enforcing.indexOf('app-a'), 1);
  const switched = registry.boundPull('app-a');
  t.check(switched.token !== tokenA && switched.source === 'root',
          'T6. enforcement switched off moves the token: the application ' +
          'is sent the root', switched.source);
  enforcing.push('app-a');

  // -------------------------------------------------------------------------
  // C. `current` ON A ROW.
  // -------------------------------------------------------------------------
  const entries = {};
  const directory = {
    allPeps: function () {
      return Object.keys(entries).map(function (name) {
        return { name: name, dn: 'cn=' + name, attributes: entries[name] };
      });
    },
    writePep: function () {
      return true;
    },
    deletePep: function () {
      return true;
    }
  };
  const wasDirectory = peps.directoryInstalled();
  peps.setDirectory(directory);
  try {
    const seen = new Date().toISOString();
    entries['local-1'] = { xacmlPepKind: 'embedded',
      xacmlPepApplication: 'app-a', xacmlPepMode: 'local',
      xacmlPepSyncToken: tokenA, xacmlPepLastSeen: seen };
    entries['local-2'] = { xacmlPepKind: 'embedded',
      xacmlPepApplication: 'app-a', xacmlPepMode: 'local',
      xacmlPepSyncToken: registry.syncToken(), xacmlPepLastSeen: seen };
    entries['box'] = { xacmlPepSyncToken: registry.syncToken(),
                       xacmlPepLastSeen: seen };
    const byName = {};
    registry.all().forEach(function (one) {
      byName[one.name] = one;
    });
    t.check(byName['local-1'].current === true &&
            byName['local-2'].current === false &&
            byName['box'].current === true,
            'C1. a local embedded PEP is current with its scope\'s token, ' +
            'not with the repository\'s; a container with the repository\'s',
            JSON.stringify([byName['local-1'].current,
                            byName['local-2'].current, byName.box.current]));
  } finally {
    peps.setDirectory(wasDirectory);
  }
  t.log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_pep_scope',
  describe: 'the policy pull scoped to a bound application: its own ' +
            'policy or the realm root, the reference closure, nothing ' +
            'else, and a token of its own (#2027)',
  run: run
};
