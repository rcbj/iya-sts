// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/xacml_pep_clusters.js
//
// ===========================================================================
// REMOTE PEP CLUSTERS (#1760, phase 1).
//
// rcbj: "a concept of a logical cluster of Remote PEPs that share a common
// configuration ... The only thing that should differ between the Remote
// PEPs is its identifier and listening address."
//
// In a throwaway realm, in a CHILD PROCESS (`xacml_pep_proxy.js`'s reason:
// the whole stack loads), through the real register, merge, pulls and
// actions (`admin-core/admin_actions.ts`):
//
//   A. a standalone PEP behaves exactly as before: its effective row IS its
//      row, and its pulls' tokens are unchanged by a cluster existing;
//   B. create from a PEP: the documents copied, the PEP the first member,
//      its own cleared, the routes' policies `pepc-<cluster>-<route>`
//      marked `@<cluster>/<route>`, one policy for every member;
//   C. the effective row: the member's publicBaseUrl, notify URL and
//      listener addresses over the cluster's documents, and the pulls
//      answered from it, the proxy naming the shared policy;
//   D. tokens move for every member on one cluster edit; nudges go to
//      every member;
//   E. join: refused without `discard`, then the own documents answered
//      and cleared; a PEP in two clusters refused; a name not registered
//      yet listed;
//   F. the per-member checks: the callback each member's publicBaseUrl
//      needs, a listener clash against the member's own report, a session
//      route with signals on (saved: each member polls its own stream),
//      the resource refusal, a notify URL on the cluster;
//   G. a member's own per-PEP actions refused, naming the cluster; and
//      Sync: refused with no notify URL, a member nudged alone for a full
//      pull and its cluster named, a PEP whose nudges are stopped dialled
//      all the same, a lost nudge refused;
//   H. leave with keep (its routes' policies `pep-<pep>-<route>`) and with
//      empty; delete refused with members, then released;
//   I. the view, `GET /admin-api/xacml/pep-clusters`' answer;
//   J. one application client's CAEP/RISC streams, told apart only by
//      X-Iya-Pep-Name: each member's stream, the untagged list, a bad
//      header refused as STS-SSF-0163, and a poll of one member's queue.
//
// The over-HTTP half, two xacml-pep containers, is
// `tests/protocol/sts_xacml_pep_cluster.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_XACML_PEP_CLUSTERS_CHILD';
const MARK = 'XACML-PEP-CLUSTERS-CHILD ';
const BASE1 = 'https://pep-1.example.test:9543';
const BASE2 = 'https://pep-2.example.test:9543';
const LOGICAL = 'https://orders.example.test';
const SECRET = 'pcl-web-secret-0123456789abcdef0123456789';

// The logical address named in a policy, parsed rather than searched for
// as text (`protocol/url_match.js`).
const urls = require('./protocol/url_match.js');
const log = require('bunyan').createLogger({ name: 'xacml_pep_clusters',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

// A reported listener set, as a heartbeat carries it.
function report(port) {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return { listeners: [
    { id: 'api-https', source: 'environment', protocol: 'https',
      purpose: 'api', address: '0.0.0.0', port: 9443, state: 'listening',
      reason: 'none' },
    { id: 'proxy-https', source: 'environment', protocol: 'https',
      purpose: 'proxy', address: '0.0.0.0', port: port, state: 'listening',
      reason: 'none' }] };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const realms = require(ROOT + '/common/realms');
  const applications = require(ROOT + '/common/applications');
  const roles = require(ROOT + '/common/roles');
  const errorCodes = require(ROOT + '/common/error_codes');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const store = require(ROOT + '/xacml/xacml_store');
  const peps = require(ROOT + '/xacml/xacml_pep_registry');
  const clusters = require(ROOT + '/xacml/xacml_pep_clusters');
  const pepProxy = require(ROOT + '/xacml/xacml_pep_proxy');
  const pepSettings = require(ROOT + '/xacml/xacml_pep_settings');
  const surface = require(ROOT + '/xacml/xacml');
  const pap = require(ROOT + '/xacml/xacml_admin');
  const adminActions = require(ROOT + '/admin-core/admin_actions');

  const act = function (body) {
    log.debug("Entering act().");
    log.debug("Leaving act().");
    return adminActions.xacmlAction(body);
  };
  const codeOf = function (answer) {
    log.debug("Entering codeOf().");
    log.debug("Leaving codeOf().");
    return errorCodes.codeOf(answer) || (answer && answer.code) || '';
  };
  // THE NUDGES, recorded where they would be dispatched.
  const nudged = [];
  const realNudge = surface.nudgePeps;
  surface.nudgePeps = function (names, what) {
    log.debug("Entering nudgePeps().");
    nudged.push({ names: names.slice(), what: what });
    log.debug("Leaving nudgePeps().");
  };

  const id = 'pcl-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, '0. a trust realm to work in',
          (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving childBody(). No realm.");
    return t.rows;
  }
  try {
    await realms.run(made.realm, async function () {
      log.debug("Entering realmBody().");
      ldap.createUser('pcl-reader', { invent: false });
      roles.write('pcl-readers', { users: ['pcl-reader'] });
      applications.createApplication({ identifier: 'pcl-api',
        protocols: ['oauth2'],
        fields: { oauthClientId: 'pcl-api',
                  oauthAudience: ['https://api.example.test/'] } });
      applications.createApplication({ identifier: 'pcl-web',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'pcl-web', oauthClientSecret: SECRET,
                  oauthTokenEndpointAuthMethod: 'client_secret_basic',
                  oauthGrantType: ['authorization_code'],
                  oauthRedirectUri: [BASE1 + '/.iya-pep/callback',
                                     LOGICAL + '/.iya-pep/callback'] } });
      ['pep-1', 'pep-2', 'pep-3', 'pep-solo'].forEach(function (name) {
        peps.register({ name: name,
          identity: 'cn=' + name + ',ou=users,dc=example,dc=com',
          certificateSubject: 'CN=' + name, thumbprint: 'test-' + name,
          authenticated: true, bias: 'deny', resource: BASE1,
          hostname: name + '.example.test' });
      });
      peps.heartbeat('pep-2', { listeners: report(9777) });

      // ---------------------------------------------------------------
      // A. A STANDALONE PEP.
      // ---------------------------------------------------------------
      const solo = { upstream: 'http://solo.internal:8080',
        publicBaseUrl: BASE1, routes: [
          { id: 'health', path: '/health', match: 'exact',
            methods: ['GET'], authorization: { kind: 'public' } }] };
      const soloSaved = act({ action: 'set-pep-proxy', name: 'pep-solo',
                              proxy: solo });
      const soloRow = peps.read('pep-solo');
      const soloBefore = pepProxy.pull('https://sts.example', soloRow,
                                       'pep-solo').token;
      t.check(soloSaved.ok && clusters.effectiveRow(soloRow) === soloRow,
              'A1. a PEP in no cluster: its effective row IS its row',
              JSON.stringify(soloSaved));

      // ---------------------------------------------------------------
      // B. CREATE FROM A PEP.
      // ---------------------------------------------------------------
      const doc = { upstream: 'http://orders.internal:8080',
        publicBaseUrl: BASE1, routes: [
          { id: 'health', path: '/health', match: 'exact',
            methods: ['GET', 'HEAD'], authorization: { kind: 'public' } },
          { id: 'orders', path: '/orders', match: 'prefix',
            methods: ['GET', 'POST'], mechanisms: ['oauth2'],
            application: 'pcl-api',
            authorization: { kind: 'simple', actionModel: 'read-write',
                             roles: { read: ['pcl-readers'] } } }] };
      const own = act({ action: 'set-pep-proxy', name: 'pep-1',
                        proxy: doc });
      act({ action: 'set-pep-settings', name: 'pep-1',
            settings: { bias: 'deny-biased',
                        notifyUrl: BASE1 + '/notify' } });
      act({ action: 'set-pep-listener', name: 'pep-1', listener: {
        id: 'proxy-alt', protocol: 'https', purpose: 'proxy', port: 9600,
        dnsNames: ['orders.example.test'] } });
      t.check(own.ok && store.read('pep-pep-1-health'),
              'B0. pep-1 holds its own configuration, its policies ' +
              'pep-pep-1-<route>', JSON.stringify(own));
      const bad = act({ action: 'create-pep-cluster', cluster: 'a b' });
      t.check(!bad.ok && codeOf(bad) === 'STS-XACML-0270',
              'B1. a cluster name that is not one is refused (0270)',
              JSON.stringify(bad));
      const created = act({ action: 'create-pep-cluster', cluster: 'orders',
                            from: 'pep-1', description: 'The orders proxies' });
      const c1 = clusters.read('orders');
      const shared = store.read('pepc-orders-health');
      t.check(created.ok && c1 && c1.members.length === 1 &&
              c1.members[0].pep === 'pep-1' &&
              c1.members[0].publicBaseUrl === BASE1 &&
              c1.members[0].notifyUrl === BASE1 + '/notify',
              'B2. created from pep-1: its first member, its publicBaseUrl ' +
              'and notify URL kept as the member\'s own',
              JSON.stringify([created, c1]));
      t.check(shared && shared.pepRoute === '@orders/health' &&
              store.read('pepc-orders-orders') &&
              store.read('pepc-orders-orders').pepRoute === '@orders/orders',
              'B3. one policy per route for the cluster, pepc-orders-<route> ' +
              'marked @orders/<route>',
              JSON.stringify(shared && shared.pepRoute));
      t.check(JSON.parse(c1.settings).bias === 'deny-biased' &&
              JSON.parse(c1.settings).notifyUrl === undefined &&
              JSON.parse(c1.listeners)[0].id === 'proxy-alt',
              'B4. the settings (without the notify URL) and the listeners ' +
              'are the cluster\'s', c1.settings + ' ' + c1.listeners);
      const p1 = peps.read('pep-1');
      t.check(!p1.proxy && !p1.settings && !p1.listeners &&
              created.policies.unreferenced.indexOf('pep-pep-1-health') >= 0,
              'B5. pep-1\'s own documents are cleared, and its old ' +
              'generated policies reported unreferenced',
              JSON.stringify(created.policies));
      const dup = act({ action: 'create-pep-cluster', cluster: 'orders' });
      const twice = act({ action: 'create-pep-cluster', cluster: 'other',
                          from: 'pep-1' });
      t.check(!dup.ok && codeOf(dup) === 'STS-XACML-0270' && !twice.ok &&
              codeOf(twice) === 'STS-XACML-0271',
              'B6. a name taken (0270), and a PEP already a member (0271), ' +
              'are refused', JSON.stringify([dup, twice]));

      // ---------------------------------------------------------------
      // C. THE EFFECTIVE ROW AND THE PULLS.
      // ---------------------------------------------------------------
      const e1 = clusters.effectiveRow(peps.read('pep-1'));
      const pulled = pepProxy.pull('https://sts.example', e1, 'pep-1');
      const policies = pulled.body.proxy.routes.map(function (r) {
        return r.authorization.policy;
      });
      t.check(e1.cluster === 'orders' && pulled.body.configured &&
              policies.join(',') === 'pepc-orders-health,pepc-orders-orders' &&
              pulled.body.proxy.publicBaseUrl === BASE1,
              'C1. a member pulls the cluster\'s routes naming the ' +
              'cluster\'s ' +
              'policies, at its own publicBaseUrl', JSON.stringify(policies));
      const sentNames = surface.pepPull().policies.map(function (p) {
        return p.name;
      });
      t.check(sentNames.indexOf('pepc-orders-health') >= 0 &&
              sentNames.indexOf('pepc-orders-orders') >= 0,
              'C2. the policy pull sends the cluster\'s policies, so every ' +
              'member finds them by name', sentNames.join(','));
      const s1 = pepSettings.pull(e1, 'pep-1');
      t.check(s1.body.settings.bias === 'deny-biased' &&
              s1.body.settings.notifyUrl === BASE1 + '/notify' &&
              s1.body.listeners[0].id === 'proxy-alt',
              'C3. the settings pull: the cluster\'s settings with the ' +
              'member\'s notify URL, and the cluster\'s listeners',
              JSON.stringify(s1.body));

      // ---------------------------------------------------------------
      // E. JOIN.
      // ---------------------------------------------------------------
      act({ action: 'set-pep-settings', name: 'pep-2',
            settings: { pollIntervalMs: 5000 } });
      const noDiscard = act({ action: 'add-pep-cluster-member',
                              cluster: 'orders', pep: 'pep-2',
                              publicBaseUrl: BASE2 });
      t.check(!noDiscard.ok && codeOf(noDiscard) === 'STS-XACML-0272',
              'E1. a PEP with its own configuration is refused without ' +
              'discard (0272)', JSON.stringify(noDiscard));
      // The callback of pep-2's own publicBaseUrl is not registered yet.
      const noCallback = act({ action: 'add-pep-cluster-member',
        cluster: 'orders', pep: 'pep-2', publicBaseUrl: BASE2,
        discard: true });
      t.check(noCallback.ok, 'E2. pep-2 joins with discard (no session ' +
              'route yet, so no callback is needed)',
              JSON.stringify(noCallback));
      t.check(noCallback.discarded && noCallback.discarded.settings &&
              noCallback.discarded.settings.pollIntervalMs === 5000 &&
              !peps.read('pep-2').settings,
              'E3. the discarded documents are answered and cleared',
              JSON.stringify(noCallback.discarded));
      const unreg = act({ action: 'add-pep-cluster-member', cluster: 'orders',
                          pep: 'pep-future' });
      t.check(unreg.ok && unreg.registered === false,
              'E4. a name not registered yet may be listed',
              JSON.stringify(unreg));
      act({ action: 'create-pep-cluster', cluster: 'second' });
      const elsewhere = act({ action: 'add-pep-cluster-member',
                              cluster: 'second', pep: 'pep-2' });
      t.check(!elsewhere.ok && codeOf(elsewhere) === 'STS-XACML-0271',
              'E5. a PEP in one cluster is refused by another (0271)',
              JSON.stringify(elsewhere));

      // ---------------------------------------------------------------
      // D. TOKENS AND NUDGES.
      // ---------------------------------------------------------------
      const before1 = pepProxy.pull('https://sts.example',
        clusters.effectiveRow(peps.read('pep-1')), 'pep-1').token;
      const before2 = pepProxy.pull('https://sts.example',
        clusters.effectiveRow(peps.read('pep-2')), 'pep-2').token;
      const e2 = clusters.effectiveRow(peps.read('pep-2'));
      t.check(e2.cluster === 'orders' && before1 !== before2 &&
              JSON.parse(e2.proxy).publicBaseUrl === BASE2,
              'D0. two members differ only in their addresses: their ' +
              'tokens differ, pep-2 at its own publicBaseUrl', e2.proxy);
      nudged.length = 0;
      const edit = act({ action: 'set-pep-cluster-route', cluster: 'orders',
        route: { id: 'status', path: '/status', match: 'exact',
                 methods: ['GET'], authorization: { kind: 'public' } } });
      const after1 = pepProxy.pull('https://sts.example',
        clusters.effectiveRow(peps.read('pep-1')), 'pep-1').token;
      const after2 = pepProxy.pull('https://sts.example',
        clusters.effectiveRow(peps.read('pep-2')), 'pep-2').token;
      t.check(edit.ok && after1 !== before1 && after2 !== before2 &&
              store.read('pepc-orders-status') &&
              !urls.namesOrigin(
                store.read('pepc-orders-status').document, LOGICAL),
              'D1. one cluster edit moves every member\'s token, and its ' +
              'generated policy is the cluster\'s', JSON.stringify(edit));
      const names = nudged.length ? nudged[nudged.length - 1].names : [];
      t.check(names.indexOf('pep-1') >= 0 && names.indexOf('pep-2') >= 0 &&
              names.indexOf('pep-future') >= 0,
              'D2. every member is nudged after a cluster write',
              JSON.stringify(nudged));
      t.check(pepProxy.pull('https://sts.example', peps.read('pep-solo'),
                            'pep-solo').token === soloBefore,
              'A2. the standalone PEP\'s token is unchanged by the cluster');

      // ---------------------------------------------------------------
      // F. THE PER-MEMBER CHECKS.
      // ---------------------------------------------------------------
      const session = act({ action: 'set-pep-cluster-route',
        cluster: 'orders', route: { id: 'web', path: '/web',
          match: 'prefix', methods: ['GET'], mechanisms: ['session'],
          application: 'pcl-web', signals: false,
          authorization: { kind: 'simple', actionModel: 'read-write',
                           roles: { read: ['pcl-readers'] } } } });
      t.check(!session.ok &&
              /^STS-XACML-02(1[7-9]|2[0-3])$/.test(codeOf(session)) &&
              /Member "pep-2"/.test(session.why),
              'F1. a session route is refused while a member\'s own ' +
              'callback is not registered, naming the member',
              JSON.stringify(session));
      const added = applications.updateApplication('pcl-web',
        { attribute: 'oauthRedirectUri', mode: 'add',
          value: BASE2 + '/.iya-pep/callback' });
      t.check(added && added.ok !== false, 'F1b. pep-2\'s callback ' +
              'registered on the client', JSON.stringify(added));
      const session2 = act({ action: 'set-pep-cluster-route',
        cluster: 'orders', route: { id: 'web', path: '/web',
          match: 'prefix', methods: ['GET'], mechanisms: ['session'],
          application: 'pcl-web', signals: false,
          authorization: { kind: 'simple', actionModel: 'read-write',
                           roles: { read: ['pcl-readers'] } } } });
      t.check(session2.ok, 'F2. registered for every member, it saves',
              JSON.stringify(session2));
      const signals = act({ action: 'set-pep-cluster-route',
        cluster: 'orders', from: 'web', part: 'authentication',
        mechanisms: ['session'], signals: 'true' });
      t.check(signals.ok,
              'F3. signals on a session route saves: each member polls a ' +
              'stream of its own', JSON.stringify(signals));
      const clash = act({ action: 'set-pep-cluster-listener',
        cluster: 'orders', listener: { id: 'proxy-alt', protocol: 'https',
          purpose: 'proxy', port: 9777 } });
      t.check(!clash.ok && codeOf(clash) === 'STS-XACML-0247' &&
              /Member "pep-2"/.test(clash.why),
              'F4. a listener on the port a member reports holding is ' +
              'refused, naming the member (0247)', JSON.stringify(clash));
      const notify = act({ action: 'set-pep-cluster-settings',
        cluster: 'orders', settings: { notifyUrl: BASE1 + '/n' } });
      t.check(!notify.ok && codeOf(notify) === 'STS-XACML-0278',
              'F5. a notify URL in the cluster\'s settings is refused (0278)',
              JSON.stringify(notify));
      act({ action: 'create-pep-cluster', cluster: 'nobase' });
      const noBase = act({ action: 'set-pep-cluster-proxy',
        cluster: 'nobase', proxy: { upstream: 'http://u.internal',
          routes: [{ id: 'h', path: '/h', methods: ['GET'],
                     authorization: { kind: 'public' } }] } });
      t.check(!noBase.ok && codeOf(noBase) === 'STS-XACML-0274',
              'F6. a public route with no resource and no cluster base URL ' +
              'is refused (0274)', JSON.stringify(noBase));
      const addr = act({ action: 'set-pep-cluster-member', cluster: 'orders',
        pep: 'pep-2', listeners: 'proxy-alt :9601 pep-2.example.test' });
      const e2b = clusters.effectiveRow(peps.read('pep-2'));
      const alt = JSON.parse(e2b.listeners)[0];
      t.check(addr.ok && alt.port === 9601 &&
              alt.dnsNames.indexOf('pep-2.example.test') >= 0 &&
              alt.dnsNames.indexOf('orders.example.test') >= 0,
              'F7. a member\'s listener override: its port, and its names ' +
              'added to the cluster\'s', JSON.stringify([addr, alt]));
      const badMember = act({ action: 'set-pep-cluster-member',
        cluster: 'orders', pep: 'pep-2', listeners: { 'proxy-alt':
          { port: 70000 } } });
      t.check(!badMember.ok && codeOf(badMember) === 'STS-XACML-0277',
              'F8. a member override of the wrong shape is refused (0277)',
              JSON.stringify(badMember));

      // ---------------------------------------------------------------
      // G. A MEMBER'S OWN ACTIONS.
      // ---------------------------------------------------------------
      const refusedActs = ['set-pep-proxy', 'set-pep-route',
                           'set-pep-settings', 'set-pep-listener',
                           'remove-pep-route'];
      const answers = refusedActs.map(function (action) {
        return act({ action: action, name: 'pep-2', proxy: doc,
                     route: 'health', settings: {} });
      });
      t.check(answers.every(function (a) {
        return !a.ok && codeOf(a) === 'STS-XACML-0276' &&
          /cluster "orders"/.test(a.why);
      }), 'G1. a member\'s per-PEP configuration actions are refused, ' +
          'naming the cluster (0276)', JSON.stringify(answers));
      const enable = act({ action: 'disable-pep', name: 'pep-2' });
      act({ action: 'enable-pep', name: 'pep-2' });
      t.check(enable.ok, 'G2. enabling and disabling stay the PEP\'s own');

      // ---------------------------------------------------------------
      // G3-G7. SYNC (rcbj, 2026-11-16): one nudge to one PEP, awaited.
      // The notifier is the module object the console's deps hold, so
      // replacing its members here is what `syncPep()` calls.
      // ---------------------------------------------------------------
      const notifier = require(ROOT + '/xacml/xacml_pep_http');
      const realSend = notifier.nudge;
      const realAllowed = notifier.notifyAllowed;
      const realProblem = notifier.urlProblem;
      const dialled = [];
      const asked = [];
      let deliver = true;
      notifier.notifyAllowed = function () {
        log.debug("Entering notifyAllowed().");
        log.debug("Leaving notifyAllowed().");
        return true;
      };
      notifier.urlProblem = function () {
        log.debug("Entering urlProblem().");
        log.debug("Leaving urlProblem().");
        return null;
      };
      notifier.nudge = function (url, issuer, options) {
        log.debug("Entering nudge().");
        dialled.push(String(url));
        asked.push(options || null);
        log.debug("Leaving nudge().");
        return Promise.resolve(deliver
          ? { ok: true, status: 204, why: 'Delivered (204).' }
          : { ok: false, status: 0, why: 'connect ECONNREFUSED' });
      };
      try {
        const noUrl = await act({ action: 'sync-pep', name: 'pep-solo' });
        t.check(!noUrl.ok && codeOf(noUrl) === 'STS-XACML-0284' &&
                dialled.length === 0,
                'G3. Sync of a PEP with no notify URL is refused (0284) ' +
                'and dials nothing', JSON.stringify(noUrl));
        peps.register({ name: 'pep-2',
          identity: 'cn=pep-2,ou=users,dc=example,dc=com',
          certificateSubject: 'CN=pep-2', thumbprint: 'test-pep-2',
          authenticated: true, bias: 'deny', resource: BASE1,
          hostname: 'pep-2.example.test',
          notifyUrl: 'https://pep-2.example.test:9443/notify' });
        const synced = await act({ action: 'sync-pep', name: 'pep-2' });
        t.check(synced.ok && synced.delivered === true &&
                synced.cluster === 'orders' && synced.pep === 'pep-2' &&
                dialled.length === 1 && /^https:\/\//.test(dialled[0]) &&
                asked[0] && asked[0].full === true,
                'G4. Sync of a cluster member nudges that one PEP for a full ' +
                'pull and names its cluster',
                JSON.stringify([synced, dialled, asked]));
        t.check(/Delivered \(204\)/
                  .test(String(peps.read('pep-2').lastNotify)),
                'G5. the nudge is recorded on the row',
                peps.read('pep-2').lastNotify);
        act({ action: 'disable-pep', name: 'pep-2' });
        const stopped = await act({ action: 'sync-pep', name: 'pep-2' });
        act({ action: 'enable-pep', name: 'pep-2' });
        t.check(stopped.ok && dialled.length === 2,
                'G6. Sync dials a PEP whose change nudges are stopped',
                JSON.stringify(stopped));
        deliver = false;
        const lost = await act({ action: 'sync-pep', name: 'pep-2' });
        t.check(!lost.ok && codeOf(lost) === 'STS-XACML-0285' &&
                /ECONNREFUSED/.test(lost.why),
                'G7. a nudge not delivered is a refusal (0285) saying why',
                JSON.stringify(lost));
      } finally {
        notifier.nudge = realSend;
        notifier.notifyAllowed = realAllowed;
        notifier.urlProblem = realProblem;
      }

      // ---------------------------------------------------------------
      // I. THE VIEW.
      // ---------------------------------------------------------------
      const view = pap.clustersJson('orders');
      const v = view.clusters[0];
      t.check(view.found && v.members.length === 3 &&
              v.members.filter(function (m) {
                return m.pep === 'pep-future';
              })[0].registered === false &&
              v.proxyRoutes.length === 4 &&
              view.peps.filter(function (p) {
                return p.name === 'pep-solo';
              })[0].cluster === null,
              'I1. the cluster\'s view: its members, the one not registered, ' +
              'its routes, and every PEP\'s cluster',
              JSON.stringify(v.members));
      const pv = pap.pepsJson('pep-2');
      t.check(pv.peps[0].cluster === 'orders' && pv.peps[0].proxy &&
              pv.peps[0].proxy.routes.length === 4 &&
              pap.pepsJson('pep-solo').peps[0].cluster === undefined,
              'I2. a member\'s PEP view names its cluster and draws the ' +
              'inherited proxy; a standalone PEP carries no cluster member');

      // ---------------------------------------------------------------
      // H. LEAVE AND DELETE.
      // ---------------------------------------------------------------
      const leave = act({ action: 'remove-pep-cluster-member',
                          cluster: 'orders', pep: 'pep-2' });
      const p2 = peps.read('pep-2');
      const kept = p2.proxy ? JSON.parse(p2.proxy) : null;
      t.check(leave.ok && leave.kept && kept &&
              kept.routes[0].authorization.policy === 'pep-pep-2-health' &&
              store.read('pep-pep-2-health') &&
              store.read('pep-pep-2-health').pepRoute === 'pep-2/health' &&
              kept.publicBaseUrl === BASE2 &&
              clusters.effectiveRow(p2) === p2,
              'H1. leave with keep: the effective configuration becomes its ' +
              'own, its policies pep-pep-2-<route>, and it is standalone',
              JSON.stringify(leave));
      const leaveEmpty = act({ action: 'remove-pep-cluster-member',
                               cluster: 'orders', pep: 'pep-future',
                               keep: false });
      t.check(leaveEmpty.ok && !leaveEmpty.kept,
              'H2. leave with keep false holds nothing',
              JSON.stringify(leaveEmpty));
      const refuseDelete = act({ action: 'delete-pep-cluster',
                                 cluster: 'orders' });
      t.check(!refuseDelete.ok && codeOf(refuseDelete) === 'STS-XACML-0273',
              'H3. a cluster with members is not deleted without release ' +
              '(0273)', JSON.stringify(refuseDelete));
      const deleted = act({ action: 'delete-pep-cluster', cluster: 'orders',
                            release: 'empty' });
      t.check(deleted.ok && !clusters.read('orders') &&
              !store.read('pepc-orders-health') &&
              !peps.read('pep-1').proxy,
              'H4. delete with release empty: the cluster and its generated ' +
              'policies go, and the member holds nothing',
              JSON.stringify(deleted));
      const unknown = act({ action: 'add-pep-cluster-member',
                            cluster: 'orders', pep: 'pep-3' });
      t.check(!unknown.ok && codeOf(unknown) === 'STS-XACML-0269',
              'H5. an unknown cluster is refused (0269)',
              JSON.stringify(unknown));
      const names2 = pap.actionNames();
      t.check(pap.CLUSTER_ACTIONS.every(function (one) {
        return names2.indexOf(one) >= 0;
      }), 'H6. the unknown-action sentence names every cluster action');

      // ---------------------------------------------------------------
      // J. ONE CLIENT, A STREAM PER MEMBER (#1760 phase 3).
      //
      // Both members authenticate as pcl-web. streamsOwnedBy cannot tell
      // them apart; only X-Iya-Pep-Name can. The same username is the
      // point of the section.
      // ---------------------------------------------------------------
      const http = require('http');
      const app = require(ROOT + '/common/app');
      const streams = require(ROOT + '/ssf/ssf_streams');
      const audit = require(ROOT + '/common/audit');
      const basic = 'Basic ' +
        Buffer.from('pcl-web:anything').toString('base64');
      const pollDelivery = { method: streams.DELIVERY_POLL };
      function ssfRequest(method, target, extra, json) {
        log.debug("Entering ssfRequest().");
        const body = json === undefined ? '' : JSON.stringify(json);
        const headers = Object.assign({
          authorization: basic, accept: 'application/json'
        }, extra || {});
        if (body) {
          headers['content-type'] = 'application/json';
          headers['content-length'] = Buffer.byteLength(body);
        }
        log.debug("Leaving ssfRequest().");
        return new Promise(function (resolve) {
          const req = http.request({
            host: '127.0.0.1', port: ssfPort, method: method,
            path: '/realm/' + id + target, headers: headers
          }, function (res) {
            let text = '';
            res.on('data', function (chunk) { text += chunk; });
            res.on('end', function () {
              let parsed = null;
              try {
                parsed = text ? JSON.parse(text) : null;
              } catch (e) {
                parsed = { parseError: String((e && e.message) || e) };
              }
              resolve({ status: res.statusCode, json: parsed,
                        text: text });
            });
          });
          req.on('error', function (e) {
            resolve({ status: 0, json: null,
                      text: String((e && e.message) || e) });
          });
          req.end(body);
        });
      }
      function streamIds(answer) {
        log.debug("Entering streamIds().");
        const list = Array.isArray(answer && answer.json)
          ? answer.json : [];
        const out = list.map(function (one) { return one.stream_id; });
        log.debug("Leaving streamIds().");
        return out;
      }
      const server = http.createServer(app);
      let ssfPort = 0;
      try {
        await new Promise(function (ready) {
          server.listen(0, '127.0.0.1', ready);
        });
        ssfPort = server.address().port;
        const plain = await ssfRequest('POST', '/ssf/stream', {},
          { delivery: pollDelivery });
        const madeA = await ssfRequest('POST', '/ssf/stream',
          { 'x-iya-pep-name': 'pep-a' }, { delivery: pollDelivery });
        const madeB = await ssfRequest('POST', '/ssf/stream',
          { 'x-iya-pep-name': 'pep-b' }, { delivery: pollDelivery });
        const idPlain = plain.json && plain.json.stream_id;
        const idA = madeA.json && madeA.json.stream_id;
        const idB = madeB.json && madeB.json.stream_id;
        const recPlain = streams.getStream(idPlain);
        const recA = streams.getStream(idA);
        const recB = streams.getStream(idB);
        t.check(plain.status === 201 && madeA.status === 201 &&
                madeB.status === 201 && idPlain && idA && idB &&
                idA !== idB && idA !== idPlain &&
                recA && recA.pepMember === 'pep-a' &&
                recB && recB.pepMember === 'pep-b' &&
                recPlain && !recPlain.pepMember &&
                madeA.json.pepMember === undefined &&
                madeB.json.pepMember === undefined &&
                plain.json.pepMember === undefined,
                'J1. one Basic client, two members: each header creates ' +
                'its own stream, the wire omits pepMember, and a call ' +
                'with no header stays untagged',
                JSON.stringify({ plain: plain.status, a: madeA.status,
                                 b: madeB.status, idPlain: idPlain,
                                 idA: idA, idB: idB }));
        if (recA) {
          recA.lastActivityAt = 1;
        }
        if (recB) {
          recB.lastActivityAt = 1;
        }
        const listA = await ssfRequest('GET', '/ssf/stream',
          { 'x-iya-pep-name': 'pep-a' });
        const seenA = streamIds(listA);
        const afterA = streams.getStream(idA);
        const stillB = streams.getStream(idB);
        t.check(listA.status === 200 && seenA.length === 1 &&
                seenA[0] === idA && afterA &&
                afterA.lastActivityAt !== 1 && stillB &&
                stillB.lastActivityAt === 1,
                'J2. listing pep-a returns only pep-a and does not ' +
                'refresh pep-b',
                JSON.stringify({ status: listA.status, ids: seenA,
                  a: afterA && afterA.lastActivityAt,
                  b: stillB && stillB.lastActivityAt }));
        const listB = await ssfRequest('GET', '/ssf/stream',
          { 'x-iya-pep-name': 'pep-b' });
        t.check(listB.status === 200 &&
                streamIds(listB).join(',') === idB,
                'J3. listing pep-b returns only pep-b',
                JSON.stringify(streamIds(listB)));
        const listAll = await ssfRequest('GET', '/ssf/stream', {});
        t.check(listAll.status === 200 &&
                streamIds(listAll).join(',') ===
                  [idPlain, idA, idB].join(','),
                'J4. no header lists the untagged stream, then pep-a, ' +
                'then pep-b, oldest first',
                JSON.stringify(streamIds(listAll)));
        const listC = await ssfRequest('GET', '/ssf/stream',
          { 'x-iya-pep-name': 'pep-c' });
        t.check(listC.status === 200 && Array.isArray(listC.json) &&
                listC.json.length === 0,
                'J5. a name nobody has created a stream for is an empty ' +
                'list', JSON.stringify(listC.json));
        const ignored = await ssfRequest('POST', '/ssf/stream',
          { 'x-iya-pep-name': 'pep-a' },
          { delivery: pollDelivery, pepMember: 'pep-b' });
        const ignoredId = ignored.json && ignored.json.stream_id;
        const ignoredRec = streams.getStream(ignoredId);
        t.check(ignored.status === 201 && ignored.json.pepMember ===
                undefined && ignoredRec &&
                ignoredRec.pepMember === 'pep-a',
                'J6. a pepMember field in the body is ignored; the ' +
                'header is what is stored',
                JSON.stringify({ status: ignored.status,
                  stored: ignoredRec && ignoredRec.pepMember }));
        const beforeBad = streams.streamsOwnedBy('pcl-web').length;
        const bad = await ssfRequest('POST', '/ssf/stream',
          { 'x-iya-pep-name': 'bad name' },
          { delivery: pollDelivery });
        const afterBad = streams.streamsOwnedBy('pcl-web').length;
        const coded = audit.list().filter(function (event) {
          return event.errorCode === 'STS-SSF-0163';
        });
        t.check(bad.status === 400 && bad.json &&
                bad.json.err === 'invalid_request' &&
                afterBad === beforeBad && coded.length >= 1,
                'J7. a header that is not a PEP name is 400, creates ' +
                'nothing, and is recorded as STS-SSF-0163',
                bad.status + ' ' + bad.text.slice(0, 240) + ' owned ' +
                beforeBad + '->' + afterBad + ' audit ' + coded.length);
        const badGet = await ssfRequest('GET', '/ssf/stream',
          { 'x-iya-pep-name': 'bad name' });
        t.check(badGet.status === 400 && badGet.json &&
                badGet.json.err === 'invalid_request' &&
                !Array.isArray(badGet.json),
                'J8. the same header on a list is 400, and the answer ' +
                'is the refusal rather than the untagged list',
                badGet.status + ' ' + badGet.text.slice(0, 200));
        const liveA = streams.getStream(idA);
        const liveB = streams.getStream(idB);
        const queuedA = liveA ? streams.enqueue(liveA,
          { jti: 'jti-pep-a', token: 'set-pep-a' }) : { ok: false };
        const queuedB = liveB ? streams.enqueue(liveB,
          { jti: 'jti-pep-b', token: 'set-pep-b' }) : { ok: false };
        const polledA = await ssfRequest('POST', '/ssf/poll', {},
          { stream_id: idA, ack: [] });
        const polledB = await ssfRequest('POST', '/ssf/poll', {},
          { stream_id: idB, ack: [] });
        const setsA = (polledA.json && polledA.json.sets) || {};
        const setsB = (polledB.json && polledB.json.sets) || {};
        t.check(queuedA.ok && queuedB.ok && polledA.status === 200 &&
                polledB.status === 200 && setsA['jti-pep-a'] ===
                  'set-pep-a' && setsA['jti-pep-b'] === undefined &&
                setsB['jti-pep-b'] === 'set-pep-b' &&
                setsB['jti-pep-a'] === undefined,
                'J9. polling one member\'s stream collects that queue ' +
                'and leaves the other member\'s',
                JSON.stringify({ a: polledA.status, b: polledB.status,
                  setsA: Object.keys(setsA),
                  setsB: Object.keys(setsB) }));
      } finally {
        await new Promise(function (done) { server.close(done); });
      }
      log.debug("Leaving realmBody().");
    });
  } finally {
    surface.nudgePeps = realNudge;
    realms.remove(id);
  }
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== remote PEP clusters (#1760) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'xacml_pep_clusters',
  describe: 'remote PEP clusters (#1760): the effective row, the shared ' +
            'route policies, join and leave, the per-member checks, a ' +
            'signal stream per member, every refusal and a standalone PEP ' +
            'unchanged',
  run: run
};
