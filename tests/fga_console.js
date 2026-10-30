// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'fga_console',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: fga_console.js
//
// ===========================================================================
// THE CONSOLE AND /admin-api FOR APPLICATION-SCOPED FINE-GRAINED
// AUTHORIZATION (#564, phase 5).
//
// The application page's Fine-grained authorization tab, its Access types
// tab's XACML mapping sub-tabs and XACML → Policies' applications' section
// all draw from an `/admin-api` read and act through one `/admin-api`
// operation each (rule 7). What this file holds, each a lettered section:
//
//   V. THE VIEW: `page.fga` on the application's read — the switch, the
//      policy it owns with its editor link, each declared type's coverage
//      and the mapping form's closed sets.
//   M. THE MAPPING ACTS: a row refused at its FIELD (a reserved identifier,
//      a bad data type, a common data field as the path), a row added and
//      then replaced rather than doubled, notForPolicy set, a row that is
//      not there refused, and a remove that would uncover a member of an
//      enforcing application refused with STS-FGA-0019.
//   F. THE SWITCH AND THE POLICY: enable refused while a type is uncovered
//      (STS-FGA-0018, naming the path), then allowed; reset refused
//      unconfirmed (STS-FGA-0020), then done, keeping a disabled policy
//      disabled; create answering the policy it has; disable.
//   X. XACML → POLICIES: the applications' policies grouped by owner; the
//      live one refused at delete (STS-FGA-0022); the orphan a deletion
//      leaves removable.
//   R. THE OPERATIONS: the seven actions on POST
//      /admin-api/applications/{action}, mirroring the application page.
//   D. THE PAGES: the tab, the sub-tabs, a refusal drawn under its box,
//      the sub-tab being read marked by the runtime (P6), and the XACML
//      section, from their views.
//
// In process, in a THROWAWAY REALM, as `fga_policies.js` is: a new realm's
// `ou=policies` is empty, so every count is exact.
// ===========================================================================

delete process.env.CONFIG_FILE;

/**
 * A request for an application's read.
 *
 * @returns the request
 */
function request() {
  log.debug('Entering request().');
  log.debug('Leaving request().');
  return { query: {}, headers: { host: 'localhost:8081' }, protocol: 'https',
           get: function () {
             return '';
           } };
}

function run(t) {
  log.debug("Entering run().");
  require('../common/config');
  require('../common/app');
  require('../ldap/ldap_server');
  // A renderer given no translator draws node's default, which
  // common/i18n.ts installs (#539) — English.
  require('../common/i18n');
  const realms = require('../common/realms');
  const errorCodes = require('../common/error_codes');
  const applications = require('../common/applications');
  const store = require('../xacml/xacml_store');
  const pap = require('../xacml/xacml_admin');
  // Loading it builds its default instance and fills the lifecycle slot.
  require('../xacml/fga_policies');
  const adminActions = require('../admin-core/admin_actions');
  const adminViews = require('../admin-core/admin_views');

  const id = 'fgac-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  const k = {
    applications: applications, store: store, pap: pap,
    errorCodes: errorCodes, adminActions: adminActions,
    APP: 'fgac-rs',
    inRealm: function (fn) {
      log.debug("Entering inRealm().");
      log.debug("Leaving inRealm().");
      return realms.run(made.realm, fn);
    },
    act: function (body) {
      log.debug("Entering act().");
      log.debug("Leaving act().");
      return realms.run(made.realm, function () {
        return adminActions.applicationsAction(Object.assign(
          { application: 'fgac-rs', actor: 'test' }, body));
      });
    },
    read: function () {
      log.debug("Entering read().");
      log.debug("Leaving read().");
      return realms.run(made.realm, function () {
        return adminViews.applicationDetailJson(request(), 'fgac-rs').json;
      });
    }
  };
  try {
    sectionV(t, k);
    sectionM(t, k);
    sectionF(t, k);
    sectionR(t);
    sectionD(t, k);
    sectionX(t, k);
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

// V. The view.
function sectionV(t, k) {
  log.debug("Entering sectionV().");
  t.log.info('=== V. page.fga on the application\'s read ===');
  const created = k.inRealm(function () {
    return k.applications.createApplication({
      identifier: k.APP, name: 'FGA console resource',
      protocols: ['oauth2'] });
  });
  t.check(created.ok, 'an application is created',
          (created.errors || []).join(' '));
  const declared = k.act({
    action: 'set-access-type', type: 'payment',
    schema: JSON.stringify({ type: 'object', additionalProperties: false,
                             properties: { amount: { type: 'number' },
                                           memo: { type: 'string' } } }) });
  t.check(declared.ok, 'a closed type with two members of its own',
          (declared.errors || []).join(' '));
  const fga = (k.read().page || {}).fga || {};
  const type = (fga.types || [])[0] || {};
  t.check(fga.known === true && fga.enforced === false && fga.usable &&
          fga.policy && fga.policy.own === true &&
          /^\/admin\/xacml\/editor\?policy=fga-/.test(fga.policy.editor) &&
          fga.policy.policyId === 'urn:sts:xacml:fga:fgac-rs',
          'V1. the read carries the switch (off), and the policy the ' +
          'application owns with its PolicyId and its editor link',
          JSON.stringify(fga.policy));
  t.check(type.type === 'payment' && type.covered === false &&
          type.uncovered.indexOf('amount') >= 0 &&
          type.uncovered.indexOf('memo') >= 0,
          'V2. each declared type with its coverage: both members uncovered',
          JSON.stringify(type));
  t.check(fga.choices && fga.choices.categories.indexOf('resource') >= 0 &&
          fga.choices.dataTypes.indexOf('double') >= 0 &&
          fga.choices.multiplicities.join() === 'single,bag',
          'V3. and the mapping form\'s closed sets, read off the grammar',
          JSON.stringify(fga.choices));
  log.debug("Leaving sectionV().");
}

// M. The mapping acts.
function sectionM(t, k) {
  log.debug("Entering sectionM().");
  t.log.info('=== M. a type\'s mapping, a row at a time ===');
  const refusedAt = function (body, field, what) {
    log.debug("Entering refusedAt().");
    const r = k.act(Object.assign({ action: 'set-access-type-row',
                                    type: 'payment', path: 'amount',
                                    attributeId: 'urn:example:amount' },
                                  body));
    t.check(!r.ok && k.errorCodes.codeOf(r) === 'STS-FGA-0023' &&
            r.field === field,
            what + ' (STS-FGA-0023, field ' + field + ')',
            JSON.stringify(r));
    log.debug("Leaving refusedAt().");
  };
  refusedAt({ attributeId: 'urn:sts:xacml:role' }, 'attributeId',
            'M1. a row onto a reserved identifier is refused at its field');
  refusedAt({ dataType: 'frob' }, 'dataType',
            'M2. a data type outside the set is refused at its field');
  refusedAt({ path: 'actions' }, 'path',
            'M3. a common data field as the path is refused at its field');
  let r = k.act({ action: 'set-access-type-row', type: 'payment',
                  path: 'amount', attributeId: 'urn:example:amount' });
  const again = k.act({ action: 'set-access-type-row', type: 'payment',
                        path: 'amount', attributeId: 'urn:example:amt',
                        dataType: 'double' });
  const rows = again.ok ? again.definition.xacml : [];
  t.check(r.ok && /^Added/.test(r.message) && again.ok &&
          /^Replaced/.test(again.message) && rows.length === 1 &&
          rows[0].attributeId === 'urn:example:amt',
          'M4. a row is added, and the same path replaced rather than ' +
          'doubled', JSON.stringify(rows));
  r = k.act({ action: 'set-not-for-policy', type: 'payment',
              notForPolicy: 'memo' });
  const type = (k.read().page.fga.types || [])[0] || {};
  t.check(r.ok && type.covered === true &&
          type.notForPolicy.join() === 'memo' && type.rows === 1,
          'M5. notForPolicy set, and the type is covered',
          JSON.stringify(type));
  r = k.act({ action: 'remove-access-type-row', type: 'payment',
              path: 'nothing' });
  t.check(!r.ok && k.errorCodes.codeOf(r) === 'STS-FGA-0023',
          'M6. a row that is not there is refused (STS-FGA-0023)',
          JSON.stringify(r));
  r = k.act({ action: 'set-access-type-row', type: 'nonesuch',
              path: 'x', attributeId: 'urn:example:x' });
  t.check(!r.ok && k.errorCodes.codeOf(r) === 'STS-REG-0295',
          'M7. a type it does not declare is refused (STS-REG-0295)',
          JSON.stringify(r));
  log.debug("Leaving sectionM().");
}

// F. The switch and the policy.
function sectionF(t, k) {
  log.debug("Entering sectionF().");
  t.log.info('=== F. the switch and the policy ===');
  // Uncover it first: memo off the list.
  k.act({ action: 'set-not-for-policy', type: 'payment', notForPolicy: '' });
  let r = k.act({ action: 'fga-enable' });
  t.check(!r.ok && k.errorCodes.codeOf(r) === 'STS-FGA-0018' &&
          r.failure === 'uncovered-type' && /memo/.test(r.errors[0]),
          'F1. enable is refused while a type is uncovered, naming the ' +
          'path (STS-FGA-0018)', JSON.stringify(r));
  k.act({ action: 'set-not-for-policy', type: 'payment',
          notForPolicy: ['memo'] });
  r = k.act({ action: 'fga-enable' });
  t.check(r.ok && r.enforced === true && k.read().page.fga.enforced,
          'F2. covered, enable switches it on', JSON.stringify(r));
  r = k.act({ action: 'remove-access-type-row', type: 'payment',
              path: 'amount' });
  t.check(!r.ok && k.errorCodes.codeOf(r) === 'STS-FGA-0019' &&
          r.field === 'path' &&
          ((k.read().page.fga.types || [])[0] || {}).rows === 1,
          'F3. on an enforcing application, a remove that would uncover a ' +
          'member is refused (STS-FGA-0019) and the row stays',
          JSON.stringify(r));
  r = k.act({ action: 'fga-reset-policy' });
  t.check(!r.ok && k.errorCodes.codeOf(r) === 'STS-FGA-0020',
          'F4. reset is refused unconfirmed (STS-FGA-0020)',
          JSON.stringify(r));
  const name = k.read().page.fga.policy.name;
  k.inRealm(function () {
    return k.pap.policyAction({ action: 'disable', name: name });
  });
  r = k.act({ action: 'fga-reset-policy', confirm: 'on' });
  const row = k.inRealm(function () {
    return k.store.read(name);
  }) || {};
  t.check(r.ok && r.policy === name && row.enabled === false &&
          row.application === k.APP && /permit-every-detail/.test(
            String(row.document)),
          'F5. confirmed, the policy is rewritten from fga-default under ' +
          'the same name, and stays disabled', JSON.stringify(r));
  k.inRealm(function () {
    return k.pap.policyAction({ action: 'enable', name: name });
  });
  r = k.act({ action: 'fga-create-policy' });
  t.check(r.ok && r.created === false && r.policy === name,
          'F6. create answers the policy it already has', JSON.stringify(r));
  r = k.act({ action: 'fga-disable' });
  t.check(r.ok && r.enforced === false && !k.read().page.fga.enforced,
          'F7. disable switches it off', JSON.stringify(r));
  log.debug("Leaving sectionF().");
}

// R. The operations.
function sectionR(t) {
  log.debug("Entering sectionR().");
  t.log.info('=== R. the operations ===');
  const adminApi = require('../mgmt-api/admin_api');
  const route = adminApi.ROUTES.filter(function (one) {
    return one.method === 'POST' &&
           one.route === '/admin-api/applications/:action';
  })[0] || { actions: [] };
  const named = route.actions.map(function (one) {
    return one.action;
  });
  const wanted = ['set-access-type-row', 'remove-access-type-row',
                  'set-not-for-policy', 'fga-enable', 'fga-disable',
                  'fga-create-policy', 'fga-reset-policy'];
  t.check(wanted.every(function (one) {
    return named.indexOf(one) >= 0;
  }) && /POST \/admin\/applications\b/.test(route.mirrors) &&
          (route.kind || 'management') === 'management',
          'R1. the seven acts are management operations on POST ' +
          '/admin-api/applications/{action}, mirroring the application page',
          wanted.filter(function (one) {
            return named.indexOf(one) < 0;
          }).join(', ') || 'all there');
  log.debug("Leaving sectionR().");
}

// D. The pages.
function sectionD(t, k) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. the pages, drawn from their views ===');
  const kit = require('../admin-ui/web_kit');
  const page = require('../admin-ui/web_applications');
  const answers = require('../admin-ui/web_answers');
  const ctx = kit.context({}, true);
  const json = k.read();
  const tab = page.applicationFgaSection(ctx, json, '');
  t.check(tab.indexOf('name="action" value="fga-enable"') >= 0 &&
          tab.indexOf('name="action" value="fga-reset-policy"') >= 0 &&
          tab.indexOf('name="confirm" value="true"') >= 0 &&
          tab.indexOf('/admin/xacml/editor?policy=fga-') >= 0 &&
          tab.indexOf('action="/admin/applications#fga"') >= 0,
          'D1. the tab draws the switch, the reset behind its checkbox and ' +
          'the editor link, posting to /admin/applications#fga',
          tab.slice(0, 300));
  const mapping = page.applicationAccessTypeMappingSection(ctx, json, '');
  t.check(mapping.indexOf('id="atmap-0"') >= 0 &&
          mapping.indexOf('value="set-access-type-row"') >= 0 &&
          mapping.indexOf('value="set-not-for-policy"') >= 0 &&
          mapping.indexOf('urn:example:amt') >= 0,
          'D2. the Access types tab draws a sub-tab per type with its rows ' +
          'and forms', mapping.slice(0, 300));
  markedSubTab(t, page, ctx, json);
  const refused = k.act({ action: 'set-access-type-row', type: 'payment',
                          path: 'amount',
                          attributeId: 'urn:sts:xacml:role' });
  const fields = { action: 'set-access-type-row', type: 'payment',
                   path: 'amount', attributeId: 'urn:sts:xacml:role' };
  const again = answers.redraw('/admin/applications', 'set-access-type-row',
                               fields, refused, json);
  const drawn = again ? page.applicationAccessTypeMappingSection(ctx,
    again.json, '') : '';
  const box = drawn.indexOf('id="atmap-0-attributeId"');
  const warn = drawn.indexOf('<div class="warn">', box);
  const next = drawn.indexOf('id="atmap-0-category"', box);
  t.check(!!again && box > 0 && warn > box && warn < next &&
          drawn.indexOf('value="urn:sts:xacml:role"') >= 0,
          'D3. a refused row is drawn again as typed, the refusal under ' +
          'the attribute id box', drawn.slice(box, box + 400));
  log.debug("Leaving sectionD().");
}

// D4. THE SUB-TAB BEING READ IS MARKED (#564 P6). The stylesheet names the
// tab ids it knows, since a selector cannot compare a link's href with the
// targeted id; `atmap-<n>` is one id per declared type and cannot be named
// in advance, so what marks it is the runtime's class-based `tab-current`
// (`markOpenTabs()`, #971), as a custom listener's tab is marked. This holds
// the markup to what that walk needs — the bar a `.tabbar` child of
// `.subtabs`, each link naming a panel that exists — and runs the walk over
// it with the SECOND type's panel targeted, so the mark cannot be the
// default one on the first.
function markedSubTab(t, page, ctx, json) {
  log.debug("Entering markedSubTab().");
  const two = JSON.parse(JSON.stringify(json));
  const first = (two.page.accessTypes || [])[0];
  two.page.accessTypes.push(Object.assign({}, first, { type: 'second' }));
  const html = page.applicationAccessTypeMappingSection(ctx, two, '');
  const bar = (html.match(/<div class="subtabs"><nav class="tabbar subbar"[^>]*>([\s\S]*?)<\/nav>/) || [])[1] || '';
  const ids = [];
  bar.replace(/href="#([^"]+)"/g, function (all, id) {
    ids.push(id);
    return all;
  });
  const cls = function () {
    const set = {};
    return { contains: function (c) { return !!set[c]; },
             add: function (c) { set[c] = true; },
             remove: function (c) { delete set[c]; } };
  };
  const node = function (tag, attrs, children) {
    return {
      tagName: tag, classList: cls(), attrs: attrs || {},
      children: children || [],
      getAttribute: function (name) {
        return this.attrs[name] || null;
      },
      setAttribute: function (name, value) {
        this.attrs[name] = value;
      },
      removeAttribute: function (name) {
        delete this.attrs[name];
      },
      contains: function (other) {
        return other === this;
      }
    };
  };
  const panels = {};
  const links = ids.map(function (id, n) {
    if (html.indexOf('<div class="subpanel' + (n === 0 ? ' first' : '') +
                     '" id="' + id + '">') >= 0) {
      panels[id] = node('DIV', { id: id }, []);
    }
    const link = node('A', { href: '#' + id }, []);
    if (n === 0) {
      link.classList.add('first');
    }
    return link;
  });
  const nav = node('NAV', {}, links);
  nav.classList.add('tabbar');
  const root = node('DIV', {}, [nav].concat(Object.keys(panels).map(
    function (id) {
      return panels[id];
    })));
  const Runtime = require('../admin-ui/web_runtime');
  const rt = Object.create(Runtime.prototype);
  rt.env = { document: {
    querySelectorAll: function () { return [root]; },
    querySelector: function () { return panels['atmap-1'] || null; },
    getElementById: function (id) { return panels[id] || null; }
  } };
  rt.markOpenTabs();
  t.check(ids.join() === 'atmap-0,atmap-1' &&
          Object.keys(panels).length === 2 &&
          links[1].classList.contains('tab-current') &&
          links[1].attrs['aria-current'] === 'true' &&
          !links[0].classList.contains('tab-current'),
          'D4. the mapping sub-tab being read is marked tab-current by the ' +
          'runtime, and the first is not', JSON.stringify(ids));
  log.debug("Leaving markedSubTab().");
}

// X. XACML → Policies.
function sectionX(t, k) {
  log.debug("Entering sectionX().");
  t.log.info('=== X. the applications\' policies on XACML → Policies ===');
  const XacmlPage = require('../xacml/web_xacml');
  const kit = require('../admin-ui/web_kit');
  const name = k.read().page.fga.policy.name;
  let view = k.inRealm(function () {
    return k.pap.policiesJson();
  });
  const group = (view.applicationPolicies || []).filter(function (one) {
    return one.application === k.APP;
  })[0] || { policies: [] };
  t.check(group.known === true && group.policies.length === 1 &&
          group.policies[0].name === name &&
          group.policies[0].referenced === true,
          'X1. the policy is listed under its application, referenced',
          JSON.stringify(view.applicationPolicies));
  let r = k.inRealm(function () {
    return k.pap.policyAction({ action: 'delete', name: name });
  });
  t.check(!r.ok && k.errorCodes.codeOf(r) === 'STS-FGA-0022' &&
          !!k.inRealm(function () {
            return k.store.read(name);
          }),
          'X2. the policy an application names is not deleted ' +
          '(STS-FGA-0022)', JSON.stringify(r));
  const html = XacmlPage.applicationPoliciesSection(view, true,
                                                    kit.context({}, true).t);
  t.check(html.indexOf('id="fga-policies"') >= 0 &&
          html.indexOf('#tab-fga') >= 0 &&
          html.indexOf('value="set-root"') < 0 &&
          html.indexOf('value="delete"') < 0,
          'X3. the section links the application\'s tab, and offers ' +
          'neither Make root nor Remove for a live policy', html.slice(0, 300));
  k.inRealm(function () {
    return k.applications.deleteApplication(k.APP, { actor: 'test' });
  });
  view = k.inRealm(function () {
    return k.pap.policiesJson();
  });
  const orphan = ((view.applicationPolicies || []).filter(function (one) {
    return one.application === k.APP;
  })[0] || { policies: [{}] }).policies[0];
  const orphanHtml = XacmlPage.applicationPoliciesSection(view, true,
    kit.context({}, true).t);
  t.check(orphan.referenced === false && !!orphan.orphanedAt &&
          orphanHtml.indexOf('value="delete"') >= 0,
          'X4. deleting the application leaves an orphan, offered Remove',
          JSON.stringify(orphan));
  r = k.inRealm(function () {
    return k.pap.policyAction({ action: 'delete', name: name });
  });
  t.check(r.ok && !k.inRealm(function () {
    return k.store.read(name);
  }), 'X5. and an administrator removes it', JSON.stringify(r));
  log.debug("Leaving sectionX().");
}

module.exports = {
  name: 'fga console',
  describe: 'the console and /admin-api for an application\'s fine-grained ' +
            'authorization: the tab, the mapping sub-tabs, the switch, the ' +
            'reset, and the applications\' policies on XACML (#564 P5)',
  run: run
};
