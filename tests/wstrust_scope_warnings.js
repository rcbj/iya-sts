// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_scope_warnings.js
//
// ===========================================================================
// A wstrustJwtScope VALUE THE SCOPE POLICY WILL DROP IS SAID AT
// CONFIGURATION TIME (#488). The write is still accepted (#485); the reply,
// the application's view and the console's cell carry the same warnings.
//
//   W1. an undeclared scope and a protected one, added through
//       `applications/add`: both written, the reply carrying `warnings` for
//       both — the undeclared one saying PRODUCT would drop it in
//       development and that it IS dropped in product, the protected one
//       dropped in every mode — and its message saying WARNING, with how to
//       resolve it;
//   W2. `update-fields` says the same;
//   W3. the application's view (`applicationScopeWarnings()`, what the GET
//       view and the page data carry) is the reply's list;
//   W4. declared on `oauthAllowedScope`, the undeclared one's warning goes;
//   W5. with the field empty there is none, and the reply has no `warnings`;
//   W6. the console's field grid draws each warning beside the field.
//
// IN PROCESS, in a throwaway realm, in both modes.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
// The directory is the registry's store. Loaded here, not left to whichever
// file ran before this one in the same process: the report runner gives every
// file a process of its own, and without it every create was refused (no
// ou=applications container).
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const WebKit = require('../admin-ui/web_kit');
// Arms the issuance gate the scope question goes to.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'wstrust_scope_warnings',
  level: process.env.LOG_LEVEL || 'info' });

const APP = 'sw-app';

function inMode(m, fn) {
  log.debug("Entering inMode(). " + m);
  config.setOverride('global.mode', m);
  try {
    log.debug("Leaving inMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

function act(m, body) {
  log.debug("Entering act().");
  log.debug("Leaving act().");
  return inMode(m, function () {
    return adminActions.applicationsAction(Object.assign({ application: APP },
                                                         body));
  });
}

function valuesOf(reply) {
  log.debug("Entering valuesOf().");
  log.debug("Leaving valuesOf().");
  return (reply.warnings || []).map(function (one) {
    return one.value + ':' + one.reason;
  }).sort();
}

function cases(t) {
  log.debug("Entering cases().");
  const made = applications.createApplication({ identifier: APP,
    protocols: ['wstrust', 'oauth2'],
    fields: { oauthAllowedScope: ['api.read'],
              wstrustJwtScope: ['api.read'] } });
  t.check(made && made.ok, 'precondition: the application exists',
          JSON.stringify(made));
  ['development', 'product'].forEach(function (m) {
    const product = m === 'product';
    // W1.
    act(m, { action: 'remove', attribute: 'wstrustJwtScope',
             value: 'api.undeclared' });
    act(m, { action: 'remove', attribute: 'wstrustJwtScope',
             value: 'admin:write' });
    act(m, { action: 'add', attribute: 'wstrustJwtScope',
             value: 'api.undeclared' });
    const added = act(m, { action: 'add', attribute: 'wstrustJwtScope',
                           value: 'admin:write' });
    const undeclared = (added.warnings || []).filter(function (one) {
      return one.value === 'api.undeclared';
    })[0] || {};
    const prot = (added.warnings || []).filter(function (one) {
      return one.value === 'admin:write';
    })[0] || {};
    t.check(added.ok === true &&
            JSON.stringify(valuesOf(added)) ===
              JSON.stringify(['admin:write:protected',
                              'api.undeclared:undeclared']) &&
            undeclared.dropped === product &&
            (product ? /is dropped from the JWT at issuance/
                     : /PRODUCT mode would drop it/).test(undeclared.text) &&
            /declare it on this application's oauthAllowedScope/i
              .test(undeclared.text) && prot.dropped === true &&
            /in every mode/.test(prot.text) &&
            /WARNING: /.test(String(added.message)),
            'W1 (' + m + '). an undeclared and a protected scope are written, ' +
            'and the reply warns: ' + (product ? 'dropped' : 'product would ' +
            'drop it') + ', and protected in every mode',
            JSON.stringify(added).slice(0, 900));
    // W2.
    const fields = act(m, { action: 'update-fields',
                            'field.wstrustJwtScope.0': 'api.read',
                            'field.wstrustJwtScope.1': 'api.undeclared',
                            'field.wstrustJwtScope.2': 'admin:write',
                            present: 'wstrustJwtScope' });
    t.check(fields.ok === true &&
            JSON.stringify(valuesOf(fields)) === JSON.stringify(valuesOf(added)),
            'W2 (' + m + '). update-fields carries the same warnings',
            JSON.stringify(fields).slice(0, 600));
    // W3.
    const view = inMode(m, function () {
      return adminViews.applicationScopeWarnings(APP);
    });
    t.check(JSON.stringify(view) === JSON.stringify(added.warnings),
            'W3 (' + m + '). the application\'s view carries the reply\'s list',
            JSON.stringify(view).slice(0, 400));
    // W4.
    act(m, { action: 'add', attribute: 'oauthAllowedScope',
             value: 'api.undeclared' });
    const declared = inMode(m, function () {
      return adminViews.applicationScopeWarnings(APP);
    });
    t.check(JSON.stringify(declared.map(function (one) {
      return one.value;
    })) === '["admin:write"]',
            'W4 (' + m + '). declared on oauthAllowedScope, the warning goes ' +
            '(the protected one stays until it is declared too)',
            JSON.stringify(declared).slice(0, 300));
    act(m, { action: 'remove', attribute: 'oauthAllowedScope',
             value: 'api.undeclared' });
  });
  // W5.
  ['api.read', 'api.undeclared', 'admin:write'].forEach(function (value) {
    act('product', { action: 'remove', attribute: 'wstrustJwtScope',
                     value: value });
  });
  const cleared = act('product', { action: 'set', attribute: 'description',
                                   value: 'scope warnings' });
  t.check(cleared.ok === true && cleared.warnings === undefined &&
          adminViews.applicationScopeWarnings(APP).length === 0,
          'W5. with wstrustJwtScope empty there is no warning',
          JSON.stringify(cleared).slice(0, 300));
  // W6.
  const row = applications.applicationFields().filter(function (one) {
    return one.attribute === 'wstrustJwtScope';
  })[0];
  const html = WebKit.fieldGridCell(row, { wstrustJwtScope: ['x'] },
    { redraw: '/admin/applications/edit', fieldWarnings: {
      wstrustJwtScope: [{ text: 'wstrustJwtScope "x" is dropped.' }] } });
  t.check(!!row && /<div class="warn fg-warn">wstrustJwtScope &quot;x&quot; is dropped\.<\/div>/
            .test(html),
          'W6. the console\'s cell draws the warning beside the field',
          html.slice(-300));
  log.debug("Leaving cases().");
}

// EVERYTHING IN A THROWAWAY REALM, removed afterwards.
function run(t) {
  log.debug("Entering run().");
  const id = 'sw-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return undefined;
  }
  try {
    realms.run(made.realm, function () {
      cases(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'wstrust_scope_warnings',
  describe: 'a wstrustJwtScope value the scope policy will drop is said at ' +
            'configuration time, in the write replies, the application\'s ' +
            'view and the console\'s cell (#488)',
  run: run
};
