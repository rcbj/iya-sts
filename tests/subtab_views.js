// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/subtab_views.js
//
// ---------------------------------------------------------------------------
// THE SIMPLE AND ADVANCED VIEWS OF A CONFIGURATION SUB-TAB (#500).
//
// rcbj: every sub-tab of an application's Configuration tab and of a
// person's Attributes tab has a simplified view (the fields usually filled
// in) and an advanced one (every field), except a sub-tab of fewer than six
// fields, which has none. The Every protocol and OAuth 2.0 / OpenID Connect
// sub-tabs' simple fields are what rcbj's two working applications hold,
// with `appMfaMechanism` added on Every protocol (rcbj). What is held:
//
//   1. those two sub-tabs' simple fields are that set — no more, no fewer —
//      and every name in `SIMPLE_FIELD_ATTRIBUTES` is a field the grid has;
//   2. `WebKit.hasViews()` draws a switch for six fields or more with some of
//      each kind, and for nothing else;
//   3. the grid classes a non-simple cell `fg-adv` only when the form has
//      views, so a sub-tab without them hides nothing;
//   4. the switch is two `view` radios, ticked as asked, and says how many
//      hidden fields hold a value;
//   5. a person's simple fields are one list with the create form's: the
//      names and contact details are in it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const personEditor = require('../ldap/person_editor');
const WebKit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({
  name: 'subtab_views',
  level: process.env.LOG_LEVEL || 'info' });

// What rcbj0002 (a web application that delegates to an API) and rcbj0003
// (that API) hold on the two sub-tabs, read from the 8081 instance on
// 2026-10-07. `appCorsOrigin` and `appRequiredRole` were held as well and are
// drawn on tabs of their own.
// `appMfaMechanism` is not held by either and was asked for beside them.
const EVERY = ['description', 'appHomePageUrl', 'appAuthnMechanism',
               'appMfaMechanism',
               'appAllowedToDelegateTo', 'appAllowedToActOnBehalfOf',
               'appDelegationSubjectGroup', 'appDelegationSemantics'];
const OAUTH = ['oauthClientId', 'oauthConfidential',
               'oauthTokenEndpointAuthMethod', 'oauthRedirectUri',
               'oauthPostLogoutRedirectUri', 'oauthGrantType',
               'oauthResponseType', 'oauthAllowedScope', 'oauthAudience',
               'oauthPermissionBaseUri', 'oauthPermission',
               'oauthDelegatedPermission', 'oauthGlobalConsent'];

/**
 * The simple fields of one group, sorted.
 *
 * @param rows - `applications.applicationFields()`
 * @param group - the group's id
 * @returns the attribute names
 */
function simpleOf(rows, group) {
  log.debug("Entering simpleOf().");
  const out = rows.filter(function (row) {
    return row.group === group && row.simple;
  }).map(function (row) {
    return row.attribute;
  }).sort();
  log.debug("Leaving simpleOf().");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const rows = applications.applicationFields();
  t.check(JSON.stringify(simpleOf(rows, 'every')) ===
          JSON.stringify(EVERY.slice().sort()),
          '1. Every protocol\'s simple fields are what the two applications ' +
          'hold', JSON.stringify(simpleOf(rows, 'every')));
  t.check(JSON.stringify(simpleOf(rows, 'oauth')) ===
          JSON.stringify(OAUTH.slice().sort()),
          '1. OAuth 2.0 / OpenID Connect\'s simple fields are what the two ' +
          'applications hold', JSON.stringify(simpleOf(rows, 'oauth')));
  const names = rows.map(function (row) {
    return row.attribute;
  });
  const unknown = applications.SIMPLE_FIELD_ATTRIBUTES.filter(function (one) {
    return names.indexOf(one) < 0;
  });
  t.check(unknown.length === 0,
          '1. every simple attribute is a field the grid draws',
          JSON.stringify(unknown));

  const mk = function (n, simple) {
    log.debug("Entering mk().");
    const out = [];
    for (let i = 0; i < n; i++) {
      out.push({ simple: i < simple });
    }
    log.debug("Leaving mk().");
    return out;
  };
  t.check(WebKit.hasViews(mk(6, 2)) && !WebKit.hasViews(mk(5, 2)) &&
          !WebKit.hasViews(mk(8, 0)) && !WebKit.hasViews(mk(8, 8)),
          '2. a switch for six fields or more with some of each kind, only');

  const cell = function (simple, views) {
    log.debug("Entering cell().");
    log.debug("Leaving cell().");
    return WebKit.fieldGridCell({ attribute: 'x', type: 'string',
                                  families: [], everyFamily: true,
                                  simple: simple }, {}, { views: views });
  };
  t.check(/class="fg-cell[^"]* fg-adv"/.test(cell(false, true)) &&
          !/fg-adv/.test(cell(true, true)) &&
          !/fg-adv/.test(cell(false, false)),
          '3. a non-simple cell is fg-adv only on a form with views');

  const simple = WebKit.viewSwitch('OAuth', false, 3, 1);
  const advanced = WebKit.viewSwitch('OAuth', true, 1, 0);
  t.check(/name="view" value="simple" checked/.test(simple) &&
          /name="view" value="advanced" checked/.test(advanced) &&
          /3 more fields in the advanced view, 1 of them holding a value/
            .test(simple) &&
          /1 more field in the advanced view\./.test(advanced),
          '4. the switch is two view radios, ticked as asked, counting ' +
          'what is hidden');

  const people = personEditor.editableAttributes();
  const want = ['cn', 'sn', 'givenName', 'displayName', 'telephoneNumber'];
  const missing = want.filter(function (name) {
    return !people.some(function (row) {
      return row.name.toLowerCase() === name.toLowerCase() && row.simple;
    });
  });
  t.check(missing.length === 0,
          '5. a person\'s names and telephone are in the simple view',
          JSON.stringify(missing));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'subtab views',
  describe: 'the simple and advanced views of an application\'s and a ' +
            'person\'s configuration sub-tabs (#500)',
  run: run
};
