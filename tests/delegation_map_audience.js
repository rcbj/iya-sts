// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/delegation_map_audience.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION IS ONE BOX ON THE DELEGATION PICTURE HOWEVER IT WAS NAMED
// (2026-10-06, rcbj).
//
// Monitoring -> Delegation drew an application named by an audience it
// registered (`oauthAudience`) and the same application named by its
// identifier as two boxes. `common/delegation.js`'s `nodeIdOf()` now resolves
// an application name to the entry that registered it — the identifier, then
// an audience, then a client_id — and keys the box by that entry. Held here,
// through `delegation.graph()`:
//
//   1. an act naming the application by its audience and one naming it by
//      its identifier reach ONE box, keyed and labelled by the identifier,
//      with the audience kept as an alias;
//   2. a configured pair (`appAllowedToDelegateTo`) naming it by audience
//      draws its line to that same box;
//   3. a client_id resolves the same way;
//   4. an audience no application registered is still a box of its own.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const delegation = require('../common/delegation');
const realms = require('../common/realms');
const stats = require('../common/admin_stats');

const log = require('bunyan').createLogger({
  name: 'delegation_map_audience',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = String(process.pid);
const API = 'dma-api-' + TAG;
const AUDIENCE = 'https://dma-api-' + TAG + '.example.com';
const CLIENT = 'dma-api-client-' + TAG;
const FRONT = 'dma-front-' + TAG;
const STRANGER = 'https://dma-nobody-' + TAG + '.example.com';

function run(t) {
  log.debug("Entering run().");
  realms.run(realms.DEFAULT_REALM, function () {
    adminActions.applicationsAction({ action: 'create', identifier: API,
      'field.oauthAudience': AUDIENCE, 'field.oauthClientId': CLIENT },
      ['oauth2']);
    adminActions.applicationsAction({ action: 'create', identifier: FRONT },
                                    ['oauth2']);
    t.check(!!applications.forAudience(AUDIENCE),
            'precondition: the audience is registered on ' + API);

    const kind = delegation.TYPES.filter(function (one) {
      return one.protocol === 'OAuth 2.0';
    })[0] || delegation.TYPES[0];
    const act = function (target) {
      log.debug("Entering act().");
      log.debug("Leaving act().");
      return delegation.record({
        protocol: kind.protocol, type: kind.type,
        outcome: delegation.OUTCOMES[0],
        initial: { presented: 'dma-alice-' + TAG },
        intermediary: { presented: FRONT, application: FRONT },
        target: { application: target },
        authorizedBy: 'a test', note: 'recorded by a test' });
    };
    const rows = [act(AUDIENCE), act(API), act(CLIENT), act(STRANGER)]
      .filter(Boolean);
    t.check(rows.length === 4, 'precondition: four acts were recorded',
            rows.length);

    const picture = delegation.graph(rows, { configured: [
      { from: FRONT, to: AUDIENCE, attribute: 'appAllowedToDelegateTo',
        mechanism: 'oauth', setOn: FRONT }] });
    const nodes = picture.nodes || [];
    const apiId = stats.identityKeyOf(API);
    const apiNodes = nodes.filter(function (n) {
      return n.id === apiId;
    });
    const asAudience = nodes.filter(function (n) {
      return n.id === stats.identityKeyOf(AUDIENCE) || n.id === AUDIENCE;
    });
    const asClient = nodes.filter(function (n) {
      return n.id === stats.identityKeyOf(CLIENT);
    });
    t.check(apiNodes.length === 1 && !asAudience.length && !asClient.length,
            '1/3. the audience, the identifier and the client_id are ONE box',
            JSON.stringify(nodes.map(function (n) { return n.id; })));
    const box = apiNodes[0] || {};
    t.check(box.application === API &&
            (box.aliases || []).indexOf(AUDIENCE) >= 0 &&
            (box.aliases || []).indexOf(CLIENT) >= 0,
            '1. the box is the registered application, with the audience and ' +
            'the client_id kept as the names it was also given',
            JSON.stringify({ application: box.application,
                             aliases: box.aliases }));

    const edges = picture.edges || [];
    const configured = edges.filter(function (e) {
      return e.relation === 'may-delegate';
    });
    t.check(configured.length === 1 && configured[0].to === apiId,
            '2. a configured pair naming the audience draws its line to ' +
            'that box', JSON.stringify(configured.map(function (e) {
              return [e.from, e.to];
            })));
    const reaching = edges.filter(function (e) {
      return e.to === apiId && e.relation === 'reaches';
    });
    t.check(reaching.length >= 1,
            '1. the acts\' lines reach that box', reaching.length);

    const stranger = nodes.filter(function (n) {
      return n.id === stats.identityKeyOf(STRANGER) || n.id === STRANGER;
    });
    t.check(stranger.length === 1 && !(stranger[0].aliases || []).length,
            '4. an audience no application registered is still a box of ' +
            'its own', JSON.stringify(stranger));

    adminActions.applicationsAction({ action: 'forget', application: API });
    adminActions.applicationsAction({ action: 'forget', application: FRONT });
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'delegation map audience',
  describe: 'an application named by an audience, a client_id or its ' +
            'identifier is one box on the delegation picture',
  run: run
};
