// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/delegation_map_client_subject.js
//
// ---------------------------------------------------------------------------
// A CLIENT ACTING AS ITSELF IS ITS APPLICATION'S BOX ON THE DELEGATION
// PICTURE (#468, 2026-10-06).
//
// An RFC 8693 delegation whose actor_token came from a client_credentials
// grant records the actor as that token's `sub`: the bare client_id with RFC
// 9700 mode off, `urn:sts:client:<id>` with it on (product). The picture
// keyed a presented identity before its application, so in product the
// service bus that hop 1 REACHED (`esb`) and the one that ACTED in hop 2
// (`urn:sts:client:esb`) were two boxes, and the chain two halves.
// `common/delegation.js`'s `nodeIdOf()` now draws a client's own subject as
// its application. Held here, through `delegation.graph()`, beside
// `delegation_map_audience.js` (the same rule for an audience):
//
//   1. PRODUCT'S FORM: a two-hop chain whose actors present
//      `urn:sts:client:<id>` draws the middle tier as ONE box — reached by
//      hop 1 and acting in hop 2 — keyed by its identifier, with the
//      namespaced subject kept as an alias, and no box keyed by it;
//   2. DEVELOPMENT'S FORM: a bare `sub` that is a REGISTERED client_id is
//      that application's box, even where the client_id is not the
//      identifier;
//   3. an actor naming ANOTHER client than the one exchanging is that other
//      client's box;
//   4. a person — a bare name no client registered — is still keyed as an
//      identity;
//   5. an unregistered `urn:sts:client:<id>` is a box named `<id>`, the box
//      an act naming that client_id as its target would be.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const delegation = require('../common/delegation');
const realms = require('../common/realms');
const stats = require('../common/admin_stats');

const log = require('bunyan').createLogger({
  name: 'delegation_map_client_subject',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = String(process.pid);
const GW = 'dmc-gw-' + TAG;
const ESB = 'dmc-esb-' + TAG;
const ESB_AUDIENCE = 'https://dmc-esb-' + TAG + '.example.com';
const SP = 'dmc-sp-' + TAG;
// An application whose client_id is NOT its identifier.
const SVC = 'dmc-svc-' + TAG;
const SVC_CLIENT = 'dmc-svc-client-' + TAG;
const PERSON = 'dmc-alice-' + TAG;
const UNREGISTERED = 'dmc-nobody-' + TAG;

function run(t) {
  log.debug("Entering run().");
  realms.run(realms.DEFAULT_REALM, function () {
    adminActions.applicationsAction({ action: 'create', identifier: GW,
      'field.oauthClientId': GW }, ['oauth2']);
    adminActions.applicationsAction({ action: 'create', identifier: ESB,
      'field.oauthClientId': ESB, 'field.oauthAudience': ESB_AUDIENCE },
      ['oauth2']);
    adminActions.applicationsAction({ action: 'create', identifier: SP,
      'field.oauthClientId': SP }, ['oauth2']);
    adminActions.applicationsAction({ action: 'create', identifier: SVC,
      'field.oauthClientId': SVC_CLIENT }, ['oauth2']);
    t.check(!!applications.forClientId(ESB) &&
            !!applications.forClientId(SVC_CLIENT),
            'precondition: the client_ids are registered');

    const kind = delegation.TYPES.filter(function (one) {
      return one.type === 'oauth-delegation';
    })[0] || delegation.TYPES[0];
    const act = function (actorSub, client, target) {
      log.debug("Entering act().");
      log.debug("Leaving act().");
      return delegation.record({
        protocol: kind.protocol, type: kind.type,
        outcome: delegation.OUTCOMES[0],
        initial: { presented: PERSON },
        intermediary: { presented: actorSub, application: client },
        target: { application: target },
        authorizedBy: 'a test', note: 'recorded by a test' });
    };
    const idOf = function (name) {
      log.debug("Entering idOf().");
      log.debug("Leaving idOf().");
      return stats.identityKeyOf(name);
    };
    const boxes = function (picture, id) {
      log.debug("Entering boxes().");
      log.debug("Leaving boxes().");
      return (picture.nodes || []).filter(function (n) {
        return n.id === id;
      });
    };
    const ids = function (picture) {
      log.debug("Entering ids().");
      log.debug("Leaving ids().");
      return JSON.stringify((picture.nodes || []).map(function (n) {
        return n.id;
      }));
    };

    // 1. Product's form: hop 1 reaches the service bus by its audience,
    //    hop 2 is the service bus acting by its namespaced subject.
    const productRows = [
      act('urn:sts:client:' + ESB, ESB, SP),
      act('urn:sts:client:' + GW, GW, ESB_AUDIENCE)].filter(Boolean);
    t.check(productRows.length === 2, 'precondition: two acts were recorded',
            productRows.length);
    const product = delegation.graph(productRows);
    const esbBoxes = boxes(product, idOf(ESB));
    const esb = esbBoxes[0] || { roles: {}, aliases: [] };
    t.check(esbBoxes.length === 1 && esb.roles.target >= 1 &&
            esb.roles.intermediary >= 1,
            '1. the service bus is ONE box, reached by hop 1 and acting in ' +
            'hop 2', ids(product) + ' ' + JSON.stringify(esb));
    t.check(!boxes(product, idOf('urn:sts:client:' + ESB)).length &&
            !boxes(product, idOf('urn:sts:client:' + GW)).length &&
            boxes(product, idOf(GW)).length === 1,
            '1. no box is keyed by a client\'s namespaced subject',
            ids(product));
    t.check(esb.application === ESB &&
            (esb.aliases || []).indexOf('urn:sts:client:' + ESB) >= 0,
            '1. the box is the registered application, with the subject it ' +
            'acted under kept as an alias', JSON.stringify(
              { application: esb.application, aliases: esb.aliases }));
    const actsFor = (product.edges || []).filter(function (e) {
      return e.relation === 'acts-for' && e.to === idOf(ESB);
    });
    t.check(actsFor.length >= 1, '1. the person\'s delegation line reaches ' +
            'that box', JSON.stringify((product.edges || []).map(
              function (e) {
                return e.from + '>' + e.to;
              })));

    // 2. Development's form, through a client_id that is not the identifier.
    const devRows = [act(SVC_CLIENT, SVC_CLIENT, SP)].filter(Boolean);
    const dev = delegation.graph(devRows);
    t.check(boxes(dev, idOf(SVC)).length === 1 &&
            !boxes(dev, idOf(SVC_CLIENT)).length,
            '2. a bare sub that is a registered client_id is that ' +
            'application\'s box', ids(dev));

    // 3. Another client's actor token, exchanged through GW.
    const otherRows = [act('urn:sts:client:' + SVC_CLIENT, GW, SP)]
      .filter(Boolean);
    const other = delegation.graph(otherRows);
    const svc = boxes(other, idOf(SVC))[0] || { roles: {} };
    t.check(svc.roles.intermediary >= 1 &&
            !boxes(other, idOf(GW)).length,
            '3. the actor is the client its subject names, not the client ' +
            'that exchanged', ids(other));

    // 4 and 5. A person, and an unregistered client.
    const personRows = [act(PERSON + '-actor', GW, SP),
      act('urn:sts:client:' + UNREGISTERED, GW, SP)].filter(Boolean);
    const people = delegation.graph(personRows);
    t.check(boxes(people, idOf(PERSON + '-actor')).length === 1,
            '4. a bare name no client registered is still an identity\'s box',
            ids(people));
    t.check(boxes(people, idOf(UNREGISTERED)).length === 1 &&
            !boxes(people, idOf('urn:sts:client:' + UNREGISTERED)).length,
            '5. an unregistered urn:sts:client: subject is a box named by ' +
            'its client_id', ids(people));

    [GW, ESB, SP, SVC].forEach(function (one) {
      adminActions.applicationsAction({ action: 'forget', application: one });
    });
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'delegation map client subject',
  describe: 'a client acting under its own subject (urn:sts:client:<id> or ' +
            'a registered client_id) is its application\'s box on the ' +
            'delegation picture',
  run: run
};
