// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_transmitters_admin.ts
//
// ===========================================================================
// /admin/ssf/transmitters — SIGNALS FROM PARTNERS (#153, 2026-09-26; a
// monitoring page since #373, 2026-10-01): every federation relationship
// whose partner's Shared Signals this realm receives, its stream at the
// partner and whether it is healthy, what arrived and what it led to, the
// sign-ins partners have blocked and the account locks a signals-only
// partner's event put on people here. Its twin is
// `GET /admin-api/ssf/transmitters` (`ssf_transmitters_api.ts`, rule 7); both
// draw `ssf_transmitters.ts`'s `report()`. Never a secret.
//
// READ ONLY SINCE #373. A partner's stream is CONFIGURED on its relationship
// (`fedSignals*`) and ACTED ON from the relationship's page — Discover,
// Create stream, Verify, Poll now, Unblock — because the relationship is
// what the partner is (rcbj's call on #373: a foreign transmitter is a
// federation partner in spirit). A second set of controls here would be a
// second door onto the same acts, and the one an operator reading this page
// during an incident did not need.
// ===========================================================================

import helpers = require('../common/helpers');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import transmitters = require('./ssf_transmitters');

type Json = any;

const esc = admin.esc;
/**
 * The console page's path, `/admin/ssf/transmitters`.
 */
const PAGE = '/admin/ssf/transmitters';

interface TransmittersAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  transmitters: typeof transmitters;
}

/**
 * The monitoring page for the federation partners whose Shared Signals this
 * realm receives: each relationship's stream, what arrived and what it led
 * to, and the blocks and locks partners put on people. It draws
 * `ssf_transmitters.ts`'s report, performs nothing, and never shows a secret.
 */
class SsfTransmittersAdmin {
  /**
   * The page's path; the module's `PAGE`.
   */
  static readonly PAGE = PAGE;

  /**
   * Builds the page from its dependencies.
   *
   * @param deps - the modules it reads, from
   * `SsfTransmittersAdmin.defaultDeps()` or the composition root
   */
  constructor(private readonly deps: TransmittersAdminDeps) {
    deps.log.debug("Entering SsfTransmittersAdmin.constructor().");
    deps.log.debug("Leaving SsfTransmittersAdmin.constructor().");
  }

  /**
   * Returns the real modules the page depends on, as the composition root
   * passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): TransmittersAdminDeps {
    helpers.log.debug("Entering SsfTransmittersAdmin.defaultDeps().");
    helpers.log.debug("Leaving SsfTransmittersAdmin.defaultDeps().");
    return { log: helpers.log, admin: admin, transmitters: transmitters };
  }

  /**
   * Draws the page's body from the report: a card per relationship, the
   * blocks and locks partners put on people here, and the table of what
   * arrived.
   *
   * @param json - `ssf_transmitters.ts`'s report
   * @returns the HTML
   */
  body(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SsfTransmittersAdmin.body().");
    const link = function (id: string): string {
      return '<a href="/admin/federation?relationship=' +
        encodeURIComponent(id) + '#signals"><code>' + esc(id) +
        '</code></a>';
    };
    const cards = json.relationships.length
      ? json.relationships.map(function (t: Json): string {
        return '<div class="card" id="relationship-' + esc(t.relationship) +
          '"><h3>' + link(t.relationship) + ' <span class="sub">' +
          esc(t.kind) + ', ' + esc(t.receiving ? t.state : 'not receiving') +
          '</span></h3><p>Issuer <code>' + esc(t.issuer) + '</code>, ' +
          'delivery <strong>' + esc(t.streamDelivery || t.delivery) +
          '</strong>' + (t.streamId ? ', stream <code>' + esc(t.streamId) +
            '</code> (aud <code>' + esc((t.streamAud || []).join(' ')) +
            '</code>)' : ', no stream yet') + '.</p><p class="sub">' +
          esc(t.counts.received || 0) + ' received, ' +
          esc(t.counts.verified || 0) + ' verified, ' +
          esc(t.counts.refused || 0) + ' refused, ' +
          esc(t.counts.acted || 0) + ' reaction(s)' +
          (t.lastPollAt ? '; last poll ' + esc(t.lastPollAt) + ': ' +
            esc(t.lastPollResult) : '') +
          (t.verifiedAt ? '; verified ' + esc(t.verifiedAt) : '') +
          (t.ready ? '' : '<br>Still to set: ' + esc(t.missing.join(', '))) +
          (t.lastError ? '<br><strong>' + esc(t.lastError) + '</strong>'
                       : '') + '</p></div>';
      }).join('')
      : '<p class="sub" id="relationships-none">No federation relationship ' +
        'in this realm receives its partner\'s Shared Signals. Turn ' +
        '<code>fedSignalsEnabled</code> on for one on <a ' +
        'href="/admin/federation">Federation</a>, or create an ' +
        '<code>ssf</code> relationship for a partner that signs nobody in.' +
        '</p>';
    const blocks = json.blocks.length
      ? '<h3>Sign-ins partners have blocked</h3><table><thead><tr><th>' +
        'Person</th><th>Relationship</th><th>Since</th><th>Event</th></tr>' +
        '</thead><tbody>' + json.blocks.map(function (b: Json): string {
          return '<tr><td>' + esc(b.username) + '</td><td>' +
            link(b.relationship) + '</td><td>' + esc(b.at) + '</td><td>' +
            '<code>' + esc(b.event) + '</code></td></tr>';
        }).join('') + '</tbody></table>'
      : '';
    const locks = json.locks.length
      ? '<h3>Accounts a partner disabled</h3><table><thead><tr><th>Person' +
        '</th><th>Relationship</th><th>Since</th></tr></thead><tbody>' +
        json.locks.map(function (l: Json): string {
          return '<tr><td>' + esc(l.username) + '</td><td>' +
            link(l.relationship) + '</td><td>' + esc(l.at) + '</td></tr>';
        }).join('') + '</tbody></table>'
      : '';
    const received = json.received.length ? json.received.map(function (r:
                                                                       Json) {
      return '<tr><td>' + link(r.relationship) + '</td><td>' +
        esc(r.receivedAt) + ' <span class="sub">' + esc(r.via) + '</span>' +
        '</td><td>' + (r.events || []).map(function (e: string) {
          return '<code>' + esc(String(e).replace(/^.*\//, '')) + '</code>';
        }).join(' ') + '</td><td>' + (r.verified ? 'verified'
          : '<strong>' + esc(r.refusal || 'unverified') + '</strong>') +
        (r.why ? '<br><span class="sub">' + esc(r.why) + '</span>' : '') +
        '</td><td>' + esc(r.person || '—') + (r.mapping
          ? '<br><span class="sub">' + esc(r.mapping) + '</span>' : '') +
        '</td><td>' + (r.reactions || []).map(function (x: Json) {
          return esc(x.reaction || '—') + (x.done ? ' ✓' : '') +
            (x.observed ? ' (observed only)' : '') +
            (x.why ? ' <span class="sub">' + esc(x.why) + '</span>' : '');
        }).join('<br>') + '</td></tr>';
    }).join('') : '<tr><td colspan="6" class="sub">Nothing has arrived.' +
      '</td></tr>';
    log.debug("Leaving SsfTransmittersAdmin.body().");
    return admin.note('<strong>Shared Signals from federation ' +
        'partners.</strong> A partner\'s CAEP and RISC events about the ' +
        'people it signs in — or, from an <code>ssf</code> relationship, ' +
        'about the people and devices it manages — are acted on only when ' +
        'they verified against the keys its SSF configuration names, name ' +
        'this stream\'s audience and a person the relationship links, and ' +
        'then only as the <code>signal-response</code> policy permits. Each ' +
        'stream is configured and acted on from its relationship\'s page.' +
        (json.observeOnly
          ? ' <strong>This realm only records what it would do</strong> ' +
            '(development; <code>ssf.actOnSignalsInDevelopment</code>).'
          : '')) + cards + blocks + locks +
      '<h3>What arrived</h3><table><thead><tr><th>Relationship</th><th>When' +
      '</th><th>Events</th><th>Verified</th><th>Person</th><th>Reactions' +
      '</th></tr></thead><tbody>' + received + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/ssf/transmitters</code></p>';
  }

  /**
   * Registers `GET /admin/ssf/transmitters` on the app.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log, admin, transmitters } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmittersAdmin.registerRoutes().");
    app.get(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin partners' signals page.");
      const json = transmitters.report({
        relationship: req.query.relationship });
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.body(json);
      admin.respond(req, res, json, 'Signals from partners', PAGE, inner);
      log.debug("Leaving the admin partners' signals page.");
    });
    log.debug("Leaving SsfTransmittersAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<SsfTransmittersAdmin>(
  'ssf/ssf_transmitters_admin',
  () => new SsfTransmittersAdmin(SsfTransmittersAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The monitoring page for federation partners' Shared Signals,
 * `/admin/ssf/transmitters`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  SsfTransmittersAdmin: SsfTransmittersAdmin,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: SsfTransmittersAdmin): void =>
    slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE
};
