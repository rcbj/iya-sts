'use strict';
//
// File: ssf_transmitters_admin.ts
//
// ===========================================================================
// /admin/ssf/transmitters — FOREIGN SHARED SIGNALS TRANSMITTERS (#153,
// 2026-09-26): the transmitters this realm receives CAEP and RISC events
// from, each with its discovered configuration, the federation relationship
// its subjects are mapped through, its stream at the transmitter and the
// stream's acts (create, read, update, delete, status, subjects, verify,
// poll now), what arrived and what it led to, and the locks a transmitter's
// account-disabled put on people here. Its twin is
// `/admin-api/ssf/transmitters` (`ssf_transmitters_api.ts`, rule 7); both call
// `ssf_transmitters.ts`'s `report()` and `act()`. Never a client secret, a
// bearer token or the push authorization header.
//
// It REVERSES `ssf/CLAUDE.md`'s rule that nothing on the console creates a
// stream — for the other direction only: there it would be this service
// dialling a delivery address a console user typed; here the administrator
// names an ISSUER, and every address dialled comes from that issuer's own
// configuration document (root CLAUDE.md's argued "Dial a URL" row).
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import transmitters = require('./ssf_transmitters');

type Json = any;

const esc = admin.esc;
const PAGE = '/admin/ssf/transmitters';

interface TransmittersAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  transmitters: typeof transmitters;
  adminViews: () => Json;
}

class SsfTransmittersAdmin {
  static readonly PAGE = PAGE;

  constructor(private readonly deps: TransmittersAdminDeps) {
    deps.log.debug("Entering SsfTransmittersAdmin.constructor().");
    deps.log.debug("Leaving SsfTransmittersAdmin.constructor().");
  }

  static defaultDeps(): TransmittersAdminDeps {
    helpers.log.debug("Entering SsfTransmittersAdmin.defaultDeps().");
    helpers.log.debug("Leaving SsfTransmittersAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf, errorCodes: errorCodes, admin: admin,
      transmitters: transmitters,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering SsfTransmittersAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in SsfTransmittersAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving SsfTransmittersAdmin.actorOf().");
    return (state && state.username) || '';
  }

  static form(action: string, fields: Json, label: string,
              danger?: boolean): string {
    helpers.log.debug("Entering SsfTransmittersAdmin.form(). " + action);
    helpers.log.debug("Leaving SsfTransmittersAdmin.form().");
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="' + esc(action) + '">' +
      Object.keys(fields).map(function (k: string): string {
        return '<input type="hidden" name="' + esc(k) + '" value="' +
          esc(fields[k]) + '">';
      }).join('') + ' <button type="submit"' +
      (danger ? ' class="danger"' : '') + '>' + esc(label) +
      '</button></form>';
  }

  body(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SsfTransmittersAdmin.body().");
    const form = SsfTransmittersAdmin.form;
    const cards = json.transmitters.length
      ? json.transmitters.map(function (t: Json): string {
        const id = { id: t.id };
        return '<div class="card" id="transmitter-' + esc(t.id) + '"><h3>' +
          esc(t.id) + ' <span class="sub">' + esc(t.state) + '</span></h3>' +
          '<p>Issuer <code>' + esc(t.issuer) + '</code>, subjects mapped ' +
          'through the relationship <code>' + esc(t.federationId) +
          '</code>, delivery <strong>' + esc(t.delivery) + '</strong>' +
          (t.streamId ? ', stream <code>' + esc(t.streamId) + '</code>' +
            ' (aud <code>' + esc((t.streamAud || []).join(' ')) +
            '</code>)' : ', no stream yet') + '.</p><p class="sub">' +
          esc(t.counts.received || 0) + ' received, ' +
          esc(t.counts.verified || 0) + ' verified, ' +
          esc(t.counts.refused || 0) + ' refused, ' +
          esc(t.counts.acted || 0) + ' reaction(s)' +
          (t.lastPollAt ? '; last poll ' + esc(t.lastPollAt) + ': ' +
            esc(t.lastPollResult) : '') +
          (t.verifiedAt ? '; verified ' + esc(t.verifiedAt) : '') +
          (t.lastError ? '<br><strong>' + esc(t.lastError) + '</strong>'
                       : '') + '</p>' +
          (t.streamId
            ? form('read-stream', id, 'Read stream') +
              form('verify', id, 'Verify') +
              (t.delivery === 'poll' ? form('poll-now', id, 'Poll now') : '') +
              form('set-status', Object.assign({ status: 'paused' }, id),
                   'Pause') +
              form('set-status', Object.assign({ status: 'enabled' }, id),
                   'Enable') +
              form('delete-stream', id, 'Delete stream', true)
            : form('create-stream', id, 'Create stream')) +
          form('remove', id, 'Remove', true) + '</div>';
      }).join('')
      : '<p class="sub" id="transmitters-none">No foreign transmitter is ' +
        'registered in this realm.</p>';
    const field = function (name: string, label: string, hint: string,
                            type?: string): string {
      return '<label>' + label + ' <input type="' + (type || 'text') +
        '" name="' + name + '" autocomplete="off"></label>' +
        (hint ? ' <span class="sub">' + hint + '</span>' : '') + '<br>';
    };
    const add = '<h3>Register a transmitter</h3>' +
      '<form method="post" action="' + PAGE + '" id="transmitter-add">' +
      '<input type="hidden" name="action" value="add">' +
      field('id', 'Id', 'lower-case letters, digits and hyphens') +
      field('issuer', 'Issuer', 'its SSF issuer; the configuration is ' +
            'discovered from it') +
      field('federationId', 'Federation relationship', 'whose linked ' +
            'identities its subjects are mapped through') +
      '<label>Delivery <select name="delivery"><option>poll</option>' +
      '<option>push</option></select></label><br>' +
      field('eventsRequested', 'Events requested', 'space-separated event ' +
            'URIs; empty asks for what it supports') +
      field('tokenEndpoint', 'Token endpoint', 'client credentials at the ' +
            'transmitter\'s authorization server') +
      field('clientId', 'client_id', '') +
      field('clientSecret', 'Client secret', 'sealed; never shown again',
            'password') +
      field('bearer', 'Or a bearer token', 'instead of client credentials',
            'password') +
      '<button type="submit">Register</button></form>';
    const received = json.received.length ? json.received.map(function (r:
                                                                       Json) {
      return '<tr><td><code>' + esc(r.transmitter) + '</code></td><td>' +
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
    return admin.note('<strong>Shared Signals from other identity ' +
        'services.</strong> A transmitter registered here is another ' +
        'service that sends CAEP and RISC events about people who also ' +
        'sign in here. Its configuration and keys are discovered from its ' +
        'issuer; a Security Event Token is acted on only when it verified ' +
        'against those keys, names this stream\'s audience and a person ' +
        'the federation relationship links — and then only as the ' +
        '<code>signal-response</code> policy permits: end their sessions ' +
        'here, disable their account, enable it again (only a lock this ' +
        'transmitter put there).' + (json.observeOnly
          ? ' <strong>This realm only records what it would do</strong> ' +
            '(development; <code>ssf.actOnSignalsInDevelopment</code>).'
          : '')) + cards + add +
      '<h3>What arrived</h3><table><thead><tr><th>Transmitter</th><th>When' +
      '</th><th>Events</th><th>Verified</th><th>Person</th><th>Reactions' +
      '</th></tr></thead><tbody>' + received + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/ssf/transmitters</code></p>';
  }

  registerRoutes(app: Json): void {
    const { log, parseBody, admin, transmitters, errorCodes,
            baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmittersAdmin.registerRoutes().");
    app.get(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin transmitters page.");
      const json = transmitters.report({ transmitter: req.query.transmitter });
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.body(json);
      admin.respond(req, res, json, 'Foreign SSF transmitters', PAGE, inner);
      log.debug("Leaving the admin transmitters page.");
    });
    app.post(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin transmitters action.");
      Promise.resolve().then(function (): Json {
        return transmitters.act(parseBody(req) || {}, { via: 'console',
          actor: self.actorOf(req), base: baseUrlOf(req) });
      }).catch(function (e: any): Json {
        log.error(errorCodes.tag('STS-SSF-0113') + 'ssf: a console ' +
                  'transmitter action failed: ' + ((e && e.stack) || e));
        return errorCodes.mark({ ok: false, errors:
          ['The action could not be completed.'] }, 'STS-SSF-0113');
      }).then(function (result: Json): void {
        admin.respondToAction(req, res, PAGE, result);
        log.debug("Leaving the admin transmitters action.");
      });
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  SsfTransmittersAdmin: SsfTransmittersAdmin,
  installInstance: (instance: SsfTransmittersAdmin): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE
};
