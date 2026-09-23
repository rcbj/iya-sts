'use strict';
//
// File: oidfed_admin.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS -> OPENID FEDERATION (#132, #133, 2026-09-23): the console page.
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `scep/scep_admin.ts` draws SCEP's. Every fact on the page comes out of ONE
// call to `oidfed.view()`, which is the same call `GET /admin-api/oidfed`
// answers with, and every control is one of `oidfed.act()`'s actions, which
// `POST /admin-api/oidfed/:action` takes too (rule 7).
//
// No script, like every page of this console but one: every control is a
// form, and the JSON fields (a JWK Set, a metadata policy) are textareas.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import oidfed = require('./oidfed');

type Json = any;

const esc = admin.esc;

interface OidfedAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  oidfed: typeof oidfed;
  // The console's gate state, for who acted (`admin-core/admin_views`),
  // lazily: it requires route modules.
  adminViews: () => Json;
}

class OidfedAdmin {
  constructor(private readonly deps: OidfedAdminDeps) {
    deps.log.debug("Entering OidfedAdmin.constructor().");
    deps.log.debug("Leaving OidfedAdmin.constructor().");
  }

  static defaultDeps(): OidfedAdminDeps {
    helpers.log.debug("Entering OidfedAdmin.defaultDeps().");
    helpers.log.debug("Leaving OidfedAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody, errorCodes: errorCodes,
      admin: admin, oidfed: oidfed,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  // Who is acting, for the audit row: the console's signed-in operator.
  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering OidfedAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in OidfedAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving OidfedAdmin.actorOf().");
    return (state && state.username) || '';
  }

  code(value: Json): string {
    this.deps.log.debug("Entering OidfedAdmin.code().");
    this.deps.log.debug("Leaving OidfedAdmin.code().");
    return '<code>' + esc(value == null ? '' : String(value)) + '</code>';
  }

  none(text: string): string {
    this.deps.log.debug("Entering OidfedAdmin.none().");
    this.deps.log.debug("Leaving OidfedAdmin.none().");
    return '<span class="sub">' + esc(text || 'none') + '</span>';
  }

  hidden(name: string, value: Json): string {
    this.deps.log.debug("Entering OidfedAdmin.hidden().");
    this.deps.log.debug("Leaving OidfedAdmin.hidden().");
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(String(value == null ? '' : value)) + '">';
  }

  // One POST control: the action, its hidden fields, the visible ones and a
  // button.
  form(action: string, fields: string, button: string,
       danger?: boolean): string {
    this.deps.log.debug("Entering OidfedAdmin.form(). " + action);
    this.deps.log.debug("Leaving OidfedAdmin.form().");
    return '<form method="post" action="/admin/oidfed" class="inline">' +
           this.hidden('action', action) + fields + ' <button type="submit"' +
           (danger ? ' class="danger"' : '') + '>' + esc(button) +
           '</button></form>';
  }

  sectionEntity(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering OidfedAdmin.sectionEntity().");
    const endpoints = Object.keys(json.endpoints).map(function (k: string) {
      return '<tr><th>' + esc(k) + '</th><td>' + self.code(json.endpoints[k]) +
             '</td></tr>';
    }).join('');
    log.debug("Leaving OidfedAdmin.sectionEntity().");
    return '<h2>This realm as a federation entity</h2><table class="kv">' +
      '<tr><th>Entity Identifier</th><td>' + this.code(json.entityId) +
      '</td></tr><tr><th>Role</th><td><strong>' + esc(json.role) +
      '</strong></td></tr><tr><th>Authority hints</th><td>' +
      (json.authorityHints.length
        ? json.authorityHints.map(this.code.bind(this)).join('<br>')
        : this.none('none — a Trust Anchor')) + '</td></tr>' +
      '<tr><th>Every realm a subordinate of the default</th><td>' +
      (json.realmsAreSubordinates ? 'yes' : 'no') + '</td></tr></table>' +
      '<h3>Endpoints</h3><table class="kv">' + endpoints + '</table>' +
      (json.entityConfigurationProblem
        ? admin.warn(esc(json.entityConfigurationProblem)) : '') +
      (json.entityConfiguration
        ? '<details><summary>The Entity Configuration\'s claims</summary>' +
          '<pre>' + esc(JSON.stringify(json.entityConfiguration, null, 2)) +
          '</pre></details>' : '');
  }

  sectionKeys(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering OidfedAdmin.sectionKeys().");
    const rows = json.keys.length ? json.keys.map(function (k: Json) {
      const control = k.state === 'retired' && !k.revokedAt
        ? self.form('revoke-key', self.hidden('kid', k.kid) +
            '<select name="reason"><option>superseded</option>' +
            '<option>compromised</option><option>unspecified</option>' +
            '</select>', 'Revoke', true)
        : '';
      return '<tr><td>' + self.code(k.kid) + '</td><td>' + esc(k.alg) +
        '</td><td>' + esc(k.state) + (k.revokedAt ? ' (revoked: ' +
        esc(k.revokedReason) + ')' : '') + '</td><td>' +
        esc(k.createdAt || '') + '</td><td>' + esc(k.publishedUntil || '') +
        '</td><td>' + (k.sealed ? 'sealed' : 'not sealed') + '</td><td>' +
        control + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">No key yet; the first ' +
      'statement this realm signs makes one.</td></tr>';
    log.debug("Leaving OidfedAdmin.sectionKeys().");
    return '<h2>Federation Entity Keys</h2>' +
      admin.note('The keys this realm signs its federation statements with, ' +
        'kept apart from its protocol signing keys (3.1.1). A <em>next</em> ' +
        'key is published before it signs; a <em>retired</em> one stays ' +
        'published through <code>oidfed.keyOverlapDays</code> and is listed ' +
        'at the Historical Keys endpoint for good (8.7). New keys are ' +
        esc(json.signingAlg) + ' (<code>oidfed.signingAlg</code>).') +
      '<table><thead><tr><th>kid</th><th>Algorithm</th><th>State</th>' +
      '<th>Made</th><th>Published until</th><th>At rest</th><th></th></tr>' +
      '</thead><tbody>' + rows + '</tbody></table>' +
      this.form('rotate-key', '', 'Rotate now') + ' ' +
      this.form('rotate-key', this.hidden('emergency', 'true') +
        ' <input name="confirm" placeholder="type compromised" required>',
        'Emergency rotation', true);
  }

  sectionSubordinates(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering OidfedAdmin.sectionSubordinates().");
    const rows = json.subordinates.length
      ? json.subordinates.map(function (s: Json) {
        return '<tr><td>' + self.code(s.entityId) + '</td><td>' +
          (s.localRealm ? 'realm ' + self.code(s.localRealm) +
                          (s.implicit ? ' (every realm)' : '')
                        : esc((s.kids || []).join(', '))) + '</td><td>' +
          esc((s.entityTypes || []).join(', ')) + '</td><td>' +
          (s.metadataPolicy ? 'yes' : '') + (s.constraints ? ' constraints'
                                                           : '') +
          '</td><td>' + (s.implicit ? '' : self.form('remove-subordinate',
            self.hidden('entityId', s.entityId), 'Remove', true)) +
          '</td></tr>';
      }).join('')
      : '<tr><td colspan="5" class="sub">This realm vouches for nobody; it ' +
        'publishes no fetch or list endpoint.</td></tr>';
    log.debug("Leaving OidfedAdmin.sectionSubordinates().");
    return '<h2>Subordinates</h2>' +
      admin.note('The entities this realm issues Subordinate Statements ' +
        'about (8.1): their keys, and the metadata, policy and constraints ' +
        'the statement carries. Registering an entity VOUCHES for it — give ' +
        'its JWK Set, or read it from its own Entity Configuration.') +
      '<table><thead><tr><th>Entity</th><th>Keys</th><th>Types</th>' +
      '<th>Policy</th><th></th></tr></thead><tbody>' + rows +
      '</tbody></table>' +
      '<form method="post" action="/admin/oidfed">' +
      this.hidden('action', 'add-subordinate') +
      '<p><input name="entityId" placeholder="https://entity.example" ' +
      'required size="50"> <label><input type="checkbox" name="fetchJwks">' +
      ' read its keys from its Entity Configuration</label> <label>' +
      '<input type="checkbox" name="intermediate"> an Intermediate</label>' +
      '</p><p><textarea name="jwks" rows="3" cols="80" placeholder="its JWK ' +
      'Set, if not read"></textarea></p><p><textarea name="metadataPolicy" ' +
      'rows="3" cols="80" placeholder="metadata_policy (JSON)"></textarea>' +
      '</p><p><textarea name="constraints" rows="2" cols="80" ' +
      'placeholder="constraints (JSON)"></textarea></p>' +
      '<p><button type="submit">Register the subordinate</button></p></form>';
  }

  sectionAnchors(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering OidfedAdmin.sectionAnchors().");
    const rows = json.trustAnchors.map(function (a: Json) {
      return '<tr><td>' + self.code(a.entityId) + '</td><td>' +
        (a.localRealm ? 'realm ' + self.code(a.localRealm)
                      : esc((a.kids || []).join(', '))) + '</td><td>' +
        (a.localRealm ? '' : self.form('remove-trust-anchor',
          self.hidden('entityId', a.entityId), 'Remove', true)) +
        '</td></tr>';
    }).join('');
    log.debug("Leaving OidfedAdmin.sectionAnchors().");
    return '<h2>Trust Anchors</h2>' +
      admin.note('The entities a Trust Chain may END at (10.2), each with ' +
        'the keys configured for it here — the one key material in a ' +
        'federation that is trusted out of band.') +
      '<table><thead><tr><th>Anchor</th><th>Keys</th><th></th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="3" class="sub">None.</td></tr>') +
      '</tbody></table>' +
      '<form method="post" action="/admin/oidfed">' +
      this.hidden('action', 'add-trust-anchor') +
      '<p><input name="entityId" placeholder="https://anchor.example" ' +
      'required size="50"> <label><input type="checkbox" name="fetchJwks">' +
      ' read its keys from its Entity Configuration</label></p><p>' +
      '<textarea name="jwks" rows="3" cols="80" placeholder="its JWK Set, ' +
      'if not read"></textarea></p><p><button type="submit">Trust it' +
      '</button></p></form>';
  }

  sectionMarks(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering OidfedAdmin.sectionMarks().");
    const types = json.markTypes.map(function (t: Json) {
      return '<tr><td>' + self.code(t.type) + '</td><td>' + esc(t.lifetimeS) +
        ' s</td><td>' + (t.delegation ? 'delegated' : '') + '</td><td>' +
        self.form('issue-trust-mark', self.hidden('type', t.type) +
          ' <input name="sub" placeholder="https://entity.example" ' +
          'required>', 'Issue') + ' ' +
        self.form('remove-mark-type', self.hidden('type', t.type), 'Remove',
                  true) + '</td></tr>';
    }).join('');
    const issued = json.issuedMarks.map(function (m: Json) {
      return '<tr><td>' + self.code(m.type) + '</td><td>' + self.code(m.sub) +
        '</td><td>' + esc(m.status) + '</td><td>' + esc(m.expiresAt || '') +
        '</td><td>' + (m.status === 'revoked' ? '' :
          self.form('revoke-trust-mark', self.hidden('id', m.id), 'Revoke',
                    true)) + '</td></tr>';
    }).join('');
    const held = json.heldMarks.map(function (m: Json) {
      return '<tr><td>' + self.code(m.type) + '</td><td>' + self.code(m.iss) +
        '</td><td>' + esc(m.expiresAt || '') + '</td><td>' +
        self.form('remove-held-mark', self.hidden('id', m.id), 'Remove',
                  true) + '</td></tr>';
    }).join('');
    const policies = json.markPolicies.map(function (p: Json) {
      return '<tr><td>' + self.code(p.type) + '</td><td>' +
        esc((p.issuers || []).join(', ') || 'anybody') + '</td><td>' +
        esc(p.owner || '') + '</td><td>' + self.form('remove-mark-policy',
          self.hidden('type', p.type), 'Remove', true) + '</td></tr>';
    }).join('');
    const empty = function (n: number): string {
      log.debug("Entering empty().");
      log.debug("Leaving empty().");
      return '<tr><td colspan="' + n + '" class="sub">None.</td></tr>';
    };
    log.debug("Leaving OidfedAdmin.sectionMarks().");
    return '<h2>Trust Marks</h2>' +
      admin.note('A Trust Mark is this realm\'s signed statement that an ' +
        'entity meets a type\'s criteria (7). The types it issues, the marks ' +
        'it has issued (their status is answered at the Trust Mark Status ' +
        'endpoint), the marks issued TO it that its Entity Configuration ' +
        'carries, and — as a Trust Anchor — who may issue a type.') +
      '<h3>Types this realm issues</h3><table><thead><tr><th>Type</th>' +
      '<th>Lifetime</th><th></th><th></th></tr></thead><tbody>' +
      (types || empty(4)) + '</tbody></table>' +
      '<form method="post" action="/admin/oidfed">' +
      this.hidden('action', 'add-mark-type') +
      '<p><input name="type" placeholder="https://federation.example/marks/' +
      'x" required size="50"> <input name="lifetimeS" type="number" ' +
      'min="60" placeholder="lifetime (s)"> <input name="logoUri" ' +
      'placeholder="logo_uri"> <input name="ref" placeholder="ref"></p>' +
      '<p><textarea name="delegation" rows="2" cols="80" placeholder="a ' +
      'trust-mark-delegation+jwt, when the type is owned by another ' +
      'entity"></textarea></p><p><button type="submit">Issue this type' +
      '</button></p></form>' +
      '<h3>Issued</h3><table><thead><tr><th>Type</th><th>To</th><th>Status' +
      '</th><th>Expires</th><th></th></tr></thead><tbody>' +
      (issued || empty(5)) + '</tbody></table>' +
      '<h3>Carried by this realm</h3><table><thead><tr><th>Type</th>' +
      '<th>Issuer</th><th>Expires</th><th></th></tr></thead><tbody>' +
      (held || empty(4)) + '</tbody></table>' +
      this.form('add-held-mark', '<input name="trustMark" size="60" ' +
                'placeholder="a trust-mark+jwt issued to this realm" ' +
                'required>', 'Carry it') +
      '<h3>As a Trust Anchor: who may issue a type</h3><table><thead><tr>' +
      '<th>Type</th><th>Issuers</th><th>Owner</th><th></th></tr></thead>' +
      '<tbody>' + (policies || empty(4)) + '</tbody></table>' +
      '<form method="post" action="/admin/oidfed">' +
      this.hidden('action', 'set-mark-policy') +
      '<p><input name="type" placeholder="type" required size="40"> ' +
      '<input name="issuers" placeholder="issuers, comma-separated (none: ' +
      'anybody)" size="40"> <input name="ownerSub" placeholder="owner ' +
      'entity"></p><p><textarea name="ownerJwks" rows="2" cols="80" ' +
      'placeholder="the owner\'s JWK Set"></textarea></p><p><button ' +
      'type="submit">Set the policy</button></p></form>';
  }

  sectionResolve(json: Json, extra: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering OidfedAdmin.sectionResolve().");
    const shown = extra ? '<pre>' + esc(JSON.stringify(extra, null, 2)) +
                          '</pre>' : '';
    log.debug("Leaving OidfedAdmin.sectionResolve().");
    return '<h2>Resolve an entity</h2>' +
      admin.note('Walks the entity\'s authority_hints up to one of this ' +
        'realm\'s Trust Anchors, fetching what it must through the outbound ' +
        'policy and bounded by <code>oidfed.maxAuthorityHints</code>, ' +
        '<code>oidfed.maxChainDepth</code> and ' +
        '<code>oidfed.maxFetchesPerResolution</code>; the result is what ' +
        'the resolve endpoint then answers with (' +
        esc(String(json.resolutions.length)) + ' held now).') +
      this.form('resolve', '<input name="sub" placeholder="https://entity.' +
                'example" required size="50"> <input name="trustAnchor" ' +
                'placeholder="trust anchor (any)" size="40">', 'Resolve') +
      shown;
  }

  async draw(req: Json, res: Json, extraTop: string,
             resolution: Json): Promise<void> {
    const { log, admin, oidfed } = this.deps;
    log.debug("Entering OidfedAdmin.draw().");
    const json = await oidfed.view(req);
    const inner = (extraTop || '') +
      (typeof admin.messagesOf === 'function' ? admin.messagesOf(req) : '') +
      admin.note('<strong>OpenID Federation 1.1 for this trust realm.' +
        '</strong> Trust between entities that were never configured with ' +
        'each other, through a chain of signed statements ending at a ' +
        'Trust Anchor. This realm is a ' + esc(json.role) + '.') +
      this.sectionEntity(json) + this.sectionKeys(json) +
      this.sectionSubordinates(json) + this.sectionAnchors(json) +
      this.sectionMarks(json) + this.sectionResolve(json, resolution) +
      admin.configFormsFor('/admin/oidfed') +
      '<p class="links"><a href="/admin/oidfed?format=json">JSON</a> · ' +
      '<code>GET /admin-api/oidfed</code> · <a href="' +
      esc(json.configurationUrl) + '">Entity Configuration</a> · ' +
      '<a href="/admin/federation">Federation</a> · <a ' +
      'href="/admin/error-codes">Error codes</a></p>';
    admin.respond(req, res, json, 'OpenID Federation', '/admin/oidfed', inner);
    log.debug("Leaving OidfedAdmin.draw().");
  }

  registerRoutes(app: Json): void {
    const { log, parseBody, admin, oidfed, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OidfedAdmin.registerRoutes().");
    app.get('/admin/oidfed', function (req: Json, res: Json): void {
      log.debug("Entering the admin OpenID Federation page.");
      self.draw(req, res, '', null).catch(function (e: any): void {
        log.error(errorCodes.tag('STS-OIDFED-0050') + 'oidfed: the console ' +
                  'page failed: ' + ((e && e.stack) || e));
        errorCodes.mark(res, 'STS-OIDFED-0050');
        res.status(500).type('text/plain').send('The page failed.');
      });
      log.debug("Leaving the admin OpenID Federation page.");
    });
    app.post('/admin/oidfed', function (req: Json, res: Json): void {
      log.debug("Entering the admin OpenID Federation action.");
      const body = parseBody(req);
      oidfed.act(body, { via: 'console', actor: self.actorOf(req), req: req })
        .then(function (result: Json): Promise<void> | void {
          const json = /json/i.test(String(req.headers['content-type'] || ''));
          if (result.ok && result.resolution && !json) {
            // A RESOLUTION is shown in full on the page, rather than as a
            // one-line message on a redirect.
            return self.draw(req, res, admin.note(esc(result.message)),
                             result.resolution);
          }
          admin.respondToAction(req, res, '/admin/oidfed', result);
        })
        .catch(function (e: any): void {
          log.error(errorCodes.tag('STS-OIDFED-0050') + 'oidfed: a console ' +
                    'action failed: ' + ((e && e.stack) || e));
          admin.respondToAction(req, res, '/admin/oidfed', errorCodes.mark(
            { ok: false, errors: ['The action could not be completed.'] },
            'STS-OIDFED-0050'));
        });
      log.debug("Leaving the admin OpenID Federation action handler.");
    });
    log.debug("Leaving OidfedAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<OidfedAdmin>(
  'oidfed/oidfed_admin',
  () => new OidfedAdmin(OidfedAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  OidfedAdmin: OidfedAdmin,
  installInstance: (instance: OidfedAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin()
};
