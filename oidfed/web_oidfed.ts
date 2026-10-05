// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_oidfed.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → OPENID FEDERATION, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws OpenID Federation from the answer of `GET /admin-api/oidfed`: this
// realm as a federation entity — its configuration, keys, subordinates, the
// collection, its Trust Anchors and Trust Marks, a resolution, and its
// settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `OidfedAdmin`'s in `oidfed/oidfed_admin.ts`, moved with
// their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * Draws OpenID Federation from the answer of `GET /admin-api/oidfed`: this
 * realm as a federation entity — its configuration, keys, subordinates, the
 * collection, its Trust Anchors and Trust Marks, a resolution, and its
 * settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class OidfedPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return OidfedPage.body(view);
  }

  /**
   * Draws a value as `<code>`, escaped.
   *
   * @param value - the value
   * @returns the markup
   */
  static code(value: Json): string {
    return '<code>' + esc(value == null ? '' : String(value)) + '</code>';
  }

  /**
   * Draws a quiet placeholder such as "none".
   *
   * @param text - the placeholder; "none" when empty
   * @returns the markup
   */
  static none(text: string): string {
    return '<span class="sub">' + esc(text || 'none') + '</span>';
  }

  /**
   * Draws a hidden form field.
   *
   * @param name - the field's name
   * @param value - its value
   * @returns the markup
   */
  static hidden(name: string, value: Json): string {
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(String(value == null ? '' : value)) + '">';
  }

  // One POST control: the action, its hidden fields, the visible ones and a
  // button.
  /**
   * Draws one POST control: the action, its hidden fields, the visible ones and
   * a button.
   *
   * @param action - the action's name
   * @param fields - the fields' markup
   * @param button - the button's label
   * @param danger - whether the button is drawn as dangerous
   * @returns the markup
   */
  static form(action: string, fields: string, button: string,
       danger?: boolean): string {
    return '<form method="post" action="/admin/oidfed" class="inline">' +
           this.hidden('action', action) + fields + ' <button type="submit"' +
           (danger ? ' class="danger"' : '') + '>' + esc(button) +
           '</button></form>';
  }

  /**
   * Draws the section about this realm as a federation entity.
   *
   * @param json - `oidfed.view()`'s answer
   * @returns the markup
   */
  static sectionEntity(json: Json): string {
    const self = this;
    const endpoints = Object.keys(json.endpoints).map(function (k: string) {
      return '<tr><th>' + esc(k) + '</th><td>' + self.code(json.endpoints[k]) +
             '</td></tr>';
    }).join('');
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
        ? kit.warn(esc(json.entityConfigurationProblem)) : '') +
      (json.entityConfiguration
        ? '<details><summary>The Entity Configuration\'s claims</summary>' +
          '<pre>' + esc(JSON.stringify(json.entityConfiguration, null, 2)) +
          '</pre></details>' : '');
  }

  /**
   * Draws the Federation Entity Keys section.
   *
   * @param json - `oidfed.view()`'s answer
   * @returns the markup
   */
  static sectionKeys(json: Json): string {
    const self = this;
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
    return '<h2>Federation Entity Keys</h2>' +
      kit.note('The keys this realm signs its federation statements with, ' +
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

  /**
   * Draws the subordinates section, with each one's history and controls.
   *
   * @param json - `oidfed.view()`'s answer
   * @returns the markup
   */
  static sectionSubordinates(json: Json): string {
    const self = this;
    const reasonField = '<input name="reason" placeholder="reason" ' +
                        'size="18"> <input name="informationUri" ' +
                        'placeholder="https://… (information)" size="18">';
    const rows = json.subordinates.length
      ? json.subordinates.map(function (s: Json) {
        const who = self.hidden('entityId', s.entityId);
        const status = s.suspended
          ? '<strong>suspended</strong> ' + esc(String(s.suspended.at || '')) +
            (s.suspended.reason ? ' — ' + esc(s.suspended.reason) : '')
          : 'active';
        const acts = (s.suspended
          ? self.form('reinstate-subordinate', who + ' ' + reasonField,
                      'Reinstate')
          : self.form('suspend-subordinate', who + ' ' + reasonField,
                      'Suspend', true)) +
          (s.implicit ? '' : ' ' + self.form('remove-subordinate',
            who + ' ' + reasonField, 'Revoke', true));
        return '<tr><td>' + self.code(s.entityId) + '</td><td>' +
          (s.localRealm ? 'realm ' + self.code(s.localRealm) +
                          (s.implicit ? ' (every realm)' : '')
                        : esc((s.kids || []).join(', '))) + '</td><td>' +
          esc((s.entityTypes || []).join(', ')) + '</td><td>' +
          (s.metadataPolicy ? 'yes' : '') + (s.constraints ? ' constraints'
                                                           : '') +
          '</td><td>' + status + self.history(s.events) + '</td><td>' +
          acts + '</td></tr>';
      }).join('')
      : '<tr><td colspan="6" class="sub">This realm vouches for nobody; it ' +
        'publishes no fetch or list endpoint.</td></tr>';
    return '<h2>Subordinates</h2>' +
      kit.note('The entities this realm issues Subordinate Statements ' +
        'about (8.1): their keys, and the metadata, policy and constraints ' +
        'the statement carries. Registering an entity VOUCHES for it — give ' +
        'its JWK Set, or read it from its own Entity Configuration. A ' +
        'SUSPENDED subordinate is issued no statement and listed nowhere ' +
        'until it is reinstated, so no chain passes through it; REVOKING ' +
        'one removes it. Every one of those acts, and every change to what ' +
        'its statement carries, is kept in its history for good and ' +
        'served by the subordinate events endpoint.') +
      '<table><thead><tr><th>Entity</th><th>Keys</th><th>Types</th>' +
      '<th>Policy</th><th>Status</th><th></th></tr></thead><tbody>' + rows +
      '</tbody></table>' + this.sectionFormer(json) +
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
      '<p><input name="eventDescription" placeholder="what the history ' +
      'records about it" size="40"> <input name="informationUri" ' +
      'placeholder="https://… (information)" size="30"></p>' +
      '<p><button type="submit">Register the subordinate</button></p></form>';
  }

  // One subordinate's history (#137), folded: a <details> needs no script.
  /**
   * Draws one subordinate's history, folded in a `<details>`.
   *
   * @param events - the subordinate's events
   * @returns the markup
   */
  static history(events: Json): string {
    const list: Json[] = Array.isArray(events) ? events : [];
    if (!list.length) {
      return '';
    }
    const rows = list.map(function (e: Json): string {
      return '<tr><td>' + esc(new Date(Number(e.iat) * 1000).toISOString()) +
        '</td><td><code>' + esc(e.event) + '</code></td><td>' +
        esc(e.event_description || '') +
        (e.information_uri ? ' <a href="' + esc(e.information_uri) +
                             '">information</a>' : '') + '</td></tr>';
    }).join('');
    return '<details><summary>History (' + list.length + ')</summary>' +
           '<table><tbody>' + rows + '</tbody></table></details>';
  }

  // The subordinates this realm revoked, whose histories it keeps (#137).
  /**
   * Draws the subordinates this realm revoked, whose histories it keeps.
   *
   * @param json - `oidfed.view()`'s answer
   * @returns the markup
   */
  static sectionFormer(json: Json): string {
    const self = this;
    const former: Json[] = json.formerSubordinates || [];
    if (!former.length) {
      return '';
    }
    const rows = former.map(function (f: Json): string {
      return '<tr><td>' + self.code(f.entityId) + '</td><td>' +
        (f.localRealm ? 'realm ' + self.code(f.localRealm) + ', deleted'
                      : 'revoked') + self.history(f.events) + '</td></tr>';
    }).join('');
    return '<h3>Former subordinates</h3><table><thead><tr><th>Entity</th>' +
           '<th>History</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  // The Entity Collection (#136): the crawl kept, and Crawl now.
  /**
   * Draws the Entity Collection section: the last crawl, and Crawl now.
   *
   * @param json - `oidfed.view()`'s answer
   * @returns the markup
   */
  static sectionCollection(json: Json): string {
    const c = json.collection || {};
    const crawl = c.crawl;
    const kept = crawl
      ? '<table><tbody><tr><th>Crawled</th><td>' + esc(crawl.crawledAt) +
        '</td></tr><tr><th>For</th><td>' + this.code(crawl.entityId) +
        (crawl.forThisIdentifier ? '' : ' <strong>— not the identifier ' +
                                        'this page was reached by, so the ' +
                                        'endpoint does not answer from ' +
                                        'it</strong>') +
        '</td></tr><tr><th>Entities</th><td>' + esc(String(crawl.entities)) +
        (crawl.truncated ? ' (stopped at a bound)' : '') + '</td></tr>' +
        (crawl.problems.length
          ? '<tr><th>Left out</th><td><details><summary>' +
            esc(String(crawl.problems.length)) + '</summary><ul>' +
            crawl.problems.map(function (p: string): string {
              return '<li>' + esc(p) + '</li>';
            }).join('') + '</ul></details></td></tr>' : '') +
        '</tbody></table>'
      : '<p class="sub">No crawl is kept; the collection endpoint answers ' +
        'with what this service collects without fetching — its own ' +
        'realms, and subordinates already resolved.</p>';
    return '<h2>Entity Collection</h2>' +
      kit.note('Every entity beneath this realm, for the collection ' +
        'endpoint: each resolved to this realm before it is kept, and each ' +
        'Intermediate outside this service asked for its list only once it ' +
        'has — through the outbound policy, bounded by ' +
        '<code>oidfed.collectionMaxEntities</code> and ' +
        '<code>oidfed.collectionMaxFetches</code>. ' +
        (c.jobOff ? 'The scheduled crawl is off: ' + esc(c.jobOff) + '.'
                  : 'The scheduled crawl runs every ' +
                    esc(String(c.crawlEveryS)) + ' s.')) +
      kept + this.form('crawl-collection', '', 'Crawl now');
  }

  /**
   * Draws the Trust Anchors section.
   *
   * @param json - `oidfed.view()`'s answer
   * @returns the markup
   */
  static sectionAnchors(json: Json): string {
    const self = this;
    const rows = json.trustAnchors.map(function (a: Json) {
      return '<tr><td>' + self.code(a.entityId) + '</td><td>' +
        (a.localRealm ? 'realm ' + self.code(a.localRealm)
                      : esc((a.kids || []).join(', '))) + '</td><td>' +
        (a.localRealm ? '' : self.form('remove-trust-anchor',
          self.hidden('entityId', a.entityId), 'Remove', true)) +
        '</td></tr>';
    }).join('');
    return '<h2>Trust Anchors</h2>' +
      kit.note('The entities a Trust Chain may END at (10.2), each with ' +
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

  /**
   * Draws the Trust Marks section.
   *
   * @param json - `oidfed.view()`'s answer
   * @returns the markup
   */
  static sectionMarks(json: Json): string {
    const self = this;
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
      return '<tr><td colspan="' + n + '" class="sub">None.</td></tr>';
    };
    return '<h2>Trust Marks</h2>' +
      kit.note('A Trust Mark is this realm\'s signed statement that an ' +
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

  /**
   * Draws the Resolve an entity section, and the last resolution's result.
   *
   * @param json - `oidfed.view()`'s answer
   * @param extra - a resolution to show, if any
   * @returns the markup
   */
  static sectionResolve(json: Json, extra: Json): string {
    const shown = extra ? '<pre>' + esc(JSON.stringify(extra, null, 2)) +
                          '</pre>' : '';
    return '<h2>Resolve an entity</h2>' +
      kit.note('Walks the entity\'s authority_hints up to one of this ' +
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

  // THE PAGE'S BODY (#446), one method so that it can be one renderer. A
  // resolution the reader just asked for is the view's `resolution`.
  /**
   * Draws the page's body.
   *
   * @param json - the view, with `resolution` when one was just made
   * @returns the body as HTML
   */
  static body(json: Json): string {
    const inner =
      kit.note('<strong>OpenID Federation 1.1 for this trust realm.' +
        '</strong> Trust between entities that were never configured with ' +
        'each other, through a chain of signed statements ending at a ' +
        'Trust Anchor. This realm is a ' + esc(json.role) + '.') +
      this.sectionEntity(json) + this.sectionKeys(json) +
      this.sectionSubordinates(json) + this.sectionCollection(json) +
      this.sectionAnchors(json) +
      this.sectionMarks(json) + this.sectionResolve(json, json.resolution) +
      SettingsForms.forms(json.settings, '/admin/oidfed') +
      '<p class="links"><a href="/admin/oidfed?format=json">JSON</a> · ' +
      '<code>GET /admin-api/oidfed</code> · <a href="' +
      esc(json.configurationUrl) + '">Entity Configuration</a> · ' +
      '<a href="/admin/federation">Federation</a> · <a ' +
      'href="/admin/error-codes">Error codes</a></p>';
    return inner;
  }
}

export = OidfedPage;
