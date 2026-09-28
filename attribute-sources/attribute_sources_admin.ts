// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
// File: attribute_sources_admin.ts
// ---------------------------------------------------------------------------
// THE CONSOLE PAGE /admin/attribute-sources (#94 part C): Directory →
// Attribute sources.
//
// The register of the operators' SQL databases this realm reads people's
// attributes from, each with its status; a form to add one; per source a
// Test (connect, and read one person's row without writing it), a Refresh
// now (every person, on the scheduler) and an Edit fold; a form to read one
// person now; and the two settings. Every act is `attribute_sources.ts`'s
// `act()`, which `POST /admin-api/attribute-sources/{action}` calls too
// (rule 7), and the page draws `view()`, which `GET /admin-api/
// attribute-sources` answers.
//
// **NO SCRIPT**: every control is a form, and the Edit fold a `<details>`,
// as the console's other folds are.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import attributeSources = require('./attribute_sources');

type Json = any;

const esc = admin.esc;
/**
 * The page's path.
 */
const PAGE = '/admin/attribute-sources';

interface AttributeSourcesAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  sources: typeof attributeSources;
  adminViews: () => Json;
}

/**
 * The console page `/admin/attribute-sources`: the attribute source
 * register, with add, change, test, refresh and remove.
 */
class AttributeSourcesAdmin {
  /**
   * Builds the page from its dependencies.
   *
   * @param deps - the logger, body parser, error codes, console shell, the
   *   register and a lazy loader of the gate state
   */
  constructor(private readonly deps: AttributeSourcesAdminDeps) {
    deps.log.debug("Entering AttributeSourcesAdmin.constructor().");
    deps.log.debug("Leaving AttributeSourcesAdmin.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): AttributeSourcesAdminDeps {
    helpers.log.debug("Entering AttributeSourcesAdmin.defaultDeps().");
    helpers.log.debug("Leaving AttributeSourcesAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody, errorCodes: errorCodes,
      admin: admin, sources: attributeSources,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  /**
   * Returns the signed-in console operator, for the audit row.
   *
   * @param req - the console request
   * @returns the operator's username, or ''
   */
  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering AttributeSourcesAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in AttributeSourcesAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving AttributeSourcesAdmin.actorOf().");
    return (state && state.username) || '';
  }

  // The fields of a source's form, filled with `source` (empty for a new
  // one). The refresh modes are checkboxes, read back as a list.
  private fields(json: Json, source: Json): string {
    const { log } = this.deps;
    log.debug("Entering AttributeSourcesAdmin.fields().");
    const s = source || {};
    const text = function (name: string, label: string, value: unknown,
                           hint?: string): string {
      return '<label>' + esc(label) + ' <input type="text" name="' + name +
        '" value="' + esc(value == null ? '' : value) + '"' +
        (hint ? ' placeholder="' + esc(hint) + '"' : '') + '></label>';
    };
    const select = function (name: string, label: string,
                              options: string[], value: string): string {
      return '<label>' + esc(label) + ' <select name="' + name + '">' +
        options.map(function (one) {
          return '<option' + (one === value ? ' selected' : '') + '>' +
                 esc(one) + '</option>';
        }).join('') + '</select></label>';
    };
    const columns = Object.keys(s.columns || {}).map(function (c) {
      return c + '=' + s.columns[c];
    }).join('\n');
    const refresh = s.refresh || ['sign-in'];
    log.debug("Leaving AttributeSourcesAdmin.fields().");
    return '<div class="formrow">' +
      select('dialect', 'Database', json.dialects, s.dialect || 'postgres') +
      text('host', 'Host', s.host, 'db.example.com') +
      text('port', 'Port', s.port, 'the dialect\'s') +
      text('database', 'Database name', s.database) +
      text('user', 'User', s.user) + '</div><div class="formrow">' +
      select('passwordProvider', 'Password from', json.passwordProviders,
             s.passwordProvider || 'none') +
      text('passwordRef', 'at', s.passwordRef, 'a path or a secret name') +
      text('passwordField', 'field', s.passwordField, 'optional') +
      text('caFile', 'CA file', s.caFile, 'optional PEM path') +
      text('serverName', 'Server name', s.serverName, 'defaults to the host') +
      '</div><div class="formrow"><label>Trusted CA certificates (PEM), ' +
      'the database\'s chain <textarea name="caCertificates" rows="4" ' +
      'cols="64" placeholder="-----BEGIN CERTIFICATE-----">' +
      esc(s.caCertificates || '') + '</textarea></label><label><input ' +
      'type="checkbox" name="trustPublicRoots" value="true"' +
      (s.trustPublicRoots ? ' checked' : '') + '> also trust the public ' +
      'roots</label></div><div class="formrow">' +
      text('table', 'Table or view', s.table, 'schema.table') +
      text('keyColumn', 'Key column', s.keyColumn) +
      text('keyAttribute', 'matches the person\'s', s.keyAttribute || 'uid') +
      '</div><div class="formrow"><label>Columns, one per line as ' +
      'column=attribute <textarea name="columns" rows="3" cols="40">' +
      esc(columns) + '</textarea></label></div><div class="formrow">' +
      'Read: ' + json.modes.map(function (mode: string) {
        return '<label><input type="checkbox" name="refresh" value="' +
               esc(mode) + '"' + (refresh.indexOf(mode) >= 0 ? ' checked'
                                                            : '') + '> ' +
               esc(mode) + '</label>';
      }).join(' ') +
      text('scheduleS', 'every (s)', s.scheduleS || 3600) +
      text('timeoutMs', 'timeout (ms)', s.timeoutMs || 2000) +
      select('onFailure', 'on failure', json.onFailure,
             s.onFailure || 'keep') +
      select('enabled', 'enabled', ['true', 'false'],
             s.enabled === false ? 'false' : 'true') + '</div>';
  }

  // What a source's connection trusts (#94): its own chain, each
  // certificate by subject, expiry and SHA-256, and whether node's store is
  // trusted beside it.
  private trustCell(source: Json): string {
    const { log } = this.deps;
    log.debug("Entering AttributeSourcesAdmin.trustCell(). " + source.id);
    const trust = source.trust || { certificates: [] };
    const chain = (trust.certificates || []).map(function (one: Json) {
      return '<div><span title="' + esc('issued by ' + one.issuer +
        ', SHA-256 ' + one.sha256) + '">' + esc(one.subject) + '</span>' +
        '<br><span class="sub">' + (one.ca ? 'CA' : 'not a CA') +
        (one.selfSigned ? ', self-signed' : '') + ', until ' +
        esc(one.notAfter.slice(0, 10)) +
        (one.expired ? ' <span class="state-revoked">expired</span>' : '') +
        '</span></div>';
    }).join('');
    log.debug("Leaving AttributeSourcesAdmin.trustCell().");
    return chain + (trust.caFile ? '<div class="sub">and the file <code>' +
      esc(trust.caFile) + '</code></div>' : '') +
      '<div class="sub">' + (trust.publicRoots
        ? (chain || trust.caFile ? 'and the public roots'
                                 : 'the public roots')
        : 'these alone, not the public roots') + '</div>';
  }

  // One source's row: where it reads, what it writes, and its status.
  private row(json: Json, source: Json): string {
    const { log } = this.deps;
    log.debug("Entering AttributeSourcesAdmin.row(). " + source.id);
    const st = source.status || {};
    const form = function (action: string, extra: string, label: string,
                           danger?: boolean): string {
      return '<form method="post" action="' + PAGE + '" class="inline">' +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="id" value="' + esc(source.id) + '">' +
        extra + ' <button type="submit"' + (danger ? ' class="danger"' : '') +
        '>' + esc(label) + '</button></form>';
    };
    log.debug("Leaving AttributeSourcesAdmin.row().");
    return '<tr><td class="who"><code>' + esc(source.id) + '</code>' +
      (source.enabled ? '' : ' <span class="sub">disabled</span>') +
      '</td><td>' + esc(source.dialect) + ' <code>' +
      esc(source.host + ':' + source.port + '/' + source.database) +
      '</code><br><span class="sub">as ' + esc(source.user) + '</span>' +
      '<br><span class="sub">TLS, verified against:</span>' +
      this.trustCell(source) + '</td>' +
      '<td><code>' + esc(source.table) + '.' + esc(source.keyColumn) +
      '</code> = the person\'s <code>' + esc(source.keyAttribute) +
      '</code></td><td>' + Object.keys(source.columns || {}).map(function (c) {
        return '<div><code>' + esc(c) + '</code> &rarr; <code>' +
               esc(source.columns[c]) + '</code></div>';
      }).join('') + '</td><td>' + esc((source.refresh || []).join(', ')) +
      '<br><span class="sub">on failure ' + esc(source.onFailure) +
      '</span></td><td>' +
      (st.lastError
        ? '<span class="state-revoked">' + esc(st.lastCode || '') +
          '</span> <span class="sub">' + esc(st.lastError) + ' at ' +
          esc(st.lastErrorAt || '') + '</span>'
        : (st.lastOkAt ? 'read at ' + esc(st.lastOkAt)
                       : '<span class="state-none">not yet</span>')) +
      (st.lastRunAt ? '<br><span class="sub">scheduled run ' +
        esc(st.lastRunAt) + ', ' + esc(st.lastRunPeople || 0) + ' people' +
        (st.cursorOpen ? ', continuing' : '') + '</span>' : '') +
      '</td><td class="act">' +
      form('test-source', '<input type="text" name="username" size="12" ' +
           'placeholder="a person">', 'Test') +
      form('refresh-source', '', 'Read everyone now') +
      '<details><summary>Edit</summary><form method="post" action="' + PAGE +
      '"><input type="hidden" name="action" value="update-source">' +
      '<input type="hidden" name="id" value="' + esc(source.id) + '">' +
      this.fields(json, source) + '<button type="submit">Save</button>' +
      '</form></details>' +
      form('remove-source', '', 'Remove', true) + '</td></tr>';
  }

  /**
   * Draws the page body.
   *
   * @param json - the view `GET /admin-api/attribute-sources` answers
   * @returns the HTML
   */
  body(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering AttributeSourcesAdmin.body().");
    const rows = json.sources.map((source: Json) => this.row(json, source))
      .join('');
    log.debug("Leaving AttributeSourcesAdmin.body().");
    return admin.note('The SQL databases this realm reads people\'s ' +
        'attributes from, <strong>onto their directory entries</strong>, ' +
        'where an attribute claim (on the claim pages) or the catalogue ' +
        'carries them into tokens and assertions. A source reads one row: ' +
        'the one whose key column holds the person\'s key attribute. It is ' +
        'read at sign-in (before the first token), once, on a schedule or ' +
        'on demand, as it says. The connection is always TLS, verified; the ' +
        'password is read from where the source names, never stored here. ' +
        'An attribute is written by one source only, and no source writes ' +
        'mail, an attribute this service keeps, or the entry\'s identity, ' +
        'structure or group membership.') +
      (json.hostPatterns ? '' : admin.warn('<strong>Any host.</strong> ' +
        '<code>attributeSources.hostPatterns</code> is empty in this realm, ' +
        'so a source here may name any host this service\'s network ' +
        'reaches, internal ones included — and a realm administrator ' +
        'manages this realm\'s sources. A service administrator narrows it ' +
        'below.')) +
      '<h3 id="sources">Sources</h3><table><thead><tr><th>Source</th>' +
      '<th>Database</th><th>Row</th><th>Columns</th><th>Read</th>' +
      '<th>Status</th><th></th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="7"><span class="state-none">No source is ' +
               'configured in this realm.</span></td></tr>') +
      '</tbody></table>' +
      '<h3 id="add">Add a source</h3><form method="post" action="' + PAGE +
      '"><input type="hidden" name="action" value="add-source">' +
      '<div class="formrow"><label>Id <input type="text" name="id" ' +
      'placeholder="hr-db" required></label></div>' +
      this.fields(json, null) + '<button type="submit">Add</button></form>' +
      '<h3 id="person">Read one person now</h3><form method="post" ' +
      'action="' + PAGE + '"><div class="formrow"><input type="hidden" ' +
      'name="action" value="refresh-person"><label>Person <input ' +
      'type="text" name="username" required></label><button ' +
      'type="submit">Read</button></div></form>' +
      '<p class="sub">From every source that allows on-demand. The ' +
      'scheduled refresh is the <code>' + esc(json.job) + '</code> job on ' +
      '<a href="/admin/scheduler">Scheduler</a>.</p>' +
      '<h2>Settings</h2>' + admin.configFormsFor(PAGE) +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/attribute-sources</code></p>';
  }

  /**
   * Registers `GET` and `POST /admin/attribute-sources`: the page, and its
   * acts.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log, parseBody, admin, sources, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AttributeSourcesAdmin.registerRoutes().");
    app.get(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin attribute sources page.");
      const json = Object.assign(sources.view(),
                                 { settings: admin.configSettingsJson(PAGE) });
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.body(json);
      admin.respond(req, res, json, 'Attribute sources', PAGE, inner);
      log.debug("Leaving the admin attribute sources page.");
    });
    app.post(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin attribute sources action.");
      Promise.resolve().then(function (): Json {
        const body = parseBody(req);
        // THE REFRESH MODES ARE CHECKBOXES, one `refresh` repeated, and the
        // body parser keeps the last: the console's own reader takes them
        // all. An update that ticked none says so rather than keeping the
        // old modes — the form always shows every box.
        if (body.action === 'add-source' || body.action === 'update-source') {
          body.refresh = admin.listField(req, body, 'refresh');
          // An unticked box posts nothing: on this form that means off.
          body.trustPublicRoots = body.trustPublicRoots === 'true';
          body.caCertificates = String(body.caCertificates || '');
        }
        return sources.act(body, { via: 'console',
                                   actor: self.actorOf(req) });
      }).catch(function (e: any): Json {
        log.error(errorCodes.tag('STS-ATTR-0002') + 'attribute sources: a ' +
                  'console action failed: ' + ((e && e.stack) || e));
        return errorCodes.mark({ ok: false, errors:
                                   ['The action could not be completed.'] },
                               'STS-ATTR-0002');
      }).then(function (result: Json): void {
        admin.respondToAction(req, res, PAGE, result);
        log.debug("Leaving the admin attribute sources action.");
      });
    });
    log.debug("Leaving AttributeSourcesAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<AttributeSourcesAdmin>(
  'attribute-sources/attribute_sources_admin',
  () => new AttributeSourcesAdmin(AttributeSourcesAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The console page `/admin/attribute-sources` (#94), the attribute source
 * register.
 *
 * The composition root builds the instance and calls `registerRoutes()`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  AttributeSourcesAdmin: AttributeSourcesAdmin,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: AttributeSourcesAdmin): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE
};
