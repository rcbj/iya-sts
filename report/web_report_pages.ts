// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_report_pages.ts
//
// ---------------------------------------------------------------------------
// THE REPORT APPLICATION'S BROWSER (#956). It signs in as the public client
// `sts-report`, holds the DPoP-bound token in memory, and draws every page
// from `/report-api`. The words come from the `report` catalogs.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// It does not hand a callback to another tab, and it does not poll.
// ---------------------------------------------------------------------------

import SpaClient = require('../common/web_spa_client');
import WebI18n = require('../common/web_i18n');
import WebAccounts = require('../common/web_accounts');
import WebMessages = require('../common/web_messages');

const CLIENT_ID = 'sts-report';
const SCOPE = 'openid profile email offline_access report:use report:admin';
const BASE = '/report';
const API = '/report-api';
const SIGNIN_KEY = 'sts-report-pkce';
const REFRESH_EARLY = 30;
const NEEDS_SIGN_IN = { needsSignIn: true };
const ABORTED = { aborted: true };

function esc(value: unknown): string {
  const text = value == null ? '' : String(value);
  return WebMessages.WebMessages.esc(text);
}

function statusWord(t: any, status: string): string {
  if (status === 'queued') {
    return t.text('report.queued');
  }
  if (status === 'running') {
    return t.text('report.running');
  }
  if (status === 'completed') {
    return t.text('report.completed');
  }
  if (status === 'failed') {
    return t.text('report.failed');
  }
  if (status === 'cancelled') {
    return t.text('report.cancelled');
  }
  if (status === 'expired') {
    return t.text('report.expired');
  }
  return esc(status);
}

function formatWord(t: any, format: string): string {
  if (format === 'json') {
    return t.text('report.json');
  }
  if (format === 'csv') {
    return t.text('report.csv');
  }
  if (format === 'pdf') {
    return t.text('report.pdf');
  }
  return esc(format);
}

function navHtml(t: any, accounts: string, chooser: string): string {
  return '<div class="bar"><nav class="nav">' +
    '<a href="' + esc(BASE) + '">' + esc(t.text('report.catalog')) +
    '</a>' +
    '<a href="' + esc(BASE + '/query') + '">' +
    esc(t.text('report.newQuery')) + '</a>' +
    '<a href="' + esc(BASE + '/definitions') + '">' +
    esc(t.text('report.definitions')) + '</a>' +
    '<a href="' + esc(BASE + '/jobs') + '">' +
    esc(t.text('report.jobs')) + '</a>' +
    '<a href="/logout">' + esc(t.text('report.signOut')) + '</a>' +
    '<button type="button" class="btn" data-act="refresh">' +
    esc(t.text('report.refresh')) + '</button>' +
    '</nav>' + accounts + chooser + '</div>';
}

function problemHtml(t: any, text: string): string {
  return '<p class="err">' + esc(text || t.text('report.error')) + '</p>';
}

function tableHtml(headers: string[], rows: string[][]): string {
  return '<table class="table"><thead><tr>' +
    headers.map(function (header: string): string {
      return '<th>' + header + '</th>';
    }).join('') + '</tr></thead><tbody>' +
    rows.map(function (row: string[]): string {
      return '<tr>' + row.map(function (cell: string): string {
        return '<td>' + cell + '</td>';
      }).join('') + '</tr>';
    }).join('') + '</tbody></table>';
}

function queryDocument(form: any): any {
  const source = String((form.elements.source &&
    form.elements.source.value) || '');
  const selected: string[] = [];
  const boxes = form.querySelectorAll('input[name="field"]:checked');
  for (let i = 0; i < boxes.length; i++) {
    selected.push(String(boxes[i].value || ''));
  }
  const filters: any[] = [];
  for (let n = 0; n < 3; n++) {
    const field = String((form.elements['filterField' + n] &&
      form.elements['filterField' + n].value) || '');
    const op = String((form.elements['filterOp' + n] &&
      form.elements['filterOp' + n].value) || '');
    const value = String((form.elements['filterValue' + n] &&
      form.elements['filterValue' + n].value) || '');
    if (!field || !op) {
      continue;
    }
    if (op === 'isNull') {
      filters.push({ op: 'isNull', field: field });
    } else if (value) {
      filters.push({ op: op, field: field, value: value });
    }
  }
  const sort = String((form.elements.sortField &&
    form.elements.sortField.value) || '');
  const dir = String((form.elements.sortDir &&
    form.elements.sortDir.value) || 'asc');
  const limit = Number(form.elements.limit && form.elements.limit.value);
  const format = String((form.elements.format &&
    form.elements.format.value) || 'json');
  const counted = !!(form.elements.counted && form.elements.counted.checked);
  const group = String((form.elements.groupBy &&
    form.elements.groupBy.value) || '');
  const document: any = {
    source: source,
    select: counted ? (group ? [group] : []) : selected,
    format: format,
    mode: 'auto'
  };
  if (Number.isFinite(limit) && limit >= 1) {
    document.limit = limit;
  }
  if (filters.length === 1) {
    document.where = filters[0];
  } else if (filters.length > 1) {
    document.where = { op: 'and', args: filters };
  }
  if (sort) {
    document.orderBy = [{ field: sort, dir: dir === 'desc' ? 'desc' : 'asc' }];
  }
  if (counted) {
    document.aggregate = 'count';
    document.groupBy = group ? [group] : [];
  }
  return document;
}

/**
 * The report application in the browser.
 */
class ReportRuntime extends SpaClient {
  private username: string;
  private i18n: any;
  private t: any;
  private accountsListening: boolean;

  /**
   * @param env - the browser's objects
   */
  constructor(env: any) {
    super(env, ReportRuntime.prefixOf(env.location.pathname), {
      clientId: CLIENT_ID,
      scope: SCOPE,
      elsewhere: {
        '/oauth2': 'data-sts-oauth',
        '/report-api': 'data-sts-api',
        '/logout': 'data-sts-authn'
      },
      accountKey: 'sts-report-account'
    });
    this.username = '';
    this.t = WebMessages.WebTranslator.fromData(null);
    this.i18n = new WebI18n(env, this, ['report']);
    this.accountsListening = false;
  }

  /**
   * The realm prefix before `/report`.
   *
   * @param pathname - the path
   * @returns the prefix, or ''
   */
  static prefixOf(pathname: string): string {
    return ReportRuntime.prefixAt(pathname, BASE);
  }

  /**
   * The report path without the realm prefix.
   *
   * @returns `/report/...`
   */
  reportPath(): string {
    const path = String(this.env.location.pathname || '');
    const at = path.indexOf(BASE);
    const rest = at >= 0 ? path.slice(at) : BASE;
    return rest.replace(/\/+$/, '') || BASE;
  }

  /**
   * The path and query to return to after a sign-in.
   *
   * @returns the path and query
   */
  here(): string {
    return this.reportPath() + String(this.env.location.search || '');
  }

  /**
   * The report API this token is audienced to.
   *
   * @returns the resource
   */
  resource(): string {
    return this.url(API);
  }

  /**
   * The authorization request for this client.
   *
   * @param state - the state
   * @param verifier - the PKCE verifier
   * @returns the URL
   */
  async authorizeUrl(state: string, verifier: string): Promise<string> {
    const params: any = {
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: this.url(BASE + '/callback'),
      scope: SCOPE,
      state: state,
      code_challenge: await this.sha256(verifier),
      code_challenge_method: 'S256',
      resource: this.resource(),
      nonce: await this.nonceFor(verifier)
    };
    const hint = this.hintFor(null);
    if (hint) {
      params.login_hint = hint;
    }
    return this.authorizationRequestUrl(params);
  }

  /**
   * Sends the browser to sign in.
   *
   * @param returnTo - where to land afterwards
   * @returns nothing
   */
  async beginSignIn(returnTo: string): Promise<void> {
    const verifier = this.random(32);
    const state = this.random(16);
    this.env.sessionStorage.setItem(SIGNIN_KEY, JSON.stringify({
      verifier: verifier,
      state: state,
      returnTo: returnTo,
      prefix: this.prefix
    }));
    this.env.location.assign(await this.authorizeUrl(state, verifier));
  }

  /**
   * Finishes the code flow on `/report/callback`. A mismatch starts one
   * fresh sign-in. The callback is not handed to another tab.
   *
   * @returns nothing
   */
  async finishSignIn(): Promise<void> {
    const query = await this.openAuthorizationResponse(
      SpaClient.queryOf(this.env.location.search));
    let saved: any = null;
    try {
      saved = JSON.parse(this.env.sessionStorage.getItem(SIGNIN_KEY) ||
        'null');
    } catch (e) {
      saved = null;
    }
    this.env.sessionStorage.removeItem(SIGNIN_KEY);
    if (query.error) {
      this.paint(problemHtml(this.t,
        String(query.error_description || query.error)));
      return;
    }
    if (!saved || !query.code || query.state !== saved.state) {
      this.env.history.replaceState(null, '', this.prefix + BASE);
      await this.beginSignIn(BASE);
      return;
    }
    const answer = await this.tokenRequest({
      grant_type: 'authorization_code',
      code: query.code,
      redirect_uri: this.url(BASE + '/callback'),
      client_id: CLIENT_ID,
      code_verifier: saved.verifier,
      resource: this.resource()
    });
    if (answer.status !== 200 || !answer.json.access_token) {
      this.paint(problemHtml(this.t,
        String((answer.json && (answer.json.error_description ||
          answer.json.error)) || this.t.text('report.error'))));
      return;
    }
    if (!await this.nonceMatches(answer.json.id_token, saved.verifier)) {
      this.paint(problemHtml(this.t, this.t.text('report.error')));
      return;
    }
    this.keepTokens(answer.json);
    this.username = SpaClient.claimOf(answer.json.id_token,
      'preferred_username');
    this.env.history.replaceState(null, '',
      this.prefix + String(saved.returnTo || BASE));
    await this.route();
  }

  /**
   * Swaps the refresh token for a new pair.
   *
   * @returns whether it worked
   */
  async refresh(): Promise<boolean> {
    if (!this.refreshToken) {
      return false;
    }
    const answer = await this.tokenRequest({
      grant_type: 'refresh_token',
      refresh_token: this.refreshToken,
      client_id: CLIENT_ID,
      resource: this.resource()
    });
    if (answer.status !== 200 || !answer.json.access_token) {
      this.refreshToken = '';
      return false;
    }
    this.keepTokens(answer.json);
    if (answer.json.id_token) {
      this.username = SpaClient.claimOf(answer.json.id_token,
        'preferred_username') || this.username;
    }
    return true;
  }

  /**
   * Sends one API request, refreshing a token that is about to expire.
   *
   * @param method - the method
   * @param target - the absolute URL
   * @param body - a JSON object, or nothing
   * @returns the response, or a sign-in sentinel
   */
  async sendOnce(method: string, target: string, body?: any): Promise<any> {
    const identity = this.identity;
    const now = this.env.now ? this.env.now() : Date.now();
    if (this.accessToken && now > this.expiresAt - REFRESH_EARLY * 1000) {
      await this.refresh();
    }
    if (identity !== this.identity) {
      return ABORTED;
    }
    if (!this.accessToken) {
      return NEEDS_SIGN_IN;
    }
    for (let attempt = 0; attempt < 3; attempt++) {
      const headers: any = {
        'Authorization': 'DPoP ' + this.accessToken,
        'DPoP': await this.proof(method, target, this.accessToken),
        'Accept': 'application/json, text/csv, application/pdf'
      };
      if (body !== undefined && body !== null) {
        headers['Content-Type'] = 'application/json';
      }
      let res: any = null;
      try {
        res = await this.env.fetch(target, {
          method: method,
          headers: headers,
          body: body !== undefined && body !== null ?
            JSON.stringify(body) : undefined,
          signal: this.identitySignal()
        });
      } catch (e) {
        if (identity !== this.identity) {
          return ABORTED;
        }
        throw e;
      }
      if (identity !== this.identity) {
        return ABORTED;
      }
      this.keepNonce(res);
      if (res.status !== 401) {
        return res;
      }
      const challenge = String((res.headers && res.headers.get &&
        res.headers.get('WWW-Authenticate')) || '');
      if (/use_dpop_nonce/.test(challenge) && attempt === 0) {
        continue;
      }
      if (/invalid_token/.test(challenge) && await this.refresh()) {
        continue;
      }
      break;
    }
    this.accessToken = '';
    return NEEDS_SIGN_IN;
  }

  /**
   * Calls the report API.
   *
   * @param method - the method
   * @param path - `/report-api/...`
   * @param body - a JSON body, or nothing
   * @returns the answer, or null when a sign-in began
   */
  async call(method: string, path: string, body?: any): Promise<any> {
    const res = await this.sendOnce(method, this.url(path), body);
    if (res === ABORTED) {
      return null;
    }
    if (res === NEEDS_SIGN_IN) {
      await this.beginSignIn(this.here());
      return null;
    }
    const type = String((res.headers && res.headers.get &&
      res.headers.get('Content-Type')) || '');
    if (type.indexOf('json') >= 0 || type === '') {
      let json: any = null;
      try {
        json = await res.json();
      } catch (e) {
        json = null;
      }
      return { status: res.status, json: json, media: type, res: res };
    }
    const bytes = await res.arrayBuffer();
    return { status: res.status, bytes: bytes, media: type, res: res };
  }

  /**
   * Loads the translator for this page.
   *
   * @returns nothing
   */
  async ensureLanguage(): Promise<void> {
    try {
      this.t = await this.i18n.load();
    } catch (e) {
      this.t = WebMessages.WebTranslator.fromData(null);
    }
  }

  /**
   * The page chrome.
   *
   * @param body - the page
   * @returns nothing
   */
  paint(body: string): void {
    const accounts = WebAccounts.controlHtml(this.accounts, this.t);
    const chooser = this.i18n.chooser(this.t, this.here());
    const html = '<h1>' + esc(this.t.text('report.title')) + '</h1>' +
      navHtml(this.t, accounts, chooser) + body;
    const main = this.env.document.getElementById('report');
    if (main) {
      main.innerHTML = html;
    }
  }

  /**
   * Remembers the signed-in accounts and hears later changes once.
   *
   * @returns nothing
   */
  async hearAccounts(): Promise<void> {
    await this.readAccounts(this.username);
    if (this.accountsListening) {
      return;
    }
    this.accountsListening = true;
    const self = this;
    this.listenForAccounts(function (): void {
      self.route();
    });
  }

  /**
   * Draws the catalog.
   *
   * @returns nothing
   */
  async drawCatalog(): Promise<void> {
    const answer = await this.call('GET', API + '/catalog');
    if (!answer) {
      return;
    }
    if (!answer.json || !answer.json.sources) {
      this.paint(problemHtml(this.t, answer.json &&
        answer.json.error_description));
      return;
    }
    const rows = answer.json.sources.map(function (src: any): string[] {
      return ['<a href="' + esc(BASE + '/sources/' + src.id) + '">' +
        esc(src.id) + '</a>',
        '<a href="' + esc(BASE + '/query?source=' + src.id) + '">' +
        esc(src.id) + '</a>'];
    });
    const body = rows.length ? tableHtml([
      esc(this.t.text('report.source')),
      esc(this.t.text('report.newQuery'))
    ], rows) : '<p class="sub">' + esc(this.t.text('report.empty')) + '</p>';
    this.paint(body);
  }

  /**
   * Draws one source.
   *
   * @param id - the source id
   * @returns nothing
   */
  async drawSource(id: string): Promise<void> {
    const answer = await this.call('GET', API + '/catalog/' +
      encodeURIComponent(id));
    if (!answer) {
      return;
    }
    if (!answer.json || !answer.json.source) {
      this.paint(problemHtml(this.t, answer.json &&
        answer.json.error_description));
      return;
    }
    const src = answer.json.source;
    const rows = (src.fields || []).map(function (field: any): string[] {
      return [esc(field.id), esc(field.type),
        field.filter ? esc('yes') : esc('no'),
        field.sort ? esc('yes') : esc('no'),
        field.group ? esc('yes') : esc('no')];
    });
    this.paint('<p><a href="' + esc(BASE + '/query?source=' + src.id) +
      '">' + esc(this.t.text('report.newQuery')) + '</a></p>' +
      '<h2>' + esc(src.id) + '</h2>' +
      tableHtml([
        esc(this.t.text('report.fields')),
        esc(this.t.text('report.format')),
        esc(this.t.text('report.filter')),
        esc(this.t.text('report.sort')),
        esc(this.t.text('report.groupBy'))
      ], rows));
  }

  /**
   * Draws the query form.
   *
   * @param sourceId - the source, when the address names one
   * @returns nothing
   */
  async drawQuery(sourceId: string): Promise<void> {
    const answer = await this.call('GET', API + '/catalog');
    if (!answer || !answer.json || !answer.json.sources) {
      this.paint(problemHtml(this.t, answer && answer.json &&
        answer.json.error_description));
      return;
    }
    const sources = answer.json.sources;
    const current = sourceId || (sources[0] && sources[0].id) || '';
    let fields: any[] = [];
    sources.forEach(function (src: any): void {
      if (src.id === current) {
        fields = src.fields || [];
      }
    });
    const self = this;
    const options = sources.map(function (src: any): string {
      return '<option value="' + esc(src.id) + '"' +
        (src.id === current ? ' selected' : '') + '>' + esc(src.id) +
        '</option>';
    }).join('');
    const checks = fields.map(function (field: any): string {
      return '<label><input type="checkbox" name="field" value="' +
        esc(field.id) + '" checked> ' + esc(field.id) + '</label>';
    }).join(' ');
    const fieldOptions = '<option value=""></option>' +
      fields.map(function (field: any): string {
        return '<option value="' + esc(field.id) + '">' + esc(field.id) +
          '</option>';
      }).join('');
    let filters = '';
    for (let n = 0; n < 3; n++) {
      filters = filters + '<div class="row"><select name="filterField' + n +
        '">' + fieldOptions + '</select><select name="filterOp' + n + '">' +
        '<option value=""></option>' +
        '<option value="eq">eq</option><option value="ne">ne</option>' +
        '<option value="contains">contains</option>' +
        '<option value="startsWith">startsWith</option>' +
        '<option value="lt">lt</option><option value="le">le</option>' +
        '<option value="gt">gt</option><option value="ge">ge</option>' +
        '<option value="isNull">isNull</option></select>' +
        '<input name="filterValue' + n + '"></div>';
    }
    this.paint('<form class="query-form" data-form="query">' +
      '<div class="field"><label>' + esc(self.t.text('report.source')) +
      '</label><select name="source">' + options + '</select></div>' +
      '<div class="field"><label>' + esc(self.t.text('report.fields')) +
      '</label><div class="row">' + checks + '</div></div>' +
      '<div class="field"><label>' + esc(self.t.text('report.filter')) +
      '</label>' + filters + '</div>' +
      '<div class="field"><label>' + esc(self.t.text('report.sort')) +
      '</label><div class="row"><select name="sortField">' + fieldOptions +
      '</select><select name="sortDir"><option value="asc">' +
      esc(self.t.text('report.ascending')) + '</option><option value="desc">' +
      esc(self.t.text('report.descending')) + '</option></select></div></div>' +
      '<div class="field"><label>' + esc(self.t.text('report.limit')) +
      '</label><input name="limit" value="100"></div>' +
      '<div class="field"><label>' + esc(self.t.text('report.format')) +
      '</label><select name="format"><option value="json">' +
      esc(self.t.text('report.json')) + '</option><option value="csv">' +
      esc(self.t.text('report.csv')) + '</option><option value="pdf">' +
      esc(self.t.text('report.pdf')) + '</option></select></div>' +
      '<div class="field"><label><input type="checkbox" name="counted"> ' +
      esc(self.t.text('report.count')) + '</label>' +
      '<select name="groupBy">' + fieldOptions + '</select> ' +
      esc(self.t.text('report.groupBy')) + '</div>' +
      '<div class="field"><label>' + esc(self.t.text('report.name')) +
      '</label><input name="definitionName"></div>' +
      '<div class="actions"><button type="submit" class="btn" ' +
      'name="intent" value="run">' + esc(self.t.text('report.run')) +
      '</button><button type="submit" class="btn" name="intent" ' +
      'value="save">' + esc(self.t.text('report.save')) + '</button></div>' +
      '<p class="sub" id="report-note"></p></form>');
  }

  /**
   * Draws the definitions.
   *
   * @returns nothing
   */
  async drawDefinitions(): Promise<void> {
    const answer = await this.call('GET', API + '/definitions');
    if (!answer) {
      return;
    }
    const list = answer.json && answer.json.definitions;
    if (!list) {
      this.paint(problemHtml(this.t, answer.json &&
        answer.json.error_description));
      return;
    }
    if (!list.length) {
      this.paint('<p class="sub">' + esc(this.t.text('report.empty')) +
        '</p>');
      return;
    }
    const rows = list.map(function (row: any): string[] {
      return ['<a href="' + esc(BASE + '/definitions/' + row.id) + '">' +
        esc(row.name) + '</a>', esc(row.owner), esc(row.schedule || '')];
    });
    this.paint(tableHtml([
      esc(this.t.text('report.name')),
      esc(this.t.text('report.owner')),
      esc(this.t.text('report.schedule'))
    ], rows));
  }

  /**
   * Draws one definition.
   *
   * @param id - the definition id
   * @returns nothing
   */
  async drawDefinition(id: string): Promise<void> {
    const answer = await this.call('GET', API + '/definitions/' +
      encodeURIComponent(id));
    if (!answer) {
      return;
    }
    const row = answer.json && answer.json.definition;
    if (!row) {
      this.paint(problemHtml(this.t, answer.json &&
        answer.json.error_description));
      return;
    }
    const groups = (row.groups || []).join('\n');
    let editor = '';
    if (row.editable) {
      editor = '<form data-form="definition" data-id="' + esc(row.id) + '">' +
        '<div class="field"><label>' + esc(this.t.text('report.name')) +
        '</label><input name="name" value="' + esc(row.name) + '"></div>' +
        '<div class="field"><label>' + esc(this.t.text('report.schedule')) +
        '</label><input name="schedule" value="' + esc(row.schedule || '') +
        '"></div>' +
        '<div class="field"><label><input type="checkbox" name="enabled"' +
        (row.scheduleEnabled ? ' checked' : '') + '> ' +
        esc(this.t.text('report.enabled')) + '</label></div>' +
        '<div class="field"><label><input type="checkbox" name="notify"' +
        (row.notify ? ' checked' : '') + '> ' +
        esc(this.t.text('report.notify')) + '</label></div>' +
        '<div class="actions"><button class="btn" type="submit">' +
        esc(this.t.text('report.save')) + '</button>' +
        '<button class="btn" type="button" data-act="delete" data-id="' +
        esc(row.id) + '">' + esc(this.t.text('report.cancel')) +
        '</button></div></form>' +
        '<form data-form="share" data-id="' + esc(row.id) + '">' +
        '<div class="field"><label>' + esc(this.t.text('report.groups')) +
        '</label><textarea name="groups">' + esc(groups) +
        '</textarea></div>' +
        '<button class="btn" type="submit">' +
        esc(this.t.text('report.share')) + '</button></form>';
    }
    this.paint('<h2>' + esc(row.name) + '</h2><p>' +
      esc(this.t.text('report.owner')) + ' ' + esc(row.owner) + '</p>' +
      '<form data-form="run" data-id="' + esc(row.id) + '">' +
      '<div class="field"><label>' +
      esc(this.t.text('report.parameters')) +
      '</label><textarea name="parameters"></textarea></div>' +
      '<button class="btn" type="submit">' +
      esc(this.t.text('report.run')) + '</button></form>' + editor);
  }

  /**
   * Draws the jobs.
   *
   * @returns nothing
   */
  async drawJobs(): Promise<void> {
    const answer = await this.call('GET', API + '/jobs');
    if (!answer) {
      return;
    }
    const list = answer.json && answer.json.jobs;
    if (!list) {
      this.paint(problemHtml(this.t, answer.json &&
        answer.json.error_description));
      return;
    }
    if (!list.length) {
      this.paint('<p class="sub">' + esc(this.t.text('report.empty')) +
        '</p>');
      return;
    }
    const self = this;
    const rows = list.map(function (job: any): string[] {
      return ['<a href="' + esc(BASE + '/jobs/' + job.id) + '">' +
        esc(job.id) + '</a>', statusWord(self.t, job.status),
        formatWord(self.t, job.format), esc(job.submittedAt || '')];
    });
    this.paint(tableHtml([
      esc(this.t.text('report.jobs')),
      esc(this.t.text('report.status')),
      esc(this.t.text('report.format')),
      esc(this.t.text('report.result'))
    ], rows));
  }

  /**
   * Draws one job.
   *
   * @param id - the job id
   * @returns nothing
   */
  async drawJob(id: string): Promise<void> {
    const answer = await this.call('GET', API + '/jobs/' +
      encodeURIComponent(id));
    if (!answer) {
      return;
    }
    const job = answer.json && answer.json.job;
    if (!job) {
      this.paint(problemHtml(this.t, answer.json &&
        answer.json.error_description));
      return;
    }
    let download = '';
    if (job.status === 'completed') {
      download = '<button type="button" class="btn" data-act="download" ' +
        'data-id="' + esc(job.id) + '" data-format="' + esc(job.format) +
        '">' + esc(this.t.text('report.download')) + '</button>';
    }
    this.paint('<h2>' + esc(job.id) + '</h2><p>' +
      esc(this.t.text('report.status')) + ' ' +
      statusWord(this.t, job.status) + '</p><p>' +
      esc(this.t.text('report.format')) + ' ' +
      formatWord(this.t, job.format) + '</p>' +
      (job.error ? problemHtml(this.t, job.error) : '') +
      '<p>' + download + '</p><p id="report-note"></p>');
  }

  /**
   * Saves the bytes of a result as a download. The address is not a link:
   * the request has to carry the DPoP proof.
   *
   * @param id - the job id
   * @param format - the file extension
   * @returns nothing
   */
  async download(id: string, format: string): Promise<void> {
    const answer = await this.call('GET', API + '/jobs/' +
      encodeURIComponent(id) + '/result');
    if (!answer) {
      return;
    }
    if (answer.status !== 200 || !answer.bytes) {
      const note = this.env.document.getElementById('report-note');
      if (note) {
        note.textContent = (answer.json && answer.json.error_description) ||
          this.t.text('report.error');
      }
      return;
    }
    const blob = new Blob([answer.bytes], {
      type: answer.media || 'application/octet-stream'
    });
    const href = this.env.window.URL.createObjectURL(blob);
    const link = this.env.document.createElement('a');
    link.href = href;
    link.download = 'report.' + (format || 'bin');
    this.env.document.body.appendChild(link);
    link.click();
    link.remove();
  }

  /**
   * Shows a synchronous body or follows an accepted job.
   *
   * @param answer - `call()`'s answer
   * @returns nothing
   */
  showRun(answer: any): void {
    if (!answer) {
      return;
    }
    if (answer.status === 202 && answer.json && answer.json.job) {
      this.env.history.pushState(null, '', this.prefix + BASE + '/jobs/' +
        answer.json.job.id);
      this.route();
      return;
    }
    if (answer.json && answer.json.rows) {
      const fields = answer.json.fields || [];
      const rows = (answer.json.rows || []).slice(0, 50).map(
        function (row: any): string[] {
          return fields.map(function (field: string): string {
            const value = row[field];
            return esc(value == null ? '' : String(value));
          });
        });
      this.paint(tableHtml(fields.map(esc), rows));
      return;
    }
    if (answer.bytes) {
      const blob = new Blob([answer.bytes], { type: answer.media });
      const href = this.env.window.URL.createObjectURL(blob);
      this.paint('<p><a href="' + esc(href) + '" download="report">' +
        esc(this.t.text('report.download')) + '</a></p>');
      return;
    }
    this.paint(problemHtml(this.t, answer.json &&
      answer.json.error_description));
  }

  /**
   * Draws the page the address names.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    this.prefix = ReportRuntime.prefixOf(this.env.location.pathname);
    await this.ensureLanguage();
    const path = this.reportPath();
    if (path === BASE + '/callback') {
      await this.finishSignIn();
      return;
    }
    if (!this.accessToken) {
      this.paint('<p><button type="button" class="btn" data-act="signin">' +
        esc(this.t.text('report.signIn')) + '</button></p><p class="sub">' +
        esc(this.t.text('report.loading')) + '</p>');
      return;
    }
    await this.hearAccounts();
    const query = SpaClient.queryOf(this.env.location.search);
    if (path === BASE) {
      await this.drawCatalog();
      return;
    }
    if (path.indexOf(BASE + '/sources/') === 0) {
      await this.drawSource(decodeURIComponent(path.slice(
        (BASE + '/sources/').length)));
      return;
    }
    if (path === BASE + '/query') {
      await this.drawQuery(String(query.source || ''));
      return;
    }
    if (path === BASE + '/definitions') {
      await this.drawDefinitions();
      return;
    }
    if (path.indexOf(BASE + '/definitions/') === 0) {
      await this.drawDefinition(decodeURIComponent(path.slice(
        (BASE + '/definitions/').length)));
      return;
    }
    if (path === BASE + '/jobs') {
      await this.drawJobs();
      return;
    }
    if (path.indexOf(BASE + '/jobs/') === 0) {
      await this.drawJob(decodeURIComponent(path.slice(
        (BASE + '/jobs/').length)));
      return;
    }
    this.paint('<p class="sub">' + esc(this.t.text('report.empty')) + '</p>');
  }

  /**
   * Follows a report link without leaving the page, and runs a download
   * or a sign-in.
   *
   * @param event - the click
   * @returns nothing
   */
  onClick(event: any): void {
    const self = this;
    let el = event.target;
    for (let i = 0; el && i < 6; i++) {
      const act = el.getAttribute ? el.getAttribute('data-act') : '';
      if (act === 'refresh') {
        event.preventDefault();
        this.route();
        return;
      }
      if (act === 'signin') {
        event.preventDefault();
        this.beginSignIn(this.here());
        return;
      }
      if (act === 'download') {
        event.preventDefault();
        this.download(String(el.getAttribute('data-id') || ''),
          String(el.getAttribute('data-format') || ''));
        return;
      }
      if (act === 'delete') {
        event.preventDefault();
        const id = String(el.getAttribute('data-id') || '');
        this.call('DELETE', API + '/definitions/' + encodeURIComponent(id))
          .then(function (answer: any): void {
            if (answer && answer.status === 200) {
              self.env.history.pushState(null, '', self.prefix + BASE +
                '/definitions');
              self.route();
            }
          }, function (): void {
            return undefined;
          });
        return;
      }
      if (el.tagName === 'A' && el.getAttribute('href')) {
        const href = String(el.getAttribute('href') || '');
        if (href.indexOf(BASE) === 0) {
          event.preventDefault();
          this.env.history.pushState(null, '', this.prefix + href);
          this.route();
          return;
        }
      }
      el = el.parentElement;
    }
  }

  /**
   * Sends a query, a definition, a share or a run. The language chooser
   * is handled first.
   *
   * @param event - the submit
   * @returns nothing
   */
  onSubmit(event: any): void {
    const self = this;
    if (this.i18n.onSubmit(event, function (): void {
      self.route();
    })) {
      return;
    }
    const form = event.target;
    if (!form || !form.getAttribute) {
      return;
    }
    const kind = String(form.getAttribute('data-form') || '');
    if (!kind) {
      return;
    }
    event.preventDefault();
    if (kind === 'query') {
      const intent = event.submitter && event.submitter.value;
      const document = queryDocument(form);
      if (intent === 'save') {
        this.call('POST', API + '/definitions', {
          name: String((form.elements.definitionName &&
            form.elements.definitionName.value) ||
            this.t.text('report.name')),
          document: document,
          schedule: '',
          scheduleEnabled: false,
          notify: false
        }).then(function (answer: any): void {
          if (answer && answer.json && answer.json.definition) {
            self.env.history.pushState(null, '', self.prefix + BASE +
              '/definitions/' + answer.json.definition.id);
            self.route();
            return;
          }
          self.paint(problemHtml(self.t, answer && answer.json &&
            answer.json.error_description));
        }, function (): void {
          return undefined;
        });
        return;
      }
      this.call('POST', API + '/queries', document).then(
        function (answer: any): void {
          self.showRun(answer);
        }, function (): void {
          return undefined;
        });
      return;
    }
    const id = String(form.getAttribute('data-id') || '');
    if (kind === 'run') {
      let parameters: any = null;
      const raw = String((form.elements.parameters &&
        form.elements.parameters.value) || '').trim();
      if (raw) {
        try {
          parameters = JSON.parse(raw);
        } catch (e) {
          this.paint(problemHtml(this.t, this.t.text('report.error')));
          return;
        }
      }
      this.call('POST', API + '/definitions/' + encodeURIComponent(id) +
        '/run', parameters).then(function (answer: any): void {
        self.showRun(answer);
      }, function (): void {
        return undefined;
      });
      return;
    }
    if (kind === 'share') {
      const groups = String((form.elements.groups &&
        form.elements.groups.value) || '').split(/\n/).map(
        function (line: string): string {
          return line.trim();
        }).filter(function (line: string): boolean {
          return line.length > 0;
        });
      this.call('POST', API + '/definitions/' + encodeURIComponent(id) +
        '/share', { groups: groups }).then(function (): void {
        self.route();
      }, function (): void {
        return undefined;
      });
      return;
    }
    if (kind === 'definition') {
      this.call('GET', API + '/definitions/' + encodeURIComponent(id)).then(
        function (current: any): any {
          const row = current && current.json && current.json.definition;
          if (!row || !row.document) {
            self.paint(problemHtml(self.t, self.t.text('report.error')));
            return null;
          }
          return self.call('POST', API + '/definitions/' +
            encodeURIComponent(id), {
            name: String(form.elements.name.value || ''),
            document: row.document,
            schedule: String(form.elements.schedule.value || ''),
            scheduleEnabled: !!form.elements.enabled.checked,
            notify: !!form.elements.notify.checked
          });
        }).then(function (answer: any): void {
        if (answer) {
          self.route();
        }
      }, function (): void {
        return undefined;
      });
    }
  }

  /**
   * Wires the document and draws the first page.
   *
   * @returns nothing
   */
  async start(): Promise<void> {
    const self = this;
    this.env.document.addEventListener('click', function (event: any): void {
      self.onClick(event);
    });
    this.env.document.addEventListener('submit', function (event: any):
        void {
      self.onSubmit(event);
    });
    if (this.env.window) {
      this.env.window.addEventListener('popstate', function (): void {
        self.prefix = ReportRuntime.prefixOf(self.env.location.pathname);
        self.route();
      });
    }
    await this.route();
  }
}

export = ReportRuntime;
