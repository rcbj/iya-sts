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
//
// The account control is the console's menu (`admin-ui/web_shell.ts`), not
// `WebAccounts.controlHtml()`. That control lists every live account in
// the document flow. This one names the account this tab is, and offers
// the browser's other signed-in accounts as a switch.
// ---------------------------------------------------------------------------

import SpaClient = require('../common/web_spa_client');
import WebI18n = require('../common/web_i18n');
import WebAccounts = require('../common/web_accounts');
import WebMessages = require('../common/web_messages');
import DocLinks = require('../common/web_doc_links');

const CLIENT_ID = 'sts-report';
const SCOPE = 'openid profile email offline_access report:use report:admin';
const BASE = '/report';
const API = '/report-api';
const SIGNIN_KEY = 'sts-report-pkce';
const ACCOUNTS_ID = 'sts-report-accounts';
const REFRESH_EARLY = 30;
// The most filter rows the form reads: what an `and` may carry (#986).
const FILTER_ROWS_MAX = 16;
// The documentation page for this application (#986), on the site every
// surface links to (`common/web_doc_links.ts`).
const DOCS_PAGE = 'reporting.html';
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

function navCurrent(path: string, suffix: string): boolean {
  const here = String(path || '');
  if (!suffix) {
    return here === BASE || here.indexOf(BASE + '/sources/') === 0;
  }
  const href = BASE + suffix;
  return here === href || here.indexOf(href + '/') === 0;
}

function navLink(href: string, label: string, current: boolean): string {
  return '<a href="' + esc(href) + '"' +
    (current ? ' aria-current="page"' : '') + '>' + esc(label) +
    '</a>';
}

// Two bars (#986). The top one is smaller and right-justified and holds
// the controls about the reader rather than the pages: the realm field,
// the language chooser and the user menu, which holds Sign out. The bar
// under it is the pages and Refresh.
function navHtml(t: any, realm: string, accounts: string, chooser: string,
                 path: string): string {
  return '<div class="topbar">' + realm + chooser + accounts + '</div>' +
    '<div class="bar"><nav class="nav">' +
    navLink(BASE, t.text('report.catalog'), navCurrent(path, '')) +
    navLink(BASE + '/query', t.text('report.newQuery'),
      navCurrent(path, '/query')) +
    navLink(BASE + '/definitions', t.text('report.definitions'),
      navCurrent(path, '/definitions')) +
    navLink(BASE + '/jobs', t.text('report.jobs'),
      navCurrent(path, '/jobs')) +
    '<button type="button" class="btn" data-act="refresh">' +
    esc(t.text('report.refresh')) + '</button>' +
    '</nav></div>';
}

// One filter row (#986): a field, an operator, a value, and — on the last
// row only — the + that adds the next. The runtime clones the last row for
// the next one, so the options are not kept anywhere else.
function filterRowHtml(t: any, n: number, fieldOptions: string,
                       last: boolean): string {
  return '<div class="row filterrow" data-filter-row="' + n + '">' +
    '<select name="filterField' + n + '">' + fieldOptions + '</select>' +
    '<select name="filterOp' + n + '">' +
    '<option value=""></option>' +
    '<option value="eq">' + esc(t.text('report.opEq')) + '</option>' +
    '<option value="ne">' + esc(t.text('report.opNe')) + '</option>' +
    '<option value="contains">' + esc(t.text('report.opContains')) +
    '</option>' +
    '<option value="startsWith">' + esc(t.text('report.opStartsWith')) +
    '</option>' +
    '<option value="lt">' + esc(t.text('report.opLt')) + '</option>' +
    '<option value="le">' + esc(t.text('report.opLe')) + '</option>' +
    '<option value="gt">' + esc(t.text('report.opGt')) + '</option>' +
    '<option value="ge">' + esc(t.text('report.opGe')) + '</option>' +
    '<option value="isNull">' + esc(t.text('report.opIsNull')) +
    '</option></select>' +
    '<input name="filterValue' + n + '">' +
    (last ? '<button type="button" class="btn addfilter" ' +
      'data-act="add-filter" title="' + esc(t.text('report.addFilter')) +
      '" aria-label="' + esc(t.text('report.addFilter')) + '">+</button>'
      : '') +
    '</div>';
}

// The realm field (#986), on the console's switcher shape
// (`admin-ui/web_shell.ts`, `realmChooser()`): the label, then a select of
// the realms and a Go button where the service has several, or the one
// realm's name where it has not. `view` is `GET /report-api/realms`'s
// answer; nothing is drawn until it has arrived.
function realmHtml(t: any, view: any, path: string): string {
  if (!view || !view.current) {
    return '';
  }
  const current = view.current;
  const list = Array.isArray(view.realms) ? view.realms : [];
  const label = '<label for="realmpick">' +
    esc(t.text('report.trustRealm')) + '</label>';
  if (list.length < 2) {
    return '<div class="realmpick">' + label +
      '<span class="realmname" id="realmpick">' +
      esc(current.name || current.id || '') + '</span></div>';
  }
  const options = list.map(function (realm: any): string {
    return '<option value="' + esc(realm.id) + '"' +
      (realm.id === current.id ? ' selected' : '') + '>' +
      esc(realm.name || realm.id) + '</option>';
  }).join('');
  return '<form class="realmpick" data-form="realm">' + label +
    '<input type="hidden" name="to" value="' + esc(path) + '">' +
    '<div class="realmpickrow">' +
    '<select id="realmpick" name="realm">' + options + '</select>' +
    '<button type="submit" class="btn">' + esc(t.text('report.go')) +
    '</button></div></form>';
}

// The query form's buttons (#986). SAVE IS FIRST IN THE DOCUMENT and drawn
// second: a form submitted with Enter — in the Name box, say — activates
// its DEFAULT button, the first submit button in tree order that is not
// disabled, and until this was so, Enter in the Name box RAN the query
// instead of saving it (rcbj, 2026-10-26: a saved query came back as a
// job's row count). So Save is first, `disabled` as well as `hidden` while
// the Save query box is clear — a hidden button is still a default button;
// a disabled one is not — and `.actions .save-only { order: 2 }` puts it
// after Run for the eye. With the box ticked, Enter saves; Run still runs.
function actionsHtml(t: any): string {
  return '<div class="actions">' +
    '<button type="submit" class="btn save-only" hidden disabled ' +
    'name="intent" value="save">' + esc(t.text('report.save')) +
    '</button>' +
    '<button type="submit" class="btn" name="intent" value="run">' +
    esc(t.text('report.run')) + '</button></div>';
}

// THE SCHEDULE EDITOR (#986). A definition's schedule is a five-field cron
// expression in UTC, and the API keeps it that way; what rcbj refused was
// a free box with no hint of what goes in it. The editor is a date-time
// (`datetime-local`, read as UTC, which the label says) and seven weekday
// boxes, and `scheduleCronOf()` composes the expression: the minute and
// hour from the time; with weekdays ticked, `m h * * d,d` (those days,
// every week); with none, `m h D M *` (that date, every year, which the
// preview says). An empty date is no schedule. `scheduleFieldsOf()` reads
// an expression back into the controls where it can — numeric minute and
// hour, a weekday list, or a numeric day and month — and the expression
// itself is always shown under the controls, so one the editor cannot
// draw (a step, a range, `*` for the minute) is still seen and kept until
// the controls are touched. Weekday names come from Intl in the page's
// language, so they cost no catalog.
const WEEKDAYS = [1, 2, 3, 4, 5, 6, 0];

function pad2(n: number): string {
  return (n < 10 ? '0' : '') + n;
}

function weekdayName(locale: string, dow: number): string {
  // 2026-02-01 is a Sunday; dow 0 is Sunday.
  const date = new Date(Date.UTC(2026, 1, 1 + dow));
  try {
    return new Intl.DateTimeFormat(locale || 'en',
      { weekday: 'short', timeZone: 'UTC' }).format(date);
  } catch (e) {
    return ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][dow];
  }
}

function scheduleFieldsOf(cron: string): any {
  const parts = String(cron || '').trim().split(/\s+/);
  const out: any = { at: '', days: [] as number[] };
  if (parts.length !== 5) {
    return out;
  }
  const minute = /^\d{1,2}$/.test(parts[0]) ? Number(parts[0]) : -1;
  const hour = /^\d{1,2}$/.test(parts[1]) ? Number(parts[1]) : -1;
  if (minute < 0 || hour < 0) {
    return out;
  }
  const now = new Date();
  let day = now.getUTCDate();
  let month = now.getUTCMonth() + 1;
  if (/^\d{1,2}$/.test(parts[2]) && /^\d{1,2}$/.test(parts[3])) {
    day = Number(parts[2]);
    month = Number(parts[3]);
  }
  if (parts[4] !== '*') {
    parts[4].split(',').forEach(function (one: string): void {
      if (/^\d$/.test(one) && Number(one) <= 7) {
        out.days.push(Number(one) === 7 ? 0 : Number(one));
      }
    });
  }
  out.at = now.getUTCFullYear() + '-' + pad2(month) + '-' + pad2(day) +
    'T' + pad2(hour) + ':' + pad2(minute);
  return out;
}

function scheduleCronOf(form: any): string {
  const at = String((form.elements.scheduleAt &&
    form.elements.scheduleAt.value) || '');
  const matched = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(at);
  if (!matched) {
    return '';
  }
  const days: string[] = [];
  const boxes = form.querySelectorAll ?
    form.querySelectorAll('input[name="repeatDay"]:checked') : [];
  for (let i = 0; i < boxes.length; i++) {
    days.push(String(boxes[i].value));
  }
  const minute = String(Number(matched[5]));
  const hour = String(Number(matched[4]));
  if (days.length) {
    return minute + ' ' + hour + ' * * ' + days.join(',');
  }
  return minute + ' ' + hour + ' ' + String(Number(matched[3])) + ' ' +
    String(Number(matched[2])) + ' *';
}

function schedulePreview(t: any, cron: string): string {
  if (!cron) {
    return t.text('report.scheduleNone');
  }
  const fields = scheduleFieldsOf(cron);
  const parts = cron.split(/\s+/);
  if (!fields.at) {
    return t.text('report.scheduleExpression', { cron: cron });
  }
  const time = fields.at.slice(11);
  if (parts[4] !== '*') {
    const names = fields.days.map(function (dow: number): string {
      return weekdayName(t.locale, dow);
    }).join(', ');
    return t.text('report.scheduleWeekly', { time: time, days: names });
  }
  return t.text('report.scheduleYearly', { date: fields.at.slice(0, 10),
    time: time });
}

function scheduleEditorHtml(t: any, cron: string): string {
  const fields = scheduleFieldsOf(cron);
  const boxes = WEEKDAYS.map(function (dow: number): string {
    return '<label class="day"><input type="checkbox" name="repeatDay" ' +
      'value="' + dow + '"' +
      (fields.days.indexOf(dow) >= 0 ? ' checked' : '') + '> ' +
      esc(weekdayName(t.locale, dow)) + '</label>';
  }).join(' ');
  return '<div class="field"><label>' + esc(t.text('report.runAt')) +
    '</label><input type="datetime-local" name="scheduleAt" step="60" ' +
    'value="' + esc(fields.at) + '"></div>' +
    '<div class="field"><label>' + esc(t.text('report.repeatOn')) +
    '</label><div class="row days">' + boxes + '</div></div>' +
    '<p class="sub" data-schedule-preview>' +
    esc(schedulePreview(t, cron)) + '</p>';
}

// Why a query is a job (#986), from the job's `queuedBecause`: one
// sentence per reason the API records, nothing for a job that records
// none (one queued before the field existed).
const BECAUSE: Record<string, string> = {
  'every-person': 'report.because.everyPerson',
  asked: 'report.because.asked',
  limit: 'report.because.limit',
  source: 'report.because.source',
  run: 'report.because.run',
  schedule: 'report.because.schedule'
};

function becauseHtml(t: any, why: any): string {
  const key = BECAUSE[String(why || '')];
  if (!key) {
    return '';
  }
  return '<p class="sub because">' + esc(t.text(key)) + '</p>';
}

// The service version under the card (#986), from the index's `version`.
function footerHtml(t: any, version: any): string {
  if (!version || !version.version) {
    return '';
  }
  return '<p class="foot" title="' + esc(version.buildInfo || '') + '">' +
    esc(t.text('report.version', { version: String(version.version) })) +
    '</p>';
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

// The chosen language is part of the document. A saved definition keeps
// it, and a later run posts parameters only, so the stored document is
// what the job is drawn in. The API does not fill the language in.
function queryDocument(form: any, locale: any): any {
  const source = String((form.elements.source &&
    form.elements.source.value) || '');
  const selected: string[] = [];
  const boxes = form.querySelectorAll('input[name="field"]:checked');
  for (let i = 0; i < boxes.length; i++) {
    selected.push(String(boxes[i].value || ''));
  }
  const filters: any[] = [];
  // As many rows as the form holds (#986): the form starts with one and
  // the + beside the last adds the next, so the reader stops at the first
  // index with no field control rather than at a fixed count.
  for (let n = 0; n < FILTER_ROWS_MAX && form.elements['filterField' + n];
       n++) {
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
  const tag = typeof locale === 'string' ? locale : '';
  if (tag && tag.length <= 35 &&
      /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/.test(tag)) {
    document.locale = tag;
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
  // The index's version and the realms view, read once per load (#986).
  private chrome: any;

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
    this.chrome = null;
  }

  /**
   * The query document a form holds, for a test (#986).
   *
   * @param form - the form
   * @param locale - the language tag, or null
   * @returns the document
   */
  static queryDocument(form: any, locale: any): any {
    return queryDocument(form, locale);
  }

  /**
   * One filter row, for a test (#986).
   *
   * @param t - the translator
   * @param n - the row's index
   * @param fieldOptions - the field options' HTML
   * @param last - whether the row carries the + that adds the next
   * @returns the row's HTML
   */
  static filterRowHtml(t: any, n: number, fieldOptions: string,
                       last: boolean): string {
    return filterRowHtml(t, n, fieldOptions, last);
  }

  /**
   * The realm field, for a test (#986).
   *
   * @param t - the translator
   * @param view - `GET /report-api/realms`'s answer
   * @param path - the page path the switch returns to
   * @returns the field's HTML
   */
  static realmHtml(t: any, view: any, path: string): string {
    return realmHtml(t, view, path);
  }

  /**
   * The two bars, for a test (#986).
   *
   * @param t - the translator
   * @param realm - the realm field's HTML
   * @param accounts - the user menu's HTML
   * @param chooser - the language chooser's HTML
   * @param path - the page path
   * @returns the bars' HTML
   */
  static navHtml(t: any, realm: string, accounts: string, chooser: string,
                 path: string): string {
    return navHtml(t, realm, accounts, chooser, path);
  }

  /**
   * The query form's buttons, for a test (#986).
   *
   * @param t - the translator
   * @returns the buttons' HTML
   */
  static actionsHtml(t: any): string {
    return actionsHtml(t);
  }

  /**
   * The schedule editor, for a test (#986).
   *
   * @param t - the translator
   * @param cron - the definition's cron expression, or ''
   * @returns the editor's HTML
   */
  static scheduleEditorHtml(t: any, cron: string): string {
    return scheduleEditorHtml(t, cron);
  }

  /**
   * The cron expression a definition form holds, for a test (#986).
   *
   * @param form - the form
   * @returns the expression, or '' for no schedule
   */
  static scheduleCronOf(form: any): string {
    return scheduleCronOf(form);
  }

  /**
   * The controls' values for an expression, for a test (#986).
   *
   * @param cron - the expression
   * @returns `{ at, days }`
   */
  static scheduleFieldsOf(cron: string): any {
    return scheduleFieldsOf(cron);
  }

  /**
   * The sentence under the editor, for a test (#986).
   *
   * @param t - the translator
   * @param cron - the expression
   * @returns the sentence
   */
  static schedulePreview(t: any, cron: string): string {
    return schedulePreview(t, cron);
  }

  /**
   * Why a job is a job, for a test (#986).
   *
   * @param t - the translator
   * @param why - the job's `queuedBecause`
   * @returns the sentence's HTML, or ''
   */
  static becauseHtml(t: any, why: any): string {
    return becauseHtml(t, why);
  }

  /**
   * The footer, for a test (#986).
   *
   * @param t - the translator
   * @param version - the index's `version`
   * @returns the footer's HTML
   */
  static footerHtml(t: any, version: any): string {
    return footerHtml(t, version);
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
   * @param extra - `login_hint` and `prompt` for a switch, or nothing
   * @returns the URL
   */
  async authorizeUrl(state: string, verifier: string,
                     extra?: any): Promise<string> {
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
    const hint = this.hintFor(extra);
    if (hint) {
      params.login_hint = hint;
    }
    if (extra && extra.prompt) {
      params.prompt = String(extra.prompt);
    }
    return this.authorizationRequestUrl(params);
  }

  /**
   * Sends the browser to sign in.
   *
   * @param returnTo - where to land afterwards
   * @param extra - for a switch: `login_hint` ('' for none), `prompt`,
   *   `expect` (the subject the answer must be for) and `another`
   * @returns nothing
   */
  async beginSignIn(returnTo: string, extra?: any): Promise<void> {
    const verifier = this.random(32);
    const state = this.random(16);
    const asked = extra || {};
    const record: any = {
      verifier: verifier,
      state: state,
      returnTo: returnTo,
      prefix: this.prefix
    };
    if (asked.expect) {
      record.expect = String(asked.expect);
    }
    if (asked.another) {
      record.another = true;
    }
    this.env.sessionStorage.setItem(SIGNIN_KEY, JSON.stringify(record));
    this.env.location.assign(await this.authorizeUrl(state, verifier,
                                                     asked));
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
    // A switch is for one account. An answer for another subject is not
    // kept, so a reload resumes the account this tab was, by its hint.
    if (saved.expect &&
        !SpaClient.answerIsFor(String(saved.expect),
                               answer.json.id_token)) {
      this.paint(problemHtml(this.t,
        this.t.text('report.accounts.refused')));
      return;
    }
    const before = this.storedAccount();
    this.keepTokens(answer.json);
    this.username = SpaClient.claimOf(answer.json.id_token,
      'preferred_username');
    this.env.history.replaceState(null, '',
      this.prefix + String(saved.returnTo || BASE));
    await this.route();
    if (saved.another || (before && before.sub !== this.subject)) {
      this.announceAccounts('added');
    }
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
    const accounts = ReportRuntime.accountMenu(this);
    const chooser = this.i18n.chooser(this.t, this.here());
    const chrome = this.chrome || {};
    const realm = realmHtml(this.t, chrome.realms, this.here());
    const docs = DocLinks.markup(DocLinks.abs(DOCS_PAGE),
      this.t.text('report.docsLink'));
    const html = '<h1>' + esc(this.t.text('report.title')) + '</h1>' +
      navHtml(this.t, realm, accounts, chooser, this.reportPath()) + docs +
      body + footerHtml(this.t, chrome.version);
    const main = this.env.document.getElementById('report');
    if (main) {
      main.innerHTML = html;
    }
  }

  /**
   * Reads the index (the version) and the realms once per load, after the
   * token is in hand (#986). A failure leaves the chrome without them;
   * nothing else is held up.
   *
   * @returns nothing
   */
  async ensureChrome(): Promise<void> {
    if (this.chrome) {
      return;
    }
    const chrome: any = { version: null, realms: null };
    const index = await this.call('GET', API);
    if (index && index.json) {
      chrome.version = index.json.version || null;
    }
    const realms = await this.call('GET', API + '/realms');
    if (realms && realms.json && realms.json.current) {
      chrome.realms = realms.json;
    }
    this.chrome = chrome;
  }

  /**
   * Opens another realm's reports application at this page (#986). The
   * token in hand belongs to this realm, so the other realm's page signs
   * in as any first load does; the browser leaves this page for it.
   *
   * @param realmId - the realm chosen
   * @param to - the report path and query to open there
   * @returns nothing
   */
  switchRealm(realmId: string, to: string): void {
    const list = (this.chrome && this.chrome.realms &&
      this.chrome.realms.realms) || [];
    const realm = list.filter(function (one: any): boolean {
      return one.id === realmId;
    })[0];
    if (!realm) {
      return;
    }
    const path = String(to || BASE);
    const where = path.indexOf(BASE) === 0 ? path : BASE;
    this.env.location.assign(String(this.env.location.origin || '') +
      String(realm.prefix || '') + where);
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
      self.redrawAccountMenu();
    });
  }

  /**
   * The name of the account this tab is.
   *
   * @param page - the runtime
   * @returns the display name, the username, or the subject
   */
  static accountLabel(page: ReportRuntime): string {
    const current = WebAccounts.bySubject(page.accounts, page.subject);
    const named = current ? WebAccounts.nameOf(current) : '';
    if (named) {
      return named;
    }
    if (page.username) {
      return page.username;
    }
    const kept = page.storedAccount();
    if (kept && kept.username) {
      return String(kept.username);
    }
    return String(page.subject || '');
  }

  /**
   * The account menu: this tab's account, and a switch to the browser's
   * other signed-in accounts. Nothing when several accounts are off.
   *
   * @param page - the runtime
   * @returns the menu's HTML, or ''
   */
  static accountMenu(page: ReportRuntime): string {
    const list = page.accounts;
    const several = !!(list && list.enabled);
    const name = ReportRuntime.accountLabel(page);
    const t = page.t;
    // Drawn for everybody since #986, because Sign out lives here; the
    // switch group still appears only with several accounts on.
    return '<details class="usermenu"><summary title="' +
      esc(several ? t.text('report.accounts.summaryTitle', { user: name })
        : name) + '">' +
      esc(name) + '</summary><div class="usermenupanel">' +
      '<p class="usermenuwho">' +
      t.html('report.accounts.who', { user: name }) + '</p>' +
      (several
        ? '<div id="' + ACCOUNTS_ID + '" class="usermenuaccounts">' +
          ReportRuntime.accountItems(page) + '</div>'
        : '') +
      '<div class="usermenuaccounts usermenusignout">' +
      '<a class="linklike" href="' + esc(page.prefix + '/logout') + '">' +
      esc(t.text('report.signOut')) + '</a></div></div></details>';
  }

  /**
   * The menu's switch group: a button per other signed-in account, or a
   * line saying there is none, then a sign-in as another account.
   *
   * @param page - the runtime
   * @returns the group's HTML
   */
  static accountItems(page: ReportRuntime): string {
    const t = page.t;
    const others = WebAccounts.live(page.accounts).filter(
      function (one: any): boolean {
        return String(one.sub || '') !== String(page.subject || '');
      });
    return '<p class="usermenuwho">' +
      t.html('report.accounts.switch') + '</p>' +
      (others.length
        ? others.map(function (one: any): string {
          const name = WebAccounts.nameOf(one);
          return '<button type="button" class="linklike" ' +
            'data-account-action="switch" data-account-key="' +
            esc(one.key) + '" title="' +
            esc(t.text('report.accounts.switchTitle', { user: name })) +
            '">' + esc(name) +
            (one.username && one.username !== name
              ? ' <span>' + esc(one.username) + '</span>' : '') +
            '</button>';
        }).join('')
        : '<p class="usermenuwho" data-account-none="1">' +
          t.html('report.accounts.none') + '</p>') +
      '<button type="button" class="linklike" ' +
      'data-account-action="another" title="' +
      esc(t.text('report.accounts.anotherTitle')) + '">' +
      t.html('report.accounts.another') + '</button>' +
      '<p class="usermenuwho">' + t.html('report.accounts.kept') + '</p>';
  }

  /**
   * Draws the switch group again, leaving the open menu open.
   *
   * @returns nothing
   */
  redrawAccountMenu(): void {
    const doc = this.env.document;
    const el = doc && doc.getElementById
      ? doc.getElementById(ACCOUNTS_ID) : null;
    if (el) {
      el.innerHTML = ReportRuntime.accountItems(this);
    }
  }

  /**
   * Switches this tab to another signed-in account of the browser.
   *
   * @param key - the account's key, from the menu
   * @returns nothing
   */
  async switchAccount(key: string): Promise<void> {
    const account = WebAccounts.byKey(this.accounts, key);
    if (!account) {
      this.redrawAccountMenu();
      return;
    }
    const back = this.here();
    this.endIdentity();
    this.discardClient();
    try {
      await this.beginSignIn(back, {
        login_hint: String(account.username || account.sub || ''),
        expect: String(account.sub || '')
      });
    } catch (e) {
      // The browser has no logger. The page says the switch did not
      // start, and keeps what the browser reported.
      this.paint(problemHtml(this.t,
        this.t.text('report.accounts.failed') + ' ' +
        String((e && e.message) || e)));
    }
  }

  /**
   * Signs this tab in as another account. The accounts already signed in
   * stay signed in.
   *
   * @returns nothing
   */
  async signInAnother(): Promise<void> {
    const back = this.here();
    this.endIdentity();
    this.discardClient();
    try {
      await this.beginSignIn(back, {
        login_hint: '',
        prompt: 'login',
        another: true
      });
    } catch (e) {
      // The browser has no logger. The page says the sign-in did not
      // start, and keeps what the browser reported.
      this.paint(problemHtml(this.t,
        this.t.text('report.accounts.failed') + ' ' +
        String((e && e.message) || e)));
    }
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
    const yes = esc(this.t.text('report.yes'));
    const no = esc(this.t.text('report.no'));
    const t = this.t;
    // The Indexed column (#985) names the operators the directory answers
    // without reading every row, in the words the filter form uses; a
    // field with none shows a dash. The page explains the column once,
    // and only where a field carries one.
    const opWords: Record<string, string> = {
      eq: 'report.opEq', ne: 'report.opNe', contains: 'report.opContains',
      startsWith: 'report.opStartsWith', in: 'report.opIn',
      lt: 'report.opLt', le: 'report.opLe', gt: 'report.opGt',
      ge: 'report.opGe', isNull: 'report.opIsNull'
    };
    let anyIndexed = false;
    const rows = (src.fields || []).map(function (field: any): string[] {
      const indexed = Array.isArray(field.indexed) ? field.indexed : [];
      if (indexed.length) {
        anyIndexed = true;
      }
      return [esc(field.id), esc(field.type),
        esc(field.meaning || ''),
        field.filter ? yes : no,
        field.sort ? yes : no,
        field.group ? yes : no,
        indexed.length ? esc(indexed.map(function (op: string): string {
          return opWords[op] ? t.text(opWords[op]) : op;
        }).join(', ')) : '&mdash;'];
    });
    const kept = src.retention ? '<p class="sub">' +
      esc(src.retention) + '</p>' : '';
    const indexedNote = anyIndexed ? '<p class="sub">' +
      esc(t.text('report.indexedNote')) + '</p>' : '';
    this.paint('<p><a href="' + esc(BASE + '/query?source=' + src.id) +
      '">' + esc(this.t.text('report.newQuery')) + '</a></p>' +
      '<h2>' + esc(src.id) + '</h2>' + kept + indexedNote +
      tableHtml([
        esc(this.t.text('report.fields')),
        esc(this.t.text('report.type')),
        esc(this.t.text('report.meaning')),
        esc(this.t.text('report.filter')),
        esc(this.t.text('report.sort')),
        esc(this.t.text('report.groupBy')),
        esc(this.t.text('report.indexed'))
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
    // One row to begin with; the + beside it adds the next (#986).
    const filters = filterRowHtml(self.t, 0, fieldOptions, true);
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
      // Save query (#986): the Name field and the Save button appear only
      // once the box is ticked; unticked, the form runs and saves nothing.
      '<div class="field"><label><input type="checkbox" name="saveQuery"> ' +
      esc(self.t.text('report.saveQuery')) + '</label></div>' +
      '<div class="field save-only" hidden><label>' +
      esc(self.t.text('report.name')) +
      '</label><input name="definitionName"></div>' +
      actionsHtml(self.t) +
      '<p class="sub" id="report-note"></p></form>');
  }

  /**
   * Adds a filter row after the last one (#986): the last row is cloned,
   * its controls renamed to the next index and emptied, and the + moves
   * to the new row.
   *
   * @param button - the + pressed
   * @returns nothing
   */
  addFilterRow(button: any): void {
    const row = button && button.closest ? button.closest('.filterrow') :
      null;
    const form = row && row.closest ? row.closest('form') : null;
    if (!row || !form) {
      return;
    }
    const rows = form.querySelectorAll('.filterrow');
    const n = rows.length;
    if (n >= FILTER_ROWS_MAX) {
      return;
    }
    const next = row.cloneNode(true);
    next.setAttribute('data-filter-row', String(n));
    const controls = next.querySelectorAll('select, input');
    for (let i = 0; i < controls.length; i++) {
      const name = String(controls[i].getAttribute('name') || '')
        .replace(/\d+$/, '');
      controls[i].setAttribute('name', name + n);
      if (controls[i].tagName === 'INPUT') {
        controls[i].value = '';
      } else {
        controls[i].selectedIndex = 0;
      }
    }
    const plus = row.querySelector('.addfilter');
    if (plus && plus.parentNode) {
      plus.parentNode.removeChild(plus);
    }
    row.parentNode.insertBefore(next, row.nextSibling);
  }

  /**
   * A control changed (#986): the Save query box shows or hides the Name
   * field and the Save button; the realm select switches realm.
   *
   * @param event - the change
   * @returns nothing
   */
  onChange(event: any): void {
    const el = event.target;
    if (!el || !el.getAttribute) {
      return;
    }
    const name = String(el.getAttribute('name') || '');
    if (name === 'saveQuery') {
      const form = el.closest ? el.closest('form') : null;
      const only = form ? form.querySelectorAll('.save-only') : [];
      for (let i = 0; i < only.length; i++) {
        if (el.checked) {
          only[i].removeAttribute('hidden');
          only[i].removeAttribute('disabled');
        } else {
          only[i].setAttribute('hidden', '');
          // A hidden submit button is still the form's default button;
          // a disabled one is not (see actionsHtml()).
          if (only[i].tagName === 'BUTTON') {
            only[i].setAttribute('disabled', '');
          }
        }
      }
      return;
    }
    if ((name === 'scheduleAt' || name === 'repeatDay') && el.closest) {
      const form = el.closest('form[data-form="definition"]');
      const preview = form ? form.querySelector('[data-schedule-preview]') :
        null;
      if (preview) {
        preview.textContent = schedulePreview(this.t, scheduleCronOf(form));
      }
      return;
    }
    if (name === 'realm' && el.closest &&
        el.closest('form[data-form="realm"]')) {
      const form = el.closest('form');
      const to = form.elements.to ? String(form.elements.to.value) : '';
      this.switchRealm(String(el.value || ''), to);
    }
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
        esc(row.name) + '</a>', esc(row.ownerName || row.owner),
        esc(row.schedule || '')];
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
        '<h3>' + esc(this.t.text('report.schedule')) + '</h3>' +
        scheduleEditorHtml(this.t, String(row.schedule || '')) +
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
      esc(this.t.text('report.owner')) + ' ' +
      esc(row.ownerName || row.owner) + '</p>' +
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
    this.paint('<h2>' + esc(job.id) + '</h2>' +
      becauseHtml(this.t, job.queuedBecause) + '<p>' +
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
    // Opening the application starts the code flow, as the portal and the
    // console do. The token is only in this page's memory, so a fresh
    // load has none, and the catalog is an answer from /report-api.
    // Painting a Sign in button under the word Loading left the page
    // where the shell had already said it was loading.
    if (!this.accessToken) {
      await this.beginSignIn(this.here());
      return;
    }
    await this.hearAccounts();
    await this.ensureChrome();
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
    const asked = this.accounts && this.accounts.enabled
      ? WebAccounts.actionOf(event.target) : null;
    if (asked && (asked.action === 'switch' ||
                  asked.action === 'another')) {
      event.preventDefault();
      if (asked.action === 'switch') {
        this.switchAccount(asked.key);
      } else {
        this.signInAnother();
      }
      return;
    }
    let el = event.target;
    for (let i = 0; el && i < 6; i++) {
      const act = el.getAttribute ? el.getAttribute('data-act') : '';
      if (act === 'refresh') {
        event.preventDefault();
        this.route();
        return;
      }
      if (act === 'add-filter') {
        event.preventDefault();
        this.addFilterRow(el);
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
    if (kind === 'realm') {
      this.switchRealm(String((form.elements.realm &&
        form.elements.realm.value) || ''),
        String((form.elements.to && form.elements.to.value) || ''));
      return;
    }
    if (kind === 'query') {
      const intent = event.submitter && event.submitter.value;
      const document = queryDocument(form, this.t && this.t.locale);
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
            schedule: scheduleCronOf(form),
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
    this.env.document.addEventListener('change', function (event: any):
        void {
      self.onChange(event);
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
