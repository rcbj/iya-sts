// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: common/csp_reports.ts
// ---------------------------------------------------------------------------
// WHERE A BROWSER TELLS THIS SERVICE ITS CONTENT SECURITY POLICY WAS BROKEN
// (#2164, ASVS 5.0.0 3.4.7; rcbj's decision: a BUILT-IN endpoint).
//
// Every page's policy names this path twice, at the flush in `common/app.js`
// (the same place, and the same guarantee, as `frame-ancestors`):
//
//   * `report-uri <prefix>/web/csp-report` — CSP Level 2. A browser POSTs
//     one `application/csp-report` body per violation.
//   * `report-to csp-endpoint`, with the response header
//     `Reporting-Endpoints: csp-endpoint="<prefix>/web/csp-report"` — CSP
//     Level 3 and the Reporting API. A browser POSTs an
//     `application/reports+json` array, possibly batching several.
//
// A browser that knows `report-to` ignores `report-uri`, so a violation is
// reported once. `<prefix>` is the page's realm prefix: a realm's own
// listener answers only that realm's paths (`common/app.js`, STS-TLS-0041),
// and the report is counted in the realm it arrives in. The path is under
// `/web`, which every listener and every hosted listener answers
// (`common/hosted_applications.js`), and it is root-relative, so the report
// always goes to the page's own origin. `connect-src` does not govern report
// delivery (CSP3 section 5.5), so no page's policy has to widen for it.
//
// THE ENDPOINT TRUSTS NOTHING IT IS SENT. A browser sends no credential with
// a report and anybody can post one, so:
//
//   * a body is at most MAX_BODY_BYTES, read here before the service's own
//     parsers (whose limit is 5 MB) see it, and a `Content-Encoding` is
//     refused rather than inflated;
//   * each address may send PER_ADDRESS_PER_WINDOW reports a WINDOW_MS, in
//     this process's own table (MAX_ADDRESSES rows, the oldest dropped at
//     the insert, an expired row replaced at the read — no timer). It is not
//     `websecurity.ts`'s limiter on purpose: that one writes every count to
//     the shared store and logs every refusal, and a flood of unauthenticated
//     reports must cost neither;
//   * nothing of the body is answered (204, or a refusal with no body), and
//     what is recorded is chosen, never copied: the directive (a known
//     shape, else `unknown`), the document's PATH (the query and the
//     fragment, which can carry a code or a token, are dropped), the blocked
//     resource's ORIGIN or its CSP keyword (`inline`, `eval`, …) and the
//     disposition. `sample`, `source-file`, `original-policy` and the
//     referrer are never recorded.
//
// Each report is a log line under STS-HTTP-0027 and a count per realm and
// directive in a small in-memory table (`realms.map()`, at most
// MAX_DIRECTIVES directives a realm, the rest counted as `other`), drawn by
// Monitoring > CSP reports (`GET /admin-api/csp-reports`).
//
// THE FRONT PROCESS ANSWERS BOTH (`request_pool.js`'s NEVER_DISPATCHED): the
// counts and the limiter are this process's, so the report and the read of
// it must land in the same one. In a cluster each node counts its own.
//
// FORWARDING, OFF BY DEFAULT: `cspReports.forwardUrl`, a per-process setting
// only a service administrator may write, names a collector each accepted
// report is POSTed to as the same record the log line carries, never the
// body as it arrived. It is dialled through `federation_http.ts`'s
// `requestConfigured()` — the URL is an administrator's, never a caller's
// (`federation/CLAUDE.md`), and the kill switch, the outbound TLS policy, no
// redirect, the body cap and the timeout apply. At most MAX_IN_FLIGHT are
// outstanding; a report past that is not forwarded (counted on the page). A
// failure is logged when the collector starts failing (STS-HTTP-0031), not
// per report.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import config = require('./config');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

type Json = any;

const log = helpers.log;

/** The path, below a realm's prefix, every page's policy reports to. */
const PATH = '/web/csp-report';
/** The Reporting API endpoint name `report-to` names. */
const GROUP = 'csp-endpoint';
/** The console page that draws the counts. */
const PAGE = '/admin/csp-reports';
/** The largest body read. A browser's report is a few hundred bytes. */
const MAX_BODY_BYTES = 16 * 1024;
/** Reports one address may send in a window. */
const PER_ADDRESS_PER_WINDOW = 60;
/** The window, in milliseconds. */
const WINDOW_MS = 60 * 1000;
/** Rows in the limiter's table before the oldest are dropped. */
const MAX_ADDRESSES = 10000;
/** Reports in one Reporting API batch that are looked at. */
const MAX_BATCH = 32;
/** Distinct directives counted a realm; the rest are `other`. */
const MAX_DIRECTIVES = 64;
/** Forwards outstanding at once. */
const MAX_IN_FLIGHT = 8;

// The content types a report arrives as. `application/json` too: a
// Reporting API polyfill and some older browsers send it.
const REPORT_TYPES =
  /^\s*application\/(?:csp-report|reports\+json|json)\s*(?:;|$)/i;
// A directive name: CSP's grammar is ALPHA / DIGIT / "-".
const DIRECTIVE_NAME = /^[a-z][a-z0-9-]{0,39}$/;
// A blocked-uri that is a keyword rather than a URL (CSP3 section 5.3).
const KEYWORD = /^[a-z][a-z0-9-]{0,31}$/;

interface Bucket {
  count: number;
  until: number;
}

/** What is recorded of one report: chosen members, never the body. */
interface Recorded {
  realm: string;
  directive: string;
  documentPath: string;
  blocked: string;
  disposition: string;
}

interface CspReportsDeps {
  config: typeof config;
  realms: typeof realms;
  now: () => number;
  addressOf: (req: Json) => string;
  dial: (url: string, options: Json) => Promise<Json>;
}

/**
 * The built-in Content Security Policy report endpoint (#2164): the
 * directives every page carries, the endpoint that receives what browsers
 * send, its counts and its optional forward.
 */
class CspReports {
  // The limiter's table: address → window. Per process, see the header.
  private readonly buckets: Map<string, Bucket> = new Map();
  // Per realm: directive → { count, lastAt }.
  private readonly counts = realms.map();
  private readonly startedAt: number;
  private inFlight = 0;
  private notForwarded = 0;
  private forwardFailing = false;

  constructor(private readonly deps: CspReportsDeps) {
    this.startedAt = deps.now();
  }

  /**
   * The module's production collaborators.
   *
   * @returns the dependencies
   */
  static defaultDeps(): CspReportsDeps {
    log.debug("Entering CspReports.defaultDeps().");
    log.debug("Leaving CspReports.defaultDeps().");
    return {
      config: config,
      realms: realms,
      now: Date.now,
      addressOf: function addressOf(req: Json): string {
        log.debug("Entering addressOf().");
        const address = String(require('./client_address')
          .clientAddressOf(req) || '');
        log.debug("Leaving addressOf().");
        return address;
      },
      // Lazily: federation_http requires much of the service, and is needed
      // only when an administrator turned forwarding on.
      dial: function dial(url: string, options: Json): Promise<Json> {
        log.debug("Entering dial().");
        log.debug("Leaving dial().");
        return require('../federation/federation_http')
          .requestConfigured(url, options);
      }
    };
  }

  /**
   * The report path in a realm.
   *
   * @param prefix - the realm's path prefix, `''` in the default realm
   * @returns the root-relative path
   */
  // Hot path: every page's flush. No Entering/Leaving pair — one would
  // drown the log.
  static pathFor(prefix: string): string {
    return String(prefix || '') + PATH;
  }

  /**
   * The two directives a page's policy gains.
   *
   * @param prefix - the realm's path prefix
   * @returns `report-uri …; report-to csp-endpoint`
   */
  // Hot path: every page's flush.
  static directives(prefix: string): string {
    return 'report-uri ' + CspReports.pathFor(prefix) + '; report-to ' + GROUP;
  }

  /**
   * The `Reporting-Endpoints` header value (Reporting API, section 3.2).
   *
   * @param prefix - the realm's path prefix
   * @returns `csp-endpoint="…"`
   */
  // Hot path: every page's flush.
  static reportingEndpoints(prefix: string): string {
    return GROUP + '="' + CspReports.pathFor(prefix) + '"';
  }

  /**
   * Counts one report against an address, and says whether it is within the
   * limit. An expired window is replaced here, at the read; the table is
   * capped here, at the insert.
   *
   * @param address - the caller's address
   * @returns true when the report may be read
   */
  allowed(address: string): boolean {
    log.debug("Entering CspReports.allowed().");
    const now = this.deps.now();
    const key = String(address || 'unknown');
    const row = this.buckets.get(key);
    if (!row || row.until <= now) {
      if (!row && this.buckets.size >= MAX_ADDRESSES) {
        const oldest = this.buckets.keys().next();
        if (!oldest.done) {
          this.buckets.delete(oldest.value);
        }
      }
      this.buckets.delete(key);
      this.buckets.set(key, { count: 1, until: now + WINDOW_MS });
      log.debug("Leaving CspReports.allowed(). A new window.");
      return true;
    }
    row.count += 1;
    log.debug("Leaving CspReports.allowed(). " + row.count + ".");
    return row.count <= PER_ADDRESS_PER_WINDOW;
  }

  /**
   * Reads a report's body before the service's own parsers do: the limit, the
   * size cap and the encoding are decided here, and a refusal is answered
   * here, with no body. On success `req.body` is the text and the parsers
   * leave it alone.
   *
   * @param req - the request
   * @param res - the response
   * @param next - the next middleware
   */
  intake(req: Json, res: Json, next: () => void): void {
    log.debug("Entering CspReports.intake().");
    if (req.method !== 'POST') {
      log.debug("Leaving CspReports.intake(). Not a POST.");
      next();
      return;
    }
    const refuse = function (status: number, code: string): void {
      log.debug("Entering refuse().");
      errorCodes.mark(res, code);
      res.statusCode = status;
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Connection', 'close');
      res.end();
      log.debug("Leaving refuse().");
    };
    if (!this.allowed(this.deps.addressOf(req))) {
      res.setHeader('Retry-After', String(Math.ceil(WINDOW_MS / 1000)));
      refuse(429, 'STS-HTTP-0029');
      req.resume();
      log.debug("Leaving CspReports.intake(). Over the limit.");
      return;
    }
    const encoding = String(req.headers['content-encoding'] || 'identity')
      .trim().toLowerCase();
    if (encoding !== 'identity' ||
        !REPORT_TYPES.test(String(req.headers['content-type'] || ''))) {
      refuse(415, 'STS-HTTP-0030');
      req.resume();
      log.debug("Leaving CspReports.intake(). Not a report's type.");
      return;
    }
    const declared = Number(req.headers['content-length']);
    if (isFinite(declared) && declared > MAX_BODY_BYTES) {
      refuse(413, 'STS-HTTP-0028');
      req.resume();
      log.debug("Leaving CspReports.intake(). Declared too large.");
      return;
    }
    const chunks: Buffer[] = [];
    let bytes = 0;
    let over = false;
    req.on('data', function (chunk: Buffer): void {
      if (over) {
        return;
      }
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        over = true;
        refuse(413, 'STS-HTTP-0028');
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', function (): void {
      log.debug("Entering the report body's end.");
      if (over) {
        log.debug("Leaving the report body's end. Too large.");
        return;
      }
      const buffer = Buffer.concat(chunks);
      req.rawBody = buffer;
      req.body = buffer.toString('utf8');
      req._body = true;
      log.debug("Leaving the report body's end.");
      next();
    });
    log.debug("Leaving CspReports.intake(). Reading.");
  }

  /**
   * A directive name as recorded: the first token of what the browser named,
   * if it has a directive's shape, else `unknown`.
   *
   * @param raw - `effective-directive`, `violated-directive` or
   *   `effectiveDirective`
   * @returns the name
   */
  static directiveOf(raw: unknown): string {
    log.debug("Entering CspReports.directiveOf().");
    const first = String(raw == null ? '' : raw).trim().split(/\s+/)[0]
      .toLowerCase();
    log.debug("Leaving CspReports.directiveOf().");
    return DIRECTIVE_NAME.test(first) ? first : 'unknown';
  }

  /**
   * A document's address as recorded: its path, with the query and the
   * fragment dropped, at most 256 characters.
   *
   * @param raw - `document-uri` or `documentURL`
   * @returns the path, or `''` when it is not an http(s) URL
   */
  static documentPathOf(raw: unknown): string {
    log.debug("Entering CspReports.documentPathOf().");
    let path = '';
    try {
      const url = new URL(String(raw == null ? '' : raw));
      path = /^https?:$/.test(url.protocol) ? url.pathname : '';
    } catch (e) {
      log.debug("Caught in CspReports.documentPathOf(): " +
                ((e && e.message) || e));
      path = '';
    }
    log.debug("Leaving CspReports.documentPathOf().");
    return path.slice(0, 256);
  }

  /**
   * What was blocked, as recorded: a URL's origin (never its path or query),
   * a CSP keyword such as `inline` or `eval`, or `other`.
   *
   * @param raw - `blocked-uri` or `blockedURL`
   * @returns the origin or keyword
   */
  static blockedOf(raw: unknown): string {
    log.debug("Entering CspReports.blockedOf().");
    const text = String(raw == null ? '' : raw).trim();
    if (!text) {
      log.debug("Leaving CspReports.blockedOf(). None.");
      return 'none';
    }
    if (KEYWORD.test(text)) {
      log.debug("Leaving CspReports.blockedOf(). A keyword.");
      return text;
    }
    let origin = 'other';
    try {
      const url = new URL(text);
      if (url.origin && url.origin !== 'null') {
        origin = url.origin;
      } else if (KEYWORD.test(url.protocol.replace(/:$/, ''))) {
        // data:, blob:, … — the scheme alone.
        origin = url.protocol.replace(/:$/, '');
      }
    } catch (e) {
      log.debug("Caught in CspReports.blockedOf(): " +
                ((e && e.message) || e));
      origin = 'other';
    }
    log.debug("Leaving CspReports.blockedOf().");
    return origin.slice(0, 256);
  }

  /**
   * Reads a body as reports: one CSP Level 2 `csp-report` object, or a
   * Reporting API array whose `csp-violation` entries are taken (at most
   * MAX_BATCH looked at). Anything else is no report.
   *
   * @param text - the body
   * @returns what is recorded of each, in the ambient realm
   */
  parse(text: unknown): Recorded[] {
    log.debug("Entering CspReports.parse().");
    let parsed: Json = null;
    try {
      parsed = JSON.parse(String(text == null ? '' : text));
    } catch (e) {
      log.debug("Caught in CspReports.parse(): " + ((e && e.message) || e));
      parsed = null;
    }
    const realm = String(this.deps.realms.currentId() || 'default');
    const out: Recorded[] = [];
    if (parsed && !Array.isArray(parsed) && typeof parsed === 'object' &&
        parsed['csp-report'] && typeof parsed['csp-report'] === 'object') {
      const one = parsed['csp-report'];
      out.push({
        realm: realm,
        directive: CspReports.directiveOf(one['effective-directive'] ||
                                          one['violated-directive']),
        documentPath: CspReports.documentPathOf(one['document-uri']),
        blocked: CspReports.blockedOf(one['blocked-uri']),
        disposition: one.disposition === 'report' ? 'report' : 'enforce'
      });
    } else if (Array.isArray(parsed)) {
      parsed.slice(0, MAX_BATCH).forEach(function (entry: Json): void {
        if (!entry || typeof entry !== 'object' ||
            entry.type !== 'csp-violation' || !entry.body ||
            typeof entry.body !== 'object') {
          return;
        }
        const body = entry.body;
        out.push({
          realm: realm,
          directive: CspReports.directiveOf(body.effectiveDirective),
          documentPath: CspReports.documentPathOf(body.documentURL ||
                                                  entry.url),
          blocked: CspReports.blockedOf(body.blockedURL),
          disposition: body.disposition === 'report' ? 'report' : 'enforce'
        });
      });
    }
    log.debug("Leaving CspReports.parse(). " + out.length + " report(s).");
    return out;
  }

  /**
   * Counts one report in its realm's table.
   *
   * @param one - what is recorded of it
   */
  count(one: Recorded): void {
    log.debug("Entering CspReports.count().");
    const table = this.counts;
    const key = table.has(one.directive) || table.size < MAX_DIRECTIVES
      ? one.directive : 'other';
    const row = table.get(key) || { count: 0, lastAt: 0 };
    row.count += 1;
    row.lastAt = this.deps.now();
    table.set(key, row);
    log.debug("Leaving CspReports.count().");
  }

  /**
   * Records one report: the log line and the count, then the forward.
   *
   * @param one - what is recorded of it
   */
  record(one: Recorded): void {
    log.debug("Entering CspReports.record().");
    log.warn(errorCodes.tag('STS-HTTP-0027') + 'csp-report: realm=' +
             one.realm + ' directive=' + one.directive + ' document=' +
             JSON.stringify(one.documentPath) + ' blocked=' +
             JSON.stringify(one.blocked) + ' disposition=' + one.disposition);
    this.count(one);
    this.forward(one);
    log.debug("Leaving CspReports.record().");
  }

  /**
   * Sends one recorded report to `cspReports.forwardUrl`, when it is set.
   * Never throws and is not awaited.
   *
   * @param one - what is recorded of it
   */
  forward(one: Recorded): void {
    log.debug("Entering CspReports.forward().");
    const self = this;
    const url = String(this.deps.config.value('cspReports.forwardUrl') || '')
      .trim();
    if (!url) {
      log.debug("Leaving CspReports.forward(). Off.");
      return;
    }
    if (this.inFlight >= MAX_IN_FLIGHT) {
      this.notForwarded += 1;
      log.debug("Leaving CspReports.forward(). Too many outstanding.");
      return;
    }
    this.inFlight += 1;
    const body = JSON.stringify(Object.assign({ type: 'csp-violation',
      at: new Date(this.deps.now()).toISOString() }, one));
    const settle = function (ok: boolean, why: string): void {
      log.debug("Entering settle().");
      self.inFlight -= 1;
      if (!ok && !self.forwardFailing) {
        log.warn(errorCodes.tag('STS-HTTP-0031') + 'csp-report: a ' +
                 'report could not be forwarded to cspReports.forwardUrl (' +
                 why + '). Logged once until a forward succeeds.');
      }
      if (ok && self.forwardFailing) {
        log.info('csp-report: forwarding to cspReports.forwardUrl ' +
                 'succeeds again.');
      }
      self.forwardFailing = !ok;
      log.debug("Leaving settle().");
    };
    this.deps.dial(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body,
      timeoutMs: 5000
    }).then(function (answer: Json): void {
      const ok = !!(answer && answer.status >= 200 && answer.status < 300);
      settle(ok, ok ? '' : String((answer && (answer.why ||
        ('it answered ' + answer.status))) || 'no answer'));
    }, function (e: Json): void {
      log.debug("Caught in CspReports.forward(): " + ((e && e.message) || e));
      settle(false, String((e && e.message) || e));
    });
    log.debug("Leaving CspReports.forward(). Sent.");
  }

  /**
   * The route: records every report the body carries and answers 204 with no
   * body; a body with none is a 400 with no body.
   *
   * @param req - the request, its body read by intake()
   * @param res - the response
   */
  receive(req: Json, res: Json): void {
    log.debug("Entering CspReports.receive().");
    const self = this;
    res.setHeader('Cache-Control', 'no-store');
    const reports = this.parse(req.body);
    if (!reports.length) {
      errorCodes.mark(res, 'STS-HTTP-0030');
      res.status(400).end();
      log.debug("Leaving CspReports.receive(). No report.");
      return;
    }
    reports.forEach(function (one) {
      self.record(one);
    });
    res.status(204).end();
    log.debug("Leaving CspReports.receive().");
  }

  /**
   * What Monitoring > CSP reports and `GET /admin-api/csp-reports` answer:
   * this realm's counts in this process, the endpoint's limits and whether
   * reports are forwarded. The management API adds the page's settings.
   *
   * @returns the view
   */
  view(): Json {
    log.debug("Entering CspReports.view().");
    const rows: Json[] = [];
    let total = 0;
    this.counts.forEach(function (row: Json, directive: string): void {
      total += row.count;
      rows.push({ directive: directive, count: row.count,
                  lastAt: new Date(row.lastAt).toISOString() });
    });
    rows.sort(function (a: Json, b: Json): number {
      return b.count - a.count || (a.directive < b.directive ? -1 : 1);
    });
    const out: Json = {
      path: CspReports.pathFor(this.deps.realms.currentPrefix()),
      since: new Date(this.startedAt).toISOString(),
      total: total,
      directives: rows,
      maxBodyBytes: MAX_BODY_BYTES,
      perAddressPerMinute: PER_ADDRESS_PER_WINDOW,
      forwarding: !!String(this.deps.config.value('cspReports.forwardUrl') ||
                           '').trim(),
      notForwarded: this.notForwarded
    };
    log.debug("Leaving CspReports.view().");
    return out;
  }

  /**
   * Registers `POST /web/csp-report`. Its body is read by intake(), which
   * `common/app.js` runs ahead of the body parsers.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    log.debug("Entering CspReports.registerRoutes().");
    const self = this;
    app.post(PATH, function (req: Json, res: Json): void {
      self.receive(req, res);
    });
    log.debug("Leaving CspReports.registerRoutes().");
  }

  /**
   * Empties this process's limiter and this realm's counts. For the tests.
   */
  reset(): void {
    log.debug("Entering CspReports.reset().");
    this.buckets.clear();
    this.counts.clear();
    this.notForwarded = 0;
    this.forwardFailing = false;
    log.debug("Leaving CspReports.reset().");
  }
}

const slot = new InstanceSlot<CspReports>(
  'common/csp_reports',
  () => new CspReports(CspReports.defaultDeps()),
  null,
  helpers.log);
slot.buildNowUnlessDeferred();

/**
 * The built-in Content Security Policy report endpoint (#2164).
 * @namespace
 */
export = {
  CspReports: CspReports,
  installInstance: (instance: CspReports): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PATH: PATH,
  GROUP: GROUP,
  PAGE: PAGE,
  MAX_BODY_BYTES: MAX_BODY_BYTES,
  PER_ADDRESS_PER_WINDOW: PER_ADDRESS_PER_WINDOW,
  pathFor: CspReports.pathFor,
  directives: CspReports.directives,
  reportingEndpoints: CspReports.reportingEndpoints,
  registerRoutes: slot.forward('registerRoutes'),
  intake: slot.forward('intake'),
  parse: slot.forward('parse'),
  receive: slot.forward('receive'),
  view: slot.forward('view'),
  reset: slot.forward('reset')
};
