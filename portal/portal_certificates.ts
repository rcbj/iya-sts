// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_certificates.ts — /portal/certificates, WHERE A PERSON GETS
// WHAT ACME AND SCEP NEED TO ISSUE THEM A CERTIFICATE, AND SEES WHAT THEY WERE
// ISSUED (2026-09-13).
//
// ACME and SCEP authenticate with a credential bound to ONE directory entry —
// an External Account Binding key and a single-use challenge password
// (`common/cert_enrollment.ts`). An administrator can make one for anybody on
// `/admin/acme` and `/admin/scep`; this page is where a person makes one for
// THEMSELVES, which is rcbj's rule read from the person's side: *any user can
// only issue key pairs that map to their authenticated user identity*.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md). The form carries no name; every credential
// is created FOR `{ kind: 'person', id: session.user.username }`, and every
// delete, and every revocation, is checked against that same entry — a kid, a
// challenge id or a serial belonging to somebody else matches nothing and is
// answered as though it did not exist, so the page is not an oracle for which
// credentials other people hold.
//
// **A SECRET IS SHOWN ON A 200 AND NEVER ON A REDIRECT** — the HMAC key and
// the challenge password are in the response and nowhere else, with
// `Cache-Control: no-store`, for `/portal/signing-key`'s reason: a secret on a
// query string is a secret in the browser history, the access log and the next
// request's `Referer`.
//
// **IT IS A FILE BESIDE `portal.ts` RATHER THAN MORE OF IT**, and the call is
// `register(context)` rather than a require that registers routes at its top
// level (rule 1), because everything that makes a page a PORTAL page — the
// shell, the navigation column, the sign-in, the CSRF field — is private to
// `portal.ts`. So `portal.ts` hands those over at the one point where the
// route order is right — inside the composite `registerRoutes(app)` it
// exports, after its own routes, which `common/protocol_stack.ts` calls
// (#50, R1) — and this file owns only what is new.
// `portal/CLAUDE.md` records the arrangement.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS CLASSES (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, with one twist that `register(context)` already had:
//
//   * **`PortalCertificates` TAKES THE ENROLLMENT CORE, ITS MONITOR AND
//     node's `crypto` THROUGH ITS CONSTRUCTOR** (`PortalCertificatesDeps`).
//     Its `register(context)` is the old function: it builds a
//     `PortalCertificatesPage` from those and from the portal's CONTEXT —
//     which is that page's second set of dependencies, handed over by the
//     portal as before — and calls its `registerRoutes(app)`, which holds the
//     GET and the POST in their old order.
//   * **THE MODULE STILL EXPORTS `register` AND `REVOCATION_REASONS`**, for
//     the portal: `register` is a FACADE forwarding to the instance the
//     composition root (`common/protocol_stack.ts`) builds (#50's R2), and a
//     process without the root builds a default at load.
//     `PortalCertificates` is exported beside it for that root.
// ---------------------------------------------------------------------------

import stsCrypto = require('../common/crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import core = require('../common/cert_enrollment');
import monitor = require('../common/enrollment_monitor');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over: everything that makes a page a portal page.
interface PortalContext {
  app: {
    get(path: string, handler: (req: Req, res: Res) => unknown): unknown;
    post(path: string, handler: (req: Req, res: Res) => unknown): unknown;
  };
  BASE: string;
  log: {
    debug(message: string): void;
    info(message: string): void;
  };
  esc(value: unknown): string;
  // The portal's translator for a session (#539 phase 3).
  translatorFor(session: Json): any;
  shell(path: string, session: Json, message: unknown, error: unknown,
        body: string): string;
  send(res: Res, status: number, body: string): unknown;
  requireSignIn(req: Req, res: Res, path: string, action: unknown): Json;
  // error-code: none — the portal helper's type, not a call to it.
  refuseShape(res: Res, result: Json): unknown;
  innerCode(result: Json): string;
  baseUrlOf(req: Req): string;
  parseBody(req: Req): Json;
  validation: Json;
  websecurity: Json;
  accessGate: Json;
  audit: Json;
  errorCodes: Json;
  config: { value(key: string): any };
}

interface PortalCertificatesDeps {
  // For the constructor only: a page logs through the portal's context.
  log: { debug(message: string): void };
  core: Json;
  monitor: Json;
  stsCrypto: typeof stsCrypto;
}

// The one-time secret a POST just made.
interface Fresh {
  kind: string;
  kid?: string;
  hmacKey?: string;
  challenge?: string;
  profile?: string;
  expiresAt?: unknown;
}

/**
 * The RFC 5280 revocation reasons a person may give when revoking their own
 * certificate.
 */
const REVOCATION_REASONS = ['unspecified', 'keyCompromise',
                            'affiliationChanged', 'superseded',
                            'cessationOfOperation'];

// One registration's page: the portal's context and the enrollment core.
class PortalCertificatesPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalCertificatesDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalCertificatesPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/certificates';
    this.FORM = vz.object({
      action: vt.opt(vt.oneOf(['create-eab', 'delete-eab', 'create-challenge',
                               'delete-challenge', 'revoke'])),
      kid: vz.string().max(600).regex(/^[A-Za-z0-9_-]*$/).optional(),
      id: vz.string().max(600).regex(/^[A-Za-z0-9_-]*$/).optional(),
      // `device` (#164 phase 2): a SCEP challenge for a device of theirs.
      profile: vt.opt(vt.oneOf(deps.core.PROFILE_IDS.concat(
        [deps.core.DEVICE_PROFILE]))),
      serial: vz.string().max(80).regex(/^[0-9A-Fa-f:]*$/).optional(),
      reason: vt.opt(vt.oneOf(REVOCATION_REASONS)),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional()
    });
    ctx.log.debug("Leaving PortalCertificatesPage.constructor().");
  }

  private selfEntry(session: Json): { kind: string; id: string } {
    const { log } = this.ctx;
    log.debug("Entering PortalCertificatesPage.selfEntry().");
    log.debug("Leaving PortalCertificatesPage.selfEntry().");
    return { kind: 'person', id: String(session.user.username) };
  }

  // A time for a person to read, in the page's language (#539): the
  // translator's date, which is UTC and says so.
  private readable(when: unknown, t: Json): string {
    const { log } = this.ctx;
    log.debug("Entering PortalCertificatesPage.readable().");
    const at = new Date(when as any);
    log.debug("Leaving PortalCertificatesPage.readable().");
    return isNaN(at.getTime()) ? String(when || '') : t.date(at);
  }

  private enabled(family: string): boolean {
    const { log, config } = this.ctx;
    log.debug("Entering PortalCertificatesPage.enabled(). family=" + family);
    log.debug("Leaving PortalCertificatesPage.enabled().");
    return config.value(family + '.enabled') !== false;
  }

  // -------------------------------------------------------------------------
  // THE PAGE. `fresh` is the one-time secret the POST just made, or null.
  // -------------------------------------------------------------------------
  private page(session: Json, base: string, message: unknown, error: unknown,
               fresh: Fresh | null): string {
    const { log, esc, websecurity, shell, BASE } = this.ctx;
    const { core } = this.deps;
    const PATH = this.PATH;
    log.debug("Entering PortalCertificatesPage.page().");
    const entry = this.selfEntry(session);
    const csrf = websecurity.field(session.id);
    // THE LANGUAGE (#539): the portal's translator for this person. The
    // refusal passed in as `error` stays English.
    const t = this.ctx.translatorFor(session);
    const resolved = core.resolveEntry(entry.kind, entry.id);
    const cards: string[] = [];

    if (fresh) {
      cards.push(this.freshCard(fresh, base, t));
    }

    if (!resolved.ok) {
      cards.push('<div class="card"><h2>' +
        t.html('portalCertificates.noEntry.heading') + '</h2><p ' +
        'class="sub">' + t.html('portalCertificates.noEntry.text',
          { name: entry.id }) + '</p></div>');
      log.debug("Leaving PortalCertificatesPage.page(). No entry.");
      return shell(PATH, session, message, error, cards.join(''));
    }

    cards.push(this.certificatesCard(core.enrolledOf(entry), csrf, t));
    if (this.enabled('acme')) {
      cards.push(this.acmeCard(core.eabsOf(entry), csrf, base, t));
    }
    if (this.enabled('est')) {
      cards.push(this.estCard(base, t));
    }
    if (this.enabled('scep')) {
      cards.push(this.scepCard(core.scepChallengesOf(entry), csrf, base, t));
    }
    cards.push(this.hostNamesCard(resolved.hostNames, t));
    // The link is markup a message may not carry (#539), so the sentence is
    // two messages around it.
    cards.push('<div class="card"><h2>' +
      t.html('portalCertificates.other.heading') + '</h2><p ' +
      'class="sub">' + t.html('portalCertificates.other.before') + ' <a ' +
      'href="' + BASE + '/signing-key">' +
      t.html('portalCertificates.other.link') + '</a>' +
      t.html('portalCertificates.other.after') + '</p></div>');
    log.debug("Leaving PortalCertificatesPage.page().");
    return shell(PATH, session, message, error, cards.join(''));
  }

  private freshCard(fresh: Fresh, base: string, t: Json): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalCertificatesPage.freshCard(). kind=" +
              fresh.kind);
    if (fresh.kind === 'eab') {
      const directory = helpers.rebaseTo(base, 'acme') +
                        '/enroll/acme/directory';
      log.debug("Leaving PortalCertificatesPage.freshCard(). EAB.");
      return '<div class="card"><h2>' +
        t.html('portalCertificates.fresh.eabHeading') + '</h2>' +
        '<div class="err">' + t.html('portalCertificates.fresh.eabCopy') +
        '</div>' +
        '<table><tr><th>' + t.html('portalCertificates.fresh.directory') +
        '</th><td><code>' + esc(directory) +
        '</code></td></tr><tr><th>' + t.html('portalCertificates.keyId') +
        '</th><td><code>' + esc(fresh.kid) +
        '</code></td></tr><tr><th>' +
        t.html('portalCertificates.fresh.hmacKey') + '</th><td><code>' +
        esc(fresh.hmacKey) + '</code></td></tr><tr><th>' +
        t.html('portalCertificates.fresh.bindsUntil') + '</th><td>' +
        esc(this.readable(fresh.expiresAt, t)) +
        '</td></tr></table><p class="sub">' +
        t.html('portalCertificates.fresh.example') + '</p><pre class="pem">' +
        esc('certbot certonly --server ' + directory + ' \\\n' +
            '  --eab-kid ' + fresh.kid + ' \\\n' +
            '  --eab-hmac-key ' + fresh.hmacKey + ' ...') + '</pre>' +
        '<p class="note">' + t.html('portalCertificates.fresh.eabNote') +
        '</p></div>';
    }
    log.debug("Leaving PortalCertificatesPage.freshCard(). Challenge.");
    return '<div class="card"><h2>' +
      t.html('portalCertificates.fresh.challengeHeading') + '</h2>' +
      '<div class="err">' + t.html('portalCertificates.fresh.challengeCopy') +
      '</div>' +
      '<table><tr><th>' + t.html('portalCertificates.fresh.scepUrl') +
      '</th><td><code>' +
      esc(helpers.rebaseTo(base, 'scep') +
          '/enroll/scep/' + fresh.profile) + '</code></td></tr>' +
      // The plain-HTTP address too (#210): sscep and most device firmware
      // speak no TLS, and SCEP secures its own messages.
      '<tr><th>' + t.html('portalCertificates.fresh.plainScepUrl') +
      '</th><td><code>' +
      esc(require('../common/pki_revocation').httpBaseInRealm() +
          '/enroll/scep/' + fresh.profile) +
      '</code></td></tr>' +
      '<tr><th>' + t.html('portalCertificates.fresh.challenge') +
      '</th><td><code>' + esc(fresh.challenge) +
      '</code></td></tr><tr><th>' + t.html('portalCertificates.profile') +
      '</th><td><code>' +
      esc(fresh.profile) + '</code></td></tr><tr><th>' +
      t.html('portalCertificates.fresh.usableUntil') + '</th><td>' +
      esc(this.readable(fresh.expiresAt, t)) + '</td></tr></table>' +
      '<p class="note">' + t.html('portalCertificates.fresh.challengeNote') +
      '</p></div>';
  }

  private certificatesCard(records: Json[], csrf: string, t: Json): string {
    const self = this;
    const { log, esc } = this.ctx;
    const { core } = this.deps;
    const PATH = this.PATH;
    log.debug("Entering PortalCertificatesPage.certificatesCard(). " +
              records.length + ".");
    if (!records.length) {
      log.debug("Leaving PortalCertificatesPage.certificatesCard(). None.");
      return '<div class="card"><h2>' +
        t.html('portalCertificates.enrolled.heading') + '</h2><p ' +
        'class="sub">' + t.html('portalCertificates.enrolled.none') +
        '</p></div>';
    }
    const rows = records.map(function (one) {
      const revoke = one.status === 'valid'
        ? '<form method="post" action="' + PATH + '">' + csrf +
          '<input type="hidden" name="action" value="revoke">' +
          '<input type="hidden" name="serial" value="' +
          esc(one.serialHex) + '"><select name="reason" aria-label="' +
          esc(t.text('portalCertificates.enrolled.reason')) + '">' +
          // The reasons are RFC 5280's names, and stay as they are.
          REVOCATION_REASONS.map(function (reason) {
            return '<option value="' + reason + '">' + esc(reason) +
              '</option>';
          }).join('') + '</select> <button class="danger">' +
          t.html('portalCertificates.enrolled.revoke') + '</button>' +
          '</form>'
        : '';
      return '<tr><td>' + esc(core.FAMILY_LABELS[one.family] || one.family) +
        '</td><td><code>' + esc(one.profile) + '</code></td><td><code>' +
        esc(one.serialHex) + '</code></td><td>' +
        (one.names || []).map(function (name) {
          return '<code>' + esc(name) + '</code>';
        }).join('<br>') + '</td><td>' +
        esc(self.readable(one.notAfter, t)) +
        '</td><td>' + esc(one.status) +
        (one.keySource === 'server' ? '<br><span class="sub">' +
          t.html('portalCertificates.enrolled.keyMadeHere') + '</span>'
          : '') + '</td><td>' + revoke + '</td></tr>';
    }).join('');
    log.debug("Leaving PortalCertificatesPage.certificatesCard().");
    return '<div class="card"><h2>' +
      t.html('portalCertificates.enrolled.heading') + '</h2>' +
      '<table><tr><th>' + t.html('portalCertificates.enrolled.protocol') +
      '</th><th>' + t.html('portalCertificates.profile') + '</th><th>' +
      t.html('portalCertificates.enrolled.serial') + '</th><th>' +
      t.html('portalCertificates.enrolled.names') + '</th><th>' +
      t.html('portalCertificates.enrolled.until') + '</th><th>' +
      t.html('portalCertificates.status') + '</th><th></th></tr>' + rows +
      '</table><p class="note">' +
      t.html('portalCertificates.enrolled.note') + '</p></div>';
  }

  private acmeCard(keys: Json[], csrf: string, base: string,
                   t: Json): string {
    const self = this;
    const { log, esc } = this.ctx;
    const PATH = this.PATH;
    log.debug("Entering PortalCertificatesPage.acmeCard().");
    const rows = keys.map(function (one) {
      return '<tr><td><code>' + esc(one.kid) + '</code></td><td>' +
        esc(one.status) + '</td><td>' +
        esc(self.readable(one.expiresAt, t)) +
        '</td><td>' + (one.status === 'bound' ? '' :
          '<form method="post" action="' + PATH + '">' + csrf +
          '<input type="hidden" name="action" value="delete-eab">' +
          '<input type="hidden" name="kid" value="' + esc(one.kid) + '">' +
          '<button class="secondary">' +
          t.html('portalCertificates.delete') + '</button></form>') +
        '</td></tr>';
    }).join('');
    log.debug("Leaving PortalCertificatesPage.acmeCard().");
    return '<div class="card"><h2>ACME</h2><p class="sub">' +
      t.html('portalCertificates.acme.text', {
        url: helpers.rebaseTo(base, 'acme') + '/enroll/acme/directory' }) +
      '</p>' +
      (rows ? '<table><tr><th>' + t.html('portalCertificates.keyId') +
        '</th><th>' + t.html('portalCertificates.status') + '</th><th>' +
        t.html('portalCertificates.expires') + '</th>' +
        '<th></th></tr>' + rows + '</table>' : '') +
      '<form method="post" action="' + PATH + '">' + csrf +
      '<input type="hidden" name="action" value="create-eab"><button>' +
      t.html('portalCertificates.acme.make') + '</button></form></div>';
  }

  private estCard(base: string, t: Json): string {
    const { log, esc } = this.ctx;
    const { core } = this.deps;
    log.debug("Entering PortalCertificatesPage.estCard().");
    const profiles: string[] = core.allowedProfiles('est');
    log.debug("Leaving PortalCertificatesPage.estCard().");
    return '<div class="card"><h2>EST</h2><p class="sub">' +
      t.html('portalCertificates.est.text') + '</p><table><tr><th>' +
      t.html('portalCertificates.profile') + '</th>' +
      '<th>' + t.html('portalCertificates.est.enrollAt') + '</th></tr>' +
      profiles.map(function (profile) {
        return '<tr><td><code>' + esc(profile) + '</code></td><td><code>' +
          esc(helpers.rebaseTo(base, 'est') +
              '/.well-known/est/' + profile + '/simpleenroll') +
          '</code></td></tr>';
      }).join('') + '</table></div>';
  }

  private scepCard(challenges: Json[], csrf: string, base: string,
                   t: Json): string {
    const self = this;
    const { log, esc } = this.ctx;
    const { core } = this.deps;
    const PATH = this.PATH;
    log.debug("Entering PortalCertificatesPage.scepCard().");
    const rows = challenges.map(function (one) {
      return '<tr><td><code>' + esc(one.id) + '</code></td><td><code>' +
        esc(one.profile) + '</code></td><td>' + esc(one.status) +
        '</td><td>' + esc(self.readable(one.expiresAt, t)) + '</td><td>' +
        (one.status === 'unused'
          ? '<form method="post" action="' + PATH + '">' + csrf +
            '<input type="hidden" name="action" value="delete-challenge">' +
            '<input type="hidden" name="id" value="' + esc(one.id) + '">' +
            '<button class="secondary">' +
            t.html('portalCertificates.delete') + '</button></form>'
          : '') + '</td></tr>';
    }).join('');
    const options = core.allowedProfiles('scep').map(function (profile) {
      return '<option value="' + profile + '"' +
        (profile === core.defaultProfile('scep') ? ' selected' : '') + '>' +
        esc(profile) + '</option>';
    }).join('');
    log.debug("Leaving PortalCertificatesPage.scepCard().");
    return '<div class="card"><h2>SCEP</h2><p class="sub">' +
      t.html('portalCertificates.scep.text', {
        url: helpers.rebaseTo(base, 'scep') + '/enroll/scep' }) + '</p>' +
      (rows ? '<table><tr><th>' + t.html('portalCertificates.scep.id') +
        '</th><th>' + t.html('portalCertificates.profile') + '</th><th>' +
        t.html('portalCertificates.status') + '</th>' +
        '<th>' + t.html('portalCertificates.expires') +
        '</th><th></th></tr>' + rows + '</table>' : '') +
      '<form method="post" action="' + PATH + '">' + csrf +
      '<input type="hidden" name="action" value="create-challenge">' +
      '<label>' + t.html('portalCertificates.profile') +
      ' <select name="profile">' + options + '</select>' +
      '</label> <button>' + t.html('portalCertificates.scep.make') +
      '</button></form></div>';
  }

  private hostNamesCard(names: string[], t: Json): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalCertificatesPage.hostNamesCard().");
    log.debug("Leaving PortalCertificatesPage.hostNamesCard().");
    return '<div class="card"><h2>' +
      t.html('portalCertificates.hostNames.heading') + '</h2>' +
      (names.length
        ? '<p>' + names.map(function (one) {
          return '<code>' + esc(one) + '</code>';
        }).join(' ') + '</p>'
        : '<p class="sub">' + t.html('portalCertificates.hostNames.none') +
          '</p>') +
      '<p class="note">' + t.html('portalCertificates.hostNames.note') +
      '</p></div>';
  }

  // A refusal drawn on the page, with its code on the response.
  private refused(res: Res, session: Json, base: string, status: number,
                  code: string, sentence: unknown): unknown {
    const { log, errorCodes, send } = this.ctx;
    log.debug("Entering PortalCertificatesPage.refused(). code=" + code);
    errorCodes.mark(res, code);
    log.debug("Leaving PortalCertificatesPage.refused().");
    return send(res, status, this.page(session, base, null, sentence, null));
  }

  // -------------------------------------------------------------------------
  // GET /portal/certificates
  // -------------------------------------------------------------------------
  private getPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const PATH = this.PATH;
    log.debug('Entering GET ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.READ);
    if (!session) {
      log.debug('Leaving GET ' + PATH + '. Not signed in.');
      return undefined;
    }
    const asked = ctx.validation.check(req, 'query', this.QUERY);
    if (!asked.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(asked) || 'STS-PORTAL-0001');
      log.debug('Leaving GET ' + PATH + '. Malformed.');
      return ctx.refuseShape(res, asked);
    }
    res.set('Cache-Control', 'no-store');
    log.debug('Leaving GET ' + PATH + '.');
    return ctx.send(res, 200, this.page(session, ctx.baseUrlOf(req),
                                        asked.value.done || null, null,
                                        null));
  }

  // -------------------------------------------------------------------------
  // POST /portal/certificates — `manage-own` for every action,
  // `/portal/mfa`'s rule: each of them makes, spends or ends a credential of
  // this person's.
  // -------------------------------------------------------------------------
  private async postPage(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { core, monitor, stsCrypto } = this.deps;
    const PATH = this.PATH;
    log.debug('Entering POST ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      log.debug('Leaving POST ' + PATH + '. Not signed in.');
      return undefined;
    }
    res.set('Cache-Control', 'no-store');
    const entry = this.selfEntry(session);
    const base = ctx.baseUrlOf(req);
    const posted = ctx.validation.checkParsed(ctx.parseBody(req), 'body',
                                              this.FORM);
    if (!posted.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(posted) || 'STS-PORTAL-0001');
      log.debug('Leaving POST ' + PATH + '. Malformed.');
      return ctx.refuseShape(res, posted);
    }
    const body = posted.value;
    const action = String(body.action || '');
    const csrf = ctx.websecurity.checkCsrf(session.id, body);
    if (!csrf.ok) {
      ctx.audit.record({
        category: 'authentication', action: 'portal.certificates.csrf',
        errorCode: ctx.innerCode(csrf) || 'STS-PORTAL-0017',
        actor: entry.id, outcome: 'failure',
        summary: 'a certificate enrollment change was refused: ' +
                 csrf.reason,
        detail: { address: ctx.websecurity.addressOf(req), what: action }
      });
      log.debug('Leaving POST ' + PATH + '. CSRF.');
      ctx.errorCodes.mark(res, ctx.innerCode(csrf) || 'STS-PORTAL-0017');
      return ctx.send(res, 403, this.page(session, base, null, csrf.detail,
                                          null));
    }

    if (action === 'create-eab' || action === 'create-challenge') {
      const family = action === 'create-eab' ? 'acme' : 'scep';
      if (!this.enabled(family)) {
        log.debug('Leaving POST ' + PATH + '. Family off.');
        return this.refused(res, session, base, 403, 'STS-PORTAL-0050',
                            core.FAMILY_LABELS[family] +
                            ' is turned off in this realm.');
      }
      // One budget for the cluster (#46): `attemptShared()`.
      const allowed = await ctx.websecurity.attemptShared(
        'portal-enrollment', req, entry.id, {
          identity: ctx.config.value('pki.personSelfServicePerIdentity'),
          address: ctx.config.value('pki.personSelfServicePerAddress')
        });
      if (!allowed.ok) {
        log.debug('Leaving POST ' + PATH + '. Rate limited.');
        return this.refused(res, session, base, 429,
                            ctx.innerCode(allowed) || 'STS-PORTAL-0020',
                            allowed.detail);
      }
      const made = family === 'acme'
        ? core.createEab({ target: entry, createdBy: entry.id })
        : core.createScepChallenge({ target: entry, createdBy: entry.id,
                                     profile: body.profile });
      if (!made.ok) {
        monitor.record(family, { operation: 'portal.' + action,
                                 outcome: 'refused', status: made.status,
                                 principal: entry.id,
                                 errorCode: ctx.errorCodes.codeOf(made) });
        log.debug('Leaving POST ' + PATH + '. Refused by the core.');
        return this.refused(res, session, base, made.status || 400,
                            'STS-PORTAL-0047',
                            (made.errors || ['Not made.'])[0]);
      }
      monitor.record(family, { operation: 'portal.' + action,
                               outcome: 'credential', status: 200,
                               principal: entry.id,
                               profile: made.profile || null });
      log.info('portal: ' + entry.id + ' made themselves a ' +
               (family === 'acme' ? 'ACME account binding key' :
                'SCEP challenge password') + '. It was shown once.');
      log.debug('Leaving POST ' + PATH + '. Made.');
      const fresh: Fresh = family === 'acme'
        ? { kind: 'eab', kid: made.kid, hmacKey: made.hmacKey,
            expiresAt: made.expiresAt }
        : { kind: 'challenge', challenge: made.challenge,
            profile: made.profile, expiresAt: made.expiresAt };
      return ctx.send(res, 200, this.page(session, base, null, null, fresh));
    }

    if (action === 'delete-eab' || action === 'delete-challenge') {
      // Checked against THIS person's credentials before anything is
      // deleted, and one that is not theirs is answered as not found.
      const id = String(action === 'delete-eab' ? body.kid || '' :
                        body.id || '');
      const mine = (action === 'delete-eab' ? core.eabsOf(entry)
                                            : core.scepChallengesOf(entry))
        .some(function (one) {
          const held = String(one.kid || one.id || '');
          // constantTimeEquals() answers false for two of different
          // lengths, where node's compare threw for two strings of one
          // length and different UTF-8 lengths.
          return id.length > 0 && stsCrypto.constantTimeEquals(held, id);
        });
      if (!mine) {
        log.debug('Leaving POST ' + PATH + '. Not theirs.');
        return this.refused(res, session, base, 404, 'STS-PORTAL-0048',
                            'You hold no such ' +
                            (action === 'delete-eab'
                              ? 'account binding key.'
                              : 'challenge password.'));
      }
      const gone = action === 'delete-eab'
        ? core.deleteEab(id, entry.id)
        : core.deleteScepChallenge(id, entry.id);
      if (!gone.ok) {
        log.debug('Leaving POST ' + PATH + '. Not deleted.');
        return this.refused(res, session, base, 400, 'STS-PORTAL-0048',
                            (gone.errors || ['Not deleted.'])[0]);
      }
      log.debug('Leaving POST ' + PATH + '. Deleted.');
      // The success message in the person's language (#539), made here
      // because the redirect carries it.
      const t = ctx.translatorFor(session);
      res.status(303).set('Location', PATH + '?done=' +
        encodeURIComponent(t.text('portalCertificates.done.deleted'))).end();
      return undefined;
    }

    if (action === 'revoke') {
      const revoked = await core.revokeEnrolled(String(body.serial || ''),
        body.reason || 'unspecified', entry.id, { entry: entry });
      if (!revoked.ok) {
        const code = ctx.errorCodes.codeOf(revoked);
        log.debug('Leaving POST ' + PATH + '. Not revoked.');
        // A certificate that is somebody else's is answered as one that does
        // not exist, which is what the core's 0071 would otherwise reveal.
        return this.refused(res, session, base,
                            code === 'STS-ENROLL-0071' ||
                            code === 'STS-ENROLL-0070' ? 404 : 400,
                            'STS-PORTAL-0049',
                            code === 'STS-ENROLL-0071' ||
                            code === 'STS-ENROLL-0070'
                              ? 'You hold no certificate with that serial.'
                              : (revoked.errors || ['Not revoked.'])[0]);
      }
      monitor.record(revoked.family, { operation: 'portal.revoke',
                                       outcome: 'revoked', status: 303,
                                       principal: entry.id,
                                       serialHex: revoked.serialHex });
      log.debug('Leaving POST ' + PATH + '. Revoked.');
      // As Deleted's, above (#539).
      const t = ctx.translatorFor(session);
      res.status(303).set('Location', PATH + '?done=' +
        encodeURIComponent(t.text('portalCertificates.done.revoked'))).end();
      return undefined;
    }

    log.debug('Leaving POST ' + PATH + '. No such action.');
    return this.refused(res, session, base, 400, 'STS-PORTAL-0051',
                        'That is not something this page does.');
  }

  // The two routes, in the order this file has always registered them.
  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalCertificatesPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalCertificatesPage.registerRoutes().");
  }
}

/**
 * The portal page at /portal/certificates: where a person gets what ACME and
 * SCEP need to issue them a certificate, and sees what they were issued.
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalCertificates {
  /**
   * The revocation reasons a person may give for their own certificate.
   */
  static readonly REVOCATION_REASONS = REVOCATION_REASONS;

  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalCertificatesDeps) {
    deps.log.debug("Entering PortalCertificates.constructor().");
    deps.log.debug("Leaving PortalCertificates.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalCertificatesDeps {
    helpers.log.debug("Entering PortalCertificates.defaultDeps().");
    helpers.log.debug("Leaving PortalCertificates.defaultDeps().");
    return {
      log: helpers.log,
      core: core,
      monitor: monitor,
      stsCrypto: stsCrypto
    };
  }

  // The portal's call, at the one point in its body where the route order is
  // right. Answers the page's path.
  /**
   * Registers the page's routes on the portal's app.
   *
   * @param context - what the portal shares with its pages: the app, `BASE`,
   *   the logger, the page shell, the sign-in check and the refusal helpers
   * @returns the page's path
   */
  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalCertificates.register().");
    const page = new PortalCertificatesPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalCertificates.register().");
    return { path: page.PATH };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PortalCertificates>(
  'portal/portal_certificates',
  () => new PortalCertificates(PortalCertificates.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The portal page at /portal/certificates, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalCertificates: PortalCertificates,
  installInstance: (instance: PortalCertificates): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register'),
  REVOCATION_REASONS: PortalCertificates.REVOCATION_REASONS
};
