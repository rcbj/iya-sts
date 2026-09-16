'use strict';
//
// portal/portal_certificates.ts — /portal/certificates, WHERE A PERSON GETS
// WHAT ACME AND SCEP NEED TO ISSUE THEM A CERTIFICATE, AND SEES WHAT THEY WERE
// ISSUED (2026-09-13).
//
// ACME and SCEP authenticate with a credential bound to ONE directory entry —
// an External Account Binding key and a single-use challenge password
// (`common/cert_enrollment.js`). An administrator can make one for anybody on
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
// `portal.ts`. So `portal.ts` hands those over at the one point in its body
// where the route order is right, and this file owns only what is new.
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
//   * **THE MODULE STILL EXPORTS `register` AND `REVOCATION_REASONS`**, from a
//     TRANSITIONAL instance built from the real modules, for the portal. It
//     goes when the composition root exists; `PortalCertificates` is exported
//     beside it for that root.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
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
  nodeCrypto: typeof nodeCrypto;
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
      profile: vt.opt(vt.oneOf(deps.core.PROFILE_IDS)),
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

  private readable(when: unknown): string {
    const { log } = this.ctx;
    log.debug("Entering PortalCertificatesPage.readable().");
    const at = new Date(when as any);
    log.debug("Leaving PortalCertificatesPage.readable().");
    return isNaN(at.getTime()) ? String(when || '')
      : at.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
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
    const resolved = core.resolveEntry(entry.kind, entry.id);
    const cards: string[] = [];

    if (fresh) {
      cards.push(this.freshCard(fresh, base));
    }

    if (!resolved.ok) {
      cards.push('<div class="card"><h2>No directory entry</h2><p ' +
        'class="sub">You are signed in as <code>' + esc(entry.id) +
        '</code>, and there is no person of that name in this realm\'s ' +
        'directory. A certificate issued over ACME, EST or SCEP always ' +
        'names an entry and is kept on it, so there is nothing to issue to ' +
        'until one exists.</p></div>');
      log.debug("Leaving PortalCertificatesPage.page(). No entry.");
      return shell(PATH, session, message, error, cards.join(''));
    }

    cards.push(this.certificatesCard(core.enrolledOf(entry), csrf));
    if (this.enabled('acme')) {
      cards.push(this.acmeCard(core.eabsOf(entry), csrf, base));
    }
    if (this.enabled('est')) {
      cards.push(this.estCard(base));
    }
    if (this.enabled('scep')) {
      cards.push(this.scepCard(core.scepChallengesOf(entry), csrf, base));
    }
    cards.push(this.hostNamesCard(resolved.hostNames));
    cards.push('<div class="card"><h2>Other certificates</h2><p ' +
      'class="sub">A TLS client certificate this portal issues you ' +
      'directly, and your RFC 7523 and RFC 7522 signing keys, are on <a ' +
      'href="' + BASE + '/signing-key">Signing keys</a>. This page is ' +
      'about the three enrollment protocols a client or a device speaks to ' +
      'get one.</p></div>');
    log.debug("Leaving PortalCertificatesPage.page().");
    return shell(PATH, session, message, error, cards.join(''));
  }

  private freshCard(fresh: Fresh, base: string): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalCertificatesPage.freshCard(). kind=" +
              fresh.kind);
    if (fresh.kind === 'eab') {
      const directory = base + '/enroll/acme/directory';
      log.debug("Leaving PortalCertificatesPage.freshCard(). EAB.");
      return '<div class="card"><h2>Your new ACME account binding key</h2>' +
        '<div class="err"><strong>Copy it now.</strong> The HMAC key is ' +
        'shown on this page once and cannot be shown again.</div>' +
        '<table><tr><th>Directory</th><td><code>' + esc(directory) +
        '</code></td></tr><tr><th>Key id</th><td><code>' + esc(fresh.kid) +
        '</code></td></tr><tr><th>HMAC key (HS256)</th><td><code>' +
        esc(fresh.hmacKey) + '</code></td></tr><tr><th>Binds an account ' +
        'until</th><td>' + esc(this.readable(fresh.expiresAt)) +
        '</td></tr></table><p class="sub">For example:</p><pre class="pem">' +
        esc('certbot certonly --server ' + directory + ' \\\n' +
            '  --eab-kid ' + fresh.kid + ' \\\n' +
            '  --eab-hmac-key ' + fresh.hmacKey + ' ...') + '</pre>' +
        '<p class="note">The key binds ONE account, and that account can ' +
        'only ever be issued certificates for you.</p></div>';
    }
    log.debug("Leaving PortalCertificatesPage.freshCard(). Challenge.");
    return '<div class="card"><h2>Your new SCEP challenge password</h2>' +
      '<div class="err"><strong>Copy it now.</strong> It is shown on this ' +
      'page once and cannot be shown again.</div>' +
      '<table><tr><th>SCEP URL</th><td><code>' +
      esc(base + '/enroll/scep/' + fresh.profile) + '</code></td></tr>' +
      '<tr><th>Challenge password</th><td><code>' + esc(fresh.challenge) +
      '</code></td></tr><tr><th>Profile</th><td><code>' +
      esc(fresh.profile) + '</code></td></tr><tr><th>Usable until</th><td>' +
      esc(this.readable(fresh.expiresAt)) + '</td></tr></table>' +
      '<p class="note">It is spent by the first certificate request that ' +
      'uses it, and that certificate names you.</p></div>';
  }

  private certificatesCard(records: Json[], csrf: string): string {
    const self = this;
    const { log, esc } = this.ctx;
    const { core } = this.deps;
    const PATH = this.PATH;
    log.debug("Entering PortalCertificatesPage.certificatesCard(). " +
              records.length + ".");
    if (!records.length) {
      log.debug("Leaving PortalCertificatesPage.certificatesCard(). None.");
      return '<div class="card"><h2>Your enrolled certificates</h2><p ' +
        'class="sub">You hold no certificate issued over ACME, EST or ' +
        'SCEP.</p></div>';
    }
    const rows = records.map(function (one) {
      const revoke = one.status === 'valid'
        ? '<form method="post" action="' + PATH + '">' + csrf +
          '<input type="hidden" name="action" value="revoke">' +
          '<input type="hidden" name="serial" value="' +
          esc(one.serialHex) + '"><select name="reason" aria-label="' +
          'Revocation reason">' + REVOCATION_REASONS.map(function (reason) {
            return '<option value="' + reason + '">' + esc(reason) +
              '</option>';
          }).join('') + '</select> <button class="danger">Revoke</button>' +
          '</form>'
        : '';
      return '<tr><td>' + esc(core.FAMILY_LABELS[one.family] || one.family) +
        '</td><td><code>' + esc(one.profile) + '</code></td><td><code>' +
        esc(one.serialHex) + '</code></td><td>' +
        (one.names || []).map(function (name) {
          return '<code>' + esc(name) + '</code>';
        }).join('<br>') + '</td><td>' + esc(self.readable(one.notAfter)) +
        '</td><td>' + esc(one.status) +
        (one.keySource === 'server' ? '<br><span class="sub">key made ' +
          'here</span>' : '') + '</td><td>' + revoke + '</td></tr>';
    }).join('');
    log.debug("Leaving PortalCertificatesPage.certificatesCard().");
    return '<div class="card"><h2>Your enrolled certificates</h2>' +
      '<table><tr><th>Protocol</th><th>Profile</th><th>Serial</th>' +
      '<th>Names</th><th>Until</th><th>Status</th><th></th></tr>' + rows +
      '</table><p class="note">Revoking puts the certificate on its ' +
      'authority\'s CRL and makes OCSP answer <code>revoked</code>. It ' +
      'cannot ' +
      'be undone.</p></div>';
  }

  private acmeCard(keys: Json[], csrf: string, base: string): string {
    const self = this;
    const { log, esc } = this.ctx;
    const PATH = this.PATH;
    log.debug("Entering PortalCertificatesPage.acmeCard().");
    const rows = keys.map(function (one) {
      return '<tr><td><code>' + esc(one.kid) + '</code></td><td>' +
        esc(one.status) + '</td><td>' + esc(self.readable(one.expiresAt)) +
        '</td><td>' + (one.status === 'bound' ? '' :
          '<form method="post" action="' + PATH + '">' + csrf +
          '<input type="hidden" name="action" value="delete-eab">' +
          '<input type="hidden" name="kid" value="' + esc(one.kid) + '">' +
          '<button class="secondary">Delete</button></form>') + '</td></tr>';
    }).join('');
    log.debug("Leaving PortalCertificatesPage.acmeCard().");
    return '<div class="card"><h2>ACME</h2><p class="sub">An ACME client ' +
      'registers an account at <code>' +
      esc(base + '/enroll/acme/directory') + '</code> with an External ' +
      'Account Binding key; the account is then bound to you for life.</p>' +
      (rows ? '<table><tr><th>Key id</th><th>Status</th><th>Expires</th>' +
        '<th></th></tr>' + rows + '</table>' : '') +
      '<form method="post" action="' + PATH + '">' + csrf +
      '<input type="hidden" name="action" value="create-eab"><button>Make ' +
      'an ACME account binding key</button></form></div>';
  }

  private estCard(base: string): string {
    const { log, esc } = this.ctx;
    const { core } = this.deps;
    log.debug("Entering PortalCertificatesPage.estCard().");
    const profiles: string[] = core.allowedProfiles('est');
    log.debug("Leaving PortalCertificatesPage.estCard().");
    return '<div class="card"><h2>EST</h2><p class="sub">An EST client ' +
      'authenticates with your username and password (or a certificate you ' +
      'were issued over EST, ACME or SCEP) and posts a certificate request. ' +
      'Nothing needs to be made here first.</p><table><tr><th>Profile</th>' +
      '<th>Enroll at</th></tr>' + profiles.map(function (profile) {
        return '<tr><td><code>' + esc(profile) + '</code></td><td><code>' +
          esc(base + '/.well-known/est/' + profile + '/simpleenroll') +
          '</code></td></tr>';
      }).join('') + '</table></div>';
  }

  private scepCard(challenges: Json[], csrf: string, base: string): string {
    const self = this;
    const { log, esc } = this.ctx;
    const { core } = this.deps;
    const PATH = this.PATH;
    log.debug("Entering PortalCertificatesPage.scepCard().");
    const rows = challenges.map(function (one) {
      return '<tr><td><code>' + esc(one.id) + '</code></td><td><code>' +
        esc(one.profile) + '</code></td><td>' + esc(one.status) +
        '</td><td>' + esc(self.readable(one.expiresAt)) + '</td><td>' +
        (one.status === 'unused'
          ? '<form method="post" action="' + PATH + '">' + csrf +
            '<input type="hidden" name="action" value="delete-challenge">' +
            '<input type="hidden" name="id" value="' + esc(one.id) + '">' +
            '<button class="secondary">Delete</button></form>'
          : '') + '</td></tr>';
    }).join('');
    const options = core.allowedProfiles('scep').map(function (profile) {
      return '<option value="' + profile + '"' +
        (profile === core.defaultProfile('scep') ? ' selected' : '') + '>' +
        esc(profile) + '</option>';
    }).join('');
    log.debug("Leaving PortalCertificatesPage.scepCard().");
    return '<div class="card"><h2>SCEP</h2><p class="sub">A SCEP client ' +
      'puts a challenge password in its certificate request to <code>' +
      esc(base + '/enroll/scep') + '</code>. Each is for one profile and ' +
      'is spent once.</p>' +
      (rows ? '<table><tr><th>Id</th><th>Profile</th><th>Status</th>' +
        '<th>Expires</th><th></th></tr>' + rows + '</table>' : '') +
      '<form method="post" action="' + PATH + '">' + csrf +
      '<input type="hidden" name="action" value="create-challenge">' +
      '<label>Profile <select name="profile">' + options + '</select>' +
      '</label> <button>Make a SCEP challenge password</button></form></div>';
  }

  private hostNamesCard(names: string[]): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalCertificatesPage.hostNamesCard().");
    log.debug("Leaving PortalCertificatesPage.hostNamesCard().");
    return '<div class="card"><h2>Host names registered to you</h2>' +
      (names.length
        ? '<p>' + names.map(function (one) {
          return '<code>' + esc(one) + '</code>';
        }).join(' ') + '</p>'
        : '<p class="sub">None.</p>') +
      '<p class="note">A TLS server certificate names only these. An ' +
      'administrator registers them; this service never proves control of ' +
      'a name by contacting it.</p></div>';
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
    const { core, monitor, nodeCrypto } = this.deps;
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
          return held.length === id.length && id.length > 0 &&
                 nodeCrypto.timingSafeEqual(Buffer.from(held),
                                            Buffer.from(id));
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
      res.status(303).set('Location', PATH + '?done=' +
        encodeURIComponent('Deleted.')).end();
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
      res.status(303).set('Location', PATH + '?done=' +
        encodeURIComponent('That certificate is revoked.')).end();
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

class PortalCertificates {
  static readonly REVOCATION_REASONS = REVOCATION_REASONS;

  constructor(private readonly deps: PortalCertificatesDeps) {
    deps.log.debug("Entering PortalCertificates.constructor().");
    deps.log.debug("Leaving PortalCertificates.constructor().");
  }

  // The portal's call, at the one point in its body where the route order is
  // right. Answers the page's path.
  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalCertificates.register().");
    const page = new PortalCertificatesPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalCertificates.register().");
    return { path: page.PATH };
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one. Its logger is the service's; a page
// logs through the one the portal hands over in the context, as it always
// did.
const certificates = new PortalCertificates({
  log: helpers.log,
  core: core,
  monitor: monitor,
  nodeCrypto: nodeCrypto
});

export = {
  PortalCertificates: PortalCertificates,
  register: certificates.register.bind(certificates) as
    PortalCertificates['register'],
  REVOCATION_REASONS: PortalCertificates.REVOCATION_REASONS
};
