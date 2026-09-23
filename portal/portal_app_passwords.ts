'use strict';
//
// portal/portal_app_passwords.ts — /portal/app-passwords, WHERE A PERSON MAKES
// THE PASSWORD A CLIENT THAT CANNOT DO A SECOND FACTOR SENDS (#101,
// 2026-09-22).
//
// In product mode a person who holds a second factor, or of whom one is
// required, is refused their own password at the five doors that cannot ask
// for one — an LDAP bind, a WS-Security UsernameToken, SCIM, SSF and EST
// Basic (`common/credentials.ts`, `secondFactorRefusal()`). An address book
// that binds to the directory, a SCIM provisioning job, an EST client on a
// device: each of them sends a password and nothing else. This page is where
// the person makes an APP PASSWORD for one of them — `common/app_passwords.ts`
// argues what one is — and sees and revokes the ones they have.
//
// **AFTER A FULL SIGN-IN.** The page is behind the portal's own sign-in, so
// the session that reaches it already met whatever the account asks for —
// the password and, where they hold or must hold one, the second factor. An
// app password is made by somebody who proved both, which is what makes it
// safe to be one factor at the doors it names.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md). A revoke names an id, and an id that is
// not one of THIS person's is answered as one that does not exist, so the
// page is not an oracle for anybody else's.
//
// **THE PASSWORD IS SHOWN ON A 200 AND NEVER ON A REDIRECT**, with
// `Cache-Control: no-store`, for `/portal/certificates`' reason: a secret on a
// query string is a secret in the history, the access log and the next
// `Referer`. **A REAL SUBMIT BUTTON AND NO SCRIPT**: the page is ordinary
// forms under the service-wide `script-src 'none'` (root CLAUDE.md, the CSP
// section), and nothing on it needs one — the scope is checkboxes, the name a
// text box.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// exactly as `portal_certificates.ts` is, and for its reason: everything that
// makes a page a PORTAL page is private to `portal.ts`, which hands it over at
// the point in the route order where the page belongs.
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS CLASSES (#50) — `portal_certificates.ts`'s shape: the
// credential store and the app-password library arrive through the
// constructor, the portal's context through `register()`, and the module
// exports `register` as a facade over the instance the composition root
// builds.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');
import appPasswords = require('../common/app_passwords');
import accountSignals = require('../ssf/account_signals');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_certificates.ts`'s context.
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

interface PortalAppPasswordsDeps {
  // For the constructor only: a page logs through the portal's context.
  log: { debug(message: string): void };
  credentials: Json;
  appPasswords: Json;
  accountSignals: Json;
}

// The one-time password a POST just made.
interface Fresh {
  id: string;
  name: string;
  doors: string[];
  password: string;
}

class PortalAppPasswordsPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalAppPasswordsDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalAppPasswordsPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/app-passwords';
    // ONE CHECKBOX PER DOOR, EACH WITH ITS OWN NAME (`door_ldap`, ...):
    // the portal's form parser keeps the last of a repeated name, so five
    // boxes all called `door` would scope a password to one door.
    const shape: Json = {
      action: vt.opt(vt.oneOf(['create', 'revoke'])),
      name: vz.string().max(200).optional(),
      id: vz.string().max(8).regex(/^[A-Za-z2-7]*$/).optional(),
      csrf_token: vt.opt(vt.token)
    };
    deps.appPasswords.DOOR_IDS.forEach(function (door) {
      shape['door_' + door] = vt.opt(vt.flag);
    });
    this.FORM = vz.object(shape);
    this.QUERY = vz.object({
      done: vz.string().max(200).optional()
    });
    ctx.log.debug("Leaving PortalAppPasswordsPage.constructor().");
  }

  private readable(when: unknown): string {
    const { log } = this.ctx;
    log.debug("Entering PortalAppPasswordsPage.readable().");
    const at = new Date(Number(when || 0));
    log.debug("Leaving PortalAppPasswordsPage.readable().");
    return !Number(when) || isNaN(at.getTime()) ? 'never'
      : at.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  }

  private doorList(doors: string[]): string {
    const { log, esc } = this.ctx;
    const { appPasswords } = this.deps;
    log.debug("Entering PortalAppPasswordsPage.doorList().");
    log.debug("Leaving PortalAppPasswordsPage.doorList().");
    return doors.map(function (door) {
      return esc(appPasswords.doorLabel(door));
    }).join(', ');
  }

  // -------------------------------------------------------------------------
  // THE PAGE. `fresh` is the password the POST just made, or null.
  // -------------------------------------------------------------------------
  private page(session: Json, message: unknown, error: unknown,
               fresh: Fresh | null): string {
    const { log, shell } = this.ctx;
    const { credentials } = this.deps;
    log.debug("Entering PortalAppPasswordsPage.page().");
    const who = String(session.user.username);
    const cards: string[] = [];
    if (fresh) {
      cards.push(this.freshCard(fresh, who));
    }
    cards.push(this.doorsCard(credentials.passwordOnlyDoors(who)));
    cards.push(this.listCard(credentials.appPasswordsOf(who), session));
    cards.push(this.createCard(session));
    log.debug("Leaving PortalAppPasswordsPage.page().");
    return shell(this.PATH, session, message, error, cards.join(''));
  }

  private freshCard(fresh: Fresh, who: string): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalAppPasswordsPage.freshCard().");
    log.debug("Leaving PortalAppPasswordsPage.freshCard().");
    return '<div class="card"><h2>Your new app password</h2>' +
      '<div class="err"><strong>Copy it now.</strong> It is shown on this ' +
      'page once and cannot be shown again — this service keeps only a ' +
      'hash of it.</div>' +
      '<table><tr><th>App password</th><td><code class="app-password">' +
      esc(fresh.password) + '</code></td></tr>' +
      '<tr><th>Name</th><td>' + esc(fresh.name) + '</td></tr>' +
      '<tr><th>Accepted at</th><td>' + this.doorList(fresh.doors) +
      '</td></tr><tr><th>Username</th><td><code>' + esc(who) +
      '</code></td></tr></table>' +
      '<p class="note">Put it in the client in place of your password, ' +
      'with your usual username. It works only at the doors above and ' +
      'never at the sign-in screen. The dashes are optional.</p></div>';
  }

  // Which doors refuse this person's own password, said on the page that is
  // the answer to it.
  private doorsCard(doors: Json): string {
    const { log, esc } = this.ctx;
    const { appPasswords } = this.deps;
    log.debug("Entering PortalAppPasswordsPage.doorsCard().");
    const rows = appPasswords.DOORS.map(function (one) {
      const refused = doors.refused.indexOf(one.id) >= 0;
      return '<tr><td>' + esc(one.label) + '</td><td>' + esc(one.what) +
        '</td><td>' + (refused
          ? '<strong>an app password only</strong>'
          : 'your password, or an app password') + '</td></tr>';
    }).join('');
    const lead = !doors.secondFactor
      ? 'You hold no second factor, so your own password is accepted at ' +
        'these doors. An app password is still worth having: it is random, ' +
        'it works only where you say, and revoking one does not change ' +
        'your password.'
      : !doors.applies
        ? 'This service is in development mode and checks no password at ' +
          'these doors. In product mode, because you use a second factor, ' +
          'your own password would be refused there and an app password is ' +
          'what you would use.'
        : 'Because you use a second factor, your own password is refused at ' +
          'the doors marked below — they cannot ask for the second factor. ' +
          'Make an app password for each client that uses one of them.';
    log.debug("Leaving PortalAppPasswordsPage.doorsCard().");
    return '<div class="card"><h2>Where a password alone is asked for</h2>' +
      '<p class="sub">' + esc(lead) + '</p><table><tr><th>Door</th>' +
      '<th>What speaks it</th><th>What it accepts from you</th></tr>' +
      rows + '</table></div>';
  }

  private listCard(held: Json, session: Json): string {
    const self = this;
    const { log, esc, websecurity } = this.ctx;
    const PATH = this.PATH;
    log.debug("Entering PortalAppPasswordsPage.listCard().");
    if (held.unreadable) {
      log.debug("Leaving PortalAppPasswordsPage.listCard(). Unreadable.");
      return '<div class="card"><h2>Your app passwords</h2><div ' +
        'class="err">The app passwords on your account cannot be read, so ' +
        'none of them is accepted. Ask an administrator to look at your ' +
        'entry.</div></div>';
    }
    if (!held.passwords.length) {
      log.debug("Leaving PortalAppPasswordsPage.listCard(). None.");
      return '<div class="card"><h2>Your app passwords</h2><p class="sub">' +
        'You have none.</p></div>';
    }
    const csrf = websecurity.field(session.id);
    const rows = held.passwords.map(function (one) {
      return '<tr><td>' + esc(one.name) + '</td><td><code>' + esc(one.id) +
        '</code></td><td>' + self.doorList(one.doors) + '</td><td>' +
        esc(self.readable(one.createdAt)) + '</td><td>' +
        esc(self.readable(one.lastUsedAt)) +
        (one.lastUsedAt && one.lastUsedDoor
          ? ' (' + self.doorList([one.lastUsedDoor]) + ')' : '') +
        '</td><td><form method="post" action="' + PATH + '">' + csrf +
        '<input type="hidden" name="action" value="revoke">' +
        '<input type="hidden" name="id" value="' + esc(one.id) + '">' +
        '<button class="danger" type="submit">Revoke</button></form>' +
        '</td></tr>';
    }).join('');
    log.debug("Leaving PortalAppPasswordsPage.listCard().");
    return '<div class="card"><h2>Your app passwords</h2>' +
      '<table><tr><th>Name</th><th>Id</th><th>Accepted at</th>' +
      '<th>Made</th><th>Last used</th><th></th></tr>' + rows + '</table>' +
      '<p class="note">Revoking one stops the client that holds it at its ' +
      'next sign-in. The id is the first four characters of the password; ' +
      'it is not secret.</p></div>';
  }

  private createCard(session: Json): string {
    const { log, esc, websecurity } = this.ctx;
    const { appPasswords } = this.deps;
    log.debug("Entering PortalAppPasswordsPage.createCard().");
    if (!appPasswords.settings().enabled) {
      log.debug("Leaving PortalAppPasswordsPage.createCard(). Off.");
      return '<div class="card"><h2>Make an app password</h2><p ' +
        'class="sub">App passwords are turned off here, so a new one cannot ' +
        'be made. The ones you have go on working.</p></div>';
    }
    const boxes = appPasswords.DOORS.map(function (one) {
      return '<label><input type="checkbox" name="door_' + esc(one.id) +
        '" value="on"> ' + esc(one.label) + '</label> ';
    }).join('');
    log.debug("Leaving PortalAppPasswordsPage.createCard().");
    return '<div class="card"><h2>Make an app password</h2>' +
      '<form method="post" action="' + this.PATH + '">' +
      websecurity.field(session.id) +
      '<input type="hidden" name="action" value="create">' +
      '<p><label>Name <input type="text" name="name" maxlength="' +
      appPasswords.MAX_NAME + '" required placeholder="' +
      'which client it is for"></label></p>' +
      '<fieldset><legend>Accepted at</legend>' + boxes + '</fieldset>' +
      '<p><button type="submit">Make an app password</button></p></form>' +
      '<p class="note">It is shown once, on the page that answers this ' +
      'form. Choose only the doors the client needs.</p></div>';
  }

  // A refusal drawn on the page, with its code on the response.
  private refused(res: Res, session: Json, status: number, code: string,
                  sentence: unknown): unknown {
    const { log, errorCodes, send } = this.ctx;
    log.debug("Entering PortalAppPasswordsPage.refused(). code=" + code);
    errorCodes.mark(res, code);
    log.debug("Leaving PortalAppPasswordsPage.refused().");
    return send(res, status, this.page(session, null, sentence, null));
  }

  // -------------------------------------------------------------------------
  // GET /portal/app-passwords
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
    log.debug('Leaving GET ' + PATH + '.');
    return ctx.send(res, 200, this.page(session, asked.value.done || null,
                                        null, null));
  }

  // -------------------------------------------------------------------------
  // POST /portal/app-passwords — `manage-own` for both actions: each makes or
  // ends a credential of this person's.
  // -------------------------------------------------------------------------
  private async postPage(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { credentials, accountSignals } = this.deps;
    const PATH = this.PATH;
    log.debug('Entering POST ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      log.debug('Leaving POST ' + PATH + '. Not signed in.');
      return undefined;
    }
    const who = String(session.user.username);
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
        category: 'authentication', action: 'portal.app-password.csrf',
        errorCode: ctx.innerCode(csrf) || 'STS-PORTAL-0017',
        actor: who, outcome: 'failure',
        summary: 'an app password change was refused: ' + csrf.reason,
        detail: { address: ctx.websecurity.addressOf(req), what: action }
      });
      log.debug('Leaving POST ' + PATH + '. CSRF.');
      ctx.errorCodes.mark(res, ctx.innerCode(csrf) || 'STS-PORTAL-0017');
      return ctx.send(res, 403, this.page(session, null, csrf.detail, null));
    }

    if (action === 'create') {
      // One budget for the cluster: making one is a scrypt hash and a
      // directory write, and it is not something anybody does a hundred times
      // a minute.
      const allowed = await ctx.websecurity.attemptShared(
        'portal-app-password', req, who);
      if (!allowed.ok) {
        log.debug('Leaving POST ' + PATH + '. Rate limited.');
        return this.refused(res, session, 429,
                            ctx.innerCode(allowed) || 'STS-PORTAL-0020',
                            allowed.detail);
      }
      const doors = this.deps.appPasswords.DOOR_IDS.filter(function (door) {
        return ['on', 'true', '1', 'yes'].indexOf(
          String(body['door_' + door] || '')) >= 0;
      });
      const made = credentials.createAppPassword(who, {
        name: body.name, doors: doors, createdBy: who });
      ctx.audit.record({
        category: 'authentication', action: 'portal.app-password.created',
        errorCode: made.ok ? undefined
          : (ctx.errorCodes.codeOf(made) || 'STS-PORTAL-0077'),
        actor: who, target: who, outcome: made.ok ? 'success' : 'failure',
        summary: (made.ok ? 'made' : 'could not make') + ' an app password ' +
                 'on /portal/app-passwords',
        detail: { id: made.ok ? made.id : undefined,
                  name: made.ok ? made.name : String(body.name || ''),
                  doors: made.ok ? made.doors : undefined,
                  errors: made.ok ? undefined : made.errors }
      });
      if (!made.ok) {
        log.debug('Leaving POST ' + PATH + '. Refused by the store.');
        return this.refused(res, session, 400, 'STS-PORTAL-0077',
                            (made.errors || ['Not made.'])[0]);
      }
      accountSignals.credentialChanged({ username: who,
        credentialType: 'password', changeType: 'create',
        friendlyName: made.name, initiatingEntity: 'user', via: 'portal',
        reasonAdmin: who + ' made the app password "' + made.name + '" for ' +
                     made.doors.join(', ') + '.',
        reasonUser: 'You made an app password called "' + made.name + '".' });
      log.info('portal: ' + who + ' made themselves the app password "' +
               made.name + '" (' + made.id + '). It was shown once.');
      log.debug('Leaving POST ' + PATH + '. Made.');
      res.set('Cache-Control', 'no-store');
      return ctx.send(res, 200, this.page(session, null, null, {
        id: made.id, name: made.name, doors: made.doors,
        password: made.password }));
    }

    if (action === 'revoke') {
      const id = String(body.id || '').toUpperCase();
      // Checked against THIS person's before anything is revoked; one that is
      // not theirs is answered as not found.
      const mine = credentials.appPasswordsOf(who).passwords
        .some(function (one) { return one.id === id; });
      const gone = mine ? credentials.revokeAppPassword(who, id) : null;
      ctx.audit.record({
        category: 'authentication', action: 'portal.app-password.revoked',
        errorCode: gone && gone.ok ? undefined
          : ((gone && ctx.errorCodes.codeOf(gone)) || 'STS-PORTAL-0078'),
        actor: who, target: who,
        outcome: gone && gone.ok ? 'success' : 'failure',
        summary: (gone && gone.ok ? 'revoked' : 'could not revoke') +
                 ' an app password on /portal/app-passwords',
        detail: { id: id }
      });
      if (!gone || !gone.ok) {
        log.debug('Leaving POST ' + PATH + '. Not theirs, or not revoked.');
        return this.refused(res, session, mine ? 400 : 404,
                            mine ? 'STS-PORTAL-0077' : 'STS-PORTAL-0078',
                            mine ? (gone.errors || ['Not revoked.'])[0]
                              : 'You hold no app password with that id.');
      }
      accountSignals.credentialChanged({ username: who,
        credentialType: 'password', changeType: 'revoke',
        friendlyName: gone.revoked.name, initiatingEntity: 'user',
        via: 'portal',
        reasonAdmin: who + ' revoked the app password "' + gone.revoked.name +
                     '".',
        reasonUser: 'You revoked the app password called "' +
                    gone.revoked.name + '".' });
      log.debug('Leaving POST ' + PATH + '. Revoked.');
      res.status(303).set('Location', PATH + '?done=' +
        encodeURIComponent('That app password is revoked.')).end();
      return undefined;
    }

    log.debug('Leaving POST ' + PATH + '. No such action.');
    return this.refused(res, session, 400, 'STS-PORTAL-0079',
                        'That is not something this page does.');
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalAppPasswordsPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalAppPasswordsPage.registerRoutes().");
  }
}

class PortalAppPasswords {
  constructor(private readonly deps: PortalAppPasswordsDeps) {
    deps.log.debug("Entering PortalAppPasswords.constructor().");
    deps.log.debug("Leaving PortalAppPasswords.constructor().");
  }

  static defaultDeps(): PortalAppPasswordsDeps {
    helpers.log.debug("Entering PortalAppPasswords.defaultDeps().");
    helpers.log.debug("Leaving PortalAppPasswords.defaultDeps().");
    return {
      log: helpers.log,
      credentials: credentials,
      appPasswords: appPasswords,
      accountSignals: accountSignals
    };
  }

  // The portal's call, at the point in its body where the route order is
  // right. Answers the page's path.
  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalAppPasswords.register().");
    const page = new PortalAppPasswordsPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalAppPasswords.register().");
    return { path: page.PATH };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `portal_certificates.ts`.
const slot = new InstanceSlot<PortalAppPasswords>(
  'portal/portal_app_passwords',
  () => new PortalAppPasswords(PortalAppPasswords.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  PortalAppPasswords: PortalAppPasswords,
  installInstance: (instance: PortalAppPasswords): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
