'use strict';
//
// portal/portal_devices.ts — /portal/devices, A PERSON'S OWN DEVICES (#130,
// 2026-09-23).
//
// The entries in `ou=devices` this person owns (`common/devices.ts`): each
// device their applications run on, the applications that used it, and
// whether its OpenID Connect Native SSO secret is live — the thing that lets
// those apps share one sign-in. A person removes a device they no longer
// have, which takes its secret with it; that is what a lost phone needs.
// Nothing is added here: a device is made by signing in on it.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md): the removal form names the DEVICE, never
// whose it is, and one that is not theirs is refused. **A REAL SUBMIT BUTTON
// AND NO SCRIPT**, under the service-wide `script-src 'none'`.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// exactly as `portal_self_issued.ts` is, and for its reason.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import devices = require('../common/devices');
import authn = require('../authn/authn');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_self_issued.ts`'s context.
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

interface PortalDevicesDeps {
  // For the constructor only: a page logs through the portal's context.
  log: { debug(message: string): void };
  devices: Json;
  authn: Json;
}

class PortalDevicesPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalDevicesDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalDevicesPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/devices';
    this.FORM = vz.object({
      action: vt.opt(vt.oneOf(['remove'])),
      id: vz.string().max(64),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional()
    });
    ctx.log.debug("Leaving PortalDevicesPage.constructor().");
  }

  // Whether a device's secret is good for a session still live and still
  // this person's — `oauth2.ts`'s `sessionIsLive()`, asked of `authn`
  // directly because the portal is loaded before the authorization server.
  private live(sid: string, who: string): boolean {
    const { authn } = this.deps;
    this.ctx.log.debug("Entering PortalDevicesPage.live().");
    const held = sid ? authn.sessionById(sid) : null;
    this.ctx.log.debug("Leaving PortalDevicesPage.live().");
    return !!held && !authn.sessionEnded(held) &&
      held.authenticated !== false && !!held.user &&
      String(held.user.username || '') === who;
  }

  private page(session: Json, message: unknown, error: unknown): string {
    const { log, shell, esc, websecurity } = this.ctx;
    const { devices } = this.deps;
    const self = this;
    log.debug("Entering PortalDevicesPage.page().");
    const who = String(session.user.username);
    const held = devices.listFor(who).map(function (one: Json) {
      return devices.view(one, function (sid: string) {
        return self.live(sid, who);
      });
    });
    const csrf = websecurity.field(session.id);
    const PATH = this.PATH;
    const rows = held.map(function (one: Json) {
      return '<tr><td>' + esc(one.label) + '</td><td>' +
        esc(one.applications.map(function (dn: string) {
          return String(dn).split(',')[0].replace(/^cn=/i, '');
        }).join(', ') || '—') + '</td><td>' +
        (one.nativeSso ? (one.sessionLive ? 'signed in' : 'signed out')
                       : '—') + '</td><td>' + esc(String(one.keys.length)) +
        '</td><td>' + esc(one.lastUsed || '') +
        '</td><td><form method="post" action="' + esc(PATH) + '">' + csrf +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="id" value="' + esc(one.id) + '">' +
        '<button class="danger" type="submit">Remove</button></form>' +
        '</td></tr>';
    });
    const body = '<div class="card"><h2>Your devices</h2>' +
      '<p class="sub">The phones and computers that are yours: the ones ' +
      'you have signed in on with an app that shares its sign-in with the ' +
      'other apps on the device (OpenID Connect Native SSO), and any an ' +
      'administrator registered for you. Remove one you no longer have: ' +
      'its apps can no longer share a sign-in, and ask you to sign in ' +
      'again.</p>' +
      (held.length
        ? '<table><tr><th>Device</th><th>Applications</th><th>Shared ' +
          'sign-in</th><th>Keys</th><th>Last used</th><th></th></tr>' +
          rows.join('') +
          '</table>'
        : '<p id="devices-none">None.</p>') + '</div>';
    log.debug("Leaving PortalDevicesPage.page().");
    return shell(this.PATH, session, message, error, body);
  }

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
    const message = asked.value.done || null;
    log.debug('Leaving GET ' + PATH + '.');
    return ctx.send(res, 200, this.page(session, message, null));
  }

  private postPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const { devices } = this.deps;
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
    const csrf = ctx.websecurity.checkCsrf(session.id, body);
    if (!csrf.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(csrf) || 'STS-PORTAL-0017');
      log.debug('Leaving POST ' + PATH + '. CSRF.');
      return ctx.send(res, 403, this.page(session, null, csrf.detail));
    }
    const result = devices.remove(body.id, who, who);
    ctx.audit.record({
      category: 'authentication', action: 'portal.device.remove',
      errorCode: result.ok ? undefined : 'STS-PORTAL-0088',
      actor: who, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? '' : 'could not ') + 'removed device ' +
               body.id + ' on /portal/devices',
      detail: { id: body.id,
                errors: result.ok ? undefined : [result.error] }
    });
    if (!result.ok) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0088');
      log.debug('Leaving POST ' + PATH + '. Refused.');
      return ctx.send(res, 400, this.page(session, null, result.error));
    }
    log.debug('Leaving POST ' + PATH + '. Removed.');
    // ABSOLUTE, ON `baseUrlOf(req)` (#164): a bare `/portal/devices`
    // Location is answered by the DEFAULT realm, because nothing adds the
    // realm prefix to a Location on the way out — so a person in another
    // realm was sent to a portal they are not signed in to
    // (`portal_claim_sources.ts` found it first; portal/CLAUDE.md).
    res.status(303).set('Location', ctx.baseUrlOf(req) + PATH + '?done=' +
      encodeURIComponent('That device is removed.')).end();
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalDevicesPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalDevicesPage.registerRoutes().");
  }
}

class PortalDevices {
  constructor(private readonly deps: PortalDevicesDeps) {
    deps.log.debug("Entering PortalDevices.constructor().");
    deps.log.debug("Leaving PortalDevices.constructor().");
  }

  static defaultDeps(): PortalDevicesDeps {
    helpers.log.debug("Entering PortalDevices.defaultDeps().");
    helpers.log.debug("Leaving PortalDevices.defaultDeps().");
    return { log: helpers.log, devices: devices, authn: authn };
  }

  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalDevices.register().");
    const page = new PortalDevicesPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalDevices.register().");
    return { path: page.PATH };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `portal_certificates.ts`.
const slot = new InstanceSlot<PortalDevices>(
  'portal/portal_devices',
  () => new PortalDevices(PortalDevices.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  PortalDevices: PortalDevices,
  installInstance: (instance: PortalDevices): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
