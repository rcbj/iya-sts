'use strict';
//
// portal/portal_devices.ts — /portal/devices, A PERSON'S OWN DEVICES (#130,
// 2026-09-23; #164 phase 2, 2026-09-26).
//
// The entries in `ou=devices` this person owns (`common/devices.ts`): each
// device their applications run on, the applications that used it, its keys
// and whether each is attested, and whether its OpenID Connect Native SSO
// secret is live. A person removes a device they no longer have, which takes
// its secret with it; that is what a lost phone needs.
//
// **SINCE #164 PHASE 2 A PERSON REGISTERS ONE HERE, BY PROVING A KEY**
// (decision 6b; `common/device_enrolment.ts` argues the flows):
//
//   * **A JWK PROOF.** "Get a challenge" issues one bound to this session;
//     the device signs a `device-key-proof+jwt` JWS over it — `{ nonce, aud,
//     iat }`, `aud` this page's absolute address — or answers with an Apple
//     App Attest object, and the person pastes what it produced. A device
//     APP does the same through the two JSON doors below. **No script**: a
//     browser page cannot sign with a device's key, so the page is a form
//     that carries what the device made.
//   * **LINKING A SECURITY KEY BUILT INTO THIS DEVICE** — a WebAuthn platform
//     credential the person enrolled on `/portal/keys`, proven again by a
//     fresh assertion. **That step runs `/authn/webauthn.js`, the SAME
//     resource `/authn/webauthn` and `/portal/keys` run**, and only while a
//     ceremony is armed; its exception is argued below and in the root
//     `CLAUDE.md`'s table.
//
// **THE JSON DOORS** (`POST /portal/devices/challenge`, `POST
// /portal/devices/proof`) are the same act for a native app holding a
// portal session: `application/json` in and out, the challenge the
// anti-forgery token (`device_enrolment.ts` argues why that is enough).
// Neither takes an identity from the request.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md): every form names the DEVICE or the
// credential, never whose it is, and one that is not theirs is refused.
//
// ---------------------------------------------------------------------------
// THE SCRIPT, AND WHY THIS PAGE MAY RUN IT.
//
// `app.js` sets `script-src 'none'`, and a page is granted `script-src 'self'`
// only when it CANNOT WORK WITHOUT ONE. Linking a WebAuthn credential is a
// fresh ASSERTION — `navigator.credentials.get()` — and no markup makes that
// call: the signature is produced inside the authenticator. That is
// `/authn/webauthn`'s argument and `/portal/keys`' argument, and it is this
// step's whole case; the JWK proof beside it is argued the other way and
// runs none. So the relaxed policy is sent ONLY on the page that draws an
// armed link ceremony (`sendPage()`), with `app.contentSecurityPolicy()`
// keeping `frame-ancestors`, and it names one resource. **THE BUTTON UNDER
// THE SCRIPT IS REAL**: with the script blocked it posts a `link-finish`
// with no assertion, answered by a sentence saying the browser ran no
// ceremony rather than by nothing happening.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// exactly as `portal_self_issued.ts` is, and for its reason.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import devices = require('../common/devices');
import deviceEnrolment = require('../common/device_enrolment');
import deviceAttestation = require('../common/device_attestation');
import credentials = require('../common/credentials');
import webauthnPolicy = require('../authn/webauthn_policy');
import authn = require('../authn/authn');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_self_issued.ts`'s context.
interface PortalContext {
  app: {
    get(path: string, handler: (req: Req, res: Res) => unknown): unknown;
    post(path: string, handler: (req: Req, res: Res) => unknown): unknown;
    contentSecurityPolicy?(overrides: Json): string;
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
  deviceEnrolment: Json;
  credentials: Json;
  webauthnPolicy: Json;
  authn: Json;
}

const ACTIONS = ['remove', 'challenge', 'prove', 'cancel-proof',
                 'link-begin', 'link-finish', 'link-cancel'];

class PortalDevicesPage {
  readonly PATH: string;
  readonly CHALLENGE_PATH: string;
  readonly PROOF_PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;
  private readonly JSON_CHALLENGE: Json;
  private readonly JSON_PROOF: Json;

  constructor(private readonly deps: PortalDevicesDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalDevicesPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    const text = function (max: number): Json {
      ctx.log.debug("Entering text().");
      ctx.log.debug("Leaving text().");
      return vz.string().max(max).optional();
    };
    this.PATH = ctx.BASE + '/devices';
    this.CHALLENGE_PATH = this.PATH + '/challenge';
    this.PROOF_PATH = this.PATH + '/proof';
    this.FORM = vz.object({
      action: vt.opt(vt.oneOf(ACTIONS)),
      id: text(64),
      challenge: text(128),
      proof: text(65536),
      app_attest_key_id: text(128),
      app_attest_object: text(65536),
      device: text(64),
      credential_id: text(1400),
      credential: text(65536),
      label: text(128),
      key_label: text(128),
      platform: text(32),
      model: text(128),
      os: text(128),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional()
    });
    this.JSON_CHALLENGE = vz.object({
      purpose: vz.enum(['key']).optional()
    });
    this.JSON_PROOF = vz.object({
      challenge: vz.string().min(1).max(128),
      proof: vz.string().max(65536).optional(),
      app_attest: vz.object({
        key_id: vz.string().max(128),
        attestation: vz.string().max(65536)
      }).optional(),
      device_id: vz.string().max(64).optional(),
      label: vz.string().max(128).optional(),
      key_label: vz.string().max(128).optional(),
      platform: vz.string().max(32).optional(),
      model: vz.string().max(128).optional(),
      os: vz.string().max(128).optional()
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

  // The `aud` a key proof names: this page's absolute address, on the base
  // the request arrived on so a realm's page names the realm's.
  audienceOf(req: Req): string {
    this.ctx.log.debug("Entering PortalDevicesPage.audienceOf().");
    this.ctx.log.debug("Leaving PortalDevicesPage.audienceOf().");
    return this.ctx.baseUrlOf(req) + this.PATH;
  }

  // The device choice and the descriptive fields, shared by both forms.
  private targetFields(held: Json[]): string {
    const { esc } = this.ctx;
    const { devices } = this.deps;
    this.ctx.log.debug("Entering PortalDevicesPage.targetFields().");
    const out = '<label for="dev-target">Which device</label>' +
      '<select id="dev-target" name="device"><option value="">A new ' +
      'device</option>' + held.map(function (one: Json) {
        return '<option value="' + esc(one.id) + '">' + esc(one.label) +
               ' (another key on it)</option>';
      }).join('') + '</select>' +
      '<label for="dev-label">Name it (a new device only)</label>' +
      '<input type="text" id="dev-label" name="label" maxlength="128" ' +
      'placeholder="my phone">' +
      '<label for="dev-platform">Platform</label>' +
      '<select id="dev-platform" name="platform"><option value="">—' +
      '</option>' + devices.PLATFORMS.map(function (p: string) {
        return '<option value="' + esc(p) + '">' + esc(p) + '</option>';
      }).join('') + '</select>' +
      '<label for="dev-model">Model</label>' +
      '<input type="text" id="dev-model" name="model" maxlength="128">' +
      '<label for="dev-os">Operating system</label>' +
      '<input type="text" id="dev-os" name="os" maxlength="128">';
    this.ctx.log.debug("Leaving PortalDevicesPage.targetFields().");
    return out;
  }

  // THE JWK PROOF block: the challenge form, or the proof form while one
  // is held.
  private proofBlock(session: Json, held: Json[], audience: string): string {
    const { esc, websecurity } = this.ctx;
    const { deviceEnrolment } = this.deps;
    this.ctx.log.debug("Entering PortalDevicesPage.proofBlock().");
    const csrf = websecurity.field(session.id);
    const pending = deviceEnrolment.pendingFor(session.id, 'key');
    const PATH = this.PATH;
    if (!pending) {
      this.ctx.log.debug("Leaving PortalDevicesPage.proofBlock(). Form.");
      return '<h2>Register a device by proving its key</h2>' +
        '<p class="sub">Your device\'s app signs a challenge from this page ' +
        'with the key it will be known by — or, on an iPhone, attests the ' +
        'key with Apple App Attest — and you paste what it produced. An ' +
        'Android key attested by the phone\'s secure hardware, or an App ' +
        'Attest key, is recorded <strong>attested</strong>; any other key ' +
        'is self-asserted, which a product deployment does not ' +
        'register.</p><form method="post" action="' + esc(PATH) + '">' +
        csrf + '<input type="hidden" name="action" value="challenge">' +
        '<button type="submit">Get a challenge</button></form>';
    }
    this.ctx.log.debug("Leaving PortalDevicesPage.proofBlock(). Held.");
    return '<h2>Register a device by proving its key</h2>' +
      '<p class="sub">Answer this challenge before ' +
      esc(new Date(Number(pending.expiresAt)).toISOString()) + ', once.</p>' +
      '<table><tr><th>Challenge (the proof\'s <code>nonce</code>)</th><td>' +
      '<code id="dev-challenge">' + esc(pending.challenge) + '</code></td>' +
      '</tr><tr><th>Audience (<code>aud</code>)</th><td><code ' +
      'id="dev-audience">' + esc(audience) + '</code></td></tr><tr><th>' +
      'Header <code>typ</code></th><td><code>' +
      esc(deviceAttestation.PROOF_TYP) + '</code>, with the public key in ' +
      '<code>jwk</code> (and an Android attestation chain in ' +
      '<code>x5c</code>)</td></tr></table>' +
      '<form method="post" action="' + esc(PATH) + '">' + csrf +
      '<input type="hidden" name="action" value="prove">' +
      '<input type="hidden" name="challenge" value="' +
      esc(pending.challenge) + '">' +
      '<label for="dev-proof">The key proof (a compact JWS)</label>' +
      '<textarea id="dev-proof" name="proof" rows="4"></textarea>' +
      '<p class="sub">Or, from an iPhone app, the App Attest key id and ' +
      'attestation object (base64), made with the challenge\'s SHA-256 as ' +
      'the client data hash:</p>' +
      '<label for="dev-aa-key">App Attest key id</label>' +
      '<input type="text" id="dev-aa-key" name="app_attest_key_id" ' +
      'maxlength="128">' +
      '<label for="dev-aa-object">App Attest attestation object</label>' +
      '<textarea id="dev-aa-object" name="app_attest_object" rows="4">' +
      '</textarea>' +
      '<label for="dev-key-label">Name the key (optional)</label>' +
      '<input type="text" id="dev-key-label" name="key_label" ' +
      'maxlength="128">' + this.targetFields(held) +
      '<button type="submit">Register</button></form>' +
      '<form method="post" action="' + esc(PATH) + '">' + csrf +
      '<input type="hidden" name="action" value="cancel-proof">' +
      '<button class="secondary" type="submit">Cancel</button></form>';
  }

  // THE WEBAUTHN LINK block, step one: which credential, and which device.
  private linkBlock(session: Json, held: Json[]): string {
    const { esc, websecurity } = this.ctx;
    const { credentials } = this.deps;
    this.ctx.log.debug("Entering PortalDevicesPage.linkBlock().");
    const who = String(session.user.username);
    const keys = (credentials.keysOf(who) || []).filter(function (k: Json) {
      return String(k.attachment || '') !== 'cross-platform';
    });
    if (!keys.length) {
      this.ctx.log.debug("Leaving PortalDevicesPage.linkBlock(). None.");
      return '<h2>Link a security key built into a device</h2>' +
        '<p class="note">You have no security key built into a device ' +
        '(a platform authenticator) to link. Enrol one on <a href="' +
        esc(this.ctx.BASE + '/keys') + '">Security keys</a> first; a ' +
        'roaming key is carried between devices and identifies none of ' +
        'them.</p>';
    }
    this.ctx.log.debug("Leaving PortalDevicesPage.linkBlock(). Form.");
    return '<h2>Link a security key built into a device</h2>' +
      '<p class="sub">You will be asked to use the key once more, on the ' +
      'device it is built into. A key whose attestation this service ' +
      'verified and trusted when you enrolled it is recorded attested.</p>' +
      '<form method="post" action="' + esc(this.PATH) + '">' +
      websecurity.field(session.id) +
      '<input type="hidden" name="action" value="link-begin">' +
      '<label for="dev-cred">Which security key</label>' +
      '<select id="dev-cred" name="credential_id">' +
      keys.map(function (k: Json) {
        const att = k.attestation || {};
        return '<option value="' + esc(k.credentialId) + '">' +
          esc(k.label || 'security key') + ' — ' +
          esc(att.verified && att.trusted ? 'attestation trusted'
                                          : 'attestation not trusted') +
          '</option>';
      }).join('') + '</select>' + this.targetFields(held) +
      '<button type="submit">Link it</button></form>';
  }

  // THE WEBAUTHN LINK, step two: the armed ceremony.
  private ceremonyBlock(session: Json, pending: Json, base: string): string {
    const { esc, websecurity } = this.ctx;
    const { authn, webauthnPolicy } = this.deps;
    this.ctx.log.debug("Entering PortalDevicesPage.ceremonyBlock().");
    const rpId = authn.rpIdOf(base);
    const csrf = websecurity.field(session.id);
    this.ctx.log.debug("Leaving PortalDevicesPage.ceremonyBlock().");
    return '<h2>Use your security key</h2>' +
      '<p class="note">Your browser is about to ask for the security key ' +
      'you chose, on the device it is built into.</p>' +
      '<div id="wa-data" data-challenge="' + esc(pending.challenge) + '"' +
      ' data-rpid="' + esc(rpId) + '"' +
      ' data-user="' + esc(session.user.username) + '"' +
      ' data-allow="' + esc((pending.detail || {}).credentialId || '') + '"' +
      ' data-exclude=""' +
      ' data-options="' +
      esc(JSON.stringify(webauthnPolicy.requestOptions(rpId))) + '"' +
      ' data-mode="get"></div>' +
      '<button id="wa-go" type="button">Use the security key</button>' +
      '<form method="post" action="' + esc(this.PATH) + '" id="wa-form">' +
      csrf + '<input type="hidden" name="action" value="link-finish">' +
      '<input type="hidden" name="challenge" value="' +
      esc(pending.challenge) + '">' +
      '<input type="hidden" name="credential" id="wa-credential">' +
      '<button class="secondary" type="submit">My browser did not ask ' +
      '&mdash; tell me why</button></form>' +
      '<form method="post" action="' + esc(this.PATH) + '">' + csrf +
      '<input type="hidden" name="action" value="link-cancel">' +
      '<button class="secondary" type="submit">Cancel</button></form>' +
      '<script src="' + esc(authn.WEBAUTHN_SCRIPT_PATH) + '"></script>';
  }

  private keysCell(one: Json): string {
    const { esc } = this.ctx;
    this.ctx.log.debug("Entering PortalDevicesPage.keysCell().");
    this.ctx.log.debug("Leaving PortalDevicesPage.keysCell().");
    return one.keys.length ? one.keys.map(function (k: Json) {
      return esc(k.kind) + ' (' + esc((k.attestation && k.attestation.level) ||
                                       'self-asserted') + ')';
    }).join('<br>') : '—';
  }

  page(session: Json, message: unknown, error: unknown, base: string): Json {
    const { log, shell, esc, websecurity } = this.ctx;
    const { devices, deviceEnrolment } = this.deps;
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
                       : '—') + '</td><td>' + self.keysCell(one) +
        '</td><td>' + esc(one.attestation.level) + '</td><td>' +
        esc(one.enrolment.method) + '</td><td>' +
        esc(one.lastUsed || '') +
        '</td><td><form method="post" action="' + esc(PATH) + '">' + csrf +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="id" value="' + esc(one.id) + '">' +
        '<button class="danger" type="submit">Remove</button></form>' +
        '</td></tr>';
    });
    const linking = deviceEnrolment.pendingFor(session.id, 'webauthn');
    const body = '<div class="card"><h2>Your devices</h2>' +
      '<p class="sub">The phones and computers that are yours: the ones ' +
      'you registered here, the ones you have signed in on with an app ' +
      'that shares its sign-in with the other apps on the device (OpenID ' +
      'Connect Native SSO), the ones a certificate was issued to, and any ' +
      'an administrator registered for you. Remove one you no longer ' +
      'have: its apps can no longer share a sign-in, and ask you to sign ' +
      'in again.</p>' +
      (held.length
        ? '<table><tr><th>Device</th><th>Applications</th><th>Shared ' +
          'sign-in</th><th>Keys</th><th>Attestation</th><th>Registered ' +
          'by</th><th>Last used</th><th></th></tr>' + rows.join('') +
          '</table>'
        : '<p id="devices-none">None.</p>') + '</div>' +
      '<div class="card">' + (linking
        ? this.ceremonyBlock(session, linking, base)
        : this.proofBlock(session, held, base + PATH) +
          this.linkBlock(session, held)) + '</div>';
    log.debug("Leaving PortalDevicesPage.page().");
    return { html: shell(this.PATH, session, message, error, body),
             ceremony: !!linking };
  }

  // A drawn page: the relaxed policy only when a ceremony is armed.
  private sendPage(res: Res, status: number, drawn: Json): unknown {
    const { log, app } = this.ctx;
    log.debug("Entering PortalDevicesPage.sendPage().");
    if (drawn.ceremony && typeof app.contentSecurityPolicy === 'function') {
      res.set('Content-Security-Policy',
              app.contentSecurityPolicy({ 'script-src': "'self'" }));
    }
    log.debug("Leaving PortalDevicesPage.sendPage().");
    return this.ctx.send(res, status, drawn.html);
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
    return this.sendPage(res, 200, this.page(session, message, null,
                                             ctx.baseUrlOf(req)));
  }

  // Back to the page after a POST: ABSOLUTE, ON `baseUrlOf(req)` (#164) — a
  // bare `/portal/devices` Location is answered by the DEFAULT realm,
  // because nothing adds the realm prefix to a Location on the way out
  // (`portal_claim_sources.ts` found it first; portal/CLAUDE.md).
  private back(req: Req, res: Res, done?: string): unknown {
    this.ctx.log.debug("Entering PortalDevicesPage.back().");
    res.status(303).set('Location', this.ctx.baseUrlOf(req) + this.PATH +
      (done ? '?done=' + encodeURIComponent(done) : '')).end();
    this.ctx.log.debug("Leaving PortalDevicesPage.back().");
    return undefined;
  }

  // One audit row for an enrolment attempt.
  private audited(who: string, action: string, result: Json,
                  detail: Json): void {
    const ctx = this.ctx;
    ctx.log.debug("Entering PortalDevicesPage.audited(). " + action);
    ctx.audit.record({
      category: 'authentication', action: 'portal.device.' + action,
      errorCode: result.ok ? undefined
        : (ctx.errorCodes.codeOf(result) || 'STS-DEVICE-0026'),
      actor: who, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? '' : 'could not ') + action + ' a device on ' +
               this.PATH,
      detail: Object.assign({ errors: result.ok ? undefined
                                                : result.errors }, detail) });
    ctx.log.debug("Leaving PortalDevicesPage.audited().");
  }

  private refusedPage(req: Req, res: Res, session: Json, result: Json,
                      fallback: string): unknown {
    const ctx = this.ctx;
    ctx.log.debug("Entering PortalDevicesPage.refusedPage().");
    ctx.errorCodes.mark(res, ctx.errorCodes.codeOf(result) || fallback);
    ctx.log.debug("Leaving PortalDevicesPage.refusedPage().");
    return this.sendPage(res, Number(result.status) || 400,
      this.page(session, null, (result.errors || [result.error])[0],
                ctx.baseUrlOf(req)));
  }

  private async postPage(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { devices, deviceEnrolment, authn } = this.deps;
    const PATH = this.PATH;
    log.debug('Entering POST ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      log.debug('Leaving POST ' + PATH + '. Not signed in.');
      return undefined;
    }
    const who = String(session.user.username);
    const base = ctx.baseUrlOf(req);
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
      return this.sendPage(res, 403, this.page(session, null, csrf.detail,
                                               base));
    }
    const action = String(body.action || 'remove');
    if (action === 'challenge') {
      const issued = deviceEnrolment.issueChallenge({ sessionId: session.id,
        username: who, purpose: 'key' });
      log.debug('Leaving POST ' + PATH + '. Challenge issued.');
      return issued.ok ? this.back(req, res)
        : this.refusedPage(req, res, session, issued, 'STS-DEVICE-0016');
    }
    if (action === 'cancel-proof' || action === 'link-cancel') {
      deviceEnrolment.abandon(session.id, action === 'cancel-proof'
        ? 'key' : 'webauthn');
      log.debug('Leaving POST ' + PATH + '. Cancelled.');
      return this.back(req, res);
    }
    if (action === 'prove') {
      const appAttest = body.app_attest_object
        ? { keyId: String(body.app_attest_key_id || ''),
            attestation: String(body.app_attest_object) } : null;
      const done = await deviceEnrolment.proveKey({ username: who,
        sessionId: session.id, challenge: String(body.challenge || ''),
        audience: base + PATH, proof: body.proof || '', appAttest: appAttest,
        deviceId: body.device || '', label: body.label,
        platform: body.platform, model: body.model, os: body.os,
        keyLabel: body.key_label });
      this.audited(who, 'prove', done, { via: appAttest ? 'app-attest'
                                                        : 'jwk-proof' });
      if (!done.ok) {
        log.debug('Leaving POST ' + PATH + '. Proof refused.');
        return this.refusedPage(req, res, session, done, 'STS-DEVICE-0017');
      }
      log.debug('Leaving POST ' + PATH + '. Registered.');
      return this.back(req, res, 'That key is registered.');
    }
    if (action === 'link-begin') {
      const begun = deviceEnrolment.beginLink({ username: who,
        sessionId: session.id, credentialId: body.credential_id,
        deviceId: body.device || '', label: body.label,
        platform: body.platform, model: body.model, os: body.os });
      log.debug('Leaving POST ' + PATH + '. Link begun: ' + begun.ok);
      return begun.ok ? this.back(req, res)
        : this.refusedPage(req, res, session, begun, 'STS-DEVICE-0022');
    }
    if (action === 'link-finish') {
      let credential: Json = null;
      try {
        credential = JSON.parse(String(body.credential || 'null'));
      } catch (e) {
        log.debug("Caught in PortalDevicesPage.postPage(): " +
                  ((e && e.message) || e));
        // The real button under the script, or a hand-made POST: the
        // sentence below is the answer, not a parse error.
        credential = null;
      }
      const ran = !!(credential && credential.response);
      const rpRefusal = ran ? authn.rpIdProblem(base) : '';
      let done: Json = null;
      if (!ran) {
        deviceEnrolment.abandon(session.id, 'webauthn');
        done = ctx.errorCodes.mark({ ok: false, errors: ['Your browser did ' +
          'not run the ceremony, so nothing was linked. This one step ' +
          'needs JavaScript — a security key signs inside the ' +
          'authenticator, and no form can do it.'] }, 'STS-DEVICE-0022');
      } else if (rpRefusal) {
        done = ctx.errorCodes.mark({ ok: false, errors: [rpRefusal] },
                                   'STS-DEVICE-0022');
      } else {
        done = await deviceEnrolment.finishLink({ username: who,
          sessionId: session.id, challenge: String(body.challenge || ''),
          credential: credential,
          origin: authn.expectedOriginFor(base, credential),
          rpId: authn.rpIdOf(base) });
      }
      this.audited(who, 'link', done, { via: 'webauthn' });
      if (!done.ok) {
        log.debug('Leaving POST ' + PATH + '. Link refused.');
        return this.refusedPage(req, res, session, done, 'STS-DEVICE-0022');
      }
      log.debug('Leaving POST ' + PATH + '. Linked.');
      return this.back(req, res, 'That security key is linked.');
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
      return this.sendPage(res, 400, this.page(session, null, result.error,
                                               base));
    }
    log.debug('Leaving POST ' + PATH + '. Removed.');
    return this.back(req, res, 'That device is removed.');
  }

  // A JSON answer.
  private json(res: Res, status: number, payload: Json): unknown {
    this.ctx.log.debug("Entering PortalDevicesPage.json(). " + status);
    res.status(status).set('Cache-Control', 'no-store')
      .type('application/json').send(JSON.stringify(payload));
    this.ctx.log.debug("Leaving PortalDevicesPage.json().");
    return undefined;
  }

  // Both JSON doors take `application/json` and nothing else.
  private notJson(req: Req, res: Res): boolean {
    this.ctx.log.debug("Entering PortalDevicesPage.notJson().");
    const type = String(req.headers['content-type'] || '');
    if (/^application\/json\b/i.test(type)) {
      this.ctx.log.debug("Leaving PortalDevicesPage.notJson(). JSON.");
      return false;
    }
    this.ctx.errorCodes.mark(res, 'STS-DEVICE-0026');
    this.json(res, 415, { ok: false, error: 'invalid_request',
      error_description: 'This door takes application/json.' });
    this.ctx.log.debug("Leaving PortalDevicesPage.notJson(). Refused.");
    return true;
  }

  // POST /portal/devices/challenge — a `key` challenge for a device app.
  private postChallenge(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { deviceEnrolment } = this.deps;
    ctx.log.debug('Entering POST ' + this.CHALLENGE_PATH + '.');
    const session = ctx.requireSignIn(req, res, this.CHALLENGE_PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      ctx.log.debug('Leaving POST ' + this.CHALLENGE_PATH + '. Not signed ' +
                    'in.');
      return undefined;
    }
    if (this.notJson(req, res)) {
      ctx.log.debug('Leaving POST ' + this.CHALLENGE_PATH + '. Not JSON.');
      return undefined;
    }
    const posted = ctx.validation.checkParsed(ctx.parseBody(req), 'body',
                                              this.JSON_CHALLENGE);
    if (!posted.ok) {
      ctx.errorCodes.mark(res, 'STS-DEVICE-0026');
      ctx.log.debug('Leaving POST ' + this.CHALLENGE_PATH + '. Malformed.');
      return this.json(res, 400, { ok: false, error: 'invalid_request',
                                   error_description: 'The body is not ' +
                                   '{ "purpose": "key" }.' });
    }
    const issued = deviceEnrolment.issueChallenge({ sessionId: session.id,
      username: String(session.user.username), purpose: 'key' });
    if (!issued.ok) {
      ctx.errorCodes.mark(res, ctx.errorCodes.codeOf(issued) ||
                               'STS-DEVICE-0016');
      ctx.log.debug('Leaving POST ' + this.CHALLENGE_PATH + '. Refused.');
      return this.json(res, 400, { ok: false, error: 'invalid_request',
                                   error_description: issued.error });
    }
    ctx.log.debug('Leaving POST ' + this.CHALLENGE_PATH + '.');
    return this.json(res, 200, { ok: true, challenge: issued.challenge,
      audience: this.audienceOf(req), typ: deviceAttestation.PROOF_TYP,
      expires_at: issued.expiresAt,
      proof_endpoint: ctx.baseUrlOf(req) + this.PROOF_PATH });
  }

  // POST /portal/devices/proof — the device app's answer.
  private async postProof(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { devices, deviceEnrolment } = this.deps;
    ctx.log.debug('Entering POST ' + this.PROOF_PATH + '.');
    const session = ctx.requireSignIn(req, res, this.PROOF_PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      ctx.log.debug('Leaving POST ' + this.PROOF_PATH + '. Not signed in.');
      return undefined;
    }
    if (this.notJson(req, res)) {
      ctx.log.debug('Leaving POST ' + this.PROOF_PATH + '. Not JSON.');
      return undefined;
    }
    const posted = ctx.validation.checkParsed(ctx.parseBody(req), 'body',
                                              this.JSON_PROOF);
    if (!posted.ok) {
      ctx.errorCodes.mark(res, 'STS-DEVICE-0026');
      ctx.log.debug('Leaving POST ' + this.PROOF_PATH + '. Malformed.');
      return this.json(res, 400, { ok: false, error: 'invalid_request',
        error_description: 'The body is { challenge, proof | app_attest: ' +
          '{ key_id, attestation }, device_id?, label?, key_label?, ' +
          'platform?, model?, os? }.' });
    }
    const b = posted.value;
    const who = String(session.user.username);
    const done = await deviceEnrolment.proveKey({ username: who,
      sessionId: session.id, challenge: b.challenge,
      audience: this.audienceOf(req), proof: b.proof || '',
      appAttest: b.app_attest ? { keyId: b.app_attest.key_id,
                                  attestation: b.app_attest.attestation }
                              : null,
      deviceId: b.device_id || '', label: b.label, platform: b.platform,
      model: b.model, os: b.os, keyLabel: b.key_label });
    this.audited(who, 'prove', done, { via: b.app_attest ? 'app-attest'
                                                         : 'jwk-proof',
                                       door: 'json' });
    if (!done.ok) {
      ctx.errorCodes.mark(res, ctx.errorCodes.codeOf(done) ||
                               'STS-DEVICE-0017');
      ctx.log.debug('Leaving POST ' + this.PROOF_PATH + '. Refused.');
      return this.json(res, Number(done.status) || 400, { ok: false,
        error: 'invalid_request',
        error_description: done.error || (done.errors || [])[0] });
    }
    const device = done.device ? devices.byId(done.device.id) : null;
    ctx.log.debug('Leaving POST ' + this.PROOF_PATH + '. Registered.');
    return this.json(res, 201, { ok: true,
      device: device ? devices.view(device) : null,
      key: done.key || null });
  }

  // An enrolment that THREW: recorded under its code and answered 500,
  // never left as an unhandled rejection with the browser waiting.
  private failed(res: Res, e: Json): unknown {
    const ctx = this.ctx;
    ctx.log.debug("Entering PortalDevicesPage.failed().");
    ctx.log.info(ctx.errorCodes.tag('STS-DEVICE-0026') + 'portal: a device ' +
                 'enrolment threw: ' + ((e && e.stack) || e));
    ctx.errorCodes.mark(res, 'STS-DEVICE-0026');
    if (!res.headersSent) {
      res.status(500).set('Cache-Control', 'no-store').type('text/plain')
        .send('The device could not be registered just now.');
    }
    ctx.log.debug("Leaving PortalDevicesPage.failed().");
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
      return self.postPage(req, res).catch(function (e: Json) {
        return self.failed(res, e);
      });
    });
    app.post(this.CHALLENGE_PATH, function (req, res) {
      return self.postChallenge(req, res);
    });
    app.post(this.PROOF_PATH, function (req, res) {
      return self.postProof(req, res).catch(function (e: Json) {
        return self.failed(res, e);
      });
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
    return { log: helpers.log, devices: devices,
             deviceEnrolment: deviceEnrolment, credentials: credentials,
             webauthnPolicy: webauthnPolicy, authn: authn };
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
