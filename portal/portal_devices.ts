// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// **SINCE #568 THESE ARE `/account-api` OPERATIONS** — the page's view and
// its form, and the two JSON doors a device app uses — and the page is drawn
// in the browser by `web_devices.ts`.
//
// **A PERSON REGISTERS A DEVICE HERE BY PROVING A KEY** (#164 phase 2,
// decision 6b; `common/device_enrolment.ts` argues the flows):
//
//   * **A JWK PROOF.** "Get a challenge" issues one bound to the sign-on
//     session the access token was issued on; the device signs a
//     `device-key-proof+jwt` JWS over it — `{ nonce, aud, iat }`, `aud` the
//     PAGE's absolute address, `<base>/portal/devices`, which is unchanged
//     by #568 so a device app built against it goes on working — or answers
//     with an Apple App Attest object, and the person pastes what it
//     produced. A device APP does the same through the two JSON doors below.
//   * **LINKING A SECURITY KEY BUILT INTO THIS DEVICE** — a WebAuthn platform
//     credential the person enrolled on `/portal/keys`, proven again by a
//     fresh assertion. The view carries the armed ceremony (`linking`) and
//     the portal's runtime runs it (`web_portal_webauthn.ts`) — the page's
//     one step that cannot work without script, because the signature is
//     produced inside the authenticator. A `link-finish` with no assertion
//     is answered by a sentence saying the browser ran no ceremony.
//
// **THE JSON DOORS** (`POST /account-api/devices/challenge` and
// `/account-api/devices/proof`, `/portal/devices/challenge` and `/proof`
// until #568) are the same act for a native app: `application/json` in and
// out, under the same access token as everything else here, the challenge
// the anti-forgery token (`device_enrolment.ts` argues why that is enough).
// Neither takes an identity from the request.
//
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md): every form names the DEVICE or the
// credential, never whose it is, and one that is not theirs is refused.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');
import devices = require('../common/devices');
import deviceEnrolment = require('../common/device_enrolment');
import deviceAttestation = require('../common/device_attestation');
import credentials = require('../common/credentials');
import webauthnPolicy = require('../authn/webauthn_policy');
import authn = require('../authn/authn');
import webauthnCeremonies = require('../authn/webauthn_ceremonies');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalDevicesDeps {
  log: { debug(message: string): void; info(message: string): void };
  devices: Json;
  deviceEnrolment: Json;
  credentials: Json;
  webauthnPolicy: Json;
  authn: Json;
  browserDevices: Json;
}

const ACTIONS = ['remove', 'challenge', 'prove', 'cancel-proof',
                 'link-begin', 'link-finish', 'link-cancel',
                 'remember-browser'];

// One optional text field of the form.
function text(max: number): Json {
  helpers.log.debug("Entering text().");
  helpers.log.debug("Leaving text().");
  return vz.string().max(max).optional();
}

const FORM = vz.object({
  action: vt.opt(vt.oneOf(ACTIONS))
    .describe('What to do; `remove` where none is named.'),
  id: text(64).describe('`remove`: the device.'),
  challenge: text(128)
    .describe('`prove`, `link-finish`: the challenge being answered.'),
  proof: text(65536).describe('`prove`: the device-key-proof+jwt JWS.'),
  app_attest_key_id: text(128)
    .describe('`prove`: an App Attest key id, beside its object.'),
  app_attest_object: text(65536)
    .describe('`prove`: an App Attest attestation object.'),
  device: text(64)
    .describe('`prove`, `link-begin`: an existing device to add the key ' +
              'to; a new device where empty.'),
  credential_id: text(1400)
    .describe('`link-begin`: the passkey (built into this device) to link.'),
  credential: text(65536)
    .describe('`link-finish`: the WebAuthn assertion, as JSON.'),
  label: text(128).describe('The device\'s name.'),
  key_label: text(128).describe('`prove`: the key\'s name.'),
  platform: text(32).describe('The device\'s platform.'),
  model: text(128).describe('The device\'s model.'),
  os: text(128).describe('The device\'s operating system.')
});

const JSON_CHALLENGE = vz.object({
  purpose: vz.enum(['key']).optional()
    .describe('What the challenge is for; `key`, the only one.')
});

const JSON_PROOF = vz.object({
  challenge: vz.string().min(1).max(128)
    .describe('The challenge `devices/challenge` issued.'),
  proof: vz.string().max(65536).optional()
    .describe('The device-key-proof+jwt JWS.'),
  app_attest: vz.object({
    key_id: vz.string().max(128),
    attestation: vz.string().max(65536)
  }).optional().describe('Or an Apple App Attest key and object.'),
  device_id: vz.string().max(64).optional()
    .describe('An existing device of yours to add the key to.'),
  label: vz.string().max(128).optional(),
  key_label: vz.string().max(128).optional(),
  platform: vz.string().max(32).optional(),
  model: vz.string().max(128).optional(),
  os: vz.string().max(128).optional()
});

/**
 * `/portal/devices`' account API operations: where a person sees and manages
 * their own registered devices, and registers one by proving a key (#130,
 * #164).
 */
class PortalDevices {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalDevicesDeps) {
    deps.log.debug("Entering PortalDevices.constructor().");
    deps.log.debug("Leaving PortalDevices.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalDevicesDeps {
    helpers.log.debug("Entering PortalDevices.defaultDeps().");
    helpers.log.debug("Leaving PortalDevices.defaultDeps().");
    return { log: helpers.log, devices: devices,
             deviceEnrolment: deviceEnrolment, credentials: credentials,
             webauthnPolicy: webauthnPolicy, authn: authn,
             browserDevices: require('../common/browser_devices') };
  }

  // Whether a device's secret is good for a session still live and still
  // this person's — `oauth2.ts`'s `sessionIsLive()`, asked of `authn`
  // directly because the portal is loaded before the authorization server.
  /**
   * Whether a device's Native SSO session is live and this person's.
   *
   * @param sid - the session
   * @param who - the person
   * @returns whether it is
   */
  private live(sid: string, who: string): boolean {
    const { log, authn } = this.deps;
    log.debug("Entering PortalDevices.live().");
    const held = sid ? authn.sessionById(sid) : null;
    log.debug("Leaving PortalDevices.live().");
    return !!held && !authn.sessionEnded(held) &&
      held.authenticated !== false && !!held.user &&
      String(held.user.username || '') === who;
  }

  // The `aud` a key proof names: the PAGE's absolute address, on the base
  // the request arrived on so a realm's page names the realm's — the same
  // address before and after #568, for the JSON doors as for the form.
  /**
   * The audience a key proof must name.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @returns the page's absolute address
   */
  audienceOf(ctx: AccountContext, req: Json): string {
    const { log } = this.deps;
    log.debug("Entering PortalDevices.audienceOf().");
    log.debug("Leaving PortalDevices.audienceOf().");
    return ctx.baseUrlOf(req) + ctx.PORTAL + '/devices';
  }

  /**
   * The page's view: the devices, the key-proof step, the passkeys that can
   * be linked, the armed link ceremony, and whether a browser may be
   * remembered.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param caller - the signed-in person
   * @returns the view
   */
  view(ctx: AccountContext, req: Json, caller: AccountCaller): Json {
    const { log, devices, deviceEnrolment, credentials, authn,
            webauthnPolicy, browserDevices } = this.deps;
    const self = this;
    log.debug("Entering PortalDevices.view().");
    const who = caller.username;
    const sid = caller.session.id;
    const base = ctx.baseUrlOf(req);
    // The device names, applications, key kinds, attestation levels and
    // enrolment methods are data and are drawn as they are (#539). Never the
    // secret's hash or its session id (`Devices.view()`).
    const held = devices.listFor(who).map(function (one: Json): Json {
      const v = devices.view(one, function (s: string): boolean {
        return self.live(s, who);
      });
      return { id: v.id, label: v.label,
               applications: (v.applications || []).map(function (dn: string) {
                 return String(dn).split(',')[0].replace(/^cn=/i, '');
               }),
               nativeSso: !!v.nativeSso, sessionLive: !!v.sessionLive,
               keys: (v.keys || []).map(function (k: Json): Json {
                 return { kind: String(k.kind || ''),
                          level: String((k.attestation &&
                                         k.attestation.level) ||
                                        'self-asserted') };
               }),
               attestation: String((v.attestation || {}).level || ''),
               enrolment: String((v.enrolment || {}).method || ''),
               lastUsed: v.lastUsed || null };
    });
    const pendingKey = sid ? deviceEnrolment.pendingFor(sid, 'key') : null;
    const linking = sid ? deviceEnrolment.pendingFor(sid, 'webauthn') : null;
    const enrolled = credentials.keysOf(who) || [];
    const linkable = enrolled.filter(function (k: Json): boolean {
      return credentials.keyKind(k).linkable;
    }).map(function (k: Json): Json {
      const att = k.attestation || {};
      return { credentialId: String(k.credentialId),
               name: credentials.keyName(k),
               trusted: !!(att.verified && att.trusted) };
    });
    const roaming = enrolled.filter(function (k: Json): boolean {
      return !credentials.keyKind(k).linkable;
    }).map(function (k: Json): string {
      return credentials.keyKind(k).name;
    });
    let ceremony: Json = null;
    if (linking) {
      const rpId = authn.rpIdOf(base);
      ceremony = { challenge: String(linking.challenge), rpId: rpId,
                   user: who,
                   allow: String((linking.detail || {}).credentialId || ''),
                   options: webauthnPolicy.requestOptions(rpId) };
    }
    log.debug("Leaving PortalDevices.view().");
    return {
      devices: held,
      platforms: (devices.PLATFORMS || []).slice(0),
      proof: pendingKey ? { challenge: String(pendingKey.challenge),
                            expiresAt: pendingKey.expiresAt } : null,
      audience: this.audienceOf(ctx, req),
      proofTyp: deviceAttestation.PROOF_TYP,
      linking: ceremony,
      link: { enrolled: enrolled.length, keys: linkable, roaming: roaming },
      remember: !!browserDevices.enabled()
    };
  }

  // One audit row for an enrolment attempt.
  /**
   * Records an enrolment attempt.
   *
   * @param ctx - the account API's helpers
   * @param who - the person
   * @param action - what was attempted
   * @param result - its outcome
   * @param detail - what else the row carries
   * @returns nothing
   */
  private audited(ctx: AccountContext, who: string, action: string,
                  result: Json, detail: Json): void {
    const { log } = this.deps;
    log.debug("Entering PortalDevices.audited(). " + action);
    ctx.audit.record({
      category: 'authentication', action: 'portal.device.' + action,
      errorCode: result.ok ? undefined
        : (ctx.errorCodes.codeOf(result) || 'STS-DEVICE-0026'),
      actor: who, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? '' : 'could not ') + action + ' a device on ' +
               ctx.PORTAL + '/devices',
      detail: Object.assign({ errors: result.ok ? undefined
                                                : result.errors }, detail) });
    log.debug("Leaving PortalDevices.audited().");
  }

  /**
   * A refusal, with the page's view.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param result - the refused result
   * @param fallback - the code where the result carries none
   * @returns nothing
   */
  private refused(ctx: AccountContext, req: Json, res: Json,
                  caller: AccountCaller, result: Json,
                  fallback: string): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalDevices.refused().");
    log.debug("Leaving PortalDevices.refused().");
    // error-code: none — the code is the caller's, passed in `code`.
    return ctx.refuse(res, Number(result.status) || 400,
                      ctx.errorCodes.codeOf(result) || fallback,
                      (result.errors || [result.error])[0] ||
                        'That could not be done.',
                      { view: this.view(ctx, req, caller) });
  }

  /**
   * POST: the page's form, every action.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async act(ctx: AccountContext, req: Json, res: Json,
            caller: AccountCaller, body: Json): Promise<unknown> {
    const { log, devices, deviceEnrolment, authn } = this.deps;
    log.debug("Entering PortalDevices.act().");
    const who = caller.username;
    const sid = caller.session.id;
    const base = ctx.baseUrlOf(req);
    const action = String(body.action || 'remove');
    // THE SUCCESS SENTENCES (#539), in this person's language; a refusal
    // stays English.
    const t = ctx.translatorFor(who);
    const done = function (message: string): unknown {
      return ctx.json(res, 200, { ok: true, message: message });
    };
    if (action === 'remember-browser') {
      // Not counted as a second factor given on this browser: the portal's
      // token says nothing about which browser gave it. The next sign-in
      // here with the second factor starts the skip period (#265). The
      // cookie it sets is on this answer, which the browser keeps: the API
      // is the portal's own origin.
      const remembered = this.deps.browserDevices.remember(req, res, who,
                                                           false);
      this.audited(ctx, who, 'remember-browser', remembered,
                   { via: 'portal' });
      if (!remembered.ok) {
        log.debug("Leaving PortalDevices.act(). Not remembered.");
        return this.refused(ctx, req, res, caller, remembered,
                            'STS-DEVICE-0044');
      }
      log.debug("Leaving PortalDevices.act(). Remembered.");
      return done(remembered.acted === 'already'
        ? t.text('portalDevices.done.alreadyRemembered')
        : t.text('portalDevices.done.remembered'));
    }
    // A challenge and a link are bound to the sign-on session the token was
    // issued on; a token the registry no longer places on one has none to
    // bind them to.
    if (!sid && action !== 'remove') {
      log.debug("Leaving PortalDevices.act(). No session to bind to.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0310',
        'This sign-in cannot register a device: sign in again, then try ' +
        'once more.', { view: this.view(ctx, req, caller) });
    }
    if (action === 'challenge') {
      const issued = deviceEnrolment.issueChallenge({ sessionId: sid,
        username: who, purpose: 'key' });
      log.debug("Leaving PortalDevices.act(). Challenge issued.");
      return issued.ok ? done('')
        : this.refused(ctx, req, res, caller, issued, 'STS-DEVICE-0016');
    }
    if (action === 'cancel-proof' || action === 'link-cancel') {
      deviceEnrolment.abandon(sid, action === 'cancel-proof'
        ? 'key' : 'webauthn');
      log.debug("Leaving PortalDevices.act(). Cancelled.");
      return done('');
    }
    if (action === 'prove') {
      const appAttest = body.app_attest_object
        ? { keyId: String(body.app_attest_key_id || ''),
            attestation: String(body.app_attest_object) } : null;
      const proved = await deviceEnrolment.proveKey({ username: who,
        sessionId: sid, challenge: String(body.challenge || ''),
        audience: this.audienceOf(ctx, req), proof: body.proof || '',
        appAttest: appAttest, deviceId: body.device || '',
        label: body.label, platform: body.platform, model: body.model,
        os: body.os, keyLabel: body.key_label });
      this.audited(ctx, who, 'prove', proved,
                   { via: appAttest ? 'app-attest' : 'jwk-proof' });
      if (!proved.ok) {
        log.debug("Leaving PortalDevices.act(). Proof refused.");
        return this.refused(ctx, req, res, caller, proved,
                            'STS-DEVICE-0017');
      }
      log.debug("Leaving PortalDevices.act(). Registered.");
      return done(t.text('portalDevices.done.registered'));
    }
    if (action === 'link-begin') {
      const begun = deviceEnrolment.beginLink({ username: who,
        sessionId: sid, credentialId: body.credential_id,
        deviceId: body.device || '', label: body.label,
        platform: body.platform, model: body.model, os: body.os });
      log.debug("Leaving PortalDevices.act(). Link begun: " + begun.ok);
      return begun.ok ? done('')
        : this.refused(ctx, req, res, caller, begun, 'STS-DEVICE-0022');
    }
    if (action === 'link-finish') {
      let credential: Json = null;
      try {
        credential = JSON.parse(String(body.credential || 'null'));
      } catch (e) {
        log.debug("Caught in PortalDevices.act(): " +
                  ((e && e.message) || e));
        // A browser that ran no ceremony, or a hand-made POST: the sentence
        // below is the answer, not a parse error.
        credential = null;
      }
      const ran = !!(credential && credential.response);
      const rpRefusal = ran ? authn.rpIdProblem(base) : '';
      let linked: Json = null;
      if (!ran) {
        // A client-side refusal is evidence, not a completed attempt. Keep
        // the challenge live so the person can retry the link ceremony.
        if (!(credential && credential.error)) {
          deviceEnrolment.abandon(sid, 'webauthn');
        }
        linked = ctx.errorCodes.mark({ ok: false, errors: ['Your browser ' +
          'did not run the ceremony, so nothing was linked. This one step ' +
          'needs a passkey prompt — a passkey signs inside the ' +
          'authenticator, and no form can do it.'] }, 'STS-DEVICE-0022');
      } else if (rpRefusal) {
        linked = ctx.errorCodes.mark({ ok: false, errors: [rpRefusal] },
                                     'STS-DEVICE-0022');
      } else {
        linked = await deviceEnrolment.finishLink({ username: who,
          sessionId: sid, challenge: String(body.challenge || ''),
          credential: credential,
          origin: authn.expectedOriginFor(base, credential),
          rpId: authn.rpIdOf(base) });
      }
      const assertedId = String((credential &&
        (credential.rawId || credential.id)) || '');
      const held = (credentials.keysOf(who) || []).filter(function (key: Json) {
        return String(key.credentialId) === assertedId;
      })[0] || null;
      // THE ROW'S `role` IS THE USE OF THE ASSERTION SINCE #1135, and a
      // device link answers no sign-in step, so it is empty. Until #1135 it
      // was the key's stored role, which a key no longer carries.
      webauthnCeremonies.record({ ceremony: 'assertion', door: 'portal',
        username: who, role: '',
        lane: held ? credentials.keyLane(held) : '',
        outcome: linked && linked.ok ? 'success' : 'refused',
        errorCode: linked && linked.ok ? '' : 'STS-DEVICE-0022',
        offered: held ? [credentials.keyAlgorithm(held).name] : [],
        algorithm: held ? credentials.keyAlgorithm(held).name : '',
        posted: credential || {}, req: req });
      this.audited(ctx, who, 'link', linked, { via: 'webauthn' });
      if (!linked.ok) {
        log.debug("Leaving PortalDevices.act(). Link refused.");
        return this.refused(ctx, req, res, caller, linked,
                            'STS-DEVICE-0022');
      }
      log.debug("Leaving PortalDevices.act(). Linked.");
      return done(t.text('portalDevices.done.linked'));
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
      log.debug("Leaving PortalDevices.act(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0088', result.error,
                        { view: this.view(ctx, req, caller) });
    }
    log.debug("Leaving PortalDevices.act(). Removed.");
    return done(t.text('portalDevices.done.removed'));
  }

  // A JSON door's refusal: the shape the doors always answered — OAuth's
  // `error` and `error_description` — beside the API's `errors`.
  /**
   * Refuses a JSON door's request.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param status - the HTTP status
   * @param code - the error code
   * @param description - what went wrong
   * @returns nothing
   */
  private doorRefusal(ctx: AccountContext, res: Json, status: number,
                      code: string, description: string): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalDevices.doorRefusal(). " + code);
    log.debug("Leaving PortalDevices.doorRefusal().");
    // error-code: none — the code is the caller's, passed in `code`.
    return ctx.refuse(res, status, code, description,
                      { error: 'invalid_request',
                        error_description: description });
  }

  /**
   * `POST /account-api/devices/challenge` — a `key` challenge for a device
   * app.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @returns nothing
   */
  challenge(ctx: AccountContext, req: Json, res: Json,
            caller: AccountCaller): unknown {
    const { log, deviceEnrolment } = this.deps;
    log.debug("Entering PortalDevices.challenge().");
    if (!caller.session.id) {
      log.debug("Leaving PortalDevices.challenge(). No session.");
      return this.doorRefusal(ctx, res, 400, 'STS-PORTAL-0310',
        'This token\'s sign-on session is not known here, so no challenge ' +
        'can be bound to it. Sign in again.');
    }
    const issued = deviceEnrolment.issueChallenge({
      sessionId: caller.session.id, username: caller.username,
      purpose: 'key' });
    if (!issued.ok) {
      log.debug("Leaving PortalDevices.challenge(). Refused.");
      return this.doorRefusal(ctx, res, 400,
        ctx.errorCodes.codeOf(issued) || 'STS-DEVICE-0016', issued.error);
    }
    log.debug("Leaving PortalDevices.challenge().");
    return ctx.json(res, 200, { ok: true, challenge: issued.challenge,
      audience: this.audienceOf(ctx, req), typ: deviceAttestation.PROOF_TYP,
      expires_at: issued.expiresAt,
      proof_endpoint: ctx.baseUrlOf(req) + ctx.BASE + '/devices/proof' });
  }

  /**
   * `POST /account-api/devices/proof` — the device app's answer.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param b - the checked body
   * @returns nothing
   */
  async proof(ctx: AccountContext, req: Json, res: Json,
              caller: AccountCaller, b: Json): Promise<unknown> {
    const { log, devices, deviceEnrolment } = this.deps;
    log.debug("Entering PortalDevices.proof().");
    const who = caller.username;
    if (!caller.session.id) {
      log.debug("Leaving PortalDevices.proof(). No session.");
      return this.doorRefusal(ctx, res, 400, 'STS-PORTAL-0310',
        'This token\'s sign-on session is not known here, so no challenge ' +
        'can be answered on it. Sign in again.');
    }
    const done = await deviceEnrolment.proveKey({ username: who,
      sessionId: caller.session.id, challenge: b.challenge,
      audience: this.audienceOf(ctx, req), proof: b.proof || '',
      appAttest: b.app_attest ? { keyId: b.app_attest.key_id,
                                  attestation: b.app_attest.attestation }
                              : null,
      deviceId: b.device_id || '', label: b.label, platform: b.platform,
      model: b.model, os: b.os, keyLabel: b.key_label });
    this.audited(ctx, who, 'prove', done,
                 { via: b.app_attest ? 'app-attest' : 'jwk-proof',
                   door: 'json' });
    if (!done.ok) {
      log.debug("Leaving PortalDevices.proof(). Refused.");
      return this.doorRefusal(ctx, res, Number(done.status) || 400,
        ctx.errorCodes.codeOf(done) || 'STS-DEVICE-0017',
        done.error || (done.errors || [])[0]);
    }
    const device = done.device ? devices.byId(done.device.id) : null;
    log.debug("Leaving PortalDevices.proof(). Registered.");
    return ctx.json(res, 201, { ok: true,
      device: device ? devices.view(device) : null, key: done.key || null });
  }

  /**
   * The operations, for `account-api/account_api.ts`.
   *
   * @param ctx - the account API's helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering PortalDevices.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/devices',
        operationId: 'getDevices', tag: 'Devices', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/devices',
        summary: 'Your devices, and how to register one',
        description: 'Each device you own: its applications, whether its ' +
          'Native SSO secret is live, its keys and their attestation, how ' +
          'it was registered and when it was last used. Then the key-proof ' +
          'step (`proof`: the challenge held, with the `audience` and ' +
          '`proofTyp` a proof names), the passkeys built into a device that ' +
          'can be linked (`link`) or the link ceremony armed (`linking`), ' +
          'and whether this browser may be remembered.',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(ctx, req, caller));
        } },
      { method: 'POST', path: ctx.BASE + '/devices',
        operationId: 'actOnDevices', tag: 'Devices', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/devices',
        summary: 'Registers, links, remembers or removes a device',
        description: '`challenge` then `prove` registers a device by a key ' +
          'proof (or an App Attest object); `link-begin` then `link-finish` ' +
          'links a passkey built into it by a fresh assertion; ' +
          '`remember-browser` remembers this browser (a cookie on the ' +
          'answer); `remove` removes a device and its Native SSO secret. A ' +
          'refusal carries the page\'s `view`.',
        body: FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.act(ctx, req, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/devices/challenge',
        operationId: 'deviceChallenge', tag: 'Devices', access: 'person',
        summary: 'A key-proof challenge, for a device app',
        description: 'Issues a challenge bound to the sign-on session this ' +
          'token was issued on: `{ ok, challenge, audience, typ, ' +
          'expires_at, proof_endpoint }`. The device signs a JWS of type ' +
          '`typ` over `{ nonce: challenge, aud: audience, iat }` with the ' +
          'key it registers, and posts it to `proof_endpoint`.',
        body: JSON_CHALLENGE,
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return self.challenge(ctx, req, res, caller);
        } },
      { method: 'POST', path: ctx.BASE + '/devices/proof',
        operationId: 'deviceProof', tag: 'Devices', access: 'person',
        summary: 'A device app\'s key proof',
        description: 'Answers a challenge with a key proof or an Apple App ' +
          'Attest object, registering the device (or adding the key to ' +
          '`device_id`). Answers 201 `{ ok, device, key }`.',
        body: JSON_PROOF,
        statuses: { 201: 'The device is registered: `{ ok, device, key }`.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.proof(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalDevices.accountOperations().");
    return rows;
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
const slot = new InstanceSlot<PortalDevices>(
  'portal/portal_devices',
  () => new PortalDevices(PortalDevices.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/devices`' account API operations (#130, #164, #568).
 * @namespace
 */
export = {
  PortalDevices: PortalDevices,
  installInstance: (instance: PortalDevices): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
