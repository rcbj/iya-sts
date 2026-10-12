// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_keys.ts
//
// ---------------------------------------------------------------------------
// `/portal/keys`' OPERATIONS (#568): THE PASSKEY PAGE'S VIEW, AND ITS THREE
// FORMS — enrolling one (begin, finish, cancel), removing one and renaming
// one. Moved from `portal.ts` when the portal became a static application;
// the page is drawn in the browser by `web_keys.ts`.
//
// THE PASSKEY PAGE (#470, 2026-10-06) follows the passkey management
// guidelines the ticket names: ONE heading, *Passkeys*, over every kind, the
// keys grouped as *on your devices* and *on security keys*
// (`credentials.keyGroup()`), each row a name (the owner's, else the
// provider's, else the group's), *Created* and *Last used*, Rename and Remove,
// and everything technical folded into a *Details* fold. Two calls to action,
// *Create a passkey* and *Use a security key*, and a nickname asked for AFTER
// the ceremony: the success lands on `?named=<id>` and the page opens that
// key's rename form. The view carries every one of those facts COMPUTED here,
// because the renderer reads no store: the group, the name, the provider, the
// algorithm, what the attestation proved, and the three refusals the realm's
// passkey policy makes of a key at sign-in (#528, #529, #530).
//
// ADDING A KEY (2026-09-10) is the ordinary WebAuthn registration flow — a
// signed-in person registering a credential — and it is what made a BACKUP
// possible. Two steps: `begin` mints a challenge and holds it
// (`credentials.beginKeyEnrolment()`, which checks the policy at the door:
// the page is markup and this is the door), the page draws the ceremony
// while one is held, and `finish` verifies the answer with the same two
// address rules the sign-in screen applies (2026-09-12) — an RP ID that does
// not fit is refused rather than replaced, `webauthn.allowedOrigins` decides
// the origin — asked of `authn.ts` so the two ceremonies cannot differ. The
// base they are asked with is the one this API call arrived on, which is the
// portal's own origin and realm prefix, exactly what the page's form posted
// to before #568.
//
// **THE CREDENTIAL ID IS THE ONE IDENTIFIER THESE OPERATIONS TAKE FROM A
// BODY, AND THE USERNAME NEVER IS**: `removeKey()` and `renameKey()` look the
// id up among THIS PERSON's keys — the token's subject — so one belonging to
// somebody else matches nothing (OWASP A01, `portal/CLAUDE.md`).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');
import validation = require('../common/validation');
import passkeyPolicy = require('../common/passkey_policy');
import webauthnPolicy = require('../authn/webauthn_policy');
import authn = require('../authn/authn');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

// `/portal/keys`' query (#470): `named`, the passkey just registered, whose
// nickname form the page opens.
const KEYS_QUERY = vz.object({
  named: vt.opt(vt.base64url)
    .describe('The passkey just registered: its rename form is drawn open.')
});

// ENROLLING ONE (2026-09-10). `credential` is the browser's ceremony result
// as JSON — a string here and parsed in the handler, exactly as `authn.ts`'s
// WEBAUTHN_FORM carries it, because what is inside it is decided by the
// WebAuthn verifier and a schema here would be a second opinion about an
// object this file does not own.
const ENROL_KEY_FORM = vz.object({
  action: vt.opt(vt.oneOf(['begin', 'finish', 'cancel']))
    .describe('`begin` mints a challenge, `finish` answers it, `cancel` ' +
              'drops it.'),
  role: vt.opt(vt.oneOf(['primary', 'mfa']))
    .describe('`begin`: instead of a password, or a second step.'),
  // WHICH CALL TO ACTION WAS PRESSED (#470): *Create a passkey* or *Use a
  // security key*. A passkey takes its provider's name and is renamed
  // afterwards.
  kind: vt.opt(vt.oneOf(['passkey', 'security-key']))
    .describe('`begin`: which call to action was pressed.'),
  enrolment_id: vt.opt(vt.base64url)
    .describe('`finish`: the pending enrolment the ceremony answers.'),
  credential: vz.string().max(validation.CAP.TEXT).optional()
    .describe('`finish`: the browser\'s ceremony result, as JSON.')
});

// A WebAuthn credential id is base64url, and it names a key on the CALLER's
// own entry, checked against that entry.
const REMOVE_KEY_FORM = vz.object({
  credentialId: vt.opt(vt.base64url)
    .describe('One of your own passkeys.')
});

// RENAMING ONE (#470). The name's rules (at most 60 characters, no control
// characters, empty restores the default) are `credentials.renameKey()`'s,
// the one writer.
const RENAME_KEY_FORM = vz.object({
  credentialId: vt.opt(vt.base64url)
    .describe('One of your own passkeys.'),
  label: vz.string().max(200).optional()
    .describe('Its new name; empty puts the default back.')
});

interface AccountKeysDeps {
  log: typeof helpers.log;
  credentials: typeof credentials;
  passkeyPolicy: typeof passkeyPolicy;
  webauthnPolicy: typeof webauthnPolicy;
  authn: typeof authn;
  accountSignals(): Json;
}

/**
 * `/portal/keys`' account API operations: the passkey page.
 */
class AccountKeys {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountKeysDeps) {
    deps.log.debug("Entering AccountKeys.constructor().");
    deps.log.debug("Leaving AccountKeys.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountKeysDeps {
    helpers.log.debug("Entering AccountKeys.defaultDeps().");
    helpers.log.debug("Leaving AccountKeys.defaultDeps().");
    return {
      log: helpers.log, credentials: credentials,
      passkeyPolicy: passkeyPolicy, webauthnPolicy: webauthnPolicy,
      authn: authn,
      accountSignals: function accountSignals(): Json {
        helpers.log.debug("Entering accountSignals().");
        helpers.log.debug("Leaving accountSignals().");
        return require('../ssf/account_signals');
      }
    };
  }

  // ONE KEY AS THE PAGE DRAWS IT (#470): every fact the row and its Details
  // fold show, computed here. The attestation goes as the facts the sentence
  // about it is made from, and the three policy refusals as their sentences,
  // each only while the realm's rule is on.
  /**
   * One key's row.
   *
   * @param one - the key as `credentials.keysOf()` holds it
   * @returns the row
   */
  keyRow(one: Json): Json {
    const { log, credentials, passkeyPolicy } = this.deps;
    log.debug("Entering AccountKeys.keyRow().");
    const att = one.attestation || null;
    const algorithm: Json = credentials.keyAlgorithm(one) || {};
    const pin: Json = passkeyPolicy.pinLengthRefusal(one.minPinLength,
                                                     'sign-in');
    const row = {
      credentialId: String(one.credentialId || ''),
      group: credentials.keyGroup(one),
      name: credentials.keyName(one),
      provider: credentials.keyProvider(one) || '',
      enrolledAt: one.enrolledAt || 0,
      lastUsedAt: one.lastUsedAt || 0,
      role: one.role,
      // A SYNCED KEY THE REALM NO LONGER TAKES (#528): refused at sign-in, so
      // the person is told here before they meet the refusal.
      syncedRefused: !!passkeyPolicy.backupEligibleRefusal(
        one.backupEligible, 'sign-in'),
      // ONE THE ATTESTATION RULES REFUSED AT SIGN-IN (#530), while the rule
      // is still on. The reason is the refusal's own and stays English.
      attestationRefused: one.attestationRefused &&
        passkeyPolicy.enforcesAttestationAtSignIn()
        ? String(one.attestationRefused.why || 'This passkey no longer ' +
                 'meets this service\'s rules.') : '',
      // ONE WHOSE MINIMUM PIN THE REALM NO LONGER ACCEPTS (#529).
      pinRefused: pin ? String(pin.why || '') : '',
      backupEligible: one.backupEligible === true ? true
        : (one.backupEligible === false ? false : null),
      backupState: one.backupState === true,
      transports: Array.isArray(one.transports) ? one.transports.slice(0)
                                                : [],
      kind: credentials.keyKind(one).text,
      withoutUsername: credentials.withoutUsername(one).text,
      algorithm: { text: String(algorithm.text || ''),
                   postQuantum: !!algorithm.postQuantum,
                   insecure: !!algorithm.insecure },
      attestation: att ? {
        verified: !!att.verified, trusted: !!att.trusted,
        model: String(att.model || ''), type: String(att.type || ''),
        // #256: Google's Android attestation status list.
        androidStatus: att.format === 'android-key' && att.androidRevocation
          ? String(att.androidRevocation.status || '') : '',
        // The device serial an enterprise attestation named (#532).
        deviceSerial: String(att.deviceSerial || '') } : null,
      aaguid: String(one.aaguid || '')
    };
    log.debug("Leaving AccountKeys.keyRow().");
    return row;
  }

  // ADDING ONE: the policy, the cap and the roles, or — while a challenge is
  // held — the ceremony to arm. The ceremony is armed while one is held and
  // never otherwise, so a reload with nothing pending is the form again
  // rather than a ceremony against a challenge that has gone. THE BASE IS THE
  // ONE THE REQUEST ARRIVED ON: a realm's base carries a path and the RP ID
  // is its host, which `authn.rpIdOf()` gets right.
  /**
   * The enrolment block's view.
   *
   * @param caller - the signed-in person
   * @param mechanisms - `credentials.mechanismsFor()`'s answer
   * @param base - the base the request arrived on
   * @returns the block's view
   */
  enrolView(caller: AccountCaller, mechanisms: Json, base: string): Json {
    const { log, credentials, webauthnPolicy, passkeyPolicy, authn } =
      this.deps;
    log.debug("Entering AccountKeys.enrolView().");
    const policy: Json = webauthnPolicy.settings();
    const username = caller.username;
    const pending: Json = credentials.pendingKeyEnrolmentFor(username);
    const out: Json = { enabled: !!policy.enabled,
                        count: mechanisms.keys.length,
                        atCap: mechanisms.keys.length >=
                               policy.maxKeysPerPerson,
                        roles: [], kinds: [], pending: null };
    if (pending) {
      const rpId = authn.rpIdOf(base);
      out.pending = {
        id: pending.id, kind: pending.kind || '', role: pending.role,
        challenge: pending.challenge, rpId: rpId, user: username,
        userHandle: pending.userHandle || '',
        // The name the prompt shows (#533), the policy's userDisplayName
        // first.
        display: passkeyPolicy.displayNameFor(username,
          String((caller.session.user || {}).name || username)),
        exclude: (pending.exclude || []).slice(0),
        options: webauthnPolicy.creationOptions(rpId, pending.kind)
      };
    }
    if (policy.mfaAllowed) {
      out.roles.push('mfa');
    }
    if (policy.primaryAllowed) {
      out.roles.push('primary');
    }
    out.kinds = webauthnPolicy.authenticatorKinds();
    log.debug("Leaving AccountKeys.enrolView().");
    return out;
  }

  // THE SIGNAL API'S DATA (#470, WebAuthn Level 3 section 5.1.10): every
  // credential id this person may still sign in with and their name, told
  // to the credential manager. ONLY UNDER A USER HANDLE THIS SERVICE MINTED
  // (#474): it is 64 random bytes unique to one entry in one realm, so the
  // signal names exactly this person's credentials; a person holding only
  // keys registered under their name is sent none. Never while a ceremony is
  // armed.
  /**
   * The Signal API's data, or null.
   *
   * @param caller - the signed-in person
   * @param keys - the person's keys
   * @param base - the base the request arrived on
   * @returns the data, or null
   */
  signalView(caller: AccountCaller, keys: Json[], base: string): Json {
    const { log, credentials, passkeyPolicy, authn } = this.deps;
    log.debug("Entering AccountKeys.signalView().");
    const username = caller.username;
    const handle = credentials.userHandleOf(username);
    if (!handle) {
      log.debug("Leaving AccountKeys.signalView(). No user handle is held.");
      return null;
    }
    log.debug("Leaving AccountKeys.signalView().");
    return { rpId: authn.rpIdOf(base), userId: handle,
             accepted: keys.map(function (one: Json): string {
               return one.credentialId;
             }),
             name: username,
             display: passkeyPolicy.displayNameFor(username,
               String((caller.session.user || {}).name || username)) };
  }

  /**
   * The page's view.
   *
   * @param caller - the signed-in person
   * @param base - the base the request arrived on
   * @param named - the passkey just registered, or ''
   * @returns the view
   */
  view(caller: AccountCaller, base: string, named?: string): Json {
    const { log, credentials, passkeyPolicy } = this.deps;
    const self = this;
    log.debug("Entering AccountKeys.view().");
    // The person's passkey policy (#535); no application is in hand here.
    passkeyPolicy.select(caller.username, '');
    const mechanisms: Json = credentials.mechanismsFor(caller.username);
    const keys: Json[] = mechanisms.keys || [];
    const enrol = this.enrolView(caller, mechanisms, base);
    const held = keys.some(function (one: Json): boolean {
      return one.credentialId === String(named || '');
    });
    log.debug("Leaving AccountKeys.view(). " + keys.length + " key(s).");
    return {
      password: !!mechanisms.password,
      mfaRequired: !!mechanisms.mfaRequired,
      keys: keys.map(function (one: Json): Json {
        return self.keyRow(one);
      }),
      named: held ? String(named) : '',
      enrol: enrol,
      signal: enrol.pending ? null : this.signalView(caller, keys, base)
    };
  }

  /**
   * Begins, finishes or cancels a registration.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async enrol(ctx: AccountContext, req: Json, res: Json,
              caller: AccountCaller, body: Json): Promise<unknown> {
    const { log, credentials, authn, passkeyPolicy } = this.deps;
    const { audit, websecurity } = ctx;
    const self = this;
    log.debug("Entering AccountKeys.enrol().");
    const username = caller.username;
    const base = ctx.baseUrlOf(req);
    // The person's passkey policy (#535).
    passkeyPolicy.select(username, '');
    const action = String(body.action || '');
    const refused = function refused(status: number, code: string,
                                     why: string): unknown {
      log.debug("Entering refused().");
      log.debug("Leaving refused().");
      // error-code: none — the code is the caller's, passed in `code`.
      return ctx.refuse(res, status, code, why,
                        { view: self.view(caller, base) });
    };

    if (action === 'cancel') {
      credentials.abandonKeyEnrolment(username);
      log.debug("Leaving AccountKeys.enrol(). Abandoned.");
      return ctx.json(res, 200, { ok: true, message: '' });
    }

    if (action === 'begin') {
      // THE POLICY IS CHECKED AT THE DOOR AND NOT ONLY ON THE PAGE: a form
      // posted by hand while `webauthn.primaryAllowed` is off must not arm a
      // ceremony that `addKey()` would then refuse after somebody had
      // touched their key. `beginKeyEnrolment()` makes every one of those
      // checks.
      const begun: Json = credentials.beginKeyEnrolment(username, {
        role: String(body.role || 'mfa'), kind: String(body.kind || '') });
      if (!begun.ok) {
        log.debug("Leaving AccountKeys.enrol(). Refused to start.");
        return refused(400, ctx.errorCodes.codeOf(begun) || 'STS-PORTAL-0033',
          (begun.errors || ['The enrolment could not be started.'])[0]);
      }
      audit.record({
        category: 'authentication', action: 'portal.key.started',
        actor: username, outcome: 'success',
        summary: username + ' started creating a passkey',
        detail: { role: begun.role, kind: begun.kind || 'any',
                  excluded: begun.exclude.length,
                  address: websecurity.addressOf(req) }
      });
      // THE PAGE IS ASKED AGAIN rather than drawn from this answer: its GET
      // draws the armed ceremony, and a repeat of this answer could not
      // mint a second challenge under the one the person is in.
      log.debug("Leaving AccountKeys.enrol(). Challenge minted and held.");
      return ctx.json(res, 200, { ok: true, message: '' });
    }

    if (action === 'finish') {
      let credential: Json = null;
      try {
        credential = JSON.parse(String(body.credential || 'null'));
      } catch (e) {
        log.debug("Caught in AccountKeys.enrol(): " + ((e && e.message) || e));
        // Not JSON: a hand-made request; the sentence below is the right
        // answer and a parse error is not.
        credential = null;
      }
      if (!credential) {
        log.debug("Leaving AccountKeys.enrol(). No ceremony ran.");
        return refused(400, 'STS-PORTAL-0034',
          'Your browser did not run the ceremony, so there is nothing to ' +
          'register. A passkey is created by the browser and there is no ' +
          'form that can do it.');
      }
      // THE SAME TWO ADDRESS RULES THE SIGN-IN SCREEN APPLIES (2026-09-12).
      const rpRefusal = authn.rpIdProblem(base);
      if (rpRefusal) {
        log.debug("Leaving AccountKeys.enrol(). The RP ID does not fit.");
        return refused(400, 'STS-PORTAL-0035', rpRefusal);
      }
      // WHAT WAS ASKED FOR, read before the answer can drop the pending
      // enrolment: a browser that could not run the ceremony is told about
      // the kind it was asked for.
      const waiting: Json = credentials.pendingKeyEnrolmentFor(username) || {};
      const asked = waiting.kind;
      let done: Json = null;
      try {
        // A PROMISE SINCE 2026-09-14: the write claims the credential id
        // across nodes first, so two posts of one attestation cannot leave
        // two rows for one key.
        done = await credentials.confirmKeyEnrolment(username,
          String(body.enrolment_id || ''), credential,
          { origin: authn.expectedOriginFor(base, credential),
            rpId: authn.rpIdOf(base) });
      } catch (e) {
        log.debug("Caught in AccountKeys.enrol(): " + ((e && e.message) || e));
        log.debug("Leaving AccountKeys.enrol(). It threw.");
        return refused(500, 'STS-PORTAL-0036',
                       'The passkey could not be created. Try again.');
      }
      if (!done.ok) {
        audit.record({
          category: 'authentication', action: 'portal.key.refused',
          errorCode: ctx.errorCodes.codeOf(done) || 'STS-PORTAL-0036',
          actor: username, outcome: 'failure',
          summary: 'a security key enrolment was not completed for ' +
                   username,
          detail: { reason: done.reason || '',
                    address: websecurity.addressOf(req) }
        });
        // THE BROWSER COULD NOT RUN THE CEREMONY (2026-09-26): it declined,
        // timed out, or has no authenticator of the kind asked for. Keeping
        // the pending enrolment re-armed that same ceremony on every reload,
        // so it is abandoned and the sentence says what to try.
        let why = (done.errors || ['The passkey could not be created.'])[0];
        if (done.reason === 'browser') {
          credentials.abandonKeyEnrolment(username);
          why += asked === 'security-key'
            ? ' Nothing was registered. If you have no security key to ' +
              'hand, choose "Create a passkey" instead.'
            : ' Nothing was registered. You can try again below, save it ' +
              'to your phone when the browser offers, or choose "Use a ' +
              'security key".';
        }
        log.debug("Leaving AccountKeys.enrol(). Refused: " + done.reason);
        return refused(400, ctx.errorCodes.codeOf(done) || 'STS-PORTAL-0036',
                       why);
      }
      // CAEP credential-change (#145), the key described by what its
      // enrolment recorded: attachment and AAGUID.
      const enrolled = credentials.keysOf(username).filter(function (one) {
        return one.credentialId === String(done.credentialId || '');
      })[0] || null;
      const signals = this.deps.accountSignals();
      signals.credentialChanged({ username: username,
        credentialType: signals.keyCredentialType(enrolled),
        fido2Aaguid: String((enrolled && enrolled.aaguid) || ''),
        friendlyName: String((enrolled && enrolled.label) || ''),
        changeType: 'create', initiatingEntity: 'user', via: 'portal',
        reasonAdmin: username + ' created a passkey.',
        reasonUser: 'You created a passkey.' });
      audit.record({
        category: 'authentication', action: 'portal.key.enrolled',
        actor: username, outcome: 'success',
        summary: username + ' created a passkey as a ' + done.role +
                 ' credential',
        detail: { role: done.role, held: done.held,
                  algorithm: credentials.keyAlgorithm(enrolled).text,
                  address: websecurity.addressOf(req) }
      });
      log.info('portal: ' + username + ' created a "' + done.role +
               '" passkey and now holds ' + done.held + '.');
      const t = ctx.translatorFor(username);
      // THE NICKNAME PROMPT (#470): `named` opens the new passkey's rename
      // form at the top of the page.
      log.debug("Leaving AccountKeys.enrol(). Enrolled.");
      return ctx.json(res, 200, { ok: true,
        message: done.held > 1
          ? t.text('portal.done.passkeyMany', { n: Number(done.held) })
          : t.text('portal.done.passkeyOne'),
        go: ctx.PORTAL + '/keys?named=' +
            encodeURIComponent(String(done.credentialId || '')) });
    }

    log.debug("Leaving AccountKeys.enrol(). Unknown action.");
    return refused(400, 'STS-PORTAL-0026', 'Unknown action "' + action +
                   '". There are three: begin, finish and cancel.');
  }

  /**
   * Removes one of the caller's own passkeys.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  remove(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log, credentials } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountKeys.remove().");
    const username = caller.username;
    // THE CREDENTIAL ID COMES FROM THE BODY AND THE USERNAME DOES NOT:
    // `removeKey()` looks the id up among THIS PERSON's keys. The key as it
    // was is read first: the event describes what was removed.
    const going = credentials.keysOf(username).filter(function (one) {
      return one.credentialId === String(body.credentialId || '');
    })[0] || null;
    const removed: Json = credentials.removeKey(username,
      String(body.credentialId || ''));
    if (!removed.ok) {
      log.debug("Leaving AccountKeys.remove(). Refused.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(removed) ||
                        'STS-PORTAL-0037',
                        (removed.errors || ['The passkey could not be ' +
                                            'removed.'])[0],
                        { view: this.view(caller, ctx.baseUrlOf(req)) });
    }
    const signals = this.deps.accountSignals();
    signals.credentialChanged({ username: username,
      credentialType: signals.keyCredentialType(going),
      fido2Aaguid: String((going && going.aaguid) || ''),
      friendlyName: String((going && going.label) || ''),
      changeType: 'delete', initiatingEntity: 'user', via: 'portal',
      reasonAdmin: username + ' removed a passkey.',
      reasonUser: 'You removed a passkey.' });
    audit.record({
      category: 'authentication', action: 'portal.key.removed',
      actor: username, outcome: 'success',
      summary: username + ' removed one of their passkeys',
      detail: { remaining: removed.remaining,
                address: websecurity.addressOf(req) }
    });
    log.debug("Leaving AccountKeys.remove(). Removed.");
    return ctx.json(res, 200, { ok: true, message:
      ctx.translatorFor(username).text('portal.done.passkeyRemoved') });
  }

  // RENAMING ONE (#470): `remove`'s door in every respect that matters, and
  // an audit row, but no CAEP credential-change: a name says nothing about
  // what the key proves.
  /**
   * Renames one of the caller's own passkeys.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  rename(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log, credentials } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountKeys.rename().");
    const username = caller.username;
    const renamed: Json = credentials.renameKey(username,
      String(body.credentialId || ''), String(body.label || ''));
    if (!renamed.ok) {
      log.debug("Leaving AccountKeys.rename(). Refused.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(renamed) ||
                        'STS-PORTAL-0245',
                        (renamed.errors || ['The passkey could not be ' +
                                            'renamed.'])[0],
                        { view: this.view(caller, ctx.baseUrlOf(req)) });
    }
    audit.record({
      category: 'authentication', action: 'portal.key.renamed',
      actor: username, outcome: 'success',
      summary: username + ' renamed one of their passkeys',
      detail: { from: renamed.previous, to: renamed.label,
                address: websecurity.addressOf(req) }
    });
    log.debug("Leaving AccountKeys.rename(). Renamed.");
    return ctx.json(res, 200, { ok: true, message:
      ctx.translatorFor(username).text('portal.done.renamed',
                                       { name: String(renamed.label) }) });
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
    log.debug("Entering AccountKeys.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/keys', operationId: 'getKeys',
        tag: 'Passkeys', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/keys',
        summary: 'Your passkeys, and adding one',
        description: 'Each passkey you hold (`keys`), grouped `device` or ' +
          '`security-key`, with its name, provider, dates, role, algorithm, ' +
          'what its attestation proved and whether the realm\'s passkey ' +
          'policy refuses it at sign-in. `enrol` says whether you may add ' +
          'one and, while a registration is waiting, the ceremony to run ' +
          '(`enrol.pending`). `signal` is the WebAuthn Signal API\'s data.',
        query: KEYS_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200, self.view(caller, ctx.baseUrlOf(req),
            String(input.query.named || '')));
        } },
      { method: 'POST', path: ctx.BASE + '/keys', operationId: 'enrolKey',
        tag: 'Passkeys', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/keys',
        summary: 'Begins, finishes or cancels adding a passkey',
        description: '`begin` mints a challenge and holds it (the policy ' +
          'checked at the door); `finish` verifies the browser\'s ' +
          'registration with the sign-in screen\'s address rules and ' +
          'answers `go` naming the new passkey; `cancel` drops the waiting ' +
          'one. A refusal carries the page\'s `view`.',
        body: ENROL_KEY_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.enrol(ctx, req, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/keys/remove',
        operationId: 'removeKey', tag: 'Passkeys', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/remove-key',
        summary: 'Removes one of your passkeys',
        description: 'Refused where it would leave you no way to sign in. ' +
          'Your relying parties are told over CAEP.',
        body: REMOVE_KEY_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.remove(ctx, req, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/keys/rename',
        operationId: 'renameKey', tag: 'Passkeys', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/rename-key',
        summary: 'Renames one of your passkeys',
        description: 'At most 60 characters, no control characters; an ' +
          'empty name puts the default back.',
        body: RENAME_KEY_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.rename(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving AccountKeys.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountKeys>(
  'portal/account_keys',
  () => new AccountKeys(AccountKeys.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/keys`' account API operations (#470, #568).
 * @namespace
 */
export = {
  AccountKeys: AccountKeys,
  installInstance: (instance: AccountKeys): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
