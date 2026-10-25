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
// UPGRADING ONE (#939, rule 3ct): `POST /account-api/keys/upgrade`, three
// steps over `credentials.ts`' upgrade ceremony — `begin` names one of the
// person's classical passkeys, `prove` answers the assertion that proves
// they hold it, `finish` answers the ML-DSA registration that follows —
// and `cancel`. While one is in progress the view's `upgrade.pending` is
// the ceremony to run, in place of an enrolment's.
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
    .describe('The passkey just registered: its rename form is drawn open.'),
  // #946's panel links here when a classical passkey was refused where a
  // post-quantum one is required (#939): the page then says which of the
  // person's passkeys can be upgraded.
  upgrade: vt.opt(vt.oneOf(['post-quantum']))
    .describe('`post-quantum`: arrived from a refusal that asked for a ' +
              'post-quantum passkey, so the page leads with the upgrade.')
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
  // THE LANE (#643): a classical passkey or a post-quantum one, where the
  // realm offers both. Carried on the pending enrolment, never read back.
  lane: vt.opt(vt.oneOf(['classical', 'pqc']))
    .describe('`begin`: `classical` (the default) or `pqc`, where the realm ' +
              'offers a post-quantum passkey beside a classical one.'),
  // THE CLASSICAL RETRY (#944): after an ML-DSA-first registration failed
  // on the device, a `begin` with the classical algorithms only. Refused
  // where the realm forbids a classical passkey (STS-AUTHN-0420).
  algorithms: vt.opt(vt.oneOf(['classical']))
    .describe('`begin`: `classical` retries with the classical algorithms ' +
              'only, where `enrol.pending.fallback.classical` says the ' +
              'realm allows it.'),
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

// UPGRADING ONE (#939). `credential` is the browser's ceremony result as
// JSON, ENROL_KEY_FORM's reason: what is inside it is the verifier's to
// decide. The credential id is looked up among the caller's own keys.
const UPGRADE_KEY_FORM = vz.object({
  action: vt.opt(vt.oneOf(['begin', 'prove', 'finish', 'cancel']))
    .describe('`begin` names the classical passkey and mints the proof\'s ' +
              'challenge, `prove` answers it with that passkey, `finish` ' +
              'answers the post-quantum registration, `cancel` drops the ' +
              'upgrade.'),
  credentialId: vt.opt(vt.base64url)
    .describe('`begin`: one of your own classical passkeys.'),
  upgrade_id: vt.opt(vt.base64url)
    .describe('`prove` and `finish`: the upgrade in progress.'),
  credential: vz.string().max(validation.CAP.TEXT).optional()
    .describe('`prove` and `finish`: the browser\'s ceremony result, as ' +
              'JSON.')
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
   * @param username - whose key it is, for whether it may be upgraded
   * @returns the row
   */
  keyRow(one: Json, username?: string): Json {
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
      // A CLASSICAL KEY WHERE THE PERSON'S PROFILE REQUIRES A POST-QUANTUM
      // ONE AT SIGN-IN (#718), from the same question the sign-in asks of
      // its algorithm, so the page and the refusal cannot disagree.
      postQuantumRefused: !!passkeyPolicy.postQuantumRefusal(algorithm,
                                                             'sign-in'),
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
      // THE LANE IT WAS CREATED IN (#643): `classical` (every key before the
      // lanes) or `pqc`.
      lane: credentials.keyLane(one),
      // WHETHER IT MAY BE UPGRADED TO AN ML-DSA PASSKEY (#939), by
      // `credentials.keyUpgradeRefusal()` — the begin's own question, so
      // the button and the door cannot disagree — and the upgrade history
      // it carries: on an upgraded key, when and from which algorithm; on
      // a classical key upgraded beside it, its successor.
      upgradable: !!username &&
        credentials.keyUpgradeRefusal(username, one).ok,
      upgrade: credentials.keyUpgradeHistory(one),
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
    // AN UPGRADE IN PROGRESS (#939) shares the pending record and is not an
    // enrolment: `upgradeView()` draws it.
    const held: Json = credentials.pendingKeyEnrolmentFor(username);
    const pending: Json = held && !held.upgrade ? held : null;
    // THE CAP COUNTS BOTH LANES (#643): one total, as `addKey()` holds it.
    const out: Json = { enabled: !!policy.enabled,
                        count: mechanisms.keys.length,
                        atCap: mechanisms.keys.length >=
                               policy.maxKeysPerPerson,
                        roles: [], kinds: [], pending: null,
                        // The lanes a new passkey may be created in (#643):
                        // the page asks which only where there are two.
                        lanes: webauthnPolicy.lanes() };
    if (pending) {
      const rpId = authn.rpIdOf(base);
      const lane = String(pending.lane || 'classical');
      // THE NAME THE PROMPT SHOWS (#533), the policy's userDisplayName
      // first — the post-quantum lane's naming ML-DSA (#643).
      const user = credentials.laneUser(username,
        passkeyPolicy.displayNameFor(username,
          String((caller.session.user || {}).name || username)), lane);
      out.pending = {
        id: pending.id, kind: pending.kind || '', role: pending.role,
        lane: lane,
        challenge: pending.challenge, rpId: rpId, user: user.name,
        userHandle: pending.userHandle || '',
        display: user.displayName,
        exclude: (pending.exclude || []).slice(0),
        options: webauthnPolicy.creationOptions(rpId, pending.kind, lane,
                                                pending.classicalOnly ===
                                                  true),
        // THE CLASSICAL RETRY (#944): whether this ceremony asks for
        // ML-DSA, whether a retry with the classical algorithms only may be
        // offered if the device cannot make it, and whether this IS that
        // retry. The page draws the guidance from these; the `begin` asks
        // the realm again.
        fallback: {
          asksPostQuantum: webauthnPolicy.asksPostQuantum(lane,
            pending.classicalOnly === true),
          classical: pending.classicalOnly !== true &&
                     webauthnPolicy.classicalFallbackOffered(lane),
          retrying: pending.classicalOnly === true }
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

  // THE CLASSICAL RETRY STAYS (#961) only for the report the guidance sends.
  // offerFallback() posts the browser error with its own `capabilities`
  // property — null where the platform reported none, which JSON keeps —
  // and only when it is about to show the guidance. The ordinary refusal is
  // `{ error }` with no such property, and that one is abandoned, as on
  // 2026-09-26: keeping every browser error re-armed the same ceremony on
  // every reload. The mark is the property, not the error's name. The
  // ceremony log's declined registration posts `{ error: 'NotAllowedError' }`
  // with no capabilities through confirmKeyEnrolment(), not this door, and
  // still records reason `browser`. An upgrade's create phase draws the
  // guidance with no classical begin and is dropped by confirmKeyUpgrade();
  // this door is an enrolment, so a record marked upgrade is never kept.
  // The condition is enrolView()'s: the one that draws `#wa-fallback` with
  // a classical begin.
  /**
   * Whether a browser refusal is the guidance's report of a ceremony whose
   * classical retry is still offered.
   *
   * @param credential - the posted ceremony answer
   * @param waiting - the pending enrolment, read before the answer
   * @returns whether the enrolment stays
   */
  private keepsClassicalRetry(credential: Json, waiting: Json): boolean {
    const { log, webauthnPolicy } = this.deps;
    log.debug("Entering AccountKeys.keepsClassicalRetry().");
    const held = waiting || {};
    const reported = !!credential && typeof credential === 'object' &&
      Object.prototype.hasOwnProperty.call(credential, 'capabilities');
    const lane = String(held.lane || 'classical');
    const classicalOnly = held.classicalOnly === true;
    const offers = reported && !held.upgrade && !!held.id &&
      !classicalOnly &&
      webauthnPolicy.asksPostQuantum(lane, classicalOnly) &&
      webauthnPolicy.classicalFallbackOffered(lane);
    log.debug("Leaving AccountKeys.keepsClassicalRetry(). " + offers);
    return offers;
  }

  // THE SIGNAL API'S DATA (#470, WebAuthn Level 3 section 5.1.10): every
  // credential id this person may still sign in with and their name, told
  // to the credential manager. ONLY UNDER A USER HANDLE THIS SERVICE MINTED
  // (#474): it is 64 random bytes unique to one entry in one realm, so the
  // signal names exactly this person's credentials; a person holding only
  // keys registered under their name is sent none. Never while a ceremony is
  // armed.
  //
  // **ONE ENTRY PER LANE (#643)**: a credential manager keeps the classical
  // and the post-quantum passkey as two accounts, each under its own user
  // handle, so each is told its OWN handle, name and credential ids — one
  // signal under the classical handle naming every key would tell it the
  // post-quantum passkeys are unknown there and to forget them. A lane whose
  // handle the person does not hold is not signalled. The post-quantum
  // lane's name says its algorithm once the rows record one
  // (`credentials.laneSignalUser()`).
  /**
   * The Signal API's data, one entry per lane whose handle is held.
   *
   * @param caller - the signed-in person
   * @param keys - the person's keys
   * @param base - the base the request arrived on
   * @returns the entries, possibly none
   */
  signalView(caller: AccountCaller, keys: Json[], base: string): Json[] {
    const { log, credentials, passkeyPolicy, authn } = this.deps;
    log.debug("Entering AccountKeys.signalView().");
    const username = caller.username;
    const display = passkeyPolicy.displayNameFor(username,
      String((caller.session.user || {}).name || username));
    const rpId = authn.rpIdOf(base);
    const out: Json[] = [];
    credentials.LANES.forEach(function (lane: string): void {
      const handle = credentials.userHandleOf(username, { lane: lane });
      if (!handle) {
        return;
      }
      const user = credentials.laneSignalUser(username, display, lane, keys);
      out.push({ lane: lane, rpId: rpId, userId: handle,
                 accepted: keys.filter(function (one: Json): boolean {
                   return credentials.keyLane(one) === lane;
                 }).map(function (one: Json): string {
                   return one.credentialId;
                 }),
                 name: user.name, display: user.displayName });
    });
    log.debug("Leaving AccountKeys.signalView(). " + out.length +
              " lane(s).");
    return out;
  }

  // THE UPGRADE (#939): whether the realm offers it and what its write
  // does here, whether the page was reached from #946's panel, and — while
  // one is in progress — the ceremony to arm: the proof (an assertion
  // naming the one classical credential), then the registration (ML-DSA
  // only, under the lane's handle, the classical credential left out of the
  // exclude list). Its `fallback` says the device may fail to make ML-DSA
  // and that NO classical retry is offered: the point is ML-DSA.
  /**
   * The upgrade block's view.
   *
   * @param caller - the signed-in person
   * @param keys - the person's keys
   * @param base - the base the request arrived on
   * @param asked - whether the page was reached from #946's panel
   * @returns the block's view
   */
  upgradeView(caller: AccountCaller, keys: Json[], base: string,
              asked: boolean): Json {
    const { log, credentials, webauthnPolicy, passkeyPolicy, authn } =
      this.deps;
    log.debug("Entering AccountKeys.upgradeView().");
    const username = caller.username;
    const held: Json = credentials.pendingKeyUpgradeFor(username);
    const out: Json = { offered: webauthnPolicy.postQuantumUpgradeOffered(),
                        mode: webauthnPolicy.upgradeMode(),
                        asked: !!asked, pending: null };
    if (held) {
      const rpId = authn.rpIdOf(base);
      const upgrading = keys.filter(function (one: Json): boolean {
        return String(one.credentialId) ===
               String(held.upgrade.credentialId);
      })[0] || null;
      const common: Json = {
        id: held.id, phase: String(held.upgrade.phase),
        credentialId: String(held.upgrade.credentialId),
        name: upgrading ? credentials.keyName(upgrading)
                        : String(held.label || ''),
        mode: String(held.upgrade.mode), lane: String(held.lane),
        previousAlgorithm: String(held.upgrade.previousAlgorithm || ''),
        challenge: held.challenge, rpId: rpId };
      if (held.upgrade.phase === 'proof') {
        common.allow = [String(held.upgrade.credentialId)];
        common.options = webauthnPolicy.requestOptions(rpId);
      } else {
        const user = credentials.laneUser(username,
          passkeyPolicy.displayNameFor(username,
            String((caller.session.user || {}).name || username)),
          String(held.lane));
        common.user = user.name;
        common.display = user.displayName;
        common.userHandle = held.userHandle || '';
        common.exclude = (held.exclude || []).slice(0);
        common.options = webauthnPolicy.upgradeCreationOptions(rpId,
                                                               held.kind);
        // #944's FACTS, read by the same runtime: ML-DSA is asked for, and
        // no classical retry is offered — `upgrade` says why.
        common.fallback = { asksPostQuantum: true, classical: false,
                            retrying: false, upgrade: true };
      }
      out.pending = common;
    }
    log.debug("Leaving AccountKeys.upgradeView(). " +
              (held ? String(held.upgrade.phase) : 'nothing pending'));
    return out;
  }

  /**
   * The page's view.
   *
   * @param caller - the signed-in person
   * @param base - the base the request arrived on
   * @param named - the passkey just registered, or ''
   * @param asked - `upgrade=post-quantum` (#939): reached from #946's panel
   * @returns the view
   */
  view(caller: AccountCaller, base: string, named?: string,
       asked?: boolean): Json {
    const { log, credentials, passkeyPolicy } = this.deps;
    const self = this;
    log.debug("Entering AccountKeys.view().");
    // The person's passkey policy (#535); no application is in hand here.
    passkeyPolicy.select(caller.username, '');
    const mechanisms: Json = credentials.mechanismsFor(caller.username);
    const keys: Json[] = mechanisms.keys || [];
    const enrol = this.enrolView(caller, mechanisms, base);
    const upgrade = this.upgradeView(caller, keys, base, !!asked);
    const held = keys.some(function (one: Json): boolean {
      return one.credentialId === String(named || '');
    });
    log.debug("Leaving AccountKeys.view(). " + keys.length + " key(s).");
    return {
      password: !!mechanisms.password,
      mfaRequired: !!mechanisms.mfaRequired,
      keys: keys.map(function (one: Json): Json {
        return self.keyRow(one, caller.username);
      }),
      named: held ? String(named) : '',
      enrol: enrol,
      upgrade: upgrade,
      // ONE PER LANE (#643); none while a ceremony is armed — an upgrade's
      // included (#939).
      signals: enrol.pending || upgrade.pending ? []
        : this.signalView(caller, keys, base)
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
        role: String(body.role || 'mfa'), kind: String(body.kind || ''),
        // The lane (#643), refused there where the realm does not offer it.
        lane: String(body.lane || 'classical'),
        // The classical retry (#944), refused there where it is forbidden.
        classicalOnly: String(body.algorithms || '') === 'classical' });
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
                  lane: begun.lane || 'classical',
                  classicalOnly: !!begun.classicalOnly,
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
        // EXCEPT THE REPORT THE GUIDANCE SENDS (#961): that post carries its
        // own `capabilities` property, and where this enrolment's fallback
        // offers the classical begin the enrolment stays and the answer
        // carries no view, so a runtime that drew it would not replace the
        // ceremony. The refusal is still audited above, as it always was.
        let why = (done.errors || ['The passkey could not be created.'])[0];
        if (done.reason === 'browser' &&
            this.keepsClassicalRetry(credential, waiting)) {
          log.debug("Leaving AccountKeys.enrol(). The browser refused; " +
                    "the classical retry stays.");
          return ctx.refuse(res, 400,
            ctx.errorCodes.codeOf(done) || 'STS-PORTAL-0036', why);
        }
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
                  lane: credentials.keyLane(enrolled),
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
   * Proves possession of a passkey and upgrades it to an ML-DSA passkey.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns the response
   */
  async upgrade(ctx: AccountContext, req: Json, res: Json,
                caller: AccountCaller, body: Json): Promise<unknown> {
    const { log, credentials, authn, passkeyPolicy } = this.deps;
    const { audit, websecurity } = ctx;
    const username = caller.username;
    const base = ctx.baseUrlOf(req);
    passkeyPolicy.select(username, '');
    const action = String(body.action || '');
    const refused = function (answer: Json): unknown {
      const code = ctx.errorCodes.codeOf(answer) || 'STS-AUTHN-0450';
      const why = (answer.errors || ['The passkey could not be upgraded.'])
        .map(String).join(' ');
      return ctx.refuse(res, 400, code, why,
                        { view: this.view(caller, base) });
    };
    if (action === 'cancel') {
      if (!credentials.pendingKeyUpgradeFor(username)) {
        return refused({ ok: false, errors: ['There is no passkey upgrade ' +
                                               'in progress.'] });
      }
      credentials.abandonKeyEnrolment(username);
      return ctx.json(res, 200, { ok: true, message: '' });
    }
    if (action === 'begin') {
      const begun: Json = credentials.beginKeyUpgrade(username,
        String(body.credentialId || ''));
      if (!begun.ok) {
        return refused(begun);
      }
      audit.record({
        category: 'authentication', action: 'portal.key.upgrade-started',
        actor: username, outcome: 'success',
        summary: username + ' began upgrading a passkey',
        detail: { role: begun.role, mode: begun.mode, lane: begun.lane,
                  previousAlgorithm: begun.previousAlgorithm,
                  address: websecurity.addressOf(req) }
      });
      return ctx.json(res, 200, { ok: true, message: '' });
    }
    if (action !== 'prove' && action !== 'finish') {
      return ctx.refuse(res, 400, 'STS-PORTAL-0026',
        'Unknown upgrade action. Choose begin, prove, finish or cancel.',
        { view: this.view(caller, base) });
    }
    let credential: Json = null;
    try {
      credential = JSON.parse(String(body.credential || 'null'));
    } catch (e) {
      // A malformed browser answer is passed as no credential; the verifier
      // returns the ceremony's ordinary refusal and leaves no partial key.
      credential = null;
    }
    const upgradeId = String(body.upgrade_id || '');
    const opts = { origin: authn.expectedOriginFor(base, credential || {}),
                   rpId: authn.rpIdOf(base) };
    let answer: Json;
    try {
      answer = action === 'prove'
        ? await credentials.proveKeyUpgrade(username, upgradeId,
                                            credential, opts)
        : await credentials.confirmKeyUpgrade(username, upgradeId,
                                               credential, opts);
    } catch (e) {
      log.debug('Caught in AccountKeys.upgrade(): ' +
                ((e && e.message) || e));
      return ctx.refuse(res, 500, 'STS-PORTAL-0036',
        'The passkey could not be upgraded. Your existing passkey is ' +
        'unchanged; try again.', { view: this.view(caller, base) });
    }
    if (!answer.ok) {
      audit.record({
        category: 'authentication', action: 'portal.key.upgrade-refused',
        errorCode: ctx.errorCodes.codeOf(answer) || 'STS-AUTHN-0458',
        actor: username, outcome: 'failure',
        summary: 'a passkey upgrade was not completed',
        detail: { phase: action, reason: (answer.errors || []).join(' '),
                  address: websecurity.addressOf(req) }
      });
      return refused(answer);
    }
    if (action === 'prove') {
      return ctx.json(res, 200, { ok: true, message: '' });
    }
    const enrolled = credentials.keysOf(username).filter(function (one: Json) {
      return String(one.credentialId) === String(answer.credentialId || '');
    })[0] || null;
    const signals = this.deps.accountSignals();
    signals.credentialChanged({ username: username,
      credentialType: signals.keyCredentialType(enrolled),
      fido2Aaguid: String((enrolled && enrolled.aaguid) || ''),
      friendlyName: String((enrolled && enrolled.label) || ''),
      changeType: answer.mode === 'replace' ? 'update' : 'create',
      initiatingEntity: 'user', via: 'portal passkey upgrade',
      reasonAdmin: username + ' upgraded a classical passkey to ML-DSA.',
      reasonUser: 'You upgraded a passkey to a post-quantum passkey.' });
    audit.record({
      category: 'authentication', action: 'portal.key.upgraded',
      actor: username, outcome: 'success',
      summary: username + ' upgraded a passkey to ML-DSA',
      detail: { mode: answer.mode, lane: answer.lane, role: answer.role,
        previousAlgorithm: answer.previousAlgorithm,
        algorithm: answer.algorithm,
        address: websecurity.addressOf(req) }
    });
    log.info('portal: ' + username + ' upgraded a passkey to ML-DSA (' +
             answer.mode + ').');
    return ctx.json(res, 200, { ok: true,
      message: 'Your passkey is now post-quantum.',
      go: ctx.PORTAL + '/keys' });
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
    // THE SESSIONS THAT KEY SIGNED IN END (#722) — as the first factor or as
    // a step — and every other stays, this one included unless the key
    // signed it in: somebody removing a passkey they do not recognise signs
    // out whoever enrolled it. After the removal and its signal, and never
    // undoing either.
    const ended: Json = ctx.endFactorSessions(username, { kind: 'webauthn',
      credentialId: String(body.credentialId || '') }, 'a passkey');
    audit.record({
      category: 'authentication', action: 'portal.key.removed',
      actor: username, outcome: 'success',
      summary: username + ' removed one of their passkeys',
      detail: { remaining: removed.remaining,
                sessionsEnded: ended.sessionsEnded,
                address: websecurity.addressOf(req) }
    });
    const said = ctx.translatorFor(username).text('portal.done.passkeyRemoved');
    log.debug("Leaving AccountKeys.remove(). Removed.");
    return ctx.json(res, 200, { ok: true,
      message: ended.sentence ? said + ' ' + ended.sentence : said,
      sessionsEnded: ended.sessionsEnded });
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
          '(`enrol.pending`) and the lanes a passkey may be created in ' +
          '(`enrol.lanes`, #643). `signals` is the WebAuthn Signal API\'s ' +
          'data, one entry per lane whose user handle you hold.',
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
          'and the `lane`, #643, checked at the door; `algorithms: ' +
          'classical`, #944, the classical retry, refused where the realm ' +
          'forbids a classical passkey); `finish` verifies the browser\'s ' +
          'registration with the sign-in screen\'s address rules and ' +
          'answers `go` naming the new passkey; `cancel` drops the waiting ' +
          'one. A refusal carries the page\'s `view`, except a browser ' +
          'error reported with its own `capabilities` property while the ' +
          'classical retry is offered (#961): that enrolment stays and the ' +
          'answer carries no view.',
        body: ENROL_KEY_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.enrol(ctx, req, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/keys/upgrade',
        operationId: 'upgradeKey', tag: 'Passkeys', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/keys/upgrade',
        summary: 'Upgrade one of your classical passkeys to ML-DSA',
        description: 'Proves possession with the existing passkey, then ' +
          'verifies a post-quantum registration before replacing it or ' +
          'adding the post-quantum lane. A refusal leaves the classical ' +
          'passkey unchanged.',
        body: UPGRADE_KEY_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.upgrade(ctx, req, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/keys/remove',
        operationId: 'removeKey', tag: 'Passkeys', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/remove-key',
        summary: 'Removes one of your passkeys',
        description: 'Refused where it would leave you no way to sign in. ' +
          'Your relying parties are told over CAEP, and every session the ' +
          'passkey signed in ends (`sessionsEnded` counts them, #722); ' +
          'your other sessions stay.',
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
