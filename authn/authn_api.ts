// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authn_api.ts
//
// ---------------------------------------------------------------------------
// `/authn-api`: THE SIGN-IN SCREEN'S API (#571, 2026-10-12).
//
// The sign-in screen became a static surface (#569's umbrella, #570's
// foundation, `common/CLAUDE.md` 3cl): `/authn/login`, `/authn/select-idp`
// and `/authn/password-change` answer one shell, and the browser draws each
// page from this API and sends each act to it. Every protocol's browser
// sign-in passes through it, and the second-factor, email, wallet and SPNEGO
// tickets (#572-#575) extend it.
//
// WHAT IT IS, AND WHAT IT IS NOT:
//
//   * UNAUTHENTICATED, AND KEYED BY THE PENDING SIGN-IN'S ID — the id
//     `beginAuthentication()` mints and sends the browser to the screen with.
//     It is a BEARER CAPABILITY, as `authn_id` was in the form: whoever holds
//     it may act on that sign-in. So it is never written to a log line or an
//     audit row here, and `common/audit.js` redacts it from the path an HTTP
//     row records (`redactedPath()`).
//   * LANGUAGE-FREE (rcbj's decision 3 on #570): a view is facts, and the
//     browser draws them in its language from the `authn` catalogs #539
//     wrote for these pages. Refusals are English (#539's decision 6), and
//     NO ERROR CODE IS EVER IN AN ANSWER — codes are recorded, never sent.
//   * THE LOGIC IS `authn/authn.ts`'s, NOT THIS FILE'S. Every view is that
//     module's (`screenView()`, `selectIdpView()`, `passwordChangeView()`) and
//     every act is that module's (`screenAct()` — what `POST /authn/login`
//     did, moved whole — `passkeyOptions()`, `passwordChangeAct()`): rate
//     limits, risk scoring, lockout, the issuance policy, the restart at a
//     home cell and the audit rows are exactly what the form's handler did.
//     This file is the door: the operation table, the CSRF binding, the body
//     schemas, and the OpenAPI document.
//
// EVERY ACT IS BOUND THREE WAYS (rcbj's decision 2 on #571):
//
//   1. THE PENDING ID in the path — the capability.
//   2. A TOKEN BOUND TO THE ARRIVAL COOKIE, in `X-CSRF-Token`:
//      `websecurity.tokenFor()` of the `sts_session` cookie's session id —
//      the signed double submit every form here already uses, derived and
//      not stored. The cookie is minted at the FRONT DOORS
//      (`ARRIVAL_PATHS`, the three shells among them), so a browser at the
//      screen always holds one; a request with NO session is REFUSED here,
//      unlike `checkCsrf()`'s no-session pass, because an act on this API
//      always follows a page that minted one. The views answer the token
//      (`csrf`), which a same-origin page can read and nobody else can
//      (`common/cors.js` answers no other origin).
//   3. `Content-Type: application/json` AND AN `Origin` THIS SERVICE ANSWERS
//      ON (`cors.ownOrigins()`): a cross-site form cannot send JSON, and a
//      cross-site script's request carries its own origin.
//
// THE ANSWERS NAME THE NEXT STEP (`authn.ts`, *What the sign-in screen's acts
// answer*): `redirect`, `mfa`, `password-change`, `home-cell`, or a refusal.
// The session cookie is set on the answer to the act that completes the
// sign-in, as it was on the form's 303.
//
// A ROUTE MODULE ON THE COMPOSITION ROOT'S PATTERN (#50): it registers
// nothing when required; `common/protocol_stack.ts` builds it and calls
// `registerRoutes(app)` just after `authn`, whose functions it calls through
// that module's exports.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import websecurity = require('../common/websecurity');
import stsCrypto = require('../common/crypto');
import version = require('../common/version');
// THE ORIGINS THIS SERVICE ANSWERS ON (a LIBRARY, rule 3), for the Origin
// check: the same list the CORS answer is built from.
import cors = require('../common/cors');
// THE SIGN-IN SERVICE, whose views and acts these are, and the reason this
// file is below #8 in the require order.
import authn = require('./authn');

type Json = any;

const vz = validation.z;
const vt = validation.types;

// The header an act's CSRF token travels in.
const CSRF_HEADER = 'x-csrf-token';

const API = authn.AUTHN_API_PATH;

// ---------------------------------------------------------------------------
// THE BODIES, ONE PER OPERATION. Closed shapes: a field this API does not
// take is refused (`.strict()`), because these are this service's own
// operations answering to no specification, and a field that decides
// whether a credential is issued must not arrive under a name nobody reads.
//
// They are the sign-in form's fields as they were (the form is gone), and
// `screenAct()` receives them as the form handler did, its `action` set by
// the operation. What each field is:
//
//   * `username` — `vt.name`, a BOUND and no control characters, and
//     deliberately not `vt.identifier`: this service accepts any name, and
//     narrowing it would refuse people whose names are none of its business.
//   * `password` — bounded and nothing else: its content is
//     `credentials.ts`'s business in product mode and nobody's in
//     development, and a scrypt should not be asked to hash a megabyte.
//   * `use_webauthn`, `webauthn_only` — the two passkey boxes; the record,
//     not the body, decides where a demand or a configuration fixed them.
//   * `remember_browser` (#265), `device_fp` (#62 P6, FingerprintJS's
//     visitorId, hex; empty where the realm asks for none).
//   * `credential` — a passkey ceremony's result (#474), bounded and parsed
//     downstream as the WebAuthn page's is.
// ---------------------------------------------------------------------------
const FLAG = vt.opt(vt.flag);
const FINGERPRINT = vz.string().max(64).regex(/^[A-Za-z0-9]*$/).optional();

const PASSWORD_BODY = vz.object({
  username: vt.opt(vt.name),
  password: vz.string().max(1024).optional(),
  use_webauthn: FLAG,
  webauthn_only: FLAG,
  remember_browser: FLAG,
  device_fp: FINGERPRINT
}).strict();

const EMPTY_BODY = vz.object({}).strict();

const ANONYMOUS_BODY = vz.object({
  remember_browser: FLAG,
  device_fp: FINGERPRINT
}).strict();

const EMAIL_BODY = vz.object({
  username: vt.opt(vt.name),
  kind: vt.oneOf(['code', 'link']),
  remember_browser: FLAG,
  device_fp: FINGERPRINT
}).strict();

const PASSKEY_BODY = vz.object({
  credential: vz.string().max(validation.CAP.TEXT).optional(),
  remember_browser: FLAG,
  device_fp: FINGERPRINT
}).strict();

const PASSWORD_CHANGE_BODY = vz.object({
  new_password: vz.string().max(1024).optional(),
  confirm_password: vz.string().max(1024).optional()
}).strict();

// THE SECOND-FACTOR AND EMAILED-FACTOR STEPS' BODIES (#572, #573): the
// fields their forms posted, `mfa_id` gone into the path.
//
//   * `code` — a STRING, never a number: `007123` is not 7123, and
//     `common/totp.ts` refuses anything that is not exactly the enrolled
//     number of digits. A recovery code's bound is wider (letters, dashes
//     and the spaces somebody typed off paper), and its alphabet is
//     `common/backup_codes.ts`'s business.
//   * `credential` — a ceremony's result, bounded and parsed downstream.
//   * `key` — the passkey a person chose (#534), a credential id.
//   * `t` — a mailed link's token, as the link carried it.
const CODE_BODY = vz.object({
  code: vz.string().max(32).optional()
}).strict();

const BACKUP_CODE_BODY = vz.object({
  code: vz.string().max(64).optional()
}).strict();

const FACTOR_PASSWORD_BODY = vz.object({
  password: vz.string().max(1024).optional()
}).strict();

const KEY_BODY = vz.object({
  key: vt.opt(vt.base64url)
}).strict();

const CREDENTIAL_BODY = vz.object({
  credential: vz.string().max(validation.CAP.TEXT).optional()
}).strict();

const SEND_BODY = vz.object({
  kind: vt.oneOf(['code', 'link'])
}).strict();

const OPEN_BODY = vz.object({
  t: vt.opt(vt.base64url)
}).strict();

// The pages a step's view is asked for (`?page=`), and the passkey chosen.
const MFA_PAGES = ['totp', 'webauthn', 'backup-code', 'password', 'setup',
                   'email-code', 'email-link', 'email-link-open'];

const MFA_QUERY = vz.object({
  page: vt.opt(vt.oneOf(MFA_PAGES)),
  key: vt.opt(vt.base64url)
});

const ID_PARAMS = vz.object({
  id: vt.base64url
});

/**
 * One operation of the API.
 */
interface Operation {
  method: 'GET' | 'POST';
  // The express path, `:id` a path parameter.
  path: string;
  operationId: string;
  // `pending` — keyed by a pending sign-in's id; `step` — a password change
  // step's id; `mfa` — a second-factor or emailed-factor step's id (#572,
  // #573); `public` — none.
  access: 'public' | 'pending' | 'step' | 'mfa';
  // The page or form control this operation is the door of, for the
  // runtime and the reader (`/account-api`'s convention, rule 7's twin).
  mirrors: string | null;
  // For an act at the screen: the form's `action` it is.
  action?: string;
  summary: string;
  description: string;
  body?: Json;
  // The answer's shape, documented.
  answer?: Json;
  // The code a body this operation does not take is recorded under, where
  // its form had one of its own (#572: the one-time code's, the
  // ceremony's, the recovery code's).
  bodyCode?: string;
  handler: string;
}

// THE ANSWERS, DOCUMENTED ONCE for the OpenAPI document.
const NEXT_ANSWER = {
  type: 'object',
  description: 'What the act leads to. `redirect`: go to `location` with a ' +
    'GET — back to the request that sent the person here (the session ' +
    'cookie is set on this answer where a sign-in completed). `mfa`: the ' +
    'second-factor step `step` (`totp`, `webauthn`, `enrol`, `email-code`, ' +
    '`email-link`) whose page is `location`. `password-change`: the forced ' +
    'change, at `location`. `home-cell`: the person is homed in another ' +
    'cell; send `form` (its `method`, `action` and `fields`) as it is. ' +
    '`refused`: `errors` says why, in English, and the page is drawn ' +
    'again — or, where `location` is named (a session refused at the end ' +
    'of a second-factor step), the sign-in screen at `location` says it; ' +
    'with `end` (`{ title }`), the emailed factor\'s page ends there. ' +
    '`stay`: an emailed factor was sent (`notice: resent`) and the page is ' +
    'drawn again.',
  properties: {
    ok: { type: 'boolean' },
    next: { type: 'string',
            enum: ['redirect', 'mfa', 'password-change', 'home-cell',
                   'stay', 'refused'] },
    location: { type: 'string' },
    step: { type: 'string' },
    id: { type: 'string' },
    form: { type: 'object' },
    notice: { type: 'string' },
    end: { type: 'object' },
    errors: { type: 'array', items: { type: 'string' } },
    passkey: { type: 'object',
               description: 'After a refused passkey: a credential nobody ' +
                 'holds, to signal to the credential manager, and whether ' +
                 'the autofill may be armed again.' }
  }
};

const OPERATIONS: Operation[] = [
  { method: 'GET', path: API, operationId: 'getIndex', access: 'public',
    mirrors: null, handler: 'index',
    summary: 'Lists every operation of this API',
    description: 'Each operation, its method and path, and the sign-in ' +
      'page or control it is the door of.' },
  { method: 'GET', path: API + '/openapi.json', operationId: 'getOpenApi',
    access: 'public', mirrors: null, handler: 'openApi',
    summary: 'This API\'s OpenAPI document',
    description: 'Generated from the operation table and its body schemas.' },
  { method: 'GET', path: API + '/pending/:id', operationId: 'getScreen',
    access: 'pending', mirrors: 'GET /authn/login', handler: 'screen',
    summary: 'What the sign-in screen offers for a pending sign-in',
    description: 'The screen\'s view, as facts and no words: the ' +
      'authentication policy\'s mechanisms, the passkey policy\'s boxes, ' +
      'the demands the calling protocol made, the partners, the Kerberos ' +
      'and wallet doors, what this mode checks, and the protocol\'s own ' +
      'rows — and `csrf`, the token every act on this sign-in carries.' },
  { method: 'GET', path: API + '/pending/:id/partners',
    operationId: 'getPartners', access: 'pending',
    mirrors: 'GET /authn/select-idp', handler: 'partners',
    summary: 'The federation partners a sign-in may choose between',
    description: 'Resolved again from the application\'s entry; with fewer ' +
      'than two left, `go` names the sign-in screen instead.' },
  { method: 'POST', path: API + '/pending/:id/password',
    operationId: 'signInWithPassword', access: 'pending',
    mirrors: 'POST /authn/login', action: 'login', handler: 'act',
    body: PASSWORD_BODY, answer: NEXT_ANSWER,
    summary: 'Signs in with a username and password, or a passkey for the ' +
             'named account',
    description: 'The Sign In button: the password checked (in product ' +
      'mode), rate limited by identity and address, the risk assessed, ' +
      'the issuance policy asked, and the second factor, the set-up step ' +
      'or the forced password change answered as the next step. ' +
      '`webauthn_only` asks for a passkey instead of the password.' },
  { method: 'POST', path: API + '/pending/:id/cancel',
    operationId: 'cancelSignIn', access: 'pending',
    mirrors: 'POST /authn/login', action: 'cancel', handler: 'act',
    body: EMPTY_BODY, answer: NEXT_ANSWER,
    summary: 'Declines the sign-in',
    description: 'Cancel: the calling protocol is told the person ' +
      'declined (`authn_error=access_denied`) at `location`.' },
  { method: 'POST', path: API + '/pending/:id/anonymous',
    operationId: 'continueAnonymously', access: 'pending',
    mirrors: 'POST /authn/login', action: 'anonymous', handler: 'act',
    body: ANONYMOUS_BODY, answer: NEXT_ANSWER,
    summary: 'Continues without signing in',
    description: 'Where `authn.unauthenticatedSessions` is on: a session ' +
      'that records that nobody authenticated.' },
  { method: 'POST', path: API + '/pending/:id/email',
    operationId: 'signInByEmail', access: 'pending',
    mirrors: 'POST /authn/login', action: 'email', handler: 'act',
    body: EMAIL_BODY, answer: NEXT_ANSWER,
    summary: 'Mails a sign-in code or link as a first factor',
    description: 'Where the authentication policy accepts one (#64): the ' +
      'next step is the page that waits for it, the same whether or not ' +
      'the account exists.' },
  { method: 'POST', path: API + '/pending/:id/passkey/options',
    operationId: 'passkeyOptions', access: 'pending',
    mirrors: 'POST /authn/login', action: 'passkey-options',
    handler: 'passkeyOptions', body: EMPTY_BODY,
    summary: 'Arms a passkey ceremony with no username',
    description: 'A single-use challenge on the pending sign-in, the RP ID ' +
      'and the request options, for the button and the username field\'s ' +
      'autofill (conditional mediation).' },
  { method: 'POST', path: API + '/pending/:id/passkey',
    operationId: 'signInWithPasskey', access: 'pending',
    mirrors: 'POST /authn/login', action: 'passkey', handler: 'act',
    body: PASSKEY_BODY, answer: NEXT_ANSWER,
    summary: 'Signs in with a passkey and no username',
    description: 'The ceremony\'s result, verified with user verification ' +
      'required against the challenge `passkey/options` armed.' },
  { method: 'GET', path: API + '/password-change/:id',
    operationId: 'getPasswordChange', access: 'step',
    mirrors: 'GET /authn/password-change', handler: 'passwordChange',
    summary: 'The forced password change a sign-in is waiting on',
    description: 'Whose password, and why it must be changed now where ' +
      'there is a reason to give; `csrf` as for the screen.' },
  { method: 'POST', path: API + '/password-change/:id',
    operationId: 'changePassword', access: 'step',
    mirrors: 'POST /authn/password-change', action: 'password-change',
    handler: 'changePassword', body: PASSWORD_CHANGE_BODY,
    answer: NEXT_ANSWER,
    summary: 'Stores the new password and continues the sign-in',
    description: 'Held to the password policy; the sign-in then continues ' +
      'exactly as after the password step — second factor included.' },
  // --- the second-factor and emailed-factor steps (#572, #573) -----------
  { method: 'GET', path: API + '/mfa/:id', operationId: 'getStep',
    access: 'mfa', handler: 'mfaStep',
    mirrors: 'GET /authn/totp, /authn/webauthn, /authn/backup-code, ' +
             '/authn/password-factor, /authn/mfa-setup, /authn/email-code, ' +
             '/authn/email-link, /authn/email-link/open',
    summary: 'What a second-factor or emailed-factor step\'s page shows',
    description: 'The step\'s view for the page `page` names (`totp`, ' +
      '`webauthn`, `backup-code`, `password`, `setup`, `email-code`, ' +
      '`email-link`, `email-link-open`; the step\'s own where left out), ' +
      'as facts and no words: the person, the ways round the factor asked ' +
      'for, the set-up step\'s choice and its authenticator app\'s ' +
      '`otpauth:` URI, the passkey ceremony\'s description, an emailed ' +
      'factor\'s state — and `csrf`. Refused (400) where the page could ' +
      'never be drawn for the step: an expired step, a code page for ' +
      'somebody with no authenticator app, a passkey page for somebody ' +
      'holding no key of the step\'s role. `key` names the passkey a ' +
      'person chose where the passkey policy offers them one by one.' },
  { method: 'POST', path: API + '/mfa/:id/totp', operationId: 'checkCode',
    access: 'mfa', mirrors: 'POST /authn/totp', action: 'totp',
    handler: 'mfaAct', body: CODE_BODY, answer: NEXT_ANSWER,
    bodyCode: 'STS-AUTHN-0039',
    summary: 'Checks a one-time code from an authenticator app',
    description: 'RFC 6238, checked in every mode and rate limited by ' +
      'identity and address; a refused code keeps the step.' },
  { method: 'POST', path: API + '/mfa/:id/backup-code',
    operationId: 'spendRecoveryCode', access: 'mfa',
    mirrors: 'POST /authn/backup-code', action: 'backup-code',
    handler: 'mfaAct', body: BACKUP_CODE_BODY, answer: NEXT_ANSWER,
    bodyCode: 'STS-AUTHN-0041',
    summary: 'Checks and spends a recovery code',
    description: 'In place of the second factor; a code that cannot be ' +
      'marked spent is refused.' },
  { method: 'POST', path: API + '/mfa/:id/password',
    operationId: 'checkFactorPassword', access: 'mfa',
    mirrors: 'POST /authn/password-factor', action: 'password',
    handler: 'mfaAct', body: FACTOR_PASSWORD_BODY, answer: NEXT_ANSWER,
    summary: 'Checks a password as the second factor after a wallet',
    description: 'Rate limited on the sign-in bucket.' },
  { method: 'POST', path: API + '/mfa/:id/webauthn/options',
    operationId: 'passkeyStepOptions', access: 'mfa',
    mirrors: 'POST /authn/webauthn', action: 'webauthn-options',
    handler: 'mfaAct', body: KEY_BODY,
    summary: 'Arms the passkey step\'s ceremony',
    description: 'The step\'s challenge, the RP ID, the user (its handle ' +
      'and display name), the keys allowed and excluded and the passkey ' +
      'policy\'s options, for `navigator.credentials.create()` or ' +
      '`.get()` as `mode` says.' },
  { method: 'POST', path: API + '/mfa/:id/webauthn',
    operationId: 'finishPasskeyStep', access: 'mfa',
    mirrors: 'POST /authn/webauthn', action: 'webauthn',
    handler: 'mfaAct', body: CREDENTIAL_BODY, answer: NEXT_ANSWER,
    bodyCode: 'STS-AUTHN-0020',
    summary: 'Verifies the passkey step\'s ceremony and finishes the step',
    description: 'A registration where the step enrols a key, an ' +
      'assertion otherwise — decided by the step, not the body.' },
  { method: 'POST', path: API + '/mfa/:id/setup/totp',
    operationId: 'beginAppEnrolment', access: 'mfa',
    mirrors: 'POST /authn/mfa-setup', action: 'totp', handler: 'mfaAct',
    body: EMPTY_BODY, answer: NEXT_ANSWER,
    summary: 'Begins enrolling an authenticator app at the set-up step',
    description: 'The next step is the set-up page again, drawing the ' +
      'secret.' },
  { method: 'POST', path: API + '/mfa/:id/setup/confirm',
    operationId: 'confirmAppEnrolment', access: 'mfa',
    mirrors: 'POST /authn/mfa-setup', action: 'confirm-totp',
    handler: 'mfaAct', body: CODE_BODY, answer: NEXT_ANSWER,
    summary: 'Confirms an authenticator app with its first code',
    description: 'Rate limited; on success a session of two factors.' },
  { method: 'POST', path: API + '/mfa/:id/setup/webauthn',
    operationId: 'beginKeyEnrolment', access: 'mfa',
    mirrors: 'POST /authn/mfa-setup', action: 'webauthn',
    handler: 'mfaAct', body: EMPTY_BODY, answer: NEXT_ANSWER,
    summary: 'Chooses a passkey at the set-up step',
    description: 'The next step is the passkey page\'s registration.' },
  { method: 'POST', path: API + '/mfa/:id/skip',
    operationId: 'ignoreOffer', access: 'mfa',
    mirrors: 'POST /authn/mfa-setup', action: 'ignore', handler: 'mfaAct',
    body: EMPTY_BODY, answer: NEXT_ANSWER,
    summary: 'Ignores an offered second factor (#246)',
    description: 'Only where the step was offered rather than required: ' +
      'the sign-in finishes on the password.' },
  { method: 'POST', path: API + '/mfa/:id/email/send',
    operationId: 'sendEmailedFactor', access: 'mfa',
    mirrors: 'POST /authn/email-code, /authn/email-link', action: 'send',
    handler: 'mfaAct', body: SEND_BODY, answer: NEXT_ANSWER,
    summary: 'Mails a code or a sign-in link for the step (#64)',
    description: 'To the person\'s verified address only; a resend ' +
      'replaces the last. `next: stay` with `notice: resent` where it ' +
      'went. A link\'s binding cookie is set on this answer.' },
  { method: 'POST', path: API + '/mfa/:id/email/code',
    operationId: 'checkEmailedCode', access: 'mfa',
    mirrors: 'POST /authn/email-code', action: 'verify',
    handler: 'mfaAct', body: CODE_BODY, answer: NEXT_ANSWER,
    summary: 'Checks an emailed code',
    description: 'Once for the cluster, a bounded number of wrong codes ' +
      'per step, rate limited as the one-time code is.' },
  { method: 'POST', path: API + '/mfa/:id/email-link/open',
    operationId: 'spendEmailedLink', access: 'mfa',
    mirrors: 'POST /authn/email-link/open', action: 'open',
    handler: 'mfaAct', body: OPEN_BODY, answer: NEXT_ANSWER,
    summary: 'Spends a mailed sign-in link: its Continue button',
    description: 'Only in the browser that asked for the link (the ' +
      '`sts_email_binding` cookie). Opening the link spends nothing.' }
];

interface AuthnApiDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  websecurity: typeof websecurity;
  stsCrypto: typeof stsCrypto;
  cors: typeof cors;
  authn: typeof authn;
}

/**
 * `/authn-api`: the operation table, the CSRF binding, the body schemas and
 * the OpenAPI document of the sign-in screen's API.
 */
class AuthnApi {
  /**
   * Builds the API over its dependencies.
   *
   * @param deps - the modules it uses
   */
  constructor(private readonly deps: AuthnApiDeps) {
    deps.log.debug("Entering AuthnApi.constructor().");
    deps.log.debug("Leaving AuthnApi.constructor().");
  }

  /**
   * The dependencies from the real modules, as the composition root passes
   * them.
   *
   * @returns the dependency object
   */
  static defaultDeps(): AuthnApiDeps {
    helpers.log.debug("Entering AuthnApi.defaultDeps().");
    helpers.log.debug("Leaving AuthnApi.defaultDeps().");
    return { log: helpers.log, helpers: helpers, errorCodes: errorCodes,
             validation: validation, websecurity: websecurity,
             stsCrypto: stsCrypto, cors: cors, authn: authn };
  }

  /**
   * The operation table.
   *
   * @returns the operations
   */
  static operations(): Operation[] {
    helpers.log.debug("Entering AuthnApi.operations().");
    helpers.log.debug("Leaving AuthnApi.operations().");
    return OPERATIONS.slice();
  }

  // --- answers ---------------------------------------------------------------

  // A refusal of the request itself — its shape, its binding, its id — in
  // the vocabulary every refusal at these doors used (`oauthError()`'s
  // members), with `ok: false` and `errors` beside them so the runtime reads
  // it as every API answer. The code was marked on the response by the
  // caller; it is never in the body.
  // error-code: none — the definition of this helper; every call site marks its own code first
  private refuse(res: Json, status: number, why: string): void {
    const { log, authn } = this.deps;
    log.debug("Entering AuthnApi.refuse(). " + status);
    authn.answerJson(res, status, { ok: false, errors: [why],
                                    error: 'invalid_request',
                                    error_description: why });
    log.debug("Leaving AuthnApi.refuse().");
  }

  // The token for the session behind this request's cookie, or '' where
  // there is none.
  private csrfOf(req: Json): string {
    const { log, authn, websecurity } = this.deps;
    log.debug("Entering AuthnApi.csrfOf().");
    const found = authn.cookieSession(req, authn.SESSION_COOKIE);
    const token = found && found.id ? websecurity.tokenFor(found.id) : '';
    log.debug("Leaving AuthnApi.csrfOf(). " + (token ? 'A session.'
                                                     : 'No session.'));
    return token;
  }

  // ---------------------------------------------------------------------------
  // THE BINDING OF AN ACT: JSON, AN ORIGIN OF THIS SERVICE, AND THE TOKEN OF
  // THE COOKIE'S SESSION (the header). True where it may go on; otherwise
  // the refusal is sent. Asked BEFORE the pending id is looked up, so a
  // request that is not bound learns nothing about which ids are live.
  // ---------------------------------------------------------------------------
  /**
   * Checks an act's content type, origin and CSRF token, refusing it where
   * one fails.
   *
   * @param req - the request
   * @param res - the response
   * @returns whether the act may go on
   */
  bound(req: Json, res: Json): boolean {
    const { log, errorCodes, stsCrypto, cors } = this.deps;
    log.debug("Entering AuthnApi.bound().");
    const type = String((req.headers && req.headers['content-type']) || '');
    if (!/^application\/json\s*(;|$)/i.test(type)) {
      errorCodes.mark(res, 'STS-AUTHN-0325');
      this.refuse(res, 415, 'This operation takes a JSON body ' +
        '(Content-Type: application/json).');
      log.debug("Leaving AuthnApi.bound(). Not JSON.");
      return false;
    }
    const origin = String((req.headers && req.headers.origin) || '');
    let own: string[] = [];
    try {
      own = cors.ownOrigins(req) || [];
    } catch (e) {
      log.debug("Caught in AuthnApi.bound(): " + ((e && e.message) || e));
      own = [];
    }
    if (!origin || own.indexOf(origin) < 0) {
      errorCodes.mark(res, 'STS-AUTHN-0326');
      this.refuse(res, 403, 'This operation is sent by a page of this ' +
        'service: the request carried ' + (origin ? 'another origin'
                                                  : 'no Origin') + '.');
      log.debug("Leaving AuthnApi.bound(). Not this origin.");
      return false;
    }
    const expected = this.csrfOf(req);
    const presented = String((req.headers && req.headers[CSRF_HEADER]) || '');
    if (!expected || !presented ||
        !stsCrypto.constantTimeEquals(presented, expected)) {
      errorCodes.mark(res, 'STS-AUTHN-0327');
      this.refuse(res, 403, expected
        ? 'The ' + CSRF_HEADER + ' header is missing or is not this ' +
          'browser\'s. Load the sign-in page again.'
        : 'This browser holds no session for this sign-in. Load the ' +
          'sign-in page again.');
      log.debug("Leaving AuthnApi.bound(). The token.");
      return false;
    }
    log.debug("Leaving AuthnApi.bound(). Bound.");
    return true;
  }

  // The id in the path, checked for shape; null with the refusal sent.
  private idOf(req: Json, res: Json): string | null {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering AuthnApi.idOf().");
    const asked = validation.checkParsed(req.params || {}, 'params',
                                         ID_PARAMS);
    if (!asked.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0001');
      this.refuse(res, 400, 'That is not the id of a sign-in.');
      log.debug("Leaving AuthnApi.idOf(). Not an id.");
      return null;
    }
    log.debug("Leaving AuthnApi.idOf().");
    return String(asked.value.id);
  }

  // The pending sign-in; null with the refusal sent — the screen's own
  // sentence for an id that expired, was spent or never existed.
  private pendingOf(req: Json, res: Json): Json {
    const { log, authn, errorCodes } = this.deps;
    log.debug("Entering AuthnApi.pendingOf().");
    const id = this.idOf(req, res);
    if (id === null) {
      log.debug("Leaving AuthnApi.pendingOf(). No id.");
      return null;
    }
    const record = authn.pendingFor(id);
    if (!record) {
      errorCodes.mark(res, 'STS-AUTHN-0003');
      this.refuse(res, 400, 'There is no sign-in waiting under that id, or ' +
        'it has expired. Start the request again from the application that ' +
        'sent you here.');
      log.debug("Leaving AuthnApi.pendingOf(). Nothing pending.");
      return null;
    }
    log.debug("Leaving AuthnApi.pendingOf().");
    return record;
  }

  // The body, checked against the operation's schema; null with the
  // refusal sent.
  private bodyOf(req: Json, res: Json, op: Operation): Json {
    const { log, validation, errorCodes, helpers } = this.deps;
    log.debug("Entering AuthnApi.bodyOf(). " + op.operationId);
    const posted = validation.checkParsed(helpers.parseBody(req) || {},
                                          'body', op.body || EMPTY_BODY);
    if (!posted.ok) {
      errorCodes.mark(res, op.bodyCode || (op.access === 'step'
        ? 'STS-AUTHN-0145'
        : (op.access === 'mfa' ? 'STS-AUTHN-0330' : 'STS-AUTHN-0002')));
      this.refuse(res, 400, String(posted.detail || 'The body is refused.'));
      log.debug("Leaving AuthnApi.bodyOf(). Refused.");
      return null;
    }
    log.debug("Leaving AuthnApi.bodyOf().");
    return posted.value;
  }

  // A JSON flag as the form's '1': `true`, `1`, `on`, `yes`.
  private static flagOf(value: unknown): string {
    helpers.log.debug("Entering AuthnApi.flagOf().");
    helpers.log.debug("Leaving AuthnApi.flagOf().");
    return ['true', '1', 'on', 'yes'].indexOf(String(value || '')
      .toLowerCase()) >= 0 ? '1' : '';
  }

  // --- the handlers ----------------------------------------------------------

  /**
   * `GET /authn-api`: the index.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  index(req: Json, res: Json): void {
    const { log, authn } = this.deps;
    log.debug("Entering AuthnApi.index().");
    void req;
    authn.answerJson(res, 200, { api: 'IYA STS sign-in',
      openapi: API + '/openapi.json',
      operations: OPERATIONS.map(function (op) {
        return { method: op.method,
                 path: op.path.replace(/:([A-Za-z]+)/g, '{$1}'),
                 operationId: op.operationId, access: op.access,
                 mirrors: op.mirrors, action: op.action || null,
                 summary: op.summary };
      }) });
    log.debug("Leaving AuthnApi.index().");
  }

  /**
   * `GET /authn-api/openapi.json`.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  openApi(req: Json, res: Json): void {
    const { log, authn, helpers } = this.deps;
    log.debug("Entering AuthnApi.openApi().");
    authn.answerJson(res, 200, AuthnApi.document({
      baseUrl: helpers.baseUrlOf(req),
      version: String(version.load().version || '') }));
    log.debug("Leaving AuthnApi.openApi().");
  }

  /**
   * `GET /authn-api/pending/{id}`: the screen's view.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  screen(req: Json, res: Json): void {
    const { log, authn } = this.deps;
    log.debug("Entering AuthnApi.screen().");
    const record = this.pendingOf(req, res);
    if (!record) {
      log.debug("Leaving AuthnApi.screen(). Refused.");
      return;
    }
    const own = authn.preferredLanguageOf(String(record.lockedUsername ||
                                                 ''));
    authn.answerJson(res, 200, Object.assign({ ok: true,
      view: authn.screenView(req, record, authn.screenProblem(record)),
      csrf: this.csrfOf(req),
      uiLocales: String(record.uiLocales || '') },
      own ? { preferredLanguage: own } : {}));
    log.debug("Leaving AuthnApi.screen().");
  }

  /**
   * `GET /authn-api/pending/{id}/partners`: the chooser's view.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  partners(req: Json, res: Json): void {
    const { log, authn } = this.deps;
    log.debug("Entering AuthnApi.partners().");
    const record = this.pendingOf(req, res);
    if (!record) {
      log.debug("Leaving AuthnApi.partners(). Refused.");
      return;
    }
    // FEWER THAN TWO LEFT: the screen instead, as the chooser's GET sends a
    // browser there (`authn.ts`).
    if (authn.refreshPartners(record) < 2) {
      authn.answerJson(res, 200, { ok: true,
        go: authn.LOGIN_PATH + '?authn=' + encodeURIComponent(record.id) });
      log.debug("Leaving AuthnApi.partners(). The screen.");
      return;
    }
    authn.answerJson(res, 200, { ok: true,
      view: authn.selectIdpView(req, record), csrf: this.csrfOf(req),
      uiLocales: String(record.uiLocales || '') });
    log.debug("Leaving AuthnApi.partners().");
  }

  /**
   * `POST /authn-api/pending/{id}/…`: an act at the screen, handed to
   * `screenAct()` with the form's fields.
   *
   * @param req - the request
   * @param res - the response
   * @param op - the operation
   * @returns a promise settled when the answer is sent
   */
  async act(req: Json, res: Json, op: Operation): Promise<void> {
    const { log, authn } = this.deps;
    log.debug("Entering AuthnApi.act(). " + op.operationId);
    if (this.idOf(req, res) === null || !this.bound(req, res)) {
      log.debug("Leaving AuthnApi.act(). Refused at the door.");
      return;
    }
    const body = this.bodyOf(req, res, op);
    if (!body) {
      log.debug("Leaving AuthnApi.act(). The body.");
      return;
    }
    const record = this.pendingOf(req, res);
    if (!record) {
      log.debug("Leaving AuthnApi.act(). Nothing pending.");
      return;
    }
    const action = op.action === 'email'
      ? (body.kind === 'link' ? 'email-link' : 'email-code')
      : String(op.action);
    const fields = { action: action,
      username: body.username, password: body.password,
      use_webauthn: AuthnApi.flagOf(body.use_webauthn),
      webauthn_only: AuthnApi.flagOf(body.webauthn_only),
      remember_browser: AuthnApi.flagOf(body.remember_browser),
      device_fp: body.device_fp,
      passkey_credential: body.credential };
    await authn.screenAct(req, res, record, fields);
    log.debug("Leaving AuthnApi.act().");
  }

  /**
   * `POST /authn-api/pending/{id}/passkey/options`.
   *
   * @param req - the request
   * @param res - the response
   * @param op - the operation
   * @returns nothing
   */
  passkeyOptions(req: Json, res: Json, op: Operation): void {
    const { log, authn, errorCodes } = this.deps;
    log.debug("Entering AuthnApi.passkeyOptions().");
    if (this.idOf(req, res) === null || !this.bound(req, res) ||
        !this.bodyOf(req, res, op)) {
      log.debug("Leaving AuthnApi.passkeyOptions(). Refused.");
      return;
    }
    const record = this.pendingOf(req, res);
    if (!record) {
      log.debug("Leaving AuthnApi.passkeyOptions(). Nothing pending.");
      return;
    }
    const armed = authn.passkeyOptions(req, record);
    if (!armed.ok) {
      errorCodes.mark(res, errorCodes.codeOf(armed) || 'STS-AUTHN-0301');
      authn.answerJson(res, 400, { ok: false, next: 'refused',
                                   errors: [String(armed.why)] });
      log.debug("Leaving AuthnApi.passkeyOptions(). Not offered.");
      return;
    }
    authn.answerJson(res, 200, { ok: true, challenge: armed.challenge,
                                 rpId: armed.rpId, options: armed.options });
    log.debug("Leaving AuthnApi.passkeyOptions().");
  }

  // The forced password change's step; null with the refusal sent.
  private stepOf(req: Json, res: Json): Json {
    const { log, authn, errorCodes } = this.deps;
    log.debug("Entering AuthnApi.stepOf().");
    const asked = this.deps.validation.checkParsed(req.params || {},
                                                   'params', ID_PARAMS);
    if (!asked.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0145');
      this.refuse(res, 400, 'That is not the id of a password change.');
      log.debug("Leaving AuthnApi.stepOf(). Not an id.");
      return null;
    }
    // `passwordChangeStep()` sends its own refusal (STS-AUTHN-0144).
    const step = authn.passwordChangeStep(res, String(asked.value.id));
    log.debug("Leaving AuthnApi.stepOf().");
    return step ? { id: String(asked.value.id), step: step } : null;
  }

  /**
   * `GET /authn-api/password-change/{id}`.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  passwordChange(req: Json, res: Json): void {
    const { log, authn } = this.deps;
    log.debug("Entering AuthnApi.passwordChange().");
    const found = this.stepOf(req, res);
    if (!found) {
      log.debug("Leaving AuthnApi.passwordChange(). No step.");
      return;
    }
    const own = authn.preferredLanguageOf(String(found.step.username || ''));
    authn.answerJson(res, 200, Object.assign({ ok: true,
      view: authn.passwordChangeView(found.id, found.step),
      csrf: this.csrfOf(req),
      uiLocales: String((found.step.authn && found.step.authn.uiLocales) ||
                        '') }, own ? { preferredLanguage: own } : {}));
    log.debug("Leaving AuthnApi.passwordChange().");
  }

  /**
   * `POST /authn-api/password-change/{id}`.
   *
   * @param req - the request
   * @param res - the response
   * @param op - the operation
   * @returns a promise settled when the answer is sent
   */
  async changePassword(req: Json, res: Json, op: Operation): Promise<void> {
    const { log, authn, errorCodes } = this.deps;
    log.debug("Entering AuthnApi.changePassword().");
    const asked = this.deps.validation.checkParsed(req.params || {},
                                                   'params', ID_PARAMS);
    if (!asked.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0145');
      this.refuse(res, 400, 'That is not the id of a password change.');
      log.debug("Leaving AuthnApi.changePassword(). Not an id.");
      return;
    }
    if (!this.bound(req, res)) {
      log.debug("Leaving AuthnApi.changePassword(). Refused at the door.");
      return;
    }
    const body = this.bodyOf(req, res, op);
    if (!body) {
      log.debug("Leaving AuthnApi.changePassword(). The body.");
      return;
    }
    const found = this.stepOf(req, res);
    if (!found) {
      log.debug("Leaving AuthnApi.changePassword(). No step.");
      return;
    }
    await authn.passwordChangeAct(req, res, found.id, found.step, body);
    log.debug("Leaving AuthnApi.changePassword().");
  }

  // ---------------------------------------------------------------------------
  // THE SECOND-FACTOR AND EMAILED-FACTOR STEPS (#572, #573). Keyed by the
  // step's id, which is a bearer capability as `?mfa=` always was: never
  // logged here, and redacted from an audit row's path. The view is
  // `authn.ts`'s (`mfaView()`) or the emailed factor's (`view()`); every
  // act is bound as the screen's are, and handed to the module whose form
  // POST it was. `res.locals.authnStep` says the answer belongs to a step,
  // so that a session refused at its end is drawn on the screen
  // (`authn.ts`, `screenRefused()`).
  // ---------------------------------------------------------------------------
  /**
   * `GET /authn-api/mfa/{id}`: a step's page's view.
   *
   * @param req - the request
   * @param res - the response
   * @returns nothing
   */
  mfaStep(req: Json, res: Json): void {
    const { log, authn, validation, errorCodes } = this.deps;
    log.debug("Entering AuthnApi.mfaStep().");
    const id = this.idOf(req, res);
    if (id === null) {
      log.debug("Leaving AuthnApi.mfaStep(). No id.");
      return;
    }
    const asked = validation.checkParsed(req.query || {}, 'query',
                                         MFA_QUERY);
    if (!asked.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0330');
      this.refuse(res, 400, 'That is not a page of a sign-in step.');
      log.debug("Leaving AuthnApi.mfaStep(). Not a page.");
      return;
    }
    const page = String(asked.value.page || this.pageOf(id));
    const csrf = this.csrfOf(req);
    if (page.indexOf('email-') === 0) {
      const seen = AuthnApi.emailFactor().view(req, page, id);
      if (seen.code) {
        errorCodes.mark(res, seen.code);
      }
      authn.answerJson(res, seen.status, Object.assign({
        ok: seen.status === 200, view: seen.view, csrf: csrf,
        uiLocales: seen.uiLocales },
        seen.status === 200 ? {} : { errors: [String(seen.view.sentence)] },
        seen.preferredLanguage ? { preferredLanguage: seen.preferredLanguage }
                               : {}));
      log.debug("Leaving AuthnApi.mfaStep(). " + page);
      return;
    }
    const seen = authn.mfaView(req, page, id, String(asked.value.key || ''));
    if (seen.problem) {
      errorCodes.mark(res, seen.problem.code);
      // error-code: none — marked on the line above, stepProblem()'s code
      this.refuse(res, 400, String(seen.problem.why));
      log.debug("Leaving AuthnApi.mfaStep(). Refused.");
      return;
    }
    authn.answerJson(res, 200, Object.assign({ ok: true, view: seen.view,
      csrf: csrf, uiLocales: seen.uiLocales },
      seen.preferredLanguage ? { preferredLanguage: seen.preferredLanguage }
                             : {}));
    log.debug("Leaving AuthnApi.mfaStep(). " + page);
  }

  // The page a step is drawn on where the view was asked for none: the
  // factor it asks for.
  private pageOf(id: string): string {
    const { log, authn } = this.deps;
    log.debug("Entering AuthnApi.pageOf().");
    const step = authn.mfaStepFor(id);
    const factor = String((step && step.factor) || '');
    const out = factor === 'enrol' || factor === 'enrol-totp' ? 'setup'
      : (['totp', 'webauthn', 'password', 'email-code', 'email-link']
          .indexOf(factor) >= 0 ? factor : 'totp');
    log.debug("Leaving AuthnApi.pageOf(). " + out);
    return out;
  }

  // The emailed factor's door, loaded when first used: it is built beside
  // `authn`, after it, and requires it.
  private static emailFactor(): Json {
    helpers.log.debug("Entering AuthnApi.emailFactor().");
    helpers.log.debug("Leaving AuthnApi.emailFactor().");
    return require('./email_factor');
  }

  /**
   * `POST /authn-api/mfa/{id}/…`: an act at a step, handed to the module
   * whose form it was.
   *
   * @param req - the request
   * @param res - the response
   * @param op - the operation
   * @returns a promise settled when the answer is sent
   */
  async mfaAct(req: Json, res: Json, op: Operation): Promise<void> {
    const { log, authn } = this.deps;
    log.debug("Entering AuthnApi.mfaAct(). " + op.operationId);
    const id = this.idOf(req, res);
    if (id === null || !this.bound(req, res)) {
      log.debug("Leaving AuthnApi.mfaAct(). Refused at the door.");
      return;
    }
    const body = this.bodyOf(req, res, op);
    if (!body) {
      log.debug("Leaving AuthnApi.mfaAct(). The body.");
      return;
    }
    res.locals.authnStep = true;
    const ef = AuthnApi.emailFactor();
    switch (op.operationId) {
      case 'checkCode':
        await authn.mfaTotpAct(req, res, id, body);
        break;
      case 'spendRecoveryCode':
        await authn.mfaBackupCodeAct(req, res, id, body);
        break;
      case 'checkFactorPassword':
        await authn.mfaPasswordAct(req, res, id, body);
        break;
      case 'passkeyStepOptions':
        authn.mfaWebauthnOptions(req, res, id, String(body.key || ''));
        break;
      case 'finishPasskeyStep':
        authn.mfaWebauthnAct(req, res, id, body);
        break;
      case 'beginAppEnrolment':
        await authn.mfaSetupAct(req, res, id, 'totp', body);
        break;
      case 'confirmAppEnrolment':
        await authn.mfaSetupAct(req, res, id, 'confirm', body);
        break;
      case 'beginKeyEnrolment':
        await authn.mfaSetupAct(req, res, id, 'webauthn', body);
        break;
      case 'ignoreOffer':
        await authn.mfaSetupAct(req, res, id, 'skip', body);
        break;
      case 'sendEmailedFactor':
        await ef.sendAct(req, res, id, body.kind);
        break;
      case 'checkEmailedCode':
        await ef.codeAct(req, res, id, String(body.code || ''));
        break;
      default:
        await ef.openAct(req, res, id, String(body.t || ''));
        break;
    }
    log.debug("Leaving AuthnApi.mfaAct().");
  }

  // ---------------------------------------------------------------------------
  // THE OPENAPI DOCUMENT: a pure function over the operation table, on
  // `account-api/account_api_spec.ts`'s rule — the schemas are the
  // operations' own zod objects, converted, so a field documented and a
  // field refused are one declaration.
  // ---------------------------------------------------------------------------
  /**
   * The OpenAPI 3.1 document of this API.
   *
   * @param options - `baseUrl` (the realm's) and `version`
   * @returns the document
   */
  static document(options: Json): Json {
    helpers.log.debug("Entering AuthnApi.document().");
    // The account API's converter, reused rather than written twice.
    const Spec = require('../account-api/account_api_spec');
    const base = String((options && options.baseUrl) || '');
    const paths: Json = {};
    OPERATIONS.forEach(function (op) {
      const path = String(op.path).replace(/:([A-Za-z]+)/g, '{$1}');
      paths[path] = paths[path] || {};
      const entry: Json = {
        operationId: op.operationId,
        tags: ['Sign-in'],
        summary: op.summary,
        description: op.description +
          (op.mirrors ? '\n\nThe door of the sign-in surface\'s `' +
                        op.mirrors + '`.' : '') +
          (op.method === 'POST'
            ? '\n\nSent with `Content-Type: application/json`, an `Origin` ' +
              'of this service and `X-CSRF-Token` — the `csrf` the page\'s ' +
              'view answered, bound to the browser\'s `sts_session` cookie.'
            : ''),
        parameters: op.access === 'public' ? [] :
          [{ name: 'id', in: 'path', required: true,
             description: op.access === 'step'
               ? 'The password change step\'s id.'
               : op.access === 'mfa'
               ? 'The second-factor or emailed-factor step\'s id: a ' +
                 'bearer capability, as the `mfa` its page was opened with.'
               : 'The pending sign-in\'s id: a bearer capability, as the ' +
                 '`authn` the screen was opened with.',
             schema: { type: 'string' } }],
        responses: {
          200: { description: 'The answer.', content: { 'application/json': {
            schema: op.answer || { type: 'object' } } } },
          400: { description: 'Refused: `{ ok: false, errors }` — the body, ' +
                              'the id, or the act itself.' }
        },
        security: []
      };
      if (op.method === 'POST') {
        entry.responses[403] = { description: 'No Origin of this service, ' +
          'or no CSRF token bound to this browser\'s session.' };
        entry.responses[415] = { description: 'Not a JSON body.' };
        entry.responses[429] = { description: 'Too many attempts.' };
        entry.requestBody = { required: true, content: { 'application/json': {
          schema: Spec.jsonSchemaOf(op.body || EMPTY_BODY) } } };
      }
      if (op.mirrors) {
        entry['x-mirrors'] = op.mirrors;
      }
      paths[path][op.method.toLowerCase()] = entry;
    });
    const doc = {
      openapi: '3.1.0',
      info: {
        title: 'IYA STS Sign-in API',
        version: String((options && options.version) || '0.0.0'),
        description: 'The sign-in screen\'s API: what the screen offers for ' +
          'a pending sign-in, and the acts it sends. Unauthenticated and ' +
          'keyed by the pending sign-in\'s id; every act is bound to the ' +
          'browser\'s session cookie by a CSRF token. Answers name the next ' +
          'step; refusals are English and carry no error code.'
      },
      servers: [{ url: base }],
      tags: [{ name: 'Sign-in' }],
      paths: paths
    };
    helpers.log.debug("Leaving AuthnApi.document().");
    return doc;
  }

  // THE ROUTES, registered by the composition root just after `authn`.
  /**
   * Registers every operation.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AuthnApi.registerRoutes().");
    OPERATIONS.forEach(function (op) {
      app[op.method.toLowerCase()](op.path, function (req: Json, res: Json) {
        log.debug('Entering ' + op.method + ' ' + op.path + '.');
        // THE ANSWERS ARE JSON: `authn.ts`'s acts read this off the
        // response (`answersJson()`).
        res.locals.authnApi = true;
        Promise.resolve((self as Json)[op.handler](req, res, op))
          .catch(function (e: Json) {
            log.debug("Caught in AuthnApi route: " +
                      ((e && e.message) || e));
            self.failed(res, e, op);
          });
        log.debug('Leaving ' + op.method + ' ' + op.path + '.');
      });
    });
    log.debug("Leaving AuthnApi.registerRoutes().");
  }

  // Every handler writes an answer; one that threw would leave a browser
  // waiting on a request nothing answers.
  // AN EMAILED FACTOR'S OPERATION (#573) keeps the code its door's own
  // failures were recorded under.
  private failed(res: Json, e: Json, op?: Operation): void {
    const { log, errorCodes, authn } = this.deps;
    log.debug("Entering AuthnApi.failed().");
    const email = !!op && /^\/authn-api\/mfa\/:id\/(email|email-link)\//
      .test(op.path);
    log.error(errorCodes.tag(email ? 'STS-AUTHN-0267' : 'STS-AUTHN-0328') +
              'authn: a sign-in API operation failed: ' +
              ((e && (e.stack || e.message)) || e));
    if (!res.headersSent) {
      errorCodes.mark(res, email ? 'STS-AUTHN-0267' : 'STS-AUTHN-0328');
      authn.answerJson(res, 500, { ok: false,
        errors: ['Something went wrong; this sign-in could not continue.'] });
    }
    log.debug("Leaving AuthnApi.failed().");
  }
}

const slot = new InstanceSlot<AuthnApi>(
  'authn/authn_api',
  () => new AuthnApi(AuthnApi.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/authn-api`, the sign-in screen's API (#571).
 *
 * Exports the class for the composition root, its facade, the operation
 * table and the OpenAPI document.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  AuthnApi: AuthnApi,
  installInstance: (instance: AuthnApi): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  operations: AuthnApi.operations,
  document: AuthnApi.document,
  CSRF_HEADER: CSRF_HEADER
};
