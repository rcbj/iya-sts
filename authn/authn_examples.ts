// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authn_examples.ts
//
// ---------------------------------------------------------------------------
// AN EXAMPLE ON EVERY `/authn-api` OPERATION THAT CAN CARRY ONE (#1483, on
// #1475's rules). What replays them is Schemathesis's Examples phase, with
// the cell's borrowed `sts_session` cookie and CSRF token; so each is valid
// against its schema and HARMLESS IF EXECUTED. Every operation is keyed by a
// pending sign-in, a step or a consent, and each example names an id nothing
// holds, so an act is refused with nothing spent. A sign-out example selects a
// row nobody has (an EMPTY selection ends everything; `select` is held off
// that) and a sign-out account example names an account the browser does not
// hold. `tests/api_request_names.js` holds every operation to having one that
// fits its schema. An operation with no parameter and no body is not listed.
// ---------------------------------------------------------------------------

type Json = any;

const NO_SIGN_IN = 'noSuchSignInExample';
const NO_STEP = 'noSuchStepExample';
const NO_CONSENT = 'noSuchConsentExample';
const NO_STATE = 'noSuchWalletStateExample';
const AN_ID = { path: { id: NO_SIGN_IN } };
const A_STEP = { path: { id: NO_STEP } };
const NOBODY = 'nobody-example';

function act(path: Json, body: Json): Json {
  return { path: path, body: body };
}

const EXAMPLES: Record<string, Json> = {
  'GET /authn-api/pending/{id}': AN_ID,
  'GET /authn-api/pending/{id}/partners': AN_ID,
  'POST /authn-api/pending/{id}/password':
    act(AN_ID.path, { username: NOBODY, password: 'not-the-password' }),
  'POST /authn-api/pending/{id}/cancel': act(AN_ID.path, {}),
  'POST /authn-api/pending/{id}/anonymous':
    act(AN_ID.path, { remember_browser: '0' }),
  'POST /authn-api/pending/{id}/certificate':
    act(AN_ID.path, { remember_browser: '0' }),
  'POST /authn-api/pending/{id}/email':
    act(AN_ID.path, { username: NOBODY, kind: 'code' }),
  'POST /authn-api/pending/{id}/passkey/options': act(AN_ID.path, {}),
  'POST /authn-api/pending/{id}/passkey':
    act(AN_ID.path, { credential: '{}' }),
  'GET /authn-api/password-change/{id}': AN_ID,
  'POST /authn-api/password-change/{id}':
    act(AN_ID.path, { new_password: 'not', confirm_password: 'equal' }),
  'POST /authn-api/password-change/{id}/start-over': act(AN_ID.path, {}),
  'GET /authn-api/mfa/{id}': { path: A_STEP.path, query: { page: 'totp' } },
  'POST /authn-api/mfa/{id}/totp': act(A_STEP.path, { code: '000000' }),
  'POST /authn-api/mfa/{id}/backup-code':
    act(A_STEP.path, { code: 'no-such-code' }),
  'POST /authn-api/mfa/{id}/password':
    act(A_STEP.path, { password: 'not-the-password' }),
  'POST /authn-api/mfa/{id}/webauthn/options':
    act(A_STEP.path, { lane: 'classical' }),
  'POST /authn-api/mfa/{id}/webauthn': act(A_STEP.path, { credential: '{}' }),
  'POST /authn-api/mfa/{id}/setup/totp': act(A_STEP.path, {}),
  'POST /authn-api/mfa/{id}/setup/confirm':
    act(A_STEP.path, { code: '000000' }),
  'POST /authn-api/mfa/{id}/setup/webauthn': act(A_STEP.path, {}),
  'POST /authn-api/mfa/{id}/skip': act(A_STEP.path, {}),
  'POST /authn-api/mfa/{id}/post-login/register': act(A_STEP.path, {}),
  'POST /authn-api/mfa/{id}/post-login/skip': act(A_STEP.path, {}),
  'POST /authn-api/mfa/{id}/email/send': act(A_STEP.path, { kind: 'code' }),
  'POST /authn-api/mfa/{id}/email/code': act(A_STEP.path, { code: '000000' }),
  'POST /authn-api/mfa/{id}/email-link/open':
    act(A_STEP.path, { t: 'noSuchLinkTokenExample' }),
  'POST /authn-api/mfa/{id}/start-over': act(A_STEP.path, {}),
  'GET /authn-api/wallet': { query: { authn: NO_SIGN_IN } },
  'POST /authn-api/wallet': { body: { authn: NO_SIGN_IN } },
  'GET /authn-api/wallet/{state}': { path: { state: NO_STATE } },
  'POST /authn-api/wallet/{state}/status':
    act({ state: NO_STATE }, { authn: NO_SIGN_IN }),
  'POST /authn-api/wallet/{state}/dc-api':
    act({ state: NO_STATE }, { authn: NO_SIGN_IN, response: '{}' }),
  'GET /authn-api/logout': { query: { username: NOBODY } },
  'POST /authn-api/logout':
    { body: { scope: 'selected', select: ['no-such-row'] } },
  'GET /authn-api/logout/accounts': { query: { login_hint: NOBODY } },
  'POST /authn-api/logout/accounts': { body: { account: 'name:' + NOBODY } },
  'GET /authn-api/pending/{id}/accounts': AN_ID,
  'POST /authn-api/pending/{id}/accounts/select':
    act(AN_ID.path, { account: 'name:' + NOBODY }),
  'POST /authn-api/pending/{id}/accounts/another': act(AN_ID.path, {}),
  'POST /authn-api/pending/{id}/accounts/forget':
    act(AN_ID.path, { account: 'name:' + NOBODY }),
  'GET /authn-api/consent/{id}': { path: { id: NO_CONSENT } },
  'POST /authn-api/consent/{id}':
    act({ id: NO_CONSENT }, { action: 'deny' })
};

export = EXAMPLES;
