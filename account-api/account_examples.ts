// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_examples.ts
//
// ---------------------------------------------------------------------------
// AN EXAMPLE ON EVERY `/account-api` OPERATION THAT CAN CARRY ONE (#1483, on
// #1475's rules). What replays them is Schemathesis's Examples phase, with
// the fuzz person's real token, against the realm the run stands on; so each
// one is valid against its schema and HARMLESS IF EXECUTED: it names a
// resource that does not exist, or a page, so it is answered with a refusal
// or a page of nothing. A `/password`'s `next` and `confirm` differ, so no
// password changes; a keytab's `current` is wrong; nothing here creates,
// signs out or removes anything. `tests/api_request_names.js` holds every
// operation to having one that fits its schema.
//
// Keyed by the operation's method and path. An operation with no parameter
// and no body has nothing to fill in and is not listed (`GET /account-api/me`).
// ---------------------------------------------------------------------------

type Json = any;

const NOBODY = 'nobody-example';
const NO_TOKEN = 'no-such-token';
const NO_SUCH = 'no-such-id';
const FIRST_PAGE = { page: 1 };
const A_LINK = { user: NOBODY, token: NO_TOKEN };

const EXAMPLES: Record<string, Json> = {
  'GET /account-api/announcements': { query: { since: '0' } },
  'GET /account-api/overview': { query: { done: 'example' } },
  'POST /account-api/language': { body: { lang: '' } },
  'POST /account-api/photo': { body: { image: 'not-an-image' } },
  'POST /account-api/attributes':
    { body: { attribute: 'no-such-attribute', values: [] } },
  'GET /account-api/applications': { query: FIRST_PAGE },
  'GET /account-api/signals': { query: FIRST_PAGE },
  // Cancelling an opt-out that was never started changes nothing.
  'POST /account-api/signals': { body: { move: 'optOutCancelled' } },
  'GET /account-api/sign-ins': { query: FIRST_PAGE },
  'POST /account-api/sign-ins':
    { body: { action: 'deny', assessment: NO_SUCH } },
  'GET /account-api/consents': { query: FIRST_PAGE },
  'POST /account-api/consents':
    { body: { action: 'scope', client: NO_SUCH, scope: NO_SUCH } },
  'GET /account-api/gnap': { query: FIRST_PAGE },
  'POST /account-api/gnap': { body: { grant: NO_SUCH } },
  'GET /account-api/email': { query: { sentPage: 1 } },
  // Not an address, so no link is ever mailed.
  'POST /account-api/email':
    { body: { action: 'change', address: 'not-an-address' } },
  'GET /account-api/verify-email': { query: A_LINK },
  'POST /account-api/verify-email': { body: A_LINK },
  'POST /account-api/forgot-password': { body: { account: NOBODY } },
  'POST /account-api/pseudonyms':
    { body: { action: 'remove', value: NOBODY } },
  'GET /account-api/verify-pseudonym': { query: A_LINK },
  'POST /account-api/verify-pseudonym': { body: A_LINK },
  'GET /account-api/owned/roles': { query: FIRST_PAGE },
  'GET /account-api/owned/groups': { query: FIRST_PAGE },
  'GET /account-api/owned/service-accounts': { query: FIRST_PAGE },
  'GET /account-api/owned/applications': { query: FIRST_PAGE },
  'GET /account-api/shared': { query: FIRST_PAGE },
  'POST /account-api/shared': { body: { action: 'unshare', share: NO_SUCH } },
  'GET /account-api/shared-with-me': { query: FIRST_PAGE },
  // `next` and `confirm` differ, and `current` is nobody's: refused whole.
  'POST /account-api/password':
    { body: { current: 'not-the-password', next: 'not', confirm: 'equal' } },
  // Cancelling a ceremony that was never begun changes nothing.
  'POST /account-api/keys': { body: { action: 'cancel' } },
  'POST /account-api/keys/remove': { body: { credentialId: NO_SUCH } },
  'POST /account-api/keys/rename':
    { body: { credentialId: NO_SUCH, label: 'example' } },
  // A code nothing is waiting for.
  'POST /account-api/mfa': { body: { action: 'confirm', code: '000000' } },
  'POST /account-api/signing-key':
    { body: { action: 'revoke', handle: NO_SUCH } },
  'POST /account-api/certificates':
    { body: { action: 'delete-eab', kid: NO_SUCH } },
  'POST /account-api/app-passwords':
    { body: { action: 'revoke', id: 'NOSUCHID' } },
  'POST /account-api/kerberos':
    { body: { action: 'keytab', current: 'not-the-password' } },
  // Clearing a delegate nobody set.
  'POST /account-api/delegate': { body: { action: 'clear' } },
  'GET /account-api/delegate/candidates': { query: { q: 'nob' } },
  'GET /account-api/self-issued': { query: { enrolled: '1' } },
  'POST /account-api/self-issued':
    { body: { action: 'remove', subject: 'did:jwk:no-such-subject' } },
  'GET /account-api/self-issued/did':
    { query: { subject: 'did:jwk:no-such-subject' } },
  'POST /account-api/self-issued/dids':
    { body: { action: 'deactivate', rid: 'AAAAAAAAAAAAAAAAAAAAAA' } },
  'GET /account-api/credentials/offerable': { query: FIRST_PAGE },
  'POST /account-api/credentials/offers':
    { body: { configuration: NO_SUCH, mode: 'cross-device' } },
  'POST /account-api/credentials/remove': { body: { id: NO_SUCH } },
  'POST /account-api/devices': { body: { action: 'remove', id: NO_SUCH } },
  'POST /account-api/devices/challenge': { body: { purpose: 'key' } },
  'POST /account-api/devices/proof':
    { body: { challenge: NO_SUCH, proof: 'not-a-proof' } },
  'GET /account-api/ciba': { query: { stepup: NO_SUCH } },
  'POST /account-api/ciba': { body: { action: 'deny', id: NO_SUCH } },
  'POST /account-api/access-requests':
    { body: { request: NO_SUCH, action: 'deny' } },
  'GET /account-api/device': { query: { user_code: 'NOSUCHCODE' } },
  'POST /account-api/device':
    { body: { action: 'deny', user_code: 'NOSUCHCODE' } },
  'GET /account-api/claim-sources': { query: { done: 'example' } },
  'POST /account-api/claim-sources':
    { body: { action: 'unlink', id: NO_SUCH } },
  'GET /account-api/connected-accounts': { query: { done: 'example' } },
  'POST /account-api/connected-accounts':
    { body: { action: 'disconnect', id: NO_SUCH } },
  'GET /account-api/activation': { query: A_LINK },
  'POST /account-api/activation': { body: Object.assign({}, A_LINK,
    { password: 'not', confirm: 'equal' }) },
  'GET /account-api/reset-password': { query: A_LINK },
  'POST /account-api/reset-password': { body: Object.assign({}, A_LINK,
    { password: 'not', confirm: 'equal' }) }
};

export = EXAMPLES;
