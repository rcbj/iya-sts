// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: own_password.js
//
// ===========================================================================
// A PERSON WHOSE PASSWORD IS THEIR OWN, IN EVERY MODE (#2160).
//
// **THIS IS A HELPER AND NOT A JOB** (MANIFEST.js's LOCAL_HELPERS).
//
// Since #2160 (ASVS 5.0.0 6.4.6), a password an administrator TYPES is
// temporary where passwords are verified (product mode). `set-password`,
// `create` with `credential: "password"`, and an administrator's LDAP write
// of somebody else's `userPassword` all set `pwdReset`. The sign-in screen
// then asks for a new one, and every door that cannot ask (ROPC, an LDAP
// bind, WS-Trust, Kerberos, SCIM Basic) refuses it (STS-AUTHN-0142,
// STS-KRB-0257). A job that wants a person to sign in with the password it
// chose has to make that password the PERSON'S, which is what this does:
//
//   1. the job's own administrator door sets a TEMPORARY password
//      (`temporaryFor(password)`, never the wanted one: the password
//      history would refuse the person choosing a value the administrator
//      had just set);
//   2. the person signs in at the screen with it, over `/authn-api`, the
//      way `sts_admin_bootstrap.js` drives the forced change;
//   3. where the screen asks for a new one (product), the person chooses
//      `password`. Where the service did not make the temporary password
//      temporary (development, or a service account), its answer does not
//      say so, and the administrator door sets `password` directly, with no
//      sign-in at all.
//
// Either way the person ends up holding `password` with no change owed. The
// sign-in leaves a sign-on session in a cookie jar nobody keeps.
//
// `setPassword(username, value)` is the JOB's door, because jobs reach
// `/admin-api` differently (a client-credentials token, the console's DPoP
// token, development's open API, a realm prefix). It resolves when the
// password is set and rejects, or answers `{ ok: false }`, when not.
// ===========================================================================

const assert = require("assert");
const crypto = require("crypto");
const authnSignin = require("./authn_signin");

const log = require('bunyan').createLogger({ name: 'own_password',
  level: process.env.LOG_LEVEL || 'info' });

/**
 * The temporary password an administrator sets before the person chooses
 * `password`: longer than it, so any length rule it met is met, and
 * different from it, so the history does not refuse the choice.
 *
 * @param {string} password - the password the person will hold
 * @returns {string} a different password that meets the same rules
 */
function temporaryFor(password) {
  log.debug("Entering temporaryFor().");
  log.debug("Leaving temporaryFor().");
  return String(password) + "-Tmp" +
    crypto.randomBytes(6).toString("base64url") + "9!";
}

/**
 * A sign-in screen waiting for somebody: the console's authorization
 * request, which every realm has a client for.
 *
 * @param {string} base - the realm's base URL
 * @returns {Promise<string>} the screen's address
 */
async function pendingSignIn(base) {
  log.debug("Entering pendingSignIn().");
  await fetch(base + "/admin?realm=default", { redirect: "manual" });
  const verifier = crypto.randomBytes(32).toString("base64url");
  const r = await fetch(base + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code",
      client_id: "sts-admin-console",
      redirect_uri: base + "/admin/callback",
      scope: "openid", state: crypto.randomBytes(8).toString("hex"),
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256",
      nonce: crypto.randomBytes(8).toString("hex"),
      resource: base + "/admin-api" }).toString(),
    { redirect: "manual" });
  const where = r.headers.get("location") || "";
  const said = /[?&#]authn=/.test(where) ? "" : await r.text();
  assert.ok(/[?&#]authn=/.test(where), "own_password: the authorization " +
    "request should send the browser to the sign-in screen; it answered " +
    r.status + " " + where + " " + said.slice(0, 300));
  log.debug("Leaving pendingSignIn().");
  return new URL(where, base).toString();
}

// The JSON a door answered, whichever shape the job's helper hands back:
// `{ json }`, `{ body }`, or the parsed body itself.
function bodyOf(answer) {
  log.debug("Entering bodyOf().");
  log.debug("Leaving bodyOf().");
  return (answer && (answer.json || answer.body)) || answer || {};
}

// Whether a door's answer says the password it set is temporary (#2160).
function saidTemporary(answer) {
  log.debug("Entering saidTemporary().");
  log.debug("Leaving saidTemporary().");
  return /temporary password/.test(String(bodyOf(answer).message || ""));
}

// What a door answered, as ok or not: a fetch answer's status, an
// `{ ok }` body, or whatever a job's helper resolved with.
function answeredOk(answer) {
  log.debug("Entering answeredOk().");
  if (answer === undefined || answer === null || answer === true) {
    log.debug("Leaving answeredOk(). Nothing to read.");
    return true;
  }
  if (typeof answer.status === "number" && answer.status !== 200) {
    log.debug("Leaving answeredOk(). Status " + answer.status + ".");
    return false;
  }
  const body = bodyOf(answer);
  log.debug("Leaving answeredOk().");
  return !(body && body.ok === false);
}

/**
 * The person signs in with `temporary` and, where the screen asks for a new
 * password, chooses `password`. Answers what happened rather than asserting,
 * for a caller that has to tell a refusal of `password` from a failure
 * to sign in.
 *
 * @param {string} base - the realm's base URL the person signs in at
 * @param {string} username - the person
 * @param {string} temporary - the password the administrator door just set
 * @param {string} password - the password they will hold
 * @returns {Promise<object>} `{ asked, chosen, status, errors }`: `asked`
 *   whether the screen asked for a new one, `chosen` whether `password` was
 *   stored
 */
async function changeTo(base, username, temporary, password) {
  log.debug("Entering changeTo(). " + username);
  const login = await authnSignin.submit(base, await pendingSignIn(base),
    { action: "login", username: username, password: temporary }, {});
  if (login.next !== "password-change") {
    log.debug("Leaving changeTo(). No change asked (" + login.next + ").");
    return { asked: false, chosen: false, status: login.status,
             errors: login.errors || null };
  }
  const changed = await authnSignin.changePassword(base, login.location,
    { new_password: password, confirm_password: password },
    { cookie: login.cookie });
  // 200 is the password stored; what the resumed sign-in does next (a
  // second factor offered, a client the person holds no role for) is not
  // this helper's business. A refused password is 400.
  log.debug("Leaving changeTo(). " + changed.status);
  return { asked: true, chosen: changed.status === 200,
           status: changed.status,
           errors: changed.errors || (changed.json && changed.json.errors) ||
                   null };
}

/**
 * The second half of `ownPassword()`, for a caller that has ALREADY set
 * `temporary` through its administrator door: the person chooses
 * `password` where the screen asks; where it does not, `setPassword` sets
 * `password`.
 *
 * @param {string} base - the realm's base URL the person signs in at
 * @param {string} username - the person
 * @param {string} temporary - the password the administrator door just set
 * @param {string} password - the password they will hold
 * @param {function(string, string): Promise<*>} setPassword - the job's
 *   administrator door, for a mode that asks no change
 * @returns {Promise<string>} `password`
 */
async function chooseOwn(base, username, temporary, password, setPassword) {
  log.debug("Entering chooseOwn(). " + username);
  const changed = await changeTo(base, username, temporary, password);
  if (changed.asked) {
    assert.ok(changed.chosen,
      "own_password: " + username + " choosing their own password at the " +
      "change step answered " + changed.status + " " +
      JSON.stringify(changed.errors).slice(0, 300));
    log.debug("Leaving chooseOwn(). Chosen at the change step.");
    return password;
  }
  // No change asked: a mode in which a typed password is not temporary, or
  // an account that holds no temporary password (a service account).
  const again = await setPassword(username, password);
  assert.ok(answeredOk(again), "own_password: setting " + username + "'s " +
    "password was refused: " +
    JSON.stringify((again && (again.json || again.body)) || again)
      .slice(0, 300));
  // Set directly where a change is owed would leave it temporary, which is
  // what this helper exists to prevent: say so here rather than at a
  // sign-in three steps on.
  assert.ok(!saidTemporary(again),
    "own_password: the sign-in screen did not ask " + username + " for a " +
    "new password (status " + changed.status + "), so the password the " +
    "administrator set is still temporary: " +
    JSON.stringify(changed.errors).slice(0, 300));
  log.debug("Leaving chooseOwn(). Set by the administrator door.");
  return password;
}

/**
 * Leaves `username` holding `password` as their own, with no change owed,
 * in either mode (#2160).
 *
 * @param {string} base - the realm's base URL the person signs in at
 * @param {string} username - the person, who must already exist
 * @param {string} password - the password they will hold
 * @param {function(string, string): Promise<*>} setPassword - the job's
 *   administrator door: sets `value` as `username`'s password
 * @returns {Promise<string>} `password`
 */
async function ownPassword(base, username, password, setPassword) {
  log.debug("Entering ownPassword(). " + username);
  const temporary = temporaryFor(password);
  const set = await setPassword(username, temporary);
  assert.ok(answeredOk(set), "own_password: setting a temporary password " +
    "for " + username + " was refused: " +
    JSON.stringify((set && (set.json || set.body)) || set).slice(0, 300));
  // WHERE THE SERVICE DID NOT MAKE IT TEMPORARY (development, a service
  // account) its answer does not say so, and the password is set directly:
  // no sign-in, so a development run is what it was before #2160.
  if (!saidTemporary(set)) {
    const direct = await setPassword(username, password);
    assert.ok(answeredOk(direct), "own_password: setting " + username +
      "'s password was refused: " +
      JSON.stringify((direct && (direct.json || direct.body)) || direct)
        .slice(0, 300));
    log.debug("Leaving ownPassword(). Not temporary here; set directly.");
    return password;
  }
  await chooseOwn(base, username, temporary, password, setPassword);
  log.debug("Leaving ownPassword().");
  return password;
}

module.exports = { ownPassword: ownPassword, chooseOwn: chooseOwn,
                   changeTo: changeTo, temporaryFor: temporaryFor };
