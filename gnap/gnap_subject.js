'use strict';
//
// File: gnap_subject.js
//
// ---------------------------------------------------------------------------
// WHO THE RESOURCE OWNER IS, IN BOTH DIRECTIONS.
//
// OUT (RFC 9635 section 3.4): a grant response may carry Subject Identifiers
// (RFC 9493) and ASSERTIONS about the RO — an OpenID Connect ID Token or a SAML
// 2.0 assertion (section 3.4.1). IN (section 2.4): a client may tell the AS who
// it thinks the end user is, by sub_ids, by assertions, or by an opaque user
// reference the AS handed out earlier (section 2.4.1).
//
// **NEITHER DIRECTION HAS A BUILDER OF ITS OWN HERE.** The ID Token is
// `oauth2.idToken()` and the SAML assertion is `saml2.buildSamlAssertion()`,
// because a GNAP assertion and an OIDC one from the same realm must say the
// same things about the same person — claim layers, persona values in
// development, the directory's facts in product — and a second builder would be
// the second answer that starts disagreeing the day either grows a claim.
// Verification of an inbound assertion is the same argument read backwards:
// `common/crypto.js` checks the JWS and the XML signature, against this realm's
// own certificate.
//
// ---------------------------------------------------------------------------
// WHICH ASSERTIONS AN INBOUND `user` MAY CARRY.
//
// Section 2.4: assertions "SHOULD be validated", and section 11.30 lists why.
// This AS accepts the ones IT ISSUED — an ID Token or SAML assertion signed
// with this realm's own key — and nothing else, which is section 2.4's own
// worked example ("an AS acting as an identity provider could expect that
// assertions being presented using this mechanism were issued by the AS to the
// client software"). A foreign IdP's assertion would need a federation
// relationship to verify, and `federation/` is the one feature here that
// refuses by default for exactly that reason; GNAP does not get a side door
// around it.
//
// Sub_ids are HINTS and never authoritative (section 2.4: "MUST NOT be taken as
// authoritative statements"). They pre-fill the sign-in screen and they are
// compared with the person who actually signs in — a mismatch is `unknown_user`
// (section 2.4) — and that is all they are allowed to do.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const helpers = require('../common/helpers');
const { log, STS, userFor } = helpers;
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
const config = require('../common/config');
const store = require('./gnap_store');

// What this AS can produce, in section 9's discovery order. `did` is absent
// on purpose: a person here has a DID only when a wallet linked one, and a
// format advertised for everybody that most people cannot be named in is a
// capability the discovery document would be overstating.
const SUB_ID_FORMATS_SUPPORTED = ['opaque', 'iss_sub', 'email', 'account',
                                  'uri', 'phone_number',
                                  'aliases'];
const ASSERTION_FORMATS_SUPPORTED = ['id_token', 'saml2'];

function refusal(code, why, gnapError) {
  log.debug("Entering refusal().");
  const out = { ok: false, errorCode: code, why: why,
                gnapError: gnapError || 'unknown_user' };
  log.debug("Leaving refusal().");
  return errorCodes.mark(out, code);
}

function normaliseName(name) {
  log.debug("Entering normaliseName().");
  log.debug("Leaving normaliseName().");
  return String(name || '').trim().toLowerCase();
}

// ---------------------------------------------------------------------------
// THE OPAQUE IDENTIFIER, and why it doubles as a user reference.
//
// Stable per person PER REALM (an HMAC under a realm-derived key), so the same
// person gets the same identifier across grants and clients — section 3.4 says
// identifiers "SHOULD uniquely identify the RO at the AS" and "SHOULD NOT reuse
// Subject Identifiers for multiple different ROs". And section 2.4.1 names this
// exact value as the way a client obtains a USER REFERENCE, so it is recorded
// in the reference store the moment it is issued: presenting it back as `user`
// then resolves, and a value this AS never issued does not.
// ---------------------------------------------------------------------------
//
// **OVER THE PERSON'S STABLE SUBJECT WHERE THERE IS ONE (2026-09-14)**, and the
// name only where the directory holds nobody. An identifier derived from the
// name changed on a rename, and a person deleted and re-created under the name
// was given the old person's — section 3.4's "SHOULD NOT reuse" broken by a
// directory edit. The reference records the subject, so presenting it back
// names whoever that entry is called now, and nobody once the entry is gone.
function opaqueIdFor(username) {
  log.debug("Entering opaqueIdFor().");
  const secret = helpers.refreshTokenKeysFor().secret;
  const key = Buffer.from(nodeCrypto.hkdfSync('sha256', secret, Buffer.alloc(0),
                                              Buffer.from('mock-sts gnap ' +
                                                  'opaque subject v1'), 32));
  const subject = helpers.subjectForName(username);
  const id = nodeCrypto.createHmac('sha256', key)
                       .update(subject || normaliseName(username))
                       .digest('base64url')
    .slice(0, 20);
  store.putUserRef(id, subject ? { username: normaliseName(username),
                                   sub: subject }
                               : { username: normaliseName(username) });
  log.debug("Leaving opaqueIdFor().");
  return id;
}

// The facts the directory holds about a person, for the formats that need one.
function factsFor(username) {
  log.debug("Entering factsFor().");
  let person = userFor(username);
  try {
    person = require('../saml/person_attributes').personFor(person);
  } catch (e) {
    // No directory in this process (an in-process test). The formats that need
    // a fact are omitted, which is the product-mode answer for a fact nobody
    // holds.
    log.debug("factsFor(): the directory could not be read: " + e.message);
  }
  let phone = null;
  try {
    const byLdap = require('../common/claim_attributes').catalogueValuesFor(
        username).byLdap || {};
    const item = byLdap.telephonenumber || byLdap.mobile || null;
    if (item && item.value &&
        /^\+[1-9][0-9]{1,14}$/.test(String(item.value).replace(/[\s-]/g, ''))) {
      phone = String(item.value).replace(/[\s-]/g, '');
    }
  } catch (e) {
    // Same as above: no directory, no telephone number.
    log.debug("factsFor(): no telephone number could be read: " + e.message);
  }
  log.debug("Leaving factsFor().");
  return { person: person, email: person.email || null, phone: phone };
}

// ---------------------------------------------------------------------------
// SUB_IDS FOR THE REQUESTED FORMATS (section 3.4). A format this AS cannot
// produce for this person is omitted rather than invented, and an unrequested
// one is never sent: the client asked for specific formats and "the AS MAY
// return the RO's information in its response as requested".
// ---------------------------------------------------------------------------
function subIdsFor(username, formats, ctx) {
  log.debug("Entering subIdsFor(). formats=" + (formats || []).join(','));
  const context = ctx || {};
  const facts = factsFor(username);
  const host = (function () {
    try {
      return new URL(context.issuer).host;
    } catch (e) {
      log.debug("Caught in a callback in subIdsFor(): " +
                ((e && e.message) || e));
      // No issuer URL to take a host from; the account format is then omitted.
      return '';
    }
  }());
  const made = {
    opaque: function () {
      log.debug("Entering opaque().");
      log.debug("Leaving opaque().");
      return { format: 'opaque', id: opaqueIdFor(username) };
    },
    iss_sub: function () {
      log.debug("Entering iss_sub().");
      log.debug("Leaving iss_sub().");
      return { format: 'iss_sub', iss: context.issuer, sub: facts.person.sub };
    },
    email: function () {
      log.debug("Entering email().");
      log.debug("Leaving email().");
      return facts.email ? { format: 'email', email: facts.email } : null;
    },
    account: function () {
      log.debug("Entering account().");
      log.debug("Leaving account().");
      return host ?
             { format: 'account',
               uri: 'acct:' + normaliseName(username) + '@' + host } : null;
    },
    uri: function () {
      log.debug("Entering uri().");
      log.debug("Leaving uri().");
      return { format: 'uri', uri: facts.person.sub };
    },
    phone_number: function () {
      log.debug("Entering phone_number().");
      log.debug("Leaving phone_number().");
      return facts.phone ?
             { format: 'phone_number', phone_number: facts.phone } : null;
    }
  };
  const out = [];
  (formats || []).forEach(function (format) {
    if (format === 'aliases') {
      const identifiers = ['opaque', 'iss_sub', 'email'].map(function (name) {
        return made[name]();
      }).filter(Boolean);
      out.push({ format: 'aliases', identifiers: identifiers });
      return;
    }
    if (made[format]) {
      const one = made[format]();
      if (one) {
        out.push(one);
      }
    }
  });
  log.debug("Leaving subIdsFor(). " + out.length + " identifier(s).");
  return out;
}

// ---------------------------------------------------------------------------
// ASSERTIONS (section 3.4.1). `ctx.oauthBase` is the realm's OAuth issuer base
// (the ID Token's `iss`); `ctx.instanceId` is the audience, because section
// 2.4's example makes the CLIENT the audience of an assertion about its user.
// ---------------------------------------------------------------------------
async function assertionsFor(username, formats, ctx) {
  log.debug("Entering assertionsFor(). formats=" + (formats || []).join(','));
  const context = ctx || {};
  const out = [];
  for (let i = 0; i < (formats || []).length; i++) {
    const format = formats[i];
    if (format === 'id_token') {
      const oauth2 = require('../oauth-oidc/oauth2');
      const value = await oauth2.idToken(context.oauthBase, {
        username: normaliseName(username), client_id: context.instanceId,
        auth_time: context.authTime, amr: context.amr, acr: context.acr,
        session_id: context.sessionId, grant: 'gnap', set_id: context.setId
      });
      out.push({ format: 'id_token', value: value });
    } else if (format === 'saml2') {
      const saml2 = require('../saml/saml2');
      const lifetime = Math.max(1,
                                Math.round((Number(
                                    config.value(
                                        'gnap.accessTokenLifetimeS')) ||
                                            3600) / 60));
      const xml = saml2.buildSamlAssertion(normaliseName(username),
                                           context.instanceId, lifetime, {
        issuer: context.issuer, sessionIndex: context.sessionId || undefined
      });
      // Section 3.4.1: "encoded as a single base64url string with no padding".
      out.push({ format: 'saml2',
                 value: Buffer.from(xml, 'utf8').toString('base64url') });
    }
  }
  log.debug("Leaving assertionsFor(). " + out.length + " assertion(s).");
  return out;
}

// ---------------------------------------------------------------------------
// AN INBOUND `user` (section 2.4), resolved to a username.
//
// Answers `{ ok:true, username, verified }`: `verified` is true only when an
// ASSERTION this realm signed named the person, which is the one case section
// 2.4 allows an AS to skip interaction on. A hint alone resolves with
// `verified: false`. Nothing resolvable is `{ ok:true, username: null }` —
// an unrecognisable sub_id is a hint that did not help, not an error; an
// unrecognised REFERENCE is `unknown_user` (section 2.4.1 says MUST).
// ---------------------------------------------------------------------------
function resolveUser(user, ctx) {
  log.debug("Entering resolveUser().");
  const context = ctx || {};
  if (!user) {
    log.debug("Leaving resolveUser(). No user member.");
    return { ok: true, username: null, verified: false };
  }
  if (user.reference) {
    const row = store.userByRef(user.reference);
    const referenced = nameOfUserRef(row);
    if (!referenced) {
      log.debug("Leaving resolveUser(). Unknown reference.");
      return refusal('STS-GNAP-0070', 'the user reference is not one this ' +
                     'authorization server issued (RFC 9635 section 2.4.1).');
    }
    log.debug("Leaving resolveUser(). By reference.");
    return { ok: true, username: referenced, verified: false };
  }
  const named = [];
  let verified = false;
  (user.assertions || []).forEach(function (assertion) {
    const name = usernameFromAssertion(assertion, context);
    if (name.ok) {
      named.push(name.username);
      verified = true;
    }
  });
  const assertionProblems = (user.assertions || []).length && !verified;
  if (assertionProblems) {
    log.debug("Leaving resolveUser(). No assertion verified.");
    return refusal('STS-GNAP-0071', 'none of the presented user assertions ' +
                   'is one this authorization server issued and can verify ' +
                   '(RFC 9635 sections 2.4 and 11.30).');
  }
  (user.subIds || []).forEach(function (subId) {
    const name = usernameFromSubId(subId, context);
    if (name) {
      named.push(name);
    }
  });
  const distinct = named.filter(function (value, index) {
    return named.indexOf(value) === index;
  });
  if (distinct.length > 1) {
    // Section 2.2: "All identifiers in the sub_ids array MUST identify the same
    // subject" — and the same is true of assertions beside them.
    log.debug("Leaving resolveUser(). Identifiers name different people.");
    return refusal('STS-GNAP-0072', 'the user identifiers and assertions ' +
                   'name more than one person (RFC 9635 section ' +
                   '2.2).', 'invalid_request');
  }
  log.debug("Leaving resolveUser(). username=" + (distinct[0] || '(none)') +
      ", " +
      "verified=" + verified);
  return { ok: true, username: distinct[0] || null, verified: verified };
}

// The name a recorded user reference's person has NOW: through its subject
// where one was recorded — null once that entry is gone — and the recorded
// name otherwise.
function nameOfUserRef(row) {
  log.debug("Entering nameOfUserRef().");
  if (!row) {
    log.debug("Leaving nameOfUserRef(). No reference.");
    return null;
  }
  if (!row.sub) {
    log.debug("Leaving nameOfUserRef(). By name.");
    return row.username;
  }
  const named = helpers.nameForSubject(row.sub);
  log.debug("Leaving nameOfUserRef(). " + (named ? 'By subject.' : 'Gone.'));
  return named ? normaliseName(named) : null;
}

function usernameFromSubId(subId, ctx) {
  log.debug("Entering usernameFromSubId().");
  if (!subId) {
    log.debug("Leaving usernameFromSubId().");
    return null;
  }
  if (subId.format === 'opaque') {
    log.debug("Leaving usernameFromSubId().");
    return nameOfUserRef(store.userByRef(subId.id));
  }
  // A SUBJECT THIS SERVICE ISSUED, IN EITHER FORM (2026-09-14):
  // `urn:uuid:<entryUUID>` is looked up in the directory and the legacy
  // `urn:sts:user:<name>` is read. `helpers.nameForSubject()` is the one place
  // that knows both, so this file cannot come to disagree with the token
  // endpoint about who a subject names.
  if (subId.format === 'iss_sub') {
    const named = subId.iss === ctx.issuer
      ? helpers.nameForSubject(subId.sub) : '';
    log.debug("Leaving usernameFromSubId().");
    return named ? normaliseName(named) : null;
  }
  if (subId.format === 'uri') {
    const named = helpers.nameForSubject(subId.uri);
    if (named) {
      log.debug("Leaving usernameFromSubId().");
      return normaliseName(named);
    }
  }
  if (subId.format === 'account') {
    const match = String(subId.uri).match(/^acct:([^@]+)@/);
    log.debug("Leaving usernameFromSubId().");
    return match ? normaliseName(match[1]) : null;
  }
  if (subId.format === 'email') {
    log.debug("Leaving usernameFromSubId().");
    // An email address is a hint for the sign-in screen's username field in
    // the local part, and nothing stronger.
    return normaliseName(String(subId.email).split('@')[0]);
  }
  if (subId.format === 'aliases') {
    for (let i = 0; i < subId.identifiers.length; i++) {
      const inner = usernameFromSubId(subId.identifiers[i], ctx);
      if (inner) {
        log.debug("Leaving usernameFromSubId().");
        return inner;
      }
    }
  }
  log.debug("Leaving usernameFromSubId().");
  return null;
}

function usernameFromAssertion(assertion, ctx) {
  log.debug("Entering usernameFromAssertion(). format=" + assertion.format);
  if (assertion.format === 'id_token') {
    let claims;
    try {
      // Signature only: section 2.4 lets an AS "accept a recently expired
      // assertion in order to help bootstrap a new session", and this AS does,
      // within `gnap.assertionMaxAgeS` of its expiry.
      claims = stsCrypto.verifyCompactJws(assertion.value, STS.certPem,
                                          { algorithms: ['RS256'] }).claims;
    } catch (e) {
      log.debug("Leaving usernameFromAssertion(). ID Token does not verify: " +
                e.message);
      return { ok: false };
    }
    const grace = Number(config.value('gnap.assertionMaxAgeS')) || 0;
    if (claims.typ !== 'ID' ||
        (ctx.oauthIssuer && claims.iss !== ctx.oauthIssuer) ||
        (claims.exp && claims.exp + grace < helpers.nowSec())) {
      log.debug("Leaving usernameFromAssertion(). Not a current ID Token " +
                "from this issuer.");
      return { ok: false };
    }
    const name = claims.preferred_username ||
      helpers.nameForSubject(claims.sub);
    log.debug("Leaving usernameFromAssertion(). id_token for " + name);
    return name ? { ok: true, username: normaliseName(name) } : { ok: false };
  }
  if (assertion.format === 'saml2') {
    const xml = Buffer.from(String(assertion.value), 'base64url')
                      .toString('utf8');
    const result = stsCrypto.verifyXmlSignature(xml,
                                                { element: 'Assertion',
                                                  certPem: STS.certPem });
    if (!result.ok) {
      log.debug("Leaving usernameFromAssertion(). SAML assertion does not " +
                "verify.");
      return { ok: false };
    }
    const match = xml.match(/<(?:[A-Za-z0-9]+:)?NameID\b[^>]*>([^<]+)<\/(?:[A-Za-z0-9]+:)?NameID>/);
    log.debug("Leaving usernameFromAssertion(). saml2.");
    return match ? { ok: true, username: normaliseName(match[1]) } :
           { ok: false };
  }
  log.debug("Leaving usernameFromAssertion(). Unsupported format.");
  return { ok: false };
}

module.exports = {
  SUB_ID_FORMATS_SUPPORTED: SUB_ID_FORMATS_SUPPORTED,
  ASSERTION_FORMATS_SUPPORTED: ASSERTION_FORMATS_SUPPORTED,
  opaqueIdFor: opaqueIdFor,
  subIdsFor: subIdsFor,
  assertionsFor: assertionsFor,
  resolveUser: resolveUser,
  normaliseName: normaliseName
};
