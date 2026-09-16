// @ts-check
'use strict';
//
// File: step_up.js
//
// ===========================================================================
// RFC 9470 — OAUTH 2.0 STEP UP AUTHENTICATION CHALLENGE PROTOCOL (2026-09-13).
//
// A resource server that finds the authentication behind an access token too
// weak or too old says so, and a client asks the authorization server for a
// token that is not:
//
//   GET /api  Authorization: Bearer <token with acr "1">
//   401  WWW-Authenticate: Bearer error="insufficient_user_authentication",
//          error_description="...", acr_values="mfa", max_age="300"
//   GET /oauth2/authorize?...&acr_values=mfa&max_age=300
//   ... the person signs in again, with a second factor ...
//   the new token carries acr "mfa" and a fresh auth_time
//
// **IT IS NOT "TWO NEW QUERY PARAMETERS".** `acr_values` and `max_age` are
// OpenID Connect Core's and were already accepted here. What was missing was
// everything RFC 9470 says about them, and all of it is a change of behaviour:
//
//   * the authorization endpoint answered from ANY session it found, so a
//     request for a second factor on a password session got the password
//     session's token back — the one thing step-up exists to stop;
//   * nothing refused `unmet_authentication_requirements` (section 5);
//   * introspection did not carry `acr` and `auth_time` (section 6.2);
//   * no resource server here ever sent the challenge (section 3).
//
// **THIS FILE DECIDES; `oauth2.js` AND `dpop.js` ANSWER.** A library (rule 3):
// it requires `common/` modules and `oauth2_monitor.js`, none of which requires
// it back, so the authorization endpoint (`oauth2.js`) and the resource-server
// check every protected endpoint shares (`dpop.js`) can both reach it. What an
// application's requirement may be SPELT as is `common/applications.js`'s
// (`stepUpRequirementOf()`), for the rule every attribute there keeps: the
// module that owns an attribute owns its grammar.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS WERE ASKED OF RCBJ, AND THEY ARE THE DESIGN:
//
//   1. THE CHALLENGE IS SENT FROM TWO PLACES. A resource APPLICATION declares
//      what it requires (`oauthStepUpAcrValues`, `oauthStepUpMaxAge`), and the
//      stand-in resource `/oauth2/step-up/resource/{application}` enforces it
//      on the application's behalf; and this service's OWN resource server —
//      UserInfo, the three credential endpoints, SCIM and SSF, all through
//      `dpop.presentedAccessToken()` — enforces `oauth2.stepUpAcrValues` and
//      `oauth2.stepUpMaxAgeS`. They are two sources because they are two
//      resource servers: a token for an API is refused at this service's own
//      endpoints by RFC 9068 section 4 before any step-up question arises, so
//      an application's requirement could never have been asked there.
//   2. AN acr_values THAT CANNOT BE MET IS REFUSED IN EVERY MODE, with
//      `unmet_authentication_requirements` — section 5's "the authorization
//      server SHOULD consider the requested acr value as necessary". That is
//      against this repository's standing rule for refusals, and it was asked:
//      a mode-gated refusal would make `acr_values` decorative in the mode
//      clients are tested in, which is exactly how a step-up flow comes to
//      "work" while proving nothing.
//   3. THE LEVELS ARE ORDERED — `0` < `1` < `mfa` — so a stronger
//      authentication satisfies a request for a weaker one, and the token
//      carries the MOST PREFERRED REQUESTED value that was met, not the
//      session's own. Section 5: "the requested acr value is included in the
//      access token". A resource server asked for `1` is told `1`.
//   4. COUNTED ON `/admin/oauth2/monitor` as its second section.
//
// And one that was not asked, because OpenID Connect Core section 3.1.2.1
// already says MUST: an elapsed `max_age` re-authenticates in every mode.
//
// ---------------------------------------------------------------------------
// THE VOCABULARY, AND THE THREE WORDS THAT ARE NOT ACR VALUES.
//
// `0`, `1` and `mfa` are what `authn.js` records on a session — no factor, one
// factor, two — and what `acr_values_supported` publishes. `hwk`, `phr` and
// `phrh` are RFC 8176 AUTHENTICATION METHOD names, not context classes, and
// were accepted in `acr_values` long before this file as a demand for a second
// factor; that is kept rather than broken. Each is met by a TWO-factor session
// whose `amr` names a hardware key — a password and a security key — and a
// session that used a one-time code as its second factor does not meet it,
// because it did not use a key. They are not published: a client should not be
// taught to put method names where class names go.
//
// Anything else — a URN a federation partner speaks — is met only by a session
// whose `acr` is EXACTLY that value, which is how a federated sign-in carrying
// its partner's `acr` can answer a request for it. It is not refused before the
// sign-in for being unknown, for that reason: the sign-in may be a partner's.
//
// ---------------------------------------------------------------------------
// ONE ATTEMPT, AND WHY THE MARKER THAT SAYS SO MAY BE FORGED.
//
// A requirement the sign-in cannot meet — `acr_values=1` answered by the
// anonymous button, or a URN nobody's sign-in produces — would send the person
// round the sign-in screen for ever. So the return address carries
// `step_up_honoured=1`, and a request carrying it that still does not meet its
// requirement is REFUSED rather than sent round again. `jar_prompt_honoured` is
// the precedent, and this marker has its weakness: a client can put it on its
// first request. What that buys the client is bounded and harmless to anybody
// else — an `acr` the session does not meet is still refused, and a `max_age`
// is still checked against a window of `authn.pendingTtlS` (the longest a
// sign-in may take) rather than waived — and the token it gets carries the
// TRUE `auth_time` either way, which is what the resource server that asked for
// the recency checks. A signed marker would defend a client against itself.
// ===========================================================================

const { log } = require('../common/helpers');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const monitor = require('./oauth2_monitor');

// The context classes this service's own sign-in produces, weakest first. The
// index is the level.
const LEVELS = ['0', '1', 'mfa'];

// What `acr_values_supported` publishes.
const SUPPORTED = LEVELS.slice();

// RFC 8176 method names accepted as a demand for two factors including a key.
const KEY_ALIASES = ['hwk', 'phr', 'phrh'];

// The round-trip marker's name. `oauth2.js` declares it in the authorization
// request's schema, puts it on the return address and strips it from a push.
const HONOURED = 'step_up_honoured';

// RFC 6749 appendix A.2's NQCHAR, less the space that separates values and
// less the quote and backslash that could not sit in an auth-param's
// quoted-string without escaping (RFC 9110 section 5.6.4). A value outside it
// is not an acr value this service will repeat in a header.
const ACR_VALUE = /^[\x21\x23-\x5B\x5D-\x7E]{1,256}$/;

// OpenID Connect Core leaves max_age unbounded; this is ten years, which is
// the authorization endpoint's schema bound too.
const MAX_AGE_LIMIT = 315360000;

// ---------------------------------------------------------------------------
// PARSING.
// ---------------------------------------------------------------------------

// `acr_values` as a list, in the order of preference it was given in, with a
// repeat dropped. A value outside ACR_VALUE is dropped too and reported in
// `invalid`, so a caller can refuse rather than quietly ask for less.
function parseAcrValues(text) {
  log.debug("Entering parseAcrValues().");
  const out = { values: [], invalid: [] };
  String(text === undefined || text === null ? '' : text).split(/\s+/)
    .forEach(function (one) {
      if (!one) {
        return;
      }
      if (!ACR_VALUE.test(one)) {
        out.invalid.push(one);
        return;
      }
      if (out.values.indexOf(one) < 0) {
        out.values.push(one);
      }
    });
  log.debug("Leaving parseAcrValues(). " + out.values.length + " value(s).");
  return out;
}

// `max_age` as a whole number of seconds, or null when absent or not one.
function parseMaxAge(value) {
  log.debug("Entering parseMaxAge().");
  if (value === undefined || value === null || String(value).trim() === '') {
    log.debug("Leaving parseMaxAge(). Absent.");
    return null;
  }
  const text = String(value).trim();
  if (!/^\d{1,9}$/.test(text) || Number(text) > MAX_AGE_LIMIT) {
    log.debug("Leaving parseMaxAge(). Not a whole number of seconds.");
    return null;
  }
  log.debug("Leaving parseMaxAge().");
  return Number(text);
}

// What an authorization request asks for. `present` is false when it asks for
// neither, which is every request that does not step up.
function requirementOf(query) {
  log.debug("Entering requirementOf().");
  const q = query || {};
  const acr = parseAcrValues(q.acr_values);
  const maxAge = parseMaxAge(q.max_age);
  log.debug("Leaving requirementOf().");
  return {
    acrValues: acr.values,
    maxAge: maxAge,
    present: acr.values.length > 0 || maxAge !== null
  };
}

// What this service's OWN resource server requires, from the two settings.
// `-1` is "no requirement" for the age, because `0` is a legal one: it means
// the authentication must have happened this second, which is what OpenID
// Connect's `max_age=0` means too.
function ownResourceRequirement() {
  log.debug("Entering ownResourceRequirement().");
  const acr = parseAcrValues(config.value('oauth2.stepUpAcrValues'));
  if (acr.invalid.length) {
    // A string setting has no check of its own in `config.js`, so a value
    // that could not sit in a challenge header is reported here, where it is
    // dropped, rather than enforced as a requirement no token could meet.
    log.warn(errorCodes.tag('STS-OAUTH-0508') + 'oauth2.stepUpAcrValues: ' +
             acr.invalid.map(function (one) {
               return JSON.stringify(one.slice(0, 60));
             }).join(', ') + ' cannot be an acr value (a double quote, a ' +
             'backslash or a control character) and was ignored.');
  }
  const age = Number(config.value('oauth2.stepUpMaxAgeS'));
  const maxAge = isFinite(age) && age >= 0 ? Math.floor(age) : null;
  log.debug("Leaving ownResourceRequirement().");
  return {
    acrValues: acr.values,
    maxAge: maxAge,
    present: acr.values.length > 0 || maxAge !== null
  };
}

// ---------------------------------------------------------------------------
// WHAT MEETS WHAT.
// ---------------------------------------------------------------------------

function levelOf(acr) {
  log.debug("Entering levelOf().");
  log.debug("Leaving levelOf().");
  return LEVELS.indexOf(String(acr === undefined || acr === null ? '' : acr));
}

function amrOf(facts) {
  log.debug("Entering amrOf().");
  const amr = facts && facts.amr;
  log.debug("Leaving amrOf().");
  return (Array.isArray(amr) ? amr : (amr ? [amr] : [])).map(String);
}

// Whether ONE requested value is met by an authentication whose `acr` and
// `amr` are `facts`. See the header for the three kinds of value.
function meets(requested, facts) {
  log.debug("Entering meets(). requested=" + requested);
  const had = String((facts && facts.acr) || '');
  if (had && had === requested) {
    log.debug("Leaving meets(). The same value.");
    return true;
  }
  const hadLevel = levelOf(had);
  if (KEY_ALIASES.indexOf(requested) >= 0) {
    const met = hadLevel >= levelOf('mfa') &&
                amrOf(facts).indexOf('hwk') >= 0;
    log.debug("Leaving meets(). A key alias; met=" + met);
    return met;
  }
  const wanted = levelOf(requested);
  if (wanted < 0) {
    log.debug("Leaving meets(). A value this sign-in does not produce.");
    return false;
  }
  log.debug("Leaving meets(). Ordered; had " + hadLevel + ", wanted " +
            wanted + ".");
  return hadLevel >= wanted;
}

// The most preferred requested value `facts` meets, or null. With nothing
// requested, the authentication's own `acr` — which is what every token here
// carried before this file.
function satisfiedAcr(acrValues, facts) {
  log.debug("Entering satisfiedAcr().");
  const wanted = acrValues || [];
  if (!wanted.length) {
    log.debug("Leaving satisfiedAcr(). Nothing was requested.");
    return (facts && facts.acr) || null;
  }
  for (let i = 0; i < wanted.length; i++) {
    if (meets(wanted[i], facts)) {
      log.debug("Leaving satisfiedAcr(). " + wanted[i] + ".");
      return wanted[i];
    }
  }
  log.debug("Leaving satisfiedAcr(). None met.");
  return null;
}

// Whether the sign-in screen must demand a second factor: every requested
// value it knows how to produce needs two. `mfa 1` does not — `1` is an
// acceptable answer, only a less preferred one — and a request naming only
// values the screen cannot produce (a partner's URN) demands nothing of it.
function demandsSecondFactor(acrValues) {
  log.debug("Entering demandsSecondFactor().");
  const producible = (acrValues || []).filter(function (one) {
    return levelOf(one) >= 0 || KEY_ALIASES.indexOf(one) >= 0;
  });
  const demands = producible.length > 0 && producible.every(function (one) {
    return KEY_ALIASES.indexOf(one) >= 0 || levelOf(one) >= levelOf('mfa');
  });
  log.debug("Leaving demandsSecondFactor(). " + demands);
  return demands;
}

function nowSec() {
  log.debug("Entering nowSec().");
  log.debug("Leaving nowSec().");
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// THE AUTHORIZATION ENDPOINT'S QUESTION: does the session in hand answer this
// request, and if not, may the person be sent to sign in again?
//
// `options.honoured` is the round-trip marker (see the header);
// `options.windowS` how long a sign-in may take, which widens `max_age` on the
// return leg only. Answers:
//
//   { met: true, acr }                        issue, carrying `acr`
//   { met: false, reason, retry: true }       sign in again
//   { met: false, reason, retry: false }      refuse
//
// `reason` is `max_age` or `acr`, and is the age when both fail: that is the
// one a fresh sign-in is sure to cure, so it is the one to name.
// ---------------------------------------------------------------------------
function assessSession(requirement, session, options) {
  log.debug("Entering assessSession().");
  const opts = options || {};
  const need = requirement || { acrValues: [], maxAge: null };
  const facts = session || {};
  const authTime = Number(facts.authTime || facts.auth_time) || 0;
  const now = opts.now || nowSec();
  const elapsed = authTime ? now - authTime : Infinity;
  let allowed = need.maxAge;
  if (allowed !== null && opts.honoured) {
    allowed = Math.max(allowed, Number(opts.windowS) || 0);
  }
  const ageMet = need.maxAge === null || elapsed <= allowed;
  const acr = satisfiedAcr(need.acrValues, facts);
  const acrMet = !need.acrValues.length || acr !== null;
  if (ageMet && acrMet) {
    log.debug("Leaving assessSession(). Met, acr=" + acr);
    return { met: true, acr: acr, elapsed: elapsed };
  }
  const reason = ageMet ? 'acr' : 'max_age';
  log.debug("Leaving assessSession(). Not met (" + reason + "), honoured=" +
            !!opts.honoured);
  return { met: false, reason: reason, retry: !opts.honoured, acr: acr,
           elapsed: elapsed };
}

// The refusal an authorization request that cannot be met is answered with,
// as `{ error, description }` with its code under the Symbol.
function unmetRefusal(requirement, assessed, promptNone) {
  log.debug("Entering unmetRefusal().");
  const need = requirement || { acrValues: [], maxAge: null };
  const said = assessed || {};
  let out = null;
  if (promptNone) {
    out = errorCodes.mark({
      error: 'login_required',
      description: (said.reason === 'max_age'
        ? 'The session authenticated ' + said.elapsed + ' seconds ago and ' +
          'max_age is ' + need.maxAge
        : 'The session\'s authentication does not meet acr_values "' +
          need.acrValues.join(' ') + '"') +
        ', so the person must sign in again, and prompt=none forbids ' +
        'showing the sign-in screen.'
    }, 'STS-OAUTH-0502');
  } else if (said.reason === 'max_age') {
    out = errorCodes.mark({
      error: 'unmet_authentication_requirements',
      description: 'The person was asked to sign in again because max_age ' +
        'is ' + need.maxAge + ', and the session that came back ' +
        'authenticated ' + said.elapsed + ' seconds ago — a sign-in that ' +
        'did not start a new authentication.'
    }, 'STS-OAUTH-0501');
  } else {
    out = errorCodes.mark({
      error: 'unmet_authentication_requirements',
      description: 'RFC 9470 section 5: acr_values "' +
        need.acrValues.join(' ') + '" were requested and the ' +
        'authentication performed does not meet any of them. This service ' +
        'produces ' + SUPPORTED.join(', ') + ' (ordered, so a stronger one ' +
        'meets a weaker request); hwk, phr and phrh are met by a password ' +
        'with a security key; any other value only by a sign-in that ' +
        'reports exactly that acr.'
    }, 'STS-OAUTH-0500');
  }
  log.debug("Leaving unmetRefusal(). " + out.error);
  return out;
}

// ---------------------------------------------------------------------------
// THE RESOURCE SERVER'S QUESTION: do the claims of a presented access token
// meet this resource's requirement? Null when they do. Otherwise
// `{ error: 'insufficient_user_authentication', description, reason }` with
// its code under the Symbol, which `challengeHeader()` turns into section 3's
// header.
//
// **A TOKEN WITH NO `auth_time` DOES NOT MEET A `max_age`**, and one with no
// `acr` does not meet `acr_values`: RFC 9068 section 2.2.1 has them absent
// where no authentication is behind the grant, and "not known" is not
// "recent enough". A client_credentials token therefore cannot reach a
// resource that requires either, which is the resource's statement to make.
//
// **NO CLOCK SKEW IS ALLOWED ON THE AGE.** `oauth2.clockSkewS` is an allowance
// between two clocks on `exp` and `nbf`; `auth_time` was written by this
// service's own clock, and thirty seconds' grace on `max_age=5` would be a
// requirement nobody made.
// ---------------------------------------------------------------------------
function tokenRefusal(requirement, claims, options) {
  log.debug("Entering tokenRefusal().");
  const need = requirement || { acrValues: [], maxAge: null };
  if (!need.present) {
    log.debug("Leaving tokenRefusal(). No requirement.");
    return null;
  }
  const c = claims || {};
  const now = (options && options.now) || nowSec();
  const authTime = Number(c.auth_time) || 0;
  if (need.maxAge !== null && (!authTime || now - authTime > need.maxAge)) {
    log.debug("Leaving tokenRefusal(). Too old, or no auth_time.");
    return errorCodes.mark({
      error: 'insufficient_user_authentication',
      reason: 'max_age',
      description: authTime
        ? 'More recent authentication is required: this resource accepts an ' +
          'authentication at most ' + need.maxAge + ' seconds old, and this ' +
          'token\'s was ' + (now - authTime) + ' seconds ago.'
        : 'More recent authentication is required, and this token carries ' +
          'no auth_time — no authentication event is behind it.'
    }, 'STS-OAUTH-0504');
  }
  if (need.acrValues.length &&
      satisfiedAcr(need.acrValues, { acr: c.acr, amr: c.amr }) === null) {
    log.debug("Leaving tokenRefusal(). The acr does not meet it.");
    return errorCodes.mark({
      error: 'insufficient_user_authentication',
      reason: 'acr',
      description: 'A different authentication level is required: this ' +
        'resource accepts ' + need.acrValues.join(', ') + ', and this ' +
        'token\'s acr is ' + (c.acr ? '"' + c.acr + '"' : 'absent') + '.'
    }, 'STS-OAUTH-0503');
  }
  log.debug("Leaving tokenRefusal(). Met.");
  return null;
}

// Section 3's challenge. The two auth-params are sent together whenever the
// resource requires both — section 3 allows it, and a client that stepped up
// for one and was challenged again for the other would have been told half.
// `description` is the refusal's; a double quote in it would end the
// quoted-string, so each is replaced, and a backslash escaped.
function challengeHeader(scheme, requirement, description) {
  log.debug("Entering challengeHeader().");
  const need = requirement || { acrValues: [], maxAge: null };
  const quoted = function (text) {
    log.debug("Entering quoted().");
    log.debug("Leaving quoted().");
    return '"' + String(text).replace(/[\r\n]+/g, ' ')
      .replace(/\\/g, '\\\\').replace(/"/g, '\'') + '"';
  };
  const parts = ['error="insufficient_user_authentication"'];
  if (description) {
    parts.push('error_description=' + quoted(description));
  }
  if (need.acrValues.length) {
    parts.push('acr_values=' + quoted(need.acrValues.join(' ')));
  }
  if (need.maxAge !== null) {
    parts.push('max_age=' + quoted(String(need.maxAge)));
  }
  log.debug("Leaving challengeHeader().");
  return (scheme === 'DPoP' ? 'DPoP' : 'Bearer') + ' ' + parts.join(', ');
}

// Counted per client on the monitoring page. Never throws, which is the
// monitor's own guarantee.
function record(clientId, event, detail) {
  log.debug("Entering record(). event=" + event);
  monitor.record(clientId, event, detail);
  log.debug("Leaving record().");
}

module.exports = {
  LEVELS: LEVELS,
  SUPPORTED: SUPPORTED,
  KEY_ALIASES: KEY_ALIASES,
  HONOURED: HONOURED,
  ACR_VALUE: ACR_VALUE,
  MAX_AGE_LIMIT: MAX_AGE_LIMIT,
  parseAcrValues: parseAcrValues,
  parseMaxAge: parseMaxAge,
  requirementOf: requirementOf,
  ownResourceRequirement: ownResourceRequirement,
  meets: meets,
  satisfiedAcr: satisfiedAcr,
  demandsSecondFactor: demandsSecondFactor,
  assessSession: assessSession,
  unmetRefusal: unmetRefusal,
  tokenRefusal: tokenRefusal,
  challengeHeader: challengeHeader,
  record: record
};
