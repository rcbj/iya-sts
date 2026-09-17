// @ts-check
'use strict';
//
// File: sender_constraints.js
//
// ===========================================================================
// ASKING FOR MORE THAN EITHER SPECIFICATION REQUIRES (#34, 2026-09-15).
//
// Issue #34 asked a plain question — does OAuth 2.1 or RFC 9700 require DPoP?
// — and the answer is no, twice:
//
//   * OAuth 2.1 (draft-ietf-oauth-v2-1-16) section 4.3.1 gives a PUBLIC
//     client's refresh token a CHOICE of two treatments: sender-constrained
//     (DPoP or RFC 8705), or rotated with replay detection. Either satisfies
//     it. This service already takes the second in RFC 9700 mode.
//   * RFC 9700 section 2.2.1 makes a sender-constrained ACCESS token a SHOULD,
//     and nothing anywhere makes it a MUST.
//
// So the five settings this file decides are all ways to go FURTHER than the
// documents, which is why none of them is implied by a compliance mode and
// every one defaults to off. They exist because a client under test should be
// able to meet a strict authorization server here before it meets one in
// production.
//
// ---------------------------------------------------------------------------
// FOUR OF THE FIVE REFUSE, AND REFUSING IS THE DESIGN.
//
// Everywhere else this service prefers to answer with something weaker rather
// than not answer at all — `mode.sendsWeakerThanAsked()` is a predicate about
// exactly that. These four do the opposite: a request that cannot meet them is
// refused, and in particular a token request that would hand back an access
// token AND a refresh token the client could never redeem is refused whole.
// Half a token set is worse than an error, because the client discovers it an
// hour later at a refresh it cannot make.
//
// The one that does not refuse is `oauth2.refreshTokenRotation`, which changes
// what is ISSUED rather than what is accepted.
//
// ---------------------------------------------------------------------------
// IT IS A LEAF (rule 3, and `oauth-oidc/CLAUDE.md` rule 3ao).
//
// It registers no route, and it requires `helpers.js`, `config.js` and
// `oauth21.js` — all three of which are leaves themselves. **It may never
// require `dpop.js`, `mtls.js`, `oauth2_bcp.js`, `applications.js` or
// `oauth2.js`, because all five require IT.** That is the whole reason this is
// a file of its own rather than five predicates in `oauth2_bcp.js`: the
// resource-side checks live in `dpop.js`, which is below `oauth2_bcp.js` and
// cannot reach it.
//
// THE SPLIT IS `oauth21.js`'s: every fact is PASSED IN — what the request
// proved, what the token carries, what the connection presented — and every
// answer is a refusal record or null. It never touches `res`, so the caller
// chooses what a refusal looks like on the wire.
// ===========================================================================

const { log } = require('../common/helpers');
const config = require('../common/config');
const oauth21 = require('./oauth21');

// The two grants that carry a refresh token to a client which authenticated
// with its certificate rather than a secret. RFC 8705 section 7.1 lets such a
// client rotate its certificate, so its refresh token is bound to the CLIENT
// and not to the key — `mtls.refreshBindingApplies()` is what decides it, and
// this file is only told the answer.
const CERTIFICATE_CLIENT_METHODS = ['tls_client_auth',
                                    'self_signed_tls_client_auth'];

// THE ONE EXEMPTION, AND WHAT IT IS NOT.
//
// These two are this service's OWN relying parties — the console and portal
// rows of `common/oidc_rp.ts`'s `SURFACES` — and they redeem their codes and
// refresh tokens over a loopback call from this process to itself. There is no
// client certificate to present on that call and nobody on the other end of it
// who is not already this process, so `oauth2.refreshTokenRequireMtls` would
// lock an operator out of /admin and /portal in exchange for nothing. They are
// exempt from THAT SETTING ONLY.
//
// They are NOT exempt from the DPoP setting: `oidc_rp.js` carries a key and
// proves possession on every back-channel call since 2026-09-15, which is why
// that half was built rather than exempted.
//
// `sts-debugger-ui` IS NOT HERE, on purpose (#34 decision 6): the embedded
// debugger is an ordinary client of this authorization server and is
// configured to meet whatever the realm it points at requires.
// `tests/sender_constraints.js` checks this list against `oidc_rp.js`'s own,
// so a surface added there cannot quietly acquire an exemption.
const MTLS_EXEMPT_CLIENTS = ['sts-admin-console', 'sts-user-portal'];

// ---------------------------------------------------------------------------
// THE PREDICATES. Each is read PER REQUEST rather than cached, because all
// five settings are `runtime: true` and therefore per trust realm: one realm
// may demand DPoP while the next does not, and the realm is ambient.
// ---------------------------------------------------------------------------

// Rotation is the one question with three answers rather than two, because a
// compliance mode already answers it. `oauth2_bcp.js`'s `enabled()` is
// deliberately NOT called here — it requires this file — so the two keys are
// read the same way it reads them. If that ever drifts, the test that catches
// it is tests/refresh_rotation_policy.js.
function rotationRequired() {
  log.debug("Entering rotationRequired().");
  const answer = !!config.value('oauth2.rfc9700') || oauth21.enabled() ||
                 !!config.value('oauth2.refreshTokenRotation');
  log.debug("Leaving rotationRequired(). " + answer);
  return answer;
}

// Which of the three turned it on, for the console page and the two compliance
// reports. A mode is named ahead of the setting, because a mode cannot be
// turned off by the setting and a reader who saw the setting named would try.
function rotationSource() {
  log.debug("Entering rotationSource().");
  if (config.value('oauth2.rfc9700')) {
    log.debug("Leaving rotationSource(). RFC 9700 mode.");
    return 'RFC 9700 mode';
  }
  if (oauth21.enabled()) {
    log.debug("Leaving rotationSource(). OAuth 2.1 mode.");
    return 'OAuth 2.1 mode';
  }
  if (config.value('oauth2.refreshTokenRotation')) {
    log.debug("Leaving rotationSource(). The setting.");
    return 'oauth2.refreshTokenRotation';
  }
  log.debug("Leaving rotationSource(). Nothing.");
  return null;
}

function refreshDpopRequired() {
  log.debug("Entering refreshDpopRequired().");
  const answer = !!config.value('oauth2.refreshTokenRequireDpop');
  log.debug("Leaving refreshDpopRequired(). " + answer);
  return answer;
}

function refreshMtlsRequired() {
  log.debug("Entering refreshMtlsRequired().");
  const answer = !!config.value('oauth2.refreshTokenRequireMtls');
  log.debug("Leaving refreshMtlsRequired(). " + answer);
  return answer;
}

function accessTokenDpopRequired() {
  log.debug("Entering accessTokenDpopRequired().");
  const answer = !!config.value('oauth2.accessTokenRequireDpop');
  log.debug("Leaving accessTokenDpopRequired(). " + answer);
  return answer;
}

function accessTokenMtlsRequired() {
  log.debug("Entering accessTokenMtlsRequired().");
  const answer = !!config.value('oauth2.accessTokenRequireMtls');
  log.debug("Leaving accessTokenMtlsRequired(). " + answer);
  return answer;
}

// Is any of the four refusals on? The console page and the two reports ask
// this to decide whether to draw the warning block at all.
function anythingRequired() {
  log.debug("Entering anythingRequired().");
  const answer = refreshDpopRequired() || refreshMtlsRequired() ||
                 accessTokenDpopRequired() || accessTokenMtlsRequired();
  log.debug("Leaving anythingRequired(). " + answer);
  return answer;
}

// The refusal record. `oauth21.js`'s shape, with the setting that caused it
// named in `setting` — an operator reading an audit row should not have to
// guess which of the four they turned on.
function refusal(errorCode, error, setting, description) {
  log.debug("Entering refusal().");
  const record = {
    ok: false,
    errorCode: errorCode,
    error: error,
    setting: setting,
    description: description
  };
  log.debug("Leaving refusal(). " + errorCode);
  return record;
}

// ---------------------------------------------------------------------------
// ISSUANCE. Asked once per token request, by the one place that knows a
// refresh token is about to be minted.
//
// `exempt` is the seeded console and portal clients under the mTLS setting,
// and nothing else. They redeem over a loopback call from this process to
// itself, where there is no certificate to present and no counterparty to
// present it to; the exemption is named on /admin/oauth2 and in the setting's
// own description so that it is never a surprise. They are NOT exempt from the
// DPoP setting — `common/oidc_rp.ts` carries proofs of its own since
// 2026-09-15, which is the whole reason that half was built.
// ---------------------------------------------------------------------------
function refreshIssuanceRefusal(opts) {
  log.debug("Entering refreshIssuanceRefusal().");
  const o = opts || {};
  const grant = String(o.grant || '');
  if (refreshDpopRequired() && !o.dpopJkt) {
    log.debug("Leaving refreshIssuanceRefusal(). No proof.");
    return refusal('STS-OAUTH-0521', 'invalid_dpop_proof',
      'oauth2.refreshTokenRequireDpop',
      'this authorization server is configured to issue refresh tokens only ' +
      'to a request that proves possession of a key (RFC 9449 section 5), ' +
      'and the ' + (grant || 'token') + ' request carried no DPoP proof. ' +
      'Send a DPoP header, or ask for a grant that mints no refresh token.');
  }
  if (refreshMtlsRequired() && !o.exempt) {
    if (!o.mtlsAvailable) {
      log.debug("Leaving refreshIssuanceRefusal(). No mTLS on this port.");
      return refusal('STS-OAUTH-0527', 'invalid_request',
        'oauth2.refreshTokenRequireMtls',
        'this authorization server is configured to issue refresh tokens ' +
        'only over mutual TLS (RFC 8705), but its main port is not bound as ' +
        'HTTPS and cannot ask for a client certificate. Set global.https, or ' +
        'turn oauth2.refreshTokenRequireMtls off.');
    }
    if (!o.certificateVerified) {
      log.debug("Leaving refreshIssuanceRefusal(). No certificate.");
      return refusal('STS-OAUTH-0522', 'invalid_client',
        'oauth2.refreshTokenRequireMtls',
        'this authorization server is configured to issue refresh tokens ' +
        'only over mutual TLS (RFC 8705), and this connection presented ' +
        (o.certificate ? 'a client certificate that did not verify'
                       : 'no client certificate') + '. Present one issued ' +
        'for this client, or ask for a grant that mints no refresh token.');
    }
  }
  log.debug("Leaving refreshIssuanceRefusal(). Nothing refused.");
  return null;
}

// ---------------------------------------------------------------------------
// REDEMPTION. Asked in the refresh_token branch, AFTER the ordinary binding
// checks that run in every mode — those refuse a bound token presented without
// its key, and this refuses an UNBOUND token, which is the case they cannot
// see.
//
// An unbound refresh token is refused rather than bound on first use. Binding
// it would be the friendlier answer and the wrong one: the token was handed
// out with no constraint, anybody holding it could bind it to a key of their
// own, and the operator who turned this setting on would have been told the
// tokens were constrained when the first use of a stolen one constrained it.
// ---------------------------------------------------------------------------
function refreshRedemptionRefusal(opts) {
  log.debug("Entering refreshRedemptionRefusal().");
  const o = opts || {};
  if (refreshDpopRequired()) {
    if (!o.provedJkt) {
      log.debug("Leaving refreshRedemptionRefusal(). No proof.");
      return refusal('STS-OAUTH-0524', 'invalid_dpop_proof',
        'oauth2.refreshTokenRequireDpop',
        'this authorization server is configured to accept a refresh token ' +
        'only from the holder of the key it is bound to (RFC 9449 section ' +
        '5), and this request carried no DPoP proof.');
    }
    if (!o.tokenJkt) {
      log.debug("Leaving refreshRedemptionRefusal(). Token unbound.");
      return refusal('STS-OAUTH-0523', 'invalid_grant',
        'oauth2.refreshTokenRequireDpop',
        'this refresh token is not bound to a key. It was issued before ' +
        'oauth2.refreshTokenRequireDpop was turned on, or by a realm that ' +
        'does not have it on, and it is refused rather than bound to the key ' +
        'presenting it now — binding it here would let whoever holds it ' +
        'choose the key. Sign in again to be issued a bound one.');
    }
  }
  if (refreshMtlsRequired() && !o.exempt) {
    if (!o.mtlsAvailable) {
      log.debug("Leaving refreshRedemptionRefusal(). No mTLS on this port.");
      return refusal('STS-OAUTH-0527', 'invalid_request',
        'oauth2.refreshTokenRequireMtls',
        'this authorization server is configured to accept a refresh token ' +
        'only over mutual TLS (RFC 8705), but its main port is not bound as ' +
        'HTTPS and cannot ask for a client certificate.');
    }
    // RFC 8705 section 7.1: a client that authenticated with its certificate
    // on THIS request, and owns this token, has met the requirement whether or
    // not the token carries a thumbprint — its refresh token is bound to the
    // client, and the specification lets it rotate the certificate.
    if (!o.section71) {
      if (!o.certificateVerified) {
        log.debug("Leaving refreshRedemptionRefusal(). No certificate.");
        return refusal('STS-OAUTH-0526', 'invalid_client',
          'oauth2.refreshTokenRequireMtls',
          'this authorization server is configured to accept a refresh token ' +
          'only over mutual TLS (RFC 8705), and this connection presented ' +
          (o.certificate ? 'a client certificate that did not verify'
                         : 'no client certificate') + '.');
      }
      if (!o.tokenThumbprint) {
        log.debug("Leaving refreshRedemptionRefusal(). Token unbound.");
        return refusal('STS-OAUTH-0525', 'invalid_grant',
          'oauth2.refreshTokenRequireMtls',
          'this refresh token is not bound to a certificate. It was issued ' +
          'before oauth2.refreshTokenRequireMtls was turned on, or by a ' +
          'realm that does not have it on, and it is refused rather than ' +
          'bound to the certificate presenting it now. Sign in again, or ' +
          'authenticate this client with tls_client_auth, which section 7.1 ' +
          'binds to the client rather than to the certificate.');
      }
    }
  }
  log.debug("Leaving refreshRedemptionRefusal(). Nothing refused.");
  return null;
}

// ---------------------------------------------------------------------------
// THE RESOURCE SIDE. Asked wherever a presented access token is accepted, and
// deliberately held to the same rule for a token this service did not issue:
// the CONFIRMATION a token carries can be read without trusting the token, and
// a token carrying none cannot satisfy a requirement that it be constrained.
//
// It is a refusal at the RESOURCE and nowhere else. The token endpoint goes on
// minting Bearer tokens, which these surfaces then refuse — that is what lets
// a client be tested against the refusal, and it is stated on /admin/oauth2 so
// that nobody reads the 401 as a bug in the issuer.
// ---------------------------------------------------------------------------
function accessTokenRefusal(opts) {
  log.debug("Entering accessTokenRefusal().");
  const o = opts || {};
  const where = String(o.where || 'this resource');
  if (accessTokenDpopRequired()) {
    if (!o.boundJkt) {
      log.debug("Leaving accessTokenRefusal(). Token unbound.");
      return refusal('STS-OAUTH-0528', 'invalid_token',
        'oauth2.accessTokenRequireDpop',
        where + ' is configured to accept only a DPoP-bound access token ' +
        '(RFC 9449), and this token carries no cnf.jkt. Ask the ' +
        'authorization server for one with a DPoP proof on the token ' +
        'request.');
    }
    if (!o.proofOk) {
      log.debug("Leaving accessTokenRefusal(). No proof.");
      return refusal('STS-OAUTH-0529', 'invalid_token',
        'oauth2.accessTokenRequireDpop',
        where + ' is configured to accept only a DPoP-bound access token, ' +
        'and this request presented one without proving possession of its ' +
        'key. Send the token as Authorization: DPoP with a DPoP header.');
    }
  }
  if (accessTokenMtlsRequired()) {
    if (!o.mtlsAvailable) {
      log.debug("Leaving accessTokenRefusal(). No mTLS on this port.");
      return refusal('STS-OAUTH-0527', 'invalid_request',
        'oauth2.accessTokenRequireMtls',
        where + ' is configured to accept only a certificate-bound access ' +
        'token (RFC 8705), but the port it answers on cannot ask for a ' +
        'client certificate.');
    }
    if (!o.boundThumbprint) {
      log.debug("Leaving accessTokenRefusal(). Token unbound.");
      return refusal('STS-OAUTH-0530', 'invalid_token',
        'oauth2.accessTokenRequireMtls',
        where + ' is configured to accept only a certificate-bound access ' +
        'token (RFC 8705), and this token carries no cnf["x5t#S256"]. Ask ' +
        'the authorization server for one over a connection presenting a ' +
        'client certificate.');
    }
    if (!o.certificateMatches) {
      log.debug("Leaving accessTokenRefusal(). No matching certificate.");
      return refusal('STS-OAUTH-0531', 'invalid_token',
        'oauth2.accessTokenRequireMtls',
        where + ' is configured to accept only a certificate-bound access ' +
        'token, and this connection presented ' +
        (o.certificate ? 'a different certificate'
                       : 'no client certificate') + '.');
    }
  }
  log.debug("Leaving accessTokenRefusal(). Nothing refused.");
  return null;
}

// Whether this client is one of the two hosted relying parties the mutual TLS
// refresh setting steps aside for. Asked by the token endpoint, and published
// on /admin/oauth2 so the exemption is never something a reader has to find.
function mtlsExemptClient(clientId) {
  log.debug("Entering mtlsExemptClient().");
  const answer = MTLS_EXEMPT_CLIENTS.indexOf(String(clientId || '')) >= 0;
  log.debug("Leaving mtlsExemptClient(). " + answer);
  return answer;
}

// Whether a client authentication method is one of RFC 8705's, which is what
// section 7.1 turns on. The caller has the method; this keeps the list in one
// place.
function certificateClientMethod(method) {
  log.debug("Entering certificateClientMethod().");
  const answer = CERTIFICATE_CLIENT_METHODS.indexOf(String(method || '')) >= 0;
  log.debug("Leaving certificateClientMethod(). " + answer);
  return answer;
}

// What `GET /oauth2/rfc9700`, `GET /oauth2/oauth21` and /admin/oauth2 publish
// about these five. One reader, so the console and the two reports cannot
// disagree about what is on.
function state() {
  log.debug("Entering state().");
  const answer = {
    rotation: {
      required: rotationRequired(),
      source: rotationSource(),
      setting: 'oauth2.refreshTokenRotation'
    },
    refreshTokenRequireDpop: refreshDpopRequired(),
    refreshTokenRequireMtls: refreshMtlsRequired(),
    accessTokenRequireDpop: accessTokenDpopRequired(),
    accessTokenRequireMtls: accessTokenMtlsRequired(),
    // Said here as well as in the settings' descriptions, because this is what
    // a compliance report is read for: neither document demands any of it.
    note: 'Neither OAuth 2.1 (draft-ietf-oauth-v2-1-16 section 4.3.1) nor ' +
          'RFC 9700 requires DPoP or mutual TLS. Section 4.3.1 asks a public ' +
          'client\'s refresh token to be sender-constrained OR rotated with ' +
          'replay detection, and RFC 9700 section 2.2.1 makes a ' +
          'sender-constrained access token a SHOULD. These five settings are ' +
          'how an operator asks for more than that.'
  };
  log.debug("Leaving state().");
  return answer;
}

module.exports = {
  MTLS_EXEMPT_CLIENTS,
  mtlsExemptClient,
  rotationRequired,
  rotationSource,
  refreshDpopRequired,
  refreshMtlsRequired,
  accessTokenDpopRequired,
  accessTokenMtlsRequired,
  anythingRequired,
  refreshIssuanceRefusal,
  refreshRedemptionRefusal,
  accessTokenRefusal,
  certificateClientMethod,
  state
};
