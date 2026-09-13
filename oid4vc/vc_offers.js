'use strict';
//
// File: vc_offers.js
//
// ---------------------------------------------------------------------------
// Credential Offer (OID4VCI section 4) — the issuer-initiated half of issuance.
//
// Appendix H.1 "Credential Offer - Same-Device": the End-User is browsing the
// issuer's site, follows a "request your digital diploma" link, and is taken to
// their Wallet with a Credential Offer in hand. That is what these three
// endpoints are:
//
//   GET /issuer                     the issuer's web page, with the link
//   GET /issuer/offer               builds an offer and redirects to the wallet,
//                                   by value (credential_offer) or by reference
//                                   (credential_offer_uri)
//   GET /oid4vci/credential-offer/:id  serves an offer fetched by reference
//
// The offer names this issuer, the credential configuration(s) on offer, and the
// grant. For H.1 that grant is authorization_code carrying an issuer_state,
// which the Wallet must hand back on the authorization request so the issuer can
// tie the two together.
//
// The Wallet a browser page can be sent to is a URL, not the openid-credential-offer://
// scheme a native wallet would register — OID4VCI_WALLET_URL says where it lives.
// ---------------------------------------------------------------------------
//
// This module owns the STATE the offer creates — the offers themselves, the
// issuer_states, the pre-authorized codes and the deferred transactions — and
// that ownership is the reason it is a module rather than part of vc_issuer.js.
// The pre-authorized code grant is redeemed at the TOKEN ENDPOINT, which belongs
// to the authorization server, and issuer_state is read on the AUTHORIZATION
// request. So this state is shared between OID4VCI and OAuth2 by design, and
// putting it in either of them would make those two require each other.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const qrcode = require('qrcode');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('../common/realms');
const app = require('../common/app');
const { log, logArtifact, baseUrlOf, randomId, xmlEscape, vciError, userFor,
        walletBaseUrl } = require('../common/helpers');
const config = require('../common/config');
// THE MODE (2026-09-12), for two questions only — are the test controls open
// (an anonymous offer page), and may a response go to an address the request
// named (the `wallet` parameter). A LEAF requiring only `config`.
const mode = require('../common/mode');
// Constant-time comparison, for the Transaction Code. A leaf.
const stsCrypto = require('../common/crypto');
// The error codes (common/error_codes.js). A LEAF that requires nothing; a code is
// marked on the response object and never written into a response.
const errorCodes = require('../common/error_codes');
const { VCI_CONFIG_ID, vciConfigIds } = require('./vc_configs');

// The input validator. A LEAF (rule 3): registers no route, closes no cycle.
const validation = require('../common/validation');
// The credential formats this issuer actually offers, read off the table that
// defines them rather than written out again.
const VCI_FORMATS = Array.from(new Set(
  Object.keys(require('./vc_configs').VCI_CONFIGS).map(function (id) {
    return require('./vc_configs').VCI_CONFIGS[id].format;
  }).filter(Boolean)));
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const credentialOffers = realms.map({ persist: 'vc_offers.credentialOffers' });  // id -> { offer, issuerState, expires }

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const issuerStates = realms.map({ persist: 'vc_offers.issuerStates' });  // issuer_state -> { configurationIds, expires }

// Pre-authorized codes (OID4VCI Appendix H.2 / H.3): the End-User authorized the
// issuance out of band, so there is no authorization request at all — the code
// in the offer IS the authorization. `txCode` is the Transaction Code the issuer
// shows on its own screen and the End-User types into the wallet; `deferred`
// marks an issuance the credential endpoint will not complete immediately.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const preAuthorizedCodes = realms.map({ persist: 'vc_offers.preAuthorizedCodes' });  // code -> { configurationIds, txCode, user, deferred, expires }

// Deferred issuance transactions (OID4VCI section 9): the credential endpoint
// answered 202 with one of these instead of a credential.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const deferredTransactions = realms.map({ persist: 'vc_offers.deferredTransactions' });  // transaction_id -> { claims, holderJwk, readyAt, expires }

// Access tokens minted from a deferred offer: the credential endpoint answers
// 202 for these instead of issuing straight away.
//
// **PER TRUST REALM AND PERSISTED SINCE 2026-09-12, AND IT WAS NEITHER.** It
// was the one store in this file declared `new Set()` beside four that were
// `realms.map()` — so a deferred access token minted at
// `/realm/acme/oauth2/token` was honoured as deferred at the DEFAULT realm's
// credential endpoint too, and in a dispatched service a token minted on one
// worker was an ordinary token on every other one, which is the deferred flow
// silently not being deferred. `vc_offers.deferredTransactions`, the other half
// of the same flow, has been declared since the day minted state persisted.
//
// **THE KEY IS A DIGEST OF THE TOKEN AND NOT THE TOKEN.** An access token is a
// bearer credential, and a declared store is journalled, replicated to every
// process and written to `sts_minted` in product mode — sealed there, but a
// credential this service does not need to hold is better never held at all.
// Membership is the only question ever asked, and SHA-256 answers it.
//
// Kept a SET-SHAPED FACADE (`add`, `has`, `delete`, `size`, `clear`) because
// `oauth-oidc/oauth2.js` adds and `vc_issuer.js` asks and spends, and neither
// has any reason to learn that the store underneath changed.
const deferredAccessTokenStore = realms.map({ persist: 'vc_offers.deferredAccessTokens' });

function deferredTokenKey(token) {
  return crypto.createHash('sha256').update(String(token || ''), 'utf8')
    .digest('base64url');
}

const deferredAccessTokens = {
  add: function (token) {
    deferredAccessTokenStore.set(deferredTokenKey(token), { at: Date.now() });
    return deferredAccessTokens;
  },
  has: function (token) {
    return deferredAccessTokenStore.has(deferredTokenKey(token));
  },
  delete: function (token) {
    return deferredAccessTokenStore.delete(deferredTokenKey(token));
  },
  clear: function () {
    return deferredAccessTokenStore.clear();
  },
  get size() { return deferredAccessTokenStore.size; }
};

// How long a deferred issuance "takes". Short enough for a test to wait for it,
// long enough that the first poll genuinely comes back still-pending.
function deferredReadyMs() {
  return config.value('oid4vci.deferredReadyMs');
}

function deferredIntervalS() {
  return config.value('oid4vci.deferredIntervalS');
}

// `oid4vci.offerTtlS` since 2026-09-12. The constant is the default and keeps
// its name because `vc_issuer.js` imports it; `offerTtlMs()` is the live value
// and what every reader here uses.
const OFFER_TTL_MS = 10 * 60 * 1000;

function offerTtlMs() {
  const seconds = Number(config.value('oid4vci.offerTtlS'));
  return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) * 1000 : OFFER_TTL_MS;
}

// ---------------------------------------------------------------------------
// THE TRANSACTION CODE (2026-09-12), and three things about it that were wrong
// in every mode or missing in product.
//
// **IT IS DRAWN FROM A CSPRNG.** It was `Math.random()`, whose V8
// implementation (xorshift128+) is recoverable from a handful of its outputs —
// and this service hands its outputs to anybody who loads an offer page. The
// Transaction Code is the only thing binding a pre-authorized code to the
// person standing at the issuer's screen, so a predictable one is no binding.
// `crypto.randomInt()` is uniform over the range, which a modulo of random
// bytes is not. BOTH MODES: a guessable code is a defect a mock should not
// teach anybody to expect.
//
// **ITS LENGTH IS `oid4vci.txCodeLength`** — five digits by default, the value
// the page has always shown — and the leading digit is never zero, which is
// what `Math.floor(Math.random() * 90000) + 10000` produced and what a wallet
// that renders the input as a number relies on.
//
// **COMPARISON AND ATTEMPTS ARE THE TOKEN ENDPOINT'S** — `checkTxCode()` below,
// which `oauth2.js` calls — because that is where the code is presented.
// ---------------------------------------------------------------------------
function txCodeLength() {
  const digits = Number(config.value('oid4vci.txCodeLength'));
  return isFinite(digits) && digits >= 4 ? Math.floor(digits) : 5;
}

function newTxCode() {
  const length = txCodeLength();
  const low = Math.pow(10, length - 1);
  return String(crypto.randomInt(low, low * 10));
}

// ---------------------------------------------------------------------------
// CHECK A PRESENTED TRANSACTION CODE AGAINST A PRE-AUTHORIZED CODE'S RECORD.
//
// CONSTANT-TIME IN BOTH MODES — a `!==` on a short numeric string leaks how
// many leading digits a guess got right, which turns a hundred thousand guesses
// into fifty.
//
// **THE ATTEMPT LIMIT IS PRODUCT MODE'S**, asked through
// `mode.verifiesCredentials()`: a Transaction Code is a credential this service
// verifies, and five digits inside a ten-minute offer are guessable at the
// token endpoint by anybody holding the offer. So in product each wrong code
// is counted ON THE RECORD, through the store (a request worker that counted in
// its own memory would give every worker its own five), and the one that
// reaches `oid4vci.txCodeMaxAttempts` SPENDS the pre-authorized code. The
// End-User asks for a new offer. Development counts nothing, so a wallet's
// wrong-code path can be driven as often as a test likes — which is what that
// mode is for.
//
// Returns `{ ok }`, or `{ ok: false, missing | spent, attemptsLeft }`, and
// writes to `preAuthorizedCodes` itself so the caller cannot forget either the
// count or the spending.
// ---------------------------------------------------------------------------
function checkTxCode(code, record, presented) {
  log.debug("Entering checkTxCode().");
  if (!record.txCode) {
    log.debug("Leaving checkTxCode(). This offer carries no Transaction Code.");
    return { ok: true };
  }
  const given = String(presented || '');
  if (!given) {
    log.debug("Leaving checkTxCode(). None was presented.");
    return { ok: false, missing: true };
  }
  if (stsCrypto.constantTimeEquals(given, record.txCode)) {
    log.debug("Leaving checkTxCode(). It matches.");
    return { ok: true };
  }
  if (!mode.verifiesCredentials()) {
    log.debug("Leaving checkTxCode(). Wrong, and development counts nothing.");
    return { ok: false };
  }
  const limit = Math.max(1, Number(config.value('oid4vci.txCodeMaxAttempts')) || 5);
  const failures = (Number(record.txCodeFailures) || 0) + 1;
  if (failures >= limit) {
    preAuthorizedCodes.delete(code);
    log.warn(errorCodes.tag('STS-VC-0030') +
             'vc_offers: a pre-authorized code was SPENT after ' + failures +
             ' wrong Transaction Code(s) (oid4vci.txCodeMaxAttempts = ' + limit + ').');
    log.debug("Leaving checkTxCode(). Spent.");
    return { ok: false, spent: true, attemptsLeft: 0 };
  }
  preAuthorizedCodes.set(code, Object.assign({}, record, { txCodeFailures: failures }));
  log.debug("Leaving checkTxCode(). Wrong; " + (limit - failures) + " attempt(s) left.");
  return { ok: false, attemptsLeft: limit - failures };
}

// ---------------------------------------------------------------------------
// WHERE THE END-USER IS SENT: the wallet URL and the page under it.
//
// The page is `oid4vci.walletIssuancePath` (2026-09-12). The `wallet` query
// parameter overrides the configured URL — which is how a wallet on a laptop
// is pointed at this service without reconfiguring it, and in DEVELOPMENT that
// stays true for any absolute URL. In a realm that accepts only registered
// addresses (`mode.acceptsUnregisteredAddresses()` false) it is AN OPEN
// REDIRECT carrying a pre-authorized code or an issuer_state, so it must name
// the configured wallet or one listed in `oid4vci.allowedWalletUrls`, and
// anything else is refused by name rather than silently replaced.
//
// Compared with trailing slashes removed, which is the only normalisation the
// URL gets before it is used, so what is compared is what is dialled.
// ---------------------------------------------------------------------------
function walletFor(req) {
  log.debug("Entering walletFor().");
  const configured = String(walletBaseUrl() || '').replace(/\/+$/, '');
  const asked = req.query.wallet ? String(req.query.wallet).replace(/\/+$/, '') : '';
  if (asked && asked !== configured && !mode.acceptsUnregisteredAddresses()) {
    const allowed = (config.value('oid4vci.allowedWalletUrls') || []).map(function (one) {
      return String(one).replace(/\/+$/, '');
    });
    if (allowed.indexOf(asked) < 0) {
      log.debug("Leaving walletFor(). An unregistered wallet URL was refused.");
      return { error: 'The wallet URL "' + asked + '" is neither oid4vci.walletUrl nor one ' +
                      'listed in oid4vci.allowedWalletUrls, and this realm does not send an ' +
                      'offer to an address the request named. Add it to that setting, or ' +
                      'leave the wallet parameter off.' };
    }
  }
  const path = String(config.value('oid4vci.walletIssuancePath') || '');
  log.debug("Leaving walletFor().");
  return { url: (asked || configured) + path };
}

// A pre-authorized offer is made to an End-User the issuer has ALREADY
// identified (H.2: they uploaded documents to an employee portal days before),
// so the issuer knows the subject without anyone signing in.
function vciOfferUsername() {
  return config.value('oid4vci.offerUsername');
}

// Build a Credential Offer for one of the Appendix H use cases.
//
//   same-device  (H.1) authorization_code + issuer_state: the wallet still has
//                      to take the End-User through the authorization server.
//   cross-device (H.2) pre-authorized_code + tx_code: the End-User already
//                      identified themselves to the issuer by some other route,
//                      so the code IS the authorization and the Transaction
//                      Code shown on the issuer's screen is what ties the
//                      wallet on the other device to this End-User.
//   deferred     (H.3) the same pre-authorized offer, but flagged so the
//                      credential endpoint answers 202 with a transaction_id
//                      instead of a credential.
//
// `options.user` (2026-09-12) is WHO a pre-authorized offer is for. Absent,
// it is `oid4vci.offerUsername` — the H.2 story, where the issuer identified the
// End-User out of band — which is what this function always did and what
// development still does. The offer page passes the signed-in person in a realm
// whose test controls are closed; see that route.
function buildCredentialOffer(req, configurationIds, mode, options) {
  log.debug("Entering buildCredentialOffer(). mode=" + mode);
  const base = baseUrlOf(req);
  const expires = Date.now() + offerTtlMs();
  const opts = options || {};
  const offer = {
    credential_issuer: base,
    credential_configuration_ids: configurationIds
  };
  let issuerState = "";
  let preAuthorizedCode = "";
  let txCodeValue = "";

  if (mode === 'cross-device' || mode === 'deferred') {
    preAuthorizedCode = randomId(24);
    // Numeric digits, which is what the issuer's page displays — see
    // newTxCode() for the length and the generator. The value never travels in
    // the offer — only its shape does — because the whole point is that it
    // reaches the End-User by a different channel.
    txCodeValue = newTxCode();
    preAuthorizedCodes.set(preAuthorizedCode, {
      configurationIds: configurationIds,
      txCode: txCodeValue,
      txCodeFailures: 0,
      user: opts.user || userFor(vciOfferUsername()),
      deferred: mode === 'deferred',
      expires: expires
    });
    offer.grants = {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': preAuthorizedCode,
        tx_code: {
          input_mode: 'numeric',
          length: txCodeValue.length,
          // No apostrophe: this string is URL-encoded into the offer, and an
          // apostrophe survives encodeURIComponent only to be XML-escaped into
          // "&apos;" when the offer URI is displayed — which turns one query
          // parameter into two for anything reading it off the page.
          description: 'Type the ' + txCodeValue.length + '-digit code shown by the issuer.'
        },
        // `oid4vci.preAuthorizedPollIntervalS`, 5 by default (2026-09-12).
        interval: Number(config.value('oid4vci.preAuthorizedPollIntervalS')) || 5
      }
    };
  } else {
    issuerState = randomId(18);
    issuerStates.set(issuerState, { configurationIds: configurationIds, expires: expires });
    offer.grants = { authorization_code: { issuer_state: issuerState } };
  }

  logArtifact('OID4VCI Credential Offer', 'as built', offer);
  log.debug("Leaving buildCredentialOffer(). mode=" + mode + ", issuer_state=" + issuerState +
            ", pre-authorized=" + (preAuthorizedCode ? "yes" : "no"));
  return { offer: offer, issuerState: issuerState,
           preAuthorizedCode: preAuthorizedCode, txCode: txCodeValue, mode: mode || 'same-device' };
}

// The issuer's own web page — where H.1 starts.
// ---------------------------------------------------------------------------
// THE FOUR SCALAR PARAMETERS THESE PAGES TAKE.
//
// **THE FORMAT LIST IS DERIVED FROM `VCI_CONFIGS` AND NEVER RETYPED.** Which
// credential formats this issuer offers is that table's statement — three of
// them today (`dc+sd-jwt`, `jwt_vc_json`, `ldp_vc`) — and a list written out
// here would be the second copy that goes stale the day a fourth is added.
// Same argument `sts_metadata.js` makes about reading the router.
//
// **`wallet` IS TYPED AS A URI AND THAT IS THE ONE THAT MATTERS.** It is a URL
// this service builds into a link and a QR code for somebody to follow, so a
// `javascript:` or `data:` scheme here is script execution on the machine of
// whoever scans it. `vt.uri` refuses the executable schemes; it deliberately
// does NOT constrain the host, because pointing this at a wallet on a laptop is
// the whole reason the parameter exists.
//
// `mode` and `by` are CASE-SENSITIVE, matching their call sites, which compare
// with `===` and lower-case nothing.
// ---------------------------------------------------------------------------
const OID4VC_QUERY = validation.z.looseObject({
  mode: validation.types.opt(validation.types.oneOf(
    ['same-device', 'cross-device', 'deferred', 'direct'])),
  by: validation.types.opt(validation.types.oneOf(['value', 'reference'])),
  format: validation.types.opt(validation.types.oneOf(VCI_FORMATS)),
  wallet: validation.types.opt(validation.types.uri),
  state: validation.types.opt(validation.types.opaque),
  credential_configuration_ids: validation.types.opt(
    validation.z.string().max(validation.CAP.SCOPE))
});

app.get('/issuer', function (req, res) {
  log.debug("Entering the issuer web page.");
  const base = baseUrlOf(req);
  const configId = VCI_CONFIG_ID;
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Mock University — digital diploma</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:520px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
    'p{line-height:1.5;color:#333}a.cta{display:inline-block;margin-top:14px;margin-right:10px;padding:10px 16px;' +
    'border-radius:6px;background:#12107c;color:#fff;text-decoration:none;font-weight:600}' +
    'a.cta.secondary{background:#fff;color:#12107c;border:1px solid #12107c}' +
    'p.alt{margin-top:20px;font-size:.92em;color:#555}' +
    '.meta{margin-top:22px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>Mock University</h1>' +
    '<p>Congratulations on your graduation. Your diploma is available as a digital credential ' +
    '(<code>' + xmlEscape(configId) + '</code>) that you can keep in your wallet.</p>' +
    '<p><a class="cta" href="/issuer/offer">Request your digital diploma</a>' +
    '<a class="cta secondary" href="/issuer/offer?by=reference">Request it (offer by reference)</a></p>' +
    '<p class="alt">On a different device? These show a QR code to scan with your wallet instead:<br>' +
    '<a class="cta secondary" href="/issuer/offer?mode=cross-device">Show a QR code (cross-device)</a>' +
    '<a class="cta secondary" href="/issuer/offer?mode=deferred">Show a QR code (issuance takes a while)</a></p>' +
    '<div class="meta">This is the Credential Issuer\'s web page in OID4VCI Appendix H. The first two links ' +
    'build a Credential Offer and send you to your wallet at <code>' + xmlEscape(walletBaseUrl()) + '</code> ' +
    '(H.1, same device). The other two hand the offer over by QR code and a Transaction Code instead — H.2, ' +
    'and H.3 where the issuer needs time to produce the credential. The issuer is ' +
    '<code>' + xmlEscape(base) + '</code>.</div>' +
    '</div></body></html>\n';
  res.status(200).type('text/html').send(page);
  log.debug("Leaving the issuer web page.");
});

// The link on that page: build the offer and send the End-User to their wallet.
app.get('/issuer/offer', function (req, res) {
  log.debug("Entering the credential offer endpoint.");
  const base = baseUrlOf(req);
  const configurationIds = req.query.credential_configuration_ids
    ? String(req.query.credential_configuration_ids).split(',').filter(Boolean)
    : [VCI_CONFIG_ID];
  const askedOffer = validation.check(req, 'query', OID4VC_QUERY);
  if (!askedOffer.ok) {
    log.debug('Leaving the offer page. ' + askedOffer.detail);
    errorCodes.mark(res, 'STS-VC-0025');
    return res.status(400).type('text/plain').send(askedOffer.detail + '\n');
  }
  const offerMode = String(req.query.mode || 'same-device');
  const walletChoice = walletFor(req);
  if (walletChoice.error) {
    log.debug("Leaving the credential offer endpoint. " + walletChoice.error);
    errorCodes.mark(res, 'STS-VC-0026');
    return res.status(400).type('text/plain').send(walletChoice.error + '\n');
  }
  // -------------------------------------------------------------------------
  // WHO A PRE-AUTHORIZED OFFER IS FOR (2026-09-12).
  //
  // A cross-device or deferred offer carries a pre-authorized code, and that
  // code IS the authorization: whoever redeems it is issued a credential about
  // the person it names. This page minted one for `oid4vci.offerUsername` for
  // anybody who loaded it and printed the Transaction Code beside it — a
  // credential about a fixed person, for the asking. That is H.2's DEMO
  // ("they uploaded documents to an employee portal days before") and it is a
  // test control.
  //
  // So where the test controls are closed the page requires a SIGN-ON SESSION
  // and mints the offer for the person signed in: the issuer's screen is then
  // what H.2 says it is, a page the End-User reached after identifying
  // themselves to the issuer. With no session the browser is sent through the
  // sign-in screen and comes back here. An unauthenticated ("continue without
  // signing in") session is not an identification and is refused by name.
  //
  // A SAME-DEVICE offer is not gated. It carries an issuer_state and no
  // authorization at all — the wallet still takes the End-User through
  // /oauth2/authorize, which authenticates them there — so there is nothing to
  // mint for anybody.
  //
  // `authn.js` is required HERE rather than at the top of this file: this
  // module is required by `oauth2.js` for its stores, and a top-level require
  // of the authentication service from a store module is a cycle waiting for
  // the load order to change. Inside the handler it is always a cache hit.
  // -------------------------------------------------------------------------
  let offerUser = null;
  const preAuthorized = offerMode === 'cross-device' || offerMode === 'deferred';
  if (preAuthorized && !mode.opensTestControls()) {
    const authn = require('../authn/authn');
    const session = authn.sessionOf(req);
    if (!session || !session.user || !session.user.username) {
      log.debug("Leaving the credential offer endpoint. A sign-in is needed first.");
      return res.redirect(302, authn.beginAuthentication({
        returnTo: req.originalUrl && req.originalUrl.charAt(0) === '/' &&
                  req.originalUrl.charAt(1) !== '/' ? req.originalUrl : '/issuer/offer',
        protocol: 'OpenID4VCI'
      }));
    }
    if (session.authenticated === false) {
      log.debug("Leaving the credential offer endpoint. The session is not authenticated.");
      errorCodes.mark(res, 'STS-VC-0027');
      return res.status(403).type('text/plain').send(
        'A pre-authorized Credential Offer is a credential about the person it is made ' +
        'for, and this browser has not signed in — it chose to continue without doing so. ' +
        'Sign in as the person the credential should describe and load this page again.\n');
    }
    offerUser = Object.assign({}, userFor(session.user.username),
                              session.user.sub ? { sub: session.user.sub } : {});
  }
  const built = buildCredentialOffer(req, configurationIds, offerMode,
                                     { user: offerUser });
  const wallet = walletChoice.url;

  // Sweep expired offers/states/codes while we are here.
  const now = Date.now();
  credentialOffers.forEach(function (v, k) { if (v.expires < now) credentialOffers.delete(k); });
  issuerStates.forEach(function (v, k) { if (v.expires < now) issuerStates.delete(k); });
  preAuthorizedCodes.forEach(function (v, k) { if (v.expires < now) preAuthorizedCodes.delete(k); });
  deferredTransactions.forEach(function (v, k) { if (v.expires < now) deferredTransactions.delete(k); });

  // How the offer reaches the wallet: in the URL, or behind a URI it fetches.
  let offerQuery;
  if (String(req.query.by || '') === 'reference') {
    const id = randomId(12);
    credentialOffers.set(id, { offer: built.offer, expires: now + offerTtlMs() });
    const offerUri = base + '/oid4vci/credential-offer/' + id;
    offerQuery = 'credential_offer_uri=' + encodeURIComponent(offerUri);
    log.debug("The offer is passed by reference: " + offerUri);
  } else {
    offerQuery = 'credential_offer=' + encodeURIComponent(JSON.stringify(built.offer));
    log.debug("The offer is passed by value.");
  }

  // Same device (H.1): the wallet is right here, so send the browser to it.
  if (built.mode !== 'cross-device' && built.mode !== 'deferred') {
    res.redirect(302, wallet + '?' + offerQuery);
    log.debug("Leaving the credential offer endpoint. Sent the End-User to " + wallet + ".");
    return;
  }

  // Cross device (H.2 / H.3): the wallet is on the End-User's OTHER device, so
  // the offer is displayed for it to scan — as the openid-credential-offer URI
  // a wallet registers for — and the Transaction Code is shown here, on the
  // issuer's screen, never in the offer.
  const offerUri = 'openid-credential-offer://?' + offerQuery;
  renderOfferQrPage(res, {
    base: base,
    mode: built.mode,
    offerUri: offerUri,
    walletUrl: wallet + '?' + offerQuery,
    txCode: built.txCode,
    offer: built.offer
  });
  log.debug("Leaving the credential offer endpoint. Displayed a QR code for the wallet to scan.");
});

// The issuer's screen in a cross-device flow: a QR code carrying the Credential
// Offer, and — separately, which is the whole point — the Transaction Code.
function renderOfferQrPage(res, opts) {
  log.debug("Entering renderOfferQrPage(). mode=" + opts.mode);
  qrcode.toDataURL(opts.offerUri, { errorCorrectionLevel: 'M', margin: 2, width: 320 })
    .then(function (dataUrl) {
      const deferred = opts.mode === 'deferred';
      const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
        '<title>Mock University — scan to receive your credential</title><style>' +
        'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
        'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
        '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
        'box-shadow:0 6px 24px rgba(0,0,0,.08);text-align:center}h1{font-size:1.25em;margin:0 0 6px}' +
        'p{line-height:1.5;color:#333}img.qr{margin:14px auto;display:block;border:1px solid #eee;border-radius:8px}' +
        '.txcode{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:2.1em;letter-spacing:.28em;' +
        'font-weight:700;color:#12107c;background:#f0f0fa;border-radius:8px;padding:12px 6px;margin:6px 0 2px}' +
        '.uri{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.72em;' +
        'color:#555;background:#fafafa;border:1px solid #eee;border-radius:6px;padding:8px;text-align:left}' +
        '.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777;text-align:left}' +
        'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
        '</style></head><body><div class="card">' +
        '<h1>Scan this with your wallet</h1>' +
        '<p>Your digital diploma is ready to be claimed' +
        (deferred ? ', though issuing it will take us a little time once you ask.' : '.') + '</p>' +
        '<img class="qr" id="offer_qr" alt="Credential Offer QR code" src="' + dataUrl + '">' +
        '<p>Then type this Transaction Code into your wallet:</p>' +
        '<div class="txcode" id="tx_code">' + xmlEscape(opts.txCode) + '</div>' +
        '<p style="font-size:.8em;color:#777">It is shown here, and only here — it does not travel in the QR code.</p>' +
        '<div class="uri" id="offer_uri">' + xmlEscape(opts.offerUri) + '</div>' +
        '<div class="meta">OID4VCI Appendix ' + (deferred ? 'H.3' : 'H.2') + '. The offer uses the ' +
        '<code>pre-authorized_code</code> grant: you already identified yourself to this issuer, so your wallet ' +
        'goes straight to the token endpoint — there is no authorization request. ' +
        (deferred ? 'The credential endpoint will answer with a <code>transaction_id</code> and your wallet will ' +
                    'have to come back for the credential. ' : '') +
        'If your wallet is on this device, <a id="open_in_wallet" href="' + xmlEscape(opts.walletUrl) + '">open it here</a>.' +
        '</div></div></body></html>\n';
      res.status(200).type('text/html').send(page);
      log.debug("Leaving renderOfferQrPage(). Rendered a QR code.");
    })
    .catch(function (e) {
      log.error(errorCodes.tag('STS-VC-0028') +
                "could not render the offer QR code: " + e.message);
      errorCodes.mark(res, 'STS-VC-0028');
      res.status(500).type('text/plain').send('Could not render the Credential Offer QR code: ' + e.message);
    });
}

app.get('/oid4vci/credential-offer/:id', function (req, res) {
  log.debug("Entering the credential offer retrieval endpoint. id=" + req.params.id);
  const record = credentialOffers.get(req.params.id);
  if (!record || record.expires < Date.now()) {
    credentialOffers.delete(req.params.id);
    log.debug("Leaving the credential offer retrieval endpoint. No such offer.");
    errorCodes.mark(res, 'STS-VC-0029');
    return vciError(res, 404, 'invalid_request', 'No such Credential Offer, or it has expired.');
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(record.offer, null, 2));
  log.debug("Leaving the credential offer retrieval endpoint.");
});

module.exports = {
  credentialOffers: credentialOffers,
  issuerStates: issuerStates,
  preAuthorizedCodes: preAuthorizedCodes,
  deferredTransactions: deferredTransactions,
  deferredAccessTokens: deferredAccessTokens,
  deferredReadyMs: deferredReadyMs,
  deferredIntervalS: deferredIntervalS,
  OFFER_TTL_MS: OFFER_TTL_MS,
  offerTtlMs: offerTtlMs,
  checkTxCode: checkTxCode,
  walletFor: walletFor,
  vciOfferUsername: vciOfferUsername,
  buildCredentialOffer: buildCredentialOffer,
  renderOfferQrPage: renderOfferQrPage
};
