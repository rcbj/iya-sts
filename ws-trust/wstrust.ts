'use strict';
//
// File: wstrust.ts
//
// ---------------------------------------------------------------------------
// WS-Trust 1.4 (and 1.0-1.3, which differ only in the namespace and action
// URIs): the SOAP RequestSecurityToken endpoint and everything that reads or
// writes one.
//
// It accepts an RST and dispatches on wst:RequestType:
//
//   Issue    -> RSTR Collection with a freshly minted, STS-signed SAML 2.0
//               assertion (or a JWT, when TokenType asks for one), a
//               Lifetime, and an attached reference.
//   Renew    -> RSTR with a fresh token for the supplied RenewTarget.
//   Validate -> RSTR with wst:Status/wst:Code valid|invalid.
//   Cancel   -> RSTR with wst:RequestedTokenCancelled.
//
// Authentication: a WS-Security UsernameToken is accepted when username and
// password are both present (and the password is not the literal "invalid",
// which lets a negative test force an auth failure). A SAML assertion in the
// security header is accepted as a credential too, and a request carrying an
// OnBehalfOf/ActAs token (delegation) is accepted on top of either. It does not
// verify request signatures or enforce delegation policy.
//
// **THAT PARAGRAPH IS DEVELOPMENT MODE, AND PRODUCT MODE IS DIFFERENT IN FIVE
// PLACES (2026-09-12)** — every one of them asked through
// `mode.verifiesCredentials()`, because each is the question "is a presented
// credential actually checked":
//
//   * a UsernameToken's password is verified against the stored
//     `userPassword` (`common/credentials.ts`), not only against "invalid";
//   * a request with NO credential is refused, where development issues a token
//     for the literal subject `anonymous` (and a Renew for whoever its
//     RenewTarget names);
//   * a SAML assertion presented AS the credential must carry a signature that
//     verifies against THIS REALM'S OWN signing certificate and be inside its
//     Conditions — the smallest real answer to "which issuer is trusted",
//     because it is the one key this service already holds and publishes at
//     /sts/cert, and it covers the case WS-Trust exists for here: exchanging or
//     renewing a token this STS issued. There is no configured list of foreign
//     issuers yet, and saying so is better than accepting any;
//   * an OnBehalfOf / ActAs is refused without a requester credential of the
//     requester's own, and the token inside it must be such an assertion too;
//   * no subject is invented: `saml-subject` and `delegated-subject` are
//     development's words for an assertion with no NameID, and product refuses.
//
// The token lifetime a request asks for is CLAMPED in both modes
// (`wstrust.maxTokenLifetimeMin`), because an STS that honours any requested
// lifetime is wrong in every mode — see handleRst().
//
// EVERY accepted credential is put through stats.recordAuthentication(), on
// every one of the four operations, and that matters beyond the counter it
// increments: it is this service's single authentication funnel, so it is also
// what writes the audit log's `authentication` row and what makes the embedded
// LDAP directory grow a `uid=<name>,ou=users` entry for the person. Three
// things here used to miss it, and each one produced somebody who had
// authenticated through WS-Trust and had no directory object:
//
//   * Validate and Cancel answered before authenticate() was ever called.
//   * a request with BOTH a UsernameToken and an OnBehalfOf recorded only the
//     delegated subject — the requester, the one party that presented a
//     credential, was dropped.
//   * a Renew with no security header read the assertion out of its own
//     RenewTarget and recorded THAT as the credential; the token was talking,
//     not the requester.
//
// The SAML assertion itself is built and protected by saml2.ts: WS-Trust
// carries tokens, it does not define them.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `WsTrust` takes every module of this service it reads — and each
// name it used to destructure from `helpers.js` and `saml/saml2` — through
// its constructor as `WsTrustDeps`, and its three endpoints are registered by
// `registerRoutes(app)`; xmldom is a library and is used directly. The module
// still exports `handleRst()`, `issuerDisagreement()`, `checkedAssertion()`,
// `buildToken()` and `soapFault()`, for the modules and tests that require it
// by them. It registers NOTHING at load (#50, R1): the module exports
// `registerRoutes(app)`, and `common/protocol_stack.ts` calls it at the point
// in the route order where requiring this module always registered them
// (rule 1). Since R2 that root also builds the instance and installs it, and
// the exported functions are FACADES that forward to it. `WsTrust.wire()`
// logs the startup issuer check, as the module did — when the root installs
// the instance, still before the routes are registered rather than after;
// a process without the root builds a default instance and logs it at load.
// ---------------------------------------------------------------------------

// One signer and one verifier for the whole service since 2026-08-27.
import stsCrypto = require('../common/crypto');
import xmldom = require('@xmldom/xmldom');
import app = require('../common/app');
// firstByLocal/textByLocal were written here and now live in helpers.js:
// WS-Federation reads the same shapes (a `wreq` RST, and a `wresult` at its
// mock relying party), and a second copy of a reader that has to cope with
// four trust namespaces is a second copy that gets one of them wrong.
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// The input validator. A LEAF (rule 3): it registers no route and requires only
// `config`, `error_codes`, bunyan, zod, zlib and @xmldom/xmldom, so it closes
// no cycle.
import validation = require('../common/validation');
// wstrust.issuer. A SAML token requested THROUGH WS-Trust is built by the
// SAML modules and carries saml.issuer instead; the two are separate
// settings for that reason and default to the same value.
import config = require('../common/config');
import saml2 = require('../saml/saml2');
import stats = require('../common/admin_stats');
// The application registry (ou=applications in the embedded directory). A
// library that registers no route, so it cannot move anything in the require
// order this module sits in.
import applications = require('../common/applications');
// THE ROLE GATE. A LEAF (rule 3) requiring only `helpers`, `config` and
// `error_codes`, so a require from here moves no route and closes no cycle.
// See `common/issuance_gate.js`; an unfilled decider answers "allowed".
import gate = require('../common/issuance_gate');
// The delegation register (/admin/delegation). Two of the eight mechanisms that
// page knows are this module's — OnBehalfOf and ActAs — and they are the two
// where nothing is checked at all, which is a fact the page states beside the
// Kerberos rows where something is. A library like the two above: it registers
// no route.
import delegation = require('../common/delegation');
// THE SESSION STORE. A plain require in the ordinary direction, and it is why
// this module moved BELOW authn.js in the require order on 2026-09-05 rather
// than keeping its old place — see the note on its line in
// common/protocol_stack.ts. Requiring it from above would have dragged every
// /authn route to the front of the router (rule 1) until #50's R1; since
// then requiring it registers nothing, and `common/protocol_stack.ts`
// registers the /authn routes ahead of this module's in its own order.
// `authn.js` does not require this module, so no cycle closes either way.
import authn = require('../authn/authn');
// The credential verifier and the mode. Libraries that register no route and
// never require this module: `mode.js` is a leaf, and `credentials.js`
// requires only other libraries.
import credentials = require('../common/credentials');
import mode = require('../common/mode');
// The one reading of how a requester authenticated, in SAML 2.0's vocabulary,
// so an assertion this STS issues says what the credential was rather than
// calling everything a password. A leaf in `saml/` that registers nothing.
import authnContext = require('../saml/authn_context');
// The error codes (common/error_codes.js). A LEAF that requires nothing. A
// refusal decided below handleRst() travels out on the result's `errorCode` and
// is marked on the response by the route; it never reaches the SOAP body.
import errorCodes = require('../common/error_codes');

const { DOMParser, XMLSerializer } = xmldom;

type Helpers = typeof helpers;
type Saml2 = typeof saml2;

// Everything this module reads of the rest of the service. The helpers and the
// two SAML 2.0 builders are named one by one, as the module destructured them.
interface WsTrustDeps {
  stsCrypto: typeof stsCrypto;
  config: typeof config;
  validation: typeof validation;
  buildSamlAssertion: Saml2['buildSamlAssertion'];
  encryptAssertion: Saml2['encryptAssertion'];
  stats: typeof stats;
  applications: typeof applications;
  gate: typeof gate;
  delegation: typeof delegation;
  authn: typeof authn;
  credentials: typeof credentials;
  mode: typeof mode;
  authnContext: typeof authnContext;
  errorCodes: typeof errorCodes;
  log: Helpers['log'];
  logArtifact: Helpers['logArtifact'];
  STS: Helpers['STS'];
  xmlEscape: Helpers['xmlEscape'];
  iso: Helpers['iso'];
  randomId: Helpers['randomId'];
  signJwtAs: Helpers['signJwtAs'];
  firstByLocal: Helpers['firstByLocal'];
  textByLocal: Helpers['textByLocal'];
  subjectForName: Helpers['subjectForName'];
  hasSubjectResolver: Helpers['hasSubjectResolver'];
}

// The express app's registration methods, as `registerRoutes()` uses them.
interface RouteRegistrar {
  get(path: string, ...handlers: any[]): unknown;
  post(path: string, ...handlers: any[]): unknown;
}

const WST_NS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';

const SOAP12_NS = 'http://www.w3.org/2003/05/soap-envelope';

const SOAP11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';

const SAML2_TOKEN_TYPE =
    'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';

const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

const STATUS_TOKEN_TYPE = WST_NS + '/RSTR/Status';

const STATUS_VALID = WST_NS + '/status/valid';

const STATUS_INVALID = WST_NS + '/status/invalid';

// The elements of a WS-Trust request that hold SOMEBODY ELSE'S token. A
// UsernameToken or an Assertion inside one of these is not the requester's
// credential and must never be read as one.
const NOT_A_CREDENTIAL = ['OnBehalfOf', 'ActAs', 'RenewTarget',
                          'ValidateTarget', 'CancelTarget'];

class WsTrust {
  constructor(private readonly deps: WsTrustDeps) {
    deps.log.debug("Entering WsTrust.constructor().");
    deps.log.debug("Leaving WsTrust.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  static defaultDeps(): WsTrustDeps {
    helpers.log.debug("Entering WsTrust.defaultDeps().");
    helpers.log.debug("Leaving WsTrust.defaultDeps().");
    return {
      stsCrypto: stsCrypto,
      config: config,
      validation: validation,
      buildSamlAssertion: saml2.buildSamlAssertion,
      encryptAssertion: saml2.encryptAssertion,
      stats: stats,
      applications: applications,
      gate: gate,
      delegation: delegation,
      authn: authn,
      credentials: credentials,
      mode: mode,
      authnContext: authnContext,
      errorCodes: errorCodes,
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      STS: helpers.STS,
      xmlEscape: helpers.xmlEscape,
      iso: helpers.iso,
      randomId: helpers.randomId,
      signJwtAs: helpers.signJwtAs,
      firstByLocal: helpers.firstByLocal,
      textByLocal: helpers.textByLocal,
      subjectForName: helpers.subjectForName,
      hasSubjectResolver: helpers.hasSubjectResolver
    };
  }

  // The work loading this module did with its own instance before R2,
  // run once for whichever instance is installed.
  static wire(instance: WsTrust): void {
    helpers.log.debug("Entering WsTrust.wire().");
    instance.warnAtStartup();
    helpers.log.debug("Leaving WsTrust.wire().");
  }

  // -------------------------------------------------------------------------
  // THE ROUTES, in the order this module has always registered them.
  // -------------------------------------------------------------------------
  registerRoutes(app: RouteRegistrar): void {
    const { log } = this.deps;
    log.debug("Entering WsTrust.registerRoutes().");
    // GET /sts/cert
    app.get('/sts/cert', (req, res) => {
      return this.stsCertEndpoint(req, res);
    });
    // GET /sts
    app.get('/sts', (req, res) => {
      return this.stsDescriptionEndpoint(req, res);
    });
    // POST /sts
    app.post('/sts', (req, res) => {
      return this.stsEndpoint(req, res);
    });
    log.debug("Leaving WsTrust.registerRoutes().");
  }

  private soapNsFor(version) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.soapNsFor().");
    log.debug("Leaving WsTrust.soapNsFor().");
    return version === '1.1' ? SOAP11_NS : SOAP12_NS;
  }

  // ---------------------------------------------------------------------------
  // THE JWT, and three things changed on 2026-09-12.
  //
  //   * THE ALGORITHM is `wstrust.jwtAlgorithm` rather than the literal RS256,
  //     signed through `helpers.signJwtAs()` with this realm's key for that
  //     algorithm — so the header now carries the `kid` /oauth2/jwks publishes
  //     it under, which the old direct signature over STS.privateKey never did.
  //   * A `jti`. Every other token this service issues carries one and the
  //     token register keys on it; this one had none, which made it the one
  //     token here that could not be named — on /admin/delegation a WS-Trust
  //     JWT's produced identifier was an empty cell explained by a sentence. It
  //     is still not put through helpers.signJwt()'s register: that funnel is
  //     RS256 by construction, and a jti a caller can quote is the half that
  //     was missing.
  //   * THE LIFETIME is whatever handleRst() decided, which is now bounded.
  //
  // `iat`, `exp`, `iss` and `aud` are set explicitly rather than by
  // jsonwebtoken's options, because signJwtAs() takes a payload and nothing
  // else.
  // ---------------------------------------------------------------------------
  private buildJwt(subject, audience, lifetimeMin) {
    const {
      config, log, logArtifact, randomId, signJwtAs, subjectForName
    } = this.deps;
    log.debug("Entering WsTrust.buildJwt().");
    const alg = String(config.value('wstrust.jwtAlgorithm') || 'RS256');
    const now = Math.floor(Date.now() / 1000);
    const claims: any = {
      iss: config.value('wstrust.issuer'),
      // THE PERSON'S SUBJECT (2026-09-14) — `urn:uuid:<entryUUID>`, as every
      // other token here. The bare name is left only for a process with no
      // directory, where nobody has a subject; with one, a person the directory
      // does not hold is refused before this is reached (`STS-WSTRUST-0017`),
      // because a bare name would be a `sub` a relying party links on and a
      // person created later under that name would inherit.
      sub: subjectForName(subject) || subject,
      name: subject,
      iat: now,
      exp: now +
           (lifetimeMin > 0 ? lifetimeMin :
            Number(config.value('wstrust.tokenLifetimeMin'))) * 60,
      jti: randomId(18)
    };
    // An empty-string audience is not an audience — only set it when present.
    if (audience) claims.aud = audience;
    logArtifact('WS-Trust JWT', 'before signing',
                { header: { alg: alg }, payload: claims });
    // `wstrust.jwtCertificateHeader` decides the `x5c` / `x5u`.
    const signed = signJwtAs(claims, alg, null,
                             { certificateHeader: 'wstrust-jwt' });
    logArtifact('WS-Trust JWT', 'after signing', signed);
    log.debug("Leaving WsTrust.buildJwt(). " + alg + ", jti=" + claims.jti +
              ".");
    return { token: signed, jti: claims.jti };
  }

  // Build the token element (what goes inside wst:RequestedSecurityToken).
  // `authnContextClassRef` is how the REQUESTER authenticated — see
  // authnContextOf() — and is written into a SAML assertion's AuthnStatement.
  // It is optional so an existing caller of this export gets `unspecified`,
  // which is the builder's default and overstates nothing.
  buildToken(tokenType, subject, audience, lifetimeMin,
                      authnContextClassRef) {
    const { buildSamlAssertion, authnContext, log, xmlEscape } = this.deps;
    log.debug("Entering WsTrust.buildToken(). tokenType=" + tokenType + ", " +
        "subject=" +
              subject);
    if (tokenType === JWT_TOKEN_TYPE) {
      const built = this.buildJwt(subject, audience, lifetimeMin);
      const token = { xml: '<wsse:BinarySecurityToken ' +
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
        'ValueType="urn:ietf:params:oauth:token-type:jwt">' + built.token +
        '</wsse:BinarySecurityToken>',
        ref: '', tokenType: JWT_TOKEN_TYPE, id: built.jti };
      log.debug("Leaving WsTrust.buildToken(). Issued a JWT.");
      return token;
    }
    const assertion = buildSamlAssertion(subject, audience, lifetimeMin,
      { authnContextClassRef: authnContextClassRef ||
                              authnContext.AC_UNSPECIFIED });
    const idm = assertion.match(/\bID="([^"]+)"/);
    const id = idm ? idm[1] : '';
    const ref = '<wst:RequestedAttachedReference>' +
      '<wsse:SecurityTokenReference ' +
      'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
      '<wsse:KeyIdentifier ' +
      'ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">' +
      xmlEscape(id) +
      '</wsse:KeyIdentifier></wsse:SecurityTokenReference>' +
      '</wst:RequestedAttachedReference>';
    log.debug("Leaving WsTrust.buildToken(). Issued a SAML 2.0 assertion " +
              "with ID " + id +
              ".");
    // `id` is carried out because /admin/delegation quotes the identifier of
    // what a delegated request PRODUCED: the AssertionID for this branch and,
    // since 2026-09-12, the `jti` for the JWT branch above, which had no
    // identifier at all until then. The JWT is still not in the tokens register
    // — what puts a token there is helpers.signJwt(), and this one is signed
    // through signJwtAs() for its configurable algorithm.
    return { xml: assertion, ref: ref, tokenType: SAML2_TOKEN_TYPE, id: id };
  }

  private envelope(version, action, bodyInner) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.envelope(). version=" + version +
              ", action=" + action);
    const soapNs = this.soapNsFor(version);
    const header = action
      ? '<soap:Header><wsa:Action ' +
        'xmlns:wsa="http://www.w3.org/2005/08/addressing">' + action +
        '</wsa:Action></soap:Header>'
      : '';
    log.debug("Leaving WsTrust.envelope().");
    return '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope xmlns:soap="' + soapNs + '">' + header +
      '<soap:Body>' + bodyInner + '</soap:Body></soap:Envelope>';
  }

  // error-code: none — the definition of the helper, not a call to it
  soapFault(version, reason) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering WsTrust.soapFault(). version=" + version + ", " +
        "reason=" + reason);
    const soapNs = this.soapNsFor(version);
    const body = version === '1.1'
      ? '<soap:Fault><faultcode>soap:Client</faultcode><faultstring>' +
        xmlEscape(reason) + '</faultstring></soap:Fault>'
      : '<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value>' +
        '</soap:Code><soap:Reason><soap:Text ' +
        'xml:lang="en">' + xmlEscape(reason) +
        '</soap:Text></soap:Reason></soap:Fault>';
    log.debug("Leaving WsTrust.soapFault().");
    return '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope xmlns:soap="' + soapNs + '">' + '<soap:Body>' + body +
      '</soap:Body></soap:Envelope>';
  }

  // --- request handling ------------------------------------------------------
  private detectSoapVersion(doc, contentType) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.detectSoapVersion().");
    const root = doc && doc.documentElement;
    log.debug("Leaving WsTrust.detectSoapVersion().");
    if (root && root.namespaceURI === SOAP11_NS) {
      log.debug("Leaving WsTrust.detectSoapVersion().");
      return '1.1';
    }
    if (root && root.namespaceURI === SOAP12_NS) {
      log.debug("Leaving WsTrust.detectSoapVersion().");
      return '1.2';
    }
    log.debug("Leaving WsTrust.detectSoapVersion().");
    return /text\/xml/i.test(contentType || '') ? '1.1' : '1.2';
  }

  // Is `node` inside one of them?
  private insideAnotherPartysToken(node) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.insideAnotherPartysToken().");
    let current = node && node.parentNode;
    while (current) {
      const name = current.localName || current.nodeName || '';
      if (NOT_A_CREDENTIAL.indexOf(String(name).split(':').pop()) >= 0) {
        log.debug("Leaving WsTrust.insideAnotherPartysToken(). It is inside " +
                  name + ".");
        return true;
      }
      current = current.parentNode;
    }
    log.debug("Leaving WsTrust.insideAnotherPartysToken(). It is not.");
    return false;
  }

  // The first element of that local name under `root` that is the REQUESTER'S
  // own, skipping any that belongs to somebody else.
  //
  // This exists because a WS-Trust request routinely carries several
  // identities: the requester's UsernameToken in the security header, the
  // subject named in `wst:OnBehalfOf` or `wst:ActAs`, and the token being
  // renewed, validated or cancelled in `wst:RenewTarget` /
  // `wst:ValidateTarget`. All of them are `wsse:UsernameToken` or
  // `saml:Assertion` elements, so a plain search over the document answers
  // "which comes first in DOCUMENT ORDER", which is not the question being
  // asked.
  //
  // That is not hypothetical: a Renew whose RenewTarget held the expiring
  // assertion, sent with no security header at all, used to authenticate as
  // that assertion's NameID. It was the TOKEN talking, not the requester.
  private firstOwnedByRequester(root, name) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.firstOwnedByRequester(). name=" + name);
    const found = root.getElementsByTagNameNS('*', name);
    for (let i = 0; found && i < found.length; i++) {
      if (!this.insideAnotherPartysToken(found[i])) {
        log.debug("Leaving WsTrust.firstOwnedByRequester(). Found one at " +
                  "index " + i +
                  ".");
        return found[i];
      }
    }
    log.debug("Leaving WsTrust.firstOwnedByRequester(). There is none.");
    return null;
  }

  // The element a REQUESTER's own credential may be read from: `wsse:Security`
  // when the request has one, and the whole document when it has none. The
  // fallback is deliberately lenient — a UsernameToken put somewhere other than
  // the security header is still read — and it is safe because
  // firstOwnedByRequester() below is what does the looking.
  private credentialScope(doc) {
    const { log, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.credentialScope().");
    const security = firstByLocal(doc, 'Security');
    if (security) {
      log.debug("Leaving WsTrust.credentialScope(). The security header is " +
                "the scope.");
      return security;
    }
    log.debug("Leaving WsTrust.credentialScope(). There is no security " +
              "header, so the whole document is the scope.");
    return doc;
  }

  // ---------------------------------------------------------------------------
  // A SAML ASSERTION SOMEBODY PRESENTED, CHECKED THE WAY PRODUCT MODE CHECKS
  // ONE (2026-09-12).
  //
  // Development reads the NameID off an assertion and believes it — the posture
  // the credential note below has always stated. In product that is a
  // credential anybody can type, so this is the check that replaces believing
  // it, used for the requester's own assertion AND for the token inside an
  // OnBehalfOf/ActAs:
  //
  //   1. THE SIGNATURE, over THIS assertion element and no other, against THIS
  //      REALM'S OWN signing certificate. The element is serialised on its own
  //      first, because the SOAP document can hold several assertions — the
  //      requester's and the delegated one — and a verifier asked about "the
  //      assertion in this document" would be answered about whichever came
  //      first. Exclusive canonicalization is what makes a standalone
  //      serialisation of an embedded element verify, and it is the only one
  //      this service signs with.
  //   2. THE CONDITIONS, NotBefore and NotOnOrAfter, with `oauth2.clockSkewS`
  //      of tolerance — the reading tolerance `federation_sp.ts` applies to an
  //      inbound assertion, for the reason it gives: a deployment decides once
  //      how far out the clocks it reads may be.
  //   3. A SUBJECT. An assertion naming nobody names nobody; development's
  //      `saml-subject` fallback is not a person.
  //
  // WHY THIS REALM'S CERTIFICATE AND NOTHING ELSE: it is the smallest real
  // answer. It is the key this STS already holds and publishes at /sts/cert,
  // and it covers what an assertion is presented here FOR — renewing,
  // validating or exchanging a token this STS issued. Trusting a foreign issuer
  // needs a register of which certificate may assert which subjects, and
  // accepting any certificate in the document's own KeyInfo would be accepting
  // any assertion at all.
  // ---------------------------------------------------------------------------
  checkedAssertion(assertion, what) {
    const { stsCrypto, config, log, STS, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.checkedAssertion(). what=" + what);
    const nameId = firstByLocal(assertion, 'NameID') ||
                   firstByLocal(assertion, 'NameIdentifier');
    const named = nameId ? (nameId.textContent || '').trim() : '';
    const xml = new XMLSerializer().serializeToString(assertion);
    // Any generation of this realm's XML key (#42): helpers.verifyOwnXml().
    const signature = helpers.verifyOwnXml(xml, { element: 'Assertion' });
    if (!signature.ok) {
      log.debug("Leaving WsTrust.checkedAssertion(). The signature did not " +
                "verify.");
      return { ok: false, errorCode: 'STS-WSTRUST-0004',
               reason: 'The ' + what + ' is a SAML assertion whose signature ' +
                       'does not verify against this security token ' +
                       'service\'s ' +
                       'own certificate (' +
                       (signature.why || 'unsigned') + '). In product mode ' +
                       'an assertion is accepted only if this STS issued it.' };
    }
    const conditions = firstByLocal(assertion, 'Conditions');
    const skewMs =
      Math.max(0, Number(config.value('oauth2.clockSkewS'))) * 1000;
    const now = Date.now();
    const notBefore = conditions ?
                      Date.parse(conditions.getAttribute('NotBefore') || '') :
                      NaN;
    const notOnOrAfter = conditions ?
                         Date.parse(conditions.getAttribute('NotOnOrAfter') ||
                                    '') : NaN;
    if (!isNaN(notBefore) && notBefore - skewMs > now) {
      log.debug("Leaving WsTrust.checkedAssertion(). Not yet valid.");
      return { ok: false, errorCode: 'STS-WSTRUST-0005',
               reason: 'The ' + what + ' is not valid until ' +
                 conditions.getAttribute('NotBefore') + '.' };
    }
    if (!isNaN(notOnOrAfter) && notOnOrAfter + skewMs <= now) {
      log.debug("Leaving WsTrust.checkedAssertion(). Expired.");
      return { ok: false, errorCode: 'STS-WSTRUST-0006',
               reason: 'The ' + what + ' expired at ' +
                 conditions.getAttribute('NotOnOrAfter') + '.' };
    }
    if (!named) {
      log.debug("Leaving WsTrust.checkedAssertion(). It names nobody.");
      return { ok: false, errorCode: 'STS-WSTRUST-0007',
               reason: 'The ' + what + ' carries no NameID, so it names ' +
                                  'nobody. Product mode does not invent a ' +
                                  'subject for it.' };
    }
    log.debug("Leaving WsTrust.checkedAssertion(). Verified, for " + named +
              ".");
    return { ok: true, subject: named };
  }

  // The requester's own credential, read from that scope. It returns null when
  // nothing was presented, which is a different answer from a credential that
  // was presented and refused.
  private requesterCredential(doc) {
    const { credentials, mode, log, firstByLocal, textByLocal } = this.deps;
    log.debug("Entering WsTrust.requesterCredential().");
    const scope = this.credentialScope(doc);
    const ut = this.firstOwnedByRequester(scope, 'UsernameToken');
    if (ut) {
      const user = textByLocal(ut, 'Username');
      const pass = textByLocal(ut, 'Password');
      if (!user || !pass) {
        log.debug("Leaving WsTrust.requesterCredential(). Incomplete " +
                  "UsernameToken.");
        return { ok: false, errorCode: 'STS-WSTRUST-0002',
                 reason: 'UsernameToken requires a username and password.' };
      }
      // THE CREDENTIAL (2026-09-06). One call, both modes — `credentials.js`
      // still refuses the reserved string `invalid` in development, which is
      // what this branch used to do on its own, and verifies against the hashed
      // `userPassword` in product mode.
      //
      // **THE FAULT SAYS THE SAME THING WHATEVER FAILED.** A SOAP Fault that
      // distinguished "no such user" from "wrong password" would be the account
      // enumeration answer over a protocol whose whole audience is machines;
      // the reason goes to the log instead.
      // `door: 'wstrust'` (#101): a password-only door, so in product a
      // person with a second factor is refused their password here — with
      // this same fault — and an app password scoped to `wstrust` is
      // accepted instead.
      const checked = credentials.verify(user, pass, {
        via: 'a WS-Security UsernameToken', door: 'wstrust'
      });
      if (!checked.ok) {
        log.info('wstrust: the UsernameToken for "' + user + '" was refused (' +
                 checked.reason + '): ' + checked.detail);
        log.debug("Leaving WsTrust.requesterCredential(). The credential was " +
                  "refused.");
        return { ok: false, errorCode: 'STS-WSTRUST-0003',
                 reason: 'Authentication failed for user ' + user + '.' };
      }
      log.debug("Leaving WsTrust.requesterCredential(). A UsernameToken " +
                "for " + user + ".");
      // AN APP PASSWORD IS SAID SO (#101): one factor, and the row names it.
      const viaApp = checked.reason === 'app-password' && checked.appPassword;
      return { ok: true, subject: user,
               method: viaApp ? 'WS-Security UsernameToken (app password)'
                 : 'WS-Security UsernameToken',
               kind: 'password',
               note: viaApp
                 ? 'An app password scoped to WS-Trust ("' +
                   checked.appPassword.name + '") was verified.'
                 : mode.verifiesCredentials()
                 ? 'The password was verified against the stored userPassword.'
                 : 'The password is not checked in development mode, except ' +
                   'for the reserved string "invalid".' };
    }
    // A SAML assertion presented directly as the credential.
    const assertion = this.firstOwnedByRequester(scope, 'Assertion');
    if (assertion) {
      // PRODUCT: verified, or refused. See checkedAssertion().
      if (mode.verifiesCredentials()) {
        const checked = this.checkedAssertion(assertion, 'requester\'s ' +
            'credential');
        if (!checked.ok) {
          log.info('wstrust: a SAML assertion presented as a credential was ' +
                   'refused: ' +
                   checked.reason);
          log.debug("Leaving WsTrust.requesterCredential(). The assertion " +
                    "was refused.");
          return { ok: false, reason: checked.reason,
                   errorCode: checked.errorCode };
        }
        log.debug("Leaving WsTrust.requesterCredential(). A verified SAML " +
                  "assertion for " +
                  checked.subject + ".");
        return { ok: true, subject: checked.subject, kind: 'assertion',
                 method: 'a SAML assertion as the credential',
                 note: 'The assertion\'s signature was verified against this ' +
                       'STS\'s own certificate and its Conditions were ' +
                       'checked.' };
      }
      const nameId = firstByLocal(assertion, 'NameID') ||
        firstByLocal(assertion, 'NameIdentifier');
      const named = (nameId && (nameId.textContent || '').trim()) ||
        'saml-subject';
      log.debug("Leaving WsTrust.requesterCredential(). A SAML assertion " +
                "for " + named +
                ".");
      return { ok: true, subject: named, kind: 'assertion',
               method: 'a SAML assertion as the credential',
               note: 'The assertion\'s signature and Conditions are not ' +
                     'checked in development mode; the NameID is read and ' +
                     'believed.' };
    }
    log.debug("Leaving WsTrust.requesterCredential(). Nothing was presented.");
    return null;
  }

  // The subject named in `wst:OnBehalfOf` or `wst:ActAs`, and WHICH OF THE TWO
  // it was. `{ subject: '', element: '' }` when the request delegates nothing.
  //
  // The two used to be collapsed with a `||`, which was right for everything
  // that reads this — the token issued is identical either way, because this
  // service polices nothing — and wrong for /admin/delegation, which is where
  // the difference is the whole point. They are not two spellings of one thing:
  //
  //   * `wst:OnBehalfOf` (1.3 §9.2) asks for a token ABOUT somebody. The
  //     relying party is handed an ordinary sign-in and cannot tell a middle
  //     tier was involved. IMPERSONATION.
  //   * `wst14:ActAs` (1.4 §9.3) is composite by definition: the token is about
  //     the named subject AND says the requester is acting. DELEGATION, and the
  //     element to reach for when the far end must be able to tell.
  //
  // A request carrying BOTH takes OnBehalfOf, which is the order the `||`
  // always had; the row says which one it attributed the act to, so the choice
  // is visible rather than silently made.
  //
  // AND THE IDENTIFIER OF THE TOKEN THAT WAS HANDED IN, which is the one thing
  // here that /admin/tokens/credential cannot do without. That page walks a
  // lineage by joining what an act PRODUCED to what the next act CONSUMED, on
  // the identifier and on nothing else (see credential_graph.js). A chain of
  // OnBehalfOf hops — the assertion one call issues is the assertion the next
  // call delegates with — is exactly the shape it exists to draw, and it was
  // invisible to it until this was read: the act's `consumed` named the
  // requester's WS-Security credential, which this service never issued and
  // cannot name, so every trail stopped one generation in at a wall.
  //
  // Three spellings, because three things can legitimately be inside one of
  // these elements: a SAML 2.0 assertion (`ID`), a SAML 1.1 one
  // (`AssertionID`), and a <wsse:SecurityTokenReference> naming a token by
  // KeyIdentifier rather than carrying it. An element holding none of them
  // yields '', which is not an error — it is the honest "this act consumed
  // something this register cannot name", and the lineage page prints that as a
  // reason rather than as an origin.
  private delegatedTokenId(element) {
    const { log, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.delegatedTokenId().");
    const assertion = firstByLocal(element, 'Assertion');
    if (assertion) {
      const id = assertion.getAttribute('ID') ||
        assertion.getAttribute('AssertionID') || '';
      if (String(id).trim()) {
        log.debug("Leaving WsTrust.delegatedTokenId(). An assertion, " + id +
                  ".");
        return String(id).trim();
      }
    }
    const keyIdentifier = firstByLocal(element, 'KeyIdentifier');
    if (keyIdentifier) {
      const named = (keyIdentifier.textContent || '').trim();
      if (named) {
        log.debug("Leaving WsTrust.delegatedTokenId(). A reference to " +
                  named + ".");
        return named;
      }
    }
    log.debug("Leaving WsTrust.delegatedTokenId(). Nothing here carries an " +
              "identifier.");
    return '';
  }

  private delegatedSubject(doc) {
    const { mode, log, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.delegatedSubject().");
    const oboEl = firstByLocal(doc, 'OnBehalfOf');
    const actAsEl = firstByLocal(doc, 'ActAs');
    const obo = oboEl || actAsEl;
    if (!obo) {
      log.debug("Leaving WsTrust.delegatedSubject(). Nothing is delegated.");
      return { subject: '', element: '', tokenId: '' };
    }
    const element = oboEl ? 'OnBehalfOf' : 'ActAs';
    // PRODUCT: the token being delegated WITH must be an assertion this STS
    // issued and that is still valid — a bare UsernameToken or an unsigned
    // assertion inside <wst:OnBehalfOf> is a name anybody can type, and the
    // token this request asks for would be ABOUT that name. See
    // checkedAssertion().
    if (mode.verifiesCredentials()) {
      const inner = firstByLocal(obo, 'Assertion');
      if (!inner) {
        log.debug("Leaving WsTrust.delegatedSubject(). Product: no assertion " +
                  "to delegate with.");
        return { subject: '', element: element, tokenId: '',
                 errorCode: 'STS-WSTRUST-0008',
                 refused: 'The <wst:' + element + '> carries no SAML ' +
                          'assertion. In product mode a delegated subject ' +
                          'must be carried in an assertion this security ' +
                          'token service issued, because a name alone is not ' +
                          'evidence of anybody.' };
      }
      const checked = this.checkedAssertion(inner,
                                       'token inside <wst:' + element + '>');
      if (!checked.ok) {
        log.debug("Leaving WsTrust.delegatedSubject(). Product: the " +
                  "delegated token was refused.");
        return { subject: '', element: element, tokenId: '',
                 refused: checked.reason,
                 errorCode: checked.errorCode };
      }
      log.debug("Leaving WsTrust.delegatedSubject(). Product: " +
                checked.subject + " via " + element + ".");
      return { subject: checked.subject, element: element,
               both: !!(oboEl && actAsEl),
               tokenId: this.delegatedTokenId(obo) };
    }
    const nameId = firstByLocal(obo, 'NameID') ||
      firstByLocal(obo, 'NameIdentifier');
    const named = (nameId && (nameId.textContent || '').trim()) ||
      'delegated-subject';
    const tokenId = this.delegatedTokenId(obo);
    log.debug("Leaving WsTrust.delegatedSubject(). " + named + " via " +
              element + ".");
    return { subject: named, element: element, both: !!(oboEl && actAsEl),
             tokenId: tokenId };
  }

  // Who this request is from, who the token it asks for is about, and whether
  // the credential presented was accepted.
  //
  // TWO identities can be in one request and BOTH are recorded, which is the
  // part that used to be wrong: a request carrying a UsernameToken AND an
  // OnBehalfOf returned at the delegation branch before it had looked at the
  // UsernameToken, so the requester — the one party here that actually
  // presented a credential — was recorded nowhere and grew no directory entry.
  // The delegated subject is still what the token is ABOUT, and is still what
  // this returns as the subject.
  //
  // Every accepted credential goes through stats.recordAuthentication(), which
  // is this service's single authentication funnel: it is what the admin
  // console's users page counts, what the audit log writes an `authentication`
  // row from, and what the embedded LDAP directory grows a
  // `uid=<name>,ou=users` entry from. A path that accepts a credential without
  // calling it is a person who authenticated here and is in none of the three.
  private authenticate(doc) {
    const { stats, delegation, mode, log } = this.deps;
    log.debug("Entering WsTrust.authenticate().");
    const credential = this.requesterCredential(doc);
    if (credential && !credential.ok) {
      log.debug("Leaving WsTrust.authenticate(). The credential was refused.");
      return { ok: false, reason: credential.reason,
               errorCode: credential.errorCode };
    }
    if (credential) {
      stats.recordAuthentication({
        presented: credential.subject, protocol: 'WS-Trust',
        method: credential.method, note: credential.note
      });
    }
    const delegatedBy = this.delegatedSubject(doc);
    if (delegatedBy.refused) {
      log.debug("Leaving WsTrust.authenticate(). The delegated token was " +
                "refused.");
      return { ok: false, reason: delegatedBy.refused,
               errorCode: delegatedBy.errorCode };
    }
    const delegated = delegatedBy.subject;
    // PRODUCT: A DELEGATION NEEDS A REQUESTER. Development issues a token about
    // somebody for a request that presented no credential of its own — the gap
    // the delegation register draws on purpose. In product the requester is the
    // one party a delegation must be attributable to, so a request with nobody
    // in that seat is refused before anything is recorded.
    if (delegated && !credential && mode.verifiesCredentials()) {
      log.debug("Leaving WsTrust.authenticate(). Product: a delegation with " +
                "no requester credential.");
      return { ok: false, errorCode: 'STS-WSTRUST-0009',
               reason: 'This request delegates (<wst:' + delegatedBy.element +
                       '>) and presents no credential of its own. In product ' +
                       'mode the requester must authenticate — a WS-Security ' +
                       'UsernameToken, or a SAML assertion this security ' +
                       'token service issued — before a token about somebody ' +
                       'else is issued to it.' };
    }
    if (delegated) {
      // Recorded, with what it is said plainly: the subject named in an
      // OnBehalfOf presented no credential of their own here. Something else
      // asked for a token about them, and this service — which checks nothing —
      // agreed. The users page prints the method, so the row is not mistaken
      // for a sign-in.
      stats.recordAuthentication({
        presented: delegated, protocol: 'WS-Trust',
        method: 'OnBehalfOf / ActAs (delegated)',
        note: 'The requester named this subject; the subject presented ' +
              'nothing. This service accepts any delegation without checking ' +
              'who may perform it.'
      });
      log.debug("Leaving WsTrust.authenticate(). Delegated request " +
                "(OnBehalfOf/ActAs).");
      // `delegation` carries what /admin/delegation needs and nothing else
      // reads: WHICH element it was, and WHO presented a credential of their
      // own — the requester, who is the intermediary of the chain and is the
      // one party this function's `subject` deliberately does not name.
      // handleRst() records the act once the token exists; recording it here
      // would claim a credential that a later failure would have meant nobody
      // held.
      return {
        ok: true, subject: delegated, kind: 'delegated',
        delegation: {
          element: delegatedBy.element,
          both: !!delegatedBy.both,
          requester: credential ? credential.subject : '',
          requesterMethod: credential ? credential.method : '',
          // The identifier of the token that was delegated WITH, where it
          // carried one. handleRst() records it as what the act consumed, which
          // is what lets /admin/tokens/credential walk a chain of these hops
          // back to the sign-in that started it. See delegatedTokenId().
          tokenId: delegatedBy.tokenId || ''
        }
      };
    }
    if (credential) {
      log.debug("Leaving WsTrust.authenticate(). Accepted for " +
                credential.subject + ".");
      return { ok: true, subject: credential.subject, kind: credential.kind };
    }
    // PRODUCT: NO CREDENTIAL, NO TOKEN (2026-09-12). Everything below this line
    // is development's — and it is also what made a Renew with no credential
    // issue a token for whoever its RenewTarget named, because that branch in
    // handleRst() starts from the `anonymous` this returns. Refusing here
    // closes both, and Validate and Cancel with them: every operation
    // authenticates above the branch on the operation, which is this file's
    // rule.
    if (mode.verifiesCredentials()) {
      log.debug("Leaving WsTrust.authenticate(). Product: no credential was " +
                "presented.");
      return { ok: false, errorCode: 'STS-WSTRUST-0010',
               reason: 'No credential was presented. In product mode every ' +
                       'WS-Trust operation requires one in the wsse:Security ' +
                       'header — a WS-Security UsernameToken verified ' +
                       'against the directory, or a SAML assertion this ' +
                       'security token service issued.' };
    }
    // No credential — lenient (anonymous), so a "None" credential still issues.
    //
    // Deliberately NOT recorded as an authentication: no userid was presented,
    // so there is nothing to record. The assertion this issues names
    // `anonymous`, and the users page picks that up from the assertion instead
    // — as a subject something was issued to and who never authenticated, which
    // is exactly what happened.
    log.debug("Leaving WsTrust.authenticate(). No credential was presented; " +
              "treating as anonymous.");
    return { ok: true, subject: 'anonymous', kind: 'none' };
  }

  // ---------------------------------------------------------------------------
  // HOW THE REQUESTER AUTHENTICATED, AS THE SAML 2.0 CLASS THE ASSERTION STATES
  // (2026-09-12).
  //
  // The assertion this STS issued used to carry PasswordProtectedTransport for
  // every request — the builder's default, and nobody passed anything else — so
  // an ANONYMOUS request, a delegation and an exchanged assertion were all
  // signed as a password sign-in. That is wrong in every mode. Now:
  //
  //   UsernameToken    PasswordProtectedTransport, exactly as before
  //   SAML assertion   PreviousSession — "authenticated to an authentication
  //                    authority at some point in the past", which is precisely
  //                    what an assertion presented as a credential proves
  //   OnBehalfOf/ActAs unspecified: the subject presented nothing here
  //   nothing          unspecified
  // ---------------------------------------------------------------------------
  private authnContextOf(auth) {
    const { authnContext, log } = this.deps;
    log.debug("Entering WsTrust.authnContextOf().");
    if (auth && auth.kind === 'password') {
      log.debug("Leaving WsTrust.authnContextOf().");
      return authnContext.AC_PASSWORD_PROTECTED;
    }
    if (auth && auth.kind === 'assertion') {
      log.debug("Leaving WsTrust.authnContextOf().");
      return 'urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession';
    }
    log.debug("Leaving WsTrust.authnContextOf().");
    return authnContext.AC_UNSPECIFIED;
  }

  handleRst(rawBody, contentType, options) {
    const {
      config, validation, encryptAssertion, applications, gate, delegation,
      mode, errorCodes, log, xmlEscape, iso, firstByLocal, textByLocal,
      subjectForName, hasSubjectResolver
    } = this.deps;
    log.debug("Entering WsTrust.handleRst().");
    options = options || {};
    // ---------------------------------------------------------------------
    // **THIS PARSE ANSWERED 500 UNTIL 2026-09-06, TO AN EMPTY BODY AMONG OTHER
    // THINGS**, and the reason is a library change rather than carelessness.
    // `@xmldom/xmldom` used to report a malformed document by calling a handler
    // whose default wrote to the console and carried on, so a bare parse
    // returned a partial tree; in 0.9.10 the default handler THROWS a
    // ParseError. The bare parse here was outside any try/catch, so
    // `POST /sts` with `<a><b></a>` — or with nothing at all — took the request
    // down with an uncaught exception rather than answering a Fault.
    //
    // `validation.parseXml()` never throws; it answers a refusal, and this
    // endpoint renders it as the SOAP Fault it should always have been. The
    // version is detected from the CONTENT TYPE alone here, because there is no
    // document to read a namespace off.
    // ---------------------------------------------------------------------
    const read = validation.parseXml(rawBody, 'request');
    if (!read.ok) {
      log.debug("Leaving WsTrust.handleRst(). The request is not well-formed " +
                "XML.");
      return { status: 400, errorCode: 'STS-WSTRUST-0001',
               version: this.detectSoapVersion(null, contentType),
               body: this.soapFault(this.detectSoapVersion(null, contentType),
                               read.detail) };
    }
    const doc = read.value;
    const version = this.detectSoapVersion(doc, contentType);
    const requestType = textByLocal(doc, 'RequestType');
    // Operation from the LAST path segment of RequestType, so any WS-Trust
    // version's namespace works (2004/04, 2005/02, or ws-sx 200512).
    const op = requestType.split('/').pop().toLowerCase();
    // Echo the request's trust namespace in the response (whatever version the
    // client used); fall back to 200512.
    const rstEl = firstByLocal(doc, 'RequestSecurityToken');
    const trustNs = (rstEl && rstEl.namespaceURI) || WST_NS;
    const statusTokenType = trustNs + '/RSTR/Status';
    const statusValid = trustNs + '/status/valid';
    const statusInvalid = trustNs + '/status/invalid';
    const keyTypeReq = textByLocal(doc, 'KeyType') || (trustNs + '/Bearer');

    const tokenTypeReq = textByLocal(doc, 'TokenType');
    const appliesToEl = firstByLocal(doc, 'AppliesTo');
    const audience = appliesToEl ?
                     (textByLocal(appliesToEl, 'Address') ||
                      (appliesToEl.textContent || '').trim()) : '';
    // THE LIFETIME (2026-09-12). The default was the literal 60 and is
    // `wstrust.tokenLifetimeMin`. A requested wst:Lifetime REPLACED it with no
    // bound at all, so a caller could ask for a token valid for a year and get
    // one — and WS-Trust 1.4 section 4.1 is explicit that the requestor's
    // Lifetime is a REQUEST and the issued one is the STS's decision, returned
    // in the RSTR. That makes an unbounded honour a defect in every mode rather
    // than a mock's leniency, so the clamp to `wstrust.maxTokenLifetimeMin`
    // applies in development too. What went out is what the RSTR's own
    // wst:Lifetime says below, so a client can see it was shortened.
    const lifetimeEl = firstByLocal(doc, 'Lifetime');
    const maxLifetimeMin = Number(config.value('wstrust.maxTokenLifetimeMin'));
    let lifetimeMin = Math.min(Number(config.value('wstrust.tokenLifetimeMin')),
                               maxLifetimeMin);
    if (lifetimeEl) {
      const created = textByLocal(lifetimeEl, 'Created');
      const expires = textByLocal(lifetimeEl, 'Expires');
      if (created && expires) {
        const diff = (Date.parse(expires) - Date.parse(created)) / 60000;
        if (diff > 0) {
          lifetimeMin = Math.max(1, Math.round(diff));
          if (lifetimeMin > maxLifetimeMin) {
            log.info('wstrust: the request asked for a ' + lifetimeMin +
                     '-minute ' +
                     'token; it is issued for ' +
                     'wstrust.maxTokenLifetimeMin, ' + maxLifetimeMin + ' ' +
                         'minutes.');
            lifetimeMin = maxLifetimeMin;
          }
        }
      }
    }

    // EVERY operation authenticates, and it happens here — above the four
    // branches rather than inside two of them.
    //
    // Validate and Cancel used to return before this line was reached, so a
    // UsernameToken presented to either was accepted (the operation answered
    // 200) and recorded nowhere: the requester appeared in neither the admin
    // console's users page, nor the audit log, nor the embedded LDAP directory,
    // which grows its `uid=<name>,ou=users` entry off the same funnel. Half of
    // this endpoint's operations authenticated nobody.
    //
    // It also means the reserved password "invalid" now refuses a Validate and
    // a Cancel the way it already refused an Issue and a Renew, which is the
    // answer a client should get: a credential this service rejects does not
    // become acceptable because of what was asked with it.
    const auth: any = this.authenticate(doc);
    if (!auth.ok) {
      log.debug("Leaving WsTrust.handleRst(). Authentication failed, " +
                "answering with a SOAP Fault.");
      // error-code: none — the code was decided where authenticate() refused, and rides out on auth.errorCode
      return { status: 500, version: version, errorCode: auth.errorCode,
               body: this.soapFault(version,
                               auth.reason || 'Authentication failed.') };
    }

    if (op === 'validate') {
      const target = firstByLocal(doc, 'ValidateTarget');
      const hasToken = target &&
                       (firstByLocal(target, 'Assertion') ||
                        firstByLocal(target, 'BinarySecurityToken') ||
                        (target.textContent || '').trim());
      const code = hasToken ? statusValid : statusInvalid;
      // A wst:Status of invalid is this operation's refusal, delivered in a
      // 200.
      const invalidCode = hasToken ? '' : 'STS-WSTRUST-0014';
      const reason = hasToken ? 'The token is valid.' : 'No token to validate.';
      const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs +
                   '"><wst:TokenType>' + statusTokenType +
                   '</wst:TokenType><wst:Status><wst:Code>' + code +
                   '</wst:Code><wst:Reason>' + xmlEscape(reason) +
                   '</wst:Reason></wst:Status>' +
                   '</wst:RequestSecurityTokenResponse>';
      log.debug("Leaving WsTrust.handleRst(). Validate answered with " +
                "wst:Status.");
      return { status: 200, version: version, errorCode: invalidCode,
               body: this.envelope(version, trustNs + '/RSTR/ValidateFinal',
                                   rstr) };
    }

    if (op === 'cancel') {
      const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs +
                   '"><wst:RequestedTokenCancelled/>' +
                   '</wst:RequestSecurityTokenResponse>';
      log.debug("Leaving WsTrust.handleRst(). Cancel answered with " +
                "wst:RequestedTokenCancelled.");
      return { status: 200, version: version,
               body: this.envelope(version, trustNs + '/RSTR/CancelFinal',
                                   rstr) };
    }

    // Issue / Renew both mint (or re-mint) a token, for whoever authenticate()
    // above says this request is about.
    //
    // The one thing that answer does not cover is a Renew sent with NO
    // credential at all: the requester is anonymous, but the token being
    // renewed names somebody, and a renewal that came back about `anonymous`
    // would have thrown away the only subject in the exchange. So the
    // RenewTarget's own NameID is read for the SUBJECT — and only for the
    // subject. It is not an authentication and is not recorded as one: the
    // token said it, nobody presented it. A Renew that DID authenticate keeps
    // its own subject, which is what a service renewing a token in its own name
    // should get.
    let subject = auth.subject;
    if (op === 'renew' && subject === 'anonymous') {
      const renewTarget = firstByLocal(doc, 'RenewTarget');
      const renewNameId = renewTarget && (firstByLocal(renewTarget, 'NameID') ||
        firstByLocal(renewTarget, 'NameIdentifier'));
      const renewNamed = renewNameId ?
        (renewNameId.textContent || '').trim() : '';
      if (renewNamed) {
        log.debug("An unauthenticated Renew; the subject is the one the " +
                  "RenewTarget names, " + renewNamed + ".");
        subject = renewNamed;
      }
    }
    // THE ROLE GATE, and this is the one issuance site here where the
    // application may be ABSENT and that is not an error. AppliesTo is optional
    // in an RST, and a token with no audience restriction is a state this
    // service deliberately allows — so there is no application to have a
    // requirement, and `issuance_gate.check()` answers "allowed" for a call
    // that names none. Its header says why that is the honest answer rather
    // than a hole: this service issues nothing to nobody, so a call with no
    // application is a caller that does not know who it is serving.
    //
    // THE SUBJECT MAY BE `anonymous`, which is this protocol's own word and not
    // a missing value — a Renew with no credential is renewing somebody else's
    // token. `authenticated` follows the credential and not the name, so an
    // anonymous Renew is decided as an unauthenticated subject and can be
    // refused by ALL_UNAUTHENTICATED_USERS, which is the one place in this
    // service besides the sign-in screen where that role means anything.
    //
    // A REFUSAL IS A SOAP FAULT, because that is the only answer this protocol
    // has: an RST is answered with an RSTR or with a Fault, and an RSTR
    // carrying no token would be a success that issued nothing.
    const roleAnswer = gate.check({
      application: audience,
      kind: gate.ISSUANCE.WSTRUST_TOKEN,
      subject: { kind: 'user', name: String(subject || ''),
                 authenticated: subject !== 'anonymous' },
      claims: null
    });
    if (!roleAnswer.allowed) {
      log.info('wstrust: the issuance policy refused a token for "' +
               String(subject) + '" to "' + audience + '". ' + roleAnswer.why);
      log.debug("Leaving the RST handler. The issuance policy refused it.");
      return { status: 403, version: version, errorCode: 'STS-WSTRUST-0011',
               body: this.soapFault(version, roleAnswer.why) };
    }

    const tokenType = (tokenTypeReq === JWT_TOKEN_TYPE) ? JWT_TOKEN_TYPE :
                       SAML2_TOKEN_TYPE;
    // A JWT'S `sub` IS A SUBJECT, AND THERE IS NONE WITHOUT AN ENTRY — the rule
    // the OAuth 2.0 grants follow (`STS-OAUTH-0510`). An `anonymous` Renew
    // names nobody by design and is left to the paragraph above.
    if (tokenType === JWT_TOKEN_TYPE && subject !== 'anonymous' &&
        hasSubjectResolver() && !subjectForName(subject)) {
      log.info('wstrust: refused a JWT for "' + String(subject) + '": the ' +
               'directory holds no entry for them, so there is no subject to ' +
               'issue it about.');
      log.debug("Leaving the RST handler. No subject for the JWT.");
      return { status: 400, version: version, errorCode: 'STS-WSTRUST-0017',
               body: this.soapFault(version, 'There is no directory entry ' +
                                             'for "' +
                               String(subject) + '", so no JWT can be issued ' +
                               'about them.') };
    }
    const tok = this.buildToken(tokenType, subject, audience, lifetimeMin,
                           this.authnContextOf(auth));

    // Optional encryption (?encrypt=1): encrypt the SAML assertion to the
    // recipient certificate carried in the request's WS-Security signature
    // (X509Data).
    //
    // TWO CHANGES ON 2026-09-12. The algorithms are `saml2.encryptionAlgorithm`
    // and `saml2.keyTransportAlgorithm`, answered for the AppliesTo as
    // `/saml2` answers them for a service provider — they were passed nowhere
    // and the cipher's own defaults decided, so the settings a console page
    // said were in force did nothing to a WS-Trust assertion. And a FAILURE is
    // a refusal in product mode: development returns the plaintext and logs it,
    // because a mock that stopped issuing when a certificate was missing is
    // useless while somebody sets this up; product returns a SOAP Fault
    // instead, because an assertion the caller asked to have encrypted crossing
    // the wire readable is the one outcome the flag exists to prevent. The
    // predicate is `sendsWeakerThanAsked()`: what a response may lose on the
    // way out, which is the question here, rather than who may drive a test
    // control.
    if (options.encrypt && tok.tokenType === SAML2_TOKEN_TYPE) {
      const x509 = firstByLocal(doc, 'X509Certificate');
      const recipB64 = x509 ? (x509.textContent || '').replace(/\s+/g, '') : '';
      let failure = '';
      if (recipB64) {
        const recipPem = '-----BEGIN CERTIFICATE-----\n' +
            (recipB64.match(/.{1,64}/g) || []).join('\n') + '\n-----END ' +
            'CERTIFICATE-----\n';
        const how = {
          algorithm: String(applications.settingFor(audience || '',
                                                    'saml2.encryptionAlgorithm',
                                                    config) || ''),
          keyTransport: String(applications.settingFor(
            audience || '', 'saml2.keyTransportAlgorithm', config) || '')
        };
        try {
          tok.xml = encryptAssertion(tok.xml, recipPem, how);
          tok.ref = '';
        } catch (e) {
          failure = 'the assertion could not be encrypted to the certificate ' +
                    'in the request: ' +
                    e.message;
        }
      } else {
        failure = '?encrypt=1 was requested and the request carries no ' +
                  'recipient certificate (no X509Certificate in its ' +
                  'WS-Security signature)';
      }
      if (failure) {
        if (!mode.sendsWeakerThanAsked()) {
          log.info('wstrust: refused to return a plaintext assertion — ' +
                   failure + '.');
          log.debug("Leaving WsTrust.handleRst(). Encryption was required " +
                    "and did not happen.");
          return { status: 500, version: version,
                   errorCode: recipB64 ? 'STS-WSTRUST-0013'
                                       : 'STS-WSTRUST-0012',
                   body: this.soapFault(version,
                                   'Encryption was requested and ' + failure +
                                            '. In product mode the assertion ' +
                                            'is not returned in clear ' +
                                            'instead.') };
        }
        log.error(errorCodes.tag(recipB64 ? 'STS-WSTRUST-0013' :
                                 'STS-WSTRUST-0012') +
                  failure + '; returning plaintext.');
      }
    }
    // THE RELYING PARTY. AppliesTo is WS-Trust's name for the service a token
    // is being issued FOR, and this is where one is about to be. It is optional
    // in an RST — a token with no AppliesTo has no audience restriction, which
    // is a state this service deliberately allows — so an absent one records
    // nothing rather than an empty application.
    //
    // The SECOND kind is the mirror of wsfed.ts's: where the token issued is a
    // SAML 2.0 assertion, this AppliesTo is also its audience, which is exactly
    // what `saml2-service-provider` is defined as in KINDS. Recording only the
    // WS-Trust kind left that one reachable through WS-Federation alone, so the
    // console's filter answered "no SAML 2.0 service providers" for a service
    // that had just issued one. A JWT gets no second kind — there is no row for
    // it, and inventing a spelling here is how one application comes to be
    // listed under two.
    if (audience) {
      applications.seen({
        identifier: audience,
        kind: tok.tokenType === SAML2_TOKEN_TYPE
          ? ['wstrust-relying-party', 'saml2-service-provider']
          : 'wstrust-relying-party',
        protocol: 'WS-Trust',
        user: subject || '',
        note: 'a token was issued for this AppliesTo',
        fields: { wstrustAppliesTo: audience, samlEntityId: audience }
      });
    }

    // -------------------------------------------------------------------------
    // THE DELEGATION ACT, for /admin/delegation.
    //
    // Recorded here rather than in authenticate() for the reason the KDC
    // records its own at the bottom of handleTgsReq(): this is the first line
    // at which the token EXISTS, and an act recorded where the decision was
    // made would name a credential nobody ever held. It is also the only place
    // that knows the AppliesTo, which is the TARGET of the chain —
    // authenticate() reads the security header and never sees it.
    //
    // Nothing about this is a check. This service accepts any delegation from
    // anybody about anybody, and the row says so in the column where a Kerberos
    // row names an attribute. That asymmetry is the most useful thing on the
    // page: the same picture, policed at one end and not at the other.
    // -------------------------------------------------------------------------
    if (auth.delegation) {
      const via = auth.delegation.element;
      // -----------------------------------------------------------------------
      // WHICH APPLICATION THE AppliesTo IS, when one has registered it.
      //
      // The same resolution the token endpoint performs for an RFC 8693
      // `audience`, arriving through a different protocol, and it is here for
      // the same reason: this string names a SERVICE —
      // `https://esb.example.com` — and the register is keyed by the identifier
      // an application PRESENTS. An act filed under the URI draws a box on
      // /admin/delegation/map that nothing else in the picture mentions, so a
      // two-hop chain through a middle tier comes out as two unconnected
      // halves: the AppliesTo the first hop asked for and the name the second
      // hop authenticated AS are one application under two names.
      //
      // NOTHING IS REFUSED. An AppliesTo nobody registered resolves to null and
      // is recorded verbatim, exactly as it was before this existed — and the
      // raw string stays in the sentence beside the target either way, because
      // what was asked for is a fact about the request and must not be lost to
      // a resolution. See applications.forAppliesTo().
      // -----------------------------------------------------------------------
      const targetApplication = audience ? applications.forAppliesTo(audience)
                                         : null;
      if (targetApplication) {
        log.debug('the AppliesTo "' + audience + '" is registered to ' +
                  'application "' + targetApplication.identifier + '" on ' +
                  targetApplication.matchedAttribute + ', so the delegation ' +
                  'is recorded against that application rather than against ' +
                  'the URI.');
      }
      // AND WHETHER THE REQUESTER IS ONE TOO. The middle tier of a WS-Trust
      // chain authenticates with a credential rather than by naming an
      // application, so `presented` is where it belongs and is what the picture
      // keys the box on. But an ESB asking for a token to reach a back end IS
      // an application, and where this registry already holds an entry under
      // that name the act says so: the box then links to the entry and is drawn
      // as a service rather than as a person. A LOOKUP and not a claim — an
      // unknown name leaves the slot empty, exactly as before.
      const requesterApplication = auth.delegation.requester
        ? applications.get(auth.delegation.requester) : null;
      delegation.record({
        protocol: 'WS-Trust',
        type: via === 'ActAs' ? 'wstrust-actas' : 'wstrust-onbehalfof',
        outcome: 'issued',
        initial: {
          presented: subject,
          what: 'the subject named in <wst:' + via + '>, who presented ' +
                                                     'nothing here'
        },
        intermediary: {
          // Empty where the request presented no credential of its own, which
          // is allowed here and is worth seeing: an ANONYMOUS requester asked
          // for a token about somebody else and got one. The page draws that as
          // a gap in the chain rather than as a missing value.
          presented: auth.delegation.requester,
          application: requesterApplication ? requesterApplication.identifier :
                       '',
          what: auth.delegation.requester
            ? 'the requester, authenticated by ' +
              auth.delegation.requesterMethod +
              (requesterApplication
                ? ', and an application in this registry'
                : '')
            : 'nobody — the request presented no credential of its own, and ' +
              'this service issued the token anyway'
        },
        target: {
          application: targetApplication ? targetApplication.identifier :
                       audience,
          what: audience
            ? (targetApplication
                ? 'the application registered for the AppliesTo "' + audience +
                  '" on ' + targetApplication.matchedAttribute + ', which is ' +
                  'also the assertion\'s audience. The request named the ' +
                  'service; this registry named the application'
                : 'the AppliesTo, which is also the assertion\'s audience. ' +
                  'No application here has registered it, so it is recorded ' +
                  'exactly as it was asked for')
            : 'unstated — the RST carried no AppliesTo, so the token issued ' +
              'has no audience restriction at all'
        },
        authorizedBy: 'nothing. WS-Trust puts no authorization on ' +
                      '<wst:' + via + '> and this service adds none: any ' +
                      'requester may ask for a token about anybody. A real ' +
                      'STS decides this from policy that has no place in the ' +
                      'message.',
        consumed: (auth.delegation.requester
          ? [{ kind: 'WS-Security credential',
               note: auth.delegation.requesterMethod }]
          : [] as any[]).concat(auth.delegation.tokenId
          ? [{ kind: 'delegated token',
               identifier: auth.delegation.tokenId,
               note: 'the token inside <wst:' + via + '>, which is what this ' +
                     'request is delegating WITH. Its signature and ' +
                     'Conditions are not checked; the identifier is read so ' +
                     'that the lineage of what came out can be followed back ' +
                     'through it' }]
          : []),
        produced: [{
          kind: tok.tokenType === SAML2_TOKEN_TYPE ? 'SAML 2.0 assertion'
                                                   : 'JWT',
          identifier: tok.id || '',
          note: tok.id
            ? (tok.tokenType === SAML2_TOKEN_TYPE ? 'AssertionID' : 'jti')
            : 'this token carries no identifier'
        }],
        note: auth.delegation.both
          ? 'The request carried BOTH <wst:OnBehalfOf> and <wst14:ActAs>. ' +
            'OnBehalfOf is what this act is attributed to, which is the ' +
            'order this service has always read them in.'
          : (via === 'ActAs'
              ? 'ActAs is COMPOSITE: the far end is meant to be able to see ' +
                'that a middle tier is acting. Nothing in the token this ' +
                'service issues carries that, which is a gap in the mock ' +
                'rather than in the profile.'
              : 'OnBehalfOf is IMPERSONATION: the assertion names the ' +
                'subject and says nothing about the requester, so the ' +
                'relying party sees an ordinary sign-in.')
      });
    }

    const appliesToOut = audience
      ? '<wsp:AppliesTo ' +
        'xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" ' +
        'xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
        '<wsa:EndpointReference><wsa:Address>' +
        xmlEscape(audience) +
        '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'
      : '';
    const rstrInner =
      '<wst:TokenType>' + tok.tokenType + '</wst:TokenType>' +
      '<wst:RequestedSecurityToken>' + tok.xml +
      '</wst:RequestedSecurityToken>' +
      appliesToOut +
      '<wst:Lifetime ' +
      'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
      '<wsu:Created>' + iso(0) + '</wsu:Created><wsu:Expires>' +
      iso(lifetimeMin) + '</wsu:Expires></wst:Lifetime><wst:KeyType>' +
      keyTypeReq + '</wst:KeyType>' +
      tok.ref;

    // ---------------------------------------------------------------------
    // WHAT THIS EXCHANGE SIGNED IN, for the caller to act on (2026-09-05).
    //
    // **AN ISSUED CREDENTIAL IMPLIES A SESSION THIS SERVICE TRACKS**, and until
    // this day WS-Trust was the one family here that issued one and tracked
    // nothing: `startSession()` was called zero times in this file. What that
    // cost was not visible from inside this endpoint — it answered correctly
    // and always had — but from `/admin/sessions` and from a global sign-out,
    // where an assertion this service had minted for somebody five minutes ago
    // belonged to nobody who was signed in. An identity provider that cannot
    // say "this is live" cannot say "I have ended it" either, which is the
    // whole of what a sign-out is.
    //
    // IT IS RETURNED RATHER THAN DONE HERE, and that is deliberate: this
    // function has no `res` and must not acquire one. It is called by the route
    // below AND directly by callers that hand it a body and read a body back,
    // so a cookie written from inside it would be a side effect on an object
    // half its callers do not have. The route starts the session; this says
    // who.
    //
    // ONLY ON AN ISSUE THAT AUTHENTICATED. A Renew whose requester was
    // anonymous is signing nobody in — its subject came off the RenewTarget,
    // which the token said and nobody presented — and Validate and Cancel issue
    // nothing at all. Each of those returns above this line.
    //
    // AND NEVER ON A DELEGATION (2026-09-12). `auth.subject` on an OnBehalfOf /
    // ActAs request is the DELEGATED subject — the person who presented nothing
    // — so this used to start a browser session in the name of somebody who was
    // not there, with amr ["pwd"], on the response to whoever asked. That is
    // wrong in every mode: the requester authenticated and the subject did not,
    // and a session is a statement that its subject signed in. The requester is
    // not signed in either — the token is about somebody else — so nothing is.
    //
    // THE AMR SAYS WHICH CREDENTIAL IT WAS. `pwd` for a UsernameToken, as
    // before; nothing for a SAML assertion, which is evidence of an earlier
    // sign-in elsewhere rather than of a password presented now.
    const signIn = auth.subject && auth.subject !== 'anonymous' &&
                   auth.kind !== 'delegated'
      ? { username: auth.subject, method: auth.method || 'WS-Trust',
          via: 'WS-Trust ' + op,
          amr: auth.kind === 'assertion' ? [] : ['pwd'] }
      : null;

    if (op === 'renew') {
      const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs +
                   '">' + rstrInner + '</wst:RequestSecurityTokenResponse>';
      log.debug("Leaving WsTrust.handleRst(). Renew answered with a fresh " +
                "token.");
      return { status: 200, version: version, signIn: signIn,
               body: this.envelope(version, trustNs + '/RSTR/RenewFinal',
                                   rstr) };
    }

    // Issue -> RSTR Collection (WS-Trust 1.3+; pre-OASIS clients tolerate it
    // too).
    const rstrc = '<wst:RequestSecurityTokenResponseCollection xmlns:wst="' +
                  trustNs + '"><wst:RequestSecurityTokenResponse>' + rstrInner +
                  '</wst:RequestSecurityTokenResponse>' +
                  '</wst:RequestSecurityTokenResponseCollection>';
    log.debug("Leaving WsTrust.handleRst(). Issue answered with an RSTR " +
              "Collection.");
    return { status: 200, version: version, signIn: signIn,
             body: this.envelope(version, trustNs + '/RSTRC/IssueFinal',
                                 rstrc) };
  }

  // **`no-store`, LIKE EVERY OTHER DOCUMENT HERE THAT DESCRIBES A KEY.** In
  // development mode this certificate is made when the process starts and is
  // thrown away when it stops — the root CLAUDE.md's *Signing keys, and any
  // document that publishes one* — so a cached copy outlives the key it names,
  // and a client that re-read it from a proxy would be checking this service's
  // signatures against the certificate of a service that is no longer running.
  // It was the ONE metadata document in this service served without the header,
  // which tests/vendored/sts_metadata_anonymous.js found by asking the same
  // question of all nineteen of them at once.
  private stsCertEndpoint(req, res) {
    const { log, STS } = this.deps;
    log.debug("Entering the STS certificate endpoint.");
    // The XML signing key's certificate (#42, D2): what signs the SAML
    // assertions this STS issues.
    res.type('text/plain').set('Cache-Control', 'no-store')
       .send(STS.xml.certPem);
    log.debug("Leaving the STS certificate endpoint.");
  }

  // ---------------------------------------------------------------------------
  // THE TWO NAMES THIS STS SIGNS UNDER, AND WHETHER THEY AGREE (2026-09-12).
  //
  // A JWT from this endpoint is issued by `wstrust.issuer`; a SAML assertion
  // from it is issued by `saml.issuer`, because the SAML builder reads that.
  // The split is deliberate (config.js argues it) and the two default to one
  // string — but a relying party configured with one and handed a token under
  // the other refuses it as coming from an unknown issuer, and nothing said the
  // two had drifted. So GET /sts says so for the realm it is asked in, and the
  // process logs it once at startup for the process-wide values. It is reported
  // rather than reconciled, because making one follow the other would take away
  // the split.
  // ---------------------------------------------------------------------------
  issuerDisagreement() {
    const { config, log } = this.deps;
    log.debug("Entering WsTrust.issuerDisagreement().");
    const jwtIssuer = String(config.value('wstrust.issuer') || '');
    const samlIssuer = String(config.value('saml.issuer') || '');
    if (jwtIssuer === samlIssuer) {
      log.debug("Leaving WsTrust.issuerDisagreement().");
      return '';
    }
    log.debug("Leaving WsTrust.issuerDisagreement().");
    return 'wstrust.issuer ("' + jwtIssuer + '") and saml.issuer ("' +
           samlIssuer + '") differ: a JWT from this STS names the first as ' +
           'its iss and a SAML assertion from it names the second as its ' +
           'Issuer, so a relying party configured with one will refuse the ' +
           'other token type.';
  }

  private stsDescriptionEndpoint(req, res) {
    const { config, log } = this.deps;
    log.debug("Entering the STS description endpoint.");
    const disagreement = this.issuerDisagreement();
    res.type('text/plain').send('WS-Trust STS mock. POST a SOAP ' +
                                'RequestSecurityToken here.\nIssuer: ' +
                                config.value('wstrust.issuer') + '\n' +
                                (disagreement ?
                                 'WARNING: ' + disagreement + '\n' : ''));
    log.debug("Leaving the STS description endpoint.");
  }

  // -------------------------------------------------------------------------
  // THE PERSON'S RISK STANDING, READ BEFORE THE EXCHANGE (#62 P3). An RST
  // rests on no session, so the issuance policy's risk facts are the
  // person's standing — and `handleRst()` asks the gate synchronously, so the
  // standing is read from the store HERE, first, for the name the request
  // CLAIMS (a UsernameToken's Username). Nothing is authenticated by it and
  // nothing is decided: a name that turns out not to authenticate simply
  // left a standing in this process's cache. Never rejects; a store that
  // cannot answer leaves the decision to roles alone.
  // -------------------------------------------------------------------------
  private stsEndpoint(req, res) {
    const { log, validation, textByLocal, subjectForName } = this.deps;
    log.debug("Entering WsTrust.stsEndpoint().");
    const self = this;
    let claimed = '';
    const read = validation.parseXml(req.body || '', 'request');
    if (read.ok) {
      claimed = textByLocal(read.value, 'Username');
    }
    let preload: Promise<unknown> = Promise.resolve(null);
    if (claimed) {
      try {
        const sub = String(subjectForName(claimed) || '');
        preload = sub ? require('../risk/risk_engine').loadStanding(
          require('../common/realms').currentId(), claimed, sub)
          : preload;
      } catch (e) {
        log.debug("Caught in WsTrust.stsEndpoint(): " +
                  ((e && e.message) || e));
        // No risk engine in this process: nothing to read, and the roles
        // decide.
        preload = Promise.resolve(null);
      }
    }
    log.debug("Leaving WsTrust.stsEndpoint().");
    return preload.then(function (): unknown {
      return self.stsEndpointNow(req, res);
    }, function (e: any): unknown {
      log.debug("Caught in WsTrust.stsEndpoint(): " + ((e && e.message) || e));
      // loadStanding() never rejects; this is its belt and braces.
      return self.stsEndpointNow(req, res);
    });
  }

  private stsEndpointNow(req, res) {
    const { authn, errorCodes, log } = this.deps;
    log.debug("Entering the WS-Trust STS endpoint.");
    const contentType = req.headers['content-type'] || '';
    try {
      const encrypt = req.query.encrypt === '1' || req.query.encrypt === 'true';
      const result = this.handleRst(req.body || '', contentType,
                                    { encrypt: encrypt });
      // THE SESSION, IF THE EXCHANGE MADE ONE. See handleRst()'s note on
      // `signIn` for why the decision is made there and the act is performed
      // here.
      //
      // The cookie goes out on a SOAP response and almost no WS-Trust client
      // will keep it, which is fine and is not what it is for: what matters is
      // the session RECORD, so that `/admin/sessions` can show that this person
      // is signed in and a global sign-out can end it. A browser-based client
      // that does keep the cookie gets single sign-on across to every other
      // protocol here, which is the same thing every other family already gives
      // it.
      if (result.signIn) {
        try {
          // `request` so a UsernameToken exchange from a BROWSER replaces
          // whatever session it was on. A SOAP client sends no cookie, so this
          // ends nothing for the ordinary caller — which is right.
          //
          // A NULL MEANS THE ISSUANCE POLICY REFUSED THE SESSION (2026-09-06),
          // and it is deliberately NOT a refusal of the exchange. The token was
          // already built and the caller is entitled to it — handleRst() asked
          // the gate in its own right, with `gate.ISSUANCE.WSTRUST_TOKEN`, and
          // that is the decision about what this endpoint
          // issues. This one is about the browser SESSION a UsernameToken
          // exchange also starts, which is a side effect of the exchange rather
          // than its product. Refusing the RSTR here would refuse a credential
          // the policy had already permitted.
          const signedIn = authn.startSession(res, result.signIn.username,
                                              result.signIn.amr || ['pwd'], '1',
                                              result.signIn.via,
                                              { request: req });
          if (!signedIn) {
            log.info('ws-trust: the token was issued and the issuance policy ' +
                     'refused the browser SESSION for ' +
                     result.signIn.username + '. The RSTR is unaffected: the ' +
                     'token was permitted in its own right.');
          }
        } catch (e) {
          // Bookkeeping must never break an exchange that has already succeeded
          // — the token is built, the caller is entitled to it, and a session
          // this service failed to record is a gap in a console page rather
          // than a reason to answer a SOAP Fault.
          log.error(errorCodes.tag('STS-WSTRUST-0016') +
                    'wstrust: starting a session for ' +
                    result.signIn.username +
                    ' failed and was ignored; the token is unaffected: ' +
                    e.message);
        }
      }
      const ct = result.version === '1.1' ? 'text/xml; charset=utf-8' :
                 'application/soap+xml; ' +
          'charset=utf-8';
      if (result.errorCode) {
        errorCodes.mark(res, result.errorCode);
      }
      res.status(result.status).type(ct).send(result.body);
      log.debug("Leaving the WS-Trust STS endpoint. HTTP " + result.status +
                ".");
    } catch (e) {
      log.error(errorCodes.tag('STS-WSTRUST-0015') + 'STS error: ' +
                (e && e.stack ? e.stack : e));
      errorCodes.mark(res, 'STS-WSTRUST-0015');
      res.status(500).type('application/soap+xml; charset=utf-8')
         .send(this.soapFault('1.2',
                         'STS error: ' +
                         (e && e.message ? e.message : String(e))));
      log.debug("Leaving the WS-Trust STS endpoint. It failed.");
    }
  }

  // The startup half of issuerDisagreement(), once, for the process-wide
  // values.
  warnAtStartup(): void {
    const { log } = this.deps;
    log.debug("Entering WsTrust.warnAtStartup().");
    const disagreement = this.issuerDisagreement();
    if (disagreement) {
      log.warn('wstrust: ' + disagreement);
    }
    log.debug("Leaving WsTrust.warnAtStartup().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<WsTrust>(
  'ws-trust/wstrust',
  () => new WsTrust(WsTrust.defaultDeps()),
  WsTrust.wire,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  WsTrust: WsTrust,
  installInstance: (instance: WsTrust): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  handleRst: slot.forward('handleRst'),
  issuerDisagreement: slot.forward('issuerDisagreement'),
  checkedAssertion: slot.forward('checkedAssertion'),
  buildToken: slot.forward('buildToken'),
  soapFault: slot.forward('soapFault')
};
