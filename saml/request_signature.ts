'use strict';
//
// File: request_signature.ts
//
// ===========================================================================
// WHETHER A SAML 2.0 SERVICE PROVIDER'S REQUEST IS SIGNED BY THAT SERVICE
// PROVIDER (2026-09-17, #37).
//
// **THIS FILE REVERSES A DOCUMENTED NON-GOAL.** Until 2026-09-17 the root
// `CLAUDE.md` listed "verify a SAML AuthnRequest's signature, or consume SP
// metadata — both recorded, neither checked" among the things this service
// deliberately does not do, and `saml2_sso.ts`'s decision 3 argued it: the
// fact that a request was signed was recorded, the certificate off its
// `ds:KeyInfo` was written onto the application entry, and nothing was
// checked. rcbj's direction on #37 was that the list of things this project
// does not do is being eliminated. What follows is the check.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS, and each is the one somebody will propose undoing.
//
// 1. **A SIGNATURE THAT IS PRESENT IS VERIFIED IN EVERY MODE.** "Verify when a
//    certificate is known" is rcbj's rule, and it is not a mode: a request
//    whose signature does not verify against the service provider's
//    registered certificate is either tampered with or signed by somebody
//    else, and a development-mode service that forwarded it anyway would tell
//    the person testing their service provider that its signing works when it
//    does not. It is refused (`STS-SAML-0061`), and so is one this service
//    cannot check at all — an algorithm it has no verifier for, a reference
//    that names something other than the request, inclusive canonicalization
//    (`STS-SAML-0062`, `STS-SAML-0064`): a signature that cannot be checked is
//    not accepted as though it were absent.
//
// 2. **THE TRUST ANCHOR IS THE REGISTERED CERTIFICATE AND NEVER THE ONE IN THE
//    REQUEST.** `samlSigningCertificate` on the entry — written by consuming
//    the service provider's metadata, by an operator on the SAML 2.0 page or
//    `/admin-api`, or by confirming an observed one — and nothing else. The
//    certificate a request carries in `ds:KeyInfo` is RECORDED as
//    `samlObservedSigningCertificate` and verifies nothing: anybody can sign a
//    request and attach the key that verifies it, which is exactly what
//    `federation/federation_sp.ts` says of a partner's assertion and why
//    `common/crypto.js`'s verifier is always handed `certPem` here — its
//    fallback to the document's own certificate is unreachable from this
//    file. The one IMPLICIT anchor is this service's own certificate for its
//    own mock service provider (`/saml2/sp`), which signs with this service's
//    key: only this process holds that key, so trusting it for that one
//    entityID lets nothing in that this process did not sign.
//
// 3. **WITH NO REGISTERED CERTIFICATE A SIGNATURE IS RECORDED, NOT
//    VERIFIED** (`no-certificate`), which is where every service provider
//    starts in development. It counts as UNSIGNED for decision 4, because a
//    signature nobody checked is not evidence of anything.
//
// 4. **WHETHER A SIGNATURE MAY BE ABSENT IS A SETTING WITH A MODE DEFAULT.**
//    `saml2.requireSignedAuthnRequests` — `auto` (off in development, on in
//    product through `mode.acceptsUnsignedSamlRequests()`), `on`, `off` — and
//    a service provider whose consumed metadata says
//    `AuthnRequestsSigned="true"` is held to its own word whatever the
//    setting says. The same answer governs a LogoutRequest and a
//    LogoutResponse arriving from the service provider:
//    saml-profiles-2.0-os section 4.4.3.1 requires a logout message to be
//    authenticated, and a service provider that signs its AuthnRequests signs
//    its logout messages with the same key.
//
// ---------------------------------------------------------------------------
// THE TWO BINDINGS SIGN DIFFERENT THINGS, AND THAT IS THE WHOLE OF THE
// MECHANICS.
//
//   HTTP Redirect  a DETACHED signature over the octets
//                  `SAMLRequest=…&RelayState=…&SigAlg=…` (or SAMLResponse),
//                  in that order, built from the parameters EXACTLY AS THEY
//                  ARRIVED — still URL-encoded (saml-bindings-2.0-os section
//                  3.4.4.1). Re-encoding the decoded values would fail every
//                  signature from a service provider whose percent-encoding is
//                  not node's, so the raw query string is read here, off
//                  `req.originalUrl`, and never `req.query`. RelayState is in
//                  the octets when the parameter is present.
//   HTTP POST      an ENVELOPED `ds:Signature` as a direct child of the
//                  request's root element, whose reference names that
//                  element's ID. `common/crypto.js`'s `verifyXmlSignature()`
//                  is told the element, so a signature on some other element
//                  — the signature-wrapping attack — says nothing about the
//                  request and is refused.
//
// A request on the Redirect binding that carries an enveloped signature and no
// `Signature` parameter is checked as the POST binding would be: section
// 3.4.4.1 says the XML signature is to be removed, and a service provider that
// left it in has still signed the message.
//
// **SHA-1 IS ACCEPTED AND MARKED.** `mode.js` has no policy about weak
// algorithms to ask, so a SHA-1 signature that verifies is `verified` in both
// modes and the outcome says `weak`. Stated rather than implied.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3): it registers no route. It requires `helpers`, `config`,
// `mode`, `error_codes` and `crypto` — all leaves — so it closes no cycle, and
// `common/protocol_stack.ts` builds it beside `sp_metadata.ts`.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import mode = require('../common/mode');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import xmldom = require('@xmldom/xmldom');

const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

// What `assess()` is asked.
interface AssessSpec {
  // 'redirect' for a GET, 'post' for a form POST.
  binding: string;
  // The query string as it arrived, without the '?'.
  rawQuery?: string;
  // The decoded parameters, for `Signature` and `SigAlg`.
  params?: Record<string, unknown>;
  // The decoded message, and the local name of its root.
  xml: string;
  rootLocalName: string;
  // 'SAMLRequest' or 'SAMLResponse'.
  messageField: string;
  // The application entry's fields.
  fields?: Record<string, unknown>;
  // Certificates trusted for this one message beyond the entry's (base64 DER).
  implicitCertificates?: string[];
}

// What `assess()` answers.
interface Assessment {
  signed: boolean;
  outcome: string;
  binding: string;
  sigAlg: string;
  weak: boolean;
  why: string;
  errorCode: string;
  keyInfoCertificate: string;
  registered: number;
}

interface RequestSignatureDeps {
  log: { debug(message: string): void };
  config: typeof config;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  xmldom: typeof xmldom;
}

class RequestSignature {
  constructor(private readonly deps: RequestSignatureDeps) {
    deps.log.debug("Entering RequestSignature.constructor().");
    deps.log.debug("Leaving RequestSignature.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): RequestSignatureDeps {
    helpers.log.debug("Entering RequestSignature.defaultDeps().");
    helpers.log.debug("Leaving RequestSignature.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      mode: mode,
      errorCodes: errorCodes,
      stsCrypto: stsCrypto,
      xmldom: xmldom
    };
  }

  // Every value of a field as trimmed non-empty strings.
  private valuesOf(value: unknown): string[] {
    const { log } = this.deps;
    log.debug("Entering RequestSignature.valuesOf().");
    const list: unknown[] = Array.isArray(value) ? value :
      (value === undefined || value === null ? [] : [value]);
    log.debug("Leaving RequestSignature.valuesOf().");
    return list.map(function (one) {
      return String(one).replace(/\s+/g, '');
    }).filter(function (one) {
      return one !== '';
    });
  }

  // A base64 DER certificate as a PEM.
  private pemOf(der: string): string {
    const { log } = this.deps;
    log.debug("Entering RequestSignature.pemOf().");
    log.debug("Leaving RequestSignature.pemOf().");
    return '-----BEGIN CERTIFICATE-----\n' +
           (der.match(/.{1,64}/g) || []).join('\n') +
           '\n-----END CERTIFICATE-----\n';
  }

  // -------------------------------------------------------------------------
  // MUST THIS SERVICE PROVIDER'S REQUESTS BE SIGNED? `{ required, why }`, and
  // `why` names what decided it, for the refusal and the console.
  // -------------------------------------------------------------------------
  requiresSignedRequests(fields?: Record<string, unknown>):
      { required: boolean; why: string } {
    const { config, mode, log } = this.deps;
    log.debug("Entering RequestSignature.requiresSignedRequests().");
    const declared = String((fields || {}).samlSpAuthnRequestsSigned || '');
    if (declared === 'TRUE') {
      log.debug("Leaving RequestSignature.requiresSignedRequests(). The " +
                "metadata says so.");
      return { required: true,
               why: 'its consumed metadata says AuthnRequestsSigned="true"' };
    }
    const asked = String(config.value('saml2.requireSignedAuthnRequests') ||
                         'auto');
    if (asked === 'on' || asked === 'off') {
      log.debug("Leaving RequestSignature.requiresSignedRequests(). " +
                asked + ".");
      return { required: asked === 'on',
               why: 'saml2.requireSignedAuthnRequests is ' + asked };
    }
    const required = !mode.acceptsUnsignedSamlRequests();
    log.debug("Leaving RequestSignature.requiresSignedRequests(). auto: " +
              required + ".");
    return { required: required,
             why: 'saml2.requireSignedAuthnRequests is auto and this realm ' +
                  'is in ' + (required ? 'PRODUCT' : 'development') +
                  ' mode' };
  }

  // What this identity provider's metadata says in WantAuthnRequestsSigned
  // for one service provider, or for everybody when `fields` is absent.
  wantsSignedRequests(fields?: Record<string, unknown>): boolean {
    const { log } = this.deps;
    log.debug("Entering RequestSignature.wantsSignedRequests().");
    log.debug("Leaving RequestSignature.wantsSignedRequests().");
    return this.requiresSignedRequests(fields).required;
  }

  // The registered certificates, base64 DER, deduplicated.
  registeredCertificates(fields?: Record<string, unknown>): string[] {
    const { log } = this.deps;
    log.debug("Entering RequestSignature.registeredCertificates().");
    const out: string[] = [];
    this.valuesOf((fields || {}).samlSigningCertificate).forEach(
        function (one) {
      const der = one.replace(/-----[^-]+-----/g, '');
      if (der && out.indexOf(der) < 0) {
        out.push(der);
      }
    });
    log.debug("Leaving RequestSignature.registeredCertificates(). " +
              out.length + ".");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE RAW PARAMETERS. The FIRST occurrence of each name, its value still
  // percent-encoded — '+' included, because a signer signed the octets it
  // sent and a '+' it sent is a '+' in those octets.
  // -------------------------------------------------------------------------
  rawParameters(rawQuery: string): Record<string, string> {
    const { log } = this.deps;
    log.debug("Entering RequestSignature.rawParameters().");
    const out: Record<string, string> = {};
    String(rawQuery || '').split('&').forEach(function (pair) {
      if (!pair) {
        return;
      }
      const at = pair.indexOf('=');
      const name = at < 0 ? pair : pair.slice(0, at);
      const value = at < 0 ? '' : pair.slice(at + 1);
      let decodedName = name;
      try {
        decodedName = decodeURIComponent(name.replace(/\+/g, ' '));
      } catch (e) {
        log.debug("Caught in RequestSignature.rawParameters(): " +
                  ((e && e.message) || e));
      }
      if (!Object.prototype.hasOwnProperty.call(out, decodedName)) {
        out[decodedName] = value;
      }
    });
    log.debug("Leaving RequestSignature.rawParameters(). " +
              Object.keys(out).length + " parameter(s).");
    return out;
  }

  // The octet string section 3.4.4.1 signs, or '' when the parameters needed
  // are not there.
  redirectOctets(rawQuery: string, messageField: string): string {
    const { log } = this.deps;
    log.debug("Entering RequestSignature.redirectOctets().");
    const raw = this.rawParameters(rawQuery);
    if (!Object.prototype.hasOwnProperty.call(raw, messageField) ||
        !Object.prototype.hasOwnProperty.call(raw, 'SigAlg')) {
      log.debug("Leaving RequestSignature.redirectOctets(). Incomplete.");
      return '';
    }
    let octets = messageField + '=' + raw[messageField];
    if (Object.prototype.hasOwnProperty.call(raw, 'RelayState')) {
      octets += '&RelayState=' + raw.RelayState;
    }
    octets += '&SigAlg=' + raw.SigAlg;
    log.debug("Leaving RequestSignature.redirectOctets().");
    return octets;
  }

  // The root element's own ds:Signature, if it has one.
  private envelopedSignature(xml: string, rootLocalName: string): any {
    const { log } = this.deps;
    const { DOMParser } = this.deps.xmldom;
    log.debug("Entering RequestSignature.envelopedSignature().");
    let doc;
    try {
      doc = new DOMParser().parseFromString(String(xml), 'text/xml');
    } catch (e) {
      log.debug("Caught in RequestSignature.envelopedSignature(): " +
                ((e && e.message) || e));
      log.debug("Leaving RequestSignature.envelopedSignature(). Unparsed.");
      return null;
    }
    const root = doc && doc.documentElement;
    if (!root || root.localName !== rootLocalName) {
      log.debug("Leaving RequestSignature.envelopedSignature(). No root.");
      return null;
    }
    for (let child = root.firstChild; child; child = child.nextSibling) {
      if (child.nodeType === 1 && child.localName === 'Signature' &&
          child.namespaceURI === DS_NS) {
        const methods = child.getElementsByTagNameNS(DS_NS, 'SignatureMethod');
        const c14n = child.getElementsByTagNameNS(DS_NS,
                                                  'CanonicalizationMethod');
        const certs = child.getElementsByTagNameNS(DS_NS, 'X509Certificate');
        log.debug("Leaving RequestSignature.envelopedSignature(). Found.");
        return {
          sigAlg: methods.length ?
                  String(methods[0].getAttribute('Algorithm') || '') : '',
          c14nAlg: c14n.length ?
                   String(c14n[0].getAttribute('Algorithm') || '') : '',
          keyInfoCertificate: certs.length ?
            String(certs[0].textContent || '').replace(/\s+/g, '') : ''
        };
      }
    }
    log.debug("Leaving RequestSignature.envelopedSignature(). None.");
    return null;
  }

  // -------------------------------------------------------------------------
  // ASSESS ONE MESSAGE. Never throws; the answer says what was found, and
  // `refusal()` says what to do about it.
  // -------------------------------------------------------------------------
  assess(spec: AssessSpec): Assessment {
    const { log, stsCrypto, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering RequestSignature.assess(). binding=" + spec.binding +
              ", root=" + spec.rootLocalName);
    const params = spec.params || {};
    const registered = this.registeredCertificates(spec.fields).concat(
      this.valuesOf(spec.implicitCertificates).filter(function (one) {
        return self.registeredCertificates(spec.fields).indexOf(one) < 0;
      }));
    const detached = spec.binding === 'redirect' && !!params.Signature;
    const enveloped = detached ? null :
      this.envelopedSignature(spec.xml, spec.rootLocalName);
    const answer: Assessment = {
      signed: detached || !!enveloped,
      outcome: 'unsigned',
      binding: detached ? 'redirect' : (enveloped ? 'post' : ''),
      sigAlg: detached ? String(params.SigAlg || '')
                       : (enveloped ? enveloped.sigAlg : ''),
      weak: false,
      why: '',
      errorCode: '',
      keyInfoCertificate: enveloped ? enveloped.keyInfoCertificate : '',
      registered: registered.length
    };
    answer.weak = /sha1(?![0-9])/i.test(answer.sigAlg);
    if (!answer.signed) {
      answer.why = 'the ' + spec.rootLocalName + ' carries no signature';
      log.debug("Leaving RequestSignature.assess(). Unsigned.");
      return answer;
    }
    if (!registered.length) {
      answer.outcome = 'no-certificate';
      answer.why = 'it is signed, and this service provider has no ' +
                   'registered signing certificate (samlSigningCertificate) ' +
                   'to check it against, so it is NOT verified';
      log.debug("Leaving RequestSignature.assess(). Nothing registered.");
      return answer;
    }
    if (enveloped && enveloped.c14nAlg &&
        enveloped.c14nAlg.indexOf('xml-exc-c14n') < 0) {
      answer.outcome = 'failed';
      answer.errorCode = 'STS-SAML-0064';
      answer.why = 'the signature uses ' + enveloped.c14nAlg + ', an ' +
                   'INCLUSIVE canonicalization; this service verifies ' +
                   'SAML signatures made with exclusive canonicalization ' +
                   'only, which is what SAML specifies';
      log.debug("Leaving RequestSignature.assess(). Inclusive c14n.");
      return answer;
    }
    let octets = '';
    if (detached) {
      octets = this.redirectOctets(spec.rawQuery || '', spec.messageField);
      if (!octets) {
        answer.outcome = 'failed';
        answer.errorCode = 'STS-SAML-0062';
        answer.why = 'a Signature parameter arrived without the ' +
                     spec.messageField + ' and SigAlg it signs, so there ' +
                     'is nothing to verify it over';
        log.debug("Leaving RequestSignature.assess(). Incomplete octets.");
        return answer;
      }
    }
    let lastWhy = '';
    let checkable = false;
    for (let i = 0; i < registered.length; i++) {
      const certPem = this.pemOf(registered[i]);
      const verdict: any = detached
        ? stsCrypto.verifyQueryString(octets, {
          signature: String(params.Signature), sigAlg: answer.sigAlg,
          certPem: certPem })
        : stsCrypto.verifyXmlSignature(spec.xml, {
          element: spec.rootLocalName, certPem: certPem });
      if (verdict.ok) {
        answer.outcome = 'verified';
        answer.sigAlg = verdict.signatureMethod || answer.sigAlg;
        answer.why = 'verified against registered certificate ' + (i + 1) +
                     ' of ' + registered.length +
                     (answer.weak ? ' — with SHA-1, which is weak' : '');
        log.debug("Leaving RequestSignature.assess(). Verified.");
        return answer;
      }
      lastWhy = verdict.why || 'it did not verify';
      // A signature that is WRONG is one the next certificate might verify; one
      // that could not be CHECKED will not become checkable by trying another.
      const wrong = detached
        ? verdict.usable
        : (verdict.present &&
           !/needs a verifier/.test(String(verdict.why || '')) &&
           (errorCodes.codeOf(verdict) === 'STS-KEYS-0012' ||
            errorCodes.codeOf(verdict) === 'STS-KEYS-0013'));
      if (wrong) {
        checkable = true;
      }
    }
    answer.outcome = 'failed';
    answer.errorCode = checkable ? 'STS-SAML-0061' : 'STS-SAML-0062';
    answer.why = checkable
      ? 'the signature does not verify against any of the ' +
        registered.length + ' registered certificate(s): ' + lastWhy
      : 'the signature could not be checked: ' + lastWhy;
    log.debug("Leaving RequestSignature.assess(). " + answer.errorCode + ".");
    return answer;
  }

  // -------------------------------------------------------------------------
  // WHAT TO DO ABOUT AN ASSESSMENT: `{ refuse, errorCode, why }`. A failed
  // signature is refused in every mode; an unsigned (or unverifiable for want
  // of a certificate) one only where signatures are required.
  // -------------------------------------------------------------------------
  refusal(assessment: Assessment, fields?: Record<string, unknown>):
      { refuse: boolean; errorCode: string; why: string } {
    const { log } = this.deps;
    log.debug("Entering RequestSignature.refusal(). outcome=" +
              assessment.outcome);
    if (assessment.outcome === 'failed') {
      log.debug("Leaving RequestSignature.refusal(). Failed.");
      return { refuse: true, errorCode: assessment.errorCode,
               why: 'The request\'s signature was refused: ' +
                    assessment.why + '.' };
    }
    if (assessment.outcome === 'verified') {
      log.debug("Leaving RequestSignature.refusal(). Verified.");
      return { refuse: false, errorCode: '', why: '' };
    }
    const need = this.requiresSignedRequests(fields);
    if (!need.required) {
      log.debug("Leaving RequestSignature.refusal(). Not required.");
      return { refuse: false, errorCode: '', why: '' };
    }
    log.debug("Leaving RequestSignature.refusal(). Required and absent.");
    return { refuse: true, errorCode: 'STS-SAML-0063',
             why: 'A signed request is required here (' + need.why + '), ' +
                  'and ' + assessment.why + '. ' +
                  (assessment.outcome === 'no-certificate'
                    ? 'Register the service provider\'s signing ' +
                      'certificate — consume its metadata, or set it on the ' +
                      'SAML 2.0 console page — or confirm the one its ' +
                      'request carried, if it is genuinely that service ' +
                      'provider\'s.'
                    : 'Have the service provider sign its requests.') };
  }

  // The one-line record written onto the entry and the audit row:
  // `<outcome> <binding> <sigAlg>`.
  summary(assessment: Assessment): string {
    const { log } = this.deps;
    log.debug("Entering RequestSignature.summary().");
    log.debug("Leaving RequestSignature.summary().");
    return [assessment.outcome, assessment.binding || '-',
            assessment.sigAlg || '-'].join(' ') +
           (assessment.weak ? ' weak' : '');
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — `return_address.ts`'s
// arrangement: `common/protocol_stack.ts` builds one and installs it, and the
// exports below are facades; a process without the root builds a default when
// the module loads.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<RequestSignature>(
  'saml/request_signature',
  () => new RequestSignature(RequestSignature.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  RequestSignature: RequestSignature,
  installInstance: (instance: RequestSignature): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  requiresSignedRequests: slot.forward('requiresSignedRequests'),
  wantsSignedRequests: slot.forward('wantsSignedRequests'),
  registeredCertificates: slot.forward('registeredCertificates'),
  rawParameters: slot.forward('rawParameters'),
  redirectOctets: slot.forward('redirectOctets'),
  assess: slot.forward('assess'),
  refusal: slot.forward('refusal'),
  summary: slot.forward('summary')
};
