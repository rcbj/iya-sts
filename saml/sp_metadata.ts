'use strict';
//
// File: sp_metadata.ts
//
// ===========================================================================
// A SERVICE PROVIDER'S OWN METADATA: PARSING IT, FETCHING IT, AND CONSUMING
// IT.
//
// Added 2026-08-27 with SAML 2.0 encryption, because encrypting to a service
// provider means holding its public key and this service had nowhere to get one
// from. It then read exactly one value — the encryption certificate — and
// REPORTED the endpoints without applying them.
//
// **SINCE 2026-09-17 (#37) IT CONSUMES THE WHOLE SPSSODescriptor**: the
// AssertionConsumerService and SingleLogoutService endpoints become the
// service provider's REGISTERED return addresses, its signing certificates
// become what its requests are VERIFIED against, and its NameIDFormats,
// AuthnRequestsSigned and WantAssertionsSigned are written onto the entry and
// read by `saml2_sso.ts`. `consume()` is the one place that happens, for a
// refreshed document and an uploaded one alike, and `saml/CLAUDE.md` argues
// why an operator's refresh or upload is the trust act.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY. It registers no route (rule 3), and it is required by
// `admin-core/admin_actions.ts` for the refresh and upload actions and by
// `saml2_sso.ts`. It requires `common/` libraries (`helpers`, `config`,
// `applications`, `audit`, `error_codes`, `version`, `crypto`) and
// `federation/federation_http.ts`, none of which requires it, so it closes no
// cycle and moves nothing in the router.
//
// ---------------------------------------------------------------------------
// THE FETCH NEVER HAPPENS DURING A FLOW, and that is the single most important
// property here.
//
// `refresh()` is called from a console button and from
// `POST /admin-api/applications/refresh-metadata`. It writes what it found onto
// the application entry, and ISSUING READS THE ENTRY. Nothing in the sign-on
// path dials anything — which stays true now that far more is read off the
// entry than a certificate.
//
// The alternative — resolve the URL when an assertion is being built — is what
// a real identity provider does with a cache, and it was rejected for a reason
// worth writing down: an assertion that has to wait on somebody else's web
// server makes every sign-in exactly as reliable as that server, and the
// failure arrives in the middle of a browser redirect where the only honest
// thing to render is a page about a timeout. A mock whose sign-ins fail because
// a metadata host is slow is a mock nobody can debug a client with.
//
// ---------------------------------------------------------------------------
// THIS IS THE SECOND OUTBOUND-REQUEST SURFACE IN THIS SERVICE, and federation
// was the first and, until now, the only one — `federation/CLAUDE.md` argues at
// length that dialling a URL is a capability this service does not hand out.
// The same three refusals apply here and for the same reasons:
//
//   * THE URL COMES OFF THE APPLICATION ENTRY and from nowhere else.
//     `refresh()` takes an application identifier, not a URL. A caller cannot
//     ask this service to dial an address of their choosing, which is the
//     difference between a metadata fetcher and an open proxy.
//   * THE SCHEME IS CHECKED. https always; http only with
//     `federation.outboundAllowInsecure` on. That setting is REUSED rather than
//     copied: a deployment has decided once whether this service may make a
//     request in the clear, and a second setting would be a second answer to
//     one question.
//   * IT TIMES OUT, on `federation.outboundTimeoutMs`, for the same reason.
//
// What it does NOT do is follow redirects or accept anything but XML, and
// neither is an oversight: a redirect is how a URL somebody vetted becomes a
// URL nobody vetted.
//
// ---------------------------------------------------------------------------
// **THE POLICY IS NOW `federation/federation_http.ts`'s, NOT A COPY OF IT
// (2026-09-12)**, and four things were wrong with the copy, each quietly:
//
//   * `federation.outbound` — the switch a deployment with no egress sets so
//     that THIS SERVICE DIALS NOTHING — was never read here, so a refresh
//     dialled out of an air-gapped deployment that believed it could not;
//   * `federation.outboundAllowInsecure` was applied to the SCHEME and not to
//     the CERTIFICATE, the opposite half from the other requester: an https
//     metadata host with a certificate nothing trusts was refused even with the
//     setting on, and the setting's own description promises otherwise;
//   * no User-Agent was sent, where the CLAUDE.md rule is that every outbound
//     request says which build is calling (`common/version.js`);
//   * the timeout read `Number(...) || 5000`, a second default disagreeing with
//     the setting's own (15000) — and a fallback no setting could be read past.
//
// So the outbound switch, the scheme rule and the insecure switch are asked of
// that module, the timeout is the setting, and the body cap is
// `saml2.spMetadataMaxBytes`. The URL rule stays in THIS file's `refresh()` —
// the URL comes off the application entry by name — because that module's
// DIALLABLE list is about federation relationships and a fourth name there
// would be the change its header forbids.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SpMetadata` takes node's `http`, `https` and `url`, the XML parser,
// node-forge, helpers, `config`, the error-code registry, the audit log, the
// application registry and `federation/federation_http.ts` through its
// constructor. Since #50's R2 the composition root builds the instance; the
// module's old names are FACADES forwarding to it, for `saml2_sso.ts`, the
// console and the management API, and a process without the root builds a
// default at load.
// ---------------------------------------------------------------------------

import http = require('http');
import https = require('https');
import url = require('url');
import xmldom = require('@xmldom/xmldom');
import forge = require('node-forge');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// THE ERROR CODES AND THE AUDIT LOG. A refresh is an action whose result the
// console or the management API sends back as it is, so a code cannot ride on
// that result — it would be serialised to the caller. Each refused refresh is
// an audit row carrying its code instead. `audit.js` requires nothing that
// reaches back here, so this closes no cycle.
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
// The one verifier (rule 3r), for a metadata document's own signature
// (2026-09-17). A leaf, so this require closes no cycle.
import stsCrypto = require('../common/crypto');
import applications = require('../common/applications');
// The outbound policy — the kill switch, the scheme rule and the insecure
// switch — from the module that owns it. A library that registers nothing and
// requires only config, helpers and version, so a require from saml/ closes no
// cycle and moves no route.
import fedHttp = require('../federation/federation_http');
// Which build is calling, in RFC 9110 product form — the rule every outbound
// requester in this service follows. Built once: the version cannot change.
import version = require('../common/version');
const USER_AGENT = version.userAgent('saml-sp-metadata');

// What parse() answers. It answers rather than throws; see that method.
interface ParsedMetadata {
  ok: boolean;
  why?: string;
  entityId?: string;
  certificate?: string;
  certificateUse?: string;
  signingCertificates?: string[];
  acs?: string[];
  slo?: string[];
  acsEndpoints?: Array<Record<string, string>>;
  sloEndpoints?: Array<Record<string, string>>;
  nameIdFormats?: string[];
  authnRequestsSigned?: boolean;
  wantAssertionsSigned?: boolean;
  validUntil?: string;
  cacheDuration?: string;
  signed?: boolean;
  skipped?: string[];
  [member: string]: unknown;
}

// The SAML 2.0 protocol namespace, which an SPSSODescriptor's
// protocolSupportEnumeration must name to be read here.
const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

// What fetchMetadata() resolves to.
interface FetchAnswer {
  ok: boolean;
  xml?: string;
  why?: string;
  errorCode?: string;
  [member: string]: unknown;
}

interface SpMetadataDeps {
  http: typeof http;
  https: typeof https;
  url: typeof url;
  xmldom: typeof xmldom;
  forge: typeof forge;
  helpers: typeof helpers;
  config: typeof config;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  applications: typeof applications;
  fedHttp: typeof fedHttp;
  stsCrypto: typeof stsCrypto;
}

class SpMetadata {
  constructor(private readonly deps: SpMetadataDeps) {
    deps.helpers.log.debug("Entering SpMetadata.constructor().");
    deps.helpers.log.debug("Leaving SpMetadata.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): SpMetadataDeps {
    helpers.log.debug("Entering SpMetadata.defaultDeps().");
    helpers.log.debug("Leaving SpMetadata.defaultDeps().");
    return {
      http: http,
      https: https,
      url: url,
      xmldom: xmldom,
      forge: forge,
      helpers: helpers,
      config: config,
      errorCodes: errorCodes,
      audit: audit,
      applications: applications,
      fedHttp: fedHttp,
      stsCrypto: stsCrypto
    };
  }

  // The metadata namespace, and the two this file reads inside it. Matched on
  // LOCAL NAME everywhere below — `getElementsByTagNameNS('*', ...)` — because
  // a metadata document may use `md:`, `saml2:` or no prefix at all and all
  // three are the same document. helpers.firstByLocal() follows the same rule.
  //
  // The cap is `saml2.spMetadataMaxBytes` since 2026-09-12; it was the constant
  // MAX_METADATA_BYTES, 512 KiB, which is still the setting's default.
  private maxMetadataBytes() {
    const { config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.maxMetadataBytes().");
    log.debug("Leaving SpMetadata.maxMetadataBytes().");
    return Number(config.value('saml2.spMetadataMaxBytes'));
  }

  // ---------------------------------------------------------------------------
  // PARSE, and it answers rather than throws.
  //
  // Until 2026-09-17 this read ONE value — the encryption certificate — and
  // reported the endpoints without applying them. Since #37 the whole
  // <md:SPSSODescriptor> is read, because `consume()` below writes it onto the
  // entry and the Single Sign-On and Single Logout services USE it:
  //
  //   entityId              the EntityDescriptor's entityID
  //   acsEndpoints          [{ binding, location, index, isDefault }]
  //   sloEndpoints          [{ binding, location, responseLocation }]
  //   signingCertificates   every X509Certificate in a KeyDescriptor marked
  //                         use="signing" or with no `use`
  //   certificate           the ENCRYPTION certificate, as before
  //   nameIdFormats         the <md:NameIDFormat> values
  //   authnRequestsSigned   the SPSSODescriptor's attribute, as a boolean
  //   wantAssertionsSigned  likewise
  //   validUntil            the EARLIER of the two elements' validUntil
  //   cacheDuration         the SPSSODescriptor's, else the EntityDescriptor's
  //   signed                whether the EntityDescriptor carries its own
  //                         ds:Signature (checked by `consume()`, not here)
  //
  // `acs` and `slo` stay as the plain location lists they always were, for
  // the callers that report them.
  //
  // WHICH KEY IS THE ENCRYPTION KEY, in the order the specification implies: a
  // KeyDescriptor with `use="encryption"`, then one with NO `use` at all —
  // which section 2.4.1.1 says serves both purposes — and never one marked
  // `use="signing"`, which is the key that would look right and be wrong.
  //
  // ONLY THE SPSSODescriptor IS READ. An entity that is both an identity
  // provider and a service provider publishes keys and endpoints under each
  // role, and a key from the IDPSSODescriptor is not the one its requests are
  // signed with in this role. A document with no SAML 2.0 SPSSODescriptor is
  // not this kind of metadata and is refused.
  // ---------------------------------------------------------------------------
  parse(xml: string): ParsedMetadata {
    const { log } = this.deps.helpers;
    const { DOMParser } = this.deps.xmldom;
    const self = this;
    log.debug("Entering SpMetadata.parse().");
    const text = String(xml || '').trim();
    if (!text) {
      log.debug("Leaving SpMetadata.parse(). Empty.");
      return { ok: false, why: 'there is no metadata document to read' };
    }
    let doc;
    try {
      doc = new DOMParser().parseFromString(text, 'text/xml');
    } catch (e) {
      log.debug("Caught in SpMetadata.parse(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpMetadata.parse(). It will not parse.");
      return { ok: false,
               why: 'the metadata is not well-formed XML: ' + e.message };
    }
    if (!doc || !doc.documentElement) {
      log.debug("Leaving SpMetadata.parse(). No root element.");
      return { ok: false, why: 'the metadata has no root element' };
    }
    const root = doc.documentElement;
    // An EntitiesDescriptor holding several entities is legal and is NOT
    // supported: which of them this application is cannot be worked out from a
    // document that does not know which application it was fetched for, and
    // guessing the first would silently encrypt to whoever happened to be
    // listed first. Named rather than half-handled.
    if (root.localName === 'EntitiesDescriptor') {
      log.debug("Leaving SpMetadata.parse(). An EntitiesDescriptor.");
      return { ok: false, why: 'this is an <md:EntitiesDescriptor> holding ' +
               'several entities. Give the <md:EntityDescriptor> for this ' +
               'one ' +
               'service provider — a document listing many does not say ' +
               'which ' +
               'of them this application is, and picking the first would ' +
               'encrypt to whoever happens to be listed first' };
    }
    if (root.localName !== 'EntityDescriptor') {
      log.debug("Leaving SpMetadata.parse(). Not an EntityDescriptor.");
      return { ok: false, why: 'the document is <' + root.localName +
               '>, not an <md:EntityDescriptor>' };
    }
    const sp = this.childrenByLocal(root, 'SPSSODescriptor').filter(
        function (one) {
      return String(one.getAttribute('protocolSupportEnumeration') || '')
        .split(/\s+/).indexOf(NS_SAMLP) >= 0;
    })[0];
    if (!sp) {
      log.debug("Leaving SpMetadata.parse(). No SAML 2.0 SPSSODescriptor.");
      return { ok: false, why: 'the EntityDescriptor has no ' +
               '<md:SPSSODescriptor> whose protocolSupportEnumeration names ' +
               'SAML 2.0, so it does not describe a SAML 2.0 service ' +
               'provider' };
    }

    const out: ParsedMetadata = {
      ok: true,
      entityId: root.getAttribute('entityID') || '',
      certificate: '',
      certificateUse: '',
      signingCertificates: [],
      acs: [],
      slo: [],
      acsEndpoints: [],
      sloEndpoints: [],
      nameIdFormats: [],
      authnRequestsSigned:
        String(sp.getAttribute('AuthnRequestsSigned') || '') === 'true',
      wantAssertionsSigned:
        String(sp.getAttribute('WantAssertionsSigned') || '') === 'true',
      validUntil: this.earliest([root.getAttribute('validUntil') || '',
                                 sp.getAttribute('validUntil') || '']),
      cacheDuration: sp.getAttribute('cacheDuration') ||
                     root.getAttribute('cacheDuration') || '',
      signed: this.childrenByLocal(root, 'Signature').length > 0,
      skipped: []
    };

    const signing: string[] = [];
    let unqualified = '';
    this.childrenByLocal(sp, 'KeyDescriptor').forEach(function (descriptor) {
      const use = (descriptor.getAttribute('use') || '').trim();
      const certs = descriptor.getElementsByTagNameNS('*', 'X509Certificate');
      for (let n = 0; n < certs.length; n++) {
        const value = (certs[n].textContent || '').replace(/\s+/g, '');
        if (!value) {
          continue;
        }
        if (use === 'encryption' && !out.certificate) {
          out.certificate = value;
          out.certificateUse = 'encryption';
        }
        if (!use && !unqualified) {
          unqualified = value;
        }
        if ((use === 'signing' || !use) && signing.indexOf(value) < 0) {
          signing.push(value);
        }
      }
    });
    if (!out.certificate && unqualified) {
      out.certificate = unqualified;
      out.certificateUse = 'unspecified';
    }
    out.signingCertificates = signing;

    this.childrenByLocal(sp, 'AssertionConsumerService').forEach(
        function (el) {
      const location = String(el.getAttribute('Location') || '').trim();
      const binding = String(el.getAttribute('Binding') || '').trim();
      if (!self.endpointProblem(location, binding, out.skipped,
                                'AssertionConsumerService')) {
        const isDefault = el.getAttribute('isDefault');
        out.acsEndpoints.push({
          binding: binding, location: location,
          index: String(el.getAttribute('index') || '').trim(),
          isDefault: isDefault === 'true' ? 'true'
            : (isDefault === 'false' ? 'false' : '-')
        });
        if (out.acs.indexOf(location) < 0) {
          out.acs.push(location);
        }
      }
    });
    this.childrenByLocal(sp, 'SingleLogoutService').forEach(function (el) {
      const location = String(el.getAttribute('Location') || '').trim();
      const binding = String(el.getAttribute('Binding') || '').trim();
      const response = String(el.getAttribute('ResponseLocation') || '').trim();
      if (!self.endpointProblem(location, binding, out.skipped,
                                'SingleLogoutService') &&
          !(response && self.endpointProblem(response, binding, out.skipped,
                                             'SingleLogoutService ' +
                                             'ResponseLocation'))) {
        out.sloEndpoints.push({ binding: binding, location: location,
                                responseLocation: response });
        if (out.slo.indexOf(location) < 0) {
          out.slo.push(location);
        }
      }
    });
    this.childrenByLocal(sp, 'NameIDFormat').forEach(function (el) {
      const format = String(el.textContent || '').trim();
      if (format && out.nameIdFormats.indexOf(format) < 0) {
        out.nameIdFormats.push(format);
      }
    });
    log.debug("Leaving SpMetadata.parse(). " + out.acsEndpoints.length +
              " ACS, " + out.sloEndpoints.length + " SLO, " +
              signing.length + " signing certificate(s), encryption " +
              (out.certificate ? out.certificateUse : 'none'));
    return out;
  }

  // The direct children of `parent` with this local name. Direct, because a
  // KeyDescriptor or an endpoint inside an <md:Extensions> or a nested role is
  // not this role's.
  private childrenByLocal(parent, localName) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.childrenByLocal(). " + localName);
    const out = [];
    for (let child = parent.firstChild; child; child = child.nextSibling) {
      if (child.nodeType === 1 && child.localName === localName) {
        out.push(child);
      }
    }
    log.debug("Leaving SpMetadata.childrenByLocal(). " + out.length);
    return out;
  }

  // Whether an endpoint can be written as a return address, and when it
  // cannot, the sentence is pushed onto `skipped` and true comes back. A
  // Location has to be an absolute http(s) URL with no space in it — the
  // stored form puts the URL last and splits on spaces — and a binding has to
  // be named.
  private endpointProblem(location, binding, skipped, what) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.endpointProblem().");
    let problem = '';
    if (!binding || /\s/.test(binding)) {
      problem = 'it names no Binding';
    } else if (!/^https?:\/\/[^\s]+$/i.test(location)) {
      problem = 'its location "' + location + '" is not an absolute http ' +
                'or https URL';
    }
    if (problem) {
      skipped.push('an <md:' + what + '> was not registered: ' + problem);
    }
    log.debug("Leaving SpMetadata.endpointProblem(). " + (problem || 'ok'));
    return !!problem;
  }

  // The earliest of some xs:dateTime values, '' for none, and an unparseable
  // one is kept as written rather than dropped — the page shows it and says it
  // could not be read.
  private earliest(values) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.earliest().");
    let best = '';
    values.forEach(function (one) {
      const text = String(one || '').trim();
      if (!text) {
        return;
      }
      if (!best || (Date.parse(text) < Date.parse(best))) {
        best = text;
      }
    });
    log.debug("Leaving SpMetadata.earliest(). " + (best || 'none'));
    return best;
  }

  // A base64 DER certificate as a PEM, which is what forge and the encryptor
  // want. It ACCEPTS a PEM too, so an operator who pasted one into
  // `samlEncryptionCertificate` is not told their certificate is invalid
  // because of its punctuation.
  toPem(value) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.toPem().");
    const text = String(value || '').trim();
    if (!text) {
      log.debug("Leaving SpMetadata.toPem().");
      return '';
    }
    if (text.indexOf('-----BEGIN') === 0) {
      log.debug("Leaving SpMetadata.toPem().");
      return text;
    }
    const body = text.replace(/\s+/g, '').replace(/-----[^-]+-----/g, '');
    if (!body) {
      log.debug("Leaving SpMetadata.toPem().");
      return '';
    }
    log.debug("Leaving SpMetadata.toPem().");
    return '-----BEGIN CERTIFICATE-----\n' +
           (body.match(/.{1,64}/g) || []).join('\n') +
           '\n-----END CERTIFICATE-----\n';
  }

  // Is this actually a certificate? Called before anything is stored, so a
  // paste-o is refused at the door rather than at the next sign-in — where the
  // only symptom would be an assertion quietly going out in clear.
  certificateProblem(value) {
    const { forge } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.certificateProblem().");
    const pem = this.toPem(value);
    if (!pem) {
      log.debug("Leaving SpMetadata.certificateProblem().");
      return 'it is empty';
    }
    try {
      const cert = forge.pki.certificateFromPem(pem);
      if (!cert.publicKey || !cert.publicKey.n) {
        log.debug("Leaving SpMetadata.certificateProblem().");
        return 'its public key is not an RSA key, and XML Encryption key ' +
               'transport here wraps to RSA';
      }
      log.debug("Leaving SpMetadata.certificateProblem().");
      return '';
    } catch (e) {
      log.debug("Caught in SpMetadata.certificateProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpMetadata.certificateProblem().");
      return 'it is not a certificate this service can read (' + e.message +
        ')';
    }
  }

  // The timeout, read as the setting and nothing else. See the header for the
  // `|| 5000` this replaced.
  private timeoutMs() {
    const { config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.timeoutMs().");
    log.debug("Leaving SpMetadata.timeoutMs().");
    return Number(config.value('federation.outboundTimeoutMs'));
  }

  // Whether this URL may be dialled, as a sentence. The empty case is this
  // file's own words; everything else is federation_http.ts's rule, so the two
  // outbound requesters cannot disagree about what "in the clear" means.
  urlProblem(raw) {
    const { fedHttp } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.urlProblem().");
    const text = String(raw || '').trim();
    if (!text) {
      log.debug("Leaving SpMetadata.urlProblem().");
      return 'there is no samlSpMetadataUrl on this application';
    }
    log.debug("Leaving SpMetadata.urlProblem().");
    return fedHttp.urlProblem(text);
  }

  // ---------------------------------------------------------------------------
  // FETCH ONE DOCUMENT. Returns a promise of `{ ok, xml, why, status }` and
  // NEVER rejects, for federation_http.ts's reason: a rejected promise would
  // have to be caught at every call site, and the one added later would not be.
  // ---------------------------------------------------------------------------
  fetchMetadata(url: string): Promise<FetchAnswer> {
    const { fedHttp, http, https } = this.deps;
    const { log } = this.deps.helpers;
    const { URL } = this.deps.url;
    const self = this;
    log.debug("Entering SpMetadata.fetchMetadata(). url=" + url);
    log.debug("Leaving SpMetadata.fetchMetadata().");
    return new Promise<FetchAnswer>(function (resolve) {
      // THE KILL SWITCH FIRST (2026-09-12) — see the header. A deployment that
      // set `federation.outbound` off has said this process dials nothing.
      if (!fedHttp.outboundAllowed()) {
        log.debug("Leaving SpMetadata.fetchMetadata(). federation.outbound " +
                  "is off.");
        resolve({ ok: false, errorCode: 'STS-SAML-0045',
                  why: 'federation.outbound is off, so this service makes no ' +
                       'outbound request at all — a metadata document cannot ' +
                       'be fetched. Paste the service provider\'s ' +
                       'certificate ' +
                       'into samlEncryptionCertificate instead' });
        return;
      }
      const problem = self.urlProblem(url);
      if (problem) {
        log.debug("Leaving SpMetadata.fetchMetadata(). Refused: " + problem);
        resolve({ ok: false, errorCode: 'STS-SAML-0046', why: problem });
        return;
      }
      const parsed = new URL(String(url).trim());
      const agent = parsed.protocol === 'https:' ? https : http;
      let settled = false;
      const done = function (answer) {
        log.debug("Entering done().");
        if (settled) {
          log.debug("Leaving done().");
          return;
        }
        settled = true;
        resolve(answer);
        log.debug("Leaving done().");
      };
      const cap = self.maxMetadataBytes();
      const insecure = fedHttp.allowInsecure();
      if (parsed.protocol !== 'https:') {
        // Every insecure request, not only the setting — federation_http.ts's
        // rule.
        log.warn('saml2: fetching SP metadata from ' + parsed.origin +
                 ' over plain http because ' +
                 'federation.outboundAllowInsecure is ON.');
      }
      const request = agent.get(String(url).trim(), {
        headers: { accept: 'application/samlmetadata+xml, application/xml, ' +
                           'text/xml',
                   'user-agent': USER_AGENT },
        // THE CERTIFICATE CHECK, and `federation.outboundAllowInsecure` is what
        // turns it off — the half the copy of this policy never applied.
        rejectUnauthorized: !insecure
      }, function (res) {
        // NO REDIRECT FOLLOWING, deliberately: a redirect is how a URL somebody
        // vetted becomes a URL nobody vetted, and this is one of two places in
        // this service that dials anything at all.
        if (res.statusCode >= 300 && res.statusCode < 400) {
          res.resume();
          done({ ok: false, status: res.statusCode, errorCode: 'STS-SAML-0047',
                 why: 'it answered ' + res.statusCode + ' with a redirect to ' +
                                                        '"' +
                      (res.headers.location || '(no Location)') + '". ' +
                      'Redirects are not followed here — a redirect is how a ' +
                      'vetted URL becomes an unvetted one. Put the final URL ' +
                      'on the entry' });
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          done({ ok: false, status: res.statusCode, errorCode: 'STS-SAML-0048',
                 why: 'it answered ' + res.statusCode + ' rather than 200' });
          return;
        }
        let body = '';
        let size = 0;
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
          size += chunk.length;
          if (size > cap) {
            // A cap, because the other end is not this service's to trust and a
            // metadata document is kilobytes. Destroying the socket is what
            // stops an endless response from being read into memory.
            request.destroy();
            done({ ok: false, errorCode: 'STS-SAML-0049', why: 'the document ' +
                'is larger than ' + cap +
                   ' bytes (saml2.spMetadataMaxBytes), which no service ' +
                   'provider metadata is' });
            return;
          }
          body += chunk;
        });
        res.on('end', function () {
          done({ ok: true, xml: body, status: 200 });
        });
      });
      request.setTimeout(self.timeoutMs(), function () {
        request.destroy();
        done({ ok: false, errorCode: 'STS-SAML-0050', why: 'it did not ' +
                                                           'answer ' +
            'within ' + self.timeoutMs() +
               'ms (federation.outboundTimeoutMs)' });
      });
      request.on('error', function (e) {
        // The message is the node error's, because "self-signed certificate",
        // "connection refused" and "getaddrinfo ENOTFOUND" send somebody to
        // three different places and a single word for all three sends them
        // nowhere.
        done({ ok: false, errorCode: 'STS-SAML-0051',
               why: 'the request failed: ' + e.message });
      });
    });
  }

  // The audit row for a refresh that did not happen. The reason sentences name
  // a URL, a status or a parser's message — never a certificate or a document
  // body.
  // error-code: none — the helper's definition, not a call to it
  private refreshRefused(code, identifier, why) {
    const { audit } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.refreshRefused().");
    audit.failure(code, {
      protocol: 'SAML 2.0', channel: 'internal',
      target: String(identifier || ''),
      summary: 'the service provider metadata for ' +
               String(identifier || '(unnamed)') +
               ' was not refreshed: ' + why,
      // error-code: none — the helper's own row; every caller passes its code
      outcome: 'refused'
    });
    log.debug("Leaving SpMetadata.refreshRefused().");
  }

  // ---------------------------------------------------------------------------
  // THE WHOLE ACT: fetch what the entry names and CONSUME it. This is what the
  // console button and `POST /admin-api/applications/refresh-metadata` call.
  //
  // A FAILURE WRITES NOTHING, so a refresh that could not reach the host leaves
  // the last good registration in place. An application that was working does
  // not stop working because a metadata server was down.
  // ---------------------------------------------------------------------------
  refresh(identifier) {
    const { applications } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering SpMetadata.refresh(). identifier=" + identifier);
    const record = applications.get(identifier);
    if (!record) {
      log.debug("Leaving SpMetadata.refresh(). No such application.");
      this.refreshRefused('STS-SAML-0044', identifier, 'there is no such ' +
                                                  'application to refresh');
      log.debug("Leaving SpMetadata.refresh().");
      return Promise.resolve({ ok: false,
                               errors: ['There is no application "' +
        identifier + '" in this registry. Create it first — a metadata URL ' +
        'is an attribute on an entry, and this action never takes a URL ' +
        'from the caller.'] });
    }
    const url = ((record.fields && record.fields.samlSpMetadataUrl) || '');
    const wanted = Array.isArray(url) ? url[0] : url;
    log.debug("Leaving SpMetadata.refresh().");
    return this.fetchMetadata(wanted).then(function (answer) {
      if (!answer.ok) {
        log.warn('saml2: could not refresh metadata for ' + identifier + ' — ' +
                 answer.why +
                 '. Nothing on the entry was changed.');
        log.debug("Leaving SpMetadata.refresh(). The fetch failed.");
        self.refreshRefused(answer.errorCode || 'STS-SAML-0051', identifier,
                       'the metadata could not be fetched: ' + answer.why);
        return { ok: false, errors: ['The metadata at "' + wanted + '" could ' +
            'not be read: ' +
          answer.why + '. Nothing on the entry was changed, so whatever ' +
          'certificate it already had is still in force.'] };
      }
      const consumed = self.consume(identifier, answer.xml, 'refresh');
      if (consumed.ok) {
        consumed.url = wanted;
      }
      return consumed;
    });
  }

  // ---------------------------------------------------------------------------
  // AN UPLOADED DOCUMENT (2026-09-17, #37): the console's SAML 2.0 page and
  // `POST /admin-api/saml2/upload-metadata`. The same consumption as a
  // refresh, with the document supplied by an operator rather than fetched
  // from the URL an operator put on the entry — which is the same trust act
  // (see `consume()`), and the way to register a service provider whose
  // metadata this service cannot reach.
  // ---------------------------------------------------------------------------
  upload(identifier, xml, actor?) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.upload(). identifier=" + identifier);
    const text = String(xml == null ? '' : xml);
    const cap = this.maxMetadataBytes();
    if (Buffer.byteLength(text, 'utf8') > cap) {
      this.refreshRefused('STS-SAML-0067', identifier, 'the uploaded ' +
                          'document is larger than ' + cap + ' bytes');
      log.debug("Leaving SpMetadata.upload(). Too large.");
      return { ok: false, errors: ['The document is larger than ' + cap +
               ' bytes (saml2.spMetadataMaxBytes), which no service provider ' +
               'metadata is. Nothing on the entry was changed.'] };
    }
    const answer = this.consume(identifier, text, 'upload', actor);
    log.debug("Leaving SpMetadata.upload(). ok=" + answer.ok);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // CONSUMING A DOCUMENT: check it, then write everything it registers onto
  // the entry in ONE save (`applications.replaceSamlMetadataFields()`).
  //
  // **THE TRUST ACT IS THE OPERATOR'S**, and it is worth being exact about
  // what that means, because this writes signing certificates that every
  // later request from the service provider is verified against. A refresh
  // dials ONLY the `samlSpMetadataUrl` an administrator put on the entry, over
  // https with the certificate checked unless
  // `federation.outboundAllowInsecure` says otherwise, and only when an
  // administrator presses the button; an
  // upload is a document an administrator chose. That is the same act as
  // pasting the certificate into the entry by hand, which is what every
  // identity provider's "import metadata" amounts to — and a request NEVER
  // reaches this code.
  //
  // **A SIGNED DOCUMENT IS VERIFIED WHEN THERE IS SOMETHING TO VERIFY IT
  // AGAINST**: `samlSpMetadataSigningCertificate` on the entry. With it set, an
  // unsigned document, or one whose signature does not verify, is refused.
  // Without it the signature is recorded as `signed-not-verified` and the
  // document consumed — the operator's choice of source stands in for it, as
  // above, and saying "verified" about a signature checked against the key
  // inside the same document would be the decoration `request_signature.ts`
  // refuses for requests.
  //
  // THREE MORE REFUSALS: the document's entityID must be this application's
  // (a document for somebody else would register somebody else's keys); a
  // document whose validUntil has passed is expired and is not consumed
  // (saml-metadata-2.0-os section 2.2.1); and an encryption certificate this
  // service cannot encrypt to refuses the whole document, as it always did. A
  // SIGNING certificate that is not RSA is SKIPPED and reported rather than
  // refusing the document, because a service provider may publish an EC key
  // beside an RSA one and the RSA one is still worth registering.
  //
  // `validUntil` and `cacheDuration` are RECORDED and shown, and nothing
  // enforces them after consumption — this service never refetches on its
  // own. Stated on the page rather than implied.
  // ---------------------------------------------------------------------------
  consume(identifier, xml, how, actor?): Record<string, any> {
    const { applications, stsCrypto } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.consume(). identifier=" + identifier +
              ", how=" + how);
    const record = applications.get(identifier);
    if (!record) {
      this.refreshRefused('STS-SAML-0044', identifier, 'there is no such ' +
                          'application');
      log.debug("Leaving SpMetadata.consume(). No such application.");
      return { ok: false, errors: ['There is no application "' + identifier +
               '" in this registry. Create it (or register the service ' +
               'provider) first.'] };
    }
    const fields = record.fields || {};
    const parsed = this.parse(xml);
    if (!parsed.ok) {
      this.refreshRefused('STS-SAML-0052', identifier,
                          'the metadata document is unusable: ' + parsed.why);
      log.debug("Leaving SpMetadata.consume(). Unusable.");
      return { ok: false, errors: ['The metadata document is unusable: ' +
               parsed.why + '. Nothing on the entry was changed.'] };
    }
    const names = [identifier].concat(
      this.valuesOf(fields.samlEntityId));
    if (names.indexOf(String(parsed.entityId)) < 0) {
      this.refreshRefused('STS-SAML-0066', identifier, 'the document ' +
                          'describes "' + parsed.entityId + '"');
      log.debug("Leaving SpMetadata.consume(). Somebody else's entityID.");
      return { ok: false, errors: ['The document describes the entityID "' +
               parsed.entityId + '", which is not this application ("' +
               identifier + '"). Consuming it would register another ' +
               'service provider\'s keys and endpoints here. Nothing on the ' +
               'entry was changed.'] };
    }
    if (parsed.validUntil && Date.parse(parsed.validUntil) <= Date.now()) {
      this.refreshRefused('STS-SAML-0068', identifier, 'the document ' +
                          'expired at ' + parsed.validUntil);
      log.debug("Leaving SpMetadata.consume(). Expired.");
      return { ok: false, errors: ['The document\'s validUntil (' +
               parsed.validUntil + ') has passed, so it is expired ' +
               '(saml-metadata-2.0-os section 2.2.1). Nothing on the entry ' +
               'was changed.'] };
    }

    // The document's own signature.
    const anchor = this.first(fields.samlSpMetadataSigningCertificate);
    let signature = parsed.signed ? 'signed-not-verified' : 'unsigned';
    if (anchor) {
      const verdict = parsed.signed
        ? stsCrypto.verifyXmlSignature(String(xml),
          { element: 'EntityDescriptor', certPem: this.toPem(anchor) })
        : { ok: false, why: 'the document is unsigned' };
      if (!verdict.ok) {
        this.refreshRefused('STS-SAML-0065', identifier, 'the document\'s ' +
                            'signature was not verified: ' + verdict.why);
        log.debug("Leaving SpMetadata.consume(). Signature refused.");
        return { ok: false, errors: ['samlSpMetadataSigningCertificate is ' +
                 'set on this application, so its metadata must be signed ' +
                 'with that key, and ' + verdict.why + '. Nothing on the ' +
                 'entry was changed.'] };
      }
      signature = 'verified';
    }

    // The encryption certificate, as it always was.
    if (parsed.certificate) {
      const bad = this.certificateProblem(parsed.certificate);
      if (bad) {
        this.refreshRefused('STS-SAML-0053', identifier, 'the metadata ' +
                            'carries a certificate this service cannot use: ' +
                            bad);
        log.debug("Leaving SpMetadata.consume(). Unusable encryption key.");
        return { ok: false, errors: ['The metadata carries an encryption ' +
                 'certificate this service cannot use: ' + bad + '. Nothing ' +
                 'on the entry was changed.'] };
      }
    }
    const skipped = (parsed.skipped || []).slice(0);
    const signing = (parsed.signingCertificates || []).filter(function (one) {
      const problem = applications.samlCertificateProblem(one);
      if (problem) {
        skipped.push('a signing certificate was not registered: ' + problem);
      }
      return !problem;
    });

    const lastOf = function (value) {
      log.debug("Entering lastOf().");
      const parts = String(value).split(' ');
      log.debug("Leaving lastOf().");
      return parts[parts.length - 1];
    };
    const secondOf = function (value) {
      log.debug("Entering secondOf().");
      log.debug("Leaving secondOf().");
      return String(value).split(' ')[1] || '';
    };
    const replacements: Record<string, unknown> = {
      samlSpMetadata: String(xml),
      samlAcsEndpoint: parsed.acsEndpoints.map(function (e) {
        return [e.index || '-', e.isDefault, e.binding, e.location].join(' ');
      }),
      samlSloEndpoint: parsed.sloEndpoints.map(function (e) {
        return [e.binding, e.location].concat(
          e.responseLocation ? [e.responseLocation] : []).join(' ');
      }),
      samlAssertionConsumerService: parsed.acs,
      samlSingleLogoutService: parsed.slo,
      samlSpNameIdFormat: parsed.nameIdFormats,
      samlSpAuthnRequestsSigned: parsed.authnRequestsSigned ? 'TRUE' : 'FALSE',
      samlSpWantAssertionsSigned:
        parsed.wantAssertionsSigned ? 'TRUE' : 'FALSE',
      samlSpMetadataValidUntil: parsed.validUntil,
      samlSpMetadataCacheDuration: parsed.cacheDuration,
      samlSpMetadataConsumedAt: new Date().toISOString() + ' ' + how,
      samlSpMetadataSignature: signature
    };
    // A document that names signing keys REPLACES the registered set: it is
    // the service provider's own statement of what it signs with, and a key it
    // has rotated away from must stop verifying. One that names none leaves
    // what an operator registered by hand.
    if (signing.length) {
      replacements.samlSigningCertificate = signing;
    }
    // Likewise the encryption certificate: replaced when the document names
    // one, left alone when it does not.
    if (parsed.certificate) {
      replacements.samlEncryptionCertificate = parsed.certificate;
    }
    const written = applications.replaceSamlMetadataFields(identifier,
      replacements, {
        how: how, actor: actor || '',
        retire: {
          samlAssertionConsumerService:
            this.valuesOf(fields.samlAcsEndpoint).map(lastOf),
          samlSingleLogoutService:
            this.valuesOf(fields.samlSloEndpoint).map(secondOf)
        }
      });
    if (!written.ok) {
      this.refreshRefused('STS-SAML-0054', identifier, 'the application ' +
                          'entry would not take the consumed metadata');
      log.debug("Leaving SpMetadata.consume(). The entry would not take it.");
      return { ok: false, errors: written.errors || [] };
    }
    skipped.forEach(function (why) {
      log.warn('saml2: consuming the metadata for ' + identifier + ': ' + why +
               '.');
    });
    log.info('saml2: consumed the metadata for ' + identifier + ' (' + how +
             '): ' + parsed.acsEndpoints.length + ' assertion consumer ' +
             'service(s), ' + parsed.sloEndpoints.length + ' single logout ' +
             'service(s), ' + signing.length + ' signing certificate(s), ' +
             (parsed.certificate ? 'an ' + parsed.certificateUse +
                                   ' certificate' : 'no encryption ' +
                                                    'certificate') +
             '; signature ' + signature + '.');
    log.debug("Leaving SpMetadata.consume(). Consumed.");
    return {
      ok: true, application: identifier, how: how,
      entityId: parsed.entityId,
      signature: signature,
      certificateUse: parsed.certificate ? parsed.certificateUse : '',
      signingCertificates: signing.length,
      assertionConsumerServices: parsed.acs,
      singleLogoutServices: parsed.slo,
      nameIdFormats: parsed.nameIdFormats,
      authnRequestsSigned: !!parsed.authnRequestsSigned,
      wantAssertionsSigned: !!parsed.wantAssertionsSigned,
      validUntil: parsed.validUntil,
      cacheDuration: parsed.cacheDuration,
      skipped: skipped,
      message: 'The metadata was consumed: ' +
               parsed.acsEndpoints.length + ' assertion consumer ' +
               'service(s) and ' + parsed.sloEndpoints.length +
               ' single logout service(s) are now REGISTERED and used, ' +
               signing.length + ' signing certificate(s) verify this ' +
               'service provider\'s requests' +
               (parsed.certificate
                 ? ', its ' + parsed.certificateUse + ' certificate is what ' +
                   'an assertion is encrypted to'
                 : '') +
               '. The document\'s own signature: ' + signature + '.' +
               (skipped.length ? ' Not registered: ' + skipped.join('; ') +
                                 '.' : '')
    };
  }

  // The first value of a single- or multi-valued field, trimmed.
  private first(value) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.first().");
    const one = Array.isArray(value) ? value[0] : value;
    log.debug("Leaving SpMetadata.first().");
    return String(one == null ? '' : one).trim();
  }

  // Every value of a field as trimmed non-empty strings.
  private valuesOf(value) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.valuesOf().");
    const list = Array.isArray(value) ? value
      : (value === undefined || value === null ? [] : [value]);
    log.debug("Leaving SpMetadata.valuesOf().");
    return list.map(function (one) {
      return String(one).trim();
    }).filter(function (one) {
      return one !== '';
    });
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SpMetadata>(
  'saml/sp_metadata',
  () => new SpMetadata(SpMetadata.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  SpMetadata: SpMetadata,
  installInstance: (instance: SpMetadata): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  parse: slot.forward('parse'),
  toPem: slot.forward('toPem'),
  certificateProblem: slot.forward('certificateProblem'),
  urlProblem: slot.forward('urlProblem'),
  fetchMetadata: slot.forward('fetchMetadata'),
  refresh: slot.forward('refresh'),
  upload: slot.forward('upload'),
  consume: slot.forward('consume')
};
