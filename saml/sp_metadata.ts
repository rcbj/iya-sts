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
//     `federation.outboundAllowHttp` on, in development mode (#171). That
//     setting is REUSED rather than copied: a deployment has decided once
//     whether this service may make a request in the clear, and a second
//     setting would be a second answer to one question. The same goes for the
//     certificate check — `federation_http.ts`'s `tlsFor()`.
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
//   * `federation.outboundAllowInsecure` (since split in three, #171) was
//     applied to the SCHEME and not to the CERTIFICATE, the opposite half
//     from the other requester: an https
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
// WHAT A METADATA QUERY MAY REGISTER, by mode (#112): `mode.js` is a leaf of
// `common/` that requires nothing reaching back here.
import mode = require('../common/mode');
// THE BACKGROUND REFRESH (#37 follow-up): it walks every trust realm, and
// each document is refreshed by ONE process of a cluster, through a claim.
// Both are libraries that require nothing reaching back here.
import realms = require('../common/realms');
import clusterClaims = require('../cluster/cluster_claims');
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
  realms: typeof realms;
  clusterClaims: typeof clusterClaims;
  mode: typeof mode;
}

// What `freshness()` answers about the metadata consumed onto an entry.
interface Freshness {
  state: string;
  consumedAt: string;
  how: string;
  validUntil: string;
  expiresAt: string;
  cacheDuration: string;
  staleAt: string;
  refreshable: boolean;
  source: string;
  why: string;
}

class SpMetadata {
  // True only while a background consumption runs — `consume()` is
  // synchronous, so nothing else can observe it set.
  private quiet = false;

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
      stsCrypto: stsCrypto,
      realms: realms,
      clusterClaims: clusterClaims,
      mode: mode
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
  parse(xml: string, wanted?: string[]): ParsedMetadata {
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
    // AN AGGREGATE (#37 follow-up): an <md:EntitiesDescriptor> — what a
    // federation operator publishes, and what an MDQ responder may answer
    // with — is read for the ONE entity this application is, found by
    // entityID at any depth of nesting. Without names to look for, which is a
    // parse nobody asked about a particular application, it is refused as it
    // always was: picking the first would register whoever happened to be
    // listed first.
    let entity = root;
    let chain = [];
    if (root.localName === 'EntitiesDescriptor') {
      const names = (wanted || []).filter(function (one) {
        return !!one;
      });
      if (!names.length) {
        log.debug("Leaving SpMetadata.parse(). An aggregate, and no name.");
        return { ok: false, why: 'this is an <md:EntitiesDescriptor> ' +
                 'holding several entities, and nothing says which of them ' +
                 'this application is' };
      }
      const found = this.entitiesIn(root, names, []);
      if (found.length !== 1) {
        log.debug("Leaving SpMetadata.parse(). " + found.length +
                  " matching entities in the aggregate.");
        return { ok: false, why: found.length
          ? 'the <md:EntitiesDescriptor> describes "' + names[0] + '" ' +
            found.length + ' times, and which one is meant cannot be told'
          : 'the <md:EntitiesDescriptor> does not describe this ' +
            'application ("' + names.join('", "') + '")' };
      }
      entity = found[0].entity;
      chain = found[0].chain;
    } else if (root.localName !== 'EntityDescriptor') {
      log.debug("Leaving SpMetadata.parse(). Not an EntityDescriptor.");
      return { ok: false, why: 'the document is <' + root.localName +
               '>, not an <md:EntityDescriptor> or <md:EntitiesDescriptor>' };
    }
    const sp = this.childrenByLocal(entity, 'SPSSODescriptor').filter(
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
      entityId: entity.getAttribute('entityID') || '',
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
      // THE EFFECTIVE EXPIRY is the earliest validUntil anywhere on the way
      // down — every enclosing EntitiesDescriptor, the EntityDescriptor, the
      // SPSSODescriptor — and the effective cacheDuration the SHORTEST
      // (saml-metadata-2.0-os section 2.3.1: an element's validity cannot
      // outlast its parent's).
      validUntil: this.earliest(chain.concat([entity, sp]).map(function (el) {
        return el.getAttribute('validUntil') || '';
      })),
      cacheDuration: this.shortest(chain.concat([entity, sp]).map(
        function (el) {
          return el.getAttribute('cacheDuration') || '';
        })),
      signed: this.childrenByLocal(root, 'Signature').length > 0 ||
              this.childrenByLocal(entity, 'Signature').length > 0,
      rootSigned: this.childrenByLocal(root, 'Signature').length > 0,
      entitySigned: this.childrenByLocal(entity, 'Signature').length > 0,
      aggregate: entity !== root,
      rootElement: root.localName,
      entityXml: entity !== root
        ? new this.deps.xmldom.XMLSerializer().serializeToString(entity) : '',
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

  // Every EntityDescriptor under an aggregate whose entityID is one of
  // `names`, with the EntitiesDescriptors that enclose it (outermost first).
  private entitiesIn(parent, names, chain) {
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering SpMetadata.entitiesIn().");
    let out = [];
    const here = chain.concat([parent]);
    this.childrenByLocal(parent, 'EntityDescriptor').forEach(function (one) {
      if (names.indexOf(String(one.getAttribute('entityID') || '')) >= 0) {
        out.push({ entity: one, chain: here });
      }
    });
    this.childrenByLocal(parent, 'EntitiesDescriptor').forEach(
      function (nested) {
        out = out.concat(self.entitiesIn(nested, names, here));
      });
    log.debug("Leaving SpMetadata.entitiesIn(). " + out.length);
    return out;
  }

  // An xs:duration in milliseconds, or -1 when it is absent or unreadable.
  // A year is 365 days and a month 30: metadata durations are hours and days
  // in practice, and the approximation only matters for a document that asks
  // to be cached for months.
  durationMs(value) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.durationMs().");
    const m = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(
      String(value || '').trim());
    if (!m || String(value).trim() === 'P' || /T$/.test(String(value).trim())) {
      log.debug("Leaving SpMetadata.durationMs(). Unreadable.");
      return -1;
    }
    const n = function (i) {
      log.debug("Entering n().");
      log.debug("Leaving n().");
      return m[i] ? Number(m[i]) : 0;
    };
    const days = n(1) * 365 + n(2) * 30 + n(3);
    log.debug("Leaving SpMetadata.durationMs().");
    return Math.round((((days * 24 + n(4)) * 60 + n(5)) * 60 + n(6)) * 1000);
  }

  // The shortest of some xs:duration values, as written; '' for none.
  private shortest(values) {
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering SpMetadata.shortest().");
    let best = '';
    values.forEach(function (one) {
      const text = String(one || '').trim();
      if (!text || self.durationMs(text) < 0) {
        return;
      }
      if (!best || self.durationMs(text) < self.durationMs(best)) {
        best = text;
      }
    });
    log.debug("Leaving SpMetadata.shortest(). " + (best || 'none'));
    return best;
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
      // THE ADDRESS, IN PRODUCT MODE (#37 follow-up): what the name resolves
      // to is checked against the internal-address rule and the connection
      // is PINNED to the address that was checked —
      // `federation_http.ts`'s `vetHost()`, which the RFC 9728 import and the
      // back-channel logout already ask. A metadata URL and an MDQ responder
      // are operators' choices, and the rule is still theirs to break only in
      // development; this path had never asked.
      fedHttp.vetHost(parsed.hostname).then(function (vetted) {
        if (!vetted.ok) {
          log.debug("Leaving SpMetadata.fetchMetadata(). The address was " +
                    "refused.");
          resolve({ ok: false, errorCode: 'STS-SAML-0079',
                    why: vetted.why });
          return;
        }
        self.dial(parsed, vetted, resolve);
      }, function (e) {
        // `vetHost()` answers rather than rejects; this is the case it did
        // not anticipate, and an address that could not be judged is one this
        // service does not dial.
        log.debug("Caught in SpMetadata.fetchMetadata(): " +
                  ((e && e.message) || e));
        resolve({ ok: false, errorCode: 'STS-SAML-0079',
                  why: 'the host could not be checked against the outbound ' +
                       'address rule: ' + ((e && e.message) || e) });
      });
    });
  }

  // THE REQUEST ITSELF, once the address is allowed — see fetchMetadata().
  private dial(parsed, vetted, resolve) {
    const { fedHttp, http, https } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering SpMetadata.dial(). " + parsed.origin);
    const url = parsed.href;
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
    if (parsed.protocol !== 'https:') {
      // Every insecure request, not only the setting — federation_http.ts's
      // rule.
      log.warn('saml2: fetching SP metadata from ' + parsed.origin +
               ' over plain http because ' +
               'federation.outboundAllowHttp is ON.');
    }
    // THE CERTIFICATE CHECK, federation's policy (#171): node's store and
    // `federation.outboundCaFile`, off only in development with
    // `federation.outboundSkipTlsVerification` on — the half the copy of this
    // policy never applied.
    const policy = parsed.protocol === 'https:'
      ? fedHttp.tlsFor(parsed.origin) : null;
    if (policy && !policy.ok) {
      log.debug("Leaving SpMetadata.dial(). " + policy.why);
      done({ ok: false, errorCode: policy.errorCode, why: policy.why });
      return;
    }
    const options: any = {
      headers: { accept: 'application/samlmetadata+xml, application/xml, ' +
                         'text/xml',
                 'user-agent': USER_AGENT },
      rejectUnauthorized: !policy || policy.rejectUnauthorized
    };
    if (policy && policy.ca) {
      options.ca = policy.ca;
    }
    if (vetted.address) {
      // PINNED to the address that was checked; the Host header and the TLS
      // server name still come from the URL.
      options.lookup = function (hostname, lookupOptions, callback) {
        log.debug("Entering lookup().");
        log.debug("Leaving lookup().");
        if (lookupOptions && lookupOptions.all) {
          callback(null, [{ address: vetted.address,
                            family: vetted.family }]);
          return;
        }
        callback(null, vetted.address, vetted.family);
      };
    }
    const request = agent.get(url, options, function (res) {
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
    log.debug("Leaving SpMetadata.dial().");
  }

  // The audit row for a refresh that did not happen. The reason sentences name
  // a URL, a status or a parser's message — never a certificate or a document
  // body.
  // error-code: none — the helper's definition, not a call to it
  private refreshRefused(code, identifier, why) {
    const { audit } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.refreshRefused().");
    // A BACKGROUND consumption writes no row per refusal: the refresher
    // records the state change instead (see `recordRefresh()`).
    if (this.quiet) {
      log.debug("Leaving SpMetadata.refreshRefused(). Quiet.");
      return;
    }
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
  refresh(identifier, options?) {
    const { applications } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    const opts = options || {};
    log.debug("Entering SpMetadata.refresh(). identifier=" + identifier);
    const record = applications.get(identifier);
    if (!record) {
      log.debug("Leaving SpMetadata.refresh(). No such application.");
      if (!opts.quiet) {
        this.refreshRefused('STS-SAML-0044', identifier, 'there is no such ' +
                                                    'application to refresh');
      }
      return Promise.resolve({ ok: false,
                               errors: ['There is no application "' +
        identifier + '" in this registry. Create it first — a metadata URL ' +
        'is an attribute on an entry, and this action never takes a URL ' +
        'from the caller.'] });
    }
    // WHERE FROM: the entry's own `samlSpMetadataUrl`, else — for an entry
    // with none — the realm's Metadata Query Protocol responder, asked for
    // this entity by name (`mdqUrlFor()`). Both are an operator's choice; the
    // request never supplies either.
    const url = this.first((record.fields || {}).samlSpMetadataUrl);
    const mdq = url ? '' : this.mdqUrlFor(identifier);
    const wanted = url || mdq;
    const how = url ? 'refresh' : (mdq ? 'mdq' : 'refresh');
    log.debug("Leaving SpMetadata.refresh(). Fetching " +
              (wanted || '(nothing)') + ".");
    return this.fetchMetadata(wanted).then(function (answer) {
      if (!answer.ok) {
        // A BACKGROUND refresh (`quiet`) writes no line and no row per
        // failure — the refresher records a state change and a periodic
        // summary instead (the standing rule against a log line per event).
        if (!opts.quiet) {
          log.warn('saml2: could not refresh metadata for ' + identifier +
                   ' — ' + answer.why + '. Nothing on the entry was ' +
                   'changed.');
          self.refreshRefused(answer.errorCode || 'STS-SAML-0051', identifier,
                              'the metadata could not be fetched: ' +
                              answer.why);
        }
        log.debug("Leaving SpMetadata.refresh(). The fetch failed.");
        return self.marked({ ok: false, why: answer.why,
          errors: ['The metadata at "' + wanted + '" could not be read: ' +
            answer.why + '. Nothing on the entry was changed, so whatever ' +
            'it already had is still in force.'] },
          answer.errorCode || 'STS-SAML-0051');
      }
      const consumed = self.consumeQuietly(!!opts.quiet, identifier,
                                           answer.xml, how, opts.actor);
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
  // https with the certificate checked (in development,
  // `federation.outboundSkipTlsVerification` may turn that off), and only
  // when an
  // administrator presses the button; an
  // upload is a document an administrator chose. That is the same act as
  // pasting the certificate into the entry by hand, which is what every
  // identity provider's "import metadata" amounts to — and a request NEVER
  // reaches this code.
  //
  // **A SIGNED DOCUMENT IS VERIFIED WHEN THERE IS SOMETHING TO VERIFY IT
  // AGAINST**: `samlSpMetadataSigningCertificate` on the entry, and — since
  // the #37 follow-up — the realm's `saml2.metadataTrustAnchors`, a
  // federation operator's keys. With either set, an unsigned document, or one
  // whose signature verifies against none of them, is refused. An aggregate
  // is verified by its OWN signature where it has one, and otherwise by the
  // signature on this entity's EntityDescriptor. Without an anchor the
  // signature is recorded as `signed-not-verified` and the
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
  // SIGNING certificate this service cannot verify with is SKIPPED and
  // reported rather than refusing the document — since the #37 follow-up
  // that is only a key no XML signature method uses, because RSA, EC, EdDSA,
  // DSA, ML-DSA and SLH-DSA keys are all verified.
  //
  // `validUntil` and `cacheDuration` ARE ENFORCED AFTER CONSUMPTION since
  // the #37 follow-up — see `freshness()`: past the effective validUntil the
  // service provider's requests are refused, and past cacheDuration the
  // background refresher fetches the document again.
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
    const names = [identifier].concat(
      this.valuesOf(fields.samlEntityId));
    const parsed = this.parse(xml, names);
    if (!parsed.ok) {
      this.refreshRefused('STS-SAML-0052', identifier,
                          'the metadata document is unusable: ' + parsed.why);
      log.debug("Leaving SpMetadata.consume(). Unusable.");
      return { ok: false, errors: ['The metadata document is unusable: ' +
               parsed.why + '. Nothing on the entry was changed.'] };
    }
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

    // The document's own signature, against the TRUST ANCHORS: this entry's
    // `samlSpMetadataSigningCertificate` and the realm's
    // `saml2.metadataTrustAnchors` (a federation operator's keys). With any
    // anchor configured the document MUST verify against one of them; with
    // none a signature is recorded and not believed.
    const anchors = this.trustAnchorsFor(fields);
    let signature = parsed.signed ? 'signed-not-verified' : 'unsigned';
    if (anchors.length) {
      const verdict = this.verifyAgainst(String(xml), parsed, anchors);
      if (!verdict.ok) {
        this.refreshRefused('STS-SAML-0065', identifier, 'the document\'s ' +
                            'signature was not verified: ' + verdict.why);
        log.debug("Leaving SpMetadata.consume(). Signature refused.");
        return { ok: false, errors: ['This service provider\'s metadata ' +
                 'must be signed by a trust anchor (' + anchors.length +
                 ' configured: samlSpMetadataSigningCertificate on the ' +
                 'entry and saml2.metadataTrustAnchors), and ' + verdict.why +
                 '. Nothing on the entry was changed.'] };
      }
      signature = 'verified';
    }

    // The encryption certificate. One marked use="encryption" that cannot be
    // encrypted to refuses the document, as it always did; an UNQUALIFIED key
    // that is not RSA is a signing key (EC, EdDSA, post-quantum) and is simply
    // not used for encryption.
    const skipped = (parsed.skipped || []).slice(0);
    if (parsed.certificate) {
      const bad = this.certificateProblem(parsed.certificate);
      if (bad && parsed.certificateUse !== 'encryption') {
        skipped.push('the unqualified key is not an encryption key: ' + bad);
        parsed.certificate = '';
      } else if (bad) {
        this.refreshRefused('STS-SAML-0053', identifier, 'the metadata ' +
                            'carries a certificate this service cannot use: ' +
                            bad);
        log.debug("Leaving SpMetadata.consume(). Unusable encryption key.");
        return { ok: false, errors: ['The metadata carries an encryption ' +
                 'certificate this service cannot use: ' + bad + '. Nothing ' +
                 'on the entry was changed.'] };
      }
    }
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
      // An explicit use="encryption" key is the service provider asking for
      // encrypted assertions (see the attribute's schema row).
      samlSpWantAssertionsEncrypted:
        parsed.certificate && parsed.certificateUse === 'encryption'
          ? 'TRUE' : 'FALSE',
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
    const quiet = this.quiet;
    skipped.forEach(function (why) {
      if (!quiet) {
        log.warn('saml2: consuming the metadata for ' + identifier + ': ' +
                 why + '.');
      }
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

  // `consume()`, with its per-refusal audit rows withheld when `quiet`.
  private consumeQuietly(quiet, identifier, xml, how, actor) {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.consumeQuietly(). quiet=" + quiet);
    this.quiet = quiet;
    try {
      const out = this.consume(identifier, xml, how, actor);
      if (!out.ok && !out.why) {
        out.why = (out.errors || []).join(' ');
      }
      log.debug("Leaving SpMetadata.consumeQuietly().");
      return out;
    } finally {
      this.quiet = false;
    }
  }

  // A result carrying its error code, the registry's own way (a Symbol, so
  // it is never serialised to a caller).
  private marked(result, code) {
    const { errorCodes } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.marked(). " + code);
    log.debug("Leaving SpMetadata.marked().");
    return errorCodes.mark(result, code);
  }

  // ---------------------------------------------------------------------------
  // THE TRUST ANCHORS FOR A METADATA DOCUMENT (#37 follow-up): the entry's
  // own certificate, then the realm's list. Base64 DER, deduplicated; a value
  // that is not a certificate this service verifies with is left out here and
  // named by `anchorProblems()` on the page.
  // ---------------------------------------------------------------------------
  trustAnchorsFor(fields?) {
    const { stsCrypto } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.trustAnchorsFor().");
    const out = [];
    const add = function (value) {
      log.debug("Entering add().");
      const der = String(value || '').replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, '');
      if (der && out.indexOf(der) < 0 &&
          !stsCrypto.xmlSignatureKeyProblem(der)) {
        out.push(der);
      }
      log.debug("Leaving add().");
    };
    add(this.first((fields || {}).samlSpMetadataSigningCertificate));
    this.realmAnchorValues().forEach(add);
    log.debug("Leaving SpMetadata.trustAnchorsFor(). " + out.length);
    return out;
  }

  // The realm's configured anchors as written, and what is wrong with each.
  realmAnchorValues(): string[] {
    const { config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.realmAnchorValues().");
    const raw = config.value('saml2.metadataTrustAnchors');
    const list = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) {
        return String(one).trim();
      }).filter(function (one) {
        return !!one;
      });
    log.debug("Leaving SpMetadata.realmAnchorValues(). " + list.length);
    return list;
  }

  anchorProblems(): string[] {
    const { stsCrypto } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.anchorProblems().");
    const out = [];
    this.realmAnchorValues().forEach(function (value, i) {
      const problem = stsCrypto.xmlSignatureKeyProblem(
        value.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
      if (problem) {
        out.push('saml2.metadataTrustAnchors entry ' + (i + 1) + ' is not ' +
                 'used: ' + problem);
      }
    });
    log.debug("Leaving SpMetadata.anchorProblems(). " + out.length);
    return out;
  }

  // Verify a document's signature against any of `anchors`: the aggregate's
  // own signature where it has one, else this entity's. `{ ok, why }`.
  private verifyAgainst(xml, parsed, anchors) {
    const { stsCrypto } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.verifyAgainst().");
    if (!parsed.signed) {
      log.debug("Leaving SpMetadata.verifyAgainst(). Unsigned.");
      return { ok: false, why: 'the document is unsigned' };
    }
    const document = parsed.rootSigned ? xml
      : (parsed.aggregate ? parsed.entityXml : xml);
    const element = parsed.rootSigned ? parsed.rootElement
                                      : 'EntityDescriptor';
    let why = '';
    for (let i = 0; i < anchors.length; i++) {
      const verdict: any = stsCrypto.verifyXmlSignature(document,
        { element: element, certPem: this.toPem(anchors[i]) });
      if (verdict.ok) {
        log.debug("Leaving SpMetadata.verifyAgainst(). Anchor " + (i + 1));
        return { ok: true, why: '', weak: !!verdict.weak };
      }
      why = verdict.why;
    }
    log.debug("Leaving SpMetadata.verifyAgainst(). None verified.");
    return { ok: false, why: 'its signature verifies against none of the ' +
             anchors.length + ' trust anchor(s): ' + why };
  }

  // ---------------------------------------------------------------------------
  // THE METADATA QUERY PROTOCOL (draft-young-md-query, and its SAML profile
  // draft-young-md-query-saml): `<base>/entities/<percent-encoded entityID>`,
  // GET, answered with the entity's metadata. The base is the realm's
  // `saml2.mdqBaseUrl` — an operator's choice, like `samlSpMetadataUrl` —
  // and the entityID is the only part a request can influence, encoded so it
  // is one path segment of that operator's server. '' when unconfigured.
  // ---------------------------------------------------------------------------
  mdqUrlFor(entityId) {
    const { config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.mdqUrlFor().");
    const base = String(config.value('saml2.mdqBaseUrl') || '').trim()
      .replace(/\/+$/, '');
    log.debug("Leaving SpMetadata.mdqUrlFor(). " + (base ? 'set' : 'unset'));
    return base && entityId
      ? base + '/entities/' + encodeURIComponent(String(entityId)) : '';
  }

  // IMPORT ONE SERVICE PROVIDER FROM THE MDQ RESPONDER, by entityID: the
  // console's and `/admin-api`'s `mdq-import`, and the background lookup
  // below. An entry that does not exist is created ONLY once the responder has
  // answered with a document that parses for that entity — and removed again
  // if consuming it is then refused — so a name nobody publishes leaves
  // nothing behind.
  //
  // **WHO STARTED IT DECIDES WHAT THE ANSWER MAY DO (2026-09-23, #112).**
  // `options.origin` is `'operator'` for the console and the API, and
  // `'request'` — the default, because it is the stricter — for the lookup an
  // AuthnRequest starts. The entityID of a request-started lookup is chosen
  // by whoever sent the request, which is anybody, so in PRODUCT
  // (`mode.registersFromMetadataQuery()` false) a request never registers an
  // entity on an answer nobody vouched for:
  //
  //   * request, entity unknown, no realm trust anchor: NOTHING IS FETCHED
  //     (`STS-SAML-0080`) — an unverifiable answer could only be refused, so
  //     asking would only spend the responder's time on an invented name;
  //   * request, entity unknown, anchors set: the answer is VERIFIED against
  //     the realm's anchors BEFORE the entry is created (`STS-SAML-0081`) —
  //     the entry has no certificate of its own yet, so the realm's are the
  //     only ones that can vouch for it;
  //   * operator, no realm trust anchor: REFUSED (`STS-SAML-0084`) unless
  //     `saml2.mdqImportWithoutAnchors` is on, whose description carries the
  //     warning — the administrator's choice of entityID is then the only
  //     thing standing in for the signature.
  //
  // draft-young-md-query-25 section 6.1 RECOMMENDS integrity checking of what
  // a responder returns, and draft-young-md-query-saml-25 section 4.1 makes a
  // signature embedded in the document the RECOMMENDED mechanism; an
  // unsigned answer to a lookup an unauthenticated request started is
  // exactly what neither asks anybody to trust. An entry that ALREADY EXISTS
  // is refreshed from MDQ as before, in both modes: somebody registered it.
  mdqImport(entityId, options?) {
    const { applications, config, mode } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    const opts = options || {};
    const origin = opts.origin === 'operator' ? 'operator' : 'request';
    log.debug("Entering SpMetadata.mdqImport(). " + entityId + ", origin=" +
              origin);
    const url = this.mdqUrlFor(entityId);
    if (!url) {
      log.debug("Leaving SpMetadata.mdqImport(). Not configured.");
      return Promise.resolve(this.marked({ ok: false, errors: [
        'saml2.mdqBaseUrl is not set in this realm, so there is no Metadata ' +
        'Query responder to ask.'] }, 'STS-SAML-0075'));
    }
    const known = !!applications.get(entityId);
    const realmAnchors = this.trustAnchorsFor({});
    const vouched = mode.registersFromMetadataQuery();
    if (origin === 'operator' && !vouched && !realmAnchors.length &&
        !config.value('saml2.mdqImportWithoutAnchors')) {
      this.refreshRefused('STS-SAML-0084', entityId, 'this realm is in ' +
                          'product mode and has no metadata trust anchor ' +
                          'to verify the answer with');
      log.debug("Leaving SpMetadata.mdqImport(). Operator, no anchor.");
      return Promise.resolve(this.marked({ ok: false, errors: [
        'This realm is in product mode and has no ' +
        'saml2.metadataTrustAnchors, so nothing could verify what the ' +
        'Metadata Query responder answers — and what it answers becomes ' +
        'the keys this service provider\'s requests are verified against ' +
        'and the addresses assertions are sent to. Set a trust anchor (the ' +
        'federation operator\'s metadata signing certificate), or turn on ' +
        'saml2.mdqImportWithoutAnchors after reading its warning. Nothing ' +
        'was fetched.'] }, 'STS-SAML-0084'));
    }
    const gated = origin === 'request' && !known && !vouched;
    if (gated && !realmAnchors.length) {
      this.recordMdqRefusal(entityId, 'STS-SAML-0080', 'no ' +
                            'saml2.metadataTrustAnchors in this realm; ' +
                            'nothing was fetched');
      log.debug("Leaving SpMetadata.mdqImport(). Request, no anchor.");
      return Promise.resolve(this.marked({ ok: false, errors: [
        'A lookup a request started may not register "' + entityId + '" ' +
        'in product mode without a trust anchor to verify the answer ' +
        'with. Nothing was fetched.'] }, 'STS-SAML-0080'));
    }
    log.debug("Leaving SpMetadata.mdqImport(). Asking " + url);
    return this.fetchMetadata(url).then(function (answer) {
      if (!answer.ok) {
        if (!opts.quiet) {
          self.refreshRefused(answer.errorCode || 'STS-SAML-0051', entityId,
                              'the MDQ responder did not answer: ' +
                              answer.why);
        }
        return self.marked({ ok: false, why: answer.why, errors: [
          'The Metadata Query responder did not answer for "' + entityId +
          '": ' + answer.why + '.'] }, answer.errorCode || 'STS-SAML-0051');
      }
      const parsed = self.parse(answer.xml, [String(entityId)]);
      if (!parsed.ok || parsed.entityId !== String(entityId)) {
        if (!opts.quiet) {
          self.refreshRefused('STS-SAML-0052', entityId, 'the MDQ answer ' +
                              'is unusable: ' + (parsed.why || 'another ' +
                              'entity'));
        }
        return self.marked({ ok: false, errors: ['The Metadata Query ' +
          'responder\'s answer for "' + entityId + '" is unusable: ' +
          (parsed.why || 'it describes "' + parsed.entityId + '"') + '.'] },
          'STS-SAML-0052');
      }
      // THE ANSWER IS VERIFIED BEFORE ANYTHING EXISTS: an entry created and
      // then removed when consume() refused it would be a registration an
      // anonymous request made, however briefly — visible to a concurrent
      // request, and a directory write per invented entityID.
      if (gated) {
        const verdict = self.verifyAgainst(String(answer.xml), parsed,
                                           realmAnchors);
        if (!verdict.ok) {
          self.recordMdqRefusal(entityId, 'STS-SAML-0081', 'the answer ' +
                                'did not verify against a realm trust ' +
                                'anchor: ' + verdict.why);
          return self.marked({ ok: false, errors: ['The Metadata Query ' +
            'responder\'s answer for "' + entityId + '" was not ' +
            'registered: ' + verdict.why + '.'] }, 'STS-SAML-0081');
        }
      }
      let created = false;
      if (!applications.get(entityId)) {
        const made = applications.createApplication({
          identifier: String(entityId), kind: 'saml2-service-provider',
          protocol: 'SAML 2.0',
          note: 'imported from the Metadata Query responder',
          fields: { samlEntityId: String(entityId) }
        });
        if (!made.ok) {
          return made;
        }
        created = true;
      }
      const consumed = self.consumeQuietly(!!opts.quiet, entityId,
                                           answer.xml, 'mdq', opts.actor);
      if (!consumed.ok && created) {
        applications.deleteApplication(entityId, { actor: 'saml2 MDQ' });
      }
      if (consumed.ok) {
        consumed.url = url;
        consumed.created = created;
        if (!vouched && origin === 'operator' && !realmAnchors.length) {
          // saml2.mdqImportWithoutAnchors let it through: say so on the
          // reply and in the log, every time, because the reply is the
          // administrator's only chance to notice what they consumed.
          consumed.warnings = ['The document was consumed WITHOUT a ' +
            'signature check (saml2.mdqImportWithoutAnchors is on and the ' +
            'realm has no trust anchor). Its keys and endpoints are ' +
            'whatever the responder answered.'];
          consumed.message = consumed.warnings[0] + ' ' +
                             String(consumed.message || '');
          log.warn('saml2: imported "' + entityId + '" from the Metadata ' +
                   'Query responder with NO signature check ' +
                   '(saml2.mdqImportWithoutAnchors).');
        }
      }
      return consumed;
    });
  }

  // THE ASYNCHRONOUS LOOKUP an SSO request for a service provider with no
  // consumed metadata starts, and never waits on (`saml2_sso.ts`): that
  // request is answered with what is known NOW — which in product mode is a
  // refusal of any unregistered return address — and the NEXT one finds the
  // registration. One lookup per entityID at a time, and a name that failed
  // is not asked again until the refresh interval has passed, so a stream of
  // invented entityIDs costs the responder one request each per interval.
  //
  // In PRODUCT with no realm trust anchor an unknown entityID is not queued
  // at all (#112, `STS-SAML-0080`, see mdqImport()): it is recorded as
  // refused and nothing is fetched.
  queueMdqLookup(entityId) {
    const { applications, mode, realms } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering SpMetadata.queueMdqLookup(). " + entityId);
    if (!entityId || !this.mdqUrlFor(entityId)) {
      log.debug("Leaving SpMetadata.queueMdqLookup(). Nothing to ask.");
      return false;
    }
    if (!mode.registersFromMetadataQuery() &&
        !applications.get(entityId) && !this.trustAnchorsFor({}).length) {
      this.recordMdqRefusal(entityId, 'STS-SAML-0080', 'no ' +
                            'saml2.metadataTrustAnchors in this realm; ' +
                            'nothing was fetched');
      log.debug("Leaving SpMetadata.queueMdqLookup(). Refused: product, " +
                "unknown, no anchor.");
      return false;
    }
    const key = realms.currentId() + '\u0000' + entityId;
    const last = mdqLookups.get(key);
    if (last && (last.pending ||
                 Date.now() - last.at < this.refreshIntervalMs())) {
      log.debug("Leaving SpMetadata.queueMdqLookup(). Asked recently.");
      return false;
    }
    mdqLookups.set(key, { pending: true, at: Date.now() });
    const realm = realms.current();
    setImmediate(function () {
      realms.run(realm, function () {
        self.mdqImport(entityId, { quiet: true, origin: 'request' })
          .then(function (answer) {
            mdqLookups.set(key, { pending: false, at: Date.now(),
                                  ok: !!answer.ok });
          });
      });
    });
    log.debug("Leaving SpMetadata.queueMdqLookup(). Queued.");
    return true;
  }

  // ---------------------------------------------------------------------------
  // THE ENTITYIDS A REQUEST-STARTED LOOKUP WAS REFUSED FOR (#112), per realm
  // and shared by every process (a replicated store since 2026-09-23 — see
  // its declaration at the foot of this file), drawn on the SAML 2.0 page
  // and `GET /admin-api/saml2` (`mdqRefused`). A row per
  // entityID, newest first, with how often and when; bounded by
  // MDQ_REFUSALS_MAX (the oldest is dropped at the insert, which is the cap
  // rather than housekeeping, so it is no scheduler job). Logged when a realm
  // STARTS refusing and summarised at most hourly — never a line per request,
  // because the requests are anybody's and a stream of invented entityIDs
  // would otherwise be a stream of log lines. One audit row per entityID the
  // first time it is refused, carrying the code.
  // ---------------------------------------------------------------------------
  private recordMdqRefusal(entityId, code, why) {
    const { audit, realms } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.recordMdqRefusal(). " + code);
    const realmId = realms.currentId();
    const key = String(entityId);
    const now = new Date().toISOString();
    const before = mdqRefusals.get(key);
    if (before) {
      mdqRefusals.delete(key);
    } else if (mdqRefusals.size >= MDQ_REFUSALS_MAX) {
      mdqRefusals.delete(mdqRefusals.keys().next().value);
    }
    mdqRefusals.set(key, {
      realm: realmId, entityId: String(entityId), errorCode: code, why: why,
      firstAt: before ? before.firstAt : now, lastAt: now,
      count: before ? before.count + 1 : 1
    });
    refusalSummary.since++;
    // The first refusal is logged below as the change it is, so the hourly
    // summary starts counting from here rather than repeating it at once.
    if (!refusalSummary.at) {
      refusalSummary.at = Date.now();
    }
    if (!before) {
      audit.audit({
        // error-code: none — the helper's own row; both callers pass theirs
        action: 'saml2.metadata.mdq', outcome: 'refused', errorCode: code,
        protocol: 'SAML 2.0', channel: 'http', target: String(entityId),
        summary: 'A Metadata Query lookup a request started for "' +
                 entityId + '" registered nothing: ' + why,
        detail: { realm: realmId }
      });
    }
    if (!refusingRealms.has(realmId)) {
      refusingRealms.add(realmId);
      log.warn(this.deps.errorCodes.tag(code) + 'saml2: realm "' +
               (realmId || '(default)') + '" is refusing Metadata Query ' +
               'lookups that requests start for unregistered entityIDs ' +
               '(product mode: ' + why + '). Logged once; the entityIDs ' +
               'are listed on the SAML 2.0 page and summarised hourly.');
    }
    this.summariseRefusals();
    log.debug("Leaving SpMetadata.recordMdqRefusal().");
  }

  // At most one line an hour while lookups are being refused.
  private summariseRefusals() {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.summariseRefusals().");
    if (refusalSummary.since &&
        Date.now() - refusalSummary.at >= 3600000) {
      log.warn(this.deps.errorCodes.tag('STS-SAML-0080') + 'saml2: ' +
               refusalSummary.since + ' Metadata Query lookup(s) for ' +
               'unregistered entityIDs refused since the last summary; ' +
               mdqRefusals.size + ' entityID(s) listed.');
      refusalSummary.at = Date.now();
      refusalSummary.since = 0;
    }
    log.debug("Leaving SpMetadata.summariseRefusals().");
  }

  // The refused entityIDs of the ambient realm, newest first.
  mdqRefusalList(): Array<Record<string, any>> {
    const { realms } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.mdqRefusalList().");
    const realmId = realms.currentId();
    const out = [];
    mdqRefusals.forEach(function (row) {
      if (row && row.realm === realmId) {
        out.push({ entityId: row.entityId, errorCode: row.errorCode,
                   why: row.why, firstAt: row.firstAt, lastAt: row.lastAt,
                   count: row.count });
      }
    });
    // By time rather than by insertion order: a row another process wrote
    // arrives in the order replication applied it.
    out.sort(function (a, b) {
      return String(b.lastAt).localeCompare(String(a.lastAt));
    });
    log.debug("Leaving SpMetadata.mdqRefusalList(). " + out.length);
    return out;
  }

  // ---------------------------------------------------------------------------
  // HOW CURRENT THE CONSUMED METADATA IS (#37 follow-up), in every mode:
  //
  //   none     nothing was consumed onto this entry
  //   fresh    consumed, and neither of the two times below has passed
  //   stale    cacheDuration has elapsed since it was consumed — the
  //            refresher fetches it again where it can (`refreshable`), and it
  //            keeps WORKING until validUntil
  //   expired  the effective validUntil has passed: the service provider's
  //            SSO and SLO requests are REFUSED (`STS-SAML-0074`) until a
  //            newer document is consumed
  //
  // With no cacheDuration a document is stale halfway between its
  // consumption and its validUntil, so it is fetched again before it
  // expires; with neither, it never goes stale. Nothing here dials anything.
  // ---------------------------------------------------------------------------
  freshness(fields?, now?): Freshness {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.freshness().");
    const f = fields || {};
    const at = Number.isFinite(now) ? now : Date.now();
    const consumedText = this.first(f.samlSpMetadataConsumedAt);
    const consumedAt = Date.parse(consumedText.split(' ')[0] || '');
    const how = consumedText.split(' ')[1] || '';
    const validUntil = this.first(f.samlSpMetadataValidUntil);
    const expires = validUntil ? Date.parse(validUntil) : NaN;
    const cacheDuration = this.first(f.samlSpMetadataCacheDuration);
    const cacheMs = this.durationMs(cacheDuration);
    const url = this.first(f.samlSpMetadataUrl);
    const out: Freshness = {
      state: 'none', consumedAt: '', how: how, validUntil: validUntil,
      expiresAt: Number.isFinite(expires) ? new Date(expires).toISOString()
                                          : '',
      cacheDuration: cacheDuration, staleAt: '',
      // Refreshable by the URL on the entry, or — for a document the MDQ
      // responder answered with — by that responder, if the realm still has
      // one. ('x' only asks whether one is configured.)
      refreshable: !!url || (how === 'mdq' &&
                             !!this.mdqUrlFor(this.first(f.samlEntityId) ||
                                              'x')),
      source: url ? 'url' : how, why: ''
    };
    if (!Number.isFinite(consumedAt)) {
      out.why = 'no metadata has been consumed';
      log.debug("Leaving SpMetadata.freshness(). None.");
      return out;
    }
    out.consumedAt = new Date(consumedAt).toISOString();
    const staleAt = cacheMs >= 0 ? consumedAt + cacheMs
      : (Number.isFinite(expires) ? consumedAt + (expires - consumedAt) / 2
                                  : NaN);
    out.staleAt = Number.isFinite(staleAt)
      ? new Date(staleAt).toISOString() : '';
    if (Number.isFinite(expires) && expires <= at) {
      out.state = 'expired';
      out.why = 'the consumed metadata expired at ' + out.expiresAt +
                ' (its effective validUntil) and must be refreshed';
    } else if (Number.isFinite(staleAt) && staleAt <= at) {
      out.state = 'stale';
      out.why = 'the consumed metadata is past its cacheDuration (stale ' +
                'since ' + out.staleAt + ') and ' + (out.refreshable
                  ? 'is due to be fetched again'
                  : 'was uploaded, so nothing here can fetch it again') +
                '; it is still used until ' + (out.expiresAt || 'replaced');
    } else {
      out.state = 'fresh';
    }
    log.debug("Leaving SpMetadata.freshness(). " + out.state);
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE BACKGROUND REFRESHER (#37 follow-up). A timer started from
  // `server.js`'s `announce()` — the front process's listen path, never a
  // require and never a request worker — that every
  // `saml2.spMetadataRefreshIntervalS` walks every trust realm's service
  // providers and fetches again each STALE document it can (a
  // `samlSpMetadataUrl`, or one imported by MDQ), through `refresh()` and so
  // through the federation outbound policy.
  //
  //   * ONE PROCESS PER CLUSTER refreshes a given document: each is claimed
  //     (`cluster_claims`, scope `saml2.sp-metadata-refresh`, keyed by realm,
  //     entity and the consumption being replaced) before it is fetched. On a
  //     store that cannot be shared the claim is this process's, which is the
  //     only process there is.
  //   * A FAILED REFRESH CHANGES NOTHING ON THE ENTRY, so the last good
  //     document keeps working until its validUntil. It is recorded as a
  //     STATE — `refreshStatus()`, drawn on the SAML 2.0 page — and logged
  //     only when that state changes, plus one summary line per hour while
  //     anything is failing. Never a line per failed attempt.
  //   * `saml2.spMetadataRefresh` off stops it at the next tick.
  //   * The timer is unreferenced: it is never why a process stays up.
  // ---------------------------------------------------------------------------
  refreshIntervalMs() {
    const { config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.refreshIntervalMs().");
    log.debug("Leaving SpMetadata.refreshIntervalMs().");
    return Number(config.value('saml2.spMetadataRefreshIntervalS')) * 1000;
  }

  // THE REFRESHER IS A SCHEDULER JOB (#49 P5): `saml2.sp-metadata-refresh`,
  // a CLUSTER job every `saml2.spMetadataRefreshIntervalS`, on the leader. It
  // was a timer in every process, each claiming a document before fetching
  // it so that one node did; the job runs once for the cluster, and the claim
  // stays as the guard for a refresh asked for by hand at the same moment.
  // `server.js` still calls this, where the timer was started.
  startRefresher() {
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering SpMetadata.startRefresher().");
    const scheduler = require('../cluster/scheduler');
    if (scheduler.job(REFRESH_JOB)) {
      log.debug("Leaving SpMetadata.startRefresher(). Already registered.");
      return false;
    }
    scheduler.register({
      id: REFRESH_JOB,
      title: 'SAML service provider metadata refresher',
      describe: 'Fetches again every service provider\'s metadata that is ' +
                'past its cacheDuration, from its samlSpMetadataUrl or the ' +
                'MDQ responder; a document past its validUntil is refused.',
      owner: 'saml/sp_metadata.ts',
      everySetting: 'saml2.spMetadataRefreshIntervalS', everySettingUnit: 's',
      run: function () {
        return self.sweepOnce();
      }
    });
    log.info('saml2: the service provider metadata refresher is the ' +
             'scheduler job ' + REFRESH_JOB + ', every ' +
             (this.refreshIntervalMs() / 1000) + 's ' +
             '(saml2.spMetadataRefreshIntervalS): a document past its ' +
             'cacheDuration is fetched again from its samlSpMetadataUrl or ' +
             'the MDQ responder, and one past its validUntil is refused.');
    log.debug("Leaving SpMetadata.startRefresher().");
    return true;
  }

  // Nothing to stop: the scheduler owns the job, and `scheduler.stop()` in
  // the shutdown stops every job at once. Kept for its callers.
  stopRefresher() {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.stopRefresher().");
    log.debug("Leaving SpMetadata.stopRefresher().");
  }

  // ONE PASS over every realm. Resolves to `{ due, refreshed, failed,
  // skipped }` and never rejects.
  sweepOnce(): Promise<Record<string, number>> {
    const { config, realms } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering SpMetadata.sweepOnce().");
    const totals = { due: 0, refreshed: 0, failed: 0, skipped: 0 };
    let chain: Promise<unknown> = Promise.resolve();
    realms.list().forEach(function (realm) {
      chain = chain.then(function () {
        return realms.run(realm, function () {
          if (!config.value('saml2.spMetadataRefresh')) {
            return null;
          }
          return self.sweepRealm(totals);
        });
      });
    });
    log.debug("Leaving SpMetadata.sweepOnce().");
    return chain.then(function () {
      self.summarise();
      return totals;
    }, function (e) {
      log.debug("Caught in SpMetadata.sweepOnce(): " +
                ((e && e.message) || e));
      return totals;
    });
  }

  private sweepRealm(totals) {
    const { applications, clusterClaims, realms } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering SpMetadata.sweepRealm().");
    const realmId = realms.currentId();
    const due = applications.list().filter(function (row) {
      const fresh = self.freshness(row.fields || {});
      return fresh.refreshable &&
        (fresh.state === 'stale' || fresh.state === 'expired');
    });
    totals.due += due.length;
    log.debug("Leaving SpMetadata.sweepRealm(). " + due.length + " due.");
    return due.reduce(function (chain, row) {
      return chain.then(function () {
        const consumed = self.first((row.fields || {})
          .samlSpMetadataConsumedAt);
        return clusterClaims.claim({
          scope: 'saml2.sp-metadata-refresh',
          value: realmId + '\n' + row.identifier + '\n' + consumed,
          ttlMs: self.refreshIntervalMs()
        }).then(function (claimed) {
          if (!claimed.ok) {
            totals.skipped++;
            return null;
          }
          return self.refresh(row.identifier, { quiet: true,
                                                actor: 'saml2 refresher' })
            .then(function (answer) {
              self.recordRefresh(realmId, row.identifier, answer);
              if (answer.ok) {
                totals.refreshed++;
              } else {
                totals.failed++;
              }
            });
        });
      });
    }, Promise.resolve());
  }

  // The state a refresh leaves behind, and a line when it CHANGES.
  private recordRefresh(realmId, identifier, answer) {
    const { audit } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.recordRefresh(). " + identifier);
    const key = realmId + '\u0000' + identifier;
    const before = refreshStates.get(key);
    const now = new Date().toISOString();
    const why = answer.ok ? '' : String(answer.why ||
      (answer.errors || []).join(' '));
    const state = {
      ok: !!answer.ok, lastAttemptAt: now,
      lastSuccessAt: answer.ok ? now : (before ? before.lastSuccessAt : ''),
      failingSince: answer.ok ? '' : ((before && !before.ok)
        ? before.failingSince : now),
      failures: answer.ok ? 0 : ((before && !before.ok)
        ? before.failures + 1 : 1),
      why: why
    };
    refreshStates.set(key, state);
    if (!before || before.ok !== state.ok) {
      const code = answer.ok ? '' : (this.deps.errorCodes.codeOf(answer) ||
                                     'STS-SAML-0076');
      audit.audit({
        action: 'saml2.metadata.refresh',
        outcome: answer.ok ? 'success' : 'failure',
        errorCode: answer.ok ? '' : 'STS-SAML-0076',
        protocol: 'SAML 2.0', channel: 'internal', target: identifier,
        summary: 'The background refresh of "' + identifier + '"\'s ' +
                 'metadata ' + (answer.ok ? 'succeeded' +
                 (before ? ' again' : '') : 'started failing: ' + why),
        detail: { realm: realmId, cause: code }
      });
      if (answer.ok) {
        log.info('saml2: the metadata of "' + identifier + '" was refreshed ' +
                 'in the background' + (before ? ', after ' + before.failures +
                 ' failed attempt(s)' : '') + '.');
      } else {
        log.warn(this.deps.errorCodes.tag('STS-SAML-0076') + 'saml2: the ' +
                 'background refresh of "' + identifier + '"\'s metadata ' +
                 'is failing (' + why + '). The last good document stays in ' +
                 'force until its validUntil; this is logged once, and again ' +
                 'only when it recovers.');
      }
    }
    log.debug("Leaving SpMetadata.recordRefresh().");
  }

  // One summary line per hour while any background refresh is failing.
  private summarise() {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.summarise().");
    const failing = [];
    refreshStates.forEach(function (state, key) {
      if (!state.ok) {
        failing.push(key.split('\u0000').join('/'));
      }
    });
    if (failing.length && Date.now() - refresher.summaryAt >= 3600000) {
      refresher.summaryAt = Date.now();
      log.warn(this.deps.errorCodes.tag('STS-SAML-0076') + 'saml2: ' +
               failing.length + ' service provider metadata refresh(es) ' +
               'still failing: ' + failing.slice(0, 10).join(', ') +
               (failing.length > 10 ? ', …' : '') + '.');
    }
    this.summariseRefusals();
    log.debug("Leaving SpMetadata.summarise(). " + failing.length);
  }

  // What the refresher last found for one entity in the ambient realm, or
  // null when it has not tried.
  refreshStatus(identifier) {
    const { realms } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.refreshStatus().");
    const state = refreshStates.get(realms.currentId() + '\u0000' +
                                    identifier);
    log.debug("Leaving SpMetadata.refreshStatus().");
    return state ? Object.assign({}, state) : null;
  }

  refresherRunning(): boolean {
    const { log } = this.deps.helpers;
    log.debug("Entering SpMetadata.refresherRunning().");
    const scheduler = require('../cluster/scheduler');
    const job = scheduler.job(REFRESH_JOB);
    log.debug("Leaving SpMetadata.refresherRunning().");
    return !!job && !scheduler.scheduler.offReason(job);
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
// The refresher's scheduler job (#49 P5): see startRefresher().
const REFRESH_JOB = 'saml2.sp-metadata-refresh';

// THE REFRESHER'S STATE, per process: when it last summarised,
// what each background refresh last found (realm \0 entity), and the MDQ
// lookups a request started. Process state, not a store: another node's
// refresher keeps its own, and a restart begins with nothing tried.
const refresher: { summaryAt: number } = { summaryAt: 0 };
const refreshStates = new Map<string, any>();
const mdqLookups = new Map<string, any>();
// The entityIDs a request-started lookup was refused for (#112), per realm
// and keyed by entityID, at most MDQ_REFUSALS_MAX each. A STORE, persisted
// and replicated, unlike the refresher's state above: the refusal is
// recorded by whichever request worker answered the AuthnRequest and read
// by whichever answers `GET /admin-api/saml2`, and as a per-process Map the
// list was empty on every other worker (`sts_saml_unregistered`, single-node,
// 2026-09-23). A row is replaced whole on every refusal, never edited in
// place, so the journal sees each change. Which realms have been logged as
// refusing, and the hourly summary's count, stay per process: they decide
// log lines, and each process logs its own.
const MDQ_REFUSALS_MAX = 500;
const mdqRefusals = realms.map({ persist: 'saml2.mdqRefusals' });
const refusingRealms = new Set<string>();
const refusalSummary: { at: number, since: number } = { at: 0, since: 0 };

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
  consume: slot.forward('consume'),
  freshness: slot.forward('freshness'),
  durationMs: slot.forward('durationMs'),
  trustAnchorsFor: slot.forward('trustAnchorsFor'),
  anchorProblems: slot.forward('anchorProblems'),
  mdqUrlFor: slot.forward('mdqUrlFor'),
  mdqImport: slot.forward('mdqImport'),
  queueMdqLookup: slot.forward('queueMdqLookup'),
  mdqRefusalList: slot.forward('mdqRefusalList'),
  startRefresher: slot.forward('startRefresher'),
  stopRefresher: slot.forward('stopRefresher'),
  sweepOnce: slot.forward('sweepOnce'),
  refreshStatus: slot.forward('refreshStatus'),
  refresherRunning: slot.forward('refresherRunning')
};
