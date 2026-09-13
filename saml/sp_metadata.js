'use strict';
//
// File: sp_metadata.js
//
// ===========================================================================
// A SERVICE PROVIDER'S OWN METADATA: PARSING IT, AND FETCHING IT.
//
// Added 2026-08-27 with SAML 2.0 encryption, because encrypting to a service
// provider means holding its public key and this service had nowhere to get one
// from. `saml/CLAUDE.md` said for months that this profile "does not consume SP
// metadata"; it does now, in exactly one direction and for exactly one value.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY. It registers no route (rule 3), and it is required by
// `admin-ui/admin.js` for the refresh action and by `saml2_sso.js` for the
// parse. It requires `helpers`, `config` and `applications` and nothing that
// requires it, so it closes no cycle and moves nothing in the router.
//
// ---------------------------------------------------------------------------
// THE FETCH NEVER HAPPENS DURING A FLOW, and that is the single most important
// property here.
//
// `refresh()` is called from a console button and from
// `POST /admin-api/applications/refresh-metadata`. It writes what it found onto
// the application entry, and ISSUING READS THE ENTRY. Nothing in the sign-on
// path dials anything.
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
// length that dialling a URL is a capability this service does not hand out. The
// same three refusals apply here and for the same reasons:
//
//   * THE URL COMES OFF THE APPLICATION ENTRY and from nowhere else. `refresh()`
//     takes an application identifier, not a URL. A caller cannot ask this
//     service to dial an address of their choosing, which is the difference
//     between a metadata fetcher and an open proxy.
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
// **THE POLICY IS NOW `federation/federation_http.js`'s, NOT A COPY OF IT
// (2026-09-12)**, and four things were wrong with the copy, each quietly:
//
//   * `federation.outbound` — the switch a deployment with no egress sets so
//     that THIS SERVICE DIALS NOTHING — was never read here, so a refresh dialled
//     out of an air-gapped deployment that believed it could not;
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

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { DOMParser } = require('@xmldom/xmldom');
const forge = require('node-forge');

const { log } = require('../common/helpers');
const config = require('../common/config');
// THE ERROR CODES AND THE AUDIT LOG. A refresh is an action whose result the
// console or the management API sends back as it is, so a code cannot ride on
// that result — it would be serialised to the caller. Each refused refresh is
// an audit row carrying its code instead. `audit.js` requires nothing that
// reaches back here, so this closes no cycle.
const errorCodes = require('../common/error_codes');
const audit = require('../common/audit');
const applications = require('../common/applications');
// The outbound policy — the kill switch, the scheme rule and the insecure
// switch — from the module that owns it. A library that registers nothing and
// requires only config, helpers and version, so a require from saml/ closes no
// cycle and moves no route.
const fedHttp = require('../federation/federation_http');
// Which build is calling, in RFC 9110 product form — the rule every outbound
// requester in this service follows. Built once: the version cannot change.
const USER_AGENT = require('../common/version').userAgent('saml-sp-metadata');

// The metadata namespace, and the two this file reads inside it. Matched on
// LOCAL NAME everywhere below — `getElementsByTagNameNS('*', ...)` — because a
// metadata document may use `md:`, `saml2:` or no prefix at all and all three
// are the same document. helpers.firstByLocal() follows the same rule.
//
// The cap is `saml2.spMetadataMaxBytes` since 2026-09-12; it was the constant
// MAX_METADATA_BYTES, 512 KiB, which is still the setting's default.
function maxMetadataBytes() {
  return Number(config.value('saml2.spMetadataMaxBytes'));
}

// ---------------------------------------------------------------------------
// PARSE, and it answers rather than throws.
//
// `{ ok, certificate, entityId, acs[], slo[], why }`. What the caller wants is
// `certificate`; the rest is reported because a person looking at a metadata
// document wants to know this service read the same one they did.
//
// WHICH KEY IS THE ENCRYPTION KEY, in the order the specification implies:
// a KeyDescriptor with `use="encryption"`, then one with NO `use` at all —
// which section 2.4.1.1 says serves both purposes — and never one marked
// `use="signing"`, which is the key that would look right and be wrong. A
// document with a signing key only therefore yields no certificate here, and
// the CALLER falls back to `samlSigningCertificate` if it wants to; making that
// decision here would hide it inside a parser.
// ---------------------------------------------------------------------------
function parse(xml) {
  log.debug("Entering parse().");
  const text = String(xml || '').trim();
  if (!text) {
    log.debug("Leaving parse(). Empty.");
    return { ok: false, why: 'there is no metadata document to read' };
  }
  let doc;
  try {
    doc = new DOMParser().parseFromString(text, 'text/xml');
  } catch (e) {
    log.debug("Leaving parse(). It will not parse.");
    return { ok: false, why: 'the metadata is not well-formed XML: ' + e.message };
  }
  if (!doc || !doc.documentElement) {
    log.debug("Leaving parse(). No root element.");
    return { ok: false, why: 'the metadata has no root element' };
  }
  const root = doc.documentElement;
  // An EntitiesDescriptor holding several entities is legal and is NOT
  // supported: which of them this application is cannot be worked out from a
  // document that does not know which application it was fetched for, and
  // guessing the first would silently encrypt to whoever happened to be listed
  // first. Named rather than half-handled.
  if (root.localName === 'EntitiesDescriptor') {
    log.debug("Leaving parse(). An EntitiesDescriptor.");
    return { ok: false, why: 'this is an <md:EntitiesDescriptor> holding several entities. ' +
             'Give the <md:EntityDescriptor> for this one service provider — a document ' +
             'listing many does not say which of them this application is, and picking the ' +
             'first would encrypt to whoever happens to be listed first' };
  }

  const out = {
    ok: true,
    entityId: root.getAttribute('entityID') || '',
    certificate: '',
    certificateUse: '',
    acs: [],
    slo: []
  };

  const descriptors = doc.getElementsByTagNameNS('*', 'KeyDescriptor');
  let unqualified = '';
  for (let n = 0; n < descriptors.length; n++) {
    const use = (descriptors[n].getAttribute('use') || '').trim();
    const certs = descriptors[n].getElementsByTagNameNS('*', 'X509Certificate');
    if (!certs.length) continue;
    const value = (certs[0].textContent || '').replace(/\s+/g, '');
    if (!value) continue;
    if (use === 'encryption') {
      out.certificate = value;
      out.certificateUse = 'encryption';
      break;
    }
    if (!use && !unqualified) unqualified = value;
  }
  if (!out.certificate && unqualified) {
    out.certificate = unqualified;
    out.certificateUse = 'unspecified';
  }

  // The endpoints, reported and NOT written anywhere. This service already
  // learns an assertion consumer service URL from the request that named one,
  // which is a fact about what actually happened; a URL from metadata is a
  // claim about what should happen, and quietly preferring it would change
  // where responses go on the strength of a document somebody pasted.
  const collect = function (element, into) {
    const els = doc.getElementsByTagNameNS('*', element);
    for (let n = 0; n < els.length; n++) {
      const location = els[n].getAttribute('Location') || '';
      if (location && into.indexOf(location) < 0) into.push(location);
    }
  };
  collect('AssertionConsumerService', out.acs);
  collect('SingleLogoutService', out.slo);

  if (!out.certificate) {
    out.ok = false;
    out.why = 'the metadata carries no <md:KeyDescriptor> with an X509Certificate that ' +
              'can be used for encryption. A descriptor marked use="signing" is ' +
              'deliberately not taken — it is the key that would look right and be wrong';
  }
  log.debug("Leaving parse(). certificate=" + (out.certificate ? out.certificateUse : 'none'));
  return out;
}

// A base64 DER certificate as a PEM, which is what forge and the encryptor
// want. It ACCEPTS a PEM too, so an operator who pasted one into
// `samlEncryptionCertificate` is not told their certificate is invalid because
// of its punctuation.
function toPem(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.indexOf('-----BEGIN') === 0) return text;
  const body = text.replace(/\s+/g, '').replace(/-----[^-]+-----/g, '');
  if (!body) return '';
  return '-----BEGIN CERTIFICATE-----\n' +
         (body.match(/.{1,64}/g) || []).join('\n') +
         '\n-----END CERTIFICATE-----\n';
}

// Is this actually a certificate? Called before anything is stored, so a
// paste-o is refused at the door rather than at the next sign-in — where the
// only symptom would be an assertion quietly going out in clear.
function certificateProblem(value) {
  const pem = toPem(value);
  if (!pem) return 'it is empty';
  try {
    const cert = forge.pki.certificateFromPem(pem);
    if (!cert.publicKey || !cert.publicKey.n) {
      return 'its public key is not an RSA key, and XML Encryption key transport here ' +
             'wraps to RSA';
    }
    return '';
  } catch (e) {
    return 'it is not a certificate this service can read (' + e.message + ')';
  }
}

// The timeout, read as the setting and nothing else. See the header for the
// `|| 5000` this replaced.
function timeoutMs() {
  return Number(config.value('federation.outboundTimeoutMs'));
}

// Whether this URL may be dialled, as a sentence. The empty case is this file's
// own words; everything else is federation_http.js's rule, so the two outbound
// requesters cannot disagree about what "in the clear" means.
function urlProblem(raw) {
  const text = String(raw || '').trim();
  if (!text) return 'there is no samlSpMetadataUrl on this application';
  return fedHttp.urlProblem(text);
}

// ---------------------------------------------------------------------------
// FETCH ONE DOCUMENT. Returns a promise of `{ ok, xml, why, status }` and NEVER
// rejects, for federation_http.js's reason: a rejected promise would have to be
// caught at every call site, and the one added later would not be.
// ---------------------------------------------------------------------------
function fetchMetadata(url) {
  log.debug("Entering fetchMetadata(). url=" + url);
  return new Promise(function (resolve) {
    // THE KILL SWITCH FIRST (2026-09-12) — see the header. A deployment that set
    // `federation.outbound` off has said this process dials nothing.
    if (!fedHttp.outboundAllowed()) {
      log.debug("Leaving fetchMetadata(). federation.outbound is off.");
      resolve({ ok: false, errorCode: 'STS-SAML-0045',
                why: 'federation.outbound is off, so this service makes no outbound request ' +
                     'at all — a metadata document cannot be fetched. Paste the service ' +
                     'provider\'s certificate into samlEncryptionCertificate instead' });
      return;
    }
    const problem = urlProblem(url);
    if (problem) {
      log.debug("Leaving fetchMetadata(). Refused: " + problem);
      resolve({ ok: false, errorCode: 'STS-SAML-0046', why: problem });
      return;
    }
    const parsed = new URL(String(url).trim());
    const agent = parsed.protocol === 'https:' ? https : http;
    let settled = false;
    const done = function (answer) {
      if (settled) return;
      settled = true;
      resolve(answer);
    };
    const cap = maxMetadataBytes();
    const insecure = fedHttp.allowInsecure();
    if (parsed.protocol !== 'https:') {
      // Every insecure request, not only the setting — federation_http.js's rule.
      log.warn('saml2: fetching SP metadata from ' + parsed.origin + ' over plain http ' +
               'because federation.outboundAllowInsecure is ON.');
    }
    const request = agent.get(String(url).trim(), {
      headers: { accept: 'application/samlmetadata+xml, application/xml, text/xml',
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
               why: 'it answered ' + res.statusCode + ' with a redirect to "' +
                    (res.headers.location || '(no Location)') + '". Redirects are not ' +
                    'followed here — a redirect is how a vetted URL becomes an unvetted ' +
                    'one. Put the final URL on the entry' });
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
          // metadata document is kilobytes. Destroying the socket is what stops
          // an endless response from being read into memory.
          request.destroy();
          done({ ok: false, errorCode: 'STS-SAML-0049', why: 'the document is larger than ' + cap +
                 ' bytes (saml2.spMetadataMaxBytes), which no service provider metadata is' });
          return;
        }
        body += chunk;
      });
      res.on('end', function () {
        done({ ok: true, xml: body, status: 200 });
      });
    });
    request.setTimeout(timeoutMs(), function () {
      request.destroy();
      done({ ok: false, errorCode: 'STS-SAML-0050', why: 'it did not answer within ' + timeoutMs() +
             'ms (federation.outboundTimeoutMs)' });
    });
    request.on('error', function (e) {
      // The message is the node error's, because "self-signed certificate",
      // "connection refused" and "getaddrinfo ENOTFOUND" send somebody to three
      // different places and a single word for all three sends them nowhere.
      done({ ok: false, errorCode: 'STS-SAML-0051', why: 'the request failed: ' + e.message });
    });
  });
}

// The audit row for a refresh that did not happen. The reason sentences name a
// URL, a status or a parser's message — never a certificate or a document body.
function refreshRefused(code, identifier, why) {
  audit.failure(code, {
    protocol: 'SAML 2.0', channel: 'internal',
    target: String(identifier || ''),
    summary: 'the service provider metadata for ' + String(identifier || '(unnamed)') +
             ' was not refreshed: ' + why,
    // error-code: none — the helper's own row; every caller passes its code
    outcome: 'refused'
  });
}

// ---------------------------------------------------------------------------
// THE WHOLE ACT: fetch what the entry names, parse it, and write back what was
// found. This is what the console button and the management API both call.
//
// IT WRITES THREE ATTRIBUTES — the document, the certificate and nothing else —
// and it writes NOTHING when anything fails, so a refresh that could not reach
// the host leaves the last good certificate in place. An application that was
// working does not stop working because a metadata server was down.
// ---------------------------------------------------------------------------
function refresh(identifier) {
  log.debug("Entering refresh(). identifier=" + identifier);
  const record = applications.get(identifier);
  if (!record) {
    log.debug("Leaving refresh(). No such application.");
    refreshRefused('STS-SAML-0044', identifier, 'there is no such application to refresh');
    return Promise.resolve({ ok: false, errors: ['There is no application "' + identifier +
      '" in this registry. Create it first — a metadata URL is an attribute on an entry, ' +
      'and this action never takes a URL from the caller.'] });
  }
  const url = ((record.fields && record.fields.samlSpMetadataUrl) || '');
  const wanted = Array.isArray(url) ? url[0] : url;
  return fetchMetadata(wanted).then(function (answer) {
    if (!answer.ok) {
      log.warn('saml2: could not refresh metadata for ' + identifier + ' — ' + answer.why +
               '. Nothing on the entry was changed.');
      log.debug("Leaving refresh(). The fetch failed.");
      refreshRefused(answer.errorCode || 'STS-SAML-0051', identifier,
                     'the metadata could not be fetched: ' + answer.why);
      return { ok: false, errors: ['The metadata at "' + wanted + '" could not be read: ' +
        answer.why + '. Nothing on the entry was changed, so whatever certificate it ' +
        'already had is still in force.'] };
    }
    const parsed = parse(answer.xml);
    if (!parsed.ok) {
      log.debug("Leaving refresh(). The document is unusable.");
      refreshRefused('STS-SAML-0052', identifier,
                     'the fetched metadata document is unusable: ' + parsed.why);
      return { ok: false, errors: ['The document at "' + wanted + '" was fetched but ' +
        parsed.why + '. Nothing on the entry was changed.'] };
    }
    const bad = certificateProblem(parsed.certificate);
    if (bad) {
      log.debug("Leaving refresh(). The certificate is unusable.");
      refreshRefused('STS-SAML-0053', identifier,
                     'the metadata carries a certificate this service cannot use: ' + bad);
      return { ok: false, errors: ['The metadata at "' + wanted + '" carries a certificate ' +
        'this service cannot use: ' + bad + '. Nothing on the entry was changed.'] };
    }
    const stored = [
      applications.updateApplication(identifier,
        { mode: 'set', attribute: 'samlSpMetadata', value: answer.xml }),
      applications.updateApplication(identifier,
        { mode: 'set', attribute: 'samlEncryptionCertificate', value: parsed.certificate })
    ];
    const failed = stored.filter(function (one) { return !one.ok; });
    if (failed.length) {
      log.debug("Leaving refresh(). The entry would not take it.");
      refreshRefused('STS-SAML-0054', identifier,
                     'the application entry would not take the fetched metadata');
      return { ok: false, errors: failed.reduce(function (all, one) {
        return all.concat(one.errors || []);
      }, []) };
    }
    log.info('saml2: refreshed the metadata for ' + identifier + ' from ' + wanted +
             '. Its encryption certificate is the ' + parsed.certificateUse +
             ' KeyDescriptor; entityID "' + parsed.entityId + '", ' + parsed.acs.length +
             ' assertion consumer service(s) and ' + parsed.slo.length +
             ' single logout service(s) are described and are REPORTED ONLY — ' +
             'this service still sends a response where the request asked.');
    log.debug("Leaving refresh(). Stored.");
    return { ok: true, application: identifier, url: wanted,
             entityId: parsed.entityId,
             certificateUse: parsed.certificateUse,
             assertionConsumerServices: parsed.acs,
             singleLogoutServices: parsed.slo,
             message: 'The metadata was fetched and its ' + parsed.certificateUse +
                      ' certificate is now on the entry, so an assertion for this service ' +
                      'provider can be encrypted to it. The endpoints in the document are ' +
                      'reported and NOT applied — a response still goes where the request ' +
                      'asks, which is what actually happened rather than what a document ' +
                      'claims should.' };
  });
}

module.exports = {
  parse: parse,
  toPem: toPem,
  certificateProblem: certificateProblem,
  urlProblem: urlProblem,
  fetchMetadata: fetchMetadata,
  refresh: refresh
};
