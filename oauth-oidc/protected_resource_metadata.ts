'use strict';
//
// File: protected_resource_metadata.ts
//
// ===========================================================================
// RFC 9728, OAUTH 2.0 PROTECTED RESOURCE METADATA, READ SO THAT AN APPLICATION
// CAN BE CREATED FROM IT (2026-09-13).
//
// A protected resource publishes a JSON document saying what it is: its
// resource identifier, the authorization servers it trusts, the scopes it
// understands, how it takes a bearer token. `/admin/applications/new` can now
// be handed one — pasted, uploaded, or fetched from a URL — and turn it into an
// application entry: the resource identifier is the default NAME, the
// permission BASE URI and the AUDIENCE; `scopes_supported` becomes the
// permissions the application exposes; a client_id is minted at random.
//
// THIS SERVICE IS THE CLIENT OF THE DOCUMENT HERE, NOT ITS PUBLISHER. Section 3
// is written for a client reading a resource's metadata, and that is exactly
// the position an operator importing one is in — so the checks section 3.3 puts
// on a client are the checks applied, and nothing here publishes a document of
// this service's own.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route. It requires `common/`
// modules, `federation/federation_http.ts` for the outbound policy, and two
// libraries beside it, none of which requires it back; `admin-core/`,
// `admin-ui/` and `mgmt-api/` require it. It decides; the two admin surfaces
// answer.
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS, FOUR OF THEM THE OWNER'S (asked before this was built):
//
//   * THE URL FETCH IS AN ADMINISTRATOR'S AND FOLLOWS THE OUTBOUND POLICY.
//     `federation/federation_http.ts` argues that a URL supplied by the CALLER
//     is never dialled and a URL supplied by the ADMINISTRATOR may be. Loading
//     a document is an Admin Write action on both surfaces, so it is the second
//     kind — and it takes that module's rules rather than a copy of them: the
//     `federation.outbound` kill switch, https only unless
//     `federation.outboundAllowInsecure`, no redirect followed, the body capped
//     at `federation.maxResponseBytes`, the request timed out at
//     `federation.outboundTimeoutMs`. That module's header says a new kind of
//     URL is "a separate argument in a separate function, never a fourth name
//     quietly added to DIALLABLE", and this is that function.
//   * AND IN PRODUCT MODE IT REFUSES AN INTERNAL ADDRESS
//     (`mode.dialsInternalAddresses()`). An administrator's URL is still a URL
//     somebody typed into a web form, and the host it names is resolved by this
//     process from inside whatever network this process sits in: loopback, a
//     private range, link-local (the cloud metadata address among them). The
//     name is resolved ONCE, every address is checked, and the connection is
//     pinned to the address that was checked — resolving twice is how a name
//     that answered a public address to the check answers a private one to the
//     connection. Development answers yes, because a resource on localhost is
//     the ordinary thing to import there.
//   * SECTION 3.3 IS A REFUSAL IN PRODUCT AND A WARNING IN DEVELOPMENT
//     (`mode.acceptsNonconformingResourceMetadata()`). A document fetched from
//     a well-known URL MUST carry the resource identifier that URL was built
//     from, and a client MUST NOT use one that does not — it is how a document
//     hosted on one resource is kept from describing another. A pasted or
//     uploaded document has no URL to compare against and is not checked; that
//     is said rather than skipped. The same predicate decides a `resource` that
//     is not https (section 2's "a URL that uses the https scheme").
//   * THE DOCUMENT IS KEPT ON THE ENTRY, as `oauthResourceMetadata` beside
//     `oauthResourceMetadataUrl`. The members with an attribute of their own
//     are written to it; everything else a resource said about itself —
//     `jwks_uri`, `bearer_methods_supported`, the DPoP members — stays readable
//     in the one place the application already lives.
//   * A SCOPE UNDER THE RESOURCE LOSES THE PREFIX. A permission here is a base
//     URI followed by a name (`common/app_permissions.ts`), so
//     `https://api.example.com/read` under the resource
//     `https://api.example.com` is the permission `read` — whose identifier is
//     then exactly the string the document advertised. A scope that is not
//     under the resource is kept as it is, and the plan says what identifier a
//     client will have to ask for.
//
// And one that is this file's own: **MALFORMED IS REFUSED IN BOTH MODES.** A
// member of the wrong JSON type, a `resource` that is not a URL or carries a
// fragment, a document that is not an object — those are SHAPE, and the input
// validation sweep's rule is that shape is validated unconditionally.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ProtectedResourceMetadata` takes the node modules, the `common/`
// libraries, the outbound policy and the two libraries beside it through its
// constructor (`ProtectedResourceMetadataDeps`). The member table and the
// internal-address list are still built at module scope, as data. The module
// still exports its old names, for the admin surfaces and the tests that
// require it by those names — the functions, since R2, FACADES over the
// instance the composition root builds and installs; a process without the
// root builds a default one at load.
// ---------------------------------------------------------------------------

import dns = require('dns');
import http = require('http');
import https = require('https');
import net = require('net');
import url = require('url');

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import mode = require('../common/mode');
// The failure codes. A refusal is returned with its code under the Symbol
// `mark()` uses, so what a caller serialises is unchanged.
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import applications = require('../common/applications');
import validation = require('../common/validation');
// The outbound policy — the kill switch, the scheme rule and the insecure
// switch — from the module that owns it, for `saml/sp_metadata.ts`'s reason: a
// second copy of the policy is the copy that drifts.
import fedHttp = require('../federation/federation_http');
import jwtAccessToken = require('./jwt_access_token');
import authorizationServers = require('./authorization_servers');
import version = require('../common/version');

type Req = any;
type Res = any;
type Next = any;
type Json = any;

interface ProtectedResourceMetadataDeps {
  dns: typeof dns;
  http: typeof http;
  https: typeof https;
  net: typeof net;
  URL: typeof url.URL;
  helpers: typeof helpers;
  log: typeof helpers.log;
  config: typeof config;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  applications: typeof applications;
  validation: typeof validation;
  fedHttp: typeof fedHttp;
  jwtAccessToken: typeof jwtAccessToken;
  authorizationServers: typeof authorizationServers;
  // Which build is calling, in RFC 9110 product form.
  USER_AGENT: string;
}

// Which build is calling, in RFC 9110 product form — the rule every outbound
// requester here follows. Built once: the version cannot change.
const USER_AGENT = version.userAgent('protected-resource-metadata');

// RFC 9728 section 3's well-known URI suffix.
const WELL_KNOWN = '/.well-known/oauth-protected-resource';

// ---------------------------------------------------------------------------
// THE MEMBERS RFC 9728 SECTION 2 DEFINES, AS A TABLE.
//
// `type` is what is checked: `uri` a string holding an absolute URL, `string`
// a string, `uri-list` and `string-list` a non-empty-string array, `bool` a
// JSON boolean, `jwt` a string of three dot-separated parts. `maps` names what
// the import writes a member to, where it writes it anywhere; a member with no
// `maps` is recorded on the entry inside the document and nowhere else.
//
// `languageTagged` is section 2.1: `resource_name`, `resource_documentation`,
// `resource_policy_uri` and `resource_tos_uri` may appear as
// `resource_name#ja-Kana-JP`, and a tagged member is the member's type.
// ---------------------------------------------------------------------------
const MEMBERS = [
  { name: 'resource', type: 'uri', required: true,
    maps: 'the application\'s default name, oauthPermissionBaseUri and ' +
          'oauthAudience',
    what: 'The protected resource\'s resource identifier: a URL using the ' +
          'https scheme with no fragment. The one REQUIRED member.' },
  { name: 'authorization_servers', type: 'uri-list',
    maps: 'compared with the authorization servers of this trust realm',
    what: 'Issuer identifiers of the authorization servers this resource ' +
          'accepts tokens from.' },
  { name: 'jwks_uri', type: 'uri',
    what: 'Where the resource publishes the keys it signs responses with. ' +
          'Recorded, never fetched.' },
  { name: 'scopes_supported', type: 'string-list',
    maps: 'oauthPermission, one permission per scope',
    what: 'The scope values a client may request to reach this resource.' },
  { name: 'bearer_methods_supported', type: 'string-list',
    enumValues: ['header', 'body', 'query'],
    what: 'How the resource accepts a bearer token: RFC 6750\'s `header`, ' +
          '`body` and `query`.' },
  { name: 'resource_signing_alg_values_supported', type: 'string-list',
    what: 'JWS algorithms the resource signs its responses with.' },
  { name: 'resource_name', type: 'string', languageTagged: true,
    what: 'A human-readable name for the resource.' },
  { name: 'resource_documentation', type: 'uri', languageTagged: true,
    what: 'Human-readable documentation for developers.' },
  { name: 'resource_policy_uri', type: 'uri', languageTagged: true,
    what: 'How a client may use the data the resource provides.' },
  { name: 'resource_tos_uri', type: 'uri', languageTagged: true,
    what: 'The resource\'s terms of service.' },
  { name: 'tls_client_certificate_bound_access_tokens', type: 'bool',
    what: 'Whether the resource supports RFC 8705 certificate-bound access ' +
          'tokens.' },
  { name: 'authorization_details_types_supported', type: 'string-list',
    maps: 'oauthAuthorizationDetailsType, one declared type per value',
    what: 'RFC 9396 authorization_details types the resource understands.' },
  { name: 'dpop_signing_alg_values_supported', type: 'string-list',
    what: 'JWS algorithms the resource accepts DPoP proofs signed with.' },
  { name: 'dpop_bound_access_tokens_required', type: 'bool',
    what: 'Whether the resource always requires DPoP-bound access tokens.' },
  { name: 'signed_metadata', type: 'jwt',
    what: 'A JWT carrying metadata values as claims (section 2.2). It is ' +
          'DECODED AND SHOWN, NOT VERIFIED AND NOT APPLIED: this service ' +
          'holds no key for the resource to verify it with, and section 2.2 ' +
          'lets a recipient that does not process signed metadata ignore it.' }
];

// The members an operator may edit on the third tab. `signed_metadata` is not
// one of them: an edited JWT is a JWT whose signature no longer covers it.
const MEMBER_BY_NAME: Record<string, Json> = {};
MEMBERS.forEach(function (row) { MEMBER_BY_NAME[row.name] = row; });

// ---------------------------------------------------------------------------
// WHICH ADDRESSES ARE INTERNAL.
//
// Loopback, the RFC 1918 and RFC 6598 private ranges, link-local (the cloud
// instance-metadata address among them), unique-local IPv6, "this network",
// multicast and the reserved blocks — every range whose address a request from
// inside this process's network would reach something that network did not
// mean to publish. The documentation ranges are included because nothing
// legitimate lives there. A NAT64 prefix is included because it embeds an IPv4
// address that may be any of the above.
// ---------------------------------------------------------------------------
const INTERNAL = (function () {
  const list = new net.BlockList();
  [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
   ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
   ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
   ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4],
   ['240.0.0.0', 4]].forEach(function (row) {
    list.addSubnet(row[0] as string, row[1] as number, 'ipv4');
  });
  [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64],
   ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10],
   ['ff00::', 8]].forEach(function (row) {
    list.addSubnet(row[0] as string, row[1] as number, 'ipv6');
  });
  return list;
})();

class ProtectedResourceMetadata {
  static readonly WELL_KNOWN = WELL_KNOWN;
  static readonly MEMBERS = MEMBERS;

  constructor(private readonly deps: ProtectedResourceMetadataDeps) {
    deps.log.debug("Entering ProtectedResourceMetadata.constructor().");
    deps.log.debug("Leaving ProtectedResourceMetadata.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  static defaultDeps(): ProtectedResourceMetadataDeps {
    helpers.log.debug("Entering ProtectedResourceMetadata.defaultDeps().");
    helpers.log.debug("Leaving ProtectedResourceMetadata.defaultDeps().");
    return {
      dns: dns,
      http: http,
      https: https,
      net: net,
      URL: url.URL,
      helpers: helpers,
      log: helpers.log,
      config: config,
      mode: mode,
      errorCodes: errorCodes,
      audit: audit,
      applications: applications,
      validation: validation,
      fedHttp: fedHttp,
      jwtAccessToken: jwtAccessToken,
      authorizationServers: authorizationServers,
      USER_AGENT: USER_AGENT
    };
  }

  // A member name, with section 2.1's language tag taken off it — so
  // `resource_name#en` is `resource_name`. Only the four members that may carry
  // one are resolved that way; `scopes_supported#en` is an extension member.
  memberRowFor(name: Json) {
    const { log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.memberRowFor().");
    const text = String(name || '');
    if (MEMBER_BY_NAME[text]) {
      log.debug("Leaving ProtectedResourceMetadata.memberRowFor().");
      return MEMBER_BY_NAME[text];
    }
    const at = text.indexOf('#');
    const row = at > 0 ? MEMBER_BY_NAME[text.slice(0, at)] : null;
    log.debug("Leaving ProtectedResourceMetadata.memberRowFor().");
    return (row && row.languageTagged) ? row : null;
  }

  // The cap on a document however it arrived: the setting the outbound fetch is
  // already bound by, so a pasted document and a fetched one are held to one
  // number.
  private maxBytes() {
    const { config, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.maxBytes().");
    log.debug("Leaving ProtectedResourceMetadata.maxBytes().");
    return Number(config.value('federation.maxResponseBytes'));
  }

  // A refusal, carrying its code the way every refusal here does.
  private refusal(code: string, errors: Json, extra?: Json) {
    const { errorCodes, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.refusal(). code=" + code);
    log.debug("Leaving ProtectedResourceMetadata.refusal().");
    return errorCodes.mark(Object.assign({ ok: false,
                                           errors: [].concat(errors) },
                                         extra || {}), code);
  }

  // ---------------------------------------------------------------------------
  // WHAT ONE VALUE IS WRONG WITH, AS A SENTENCE, OR ''.
  // ---------------------------------------------------------------------------
  private absoluteUrlProblem(name: Json, value: Json) {
    const { URL, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.absoluteUrlProblem().");
    let parsed = null;
    try {
      parsed = new URL(String(value));
    } catch (e) {
      log.debug("Caught in ProtectedResourceMetadata.absoluteUrlProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving ProtectedResourceMetadata.absoluteUrlProblem().");
      return '`' + name + '` is "' + value + '", which is not an absolute URL.';
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      log.debug("Leaving ProtectedResourceMetadata.absoluteUrlProblem().");
      return '`' + name + '` has the scheme "' +
             parsed.protocol.replace(':', '') + '"; RFC 9728 names URLs, and ' +
             'only http and https are read here.';
    }
    log.debug("Leaving ProtectedResourceMetadata.absoluteUrlProblem().");
    return '';
  }

  private memberProblem(name: Json, row: Json, value: Json) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.memberProblem(). " +
              "name=" + name);
    const isStringList = function (list) {
      log.debug("Entering isStringList().");
      log.debug("Leaving isStringList().");
      return Array.isArray(list) && list.every(function (one) {
        return typeof one === 'string' && one.trim() !== '';
      });
    };
    if (row.type === 'bool') {
      log.debug("Leaving ProtectedResourceMetadata.memberProblem().");
      return typeof value === 'boolean' ? '' :
             '`' + name + '` must be a JSON boolean, not ' +
             JSON.stringify(value) + '.';
    }
    if (row.type === 'string' || row.type === 'uri' || row.type === 'jwt') {
      if (typeof value !== 'string' || !value.trim()) {
        log.debug("Leaving ProtectedResourceMetadata.memberProblem().");
        return '`' + name + '` must be a non-empty JSON string.';
      }
      if (row.type === 'uri') {
        log.debug("Leaving ProtectedResourceMetadata.memberProblem().");
        return self.absoluteUrlProblem(name, value);
      }
      if (row.type === 'jwt' && value.split('.').length !== 3) {
        log.debug("Leaving ProtectedResourceMetadata.memberProblem().");
        return '`' + name + '` must be a JWT — three base64url parts ' +
               'separated by dots.';
      }
      log.debug("Leaving ProtectedResourceMetadata.memberProblem().");
      return '';
    }
    if (!isStringList(value)) {
      log.debug("Leaving ProtectedResourceMetadata.memberProblem().");
      return '`' + name + '` must be a JSON array of non-empty strings.';
    }
    if (row.type === 'uri-list') {
      const bad = value.map(function (one) {
        return self.absoluteUrlProblem(name, one);
      }).filter(function (one) { return !!one; });
      log.debug("Leaving ProtectedResourceMetadata.memberProblem().");
      return bad.length ? bad[0] : '';
    }
    log.debug("Leaving ProtectedResourceMetadata.memberProblem().");
    return '';
  }

  // ---------------------------------------------------------------------------
  // SIGNED METADATA, DECODED FOR READING. Never verified — see the table.
  // ---------------------------------------------------------------------------
  private decodeSignedMetadata(jwt: Json) {
    const { log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.decodeSignedMetadata().");
    const parts = String(jwt || '').split('.');
    const out = { verified: false, applied: false, header: null, claims: null,
                  why: '' };
    try {
      out.header = JSON.parse(Buffer.from(parts[0], 'base64url')
                                    .toString('utf8'));
      out.claims = JSON.parse(Buffer.from(parts[1], 'base64url')
                                    .toString('utf8'));
    } catch (e) {
      log.debug("Caught in " +
                "ProtectedResourceMetadata.decodeSignedMetadata(): " +
                ((e && e.message) || e));
      out.why = 'its header or claims are not base64url JSON (' + e.message +
                ')';
    }
    log.debug("Leaving ProtectedResourceMetadata.decodeSignedMetadata().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // PARSE ONE DOCUMENT.
  //
  // `{ ok, document, members, extensions, signedMetadata, warnings }` or a
  // refusal. Every member RFC 9728 defines is type-checked; a member it does
  // not define is KEPT and listed as an extension, because section 2 says a
  // recipient ignores what it does not understand and an import that dropped it
  // would store a different document from the one the operator loaded.
  // ---------------------------------------------------------------------------
  parseDocument(text: Json) {
    const { URL, validation, log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.parseDocument().");
    const raw = String(text == null ? '' : text);
    if (!raw.trim()) {
      log.debug("Leaving ProtectedResourceMetadata.parseDocument(). Empty.");
      return self.refusal('STS-REG-0076', 'The protected resource metadata ' +
                                     'document is empty.');
    }
    const cap = self.maxBytes();
    if (Buffer.byteLength(raw, 'utf8') > cap) {
      log.debug("Leaving ProtectedResourceMetadata.parseDocument(). Too " +
                "large.");
      return self.refusal('STS-REG-0076', 'The document is larger than ' + cap +
                     ' bytes (federation.maxResponseBytes). A protected ' +
                     'resource metadata document is a few hundred bytes.');
    }
    let document: Json = null;
    try {
      document = JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in ProtectedResourceMetadata.parseDocument(): " +
                ((e && e.message) || e));
      log.debug("Leaving ProtectedResourceMetadata.parseDocument(). Not JSON.");
      return self.refusal('STS-REG-0076', 'The document is not JSON: ' +
                          e.message + '. RFC 9728 section 3.2 makes it a ' +
                          'JSON object.');
    }
    if (!document || typeof document !== 'object' || Array.isArray(document)) {
      log.debug("Leaving ProtectedResourceMetadata.parseDocument(). Not an " +
                "object.");
      return self.refusal('STS-REG-0076', 'The document is JSON but not a ' +
                          'JSON object, and RFC 9728 section 3.2 makes it ' +
                          'one.');
    }
    // The pollution walk every arbitrary JSON document here goes through, with
    // its depth and member-count bounds. It returns the value unchanged.
    const walked = validation.checkDocument(document,
                                            'protected resource metadata');
    if (!walked.ok) {
      log.debug("Leaving ProtectedResourceMetadata.parseDocument(). The " +
                "walk refused it.");
      return self.refusal('STS-REG-0076', 'The document was refused: ' +
                     (walked.message || walked.detail || walked.code) + '.');
    }

    const problems = [];
    const members = [];
    const extensions = [];
    Object.keys(document).forEach(function (name) {
      const row = self.memberRowFor(name);
      if (!row) {
        extensions.push(name);
        members.push({ member: name, value: document[name], known: false,
                       type: 'extension', what: 'Not a member RFC 9728 ' +
                       'defines. Kept on the entry with the rest of the ' +
                       'document and not interpreted.', maps: '' });
        return;
      }
      const problem = self.memberProblem(name, row, document[name]);
      if (problem) {
        problems.push(problem);
      }
      members.push({ member: name, value: document[name], known: true,
                     type: row.type, what: row.what, maps: row.maps || '',
                     problem: problem });
    });
    if (!Object.prototype.hasOwnProperty.call(document, 'resource')) {
      problems.unshift('`resource` is missing, and it is the one member RFC ' +
                       '9728 section 2 makes REQUIRED.');
    }
    if (typeof document.resource === 'string' && document.resource.trim()) {
      try {
        if (new URL(document.resource).hash) {
          problems.push('`resource` carries a fragment, and section 2 says a ' +
                        'resource identifier has none.');
        }
      } catch (e) {
        log.debug("Caught in ProtectedResourceMetadata.parseDocument(): " +
                  ((e && e.message) || e));
      }
    }
    if (problems.length) {
      log.debug("Leaving ProtectedResourceMetadata.parseDocument(). " +
                problems.length + " problem(s).");
      return self.refusal('STS-REG-0077', problems, { members: members });
    }

    const warnings = [];
    const scheme = new URL(document.resource).protocol;
    const signedMetadata = typeof document.signed_metadata === 'string'
      ? self.decodeSignedMetadata(document.signed_metadata) : null;
    if (Array.isArray(document.bearer_methods_supported)) {
      const odd = document.bearer_methods_supported.filter(function (one) {
        return MEMBER_BY_NAME.bearer_methods_supported.enumValues
                             .indexOf(one) < 0;
      });
      if (odd.length) {
        warnings.push('`bearer_methods_supported` names ' + odd.join(', ') +
                      ', which RFC 6750 does not define (header, body and ' +
                      'query are the three).');
      }
    }
    log.debug("Leaving ProtectedResourceMetadata.parseDocument(). ok, " +
              members.length + " member(s).");
    return { ok: true, document: document, members: members,
             extensions: extensions, signedMetadata: signedMetadata,
             httpsResource: scheme === 'https:', warnings: warnings };
  }

  // ---------------------------------------------------------------------------
  // RFC 9728 SECTION 3.1, BOTH WAYS.
  //
  // The well-known URI suffix is inserted between the host component and the
  // path, and "any terminating slash (/) following the host component MUST be
  // removed" first — so `https://api.example.com/` and
  // `https://api.example.com` share one well-known URL, and
  // `https://api.example.com/v1` has
  // `https://api.example.com/.well-known/oauth-protected-resource/v1`.
  // ---------------------------------------------------------------------------
  wellKnownUrlFor(resource: Json) {
    const { URL, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.wellKnownUrlFor().");
    let parsed = null;
    try {
      parsed = new URL(String(resource || ''));
    } catch (e) {
      log.debug("Caught in ProtectedResourceMetadata.wellKnownUrlFor(): " +
                ((e && e.message) || e));
      log.debug("Leaving ProtectedResourceMetadata.wellKnownUrlFor().");
      return '';
    }
    const path = parsed.pathname === '/' ? '' : parsed.pathname;
    log.debug("Leaving ProtectedResourceMetadata.wellKnownUrlFor().");
    return parsed.origin + WELL_KNOWN + path + parsed.search;
  }

  // The resource identifiers a well-known URL could have been built from, or
  // null for a URL that is not one. Two where the path is empty, for the
  // terminating-slash rule above.
  resourcesForWellKnownUrl(url: Json) {
    const { URL, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.resourcesForWellKnownUrl().");
    let parsed = null;
    try {
      parsed = new URL(String(url || ''));
    } catch (e) {
      log.debug("Caught in " +
                "ProtectedResourceMetadata.resourcesForWellKnownUrl(): " +
                ((e && e.message) || e));
      log.debug("Leaving " +
                "ProtectedResourceMetadata.resourcesForWellKnownUrl().");
      return null;
    }
    const path = parsed.pathname;
    if (path !== WELL_KNOWN && path.indexOf(WELL_KNOWN + '/') !== 0) {
      log.debug("Leaving " +
                "ProtectedResourceMetadata.resourcesForWellKnownUrl(). Not " +
                "a well-known URL.");
      return null;
    }
    const rest = path.slice(WELL_KNOWN.length);
    log.debug("Leaving ProtectedResourceMetadata.resourcesForWellKnownUrl().");
    return rest
      ? [parsed.origin + rest + parsed.search]
      : [parsed.origin + parsed.search, parsed.origin + '/' + parsed.search];
  }

  // SECTION 3.3, as a verdict: whether it could be checked, whether it matched,
  // and what it was compared against.
  resourceCheckFor(document: Json, url: Json) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.resourceCheckFor().");
    const resource = String((document && document.resource) || '');
    const expectedWellKnown = self.wellKnownUrlFor(resource);
    if (!url) {
      log.debug("Leaving ProtectedResourceMetadata.resourceCheckFor(). No " +
                "URL.");
      return { checked: false, matches: null, expected: [],
               wellKnownUrl: expectedWellKnown,
               why: 'The document was pasted or uploaded, so there is no URL ' +
                    'to hold its `resource` to. Section 3.3 is a check on a ' +
                    'FETCHED document.' };
    }
    const candidates = self.resourcesForWellKnownUrl(url);
    if (!candidates) {
      log.debug("Leaving ProtectedResourceMetadata.resourceCheckFor(). Not " +
                "well-known.");
      return { checked: false, matches: null, expected: [],
               wellKnownUrl: expectedWellKnown,
               why: 'It was fetched from ' + url + ', which is not a ' +
                    'well-known URL (' + WELL_KNOWN + '), so section 3.3 has ' +
                    'nothing to compare `resource` with. Section 3.1 locates ' +
                    'this resource\'s document at ' + expectedWellKnown + '.' };
    }
    const matches = candidates.indexOf(resource) >= 0;
    log.debug("Leaving ProtectedResourceMetadata.resourceCheckFor(). " +
              "matches=" + matches);
    return { checked: true, matches: matches, expected: candidates,
             wellKnownUrl: expectedWellKnown,
             why: matches
               ? 'The document\'s `resource` is the identifier the ' +
                 'well-known URL it was fetched from was built from.'
               : 'The document was fetched from ' + url + ', which is built ' +
                 'from ' + candidates.join(' or ') + ', and it says its ' +
                 '`resource` is ' + resource + '. RFC 9728 section 3.3 ' +
                 'says a client MUST NOT use a document that fails this.' };
  }

  // Why an address may not be dialled, or ''. An IPv4-mapped IPv6 address is
  // judged as the IPv4 address inside it, whichever of its two spellings
  // arrived, because `::ffff:127.0.0.1` reaches loopback exactly as `127.0.0.1`
  // does.
  internalAddressProblem(address: Json) {
    const { net, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.internalAddressProblem(). " +
              "address=" + address);
    let text = String(address || '').replace(/^\[|\]$/g, '');
    const mappedDotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(text);
    const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(text);
    if (mappedDotted) {
      text = mappedDotted[1];
    } else if (mappedHex) {
      const high = parseInt(mappedHex[1], 16);
      const low = parseInt(mappedHex[2], 16);
      text = [high >> 8, high & 255, low >> 8, low & 255].join('.');
    }
    const family = net.isIP(text);
    if (!family) {
      log.debug("Leaving " +
                "ProtectedResourceMetadata.internalAddressProblem(). Not an " +
                "address.");
      return '"' + address + '" is not an IP address';
    }
    const internal = INTERNAL.check(text, family === 4 ? 'ipv4' : 'ipv6');
    log.debug("Leaving ProtectedResourceMetadata.internalAddressProblem(). " +
              "internal=" + internal);
    return internal
      ? text + ' is a loopback, private, link-local or reserved address'
      : '';
  }

  // ---------------------------------------------------------------------------
  // RESOLVE ONCE, AND SAY WHICH ADDRESS THE CONNECTION MAY USE.
  //
  // `{ ok, address, family }` or a refusal. In development the name is resolved
  // by the connection itself and nothing is pinned; in product every address
  // the name resolves to is checked and the first is what the request connects
  // to.
  // ---------------------------------------------------------------------------
  private vetHost(hostname: Json) {
    const { dns, net, mode, log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.vetHost(). " +
              "hostname=" + hostname);
    const host = String(hostname || '').replace(/^\[|\]$/g, '');
    if (mode.dialsInternalAddresses()) {
      log.debug("Leaving ProtectedResourceMetadata.vetHost(). Development: " +
                "not pinned.");
      return Promise.resolve({ ok: true, address: '', family: 0 });
    }
    const judge = function (addresses) {
      log.debug("Entering judge().");
      const bad = addresses.map(function (one) {
        return self.internalAddressProblem(one.address);
      }).filter(function (one) { return !!one; });
      if (bad.length || !addresses.length) {
        log.debug("Leaving judge(). Refused.");
        return self.refusal('STS-REG-0080', '"' + host + '" resolves to ' +
          (bad.length ? bad.join('; ') : 'no address') + '. This service is ' +
          'running as a product (global.mode=product), so a URL an ' +
          'administrator names may not reach an address inside this ' +
          'service\'s own network. Paste or upload the document instead.');
      }
      log.debug("Leaving judge(). ok.");
      return { ok: true, address: addresses[0].address,
               family: addresses[0].family };
    };
    const literal = net.isIP(host);
    if (literal) {
      log.debug("Leaving ProtectedResourceMetadata.vetHost(). A literal " +
                "address.");
      return Promise.resolve(judge([{ address: host, family: literal }]));
    }
    log.debug("Leaving ProtectedResourceMetadata.vetHost(). Resolving.");
    return new Promise(function (resolve) {
      dns.lookup(host, { all: true }, function (error, addresses) {
        if (error) {
          log.debug("Caught in ProtectedResourceMetadata.vetHost(): " +
                    ((error && error.message) ||
                                               error));
          resolve(self.refusal('STS-REG-0081', '"' + host + '" could not be ' +
                          'resolved: ' + error.message + '.'));
          return;
        }
        resolve(judge(addresses || []));
      });
    });
  }

  // ---------------------------------------------------------------------------
  // FETCH ONE DOCUMENT BY URL. A promise of `{ ok, text, url, status }` or a
  // refusal, and it NEVER rejects — `federation_http.ts`'s rule, for its
  // reason.
  // ---------------------------------------------------------------------------
  fetchDocument(url: Json) {
    const { http, https, URL, config, fedHttp, USER_AGENT, log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.fetchDocument(). url=" + url);
    const asked = String(url || '').trim();
    if (!fedHttp.outboundAllowed()) {
      log.debug("Leaving ProtectedResourceMetadata.fetchDocument(). " +
                "federation.outbound is off.");
      return Promise.resolve(self.refusal('STS-REG-0078',
        'federation.outbound is off, so this service makes no outbound ' +
        'request at all and the ' +
        'document cannot be fetched. Paste or upload it instead.'));
    }
    const problem = fedHttp.urlProblem(asked);
    if (problem) {
      log.debug("Leaving ProtectedResourceMetadata.fetchDocument(). The URL " +
                "was refused.");
      return Promise.resolve(self.refusal('STS-REG-0079', 'The URL cannot be ' +
                                     'fetched: ' + problem + '.'));
    }
    const parsed = new URL(asked);
    log.debug("Leaving ProtectedResourceMetadata.fetchDocument(). Vetting " +
              "the host.");
    return self.vetHost(parsed.hostname).then(function (vetted) {
      if (!vetted.ok) {
        return vetted;
      }
      return new Promise(function (resolve) {
        let settled = false;
        const done = function (answer) {
          log.debug("Entering done().");
          if (!settled) {
            settled = true;
            resolve(answer);
          }
          log.debug("Leaving done().");
        };
        const agent = parsed.protocol === 'https:' ? https : http;
        const insecure = fedHttp.allowInsecure();
        if (parsed.protocol !== 'https:') {
          // Every insecure request, not only the setting — federation_http.ts's
          // rule.
          log.warn('resource metadata: fetching ' + parsed.origin + ' over ' +
                   'plain http because federation.outboundAllowInsecure is ' +
                   'ON.');
        }
        const options: Json = {
          headers: { accept: 'application/json', 'user-agent': USER_AGENT },
          rejectUnauthorized: !insecure
        };
        if (vetted.address) {
          // PINNED to the address that was checked. The Host header and TLS
          // server name still come from the URL, so a certificate is checked
          // against the name that was typed.
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
        const cap = self.maxBytes();
        const request = agent.get(asked, options, function (res) {
          if (res.statusCode >= 300 && res.statusCode < 400) {
            res.resume();
            done(self.refusal('STS-REG-0082', 'It answered ' + res.statusCode +
              ' with a redirect to "' + (res.headers.location ||
                                         '(no Location)') + '". Redirects ' +
              'are not followed — a redirect is how a URL somebody named ' +
              'becomes one nobody named. Give the final URL.',
              { status: res.statusCode }));
            return;
          }
          if (res.statusCode !== 200) {
            res.resume();
            done(self.refusal('STS-REG-0083', 'It answered ' + res.statusCode +
                         ' rather than 200.', { status: res.statusCode }));
            return;
          }
          const chunks = [];
          let size = 0;
          res.on('data', function (chunk) {
            size += chunk.length;
            if (size > cap) {
              request.destroy();
              done(self.refusal('STS-REG-0084', 'The document is larger than ' +
                           cap + ' bytes (federation.maxResponseBytes).'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', function () {
            done({ ok: true, status: 200, url: asked,
                   contentType: String(res.headers['content-type'] || ''),
                   text: Buffer.concat(chunks).toString('utf8') });
          });
        });
        request.setTimeout(Number(config.value('federation.outboundTimeoutMs')),
                           function () {
          request.destroy();
          done(self.refusal('STS-REG-0085', 'It did not answer within ' +
                       config.value('federation.outboundTimeoutMs') +
                       'ms (federation.outboundTimeoutMs).'));
        });
        request.on('error', function (e) {
          log.debug("Caught in ProtectedResourceMetadata.fetchDocument(): " +
                    ((e && e.message) || e));
          done(self.refusal('STS-REG-0086', 'The request failed: ' + e.message +
                       '.'));
        });
      });
    });
  }

  // ---------------------------------------------------------------------------
  // THE AUTHORIZATION SERVERS OF THIS TRUST REALM, with the issuer each
  // publishes at the address this request arrived on — through
  // `jwt_access_token.issuerFor()`, which `oauth2.ts`'s `issuerOf()` (what its
  // discovery documents are built from) calls, so the comparison is against
  // what a client of this realm would actually read.
  // ---------------------------------------------------------------------------
  authorizationServersOf(req: Req) {
    const { helpers, jwtAccessToken, authorizationServers, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.authorizationServersOf().");
    const base = helpers.baseUrlOf(req);
    const rows = [{ id: authorizationServers.DEFAULT_ID, label: 'default',
                    issuer: jwtAccessToken.issuerFor(base) }];
    authorizationServers.list().forEach(function (profile) {
      if (profile.id === authorizationServers.DEFAULT_ID) {
        return;
      }
      rows.push({ id: profile.id, label: profile.label || '',
                  issuer: jwtAccessToken.issuerFor(base + '/' + profile.id) });
    });
    log.debug("Leaving ProtectedResourceMetadata.authorizationServersOf(). " +
              rows.length + " row(s).");
    return rows;
  }

  // An issuer as compared: RFC 8414 section 3.3 compares issuers by simple
  // string comparison, and the one liberty taken is a trailing slash — which
  // `https://sts.example.com` and `https://sts.example.com/` differ by and no
  // deployment means as two authorization servers.
  private issuerKey(issuer: Json) {
    const { log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.issuerKey().");
    log.debug("Leaving ProtectedResourceMetadata.issuerKey().");
    return String(issuer || '').trim().replace(/\/+$/, '');
  }

  compareAuthorizationServers(document: Json, known: Json) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering " +
              "ProtectedResourceMetadata.compareAuthorizationServers().");
    const listed = Array.isArray(document && document.authorization_servers)
      ? document.authorization_servers : [];
    const realm = known || [];
    const rows = listed.map(function (issuer) {
      const match = realm.filter(function (one) {
        return self.issuerKey(one.issuer) === self.issuerKey(issuer);
      })[0];
      return { issuer: issuer, matched: !!match,
               authorizationServer: match ? match.id : '' };
    });
    const matched = rows.filter(function (row) { return row.matched; }).length;
    log.debug("Leaving " +
              "ProtectedResourceMetadata.compareAuthorizationServers(). " +
              matched + " of " +
              rows.length + " matched.");
    return {
      listed: rows.length,
      matched: matched,
      allMatched: rows.length > 0 && matched === rows.length,
      anyUnmatched: matched < rows.length,
      rows: rows,
      realm: realm
    };
  }

  // ---------------------------------------------------------------------------
  // A CLIENT_ID, AT RANDOM, IN THE SHAPE A DYNAMIC CLIENT REGISTRATION MINTS —
  // `oauth2.registeredClientIdPrefix` and `oauth2.registeredClientIdBytes`,
  // read the way `oauth2.ts`'s registration endpoint reads them, so an
  // application imported here and one that registered itself cannot be told
  // apart by their identifiers. One already in the registry is drawn again.
  // ---------------------------------------------------------------------------
  generateClientId() {
    const { helpers, config, applications, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.generateClientId().");
    const prefix = String(config.value('oauth2.registeredClientIdPrefix') ||
                          '');
    const bytes = Number(config.value('oauth2.registeredClientIdBytes')) || 8;
    let id = '';
    for (let attempt = 0; attempt < 8; attempt++) {
      id = prefix + helpers.randomId(bytes);
      if (!applications.get(id)) {
        break;
      }
    }
    log.debug("Leaving ProtectedResourceMetadata.generateClientId().");
    return id;
  }

  // ---------------------------------------------------------------------------
  // ONE SCOPE AS A PERMISSION. The prefix comes off only where the scope is the
  // resource's own base followed by something — so the permission identifier
  // this service composes is the scope the document advertised.
  // ---------------------------------------------------------------------------
  permissionFor(scope: Json, resource: Json) {
    const { applications, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.permissionFor().");
    const base = applications.permissionBaseOf(resource);
    const text = String(scope || '');
    const stripped = !!base && text.indexOf(base) === 0 &&
                     text.length > base.length;
    const name = stripped ? text.slice(base.length) : text;
    const id = applications.permissionIdOf(resource, name);
    log.debug("Leaving ProtectedResourceMetadata.permissionFor().");
    return { scope: text, name: name, stripped: stripped, id: id,
             sameAsAdvertised: id === text,
             problem: applications.permissionNameProblem(name) };
  }

  // ---------------------------------------------------------------------------
  // THE APPLICATION THE DOCUMENT DESCRIBES, as defaults a person then edits.
  // ---------------------------------------------------------------------------
  planFor(document: Json) {
    const { applications, log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.planFor().");
    const resource = String((document && document.resource) || '');
    const base = applications.permissionBaseOf(resource);
    const scopes = Array.isArray(document && document.scopes_supported)
      ? document.scopes_supported : [];
    const seen = {};
    const permissions = scopes.map(function (scope) {
      const one: Json = self.permissionFor(scope, resource);
      one.duplicate = !!seen[one.name];
      seen[one.name] = true;
      return one;
    });
    const clientId = self.generateClientId();
    const warnings = [];
    const baseProblem = applications.permissionBaseProblem(resource);
    if (baseProblem) {
      warnings.push(baseProblem);
    }
    if (base && base !== resource) {
      warnings.push('A permission identifier is the base URI followed by the ' +
        'name, so the base is used as ' + base + ' — with a trailing `/` — ' +
        'and an access token asking for one of these permissions is ' +
        'audienced to ' + base + '. `oauthAudience` is ' + resource + ' as ' +
        'the document spells it, which is what an RFC 8707 `resource=` ' +
        'request produces. A resource server comparing `aud` exactly will ' +
        'see the two as different strings.');
    }
    const exposing = base ? applications.forPermissionBase(base) : null;
    if (exposing) {
      warnings.push('"' + exposing.identifier + '" already exposes ' +
        'permissions under ' + base + '. Two applications with one base URI ' +
        'make a permission identifier that names either of them.');
    }
    const audienceHolder = resource ? applications.forAudience(resource) : null;
    if (audienceHolder) {
      warnings.push('"' + audienceHolder.identifier + '" already registers ' +
        resource + ' as its audience.');
    }
    permissions.forEach(function (one) {
      if (one.problem) {
        warnings.push('The scope "' + one.scope + '" cannot be a permission: ' +
                      one.problem);
      } else if (one.duplicate) {
        warnings.push('The scope "' + one.scope + '" becomes the permission ' +
                      '"' + one.name + '" a second time; one is enough.');
      } else if (!one.sameAsAdvertised) {
        warnings.push('The scope "' + one.scope + '" is not under the ' +
          'resource, so it becomes the permission identified by ' + one.id +
          ' — a client asks for that string, not for "' + one.scope + '".');
      }
    });
    // RFC 9396: the types the resource says it understands become the types
    // this application DECLARES, which is what lets a detail of one reach it.
    // The built-in openid_credential, a name that cannot be one, and a type
    // another application already declares are left out and said so.
    const declaredElsewhere = {};
    applications.list().forEach(function (row) {
      const held = (row.fields || {}).oauthAuthorizationDetailsType;
      (held === undefined ? [] : [].concat(held)).forEach(function (value) {
        const definition = applications.authorizationDetailsTypeOf(value);
        if (!definition.problem) {
          declaredElsewhere[definition.type] = row.identifier;
        }
      });
    });
    const detailsTypeLines = [];
    (Array.isArray(document && document.authorization_details_types_supported)
      ? document.authorization_details_types_supported : [])
      .forEach(function (type) {
        const definition = applications.authorizationDetailsTypeOf(
          typeof type === 'string' ? type : '');
        if (definition.problem) {
          warnings.push('The authorization_details type ' +
                        JSON.stringify(type) +
                        ' is not declared: ' + definition.problem + '.');
        } else if (declaredElsewhere[definition.type]) {
          warnings.push('The authorization_details type "' + definition.type +
            '" is already declared by "' + declaredElsewhere[definition.type] +
            '", which answers for it; it is not declared again.');
        } else if (detailsTypeLines.indexOf(definition.type) < 0) {
          detailsTypeLines.push(definition.type);
        }
      });
    log.debug("Leaving ProtectedResourceMetadata.planFor(). " +
              permissions.length + " permission(s).");
    return {
      // The spelling `oauthAuthorizationDetailsType` holds, one per line.
      detailsTypeLines: detailsTypeLines,
      name: resource,
      identifier: clientId,
      clientId: clientId,
      baseUri: resource,
      audience: resource,
      protocols: ['oauth2'],
      permissions: permissions,
      // The spelling `oauthPermission` holds, one per line, for the form.
      permissionLines: permissions.filter(function (one) {
        return !one.problem && !one.duplicate;
      }).map(function (one) { return one.name; }),
      warnings: warnings
    };
  }

  // ---------------------------------------------------------------------------
  // LOAD: whichever of the three sources was given, fetched if it is a URL,
  // parsed, checked and planned.
  //
  //   input    { document, url, file: { name, text } }  — exactly one of
  //            the three
  //   context  { authorizationServers: [...], actor }
  //
  // A promise of the whole view or of a refusal. It writes nothing: loading a
  // document creates no application, and the create is a separate act.
  // ---------------------------------------------------------------------------
  private documentTextOf(value: Json) {
    const { log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.documentTextOf().");
    if (value && typeof value === 'object') {
      // A JSON caller may send the document as an object rather than as text.
      log.debug("Leaving ProtectedResourceMetadata.documentTextOf(). An " +
                "object.");
      return JSON.stringify(value);
    }
    log.debug("Leaving ProtectedResourceMetadata.documentTextOf().");
    return String(value == null ? '' : value);
  }

  private refusedLoad(result: Json, context: Json, source: Json) {
    const { errorCodes, audit, log } = this.deps;
    log.debug("Entering ProtectedResourceMetadata.refusedLoad().");
    audit.failure(errorCodes.codeOf(result) || 'STS-REG-0077', {
      protocol: 'OAuth 2.0', channel: 'internal',
      actor: (context && context.actor) || '',
      target: source,
      summary: 'protected resource metadata was not loaded (' + source + '): ' +
               String((result.errors || [])[0] || '').slice(0, 300),
      // error-code: none — the helper's own row; the caller's code is passed
      outcome: 'refused'
    });
    log.debug("Leaving ProtectedResourceMetadata.refusedLoad().");
    return result;
  }

  load(input: Json, context: Json) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.load().");
    const given = input || {};
    const text = self.documentTextOf(given.document);
    const file = given.file && given.file.text ? given.file : null;
    const url = String(given.url || '').trim();
    const sources = [];
    if (text.trim()) {
      sources.push('pasted');
    }
    if (file && String(file.text).trim()) {
      sources.push('upload');
    }
    if (url) {
      sources.push('url');
    }
    if (!sources.length) {
      log.debug("Leaving ProtectedResourceMetadata.load(). Nothing given.");
      return Promise.resolve(self.refusedLoad(self.refusal('STS-REG-0074',
        'Give the protected resource metadata document one way: paste it in ' +
        '`document`, upload it as `file`, or name the URL it is published at ' +
        'in `url`.'), context, 'nothing'));
    }
    if (sources.length > 1) {
      log.debug("Leaving ProtectedResourceMetadata.load(). More than one " +
                "source.");
      return Promise.resolve(self.refusedLoad(self.refusal('STS-REG-0075',
        'The document was given ' + sources.length + ' ways (' +
        sources.join(', ') + '). Give it one way, so there is no question ' +
        'which of them was imported.'), context, sources.join('+')));
    }
    const source = sources[0];
    const obtained = source === 'url'
      ? self.fetchDocument(url)
      : Promise.resolve({ ok: true,
                          text: source === 'upload' ? file.text : text,
                          url: '' });
    log.debug("Leaving ProtectedResourceMetadata.load(). Source " +
              source + ".");
    return obtained.then(function (got) {
      if (!got.ok) {
        return self.refusedLoad(got, context, source);
      }
      if (source === 'url') {
        log.info('resource metadata: fetched ' + url + ' (' +
                 Buffer.byteLength(got.text, 'utf8') + ' bytes, ' +
                 (got.contentType || 'no content type') + ').');
      }
      const view = self.analyse(got.text, { source: source, url: got.url || '',
                                       filename: file ? String(file.name || '')
                                                      : '',
                                       contentType: got.contentType || '' },
                           context);
      return view.ok ? view : self.refusedLoad(view, context, source);
    });
  }

  // THE HALF OF LOAD THAT NEEDS NO NETWORK — also what redraws the page after a
  // refused create, from the document the form carried back, without fetching
  // it again.
  analyse(text: Json, origin: Json, context: Json) {
    const { mode, authorizationServers, log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.analyse().");
    const from = origin || {};
    const parsed = self.parseDocument(text);
    if (!parsed.ok) {
      log.debug("Leaving ProtectedResourceMetadata.analyse(). Unparsed.");
      return parsed;
    }
    const document = parsed.document;
    const lenient = mode.acceptsNonconformingResourceMetadata();
    const resourceCheck = self.resourceCheckFor(document, from.url);
    const warnings = parsed.warnings.slice(0);
    if (resourceCheck.checked && !resourceCheck.matches) {
      if (!lenient) {
        log.debug("Leaving ProtectedResourceMetadata.analyse(). Section 3.3 " +
                  "refused.");
        return self.refusal('STS-REG-0087', resourceCheck.why + ' This ' +
          'service is running as a product (global.mode=product), so the ' +
          'document is ' +
          'refused.', { resourceCheck: resourceCheck });
      }
      warnings.unshift(resourceCheck.why + ' It is accepted because this ' +
                       'service is in development mode.');
    }
    if (!parsed.httpsResource) {
      const why = '`resource` is ' + document.resource + '; RFC 9728 section ' +
                  '2 makes a resource identifier a URL that uses the https ' +
                  'scheme.';
      if (!lenient) {
        log.debug("Leaving ProtectedResourceMetadata.analyse(). Not https, " +
                  "refused.");
        return self.refusal('STS-REG-0088', why + ' This service is running ' +
                       'as a product (global.mode=product), so the document ' +
                       'is ' +
                       'refused.');
      }
      warnings.unshift(why + ' It is accepted because this service is in ' +
                       'development mode.');
    }
    if (parsed.signedMetadata) {
      warnings.push('The document carries `signed_metadata`. It is decoded ' +
        'and shown and is NOT verified or applied: this service holds no key ' +
        'for the resource, and RFC 9728 section 2.2 lets a recipient that ' +
        'does not process signed metadata ignore it.');
    }
    const servers = self.compareAuthorizationServers(document,
        (context && context.authorizationServers) || []);
    const plan = self.planFor(document);
    log.debug("Leaving ProtectedResourceMetadata.analyse(). ok.");
    return {
      ok: true,
      source: from.source || 'pasted',
      url: from.url || '',
      filename: from.filename || '',
      contentType: from.contentType || '',
      document: document,
      // The document as it was read, compact — what the form carries back and
      // what the entry stores unless the third tab changes a member.
      compact: JSON.stringify(document),
      pretty: JSON.stringify(document, null, 2),
      members: parsed.members,
      extensions: parsed.extensions,
      signedMetadata: parsed.signedMetadata,
      resourceCheck: resourceCheck,
      authorizationServers: servers,
      plan: plan,
      warnings: warnings.concat(plan.warnings),
      message: 'The protected resource metadata for ' + document.resource +
               ' was read. Nothing has been created yet: review it and ' +
               'create the application.'
    };
  }

  // ---------------------------------------------------------------------------
  // THE DOCUMENT AS THE THIRD TAB LEFT IT.
  //
  // The console form carries the document it loaded back in `metadata` and one
  // field per member it read in `metadata.<member>`. A member's box being
  // present is what makes it an edit; an emptied box removes the member. A
  // member RFC 9728 does not define, and `signed_metadata`, have no box and are
  // kept exactly as they were. Returns the compact JSON to store, or '' where
  // the form carried no document.
  // ---------------------------------------------------------------------------
  documentFromForm(body: Json) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ProtectedResourceMetadata.documentFromForm().");
    const form = body || {};
    let document = null;
    try {
      document = JSON.parse(String(form.metadata || ''));
    } catch (e) {
      log.debug("Caught in ProtectedResourceMetadata.documentFromForm(): " +
                ((e && e.message) || e));
      log.debug("Leaving ProtectedResourceMetadata.documentFromForm(). No " +
                "document.");
      return '';
    }
    if (!document || typeof document !== 'object' || Array.isArray(document)) {
      log.debug("Leaving ProtectedResourceMetadata.documentFromForm(). Not " +
                "an object.");
      return '';
    }
    Object.keys(document).forEach(function (name) {
      const row = self.memberRowFor(name);
      const key = 'metadata.' + name;
      if (!row || row.type === 'jwt' ||
          !Object.prototype.hasOwnProperty.call(form, key)) {
        return;
      }
      const raw = String(form[key] == null ? '' : form[key]);
      if (row.type === 'bool') {
        if (raw === 'true' || raw === 'false') {
          document[name] = raw === 'true';
        } else {
          delete document[name];
        }
        return;
      }
      if (row.type === 'string-list' || row.type === 'uri-list') {
        const list = raw.split(/\r?\n/).map(function (one) {
          return one.trim();
        }).filter(function (one) { return one !== ''; });
        if (list.length) {
          document[name] = list;
        } else {
          delete document[name];
        }
        return;
      }
      if (raw.trim()) {
        document[name] = raw.trim();
      } else {
        delete document[name];
      }
    });
    log.debug("Leaving ProtectedResourceMetadata.documentFromForm().");
    return JSON.stringify(document);
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
const slot = new InstanceSlot<ProtectedResourceMetadata>(
  'oauth-oidc/protected_resource_metadata',
  () => new ProtectedResourceMetadata(ProtectedResourceMetadata.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  ProtectedResourceMetadata: ProtectedResourceMetadata,
  installInstance: (instance: ProtectedResourceMetadata): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  WELL_KNOWN: ProtectedResourceMetadata.WELL_KNOWN,
  MEMBERS: ProtectedResourceMetadata.MEMBERS,
  memberRowFor: slot.forward('memberRowFor'),
  parseDocument: slot.forward('parseDocument'),
  wellKnownUrlFor: slot.forward('wellKnownUrlFor'),
  resourcesForWellKnownUrl: slot.forward('resourcesForWellKnownUrl'),
  resourceCheckFor: slot.forward('resourceCheckFor'),
  internalAddressProblem: slot.forward('internalAddressProblem'),
  fetchDocument: slot.forward('fetchDocument'),
  authorizationServersOf: slot.forward('authorizationServersOf'),
  compareAuthorizationServers: slot.forward('compareAuthorizationServers'),
  generateClientId: slot.forward('generateClientId'),
  permissionFor: slot.forward('permissionFor'),
  planFor: slot.forward('planFor'),
  load: slot.forward('load'),
  analyse: slot.forward('analyse'),
  documentFromForm: slot.forward('documentFromForm')
};
