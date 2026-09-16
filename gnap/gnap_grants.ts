'use strict';
//
// File: gnap_grants.ts
//
// ---------------------------------------------------------------------------
// THE GRANT ENGINE: EVERY DECISION A GNAP AUTHORIZATION SERVER MAKES, IN ONE
// ROUTE-FREE LIBRARY.
//
// Two route modules call it — `gnap.ts` (the grant endpoint, continuation,
// token management, the RS-facing API) and `gnap_interact.ts` (the pages a
// resource owner sees) — and a grant crosses between them twice: created at the
// grant endpoint, decided on a page, released at the continuation URI. So the
// state machine of RFC 9635 section 1.5 lives HERE, where both halves reach it,
// and neither route module holds a rule the other could contradict.
//
// ---------------------------------------------------------------------------
// THE LIFE OF A GRANT, AS THIS SERVICE RUNS IT.
//
//   processing  the request is read, the client and its key identified and
//               PROVED, the user member resolved, the policy asked.
//   pending     interaction is needed. The response carries the start modes
//               and a continuation token. When the RO decides, the grant stays
//               PENDING with a DECISION recorded on it — approved or denied —
//               until the client continues: section 5.1 says an interaction
//               reference presented when the request is "not in the pending
//               state" is `too_many_attempts`, so the grant cannot leave
//               pending before the client has presented it.
//   approved    the client continued; tokens and subject information are
//               released. The grant stays approved (and continuable, section
//               5.3) until it is revoked or its tokens are gone.
//   finalized   revoked by the client (section 5.4), exhausted (too many polls,
//               an interaction reference replayed), or expired. Never leaves.
//
// ---------------------------------------------------------------------------
// WHAT IS MODE-GATED, AND WHAT IS NOT.
//
// The refusals that are the specification's own — an unproved key, a malformed
// request, a flag twice, a continuation token for a different grant — are
// refused in both modes (see gnap_proof.ts's header). What changes with
// `global.mode` is what this service decides about things the specification
// leaves to the AS, through the existing predicates rather than a GNAP one
// (root CLAUDE.md, Code style):
//
//   * **an unknown client key** — `mode.autoCreates()`: development makes an
//     application entry for it on sight (the user's decision, 2026-09-12);
//     product refuses `invalid_client` unless it is registered.
//   * **an unregistered finish URI** — `mode.acceptsUnregisteredAddresses()`,
//     through `applications.returnAddressesOf()`: development records it as
//     observed; product refuses `invalid_interaction`.
//
// ---------------------------------------------------------------------------
// APPROVALS ARE REMEMBERED IN THE CONSENT REGISTER, AS DIGEST TOKENS.
//
// `common/consent.ts` is where this service writes down what a person agreed an
// application may have, on the person's own directory entry — durable in every
// store mode and shown on every consent surface. Its values are RFC 6749 scope
// tokens and a GNAP right is not one (a reference string may carry spaces; an
// object is JSON), so each approved right is stored as `gnap:` + a truncated
// SHA-256 of its CANONICAL JSON (keys and string arrays sorted), approved by
// the user on 2026-09-12. What that costs is said where it is paid: the
// register shows an opaque value, and the readable right is on the grant
// record.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapGrants` takes everything it reads through its constructor — the
// settings, the logger and clock, the error-code table, the mode predicates,
// the audit log, the application registry, the keystore, the issuance gate,
// the consent register, the statistics, the authorization-server profiles and
// the rest of the family — and `oauth2.js` as a LOADER, because that require
// was lazy and stays lazy (it registers routes). The kinds, the protocol name,
// the discovery members and the reserved names are its static constants.
// The module still exports every name it did from a TRANSITIONAL instance for
// `gnap.ts`, `gnap_interact.ts`, `gnap_rs.ts`, `gnap_console.ts` and the
// tests, none of which are converted.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import config = require('../common/config');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import mode = require('../common/mode');
import audit = require('../common/audit');
import applications = require('../common/applications');
import keystore = require('../common/keystore');
import gate = require('../common/issuance_gate');
import consent = require('../common/consent');
import stats = require('../common/admin_stats');
import authorizationServers = require('../oauth-oidc/authorization_servers');
import store = require('./gnap_store');
import keys = require('./gnap_keys');
import proof = require('./gnap_proof');
import request = require('./gnap_request');
import tokens = require('./gnap_tokens');
import subject = require('./gnap_subject');
import transport = require('./gnap_http');
import monitor = require('./gnap_monitor');
import signals = require('./gnap_signals');
import accessRights = require('./gnap_access');

const PROTOCOL = 'GNAP';
const STATE = store.STATE;

// Application kinds this family records (common/applications.js KINDS).
const KIND_CLIENT = 'gnap-client';
const KIND_RS = 'gnap-resource-server';

// An unambiguous alphabet for user codes (section 4.1.2: "choose from character
// values that are easily copied and typed without ambiguity") — no 0/O, 1/I/L.
const USER_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// Reserved first path segments a named authorization server may not take: a
// `/:as/gnap` route would otherwise capture `POST /admin/gnap` and CREATE an
// authorization server called "admin" on sight (authorization_servers.js
// ensure()).
const RESERVED_AS_NAMES = ['admin', 'admin-api', 'realm', 'realms', 'portal',
  'authn', 'oauth2',
  'gnap', 'ssf', 'scim', 'xacml', 'saml2', 'saml11', 'wsfed', 'wstrust', 'tls',
  'pki',
  'federation', 'spiffe', 'logout', 'ldap', 'krb5', 'sts', '.well-known', 'vci',
  'vp',
  'did', 'dpop', 'home', 'KdcProxy'];

// ---------------------------------------------------------------------------
// THE AUTHORIZATION SERVER'S GNAP CAPABILITIES.
//
// "GNAP incorporates the existing authorization server concept": a named
// authorization server (`/:as/...`) is one profile with one set of
// capabilities, and since 2026-09-12 that profile carries GNAP's section 9
// discovery members beside its RFC 8414 ones. The defaults come from the
// `gnap.*` settings; the profile's overrides and removals apply on top; and the
// RESULT is both what OPTIONS publishes and what the grant endpoint enforces —
// the rule `authorization_servers.js` states for OAuth, for the same reason:
// there is no second table of what this server does that could disagree with
// what it says.
// ---------------------------------------------------------------------------
const GNAP_MEMBERS = ['interaction_start_modes_supported',
  'interaction_finish_methods_supported',
  'key_proofs_supported', 'sub_id_formats_supported',
  'assertion_formats_supported',
  'key_rotation_supported', 'token_formats_supported'];

interface GnapGrantsDeps {
  log: typeof helpers.log;
  nowSec: typeof helpers.nowSec;
  baseUrlOf: typeof helpers.baseUrlOf;
  config: typeof config;
  helpers: typeof helpers;
  errorCodes: typeof errorCodes;
  mode: typeof mode;
  audit: typeof audit;
  applications: typeof applications;
  keystore: typeof keystore;
  gate: typeof gate;
  consent: typeof consent;
  stats: typeof stats;
  authorizationServers: typeof authorizationServers;
  store: typeof store;
  keys: typeof keys;
  proof: typeof proof;
  request: typeof request;
  tokens: typeof tokens;
  subject: typeof subject;
  transport: typeof transport;
  monitor: typeof monitor;
  signals: typeof signals;
  accessRights: typeof accessRights;
  // oauth2.js, required when it is needed and not before (it registers
  // routes, and was a lazy require before the conversion).
  loadOauth2(): typeof import('../oauth-oidc/oauth2');
}

class GnapGrants {
  static readonly PROTOCOL = PROTOCOL;
  static readonly KIND_CLIENT = KIND_CLIENT;
  static readonly KIND_RS = KIND_RS;
  static readonly GNAP_MEMBERS = GNAP_MEMBERS;
  static readonly RESERVED_AS_NAMES = RESERVED_AS_NAMES;

  constructor(private readonly deps: GnapGrantsDeps) {
    deps.log.debug("Entering GnapGrants.constructor().");
    deps.log.debug("Leaving GnapGrants.constructor().");
  }

  // `keys.describe()`'s options: the reference resolver, bound to this
  // instance. It was this module's own `resolveKeyReference`, passed by name,
  // before the conversion, and `describe()` only reads it.
  private readonly referenceResolver = {
    resolveReference: (reference) => this.resolveKeyReference(reference)
  };

  private refusal(code, why, gnapError?, status?) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapGrants.refusal().");
    const out = { ok: false, errorCode: code, why: why,
                  gnapError: gnapError || 'invalid_request',
                  status: status || null };
    log.debug("Leaving GnapGrants.refusal().");
    return errorCodes.mark(out, code);
  }

  private bool(value) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.bool().");
    log.debug("Leaving GnapGrants.bool().");
    return value === true ||
           /^(true|1|yes)$/i.test(String(value == null ? '' : value));
  }

  private csv(key) {
    const { log, config } = this.deps;
    log.debug("Entering GnapGrants.csv().");
    const raw = config.value(key);
    const list = Array.isArray(raw) ? raw : String(raw || '').split(',');
    log.debug("Leaving GnapGrants.csv().");
    return list.map(function (one) {
      return String(one).trim();
    }).filter(Boolean);
  }

  fieldValues(app, name) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.fieldValues().");
    if (!app || !app.fields) {
      log.debug("Leaving GnapGrants.fieldValues().");
      return [];
    }
    const value = app.fields[name];
    if (value === undefined || value === null || value === '') {
      log.debug("Leaving GnapGrants.fieldValues().");
      return [];
    }
    log.debug("Leaving GnapGrants.fieldValues().");
    return (Array.isArray(value) ? value : [value]).map(String);
  }

  field(app, name) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.field().");
    log.debug("Leaving GnapGrants.field().");
    return this.fieldValues(app, name)[0] || null;
  }

  // ---------------------------------------------------------------------------
  // URIS. Every URI a response carries is ABSOLUTE (sections 3.1, 3.2.1, 3.3),
  // built from the realm base the request arrived on. The GRANT ENDPOINT
  // carries the authorization server's path; the rest do not need to, because
  // every one of them identifies a grant or a token that already records its
  // AS.
  // ---------------------------------------------------------------------------
  private asPath(asId) {
    const { log, authorizationServers } = this.deps;
    log.debug("Entering GnapGrants.asPath().");
    log.debug("Leaving GnapGrants.asPath().");
    return asId && asId !== authorizationServers.DEFAULT_ID ? '/' + asId : '';
  }

  grantEndpointOf(req, asId) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering GnapGrants.grantEndpointOf().");
    log.debug("Leaving GnapGrants.grantEndpointOf().");
    return baseUrlOf(req) + this.asPath(asId) + '/gnap';
  }

  realmBase(req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering GnapGrants.realmBase().");
    log.debug("Leaving GnapGrants.realmBase().");
    return baseUrlOf(req);
  }

  defaultCapabilities(req, asId) {
    const { log, config, keys, request, tokens, subject } = this.deps;
    log.debug("Entering GnapGrants.defaultCapabilities().");
    const startModes = this.csv('gnap.interactionStartModes').filter(
        function (m) {
      return request.START_MODES.indexOf(m) >= 0;
    });
    const finish = this.csv('gnap.finishMethods').filter(function (m) {
      return request.FINISH_METHODS.indexOf(m) >= 0 &&
             (m !== 'push' || config.value('gnap.pushFinish'));
    });
    log.debug("Leaving GnapGrants.defaultCapabilities().");
    return {
      grant_request_endpoint: this.grantEndpointOf(req, asId),
      interaction_start_modes_supported: startModes,
      interaction_finish_methods_supported: finish,
      key_proofs_supported: this.csv('gnap.keyProofs').filter(function (m) {
        return keys.PROOF_METHODS.indexOf(m) >= 0;
      }),
      sub_id_formats_supported: this.csv('gnap.subIdFormats').filter(
          function (f) {
        return subject.SUB_ID_FORMATS_SUPPORTED.indexOf(f) >= 0;
      }),
      assertion_formats_supported: this.csv('gnap.assertionFormats').filter(
          function (f) {
        return subject.ASSERTION_FORMATS_SUPPORTED.indexOf(f) >= 0;
      }),
      key_rotation_supported: !!config.value('gnap.keyRotation'),
      token_formats_supported: this.csv('gnap.tokenFormats').filter(
          function (f) {
        return tokens.FORMATS.indexOf(f) >= 0;
      })
    };
  }

  capabilities(req, asId) {
    const { log, authorizationServers } = this.deps;
    log.debug("Entering GnapGrants.capabilities().");
    const defaults = this.defaultCapabilities(req, asId);
    const merged = authorizationServers.capabilitiesOf(
        asId || authorizationServers.DEFAULT_ID,
                                                       defaults, 'gnap');
    const out: Record<string, any> = { grant_request_endpoint:
                                       defaults.grant_request_endpoint };
    GNAP_MEMBERS.forEach(function (member) {
      if (merged[member] !== undefined) {
        out[member] = merged[member];
      }
    });
    log.debug("Leaving GnapGrants.capabilities().");
    return out;
  }

  // A list capability, or null when the profile REMOVED the member — which the
  // OAuth side reads as "enforce nothing" (authorization_servers.js), and so
  // does this one.
  capabilityList(req, asId, member) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.capabilityList().");
    const value = this.capabilities(req, asId)[member];
    if (value === undefined) {
      log.debug("Leaving GnapGrants.capabilityList().");
      return null;
    }
    log.debug("Leaving GnapGrants.capabilityList().");
    return Array.isArray(value) ? value.map(String) : [String(value)];
  }

  private allows(list, value) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.allows().");
    log.debug("Leaving GnapGrants.allows().");
    return list === null || list.indexOf(value) >= 0;
  }

  // ---------------------------------------------------------------------------
  // APPLICATION ENTRIES. Every GNAP client instance and resource server is one
  // (the user's requirement), found by the identity of its key, by its static
  // instance identifier, or by a dynamic one this AS issued.
  // ---------------------------------------------------------------------------
  gnapApplications() {
    const { log, applications } = this.deps;
    log.debug("Entering GnapGrants.gnapApplications().");
    log.debug("Leaving GnapGrants.gnapApplications().");
    return applications.list().filter((app) => {
      return (app.kinds || []).some(function (kind) {
        return kind === KIND_CLIENT || kind === KIND_RS;
      }) || (app.allowedProtocols || []).indexOf('gnap') >= 0 ||
        !!this.field(app, 'gnapKey') || !!this.field(app, 'gnapInstanceId');
    });
  }

  private registeredKeyIdentity(app) {
    const { log, errorCodes, keys } = this.deps;
    log.debug("Entering GnapGrants.registeredKeyIdentity().");
    const raw = this.field(app, 'gnapKey');
    if (!raw) {
      log.debug("Leaving GnapGrants.registeredKeyIdentity().");
      return null;
    }
    try {
      const described = keys.describe(JSON.parse(raw), {});
      log.debug("Leaving GnapGrants.registeredKeyIdentity().");
      return described.ok ? described.identity : null;
    } catch (e) {
      log.debug("Caught in GnapGrants.registeredKeyIdentity(): " +
                ((e && e.message) || e));
      // A registered key that is not JSON. The console refuses to write one; an
      // LDAP modify can. It identifies nobody, and the log says which entry.
      log.warn(errorCodes.tag('STS-GNAP-0652') + 'gnap: the application "' +
               app.identifier + '" carries a gnapKey that is not a JSON key ' +
               'object: ' + e.message);
      log.debug("Leaving GnapGrants.registeredKeyIdentity().");
      return null;
    }
  }

  private appByKeyIdentity(identity) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.appByKeyIdentity().");
    log.debug("Leaving GnapGrants.appByKeyIdentity().");
    return this.gnapApplications().filter((app) => {
      return this.registeredKeyIdentity(app) === identity ||
             this.field(app, 'gnapKeyIdentity') === identity;
    })[0] || null;
  }

  private appByInstanceId(instanceId) {
    const { log, applications, store } = this.deps;
    log.debug("Entering GnapGrants.appByInstanceId().");
    const dynamic = store.instanceById(instanceId);
    if (dynamic) {
      const app = applications.get(dynamic.identifier);
      log.debug("Leaving GnapGrants.appByInstanceId().");
      return app ? { app: app, key: dynamic.key, dynamic: true } : null;
    }
    const app = this.gnapApplications().filter((one) => {
      return this.field(one, 'gnapInstanceId') === instanceId;
    })[0];
    log.debug("Leaving GnapGrants.appByInstanceId().");
    return app ?
           { app: app,
                   key: this.field(app, 'gnapKey') ?
                        JSON.parse(this.field(app, 'gnapKey')) : null,
                   dynamic: false } : null;
  }

  // Resolve a key REFERENCE (section 7.1.1) against application entries: a
  // registered `gnapKeyReference` naming either the entry's public key or its
  // shared secret. The secret is SEALED at rest when keys persist
  // (common/keystore.js) and arrives opened through applications.get().
  resolveKeyReference(reference) {
    const { log, errorCodes, keystore } = this.deps;
    log.debug("Entering GnapGrants.resolveKeyReference().");
    const app = this.gnapApplications().filter((one) => {
      return this.field(one, 'gnapKeyReference') === reference;
    })[0];
    if (!app) {
      log.debug("Leaving GnapGrants.resolveKeyReference(). Unknown.");
      return null;
    }
    const secret = this.field(app, 'gnapSymmetricKey');
    if (secret) {
      let bytes = Buffer.from(secret, 'base64url');
      if (keystore.persists() && /^\$aesgcm\$/.test(secret)) {
        // Still ciphertext: the opened view could not open it. Refused rather
        // than used — a MAC keyed with ciphertext would verify nothing any
        // client could produce, and the log names the entry.
        log.warn(errorCodes.tag('STS-GNAP-0653') + 'gnap: the shared key on "' +
                 app.identifier +
                 '" could not be opened with this process\'s key-encryption ' +
                 'key.');
        log.debug("Leaving GnapGrants.resolveKeyReference(). Sealed and " +
                  "unopenable.");
        return null;
      }
      if (bytes.length < 32) {
        // Section 7.1.2: a symmetric key "MUST NOT be a human-memorable
        // password". Thirty-two bytes is HS256's own key length.
        bytes = null;
      }
      log.debug("Leaving GnapGrants.resolveKeyReference(). Shared secret.");
      return bytes ? { secret: bytes, proof: this.field(app, 'gnapKeyProof') ||
                       'httpsig', alg: this.field(app, 'gnapSymmetricAlg') ||
                       'HS256', app: app } : null;
    }
    const raw = this.field(app, 'gnapKey');
    log.debug("Leaving GnapGrants.resolveKeyReference(). Registered public " +
              "key.");
    return raw ? { key: JSON.parse(raw), app: app } : null;
  }

  // ---------------------------------------------------------------------------
  // WHO IS CALLING: the client (or RS) member, its key, the entry, and the
  // proof.
  //
  // `member` is `{ reference, key, classId, display }` (gnap_request.ts).
  // `kind` is KIND_CLIENT or KIND_RS.
  // ---------------------------------------------------------------------------
  async identifyCaller(req, body, member, kind, options?) {
    const { log, mode, applications, keys, proof, monitor } = this.deps;
    log.debug("Entering GnapGrants.identifyCaller(). kind=" + kind);
    const opts = options || {};
    let descriptor;
    let app = null;
    let instanceId = null;
    if (member.reference) {
      const found = this.appByInstanceId(member.reference);
      if (!found) {
        log.debug("Leaving GnapGrants.identifyCaller(). Unknown instance " +
                  "identifier.");
        return this.refusal('STS-GNAP-0080', 'the instance identifier is not ' +
            'one this authorization server knows (RFC 9635 section 2.3.1).',
                            kind === KIND_RS ? 'invalid_resource_server' :
                            'invalid_client', 401);
      }
      app = found.app;
      instanceId = member.reference;
      if (found.key) {
        descriptor = keys.describe(found.key,
                                   this.referenceResolver);
      } else if (this.field(app, 'gnapKeyReference')) {
        descriptor = keys.describe(this.field(app, 'gnapKeyReference'),
                                   this.referenceResolver);
      } else {
        descriptor = this.refusal('STS-GNAP-0081', 'the application "' +
                                  app.identifier + '" has no key registered ' +
                                  'to verify its requests with.',
                                  'invalid_client', 401);
      }
    } else {
      descriptor = keys.describe(member.key,
                                 this.referenceResolver);
    }
    if (!descriptor.ok) {
      log.debug("Leaving GnapGrants.identifyCaller(). The key is refused: " +
                descriptor.why);
      descriptor.status = 401;
      if (kind === KIND_RS && descriptor.gnapError === 'invalid_client') {
        descriptor.gnapError = 'invalid_resource_server';
      }
      log.debug("Leaving GnapGrants.identifyCaller().");
      return descriptor;
    }
    // ONCE ACROSS THE CLUSTER (#46): the proof's replay keys are spent before
    // anything is done for this caller — gnap_proof.ts's verifyRequestOnce().
    const verified = await proof.verifyRequestOnce(req, body, descriptor, {
        accessToken: opts.accessToken || null });
    if (!verified.ok) {
      log.debug("Leaving GnapGrants.identifyCaller(). Proof refused: " +
                verified.why);
      monitor.record(app ? app.identifier : '(unidentified)', 'proof.failed',
                     { gnapError: kind === KIND_RS ? 'invalid_resource_server' :
                                  'invalid_client' });
      log.debug("Leaving GnapGrants.identifyCaller().");
      return Object.assign(verified, { gnapError: kind === KIND_RS ?
                                       'invalid_resource_server' :
                                       'invalid_client', status: 401 });
    }
    if (!app && descriptor.reference) {
      const resolved = this.resolveKeyReference(descriptor.reference);
      app = resolved ? resolved.app : null;
    }
    if (!app) {
      app = this.appByKeyIdentity(descriptor.identity);
    }
    let created = false;
    if (!app) {
      // AN UNKNOWN BUT PROVED KEY. Section 2.3.3 lets the AS allow it; the
      // user's decision is that development does, as an application entry, and
      // product does not (the header).
      if (!mode.autoCreates()) {
        log.debug("Leaving GnapGrants.identifyCaller(). Unregistered key in " +
                  "product mode.");
        return this.refusal('STS-GNAP-0082', 'this key is not registered ' +
            'with this authorization server, and in product mode an ' +
            'application must be provisioned before it can make requests ' +
                            '(RFC 9635 section 2.3.3).', kind === KIND_RS ?
                            'invalid_resource_server' : 'invalid_client', 401);
      }
      const identifier = 'gnap-' +
                         descriptor.identity.replace(/[^A-Za-z0-9_-]/g, '-')
                                            .slice(0, 48);
      const fields: Record<string, any> = { gnapKey:
                                            JSON.stringify(descriptor.value),
                                            gnapKeyIdentity:
                                            descriptor.identity };
      if (member.classId) {
        fields.gnapClassId = member.classId;
      }
      if (member.display && member.display.uri) {
        fields.gnapDisplayUri = member.display.uri;
      }
      if (member.display && member.display.logoUri &&
          member.display.logoUri.length < 2048) {
        fields.gnapLogoUri = member.display.logoUri;
      }
      applications.seen({ identifier: identifier, kind: kind, protocol:
                          PROTOCOL, name: (member.display &&
                                           member.display.name) || undefined,
                          counts: false, fields: fields, note:
          'Created on first sight of a proved GNAP key (development mode).' });
      app = applications.get(identifier);
      created = true;
      if (!app) {
        log.debug("Leaving GnapGrants.identifyCaller(). The entry could not " +
                  "be created.");
        return this.refusal('STS-GNAP-0083', 'the application entry for this ' +
                            'key could not be created.', 'invalid_client', 401);
      }
    } else {
      applications.seen({ identifier: app.identifier, kind: kind,
                          protocol: PROTOCOL, counts: false });
    }
    log.debug("Leaving GnapGrants.identifyCaller(). app=" + app.identifier +
              ", created=" + created);
    return { ok: true, app: app, descriptor: descriptor, proof: verified,
             instanceId: instanceId,
             created: created,
            // Section 2.3: "the pre-registered values MUST take precedence".
             display: {
               name: app.name || (member.display && member.display.name) ||
                   app.identifier, uri: this.field(app, 'gnapDisplayUri') ||
                   (member.display && member.display.uri) || null, logoUri:
                   this.field(app, 'gnapLogoUri') || (member.display &&
                                                      member.display.logoUri) ||
                   null }, classId: this.field(app, 'gnapClassId') ||
                   member.classId || null };
  }

  // ---------------------------------------------------------------------------
  // ACCESS POLICY for one requested token.
  // ---------------------------------------------------------------------------
  canonicalJson(value) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.canonicalJson().");
    if (Array.isArray(value)) {
      const items = value.map((one) => this.canonicalJson(one));
      log.debug("Leaving GnapGrants.canonicalJson().");
      return '[' +
             (value.every(function (one) { return typeof one === 'string'; })
        ? items.slice().sort() : items).join(',') + ']';
    }
    if (value && typeof value === 'object') {
      log.debug("Leaving GnapGrants.canonicalJson().");
      return '{' + Object.keys(value).sort().map((name) => {
        return JSON.stringify(name) + ':' + this.canonicalJson(value[name]);
      }).join(',') + '}';
    }
    log.debug("Leaving GnapGrants.canonicalJson().");
    return JSON.stringify(value);
  }

  digestTokenOf(right) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.digestTokenOf().");
    log.debug("Leaving GnapGrants.digestTokenOf().");
    return 'gnap:' + nodeCrypto.createHash('sha256')
        .update(this.canonicalJson(right), 'utf8').digest('base64url').slice(0,
        22);
  }

  // What a client may ask for (`gnapAllowedAccess`: types and reference
  // strings; empty means anything) and what an unknown reference string does.
  private accessProblem(app, access) {
    const { log, config, store } = this.deps;
    log.debug("Entering GnapGrants.accessProblem().");
    const allowed = this.fieldValues(app, 'gnapAllowedAccess');
    for (let i = 0; i < access.length; i++) {
      const right = access[i];
      const name = typeof right === 'string' ? right : right.type;
      if (allowed.length && allowed.indexOf(name) < 0) {
        log.debug("Leaving GnapGrants.accessProblem(). Not allowed for this " +
                  "client.");
        return 'the right "' + name + '" is not one this client instance may ' +
                                      'request';
      }
      if (typeof right === 'string' && !store.resourceByReference(right) &&
          String(config.value('gnap.unknownAccessReferences') ||
                 'accept') === 'refuse' &&
          allowed.indexOf(right) < 0) {
        log.debug("Leaving GnapGrants.accessProblem(). Unknown reference " +
                  "refused.");
        return 'the access reference "' + right + '" names nothing ' +
            'registered with this authorization server';
      }
    }
    log.debug("Leaving GnapGrants.accessProblem().");
    return '';
  }

  // ---------------------------------------------------------------------------
  // RESOURCE SERVERS AND TOKEN FORMAT for a set of rights.
  // ---------------------------------------------------------------------------
  resourceServersFor(access) {
    const { log, store } = this.deps;
    log.debug("Entering GnapGrants.resourceServersFor().");
    const found = {};
    (access || []).forEach((right) => {
      if (typeof right === 'string') {
        const row = store.resourceByReference(right);
        if (row && row.rsIdentifier) {
          found[row.rsIdentifier] = true;
        }
        return;
      }
      (right.locations || []).forEach((location) => {
        this.gnapApplications().forEach((app) => {
          if (this.fieldValues(app, 'gnapResourceServerUri').some(
              function (uri) {
            return location === uri || location.indexOf(uri) === 0;
          })) {
            found[app.identifier] = true;
          }
        });
      });
    });
    log.debug("Leaving GnapGrants.resourceServersFor().");
    return Object.keys(found);
  }

  private chooseFormat(req, grant, access, rsIds) {
    const { log, config, applications, store, tokens } = this.deps;
    log.debug("Entering GnapGrants.chooseFormat().");
    const enabled = this.capabilityList(req, grant.as,
                                        'token_formats_supported') ||
        tokens.FORMATS;
    let candidates = enabled.slice();
    (access || []).forEach(function (right) {
      if (typeof right === 'string') {
        const row = store.resourceByReference(right);
        if (row && row.tokenFormats && row.tokenFormats.length) {
          candidates = candidates.filter(function (format) {
            return row.tokenFormats.indexOf(format) >= 0;
          });
        }
      }
    });
    if (!candidates.length) {
      log.debug("Leaving GnapGrants.chooseFormat(). No format satisfies " +
                "every resource set.");
      return null;
    }
    const preferences = [];
    if (rsIds.length === 1) {
      const rs = applications.get(rsIds[0]);
      if (this.field(rs, 'gnapAccessTokenFormat')) {
        preferences.push(this.field(rs, 'gnapAccessTokenFormat'));
      }
    }
    const client = applications.get(grant.client.identifier);
    if (this.field(client, 'gnapAccessTokenFormat')) {
      preferences.push(this.field(client, 'gnapAccessTokenFormat'));
    }
    preferences.push(String(config.value('gnap.accessTokenFormat') ||
                            'jwt-signed'));
    const chosen = preferences.filter(function (format) {
      return candidates.indexOf(format) >= 0;
    })[0] || candidates[0];
    log.debug("Leaving GnapGrants.chooseFormat(). " + chosen);
    return chosen;
  }

  // ---------------------------------------------------------------------------
  // TOKEN ISSUANCE for an approved grant (section 3.2).
  //
  // `requests` is `[{ label, access, bearer }]` of APPROVED rights. Returns the
  // response member: an object for a single-token request and an array for a
  // multiple-token one (section 3.2.2: the AS MUST NOT switch shapes), omitting
  // a token the AS refused (section 3.2.2 allows that).
  // ---------------------------------------------------------------------------
  private async issueTokens(req, grant, requests, multiple) {
    const { log, nowSec, config, helpers, errorCodes, audit, applications,
          gate, store, keys, tokens, monitor } = this.deps;
    log.debug("Entering GnapGrants.issueTokens(). grant=" + grant.id + ", " +
        requests.length + " " +
        "token(s)");
    const out = [];
    const base = this.realmBase(req);
    const client = applications.get(grant.client.identifier);
    for (let i = 0; i < requests.length; i++) {
      const asked = requests[i];
      if (!asked.access.length) {
        continue;
      }
      const username = grant.ro ? grant.ro.username : null;
      const allowed = gate.check({
        application: grant.client.identifier, kind: gate.ISSUANCE.ACCESS_TOKEN,
            subject: username ? { kind: 'user', name: username, authenticated:
                                  true } : { kind: 'application', name:
                                             grant.client.identifier,
                                             authenticated: true }, claims:
            null });
      if (!allowed.allowed) {
        log.info('gnap: the issuance policy refused a token for grant ' +
                 grant.id + ': ' + allowed.why);
        audit.failure('STS-GNAP-0090', { protocol: PROTOCOL, channel: 'http',
                                         target: grant.client.identifier,
                                         summary: 'The issuance policy ' +
                                         'refused a GNAP access token', detail:
                                         { grant: grant.id, why:
                                           String(allowed.why || '') } });
        continue;
      }
      const rsIds = this.resourceServersFor(asked.access);
      const format = this.chooseFormat(req, grant, asked.access, rsIds);
      if (!format) {
        audit.failure('STS-GNAP-0091', { protocol: PROTOCOL, channel: 'http',
                                         target: grant.client.identifier,
                                         summary: 'No token format satisfies ' +
                                         'every requested resource set',
                                         detail: { grant: grant.id } });
        continue;
      }
      const iat = nowSec();
      const lifetime = Number(applications.settingFor(grant.client.identifier,
          'gnap.accessTokenLifetimeS', config)) || 3600;
      const durable = !!config.value('gnap.durableTokens');
      const flags = [];
      if (asked.bearer) {
        flags.push('bearer');
      }
      if (durable) {
        flags.push('durable');
      }
      const keyDescriptor = keys.describe(grant.client.key,
                                          this.referenceResolver);
      const audience = rsIds.slice();
      if (!audience.length &&
          (config.value('gnap.demoResourceServer') !== false)) {
        // A token for nobody in particular is valid at the demonstration RS,
        // which is how a client can present one somewhere at all.
        audience.push(base + '/gnap/rs/resource');
      }
      const model = {
        jti: store.mint(16),
        iss: grant.grantEndpoint,
        sub: username ? helpers.userFor(username).sub : null,
        aud: audience,
        instanceId: grant.client.identifier,
        access: asked.access,
        flags: flags,
        cnf: asked.bearer ? null : keys.confirmationOf(keyDescriptor),
        iat: iat,
        nbf: iat,
        exp: iat + lifetime,
        label: asked.label || null
      };
      const rs = rsIds.length === 1 ? applications.get(rsIds[0]) : null;
      let jweKey = null;
      if (rs && this.field(rs, 'gnapJweKey')) {
        try {
          jweKey = JSON.parse(this.field(rs, 'gnapJweKey'));
        } catch (e) {
          log.debug("Caught in GnapGrants.issueTokens(): " +
                    ((e && e.message) || e));
          // Not a JWK: encrypted to this AS instead, and said so.
          log.warn(errorCodes.tag('STS-GNAP-0654') + 'gnap: "' + rs.identifier +
                   '" ' +
                   'carries a gnapJweKey that is not JSON; jwt-encrypted ' +
                   'tokens for it are encrypted to this authorization server ' +
                   'instead: ' + e.message);
        }
      }
      let minted;
      try {
        minted = await tokens.mint(format, model, { base: base,
          rs: rs ? { identity: rs.identifier, jweKey: jweKey } : null,
          sessionId: grant.ro ? grant.ro.sessionId : null, setId: grant.id });
      } catch (e) {
        log.debug("Caught in GnapGrants.issueTokens(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-GNAP-0092') + 'gnap: a ' + format + ' ' +
                  'access token could not be minted for ' +
                  'grant ' + grant.id + ': ' + e.message);
        continue;
      }
      const record = store.putToken(Object.assign({}, model, {
        format: format, grantId: grant.id, as: grant.as,
        key: asked.bearer ? null : grant.client.key,
        proof: asked.bearer ? null :
               keyDescriptor.proof, revoked: false, createdAt: iat,
        rsIdentifiers: rsIds, username: username
      }), minted.value);
      const response: Record<string, any> = { value: minted.value, access:
                                              asked.access, expires_in:
                                              lifetime };
      if (asked.label) {
        response.label = asked.label;
      }
      if (flags.length) {
        response.flags = flags;
      }
      if (config.value('gnap.tokenManagement') !== false) {
        const manageValue = store.issueManagement(record);
        store.saveToken(record);
        response.manage = { uri: base + '/gnap/token/' + record.manageHandle,
                            access_token: { value: manageValue } };
      }
      grant.tokens = (grant.tokens || []).concat([record.jti]);
      monitor.record(grant.client.identifier, 'token.issued', { format:
          format });
      if (rsIds.length === 1) {
        monitor.record(rsIds[0], 'rs.presented', {});
      }
      audit.audit({ action: 'gnap.token.issue', category: 'protocol',
        protocol: PROTOCOL,
        channel: 'http', outcome: 'success', actor: username ||
                                                    grant.client.identifier,
        target: grant.client.identifier,
        summary: 'A GNAP ' + format + ' access token was issued',
        detail: { grant: grant.id, jti: record.jti, format: format,
                  bearer: !!asked.bearer,
                  label: asked.label || '' } });
      out.push(response);
    }
    if (client) {
      applications.seen({ identifier: client.identifier, kind: KIND_CLIENT,
                          protocol: PROTOCOL, counts: true, user: grant.ro ?
                          grant.ro.username : undefined, sessionId: grant.ro ?
                          grant.ro.sessionId : undefined });
    }
    log.debug("Leaving GnapGrants.issueTokens(). " + out.length + " issued.");
    if (!out.length) {
      log.debug("Leaving GnapGrants.issueTokens().");
      return null;
    }
    log.debug("Leaving GnapGrants.issueTokens().");
    return multiple ? out : out[0];
  }

  // Subject information for an approved grant with a known RO (section 3.4).
  private async releaseSubject(req, grant) {
    const { log, nowSec, gate, subject, monitor } = this.deps;
    log.debug("Entering GnapGrants.releaseSubject().");
    if (!grant.request.subject || !grant.ro) {
      log.debug("Leaving GnapGrants.releaseSubject(). Nothing requested or " +
                "no RO.");
      return null;
    }
    const oauth2 = this.deps.loadOauth2();
    const issuer = oauth2.issuerOf(this.realmBase(req));
    const formats = grant.request.subject.subIdFormats.filter((format) => {
      return this.allows(this.capabilityList(req, grant.as,
                                             'sub_id_formats_supported'),
                         format);
    });
    const assertionFormats = grant.request.subject.assertionFormats.filter(
        (format) => {
      return this.allows(this.capabilityList(req, grant.as,
                                             'assertion_formats_supported'),
                         format);
    });
    const out: Record<string, any> = {};
    const ids = subject.subIdsFor(grant.ro.username, formats, { issuer:
        issuer });
    if (ids.length) {
      out.sub_ids = ids;
    }
    const wanted = assertionFormats.filter(function (format) {
      const kind = format === 'id_token' ? gate.ISSUANCE.ID_TOKEN :
                   gate.ISSUANCE.SAML_ASSERTION;
      return gate.check({ application: grant.client.identifier, kind: kind,
                          subject: { kind: 'user', name: grant.ro.username,
                                     authenticated: true },
                          claims: null }).allowed;
    });
    if (wanted.length) {
      out.assertions = await subject.assertionsFor(grant.ro.username, wanted, {
        oauthBase: this.realmBase(req), instanceId: grant.client.identifier,
        issuer: issuer,
        authTime: grant.ro.authTime, amr: grant.ro.amr, acr: grant.ro.acr,
        sessionId: grant.ro.sessionId, setId: grant.id });
    }
    out.updated_at = new Date((grant.ro.authTime ||
                               nowSec()) * 1000).toISOString();
    monitor.record(grant.client.identifier, 'subject.released', {});
    log.debug("Leaving GnapGrants.releaseSubject().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE CONTINUATION MEMBER (section 3.1). A new token every time (section 5:
  // SHOULD invalidate the previous one), and `wait` always stated, because its
  // omission MUST be read as five seconds and a client should not have to know
  // that.
  // ---------------------------------------------------------------------------
  private continueMember(req, grant) {
    const { log, nowSec, config, store } = this.deps;
    log.debug("Entering GnapGrants.continueMember().");
    const value = store.issueContinuation(grant);
    const wait = Math.max(0, Number(config.value('gnap.continueWaitS')));
    grant.continueNotBefore = nowSec() + (Number.isFinite(wait) ? wait : 5);
    log.debug("Leaving GnapGrants.continueMember().");
    return { access_token: { value: value },
             uri: this.realmBase(req) + '/gnap/continue/' + grant.id,
             wait: Number.isFinite(wait) ? wait : 5 };
  }

  private newUserCode() {
    const { log, config, store } = this.deps;
    log.debug("Entering GnapGrants.newUserCode().");
    const length = Math.min(8,
                            Math.max(6,
                                     Number(config.value(
                                         'gnap.userCodeLength')) || 8));
    for (let attempt = 0; attempt < 20; attempt++) {
      let code = '';
      const bytes = nodeCrypto.randomBytes(length);
      for (let i = 0; i < length; i++) {
        code += USER_CODE_ALPHABET[bytes[i] % USER_CODE_ALPHABET.length];
      }
      if (!store.userCodeTaken(code)) {
        log.debug("Leaving GnapGrants.newUserCode().");
        return code;
      }
    }
    log.debug("Leaving GnapGrants.newUserCode().");
    return null;
  }

  // Section 4.1.2: strip what is not in the alphabet, compare
  // case-insensitively.
  normaliseUserCode(input) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.normaliseUserCode().");
    log.debug("Leaving GnapGrants.normaliseUserCode().");
    return String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  }

  // ---------------------------------------------------------------------------
  // START INTERACTION (section 3.3). Answers the `interact` response member, or
  // a refusal when no mode the client offered can be used and the AS cannot
  // reach the RO any other way (section 2.5: invalid_interaction).
  // ---------------------------------------------------------------------------
  private startInteraction(req, grant, app, interact) {
    const { log, nowSec, config, mode, applications, store, request, transport,
          monitor } = this.deps;
    log.debug("Entering GnapGrants.startInteraction(). grant=" + grant.id);
    const supportedStarts = this.capabilityList(req, grant.as,
        'interaction_start_modes_supported');
    const appModes = this.fieldValues(app, 'gnapInteractionStartModes');
    const usable = interact.start.filter((mode) => {
      return request.START_MODES.indexOf(mode) >= 0 &&
             this.allows(supportedStarts, mode) &&
        (!appModes.length || appModes.indexOf(mode) >= 0);
    });
    const finishMethods = this.capabilityList(req, grant.as,
        'interaction_finish_methods_supported');
    let finish = null;
    if (interact.finish &&
        request.FINISH_METHODS.indexOf(interact.finish.method) >= 0 &&
        this.allows(finishMethods, interact.finish.method)) {
      finish = interact.finish;
    }
    if (!usable.length && !(finish && finish.method === 'push')) {
      log.debug("Leaving GnapGrants.startInteraction(). No usable start mode.");
      return this.refusal('STS-GNAP-0100', 'none of the interaction start ' +
                          'modes offered (' + (interact.start.join(', ') ||
                                               'none') + ') is supported for ' +
          'this client, and this authorization server cannot reach the ' +
                          'resource owner another way (RFC 9635 section 2.5).',
                          'invalid_interaction');
    }
    if (finish) {
      const addresses = applications.returnAddressesOf(app, 'gnapFinishUri');
      const registered = (addresses.registered || []).indexOf(finish.uri) >= 0;
      if (!mode.acceptsUnregisteredAddresses() && !registered) {
        log.debug("Leaving GnapGrants.startInteraction(). Finish URI not " +
                  "registered (product).");
        return this.refusal('STS-GNAP-0101', 'the interaction finish URI is ' +
            'not registered for this client instance, and in product mode ' +
            'only a registered one is used (RFC 9635 sections 2.5.2 and ' +
                            '11.18).', 'invalid_interaction');
      }
      if (mode.acceptsUnregisteredAddresses() && !registered) {
        applications.seen({ identifier: app.identifier, kind: KIND_CLIENT,
                            protocol: PROTOCOL,
                            counts: false, fields: {
                              gnapFinishUri: finish.uri } });
      }
      if (finish.method === 'push') {
        const problem = transport.urlProblem(finish.uri);
        if (problem) {
          log.debug("Leaving GnapGrants.startInteraction(). Push URI cannot " +
                    "be dialled.");
          return this.refusal('STS-GNAP-0102', problem + ' (RFC 9635 section ' +
                              '11.34).', 'invalid_interaction');
        }
      }
      if (!/^https:/i.test(finish.uri) &&
          !mode.acceptsUnregisteredAddresses() &&
          !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/)/i.test(
            finish.uri) &&
          /^http:/i.test(finish.uri)) {
        log.debug("Leaving GnapGrants.startInteraction(). Plain http finish " +
                  "URI in product.");
        return this.refusal('STS-GNAP-0103', 'the finish URI must be https, ' +
            'localhost, or an application scheme (RFC 9635 section 2.5.2.1).',
                            'invalid_interaction');
      }
    }
    const base = this.realmBase(req);
    const lifetime = Number(config.value('gnap.interactionLifetimeS')) || 600;
    const out: Record<string, any> = {};
    const interaction = { modes: {} as Record<string, any>, finish: finish,
                          serverNonce: null, expiresAt: nowSec() + lifetime,
                          started: null, decided: false, decision: null,
                          interactRef: null, approvalId: store.mint(18), hints:
                          interact.hints };
    store.putInteraction('approve:' + interaction.approvalId, grant.id);
    usable.forEach((mode) => {
      if (mode === 'redirect' || mode === 'app') {
        const id = store.mint(18);
        interaction.modes[mode] = { id: id, used: false };
        store.putInteraction(mode + ':' + id, grant.id);
        out[mode] = base + '/gnap/' + (mode === 'redirect' ? 'interact' :
                                       'app') + '/' + id;
      } else if (mode === 'user_code' || mode === 'user_code_uri') {
        const code = interaction.modes.user_code ?
                     interaction.modes.user_code.code
          : (interaction.modes.user_code_uri ?
             interaction.modes.user_code_uri.code : this.newUserCode());
        interaction.modes[mode] = { code: code, used: false };
        store.putUserCode(code, grant.id);
        out[mode] = mode === 'user_code' ? code :
                    { code: code, uri: base + '/gnap/code' };
      }
    });
    if (finish) {
      interaction.serverNonce = store.mint(15);
      out.finish = interaction.serverNonce;
    }
    out.expires_in = lifetime;
    grant.interaction = interaction;
    grant.state = STATE.PENDING;
    grant.expiresAt = interaction.expiresAt;
    usable.forEach(function (mode) {
      monitor.record(app.identifier, 'interaction.' + mode, {});
    });
    log.debug("Leaving GnapGrants.startInteraction(). modes=" +
              usable.join(',') + ", finish=" + (finish ? finish.method :
                                                'none'));
    return { ok: true, interact: out };
  }

  // Section 4.2.3.
  interactionHash(clientNonce, serverNonce, interactRef, grantEndpoint,
                           hashMethod?) {
    const { log, request } = this.deps;
    log.debug("Entering GnapGrants.interactionHash().");
    const spec = request.HASH_METHODS[hashMethod || 'sha-256'];
    const digest = nodeCrypto.createHash(spec.node)
      .update([clientNonce, serverNonce, interactRef, grantEndpoint].join('\n'),
              'ascii').digest();
    log.debug("Leaving GnapGrants.interactionHash().");
    return digest.subarray(0, spec.bits / 8).toString('base64url');
  }

  // ---------------------------------------------------------------------------
  // A NEW GRANT REQUEST (section 2). Answers `{ status, body }` or a refusal.
  // ---------------------------------------------------------------------------
  async createGrant(req, asId) {
    const { log, nowSec, config, audit, authorizationServers, store, keys,
          proof, request, tokens, subject, monitor } = this.deps;
    log.debug("Entering GnapGrants.createGrant(). as=" + (asId || 'default'));
    const body = proof.readBody(req);
    if (!body.ok) {
      log.debug("Leaving GnapGrants.createGrant(). Body refused.");
      return body;
    }
    const parsed = request.parseGrantRequest(body.json);
    if (!parsed.ok) {
      log.debug("Leaving GnapGrants.createGrant(). Request refused: " +
                parsed.why);
      return parsed;
    }
    const asked = parsed.request;
    const proofList = this.capabilityList(req, asId, 'key_proofs_supported');
    const caller = await this.identifyCaller(req, body, asked.client,
                                       asked.existingAccessToken ? KIND_RS :
                                       KIND_CLIENT);
    if (!caller.ok) {
      log.debug("Leaving GnapGrants.createGrant(). Caller refused.");
      return caller;
    }
    if (!this.allows(proofList, caller.descriptor.proof.method)) {
      log.debug("Leaving GnapGrants.createGrant(). Proof method not " +
                "supported by this AS.");
      return this.refusal('STS-GNAP-0110', 'this authorization server does ' +
                          'not accept the "' + caller.descriptor.proof.method +
                          '" proofing method (see key_proofs_supported).',
                          'invalid_client', 401);
    }
    const app = caller.app;
    const identifier = app.identifier;
    monitor.record(identifier, 'grant.requested', {});
    for (let i = 0; i < asked.tokens.length; i++) {
      if (asked.tokens[i].bearer &&
          (config.value('gnap.bearerTokens') === false ||
          this.field(app, 'gnapBearerTokens') === 'FALSE')) {
        log.debug("Leaving GnapGrants.createGrant(). Bearer not allowed.");
        return this.refusal('STS-GNAP-0111', 'this client instance may not ' +
            'be issued bearer tokens (RFC 9635 section 2.1.1).',
                            'invalid_flag');
      }
      const problem = this.accessProblem(app, asked.tokens[i].access);
      if (problem) {
        log.debug("Leaving GnapGrants.createGrant(). Access refused.");
        return this.refusal('STS-GNAP-0112', problem + '.', 'request_denied',
                            403);
      }
    }
    const oauth2 = this.deps.loadOauth2();
    const resolved = subject.resolveUser(asked.user, {
      issuer: oauth2.issuerOf(this.realmBase(req)),
      oauthIssuer: oauth2.issuerOf(this.realmBase(req))
    });
    if (!resolved.ok) {
      log.debug("Leaving GnapGrants.createGrant(). User refused.");
      return resolved;
    }
    const grant = store.newGrant({
      as: asId || authorizationServers.DEFAULT_ID,
      grantEndpoint: this.grantEndpointOf(req, asId),
      referer: String(req.headers.referer || '').slice(0, 512) || null,
      client: { identifier: identifier, instanceId: caller.instanceId,
                key: caller.descriptor.value,
                keyIdentity: caller.descriptor.identity,
                proof: caller.descriptor.proof.method,
                display: caller.display, classId: caller.classId },
      request: { tokens: asked.tokens, multiple: asked.multiple,
                 subject: asked.subject,
                 interact: asked.interact },
      userHint: resolved.username,
      userVerified: resolved.verified,
      ro: null,
      decision: null,
      delivered: false,
      polls: 0
    });
    store.saveGrant(grant,
                    'requested by ' + identifier + ' (' +
                    caller.descriptor.proof.method + ')');
    audit.audit({ action: 'gnap.grant.request', category: 'protocol', protocol:
                  PROTOCOL, channel: 'http', outcome: 'success', actor:
                  identifier, target: identifier, summary: 'A GNAP grant was ' +
                  'requested', detail: { grant: grant.id, as: grant.as, tokens:
                                         asked.tokens.length, subject:
                                         !!asked.subject, created:
                                         caller.created } });

    // RFC 9767 section 4: a resource server deriving a downstream token.
    if (asked.existingAccessToken) {
      const derived = await this.deriveToken(req, grant, app, asked);
      log.debug("Leaving GnapGrants.createGrant(). Derivation.");
      return derived;
    }

    const response: Record<string, any> = {};
    if (config.value('gnap.instanceIds') !== false && !caller.instanceId &&
        caller.descriptor.format !== 'reference') {
      const instanceId = store.mint(18);
      store.putInstance(instanceId, { identifier: identifier, key:
                                      caller.descriptor.value });
      response.instance_id = instanceId;
    }
    // WITHOUT INTERACTION. A registered client marked `gnapSkipInteraction`
    // (section 2.3.3's "only specific client instances with certain known keys
    // might be trusted with access tokens without the AS interacting directly
    // with the RO") gets tokens with no RO, when it asks for no subject
    // information; with a VERIFIED user assertion it gets them for that person
    // (section 2.4).
    const trusted = this.field(app, 'gnapSkipInteraction') === 'TRUE' &&
                    !caller.created;
    if (trusted && (!asked.subject || resolved.verified)) {
      grant.ro = resolved.verified ?
                 { username: resolved.username, sessionId: null,
                                       authTime: nowSec(),
                                       amr: ['assertion'], acr: null } : null;
      grant.decision = { approved: true, tokens: asked.tokens,
                         subject: !!asked.subject };
      const released = await this.release(req, grant);
      Object.assign(response, released);
      monitor.record(identifier, 'grant.immediate', {});
      log.debug("Leaving GnapGrants.createGrant(). Approved without " +
                "interaction.");
      return { ok: true, status: 200, body: response, grant: grant };
    }
    if (!asked.interact) {
      grant.state = STATE.FINALIZED;
      store.saveGrant(grant, 'refused: interaction required and the client ' +
                             'offers none');
      monitor.record(identifier, 'grant.refused',
                     { gnapError: 'invalid_interaction' });
      log.debug("Leaving GnapGrants.createGrant(). Interaction needed, none " +
                "offered.");
      return this.refusal('STS-GNAP-0113', 'this request needs the resource ' +
          'owner\'s approval and the client offered no way to interact (RFC ' +
                          '9635 section 2.5).', 'invalid_interaction');
    }
    const started = this.startInteraction(req, grant, app, asked.interact);
    if (!started.ok) {
      grant.state = STATE.FINALIZED;
      store.saveGrant(grant, 'refused: ' + started.why);
      monitor.record(identifier, 'grant.refused',
                     { gnapError: started.gnapError });
      log.debug("Leaving GnapGrants.createGrant(). Interaction refused.");
      return started;
    }
    response.interact = started.interact;
    response.continue = this.continueMember(req, grant);
    store.saveGrant(grant, 'pending interaction');
    log.debug("Leaving GnapGrants.createGrant(). Pending.");
    return { ok: true, status: 200, body: response, grant: grant };
  }

  // Tokens and subject information for a grant whose decision is approved.
  private async release(req, grant) {
    const { log, config, audit, store, monitor, accessRights } = this.deps;
    log.debug("Entering GnapGrants.release(). grant=" + grant.id);
    const out: Record<string, any> = {};
    const requests = grant.decision.tokens || [];
    if (requests.length) {
      const issued = await this.issueTokens(req, grant, requests,
                                            grant.request.multiple);
      if (issued) {
        out.access_token = issued;
      }
    }
    if (grant.decision.subject) {
      const released = await this.releaseSubject(req, grant);
      if (released && (released.sub_ids || released.assertions)) {
        out.subject = released;
      }
    }
    grant.state = STATE.APPROVED;
    grant.delivered = true;
    grant.approvedAccess = accessRights.union ?
                           accessRights.union((grant.approvedAccess || []),
      requests.reduce(function (all, one) {
        return all.concat(one.access);
      }, []))
      : requests.reduce(function (all, one) {
        return all.concat(one.access);
      }, grant.approvedAccess || []);
    if (config.value('gnap.continueAfterApproval') !== false) {
      out.continue = this.continueMember(req, grant);
    } else {
      store.dropContinuation(grant);
    }
    store.saveGrant(grant, 'approved and released');
    monitor.record(grant.client.identifier, 'grant.approved', {});
    audit.audit({ action: 'gnap.grant.approve', category: 'protocol', protocol:
                  PROTOCOL, channel: 'http', outcome: 'success', actor:
                  grant.ro ? grant.ro.username : grant.client.identifier,
                  target: grant.client.identifier, summary: 'A GNAP grant ' +
                  'was approved and released', detail: { grant: grant.id,
        tokens: out.access_token ? (Array.isArray(out.access_token) ?
                                    out.access_token.length : 1) : 0, subject:
        !!out.subject } });
    log.debug("Leaving GnapGrants.release().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // RFC 9767 SECTION 4: TOKEN DERIVATION.
  // ---------------------------------------------------------------------------
  private async deriveToken(req, grant, app, asked) {
    const { log, nowSec, config, store, tokens, monitor, accessRights } =
        this.deps;
    log.debug("Entering GnapGrants.deriveToken().");
    if (config.value('gnap.tokenDerivation') === false) {
      log.debug("Leaving GnapGrants.deriveToken(). Off.");
      return this.refusal('STS-GNAP-0510', 'token derivation is not offered ' +
                          'by this authorization server (RFC 9767 section 4).',
                          'request_denied', 403);
    }
    const existing = store.tokenByValue(asked.existingAccessToken);
    if (!existing || existing.revoked ||
        (existing.exp && existing.exp < nowSec()) ||
        tokens.isRevokedJti(existing.jti)) {
      log.debug("Leaving GnapGrants.deriveToken(). Existing token not active.");
      return this.refusal('STS-GNAP-0511', 'the existing access token is not ' +
          'active at this authorization server (RFC 9767 section 4).',
                          'invalid_request');
    }
    const rsNames = [app.identifier].concat(this.fieldValues(app,
        'gnapResourceServerUri'));
    const forThisRs = !existing.aud.length || existing.aud.some(function (aud) {
      return rsNames.indexOf(aud) >= 0;
    });
    if (!forThisRs) {
      log.debug("Leaving GnapGrants.deriveToken(). Existing token not for " +
                "this RS.");
      return this.refusal('STS-GNAP-0512', 'the existing access token was ' +
          'not issued for use at this resource server, so it cannot derive a ' +
                          'token (RFC 9767 section 4).', 'request_denied', 403);
    }
    const requested = asked.tokens.length ? asked.tokens : [];
    for (let i = 0; i < requested.length; i++) {
      const covered = requested[i].access.every((right) => {
        return accessRights.accessCovers(existing.access, [right]) ||
               typeof right === 'string' &&
          !!store.resourceByReference(right) && this.resourceServersFor(
              [right]).length;
      });
      if (!covered) {
        log.debug("Leaving GnapGrants.deriveToken(). Asks for more than the " +
                  "existing token.");
        return this.refusal('STS-GNAP-0513', 'a derived token must not carry ' +
            'more access than the token it is derived from, except rights ' +
                            'registered for a downstream resource server.',
                            'request_denied', 403);
      }
    }
    grant.ro = existing.username ? { username: existing.username, sessionId:
                                     null, authTime: existing.iat, amr:
                                     ['derived'], acr: null } : null;
    grant.derivedFrom = existing.jti;
    grant.decision = { approved: true, tokens: requested, subject: false };
    const body = await this.release(req, grant);
    monitor.record(app.identifier, 'rs.derivation', {});
    log.debug("Leaving GnapGrants.deriveToken().");
    return { ok: true, status: 200, body: body, grant: grant };
  }

  // ---------------------------------------------------------------------------
  // THE RESOURCE OWNER'S DECISION, from `gnap_interact.ts`.
  //
  // `selection` is `{ approve: bool, tokens: [{label, access}], subject: bool
  // }` with the rights the RO LEFT TICKED — section 4 lets the RO "modify the
  // client instance's requested access, including limiting ... that access".
  // Answers what the page does next: the finish method's redirect URI, or a
  // sentence.
  // ---------------------------------------------------------------------------
  async decide(req, grant, session, selection) {
    const { log, config, audit, consent, store, request, subject, monitor,
          signals } = this.deps;
    log.debug("Entering GnapGrants.decide(). grant=" + grant.id + ", approve=" +
              selection.approve);
    const interaction = grant.interaction;
    interaction.decided = true;
    const username = subject.normaliseName(session.user.username);
    if (selection.approve && grant.userHint && grant.userHint !== username &&
        config.value('gnap.allowCrossUser') !== true) {
      // Section 2.4: "If the identified end user does not match the RO present
      // at the AS ... the AS SHOULD reject the request with an unknown_user
      // error." Recorded as the decision, so the continuation says it.
      grant.decision = { approved: false, error: 'unknown_user' };
    } else if (selection.approve) {
      grant.decision = { approved: true, tokens: selection.tokens,
                         subject: !!selection.subject };
      grant.ro = { username: username, sessionId: session.id,
                   authTime: session.authTime,
                   amr: session.amr, acr: session.acr };
      if (config.value('gnap.rememberApprovals') !== false) {
        const digests = [];
        selection.tokens.forEach((one) => {
          one.access.forEach((right) => {
            digests.push(this.digestTokenOf(right));
          });
        });
        if (digests.length) {
          consent.record(username, grant.client.identifier, digests, username);
        }
      }
      signals.noteApprover(grant.client.identifier, username);
    } else {
      grant.decision = { approved: false, error: 'user_denied' };
      grant.ro = { username: username, sessionId: session.id,
                   authTime: session.authTime,
                   amr: session.amr, acr: session.acr };
    }
    monitor.record(grant.client.identifier,
                   grant.decision.approved ? 'grant.approved' : 'grant.denied',
                   { gnapError: grant.decision.error });
    audit.audit({ action: grant.decision.approved ? 'gnap.grant.consent' :
                  'gnap.grant.deny', category: 'protocol', protocol: PROTOCOL,
                  channel: 'http', outcome: grant.decision.approved ?
                  'success' : 'refused', errorCode: grant.decision.approved ?
                  undefined : 'STS-GNAP-0120', actor: username, target:
                  grant.client.identifier, summary: grant.decision.approved ?
                  'A resource owner approved a GNAP grant' : 'A resource ' +
                  'owner did not approve a GNAP grant', detail: { grant:
        grant.id, why: grant.decision.error || '' } });
    const finished = await this.finishInteraction(req, grant);
    store.saveGrant(grant,
                    'resource owner ' +
                    (grant.decision.approved ? 'approved' : 'did ' +
        'not approve') +
                    (grant.decision.error ? ' (' + grant.decision.error + ')' :
                     ''));
    log.debug("Leaving GnapGrants.decide().");
    return finished;
  }

  // A decision already remembered for every requested right — the approval page
  // is skipped, the way the OAuth consent screen is.
  rememberedFor(grant, username) {
    const { log, config, consent } = this.deps;
    log.debug("Entering GnapGrants.rememberedFor().");
    if (config.value('gnap.consentRequired') === false) {
      log.debug("Leaving GnapGrants.rememberedFor().");
      return true;
    }
    if (config.value('gnap.rememberApprovals') === false) {
      log.debug("Leaving GnapGrants.rememberedFor().");
      return false;
    }
    const held = consent.consentsOf(username).filter(function (row) {
      return row.client === grant.client.identifier;
    }).map(function (row) {
      return row.scope;
    });
    const all = [];
    grant.request.tokens.forEach((one) => {
      one.access.forEach((right) => {
        all.push(this.digestTokenOf(right));
      });
    });
    log.debug("Leaving GnapGrants.rememberedFor().");
    return all.length > 0 && !grant.request.subject &&
           all.every(function (digest) {
      return held.indexOf(digest) >= 0;
    });
  }

  // Section 4.2: create the interaction reference, compute the hash, and follow
  // the finish method. Answers `{ redirect }`, `{ pushed }` or `{ none }`.
  async finishInteraction(req, grant) {
    const { log, audit, store, transport, monitor } = this.deps;
    log.debug("Entering GnapGrants.finishInteraction(). grant=" + grant.id);
    const interaction = grant.interaction;
    interaction.interactRef = store.mint(15);
    const finish = interaction.finish;
    if (!finish) {
      log.debug("Leaving GnapGrants.finishInteraction(). No finish method; " +
                "the client polls.");
      return { none: true };
    }
    const hash = this.interactionHash(finish.nonce, interaction.serverNonce,
                                      interaction.interactRef,
                                      grant.grantEndpoint, finish.hashMethod);
    if (finish.method === 'redirect') {
      const target = finish.uri + (finish.uri.indexOf('?') >= 0 ? '&' : '?') +
        'hash=' + encodeURIComponent(hash) + '&interact_ref=' +
        encodeURIComponent(interaction.interactRef);
      monitor.record(grant.client.identifier, 'finish.redirect', {});
      log.debug("Leaving GnapGrants.finishInteraction(). Redirect.");
      return { redirect: target };
    }
    const pushed = await transport.pushFinish(finish.uri, { hash: hash,
        interact_ref: interaction.interactRef });
    if (pushed.ok) {
      monitor.record(grant.client.identifier, 'finish.push', {});
    } else {
      monitor.record(grant.client.identifier, 'finish.push_failed', {});
      audit.failure(pushed.errorCode || 'STS-GNAP-0604',
                    { protocol: PROTOCOL, channel: 'http',
        outcome: 'error', target: grant.client.identifier,
        summary: 'A GNAP push interaction finish was not delivered',
        detail: { grant: grant.id, why: pushed.why, status: pushed.status } });
    }
    interaction.pushed = pushed.ok;
    log.debug("Leaving GnapGrants.finishInteraction(). Push ok=" + pushed.ok);
    return { pushed: pushed.ok, why: pushed.why };
  }

  // ---------------------------------------------------------------------------
  // CONTINUATION (section 5). `method` is POST, PATCH or DELETE.
  // ---------------------------------------------------------------------------
  private async continuationCaller(req, grantId) {
    const { log, store, keys, proof, request, monitor } = this.deps;
    log.debug("Entering GnapGrants.continuationCaller().");
    const token = proof.presentedToken(req);
    const grant = store.getGrant(grantId);
    const byToken = token ? store.grantByContinuation(token) : null;
    // Section 5: the URI AND the token together identify ONE grant. A live
    // continuation token for a different grant is refused exactly like an
    // unknown one — it must not even reveal that the URI names a grant.
    if (!grant || !byToken || byToken.id !== grant.id) {
      log.debug("Leaving GnapGrants.continuationCaller(). No grant for that " +
                "URI and token.");
      return this.refusal('STS-GNAP-0130', 'the continuation URI and access ' +
          'token do not identify an active grant request (RFC 9635 section 5).',
                          'invalid_continuation', 401);
    }
    if (grant.state === STATE.FINALIZED) {
      log.debug("Leaving GnapGrants.continuationCaller(). Finalized.");
      return this.refusal('STS-GNAP-0131', 'this grant request is finalized ' +
                          'and cannot be continued.', 'invalid_continuation',
                          400);
    }
    const body = proof.readBody(req);
    if (!body.ok) {
      log.debug("Leaving GnapGrants.continuationCaller(). Body refused.");
      return body;
    }
    const descriptor = keys.describe(grant.client.key,
                                     this.referenceResolver);
    if (!descriptor.ok) {
      log.debug("Leaving GnapGrants.continuationCaller(). The grant's key no " +
                "longer describes.");
      return Object.assign(descriptor,
                           { status: 401, gnapError: 'invalid_client' });
    }
    const verified = await proof.verifyRequestOnce(req, body, descriptor,
                                                   { accessToken: token });
    if (!verified.ok) {
      monitor.record(grant.client.identifier, 'proof.failed',
                     { gnapError: 'invalid_client' });
      log.debug("Leaving GnapGrants.continuationCaller(). Proof refused.");
      return Object.assign(verified,
                           { status: 401, gnapError: 'invalid_client' });
    }
    log.debug("Leaving GnapGrants.continuationCaller().");
    return { ok: true, grant: grant, body: body, token: token };
  }

  private expired(grant) {
    const { log, nowSec } = this.deps;
    log.debug("Entering GnapGrants.expired().");
    log.debug("Leaving GnapGrants.expired().");
    return grant.state === STATE.PENDING && grant.expiresAt &&
           grant.expiresAt < nowSec();
  }

  private finalize(grant, note) {
    const { log, store } = this.deps;
    log.debug("Entering GnapGrants.finalize().");
    grant.state = STATE.FINALIZED;
    store.dropContinuation(grant);
    store.saveGrant(grant, note);
    log.debug("Leaving GnapGrants.finalize().");
  }

  // ---------------------------------------------------------------------------
  // THE CONTINUATION ACCESS TOKEN, SPENT ONCE ACROSS THE CLUSTER (2026-09-14,
  // #46).
  //
  // Every continuation this service answers either ROTATES the token
  // (`continueMember()` issues a successor and deletes the old hash) or ends it
  // (`finalize()`), so a continuation token is a single-use value in practice —
  // and the rotation is a write to a replicated map. Two requests carrying one
  // token, on two nodes inside the replication window, were both answered: two
  // successor tokens for one grant, one of which the client never sees, and a
  // poll counted twice as once.
  //
  // So after the caller is identified (the in-memory lookup and the proof, both
  // unchanged and first) the token is SPENT through `store.spend()`, and the
  // continuation runs only for the one request that won it. **THE CLAIM IS
  // GIVEN BACK WHEN THE TOKEN IS STILL LIVE AFTERWARDS** — a refusal that
  // neither rotated nor dropped it (a malformed body, a wrong state) leaves the
  // token usable in this process, and the claim must leave it usable
  // everywhere, or a client's retry of a request it got wrong would be refused
  // on every node as a replay. The test is the store's own answer,
  // `grantByContinuation()`, so the rule cannot drift from what rotation
  // actually does.
  // ---------------------------------------------------------------------------
  async continueGrant(req, grantId) {
    const { log, store, request } = this.deps;
    log.debug("Entering GnapGrants.continueGrant(). method=" + req.method);
    const caller = await this.continuationCaller(req, grantId);
    if (!caller.ok) {
      log.debug("Leaving GnapGrants.continueGrant(). Caller refused.");
      return caller;
    }
    const spent: any = await store.spend('continuation', caller.token, 0,
                                    'STS-GNAP-0710');
    if (!spent.ok) {
      log.debug("Leaving GnapGrants.continueGrant(). The continuation token " +
                "was refused at its spend.");
      return spent.reason === 'used' ? this.refusal('STS-GNAP-0710',
          'the continuation URI and access token do not identify an active ' +
          'grant request (RFC 9635 section 5).', 'invalid_continuation', 401) :
          this.refusal('STS-GNAP-0716', 'this authorization server could not ' +
          'confirm the continuation access token is unused; retry shortly.',
                       'invalid_continuation', 401);
    }
    let result;
    try {
      result = await this.continueAccepted(req, caller);
    } finally {
      const stillLive = store.grantByContinuation(caller.token);
      if (stillLive) {
        await store.unspend(spent.handle);
      }
    }
    log.debug("Leaving GnapGrants.continueGrant().");
    return result;
  }

  private async continueAccepted(req, caller) {
    const { log, nowSec, config, store, request, tokens, monitor } = this.deps;
    log.debug("Entering GnapGrants.continueAccepted(). method=" + req.method);
    const grant = caller.grant;
    const identifier = grant.client.identifier;
    if (this.expired(grant)) {
      this.finalize(grant, 'expired');
      log.debug("Leaving GnapGrants.continueAccepted(). Expired.");
      return this.refusal('STS-GNAP-0132', 'this grant request expired ' +
                          'before it was approved.', 'invalid_continuation');
    }
    if (req.method === 'DELETE') {
      log.debug("Leaving GnapGrants.continueAccepted().");
      return this.revokeGrant(req, grant);
    }
    if (grant.continueNotBefore && nowSec() < grant.continueNotBefore) {
      monitor.record(identifier, 'continue.too_fast', { gnapError:
          'too_fast' });
      const keepGoing = { continue: this.continueMember(req, grant) };
      store.saveGrant(grant, 'continued too fast');
      log.debug("Leaving GnapGrants.continueAccepted(). Too fast.");
      return Object.assign(this.refusal('STS-GNAP-0133', 'the client ' +
          'continued before the wait period ended (RFC 9635 section 5).',
                                        'too_fast'), { extra: keepGoing });
    }
    if (req.method === 'PATCH') {
      log.debug("Leaving GnapGrants.continueAccepted().");
      return this.modifyGrant(req, grant, caller.body);
    }
    const parsed = request.parseContinuation(caller.body.json,
                                             caller.body.hadContent);
    if (!parsed.ok) {
      log.debug("Leaving GnapGrants.continueAccepted(). Continuation body " +
                "refused.");
      return parsed;
    }
    if (parsed.interactRef) {
      const interaction = grant.interaction;
      if (grant.state !== STATE.PENDING || !interaction) {
        // Section 5.1: MUST return too_many_attempts, SHOULD finalize.
        this.finalize(grant, 'interaction reference presented outside the ' +
                      'pending state');
        monitor.record(identifier, 'grant.refused',
                       { gnapError: 'too_many_attempts' });
        log.debug("Leaving GnapGrants.continueAccepted(). interact_ref when " +
                  "not pending.");
        return this.refusal('STS-GNAP-0134', 'an interaction reference was ' +
            'presented for a grant request that is not pending (RFC 9635 ' +
                            'section 5.1).', 'too_many_attempts');
      }
      if (!interaction.interactRef ||
          interaction.interactRef !== parsed.interactRef) {
        const keepGoing = { continue: this.continueMember(req, grant) };
        store.saveGrant(grant, 'wrong interaction reference presented');
        log.debug("Leaving GnapGrants.continueAccepted(). Wrong interact_ref.");
        return Object.assign(this.refusal('STS-GNAP-0135', 'the interaction ' +
                             'reference is not the one issued for this grant ' +
                             'request.', 'invalid_interaction'),
                             { extra: keepGoing });
      }
      // ONCE ACROSS THE CLUSTER (#46). The continuation token's claim already
      // serialises this request, and the reference is claimed as well because
      // it is the value section 5.1 names single-use: a second presentation of
      // it must be refused on every node even if a node were ever to hold two
      // live continuation tokens for one grant.
      const refSpent = await store.spend('interact-ref',
                                         grant.id + '|' + parsed.interactRef,
                                         (Number(interaction.expiresAt) || 0) -
                                         nowSec(), 'STS-GNAP-0711');
      if (!refSpent.ok) {
        log.debug("Leaving GnapGrants.continueAccepted(). interact_ref " +
                  "already spent.");
        return refSpent.reason === 'used' ? this.refusal('STS-GNAP-0711',
            'the interaction reference has already been used (RFC 9635 ' +
            'section 5.1).', 'invalid_interaction') :
            this.refusal('STS-GNAP-0716', 'this authorization server could ' +
            'not confirm the interaction reference is unused; retry shortly.',
                         'invalid_interaction');
      }
      interaction.interactRef = null;
      interaction.refUsed = true;
      monitor.record(identifier, 'continue.interact_ref', {});
      log.debug("Leaving GnapGrants.continueAccepted().");
      return this.settle(req, grant);
    }
    // A POLL (section 5.2).
    monitor.record(identifier, 'continue.poll', {});
    grant.polls = (grant.polls || 0) + 1;
    const maxPolls = Number(config.value('gnap.maxPolls')) || 60;
    if (grant.state === STATE.PENDING && grant.polls > maxPolls) {
      this.finalize(grant, 'too many polls');
      log.debug("Leaving GnapGrants.continueAccepted(). Too many polls.");
      return this.refusal('STS-GNAP-0136',
                          'the client polled more than ' + maxPolls + ' ' +
                          'times before the resource owner decided (RFC 9635 ' +
                          'section 5.2).', 'too_many_attempts');
    }
    if (grant.state === STATE.PENDING && grant.interaction &&
        grant.interaction.finish &&
        !grant.interaction.refUsed) {
      // Section 3.3.5: a client given a finish nonce "MUST NOT continue a grant
      // request before it receives the associated interaction reference".
      const keepGoing = { continue: this.continueMember(req, grant) };
      store.saveGrant(grant,
                      'polled before presenting the interaction reference');
      log.debug("Leaving GnapGrants.continueAccepted(). Poll before the " +
                "interaction reference.");
      return Object.assign(this.refusal('STS-GNAP-0137', 'this grant request ' +
                                        'finishes with a ' +
                                        grant.interaction.finish.method +
          ' carrying an interaction reference; the client must present it ' +
          'rather than poll (RFC 9635 section 3.3.5).', 'invalid_continuation'),
                           { extra: keepGoing });
    }
    log.debug("Leaving GnapGrants.continueAccepted().");
    return this.settle(req, grant);
  }

  // Where a pending grant goes when the client comes back.
  private async settle(req, grant) {
    const { log, store, request } = this.deps;
    log.debug("Entering GnapGrants.settle(). state=" + grant.state);
    if (grant.state === STATE.APPROVED) {
      const body = { continue: this.continueMember(req, grant) };
      store.saveGrant(grant, 'continued after approval');
      log.debug("Leaving GnapGrants.settle(). Already approved; nothing new.");
      return { ok: true, status: 200, body: body };
    }
    if (!grant.decision) {
      const body = { continue: this.continueMember(req, grant) };
      store.saveGrant(grant, 'polled while pending');
      log.debug("Leaving GnapGrants.settle(). Still pending.");
      return { ok: true, status: 200, body: body };
    }
    if (!grant.decision.approved) {
      const code = grant.decision.error || 'user_denied';
      grant.decision = null;
      grant.interaction = null;
      const keepGoing = { continue: this.continueMember(req, grant) };
      store.saveGrant(grant, 'told the client: ' + code);
      log.debug("Leaving GnapGrants.settle(). " + code);
      return Object.assign(this.refusal(code === 'unknown_user' ?
                                        'STS-GNAP-0121' : 'STS-GNAP-0120',
                                        code === 'unknown_user' ?
          'the person who signed in is not the user the request named (RFC ' +
                                        '9635 section 2.4).' :
          'the resource owner did not approve the request.', code, 403), {
          extra: keepGoing });
    }
    const body = await this.release(req, grant);
    log.debug("Leaving GnapGrants.settle(). Released.");
    return { ok: true, status: 200, body: body };
  }

  // Section 5.3.
  private async modifyGrant(req, grant, bodyRead) {
    const { log, config, applications, consent, store, request, monitor,
          signals, accessRights } = this.deps;
    log.debug("Entering GnapGrants.modifyGrant().");
    if (grant.state !== STATE.APPROVED && grant.state !== STATE.PENDING) {
      log.debug("Leaving GnapGrants.modifyGrant(). Wrong state.");
      return this.refusal('STS-GNAP-0140', 'only a pending or approved grant ' +
                          'request can be modified (RFC 9635 section ' +
                          '5.3).', 'invalid_continuation');
    }
    const parsed = request.parseModification(bodyRead.json || {});
    if (!parsed.ok) {
      log.debug("Leaving GnapGrants.modifyGrant(). Refused.");
      return parsed;
    }
    const asked = parsed.request;
    const app = applications.get(grant.client.identifier);
    if (asked.tokens) {
      for (let i = 0; i < asked.tokens.length; i++) {
        const problem = this.accessProblem(app, asked.tokens[i].access);
        if (problem) {
          log.debug("Leaving GnapGrants.modifyGrant(). Access refused.");
          return this.refusal('STS-GNAP-0112', problem + '.', 'request_denied',
                              403);
        }
      }
      grant.request.tokens = asked.tokens;
      grant.request.multiple = asked.multiple;
    }
    if (asked.subject) {
      grant.request.subject = asked.subject;
    }
    monitor.record(grant.client.identifier, 'grant.modified', {});
    const previouslyApproved = grant.approvedAccess || [];
    const requested = grant.request.tokens.reduce(function (all, one) {
      return all.concat(one.access);
    }, []);
    const withinApproval = grant.state === STATE.APPROVED &&
        grant.ro !== undefined && accessRights.accessCovers(previouslyApproved,
        requested) && !asked.subject;
    grant.state = STATE.PROCESSING;
    if (withinApproval) {
      // Section 5.3's worked example: narrower access, no new consent.
      if (config.value('gnap.revokeOnModify') !== false &&
          config.value('gnap.durableTokens') !== true) {
        this.revokeTokens(grant, 'grant modified');
      }
      grant.decision = { approved: true, tokens: grant.request.tokens,
                         subject: false };
      const body = await this.release(req, grant);
      signals.grantModified(req, grant, requested);
      log.debug("Leaving GnapGrants.modifyGrant(). Within the earlier " +
                "approval.");
      return { ok: true, status: 200, body: body };
    }
    if (!asked.interact) {
      grant.state = previouslyApproved.length ? STATE.APPROVED : STATE.PENDING;
      const keepGoing = { continue: this.continueMember(req, grant) };
      store.saveGrant(grant, 'modification needs approval and no interaction ' +
                             'was offered');
      log.debug("Leaving GnapGrants.modifyGrant(). Needs interaction, none " +
                "offered.");
      return Object.assign(this.refusal('STS-GNAP-0141', 'the modified ' +
          'request asks for more than was approved and offers no way to ' +
          'interact with the resource owner (RFC 9635 section 5.3).',
                                        'request_denied', 403), { extra:
          keepGoing });
    }
    grant.decision = null;
    grant.request.interact = asked.interact;
    const started = this.startInteraction(req, grant, app, asked.interact);
    if (!started.ok) {
      grant.state = previouslyApproved.length ? STATE.APPROVED : STATE.PENDING;
      store.saveGrant(grant, 'modification interaction refused');
      log.debug("Leaving GnapGrants.modifyGrant(). Interaction refused.");
      return started;
    }
    const body = { interact: started.interact,
                   continue: this.continueMember(req, grant) };
    store.saveGrant(grant, 'modified; pending interaction');
    log.debug("Leaving GnapGrants.modifyGrant(). Pending interaction.");
    return { ok: true, status: 200, body: body };
  }

  revokeTokens(grant, why) {
    const { log, nowSec, stats, store } = this.deps;
    log.debug("Entering GnapGrants.revokeTokens().");
    (grant.tokens || []).forEach(function (jti) {
      const record = store.tokenByJti(jti);
      if (record && !record.revoked) {
        record.revoked = true;
        record.revokedAt = nowSec();
        record.revokedWhy = why;
        store.dropManagement(record);
        store.saveToken(record);
        if (/^jwt/.test(record.format)) {
          stats.revoke(record.jti, 'GNAP: ' + why);
        }
      }
    });
    log.debug("Leaving GnapGrants.revokeTokens().");
  }

  // Section 5.4.
  private revokeGrant(req, grant) {
    const { log, audit, monitor, signals } = this.deps;
    log.debug("Entering GnapGrants.revokeGrant().");
    this.revokeTokens(grant, 'grant revoked by the client instance');
    this.finalize(grant, 'revoked by the client instance');
    monitor.record(grant.client.identifier, 'grant.revoked', {});
    audit.audit({ action: 'gnap.grant.revoke', category: 'protocol',
      protocol: PROTOCOL,
      channel: 'http', outcome: 'success', actor: grant.client.identifier,
      target: grant.client.identifier, summary: 'A GNAP grant was revoked by ' +
                                                'its client instance',
      detail: { grant: grant.id, tokens: (grant.tokens || []).length } });
    signals.grantRevoked(req, grant, 'The client instance revoked the grant.');
    log.debug("Leaving GnapGrants.revokeGrant().");
    return { ok: true, status: 204, body: null };
  }

  // ---------------------------------------------------------------------------
  // TOKEN MANAGEMENT (section 6).
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE MANAGEMENT ACCESS TOKEN, SPENT ONCE ACROSS THE CLUSTER (2026-09-14,
  // #46).
  //
  // A rotation issues a new management access token and deletes the old one's
  // hash, and a revocation drops both — so, like a continuation token, the
  // value is single-use in practice and its spending is a replicated write. Two
  // rotations of one token on two nodes inside the window both rotated it: two
  // live successor access tokens where section 6.1 describes one. The spend is
  // made in manageVerified() right after the proof verifies, and given back
  // here when the management token is still live afterwards, for the reason
  // continueGrant() gives.
  // ---------------------------------------------------------------------------
  async manageToken(req, handle) {
    const { log, store, proof } = this.deps;
    log.debug("Entering GnapGrants.manageToken(). method=" + req.method);
    const spentBox = { handle: null };
    let result;
    try {
      result = await this.manageVerified(req, handle, spentBox);
    } finally {
      const presented = proof.presentedToken(req);
      if (spentBox.handle && presented &&
          store.tokenByManagement(handle, presented)) {
        await store.unspend(spentBox.handle);
      }
    }
    log.debug("Leaving GnapGrants.manageToken().");
    return result;
  }

  private async spendManagement(req, presented, spentBox) {
    const { log, store } = this.deps;
    log.debug("Entering GnapGrants.spendManagement().");
    const spent: any = await store.spend('management', presented, 0,
                                    'STS-GNAP-0714');
    if (spent.ok) {
      spentBox.handle = spent.handle;
      log.debug("Leaving GnapGrants.spendManagement(). Spent.");
      return { ok: true };
    }
    const gnapError = req.method === 'DELETE' ? 'invalid_request'
      : 'invalid_rotation';
    log.debug("Leaving GnapGrants.spendManagement(). Refused.");
    return spent.reason === 'used' ? this.refusal('STS-GNAP-0714',
        'the token management URI and access token do not identify a token ' +
                                                  '(RFC 9635 section 6).',
                                                  gnapError, 401) :
        this.refusal('STS-GNAP-0716', 'this authorization server could not ' +
        'confirm the token management access token is unused; retry shortly.',
                     gnapError, 401);
  }

  private async manageVerified(req, handle, spentBox) {
    const { log, nowSec, config, errorCodes, audit, applications, stats, store,
          keys, proof, request, tokens, monitor, signals } = this.deps;
    log.debug("Entering GnapGrants.manageVerified(). method=" + req.method);
    const presented = proof.presentedToken(req);
    const record = presented ? store.tokenByManagement(handle, presented) :
        null;
    if (!record) {
      log.debug("Leaving GnapGrants.manageVerified(). Unknown management URI " +
                "or token.");
      return this.refusal('STS-GNAP-0150', 'the token management URI and ' +
          'access token do not identify a token (RFC 9635 section 6).',
                          req.method === 'DELETE' ? 'invalid_request' :
                          'invalid_rotation', 401);
    }
    const grant = store.getGrant(record.grantId);
    const body = proof.readBody(req);
    if (!body.ok) {
      log.debug("Leaving GnapGrants.manageVerified(). Body refused.");
      return body;
    }
    // Section 7.3: bound to the token's own key or, for a bearer token, the
    // client instance's.
    const keyJson = record.key || (grant ? grant.client.key : null);
    const descriptor = keys.describe(keyJson,
                                     this.referenceResolver);
    if (!descriptor.ok) {
      log.debug("Leaving GnapGrants.manageVerified(). No key to verify with.");
      return Object.assign(descriptor,
                           { status: 401, gnapError: 'invalid_client' });
    }
    if (req.method === 'DELETE') {
      const verified = await proof.verifyRequestOnce(req, body, descriptor, {
          accessToken: presented });
      if (!verified.ok) {
        monitor.record(record.instanceId, 'proof.failed',
                       { gnapError: 'invalid_client' });
        log.debug("Leaving GnapGrants.manageVerified(). DELETE proof refused.");
        return Object.assign(verified,
                             { status: 401, gnapError: 'invalid_client' });
      }
      const deleteOnce = await this.spendManagement(req, presented, spentBox);
      if (!deleteOnce.ok) {
        log.debug("Leaving GnapGrants.manageVerified(). DELETE refused at " +
                  "the spend.");
        return deleteOnce;
      }
      record.revoked = true;
      record.revokedAt = nowSec();
      record.revokedWhy = 'revoked by the client instance';
      store.dropManagement(record);
      store.saveToken(record);
      if (/^jwt/.test(record.format)) {
        stats.revoke(record.jti, 'GNAP token management');
      }
      monitor.record(record.instanceId, 'token.revoked', {});
      audit.audit({ action: 'gnap.token.revoke', category: 'protocol',
        protocol: PROTOCOL,
        channel: 'http', outcome: 'success', actor: record.instanceId,
        target: record.instanceId,
        summary: 'A GNAP access token was revoked by its client instance',
        detail: { jti: record.jti, format: record.format } });
      signals.tokenRevoked(req, record, grant);
      log.debug("Leaving GnapGrants.manageVerified(). Revoked.");
      return { ok: true, status: 204, body: null };
    }
    // POST: rotation, optionally with a new key.
    const parsed = request.parseRotation(body.json, body.hadContent);
    if (!parsed.ok) {
      log.debug("Leaving GnapGrants.manageVerified(). Rotation body refused.");
      return parsed;
    }
    let newDescriptor = null;
    if (parsed.key) {
      if (!config.value('gnap.keyRotation') ||
          this.capabilities(req, record.as).key_rotation_supported === false) {
        log.debug("Leaving GnapGrants.manageVerified(). Key rotation off.");
        return this.refusal('STS-GNAP-0151', 'this authorization server does ' +
            'not allow rotating an access token\'s key (RFC 9635 section ' +
                            '6.1.1).', 'key_rotation_not_supported');
      }
      if (!record.key) {
        log.debug("Leaving GnapGrants.manageVerified(). Bearer token has no " +
                  "key to rotate.");
        return this.refusal('STS-GNAP-0152', 'a bearer token has no key to ' +
                            'rotate (RFC 9635 section 6.1.1).',
                            'invalid_rotation');
      }
      newDescriptor = keys.describe(parsed.key,
                                    this.referenceResolver);
      if (!newDescriptor.ok) {
        log.debug("Leaving GnapGrants.manageVerified(). New key refused.");
        return Object.assign(newDescriptor, { gnapError: 'invalid_rotation' });
      }
    }
    const verified = await proof.verifyRequestOnce(req, body, descriptor,
                                                   { accessToken: presented,
                                                     rotation: newDescriptor });
    if (!verified.ok) {
      monitor.record(record.instanceId, 'proof.failed',
                     { gnapError: verified.gnapError });
      log.debug("Leaving GnapGrants.manageVerified(). Rotation proof refused.");
      return Object.assign(verified, {
        status: verified.gnapError === 'key_rotation_not_supported' ? 400 :
                401,
        gnapError: newDescriptor ? verified.gnapError : 'invalid_client'
      });
    }
    const rotateOnce = await this.spendManagement(req, presented, spentBox);
    if (!rotateOnce.ok) {
      log.debug("Leaving GnapGrants.manageVerified(). Rotation refused at " +
                "the spend.");
      return rotateOnce;
    }
    if (record.revoked || tokens.isRevokedJti(record.jti)) {
      log.debug("Leaving GnapGrants.manageVerified(). Revoked tokens do not " +
                "rotate.");
      return this.refusal('STS-GNAP-0153', 'a revoked access token cannot be ' +
                          'rotated.', 'invalid_rotation');
    }
    if (grant && grant.state === STATE.FINALIZED) {
      log.debug("Leaving GnapGrants.manageVerified(). The grant is finalized.");
      return this.refusal('STS-GNAP-0154', 'the grant this token belongs to ' +
                          'is finalized.', 'invalid_rotation');
    }
    const iat = nowSec();
    const lifetime = Math.max(1, (record.exp || iat) - (record.iat || iat)) ||
      (Number(config.value('gnap.accessTokenLifetimeS')) || 3600);
    const cnf = newDescriptor ? keys.confirmationOf(newDescriptor) : record.cnf;
    const model = { jti: store.mint(16), iss: record.iss, sub: record.sub,
                    aud: record.aud,
                    instanceId: record.instanceId, access: record.access,
                    flags: record.flags,
                    cnf: cnf, iat: iat, nbf: iat, exp: iat +
                                                       lifetime,
                    label: record.label };
    let minted;
    try {
      const rs = record.rsIdentifiers && record.rsIdentifiers.length === 1
        ? applications.get(record.rsIdentifiers[0]) : null;
      minted = await tokens.mint(record.format, model, { base:
          this.realmBase(req), rs: rs ? { identity: rs.identifier, jweKey:
                                          this.field(rs, 'gnapJweKey') ?
                                          JSON.parse(this.field(rs,
          'gnapJweKey')) : null } : null, setId: record.grantId });
    } catch (e) {
      log.debug("Caught in GnapGrants.manageVerified(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-GNAP-0155') + 'gnap: a rotated ' +
                record.format + ' ' +
                'token could not be minted: ' + e.message);
      log.debug("Leaving GnapGrants.manageVerified().");
      return this.refusal('STS-GNAP-0155', 'the token could not be rotated.',
                          'invalid_rotation');
    }
    const next = store.putToken(Object.assign({}, record, model, {
      key: newDescriptor ? newDescriptor.value : record.key, proof:
          newDescriptor ? newDescriptor.proof : record.proof, rotatedFrom:
          record.jti, revoked: false, createdAt: iat, manageHandle: null,
          manageHash: null }), minted.value);
    // Section 6.1: "the AS MUST invalidate the current access token value".
    record.revoked = true;
    record.revokedAt = iat;
    record.revokedWhy = 'rotated';
    record.rotatedTo = next.jti;
    store.moveManagement(record, next);
    store.saveToken(record);
    if (/^jwt/.test(record.format)) {
      stats.revoke(record.jti, 'GNAP rotation');
    }
    const manageValue = store.issueManagement(next);
    store.saveToken(next);
    if (grant) {
      grant.tokens = (grant.tokens || []).concat([next.jti]);
      if (newDescriptor) {
        // Section 6.1.1: the grant's key follows the token's most recent
        // rotation.
        grant.client.key = newDescriptor.value;
        grant.client.keyIdentity = newDescriptor.identity;
      }
      store.saveGrant(grant,
                      newDescriptor ? 'token key rotated' : 'token rotated');
    }
    monitor.record(record.instanceId,
                   newDescriptor ? 'token.key_rotated' : 'token.rotated',
                   { format: record.format });
    audit.audit({ action: 'gnap.token.rotate', category: 'protocol',
      protocol: PROTOCOL,
      channel: 'http', outcome: 'success', actor: record.instanceId,
      target: record.instanceId,
      summary: 'A GNAP access token was rotated' + (newDescriptor ? ' onto a ' +
          'new key' : ''),
      detail: { from: record.jti, to: next.jti, format: record.format } });
    const response: Record<string, any> = { value: minted.value, access:
                                            next.access, expires_in: lifetime,
                                            manage: { uri: this.realmBase(req) +
                                                      '/gnap/token/' +
                                                      next.manageHandle,
                                                      access_token: { value:
        manageValue } } };
    if (next.label) {
      response.label = next.label;
    }
    if (next.flags && next.flags.length) {
      response.flags = next.flags;
    }
    log.debug("Leaving GnapGrants.manageVerified(). Rotated.");
    return { ok: true, status: 200, body: { access_token: response } };
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one.
const engine = new GnapGrants({
  log: helpers.log,
  nowSec: helpers.nowSec,
  baseUrlOf: helpers.baseUrlOf,
  config: config,
  helpers: helpers,
  errorCodes: errorCodes,
  mode: mode,
  audit: audit,
  applications: applications,
  keystore: keystore,
  gate: gate,
  consent: consent,
  stats: stats,
  authorizationServers: authorizationServers,
  store: store,
  keys: keys,
  proof: proof,
  request: request,
  tokens: tokens,
  subject: subject,
  transport: transport,
  monitor: monitor,
  signals: signals,
  accessRights: accessRights,
  loadOauth2: function loadOauth2() {
    helpers.log.debug("Entering loadOauth2().");
    helpers.log.debug("Leaving loadOauth2().");
    return require('../oauth-oidc/oauth2');
  }
});

export = {
  GnapGrants: GnapGrants,
  PROTOCOL: GnapGrants.PROTOCOL,
  KIND_CLIENT: GnapGrants.KIND_CLIENT,
  KIND_RS: GnapGrants.KIND_RS,
  GNAP_MEMBERS: GnapGrants.GNAP_MEMBERS,
  RESERVED_AS_NAMES: GnapGrants.RESERVED_AS_NAMES,
  capabilities: engine.capabilities.bind(engine) as GnapGrants['capabilities'],
  capabilityList: engine.capabilityList.bind(engine) as
    GnapGrants['capabilityList'],
  defaultCapabilities: engine.defaultCapabilities.bind(engine) as
    GnapGrants['defaultCapabilities'],
  grantEndpointOf: engine.grantEndpointOf.bind(engine) as
    GnapGrants['grantEndpointOf'],
  realmBase: engine.realmBase.bind(engine) as GnapGrants['realmBase'],
  gnapApplications: engine.gnapApplications.bind(engine) as
    GnapGrants['gnapApplications'],
  field: engine.field.bind(engine) as GnapGrants['field'],
  fieldValues: engine.fieldValues.bind(engine) as GnapGrants['fieldValues'],
  resolveKeyReference: engine.resolveKeyReference.bind(engine) as
    GnapGrants['resolveKeyReference'],
  identifyCaller: engine.identifyCaller.bind(engine) as
    GnapGrants['identifyCaller'],
  createGrant: engine.createGrant.bind(engine) as GnapGrants['createGrant'],
  continueGrant: engine.continueGrant.bind(engine) as
    GnapGrants['continueGrant'],
  manageToken: engine.manageToken.bind(engine) as GnapGrants['manageToken'],
  decide: engine.decide.bind(engine) as GnapGrants['decide'],
  rememberedFor: engine.rememberedFor.bind(engine) as
    GnapGrants['rememberedFor'],
  finishInteraction: engine.finishInteraction.bind(engine) as
    GnapGrants['finishInteraction'],
  interactionHash: engine.interactionHash.bind(engine) as
    GnapGrants['interactionHash'],
  normaliseUserCode: engine.normaliseUserCode.bind(engine) as
    GnapGrants['normaliseUserCode'],
  digestTokenOf: engine.digestTokenOf.bind(engine) as
    GnapGrants['digestTokenOf'],
  canonicalJson: engine.canonicalJson.bind(engine) as
    GnapGrants['canonicalJson'],
  resourceServersFor: engine.resourceServersFor.bind(engine) as
    GnapGrants['resourceServersFor'],
  revokeTokens: engine.revokeTokens.bind(engine) as GnapGrants['revokeTokens']
};
