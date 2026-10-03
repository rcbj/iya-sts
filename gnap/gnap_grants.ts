// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// **EVERY FINALIZED GRANT RECORDS WHY (#432 phase 7, 2026-10-03)**, as
// `grant.finalization = { reason, at, note }`, through `finalize()` and
// nowhere else, with an audit row (`gnap.grant.finalize`). Four reasons:
//
//   issued    its tokens were released and nothing more can be asked of it —
//             an approved grant whose response carries no continuation
//             (`gnap.continueAfterApproval` off). Section 1.5's Approved ->
//             Finalized edge. ITS TOKENS STAY LIVE: the one reason
//             `gnap_rs.ts`'s liveProblem() and a rotation do not refuse.
//   revoked   ended by an act — the client's DELETE (section 5.4), an
//             administrator, the resource owner on /portal/gnap.
//   rejected  refused: no way to interact, an interaction that could not
//             start, too many polls, an interaction reference outside the
//             pending state — and a grant that expires after its resource
//             owner said no.
//   expired   its interaction ran out, or its GRANT LIFETIME did.
//
// **THE GRANT HAS A LIFETIME OF ITS OWN (#432 phase 7)**,
// `gnap.grantLifetimeS`, counted from its creation and separate from any
// token's: past it the grant can no longer be continued, modified
// (`STS-GNAP-0790`) or have a token rotated (`STS-GNAP-0791`), and no token
// issued under it is given an `exp` past it. A rotation could otherwise
// renew a grant's access for ever on the strength of one approval; the
// lifetime is the point at which the resource owner is asked again. The
// `gnap.grant-expiry` scheduler job records the expiry of a grant nobody
// touches.
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
// the discovery members and the reserved names are its static constants. The
// module still exports every name it did as FACADES forwarding to the instance
// the composition root builds (#50, R2), for `gnap.ts`, `gnap_interact.ts`,
// `gnap_rs.ts`, `gnap_console.ts` and the tests, none of which are converted.
// A process that loads this module without the root builds a default instance
// when the module loads.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import config = require('../common/config');
import helpers = require('../common/helpers');
// The one random-value section (#65): user codes, drawn uniformly.
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');
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
// WHAT ENDS A GRANT FROM OUTSIDE THE PROTOCOL, and the check at use (#432):
// it requires nothing of this module, so this require closes no cycle.
import revocation = require('./gnap_revocation');
// WHICH CLIENTS MAY HOLD THIS SERVICE'S PROTECTED SCOPES (#110), the same
// question the OAuth token endpoint asks. A library.
import scopePolicy = require('../common/scope_policy');
// The TLS client certificate on a connection, and who this realm issued it to
// (#107). A library.
import mtls = require('../oauth-oidc/mtls');
// WHO MAY ACT FOR WHOM (#432 phase 1): #186's delegation policy asked for
// impersonation by assertion and RFC 9767 derivation, the register they are
// recorded in, and the derived token's actor chain. A library.
import gnapDelegation = require('./gnap_delegation');
// EACH ACCESS RIGHT A POLICY QUESTION, READ AGAINST ONE CATALOGUE (#432
// phases 3 and 4): the facts, the verdicts and the access-type catalogue's
// well-formedness. A library.
import gnapRights = require('./gnap_rights');
// Who owns an identifier (#432 phase 5), for the approval page's question.
import ownership = require('./gnap_ownership');
// WHO APPROVES, AND HOW STRONGLY SIGNED IN (#432 phase 6): the step-up an
// approval needs and approval by an absent resource owner. A library; it
// reaches this module back lazily, so the require closes no cycle.
import gnapApproval = require('./gnap_approval');

const PROTOCOL = 'GNAP';
const STATE = store.STATE;

// Why a grant was finalized (#432 phase 7) — the header's four.
const FINALIZATION_REASONS = ['issued', 'revoked', 'rejected', 'expired'];

// What authorizes releasing subject information (#432 phase 7): the resource
// owner ticking the subject checkbox at an interaction, or a delegation
// decision for a client acting for a person by assertion. releaseSubject()'s
// header argues it.
const SUBJECT_AUTHORIZATIONS = ['interaction', 'delegation'];
// (An owner's approval on the portal, #432 phase 6, authorizes it as an
// `interaction` does: the person saw the box and left it ticked.)

// The expiry job (#432 phase 7): finalizes, and records the reason of, every
// grant past its interaction or its grant lifetime that nobody has touched.
const EXPIRY_JOB = 'gnap.grant-expiry';

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
  revocation: typeof revocation;
  scopePolicy: typeof scopePolicy;
  mtls: typeof mtls;
  delegation: typeof gnapDelegation;
  rights: typeof gnapRights;
  ownership: typeof ownership;
  approval: typeof gnapApproval;
  // oauth2.js, required when it is needed and not before (it registers
  // routes, and was a lazy require before the conversion).
  loadOauth2(): typeof import('../oauth-oidc/oauth2');
  // The scheduler (#49), for the expiry job (#432 phase 7). Lazily, as every
  // job owner reaches it.
  scheduler(): any;
}

/**
 * The grant engine: every decision a GNAP authorization server makes, in one
 * route-free library.
 *
 * `gnap.ts` and `gnap_interact.ts` both call it, so the grant state machine of
 * RFC 9635 section 1.5 lives here where both halves reach it.
 */
class GnapGrants {
  /**
   * The protocol name recorded on audit rows, `GNAP`.
   */
  static readonly PROTOCOL = PROTOCOL;
  /**
   * The application kind recorded for a GNAP client instance, `gnap-client`.
   */
  static readonly KIND_CLIENT = KIND_CLIENT;
  /**
   * The application kind recorded for a GNAP resource server,
   * `gnap-resource-server`.
   */
  static readonly KIND_RS = KIND_RS;
  /**
   * The discovery members (section 9) an authorization server profile may set,
   * and which the grant endpoint enforces.
   */
  static readonly GNAP_MEMBERS = GNAP_MEMBERS;
  /**
   * The first path segments that are never taken as an authorization server
   * name by `/:as/gnap`.
   */
  static readonly RESERVED_AS_NAMES = RESERVED_AS_NAMES;
  /**
   * Why a grant may be finalized: `issued`, `revoked`, `rejected`,
   * `expired` (#432 phase 7).
   */
  static readonly FINALIZATION_REASONS = FINALIZATION_REASONS;
  /**
   * What may authorize releasing subject information: `interaction` or
   * `delegation` (#432 phase 7).
   */
  static readonly SUBJECT_AUTHORIZATIONS = SUBJECT_AUTHORIZATIONS;
  /**
   * The scheduler job that records the expiry of untouched grants.
   */
  static readonly EXPIRY_JOB = EXPIRY_JOB;

  /**
   * Builds the grant engine from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
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

  // -------------------------------------------------------------------------
  // THE GRANT LIFETIME (#432 phase 7, the header). `gnap.grantLifetimeS` is
  // read when a grant is made and fixed on it then, so changing the setting
  // moves no grant already made.
  // -------------------------------------------------------------------------
  /**
   * Returns when a grant made now expires: `gnap.grantLifetimeS` after it.
   *
   * @param createdAt - the grant's creation, epoch seconds
   * @returns the expiry, epoch seconds
   */
  grantExpiryFrom(createdAt: number): number {
    const { log, config } = this.deps;
    log.debug("Entering GnapGrants.grantExpiryFrom().");
    const lifetime = Number(config.value('gnap.grantLifetimeS'));
    log.debug("Leaving GnapGrants.grantExpiryFrom().");
    return createdAt + (lifetime > 0 ? lifetime : 86400);
  }

  /**
   * Says whether a grant's own lifetime has ended (#432 phase 7).
   *
   * @param grant - the grant, or a token record carrying `grantExpiresAt`
   * @returns true once its lifetime is over
   */
  grantLifetimeEnded(grant: any): boolean {
    const { log, nowSec } = this.deps;
    log.debug("Entering GnapGrants.grantLifetimeEnded().");
    const until = Number(grant && grant.grantExpiresAt);
    log.debug("Leaving GnapGrants.grantLifetimeEnded().");
    return until > 0 && nowSec() >= until;
  }

  // A token's lifetime, cut short where it would outlive its grant.
  private cappedLifetime(grant: any, iat: number, lifetime: number): number {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.cappedLifetime().");
    const until = Number(grant && grant.grantExpiresAt);
    log.debug("Leaving GnapGrants.cappedLifetime().");
    return until > 0 ? Math.max(1, Math.min(lifetime, until - iat))
                     : lifetime;
  }

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

  /**
   * Returns every value of a field on an application entry, as strings.
   *
   * @param app - the application entry
   * @param name - the field's name
   * @returns the values, empty when there are none
   */
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

  /**
   * Returns the first value of a field on an application entry.
   *
   * @param app - the application entry
   * @param name - the field's name
   * @returns the value, or null
   */
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

  /**
   * Returns the absolute grant endpoint URI of an authorization server on the
   * realm the request arrived on.
   *
   * @param req - the request
   * @param asId - the authorization server's name, or none for the default
   * @returns the URI
   */
  grantEndpointOf(req, asId) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering GnapGrants.grantEndpointOf().");
    log.debug("Leaving GnapGrants.grantEndpointOf().");
    return baseUrlOf(req) + this.asPath(asId) + '/gnap';
  }

  /**
   * Returns the base URL of the realm the request arrived on.
   *
   * @param req - the request
   * @returns the base URL
   */
  realmBase(req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering GnapGrants.realmBase().");
    log.debug("Leaving GnapGrants.realmBase().");
    return baseUrlOf(req);
  }

  /**
   * Returns the discovery document's members (section 9) as the settings make
   * them, before an authorization server profile changes any.
   *
   * @param req - the request
   * @param asId - the authorization server's name
   * @returns the members
   */
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

  /**
   * Returns an authorization server's discovery members: the defaults, as its
   * profile changes them.
   *
   * @param req - the request
   * @param asId - the authorization server's name
   * @returns the members
   */
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
  /**
   * Returns one list capability of an authorization server.
   *
   * @param req - the request
   * @param asId - the authorization server's name
   * @param member - the discovery member
   * @returns the list, or null when the profile removed the member (enforce
   *   nothing)
   */
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
  /**
   * Lists the application entries that are GNAP client instances or resource
   * servers — by kind, declared protocol, or a GNAP key or instance identifier.
   *
   * @returns the entries
   */
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
  /**
   * Resolves a key reference (section 7.1.1) against application entries: the
   * entry's public key or its shared secret.
   *
   * @param reference - the reference
   * @returns the key material, or null for an unknown reference
   */
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
      if (keystore.persists() && stsCrypto.isEncryptedWithKek(secret)) {
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
  // MUTUAL TLS UNDER A PKI: WHICH ENTRY A CERTIFICATE IS, AND WHICH KEY IT
  // PROVES (#107, 2026-09-23). `gnap_proof.ts` argues the two trust models;
  // what is decided here is only what the engine knows and the proof does not
  // — the application entry.
  //
  // The model in force for an entry (or for none): `applications.js`'s
  // `gnapMtlsTrustFor()`, the one combination of the realm's setting and the
  // entry's stricter-only override.
  // ---------------------------------------------------------------------------
  /**
   * Returns the mutual TLS trust model in force for an application entry
   * (#107): the realm's setting with the entry's stricter-only override.
   *
   * @param app - the application entry, or null
   * @returns `pki` or `pinned`
   */
  mtlsTrustOf(app) {
    const { log, applications } = this.deps;
    log.debug("Entering GnapGrants.mtlsTrustOf().");
    const trust = applications.gnapMtlsTrustFor(app ? app.fields : null).trust;
    log.debug("Leaving GnapGrants.mtlsTrustOf(). " + trust);
    return trust;
  }

  // The same, for a caller named by the identifier a grant or token records.
  /**
   * Returns the mutual TLS trust model in force for the caller a grant or token
   * records.
   *
   * @param identifier - the application's identifier
   * @returns `pki` or `pinned`
   */
  mtlsTrustOfIdentifier(identifier) {
    const { log, applications } = this.deps;
    log.debug("Entering GnapGrants.mtlsTrustOfIdentifier().");
    const app = identifier ? applications.get(String(identifier)) : null;
    log.debug("Leaving GnapGrants.mtlsTrustOfIdentifier().");
    return this.mtlsTrustOf(app);
  }

  // A key by value whose thumbprint no entry holds is found, UNDER A PKI
  // ONLY, by what the certificate AUTHORITY says: the application a
  // certificate this realm issued names, or the one GNAP entry whose RFC 8705
  // subject parameter the certificate carries. That is section 11.4's
  // rotation — a new certificate from the authority, no new registration —
  // and it is never done by thumbprint, which is exactly what is unknown.
  // Whatever it finds is then held to `proof.certificateBinding()`, so a
  // lookup that found the wrong entry refuses rather than binds. Two entries
  // registering the same subject find nobody.
  private appByCertificate(req) {
    const { log, applications, proof } = this.deps;
    log.debug("Entering GnapGrants.appByCertificate().");
    const issued = this.deps.mtls.issuedIdentityOf(req);
    const identity: any = issued.identity || {};
    if (identity.issuedHere) {
      const app = identity.accepted && identity.kind === 'application'
        ? applications.get(String(identity.username)) : null;
      log.debug("Leaving GnapGrants.appByCertificate(). Issued here: " +
                (app ? app.identifier : 'no entry'));
      return app || null;
    }
    const matching = this.gnapApplications().filter((one) => {
      return proof.certificateBinding(req, one).ok;
    });
    log.debug("Leaving GnapGrants.appByCertificate(). " + matching.length +
              " entry(ies) by subject.");
    return matching.length === 1 ? matching[0] : null;
  }

  // Before the proof of an mtls key: the entry it belongs to, as far as
  // anything before the proof can say, the model in force for it, and — under
  // a PKI, for a caller named by instance identifier or key reference — the
  // key the proof should compare, which is the certificate on THIS
  // connection: the entry names the client, the authority vouches for the
  // certificate, and `certificateBinding()` ties the two after the proof. A
  // key presented BY VALUE is never replaced: section 11.3 makes the TLS key
  // the request's key, and a different one is STS-GNAP-0278.
  private placeMtlsCaller(req, descriptor, app, byReference) {
    const { log, keys, mtls: mtlsLib } = this.deps;
    log.debug("Entering GnapGrants.placeMtlsCaller().");
    let found = app;
    if (!found && descriptor.reference) {
      const resolved = this.resolveKeyReference(descriptor.reference);
      found = resolved ? resolved.app : null;
    }
    if (!found) {
      found = this.appByKeyIdentity(descriptor.identity);
    }
    const trust = this.mtlsTrustOf(found);
    if (trust !== 'pki') {
      log.debug("Leaving GnapGrants.placeMtlsCaller(). Pinned.");
      return { app: found, descriptor: descriptor, trust: trust };
    }
    if (!found) {
      found = this.appByCertificate(req);
    }
    let chosen = descriptor;
    const certificate = mtlsLib.peerCertificate(req);
    if (byReference && certificate &&
        descriptor.thumbprint !== mtlsLib.thumbprintOf(certificate)) {
      const presented = keys.describe({ proof: 'mtls',
                                        cert: Buffer.from(certificate.raw)
                                          .toString('base64') }, {});
      if (presented.ok) {
        chosen = presented;
      }
    }
    log.debug("Leaving GnapGrants.placeMtlsCaller(). PKI, app=" +
              (found ? found.identifier : '(none)'));
    return { app: found, descriptor: chosen, trust: trust };
  }

  // After the proof, under a PKI: the certificate must be bound to the entry,
  // and a thumbprint the entry does not yet hold is recorded on it, so the
  // next request by value finds it (section 11.4's rotation at the
  // authority). Answers null, or the refusal.
  private bindMtlsCaller(req, app, descriptor) {
    const { log, applications, proof } = this.deps;
    log.debug("Entering GnapGrants.bindMtlsCaller().");
    const bound = proof.certificateBinding(req, app);
    if (!bound.ok) {
      log.debug("Leaving GnapGrants.bindMtlsCaller(). Not bound: " +
                bound.why);
      return bound;
    }
    if (app && descriptor.identity &&
        this.registeredKeyIdentity(app) !== descriptor.identity &&
        this.field(app, 'gnapKeyIdentity') !== descriptor.identity) {
      applications.seen({ identifier: app.identifier, protocol: PROTOCOL,
                          counts: false,
                          fields: { gnapKeyIdentity: descriptor.identity } });
      log.info('gnap: the application "' + app.identifier + '" proved a ' +
               'certificate its authority issued it (' + bound.mapping +
               ') that it had not presented before; its thumbprint ' +
               descriptor.identity + ' is recorded on the entry (RFC 9635 ' +
               'section 11.4).');
    }
    log.debug("Leaving GnapGrants.bindMtlsCaller(). " + bound.mapping);
    return null;
  }

  // ---------------------------------------------------------------------------
  // WHO IS CALLING: the client (or RS) member, its key, the entry, and the
  // proof.
  //
  // `member` is `{ reference, key, classId, display }` (gnap_request.ts).
  // `kind` is KIND_CLIENT or KIND_RS.
  // ---------------------------------------------------------------------------
  /**
   * Identifies who is calling — a client instance or a resource server — by its
   * key, its entry and its proof of possession.
   *
   * @param req - the request
   * @param body - what `gnap_proof.readBody()` read
   * @param member - the `client` or resource server member: `{ reference, key,
   *   classId, display }`
   * @param kind - `KIND_CLIENT` or `KIND_RS`
   * @param options - further options for the proof
   * @returns `{ ok: true, app, descriptor, proof, ... }`, or a refusal
   */
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
    // MUTUAL TLS (#107): the entry, the trust model and the key to compare,
    // decided before the proof, which needs the model.
    let mtlsTrust = null;
    if (descriptor.proof && descriptor.proof.method === 'mtls') {
      const placed = this.placeMtlsCaller(req, descriptor, app,
                                          !!member.reference ||
                                          !!descriptor.reference);
      app = placed.app;
      descriptor = placed.descriptor;
      mtlsTrust = placed.trust;
    }
    // ONCE ACROSS THE CLUSTER (#46): the proof's replay keys are spent before
    // anything is done for this caller — gnap_proof.ts's verifyRequestOnce().
    const verified = await proof.verifyRequestOnce(req, body, descriptor, {
        accessToken: opts.accessToken || null, mtlsTrust: mtlsTrust });
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
    if (mtlsTrust === 'pki') {
      const unbound = this.bindMtlsCaller(req, app, descriptor);
      if (unbound) {
        monitor.record(app ? app.identifier : '(unidentified)',
                       'proof.failed',
                       { gnapError: kind === KIND_RS ?
                                    'invalid_resource_server' :
                                    'invalid_client' });
        log.debug("Leaving GnapGrants.identifyCaller(). The certificate is " +
                  "not bound to the entry.");
        return Object.assign(unbound, { gnapError: kind === KIND_RS ?
                                        'invalid_resource_server' :
                                        'invalid_client', status: 401 });
      }
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
      // ---------------------------------------------------------------------
      // NOTHING THE CLIENT SAID ABOUT ITSELF IS WRITTEN ONTO THE ENTRY (#432
      // phase 7, 2026-10-03). `class_id` and `display` (section 2.3) are
      // SELF-DECLARED: any key can claim any name, logo, home page or class.
      // They were copied into `gnapClassId`, `gnapDisplayUri`, `gnapLogoUri`
      // and the entry's name here — and section 2.3 has "the pre-registered
      // values ... take precedence", so the client's own claims became the
      // REGISTERED values from its second request on, and the approval page
      // drew them as the administrator's. The entry records the key and
      // nothing else; what the client declares is read from each request
      // and marked as declared (below).
      // ---------------------------------------------------------------------
      const fields: Record<string, any> = { gnapKey:
                                            JSON.stringify(descriptor.value),
                                            gnapKeyIdentity:
                                            descriptor.identity };
      applications.seen({ identifier: identifier, kind: kind, protocol:
                          PROTOCOL,
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
             display: this.displayOf(app, member),
             classId: this.field(app, 'gnapClassId') || member.classId || null,
             classIdDeclared: !this.field(app, 'gnapClassId') &&
                              !!member.classId };
  }

  // -------------------------------------------------------------------------
  // `class_id` AND `display` ARE SELF-DECLARED AND NEVER RAISE TRUST (#432
  // phase 7, 2026-10-03).
  //
  // Section 2.3: "the pre-registered values MUST take precedence" — so a
  // value an administrator put on the entry wins, and a value only the
  // request carries is the CLIENT's claim about itself, which any key can
  // make. Every member taken from the request is named in `declared`, and
  // the approval page says so beside it rather than drawing it as this
  // service's word. NOTHING DECIDES ON EITHER: no reader of `classId` or
  // `display` grants, skips interaction, picks a token format or relaxes a
  // check — `gnapSkipInteraction`, the access policy and the issuance gate
  // read the ENTRY. Audited 2026-10-03 (`gnap/CLAUDE.md`); a reader added
  // later that decides on one of them is a defect, and the in-process test
  // (`tests/gnap_person_grants.js`) holds the auto-created entry to carrying
  // none of them.
  // -------------------------------------------------------------------------
  private displayOf(app: any, member: any): any {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.displayOf().");
    const asked = member.display || {};
    const declared: string[] = [];
    const registeredName = app.name && app.name !== app.identifier
      ? app.name : '';
    let name = registeredName;
    if (!name && asked.name) {
      name = String(asked.name);
      declared.push('name');
    }
    let uri = this.field(app, 'gnapDisplayUri');
    if (!uri && asked.uri) {
      uri = String(asked.uri);
      declared.push('uri');
    }
    let logoUri = this.field(app, 'gnapLogoUri');
    if (!logoUri && asked.logoUri && String(asked.logoUri).length < 2048) {
      logoUri = String(asked.logoUri);
      declared.push('logoUri');
    }
    log.debug("Leaving GnapGrants.displayOf(). declared=" +
              declared.join(','));
    return { name: name || app.identifier, uri: uri || null,
             logoUri: logoUri || null, declared: declared };
  }

  // ---------------------------------------------------------------------------
  // ACCESS POLICY for one requested token.
  // ---------------------------------------------------------------------------
  /**
   * Serializes a value as canonical JSON — sorted keys, and arrays of strings
   * sorted — so equal rights compare equal.
   *
   * @param value - the value
   * @returns the canonical JSON
   */
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

  /**
   * Returns the consent token recorded for one access right: `gnap:` and a
   * truncated SHA-256 of its canonical JSON.
   *
   * @param right - the access right
   * @returns the digest token
   */
  digestTokenOf(right) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.digestTokenOf().");
    log.debug("Leaving GnapGrants.digestTokenOf().");
    return 'gnap:' + nodeCrypto.createHash('sha256')
        .update(this.canonicalJson(right), 'utf8').digest('base64url').slice(0,
        22);
  }

  // ---------------------------------------------------------------------------
  // WHAT A CLIENT MAY BE GRANTED IS THE ISSUANCE POLICY'S (#432 phase 3).
  // `protectedAccessProblem()` (this service's protected scopes, #110) and
  // `accessProblem()` (gnapAllowedAccess, an unknown reference) were here;
  // with the bearer check they are now rules of the built-in issuance
  // policy, asked one right at a time by `gnap_rights.ts`'s `judge()` —
  // `rightsContext()` below is what this engine tells it. No copy of them
  // stays: a second authority would be one an operator's policy could not
  // override.
  // ---------------------------------------------------------------------------
  private rightsContext(req, grantish, app, approval) {
    const { log, authorizationServers, gate } = this.deps;
    const self = this;
    log.debug("Entering GnapGrants.rightsContext(). " + approval);
    const grant = grantish || {};
    const ro = grant.ro || null;
    const session = ro ? this.sessionOfGrant(grant) : null;
    const about = ro ? { kind: 'user', name: ro.username,
                         authenticated: true } : null;
    let risk = null;
    let device = null;
    if (about) {
      risk = gate.riskFactsOf({ session: session, subject: about });
      device = gate.deviceFactsOf({ session: session });
    }
    const pseudo = { as: grant.as || authorizationServers.DEFAULT_ID,
                     client: { identifier: app.identifier } };
    log.debug("Leaving GnapGrants.rightsContext().");
    return {
      app: app,
      approver: ro ? ro.username : '',
      approval: approval,
      session: ro ? { acr: ro.acr || (session && session.acr) || '',
                      amr: ro.amr || (session && session.amr) || [] }
                  : null,
      risk: risk, device: device,
      // What the owner lookups answered (#432 phase 5): filled by the caller
      // from `rights.owners()` before the question is asked.
      owners: {} as any,
      targetsOf: function targetsOf(access) {
        log.debug("Entering targetsOf().");
        log.debug("Leaving targetsOf().");
        return self.resourceServersFor(access);
      },
      formatOf: function formatOf(access, targets) {
        log.debug("Entering formatOf().");
        log.debug("Leaving formatOf().");
        return self.chooseFormat(req, pseudo, access, targets) || '';
      }
    };
  }

  // The request stage (#432 phase 3): the catalogue's well-formedness, then
  // one policy question per right. A refusal, or the tokens as the policy
  // left them and what it narrowed.
  private async judgeRequested(req, grantish, app, tokens, approval) {
    const { log, rights } = this.deps;
    log.debug("Entering GnapGrants.judgeRequested().");
    const malformed = rights.conformanceRefusal(tokens);
    if (malformed) {
      log.debug("Leaving GnapGrants.judgeRequested(). Malformed.");
      return malformed;
    }
    const ctx = this.rightsContext(req, grantish, app, approval);
    // The owner lookups first (#432 phase 5): the question is synchronous.
    ctx.owners = await rights.owners(tokens, ctx);
    const judged = rights.judge(tokens, ctx, rights.STAGES.REQUEST);
    log.debug("Leaving GnapGrants.judgeRequested(). " +
              (judged.ok ? 'Judged.' : 'Refused.'));
    return judged;
  }

  // ---------------------------------------------------------------------------
  // MAY THIS PERSON APPROVE WHAT IS ASKED? (#432 phase 5) — the approval
  // page's question before it draws, and again before it records an
  // approval. Only the rights whose identifier is OWNED by somebody else, or
  // whose owner could not be looked up, are put to the issuance policy, as
  // this person's `interaction` approval; the policy's built-in rule refuses
  // them (STS-GNAP-0861, 0863) unless a realm's own allows. Every other right
  // is the page's ordinary business and is not asked about here, so the page
  // refuses for ownership and nothing else. The refusal, or null.
  // ---------------------------------------------------------------------------
  /**
   * Says whether a person may approve the rights a grant asks for, as their
   * resource owner (#432 phase 5).
   *
   * @param req - the request from the approval page
   * @param grant - the grant
   * @param username - the person signed in on the page
   * @returns a promise of the policy's refusal, or null
   */
  async approverRefusal(req, grant, username) {
    const { log, applications, rights, ownership } = this.deps;
    log.debug("Entering GnapGrants.approverRefusal().");
    const app = applications.get(grant.client.identifier) ||
                { identifier: grant.client.identifier, fields: {} };
    const ctx = this.rightsContext(req, Object.assign({}, grant, {
      ro: { username: username, sessionId: null, amr: [], acr: '' } }),
      app, 'interaction');
    const asked = (grant.request && grant.request.tokens) || [];
    ctx.owners = await rights.owners(asked, ctx);
    const disputed = asked.map(function (token) {
      return Object.assign({}, token, {
        access: (token.access || []).filter(function (right) {
          const facts = ownership.facts(right, ctx.targetsOf([right]),
                                        username, ctx.owners);
          return facts.unresolved || (facts.known && !facts.matches);
        }) });
    }).filter(function (token) {
      return token.access.length > 0;
    });
    if (!disputed.length) {
      log.debug("Leaving GnapGrants.approverRefusal(). Nothing disputed.");
      return null;
    }
    const judged = rights.judge(disputed, ctx, rights.STAGES.REQUEST);
    log.debug("Leaving GnapGrants.approverRefusal(). " +
              (judged.ok ? 'The policy allows it.' : 'Refused.'));
    return judged.ok ? null : judged;
  }

  // ---------------------------------------------------------------------------
  // RESOURCE SERVERS AND TOKEN FORMAT for a set of rights.
  // ---------------------------------------------------------------------------
  /**
   * Returns the resource servers a set of rights is for: by registered
   * reference, or by a location under a resource server's registered URI.
   *
   * @param access - the access rights
   * @returns the resource servers' identifiers
   */
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
    // THE OWNER OF A CATALOGUED TYPE (#432 phase 4): a right of a type a
    // resource server declares that names NO location is for that resource
    // server — the API that defines it. One that names locations is for the
    // resource servers they resolve to above, which the catalogue holds to
    // the addresses its owner declares.
    this.deps.rights.ownersOf((access || []).filter(function (right) {
      return right && typeof right === 'object' &&
             !(Array.isArray(right.locations) && right.locations.length);
    })).forEach(function (owner) {
      found[owner] = true;
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
        // GNAP's, not OAuth 2.0's, for the protocol-declaration rule.
        protocolFamilies: ['gnap'],
            subject: username ? { kind: 'user', name: username, authenticated:
                                  true } : { kind: 'application', name:
                                             grant.client.identifier,
                                             authenticated: true }, claims:
            null, session: this.sessionOfGrant(grant) });
      if (!allowed.allowed) {
        log.info('gnap: the issuance policy refused a token for grant ' +
                 grant.id + ': ' + allowed.why);
        // A realm being removed (#262) is its own code.
        audit.failure(allowed.retiring ? 'STS-CORE-0121' : 'STS-GNAP-0090',
                      { protocol: PROTOCOL, channel: 'http',
                        target: grant.client.identifier,
                        summary: 'The issuance policy refused a GNAP ' +
                                 'access token',
                        detail: { grant: grant.id,
                                  why: String(allowed.why || '') } });
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
      // NO TOKEN OUTLIVES ITS GRANT (#432 phase 7): the token's lifetime,
      // cut short at the grant's own expiry.
      let lifetime = this.cappedLifetime(grant, iat,
          Number(applications.settingFor(grant.client.identifier,
                                         'gnap.accessTokenLifetimeS',
                                         config)) || 3600);
      // THE ISSUANCE POLICY'S LIFETIME for a right in this token (#432
      // phase 3: the catalogue's maxLifetimeS, as the built-in policy
      // states it), never lengthening what the grant allows.
      if (typeof asked.maxLifetimeS === 'number' &&
          asked.maxLifetimeS < lifetime) {
        lifetime = asked.maxLifetimeS;
      }
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
        jti: store.handle(16),
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
        label: asked.label || null,
        // RFC 8693 section 4.1's `act` (#432): set on a DERIVED grant only,
        // naming the deriving resource server over the original token's
        // chain (`deriveToken()`). Every format carries it.
        act: grant.actorChain || null,
        // THE GRANT A RIGHT'S LIMITS ARE COUNTED AGAINST (#432 phase 5): a
        // resource server keeps the running totals per grant (rcbj's
        // decision 2), and one that verifies the token on its own needs to
        // know which — this grant, the same across rotation, or for a
        // derived token the original's (`deriveToken()`).
        grant: grant.limitsGrant || grant.id
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
        rsIdentifiers: rsIds, username: username,
        // Kept on the token too, so a rotation is held to it after the
        // finalized grant itself is pruned.
        grantExpiresAt: grant.grantExpiresAt || null,
        // #432: the JWT formats' index in the realm's access-token status
        // list, and a biscuit's revocation identifiers — what the token's
        // value says, kept because the store keeps only its digest.
        statusIdx: minted.statusIdx === undefined ? null : minted.statusIdx,
        revocationIds: minted.revocationIds || null
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
  // -------------------------------------------------------------------------
  // THE SIGN-ON SESSION A GRANT'S RESOURCE OWNER INTERACTED ON (#62 P3), or
  // null: what the issuance gate reads the risk of the authentication from,
  // so a GNAP token rests on the same decision a session would. Required
  // LAZILY — the sign-in service is loaded long before this family, and a
  // process without it (a test of this file) has no session to find.
  // -------------------------------------------------------------------------
  private sessionOfGrant(grant: any): any {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.sessionOfGrant().");
    const id = grant && grant.ro ? String(grant.ro.sessionId || '') : '';
    if (!id) {
      log.debug("Leaving GnapGrants.sessionOfGrant(). None named.");
      return null;
    }
    try {
      log.debug("Leaving GnapGrants.sessionOfGrant().");
      return require('../authn/authn').sessionById(id) || null;
    } catch (e) {
      log.debug("Caught in GnapGrants.sessionOfGrant(): " +
                ((e && e.message) || e));
      // No sign-in service in this process: no session, and the gate finds
      // the person's standing or nothing.
      log.debug("Leaving GnapGrants.sessionOfGrant(). None held.");
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // SUBJECT INFORMATION IS RELEASED ONCE, AND ONLY ON AN AUTHORIZATION (#432
  // phase 7, 2026-10-03).
  //
  // Section 3.4's sub_ids and assertions say WHO the resource owner is, and
  // the only parties who can authorize telling a client that are the person
  // and the policy that lets a client act for them. So `release()` releases
  // subject information only when the grant carries
  // `subjectAuthorizedBy`:
  //
  //   'interaction'  the resource owner left the "who you are" box ticked on
  //                  the approval page (`decide()`);
  //   'delegation'   a trusted client presented a verified assertion about
  //                  the person and the delegation decision (#432 phase 1,
  //                  `delegation_policy.ts`, S4U2Self's question) allowed it
  //                  to act for them (`createGrant()`).
  //
  // **THE AUTHORIZATION IS SPENT BY THE RELEASE.** Once subject information
  // has gone out the flag is cleared and the instant recorded
  // (`subjectReleasedAt`, `subjectReleasedBy`), so nothing later in the
  // grant's life sends it again: not a continuation after approval
  // (`settle()` answers a continue member only), not a modification within
  // the earlier approval (its decision carries `subject: false`), not a token
  // rotation (`manageVerified()` mints a token and nothing else), and not a
  // derivation (`deriveToken()`, `subject: false`). A modification that ASKS
  // for subject information is not within the earlier approval
  // (`modifyGrant()`), so it goes to a new interaction, whose decision
  // authorizes the one release that follows it. A decision that asks for the
  // subject without either authorization releases nothing and says so
  // (`STS-GNAP-0793`).
  // -------------------------------------------------------------------------
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
    // The CLIENT the identifiers are for (#432 phase 7): the opaque
    // identifier is per client or sector, and `iss_sub` is the `sub` this
    // client's ID Token carries.
    const ids = subject.subIdsFor(grant.ro.username, formats, {
      issuer: issuer, client: grant.client.identifier,
      sessionId: grant.ro.sessionId || null });
    if (ids.length) {
      out.sub_ids = ids;
    }
    const heldSession = this.sessionOfGrant(grant);
    const wanted = assertionFormats.filter(function (format) {
      const kind = format === 'id_token' ? gate.ISSUANCE.ID_TOKEN :
                   gate.ISSUANCE.SAML_ASSERTION;
      return gate.check({ application: grant.client.identifier, kind: kind,
                          protocolFamilies: ['gnap'],
                          subject: { kind: 'user', name: grant.ro.username,
                                     authenticated: true },
                          claims: null,
                          session: heldSession }).allowed;
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
    // A grant waiting for an absent owner (#432 phase 6) is polled at a
    // pace that lets `gnap.maxPolls` cover the owner's whole time.
    const ownerWait = this.deps.approval.waitFor(grant);
    const wait = ownerWait !== null ? ownerWait
      : Math.max(0, Number(config.value('gnap.continueWaitS')));
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
      // UNIFORM over the alphabet (#65): a byte modulo 31 drew the first
      // eight characters 9/256 of the time and the rest 8/256.
      const code = stsCrypto.randomString(USER_CODE_ALPHABET, length);
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
  /**
   * Normalises a user code (section 4.1.2): upper-cased, everything outside the
   * alphabet stripped.
   *
   * @param input - the code as typed
   * @returns the normalised code
   */
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
        // `urlVerdict()` rather than `urlProblem()` since #171: plain http
        // refused because this realm is in product mode is `STS-GNAP-0103`,
        // the condition the check below names for every finish method.
        const problem = transport.urlVerdict(finish.uri);
        if (problem.why) {
          log.debug("Leaving GnapGrants.startInteraction(). Push URI cannot " +
                    "be dialled.");
          return this.refusal(problem.errorCode || 'STS-GNAP-0102',
                              problem.why + ' (RFC 9635 section 11.34).',
                              'invalid_interaction');
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
                          interactRef: null,
                          approvalId: store.handle(18),
                          hints: interact.hints };
    store.putInteraction('approve:' + interaction.approvalId, grant.id);
    usable.forEach((mode) => {
      if (mode === 'redirect' || mode === 'app') {
        const id = store.handle(18);
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
  /**
   * Computes the interaction hash of section 4.2.3 over the two nonces, the
   * interaction reference and the grant endpoint URI.
   *
   * @param clientNonce - the client's nonce
   * @param serverNonce - the AS's nonce
   * @param interactRef - the interaction reference
   * @param grantEndpoint - the grant endpoint URI
   * @param hashMethod - the hash method (`sha-256` by default)
   * @returns the base64url hash
   */
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
  // MAY THIS REQUEST BE ISSUED WITH NOBODY ON THE PAGE? (#432 phase 6)
  //
  // `requirement` is what the issuance policy's verdicts said the rights
  // need (`gnap_rights.ts`): the most demanding interaction among them and
  // every acr. `gnapSkipInteraction` now means "may skip where every
  // requested right's type allows it":
  //
  //   always     nobody skips — the person sees the page (STS-GNAP-0892
  //              when a trusted client then offers no way to reach them);
  //   skippable  a trusted client skips, as before #432;
  //   none       every right is of a `never` type: issued with nobody
  //              asked, from any client, but only as ITSELF — a request
  //              naming a person or asking who they are is about that
  //              person, which only a trusted client's delegation decision
  //              or the person can authorize.
  //
  // And a right that needs an authentication level is never issued with no
  // session to meet it (STS-GNAP-0893): the request goes to the page, which
  // steps the person up, or — offering no interaction — is refused. An
  // assertion's own `acr` is not taken as that session: it is a statement
  // about a sign-in somewhere else, at some earlier time, presented by the
  // client that wants the token.
  // ---------------------------------------------------------------------------
  private skipVerdict(trusted: boolean, asked: any, resolved: any,
                      requirement: any): any {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.skipVerdict(). interaction=" +
              requirement.interaction);
    const always: string[] = Array.isArray(requirement.always)
      ? requirement.always : [];
    if (requirement.interaction === 'always') {
      log.debug("Leaving GnapGrants.skipVerdict(). A type asks for its " +
                "owner.");
      return { skip: false, forPerson: false, code: 'STS-GNAP-0892',
               why: 'a right of type ' + always.map(function (one) {
                 return '"' + one + '"';
               }).join(', ') + ' needs its resource owner on the approval ' +
               'page, by its access type or a consent action' };
    }
    let skip = false;
    let forPerson = false;
    if (trusted && (!asked.subject || resolved.verified)) {
      skip = true;
      forPerson = !!(resolved.verified && resolved.username);
    } else if (requirement.interaction === 'none' && !asked.user &&
               !asked.subject) {
      skip = true;
    }
    const acrs: string[] = Array.isArray(requirement.acr) ? requirement.acr
                                                          : [];
    if (skip && acrs.length) {
      log.debug("Leaving GnapGrants.skipVerdict(). An acr is needed.");
      return { skip: false, forPerson: false, code: 'STS-GNAP-0893',
               why: 'a right needs authentication level ' + acrs.join(' ') +
                    ', which only a session the resource owner signs in ' +
                    'with can meet' };
    }
    log.debug("Leaving GnapGrants.skipVerdict(). skip=" + skip);
    return { skip: skip, forPerson: forPerson, code: '', why: '' };
  }

  // ---------------------------------------------------------------------------
  // A NEW GRANT REQUEST (section 2). Answers `{ status, body }` or a refusal.
  // ---------------------------------------------------------------------------
  /**
   * Handles a new grant request (section 2): identifies the client, decides the
   * access, and answers with tokens, an interaction, or both.
   *
   * @param req - the request to the grant endpoint
   * @param asId - the authorization server's name
   * @returns `{ ok: true, status, body, grant }`, or a refusal
   */
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
    // EACH RIGHT, BEFORE ANYBODY IS ASKED (#432 phases 3 and 4): the
    // catalogue's well-formedness, then the issuance policy's verdict per
    // right — the bearer flag, the protected scopes, gnapAllowedAccess, an
    // unknown reference, an uncatalogued type in product. A derivation is
    // judged in `deriveToken()`, as the deriving resource server's request.
    let narrowedAtRequest = [];
    // What the rights need of their approval (#432 phase 6): who must be
    // asked and how strongly signed in, from the policy's verdicts.
    let requirement: any = { interaction: 'skippable', acr: [], always: [],
                             byRight: {} };
    if (!asked.existingAccessToken) {
      const judged = await this.judgeRequested(req, { as: asId }, app,
                                               asked.tokens, 'pending');
      if (!judged.ok) {
        monitor.record(identifier, 'grant.refused',
                       { gnapError: judged.gnapError });
        log.debug("Leaving GnapGrants.createGrant(). A right was refused.");
        return judged;
      }
      asked.tokens = judged.tokens;
      narrowedAtRequest = judged.narrowed;
      requirement = judged.requirement;
    }
    const oauth2 = this.deps.loadOauth2();
    const resolved = subject.resolveUser(asked.user, {
      issuer: oauth2.issuerOf(this.realmBase(req)),
      oauthIssuer: oauth2.issuerOf(this.realmBase(req)),
      // A user reference resolves only for the client it was issued to
      // (#432 phase 7, gnap_subject.ts).
      client: identifier
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
                // THE KEY UNDER A MUTUAL-TLS CLIENT'S CERTIFICATE (#432
                // follow-up): a `cert#S256` key names only a certificate, so
                // the key it was proved with is recorded here, for a
                // compromised device's key to find it.
                certSpki: caller.descriptor.proof.method === 'mtls'
                  ? this.deps.mtls.presentedKeyThumbprint(req) : '',
                display: caller.display, classId: caller.classId,
                classIdDeclared: caller.classIdDeclared },
      request: { tokens: asked.tokens, multiple: asked.multiple,
                 subject: asked.subject,
                 interact: asked.interact },
      userHint: resolved.username,
      userVerified: resolved.verified,
      ro: null,
      decision: null,
      delivered: false,
      polls: 0,
      // The grant's own lifetime (#432 phase 7, the header).
      grantExpiresAt: this.grantExpiryFrom(nowSec()),
      // What authorizes releasing subject information, set by an interaction
      // or a delegation decision and spent by the release (releaseSubject()).
      subjectAuthorizedBy: null,
      finalization: null,
      // How the grant was approved, for the issuance policy's per-right
      // question (#432 phase 3): pending until it is, then interaction,
      // remembered, skipped or derived.
      approval: 'pending',
      // What the issuance policy narrowed before the approval page was
      // drawn, which the page says (#432 phase 3).
      narrowed: narrowedAtRequest,
      // Who must be asked and how strongly signed in (#432 phase 6).
      requirement: requirement,
      // A grant waiting for its absent resource owner on the portal (#432
      // phase 6, `gnap_approval.ts`): null until it does.
      ownerApproval: null
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
      const instanceId = store.handle(18);
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
    //
    // THE SECOND IS IMPERSONATION, AND SINCE #432 IT IS ASKED (phase 1). Tokens
    // for a person nobody asked are Kerberos's S4U2Self in GNAP: the flag on
    // the client says it may skip the PAGE, not that it may act for anybody.
    // So `gnap_delegation.ts` puts #186's question to the issuance policy —
    // actor the client, subject the person, R each resource server the rights
    // resolve to — and impersonation must be in the client's allowed semantics
    // (`appDelegationSemantics`), the person not protected, inside the
    // client's subject groups, holding R's roles, with R reachable by the
    // client; a `may_act` in the assertion is honoured. Enforced in product,
    // recorded "would have been refused" in development; recorded either way.
    // The first case — the client acting as ITSELF — acts for nobody, asks
    // nothing, and releases no subject.
    //
    // SINCE #432 PHASE 6 THE FLAG IS NOT ALL OR NOTHING. `skipVerdict()`
    // holds it to what every requested right's type allows: a client
    // trusted to skip may skip only where each right is `skippable`; a
    // right of an `always` type, or naming a consent action, needs its
    // owner on the page whoever asks; a request of `never` rights alone
    // needs nobody, from any client, acting as itself; and a right that
    // needs an authentication level cannot be issued with no session to
    // meet it.
    const trusted = this.field(app, 'gnapSkipInteraction') === 'TRUE' &&
                    !caller.created;
    const skip = this.skipVerdict(trusted, asked, resolved, requirement);
    if (skip.skip) {
      const forPerson = skip.forPerson;
      let actQuestion = null;
      let decided = null;
      if (forPerson) {
        const formats = ((asked.user && asked.user.assertions) || [])
          .map(function (one) { return String(one.format || ''); })
          .filter(function (one, i, all) {
            return !!one && all.indexOf(one) === i;
          }).join(', ');
        actQuestion = {
          act: 'impersonation', actor: app, subject: resolved.username,
          targets: this.resourceServersFor(asked.tokens.reduce(
            function (all, one) {
              return all.concat(one.access);
            }, [])),
          mayAct: resolved.mayAct || null, format: formats,
          consumed: { kind: 'user assertion', identifier: formats,
                      note: 'signed by this realm and verified (RFC 9635 ' +
                            'section 2.4)' },
          grantId: grant.id };
        decided = this.deps.delegation.decide(actQuestion);
        if (!decided.ok) {
          this.deps.delegation.record(actQuestion, decided.decided,
                                      'refused', []);
          grant.state = STATE.FINALIZED;
          store.saveGrant(grant, 'refused: ' + decided.why);
          monitor.record(identifier, 'grant.refused',
                         { gnapError: decided.gnapError });
          log.debug("Leaving GnapGrants.createGrant(). The delegation " +
                    "policy refused the impersonation.");
          return decided;
        }
      }
      grant.ro = forPerson ?
                 { username: resolved.username, sessionId: null,
                                       authTime: nowSec(),
                                       amr: ['assertion'], acr: null } : null;
      grant.approval = 'skipped';
      // A client acting as itself is nobody's delegate and is told nothing
      // about anybody: no subject without a person.
      grant.decision = { approved: true, tokens: asked.tokens,
                         subject: forPerson && !!asked.subject };
      // SUBJECT INFORMATION WITHOUT AN INTERACTION IS A DELEGATION (#432
      // phase 7). The only way here with subject information asked for is a
      // trusted client presenting a VERIFIED assertion about a person — an
      // act for that person with nobody asked, put before the delegation
      // policy above (phase 1, S4U2Self's question). An enforced refusal has
      // already returned, so reaching here means the policy allowed it — or,
      // in development, recorded that product would have refused it and
      // issued anyway. The flag names that decision; release() releases
      // nothing without one of the two (releaseSubject()'s header). A client
      // acting as itself has no person and no decision: null.
      grant.subjectAuthorizedBy = forPerson && asked.subject
        ? 'delegation' : null;
      const before = (grant.tokens || []).length;
      const released = await this.release(req, grant);
      if (actQuestion) {
        this.deps.delegation.record(actQuestion, decided.decided, 'issued',
                                    (grant.tokens || []).slice(before));
      }
      Object.assign(response, released);
      monitor.record(identifier, 'grant.immediate', {});
      log.debug("Leaving GnapGrants.createGrant(). Approved without " +
                "interaction.");
      return { ok: true, status: 200, body: response, grant: grant };
    }
    if (!asked.interact) {
      // APPROVAL BY AN ABSENT RESOURCE OWNER (#432 phase 6, RFC 9635
      // section 1.4): the request names a person and offers no way to reach
      // them through the client, so it waits on their portal.
      if (resolved.username && this.deps.approval.available()) {
        const queued = await this.deps.approval.queue(grant,
          resolved.username, { via: 'no interaction offered' });
        if (!queued.ok) {
          this.finalize(grant, 'refused: ' + queued.why, 'rejected');
          monitor.record(identifier, 'grant.refused',
                         { gnapError: queued.gnapError });
          log.debug("Leaving GnapGrants.createGrant(). Not queued.");
          return queued;
        }
        response.continue = this.continueMember(req, grant);
        store.saveGrant(grant, 'waiting for its resource owner');
        log.debug("Leaving GnapGrants.createGrant(). Waiting for the owner.");
        return { ok: true, status: 200, body: response, grant: grant };
      }
      this.finalize(grant, 'refused: interaction required and the client ' +
                           'offers none', 'rejected');
      monitor.record(identifier, 'grant.refused',
                     { gnapError: 'invalid_interaction' });
      log.debug("Leaving GnapGrants.createGrant(). Interaction needed, none " +
                "offered.");
      // WHY a trusted client could not skip (#432 phase 6) is its own code.
      return this.refusal(trusted && skip.code ? skip.code : 'STS-GNAP-0113',
          'this request needs the resource owner\'s approval' +
          (trusted && skip.why ? ' (' + skip.why + ')' : '') +
          ' and the client offered no way to interact (RFC 9635 section ' +
          '2.5).', 'invalid_interaction');
    }
    const started = this.startInteraction(req, grant, app, asked.interact);
    if (!started.ok) {
      this.finalize(grant, 'refused: ' + started.why, 'rejected');
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
    const { log, nowSec, config, errorCodes, audit, store, monitor,
            accessRights } = this.deps;
    log.debug("Entering GnapGrants.release(). grant=" + grant.id);
    const out: Record<string, any> = {};
    // THE ISSUE STAGE (#432 phase 3): every approved right asked again, now
    // that who approved it, how, and on what session are known. A refused
    // right is left out of its token (audited), a narrowed one narrowed, and
    // a lifetime the policy states caps the token (`maxLifetimeS`).
    const app = this.deps.applications.get(grant.client.identifier) ||
                { identifier: grant.client.identifier, fields: {} };
    const issueCtx = this.rightsContext(req, grant, app,
                                        grant.approval || 'pending');
    issueCtx.owners = await this.deps.rights.owners(
      grant.decision.tokens || [], issueCtx);
    const judged = this.deps.rights.judge(grant.decision.tokens || [],
      issueCtx, this.deps.rights.STAGES.ISSUE);
    const requests = judged.tokens || [];
    if (judged.narrowed && judged.narrowed.length) {
      grant.narrowed = (grant.narrowed || []).concat(judged.narrowed);
    }
    if (requests.length) {
      const issued = await this.issueTokens(req, grant, requests,
                                            grant.request.multiple);
      if (issued) {
        out.access_token = issued;
      }
    }
    if (grant.decision.subject) {
      const authorizedBy = String(grant.subjectAuthorizedBy || '');
      if (SUBJECT_AUTHORIZATIONS.indexOf(authorizedBy) >= 0) {
        const released = await this.releaseSubject(req, grant);
        if (released && (released.sub_ids || released.assertions)) {
          out.subject = released;
          grant.subjectReleasedAt = nowSec();
          grant.subjectReleasedBy = authorizedBy;
        }
      } else if (!grant.subjectReleasedAt) {
        // Asked and approved, but by nothing that may authorize it — never
        // reached by this file's own paths; the code says which grant if a
        // new one ever does. (Already released and spent is the ordinary
        // case of a later release, and says nothing.)
        log.warn(errorCodes.tag('STS-GNAP-0793') + 'gnap: grant ' + grant.id +
                 ' was to release subject information that neither an ' +
                 'interaction nor a delegation decision authorized; none ' +
                 'was released.');
      }
      // SPENT, released or not: the next release needs a new authorization.
      grant.subjectAuthorizedBy = null;
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
    const continuable = config.value('gnap.continueAfterApproval') !== false;
    if (continuable) {
      out.continue = this.continueMember(req, grant);
    }
    store.saveGrant(grant, 'approved and released');
    if (!continuable) {
      // Section 1.5's Approved -> Finalized: the tokens are out and nothing
      // more can be asked of this grant. FINALIZED AS `issued`, whose tokens
      // stay live (the header).
      this.finalize(grant, 'released with no continuation offered',
                    'issued');
    }
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
  //
  // SINCE #432 (phase 1) A DERIVATION IS A DELEGATION, AND IS DECIDED AS ONE.
  // It is Kerberos's S4U2Proxy in GNAP: the deriving resource server (actor
  // and S) presents the person's token and asks for one to reach a downstream
  // resource server (R) as them. `gnap_delegation.ts` asks #186's policy —
  // the deriving RS must delegate to R (`appAllowedToDelegateTo` on it, or
  // `appAllowedToActOnBehalfOf` on R), the person must not be protected and
  // must hold S's roles — enforced in product, recorded in development. And
  // three rules that are the format's, in every mode:
  //
  //   * THE DERIVED TOKEN IS A SUBSET of the original (rcbj's decision 3): the
  //     exception for "rights registered for a downstream resource server"
  //     is gone — it let any resource server a token reached mint access
  //     nobody approved. `gnap_delegation.ts`'s `derivableBeyond()` is the
  //     one place the access-type catalogue (phase 4) will widen it.
  //   * IT CARRIES THE ACTOR CHAIN: RFC 8693 section 4.1's `act`, the deriving
  //     resource server outermost over the original token's chain, in every
  //     format (`grant.actorChain`, read by `issueTokens()` and kept by
  //     rotation and modification).
  //   * THE CHAIN IS CAPPED at `gnap.maxDerivationDepth` (STS-GNAP-0782).
  // ---------------------------------------------------------------------------
  private async deriveToken(req, grant, app, asked) {
    const { log, nowSec, config, store, tokens, monitor, delegation } =
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
    // Nor one whose resource owner is disabled or whose client is gone
    // (#432): a derived token would carry the person on past the end.
    const ended = this.deps.revocation.tokenProblem(existing);
    if (ended) {
      log.debug("Leaving GnapGrants.deriveToken(). " + ended.why);
      return this.refusal('STS-GNAP-0733', 'the existing access token is not ' +
          'active at this authorization server: ' + ended.why + ' (RFC 9767 ' +
          'section 4).', 'invalid_request');
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
    const askedRights = requested.reduce(function (all, one) {
      return all.concat(one.access);
    }, []);
    const downstream = this.resourceServersFor(askedRights);
    const widened = delegation.derivationWidens(existing.access, askedRights,
                                                { rs: app.identifier,
                                                  downstream: downstream });
    if (widened !== null) {
      log.debug("Leaving GnapGrants.deriveToken(). Asks for more than the " +
                "existing token.");
      return this.refusal('STS-GNAP-0513', 'a derived token must not carry ' +
                          'more access than the token it is derived from ' +
                          '(RFC 9767 section 4).', 'request_denied', 403);
    }
    // NOR MORE THAN ITS LIMITS (#432 phase 5): a derived right that drops
    // or raises the original's limits is wider, though covered.
    const raised = this.deps.rights.limitsRaised(existing.access, askedRights);
    if (raised) {
      log.debug("Leaving GnapGrants.deriveToken(). Raises a limit.");
      return this.refusal('STS-GNAP-0868', 'a derived token must not carry ' +
                          'more than the token it is derived from: ' + raised +
                          ' (RFC 9767 section 4).', 'request_denied', 403);
    }
    const chain = delegation.actorChainFor(app.identifier, existing.act);
    if (!chain.ok) {
      log.debug("Leaving GnapGrants.deriveToken(). The chain is too deep.");
      return chain;
    }
    // EACH DERIVED RIGHT IS JUDGED TOO (#432 phase 3), as the deriving
    // resource server's request, approval `derived`, about the original's
    // person: the catalogue's well-formedness, then the issuance policy.
    const derivedJudged = await this.judgeRequested(req,
      { as: grant.as, ro: existing.username ? { username: existing.username,
                                                amr: ['derived'] } : null },
      app, requested, 'derived');
    if (!derivedJudged.ok) {
      grant.state = STATE.FINALIZED;
      store.saveGrant(grant, 'refused: ' + derivedJudged.why);
      log.debug("Leaving GnapGrants.deriveToken(). A right was refused.");
      return derivedJudged;
    }
    // WHAT THE DERIVED RIGHTS NEED OF THEIR APPROVAL (#432 phase 6). A right
    // the original covers was approved on the original's page and inherits
    // that; one it does not — a catalogued `derivableFrom` type, the one
    // way past the subset rule — was never shown to anybody, so a type that
    // needs its owner on the page cannot be derived (STS-GNAP-0895). And an
    // acr is held to the session the ORIGINAL grant was approved on: a
    // derivation adds a party, never a sign-in (STS-GNAP-0896).
    const needs = derivedJudged.requirement || { always: [], acr: [] };
    const beyond = (derivedJudged.tokens || []).reduce(function (all, one) {
      return all.concat(one.access);
    }, []).filter((right) => {
      return !this.deps.accessRights.accessCovers(existing.access, [right]);
    });
    const unseen = beyond.filter(function (right) {
      return typeof right !== 'string' &&
        (needs.always || []).indexOf(right.type) >= 0;
    });
    if (unseen.length) {
      grant.state = STATE.FINALIZED;
      store.saveGrant(grant, 'refused: a derived right needs its owner');
      log.debug("Leaving GnapGrants.deriveToken(). A type needs its owner.");
      return this.refusal('STS-GNAP-0895', 'a right of type "' +
        unseen[0].type + '" needs its resource owner on the approval page, ' +
        'and a derived token adds it without anybody having seen it (RFC ' +
        '9767 section 4).', 'request_denied', 403);
    }
    const original = existing.grantId ? store.getGrant(existing.grantId)
                                      : null;
    const originalRo = original && original.ro ? original.ro : {};
    const unmetAcr = this.deps.rights.unmetAcr(needs.acr || [],
                                               { acr: originalRo.acr,
                                                 amr: originalRo.amr });
    if (unmetAcr.length) {
      grant.state = STATE.FINALIZED;
      store.saveGrant(grant, 'refused: an acr the original did not meet');
      log.debug("Leaving GnapGrants.deriveToken(). An acr is not met.");
      return this.refusal('STS-GNAP-0896', 'a derived right needs ' +
        'authentication level ' + unmetAcr.join(' ') + ', which the session ' +
        'the original token was approved on did not meet (RFC 9767 section ' +
        '4, RFC 9470).', 'request_denied', 403);
    }
    // WHO THE DERIVED TOKEN IS ABOUT: the original's person, or — for a
    // token a client was issued as itself — that client's application.
    const actQuestion = {
      act: 'derivation' as const, actor: app,
      subject: existing.username || existing.instanceId,
      targets: downstream, mayAct: null,
      consumed: { kind: 'access_token', identifier: String(existing.jti),
                  note: 'the existing_access_token, issued by this realm and ' +
                        'active' },
      grantId: grant.id };
    const decided = delegation.decide(actQuestion);
    if (!decided.ok) {
      delegation.record(actQuestion, decided.decided, 'refused', []);
      grant.state = STATE.FINALIZED;
      store.saveGrant(grant, 'refused: ' + decided.why);
      log.debug("Leaving GnapGrants.deriveToken(). The delegation policy " +
                "refused it.");
      return decided;
    }
    // The original's acr carried over (#432 phase 6), so the issue stage
    // holds each right to the session the original was approved on.
    grant.ro = existing.username ? { username: existing.username, sessionId:
                                     null, authTime: existing.iat, amr:
                                     ['derived'],
                                     acr: originalRo.acr || null } : null;
    grant.derivedFrom = existing.jti;
    // THE GRANT ITS LIMITS ARE COUNTED AGAINST (#432 phase 5): the
    // original's, so a derivation is a way to spend the same budget from
    // somewhere else and never a second one.
    grant.limitsGrant = existing.grant || existing.grantId || null;
    grant.actorChain = chain.act;
    grant.approval = 'derived';
    grant.narrowed = derivedJudged.narrowed;
    grant.decision = { approved: true, tokens: derivedJudged.tokens,
                       subject: false };
    const before = (grant.tokens || []).length;
    const body = await this.release(req, grant);
    delegation.record(actQuestion, decided.decided, 'issued',
                      (grant.tokens || []).slice(before));
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
  /**
   * Records the resource owner's decision on a grant and follows the finish
   * method.
   *
   * @param req - the request from the approval page
   * @param grant - the grant
   * @param session - the resource owner's session
   * @param selection - `{ approve, tokens, subject }`, with the rights the
   *   resource owner left ticked
   * @returns what the page does next: `{ redirect }`, `{ pushed, why }` or `{
   *   none }`
   */
  async decide(req, grant, session, selection) {
    const { log, config, audit, consent, store, request, subject, monitor,
          signals } = this.deps;
    log.debug("Entering GnapGrants.decide(). grant=" + grant.id + ", approve=" +
              selection.approve);
    const interaction = grant.interaction;
    interaction.decided = true;
    const username = subject.normaliseName(session.user.username);
    // Nothing about who the person is may go out unless THIS decision says
    // so (releaseSubject()'s header): cleared first, set below only by an
    // approval with the subject box ticked.
    grant.subjectAuthorizedBy = null;
    if (selection.approve && grant.userHint && grant.userHint !== username) {
      // Section 2.4: "If the identified end user does not match the RO present
      // at the AS ... the AS SHOULD reject the request with an unknown_user
      // error." Recorded as the decision, so the continuation says it.
      // `gnap.allowCrossUser`, which let whoever signed in approve instead,
      // is RETIRED (#432 phase 6): where approval by an absent owner is on,
      // the page never asks a different person — `forwardToOwner()` puts
      // the grant on the named owner's portal first — and where it is off
      // the answer is this one.
      grant.decision = { approved: false, error: 'unknown_user' };
    } else if (selection.approve) {
      grant.decision = { approved: true, tokens: selection.tokens,
                         subject: !!selection.subject };
      // How (#432 phase 3): a decision the approval page drew, or one a
      // remembered approval made without drawing it (`gnap_interact.ts`).
      grant.approval = selection.remembered ? 'remembered' : 'interaction';
      grant.subjectAuthorizedBy = selection.subject ? 'interaction' : null;
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
  /**
   * Says whether a decision is already remembered for every right a grant
   * requests, so the approval page is skipped.
   *
   * @param grant - the grant
   * @param username - the resource owner
   * @returns true when every right is remembered
   */
  rememberedFor(grant, username) {
    const { log, config, consent } = this.deps;
    log.debug("Entering GnapGrants.rememberedFor().");
    // A RIGHT WHOSE TYPE SAYS `always` (#432 phase 6) is approved on the page
    // every time: no remembered approval stands in for it, and neither does
    // `gnap.consentRequired` off — the type's declaration is the more
    // specific decision, and "always" that a setting could turn off would
    // be a word, not a rule. The person sees the page again.
    if (grant.requirement && grant.requirement.interaction === 'always') {
      log.debug("Leaving GnapGrants.rememberedFor(). A type asks every time.");
      return false;
    }
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

  // -------------------------------------------------------------------------
  // #432 PHASE 6: THE THREE WAYS AN APPROVAL ENDS OTHER THAN ON THE PAGE.
  // -------------------------------------------------------------------------
  /**
   * The person at the approval page is not the user the request named:
   * where approval by an absent owner is on, the grant goes to the named
   * owner's portal instead of being decided here, and the interaction is
   * finished so the client continues and polls (RFC 9635 sections 1.4 and
   * 2.4). Null where it does not apply — the person is the one named, or
   * the setting is off and the page answers `unknown_user` as before.
   *
   * @param req - the request to the approval page
   * @param grant - the grant
   * @param session - the person at the page
   * @returns `{ finished }` (the finish method's answer, `owner: true`), a
   *   refusal recorded as the decision, or null
   */
  async forwardToOwner(req, grant, session) {
    const { log, store, subject, audit } = this.deps;
    log.debug("Entering GnapGrants.forwardToOwner().");
    const present = subject.normaliseName(session.user.username);
    if (!grant.userHint || grant.userHint === present ||
        !this.deps.approval.available()) {
      log.debug("Leaving GnapGrants.forwardToOwner(). Not another person's.");
      return null;
    }
    grant.interaction.decided = true;
    const queued = await this.deps.approval.queue(grant, grant.userHint, {
      requestedBy: present, via: 'another person at the approval page' });
    if (!queued.ok) {
      // Recorded as the decision, so the client hears it at its next
      // continuation, and the finish method is still enacted.
      grant.decision = { approved: false, error: queued.gnapError,
                         code: this.deps.errorCodes.codeOf(queued) || '',
                         why: queued.why };
    }
    audit.audit({ action: 'gnap.grant.forward', category: 'protocol',
                  protocol: PROTOCOL, channel: 'http',
                  outcome: queued.ok ? 'success' : 'refused',
                  errorCode: queued.ok ? undefined
                    : this.deps.errorCodes.codeOf(queued),
                  actor: present, target: grant.client.identifier,
                  summary: 'The person at a GNAP approval page was not the ' +
                           'user the request named; the grant was sent to ' +
                           'that user\'s portal',
                  detail: { grant: grant.id, queued: !!queued.ok } });
    const finished = await this.finishInteraction(req, grant);
    store.saveGrant(grant, queued.ok ? 'sent to its resource owner'
                                     : 'not sent to its resource owner');
    log.debug("Leaving GnapGrants.forwardToOwner(). queued=" + !!queued.ok);
    return { finished: Object.assign({ owner: !!queued.ok }, finished),
             queued: !!queued.ok };
  }

  /**
   * The approval page asked the person to sign in again for the
   * authentication level the rights need, and the sign-in that came back
   * still does not meet it: the request is answered `request_denied`
   * (STS-GNAP-0899), recorded as the decision, and the finish method is
   * enacted — RFC 9470's "one sign-in, then refuse" in GNAP's vocabulary.
   *
   * @param req - the request to the approval page
   * @param grant - the grant
   * @param session - the session that came back
   * @param missing - the acr values it does not meet
   * @returns the finish method's answer
   */
  async refuseUnmetStepUp(req, grant, session, missing) {
    const { log, store, audit, monitor, subject } = this.deps;
    log.debug("Entering GnapGrants.refuseUnmetStepUp().");
    grant.interaction.decided = true;
    grant.decision = { approved: false, error: 'request_denied',
                       code: 'STS-GNAP-0899',
                       why: 'the approval needed authentication level ' +
                            (missing || []).join(' ') + ', which the ' +
                            'resource owner\'s sign-in did not meet (RFC ' +
                            '9470).' };
    const username = subject.normaliseName(session.user.username);
    grant.ro = { username: username, sessionId: session.id,
                 authTime: session.authTime, amr: session.amr,
                 acr: session.acr };
    monitor.record(grant.client.identifier, 'grant.denied',
                   { gnapError: 'request_denied' });
    audit.failure('STS-GNAP-0899', { protocol: PROTOCOL, channel: 'http',
      actor: username, target: grant.client.identifier,
      summary: 'A GNAP approval needed a stronger sign-in than the resource ' +
               'owner completed',
      detail: { grant: grant.id, missing: (missing || []).join(' '),
                acr: String(session.acr || '') } });
    const finished = await this.finishInteraction(req, grant);
    store.saveGrant(grant, 'refused: the step-up was not met');
    log.debug("Leaving GnapGrants.refuseUnmetStepUp().");
    return finished;
  }

  /**
   * Records the resource owner's answer given on the portal to a grant that
   * waited for them (`gnap_approval.ts`): the same decision the approval
   * page records, `approval: 'owner'`, with no finish method — the client
   * is polling. The caller has held the session to the step-up and claimed
   * the answer once across the cluster.
   *
   * @param grant - the grant
   * @param session - the owner's sign-on session
   * @param selection - `{ approve, tokens, subject }`, the rights left ticked
   */
  decideAsOwner(grant, session, selection) {
    const { log, store, audit, monitor, signals, subject } = this.deps;
    log.debug("Entering GnapGrants.decideAsOwner(). grant=" + grant.id);
    const username = subject.normaliseName(session.user.username);
    grant.ownerApproval.answered = true;
    grant.ownerApproval.answeredAt = this.deps.nowSec();
    grant.subjectAuthorizedBy = null;
    grant.ro = { username: username, sessionId: session.id,
                 authTime: session.authTime, amr: session.amr,
                 acr: session.acr };
    if (selection.approve) {
      grant.decision = { approved: true, tokens: selection.tokens,
                         subject: !!selection.subject };
      grant.approval = 'owner';
      grant.subjectAuthorizedBy = selection.subject ? 'interaction' : null;
      signals.noteApprover(grant.client.identifier, username);
    } else {
      grant.decision = { approved: false, error: 'user_denied' };
    }
    // The wait was stretched for the owner; the client may now collect.
    grant.continueNotBefore = 0;
    monitor.record(grant.client.identifier,
                   grant.decision.approved ? 'grant.approved' : 'grant.denied',
                   { gnapError: grant.decision.error });
    audit.audit({ action: grant.decision.approved ? 'gnap.grant.consent' :
                  'gnap.grant.deny', category: 'protocol', protocol: PROTOCOL,
                  channel: 'portal', outcome: grant.decision.approved ?
                  'success' : 'refused', errorCode: grant.decision.approved ?
                  undefined : 'STS-GNAP-0120', actor: username,
                  target: grant.client.identifier,
                  summary: grant.decision.approved
                    ? 'A resource owner approved a GNAP grant on the portal'
                    : 'A resource owner did not approve a GNAP grant on the ' +
                      'portal',
                  detail: { grant: grant.id, via: 'portal' } });
    store.saveGrant(grant, 'resource owner ' + (grant.decision.approved
      ? 'approved' : 'did not approve') + ' on the portal');
    log.debug("Leaving GnapGrants.decideAsOwner().");
  }

  // Section 4.2: create the interaction reference, compute the hash, and follow
  // the finish method. Answers `{ redirect }`, `{ pushed }` or `{ none }`.
  /**
   * Finishes an interaction (section 4.2): creates the interaction reference,
   * computes the hash and follows the finish method.
   *
   * @param req - the request
   * @param grant - the grant
   * @returns `{ redirect }`, `{ pushed, why }` or `{ none }`
   */
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
    // ITS RESOURCE OWNER DISABLED, OR ITS CLIENT'S ENTRY GONE OR NO LONGER
    // NAMING ITS KEY (#432): refused at use, whatever door made the change
    // and on a node it has not reached yet. Nothing is written here — the act
    // that disabled the person or changed the entry ends the grant. A DELETE
    // is the client revoking it (section 5.4), which is never refused for
    // this.
    const ended = req.method === 'DELETE' ? null
      : this.deps.revocation.grantProblem(grant);
    if (ended) {
      log.debug("Leaving GnapGrants.continuationCaller(). " + ended.why);
      return this.refusal(ended.code, 'this grant can no longer be ' +
                          'continued: ' + ended.why + '.',
                          'invalid_continuation', 400);
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
    const mtlsTrust = this.mtlsTrustOfIdentifier(grant.client.identifier);
    const verified = await proof.verifyRequestOnce(req, body, descriptor,
                                                   { accessToken: token,
                                                     mtlsTrust: mtlsTrust });
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

  // THE ONE PLACE A GRANT IS FINALIZED (#432 phase 7): the state, the
  // reason (`FINALIZATION_REASONS`, the header), the continuation dropped,
  // the history note and the audit row, together — so no path can finalize
  // a grant without saying why.
  /**
   * Finalizes a grant, recording why (#432 phase 7): `issued`, `revoked`,
   * `rejected` or `expired`, with the transition on its history and an audit
   * row.
   *
   * @param grant - the grant
   * @param note - the transition, as its history records it
   * @param reason - one of `FINALIZATION_REASONS`
   * @param actor - who finalized it, for the audit row; the client otherwise
   */
  finalize(grant, note, reason, actor?) {
    const { log, nowSec, audit, store } = this.deps;
    log.debug("Entering GnapGrants.finalize(). reason=" + reason);
    const why = FINALIZATION_REASONS.indexOf(reason) >= 0 ? reason
      : (grant.delivered ? 'issued' : 'rejected');
    grant.state = STATE.FINALIZED;
    grant.finalization = { reason: why, at: nowSec(),
                           note: String(note || '').slice(0, 200) };
    store.dropContinuation(grant);
    store.saveGrant(grant, note + ' (finalized: ' + why + ')');
    audit.audit({ action: 'gnap.grant.finalize', category: 'protocol',
                  protocol: PROTOCOL, channel: 'http', outcome: 'success',
                  actor: actor || (grant.client && grant.client.identifier),
                  target: grant.client && grant.client.identifier,
                  summary: 'A GNAP grant was finalized: ' + why,
                  detail: { grant: grant.id, reason: why,
                            note: String(note || '').slice(0, 200),
                            resourceOwner: grant.ro ? grant.ro.username :
                                           '' } });
    log.debug("Leaving GnapGrants.finalize().");
  }

  // Why an untouched grant that ran out is finalized: `rejected` when the
  // last thing its resource owner said was no, `expired` otherwise.
  private expiryReason(grant) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.expiryReason().");
    log.debug("Leaving GnapGrants.expiryReason().");
    // An owner asked on the portal who never said yes (#432 phase 6) is a
    // rejection, as a no is.
    return grant.lastDenial || grant.ownerApproval ? 'rejected' : 'expired';
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
  /**
   * Handles a continuation request (section 5), the continuation token spent
   * once across the cluster and given back if it is still live afterwards.
   *
   * @param req - the request to the continuation URI
   * @param grantId - the grant's identifier
   * @returns the response to send, or a refusal
   */
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
      this.finalize(grant, 'expired', this.expiryReason(grant));
      if (grant.ownerApproval && !grant.ownerApproval.answered) {
        log.debug("Leaving GnapGrants.continueAccepted(). The owner did not " +
                  "answer in time.");
        return this.refusal('STS-GNAP-0894', 'the resource owner did not ' +
          'answer this request on their portal in time ' +
          '(gnap.ownerApprovalLifetimeS); it is finalized as rejected (RFC ' +
          '9635 section 1.4).', 'invalid_continuation');
      }
      log.debug("Leaving GnapGrants.continueAccepted(). Expired.");
      return this.refusal('STS-GNAP-0132', 'this grant request expired ' +
                          'before it was approved.', 'invalid_continuation');
    }
    if (req.method === 'DELETE') {
      log.debug("Leaving GnapGrants.continueAccepted().");
      return this.revokeGrant(req, grant);
    }
    // THE GRANT'S OWN LIFETIME (#432 phase 7): past it nothing continues or
    // modifies the grant — only the DELETE above, which ends it anyway.
    if (this.grantLifetimeEnded(grant)) {
      this.finalize(grant, 'the grant lifetime ended', 'expired');
      monitor.record(identifier, 'grant.refused',
                     { gnapError: 'invalid_continuation' });
      log.debug("Leaving GnapGrants.continueAccepted(). Lifetime ended.");
      return this.refusal('STS-GNAP-0790', 'this grant\'s lifetime ' +
          '(gnap.grantLifetimeS) has ended, so it can no longer be ' +
          'continued or modified; make a new grant request (RFC 9635 ' +
          'section 5).', 'invalid_continuation');
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
                      'pending state', 'rejected');
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
      this.finalize(grant, 'too many polls', 'rejected');
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
      const lastDecision = grant.decision;
      // Remembered so that a grant left to run out after a no is finalized
      // as `rejected` rather than `expired` (expiryReason()).
      grant.lastDenial = code;
      grant.decision = null;
      grant.interaction = null;
      const keepGoing = { continue: this.continueMember(req, grant) };
      store.saveGrant(grant, 'told the client: ' + code);
      log.debug("Leaving GnapGrants.settle(). " + code);
      // A decision may carry its own code (#432 phase 6: a step-up the
      // person could not meet is `request_denied`, STS-GNAP-0899).
      const decidedCode = String(lastDecision.code || '');
      return Object.assign(this.refusal(decidedCode ||
                                        (code === 'unknown_user' ?
                                        'STS-GNAP-0121' : 'STS-GNAP-0120'),
                                        code === 'unknown_user' ?
          'the person who signed in is not the user the request named (RFC ' +
                                        '9635 section 2.4).' :
          (lastDecision.why
            ? String(lastDecision.why)
            : 'the resource owner did not approve the request.'),
          code, 403), {
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
      // THE REQUEST STAGE AGAIN (#432 phase 3): a modification asks for
      // rights afresh, so each is judged as at creation.
      const judged = await this.judgeRequested(req, grant,
        app || { identifier: grant.client.identifier, fields: {} },
        asked.tokens, 'pending');
      if (!judged.ok) {
        log.debug("Leaving GnapGrants.modifyGrant(). A right was refused.");
        return judged;
      }
      asked.tokens = judged.tokens;
      grant.narrowed = judged.narrowed;
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
    // A LIMIT DROPPED OR RAISED IS NOT WITHIN THE APPROVAL (#432 phase 5),
    // though the matcher finds the right covered — `limitsRaised()` says why.
    const withinApproval = grant.state === STATE.APPROVED &&
        grant.ro !== undefined && accessRights.accessCovers(previouslyApproved,
        requested) && !asked.subject &&
        !this.deps.rights.limitsRaised(previouslyApproved, requested);
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

  /**
   * Revokes every live access token a grant issued, and its management token.
   *
   * @param grant - the grant
   * @param why - the reason recorded
   */
  revokeTokens(grant, why) {
    const { log, revocation } = this.deps;
    log.debug("Entering GnapGrants.revokeTokens().");
    // ONE WAY TO REVOKE A GRANT'S TOKENS (#432): `gnap_revocation.ts` holds
    // it, because a sign-out, a deleted client and a received signal end
    // grants there and must revoke exactly what the client's own section
    // 5.4 revocation does.
    revocation.revokeTokens(grant, why);
    log.debug("Leaving GnapGrants.revokeTokens().");
  }

  // Section 5.4.
  private revokeGrant(req, grant) {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.revokeGrant().");
    this.revokeGrantBy(grant, { by: 'client', actor: grant.client.identifier,
                                via: 'continuation', req: req });
    log.debug("Leaving GnapGrants.revokeGrant().");
    return { ok: true, status: 204, body: null };
  }

  /**
   * Says whether a grant can still be revoked: not finalized, or finalized
   * as `issued` with its tokens live (#432 phase 7).
   *
   * @param grant - the grant
   * @returns true when a revocation would change something
   */
  revocable(grant: any): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapGrants.revocable().");
    log.debug("Leaving GnapGrants.revocable().");
    return !!grant && (grant.state !== STATE.FINALIZED ||
      !!(grant.finalization && grant.finalization.reason === 'issued'));
  }

  // -------------------------------------------------------------------------
  // REVOKING A GRANT, BY WHOEVER MAY (#432 phase 7). Section 5.4's act — the
  // tokens revoked, the grant finalized as `revoked`, CAEP `session-revoked`
  // sent (`gnap_signals.ts`) — in ONE function, which the client's DELETE,
  // the console and `/admin-api` (`gnap_console.ts`) and the person's own
  // `/portal/gnap` all call, so what the client sees next is the same
  // whoever ended it. `by` is who: `client`, `administrator` or `person`
  // (the resource owner); it goes onto the history, the audit row and the
  // CAEP reason. A grant finalized for any reason but `issued` is left alone
  // and answered false — there is nothing live left to revoke.
  // -------------------------------------------------------------------------
  /**
   * Revokes a grant (section 5.4): its tokens revoked, the grant finalized as
   * `revoked`, CAEP `session-revoked` sent — the one path for the client, an
   * administrator and the resource owner.
   *
   * @param grant - the grant
   * @param context - `{ by, actor, via, req, why, initiatingEntity, action }`:
   *   `client`, `administrator`, `person` or `system` (an act from outside
   *   the protocol, `gnap_revocation.ts`, which states `why`), who acted,
   *   through which door, the request, CAEP's initiating entity and the
   *   audit action
   * @returns true when it was revoked, false when nothing live was left
   */
  revokeGrantBy(grant: any, context: any): boolean {
    const { log, audit, monitor, signals } = this.deps;
    const ctx = context || {};
    const by = String(ctx.by || 'client');
    log.debug("Entering GnapGrants.revokeGrantBy(). by=" + by);
    if (!this.revocable(grant)) {
      log.debug("Leaving GnapGrants.revokeGrantBy(). Nothing live.");
      return false;
    }
    // `system` is an act from outside the protocol (`gnap_revocation.ts`: a
    // sign-out, a deleted client, a compromised device, a received signal),
    // which states its own reason; the other three are named here.
    const who = by === 'administrator' ? 'an administrator'
      : (by === 'person' ? 'its resource owner'
        : (by === 'system' ? '' : 'the client instance'));
    const why = by === 'system' ? String(ctx.why || 'revoked')
      : 'revoked by ' + who;
    const actor = String(ctx.actor || grant.client.identifier);
    // CAEP section 2's initiating entity: the caller's where it says one,
    // `admin` for an administrator and `user` for the resource owner; the
    // client's own revocation states none, as before.
    const entity = ctx.initiatingEntity ? String(ctx.initiatingEntity)
      : (by === 'administrator' ? 'admin'
        : (by === 'person' ? 'user' : (by === 'system' ? 'system' :
                                       undefined)));
    this.revokeTokens(grant, by === 'system' ? why : 'grant ' + why);
    this.finalize(grant, why +
                  (by === 'client' || !ctx.actor ? '' : ' (' + actor + ')'),
                  'revoked', actor);
    monitor.record(grant.client.identifier, 'grant.revoked', {});
    audit.audit({ action: String(ctx.action || 'gnap.grant.revoke'),
      category: 'protocol', protocol: PROTOCOL,
      channel: ctx.via === 'portal' ? 'portal'
        : (by === 'system' ? 'internal' : 'http'),
      outcome: 'success', actor: actor,
      target: grant.client.identifier,
      summary: 'A GNAP grant was ' + why,
      detail: { grant: grant.id, by: by, via: String(ctx.via || ''),
                tokens: (grant.tokens || []).length,
                initiatingEntity: String(entity || '') } });
    try {
      signals.grantRevoked(ctx.req || null, grant,
                           'The grant was ' + why + '.', entity);
    } catch (e) {
      log.debug("Caught in GnapGrants.revokeGrantBy(): " +
                ((e && e.message) || e));
      // The revocation is done; a signal that could not be started is logged
      // by gnap_signals itself and must not undo the answer.
    }
    log.debug("Leaving GnapGrants.revokeGrantBy().");
    return true;
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
  /**
   * Handles token management (section 6): rotation or revocation, the
   * management token spent once across the cluster and given back if it is
   * still live afterwards.
   *
   * @param req - the request to the management URI
   * @param handle - the management handle
   * @returns the response to send, or a refusal
   */
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
          accessToken: presented,
          mtlsTrust: this.mtlsTrustOfIdentifier(grant ?
                                                grant.client.identifier :
                                                null) });
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
        stats.revoke(record.jti, 'GNAP token management', undefined,
                     record.exp);
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
    // POST: rotation, optionally with a new key. A token whose resource owner
    // is disabled, or whose client's entry is gone or no longer names its
    // key, is not rotated (#432) — revoking it, above, is still allowed.
    const ended = this.deps.revocation.tokenProblem(record);
    if (ended) {
      log.debug("Leaving GnapGrants.manageVerified(). " + ended.why);
      return this.refusal('STS-GNAP-0732', 'this access token cannot be ' +
                          'rotated: ' + ended.why + '.', 'invalid_rotation');
    }
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
    const rotationTrust = this.mtlsTrustOfIdentifier(
        grant ? grant.client.identifier : null);
    const verified = await proof.verifyRequestOnce(req, body, descriptor,
                                                   { accessToken: presented,
                                                     rotation: newDescriptor,
                                                     mtlsTrust:
                                                       rotationTrust });
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
    // A grant finalized as `issued` keeps its tokens, and they rotate (#432
    // phase 7); every other finalized grant's tokens are over.
    if (grant && grant.state === STATE.FINALIZED && !this.revocable(grant)) {
      log.debug("Leaving GnapGrants.manageVerified(). The grant is finalized.");
      return this.refusal('STS-GNAP-0154', 'the grant this token belongs to ' +
                          'is finalized.', 'invalid_rotation');
    }
    // THE GRANT'S OWN LIFETIME (#432 phase 7): a rotation would renew the
    // grant's access past the point its resource owner is to be asked again.
    // The token record carries it too, for a grant already pruned.
    if (this.grantLifetimeEnded(grant || record)) {
      if (grant && grant.state !== STATE.FINALIZED) {
        this.finalize(grant, 'the grant lifetime ended', 'expired');
      }
      log.debug("Leaving GnapGrants.manageVerified(). Lifetime ended.");
      return this.refusal('STS-GNAP-0791', 'the grant this token was issued ' +
          'under has reached the end of its lifetime (gnap.grantLifetimeS), ' +
          'so the token cannot be rotated; make a new grant request (RFC ' +
          '9635 section 6.1).', 'invalid_rotation');
    }
    const iat = nowSec();
    const lifetime = this.cappedLifetime(grant || record, iat,
      Math.max(1, (record.exp || iat) - (record.iat || iat)) ||
      (Number(config.value('gnap.accessTokenLifetimeS')) || 3600));
    const cnf = newDescriptor ? keys.confirmationOf(newDescriptor) : record.cnf;
    const model = { jti: store.handle(16), iss: record.iss, sub: record.sub,
                    aud: record.aud,
                    instanceId: record.instanceId, access: record.access,
                    flags: record.flags,
                    cnf: cnf, iat: iat, nbf: iat, exp: iat +
                                                       lifetime,
                    label: record.label,
                    // The actor chain survives rotation (#432): a rotated
                    // derived token that dropped it would launder a
                    // delegation into a token nobody acted for.
                    act: record.act || null,
                    // And the grant its limits are counted against (#432
                    // phase 5): a rotation that changed it would be a fresh
                    // budget for the asking.
                    grant: record.grant || record.grantId || null };
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
          manageHash: null,
          // The NEW value's (#432), never the rotated one's copied above.
          statusIdx: minted.statusIdx === undefined ? null : minted.statusIdx,
          revocationIds: minted.revocationIds || null }), minted.value);
    // Section 6.1: "the AS MUST invalidate the current access token value".
    record.revoked = true;
    record.revokedAt = iat;
    record.revokedWhy = 'rotated';
    record.rotatedTo = next.jti;
    store.moveManagement(record, next);
    store.saveToken(record);
    if (/^jwt/.test(record.format)) {
      stats.revoke(record.jti, 'GNAP rotation', undefined, record.exp);
    }
    const manageValue = store.issueManagement(next);
    store.saveToken(next);
    if (grant) {
      grant.tokens = (grant.tokens || []).concat([next.jti]);
      if (newDescriptor) {
        // Section 6.1.1: the grant's key follows the token's most recent
        // rotation. THE KEY IT CAME FROM IS KEPT (#432): the entry names the
        // key the grant began with, and a rotated grant is the same client's
        // — `gnap_revocation.ts` reads the lineage so a rotation is never
        // mistaken for the entry's key being removed.
        const before = this.deps.revocation.keyIdentityOf(grant.client.key);
        if (before) {
          grant.client.keyLineage = (grant.client.keyLineage || [])
            .concat([before]).slice(-20);
        }
        grant.client.key = newDescriptor.value;
        grant.client.keyIdentity = newDescriptor.identity;
        grant.client.certSpki = newDescriptor.proof &&
          newDescriptor.proof.method === 'mtls'
          ? this.deps.mtls.presentedKeyThumbprint(req) : '';
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

  // -------------------------------------------------------------------------
  // THE EXPIRY JOB (#432 phase 7). A grant past its interaction or its grant
  // lifetime is refused by the next request that touches it, which finalizes
  // it then (continueAccepted(), manageVerified()); this records the end of
  // one NOBODY touches, so the console, the portal and the audit log say
  // `expired` (or `rejected`) about it rather than showing it approved or
  // pending for ever. A cluster job per realm (#49: anything periodic is a
  // scheduler job); the opportunistic prune in `gnap_store.ts` still deletes
  // the rows later, as it did.
  // -------------------------------------------------------------------------
  /**
   * Finalizes every grant in the ambient realm past its interaction or its
   * grant lifetime, recording why. The `gnap.grant-expiry` job's body.
   *
   * @returns `{ summary }` for the scheduler
   */
  expireGrants(): any {
    const { log, store } = this.deps;
    log.debug("Entering GnapGrants.expireGrants().");
    let ended = 0;
    store.listGrants().forEach((grant) => {
      if (grant.state === STATE.FINALIZED) {
        return;
      }
      if (this.expired(grant)) {
        this.finalize(grant, 'the interaction expired',
                      this.expiryReason(grant), 'scheduler');
        ended += 1;
      } else if (this.grantLifetimeEnded(grant)) {
        this.finalize(grant, 'the grant lifetime ended', 'expired',
                      'scheduler');
        ended += 1;
      }
    });
    log.debug("Leaving GnapGrants.expireGrants(). " + ended + ".");
    return { summary: ended + ' GNAP grant(s) finalized as expired' };
  }

  /**
   * Registers the expiry job on the scheduler, once.
   */
  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering GnapGrants.scheduleJobs().");
    const s = scheduler();
    if (s.job(EXPIRY_JOB)) {
      log.debug("Leaving GnapGrants.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: EXPIRY_JOB,
      title: 'GNAP: expired grants',
      describe: 'Finalizes each GNAP grant whose interaction or grant ' +
                'lifetime (gnap.grantLifetimeS) has ended and that no ' +
                'request has touched since, recording why (#432).',
      owner: 'gnap/gnap_grants.ts',
      kind: 'cluster', scope: 'realm', everyMs: function (): number {
        return 300000;
      },
      manual: true,
      run: function (): any {
        return self.expireGrants();
      }
    });
    log.debug("Leaving GnapGrants.scheduleJobs(). On the scheduler.");
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  /**
   * Returns the real modules the instance was built from before the composition
   * root (#50, R2) passed them.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapGrantsDeps {
    helpers.log.debug("Entering GnapGrants.defaultDeps().");
    helpers.log.debug("Leaving GnapGrants.defaultDeps().");
    return {
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
      revocation: revocation,
      scopePolicy: scopePolicy,
      mtls: mtls,
      delegation: gnapDelegation,
      rights: gnapRights,
      ownership: ownership,
      approval: gnapApproval,
      loadOauth2: function loadOauth2() {
        helpers.log.debug("Entering loadOauth2().");
        helpers.log.debug("Leaving loadOauth2().");
        return require('../oauth-oidc/oauth2');
      },
      scheduler: function scheduler() {
        helpers.log.debug("Entering scheduler().");
        helpers.log.debug("Leaving scheduler().");
        return require('../cluster/scheduler');
      }
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapGrants>(
  'gnap/gnap_grants',
  () => new GnapGrants(GnapGrants.defaultDeps()),
  // The wire step registers the expiry job (#432 phase 7), as
  // `pairwise_subjects.ts`'s registers its purge.
  function (instance: GnapGrants): void {
    instance.scheduleJobs();
  },
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The GNAP grant engine: every decision the authorization server makes, in one
 * route-free library.
 *
 * @namespace
 */
export = {
  GnapGrants: GnapGrants,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapGrants): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  PROTOCOL: GnapGrants.PROTOCOL,
  KIND_CLIENT: GnapGrants.KIND_CLIENT,
  KIND_RS: GnapGrants.KIND_RS,
  GNAP_MEMBERS: GnapGrants.GNAP_MEMBERS,
  RESERVED_AS_NAMES: GnapGrants.RESERVED_AS_NAMES,
  FINALIZATION_REASONS: GnapGrants.FINALIZATION_REASONS,
  SUBJECT_AUTHORIZATIONS: GnapGrants.SUBJECT_AUTHORIZATIONS,
  EXPIRY_JOB: GnapGrants.EXPIRY_JOB,
  capabilities: slot.forward('capabilities'),
  capabilityList: slot.forward('capabilityList'),
  defaultCapabilities: slot.forward('defaultCapabilities'),
  grantEndpointOf: slot.forward('grantEndpointOf'),
  realmBase: slot.forward('realmBase'),
  gnapApplications: slot.forward('gnapApplications'),
  field: slot.forward('field'),
  fieldValues: slot.forward('fieldValues'),
  resolveKeyReference: slot.forward('resolveKeyReference'),
  identifyCaller: slot.forward('identifyCaller'),
  createGrant: slot.forward('createGrant'),
  continueGrant: slot.forward('continueGrant'),
  manageToken: slot.forward('manageToken'),
  decide: slot.forward('decide'),
  approverRefusal: slot.forward('approverRefusal'),
  rememberedFor: slot.forward('rememberedFor'),
  forwardToOwner: slot.forward('forwardToOwner'),
  refuseUnmetStepUp: slot.forward('refuseUnmetStepUp'),
  decideAsOwner: slot.forward('decideAsOwner'),
  finishInteraction: slot.forward('finishInteraction'),
  interactionHash: slot.forward('interactionHash'),
  normaliseUserCode: slot.forward('normaliseUserCode'),
  digestTokenOf: slot.forward('digestTokenOf'),
  canonicalJson: slot.forward('canonicalJson'),
  resourceServersFor: slot.forward('resourceServersFor'),
  revokeTokens: slot.forward('revokeTokens'),
  revokeGrantBy: slot.forward('revokeGrantBy'),
  revocable: slot.forward('revocable'),
  finalize: slot.forward('finalize'),
  grantLifetimeEnded: slot.forward('grantLifetimeEnded'),
  grantExpiryFrom: slot.forward('grantExpiryFrom'),
  expireGrants: slot.forward('expireGrants')
};
