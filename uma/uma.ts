// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma.ts
//
// ===========================================================================
// USER-MANAGED ACCESS 2.0 (#1168): THE ROUTES.
//
//   POST   /uma/rreg              register a resource (Federated
//   GET    /uma/rreg              Authorization section 3): create, list,
//   GET    /uma/rreg/:id          read, update, delete — #1191
//   PUT    /uma/rreg/:id
//   DELETE /uma/rreg/:id
//   POST   /uma/perm              the permission endpoint (section 4) — #1191
//   GET    /.well-known/uma2-configuration[/realm/<id>]
//                                 discovery (the Grant specification's
//                                 section 2) — #1191
//   GET    /uma                   the description page (#584's shell)
//
// per realm, under the realm's prefix. Deliberately thin, as `authzen.ts`
// is: the PAT door is `uma_pat.ts`, the state is `uma_store.ts`, and the
// decisions — once phase 4 asks any — are the PDP's. **WELL-FORMEDNESS IS
// NOT POLICY** (3bz's line): an unregistered resource is
// `invalid_resource_id` and an unregistered scope `invalid_scope` before any
// question is asked, and nothing here asks one.
//
// **THE ROUTES STAY REGISTERED AND ANSWER 501 while `uma.enabled` is off**
// (or the realm has no `sts-uma-protection-api` object), as XACML's and
// AuthZEN's do: the feature being off and the URL being wrong are different
// sentences. The discovery document is 501 too: a document advertising
// endpoints that do not answer would be a lie.
//
// **NOTHING UNIMPLEMENTED IS ADVERTISED.** `capabilities()` says what the
// later phases have filled: the `uma-ticket` grant (phase 4) and the claims
// interaction endpoint (phase 5) appear in the discovery document only once
// they answer.
//
// THE PROTECTION API'S ERRORS are Federated Authorization's: `{ error,
// error_description }` with `invalid_request`, `not_found`,
// `unsupported_method_type`, `invalid_resource_id` and `invalid_scope`.
//
// A REGISTRATION'S REMOVAL REACHES THE TOKENS THAT CARRIED IT (decision 11):
// deleting a resource, or narrowing its scopes, revokes every RPT recorded
// with a permission over it (`uma_store.ts`'s index) through
// `admin_stats.revoke()`, so introspection answers inactive. Before phase 4
// issues any RPT there is nothing to find, and the hook already holds.
//
// TYPESCRIPT, AS A CLASS (#50): `UmaSurface` takes what it uses through its
// constructor; `registerRoutes(app)` holds every route, and
// `common/protocol_stack.ts` calls it at 23d-ii. Its wire step registers the
// `uma.sweep` scheduler job.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import audit = require('../common/audit');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import applications = require('../common/applications');
import DescriptionPages = require('../common/description_pages');
import umaStore = require('./uma_store');
import umaPat = require('./uma_pat');

const { log } = helpers;

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;
type Handler = (req: Req, res: Res, next?: () => void) => unknown;

interface RouteTable {
  get(path: string, ...handlers: Handler[]): unknown;
  post(path: string, ...handlers: Handler[]): unknown;
  put(path: string, ...handlers: Handler[]): unknown;
  delete(path: string, ...handlers: Handler[]): unknown;
  all(path: string, ...handlers: Handler[]): unknown;
}

// The protection API's resource object, whose absence turns the API off.
const API_OBJECT = 'sts-uma-protection-api';

// The paths.
const BASE_PATH = '/uma';
const RREG_PATH = '/uma/rreg';
const PERM_PATH = '/uma/perm';
const CLAIMS_PATH = '/uma/claims';
const METADATA_PATH = '/.well-known/uma2-configuration';

// The UMA grant, as the token endpoint will name it (phase 4).
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:uma-ticket';

// The members of a resource description (Federated Authorization 3.1).
// Anything else a resource server sends is not stored: the specification
// lets an authorization server define extensions, this one defines none,
// and a member nobody reads is a member nobody bounded.
const DESCRIPTION_MEMBERS = Object.freeze(['resource_scopes', 'description',
                                           'icon_uri', 'name', 'type']);

// Bounds on what one request may carry, beside the settings.
const MAX_SCOPE_LENGTH = 256;
const MAX_NAME_LENGTH = 512;
const MAX_TYPE_LENGTH = 512;
const MAX_DESCRIPTION_LENGTH = 4096;
const MAX_ICON_URI_LENGTH = 2048;
const MAX_PERMISSIONS = 100;

// A printable string with no control character.
const PRINTABLE = /^[^\x00-\x1f\x7f]+$/;

// The sweep's id and how often it runs.
const JOB = 'uma.sweep';
const JOB_EVERY_MS = 10 * 60 * 1000;

interface Capabilities {
  // The `uma-ticket` grant is performed at the token endpoint (phase 4).
  grant: boolean;
  // The claims interaction endpoint answers (phase 5).
  claims: boolean;
}

interface SurfaceDeps {
  log: typeof log;
  helpers: typeof helpers;
  config: typeof config;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  applications: Json;
  store: Json;
  pat: Json;
  // What the later phases have filled; nothing in phase 2.
  capabilities(): Capabilities;
  loadOauth2(): Json;
  loadStats(): Json;
  loadScheduler(): Json;
}

/**
 * The UMA 2.0 protection API, discovery and description page.
 */
class UmaSurface {
  /**
   * Builds the surface over its dependencies.
   *
   * @param deps - the logger, helpers, settings, audit log, error codes,
   *   realms, the registry, the store, the PAT door, the capabilities and
   *   the lazy loaders
   */
  constructor(private readonly deps: SurfaceDeps) {
    deps.log.debug("Entering UmaSurface.constructor().");
    deps.log.debug("Leaving UmaSurface.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SurfaceDeps {
    log.debug("Entering UmaSurface.defaultDeps().");
    log.debug("Leaving UmaSurface.defaultDeps().");
    return {
      log: log,
      helpers: helpers,
      config: config,
      audit: audit,
      errorCodes: errorCodes,
      realms: realms,
      applications: applications,
      store: umaStore,
      pat: umaPat,
      capabilities: function (): Capabilities {
        return { grant: false, claims: false };
      },
      loadOauth2: function (): Json {
        log.debug("Entering loadOauth2().");
        log.debug("Leaving loadOauth2().");
        return require('../oauth-oidc/oauth2');
      },
      loadStats: function (): Json {
        log.debug("Entering loadStats().");
        log.debug("Leaving loadStats().");
        return require('../common/admin_stats');
      },
      loadScheduler: function (): Json {
        log.debug("Entering loadScheduler().");
        log.debug("Leaving loadScheduler().");
        return require('../cluster/scheduler');
      }
    };
  }

  /**
   * Whether UMA answers in this realm: `uma.enabled`.
   *
   * @returns true when on
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering UmaSurface.enabled().");
    log.debug("Leaving UmaSurface.enabled().");
    return config.value('uma.enabled') === true;
  }

  /**
   * The realm's protection API object, or null when an operator removed it.
   *
   * @returns the registry's view of `sts-uma-protection-api`, or null
   */
  apiObject(): Json {
    const { log, applications } = this.deps;
    log.debug("Entering UmaSurface.apiObject().");
    let found: Json = null;
    try {
      found = applications.get(API_OBJECT);
    } catch (e) {
      log.debug("Caught in UmaSurface.apiObject(): " +
                ((e && e.message) || e));
      found = null;
    }
    log.debug("Leaving UmaSurface.apiObject(). " + !!found);
    return found;
  }

  /**
   * Sends a protection API error: `{ error, error_description }`, marked
   * with its code.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param code - the STS-UMA code
   * @param error - the protocol's error
   * @param description - why
   */
  // error-code: none — the caller's code is marked on the first line.
  fail(res: Res, status: number, code: string, error: string,
       description: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering UmaSurface.fail(). " + code);
    errorCodes.mark(res, code);
    const body: Json = {};
    if (error) {
      body.error = error;
    }
    body.error_description = description;
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store').send(JSON.stringify(body));
    log.debug("Leaving UmaSurface.fail().");
  }

  // 501 while the API is off; true when the response was written.
  private offCheck(res: Res): boolean {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering UmaSurface.offCheck().");
    if (!self.enabled()) {
      self.fail(res, 501, 'STS-UMA-0108', '', 'User-Managed Access is ' +
                'turned off in this realm (uma.enabled).');
      log.debug("Leaving UmaSurface.offCheck(). Off.");
      return true;
    }
    if (!self.apiObject()) {
      self.fail(res, 501, 'STS-UMA-0109', '', 'This realm has no ' +
                API_OBJECT + ' application, the UMA protection API\'s ' +
                'resource object, so the API is off here.');
      log.debug("Leaving UmaSurface.offCheck(). No object.");
      return true;
    }
    log.debug("Leaving UmaSurface.offCheck(). On.");
    return false;
  }

  /**
   * Parses a request body as JSON.
   *
   * @param req - the request
   * @returns the parsed value, or undefined when it does not parse
   */
  static bodyOf(req: Req): unknown {
    log.debug("Entering UmaSurface.bodyOf().");
    const raw = typeof req.body === 'string' ? req.body
      : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
    try {
      log.debug("Leaving UmaSurface.bodyOf().");
      return JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in UmaSurface.bodyOf(): " + ((e && e.message) || e));
      log.debug("Leaving UmaSurface.bodyOf(). Not JSON.");
      return undefined;
    }
  }

  // -------------------------------------------------------------------------
  // THE RESOURCE DESCRIPTION, read and bounded.
  // -------------------------------------------------------------------------
  /**
   * Reads a resource description: the members it may carry, each bounded.
   *
   * @param body - the parsed body
   * @returns `{ description }`, or `{ code, why }`
   */
  readDescription(body: unknown): Json {
    const { log, config } = this.deps;
    log.debug("Entering UmaSurface.readDescription().");
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      log.debug("Leaving UmaSurface.readDescription(). Not an object.");
      return { code: 'STS-UMA-0110',
               why: 'A resource description is a JSON object.' };
    }
    const given: Json = body;
    const scopes = given.resource_scopes;
    if (!Array.isArray(scopes) || !scopes.length) {
      log.debug("Leaving UmaSurface.readDescription(). No scopes.");
      return { code: 'STS-UMA-0111', why: 'resource_scopes is required: ' +
               'a non-empty array of scope strings.' };
    }
    const bad = scopes.filter(function (one: unknown) {
      return typeof one !== 'string' || !one.length ||
             one.length > MAX_SCOPE_LENGTH || !PRINTABLE.test(one);
    });
    if (bad.length) {
      log.debug("Leaving UmaSurface.readDescription(). A bad scope.");
      return { code: 'STS-UMA-0111', why: 'Every member of resource_scopes ' +
               'is a printable string of at most ' + MAX_SCOPE_LENGTH +
               ' characters.' };
    }
    const unique: string[] = [];
    scopes.forEach(function (one: string) {
      if (unique.indexOf(one) < 0) {
        unique.push(one);
      }
    });
    const most = Number(config.value('uma.maxResourceScopes'));
    if (unique.length > most) {
      log.debug("Leaving UmaSurface.readDescription(). Too many scopes.");
      return { code: 'STS-UMA-0112', why: 'resource_scopes carries ' +
               unique.length + ' scopes, and this realm takes at most ' +
               most + ' (uma.maxResourceScopes).' };
    }
    const out: Json = { resource_scopes: unique };
    const limits: Json = { name: MAX_NAME_LENGTH, type: MAX_TYPE_LENGTH,
                           description: MAX_DESCRIPTION_LENGTH,
                           icon_uri: MAX_ICON_URI_LENGTH };
    let problem = '';
    ['name', 'type', 'description', 'icon_uri'].forEach(function (key) {
      if (problem || given[key] === undefined || given[key] === null) {
        return;
      }
      const value = given[key];
      if (typeof value !== 'string' || value.length > limits[key] ||
          (value.length && !PRINTABLE.test(value.replace(/[\r\n\t]/g, ' ')))) {
        problem = key + ' is a printable string of at most ' + limits[key] +
                  ' characters.';
        return;
      }
      if (key === 'icon_uri' && value) {
        let parsed: URL | null = null;
        try {
          parsed = new URL(value);
        } catch (e) {
          log.debug("Caught in UmaSurface.readDescription(): " +
                    ((e && e.message) || e));
          parsed = null;
        }
        if (!parsed || parsed.protocol !== 'https:' || parsed.username ||
            parsed.password) {
          problem = 'icon_uri is an https URL with no user information.';
          return;
        }
      }
      if (value.length) {
        out[key] = value;
      }
    });
    if (problem) {
      log.debug("Leaving UmaSurface.readDescription(). " + problem);
      return { code: 'STS-UMA-0113', why: problem };
    }
    log.debug("Leaving UmaSurface.readDescription().");
    return { description: out };
  }

  /**
   * The resource description as the protection API answers it.
   *
   * @param row - the stored resource
   * @returns the description, with `_id`
   */
  static describe(row: Json): Json {
    log.debug("Entering UmaSurface.describe().");
    const out: Json = { _id: row._id,
                        resource_scopes: (row.resource_scopes || []).slice() };
    ['name', 'type', 'description', 'icon_uri'].forEach(function (key) {
      if (row[key]) {
        out[key] = row[key];
      }
    });
    log.debug("Leaving UmaSurface.describe().");
    return out;
  }

  /**
   * Where a resource owner manages who may reach a resource: the portal's
   * Sharing page for a person, the console's UMA page for an application.
   *
   * @param req - the request
   * @param caller - the PAT's caller
   * @param id - the resource's `_id`
   * @returns the URL
   */
  policyUriOf(req: Req, caller: Json, id: string): string {
    const { log, helpers, realms } = this.deps;
    log.debug("Entering UmaSurface.policyUriOf().");
    const prefix = String(realms.currentPrefix() || '');
    const out = caller.ownerKind === 'application'
      ? String(helpers.baseUrlOf(req, 'admin') || '') + prefix +
        '/admin/uma?owner=' + encodeURIComponent(caller.owner)
      : String(helpers.baseUrlOf(req, 'portal') || '') + prefix +
        '/portal/shared?resource=' + encodeURIComponent(id);
    log.debug("Leaving UmaSurface.policyUriOf().");
    return out;
  }

  // The resource this caller registered, or null: another owner's or
  // another resource server's is nobody's here.
  private ownResource(caller: Json, id: string): Json {
    const { log, store } = this.deps;
    log.debug("Entering UmaSurface.ownResource().");
    const row = store.resource(String(id || ''));
    const ours = row && String(row.owner) === String(caller.owner) &&
      String(row.resourceServer) === String(caller.resourceServer);
    log.debug("Leaving UmaSurface.ownResource(). " + !!ours);
    return ours ? row : null;
  }

  // One audit row of the protection API: ids only, never a resource's
  // name or description (the owner's data).
  private record(action: string, caller: Json, id: string,
                 detail: string, code?: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering UmaSurface.record(). " + action);
    audit.audit({
      action: action,
      actor: String(caller.clientId || ''),
      target: String(id || ''),
      protocol: 'UMA 2.0',
      errorCode: code || undefined,
      summary: detail,
      detail: { resourceServer: String(caller.resourceServer || ''),
                owner: String(caller.owner || ''),
                ownerKind: String(caller.ownerKind || ''),
                resource: String(id || '') }
    });
    log.debug("Leaving UmaSurface.record().");
  }

  /**
   * Revokes every RPT carrying a permission over a resource — all of its
   * scopes, or only those given — and forgets their records (decision 11).
   *
   * @param resourceId - the resource's `_id`
   * @param scopes - the scopes withdrawn, or null for all
   * @param via - what withdrew them, for the revocation record
   * @returns how many tokens were revoked
   */
  revokeFor(resourceId: string, scopes: string[] | null, via: string):
      number {
    const { log, store } = this.deps;
    log.debug("Entering UmaSurface.revokeFor(). " + resourceId);
    const stats = this.deps.loadStats();
    let revoked = 0;
    store.rptsBy('resource', resourceId).forEach(function (row: Json) {
      const affected = (row.permissions || []).some(function (p: Json) {
        return String(p.resource_id) === String(resourceId) &&
          (!scopes || (p.resource_scopes || []).some(function (s: string) {
            return scopes.indexOf(s) >= 0;
          }));
      });
      if (!affected) {
        return;
      }
      if (stats.revoke(String(row.jti), via, { uma: true },
                       Number(row.exp) || 0)) {
        revoked += 1;
      }
      store.deleteRpt(String(row.jti));
    });
    log.debug("Leaving UmaSurface.revokeFor(). " + revoked);
    return revoked;
  }

  // -------------------------------------------------------------------------
  // THE PERMISSION REQUEST, read and checked against the registrations.
  // -------------------------------------------------------------------------
  /**
   * Reads a permission request: one object or an array of
   * `{ resource_id, resource_scopes }`, each resource registered by this
   * caller and each scope one it was registered with.
   *
   * @param body - the parsed body
   * @param caller - the PAT's caller
   * @returns `{ permissions }`, or `{ status, code, error, why }`
   */
  readPermissions(body: unknown, caller: Json): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering UmaSurface.readPermissions().");
    const items = Array.isArray(body) ? body : [body];
    const malformed = function (why: string): Json {
      log.debug("Entering malformed().");
      log.debug("Leaving malformed().");
      return { status: 400, code: 'STS-UMA-0117', error: 'invalid_request',
               why: why };
    };
    if (body === undefined || body === null || !items.length) {
      log.debug("Leaving UmaSurface.readPermissions(). Empty.");
      return malformed('A permission request is an object, or a non-empty ' +
                       'array of objects, each with resource_id and ' +
                       'resource_scopes.');
    }
    if (items.length > MAX_PERMISSIONS) {
      log.debug("Leaving UmaSurface.readPermissions(). Too many.");
      return malformed('A permission request carries at most ' +
                       MAX_PERMISSIONS + ' permissions.');
    }
    const out: Json[] = [];
    for (let i = 0; i < items.length; i += 1) {
      const one: Json = items[i];
      if (!one || typeof one !== 'object' || Array.isArray(one) ||
          typeof one.resource_id !== 'string' || !one.resource_id ||
          !Array.isArray(one.resource_scopes) ||
          !one.resource_scopes.length ||
          one.resource_scopes.some(function (s: unknown) {
            return typeof s !== 'string' || !s;
          })) {
        log.debug("Leaving UmaSurface.readPermissions(). Malformed item.");
        return malformed('Every permission is an object with resource_id ' +
                         '(a string) and resource_scopes (a non-empty ' +
                         'array of strings).');
      }
      const row = self.ownResource(caller, one.resource_id);
      if (!row) {
        log.debug("Leaving UmaSurface.readPermissions(). Unknown resource.");
        return { status: 400, code: 'STS-UMA-0118',
                 error: 'invalid_resource_id',
                 why: 'At least one resource_id is not one this resource ' +
                      'server registered for this resource owner.' };
      }
      const registered: string[] = row.resource_scopes || [];
      const stray = one.resource_scopes.filter(function (s: string) {
        return registered.indexOf(s) < 0;
      });
      if (stray.length) {
        log.debug("Leaving UmaSurface.readPermissions(). Unknown scope.");
        return { status: 400, code: 'STS-UMA-0119', error: 'invalid_scope',
                 why: 'At least one scope is not one the resource "' +
                      row._id + '" was registered with.' };
      }
      const scopes: string[] = [];
      one.resource_scopes.forEach(function (s: string) {
        if (scopes.indexOf(s) < 0) {
          scopes.push(s);
        }
      });
      const kept = out.filter(function (p: Json) {
        return p.resource_id === row._id;
      })[0];
      if (kept) {
        scopes.forEach(function (s: string) {
          if (kept.resource_scopes.indexOf(s) < 0) {
            kept.resource_scopes.push(s);
          }
        });
      } else {
        out.push({ resource_id: String(row._id), resource_scopes: scopes });
      }
    }
    log.debug("Leaving UmaSurface.readPermissions(). " + out.length);
    return { permissions: out };
  }

  // -------------------------------------------------------------------------
  // DISCOVERY.
  // -------------------------------------------------------------------------
  /**
   * The `uma2-configuration` document: the realm's RFC 8414 metadata and
   * the UMA members, advertising only what answers.
   *
   * @param req - the request
   * @returns the document
   */
  metadata(req: Req): Json {
    const self = this;
    const { log, helpers } = this.deps;
    log.debug("Entering UmaSurface.metadata().");
    const oauth = self.deps.loadOauth2();
    const out: Json = Object.assign({}, oauth.asMetadata(req) || {});
    // The signed form describes the OAuth document it was signed from; it
    // is not re-signed here, so it is not carried.
    delete out.signed_metadata;
    const base = String(helpers.baseUrlOf(req, 'uma') || '');
    out.permission_endpoint = base + PERM_PATH;
    out.resource_registration_endpoint = base + RREG_PATH;
    out.uma_profiles_supported = [];
    const can = self.deps.capabilities();
    if (can.claims) {
      out.claims_interaction_endpoint = base + CLAIMS_PATH;
    }
    const grants = Array.isArray(out.grant_types_supported)
      ? out.grant_types_supported.filter(function (one: string) {
          return one !== GRANT_TYPE;
        }) : [];
    if (can.grant) {
      grants.push(GRANT_TYPE);
    }
    out.grant_types_supported = grants;
    log.debug("Leaving UmaSurface.metadata().");
    return out;
  }

  // Answers the document in the realm the request is in, or 501 while off.
  private sendMetadata(req: Req, res: Res): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering UmaSurface.sendMetadata().");
    if (self.offCheck(res)) {
      log.debug("Leaving UmaSurface.sendMetadata(). Off.");
      return;
    }
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(self.metadata(req), null, 2));
    log.debug("Leaving UmaSurface.sendMetadata().");
  }

  // -------------------------------------------------------------------------
  // THE DESCRIPTION PAGE'S DOCUMENT.
  // -------------------------------------------------------------------------
  /**
   * What `/uma` says: on or off, the endpoints, the resource servers
   * declared in this realm, and what is built.
   *
   * @param req - the request
   * @returns the document
   */
  description(req: Req): Json {
    const self = this;
    const { log, helpers, applications } = this.deps;
    log.debug("Entering UmaSurface.description().");
    const base = String(helpers.baseUrlOf(req, 'uma') || '');
    let servers: string[] = [];
    try {
      servers = applications.applicationsDeclaredFor('uma');
    } catch (e) {
      log.debug("Caught in UmaSurface.description(): " +
                ((e && e.message) || e));
      servers = [];
    }
    const can = self.deps.capabilities();
    const out = {
      enabled: self.enabled(),
      apiObject: !!self.apiObject(),
      endpoints: {
        resourceRegistration: base + RREG_PATH,
        permission: base + PERM_PATH,
        discovery: base + METADATA_PATH,
        claimsInteraction: can.claims ? base + CLAIMS_PATH : ''
      },
      grantPerformed: can.grant,
      resourceServers: servers,
      scope: umaPat.SCOPE
    };
    log.debug("Leaving UmaSurface.description().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE SWEEP, a scheduler job (rcbj's directive): expired tickets, PCTs,
  // RPT records and pending approvals. A read applies every deadline
  // itself, so this is housekeeping and never what decides.
  // -------------------------------------------------------------------------
  /**
   * Registers the `uma.sweep` job with the scheduler, once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const self = this;
    const { log, config, errorCodes, store } = this.deps;
    log.debug("Entering UmaSurface.registerJobs().");
    const s = self.deps.loadScheduler();
    if (s.job(JOB)) {
      log.debug("Leaving UmaSurface.registerJobs(). Already there.");
      return false;
    }
    s.register({
      id: JOB,
      title: 'UMA expiry',
      describe: 'Removes every User-Managed Access permission ticket, ' +
                'persisted claims token, RPT record and pending owner ' +
                'approval past its life (#1168). A read applies the ' +
                'deadline itself, so this is the clean-up, never what ' +
                'decides.',
      owner: 'uma/uma.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return JOB_EVERY_MS;
      },
      off: function (): string {
        return config.value('uma.enabled') === true ? ''
          : 'uma.enabled is off in this realm.';
      },
      manual: true,
      timeoutS: 300,
      run: function (): Promise<Json> {
        return Promise.resolve().then(function () {
          try {
            const swept = store.sweep();
            const total = swept.tickets + swept.pcts + swept.pending +
                          swept.rpts;
            return { summary: total ? total + ' expired UMA row(s) ' +
                                      'removed.' : '' };
          } catch (e) {
            log.error(errorCodes.tag('STS-UMA-0004') + 'uma: the sweep ' +
                      'failed: ' + ((e && e.message) || e));
            throw e;
          }
        });
      }
    });
    log.debug("Leaving UmaSurface.registerJobs().");
    return true;
  }

  // -------------------------------------------------------------------------
  // THE ROUTES.
  // -------------------------------------------------------------------------
  // The door every protection API route passes: on, and a PAT.
  private admit(req: Req, res: Res): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering UmaSurface.admit().");
    if (self.offCheck(res)) {
      log.debug("Leaving UmaSurface.admit(). Off.");
      return null;
    }
    const caller = self.deps.pat.authenticate(req, res);
    log.debug("Leaving UmaSurface.admit(). " + (caller ? 'In.' : 'Refused.'));
    return caller;
  }

  // 405 for a method an endpoint does not take.
  private unsupported(res: Res, what: string): void {
    const { log } = this.deps;
    log.debug("Entering UmaSurface.unsupported().");
    this.fail(res, 405, 'STS-UMA-0115', 'unsupported_method_type',
              what + ' does not take this method.');
    log.debug("Leaving UmaSurface.unsupported().");
  }

  /**
   * Registers the routes on the shared app.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, store, config } = this.deps;
    log.debug("Entering UmaSurface.registerRoutes().");

    // ---------------------------------------------------------------------
    // POST /uma/rreg — register a resource (section 3.2.1).
    // ---------------------------------------------------------------------
    app.post(RREG_PATH, function (req, res) {
      log.debug('Entering POST ' + RREG_PATH + '.');
      const caller = self.admit(req, res);
      if (!caller) {
        log.debug('Leaving POST ' + RREG_PATH + '. Not admitted.');
        return;
      }
      const read = self.readDescription(UmaSurface.bodyOf(req));
      if (read.code) {
        // error-code: none — readDescription()'s code, STS-UMA-0110..0113.
        self.fail(res, 400, read.code, 'invalid_request', read.why);
        log.debug('Leaving POST ' + RREG_PATH + '. ' + read.code);
        return;
      }
      const most = Number(config.value('uma.maxResourcesPerOwner'));
      if (store.resourcesOf(caller.owner).length >= most) {
        self.fail(res, 400, 'STS-UMA-0116', 'invalid_request',
                  'This resource owner already has ' + most + ' resources ' +
                  'registered, the most this realm takes ' +
                  '(uma.maxResourcesPerOwner).');
        log.debug('Leaving POST ' + RREG_PATH + '. Too many.');
        return;
      }
      const row = store.saveResource(Object.assign({}, read.description, {
        resourceServer: caller.resourceServer, owner: caller.owner,
        ownerKind: caller.ownerKind, clientId: caller.clientId }));
      self.record('uma.resource.register', caller, row._id,
                  'Resource server "' + caller.resourceServer + '" ' +
                  'registered the resource ' + row._id + ' with ' +
                  row.resource_scopes.length + ' scope(s).');
      const base = String(self.deps.helpers.baseUrlOf(req, 'uma') || '');
      res.status(201).type('application/json')
         .set('Cache-Control', 'no-store')
         .set('Location', base + RREG_PATH + '/' + row._id)
         .send(JSON.stringify({ _id: row._id,
           user_access_policy_uri: self.policyUriOf(req, caller, row._id) }));
      log.debug('Leaving POST ' + RREG_PATH + '. ' + row._id);
    });

    // ---------------------------------------------------------------------
    // GET /uma/rreg — this caller's resources (section 3.2.5).
    // ---------------------------------------------------------------------
    app.get(RREG_PATH, function (req, res) {
      log.debug('Entering GET ' + RREG_PATH + '.');
      const caller = self.admit(req, res);
      if (!caller) {
        log.debug('Leaving GET ' + RREG_PATH + '. Not admitted.');
        return;
      }
      const ids = store.resourcesOf(caller.owner).filter(function (row: Json) {
        return String(row.resourceServer) === String(caller.resourceServer);
      }).map(function (row: Json) {
        return String(row._id);
      });
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store').send(JSON.stringify(ids));
      log.debug('Leaving GET ' + RREG_PATH + '. ' + ids.length);
    });
    app.all(RREG_PATH, function (req, res) {
      log.debug('Entering ' + req.method + ' ' + RREG_PATH + '.');
      if (!self.offCheck(res)) {
        self.unsupported(res, RREG_PATH);
      }
      log.debug('Leaving ' + req.method + ' ' + RREG_PATH + '.');
    });

    // ---------------------------------------------------------------------
    // GET, PUT, DELETE /uma/rreg/:id (sections 3.2.2–3.2.4).
    // ---------------------------------------------------------------------
    const PATH_ID = RREG_PATH + '/:id';
    const located = function (req: Req, res: Res): Json {
      log.debug("Entering located().");
      const caller = self.admit(req, res);
      if (!caller) {
        log.debug("Leaving located(). Not admitted.");
        return null;
      }
      const row = self.ownResource(caller, String(req.params.id || ''));
      if (!row) {
        self.fail(res, 404, 'STS-UMA-0114', 'not_found', 'There is no ' +
                  'resource of that _id registered by this resource server ' +
                  'for this resource owner.');
        log.debug("Leaving located(). Not found.");
        return null;
      }
      log.debug("Leaving located().");
      return { caller: caller, row: row };
    };
    app.get(PATH_ID, function (req, res) {
      log.debug('Entering GET ' + PATH_ID + '.');
      const found = located(req, res);
      if (!found) {
        log.debug('Leaving GET ' + PATH_ID + '. Refused.');
        return;
      }
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(UmaSurface.describe(found.row)));
      log.debug('Leaving GET ' + PATH_ID + '.');
    });
    app.put(PATH_ID, function (req, res) {
      log.debug('Entering PUT ' + PATH_ID + '.');
      const found = located(req, res);
      if (!found) {
        log.debug('Leaving PUT ' + PATH_ID + '. Refused.');
        return;
      }
      const read = self.readDescription(UmaSurface.bodyOf(req));
      if (read.code) {
        // error-code: none — readDescription()'s code, STS-UMA-0110..0113.
        self.fail(res, 400, read.code, 'invalid_request', read.why);
        log.debug('Leaving PUT ' + PATH_ID + '. ' + read.code);
        return;
      }
      const before: string[] = found.row.resource_scopes || [];
      const kept: Json = { _id: found.row._id,
                           createdAt: found.row.createdAt,
                           resourceServer: found.row.resourceServer,
                           owner: found.row.owner,
                           ownerKind: found.row.ownerKind,
                           clientId: found.row.clientId };
      const row = store.saveResource(Object.assign(kept, read.description));
      const withdrawn = before.filter(function (s: string) {
        return row.resource_scopes.indexOf(s) < 0;
      });
      const revoked = withdrawn.length
        ? self.revokeFor(row._id, withdrawn, 'a UMA resource update') : 0;
      self.record('uma.resource.update', found.caller, row._id,
                  'Resource server "' + found.caller.resourceServer + '" ' +
                  'updated the resource ' + row._id + (withdrawn.length
                    ? '; ' + withdrawn.length + ' scope(s) withdrawn, ' +
                      revoked + ' RPT(s) revoked' : '') + '.');
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({ _id: row._id }));
      log.debug('Leaving PUT ' + PATH_ID + '.');
    });
    app.delete(PATH_ID, function (req, res) {
      log.debug('Entering DELETE ' + PATH_ID + '.');
      const found = located(req, res);
      if (!found) {
        log.debug('Leaving DELETE ' + PATH_ID + '. Refused.');
        return;
      }
      store.deleteResource(found.row._id);
      const revoked = self.revokeFor(found.row._id, null,
                                     'a UMA resource deletion');
      self.record('uma.resource.delete', found.caller, found.row._id,
                  'Resource server "' + found.caller.resourceServer + '" ' +
                  'deleted the resource ' + found.row._id + '; ' + revoked +
                  ' RPT(s) revoked.');
      res.status(204).set('Cache-Control', 'no-store').end();
      log.debug('Leaving DELETE ' + PATH_ID + '.');
    });
    app.all(PATH_ID, function (req, res) {
      log.debug('Entering ' + req.method + ' ' + PATH_ID + '.');
      if (!self.offCheck(res)) {
        self.unsupported(res, PATH_ID);
      }
      log.debug('Leaving ' + req.method + ' ' + PATH_ID + '.');
    });

    // ---------------------------------------------------------------------
    // POST /uma/perm — the permission endpoint (section 4).
    // ---------------------------------------------------------------------
    app.post(PERM_PATH, function (req, res) {
      log.debug('Entering POST ' + PERM_PATH + '.');
      const caller = self.admit(req, res);
      if (!caller) {
        log.debug('Leaving POST ' + PERM_PATH + '. Not admitted.');
        return;
      }
      const read = self.readPermissions(UmaSurface.bodyOf(req), caller);
      if (!read.permissions) {
        // error-code: none — readPermissions()'s code, STS-UMA-0117..0119.
        self.fail(res, read.status, read.code, read.error, read.why);
        log.debug('Leaving POST ' + PERM_PATH + '. ' + read.code);
        return;
      }
      const made = store.issueTicket({
        resourceServer: caller.resourceServer, owner: caller.owner,
        ownerKind: caller.ownerKind, permissions: read.permissions,
        client: '', claims: {} }, Number(config.value('uma.ticketLifetimeS')));
      self.record('uma.permission.ticket', caller,
                  read.permissions.map(function (p: Json) {
                    return p.resource_id;
                  }).join(' '),
                  'Resource server "' + caller.resourceServer + '" was ' +
                  'issued a permission ticket for ' +
                  read.permissions.length + ' resource(s).');
      res.status(201).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({ ticket: made.value }));
      log.debug('Leaving POST ' + PERM_PATH + '.');
    });
    app.all(PERM_PATH, function (req, res) {
      log.debug('Entering ' + req.method + ' ' + PERM_PATH + '.');
      if (!self.offCheck(res)) {
        self.unsupported(res, PERM_PATH);
      }
      log.debug('Leaving ' + req.method + ' ' + PERM_PATH + '.');
    });

    // ---------------------------------------------------------------------
    // GET /.well-known/uma2-configuration — discovery. Appended to the
    // issuer (the Grant specification's form) it arrives in its realm with
    // the prefix stripped; RFC 8414's INSERTED form arrives at the host
    // root with the realm after it, read as AuthZEN's is.
    // ---------------------------------------------------------------------
    app.get(METADATA_PATH, function (req, res) {
      log.debug('Entering GET ' + METADATA_PATH + '.');
      self.sendMetadata(req, res);
      log.debug('Leaving GET ' + METADATA_PATH + '.');
    });
    app.get(METADATA_PATH + '/*', function (req, res, next) {
      log.debug('Entering GET ' + METADATA_PATH + '/*.');
      const { realms, errorCodes } = self.deps;
      const segments = String((req.params as Json)[0] || '').split('/')
        .filter(Boolean);
      const named = segments.length === 2 && segments[0] === 'realm' &&
                    realms.isDefault() && segments[1] !== realms.DEFAULT_ID
        ? realms.get(segments[1]) : null;
      if (!named) {
        errorCodes.mark(res, 'STS-UMA-0120');
        log.debug('Leaving GET ' + METADATA_PATH + '/*. Names no realm.');
        next();
        return;
      }
      realms.run(named, function () {
        self.sendMetadata(req, res);
      });
      log.debug('Leaving GET ' + METADATA_PATH + '/*.');
    });

    // ---------------------------------------------------------------------
    // GET /uma — the description page (#584's shell), answered whether UMA
    // is on or off: it says which.
    // ---------------------------------------------------------------------
    app.get(BASE_PATH, function (req, res) {
      log.debug('Entering GET ' + BASE_PATH + '.');
      const info = self.description(req);
      if (DescriptionPages.asksForJson(req,
            String(req.query.format || '').toLowerCase() === 'json')) {
        res.status(200).set('Cache-Control', 'no-store').json(info);
        log.debug('Leaving GET ' + BASE_PATH + '. JSON.');
        return;
      }
      DescriptionPages.send(req, res, { base: BASE_PATH,
        title: 'User-Managed Access 2.0',
        view: { kind: 'uma', document: info } });
      log.debug('Leaving GET ' + BASE_PATH + '. The shell.');
    });
    app.get(DescriptionPages.scriptPath(BASE_PATH), function (req, res) {
      log.debug('Entering GET ' + BASE_PATH + '/description.js.');
      DescriptionPages.script(req, res);
      log.debug('Leaving GET ' + BASE_PATH + '/description.js.');
    });

    log.debug("Leaving UmaSurface.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). Its wire step
// registers the sweep, as `authzen_access_request.ts`'s does.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<UmaSurface>(
  'uma/uma',
  () => new UmaSurface(UmaSurface.defaultDeps()),
  function (instance: UmaSurface): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * User-Managed Access 2.0, registered by `common/protocol_stack.ts`.
 * @namespace
 */
export = {
  registerRoutes: (target: any): void => slot.get().registerRoutes(target),
  UmaSurface: UmaSurface,
  installInstance: (instance: UmaSurface): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  enabled: slot.forward('enabled'),
  metadata: slot.forward('metadata'),
  description: slot.forward('description'),
  revokeFor: slot.forward('revokeFor'),
  API_OBJECT: API_OBJECT,
  GRANT_TYPE: GRANT_TYPE,
  RREG_PATH: RREG_PATH,
  PERM_PATH: PERM_PATH,
  METADATA_PATH: METADATA_PATH
};
