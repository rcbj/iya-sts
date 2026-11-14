// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_spec.ts
//
// ---------------------------------------------------------------------------
// The OpenAPI document for the management API, and the schemas it is written
// in.
//
// It is BUILT FROM THE ROUTE TABLE in admin_api.ts rather than kept beside it
// as a hand-written YAML file, and that is the whole point of this module. A
// spec file next to the code it describes is a spec file that is wrong within a
// month: somebody adds an action to the console, adds it to the API, and does
// not touch the document — and the only thing that then reports the drift is a
// person reading both. Here the operation and its description are ONE OBJECT,
// so an operation that exists is documented by construction and one that is
// documented exists.
//
// The counterpart rule is in admin_api.ts: an /admin control gets an /admin-api
// operation in the same commit. That one cannot be enforced by construction —
// nothing can see a form appear on a page — so it is asserted by this
// repository's own tests/protocol/admin_api.js (a `local: true` job) instead,
// which walks the console's own NAV and action lists and fails on a page or an
// action with no operation.
//
// OpenAPI 3.1.0 rather than 3.0.3: this document uses JSON Schema `examples`,
// `const` and nullable-by-union, all of which 3.0 spells differently or not at
// all. Every tool this repository would plausibly meet reads 3.1.
//
// This module registers no route and requires nothing of this service's but the
// LOGGER and `admin-core/protocol_endpoints.ts`, a table that holds no state —
// it is a pure function over a table — so its position in the require
// order does not matter, in the sense rule 3 gives for dpop.js, which reaches
// for helpers.js on exactly the same terms. What it must not grow is a require
// of anything that holds state: a document built from what the service happens
// to be doing is a document that describes one moment.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AdminApiSpec` takes the modules it uses through its constructor
// (`AdminApiSpecDeps`). Since R2 the composition root
// (`common/protocol_stack.ts`) builds the instance, and the module's old
// names are FACADES that forward to it, for the JavaScript callers; a process
// without the root builds a default at load. `AdminApiSpec` is exported
// beside them for the root.
//
// The schemas are written in `models/api/management.tsp` and `console.tsp` (#1390).
// `mgmt-api/admin_api.ts` has always read.
// ---------------------------------------------------------------------------

// The reply shape shared by every POST here: the console's own action result,
// unchanged. `ok` is the only member that is always present; the rest depends
// on what was asked, which is why this schema is open rather than closed.
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log } = helpers;
// Which console pages list their realm's endpoints, so a GET mirroring one
// can say that its reply carries them (2026-09-13). A library that requires
// nothing route-registering; see its header.
import protocolEndpoints = require('../admin-core/protocol_endpoints');
import ModelTables = require('../common/model_tables');

interface AdminApiSpecDeps {
  log: typeof log;
  protocolEndpoints: typeof protocolEndpoints;
}

/**
 * Builds the management API's OpenAPI 3.1.0 document from `admin_api.ts`'s
 * route table, so that an operation that exists is documented by construction.
 */
class AdminApiSpec {
  /**
   * Builds a document builder over the given dependencies.
   *
   * @param deps - the logger and `admin-core/protocol_endpoints`
   */
  constructor(private readonly deps: AdminApiSpecDeps) {
    deps.log.debug("Entering AdminApiSpec.constructor().");
    deps.log.debug("Leaving AdminApiSpec.constructor().");
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies the composition root passes, from the real
   * modules.
   *
   * @returns the logger and `admin-core/protocol_endpoints`
   */
  static defaultDeps(): AdminApiSpecDeps {
    log.debug("Entering AdminApiSpec.defaultDeps().");
    log.debug("Leaving AdminApiSpec.defaultDeps().");
    return {
      log: log,
      protocolEndpoints: protocolEndpoints
    };
  }

  // The same members as an OBJECT, for a reply that carries more than one list
  // and therefore cannot put them at the top level. Built from
  // PAGING_PROPERTIES above rather than written out again, because two
  // hand-kept copies of five member names is one copy that will eventually be
  // missing `lastRow`.
  //
  // `total` is here and not up there for a reason worth stating: at the top
  // level the number is called `matched`, which is the count AFTER a filter. A
  // drill-down's lists have no filter, so the honest name for the number is the
  // plain one.
  // Static since R2: the tables call it at load (see the header).
  // Static since R2: the tables call it at load (see the header).
  // ---------------------------------------------------------------------------
  // THE PROSE AT THE TOP OF THE DOCUMENT, AND IT IS A FUNCTION OF THE GATE
  // SINCE 2026-09-10 BECAUSE IT USED TO BE A FLAT CONTRADICTION OF IT.
  //
  // It is long on purpose: the first thing anybody pointing a tool at this
  // needs to know is whether it is protected and that four of its operations
  // change what the PROTOCOL endpoints do.
  //
  // **IT SAID "Nothing here is protected" FOR A DAY AFTER IT STOPPED BEING
  // TRUE.** `/admin-api` began requiring an OAuth 2.0 access token on
  // 2026-09-09; the startup banner was taught to read `adminApi.authRequired`
  // and this document was not, so the one artifact a machine reads went on
  // stating the opposite of what every one of its 238 operations would do. That
  // is worse than a stale comment: `security: []` is OpenAPI's way of saying a
  // credential is not needed, so a generated client sent none and was refused
  // everywhere, and the sentence a person read told them the refusal was a bug.
  //
  // Both states are still real — `adminApi.authRequired` is the off switch and
  // it restores the open API exactly — so the paragraph is written twice rather
  // than hedged once. The OFF text is the original, verbatim, because it is the
  // argument for the switch.
  // ---------------------------------------------------------------------------
  /**
   * Returns the prose at the top of the document, whose paragraph on protection
   * depends on whether the API's gate is on.
   *
   * @param authRequired - whether `/admin-api` requires an access token
   * @returns the description, paragraphs separated by blank lines
   */
  describe(authRequired) {
    const { log } = this.deps;
    log.debug("Entering AdminApiSpec.describe(). authRequired=" + authRequired);
    const protection = authRequired ? PROTECTED_PARAGRAPH : OPEN_PARAGRAPH;
    log.debug("Leaving AdminApiSpec.describe().");
    return [DESCRIPTION_OPENING, protection].concat(DESCRIPTION_REST)
      .join('\n\n');
  }

  // ===========================================================================
  // THE SECURITY HALF OF THE DOCUMENT.
  //
  // **THE SCOPE A GIVEN OPERATION NEEDS IS DECIDED BY ITS METHOD, AND THE
  // AUTHORITY IS THE GATE RATHER THAN THIS FILE.** `admin_api.ts`'s
  // `app.use(BASE, ...)` middleware reads `req.method === 'GET' ? 'admin:read'
  // : 'admin:write'`, and `scopeForMethod()` below is that one line written a
  // second time — which is a duplication worth naming, because a document that
  // disagrees with the gate is exactly the failure this whole change is about.
  // `tests/admin_api_document_security.js` compares the two over every
  // operation in the table, so the copy cannot drift silently.
  //
  // TWO SCHEMES, and they describe the same credential from the two ends a
  // reader arrives from:
  //
  //   * `oauth2` (client credentials) is what the API actually wants and where
  //     it comes from — the token endpoint, the two scopes, the client. It is
  //     the accurate description, and it is the one a tool can act on.
  //   * `bearerAuth` (http/bearer) is for the reader who already HAS a token —
  //     out of a launcher's environment, out of the console's explorer, out of
  //     a shell — and wants to paste it into a tool's Authorize box. Nothing
  //     but a header, which is all such a reader needs.
  //
  // **`resource` HAS NO FIELD IN OPENAPI AND IT IS THE PARAMETER MOST LIKELY TO
  // BE MISSED**, so it is in the scheme's own description rather than left to
  // the prose at the top: a token minted without it carries the wrong `aud` and
  // is refused by a gate that has just told the caller the credential was good
  // enough to parse. Being explicit here is the difference between a
  // five-second fix and reading a middleware.
  // ===========================================================================
  //
  // **ONE OPERATION IS THE EXCEPTION, AND THE GATE SAYS SO THE SAME WAY**
  // (#164 phase 3): `POST /admin-api/device-compliance`, the MDM feed, takes
  // `device:compliance` and not `admin:write` — `admin_api.ts`'s
  // `isDeviceComplianceFeed()` — so a posture feed holds nothing else.
  /**
   * Returns the scope an operation needs: `admin:read` for a GET, `admin:write`
   * for any other method, `admin:security` for a write of
   * `/admin-api/policies/{action}` (#645), and `device:compliance` for `POST
   * /admin-api/device-compliance`.
   *
   * A second copy of the gate's rule; `tests/admin_api_document_security.js`
   * compares the two.
   *
   * @param method - the HTTP method
   * @param path - the operation's path, if known
   * @returns the scope name
   */
  scopeForMethod(method, path?) {
    const { log } = this.deps;
    log.debug("Entering AdminApiSpec.scopeForMethod().");
    log.debug("Leaving AdminApiSpec.scopeForMethod().");
    if (String(method).toUpperCase() === 'POST' &&
        String(path || '') === '/admin-api/device-compliance') {
      return 'device:compliance';
    }
    // THE CONSOLE'S OWN OPERATIONS (#454), as the gate's `consoleOp` reads
    // them: everything under `/admin-api/console` takes `admin:console`.
    if (/^\/admin-api\/console(\/|$)/.test(String(path || ''))) {
      return 'admin:console';
    }
    // A DIRECTORY → POLICIES WRITE (#645): every action of
    // `/admin-api/policies/{action}` is a policy kind's save, reset or act,
    // which the gate asks `admin:security` for
    // (`common/security_operations.ts`). The other security changes depend
    // on the body — which attribute, whose account — so their operations
    // say `admin:write` and the scheme's description says the rest.
    if (String(method).toUpperCase() !== 'GET' &&
        /^\/admin-api\/policies\/\{action\}$/.test(String(path || ''))) {
      return 'admin:security';
    }
    return String(method).toUpperCase() === 'GET' ? 'admin:read' :
           'admin:write';
  }

  /**
   * Returns the document's two security schemes: `oauth2` (client credentials
   * at this service's token endpoint, with the resource indicator to send) and
   * `bearerAuth` (an already-held token).
   *
   * @param baseUrl - the service's base URL, for the token URL and resource
   * @returns the `securitySchemes` object
   */
  securitySchemesFor(baseUrl) {
    const { log } = this.deps;
    log.debug("Entering AdminApiSpec.securitySchemesFor().");
    const schemes = {
      oauth2: {
        type: 'oauth2',
        description:
          'An access token from this service\'s own token endpoint. ' +
          'Ask as the seeded client `sts-api-client`, whose secret is ' +
          'the `adminApi.clientSecret` setting, and **send ' +
          '`resource=' + String(baseUrl || '') + '/admin-api`** with the ' +
          'request: OpenAPI has no field for RFC 8707\'s resource indicator ' +
          'and it is what puts this API in the token\'s `aud`, without which ' +
          'every call here is refused 401.',
        flows: {
          clientCredentials: {
            tokenUrl: String(baseUrl || '') + '/oauth2/token',
            scopes: {
              'admin:read': 'Read anything this API exposes (every GET).',
              'admin:write': 'Change anything this API can change ' +
                             '(every other method), except a security ' +
                             'change.',
              // #645.
              'admin:security': 'A security change, in place of ' +
                                'admin:write: a Directory → Policies ' +
                                'policy saved, reset or acted on, a policy ' +
                                'named on an application, group or person, ' +
                                'the Security Administrator\'s role granted ' +
                                'or revoked, and the account of a person ' +
                                'who holds it. Issued only to a subject ' +
                                'holding SECURITY_ADMIN.',
              'admin:console': 'The admin console\'s own operations, under ' +
                               '/admin-api/console (#454). Issued only to ' +
                               'the console\'s client, sts-admin-console, ' +
                               'through the ADMIN_CONSOLE role it confers.',
              'device:compliance': 'Report device compliance through POST ' +
                                   '/admin-api/device-compliance, and ' +
                                   'nothing else — the scope an MDM or ' +
                                   'posture feed holds (#164). Issued only ' +
                                   'to a client that declares it.'
            }
          }
        }
      },
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'The same token, pasted. Use this when you already hold ' +
          'one — from a launcher\'s ' +
          '`STS_ADMIN_API_TOKEN`, from the console\'s ' +
          'API explorer, or from a shell — rather than minting one here.'
      }
    };
    log.debug("Leaving AdminApiSpec.securitySchemesFor().");
    return schemes;
  }

  // What one operation requires. Two alternatives rather than one, because the
  // schemes above are two ways to present the same credential and OpenAPI reads
  // a LIST of requirement objects as "any one of these will do". The bearer
  // entry carries an empty array because scopes are meaningless outside oauth2
  // — naming them there would be a document that validators reject.
  // One operation, as OpenAPI wants it. `entry` is a row of admin_api.ts's
  // route table and `action` is one of its actions, or null for a plain route.
  // The document. `routes` is admin_api.ts's table; an entry carrying `actions`
  // becomes one operation per action, at the concrete URL each of them has —
  // which is a real address even though express serves all of them from one
  // `:action` pattern.
  /**
   * The OpenAPI document of the routes given, as the model states it. The
   * Management API OpenAPI document and the Admin Console API OpenAPI document
   * are written in `models/api/` (#1390). What depends on this request or this
   * process is set here: the base URL, the version, and the access gate's state.
   *
   * @param routes - the route table, or part of it
   * @param options - `baseUrl`, `version`, `authRequired` and `console`
   * @returns the OpenAPI document
   */
  buildSpec(routes, options) {
    const { log } = this.deps;
    log.debug("Entering AdminApiSpec.buildSpec().");
    const opts = options || {};
    // ---------------------------------------------------------------------
    // **THE GATE'S STATE ARRIVES AS AN OPTION AND DEFAULTS TO ON.** A caller
    // that forgets to pass it makes a document that over-states the
    // requirement, which costs a client one unnecessary token; the other
    // default would tell a client no credential is needed by an API that
    // refuses it on every operation.
    // ---------------------------------------------------------------------
    const authRequired = opts.authRequired === undefined
      ? true : opts.authRequired === true;
    const source = AdminApiSpec.sourceFor(routes);
    const paths = {};
    const tags = [];
    routes.forEach(function (entry) {
      if (tags.indexOf(entry.tag) < 0) {
        tags.push(entry.tag);
      }
      AdminApiSpec.keysOf(entry).forEach(function (key) {
        const operation = source.paths[key.path] &&
          source.paths[key.path][key.method];
        if (!operation) {
          return;
        }
        if (!authRequired) {
          delete operation.security;
        }
        paths[key.path] = paths[key.path] || {};
        paths[key.path][key.method] = operation;
      });
    });
    const components: Record<string, any> = {
      schemas: source.components.schemas };
    if (authRequired) {
      components.securitySchemes = this.securitySchemesFor(opts.baseUrl);
    }
    // THE CONSOLE'S DOCUMENT (#454), `GET /admin-api/console/openapi.json`,
    // under its own title and with a first paragraph saying what they are.
    const consoleDocument = opts.console === true;
    log.debug("Leaving AdminApiSpec.buildSpec().");
    return {
      openapi: '3.1.0',
      info: {
        title: consoleDocument ? 'IYA STS admin console operations'
                               : 'IYA STS management API',
        version: opts.version || '0.0.0',
        description: (consoleDocument ? CONSOLE_PARAGRAPH + '\n\n' : '') +
                     this.describe(authRequired),
        license: { name: 'MIT' }
      },
      servers: [{ url: opts.baseUrl || '/', description: 'This service.' }],
      tags: tags.map(function (name) {
        return { name: name, description: TAG_DESCRIPTIONS[name] || '' };
      }),
      // A tool's Authorize box reads this one, so it names every scope a
      // reader's token carries; each operation states its narrower truth.
      // An empty array claims that no credential is needed, so it appears
      // only when the gate is off.
      security: authRequired
        ? [{ oauth2: consoleDocument
            ? ['admin:console', 'admin:read', 'admin:write']
            : ['admin:read', 'admin:write', 'admin:security'] },
           { bearerAuth: [] }]
        : [],
      paths: paths,
      components: components
    };
  }

  /**
   * The paths and methods of one route-table row.
   *
   * @param entry - the row
   * @returns one `{ path, method }` per operation
   */
  static keysOf(entry) {
    log.debug("Entering AdminApiSpec.keysOf().");
    const method = entry.method.toLowerCase();
    const keys = entry.actions ? entry.actions.map(function (action) {
      return { path: entry.route.replace(':action', action.action),
               method: method, action: action };
    }) : [{ path: entry.path, method: method, action: null }];
    log.debug("Leaving AdminApiSpec.keysOf().");
    return keys;
  }

  /**
   * The document the routes belong to. Each of the two numbers its shared
   * schemas alone, so when one set spans both, the Admin Console API's are
   * renamed to keep them apart.
   *
   * @param routes - the routes
   * @returns the document's paths and components
   */
  static sourceFor(routes) {
    log.debug("Entering AdminApiSpec.sourceFor().");
    const kinds = routes.map(function (entry) {
      return entry.kind || 'management';
    });
    const consoleOnly = kinds.length > 0 && kinds.every(function (kind) {
      return kind === 'console';
    });
    const managementOnly = kinds.every(function (kind) {
      return kind === 'management';
    });
    const source = managementOnly ?
      ModelTables.file('openapi.management.json') : consoleOnly ?
        ModelTables.file('openapi.console.json') : AdminApiSpec.merged();
    log.debug("Leaving AdminApiSpec.sourceFor().");
    return source;
  }

  /**
   * Both documents as one, for what spans them.
   *
   * @returns the paths and components
   */
  static merged() {
    log.debug("Entering AdminApiSpec.merged().");
    const management = ModelTables.file('openapi.management.json');
    const console_ = JSON.parse(JSON.stringify(
      ModelTables.file('openapi.console.json')).split(
      '#/components/schemas/').join('#/components/schemas/Console_'));
    const schemas = Object.assign({}, management.components.schemas);
    Object.keys(console_.components.schemas).forEach(function (name) {
      schemas['Console_' + name] = console_.components.schemas[name];
    });
    const merged = {
      paths: Object.assign({}, management.paths, console_.paths),
      components: { schemas: schemas }
    };
    log.debug("Leaving AdminApiSpec.merged().");
    return merged;
  }

  /**
   * Gives routing rows what the model states of them: the summary, and the
   * body the request is validated against. Rows keep the path, the handler,
   * and which console control each mirrors.
   *
   * @param routes - the route table
   * @returns the same table
   */
  static named(routes) {
    log.debug("Entering AdminApiSpec.named().");
    const paths = AdminApiSpec.merged().paths;
    routes.forEach(function (entry) {
      AdminApiSpec.keysOf(entry).forEach(function (key) {
        const operation = paths[key.path] && paths[key.path][key.method];
        if (!operation) {
          return;
        }
        const row = key.action || entry;
        row.summary = operation.summary;
        const body = operation.requestBody &&
          operation.requestBody.content['application/json'];
        if (body) {
          row.requestBody = body.schema;
        }
      });
    });
    log.debug("Leaving AdminApiSpec.named().");
    return routes;
  }

  /**
   * The body every refusal of these two APIs is held to.
   *
   * @returns the schema
   */
  static refusalSchema() {
    log.debug("Entering AdminApiSpec.refusalSchema().");
    const paths = AdminApiSpec.merged().paths;
    const schema = paths['/admin-api'].get.responses.default.content[
      'application/json'].schema;
    log.debug("Leaving AdminApiSpec.refusalSchema().");
    return schema;
  }

}

// THE HELPERS THE TABLES BELOW CALL at load, under their old names so that
// every call site in them reads as it did. Static, so no instance is used.
// THE CONSOLE'S DOCUMENT'S FIRST PARAGRAPH (#454).
const CONSOLE_PARAGRAPH =
  '**These are the admin console\'s own operations, not the management ' +
  'API.** They exist to draw the static console at /admin — its frame, ' +
  'its drawings and its form helpers — and answer in the shape its pages ' +
  'want, which changes when a page does. They take `admin:console`, ' +
  'issued only to the console\'s client through the ADMIN_CONSOLE role ' +
  'it confers, and a page that shows realm data takes ADMIN_READ too. ' +
  'Every control the console has is a management operation, described by ' +
  '/admin-api/openapi.json.';

const DESCRIPTION_OPENING =
  'The management API of IYA STS: everything the /admin console ' +
  'shows and everything it can change, over JSON, with no browser.';

// ---------------------------------------------------------------------------
// THE GATE, WHEN IT IS ON — which is the default.
// ---------------------------------------------------------------------------
const PROTECTED_PARAGRAPH =
  '**Every operation here requires an OAuth 2.0 access token, and this ' +
  'document says which scope each one needs.** Ask this service\'s own token ' +
  'endpoint for one: `grant_type=client_credentials` as the seeded client ' +
  '`sts-api-client` (its secret is `adminApi.clientSecret`), ' +
  '`scope=admin:read admin:write`, and **`resource=<this ' +
  'server>/admin-api`** — that last parameter is what puts this API in the ' +
  'token\'s `aud`, and a token audienced at anything else is refused however ' +
  'good it is. A GET needs `admin:read` and everything else needs ' +
  '`admin:write`; they are checked as a XACML access decision against the ' +
  'built-in ADMIN_READ and ADMIN_WRITE roles, so the requirement is stated ' +
  'in the same policy document as every other access decision in this ' +
  'service. **The credential is service-wide**: the token is verified ' +
  'against the DEFAULT realm\'s key and audienced without a realm prefix ' +
  'wherever it is presented, for the reason the console\'s two roles are ' +
  'groups in the default realm — a per-realm one would let anybody who can ' +
  'create a realm mint themselves an administrator. A trust realm\'s own ' +
  'administrators have a narrower token of their own: issued to that ' +
  'realm\'s `sts-api-client` client, accepted only under ' +
  '`/realm/<id>/admin-api`, and refused every service-wide operation. ' +
  '`adminApi.authRequired` ' +
  'turns this off and restores the open API exactly; what follows is what ' +
  'that means. **AND IT IS STILL WORTH STATING PLAINLY**: a holder of this ' +
  'token can revoke every token this service has issued and change what the ' +
  'next one contains. That is fine on a laptop or a compose network and is ' +
  'not fine on a public address, which was already true of /oauth2/token — ' +
  'it will mint a token for any username asked of it.';

// ---------------------------------------------------------------------------
// AND WHEN IT IS OFF (`adminApi.authRequired: false`). The original text.
// ---------------------------------------------------------------------------
const OPEN_PARAGRAPH =
  '**Nothing here is protected, and that is a decision rather than an ' +
  'oversight.** This service checks no end-user password anywhere — the ' +
  'username typed at its sign-in screen simply becomes the identity in every ' +
  'token it issues — so a console or an API with a credential on it would be ' +
  'a surface a test would have to hold a secret for, in a service whose ' +
  'premise is that it authenticates nobody. Several surfaces are the ' +
  'exception and none of them is this one. THREE ARE TURNSTILES — anybody ' +
  'can get the credential — and each exists so that a client\'s refusal ' +
  'paths can be exercised at all: the SCIM endpoints, which create and ' +
  'delete accounts; the SPIRE Server API, whose callers present an X509-SVID ' +
  'over mutual TLS; and the admin console, which needs a sign-on session and ' +
  'one of two directory-group roles. THE XACML SURFACE IS NOT A TURNSTILE ' +
  'and is worth knowing about before driving it: all eight /xacml endpoints ' +
  'require a client certificate this service VERIFIED against an anchor in ' +
  'its own truststore, whose subject DN resolves to a directory entry ' +
  'holding a role — XACML_USER for the four endpoints proper and REMOTE_PEPS ' +
  'for the three a remote enforcement point uses plus POST /xacml/pip. ' +
  'xacml.enforceAccess is the one way past it, and it is settable HERE. ' +
  'What follows is worth stating plainly: anyone who can reach ' +
  'this port can revoke every token this service has issued and change ' +
  'what the next one contains. That is fine on a laptop or a compose ' +
  'network and is not fine on a public address, which was already true of ' +
  '/oauth2/token — it will mint a token for any username asked of it.';

// The paragraphs that are true whichever way the switch is set.
const DESCRIPTION_REST = [
  '**Many operations change what the protocol endpoints do**, rather ' +
  'than only reporting on them; four examples. Revoking a token is the same ' +
  'revocation RFC 7009\'s /oauth2/revoke performs, so introspection, ' +
  'UserInfo and the refresh grant all honour it immediately. A custom ' +
  'claim reaches every access token, ID Token and SAML assertion issued ' +
  'from then on. The credential claim set reaches every Verifiable ' +
  'Credential AND sweeps the embedded LDAP directory. And the verifier ' +
  'request reaches the dcql_query of the next OID4VP Authorization ' +
  'Request. Nothing already issued ever changes — a signed document ' +
  'cannot be reached into.',

  '**Every operation here mirrors a control on the /admin console and ' +
  'calls the same function behind it.** They are not two implementations ' +
  'of one idea: admin_api.js holds no opinion about what a revocation ' +
  'means that the console does not. The `mirrors` line on each operation ' +
  'says which control it is.',

  'In the default memory persistence mode all state is in memory and dies ' +
  'with the process; `GET /admin-api/persistence` says what this process ' +
  'writes down.'
];

const TAG_DESCRIPTIONS = {
  Service: 'What this API is, its document, and the explorer that calls it.',
  SCEP: 'The Simple Certificate Enrolment Protocol (RFC 8894) server of this ' +
        'realm: its Issuing CA and RA certificate, the single-use challenge ' +
        'passwords that authorize an enrollment, registered host names, the ' +
        'certificates issued over it, and what it has done.',
  GNAP: 'The Grant Negotiation and Authorization Protocol (RFC 9635) and its ' +
        'resource server connections (RFC 9767): the authorization server of ' +
        'this realm, what the applications using it have done, and the two ' +
        'things an operator does to its state by hand.',
  Metrics: 'What this service has done since it started.',
  Users: 'Who it has authenticated, and what each of them holds.',
  Groups: 'The embedded LDAP directory\'s groups. A group here GRANTS ' +
          'NOTHING: no token, assertion, ticket or PAC carries one and no ' +
          'endpoint reads one.',
  Roles: 'Who holds a role, and what requires one. A role is a name a ' +
         'person, a GROUP or an APPLICATION can be mapped into, and holding ' +
         'one is what an ISSUANCE is decided on — which is the whole ' +
         'difference from Groups above, where a group grants nothing. The ' +
         'decision is made by the XACML PDP against a policy, never by an ' +
         '`if` in an issuance site, so a refusal is a document somebody can ' +
         'read. It is not Admin roles either: those are two directory groups ' +
         'that grant the /admin console and nothing else.',
  Policies: 'The rules this realm holds a credential to — the password ' +
            'policy first: its minimum length, how many previous passwords ' +
            'may not be reused, and the symbol, uppercase and digit rules, ' +
            'stored as `cn=default,ou=passwordPolicies` in the directory and ' +
            'ENFORCED IN PRODUCT MODE at every door that sets a password. ' +
            'Not the XACML policy repository, which is under XACML.',
  Tokens:'What has been issued, and the revocation of the three kinds that ' +
          'can be revoked.',
  SCIM: 'The SCIM 2.0 provisioning endpoints under /scim/v2 — what they have ' +
        'been asked to do, and what they will and will not do. READ-ONLY ' +
        'here, and that is the parity rule holding rather than a gap: the ' +
        'console page has no form on it either, because everything about ' +
        'SCIM that can be changed is a configuration row. What SCIM WROTE is ' +
        'under Users and Groups, since it provisions into the same directory ' +
        'and has no store of its own.',
  'Audit log': 'What happened here, in order — history rather than state, ' +
               'and read-only. It carries no credential of any kind and has ' +
               'no clear operation: an erase control on an administrative ' +
               'surface would make an audit log unable to answer the one ' +
               'question it exists for.',
  'Custom claims': 'What to add to every access token and ID Token issued ' +
                   'from now on. The assertions are next door, under Custom ' +
                   'SAML attributes.',
  'Custom SAML attributes': 'What to add to every SAML 2.0 and SAML 1.1 ' +
                            'assertion issued from now on — WS-Trust\'s and ' +
                            'WS-Federation\'s alike. The same store the ' +
                            'custom claims are in, and the same two halves: ' +
                            'a typed attribute and a directory one.',
  'Credential claims': 'What an issued Verifiable Credential carries.',
  'Credential status': 'The status lists every issued Verifiable ' +
    'Credential names, and suspending, reinstating or revoking one: ' +
    'Monitoring → Verifiable Credentials (`/admin/vc/monitor`) in the ' +
    'console.',
  'Verifier request': 'What this realm\'s OID4VP Verifier asks a wallet ' +
  'for.',
  'Token lifetimes': 'How long an access token, an ID Token and a refresh ' +
                     'token issued here last, and how far out a clock may be ' +
                     'before this service stops believing one of its own. ' +
                     'Four of the settings under Configuration, behind a ' +
                     'name that promises four rather than forty-nine — and a ' +
                     'door that refuses a key it does not recognise instead ' +
                     'of ignoring it.'
};

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AdminApiSpec>(
  'mgmt-api/admin_api_spec',
  () => new AdminApiSpec(AdminApiSpec.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The OpenAPI document for the management API, built from the route table in
 * `admin_api.ts`, and the schemas it is written in.
 *
 * A library: it registers no route and holds no state.
 *
 * @namespace
 */
export = {
  AdminApiSpec: AdminApiSpec,
  SCHEMAS: AdminApiSpec.merged().components.schemas,
  named: AdminApiSpec.named,
  refusalSchema: AdminApiSpec.refusalSchema,
  /**
   * Installs the instance the composition root built, which the facades below
   * forward to.
   *
   * @param instance - the instance to install
   */
  installInstance: (instance: AdminApiSpec): void => slot.install(instance),
  /**
   * Says whether the installed instance came from the root or the default.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * Forwards to `AdminApiSpec.buildSpec()` on the installed instance.
   */
  buildSpec: slot.forward('buildSpec')
};
