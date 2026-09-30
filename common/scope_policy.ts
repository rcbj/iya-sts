// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: scope_policy.ts
//
// ===========================================================================
// WHICH SCOPES A CLIENT MAY BE ISSUED, DECIDED IN ONE PLACE (#110,
// 2026-09-22).
//
// Until this file nothing tied a scope to a client. `oauth-oidc/oauth2.ts`
// kept every scope a request named, verbatim, in every mode — so any client
// that could reach the token endpoint could ask for `admin:write` addressed to
// /admin-api, or `scim:write`, or `ssf:write`, and be given it. RFC 6749
// section 3.3 lets an authorization server "fully or partially ignore the
// scope requested … based on the authorization server policy", and RFC 7591
// section 2 says where such a policy lives: a client's `scope` is "the list
// that the client can use when requesting access tokens". Here that list is
// `oauthAllowedScope` on the client's entry in ou=applications, and this file
// is the policy that reads it.
//
// **THREE KINDS OF SCOPE, READ THREE WAYS.**
//
//   * THIS SERVICE'S OWN PROTECTED SCOPES — `admin:read` and `admin:write`
//     (/admin-api), the SCIM pair (`scim.scopeRead`, `scim.scopeWrite`), the
//     Shared Signals pair (`ssf.authScopeRead`, `ssf.authScopeWrite`), the
//     embedded debugger's permission, Grant Management's two (#142), the
//     VC-API test endpoints' two (#194) and the device compliance feed's
//     `device:compliance` (#164). Issued ONLY to a client whose
//     `oauthAllowedScope` lists them, IN BOTH MODES: the resource servers
//     behind them are this service's own, development already gates them, and
//     a gate any client can mint a key for is not one. Each of those resource
//     servers asks `declares()` again on every call, so removing a value cuts
//     off a token already issued.
//   * A SCOPE NAMING AN APPLICATION OR A DELEGATED PERMISSION — the audience
//     rule and `oauthDelegatedPermission` (`oauth2.ts`'s `audienceScopes()`,
//     `permissionRefusal()`). They keep their own rules and are never judged
//     here: a grant IS the declaration for a permission, and a scope that is
//     another application's client_id is an audience, not a privilege.
//   * EVERY OTHER SCOPE — held to the declaration in PRODUCT only
//     (`mode.grantsUndeclaredScopes()`). A client whose list names it gets it;
//     a client with no list at all gets the documented DEFAULT: OpenID Connect
//     Core's six and the caller's `defaults` (this realm's OpenID4VCI
//     credential scopes). That is RFC 6749 section 3.3's "pre-defined default
//     value", and it is what keeps every plain OpenID Connect client working
//     without anybody having to declare `openid`. In development a client
//     under test asks for whatever it likes.
//
// **REFUSED AT THE DOOR, NARROWED AT THE BACKSTOP.** `refusal()` is what the
// authorization, pushed authorization and token endpoints ask, and they answer
// `invalid_scope` (RFC 6749 sections 4.1.2.1 and 5.2: "exceeds the scope
// granted by the resource owner" — here, by the registration). A misconfigured
// client fails loudly, at the request that was wrong. `narrow()` is what
// `tokenSet()` asks for a grant that carries its scope from earlier — a
// refresh, a token exchange's inherited scope, an assertion grant — and it
// takes the value off, with an audit row, and the token response's `scope`
// says what was issued (section 5.1).
//
// **A TRANSLATION MUST NOT ALSO BE A POLICY** — `permissionRefusal()`'s header
// in `oauth2.ts`, and the reason this is a file of its own rather than a
// branch in `audienceScopes()`. It is also asked by GNAP (`gnap_grants.ts`),
// which reuses `oauthAllowedScope` for the Shared Signals access rights: one
// declared vocabulary per application, whatever protocol it asks in.
//
// A LIBRARY (rule 3): it registers nothing, and everything it requires is a
// library `oauth2.ts` already requires. The debugger's permission identifier
// is written out rather than required from `debugger/debugger_access.ts`, for
// `applications.js`'s reason — a feature directory is not a dependency of
// `common/` — and `tests/scope_policy.js` compares the two.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import mode = require('./mode');
import applications = require('./applications');
import audit = require('./audit');
// THE ISSUANCE POLICY DECIDES (#305, part D of #88): this file gathers the
// FACTS about each scope and asks the per-scope question through the gate;
// the rules — protected scopes in both modes, every other scope in product,
// the default set, device_sso — are the built-in `role-issuance`'s.
import gate = require('./issuance_gate');
import scopeVerdicts = require('../xacml/xacml_scope_verdicts');

// OpenID Connect Core 1.0 section 5.4, plus section 11's offline_access. All
// six, including the two this service issues no claims for — and OpenID
// Connect Key Binding's `bound_key` (#150), which asks for a bound ID Token.
/**
 * OpenID Connect Core's scopes (section 5.4 and offline_access) and Key
 * Binding's `bound_key`: the default set of a client that declares none.
 */
const OIDC_SCOPES = Object.freeze(['openid', 'profile', 'email', 'address',
  'phone', 'offline_access', 'bound_key']);

// `/admin-api`'s two, as `common/roles.js` maps them to ADMIN_READ and
// ADMIN_WRITE. Not settings: the management API's vocabulary is fixed.
/**
 * The management API's two scopes, `admin:read` and `admin:write`.
 */
const ADMIN_SCOPES = Object.freeze(['admin:read', 'admin:write']);

// Grant Management for OAuth 2.0's two (#142): the grant management API is
// this service's own resource server, so its scopes are protected like the
// rest — a client must declare them, and the API asks again on every call.
// Written out rather than required from `oauth-oidc/grant_management.ts`,
// for the debugger permission's reason below.
const GRANT_MANAGEMENT_SCOPES = Object.freeze(['grant_management_query',
                                               'grant_management_revoke']);

// The VC-API test endpoints' two (#194, `oid4vc/vc_api.ts`): an endpoint
// that signs any document its caller writes with a realm's key is this
// service's own resource server, and a development-only one is still no
// reason to let any client mint the key to it. Written out for the
// debugger permission's reason below; `tests/scope_policy.js` compares.
const VC_API_SCOPES = Object.freeze(['vc-api:issue', 'vc-api:verify']);

// THE MDM FEED'S (#164 phase 3): the one scope `/admin-api`'s device
// compliance operation takes instead of `admin:write`, so a posture feed
// holds nothing else. Protected like the rest — a client must declare it, in
// both modes, and the API asks again on every call. `common/roles.js`'s
// DEVICE_COMPLIANCE is read off it.
/**
 * The device compliance feed's one scope, protected like the rest.
 */
const DEVICE_COMPLIANCE_SCOPE = 'device:compliance';

// `debugger/debugger_access.ts`'s PERMISSION_ID. See the header.
/**
 * The embedded debugger's permission, a protected scope.
 */
const DEBUGGER_PERMISSION = 'urn:sts:debugger-api:debugger';

// OPENID CONNECT NATIVE SSO's scope (#130): granted, in every mode, only to
// a client `applications.nativeSsoOf()` enables — the flag and a group —
// because what it buys is a device_secret another app can turn into tokens.
const DEVICE_SSO = 'device_sso';
const NATIVE_SSO_CODE = 'STS-OAUTH-0624';

// The two codes a refusal carries: a protected scope, then any other.
/**
 * The error code of a refusal of this service's own protected scope.
 */
const PROTECTED_CODE = 'STS-OAUTH-0577';
/**
 * The error code of a refusal of a scope the client did not declare.
 */
const UNDECLARED_CODE = 'STS-OAUTH-0578';
// The backstop's audit row.
/**
 * The error code of the audit row `narrow()` writes.
 */
const NARROWED_CODE = 'STS-OAUTH-0579';

// A loose JSON-shaped value: a refusal, an audit detail.
type Json = any;

interface ScopePolicyDeps {
  log: typeof helpers.log;
  config: typeof config;
  mode: typeof mode;
  applications: typeof applications;
  audit: typeof audit;
}

// What a caller may say about the request beyond the scope and the client.
interface JudgeOptions {
  // Scopes the default set holds beside OIDC's six (OpenID4VCI's).
  defaults?: string[];
  // Which moment the scope is judged at (#305): `request`, where an endpoint
  // refuses, or `mint`, the backstop that narrows. `request` by default.
  stage?: string;
}

/**
 * Decides which scopes a client may be issued, from the `oauthAllowedScope`
 * its application entry declares (RFC 7591 section 2).
 *
 * This service's protected scopes are held to the declaration in both modes;
 * every other scope in product only, with OpenID Connect's scopes as the
 * default for a client that declares none. A scope naming an application or
 * a delegated permission keeps its own rules and is not judged here.
 */
class ScopePolicy {
  /**
   * The module's `OIDC_SCOPES`.
   */
  static readonly OIDC_SCOPES = OIDC_SCOPES;
  /**
   * The module's `ADMIN_SCOPES`.
   */
  static readonly ADMIN_SCOPES = ADMIN_SCOPES;
  /**
   * The module's `DEBUGGER_PERMISSION`.
   */
  static readonly DEBUGGER_PERMISSION = DEBUGGER_PERMISSION;
  /**
   * The module's `DEVICE_COMPLIANCE_SCOPE`.
   */
  static readonly DEVICE_COMPLIANCE_SCOPE = DEVICE_COMPLIANCE_SCOPE;
  /**
   * The module's `PROTECTED_CODE`.
   */
  static readonly PROTECTED_CODE = PROTECTED_CODE;
  /**
   * The module's `UNDECLARED_CODE`.
   */
  static readonly UNDECLARED_CODE = UNDECLARED_CODE;
  /**
   * The module's `NARROWED_CODE`.
   */
  static readonly NARROWED_CODE = NARROWED_CODE;

  /**
   * Builds the policy over its dependencies.
   *
   * @param deps - the logger, `config`, `mode`, `applications` and `audit`
   */
  constructor(private readonly deps: ScopePolicyDeps) {
    deps.log.debug("Entering ScopePolicy.constructor().");
    deps.log.debug("Leaving ScopePolicy.constructor().");
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies the composition root builds the policy with.
   *
   * @returns the real modules
   */
  static defaultDeps(): ScopePolicyDeps {
    helpers.log.debug("Entering ScopePolicy.defaultDeps().");
    helpers.log.debug("Leaving ScopePolicy.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      mode: mode,
      applications: applications,
      audit: audit
    };
  }

  // A space-delimited scope as a list of distinct tokens, in order.
  /**
   * Splits a space-delimited scope into its distinct values, in order.
   *
   * @param scope - the scope string (anything else is stringified)
   * @returns the distinct non-empty values
   */
  static split(scope: unknown): string[] {
    helpers.log.debug("Entering ScopePolicy.split().");
    const out: string[] = [];
    String(scope == null ? '' : scope).split(/\s+/).forEach(function (one) {
      if (one && out.indexOf(one) < 0) {
        out.push(one);
      }
    });
    helpers.log.debug("Leaving ScopePolicy.split().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE PROTECTED SCOPES, computed rather than written out, because four of
  // them are settings: a list written here would go stale the first time
  // `scim.scopeWrite` was set from /admin/config, and the symptom would be the
  // renamed scope issued to anybody. Each resource server names its own; this
  // reads the same settings they read.
  // ---------------------------------------------------------------------------
  /**
   * Lists this service's own protected scopes, reading the SCIM and Shared
   * Signals scope names from their settings each time.
   *
   * @returns the protected scope names
   */
  protectedScopes(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering ScopePolicy.protectedScopes().");
    const names = ADMIN_SCOPES.slice(0);
    [String(config.value('scim.scopeRead') || 'scim:read'),
     String(config.value('scim.scopeWrite') || 'scim:write'),
     String(config.value('ssf.authScopeRead') || 'ssf:read'),
     String(config.value('ssf.authScopeWrite') || 'ssf:write'),
     DEBUGGER_PERMISSION, DEVICE_COMPLIANCE_SCOPE]
      .concat(GRANT_MANAGEMENT_SCOPES, VC_API_SCOPES)
      .forEach(function (one) {
      if (names.indexOf(one) < 0) {
        names.push(one);
      }
    });
    log.debug("Leaving ScopePolicy.protectedScopes(). " + names.length +
              " name(s).");
    return names;
  }

  /**
   * Tells whether a scope is one of this service's protected scopes.
   *
   * @param scope - one scope value
   * @returns true for a protected scope
   */
  isProtected(scope: string): boolean {
    const { log } = this.deps;
    log.debug("Entering ScopePolicy.isProtected().");
    const answer = this.protectedScopes().indexOf(String(scope)) >= 0;
    log.debug("Leaving ScopePolicy.isProtected(). " + answer);
    return answer;
  }

  // The client's declared list, or null when it declares none.
  /**
   * Returns a client's declared scopes (`oauthAllowedScope`) in the ambient
   * realm.
   *
   * @param clientId - the client_id
   * @returns the declared list, or null when the client declares none
   */
  declaredScopes(clientId: unknown): string[] | null {
    const { log, applications } = this.deps;
    log.debug("Entering ScopePolicy.declaredScopes().");
    const held = applications.allowedScopesOf(clientId);
    log.debug("Leaving ScopePolicy.declaredScopes().");
    return held;
  }

  // ---------------------------------------------------------------------------
  // declares(clientId, scope) — whether the client's `oauthAllowedScope`
  // lists this scope. The resource servers' question: a token carrying a
  // protected scope is honoured only while the client it was issued to still
  // declares it. In the ambient realm, which the caller has set to the
  // token's.
  // ---------------------------------------------------------------------------
  /**
   * Tells whether a client's `oauthAllowedScope` lists a scope: the question a
   * resource server asks on every call, so that removing a value cuts off
   * tokens already issued.
   *
   * @param clientId - the client_id the token was issued to
   * @param scope - the scope value
   * @returns true when the client declares it
   */
  declares(clientId: unknown, scope: string): boolean {
    const { log } = this.deps;
    log.debug("Entering ScopePolicy.declares().");
    const held = this.declaredScopes(clientId);
    const answer = !!held && held.indexOf(String(scope)) >= 0;
    log.debug("Leaving ScopePolicy.declares(). " + answer);
    return answer;
  }

  // The default set for a client that declares nothing: OIDC's six and the
  // caller's.
  /**
   * Returns the default set for a client that declares nothing: OpenID
   * Connect's scopes and the caller's `defaults`.
   *
   * @param opts - optional; `defaults` adds scopes (the realm's OpenID4VCI
   *   credential scopes)
   * @returns the default scope names
   */
  defaultScopes(opts?: JudgeOptions): string[] {
    const { log } = this.deps;
    log.debug("Entering ScopePolicy.defaultScopes().");
    const out = OIDC_SCOPES.slice(0);
    ((opts && opts.defaults) || []).forEach(function (one) {
      if (one && out.indexOf(String(one)) < 0) {
        out.push(String(one));
      }
    });
    log.debug("Leaving ScopePolicy.defaultScopes().");
    return out;
  }

  // Whether the scope names an application or a delegated permission, which
  // keep their own rules — see the header.
  private namesAnotherParty(scope: string): boolean {
    const { log, applications } = this.deps;
    log.debug("Entering ScopePolicy.namesAnotherParty().");
    const answer = !!(applications.forPermission(scope) ||
                      applications.forClientId(scope));
    log.debug("Leaving ScopePolicy.namesAnotherParty(). " + answer);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // judge(scope, clientId, opts) — `{ kept, protectedRefused,
  // undeclaredRefused, declared }`. The whole decision, which `refusal()`
  // and `narrow()` phrase two ways.
  // ---------------------------------------------------------------------------
  /**
   * Makes the whole decision for a requested scope, value by value.
   *
   * @param scope - the requested scope
   * @param clientId - the client_id
   * @param opts - optional; `defaults` as for `defaultScopes()`
   * @returns `{ kept, protectedRefused, undeclaredRefused, nativeSsoRefused,
   *   declared }`
   */
  judge(scope: unknown, clientId: unknown, opts?: JudgeOptions): Json {
    const { log, mode } = this.deps;
    const self = this;
    log.debug("Entering ScopePolicy.judge().");
    const asked = ScopePolicy.split(scope);
    const out = { kept: [] as string[], protectedRefused: [] as string[],
                  undeclaredRefused: [] as string[],
                  nativeSsoRefused: [] as string[],
                  declared: null as string[] | null };
    if (!asked.length) {
      log.debug("Leaving ScopePolicy.judge(). Nothing was asked for.");
      return out;
    }
    const declared = self.declaredScopes(clientId);
    out.declared = declared;
    const protectedNames = self.protectedScopes();
    // The default set matters only to a client declaring nothing.
    const defaults = declared ? [] : self.defaultScopes(opts);
    const nativeSso = asked.indexOf(DEVICE_SSO) >= 0 &&
      !!self.deps.applications.nativeSsoOf(clientId).enabled;
    // THE FACTS (#305). Every value, with what this file knows about it and
    // about the client; the rules are the issuance policy's, and the policy
    // is what decides. See `xacml/CLAUDE.md`, the per-scope question.
    const A = scopeVerdicts.ATTRIBUTE;
    const facts = asked.map(function (one) {
      return {
        scope: one,
        attributes: [
          scopeVerdicts.resourceFact(A.SCOPE_DEVICE_SSO, one === DEVICE_SSO),
          scopeVerdicts.resourceFact(A.SCOPE_PROTECTED,
                                     protectedNames.indexOf(one) >= 0),
          scopeVerdicts.resourceFact(A.SCOPE_DECLARED,
                                     !!declared && declared.indexOf(one) >= 0),
          scopeVerdicts.resourceFact(A.SCOPE_NAMES_PARTY,
                                     self.namesAnotherParty(one)),
          scopeVerdicts.resourceFact(A.SCOPE_IN_DEFAULTS,
                                     defaults.indexOf(one) >= 0),
          scopeVerdicts.subjectFact(A.CLIENT_HAS_DECLARATION, !!declared),
          scopeVerdicts.subjectFact(A.CLIENT_NATIVE_SSO, nativeSso)]
      };
    });
    const client = String(clientId == null ? '' : clientId);
    const answer = gate.checkScopes({
      subject: { kind: 'application', name: client, authenticated: true },
      client: client,
      protocol: 'OAuth 2.0',
      mode: mode.current(),
      stage: (opts && opts.stage) || 'request',
      requested: asked,
      facts: facts
    });
    const verdictOf: Record<string, any> = {};
    (answer.verdicts || []).forEach(function (one) {
      verdictOf[one.scope] = one;
    });
    // EACH VERDICT FILED WHERE `refusal()` AND `narrow()` READ IT, by the
    // code the policy gave: the two #110 codes and Native SSO's. A refusal
    // the policy made with any other code — an operator's rule — is filed as
    // undeclared, the general case.
    asked.forEach(function (one) {
      const found = verdictOf[one] || { verdict: 'keep', code: '' };
      if (found.verdict === 'keep' || found.verdict === 'consent') {
        out.kept.push(one);
      } else if (found.code === NATIVE_SSO_CODE) {
        out.nativeSsoRefused.push(one);
      } else if (found.code === PROTECTED_CODE) {
        out.protectedRefused.push(one);
      } else {
        out.undeclaredRefused.push(one);
      }
    });
    log.debug("Leaving ScopePolicy.judge(). kept=" + out.kept.length +
              ", protected=" + out.protectedRefused.length +
              ", undeclared=" + out.undeclaredRefused.length);
    return out;
  }


  // ---------------------------------------------------------------------------
  // refusal(scope, clientId, opts) — null, or `{ code, error, description,
  // scopes }` for the endpoint to send as `invalid_scope`. A protected scope
  // is reported first: it is the refusal that holds in both modes, and the one
  // an operator most needs to recognise.
  // ---------------------------------------------------------------------------
  /**
   * Returns the refusal an endpoint sends as `invalid_scope`, reporting a
   * protected scope first, then `device_sso`, then an undeclared scope.
   *
   * @param scope - the requested scope
   * @param clientId - the client_id
   * @param opts - optional; `defaults` as for `defaultScopes()`
   * @returns null when the scope is allowed, otherwise `{ code, error,
   *   description, scopes }`
   */
  refusal(scope: unknown, clientId: unknown, opts?: JudgeOptions): Json {
    const { log } = this.deps;
    log.debug("Entering ScopePolicy.refusal().");
    const judged = this.judge(scope, clientId, opts);
    const who = String(clientId == null ? '' : clientId).trim();
    const client = who ? 'the client "' + who + '"' : 'a client that ' +
                                                      'named no client_id';
    const quoted = function (list: string[]): string {
      log.debug("Entering quoted().");
      log.debug("Leaving quoted().");
      return list.map(function (one) {
        return '"' + one + '"';
      }).join(', ');
    };
    const where = ' A client\'s declared scopes are `oauthAllowedScope` on ' +
      'its entry in ou=applications — the application\'s page under ' +
      '/admin/applications, or POST /admin-api/applications/add.';
    if (judged.protectedRefused.length) {
      log.debug("Leaving ScopePolicy.refusal(). A protected scope.");
      return { code: PROTECTED_CODE, error: 'invalid_scope',
        scopes: judged.protectedRefused,
        description: quoted(judged.protectedRefused) +
          (judged.protectedRefused.length === 1 ? ' is' : ' are') +
          ' this service\'s own ' +
          (judged.protectedRefused.length === 1 ? 'scope' : 'scopes') +
          ', issued in every mode only to a client that declares ' +
          (judged.protectedRefused.length === 1 ? 'it' : 'them') + ', and ' +
          client + ' does not.' + where + ' A dynamic registration cannot ' +
          'declare one; an administrator does.' };
    }
    if (judged.nativeSsoRefused.length) {
      log.debug("Leaving ScopePolicy.refusal(). Native SSO.");
      return { code: NATIVE_SSO_CODE, error: 'invalid_scope',
        scopes: judged.nativeSsoRefused,
        description: '"device_sso" (OpenID Connect Native SSO) is issued in ' +
          'every mode only to a client an administrator has enabled for it — ' +
          'oauthNativeSso TRUE and an oauthNativeSsoGroup on its entry in ' +
          'ou=applications — and ' + client + ' is not.' };
    }
    if (judged.undeclaredRefused.length) {
      log.debug("Leaving ScopePolicy.refusal(). An undeclared scope.");
      return { code: UNDECLARED_CODE, error: 'invalid_scope',
        scopes: judged.undeclaredRefused,
        description: client + ' has not declared ' +
          quoted(judged.undeclaredRefused) + ', and in product mode a client ' +
          'is issued only the scopes it declared (RFC 7591 section 2) — ' +
          (judged.declared
            ? 'its list is ' + quoted(judged.declared) + '.'
            : 'it declares none, so it may have the default set: ' +
              quoted(this.defaultScopes(opts)) + '.') + where };
    }
    log.debug("Leaving ScopePolicy.refusal(). Allowed.");
    return null;
  }

  // ---------------------------------------------------------------------------
  // narrow(scope, clientId, context) — the scope to ISSUE, with every value
  // `refusal()` would refuse taken off and one audit row saying which. The
  // backstop in `tokenSet()`, for a grant carrying its scope from earlier;
  // `context` is `{ grant, defaults }`. Unchanged, and no row, when nothing
  // is taken off.
  // ---------------------------------------------------------------------------
  /**
   * Returns the scope to issue, with every value `refusal()` would refuse taken
   * off and one audit row (STS-OAUTH-0579) naming them.
   *
   * The backstop in `tokenSet()` for a grant that carries its scope from
   * earlier.
   * @param scope - the scope to be issued
   * @param clientId - the client_id
   * @param context - optional `{ grant, defaults }`
   * @returns the narrowed scope, unchanged when nothing was taken off
   */
  narrow(scope: unknown, clientId: unknown, context?: Json): string {
    const { log, audit } = this.deps;
    log.debug("Entering ScopePolicy.narrow().");
    const ctx = context || {};
    const judged = this.judge(scope, clientId, { defaults: ctx.defaults,
                                                  stage: 'mint' });
    const removed = judged.protectedRefused.concat(judged.undeclaredRefused,
                                                   judged.nativeSsoRefused);
    if (!removed.length) {
      log.debug("Leaving ScopePolicy.narrow(). Nothing taken off.");
      return String(scope == null ? '' : scope);
    }
    const who = String(clientId == null ? '' : clientId).trim();
    // ONE line, the audit row's — `audit.js` writes a row carrying an
    // errorCode to the log itself.
    audit.failure('STS-OAUTH-0579', {
      actor: who,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: who,
      // STS-OAUTH-0579, as NARROWED_CODE exports it.
      outcome: 'refused',
      summary: 'the scope(s) ' + removed.join(', ') + ' were not issued to ' +
               (who || 'an unnamed client') + ': not in its ' +
               'oauthAllowedScope' +
               (judged.protectedRefused.length ? ' (this service\'s own ' +
                'protected scopes are held to it in every mode)' : ''),
      detail: { client_id: who, grant: String(ctx.grant || ''),
                removed: removed.join(' '),
                declared: (judged.declared || []).join(' ') }
    });
    const kept = ScopePolicy.split(scope).filter(function (one) {
      return removed.indexOf(one) < 0;
    }).join(' ');
    log.debug("Leaving ScopePolicy.narrow(). " + removed.length +
              " taken off.");
    return kept;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`. The exports below are FACADES for the
// JavaScript that calls this module through `require()`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ScopePolicy>(
  'common/scope_policy',
  () => new ScopePolicy(ScopePolicy.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

/**
 * Which scopes a client may be issued, decided in one place (#110).
 *
 * The method names below forward to the instance the composition root
 * installs.
 * @namespace
 */
export = {
  ScopePolicy: ScopePolicy,
  /**
   * Installs the instance the composition root built.
   */
  installInstance: (instance: ScopePolicy): void => slot.install(instance),
  /**
   * Names where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  OIDC_SCOPES: OIDC_SCOPES,
  ADMIN_SCOPES: ADMIN_SCOPES,
  DEBUGGER_PERMISSION: DEBUGGER_PERMISSION,
  DEVICE_COMPLIANCE_SCOPE: DEVICE_COMPLIANCE_SCOPE,
  PROTECTED_CODE: PROTECTED_CODE,
  UNDECLARED_CODE: UNDECLARED_CODE,
  NARROWED_CODE: NARROWED_CODE,
  split: ScopePolicy.split,
  protectedScopes: slot.forward('protectedScopes'),
  isProtected: slot.forward('isProtected'),
  declaredScopes: slot.forward('declaredScopes'),
  declares: slot.forward('declares'),
  defaultScopes: slot.forward('defaultScopes'),
  judge: slot.forward('judge'),
  refusal: slot.forward('refusal'),
  narrow: slot.forward('narrow')
};
