// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_scopes.ts
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS SCOPE NAMES (#334).
//
// CAEP Interoperability Profile 1.0 section 2.7.3 says an authorization
// server that issues tokens to SSF Receivers MUST support `ssf.manage` and
// `ssf.read`. `ssf.read` is Read Stream Configuration and Get Stream Status.
// `ssf.manage` includes every `ssf.read` permission and adds Create Stream,
// Delete Stream and Stream Verification. Those are the two settings'
// defaults (`ssf.authScopeRead`, `ssf.authScopeWrite`). This service's own
// colon names, `ssf:read` and `ssf:write`, are gone: rcbj's decision on
// #334 (2026-10-19), with no alias, because this repository keeps no
// backwards-compatibility shims. A receiver that still asks for `ssf:read`
// is asking for a scope this service does not have.
//
// THE RULE IS ONE STATEMENT: WRITE INCLUDES READ. Every Shared Signals name
// grants a set of permissions:
//
//   * a READ name grants `read`: `ssf.read`, always, and the read setting's
//     name;
//   * a WRITE name grants `read` AND `write`: `ssf.manage`, always, and the
//     write setting's name. The profile says manage includes read, and the
//     write setting names this service's manage scope, so a renamed write
//     scope includes read exactly as `ssf.manage` does. A name set on both
//     settings is a write name, and so grants both.
//
// The two fixed names never move: setting the read setting to `ssf.manage`
// leaves it a write name, and setting the write setting to `ssf.read` leaves
// it a read name. Everything below asks `permissionsOf()` and nothing else:
//
//   * ISSUANCE (`declarationCovers()`, which `common/scope_policy.ts` asks
//     beside an exact match): a client may be issued a Shared Signals name
//     when the names it declares in `oauthAllowedScope` grant, between
//     them, every permission that name grants. So declaring `ssf.manage`
//     authorizes `ssf.read` (manage includes read), declaring only
//     `ssf.read` does not authorize `ssf.manage`, and a client that declares
//     only a renamed write scope is issued a read name by that one path,
//     "write includes read", and by no other.
//   * THE TOKEN (`covers()`): an operation needing a permission is attempted
//     when some name the token holds grants it.
//   * THE RE-CHECK (`stillDeclared()`, what `ssf/ssf_auth.ts` asks on every
//     call, `STS-SSF-0107`): the token holds a name granting the permission
//     AND the client still declares a name granting it. A manage-only token
//     whose client now declares only `ssf.read` keeps its read and loses
//     its write, which is what that client could be issued today.
//
// These names stay protected whatever the settings say, or development would
// issue `ssf.read` and `ssf.manage` to anybody. A configured name is
// protected only while the setting names it. SCIM is the opposite: renaming
// `scim.scopeWrite` unprotects `scim:write`.
//
// A LIBRARY (rule 3). It requires `config` and `helpers` and nothing in
// `ssf/`, so `common/scope_policy.ts` and `oauth-oidc/oauth2.ts` can read
// the vocabulary without a feature directory becoming a dependency of
// `common/`. The composition root builds it immediately before the scope
// policy. Nothing here calls a facade at load.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import config = require('./config');
import InstanceSlot = require('./instance_slot');

type Permission = 'read' | 'write';

interface SsfScopesDeps {
  log: { debug(message: string): void };
  config: { value(key: string): unknown };
}

/**
 * The Shared Signals scope vocabulary: the two settings and the CAEP
 * Interoperability Profile names (#334).
 *
 * A read name grants read. A write name grants read and write: write
 * includes read. `ssf.read` is always a read name and `ssf.manage` always a
 * write name.
 */
class SsfScopes {
  /** The profile's read scope (CAEP Interoperability Profile 1.0 §2.7.3). */
  static readonly PROFILE_READ = 'ssf.read';
  /** The profile's manage scope, which includes read. */
  static readonly PROFILE_MANAGE = 'ssf.manage';

  /**
   * Builds the vocabulary over its dependencies.
   *
   * @param deps - the logger and `config`
   */
  constructor(private readonly deps: SsfScopesDeps) {
    deps.log.debug("Entering SsfScopes.constructor().");
    deps.log.debug("Leaving SsfScopes.constructor().");
  }

  /**
   * Returns the dependencies the composition root builds this with.
   *
   * @returns the logger and `config`
   */
  static defaultDeps(): SsfScopesDeps {
    helpers.log.debug("Entering SsfScopes.defaultDeps().");
    helpers.log.debug("Leaving SsfScopes.defaultDeps().");
    return { log: helpers.log, config: config };
  }

  // One setting, or its profile default when the value is empty. `0` is
  // not a legal scope name, so `||` is the same reading the settings had.
  private setting(key: string, fallback: string): string {
    const { log, config } = this.deps;
    log.debug("Entering SsfScopes.setting(). " + key);
    const value = String(config.value(key) || fallback);
    log.debug("Leaving SsfScopes.setting(). " + value);
    return value;
  }

  /**
   * Returns the operator's read scope (`ssf.authScopeRead`).
   *
   * @returns the configured read name, or `ssf.read`
   */
  configuredRead(): string {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.configuredRead().");
    const value = this.setting('ssf.authScopeRead', SsfScopes.PROFILE_READ);
    log.debug("Leaving SsfScopes.configuredRead(). " + value);
    return value;
  }

  /**
   * Returns the operator's write scope (`ssf.authScopeWrite`).
   *
   * @returns the configured write name, or `ssf.manage`
   */
  configuredWrite(): string {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.configuredWrite().");
    const value = this.setting('ssf.authScopeWrite',
                               SsfScopes.PROFILE_MANAGE);
    log.debug("Leaving SsfScopes.configuredWrite(). " + value);
    return value;
  }

  // Appends a non-empty name that is not already in the list.
  private pushUnique(out: string[], name: string): void {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.pushUnique().");
    if (name && out.indexOf(name) < 0) {
      out.push(name);
    }
    log.debug("Leaving SsfScopes.pushUnique().");
  }

  /**
   * Lists the permissions one scope name grants: the whole rule.
   *
   * A write name (`ssf.manage`, or the write setting's name unless it is
   * `ssf.read`) grants read and write. A read name (`ssf.read`, or the read
   * setting's name) grants read. Anything else grants nothing.
   *
   * @param scope - one scope value
   * @returns `['read', 'write']`, `['read']` or `[]`
   */
  permissionsOf(scope: unknown): Permission[] {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.permissionsOf().");
    if (scope == null || scope === '') {
      log.debug("Leaving SsfScopes.permissionsOf(). (empty)");
      return [];
    }
    const name = String(scope);
    // `ssf.read` is checked first so that the write setting cannot make the
    // profile's read name a write name; `ssf.manage` is a write name before
    // the read setting is asked, for the same reason the other way round.
    if (name === SsfScopes.PROFILE_READ) {
      log.debug("Leaving SsfScopes.permissionsOf(). read");
      return ['read'];
    }
    if (name === SsfScopes.PROFILE_MANAGE ||
        name === this.configuredWrite()) {
      log.debug("Leaving SsfScopes.permissionsOf(). read, write");
      return ['read', 'write'];
    }
    if (name === this.configuredRead()) {
      log.debug("Leaving SsfScopes.permissionsOf(). read");
      return ['read'];
    }
    log.debug("Leaving SsfScopes.permissionsOf(). (none)");
    return [];
  }

  // Whether one name grants one permission.
  private grants(name: unknown, permission: string): boolean {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.grants(). " + permission);
    const answer = this.permissionsOf(name)
      .indexOf(permission as Permission) >= 0;
    log.debug("Leaving SsfScopes.grants(). " + answer);
    return answer;
  }

  /**
   * Lists every published name that grants a permission, in published
   * order. With the defaults a read is `ssf.read` and `ssf.manage`, and a
   * write is `ssf.manage`.
   *
   * @param permission - `read` or `write`
   * @returns the names, without duplicates
   */
  namesGranting(permission: string): string[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfScopes.namesGranting(). " + permission);
    const out = this.published().filter(function (one) {
      return self.grants(one, permission);
    });
    log.debug("Leaving SsfScopes.namesGranting(). " + out.length);
    return out;
  }

  /**
   * Lists every name discovery and the protected-scope list publish: the
   * configured names first, then a profile name not already there. With the
   * defaults that is `ssf.read`, `ssf.manage`.
   *
   * @returns the published names, without duplicates
   */
  published(): string[] {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.published().");
    const out: string[] = [];
    this.pushUnique(out, this.configuredRead());
    this.pushUnique(out, this.configuredWrite());
    this.pushUnique(out, SsfScopes.PROFILE_READ);
    this.pushUnique(out, SsfScopes.PROFILE_MANAGE);
    log.debug("Leaving SsfScopes.published(). " + out.length);
    return out;
  }

  /**
   * Tells whether a name is one discovery advertises.
   *
   * @param name - one scope value
   * @returns true when `published()` contains it
   */
  isPublished(name: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.isPublished().");
    const answer = this.published().indexOf(String(name)) >= 0;
    log.debug("Leaving SsfScopes.isPublished(). " + answer);
    return answer;
  }

  // A scope string or a list, as the distinct tokens a token or a grant
  // carried. Empty tokens are dropped. Order is kept; duplicates are not.
  private tokens(held: unknown): string[] {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.tokens().");
    const raw = Array.isArray(held)
      ? held.map(function (one) {
        return String(one);
      })
      : String(held == null ? '' : held).split(/\s+/);
    const out: string[] = [];
    raw.forEach(function (one) {
      if (one && out.indexOf(one) < 0) {
        out.push(one);
      }
    });
    log.debug("Leaving SsfScopes.tokens(). " + out.length);
    return out;
  }

  /**
   * Tells whether a token's scopes cover an operation: some name it holds
   * grants the permission. Any other need is covered.
   *
   * @param held - the token's scope string, or a list of names
   * @param need - `read`, `write`, or anything else
   * @returns true when the token may attempt the operation
   */
  covers(held: unknown, need: string): boolean {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfScopes.covers(). " + need);
    if (need !== 'read' && need !== 'write') {
      log.debug("Leaving SsfScopes.covers(). (not a scope question)");
      return true;
    }
    const answer = this.tokens(held).some(function (one) {
      return self.grants(one, need);
    });
    log.debug("Leaving SsfScopes.covers(). " + answer);
    return answer;
  }

  /**
   * Tells whether a client's declaration authorizes issuing one scope: the
   * scope is a Shared Signals name and the declared names grant, between
   * them, every permission it grants. Declaring a write name therefore
   * authorizes a read name, and declaring only read names does not
   * authorize a write name.
   *
   * @param declared - the client's `oauthAllowedScope`, or null
   * @param scope - the scope being issued
   * @returns true when every permission is declared
   */
  declarationCovers(declared: string[] | null, scope: unknown): boolean {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfScopes.declarationCovers().");
    const wanted = this.permissionsOf(scope);
    if (!wanted.length || !declared || !declared.length) {
      log.debug("Leaving SsfScopes.declarationCovers(). false");
      return false;
    }
    const answer = wanted.every(function (permission) {
      return self.covers(declared, permission);
    });
    log.debug("Leaving SsfScopes.declarationCovers(). " + answer);
    return answer;
  }

  /**
   * Tells whether an operation the token covers is still declared: the
   * token holds a name granting the permission, and the client still
   * declares a name granting it. A need other than read or write is still
   * declared.
   *
   * @param held - the token's scope string, or a list of names
   * @param declared - the client's `oauthAllowedScope`, or null
   * @param need - `read`, `write`, or anything else
   * @returns true when the operation may still be honoured
   */
  stillDeclared(held: unknown, declared: string[] | null,
                need: string): boolean {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.stillDeclared(). " + need);
    if (need !== 'read' && need !== 'write') {
      log.debug("Leaving SsfScopes.stillDeclared(). (not a scope question)");
      return true;
    }
    if (!declared || !declared.length) {
      log.debug("Leaving SsfScopes.stillDeclared(). Nothing declared.");
      return false;
    }
    const answer = this.covers(held, need) && this.covers(declared, need);
    log.debug("Leaving SsfScopes.stillDeclared(). " + answer);
    return answer;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`. The exports below are FACADES. The root builds
// this module before `common/scope_policy.ts`, which reads it while judging
// a request, and nothing here calls a facade while the module loads.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SsfScopes>(
  'common/ssf_scopes',
  () => new SsfScopes(SsfScopes.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The Shared Signals scope names (#334).
 *
 * The method names below forward to the instance the composition root
 * installs.
 * @namespace
 */
export = {
  SsfScopes: SsfScopes,
  /**
   * Installs the instance the composition root built.
   */
  installInstance: (instance: SsfScopes): void => slot.install(instance),
  /**
   * Names where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  PROFILE_READ: SsfScopes.PROFILE_READ,
  PROFILE_MANAGE: SsfScopes.PROFILE_MANAGE,
  configuredRead: slot.forward('configuredRead'),
  configuredWrite: slot.forward('configuredWrite'),
  permissionsOf: slot.forward('permissionsOf'),
  namesGranting: slot.forward('namesGranting'),
  published: slot.forward('published'),
  isPublished: slot.forward('isPublished'),
  covers: slot.forward('covers'),
  declarationCovers: slot.forward('declarationCovers'),
  stillDeclared: slot.forward('stillDeclared')
};
