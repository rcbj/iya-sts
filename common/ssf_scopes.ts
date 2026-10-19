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
// Delete Stream and Stream Verification. This service's write scope was
// `ssf:write` (`ssf.authScopeWrite`). #334 replaces that name: the default
// write scope is `ssf.manage`, and `ssf:write` is not a scope this service
// treats as Shared Signals unless an operator sets the write setting back
// to it.
//
// Three names are always accepted, in both modes, even when an operator
// renames a setting:
//
//   * `ssf:read` and `ssf.read` are read. Always.
//   * `ssf.manage` is write, and it is the ONLY write name that includes
//     read. A token that carries it can read without a read scope beside it.
//
// A configured name is an ADDITIONAL accepted name of the class `classOf`
// gives it. Setting the write setting to `ssf:write`, or to any other name
// that is not `ssf.manage`, makes that name write and it does NOT include
// read. Setting the read setting to `ssf.manage` does not make `ssf.manage`
// a read name, and setting both settings to one custom name makes that name
// write without manage's inclusion of read. `classOf` must not call
// `readNames` or `writeNames`: those are built FROM `classOf`, and the call
// would recurse.
//
// ISSUANCE IS PER CLASS. A client that declares any read name may be issued
// any read name, in the spelling it asked for. A client that declares any
// write name may be issued any write name. Declaring only write does not
// authorize `ssf.read` or `ssf:read` as their own scope, and declaring only
// read does not authorize `ssf.manage`. With the defaults, declaring
// `ssf:write` authorizes nothing here, because that string is not a write
// name. That is `declarationCovers()`, which `common/scope_policy.ts` asks
// beside an exact match. SCIM is the opposite: renaming `scim.scopeWrite`
// unprotects `scim:write`. These three names stay protected whatever the
// settings say, or development would issue `ssf.read` and `ssf.manage` to
// anybody. A configured write name is protected only while the setting
// names it.
//
// THE RE-CHECK LOOKS AT THE TOKEN. `stillDeclared()` is what
// `ssf/ssf_auth.ts` asks on every call (`STS-SSF-0107`). A read passes
// while the token holds a read name and the client still declares some read
// name, or while the token holds `ssf.manage` and the client still declares
// some write name. A write passes while the token holds a write name and
// the client still declares some write name. A token that holds both a read
// name and `ssf.manage` keeps the read when either class stays declared. A
// token that holds only `ssf.manage` loses the read when the write
// declaration goes, even if a read name is still declared: manage's
// authority came from write.
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

type ScopeClass = 'read' | 'write';

interface SsfScopesDeps {
  log: { debug(message: string): void };
  config: { value(key: string): unknown };
}

/**
 * The Shared Signals scope vocabulary: the two settings, the historical
 * read name and the CAEP Interoperability Profile names (#334).
 *
 * `ssf.manage` is the write scope and includes read. A configured write
 * name other than `ssf.manage` does not. A configured name is an extra
 * name of the class `classOf` gives it.
 */
class SsfScopes {
  /** The profile's read scope (CAEP Interoperability Profile 1.0 §2.7.3). */
  static readonly PROFILE_READ = 'ssf.read';
  /** The profile's manage scope. The only write name that includes read. */
  static readonly PROFILE_MANAGE = 'ssf.manage';
  /** This service's historical read scope, and the read setting's default. */
  static readonly HISTORICAL_READ = 'ssf:read';

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

  // One setting, or its historical default when the value is empty. `0` is
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
   * @returns the configured read name, or `ssf:read`
   */
  configuredRead(): string {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.configuredRead().");
    const value = this.setting('ssf.authScopeRead',
                               SsfScopes.HISTORICAL_READ);
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
   * Tells which permission a scope name is.
   *
   * `ssf.manage` is always write. `ssf.read` and `ssf:read` are always read.
   * A configured name joins that class only when it is not one of those
   * three, and a name used for both settings is write. It does not call
   * `readNames` or `writeNames`.
   *
   * @param scope - one scope value
   * @returns `read`, `write`, or null when the name is not an SSF scope
   */
  classOf(scope: unknown): ScopeClass | null {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.classOf().");
    if (scope == null || scope === '') {
      log.debug("Leaving SsfScopes.classOf(). (empty)");
      return null;
    }
    const name = String(scope);
    if (name === SsfScopes.PROFILE_MANAGE) {
      log.debug("Leaving SsfScopes.classOf(). write");
      return 'write';
    }
    if (name === SsfScopes.PROFILE_READ ||
        name === SsfScopes.HISTORICAL_READ) {
      log.debug("Leaving SsfScopes.classOf(). read");
      return 'read';
    }
    const read = this.configuredRead();
    const write = this.configuredWrite();
    // One custom name for both settings is write, and it does not gain
    // manage's inclusion of read.
    if (name === write && name === read) {
      log.debug("Leaving SsfScopes.classOf(). write (both settings)");
      return 'write';
    }
    if (name === read && name !== write) {
      log.debug("Leaving SsfScopes.classOf(). read");
      return 'read';
    }
    if (name === write) {
      log.debug("Leaving SsfScopes.classOf(). write");
      return 'write';
    }
    log.debug("Leaving SsfScopes.classOf(). (none)");
    return null;
  }

  /**
   * Lists every read name: the configured read name when it is a read name,
   * then `ssf:read` and `ssf.read`.
   *
   * @returns the read-class names, without duplicates
   */
  readNames(): string[] {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.readNames().");
    const out: string[] = [];
    const configured = this.configuredRead();
    if (this.classOf(configured) === 'read') {
      this.pushUnique(out, configured);
    }
    this.pushUnique(out, SsfScopes.HISTORICAL_READ);
    this.pushUnique(out, SsfScopes.PROFILE_READ);
    log.debug("Leaving SsfScopes.readNames(). " + out.length);
    return out;
  }

  /**
   * Lists every write name: the configured write name when it is a write
   * name, then `ssf.manage`.
   *
   * @returns the write-class names, without duplicates
   */
  writeNames(): string[] {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.writeNames().");
    const out: string[] = [];
    const configured = this.configuredWrite();
    if (this.classOf(configured) === 'write') {
      this.pushUnique(out, configured);
    }
    this.pushUnique(out, SsfScopes.PROFILE_MANAGE);
    log.debug("Leaving SsfScopes.writeNames(). " + out.length);
    return out;
  }

  /**
   * Lists every name discovery and the protected-scope list publish.
   *
   * The configured names come first, then any historical or profile name
   * not already there. With the defaults that is `ssf:read`, `ssf.manage`,
   * `ssf.read`.
   *
   * @returns the published names, without duplicates
   */
  published(): string[] {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.published().");
    const out: string[] = [];
    this.pushUnique(out, this.configuredRead());
    this.pushUnique(out, this.configuredWrite());
    this.pushUnique(out, SsfScopes.HISTORICAL_READ);
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
   * Tells whether a token's scopes cover an operation.
   *
   * A read is covered by any read name or by `ssf.manage`. A write is
   * covered by any write name. A configured write name other than
   * `ssf.manage` does not cover a read. Any other need is covered.
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
    const names = this.tokens(held);
    const answer = need === 'write'
      ? names.some(function (one) {
        return self.classOf(one) === 'write';
      })
      : names.some(function (one) {
        return self.classOf(one) === 'read' ||
          one === SsfScopes.PROFILE_MANAGE;
      });
    log.debug("Leaving SsfScopes.covers(). " + answer);
    return answer;
  }

  /**
   * Tells whether a client's declaration authorizes issuing one scope.
   *
   * True when the scope is an SSF name and the client declares any name of
   * that same class. Declaring write does not authorize a read name, and
   * declaring read does not authorize a write name.
   *
   * @param declared - the client's `oauthAllowedScope`, or null
   * @param scope - the scope being issued
   * @returns true when the class is declared
   */
  declarationCovers(declared: string[] | null, scope: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering SsfScopes.declarationCovers().");
    const kind = this.classOf(scope);
    if (!kind || !declared || !declared.length) {
      log.debug("Leaving SsfScopes.declarationCovers(). false");
      return false;
    }
    const names = kind === 'read' ? this.readNames() : this.writeNames();
    let answer = false;
    for (let i = 0; i < declared.length; i++) {
      if (names.indexOf(String(declared[i])) >= 0) {
        answer = true;
        break;
      }
    }
    log.debug("Leaving SsfScopes.declarationCovers(). " + answer);
    return answer;
  }

  /**
   * Lists the permission classes a token's scopes give an operation.
   *
   * A read name contributes `read`. `ssf.manage` contributes `write` on a
   * read as well as on a write, because that is the declaration the read
   * rests on. Another write name contributes `write` and nothing on a read.
   *
   * @param held - the token's scope string, or a list of names
   * @param need - `read` or `write`
   * @returns the classes, `read` before `write` when both apply
   */
  authorities(held: unknown, need: string): ScopeClass[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfScopes.authorities(). " + need);
    const names = this.tokens(held);
    const out: ScopeClass[] = [];
    if (need === 'read') {
      const hasRead = names.some(function (one) {
        return self.classOf(one) === 'read';
      });
      if (hasRead) {
        out.push('read');
      }
      if (names.some(function (one) {
        return one === SsfScopes.PROFILE_MANAGE;
      })) {
        out.push('write');
      }
    } else if (need === 'write') {
      if (names.some(function (one) {
        return self.classOf(one) === 'write';
      })) {
        out.push('write');
      }
    }
    log.debug("Leaving SsfScopes.authorities(). " + out.join(','));
    return out;
  }

  /**
   * Tells whether the client still declares a class the token used.
   *
   * A need other than read or write is still declared. A token that gives
   * the operation no class is not. Otherwise one surviving class is enough:
   * a token holding both a read name and `ssf.manage` keeps a read while
   * either class stays declared.
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
    const classes = this.authorities(held, need);
    if (!classes.length || !declared || !declared.length) {
      log.debug("Leaving SsfScopes.stillDeclared(). false");
      return false;
    }
    let answer = false;
    for (let c = 0; c < classes.length && !answer; c++) {
      const names = classes[c] === 'read' ? this.readNames()
                                          : this.writeNames();
      for (let i = 0; i < declared.length; i++) {
        if (names.indexOf(String(declared[i])) >= 0) {
          answer = true;
          break;
        }
      }
    }
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
  HISTORICAL_READ: SsfScopes.HISTORICAL_READ,
  configuredRead: slot.forward('configuredRead'),
  configuredWrite: slot.forward('configuredWrite'),
  readNames: slot.forward('readNames'),
  writeNames: slot.forward('writeNames'),
  published: slot.forward('published'),
  isPublished: slot.forward('isPublished'),
  classOf: slot.forward('classOf'),
  covers: slot.forward('covers'),
  declarationCovers: slot.forward('declarationCovers'),
  authorities: slot.forward('authorities'),
  stillDeclared: slot.forward('stillDeclared')
};
