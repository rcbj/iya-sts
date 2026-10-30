// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fga_policies.ts
//
// ===========================================================================
// AN APPLICATION'S FINE-GRAINED AUTHORIZATION POLICY, AND ITS LIFECYCLE
// (#564, phase 1).
//
// The RESOURCE application that declares an `authorization_details` type
// owns the policy that decides details of that type (rcbj's decision 1).
// That policy is an ordinary entry in the realm's `ou=policies`, carrying
// the owner's identifier in `xacmlApplication` (`xacml_store.ts`), and the
// application carries the entry's name in `appFgaPolicy` and the switch in
// `appFgaEnforced` (`common/applications.js`). This module is the one place
// the two halves are kept in step:
//
//   ensure(id)   the application's policy, created from `fga-default` if it
//                has none of its own (decision 2's fallback)
//   enable(id)   ensure(), then switch enforcement on — refused while the
//                policy is disabled or does not parse
//   disable(id)  switch enforcement off; the policy is untouched
//   retire(id)   on deletion: the policy DISABLED and marked orphaned, and
//                kept for audit until an administrator removes it
//                (decision 3)
//   resolve(id)  the policy row and whether it is enforced, or a precise,
//                coded failure — what phases 3 and 4 decide with
//
// **IT FOLLOWS THE REFERENCE AND NEVER ADOPTS.** `appFgaPolicy` is how an
// application finds its policy; a policy that merely carries the identifier
// is not attached by `ensure()`. An application deleted through LDAP (which
// bypasses the retirement) and created again under the same identifier
// would otherwise inherit a policy written for the application that went —
// precisely what keeping an orphan for audit must not grant. So an
// application without a valid reference gets a NEW policy, under a fresh
// entry name if the derived one is taken.
//
// **ORPHANED IS AN EXPLICIT MARK, `xacmlOrphanedAt`, NOT A COMPUTATION.**
// "Its owner is no longer in the registry" stops being true the moment an
// application of the same identifier is created again, and the old policy
// would silently stop being an orphan and read as the new application's.
// The mark is written once, by the deletion that made it true, carries
// when, and is visible to `ldapsearch` without a registry lookup per row.
//
// Everything is in the CURRENT realm: the registry and `ou=policies` are
// both per realm, and every method here reads the ambient one.
//
// Its `wire` step fills `applications.setFgaLifecycle()` (rule 3e;
// `common/applications.js` argues it both ways round), so an application
// created through the console or the API from 23c on gets its policy.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

const { log } = helpers;

// The template every application's policy starts from.
const TEMPLATE = 'fga-default';

// How many alternative entry names `ensure()` tries when the derived one is
// taken (by an orphan of an earlier application of the same identifier, or
// by somebody's own policy). A bound, so a container full of collisions is a
// refusal rather than a loop.
const MAX_NAME_ATTEMPTS = 50;

// The longest slug kept in an entry name, which the store bounds at 128.
const MAX_SLUG = 80;

// One policy row, as `xacml_store.ts` answers it.
interface PolicyRow {
  name: string;
  id: string | null;
  version: string;
  enabled: boolean;
  description: string;
  document: string;
  application: string | null;
  orphanedAt: string | null;
  [name: string]: any;
}

// What every act answers. `why` and the non-enumerable code (`errorCodes`'
// `mark()`) on a refusal; `failure` names which one for `resolve()`.
interface FgaResult {
  ok: boolean;
  why?: string;
  failure?: string;
  policy?: string;
  row?: PolicyRow | null;
  parsed?: any;
  enforced?: boolean;
  created?: boolean;
  changed?: boolean;
}

// Who is acting, for the audit rows.
interface ActOptions {
  actor?: string;
  // retire() only: the deleted entry's appFgaPolicy.
  policy?: string;
}

interface FgaDeps {
  log: { debug(message: string): void; warn(message: string): void };
  errorCodes: {
    tag(code: string): string;
    mark<T>(target: T, code: string): T;
  };
  audit: { audit(row: Record<string, unknown>): unknown };
  store: {
    read(name: string): PolicyRow | null;
    write(name: string, document: string, options: object): any;
    remove(name: string): boolean;
    parseDocument(document: string): any;
    fgaPolicyFor(identifier: string): PolicyRow | null;
  };
  templates: {
    build(id: string, answers: object, options?: object): any;
    slug(text: unknown): string;
  };
  xml: { writePolicy(policy: any): string };
  applications: {
    get(identifier: string): any;
    authorizationDetailsTypeOf(value: unknown): any;
    fgaStateOf(identifier: string): { known: boolean; policy: string;
                                      enforced: boolean };
    setFgaState(identifier: string, change: object, options: object): any;
    setFgaLifecycle(hooks: object | null): void;
  };
  // The mapping's coverage question (#564, P3): what a type leaves neither
  // mapped nor deliberately out.
  map: { uncovered(definition: any): string[] };
  sha256Hex(text: string): string;
  now(): Date;
}

/**
 * An application's fine-grained authorization policy and its lifecycle:
 * created with the application, enforced by a switch, retired with it.
 */
class FgaPolicies {
  /**
   * The template every application's policy is created from.
   */
  static readonly TEMPLATE = TEMPLATE;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, error codes, the audit log, the policy store,
   *   the templates, the XML writer, the application registry, a SHA-256
   *   and a clock
   */
  constructor(private readonly deps: FgaDeps) {
    deps.log.debug("Entering FgaPolicies.constructor().");
    deps.log.debug("Leaving FgaPolicies.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): FgaDeps {
    log.debug("Entering FgaPolicies.defaultDeps().");
    const crypto: typeof import('../common/crypto') =
      require('../common/crypto');
    log.debug("Leaving FgaPolicies.defaultDeps().");
    return {
      log: log,
      errorCodes: require('../common/error_codes'),
      audit: require('../common/audit'),
      store: require('./xacml_store'),
      templates: require('./xacml_templates'),
      xml: require('./xacml_xml'),
      applications: require('../common/applications'),
      map: require('./fga_map'),
      sha256Hex: function (text: string): string {
        return crypto.digest('sha256', text, 'hex');
      },
      now: function (): Date {
        return new Date();
      }
    };
  }

  // A refusal, coded, naming which failure it is.
  private refused(code: string, failure: string, why: string,
                  extra?: Partial<FgaResult>): FgaResult {
    const { log, errorCodes } = this.deps;
    log.debug("Entering FgaPolicies.refused(). " + code);
    log.debug("Leaving FgaPolicies.refused().");
    return errorCodes.mark(Object.assign({ ok: false, failure: failure,
                                           why: why }, extra || {}), code);
  }

  // -------------------------------------------------------------------------
  // THE ENTRY NAME. Derived from the identifier so that `ldapsearch` shows
  // whose a policy is at a glance: `fga-`, a slug of the identifier, and the
  // first twelve hex digits of its SHA-256 — the slug for a reader, the
  // digest because the slug is lossy (`a.b` and `a-b` slug alike) and the
  // store's names are 1 to 128 of `[A-Za-z0-9._-]`. The PolicyId inside the
  // document is the unambiguous one (`fgaPolicyId()`); this is a handle.
  // -------------------------------------------------------------------------
  /**
   * Returns the entry name an application's policy is first given.
   *
   * @param identifier - the application's identifier
   * @returns `fga-<slug>-<12 hex digits>`
   */
  nameFor(identifier: string): string {
    const { log, templates, sha256Hex } = this.deps;
    log.debug("Entering FgaPolicies.nameFor().");
    const slug = templates.slug(identifier).slice(0, MAX_SLUG)
      .replace(/-+$/, '') || 'x';
    const name = 'fga-' + slug + '-' +
                 sha256Hex(String(identifier)).slice(0, 12);
    log.debug("Leaving FgaPolicies.nameFor(). " + name);
    return name;
  }

  // The derived name, or the first `-2`, `-3`… that no entry holds.
  private freeName(identifier: string): string | null {
    const { log, store } = this.deps;
    log.debug("Entering FgaPolicies.freeName().");
    const base = this.nameFor(identifier);
    for (let n = 1; n <= MAX_NAME_ATTEMPTS; n++) {
      const name = n === 1 ? base : base + '-' + n;
      if (!store.read(name)) {
        log.debug("Leaving FgaPolicies.freeName(). " + name);
        return name;
      }
    }
    log.debug("Leaving FgaPolicies.freeName(). None free.");
    return null;
  }

  // The application's OWN, live policy through its reference, or null.
  private ownPolicy(identifier: string, reference: string): PolicyRow | null {
    const { log, store } = this.deps;
    log.debug("Entering FgaPolicies.ownPolicy().");
    const row = reference ? store.read(reference) : null;
    const own = !!row && row.application === identifier && !row.orphanedAt;
    log.debug("Leaving FgaPolicies.ownPolicy(). " + (own ? 'Own.' : 'None.'));
    return own ? row : null;
  }

  // when, as LDAP writes a timestamp (RFC 4517's GeneralizedTime), which is
  // what `createTimestamp` beside it on the same entry looks like.
  private generalizedTime(): string {
    const { log, now } = this.deps;
    log.debug("Entering FgaPolicies.generalizedTime().");
    const text = now().toISOString().replace(/[-:T]/g, '')
      .replace(/\.\d+Z$/, 'Z');
    log.debug("Leaving FgaPolicies.generalizedTime(). " + text);
    return text;
  }

  // -------------------------------------------------------------------------
  // ENSURE. The create hook, and the first half of enable().
  // -------------------------------------------------------------------------
  /**
   * Gives an application its default fine-grained policy if it has none of
   * its own: one built from `fga-default`, written to `ou=policies` with
   * `xacmlApplication`, and named on the application as `appFgaPolicy`.
   *
   * @param identifier - the application's identifier
   * @param options - `actor`
   * @returns `{ ok, policy, created }`, or a refusal: an unknown
   *   application (STS-FGA-0009), a policy that could not be written
   *   (STS-FGA-0008) or a reference that could not be (STS-FGA-0012)
   */
  ensure(identifier: string, options?: ActOptions): FgaResult {
    const { log, store, templates, xml, applications, audit } = this.deps;
    const id = String(identifier);
    const actor = (options && options.actor) || '';
    log.debug("Entering FgaPolicies.ensure(). identifier=" + id);
    const state = applications.fgaStateOf(id);
    if (!state.known) {
      log.debug("Leaving FgaPolicies.ensure(). Unknown application.");
      return this.refused('STS-FGA-0009', 'unknown-application',
                          'There is no application called "' + id +
                          '" in this realm.');
    }
    const own = this.ownPolicy(id, state.policy);
    if (own) {
      log.debug("Leaving FgaPolicies.ensure(). It has one: " + own.name);
      return { ok: true, policy: own.name, created: false };
    }
    const name = this.freeName(id);
    if (!name) {
      log.debug("Leaving FgaPolicies.ensure(). No free name.");
      return this.refused('STS-FGA-0008', 'not-written',
                          'No entry name is free for the fine-grained ' +
                          'policy of "' + id + '": ' + this.nameFor(id) +
                          ' and ' + (MAX_NAME_ATTEMPTS - 1) +
                          ' alternatives are all taken.');
    }
    const built = templates.build(TEMPLATE, { application: id });
    if (!built.ok) {
      log.debug("Leaving FgaPolicies.ensure(). The template refused.");
      return this.refused('STS-FGA-0008', 'not-written',
                          'The ' + TEMPLATE + ' template did not build: ' +
                          built.why);
    }
    const written = store.write(name, xml.writePolicy(built.policy), {
      enabled: true, isRoot: false, description: built.policy.description,
      application: id, orphanedAt: null });
    if (!written.ok) {
      log.debug("Leaving FgaPolicies.ensure(). The store refused.");
      return this.refused('STS-FGA-0008', 'not-written',
                          'The fine-grained policy of "' + id + '" could ' +
                          'not be written: ' + written.why);
    }
    const referenced = applications.setFgaState(id, { policy: name },
                                                { actor: actor });
    if (!referenced.ok) {
      // TAKEN BACK, so that a failed reference never leaves a policy that
      // carries the identifier and that nothing names: `ensure()` follows
      // the reference and would never find it again.
      store.remove(name);
      log.debug("Leaving FgaPolicies.ensure(). The reference was refused.");
      return this.refused('STS-FGA-0012', 'not-referenced',
                          (referenced.errors || []).join(' ') ||
                          'The application would not take the reference.');
    }
    audit.audit({ action: 'xacml.policy.write', actor: actor,
                  protocol: 'XACML',
                  detail: 'Created "' + name + '", the fine-grained ' +
                          'authorization policy of the application "' + id +
                          '", from the ' + TEMPLATE + ' template.' });
    log.debug("Leaving FgaPolicies.ensure(). Created " + name);
    return { ok: true, policy: name, created: true };
  }

  // -------------------------------------------------------------------------
  // THE SWITCH.
  // -------------------------------------------------------------------------
  /**
   * Switches fine-grained authorization on for an application: ensures its
   * policy, then sets `appFgaEnforced`. Refused while the policy is
   * disabled (STS-FGA-0006) or does not parse (STS-FGA-0007), because an
   * enforced application with such a policy refuses every detail — the
   * moment to say so is while somebody is switching it on.
   *
   * @param identifier - the application's identifier
   * @param options - `actor`
   * @returns `{ ok, policy, enforced: true, changed }`, or a refusal
   */
  enable(identifier: string, options?: ActOptions): FgaResult {
    const { log, applications } = this.deps;
    const id = String(identifier);
    log.debug("Entering FgaPolicies.enable(). identifier=" + id);
    const gaps = this.uncoveredTypes(id);
    if (gaps.length) {
      log.debug("Leaving FgaPolicies.enable(). Uncovered types.");
      return this.refused('STS-FGA-0018', 'uncovered-type',
                          'Fine-grained authorization cannot be enforced ' +
                          'on "' + id + '" while a type it declares has ' +
                          'members that are neither mapped (xacml) nor ' +
                          'listed in notForPolicy: ' + gaps.map(
                            function (one) {
                              return one.type + ' (' +
                                     one.paths.join(', ') + ')';
                            }).join('; ') + '. A detail carrying such a ' +
                          'member could never reach the policy, so every ' +
                          'one would be refused. Map each, list it in ' +
                          'notForPolicy, or close the schema ' +
                          '(additionalProperties: false) where "*" is ' +
                          'shown.');
    }
    const ensured = this.ensure(id, options);
    if (!ensured.ok) {
      log.debug("Leaving FgaPolicies.enable(). Not ensured.");
      return ensured;
    }
    const resolved = this.resolve(id);
    if (!resolved.ok) {
      log.debug("Leaving FgaPolicies.enable(). " + resolved.failure);
      return resolved;
    }
    const set = applications.setFgaState(id, { enforced: true },
      { actor: (options && options.actor) || '' });
    if (!set.ok) {
      log.debug("Leaving FgaPolicies.enable(). Not written.");
      return this.refused('STS-FGA-0012', 'not-referenced',
                          (set.errors || []).join(' ') ||
                          'The application would not take the switch.');
    }
    log.debug("Leaving FgaPolicies.enable().");
    return { ok: true, policy: ensured.policy, enforced: true,
             changed: !!set.changed };
  }

  // -------------------------------------------------------------------------
  // COVERAGE (#564, P3): the types an application declares whose
  // `fga_map.uncovered()` is not empty. Asked before enforcement is
  // switched on — a detail with an uncovered member is refused at every
  // issuance (STS-FGA-0103), so an enforced application with such a type
  // would refuse all of them, and the moment to say so is while somebody is
  // switching it on. A value the registry cannot read is skipped here: the
  // write doors refuse one (STS-REG-0112), and `declaredTypes()` ignores it.
  // -------------------------------------------------------------------------
  /**
   * Lists the types an application declares that fine-grained
   * authorization could not cover, with the uncovered member paths.
   *
   * @param identifier - the application's identifier
   * @returns `[{ type, paths }]`, empty when every type is covered
   */
  uncoveredTypes(identifier: string): Array<{ type: string;
                                              paths: string[] }> {
    const { log, applications, map } = this.deps;
    log.debug("Entering FgaPolicies.uncoveredTypes().");
    const entry = applications.get(String(identifier));
    const fields = (entry && entry.fields) || {};
    const raw = fields.oauthAuthorizationDetailsType;
    const values = raw === undefined || raw === null ? []
      : (Array.isArray(raw) ? raw : [raw]);
    const out: Array<{ type: string; paths: string[] }> = [];
    values.forEach(function (value: unknown) {
      const definition = applications.authorizationDetailsTypeOf(value);
      if (!definition || definition.problem) {
        return;
      }
      const paths = map.uncovered(definition);
      if (paths.length) {
        out.push({ type: String(definition.type), paths: paths });
      }
    });
    log.debug("Leaving FgaPolicies.uncoveredTypes(). " + out.length);
    return out;
  }

  /**
   * Switches fine-grained authorization off for an application. Its policy
   * is left exactly as it is.
   *
   * @param identifier - the application's identifier
   * @param options - `actor`
   * @returns `{ ok, enforced: false, changed }`, or a refusal
   */
  disable(identifier: string, options?: ActOptions): FgaResult {
    const { log, applications } = this.deps;
    const id = String(identifier);
    log.debug("Entering FgaPolicies.disable(). identifier=" + id);
    if (!applications.fgaStateOf(id).known) {
      log.debug("Leaving FgaPolicies.disable(). Unknown application.");
      return this.refused('STS-FGA-0009', 'unknown-application',
                          'There is no application called "' + id +
                          '" in this realm.');
    }
    const set = applications.setFgaState(id, { enforced: false },
      { actor: (options && options.actor) || '' });
    if (!set.ok) {
      log.debug("Leaving FgaPolicies.disable(). Not written.");
      return this.refused('STS-FGA-0012', 'not-referenced',
                          (set.errors || []).join(' ') ||
                          'The application would not take the switch.');
    }
    log.debug("Leaving FgaPolicies.disable().");
    return { ok: true, enforced: false, changed: !!set.changed };
  }

  // -------------------------------------------------------------------------
  // RETIRE. The delete hook. The application is already gone, so the
  // reference arrives as an argument, read before the entry went; failing
  // that, the live policy carrying the identifier is the one.
  // -------------------------------------------------------------------------
  /**
   * Retires a deleted application's policy: disabled, marked
   * `xacmlOrphanedAt`, and kept. A policy that is not that application's
   * own is never touched.
   *
   * @param identifier - the deleted application's identifier
   * @param options - `actor`, and `policy`: its appFgaPolicy
   * @returns `{ ok, policy, changed }`, or a refusal (STS-FGA-0013)
   */
  retire(identifier: string, options?: ActOptions): FgaResult {
    const { log, store, audit } = this.deps;
    const id = String(identifier);
    const opts = options || {};
    log.debug("Entering FgaPolicies.retire(). identifier=" + id);
    const row = this.ownPolicy(id, String(opts.policy || '')) ||
                store.fgaPolicyFor(id);
    if (!row) {
      log.debug("Leaving FgaPolicies.retire(). It had none.");
      return { ok: true, changed: false };
    }
    const when = this.generalizedTime();
    const written = store.write(row.name, row.document, {
      enabled: false, isRoot: false, description: row.description,
      application: id, orphanedAt: when });
    if (!written.ok) {
      log.debug("Leaving FgaPolicies.retire(). The store refused.");
      return this.refused('STS-FGA-0013', 'not-retired',
                          'The fine-grained policy "' + row.name + '" of ' +
                          'the deleted application "' + id + '" could not ' +
                          'be disabled and marked orphaned: ' + written.why);
    }
    audit.audit({ action: 'xacml.policy.write', actor: opts.actor || '',
                  protocol: 'XACML',
                  detail: 'Retired "' + row.name + '": the application "' +
                          id + '" was deleted, so its fine-grained ' +
                          'authorization policy is disabled and kept, ' +
                          'orphaned since ' + when + ', until an ' +
                          'administrator removes it.' });
    log.debug("Leaving FgaPolicies.retire(). " + row.name);
    return { ok: true, policy: row.name, changed: true };
  }

  // -------------------------------------------------------------------------
  // RESOLVE. What phases 3 and 4 decide with: the policy, parsed, and
  // whether it is enforced — or exactly why there is none to decide with.
  // Each failure is its own code, because "the policy is disabled" and "the
  // reference names somebody else's policy" are fixed in different places.
  // A failure still says whether the application is enforced, since only an
  // enforced application's failure refuses anything.
  // -------------------------------------------------------------------------
  /**
   * Resolves an application's fine-grained policy.
   *
   * @param identifier - the application's identifier
   * @returns `{ ok: true, policy, row, parsed, enforced }`, or a refusal
   *   whose `failure` is `unknown-application` (STS-FGA-0009), `no-policy`
   *   (0003), `missing-policy` (0004), `not-its-policy` (0005),
   *   `disabled-policy` (0006) or `unparseable-policy` (0007), carrying
   *   `enforced`
   */
  resolve(identifier: string): FgaResult {
    const { log, store, errorCodes } = this.deps;
    const id = String(identifier);
    log.debug("Entering FgaPolicies.resolve(). identifier=" + id);
    const state = this.deps.applications.fgaStateOf(id);
    if (!state.known) {
      log.debug("Leaving FgaPolicies.resolve(). Unknown application.");
      return this.refused('STS-FGA-0009', 'unknown-application',
                          'There is no application called "' + id +
                          '" in this realm.', { enforced: false });
    }
    const enforced = state.enforced;
    if (!state.policy) {
      log.debug("Leaving FgaPolicies.resolve(). No reference.");
      return this.refused('STS-FGA-0003', 'no-policy',
                          'The application "' + id + '" has no ' +
                          'fine-grained policy (appFgaPolicy is empty).',
                          { enforced: enforced });
    }
    const row = store.read(state.policy);
    if (!row) {
      log.debug("Leaving FgaPolicies.resolve(). The entry is not there.");
      return this.refused('STS-FGA-0004', 'missing-policy',
                          'The fine-grained policy "' + state.policy +
                          '" of the application "' + id + '" is not in ' +
                          'ou=policies.', { enforced: enforced });
    }
    if (row.application !== id || row.orphanedAt) {
      log.debug("Leaving FgaPolicies.resolve(). Not its own.");
      return this.refused('STS-FGA-0005', 'not-its-policy',
                          'The policy "' + row.name + '" that the ' +
                          'application "' + id + '" names is not its own: ' +
                          (row.orphanedAt
                            ? 'it is orphaned since ' + row.orphanedAt + '.'
                            : (row.application
                                ? 'it belongs to "' + row.application + '".'
                                : 'it carries no xacmlApplication.')),
                          { enforced: enforced, row: row });
    }
    if (!row.enabled) {
      log.debug("Leaving FgaPolicies.resolve(). Disabled.");
      return this.refused('STS-FGA-0006', 'disabled-policy',
                          'The fine-grained policy "' + row.name + '" of ' +
                          'the application "' + id + '" is disabled.',
                          { enforced: enforced, row: row });
    }
    let parsed = null;
    try {
      parsed = store.parseDocument(row.document);
    } catch (error) {
      log.debug("Caught in FgaPolicies.resolve(): " +
                ((error && error.message) || error));
      log.warn(errorCodes.tag('STS-FGA-0007') +
               'fga: the fine-grained policy "' + row.name + '" of "' + id +
               '" does not parse: ' + ((error && error.message) || error));
      log.debug("Leaving FgaPolicies.resolve(). Does not parse.");
      return this.refused('STS-FGA-0007', 'unparseable-policy',
                          'The fine-grained policy "' + row.name + '" of ' +
                          'the application "' + id + '" does not parse: ' +
                          ((error && error.message) || error),
                          { enforced: enforced, row: row });
    }
    log.debug("Leaving FgaPolicies.resolve(). " + row.name +
              (enforced ? ', enforced.' : ', not enforced.'));
    return { ok: true, policy: row.name, row: row, parsed: parsed,
             enforced: enforced };
  }

  /**
   * Fills `applications.setFgaLifecycle()`: `created` ensures the new
   * application's policy, `deleted` retires the deleted one's.
   */
  installLifecycle(): void {
    const self = this;
    const { log, applications } = this.deps;
    log.debug("Entering FgaPolicies.installLifecycle().");
    applications.setFgaLifecycle({
      created: function (identifier: string, actor: string): FgaResult {
        return self.ensure(identifier, { actor: actor });
      },
      deleted: function (identifier: string, actor: string,
                         policy: string): FgaResult {
        return self.retire(identifier, { actor: actor, policy: policy });
      }
    });
    log.debug("Leaving FgaPolicies.installLifecycle().");
  }
}

// The module's own work with its instance: the lifecycle slot.
function wireFga(instance: FgaPolicies): void {
  log.debug("Entering wireFga().");
  instance.installLifecycle();
  log.debug("Leaving wireFga().");
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) at 23c.
const slot = new InstanceSlot<FgaPolicies>(
  'xacml/fga_policies',
  () => new FgaPolicies(FgaPolicies.defaultDeps()),
  wireFga,
  helpers.log);

// Standalone, build the default now, as every module on the pattern does.
slot.buildNowUnlessDeferred();

/**
 * Application-scoped fine-grained authorization (#564): each application's
 * policy, the switch that enforces it, and its retirement.
 * @namespace
 */
export = {
  FgaPolicies: FgaPolicies,
  installInstance: (instance: FgaPolicies): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  TEMPLATE: FgaPolicies.TEMPLATE,
  nameFor: slot.forward('nameFor'),
  ensure: slot.forward('ensure'),
  enable: slot.forward('enable'),
  uncoveredTypes: slot.forward('uncoveredTypes'),
  disable: slot.forward('disable'),
  retire: slot.forward('retire'),
  resolve: slot.forward('resolve')
};
