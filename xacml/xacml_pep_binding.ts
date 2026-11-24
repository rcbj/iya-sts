// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_binding.ts
//
// ===========================================================================
// AN EMBEDDED REMOTE PEP, BOUND TO THE ONE APPLICATION IT IS EMBEDDED IN
// (#2025, work item 2 of #1206; rcbj's decision D1, 2026-11-23).
//
// An authentication library (`oidc-caep-risc`, `saml2-sp`, `wsfed-caep`,
// `gnap-caep-risc`, in every language) may carry the remote PEP inside the
// application it serves, through the shared `iya-pep-<lang>` package. Two
// principals then live in one process, and rcbj chose to keep them apart:
//
//   * THE APPLICATION signs people in through its own client registration,
//     with its own credential, exactly as before;
//   * THE PEP signs in as a SERVICE ACCOUNT holding REMOTE_PEPS, with its own
//     key, certified by `issue-pep-credential` (`xacml_pep_credential.ts`),
//     through `sts-remote-pep` — the 1.1.0 path, unchanged.
//
// What ties the two together is THIS: one attribute on the PEP's entry,
// `stsPepApplication`, naming the application's identifier in the realm's
// registry, set by an administrator. A registration (#2026) is refused
// unless the binding names the application the PEP says it is embedded in,
// so a PEP key copied into another application cannot pose as that
// application's PEP; and the policy pull (#2027), the AuthZEN scope (#2026)
// and the policy-change event (#2028) all read it.
//
// ---------------------------------------------------------------------------
// WHO MAY BE BOUND: the entry a PEP door would admit, and nobody else — the
// same three questions `issue-pep-credential` asks, for the same reason (a
// binding on an entry every PEP door refuses would be a setting that does
// nothing and reads as one that does):
//
//   1. THERE (STS-XACML-0334) — a username under this realm's `ou=users`;
//   2. A SERVICE ACCOUNT HOLDING REMOTE_PEPS (STS-XACML-0335);
//   3. AND THE APPLICATION IS IN THE REGISTRY (STS-XACML-0336). Read through
//      `applications.get()`, which is the registry's own answer, never a
//      directory walk of ours.
//
// **NO REGISTERED `ou=peps` ROW IS ASKED FOR** — `issue-pep-credential`'s
// rule: the binding is provisioned before the PEP ever starts, so the
// registration that checks it has something to check.
//
// **ONE APPLICATION PER PEP.** The attribute is single-valued. A PEP is
// embedded in one application; a second application is a second PEP with
// its own key. Clearing is the same act with no application.
//
// ---------------------------------------------------------------------------
// THE DIRECTORY IS REACHED THROUGH A SLOT, `setDirectory()`, FILLED BY
// `ldap/ldap_server.js` AT REQUIRE TIME — `authzen/authzen_admin.ts`'s
// arrangement, for its reason. Rule 3e's test:
//
//   * a require of `ldap_server.js` from here at load would put every
//     `/admin/ldap/*` route wherever this module is first required, and the
//     console requires it at 18, ahead of the directory at 21;
//   * a LAZY require would reach a directory that exports no person writer:
//     `writePersonAttribute()` is not exported, on purpose, because an
//     `sts*` attribute is refused by every door but the one that owns it.
//
// So the slot carries a write RESTRICTED TO THIS ONE ATTRIBUTE, a lookup
// that reads the value as the store reads it (so no module outside the store
// reads `stsPepApplication` by its LDAP name — `tests/model_entry_reads.js`),
// and the list of holders. VALIDATED WHOLE: a slot that could read and not
// write would draw a binding nobody can change.
//
// ---------------------------------------------------------------------------
// AN APPLICATION DELETED TAKES ITS BINDINGS WITH IT. `ldap_server.js`'s
// `noteApplicationRemoved()` — the one place both doors that delete an
// application reach — calls `applicationRemoved()`, which clears every
// binding naming the identifier and writes an audit row for each. Without it
// an application registered later under the same identifier would inherit
// the PEPs bound to the one deleted.
//
// A LIBRARY: it registers no route. `xacml_admin.ts` answers
// `set-pep-application` and `clear-pep-application` for the console and
// `/admin-api` (rule 7), and `issue-pep-credential` sets a binding in the
// same call when it is given an application.
// ===========================================================================

import helpers = require('../common/helpers');
import audit = require('../common/audit');
import errorCodes = require('../common/error_codes');

type Json = any;

/**
 * The built-in role a remote PEP's entry holds through its group.
 */
const REMOTE_PEP_ROLE = 'REMOTE_PEPS';

/**
 * The attribute the binding is held in. Named here for the slot's restricted
 * write, and for nothing that reads it: the store reads it.
 */
const ATTRIBUTE = 'stsPepApplication';

/**
 * What the directory's slot offers: an entry by username, the restricted
 * write, and every holder of the attribute in the ambient realm.
 */
interface BindingDirectory {
  // `{ dn, name, person, serviceAccount, application }`, or null.
  locate(name: string): {
    dn: string; name: string; person: boolean; serviceAccount: boolean;
    application: string;
  } | null;
  // The binding written ('' removes it); false when the store refused.
  write(dn: string, application: string): boolean;
  // Every person holding a binding, with the application it names.
  holders(): Array<{ dn: string; name: string; application: string }>;
}

let directory: BindingDirectory | null = null;

// The instance `shared()` builds, for the callers that are not the console
// (`ldap_server.js`'s application delete).
let sharedInstance: PepBinding | null = null;

// What every act answers. A refusal carries its code under a Symbol
// (`errorCodes.mark()`).
interface BindingResult {
  ok: boolean;
  why?: string;
  [member: string]: unknown;
}

interface PepBindingDeps {
  log: typeof helpers.log;
  audit: { audit(row: object): unknown };
  errorCodes: { mark<T>(result: T, code: string): T };
  // The directory's slot, or null where no directory was installed.
  directory(): BindingDirectory | null;
  // `common/roles.js`'s `rolesOf()`.
  rolesOf(who: object): string[];
  // Whether the realm's registry holds an application by this identifier.
  applicationExists(identifier: string): boolean;
  // `roles.remotePepGroup`, for the refusal's sentence.
  remotePepGroup(): string;
}

/**
 * Binds an embedded remote PEP's service account to the one application it
 * is embedded in (#2025), and answers who is bound to what.
 */
class PepBinding {
  /**
   * The attribute the binding is held in.
   */
  static readonly ATTRIBUTE = ATTRIBUTE;

  /**
   * Builds the act over its dependencies.
   *
   * @param deps - the logger, audit log, error codes, directory slot, roles,
   *   registry and the remote PEPs group's name
   */
  constructor(private readonly deps: PepBindingDeps) {
    deps.log.debug("Entering PepBinding.constructor().");
    deps.log.debug("Leaving PepBinding.constructor().");
  }

  /**
   * Fills the directory's slot. Called by `ldap/ldap_server.js` at require
   * time. A partial object is refused whole (rule 3e).
   *
   * @param hooks - `locate`, `write` and `holders`, or null to empty it
   */
  static setDirectory(hooks: BindingDirectory | null): void {
    helpers.log.debug("Entering PepBinding.setDirectory().");
    const whole = !!hooks && typeof hooks.locate === 'function' &&
                  typeof hooks.write === 'function' &&
                  typeof hooks.holders === 'function';
    directory = whole ? hooks : null;
    if (hooks && !whole) {
      helpers.log.warn(errorCodes.tag('STS-XACML-0337') + 'xacml: the ' +
                       'directory offered an incomplete PEP binding slot, ' +
                       'so no embedded PEP can be bound or listed.');
    }
    helpers.log.debug("Leaving PepBinding.setDirectory().");
  }

  /**
   * The one instance over the real modules, built at first use, for a
   * caller that holds none (`ldap_server.js`'s application delete).
   *
   * @returns the instance
   */
  static shared(): PepBinding {
    helpers.log.debug("Entering PepBinding.shared().");
    if (!sharedInstance) {
      sharedInstance = new PepBinding(PepBinding.defaultDeps());
    }
    helpers.log.debug("Leaving PepBinding.shared().");
    return sharedInstance;
  }

  /**
   * Returns the dependencies built from the real modules, each reached
   * LAZILY: `roles.js`, `applications.js` and `config.js` are loaded long
   * before an administrator binds anything.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PepBindingDeps {
    helpers.log.debug("Entering PepBinding.defaultDeps().");
    helpers.log.debug("Leaving PepBinding.defaultDeps().");
    return {
      log: helpers.log,
      audit: audit,
      errorCodes: errorCodes,
      directory: function (): BindingDirectory | null {
        helpers.log.debug("Entering directory().");
        helpers.log.debug("Leaving directory().");
        return directory;
      },
      rolesOf: function (who: object): string[] {
        helpers.log.debug("Entering rolesOf().");
        helpers.log.debug("Leaving rolesOf().");
        return require('../common/roles').rolesOf(who);
      },
      applicationExists: function (identifier: string): boolean {
        helpers.log.debug("Entering applicationExists().");
        const found = !!require('../common/applications').get(identifier);
        helpers.log.debug("Leaving applicationExists(). " + found);
        return found;
      },
      remotePepGroup: function (): string {
        helpers.log.debug("Entering remotePepGroup().");
        helpers.log.debug("Leaving remotePepGroup().");
        return String(require('../common/config')
          .value('roles.remotePepGroup') || '');
      }
    };
  }

  // A refusal in the shape `xacml_admin.ts` answers: `why`, and the code.
  private refuse(code: string, why: string): BindingResult {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepBinding.refuse(). code=" + code);
    log.debug("Leaving PepBinding.refuse().");
    return errorCodes.mark({ ok: false, why: why }, code);
  }

  // The PEP named in a body: `name`, or `pep`.
  private static nameOf(body: Json): string {
    helpers.log.debug("Entering PepBinding.nameOf().");
    const b = body || {};
    helpers.log.debug("Leaving PepBinding.nameOf().");
    return String(b.name || b.pep || '').trim();
  }

  /**
   * Asks whether a PEP's entry may carry a binding, without writing
   * anything: there, a service account, holding REMOTE_PEPS. Also asked by
   * `issue-pep-credential` before it certifies, so a binding that would be
   * refused does not leave a certified key behind it.
   *
   * @param name - the PEP's username
   * @returns `{ ok: true, entry }`, or a refusal with its code
   */
  eligible(name: string): BindingResult {
    const { log } = this.deps;
    log.debug('Entering PepBinding.eligible(). name=' + name);
    const dir = this.deps.directory();
    if (!dir) {
      log.debug('Leaving PepBinding.eligible(). No directory.');
      return this.refuse('STS-XACML-0337', 'The directory is not ' +
                         'available, so no binding can be read or written.');
    }
    if (!name) {
      log.debug('Leaving PepBinding.eligible(). No name.');
      return this.refuse('STS-XACML-0334', 'Which remote PEP? Send `name` ' +
                         '(or `pep`): the username of its entry under this ' +
                         'realm\'s ou=users.');
    }
    const entry = dir.locate(name);
    if (!entry || !entry.person) {
      log.debug('Leaving PepBinding.eligible(). Nobody.');
      return this.refuse('STS-XACML-0334', 'There is nobody called "' +
                         name + '" in this realm\'s ou=users. An embedded ' +
                         'PEP is bound on the entry it signs in as: create ' +
                         'it (a service account in the remote PEPs group) ' +
                         'first.');
    }
    if (!entry.serviceAccount) {
      log.debug('Leaving PepBinding.eligible(). Not a service account.');
      return this.refuse('STS-XACML-0335', '"' + name + '" is not a service ' +
                         'account. Only a remote PEP\'s identity is bound to ' +
                         'an application, and a remote PEP\'s identity is a ' +
                         'service account: putting the entry in the remote ' +
                         'PEPs group makes it one.');
    }
    const held = this.deps.rolesOf({ kind: 'user', name: entry.dn,
                                     authenticated: true });
    if (held.indexOf(REMOTE_PEP_ROLE) < 0) {
      log.debug('Leaving PepBinding.eligible(). No REMOTE_PEPS.');
      return this.refuse('STS-XACML-0335', '"' + name + '" does not hold ' +
                         REMOTE_PEP_ROLE + ': it is not a member of the ' +
                         'group roles.remotePepGroup names ("' +
                         this.deps.remotePepGroup() + '"). Add it to the ' +
                         'group first.');
    }
    log.debug('Leaving PepBinding.eligible(). Yes.');
    return { ok: true, entry: entry };
  }

  /**
   * Asks whether an application may be bound: named, and in the realm's
   * registry.
   *
   * @param application - the application's identifier
   * @returns `{ ok: true }`, or a refusal with its code
   */
  applicationProblem(application: string): BindingResult | null {
    const { log } = this.deps;
    log.debug('Entering PepBinding.applicationProblem(). ' + application);
    if (!application) {
      log.debug('Leaving PepBinding.applicationProblem(). None named.');
      return this.refuse('STS-XACML-0336', 'Which application is the PEP ' +
                         'embedded in? Send `application`: its identifier ' +
                         'in this realm\'s registry. To remove a binding, ' +
                         'use clear-pep-application.');
    }
    if (!this.deps.applicationExists(application)) {
      log.debug('Leaving PepBinding.applicationProblem(). Unknown.');
      return this.refuse('STS-XACML-0336', 'This realm\'s registry holds no ' +
                         'application "' + application + '". An embedded ' +
                         'PEP is bound to an application that exists: ' +
                         'register it first.');
    }
    log.debug('Leaving PepBinding.applicationProblem(). None.');
    return null;
  }

  /**
   * Binds a PEP's service account to the application it is embedded in,
   * replacing any binding it had. Audited as `xacml.pep.binding`.
   *
   * @param body - `name` (or `pep`) and `application`
   * @param actor - who did it, for the audit row
   * @returns `{ ok, what, pep, application, previous }`, or a refusal
   */
  set(body?: Json, actor?: string): BindingResult {
    const { log, audit } = this.deps;
    const name = PepBinding.nameOf(body);
    const application = String((body || {}).application || '').trim();
    log.debug('Entering PepBinding.set(). name=' + name + ', application=' +
              application);
    const may = this.eligible(name);
    if (!may.ok) {
      log.debug('Leaving PepBinding.set(). Not eligible.');
      return may;
    }
    const problem = this.applicationProblem(application);
    if (problem) {
      log.debug('Leaving PepBinding.set(). The application.');
      return problem;
    }
    const entry = (may as Json).entry;
    const previous = String(entry.application || '');
    if (previous === application) {
      log.debug('Leaving PepBinding.set(). Already bound.');
      return { ok: true, pep: name, application: application,
               previous: previous,
               what: '"' + name + '" was already bound to "' + application +
                     '". Nothing changed.' };
    }
    const dir = this.deps.directory() as BindingDirectory;
    if (!dir.write(entry.dn, application)) {
      log.debug('Leaving PepBinding.set(). The directory refused.');
      return this.refuse('STS-XACML-0337', 'The directory refused to write ' +
                         '"' + name + '"\'s binding. Nothing changed.');
    }
    audit.audit({ action: 'xacml.pep.binding', actor: actor || '',
                  target: name, protocol: 'XACML',
                  detail: 'Bound the embedded remote PEP "' + name +
                          '" to the application "' + application + '"' +
                          (previous ? ' (it was bound to "' + previous +
                                      '")' : '') + '.' });
    log.debug('Leaving PepBinding.set(). Bound.');
    return { ok: true, pep: name, application: application,
             previous: previous,
             what: 'Bound the embedded remote PEP "' + name + '" to "' +
                   application + '"' +
                   (previous ? ', replacing "' + previous + '"' : '') +
                   '. A registration as an embedded PEP is checked against ' +
                   'it.' };
  }

  /**
   * Removes a PEP's binding. Removing one that is not there is not a
   * refusal: the act is idempotent, as a script that clears on every run
   * needs. Audited when something was removed.
   *
   * @param body - `name` (or `pep`)
   * @param actor - who did it, for the audit row
   * @returns `{ ok, what, pep, application: '', previous }`, or a refusal
   */
  clear(body?: Json, actor?: string): BindingResult {
    const { log, audit } = this.deps;
    const name = PepBinding.nameOf(body);
    log.debug('Entering PepBinding.clear(). name=' + name);
    const dir = this.deps.directory();
    if (!dir) {
      log.debug('Leaving PepBinding.clear(). No directory.');
      return this.refuse('STS-XACML-0337', 'The directory is not ' +
                         'available, so no binding can be read or written.');
    }
    const entry = name ? dir.locate(name) : null;
    if (!entry || !entry.person) {
      log.debug('Leaving PepBinding.clear(). Nobody.');
      return this.refuse('STS-XACML-0334', name
        ? 'There is nobody called "' + name + '" in this realm\'s ou=users.'
        : 'Which remote PEP? Send `name` (or `pep`).');
    }
    const previous = String(entry.application || '');
    if (!previous) {
      log.debug('Leaving PepBinding.clear(). Not bound.');
      return { ok: true, pep: name, application: '', previous: '',
               what: '"' + name + '" was bound to no application. Nothing ' +
                     'changed.' };
    }
    if (!dir.write(entry.dn, '')) {
      log.debug('Leaving PepBinding.clear(). The directory refused.');
      return this.refuse('STS-XACML-0337', 'The directory refused to ' +
                         'remove "' + name + '"\'s binding. Nothing changed.');
    }
    audit.audit({ action: 'xacml.pep.binding', actor: actor || '',
                  target: name, protocol: 'XACML',
                  detail: 'Removed the embedded remote PEP "' + name +
                          '"\'s binding to the application "' + previous +
                          '".' });
    log.debug('Leaving PepBinding.clear(). Cleared.');
    return { ok: true, pep: name, application: '', previous: previous,
             what: 'Removed "' + name + '"\'s binding to "' + previous +
                   '". A registration as an embedded PEP is refused until ' +
                   'it is bound again.' };
  }

  /**
   * The application a PEP is bound to, or '' when it is bound to none or is
   * nobody. Never throws.
   *
   * @param name - the PEP's username
   * @returns the application's identifier, or ''
   */
  of(name: string): string {
    const { log } = this.deps;
    log.debug('Entering PepBinding.of(). name=' + name);
    const dir = this.deps.directory();
    let out = '';
    try {
      const entry = dir && name ? dir.locate(name) : null;
      out = entry && entry.person ? String(entry.application || '') : '';
    } catch (e) {
      // A directory that throws is a binding that cannot be read: the row
      // draws none, and a registration is refused for it (#2026).
      log.debug('Caught in PepBinding.of(): ' + ((e && e.message) || e));
      out = '';
    }
    log.debug('Leaving PepBinding.of(). ' + out);
    return out;
  }

  /**
   * Every PEP bound to an application, by username, sorted. Never throws.
   *
   * @param application - the application's identifier
   * @returns the PEPs' usernames
   */
  boundTo(application: string): string[] {
    const { log } = this.deps;
    log.debug('Entering PepBinding.boundTo(). ' + application);
    const dir = this.deps.directory();
    let out: string[] = [];
    try {
      out = !dir || !application ? [] : dir.holders()
        .filter(function (one) {
          return one.application === application;
        })
        .map(function (one) {
          return one.name;
        })
        .sort();
    } catch (e) {
      // The application's page draws none rather than failing.
      log.debug('Caught in PepBinding.boundTo(): ' + ((e && e.message) || e));
      out = [];
    }
    log.debug('Leaving PepBinding.boundTo(). ' + out.length);
    return out;
  }

  /**
   * Every binding in the ambient realm, by username, sorted (#2028). Never
   * throws.
   *
   * @returns `{ name, application }` per bound PEP
   */
  all(): Array<{ name: string; application: string }> {
    const { log } = this.deps;
    log.debug('Entering PepBinding.all().');
    const dir = this.deps.directory();
    let out: Array<{ name: string; application: string }> = [];
    try {
      out = !dir ? [] : dir.holders().filter(function (one) {
        return !!one.application;
      }).map(function (one) {
        return { name: one.name, application: one.application };
      }).sort(function (a, b) {
        return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
      });
    } catch (e) {
      // No binding can be read: no PEP is told anything, and each converges
      // on its fallback poll.
      log.debug('Caught in PepBinding.all(): ' + ((e && e.message) || e));
      out = [];
    }
    log.debug('Leaving PepBinding.all(). ' + out.length);
    return out;
  }

  /**
   * Clears every binding naming an application that was just deleted, and
   * writes an audit row for each. Called by `ldap_server.js`'s
   * `noteApplicationRemoved()`, which both doors that delete an application
   * reach. Never throws into the delete.
   *
   * @param identifier - the deleted application's identifier
   * @param via - which door deleted it, for the audit row
   * @returns the PEPs whose binding was removed
   */
  applicationRemoved(identifier: string, via: string): string[] {
    const { log, audit } = this.deps;
    log.debug('Entering PepBinding.applicationRemoved(). ' + identifier);
    const dir = this.deps.directory();
    const cleared: string[] = [];
    if (!dir || !identifier) {
      log.debug('Leaving PepBinding.applicationRemoved(). Nothing to do.');
      return cleared;
    }
    try {
      dir.holders().forEach(function (one) {
        if (one.application !== identifier) {
          return;
        }
        if (dir.write(one.dn, '')) {
          cleared.push(one.name);
          audit.audit({ action: 'xacml.pep.binding', actor: '',
                        target: one.name, protocol: 'XACML',
                        channel: 'internal',
                        detail: 'Removed the embedded remote PEP "' +
                                one.name + '"\'s binding: the application "' +
                                identifier + '" it was bound to was deleted ' +
                                'by ' + via + '.' });
        } else {
          log.warn(errorCodes.tag('STS-XACML-0337') + 'xacml: the binding ' +
                   'of "' + one.name + '" to the deleted application "' +
                   identifier + '" could not be removed.');
        }
      });
    } catch (e) {
      log.debug('Caught in PepBinding.applicationRemoved(): ' +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-XACML-0337') + 'xacml: the bindings to ' +
               'the deleted application "' + identifier + '" could not be ' +
               'removed: ' + ((e && e.message) || e));
    }
    log.debug('Leaving PepBinding.applicationRemoved(). ' + cleared.length);
    return cleared;
  }
}

export = PepBinding;
