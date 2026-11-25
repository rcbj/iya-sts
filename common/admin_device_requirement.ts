// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_device_requirement.ts
//
// ===========================================================================
// THE ADMINISTRATIVE SURFACE REQUIRES A COMPLIANT REGISTERED DEVICE (#2179,
// ASVS 5.0.0 8.4.2, rcbj's decision of 2026-11-24).
//
// In product, a PERSON is issued a credential for the administrative surface
// — a token to the console (`sts-admin-console`) or one carrying an `admin:*`
// scope, at the token endpoint, every grant and every refresh — only from a
// compliant registered device of their own (or an application's: a managed
// host). `devices.requireCompliantDeviceForAdmin` (`auto`, on in product and
// off in development: `mode.requiresCompliantDeviceForAdmin()`) is the
// switch; the RULE is the issuance policy's `device-required-admin`
// (`xacml/xacml_templates.ts`), which reads the requirement bag this module
// adds `compliant-admin` to (`issuance_gate.deviceRequirementOf()`) and the
// gate's `device-admin-surface` fact. Programs are never asked: the fact is
// true only for a person subject.
//
// **THE REQUIREMENT IS ARMED ON FIRST PROOF, AND THAT IS HOW IT CANNOT LOCK A
// REALM OUT.** The console is where a device is marked compliant, and the
// first administrator of an install — or every administrator of one upgraded
// to 1.2.0 — holds no compliant device. So while the switch is in force and
// the realm is NOT ARMED, the rule is not in the bag and every administrator
// is admitted as before; the first time a CONSOLE ADMINISTRATOR (a member of
// a roster group, `admin_rbac.rolesOf().groups` — never the open console's
// "everybody") is ALLOWED an administrative credential from a device that
// passes the compliant test, the realm is armed, and from then on the rule
// holds for every administrator. Arming on an admitted sign-in rather than on
// a compliance write proves that somebody can actually meet the rule — the
// device is recognisable at a sign-in, not merely marked — before it can
// refuse anybody.
//
// **IT IS A LATCH, NOT A COUNT.** "While some administrator owns a compliant
// device" would be re-opened by REMOVING that device, and a person removes
// their own device on the portal, which is exempt from every device rule: an
// attacker holding one administrator's password could empty the count and
// walk in. Nothing here disarms. Turning the switch off and on again leaves
// the realm armed. The way back in for a realm whose every administrator lost
// their device is the deployment's own management credential — a program,
// which this rule never asks — setting the new device's compliance, or the
// switch to `off`, through `/admin-api`.
//
// **THE ROW HOLDS NO PERSONAL DATA**: when it was armed, and nothing else (who
// and through which device are on the audit row). It is configuration every
// cell must honour alike, so it is GLOBAL-tier (`persistence/tiers.js`).
//
// A LIBRARY (rule 3): it registers no route. `issuance_gate.js` requires it
// LAZILY (that file is a leaf), and it reaches `mode`, `admin_rbac` and
// `audit` lazily too.
// ===========================================================================

import realms = require('./realms');
import config = require('./config');

type Json = any;

// One row per realm, under ARMED_KEY: `{ at }`. Persisted and kept: a latch
// that a restart forgot would be a latch an attacker could wait out.
const latch = realms.map({ persist: 'devices.adminRequirement' });

// The one key the latch is stored under.
const ARMED_KEY = 'armed';

// The setting's name, for the views and the sentences that cite it.
const SETTING = 'devices.requireCompliantDeviceForAdmin';

// The scopes that make a person's credential an administrative one: the
// management API's own (`common/role_permissions.ts`, #302, #645, #454).
const ADMIN_SCOPES = ['admin:read', 'admin:write', 'admin:security',
                      'admin:console'];

// The client that IS the console (#446).
const CONSOLE_CLIENT = 'sts-admin-console';

// The kinds minted at the token endpoint, which is where the rule is asked:
// a token request carries the strongest device proof (a client certificate,
// a registered DPoP key), and a refusal at the session or the code would
// refuse a client that first proves its device there (RFC 9449).
const TOKEN_KINDS = ['issue-access-token', 'issue-refresh-token',
                     'issue-id-token'];

interface AdminDeviceRequirementDeps {
  log: Json;
  config: Json;
  // Lazily: `mode` resolves `auto`, `admin_rbac` says who is an
  // administrator, `audit` records the arming.
  mode: () => Json;
  rbac: () => Json;
  audit: () => Json;
  now: () => number;
}

/**
 * The administrative surface's compliant-device requirement (#2179): whether
 * it is in force in the ambient realm, whether the realm is armed, and the
 * one writer that arms it.
 */
class AdminDeviceRequirement {
  static readonly SETTING = SETTING;
  static readonly ADMIN_SCOPES = ADMIN_SCOPES;
  static readonly CONSOLE_CLIENT = CONSOLE_CLIENT;
  static readonly TOKEN_KINDS = TOKEN_KINDS;

  /**
   * Builds the requirement over its dependencies.
   *
   * @param deps - the logger, `config`, lazy readers of `mode`, `admin_rbac`
   *   and `audit`, and a clock
   */
  constructor(private readonly deps: AdminDeviceRequirementDeps) {
    deps.log.debug("Entering AdminDeviceRequirement.constructor().");
    deps.log.debug("Leaving AdminDeviceRequirement.constructor().");
  }

  /**
   * Returns the dependencies the module's own instance is built with.
   *
   * @returns a logger, the real `config`, lazy requires of `mode`,
   *   `admin_rbac` and `audit`, and `Date.now`
   */
  static defaultDeps(): AdminDeviceRequirementDeps {
    const log = require('bunyan').createLogger({
      name: 'admin_device_requirement',
      level: process.env.STS_LOG_LEVEL || 'info' });
    log.debug("Entering AdminDeviceRequirement.defaultDeps().");
    log.debug("Leaving AdminDeviceRequirement.defaultDeps().");
    return {
      log: log,
      config: config,
      mode: function (): Json {
        return require('./mode');
      },
      rbac: function (): Json {
        return require('../admin-ui/admin_rbac');
      },
      audit: function (): Json {
        return require('./audit');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // -------------------------------------------------------------------------
  // IN FORCE: the setting, `auto` resolved by the mode predicate. Per realm,
  // like every setting.
  // -------------------------------------------------------------------------
  /**
   * Tells whether the ambient realm requires a compliant registered device
   * for the administrative surface: `on`, or `auto` in product.
   *
   * @returns true when the switch is in force
   */
  inForce(): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.inForce().");
    const value = String(this.deps.config.value(SETTING) || 'auto');
    let out = false;
    if (value === 'on') {
      out = true;
    } else if (value === 'off') {
      out = false;
    } else {
      out = this.deps.mode().requiresCompliantDeviceForAdmin() === true;
    }
    log.debug("Leaving AdminDeviceRequirement.inForce(). " + out);
    return out;
  }

  /**
   * Returns the ambient realm's latch row, or null while it is not armed.
   *
   * @returns `{ at }` (epoch milliseconds), or null
   */
  armedRow(): Json {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.armedRow().");
    const row = latch.get(ARMED_KEY) || null;
    log.debug("Leaving AdminDeviceRequirement.armedRow(). " +
              (row ? 'Armed.' : 'Not armed.'));
    return row;
  }

  /**
   * Tells whether the rule is in the requirement bag: in force AND armed.
   *
   * @returns true when the issuance policy's `device-required-admin` rule
   *   applies in the ambient realm
   */
  enforced(): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.enforced().");
    const out = this.inForce() && !!this.armedRow();
    log.debug("Leaving AdminDeviceRequirement.enforced(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE FACT: a person is being issued a credential for the administrative
  // surface. A fact, gathered here so the gate and the tests read one
  // definition; what is DONE about it is the policy's.
  // -------------------------------------------------------------------------
  /**
   * Tells whether an issuance question is a person's credential for the
   * administrative surface: the console's client, or an `admin:*` scope, at
   * the token endpoint.
   *
   * @param asked - the gate's question: `application`, `kind`, `subject`,
   *   `scopes`
   * @returns true for a person's administrative token
   */
  isAdminSurface(asked: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.isAdminSurface().");
    const a = asked || {};
    const subject = a.subject || {};
    if (subject.kind !== 'user' || !subject.name ||
        TOKEN_KINDS.indexOf(String(a.kind || '')) < 0) {
      log.debug("Leaving AdminDeviceRequirement.isAdminSurface(). Not a " +
                "person's token.");
      return false;
    }
    const scopes = Array.isArray(a.scopes) ? a.scopes.map(String) : [];
    const out = String(a.application || '') === CONSOLE_CLIENT ||
      scopes.some(function (one: string): boolean {
        return ADMIN_SCOPES.indexOf(one) >= 0;
      });
    log.debug("Leaving AdminDeviceRequirement.isAdminSurface(). " + out);
    return out;
  }

  /**
   * Tells whether a device fact passes the compliant test the policy's
   * device rules state: recognised, the subject's own or an application's,
   * compliant, not compromised, attested where the realm says so.
   *
   * @param fact - `device_recognition.ts`'s fact, brought up to date
   * @param username - the subject
   * @returns true for a compliant device of theirs
   */
  compliantFor(fact: Json, username: string): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.compliantFor().");
    if (!fact) {
      log.debug("Leaving AdminDeviceRequirement.compliantFor(). None.");
      return false;
    }
    const owned = fact.ownerKind === 'application' ||
      (fact.ownerKind === 'person' &&
       String(fact.ownerName || '') === String(username || ''));
    const attestedEnough =
      this.deps.config.value('devices.compliantDeviceAttested') !== true ||
      fact.attestation === 'attested';
    const out = owned && fact.compliance === 'compliant' &&
      fact.status !== 'compromised' && attestedEnough;
    log.debug("Leaving AdminDeviceRequirement.compliantFor(). " + out);
    return out;
  }

  // A member of a console roster group (`credentials.ts`'s reading for #246):
  // never `read`/`write`, which are true for everybody while the roster is
  // empty, so an open console cannot arm the realm for a person who is not
  // an administrator.
  private isAdministrator(username: string): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.isAdministrator().");
    let out = false;
    try {
      const roles = this.deps.rbac().rolesOf(username) || {};
      const groups = Array.isArray(roles.groups) ? roles.groups : [];
      out = groups.some(function (g: Json): boolean {
        return !!g && (g.role === 'read' || g.role === 'write');
      });
    } catch (e) {
      log.debug("Caught in AdminDeviceRequirement.isAdministrator(): " +
                ((e && e.message) || e));
      // No console in this process: nobody is an administrator, and nothing
      // is armed.
      out = false;
    }
    log.debug("Leaving AdminDeviceRequirement.isAdministrator(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // ARM — the one writer, called by the gate after an ALLOWED answer. Arms
  // only where every condition in the header holds; anything else is a no-op.
  // Never throws: it runs inside an issuance that has already been decided.
  // -------------------------------------------------------------------------
  /**
   * Arms the ambient realm when an allowed administrative credential came
   * from a compliant device of a console administrator's own.
   *
   * @param asked - the gate's question
   * @param fact - the device fact the gate decided on
   * @returns true when this call armed the realm
   */
  noteAllowed(asked: Json, fact: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.noteAllowed().");
    try {
      const a = asked || {};
      const username = String((a.subject || {}).name || '');
      if (a.preview || !this.isAdminSurface(a) || !this.inForce() ||
          this.armedRow() || !this.compliantFor(fact, username) ||
          !this.isAdministrator(username)) {
        log.debug("Leaving AdminDeviceRequirement.noteAllowed(). Nothing " +
                  "to arm.");
        return false;
      }
      latch.set(ARMED_KEY, { at: this.deps.now() });
      log.info('admin_device_requirement: realm "' + realms.currentId() +
               '" is ARMED: ' + username + ' was issued an administrative ' +
               'credential from compliant device ' + String(fact.id) +
               ', and from now on every administrator needs one.');
      try {
        this.deps.audit().audit({
          action: 'device.admin-requirement-armed', actor: username,
          protocol: 'OAuth 2.0 / OIDC', channel: 'http', target: '',
          summary: 'the administrative surface now requires a compliant ' +
                   'registered device (' + SETTING + '): ' + username +
                   ' signed in from one',
          detail: { device: String(fact.id || ''),
                    application: String(a.application || '') } });
      } catch (e) {
        log.debug("Caught in AdminDeviceRequirement.noteAllowed(): " +
                  ((e && e.message) || e));
        // The latch is written; a missing audit row is logged above.
      }
      log.debug("Leaving AdminDeviceRequirement.noteAllowed(). Armed.");
      return true;
    } catch (e) {
      log.debug("Caught in AdminDeviceRequirement.noteAllowed(): " +
                ((e && e.message) || e));
      // A store that cannot be written leaves the realm unarmed, which is
      // the state that admits: it can be armed at the next sign-in.
      log.debug("Leaving AdminDeviceRequirement.noteAllowed(). Not armed.");
      return false;
    }
  }

  /**
   * Describes the ambient realm's state for Directory -> Devices.
   *
   * @returns `{ setting, value, inForce, armed, armedAt }`
   */
  view(): Json {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.view().");
    const row = this.armedRow();
    const out = {
      setting: SETTING,
      value: String(this.deps.config.value(SETTING) || 'auto'),
      inForce: this.inForce(),
      armed: !!row,
      armedAt: row && Number(row.at) > 0
        ? new Date(Number(row.at)).toISOString() : ''
    };
    log.debug("Leaving AdminDeviceRequirement.view().");
    return out;
  }

  // For the tests, and for nothing in the service: the latch cleared, so a
  // test can start from an unarmed realm. Nothing in the service disarms —
  // see the header.
  /**
   * Clears the ambient realm's latch; for tests only.
   */
  forgetForTests(): void {
    const { log } = this.deps;
    log.debug("Entering AdminDeviceRequirement.forgetForTests().");
    latch.delete(ARMED_KEY);
    log.debug("Leaving AdminDeviceRequirement.forgetForTests().");
  }
}

// TRANSITIONAL (#50's R2): the instance the unconverted callers use, and the
// names they require. A library with no route or socket, so the composition
// root does not build it; it is built here, once, at load.
const instance = new AdminDeviceRequirement(
  AdminDeviceRequirement.defaultDeps());

/**
 * The administrative surface's compliant-device requirement (#2179).
 *
 * A library (rule 3); the functions are bound to an instance built at load.
 * @namespace
 */
export = {
  AdminDeviceRequirement: AdminDeviceRequirement,
  SETTING: SETTING,
  ADMIN_SCOPES: ADMIN_SCOPES,
  inForce: instance.inForce.bind(instance),
  enforced: instance.enforced.bind(instance),
  armedRow: instance.armedRow.bind(instance),
  isAdminSurface: instance.isAdminSurface.bind(instance),
  compliantFor: instance.compliantFor.bind(instance),
  noteAllowed: instance.noteAllowed.bind(instance),
  view: instance.view.bind(instance),
  forgetForTests: instance.forgetForTests.bind(instance)
};
