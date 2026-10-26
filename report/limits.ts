// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: limits.ts
//
// ---------------------------------------------------------------------------
// THE REPORTING LIMITS (#956).
//
// Every cap is a setting, read when the question is asked, so a console
// change applies to the next query and not to a number this module captured
// at load. Zero is a legal stored value on an int row whose minimum allows
// it; these rows do not, and the reader still does not write `|| default`,
// which would make a real zero look like "unset".
//
// A test passes `Limits.fixed` and never touches the configuration. The
// service constructs `Limits` with no argument.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-report-limits' });

// The same numbers the settings rows default to. `Limits.fixed` fills from
// here so a test that names one cap does not have to name the other eleven,
// and does not have to load the configuration.
const DEFAULTS: Record<string, number | string> = {
  syncMaxRows: 500,
  syncMaxBytes: 1000000,
  syncMaxMs: 2000,
  asyncMaxRows: 100000,
  asyncMaxBytes: 32000000,
  pdfMaxRows: 2000,
  pdfMaxPages: 100,
  maxConcurrentPerRealm: 2,
  maxConcurrentPerSubject: 1,
  artifactRetentionS: 86400,
  jobRetentionS: 604800,
  usersGroup: ''
};

function configured(key: string): number | string {
  log.debug("Entering configured().");
  // Lazy: requiring this module must not require the configuration, so a
  // test that builds Limits.fixed can load the catalog with no appconfig.
  const config = require('../common/config');
  const value = config.value('report.' + key);
  log.debug("Leaving configured().");
  return value;
}

/**
 * The reporting caps. Each method reads the setting, or the test override.
 */
class Limits {
  fixedValues: Record<string, number | string> | null;

  /**
   * Settings-backed limits. Tests use `Limits.fixed` instead.
   */
  constructor() {
    log.debug("Entering Limits().");
    this.fixedValues = null;
    log.debug("Leaving Limits().");
  }

  /**
   * A limits object that never reads the configuration. A key the caller
   * omits keeps the setting's default.
   *
   * @param overrides - the numbers the test wants
   * @returns the limits
   */
  static fixed(overrides: Record<string, number | string>): Limits {
    log.debug("Entering Limits.fixed().");
    const limits = new Limits();
    const values: Record<string, number | string> = {};
    const names = Object.keys(DEFAULTS);
    for (let i = 0; i < names.length; i++) {
      const name = names[i];
      values[name] = Object.prototype.hasOwnProperty.call(
        overrides || {}, name) ? overrides[name] : DEFAULTS[name];
    }
    limits.fixedValues = values;
    log.debug("Leaving Limits.fixed().");
    return limits;
  }

  /**
   * One cap: the override when this instance has one, otherwise the setting.
   *
   * @param key - the name without the `report.` prefix
   * @returns the number, or the string for usersGroup
   */
  private pick(key: string): number | string {
    log.debug("Entering Limits.pick().");
    if (this.fixedValues &&
        Object.prototype.hasOwnProperty.call(this.fixedValues, key)) {
      log.debug("Leaving Limits.pick(). Fixed.");
      return this.fixedValues[key];
    }
    const value = configured(key);
    log.debug("Leaving Limits.pick().");
    return value;
  }

  /** @returns report.syncMaxRows */
  syncMaxRows(): number {
    log.debug("Entering Limits.syncMaxRows().");
    log.debug("Leaving Limits.syncMaxRows().");
    return Number(this.pick('syncMaxRows'));
  }

  /** @returns report.syncMaxBytes */
  syncMaxBytes(): number {
    log.debug("Entering Limits.syncMaxBytes().");
    log.debug("Leaving Limits.syncMaxBytes().");
    return Number(this.pick('syncMaxBytes'));
  }

  /** @returns report.syncMaxMs */
  syncMaxMs(): number {
    log.debug("Entering Limits.syncMaxMs().");
    log.debug("Leaving Limits.syncMaxMs().");
    return Number(this.pick('syncMaxMs'));
  }

  /** @returns report.asyncMaxRows */
  asyncMaxRows(): number {
    log.debug("Entering Limits.asyncMaxRows().");
    log.debug("Leaving Limits.asyncMaxRows().");
    return Number(this.pick('asyncMaxRows'));
  }

  /** @returns report.asyncMaxBytes */
  asyncMaxBytes(): number {
    log.debug("Entering Limits.asyncMaxBytes().");
    log.debug("Leaving Limits.asyncMaxBytes().");
    return Number(this.pick('asyncMaxBytes'));
  }

  /** @returns report.pdfMaxRows */
  pdfMaxRows(): number {
    log.debug("Entering Limits.pdfMaxRows().");
    log.debug("Leaving Limits.pdfMaxRows().");
    return Number(this.pick('pdfMaxRows'));
  }

  /** @returns report.pdfMaxPages */
  pdfMaxPages(): number {
    log.debug("Entering Limits.pdfMaxPages().");
    log.debug("Leaving Limits.pdfMaxPages().");
    return Number(this.pick('pdfMaxPages'));
  }

  /** @returns report.maxConcurrentPerRealm */
  maxConcurrentPerRealm(): number {
    log.debug("Entering Limits.maxConcurrentPerRealm().");
    log.debug("Leaving Limits.maxConcurrentPerRealm().");
    return Number(this.pick('maxConcurrentPerRealm'));
  }

  /** @returns report.maxConcurrentPerSubject */
  maxConcurrentPerSubject(): number {
    log.debug("Entering Limits.maxConcurrentPerSubject().");
    log.debug("Leaving Limits.maxConcurrentPerSubject().");
    return Number(this.pick('maxConcurrentPerSubject'));
  }

  /** @returns report.artifactRetentionS */
  artifactRetentionS(): number {
    log.debug("Entering Limits.artifactRetentionS().");
    log.debug("Leaving Limits.artifactRetentionS().");
    return Number(this.pick('artifactRetentionS'));
  }

  /** @returns report.jobRetentionS */
  jobRetentionS(): number {
    log.debug("Entering Limits.jobRetentionS().");
    log.debug("Leaving Limits.jobRetentionS().");
    return Number(this.pick('jobRetentionS'));
  }

  /** @returns report.usersGroup, which may be empty */
  usersGroup(): string {
    log.debug("Entering Limits.usersGroup().");
    const value = this.pick('usersGroup');
    log.debug("Leaving Limits.usersGroup().");
    return value == null ? '' : String(value);
  }
}

export = Limits;
