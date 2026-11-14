// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: common/bootstrap_name.ts
// ---------------------------------------------------------------------------
// THE BOOTSTRAP ADMINISTRATOR'S NAME (#1447, ASVS 5.0.0 6.3.2).
//
// The requirement says a default account such as `admin`, `root` or `sa` is not
// present or is disabled. Refusing to start, or starting with no administrator,
// would leave a new product install with a console nobody can reach
// (`STS-ADMIN-0798`), so where the configured name is one of those, or empty,
// product mode uses a generated one.
//
// IT IS DERIVED AND NOT STORED: an HMAC under the key every node of a cluster
// already shares (`cluster/cluster_secrets.ts`), so each node and each restart
// arrives at one name with nothing further to replicate, and somebody without
// that key cannot predict it. It is printed once with the generated password
// (`credentials.bootstrap()`).
// ---------------------------------------------------------------------------

import config = require('./config');
import stsCrypto = require('./crypto');
import helpers = require('./helpers');
import mode = require('./mode');
import clusterSecrets = require('../cluster/cluster_secrets');

const log = helpers.log;

const DEFAULT_NAMES = ['admin', 'root', 'sa', 'administrator'];
const DOMAIN = 'iya-sts bootstrap administrator name';

class BootstrapName {
  /**
   * Says whether a name is one a default account would carry, or none at all.
   *
   * @param name - the configured name
   * @returns true for an empty name and for the default account names
   */
  static isDefaultName(name: unknown): boolean {
    log.debug("Entering BootstrapName.isDefaultName().");
    log.debug("Leaving BootstrapName.isDefaultName().");
    const text = String(name || '').trim().toLowerCase();
    return !text || DEFAULT_NAMES.indexOf(text) >= 0;
  }

  /**
   * The bootstrap administrator's username in force.
   *
   * @returns the configured name, or the generated one where product mode
   * does not allow it
   */
  static current(): string {
    log.debug("Entering BootstrapName.current().");
    const named = String(config.value('admin.bootstrapUsername') || '').trim();
    if (!mode.generatesBootstrapName() || !BootstrapName.isDefaultName(named)) {
      log.debug("Leaving BootstrapName.current(). As configured.");
      return named;
    }
    const digest = String(stsCrypto.hmac('sha256', clusterSecrets.get('csrf'),
                                         DOMAIN, 'hex'));
    log.debug("Leaving BootstrapName.current(). Generated.");
    return 'admin-' + digest.slice(0, 16);
  }
}

export = BootstrapName;
