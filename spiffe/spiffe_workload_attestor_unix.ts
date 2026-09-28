// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: spiffe_workload_attestor_unix.ts
//
// ---------------------------------------------------------------------------
// THE `unix` WORKLOAD ATTESTOR (#40 phase four, 2026-09-21).
//
// SPIRE's `pkg/agent/plugin/workloadattestor/unix`: who the process runs as,
// and — with `spiffe.unixDiscoverWorkloadPath` — what it runs.
//
//   uid:<n>, user:<name>              the EFFECTIVE uid from
//                                     /proc/<pid>/status, the name where
//                                     /etc/passwd has one
//   gid:<n>, group:<name>             the effective gid, likewise
//   supplementary_gid:<n>,
//   supplementary_group:<name>        each of the status file's Groups
//   path:<exe>                        where /proc/<pid>/exe points
//   sha256:<hex>                      the executable's digest, read through
//                                     /proc/<pid>/exe so a binary in another
//                                     mount namespace is the one hashed;
//                                     `spiffe.unixWorkloadSizeLimit` above 0
//                                     refuses a larger one, below 0 hashes
//                                     nothing
//
// **A PEER IN ANOTHER PID NAMESPACE GETS ITS KERNEL CREDENTIALS AND NOTHING
// ELSE.** SPIRE, which runs with the host's pid namespace, would fail such a
// call; this service commonly runs in a container whose workloads are in
// others, and the kernel's uid and gid at connect ARE attested facts. So
// uid, user, gid and group come from SO_PEERCRED there, and nothing that
// needs the process — supplementary groups, path, digest — is invented.
// ---------------------------------------------------------------------------

import fs = require('fs');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import stsCrypto = require('../common/crypto');

interface UnixDeps {
  log: typeof log;
  fs: typeof fs;
  stsCrypto: typeof stsCrypto;
  config: typeof config;
  passwdPath: string;
  groupPath: string;
}

/**
 * The `unix` workload attestor: who the caller's process runs as and, with
 * `spiffe.unixDiscoverWorkloadPath`, what it runs.
 *
 * A peer in another pid namespace gets its kernel credentials from SO_PEERCRED
 * and nothing that needs the process.
 */
class UnixWorkloadAttestor {
  /**
   * The workload attestor's name, as `spiffe.workloadAttestors` lists it.
   */
  readonly type = 'unix';
  /**
   * One sentence for `GET /spiffe` and the console: what this attestor
   * verifies.
   */
  readonly verifies = 'The uid, gid and supplementary groups the kernel ' +
    'reports for the caller\'s process, and its executable\'s path and ' +
    'SHA-256.';

  /**
   * Builds the attestor over its dependencies.
   *
   * @param deps - the logger, file system, crypto, configuration and the proc,
   *   passwd and group paths
   */
  constructor(private readonly deps: UnixDeps) {
    deps.log.debug("Entering UnixWorkloadAttestor.constructor().");
    deps.log.debug("Leaving UnixWorkloadAttestor.constructor().");
  }

  /**
   * Returns the dependencies the service runs the attestor with.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): UnixDeps {
    helpers.log.debug("Entering UnixWorkloadAttestor.defaultDeps().");
    helpers.log.debug("Leaving UnixWorkloadAttestor.defaultDeps().");
    return { log: log, fs: fs, stsCrypto: stsCrypto, config: config,
             passwdPath: '/etc/passwd', groupPath: '/etc/group' };
  }

  // One name from a passwd- or group-style file, by id, or ''.
  /**
   * Looks up one name by id in a passwd- or group-style file.
   *
   * @param file - the file's path
   * @param id - the numeric id
   * @returns the name, or ''
   */
  nameOf(file: string, id: string): string {
    const { log, fs } = this.deps;
    log.debug("Entering UnixWorkloadAttestor.nameOf(). " + id);
    try {
      const lines = fs.readFileSync(file, 'utf8').split('\n');
      for (let i = 0; i < lines.length; i++) {
        const fields = lines[i].split(':');
        if (fields.length > 2 && fields[2] === id) {
          log.debug("Leaving UnixWorkloadAttestor.nameOf().");
          return fields[0];
        }
      }
    } catch (e) {
      log.debug("Caught in UnixWorkloadAttestor.nameOf(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving UnixWorkloadAttestor.nameOf(). None.");
    return '';
  }

  // The status file's Uid, Gid and Groups.
  /**
   * Reads the effective Uid, Gid and the Groups of a process's status file.
   *
   * @param procRoot - the proc file system's root
   * @param pid - the process id
   * @returns the uid, the gid and the supplementary gids
   */
  status(procRoot: string, pid: number): { uid: string; gid: string;
                                          groups: string[] } {
    const { log, fs } = this.deps;
    log.debug("Entering UnixWorkloadAttestor.status(). pid=" + pid);
    const out = { uid: '', gid: '', groups: [] };
    fs.readFileSync(procRoot + '/' + pid + '/status', 'utf8').split('\n')
      .forEach(function (row) {
        const at = row.indexOf(':');
        if (at < 0) return;
        const key = row.slice(0, at).trim().toLowerCase();
        const values = row.slice(at + 1).trim().split(/\s+/).filter(Boolean);
        // Real, EFFECTIVE, saved, filesystem: SPIRE takes the second.
        if (key === 'uid') out.uid = values[values.length > 1 ? 1 : 0] || '';
        if (key === 'gid') out.gid = values[values.length > 1 ? 1 : 0] || '';
        if (key === 'groups') out.groups = values;
      });
    if (!out.uid || !out.gid) {
      log.debug("Leaving UnixWorkloadAttestor.status(). Incomplete.");
      // error-code: none — reported by the table under STS-SPIFFE-0111
      throw new Error('UIDs lookup: no UIDs for process');
    }
    log.debug("Leaving UnixWorkloadAttestor.status().");
    return out;
  }

  // `uid:` and `user:`.
  /**
   * Returns the `uid:` and, where the passwd file has one, `user:` selectors.
   *
   * @param uid - the numeric uid
   * @returns the selector values
   */
  userSelectors(uid: string): string[] {
    const { log, passwdPath } = this.deps;
    log.debug("Entering UnixWorkloadAttestor.userSelectors().");
    const name = this.nameOf(passwdPath, uid);
    log.debug("Leaving UnixWorkloadAttestor.userSelectors().");
    return ['uid:' + uid].concat(name ? ['user:' + name] : []);
  }

  // `gid:` and `group:`, or their `supplementary_` forms.
  /**
   * Returns the `gid:` and `group:` selectors, or their `supplementary_` forms.
   *
   * @param prefix - '' or `supplementary_`
   * @param gid - the numeric gid
   * @returns the selector values
   */
  groupSelectors(prefix: string, gid: string): string[] {
    const { log, groupPath } = this.deps;
    log.debug("Entering UnixWorkloadAttestor.groupSelectors().");
    const name = this.nameOf(groupPath, gid);
    log.debug("Leaving UnixWorkloadAttestor.groupSelectors().");
    return [prefix + 'gid:' + gid].concat(name ? [prefix + 'group:' + name]
                                               : []);
  }

  /**
   * Attests the caller's process: its uid, gid, supplementary groups and, when
   * configured, its executable's path and SHA-256.
   *
   * @param facts - the caller's peer facts from `spiffe_peer.ts`, taken at
   *   accept
   * @returns the `unix` selector values
   */
  async attest(facts: any): Promise<string[]> {
    const { log, fs, config, stsCrypto } = this.deps;
    const self = this;
    log.debug("Entering UnixWorkloadAttestor.attest(). " + facts.tag);
    if (!facts.visible) {
      log.debug("Leaving UnixWorkloadAttestor.attest(). Kernel credentials " +
                "only.");
      return this.userSelectors(String(facts.uid))
        .concat(this.groupSelectors('', String(facts.gid)));
    }
    const status = this.status(facts.procRoot, facts.pid);
    let out = this.userSelectors(status.uid)
      .concat(this.groupSelectors('', status.gid));
    status.groups.forEach(function (gid) {
      out = out.concat(self.groupSelectors('supplementary_', gid));
    });
    if (config.value('spiffe.unixDiscoverWorkloadPath')) {
      const exe = facts.procRoot + '/' + facts.pid + '/exe';
      out.push('path:' + fs.readlinkSync(exe));
      const limit = Number(config.value('spiffe.unixWorkloadSizeLimit'));
      if (limit >= 0) {
        // The digest is crypto.js's, as every hash here is.
        out.push('sha256:' + await stsCrypto.sha256OfFile(exe, limit));
      }
    }
    log.debug("Leaving UnixWorkloadAttestor.attest(). " + out.length);
    return out;
  }
}

/**
 * The `unix` workload attestor (#40), after SPIRE's plugin.
 * @namespace
 */
export = {
  UnixWorkloadAttestor: UnixWorkloadAttestor
};
