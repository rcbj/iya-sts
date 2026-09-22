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

class UnixWorkloadAttestor {
  readonly type = 'unix';
  readonly verifies = 'The uid, gid and supplementary groups the kernel ' +
    'reports for the caller\'s process, and its executable\'s path and ' +
    'SHA-256.';

  constructor(private readonly deps: UnixDeps) {
    deps.log.debug("Entering UnixWorkloadAttestor.constructor().");
    deps.log.debug("Leaving UnixWorkloadAttestor.constructor().");
  }

  static defaultDeps(): UnixDeps {
    helpers.log.debug("Entering UnixWorkloadAttestor.defaultDeps().");
    helpers.log.debug("Leaving UnixWorkloadAttestor.defaultDeps().");
    return { log: log, fs: fs, stsCrypto: stsCrypto, config: config,
             passwdPath: '/etc/passwd', groupPath: '/etc/group' };
  }

  // One name from a passwd- or group-style file, by id, or ''.
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
  userSelectors(uid: string): string[] {
    const { log, passwdPath } = this.deps;
    log.debug("Entering UnixWorkloadAttestor.userSelectors().");
    const name = this.nameOf(passwdPath, uid);
    log.debug("Leaving UnixWorkloadAttestor.userSelectors().");
    return ['uid:' + uid].concat(name ? ['user:' + name] : []);
  }

  // `gid:` and `group:`, or their `supplementary_` forms.
  groupSelectors(prefix: string, gid: string): string[] {
    const { log, groupPath } = this.deps;
    log.debug("Entering UnixWorkloadAttestor.groupSelectors().");
    const name = this.nameOf(groupPath, gid);
    log.debug("Leaving UnixWorkloadAttestor.groupSelectors().");
    return [prefix + 'gid:' + gid].concat(name ? [prefix + 'group:' + name]
                                               : []);
  }

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

export = {
  UnixWorkloadAttestor: UnixWorkloadAttestor
};
