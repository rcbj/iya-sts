'use strict';
//
// File: spiffe_peer.ts
//
// ---------------------------------------------------------------------------
// WHO IS ON THE OTHER END OF THE WORKLOAD API'S UNIX SOCKET (#40 phase four,
// 2026-09-21).
//
// A SPIRE agent attests a workload by asking the KERNEL who connected: the
// peer credentials of the Unix socket give a pid, and the pid gives the
// uid, the executable, the container, the pod. Node has no API for that, so
// `native/peercred.node` (compiled by `build-native.sh` inside an image
// build only) supplies SO_PEERCRED and a pidfd, and this module keeps what
// they said about each CONNECTION:
//
//   * `observe(socket)` runs at ACCEPT, before the connection is handed to
//     gRPC (`spiffe_grpc.ts`'s `bindAttestedSocket()`): the credentials, a
//     pidfd taken by the kernel at connect where the kernel offers one
//     (SO_PEERPIDFD, Linux 6.5+) or by pidfd_open() at once otherwise, and
//     the process's start time and executable inode;
//   * `stillValid(facts)` runs on EVERY CALL and answers whether the process
//     those facts describe is still the one holding the connection — the
//     pidfd still names a live process, the start time is unchanged (a pid
//     reused by another process has another start time), and the executable
//     inode is unchanged (a process that exec'd something else keeps its pid
//     and its pidfd, and is refused the selectors of what it was);
//   * `forget(tag)` runs when the connection closes, and closes the pidfd.
//
// **A CONNECTION IS TAGGED, NOT LOOKED UP BY FD.** The socket handed to gRPC
// carries `remoteAddress` `unix:attested-<n>`, so `call.getPeer()` in a
// handler names it — the probe on #40 showed grpc-js builds the peer from
// exactly those two properties — and `transportOf()` reads a `unix:` peer as
// the socket, which it is.
//
// **A PEER IN ANOTHER PID NAMESPACE HAS PID 0**, and that is the ordinary
// case in a compose stack or ECS, where workloads in other containers reach
// the socket through a shared volume. The kernel's uid and gid are still
// right there; the executable, the container and the pod are not reachable,
// and `facts.visible` says so rather than an attestor guessing.
// ---------------------------------------------------------------------------

import fs = require('fs');
import pathModule = require('path');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');

interface PeerFacts {
  tag: string;
  // What the kernel said at connect.
  pid: number;
  uid: number;
  gid: number;
  // A pidfd for the peer, or -1; and how it was taken.
  pidfd: number;
  pidfdSource: string;
  // Where /proc is (spiffe.workloadProcRoot, SPIRE's HOST_PROC).
  procRoot: string;
  // Whether the process can be read at all — pid 0 or an unreadable /proc
  // entry is not.
  visible: boolean;
  starttime: string;
  exeDev: number;
  exeIno: number;
  // Filled by the workload attestors, at accept.
  selectors: Array<{ type: string; value: string }>;
  // Why attestation failed, when it did; calls on the connection are refused.
  error: string;
  note: string;
}

interface SpiffePeerDeps {
  log: typeof log;
  fs: typeof fs;
  config: typeof config;
  loadAddon(): any;
}

class SpiffePeer {
  private addon: any = undefined;
  private addonProblem = '';
  private readonly connections = new Map<string, PeerFacts>();
  private counter = 0;

  constructor(private readonly deps: SpiffePeerDeps) {
    deps.log.debug("Entering SpiffePeer.constructor().");
    deps.log.debug("Leaving SpiffePeer.constructor().");
  }

  static defaultDeps(): SpiffePeerDeps {
    helpers.log.debug("Entering SpiffePeer.defaultDeps().");
    helpers.log.debug("Leaving SpiffePeer.defaultDeps().");
    return {
      log: log, fs: fs, config: config,
      loadAddon: function () {
        return require(pathModule.join(__dirname, 'native', 'peercred.node'));
      }
    };
  }

  // The native module, loaded once; null when it is not there.
  native(): any {
    const { log, loadAddon } = this.deps;
    log.debug("Entering SpiffePeer.native().");
    if (this.addon === undefined) {
      try {
        this.addon = loadAddon();
        if (typeof this.addon.peerCred !== 'function') {
          this.addonProblem = 'the native module has no peerCred()';
          this.addon = null;
        }
      } catch (e) {
        log.debug("Caught in SpiffePeer.native(): " + ((e && e.message) || e));
        this.addonProblem = 'spiffe/native/peercred.node is not built — it ' +
          'is compiled by build-native.sh inside an image build (' +
          ((e && e.message) || e) + ')';
        this.addon = null;
      }
    }
    log.debug("Leaving SpiffePeer.native(). " + (this.addon ? 'loaded'
                                                              : 'absent'));
    return this.addon;
  }

  // Whether workload attestation can run here, and why not when it cannot.
  availability(): { available: boolean; problem: string } {
    const { log } = this.deps;
    log.debug("Entering SpiffePeer.availability().");
    const native = this.native();
    log.debug("Leaving SpiffePeer.availability().");
    return { available: !!native, problem: native ? '' : this.addonProblem };
  }

  procRoot(): string {
    const { log, config } = this.deps;
    log.debug("Entering SpiffePeer.procRoot().");
    log.debug("Leaving SpiffePeer.procRoot().");
    return String(config.value('spiffe.workloadProcRoot') || '/proc');
  }

  // A process's start time (field 22 of /proc/<pid>/stat), or ''.
  starttimeOf(procRoot: string, pid: number): string {
    const { log, fs } = this.deps;
    log.debug("Entering SpiffePeer.starttimeOf(). pid=" + pid);
    try {
      const stat = fs.readFileSync(procRoot + '/' + pid + '/stat', 'utf8');
      // The command is in parentheses and may contain anything, so the
      // fields are counted from the LAST ')' — state is field 3.
      const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      log.debug("Leaving SpiffePeer.starttimeOf().");
      return String(fields[19] || '');
    } catch (e) {
      log.debug("Caught in SpiffePeer.starttimeOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffePeer.starttimeOf(). Unreadable.");
      return '';
    }
  }

  // The executable's device and inode, or zeros.
  exeOf(procRoot: string, pid: number): { dev: number; ino: number } {
    const { log, fs } = this.deps;
    log.debug("Entering SpiffePeer.exeOf(). pid=" + pid);
    try {
      const stat = fs.statSync(procRoot + '/' + pid + '/exe');
      log.debug("Leaving SpiffePeer.exeOf().");
      return { dev: Number(stat.dev), ino: Number(stat.ino) };
    } catch (e) {
      log.debug("Caught in SpiffePeer.exeOf(): " + ((e && e.message) || e));
      log.debug("Leaving SpiffePeer.exeOf(). Unreadable.");
      return { dev: 0, ino: 0 };
    }
  }

  // AT ACCEPT: what the kernel says about the socket's peer. Never throws; a
  // failure is `facts.error`, and the connection's calls are refused with it.
  observe(socket: any): PeerFacts {
    const { log } = this.deps;
    log.debug("Entering SpiffePeer.observe().");
    this.counter += 1;
    const facts: PeerFacts = {
      tag: 'unix:attested-' + this.counter, pid: 0, uid: -1, gid: -1,
      pidfd: -1, pidfdSource: '', procRoot: this.procRoot(), visible: false,
      starttime: '', exeDev: 0, exeIno: 0, selectors: [], error: '', note: ''
    };
    const native = this.native();
    const fd = socket && socket._handle ? socket._handle.fd : undefined;
    if (!native) {
      facts.error = this.addonProblem;
    } else if (typeof fd !== 'number' || fd < 0) {
      facts.error = 'the accepted socket exposes no file descriptor';
    } else {
      try {
        const cred = native.peerCred(fd);
        facts.pid = Number(cred.pid);
        facts.uid = Number(cred.uid);
        facts.gid = Number(cred.gid);
        facts.pidfd = Number(native.peerPidfd(fd));
        facts.pidfdSource = facts.pidfd >= 0 ? 'SO_PEERPIDFD' : '';
        if (facts.pidfd < 0 && facts.pid > 0) {
          facts.pidfd = Number(native.pidfdOpen(facts.pid));
          facts.pidfdSource = facts.pidfd >= 0 ? 'pidfd_open' : '';
        }
        if (facts.pid > 0) {
          facts.starttime = this.starttimeOf(facts.procRoot, facts.pid);
          const exe = this.exeOf(facts.procRoot, facts.pid);
          facts.exeDev = exe.dev;
          facts.exeIno = exe.ino;
          facts.visible = !!facts.starttime && facts.pidfd >= 0;
        }
        if (!facts.visible) {
          facts.note = facts.pid > 0
            ? 'the peer\'s process could not be read, so only its uid and ' +
              'gid are attested'
            : 'the peer is in another pid namespace (pid 0), so only its ' +
              'uid and gid are attested — share the pid namespace for the ' +
              'rest';
        }
      } catch (e) {
        log.debug("Caught in SpiffePeer.observe(): " + ((e && e.message) || e));
        facts.error = 'SO_PEERCRED failed: ' + ((e && e.message) || e);
      }
    }
    this.connections.set(facts.tag, facts);
    log.debug("Leaving SpiffePeer.observe(). " + facts.tag + " pid=" +
              facts.pid + " uid=" + facts.uid);
    return facts;
  }

  // ON EVERY CALL: '' when `facts` still describe the process holding the
  // connection, otherwise why not.
  stillValid(facts: PeerFacts): string {
    const { log } = this.deps;
    log.debug("Entering SpiffePeer.stillValid(). " + facts.tag);
    if (!facts.visible) {
      log.debug("Leaving SpiffePeer.stillValid(). Nothing process-bound.");
      return '';
    }
    const native = this.native();
    if (!native || !native.pidfdAlive(facts.pidfd)) {
      log.debug("Leaving SpiffePeer.stillValid(). Gone.");
      return 'the process that connected has exited';
    }
    if (this.starttimeOf(facts.procRoot, facts.pid) !== facts.starttime) {
      log.debug("Leaving SpiffePeer.stillValid(). Reused pid.");
      return 'the pid that connected now belongs to another process';
    }
    const exe = this.exeOf(facts.procRoot, facts.pid);
    if (exe.dev !== facts.exeDev || exe.ino !== facts.exeIno) {
      log.debug("Leaving SpiffePeer.stillValid(). exec'd.");
      return 'the process that connected has since executed a different ' +
             'program';
    }
    log.debug("Leaving SpiffePeer.stillValid().");
    return '';
  }

  // The facts for a call's peer string (`unix:attested-7:7`), or null.
  factsFor(peer: string): PeerFacts | null {
    const { log } = this.deps;
    log.debug("Entering SpiffePeer.factsFor().");
    const match = /^(unix:attested-\d+)(?::\d+)?$/.exec(String(peer || ''));
    log.debug("Leaving SpiffePeer.factsFor().");
    return match ? this.connections.get(match[1]) || null : null;
  }

  // When the connection closes.
  forget(tag: string): void {
    const { log } = this.deps;
    log.debug("Entering SpiffePeer.forget(). " + tag);
    const facts = this.connections.get(tag);
    if (facts && facts.pidfd >= 0 && this.native()) {
      this.native().closeFd(facts.pidfd);
    }
    this.connections.delete(tag);
    log.debug("Leaving SpiffePeer.forget().");
  }

  // What the pages draw.
  state() {
    const { log } = this.deps;
    log.debug("Entering SpiffePeer.state().");
    const availability = this.availability();
    const open = [];
    this.connections.forEach(function (facts) {
      open.push({ tag: facts.tag, pid: facts.pid, uid: facts.uid,
                  gid: facts.gid, visible: facts.visible,
                  pidfdSource: facts.pidfdSource,
                  selectors: facts.selectors.length, error: facts.error,
                  note: facts.note });
    });
    log.debug("Leaving SpiffePeer.state().");
    return { nativeModule: availability.available,
             problem: availability.problem, connections: open };
  }
}

const shared = new SpiffePeer(SpiffePeer.defaultDeps());

export = {
  SpiffePeer: SpiffePeer,
  shared: shared,
  availability: () => shared.availability(),
  observe: (socket: any) => shared.observe(socket),
  stillValid: (facts: any) => shared.stillValid(facts),
  factsFor: (peer: string) => shared.factsFor(peer),
  forget: (tag: string) => shared.forget(tag),
  state: () => shared.state()
};
