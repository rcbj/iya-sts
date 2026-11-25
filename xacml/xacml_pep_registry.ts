// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_registry.ts
//
// ---------------------------------------------------------------------------
// THE REGISTER OF REMOTE POLICY ENFORCEMENT POINTS, AND `ou=peps` IS IT.
//
// The same arrangement `xacml_store.ts` has with `ou=policies`, for the same
// three reasons argued there — persistence in all three modes with no driver
// change, per-realm isolation for free, and `ldapsearch` and
// `/admin/ldap/directory` as inspection tools that already exist. This module
// owns the SCHEMA and the directory functions arrive through `setDirectory()`,
// filled by `ldap/ldap_server.js` at require time.
//
// ---------------------------------------------------------------------------
// WHAT A ROW HERE IS, AND THE ONE THING IT IS NOT.
//
// It is a record that some other process is enforcing this service's policy,
// what it last pulled, and how to reach it. **IT IS NOT A PERMISSION.** A PEP
// that never registers can still pull `GET /xacml/pep/policies` and enforce
// perfectly — **as long as it holds `REMOTE_PEPS`**, which is a separate
// thing and not this register. That endpoint asks for a verified certificate
// resolving to a directory entry in the group `roles.remotePepGroup` names;
// what it does NOT ask is whether the PEP has a row here. Registering buys two
// things and neither is access — a row on the console saying this PEP exists
// and whether it is current, and an address for the nudge.
//
// **THIS COMMENT SAID THAT ENDPOINT AUTHENTICATED NOBODY**, which was true
// when it was written and stopped being true in the change that added the
// gate. The claim worth keeping is the one about this register: membership
// here is not a permission, and permission is not membership here.
//
// That is worth stating plainly because the shape looks like an authorization
// register and is not one. If a future change makes registration a
// precondition for pulling policy, that is a different feature with a
// different argument, and the argument would have to be made rather than
// inherited from the fact that this file exists.
//
// ---------------------------------------------------------------------------
// ONE CERTIFICATE IS ONE ENTRY.
//
// The entry is NAMED from the client certificate, through
// `certificatePlan()`'s naming rule — which arrives across the slot rather
// than being reimplemented here, so that a PEP is filed under exactly the name
// this service already gives any identity that arrives holding a certificate.
// A PEP that restarts and re-registers UPDATES its row; it does not add a
// second one.
//
// So two instances of one component sharing a certificate collapse into one
// row, and that is correct rather than a limitation. The question this
// register answers is "which PEPs am I distributing policy to, and are they
// current" — and a nudge sent to either instance is a nudge to that
// deployment. Telling them apart needs certificates of their own, which is
// what telling them apart would need anywhere else in this service too.
//
// **THE ENTRY IS NOT CREATED IN `ou=users`.** `certificatePlan()`'s NAMING is
// reused; its entry creation is not. A PEP is a component rather than a
// person, and an `ou=users` entry per PEP would make `/admin/users` count
// components as people — which is exactly the distinction `spiffe_registry.js`
// had to draw between an ISSUANCE and an AUTHENTICATION, recorded in
// `spiffe/CLAUDE.md`. The DN the naming rule produces is stored as
// `xacmlPepIdentity` so that a PEP whose certificate HAS also signed in
// somewhere can be joined up with that entry by anybody reading either.
//
// ---------------------------------------------------------------------------
// THE SYNC TOKEN IS A DIGEST OF WHAT WOULD BE SENT, NOT A CLOCK.
//
// `syncToken()` hashes the documents of every ENABLED policy plus which one is
// the root — that is, exactly the bytes `GET /xacml/pep/policies` would answer
// with. Three consequences, and the third is the one that made it worth doing
// this way rather than stamping a modification time:
//
//   * a policy edited and edited back to what it was does NOT invalidate
//     anybody's copy, because the repository genuinely did not change;
//   * DISABLING a policy changes the token, because a disabled policy is not
//     sent and the PEP's copy is therefore wrong;
//   * a change made through ANY door moves it — the console, `/admin-api`, an
//     `ldapmodify` on 389, an LDIF restore — because the token is computed
//     from the store on the ask rather than maintained by whatever wrote last.
//     A counter incremented by the write path would have been correct for the
//     two doors that remembered to increment it.
//
// A PEP reports the token it last pulled on every heartbeat, so "current" is a
// comparison this service can make rather than a claim the PEP makes about
// itself.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `PepRegistry` takes the logger, the settings, the error codes, the
// realm registry, the policy repository and the hash function through its
// constructor. The directory functions still arrive through the
// `setDirectory()` slot `ldap/ldap_server.js` fills at require time, and are
// held at module level, because that fill comes before the composition root
// builds the instance (#50, R2), so `setDirectory()` and
// `directoryInstalled()` are static. The root builds the instance and
// installs it here. The module still exports `SCHEMA`, the two static slot
// functions, and every other old function as a FACADE forwarding to the
// instance, for
// `xacml/xacml.ts`, the console, the management API, `ldap_server.js` and the
// tests, which are not all converted; a process without the root builds a
// default when this module loads. `PepRegistry` is exported for the root.
// ---------------------------------------------------------------------------

// For `hostnameOf()`: an IP literal is never a reported hostname.
import net = require('net');
// The one place this service hashes (#453).
import ModelTables = require('../common/model_tables');
import DomainClasses = require('../common/domain_classes');
import crypto = require('../common/crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// The error-code registry (a leaf). A refusal's code is marked on the RESULT
// as a non-enumerable property, which `xacml.ts` reads back onto its
// response.
import errorCodes = require('../common/error_codes');
// For elsewhere() below, which answers the one question a per-realm register
// cannot answer about itself. A LEAF like `config` — it registers no route
// and requiring it is what fills the realm slot every store here already
// depends on, so it can neither move a route nor close a cycle.
import realms = require('../common/realms');
import store = require('./xacml_store');
// The managed settings' table and the reading of a PEP's report (#1760): a
// library requiring only leaves, so it can neither move a route nor close
// a cycle.
import pepSettings = require('./xacml_pep_settings');
// A remote PEP's listeners (#1760): the reading of what the PEP reports.
import pepListeners = require('./xacml_pep_listeners');

// ---------------------------------------------------------------------------
// AN EMBEDDED PEP'S IDENTITY (#2026, part of #1206; rcbj's D1-D3).
//
// A registration and a heartbeat carry `kind` (`container` | `embedded`;
// ABSENT IS `container`, so every PEP built before this keeps working),
// `application`, `mode` (`central` | `local`, embedded only) and
// `protocolVersion`, and a heartbeat `policyEvents` (D4). The closed sets
// are here; `identityOf()` is the one reading of them.
// ---------------------------------------------------------------------------
const KINDS: readonly string[] = Object.freeze(['container', 'embedded']);
const MODES: readonly string[] = Object.freeze(['central', 'local']);
const POLICY_EVENTS: readonly string[] =
  Object.freeze(['none', 'requested', 'excluded', 'down']);
// THE PEP PROTOCOL VERSIONS THIS SERVICE SPEAKS. A version is added here
// when the control plane changes in a way an older package cannot follow,
// and one is removed when this service stops answering it: a PEP that
// sends one not here is refused (STS-XACML-0342), so a library that fell
// behind is visible on its own registration rather than silently wrong.
const PROTOCOL_VERSIONS: readonly number[] = Object.freeze([1]);

// A control character, C0, DEL or C1, in a heartbeat's text member
// (`reportProblem()`, fuzz run #595).
const REPORT_CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

// The directory functions `ldap/ldap_server.js` installs.
interface PepDirectory {
  certificateIdentity?: (certificate: any) => {
    dn?: string;
    commonName?: string;
    subject?: string;
  };
  allPeps(): Array<{ name: string; dn: string; attributes: object }>;
  writePep(name: string, attributes: object): boolean;
  deletePep(name: string): boolean;
}

// One registered PEP, as `all()` answers it.
interface PepRow {
  name: string;
  dn: string;
  identity: string;
  certificateSubject: string;
  thumbprint: string;
  authenticated: boolean;
  notifyUrl: string;
  bias: string;
  resource: string;
  description: string;
  version: string;
  // The hostname the PEP reports (#1760), validated by `hostnameOf()`; ''
  // when it never reported one (an older PEP).
  hostname: string;
  enabled: boolean;
  registeredAt: string;
  lastSeen: string;
  syncToken: string;
  policyCount: number;
  decisions: number;
  allowed: number;
  refused: number;
  undischargeable: number;
  lastNotify: string;
  // The reverse-proxy configuration (#1760) as stored: the JSON text, or ''
  // when none was ever set. Read and validated by `xacml_pep_proxy.ts`.
  proxy: string;
  // The reverse proxy's CAEP/RISC signal-stream health as the PEP last
  // reported it on a heartbeat (#1760), normalised by `signalsOf()`; null
  // when it never reported any (an older PEP, or one with no proxy).
  signals: PepSignals | null;
  // The settings an administrator set for this PEP (#1760), as stored:
  // the JSON text, or '' when none. Read and validated by
  // `xacml_pep_settings.ts`.
  settings: string;
  // What the PEP last reported having in force, normalised by
  // `xacml_pep_settings.ts`'s `inUseOf()`; null when it never reported.
  settingsInUse: any;
  // The listeners an administrator defined for this PEP (#1760), as stored:
  // the JSON text, or '' when none. Read and validated by
  // `xacml_pep_listeners.ts`.
  listeners: string;
  // What the PEP last reported about every listener it has, normalised by
  // `xacml_pep_listeners.ts`'s `inUseOf()`; null when it never reported.
  listenersInUse: any;
  // AN EMBEDDED PEP (#2026, part of #1206): `container` (an absent kind,
  // so every row an older PEP wrote) or `embedded`; the application it
  // registered for (`application` on the console's row is the BINDING,
  // read off its entry, which the registration had to equal); its mode,
  // `central` or `local`; the protocol version its package speaks (null
  // when it sent none); and whether its application's stream can carry
  // `pep-policies-changed` (`none`, `requested`, `excluded`, `down`, or ''
  // until reported).
  kind: string;
  registeredApplication: string;
  mode: string;
  protocolVersion: number | null;
  policyEvents: string;
  // WHAT THE PEP LAST PULLED (#2027): `repository` (every enabled policy,
  // the container's pull) or `bound-application`; '' until it pulled.
  pullScope: string;
  current: boolean;
  stale: boolean;
}

// WHAT A REGISTRATION OR HEARTBEAT SAYS AN EMBEDDED PEP IS (#2026), read by
// `PepRegistry.identityOf()`: normalised, or a refusal with its status and
// code.
interface PepIdentity {
  ok: boolean;
  kind?: string;
  application?: string;
  mode?: string;
  protocolVersion?: number | null;
  policyEvents?: string;
  status?: number;
  error?: string;
  code?: string;
  why?: string;
}

// What a remote PEP reports about its reverse proxy's CAEP/RISC receivers
// (#1760): COUNTS AND AGES ONLY, and only these members. `at` is when this
// service received the report, so the ages are as of that instant.
interface PepSignals {
  at: string;
  receivers: number;
  healthy: number;
  stale: number;
  staleAfterMs: number;
  pollIntervalMs: number;
  oldestSuccessAgeMs: number | null;
  mostConsecutiveFailures: number;
  setsAccepted: number;
  setsRefused: number;
  sessionsEnded: number;
  librarySessions: {
    held: number;
    max: number;
    ttlSec: number;
    evicted: number;
    expired: number;
  };
  // ONE ROW PER STREAM (#1760), from a PEP that reports them on its
  // heartbeat; absent from an older one. The client id and stream id are
  // held to a charset, the times are computed here from the ages the PEP
  // sent and when the report arrived, and every other member is dropped.
  streams?: PepSignalStream[];
}

// One CAEP/RISC receiver as the PEP reported it.
interface PepSignalStream {
  clientId: string;
  streamId: string;
  running: boolean;
  healthy: boolean;
  startedAt: string | null;
  lastPollAt: string | null;
  lastSuccessAt: string | null;
  consecutiveFailures: number;
  polls: number;
  failedPolls: number;
  setsAccepted: number;
  setsRefused: number;
  sessionsEnded: number;
}

// What a register or heartbeat answers. A refusal carries its code under a
// Symbol (`errorCodes.mark()`).
interface PepResult {
  ok: boolean;
  why?: string;
  name?: string;
  created?: boolean;
  current?: string;
  // THE HTTP STATUS EVERY REFUSAL IS ANSWERED WITH (#1830), on register
  // and heartbeat alike — each refusal says which it is, because the two
  // handlers used to pick one status apiece (400 and 404) and so answered
  // a service that had no directory as if the PEP had sent a bad request
  // or had never registered. Chosen by whose fault it is and whether a
  // retry can succeed:
  //   400  the request: no usable name (0019), a bad hostname (0261);
  //   404  no such row: a heartbeat from a PEP never registered (0021);
  //   503  this process has no directory (0026): nothing the PEP sent is
  //        wrong, and a later attempt — on another node, or after the
  //        directory loads — can succeed;
  //   507  the directory refused the write (0027), which `writePep()` does
  //        only when ou=peps holds xacml.maxPeps or the directory its
  //        entry cap: RFC 4918 section 11.5's "unable to store the
  //        representation", temporary until an operator makes room.
  // A deployed PEP treats any answer but 200 and 201 as a failure and tries
  // again on its next poll, so none of these changes what it does.
  status?: number;
}

// WHAT A HEARTBEAT THAT CHANGED NOTHING DURABLE LEAVES BEHIND (#1882): the
// volatile half of a row, kept in the minted store `liveness` and in this
// process's `latest`, never in the entry. `registeredAt` ties it to the
// registration it describes; `seenAt` is '' on a record that holds only a
// nudge's outcome.
interface LivenessRow {
  registeredAt: string;
  seenAt: string;
  decisions: number;
  allowed: number;
  refused: number;
  undischargeable: number;
  signals: PepSignals | null;
  settingsInUse: any;
  listenersInUse: any;
  lastNotify: string;
}

// The parts of a `realms.map()` store the liveness record is kept in.
interface LivenessStore {
  get(name: string): LivenessRow | undefined;
  set(name: string, row: LivenessRow): unknown;
  delete(name: string): boolean;
}

// The parts of the policy repository the sync token reads.
interface PolicyRepository {
  root(): { name: string } | null;
  all(): Array<{ name: string; document: string; enabled: boolean;
                 application?: string | null;
                 role?: string | null;
                 // What a scoped pull (#2027) sends of a row, beside the
                 // document.
                 id?: string | null; kind?: string; version?: string;
                 combiningAlgId?: string; description?: string;
                 orphanedAt?: string | null }>;
}

// WHAT A PULL SCOPED TO THE BOUND APPLICATION SENDS (#2027): the rows in
// `GET /xacml/pep/policies`' shape, the one marked root (the application's
// own policy, or the realm root when it decides with none), where it came
// from, and the scope's own token.
interface BoundPull {
  scope: string;
  application: string;
  source: 'application' | 'root' | 'none';
  root: string | null;
  policies: Array<Record<string, unknown>>;
  withheld: string[];
  token: string;
}

interface PepRegistryDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    warn(message: string): void;
  };
  config: { value(key: string): any };
  errorCodes: {
    mark<T>(result: T, code: string): T;
    tag(code: string): string;
  };
  realms: {
    currentId(): string;
    list(): Array<{ id: string; name?: string }>;
    run<T>(realm: unknown, fn: () => T): T;
  };
  store: PolicyRepository;
  sha256Base64(text: string): string;
  // The heartbeat's record (#1882): the journalled store every process
  // reads, and this process's newest, journalled or not.
  liveness: LivenessStore;
  latest: LivenessStore;
  // A SCOPED PULL'S TWO QUESTIONS (#2027), optional so a test's own deps
  // that predate them answer none: whether an application enforces
  // fine-grained authorization, and the PolicyIds a document references.
  enforcesFga?(application: string): boolean;
  referencesOf?(document: string): string[];
}

// ---------------------------------------------------------------------------
// THE SCHEMA. Published on `/admin/ldap/*` the way every other container's is,
// because this directory is schemaless and a container of entries carrying
// invented attributes needs to say what they mean somewhere.
// ---------------------------------------------------------------------------
/**
 * The `ou=peps` schema, the object class and attributes a registration
 * entry carries, published on `/admin/ldap/*`.
 */
// The table is written in models/directory/xacml_pep.tsp (#1390).
const SCHEMA = ModelTables.schema('xacmlPep');

// The directory functions, installed by `ldap/ldap_server.js` — module-level,
// as `xacml_store.ts` and `xacml_pip.ts` hold theirs, because the slot is
// filled before the composition root builds the instance (#50, R2; see
// `PepRegistry.setDirectory()`).
let directory: PepDirectory | null = null;
let warnedAboutNoDirectory = false;

// ---------------------------------------------------------------------------
// A HEARTBEAT IS NOT A DIRECTORY WRITE (#1882, rcbj: "not every PEP heartbeat
// needs a directory write").
//
// Until then every heartbeat — and every pull that named a registered PEP,
// which calls `heartbeat(name, {})` — REPLACED the whole entry through
// `writePep()`. At the PEP's defaults (a pull every 15 s, a heartbeat every
// 60 s) that was five rewrites a minute per PEP, each a directory write, a
// persistence flush, a change-log row every node pulls and an audit
// `entry.update` row; 8081's audit log held about 1,900 of them, nearly all
// changing nothing but the last-seen time and the counters. And a pull is a
// GET, which the write made a request the cluster barrier holds.
//
// **THE ENTRY IS WRITTEN WHEN SOMETHING DURABLE CHANGES**, and only then:
// what the PEP is (identity, certificate, version, hostname, bias, resource,
// notify URL), what it holds (sync token, policy count, the settings in
// force, the listeners and their certificates), and everything an
// administrator set. `VOLATILE_ATTRIBUTES` and `durableOf()` say which.
//
// **WHAT IS NOT DURABLE IS KEPT HERE**: last seen, the four counters, the
// signal-stream health, the in-use reports with their stamps and per-listener
// figures, and the last nudge's outcome. `liveness` is a MINTED store —
// journalled, flushed and replicated like any other, so another node reads
// it within one flush — declared `observation: true`, because a heartbeat
// counted is a tally of what a request did and not a thing it did: the
// barrier no longer holds a pull for it (`cluster/CLAUDE.md`, *A decision
// counted is not a write either*). `mergeRow` keeps the newer record of each
// half, and `mergeOnApply` keeps an arriving older row from going over a
// newer one held here.
//
// **AND IT IS JOURNALLED AT MOST ONCE AN INTERVAL** unless the counters
// moved (`journalIntervalMs()`): a fifth of `xacml.pepStaleAfterS`, at most
// a minute. `latest` holds this process's newest record, journalled or not,
// so a read here is exact and a read in another process is at most one
// interval behind on `lastSeen` — a fifth of the stale threshold, which is
// why the stale determination does not move. It is per process because what
// it holds is reachable from no other until it is journalled, and it holds
// one small row per registered PEP (`xacml.maxPeps` bounds it); a process
// that stops loses at most the last interval's `lastSeen`.
//
// **A READER SEES THE NEWER OF THE TWO** (`withLiveness()`): the entry, or a
// record of the same registration seen later. So every reader of `all()` —
// the console's PEP pages, `/admin-api/xacml/peps`, the clusters, the
// monitor, the nudge — is unchanged, an entry written before this change is
// read exactly as it was until its PEP's next heartbeat, and a durable write
// still carries the newest volatile values into the entry.
// ---------------------------------------------------------------------------
const VOLATILE_ATTRIBUTES: readonly string[] = Object.freeze([
  'xacmlPepLastSeen', 'xacmlPepDecisions', 'xacmlPepAllowed',
  'xacmlPepRefused', 'xacmlPepUndischargeable', 'xacmlPepSignals',
  'xacmlPepLastNotify'
]);

const liveness: any = realms.map({
  persist: 'xacml_pep_registry.liveness',
  observation: true,
  mergeRow: function (mine: LivenessRow, theirs: LivenessRow): LivenessRow {
    return PepRegistry.mergeLiveness(mine, theirs);
  },
  mergeOnApply: true
});

// This process's newest record per PEP, journalled or not. Per realm at its
// declaration, as every store is; not persisted, by design (see above).
const latest: any = realms.map();

/**
 * The register of remote Policy Enforcement Points, kept as entries under
 * the realm's `ou=peps` through the directory slot.
 *
 * A row is a record, not a permission: pulling policy needs `REMOTE_PEPS`,
 * not a registration. One client certificate is one entry.
 */
class PepRegistry {
  /**
   * The `ou=peps` schema, the object class and attributes a registration
   * entry carries.
   */
  static readonly SCHEMA = SCHEMA;

  /**
   * The `/admin-api` route whose answer carries this module's prose (#543
   * phase 2b): `/admin/ldap/peps`, which publishes SCHEMA. No other
   * answer carries it.
   */
  static readonly PROSE_ROUTES: readonly string[] =
    Object.freeze(['/admin-api/ldap/peps']);

  /**
   * Extracts this module's console prose (#543 phase 2b): the object
   * class's and each attribute's `what` in SCHEMA.
   *
   * @returns key → English
   */
  static prose(): Record<string, string> {
    helpers.log.debug("Entering PepRegistry.prose().");
    // Lazily, which is safe wherever this module sits in the require order;
    // the extractor is the only caller.
    const serverProse: typeof import('../common/server_prose') =
      require('../common/server_prose');
    const out = serverProse.harvest('xacmlPeps.schema', SCHEMA, ['what']);
    helpers.log.debug("Leaving PepRegistry.prose(). " +
                      Object.keys(out).length);
    return out;
  }

  /**
   * Builds the register over the given dependencies.
   * @param deps - the logger, settings, error codes, realms, the policy
   * repository and a SHA-256 function
   */
  constructor(private readonly deps: PepRegistryDeps) {
    deps.log.debug("Entering PepRegistry.constructor().");
    deps.log.debug("Leaving PepRegistry.constructor().");
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies built from the real modules, for the default
   * instance.
   * @returns the register's dependencies
   */
  static defaultDeps(): PepRegistryDeps {
    helpers.log.debug("Entering PepRegistry.defaultDeps().");
    helpers.log.debug("Leaving PepRegistry.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      realms: realms,
      store: store as unknown as PolicyRepository,
      sha256Base64: function (text) {
        return crypto.digest('sha256', text, 'base64');
      },
      liveness: liveness as LivenessStore,
      latest: latest as LivenessStore,
      enforcesFga: function (application: string): boolean {
        helpers.log.debug("Entering enforcesFga(). " + application);
        // Lazily: the registry is loaded long before the applications
        // registry is asked anything.
        const enforcing = require('../common/applications')
          .applicationsEnforcingFga() || [];
        const out = enforcing.indexOf(application) >= 0;
        helpers.log.debug("Leaving enforcesFga(). " + out);
        return out;
      },
      referencesOf: function (document: string): string[] {
        helpers.log.debug("Entering referencesOf().");
        const out = PepRegistry.referencesIn(
          require('./xacml_xml').parsePolicy(document));
        helpers.log.debug("Leaving referencesOf(). " + out.length);
        return out;
      }
    };
  }

  // Every PolicyIdReference and PolicySetIdReference in a parsed document,
  // at any depth, by its PolicyId, in document order and without repeats.
  static referencesIn(node: any): string[] {
    helpers.log.debug("Entering PepRegistry.referencesIn().");
    const out: string[] = [];
    // A model is a tree, but a walk that met a cycle must still end.
    const seen = new WeakSet();
    const walk = function (one: any): void {
      if (!one || typeof one !== 'object' || seen.has(one)) {
        return;
      }
      seen.add(one);
      if (Array.isArray(one)) {
        one.forEach(walk);
        return;
      }
      if ((one.kind === 'PolicyIdReference' ||
           one.kind === 'PolicySetIdReference') &&
          typeof one.ref === 'string' && one.ref &&
          out.indexOf(one.ref) < 0) {
        out.push(one.ref);
      }
      Object.keys(one).forEach(function (key) {
        walk(one[key]);
      });
    };
    walk(node);
    helpers.log.debug("Leaving PepRegistry.referencesIn(). " + out.length);
    return out;
  }

  // STATIC, BECAUSE THE SLOT IS FILLED BEFORE THE ROOT BUILDS THE INSTANCE
  // (#50, R2). `ldap/ldap_server.js` fills it at ITS load, which happens
  // inside the require that loads this module and so before
  // `common/protocol_stack.ts` reaches this module's build line; a facade
  // there would build a default instance and the root's install would be
  // refused. What it installs is module-level, so it needs no instance.
  /**
   * Installs the directory functions the register reads and writes through;
   * filled by `ldap/ldap_server.js` when it loads.
   * @param fns - the directory functions, or null to remove them
   */
  static setDirectory(fns?: PepDirectory | null): void {
    const { log } = helpers;
    log.debug('Entering PepRegistry.setDirectory().');
    directory = fns || null;
    log.debug('Leaving PepRegistry.setDirectory(). The PEP register ' +
              (directory ? 'has its container.' : 'has none.'));
  }

  // WHAT IS CURRENTLY INSTALLED, so that a test which stubs the slot can put
  // back WHAT WAS THERE rather than `null`. `tests/CLAUDE.md` records why that
  // distinction is not pedantry: `run.js` runs every file in one process, so
  // this is one reference shared by the whole run, and restoring `null` is
  // only correct in a process where `ldap/ldap_server.js` was never loaded —
  // which is a fact about the file list rather than about the test. Nothing
  // in the service calls this, exactly as nothing calls
  // `applications.directoryInstalled()`.
  /**
   * Returns the directory functions currently installed, so that a test can
   * put back what was there.
   * @returns the installed directory functions, or null
   */
  static directoryInstalled(): PepDirectory | null {
    const { log } = helpers;
    log.debug("Entering PepRegistry.directoryInstalled().");
    log.debug("Leaving PepRegistry.directoryInstalled().");
    return directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering PepRegistry.haveDirectory().");
    if (directory) {
      log.debug("Leaving PepRegistry.haveDirectory().");
      return true;
    }
    if (!warnedAboutNoDirectory) {
      warnedAboutNoDirectory = true;
      log.warn('xacml: the embedded directory was never loaded, so there is ' +
               'no ou=peps to register a remote Policy Enforcement Point ' +
               'in. Registration is refused and the register is empty. This ' +
               'is the ordinary state of an in-process test that requires ' +
               'only app.js and one module; it is not a failure, and there ' +
               'is no fallback store, deliberately — a register that quietly ' +
               'lived in memory would list PEPs nobody could find.');
    }
    log.debug("Leaving PepRegistry.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // WHAT IDENTITY A CLIENT CERTIFICATE IS.
  //
  // A passthrough to the slot, and it is a function here rather than a direct
  // call from `xacml.ts` for one reason: `xacml.ts` would then have to know
  // that the answer comes from the directory, and the whole arrangement exists
  // so that a module which needs a NAME does not acquire a dependency on the
  // store that happens to know it. `certificatePlan()` is on the other side.
  //
  // The SUBJECT is added here rather than crossing the slot, because it is on
  // the certificate the caller already holds and does not need looking up.
  // -------------------------------------------------------------------------
  /**
   * Resolves a client certificate to the identity this service names it
   * with, through the directory slot.
   * @param certificate - the peer certificate, as node returns it
   * @returns `{ dn, commonName, subject }`, each '' when there is no
   * directory
   */
  certificateIdentity(certificate: any):
      { dn: string; commonName: string; subject: string } {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.certificateIdentity().');
    if (!this.haveDirectory() ||
        typeof directory.certificateIdentity !== 'function') {
      // NO FALLBACK NAMING RULE, deliberately. Inventing one here would be
      // the second answer to "what identity is this certificate" that the
      // slot exists to prevent, and it would only ever be used in a process
      // with no directory — which is a process with no ou=peps to register
      // into either.
      log.debug('Leaving PepRegistry.certificateIdentity(). No directory.');
      return { dn: '', commonName: '', subject: '' };
    }
    // THE SUBJECT STRING COMES ACROSS THE SLOT TOO, rather than being built
    // here from node's subject object. That looks like the slot carrying one
    // thing too many and it is not: node hands back a null-prototype object
    // of RDN types, this service has exactly one function that turns it into
    // a DN (`helpers.dnRfc4514()`), and a second join written here would
    // produce a string that DIFFERED from the one the same certificate writes
    // arriving on the main port or 636 — which is two identities for one
    // certificate. The other side of the slot has that function; this module
    // does not and should not.
    const named = directory.certificateIdentity(certificate);
    log.debug('Leaving PepRegistry.certificateIdentity(). dn=' + named.dn);
    return { dn: named.dn || '', commonName: named.commonName || '',
             subject: named.subject || '' };
  }

  /**
   * Returns how long a PEP may go unseen before its row is stale
   * (`xacml.pepStaleAfterS`); 300 when unset or not positive.
   * @returns the interval in seconds
   */
  staleAfterS(): number {
    const { log, config } = this.deps;
    log.debug("Entering PepRegistry.staleAfterS().");
    const value = config.value('xacml.pepStaleAfterS');
    log.debug("Leaving PepRegistry.staleAfterS().");
    return typeof value === 'number' && value > 0 ? value : 300;
  }

  // -------------------------------------------------------------------------
  // HOW OFTEN A HEARTBEAT THAT MOVED ONLY `lastSeen` IS JOURNALLED (#1882).
  //
  // DERIVED FROM THE STALE THRESHOLD RATHER THAN A SETTING OF ITS OWN, so
  // the two cannot be set against each other: another process reads a
  // `lastSeen` at most this far behind, and at a fifth of the threshold a
  // PEP that is heartbeating can never be called stale for it. At the
  // default 300 s it is a minute; never under a second, never over a
  // minute, so a long threshold does not leave the other nodes' view of a
  // quiet PEP an hour old.
  // -------------------------------------------------------------------------
  /**
   * Returns the longest a heartbeat whose counters did not move is held in
   * this process before the liveness record is journalled: a fifth of
   * `xacml.pepStaleAfterS`, between one second and one minute.
   * @returns the interval in milliseconds
   */
  journalIntervalMs(): number {
    const { log } = this.deps;
    log.debug("Entering PepRegistry.journalIntervalMs().");
    const fifth = Math.floor(this.staleAfterS() * 1000 / 5);
    log.debug("Leaving PepRegistry.journalIntervalMs().");
    return Math.max(1000, Math.min(60000, fifth));
  }

  // No Entering/Leaving pair: it runs for every candidate record of every
  // row read, and a pair would drown the log. '' and junk are -Infinity, so
  // "never" is older than any instant.
  private static instant(text: unknown): number {
    const at = typeof text === 'string' && text ? Date.parse(text) : NaN;
    return isNaN(at) ? -Infinity : at;
  }

  // The members of a record's SEEN half, as one string: what a tie between
  // two records seen in the same millisecond is broken on, so the merge
  // below answers the same whichever side it is handed first.
  private static seenKey(row: LivenessRow): string {
    helpers.log.debug("Entering PepRegistry.seenKey().");
    helpers.log.debug("Leaving PepRegistry.seenKey().");
    return JSON.stringify([row.seenAt, row.decisions, row.allowed,
                           row.refused, row.undischargeable, row.signals,
                           row.settingsInUse, row.listenersInUse]);
  }

  // -------------------------------------------------------------------------
  // TWO PROCESSES' RECORDS OF ONE PEP, MERGED (#1882): the store's
  // `mergeRow`, so pure and convergent. A later REGISTRATION wins whole,
  // because the earlier one's record describes a process that has gone;
  // otherwise the seen half comes from the record seen later and the nudge
  // half is the later outcome (each is stamped with an ISO instant at its
  // front, so the text compares as the time does).
  // -------------------------------------------------------------------------
  /**
   * Merges two liveness records of one PEP: the later registration's whole,
   * else the later-seen record's counters and reports with the later
   * nudge outcome of the two.
   * @param mine - the record held here
   * @param theirs - the record arriving or stored
   * @returns the merged record
   */
  static mergeLiveness(mine: LivenessRow, theirs: LivenessRow): LivenessRow {
    helpers.log.debug("Entering PepRegistry.mergeLiveness().");
    if (!mine || typeof mine !== 'object') {
      helpers.log.debug("Leaving PepRegistry.mergeLiveness(). Theirs.");
      return theirs;
    }
    if (!theirs || typeof theirs !== 'object') {
      helpers.log.debug("Leaving PepRegistry.mergeLiveness(). Mine.");
      return mine;
    }
    if (String(mine.registeredAt || '') !==
        String(theirs.registeredAt || '')) {
      helpers.log.debug("Leaving PepRegistry.mergeLiveness(). The later " +
                        "registration.");
      return String(mine.registeredAt || '') >
        String(theirs.registeredAt || '') ? mine : theirs;
    }
    const a = PepRegistry.instant(mine.seenAt);
    const b = PepRegistry.instant(theirs.seenAt);
    const seen = a > b ? mine : b > a ? theirs
      : (PepRegistry.seenKey(mine) >= PepRegistry.seenKey(theirs)
          ? mine : theirs);
    const mineNotify = String(mine.lastNotify || '');
    const theirNotify = String(theirs.lastNotify || '');
    helpers.log.debug("Leaving PepRegistry.mergeLiveness().");
    return Object.assign({}, seen, {
      lastNotify: mineNotify >= theirNotify ? mineNotify : theirNotify
    });
  }

  // -------------------------------------------------------------------------
  // THE SYNC TOKEN. See the header — a digest of what would be SENT.
  // -------------------------------------------------------------------------
  /**
   * Returns the digest of what a PEP pulling now would be sent: the enabled
   * policies by name and the root's name, sorted so order does not matter.
   * A policy an application owns is never sent and is not in it.
   * @returns the token, base64url without padding
   */
  syncToken(): string {
    const { log, store, sha256Base64 } = this.deps;
    log.debug('Entering PepRegistry.syncToken().');
    const root = store.root();
    // Sorted by name so that the token is a property of the repository's
    // CONTENT rather than of the order the directory happened to iterate in.
    // A token that changed when nothing had would make every PEP re-pull on
    // every heartbeat and would look exactly like a PEP that cannot hold a
    // copy.
    //
    // A POLICY AN APPLICATION OWNS IS LEFT OUT (#564), because the pull
    // withholds it (`xacml.ts`): every application created writes one, and
    // were it counted here every client registered in the realm would make
    // every remote PEP re-pull a repository whose sent bytes had not moved.
    const parts = store.all().filter(function (row) {
      // Owned by an application or a role (#1072): `XacmlStore.owned()`.
      return row.enabled && !row.application && !row.role;
    }).map(function (row) {
      return row.name + ' ' + row.document;
    }).sort();
    parts.push('root ' + (root ? root.name : ''));
    const digest = sha256Base64(parts.join(''))
                     .replace(/\+/g, '-').replace(/\//g, '_')
                     .replace(/=+$/, '');
    log.debug('Leaving PepRegistry.syncToken(). ' + digest);
    return digest;
  }

  // -------------------------------------------------------------------------
  // THE PULL SCOPED TO THE BOUND APPLICATION (#2027, part of #1206; rcbj's
  // D3 (b)). A `local` embedded PEP decides in process and holds ONLY what
  // its application is decided with:
  //
  //   * THE APPLICATION'S OWN POLICY, withheld from every other pull, when
  //     the application ENFORCES fine-grained authorization
  //     (`appFgaEnforced`) and its policy is enabled. That is the rule
  //     AuthZEN decides the application by (`decideAccess()`, #564 P4): an
  //     application that does not enforce is decided by the realm root even
  //     though it owns a policy (every application created gets one), so a
  //     local PEP holding the policy the service does not use would decide
  //     differently from a central one. An application that owns none
  //     decides by the root for the same reason;
  //   * otherwise THE REALM ROOT;
  //   * and from either, its REFERENCE CLOSURE: every PolicyIdReference
  //     and PolicySetIdReference followed, transitively, among the enabled
  //     policies nobody owns. Never another application's policy or a
  //     role's (an owned policy is never a reference target, the store's
  //     rule), and never the access or issuance policy, which the
  //     repository pull withholds by name for its reason (*This service's
  //     own policies are never pushed*). A reference that resolves to none
  //     of these is left unresolved, which the PEP evaluates as
  //     Indeterminate, as the service's PDP does.
  //
  // THE ENTRY IS SENT AS THE ROOT (`isRoot`), the one row the package
  // evaluates; the closure rows are what its references reach.
  //
  // ITS TOKEN IS A DIGEST OF EXACTLY WHAT IT SENDS (*The sync token is a
  // digest of what would be SENT*, per scope): the scope, the application,
  // where the entry came from, and every row's name, document and root
  // mark. A change to a policy outside the closure, or to another
  // application's, does not move it.
  // -------------------------------------------------------------------------
  /**
   * What `GET /xacml/pep/policies?scope=bound-application` sends a PEP
   * bound to an application, and its token.
   *
   * @param application - the application the PEP is bound to
   * @returns the rows, the root's name, where it came from and the token
   */
  boundPull(application: string): BoundPull {
    const { log, config, store, sha256Base64 } = this.deps;
    log.debug('Entering PepRegistry.boundPull(). ' + application);
    const internal = [config.value('xacml.accessPolicy') || 'access-control',
                      config.value('xacml.issuancePolicy') || 'role-issuance']
      .map(function (one) {
        return String(one).toLowerCase();
      });
    const rows = store.all().slice().sort(function (a, b) {
      return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
    });
    let enforcing = false;
    try {
      enforcing = typeof this.deps.enforcesFga === 'function' &&
        this.deps.enforcesFga(application);
    } catch (e) {
      // A registry that cannot be read is an application decided by the
      // root, which is what AuthZEN decides it by when it cannot read it
      // either; the log says so.
      log.debug('Caught in PepRegistry.boundPull(): ' +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-XACML-0347') + 'xacml: whether "' +
               application + '" enforces fine-grained authorization could ' +
               'not be read, so its PEP is sent the realm root: ' +
               ((e && e.message) || e));
      enforcing = false;
    }
    const own = enforcing ? rows.filter(function (row) {
      return row.enabled && row.application === application &&
        !row.orphanedAt;
    })[0] || null : null;
    const candidates: Record<string, any> = {};
    rows.forEach(function (row) {
      if (row.enabled && row.id && !row.application && !row.role &&
          internal.indexOf(String(row.name).toLowerCase()) < 0 &&
          !Object.prototype.hasOwnProperty.call(candidates, row.id)) {
        candidates[row.id] = row;
      }
    });
    const rootRow = store.root();
    const rootFull = rootRow && internal.indexOf(
      String(rootRow.name).toLowerCase()) < 0
      ? rows.filter(function (row) {
          return row.name === rootRow.name;
        })[0] || null
      : null;
    const entry: any = own || rootFull;
    const sent: any[] = [];
    if (entry) {
      const queue: any[] = [entry];
      const seen: string[] = [entry.name];
      while (queue.length) {
        const row = queue.shift();
        sent.push(row);
        let refs: string[] = [];
        try {
          refs = typeof this.deps.referencesOf === 'function'
            ? this.deps.referencesOf(String(row.document || '')) : [];
        } catch (e) {
          // A document that does not parse references nothing here; the
          // PEP refuses it again and the console shows why.
          log.debug('Caught in PepRegistry.boundPull(): ' +
                    ((e && e.message) || e));
          refs = [];
        }
        refs.forEach(function (ref) {
          const target = Object.prototype.hasOwnProperty.call(candidates,
                                                              ref)
            ? candidates[ref] : null;
          if (target && seen.indexOf(target.name) < 0) {
            seen.push(target.name);
            queue.push(target);
          }
        });
      }
    }
    const policies = sent.map(function (row) {
      return { name: row.name, policyId: row.id, kind: row.kind,
               version: row.version, combiningAlgId: row.combiningAlgId,
               isRoot: row === entry, description: row.description,
               document: row.document };
    });
    const source: 'application' | 'root' | 'none' =
      own ? 'application' : (entry ? 'root' : 'none');
    const parts = policies.map(function (one) {
      return one.name + ' ' + (one.isRoot ? 'root ' : '') + one.document;
    }).sort();
    parts.unshift('bound-application ' + application + ' ' + source);
    const token = sha256Base64(parts.join('\n'))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    log.debug('Leaving PepRegistry.boundPull(). ' + source + ', ' +
              policies.length + ' policy(ies).');
    return { scope: 'bound-application', application: application,
             source: source, root: entry ? entry.name : null,
             policies: policies, withheld: internal.slice(), token: token };
  }

  // THE TOKEN A PEP'S ROW IS COMPARED WITH (#2027): a `local` embedded
  // PEP's is its scope's, every other PEP's the repository's.
  private expectedToken(kind: string, mode: string, application: string,
                        cache: Record<string, string>): string {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.expectedToken().');
    if (kind !== 'embedded' || mode !== 'local' || !application) {
      if (!Object.prototype.hasOwnProperty.call(cache, '')) {
        cache[''] = this.syncToken();
      }
      log.debug('Leaving PepRegistry.expectedToken(). The repository\'s.');
      return cache[''];
    }
    const key = 'app ' + application;
    if (!Object.prototype.hasOwnProperty.call(cache, key)) {
      cache[key] = this.boundPull(application).token;
    }
    log.debug('Leaving PepRegistry.expectedToken(). The scope\'s.');
    return cache[key];
  }

  // -------------------------------------------------------------------------
  // READING. `all()` reads an entry through its concept (#1390), which finds
  // an attribute in any case: LDAP attribute names come back LOWER-CASED
  // (RFC 4512), which cost a boot in phase two — `xacml/CLAUDE.md` records it
  // as the first of four silent defects.
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // A REVERSE PROXY'S SIGNAL-STREAM HEALTH (#1760), held to its members.
  //
  // **ONLY COUNTS AND AGES ARE KEPT, WHATEVER THE PEP SENT.** The PEP's own
  // `GET /` reports the same numbers and promises no client id, URL or error
  // text, because an error can carry the service's address; this is the
  // other end of that promise, so a member this function does not name is
  // dropped rather than stored, and a value that is not a non-negative
  // integer is 0. A REMOTE_PEPS holder cannot use the row to put text on an
  // administrator's page. The same function reads the stored value back, so
  // an ldapmodify that wrote something else is drawn as these members too,
  // and text that is not JSON as "not reported".
  // -------------------------------------------------------------------------
  /**
   * Normalises a reported (or stored) signal-health document.
   * @param raw - the heartbeat's `signals` member, or the stored JSON text
   * @param at - when it was received; the stored `at` when omitted
   * @returns the members this service keeps, or null when there is no
   * object to read
   */
  static signalsOf(raw: unknown, at?: string): PepSignals | null {
    const { log } = helpers;
    log.debug('Entering PepRegistry.signalsOf().');
    let said: any = raw;
    if (typeof said === 'string') {
      try {
        said = said ? JSON.parse(said) : null;
      } catch (e) {
        // Not JSON: nothing a person could be shown as health.
        log.debug('Caught in PepRegistry.signalsOf(): ' +
                  ((e && (e as Error).message) || e));
        said = null;
      }
    }
    if (!said || typeof said !== 'object' || Array.isArray(said)) {
      log.debug('Leaving PepRegistry.signalsOf(). Nothing to read.');
      return null;
    }
    // No Entering/Leaving pair on `count`: it runs fifteen times for every
    // report and every row drawn, and a pair would drown the log.
    const count = function (value: unknown): number {
      return typeof value === 'number' && Number.isSafeInteger(value) &&
        value >= 0 ? value : 0;
    };
    const library = said.librarySessions &&
      typeof said.librarySessions === 'object' ? said.librarySessions : {};
    const stamp = at !== undefined ? at
      : (typeof said.at === 'string' && !isNaN(Date.parse(said.at))
          ? new Date(Date.parse(said.at)).toISOString() : '');
    const signals: PepSignals = {
      at: stamp,
      receivers: count(said.receivers),
      healthy: count(said.healthy),
      stale: count(said.stale),
      staleAfterMs: count(said.staleAfterMs),
      pollIntervalMs: count(said.pollIntervalMs),
      // Null, not 0, when no receiver has polled or started: "no age" and
      // "polled just now" are different facts.
      oldestSuccessAgeMs: said.oldestSuccessAgeMs === null ||
        said.oldestSuccessAgeMs === undefined
        ? null : count(said.oldestSuccessAgeMs),
      mostConsecutiveFailures: count(said.mostConsecutiveFailures),
      setsAccepted: count(said.setsAccepted),
      setsRefused: count(said.setsRefused),
      sessionsEnded: count(said.sessionsEnded),
      librarySessions: {
        held: count(library.held),
        max: count(library.max),
        ttlSec: count(library.ttlSec),
        evicted: count(library.evicted),
        expired: count(library.expired)
      }
    };
    // THE STREAMS, when reported (#1760). A time is the arrival minus the
    // age the PEP sent, so no clock of the PEP's is believed; the stored
    // report is read back as it was written.
    if (Array.isArray(said.streams)) {
      const base = Date.parse(stamp);
      const timeOf = function (age: unknown, stored: unknown): string | null {
        // A report's own times are not read: only a stored one's.
        if (at === undefined && typeof stored === 'string' &&
            !isNaN(Date.parse(stored))) {
          return new Date(Date.parse(stored)).toISOString();
        }
        // AN AGE OLDER THAN THE EPOCH IS NO TIME (fuzz run #595). A safe
        // integer is not a safe AGE: `lastSuccessAgeMs` 9007199254740991
        // put the instant before the earliest a Date can hold, and
        // `toISOString()` THREW — a RangeError past the fault boundary,
        // express's HTML 500. Such an age is no time, as a negative one
        // always was.
        return typeof age === 'number' && Number.isSafeInteger(age) &&
          age >= 0 && !isNaN(base) && age <= base
          ? new Date(base - age).toISOString() : null;
      };
      const ident = function (value: unknown, max: number): string {
        return typeof value === 'string' && value.length <= max &&
          /^[A-Za-z0-9._:~@/+-]*$/.test(value) ? value : '';
      };
      signals.streams = said.streams.slice(0, 64)
        .filter(function (one: any) {
          return one && typeof one === 'object';
        }).map(function (one: any): PepSignalStream {
          return {
            clientId: ident(one.clientId, 256),
            streamId: ident(one.streamId, 128),
            running: one.running === true,
            healthy: one.healthy === true,
            startedAt: timeOf(one.startedAgeMs, one.startedAt),
            lastPollAt: timeOf(one.lastPollAgeMs, one.lastPollAt),
            lastSuccessAt: timeOf(one.lastSuccessAgeMs, one.lastSuccessAt),
            consecutiveFailures: count(one.consecutiveFailures),
            polls: count(one.polls),
            failedPolls: count(one.failedPolls),
            setsAccepted: count(one.setsAccepted),
            setsRefused: count(one.setsRefused),
            sessionsEnded: count(one.sessionsEnded)
          };
        });
    }
    log.debug('Leaving PepRegistry.signalsOf(). ' + signals.receivers +
              ' receiver(s).');
    return signals;
  }

  // -------------------------------------------------------------------------
  // THE HOSTNAME A PEP REPORTS (#1760).
  //
  // A PEP that derives its notify URL picks the DNS name of its HTTPS
  // listener certificate that EQUALS ITS HOSTNAME, and the realm's default
  // certificate names only what this row holds — so on a fresh install,
  // where the PEP registered with no notify URL because it had no
  // certificate yet, the defaults were the registered name alone and the
  // derivation fell through to it (`remote-pep-1`, which nothing resolves).
  // The PEP therefore reports the hostname it derives from, and
  // `xacml_pep_tls.ts`'s `derivedNames()` puts it in the certificate.
  //
  // IT BECOMES A NAME IN A CERTIFICATE THIS SERVICE SIGNS, so it is held to
  // exactly what a DNS subjectAltName may be: labels of letters, digits and
  // hyphens, 1-63 each, 253 in all, the last not all digits, and never an
  // IP literal (which would have to be an IP subjectAltName, and is not what
  // a container is known by). Lower-cased, a trailing dot dropped. Anything
  // else is REFUSED with STS-XACML-0261 rather than dropped, so a PEP that
  // sends junk finds out; the PEP applies the same rule before it sends, so
  // a well-behaved one never meets the refusal. Absent, null or '' is "not
  // reported", which is what an older PEP sends.
  // -------------------------------------------------------------------------
  /**
   * Validates the hostname a PEP reports on its registration or heartbeat.
   *
   * @param value - the `hostname` member as it arrived
   * @returns `{ ok: true, hostname }` (lower-cased, '' when not reported),
   *   or `{ ok: false, why, status: 400 }` carrying STS-XACML-0261
   */
  static hostnameOf(value: unknown): { ok: boolean; hostname?: string;
                                       why?: string; status?: number } {
    const { log } = helpers;
    log.debug('Entering PepRegistry.hostnameOf().');
    if (value === undefined || value === null || value === '') {
      log.debug('Leaving PepRegistry.hostnameOf(). Not reported.');
      return { ok: true, hostname: '' };
    }
    const text = typeof value === 'string'
      ? value.trim().toLowerCase().replace(/\.$/, '') : null;
    const labels = text === null ? [] : text.split('.');
    const good = text !== null && text.length > 0 && text.length <= 253 &&
      !net.isIP(text.replace(/^\[|\]$/g, '')) &&
      labels.every(function (label) {
        return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
      }) &&
      !/^[0-9]+$/.test(labels[labels.length - 1]);
    if (!good) {
      const why = '`hostname` must be this PEP\'s hostname as a DNS name: ' +
        'letters, digits and hyphens in dot-separated labels of at most 63 ' +
        'characters, 253 in all, not an IP address. It is put in the ' +
        'realm\'s default listener certificate, so nothing else is ' +
        'accepted. Leave it out to report none.';
      log.debug('Leaving PepRegistry.hostnameOf(). Refused.');
      return errorCodes.mark({ ok: false, status: 400, why: why },
                             'STS-XACML-0261');
    }
    log.debug('Leaving PepRegistry.hostnameOf(). ' + text);
    return { ok: true, hostname: text };
  }

  // -------------------------------------------------------------------------
  // WHAT A HEARTBEAT MAY CARRY (fuzz run #595).
  //
  // The fuzz gate's pep-control-plane profile sent a heartbeat of counters
  // past Number.MAX_SAFE_INTEGER (`"refused": -50380761491719199916032`),
  // negative counts and ages, an age as a string and strings carrying
  // control characters, in all three fuzz realms, and the service answered
  // express's HTML 500: a stream's `lastSuccessAgeMs` of 2^53 - 1 put its
  // instant before the earliest a Date holds and `signalsOf()`'s
  // `toISOString()` threw. That is fixed where it threw (`timeOf()`, which
  // answers null for such an age). This is the other half: what the PEP's
  // ENTRY stores was taken as given — a counter of -5e22 was stored as -5
  // (`parseInt()` of its exponent form), which is neither what the PEP said
  // nor zero, and `version` went into its attribute with a control
  // character in it.
  //
  // **SO THE MEMBERS THE ENTRY STORES ARE REFUSED, WHOLE, BEFORE ANYTHING IS
  // READ** — `models/pep/pep_control_plane.tsp`'s `HeartbeatRequest`, which
  // says so: a counter (`policyCount`, `decisions`, `allowed`, `refused`,
  // `undischargeable`) is a non-negative safe integer, a text member
  // (`syncToken`, `bias`, `resource`, `version`, `notifyUrl`) a string with
  // no C0, DEL or C1 control character, or null, which has always cleared
  // it, and `signals`, `settings` and `listeners` an object or null. A
  // refusal is 400 STS-XACML-0331 naming the member and writes nothing —
  // `hostname`'s rule (STS-XACML-0261). The PEP sends nothing else
  // (`rust/bins/xacml-pep/src/sync.rs`: u64 counters, Strings), so a
  // well-behaved one never meets it.
  //
  // **WITHIN `signals` AND `listeners` A VALUE IS STILL HELD TO ITS MEMBER,
  // NOT REFUSED** (`signalsOf()`, `pepListeners.inUseOf()`): a count that is
  // not a non-negative integer is 0 and an unknown member is dropped,
  // "whatever the PEP sent", which is the design those two argue and
  // `tests/xacml_pep_proxy.js` B4/B5 hold. Neither can throw or reach the
  // entry as anything but the kept members.
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // WHAT A REGISTRATION OR A HEARTBEAT SAYS THE PEP IS (#2026, part of
  // #1206), read ONCE, here, for both doors. Refused, in this order, each
  // before anything is written:
  //
  //   * a `kind` that is neither `container` nor `embedded` (0342). ABSENT
  //     IS THE ROW'S on a heartbeat and `container` on a registration, so a
  //     PEP built before this — which sends none — is a container, as it
  //     always was;
  //   * `mode` with a container (0341): `central` and `local` are an
  //     embedded PEP's, and a container that sends one has been configured
  //     as something it is not; an embedded PEP's mode that is neither (0342);
  //   * a `protocolVersion` this service does not speak (0340), and none
  //     at all from an embedded PEP, whose package always sends one: a
  //     library that fell behind is refused on its own registration;
  //   * a `policyEvents` outside the four words (0342);
  //   * AN EMBEDDED PEP NOT BOUND, OR BOUND ELSEWHERE (0338, 0339), against
  //     `boundTo` — `stsPepApplication` on its entry, which the caller reads
  //     (`xacml_pep_binding.ts`) because this module holds no directory of
  //     people. 403, not 400: the PEP's request is well formed and it is
  //     not allowed to be what it says. This is what stops a PEP key
  //     copied into another application posing as that application's PEP.
  //
  // A HEARTBEAT ASKS THE SAME, so a binding an administrator removed or
  // moved refuses the PEP's next heartbeat rather than leaving a row that
  // claims an application it is no longer bound to.
  // -------------------------------------------------------------------------
  /**
   * Reads what a registration or heartbeat says the PEP is, against the
   * application its entry is bound to.
   *
   * @param said - the request body
   * @param kept - the PEP's row, on a heartbeat; null on a registration
   * @param boundTo - the application the PEP's entry is bound to, or ''
   * @returns the identity normalised, or a refusal with status and code
   */
  static identityOf(said: any, kept: PepRow | null,
                    boundTo: string): PepIdentity {
    const { log } = helpers;
    log.debug('Entering PepRegistry.identityOf().');
    const body = said && typeof said === 'object' ? said : {};
    const refuse = function (status: number, code: string,
                             why: string): PepIdentity {
      log.debug('Entering refuse(). ' + code);
      log.debug('Leaving refuse().');
      return { ok: false, status: status, code: code, why: why,
               error: status === 403 ? 'access_denied' : 'invalid_request' };
    };
    const kind = body.kind === undefined || body.kind === null
      ? (kept ? kept.kind : 'container') : body.kind;
    if (typeof kind !== 'string' || KINDS.indexOf(kind) < 0) {
      log.debug('Leaving PepRegistry.identityOf(). An unknown kind.');
      return refuse(400, 'STS-XACML-0344', '`kind` is container (or ' +
        'absent) for the xacml-pep image, or embedded for a PEP inside an ' +
        'authentication library; nothing else is a remote PEP here.');
    }
    const sentMode = body.mode !== undefined && body.mode !== null &&
      body.mode !== '';
    if (kind === 'container' && sentMode) {
      log.debug('Leaving PepRegistry.identityOf(). Mode with a container.');
      return refuse(400, 'STS-XACML-0343', '`mode` (central or local) is ' +
        'an embedded PEP\'s, and this one registers as a container (kind ' +
        'container, or no kind). Send kind embedded with the application ' +
        'it is embedded in, or leave mode out.');
    }
    const mode = kind === 'container' ? ''
      : sentMode ? body.mode
      : (kept && kept.kind === 'embedded' ? kept.mode : '');
    if (kind === 'embedded' &&
        (typeof mode !== 'string' || MODES.indexOf(mode) < 0)) {
      log.debug('Leaving PepRegistry.identityOf(). No usable mode.');
      return refuse(400, 'STS-XACML-0344', 'An embedded PEP says its mode: ' +
        'central (every decision asked of this service) or local (its ' +
        'application\'s policies pulled and decided in process).');
    }
    const sentVersion = body.protocolVersion !== undefined &&
      body.protocolVersion !== null;
    const version = sentVersion ? body.protocolVersion
      : (kept ? kept.protocolVersion : null);
    if ((version !== null && (typeof version !== 'number' ||
         PROTOCOL_VERSIONS.indexOf(version) < 0)) ||
        (kind === 'embedded' && version === null)) {
      log.debug('Leaving PepRegistry.identityOf(). An unsupported version.');
      return refuse(400, 'STS-XACML-0342', 'This service speaks PEP ' +
        'protocol version ' + PROTOCOL_VERSIONS.join(', ') + ', and this ' +
        'PEP ' + (version === null ? 'sent none'
          : 'speaks ' + String(version).slice(0, 20)) + '. Upgrade the ' +
        'PEP\'s package (iya-pep) to one that speaks a supported version.');
    }
    const events = body.policyEvents === undefined
      ? (kept ? kept.policyEvents : '') : body.policyEvents;
    if (events !== null && events !== '' &&
        (typeof events !== 'string' || POLICY_EVENTS.indexOf(events) < 0)) {
      log.debug('Leaving PepRegistry.identityOf(). Unknown policyEvents.');
      return refuse(400, 'STS-XACML-0344', '`policyEvents` is none, ' +
        'requested, excluded or down: whether the stream of the ' +
        'application the PEP is embedded in can carry pep-policies-changed.');
    }
    const application = kind === 'container' ? ''
      : body.application === undefined || body.application === null
        ? (kept ? kept.registeredApplication : '')
        : String(body.application);
    if (kind === 'embedded' && !boundTo) {
      log.debug('Leaving PepRegistry.identityOf(). Not bound.');
      return refuse(403, 'STS-XACML-0340', 'This PEP registers as embedded ' +
        'in "' + application.slice(0, 120) + '", and its entry is bound to ' +
        'no application. An administrator binds it first ' +
        '(set-pep-application, or issue-pep-credential with an ' +
        'application).');
    }
    if (kind === 'embedded' && application !== boundTo) {
      log.debug('Leaving PepRegistry.identityOf(). Bound elsewhere.');
      return refuse(403, 'STS-XACML-0341', application
        ? 'This PEP registers as embedded in "' + application.slice(0, 120) +
          '", and its entry is bound to "' + boundTo + '". An embedded PEP ' +
          'is admitted only for the application it is bound to.'
        : 'An embedded PEP names the application it is embedded in ' +
          '(`application`); this one is bound to "' + boundTo + '".');
    }
    log.debug('Leaving PepRegistry.identityOf(). ' + kind +
              (mode ? ' ' + mode : ''));
    return { ok: true, kind: kind, application: application, mode: mode,
             protocolVersion: version,
             policyEvents: kind === 'embedded' ? String(events || '') : '' };
  }

  // The identity's attributes on an entry (#2026), each only when it says
  // something, so a container's entry is written as it always was.
  private static identityAttributes(attributes: Record<string, unknown>,
                                    identity: any): void {
    helpers.log.debug("Entering PepRegistry.identityAttributes().");
    const set = function (name: string, value: unknown): void {
      helpers.log.debug("Entering set().");
      if (value === undefined || value === null || value === '') {
        delete attributes[name];
      } else {
        attributes[name] = String(value);
      }
      helpers.log.debug("Leaving set().");
    };
    const embedded = identity.kind === 'embedded';
    set('xacmlPepKind', embedded ? 'embedded' : '');
    set('xacmlPepApplication', embedded ? identity.application : '');
    set('xacmlPepMode', embedded ? identity.mode : '');
    set('xacmlPepProtocolVersion', identity.protocolVersion);
    set('xacmlPepPolicyEvents', embedded ? identity.policyEvents : '');
    helpers.log.debug("Leaving PepRegistry.identityAttributes().");
  }

  /**
   * The first member of a heartbeat report the service cannot hold.
   * @param report - what the PEP reports (the handler's object)
   * @returns a sentence naming the member, or null when it may be held
   */
  static reportProblem(report: unknown): string | null {
    const { log } = helpers;
    log.debug('Entering PepRegistry.reportProblem().');
    const said: any = report && typeof report === 'object' ? report : {};
    const problems: string[] = [];
    ['policyCount', 'decisions', 'allowed', 'refused',
     'undischargeable'].forEach(function (key) {
      const value = said[key];
      if (value !== undefined && !(typeof value === 'number' &&
          Number.isSafeInteger(value) && value >= 0)) {
        problems.push('`' + key + '` is not a non-negative integer of at ' +
                      'most ' + Number.MAX_SAFE_INTEGER + '.');
      }
    });
    ['syncToken', 'bias', 'resource', 'version',
     'notifyUrl'].forEach(function (key) {
      const value = said[key];
      if (value !== undefined && value !== null &&
          !(typeof value === 'string' && !REPORT_CONTROL.test(value))) {
        problems.push('`' + key + '` is not a string free of control ' +
                      'characters.');
      }
    });
    ['signals', 'settings', 'listeners'].forEach(function (key) {
      const value = said[key];
      if (value !== undefined && value !== null &&
          !(typeof value === 'object' && !Array.isArray(value))) {
        problems.push('`' + key + '` is not an object or null.');
      }
    });
    const found = problems[0] || null;
    log.debug('Leaving PepRegistry.reportProblem(). ' + (found || 'None.'));
    return found;
  }

  private number(value: unknown): number {
    const { log } = this.deps;
    log.debug("Entering PepRegistry.number().");
    const n = parseInt(value as string, 10);
    log.debug("Leaving PepRegistry.number().");
    return isNaN(n) ? 0 : n;
  }

  // -------------------------------------------------------------------------
  // WHERE A REMOTE PEP IS, WHEN IT IS NOT HERE (2026-09-06).
  //
  // **`ou=peps` IS PER REALM, AND THIS PAGE SHOWS ONE REALM**, like every
  // other page in this console. So "no remote Policy Enforcement Point has
  // registered" was a sentence with two causes and it named neither: nothing
  // anywhere, or nothing IN THE REALM BEING READ while another realm holds
  // one. That is exactly the failure `/admin/realms`'s off-banner records
  // having shipped — **a predicate that is false for two reasons must not be
  // rendered as a message that names one of them** — and this is the same
  // mistake in a different file.
  //
  // It cost somebody real time, and the case is worth writing down because
  // nothing about it looks like a mistake from either end.
  // `tests/protocol/sts_xacml_remote_pep.js` drives the `xacml-pep/`
  // container against a THROWAWAY REALM (`XACML_PEP_REALM`, `pep-e2e` by
  // default), so a registration made by a passing suite has never been in the
  // default realm and never will be — while the default realm's page said, in
  // effect, that nothing had registered. **That job REMOVED the realm at its
  // teardown until 2026-09-06**, taking its `ou=peps` with it, so after a
  // green run the honest answer was "none anywhere" — with a PEP container
  // still running and still polling a realm that was gone. The suite leaves
  // its realms standing now, so the ordinary state after a run is the second
  // one: a registration in `pep-e2e` and none in the realm being read. Those
  // are two different states and a reader has to be able to tell them apart.
  //
  // THE WALK IS OVER `realms.list()` AND IS BOUNDED BY IT. A service with no
  // realms defined does nothing at all here, because that list is the default
  // realm alone and the default realm is the one being read. It is computed
  // when the page is drawn rather than kept, for `/admin/metrics`'s reason:
  // what is registered is a function of what has been written since.
  // -------------------------------------------------------------------------
  /**
   * Lists the other trust realms that hold a registration, so that an empty
   * register here can be told from an empty register everywhere.
   * @returns `{ id, name, count }` per other realm with at least one row
   */
  elsewhere(): Array<{ id: string; name: string; count: number }> {
    const self = this;
    const { log, realms, errorCodes } = this.deps;
    log.debug('Entering PepRegistry.elsewhere().');
    const here = realms.currentId();
    const found: Array<{ id: string; name: string; count: number }> = [];
    realms.list().forEach(function (realm) {
      if (!realm || realm.id === here) {
        return;
      }
      // `realms.run()` because `all()` reaches the directory through the slot
      // `ldap_server.js` fills, and that resolves the container from the
      // AMBIENT realm. Reading another realm's register means being in it.
      const rows = realms.run(realm, function () {
        try {
          return self.all();
        } catch (e) {
          // A realm whose directory subtree is mid-build answers nothing
          // rather than taking the page down: this is a hint about where to
          // look, and a hint that throws is worse than no hint.
          log.warn(errorCodes.tag('STS-XACML-0064') +
                   'xacml: could not read the "' + realm.id + '" realm\'s ' +
                   'remote PEP register: ' + e.message);
          return [];
        }
      });
      if (rows && rows.length) {
        found.push({ id: realm.id, name: realm.name || realm.id,
                     count: rows.length });
      }
    });
    log.debug('Leaving PepRegistry.elsewhere(). ' + found.length +
              ' other realm(s) hold one.');
    return found;
  }

  /**
   * Lists every registered PEP in the current realm, each with the derived
   * `current` (its sync token matches) and `stale` flags.
   * @returns the rows; empty when there is no directory
   */
  all(): PepRow[] {
    const self = this;
    const { log } = this.deps;
    log.debug('Entering PepRegistry.all().');
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.all(). No directory.');
      return [];
    }
    const now = Date.now();
    const stale = this.staleAfterS() * 1000;
    const rows = this.entryRows().map(function (row) {
      return self.withLiveness(row, now, stale);
    });
    log.debug('Leaving PepRegistry.all(). ' + rows.length +
              ' registered PEP(s).');
    return rows;
  }

  // -------------------------------------------------------------------------
  // THE ENTRY AND THE HEARTBEAT'S RECORD, JOINED (#1882). The volatile half
  // of the row is the newest of three: the entry's, the journalled record
  // every process reads, and this process's own. A record counts only for
  // the registration it was made under (`registeredAt`), and only when SEEN
  // LATER than the entry was written — a tie is the entry's, so a
  // registration in the same millisecond as a heartbeat drops what a new
  // process has not reported yet, as it always did. The nudge's outcome is
  // the latest of the three on its own, because a nudge moves no `lastSeen`.
  // -------------------------------------------------------------------------
  private withLiveness(row: PepRow, now: number, staleMs: number): PepRow {
    const { log, liveness, latest } = this.deps;
    log.debug('Entering PepRegistry.withLiveness(). name=' + row.name);
    const records = [latest.get(row.name), liveness.get(row.name)]
      .filter(function (one) {
        return !!one && typeof one === 'object' &&
          String(one.registeredAt || '') === row.registeredAt;
      });
    // A loop rather than forEach, so the checker sees `newest` assigned.
    let newest: LivenessRow | null = null;
    let newestAt = PepRegistry.instant(row.lastSeen);
    let lastNotify = row.lastNotify;
    for (const one of records) {
      const at = PepRegistry.instant(one.seenAt);
      if (at > newestAt) {
        newest = one;
        newestAt = at;
      }
      if (String(one.lastNotify || '') > lastNotify) {
        lastNotify = String(one.lastNotify);
      }
    }
    if (!newest) {
      log.debug('Leaving PepRegistry.withLiveness(). The entry\'s.');
      return lastNotify === row.lastNotify ? row
        : Object.assign({}, row, { lastNotify: lastNotify });
    }
    const seen: LivenessRow = newest;
    log.debug('Leaving PepRegistry.withLiveness(). Seen ' + seen.seenAt);
    return Object.assign({}, row, {
      lastSeen: seen.seenAt,
      decisions: seen.decisions || 0,
      allowed: seen.allowed || 0,
      refused: seen.refused || 0,
      undischargeable: seen.undischargeable || 0,
      signals: seen.signals || null,
      settingsInUse: seen.settingsInUse || null,
      listenersInUse: seen.listenersInUse || null,
      lastNotify: lastNotify,
      stale: (now - newestAt) > staleMs
    });
  }

  // The journalled record of this registration of a PEP, or null.
  private storedFor(entry: PepRow): LivenessRow | null {
    const { log, liveness } = this.deps;
    log.debug('Entering PepRegistry.storedFor(). name=' + entry.name);
    const stored = liveness.get(entry.name);
    const mine = !!stored && typeof stored === 'object' &&
      String(stored.registeredAt || '') === entry.registeredAt;
    log.debug('Leaving PepRegistry.storedFor(). ' +
              (mine ? 'Held.' : 'None.'));
    return mine ? stored : null;
  }

  // One PEP's ENTRY as it is stored, without the heartbeat's record (#1882):
  // what a heartbeat compares against to decide whether it changed anything
  // durable.
  private readEntry(name: string): PepRow | null {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.readEntry(). name=' + name);
    const found = this.entryRows().filter(function (row) {
      return row.name === name;
    })[0] || null;
    log.debug('Leaving PepRegistry.readEntry(). ' +
              (found ? 'Found.' : 'Not found.'));
    return found;
  }

  // Every entry under ou=peps as a row, as it is STORED — `all()` without
  // the heartbeat's record (#1882). The caller has checked the directory.
  private entryRows(): PepRow[] {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.entryRows().');
    const self = this;
    // Each row is compared with the token of what IT pulls (#2027): one
    // digest per scope asked, whatever the number of rows.
    const tokens: Record<string, string> = {};
    const now = Date.now();
    const stale = this.staleAfterS() * 1000;
    const rows = directory.allPeps().map(function (entry): PepRow {
      const pep = DomainClasses.XacmlPep.fromEntry(entry.attributes);
      const lastSeen = pep.lastSeen || '';
      const seenAt = lastSeen ? Date.parse(lastSeen) : NaN;
      const token = pep.syncToken || '';
      return {
        name: entry.name,
        dn: entry.dn,
        identity: pep.identity || '',
        certificateSubject: pep.certificateSubject || '',
        thumbprint: pep.thumbprint || '',
        authenticated: pep.authenticated === true,
        notifyUrl: pep.notifyUrl || '',
        bias: pep.bias || '',
        resource: pep.resource || '',
        description: (pep.description || [])[0] || '',
        version: pep.version || '',
        hostname: pep.hostname || '',
        // A missing mark is not FALSE: only one that says so disables it.
        enabled: pep.enabled !== false,
        registeredAt: pep.registeredAt || '',
        lastSeen: lastSeen,
        syncToken: token,
        policyCount: pep.policyCount || 0,
        decisions: pep.decisions || 0,
        allowed: pep.allowed || 0,
        refused: pep.refused || 0,
        undischargeable: pep.undischargeable || 0,
        lastNotify: pep.lastNotify || '',
        proxy: pep.proxy || '',
        signals: PepRegistry.signalsOf(pep.signals || ''),
        settings: pep.settings || '',
        settingsInUse: pepSettings.inUseOf(pep.settingsInUse || ''),
        listeners: pep.listeners || '',
        listenersInUse: pepListeners.inUseOf(pep.listenersInUse || ''),
        // AN EMBEDDED PEP (#2026): an entry with no kind is a container's,
        // which is every entry written before the kind existed.
        kind: pep.kind === 'embedded' ? 'embedded' : 'container',
        registeredApplication: pep.application || '',
        mode: pep.mode || '',
        protocolVersion: typeof pep.protocolVersion === 'number'
          ? pep.protocolVersion : null,
        policyEvents: pep.policyEvents || '',
        pullScope: pep.pullScope || '',
        // DERIVED, not stored, and both of them for the same reason: a
        // stored "current" would be a second copy of a comparison, and it
        // would be wrong the moment somebody edited a policy without this row
        // being rewritten.
        current: !!token && token === self.expectedToken(
          pep.kind === 'embedded' ? 'embedded' : 'container',
          pep.mode || '', pep.application || '', tokens),
        stale: !(seenAt > 0) || (now - seenAt) > stale
      };
    });
    log.debug('Leaving PepRegistry.entryRows(). ' + rows.length +
              ' entry/entries.');
    return rows;
  }

  /**
   * Returns one registered PEP by name.
   * @param name - the PEP's entry name
   * @returns the row, or null when not registered
   */
  read(name: string): PepRow | null {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.read(). name=' + name);
    const found = this.all().filter(function (row) {
      return row.name === name;
    })[0] || null;
    log.debug('Leaving PepRegistry.read(). ' +
              (found ? 'Found.' : 'Not found.'));
    return found;
  }

  // A PEP name is an entry name, so it follows `xacml_store.ts`'s rule for
  // one — and it is DERIVED from a certificate rather than typed, which means
  // the characters a subject may legitimately hold have to be FOLDED rather
  // than refused. A common name of `pep-1.example.com` keeps its dots; a
  // subject with a comma or an equals sign in it has them replaced, because
  // those are DN syntax and a name carrying them would have to be escaped by
  // every reader separately.
  /**
   * Folds a certificate common name or a given name into an entry name:
   * letters, digits, dot, dash and underscore, at most 128 characters.
   * @param raw - the name to fold
   * @returns the folded name, '' when nothing usable is left
   */
  nameFrom(raw: unknown): string {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.nameFrom(). raw=' + raw);
    const folded = String(raw || '').trim()
      .replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '').slice(0, 128);
    log.debug('Leaving PepRegistry.nameFrom(). ' + folded);
    return folded;
  }

  // -------------------------------------------------------------------------
  // REGISTERING.
  //
  // `identity` is what the caller's certificate resolved to and is supplied
  // by `xacml.ts` rather than computed here — this module has no request, no
  // socket and no `certificatePlan()`, and it is a library for exactly that
  // reason.
  // -------------------------------------------------------------------------
  /**
   * Registers a remote PEP, or updates its row when it re-registers.
   *
   * A re-registration keeps the registration date, the counters, the sync
   * token and a disabled state.
   * @param record - the registration: name, identity, certificate subject,
   * thumbprint, authenticated, notify URL, bias, resource, version and
   * description
   * @returns `{ ok: true, name, created }`, or `{ ok: false, why }` carrying
   * its error code when there is no directory, no usable name or the
   * directory refuses the entry
   */
  register(record?: any): PepResult {
    const { log, config, errorCodes } = this.deps;
    log.debug('Entering PepRegistry.register().');
    const given = record || {};
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.register(). No directory.');
      // error-code: none — the code is the mark()'s, after the reason.
      return errorCodes.mark({ ok: false, status: 503,
                               why: 'There is no embedded directory, so ' +
                                    'there is nowhere to register a Policy ' +
                                    'Enforcement Point.' }, 'STS-XACML-0026');
    }
    const name = this.nameFrom(given.name);
    if (!name) {
      log.debug('Leaving PepRegistry.register(). No usable name.');
      // error-code: none — the code is the mark()'s, after the reason.
      return errorCodes.mark({ ok: false, status: 400,
               why: 'A remote PEP is named from the common name of the ' +
                    'client certificate it registered with, or — when ' +
                    'xacml.pepRequireCertificate is off — from the `name` ' +
                    'in the registration. Neither produced anything usable ' +
                    'after folding to letters, digits, dot, dash and ' +
                    'underscore.' },
                             'STS-XACML-0019');
    }
    // THE HOSTNAME (#1760), refused before anything is written.
    const host = PepRegistry.hostnameOf(given.hostname);
    if (!host.ok) {
      log.debug('Leaving PepRegistry.register(). A bad hostname.');
      return host as PepResult;
    }
    const existing = this.read(name);
    const now = new Date().toISOString();
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'xacmlPep'],
      xacmlPepIdentity: String(given.identity || ''),
      xacmlPepCertificateSubject: String(given.certificateSubject || ''),
      xacmlPepThumbprint: String(given.thumbprint || ''),
      xacmlPepAuthenticated: given.authenticated ? 'TRUE' : 'FALSE',
      xacmlPepNotifyUrl: String(given.notifyUrl || ''),
      xacmlPepBias: String(given.bias || ''),
      xacmlPepResource: String(given.resource || ''),
      xacmlPepVersion: String(given.version || ''),
      // A RE-REGISTRATION KEEPS THE ORIGINAL DATE. A component that restarts
      // every few minutes is a fact somebody wants to see, and a registration
      // date that reset on each restart could never show it.
      xacmlPepRegisteredAt: existing ? existing.registeredAt || now : now,
      xacmlPepLastSeen: now,
      // AND IT KEEPS THE COUNTERS AND THE SYNC TOKEN, which is the same
      // decision read from the other side: a PEP that re-registers has not
      // un-enforced anything, and zeroing its counters would make a restart
      // loop look like a component that has never done any work.
      xacmlPepSyncToken: existing ? existing.syncToken : '',
      xacmlPepPolicyCount: String(existing ? existing.policyCount : 0),
      xacmlPepDecisions: String(existing ? existing.decisions : 0),
      xacmlPepAllowed: String(existing ? existing.allowed : 0),
      xacmlPepRefused: String(existing ? existing.refused : 0),
      xacmlPepUndischargeable:
        String(existing ? existing.undischargeable : 0),
      xacmlPepLastNotify: existing ? existing.lastNotify : '',
      // ENABLED IS KEPT TOO, and this is the one that would have been a
      // security-shaped mistake to get wrong the other way round: a PEP an
      // administrator disabled must not be able to re-enable itself by
      // reconnecting.
      xacmlPepEnabled: existing && !existing.enabled ? 'FALSE' : 'TRUE'
    };
    // THE PROXY CONFIGURATION IS KEPT (#1760): it is an administrator's, set
    // through `setProxy()`, and a PEP that re-registers must not be able to
    // drop or replace what it is told to enforce by reconnecting — the
    // disabled flag's argument above.
    if (existing && existing.proxy) {
      attributes.xacmlPepProxy = existing.proxy;
    }
    // THE MANAGED SETTINGS ARE KEPT TOO (#1760), for the same reason; what
    // the PEP reported having in force is NOT, as the signal health is not:
    // a registration is a new process, and its first heartbeat reports.
    if (existing && existing.settings) {
      attributes.xacmlPepSettings = existing.settings;
    }
    // AND THE DEFINED LISTENERS (#1760), for the same reason; what the PEP
    // reported about them is dropped, as the settings in force are.
    if (existing && existing.listeners) {
      attributes.xacmlPepListeners = existing.listeners;
    }
    // THE HOSTNAME IS THE REGISTRATION'S (#1760): a registration is a new
    // process, so one without it (an older PEP) drops it, and an entry that
    // never had one is written exactly as it always was.
    if (host.hostname) {
      attributes.xacmlPepHostname = host.hostname;
    }
    // AN EMBEDDED PEP'S IDENTITY (#2026), as `identityOf()` read it in the
    // handler; written only when there is something to say, so a
    // container's entry is written exactly as it always was. A
    // registration is a new process: what it said replaces what was held,
    // and its stream's report waits for its first heartbeat.
    PepRegistry.identityAttributes(attributes, {
      kind: given.kind, application: given.application, mode: given.mode,
      protocolVersion: given.protocolVersion, policyEvents: ''
    });
    // WHAT IT PULLS IS KEPT (#2027): a PEP that restarts pulls the same
    // scope, and keeping it keeps the audit row for a CHANGE of scope from
    // being written on every restart.
    if (existing && existing.pullScope) {
      attributes.xacmlPepPullScope = existing.pullScope;
    }
    // THE SIGNAL HEALTH IS NOT KEPT across a registration: a PEP registers
    // when its process starts, so the last snapshot describes receivers that
    // no longer exist. The next heartbeat reports the new ones.
    if (given.description) {
      attributes.description = String(given.description);
    } else if (existing && existing.description) {
      attributes.description = existing.description;
    }
    const written = directory.writePep(name, attributes);
    if (!written) {
      log.debug('Leaving PepRegistry.register(). The directory refused it.');
      // error-code: none — the code is the mark()'s, after the reason.
      return errorCodes.mark({ ok: false, status: 507,
               why: 'The directory refused the entry. ou=peps may be at its ' +
                    'maximum of ' + config.value('xacml.maxPeps') +
                    ' (xacml.maxPeps).' }, 'STS-XACML-0027');
    }
    // THE ENTRY IS NOW THE NEWEST RECORD (#1882): it carries the counters
    // kept above and a `lastSeen` of now, so this process's held record is
    // dropped; a journalled one is older and is not read.
    this.deps.latest.delete(name);
    log.info('xacml: remote PEP "' + name + '" ' +
             (existing ? 're-registered' : 'registered') +
             (given.authenticated && !given.certificateSubject
               // #1827's follow-up: a token names no certificate subject;
               // the thumbprint is its DPoP key's.
               ? ' with a DPoP-bound access token (key ' +
                 String(given.thumbprint || '') + ')'
               : given.authenticated
               ? ' with client certificate ' + given.certificateSubject
               : ' WITHOUT a client certificate ' +
                 '(xacml.pepRequireCertificate is off)') + '.');
    log.debug('Leaving PepRegistry.register(). ' +
              (existing ? 'Updated.' : 'Created.'));
    return { ok: true, name: name, created: !existing };
  }

  // -------------------------------------------------------------------------
  // A HEARTBEAT.
  //
  // **THE COUNTERS ARE SET, NOT ADDED TO**, and that is the opposite of what a
  // counter usually wants. A remote PEP reports its own CUMULATIVE totals, so
  // adding them here would count every decision once per heartbeat — which
  // produces a number that only ever goes up, looks entirely plausible, and
  // is wrong by a factor of however often the PEP checks in. A PEP that
  // restarts and resets its own counters therefore makes this row go DOWN,
  // which is honest: what is shown is what that process has done since it
  // started, which is the only thing it can truthfully report.
  // -------------------------------------------------------------------------
  /**
   * Records a PEP's heartbeat: last seen, its sync token and its cumulative
   * counters, which are set rather than added to. The entry is written only
   * when something durable changed; otherwise the heartbeat's record is
   * held and journalled in the minted liveness store (#1882).
   * @param name - the PEP's entry name
   * @param report - what the PEP reports; an absent member keeps the value
   * @returns `{ ok: true, name, current }` with the current sync token, or
   * `{ ok: false, why }` when there is no directory, no such PEP or the
   * directory refuses the entry
   */
  heartbeat(name: string, report?: any): PepResult {
    const { log, errorCodes, liveness, latest } = this.deps;
    log.debug('Entering PepRegistry.heartbeat(). name=' + name);
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.heartbeat(). No directory.');
      // error-code: none — the code is the mark()'s, after the reason.
      return errorCodes.mark({ ok: false, status: 503,
                               why: 'There is no embedded directory.' },
                             'STS-XACML-0026');
    }
    // THE ENTRY AS STORED, AND THE ROW AS READ (#1882): an absent member
    // keeps the value a reader sees, the newest; whether to write the entry
    // is decided against what the entry holds.
    const entry = this.readEntry(name);
    const existing = entry
      ? this.withLiveness(entry, Date.now(), this.staleAfterS() * 1000)
      : null;
    if (!entry || !existing) {
      log.debug('Leaving PepRegistry.heartbeat(). Not registered.');
      // error-code: none — the code is the mark()'s, after the reason.
      return errorCodes.mark({ ok: false, status: 404,
               why: 'No Policy Enforcement Point is registered as "' + name +
                    '". Register first — POST /xacml/pep/register. A ' +
                    'heartbeat does not create a row, deliberately: a row ' +
                    'created by a heartbeat would carry no certificate, no ' +
                    'notify URL and no registration date, and would be a ' +
                    'PEP nobody could nudge.' }, 'STS-XACML-0021');
    }
    const said = report || {};
    // A VALUE THE SERVICE CANNOT HOLD (fuzz run #595) refuses the heartbeat
    // before anything is read or written: `reportProblem()`'s header.
    const problem = PepRegistry.reportProblem(said);
    if (problem) {
      log.debug('Leaving PepRegistry.heartbeat(). A value it cannot hold.');
      // error-code: none — the code is the mark()'s, after the reason.
      return errorCodes.mark({ ok: false, status: 400,
               why: 'This heartbeat carries a value the service cannot ' +
                    'hold, and nothing of it was recorded: ' + problem +
                    ' A counter is a non-negative integer of at most ' +
                    '2^53 - 1, a text member a string with no control ' +
                    'character, and signals, settings and listeners an ' +
                    'object or null.' },
             'STS-XACML-0331');
    }
    // THE HOSTNAME (#1760): absent keeps, as every member here does; a bad
    // one refuses the heartbeat before anything is written.
    const host = said.hostname === undefined
      ? { ok: true, hostname: existing.hostname }
      : PepRegistry.hostnameOf(said.hostname);
    if (!host.ok) {
      log.debug('Leaving PepRegistry.heartbeat(). A bad hostname.');
      return host as PepResult;
    }
    // `lastSeen` NEVER GOES BACK OR STANDS STILL across a heartbeat: one in
    // the same millisecond as the last is stamped a millisecond after it,
    // so it is the newest record and a tie never hides it (#1882).
    const floor = PepRegistry.instant(existing.lastSeen);
    const clock = Date.now();
    const now = new Date(clock > floor ? clock : floor + 1).toISOString();
    // THE SIGNAL HEALTH (#1760): an absent member keeps the last snapshot,
    // as every member here does (the pull's own `heartbeat(name, {})` sends
    // none), null clears it (a PEP whose proxy is off), and an object
    // replaces it, normalised and stamped with when it arrived.
    const signals = said.signals === undefined ? existing.signals
      : PepRegistry.signalsOf(said.signals, now);
    // THE SETTINGS IN FORCE AT THE PEP (#1760), the signal health's rule:
    // absent keeps, null clears, an object replaces, held to its members.
    const inUse = said.settings === undefined ? existing.settingsInUse
      : pepSettings.inUseOf(said.settings, now);
    // EVERY LISTENER THE PEP HAS AND WHAT IT IS DOING (#1760), the same
    // rule again: held to the closed sets, stamped on arrival.
    const listening = said.listeners === undefined ? existing.listenersInUse
      : pepListeners.inUseOf(said.listeners, now);
    const attributes = this.attributesOf(
      Object.assign({}, existing, { signals: signals,
                                    settingsInUse: inUse,
                                    listenersInUse: listening,
                                    hostname: host.hostname || '' }), {
      xacmlPepLastSeen: now,
      xacmlPepNotifyUrl: said.notifyUrl === undefined
        ? existing.notifyUrl : String(said.notifyUrl || ''),
      xacmlPepBias: said.bias === undefined
        ? existing.bias : String(said.bias || ''),
      xacmlPepResource: said.resource === undefined
        ? existing.resource : String(said.resource || ''),
      xacmlPepVersion: said.version === undefined
        ? existing.version : String(said.version || ''),
      xacmlPepSyncToken: said.syncToken === undefined
        ? existing.syncToken : String(said.syncToken || ''),
      xacmlPepPolicyCount: String(said.policyCount === undefined
        ? existing.policyCount : this.number(said.policyCount)),
      xacmlPepDecisions: String(said.decisions === undefined
        ? existing.decisions : this.number(said.decisions)),
      xacmlPepAllowed: String(said.allowed === undefined
        ? existing.allowed : this.number(said.allowed)),
      xacmlPepRefused: String(said.refused === undefined
        ? existing.refused : this.number(said.refused)),
      xacmlPepUndischargeable: String(said.undischargeable === undefined
        ? existing.undischargeable : this.number(said.undischargeable))
    });
    // AN EMBEDDED PEP'S IDENTITY AND ITS STREAM'S REPORT (#2026): an absent
    // member keeps the row's, as every member here does (the pull's own
    // `heartbeat(name, {})` sends none). The handler has already refused
    // what `identityOf()` refuses.
    PepRegistry.identityAttributes(attributes as Record<string, unknown>, {
      kind: said.kind === undefined ? existing.kind : said.kind,
      application: said.application === undefined
        ? existing.registeredApplication : said.application,
      mode: said.mode === undefined ? existing.mode : said.mode,
      protocolVersion: said.protocolVersion === undefined
        ? existing.protocolVersion : said.protocolVersion,
      policyEvents: said.policyEvents === undefined
        ? existing.policyEvents : said.policyEvents
    });
    // WHAT IT PULLS (#2027), from the pull's own heartbeat; absent keeps.
    const scope = said.pullScope === undefined ? existing.pullScope
      : String(said.pullScope || '');
    if (scope) {
      (attributes as Record<string, unknown>).xacmlPepPullScope = scope;
    } else {
      delete (attributes as Record<string, unknown>).xacmlPepPullScope;
    }
    // What it pulls decides the token it is told is current (#2027).
    const attrs = attributes as Record<string, unknown>;
    // NOTHING DURABLE CHANGED (#1882): no entry write, no audit row, no
    // directory change-log row. The record is held here and journalled
    // when `journalNow()` says so.
    if (this.durableOf(attributes as Record<string, unknown>) ===
        this.durableOf(this.attributesOf(entry) as Record<string, unknown>)) {
      const record: LivenessRow = {
        registeredAt: entry.registeredAt,
        seenAt: now,
        decisions: this.number((attributes as any).xacmlPepDecisions),
        allowed: this.number((attributes as any).xacmlPepAllowed),
        refused: this.number((attributes as any).xacmlPepRefused),
        undischargeable:
          this.number((attributes as any).xacmlPepUndischargeable),
        signals: signals,
        settingsInUse: inUse,
        listenersInUse: listening,
        lastNotify: existing.lastNotify
      };
      latest.set(name, record);
      const journalled = this.journalNow(entry, record);
      if (journalled) {
        liveness.set(name, record);
      }
      log.debug('Leaving PepRegistry.heartbeat(). Nothing durable changed; ' +
                (journalled ? 'journalled.' : 'held.'));
      return { ok: true, name: name, current: this.expectedToken(
        String(attrs.xacmlPepKind || ''), String(attrs.xacmlPepMode || ''),
        String(attrs.xacmlPepApplication || ''), {}) };
    }
    const written = directory.writePep(name, attributes);
    log.debug('Leaving PepRegistry.heartbeat(). ' +
              (written ? 'Recorded.' : 'Refused.'));
    if (written) {
      // The entry is the newest record now, as after a registration.
      latest.delete(name);
      return { ok: true, name: name, current: this.expectedToken(
        String(attrs.xacmlPepKind || ''), String(attrs.xacmlPepMode || ''),
        String(attrs.xacmlPepApplication || ''), {}) };
    }
    return errorCodes.mark({ ok: false, status: 507, why: 'The directory ' +
                             'refused the entry.' }, 'STS-XACML-0027');
  }

  // -------------------------------------------------------------------------
  // WHAT IN A SIGNAL-HEALTH SNAPSHOT IS AN EVENT (#1882), as one string:
  // every count and flag, without `at`, `oldestSuccessAgeMs` and each
  // stream's times and poll counts, which move on every heartbeat of a
  // PEP whose receivers are polling and say only that they are.
  // -------------------------------------------------------------------------
  private static signalEvents(signals: PepSignals | null): string {
    helpers.log.debug("Entering PepRegistry.signalEvents().");
    if (!signals || typeof signals !== 'object') {
      helpers.log.debug("Leaving PepRegistry.signalEvents(). None.");
      return '';
    }
    const kept: any = Object.assign({}, signals);
    delete kept.at;
    delete kept.oldestSuccessAgeMs;
    if (Array.isArray(kept.streams)) {
      kept.streams = kept.streams.map(function (one: any) {
        const copy = Object.assign({}, one);
        delete copy.startedAt;
        delete copy.lastPollAt;
        delete copy.lastSuccessAt;
        delete copy.polls;
        return copy;
      });
    }
    helpers.log.debug("Leaving PepRegistry.signalEvents().");
    return JSON.stringify(kept);
  }

  // -------------------------------------------------------------------------
  // WHETHER A HEARTBEAT THAT CHANGED NOTHING DURABLE IS JOURNALLED (#1882).
  //
  // AT ONCE WHEN THE COUNTERS MOVED, because they are what the PEP did and
  // another node's page should not show a number a minute old; they move
  // only on the PEP's own heartbeat, so a busy PEP costs one minted row a
  // heartbeat interval (a minute by default) and never a directory write.
  // AND AT ONCE WHEN THE SIGNAL HEALTH'S EVENTS MOVED (`signalEvents()`): a
  // set accepted or refused, a session ended, a receiver gone unhealthy or
  // failing. Those are what the PEP's proxy DID, the counters' argument;
  // until this was said, a heartbeat carrying them was held in the one
  // process that received it, and in a dispatched service the page and
  // `/admin-api/xacml/peps` are answered by another, which drew the last
  // journalled snapshot for up to a minute — `sts_xacml_remote_pep` waited
  // 40 s for `setsAccepted` and gave up (run #478). The ages and poll
  // counts in it move on every heartbeat and wait for the interval.
  // OTHERWISE ONCE AN INTERVAL (`journalIntervalMs()`), measured from the
  // newer of the entry's `lastSeen` and the journalled record's, which every
  // process reads, so the request workers of one node and the nodes of a
  // cluster share the one interval rather than each journalling its own.
  // -------------------------------------------------------------------------
  private journalNow(entry: PepRow, record: LivenessRow): boolean {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.journalNow(). name=' + entry.name);
    const stored = this.storedFor(entry);
    const storedAt = stored ? PepRegistry.instant(stored.seenAt) : -Infinity;
    const entryAt = PepRegistry.instant(entry.lastSeen);
    const held: { decisions: number; allowed: number; refused: number;
                  undischargeable: number; signals: PepSignals | null } =
      stored && storedAt > entryAt ? stored : entry;
    if (held.decisions !== record.decisions ||
        held.allowed !== record.allowed ||
        held.refused !== record.refused ||
        held.undischargeable !== record.undischargeable) {
      log.debug('Leaving PepRegistry.journalNow(). The counters moved.');
      return true;
    }
    if (PepRegistry.signalEvents(held.signals) !==
        PepRegistry.signalEvents(record.signals)) {
      log.debug('Leaving PepRegistry.journalNow(). The signal health moved.');
      return true;
    }
    const due = PepRegistry.instant(record.seenAt) -
      Math.max(storedAt, entryAt) >= this.journalIntervalMs();
    log.debug('Leaving PepRegistry.journalNow(). ' +
              (due ? 'Due.' : 'Not due.'));
    return due;
  }

  // -------------------------------------------------------------------------
  // THE PART OF AN ENTRY A HEARTBEAT HAS TO WRITE (#1882), as one string.
  //
  // Every attribute but `VOLATILE_ATTRIBUTES`, and of the two in-use reports
  // only what they say rather than when they said it: the settings in force
  // without their arrival stamp, and each listener's state, reason, address,
  // port, renewal and certificate without its pool and connection figures,
  // and without the process's memory and per-path counts. Those figures move
  // on every heartbeat of a PEP serving traffic, and a listener that stops
  // listening or is given a new certificate does not.
  //
  // **EXCEPT THE POOL'S BOUNDS, `stats.pool.min` AND `max`, WHICH ARE
  // DURABLE.** They are not a figure of the traffic but the listener's
  // `threadPoolMin` and `threadPoolMax` IN FORCE, and they move only when a
  // saved tuning is applied — the same fact as the settings in force. Until
  // this was said they were held in the receiving process with the rest of
  // the pool for up to a journal interval (a minute at the defaults), so in a
  // cluster the node answering `/admin-api/xacml/peps` drew the old bounds:
  // the PEP reports a pulled settings token on the heartbeat that can come
  // before its listeners are re-tuned, that heartbeat wrote the entry with
  // the old pool, the next one carried the new bounds as volatile, and
  // `sts_xacml_pep_proxy_cluster` gave up on `api-http.threadPoolMax` after
  // 60 s, a second before the record was due (run #500, cluster).
  // -------------------------------------------------------------------------
  private durableOf(attributes: Record<string, unknown>): string {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.durableOf().');
    const kept: Record<string, unknown> = {};
    Object.keys(attributes).sort().forEach(function (key) {
      if (VOLATILE_ATTRIBUTES.indexOf(key) < 0) {
        kept[key] = attributes[key];
      }
    });
    const settings = pepSettings.inUseOf(
      String(attributes.xacmlPepSettingsInUse || ''));
    if (settings) {
      kept.xacmlPepSettingsInUse = { token: settings.token,
                                     values: settings.values };
    }
    const listeners: any = pepListeners.inUseOf(
      String(attributes.xacmlPepListenersInUse || ''));
    if (listeners) {
      kept.xacmlPepListenersInUse = (listeners.listeners || [])
        .map(function (one: any) {
          const copy = Object.assign({}, one);
          const pool = (one.stats || {}).pool;
          delete copy.stats;
          if (pool) {
            copy.poolBounds = { min: pool.min, max: pool.max };
          }
          return copy;
        });
    }
    log.debug('Leaving PepRegistry.durableOf().');
    return JSON.stringify(kept);
  }

  // What happened to the last nudge, written back onto the row. Separate from
  // `heartbeat()` because it is this service talking about itself rather than
  // the PEP reporting — and because it must not move `lastSeen`: a nudge that
  // failed is evidence that the PEP is NOT reachable, and letting it stamp
  // the liveness field would make an unreachable PEP look freshly seen.
  /**
   * Writes what happened to the last nudge onto a PEP's row, without moving
   * its last-seen time.
   * @param name - the PEP's entry name
   * @param sentence - the nudge's outcome, stamped with the time
   * @returns true when written
   */
  recordNotify(name: string, sentence: unknown): boolean {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.recordNotify(). name=' + name);
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.recordNotify(). No directory.');
      return false;
    }
    const entry = this.readEntry(name);
    if (!entry) {
      log.debug('Leaving PepRegistry.recordNotify(). Not registered.');
      return false;
    }
    // INTO THE HEARTBEAT'S RECORD, NOT THE ENTRY (#1882): a nudge goes to
    // every PEP on every policy change, and its outcome is what this service
    // did rather than anything durable about the PEP. A record that holds
    // only this has no `seenAt`, so it moves no `lastSeen` — the rule above.
    const stored = this.storedFor(entry);
    const base: LivenessRow = stored || {
      registeredAt: entry.registeredAt, seenAt: '', decisions: 0,
      allowed: 0, refused: 0, undischargeable: 0, signals: null,
      settingsInUse: null, listenersInUse: null, lastNotify: ''
    };
    this.deps.liveness.set(name, Object.assign({}, base, {
      lastNotify: new Date().toISOString() + ' — ' + String(sentence)
    }));
    log.debug('Leaving PepRegistry.recordNotify(). Recorded.');
    return true;
  }

  /**
   * Enables or disables a registered PEP.
   * @param name - the PEP's entry name
   * @param on - true to enable, false to disable
   * @returns true when written
   */
  setEnabled(name: string, on: unknown): boolean {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.setEnabled(). name=' + name + ' on=' + on);
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.setEnabled(). No directory.');
      return false;
    }
    const existing = this.read(name);
    if (!existing) {
      log.debug('Leaving PepRegistry.setEnabled(). Not registered.');
      return false;
    }
    const written = directory.writePep(name, this.attributesOf(existing, {
      xacmlPepEnabled: on ? 'TRUE' : 'FALSE'
    }));
    log.debug('Leaving PepRegistry.setEnabled(). ' +
              (written ? 'Written.' : 'Refused.'));
    return written;
  }

  // -------------------------------------------------------------------------
  // THE REVERSE-PROXY CONFIGURATION (#1760). The text is written as given:
  // `xacml_pep_proxy.ts` validates it before this is called, and again when
  // the pull is built, because `ldapmodify` reaches this attribute too.
  // -------------------------------------------------------------------------
  /**
   * Sets or clears a registered PEP's reverse-proxy configuration.
   * @param name - the PEP's entry name
   * @param text - the validated JSON document, or null to remove it
   * @returns true when written
   */
  setProxy(name: string, text: string | null): boolean {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.setProxy(). name=' + name);
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.setProxy(). No directory.');
      return false;
    }
    const existing = this.read(name);
    if (!existing) {
      log.debug('Leaving PepRegistry.setProxy(). Not registered.');
      return false;
    }
    const attributes: Record<string, unknown> =
      this.attributesOf(Object.assign({}, existing, { proxy: '' })) as
        Record<string, unknown>;
    if (text) {
      attributes.xacmlPepProxy = text;
    }
    const written = directory.writePep(name, attributes);
    log.debug('Leaving PepRegistry.setProxy(). ' +
              (written ? 'Written.' : 'Refused.'));
    return written;
  }

  /**
   * Sets or clears a registered PEP's managed settings (#1760).
   * @param name - the PEP's entry name
   * @param text - the validated JSON document, or null to remove it
   * @returns true when written
   */
  setSettings(name: string, text: string | null): boolean {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.setSettings(). name=' + name);
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.setSettings(). No directory.');
      return false;
    }
    const existing = this.read(name);
    if (!existing) {
      log.debug('Leaving PepRegistry.setSettings(). Not registered.');
      return false;
    }
    const attributes: Record<string, unknown> =
      this.attributesOf(Object.assign({}, existing, { settings: '' })) as
        Record<string, unknown>;
    if (text) {
      attributes.xacmlPepSettings = text;
    }
    const written = directory.writePep(name, attributes);
    log.debug('Leaving PepRegistry.setSettings(). ' +
              (written ? 'Written.' : 'Refused.'));
    return written;
  }

  /**
   * Sets or clears a registered PEP's defined listeners (#1760).
   * @param name - the PEP's entry name
   * @param text - the validated JSON array, or null to remove them
   * @returns true when written
   */
  setListeners(name: string, text: string | null): boolean {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.setListeners(). name=' + name);
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.setListeners(). No directory.');
      return false;
    }
    const existing = this.read(name);
    if (!existing) {
      log.debug('Leaving PepRegistry.setListeners(). Not registered.');
      return false;
    }
    const attributes: Record<string, unknown> =
      this.attributesOf(Object.assign({}, existing, { listeners: '' })) as
        Record<string, unknown>;
    if (text) {
      attributes.xacmlPepListeners = text;
    }
    const written = directory.writePep(name, attributes);
    log.debug('Leaving PepRegistry.setListeners(). ' +
              (written ? 'Written.' : 'Refused.'));
    return written;
  }

  // -------------------------------------------------------------------------
  // THE WHOLE ENTRY AS ATTRIBUTES, with an override or two applied.
  //
  // `writePep()` REPLACES rather than merges — `writePolicy()`'s decision,
  // for `writeFederation()`'s reason — so every caller that changes ONE field
  // has to hand back all of them. Doing that in one place is what stops the
  // next caller silently dropping a counter, which is a failure that would
  // look like a PEP that had stopped enforcing.
  // -------------------------------------------------------------------------
  private attributesOf(row: PepRow,
                       overrides?: Record<string, unknown>): object {
    const { log } = this.deps;
    log.debug("Entering PepRegistry.attributesOf().");
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'xacmlPep'],
      xacmlPepIdentity: row.identity,
      xacmlPepCertificateSubject: row.certificateSubject,
      xacmlPepThumbprint: row.thumbprint,
      xacmlPepAuthenticated: row.authenticated ? 'TRUE' : 'FALSE',
      xacmlPepNotifyUrl: row.notifyUrl,
      xacmlPepBias: row.bias,
      xacmlPepResource: row.resource,
      xacmlPepVersion: row.version,
      xacmlPepEnabled: row.enabled ? 'TRUE' : 'FALSE',
      xacmlPepRegisteredAt: row.registeredAt,
      xacmlPepLastSeen: row.lastSeen,
      xacmlPepSyncToken: row.syncToken,
      xacmlPepPolicyCount: String(row.policyCount),
      xacmlPepDecisions: String(row.decisions),
      xacmlPepAllowed: String(row.allowed),
      xacmlPepRefused: String(row.refused),
      xacmlPepUndischargeable: String(row.undischargeable),
      xacmlPepLastNotify: row.lastNotify
    };
    if (row.description) {
      attributes.description = row.description;
    }
    // Only when reported (#1760), so an older PEP's entry is written as it
    // always was.
    if (row.hostname) {
      attributes.xacmlPepHostname = row.hostname;
    }
    // Only when set, so an entry that never had one is written exactly as it
    // always was (#1760); `setProxy(name, null)` passes it as an override.
    if (row.proxy) {
      attributes.xacmlPepProxy = row.proxy;
    }
    // Only when reported, for the same reason (#1760).
    if (row.signals) {
      attributes.xacmlPepSignals = JSON.stringify(row.signals);
    }
    // Only when set, and only when reported (#1760).
    if (row.settings) {
      attributes.xacmlPepSettings = row.settings;
    }
    if (row.settingsInUse) {
      attributes.xacmlPepSettingsInUse = JSON.stringify(row.settingsInUse);
    }
    // Only when defined, and only when reported (#1760).
    if (row.listeners) {
      attributes.xacmlPepListeners = row.listeners;
    }
    if (row.listenersInUse) {
      attributes.xacmlPepListenersInUse =
        JSON.stringify(row.listenersInUse);
    }
    // What it pulls (#2027), only once it has pulled.
    if (row.pullScope) {
      attributes.xacmlPepPullScope = row.pullScope;
    }
    // An embedded PEP's identity (#2026), only when there is one.
    PepRegistry.identityAttributes(attributes, {
      kind: row.kind, application: row.registeredApplication,
      mode: row.mode, protocolVersion: row.protocolVersion,
      policyEvents: row.policyEvents
    });
    log.debug("Leaving PepRegistry.attributesOf().");
    return Object.assign(attributes, overrides || {});
  }

  /**
   * Deletes a PEP's registration.
   * @param name - the PEP's entry name
   * @returns true when an entry was removed
   */
  remove(name: string): boolean {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.remove(). name=' + name);
    if (!this.haveDirectory()) {
      log.debug('Leaving PepRegistry.remove(). No directory.');
      return false;
    }
    const removed = directory.deletePep(name);
    // And the heartbeat's record (#1882): a registration made again under
    // the name is a new one, and an older record is never read for it.
    this.deps.liveness.delete(name);
    this.deps.latest.delete(name);
    log.debug('Leaving PepRegistry.remove(). ' +
              (removed ? 'Removed.' : 'Not there.'));
    return removed;
  }

  // Every registered PEP that should be nudged: enabled, and holding a URL to
  // nudge. NOT filtered on `stale`, deliberately — a PEP that has not been
  // seen for an hour is exactly the one a nudge might wake up, and refusing
  // to try would turn a latency problem into a permanent one.
  /**
   * Lists the PEPs a nudge should go to: enabled and holding a notify URL,
   * stale or not.
   * @returns the rows
   */
  notifiable(): PepRow[] {
    const { log } = this.deps;
    log.debug('Entering PepRegistry.notifiable().');
    // THE URL AN ADMINISTRATOR SET WINS (#1760): the row is answered with
    // it, so the nudge dials the managed address and the PEP's registered
    // one only where none is set.
    // A MEMBER OF A CLUSTER IS NUDGED AT ITS OWN ADDRESS (#1760, Remote
    // PEP clusters): its effective row carries the notify URL set on its
    // membership. Required lazily: the clusters module reads this one.
    const clusters = require('./xacml_pep_clusters');
    const rows = this.all().map(function (row) {
      const effective = clusters.effectiveRow(row) || row;
      return Object.assign({}, row,
                           { notifyUrl: pepSettings.notifyUrlOf(effective) });
    }).filter(function (row) {
      return row.enabled && row.notifyUrl;
    });
    log.debug('Leaving PepRegistry.notifiable(). ' + rows.length +
              ' PEP(s).');
    return rows;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PepRegistry>(
  'xacml/xacml_pep_registry',
  () => new PepRegistry(PepRegistry.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The register of remote XACML Policy Enforcement Points, `ou=peps` in the
 * realm's directory.
 *
 * The functions forward to the instance the composition root installs.
 * @namespace
 */
export = {
  PepRegistry: PepRegistry,
  installInstance: (instance: PepRegistry): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SCHEMA: PepRegistry.SCHEMA,
  // #543 phase 2b: the routes whose answers carry this module's prose, and
  // the prose by key.
  PROSE_ROUTES: PepRegistry.PROSE_ROUTES,
  prose: PepRegistry.prose,
  setDirectory: PepRegistry.setDirectory,
  directoryInstalled: PepRegistry.directoryInstalled,
  certificateIdentity: slot.forward('certificateIdentity'),
  syncToken: slot.forward('syncToken'),
  staleAfterS: slot.forward('staleAfterS'),
  // How long a heartbeat that moved only `lastSeen` is held before it is
  // journalled (#1882), and how two processes' records of one PEP merge.
  journalIntervalMs: slot.forward('journalIntervalMs'),
  mergeLiveness: PepRegistry.mergeLiveness,
  nameFrom: slot.forward('nameFrom'),
  all: slot.forward('all'),
  // Which OTHER realms hold a registration. See its header: an empty list in
  // one realm is two different facts and this is what tells them apart.
  elsewhere: slot.forward('elsewhere'),
  read: slot.forward('read'),
  register: slot.forward('register'),
  heartbeat: slot.forward('heartbeat'),
  signalsOf: PepRegistry.signalsOf,
  hostnameOf: PepRegistry.hostnameOf,
  reportProblem: PepRegistry.reportProblem,
  // An embedded PEP's identity (#2026): the one reading of kind,
  // application, mode, protocol version and the stream's report.
  identityOf: PepRegistry.identityOf,
  // The pull scoped to a bound application (#2027).
  boundPull: slot.forward('boundPull'),
  PROTOCOL_VERSIONS: PROTOCOL_VERSIONS,
  recordNotify: slot.forward('recordNotify'),
  setEnabled: slot.forward('setEnabled'),
  setProxy: slot.forward('setProxy'),
  setSettings: slot.forward('setSettings'),
  setListeners: slot.forward('setListeners'),
  remove: slot.forward('remove'),
  notifiable: slot.forward('notifiable')
};
