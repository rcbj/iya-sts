// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// @ts-check
'use strict';

// ===========================================================================
// REMOTE PEP CLUSTERS (#1760, phase 1).
//
// rcbj: "a concept of a logical cluster of Remote PEPs that share a common
// configuration. You can configure one Remote PEP, then apply it to
// additional PEPs. The only thing that should differ between the Remote
// PEPs is its identifier and listening address."
//
// THE WHOLE FEATURE IS ON THIS SIDE. A PEP pulls its proxy, its settings and
// its listeners as documents this service builds from ONE stored row
// (`GET /xacml/pep/proxy`, `GET /xacml/pep/settings`), so a cluster is the
// row it is answered from: `effectiveRow()` merges the cluster's documents
// with the member's own addresses, and every door that reads a PEP's
// configuration reads that. The PEP is unchanged, and so is a PEP in no
// cluster: its effective row IS its row, the same object.
//
// ONE ENTRY PER CLUSTER under the realm's `ou=pepClusters`, object class
// `xacmlPepCluster` (`models/directory/xacml_pep_cluster.tsp`), its three
// documents in the PEP's own grammars and the members on the entry. A
// member's name may be listed before that PEP registers; a PEP is a member
// of at most one cluster. `ldap/ldap_server.js` fills the directory slot.
//
// WHAT IS SHARED AND WHAT IS A MEMBER'S. Shared: the routes and everything
// in them, the upstream, the timeouts, the body bound, `enabled`, the
// managed settings and the listener definitions. A member's: its name,
// its `publicBaseUrl`, its `notifyUrl`, and per listener its address, port
// and extra certificate names. The generated route policies are the
// cluster's, one per route, `pepc-<cluster>-<route>` marked
// `@<cluster>/<route>`, so every member is sent the same policy and the
// route names it.
//
// A LIBRARY: it registers nothing. `xacml_admin.ts` answers the actions,
// `xacml.ts` the pulls.
// ===========================================================================

import ModelTables = require('../common/model_tables');
import DomainClasses = require('../common/domain_classes');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import peps = require('./xacml_pep_registry');
import pepProxy = require('./xacml_pep_proxy');
import pepSettings = require('./xacml_pep_settings');
import pepListeners = require('./xacml_pep_listeners');

// What `ldap/ldap_server.js` hands over: the container and nothing else.
interface ClusterDirectory {
  allPepClusters(): Array<{ name: string; dn: string; attributes: object }>;
  writePepCluster(name: string, attributes: object): boolean;
  deletePepCluster(name: string): boolean;
}

// One listener's addresses on one member.
interface ListenerOverride {
  address?: string;
  port?: number;
  names?: string[];
}

// One member, normalised.
interface Member {
  pep: string;
  publicBaseUrl: string;
  notifyUrl: string;
  listeners: Record<string, ListenerOverride>;
}

// One cluster, as the module answers it.
interface ClusterRow {
  name: string;
  dn: string;
  description: string;
  proxy: string;
  settings: string;
  listeners: string;
  members: Member[];
  membersProblem: string | null;
}

interface Refusal {
  ok: false;
  why: string;
  code: string;
}

interface ClustersDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  config: { value(key: string): any };
  errorCodes: {
    mark<T>(result: T, code: string): T;
    tag(code: string): string;
  };
  peps: {
    read(name: string): any;
    all(): any[];
    nameFrom(raw: unknown): string;
  };
  pepProxy: any;
  pepSettings: any;
  pepListeners: any;
}

/**
 * The `ou=pepClusters` schema, the object class and attributes a cluster
 * entry carries.
 */
const SCHEMA = ModelTables.schema('xacmlPepCluster');

// A cluster's name: an entry name, the PEP's own rule.
const NAME = /^[A-Za-z0-9._-]{1,64}$/;
// A listener id, `xacml_pep_listeners.ts`'s rule.
const LISTENER_ID = /^[A-Za-z0-9._-]{1,64}$/;
// What a member carries, and what one listener's override carries.
const MEMBER_MEMBERS = ['pep', 'publicBaseUrl', 'notifyUrl', 'listeners'];
const OVERRIDE_MEMBERS = ['address', 'port', 'names'];
// At most this many members: the register's own bound is `xacml.maxPeps`,
// and no cluster can have more members than a realm has PEPs.
const MAX_MEMBERS = 256;
const MAX_NAMES = 16;

let directory: ClusterDirectory | null = null;

/**
 * The register of remote PEP clusters, entries under the realm's
 * `ou=pepClusters`, and the merge that answers a member's pulls.
 */
class PepClusters {
  /**
   * The `ou=pepClusters` schema.
   */
  static readonly SCHEMA = SCHEMA;

  /**
   * The `/admin-api` route whose answer carries this module's prose (#543
   * phase 2b): the clusters' own answer, which publishes SCHEMA.
   */
  static readonly PROSE_ROUTES: readonly string[] =
    Object.freeze(['/admin-api/xacml/pep-clusters']);

  /**
   * What a member carries.
   */
  static readonly MEMBER_MEMBERS = MEMBER_MEMBERS;

  /**
   * Extracts this module's console prose (#543 phase 2b): the object
   * class's and each attribute's `what` in SCHEMA.
   *
   * @returns key → English
   */
  static prose(): Record<string, string> {
    helpers.log.debug("Entering PepClusters.prose().");
    const serverProse: typeof import('../common/server_prose') =
      require('../common/server_prose');
    const out = serverProse.harvest('xacmlPepClusters.schema', SCHEMA,
                                    ['what']);
    helpers.log.debug("Leaving PepClusters.prose(). " +
                      Object.keys(out).length);
    return out;
  }

  /**
   * Builds the register over its dependencies.
   * @param deps - the logger, settings, codes and the PEP modules
   */
  constructor(private readonly deps: ClustersDeps) {
    deps.log.debug("Entering PepClusters.constructor().");
    deps.log.debug("Leaving PepClusters.constructor().");
  }

  /**
   * The dependencies from the real modules.
   * @returns the dependencies
   */
  static defaultDeps(): ClustersDeps {
    helpers.log.debug("Entering PepClusters.defaultDeps().");
    helpers.log.debug("Leaving PepClusters.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      peps: peps as any,
      pepProxy: pepProxy,
      pepSettings: pepSettings,
      pepListeners: pepListeners
    };
  }

  /**
   * Installs the directory functions; filled by `ldap/ldap_server.js`.
   * @param fns - the directory functions, or null to remove them
   */
  static setDirectory(fns?: ClusterDirectory | null): void {
    helpers.log.debug("Entering PepClusters.setDirectory().");
    directory = fns || null;
    helpers.log.debug("Leaving PepClusters.setDirectory(). " +
                      (directory ? 'Installed.' : 'None.'));
  }

  /**
   * The directory functions installed, for a test to put back.
   * @returns them, or null
   */
  static directoryInstalled(): ClusterDirectory | null {
    helpers.log.debug("Entering PepClusters.directoryInstalled().");
    helpers.log.debug("Leaving PepClusters.directoryInstalled().");
    return directory;
  }

  /**
   * Whether a cluster's name is one: 1 to 64 letters, digits, dots, dashes
   * or underscores, a PEP's own rule.
   * @param name - the name
   * @returns true when it is
   */
  static nameOk(name: unknown): boolean {
    helpers.log.debug("Entering PepClusters.nameOk().");
    const out = typeof name === 'string' && NAME.test(name);
    helpers.log.debug("Leaving PepClusters.nameOk(). " + out);
    return out;
  }

  /**
   * The owner a cluster's routes and generated policies are named for:
   * `@<cluster>`, which no PEP name can be.
   * @param name - the cluster's name
   * @returns the owner
   */
  static ownerOf(name: string): string {
    helpers.log.debug("Entering PepClusters.ownerOf().");
    helpers.log.debug("Leaving PepClusters.ownerOf().");
    return '@' + String(name);
  }

  private refuse(why: string, code: string): Refusal {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepClusters.refuse(). " + code);
    log.debug("Leaving PepClusters.refuse().");
    return errorCodes.mark({ ok: false, why: why, code: code }, code);
  }

  // =========================================================================
  // THE MEMBERS DOCUMENT.
  // =========================================================================
  /**
   * One member, normalised, or a refusal naming what is wrong. The
   * addresses' own grammar (a URL, a port) is asked again of the merged
   * documents, by the validators they belong to.
   * @param raw - the member
   * @param where - how a refusal names it
   * @returns the member, or a refusal (`STS-XACML-0277`)
   */
  memberOf(raw: unknown, where: string): Member | Refusal {
    const { log } = this.deps;
    log.debug("Entering PepClusters.memberOf(). " + where);
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving PepClusters.memberOf(). Not an object.");
      return this.refuse(where + ' is an object of ' +
                         MEMBER_MEMBERS.join(', ') + '.', 'STS-XACML-0277');
    }
    const node = raw as Record<string, unknown>;
    const stray = Object.keys(node).filter(function (key) {
      return MEMBER_MEMBERS.indexOf(key) < 0;
    })[0];
    if (stray) {
      log.debug("Leaving PepClusters.memberOf(). Stray member.");
      return this.refuse(where + ' carries "' + stray + '", which a ' +
                         'member does not have. A member has ' +
                         MEMBER_MEMBERS.join(', ') + '.', 'STS-XACML-0277');
    }
    const pep = typeof node.pep === 'string' ? node.pep : '';
    if (!NAME.test(pep.length > 128 ? '' : pep.replace(/^(.{64}).+$/, '$1')) ||
        pep.length > 128 || /[^A-Za-z0-9._-]/.test(pep) || !pep) {
      log.debug("Leaving PepClusters.memberOf(). PEP name.");
      return this.refuse(where + '\'s `pep` is a remote PEP\'s name: 1 to ' +
                         '128 letters, digits, dots, dashes or underscores.',
                         'STS-XACML-0277');
    }
    const text = function (value: unknown): string | null {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return value === undefined || value === null ? ''
        : (typeof value === 'string' && value.length <= 2048 &&
           !/[\u0000-\u001f\u007f\s]/.test(value) ? value : null);
    };
    const publicBaseUrl = text(node.publicBaseUrl);
    const notifyUrl = text(node.notifyUrl);
    if (publicBaseUrl === null || notifyUrl === null) {
      log.debug("Leaving PepClusters.memberOf(). Address text.");
      return this.refuse(where + ' ("' + pep + '"): `publicBaseUrl` and ' +
                         '`notifyUrl` are URLs of at most 2048 characters ' +
                         'with no space, or empty.', 'STS-XACML-0277');
    }
    const given = node.listeners === undefined || node.listeners === null
      ? {} : node.listeners;
    if (typeof given !== 'object' || Array.isArray(given)) {
      log.debug("Leaving PepClusters.memberOf(). Listeners shape.");
      return this.refuse(where + ' ("' + pep + '"): `listeners` is an ' +
                         'object of listener id → { address, port, names }.',
                         'STS-XACML-0277');
    }
    const listeners: Record<string, ListenerOverride> = {};
    const ids = Object.keys(given);
    for (let i = 0; i < ids.length; i++) {
      const id = ids[i];
      const one = (given as Record<string, unknown>)[id];
      const bad = !LISTENER_ID.test(id) || !one || typeof one !== 'object' ||
        Array.isArray(one) || Object.keys(one).some(function (key) {
          return OVERRIDE_MEMBERS.indexOf(key) < 0;
        });
      if (bad) {
        log.debug("Leaving PepClusters.memberOf(). Override shape.");
        return this.refuse(where + ' ("' + pep + '"): listener "' + id +
                           '" is overridden by an object of ' +
                           OVERRIDE_MEMBERS.join(', ') + ', its key a ' +
                           'listener id.', 'STS-XACML-0277');
      }
      const o = one as Record<string, unknown>;
      const out: ListenerOverride = {};
      if (o.address !== undefined && o.address !== '') {
        if (typeof o.address !== 'string' || o.address.length > 64) {
          log.debug("Leaving PepClusters.memberOf(). Address.");
          return this.refuse(where + ' ("' + pep + '"): listener "' + id +
                             '"\'s `address` is an IP address.',
                             'STS-XACML-0277');
        }
        out.address = o.address;
      }
      if (o.port !== undefined && o.port !== '') {
        const port = typeof o.port === 'string' && /^\d+$/.test(o.port)
          ? Number(o.port) : o.port;
        if (typeof port !== 'number' || !Number.isInteger(port) ||
            port < 1 || port > 65535) {
          log.debug("Leaving PepClusters.memberOf(). Port.");
          return this.refuse(where + ' ("' + pep + '"): listener "' + id +
                             '"\'s `port` is an integer from 1 to 65535.',
                             'STS-XACML-0277');
        }
        out.port = port;
      }
      if (o.names !== undefined) {
        const names = Array.isArray(o.names) ? o.names : [o.names];
        if (names.length > MAX_NAMES || names.some(function (n) {
          return typeof n !== 'string' || !n || n.length > 253;
        })) {
          log.debug("Leaving PepClusters.memberOf(). Names.");
          return this.refuse(where + ' ("' + pep + '"): listener "' + id +
                             '"\'s `names` are at most ' + MAX_NAMES +
                             ' DNS names.', 'STS-XACML-0277');
        }
        if (names.length) {
          out.names = (names as string[]).map(function (n) {
            return n.trim().toLowerCase();
          });
        }
      }
      if (Object.keys(out).length) {
        listeners[id] = out;
      }
    }
    log.debug("Leaving PepClusters.memberOf(). " + pep);
    return { pep: pep, publicBaseUrl: publicBaseUrl, notifyUrl: notifyUrl,
             listeners: listeners };
  }

  /**
   * Reads a members document: a JSON array of members, each normalised,
   * no PEP twice.
   * @param input - the array, or its JSON text
   * @returns `{ ok: true, members }` or a refusal
   */
  membersOf(input: unknown): { ok: true; members: Member[] } | Refusal {
    const { log } = this.deps;
    log.debug("Entering PepClusters.membersOf().");
    let list: unknown = input;
    if (typeof input === 'string') {
      try {
        list = input ? JSON.parse(input) : [];
      } catch (e) {
        log.debug("Caught in PepClusters.membersOf(): " +
                  ((e && e.message) || e));
        list = null;
      }
    }
    if (list === undefined || list === null) {
      list = input === '' ? [] : list;
    }
    if (!Array.isArray(list) || list.length > MAX_MEMBERS) {
      log.debug("Leaving PepClusters.membersOf(). Not a list.");
      return this.refuse('The members are a JSON array of at most ' +
                         MAX_MEMBERS + ' members.', 'STS-XACML-0277');
    }
    const out: Member[] = [];
    for (let i = 0; i < list.length; i++) {
      const one = this.memberOf(list[i], 'Member ' + (i + 1));
      if ((one as Refusal).ok === false) {
        log.debug("Leaving PepClusters.membersOf(). Refused.");
        return one as Refusal;
      }
      const member = one as Member;
      if (out.some(function (other) { return other.pep === member.pep; })) {
        log.debug("Leaving PepClusters.membersOf(). Twice.");
        return this.refuse('"' + member.pep + '" is listed twice; a PEP is ' +
                           'a member once.', 'STS-XACML-0271');
      }
      out.push(member);
    }
    log.debug("Leaving PepClusters.membersOf(). " + out.length);
    return { ok: true, members: out };
  }

  // =========================================================================
  // THE REGISTER.
  // =========================================================================
  /**
   * Every cluster of the current realm.
   * @returns the rows; empty with no directory
   */
  all(): ClusterRow[] {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepClusters.all().");
    if (!directory) {
      log.debug("Leaving PepClusters.all(). No directory.");
      return [];
    }
    const self = this;
    const rows = directory.allPepClusters().map(function (entry): ClusterRow {
      const c = DomainClasses.XacmlPepCluster.fromEntry(entry.attributes);
      const read = self.membersOf(c.members || '');
      if (!read.ok) {
        log.warn(errorCodes.tag('STS-XACML-0280') + 'xacml: the members ' +
                 'stored for remote PEP cluster "' + entry.name + '" do not ' +
                 'validate (' + (read as Refusal).why + '); the cluster is ' +
                 'read with none, so no PEP pulls its configuration.');
      }
      return {
        name: entry.name,
        dn: entry.dn,
        description: (c.description || [])[0] || '',
        proxy: c.proxy || '',
        settings: c.settings || '',
        listeners: c.listeners || '',
        members: read.ok ? read.members : [],
        membersProblem: read.ok ? null : (read as Refusal).why
      };
    });
    log.debug("Leaving PepClusters.all(). " + rows.length);
    return rows;
  }

  /**
   * One cluster by name.
   * @param name - the cluster's name
   * @returns the row, or null
   */
  read(name: string): ClusterRow | null {
    const { log } = this.deps;
    log.debug("Entering PepClusters.read(). " + name);
    const found = this.all().filter(function (row) {
      return row.name === name;
    })[0] || null;
    log.debug("Leaving PepClusters.read(). " + (found ? 'Found.' : 'None.'));
    return found;
  }

  /**
   * The cluster a PEP is a member of.
   * @param pep - the PEP's name
   * @returns the cluster's row, or null for a PEP in none
   */
  clusterOf(pep: string): ClusterRow | null {
    const { log } = this.deps;
    log.debug("Entering PepClusters.clusterOf(). " + pep);
    const found = this.all().filter(function (row) {
      return row.members.some(function (one) { return one.pep === pep; });
    })[0] || null;
    log.debug("Leaving PepClusters.clusterOf(). " +
              (found ? found.name : 'None.'));
    return found;
  }

  /**
   * Writes a cluster whole: its documents and its members.
   * @param row - the cluster, every member normalised
   * @returns true when written
   */
  write(row: { name: string; description?: string; proxy?: string;
               settings?: string; listeners?: string;
               members: Member[] }): boolean {
    const { log } = this.deps;
    log.debug("Entering PepClusters.write(). " + row.name);
    if (!directory) {
      log.debug("Leaving PepClusters.write(). No directory.");
      return false;
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'xacmlPepCluster'],
      xacmlPepClusterMembers: JSON.stringify(row.members.map(function (one) {
        const out: Record<string, unknown> = { pep: one.pep };
        if (one.publicBaseUrl) {
          out.publicBaseUrl = one.publicBaseUrl;
        }
        if (one.notifyUrl) {
          out.notifyUrl = one.notifyUrl;
        }
        if (Object.keys(one.listeners || {}).length) {
          out.listeners = one.listeners;
        }
        return out;
      }))
    };
    if (row.description) {
      attributes.description = String(row.description);
    }
    if (row.proxy) {
      attributes.xacmlPepClusterProxy = row.proxy;
    }
    if (row.settings) {
      attributes.xacmlPepClusterSettings = row.settings;
    }
    if (row.listeners) {
      attributes.xacmlPepClusterListeners = row.listeners;
    }
    const written = directory.writePepCluster(row.name, attributes);
    log.debug("Leaving PepClusters.write(). " + written);
    return written;
  }

  /**
   * Removes a cluster's entry.
   * @param name - the cluster's name
   * @returns true when removed
   */
  remove(name: string): boolean {
    const { log } = this.deps;
    log.debug("Entering PepClusters.remove(). " + name);
    const gone = !!directory && directory.deletePepCluster(name);
    log.debug("Leaving PepClusters.remove(). " + gone);
    return gone;
  }

  // =========================================================================
  // THE EFFECTIVE ROW: what a member pulls.
  // =========================================================================
  /**
   * The documents one member is sent: the cluster's, with the member's
   * own addresses. Each is text, as a stored attribute is, or '' for none.
   * @param cluster - the cluster's row
   * @param member - the member
   * @returns `{ proxy, settings, listeners }`
   */
  documentsFor(cluster: ClusterRow, member: Member):
      { proxy: string; settings: string; listeners: string } {
    const { log } = this.deps;
    log.debug("Entering PepClusters.documentsFor(). " + member.pep);
    const parse = function (text: string): any {
      log.debug("Entering parse().");
      let out: any = null;
      try {
        out = text ? JSON.parse(text) : null;
      } catch (e) {
        log.debug("Caught in parse(): " + ((e && e.message) || e));
        out = undefined;
      }
      log.debug("Leaving parse().");
      return out;
    };
    // THE PROXY: the cluster's document with the member's public base URL
    // (the cluster's logical one where the member has none). A document
    // that does not parse is handed on as it is, so the pull refuses it
    // by the grammar's own code rather than this module inventing one.
    let proxy = cluster.proxy;
    const doc = parse(cluster.proxy);
    if (doc && typeof doc === 'object' && !Array.isArray(doc)) {
      if (member.publicBaseUrl) {
        doc.publicBaseUrl = member.publicBaseUrl;
      }
      proxy = JSON.stringify(doc);
    }
    // THE SETTINGS: the cluster's, with the member's notify URL.
    let settings = cluster.settings;
    const set = parse(cluster.settings);
    if (member.notifyUrl && (set === null ||
        (set && typeof set === 'object' && !Array.isArray(set)))) {
      settings = JSON.stringify(Object.assign({}, set || {},
                                              { notifyUrl: member.notifyUrl }));
    }
    // THE LISTENERS: each definition with the member's address, port and
    // extra names over it.
    let listeners = cluster.listeners;
    const list = parse(cluster.listeners);
    if (Array.isArray(list)) {
      listeners = JSON.stringify(list.map(function (one: any) {
        const over = one && typeof one === 'object' && typeof one.id ===
          'string' ? member.listeners[one.id] : undefined;
        if (!over) {
          return one;
        }
        const out = Object.assign({}, one);
        if (over.address !== undefined) {
          out.address = over.address;
        }
        if (over.port !== undefined) {
          out.port = over.port;
        }
        if (over.names && over.names.length) {
          const held = Array.isArray(one.dnsNames) ? one.dnsNames : [];
          out.dnsNames = held.concat(over.names.filter(function (n) {
            return held.indexOf(n) < 0;
          }));
        }
        return out;
      }));
    }
    log.debug("Leaving PepClusters.documentsFor().");
    return { proxy: proxy, settings: settings, listeners: listeners };
  }

  /**
   * A register row as its PEP pulls it: a PEP in no cluster is its row,
   * THE SAME OBJECT; a member's is a copy whose proxy, settings and
   * listeners are the cluster's merged with its own addresses, and which
   * names the cluster (`cluster`), so the routes' generated policies are
   * the cluster's (`xacml_pep_proxy.ts`'s `ownerOf()`).
   * @param row - the PEP's register row, or null
   * @returns the effective row, or null
   */
  effectiveRow(row: any): any {
    const { log } = this.deps;
    log.debug("Entering PepClusters.effectiveRow().");
    if (!row || !directory) {
      log.debug("Leaving PepClusters.effectiveRow(). No row or directory.");
      return row;
    }
    const cluster = this.clusterOf(String(row.name));
    if (!cluster) {
      log.debug("Leaving PepClusters.effectiveRow(). In no cluster.");
      return row;
    }
    const member = cluster.members.filter(function (one) {
      return one.pep === row.name;
    })[0];
    const out = Object.assign({}, row, this.documentsFor(cluster, member),
                              { cluster: cluster.name });
    log.debug("Leaving PepClusters.effectiveRow(). " + cluster.name);
    return out;
  }

  /**
   * A member's effective row whether or not the PEP is registered: its
   * register row merged, or a row holding only its name.
   * @param cluster - the cluster (as it would be written)
   * @param member - the member
   * @returns the row, and whether the PEP is registered
   */
  memberRow(cluster: ClusterRow, member: Member):
      { row: any; registered: boolean } {
    const { log, peps } = this.deps;
    log.debug("Entering PepClusters.memberRow(). " + member.pep);
    const held = peps.read(member.pep);
    const base = held || { name: member.pep, hostname: '', notifyUrl: '',
                           listenersInUse: null };
    const out = Object.assign({}, base, this.documentsFor(cluster, member),
                              { cluster: cluster.name });
    log.debug("Leaving PepClusters.memberRow(). " + !!held);
    return { row: out, registered: !!held };
  }

  // =========================================================================
  // THE CHECKS A CLUSTER WRITE ASKS OF EVERY MEMBER.
  // =========================================================================
  /**
   * Whether a cluster's proxy document makes the members share a signal
   * stream: a session route with `signals` on, and more than one member.
   * The members poll one CAEP/RISC stream per client, so a sign-out
   * could be consumed by the wrong member; a stream per member is phase 3.
   * @param proxy - the normalised document, or null
   * @param count - how many members the cluster would have
   * @returns a refusal (`STS-XACML-0275`), or null
   */
  signalsProblem(proxy: any, count: number): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering PepClusters.signalsProblem().");
    const route = proxy && count > 1 ? (proxy.routes || [])
      .filter(function (one: any) {
        return one.mechanisms.indexOf('session') >= 0 && one.signals === true;
      })[0] : null;
    if (route) {
      log.debug("Leaving PepClusters.signalsProblem(). " + route.id);
      return this.refuse('Route "' + route.id + '" signs people in with a ' +
        'session and ends their sessions by CAEP/RISC signals (`signals`), ' +
        'and the cluster would have ' + count + ' members. The members ' +
        'would share one signal stream per client, so a sign-out could be ' +
        'consumed by a member that does not hold the session. Turn the ' +
        'route\'s signals off (its sign-out then reaches the proxy by POST ' +
        '/xacml/pep/session), or keep this cluster to one member.',
        'STS-XACML-0275');
    }
    log.debug("Leaving PepClusters.signalsProblem(). None.");
    return null;
  }

  /**
   * Whether a simple or public route of a cluster's document names no
   * resource while the cluster has no logical base URL to build it from.
   * @param doc - the document as given (before the grammar)
   * @returns a refusal (`STS-XACML-0274`), or null
   */
  resourceProblem(doc: any): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering PepClusters.resourceProblem().");
    const base = doc && typeof doc.publicBaseUrl === 'string'
      ? doc.publicBaseUrl : '';
    const route = !base && doc && Array.isArray(doc.routes)
      ? doc.routes.filter(function (one: any) {
          const choice = one && one.authorization;
          return choice && typeof choice === 'object' &&
            (choice.kind === 'simple' || choice.kind === 'public') &&
            (choice.resource === undefined || choice.resource === '');
        })[0] : null;
    if (route) {
      log.debug("Leaving PepClusters.resourceProblem(). " + route.id);
      return this.refuse('Route "' + String(route.id) + '" has a generated ' +
        '(' + route.authorization.kind + ') policy and names no resource, ' +
        'and the cluster has no publicBaseUrl, its logical base URL, to ' +
        'build the default from: every member decides with the one ' +
        'policy, so the resource is the cluster\'s, not a member\'s ' +
        'address. Give the route its resource, or the cluster a ' +
        'publicBaseUrl.', 'STS-XACML-0274');
    }
    log.debug("Leaving PepClusters.resourceProblem(). None.");
    return null;
  }

  /**
   * Asks every member's effective documents what a PEP's own save asks:
   * the proxy's grammar with the member's address, every route's
   * application resolving with the member's callback
   * (`<publicBaseUrl>/.iya-pep/callback` registered), the member's notify
   * URL, and its listeners against what it last reported (the 0247
   * clash). A refusal keeps its code and names the member.
   * @param cluster - the cluster as it would be written
   * @param only - optional; the one member to check
   * @returns a refusal, or null
   */
  memberProblem(cluster: ClusterRow, only?: string): Refusal | null {
    const { log, pepProxy, pepSettings, pepListeners } = this.deps;
    log.debug("Entering PepClusters.memberProblem().");
    const owner = PepClusters.ownerOf(cluster.name);
    const self = this;
    const named = function (pep: string, problem: Refusal): Refusal {
      log.debug("Entering named().");
      log.debug("Leaving named().");
      return self.refuse('Member "' + pep + '": ' + problem.why,
                         problem.code);
    };
    for (let i = 0; i < cluster.members.length; i++) {
      const member = cluster.members[i];
      if (only && member.pep !== only) {
        continue;
      }
      const held = this.memberRow(cluster, member).row;
      if (held.proxy) {
        const checked = pepProxy.validate(held.proxy, owner);
        if (!checked.ok) {
          log.debug("Leaving PepClusters.memberProblem(). Grammar.");
          return named(member.pep, checked);
        }
        const unusable = pepProxy.resolutionProblem(checked.proxy);
        if (unusable) {
          log.debug("Leaving PepClusters.memberProblem(). Resolution.");
          return named(member.pep, unusable);
        }
      }
      if (member.notifyUrl) {
        const set = pepSettings.validate({ settings:
                                           { notifyUrl: member.notifyUrl } });
        if (!set.ok) {
          log.debug("Leaving PepClusters.memberProblem(). Notify URL.");
          return named(member.pep, set);
        }
      }
      if (held.listeners) {
        const list = pepListeners.validate(held.listeners,
                                           held.listenersInUse || null);
        if (!list.ok) {
          log.debug("Leaving PepClusters.memberProblem(). Listeners.");
          return named(member.pep, list);
        }
      }
    }
    log.debug("Leaving PepClusters.memberProblem(). None.");
    return null;
  }

  /**
   * The member problems a cluster's page draws, one row per member with
   * a problem: the same checks as a write, each member on its own, and
   * whether it is registered.
   * @param cluster - the cluster's row
   * @returns `{ pep, registered, code, why }` rows
   */
  memberProblems(cluster: ClusterRow):
      Array<{ pep: string; registered: boolean; code: string | null;
              why: string | null }> {
    const { log } = this.deps;
    log.debug("Entering PepClusters.memberProblems().");
    const self = this;
    const out = cluster.members.map(function (member) {
      const registered = self.memberRow(cluster, member).registered;
      const problem = self.memberProblem(cluster, member.pep);
      return { pep: member.pep, registered: registered,
               code: problem ? problem.code : null,
               why: problem ? problem.why : null };
    });
    log.debug("Leaving PepClusters.memberProblems(). " + out.length);
    return out;
  }
}

const slot = new InstanceSlot<PepClusters>(
  'xacml/xacml_pep_clusters',
  () => new PepClusters(PepClusters.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Remote PEP clusters (#1760): the register under `ou=pepClusters` and the
 * merge a member's pulls are answered from.
 * @namespace
 */
export = {
  PepClusters: PepClusters,
  installInstance: (instance: PepClusters): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SCHEMA: PepClusters.SCHEMA,
  PROSE_ROUTES: PepClusters.PROSE_ROUTES,
  MEMBER_MEMBERS: PepClusters.MEMBER_MEMBERS,
  prose: PepClusters.prose,
  setDirectory: PepClusters.setDirectory,
  directoryInstalled: PepClusters.directoryInstalled,
  nameOk: PepClusters.nameOk,
  ownerOf: PepClusters.ownerOf,
  memberOf: slot.forward('memberOf'),
  membersOf: slot.forward('membersOf'),
  all: slot.forward('all'),
  read: slot.forward('read'),
  clusterOf: slot.forward('clusterOf'),
  write: slot.forward('write'),
  remove: slot.forward('remove'),
  documentsFor: slot.forward('documentsFor'),
  effectiveRow: slot.forward('effectiveRow'),
  memberRow: slot.forward('memberRow'),
  signalsProblem: slot.forward('signalsProblem'),
  resourceProblem: slot.forward('resourceProblem'),
  memberProblem: slot.forward('memberProblem'),
  memberProblems: slot.forward('memberProblems')
};
