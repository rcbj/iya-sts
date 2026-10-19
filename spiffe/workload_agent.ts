// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: workload_agent.ts
//
// ---------------------------------------------------------------------------
// THE WORKLOAD AGENT (#324). A workload on AWS cannot reach this service's
// Workload API: SPIFFE forbids serving that API over TCP unless the network
// authenticates the caller by source address, and a load balancer's address
// is not the workload's (#166, STS-SPIFFE-0120). The honest place for the
// API is next to the workload. This process is that place.
//
// It is a sidecar. An operator mints one join token (the console, or
// POST /admin-api/spiffe/agents/join-token) and this process spends it at
// the SPIRE Server API, which product clusters do publish, over TLS. The
// server returns an agent X509-SVID. From then on this process calls
// GetAuthorizedEntries, BatchNewX509SVID and NewJWTSVID with that SVID, and
// serves the Workload API to the workload on a Unix socket in the same
// task. The kernel tells it the caller's uid and gid. Nothing here binds a
// TCP port, and nothing here treats the load balancer's address as a
// workload.
//
// A LEAF. It requires node, the two gRPC packages, pkijs, asn1js, bunyan
// and common/error_codes.js, and nothing else this repository owns. The
// Workload API implementation, the unix attestor and the peer module all
// require the service's configuration, and requiring any of them from a
// test process would load the service into it. The copies here are the
// small parts a client of the Server API needs: the socket injector, the
// uid/gid selectors, the Struct builder, the JWT check. They are not a
// second implementation of the server.
//
// THE ROTATION TIMER IS NOT A SCHEDULER JOB. A Workload API stream stays
// open and is written again at half the SVID's lifetime, which is what the
// specification's stream is for. That timer lives in this process, per
// stream, the same way spiffe_workload.ts's pushOnRotation lives in the
// service: the stream's file descriptor is here, and a job on the service's
// scheduler could not write it. It is a setTimeout, unref'd, cleared when
// the client goes. It is not setInterval and it does not repeat except by
// the stream still being open.
//
// THE JOIN TOKEN IS NEVER AN ARGUMENT AND NEVER A LOG LINE. `ps` shows
// argv. A flag named --join-token is refused without the value being
// repeated. The token is read from STS_SPIFFE_JOIN_TOKEN or from a file.
//
// WHAT A CALLER IS. At accept, SO_PEERCRED supplies uid and gid (and, when
// the peer is in this pid namespace, a pidfd). The selectors are unix:uid,
// unix:gid, and unix:user / unix:group when the name files have them. No
// supplementary group and no path: the set selectorsFor() returns is the
// set accept emits, and a registration entry is written against that set.
// A peer in another pid namespace (pid 0) is attested on uid and gid only.
// On every call the pidfd, the start time and the executable are checked
// again (STS-SPIFFE-0149). The security header is checked BEFORE that, so a
// missing header is STS-SPIFFE-0003 and not a story about the process.
//
// THE SOCKET IS NOT RESUMED BEFORE IT IS INJECTED. A resume with no reader
// yet emits the client's HTTP/2 preface to nobody. grpc-js's injector takes
// the paused socket. The peer tag is unix:attested-<n> and the number is
// read back with a regex: unix:attested-1 is a prefix of unix:attested-10.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import net = require('net');
import https = require('https');
import crypto = require('crypto');
import grpc = require('@grpc/grpc-js');
import protoLoader = require('@grpc/proto-loader');
import pkijs = require('pkijs');
import asn1js = require('asn1js');
import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({
  name: 'spiffe-workload-agent',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

const PROTO_DIR = path.join(__dirname, 'protos');

const LOAD_OPTIONS = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [PROTO_DIR]
};

const SERVER_PROTOS = [
  'spire/api/server/agent/v1/agent.proto',
  'spire/api/server/entry/v1/entry.proto',
  'spire/api/server/bundle/v1/bundle.proto',
  'spire/api/server/svid/v1/svid.proto'
];

const CHANNEL_OPTIONS = { 'grpc.use_local_subchannel_pool': 1 };

const SECURITY_HEADER = 'workload.spiffe.io';

const DEADLINE_MS = 20000;

const ATTEST_PAUSE_MS = 500;

const WIT_MESSAGE =
  'This service does not issue WIT-SVIDs. The Workload Identity Token\'s ' +
  'format is not settled in a specification this agent could implement ' +
  'against, and minting something JWS-shaped and calling it a WIT-SVID ' +
  'would be inventing a credential format. X509-SVIDs and JWT-SVIDs are ' +
  'implemented.';

const TRUST_DOMAIN_CHARS = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/;

const PATH_SEGMENT_CHARS = /^[A-Za-z0-9._-]+$/;

/**
 * A workload agent: one join token, the SPIRE Server API, and the Workload
 * API on a Unix socket beside the workload (#324).
 */
class WorkloadAgent {

  log: any;

  server: string;

  socketPath: string;

  trustDomain: string;

  joinToken: string;

  trustBundlePem: string;

  bundleUrl: string;

  requireSecurityHeader: boolean;

  attestWorkloads: boolean;

  nativePath: string;

  procRoot: string;

  passwdPath: string;

  groupPath: string;

  attestAttempts: number;

  attestPauseMs: number;

  native: any;

  anchorsPem: string;

  agentSpiffeId: string;

  agentKeyPem: string;

  agentCertPem: string;

  services: any;

  clients: any;

  grpcServer: any;

  injector: any;

  listener: any;

  peers: Map<number, any>;

  counter: number;

  latest: any;

  timers: Set<any>;

  started: boolean;

  stopped: boolean;

  /**
   * Records the options. Nothing is bound and nothing is attested here.
   *
   * @param opts - the server, the socket, the trust domain, the join token
   *   and the trust bundle
   */
  constructor(opts: any) {
    log.debug("Entering WorkloadAgent.constructor().");
    const options = opts || {};
    this.log = options.log || log;
    this.server = String(options.server || '').trim();
    this.socketPath = options.socketPath
      ? path.resolve(String(options.socketPath)) : '';
    this.trustDomain = String(options.trustDomain || '').trim();
    this.joinToken = String(options.joinToken || '');
    this.trustBundlePem = String(options.trustBundlePem || '');
    this.bundleUrl = String(options.bundleUrl || '').trim();
    this.requireSecurityHeader = options.requireSecurityHeader !== false;
    this.attestWorkloads = options.attestWorkloads !== false;
    this.nativePath = options.nativePath
      ? String(options.nativePath) : '';
    this.procRoot = String(options.procRoot || '/proc');
    this.passwdPath = String(options.passwdPath || '/etc/passwd');
    this.groupPath = String(options.groupPath || '/etc/group');
    this.attestAttempts = Number(options.attestAttempts) > 0
      ? Number(options.attestAttempts) : 30;
    this.attestPauseMs = Number(options.attestPauseMs) >= 0
      ? Number(options.attestPauseMs) : ATTEST_PAUSE_MS;
    this.native = null;
    this.anchorsPem = '';
    this.agentSpiffeId = '';
    this.agentKeyPem = '';
    this.agentCertPem = '';
    this.services = null;
    this.clients = null;
    this.grpcServer = null;
    this.injector = null;
    this.listener = null;
    this.peers = new Map();
    this.counter = 0;
    this.latest = null;
    this.timers = new Set();
    this.started = false;
    this.stopped = false;
    log.debug("Leaving WorkloadAgent.constructor().");
  }

  /**
   * The unix selectors a caller of this uid and gid is seen as. The same
   * set accept emits: uid, gid, and the names when the files have them.
   *
   * @param uid - the numeric uid
   * @param gid - the numeric gid
   * @param opts - passwdPath and groupPath, when not the system files
   * @returns the selectors, type `unix`
   */
  static selectorsFor(uid: any, gid: any, opts?: any): any[] {
    log.debug("Entering WorkloadAgent.selectorsFor().");
    const options = opts || {};
    const passwd = options.passwdPath || '/etc/passwd';
    const group = options.groupPath || '/etc/group';
    const uidText = String(uid);
    const gidText = String(gid);
    const user = WorkloadAgent.nameOf(passwd, uidText);
    const groupName = WorkloadAgent.nameOf(group, gidText);
    const values = ['uid:' + uidText];
    if (user) {
      values.push('user:' + user);
    }
    values.push('gid:' + gidText);
    if (groupName) {
      values.push('group:' + groupName);
    }
    const out = values.map(function (value) {
      return { type: 'unix', value: value };
    });
    log.debug("Leaving WorkloadAgent.selectorsFor().");
    return out;
  }

  /**
   * The selectors as the admin API takes them, comma-separated.
   *
   * @param uid - the numeric uid
   * @param gid - the numeric gid
   * @param opts - passwdPath and groupPath, when not the system files
   * @returns the selector text
   */
  static selectorsText(uid: any, gid: any, opts?: any): string {
    log.debug("Entering WorkloadAgent.selectorsText().");
    const text = WorkloadAgent.selectorsFor(uid, gid, opts).map(
      function (selector) {
        return selector.type + ':' + selector.value;
      }).join(', ');
    log.debug("Leaving WorkloadAgent.selectorsText().");
    return text;
  }

  /**
   * Looks up one name by id in a passwd- or group-style file.
   *
   * @param file - the file's path
   * @param id - the numeric id
   * @returns the name, or ''
   */
  static nameOf(file: string, id: string): string {
    log.debug("Entering WorkloadAgent.nameOf().");
    try {
      const lines = fs.readFileSync(file, 'utf8').split('\n');
      for (let i = 0; i < lines.length; i++) {
        const fields = lines[i].split(':');
        if (fields.length > 2 && fields[2] === id && fields[0]) {
          log.debug("Leaving WorkloadAgent.nameOf().");
          return fields[0];
        }
      }
    } catch (e) {
      // A missing passwd or group file is not a failure; the name becomes ''.
      log.debug("Caught in WorkloadAgent.nameOf(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving WorkloadAgent.nameOf(). None.");
    return '';
  }

  /**
   * Builds an Error carrying an STS code. The code is for the operator;
   * it is never put on the wire.
   *
   * @param code - the error code
   * @param message - the sentence
   * @returns the error
   */
  static fail(code: string, message: string): any {
    log.debug("Entering WorkloadAgent.fail().");
    const err: any = new Error(message);
    err.code = code;
    log.debug("Leaving WorkloadAgent.fail().");
    return err;
  }

  /**
   * Builds a refusal a Workload API method answers with: a gRPC status and
   * the STS code the log records.
   *
   * @param code - the error code
   * @param status - the gRPC status
   * @param message - the sentence the client sees
   * @returns the error
   */
  static refusal(code: string, status: number, message: string): any {
    log.debug("Entering WorkloadAgent.refusal().");
    const err: any = new Error(message);
    err.code = status;
    err.details = message;
    err.errorCode = code;
    log.debug("Leaving WorkloadAgent.refusal().");
    return err;
  }

  /**
   * The sentence a caller entitled to nothing is answered with.
   *
   * @param method - the method
   * @param what - what it is not entitled to
   * @returns the sentence
   */
  static notEntitled(method: string, what: string): string {
    log.debug("Entering WorkloadAgent.notEntitled().");
    log.debug("Leaving WorkloadAgent.notEntitled().");
    return 'no identity issued: ' + method + ' — the caller is not ' +
           'entitled to ' + what + ' (no registration entry matches it).';
  }

  /**
   * Installs node's Web Crypto as pkijs's engine when nothing has. A
   * process that already installed one — the service, in the in-process
   * test — is left alone: replacing the engine would change the service's
   * signatures.
   */
  static ensurePkijs(): void {
    log.debug("Entering WorkloadAgent.ensurePkijs().");
    try {
      pkijs.getCrypto(true);
      log.debug("Leaving WorkloadAgent.ensurePkijs(). Already set.");
      return;
    } catch (e) {
      // No engine is installed yet, which is the case this method exists
      // to fill. One already installed returned above.
      log.debug("Caught in WorkloadAgent.ensurePkijs(): " +
                ((e && e.message) || e));
    }
    const webcrypto = (crypto as any).webcrypto;
    if (!webcrypto || !webcrypto.subtle) {
      log.debug("Leaving WorkloadAgent.ensurePkijs(). No Web Crypto.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The workload agent has no crypto engine to sign a certificate ' +
        'request with.');
    }
    pkijs.setEngine('webcrypto', new (pkijs as any).CryptoEngine({
      name: 'webcrypto', crypto: webcrypto
    }));
    log.debug("Leaving WorkloadAgent.ensurePkijs(). Installed.");
  }

  /**
   * Wraps DER as a PEM block, 64 columns to a line.
   *
   * @param der - the DER
   * @param label - the PEM label
   * @returns the PEM
   */
  static pemFromDer(der: Buffer, label: string): string {
    log.debug("Entering WorkloadAgent.pemFromDer().");
    const b64 = Buffer.from(der).toString('base64');
    const lines = [];
    for (let i = 0; i < b64.length; i += 64) {
      lines.push(b64.slice(i, i + 64));
    }
    log.debug("Leaving WorkloadAgent.pemFromDer().");
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') +
           '\n-----END ' + label + '-----\n';
  }

  /**
   * Concatenates DER fragments, leaf first as the caller handed them.
   *
   * @param parts - the fragments
   * @returns one buffer
   */
  static concatDer(parts: any): Buffer {
    log.debug("Entering WorkloadAgent.concatDer().");
    const bufs = [];
    (parts || []).forEach(function (part) {
      if (part && part.length) {
        bufs.push(Buffer.from(part));
      }
    });
    log.debug("Leaving WorkloadAgent.concatDer().");
    return bufs.length ? Buffer.concat(bufs) : Buffer.alloc(0);
  }

  /**
   * Concatenates certificates as PEM, leaf first.
   *
   * @param ders - the certificate DER fragments
   * @returns the PEM
   */
  static certsToPem(ders: any): string {
    log.debug("Entering WorkloadAgent.certsToPem().");
    const parts = [];
    (ders || []).forEach(function (der) {
      if (der && der.length) {
        parts.push(WorkloadAgent.pemFromDer(Buffer.from(der),
                                            'CERTIFICATE'));
      }
    });
    log.debug("Leaving WorkloadAgent.certsToPem().");
    return parts.join('');
  }

  /**
   * Reads a SPIFFE ID out of a SPIRE `trust_domain` and `path`.
   *
   * @param message - the proto
   * @returns the id, or ''
   */
  static idFromProto(message: any): string {
    log.debug("Entering WorkloadAgent.idFromProto().");
    const proto = message || {};
    const trustDomain = String(proto.trust_domain || '').trim();
    const idPath = String(proto.path || '');
    if (!trustDomain || (idPath && idPath.charAt(0) !== '/')) {
      log.debug("Leaving WorkloadAgent.idFromProto(). None.");
      return '';
    }
    log.debug("Leaving WorkloadAgent.idFromProto().");
    return 'spiffe://' + trustDomain + idPath;
  }

  /**
   * Reads one registration entry out of the Server API's message.
   *
   * @param message - the proto
   * @returns the entry
   */
  static entryFromProto(message: any): any {
    log.debug("Entering WorkloadAgent.entryFromProto().");
    const proto = message || {};
    log.debug("Leaving WorkloadAgent.entryFromProto().");
    return {
      id: String(proto.id || ''),
      spiffeId: WorkloadAgent.idFromProto(proto.spiffe_id),
      selectors: (proto.selectors || []).map(function (selector) {
        return { type: String(selector.type || ''),
                 value: String(selector.value || '') };
      }),
      x509SvidTtl: Number(proto.x509_svid_ttl || 0),
      jwtSvidTtl: Number(proto.jwt_svid_ttl || 0),
      federatesWith: (proto.federates_with || []).map(String),
      hint: String(proto.hint || '')
    };
  }

  /**
   * SPIRE's rule: every selector on the entry is present on the caller.
   * An entry with none matches every caller.
   *
   * @param entrySelectors - the entry's selectors
   * @param callerSelectors - the caller's selector texts
   * @returns whether the entry matches
   */
  static selectorsMatch(entrySelectors: any, callerSelectors: any): boolean {
    log.debug("Entering WorkloadAgent.selectorsMatch().");
    const have = {};
    (callerSelectors || []).forEach(function (text) {
      if (text) {
        have[text] = true;
      }
    });
    const wanted = [];
    (entrySelectors || []).forEach(function (selector) {
      const type = String(selector.type || '').trim();
      const value = String(selector.value || '').trim();
      if (type && value) {
        wanted.push(type + ':' + value);
      }
    });
    if (!wanted.length) {
      log.debug("Leaving WorkloadAgent.selectorsMatch(). Empty.");
      return true;
    }
    for (let i = 0; i < wanted.length; i++) {
      if (!have[wanted[i]]) {
        log.debug("Leaving WorkloadAgent.selectorsMatch(). No.");
        return false;
      }
    }
    log.debug("Leaving WorkloadAgent.selectorsMatch().");
    return true;
  }

  /**
   * Asks whether one batch item's status is OK. The loader stringifies
   * enums and int64s, and this field is an int32, so 0, '0' and 'OK' are
   * the same answer.
   *
   * @param status - the status message
   * @returns whether it is OK
   */
  static statusOk(status: any): boolean {
    log.debug("Entering WorkloadAgent.statusOk().");
    const code = status && status.code;
    const ok = code === 0 || code === '0' || code === 'OK';
    log.debug("Leaving WorkloadAgent.statusOk(). " + ok);
    return ok;
  }

  /**
   * Decodes a base64url segment, adding the padding the JWT omitted.
   *
   * @param text - the segment
   * @returns the bytes
   */
  static b64url(text: string): Buffer {
    log.debug("Entering WorkloadAgent.b64url().");
    const pad = text.length % 4 === 0 ? ''
      : '='.repeat(4 - (text.length % 4));
    log.debug("Leaving WorkloadAgent.b64url().");
    return Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/') + pad,
                       'base64');
  }

  /**
   * Parses a SPIFFE ID. Enough of the grammar that a caller cannot name
   * an identity by a string that is not one; the server remains the
   * authority for the ids it issues.
   *
   * @param value - the text
   * @returns `{ ok, id, trustDomain, path }` or `{ ok: false, reason }`
   */
  static parseSpiffeId(value: string): any {
    log.debug("Entering WorkloadAgent.parseSpiffeId().");
    const text = String(value == null ? '' : value);
    if (text.slice(0, 9).toLowerCase() !== 'spiffe://') {
      log.debug("Leaving WorkloadAgent.parseSpiffeId(). Scheme.");
      return { ok: false, reason: 'A SPIFFE ID begins with spiffe://; ' +
               'this one does not.' };
    }
    const rest = text.slice(9);
    const slash = rest.indexOf('/');
    const authority = slash === -1 ? rest : rest.slice(0, slash);
    const idPath = slash === -1 ? '' : rest.slice(slash);
    if (!authority || authority.indexOf('@') !== -1 ||
        authority.indexOf(':') !== -1 ||
        !TRUST_DOMAIN_CHARS.test(authority)) {
      log.debug("Leaving WorkloadAgent.parseSpiffeId(). Trust domain.");
      return { ok: false, reason: 'The trust domain is not a valid ' +
               'SPIFFE trust domain name.' };
    }
    if (idPath) {
      if (idPath.indexOf('?') !== -1 || idPath.indexOf('#') !== -1 ||
          idPath.indexOf('%') !== -1) {
        log.debug("Leaving WorkloadAgent.parseSpiffeId(). Path.");
        return { ok: false, reason: 'A SPIFFE ID path carries no query, ' +
                 'no fragment and no percent-encoding.' };
      }
      const parts = idPath.split('/');
      for (let i = 1; i < parts.length; i++) {
        const segment = parts[i];
        if (!segment || segment === '.' || segment === '..' ||
            !PATH_SEGMENT_CHARS.test(segment)) {
          log.debug("Leaving WorkloadAgent.parseSpiffeId(). Segment.");
          return { ok: false, reason: 'A SPIFFE ID path segment is ' +
                   'empty, relative, or has a character it may not.' };
        }
      }
    }
    log.debug("Leaving WorkloadAgent.parseSpiffeId().");
    return { ok: true, id: 'spiffe://' + authority + idPath,
             trustDomain: authority, path: idPath };
  }

  /**
   * Converts a plain object to a `google.protobuf.Struct`. The well-known
   * type's fields are camelCase even when every other field is kept in
   * the proto's spelling: `stringValue`, not `string_value`.
   *
   * @param value - the object
   * @returns the Struct
   */
  static structFrom(value: any): any {
    log.debug("Entering WorkloadAgent.structFrom().");
    const fields = {};
    Object.keys(value || {}).forEach(function (key) {
      fields[key] = WorkloadAgent.valueFrom(value[key]);
    });
    log.debug("Leaving WorkloadAgent.structFrom().");
    return { fields: fields };
  }

  /**
   * Converts one JSON value to a `google.protobuf.Value`.
   *
   * @param value - the value
   * @returns the Value
   */
  static valueFrom(value: any): any {
    log.debug("Entering WorkloadAgent.valueFrom().");
    if (value === null || value === undefined) {
      log.debug("Leaving WorkloadAgent.valueFrom(). Null.");
      return { nullValue: 'NULL_VALUE' };
    }
    if (typeof value === 'boolean') {
      log.debug("Leaving WorkloadAgent.valueFrom(). Boolean.");
      return { boolValue: value };
    }
    if (typeof value === 'number') {
      log.debug("Leaving WorkloadAgent.valueFrom(). Number.");
      return Number.isFinite(value) ? { numberValue: value }
                                    : { stringValue: String(value) };
    }
    if (typeof value === 'string') {
      log.debug("Leaving WorkloadAgent.valueFrom(). String.");
      return { stringValue: value };
    }
    if (Array.isArray(value)) {
      log.debug("Leaving WorkloadAgent.valueFrom(). List.");
      return { listValue: { values: value.map(function (one) {
        return WorkloadAgent.valueFrom(one);
      }) } };
    }
    log.debug("Leaving WorkloadAgent.valueFrom(). Struct.");
    return { structValue: WorkloadAgent.structFrom(value) };
  }

  /**
   * Loads the native peer-credentials module. A failure here is the end:
   * the socket is not created, because a Workload API that cannot say who
   * called it must not answer.
   */
  loadNative(): void {
    this.log.debug("Entering WorkloadAgent.loadNative().");
    const where = this.nativePath ||
                  path.join(__dirname, 'native', 'peercred.node');
    let loaded = null;
    try {
      loaded = require(where);
    } catch (e) {
      // Without peer credentials the agent must not answer. This is
      // STS-SPIFFE-0148, and no socket is created.
      this.log.debug("Caught in WorkloadAgent.loadNative(): " +
                     ((e && e.message) || e));
      this.log.debug("Leaving WorkloadAgent.loadNative(). Failed.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The workload agent could not load the native peer-credentials ' +
        'module (' + where + ').');
    }
    if (!loaded || typeof loaded.peerCred !== 'function') {
      this.log.debug("Leaving WorkloadAgent.loadNative(). Incomplete.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The native peer-credentials module at ' + where +
        ' does not export peerCred.');
    }
    this.native = loaded;
    this.log.debug("Leaving WorkloadAgent.loadNative().");
  }

  /**
   * Fetches the trust anchors: the PEM handed in, or the public HTTPS
   * bundle document's `x509-svid` certificates.
   */
  async loadAnchors(): Promise<void> {
    this.log.debug("Entering WorkloadAgent.loadAnchors().");
    if (this.trustBundlePem.trim()) {
      this.anchorsPem = this.trustBundlePem;
      this.log.debug("Leaving WorkloadAgent.loadAnchors(). Given.");
      return;
    }
    if (!this.bundleUrl) {
      this.log.debug("Leaving WorkloadAgent.loadAnchors(). None.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The workload agent was given no trust bundle and no bundle URL.');
    }
    // ONLY OVER HTTPS. These are the anchors every later connection to the
    // server is verified against, so a bundle fetched in the clear is one
    // anybody on the path could have written. A deployment without an HTTPS
    // bundle endpoint hands the PEM in instead (`--trust-bundle-file`).
    if (!/^https:\/\//i.test(this.bundleUrl)) {
      this.log.debug("Leaving WorkloadAgent.loadAnchors(). Not HTTPS.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The workload agent\'s bundle URL is not an https: URL; the trust ' +
        'bundle is fetched only over HTTPS.');
    }
    let text = '';
    try {
      text = await this.fetchText(this.bundleUrl);
    } catch (e) {
      // The bundle URL did not answer. The caller sees STS-SPIFFE-0148
      // rather than the transport's own error.
      this.log.debug("Caught in WorkloadAgent.loadAnchors(): " +
                     ((e && e.message) || e));
      this.log.debug("Leaving WorkloadAgent.loadAnchors(). Fetch.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The workload agent could not fetch its trust bundle.');
    }
    this.anchorsPem = WorkloadAgent.anchorsFromDocument(text);
    if (!this.anchorsPem) {
      this.log.debug("Leaving WorkloadAgent.loadAnchors(). Empty.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The bundle document carried no x509-svid certificate.');
    }
    this.log.debug("Leaving WorkloadAgent.loadAnchors().");
  }

  /**
   * Takes the `x509-svid` `x5c` certificates out of a JWK Set.
   *
   * @param text - the document
   * @returns PEM anchors, or ''
   */
  static anchorsFromDocument(text: string): string {
    log.debug("Entering WorkloadAgent.anchorsFromDocument().");
    let document = null;
    try {
      document = JSON.parse(text);
    } catch (e) {
      // Not a JWK Set. '' is what the caller refuses as an empty bundle.
      log.debug("Caught in WorkloadAgent.anchorsFromDocument(): " +
                ((e && e.message) || e));
      log.debug("Leaving WorkloadAgent.anchorsFromDocument(). Not JSON.");
      return '';
    }
    const pems = [];
    ((document && document.keys) || []).forEach(function (key) {
      if (key && key.use === 'x509-svid' && key.x5c && key.x5c[0]) {
        pems.push(WorkloadAgent.pemFromDer(
          Buffer.from(String(key.x5c[0]), 'base64'), 'CERTIFICATE'));
      }
    });
    log.debug("Leaving WorkloadAgent.anchorsFromDocument().");
    return pems.join('');
  }

  /**
   * GETs a URL and returns the body. Used for the public bundle document
   * only.
   *
   * @param url - the URL
   * @returns the body
   */
  fetchText(url: string): Promise<string> {
    this.log.debug("Entering WorkloadAgent.fetchText().");
    this.log.debug("Leaving WorkloadAgent.fetchText().");
    return new Promise(function (resolve, reject) {
      const req = https.get(url, { timeout: DEADLINE_MS }, function (res) {
        const chunks = [];
        res.on('data', function (chunk) { chunks.push(chunk); });
        res.on('end', function () {
          if (res.statusCode !== 200) {
            reject(new Error('the bundle endpoint answered ' +
                             res.statusCode));
            return;
          }
          resolve(Buffer.concat(chunks).toString('utf8'));
        });
      });
      req.on('error', function (err) { reject(err); });
    });
  }

  /**
   * Makes one ECDSA P-256 certificate request. The server reads the public
   * key and ignores the subject. The attributes tag is present and empty,
   * because PKCS#10 requires it and pkijs omits it when the member is
   * undefined.
   *
   * @param commonName - the subject CN
   * @returns the PKCS#8 private key and the CSR, both DER
   */
  async makeCsr(commonName: string): Promise<any> {
    this.log.debug("Entering WorkloadAgent.makeCsr().");
    WorkloadAgent.ensurePkijs();
    const subtle = (crypto as any).webcrypto.subtle;
    const pair = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8 = Buffer.from(await subtle.exportKey('pkcs8',
                                                     pair.privateKey));
    const spki = Buffer.from(await subtle.exportKey('spki',
                                                    pair.publicKey));
    const request = new pkijs.CertificationRequest();
    request.version = 0;
    request.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: commonName || 'workload' })
    }));
    const parsed = asn1js.fromBER(spki);
    if (parsed.offset === -1) {
      this.log.debug("Leaving WorkloadAgent.makeCsr(). SPKI.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The workload agent could not encode a certificate signing ' +
        'request.');
    }
    request.subjectPublicKeyInfo.fromSchema(parsed.result);
    request.attributes = [];
    await request.sign(pair.privateKey, 'SHA-256');
    const csr = Buffer.from(request.toSchema(true).toBER(false));
    this.log.debug("Leaving WorkloadAgent.makeCsr().");
    return { pkcs8: pkcs8, csr: csr };
  }

  /**
   * The Server API address, without a scheme.
   *
   * @returns host:port
   */
  serverTarget(): string {
    this.log.debug("Entering WorkloadAgent.serverTarget().");
    const target = this.server.replace(/^(tcp|dns):\/\//i, '');
    this.log.debug("Leaving WorkloadAgent.serverTarget().");
    return target;
  }

  /**
   * Accepts the server only when its certificate names this trust domain's
   * SPIRE server. A hostname check cannot: the certificate has no DNS name.
   *
   * @param hostname - unused; grpc-js passes it
   * @param cert - the peer certificate
   * @returns undefined when it matches, otherwise an Error
   */
  checkServerIdentity(hostname: string, cert: any): any {
    this.log.debug("Entering WorkloadAgent.checkServerIdentity().");
    const want = 'URI:spiffe://' + this.trustDomain + '/spire/server';
    const names = String((cert && cert.subjectaltname) || '')
      .split(/,\s*/);
    if (names.indexOf(want) >= 0) {
      this.log.debug("Leaving WorkloadAgent.checkServerIdentity().");
      return undefined;
    }
    this.log.debug("Leaving WorkloadAgent.checkServerIdentity(). Not " +
                   "the server.");
    return new Error('the SPIRE Server API presented ' +
                     ((cert && cert.subjectaltname) || 'no SAN') +
                     ', not ' + want);
  }

  /**
   * TLS credentials for the Server API. No client certificate until the
   * agent has attested.
   *
   * @param identity - the agent key and certificate, or null
   * @returns the channel credentials
   */
  tlsCredentials(identity: any): any {
    this.log.debug("Entering WorkloadAgent.tlsCredentials().");
    const self = this;
    const creds = grpc.credentials.createSsl(
      Buffer.from(this.anchorsPem, 'utf8'),
      identity ? Buffer.from(identity.keyPem, 'utf8') : null,
      identity ? Buffer.from(identity.certPem, 'utf8') : null,
      { checkServerIdentity: function (hostname, cert) {
        return self.checkServerIdentity(hostname, cert);
      } });
    this.log.debug("Leaving WorkloadAgent.tlsCredentials().");
    return creds;
  }

  /**
   * One AttestAgent exchange. The send side stays open until the answer
   * arrives: half-closing first makes the server finish the stream before
   * the handler replies, and the token is spent on an empty answer.
   *
   * @param csr - the agent's CSR
   * @returns the response message
   */
  attestOnce(csr: Buffer): Promise<any> {
    this.log.debug("Entering WorkloadAgent.attestOnce().");
    const self = this;
    const client = new this.services.Agent(
      this.serverTarget(), this.tlsCredentials(null), CHANNEL_OPTIONS);
    this.log.debug("Leaving WorkloadAgent.attestOnce().");
    return new Promise(function (resolve, reject) {
      let settled = false;
      const stream = client.AttestAgent({
        deadline: Date.now() + DEADLINE_MS
      });
      const timer = setTimeout(function () {
        finish(WorkloadAgent.fail('STS-SPIFFE-0148',
                                  'AttestAgent timed out.'));
      }, DEADLINE_MS + 1000);
      function finish(err, value?) {
        self.log.debug("Entering finish().");
        if (settled) {
          self.log.debug("Leaving finish(). Settled.");
          return;
        }
        settled = true;
        clearTimeout(timer);
        try {
          stream.end();
        } catch (e) {
          // Closing a stream that is already going away.
          self.log.debug("Caught in WorkloadAgent.attestOnce(): " +
                         ((e && e.message) || e));
        }
        try {
          client.close();
        } catch (e) {
          // Closing a client that is already going away.
          self.log.debug("Caught in WorkloadAgent.attestOnce(): " +
                         ((e && e.message) || e));
        }
        if (err) {
          self.log.debug("Leaving finish(). Refused.");
          reject(err);
          return;
        }
        self.log.debug("Leaving finish().");
        resolve(value);
      }
      stream.on('data', function (message) { finish(null, message); });
      stream.on('error', function (err) { finish(err); });
      stream.write({
        params: {
          data: { type: 'join_token',
                  payload: Buffer.from(self.joinToken, 'utf8') },
          params: { csr: csr }
        }
      });
    });
  }

  /**
   * Attests with the join token, retrying while the call failed. A token
   * minted on another node is not visible everywhere at once, and a
   * refusal before the token is known does not spend it. A success is not
   * retried: the token is spent.
   *
   * @param csr - the agent's CSR
   * @returns the agent X509-SVID message
   */
  async attest(csr: Buffer): Promise<any> {
    this.log.debug("Entering WorkloadAgent.attest().");
    let last = null;
    for (let i = 0; i < this.attestAttempts; i++) {
      try {
        const message = await this.attestOnce(csr);
        const svid = message && message.result && message.result.svid;
        if (!svid || !(svid.cert_chain && svid.cert_chain.length)) {
          this.log.debug("Leaving WorkloadAgent.attest(). No SVID.");
          throw WorkloadAgent.fail('STS-SPIFFE-0148',
            'AttestAgent returned no agent SVID.');
        }
        this.log.debug("Leaving WorkloadAgent.attest(). Attempt " +
                       (i + 1) + '.');
        return svid;
      } catch (e) {
        // A token minted on another node is not visible everywhere at
        // once, so those three statuses are retried and the last is kept.
        last = e;
        this.log.debug("Caught in WorkloadAgent.attest(): status " +
                       (e && e.code));
        const retry = e && (e.code === grpc.status.UNAVAILABLE ||
                            e.code === grpc.status.PERMISSION_DENIED ||
                            e.code === grpc.status.DEADLINE_EXCEEDED);
        if (!retry || i + 1 === this.attestAttempts) {
          break;
        }
        await this.sleep(this.attestPauseMs);
      }
    }
    this.log.debug("Leaving WorkloadAgent.attest(). Failed.");
    throw WorkloadAgent.fail('STS-SPIFFE-0148',
      'Join-token attestation failed (gRPC status ' +
      ((last && last.code) == null ? 'unknown' : last.code) + ').');
  }

  /**
   * Waits. One delay inside an attestation attempt, not a periodic timer.
   *
   * @param ms - the delay
   */
  sleep(ms: number): Promise<void> {
    this.log.debug("Entering WorkloadAgent.sleep().");
    this.log.debug("Leaving WorkloadAgent.sleep().");
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  /**
   * Loads the four Server API services and the Workload API service.
   */
  loadServices(): void {
    this.log.debug("Entering WorkloadAgent.loadServices().");
    if (this.services) {
      this.log.debug("Leaving WorkloadAgent.loadServices(). Cached.");
      return;
    }
    const workload = grpc.loadPackageDefinition(protoLoader.loadSync(
      path.join(PROTO_DIR, 'workloadapi.proto'), LOAD_OPTIONS));
    const server: any = grpc.loadPackageDefinition(protoLoader.loadSync(
      SERVER_PROTOS.map(function (name) {
        return path.join(PROTO_DIR, name);
      }), LOAD_OPTIONS));
    this.services = {
      Workload: (workload as any).SpiffeWorkloadAPI,
      Agent: server.spire.api.server.agent.v1.Agent,
      Entry: server.spire.api.server.entry.v1.Entry,
      Bundle: server.spire.api.server.bundle.v1.Bundle,
      SVID: server.spire.api.server.svid.v1.SVID
    };
    this.log.debug("Leaving WorkloadAgent.loadServices().");
  }

  /**
   * Opens the Server API clients with the agent SVID.
   */
  openClients(): void {
    this.log.debug("Entering WorkloadAgent.openClients().");
    const creds = this.tlsCredentials({
      keyPem: this.agentKeyPem, certPem: this.agentCertPem
    });
    const target = this.serverTarget();
    this.clients = {
      entry: new this.services.Entry(target, creds, CHANNEL_OPTIONS),
      bundle: new this.services.Bundle(target, creds, CHANNEL_OPTIONS),
      svid: new this.services.SVID(target, creds, CHANNEL_OPTIONS)
    };
    this.log.debug("Leaving WorkloadAgent.openClients().");
  }

  /**
   * One unary Server API call.
   *
   * @param client - the service client
   * @param method - the method
   * @param request - the request
   * @returns the response
   */
  callUnary(client: any, method: string, request: any): Promise<any> {
    this.log.debug("Entering WorkloadAgent.callUnary(). " + method);
    this.log.debug("Leaving WorkloadAgent.callUnary().");
    return new Promise(function (resolve, reject) {
      client[method](request || {}, new grpc.Metadata(),
                     { deadline: Date.now() + DEADLINE_MS },
                     function (err, value) {
        if (err) {
          const wrapped: any = new Error(err.details || err.message ||
                                         method);
          wrapped.code = err.code;
          reject(wrapped);
          return;
        }
        resolve(value || {});
      });
    });
  }

  /**
   * Binds the Unix socket and hands each connection to grpc-js after the
   * peer is recorded. The socket is mode 0666 so a workload of another
   * uid in the same task can connect. It is not resumed.
   */
  async bindSocket(): Promise<void> {
    this.log.debug("Entering WorkloadAgent.bindSocket().");
    const self = this;
    const dir = path.dirname(this.socketPath);
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    } catch (e) {
      // The socket directory could not be created, so the agent does not
      // bind. The caller sees STS-SPIFFE-0148.
      this.log.debug("Caught in WorkloadAgent.bindSocket(): " +
                     ((e && e.message) || e));
      this.log.debug("Leaving WorkloadAgent.bindSocket(). Directory.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The workload agent could not create ' + dir + '.');
    }
    try {
      fs.unlinkSync(this.socketPath);
    } catch (e) {
      // A missing socket is the state replace wanted.
      this.log.debug("Caught in WorkloadAgent.bindSocket(): " +
                     ((e && e.message) || e));
      if (!e || e.code !== 'ENOENT') {
        this.log.debug("Leaving WorkloadAgent.bindSocket(). Unlink.");
        throw WorkloadAgent.fail('STS-SPIFFE-0148',
          'The workload agent could not replace ' + this.socketPath + '.');
      }
    }
    this.grpcServer = new grpc.Server();
    this.grpcServer.addService(this.services.Workload.service,
                               this.handlers());
    this.injector = this.grpcServer.createConnectionInjector(
      grpc.ServerCredentials.createInsecure());
    this.listener = net.createServer(function (socket) {
      self.accept(socket);
    });
    try {
      await new Promise(function (resolve, reject) {
        self.listener.once('error', function (err) { reject(err); });
        self.listener.listen(self.socketPath, function () { resolve(null); });
      });
      fs.chmodSync(this.socketPath, 0o666);
    } catch (e) {
      // The listen or the mode change failed, so the agent does not
      // serve. The caller sees STS-SPIFFE-0148.
      this.log.debug("Caught in WorkloadAgent.bindSocket(): " +
                     ((e && e.message) || e));
      this.log.debug("Leaving WorkloadAgent.bindSocket(). Bind.");
      throw WorkloadAgent.fail('STS-SPIFFE-0148',
        'The workload agent could not bind ' + this.socketPath + '.');
    }
    this.log.debug("Leaving WorkloadAgent.bindSocket().");
  }

  /**
   * Records one accepted peer and injects the paused socket.
   *
   * @param socket - the accepted socket
   */
  accept(socket: any): void {
    this.log.debug("Entering WorkloadAgent.accept().");
    socket.pause();
    const facts = this.observe(socket);
    if (facts.error) {
      this.log.debug("Leaving WorkloadAgent.accept(). " + facts.error);
      socket.destroy();
      return;
    }
    try {
      Object.defineProperty(socket, 'remoteAddress', { value: facts.tag });
      Object.defineProperty(socket, 'remotePort', { value: facts.n });
    } catch (e) {
      // The peer tag could not be set. The socket is closed rather than
      // injected: the tag is how a later call is matched to this peer.
      this.log.debug("Caught in WorkloadAgent.accept(): " +
                     ((e && e.message) || e));
      this.log.debug("Leaving WorkloadAgent.accept(). Tag.");
      socket.destroy();
      return;
    }
    const self = this;
    socket.on('close', function () { self.forget(facts); });
    try {
      this.injector.injectConnection(socket);
    } catch (e) {
      // grpc-js refused the paused socket. The peer is forgotten and the
      // socket is destroyed, so a half-injected connection is not served.
      this.log.debug("Caught in WorkloadAgent.accept(): " +
                     ((e && e.message) || e));
      this.forget(facts);
      socket.destroy();
      this.log.debug("Leaving WorkloadAgent.accept(). Inject.");
      return;
    }
    this.log.debug("Leaving WorkloadAgent.accept(). " + facts.tag);
  }

  /**
   * What the kernel says about the socket's peer, taken at accept. Never
   * throws; a failure is `facts.error` and the socket is closed.
   *
   * @param socket - the accepted socket
   * @returns the facts
   */
  observe(socket: any): any {
    this.log.debug("Entering WorkloadAgent.observe().");
    this.counter += 1;
    const facts: any = {
      tag: 'unix:attested-' + this.counter, n: this.counter,
      pid: 0, uid: -1, gid: -1, pidfd: -1, procRoot: this.procRoot,
      visible: false, starttime: '', exeDev: 0, exeIno: 0,
      error: '', forced: ''
    };
    const fd = socket && socket._handle ? socket._handle.fd : undefined;
    if (typeof fd !== 'number' || fd < 0) {
      facts.error = 'the accepted socket exposes no file descriptor';
      this.log.debug("Leaving WorkloadAgent.observe(). No fd.");
      return facts;
    }
    try {
      const cred = this.native.peerCred(fd);
      facts.pid = Number(cred.pid);
      facts.uid = Number(cred.uid);
      facts.gid = Number(cred.gid);
      facts.pidfd = Number(this.native.peerPidfd(fd));
      if (facts.pidfd < 0 && facts.pid > 0) {
        facts.pidfd = Number(this.native.pidfdOpen(facts.pid));
      }
      if (facts.pid > 0) {
        facts.starttime = this.starttimeOf(facts.pid);
        const exe = this.exeOf(facts.pid);
        facts.exeDev = exe.dev;
        facts.exeIno = exe.ino;
        facts.visible = !!facts.starttime && facts.pidfd >= 0;
      }
    } catch (e) {
      // SO_PEERCRED or the pidfd failed. The facts carry the error and
      // accept closes the socket; observe itself does not throw.
      this.log.debug("Caught in WorkloadAgent.observe(): " +
                     ((e && e.message) || e));
      facts.error = 'SO_PEERCRED failed';
    }
    if (!facts.error) {
      this.peers.set(facts.n, facts);
      this.latest = facts;
    }
    this.log.debug("Leaving WorkloadAgent.observe(). " + facts.tag +
                   " uid=" + facts.uid);
    return facts;
  }

  /**
   * Closes the pidfd and drops the facts.
   *
   * @param facts - the connection's facts
   */
  forget(facts: any): void {
    this.log.debug("Entering WorkloadAgent.forget().");
    if (facts && facts.pidfd >= 0 && this.native) {
      try {
        this.native.closeFd(facts.pidfd);
      } catch (e) {
        // A pidfd that will not close must not stop the facts being
        // dropped. The descriptor is marked closed either way.
        this.log.debug("Caught in WorkloadAgent.forget(): " +
                       ((e && e.message) || e));
      }
      facts.pidfd = -1;
    }
    if (facts) {
      this.peers.delete(facts.n);
    }
    this.log.debug("Leaving WorkloadAgent.forget().");
  }

  /**
   * A process's start time, field 22 of /proc/pid/stat, counted from the
   * last ')' because the command may contain spaces.
   *
   * @param pid - the process id
   * @returns the start time, or ''
   */
  starttimeOf(pid: number): string {
    this.log.debug("Entering WorkloadAgent.starttimeOf(). pid=" + pid);
    try {
      const stat = fs.readFileSync(this.procRoot + '/' + pid + '/stat',
                                   'utf8');
      const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      this.log.debug("Leaving WorkloadAgent.starttimeOf().");
      return String(fields[19] || '');
    } catch (e) {
      // /proc's stat is unreadable: the process is gone, or not in this
      // pid namespace. An empty start time is the defined result.
      this.log.debug("Caught in WorkloadAgent.starttimeOf(): " +
                     ((e && e.message) || e));
      this.log.debug("Leaving WorkloadAgent.starttimeOf(). Unreadable.");
      return '';
    }
  }

  /**
   * The device and inode of a process's executable.
   *
   * @param pid - the process id
   * @returns the device and inode, or zeros
   */
  exeOf(pid: number): any {
    this.log.debug("Entering WorkloadAgent.exeOf(). pid=" + pid);
    try {
      const stat = fs.statSync(this.procRoot + '/' + pid + '/exe');
      this.log.debug("Leaving WorkloadAgent.exeOf().");
      return { dev: Number(stat.dev), ino: Number(stat.ino) };
    } catch (e) {
      // /proc's exe cannot be stat'd: the process is gone, or not in
      // this pid namespace. Zeros are the defined result.
      this.log.debug("Caught in WorkloadAgent.exeOf(): " +
                     ((e && e.message) || e));
      this.log.debug("Leaving WorkloadAgent.exeOf(). Unreadable.");
      return { dev: 0, ino: 0 };
    }
  }

  /**
   * Whether these facts still name the process that connected. '' when
   * they do. A peer that was never visible (another pid namespace) stays
   * valid: its identity is the uid and gid, which do not change.
   *
   * @param facts - the connection's facts
   * @returns '' or why not
   */
  stillValid(facts: any): string {
    this.log.debug("Entering WorkloadAgent.stillValid().");
    if (!facts) {
      this.log.debug("Leaving WorkloadAgent.stillValid(). None.");
      return 'no attested caller';
    }
    if (facts.forced) {
      this.log.debug("Leaving WorkloadAgent.stillValid(). Forced.");
      return String(facts.forced);
    }
    if (!facts.visible) {
      this.log.debug("Leaving WorkloadAgent.stillValid(). Not process-bound.");
      return '';
    }
    if (!this.native || !this.native.pidfdAlive(facts.pidfd)) {
      this.log.debug("Leaving WorkloadAgent.stillValid(). Gone.");
      return 'the process that connected has exited';
    }
    if (this.starttimeOf(facts.pid) !== facts.starttime) {
      this.log.debug("Leaving WorkloadAgent.stillValid(). Reused pid.");
      return 'the pid that connected now belongs to another process';
    }
    const exe = this.exeOf(facts.pid);
    if (exe.dev !== facts.exeDev || exe.ino !== facts.exeIno) {
      this.log.debug("Leaving WorkloadAgent.stillValid(). exec'd.");
      return 'the process that connected has since executed a different ' +
             'program';
    }
    this.log.debug("Leaving WorkloadAgent.stillValid().");
    return '';
  }

  /**
   * Marks a connection's facts as no longer the process that connected, so
   * the next call on that socket is refused. A test uses this; killing the
   * pidfd from outside is the same check against a live process.
   *
   * @param facts - the connection's facts
   */
  callerChanged(facts: any): void {
    this.log.debug("Entering WorkloadAgent.callerChanged().");
    if (facts) {
      facts.forced = 'the process that connected has exited';
    }
    this.log.debug("Leaving WorkloadAgent.callerChanged().");
  }

  /**
   * The facts of the connection accepted most recently, or null.
   *
   * @returns the facts
   */
  latestFacts(): any {
    this.log.debug("Entering WorkloadAgent.latestFacts().");
    this.log.debug("Leaving WorkloadAgent.latestFacts().");
    return this.latest || null;
  }

  /**
   * The selector texts for one connection's uid and gid.
   *
   * @param facts - the connection's facts
   * @returns the texts `unix:uid:…`
   */
  selectorsForFacts(facts: any): string[] {
    this.log.debug("Entering WorkloadAgent.selectorsForFacts().");
    const texts = WorkloadAgent.selectorsFor(facts.uid, facts.gid, {
      passwdPath: this.passwdPath, groupPath: this.groupPath
    }).map(function (selector) {
      return selector.type + ':' + selector.value;
    });
    this.log.debug("Leaving WorkloadAgent.selectorsForFacts().");
    return texts;
  }

  /**
   * The number in `unix:attested-<n>`, matched as a whole number. A prefix
   * would take 1 out of unix:attested-10.
   *
   * @param call - the gRPC call
   * @returns the id, or null
   */
  peerId(call: any): number | null {
    this.log.debug("Entering WorkloadAgent.peerId().");
    let peer = '';
    try {
      peer = String(call.getPeer());
    } catch (e) {
      // getPeer threw. An empty string matches no connection, and prepare
      // refuses the call rather than guessing which peer it was.
      this.log.debug("Caught in WorkloadAgent.peerId(): " +
                     ((e && e.message) || e));
    }
    const matched = /unix:attested-(\d+)/.exec(peer);
    this.log.debug("Leaving WorkloadAgent.peerId().");
    return matched ? Number(matched[1]) : null;
  }

  /**
   * Whether the call carries `workload.spiffe.io: true`.
   *
   * @param call - the gRPC call
   * @returns whether it does
   */
  securityHeaderPresent(call: any): boolean {
    this.log.debug("Entering WorkloadAgent.securityHeaderPresent().");
    const metadata = call && call.metadata;
    if (!metadata || typeof metadata.get !== 'function') {
      this.log.debug("Leaving WorkloadAgent.securityHeaderPresent(). None.");
      return false;
    }
    const values = metadata.get(SECURITY_HEADER) || [];
    for (let i = 0; i < values.length; i++) {
      if (String(values[i]).trim().toLowerCase() === 'true') {
        this.log.debug("Leaving WorkloadAgent.securityHeaderPresent().");
        return true;
      }
    }
    this.log.debug("Leaving WorkloadAgent.securityHeaderPresent(). No.");
    return false;
  }

  /**
   * The header, then the attested peer. The header wins, so a client that
   * forgot it is told about the header.
   *
   * @param call - the gRPC call
   * @param method - the method
   * @returns the caller, or a refusal
   */
  prepare(call: any, method: string): any {
    this.log.debug("Entering WorkloadAgent.prepare(). " + method);
    if (this.requireSecurityHeader &&
        !this.securityHeaderPresent(call)) {
      this.log.debug("Leaving WorkloadAgent.prepare(). No header.");
      return { ok: false, errorCode: 'STS-SPIFFE-0003',
               status: grpc.status.INVALID_ARGUMENT,
               message: 'Every call to the SPIFFE Workload API must ' +
                 'carry the metadata header "' + SECURITY_HEADER +
                 ': true" (SPIFFE Workload Endpoint specification). ' +
                 'This one did not.' };
    }
    const id = this.peerId(call);
    const facts = id == null ? null : this.peers.get(id);
    if (!facts) {
      this.log.debug("Leaving WorkloadAgent.prepare(). No caller.");
      return { ok: false, errorCode: 'STS-SPIFFE-0149',
               status: grpc.status.PERMISSION_DENIED,
               message: 'The Workload API caller no longer matches the ' +
                        'process that connected.' };
    }
    const why = this.stillValid(facts);
    if (why) {
      this.log.debug("Leaving WorkloadAgent.prepare(). " + why);
      return { ok: false, errorCode: 'STS-SPIFFE-0149',
               status: grpc.status.PERMISSION_DENIED,
               message: 'The Workload API caller no longer matches the ' +
                        'process that connected: ' + why + '.' };
    }
    this.log.debug("Leaving WorkloadAgent.prepare().");
    return { ok: true, facts: facts,
             selectors: this.selectorsForFacts(facts) };
  }

  /**
   * Ends a server stream with a status.
   *
   * @param call - the gRPC call
   * @param refusal - the error code, the status and the sentence
   */
  failStream(call: any, refusal: any): void {
    this.log.debug("Entering WorkloadAgent.failStream().");
    errorCodes.mark(call, refusal.errorCode);
    call.emit('error', { code: refusal.status, details: refusal.message });
    this.log.debug("Leaving WorkloadAgent.failStream().");
  }

  /**
   * Fails a unary call.
   *
   * @param call - the gRPC call
   * @param callback - grpc-js's callback
   * @param refusal - the error code, the status and the sentence
   */
  failUnary(call: any, callback: any, refusal: any): void {
    this.log.debug("Entering WorkloadAgent.failUnary().");
    errorCodes.mark(call, refusal.errorCode);
    const err: any = new Error(refusal.message);
    err.code = refusal.status;
    err.details = refusal.message;
    callback(err);
    this.log.debug("Leaving WorkloadAgent.failUnary().");
  }

  /**
   * Turns a thrown error into the refusal a handler reports.
   *
   * @param err - what was thrown
   * @returns the refusal
   */
  asRefusal(err: any): any {
    this.log.debug("Entering WorkloadAgent.asRefusal().");
    if (err && err.errorCode && typeof err.code === 'number') {
      this.log.debug("Leaving WorkloadAgent.asRefusal(). Status.");
      return { errorCode: err.errorCode, status: err.code,
               message: err.details || err.message };
    }
    this.log.debug("Leaving WorkloadAgent.asRefusal().");
    return { errorCode: 'STS-SPIFFE-0151',
             status: grpc.status.UNAVAILABLE,
             message: 'The workload agent could not obtain an SVID or a ' +
                      'bundle from the SPIRE Server API.' };
  }

  /**
   * The Workload API handlers, keyed by the proto's method names.
   *
   * @returns the handlers
   */
  handlers(): any {
    this.log.debug("Entering WorkloadAgent.handlers().");
    const self = this;
    this.log.debug("Leaving WorkloadAgent.handlers().");
    return {
      FetchX509SVID: function (call) { self.onFetchX509(call); },
      FetchX509Bundles: function (call) { self.onFetchX509Bundles(call); },
      FetchJWTSVID: function (call, callback) {
        self.onFetchJwt(call, callback);
      },
      FetchJWTBundles: function (call) { self.onFetchJwtBundles(call); },
      ValidateJWTSVID: function (call, callback) {
        self.onValidateJwt(call, callback);
      },
      FetchWITSVID: function (call) {
        self.onUnimplemented(call, 'FetchWITSVID');
      },
      FetchWITBundles: function (call) {
        self.onUnimplemented(call, 'FetchWITBundles');
      }
    };
  }

  /**
   * FetchX509SVID. The first message is written and the stream stays open.
   *
   * @param call - the gRPC call
   */
  onFetchX509(call: any): void {
    this.log.debug("Entering WorkloadAgent.onFetchX509().");
    const self = this;
    const open = { open: true, timer: null };
    call.on('cancelled', function () { self.drop(open); });
    const prepared = this.prepare(call, 'FetchX509SVID');
    if (!prepared.ok) {
      this.failStream(call, prepared);
      this.log.debug("Leaving WorkloadAgent.onFetchX509(). Refused.");
      return;
    }
    this.sendX509(call, open, prepared).then(function () {
      self.log.debug("Leaving WorkloadAgent.onFetchX509().");
    }, function (err) {
      // The first message could not be written. The caller gets the
      // refusal while the stream is still open.
      self.log.debug("Caught in WorkloadAgent.onFetchX509(): " +
                     ((err && err.message) || err));
      if (open.open) {
        self.failStream(call, self.asRefusal(err));
      }
      self.log.debug("Leaving WorkloadAgent.onFetchX509(). Failed.");
    });
  }

  /**
   * FetchX509Bundles. Stays open. A caller entitled to no SVID still
   * receives the bundles: the method is how a client validates.
   *
   * @param call - the gRPC call
   */
  onFetchX509Bundles(call: any): void {
    this.log.debug("Entering WorkloadAgent.onFetchX509Bundles().");
    const self = this;
    const open = { open: true, timer: null };
    call.on('cancelled', function () { self.drop(open); });
    const prepared = this.prepare(call, 'FetchX509Bundles');
    if (!prepared.ok) {
      this.failStream(call, prepared);
      this.log.debug("Leaving WorkloadAgent.onFetchX509Bundles(). Refused.");
      return;
    }
    this.sendBundles(call, open, 'x509').then(function () {
      self.log.debug("Leaving WorkloadAgent.onFetchX509Bundles().");
    }, function (err) {
      // The bundles could not be written. The caller gets the refusal
      // while the stream is still open.
      self.log.debug("Caught in WorkloadAgent.onFetchX509Bundles(): " +
                     ((err && err.message) || err));
      if (open.open) {
        self.failStream(call, self.asRefusal(err));
      }
      self.log.debug("Leaving WorkloadAgent.onFetchX509Bundles(). Failed.");
    });
  }

  /**
   * FetchJWTSVID.
   *
   * @param call - the gRPC call
   * @param callback - grpc-js's callback
   */
  onFetchJwt(call: any, callback: any): void {
    this.log.debug("Entering WorkloadAgent.onFetchJwt().");
    const self = this;
    const prepared = this.prepare(call, 'FetchJWTSVID');
    if (!prepared.ok) {
      this.failUnary(call, callback, prepared);
      this.log.debug("Leaving WorkloadAgent.onFetchJwt(). Refused.");
      return;
    }
    this.buildJwt(call.request || {}, prepared.selectors).then(
      function (value) {
        callback(null, value);
        self.log.debug("Leaving WorkloadAgent.onFetchJwt().");
      }, function (err) {
        // The JWT-SVID could not be built. The caller gets the refusal.
        self.log.debug("Caught in WorkloadAgent.onFetchJwt(): " +
                       ((err && err.message) || err));
        self.failUnary(call, callback, self.asRefusal(err));
        self.log.debug("Leaving WorkloadAgent.onFetchJwt(). Failed.");
      });
  }

  /**
   * FetchJWTBundles. Stays open.
   *
   * @param call - the gRPC call
   */
  onFetchJwtBundles(call: any): void {
    this.log.debug("Entering WorkloadAgent.onFetchJwtBundles().");
    const self = this;
    const open = { open: true, timer: null };
    call.on('cancelled', function () { self.drop(open); });
    const prepared = this.prepare(call, 'FetchJWTBundles');
    if (!prepared.ok) {
      this.failStream(call, prepared);
      this.log.debug("Leaving WorkloadAgent.onFetchJwtBundles(). Refused.");
      return;
    }
    this.sendBundles(call, open, 'jwt').then(function () {
      self.log.debug("Leaving WorkloadAgent.onFetchJwtBundles().");
    }, function (err) {
      // The bundles could not be written. The caller gets the refusal
      // while the stream is still open.
      self.log.debug("Caught in WorkloadAgent.onFetchJwtBundles(): " +
                     ((err && err.message) || err));
      if (open.open) {
        self.failStream(call, self.asRefusal(err));
      }
      self.log.debug("Leaving WorkloadAgent.onFetchJwtBundles(). Failed.");
    });
  }

  /**
   * ValidateJWTSVID.
   *
   * @param call - the gRPC call
   * @param callback - grpc-js's callback
   */
  onValidateJwt(call: any, callback: any): void {
    this.log.debug("Entering WorkloadAgent.onValidateJwt().");
    const self = this;
    const prepared = this.prepare(call, 'ValidateJWTSVID');
    if (!prepared.ok) {
      this.failUnary(call, callback, prepared);
      this.log.debug("Leaving WorkloadAgent.onValidateJwt(). Refused.");
      return;
    }
    this.buildValidate(call.request || {}).then(function (value) {
      callback(null, value);
      self.log.debug("Leaving WorkloadAgent.onValidateJwt().");
    }, function (err) {
      // The token could not be validated. The caller gets the refusal.
      self.log.debug("Caught in WorkloadAgent.onValidateJwt(): " +
                     ((err && err.message) || err));
      self.failUnary(call, callback, self.asRefusal(err));
      self.log.debug("Leaving WorkloadAgent.onValidateJwt(). Failed.");
    });
  }

  /**
   * FetchWITSVID and FetchWITBundles. Unimplemented, after the header.
   *
   * @param call - the gRPC call
   * @param method - the method
   */
  onUnimplemented(call: any, method: string): void {
    this.log.debug("Entering WorkloadAgent.onUnimplemented(). " + method);
    const prepared = this.prepare(call, method);
    if (!prepared.ok) {
      this.failStream(call, prepared);
      this.log.debug("Leaving WorkloadAgent.onUnimplemented(). Refused.");
      return;
    }
    errorCodes.mark(call, 'STS-SPIFFE-0029');
    call.emit('error', { code: grpc.status.UNIMPLEMENTED,
                         details: WIT_MESSAGE });
    this.log.debug("Leaving WorkloadAgent.onUnimplemented().");
  }

  /**
   * Stops one stream's rotation and forgets its timer.
   *
   * @param open - the stream's flag
   */
  drop(open: any): void {
    this.log.debug("Entering WorkloadAgent.drop().");
    open.open = false;
    if (open.timer) {
      clearTimeout(open.timer);
      this.timers.delete(open.timer);
      open.timer = null;
    }
    this.log.debug("Leaving WorkloadAgent.drop().");
  }

  /**
   * Writes the first X509 response and keeps the stream open.
   *
   * @param call - the gRPC call
   * @param open - the stream's flag
   * @param prepared - the caller
   */
  async sendX509(call: any, open: any, prepared: any): Promise<void> {
    this.log.debug("Entering WorkloadAgent.sendX509().");
    const built = await this.buildX509(prepared.selectors);
    if (!built.svids.length) {
      this.log.debug("Leaving WorkloadAgent.sendX509(). None.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0150',
        grpc.status.PERMISSION_DENIED,
        WorkloadAgent.notEntitled('FetchX509SVID', 'any X509-SVID'));
    }
    if (!open.open) {
      this.log.debug("Leaving WorkloadAgent.sendX509(). Closed.");
      return;
    }
    call.write({ svids: built.svids, crl: [],
                 federated_bundles: built.federated });
    const self = this;
    this.holdOpen(call, open, 'FetchX509SVID', function () {
      return self.nextX509(prepared);
    }, built.lifetime);
    this.log.debug("Leaving WorkloadAgent.sendX509().");
  }

  /**
   * The next X509 response, or a refusal when the caller is entitled to
   * nothing any more.
   *
   * @param prepared - the caller
   * @returns the message and the lifetime
   */
  async nextX509(prepared: any): Promise<any> {
    this.log.debug("Entering WorkloadAgent.nextX509().");
    const built = await this.buildX509(prepared.selectors);
    if (!built.svids.length) {
      this.log.debug("Leaving WorkloadAgent.nextX509(). None.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0150',
        grpc.status.PERMISSION_DENIED,
        WorkloadAgent.notEntitled('FetchX509SVID', 'any X509-SVID'));
    }
    this.log.debug("Leaving WorkloadAgent.nextX509().");
    return { body: { svids: built.svids, crl: [],
                     federated_bundles: built.federated },
             lifetime: built.lifetime };
  }

  /**
   * Writes the first bundle response and keeps the stream open.
   *
   * @param call - the gRPC call
   * @param open - the stream's flag
   * @param kind - `x509` or `jwt`
   */
  async sendBundles(call: any, open: any, kind: string): Promise<void> {
    this.log.debug("Entering WorkloadAgent.sendBundles(). " + kind);
    const body = await this.bundleResponse(kind);
    if (!open.open) {
      this.log.debug("Leaving WorkloadAgent.sendBundles(). Closed.");
      return;
    }
    call.write(body);
    const self = this;
    this.holdOpen(call, open, kind === 'jwt' ? 'FetchJWTBundles'
                                            : 'FetchX509Bundles',
                  function () {
      return self.bundleResponse(kind).then(function (next) {
        return { body: next, lifetime: 60 };
      });
    }, 60);
    this.log.debug("Leaving WorkloadAgent.sendBundles().");
  }

  /**
   * Re-sends a stream at half the lifetime, and again after that, while
   * the client is still there. Two functions, so the wait and the send
   * are not one function calling itself: this is the Workload API's own
   * rotation, per stream, in this process.
   *
   * @param call - the gRPC call
   * @param open - the stream's flag
   * @param label - what is being re-sent
   * @param build - the next message
   * @param lifetimeSeconds - the lifetime the last message carried
   */
  holdOpen(call: any, open: any, label: string, build: any,
           lifetimeSeconds: number): void {
    this.log.debug("Entering WorkloadAgent.holdOpen(). " + label);
    const self = this;
    let life = lifetimeSeconds;
    const handle = { timer: null };
    function arm() {
      self.log.debug("Entering arm().");
      if (!open.open || self.stopped) {
        self.log.debug("Leaving arm(). Stopped.");
        return;
      }
      const period = Math.max(1, Math.floor(
        ((Number(life) > 0 ? Number(life) : 60) / 2)));
      handle.timer = setTimeout(tick, period * 1000);
      if (handle.timer.unref) {
        handle.timer.unref();
      }
      open.timer = handle.timer;
      self.timers.add(handle.timer);
      self.log.debug("Leaving arm().");
    }
    function tick() {
      self.log.debug("Entering tick().");
      if (handle.timer) {
        self.timers.delete(handle.timer);
      }
      if (!open.open || self.stopped) {
        self.log.debug("Leaving tick(). Stopped.");
        return;
      }
      Promise.resolve().then(build).then(function (message: any) {
        if (!open.open || self.stopped || !message) {
          return;
        }
        try {
          call.write(message.body);
        } catch (e) {
          // The client has gone. The stream is closed and this rotation
          // does not arm again.
          self.log.debug("Caught in tick(): " + ((e && e.message) || e));
          open.open = false;
          return;
        }
        life = message.lifetime;
        arm();
      }).catch(function (err) {
        // A not-entitled caller ends the stream while any other failure
        // is retried on the next half-life.
        if (err && err.errorCode === 'STS-SPIFFE-0150') {
          self.log.debug("Caught in tick(): " +
                         ((err && err.message) || err));
          open.open = false;
          self.failStream(call, self.asRefusal(err));
          return;
        }
        self.log.debug("Caught in tick(): " +
                       ((err && err.message) || err));
        self.log.error(errorCodes.tag('STS-SPIFFE-0030') +
          'workload agent: could not re-send ' + label + '. ' +
          ((err && err.message) || err));
        if (open.open && !self.stopped) {
          arm();
        }
      });
      self.log.debug("Leaving tick().");
    }
    arm();
    this.log.debug("Leaving WorkloadAgent.holdOpen().");
  }

  /**
   * The entries this agent may issue, narrowed to the caller when
   * attestation is on.
   *
   * @param selectors - the caller's selector texts
   * @returns the entries
   */
  async entriesFor(selectors: string[]): Promise<any[]> {
    this.log.debug("Entering WorkloadAgent.entriesFor().");
    const rows = await this.authorizedEntries();
    if (!this.attestWorkloads) {
      this.log.debug("Leaving WorkloadAgent.entriesFor(). All.");
      return rows;
    }
    const matched = rows.filter(function (entry) {
      return WorkloadAgent.selectorsMatch(entry.selectors, selectors);
    });
    this.log.debug("Leaving WorkloadAgent.entriesFor(). " + matched.length);
    return matched;
  }

  /**
   * The entries the Server API says this agent may issue.
   *
   * @returns the entries
   */
  async authorizedEntries(): Promise<any[]> {
    this.log.debug("Entering WorkloadAgent.authorizedEntries().");
    let response = null;
    try {
      response = await this.callUnary(this.clients.entry,
                                     'GetAuthorizedEntries', {});
    } catch (e) {
      // The registration list could not be read. A refusal is thrown so
      // the caller sees STS-SPIFFE-0151, not the raw gRPC error.
      this.log.error(errorCodes.tag('STS-SPIFFE-0151') +
        'workload agent: GetAuthorizedEntries failed with gRPC status ' +
        (e && e.code) + '.');
      this.log.debug("Leaving WorkloadAgent.authorizedEntries(). Failed.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0151',
        grpc.status.UNAVAILABLE,
        'The workload agent could not read its registration entries ' +
        'from the SPIRE Server API.');
    }
    const rows = ((response && response.entries) || []).map(function (one) {
      return WorkloadAgent.entryFromProto(one);
    }).filter(function (entry) {
      return !!entry.spiffeId;
    });
    this.log.debug("Leaving WorkloadAgent.authorizedEntries(). " +
                   rows.length);
    return rows;
  }

  /**
   * Mints an X509-SVID for every entry the caller matches.
   *
   * @param selectors - the caller's selector texts
   * @returns the SVIDs, the federated bundles and the shortest lifetime
   */
  async buildX509(selectors: string[]): Promise<any> {
    this.log.debug("Entering WorkloadAgent.buildX509().");
    const entries = await this.entriesFor(selectors);
    if (!entries.length) {
      this.log.debug("Leaving WorkloadAgent.buildX509(). None.");
      return { svids: [], federated: {}, lifetime: 0 };
    }
    const made = [];
    for (let i = 0; i < entries.length; i++) {
      const key = await this.makeCsr('workload');
      made.push({ entry: entries[i], pkcs8: key.pkcs8, csr: key.csr });
    }
    let response = null;
    try {
      response = await this.callUnary(this.clients.svid, 'BatchNewX509SVID',
        { params: made.map(function (one) {
          return { entry_id: one.entry.id, csr: one.csr };
        }) });
    } catch (e) {
      // The Server API did not mint. A refusal is thrown so the caller
      // sees STS-SPIFFE-0151 rather than an empty chain.
      this.log.error(errorCodes.tag('STS-SPIFFE-0151') +
        'workload agent: BatchNewX509SVID failed with gRPC status ' +
        (e && e.code) + '.');
      this.log.debug("Leaving WorkloadAgent.buildX509(). Unreachable.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0151',
        grpc.status.UNAVAILABLE,
        'The workload agent could not obtain an X509-SVID from the ' +
        'SPIRE Server API.');
    }
    const own = await this.ownBundleDer();
    const svids = [];
    const federates = [];
    let shortest = 0;
    const now = Math.floor(Date.now() / 1000);
    const results = (response && response.results) || [];
    for (let i = 0; i < made.length; i++) {
      const result = results[i] || {};
      if (!WorkloadAgent.statusOk(result.status) || !result.svid ||
          !(result.svid.cert_chain && result.svid.cert_chain.length)) {
        this.log.error(errorCodes.tag('STS-SPIFFE-0151') +
          'workload agent: BatchNewX509SVID refused entry ' +
          made[i].entry.id + '.');
        continue;
      }
      const exp = Number(result.svid.expires_at || 0);
      const life = exp > now ? exp - now : 0;
      if (life > 0 && (shortest === 0 || life < shortest)) {
        shortest = life;
      }
      (made[i].entry.federatesWith || []).forEach(function (domain) {
        federates.push(domain);
      });
      svids.push({
        spiffe_id: made[i].entry.spiffeId,
        x509_svid: WorkloadAgent.concatDer(result.svid.cert_chain),
        x509_svid_key: made[i].pkcs8,
        bundle: own,
        hint: made[i].entry.hint || String(result.svid.hint || '')
      });
    }
    if (!svids.length) {
      this.log.debug("Leaving WorkloadAgent.buildX509(). No SVID.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0151',
        grpc.status.UNAVAILABLE,
        'The workload agent could not obtain an X509-SVID from the ' +
        'SPIRE Server API.');
    }
    const federated = await this.federatedBundles(federates, false);
    this.log.debug("Leaving WorkloadAgent.buildX509(). " + svids.length);
    return { svids: svids, federated: federated,
             lifetime: shortest || 60 };
  }

  /**
   * One bundle response. The trust domain's own bundle is written after
   * every federated one, so a federated document cannot replace it.
   *
   * @param kind - `x509` or `jwt`
   * @returns the response message
   */
  async bundleResponse(kind: string): Promise<any> {
    this.log.debug("Entering WorkloadAgent.bundleResponse(). " + kind);
    const jwt = kind === 'jwt';
    const bundles: any = {};
    let domains = [];
    try {
      const entries = await this.authorizedEntries();
      entries.forEach(function (entry) {
        (entry.federatesWith || []).forEach(function (domain) {
          domains.push(domain);
        });
      });
    } catch (e) {
      // The entries could not be listed. The answer still carries this
      // trust domain's own bundle, and names no federated domain.
      this.log.debug("Caught in WorkloadAgent.bundleResponse(): " +
                     ((e && e.message) || e));
      domains = [];
    }
    const federated = await this.federatedBundles(domains, jwt);
    Object.keys(federated).forEach(function (key) {
      bundles[key] = federated[key];
    });
    const ownKey = 'spiffe://' + this.trustDomain;
    bundles[ownKey] = jwt ? await this.jwtBundleBytes()
                          : await this.ownBundleDer();
    this.log.debug("Leaving WorkloadAgent.bundleResponse().");
    return jwt ? { bundles: bundles } : { crl: [], bundles: bundles };
  }

  /**
   * This trust domain's X.509 anchors, concatenated DER.
   *
   * @returns the DER
   */
  async ownBundleDer(): Promise<Buffer> {
    this.log.debug("Entering WorkloadAgent.ownBundleDer().");
    let response = null;
    try {
      response = await this.callUnary(this.clients.bundle, 'GetBundle', {});
    } catch (e) {
      // This trust domain's bundle could not be fetched. A refusal is
      // thrown so the caller sees STS-SPIFFE-0151, not an empty DER.
      this.log.error(errorCodes.tag('STS-SPIFFE-0151') +
        'workload agent: GetBundle failed with gRPC status ' +
        (e && e.code) + '.');
      this.log.debug("Leaving WorkloadAgent.ownBundleDer(). Failed.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0151',
        grpc.status.UNAVAILABLE,
        'The workload agent could not obtain the trust bundle from the ' +
        'SPIRE Server API.');
    }
    this.log.debug("Leaving WorkloadAgent.ownBundleDer().");
    return WorkloadAgent.x509FromProto(response);
  }

  /**
   * This trust domain's JWT authorities, as a JWK Set document.
   *
   * @returns the document's bytes
   */
  async jwtBundleBytes(): Promise<Buffer> {
    this.log.debug("Entering WorkloadAgent.jwtBundleBytes().");
    let response = null;
    try {
      response = await this.callUnary(this.clients.bundle, 'GetBundle', {});
    } catch (e) {
      // This trust domain's JWT bundle could not be fetched. A refusal
      // is thrown so the caller sees STS-SPIFFE-0151, not an empty set.
      this.log.error(errorCodes.tag('STS-SPIFFE-0151') +
        'workload agent: GetBundle failed with gRPC status ' +
        (e && e.code) + '.');
      this.log.debug("Leaving WorkloadAgent.jwtBundleBytes(). Failed.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0151',
        grpc.status.UNAVAILABLE,
        'The workload agent could not obtain the JWT bundle from the ' +
        'SPIRE Server API.');
    }
    const keys = WorkloadAgent.jwtKeysFromProto(response);
    this.log.debug("Leaving WorkloadAgent.jwtBundleBytes().");
    return Buffer.from(JSON.stringify({ keys: keys }), 'utf8');
  }

  /**
   * The X.509 anchors of a bundle message.
   *
   * @param proto - the bundle
   * @returns concatenated DER
   */
  static x509FromProto(proto: any): Buffer {
    log.debug("Entering WorkloadAgent.x509FromProto().");
    const ders = ((proto && proto.x509_authorities) || []).map(
      function (authority) {
        return authority && authority.asn1;
      });
    log.debug("Leaving WorkloadAgent.x509FromProto().");
    return WorkloadAgent.concatDer(ders);
  }

  /**
   * The JWT authorities of a bundle message, as JWKs with `use` and `kid`.
   *
   * @param proto - the bundle
   * @returns the JWKs
   */
  static jwtKeysFromProto(proto: any): any[] {
    log.debug("Entering WorkloadAgent.jwtKeysFromProto().");
    const keys = [];
    ((proto && proto.jwt_authorities) || []).forEach(function (authority) {
      const der = Buffer.from((authority && authority.public_key) || []);
      if (!der.length) {
        return;
      }
      try {
        const jwk: any = crypto.createPublicKey({
          key: der, format: 'der', type: 'spki'
        }).export({ format: 'jwk' });
        delete jwk.key_ops;
        delete jwk.ext;
        jwk.use = 'jwt-svid';
        jwk.kid = String((authority && authority.key_id) || '');
        keys.push(jwk);
      } catch (e) {
        // One authority's key will not import. It is skipped; the rest
        // of the bundle is still returned.
        log.debug("Caught in WorkloadAgent.jwtKeysFromProto(): " +
                  ((e && e.message) || e));
      }
    });
    log.debug("Leaving WorkloadAgent.jwtKeysFromProto().");
    return keys;
  }

  /**
   * Federated bundles named by registration entries. A denial is ignored:
   * one trust domain the server will not show must not empty the answer.
   * A key equal to this trust domain is skipped.
   *
   * @param domains - the trust domain names
   * @param jwt - JWT documents rather than X.509 DER
   * @returns the map keyed by `spiffe://<domain>`
   */
  async federatedBundles(domains: string[], jwt: boolean): Promise<any> {
    this.log.debug("Entering WorkloadAgent.federatedBundles().");
    const out = {};
    const own = 'spiffe://' + this.trustDomain;
    const seen = {};
    for (let i = 0; i < (domains || []).length; i++) {
      let name = String(domains[i] || '').trim();
      if (name.indexOf('spiffe://') === 0) {
        name = name.slice('spiffe://'.length).replace(/\/.*$/, '');
      }
      name = name.toLowerCase();
      if (!name || seen[name]) {
        continue;
      }
      seen[name] = true;
      const key = 'spiffe://' + name;
      if (key === own) {
        continue;
      }
      try {
        const bundle = await this.callUnary(this.clients.bundle,
          'GetFederatedBundle', { trust_domain: name });
        out[key] = jwt
          ? Buffer.from(JSON.stringify({
              keys: WorkloadAgent.jwtKeysFromProto(bundle) }), 'utf8')
          : WorkloadAgent.x509FromProto(bundle);
      } catch (e) {
        // A denial is ignored: one trust domain the server will not show
        // must not empty the answer.
        this.log.debug("Caught in WorkloadAgent.federatedBundles(): " +
                       "status " + (e && e.code));
      }
    }
    this.log.debug("Leaving WorkloadAgent.federatedBundles().");
    return out;
  }

  /**
   * FetchJWTSVID's answer.
   *
   * @param request - the request
   * @param selectors - the caller's selector texts
   * @returns the response
   */
  async buildJwt(request: any, selectors: string[]): Promise<any> {
    this.log.debug("Entering WorkloadAgent.buildJwt().");
    const audiences = (request.audience || []).map(function (one) {
      return String(one || '').trim();
    }).filter(Boolean);
    if (!audiences.length) {
      this.log.debug("Leaving WorkloadAgent.buildJwt(). No audience.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0027',
        grpc.status.INVALID_ARGUMENT,
        'FetchJWTSVID requires at least one audience. A JWT-SVID is a ' +
        'bearer credential, so the audience is what stops one issued for ' +
        'one service being replayed against another.');
    }
    const wanted = String(request.spiffe_id || '').trim();
    if (wanted) {
      const parsed = WorkloadAgent.parseSpiffeId(wanted);
      if (!parsed.ok) {
        this.log.debug("Leaving WorkloadAgent.buildJwt(). Bad id.");
        throw WorkloadAgent.refusal('STS-SPIFFE-0028',
          grpc.status.INVALID_ARGUMENT, 'spiffe_id: ' + parsed.reason);
      }
    }
    let entries = await this.entriesFor(selectors);
    if (wanted) {
      entries = entries.filter(function (entry) {
        return entry.spiffeId === wanted;
      });
    }
    if (!entries.length) {
      this.log.debug("Leaving WorkloadAgent.buildJwt(). None.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0150',
        grpc.status.PERMISSION_DENIED,
        WorkloadAgent.notEntitled('FetchJWTSVID',
                                 wanted || 'any JWT-SVID'));
    }
    const svids = [];
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      try {
        const minted = await this.callUnary(this.clients.svid, 'NewJWTSVID',
          { entry_id: entry.id, audience: audiences });
        if (minted && minted.svid && minted.svid.token) {
          svids.push({ spiffe_id: entry.spiffeId, svid: minted.svid.token,
                       hint: entry.hint ||
                             String(minted.svid.hint || '') });
        } else {
          this.log.error(errorCodes.tag('STS-SPIFFE-0151') +
            'workload agent: NewJWTSVID returned no token for entry ' +
            entry.id + '.');
        }
      } catch (e) {
        // One entry did not mint. The others are still asked; if none
        // do, the caller is refused after the loop.
        this.log.error(errorCodes.tag('STS-SPIFFE-0151') +
          'workload agent: NewJWTSVID failed for entry ' + entry.id +
          ' with gRPC status ' + (e && e.code) + '.');
      }
    }
    if (!svids.length) {
      this.log.debug("Leaving WorkloadAgent.buildJwt(). No token.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0151',
        grpc.status.UNAVAILABLE,
        'The workload agent could not obtain a JWT-SVID from the SPIRE ' +
        'Server API.');
    }
    this.log.debug("Leaving WorkloadAgent.buildJwt(). " + svids.length);
    return { svids: svids };
  }

  /**
   * ValidateJWTSVID's answer. The signature is checked here, with node,
   * against the bundle the Server API publishes.
   *
   * @param request - the request
   * @returns the SPIFFE ID and the claims
   */
  async buildValidate(request: any): Promise<any> {
    this.log.debug("Entering WorkloadAgent.buildValidate().");
    const token = String(request.svid == null ? '' : request.svid).trim();
    const audience = String(request.audience == null ? ''
                            : request.audience).trim();
    if (!token) {
      this.log.debug("Leaving WorkloadAgent.buildValidate(). No token.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0031',
        grpc.status.INVALID_ARGUMENT, 'No JWT-SVID was given.');
    }
    if (!audience) {
      this.log.debug("Leaving WorkloadAgent.buildValidate(). No audience.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0032',
        grpc.status.INVALID_ARGUMENT,
        'ValidateJWTSVID requires the audience the validating party ' +
        'goes by.');
    }
    const decoded = WorkloadAgent.decodeJwt(token);
    if (!decoded.ok) {
      this.log.debug("Leaving WorkloadAgent.buildValidate(). Not a JWT.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0033',
        grpc.status.INVALID_ARGUMENT, 'That is not a JWT.');
    }
    const parsed = WorkloadAgent.parseSpiffeId(
      String((decoded.payload || {}).sub || ''));
    if (!parsed.ok) {
      this.log.debug("Leaving WorkloadAgent.buildValidate(). Bad sub.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0034',
        grpc.status.INVALID_ARGUMENT,
        'The sub claim of a JWT-SVID is a SPIFFE ID; this one is not: ' +
        parsed.reason);
    }
    let keys = null;
    try {
      keys = await this.jwtKeysFor(parsed.trustDomain);
    } catch (e) {
      // This trust domain's own bundle could not be fetched. The caller
      // is refused STS-SPIFFE-0151 rather than told the token is bad.
      this.log.debug("Caught in WorkloadAgent.buildValidate(): status " +
                     (e && e.code));
      this.log.debug("Leaving WorkloadAgent.buildValidate(). Unreachable.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0151',
        grpc.status.UNAVAILABLE,
        'The workload agent could not obtain the JWT bundle from the ' +
        'SPIRE Server API.');
    }
    if (!keys) {
      this.log.debug("Leaving WorkloadAgent.buildValidate(). No bundle.");
      throw WorkloadAgent.refusal('STS-SPIFFE-0035',
        grpc.status.INVALID_ARGUMENT,
        'This agent holds no JWT bundle for the trust domain ' +
        parsed.trustDomain + '.');
    }
    const verified = WorkloadAgent.verifyJwt(decoded, audience, keys);
    if (!verified.ok) {
      this.log.debug("Leaving WorkloadAgent.buildValidate(). Refused.");
      throw WorkloadAgent.refusal(verified.errorCode,
        grpc.status.INVALID_ARGUMENT, verified.reason);
    }
    this.log.debug("Leaving WorkloadAgent.buildValidate().");
    return { spiffe_id: verified.spiffeId,
             claims: WorkloadAgent.structFrom(verified.claims) };
  }

  /**
   * The JWT keys of a trust domain. Null when this agent has no bundle
   * for it. A failure to reach this trust domain's own bundle is thrown.
   *
   * @param trustDomain - the trust domain
   * @returns the JWKs, or null
   */
  async jwtKeysFor(trustDomain: string): Promise<any[] | null> {
    this.log.debug("Entering WorkloadAgent.jwtKeysFor().");
    if (trustDomain === this.trustDomain) {
      const bundle = await this.callUnary(this.clients.bundle, 'GetBundle',
                                          {});
      this.log.debug("Leaving WorkloadAgent.jwtKeysFor(). Own.");
      return WorkloadAgent.jwtKeysFromProto(bundle);
    }
    try {
      const bundle = await this.callUnary(this.clients.bundle,
        'GetFederatedBundle', { trust_domain: trustDomain });
      this.log.debug("Leaving WorkloadAgent.jwtKeysFor(). Federated.");
      return WorkloadAgent.jwtKeysFromProto(bundle);
    } catch (e) {
      // A federated bundle the server will not show is no bundle, not an
      // outage. Null is what the caller reports as STS-SPIFFE-0035.
      this.log.debug("Caught in WorkloadAgent.jwtKeysFor(): status " +
                     (e && e.code));
      this.log.debug("Leaving WorkloadAgent.jwtKeysFor(). None.");
      return null;
    }
  }

  /**
   * Splits a compact JWS. The signing input is the two segments as they
   * were sent, not a re-encoding of the JSON.
   *
   * @param token - the compact JWS
   * @returns the header, the payload and the signing input, or not ok
   */
  static decodeJwt(token: string): any {
    log.debug("Entering WorkloadAgent.decodeJwt().");
    const parts = String(token || '').split('.');
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
      log.debug("Leaving WorkloadAgent.decodeJwt(). Shape.");
      return { ok: false };
    }
    try {
      const header = JSON.parse(
        WorkloadAgent.b64url(parts[0]).toString('utf8'));
      const payload = JSON.parse(
        WorkloadAgent.b64url(parts[1]).toString('utf8'));
      if (!header || typeof header !== 'object' ||
          !payload || typeof payload !== 'object' ||
          Array.isArray(payload)) {
        log.debug("Leaving WorkloadAgent.decodeJwt(). Not objects.");
        return { ok: false };
      }
      log.debug("Leaving WorkloadAgent.decodeJwt().");
      return { ok: true, header: header, payload: payload,
               signingInput: parts[0] + '.' + parts[1],
               signature: parts[2] };
    } catch (e) {
      // The segments are not base64url JSON. The caller refuses that as
      // not a JWT (STS-SPIFFE-0033).
      log.debug("Caught in WorkloadAgent.decodeJwt(): " +
                ((e && e.message) || e));
      log.debug("Leaving WorkloadAgent.decodeJwt(). Unreadable.");
      return { ok: false };
    }
  }

  /**
   * Verifies a decoded JWT-SVID: the signature, then the audience, then
   * the expiry. A failure of any of the three is STS-SPIFFE-0037.
   *
   * @param decoded - the decoded token
   * @param audience - the audience the caller claims
   * @param keys - the JWKs that may have signed it
   * @returns the result
   */
  static verifyJwt(decoded: any, audience: string, keys: any[]): any {
    log.debug("Entering WorkloadAgent.verifyJwt().");
    const kid = String((decoded.header && decoded.header.kid) || '');
    const usable = (keys || []).filter(function (key) {
      return !kid || key.kid === kid;
    });
    if (!usable.length) {
      log.debug("Leaving WorkloadAgent.verifyJwt(). No key.");
      return { ok: false, errorCode: 'STS-SPIFFE-0036',
               reason: 'No key in the bundle has the kid ' +
                       (kid || '(none)') + '.' };
    }
    const data = Buffer.from(decoded.signingInput, 'utf8');
    let sig: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    try {
      sig = WorkloadAgent.b64url(decoded.signature);
    } catch (e) {
      // The signature segment is not base64url. Verification then fails
      // as STS-SPIFFE-0037 rather than this decode throwing.
      log.debug("Caught in WorkloadAgent.verifyJwt(): " +
                ((e && e.message) || e));
    }
    const alg = String((decoded.header && decoded.header.alg) || '');
    let verified = false;
    for (let i = 0; i < usable.length && !verified; i++) {
      try {
        verified = WorkloadAgent.signatureOk(alg, data, sig, usable[i]);
      } catch (e) {
        // This key could not be used (a bad JWK, or the wrong algorithm).
        // The next key is tried; none verifying is STS-SPIFFE-0037.
        log.debug("Caught in WorkloadAgent.verifyJwt(): " +
                  ((e && e.message) || e));
      }
    }
    if (!verified) {
      log.debug("Leaving WorkloadAgent.verifyJwt(). Signature.");
      return { ok: false, errorCode: 'STS-SPIFFE-0037',
               reason: 'The SVID did not verify.' };
    }
    const aud = decoded.payload.aud;
    const list = Array.isArray(aud) ? aud.map(String) : [String(aud || '')];
    if (list.indexOf(audience) < 0) {
      log.debug("Leaving WorkloadAgent.verifyJwt(). Audience.");
      return { ok: false, errorCode: 'STS-SPIFFE-0037',
               reason: 'The SVID is not for the audience ' + audience + '.' };
    }
    const exp = Number(decoded.payload.exp);
    if (!Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) {
      log.debug("Leaving WorkloadAgent.verifyJwt(). Expired.");
      return { ok: false, errorCode: 'STS-SPIFFE-0037',
               reason: 'The SVID has expired.' };
    }
    log.debug("Leaving WorkloadAgent.verifyJwt().");
    return { ok: true, spiffeId: String(decoded.payload.sub || ''),
             claims: decoded.payload };
  }

  /**
   * Verifies one JWS signature with node. ES uses IEEE-P1363, PS uses PSS,
   * EdDSA uses the key's own algorithm.
   *
   * @param alg - the JWS alg
   * @param data - the signing input
   * @param sig - the signature
   * @param jwk - the key, which may still carry use and kid
   * @returns whether it verified
   */
  static signatureOk(alg: string, data: Buffer, sig: Buffer,
                     jwk: any): boolean {
    log.debug("Entering WorkloadAgent.signatureOk().");
    const bare: any = Object.assign({}, jwk);
    delete bare.use;
    delete bare.kid;
    delete bare.key_ops;
    delete bare.ext;
    const key = crypto.createPublicKey({ key: bare, format: 'jwk' });
    if (alg === 'EdDSA') {
      log.debug("Leaving WorkloadAgent.signatureOk(). EdDSA.");
      return crypto.verify(null, data, key, sig);
    }
    const ec = { ES256: 'sha256', ES384: 'sha384', ES512: 'sha512' };
    if (ec[alg]) {
      log.debug("Leaving WorkloadAgent.signatureOk(). EC.");
      return crypto.verify(ec[alg], data,
        { key: key, dsaEncoding: 'ieee-p1363' }, sig);
    }
    const rs = { RS256: 'RSA-SHA256', RS384: 'RSA-SHA384',
                 RS512: 'RSA-SHA512' };
    if (rs[alg]) {
      log.debug("Leaving WorkloadAgent.signatureOk(). RSA.");
      return crypto.verify(rs[alg], data, key, sig);
    }
    const ps = { PS256: 'sha256', PS384: 'sha384', PS512: 'sha512' };
    if (ps[alg]) {
      log.debug("Leaving WorkloadAgent.signatureOk(). PSS.");
      return crypto.verify('RSA-' + ps[alg].toUpperCase(), data, {
        key: key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.createHash(ps[alg]).digest().length
      }, sig);
    }
    log.debug("Leaving WorkloadAgent.signatureOk(). Unknown.");
    return false;
  }

  /**
   * Attests, then serves. The native module is loaded before any socket
   * exists. A failure throws an Error whose `code` is STS-SPIFFE-0148.
   */
  async start(): Promise<void> {
    this.log.debug("Entering WorkloadAgent.start().");
    if (this.started) {
      this.log.debug("Leaving WorkloadAgent.start(). Already.");
      return;
    }
    try {
      this.loadNative();
      if (!this.server || !this.socketPath || !this.trustDomain ||
          !this.joinToken) {
        throw WorkloadAgent.fail('STS-SPIFFE-0148',
          'The workload agent needs a server, a socket, a trust domain ' +
          'and a join token.');
      }
      await this.loadAnchors();
      WorkloadAgent.ensurePkijs();
      this.loadServices();
      const made = await this.makeCsr('agent');
      const svid = await this.attest(made.csr);
      const agentId = WorkloadAgent.idFromProto(svid.id);
      if (!agentId) {
        throw WorkloadAgent.fail('STS-SPIFFE-0148',
          'AttestAgent returned no agent SPIFFE ID.');
      }
      this.agentSpiffeId = agentId;
      const exported = crypto.createPrivateKey({
        key: made.pkcs8, format: 'der', type: 'pkcs8'
      }).export({ type: 'pkcs8', format: 'pem' });
      this.agentKeyPem = typeof exported === 'string' ? exported
        : exported.toString('utf8');
      this.agentCertPem = WorkloadAgent.certsToPem(svid.cert_chain);
      this.openClients();
      await this.bindSocket();
      this.started = true;
      this.log.info('workload agent ' + this.agentSpiffeId +
                    ' serving ' + this.socketPath);
      this.log.debug("Leaving WorkloadAgent.start().");
    } catch (e) {
      // Start did not finish. stop() drops a socket already bound, and
      // the error is rethrown so the process does not claim to be serving.
      this.log.debug("Caught in WorkloadAgent.start(): " +
                     ((e && e.message) || e));
      this.stop();
      if (e && !e.code) {
        e.code = 'STS-SPIFFE-0148';
      }
      this.log.debug("Leaving WorkloadAgent.start(). Failed.");
      throw e;
    }
  }

  /**
   * Closes the socket, the clients and every pidfd. Safe to call twice,
   * and safe to call when start did not finish.
   */
  stop(): void {
    this.log.debug("Entering WorkloadAgent.stop().");
    if (this.stopped) {
      this.log.debug("Leaving WorkloadAgent.stop(). Already.");
      return;
    }
    this.stopped = true;
    this.started = false;
    this.timers.forEach(function (timer) { clearTimeout(timer); });
    this.timers.clear();
    const self = this;
    this.peers.forEach(function (facts) { self.forget(facts); });
    if (this.injector) {
      try {
        this.injector.destroy();
      } catch (e) {
        // Cleanup must not hide the original error. destroy() throwing
        // is logged and the rest of stop() still runs.
        this.log.debug("Caught in WorkloadAgent.stop(): " +
                       ((e && e.message) || e));
      }
      this.injector = null;
    }
    if (this.listener) {
      try {
        this.listener.close();
      } catch (e) {
        // Cleanup must not hide the original error. A listener that will
        // not close is logged and the rest of stop() still runs.
        this.log.debug("Caught in WorkloadAgent.stop(): " +
                       ((e && e.message) || e));
      }
      this.listener = null;
    }
    if (this.grpcServer) {
      try {
        this.grpcServer.forceShutdown();
      } catch (e) {
        // Cleanup must not hide the original error. A server that will
        // not shut down is logged and the rest of stop() still runs.
        this.log.debug("Caught in WorkloadAgent.stop(): " +
                       ((e && e.message) || e));
      }
      this.grpcServer = null;
    }
    if (this.socketPath) {
      try {
        fs.unlinkSync(this.socketPath);
      } catch (e) {
        // A missing socket is the state shutdown wanted.
        this.log.debug("Caught in WorkloadAgent.stop(): " +
                       ((e && e.message) || e));
      }
    }
    if (this.clients) {
      ['entry', 'bundle', 'svid'].forEach(function (name) {
        try {
          if (self.clients[name]) {
            self.clients[name].close();
          }
        } catch (e) {
          // Cleanup must not hide the original error. A client that will
          // not close is logged and the other clients are still closed.
          self.log.debug("Caught in WorkloadAgent.stop(): " +
                         ((e && e.message) || e));
        }
      });
      this.clients = null;
    }
    this.log.debug("Leaving WorkloadAgent.stop().");
  }

  /**
   * Reads argv. A `--join-token` flag is refused and its value is not
   * repeated. The token comes from the environment or from a file.
   *
   * @param argv - the arguments after the program name
   * @returns `{ ok, message }` or `{ ok, opts }`
   */
  static readArgs(argv: string[]): any {
    log.debug("Entering WorkloadAgent.readArgs().");
    for (let i = 0; i < argv.length; i++) {
      const arg = String(argv[i] || '');
      if (arg === '--join-token' || arg.indexOf('--join-token=') === 0) {
        log.debug("Leaving WorkloadAgent.readArgs(). Refused.");
        return { ok: false, message:
          'A join token is not accepted on the command line. Set ' +
          'STS_SPIFFE_JOIN_TOKEN or pass --join-token-file.' };
      }
    }
    const map: any = {};
    const known = ['server', 'socket', 'trust-domain', 'bundle-url',
                   'trust-bundle-file', 'require-security-header',
                   'attest-workloads', 'join-token-file', 'native'];
    for (let i = 0; i < argv.length; i++) {
      const arg = String(argv[i] || '');
      if (arg.indexOf('--') !== 0) {
        log.debug("Leaving WorkloadAgent.readArgs(). Unexpected.");
        return { ok: false, message: 'Unexpected argument.' };
      }
      const eq = arg.indexOf('=');
      const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
      let value = eq === -1 ? '' : arg.slice(eq + 1);
      if (known.indexOf(name) < 0) {
        log.debug("Leaving WorkloadAgent.readArgs(). Unknown.");
        return { ok: false, message: 'Unknown option --' + name + '.' };
      }
      if (eq === -1) {
        const next = argv[i + 1];
        if (next != null && String(next).indexOf('--') !== 0) {
          value = String(next);
          i++;
        } else {
          value = 'true';
        }
      }
      map[name] = value;
    }
    let token = '';
    if (map['join-token-file']) {
      try {
        token = fs.readFileSync(map['join-token-file'], 'utf8').trim();
      } catch (e) {
        // The join-token file could not be read. A fixed refusal is
        // returned, and the token itself is never what the message carries.
        log.debug("Caught in WorkloadAgent.readArgs(): " +
                  ((e && e.message) || e));
        log.debug("Leaving WorkloadAgent.readArgs(). File.");
        return { ok: false, message:
          'The join-token file could not be read.' };
      }
    } else {
      token = String(process.env.STS_SPIFFE_JOIN_TOKEN || '').trim();
    }
    if (!token) {
      log.debug("Leaving WorkloadAgent.readArgs(). No token.");
      return { ok: false, message:
        'Set STS_SPIFFE_JOIN_TOKEN or pass --join-token-file. The token ' +
        'is not accepted as an argument.' };
    }
    let pem = '';
    if (map['trust-bundle-file']) {
      try {
        pem = fs.readFileSync(map['trust-bundle-file'], 'utf8');
      } catch (e) {
        // The trust-bundle file could not be read. A fixed refusal is
        // returned rather than starting the agent with no anchors.
        log.debug("Caught in WorkloadAgent.readArgs(): " +
                  ((e && e.message) || e));
        log.debug("Leaving WorkloadAgent.readArgs(). Bundle file.");
        return { ok: false, message:
          'The trust-bundle file could not be read.' };
      }
    }
    if (!map.server || !map.socket || !map['trust-domain'] ||
        (!pem && !map['bundle-url'])) {
      log.debug("Leaving WorkloadAgent.readArgs(). Incomplete.");
      return { ok: false, message:
        'Required: --server, --socket, --trust-domain, and --bundle-url ' +
        'or --trust-bundle-file.' };
    }
    log.debug("Leaving WorkloadAgent.readArgs().");
    return { ok: true, opts: {
      server: map.server,
      socketPath: map.socket,
      trustDomain: map['trust-domain'],
      joinToken: token,
      trustBundlePem: pem,
      bundleUrl: map['bundle-url'] || '',
      requireSecurityHeader: WorkloadAgent.flag(
        map['require-security-header']),
      attestWorkloads: WorkloadAgent.flag(map['attest-workloads']),
      nativePath: map.native || ''
    } };
  }

  /**
   * Reads a boolean flag. Absent means on, which is the default for both
   * checks.
   *
   * @param value - the text, or undefined
   * @returns the boolean
   */
  static flag(value: any): boolean {
    log.debug("Entering WorkloadAgent.flag().");
    if (value == null || String(value).trim() === '') {
      log.debug("Leaving WorkloadAgent.flag(). Default.");
      return true;
    }
    const text = String(value).trim().toLowerCase();
    log.debug("Leaving WorkloadAgent.flag().");
    return text !== 'false' && text !== '0' && text !== 'no' &&
           text !== 'off';
  }

  /**
   * The process entry. Loads nothing of the service and binds nothing
   * until start().
   */
  static main(): void {
    log.debug("Entering WorkloadAgent.main().");
    const read = WorkloadAgent.readArgs(process.argv.slice(2));
    if (!read.ok) {
      process.stderr.write(read.message + '\n');
      log.debug("Leaving WorkloadAgent.main(). Refused.");
      process.exit(1);
    }
    const agent = new WorkloadAgent(read.opts);
    const shutdown = function () {
      log.debug("Entering shutdown().");
      agent.stop();
      log.debug("Leaving shutdown().");
      process.exit(0);
    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    agent.start().then(function () {
      log.debug("Leaving WorkloadAgent.main().");
    }, function (err) {
      // start() failed before the socket was serving. The code is
      // recorded and the process exits; nothing is left listening.
      log.debug("Caught in WorkloadAgent.main(): " +
                ((err && err.message) || err));
      log.error(errorCodes.tag(err && err.code ? err.code
                                              : 'STS-SPIFFE-0148') +
                ((err && err.message) || err));
      log.debug("Leaving WorkloadAgent.main(). Failed.");
      process.exit(1);
    });
  }
}

if (require.main === module) {
  WorkloadAgent.main();
}

export = WorkloadAgent;
