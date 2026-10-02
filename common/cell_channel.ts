// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cell_channel.ts
//
// ---------------------------------------------------------------------------
// THE CHANNEL BETWEEN CELLS (#98, 2026-09-28).
//
// A service deployed as cells (`cells.ts`) talks to itself across regions for
// three things, and this module is the only way it does:
//
//   * **A RELAYED REQUEST.** A request that reached one cell and belongs to
//     another — a browser pinned to its home cell, an artifact another cell
//     minted, a token whose subject is homed elsewhere (`cell_placement.ts`)
//     — is sent WHOLE to the cell that owns it and answered from there, the
//     bytes piped back. The receiving cell serves it through the same express
//     app as its public port, as the request the client sent.
//   * **AN OPERATION.** A JSON call a module registers (`registerOp()`): a
//     subject's state asked of its home, a revocation pushed to every cell, a
//     session exported to the cell that will hold it.
//   * **NOTHING ELSE.** There is no third kind, and no path on this listener
//     answers a request that did not come from a peer cell.
//
// **MUTUAL TLS, TLS 1.3, AND A PEER IS A CELL ONLY BY ITS CERTIFICATE.** Every
// node presents a leaf from the process branch's `cell` Issuing CA
// (`common/pki.js`), in both roles, naming its cell in a `urn:sts:cell:<id>`
// subjectAltName. A connection is accepted only when its chain verifies to
// the service Root AND its issuer is that CA AND the named cell is one of
// `cells.peers` — "chains to the service Root" alone is true of a person's
// TLS client certificate, and is not a statement that the peer is a cell.
// The leaves are short-lived and never recorded (`pki.issueUnder()`), re-
// minted by each process on a scheduler job, the arrangement an X509-SVID has.
//
// **WHAT A RELAYED REQUEST CARRIES ABOUT ITS CLIENT**, and why the receiving
// side may believe it: the client's address, its TLS client certificate (as
// the front process hands one to a request worker — `request_pool.peerOf()`)
// and the hop count, in `x-sts-cell-*` headers that the SENDING side strips
// from what the client sent and the RECEIVING side reads only from an
// authenticated peer. On the receiving side the socket is shimmed exactly as
// a request worker's is, so `getPeerCertificate()` answers with the CLIENT's
// certificate — or with nothing — and never with the peer cell's leaf, which
// would otherwise be a certificate every mTLS door here would read as the
// caller's.
//
// **AND THE HOST IT ADDRESSED, IN THE HOST HEADER** (2026-09-28): the peer is
// DIALLED by its private name — the TLS server name its leaf is checked
// against — but the Host header is the host the client addressed, so a
// signature over `@authority` or `@target-uri`, a DPoP `htu` and every
// address the owning cell builds come out as they would have at the cell the
// client reached. `relay()` argues why that widens nothing the owning cell
// trusts.
//
// **ONE HOP.** A relayed request is never relayed again: a cell that is asked
// to serve something it does not own answers it as best it can rather than
// sending it on, because two cells that each believe the other owns a request
// would pass it between them until the timeout.
//
// A LIBRARY: it registers no route on the public app. `server.js` binds the
// listener from `listen()`, in the front process only; any process may DIAL.
// ---------------------------------------------------------------------------

import https = require('https');
import tls = require('tls');
import dns = require('dns');
import nodeCrypto = require('crypto');
import bunyan = require('bunyan');
import config = require('./config');
import errorCodes = require('./error_codes');
import cells = require('./cells');

const log = bunyan.createLogger({ name: 'sts-cell-channel' });

// The operations live under this path on the inter-cell listener, and only
// there: the public app has no such route and a public request for it is
// answered 404 like any other unrouted path.
const OP_PREFIX = '/_cell/v1/';
// The URI subjectAltName every inter-cell leaf carries.
const CELL_URN_PREFIX = 'urn:sts:cell:';
// How long a leaf lives, and when a process re-mints its own: at half-life,
// asked by the scheduler job below every CHECK_MS.
const LEAF_LIFETIME_MS = 24 * 60 * 60 * 1000;
const CHECK_MS = 60 * 60 * 1000;
// The largest JSON body an operation takes or returns. Operations carry a
// session, a subject's state, a page of directory entries — never a bulk.
const MAX_OP_BYTES = 1024 * 1024;

// The internal headers of a relayed request. The sending side removes every
// one of them from what the client sent before adding its own.
const H_FROM = 'x-sts-cell-from';
const H_CLIENT = 'x-sts-cell-client';
const H_HOPS = 'x-sts-cell-hops';
const H_REASON = 'x-sts-cell-reason';
const H_PEER_CERT = 'x-sts-peer-certificate';
const H_PEER_AUTHORIZED = 'x-sts-peer-authorized';
const H_CLIENT_HELLO = 'x-sts-tls-client-hello';
const INTERNAL_HEADERS = [H_FROM, H_CLIENT, H_HOPS, H_REASON, H_PEER_CERT,
                          H_PEER_AUTHORIZED, H_CLIENT_HELLO];
// The forwarding headers a client may have sent. A relay replaces them with
// what the sending cell understood (relay()), so they are never copied.
const FORWARDING_HEADERS = ['forwarded', 'x-forwarded-for', 'x-forwarded-host',
                            'x-forwarded-proto', 'x-forwarded-port'];
// Hop-by-hop headers (RFC 9110 section 7.6.1), never forwarded.
const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-connection',
                    'transfer-encoding', 'te', 'trailer', 'upgrade',
                    'proxy-authorization', 'proxy-authenticate'];

/**
 * A node's own inter-cell credential: its key, its leaf and the chain above
 * it (Root excluded), and when the leaf expires.
 */
interface Leaf {
  keyPem: string;
  certPem: string;
  chainPem: string[];
  notAfterMs: number;
  mintedAt: number;
}

/**
 * What an operation handler is told about the call: the calling cell.
 */
interface OpContext {
  peer: string;
}

type OpHandler = (body: any, ctx: OpContext) => Promise<any> | any;

// What `status()` counts.
interface Counters {
  relayedOut: number;
  relayedIn: number;
  opsOut: number;
  opsIn: number;
  refusedPeers: number;
  failures: number;
}

/**
 * The channel between the cells of one service: its listener, its client,
 * the operations modules register, and the relay of a whole request.
 */
class CellChannel {
  private leaf: Leaf | null = null;
  private minting: Promise<Leaf> | null = null;
  private server: any = null;
  private unregisterPolicy: (() => void) | null = null;
  private listening = false;
  private listenError = '';
  private boundPort = 0;
  private readonly ops = new Map<string, OpHandler>();
  private readonly counters: Counters = { relayedOut: 0, relayedIn: 0,
                                          opsOut: 0, opsIn: 0,
                                          refusedPeers: 0, failures: 0 };
  private lastFailure = '';
  private jobRegistered = false;

  /**
   * Builds the channel. It holds nothing until a leaf is first needed.
   */
  constructor() {
    log.debug("Entering CellChannel.constructor().");
    log.debug("Leaving CellChannel.constructor().");
  }

  // -------------------------------------------------------------------------
  // THE LEAF. Minted over a key made here, by `pki.issueUnder()` from the
  // process branch's `cell` Issuing CA, which `ensureScope()` adds to a
  // branch built before the use case existed. Required LAZILY: `pki.js`
  // loads the keystore, and this module is reached from `app.js` (#2) by the
  // placement middleware, long before either may be loaded.
  // -------------------------------------------------------------------------
  private async mintLeaf(): Promise<Leaf> {
    log.debug("Entering CellChannel.mintLeaf().");
    const pki = require('./pki');
    const scoped = await pki.ensureScope(pki.PROCESS_SCOPE);
    if (scoped && scoped.ok === false) {
      log.debug("Leaving CellChannel.mintLeaf(). No process branch.");
      throw new Error(errorCodes.tag('STS-CELL-0031') + 'the process ' +
                      'branch of the certificate authority could not be ' +
                      'built, so no inter-cell certificate can be issued: ' +
                      (scoped.errors || []).join(' '));
    }
    const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const publicKeyPem = pair.publicKey.export({ type: 'spki',
                                                 format: 'pem' }).toString();
    const keyPem = pair.privateKey.export({ type: 'pkcs8',
                                            format: 'pem' }).toString();
    const id = cells.id();
    const host = cells.hostname() || require('os').hostname().toLowerCase();
    const now = Date.now();
    const issued = await pki.issueUnder(pki.PROCESS_SCOPE, 'cell', {
      publicKeyPem: publicKeyPem,
      // `CN`, the encoder's own name for the attribute (common/vendored/
      // x509.js, DN_ATTRS). It read `commonName` until the `cells` mode's
      // first run (2026-09-28), which the encoder refuses — "Unknown DN
      // attribute" — so no cell ever held a leaf and every peer answered
      // unreachable (STS-CELL-0031); tests/vendored/sts_cells_map.js.
      subject: [{ name: 'CN', value: 'cell ' + id + ' ' + host }],
      profile: 'tls-server',
      notBefore: now - 60 * 1000,
      notAfter: now + LEAF_LIFETIME_MS,
      extensions: {
        keyUsage: { present: true, critical: true,
                    usages: ['digitalSignature'] },
        extKeyUsage: { present: true, critical: false,
                       usages: ['serverAuth', 'clientAuth'] },
        subjectAltName: { present: true, critical: false, names: [
          { kind: 'dns', value: host },
          { kind: 'uri', value: CELL_URN_PREFIX + id }
        ] }
      }
    });
    if (!issued || !issued.ok) {
      log.debug("Leaving CellChannel.mintLeaf(). Refused.");
      throw new Error(errorCodes.tag('STS-CELL-0031') + 'the inter-cell ' +
                      'certificate could not be issued: ' +
                      ((issued && issued.errors) || []).join(' '));
    }
    const leaf: Leaf = {
      keyPem: keyPem,
      certPem: issued.certificatePem,
      chainPem: issued.issuerChainPem,
      notAfterMs: new Date(issued.notAfter).getTime(),
      mintedAt: now
    };
    log.info('cells: this process holds an inter-cell certificate for cell ' +
             '"' + id + '" as ' + host + ', until ' + issued.notAfter + '.');
    log.debug("Leaving CellChannel.mintLeaf().");
    return leaf;
  }

  /**
   * Returns this process's inter-cell credential, minting it when there is
   * none or the one held is past half its life.
   *
   * @returns a promise of the leaf
   */
  async ensureLeaf(): Promise<Leaf> {
    log.debug("Entering CellChannel.ensureLeaf().");
    const now = Date.now();
    if (this.leaf && now < this.leaf.mintedAt +
        (this.leaf.notAfterMs - this.leaf.mintedAt) / 2) {
      log.debug("Leaving CellChannel.ensureLeaf(). Held.");
      return this.leaf;
    }
    if (!this.minting) {
      const self = this;
      this.minting = this.mintLeaf().then(function (made) {
        self.leaf = made;
        self.minting = null;
        if (self.server && typeof self.server.setSecureContext ===
            'function') {
          self.server.setSecureContext(self.serverContextOptions(made));
        }
        return made;
      }, function (err) {
        self.minting = null;
        throw err;
      });
    }
    log.debug("Leaving CellChannel.ensureLeaf(). Minting.");
    return this.minting;
  }

  // The service Root, the one anchor either side verifies the other against.
  private rootPem(): string {
    log.debug("Entering CellChannel.rootPem().");
    const pki = require('./pki');
    const root = pki.serviceRoot();
    log.debug("Leaving CellChannel.rootPem().");
    return root && root.certificatePem ? String(root.certificatePem) : '';
  }

  // The `cell` Issuing CA's certificate, as DER: a peer's leaf must be
  // issued by exactly this.
  private cellCaDer(): Buffer | null {
    log.debug("Entering CellChannel.cellCaDer().");
    const pki = require('./pki');
    const row = pki.rawRowFor(pki.PROCESS_SCOPE);
    const ca = row && row.issuing ? row.issuing.cell : null;
    if (!ca || !ca.certificatePem) {
      log.debug("Leaving CellChannel.cellCaDer(). None.");
      return null;
    }
    const b64 = String(ca.certificatePem)
      .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
    log.debug("Leaving CellChannel.cellCaDer().");
    return Buffer.from(b64, 'base64');
  }

  // THE LISTENERS' POLICY (#423): the TLS 1.3 suites chosen, the groups (only
  // the ML-KEM ones under tls.pqcOnly) and the signature algorithms, as every
  // listener takes them — always TLS 1.3, whatever tls.disableTls12 says,
  // because this channel never spoke anything else. Its client
  // authentication is the protocol's (a cell's certificate, always
  // required), so it has no toggle. Required lazily: `tls/tls_server.js` is a
  // JavaScript route module, and a require from here would move its routes.
  private serverContextOptions(leaf: Leaf): tls.SecureContextOptions {
    log.debug("Entering CellChannel.serverContextOptions().");
    const tlsServer = require('../tls/tls_server');
    const policy = Object.assign({},
      tlsServer.protocolOptions(tlsServer.policyFor('cell')),
      { minVersion: 'TLSv1.3' });
    log.debug("Leaving CellChannel.serverContextOptions().");
    return Object.assign(policy, {
      key: leaf.keyPem,
      cert: [leaf.certPem].concat(leaf.chainPem).join('\n'),
      ca: [this.rootPem()]
    });
  }

  // -------------------------------------------------------------------------
  // WHO IS ON THE OTHER END. `authorized` is OpenSSL's verdict on the chain
  // against the Root; the rest is what makes the chain a CELL's: issued by
  // the `cell` authority, naming one cell, and that cell one of the peers.
  // Answers the cell id, or '' with the reason recorded.
  // -------------------------------------------------------------------------
  /**
   * Decides which cell a TLS socket's peer is.
   *
   * @param socket - the TLS socket
   * @param expected - the cell the caller dialled, or '' on the listener
   * @returns the peer's cell id, or '' when it is not a cell of this service
   */
  peerCellOf(socket: any, expected: string): string {
    log.debug("Entering CellChannel.peerCellOf().");
    const refuse = (why: string): string => {
      this.counters.refusedPeers += 1;
      this.lastFailure = why;
      log.warn(errorCodes.tag('STS-CELL-0032') + 'cells: an inter-cell ' +
               'peer was refused: ' + why);
      return '';
    };
    if (!socket || !socket.authorized) {
      log.debug("Leaving CellChannel.peerCellOf(). Not authorized.");
      return refuse('its chain does not verify to the service Root (' +
                    String((socket && socket.authorizationError) ||
                           'no certificate') + ')');
    }
    const cert = socket.getPeerCertificate(true);
    const caDer = this.cellCaDer();
    const issuer = cert && cert.issuerCertificate;
    if (!caDer || !issuer || !issuer.raw ||
        Buffer.compare(Buffer.from(issuer.raw), caDer) !== 0) {
      log.debug("Leaving CellChannel.peerCellOf(). Wrong issuer.");
      return refuse('its certificate was not issued by the inter-cell ' +
                    'Issuing CA');
    }
    const names = String((cert && cert.subjectaltname) || '')
      .split(',').map((one: string) => one.trim())
      .filter((one: string) => one.indexOf('URI:' + CELL_URN_PREFIX) === 0)
      .map((one: string) => one.slice(('URI:' + CELL_URN_PREFIX).length));
    if (names.length !== 1) {
      log.debug("Leaving CellChannel.peerCellOf(). No single cell.");
      return refuse('its certificate names ' + names.length + ' cells');
    }
    const id = names[0];
    if (id === cells.id() || !cells.get(id)) {
      log.debug("Leaving CellChannel.peerCellOf(). Not a peer.");
      return refuse('it names cell "' + id + '", which is not one of this ' +
                    'cell\'s peers');
    }
    if (expected && id !== expected) {
      log.debug("Leaving CellChannel.peerCellOf(). Not the one dialled.");
      return refuse('cell "' + expected + '" was dialled and "' + id +
                    '" answered');
    }
    log.debug("Leaving CellChannel.peerCellOf(). " + id);
    return id;
  }

  // =========================================================================
  // THE LISTENER — from `server.js`'s `listen()`, in the front process only,
  // and only when this is a cell. A failure to bind is RECORDED, as every
  // socket owner's is: the rest of the service still answers, and what it
  // cannot do without the channel (serve a relayed request, answer another
  // cell's question) fails closed at the other cell.
  // =========================================================================
  /**
   * Binds the inter-cell listener; called from server.js's listen().
   *
   * @param app - the express app a relayed request is served by
   * @returns `{ whenReady }`, resolving to the bound port, or to `null` with
   *   the reason when this is not a cell
   */
  listen(app: any): { whenReady: Promise<{ port: number | null;
                                            why?: string }> } {
    log.debug("Entering CellChannel.listen().");
    if (!cells.isMulti()) {
      log.debug("Leaving CellChannel.listen(). Single-cell.");
      return { whenReady: Promise.resolve({ port: null,
                                            why: 'single-cell mode' }) };
    }
    this.registerLeafJob();
    const self = this;
    const port = Number(config.value('cells.port'));
    log.debug("Leaving CellChannel.listen().");
    return {
      whenReady: this.ensureLeaf().then(function (leaf) {
        return new Promise(function (resolve, reject) {
          const server = https.createServer(Object.assign(
            self.serverContextOptions(leaf),
            { requestCert: true, rejectUnauthorized: true }),
          function (req: any, res: any) {
            self.handle(app, req, res);
          });
          self.server = server;
          // A change to the listeners' policy re-keys this one too (#423).
          self.unregisterPolicy = require('../tls/tls_server')
            .registerPolicyApplier('the channel between cells (' + port + ')',
              'cell', function () {
                if (self.server && self.leaf) {
                  self.server.setSecureContext(
                    self.serverContextOptions(self.leaf));
                }
              });
          server.once('error', function (err: any) {
            self.listenError = err.message;
            log.error(errorCodes.tag('STS-CELL-0033') + 'cells: the ' +
                      'inter-cell listener could not bind port ' + port +
                      ': ' + err.message + '. Requests relayed to this cell ' +
                      'and questions from the other cells will fail at ' +
                      'them.');
            reject(err);
          });
          server.listen(port, function () {
            self.listening = true;
            self.boundPort = (server.address() as any).port;
            resolve({ port: self.boundPort });
          });
        });
      })
    };
  }

  /**
   * Closes the inter-cell listener.
   *
   * @returns a promise settled once it has closed
   */
  close(): Promise<void> {
    log.debug("Entering CellChannel.close().");
    const closing = this.server;
    this.server = null;
    if (this.unregisterPolicy) {
      this.unregisterPolicy();
      this.unregisterPolicy = null;
    }
    this.listening = false;
    log.debug("Leaving CellChannel.close().");
    return new Promise<void>(function (resolve) {
      if (!closing) {
        resolve();
        return;
      }
      closing.close(function () {
        resolve();
      });
      if (typeof closing.closeAllConnections === 'function') {
        closing.closeAllConnections();
      }
    });
  }

  // A process re-mints its own leaf at half-life (#49: periodic work is a
  // scheduler job). PER-PROCESS, because every process holds its own key —
  // the front process for the listener and for dialling, a worker for
  // dialling — and none may use another's.
  private registerLeafJob(): void {
    log.debug("Entering CellChannel.registerLeafJob().");
    if (this.jobRegistered) {
      log.debug("Leaving CellChannel.registerLeafJob(). Registered.");
      return;
    }
    this.jobRegistered = true;
    const self = this;
    const scheduler = require('../cluster/scheduler');
    scheduler.register({
      id: 'cells.channel-certificate',
      title: 'Inter-cell certificate',
      describe: 'Re-mints this process\'s inter-cell certificate when it is ' +
                'past half its ' + (LEAF_LIFETIME_MS / 3600000) + '-hour ' +
                'life, and presents the new one on the inter-cell listener.',
      owner: 'common/cell_channel.ts',
      kind: 'per-process', quiet: true,
      everyMs: function () {
        return CHECK_MS;
      },
      off: function () {
        return cells.isMulti() ? '' : 'this service is not deployed as cells';
      },
      run: function () {
        return self.ensureLeaf().then(function (leaf) {
          return { notAfter: new Date(leaf.notAfterMs).toISOString() };
        });
      }
    });
    log.debug("Leaving CellChannel.registerLeafJob().");
  }

  // -------------------------------------------------------------------------
  // A CONNECTION ON THE LISTENER. The peer is checked first, for every
  // request; an operation is answered here; anything else is a relayed
  // request, handed to the public app as the client's own.
  // -------------------------------------------------------------------------
  private handle(app: any, req: any, res: any): void {
    log.debug("Entering CellChannel.handle().");
    const peer = this.peerCellOf(req.socket, '');
    if (!peer) {
      errorCodes.mark(res, 'STS-CELL-0032');
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('not a cell of this service\n');
      log.debug("Leaving CellChannel.handle(). Refused.");
      return;
    }
    const url = String(req.url || '');
    if (url.indexOf(OP_PREFIX) === 0) {
      this.answerOp(peer, url.slice(OP_PREFIX.length).split('?')[0], req,
                    res);
      log.debug("Leaving CellChannel.handle(). An operation.");
      return;
    }
    if (String(req.headers[H_FROM] || '') !== peer ||
        Number(req.headers[H_HOPS] || 0) !== 1) {
      errorCodes.mark(res, 'STS-CELL-0034');
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('a relayed request must carry its sending cell and one hop\n');
      log.debug("Leaving CellChannel.handle(). Malformed relay.");
      return;
    }
    this.counters.relayedIn += 1;
    this.serveRelayed(app, peer, req, res);
    log.debug("Leaving CellChannel.handle(). Relayed in.");
  }

  // THE RELAYED REQUEST, SERVED AS THE CLIENT'S. See the header: the
  // socket is shimmed so the peer cell's leaf is never the caller's
  // certificate, and the internal headers are read and removed.
  private serveRelayed(app: any, peer: string, req: any, res: any): void {
    log.debug("Entering CellChannel.serveRelayed().");
    const client = String(req.headers[H_CLIENT] || '').trim();
    const reason = String(req.headers[H_REASON] || '').trim();
    const encoded = req.headers[H_PEER_CERT];
    const authorized = req.headers[H_PEER_AUTHORIZED] === 'yes';
    const cert = encoded ? CellChannel.decodePeerCertificate(encoded) : null;
    const shim = Object.create(req.socket);
    shim.authorized = !!cert && authorized;
    shim.getPeerCertificate = function () {
      log.debug("Entering getPeerCertificate().");
      log.debug("Leaving getPeerCertificate().");
      return cert || {};
    };
    req.socket = shim;
    req.connection = shim;
    // The client's own TLS fingerprint, as the sending cell forwarded it,
    // or none — never this connection's, which is the sending node's.
    // Required lazily, as `request_pool.js` requires it.
    require('../tls/client_hello').adoptRelayed(req);
    INTERNAL_HEADERS.forEach(function (name) {
      delete req.headers[name];
    });
    req.stsCellRelay = { from: peer, client: client, reason: reason };
    log.debug("Leaving CellChannel.serveRelayed().");
    app(req, res);
  }

  /**
   * Decodes a forwarded client certificate — `request_pool.peerOf()`'s
   * encoding, the one a request worker decodes.
   *
   * @param encoded - the header value
   * @returns the certificate object, or null when it cannot be read
   */
  static decodePeerCertificate(encoded: unknown): Record<string, any> | null {
    log.debug("Entering CellChannel.decodePeerCertificate().");
    let flat: Record<string, any>;
    try {
      flat = JSON.parse(Buffer.from(String(encoded), 'base64')
        .toString('utf8'));
    } catch (e) {
      log.debug("Caught in CellChannel.decodePeerCertificate(): " +
                ((e && e.message) || e));
      log.debug("Leaving CellChannel.decodePeerCertificate(). Unreadable.");
      return null;
    }
    Object.keys(flat).forEach(function (name) {
      const value = flat[name];
      if (value && typeof value === 'object' &&
          typeof value.__buffer === 'string') {
        flat[name] = Buffer.from(value.__buffer, 'base64');
      }
    });
    log.debug("Leaving CellChannel.decodePeerCertificate().");
    return flat;
  }

  // =========================================================================
  // OPERATIONS. A module registers a name and a handler; a peer POSTs JSON
  // to `/_cell/v1/<name>` and gets the handler's answer as JSON. An unknown
  // name is 404 and a handler that throws is 500 with its message, which is
  // another cell of the same service reading it and nobody else.
  // =========================================================================
  /**
   * Registers an operation other cells may call.
   *
   * @param name - `[a-z0-9-]+`
   * @param handler - `(body, { peer }) => answer`, possibly a promise
   */
  registerOp(name: string, handler: OpHandler): void {
    log.debug("Entering CellChannel.registerOp(). " + name);
    if (!/^[a-z0-9-]+$/.test(String(name))) {
      throw new Error('cell_channel: "' + name + '" is not an operation ' +
                      'name ([a-z0-9-]+).');
    }
    this.ops.set(String(name), handler);
    log.debug("Leaving CellChannel.registerOp().");
  }

  /**
   * The names of the registered operations.
   *
   * @returns the names, sorted
   */
  opNames(): string[] {
    log.debug("Entering CellChannel.opNames().");
    log.debug("Leaving CellChannel.opNames().");
    return Array.from(this.ops.keys()).sort();
  }

  private answerOp(peer: string, name: string, req: any, res: any): void {
    log.debug("Entering CellChannel.answerOp(). " + name);
    const self = this;
    const handler = this.ops.get(name);
    const reply = function (status: number, body: any) {
      const text = JSON.stringify(body);
      res.writeHead(status, { 'content-type': 'application/json',
                              'cache-control': 'no-store',
                              'content-length': Buffer.byteLength(text) });
      res.end(text);
    };
    if (!handler || req.method !== 'POST') {
      errorCodes.mark(res, 'STS-CELL-0035');
      reply(404, { error: 'no operation "' + name + '"' });
      log.debug("Leaving CellChannel.answerOp(). Unknown.");
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let refused = false;
    req.on('data', function (chunk: Buffer) {
      size += chunk.length;
      if (size > MAX_OP_BYTES) {
        refused = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', function () {
      if (refused) {
        errorCodes.mark(res, 'STS-CELL-0035');
        reply(413, { error: 'the operation body is too large' });
        return;
      }
      let body: any = {};
      try {
        body = chunks.length ? JSON.parse(Buffer.concat(chunks)
          .toString('utf8')) : {};
      } catch (e) {
        log.debug("Caught in CellChannel.answerOp(): " +
                  ((e && e.message) || e));
        errorCodes.mark(res, 'STS-CELL-0035');
        reply(400, { error: 'the operation body is not JSON' });
        return;
      }
      self.counters.opsIn += 1;
      Promise.resolve().then(function () {
        return handler(body, { peer: peer });
      }).then(function (answer) {
        reply(200, answer === undefined ? {} : answer);
      }, function (err) {
        self.counters.failures += 1;
        log.error(errorCodes.tag('STS-CELL-0036') + 'cells: the ' +
                  'operation "' + name + '" called by cell "' + peer +
                  '" failed: ' + ((err && err.message) || err));
        reply(500, { error: String((err && err.message) || err) });
      });
    });
    log.debug("Leaving CellChannel.answerOp().");
  }

  // =========================================================================
  // DIALLING A PEER. Its URL is `cells.peers`' — a private name that may
  // resolve to one address per node — so every address is tried in turn
  // until one connects, and the peer's leaf must name the cell dialled.
  // =========================================================================
  private addressesOf(host: string): Promise<string[]> {
    log.debug("Entering CellChannel.addressesOf().");
    log.debug("Leaving CellChannel.addressesOf().");
    return new Promise(function (resolve) {
      dns.lookup(host, { all: true }, function (err, found) {
        if (err || !found || !found.length) {
          resolve([host]);
          return;
        }
        resolve(found.map(function (one) {
          return one.address;
        }));
      });
    });
  }

  // One request to a peer, over the first of its addresses that connects.
  // `send(request)` writes the body; the answer is the response, unread.
  private dial(cellId: string, method: string, path: string,
               headers: Record<string, any>,
               send: (request: any) => void): Promise<any> {
    log.debug("Entering CellChannel.dial(). " + cellId + " " + path);
    const self = this;
    const peer = cells.get(cellId);
    if (!peer || peer.self || !peer.url) {
      log.debug("Leaving CellChannel.dial(). No such peer.");
      return Promise.reject(new Error(errorCodes.tag('STS-CELL-0030') +
        'cells: there is no peer cell "' + cellId + '" to dial.'));
    }
    const target = new URL(peer.url);
    const timeout = Math.max(1000,
                             Number(config.value('cells.relayTimeoutMs')) ||
                             10000);
    log.debug("Leaving CellChannel.dial().");
    return Promise.all([this.ensureLeaf(), this.addressesOf(target.hostname)])
      .then(function (both) {
        const leaf = both[0];
        const addresses = both[1];
        const attempt = function (i: number): Promise<any> {
          return new Promise(function (resolve, reject) {
            const request = https.request({
              host: addresses[i],
              servername: target.hostname,
              port: Number(target.port) || 443,
              method: method,
              path: path,
              // The peer's private name is the TLS server name above, and
              // the Host header unless the caller names one: a relayed
              // request carries the host the CLIENT addressed (relay()).
              headers: Object.assign({ host: target.host }, headers),
              key: leaf.keyPem,
              cert: [leaf.certPem].concat(leaf.chainPem).join('\n'),
              ca: [self.rootPem()],
              minVersion: 'TLSv1.3',
              timeout: timeout,
              agent: false
            }, function (response: any) {
              const answered = self.peerCellOf(response.socket, cellId);
              if (!answered) {
                response.resume();
                reject(new Error(errorCodes.tag('STS-CELL-0032') +
                                 'cells: the peer that answered for "' +
                                 cellId + '" is not that cell.'));
                return;
              }
              resolve(response);
            });
            request.on('timeout', function () {
              request.destroy(new Error('timed out after ' + timeout + 'ms'));
            });
            request.on('error', function (err: any) {
              if (i + 1 < addresses.length && !request.reusedSocket &&
                  /ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT|ENETUNREACH|timed out/
                    .test(String(err && (err.code || err.message)))) {
                attempt(i + 1).then(resolve, reject);
                return;
              }
              reject(err);
            });
            send(request);
          });
        };
        return attempt(0);
      }).catch(function (err) {
        self.counters.failures += 1;
        self.lastFailure = String((err && err.message) || err);
        throw err;
      });
  }

  /**
   * Calls an operation of another cell.
   *
   * @param cellId - the cell
   * @param name - the operation
   * @param body - JSON-serialisable
   * @returns a promise of the operation's answer
   * @throws a rejected promise when the cell cannot be reached or the
   *   operation failed there
   */
  call(cellId: string, name: string, body: any): Promise<any> {
    log.debug("Entering CellChannel.call(). " + cellId + " " + name);
    const self = this;
    const text = JSON.stringify(body === undefined ? {} : body);
    this.counters.opsOut += 1;
    log.debug("Leaving CellChannel.call().");
    return this.dial(cellId, 'POST', OP_PREFIX + name, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(text)
    }, function (request) {
      request.end(text);
    }).then(function (response) {
      return new Promise(function (resolve, reject) {
        const chunks: Buffer[] = [];
        response.on('data', function (chunk: Buffer) {
          chunks.push(chunk);
        });
        response.on('end', function () {
          let parsed: any = {};
          try {
            parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') ||
                                '{}');
          } catch (e) {
            log.debug("Caught in CellChannel.call(): " +
                      ((e && e.message) || e));
            parsed = { error: 'an answer that is not JSON' };
          }
          if (response.statusCode !== 200) {
            self.counters.failures += 1;
            reject(new Error(errorCodes.tag('STS-CELL-0036') + 'cells: "' +
                             name + '" at cell "' + cellId + '" answered ' +
                             response.statusCode + ': ' +
                             (parsed.error || '')));
            return;
          }
          resolve(parsed);
        });
        response.on('error', reject);
      });
    });
  }

  // =========================================================================
  // RELAYING A WHOLE REQUEST. `body` is given when the request's body was
  // already read (a handler that found an artifact another cell minted);
  // otherwise the request stream is piped, which is what the edge does
  // before any body parser has run. The answer's status, headers and body
  // are the owning cell's, piped back untouched.
  // =========================================================================
  /**
   * Sends a request to the cell that owns it and pipes the answer back.
   *
   * @param req - the express request
   * @param res - the express response
   * @param cellId - the owning cell
   * @param opts - `reason` (recorded at both ends) and `body` (a Buffer or
   *   string, when the request's body was already consumed)
   * @returns a promise settled when the answer has been sent; a cell that
   *   cannot be reached is answered 503 here (#98 D6, fail-closed)
   */
  relay(req: any, res: any, cellId: string,
        opts?: { reason?: string; body?: Buffer | string }): Promise<void> {
    log.debug("Entering CellChannel.relay(). to " + cellId);
    const self = this;
    const o = opts || {};
    if (req.stsCellRelay) {
      // ONE HOP — see the header. The caller should never reach here with a
      // relayed request; this is the backstop.
      errorCodes.mark(res, 'STS-CELL-0034');
      res.status(508).type('text/plain')
        .send('this request was already relayed once\n');
      log.debug("Leaving CellChannel.relay(). Already relayed.");
      return Promise.resolve();
    }
    const headers: Record<string, any> = {};
    Object.keys(req.headers || {}).forEach(function (name) {
      const lower = name.toLowerCase();
      if (HOP_BY_HOP.indexOf(lower) >= 0 ||
          INTERNAL_HEADERS.indexOf(lower) >= 0 || lower === 'host' ||
          FORWARDING_HEADERS.indexOf(lower) >= 0) {
        return;
      }
      headers[lower] = req.headers[name];
    });
    const clientAddress = require('./client_address');
    headers[H_FROM] = cells.id();
    headers[H_HOPS] = '1';
    headers[H_CLIENT] = clientAddress.clientAddressOf(req);
    headers[H_REASON] = String(o.reason || '');
    // The client's certificate, as the front process hands one to a worker.
    const pool = require('./request_pool');
    const presented = typeof pool.peerOf === 'function' ? pool.peerOf(req)
                                                         : null;
    if (presented) {
      headers[H_PEER_CERT] = presented.cert;
      headers[H_PEER_AUTHORIZED] = presented.authorized ? 'yes' : 'no';
    }
    // And its TLS fingerprint, read off the connection here.
    const hello = require('../tls/client_hello').encodeForward(req);
    if (hello) {
      headers[H_CLIENT_HELLO] = hello;
    }
    // THE HOST AND SCHEME THE CLIENT ADDRESSED, AS THIS CELL UNDERSTOOD
    // THEM (#98, 2026-09-28) — in the Host header itself, not only in
    // `x-forwarded-host`. The owning cell builds its own addresses from them
    // (`helpers.baseUrlOf()`) wherever `global.publicBaseUrl` does not pin
    // them, and so does every check that compares a signed URI with the one
    // the request arrived at: a GNAP HTTP message signature covering
    // `@authority` or `@target-uri` (RFC 9421 section 2.2), a DPoP proof's
    // `htu`, a JWS request's `uri`. Until this change the Host header was the
    // PEER'S PRIVATE NAME and only `x-forwarded-host` carried the client's —
    // which the owning cell believes only where `global.trustProxy` is on
    // and the sending node is a trusted proxy, i.e. almost never — so a
    // relayed signed request was verified against an authority the client
    // never saw, and refused. The private name is still what is DIALLED and
    // what the peer's certificate is checked against: it is the TLS server
    // name (`dial()`), and the Host header plays no part in either.
    //
    // WHAT THE OWNING CELL TRUSTS IS NOT WIDENED. The value is not the raw
    // header the client sent but `helpers.forwardedFrom()`'s answer here —
    // the header, or a forwarded host only where THIS cell believes its
    // proxy — so the owning cell sees exactly what it would have seen had
    // the client reached it directly through the same balancer. The client's
    // own `x-forwarded-*` and `forwarded` headers are dropped above and the
    // two forwarded headers are rewritten to the same answer, so a receiving
    // cell that does believe forwarded headers from a peer (trustProxy on
    // with no ranges named) reads the same host, never one a client chose
    // behind this cell's back. And where `global.publicBaseUrl` is set — as
    // product mode requires of a deployed service — neither header decides
    // any address at all: the pinned base does, in every cell alike.
    const understood = require('./helpers').forwardedFrom(req);
    headers.host = String(understood.host || req.headers.host || '');
    headers['x-forwarded-host'] = headers.host;
    headers['x-forwarded-proto'] = String(understood.proto || 'https');
    let body: Buffer | null = null;
    if (o.body !== undefined) {
      body = Buffer.isBuffer(o.body) ? o.body : Buffer.from(String(o.body));
      headers['content-length'] = String(body.length);
      delete headers['content-encoding'];
    }
    this.counters.relayedOut += 1;
    log.info('cells: a request for ' + String(req.method) + ' ' +
             String(req.originalUrl || req.url).split('?')[0] + ' is ' +
             'relayed to cell "' + cellId + '" (' + (o.reason || 'owner') +
             ').');
    log.debug("Leaving CellChannel.relay().");
    return this.dial(cellId, String(req.method), String(req.originalUrl ||
                     req.url), headers, function (request) {
      if (body) {
        request.end(body);
      } else {
        req.pipe(request);
      }
    }).then(function (response) {
      const out: Record<string, any> = {};
      Object.keys(response.headers || {}).forEach(function (name) {
        if (HOP_BY_HOP.indexOf(name.toLowerCase()) < 0) {
          out[name] = response.headers[name];
        }
      });
      res.writeHead(response.statusCode, out);
      response.pipe(res);
      return new Promise<void>(function (resolve) {
        response.on('end', function () {
          resolve();
        });
        response.on('error', function () {
          resolve();
        });
      });
    }, function (err) {
      log.error(errorCodes.tag('STS-CELL-0030') + 'cells: a request could ' +
                'not be relayed to cell "' + cellId + '": ' +
                ((err && err.message) || err) + '. It is answered 503 here, ' +
                'fail-closed (cells.homeUnreachable).');
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-CELL-0030');
        res.status(503).set('retry-after', '30').type('text/plain')
          .send('This service cannot reach the region that holds this ' +
                'request just now. Please try again shortly.\n');
      }
    });
  }

  /**
   * What `/admin/cells` shows about the channel in this process.
   *
   * @returns the listener's state, this process's leaf, the operations and
   *   the counters
   */
  status(): Record<string, any> {
    log.debug("Entering CellChannel.status().");
    log.debug("Leaving CellChannel.status().");
    return {
      listening: this.listening,
      port: this.boundPort || null,
      listenError: this.listenError || null,
      certificateUntil: this.leaf
        ? new Date(this.leaf.notAfterMs).toISOString() : null,
      operations: this.opNames(),
      counters: Object.assign({}, this.counters),
      lastFailure: this.lastFailure || null
    };
  }
}

// The process's own channel. A LIBRARY: building it binds and dials nothing.
const channel = new CellChannel();

/**
 * The channel between the cells of a service deployed as cells (#98): a
 * mutual-TLS listener and client, operations modules register, and the relay
 * of a whole request to the cell that owns it.
 *
 * A library: it registers no route on the public app.
 * @namespace
 */
export = {
  CellChannel: CellChannel,
  OP_PREFIX: OP_PREFIX,
  CELL_URN_PREFIX: CELL_URN_PREFIX,
  INTERNAL_HEADERS: INTERNAL_HEADERS,
  listen: (app: any) => channel.listen(app),
  close: (): Promise<void> => channel.close(),
  ensureLeaf: () => channel.ensureLeaf(),
  registerOp: (name: string, handler: OpHandler): void =>
    channel.registerOp(name, handler),
  opNames: (): string[] => channel.opNames(),
  call: (cellId: string, name: string, body: any): Promise<any> =>
    channel.call(cellId, name, body),
  relay: (req: any, res: any, cellId: string,
          opts?: { reason?: string; body?: Buffer | string }): Promise<void> =>
    channel.relay(req, res, cellId, opts),
  peerCellOf: (socket: any, expected: string): string =>
    channel.peerCellOf(socket, expected),
  decodePeerCertificate: CellChannel.decodePeerCertificate,
  status: () => channel.status()
};
