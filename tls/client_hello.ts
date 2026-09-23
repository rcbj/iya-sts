'use strict';
//
// File: tls/client_hello.ts
//
// ===========================================================================
// THE CLIENT'S TLS FINGERPRINT (JA4), READ OFF THE MAIN PORT (#62 P0,
// 2026-09-22).
//
// Risk scoring (#62) needs to know what kind of TLS stack is on the other end
// of a sign-in, because a User-Agent header is a string anybody can type and
// a TLS ClientHello is what their library actually sends. A request that says
// "Chrome" over a Python or Go TLS stack, and a session whose cookie turns up
// from a different stack than the one that signed in, are two of the
// strongest signals the plan names. JA4 (FoxIO's JA4 specification, the TLS
// client fingerprint, BSD-3-Clause) is the published way of reducing a
// ClientHello to a comparable string, so this computes JA4 and nothing of the
// rest of JA4+, which is under a non-commercial licence.
//
// **THAT IS A LEGAL BOUNDARY, NOT A TODO** (the licence review on #62). JA4S,
// JA4H, JA4X, JA4SSH and the rest of JA4+ are under the FoxIO License 1.1,
// which restricts commercial use; the BSD-3 notice in `LICENSE.md` covers JA4
// alone. None of them is to be added to this file or anywhere else here
// without a licence decision of its own.
//
// **IT IS COMPUTED HERE, NOT BY A LIBRARY**, because the one maintained Node
// library (`read-tls-client-hello`) is Apache-2.0 and this project takes MIT
// dependencies where it can (#62's plan, §1). Parsing a ClientHello is a few
// dozen lines, and the specification's own worked example is the test
// (`tests/tls_client_hello.js`).
//
// ---------------------------------------------------------------------------
// HOW THE BYTES ARE READ WITHOUT DISTURBING THE HANDSHAKE.
//
// Node gives the TLS engine the raw socket's handle; nothing on the JS side
// sees the ClientHello once TLS has it. So `install(server)` does what
// `common/proxy_protocol.ts` does with the PROXY header, one layer in: it
// shadows the server's `emit` for `connection`, reads from the raw socket
// until a whole ClientHello has arrived, UNSHIFTS every byte it read back onto
// the paused socket, and only then emits the event for real — so the TLS
// engine drains exactly the bytes the client sent, in order. It never answers
// anything and never refuses anything: a connection that does not begin with
// a TLS handshake record, sends more than MAX_HELLO_BYTES, or sends nothing
// for HELLO_WAIT_MS is handed over as it stands with no fingerprint, and the
// TLS engine deals with it exactly as it would have.
//
// **IT IS INSTALLED BEFORE THE PROXY PROTOCOL**, so the PROXY header's
// wrapper is the outer one: it takes its header off first and hands this one
// a socket that begins with the ClientHello, whose peer address is already
// the client's.
//
// **WHERE THE ANSWER GOES.** The raw socket and the `TLSSocket` wrapped
// around it are two objects, and a request sees the second. The fingerprint
// is held by connection — peer address and port — until the server's
// `secureConnection` hands over the TLS socket, and is put on that socket
// then; a connection that closes before its handshake completes takes its
// entry with it. That avoids reading node's private `_parent` link, which
// works and is not an interface.
//
// **A REQUEST WORKER SEES IT TOO.** A dispatched request reaches its worker
// over a unix socket with no TLS at all, so `common/request_pool.js` forwards
// the fingerprint in a header it strips from what the client sent, exactly as
// it forwards the client certificate, and `common/request_worker.ts` puts it
// on the REQUEST (not the socket, which a kept-alive connection shares).
// `of(req)` reads either.
//
// A LIBRARY (rule 3): it registers no route. It requires `common/crypto.js`
// (the digests), bunyan and `config` for the logger, and `instance_slot`.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');

const log = bunyan.createLogger({ name: 'sts-tls-client-hello' });
config.registerLogger(log);

// ---------------------------------------------------------------------------
// THE BOUNDS, AND WHY THEY ARE CONSTANTS RATHER THAN SETTINGS.
//
// A ClientHello with a post-quantum key share (X25519MLKEM768) is about
// 1.8 KB, and the largest seen in the wild are a few kilobytes more; the
// handshake length field allows 16 MB. 64 KiB is well past anything real and
// is what one connection may hold here before it is handed over unread. The
// wait is how long a connection that has sent part of a hello is held back
// from the TLS engine; the engine's own handshake timeout still applies after
// it, so this adds at most this much to it and never removes anything.
// ---------------------------------------------------------------------------
const MAX_HELLO_BYTES = 64 * 1024;
const HELLO_WAIT_MS = 10 * 1000;
// Connections waiting for their TLS socket; a bound, not a tunable.
const MAX_PENDING = 20000;

// The header `common/request_pool.js` forwards the fingerprint in.
const FORWARD_HEADER = 'x-sts-tls-client-hello';

// TLS constants the parse reads (RFC 8446 sections 4 and 5.1).
const RECORD_HANDSHAKE = 0x16;
const HANDSHAKE_CLIENT_HELLO = 0x01;
const RECORD_HEADER_BYTES = 5;
const EXT_SERVER_NAME = 0x0000;
const EXT_ALPN = 0x0010;
const EXT_SIGNATURE_ALGORITHMS = 0x000d;
const EXT_SUPPORTED_VERSIONS = 0x002b;

// JA4's version labels (the specification's table). Anything else is "00".
const VERSION_LABELS = {
  0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
  0x0002: 's2', 0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3'
};

// What a hello's `parse()` hands `ja4()`, and what `of()` answers.
interface ParsedHello {
  version: number;
  ciphers: number[];
  extensions: number[];
  signatureAlgorithms: number[];
  supportedVersions: number[];
  serverName: string;
  alpn: string[];
  firstAlpn: Buffer | null;
}

interface ParseResult {
  state: 'incomplete' | 'invalid' | 'complete';
  reason?: string;
  hello?: ParsedHello;
}

interface HelloInfo {
  ja4: string;
  version: string;
  sni: string;
  alpn: string[];
}

interface ClientHelloDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
  };
}

// Where the answer is kept on a TLS socket and on a worker's request.
const INFO = Symbol('sts.tlsClientHello');
// The mark that a socket has already been through the gate, so the real
// `connection` emit below is not intercepted a second time.
const SEEN = Symbol('sts.tlsClientHelloSeen');

// The shape a forwarded or stored JA4 must have: protocol, version, SNI flag,
// two two-digit counts, two ALPN characters, then two 12-hex hashes.
const JA4_SHAPE = new RegExp('^[tqd](13|12|11|10|s3|s2|d1|d2|d3|00)[di]' +
                             '[0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_' +
                             '[0-9a-f]{12}$');

// What has happened, for `report()`.
const counters = { fingerprinted: 0, notTls: 0, unparsed: 0, overLimit: 0,
                   timedOut: 0 };

class ClientHello {
  static readonly FORWARD_HEADER = FORWARD_HEADER;
  static readonly MAX_HELLO_BYTES = MAX_HELLO_BYTES;

  // Connection key -> the answer, until `secureConnection` collects it.
  private readonly waiting = new Map<string, HelloInfo>();

  constructor(private readonly deps: ClientHelloDeps) {
    deps.log.debug("Entering ClientHello.constructor().");
    deps.log.debug("Leaving ClientHello.constructor().");
  }

  static defaultDeps(): ClientHelloDeps {
    log.debug("Entering ClientHello.defaultDeps().");
    log.debug("Leaving ClientHello.defaultDeps().");
    return { log: log };
  }

  // -------------------------------------------------------------------------
  // GREASE (RFC 8701): the sixteen reserved values 0x0a0a, 0x1a1a … 0xfafa a
  // client sprinkles into its lists so that servers do not ossify. JA4
  // ignores them everywhere, or every Chrome would fingerprint differently.
  //
  // A HOT PATH, with no Entering/Leaving pair: it is asked once per value in
  // every list of every ClientHello, and a pair here would drown the log.
  // `hex4()` and `count2()` below are the same case.
  // -------------------------------------------------------------------------
  static isGrease(value: number): boolean {
    return (value & 0x0f0f) === 0x0a0a && (value >> 8) === (value & 0xff);
  }

  // -------------------------------------------------------------------------
  // parse(bytes) — the TLS records at the front of a connection, read far
  // enough to hold one whole ClientHello. `incomplete` asks for more bytes;
  // `invalid` means this is not a ClientHello and never will be; `complete`
  // carries the lists JA4 is made of. The hello may span several handshake
  // records (RFC 8446 section 5.1 allows fragmenting it), so the records'
  // bodies are joined before the handshake message is read.
  // -------------------------------------------------------------------------
  static parse(bytes: Buffer): ParseResult {
    log.debug("Entering ClientHello.parse(). bytes=" + bytes.length);
    const body = [];
    let offset = 0;
    let joined = Buffer.alloc(0);
    let wanted = -1;
    while (true) {
      if (bytes.length < offset + RECORD_HEADER_BYTES) {
        log.debug("Leaving ClientHello.parse(). Incomplete record header.");
        return { state: 'incomplete' };
      }
      if (bytes[offset] !== RECORD_HANDSHAKE) {
        log.debug("Leaving ClientHello.parse(). Not a handshake record.");
        return { state: 'invalid', reason: 'not a TLS handshake record' };
      }
      const length = bytes.readUInt16BE(offset + 3);
      if (bytes.length < offset + RECORD_HEADER_BYTES + length) {
        log.debug("Leaving ClientHello.parse(). Incomplete record.");
        return { state: 'incomplete' };
      }
      body.push(bytes.subarray(offset + RECORD_HEADER_BYTES,
                               offset + RECORD_HEADER_BYTES + length));
      offset += RECORD_HEADER_BYTES + length;
      joined = Buffer.concat(body);
      if (wanted < 0 && joined.length >= 4) {
        if (joined[0] !== HANDSHAKE_CLIENT_HELLO) {
          log.debug("Leaving ClientHello.parse(). Not a ClientHello.");
          return { state: 'invalid', reason: 'the first handshake message ' +
                   'is not a ClientHello' };
        }
        wanted = 4 + joined.readUIntBE(1, 3);
      }
      if (wanted >= 0 && joined.length >= wanted) {
        break;
      }
    }
    const hello = ClientHello.readHello(joined.subarray(4, wanted));
    if (!hello) {
      log.debug("Leaving ClientHello.parse(). Malformed.");
      return { state: 'invalid', reason: 'the ClientHello is malformed' };
    }
    log.debug("Leaving ClientHello.parse(). Complete.");
    return { state: 'complete', hello: hello };
  }

  // The ClientHello body (RFC 8446 section 4.1.2), or null when it runs past
  // its own end. Every length is checked against what is left, because the
  // bytes are a stranger's.
  private static readHello(message: Buffer): ParsedHello | null {
    log.debug("Entering ClientHello.readHello(). bytes=" + message.length);
    let at = 0;
    // Asked before every read, so no Entering/Leaving pair (a hot path, as
    // the code style allows when it says so).
    function need(count) {
      return at + count <= message.length;
    }
    // legacy_version, random
    if (!need(2 + 32 + 1)) {
      log.debug("Leaving ClientHello.readHello(). Too short.");
      return null;
    }
    const version = message.readUInt16BE(0);
    at = 34;
    // legacy_session_id
    const sessionIdLength = message[at];
    at += 1 + sessionIdLength;
    if (!need(2)) {
      log.debug("Leaving ClientHello.readHello(). No cipher suites.");
      return null;
    }
    const cipherBytes = message.readUInt16BE(at);
    at += 2;
    if (!need(cipherBytes) || cipherBytes % 2 !== 0) {
      log.debug("Leaving ClientHello.readHello(). Bad cipher suites.");
      return null;
    }
    const ciphers = [];
    for (let i = 0; i < cipherBytes; i += 2) {
      ciphers.push(message.readUInt16BE(at + i));
    }
    at += cipherBytes;
    // legacy_compression_methods
    if (!need(1)) {
      log.debug("Leaving ClientHello.readHello(). No compression methods.");
      return null;
    }
    at += 1 + message[at];
    const hello: ParsedHello = {
      version: version, ciphers: ciphers, extensions: [],
      signatureAlgorithms: [], supportedVersions: [], serverName: '',
      alpn: [], firstAlpn: null
    };
    // No extensions at all is legal before TLS 1.3.
    if (at === message.length) {
      log.debug("Leaving ClientHello.readHello(). No extensions.");
      return hello;
    }
    if (!need(2)) {
      log.debug("Leaving ClientHello.readHello(). Bad extensions length.");
      return null;
    }
    const extensionsEnd = at + 2 + message.readUInt16BE(at);
    at += 2;
    if (extensionsEnd > message.length) {
      log.debug("Leaving ClientHello.readHello(). Extensions overrun.");
      return null;
    }
    while (at + 4 <= extensionsEnd) {
      const type = message.readUInt16BE(at);
      const length = message.readUInt16BE(at + 2);
      const data = message.subarray(at + 4, at + 4 + length);
      at += 4 + length;
      if (at > extensionsEnd) {
        log.debug("Leaving ClientHello.readHello(). An extension overruns.");
        return null;
      }
      hello.extensions.push(type);
      ClientHello.readExtension(hello, type, data);
    }
    log.debug("Leaving ClientHello.readHello(). " + hello.extensions.length +
              " extension(s).");
    return hello;
  }

  // The four extensions JA4 looks inside. A malformed one is read as far as
  // it goes and otherwise ignored: the fingerprint is evidence, and a client
  // that sends a broken extension will find out from the TLS engine.
  private static readExtension(hello: ParsedHello, type: number,
                               data: Buffer): void {
    log.debug("Entering ClientHello.readExtension(). type=" + type);
    if (type === EXT_SERVER_NAME && data.length >= 5) {
      // server_name_list: length, then (type, length, name); host_name is 0.
      const nameLength = data.readUInt16BE(3);
      if (data[2] === 0 && 5 + nameLength <= data.length) {
        hello.serverName = data.subarray(5, 5 + nameLength).toString('latin1');
      }
    } else if (type === EXT_ALPN && data.length >= 2) {
      const end = Math.min(data.length, 2 + data.readUInt16BE(0));
      let at = 2;
      while (at < end) {
        const length = data[at];
        const value = data.subarray(at + 1, at + 1 + length);
        at += 1 + length;
        if (at > end) {
          break;
        }
        if (!hello.firstAlpn) {
          hello.firstAlpn = Buffer.from(value);
        }
        hello.alpn.push(value.toString('latin1'));
      }
    } else if (type === EXT_SIGNATURE_ALGORITHMS && data.length >= 2) {
      const end = Math.min(data.length, 2 + data.readUInt16BE(0));
      for (let at = 2; at + 2 <= end; at += 2) {
        hello.signatureAlgorithms.push(data.readUInt16BE(at));
      }
    } else if (type === EXT_SUPPORTED_VERSIONS && data.length >= 1) {
      // In a ClientHello: a one-byte length, then the versions.
      const end = Math.min(data.length, 1 + data[0]);
      for (let at = 1; at + 2 <= end; at += 2) {
        hello.supportedVersions.push(data.readUInt16BE(at));
      }
    }
    log.debug("Leaving ClientHello.readExtension().");
  }

  // Four lowercase hex digits, as JA4 writes every value.
  private static hex4(value: number): string {
    return ('000' + value.toString(16)).slice(-4);
  }

  // A count as JA4 writes it: two digits, capped at 99.
  private static count2(value: number): string {
    return ('0' + Math.min(99, value)).slice(-2);
  }

  // -------------------------------------------------------------------------
  // ja4(hello, transport) — FoxIO's JA4, from a parsed ClientHello.
  //
  //   a: transport ('t' TCP), version, 'd' with SNI or 'i' without, the
  //      cipher and extension counts (GREASE not counted), and the first and
  //      last characters of the first ALPN value ('00' with none; the first
  //      and last hex digits when either end is not alphanumeric).
  //   b: the first 12 hex of SHA-256 over the ciphers, sorted, comma-joined.
  //   c: the same over the extensions, sorted, with SNI and ALPN left out
  //      (they are counted in a), then '_' and the signature algorithms in
  //      the order sent.
  //
  // GREASE is left out of every list. An empty list hashes to twelve zeros,
  // and with no signature algorithms part c has no '_' — both the
  // specification's own rules.
  // -------------------------------------------------------------------------
  static ja4(hello: ParsedHello, transport?: string): string {
    log.debug("Entering ClientHello.ja4().");
    const real = function (value) {
      return !ClientHello.isGrease(value);
    };
    const versions = hello.supportedVersions.filter(real);
    const highest = versions.length ? Math.max.apply(null, versions)
                                    : hello.version;
    const version = VERSION_LABELS[highest] || '00';
    const ciphers = hello.ciphers.filter(real);
    const extensions = hello.extensions.filter(real);
    const a = (transport || 't') + version +
      (hello.extensions.indexOf(EXT_SERVER_NAME) >= 0 ? 'd' : 'i') +
      ClientHello.count2(ciphers.length) +
      ClientHello.count2(extensions.length) +
      ClientHello.alpnMark(hello.firstAlpn);
    const zeros = '000000000000';
    const sortedHex = function (list) {
      return list.map(ClientHello.hex4).sort().join(',');
    };
    const b = ciphers.length
      ? stsCrypto.truncatedSha256Hex(sortedHex(ciphers), 12) : zeros;
    const hashed = extensions.filter(function (value) {
      return value !== EXT_SERVER_NAME && value !== EXT_ALPN;
    });
    const algorithms = hello.signatureAlgorithms.filter(real)
      .map(ClientHello.hex4).join(',');
    const c = extensions.length
      ? stsCrypto.truncatedSha256Hex(sortedHex(hashed) +
                                     (algorithms ? '_' + algorithms : ''), 12)
      : zeros;
    log.debug("Leaving ClientHello.ja4().");
    return a + '_' + b + '_' + c;
  }

  // The two ALPN characters of JA4's part a.
  private static alpnMark(first: Buffer | null): string {
    log.debug("Entering ClientHello.alpnMark().");
    if (!first || !first.length) {
      log.debug("Leaving ClientHello.alpnMark(). None.");
      return '00';
    }
    const alphanumeric = function (byte) {
      return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) ||
             (byte >= 0x61 && byte <= 0x7a);
    };
    const firstByte = first[0];
    const lastByte = first[first.length - 1];
    if (alphanumeric(firstByte) && alphanumeric(lastByte)) {
      log.debug("Leaving ClientHello.alpnMark().");
      return String.fromCharCode(firstByte) + String.fromCharCode(lastByte);
    }
    const hex = first.toString('hex');
    log.debug("Leaving ClientHello.alpnMark(). Hex.");
    return hex[0] + hex[hex.length - 1];
  }

  // What `of()` answers, built from a parsed hello.
  static describe(hello: ParsedHello): HelloInfo {
    log.debug("Entering ClientHello.describe().");
    const versions = hello.supportedVersions.filter(function (value) {
      return !ClientHello.isGrease(value);
    });
    const highest = versions.length ? Math.max.apply(null, versions)
                                    : hello.version;
    log.debug("Leaving ClientHello.describe().");
    return {
      ja4: ClientHello.ja4(hello, 't'),
      version: VERSION_LABELS[highest] || '00',
      // Bounded, because the bytes are a stranger's and this is copied into
      // a header and onto authentication events.
      sni: hello.serverName.slice(0, 253),
      alpn: hello.alpn.slice(0, 8).map(function (one) {
        return one.slice(0, 32);
      })
    };
  }

  // Which connection a socket is, as both the raw socket and the TLS socket
  // around it report it.
  private static connectionKey(socket: any): string {
    log.debug("Entering ClientHello.connectionKey().");
    log.debug("Leaving ClientHello.connectionKey().");
    return String(socket.remoteAddress || '') + '|' +
           String(socket.remotePort || '') + '|' +
           String(socket.localPort || '');
  }

  // -------------------------------------------------------------------------
  // install(server, { label }) — see the header. Idempotent per server.
  // -------------------------------------------------------------------------
  install(server: any, options?: { label?: string } | null): boolean {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ClientHello.install().");
    const label = String((options && options.label) || 'a listener');
    if (!server || server[SEEN]) {
      log.debug("Leaving ClientHello.install(). Nothing to do.");
      return false;
    }
    server[SEEN] = true;
    const originalEmit = server.emit;

    function deliver(socket) {
      log.debug("Entering deliver().");
      socket[SEEN] = true;
      originalEmit.call(server, 'connection', socket);
      log.debug("Leaving deliver().");
    }

    function capture(socket) {
      log.debug("Entering capture().");
      let buffered = Buffer.alloc(0);
      let finished = false;

      function handOver(outcome) {
        log.debug("Entering handOver(). " + outcome);
        finished = true;
        clearTimeout(timer);
        socket.removeListener('data', onData);
        socket.removeListener('error', onDone);
        socket.removeListener('close', onDone);
        socket.pause();
        if (buffered.length) {
          socket.unshift(buffered);
        }
        if (!socket.destroyed) {
          deliver(socket);
        }
        log.debug("Leaving handOver().");
      }

      function onData(chunk) {
        log.debug("Entering onData(). " + chunk.length);
        if (finished) {
          log.debug("Leaving onData(). Finished.");
          return;
        }
        buffered = buffered.length ? Buffer.concat([buffered, chunk]) : chunk;
        if (buffered.length > MAX_HELLO_BYTES) {
          counters.overLimit += 1;
          handOver('over the limit');
          log.debug("Leaving onData(). Over the limit.");
          return;
        }
        const parsed = ClientHello.parse(buffered);
        if (parsed.state === 'incomplete') {
          log.debug("Leaving onData(). Incomplete.");
          return;
        }
        if (parsed.state === 'invalid') {
          if (buffered[0] === RECORD_HANDSHAKE) {
            counters.unparsed += 1;
          } else {
            counters.notTls += 1;
          }
          log.debug('tls: ' + label + ' — no fingerprint for ' +
                    socket.remoteAddress + ': ' + parsed.reason + '.');
          handOver('invalid');
          log.debug("Leaving onData(). Invalid.");
          return;
        }
        const info = ClientHello.describe(parsed.hello);
        if (self.waiting.size >= MAX_PENDING) {
          const oldest = self.waiting.keys().next().value;
          self.waiting.delete(oldest);
        }
        const key = ClientHello.connectionKey(socket);
        self.waiting.set(key, info);
        socket.once('close', function () {
          self.waiting.delete(key);
        });
        counters.fingerprinted += 1;
        handOver('fingerprinted');
        log.debug("Leaving onData(). " + info.ja4);
      }

      // The client went away while being read: nothing to hand over.
      function onDone() {
        log.debug("Entering onDone().");
        finished = true;
        clearTimeout(timer);
        socket.removeListener('data', onData);
        log.debug("Leaving onDone().");
      }

      const timer = setTimeout(function () {
        log.debug("Entering the ClientHello wait's timeout.");
        if (!finished) {
          counters.timedOut += 1;
          handOver('timed out');
        }
        log.debug("Leaving the ClientHello wait's timeout.");
      }, HELLO_WAIT_MS);
      socket.on('data', onData);
      socket.once('error', onDone);
      socket.once('close', onDone);
      log.debug("Leaving capture().");
    }

    // Anonymous and unlogged, for `proxy_protocol.ts`'s reason: `emit` runs
    // for every event the server raises, and only a first `connection` is
    // this file's business. capture() logs that.
    server.emit = function (event, socket) {
      if (event !== 'connection' || !socket || socket[SEEN]) {
        return originalEmit.apply(server, arguments);
      }
      capture(socket);
      return true;
    };
    // THE TLS SOCKET COLLECTS WHAT ITS RAW SOCKET SAID. Anonymous: it runs
    // once per handshake.
    server.on('secureConnection', function (tlsSocket) {
      const key = ClientHello.connectionKey(tlsSocket);
      const info = self.waiting.get(key);
      if (info) {
        self.waiting.delete(key);
        tlsSocket[INFO] = info;
      }
    });
    log.info('tls: ' + label + ' records each client\'s JA4 TLS fingerprint.');
    log.debug("Leaving ClientHello.install().");
    return true;
  }

  // -------------------------------------------------------------------------
  // of(req) — the connection's fingerprint, or null: none was read (plain
  // HTTP, a hello that did not parse), or the request came from somewhere
  // with no TLS of its own and nobody forwarded one.
  // -------------------------------------------------------------------------
  of(req: any): HelloInfo | null {
    const { log } = this.deps;
    log.debug("Entering ClientHello.of().");
    const found = (req && req[INFO]) ||
                  (req && req.socket && req.socket[INFO]) || null;
    log.debug("Leaving ClientHello.of(). " + (found ? found.ja4 : 'none'));
    return found;
  }

  // The header value `request_pool.js` forwards, or '' for none.
  encodeForward(req: any): string {
    const { log } = this.deps;
    log.debug("Entering ClientHello.encodeForward().");
    const info = this.of(req);
    log.debug("Leaving ClientHello.encodeForward().");
    return info ? Buffer.from(JSON.stringify(info), 'utf8')
      .toString('base64url') : '';
  }

  // -------------------------------------------------------------------------
  // adoptForwarded(req) — in a request worker: read the forwarded header,
  // put a well-formed answer on the request, and strip the header either way.
  // The header is trusted because the worker's socket is reachable only by
  // the front process, which strips it from what a client sent — the reason
  // `request_worker.ts` gives for the certificate headers — and it is still
  // checked for shape, because a header that fails to parse must not become
  // a string on an authentication event.
  // -------------------------------------------------------------------------
  adoptForwarded(req: any): void {
    const { log } = this.deps;
    log.debug("Entering ClientHello.adoptForwarded().");
    const encoded = req && req.headers ? req.headers[FORWARD_HEADER] : '';
    if (!encoded) {
      log.debug("Leaving ClientHello.adoptForwarded(). None.");
      return;
    }
    delete req.headers[FORWARD_HEADER];
    let info = null;
    try {
      info = JSON.parse(Buffer.from(String(encoded), 'base64url')
        .toString('utf8'));
    } catch (e) {
      log.debug("Caught in ClientHello.adoptForwarded(): " +
                ((e && e.message) || e));
      // A header only the front process writes that does not parse is a bug
      // there, and the request goes on without a fingerprint.
      info = null;
    }
    if (info && typeof info.ja4 === 'string' && JA4_SHAPE.test(info.ja4)) {
      req[INFO] = {
        ja4: info.ja4,
        version: String(info.version || '').slice(0, 2),
        sni: String(info.sni || '').slice(0, 253),
        alpn: Array.isArray(info.alpn)
          ? info.alpn.slice(0, 8).map(function (one) {
              return String(one).slice(0, 32);
            })
          : []
      };
    }
    log.debug("Leaving ClientHello.adoptForwarded().");
  }

  // For a report page and the tests.
  report(): Record<string, number> {
    const { log } = this.deps;
    log.debug("Entering ClientHello.report().");
    log.debug("Leaving ClientHello.report().");
    return Object.assign({ waiting: this.waiting.size }, counters);
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), with facades for the
// JavaScript callers (`server.js`, `request_pool.js`) — `proxy_protocol.ts`'s
// arrangement.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ClientHello>(
  'tls/client_hello',
  () => new ClientHello(ClientHello.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

export = {
  ClientHello: ClientHello,
  installInstance: (instance: ClientHello): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  FORWARD_HEADER: ClientHello.FORWARD_HEADER,
  MAX_HELLO_BYTES: ClientHello.MAX_HELLO_BYTES,
  parse: ClientHello.parse,
  ja4: ClientHello.ja4,
  describe: ClientHello.describe,
  isGrease: ClientHello.isGrease,
  install: slot.forward('install'),
  of: slot.forward('of'),
  encodeForward: slot.forward('encodeForward'),
  adoptForwarded: slot.forward('adoptForwarded'),
  report: slot.forward('report')
};
