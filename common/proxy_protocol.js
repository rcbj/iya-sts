'use strict';
//
// File: common/proxy_protocol.js
//
// ===========================================================================
// THE PROXY PROTOCOL, VERSION 2, ON EVERY TCP LISTENER THIS SERVICE OWNS
// (2026-09-14, #46).
//
// Behind an L4 load balancer — an AWS Network Load Balancer with TLS
// PASSTHROUGH is the case this was written for — the TCP peer of every
// connection is the balancer, not the client. `common/client_address.js`
// cannot help there: it believes `X-Forwarded-For`, which only an L7 hop that
// terminated TLS can write, and terminating TLS at the balancer is exactly
// what a deployment of this service must not do (mutual TLS, RFC 8705,
// certificate sign-in, the XACML certificate gates — `common/CLAUDE.md`,
// *Mutual TLS needs L4 passthrough*). So the client's address has to arrive
// BELOW TLS, and the HAProxy PROXY protocol is how every L4 balancer that
// offers it sends it: a binary header written at the very front of the TCP
// stream, before the ClientHello, before an LDAP BindRequest, before a
// Kerberos length prefix.
//
// `global.proxyProtocol` is `off` (the default: this file is never installed
// and nothing changes) or `v2`. Version 1 — a text line — is refused rather
// than parsed: AWS sends v2 only, HAProxy sends v2 with `send-proxy-v2`, and a
// second parser is a second place to get a length wrong.
//
// ---------------------------------------------------------------------------
// WHO MAY SEND ONE, AND WHY A STRANGER IS REFUSED RATHER THAN SERVED PLAIN.
//
// The header is believed from `global.trustedProxies` and from nobody else —
// the SAME list `client_address.js` reads, because the question is the same
// question ("which peers are hops this deployment runs?") asked one layer
// down, and two lists would be two answers to it that drift. A connection:
//
//   1. **from a trusted address MUST begin with a valid v2 header**, or it is
//      closed. There is no "plain if the signature is absent" fallback for a
//      remote trusted peer: the balancer ALWAYS sends one once the target
//      group has it on, so a trusted peer with no header is a misconfigured
//      balancer (or a second path through the same subnet), and serving it
//      plain would record the balancer as the client — the failure this file
//      exists to end — with nothing saying so.
//   2. **from an address that is not trusted is REFUSED**, not served as a
//      plain connection. Serving it plain would claim no address, true; but a
//      node reachable directly when the deployment says every client comes
//      through the balancer is a network fault, and a node that quietly
//      answers it hides that fault — while the per-address rate limiter, the
//      audit and every refusal then see an address the balancer never vetted.
//      Closing it is what makes "the balancer is the only way in" a property
//      the node enforces rather than one the security group is trusted with.
//   3. **from THIS HOST ITSELF — a loopback peer, or a peer whose address is
//      the connection's own local address — is served plain**, and this is
//      the one exception, argued: the service dials itself. The OpenID
//      Connect back channel of `/admin` and `/portal` (`common/oidc_rp.js`),
//      the Shared Signals push to its own receivers (`ssf/ssf_http.js`) and
//      every request worker's back channel open a TCP connection to
//      `helpers.loopbackHost()` on the main port and write no header — so
//      refusing them would break sign-in to the console the moment this
//      setting is on. A same-host peer cannot be forged from the network
//      (the kernel drops a packet arriving from outside with a local source
//      address as martian), and a plain connection reads NO header, so it
//      claims no address either — anything it sends first goes to the
//      protocol parser as protocol bytes. A container HEALTHCHECK that curls
//      localhost lands here too.
//
//      A same-host peer that is ALSO in `global.trustedProxies` — a sidecar
//      proxy on 127.0.0.1 — is served either way: a header is read when the
//      first bytes carry the v2 signature and the connection is plain when
//      they do not, because both that proxy and the service's own back
//      channel connect from the same address. The twelve-byte signature was
//      designed for exactly this test: it begins `\r\n\r\n\0`, which no
//      HTTP request line, TLS record, LDAP message or Kerberos length prefix
//      can start with.
//
// ---------------------------------------------------------------------------
// HEALTH CHECKS, AND THE `LOCAL` COMMAND.
//
// **AWS: VERIFIED AGAINST ITS DOCUMENTATION on 2026-09-14** (Network Load
// Balancers, *Edit target group attributes*, *Health check connections*):
// "After you enable proxy protocol, the proxy protocol header is also
// included in health check connections from the load balancer. However, with
// health check connections, the client connection information is not sent in
// the proxy protocol header." So a health check arrives from a balancer node's
// private address — trusted — with a header that carries no client: the
// `LOCAL` command, or `PROXY` with the `UNSPEC` family. Both are ACCEPTED and
// the connection keeps the socket's own address, which is what the
// specification says a receiver does with either. The same page is why the
// header is required rather than sniffed: "Targets can fail health checks if
// they can't parse the proxy protocol header."
//
// HAProxy sends a header on its health checks when the server line has
// `send-proxy-v2` and no `port`/`addr` override, or with `check-send-proxy`.
//
// The same AWS page says a TCP listener "does not discard or overwrite any
// existing data, including any incoming proxy protocol headers sent by the
// client" — so a client can put a SECOND header behind the balancer's. Only
// the first is read here; anything after it is protocol bytes, and a v2
// signature in front of an HTTP request is a 400, not an address.
//
// ---------------------------------------------------------------------------
// WHERE THE ADDRESS GOES, AND WHY IT IS THE SOCKET AND NOT A FIELD.
//
// Everything that asks where a connection came from asks the SOCKET:
// express's `req.ip` and `client_address.js` read `req.socket.remoteAddress`,
// `ldap_server.js`'s bind limiter and audit read the ldapjs connection's,
// `tls_server.js`'s whoami and handshake refusals read the TLS socket's, and
// `request_pool.js` forwards `clientAddressOf(req)` to a worker. A field of
// our own would have to be taught to each of those readers and to every one
// written after them. So the address is put where they already look: the
// connection's native handle is given an own `getpeername()` answering the
// header's source, and the socket's cached peer name is set to it.
//
// The handle rather than the JS socket for one reason, measured: a TLS server
// wraps the raw socket in a `TLSSocket` whose `remoteAddress` does not ask the
// raw socket at all — it asks ITS handle, a TLSWrap, whose `getpeername` is
// proxied to the underlying TCP handle (node's `_tls_wrap.js`,
// `makeMethodProxy`). Shadowing the TCP handle's method is the one place both
// sockets, and anything node builds over them, read from.
//
// ---------------------------------------------------------------------------
// HOW THE HEADER IS TAKEN OFF BEFORE TLS, WITHOUT A SECOND LISTENER.
//
// `install(server)` shadows the server's own `emit` for one event,
// `connection`: the raw socket is held back while the header is read, then
// the event is emitted for real — so EVERY `connection` listener, the TLS
// handshake that `tls.Server` installed at construction and anything added
// after `install()`, sees a socket whose header is gone and whose address is
// the client's. Wrapping emit rather than listening in front of it is what
// keeps `server.listen()`, `address()`, `setSecureContext()` and
// `getConnections()` exactly as every listener module already calls them, on
// the same object; a second `net.Server` in front would have needed each of
// those re-plumbed at seven call sites.
//
// Bytes that arrived with the header — a ClientHello coalesced into the same
// segment, which is ordinary — are UNSHIFTED back onto the paused socket.
// `tls.Server` drains a socket's buffered bytes into the TLS engine when it
// wraps it; `http.Server` and the plain `net` listeners receive them as their
// first `data` event once the socket is resumed. Measured for all three
// before this was written: without the resume a plain `http.Server` answered
// `408` because the unshifted request line was never delivered.
//
// A LIBRARY (rule 3): it registers no route. It requires `net`, bunyan,
// `config`, `client_address` and `error_codes`, and `audit` lazily. It is
// installed from each socket owner's `listen()` and from `server.js` — the
// KDC's TCP listener from `server.js` rather than `krb5_kdc.js`, so that this
// file does not join the parent project's Kerberos COPY set
// (`kerberos/CLAUDE.md`).
// ===========================================================================

const net = require('net');
const tls = require('tls');
const bunyan = require('bunyan');
const config = require('./config');
const clientAddress = require('./client_address');
const errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-proxy-protocol' });
config.registerLogger(log);

// The twelve bytes every v2 header begins with (the specification, section
// 2.2).
const SIGNATURE = Buffer.from([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
                               0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]);
const PREFIX_LENGTH = 16;
// A version 1 header begins with these six bytes, so a balancer configured
// for v1 is named rather than reported as "not a header".
const V1_PREFIX = Buffer.from('PROXY ', 'ascii');

// ---------------------------------------------------------------------------
// THE LARGEST ADDRESS-AND-TLV BLOCK READ, AND IT IS A PROTOCOL BOUND RATHER
// THAN A TUNABLE. The length field is sixteen bits, so a sender may declare
// 65 535 bytes, and a connection from a trusted address that declares that
// and trickles it would hold 64 KiB per connection until the timeout. The
// largest header a real sender writes is a UNIX-family block (216 bytes) plus
// its TLVs — HAProxy's SSL sub-TLVs carry a certificate's CN and cipher name,
// AWS's 0xEA carries a VPC endpoint id of about 22 bytes — so 4 096 is more
// than ten times anything seen, and a header over it is refused before it is
// buffered.
// ---------------------------------------------------------------------------
const MAX_BLOCK_LENGTH = 4096;

// The address blocks' sizes per family (section 2.2): two IPv4 addresses and
// two ports; two IPv6 addresses and two ports; two 108-byte paths.
const FAMILY = { 0x0: 'UNSPEC', 0x1: 'INET', 0x2: 'INET6', 0x3: 'UNIX' };
const FAMILY_BLOCK = { UNSPEC: 0, INET: 12, INET6: 36, UNIX: 216 };
const TRANSPORT = { 0x0: 'UNSPEC', 0x1: 'STREAM', 0x2: 'DGRAM' };

// The TLV types this file reads; every other type is carried in `tlvs` and
// otherwise ignored, as section 2.2.x asks.
const PP2_TYPE_ALPN = 0x01;
const PP2_TYPE_AUTHORITY = 0x02;
const PP2_TYPE_CRC32C = 0x03;
const PP2_TYPE_AWS = 0xEA;
const PP2_SUBTYPE_AWS_VPCE_ID = 0x01;

// ---------------------------------------------------------------------------
// CRC32C (Castagnoli), for PP2_TYPE_CRC32C. HAProxy verifies it when present
// and so does this: a checksum a sender went to the trouble of writing and a
// receiver ignores is a corrupted header believed.
// ---------------------------------------------------------------------------
const CRC32C_TABLE = (function () {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0x82F63B78 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c;
  }
  return table;
})();

// No Entering/Leaving pair: it is called once per byte-run of a header and
// its loop body is the whole function — a log line here says nothing the
// caller's does not.
function crc32c(bytes) {
  let crc = -1;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32C_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ -1) >>> 0;
}

function invalid(code, reason) {
  log.debug("Entering invalid().");
  log.debug("Leaving invalid().");
  return { state: 'invalid', code: code, reason: reason };
}

function ipv6Of(bytes) {
  log.debug("Entering ipv6Of().");
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(bytes.readUInt16BE(i).toString(16));
  }
  // `net.SocketAddress` canonicalises — `2001:db8:0:0:0:0:0:1` comes back as
  // `2001:db8::1`, the form node itself reports for a peer.
  const text = groups.join(':');
  try {
    const canonical = new net.SocketAddress({ address: text,
                                              family: 'ipv6' }).address;
    log.debug("Leaving ipv6Of().");
    return canonical;
  } catch (e) {
    log.debug("Caught in ipv6Of(): " + ((e && e.message) || e));
    log.debug("Leaving ipv6Of(). Uncanonicalised.");
    return text;
  }
}

function unixPathOf(bytes) {
  log.debug("Entering unixPathOf().");
  const end = bytes.indexOf(0);
  log.debug("Leaving unixPathOf().");
  return bytes.subarray(0, end >= 0 ? end : bytes.length).toString('utf8');
}

// The TLV vectors after the address block. Malformed — a vector whose length
// runs past the block — is REFUSED, as HAProxy refuses it: a header whose own
// structure does not parse is not one whose addresses should be believed.
function tlvsOf(block) {
  log.debug("Entering tlvsOf().");
  const tlvs = [];
  let offset = 0;
  while (offset < block.length) {
    if (block.length - offset < 3) {
      log.debug("Leaving tlvsOf(). A truncated TLV.");
      return null;
    }
    const type = block[offset];
    const length = block.readUInt16BE(offset + 1);
    if (offset + 3 + length > block.length) {
      log.debug("Leaving tlvsOf(). A TLV longer than the block.");
      return null;
    }
    tlvs.push({ type: type, offset: offset + 3,
                value: block.subarray(offset + 3, offset + 3 + length) });
    offset += 3 + length;
  }
  log.debug("Leaving tlvsOf(). " + tlvs.length + " TLV(s).");
  return tlvs;
}

// ---------------------------------------------------------------------------
// parse(bytes) — the header at the front of `bytes`, which may be a PREFIX of
// the stream (a header split across TCP segments is ordinary).
//
//   { state: 'incomplete' }                     read more and ask again
//   { state: 'invalid', code, reason }          close the connection
//   { state: 'complete', length, header }       `length` bytes are the header
//
// It never waits to refuse: a first byte that cannot begin a v2 signature is
// answered at once, so a plain HTTP request from a trusted address is closed
// on its first segment rather than at the timeout.
// ---------------------------------------------------------------------------
function parse(bytes) {
  log.debug("Entering parse(). bytes=" + (bytes ? bytes.length : 0));
  const buffer = bytes || Buffer.alloc(0);
  const seen = Math.min(buffer.length, SIGNATURE.length);
  if (buffer.subarray(0, seen).equals(SIGNATURE.subarray(0, seen)) === false) {
    const v1Seen = Math.min(buffer.length, V1_PREFIX.length);
    if (buffer.subarray(0, v1Seen).equals(V1_PREFIX.subarray(0, v1Seen))) {
      if (v1Seen < V1_PREFIX.length) {
        log.debug("Leaving parse(). Perhaps a v1 line; waiting.");
        return { state: 'incomplete' };
      }
      log.debug("Leaving parse(). A v1 header.");
      return invalid('STS-PROXY-0003', 'a PROXY protocol version 1 (text) ' +
                     'header, and global.proxyProtocol accepts version 2 only');
    }
    log.debug("Leaving parse(). No signature.");
    return invalid('STS-PROXY-0002', 'the connection did not begin with the ' +
                   'PROXY protocol v2 signature');
  }
  if (buffer.length < PREFIX_LENGTH) {
    log.debug("Leaving parse(). Incomplete prefix.");
    return { state: 'incomplete' };
  }
  const version = buffer[12] >> 4;
  const command = buffer[12] & 0x0F;
  const familyName = FAMILY[buffer[13] >> 4];
  const transportName = TRANSPORT[buffer[13] & 0x0F];
  const blockLength = buffer.readUInt16BE(14);
  if (version !== 2) {
    log.debug("Leaving parse(). Version " + version + ".");
    return invalid('STS-PROXY-0004', 'the version nibble is ' + version +
                   ', not 2');
  }
  if (command !== 0 && command !== 1) {
    log.debug("Leaving parse(). Command " + command + ".");
    return invalid('STS-PROXY-0004', 'the command nibble is ' + command +
                   ', neither LOCAL (0) nor PROXY (1)');
  }
  if (blockLength > MAX_BLOCK_LENGTH) {
    log.debug("Leaving parse(). Oversize: " + blockLength + ".");
    return invalid('STS-PROXY-0005', 'the header declares ' + blockLength +
                   ' bytes of addresses and TLVs, over the ' +
                   MAX_BLOCK_LENGTH + ' this service reads');
  }
  if (buffer.length < PREFIX_LENGTH + blockLength) {
    log.debug("Leaving parse(). Incomplete block.");
    return { state: 'incomplete' };
  }
  const total = PREFIX_LENGTH + blockLength;
  const block = buffer.subarray(PREFIX_LENGTH, total);
  const header = {
    version: 2,
    command: command === 0 ? 'LOCAL' : 'PROXY',
    family: familyName || null,
    transport: transportName || null,
    source: null,
    destination: null,
    tlvs: [],
    authority: null,
    alpn: null,
    awsVpceId: null
  };
  // Section 2.2: with LOCAL "the receiver must accept this connection as
  // valid and must use the real connection endpoints and discard the protocol
  // block including the family", so the family and transport nibbles are
  // judged for PROXY only.
  let addressLength = 0;
  if (header.command === 'PROXY') {
    if (!familyName || !transportName) {
      log.debug("Leaving parse(). Unknown family or transport.");
      return invalid('STS-PROXY-0004', 'the address family or transport ' +
                     'byte is 0x' + buffer[13].toString(16) + ', which the ' +
                     'specification defines no meaning for');
    }
    addressLength = FAMILY_BLOCK[familyName];
    if (blockLength < addressLength) {
      log.debug("Leaving parse(). Address block too short.");
      return invalid('STS-PROXY-0004', 'the header declares ' + blockLength +
                     ' bytes, shorter than the ' + addressLength + ' an ' +
                     familyName + ' address block needs');
    }
    if (familyName === 'INET') {
      header.source = { address: Array.from(block.subarray(0, 4)).join('.'),
                        port: block.readUInt16BE(8), family: 'IPv4' };
      header.destination = { address:
                               Array.from(block.subarray(4, 8)).join('.'),
                             port: block.readUInt16BE(10), family: 'IPv4' };
    } else if (familyName === 'INET6') {
      header.source = { address: ipv6Of(block.subarray(0, 16)),
                        port: block.readUInt16BE(32), family: 'IPv6' };
      header.destination = { address: ipv6Of(block.subarray(16, 32)),
                             port: block.readUInt16BE(34), family: 'IPv6' };
    } else if (familyName === 'UNIX') {
      // Recorded for the report and NOT made the peer: a path is not an
      // address anything here can rate-limit or compare against a range.
      header.source = { path: unixPathOf(block.subarray(0, 108)) };
      header.destination = { path: unixPathOf(block.subarray(108, 216)) };
    }
  }
  // Under LOCAL the whole block is discarded, TLVs included — there is
  // nothing to parse them relative to that the specification promises.
  if (header.command === 'PROXY') {
    const tlvs = tlvsOf(block.subarray(addressLength));
    if (!tlvs) {
      log.debug("Leaving parse(). Malformed TLVs.");
      return invalid('STS-PROXY-0004', 'a TLV vector after the address ' +
                     'block runs past the declared length');
    }
    for (let i = 0; i < tlvs.length; i++) {
      const tlv = tlvs[i];
      if (tlv.type === PP2_TYPE_CRC32C) {
        if (tlv.value.length !== 4) {
          log.debug("Leaving parse(). A CRC32C TLV of the wrong size.");
          return invalid('STS-PROXY-0004', 'the CRC32C TLV is ' +
                         tlv.value.length + ' bytes, not 4');
        }
        const copy = Buffer.from(buffer.subarray(0, total));
        copy.fill(0, PREFIX_LENGTH + addressLength + tlv.offset,
                  PREFIX_LENGTH + addressLength + tlv.offset + 4);
        const expected = tlv.value.readUInt32BE(0);
        const computed = crc32c(copy);
        if (expected !== computed) {
          log.debug("Leaving parse(). CRC32C mismatch.");
          return invalid('STS-PROXY-0006', 'the CRC32C TLV says 0x' +
                         expected.toString(16) + ' and the header ' +
                         'computes to 0x' + computed.toString(16));
        }
      } else if (tlv.type === PP2_TYPE_AUTHORITY) {
        header.authority = tlv.value.toString('utf8');
      } else if (tlv.type === PP2_TYPE_ALPN) {
        header.alpn = tlv.value.toString('ascii');
      } else if (tlv.type === PP2_TYPE_AWS && tlv.value.length > 1 &&
                 tlv.value[0] === PP2_SUBTYPE_AWS_VPCE_ID) {
        header.awsVpceId = tlv.value.subarray(1).toString('ascii');
      }
      header.tlvs.push({ type: tlv.type, length: tlv.value.length });
    }
  }
  log.debug("Leaving parse(). " + header.command + " " + header.family +
            ", " + total + " byte(s).");
  return { state: 'complete', length: total, header: header };
}

// ---------------------------------------------------------------------------
// build(options) — a v2 header, for the tests and the live probe. The inverse
// of parse() over what this service reads: IPv4 or IPv6 PROXY, LOCAL, extra
// TLVs, and a CRC32C when asked.
// ---------------------------------------------------------------------------
function build(options) {
  log.debug("Entering build().");
  const opts = options || {};
  const local = opts.command === 'LOCAL';
  const source = opts.source || {};
  const destination = opts.destination || {};
  let family = 0x0;
  let addresses = Buffer.alloc(0);
  if (!local) {
    const isV6 = net.isIPv6(String(source.address || ''));
    family = isV6 ? 0x2 : 0x1;
    if (isV6) {
      addresses = Buffer.alloc(36);
      [source.address, destination.address || '::1'].forEach(function (a, i) {
        const socketAddress = new net.SocketAddress({ address: a,
                                                      family: 'ipv6' });
        const full = expandIpv6(socketAddress.address);
        full.copy(addresses, i * 16);
      });
      addresses.writeUInt16BE(source.port || 0, 32);
      addresses.writeUInt16BE(destination.port || 0, 34);
    } else {
      addresses = Buffer.alloc(12);
      String(source.address || '0.0.0.0').split('.').forEach(function (o, i) {
        addresses[i] = Number(o);
      });
      String(destination.address || '127.0.0.1').split('.')
        .forEach(function (o, i) {
          addresses[4 + i] = Number(o);
        });
      addresses.writeUInt16BE(source.port || 0, 8);
      addresses.writeUInt16BE(destination.port || 0, 10);
    }
  }
  const tlvParts = (opts.tlvs || []).map(function (tlv) {
    const value = Buffer.from(tlv.value || []);
    const head = Buffer.alloc(3);
    head[0] = tlv.type;
    head.writeUInt16BE(value.length, 1);
    return Buffer.concat([head, value]);
  });
  if (opts.crc32c) {
    tlvParts.push(Buffer.from([PP2_TYPE_CRC32C, 0x00, 0x04, 0, 0, 0, 0]));
  }
  const block = Buffer.concat([addresses].concat(tlvParts));
  const prefix = Buffer.alloc(PREFIX_LENGTH);
  SIGNATURE.copy(prefix, 0);
  prefix[12] = 0x20 | (local ? 0x0 : 0x1);
  prefix[13] = (family << 4) | (local ? 0x0 : 0x1);
  prefix.writeUInt16BE(opts.declaredLength !== undefined
    ? opts.declaredLength : block.length, 14);
  const out = Buffer.concat([prefix, block]);
  if (opts.crc32c) {
    out.writeUInt32BE(crc32c(out), out.length - 4);
  }
  log.debug("Leaving build(). " + out.length + " byte(s).");
  return out;
}

function expandIpv6(address) {
  log.debug("Entering expandIpv6().");
  const halves = String(address).split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  const groups = head.concat(new Array(Math.max(missing, 0)).fill('0'),
                             tail);
  const out = Buffer.alloc(16);
  groups.forEach(function (group, i) {
    out.writeUInt16BE(parseInt(group, 16) || 0, i * 2);
  });
  log.debug("Leaving expandIpv6().");
  return out;
}

// ---------------------------------------------------------------------------
// THE SETTING, AND THE STARTUP REFUSAL.
// ---------------------------------------------------------------------------
function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
  return String(config.value('global.proxyProtocol') || 'off') === 'v2';
}

function headerTimeoutMs() {
  log.debug("Entering headerTimeoutMs().");
  const raw = Number(config.value('global.proxyProtocolTimeoutMs'));
  log.debug("Leaving headerTimeoutMs().");
  return Number.isFinite(raw) && raw > 0 ? raw : 5000;
}

// A non-empty sentence when `v2` is on with no usable trusted range. Such a
// process would either refuse every connection that did not start on its own
// host or — if an empty list meant "anybody", as it does for forwarded
// headers — let any caller that reaches a node name any client address it
// likes. Neither is a service, so `server.js` does not start it.
function startupProblem() {
  log.debug("Entering startupProblem().");
  if (!enabled()) {
    log.debug("Leaving startupProblem(). Off.");
    return '';
  }
  const ranges = clientAddress.trustedProxyRanges();
  if (ranges.count > 0) {
    log.debug("Leaving startupProblem(). " + ranges.count + " range(s).");
    return '';
  }
  log.debug("Leaving startupProblem(). No usable range.");
  return 'global.proxyProtocol is v2 and global.trustedProxies holds ' +
         (ranges.configured ? 'no entry that is an address or a CIDR range ' +
                              '(' + ranges.configured + ' ignored)'
                            : 'nothing') +
         ', so no connection could be believed. Set global.trustedProxies ' +
         '(STS_TRUSTED_PROXIES) to the addresses the load balancer connects ' +
         'from — for an AWS Network Load Balancer, the private addresses of ' +
         'its nodes, the CIDRs of the subnets it is in — or set ' +
         'global.proxyProtocol back to off.';
}

// ---------------------------------------------------------------------------
// WHAT HAS HAPPENED, FOR A READER THAT WANTS A NUMBER RATHER THAN A LOG.
// ---------------------------------------------------------------------------
const counters = {
  proxied: 0,
  local: 0,
  sameHost: 0,
  closedEmpty: 0,
  refused: {}
};
const installed = [];

// What the header said, on the raw socket; and the mark that a socket has
// been through `install()`'s gate once, so the real `connection` emit is not
// intercepted a second time.
const INFO = Symbol('sts.proxyProtocol');
const SEEN = Symbol('sts.proxyProtocolSeen');

function report() {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return {
    mode: enabled() ? 'v2' : 'off',
    headerTimeoutMs: headerTimeoutMs(),
    maxBlockLength: MAX_BLOCK_LENGTH,
    listeners: installed.slice(),
    proxied: counters.proxied,
    local: counters.local,
    sameHost: counters.sameHost,
    closedEmpty: counters.closedEmpty,
    refused: Object.assign({}, counters.refused)
  };
}

// What the header said about the connection `socket` — or the TLS socket
// built over it — or null when none was read.
function describe(socket) {
  log.debug("Entering describe().");
  let one = socket;
  for (let i = 0; one && i < 3; i++) {
    if (one[INFO]) {
      log.debug("Leaving describe(). Found.");
      return one[INFO];
    }
    one = one._parent || null;
  }
  log.debug("Leaving describe(). None.");
  return null;
}

// ---------------------------------------------------------------------------
// ONE AUDIT ROW PER SOURCE AND CODE PER MINUTE.
//
// A refusal is recorded on the audit ring, which is capped — and the
// connections refused here are exactly the ones a stranger can open as fast
// as they like. A row per connection would let anybody who reaches a node
// directly push every real row out of the ring in a second. So the first
// refusal of a (code, address) pair in a minute is a row, and the rest are
// counted into `report()` and into the next row's summary. The map is bounded
// for the same reason.
// ---------------------------------------------------------------------------
const AUDIT_WINDOW_MS = 60 * 1000;
const AUDIT_MAX_KEYS = 1024;
const lastAudited = new Map();

function recordRefusal(code, reason, peer, label, channel) {
  log.debug("Entering recordRefusal(). " + code);
  counters.refused[code] = (counters.refused[code] || 0) + 1;
  const key = code + ' ' + peer;
  const now = Date.now();
  const previous = lastAudited.get(key);
  if (previous && now - previous.at < AUDIT_WINDOW_MS) {
    previous.suppressed += 1;
    log.debug('proxy: ' + errorCodes.tag(code) + label + ' closed a ' +
              'connection from ' + peer + ': ' + reason + ' (counted; ' +
              'already audited this minute).');
    log.debug("Leaving recordRefusal(). Suppressed.");
    return;
  }
  if (lastAudited.size >= AUDIT_MAX_KEYS) {
    lastAudited.clear();
  }
  const suppressed = previous ? previous.suppressed : 0;
  lastAudited.set(key, { at: now, suppressed: 0 });
  // Lazily, because audit.js requires helpers.js and this file is a leaf
  // every socket owner requires; by the time a connection arrives the whole
  // stack is loaded and this is a cache hit.
  require('./audit').failure(code, {
    protocol: 'PROXY protocol', channel: channel || 'tcp',
    target: label + ', from ' + peer,
    summary: 'a connection was closed before it reached the listener: ' +
             reason + (suppressed ? ' (and ' + suppressed + ' more like it ' +
                                    'from this address in the last minute)'
                                  : ''),
    // error-code: none — `code` is the caller's STS-PROXY code, passed in
    outcome: 'refused'
  });
  log.debug("Leaving recordRefusal().");
}

// For tests: every connection a test can open is from this host, so the
// refusals of a REMOTE peer are reachable in process only by telling this
// file what counts as this host. Null restores the real check.
let thisHostCheck = null;

function setThisHostCheck(fn) {
  log.debug("Entering setThisHostCheck().");
  thisHostCheck = typeof fn === 'function' ? fn : null;
  log.debug("Leaving setThisHostCheck().");
}

function isThisHost(peer, local) {
  log.debug("Entering isThisHost().");
  if (thisHostCheck) {
    log.debug("Leaving isThisHost(). The test's check.");
    return !!thisHostCheck(peer, local);
  }
  log.debug("Leaving isThisHost().");
  return isLoopback(peer) || (!!local && peer === local);
}

function isLoopback(address) {
  log.debug("Entering isLoopback().");
  const clean = clientAddress.normalise(address);
  log.debug("Leaving isLoopback().");
  return clean === '::1' || /^127\./.test(clean);
}

// ---------------------------------------------------------------------------
// PUT THE HEADER'S SOURCE WHERE EVERY READER LOOKS. See the header comment,
// *Where the address goes*.
// ---------------------------------------------------------------------------
function adoptSource(socket, source) {
  log.debug("Entering adoptSource(). " + source.address);
  const handle = socket._handle;
  const peer = { address: source.address, port: source.port,
                 family: source.family };
  if (handle) {
    handle.getpeername = function (out) {
      out.address = peer.address;
      out.port = peer.port;
      out.family = peer.family;
      return 0;
    };
  }
  // The JS socket caches what its handle answered the first time; the trust
  // check below read the balancer's address through it, so the cache is
  // replaced rather than trusted to be empty.
  socket._peername = Object.assign({}, peer);
  log.debug("Leaving adoptSource().");
}

// ---------------------------------------------------------------------------
// install(server, { label, channel }) — see the header, *How the header is
// taken off*. A no-op returning false when `global.proxyProtocol` is off, so
// a listener module calls it unconditionally. Idempotent per server.
// ---------------------------------------------------------------------------
function install(server, options) {
  log.debug("Entering install().");
  const opts = options || {};
  const label = String(opts.label || 'a listener');
  const channel = String(opts.channel || 'tcp');
  if (!server || !enabled()) {
    log.debug("Leaving install(). Off.");
    return false;
  }
  if (server[INFO]) {
    log.debug("Leaving install(). Already installed.");
    return true;
  }
  server[INFO] = { label: label };
  installed.push(label);
  const originalEmit = server.emit;

  function deliver(socket) {
    log.debug("Entering deliver().");
    originalEmit.call(server, 'connection', socket);
    log.debug("Leaving deliver().");
  }

  function readHeader(socket, peer, optional) {
    log.debug("Entering readHeader(). peer=" + peer);
    let buffered = Buffer.alloc(0);
    let finished = false;

    function finish() {
      log.debug("Entering finish().");
      finished = true;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('end', onEnd);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      log.debug("Leaving finish().");
    }

    function refuse(code, reason) {
      log.debug("Entering refuse(). " + code);
      finish();
      recordRefusal(code, reason, peer, label, channel);
      socket.destroy();
      log.debug("Leaving refuse().");
    }

    function handOver(rest) {
      log.debug("Entering handOver(). rest=" + rest.length);
      finish();
      socket.pause();
      if (rest.length) {
        socket.unshift(rest);
      }
      deliver(socket);
      // `tls.Server` has taken the socket's handle and drained what was
      // unshifted; resuming the raw socket there would start a second reader
      // on a handle the TLS engine owns. Every other server reads the raw
      // socket through `data`, and a socket this file paused would never
      // flow again.
      if (!(server instanceof tls.Server) && !socket.destroyed) {
        socket.resume();
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
      if (optional && buffered[0] !== SIGNATURE[0]) {
        counters.sameHost += 1;
        log.debug('proxy: ' + label + ' — ' + peer + ' is this host and ' +
                  'sent no header; served as a plain connection.');
        handOver(buffered);
        log.debug("Leaving onData(). Same host, plain.");
        return;
      }
      const parsed = parse(buffered);
      if (parsed.state === 'incomplete') {
        log.debug("Leaving onData(). Incomplete.");
        return;
      }
      if (parsed.state === 'invalid') {
        refuse(parsed.code, parsed.reason);
        log.debug("Leaving onData(). Invalid.");
        return;
      }
      const header = parsed.header;
      const info = { via: peer, command: header.command,
                     family: header.family, transport: header.transport,
                     source: header.source, destination: header.destination,
                     authority: header.authority, alpn: header.alpn,
                     awsVpceId: header.awsVpceId, tlvs: header.tlvs,
                     listener: label };
      socket[INFO] = info;
      if (header.command === 'PROXY' && header.source &&
          header.source.address) {
        adoptSource(socket, header.source);
        counters.proxied += 1;
        log.debug('proxy: ' + label + ' — ' + header.source.address + ':' +
                  header.source.port + ' via ' + peer + '.');
      } else {
        counters.local += 1;
        log.debug('proxy: ' + label + ' — a ' + header.command + ' header ' +
                  '(' + (header.family || 'no family') + ') from ' + peer +
                  '; the connection keeps the balancer\'s address.');
      }
      handOver(buffered.subarray(parsed.length));
      log.debug("Leaving onData(). Handed over.");
    }

    function onEnd() {
      log.debug("Entering onEnd().");
      if (finished) {
        log.debug("Leaving onEnd(). Finished.");
        return;
      }
      if (!buffered.length) {
        // A TCP probe that connects and closes — a port check, a balancer
        // configured for plain TCP health checks. Counted and not audited:
        // it sent nothing that could be wrong.
        finish();
        counters.closedEmpty += 1;
        log.debug('proxy: ' + label + ' — ' + peer + ' connected and closed ' +
                  'without sending a byte (a TCP connect check).');
        socket.destroy();
        log.debug("Leaving onEnd(). Closed with nothing sent.");
        return;
      }
      refuse('STS-PROXY-0008', 'the connection closed after ' +
             buffered.length + ' byte(s), part-way through the header');
      log.debug("Leaving onEnd().");
    }

    function onError(error) {
      log.debug("Entering onError().");
      // A reset while the header is read is the client leaving, which is
      // ordinary: nothing was served, nothing is recorded as a refusal.
      log.debug("Caught in onError(): " + ((error && error.message) || error));
      finish();
      socket.destroy();
      log.debug("Leaving onError().");
    }

    function onClose() {
      log.debug("Entering onClose().");
      finish();
      log.debug("Leaving onClose().");
    }

    const timer = setTimeout(function () {
      if (!finished) {
        refuse('STS-PROXY-0007', 'no complete header within ' +
               headerTimeoutMs() + 'ms (global.proxyProtocolTimeoutMs), ' +
               'after ' + buffered.length + ' byte(s)');
      }
    }, headerTimeoutMs());
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('error', onError);
    socket.on('close', onClose);
    log.debug("Leaving readHeader().");
  }

  function onConnection(socket) {
    log.debug("Entering onConnection().");
    socket[SEEN] = true;
    const peer = clientAddress.normalise(socket.remoteAddress);
    const local = clientAddress.normalise(socket.localAddress);
    if (!peer) {
      // Already gone: node could not read a peer name for a socket that
      // closed between accept and here. Nothing to serve.
      socket.destroy();
      log.debug("Leaving onConnection(). No peer.");
      return;
    }
    const trusted = clientAddress.isTrustedProxy(peer);
    const sameHost = isThisHost(peer, local);
    if (!trusted && sameHost) {
      counters.sameHost += 1;
      deliver(socket);
      log.debug("Leaving onConnection(). This host, plain.");
      return;
    }
    if (!trusted) {
      recordRefusal('STS-PROXY-0001', peer + ' is not in ' +
                    'global.trustedProxies, and with global.proxyProtocol ' +
                    'on every connection must come through a trusted proxy',
                    peer, label, channel);
      socket.destroy();
      log.debug("Leaving onConnection(). Untrusted.");
      return;
    }
    readHeader(socket, peer, sameHost);
    log.debug("Leaving onConnection(). Reading the header.");
  }

  // Anonymous and unlogged: `emit` is called for every event the server
  // raises — `listening`, `request` on an http.Server, `close` — and only a
  // first `connection` is this file's business. onConnection() logs that.
  server.emit = function (event, socket) {
    if (event !== 'connection' || !socket || socket[SEEN]) {
      return originalEmit.apply(server, arguments);
    }
    onConnection(socket);
    return true;
  };
  log.info('proxy: ' + label + ' expects a PROXY protocol v2 header from ' +
           'global.trustedProxies (' + clientAddress.trustedProxyRanges()
             .count + ' range(s)) and refuses every other address except ' +
           'this host\'s own.');
  log.debug("Leaving install().");
  return true;
}

// For tests: forget the counters and the audit window.
function reset() {
  log.debug("Entering reset().");
  counters.proxied = 0;
  counters.local = 0;
  counters.sameHost = 0;
  counters.closedEmpty = 0;
  counters.refused = {};
  lastAudited.clear();
  thisHostCheck = null;
  log.debug("Leaving reset().");
}

module.exports = {
  SIGNATURE: SIGNATURE,
  MAX_BLOCK_LENGTH: MAX_BLOCK_LENGTH,
  parse: parse,
  build: build,
  crc32c: crc32c,
  enabled: enabled,
  startupProblem: startupProblem,
  install: install,
  describe: describe,
  report: report,
  setThisHostCheck: setThisHostCheck,
  reset: reset
};
