// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: ldap-wire-vectors.js
//
// ---------------------------------------------------------------------------
// THE LDAP WIRE LAYER (#444, phase 5's first step; `sts-ldap`). What the
// directory's socket does with bytes today: node-ldapjs (the `rcbj/node-ldapjs`
// fork, a submodule) created with the options `ldap/ldap_server.js` passes,
// and `@ldapjs/messages`, `@ldapjs/filter`, `@ldapjs/dn` and
// `@ldapjs/controls` under it. Every request PDU is fed to a REAL server's
// connection handler (`server.newConnection`, on a stand-in socket) with a
// handler on every route that records what reached it, so a vector's
// `events` are exactly what the front of the service does: a request handed
// to the handlers (decoded, and re-encoded by its own `toBer()`), an answer
// the library writes itself (an invalid DN, an extended operation nobody
// registered, a SASL mechanism the service does not take), nothing (an
// abandon), or the connection destroyed. A PDU that sends the library into
// a loop it never leaves is run under a `vm` timeout and recorded as `hang`.
// Beside them: DNs, filter strings and their BER, the two escapers, the
// service's own DN helpers (read out of `ldap/ldap_server.js` itself), every
// response the service sends, built by the classes it builds them with, and
// the result-code errors. Nothing here is key material.
//
// Written by `tests/tools/crypto-vectors.js` as `ldap-wire-node.json`
// (`STS_ONLY=ldap-wire`); read by `rust/crates/sts-ldap/tests/
// node_vectors.rs`, which writes `ldap-wire-rust.json` back under
// `STS_WRITE_VECTORS=1`, and `tests/rust_crypto_vectors.js` holds THAT to
// Node through `checkRust()` below, with the same server front.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

/**
 * The server front and the describers, built once per root.
 *
 * @param {string} ROOT - the repository
 * @returns {any} the helpers
 */
function harness(ROOT) {

  const vm = require('vm');
  const ldap = require(path.join(ROOT, 'node_modules', 'ldapjs'));
  const messages = require(path.join(ROOT, 'node_modules', '@ldapjs',
                                     'messages'));
  const ldapFilter = require(path.join(ROOT, 'node_modules', '@ldapjs',
                                       'filter'));
  const { DN } = require(path.join(ROOT, 'node_modules', '@ldapjs', 'dn'));
  const escapeFilterValue = require(path.join(
    ROOT, 'node_modules', '@ldapjs', 'filter', 'lib', 'utils',
    'escape-filter-value.js'));
  const escapeDnValueLib = require(path.join(
    ROOT, 'node_modules', '@ldapjs', 'dn', 'lib', 'utils',
    'escape-value.js'));
  const UNDEF = { undefined: true };
  const HANG_MS = 250;

  function hex(b) {
    return Buffer.from(b).toString('hex');
  }
  function u(x) {
    return x === undefined ? UNDEF : x;
  }
  // A BER TLV with the shortest length, which is what a client sends.
  function len(n) {
    if (n < 0x80) {
      return Buffer.from([n]);
    }
    const bytes = [];
    let rest = n;
    while (rest > 0) {
      bytes.unshift(rest & 0xff);
      rest = Math.floor(rest / 256);
    }
    return Buffer.from([0x80 | bytes.length].concat(bytes));
  }
  function tlv(tag) {
    const body = Buffer.concat(Array.prototype.slice.call(arguments, 1)
      .map(function (p) {
        return Buffer.isBuffer(p) ? p : Buffer.from(p);
      }));
    return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
  }
  function str(tag, s) {
    return tlv(tag, Buffer.isBuffer(s) ? s : Buffer.from(s, 'utf8'));
  }
  function int(tag, n) {
    const w = new (require(path.join(ROOT, 'node_modules', '@ldapjs',
                                     'asn1')).BerWriter)();
    w.writeInt(n, tag);
    return w.buffer;
  }
  function msg(id, op, controls) {
    return tlv(0x30, int(0x02, id), op, controls || Buffer.alloc(0));
  }
  function bool(tag, b) {
    return Buffer.from([tag, 1, b ? 0xff : 0]);
  }

  // ---- what a value of node's looks like in a vector --------------------
  function describeFilter(f) {
    if (!f) {
      return null;
    }
    const out = { type: f.type };
    switch (f.type) {
      case 'AndFilter':
      case 'OrFilter':
        out.clauses = f.clauses.map(describeFilter);
        break;
      case 'NotFilter':
        out.filter = describeFilter(f.filter);
        break;
      case 'PresenceFilter':
        out.attribute = f.attribute;
        break;
      case 'SubstringFilter':
        out.attribute = f.attribute;
        out.initial = u(f.initial);
        out.any = f.any.slice(0);
        out.final = u(f.final);
        break;
      case 'ExtensibleFilter':
        out.attribute = u(f.attribute);
        out.rule = u(f.matchingRule);
        out.value = u(f.value);
        out.dnAttributes = f.dnAttributes;
        break;
      default:
        out.attribute = f.attribute;
        out.value = u(f.value);
    }
    return out;
  }
  function describeControl(c) {
    const out = { type: u(c.type), criticality: u(c.criticality) };
    const v = c.value;
    if (Buffer.isBuffer(v)) {
      out.value = { hex: hex(v) };
    } else if (v === null || v === undefined) {
      out.value = u(v);
    } else {
      out.value = JSON.parse(JSON.stringify(v, function (k, x) {
        if (x && x.type === 'Buffer' && Array.isArray(x.data)) {
          return { hex: hex(Buffer.from(x.data)) };
        }
        return x === undefined ? UNDEF : x;
      }));
    }
    return out;
  }
  function describeAttribute(a) {
    return { type: u(a.type), values: a.values,
             buffers: a.buffers.map(hex) };
  }
  function text(x) {
    if (x === null || x === undefined) {
      return u(x);
    }
    return typeof x === 'string' ? x : x.toString();
  }
  function describeRequest(req) {
    const out = { messageId: req.messageId, protocolOp: req.protocolOp,
                  type: req.type, controls: req.controls.map(describeControl) };
    switch (req.type) {
      case 'BindRequest':
        out.version = u(req.version);
        out.name = text(req.name);
        out.authentication = req.authentication;
        out.credentials = u(req.credentials);
        if (req.authentication === 'sasl') {
          out.mechanism = req.mechanism;
          out.saslCredentials = req.saslCredentials
            ? hex(req.saslCredentials) : null;
        }
        break;
      case 'SearchRequest':
        out.baseObject = req.baseObject.toString();
        out.scope = req.scopeName;
        out.derefAliases = req.derefAliases;
        out.sizeLimit = req.sizeLimit;
        out.timeLimit = req.timeLimit;
        out.typesOnly = req.typesOnly;
        out.filter = req.filter.toString();
        out.filterTree = describeFilter(req.filter);
        out.attributes = req.attributes.slice(0);
        break;
      case 'AddRequest':
        out.entry = text(req.entry);
        out.attributes = req.attributes.map(describeAttribute);
        break;
      case 'ModifyRequest':
        out.object = text(req.object);
        out.changes = req.changes.map(function (c) {
          return { operation: c.operation,
                   modification: describeAttribute(c.modification) };
        });
        break;
      case 'ModifyDnRequest':
        out.entry = text(req.entry);
        out.newRdn = text(req.newRdn);
        out.deleteOldRdn = req.deleteOldRdn;
        out.newSuperior = text(req.newSuperior);
        break;
      case 'CompareRequest':
        out.entry = text(req.entry);
        out.attribute = u(req.attribute);
        out.value = u(req.value);
        break;
      case 'DeleteRequest':
        out.entry = text(req.entry);
        break;
      case 'ExtensionRequest':
        out.requestName = u(req.requestName);
        out.requestValue = u(req.requestValue);
        break;
      case 'AbandonRequest':
        out.abandonId = req.abandonId;
        break;
      default:
        break;
    }
    return out;
  }

  // ---- the front of the service's server ----------------------------------
  // The options `ldap/ldap_server.js` creates both servers with, and a
  // handler on each route it mounts there ('' for every DN operation, and
  // unbind), which records the request and answers nothing.
  const server = ldap.createServer({
    log: { trace: function () {}, debug: function () {},
           info: function () {}, warn: function () {},
           error: function () {} },
    routeAnonymousBinds: true, encodeErrorMessage: true,
    saslMechanisms: ['EXTERNAL'], bindDnFromHandler: true,
    errorCloseDelay: 0 });
  server.on('error', function () {});
  server.on('clientError', function () {});
  let events = null;
  let destroyed = false;
  function record(req) {
    let reencoded;
    try {
      reencoded = hex(req.toBer().buffer);
    } catch (e) {
      reencoded = { error: e.message };
    }
    events.push({ dispatch: describeRequest(req), reencoded: reencoded });
  }
  function handler(req) {
    record(req);
  }
  ['bind', 'add', 'del', 'modify', 'modifyDN', 'compare', 'search']
    .forEach(function (op) {
      server[op]('', handler);
    });
  server.unbind(handler);
  function connection() {
    const EventEmitter = require('events').EventEmitter;
    const c = new EventEmitter();
    c.remoteAddress = '127.0.0.1';
    c.remotePort = 1;
    c.write = function (b) {
      if (!destroyed) {
        events.push({ write: hex(Buffer.isBuffer(b) ? b : b.buffer) });
      }
      return true;
    };
    c.end = function (b) {
      if (!destroyed) {
        events.push({ end: b ? hex(Buffer.isBuffer(b) ? b : b.buffer) : null });
      }
    };
    c.destroy = function () {
      if (!destroyed) {
        events.push({ destroy: true });
      }
      destroyed = true;
    };
    return c;
  }
  // Every chunk is one `data` event on one new connection.
  function front(chunks) {
    events = [];
    destroyed = false;
    const conn = connection();
    server.newConnection(conn);
    let hung = false;
    for (const chunk of chunks) {
      if (destroyed) {
        break;
      }
      try {
        vm.runInNewContext('feed()', { feed: function () {
          conn.emit('data', chunk);
        } }, { timeout: HANG_MS });
      } catch (e) {
        if (e && e.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
          hung = true;
          break;
        }
        events.push({ thrown: e.message });
        break;
      }
    }
    if (hung) {
      events.push({ hang: true });
    }
    const pending = conn.parser.buffer ? conn.parser.buffer.length : 0;
    return { events: events, pending: hung ? 0 : pending };
  }

  return { vm, ldap, messages, ldapFilter, DN, escapeFilterValue, escapeDnValueLib, UNDEF, HANG_MS, hex, u, len, tlv, str, int, msg, bool, describeFilter, describeControl, describeAttribute, text, describeRequest, front };
}

/**
 * The vectors.
 *
 * @param {string} ROOT - the repository
 * @returns {any} ldap-wire-node.json
 */
function build(ROOT) {
  const h = harness(ROOT);
  const { vm, ldap, messages, ldapFilter, DN, escapeFilterValue, escapeDnValueLib, UNDEF, HANG_MS, hex, u, len, tlv, str, int, msg, bool, describeFilter, describeControl, describeAttribute, text, describeRequest, front } = h;
  // ---- the request corpus --------------------------------------------------
  const corpus = [];
  function add(name, pdu, chunks) {
    corpus.push({ name: name, chunks: chunks || [pdu] });
  }
  function viaClass(Klass, options) {
    return new Klass(options).toBer().buffer;
  }
  const B = 'dc=example,dc=com';
  function bindPdu(id, name, pw, version) {
    return msg(id, tlv(0x60, int(0x02, version || 3), str(0x04, name),
                       str(0x80, pw)));
  }
  function saslPdu(id, name, mech, creds) {
    return msg(id, tlv(0x60, int(0x02, 3), str(0x04, name),
                       tlv(0xa3, str(0x04, mech),
                           creds === undefined ? Buffer.alloc(0)
                             : str(0x04, creds))));
  }
  add('bind simple', bindPdu(1, 'cn=admin,' + B, 'secret'));
  add('bind via class', viaClass(messages.BindRequest, {
    messageId: 2, name: 'uid=alice,ou=users,' + B, credentials: 'pw' }));
  add('bind anonymous', bindPdu(3, '', ''));
  add('bind version 2', bindPdu(4, 'cn=x', 'y', 2));
  add('bind version 127', bindPdu(4, 'cn=x', 'y', 127));
  add('bind invalid dn', bindPdu(5, 'cn', 'pw'));
  add('bind invalid dn 2', bindPdu(5, '=x', 'pw'));
  add('bind dn escaped comma', bindPdu(6, 'cn=Smith\\, John,' + B, 'pw'));
  add('bind multi-valued rdn', bindPdu(7, 'cn=a+uid=b,' + B, 'pw'));
  add('bind hex value', bindPdu(8, 'cn=#41424344,' + B, 'pw'));
  add('bind hex value then space hangs', bindPdu(8, 'cn=#4142 ,' + B,
                                                 'pw'));
  add('bind quoted value', bindPdu(9, 'cn="a,b",' + B, 'pw'));
  add('bind utf8', bindPdu(10, 'cn=Jörg,' + B, 'pw'));
  add('bind escaped utf8', bindPdu(11, 'cn=J\\c3\\b6rg,' + B, 'pw'));
  add('bind spaces', bindPdu(12, '  cn = alice , dc=x  ', 'pw'));
  add('bind semicolon separator', bindPdu(13, 'cn=a;dc=b', 'pw'));
  add('bind empty password', bindPdu(14, 'cn=a', ''));
  add('bind unicode password', bindPdu(15, 'cn=a', 'päss☃'));
  add('bind invalid utf8 password',
      msg(16, tlv(0x60, int(0x02, 3), str(0x04, 'cn=a'),
                  tlv(0x80, Buffer.from([0xff, 0xfe, 0x41, 0xc3])))));
  add('bind large password', bindPdu(17, 'cn=a', 'x'.repeat(70000)));
  add('bind sasl external', saslPdu(18, '', 'EXTERNAL'));
  add('bind sasl external creds', saslPdu(19, '', 'EXTERNAL',
                                          'dn:cn=a,' + B));
  add('bind sasl external empty creds', saslPdu(19, '', 'EXTERNAL', ''));
  add('bind sasl plain', saslPdu(20, '', 'PLAIN', '\u0000a\u0000b'));
  add('bind sasl quote in mechanism', saslPdu(21, '', 'X"\\\n\u0001', 'z'));
  add('bind sasl with name', saslPdu(22, 'cn=a,' + B, 'EXTERNAL'));
  add('bind sasl invalid name', saslPdu(22, 'cn', 'EXTERNAL'));
  add('bind sasl no mechanism', msg(23, tlv(0x60, int(0x02, 3),
                                            str(0x04, ''), tlv(0xa3))));
  add('bind auth choice 1', msg(24, tlv(0x60, int(0x02, 3), str(0x04, ''),
                                        str(0x81, 'x'))));
  add('bind with control', msg(25, tlv(0x60, int(0x02, 3), str(0x04, 'cn=a'),
                                       str(0x80, 'p')),
                               tlv(0xa0, tlv(0x30,
                                             str(0x04, '1.2.3.4'),
                                             bool(0x01, true)))));
  add('bind sasl with control',
      msg(26, tlv(0x60, int(0x02, 3), str(0x04, ''),
                  tlv(0xa3, str(0x04, 'EXTERNAL'))),
          tlv(0xa0, tlv(0x30, str(0x04, '2.16.840.1.113730.3.4.2')))));

  function searchPdu(id, base, scope, deref, size, time, typesOnly, filter,
                     attrs, controls) {
    return msg(id, tlv(0x63, str(0x04, base), int(0x0a, scope),
                       int(0x0a, deref), int(0x02, size), int(0x02, time),
                       bool(0x01, typesOnly), filter,
                       tlv(0x30, Buffer.concat(attrs.map(function (a) {
                         return str(0x04, a);
                       })))), controls);
  }
  const fEq = function (a, v) {
    return tlv(0xa3, str(0x04, a), str(0x04, v));
  };
  const fPresent = function (a) {
    return str(0x87, a);
  };
  const fAnd = function () {
    return tlv.apply(null, [0xa0].concat(Array.prototype.slice.call(
      arguments)));
  };
  const fOr = function () {
    return tlv.apply(null, [0xa1].concat(Array.prototype.slice.call(
      arguments)));
  };
  const fNot = function (f) {
    return tlv(0xa2, f);
  };
  const fSub = function (a, parts) {
    return tlv(0xa4, str(0x04, a), tlv(0x30, Buffer.concat(parts.map(
      function (p) {
        return str(p[0], p[1]);
      }))));
  };
  const fGe = function (a, v) {
    return tlv(0xa5, str(0x04, a), str(0x04, v));
  };
  const fLe = function (a, v) {
    return tlv(0xa6, str(0x04, a), str(0x04, v));
  };
  const fApprox = function (a, v) {
    return tlv(0xa8, str(0x04, a), str(0x04, v));
  };
  const fExt = function (rule, type, value, dn) {
    return tlv(0xa9, rule === null ? Buffer.alloc(0) : str(0x81, rule),
               type === null ? Buffer.alloc(0) : str(0x82, type),
               value === null ? Buffer.alloc(0) : str(0x83, value),
               dn === null ? Buffer.alloc(0) : bool(0x84, dn));
  };
  function search(name, filter, extra) {
    const o = Object.assign({ id: 30, base: B, scope: 2, deref: 0, size: 0,
                              time: 0, typesOnly: false, attrs: [],
                              controls: undefined }, extra || {});
    add(name, searchPdu(o.id, o.base, o.scope, o.deref, o.size, o.time,
                        o.typesOnly, filter, o.attrs, o.controls));
  }
  search('search root dse', fPresent('objectClass'),
         { base: '', scope: 0, attrs: ['*', '+'] });
  search('search via class', fPresent('x'));
  corpus.pop();
  add('search via class', viaClass(messages.SearchRequest, {
    messageId: 31, baseObject: 'ou=users,' + B, scope: 'sub',
    filter: '(&(objectClass=person)(|(uid=al*)(mail=*@example.com)))',
    attributes: ['cn', 'mail'], sizeLimit: 10 }));
  search('search eq', fEq('uid', 'alice'));
  search('search present', fPresent('mail'));
  search('search and', fAnd(fEq('a', '1'), fEq('b', '2')));
  search('search or', fOr(fEq('a', '1'), fPresent('c')));
  search('search not', fNot(fEq('a', '1')));
  search('search empty and', fAnd());
  search('search empty or', fOr());
  search('search ge le approx', fAnd(fGe('n', '5'), fLe('n', '9'),
                                     fApprox('cn', 'jon')));
  search('search ge empty', fGe('n', ''));
  search('search eq empty value', fEq('cn', ''));
  search('search substr initial', fSub('cn', [[0x80, 'al']]));
  search('search substr any', fSub('cn', [[0x81, 'li'], [0x81, 'c']]));
  search('search substr final', fSub('cn', [[0x82, 'ce']]));
  search('search substr all', fSub('cn', [[0x80, 'a'], [0x81, 'l'],
                                          [0x81, 'i'], [0x82, 'e']]));
  search('search substr empty', fSub('cn', []));
  search('search substr bad tag', fSub('cn', [[0x83, 'x']]));
  search('search ext full', fExt('2.5.13.5', 'cn', 'Alice', true));
  search('search ext rule only', fExt('caseExactMatch', null, 'x', null));
  search('search ext type only', fExt(null, 'cn', 'x', false));
  search('search ext no value', fExt(null, 'cn', null, null));
  search('search eq special chars', fEq('cn', 'a(b)c*d\\e'));
  search('search eq nul', fEq('cn', 'a\u0000b'));
  search('search eq utf8', fEq('cn', 'Jörg ☃ 😀'));
  search('search eq invalid utf8', tlv(0xa3, str(0x04, 'cn'),
                                       tlv(0x04, Buffer.from([0xc3]))));
  search('search eq invalid utf8 2', tlv(0xa3, str(0x04, 'cn'),
                                         tlv(0x04, Buffer.from(
                                           [0x41, 0xe2, 0x82]))));
  search('search eq latin1', tlv(0xa3, str(0x04, 'cn'),
                                 tlv(0x04, Buffer.from([0xe9, 0x41]))));
  search('search eq binary', tlv(0xa3, str(0x04, 'objectGUID'),
                                 tlv(0x04, Buffer.from(
                                   [0x01, 0x80, 0xff, 0x00, 0x7f]))));
  search('search eq escaped looking', fEq('cn', '\\28x\\29'));
  search('search eq trailing backslash', fEq('cn', 'x\\'));
  search('search eq backslash hex', fEq('cn', '\\c3\\a9'));
  search('search eq attribute with dash', fEq('x-y_z', 'v'));
  search('search eq attribute with semicolon', fEq('cn;lang-en', 'v'));
  search('search eq attribute with dot oid', fEq('2.5.4.3', 'v'));
  search('search eq attribute empty', fEq('', 'v'));
  search('search present attribute bad', fPresent('a b'));
  let deep = fEq('a', '1');
  for (let i = 0; i < 40; i++) {
    deep = i % 2 ? fNot(deep) : fAnd(deep, fPresent('x' + i));
  }
  search('search deep nesting', deep);
  search('search bad filter tag', str(0x8a, 'x'));
  search('search scope one', fPresent('x'), { scope: 1 });
  search('search scope base', fPresent('x'), { scope: 0 });
  search('search scope 3', fPresent('x'), { scope: 3 });
  search('search deref 3', fPresent('x'), { deref: 3 });
  search('search deref 9', fPresent('x'), { deref: 9 });
  search('search limits', fPresent('x'), { size: 500, time: -1 });
  search('search limits big', fPresent('x'), { size: 2147483647,
                                               time: 65536 });
  search('search typesOnly', fPresent('x'), { typesOnly: true });
  search('search attrs', fPresent('x'), {
    attrs: ['cn', 'mail', 'userCertificate;binary', '1.1', '@person',
            'member;range=0-10', ''] });
  search('search attr invalid', fPresent('x'), { attrs: ['cn name'] });
  search('search attr digit lead', fPresent('x'), { attrs: ['2.5.4.3'] });
  search('search base invalid', fPresent('x'), { base: 'nope' });
  search('search base escaped', fPresent('x'),
         { base: 'ou=a\\2Cb,dc=x' });
  const paged = function (size, cookie, critical) {
    const w = tlv(0x30, int(0x02, size), str(0x04, cookie));
    return tlv(0x30, str(0x04, '1.2.840.113556.1.4.319'),
               critical === undefined ? Buffer.alloc(0)
                 : bool(0x01, critical),
               tlv(0x04, w));
  };
  search('search paged', fPresent('x'),
         { controls: tlv(0xa0, paged(100, '', true)) });
  search('search paged cookie', fPresent('x'),
         { controls: tlv(0xa0, paged(5, Buffer.from([1, 2, 0xff]))) });
  search('search paged no value', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '1.2.840.113556.1.4.319'))) });
  search('search paged empty value', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '1.2.840.113556.1.4.319'),
                            tlv(0x04))) });
  search('search sort', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '1.2.840.113556.1.4.473'),
                            tlv(0x04, tlv(0x30, tlv(0x30, str(0x04, 'cn'),
                                                    str(0x80, '2.5.13.3'))))))
  });
  search('search sort reverse', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '1.2.840.113556.1.4.473'),
                            tlv(0x04, tlv(0x30, tlv(0x30, str(0x04, 'cn'),
                                                    bool(0x81, true))))))
  });
  search('search sort no value', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '1.2.840.113556.1.4.473'))) });
  search('search vlv', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '2.16.840.1.113730.3.4.9'),
                            tlv(0x04, tlv(0x30, int(0x02, 0),
                                          int(0x02, 9))))) });
  search('search psearch', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '2.16.840.1.113730.3.4.3'),
                            bool(0x01, true),
                            tlv(0x04, tlv(0x30, int(0x02, 15),
                                          bool(0x01, true),
                                          bool(0x01, false))))) });
  search('search ppolicy request', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30,
                            str(0x04, '1.3.6.1.4.1.42.2.27.8.5.1'))) });
  search('search manage dsa it', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '2.16.840.1.113730.3.4.2'),
                            bool(0x01, false))) });
  search('search generic control value', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '1.3.6.1.4.1.4203.1.10.1'),
                            str(0x04, 'dn:cn=x'))) });
  search('search generic control binary value', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30, str(0x04, '1.9.9'),
                            tlv(0x04, Buffer.from([0xff, 0x00])))) });
  search('search two controls', fPresent('x'), {
    controls: tlv(0xa0, paged(10, ''),
                  tlv(0x30, str(0x04, '2.16.840.1.113730.3.4.2'))) });
  search('search empty control', fPresent('x'), {
    controls: tlv(0xa0, tlv(0x30)) });
  search('search empty controls', fPresent('x'), {
    controls: tlv(0xa0) });
  search('search control past end hangs', fPresent('x'), {
    controls: Buffer.from([0xa0, 0x03, 0x30]) });

  const attr = function (type, values) {
    return tlv(0x30, str(0x04, type), tlv(0x31, Buffer.concat(values.map(
      function (v) {
        return str(0x04, v);
      }))));
  };
  function addPdu(id, entry, attrs) {
    return msg(id, tlv(0x68, str(0x04, entry),
                       tlv(0x30, Buffer.concat(attrs))));
  }
  add('add', addPdu(40, 'uid=bob,ou=users,' + B,
                    [attr('objectClass', ['top', 'inetOrgPerson']),
                     attr('uid', ['bob']), attr('CN', ['Bob B'])]));
  add('add via class', viaClass(messages.AddRequest, {
    messageId: 41, entry: 'cn=g,' + B,
    attributes: [new ldap.Attribute({ type: 'member',
                                      values: ['cn=a', 'cn=b'] })] }));
  add('add empty dn', addPdu(42, '', [attr('cn', ['x'])]));
  add('add invalid dn', addPdu(42, 'x', [attr('cn', ['x'])]));
  add('add binary', addPdu(43, 'cn=c,' + B, [
    attr('userCertificate;binary', [Buffer.from([0x30, 0x82, 0xff, 0x00])]),
    attr('jpegPhoto', [Buffer.from([0xff, 0xd8, 0xff, 0xe0])])]));
  add('add binary type mixed case', addPdu(43, 'cn=c,' + B, [
    attr('userCertificate;Binary', [Buffer.from([1, 2, 3])])]));
  add('add no values', addPdu(44, 'cn=d,' + B, [attr('cn', [])]));
  add('add no set', addPdu(44, 'cn=d,' + B,
                           [tlv(0x30, str(0x04, 'cn'))]));
  add('add large value', addPdu(45, 'cn=e,' + B, [
    attr('description', ['v'.repeat(200000)])]));
  add('add many attributes', addPdu(46, 'cn=f,' + B,
    Array.from({ length: 120 }, function (_, i) {
      return attr('a' + i, ['v' + i, 'w' + i]);
    })));
  add('add bad value tag', addPdu(47, 'cn=g,' + B, [
    tlv(0x30, str(0x04, 'cn'), tlv(0x31, str(0x0c, 'x')))]));

  const change = function (op, type, values) {
    return tlv(0x30, int(0x0a, op), attr(type, values));
  };
  function modPdu(id, object, changes) {
    return msg(id, tlv(0x66, str(0x04, object),
                       tlv(0x30, Buffer.concat(changes))));
  }
  add('modify', modPdu(50, 'uid=alice,ou=users,' + B, [
    change(0, 'mail', ['a@x']), change(1, 'description', []),
    change(2, 'cn', ['Alice', 'Al'])]));
  add('modify via class', viaClass(messages.ModifyRequest, {
    messageId: 51, object: 'cn=a,' + B,
    changes: [new (require(path.join(ROOT, 'node_modules', '@ldapjs',
                                     'change')))({
      operation: 'replace',
      modification: new ldap.Attribute({ type: 'sn', values: ['x'] }) })]
  }));
  add('modify invalid dn', modPdu(52, 'bad', [change(0, 'cn', ['x'])]));
  add('modify empty dn', modPdu(52, '', [change(0, 'cn', ['x'])]));
  add('modify op 3', modPdu(53, 'cn=a', [change(3, 'cn', ['x'])]));
  add('modify increment op', modPdu(53, 'cn=a', [change(4, 'n', ['1'])]));
  add('modify invalid utf8 value', modPdu(54, 'cn=a', [
    change(2, 'description', [Buffer.from([0x61, 0xff, 0x62])])]));
  add('modify binary value', modPdu(54, 'cn=a', [
    change(2, 'userCertificate;binary', [Buffer.from([0xff, 0x00, 0x10])])
  ]));
  add('modify no changes', modPdu(55, 'cn=a', []));

  function modDnPdu(id, entry, newRdn, del, superior) {
    return msg(id, tlv(0x6c, str(0x04, entry), str(0x04, newRdn),
                       bool(0x01, del),
                       superior === undefined ? Buffer.alloc(0)
                         : str(0x80, superior)));
  }
  add('modifydn', modDnPdu(60, 'cn=a,' + B, 'cn=b', true));
  add('modifydn superior', modDnPdu(61, 'cn=a,' + B, 'cn=b', false,
                                    'ou=x,' + B));
  add('modifydn empty superior', modDnPdu(61, 'cn=a,' + B, 'cn=b', false,
                                          ''));
  add('modifydn invalid newrdn', modDnPdu(62, 'cn=a,' + B, 'b', true));
  add('modifydn invalid entry', modDnPdu(62, 'a', 'cn=b', true));
  add('modifydn empty entry', modDnPdu(62, '', 'cn=b', true));
  add('modifydn multi rdn', modDnPdu(63, 'cn=a,' + B, 'cn=b+sn=c', true));

  function cmpPdu(id, entry, a, v) {
    return msg(id, tlv(0x6e, str(0x04, entry),
                       tlv(0x30, str(0x04, a), str(0x04, v))));
  }
  add('compare', cmpPdu(70, 'uid=alice,ou=users,' + B, 'mail', 'a@x'));
  add('compare empty dn', cmpPdu(71, '', 'cn', 'x'));
  add('compare invalid dn', cmpPdu(72, 'zz', 'cn', 'x'));
  add('compare empty value', cmpPdu(73, 'cn=a', 'cn', ''));
  add('compare invalid utf8', msg(74, tlv(0x6e, str(0x04, 'cn=a'),
                                          tlv(0x30, str(0x04, 'cn'),
                                              tlv(0x04, Buffer.from(
                                                [0x80]))))));

  add('delete', msg(80, str(0x4a, 'uid=bob,ou=users,' + B)));
  add('delete empty', msg(81, str(0x4a, '')));
  add('delete invalid', msg(82, str(0x4a, 'bob')));
  add('delete via class', viaClass(messages.DeleteRequest, {
    messageId: 83, entry: 'cn=z,' + B }));

  function extPdu(id, name, value) {
    return msg(id, tlv(0x77, str(0x80, name),
                       value === undefined ? Buffer.alloc(0)
                         : (Buffer.isBuffer(value) && value[0] === 0x81
                           ? value : str(0x81, value))));
  }
  add('extended starttls', extPdu(90, '1.3.6.1.4.1.1466.20037'));
  add('extended whoami', extPdu(91, '1.3.6.1.4.1.4203.1.11.3'));
  add('extended unknown value', extPdu(92, '1.2.3.4.5', 'payload'));
  add('extended password modify', extPdu(93, '1.3.6.1.4.1.4203.1.11.1',
    tlv(0x81, tlv(0x30, str(0x80, 'uid=a'), str(0x81, 'old'),
                  str(0x82, 'new')))));
  add('extended password modify empty', extPdu(93,
    '1.3.6.1.4.1.4203.1.11.1', tlv(0x81, tlv(0x30))));
  add('extended password modify malformed', extPdu(93,
    '1.3.6.1.4.1.4203.1.11.1', str(0x81, 'x')));
  add('extended cancel', extPdu(94, '1.3.6.1.1.8',
                                tlv(0x81, tlv(0x30, int(0x02, 7)))));
  add('extended cancel malformed', extPdu(94, '1.3.6.1.1.8', str(0x81, 'x')));
  add('extended empty name', extPdu(95, ''));
  add('extended name unbind', extPdu(96, 'unbind'));
  add('extended name proto', extPdu(96, '__proto__'));
  add('extended no name', msg(97, tlv(0x77)));
  add('extended via class', viaClass(messages.ExtensionRequest, {
    messageId: 98, requestName: '1.3.6.1.4.1.4203.1.11.3' }));

  add('abandon', msg(100, int(0x50, 7)));
  add('abandon zero', msg(101, int(0x50, 0)));
  add('abandon via class', viaClass(messages.AbandonRequest, {
    messageId: 102, abandonId: 3 }));
  add('unbind', msg(103, tlv(0x42)));
  add('unbind via class', viaClass(messages.UnbindRequest,
                                   { messageId: 104 }));
  add('unbind with content', msg(105, str(0x42, 'x')));

  add('bind response from client', msg(110, tlv(0x61, int(0x0a, 0),
                                                str(0x04, ''),
                                                str(0x04, ''))));
  add('search done from client', msg(111, tlv(0x65, int(0x0a, 0),
                                              str(0x04, ''), str(0x04, ''))));
  add('intermediate response', msg(112, tlv(0x79)));
  add('unknown op', msg(113, tlv(0x70, str(0x04, 'x'))));
  add('unknown primitive op', msg(113, str(0x45, 'x')));

  // Framing: what the parser does with a stream rather than a PDU.
  const one = bindPdu(120, 'cn=a', 'b');
  const two = msg(121, int(0x50, 1));
  const three = searchPdu(122, B, 2, 0, 0, 0, false, fPresent('cn'), []);
  add('two in one chunk', null, [Buffer.concat([one, three])]);
  add('three in one chunk', null, [Buffer.concat([one, two, three])]);
  add('split in three', null, [three.subarray(0, 5), three.subarray(5, 9),
                               three.subarray(9)]);
  add('one and a half', null, [Buffer.concat([one, three.subarray(0, 7)])]);
  add('half then rest and another', null, [
    one.subarray(0, 4), Buffer.concat([one.subarray(4), two])]);
  add('response then request', null, [Buffer.concat([
    msg(123, tlv(0x61, int(0x0a, 0), str(0x04, ''), str(0x04, ''))), one])]);
  add('bad dn then request', null, [Buffer.concat([
    bindPdu(124, 'x', ''), one])]);
  add('leading zero byte', Buffer.concat([Buffer.from([0x00]), one]));
  add('leading zero tag message', Buffer.from([0x00, 0x05, 0x02, 0x01, 0x01,
                                               0x42, 0x00]));
  add('indefinite length', Buffer.from([0x30, 0x80, 0x02, 0x01, 0x01, 0x42,
                                        0x00, 0x00, 0x00]));
  add('five length bytes', Buffer.from([0x30, 0x85, 0, 0, 0, 0, 5, 0x02, 1,
                                        1, 0x42, 0]));
  add('four length bytes', Buffer.from([0x30, 0x84, 0, 0, 0, 5, 0x02, 1, 1,
                                        0x42, 0]));
  add('outer tag 0x31', Buffer.from([0x31, 0x05, 0x02, 0x01, 0x01, 0x42,
                                     0x00]));
  add('outer tag 0x04', Buffer.from([0x04, 0x05, 0x02, 0x01, 0x01, 0x42,
                                     0x00]));
  add('message id five bytes', Buffer.from([0x30, 0x09, 0x02, 0x05, 0x01,
                                            0x00, 0x00, 0x00, 0x07, 0x42,
                                            0x00]));
  add('message id empty', Buffer.from([0x30, 0x04, 0x02, 0x00, 0x42, 0x00]));
  add('message id negative', msg(-5, tlv(0x42)));
  add('message id negative bind', bindPdu(-129, 'cn=bad', ''));
  add('message id max', bindPdu(2147483647, 'x', ''));
  add('message id 0x80000000', Buffer.from([0x30, 0x09, 0x02, 0x04, 0x80,
                                            0, 0, 0, 0x42, 0x00]));
  add('message id tag wrong', Buffer.from([0x30, 0x05, 0x04, 0x01, 0x01,
                                           0x42, 0x00]));
  add('no protocol op', Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]));
  add('empty message', Buffer.from([0x30, 0x00]));
  add('garbage', Buffer.from('GET / HTTP/1.0\r\n\r\n'));
  add('tls client hello', Buffer.from(
    '16030100a5010000a10303' + '00'.repeat(32) + '00', 'hex'));
  add('trailing bytes inside message',
      tlv(0x30, int(0x02, 1), tlv(0x42), Buffer.from([0xde, 0xad])));
  add('huge declared length', Buffer.from([0x30, 0x84, 0x7f, 0xff, 0xff,
                                           0xff, 0x02, 0x01, 0x01]));

  // Mutations of a handful of the above, from a seeded generator, so the
  // same corpus is written every time: every truncation of four short
  // PDUs, and byte substitutions everywhere in a dozen more.
  let seed = 0x1f2e3d4c;
  function rnd(n) {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    return (seed >>> 8) % n;
  }
  const bases = corpus.filter(function (c) {
    return c.chunks.length === 1 && c.chunks[0] &&
      c.chunks[0].length < 400;
  });
  ['bind simple', 'search and', 'modify', 'extended password modify']
    .forEach(function (name) {
      const pdu = bases.find(function (c) {
        return c.name === name;
      }).chunks[0];
      for (let n = 1; n < pdu.length; n++) {
        add('truncated ' + name + ' at ' + n, pdu.subarray(0, n));
      }
    });
  bases.slice(0).forEach(function (c, index) {
    if (index % 3 !== 0) {
      return;
    }
    const pdu = c.chunks[0];
    for (let k = 0; k < 12; k++) {
      const copy = Buffer.from(pdu);
      const at = rnd(copy.length);
      const choice = rnd(4);
      if (choice === 0) {
        copy[at] = rnd(256);
      } else if (choice === 1) {
        copy[at] = (copy[at] + 1) & 0xff;
      } else if (choice === 2) {
        copy[at] = (copy[at] + 255) & 0xff;
      } else {
        copy[at] = [0x00, 0x80, 0xff, 0x30, 0x04, 0x84][rnd(6)];
      }
      add('mutated ' + c.name + ' #' + k + ' [' + at + ']', copy);
    }
  });

  const requests = corpus.map(function (c) {
    const out = front(c.chunks);
    return { name: c.name, chunks: c.chunks.map(hex), events: out.events,
             pending: out.pending };
  });

  // ---- DNs -----------------------------------------------------------------
  const dnInputs = ['', 'cn=a', 'CN=Alice,OU=Users,DC=Example,DC=Com',
    'cn=a,dc=b', 'cn = a , dc = b', '  cn=a', 'cn=a  ', 'cn=a+sn=b,dc=c',
    'cn=a+cn=b', 'sn=b+cn=a', 'cn=Smith\\, John,dc=x', 'cn=a\\+b',
    'cn=\\23hash', 'cn=#41', 'cn=#414243,o=x', 'cn=#4', 'cn=#zz',
    'cn=#4142 ,o=x', 'cn="quoted, value"', 'cn="unterminated',
    'cn="a" x', 'cn=a"b', 'cn=Jörg', 'cn=J\\c3\\b6rg',
    'cn=\\e2\\98\\83', 'cn=\\f0\\9f\\98\\80', 'cn=\\', 'cn=a\\',
    'cn=\\4', 'cn=\\4,dc=x', 'cn=\\zz', 'cn=\\ x', 'cn=a\\ ',
    'cn=\\20a', 'cn=a;dc=b', 'cn=a,', 'cn=a+', 'cn=a;', ',cn=a',
    'cn', '=a', 'c n=a', '1cn=a', '2.5.4.3=a', '1.2=x', '1=a', 'a-b=c',
    'a_b=c', 'cn=', 'cn= ', 'cn=,dc=x', 'cn=a=b', 'cn=<x>', 'cn=a#b',
    'cn=\u0001', 'cn=a\tb', 'cn= x', 'cn=﻿x', 'cn=-5',
    'cn=\\-5x', 'cn=\\ +x', 'uid=a,ou=users,dc=example,dc=com',
    'cn=a,,dc=b', 'cn=x y', 'CN=Mixed+UID=Case', 'cn=\\5c',
    'cn=back\\\\slash', 'cn=\\"q\\"'];
  function rdnsOf(dn) {
    const out = [];
    for (let i = 0; i < dn.length; i++) {
      const r = dn.rdnAt(i);
      const pairs = [];
      for (const k of r.keys()) {
        const v = r.getValue(k);
        pairs.push([k, typeof v === 'string' ? v
          : { hex: hex(v.buffer) }]);
      }
      out.push(pairs);
    }
    return out;
  }
  function dnCase(input) {
    let hung = false;
    let result = null;
    try {
      vm.runInNewContext('f()', { f: function () {
        try {
          const dn = DN.fromString(input);
          result = { ok: true, text: dn.toString(), rdns: rdnsOf(dn),
                     length: dn.length };
        } catch (e) {
          result = { ok: false, error: e.message };
        }
      } }, { timeout: HANG_MS });
    } catch (e) {
      hung = true;
    }
    return Object.assign({ input: input }, hung ? { hang: true } : result);
  }
  const dns = dnInputs.map(dnCase);
  const dnPairs = [['dc=b', 'cn=a,dc=b'], ['cn=a,dc=b', 'cn=a,dc=b'],
    ['DC=b', 'cn=a,dc=b'], ['dc=b', 'dc=b'], ['', 'cn=a'],
    ['dc=c', 'cn=a,dc=b'], ['cn=a+sn=b', 'sn=b+cn=a'],
    ['cn=a,dc=b', 'cn=x,cn=a,dc=b'], ['cn=a', 'cn=a '],
    ['cn=#41', 'cn=A']].map(function (p) {
    const a = DN.fromString(p[0]);
    const b = DN.fromString(p[1]);
    return { a: p[0], b: p[1], equals: a.equals(b),
             parentOf: a.parentOf(b), childOf: a.childOf(b) };
  });

  // The service's own DN helpers, read out of ldap/ldap_server.js so that
  // what is tested is the function it calls, not a copy of it.
  const serverSource = fs.readFileSync(
    path.join(ROOT, 'ldap', 'ldap_server.js'), 'utf8');
  const helperNames = ['normalizeDn', 'parentDn', 'isUnder', 'depthUnder',
                       'splitRdns', 'rdnPairs', 'escapeDnValue',
                       'unescapeDnValue', 'nameUsableInDn'];
  const helperSource = helperNames.map(function (name) {
    const at = serverSource.indexOf('\nfunction ' + name + '(');
    const end = serverSource.indexOf('\n}\n', at);
    return serverSource.slice(at, end + 3);
  }).join('\n');
  const reserved = /^const DN_RESERVED = (.*);$/m.exec(serverSource)[1];
  // eslint-disable-next-line no-new-func
  const helpers = new Function('log', 'const DN_RESERVED = ' + reserved +
                               ';\n' + helperSource + '\nreturn {' +
                               helperNames.join(', ') + '};')({
    debug: function () {} });
  const helperInputs = ['', 'cn=a', ' CN=Alice , OU=Users ,DC=X ',
    'cn=a\\,b,dc=x', 'cn=a+uid=b,dc=x', 'cn= a + UID = B ', '  ', ',',
    'cn=a,,dc=b', 'cn=İ,dc=X', 'cn=ΣΑΣ', 'a=b=c',
    '=x', 'cn', 'cn=x﻿', 'cn=x\u0085', null, 'a\\\\,b'];
  const helperValues = ['', 'plain', 'a,b', '#hash', ' lead', 'trail ',
    ' both ', 'q"uote', 'semi;colon', 'lt<gt>', 'eq=', 'plus+',
    'back\\slash', '\\,', 'x\\', 'Jörg', '##'];
  const serviceDn = {
    normalizeDn: helperInputs.map(function (x) {
      return [x, helpers.normalizeDn(x)];
    }),
    parentDn: helperInputs.map(function (x) {
      return [x, helpers.parentDn(x)];
    }),
    splitRdns: helperInputs.map(function (x) {
      return [x, helpers.splitRdns(x)];
    }),
    rdnPairs: helperInputs.map(function (x) {
      return [x, helpers.rdnPairs(x)];
    }),
    isUnder: [['cn=a,dc=x', 'dc=x'], ['cn=a,dc=x', 'DC=X'],
      ['dc=x', 'dc=x'], ['cn=a,dc=xx', 'dc=x'], ['cn=a,dcdc=x', 'dc=x'],
      ['anything', ''], ['', 'dc=x'], ['cn=a, dc=x ', ' dc=x']]
      .map(function (p) {
        return [p[0], p[1], helpers.isUnder(p[0], p[1]),
                helpers.depthUnder(p[0], p[1])];
      }),
    escapeDnValue: helperValues.map(function (x) {
      return [x, helpers.escapeDnValue(x)];
    }),
    unescapeDnValue: helperValues.concat(['a\\,b', '\\\\', '\\']).map(
      function (x) {
        return [x, helpers.unescapeDnValue(x)];
      }),
    nameUsableInDn: helperValues.map(function (x) {
      return [x, helpers.nameUsableInDn(x)];
    })
  };

  // ---- filter strings and filter BER ------------------------------------
  const filterInputs = ['(cn=foo)', 'cn=foo', '(&(a=1)(b=2))', '(|(a=1))',
    '(!(a=1))', '(&)', '(|)', '(!)', '(a=*)', '(a=b*)', '(a=*b)',
    '(a=*b*)', '(a=b*c*d)', '(a=**)', '(a>=5)', '(a<=5)', '(a~=x)',
    '(a:=x)', '(a:dn:=x)', '(a:caseExactMatch:=x)', '(:dn:2.5.13.5:=x)',
    '(:rule:=x)', '(a:dn:rule:=x:y)', '(a:dn:rule=x)', '(a=\\28)',
    '(a=\\2a)', '(a=\\5c)', '(a=\\c3\\a9)', '(a=é)', '(a=☃)',
    '(a=😀)', '(a=x\\)', '(a=x\\zz)', '(a=\n)', '(a= )',
    '(a=)', '(=x)', '($a=x)', '(a!=x)', '(a)', '((a=b))', '(a=b',
    '(a=b))', '(a=b)x', 'x(a=b)', '(&(a=b)c)', '(&(a=b)|(c=d))',
    '(uniquemember=uuid=1, ou=users)', '(foo_bar=1)', '(_x=1)',
    '(a=b)(c=d)', '(&(objectClass=person)(|(uid=al*)(mail=*@x.com)))',
    '(a=<x>)', '(a=&)', '(a=|)', '(a=!)', '(a>=)', '(a~=)', '(a<=x',
    '(cn=a\\2ab*)', '(!(a=1)', '(&(a=1)', '(|(a=1)(b=2)', '(a=\\',
    '(a=\\0)', '(a=\\e2\\98)', '(a=b\u0000)', '(a=\\-1)', '(a=\\ 1)',
    '(member=cn=x,dc=y)', '(a:1.2.3:=\\28)', '(a::=x)', ''];
  function filterCase(input) {
    const out = { input: input };
    let f;
    try {
      f = ldapFilter.parseString(input);
    } catch (e) {
      out.ok = false;
      out.error = e.message;
      return out;
    }
    out.ok = true;
    out.tree = describeFilter(f);
    try {
      out.text = f.toString();
    } catch (e) {
      out.textError = e.message;
    }
    try {
      out.ber = hex(f.toBer().buffer);
    } catch (e) {
      out.berError = e.message;
    }
    return out;
  }
  const filters = filterInputs.map(filterCase);
  const filterBers = [fEq('cn', 'x'), fEq('cn', 'a(b'), fPresent('cn'),
    fAnd(), fOr(), fNot(fPresent('x')), fSub('cn', [[0x80, 'a*']]),
    fExt('r', 't', 'v', true), fExt(null, null, null, null),
    tlv(0xa3, str(0x04, 'cn'), tlv(0x04, Buffer.from([0xff]))),
    tlv(0xa3, str(0x04, 'cn'), tlv(0x04, Buffer.from([0xc3, 0x28]))),
    tlv(0xa3, str(0x04, 'cn'), tlv(0x04, Buffer.from([0xe9, 0x05]))),
    tlv(0xa3, str(0x04, 'cn'), tlv(0x04, Buffer.from([0x80, 0xbf]))),
    fGe('a', 'b'), fApprox('a', 'b'), fLe('a', ''), str(0x8a, 'x'),
    tlv(0xa3, str(0x04, 'cn')), fAnd(fEq('a', '1'), str(0x01, 'x'))]
    .map(function (b) {
      const out = { hex: hex(b) };
      let f;
      try {
        f = ldapFilter.parseBer(new (require(path.join(
          ROOT, 'node_modules', '@ldapjs', 'asn1')).BerReader)(b));
      } catch (e) {
        out.ok = false;
        out.error = e.message;
        return out;
      }
      out.ok = true;
      out.tree = describeFilter(f);
      try {
        out.text = f.toString();
      } catch (e) {
        out.textError = e.message;
      }
      try {
        out.ber = hex(f.toBer().buffer);
      } catch (e) {
        out.berError = e.message;
      }
      return out;
    });

  const escapes = {
    filter: ['', 'plain', 'a*b(c)d', '\\', 'x\\', '\\\\', '\\28', '\\2',
      '\\zz', '\\c3\\a9', '\\c3', '\\e2\\98\\83', '\\e2', 'é',
      '☃', '😀', '\u0000\u001f\u007f', '\n', 'a\\-1',
      '\\ 1', '\\5c\\5c', '\\c3\\'].map(function (x) {
      let r;
      try {
        r = { ok: true, value: escapeFilterValue(x) };
      } catch (e) {
        r = { ok: false, error: e.message };
      }
      return Object.assign({ input: x }, r);
    }),
    filterBuffers: [[0xc3], [0xe2, 0x82], [0xff, 0xfe], [0x80, 0x41],
      [0xc3, 0x05], [0xe2, 0x01, 0x02], [0x5c, 0x80, 0x41],
      [0xf0, 0x9f, 0x98, 0x80]].map(function (bytes) {
      let r;
      try {
        r = { ok: true, value: escapeFilterValue(Buffer.from(bytes)) };
      } catch (e) {
        r = { ok: false, error: e.message };
      }
      return Object.assign({ hex: hex(bytes) }, r);
    }),
    dn: ['', 'a', ' a', '#a', 'a ', ' ', '"+,;<>', '=\\', 'Jörg',
      '☃', '😀', '\u0001\u001f\u007f', 'a '].map(
      function (x) {
        return { input: x, value: escapeDnValueLib(x) };
      })
  };

  // ---- the responses the service sends ----------------------------------
  const responses = [];
  function response(kind, Klass, input) {
    const r = new Klass(Object.assign({}, input));
    responses.push(Object.assign({ kind: kind }, JSON.parse(JSON.stringify(
      input, function (k, x) {
        return x === undefined ? UNDEF : x;
      })), { hex: hex(r.toBer().buffer) }));
  }
  const resultKinds = [['bind', messages.BindResponse],
    ['add', messages.AddResponse], ['delete', messages.DeleteResponse],
    ['modify', messages.ModifyResponse],
    ['modifyDn', messages.ModifyDnResponse],
    ['compare', messages.CompareResponse],
    ['searchDone', messages.SearchResultDone],
    ['extended', messages.ExtensionResponse]];
  const statuses = Object.keys(ldap).filter(function (k) {
    return /^LDAP_/.test(k) && typeof ldap[k] === 'number';
  }).map(function (k) {
    return ldap[k];
  }).concat([16654, 4096, 113, 255, 256, 65536]);
  resultKinds.forEach(function (kind, k) {
    statuses.forEach(function (status, i) {
      response(kind[0], kind[1], { messageId: 1 + i + k * 100,
                                   status: status });
    });
    response(kind[0], kind[1], { messageId: 7, status: 53,
                                 matchedDN: 'ou=users,' + B,
                                 diagnosticMessage: 'refused: Jörg' });
    response(kind[0], kind[1], { messageId: 2147483647, status: 0,
                                 referrals: ['ldap://a/', 'ldap://b/x'] });
    response(kind[0], kind[1], { messageId: -129, status: 34 });
    response(kind[0], kind[1], { messageId: 0, status: 0,
                                 diagnosticMessage: 'd'.repeat(300) });
  });
  response('extended', messages.ExtensionResponse, {
    messageId: 9, status: 0, responseName: '1.3.6.1.4.1.4203.1.11.3',
    responseValue: 'dn:cn=a' });
  response('extended', messages.ExtensionResponse, {
    messageId: 9, status: 2, responseName: '1.3.6.1.4.1.1466.20037',
    diagnosticMessage: '1.3.6.1.4.1.1466.20037 not supported' });
  response('extended', messages.ExtensionResponse, {
    messageId: 9, status: 0, responseValue: '' });
  response('extended', messages.ExtensionResponse, {
    messageId: 9, status: 0, responseName: '' });
  function entry(input) {
    const r = new ldap.SearchEntry({
      messageId: input.messageId, objectName: input.objectName,
      attributes: input.attributes.map(function (a) {
        return new ldap.Attribute({ type: a.type, values: a.values });
      }) });
    let out;
    try {
      out = { hex: hex(r.toBer().buffer) };
    } catch (e) {
      out = { error: e.message };
    }
    responses.push(Object.assign({ kind: 'searchEntry' }, input, out));
  }
  entry({ messageId: 3, objectName: 'uid=alice,ou=users,' + B,
          attributes: [{ type: 'objectClass', values: ['top', 'person'] },
                       { type: 'uid', values: ['alice'] },
                       { type: 'cn', values: ['Alice Åberg'] }] });
  entry({ messageId: 3, objectName: '', attributes: [
    { type: 'namingContexts', values: [B, 'dc=acme,dc=example'] },
    { type: 'supportedLDAPVersion', values: ['3'] }] });
  entry({ messageId: 4, objectName: 'cn=x,' + B, attributes: [
    { type: 'userCertificate;binary', values: ['MIIBAAECAw=='] },
    { type: 'jpegPhoto;binary', values: ['not base64 !'] },
    { type: 'empty', values: [] }, { type: 'blank', values: [''] }] });
  entry({ messageId: 5, objectName: ' CN = Odd , DC=Spaces ',
          attributes: [] });
  entry({ messageId: 5, objectName: 'cn=Smith\\, John+uid=js,' + B,
          attributes: [{ type: 'description', values: ['v'.repeat(70000)] }]
  });
  entry({ messageId: 5, objectName: 'cn=#41,' + B, attributes: [] });
  entry({ messageId: 5, objectName: 'cn=\\e2\\98\\83 x,' + B,
          attributes: [] });
  entry({ messageId: 6, objectName: 'cn=many,' + B,
          attributes: Array.from({ length: 50 }, function (_, i) {
            return { type: 'a' + i, values: ['x' + i] };
          }) });
  [['ldap://h/dc=x'], ['ldap://a', 'ldap://b'], []].forEach(function (u) {
    const r = new ldap.SearchReference({ messageId: 8, uri: u });
    responses.push({ kind: 'searchReference', messageId: 8, uris: u,
                     hex: hex(r.toBer().buffer) });
  });

  const errors = Object.keys(ldap).filter(function (k) {
    return /^[A-Z]\w*Error$/.test(k) && k !== 'LDAPError' &&
      typeof ldap[k] === 'function';
  }).sort().map(function (k) {
    const e = new ldap[k]();
    return { name: k, code: u(e.code), message: e.message,
             withMessage: new ldap[k]('why').message,
             text: typeof e.code === 'number' ? ldap.getMessage(e.code)
               : UNDEF };
  });

  return { requests: requests, dns: dns, dnPairs: dnPairs,
           serviceDn: serviceDn, filters: filters, filterBers: filterBers,
           escapes: escapes, responses: responses, errors: errors };
}

/**
 * Whether two answers are the same JSON, keys in any order. Each side is
 * put through JSON first, so a key holding `undefined` is a key absent.
 *
 * @param {any} a - one answer
 * @param {any} b - the other
 * @returns {boolean} the same
 */
function same(a, b) {
  const canon = function (v) {
    if (Array.isArray(v)) {
      return v.map(canon);
    }
    if (v && typeof v === 'object') {
      const out = {};
      Object.keys(v).sort().forEach(function (k) {
        out[k] = canon(v[k]);
      });
      return out;
    }
    return v;
  };
  return JSON.stringify(canon(JSON.parse(JSON.stringify(a)))) ===
    JSON.stringify(canon(JSON.parse(JSON.stringify(b))));
}

/**
 * The other direction: what the Rust crate made, held to node-ldapjs.
 *
 *   requests   a corpus Rust built (each PDU Node dispatched, re-encoded
 *              by Rust, and mutations of them from a seed Node's corpus
 *              does not use) fed to the same server front: the same events
 *              and pending bytes as Rust's front answered
 *   responses  every response Rust encoded is the one node-ldapjs builds
 *              from the same fields, and reads back to the same bytes
 *              (not a result with referrals, whose referrals
 *              `LdapResult._parseToPojo()` never reads, nor an extended
 *              response with a value, which it reads as `<buffer>…`)
 *   filters    each filter string Rust printed reads in Node — tree, text,
 *              BER or refusal — as Rust reads it again
 *   dns        each DN Rust printed reads in Node as Rust reads it again
 *              (printing is not a fixed point of either: a DN value
 *              holding a backslash prints it unescaped, a filter value's
 *              escapes are printed again)
 *
 * @param {string} ROOT - the repository
 * @param {any} rust - ldap-wire-rust.json
 * @param {(ok: boolean, what: string) => void} check - the collector
 */
function checkRust(ROOT, rust, check) {
  const h = harness(ROOT);
  const asn1 = require(path.join(ROOT, 'node_modules', '@ldapjs', 'asn1'));
  const KINDS = { bind: 'BindResponse', add: 'AddResponse',
                  delete: 'DeleteResponse', modify: 'ModifyResponse',
                  modifyDn: 'ModifyDnResponse',
                  compare: 'CompareResponse',
                  searchDone: 'SearchResultDone',
                  extended: 'ExtensionResponse' };
  let bad = 0;
  rust.requests.forEach(function (r) {
    const out = h.front(r.chunks.map(function (c) {
      return Buffer.from(c, 'hex');
    }));
    if (!same(out, { events: r.events, pending: r.pending })) {
      bad++;
      if (bad <= 10) {
        check(false, 'the front answers ' + r.name + ' as Rust did: Node ' +
              JSON.stringify(out) + ', Rust ' + JSON.stringify(r));
      }
    }
  });
  check(bad === 0, rust.requests.length + ' PDUs Rust built get the ' +
        'same events from the node-ldapjs front as from Rust\'s (' + bad +
        ' differ)');
  let built = 0;
  let readBack = 0;
  rust.responses.forEach(function (r) {
    if (r.error) {
      return;
    }
    let mine;
    if (r.kind === 'searchEntry') {
      mine = new h.ldap.SearchEntry({
        messageId: r.messageId, objectName: r.objectName,
        attributes: r.attributes.map(function (a) {
          return new h.ldap.Attribute({ type: a.type, values: a.values });
        }) });
    } else if (r.kind === 'searchReference') {
      mine = new h.ldap.SearchReference({ messageId: r.messageId,
                                          uri: r.uris });
    } else {
      const input = Object.assign({}, r);
      delete input.kind;
      delete input.hex;
      Object.keys(input).forEach(function (k) {
        if (input[k] && input[k].undefined === true) {
          input[k] = undefined;
        }
      });
      mine = new h.messages[KINDS[r.kind]](input);
    }
    const hex = h.hex(mine.toBer().buffer);
    check(hex === r.hex, 'node-ldapjs builds the ' + r.kind + ' Rust ' +
          'encoded (message ' + r.messageId + ')');
    built++;
    const skip = (r.referrals && r.referrals.length > 0) ||
      (r.kind === 'extended' && r.responseValue !== undefined);
    if (!skip) {
      const parsed = h.messages.LdapMessage.parse(
        new asn1.BerReader(Buffer.from(r.hex, 'hex')));
      check(h.hex(parsed.toBer().buffer) === r.hex, 'node-ldapjs reads ' +
            'the ' + r.kind + ' Rust encoded back to the same bytes');
      readBack++;
    }
  });
  check(built > 0 && readBack > 0, built + ' responses Rust encoded are ' +
        'node-ldapjs\'s, ' + readBack + ' read back');
  rust.filters.forEach(function (f) {
    const out = { input: f.input };
    try {
      const parsed = h.ldapFilter.parseString(f.input);
      out.ok = true;
      out.tree = h.describeFilter(parsed);
      out.text = parsed.toString();
      out.ber = h.hex(parsed.toBer().buffer);
    } catch (e) {
      out.ok = false;
      out.error = e.message;
    }
    check(same(out, f), 'the filter Rust printed, ' + f.input + ', reads ' +
          'in Node as Rust reads it');
  });
  rust.dns.forEach(function (d) {
    let out;
    try {
      const dn = h.DN.fromString(d.input);
      out = { input: d.input, ok: true, text: dn.toString(),
              length: dn.length };
    } catch (e) {
      out = { input: d.input, ok: false, error: e.message };
    }
    const mine = Object.assign({}, d);
    delete mine.rdns;
    check(same(out, mine), 'the DN Rust printed, ' + d.input + ', reads ' +
          'in Node as Rust reads it');
  });
}

module.exports = { build: build, checkRust: checkRust };
