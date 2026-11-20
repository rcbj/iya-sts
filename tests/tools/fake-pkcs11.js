// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/fake-pkcs11.js
//
// ---------------------------------------------------------------------------
// A FAKE PKCS#11 BINDING, SHAPED AS `pkcs11js` IS (#1955 P8), for the tests
// that cannot load a real module: `tests/pkcs11_kek.js` and
// `tests/pkcs11_signing.js` hand it to `common/secrets.js` through
// `setSdkLoader()`.
//
// It keeps tokens, sessions, a login and objects, and does the cryptography
// a module would with node's own: AES-256-GCM through C_Encrypt with the
// caller's IV and additional data, RFC 5649 key wrap with padding through
// C_WrapKey / C_UnwrapKey (node's `id-aes256-wrap-pad`), the YubiHSM's
// CKM_YUBICO_AES_CCM_WRAP as AES-256-CCM with a 13-byte nonce, and RSA,
// ECDSA (over a digest, answering r || s) and EdDSA signatures with keys it
// never hands out. A token can be told to offer only some mechanisms, and
// the binding can be told to lose every session (`loseDevice()`), which is
// what a connector restart looks like from the client.
//
// It is a TEST'S fake: it holds the PKCS#11 numbers it needs, and nothing
// in the service requires it.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');

const CKA = { CLASS: 0x0, TOKEN: 0x1, PRIVATE: 0x2, LABEL: 0x3, VALUE: 0x11,
              KEY_TYPE: 0x100, ID: 0x102, SENSITIVE: 0x103, EXTRACTABLE: 0x162,
              VALUE_LEN: 0x161, MODULUS: 0x120, PUBLIC_EXPONENT: 0x122,
              EC_PARAMS: 0x180, EC_POINT: 0x181, MODULUS_BITS: 0x121 };
const CKM = { AES_KEY_GEN: 0x1080, AES_GCM: 0x1087, KWP: 0x210a,
              YUBICO_CCM: 0xd9554204, RSA_GEN: 0x0, EC_GEN: 0x1040,
              ED_GEN: 0x1055, ECDSA: 0x1041, EDDSA: 0x1057,
              RS256: 0x40, RS384: 0x41, RS512: 0x42, PS256: 0x43,
              PS384: 0x44, PS512: 0x45 };
const FLAGS = { ENCRYPT: 0x100, DECRYPT: 0x200, SIGN: 0x800, WRAP: 0x20000,
                UNWRAP: 0x40000, GENERATE_PAIR: 0x10000, GENERATE: 0x8000 };
const CURVES = { '06082a8648ce3d030107': 'prime256v1',
                 '06052b81040022': 'secp384r1',
                 '06052b81040023': 'secp521r1',
                 '06052b8104000a': 'secp256k1',
                 '06032b6570': 'ed25519' };

// Every mechanism, with the flags a module would answer.
const ALL_MECHS = new Map([
  [CKM.AES_KEY_GEN, FLAGS.GENERATE], [CKM.AES_GCM, FLAGS.ENCRYPT |
                                      FLAGS.DECRYPT],
  [CKM.KWP, FLAGS.WRAP | FLAGS.UNWRAP], [CKM.YUBICO_CCM, FLAGS.ENCRYPT |
                                         FLAGS.DECRYPT],
  [CKM.RSA_GEN, FLAGS.GENERATE_PAIR], [CKM.EC_GEN, FLAGS.GENERATE_PAIR],
  [CKM.ED_GEN, FLAGS.GENERATE_PAIR], [CKM.ECDSA, FLAGS.SIGN],
  [CKM.EDDSA, FLAGS.SIGN], [CKM.RS256, FLAGS.SIGN], [CKM.RS384, FLAGS.SIGN],
  [CKM.RS512, FLAGS.SIGN], [CKM.PS256, FLAGS.SIGN], [CKM.PS384, FLAGS.SIGN],
  [CKM.PS512, FLAGS.SIGN]
]);

class Pkcs11Error extends Error {
  constructor(name, code) {
    super(name);
    this.code = code;
  }
}

function fail(name, code) {
  throw new Pkcs11Error(name, code);
}

// An attribute value as the module would store and answer it.
function norm(type, value) {
  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }
  if (typeof value === 'boolean') {
    return Buffer.from([value ? 1 : 0]);
  }
  if (typeof value === 'number') {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(value));
    return b;
  }
  return Buffer.from(String(value), 'utf8');
}

/**
 * Builds a fake binding.
 *
 * @param options - `{ modulePath, tokens: [{ label, serial, pin, mechs }] }`
 *   where `mechs` is a list of mechanism numbers (all when absent)
 * @returns the binding, with `state`, `addSecretKey()`, `loseDevice()` and
 *   `breakAlways()` for the test
 */
function fakeBinding(options) {
  const o = options || {};
  const state = {
    modulePath: o.modulePath || '/fake/libfake-pkcs11.so',
    initialized: false,
    tokens: (o.tokens || [{ label: 'sts', pin: '1234' }]).map(function (t,
                                                                         i) {
      return { label: t.label, serial: t.serial || ('S' + i), pin: t.pin,
               mechs: t.mechs ? new Map(t.mechs.map(function (m) {
                 return [m, ALL_MECHS.get(m) || 0];
               })) : new Map(ALL_MECHS),
               objects: new Map(), loggedIn: false };
    }),
    sessions: new Map(),
    nextHandle: 1,
    nextSession: 1,
    down: 0,
    loseOnce: 0,
    calls: []
  };

  function token(slot) {
    const t = state.tokens[Number(slot)];
    if (!t) {
      fail('CKR_SLOT_ID_INVALID', 0x3);
    }
    return t;
  }
  function check(op) {
    state.calls.push(op);
    if (!state.initialized) {
      fail('CKR_CRYPTOKI_NOT_INITIALIZED', 0x190);
    }
    if (state.down) {
      fail('CKR_DEVICE_ERROR', 0x30);
    }
    if (state.loseOnce) {
      state.loseOnce = 0;
      state.sessions.clear();
      state.tokens.forEach(function (t) {
        t.loggedIn = false;
      });
      fail('CKR_DEVICE_ERROR', 0x30);
    }
  }
  function session(s) {
    const one = state.sessions.get(Number(s));
    if (!one) {
      fail('CKR_SESSION_HANDLE_INVALID', 0xb3);
    }
    return one;
  }
  function object(sess, h) {
    const obj = token(sess.slot).objects.get(Number(h));
    if (!obj) {
      fail('CKR_OBJECT_HANDLE_INVALID', 0x82);
    }
    const priv = obj.attrs.get(CKA.PRIVATE);
    if (priv && priv[0] && !token(sess.slot).loggedIn) {
      fail('CKR_USER_NOT_LOGGED_IN', 0x101);
    }
    return obj;
  }
  function addObject(t, attrs, extra) {
    const h = state.nextHandle++;
    const map = new Map();
    attrs.forEach(function (a) {
      map.set(a.type, norm(a.type, a.value));
    });
    t.objects.set(h, Object.assign({ attrs: map }, extra || {}));
    return h;
  }
  function matches(obj, template) {
    return template.every(function (a) {
      const have = obj.attrs.get(a.type);
      return have && have.equals(norm(a.type, a.value));
    });
  }
  function secretValue(obj) {
    return obj.secret;
  }

  function PKCS11() {}
  PKCS11.prototype.load = function (p) {
    if (p !== state.modulePath) {
      throw new Error('dlopen(' + p + '): no such file');
    }
  };
  PKCS11.prototype.C_Initialize = function () {
    if (state.initialized) {
      fail('CKR_CRYPTOKI_ALREADY_INITIALIZED', 0x191);
    }
    state.initialized = true;
  };
  PKCS11.prototype.C_Finalize = function () {
    state.initialized = false;
    state.sessions.clear();
    state.tokens.forEach(function (t) {
      t.loggedIn = false;
    });
  };
  PKCS11.prototype.C_GetSlotList = function () {
    check('C_GetSlotList');
    return state.tokens.map(function (t, i) {
      return i;
    });
  };
  PKCS11.prototype.C_GetTokenInfo = function (slot) {
    check('C_GetTokenInfo');
    const t = token(slot);
    return { label: (t.label + '                                ')
      .slice(0, 32), serialNumber: t.serial };
  };
  PKCS11.prototype.C_GetMechanismList = function (slot) {
    check('C_GetMechanismList');
    return Array.from(token(slot).mechs.keys());
  };
  PKCS11.prototype.C_GetMechanismInfo = function (slot, m) {
    check('C_GetMechanismInfo');
    return { minKeySize: 0, maxKeySize: 0, flags: token(slot).mechs.get(m) };
  };
  PKCS11.prototype.C_OpenSession = function (slot) {
    check('C_OpenSession');
    token(slot);
    const id = state.nextSession++;
    state.sessions.set(id, { slot: Number(slot), op: null, find: null });
    return id;
  };
  PKCS11.prototype.C_CloseSession = function (s) {
    const one = state.sessions.get(Number(s));
    state.sessions.delete(Number(s));
    if (one && !Array.from(state.sessions.values()).some(function (x) {
      return x.slot === one.slot;
    })) {
      token(one.slot).loggedIn = false;
    }
  };
  PKCS11.prototype.C_Login = function (s, user, pin) {
    check('C_Login');
    const t = token(session(s).slot);
    if (t.loggedIn) {
      fail('CKR_USER_ALREADY_LOGGED_IN', 0x100);
    }
    if (String(pin) !== String(t.pin)) {
      fail('CKR_PIN_INCORRECT', 0xa0);
    }
    t.loggedIn = true;
  };
  PKCS11.prototype.C_FindObjectsInit = function (s, template) {
    check('C_FindObjectsInit');
    const sess = session(s);
    const t = token(sess.slot);
    sess.find = Array.from(t.objects.entries()).filter(function (e) {
      const priv = e[1].attrs.get(CKA.PRIVATE);
      if (priv && priv[0] && !t.loggedIn) {
        return false;
      }
      return matches(e[1], template);
    }).map(function (e) {
      return e[0];
    });
  };
  PKCS11.prototype.C_FindObjects = function (s, n) {
    check('C_FindObjects');
    const sess = session(s);
    return sess.find.splice(0, n || 1);
  };
  PKCS11.prototype.C_FindObjectsFinal = function (s) {
    session(s).find = null;
  };
  PKCS11.prototype.C_GetAttributeValue = function (s, h, template) {
    check('C_GetAttributeValue');
    const sess = session(s);
    const obj = object(sess, h);
    return template.map(function (a) {
      if (a.type === CKA.VALUE) {
        const sens = obj.attrs.get(CKA.SENSITIVE);
        const ext = obj.attrs.get(CKA.EXTRACTABLE);
        if ((sens && sens[0]) || (ext && !ext[0])) {
          fail('CKR_ATTRIBUTE_SENSITIVE', 0x11);
        }
        return { type: a.type, value: Buffer.from(secretValue(obj)) };
      }
      if (a.type === CKA.MODULUS || a.type === CKA.PUBLIC_EXPONENT ||
          a.type === CKA.EC_POINT) {
        return { type: a.type, value: obj.publicAttr(a.type) };
      }
      const v = obj.attrs.get(a.type);
      if (!v) {
        fail('CKR_ATTRIBUTE_TYPE_INVALID', 0x12);
      }
      return { type: a.type, value: v };
    });
  };
  PKCS11.prototype.C_GenerateKey = function (s, mech, template) {
    check('C_GenerateKey');
    const sess = session(s);
    const t = token(sess.slot);
    if (mech.mechanism !== CKM.AES_KEY_GEN || !t.mechs.has(CKM.AES_KEY_GEN)) {
      fail('CKR_MECHANISM_INVALID', 0x70);
    }
    return addObject(t, template.concat([{ type: CKA.KEY_TYPE, value: 0x1f }]),
                     { secret: nodeCrypto.randomBytes(32) });
  };
  PKCS11.prototype.C_CreateObject = function (s, template) {
    check('C_CreateObject');
    const sess = session(s);
    const value = template.filter(function (a) {
      return a.type === CKA.VALUE;
    })[0];
    return addObject(token(sess.slot), template.filter(function (a) {
      return a.type !== CKA.VALUE;
    }), { secret: Buffer.from(value.value) });
  };
  PKCS11.prototype.C_DestroyObject = function (s, h) {
    const sess = session(s);
    token(sess.slot).objects.delete(Number(h));
  };

  function cipherOp(s, mech, h, encrypt) {
    check(encrypt ? 'C_EncryptInit' : 'C_DecryptInit');
    const sess = session(s);
    const t = token(sess.slot);
    const obj = object(sess, h);
    if (!t.mechs.has(mech.mechanism)) {
      fail('CKR_MECHANISM_INVALID', 0x70);
    }
    sess.op = { kind: encrypt ? 'enc' : 'dec', mech: mech, key: obj.secret };
  }
  function cipherRun(s, data) {
    check('C_Encrypt');
    const sess = session(s);
    const op = sess.op;
    sess.op = null;
    if (!op) {
      fail('CKR_OPERATION_NOT_INITIALIZED', 0x91);
    }
    if (op.mech.mechanism === CKM.AES_GCM) {
      const p = op.mech.parameter;
      if (op.kind === 'enc') {
        const c = nodeCrypto.createCipheriv('aes-256-gcm', op.key, p.iv);
        c.setAAD(p.aad);
        return Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
      }
      try {
        const d = nodeCrypto.createDecipheriv('aes-256-gcm', op.key, p.iv);
        d.setAAD(p.aad);
        d.setAuthTag(data.subarray(data.length - 16));
        return Buffer.concat([d.update(data.subarray(0, data.length - 16)),
                              d.final()]);
      } catch (e) {
        fail('CKR_GENERAL_ERROR', 0x5);
      }
    }
    // CKM_YUBICO_AES_CCM_WRAP: nonce (13) || ciphertext || tag (16).
    if (op.kind === 'enc') {
      const nonce = nodeCrypto.randomBytes(13);
      const c = nodeCrypto.createCipheriv('aes-256-ccm', op.key, nonce,
                                          { authTagLength: 16 });
      const ct = Buffer.concat([c.update(data), c.final()]);
      return Buffer.concat([nonce, ct, c.getAuthTag()]);
    }
    try {
      const nonce = data.subarray(0, 13);
      const tag = data.subarray(data.length - 16);
      const d = nodeCrypto.createDecipheriv('aes-256-ccm', op.key, nonce,
                                            { authTagLength: 16 });
      d.setAuthTag(tag);
      return Buffer.concat([d.update(data.subarray(13, data.length - 16)),
                            d.final()]);
    } catch (e) {
      fail('CKR_ENCRYPTED_DATA_INVALID', 0x40);
    }
    return null;
  }
  PKCS11.prototype.C_EncryptInit = function (s, mech, h) {
    cipherOp(s, mech, h, true);
  };
  PKCS11.prototype.C_DecryptInit = function (s, mech, h) {
    cipherOp(s, mech, h, false);
  };
  PKCS11.prototype.C_Encrypt = function (s, data) {
    return cipherRun(s, data);
  };
  PKCS11.prototype.C_Decrypt = function (s, data) {
    return cipherRun(s, data);
  };
  PKCS11.prototype.C_EncryptAsync = function (s, data) {
    const self = this;
    return new Promise(function (resolve) {
      setImmediate(resolve);
    }).then(function () {
      return self.C_Encrypt(s, data);
    });
  };
  PKCS11.prototype.C_DecryptAsync = function (s, data) {
    const self = this;
    return new Promise(function (resolve) {
      setImmediate(resolve);
    }).then(function () {
      return self.C_Decrypt(s, data);
    });
  };
  const KWP_IV = Buffer.from('a65959a6', 'hex');
  PKCS11.prototype.C_WrapKey = function (s, mech, wrapping, key) {
    check('C_WrapKey');
    const sess = session(s);
    const t = token(sess.slot);
    if (mech.mechanism !== CKM.KWP || !t.mechs.has(CKM.KWP)) {
      fail('CKR_MECHANISM_INVALID', 0x70);
    }
    const kek = object(sess, wrapping);
    const target = object(sess, key);
    const c = nodeCrypto.createCipheriv('id-aes256-wrap-pad', kek.secret,
                                        KWP_IV);
    return Buffer.concat([c.update(target.secret), c.final()]);
  };
  PKCS11.prototype.C_UnwrapKey = function (s, mech, unwrapping, wrapped,
                                           template) {
    check('C_UnwrapKey');
    const sess = session(s);
    const kek = object(sess, unwrapping);
    let plain;
    try {
      const d = nodeCrypto.createDecipheriv('id-aes256-wrap-pad', kek.secret,
                                            KWP_IV);
      plain = Buffer.concat([d.update(wrapped), d.final()]);
    } catch (e) {
      fail('CKR_WRAPPED_KEY_INVALID', 0x110);
    }
    return addObject(token(sess.slot), template, { secret: plain });
  };

  // ------------------------------------------------------------- SIGNING
  PKCS11.prototype.C_GenerateKeyPair = function (s, mech, pubT, privT) {
    check('C_GenerateKeyPair');
    const sess = session(s);
    const t = token(sess.slot);
    if (!t.mechs.has(mech.mechanism)) {
      fail('CKR_MECHANISM_INVALID', 0x70);
    }
    let pair;
    if (mech.mechanism === CKM.RSA_GEN) {
      const bits = pubT.filter(function (a) {
        return a.type === CKA.MODULUS_BITS;
      })[0].value;
      pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: bits });
    } else {
      const oid = Buffer.from(pubT.filter(function (a) {
        return a.type === CKA.EC_PARAMS;
      })[0].value).toString('hex');
      const curve = CURVES[oid];
      if (!curve) {
        fail('CKR_DOMAIN_PARAMS_INVALID', 0x130);
      }
      pair = curve === 'ed25519' ? nodeCrypto.generateKeyPairSync('ed25519')
        : nodeCrypto.generateKeyPairSync('ec', { namedCurve: curve });
    }
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const publicAttr = function (type) {
      if (type === CKA.MODULUS) {
        return Buffer.from(jwk.n, 'base64url');
      }
      if (type === CKA.PUBLIC_EXPONENT) {
        return Buffer.from(jwk.e, 'base64url');
      }
      const point = jwk.kty === 'OKP' ? Buffer.from(jwk.x, 'base64url') :
        Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'),
                       Buffer.from(jwk.y, 'base64url')]);
      const len = point.length < 128 ? Buffer.from([point.length]) :
                                       Buffer.from([0x81, point.length]);
      return Buffer.concat([Buffer.from([4]), len, point]);
    };
    const pub = addObject(t, pubT.concat([{ type: CKA.CLASS, value: 2 }]),
                          { publicAttr: publicAttr });
    const priv = addObject(t, privT.concat([{ type: CKA.CLASS, value: 3 }]),
                           { privateKey: pair.privateKey,
                             publicAttr: publicAttr });
    return { publicKey: pub, privateKey: priv };
  };
  PKCS11.prototype.C_SignInit = function (s, mech, h) {
    check('C_SignInit');
    const sess = session(s);
    const obj = object(sess, h);
    if (!obj.privateKey) {
      fail('CKR_KEY_TYPE_INCONSISTENT', 0x63);
    }
    sess.op = { kind: 'sign', mech: mech, key: obj.privateKey };
  };
  PKCS11.prototype.C_Sign = function (s, data) {
    check('C_Sign');
    const sess = session(s);
    const op = sess.op;
    sess.op = null;
    if (!op || op.kind !== 'sign') {
      fail('CKR_OPERATION_NOT_INITIALIZED', 0x91);
    }
    const m = op.mech.mechanism;
    const hashes = { [CKM.RS256]: 'sha256', [CKM.RS384]: 'sha384',
                     [CKM.RS512]: 'sha512', [CKM.PS256]: 'sha256',
                     [CKM.PS384]: 'sha384', [CKM.PS512]: 'sha512' };
    if (hashes[m] && m >= CKM.PS256) {
      return nodeCrypto.sign(hashes[m], data, {
        key: op.key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: op.mech.parameter.saltLen });
    }
    if (hashes[m]) {
      return nodeCrypto.sign(hashes[m], data, op.key);
    }
    if (m === CKM.EDDSA) {
      return nodeCrypto.sign(null, data, op.key);
    }
    // CKM_ECDSA over a digest, answering r || s.
    return ecdsaSignDigest(op.key, data);
  };
  PKCS11.prototype.C_SignAsync = function (s, data) {
    const self = this;
    return new Promise(function (resolve) {
      setImmediate(resolve);
    }).then(function () {
      return self.C_Sign(s, data);
    });
  };

  const binding = {
    PKCS11: PKCS11,
    Pkcs11Error: Pkcs11Error,
    CK_PARAMS_AES_GCM: 3,
    CK_PARAMS_RSA_PSS: 5,
    state: state,
    // An existing AES key (or a YubiHSM wrap key), made "with the HSM's own
    // tool".
    addSecretKey: function (label, opts) {
      const op = opts || {};
      const t = state.tokens[op.slot || 0];
      return addObject(t, [{ type: CKA.CLASS, value: 4 },
                           { type: CKA.KEY_TYPE,
                             value: op.keyType === undefined ? 0x1f :
                                    op.keyType },
                           { type: CKA.LABEL, value: label },
                           { type: CKA.TOKEN, value: true },
                           { type: CKA.PRIVATE, value: true },
                           { type: CKA.SENSITIVE, value: true },
                           { type: CKA.EXTRACTABLE, value: !!op.extractable },
                           { type: CKA.VALUE_LEN, value: op.bytes || 32 }]
                     .concat(op.id ? [{ type: CKA.ID, value: op.id }] : []),
                       { secret: nodeCrypto.randomBytes(op.bytes || 32) });
    },
    // A connector restart: the next call fails and every session is gone.
    loseDevice: function () {
      state.loseOnce = 1;
    },
    // The device stays away until put back.
    breakAlways: function (down) {
      state.down = down ? 1 : 0;
    }
  };
  return binding;
}

// An ECDSA signature over a DIGEST (CKM_ECDSA's input), as r || s. node
// signs messages and hashes them itself, so the digest is signed with
// @noble/curves (a dependency of the service already), which takes a hash.
function ecdsaSignDigest(key, digest) {
  const jwk = key.export({ format: 'jwk' });
  const noble = {
    'P-256': function () { return require('@noble/curves/p256').p256; },
    'P-384': function () { return require('@noble/curves/p384').p384; },
    'P-521': function () { return require('@noble/curves/p521').p521; },
    'secp256k1': function () {
      return require('@noble/curves/secp256k1').secp256k1;
    }
  }[jwk.crv]();
  const sig = noble.sign(Buffer.from(digest),
                         Buffer.from(jwk.d, 'base64url'), { lowS: false });
  return Buffer.from(sig.toCompactRawBytes());
}

module.exports = { fakeBinding: fakeBinding, CKM: CKM };
