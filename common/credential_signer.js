// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: credential_signer.js
//
// ===========================================================================
// THE KEY A REALM SIGNS ITS CREDENTIALS WITH, AND THE CERTIFICATE THAT BINDS
// IT TO THE ISSUER (#1880, for 1.1.0).
//
// Until 1.1.0 an SD-JWT VC, a `jwt_vc_json` credential and the Token Status
// List Token that describes them were signed with the realm's GENERAL JOSE
// key: the key that signs every ID Token, access token, introspection
// response, signed metadata document, Security Event Token and GNAP token.
// Its certificate's `x5c` carried a chain to the service Root and named no
// issuer, so a wallet following HAIP 1.0 section 6.1.1 had nothing to compare
// the credential's `iss` with. A `uniformResourceIdentifier` subjectAltName
// on that certificate would have fixed the comparison and broken something
// worse: every token the key signs would then be attributable to the
// credential issuer, and a certificate with a `dNSName` and no extended key
// usage is, to most TLS stacks, a server certificate for that host (RFC 5280
// section 4.2.1.12: no EKU means any purpose).
//
// So the credentials get a key of their OWN, per realm and per key family,
// used for nothing else, under a certificate that says what it is for:
//
//   * subjectAltName: one `uniformResourceIdentifier` for every issuer
//     identifier the realm answers to (`issuerUris()`, below), and the
//     `did:web` of each, because a realm may name its issuer by DID. NO
//     `dNSName`, ever.
//   * extendedKeyUsage: `id-kp-documentSigning` (RFC 9336) alone, which no
//     TLS stack takes for `serverAuth` or `clientAuth`.
//   * keyUsage: `digitalSignature` alone, critical. Not `keyEncipherment`
//     (these keys never decrypt, and an EC key cannot), and not
//     `nonRepudiation`: the signature is the service's, made automatically,
//     and no person commits to anything with it.
//
// **WHAT MOVES HERE AND WHAT DOES NOT.** The `vci-credential` use case of
// `common/jose_certificate_header.js` covers the SD-JWT VC issuer JWT, the
// `jwt_vc_json` JWT and the Token Status List Token, and all three sign
// here. The status list is signed by the same key as the credentials it
// describes, so a verifier resolves one key per issuer (draft-ietf-oauth-
// status-list section 11.3, and `vc_status.ts`'s `signerAsync()`). The ETSI
// trusted list (`vci-trusted-list`) does NOT: it is signed by the list's
// SCHEME OPERATOR, a different role, carries no `iss`, and lists the service
// Root as the anchor of its issuance and revocation services, and the
// certificates here chain to that Root. The signed issuer metadata and the
// OpenID4VP request objects are not credentials, and stay where they are.
//
// **EVERY ALGORITHM `oid4vci.credentialSigningAlgorithm` CAN NAME.** One key
// per key family: an RSA key for every RS* and PS* algorithm, one per curve
// (ES256, ES384, ES512, ES256K, and EdDSA on the curve `oauth2.eddsaCurve`
// names), and one per post-quantum algorithm, the composites included. Each
// has a certificate of its own, whose subjectPublicKeyInfo IS that key, so
// RFC 7515 section 4.1.6 holds for `x5c`. **A post-quantum key is never a
// PARTNER here**: the hybrid-groups model certifies an ML-DSA key as the
// alternative key of its classical partner's certificate, which binds
// nothing to the ML-DSA signature (`helpers.certificateSignerFor()`'s D5), and
// that arrangement is not carried over to credentials.
//
// **MADE WHEN FIRST ASKED FOR, OFF THE EVENT LOOP**, on libuv's thread pool,
// as the signer groups and the post-quantum keys are (`helpers.js`): a realm
// that never issues a credential holds none, and one that issues RS256 holds
// an RSA key and nothing else. A key is a member of the key set
// (`credentialSigners`, in `keystore.js`), sealed, shared and stored with
// it, joined BY SLOT so a race never replaces a key a credential was already
// signed with, and minted under a cluster claim so two nodes do not each make
// one. A rotation of the realm's general keys carries them over unchanged.
//
// **THE CERTIFICATE NEVER GOES STALE.** It is checked before every
// credential is signed (`ensureCertificate()`): a held certificate is used
// again only while it is over this key, from the Issuing CA the branch holds
// now, still chaining to the Root, with more than a third of its validity
// left, carrying documentSigning, and naming EXACTLY the issuer addresses the
// realm answers to now. Anything else is re-issued, and the certificate it
// replaces is NOT revoked: `pki.certify()` keeps it in the issued register as
// a displaced record, so a credential issued under it goes on verifying.
//
// `keys.credentialSigner` is the way back: `realm-key` signs with the realm's
// general JOSE key, as 1.0.0 did, and binds nothing. `dedicated`, the
// default, is everything above.
//
// A LEAF in the require graph below `helpers.js`, which wires it: it requires
// `config`, `crypto`, `keystore`, `pq_jose`, `realms`, `listener_map`,
// `hosted_applications`, `error_codes` and `mode`, never `helpers`, and
// reaches `pki` and `cluster/cluster_claims` lazily.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');
const stsCrypto = require('./crypto');
const keystore = require('./keystore');
const pqJose = require('./pq_jose');
const realms = require('./realms');
const listenerMap = require('./listener_map');
const hostedApplications = require('./hosted_applications');
const errorCodes = require('./error_codes');

const log = bunyan.createLogger({
  name: 'credential_signer',
  level: config.value('global.logLevel')
});

/**
 * The values `keys.credentialSigner` takes: `dedicated` (the default) and
 * `realm-key`, 1.0.0's behaviour.
 */
const MODES = ['dedicated', 'realm-key'];
/** The default of `keys.credentialSigner`. */
const DEFAULT_MODE = 'dedicated';
/** The `group` every credential-signer row carries in the stored blob. */
const GROUP = 'vc-issuer';
/** The prefix of a credential signer's certificate slot under `jose`. */
const PKI_SLOT_PREFIX = 'vc-issuer:';
/** The prefix of a credential signer's `kid`. */
const KID_PREFIX = 'sts-vc-';
/** The extended key usage of every credential-signing certificate. */
const EKU = 'documentSigning';
/** Its OID (RFC 9336). */
const EKU_OID = '1.3.6.1.5.5.7.3.36';
/** The keyUsage of every credential-signing certificate. */
const KEY_USAGE = ['digitalSignature'];
// The most issuer identifiers one certificate names. A deployment with more
// names than this has a configuration nobody can reason about, and a
// certificate the size of a page is one no wallet should have to parse.
const MAX_URIS = 64;
// How long a request waits for a certificate to be issued before the
// credential is signed with whatever is held: `helpers.js`'s
// CERTIFICATE_WAIT_MS, and for its reason.
const CERTIFICATE_WAIT_MS = 5000;
// The claim a node takes to mint one key family of a realm, and how long a
// node that lost it waits for the winner's key — the signer groups' numbers.
const MINT_SCOPE = 'keys.credential-signer-mint';
const MINT_WAIT_MS = 15000;
const MINT_POLL_MS = 100;

// One generation per realm and slot in this process at a time.
const minting = new Map();
// One certification per realm and slot in this process at a time.
const certifying = new Map();
// The `iss` values already reported as unnamed, per realm, bounded.
const warnedUnbound = new Set();

/**
 * Tells whether the ambient realm signs its credentials with the dedicated
 * credential signer (`keys.credentialSigner` is `dedicated`, the default).
 *
 * @returns true unless the realm asked for 1.0.0's `realm-key`
 */
function dedicatedOn() {
  log.debug("Entering dedicatedOn().");
  const value = String(config.value('keys.credentialSigner') ||
                       DEFAULT_MODE);
  log.debug("Leaving dedicatedOn(). " + value);
  return value !== 'realm-key';
}

/**
 * The key family that signs a JWS algorithm: its slot, its kind and the
 * algorithm its key is made for.
 *
 * @param alg - the JWS algorithm
 * @param curveSpecs - `helpers.js`'s CURVE_KEY_SPECS rows
 * @returns `{ slot, kind, alg, curveSpec, keyAlg }`
 * @throws Error for an algorithm no credential can be signed with
 */
function familyOf(alg, curveSpecs) {
  log.debug("Entering familyOf(). alg=" + alg);
  const name = String(alg || '');
  if (/^(RS|PS)(256|384|512)$/.test(name)) {
    log.debug("Leaving familyOf(). RSA.");
    return { slot: 'RSA', kind: 'rsa', alg: 'RS256', curveSpec: null,
             keyAlg: 'rsa-' + require('./mode').defaultRsaBits() };
  }
  if (pqJose.isPqAlg(name)) {
    log.debug("Leaving familyOf(). Post-quantum.");
    return { slot: name, kind: 'pq', alg: name, curveSpec: null,
             keyAlg: name.toLowerCase() };
  }
  const curve = name === 'EdDSA'
    ? String(config.value('oauth2.eddsaCurve') || 'Ed25519') : '';
  const spec = (curveSpecs || []).filter(function (one) {
    return one.alg === name &&
           (name !== 'EdDSA' || (one.curve || 'Ed25519') === curve);
  })[0];
  if (!spec) {
    log.debug("Leaving familyOf(). No key family.");
    throw errorCodes.mark(new Error('a credential cannot be signed with "' +
      name + '": it is not an asymmetric JWS algorithm this service holds ' +
      'a key family for.'), 'STS-PKI-0282');
  }
  const slot = name === 'EdDSA' ? 'EdDSA:' + curve : name;
  log.debug("Leaving familyOf(). " + slot + ".");
  return { slot: slot, kind: 'curve', alg: name, curveSpec: spec,
           keyAlg: (curve || name).toLowerCase() };
}

/**
 * The certificate slot, under the `jose` use case, of a credential signer.
 *
 * @param slot - the key family's slot (`RSA`, `ES256`, `ML-DSA-65` ...)
 * @returns `vc-issuer:<slot>`
 */
function pkiSlotOf(slot) {
  log.debug("Entering pkiSlotOf().");
  log.debug("Leaving pkiSlotOf().");
  return PKI_SLOT_PREFIX + String(slot);
}

/**
 * Tells whether a `kid` names a credential signer (cheap: the prefix).
 *
 * @param kid - a key's internal `kid`
 * @returns true for `sts-vc-…`
 */
function isCredentialKid(kid) {
  log.debug("Entering isCredentialKid().");
  log.debug("Leaving isCredentialKid().");
  return String(kid || '').indexOf(KID_PREFIX) === 0;
}

// The kid: `sts-vc-<slot>-<hash of the public key>`, from the key's own
// material like every kid here, and unable to collide with a per-algorithm
// key's (`sts-es256-…`) or a signer group's (`sts-g-…`).
function kidOf(slot, material) {
  log.debug("Entering kidOf().");
  log.debug("Leaving kidOf().");
  return KID_PREFIX + String(slot).toLowerCase().replace(/[^a-z0-9]+/g, '-') +
         '-' + stsCrypto.sha256Hex(Buffer.from(material)).slice(0, 8);
}

/**
 * Makes one credential signer of a key family, on libuv's thread pool.
 *
 * @param family - `familyOf()`'s answer
 * @returns a promise of `{ group, slot, alg, kind, pairedSlot, privateKey,
 *   publicJwk }`, the signer groups' row shape
 */
async function makeMember(family) {
  log.debug("Entering makeMember(). " + family.slot);
  if (family.kind === 'pq') {
    const raw = await pqJose.generateAsync(family.alg);
    const kid = kidOf(family.slot, Buffer.from(raw.pub).toString('base64'));
    log.debug("Leaving makeMember(). Post-quantum.");
    return { group: GROUP, slot: family.slot, alg: family.alg, kind: 'pq',
             pairedSlot: null, privateKey: raw.priv,
             publicJwk: pqJose.akpPublicJwk(family.alg, raw.pub, kid) };
  }
  const pair = family.kind === 'rsa'
    ? await stsCrypto.generateKeyPairAsync('rsa', {
        modulusLength: require('./mode').defaultRsaBits() })
    : await stsCrypto.generateKeyPairAsync(family.curveSpec.gen[0],
                                           family.curveSpec.gen[1]);
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const material = JSON.stringify([jwk.kty, jwk.n || '', jwk.e || '',
                                   jwk.crv || '', jwk.x || '', jwk.y || '']);
  log.debug("Leaving makeMember(). " + family.kind + ".");
  return {
    group: GROUP, slot: family.slot, alg: family.alg, kind: family.kind,
    pairedSlot: null, privateKey: pair.privateKey,
    publicJwk: Object.assign({ use: 'sig', alg: family.alg }, jwk,
                             { kid: kidOf(family.slot, material) })
  };
}

// ---------------------------------------------------------------------------
// THE ISSUER IDENTIFIERS THE REALM ANSWERS TO.
//
// `credential_issuer` is `helpers.baseUrlOf(req)`, so what it is depends on
// how `global.publicBaseUrl` and the listener map are set:
//
//   * PINNED: the verifiable credentials application's advertised listener
//     has a `publicBaseUrl`, or `global.publicBaseUrl` is set. Every request
//     is answered under that base whatever its Host header said, so the
//     realm answers to exactly one issuer, and the certificate names it.
//   * NOT PINNED, the default in development: the base is the request's own
//     address on the main port's scheme and port. The names the service
//     answers to are the ones its main port's TLS certificate already
//     asserts, `tls.hostnames` and `tls.ips`, and the host of every custom
//     listener's `publicBaseUrl` (a request on a custom listener is answered
//     under that host on the main port, `baseUrlOf()`'s rule). With the
//     scheme's default port, the base without a port is named as well,
//     because a client that dials `https://sts` sends `Host: sts`.
//
// Each is followed by the realm's prefix (`/realm/<id>`), and each has its
// `did:web` beside it, written as `oid4vc/vc_did.ts`'s `stsDid()` writes one.
//
// **A REQUEST'S HOST NEVER JOINS THE SET.** In development that would let
// anybody who can send a Host header have this service's Root certify that
// this issuer is theirs; the OpenID4VP Verifier's product rule
// (`mode.certifiesRequestHost()`) says the same. A credential whose `iss`
// is not named is still signed, with its `x5c`, and the operator is told
// once (STS-PKI-0283) how to name it.
// ---------------------------------------------------------------------------
// The pinned base of the credential issuer, or ''.
function pinnedBase() {
  log.debug("Entering pinnedBase().");
  const app = hostedApplications.classify('/oid4vci/credential');
  const own = listenerMap.advertisedBase(
    app === hostedApplications.EVERYWHERE ? null : app);
  const raw = own || String(config.value('global.publicBaseUrl') || '').trim();
  log.debug("Leaving pinnedBase().");
  return raw ? raw.replace(/\/+$/, '') : '';
}

// A host as it appears in a URL authority: an IPv6 address in brackets.
function urlHost(name) {
  log.debug("Entering urlHost().");
  const value = String(name || '').trim();
  log.debug("Leaving urlHost().");
  return value.indexOf(':') >= 0 && value.charAt(0) !== '['
    ? '[' + value + ']' : value;
}

/**
 * The `did:web` of a base URL, as `oid4vc/vc_did.ts`'s `stsDid()` builds the
 * issuer's: the authority with `:` written `%3A`, then each path segment.
 *
 * @param base - a base URL, the realm prefix included
 * @returns the DID
 */
function didWebOf(base) {
  log.debug("Entering didWebOf().");
  const rest = String(base || '').replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  const slash = rest.indexOf('/');
  const host = slash < 0 ? rest : rest.slice(0, slash);
  const segments = slash < 0 ? [] : rest.slice(slash + 1).split('/')
    .filter(function (one) {
      return one !== '';
    });
  log.debug("Leaving didWebOf().");
  return 'did:web:' + [host.replace(/:/g, '%3A')].concat(
    segments.map(function (one) {
      return one.replace(/:/g, '%3A');
    })).join(':');
}

/**
 * The base URLs the ambient realm's credential issuer answers under, the
 * realm prefix included.
 *
 * @returns the bases, in a fixed order, without duplicates
 */
function issuerBases() {
  log.debug("Entering issuerBases().");
  const prefix = realms.currentPrefix();
  const pinned = pinnedBase();
  if (pinned) {
    log.debug("Leaving issuerBases(). Pinned.");
    return [pinned + prefix];
  }
  const https = config.value('global.https') === true;
  const scheme = https ? 'https' : 'http';
  const port = Number(config.value('global.port')) || 0;
  const defaultPort = https ? 443 : 80;
  const names = [];
  const add = function (name) {
    log.debug("Entering add().");
    const value = String(name || '').trim().toLowerCase();
    if (value && names.indexOf(value) < 0) {
      names.push(value);
    }
    log.debug("Leaving add().");
  };
  [].concat(config.value('tls.hostnames') || [])
    .concat(config.value('tls.ips') || []).forEach(add);
  listenerMap.ownOrigins().forEach(function (origin) {
    try {
      add(new URL(origin).hostname.replace(/^\[|\]$/g, ''));
    } catch (e) {
      log.debug("Caught in issuerBases(): " + ((e && e.message) || e));
    }
  });
  const out = [];
  names.forEach(function (name) {
    const host = urlHost(name);
    out.push(scheme + '://' + host + ':' + port + prefix);
    if (port === defaultPort) {
      out.push(scheme + '://' + host + prefix);
    }
  });
  log.debug("Leaving issuerBases(). " + out.length + ".");
  return out;
}

/**
 * Every issuer identifier the ambient realm answers to, and the `did:web` of
 * each: what a credential signer's certificate names, sorted.
 *
 * @returns the URIs
 */
function issuerUris() {
  log.debug("Entering issuerUris().");
  const out = [];
  issuerBases().forEach(function (base) {
    [base, didWebOf(base)].forEach(function (one) {
      if (out.indexOf(one) < 0) {
        out.push(one);
      }
    });
  });
  out.sort();
  if (out.length > MAX_URIS) {
    log.warn(errorCodes.tag('STS-PKI-0284') + 'credential_signer: the "' +
             (realms.currentId() || 'default') + '" realm answers to ' +
             out.length + ' issuer identifiers, and its credential-signing ' +
             'certificate names the first ' + MAX_URIS + '. Pin ' +
             'global.publicBaseUrl, or shorten tls.hostnames.');
  }
  log.debug("Leaving issuerUris(). " + out.length + ".");
  return out.slice(0, MAX_URIS);
}

/**
 * Reports, once per realm and address, a credential whose `iss` its
 * certificate does not name (STS-PKI-0283). The credential is still signed.
 *
 * @param issuer - the credential's `iss`
 * @param uris - what the certificate names
 * @returns true when the issuer is named
 */
function noteIssuer(issuer, uris) {
  log.debug("Entering noteIssuer().");
  const wanted = String(issuer || '');
  if (!wanted || (uris || []).indexOf(wanted) >= 0) {
    log.debug("Leaving noteIssuer(). Named.");
    return true;
  }
  const once = (realms.currentId() || '') + ' ' + wanted;
  if (!warnedUnbound.has(once)) {
    if (warnedUnbound.size >= 512) {
      warnedUnbound.clear();
    }
    warnedUnbound.add(once);
    log.warn(errorCodes.tag('STS-PKI-0283') + 'credential_signer: a ' +
             'credential in the "' + (realms.currentId() || 'default') +
             '" realm has iss "' + wanted + '", which its credential-signing ' +
             'certificate does not name (it names ' + (uris || []).length +
             ' issuer identifier(s)), so a wallet that compares iss with the ' +
             'certificate (HAIP 1.0 section 6.1.1) refuses it. It is signed ' +
             'anyway. Pin global.publicBaseUrl, or add the host to ' +
             'tls.hostnames, and the certificate names it from the next ' +
             'credential on.');
  }
  log.debug("Leaving noteIssuer(). Not named.");
  return false;
}

/**
 * The credential signers a key set holds now: its own list, and every key
 * family the keystore holds for the realm that the list lacks — a key a
 * sibling process or another node made, found in the store or the shared
 * blob — joined BY SLOT, the set's own key winning. A key found that way
 * reads its private half through the keystore when it signs.
 *
 * @param keys - the realm's key set
 * @returns the members
 */
function membersOf(keys) {
  log.debug("Entering membersOf().");
  const own = ((keys && keys.credentialSigners) || []).filter(function (one) {
    return one && one.publicJwk;
  });
  if (!keys || keys.realm === undefined) {
    log.debug("Leaving membersOf(). " + own.length + ", no realm.");
    return own;
  }
  const realmId = String(keys.realm);
  const slots = own.map(function (one) {
    return one.slot;
  });
  const extra = (keystore.credentialSignersHeldFor(realmId) || [])
    .filter(function (one) {
      return slots.indexOf(one.slot) < 0;
    }).map(function (one) {
      const kid = one.publicJwk && one.publicJwk.kid;
      const view = { group: GROUP, slot: one.slot, alg: one.alg,
                     kind: one.kind, pairedSlot: null,
                     publicJwk: one.publicJwk };
      Object.defineProperty(view, 'privateKey', {
        enumerable: true, configurable: true,
        get: function () {
          log.debug("Entering a credential signer's private door.");
          const key = keystore.credentialSignerPrivateFor(realmId, kid);
          if (!key) {
            throw errorCodes.mark(new Error('the "' + realmId + '" ' +
              'realm\'s ' + one.slot + ' credential-signing key is held ' +
              'encrypted and could not be decrypted; see the keystore ' +
              'errors above.'), 'STS-PKI-0285');
          }
          log.debug("Leaving a credential signer's private door.");
          return key;
        }
      });
      return view;
    });
  log.debug("Leaving membersOf(). " + own.length + " + " + extra.length +
            ".");
  return own.concat(extra);
}

// The held member of one slot, or null.
function memberIn(keys, slot) {
  log.debug("Entering memberIn(). " + slot);
  const found = membersOf(keys).filter(function (one) {
    return one && one.slot === slot && one.publicJwk;
  })[0] || null;
  log.debug("Leaving memberIn(). " + (found ? 'Held.' : 'None.'));
  return found;
}

// Mint one key family under the cluster claim, or wait for the node that
// holds the claim to have made it. Answers the member made here, or null
// where another process's is held now.
async function mintOrAwait(keys, family) {
  log.debug("Entering mintOrAwait(). " + family.slot);
  // `cluster_claims.claim()`'s ClaimResult, or this stand-in where no claim
  // could be asked: the two shapes share `ok` and `reason`, which is all
  // that is read, and the cast says so rather than restating the union.
  /** @type {any} */
  let claimed = { ok: true, reason: '' };
  if (keys.realm !== undefined) {
    try {
      claimed = await require('../cluster/cluster_claims').claim({
        scope: MINT_SCOPE,
        value: String(keys.realm) + ':' + String(keys.kid || '') + ':' +
               family.slot,
        realm: String(keys.realm), ttlMs: 60000 });
    } catch (e) {
      log.debug("Caught in mintOrAwait(): " + ((e && e.message) || e));
      claimed = { ok: true, reason: '' };
    }
  }
  if (!claimed.ok && claimed.reason === 'used') {
    const deadline = Date.now() + MINT_WAIT_MS;
    while (Date.now() < deadline) {
      if (memberIn(keys, family.slot)) {
        log.debug("Leaving mintOrAwait(). Minted elsewhere.");
        return null;
      }
      // A per-operation poll inside one bounded wait, not periodic work
      // (root CLAUDE.md, *Anything periodic is a scheduler job*).
      await new Promise(function (resolve) {
        setTimeout(resolve, MINT_POLL_MS);
      });
    }
    log.warn(errorCodes.tag('STS-PKI-0285') + 'credential_signer: another ' +
             'process claimed the "' + keys.realm + '" realm\'s ' +
             family.slot + ' credential signer and it did not arrive within ' +
             MINT_WAIT_MS + 'ms; it is made here.');
  }
  const made = await makeMember(family);
  log.debug("Leaving mintOrAwait(). Made here.");
  return made;
}

/**
 * The credential signer of a key family, made where the realm holds none:
 * once per process at a time, under a cluster claim, joined to the key set
 * BY SLOT, stored and shared.
 *
 * @param keys - the realm's key set
 * @param family - `familyOf()`'s answer
 * @returns a promise of the member
 */
function memberForAsync(keys, family) {
  log.debug("Entering memberForAsync(). " + family.slot);
  const held = memberIn(keys, family.slot);
  if (held) {
    log.debug("Leaving memberForAsync(). Held.");
    return Promise.resolve(held);
  }
  const key = String(keys.realm) + ' ' + family.slot;
  if (minting.has(key)) {
    log.debug("Leaving memberForAsync(). One is already in flight.");
    return minting.get(key);
  }
  const started = Date.now();
  const running = mintOrAwait(keys, family).then(function (made) {
    const already = memberIn(keys, family.slot);
    if (made === null || already) {
      // Another process's key won while this one was made: it is the one.
      return already || memberIn(keys, family.slot);
    }
    keys.credentialSigners = membersOf(keys).concat([made]);
    if (keys.realm !== undefined) {
      // Stored and shared as the KEM keys are (`helpers.js`'s
      // kemEncryptionKeysFor()): `keystore.decideKeys()` joins a list that
      // grows one slot at a time BY SLOT, the stored key winning.
      keystore.remember(String(keys.realm), keys);
      keystore.publishShared(String(keys.realm), keys);
    }
    log.info('A ' + family.slot + ' credential-signing key was made for the "' +
             keys.realm + '" realm in ' + (Date.now() - started) + 'ms: ' +
             made.publicJwk.kid + ' (keys.credentialSigner=dedicated).');
    return memberIn(keys, family.slot) || made;
  });
  minting.set(key, running);
  const release = function () {
    log.debug("Entering release().");
    if (minting.get(key) === running) {
      minting.delete(key);
    }
    log.debug("Leaving release().");
  };
  running.then(release, function (e) {
    log.debug("Caught in memberForAsync(): " + ((e && e.message) || e));
    release();
  });
  log.debug("Leaving memberForAsync(). Generating.");
  return running;
}

/**
 * The SubjectPublicKeyInfo PEM of a credential signer.
 *
 * @param member - the member
 * @returns the PEM
 */
function spkiPemOf(member) {
  log.debug("Entering spkiPemOf().");
  if (member.publicJwk && member.publicJwk.kty === 'AKP') {
    log.debug("Leaving spkiPemOf(). Post-quantum.");
    return require('./pki').pqSubjectPublicKeyPem(member.alg,
                                                  member.publicJwk);
  }
  log.debug("Leaving spkiPemOf().");
  return String(stsCrypto.publicKeyFromJwk(member.publicJwk)
                         .export({ type: 'spki', format: 'pem' }));
}

// A promise bounded by CERTIFICATE_WAIT_MS that never rejects.
function withinWait(promise) {
  log.debug("Entering withinWait().");
  let timer = null;
  const late = new Promise(function (resolve) {
    // A per-request bound, cleared as soon as the work settles.
    timer = setTimeout(function () {
      resolve(null);
    }, CERTIFICATE_WAIT_MS);
  });
  log.debug("Leaving withinWait().");
  return Promise.race([Promise.resolve(promise).catch(function (e) {
    log.debug("Caught in withinWait(): " + ((e && e.message) || e));
    return null;
  }), late]).then(function (answer) {
    clearTimeout(timer);
    return answer;
  });
}

/**
 * Makes sure a credential signer holds a current certificate naming `uris`,
 * issuing one where it does not. Never rejects: a key that could not be
 * certified still signs, and the credential carries no `x5c`.
 *
 * @param realmId - the realm
 * @param member - the credential signer
 * @param uris - the issuer identifiers it must name
 * @returns a promise of `{ ok, issued, why }`
 */
async function ensureCertificate(realmId, member, uris) {
  log.debug("Entering ensureCertificate(). " + member.slot);
  let pki = null;
  try {
    pki = require('./pki');
  } catch (e) {
    log.debug("Caught in ensureCertificate(): " + ((e && e.message) || e));
    pki = null;
  }
  if (!pki || typeof pki.certifyCredentialSigner !== 'function') {
    log.debug("Leaving ensureCertificate(). No certificate authority.");
    return { ok: false, issued: false, why: 'no certificate authority' };
  }
  let spkiPem = '';
  try {
    spkiPem = spkiPemOf(member);
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0286') + 'credential_signer: the "' +
              realmId + '" realm\'s ' + member.slot + ' credential signer ' +
              'could not be read to certify it: ' + e.message);
    log.debug("Leaving ensureCertificate(). Unreadable.");
    return { ok: false, issued: false, why: e.message };
  }
  const spec = { slot: pkiSlotOf(member.slot), kid: member.publicJwk.kid,
                 alg: member.alg, publicKeyPem: spkiPem, uris: uris,
                 keyAlg: member.kind === 'pq'
                   ? String(member.alg).toLowerCase()
                   : (member.publicJwk.crv ||
                      ('rsa-' + require('./mode').defaultRsaBits()))
                     .toLowerCase() };
  const verdict = pki.credentialSignerCertificateCurrent(realmId, spec);
  if (verdict.current) {
    log.debug("Leaving ensureCertificate(). Current.");
    return { ok: true, issued: false, why: '' };
  }
  const key = String(realmId) + ' ' + member.slot + ' ' + uris.join(' ');
  if (!certifying.has(key)) {
    const running = Promise.resolve(pki.certifyCredentialSigner(realmId, spec,
                                                                verdict.why));
    certifying.set(key, running);
    const release = function () {
      log.debug("Entering release().");
      if (certifying.get(key) === running) {
        certifying.delete(key);
      }
      log.debug("Leaving release().");
    };
    running.then(release, function (e) {
      log.debug("Caught in ensureCertificate(): " + ((e && e.message) || e));
      release();
    });
  }
  const done = await withinWait(certifying.get(key));
  log.debug("Leaving ensureCertificate(). " +
            (done && done.ok ? 'Issued.' : 'Not issued.'));
  return done && done.ok ? { ok: true, issued: true, why: verdict.why }
                         : { ok: false, issued: false,
                             why: (done && (done.errors || []).join(' ')) ||
                                  'not issued within ' + CERTIFICATE_WAIT_MS +
                                  'ms' };
}

/**
 * The key a credential of `alg` is signed with in the ambient realm, made
 * and certified where it needs to be.
 *
 * @param keys - the ambient realm's key set
 * @param alg - the JWS algorithm
 * @param opts - `curveSpecs` (helpers.js's CURVE_KEY_SPECS) and `issuer`, the
 *   credential's `iss` where it has one
 * @returns a promise of `{ alg, key, kid, slot, pkiSlot, uris, named }`
 */
async function signerForAsync(keys, alg, opts) {
  log.debug("Entering signerForAsync(). alg=" + alg);
  const o = opts || {};
  const family = familyOf(alg, o.curveSpecs);
  const member = await memberForAsync(keys, family);
  if (!member) {
    log.debug("Leaving signerForAsync(). Not made.");
    throw errorCodes.mark(new Error('the "' + keys.realm + '" realm\'s ' +
      family.slot + ' credential signer could not be made.'),
                          'STS-PKI-0285');
  }
  const uris = issuerUris();
  await ensureCertificate(String(keys.realm || ''), member, uris);
  const named = o.issuer ? noteIssuer(o.issuer, uris) : true;
  log.debug("Leaving signerForAsync(). " + member.publicJwk.kid);
  return { alg: String(alg), key: member.privateKey,
           kid: member.publicJwk.kid, slot: member.slot,
           pkiSlot: pkiSlotOf(member.slot), uris: uris, named: named };
}

/**
 * The credential signers as rows a verifier finds by `kid`.
 *
 * @param keys - the realm's key set
 * @returns `{ alg, publicJwk, role, slot }` rows
 */
function verificationRows(keys) {
  log.debug("Entering verificationRows().");
  const out = membersOf(keys).filter(function (one) {
    return one && one.publicJwk;
  }).map(function (one) {
    return { alg: one.alg, publicJwk: one.publicJwk, role: 'credential',
             slot: one.slot, kind: one.kind };
  });
  log.debug("Leaving verificationRows(). " + out.length + ".");
  return out;
}

/**
 * Credential signers: the dedicated per-realm key that signs credentials and
 * their status lists, and the certificate that binds it to the issuer
 * (#1880).
 * @namespace
 */
module.exports = {
  MODES: MODES,
  DEFAULT_MODE: DEFAULT_MODE,
  GROUP: GROUP,
  PKI_SLOT_PREFIX: PKI_SLOT_PREFIX,
  KID_PREFIX: KID_PREFIX,
  EKU: EKU,
  EKU_OID: EKU_OID,
  KEY_USAGE: KEY_USAGE,
  dedicatedOn: dedicatedOn,
  familyOf: familyOf,
  pkiSlotOf: pkiSlotOf,
  isCredentialKid: isCredentialKid,
  makeMember: makeMember,
  didWebOf: didWebOf,
  issuerBases: issuerBases,
  issuerUris: issuerUris,
  noteIssuer: noteIssuer,
  membersOf: membersOf,
  memberForAsync: memberForAsync,
  spkiPemOf: spkiPemOf,
  ensureCertificate: ensureCertificate,
  signerForAsync: signerForAsync,
  verificationRows: verificationRows
};
