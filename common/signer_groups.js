// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: signer_groups.js
//
// ===========================================================================
// SIGNER GROUPS: THE KEYS A REALM SIGNS WITH, COLLAPSED BY ALGORITHM AND
// SEPARATED BY USE (2026-09-26, #68).
//
// A realm in the default `per-algorithm` model holds one key per JWS
// algorithm — the RSA key, six curve keys, eleven post-quantum keys — and
// EVERY JOSE use (access tokens, ID Tokens, credentials, Security Event
// Tokens …) signs with the same one for a given `alg`. XML signs with one
// RSA key. rcbj's request on #68 turns that round: **a small, chosen set of
// algorithms, and a separate key pair per USE**, "collapsing by signing algo,
// not use case". His answers, recorded on the ticket:
//
//   D2  five coarse groups — the rows of GROUPS below (a sixth, #265's
//       remembered browsers, joined for rcbj's "both key pair modes");
//   D3  in each group, three HYBRID certificates, each binding a classical
//       key and an ML-DSA key (ITU-T X.509 (2019) clause 9.8, approach #1 of
//       his article), plus one plain SLH-DSA certificate — PAIRS below;
//   D5  the ML-DSA half is published in the JWKS WITHOUT `x5c` (RFC 7517
//       section 4.7: the key in the first certificate MUST match the JWK);
//   D6  an algorithm outside the set falls back to the per-algorithm keys.
//
// **EVERY KEY IS STILL A KEY PAIR OF ITS OWN** ("use the existing separate
// key pair per algorithm"). The hybrid certificate is what is shared, not a
// key: nothing here is a composite.
//
// A LEAF TABLE, and the reason it is a file: `helpers.js` (which makes the
// keys), `keystore.js` (which seals them), `pki.js` (which certifies them),
// `oauth2.ts` (which publishes them) and the admin pages all need the same
// rows, and a copy in each is five tables that agree until somebody edits
// one. It requires `config` and nothing that requires it back.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({
  name: 'signer_groups',
  level: config.value('global.logLevel')
});

// The two models `keys.signerModel` names. `per-algorithm` is what every
// realm had before #68 and is the default.
/**
 * The two signer models `keys.signerModel` names.
 */
const MODELS = ['per-algorithm', 'hybrid-groups'];
/**
 * The default signer model, one key per JWS algorithm shared by every use.
 */
const DEFAULT_MODEL = 'per-algorithm';
/**
 * The signer model of #68: a separate set of keys per group of uses.
 */
const HYBRID_MODEL = 'hybrid-groups';

// ---------------------------------------------------------------------------
// THE GROUPS (D2). `useCases` are `common/jose_certificate_header.js`'s ids —
// the name every JOSE signing call in this service already passes — so a
// signature finds its group from what it says about itself rather than from
// a second list of call sites. `pkiUseCase` is the Issuing CA the group's
// certificates come from: JOSE groups under the JOSE Signing CA, the XML
// group under the XML Signing CA, as the per-algorithm keys are.
// ---------------------------------------------------------------------------
/**
 * The signer groups: `id`, `label`, the Issuing CA its certificates come
 * from (`pkiUseCase`) and the JOSE certificate-header use cases it signs.
 */
const GROUPS = [
  { id: 'tokens', label: 'OAuth 2.0 and OpenID Connect tokens',
    pkiUseCase: 'jose',
    useCases: ['access-token', 'id-token', 'refresh-token', 'userinfo',
               'introspection', 'oauth-signed-metadata'] },
  { id: 'credentials', label: 'Verifiable credentials',
    pkiUseCase: 'jose',
    useCases: ['vci-credential', 'vci-signed-metadata', 'vp-request-object'] },
  { id: 'events', label: 'Security Event Tokens', pkiUseCase: 'jose',
    useCases: ['ssf-set'] },
  { id: 'wstrust-gnap', label: 'WS-Trust JWTs and GNAP access tokens',
    pkiUseCase: 'jose', useCases: ['wstrust-jwt', 'gnap-access-token'] },
  // A REMEMBERED BROWSER'S DEVICE TOKEN (#265, rcbj: a key pair for that
  // purpose alone, in both signer models). Only its ES256 member signs — a
  // cookie cannot hold a post-quantum signature — and its certificate is
  // hybrid with the ML-DSA-44 partner, as every group's is.
  { id: 'browser-devices', label: 'Remembered browser device tokens',
    pkiUseCase: 'jose', useCases: ['browser-device-token'] },
  { id: 'xml', label: 'XML signatures (SAML, WS-Federation, WS-Trust)',
    pkiUseCase: 'xml', useCases: [] }
];

/**
 * The ids of `GROUPS`, in order.
 */
const GROUP_IDS = GROUPS.map(function (one) { return one.id; });

// ---------------------------------------------------------------------------
// THE MEMBERS OF A GROUP (D3). Each row is ONE CERTIFICATE: a classical key
// and, for three of them, the ML-DSA key certified beside it in
// `subjectAltPublicKeyInfo`. The pairings are the IETF composite draft's own
// (draft-ietf-lamps-pq-composite-sigs pairs ML-DSA-44 with P-256, ML-DSA-65
// with RSA-3072 and ML-DSA-87 with P-384), matched by security category —
// a pairing whose halves are of different strengths protects at the weaker.
//
// `keyAlg` is `common/vendored/key_material.js`'s id, `jwsAlgs` the JWS
// algorithms the key signs (an RSA key signs RS* and PS*; an EC key's curve
// fixes its one algorithm), and `slot` the name its certificate is filed
// under — `<group>/<slot>` — which can never collide with a per-algorithm
// key's slot (`RS256`, `ES256:P-256`, `ML-DSA-65`), because none of those
// contains a slash.
// ---------------------------------------------------------------------------
/**
 * The members of every group, one certificate each: a classical key with its
 * ML-DSA partner certified beside it (a hybrid certificate), or SLH-DSA
 * alone; `slot`, `keyAlg`, `kind`, `jwsAlgs` and `pq`.
 */
const PAIRS = [
  { slot: 'RS256', keyAlg: 'rsa-3072', kind: 'rsa',
    jwsAlgs: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
    pq: { slot: 'ML-DSA-65', alg: 'ML-DSA-65' } },
  { slot: 'ES256', keyAlg: 'ec-p256', kind: 'curve', jwsAlgs: ['ES256'],
    pq: { slot: 'ML-DSA-44', alg: 'ML-DSA-44' } },
  { slot: 'ES384', keyAlg: 'ec-p384', kind: 'curve', jwsAlgs: ['ES384'],
    pq: { slot: 'ML-DSA-87', alg: 'ML-DSA-87' } },
  // The hash-based one stands ALONE: clause 9.8 gives a certificate one
  // alternative key, every classical key above already has its partner, and
  // a second classical key only to carry it would be a key pair with no job.
  { slot: 'SLH-DSA-SHA2-128s', keyAlg: 'slh-dsa-sha2-128s', kind: 'pq',
    jwsAlgs: ['SLH-DSA-SHA2-128s'], pq: null }
];

// Every JWS algorithm a group signs, classical and post-quantum.
/**
 * Lists every JWS algorithm a group signs, classical and post-quantum.
 *
 * @returns the algorithm names
 */
function groupAlgs() {
  log.debug("Entering groupAlgs().");
  const out = [];
  PAIRS.forEach(function (pair) {
    pair.jwsAlgs.forEach(function (alg) { out.push(alg); });
    if (pair.pq) {
      out.push(pair.pq.alg);
    }
  });
  log.debug("Leaving groupAlgs(). " + out.length + " algorithm(s).");
  return out;
}

/**
 * Returns a group by id.
 *
 * @param id - a group id
 * @returns the `GROUPS` row, or null
 */
function group(id) {
  log.debug("Entering group().");
  log.debug("Leaving group().");
  return GROUPS.filter(function (one) {
    return one.id === String(id || '');
  })[0] || null;
}

// The group a JOSE certificate-header use case belongs to, or null.
/**
 * Returns the group a JOSE certificate-header use case belongs to.
 *
 * @param useCaseId - a use-case id from `jose_certificate_header.js`
 * @returns the `GROUPS` row, or null when no group signs it
 */
function groupForUseCase(useCaseId) {
  log.debug("Entering groupForUseCase(). use=" + useCaseId);
  const found = GROUPS.filter(function (one) {
    return one.useCases.indexOf(String(useCaseId || '')) >= 0;
  })[0] || null;
  log.debug("Leaving groupForUseCase(). " + (found ? found.id : 'none'));
  return found;
}

// The certificate slot of a member: `<group>/<slot>`.
/**
 * Builds a group member's certificate slot, `<group>/<slot>`.
 *
 * @param groupId - the group id
 * @param slot - the member's slot in `PAIRS`
 * @returns the slot name
 */
function slotOf(groupId, slot) {
  log.debug("Entering slotOf().");
  log.debug("Leaving slotOf().");
  return String(groupId) + '/' + String(slot);
}

// Is a certificate slot a group member's? The slash is the whole test.
/**
 * Tells whether a certificate slot is a group member's (it contains a
 * slash, which no per-algorithm slot does).
 *
 * @param slot - a certificate slot name
 * @returns true for a group member's slot
 */
function isGroupSlot(slot) {
  log.debug("Entering isGroupSlot().");
  log.debug("Leaving isGroupSlot().");
  return String(slot || '').indexOf('/') > 0;
}

// ---------------------------------------------------------------------------
// THE XML GROUP'S SIGNATURE ALGORITHMS (#68 phase 4b): each value of
// `saml.signatureAlgorithm` and the XML group member that signs it. The RSA
// family all sign with the RSA-3072 key; ECDSA with the P-256 or P-384 key
// (through the vendored GENERAL engine, rcbj's D8); ML-DSA and SLH-DSA with
// the group's own post-quantum keys under the W3C xmldsig-more DRAFT
// identifiers, each with a plain certificate of its own for KeyInfo (D7).
// Anything but the RSA family needs a `hybrid-groups` realm: the
// per-algorithm model has an RSA key for XML and nothing else.
// ---------------------------------------------------------------------------
/**
 * Each `saml.signatureAlgorithm` value and the XML group member slot that
 * signs it.
 */
const XML_SIGNATURE_SLOTS = {
  'rsa-sha256': 'RS256', 'rsa-sha384': 'RS256', 'rsa-sha512': 'RS256',
  'rsa-sha1': 'RS256',
  'ecdsa-sha256': 'ES256', 'ecdsa-sha384': 'ES384',
  'ml-dsa-44': 'ML-DSA-44', 'ml-dsa-65': 'ML-DSA-65', 'ml-dsa-87': 'ML-DSA-87',
  'slh-dsa-sha2-128s': 'SLH-DSA-SHA2-128s'
};

// The XML group slot that signs a `saml.signatureAlgorithm` value.
/**
 * Returns the XML group slot that signs a `saml.signatureAlgorithm` value,
 * the RSA member for an unknown one.
 *
 * @param name - a `saml.signatureAlgorithm` value
 * @returns the slot, `xml/<member>`
 */
function xmlSlotFor(name) {
  log.debug("Entering xmlSlotFor(). " + name);
  log.debug("Leaving xmlSlotFor().");
  return slotOf('xml', XML_SIGNATURE_SLOTS[String(name)] || 'RS256');
}

// Is a `saml.signatureAlgorithm` value the RSA family's, which the
// per-algorithm XML key can sign?
/**
 * Tells whether a `saml.signatureAlgorithm` value is in the RSA family, which
 * the per-algorithm XML key can sign.
 *
 * @param name - a `saml.signatureAlgorithm` value
 * @returns true for an `rsa-*` value
 */
function isRsaXmlAlgorithm(name) {
  log.debug("Entering isRsaXmlAlgorithm().");
  log.debug("Leaving isRsaXmlAlgorithm().");
  return /^rsa-/.test(String(name || ''));
}

// The realm's model, read in the AMBIENT realm (`keys.signerModel` is
// `runtime: true`, so the realm's override answers first).
/**
 * Returns the ambient realm's signer model, the default for an unknown
 * value.
 *
 * @returns `per-algorithm` or `hybrid-groups`
 */
function model() {
  log.debug("Entering model().");
  const value = String(config.value('keys.signerModel') || DEFAULT_MODEL);
  log.debug("Leaving model(). " + value);
  return MODELS.indexOf(value) >= 0 ? value : DEFAULT_MODEL;
}

/**
 * Tells whether the ambient realm uses the hybrid-groups signer model.
 *
 * @returns true under `hybrid-groups`
 */
function hybridGroupsOn() {
  log.debug("Entering hybridGroupsOn().");
  log.debug("Leaving hybridGroupsOn().");
  return model() === HYBRID_MODEL;
}

/**
 * Signer groups: the keys a realm signs with, collapsed by algorithm and
 * separated by use (#68).
 *
 * A leaf table shared by the modules that make, seal, certify and publish the
 * keys, so that they cannot disagree.
 * @namespace
 */
module.exports = {
  MODELS: MODELS,
  DEFAULT_MODEL: DEFAULT_MODEL,
  HYBRID_MODEL: HYBRID_MODEL,
  GROUPS: GROUPS,
  GROUP_IDS: GROUP_IDS,
  PAIRS: PAIRS,
  groupAlgs: groupAlgs,
  group: group,
  groupForUseCase: groupForUseCase,
  slotOf: slotOf,
  isGroupSlot: isGroupSlot,
  model: model,
  hybridGroupsOn: hybridGroupsOn,
  XML_SIGNATURE_SLOTS: XML_SIGNATURE_SLOTS,
  xmlSlotFor: xmlSlotFor,
  isRsaXmlAlgorithm: isRsaXmlAlgorithm
};
