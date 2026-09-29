// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: tiers.js
//
// ---------------------------------------------------------------------------
// WHICH TIER EVERY STORED THING BELONGS TO (#98, 2026-09-28).
//
// A service deployed as cells keeps its store in TWO databases per cell
// (`persistence/CLAUDE.md`, *Tiers*):
//
//   GLOBAL    configuration and control-plane state with no personal data —
//             realms, settings, applications, policies, keys, the routing
//             index — one writer for the whole service and a read replica in
//             every cell.
//   CELL      what is homed or minted here: the people homed in this cell's
//             jurisdiction (RESIDENT) and the sessions, codes and tokens this
//             cell minted (LOCAL). Never replicated outside the jurisdiction,
//             and sealed under the cell's own key.
//
// The design names three tiers and the store has two databases, because
// RESIDENT and LOCAL live in the same place and differ only in what may be
// done with them: a resident row may be PROJECTED to another cell for a
// session the policy lets it hold (#98 D9) and a local row never leaves.
//
// **THIS FILE IS THE ONE PLACE A STORE'S TIER IS DECIDED, AND EVERY STORE HAS
// TO BE IN IT.** A minted handle that is in neither list below is refused by
// `mintedTierOf()` as unclassified — and `tests/cell_tiers.js` reads every
// `persist:` in the tree and fails on one that is missing, so a new store
// cannot arrive without somebody deciding where it lives. The alternative, a
// default tier, would be a default ANSWER to a residency question, and the
// wrong default is a person's data in another country with nothing failing.
//
// **IN SINGLE-CELL MODE THE ANSWERS ARE STILL GIVEN AND IGNORED**: both tiers
// are the one database, and `persistence_tiered.js` is not built at all.
//
// A LEAF: no route, no require of this service's modules.
// ---------------------------------------------------------------------------

const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-persistence-tiers' });

// ---------------------------------------------------------------------------
// THE DIRECTORY. An entry's tier is decided by where it sits and, for a
// device, by who owns it:
//
//   * a PERSON (an entry below `ou=users`) is RESIDENT — the whole point;
//   * a DEVICE (below `ou=devices`) is resident when a person owns it and
//     global when an application does, because an application is
//     configuration every cell has and so are its devices;
//   * a GROUP's DEFINITION is global and its MEMBERSHIP is split: the members
//     that are resident people stay in their cell, every other member (an
//     application, a group) is global. `splitGroup()` and `joinGroup()` are
//     the two halves; a cell holds each group with its own residents in it;
//   * everything else — applications, policies, roles, federations, the
//     realm's own containers — is GLOBAL.
// ---------------------------------------------------------------------------
const RESIDENT_CONTAINERS = ['ou=users'];
const DEVICE_CONTAINER = 'ou=devices';
const GROUP_CONTAINER = 'ou=groups';
// The membership attributes a group's members are split out of. `memberUid`
// (RFC 2307's posixGroup) holds LOGIN NAMES rather than DNs, so every value
// of it is a person's and goes to the cell half: a name is exactly what the
// global tier must never hold.
const MEMBER_ATTRIBUTES = ['member', 'uniquemember', 'memberuid'];
const NAME_MEMBER_ATTRIBUTES = ['memberuid'];

// The RDNs of a normalised DN key, lower-cased. A DN key is already
// normalised by the directory; this only splits it, and does not attempt an
// RFC 4514 parse because a key never carries an escaped comma in the RDNs
// this file looks at (the containers are fixed names).
function rdnsOf(dnKey) {
  log.debug("Entering rdnsOf().");
  const out = String(dnKey || '').toLowerCase().split(',')
    .map(function (one) {
      return one.trim();
    })
    .filter(function (one) {
      return one;
    });
  log.debug("Leaving rdnsOf().");
  return out;
}

// Where a DN sits relative to a container directly under the realm's base:
// 'inside' when it is below `container,<dc=…>`, 'container' when it IS the
// container, and '' otherwise. The base is every trailing `dc=` RDN.
function placeOf(dnKey, container) {
  log.debug("Entering placeOf().");
  const rdns = rdnsOf(dnKey);
  let base = rdns.length;
  while (base > 0 && rdns[base - 1].indexOf('dc=') === 0) {
    base -= 1;
  }
  const at = base - 1;
  if (at < 0 || rdns[at] !== container) {
    log.debug("Leaving placeOf(). Not under it.");
    return '';
  }
  log.debug("Leaving placeOf().");
  return at === 0 ? 'container' : 'inside';
}

// One attribute of an entry's attribute map, whatever its case — the store
// keeps the names as the directory wrote them.
function attributeOf(attrs, name) {
  log.debug("Entering attributeOf().");
  const wanted = String(name).toLowerCase();
  const key = Object.keys(attrs || {}).filter(function (one) {
    return one.toLowerCase() === wanted;
  })[0];
  const value = key === undefined ? [] : attrs[key];
  log.debug("Leaving attributeOf().");
  return Array.isArray(value) ? value : (value === undefined ? [] : [value]);
}

/**
 * Tells whether a DN names a person homed somewhere — an entry below
 * `ou=users`.
 *
 * @param dnKey - the normalised DN
 * @returns true for a person's entry
 */
function isPersonDn(dnKey) {
  log.debug("Entering isPersonDn().");
  const out = RESIDENT_CONTAINERS.some(function (container) {
    return placeOf(dnKey, container) === 'inside';
  });
  log.debug("Leaving isPersonDn(). " + out);
  return out;
}

/**
 * Tells whether a DN names a group — an entry below `ou=groups`.
 *
 * @param dnKey - the normalised DN
 * @returns true for a group
 */
function isGroupDn(dnKey) {
  log.debug("Entering isGroupDn().");
  const out = placeOf(dnKey, GROUP_CONTAINER) === 'inside';
  log.debug("Leaving isGroupDn(). " + out);
  return out;
}

/**
 * Decides which tier a directory entry is stored in.
 *
 * @param dnKey - the entry's normalised DN
 * @param attrs - its attributes (a device's owner kind decides its tier)
 * @returns 'cell' for a person or a person's device, 'split' for a group
 *   (definition global, resident members in the cell), 'global' otherwise
 */
function directoryTierOf(dnKey, attrs) {
  log.debug("Entering directoryTierOf().");
  if (isPersonDn(dnKey)) {
    log.debug("Leaving directoryTierOf(). A person.");
    return 'cell';
  }
  if (placeOf(dnKey, DEVICE_CONTAINER) === 'inside') {
    const kind = String(attributeOf(attrs, 'stsDeviceOwnerKind')[0] ||
                        'person').toLowerCase();
    log.debug("Leaving directoryTierOf(). A device of a " + kind + ".");
    return kind === 'application' ? 'global' : 'cell';
  }
  if (isGroupDn(dnKey)) {
    log.debug("Leaving directoryTierOf(). A group.");
    return 'split';
  }
  log.debug("Leaving directoryTierOf(). Global.");
  return 'global';
}

// ---------------------------------------------------------------------------
// A GROUP, SPLIT AND JOINED. The global half is the entry with every member
// that is NOT a person; the cell half carries ONLY the person members, under
// the same DN, in an entry that is never restored on its own — `joinGroup()`
// puts it back into the global half at load, and a cell half whose group has
// no global half is dropped with a warning (the group was deleted in another
// cell while this one still held members of it).
//
// A member value is a DN; it is a person when `isPersonDn()` says so. The
// comparison is on the value as written, lower-cased, because a member
// attribute holds DNs in whatever spelling the writer used.
// ---------------------------------------------------------------------------
/**
 * Splits a group's attributes into the global half and the cell half.
 *
 * @param attrs - the group's attributes
 * @returns `{ global, cell }`: two attribute maps; `cell` holds only the
 *   member attributes, and only their person values
 */
function splitGroup(attrs) {
  log.debug("Entering splitGroup().");
  const globalHalf = {};
  const cellHalf = {};
  Object.keys(attrs || {}).forEach(function (name) {
    const lower = name.toLowerCase();
    const values = Array.isArray(attrs[name]) ? attrs[name] : [attrs[name]];
    if (MEMBER_ATTRIBUTES.indexOf(lower) < 0) {
      globalHalf[name] = attrs[name];
      return;
    }
    const byName = NAME_MEMBER_ATTRIBUTES.indexOf(lower) >= 0;
    const people = values.filter(function (one) {
      return byName || isPersonDn(String(one));
    });
    const others = values.filter(function (one) {
      return !byName && !isPersonDn(String(one));
    });
    // An EMPTY member attribute stays on the global half: `groupOfNames`
    // requires one, and the directory's own convention for an empty group
    // is decided by the directory, not here.
    if (others.length || !people.length) {
      globalHalf[name] = others;
    }
    if (people.length) {
      cellHalf[name] = people;
    }
  });
  log.debug("Leaving splitGroup().");
  return { global: globalHalf, cell: cellHalf };
}

/**
 * Puts a group's cell half back into its global half.
 *
 * @param globalAttrs - the global half's attributes
 * @param cellAttrs - the cell half's (member attributes only)
 * @returns one attribute map, members de-duplicated
 */
function joinGroup(globalAttrs, cellAttrs) {
  log.debug("Entering joinGroup().");
  const out = Object.assign({}, globalAttrs || {});
  Object.keys(cellAttrs || {}).forEach(function (name) {
    const lower = name.toLowerCase();
    if (MEMBER_ATTRIBUTES.indexOf(lower) < 0) {
      return;
    }
    const existing = Object.keys(out).filter(function (one) {
      return one.toLowerCase() === lower;
    })[0] || name;
    const have = (Array.isArray(out[existing]) ? out[existing]
                  : (out[existing] === undefined ? [] : [out[existing]]))
      .map(String);
    const seen = {};
    have.forEach(function (one) {
      seen[one.toLowerCase()] = true;
    });
    const add = (Array.isArray(cellAttrs[name]) ? cellAttrs[name]
                 : [cellAttrs[name]]).map(String).filter(function (one) {
      const k = one.toLowerCase();
      if (seen[k]) {
        return false;
      }
      seen[k] = true;
      return true;
    });
    out[existing] = have.concat(add);
  });
  log.debug("Leaving joinGroup().");
  return out;
}

// ---------------------------------------------------------------------------
// THE MINTED STORES. Every `persist:` handle in the tree is in exactly one of
// these two lists; the reason for each GLOBAL one is beside it, because a
// store is cell-tier by nature (it is minted here, or it is somebody's) and a
// global one is the exception that has to be argued.
//
// **A REPLAY SET THAT A CLIENT CHOOSES THE KEYS OF IS GLOBAL**: a DPoP proof's
// `jti`, a Kerberos authenticator, a GNAP signed request. Every cell answers
// on the same public name, so a proof accepted in one cell is valid in all of
// them, and a replay set per cell would accept it once per cell. A nonce THIS
// service issued (ACME, SCIM digest, attestation challenges) stays in the
// cell: it is only valid where it was issued, so a replay elsewhere is
// refused as unknown. The global ones are eventually consistent across cells
// — a replay presented at two cells inside the replica lag is accepted at
// both — which is the same window a single cell had before its barrier, and
// is said rather than hidden.
// ---------------------------------------------------------------------------
const GLOBAL_MINTED = {
  // Configuration, which every cell must hold the same copy of.
  'authorization_servers.profiles': 'the named authorization servers',
  'mail.templates': 'a realm\'s wording of its messages',
  'oauth2.commandIssuer': 'the issuer a realm\'s provider commands use',
  'oauth2.commandMetadata': 'what each client says it supports',
  'oidfed.registerGeneration': 'the OpenID Federation register generation',
  'signing.history': 'the signer generations every cell publishes',
  'spiffe.authorities': 'the SPIFFE trust domain authorities',
  'spiffe.federatedBundles': 'the SPIFFE federated bundles',
  'spiffe.sigstoreTuf': 'the Sigstore TUF trust root',
  'ssf.foreignTransmitters': 'the registered foreign SSF transmitters',
  'vc_claims.state': 'the credential claim selections of a realm',
  'vc_verifier_config.state': 'the OpenID4VP verifier configuration',
  // One list per realm, published by every cell: a credential issued in one
  // cell and revoked in another must show revoked everywhere.
  'vc_status.entries': 'the status list bits every cell publishes',
  // A revocation reaches every cell, or a token revoked in one is live in
  // the next (#98 §5).
  'admin_stats.revokedJtis': 'revoked token ids',
  'admin_stats.revokedArtifacts': 'revoked artifacts',
  // Client-chosen replay keys — see the block above.
  'dpop.seenJtis': 'DPoP proof ids already seen',
  'krb5.replayCache': 'Kerberos authenticators already seen',
  'gnap.replay': 'GNAP signed requests already seen',
  // A resource server's registered resource set (RFC 9767 section 3.4) is
  // configuration about a resource server, with nothing of anybody's in it,
  // and its reference is written into grant requests a client may send to
  // any cell: held in one cell, a set registered there would be unknown at
  // every other. Written when an RS registers a set it has not registered
  // before, which is rare and administrative (#98 section 3).
  'gnap.resources': 'the resource sets GNAP resource servers registered'
};

// Cell-tier: minted here, or somebody's. Listed rather than defaulted — see
// the header.
const CELL_MINTED = [
  // `attribute_sources.status` and `federation.unmapped` (#94) are
  // OBSERVATIONS of this cell's own traffic: a source's last error can name
  // the person it was looking up, and the names a partner sent arrived at
  // somebody's sign-in. Each cell's console shows what that cell saw.
  'acme.accountKeys', 'acme.accounts', 'acme.authorizations',
  'acme.certificates', 'acme.orders', 'acme.renewalInfo', 'acme.usedNonces',
  'admin_stats.artifacts', 'admin_stats.calls', 'admin_stats.claimSets',
  'admin_stats.nums', 'admin_stats.scimCounts', 'admin_stats.tokens',
  'admin_stats.users', 'attribute_sources.status', 'audit.events',
  'audit.nums', 'authn.pending',
  'authn.pendingMfa', 'authn.pendingPasswordChange', 'authn.sessions',
  'authn.webauthnCredentials', 'authorization_details.consented',
  'caep.register', 'cells.deliveries', 'cells.exports', 'cells.projections',
  'claim_attributes.selections', 'consent_screen.pending',
  'credentials.pendingBackupCodes', 'credentials.pendingKeys',
  'credentials.pendingTotp', 'delegation.acts', 'devices.challenges',
  'devices.events', 'dpop.issuedNonces', 'federation.unmapped',
  'federation_sp.contexts',
  'gnap.approvers', 'gnap.continuations', 'gnap.grants', 'gnap.instances',
  'gnap.interactions', 'gnap.manageHandles', 'gnap.manageValues',
  'gnap.movedGrants', 'gnap_monitor.counters', 'gnap.tokens',
  'gnap.tokenValues', 'gnap.userCodes', 'gnap.userRefs', 'krb5.principals',
  'ldap.clusterConnections', 'ldap.clusterSignOuts', 'mail.outbox',
  'mail.preferences', 'oauth2.attestationChallenges', 'oauth2.authzCodes',
  'oauth2.backchannelDeliveries', 'oauth2_bcp.grantTokens',
  'oauth2_bcp.refreshFamilies', 'oauth2_bcp.refreshTokens',
  'oauth2_bcp.transactions', 'oauth2.cibaDeliveries', 'oauth2.cibaRequests',
  'oauth2.claimSourceFlows', 'oauth2.commandAccounts',
  'oauth2.commandCallbacks', 'oauth2.commandDeliveries',
  'oauth2.commandMockAccounts', 'oauth2.commandMockJtis',
  'oauth2.commandMockKnobs', 'oauth2.deviceCodes', 'oauth2.ephemeralSubjects',
  'oauth2.grantIssued', 'oauth2.grants', 'oauth2_monitor.counters',
  'oauth2.pushedRequests', 'oauth2.redeemedCodes', 'oauth2.tenantCommandRuns',
  'oidc_rp.flows', 'risc.register', 'saml11_sso.artifacts',
  'saml11_sso.assertionsById', 'saml11_sso.pendingFlows', 'saml2.mdqRefusals',
  'saml2_sso.artifacts', 'saml2_sso.pendingRequests', 'saml2_sso.spContexts',
  'scep.transactions', 'scheduler.runs', 'scim.digestCounts',
  'scim.digestNonces', 'scim.hobaChallenges', 'scim.hobaSeen',
  'security.rateLimitBuckets', 'spiffe.joinTokens',
  'spiffe.recordedConnections', 'spnego.pending',
  'ssf_dead_letter_report.sweeps', 'ssf.foreignInbox', 'ssf.foreignLocks',
  'ssf_receivers.inbox', 'ssf_streams.deadLetters', 'ssf_streams.queued',
  'ssf_streams.received', 'ssf_streams.streams', 'tls.listenerAnnounced',
  'tls.sessionTicketKey', 'vc_api.issued', 'vc_issued.credentials',
  'vc_issuer.lastCredentialRequest', 'vc_issuer.notificationIds',
  'vc_issuer.vciNonces', 'vc_offers.credentialOffers',
  'vc_offers.deferredAccessTokens', 'vc_offers.deferredTransactions',
  'vc_offers.issuerStates', 'vc_offers.preAuthorizedCodes',
  'vc_verifier.vpRequests', 'vc_verifier.vpTransactions', 'wsfed.rpContexts',
  'xacml_monitor.counters'
];

// Handles made per owner at run time (`enrollment_monitor.<family>`), and
// the stores the in-process tests declare, which never reach a database but
// must not be refused as unclassified when a test runs the tiered driver.
const CELL_PREFIXES = ['enrollment_monitor.', 'test.'];

// ---------------------------------------------------------------------------
// THE SCHEDULER JOBS THAT ACT ON GLOBAL STATE (#98). A cluster job runs once
// per cluster, and a cell IS a cluster — so a job whose work is the global
// tier's (rotating a realm's signing keys, the krbtgt key, a SPIFFE authority,
// the OpenID Federation key; expiring a client secret; purging the global
// used-assertion history) would run once PER CELL if its run were claimed in
// the cell's database. Their runs are claimed in the global tier instead,
// under `GLOBAL_RUN_SCOPE`, so exactly one cell runs each slot. Every other
// job's work is what its own cell holds, and it runs in every cell.
// ---------------------------------------------------------------------------
const GLOBAL_JOBS = [
  'signing.rotate', 'signing.retire', 'signing.rotate-now',
  'krb5.krbtgt-rotate', 'krb5.krbtgt-rotate-now',
  'oidfed.key-rotate', 'oidfed.key-rotate-now', 'oidfed.collection-crawl',
  'oidfed.registrations-expire', 'federation.encryption-key-retire',
  'spiffe.authority-rotation', 'spiffe.sigstore-tuf-refresh',
  'oauth2.client-secret-expiry', 'oauth2.used-assertion-purge',
  'saml2.sp-metadata-refresh', 'ssf.stream-maintenance', 'ssf.foreign-poll'
];
// The claim scope a global job's run is claimed under.
const GLOBAL_RUN_SCOPE = 'scheduler.run.global';
// The claim scopes kept in the global tier.
const GLOBAL_CLAIM_SCOPES = [GLOBAL_RUN_SCOPE];

/**
 * Tells whether a scheduler job's work is the global tier's.
 *
 * @param id - the job id
 * @returns true for a job whose run is claimed in the global tier
 */
function isGlobalJob(id) {
  log.debug("Entering isGlobalJob().");
  log.debug("Leaving isGlobalJob().");
  return GLOBAL_JOBS.indexOf(String(id || '')) >= 0;
}

/**
 * Decides which tier a cluster claim is kept in.
 *
 * @param scope - the claim's scope
 * @returns 'global' or 'cell'
 */
function claimTierOf(scope) {
  log.debug("Entering claimTierOf().");
  log.debug("Leaving claimTierOf().");
  return GLOBAL_CLAIM_SCOPES.indexOf(String(scope || '')) >= 0 ? 'global'
                                                                : 'cell';
}

/**
 * Decides which tier a minted store is kept in.
 *
 * @param handle - the store's `persist:` handle
 * @returns 'global' or 'cell'
 * @throws an Error for a handle that is in neither list — see the header
 */
function mintedTierOf(handle) {
  log.debug("Entering mintedTierOf().");
  const name = String(handle || '');
  if (Object.prototype.hasOwnProperty.call(GLOBAL_MINTED, name)) {
    log.debug("Leaving mintedTierOf(). Global.");
    return 'global';
  }
  if (CELL_MINTED.indexOf(name) >= 0 ||
      CELL_PREFIXES.some(function (prefix) {
        return name.indexOf(prefix) === 0;
      })) {
    log.debug("Leaving mintedTierOf(). Cell.");
    return 'cell';
  }
  log.debug("Leaving mintedTierOf(). Unclassified.");
  throw new Error('persistence/tiers.js: the minted store "' + name + '" ' +
                  'is in neither the global nor the cell list. Every store ' +
                  'has to be classified — add it to one, with the reason if ' +
                  'it is global.');
}

/**
 * Tells whether a handle is classified at all, without throwing.
 *
 * @param handle - the store's `persist:` handle
 * @returns true when `mintedTierOf()` would answer
 */
function isClassified(handle) {
  log.debug("Entering isClassified().");
  let out = true;
  try {
    mintedTierOf(handle);
  } catch (e) {
    log.debug("Caught in isClassified(): " + ((e && e.message) || e));
    out = false;
  }
  log.debug("Leaving isClassified().");
  return out;
}

/**
 * Which store the tiers live in, one decision per stored thing (#98). A
 * leaf: no route.
 * @namespace
 */
module.exports = {
  directoryTierOf: directoryTierOf,
  isPersonDn: isPersonDn,
  isGroupDn: isGroupDn,
  splitGroup: splitGroup,
  joinGroup: joinGroup,
  mintedTierOf: mintedTierOf,
  isClassified: isClassified,
  GLOBAL_MINTED: GLOBAL_MINTED,
  CELL_MINTED: CELL_MINTED,
  CELL_PREFIXES: CELL_PREFIXES,
  MEMBER_ATTRIBUTES: MEMBER_ATTRIBUTES,
  GLOBAL_JOBS: GLOBAL_JOBS,
  GLOBAL_RUN_SCOPE: GLOBAL_RUN_SCOPE,
  isGlobalJob: isGlobalJob,
  claimTierOf: claimTierOf
};
