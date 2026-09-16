// @ts-check
'use strict';
//
// File: cluster/cluster_capabilities.js
//
// ===========================================================================
// WHAT ACTIVE-ACTIVE MODE DEPENDS ON, AS DATA (2026-09-14, #46).
//
// Issue #46 is a list of the ways several containers against one store give
// WRONG ANSWERS: a signing key one node publishes and another does not, an
// authorization code redeemed on two nodes, a revocation one node's save
// throws away. Each of those is a row in `CAPABILITIES` below, and a row is
// `provided` only when the module that fixed it says so — at its own require
// time, by calling `provide()` with the capability's id.
//
// **THE REFUSAL IS THE POINT OF THE TABLE.** `cluster/cluster.js` will not
// start a node in active-active mode while a required capability is missing,
// because the failure the issue opens with is exactly "it would start and look
// healthy, and then give wrong answers in ways nothing reports". A build that
// has fixed three of the eleven single-use values is not a build that may run
// active-active and say so on a status page.
//
// **`cluster.acceptMissingCapabilities` NAMES EXCEPTIONS ONE BY ONE**, and there
// is no wildcard. An operator who writes `oauth.refresh-rotation` there has read
// what it means and accepted that failure; the node starts and logs, at every
// start, what it is running without.
//
// **A CAPABILITY IS PROVIDED BY THE CODE THAT IMPLEMENTS IT AND NOWHERE ELSE.**
// Marking one provided in this file, or from a module that did not change the
// behaviour the row describes, turns the refusal into the status page the issue
// warns about. `tests/cluster_foundation.js` checks that every `provide()`
// call names a row here, and that every row names the module expected to
// provide it.
//
// A LEAF (rule 3): it registers no route and requires only bunyan and config.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('../common/config');

const log = bunyan.createLogger({ name: 'sts-cluster-capabilities' });
config.registerLogger(log);

// `section` is the heading of issue #46 the failure is described under.
// `by` names the module expected to call provide() — which is what a reader
// opens to see the fix, and what the test holds the call to.
const CAPABILITIES = [
  // ---- the foundation ------------------------------------------------------
  { id: 'cluster.membership', section: '8',
    by: 'cluster/cluster.js',
    what: 'Every node joins with a UUID identity, renews a membership row by ' +
          'the database clock, and exits when it cannot; every write is ' +
          'fenced by that membership.' },
  { id: 'cluster.settings-agreement', section: '5, 8',
    by: 'cluster/cluster.js',
    what: 'A node whose Kerberos keys, mode, public address or other ' +
          'must-agree settings differ from a live node\'s refuses to start.' },
  { id: 'replication.late-commits', section: '3',
    by: 'persistence/persistence_replication.js',
    what: 'A change committed after later sequence numbers were already ' +
          'visible is applied when it appears, instead of being skipped for ' +
          'ever after four seconds.' },
  { id: 'cluster.read-barrier', section: '5',
    by: 'cluster/cluster_barrier.js',
    what: 'A request is served only after its node has applied what every ' +
          'node committed before it arrived, and a request that wrote is ' +
          'answered only once its writes have committed.' },
  { id: 'cluster.claims', section: '2',
    by: 'cluster/cluster_claims.js',
    what: 'An atomic "once" in the store that every single-use value can be ' +
          'spent through.' },
  { id: 'cluster.shared-secrets', section: '5',
    by: 'cluster/cluster_secrets.ts',
    what: 'Secrets every node must agree on are generated once, sealed, and ' +
          'read by every node before it serves.' },
  // ---- section 1: keys and the certificate authority -----------------------
  { id: 'keys.agreement', section: '1',
    by: 'common/keystore.js',
    what: 'A realm\'s signing keys are generated once for the cluster and ' +
          'adopted by every node, including after a rotation.' },
  { id: 'pki.agreement', section: '1',
    by: 'common/pki.js',
    what: 'The Root, Intermediates and Issuing CAs are built once for the ' +
          'cluster, and a rebuild reaches every node and its listeners.' },
  { id: 'pki.revocation-register', section: '1',
    by: 'common/pki_revocation.js',
    what: 'A revocation or an issued certificate recorded on one node cannot ' +
          'be lost to another node\'s save, and CRL numbers only go up.' },
  { id: 'scep.ra-agreement', section: '1',
    by: 'scep/scep_ra.ts',
    what: 'Every node presents the same SCEP RA certificate.' },
  { id: 'spiffe.authority-agreement', section: '1',
    by: 'spiffe/spiffe_ca.ts',
    what: 'Every node issues SVIDs from, and verifies against, the same ' +
          'SPIFFE X.509 and JWT authorities.' },
  { id: 'vc.keys-agreement', section: '1',
    by: 'cluster/cluster_secrets.ts',
    what: 'Every node signs bbs-2023 Data Integrity proofs with, and ' +
          'publishes at /bbs/keys/1 and in the did:web document, the same ' +
          'BBS key pair.' },
  // ---- section 2: single-use values ----------------------------------------
  { id: 'oauth.codes-once', section: '2',
    by: 'oauth-oidc/oauth2.js',
    what: 'An authorization code and a PAR request_uri are spent once across ' +
          'the cluster, and a replayed code revokes what it bought.' },
  { id: 'oauth.refresh-rotation', section: '2',
    by: 'oauth-oidc/oauth2_bcp.js',
    what: 'A rotated refresh token is redeemed once, reuse detection sees ' +
          'every node, and the hosted surfaces renew once.' },
  { id: 'oauth.dpop-jti', section: '2',
    by: 'oauth-oidc/dpop.js',
    what: 'A DPoP proof\'s jti is accepted once across the cluster, and the ' +
          'server nonce verifies on every node.' },
  { id: 'authn.second-factors-once', section: '2',
    by: 'common/credentials.js',
    what: 'A TOTP step and a recovery code are accepted once across the ' +
          'cluster, and a WebAuthn signature counter never goes backwards.' },
  { id: 'credentials.links-once', section: '2',
    by: 'common/credentials.js',
    what: 'An activation or password-reset link is used once across the ' +
          'cluster.' },
  { id: 'enrollment.credentials-once', section: '2',
    by: 'common/cert_enrollment.js',
    what: 'An ACME External Account Binding key binds one account, a SCEP ' +
          'challenge password and an ACME nonce are spent once, and a SPIFFE ' +
          'join token is used once.' },
  { id: 'saml.artifacts-once', section: '2',
    by: 'saml/saml2_sso.ts',
    what: 'A SAML 2.0 or SAML 1.1 artifact is resolved once across the ' +
          'cluster.' },
  { id: 'oid4vc.once', section: '2',
    by: 'oid4vc/vc_issuer.ts',
    what: 'An OpenID4VCI pre-authorized code and c_nonce are spent once, and ' +
          'tx_code failures are counted across the cluster.' },
  { id: 'gnap.once', section: '2',
    by: 'gnap/gnap_store.ts',
    what: 'A GNAP continuation, interaction reference, user code and request ' +
          'signature are spent once across the cluster.' },
  { id: 'kerberos.replay-cache', section: '2',
    by: 'kerberos/krb5_service.js',
    what: 'A Kerberos AP-REQ authenticator is accepted once across the ' +
          'cluster.' },
  { id: 'security.rate-limits', section: '2',
    by: 'common/websecurity.js',
    what: 'Rate limits and LDAP bind throttling count every node\'s attempts ' +
          'against one budget.' },
  // ---- section 3: last writer wins -----------------------------------------
  { id: 'store.no-foreign-deletes', section: '3',
    by: 'persistence/persistence_postgres.js',
    what: 'Saving the realm registry or the settings overrides never deletes ' +
          'a row another node wrote.' },
  { id: 'directory.concurrent-writes', section: '3',
    by: 'persistence/persistence_postgres.js',
    what: 'Two nodes modifying one directory entry keep both changes, two ' +
          'adds of one DN do not silently replace each other, and a uid is ' +
          'unique in its realm.' },
  { id: 'sessions.no-resurrection', section: '3, 4',
    by: 'persistence/persistence_minted.js',
    what: 'An ended session, a revoked token or a spent code cannot be ' +
          'written back by a node holding an older copy.' },
  // ---- section 4: sign-out -------------------------------------------------
  { id: 'ldap.connections-cluster', section: '4',
    by: 'ldap/ldap_cluster_connections.ts',
    what: 'A sign-out closes an identity\'s LDAP connections on every node, ' +
          'and the session inventory lists them all.' },
  // ---- section 5: valid requests refused -----------------------------------
  { id: 'secrets.protocol-keys', section: '5',
    by: 'common/websecurity.js',
    what: 'The CSRF key, the ACME nonce key and the SSF receiver secret are ' +
          'the cluster\'s shared secrets rather than generated per process ' +
          'or per run.' },
  { id: 'scim.challenge-state', section: '5',
    by: 'scim/scim_auth.ts',
    what: 'A SCIM Digest or HOBA challenge issued by one node is answered at ' +
          'any node.' },
  { id: 'spnego.pending', section: '5',
    by: 'kerberos/spnego_exchange.js',
    what: 'A SPNEGO negotiation is not keyed by the client address, which a ' +
          'load balancer makes one address for everybody.' },
  // ---- section 6: shared signals -------------------------------------------
  { id: 'ssf.delivery', section: '6',
    by: 'ssf/ssf.ts',
    what: 'An acknowledged SET is never delivered again by another node, a ' +
          'session end emits one event, and stream health is one state.' },
  // ---- section 8: operations -----------------------------------------------
  { id: 'ops.change-log-retention', section: '8',
    by: 'persistence/persistence_replication.js',
    what: 'The change log is trimmed below what every live node has applied.' },
  { id: 'ops.bootstrap-once', section: '8',
    by: 'common/credentials.js',
    what: 'A cold start of several nodes against an empty store generates one ' +
          'bootstrap administrator password.' }
];

const byId = new Map(CAPABILITIES.map(function (row) {
  return [row.id, row];
}));

// id -> { by, note, at }
const provided = new Map();

// A module saying it has fixed one row. Called at require time. An id that is
// not a row is a programming error and is thrown, because a capability nobody
// can see in the table is a refusal that can never be satisfied or explained.
function provide(id, detail) {
  log.debug("Entering provide(). id=" + id);
  if (!byId.has(id)) {
    log.debug("Leaving provide(). Unknown.");
    throw new Error('cluster_capabilities: "' + id + '" is not a capability ' +
                    'this build knows; add it to CAPABILITIES first.');
  }
  provided.set(id, { note: String((detail && detail.note) || ''),
                     at: new Date().toISOString() });
  log.debug("Leaving provide().");
}

function isProvided(id) {
  log.debug("Entering isProvided().");
  log.debug("Leaving isProvided().");
  return provided.has(id);
}

// The operator's list, from `cluster.acceptMissingCapabilities`, with anything
// that is not a real id kept apart — a typo there must be SAID, not silently
// accept nothing.
function accepted() {
  log.debug("Entering accepted().");
  const raw = config.value('cluster.acceptMissingCapabilities');
  const list = (Array.isArray(raw) ? raw : String(raw || '').split(','))
    .map(function (one) { return String(one).trim(); })
    .filter(Boolean);
  log.debug("Leaving accepted().");
  return {
    known: list.filter(function (id) { return byId.has(id); }),
    unknown: list.filter(function (id) { return !byId.has(id); })
  };
}

// The whole table as a page and the API draw it, and the verdict active-active
// is held to.
function report() {
  log.debug("Entering report().");
  const ok = accepted();
  const rows = CAPABILITIES.map(function (row) {
    const has = provided.get(row.id);
    return {
      id: row.id, section: row.section, by: row.by, what: row.what,
      provided: !!has, note: has ? has.note : '',
      accepted: !has && ok.known.indexOf(row.id) >= 0
    };
  });
  const missing = rows.filter(function (row) {
    return !row.provided && !row.accepted;
  }).map(function (row) { return row.id; });
  log.debug("Leaving report().");
  return {
    rows: rows,
    missing: missing,
    acceptedMissing: rows.filter(function (row) {
      return row.accepted;
    }).map(function (row) { return row.id; }),
    unknownAccepted: ok.unknown,
    ready: missing.length === 0
  };
}

// For tests only.
function reset() {
  log.debug("Entering reset().");
  provided.clear();
  log.debug("Leaving reset().");
}

module.exports = {
  CAPABILITIES: CAPABILITIES,
  provide: provide,
  isProvided: isProvided,
  accepted: accepted,
  report: report,
  reset: reset
};
