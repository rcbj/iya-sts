'use strict';
//
// File: spiffe_auth.ts
//
// ---------------------------------------------------------------------------
// WHO IS CALLING THE TWO gRPC SURFACES — the SPIFFE half of what `scim_auth.js`
// is to `/scim/v2`, and the second surface in this service that enforced
// anything at all when it was written.
//
// A LIBRARY: it registers no route, starts no listener and NEVER TOUCHES A
// `call` TO ANSWER ONE. It decides and `spiffe_grpc.ts` answers — the same
// split `oauth2_bcp.js` has with `oauth2.js` and `scim_auth.js` has with
// `scim.js` — which is why every refusal below is returned as a plain
// `{ status, message }` descriptor rather than as a gRPC error. It requires
// `crypto`, `helpers.js`, `config.js`, `audit.js`, `admin_stats.js`,
// `spiffe_id.ts`, `spiffe_ca.ts` and `spiffe_registry.ts`; `spiffe_grpc.ts`
// requires THIS, in the ordinary direction, so it cannot join a cycle.
//
// ---------------------------------------------------------------------------
// THE TWO SURFACES ARE AUTHENTICATED DIFFERENTLY BECAUSE THE SPECIFICATIONS
// SAY OPPOSITE THINGS, AND THAT IS THE FIRST THING TO KNOW
//
// It reads like an inconsistency and it is not. They are two different
// documents making two different demands, and getting them the same way round
// would break a real client either way.
//
//   **The Workload API MUST NOT authenticate its clients.** The SPIFFE Workload
//   Endpoint specification says so in terms: the endpoint "MUST NOT require any
//   direct authentication of its clients", and "Transport Layer Security MUST
//   NOT be required". The reason is bootstrapping — a workload has no secret
//   and no root of trust until this call gives it one, so a credential cannot
//   be asked for. The endpoint instead ASCERTAINS the caller out of band, by
//   asking the kernel about the peer of the Unix socket, and turns what it
//   learns into SELECTORS. A mock that demanded a credential here would refuse
//   every conforming client.
//
//   **The SPIRE Server API is mutual TLS with an X509-SVID.** A real
//   `spire-server` binds a TCP port whose clients present an SVID from this
//   trust domain, takes the caller's SPIFFE ID off the certificate, and
//   authorizes each method against WHAT THAT CALLER IS — local, agent, admin,
//   downstream. Its private Unix socket is `local` and needs no credential,
//   which is how the `spire-server` CLI works on the same host.
//
// So: the Workload API gains ATTESTATION here and no credential; the Server API
// gains a CREDENTIAL and an authorization table. Neither is a softening of the
// other.
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVICE CAN AND CANNOT ATTEST, SAID PLAINLY
//
// A real agent reads the peer credentials of its Unix socket — `SO_PEERCRED`,
// giving pid, uid and gid — and from the pid derives the executable path, its
// sha256, the container, the Kubernetes pod. **Node has no portable way to read
// `SO_PEERCRED`**: `net.Socket` exposes no such call, `/proc/net/unix` does not
// record the peer, and the only routes to it are native addons. So the honest
// list of what a caller can be identified BY here is short, and it is published
// rather than implied:
//
//   * the TRANSPORT it arrived on — the Unix socket or TCP;
//   * the ENDPOINT it reached — which socket path, or which address and port;
//   * for TCP, the peer address;
//   * and, only when `spiffe.acceptAssertedSelectors` is on, whatever the
//     caller SAID about itself.
//
// (The Unix socket's caller is ATTESTED since #40 — the native module reads
// SO_PEERCRED after all — and those selectors join these; see
// `workloadSelectors()`. Only the first two say HOW a caller arrived and never
// WHO it is, which is why a product realm refuses an entry that selects
// nothing else, and serves TCP, whose only WHO is the peer address, only on a
// network declared to authenticate it — #166, `workloadTcpPosture()`.)
//
// The first three are facts about the connection and are real. The fourth is
// not attestation at all and is named so that nobody can mistake it for any:
// it exists because SELECTOR MATCHING IS THE INTERESTING BEHAVIOUR and there is
// otherwise no way to exercise it. A client library's "these selectors matched
// and those did not" path is a real path with real bugs in it, and a mock that
// hands every caller every identity can never run it.
//
// **THE SELECTORS THIS SERVICE PRODUCES ARE NOT SPELT LIKE SPIRE'S.** They are
// `transport:`, `endpoint:` and `peer:`, which are types no attestor plugin
// defines. Writing `unix:uid:1000` for a uid nothing read would be inventing an
// attested fact, which is the same offence as minting a WIT-SVID against no
// specification. An ASSERTED selector, by contrast, is passed through VERBATIM
// — if a caller says `unix:uid:1000` that is what it is matched on — because
// the whole point of the affordance is to reproduce a real match, and it is the
// caller's own claim rather than this service's invention.
//
// ---------------------------------------------------------------------------
// THE AUTHORIZATION TABLE IS SPIRE'S OWN, ROW FOR ROW
//
// `POLICY` below is `pkg/server/authpolicy/policy_data.json` from the SPIRE
// source, restricted to the forty-two methods this service implements. It is
// COPIED rather than reasoned out, deliberately: a table somebody derived from
// what each method "obviously" needs is a table that disagrees with SPIRE in
// two or three places, and the client author who meets the disagreement has no
// way to tell which end is wrong. Where a row here looks surprising — `Debug.
// GetInfo` is local-only, so an admin SVID over TCP is refused it — that is
// SPIRE's answer and the surprise is the point.
//
// ---------------------------------------------------------------------------
// WHAT IS STILL NOT CHECKED, BECAUSE THE LIST MATTERS MORE THAN THE ADDITIONS
//
// The Workload API still hands out identities to anybody who can reach the
// socket; there is no attestation of a workload's identity, only of which
// entries its observable selectors match. Node attestation at `AttestAgent` is
// no longer on this list (#40, 2026-09-21): a type is verified by its attestor
// in `spiffe_node_attestation.ts`'s table or refused. It used to be possible
// to stand all of this
// down — `spiffe.authRequired` off, and the service behaved exactly as it did
// before this file existed — and it is not: that setting was removed on
// 2026-09-06 when `global.mode` took the question over. See `GET /spiffe`,
// which publishes the whole of it.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SpiffeAuth` takes the modules it uses through its constructor
// (`SpiffeAuthDeps`), and since #50's R2 the composition root builds the
// instance and installs it here. The module still exports its old names as
// FACADES forwarding to it, for the callers that are not converted; a process
// without the root builds a default when this module loads. `SpiffeAuth` is
// exported for the root.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log, nowSec } = helpers;
import config = require('../common/config');
// The mode. A LEAF (rule 3): registers nothing, requires only `config`.
import mode = require('../common/mode');
import audit = require('../common/audit');
// THE ERROR CODES. A LEAF. Every refusal descriptor below carries the condition
// as `errorCode`, and `spiffe_grpc.ts` puts it on the one audit row the refusal
// gets; the descriptor itself never reaches a client.
import errorCodes = require('../common/error_codes');
import stats = require('../common/admin_stats');
// PER REALM SINCE 2026-09-12 (it was per process) — see the store below.
// Required only for `realms.map()`, and it is a LEAF that registers no route,
// so this cannot move a route or join a cycle.
import realms = require('../common/realms');
import spiffeId = require('./spiffe_id');
import ca = require('./spiffe_ca');
import registry = require('./spiffe_registry');
// The RFC 4514 form of a certificate subject. Required rather than
// reimplemented for the reason that module's export note gives — two spellings
// of one DN is two people on /admin/users — and `scim_auth.js` requires it for
// exactly this. That module knows nothing about SPIFFE, so there is no cycle.
// **THE ROUTE ORDER IS NOT WHAT IT LOOKS LIKE**: this file is first loaded
// from inside `admin-ui/admin.ts`'s require (`admin-core/admin_views.ts` →
// here), so THIS line is what first loads `tls/tls_server.js` and registers
// its `/tls` routes during position 18 rather than 20, as `tls/CLAUDE.md`
// records.
import tls = require('../tls/tls_server');
// THE REVOCATION CHECK (2026-09-12), its synchronous register-only door. A
// LIBRARY that registers no route; it requires `common/pki.js`, which
// `spiffe_ca.ts` above already requires, so nothing new is loaded here.
import revocationStatus = require('../common/revocation_status');
// WHO IS ON THE OTHER END OF A UNIX SOCKET (#40), asked here since #104 for
// the SPIRE Server API's socket: in product mode the `local` entity needs the
// peer's kernel uid. It requires only `helpers` and `config`, so it cannot
// join a cycle.
import peer = require('./spiffe_peer');

// ---------------------------------------------------------------------------
// THE ENTITIES. A CALLER MAY BE SEVERAL AT ONCE.
//
// SPIRE's authorizers are not exclusive and this must not make them so: the
// `spire-server` CLI on the same host is `local`, an agent that also holds an
// entry marked admin is both, and a caller over TCP with no certificate is
// none of them. `authorize()` therefore asks "is the caller ANY of the
// entities this method allows", which is what the rego does.
//
// The prose is here rather than on the pages because both `GET /spiffe` and
// `/admin/spiffe` draw it, and two copies of an explanation is one that will
// eventually be wrong on one page.
// ---------------------------------------------------------------------------
const ENTITIES = [
  { id: 'local', label: 'Local',
    what: 'The call arrived on the Unix domain socket. A real SPIRE server ' +
          'trusts its private socket outright — that is how the spire-server ' +
          'CLI works — and the access control is the socket\'s filesystem ' +
          'permissions. Development mode assumes that boundary; PRODUCT ' +
          'mode verifies it per connection: the socket made 0600 in a ' +
          'directory other users cannot reach, and the caller\'s kernel uid ' +
          'this service\'s own. `spiffe.trustLocalSocket` turns it off, ' +
          'which makes the socket demand an SVID like the TCP port and is ' +
          'the only way to exercise a client\'s "I was refused on the ' +
          'socket" path.' },
  { id: 'agent', label: 'Agent',
    what: 'The caller presented an X509-SVID whose SPIFFE ID is an agent id ' +
          '(/spire/agent/...) and which names an agent this server has ' +
          'attested and has not banned. A banned agent is refused here ' +
          'rather than at AttestAgent alone, which is what makes the ban on ' +
          '/admin/spiffe/agents mean something for a caller that already ' +
          'holds an SVID.' },
  { id: 'admin', label: 'Admin',
    what: 'The caller\'s SPIFFE ID is named in `spiffe.adminIds`, or a ' +
          'registration entry for that identity is marked `admin`. Both, ' +
          'because SPIRE has both: admin_ids needs no entry, and the flag on ' +
          'an entry is what an operator sets from the console. This is the ' +
          'thing that lets a remote caller manage registration entries.' },
  { id: 'downstream', label: 'Downstream',
    what: 'A registration entry for the caller\'s identity is marked ' +
          '`downstream` — a nested SPIRE server, which may ask for an ' +
          'intermediate CA and publish an authority and may do nothing else.' },
  { id: 'anonymous', label: 'Anonymous',
    what: 'No credential was presented, or one was and it did not verify. ' +
          'Two methods are still open to it, and both have to be: ' +
          'AttestAgent, because an agent has no SVID until that call gives ' +
          'it one, and GetBundle, because the trust bundle is public by ' +
          'design.' }
];

// ---------------------------------------------------------------------------
// THE POLICY TABLE — SPIRE's `policy_data.json`, the forty-two rows this
// service has methods for.
//
// `any` is `allow_any` in that file and means the method is open, which is a
// different statement from "this service does not check it": AttestAgent and
// GetBundle are open in a real SPIRE server too, for the reasons in ENTITIES
// above.
//
// A method with NO ROW is refused rather than allowed. That is the safer
// direction and it is also the one that fails visibly: a method added without
// a row is refused for everybody the first time it is called, where a default
// of "allow" would leave it unauthorized forever with nothing to notice.
// ---------------------------------------------------------------------------
const POLICY = {
  // Entry
  'Entry.CountEntries':        { admin: true, local: true },
  'Entry.ListEntries':         { admin: true, local: true },
  'Entry.GetEntry':            { admin: true, local: true },
  'Entry.BatchCreateEntry':    { admin: true, local: true },
  'Entry.BatchUpdateEntry':    { admin: true, local: true },
  'Entry.BatchDeleteEntry':    { admin: true, local: true },
  'Entry.GetAuthorizedEntries':  { agent: true },
  'Entry.SyncAuthorizedEntries': { agent: true },
  // Agent
  'Agent.CountAgents':         { admin: true, local: true },
  'Agent.ListAgents':          { admin: true, local: true },
  'Agent.GetAgent':            { admin: true, local: true },
  'Agent.DeleteAgent':         { admin: true, local: true },
  'Agent.BanAgent':            { admin: true, local: true },
  'Agent.CreateJoinToken':     { admin: true, local: true },
  'Agent.AttestAgent':         { any: true },
  'Agent.RenewAgent':          { agent: true },
  'Agent.PostStatus':          { agent: true },
  // Bundle
  'Bundle.GetBundle':          { any: true },
  'Bundle.CountBundles':       { admin: true, local: true },
  'Bundle.AppendBundle':       { admin: true, local: true },
  'Bundle.PublishJWTAuthority': { downstream: true },
  'Bundle.PublishWITAuthority': { downstream: true },
  'Bundle.ListFederatedBundles': { admin: true, local: true },
  'Bundle.GetFederatedBundle': { admin: true, local: true, agent: true },
  'Bundle.BatchCreateFederatedBundle': { admin: true, local: true },
  'Bundle.BatchUpdateFederatedBundle': { admin: true, local: true },
  'Bundle.BatchSetFederatedBundle':    { admin: true, local: true },
  'Bundle.BatchDeleteFederatedBundle': { admin: true, local: true },
  // SVID
  'SVID.MintX509SVID':         { admin: true, local: true },
  'SVID.MintJWTSVID':          { admin: true, local: true },
  'SVID.MintWITSVID':          { admin: true, local: true },
  'SVID.BatchNewX509SVID':     { agent: true },
  'SVID.NewJWTSVID':           { agent: true },
  'SVID.BatchNewWITSVID':      { agent: true },
  'SVID.NewDownstreamX509CA':  { downstream: true },
  // TrustDomain
  'TrustDomain.ListFederationRelationships':       { admin: true, local: true },
  'TrustDomain.GetFederationRelationship':         { admin: true, local: true },
  'TrustDomain.BatchCreateFederationRelationship': { admin: true, local: true },
  'TrustDomain.BatchUpdateFederationRelationship': { admin: true, local: true },
  'TrustDomain.BatchDeleteFederationRelationship': { admin: true, local: true },
  'TrustDomain.RefreshBundle':                     { admin: true, local: true },
  // Debug. Local ONLY, in SPIRE and therefore here: an admin SVID over TCP is
  // refused it. That reads like an omission and is not — it is a health check
  // for whoever is standing on the host.
  'Debug.GetInfo':             { local: true }
};

// The order the entities are named in a refusal message, so two refusals for
// the same method read the same way.
const ENTITY_ORDER = ['local', 'admin', 'agent', 'downstream'];

// The bind addresses that mean EVERY interface (#166). `spiffe_server.ts`'s
// `overlaps()` recognises the same four for the address-collision refusal.
const WILDCARD_HOSTS = ['0.0.0.0', '::', '[::]', ''];

// The reference types an entry of `spiffe.brokers` may allow (#170).
const BROKER_REFERENCE_TYPES = ['pid', 'k8s', '*'];

// What `SpiffeAuth` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface SpiffeAuthDeps {
  crypto: typeof crypto;
  log: typeof log;
  nowSec: typeof nowSec;
  config: typeof config;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  stats: typeof stats;
  spiffeId: typeof spiffeId;
  ca: typeof ca;
  registry: typeof registry;
  tls: typeof tls;
  revocationStatus: typeof revocationStatus;
  peer: typeof peer;
  // This process's effective uid, or -1 where the platform has none. A
  // function rather than a number so a test can be another process.
  processUid(): number;
}

class SpiffeAuth {
  constructor(private readonly deps: SpiffeAuthDeps) {
    deps.log.debug("Entering SpiffeAuth.constructor().");
    deps.log.debug("Leaving SpiffeAuth.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): SpiffeAuthDeps {
    helpers.log.debug("Entering SpiffeAuth.defaultDeps().");
    helpers.log.debug("Leaving SpiffeAuth.defaultDeps().");
    return {
      crypto: crypto,
      log: log,
      nowSec: nowSec,
      config: config,
      mode: mode,
      errorCodes: errorCodes,
      stats: stats,
      spiffeId: spiffeId,
      ca: ca,
      registry: registry,
      tls: tls,
      revocationStatus: revocationStatus,
      peer: peer,
      processUid: function () {
        return typeof process.geteuid === 'function' ? process.geteuid() : -1;
      }
    };
  }

  // ---------------------------------------------------------------------------
  // SETTINGS, read per call rather than captured. Every one of these is
  // `runtime: true`. The one that was not — `spiffe.authRequired`, which bound
  // a socket — is gone; see config.js's header for why a captured `const` is
  // the one thing /admin/config cannot reach.
  // ---------------------------------------------------------------------------
  // THE MODE, since 2026-09-06, where this read `spiffe.authRequired`. The
  // Workload API is deliberately NOT covered by it and never may be — its
  // specification says it MUST NOT authenticate a caller, because a workload
  // has no root of trust until that call gives it one. What this gates is the
  // SPIRE Server API, whose output is a credential another service will
  // believe.
  authRequired() {
    const { log, mode } = this.deps;
    log.debug("Entering SpiffeAuth.authRequired().");
    log.debug("Leaving SpiffeAuth.authRequired().");
    return mode.gatesSpireServerApi();
  }

  trustLocalSocket() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeAuth.trustLocalSocket().");
    log.debug("Leaving SpiffeAuth.trustLocalSocket().");
    return !!config.value('spiffe.trustLocalSocket');
  }

  // AS IT IS IN FORCE (#104): OFF is honoured in development only
  // (`mode.servesUnattestedEntries()`); a product realm reads the default,
  // ON, whatever is stored, and says so once.
  attestWorkloads() {
    const { log, mode } = this.deps;
    log.debug("Entering SpiffeAuth.attestWorkloads().");
    log.debug("Leaving SpiffeAuth.attestWorkloads().");
    return !!mode.valueInForce('spiffe.attestWorkloads');
  }

  // ON, AND BELIEVED ONLY OUTSIDE PRODUCT MODE (#40, 2026-09-21): a
  // selector the caller wrote is a claim nothing checked, and a registration
  // entry for `unix:uid:0` must not be had by typing it into a header. The
  // row's `onlyWhile` marker names `mode.believesAssertedSelectors()`, so
  // `valueInForce()` asks it, says once that a stored value is ignored, and
  // the write is refused in product too (#104).
  acceptAssertedSelectors() {
    const { log, mode } = this.deps;
    log.debug("Entering SpiffeAuth.acceptAssertedSelectors().");
    log.debug("Leaving SpiffeAuth.acceptAssertedSelectors().");
    return !!mode.valueInForce('spiffe.acceptAssertedSelectors');
  }

  // ---------------------------------------------------------------------------
  // IS THIS UNIX-SOCKET CALLER THE `local` ENTITY? (#104, 2026-09-23.)
  //
  // SPIRE trusts its private socket outright and relies on the socket's
  // filesystem permissions. Development does exactly that. Product VERIFIES
  // the two things that make the trust sound, from facts recorded when the
  // connection was accepted (`spiffe_server.ts` binds the SPIRE Server API
  // socket through `bindAttestedSocket()` wherever the native module is
  // built, and records `facts.localSocket` at accept):
  //
  //   * the socket is PRIVATE — `restrictSocket()` made it 0600, and neither
  //     it nor its directory has a group or other bit (STS-SPIFFE-0117). A
  //     chmod that failed (STS-SPIFFE-0010) is exactly the case this refuses;
  //   * the peer's kernel uid (SO_PEERCRED) is this process's own
  //     (STS-SPIFFE-0118). Where the kernel could not be asked — no native
  //     module, or SO_PEERCRED failed — nothing is known and the answer is no
  //     (STS-SPIFFE-0119).
  //
  // Asked per call, in the realm the socket belongs to, because the mode is a
  // runtime setting: a realm switched to product stops trusting an unverified
  // connection on its very next call. A refused caller is not `local`; it is
  // whatever else it is — on the socket, which carries no TLS, that is
  // anonymous, and the remedy is an administrator's X509-SVID on the TCP port.
  // ---------------------------------------------------------------------------
  localTrust(call): { local: boolean; why: string; errorCode: string } {
    const { log, mode, peer } = this.deps;
    log.debug('Entering SpiffeAuth.localTrust().');
    if (!this.trustLocalSocket()) {
      log.debug('Leaving SpiffeAuth.localTrust(). The setting is off.');
      return { local: false, errorCode: '',
               why: 'arrived on the Unix domain socket, which is NOT trusted ' +
                    'as local here (spiffe.trustLocalSocket is off)' };
    }
    if (mode.trustsUnverifiedLocalSocket()) {
      log.debug('Leaving SpiffeAuth.localTrust(). Development: trusted.');
      return { local: true, errorCode: '',
               why: 'arrived on the Unix domain socket, which this server ' +
                    'trusts as local (spiffe.trustLocalSocket)' };
    }
    const facts: Record<string, any> | null =
      peer.factsFor(this.peerOf(call));
    if (!facts || facts.error || facts.uid < 0) {
      const problem = facts
        ? (facts.error || 'the kernel named no uid')
        : (peer.availability().problem ||
           'the connection was not accepted by a listener that reads the ' +
           'peer\'s credentials');
      log.debug('Leaving SpiffeAuth.localTrust(). No peer credentials.');
      return { local: false, errorCode: 'STS-SPIFFE-0119',
               why: 'arrived on the Unix domain socket and is NOT trusted as ' +
                    'local: this realm is in product mode, where the ' +
                    'caller\'s kernel uid must be read and this one could ' +
                    'not be (' + problem + ')' };
    }
    const boundary = facts.localSocket || { private: false,
      why: 'the socket\'s permissions were not checked when this ' +
           'connection was accepted' };
    if (!boundary.private) {
      log.debug('Leaving SpiffeAuth.localTrust(). The socket is not private.');
      return { local: false, errorCode: 'STS-SPIFFE-0117',
               why: 'arrived on the Unix domain socket and is NOT trusted as ' +
                    'local: this realm is in product mode, where the socket ' +
                    'must be verified private, and ' + boundary.why };
    }
    const own = this.deps.processUid();
    if (facts.uid !== own) {
      log.debug('Leaving SpiffeAuth.localTrust(). A foreign uid.');
      return { local: false, errorCode: 'STS-SPIFFE-0118',
               why: 'arrived on the Unix domain socket and is NOT trusted as ' +
                    'local: this realm is in product mode, and the caller ' +
                    'runs as uid ' + facts.uid + ', not this service\'s uid ' +
                    own };
    }
    log.debug('Leaving SpiffeAuth.localTrust(). Verified.');
    return { local: true, errorCode: '',
             why: 'arrived on the Unix domain socket, which this server ' +
                  'trusts as local (spiffe.trustLocalSocket): the socket is ' +
                  'private and the caller runs as this service\'s uid ' +
                  own + ', verified by the kernel' };
  }

  // ---------------------------------------------------------------------------
  // IS THE WORKLOAD API SERVED OVER TCP HERE, AND WHY? (#166, 2026-09-23.)
  //
  // The Workload Endpoint specification section 3: "TCP transport MUST NOT be
  // used unless the underlying network allows the Workload Endpoint server to
  // strongly authenticate the workload based on source IP address." Section
  // 3.1 and section 5 rule out the other fixes — "Transport Layer Security
  // MUST NOT be required", and the endpoint "MUST NOT require any direct
  // authentication of its clients" — so the only identity a TCP caller can
  // carry is its source address, and only on a network that guarantees it.
  // That is a fact about the deployment this process cannot observe, so the
  // operator DECLARES it (`spiffe.workloadTcpSourceAuthenticated`) and a
  // product realm does not serve TCP without the declaration.
  //
  // WITH it, a wildcard `spiffe.grpcHost` is still refused: 0.0.0.0 is every
  // interface this host has, including ones the declaration was never about,
  // so the operator names the address whose network they vouch for.
  //
  // One answer for three askers: `spiffe_server.ts`'s `bindAll()` (whether
  // the port is bound), `spiffe_grpc.ts`'s `prepareCall()` (a realm switched
  // to product with the port already bound refuses every call on it — the
  // mode is runtime, so the read is the guard) and the three pages, through
  // `workloadAttestationState()`. Read in the AMBIENT realm, which is the
  // listener's in all three.
  // ---------------------------------------------------------------------------
  workloadTcpPosture(): { port: number; host: string; served: boolean;
                          declared: boolean; errorCode: string;
                          state: string; why: string } {
    const { log, config, mode } = this.deps;
    log.debug('Entering SpiffeAuth.workloadTcpPosture().');
    const port = Number(config.value('spiffe.workloadPort'));
    const host = String(config.value('spiffe.grpcHost') || '');
    const declared = !!config.value('spiffe.workloadTcpSourceAuthenticated');
    const base = { port: port, host: host, declared: declared };
    if (!port) {
      log.debug('Leaving SpiffeAuth.workloadTcpPosture(). The port is 0.');
      return Object.assign(base, { served: false, errorCode: '',
        state: 'off (spiffe.workloadPort is 0)',
        why: 'the Workload API TCP port is turned off' });
    }
    if (mode.servesUnattestedWorkloadTcp()) {
      log.debug('Leaving SpiffeAuth.workloadTcpPosture(). Development.');
      return Object.assign(base, { served: true, errorCode: '',
        state: 'served (development, not attested)',
        why: 'development mode serves the Workload API over TCP; a caller ' +
             'there is identified by its transport, the endpoint it ' +
             'reached and its source address, and nothing attests it' });
    }
    if (!declared) {
      log.debug('Leaving SpiffeAuth.workloadTcpPosture(). Not declared.');
      return Object.assign(base, { served: false,
        errorCode: 'STS-SPIFFE-0120',
        state: 'not served (product, source not declared authenticated)',
        why: 'this realm is in product mode, where the Workload API is not ' +
             'served over TCP unless spiffe.workloadTcpSourceAuthenticated ' +
             'declares that the network authenticates source addresses — ' +
             'the SPIFFE Workload Endpoint specification, section 3, allows ' +
             'TCP on no other condition. Use the Unix socket, or declare the ' +
             'network and name its address in spiffe.grpcHost' });
    }
    if (WILDCARD_HOSTS.indexOf(host) >= 0) {
      log.debug('Leaving SpiffeAuth.workloadTcpPosture(). A wildcard.');
      return Object.assign(base, { served: false,
        errorCode: 'STS-SPIFFE-0121',
        state: 'not served (product, wildcard bind address)',
        why: 'spiffe.workloadTcpSourceAuthenticated declares one network\'s ' +
             'source addresses authenticated, and spiffe.grpcHost is "' +
             host + '" — every interface on this host, including ones that ' +
             'declaration was never about. Product mode refuses it: set ' +
             'spiffe.grpcHost to the address on the network you vouch for' });
    }
    log.debug('Leaving SpiffeAuth.workloadTcpPosture(). Declared.');
    return Object.assign(base, { served: true, errorCode: '',
      state: 'served (product, source declared authenticated)',
      why: 'spiffe.workloadTcpSourceAuthenticated declares that the network ' +
           'at ' + host + ' authenticates source addresses, so a TCP caller ' +
           'is identified by its peer: address, and a registration entry ' +
           'must select one (or another identifying selector) to answer it' });
  }

  // The admin ids, as a list. A string in configuration because it is a list of
  // URIs and every other list-shaped setting here is one; parsed on every read
  // so that adding one on /admin/config takes effect on the next call.
  adminIds() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeAuth.adminIds().");
    const raw = String(config.value('spiffe.adminIds') || '');
    log.debug("Leaving SpiffeAuth.adminIds().");
    return raw.split(/[\s,]+/).map(function (id) { return id.trim(); })
              .filter(Boolean);
  }

  // ---------------------------------------------------------------------------
  // THE SPIFFE BROKER API'S BROKERS (#170, 2026-09-23).
  //
  // The SPIFFE Broker API section 4.1: "Implementations MUST maintain a strict
  // allow-only policy", and the Broker Endpoint section 5 recommends a static
  // one keyed on the broker's SPIFFE ID. `spiffe.brokers` is that list, one
  // entry per broker — `<SPIFFE ID>=<types>` — and the types are SPIRE's
  // per-broker `allowed_reference_types` (`pkg/agent/broker/endpoints.go`),
  // spelt `pid` (WorkloadPIDReference), `k8s` (KubernetesObjectReference) and
  // `*`. SPIRE also says per type whether TCP may carry it; this endpoint is
  // TCP only, so listing a type IS allowing it over TCP, and an entry that
  // lists none allows nothing (SPIRE's "must list at least one entry").
  //
  // Parsed on every call and never cached, like `adminIds()`: an edit on
  // /admin/spiffe/brokers takes effect on the broker's next call. An entry
  // that does not parse is REPORTED with its problem and authorizes nothing.
  // ---------------------------------------------------------------------------
  parseBrokers(raw: string): Array<{ id: string; types: string[];
                                     problem: string; raw: string }> {
    const { log, spiffeId } = this.deps;
    log.debug("Entering SpiffeAuth.parseBrokers().");
    const out = String(raw || '').split(/\s+/).filter(Boolean)
      .map(function (entry) {
        const cut = entry.indexOf('=');
        const idText = cut >= 0 ? entry.slice(0, cut) : entry;
        const parsed = spiffeId.parse(idText);
        const types = (cut >= 0 ? entry.slice(cut + 1) : '').split(',')
          .map(function (one) {
            return one.trim().toLowerCase();
          }).filter(Boolean);
        let problem = '';
        if (!parsed.ok) {
          problem = 'not a SPIFFE ID: ' + parsed.reason;
        } else if (!types.length) {
          problem = 'no reference type is allowed (list pid, k8s or *)';
        } else if (types.some(function (one) {
          return BROKER_REFERENCE_TYPES.indexOf(one) < 0;
        })) {
          problem = 'a reference type is not one of pid, k8s and *';
        }
        return { id: parsed.ok ? parsed.id : idText,
                 types: problem ? [] : types, problem: problem, raw: entry };
      });
    log.debug("Leaving SpiffeAuth.parseBrokers(). " + out.length);
    return out;
  }

  // The list as a setting's value. An entry that did not parse is written
  // back as it was typed (`raw`), so an edit elsewhere does not rewrite an
  // operator's typo into a different one.
  serializeBrokers(list: Array<{ id: string; types: string[];
                                 problem?: string; raw?: string }>): string {
    const { log } = this.deps;
    log.debug("Entering SpiffeAuth.serializeBrokers().");
    log.debug("Leaving SpiffeAuth.serializeBrokers().");
    return list.map(function (one) {
      return one.problem && one.raw ? one.raw
        : one.id + '=' + one.types.join(',');
    }).join(' ');
  }

  brokers(): Array<{ id: string; types: string[]; problem: string;
                     raw: string }> {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeAuth.brokers().");
    log.debug("Leaving SpiffeAuth.brokers().");
    return this.parseBrokers(String(config.value('spiffe.brokers') || ''));
  }

  // The broker an AUTHENTICATED caller is, or a refusal descriptor
  // (STS-SPIFFE-0133 unauthenticated, STS-SPIFFE-0134 not a broker).
  brokerOf(caller): { broker?: { id: string; types: string[] };
                      status?: string; message?: string;
                      errorCode?: string } {
    const { log } = this.deps;
    log.debug("Entering SpiffeAuth.brokerOf().");
    if (!caller || !caller.authenticated || !caller.spiffeId) {
      log.debug("Leaving SpiffeAuth.brokerOf(). Unauthenticated.");
      return { status: 'UNAUTHENTICATED', errorCode: 'STS-SPIFFE-0133',
               message: 'The SPIFFE Broker Endpoint requires mutual TLS with ' +
                        'an X509-SVID (SPIFFE Broker Endpoint section 5)' +
                        (caller && caller.refusal ? ': ' + caller.refusal
                         : ', and none was presented') + '.' };
    }
    const found = this.brokers().filter(function (one) {
      return !one.problem && one.id === caller.spiffeId;
    })[0];
    if (!found) {
      log.debug("Leaving SpiffeAuth.brokerOf(). Not a broker.");
      return { status: 'PERMISSION_DENIED', errorCode: 'STS-SPIFFE-0134',
               message: caller.spiffeId + ' is not an authorized broker ' +
                        'here (spiffe.brokers).' };
    }
    log.debug("Leaving SpiffeAuth.brokerOf(). " + found.id);
    return { broker: { id: found.id, types: found.types.slice(0) } };
  }

  // ---------------------------------------------------------------------------
  // THE TRANSPORT A CALL ARRIVED ON.
  //
  // This decides whether the caller is `local`, so it has to be right, and
  // grpc-js does not answer it directly. Two signals, in this order:
  //
  //   * the AUTH CONTEXT. The TCP listener for
  //     the SPIRE Server API is TLS and the Unix socket is not — so
  //     `transportSecurityType === 'ssl'` is conclusive proof of TCP.
  //   * `getPeer()`. grpc-js builds it from `socket.remoteAddress`, which a
  //     Unix socket does not have, so it answers the literal string `unknown`
  //     there and `address:port` for TCP. That is an implementation detail of
  //     the library rather than a documented API, which is why it is the SECOND
  //     signal and not the only one.
  //
  // Getting this wrong in the direction that matters — calling a TCP caller
  // `local` — would hand every method to anybody who could reach the port, so
  // the fallback below defaults to TCP for anything it does not recognise.
  // ---------------------------------------------------------------------------
  transportOf(call) {
    const { log } = this.deps;
    log.debug('Entering SpiffeAuth.transportOf().');
    let context = null;
    try {
      context = call && typeof call.getAuthContext === 'function'
        ? call.getAuthContext() : null;
    } catch (e) {
      // grpc-js throws here if the stream is already gone, which happens when a
      // client cancels mid-call. Not a fault and not the caller's problem.
      log.debug('transportOf(): the auth context was not readable (' +
                e.message +
                '), so the peer address decides.');
    }
    if (context && context.transportSecurityType === 'ssl') {
      log.debug('Leaving SpiffeAuth.transportOf().');
      return 'tcp';
    }
    let peer = '';
    try {
      peer = call && typeof call.getPeer === 'function' ?
             String(call.getPeer()) :
             '';
    } catch (e) {
      // Same case as above, and the same answer: assume the less trusting one.
      log.debug('transportOf(): the peer was not readable (' + e.message +
                ').');
    }
    if (!peer || peer === 'unknown' || peer.indexOf('unix:') === 0) {
      log.debug('Leaving SpiffeAuth.transportOf().');
      return 'uds';
    }
    log.debug('Leaving SpiffeAuth.transportOf().');
    return 'tcp';
  }

  peerOf(call) {
    const { log } = this.deps;
    log.debug("Entering SpiffeAuth.peerOf().");
    try {
      const peer = call && typeof call.getPeer === 'function' ?
                   String(call.getPeer()) : '';
      log.debug("Leaving SpiffeAuth.peerOf().");
      return peer === 'unknown' ? '' : peer;
    } catch (e) {
      // See transportOf(). A peer that cannot be read is not an error here; it
      // is a column on a page that says nothing.
      log.debug('peerOf(): the peer was not readable (' + e.message + ').');
      log.debug("Leaving SpiffeAuth.peerOf().");
      return '';
    }
  }

  // The certificate the client presented, or null. `sslPeerCertificate` is
  // absent rather than empty when none was sent — grpc-js only sets it when the
  // DER is there — which is what distinguishes "no certificate" from "a
  // certificate that did not verify", and those are two different refusals.
  peerCertificateOf(call) {
    const { log } = this.deps;
    log.debug("Entering SpiffeAuth.peerCertificateOf().");
    try {
      const context = call && typeof call.getAuthContext === 'function'
        ? call.getAuthContext() : null;
      if (!context || !context.sslPeerCertificate) {
        log.debug("Leaving SpiffeAuth.peerCertificateOf().");
        return null;
      }
      log.debug("Leaving SpiffeAuth.peerCertificateOf().");
      return context.sslPeerCertificate.raw ? context.sslPeerCertificate : null;
    } catch (e) {
      log.debug('peerCertificateOf(): no readable auth context (' + e.message +
                ').');
      log.debug("Leaving SpiffeAuth.peerCertificateOf().");
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // THE SPIFFE ID OFF A CERTIFICATE.
  //
  // It is the URI SAN and nothing else — not the subject, not a DNS name, not
  // `CN=`. An X509-SVID carries exactly ONE URI SAN and that is its identity;
  // reading a SPIFFE ID out of a common name would accept a certificate that is
  // not an SVID at all and would let anyone who can obtain a certificate with a
  // chosen CN name themselves anything.
  //
  // Node hands the SANs back as one comma-separated string —
  // `URI:spiffe://example.org/a, DNS:host` — so it is split rather than
  // indexed. A certificate with SEVERAL URI SANs is refused rather than having
  // the first taken: the SVID specification permits one, and picking one of two
  // would be choosing which identity a caller has on their behalf.
  // ---------------------------------------------------------------------------
  spiffeIdFromCertificate(certificate) {
    const { log, spiffeId } = this.deps;
    log.debug('Entering SpiffeAuth.spiffeIdFromCertificate().');
    const sans = String((certificate || {}).subjectaltname || '');
    const uris = sans.split(',').map(function (part) {
      return part.trim();
    }).filter(function (part) {
      return part.toLowerCase().indexOf('uri:') === 0;
    }).map(function (part) {
      return part.slice(4).trim();
    });
    if (!uris.length) {
      log.debug('Leaving SpiffeAuth.spiffeIdFromCertificate(). No URI SAN.');
      return { ok: false, reason: 'The certificate carries no URI ' +
               'subjectAltName, so it is not an ' +
               'X509-SVID. An SVID\'s identity ' +
               'is its URI SAN; nothing else on a certificate names one.',
               errorCode: 'STS-SPIFFE-0016' };
    }
    if (uris.length > 1) {
      log.debug('Leaving SpiffeAuth.spiffeIdFromCertificate(). ' + uris.length +
                ' URI SANs.');
      return { ok: false, reason: 'The certificate carries ' + uris.length +
               ' URI subjectAltNames. An X509-SVID ' +
               'has exactly one — choosing ' +
               'between them would be deciding which identity you have.',
               errorCode: 'STS-SPIFFE-0017' };
    }
    const parsed = spiffeId.parse(uris[0]);
    if (!parsed.ok) {
      log.debug('Leaving SpiffeAuth.spiffeIdFromCertificate(). Not a SPIFFE ' +
                'ID.');
      return { ok: false, reason: 'The certificate\'s URI subjectAltName is ' +
               'not a valid SPIFFE ID: ' + parsed.reason,
               errorCode: 'STS-SPIFFE-0018' };
    }
    log.debug('Leaving SpiffeAuth.spiffeIdFromCertificate(). ' + parsed.id);
    return { ok: true, id: parsed.id };
  }

  // ---------------------------------------------------------------------------
  // VERIFYING THE CERTIFICATE.
  //
  // This is done HERE and not by the TLS stack, and the reason is the one thing
  // about this listener that has to be understood before changing it.
  //
  // The socket is bound `requestCert: true, rejectUnauthorized: false` — ask
  // for a certificate, do not refuse a handshake that has none. It has to be,
  // because
  // `AttestAgent` is open to a caller with no SVID and an agent HAS no SVID
  // until that call gives it one. A listener that rejected unauthorized
  // connections would make agent bootstrapping impossible over TCP, which is
  // the one thing this port is for. So OpenSSL is told to collect the
  // certificate and this function decides what it is worth. `mtls.js` makes the
  // same arrangement on the main HTTPS listener, for a related reason.
  //
  // What is checked: the validity window, then that some X.509 authority this
  // service holds ISSUED and SIGNED it, then that the SPIFFE ID's trust domain
  // is the one whose authority verified it. That last check is not decoration —
  // a federated trust domain's authority verifying a certificate that claims to
  // be in OUR trust domain is precisely the cross-domain confusion a bundle is
  // meant to prevent.
  //
  // A chain longer than the leaf is NOT walked, deliberately: this CA signs
  // leaves directly, an intermediate would have to be one this service issued
  // through NewDownstreamX509CA, and pretending to build a path we do not build
  // would be reporting a check that did not happen.
  //
  // **IT IS THE ISSUING AUTHORITY HERE AND NOT THE TRUST ANCHOR, AND AFTER
  // 2026-09-11 THOSE ARE TWO DIFFERENT CERTIFICATES.** `ca.state()`'s
  // `x509Authorities` is what SIGNS an SVID — this realm's SPIFFE Issuing CA
  // under the service Root — and `trustAnchors` is what a consumer installs,
  // which is the Root. This check is a DIRECT ISSUER check, so it wants the
  // first: `checkIssued()` against the Root would be false of every SVID this
  // service has ever minted under the hierarchy, and the refusal would name the
  // certificate rather than the anchor it was compared with. The places that
  // want the anchor instead — the bundle, and the gRPC listener's client
  // truststore — say `trustAnchors` and say why.
  // ---------------------------------------------------------------------------
  authorityCertificates() {
    const { log, ca, crypto, errorCodes } = this.deps;
    log.debug('Entering SpiffeAuth.authorityCertificates().');
    const out = [];
    const state = ca.state();
    (state.x509Authorities || []).forEach(function (authority) {
      try {
        out.push({ trustDomain: ca.trustDomain(),
                   certificate: new crypto.X509Certificate(
                       authority.certificatePem) });
      } catch (e) {
        // An authority this service minted itself that will not parse is a
        // defect here rather than a caller problem, so it is logged loudly and
        // the others are still usable.
        log.error(errorCodes.tag('STS-SPIFFE-0025') +
                  'spiffe: one of this trust domain\'s own X.509 authorities ' +
                  'would not parse and cannot verify anything: ' + e.message);
      }
    });
    // THIS REALM'S federated bundles, and never one named after a trust domain
    // this service serves: `ca.federatedBundles()` drops those, because the
    // match below trusts the LABEL a bundle was stored under, and a label
    // naming a served domain would let a foreign anchor vouch for this
    // service's own identities. Until 2026-09-12 the store was process-wide and
    // that is exactly what one realm could arrange for another. See
    // spiffe_ca.ts.
    ca.federatedBundles().forEach(function (foreign) {
      if (foreign.trustDomain === ca.trustDomain()) {
        return;
      }
      ((foreign.document || {}).keys || []).forEach(function (key) {
        if (key.use !== 'x509-svid') return;
        (key.x5c || []).forEach(function (b64) {
          try {
            out.push({ trustDomain: foreign.trustDomain,
                       certificate: new crypto.X509Certificate(
                           Buffer.from(String(b64), 'base64')) });
          } catch (e) {
            // A malformed x5c in a bundle somebody pushed in. Skipped with the
            // same reasoning federatedX509BundleDer() gives: the rest of the
            // bundle is still usable, and a bad key is the pusher's problem.
            log.warn('spiffe: an x5c entry in the ' + foreign.trustDomain +
                     ' bundle would not parse and cannot verify anything: ' +
                     e.message);
          }
        });
      });
    });
    log.debug('Leaving SpiffeAuth.authorityCertificates().');
    return out;
  }

  verifyPresentedCertificate(certificate, id) {
    const { log, crypto, config, nowSec, spiffeId, revocationStatus, errorCodes,
            ca } = this.deps;
    log.debug('Entering SpiffeAuth.verifyPresentedCertificate(). id=' + id);
    let leaf;
    try {
      leaf = new crypto.X509Certificate(certificate.raw);
    } catch (e) {
      log.debug('Leaving SpiffeAuth.verifyPresentedCertificate(). It would ' +
                'not parse.');
      return { ok: false,
               reason: 'The presented certificate would not parse: ' +
                                  e.message,
               errorCode: 'STS-SPIFFE-0019' };
    }
    // The clock, with this service's configured skew. An SVID's lifetime is
    // short — an hour by default — so a client whose clock is a few minutes out
    // meets this constantly, and a refusal that does not name the skew reads as
    // a broken certificate.
    const skew = Number(config.value('spiffe.clockSkew')) || 0;
    const now = nowSec();
    const from = Math.floor(new Date(leaf.validFrom).getTime() / 1000);
    const to = Math.floor(new Date(leaf.validTo).getTime() / 1000);
    if (Number.isFinite(from) && now + skew < from) {
      log.debug('Leaving SpiffeAuth.verifyPresentedCertificate(). Not yet ' +
                'valid.');
      return { ok: false, reason: 'The presented SVID is not valid until ' +
               leaf.validFrom + ' and it is now ' + new Date().toISOString() +
               ' here (allowing ' + skew + 's of skew).',
               errorCode: 'STS-SPIFFE-0020' };
    }
    if (Number.isFinite(to) && now - skew > to) {
      log.debug('Leaving SpiffeAuth.verifyPresentedCertificate(). Expired.');
      return { ok: false,
               reason: 'The presented SVID expired at ' + leaf.validTo +
               '. SVIDs here live for ' + config.value('spiffe.svidTtl') +
               's — fetch a new one rather than reusing this.',
               errorCode: 'STS-SPIFFE-0021' };
    }
    const authorities = this.authorityCertificates();
    if (!authorities.length) {
      log.debug('Leaving SpiffeAuth.verifyPresentedCertificate(). No ' +
                'authorities.');
      return { ok: false, reason: 'This service holds no X.509 authority to ' +
               'verify an SVID against, which is a fault here rather than a ' +
               'problem with your certificate. See GET /spiffe.',
               errorCode: 'STS-SPIFFE-0022' };
    }
    for (let i = 0; i < authorities.length; i++) {
      const authority = authorities[i];
      let signed = false;
      try {
        signed = leaf.checkIssued(authority.certificate) &&
                 leaf.verify(authority.certificate.publicKey);
      } catch (e) {
        log.debug("Caught in SpiffeAuth.verifyPresentedCertificate(): " +
                  ((e && e.message) || e));
        // `verify` throws rather than returning false for a key of the wrong
        // type, which is the ordinary case when the bundle holds both an EC and
        // an RSA authority. Not an error: it means this one did not sign it.
        signed = false;
      }
      if (!signed) continue;
      const claimed = spiffeId.trustDomainOf(id);
      if (claimed !== authority.trustDomain) {
        log.debug('Leaving SpiffeAuth.verifyPresentedCertificate(). Trust ' +
                  'domain mismatch.');
        return { ok: false, reason: 'The certificate says it is ' + id +
                 ', but the authority that signed it belongs to the trust ' +
                 'domain ' + authority.trustDomain + '. A bundle verifies ' +
                 'identities in ITS OWN trust domain and nowhere else; ' +
                 'accepting this would be exactly the cross-domain confusion ' +
                 'federation exists to prevent.',
                 errorCode: 'STS-SPIFFE-0023' };
      }
      // -------------------------------------------------------------------
      // AND IT MAY NOT BE REVOKED (2026-09-12). An SVID this realm's SPIFFE
      // Issuing CA signed is looked up in the register, and so is every tier
      // above it this service holds — so revoking the Issuing CA or the realm's
      // Intermediate on /admin/pki refuses every SVID under it at this door.
      //
      // **THE REGISTER ONLY, AND NEVER A FETCH, WHATEVER THE POLICY.** This
      // runs synchronously inside a gRPC handler, and the X509-SVID
      // specification defines no revocation for a FEDERATED identity at all: a
      // trust domain stops vouching for a key by taking it out of its bundle,
      // which is the mechanism `authorityCertificates()` above already honours.
      // So a federated SVID is answered `not-consulted` and never refused on
      // it.
      // -------------------------------------------------------------------
      const revocation = revocationStatus.localVerdictFor({
        leaf: leaf, chain: [], verified: true
      });
      if (revocation.refused) {
        log.debug('Leaving SpiffeAuth.verifyPresentedCertificate(). Refused ' +
                  'on revocation.');
        return { ok: false,
                 reason: 'The presented SVID was signed by ' +
                         authority.trustDomain + '\'s authority and was ' +
                         'REFUSED ON REVOCATION (pki.revocationCheck ' +
                         'is ' + revocation.policy +
                         '): ' + revocation.why,
                 errorCode: errorCodes.codeOf(revocation) || 'STS-PKI-0118' };
      }
      log.debug('Leaving SpiffeAuth.verifyPresentedCertificate(). Verified ' +
                'against ' +
                authority.trustDomain + '.');
      return { ok: true, trustDomain: authority.trustDomain,
               revocation: revocation };
    }
    log.debug('Leaving SpiffeAuth.verifyPresentedCertificate(). Nothing ' +
              'signed it.');
    return { ok: false,
             reason: 'No X.509 authority this service holds signed ' +
             'that certificate — neither this trust domain\'s (' +
             ca.trustDomain() +
             ') nor any federated one. It is a certificate ' +
             'from somewhere else, or from a previous run: the authorities ' +
             'here are generated at startup and do not survive a restart.',
             errorCode: 'STS-SPIFFE-0024' };
  }

  // ---------------------------------------------------------------------------
  // CLASSIFYING A VERIFIED IDENTITY.
  //
  // Read from the registry on every call and never cached, which is the same
  // rule `applications.js` follows about its entries and for the same reason:
  // an
  // `ldapmodify` of `spiffeAdmin` on an entry under ou=spiffe changes what that
  // caller may do on the NEXT call, and a cache added for speed would quietly
  // undo it.
  // ---------------------------------------------------------------------------
  classify(id) {
    const { log, registry, spiffeId } = this.deps;
    log.debug('Entering SpiffeAuth.classify(). id=' + id);
    const entities = { local: false, agent: false, admin: false,
                       downstream: false };
    const notes = [];
    if (!id) {
      log.debug('Leaving SpiffeAuth.classify(). No identity.');
      return { entities: entities, notes: notes };
    }
    if (this.adminIds().indexOf(id) >= 0) {
      entities.admin = true;
      notes.push('named in spiffe.adminIds');
    }
    // The entries for this identity. An entry marked admin or downstream is
    // what an operator sets from /admin/spiffe/entries, and SPIRE reads both
    // flags the same way. Note that this is the first thing in this service
    // that READS those flags — they have been recorded and reported since the
    // registry was written, and the header of spiffe_api.ts used to say nothing
    // read them.
    registry.entriesForSpiffeId(id).forEach(function (entry) {
      if (entry.expired) return;
      if (entry.admin) {
        entities.admin = true;
        notes.push('registration entry ' + entry.id + ' is marked admin');
      }
      if (entry.downstream) {
        entities.downstream = true;
        notes.push('registration entry ' + entry.id + ' is marked downstream');
      }
    });
    if (spiffeId.isAgentId(id)) {
      const agent = registry.agentById(id);
      if (!agent) {
        notes.push('the id is agent-shaped but no agent by that name has ' +
                   'attested here');
      } else if (agent.banned) {
        // Not an agent for authorization purposes, and the note says so rather
        // than leaving a refusal that reads as "you are not an agent".
        notes.push('that agent is BANNED on this server');
      } else {
        entities.agent = true;
        notes.push('attested agent, last seen ' +
                   (agent.attestedAt || 'unknown'));
      }
    }
    log.debug('Leaving SpiffeAuth.classify(). ' + JSON.stringify(entities));
    return { entities: entities, notes: notes };
  }

  // ---------------------------------------------------------------------------
  // THE CALLER. One object, built once per call, carried through the wrappers.
  //
  // Built for BOTH surfaces even though only one authorizes on it, because the
  // Workload API needs the transport and the endpoint to derive its selectors
  // and because `/admin/spiffe` reports the same shape for both.
  // ---------------------------------------------------------------------------
  callerOf(call, surface): Record<string, any> {
    const { log, tls } = this.deps;
    log.debug('Entering SpiffeAuth.callerOf(). surface=' + surface);
    const transport = this.transportOf(call);
    const caller: Record<string, any> = {
      surface: surface,
      transport: transport,
      peer: this.peerOf(call),
      spiffeId: '',
      authenticated: false,
      entities: { local: false, agent: false, admin: false, downstream: false },
      notes: [],
      certificate: null,
      refusal: ''
    };
    // The local entity. It is a property of the TRANSPORT and not of a
    // credential, which is why it is set before anything is read off a
    // certificate: a caller on the socket is local whether or not it also
    // presented an SVID, exactly as `spire-server` is.
    // ON THE SPIRE SERVER API ONLY is the boundary verified (#104): the
    // Workload API authorizes nobody, so `local` decides nothing there and is
    // left as the setting says.
    if (transport === 'uds' && surface !== 'server') {
      caller.entities.local = this.trustLocalSocket();
      caller.notes.push('arrived on the Workload API\'s Unix domain socket');
    } else if (transport === 'uds') {
      const trust = this.localTrust(call);
      caller.entities.local = trust.local;
      caller.notes.push(trust.why);
      if (trust.errorCode) {
        // The condition, for the refusal this caller may meet in
        // `authorize()`: it is what has to be fixed, not "nothing was
        // presented".
        caller.localRefusal = trust.why;
        caller.localRefusalCode = trust.errorCode;
      }
    }
    const certificate = this.peerCertificateOf(call);
    if (!certificate) {
      log.debug('Leaving SpiffeAuth.callerOf(). No certificate was presented.');
      return caller;
    }
    // ---------------------------------------------------------------------
    // `subject` AND `issuer` ARE OBJECTS WITH A NULL PROTOTYPE, and that cost a
    // debugging session. Node builds a `PeerCertificate`'s name fields with
    // `Object.create(null)`, so `String(cert.subject)` does not produce
    // "[object Object]" — it THROWS `Cannot convert object to primitive value`,
    // inside a gRPC handler, where it surfaces to the client as a generic
    // "server method handler threw error" naming neither the field nor this
    // file. `dnRfc4514()` renders them properly and is the same function
    // `tls_server.js` and `scim_auth.js` use.
    // ---------------------------------------------------------------------
    caller.certificate = {
      subject: tls.dnRfc4514(certificate.subject),
      issuer: tls.dnRfc4514(certificate.issuer),
      serialNumber: String(certificate.serialNumber || ''),
      validFrom: String(certificate.valid_from || ''),
      validTo: String(certificate.valid_to || ''),
      // The DER thumbprint, so that a page and a log line naming "the same
      // certificate" mean the same thing. Node hands `fingerprint256` back
      // colon-separated and upper case, which is a different string from every
      // other thumbprint in this service; it is left as node produced it and
      // named for what it is rather than being converted into a fourth
      // spelling.
      fingerprintSha256: String(certificate.fingerprint256 || '')
    };
    const identity = this.spiffeIdFromCertificate(certificate);
    if (!identity.ok) {
      caller.refusal = identity.reason;
      caller.refusalCode = identity.errorCode;
      caller.notes.push(identity.reason);
      log.debug('Leaving SpiffeAuth.callerOf(). The certificate names no ' +
                'SPIFFE ID.');
      return caller;
    }
    const verified = this.verifyPresentedCertificate(certificate, identity.id);
    if (!verified.ok) {
      caller.refusal = verified.reason;
      caller.refusalCode = verified.errorCode;
      caller.notes.push(verified.reason);
      // The id is recorded even though the certificate did not verify, because
      // a refusal naming the identity somebody CLAIMED is the one a client
      // author can act on. Nothing downstream reads it — `authenticated` is
      // false.
      caller.claimedSpiffeId = identity.id;
      log.debug('Leaving SpiffeAuth.callerOf(). The certificate did not ' +
                'verify.');
      return caller;
    }
    caller.spiffeId = identity.id;
    caller.authenticated = true;
    caller.trustDomain = verified.trustDomain;
    const classified = this.classify(identity.id);
    Object.keys(classified.entities).forEach(function (key) {
      if (classified.entities[key]) caller.entities[key] = true;
    });
    caller.notes = caller.notes.concat(classified.notes);
    log.debug('Leaving SpiffeAuth.callerOf(). ' + identity.id + ' verified.');
    return caller;
  }

  // A one-line description, used in refusals, in the audit row and on the
  // pages. One function so that three surfaces cannot describe the same caller
  // three ways.
  describeCaller(caller) {
    const { log } = this.deps;
    log.debug("Entering SpiffeAuth.describeCaller().");
    if (!caller) {
      log.debug("Leaving SpiffeAuth.describeCaller().");
      return 'an unknown caller';
    }
    const held =
        ENTITY_ORDER.filter(function (id) { return caller.entities[id]; });
    const who = caller.authenticated ? caller.spiffeId
      : (caller.claimedSpiffeId ? 'an unverified ' + caller.claimedSpiffeId
                                : 'an anonymous caller');
    log.debug("Leaving SpiffeAuth.describeCaller().");
    return who + ' over ' +
           (caller.transport === 'uds' ? 'the Unix socket' : 'TCP') +
           (held.length ? ' (' + held.join(', ') + ')' : ' (no entity)');
  }

  // ---------------------------------------------------------------------------
  // THE DECISION. Returns null to allow, or a descriptor to refuse.
  //
  // It never builds a gRPC error — see the header. `status` is the NAME of a
  // grpc-js status and `spiffe_grpc.ts` maps it, so this module needs no
  // require into the transport and cannot join a cycle with it.
  // ---------------------------------------------------------------------------
  authorize(caller, method) {
    const { log, errorCodes } = this.deps;
    log.debug('Entering SpiffeAuth.authorize(). method=' + method);
    if (!this.authRequired()) {
      log.debug('Leaving SpiffeAuth.authorize(). Authentication is off. ' +
                'UNREACHABLE since ' +
                '2026-09-06: mode.gatesSpireServerApi() is unconditional.');
      return null;
    }
    const row = POLICY[method];
    if (!row) {
      // See the note on POLICY: no row means refuse. It is a defect in this
      // service rather than in the call, so it is logged as one and the message
      // says so — a client author must not spend an afternoon on it.
      log.error(errorCodes.tag('STS-SPIFFE-0013') +
                'spiffe: ' + method +
                ' has no row in spiffe_auth.js\'s POLICY ' +
                'table, so it is refused. That is a defect in this service: ' +
                'every method needs a row, copied from SPIRE\'s ' +
                'policy_data.json.');
      log.debug('Leaving SpiffeAuth.authorize(). No policy row.');
      return { status: 'PERMISSION_DENIED', errorCode: 'STS-SPIFFE-0013',
               message: method +
                        ' has no authorization rule in this service, so it ' +
                        'is refused rather than allowed. That is a bug here ' +
                        'rather than a problem with your call — please ' +
                        'report it.' };
    }
    if (row.any) {
      log.debug('Leaving SpiffeAuth.authorize(). The method is open.');
      return null;
    }
    const allowed = ENTITY_ORDER.filter(function (id) { return row[id]; });
    for (let i = 0; i < allowed.length; i++) {
      if (caller.entities[allowed[i]]) {
        log.debug('Leaving SpiffeAuth.authorize(). Allowed as ' + allowed[i] +
                  '.');
        return null;
      }
    }
    // UNAUTHENTICATED when nothing was presented, PERMISSION_DENIED when
    // something was and it is not enough. The two are genuinely different
    // instructions to a client — "authenticate" and "you may not" — and SPIRE
    // distinguishes them; collapsing them sends a client that needs a
    // credential off to look for a permission it will never get.
    const nothingPresented = !caller.authenticated && !caller.certificate &&
                             !caller.entities.local;
    const reason = method + ' is allowed to: ' + allowed.join(', ') +
      '. This call came from ' + this.describeCaller(caller) + '.' +
      (caller.refusal ? ' The certificate presented was not accepted: ' +
                        caller.refusal : '') +
      (caller.localRefusal ? ' The caller ' + caller.localRefusal + '.' : '') +
      ' The rule is SPIRE\'s own — see GET /spiffe for the whole table.';
    log.debug('Leaving SpiffeAuth.authorize(). Refused.');
    return { status: nothingPresented ? 'UNAUTHENTICATED' : 'PERMISSION_DENIED',
             // WHICH CONDITION: the certificate's own refusal where one was
             // presented and not accepted, since that is what actually has to
             // be fixed; otherwise nothing presented, or not enough.
             errorCode: caller.refusalCode || caller.localRefusalCode ||
               (nothingPresented ? 'STS-SPIFFE-0014' : 'STS-SPIFFE-0015'),
             message: reason };
  }

  // ---------------------------------------------------------------------------
  // RECORDING THE IDENTITY — the second half of what this file is for.
  //
  // A credential that was PRESENTED AND ACCEPTED reaches
  // `stats.recordAuthentication()`, which is the single funnel every one of the
  // fifteen other families passes through, and the directory's observer creates
  // or REUSES one entry for it. So an SVID presented here puts its holder on
  // /admin/users beside everybody else, and a second presentation of the same
  // identity lands on the same entry rather than a new one.
  //
  // **ONCE PER CONNECTION, NOT ONCE PER CALL.** The credential is the client
  // certificate and it was accepted at the TLS handshake; a caller that then
  // makes six RPCs on that connection has authenticated once. That is the same
  // decision `tls_server.js` makes deliberately about client certificates (it
  // records on `secureConnection`), and counting per call would undo it from
  // the other end. The key is the
  // certificate's thumbprint and the peer address together — a TCP peer's
  // ephemeral port differs per connection, so the pair is a connection.
  //
  // Bounded, like everything else held here, and FIFO: forgetting the oldest
  // costs one duplicate row on a long-lived connection, where forgetting
  // nothing is a map that grows for the life of the process.
  // ---------------------------------------------------------------------------
  // `spiffe.maxRecordedConnections` since 2026-09-12; 512 was the constant and
  // is its default. Read per call. `perProcess` in config.js, and that is still
  // right with the store below partitioned: the cap is the same number in every
  // realm's partition, and a realm resizing it would be one realm deciding how
  // much every other realm's register remembers. The floor is 1: a cap of 0
  // would record every connection as new on every call, which is the per-call
  // counting this map exists to undo.
  maxRecordedConnections() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeAuth.maxRecordedConnections().");
    log.debug("Leaving SpiffeAuth.maxRecordedConnections().");
    return config.value('spiffe.maxRecordedConnections');
  }

  alreadyRecorded(key) {
    const { log, nowSec } = this.deps;
    log.debug("Entering SpiffeAuth.alreadyRecorded().");
    if (!key) {
      log.debug("Leaving SpiffeAuth.alreadyRecorded().");
      return false;
    }
    if (recordedConnections.has(key)) {
      log.debug("Leaving SpiffeAuth.alreadyRecorded().");
      return true;
    }
    recordedConnections.set(key, nowSec());
    // A `while` rather than an `if`, because the cap is runtime-settable:
    // lowered by more than one, a single eviction would leave the map above it
    // for ever.
    const cap = this.maxRecordedConnections();
    while (recordedConnections.size > cap) {
      const oldest = recordedConnections.keys().next().value;
      recordedConnections.delete(oldest);
    }
    log.debug("Leaving SpiffeAuth.alreadyRecorded().");
    return false;
  }

  // The one recording function every accepted SPIFFE credential goes through.
  // `detail.method` is what was accepted — "X509-SVID (mTLS)", "join token" —
  // and it is what shows on /admin/users, so it is written the way a person
  // would read it rather than as a code.
  recordIdentity(detail) {
    const { log, stats, errorCodes } = this.deps;
    log.debug('Entering SpiffeAuth.recordIdentity(). presented=' +
              (detail || {}).presented);
    const info = detail || {};
    if (!info.presented) {
      log.debug('Leaving SpiffeAuth.recordIdentity(). Nothing to record.');
      return;
    }
    if (info.once && this.alreadyRecorded(info.once)) {
      log.debug('Leaving SpiffeAuth.recordIdentity(). Already recorded for ' +
                'this connection.');
      return;
    }
    try {
      stats.recordAuthentication({
        presented: info.presented,
        protocol: info.protocol || 'SPIFFE',
        method: info.method || 'unstated',
        note: info.note || ''
      });
    } catch (e) {
      // Recording an authentication must never be able to fail one — the rule
      // the observer in ldap_server.js already follows, applied at the caller
      // as well because this one runs inside a gRPC handler where a throw
      // becomes an Unknown status on a call that actually succeeded.
      log.error(errorCodes.tag('STS-SPIFFE-0026') +
                'spiffe: recording an accepted credential threw and was ' +
                'ignored: ' + e.message);
    }
    log.debug('Leaving SpiffeAuth.recordIdentity().');
  }

  // The Server API's own recording, called from the wrappers once a caller has
  // been built. Only an ACCEPTED credential is recorded: a certificate that did
  // not verify is a refusal and belongs in the audit log rather than on
  // /admin/users, which answers "who has authenticated here".
  recordCaller(caller) {
    const { log } = this.deps;
    log.debug("Entering SpiffeAuth.recordCaller().");
    if (!caller || !caller.authenticated || !caller.spiffeId) {
      log.debug("Leaving SpiffeAuth.recordCaller().");
      return;
    }
    const once = (caller.certificate ? caller.certificate.fingerprintSha256 :
                  '') +
                 '|' + caller.peer;
    this.recordIdentity({
      presented: caller.spiffeId,
      protocol: 'SPIFFE',
      method: 'X509-SVID (mTLS)',
      note: this.describeCaller(caller),
      once: once
    });
    log.debug("Leaving SpiffeAuth.recordCaller().");
  }

  // ---------------------------------------------------------------------------
  // WHAT THE WORKLOAD API CAN SEE ABOUT ITS CALLER.
  //
  // The selector list. See the header for why these are spelt `transport:`,
  // `endpoint:` and `peer:` rather than `unix:` and `k8s:`, and why an asserted
  // selector is passed through verbatim while an observed one is not.
  // ---------------------------------------------------------------------------
  assertedSelectorsOf(call) {
    const { log, registry } = this.deps;
    log.debug('Entering SpiffeAuth.assertedSelectorsOf().');
    const out = [];
    if (!this.acceptAssertedSelectors()) {
      log.debug('Leaving SpiffeAuth.assertedSelectorsOf().');
      return out;
    }
    let values = [];
    try {
      values = (call && call.metadata &&
                call.metadata.get(ASSERTED_SELECTOR_KEY)) || [];
    } catch (e) {
      // A call whose metadata is gone. Nothing to read and nothing to report.
      log.debug('assertedSelectorsOf(): the metadata was not readable (' +
                e.message + ').');
      log.debug('Leaving SpiffeAuth.assertedSelectorsOf().');
      return out;
    }
    values.forEach(function (value) {
      // One header may carry several, comma-separated, because a client library
      // that folds repeated metadata keys into one value is ordinary and a
      // caller should not have to know which kind it has.
      String(value).split(',').forEach(function (text) {
        const selector = registry.parseSelector(text);
        if (selector) out.push(selector);
        else if (String(text).trim()) {
          log.warn('spiffe: a caller asserted the selector "' +
                   String(text).trim() +
                   '", which is not `type:value` and was ignored.');
        }
      });
    });
    log.debug('Leaving SpiffeAuth.assertedSelectorsOf().');
    return out;
  }

  // The address the caller reached, derived from configuration rather than from
  // the call. grpc-js tells a handler about the PEER and not about the local
  // end, and there is exactly one Workload API socket and one Workload API port
  // per realm — read here in the ambient realm the listener entered — so the
  // transport settles which of the two it was. Deriving it beats reading it:
  // there is nothing to read.
  endpointFor(surface, transport) {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeAuth.endpointFor().");
    if (surface === 'workload') {
      log.debug("Leaving SpiffeAuth.endpointFor().");
      return transport === 'uds'
        ? String(config.value('spiffe.workloadSocket') || '')
        : String(config.value('spiffe.grpcHost') || '') + ':' +
          String(config.value('spiffe.workloadPort') || '');
    }
    log.debug("Leaving SpiffeAuth.endpointFor().");
    return transport === 'uds'
      ? String(config.value('spiffe.serverSocket') || '')
      : String(config.value('spiffe.grpcHost') || '') + ':' +
        String(config.value('spiffe.serverPort') || '');
  }

  // The peer as a SELECTOR value, which is not the same string as the peer on
  // the page. grpc-js builds `address:port` and the port is EPHEMERAL — a new
  // one per connection — so a selector carrying it could never be written into
  // a registration entry that matches twice. The address alone is the stable,
  // matchable fact; the whole peer stays on the caller object, in the log and
  // in the audit row, where a reader wants the connection and not the rule.
  peerSelectorValue(peer) {
    const { log } = this.deps;
    log.debug("Entering SpiffeAuth.peerSelectorValue().");
    log.debug("Leaving SpiffeAuth.peerSelectorValue().");
    return String(peer || '').replace(/:\d+$/, '');
  }

  workloadSelectors(call, caller, endpoint?) {
    const { log, registry } = this.deps;
    log.debug('Entering SpiffeAuth.workloadSelectors().');
    const where = endpoint || this.endpointFor('workload', caller.transport);
    const out = [{ type: 'transport',
                   value: caller.transport === 'uds' ? 'uds' : 'tcp' }];
    if (where) out.push({ type: 'endpoint', value: where });
    // A `peer:` is a TCP address. A Unix connection's peer string is the
    // attested socket's per-connection tag, which no entry could select on.
    const address = caller.transport === 'uds' ? ''
      : this.peerSelectorValue(caller.peer);
    if (address) out.push({ type: 'peer', value: address });
    // THE ATTESTED SELECTORS (#40 phase four): what the workload attestors
    // established from the kernel at accept — `unix:uid:1000` read, not
    // written — revalidated for this call by `spiffe_grpc.prepareCall()`.
    ((caller.attested && caller.attested.selectors) || [])
      .forEach(function (selector) {
        out.push({ type: selector.type, value: selector.value });
      });
    const asserted = this.assertedSelectorsOf(call);
    if (asserted.length) {
      log.info('spiffe: a Workload API caller asserted ' + asserted.length +
               ' selector(s) — ' +
               asserted.map(registry.selectorText).join(' ') +
               '. NOTHING VERIFIED THEM; this is ' +
               'spiffe.acceptAssertedSelectors, which exists so that ' +
               'selector matching can be exercised at all.');
    }
    const all = out.concat(asserted);
    log.debug('Leaving SpiffeAuth.workloadSelectors(). ' + all.length +
              ' selector(s).');
    return all;
  }

  // ---------------------------------------------------------------------------
  // WHAT THE PAGES DRAW. One shape, read by `GET /spiffe`, by `/admin/spiffe`
  // and by the management API, so that three surfaces cannot disagree about
  // what is enforced.
  // ---------------------------------------------------------------------------
  state() {
    const { log } = this.deps;
    log.debug("Entering SpiffeAuth.state().");
    log.debug("Leaving SpiffeAuth.state().");
    return {
      // The prose lives HERE and not on the pages, for the reason the two
      // discovery documents are built from one object: `GET /spiffe`,
      // `/admin/spiffe` and the management API all draw this, and three
      // explanations of one mechanism is two that will eventually be wrong.
      what: 'The SPIRE Server API only. Its TCP port is mutual TLS: a caller ' +
            'presents an X509-SVID from this trust domain, this service ' +
            'verifies it against the trust bundle and against the ' +
            'certificate\'s own validity window, takes the SPIFFE ID from ' +
            'the URI subjectAltName (never from the subject), classifies it ' +
            'as local, agent, admin or downstream, and authorizes the method ' +
            'against SPIRE\'s own policy_data.json, row for row. Its Unix ' +
            'socket is the `local` entity and needs no credential, which is ' +
            'how the spire-server CLI reaches a real server. The Workload ' +
            'API is deliberately untouched by all of it: its specification ' +
            'says a client MUST NOT be required to authenticate.',
      bootstrapping:
        'The TCP port asks for a client certificate and does NOT ' +
            'require one, because AttestAgent is open to a caller with no ' +
            'SVID — an agent has none until that call gives it one. Fetch ' +
            'the bundle from the bundle endpoint, verify this server against ' +
            'it, and attest.',
      identityNote: 'An accepted credential is an IDENTITY here like any ' +
            'other: it reaches the same funnel every one of the sixteen ' +
            'protocol families uses, so its holder appears on /admin/users ' +
            'and gets a directory entry under ou=users — named by a digest, ' +
            'with the identifier on it as `spiffeSubject`, and REUSED when ' +
            'the same identity arrives again by another route. Three ' +
            'acceptances do that: an X509-SVID over mutual TLS (once per ' +
            'connection), an agent attesting, and a JWT-SVID verified at ' +
            'ValidateJWTSVID. AN ISSUANCE IS A FOURTH WAY IN and is not one ' +
            'of those three: every identity this trust domain mints an ' +
            'X509-SVID for gets the same entry, carrying the certificate as ' +
            'the same six `x509*` attributes a verified TLS client ' +
            'certificate writes — ASSIGNED rather than appended, because an ' +
            'SVID is minted afresh every half-lifetime, with ' +
            '`x509svidsIssued` and two timestamps beside them. It ' +
            'is not counted as an authentication, because being ' +
            'issued a credential is not presenting one.',
      credentialStatusNote: 'The entry also records whether the identity may ' +
            'still be issued a credential HERE — `spiffeCredentialStatus`, ' +
            'with a reason beside it. THAT IS NOT A CERTIFICATE STATUS AND ' +
            'NOTHING READS IT BACK: SPIFFE has no revocation, and an SVID ' +
            'already issued verifies against the bundle until it expires ' +
            'whatever the directory says. What it records is the three ' +
            'things that end an identity\'s ability to get a NEW one — its ' +
            'last registration entry deleted, its agent banned, its agent ' +
            'deleted — each of which is reversible and recorded the same way ' +
            'when it is reversed. The entry is never removed.',
      enforced: this.authRequired(),
      trustLocalSocket: this.trustLocalSocket(),
      adminIds: this.adminIds(),
      attestWorkloads: this.attestWorkloads(),
      acceptAssertedSelectors: this.acceptAssertedSelectors(),
      assertedSelectorHeader: ASSERTED_SELECTOR_KEY,
      entities: ENTITIES.map(function (entity) {
        return { id: entity.id, label: entity.label, what: entity.what };
      }),
      policy: Object.keys(POLICY).sort().map(function (method) {
        const row = POLICY[method];
        return {
          method: method,
          allow: row.any ? ['any']
            : ENTITY_ORDER.filter(function (id) { return row[id]; })
        };
      })
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SpiffeAuth>(
  'spiffe/spiffe_auth',
  () => new SpiffeAuth(SpiffeAuth.defaultDeps()),
  null,
  helpers.log);

// The metadata key an asserted selector arrives under. Deliberately NOT one any
// specification names, and deliberately ugly: a client author who copies it
// into production code should be able to see from the spelling alone that it is
// this service's own affordance and not part of the Workload API.
const ASSERTED_SELECTOR_KEY = 'x-sts-workload-selector';
// -------------------------------------------------------------------------
// PER TRUST REALM SINCE 2026-09-12, AND IT WAS `sharedMap()` WITH
// `scope: 'shared'` UNTIL THEN.
//
// That was right while the SPIRE Server API had one pair of sockets for the
// whole process. It has a pair PER REALM since the same day (see
// `spiffe/CLAUDE.md`), and a connection belongs to exactly one of them — so a
// process-wide register let one realm's connections evict another's from the
// cap (a duplicate authentication row in the realm that lost) and put every
// realm's connection keys in one row set.
//
// **HOW THE REALM IS KNOWN FOR A gRPC CONNECTION**, which is the question an
// HTTP-shaped answer gets wrong: not from a path — gRPC's path is the method
// name — and not from anything the caller sends. It is the LISTENER the
// connection was accepted on. `spiffe_server.ts`'s `handlersInRealm()` enters
// that listener's realm with `realms.run()` around every handler it registers,
// the default realm's four sockets included, and `recordCaller()` runs inside
// `spiffe_grpc.ts`'s `prepareCall()`, which is inside that handler — so the
// ambient realm HERE is the realm whose socket the call arrived on, and the
// partition `realms.map()` picks is that realm's. It never reaches a request
// worker: `prepareCall()` stays in the front process, which holds the socket.
//
// A connection key (certificate thumbprint and peer address) cannot occur on
// two realms' listeners at once, because a peer's ephemeral port is one
// connection to one socket — so no entry is split and no answer changes; what
// changes is whose cap it counts against and which realm a restore puts it in.
// -------------------------------------------------------------------------
const recordedConnections =
    realms.map({ persist: 'spiffe.recordedConnections', retain: 'age' });

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  SpiffeAuth: SpiffeAuth,
  installInstance: (instance: SpiffeAuth): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ENTITIES: ENTITIES,
  POLICY: POLICY,
  ASSERTED_SELECTOR_KEY: ASSERTED_SELECTOR_KEY,
  authRequired: slot.forward('authRequired'),
  trustLocalSocket: slot.forward('trustLocalSocket'),
  attestWorkloads: slot.forward('attestWorkloads'),
  acceptAssertedSelectors: slot.forward('acceptAssertedSelectors'),
  adminIds: slot.forward('adminIds'),
  parseBrokers: slot.forward('parseBrokers'),
  serializeBrokers: slot.forward('serializeBrokers'),
  brokers: slot.forward('brokers'),
  brokerOf: slot.forward('brokerOf'),
  transportOf: slot.forward('transportOf'),
  callerOf: slot.forward('callerOf'),
  describeCaller: slot.forward('describeCaller'),
  authorize: slot.forward('authorize'),
  recordIdentity: slot.forward('recordIdentity'),
  recordCaller: slot.forward('recordCaller'),
  workloadSelectors: slot.forward('workloadSelectors'),
  workloadTcpPosture: slot.forward('workloadTcpPosture'),
  endpointFor: slot.forward('endpointFor'),
  peerSelectorValue: slot.forward('peerSelectorValue'),
  spiffeIdFromCertificate: slot.forward('spiffeIdFromCertificate'),
  verifyPresentedCertificate: slot.forward('verifyPresentedCertificate'),
  state: slot.forward('state')
};
