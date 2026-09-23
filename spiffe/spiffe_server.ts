'use strict';
//
// File: spiffe_server.ts
//
// ---------------------------------------------------------------------------
// THE FIRST OF THE THREE SERVER-SIDE SPIFFE SURFACES — the BUNDLE ENDPOINT,
// which is plain HTTPS and needs no gRPC at all — plus the page that explains
// all three, plus the `listen()` that starts the gRPC listeners the other two
// surfaces live on — four per realm that has SPIFFE turned on.
//
// It is the module `common/protocol_stack.ts` requires for this family, and it
// is the SPIFFE analogue of `ldap_server.js`: its HTTP views are registered
// by its exported `registerRoutes(app)`, which that file calls (rule 1; #50,
// R1) where `ldap_server.js` still registers its own at require time; and
// its **own listeners are started from `listen()` in `server.js`, not at
// require time**. That is the rule every socket owner
// carries (`tls_server.js` did too, until its listeners were deleted on
// 2026-09-16) and the reason is the same — binding a port can fail, and a
// `require` that throws takes the whole service down where a route cannot. A
// failure to bind is RECORDED rather than thrown, and published on
// `GET /spiffe`, because the HTTP view answers 200 either way and there is
// otherwise no way to tell a running listener from one whose port was already
// taken.
//
// ---------------------------------------------------------------------------
// THE BUNDLE ENDPOINT IS THE SURFACE WITH NO MOVING PARTS
//
// It is one GET returning a JWK Set with two extra members. That is the whole
// of the SPIFFE federation protocol's server side: a foreign trust domain is
// configured with this URL, polls it, and trusts what it finds according to one
// of two profiles —
//
//   `https_web`     the URL is verified with the WEB PKI, the way a browser
//                   would. Which means it is only as good as the certificate
//                   this service is reached over, and this service's
//                   certificate is issued by its own Root (or supplied), not
//                   by anything in the Web PKI.
//   `https_spiffe`  the URL is verified with a SPIFFE ID and an already-known
//                   bundle. The chicken-and-egg is solved by the first bundle
//                   being configured out of band.
//
// **This service publishes its bundle over whichever scheme the main port is
// on**, which is http by default and https when `global.https` is set. A real
// federation partner will refuse a plain-http bundle endpoint, and that is
// correct of it: the bundle is the root of trust for a whole trust domain, and
// fetching it over a channel anybody can rewrite means trusting whoever is in
// the middle. Said on the page rather than left to be met as a refusal.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SpiffeServer` takes the modules it uses through its constructor
// (`SpiffeServerDeps`), and since #50's R2 the composition root builds the
// instance and installs it here. The module still exports its old names as
// FACADES forwarding to it, for the callers that are not converted; a process
// without the root builds a default when this module loads. `SpiffeServer` is
// exported for the root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the module
// exports and `common/protocol_stack.ts` calls (#50, R1) at the point in the
// route order where requiring this module used to register them, so rule 1's
// order is unchanged. Requiring the module registers nothing.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log, xmlEscape, baseUrlOf } = helpers;
import config = require('../common/config');
// The realm registry, for the per-realm listeners below. A LIBRARY (rule 3)
// and loaded by `app.js` long before this module, so requiring it here
// registers nothing and cannot move a route.
import realms = require('../common/realms');
import audit = require('../common/audit');
// A LEAF. The bundle endpoint's refusals are marked on the response for the
// call log; a listener that could not come up is tagged on its log line.
import errorCodes = require('../common/error_codes');
import spiffeId = require('./spiffe_id');
import ca = require('./spiffe_ca');
import registry = require('./spiffe_registry');
import rpc = require('./spiffe_grpc');
import workload = require('./spiffe_workload');
import serverApi = require('./spiffe_api');
// What is enforced, for the page and for the decision above about which
// socket gets TLS. A library that registers nothing.
import auth = require('./spiffe_auth');
// For `onServerCertificateChange()` (2026-09-21). Already loaded by
// `spiffe_auth.ts` just above, which is where it is first required and its
// routes register, so this adds a cache hit and moves nothing.
import tlsServer = require('../tls/tls_server');
// For `scopeChainsToRoot()`, in `refreshServerCredentials()`. A library,
// loaded long before this module; it registers nothing.
import pki = require('../common/pki');
// Workload attestation (#40 phase four): the kernel's facts about a caller,
// and the attestors that turn them into selectors. LIBRARIES.
import peer = require('./spiffe_peer');
import workloadAttestation = require('./spiffe_workload_attestation');
import unixAttestor = require('./spiffe_workload_attestor_unix');
import dockerAttestor = require('./spiffe_workload_attestor_docker');
import k8sAttestor = require('./spiffe_workload_attestor_k8s');
// #170: the systemd attestor, and the docker attestor's sigstore verifier
// (with its TUF trust root, whose scheduler job registers when it loads).
// LIBRARIES; they register no route.
import systemdAttestor = require('./spiffe_workload_attestor_systemd');
import sigstore = require('./spiffe_sigstore');
// The SPIFFE Broker API's handlers (#170). A LIBRARY: `handlers()` wraps them
// for the `broker` surface and binds nothing; the listener is this module's.
import broker = require('./spiffe_broker');
import mode = require('../common/mode');
// The console, for one slot and nothing else. `admin.js` cannot require THIS
// module — `common/protocol_stack.ts` requires admin.js first, and until
// #50's R1 the require would have pulled the bundle endpoint and /spiffe into
// the express router ahead of every /admin route, and GET /admin/sts-metadata
// is built by walking that router. Requiring this module registers nothing
// now, so that half of the argument is history; the other half is not — this
// module requires admin.js (below), so a require back would close a cycle and
// hand one of the two a half-built module. So it offers a slot
// and this module fills it at require time, the same shape
// setDirectoryReader(), setGroupReader() and setScimReader() already have.
//
// What crosses is two facts about SOCKETS — which of the four bound, and where
// the bundle is — because a page cannot see a socket any other way. Requiring
// admin.js from here is safe in the direction that matters: the stack has
// already required it, so this is a cache hit, and requiring it registers no
// route in any case — the stack registers its routes, at 18 (#50, R1).
import admin = require('../admin-ui/admin');

// Read once, at require time: `registerRoutes()` registers the route with
// this value when the stack calls it at startup, which is what makes
// `spiffe.bundlePath` restart-only in config.js. `sts_metadata.js` reads
// the same setting for its row, so the description cannot name a path the
// router does not have.
const BUNDLE_PATH = config.value('spiffe.bundlePath') || '/spiffe/bundle';

// Listener state. Declared HERE, beside the other module state rather than
// beside `listen()` where it is written, because the HTTP views read it and
// they are registered above `listen()` — the same arrangement `ldap_server.js`
// uses (and `tls_server.js` did, while it owned listeners), for the same
// reason.
// ONE ENTRY PER REALM THAT HAS SPIFFE SOCKETS, keyed by realm id with the
// DEFAULT realm under the empty string — the same key every per-realm store in
// this service uses, so `''` is a realm here rather than a missing value.
const listeners = new Map();
let started = false;

// What `SpiffeServer` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface SpiffeServerDeps {
  log: typeof log;
  xmlEscape: typeof xmlEscape;
  baseUrlOf: typeof baseUrlOf;
  config: typeof config;
  realms: typeof realms;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  ca: typeof ca;
  registry: typeof registry;
  rpc: typeof rpc;
  workload: typeof workload;
  serverApi: typeof serverApi;
  auth: typeof auth;
  peer: typeof peer;
  mode: typeof mode;
  // The workload attestation table, built with its three attestors.
  buildWorkloadAttestation(): any;
}

type RouteApp = typeof app;

// The workload attestation table, built on first use by any instance.
const WORKLOAD_ATTESTATION: { table: any } = { table: null };

// The SPIFFE Broker API's handler table, built once (#170): its wrappers are
// `spiffe_grpc.ts`'s, and a realm's server takes it through
// `handlersInRealm()` like the other two surfaces.
const BROKER_HANDLERS: { table: Record<string, any> | null } = { table: null };

class SpiffeServer {
  constructor(private readonly deps: SpiffeServerDeps) {
    deps.log.debug("Entering SpiffeServer.constructor().");
    deps.log.debug("Leaving SpiffeServer.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): SpiffeServerDeps {
    helpers.log.debug("Entering SpiffeServer.defaultDeps().");
    helpers.log.debug("Leaving SpiffeServer.defaultDeps().");
    return {
      log: log,
      xmlEscape: xmlEscape,
      baseUrlOf: baseUrlOf,
      config: config,
      realms: realms,
      audit: audit,
      errorCodes: errorCodes,
      ca: ca,
      registry: registry,
      rpc: rpc,
      workload: workload,
      serverApi: serverApi,
      auth: auth,
      peer: peer,
      mode: mode,
      buildWorkloadAttestation: function () {
        const table = new workloadAttestation.WorkloadAttestation(
          workloadAttestation.WorkloadAttestation.defaultDeps());
        const info = table.containerInfo.bind(table);
        table.register(new unixAttestor.UnixWorkloadAttestor(
          unixAttestor.UnixWorkloadAttestor.defaultDeps()));
        table.register(new dockerAttestor.DockerWorkloadAttestor(
          dockerAttestor.DockerWorkloadAttestor.defaultDeps(info,
            table.cgroupPaths.bind(table), sigstore.shared)));
        table.register(new k8sAttestor.K8sWorkloadAttestor(
          k8sAttestor.K8sWorkloadAttestor.defaultDeps(info)));
        table.register(new systemdAttestor.SystemdWorkloadAttestor(
          systemdAttestor.SystemdWorkloadAttestor.defaultDeps(
            function (facts) {
              return peer.stillValid(facts);
            })));
        return table;
      }
    };
  }

  // ---------------------------------------------------------------------------
  // **WHETHER SPIFFE ANSWERS HERE, AND THE ONE THING THAT IS NOT A PLAIN
  // SETTING READ (2026-09-12).**
  //
  // For the DEFAULT realm it is `spiffe.enabled`, exactly as it has always
  // been. For every other realm it is that realm's OWN override and nothing
  // else — not the effective value, which would inherit the process's `true`.
  //
  // **THE DIFFERENCE IS NOT PEDANTRY, IT IS WHAT A REALM COSTS.** Turning
  // SPIFFE on for a realm builds that realm's authorities (a key generation
  // each) and binds two listeners. A realm created before this existed, or
  // restored from a store written by an older build, carries no override — so
  // reading the effective value would give every one of them SPIFFE on the next
  // start: a pile of key generations nobody asked for and, because they would
  // all inherit
  // `spiffe.grpcHost` of `0.0.0.0`, a pile of refused binds reported on
  // `/spiffe`. Measured on a stack whose realms a test run had left behind.
  //
  // So a realm OPTS IN. `realms.js` seeds `spiffe.enabled: false` when a realm
  // is created, which makes the state visible on `/admin/realms` and in
  // `/admin-api`; this predicate is what makes a realm that has no such row
  // behave the same way.
  // ---------------------------------------------------------------------------
  enabledIn(realm) {
    const { log, realms, config } = this.deps;
    log.debug("Entering SpiffeServer.enabledIn().");
    if (!realm || realm.id === realms.DEFAULT_ID) {
      log.debug("Leaving SpiffeServer.enabledIn().");
      return !!realms.run(realms.DEFAULT_REALM, function () {
        return config.value('spiffe.enabled');
      });
    }
    const own = (realm.overrides || {})['spiffe.enabled'];
    log.debug("Leaving SpiffeServer.enabledIn().");
    return own === true || String(own).toLowerCase() === 'true';
  }

  enabled() {
    const { log, realms } = this.deps;
    log.debug("Entering SpiffeServer.enabled().");
    log.debug("Leaving SpiffeServer.enabled().");
    return this.enabledIn(realms.current());
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS IS, FOR A PERSON — and, with ?format=json, for a program.
  //
  // The same shape `GET /admin/ldap/service` and `GET /tls` have, and it
  // carries the same kind of thing: what the surfaces are, where they are,
  // whether the sockets actually bound, and — at length — what is NOT checked.
  // That last part is most of the page on purpose. A mock that quietly issued
  // identities to anybody would teach a client author something false about
  // every SPIFFE deployment they will ever meet.
  // ---------------------------------------------------------------------------
  description(req) {
    const { log, baseUrlOf, ca, config, rpc, workload, serverApi, registry,
            auth, mode } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.description().');
    const base = baseUrlOf(req);
    const state = ca.state();
    const document = {
      what: 'A SPIFFE issuing authority: the bundle endpoint, the Workload ' +
            'API and the SPIRE Server API. The SPIRE Server API ' +
            'authenticates its caller with mutual TLS and an X509-SVID and ' +
            'authorizes every method against SPIRE\'s own table; the ' +
            'Workload API authenticates nobody, because its specification ' +
            'says it MUST NOT, and identifies a caller ' +
            'only by what this service can see of the ' +
            'connection. Nothing attests a workload or a node.',
      enabled: this.enabled(),
      trustDomain: state.trustDomain,
      trustDomainId: state.trustDomainId,
      serverId: state.serverId,
      ready: state.ready,
      error: state.error,
      bundle: {
        url: base + BUNDLE_PATH,
        sequence: state.sequence,
        refreshHint: state.refreshHint,
        profiles: {
          https_web: 'The partner verifies this URL with the Web PKI. This ' +
                     'service\'s certificate is not in it — it is either ' +
                     'self-signed or issued by a local authority — so a ' +
                     'partner using this profile has to trust it explicitly: ' +
                     'fetch it from /tls/server-certificate.',
          https_spiffe: 'The partner verifies this URL with a SPIFFE ID and ' +
                        'a bundle it already has. Supported in the sense ' +
                        'that the endpoint serves the right document; the ' +
                        'SPIFFE ID this service would ' +
                        'present on that connection is the ' +
                        'TLS certificate\'s, which is not an SVID.'
        },
        scheme: config.value('global.https') ? 'https' : 'http',
        schemeNote: config.value('global.https')
          ? 'The main port is HTTPS (global.https), so the bundle endpoint ' +
            'is too.'
          : 'THE MAIN PORT IS PLAIN HTTP, so this bundle endpoint is http. A ' +
            'real federation partner will refuse it, and is right to: the ' +
            'bundle is the root of trust for a whole trust domain, and ' +
            'fetching it over a channel anybody can rewrite means trusting ' +
            'whoever is in the middle. Set global.https to serve it over TLS.'
      },
      authorities: {
        // WHERE THE AUTHORITY CAME FROM, first, because it decides what every
        // other field here means — see `spiffe_ca.ts`'s `state()`.
        source: state.authoritySource,
        realm: state.realm,
        x509: state.x509Authorities.map(function (authority) {
          return { id: authority.id, active: authority.active,
                   source: authority.source,
                   keyType: authority.keyType, subject: authority.subject,
                   notAfter: authority.notAfter };
        }),
        // WHAT SIGNS an SVID and WHAT A CONSUMER TRUSTS are two lists now and
        // this document has to publish both: the bundle carries the second, and
        // a reader with only the first cannot tell what to install.
        trustAnchors: state.trustAnchors.map(function (anchor) {
          return { id: anchor.id, source: anchor.source,
                   subject: anchor.subject,
                   notAfter: anchor.notAfter };
        }),
        // The certificates that travel WITH an SVID, between the leaf and the
        // anchor. Empty on the self-signed path.
        chainSubjects: state.chainSubjects.slice(),
        jwt: state.jwtAuthorities.map(function (authority) {
          return { kid: authority.id, active: authority.active,
                   keyType: authority.keyType, alg: authority.alg };
        }),
        note: state.authoritySource === 'pki'
          ? 'The X.509 authority is this realm\'s SPIFFE Issuing CA under ' +
            'this service\'s own Root CA — see /admin/pki — so the trust ' +
            'anchor a consumer installs is that Root, which every realm ' +
            'shares and which also covers the main port, LDAPS 636 and every ' +
            'token this service signs. An SVID carries the Issuing CA and ' +
            'this realm\'s Intermediate in its own chain. In DEVELOPMENT ' +
            'mode the Root is generated per start like every other key here; ' +
            'in PRODUCT mode the keystore keeps it, so a bundle survives a ' +
            'restart. The JWT authority has no certificate and is generated ' +
            'per start in either mode.'
          : 'This realm has NO certificate authority, so the X.509 authority ' +
            'is SELF-SIGNED and IS the trust anchor — generated per start ' +
            'and held in memory, exactly like the STS signing key and the ' +
            'TLS certificate. A workload holding a bundle from before a ' +
            'restart will fail to verify every SVID minted after it. Build ' +
            'the realm\'s certificate authority on /admin/pki to put this ' +
            'authority under this service\'s Root instead.'
      },
      workloadApi: {
        service: 'SpiffeWorkloadAPI',
        listeners: this.bindingsNow().workload,
        securityHeader: rpc.SECURITY_HEADER + ': true',
        // As IN FORCE (#181): true in a product realm whatever is stored.
        securityHeaderRequired:
          !!mode.valueInForce('spiffe.requireSecurityHeader'),
        methods: rpc.methodsOf('workload').map(function (method) {
          const note = workload.METHOD_NOTES[self.protoNameOf(method.path)] ||
                       {};
          return { name: self.protoNameOf(method.path), path: method.path,
                   streaming: method.responseStream,
                   implemented: note.implemented !== false,
                   what: note.what || '' };
        })
      },
      serverApi: {
        listeners: this.bindingsNow().api,
        services: serverApi.SERVICE_HANDLERS.map(function (entry) {
          return {
            name: entry.label,
            what: entry.what,
            methods: rpc.methodsOf(entry.name).map(function (method) {
              const full = entry.label + '.' + self.protoNameOf(method.path);
              return { name: self.protoNameOf(method.path), path: method.path,
                       implemented: !serverApi.NOT_IMPLEMENTED[full],
                       what: serverApi.NOT_IMPLEMENTED[full] || '' };
            })
          };
        })
      },
      // THE SPIFFE BROKER API (#170).
      brokerApi: {
        service: 'spiffe.broker.API',
        specification: 'SPIFFE Broker API and SPIFFE Broker Endpoint ' +
                       '(Incubating)',
        listeners: this.bindingsNow().broker,
        securityHeader: rpc.BROKER_SECURITY_HEADER + ': true',
        brokers: auth.brokers(),
        referenceTypes: [broker.PID_REFERENCE, broker.K8S_REFERENCE],
        methods: rpc.methodsOf('broker').map(function (method) {
          return { name: self.protoNameOf(method.path), path: method.path,
                   streaming: method.responseStream };
        })
      },
      registry: {
        entries: registry.entryCount(),
        agents: registry.agentCount(),
        maxEntries: registry.maxEntries(),
        maxAgents: registry.maxAgents(),
        note: 'The store is the embedded LDAP directory. An ldapmodify under ' +
              'ou=spiffe changes what the next SVID looks like, because ' +
              'nothing caches these.'
      },
      federated: state.federated,
      // The list every reader of this page needs most, and it is deliberately
      // longer than the rest of the document.
      notChecked: [
        'A WORKLOAD API CALLER OVER TCP IS NOT ATTESTED. The Unix socket ' +
        'is (#40, 2026-09-21): the kernel names the connecting process ' +
        '(SO_PEERCRED, and a pidfd that holds it), the unix, docker ' +
        '(Docker and Podman, with a cosign image signature where asked), ' +
        'k8s and systemd workload attestors turn it into SPIRE\'s ' +
        'selectors (#170), and every call ' +
        'checks the process is still the one attested. A TCP connection has ' +
        'no peer process to ask, so its caller is identified only by the ' +
        'transport, the endpoint and its address — which is why a product ' +
        'realm does not serve TCP at all unless ' +
        'spiffe.workloadTcpSourceAuthenticated declares that the network ' +
        'authenticates source addresses (Workload Endpoint section 3), on a ' +
        'named address, and refuses a registration entry that selects ' +
        'nothing but the transport and endpoint (#166); ' +
        'workloadAttestation.tcp says which. A peer in a pid namespace ' +
        'this service cannot see is attested on its uid and gid alone. In ' +
        'development without the native module the socket is served ' +
        'unattested and workloadAttestation below says so; a product does ' +
        'not serve it at all.',
        'NO CREDENTIAL AT ALL ON THE WORKLOAD API, and that is the ' +
        'specification rather than this service being permissive. The SPIFFE ' +
        'Workload Endpoint specification says the endpoint "MUST NOT require ' +
        'any direct authentication of its clients" and that "Transport Layer ' +
        'Security MUST NOT be required" — a workload has no root of trust ' +
        'until this call gives it one. So the mutual TLS the SPIRE Server ' +
        'API requires deliberately does not reach this surface, and no mode ' +
        'changes that.',
        'NOTHING VERIFIES AN ASSERTED SELECTOR. With ' +
        'spiffe.acceptAssertedSelectors on, a Workload API caller may send ' +
        'its own selectors in a metadata header and they are matched as ' +
        'though something had checked them. It is off by default, is ' +
        'never in force in product mode (nor can it be turned on there), ' +
        'and it exists because selector matching is ' +
        'the interesting behaviour of a Workload ' +
        'API and there is otherwise no way to exercise a client\'s "these ' +
        'matched and those did not" path here.',
        'NODE ATTESTATION IS VERIFIED OR REFUSED (#40, 2026-09-21). ' +
        'AttestAgent accepts only a type the realm names in ' +
        'spiffe.nodeAttestors and an attestor here verifies — ' +
        '`nodeAttestation` below lists them — and refuses every other with ' +
        'FAILED_PRECONDITION. Nothing an agent claims is written down ' +
        'unverified.',
        'A CSR SIGNATURE IS NOT VERIFIED. Only the public key is read out of ' +
        'a CSR — which is what stops a caller naming itself something it is ' +
        'not — but proof of possession is not checked.',
        'NO REVOCATION, ANYWHERE. SPIFFE has none: the answer is a short ' +
        'lifetime and rotation. The CRL fields in the Workload API responses ' +
        'are empty because that is the conforming value, not because they ' +
        'are unimplemented. An SVID presented to the SPIRE Server API is ' +
        'checked against its validity window and the trust bundle and ' +
        'against no revocation list, because there is none to check. The ' +
        'directory does record a `spiffeCredentialStatus` on an identity ' +
        'whose last registration entry was deleted or whose agent was banned ' +
        'or deleted, and THAT IS NOT A REVOCATION EITHER: nothing reads it ' +
        'back, no certificate is refused because of it, and it says only ' +
        'that no FURTHER SVID can be issued here. Read it as a note on the ' +
        'directory entry, never as a check this service makes.'
      ].concat(auth.authRequired() ? [] : [
        'AND, RIGHT NOW, NOTHING ON THE SPIRE SERVER API EITHER. ' +
        'Authentication is off there, so that port is plain gRPC, no caller ' +
        'is identified, the per-method table below is not applied, and ' +
        'anybody who can reach it can create a registration entry granting ' +
        'any identity in this trust domain and then collect an SVID for it. ' +
        'The `admin` and `downstream` flags on an entry are recorded and ' +
        'read by nothing while it is off.'
      ]),
      // WHO IS ASKING, on the surface that asks. The whole table comes from
      // spiffe_auth.ts so that this page, /admin/spiffe and the management API
      // cannot disagree about what is enforced — the same reason the two
      // discovery documents are built from one object.
      authentication: auth.state(),
      // And the short list of what IS refused, because a page that only said
      // "nothing is checked" would be wrong.
      refused: [
        'A Workload API call with no `' + rpc.SECURITY_HEADER + ': true` ' +
        'metadata header, unless spiffe.requireSecurityHeader is off. Every ' +
        'conforming implementation refuses this, so a client that omits it ' +
        'has a bug nothing else will tell them about.',
        'FetchJWTSVID and MintJWTSVID with no audience.',
        'ValidateJWTSVID on anything that does not really verify: signature, ' +
        'expiry with no leeway, audience, and that the sub belongs to the ' +
        'trust domain whose key verified it.',
        'A registration entry whose SPIFFE ID is invalid, belongs to another ' +
        'trust domain, or sits under the reserved /spire path.',
        'AttestAgent for an attestation type the realm does not accept or ' +
        'no attestor here verifies (FAILED_PRECONDITION), evidence its ' +
        'attestor could not verify, a banned agent, a second attestation ' +
        'with evidence that is not re-attestable, and a challenge left ' +
        'unanswered. For a join token: one this server did not mint, one ' +
        'that has expired, and one presented twice.',
        'Every method on the SPIRE Server API that the caller\'s entity is ' +
        'not allowed, with UNAUTHENTICATED when nothing was presented and ' +
        'PERMISSION_DENIED when something was and it was not enough. The two ' +
        'are different instructions to a client and SPIRE distinguishes ' +
        'them. Note that Debug.GetInfo is LOCAL-ONLY, so even an admin SVID ' +
        'is refused it over TCP — that is SPIRE\'s row and the surprise is ' +
        'the point.',
        'An X509-SVID that no authority in this trust domain or a federated ' +
        'one signed, one outside its validity window (spiffe.clockSkew), one ' +
        'with no URI subjectAltName, one with several, and one whose SPIFFE ' +
        'ID names a different trust domain from the authority that signed it.',
        'RenewAgent for a caller that is not the agent it would renew — ' +
        'which, on a port where nothing identifies a caller, is every ' +
        'caller, so the method answers Unimplemented there with the reason ' +
        'it used to give always.',
        'Appending an authority to this trust domain\'s own bundle, which ' +
        'would publish a signing key nothing here holds.',
        'RefreshBundle, which would have this service fetch a URL somebody ' +
        'registered — the same refusal it gives WS-Federation\'s wreqptr and ' +
        'a client\'s jwks_uri.'
      ],
      // The node attestors this build verifies, which this realm accepts, and
      // any configured name nothing verifies (#40).
      nodeAttestation: serverApi.nodeAttestationState(),
      // The workload attestors, whether the kernel can be asked at all, and
      // each open attested connection (#40 phase four).
      workloadAttestation: this.workloadAttestationState(),
      links: {
        bundle: base + BUNDLE_PATH,
        console: base + '/admin/spiffe',
        entries: base + '/admin/spiffe/entries',
        agents: base + '/admin/spiffe/agents',
        brokers: base + '/admin/spiffe/brokers',
        api: base + '/admin-api/spiffe',
        directory: base + '/admin/ldap/spiffe',
        metadata: base + '/admin/sts-metadata'
      }
    };
    log.debug('Leaving SpiffeServer.description().');
    return document;
  }

  // `/SpiffeWorkloadAPI/FetchX509SVID` -> `FetchX509SVID`. The loader gives
  // handlers camelCase names and the wire path carries the real one, so the
  // path is what these pages report: a reader comparing this page with the
  // `.proto` should see the same spelling.
  protoNameOf(methodPath) {
    const { log } = this.deps;
    log.debug("Entering SpiffeServer.protoNameOf().");
    const parts = String(methodPath || '').split('/');
    log.debug("Leaving SpiffeServer.protoNameOf().");
    return parts[parts.length - 1] || '';
  }

  esc(value) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering SpiffeServer.esc().");
    log.debug("Leaving SpiffeServer.esc().");
    return xmlEscape(value == null ? '' : String(value));
  }

  // A listener, and WHAT A CALLER HAS TO PRESENT ON IT. The third column is not
  // decoration: the four sockets have three different postures — plain, plain
  // and trusted as `local`, and mutual TLS — and a reader who cannot see which
  // is which meets the difference as a handshake failure. Same reason
  // `tls_server.js` says on the page which port needs verification turned off.
  listenerRows(bindings) {
    const { log } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.listenerRows().');
    if (!bindings.length) {
      log.debug('Leaving SpiffeServer.listenerRows().');
      return '<tr><td colspan="4">Nothing bound. Either this listener is ' +
             'turned off in configuration, or <code>listen()</code> has not ' +
             'run yet.</td></tr>';
    }
    log.debug('Leaving SpiffeServer.listenerRows().');
    return bindings.map(function (binding) {
      return '<tr><td>' + self.esc(binding.realm || 'default') +
             '</td><td><code>' +
        self.esc(binding.address) + '</code>' +
        (binding.tls ? ' <span class="note">(mutual TLS)</span>' : '') +
        '</td><td>' +
        (binding.listening
          ? 'listening'
          : '<strong>did not bind</strong>: ' + self.esc(binding.error)) +
        '</td><td>' + self.esc(binding.authentication || '') + '</td></tr>';
    }).join('');
  }

  methodRows(methods) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SpiffeServer.methodRows().");
    log.debug("Leaving SpiffeServer.methodRows().");
    return methods.map(function (method) {
      return '<tr><td><code>' + self.esc(method.name) + '</code>' +
        (method.streaming ? ' <span class="note">(stream)</span>' : '') +
        '</td><td>' + (method.implemented ? 'yes' : '<strong>no</strong>') +
        '</td><td>' + self.esc(method.what) + '</td></tr>';
    }).join('');
  }

  page(document) {
    const { log, ca, config } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.page().');
    const state = ca.state();
    log.debug('Leaving SpiffeServer.page().');
    return '<!doctype html><html><head><meta charset="utf-8"><title>SPIFFE — ' +
      'mock STS</title><style>body{font-family:system-ui,sans-serif;' +
      'margin:2rem;max-width:60rem;line-height:1.5}' +
      'table{border-collapse:collapse;margin:1rem ' +
      '0;width:100%}th,td{border:1px solid #ccc;padding:.4rem .6rem;' +
      'text-align:left;vertical-align:top}th{background:#f4f4f4}' +
      'code{background:#f4f4f4;padding:.1rem ' +
      '.3rem}.note{color:#666}.warn{background:#fff6e5;border-left:4px solid ' +
      '#e69500;padding:.6rem ' +
      '1rem}</style></head><body><h1>SPIFFE</h1><p>This service ' +
      'is the issuing authority for the trust domain <code>' +
      this.esc(document.trustDomainId) +
      '</code>. Three server-side surfaces: the ' +
      'bundle endpoint below (plain HTTPS), the <strong>Workload ' +
      'API</strong> and the <strong>SPIRE Server API</strong> (both gRPC, on ' +
      'their own sockets — this page cannot see a socket, so it reports ' +
      'whether each one actually bound).</p>' +
      (document.enabled ? '' :
        '<p class="warn">SPIFFE is turned OFF on this service ' +
        '(<code>spiffe.enabled</code>). The bundle endpoint answers 404 and ' +
        'every gRPC call is refused with <code>Unavailable</code>. Turning ' +
        'it back on needs no restart.</p>') +
      (state.ready ? '' :
        '<p class="warn">' + (state.error
          ? 'The issuing authority could not be built, so nothing here will ' +
            'issue an SVID: ' + this.esc(state.error)
          : 'The issuing authority is still being generated. An RSA-4096 key ' +
            'takes a few seconds; reload.') + '</p>') +
      // **THIS SAID *NOTHING HERE IS ATTESTED. No workload and no node* UNTIL
      // 2026-09-22**, which #40 had made false in both halves a day earlier —
      // every one of SPIRE's node attestors verifies or refuses, and the
      // Workload API's Unix socket attests its caller. A page that
      // OVERSTATES what a service checks is the worse of the two errors, so
      // what is left here is the narrow, true version, READ from the state
      // rather than asserted; the `notChecked` list below has the detail.
      '<p class="' +
      (document.workloadAttestation &&
       document.workloadAttestation.nativeModule ? 'note' : 'warn') + '">' +
      '<strong>WHAT IS ATTESTED HERE, AND WHAT IS NOT.</strong> A node ' +
      'attesting through the SPIRE Server API is VERIFIED (#40, ' +
      '2026-09-21) — an agent\'s payload used to be written down as claimed ' +
      'and is checked now — and a workload on the Workload API\'s ' +
      '<strong>Unix socket</strong> is attested from the kernel\'s own ' +
      'account of the connecting process. ' +
      (document.workloadAttestation &&
       document.workloadAttestation.nativeModule
        ? 'This build attests it.'
        : '<strong>THIS BUILD DOES NOT</strong>: it holds no ' +
          'peer-credentials module (' +
          this.esc(String((document.workloadAttestation &&
                           document.workloadAttestation.problem) ||
                          'not built')) +
          '), so the socket is served unattested here and any caller on it ' +
          'obtains an identity in this trust domain. Product mode does not ' +
          'serve it at all.') +
      ' <strong>A caller over TCP is not attested</strong> — there is no ' +
      'peer process to ask — so its source address is the only identity it ' +
      'carries. Here the TCP port is <strong>' +
      this.esc(String((document.workloadAttestation &&
                       document.workloadAttestation.tcp &&
                       document.workloadAttestation.tcp.state) || 'unknown')) +
      '</strong>: product mode serves it only where ' +
      '<code>spiffe.workloadTcpSourceAuthenticated</code> declares that the ' +
      'network authenticates source addresses, on a named address, and ' +
      'refuses an entry that selects nothing but the transport and ' +
      'endpoint; development serves it to anybody who can reach it. It ' +
      'matters more here than anywhere else in this service, because what ' +
      'comes out is a credential another service will believe.</p>' +
      '<p class="' + (document.authentication.enforced ? 'note' : 'warn') +
      '">' +
      (document.authentication.enforced
        ? '<strong>The SPIRE Server API is the exception, and it is ' +
          'on.</strong> Its TCP port is mutual TLS, a caller presents an ' +
          'X509-SVID from this trust domain, and every method is authorized ' +
          'against SPIRE\'s own table — the whole of which is below. Its ' +
          'Unix socket is the <code>local</code> entity and needs no ' +
          'credential. The Workload API is ' +
          'deliberately untouched by this: its ' +
          'specification says a client MUST NOT be required to authenticate.'
        : '<strong>And the SPIRE Server API is not authenticating anybody ' +
          'either.</strong> That port is plain gRPC and anybody who can ' +
          'reach it can create a registration entry granting any identity ' +
          'here and then collect an SVID for it. Restart with it on — the ' +
          'socket is bound once, because it decides how the socket is bound ' +
          '— to get the behaviour of a real spire-server.') +
      '</p>' +

      '<h2>The bundle endpoint</h2>' +
      '<p><a href="' + this.esc(document.bundle.url) + '"><code>' +
      this.esc(document.bundle.url) + '</code></a> — a JWK Set with ' +
      '<code>spiffe_sequence</code> (' + this.esc(document.bundle.sequence) +
      ') ' +
      'and <code>spiffe_refresh_hint</code> ' +
      '(' + this.esc(document.bundle.refreshHint) +
      ' seconds). Each key carries <code>use</code> of ' +
      '<code>x509-svid</code> or <code>jwt-svid</code>; a consumer MUST ' +
      'IGNORE a key whose <code>use</code> it does not recognise, which is ' +
      'why a bundle with the member missing ' +
      'verifies nothing and reports no error.</p><p ' +
      'class="' + (config.value('global.https') ? 'note' : 'warn') + '">' +
      this.esc(document.bundle.schemeNote) + '</p>' +

      '<h2>The trust domain\'s authorities</h2>' +
      // **THE TABLE ANSWERS "WHAT SIGNS" AND THE ONE BELOW IT ANSWERS "WHAT DO
      // I TRUST".** They were one table until 2026-09-11, because a self-signed
      // authority is both. Merging them again would be the single most
      // misleading thing this page could do about key material: a reader who
      // installed the SPIFFE Issuing CA as an anchor would have something that
      // works until the first rotation and then stops, with no error naming it.
      '<table><tr><th>Kind</th><th>Id</th><th>Key</th><th>State</th></tr>' +
      document.authorities.x509.map(function (a) {
        return '<tr><td>X.509</td><td><code>' + self.esc(a.id) +
               '</code></td><td>' +
          self.esc(a.keyType) + '</td><td>' +
          (a.active ? 'active' : 'retired, ' +
          'still published') + ', until ' + self.esc(a.notAfter) + '</td></tr>';
      }).join('') +
      document.authorities.jwt.map(function (a) {
        return '<tr><td>JWT</td><td><code>' + self.esc(a.kid) +
               '</code></td><td>' +
          self.esc(a.keyType) + ' / ' + self.esc(a.alg) + '</td><td>' +
          (a.active ? 'active' : 'retired, still published') + '</td></tr>';
      }).join('') +
      '</table>' +
      (document.authorities.chainSubjects.length
        ? '<p>An X509-SVID travels with its chain: ' +
          document.authorities.chainSubjects.map(function (subject) {
            return '<code>' + self.esc(subject) + '</code>';
          }).join(' &rarr; ') + '. The anchor below is NOT sent with it — it ' +
          'is what the bundle publishes.</p>'
        : '') +
      '<h3>What a consumer trusts</h3>' +
      '<table><tr><th>Anchor</th><th>Subject</th><th>Until</th></tr>' +
      document.authorities.trustAnchors.map(function (a) {
        return '<tr><td><code>' + self.esc(a.id) + '</code></td><td>' +
          self.esc(a.subject) + '</td><td>' + self.esc(a.notAfter) +
          '</td></tr>';
      }).join('') +
      '</table>' +
      '<p class="' + (document.authorities.source === 'pki' ? 'note' : 'warn') +
      '">' + this.esc(document.authorities.note) + '</p>' +

      '<h2>The Workload API</h2>' +
      '<table><tr><th>Realm</th><th>Address</th><th>State</th>' +
      '<th>What a caller presents</th></tr>' +
      this.listenerRows(document.workloadApi.listeners) + '</table>' +
      '<p>Every call must carry the metadata header <code>' +
      this.esc(document.workloadApi.securityHeader) + '</code>' +
      (document.workloadApi.securityHeaderRequired
        ? '. This service enforces that, which is the one conformance check ' +
          'it makes: a client that omits it has a bug that nothing else will ' +
          'ever report.'
        : ', and this service is NOT enforcing it at the moment ' +
          '(<code>spiffe.requireSecurityHeader</code> is off).') + '</p>' +
      '<table><tr><th>Method</th><th>Implemented</th><th>What</th></tr>' +
      this.methodRows(document.workloadApi.methods) + '</table>' +

      '<h2>The SPIRE Server API</h2>' +
      '<table><tr><th>Realm</th><th>Address</th><th>State</th>' +
      '<th>What a caller presents</th></tr>' +
      this.listenerRows(document.serverApi.listeners) + '</table>' +
      document.serverApi.services.map(function (service) {
        return '<h3>' + self.esc(service.name) + '</h3><p>' +
               self.esc(service.what) +
          '</p><table><tr><th>Method</th><th>Implemented</th>' +
          '<th>What</th></tr>' +
          self.methodRows(service.methods) + '</table>';
      }).join('') +

      '<h2>The SPIFFE Broker API</h2>' +
      '<table><tr><th>Realm</th><th>Address</th><th>State</th>' +
      '<th>What a caller presents</th></tr>' +
      this.listenerRows(document.brokerApi.listeners) + '</table>' +
      '<p>A broker authenticates with its X509-SVID over mutual TLS, sends ' +
      '<code>' + this.esc(document.brokerApi.securityHeader) + '</code>, and ' +
      'names a workload by reference — a process id or a Kubernetes pod — ' +
      'which this service attests itself before answering with that ' +
      'workload\'s SVIDs. Brokers (<code>spiffe.brokers</code>): ' +
      (document.brokerApi.brokers.length
        ? document.brokerApi.brokers.map(function (one) {
            return '<code>' + self.esc(one.id) + '</code> (' +
              self.esc(one.problem || one.types.join(', ')) + ')';
          }).join(', ')
        : 'none, so every call is refused PERMISSION_DENIED') + '.</p>' +

      '<h2>Who may call the SPIRE Server API</h2>' +
      '<p>' + this.esc(document.authentication.what) + '</p>' +
      '<p class="note">' + this.esc(document.authentication.bootstrapping) +
      '</p><p class="note">' + this.esc(document.authentication.identityNote) +
      '</p><p class="note">' +
      this.esc(document.authentication.credentialStatusNote || '') + '</p>' +
      (document.authentication.adminIds.length
        ? '<p>Administrators by configuration ' +
          '(<code>spiffe.adminIds</code>): ' +
          document.authentication.adminIds.map(function (id) {
            return '<code>' + self.esc(id) + '</code>';
          }).join(', ') +
            '. A registration entry marked <code>admin</code> is ' +
          'the other way, and both are read on every call.</p>'
        : '<p>No SPIFFE ID is an administrator by configuration ' +
          '(<code>spiffe.adminIds</code> is empty). The other way in is a ' +
          'registration entry marked <code>admin</code>, which the form on ' +
          '<a href="/admin/spiffe/entries">/admin/spiffe/entries</a> sets, ' +
          'and the <code>local</code> Unix socket, which needs no credential ' +
          'at all.</p>') +
      '<table><tr><th>Entity</th><th>What it means</th></tr>' +
      document.authentication.entities.map(function (entity) {
        return '<tr><td><code>' + self.esc(entity.id) + '</code></td><td>' +
          self.esc(entity.what) + '</td></tr>';
      }).join('') + '</table>' +
      '<h3>The per-method table</h3>' +
      '<p>Copied from SPIRE\'s own <code>policy_data.json</code> rather than ' +
      'reasoned out, because a table somebody derived from what each method ' +
      '"obviously" needs is one that disagrees with SPIRE in two or three ' +
      'places — and the client author who meets the disagreement has no way ' +
      'to tell which end is wrong. <code>any</code> means the method is open ' +
      'here and in a real server too.</p>' +
      '<table><tr><th>Method</th><th>Allowed to</th></tr>' +
      document.authentication.policy.map(function (row) {
        return '<tr><td><code>' + self.esc(row.method) + '</code></td><td>' +
          self.esc(row.allow.join(', ')) + '</td></tr>';
      }).join('') + '</table>' +

      '<h2>What is not checked</h2><ul>' +
      document.notChecked.map(function (line) {
        return '<li>' + self.esc(line) + '</li>';
      }).join('') + '</ul><h2>What is refused</h2><p>A short list, and it is ' +
      'here because a page that only said "nothing is checked" would be ' +
      'wrong.</p><ul>' +
      document.refused.map(function (line) {
        return '<li>' + self.esc(line) + '</li>';
      }).join('') + '</ul>' +

      '<h2>The registry</h2><p>' + this.esc(document.registry.entries) +
      ' registration entry/entries and ' +
      this.esc(document.registry.agents) + ' agent(s). ' +
      this.esc(document.registry.note) + '</p>' +

      '<h2>Elsewhere</h2><ul>' +
      Object.keys(document.links).map(function (key) {
        return '<li><a href="' + self.esc(document.links[key]) + '">' +
               self.esc(key) +
          '</a> — <code>' + self.esc(document.links[key]) + '</code></li>';
      }).join('') + '</ul>' +
      '<p class="note">Add <code>?format=json</code> to this page for the ' +
      'machine-readable form.</p>' +
      '</body></html>';
  }

  // ---------------------------------------------------------------------------
  // STARTING A REALM'S gRPC LISTENERS.
  //
  // Called from `listen()` in `server.js`, for the reason at the top of this
  // file. Four addresses per realm at most — a Unix socket and a TCP port for
  // each surface — and each is reported separately, because "the Workload API
  // socket is up and the SPIRE Server API port is not" is an ordinary outcome
  // and one flag could only report one of them. That is the lesson
  // `ldap_server.js` records about 389 and 636, applied before it had to be
  // learnt again.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // **THE ADDRESSES ARE A REALM'S SINCE 2026-09-12, AND THE ENDPOINT ADDRESS IS
  // THE ONLY THING A SPIFFE CLIENT CAN NAME A TENANT WITH.**
  //
  // Every other family here is told which realm it is in by a segment at the
  // front of the path. gRPC has a path — `/SpiffeWorkloadAPI/FetchX509SVID` —
  // and it is the METHOD: the Workload API's service name is fixed by its
  // specification and the SPIRE APIs by theirs, so a realm segment in it would
  // be a method no conforming client calls. That is the whole reason SPIFFE was
  // `none` in `realms.realmSupport()` for as long as it was.
  //
  // So the realm is the SOCKET. A realm with SPIFFE turned on gets a Workload
  // API and a SPIRE Server API of its own — its own Unix socket paths, seeded
  // when the realm was created, and its own bind ADDRESS with the ports
  // unchanged, because a client configured for `:8181`/`:8092` should reach
  // every realm where it expects to. `spiffe.grpcHost` on the realm is the row
  // that does it, and rcbj's instruction was *for the SPIFFE service, a unique
  // IP will be used* — which is this.
  // ---------------------------------------------------------------------------
  addressesFor(surface, realmId) {
    const { log, config, realms } = this.deps;
    log.debug('Entering SpiffeServer.addressesFor(). surface=' + surface +
              ' realm=' + (realmId || 'default'));
    const read = function () {
      log.debug("Entering read().");
      const out = [];
      if (surface === 'broker') {
        const port = config.value('spiffe.brokerPort');
        if (port) {
          out.push({ address: config.value('spiffe.grpcHost') + ':' + port });
        }
      } else if (surface === 'workload') {
        if (config.value('spiffe.workloadSocketEnabled')) {
          out.push({ address: 'unix://' + config.value('spiffe.workloadSocket'),
                     socketPath: config.value('spiffe.workloadSocket') });
        }
        const port = config.value('spiffe.workloadPort');
        if (port) {
          out.push({ address: config.value('spiffe.grpcHost') + ':' + port });
        }
      } else {
        if (config.value('spiffe.serverSocketEnabled')) {
          out.push({ address: 'unix://' + config.value('spiffe.serverSocket'),
                     socketPath: config.value('spiffe.serverSocket') });
        }
        const port = config.value('spiffe.serverPort');
        if (port) {
          out.push({ address: config.value('spiffe.grpcHost') + ':' + port });
        }
      }
      log.debug("Leaving read().");
      return out;
    };
    const realm = realms.get(String(realmId || ''));
    const out = realm ? realms.run(realm, read) : read();
    log.debug('Leaving SpiffeServer.addressesFor(). ' + out.length +
              ' address(es).');
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHICH REALMS HAVE SPIFFE SOCKETS, AND THE ONE ASYMMETRY IN IT.
  //
  // The DEFAULT realm always does. Its four listeners are bound at startup and
  // stay bound with `spiffe.enabled` off — they answer `Unavailable`, which is
  // what this service has always done and is deliberate: a socket that vanished
  // when a setting was turned off is indistinguishable from a service that had
  // stopped, and every client would report a connection error rather than the
  // refusal this service is trying to give it.
  //
  // EVERY OTHER REALM IS THE OPPOSITE, and it is the same argument read the
  // other way: a realm is created with SPIFFE OFF, so a socket that existed
  // before anybody turned it on would be this service binding two ports per
  // realm for realms that will never use them. There is nothing for a client to
  // be confused by, because there was never an endpoint to connect to.
  // ---------------------------------------------------------------------------
  realmsWithSockets() {
    const { log, realms } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.realmsWithSockets().');
    const out = [realms.DEFAULT_REALM];
    realms.list().forEach(function (realm) {
      if (realm.id === realms.DEFAULT_ID) {
        return;
      }
      if (self.enabledIn(realm)) {
        out.push(realm);
      }
    });
    log.debug('Leaving SpiffeServer.realmsWithSockets(). ' + out.length +
              ' realm(s).');
    return out;
  }

  async bindAll(server, surface, realmId) {
    const { log, auth, rpc, errorCodes } = this.deps;
    log.debug('Entering SpiffeServer.bindAll(). surface=' + surface +
              ' realm=' + (realmId || 'default'));
    const results = [];
    const addresses = this.addressesFor(surface, realmId);
    // ---------------------------------------------------------------------
    // WHICH SOCKET GETS TLS, AND WHY IT IS EXACTLY ONE OF THE FOUR.
    //
    // The two specifications ask for opposite things and this is where that
    // becomes four sockets with three different postures. See
    // `spiffe_auth.ts`'s header for the argument; the shape of it here:
    //
    //   Workload API, socket AND TCP   PLAIN, always. The Workload Endpoint
    //                                  specification says "Transport Layer
    //                                  Security MUST NOT be required", because
    //                                  a workload has no root of trust until
    //                                  this call gives it one. TLS here would
    //                                  refuse every conforming client.
    //   SPIRE Server API, socket       PLAIN, always. It is the `local`
    //                                  entity — the private socket a real
    //                                  `spire-server` CLI uses, whose access
    //                                  control is the filesystem.
    //   SPIRE Server API, TCP          MUTUAL TLS, always, since
    //                                  `spiffe.authRequired` was removed on
    //                                  2026-09-06.
    //
    // That last line is the one that changed what an existing caller saw, which
    // is why `spiffe.authRequired` was RESTART-ONLY while it existed: a flag
    // that was runtime for its checks and restart-only for its socket is the
    // silent disagreement config.js's header warns about — /admin/config would
    // have reported mutual TLS while a plain listener went on answering. The
    // same reasoning `oauth2.rfc9700` carries about `global.https`.
    // ---------------------------------------------------------------------
    let secure = null;
    if (surface === 'server' && auth.authRequired()) {
      try {
        // IN THE REALM, because the SVID this listener presents is an identity
        // in THAT realm's trust domain. A credential minted outside it would
        // name the default realm's domain on a socket every client reaching it
        // verifies against the realm's own bundle — a handshake that fails for
        // a reason neither end can see.
        secure = await this.inRealm(realmId, function () {
          return rpc.serverApiCredentials();
        });
      } catch (e) {
        // REPORTED, never thrown, and the port still comes up — plain. A
        // listener that refused to bind because its certificate could not be
        // minted would take the surface away for a reason nothing could show,
        // and `GET /spiffe` reports which of the two each address got.
        log.error(errorCodes.tag('STS-SPIFFE-0070') +
                  'spiffe: the SPIRE Server API could not be given a TLS ' +
                  'identity (' + e.message + '), so its TCP port is binding ' +
                  'PLAIN and nothing on it is authenticated. GET /spiffe ' +
                  'says so; this is a fault here rather than a configuration ' +
                  'problem.');
        secure = null;
      }
    }
    // KEPT, so a new Root can re-key this socket without rebinding it
    // (refreshServerCredentials(), 2026-09-21). startRealm() registers the
    // entry before it binds, so it is always there to hold them.
    const heldEntry = listeners.get(String(realmId || ''));
    if (heldEntry && secure) {
      heldEntry.apiCredentials = secure;
    }
    for (let i = 0; i < addresses.length; i++) {
      const entry = addresses[i];
      // ---------------------------------------------------------------------
      // **TWO REALMS CANNOT HAVE ONE ADDRESS, AND THE REFUSAL SAYS WHICH ROW TO
      // CHANGE.** Left to grpc-js this is `Failed to bind`, which is the same
      // message a port taken by another process gives — and the two need
      // different things done about them. A realm created without an address of
      // its own inherits `spiffe.grpcHost`, so this is the ordinary mistake
      // rather than an exotic one.
      //
      // The socket paths are seeded per realm when a realm is created, so a
      // collision there means somebody set one deliberately; it is refused the
      // same way, because the alternative is one realm silently taking another
      // realm's socket away on a restart.
      // ---------------------------------------------------------------------
      const taken = this.claimedBy(entry.address, realmId);
      if (taken !== null) {
        const held = this.addressHeldBy(taken, entry.address);
        const why = 'the "' + (taken || 'default') +
                    '" realm already answers ' +
          'on ' + held + ' in this process' +
          (held === entry.address ? '' : ', which INCLUDES ' + entry.address +
           ' — 0.0.0.0 is every address on this machine') +
          '. Give this realm an address of its own — spiffe.grpcHost on the ' +
          'realm — or a port of its own; and if it is the wildcard in the ' +
          'way, give the realm that holds it a ' +
          'real address too. Two trust domains ' +
          'on one endpoint would be one socket issuing SVIDs in two names.';
        log.error(errorCodes.tag('STS-SPIFFE-0071') +
                  'spiffe: the "' + (realmId || 'default') + '" realm\'s ' +
                  surface + ' listener was NOT bound: ' + why);
        results.push({ address: entry.address, listening: false, error: why,
                       port: 0, tls: false, socket: !!entry.socketPath,
                       realm: realmId || '',
                       authentication: 'Nothing is listening here.' });
        continue;
      }
      // THE WORKLOAD API'S UNIX SOCKET IS ATTESTED (#40 phase four), and in
      // product mode it is not served at all without the native module that
      // makes attestation possible — every process that could reach it would
      // otherwise get whatever the transport selectors match.
      const attested = surface === 'workload' && !!entry.socketPath;
      if (attested && !this.deps.peer.availability().available &&
          this.deps.mode.requiresWorkloadAttestation()) {
        const why = 'workload attestation is unavailable (' +
          this.deps.peer.availability().problem + '), and this service is ' +
          'running as a product, where the Workload API socket is not ' +
          'served unattested';
        log.error(errorCodes.tag('STS-SPIFFE-0113') + 'spiffe: the "' +
                  (realmId || 'default') + '" realm\'s Workload API socket ' +
                  'was NOT bound: ' + why);
        results.push({ address: entry.address, listening: false, error: why,
                       port: 0, tls: false, socket: true,
                       realm: realmId || '',
                       authentication: 'Nothing is listening here.' });
        continue;
      }
      // THE WORKLOAD API'S TCP PORT IS SERVED ONLY WHERE THE NETWORK
      // AUTHENTICATES THE SOURCE ADDRESS (#166): in product, not without
      // `spiffe.workloadTcpSourceAuthenticated`, and never on a wildcard
      // address. `spiffe_auth.ts`'s `workloadTcpPosture()` decides, IN THE
      // REALM, because the mode and both settings are the realm's. Recorded
      // and reported like 0113, never thrown: the Unix socket beside it and
      // the SPIRE Server API are unaffected.
      if (surface === 'workload' && !entry.socketPath) {
        const posture = this.inRealm(realmId, function () {
          return auth.workloadTcpPosture();
        });
        if (!posture.served) {
          // STS-SPIFFE-0120 (not declared) or STS-SPIFFE-0121 (a wildcard).
          log.error(errorCodes.tag(posture.errorCode) + 'spiffe: the "' +
                    (realmId || 'default') + '" realm\'s Workload API TCP ' +
                    'port (' + entry.address + ') was NOT bound: ' +
                    posture.why + '.');
          // The code rides as errorCodes' non-enumerable mark: this row is
          // drawn on GET /spiffe and returned by /admin-api, and a code is
          // recorded, never sent.
          results.push(errorCodes.mark({ address: entry.address,
                         listening: false, error: posture.why,
                         port: 0, tls: false, socket: false,
                         realm: realmId || '',
                         authentication: 'Nothing is listening here.' },
                       posture.errorCode));
          continue;
        }
      }
      // The SPIRE Server API's socket is PRIVATE — it is the trusted `local`
      // entity — and the Workload API's is not. See spiffe_grpc.ts.
      if (entry.socketPath) {
        rpc.prepareSocketPath(entry.socketPath, surface === 'server');
      }
      // The socket is the `local` entity and is never TLS; see above. `secure`
      // is null for every address but one.
      const tls = !entry.socketPath && secure;
      const self = this;
      // THE SPIRE SERVER API'S SOCKET IS ACCEPTED THROUGH THE SAME LISTENER
      // (#104) wherever the native module is built, in both modes, so that a
      // product realm can read the peer's kernel uid before it calls anybody
      // `local`. Nothing is refused at accept: the facts are recorded, and
      // `spiffe_auth.ts`'s `localTrust()` decides per call, in the mode the
      // realm is in then. Without the module it is bound as it always was,
      // and a product realm trusts nobody on it (STS-SPIFFE-0119).
      const peerRead = surface === 'server' && !!entry.socketPath &&
        this.deps.peer.availability().available;
      const bound = attested
        ? await rpc.bindAttestedSocket(server, entry.socketPath,
          function (socket) {
            return self.attestConnection(realmId, socket);
          })
        : peerRead
          ? await rpc.bindAttestedSocket(server, entry.socketPath,
            function (socket) {
              return self.observeLocalCaller(entry.socketPath, socket);
            })
          : await rpc.bindOne(server, entry.address,
            tls ? secure : rpc.grpc.ServerCredentials.createInsecure());
      bound.tls = !!tls;
      bound.socket = !!entry.socketPath;
      // Workload attestation is the Workload API's; the SPIRE Server API's
      // socket only has its peer's credentials read (#104).
      bound.attested = attested;
      bound.peerCredentials = attested || peerRead;
      if (bound.listening && entry.socketPath && surface === 'server') {
        bound.restricted = rpc.restrictSocket(entry.socketPath);
      }
      // What a caller has to do to use this address, said on the page rather
      // than left to be met as a handshake failure — the rule `tls_server.js`
      // follows about the main port.
      bound.authentication = entry.socketPath
        ? (surface === 'server'
            ? (auth.trustLocalSocket()
                ? (this.deps.mode.trustsUnverifiedLocalSocket()
                    ? 'No credential. This socket is the `local` entity and ' +
                      'is trusted outright, which is how the spire-server ' +
                      'CLI works.'
                    : (peerRead && bound.restricted
                        ? 'No credential, from a process running as this ' +
                          'service\'s own uid: product mode verifies per ' +
                          'connection that the socket is private and reads ' +
                          'the caller\'s uid from the kernel before it is ' +
                          'the `local` entity.'
                        : 'Nobody is the `local` entity here: product mode ' +
                          'verifies the socket\'s boundary and cannot (' +
                          (peerRead ? 'the socket is not private'
                                    : 'the peer\'s uid cannot be read — ' +
                                      this.deps.peer.availability().problem) +
                          '). Present an administrator\'s X509-SVID on the ' +
                          'TCP port.'))
                : 'An X509-SVID is required even here ' +
                  '(spiffe.trustLocalSocket is off).')
            : 'None, and there must be none: the Workload Endpoint ' +
              'specification forbids requiring one.')
        : (tls
            ? 'Mutual TLS. Verify this server against the trust bundle, ' +
              'present your own X509-SVID, and expect to be authorized per ' +
              'method.'
            : (surface === 'server'
                ? 'None — authentication is off, so this port is plain ' +
                  'gRPC and every method is open to everybody.'
                : 'None, and there must be none: the Workload Endpoint ' +
                  'specification forbids requiring one. ' +
                  (this.inRealm(realmId, function () {
                    return auth.workloadTcpPosture().declared;
                  }) && !this.inRealm(realmId, function () {
                    return self.deps.mode.servesUnattestedWorkloadTcp();
                  })
                    ? 'The network is DECLARED to authenticate source ' +
                      'addresses (spiffe.workloadTcpSourceAuthenticated), ' +
                      'so a caller is answered with the entries its ' +
                      'peer: address selects.'
                    : 'Nothing attests a caller here (development): the ' +
                      'deployment secures this port by other means or does ' +
                      'not expose it.')));
      bound.realm = realmId || '';
      results.push(bound);
    }
    log.debug('Leaving SpiffeServer.bindAll(). ' + results.length +
              ' address(es).');
    return results;
  }

  // Which realm, if any, is already listening on an address in THIS process.
  // Null when nobody is — not the realm id, because the default realm's id is
  // the empty string and `'' || 'nobody'` is the kind of bug this whole file is
  // written to avoid.
  claimedBy(address, realmId) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SpiffeServer.claimedBy().");
    let found = null;
    listeners.forEach(function (entry, id) {
      if (String(id) === String(realmId || '')) {
        return;
      }
      entry.bindings.forEach(function (bound) {
        if (bound.listening && self.overlaps(bound.address, address)) {
          found = id;
        }
      });
    });
    log.debug("Leaving SpiffeServer.claimedBy().");
    return found;
  }

  // ---------------------------------------------------------------------------
  // **`0.0.0.0:8092` AND `172.29.0.11:8092` ARE THE SAME SOCKET, AND A STRING
  // COMPARISON SAYS THEY ARE NOT.** This is the case that actually happens
  // rather than an edge one: `spiffe.grpcHost` defaults to `0.0.0.0`, which is
  // every address on this machine, so the DEFAULT realm's listeners own the
  // Workload API port on every address a realm could possibly be given — and
  // the second realm's bind fails with `EADDRINUSE` on an address nothing else
  // appears to be using.
  //
  // Measured on the compose stack the hour this was written: a realm configured
  // with `spiffe.grpcHost=172.29.0.11` bound its Unix socket, failed on both
  // TCP ports, and said `address already in use 172.29.0.11:8092` with nothing
  // listening on that address. The fix is in two halves and this is the first:
  // the wildcard is recognised here, so the refusal names the realm and the
  // setting. The second is that the compose files now give the default realm
  // the container's OWN address instead of the wildcard, so the ordinary stack
  // has three addresses free for realms to take.
  //
  // A Unix socket path is compared literally: there is no wildcard for one.
  // ---------------------------------------------------------------------------
  overlaps(bound, wanted) {
    const { log } = this.deps;
    log.debug("Entering SpiffeServer.overlaps().");
    if (bound === wanted) {
      log.debug("Leaving SpiffeServer.overlaps().");
      return true;
    }
    if (bound.indexOf('unix://') === 0 || wanted.indexOf('unix://') === 0) {
      log.debug("Leaving SpiffeServer.overlaps().");
      return false;
    }
    const boundCut = bound.lastIndexOf(':');
    const wantedCut = wanted.lastIndexOf(':');
    if (boundCut < 0 || wantedCut < 0) {
      log.debug("Leaving SpiffeServer.overlaps().");
      return false;
    }
    if (bound.slice(boundCut) !== wanted.slice(wantedCut)) {
      log.debug("Leaving SpiffeServer.overlaps().");
      return false;
    }
    const boundHost = bound.slice(0, boundCut);
    const wantedHost = wanted.slice(0, wantedCut);
    const WILDCARD = ['0.0.0.0', '::', '[::]', ''];
    log.debug("Leaving SpiffeServer.overlaps().");
    return WILDCARD.indexOf(boundHost) >= 0 ||
                                          WILDCARD.indexOf(wantedHost) >= 0;
  }

  // WHICH of that realm's addresses is in the way, for the message. It is
  // usually the same string; it is not when a wildcard is what overlaps, and
  // that is exactly the case a reader needs told.
  addressHeldBy(realmId, wanted) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SpiffeServer.addressHeldBy().");
    const entry = listeners.get(String(realmId || ''));
    let held = wanted;
    if (entry) {
      entry.bindings.forEach(function (bound) {
        if (bound.listening && self.overlaps(bound.address, wanted)) {
          held = bound.address;
        }
      });
    }
    log.debug("Leaving SpiffeServer.addressHeldBy().");
    return held;
  }

  // Run something inside a realm. The realm registry takes a RECORD rather than
  // an id, and `realms.get('')` is the default realm's record, so this is the
  // one place that conversion happens.
  inRealm(realmId, fn) {
    const { log, realms } = this.deps;
    log.debug("Entering SpiffeServer.inRealm().");
    const realm = realms.get(String(realmId || ''));
    log.debug("Leaving SpiffeServer.inRealm().");
    return realm ? realms.run(realm, fn) : fn();
  }

  // ---------------------------------------------------------------------------
  // ONE REALM'S FOUR LISTENERS.
  //
  // **THE HANDLERS ARE WRAPPED RATHER THAN PARAMETERISED, WHICH IS THE WHOLE
  // TRICK.** Not one line of `spiffe_workload.ts` or `spiffe_api.ts` knows
  // about a realm: they call `ca.trustDomain()`, `registry.entriesFor()` and
  // the rest, every one of which reads the AMBIENT realm and falls back to the
  // default — the shape every per-realm store in this service has. So a realm's
  // gRPC server is the same handler table entered through `realms.run()`, and
  // the realm a call is in is decided by the socket it arrived on and nowhere
  // else.
  //
  // That also makes the streaming handlers right for free: `FetchX509SVID`
  // keeps the stream open and re-sends at half the SVID lifetime, and the timer
  // it arms is armed INSIDE the realm context, so the re-send is in the same
  // realm as the call that asked for it. An explicit realm argument threaded
  // through the handlers would have had to be remembered at each of those
  // points.
  // ---------------------------------------------------------------------------
  handlersInRealm(realmId, table) {
    const { log, realms } = this.deps;
    log.debug("Entering SpiffeServer.handlersInRealm().");
    const realm = realms.get(String(realmId || ''));
    const out = {};
    Object.keys(table).forEach(function (name) {
      const fn = table[name];
      out[name] = function () {
        const args = arguments;
        return realms.run(realm || realms.DEFAULT_REALM, function () {
          return fn.apply(null, args);
        });
      };
    });
    log.debug("Leaving SpiffeServer.handlersInRealm().");
    return out;
  }

  async startRealm(realm) {
    const { log, realms, rpc, workload, serverApi, ca, errorCodes,
            registry } = this.deps;
    const self = this;
    log.debug("Entering SpiffeServer.startRealm().");
    const realmId = realm.id === realms.DEFAULT_ID ? '' : realm.id;
    log.debug('Entering SpiffeServer.startRealm(). realm=' +
              (realmId || 'default'));
    const workloadServer = rpc.buildServer([
      { name: 'workload',
        handlers: this.handlersInRealm(realmId, workload.HANDLERS) }
    ]);
    const apiServer = rpc.buildServer(
      serverApi.SERVICE_HANDLERS.map(function (entry) {
        return { name: entry.name,
                 handlers: self.handlersInRealm(realmId, entry.handlers) };
      }));
    const brokerServer = rpc.buildServer([
      { name: 'broker',
        handlers: this.handlersInRealm(realmId, this.brokerHandlers()) }
    ]);
    const entry = { realmId: realmId, workloadServer: workloadServer,
                    apiServer: apiServer, brokerServer: brokerServer,
                    workload: [], api: [], broker: [], bindings: [] };
    // REGISTERED BEFORE IT BINDS, so that `claimedBy()` sees this realm while
    // the next one is being started — the bindings are empty until they are
    // not, and an address is only claimed once it is listening.
    listeners.set(realmId, entry);
    // The authorities first: a listener that answered before the CA existed
    // would refuse every call for a reason that has nothing to do with the
    // call. Awaited rather than raced, and a failure here is REPORTED — the
    // listeners still come up, and every call then fails with the real reason
    // rather than with a connection refused.
    try {
      await this.inRealm(realmId, function () { return ca.ready(realmId); });
    } catch (e) {
      log.error(errorCodes.tag('STS-SPIFFE-0072') +
                'spiffe: the "' + (realmId || 'default') +
                '" realm\'s issuing ' +
                'authority failed, so its listeners will answer and every ' +
                'call will be refused with the reason: ' + e.message);
    }
    // The registry's seed entries, once the store exists. Here rather than at
    // require time because `ldap_server.js` fills the directory slot at ITS
    // require time, and `common/protocol_stack.ts` requires this module after
    // it — but `listen()` is the first moment BOTH are certainly true. IN THE
    // REALM, because `ou=spiffe` is a container in that realm's own directory.
    try {
      this.inRealm(realmId, function () {
        registry.seed(ca.trustDomain(realmId));
      });
    } catch (e) {
      // A directory that would not hold the seed entries. Reported, never
      // fatal: the surfaces work, they simply have nothing in them.
      log.error(errorCodes.tag('STS-SPIFFE-0073') +
                'spiffe: the "' + (realmId || 'default') + '" realm\'s seed ' +
                'registration entries could not be created: ' + e.message);
    }
    entry.workload = await this.bindAll(workloadServer, 'workload', realmId);
    entry.bindings = entry.workload.slice(0);
    entry.api = await this.bindAll(apiServer, 'server', realmId);
    entry.bindings = entry.workload.concat(entry.api);
    entry.broker = await this.bindBroker(brokerServer, realmId);
    entry.bindings = entry.workload.concat(entry.api, entry.broker);
    log.info('spiffe: the "' + (realmId || 'default') + '" realm answers on ' +
             entry.bindings.filter(function (b) { return b.listening; })
               .map(function (b) { return b.address; }).join(', ') +
             ' for the trust domain ' + ca.trustDomainId(realmId) + '.');
    log.debug('Leaving SpiffeServer.startRealm().');
    return entry;
  }

  // ONE WORKLOAD API CONNECTION, ATTESTED IN THE LISTENER'S REALM (#40 phase
  // four): the kernel's facts, then the realm's workload attestors. Resolves
  // the facts — with `error` set when attestation failed, which the
  // connection's every call is then refused with.
  async attestConnection(realmId, socket) {
    const { log, peer } = this.deps;
    log.debug('Entering SpiffeServer.attestConnection(). realm=' +
              (realmId || 'default'));
    const self = this;
    const facts = peer.observe(socket);
    if (!facts.error) {
      try {
        facts.selectors = await this.inRealm(realmId, function () {
          return self.workloadAttestation().attest(facts);
        });
      } catch (e) {
        log.debug("Caught in SpiffeServer.attestConnection(): " +
                  ((e && e.message) || e));
        facts.error = String((e && e.message) || e);
      }
    } else if (!this.deps.mode.requiresWorkloadAttestation() &&
               !peer.availability().available) {
      // DEVELOPMENT WITHOUT THE NATIVE MODULE: served on transport selectors
      // alone, as the socket always was, and GET /spiffe says so.
      facts.error = '';
      facts.note = 'workload attestation is unavailable here: ' +
                   peer.availability().problem;
    }
    log.debug('Leaving SpiffeServer.attestConnection(). ' + facts.tag + ' ' +
              facts.selectors.length + ' selector(s)' +
              (facts.error ? ', failed: ' + facts.error : ''));
    return facts;
  }

  // ONE SPIRE SERVER API SOCKET CONNECTION (#104): the kernel's facts and
  // whether the socket is private, recorded for `localTrust()`. No workload
  // attestor runs — this is not the Workload API — and nothing is refused
  // here: an unreadable peer is `facts.error`, which `localTrust()` reads as
  // "not local" in a product realm and a development realm never asks.
  async observeLocalCaller(socketPath, socket) {
    const { log, peer, rpc } = this.deps;
    log.debug('Entering SpiffeServer.observeLocalCaller().');
    const facts = peer.observe(socket);
    facts.localSocket = rpc.socketPrivacy(socketPath);
    log.debug('Leaving SpiffeServer.observeLocalCaller(). ' + facts.tag +
              ' uid=' + facts.uid + ' private=' + facts.localSocket.private);
    return facts;
  }

  // What GET /spiffe, the console and /admin-api draw about workload
  // attestation.
  workloadAttestationState() {
    const { log, peer, mode, auth, realms } = this.deps;
    log.debug('Entering SpiffeServer.workloadAttestationState().');
    const kernel = peer.state();
    const attestors = this.workloadAttestation().state();
    // THE TCP PORT (#166), in the realm asking: what the posture says NOW,
    // and whether this realm's port is actually listening — two facts, since
    // a realm switched to product after its port was bound keeps the socket
    // and refuses every call on it.
    // Without its `errorCode`: this is drawn and returned, and a code is
    // recorded, never sent.
    const posture: Record<string, any> =
      Object.assign({}, auth.workloadTcpPosture());
    delete posture.errorCode;
    const realmId = realms.current().id === realms.DEFAULT_ID
      ? '' : realms.current().id;
    const held = listeners.get(realmId);
    const tcpBinding = held ? held.workload.filter(function (b) {
      return !b.socket;
    })[0] : null;
    posture.listening = !!(tcpBinding && tcpBinding.listening);
    posture.attested = false;
    log.debug('Leaving SpiffeServer.workloadAttestationState().');
    return {
      tcp: posture,
      nativeModule: kernel.nativeModule,
      problem: kernel.problem,
      unattestedSocketServed: !kernel.nativeModule &&
        !mode.requiresWorkloadAttestation(),
      attestors: attestors.attestors,
      unknownConfigured: attestors.unknownConfigured,
      connections: kernel.connections
    };
  }

  // The workload attestation table, built once.
  workloadAttestation() {
    const { log, buildWorkloadAttestation } = this.deps;
    log.debug('Entering SpiffeServer.workloadAttestation().');
    if (!WORKLOAD_ATTESTATION.table) {
      WORKLOAD_ATTESTATION.table = buildWorkloadAttestation();
    }
    log.debug('Leaving SpiffeServer.workloadAttestation().');
    return WORKLOAD_ATTESTATION.table;
  }

  // The Broker API's handlers, wrapped once (#170).
  brokerHandlers(): Record<string, any> {
    const { log } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.brokerHandlers().');
    if (!BROKER_HANDLERS.table) {
      BROKER_HANDLERS.table = new broker.SpiffeBroker(
        broker.SpiffeBroker.defaultDeps(function () {
          return self.workloadAttestation();
        })).handlers();
    }
    log.debug('Leaving SpiffeServer.brokerHandlers().');
    return BROKER_HANDLERS.table;
  }

  // ---------------------------------------------------------------------------
  // THE SPIFFE BROKER ENDPOINT'S LISTENER (#170): `spiffe.grpcHost` and
  // `spiffe.brokerPort` in the realm, MUTUAL TLS ONLY. Three rules, each the
  // family's:
  //
  //   * started from `listen()` through `startRealm()`, never at require — a
  //     bind can fail, and a require that throws takes the service down;
  //   * a failure is RECORDED on the binding and logged under its code
  //     (STS-SPIFFE-0140), and GET /spiffe draws it;
  //   * it is NEVER bound plain. The SPIRE Server API's port falls back to
  //     plain when it cannot be given a certificate (STS-SPIFFE-0070), in a
  //     posture that is reported; the Broker Endpoint's specification says
  //     it "requires transport security in the form of mutual TLS", and a
  //     port handing any workload's SVIDs to whoever asked would be the whole
  //     trust domain on a socket. So no certificate is no listener.
  //
  // An address another realm holds is refused exactly as `bindAll()` refuses
  // it, naming the realm.
  // ---------------------------------------------------------------------------
  async bindBroker(server, realmId) {
    const { log, rpc, errorCodes } = this.deps;
    log.debug('Entering SpiffeServer.bindBroker(). realm=' +
              (realmId || 'default'));
    const results = [];
    const addresses = this.addressesFor('broker', realmId);
    for (let i = 0; i < addresses.length; i++) {
      const wanted = addresses[i].address;
      const row: Record<string, any> = {
        address: wanted, listening: false, error: '', port: 0, tls: false,
        socket: false, realm: realmId || '',
        authentication: 'Nothing is listening here.' };
      const taken = this.claimedBy(wanted, realmId);
      if (taken !== null) {
        row.error = 'the "' + (taken || 'default') + '" realm already ' +
          'answers on ' + this.addressHeldBy(taken, wanted) + ' in this ' +
          'process; give this realm spiffe.grpcHost or spiffe.brokerPort of ' +
          'its own';
        log.error(errorCodes.tag('STS-SPIFFE-0140') + 'spiffe: the "' +
                  (realmId || 'default') + '" realm\'s SPIFFE Broker API ' +
                  'listener was NOT bound: ' + row.error);
        results.push(errorCodes.mark(row, 'STS-SPIFFE-0140'));
        continue;
      }
      let credentials = null;
      try {
        credentials = await this.inRealm(realmId, function () {
          return rpc.brokerCredentials();
        });
      } catch (e) {
        log.debug("Caught in SpiffeServer.bindBroker(): " +
                  ((e && e.message) || e));
        row.error = 'it could not be given a mutual-TLS identity (' +
                    ((e && e.message) || e) + '), and the Broker Endpoint ' +
                    'is never served without one';
        log.error(errorCodes.tag('STS-SPIFFE-0140') + 'spiffe: the "' +
                  (realmId || 'default') + '" realm\'s SPIFFE Broker API ' +
                  'listener was NOT bound: ' + row.error);
        results.push(errorCodes.mark(row, 'STS-SPIFFE-0140'));
        continue;
      }
      const held = listeners.get(String(realmId || ''));
      if (held) {
        held.brokerCredentials = credentials;
      }
      const bound = await rpc.bindOne(server, wanted, credentials);
      bound.tls = true;
      bound.socket = false;
      bound.realm = realmId || '';
      bound.authentication = 'Mutual TLS. Verify this server as ' +
        'spiffe://<trust domain>/spire/server against the trust bundle, ' +
        'present the X509-SVID of a broker named in spiffe.brokers, and send ' +
        'broker.spiffe.io: true on every call.';
      results.push(bound);
    }
    log.debug('Leaving SpiffeServer.bindBroker(). ' + results.length);
    return results;
  }

  stopRealm(realmId) {
    const { log } = this.deps;
    log.debug('Entering SpiffeServer.stopRealm(). realm=' +
              (realmId || 'default'));
    const entry = listeners.get(String(realmId || ''));
    if (!entry) {
      log.debug('Leaving SpiffeServer.stopRealm(). Nothing bound.');
      return;
    }
    // The attested socket's accepting listener is this module's, not
    // grpc-js's, and is closed here.
    this.deps.rpc.closeAttested(entry.workloadServer);
    [entry.workloadServer, entry.apiServer,
     entry.brokerServer].forEach(function (server) {
      if (!server) return;
      try {
        server.forceShutdown();
      } catch (e) {
        // Already down, or never came up. Nothing to do about it and nothing
        // depends on it having worked.
        log.debug('stopRealm(): a gRPC server would not shut down: ' +
                  e.message);
      }
    });
    listeners.delete(String(realmId || ''));
    log.info('spiffe: the "' + (realmId || 'default') + '" realm\'s SPIFFE ' +
             'listeners were closed. Its registration entries and its ' +
             'authorities are untouched — turning it back on binds them ' +
             'again under the same trust domain.');
    log.debug('Leaving SpiffeServer.stopRealm().');
  }

  reconcile() {
    const { log } = this.deps;
    log.debug('Entering SpiffeServer.reconcile().');
    if (!started) {
      log.debug('Leaving SpiffeServer.reconcile(). This process binds no ' +
                'SPIFFE socket.');
      return Promise.resolve([]);
    }
    pending = pending.then(this.reconcileNow.bind(this),
                           this.reconcileNow.bind(this));
    log.debug('Leaving SpiffeServer.reconcile(). Queued.');
    return pending;
  }

  reconcileNow() {
    const { log, realms } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.reconcileNow().');
    const wanted = this.realmsWithSockets();
    const wantedIds = wanted.map(function (realm) {
      return realm.id === realms.DEFAULT_ID ? '' : realm.id;
    });
    const going = [];
    listeners.forEach(function (entry, id) {
      if (wantedIds.indexOf(String(id)) < 0) {
        going.push(String(id));
      }
    });
    going.forEach(this.stopRealm.bind(this));
    const coming = wanted.filter(function (realm) {
      const id = realm.id === realms.DEFAULT_ID ? '' : realm.id;
      return !listeners.has(id);
    });
    log.debug('Leaving SpiffeServer.reconcileNow(). ' + coming.length +
              ' starting, ' +
              going.length + ' stopped.');
    // SERIALLY, because `claimedBy()` reads what is already bound and two
    // realms starting at once would each find the other's addresses unclaimed.
    return coming.reduce(function (chain, realm) {
      return chain.then(function (done) {
        return self.startRealm(realm).then(function (entry) {
          return done.concat([entry]);
        });
      });
    }, Promise.resolve([]));
  }

  listen() {
    const { log } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.listen().');
    if (started) {
      log.debug('Leaving SpiffeServer.listen(). Already started.');
      return { whenReady: Promise.resolve(this.bindingsNow()) };
    }
    started = true;
    const whenReady = this.reconcile().then(function () {
      return self.bindingsNow();
    });
    log.debug('Leaving SpiffeServer.listen().');
    return { whenReady: whenReady };
  }

  // EVERY REALM'S BINDINGS IN THE TWO LISTS THE REST OF THIS SERVICE ALREADY
  // READS. `/spiffe`, `/admin/spiffe` and `/admin-api` all take
  // `{ workload, api }`, and each row now says which realm it belongs to — the
  // alternative was a second shape everywhere and two things to keep in step.
  bindingsNow() {
    const { log } = this.deps;
    log.debug("Entering SpiffeServer.bindingsNow().");
    const workloadAll = [];
    const apiAll = [];
    const brokerAll = [];
    listeners.forEach(function (entry) {
      entry.workload.forEach(function (b) { workloadAll.push(b); });
      entry.api.forEach(function (b) { apiAll.push(b); });
      (entry.broker || []).forEach(function (b) { brokerAll.push(b); });
    });
    log.debug("Leaving SpiffeServer.bindingsNow().");
    return { workload: workloadAll, api: apiAll, broker: brokerAll };
  }

  close() {
    const { log } = this.deps;
    log.debug('Entering SpiffeServer.close().');
    Array.from(listeners.keys()).forEach(this.stopRealm.bind(this));
    started = false;
    log.debug('Leaving SpiffeServer.close().');
  }

  // THE ROUTES, registered where they always were: the module exports
  // this, and `common/protocol_stack.ts` calls it (#50, R1) at the point
  // where requiring the module used to register them, so the route order
  // is unchanged (rule 1). Nothing calls it at load.
  registerRoutes(app: RouteApp): void {
    const { log, errorCodes, ca, audit } = this.deps;
    const self = this;
    log.debug("Entering SpiffeServer.registerRoutes().");
    // -------------------------------------------------------------------------
    // THE BUNDLE ENDPOINT.
    //
    // `Cache-Control: no-store`, and that is not boilerplate here. The bundle
    // carries this trust domain's authority certificates and JWT verification
    // keys, they are regenerated on every start, and a cached copy outlives the
    // keys it describes. The resulting failure is "nothing from that trust
    // domain verifies", which reads as a broken bundle rather than a stale one
    // — the same reasoning that puts the header on every document that carries
    // the STS signing key.
    // -------------------------------------------------------------------------
    app.get(BUNDLE_PATH, async function (req, res) {
      log.debug('Entering the SPIFFE bundle endpoint.');
      if (!self.enabled()) {
        // 404 rather than 503, because with SPIFFE off there is no bundle
        // endpoint here at all — a federation partner should see the same thing
        // it would see against a service that never had one.
        errorCodes.mark(res, 'STS-SPIFFE-0002');
        res.status(404).type('application/json')
          .set('Cache-Control', 'no-store')
           .send(JSON.stringify({ error: 'SPIFFE is turned off on this ' +
                                         'service (spiffe.enabled).' }));
        log.debug('Leaving the SPIFFE bundle endpoint. SPIFFE is off.');
        return;
      }
      try {
        const document = await ca.bundle();
        audit.audit({
          action: 'spiffe.bundle.read', actor: '', protocol: 'SPIFFE',
          channel: 'http', target: ca.trustDomainId(),
          summary: 'The trust bundle was fetched',
          detail: { sequence: document.spiffe_sequence,
                    keys: (document.keys || []).length }
        });
        // `application/json`. The federation specification does not mint a
        // media type of its own — a bundle is a JWK Set — and
        // `application/jwk-set+json` would be defensible and is NOT what SPIRE
        // sends. Matching SPIRE is worth more here than being clever, because
        // the client on the other end was probably written against it.
        res.status(200).type('application/json')
          .set('Cache-Control', 'no-store')
           .send(JSON.stringify(document, null, 2));
        log.debug('Leaving the SPIFFE bundle endpoint. sequence=' +
                  document.spiffe_sequence);
      } catch (e) {
        // The authorities failed to build at startup. 503 rather than 500: it
        // is a state this service can recover from with a restart, and the
        // message says which setting to look at.
        errorCodes.mark(res, 'STS-SPIFFE-0069');
        res.status(503).type('application/json')
          .set('Cache-Control', 'no-store')
           .send(JSON.stringify({ error: 'This service has no trust bundle: ' +
                                         e.message }));
        log.debug('Leaving the SPIFFE bundle endpoint. There is no bundle.');
      }
    });

    // A federated trust domain's bundle, exactly as it was given to this
    // service. Published because a person debugging a federation needs to see
    // what this service actually holds, and because "the bundle I pushed" and
    // "the bundle you are serving to workloads" are two things worth being able
    // to compare.
    app.get('/spiffe/federated/:trustDomain', function (req, res) {
      log.debug('Entering the federated bundle view.');
      const name = String(req.params.trustDomain || '').trim().toLowerCase();
      const entry = ca.federatedBundle(name);
      if (!entry) {
        errorCodes.mark(res, 'STS-SPIFFE-0061');
        res.status(404).type('application/json')
          .set('Cache-Control', 'no-store')
           .send(JSON.stringify({ error: 'This service holds no bundle for ' +
                                         'the trust domain ' + name + '.',
                                  held: ca.federatedBundles().map(function (e) {
                                    return e.trustDomain;
                                  }) }));
        log.debug('Leaving the federated bundle view. Not held.');
        return;
      }
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify(entry.document, null, 2));
      log.debug('Leaving the federated bundle view. trustDomain=' + name);
    });

    app.get('/spiffe', function (req, res) {
      log.debug('Entering the /spiffe view.');
      const document = self.description(req);
      if (String(req.query.format || '') === 'json') {
        res.status(200).type('application/json')
          .set('Cache-Control', 'no-store')
           .send(JSON.stringify(document, null, 2));
        log.debug('Leaving the /spiffe view. JSON.');
        return;
      }
      res.status(200).type('text/html').set('Cache-Control', 'no-store')
         .send(self.page(document));
      log.debug('Leaving the /spiffe view. HTML.');
    });
    log.debug("Leaving SpiffeServer.registerRoutes().");
  }

  // -------------------------------------------------------------------------
  // A REPLACED ROOT RE-KEYS EVERY REALM'S SPIRE SERVER API (2026-09-21).
  //
  // Each realm's API socket presents an SVID minted at `listen()` under the
  // realm's SPIFFE Issuing CA, which chains to the service Root. After
  // `POST /admin-api/pki/build-root` that chain ends at a Root nothing holds,
  // so every mutual-TLS caller holding the new bundle was refused with
  // `unable to get local issuer certificate` until a restart. `tls_server.js`
  // calls this whenever it adopts a re-issued listener certificate, which a
  // Root replacement always causes; a realm branch rebuilt under the SAME
  // Root re-keys too, harmlessly, since the old SVID would still verify.
  // Per realm and never thrown: one realm that could not be re-keyed is
  // reported and the others still are.
  // -------------------------------------------------------------------------
  refreshServerCredentials() {
    const { log, rpc, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.refreshServerCredentials().');
    listeners.forEach(function (entry, realmId) {
      if (!entry.apiCredentials && !entry.brokerCredentials) {
        return;
      }
      self.awaitRealmBranch(realmId).then(function () {
        return self.inRealm(realmId, function () {
          // The Broker endpoint presents the same identity (#170), so it is
          // re-keyed with it.
          return Promise.all([entry.apiCredentials, entry.brokerCredentials]
            .filter(Boolean).map(function (credentials) {
              return rpc.refreshServerApiCredentials(credentials);
            }));
        });
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-SPIFFE-0114') +
                  'spiffe: the "' + (realmId || 'default') + '" realm\'s ' +
                  'SPIRE Server API kept its old certificate after the ' +
                  'service Root changed, so a client holding the new bundle ' +
                  'cannot verify it until a restart: ' +
                  ((e && e.message) || e));
      });
    });
    log.debug('Leaving SpiffeServer.refreshServerCredentials().');
  }

  // ---------------------------------------------------------------------------
  // THE REALM'S BRANCH UNDER THE NEW ROOT BEFORE ANYTHING IS ISSUED FROM IT
  // (2026-09-21). The listener certificate changes the moment a replaced Root
  // arrives here — often from ANOTHER process, whose build-root then rebuilds
  // every realm's branch a few hundred milliseconds later. Re-keying straight
  // away issued from a branch still under the old Root, `pki.issueUnder()`
  // repaired it in THIS process, and the rebuilding process built it too: two
  // Intermediate CAs for one realm, which `sts_pki_distribution_points` found
  // in `single-node`, where no cluster claim serialises the two. The listener
  // already waits for its branch rather than building it (`tls/CLAUDE.md`);
  // this is the same rule for the SPIRE Server API. Bounded: a branch that
  // never arrives is left to `issueUnder()`'s repair, which is what happened
  // before this wait existed.
  // ---------------------------------------------------------------------------
  private awaitRealmBranch(realmId: string): Promise<boolean> {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering SpiffeServer.awaitRealmBranch(). realm=' + realmId);
    const deadline = Date.now() + 30000;
    log.debug('Leaving SpiffeServer.awaitRealmBranch().');
    return new Promise(function (resolve) {
      function look() {
        const current = self.inRealm(realmId, function () {
          return pki.scopeChainsToRoot(realmId);
        });
        if (current) {
          resolve(true);
          return;
        }
        if (Date.now() >= deadline) {
          log.warn(errorCodes.tag('STS-SPIFFE-0115') + 'spiffe: the "' +
                   (realmId || 'default') + '" realm\'s ' +
                   'certificate authority branch did not arrive under the ' +
                   'new Root within 30s; its SPIRE Server API is re-keyed ' +
                   'now, and the branch is repaired in this process.');
          resolve(false);
          return;
        }
        setTimeout(look, 250).unref();
      }
      look();
    });
  }

  // THE WORK LOADING THIS MODULE USED TO DO WITH ITS OWN INSTANCE (#50, R2),
  // run by `common/instance_slot.ts` once for whichever instance is
  // installed, in the order the module used to do it: the realm-change
  // subscription that reconciles the listeners, then the console's reader.
  static wire(instance: SpiffeServer): void {
    helpers.log.debug("Entering SpiffeServer.wire().");
    // A realm created, changed or removed. `realms.setOverride()` fires this,
    // so turning a realm's SPIFFE on is what binds its sockets — see
    // reconcile().
    realms.onChange(function () {
      const running = instance.reconcile();
      if (running && typeof running.catch === 'function') {
        // Never thrown into the caller: this is a notification, and the
        // caller is whoever happened to write a setting. A listener that
        // would not bind is reported on `GET /spiffe` like every other one.
        running.catch(function (e) {
          log.error(errorCodes.tag('STS-SPIFFE-0074') +
                    'spiffe: the listeners could not be reconciled after a ' +
                    'realm changed: ' + e.message);
        });
      }
    });

    // A re-issued listener certificate — a replaced Root — re-keys every
    // realm's SPIRE Server API socket. See refreshServerCredentials().
    if (typeof tlsServer.onServerCertificateChange === 'function') {
      tlsServer.onServerCertificateChange(function () {
        instance.refreshServerCredentials();
      });
    }

    admin.setSpiffeReader(function () {
      const now = instance.bindingsNow();
      // The workload attestation state rides the same reader (#40): it is
      // this module's, and a slot of its own would fail rule 3e's test.
      return { workload: now.workload, api: now.api, broker: now.broker,
               bundlePath: BUNDLE_PATH,
               workloadAttestation: instance.workloadAttestationState() };
    });
    helpers.log.debug("Leaving SpiffeServer.wire().");
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
const slot = new InstanceSlot<SpiffeServer>(
  'spiffe/spiffe_server',
  () => new SpiffeServer(SpiffeServer.defaultDeps()),
  SpiffeServer.wire,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// ---------------------------------------------------------------------------
// **RECONCILE, AND WHY IT IS NOT A RESTART.**
//
// A realm's SPIFFE is turned on by writing `spiffe.enabled` on the realm, and
// `realms.setOverride()` fires `realms.onChange()` for it — so this is called
// with no new mechanism and no polling. What it does is the difference
// between the set of realms that SHOULD have sockets and the set that HAS
// them, in both directions.
//
// **ONLY THE PROCESS THAT BOUND THEM RECONCILES.** In a dispatched service the
// request workers load this module too, and they bind nothing: `listen()` is
// called from `server.js` alone. `started` is the guard, and without it a
// worker would try to bind the realm's sockets the moment a realm changed —
// four listeners per worker, all but one failing, and the one that succeeded
// answering in a process whose own listeners nobody meant to exist.
// ---------------------------------------------------------------------------
// **RECONCILES RUN ONE AT A TIME, AND THAT IS NOT TIDINESS.** Two of them
// overlap in the ordinary case — `realms.setOverride()` fires the change
// notification and a caller that wants to know the sockets are up asks for one
// itself — and each computes the difference between what is wanted and what is
// BOUND. A realm's entry appears only once its `startRealm()` has begun
// awaiting, so two overlapping passes both decided the realm was missing and
// both bound it: `EADDRINUSE` on a socket path created seconds earlier, with
// the second pass's failed bindings overwriting the first's working ones.
//
// So the queue, and it is also what makes `await reconcile()` mean what a
// caller expects: everything asked for up to this point has been done.
let pending = Promise.resolve([]);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: (target: any): void => slot.get().registerRoutes(target),
  SpiffeServer: SpiffeServer,
  installInstance: (instance: SpiffeServer): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  listen: slot.forward('listen'),
  close: slot.forward('close'),
  description: slot.forward('description'),
  // What is attested on the Workload API, for `server.js`'s startup line as
  // well as `/spiffe` (#40): a banner that ASSERTS what this service checks
  // goes stale the day the answer changes, and this one did.
  workloadAttestationState: slot.forward('workloadAttestationState'),
  BUNDLE_PATH: BUNDLE_PATH,
  bindings: function () {
    log.debug("Entering bindings().");
    log.debug("Leaving bindings().");
    return slot.get().bindingsNow();
  },
  // What a test and `/spiffe` need that the two flat lists cannot carry: which
  // realms have sockets at all. Exported rather than derived from the rows
  // because a realm whose every binding FAILED is still a realm with SPIFFE
  // turned on, and the two states need telling apart.
  realmsListening: function () {
    log.debug("Entering realmsListening().");
    log.debug("Leaving realmsListening().");
    return Array.from(listeners.keys());
  },
  reconcile: slot.forward('reconcile')
};
