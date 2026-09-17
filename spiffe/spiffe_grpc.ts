'use strict';
//
// File: spiffe_grpc.ts
//
// ---------------------------------------------------------------------------
// THE gRPC PLUMBING BOTH SPIFFE SURFACES SIT ON: loading the vendored `.proto`
// files, binding the listeners, the one header check the Workload Endpoint
// specification requires, and turning an ordinary thrown Error into a gRPC
// status.
//
// It is a LIBRARY: it registers no HTTP route, and it holds no protocol
// knowledge — `spiffe_workload.ts` and `spiffe_api.ts` are the two callers and
// each brings its own handlers. It requires `helpers.js`, `config.js`,
// `audit.js` and `admin_stats.js`, none of which requires it back.
//
// ---------------------------------------------------------------------------
// WHY `@grpc/grpc-js` IS A DEPENDENCY HERE, IN A PACKAGE THAT IS DELIBERATELY
// SHORT
//
// The argument this repository makes against `swagger-ui-dist` (see
// `mgmt-api/admin_api_docs.ts`) is a real argument and it was made again here,
// in the other direction. The Workload API is gRPC over HTTP/2 with protobuf
// framing; this service already hand-rolls ASN.1, NDR and a Kerberos PAC, so a
// hand-rolled protobuf codec and a gRPC server over node's built-in `http2`
// was a genuine option — around 900 lines, no dependency.
//
// It was not taken, and the reason is what this whole service is FOR. A mock
// exists to be talked to by REAL clients: `go-spiffe`, `spiffe-helper`, a SPIRE
// agent, the `spire-server` CLI. An interoperability bug in a hand-rolled
// HTTP/2 framer does not announce itself as a framing bug — it appears as a
// client that hangs, or that reports a truncated message, and the client author
// debugging it has no way to tell whether the fault is theirs or ours. That is
// the exact failure this service exists to prevent somebody suffering. The
// explorer script traded a familiar look for 11.7 MB; this trades ~30 packages
// for the wire being right.
//
// ---------------------------------------------------------------------------
// THE `.proto` FILES ARE VENDORED AND ARE LOAD-BEARING
//
// `protos/workloadapi.proto` is a verbatim copy of the SPIFFE project's own,
// and `protos/spire/**` of the `spire-api-sdk`'s. They are read AT REQUIRE
// TIME, at module scope, and a missing one is not a degraded feature — this
// module does not load. That is the same decision `bbs2023.js` makes about
// `contexts/`, and for a similar reason: a service that advertised the Workload
// API and then answered `Unimplemented` because a file was missing would be
// worse than one that did not start.
//
// **Do not edit them.** They are somebody else's files, and the whole value of
// the dependency above is that the wire matches what a real client expects.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SpiffeGrpc` takes the modules it uses through its constructor
// (`SpiffeGrpcDeps`), and since #50's R2 the composition root builds the
// instance and installs it here. The module still exports its old names as
// FACADES forwarding to it, for the callers that are not converted; a process
// without the root builds a default when this module loads. `SpiffeGrpc` is
// exported for the root.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import grpc = require('@grpc/grpc-js');
import loader = require('@grpc/proto-loader');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log } = helpers;
import config = require('../common/config');
// THE REALM REGISTRY, for the one thing an operation has to carry that this
// file did not know about when the operation seam was written — see
// `methodRequest()`. A LIBRARY (rule 3), loaded by `app.js` long before this
// module, so requiring it registers nothing.
import realms = require('../common/realms');
import audit = require('../common/audit');
// THE ERROR CODES. A LEAF. A handler records which condition a refusal is by
// marking the CALL on the line before it throws — `mark()` puts the code on the
// object under a Symbol, which is never serialised — and the wrappers below
// read it back into the one audit row the call already gets. The status the
// client receives is unchanged: `errorToStatus()` builds `{ code, details }`
// and nothing else.
import errorCodes = require('../common/error_codes');
import stats = require('../common/admin_stats');
// WHO IS CALLING. A library that decides and never answers — see its header —
// which is why this module maps its refusal descriptors onto statuses below
// rather than that one building a gRPC error. The require is the ordinary
// direction and closes no cycle: nothing it requires reaches back here.
import auth = require('./spiffe_auth');
import authn = require('../authn/authn');
// THE ACCESS GATE, armed by `xacml/xacml_access_pep.ts` at 23c. A LEAF
// (rule 3): with no decider installed `check()` answers "allowed", so a
// process without the XACML family behaves exactly as this file did before.
import accessGate = require('../common/access_gate');
import nodeCrypto = require('crypto');
// For the server's own SVID and the roots it verifies clients against. Both
// register nothing, so neither can move a route or close a cycle.
import spiffeId = require('./spiffe_id');
import ca = require('./spiffe_ca');

// ---------------------------------------------------------------------------
// LOADING.
//
// `keepCase: true` is the one option here that is not a default and it is
// load-bearing: without it, `spiffe_id` on the wire becomes `spiffeId` in the
// handler and `x509_svid_key` becomes `x509SvidKey`. Both spellings work as
// long as EVERY site uses the same one — which is exactly the kind of thing
// that is true until somebody writes one field by hand. The field names in the
// handlers below are therefore the field names in the `.proto` files, and a
// reader can compare them line for line.
//
// `longs: String` because `expires_at` is an int64 and JavaScript numbers are
// not. A protobuf int64 arriving as a `Long` object that stringifies to
// something unexpected is a class of bug that shows up as a certificate
// expiring in 1970.
// ---------------------------------------------------------------------------
const PROTO_DIR = path.join(__dirname, 'protos');

const LOAD_OPTIONS = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [PROTO_DIR]
};

const WORKLOAD_PROTO = 'workloadapi.proto';

const SERVER_PROTOS = [
  'spire/api/server/entry/v1/entry.proto',
  'spire/api/server/agent/v1/agent.proto',
  'spire/api/server/bundle/v1/bundle.proto',
  'spire/api/server/svid/v1/svid.proto',
  'spire/api/server/trustdomain/v1/trustdomain.proto',
  'spire/api/server/debug/v1/debug.proto'
];

// What `SpiffeGrpc` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface SpiffeGrpcDeps {
  fs: typeof fs;
  path: typeof path;
  grpc: typeof grpc;
  loader: typeof loader;
  log: typeof log;
  config: typeof config;
  realms: typeof realms;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  stats: typeof stats;
  auth: typeof auth;
  authn: typeof authn;
  accessGate: typeof accessGate;
  nodeCrypto: typeof nodeCrypto;
  spiffeId: typeof spiffeId;
  ca: typeof ca;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadRequestPool(): typeof import('../common/request_pool');
  loadRequestWorker(): typeof import('../common/request_worker');
}

// The services `SpiffeGrpc.wire()` names.
type ServiceName = 'workload' | 'entry' | 'agent' | 'bundle' | 'svid' |
  'trustdomain' | 'debug';

class SpiffeGrpc {
  constructor(private readonly deps: SpiffeGrpcDeps) {
    deps.log.debug("Entering SpiffeGrpc.constructor().");
    deps.log.debug("Leaving SpiffeGrpc.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): SpiffeGrpcDeps {
    helpers.log.debug("Entering SpiffeGrpc.defaultDeps().");
    helpers.log.debug("Leaving SpiffeGrpc.defaultDeps().");
    return {
      fs: fs,
      path: path,
      grpc: grpc,
      loader: loader,
      log: log,
      config: config,
      realms: realms,
      audit: audit,
      errorCodes: errorCodes,
      stats: stats,
      auth: auth,
      authn: authn,
      accessGate: accessGate,
      nodeCrypto: nodeCrypto,
      spiffeId: spiffeId,
      ca: ca,
      loadRequestPool: function () {
        return require('../common/request_pool');
      },
      loadRequestWorker: function () {
        return require('../common/request_worker');
      }
    };
  }

  // THE WORK LOADING THIS MODULE USED TO DO WITH ITS OWN INSTANCE (#50, R2),
  // run by `common/instance_slot.ts` once for whichever instance is
  // installed: loading the vendored protos and naming the services, and
  // refusing to go on when one is missing.
  static wire(instance: SpiffeGrpc): void {
    helpers.log.debug("Entering SpiffeGrpc.wire().");
    const DEFINITIONS = instance.loadDefinitions();
    const services = {
      workload: DEFINITIONS.workload['SpiffeWorkloadAPI'],
      entry: DEFINITIONS.server['spire.api.server.entry.v1.Entry'],
      agent: DEFINITIONS.server['spire.api.server.agent.v1.Agent'],
      bundle: DEFINITIONS.server['spire.api.server.bundle.v1.Bundle'],
      svid: DEFINITIONS.server['spire.api.server.svid.v1.SVID'],
      trustdomain:
        DEFINITIONS.server['spire.api.server.trustdomain.v1.TrustDomain'],
      debug: DEFINITIONS.server['spire.api.server.debug.v1.Debug']
    };
    SERVICES = services;
    Object.keys(services).forEach(function (name) {
      if (!services[name]) {
        helpers.log.debug("Leaving SpiffeGrpc.wire(). " + name +
                          " missing.");
        throw new Error('spiffe: the ' + name + ' service is not in the ' +
                        'vendored protos. This is a build problem rather ' +
                        'than a runtime one — see protos/ and the note at ' +
                        'the top of spiffe_grpc.js.');
      }
    });
    helpers.log.debug("Leaving SpiffeGrpc.wire().");
  }

  loadDefinitions() {
    const { log, loader } = this.deps;
    log.debug('Entering SpiffeGrpc.loadDefinitions().');
    const workload = loader.loadSync(WORKLOAD_PROTO, LOAD_OPTIONS);
    const server = loader.loadSync(SERVER_PROTOS, LOAD_OPTIONS);
    log.debug('Leaving SpiffeGrpc.loadDefinitions().');
    return { workload: workload, server: server };
  }

  // What each surface publishes, for `/spiffe` and `/admin/sts-metadata` —
  // which cannot see a gRPC method any more than they can see a raw socket, so
  // the list is built HERE from the loaded definitions rather than typed out. A
  // method that exists and goes undescribed is the drift `sts_metadata.js`
  // exists to prevent, and this is the only way to have the same property for a
  // surface Express knows nothing about.
  methodsOf(serviceName) {
    const { log } = this.deps;
    log.debug("Entering SpiffeGrpc.methodsOf().");
    const service = SERVICES[serviceName];
    log.debug("Leaving SpiffeGrpc.methodsOf().");
    return Object.keys(service).map(function (key) {
      const method = service[key];
      return {
        name: method.originalName || key,
        path: method.path,
        requestStream: !!method.requestStream,
        responseStream: !!method.responseStream
      };
    }).sort(function (a, b) { return a.name.localeCompare(b.name); });
  }

  securityHeaderPresent(call) {
    const { log } = this.deps;
    log.debug("Entering SpiffeGrpc.securityHeaderPresent().");
    const metadata = call && call.metadata;
    if (!metadata) {
      log.debug("Leaving SpiffeGrpc.securityHeaderPresent().");
      return false;
    }
    const values = metadata.get(SECURITY_HEADER) || [];
    for (let i = 0; i < values.length; i++) {
      if (String(values[i]).trim().toLowerCase() === 'true') {
        log.debug("Leaving SpiffeGrpc.securityHeaderPresent().");
        return true;
      }
    }
    log.debug("Leaving SpiffeGrpc.securityHeaderPresent().");
    return false;
  }

  // ---------------------------------------------------------------------------
  // TURNING A THROWN ERROR INTO A STATUS.
  //
  // Every handler below is written as though it may throw, and this is the
  // single place a throw becomes an answer. That is the same funnel argument
  // `helpers.signJwt()` makes about counting tokens: a status built at each of
  // forty-two call sites is forty-one that are right and one that reports
  // `Unknown` for an argument problem.
  //
  // A handler may throw a plain Error — which becomes `Unknown` and is LOGGED
  // as a defect, because an unclassified error in a mock is a bug in the mock —
  // or one carrying a `.code`, built by `statusError()` below, which is what
  // every deliberate refusal uses.
  // ---------------------------------------------------------------------------
  // error-code: none — the constructor every refusal is built with; each caller
  // marks its own condition
  statusError(code, message) {
    const { log } = this.deps;
    log.debug("Entering SpiffeGrpc.statusError().");
    const err: any = new Error(message);
    err.code = code;
    log.debug("Leaving SpiffeGrpc.statusError().");
    return err;
  }

  // error-code: none — the definition of this helper, not a call to it
  invalidArgument(message) {
    const { log, grpc } = this.deps;
    log.debug("Entering SpiffeGrpc.invalidArgument().");
    log.debug("Leaving SpiffeGrpc.invalidArgument().");
    // error-code: none — a constructor; the caller marks the condition
    return this.statusError(grpc.status.INVALID_ARGUMENT, message);
  }

  // error-code: none — the definition of this helper, not a call to it
  notFound(message) {
    const { log, grpc } = this.deps;
    log.debug("Entering SpiffeGrpc.notFound().");
    log.debug("Leaving SpiffeGrpc.notFound().");
    // error-code: none — a constructor; the caller marks the condition
    return this.statusError(grpc.status.NOT_FOUND, message);
  }

  // error-code: none — the definition of this helper, not a call to it
  permissionDenied(message) {
    const { log, grpc } = this.deps;
    log.debug("Entering SpiffeGrpc.permissionDenied().");
    log.debug("Leaving SpiffeGrpc.permissionDenied().");
    // error-code: none — a constructor; the caller marks the condition
    return this.statusError(grpc.status.PERMISSION_DENIED, message);
  }

  // error-code: none — the definition of this helper, not a call to it
  unavailable(message) {
    const { log, grpc } = this.deps;
    log.debug("Entering SpiffeGrpc.unavailable().");
    log.debug("Leaving SpiffeGrpc.unavailable().");
    // error-code: none — a constructor; the caller marks the condition
    return this.statusError(grpc.status.UNAVAILABLE, message);
  }

  // WHICH CODE THE AUDIT ROW FOR A FAILED CALL CARRIES. A throw that is not a
  // status error is a defect (see errorToStatus() just below), and has a code
  // of its own whatever was marked; otherwise it is what the handler marked on
  // the call, or '' — which means the condition was already recorded on a row
  // of its own (an authorization refusal, a JWT-SVID refused at
  // ValidateJWTSVID) and a second coded row would count one refusal twice.
  failureCodeOf(call, err) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SpiffeGrpc.failureCodeOf().");
    if (!err || typeof err.code !== 'number') {
      log.debug("Leaving SpiffeGrpc.failureCodeOf().");
      return 'STS-SPIFFE-0001';
    }
    log.debug("Leaving SpiffeGrpc.failureCodeOf().");
    return errorCodes.codeOf(call);
  }

  errorToStatus(err, where) {
    const { log, errorCodes, grpc } = this.deps;
    log.debug("Entering SpiffeGrpc.errorToStatus().");
    if (err && typeof err.code === 'number') {
      log.debug("Leaving SpiffeGrpc.errorToStatus().");
      return { code: err.code, details: err.message };
    }
    log.error(errorCodes.tag('STS-SPIFFE-0001') +
              'spiffe: ' + where + ' threw something that was not a status ' +
              'error, which is a defect in this service rather than in the ' +
              'call: ' + (err && err.stack ? err.stack : err));
    log.debug("Leaving SpiffeGrpc.errorToStatus().");
    return { code: grpc.status.UNKNOWN,
             details: (err && err.message) || 'Something went wrong.' };
  }

  // ---------------------------------------------------------------------------
  // WRAPPING A HANDLER.
  //
  // Every method goes through here, and it does five things that would
  // otherwise be written forty-two times:
  //
  //   * refuses everything when `spiffe.enabled` is off, with `Unavailable` and
  //     a message naming the setting. Read per call, so the switch works
  //     without a restart;
  //   * checks the security header, on the Workload API only — the SPIRE Server
  //     API has no such requirement and adding one would refuse every real
  //     `spire-server` client;
  //   * logs the call at debug, which is what this service is for;
  //   * records it, so `/admin/metrics` counts a gRPC call the way it counts an
  //     HTTP one and `/admin/audit` has a row;
  //   * turns a throw into a status.
  //
  // **A STREAMING METHOD IS NOT A UNARY ONE AND THE TWO ARE WRAPPED
  // SEPARATELY.** The Workload API's `FetchX509SVID` is a server stream that a
  // real client keeps open for the life of the process, expecting a new message
  // whenever the SVID rotates. Wrapping it as though it were unary — write
  // once, call `end()` — is the single most common way to build a Workload API
  // that appears to work: `go-spiffe`'s first fetch succeeds and the client
  // then treats the stream ending as an error and reconnects in a tight loop.
  // ---------------------------------------------------------------------------
  enabled() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeGrpc.enabled().");
    log.debug("Leaving SpiffeGrpc.enabled().");
    return !!config.value('spiffe.enabled');
  }

  requireSecurityHeader() {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeGrpc.requireSecurityHeader().");
    log.debug("Leaving SpiffeGrpc.requireSecurityHeader().");
    return !!config.value('spiffe.requireSecurityHeader');
  }

  // A refusal descriptor from `spiffe_auth.ts` — `{ status, message }` where
  // `status` is the NAME of a grpc-js status — becomes a status error here. The
  // mapping is in one place so that module can stay ignorant of the transport,
  // and an unknown name becomes PERMISSION_DENIED rather than UNKNOWN: a
  // misspelt status in a refusal must still refuse.
  fromDescriptor(descriptor) {
    const { log, grpc, errorCodes } = this.deps;
    log.debug("Entering SpiffeGrpc.fromDescriptor().");
    const code = grpc.status[descriptor.status];
    if (typeof code !== 'number') {
      log.error(errorCodes.tag('STS-SPIFFE-0004') +
                'spiffe: spiffe_auth.js returned the status name "' +
                descriptor.status +
                '", which grpc-js does not have. Refusing ' +
                'with PERMISSION_DENIED; this is a defect in this service.');
      log.debug("Leaving SpiffeGrpc.fromDescriptor().");
      // The refusal STS-SPIFFE-0004 above describes.
      return this.statusError(grpc.status.PERMISSION_DENIED,
                              descriptor.message);
    }
    log.debug("Leaving SpiffeGrpc.fromDescriptor().");
    // error-code: none — a translation; the descriptor's own errorCode was
    // recorded by prepareCall()
    return this.statusError(code, descriptor.message);
  }

  // ---------------------------------------------------------------------------
  // EVERY CALL PASSES THROUGH HERE, AND IT IS THE ONLY PLACE AUTHORIZATION
  // HAPPENS.
  //
  // Four checks and one side effect, in an order that matters:
  //
  //   1. is SPIFFE on at all;
  //   2. the Workload API's security header (that surface only — the SPIRE
  //      Server API has no such requirement and adding one would refuse every
  //      real `spire-server` client);
  //   3. WHO IS CALLING, built once and attached to the call as `spiffeCaller`
  //      so a handler can read it without building it a second way;
  //   4. whether that caller may call THIS method, against SPIRE's own table.
  //
  // The side effect is the identity: an ACCEPTED credential reaches
  // `stats.recordAuthentication()` through `auth.recordCaller()`, once per
  // connection, so the holder of an SVID appears on /admin/users and in the
  // directory beside everybody else who has authenticated here.
  //
  // **It is here rather than in forty-two handlers** for the reason
  // `helpers.signJwt()` is the single token counter: forty-two call sites is
  // forty-one that are right and a forty-second added later with no check at
  // all. A caller is built for the Workload API too, even though nothing
  // authorizes on it there, because that surface derives its SELECTORS from the
  // same object.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE SESSION FOR A SPIRE SERVER API CALLER, and then the policy about it.
  //
  // **THE SESSION IS `authn.startSession()` AND NOT A REGISTER OF THIS
  // FILE'S**, for the reason `scim_auth.js` gives at its own funnel: that
  // function owns every session this service holds, and a second store for API
  // callers would be a second answer to "is somebody signed in". `detail.key`
  // is what makes it work for a credential presented on every call — the same
  // SVID touches the session it already has rather than minting one per RPC,
  // which on a busy agent would be a row a second.
  //
  // The key is the SPIFFE ID and not the certificate: an agent that rotates its
  // SVID mid-run is the same agent on the same surface, and keying on the
  // certificate would give it a second row and leave the first until it
  // expired. It is hashed because a session id is printed on `/admin/sessions`.
  //
  // **A CALLER THAT AUTHENTICATED NOBODY GETS NO SESSION.** The local Unix
  // socket is trusted by path and presents no credential, and a caller on a
  // port where nothing is checked presents none either. Both reach here with
  // `authenticated` false, and a session recording that somebody signed in
  // would be untrue.
  // ---------------------------------------------------------------------------
  sessionForCaller(caller) {
    const { log, nodeCrypto, authn, errorCodes } = this.deps;
    log.debug('Entering SpiffeGrpc.sessionForCaller().');
    if (!caller || !caller.authenticated || !caller.spiffeId) {
      log.debug('Leaving SpiffeGrpc.sessionForCaller(). Nobody authenticated.');
      return null;
    }
    try {
      const key = nodeCrypto.createHash('sha256')
        .update('spire-server-api ' + String(caller.spiffeId))
        .digest('hex').slice(0, 24);
      const session = authn.startSession(
        { set: function () {}, req: null }, caller.spiffeId,
        ['swk'], '1', 'SPIRE Server API',
        { key: key, cookie: false,
          summary: caller.spiffeId + ' authenticated at the SPIRE Server API ' +
                   'with an X509-SVID over mutual TLS; session created',
          note: 'An X509-SVID was presented over mutual TLS and accepted. ' +
                'This session is a RECORD that it was, not a thing that can ' +
                'be presented in its place: every call authenticates again.' });
      log.debug('Leaving SpiffeGrpc.sessionForCaller(). ' +
                (session ? session.id : 'none'));
      return session;
    } catch (error) {
      // Nothing about recording a session may be able to fail a call.
      log.error(errorCodes.tag('STS-SPIFFE-0006') +
                'spiffe: a session could not be recorded and the call is ' +
                'unaffected: ' + error.message);
      log.debug('Leaving SpiffeGrpc.sessionForCaller(). It threw.');
      return null;
    }
  }

  // The gate, in a refusal shape `authorize()`'s caller already understands.
  // Null means permitted, which is what that function returns too — so the `||`
  // at the call site reads as "SPIRE's rule, then ours".
  policyRefusal(caller, method) {
    const { log, accessGate, auth } = this.deps;
    log.debug('Entering SpiffeGrpc.policyRefusal(). method=' + method);
    // -----------------------------------------------------------------------
    // THE POLICY DECIDES ABOUT A CALLER THIS SERVICE CAN NAME, AND THIS SURFACE
    // HAS CALLERS IT CANNOT (2026-09-10).
    //
    // **THIS IS THE ONE GATED SURFACE WHERE AN ANONYMOUS CALLER IS THE
    // SPECIFICATION RATHER THAN A MISTAKE.** The SPIRE Server API's TCP port
    // asks for a client certificate and does not require one, because
    // `AttestAgent` has to be reachable by an agent that HAS NO SVID YET and
    // `GetBundle` by whoever is about to trust this trust domain. Both are
    // marked `any` in SPIRE's own table in `spiffe_auth.ts`, copied from that
    // project's `policy_data.json`, and `authorize()` above has already let
    // them through by the time this runs.
    //
    // The built-in `access-control` policy then refused them. Its
    // `requireAuthenticated` conjunct is ON by default and is CORRECT for what
    // it was written for — the sign-in screen's "continue without signing in"
    // session, which is a real subject that declined to authenticate and has no
    // business on the console, the management API, the portal or SCIM. A caller
    // here that presented nothing is not that: it is not a subject at all,
    // there is no session and no name, and the policy was being asked to decide
    // about nobody. It answered Deny, so the bootstrap of the whole trust
    // domain was closed on an unedited service — while `xacml.enforceAccess`'s
    // own description promised that the layer "changes nothing on an unedited
    // service", and the note at the call site below said the built-in document
    // "permits, because it asks for a role only where somebody has required
    // one". Three places said one thing and the service did another.
    //
    // So the question is asked about a caller with a NAME, and skipped for one
    // without. Nothing is widened by that: every method SPIRE's table restricts
    // is refused BEFORE this runs, with UNAUTHENTICATED when nothing was
    // presented — so the only calls this exempts are the ones SPIRE itself
    // defines as open to anybody. An operator narrowing this surface by policy
    // is unaffected, because a policy about a named subject is still asked.
    //
    // It also restored what `spiffe.authRequired` off was documented to mean,
    // while that setting existed. With it off `authorize()` returned null
    // without consulting the table at all, so EVERY method reached this gate
    // with an unauthenticated caller and was refused — turning the mock's own
    // "nothing is checked" switch into the most closed configuration it has.
    // -----------------------------------------------------------------------
    if (!caller || !caller.authenticated || !caller.spiffeId) {
      log.debug('Leaving SpiffeGrpc.policyRefusal(). No subject to decide ' +
                'about.');
      return null;
    }
    const session = this.sessionForCaller(caller);
    const answer = accessGate.check({
      resource: accessGate.RESOURCE.SPIRE_SERVER_API,
      // EVERY METHOD IS `write` AND THAT IS NOT LAZINESS. What comes out of
      // this surface is a credential another service will believe — SPIRE's own
      // table is where read and write are told apart, per method, and it has
      // already run. A second, coarser split here would invite a policy author
      // to think
      // `read` on this resource meant something SPIRE agrees with.
      action: accessGate.ACTION.WRITE,
      subject: { name: caller.spiffeId || '',
                 authenticated: !!caller.authenticated,
                 sessionId: session ? session.id : null },
      context: { method: method, transport: caller.transport || '' }
    });
    if (answer.allowed) {
      log.debug('Leaving SpiffeGrpc.policyRefusal(). Permitted.');
      return null;
    }
    log.info('spiffe: the access policy refused ' + method + ' for ' +
             auth.describeCaller(caller) + '. ' + answer.why);
    log.debug('Leaving SpiffeGrpc.policyRefusal(). Refused.');
    return { status: 'PERMISSION_DENIED', errorCode: 'STS-SPIFFE-0005',
             message: 'The access policy refused this call. ' + answer.why +
                      ' This is a POLICY decision rather than SPIRE\'s own ' +
                      'per-method rule, which allowed it. The document is on ' +
                      '/admin/xacml and xacml.enforceAccess turns the layer ' +
                      'off.' };
  }

  prepareCall(call, surface, method) {
    const { log, auth, errorCodes, audit } = this.deps;
    log.debug('Entering SpiffeGrpc.prepareCall(). surface=' + surface +
              ', method=' +
              method);
    if (!this.enabled()) {
      log.debug('Leaving SpiffeGrpc.prepareCall(). SPIFFE is off.');
      return { caller: null, errorCode: 'STS-SPIFFE-0002',
               refusal:
                 this.unavailable('SPIFFE is turned off on this service ' +
                         '(spiffe.enabled). The listeners are still bound ' +
                         'and GET /spiffe still says what this is; nothing ' +
                         'will be issued until it is turned back on, which ' +
                         'needs no restart.') };
    }
    if (surface === 'workload' && this.requireSecurityHeader() &&
        !this.securityHeaderPresent(call)) {
      log.debug('Leaving SpiffeGrpc.prepareCall(). No security header.');
      return { caller: null, errorCode: 'STS-SPIFFE-0003',
               refusal:
                 this.invalidArgument('Every call to the SPIFFE Workload API ' +
                             'must carry the metadata header "' +
                             SECURITY_HEADER + ': true" (SPIFFE Workload ' +
                             'Endpoint specification). This one did not. ' +
                             'Every conforming Workload API will refuse it, ' +
                             'which is why this mock does too; ' +
                             'spiffe.requireSecurityHeader turns the check ' +
                             'off if you are deliberately testing something ' +
                             'else.') };
    }
    const caller = auth.callerOf(call, surface);
    if (surface === 'workload') {
      // What this service can see about a Workload API caller, as selectors.
      // Built HERE rather than in the handlers because all four issuing methods
      // must answer the same question the same way — a FetchX509SVID that
      // returned three identities and a FetchJWTSVID that returned one would be
      // a mock contradicting itself.
      caller.selectors = auth.workloadSelectors(call, caller);
    }
    // Attached to the call rather than threaded through every handler
    // signature.
    // `call` is the one object every handler already has, the property name
    // says whose it is, and a handler that does not care is unaffected.
    try {
      call.spiffeCaller = caller;
    } catch (e) {
      // A frozen call object would be a grpc-js change rather than anything a
      // caller did. The check still runs; only the handlers lose the detail.
      log.error(errorCodes.tag('STS-SPIFFE-0007') +
                'spiffe: the caller could not be attached to the call (' +
                e.message + '), so handlers will see none.');
    }
    if (surface === 'server') {
      const refusal = auth.authorize(caller, method) ||
        // -------------------------------------------------------------------
        // THE POLICY, AFTER SPIRE'S OWN TABLE AND NOT INSTEAD OF IT
        // (2026-09-06).
        //
        // `authorize()` above is SPIRE's per-method rule, copied from its
        // `policy_data.json`, and it is unchanged: what an agent may call is
        // that project's answer and not this service's to reinvent. The gate is
        // the layer ABOVE it, so a deployment can narrow this surface by
        // POLICY — and on an unedited service the built-in document permits,
        // because it asks for a role only where somebody has required one.
        //
        // **AFTER, so the refusal a caller sees is the most specific one.**
        // "your SVID is not an admin and this method is admins only" is a
        // sentence somebody can act on; "the policy denied it" is not, and
        // reaching the second first would hide the first for every ordinary
        // misconfiguration.
        // -------------------------------------------------------------------
        this.policyRefusal(caller, method);
      if (refusal) {
        // The refusal is audited with the identity that was refused, which is
        // the row somebody debugging "why can my agent not list entries" needs.
        // No credential goes in it — a SPIFFE ID is a name, not a secret, and
        // the certificate itself is never recorded.
        audit.audit({
          action: 'spiffe.call.refuse', actor: caller.spiffeId || '',
          protocol: 'SPIRE Server API', channel: 'grpc', target: method,
          // WHICH CONDITION, from the descriptor that decided it. This row is
          // the one that carries the code, so the call's own row below does
          // not.
          errorCode: refusal.errorCode || 'STS-SPIFFE-0015',
          summary: method + ' was refused for ' + auth.describeCaller(caller),
          detail: { status: refusal.status,
                    caller: auth.describeCaller(caller) }
        });
        log.debug('Leaving SpiffeGrpc.prepareCall(). Not authorized.');
        return { caller: caller, refusal: this.fromDescriptor(refusal),
                 errorCode: '' };
      }
    }
    // An accepted credential is an authentication, and this is where it is
    // recorded — at the moment it was ACCEPTED, which is the rule every other
    // family here follows. A caller that presented nothing records nothing:
    // being allowed because a method is open is not authenticating.
    auth.recordCaller(caller);
    log.debug('Leaving SpiffeGrpc.prepareCall(). Allowed.');
    return { caller: caller, refusal: null };
  }

  // The audit and metrics row for one gRPC call. `channel: 'grpc'` is a new one
  // beside http, ldap, ldaps and internal, and it is a channel rather than a
  // protocol for the same reason those are: it says HOW the call arrived, which
  // is the question a reader of a mixed log is asking.
  // `errorCode` is the condition a refused call was refused for — see
  // failureCodeOf() — and '' for a success or for a refusal already recorded on
  // a row of its own.
  recordCall(surface, method, ok, detail, caller, errorCode?) {
    const { log, stats, errorCodes, audit } = this.deps;
    log.debug('Entering SpiffeGrpc.recordCall().');
    try {
      // ONE OBJECT, the shape `app.js`'s call log passes. This passed three
      // positional arguments until 2026-09-16, so every gRPC call was counted
      // on one row keyed "undefined undefined" with status 0xx; the type
      // checker (#50) found it.
      stats.recordCall({ method: 'GRPC', path: 'grpc:' + method, matched: true,
                         status: ok ? 200 : 500, durationMs: 0 });
    } catch (e) {
      // Statistics must never be able to fail a call — the same rule the JWT
      // recorder follows in helpers.js.
      log.error(errorCodes.tag('STS-SPIFFE-0008') +
                'spiffe: recording a gRPC call threw and was ignored: ' +
                e.message);
    }
    const code = ok ? '' : String(errorCode || '');
    audit.audit({
      action: 'protocol.call',
      // The identity that made the call, where one was accepted. Empty for an
      // anonymous or local caller, which is most of the Workload API — an audit
      // row must not imply an identity nothing established.
      actor: (caller && caller.authenticated) ? caller.spiffeId : '',
      protocol: surface === 'workload' ? 'SPIFFE Workload API' :
                'SPIRE Server ' +
          'API',
      channel: 'grpc',
      target: method,
      errorCode: code,
      // A handler that failed rather than refused is this service failing, and
      // is recorded as an error; every other coded row defaults to a refusal.
      outcome: code === 'STS-SPIFFE-0001' ? 'error' : undefined,
      summary: (ok ? 'A ' : 'A refused ') + surface + ' gRPC call: ' + method,
      detail: detail || {}
    });
    log.debug('Leaving SpiffeGrpc.recordCall().');
  }

  methodKind(surface, method) {
    const { log } = this.deps;
    log.debug("Entering SpiffeGrpc.methodKind().");
    log.debug("Leaving SpiffeGrpc.methodKind().");
    return 'spiffe.' + surface + '.' + method;
  }

  // The pool, required LAZILY. `spiffe_server.ts` sits at 23 in the require
  // order and the pool is loaded by `app.js` above every route, so a top-level
  // require would be this family reaching up into the process's own bootstrap.
  // By the time a gRPC call arrives it is a cache hit.
  requestPool() {
    const { log, loadRequestPool } = this.deps;
    log.debug("Entering SpiffeGrpc.requestPool().");
    try {
      log.debug("Leaving SpiffeGrpc.requestPool().");
      return loadRequestPool();
    } catch (e) {
      log.debug("Caught in SpiffeGrpc.requestPool(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffeGrpc.requestPool().");
      // A process with no pool module cannot dispatch, which is the ordinary
      // state of every in-process loader of this tree.
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // WHAT A WORKER IS STUCK TO: NOTHING, DELIBERATELY.
  //
  // LDAP operations hold affinity to the CONNECTION, because RFC 4511 makes the
  // connection the unit of authorization state and a client may have several
  // operations outstanding on one. **A unary gRPC call is the opposite**: it
  // carries its own credential — an X509-SVID, or the socket it arrived on —
  // and is answered on its own. Nothing about one has to be remembered to
  // answer the next, which is the same property `/scim`, `/xacml` and
  // `/admin-api` have and the reason those three are the HTTP side's fanout
  // list.
  //
  // So these FAN OUT, and the read barrier is what makes a write visible to the
  // next call, exactly as it is for a dispatched path.
  // ---------------------------------------------------------------------------
  // WHAT THE WORKER IS SENT, as a function of its own so that a test can drive
  // it. It was inline in `dispatchUnary()` until a mutant that sent `caller:
  // null` survived — the test was building the shape itself and therefore
  // asserting `structuredClone()` rather than this.
  methodRequest(call) {
    const { log, realms } = this.deps;
    log.debug("Entering SpiffeGrpc.methodRequest().");
    log.debug("Leaving SpiffeGrpc.methodRequest().");
    return {
      // THE REQUEST AS THE CODEC DECODED IT. It crosses by node's IPC advanced
      // serialization, so the `bytes` fields in it stay Buffers — see
      // `request_pool.js`'s fork options for what the default JSON channel did
      // to one.
      request: call.request,
      // THE CALLER, WHICH IS THE ONE THING A WORKER COULD NOT WORK OUT. It is
      // already plain: `callerOf()` renders both DNs with `dnRfc4514()` and
      // everything else on it is a string, a boolean or an array.
      caller: call.spiffeCaller || null,
      // ---------------------------------------------------------------------
      // **AND THE REALM, WHICH IS THE SECOND THING A WORKER COULD NOT WORK OUT
      // (2026-09-12).**
      //
      // SPIFFE became per realm the same day this seam was written, and the two
      // changes met here. A realm with SPIFFE turned on binds a Workload API
      // and a SPIRE Server API of its OWN, and `spiffe_server.ts` enters that
      // realm around the handler table — so by the time this runs, the ambient
      // realm is the one whose SOCKET the call arrived on. That is the whole
      // discriminator: gRPC's path is the method name, so there is nowhere else
      // for a realm to be.
      //
      // A worker has no socket and therefore no way to recover it. Without this
      // line every dispatched call would be answered in the DEFAULT realm — the
      // right trust domain on the way in and the wrong authority on the way
      // out, with nothing failing: an SVID would be minted, signed by the wrong
      // realm's CA, in the wrong trust domain, and the caller would have no way
      // to tell until it presented one.
      //
      // It crosses as an ID rather than as the record, because a realm record
      // is a store this worker already has.
      // ---------------------------------------------------------------------
      realm: realms.currentId()
    };
  }

  dispatchUnary(surface, method, call) {
    const { log } = this.deps;
    log.debug("Entering SpiffeGrpc.dispatchUnary().");
    const pool = this.requestPool();
    if (!pool || typeof pool.runOperation !== 'function') {
      log.debug("Leaving SpiffeGrpc.dispatchUnary().");
      return Promise.resolve({ dispatched: false });
    }
    log.debug("Leaving SpiffeGrpc.dispatchUnary().");
    return pool.runOperation(this.methodKind(surface, method),
                             this.methodRequest(call));
  }

  // One method, run wherever it is running. The handler is the SAME function
  // the socket would have called, which is what makes "a dispatched method is
  // the same answer" true by construction rather than by a comparison somebody
  // maintains.
  performMethod(surface, method, args) {
    const { log, realms, errorCodes } = this.deps;
    log.debug('Entering SpiffeGrpc.performMethod(). ' + surface + '.' + method);
    const handler = LOCAL_METHODS.get(this.methodKind(surface, method));
    if (!handler) {
      throw new Error('this process has no handler registered for the SPIFFE ' +
        'method "' + surface + '.' + method + '".');
    }
    // THE TWO MEMBERS A HANDLER READS, AND NOTHING ELSE. A fuller fake would be
    // offering a surface no handler uses — and the next handler to reach for
    // one would find it working in one process and absent in the other.
    const call = { request: args.request, spiffeCaller: args.caller || null };
    // IN THE REALM THE CALL ARRIVED IN — see `methodRequest()`. `realms.get()`
    // answers the DEFAULT realm's record for an empty id and null for a realm
    // this process has not heard of; the fallback is the default realm, which
    // is what this file did before realms reached it and is the only answer
    // available when the registry disagrees.
    const realm = realms.get(String(args.realm || '')) || realms.DEFAULT_REALM;
    log.debug("Leaving SpiffeGrpc.performMethod().");
    return Promise.resolve()
      .then(function () {
        return realms.run(realm, function () { return handler(call); });
      })
      .then(function (reply) {
        log.debug('Leaving SpiffeGrpc.performMethod(). Answered.');
        return { ok: true, reply: reply || {} };
      }, function (err) {
        // A STATUS CROSSES AS ITS CODE. Anything else is a defect in this
        // service rather than in the call, and it is reported as one at the far
        // end by `errorToStatus()` — so what travels is enough for that
        // function to make the same decision it would have made here.
        log.debug('Leaving SpiffeGrpc.performMethod(). Refused.');
        return { ok: false,
                 code: (err && typeof err.code === 'number') ? err.code : null,
                 message: (err && err.message) || '',
                 stack: (err && err.stack) || '',
                 // THE CONDITION THE HANDLER MARKED, which lives under a Symbol
                 // on this process's call object and would not cross on its
                 // own. The front process marks its own call with it and
                 // records the row.
                 errorCode: errorCodes.codeOf(call) };
      });
  }

  // The other end: a result turned back into what the wrapper above expects.
  // A refusal carrying no numeric code was NOT a status error in the worker, so
  // it is rebuilt as a plain Error and `errorToStatus()` logs it as the defect
  // it is — the same answer it would have reached had the handler run here.
  errorFromResult(result) {
    const { log } = this.deps;
    log.debug("Entering SpiffeGrpc.errorFromResult().");
    if (result && typeof result.code === 'number') {
      log.debug("Leaving SpiffeGrpc.errorFromResult().");
      // error-code: none — a rebuild of the worker's refusal; its code travels
      // as result.errorCode
      return this.statusError(result.code, result.message);
    }
    const err = new Error((result && result.message) ||
      'the request worker running this method did not say what went wrong');
    if (result && result.stack) {
      err.stack = result.stack;
    }
    log.debug("Leaving SpiffeGrpc.errorFromResult().");
    return err;
  }

  unary(surface, method, handler) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering SpiffeGrpc.unary().");
    // REGISTERED AT WRAP TIME, which is module load. `spiffe_workload.ts` and
    // `spiffe_api.ts` call this once per method as they load, so by the time
    // anything can arrive the table is complete — there is no later moment to
    // do it in, and no list anywhere that could disagree with the methods that
    // actually exist.
    this.registerWorkerMethod(surface, method, handler);
    log.debug("Leaving SpiffeGrpc.unary().");
    return function (call, callback) {
      log.debug('Entering the ' + method + ' handler.');
      const prepared = self.prepareCall(call, surface, method);
      if (prepared.refusal) {
        self.recordCall(surface, method, false,
                        { refused: prepared.refusal.message },
                        prepared.caller, prepared.errorCode);
        log.debug('Leaving the ' + method + ' handler. Refused.');
        callback(self.errorToStatus(prepared.refusal, method));
        return;
      }
      Promise.resolve()
        .then(function () { return self.dispatchUnary(surface, method, call); })
        .then(function (answer) {
          if (!answer || !answer.dispatched) {
            // NOT DISPATCHED: no pool, this method not named in
            // `workers.dispatch`, or no worker to take it. All three mean the
            // front process does the work, which is what
            // `workers.requestCount = 0` means and is a supported configuration
            // rather than a degraded one.
            return handler(call);
          }
          if (answer.result && answer.result.ok) {
            return answer.result.reply;
          }
          if (answer.result && answer.result.errorCode) {
            errorCodes.mark(call, answer.result.errorCode);
          }
          throw self.errorFromResult(answer.result);
        })
        .then(function (reply) {
          self.recordCall(surface, method, true, {}, prepared.caller);
          callback(null, reply || {});
          log.debug('Leaving the ' + method + ' handler.');
        })
        .catch(function (err) {
          const status = self.errorToStatus(err, method);
          self.recordCall(surface, method, false, { status: status.code },
                          prepared.caller,
                          self.failureCodeOf(call, err));
          callback(status);
          log.debug('Leaving the ' + method + ' handler. ' + status.details);
        });
    };
  }

  // ---------------------------------------------------------------------------
  // THE WORKER SIDE OF THE SEAM.
  //
  // `common/request_worker.js` offers `register(kind, fn)` and its header says
  // the table is filled BY THE MODULE THAT OWNS THE OPERATION — so this is that
  // module doing it, as each method is wrapped, which is exactly when a route
  // module registers its routes (rule 1).
  //
  // **IT IS CALLED FROM `unary()` AND FROM NEITHER STREAM WRAPPER**, which is
  // how the list of what may be dispatched stays the list of what CAN be:
  // there is no table anywhere naming the forty-two, so none can go stale.
  // ---------------------------------------------------------------------------
  // **THE TABLE IS FILLED IN EVERY PROCESS AND THE WORKER MODULE IS REQUIRED IN
  // ONLY ONE OF THEM**, and that distinction is not tidiness — it cost a test.
  //
  // `LOCAL_METHODS` is a plain Map and every process needs it: it is what a
  // worker runs AND what the front process falls back to. Requiring
  // `common/request_worker.js` is a different matter — that module pulls in
  // `common/service_state.ts` at module scope (the store, the keys, the minted
  // rows, coordination) and installs `process.on('message')` handlers. In a
  // process that is not a worker that is a table nothing will ever read, bought
  // with a load of half the service's startup machinery.
  //
  // **IT WAS UNCONDITIONAL FOR TEN MINUTES AND `tests/spiffe_pki.js` WENT RED
  // IN THE SUITE WHILE PASSING ALONE** — `run.js` runs every file in one
  // process, so pulling `service_state.js` in at a new point in the load order
  // changed what a later file saw of the certificate hierarchy. That is
  // precisely the process-wide-state hazard `tests/CLAUDE.md` warns about,
  // arriving from the one direction nobody watches: a require added for a
  // feature that is off.
  //
  // So the gate is `STS_REQUEST_WORKER`, which is the marker `request_pool.js`
  // forks a child with and the same one it uses itself to stop a worker
  // proxying to itself.
  registerWorkerMethod(surface, method, handler) {
    const { log, loadRequestWorker } = this.deps;
    const self = this;
    log.debug("Entering SpiffeGrpc.registerWorkerMethod().");
    if (DISPATCHED_SURFACES.indexOf(surface) < 0) {
      log.debug("Leaving SpiffeGrpc.registerWorkerMethod().");
      return;
    }
    const kind = this.methodKind(surface, method);
    LOCAL_METHODS.set(kind, handler);
    if (!process.env.STS_REQUEST_WORKER) {
      log.debug("Leaving SpiffeGrpc.registerWorkerMethod().");
      return;
    }
    let worker = null;
    try {
      worker = loadRequestWorker();
    } catch (e) {
      log.debug("Caught in SpiffeGrpc.registerWorkerMethod(): " +
                ((e && e.message) || e));
      log.debug("Leaving SpiffeGrpc.registerWorkerMethod().");
      // A process with no worker module cannot be a worker. The local table
      // above is still filled, because it is also the fallback path's handler.
      return;
    }
    if (!worker || typeof worker.register !== 'function' ||
        (worker.OPERATIONS && worker.OPERATIONS.has(kind))) {
      log.debug("Leaving SpiffeGrpc.registerWorkerMethod().");
      return;
    }
    worker.register(kind, function (args) {
      return self.performMethod(surface, method, args);
    });
    log.debug("Leaving SpiffeGrpc.registerWorkerMethod().");
  }

  // ---------------------------------------------------------------------------
  // A server-streaming method. `handler` returns the FIRST message; the stream
  // is then held open and nothing further is written unless `onUpdate` is
  // given.
  //
  // **The stream is not ended**, and that is the whole point of this function.
  // See the note above `unary()`: a Workload API client treats the stream
  // ending as a fault. It ends when the client goes away, which is the
  // `cancelled` listener below, or when the process does.
  //
  // ---------------------------------------------------------------------------
  // **AND IT IS NOT DISPATCHED TO A REQUEST WORKER, WHICH IS A DECISION RATHER
  // THAN AN OMISSION (2026-09-12).**
  //
  // Five of the forty-seven methods are server streams and all five are on the
  // Workload API — `FetchX509SVID`, `FetchX509Bundles`, `FetchJWTBundles` among
  // them. Two things about them put them on the socket side of the line that
  // `unbind` is on in `ldap/ldap_server.js`:
  //
  //   * **A STREAM HERE IS A SUBSCRIPTION AND NOT A REQUEST.** It is opened
  //     once and held for the life of the process — the header above says a
  //     real client treats it ending as a FAULT — and what feeds it is a
  //     ROTATION TIMER in whichever process holds the authority, not a caller.
  //     There is no request/response to move. Moving it would mean a worker
  //     owning a stream whose file descriptor is here, every `push()` crossing
  //     the channel, and a worker's death silently turning a live subscription
  //     into one that never updates again: a client would go on holding an SVID
  //     it believes is being renewed. That is the LDAP connection's problem
  //     exactly, and the answer there was to keep it here.
  //   * **DISPATCHING ONLY THE FIRST MESSAGE WOULD BE WORSE THAN NOT
  //     DISPATCHING.** `pushOnRotation()` builds LATER messages with the same
  //     `buildX509SvidResponse()` the first one uses, so the front process has
  //     to be able to build one anyway — and splitting them would put one
  //     response in two processes, which is the thing every codec in this
  //     repository is written to avoid.
  //
  // **WHAT THAT COSTS IS SMALL AND IS WORTH STATING.** The expensive thing on
  // this surface is minting an SVID, and a stream mints one on rotation rather
  // than per call; the per-call work — forty-two unary methods, every one of
  // the SPIRE Server API's among them — does leave this thread. `bidiStream()`
  // is unchanged for the same reason read the other way: `AttestAgent` and
  // `SyncAuthorizedEntries` are request/response in practice, but the stream
  // and its `data`/`end` events belong to the connection.
  // ---------------------------------------------------------------------------
  serverStream(surface, method, handler) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SpiffeGrpc.serverStream().");
    log.debug("Leaving SpiffeGrpc.serverStream().");
    return function (call) {
      log.debug('Entering the ' + method + ' stream handler.');
      const prepared = self.prepareCall(call, surface, method);
      if (prepared.refusal) {
        self.recordCall(surface, method, false,
                        { refused: prepared.refusal.message },
                        prepared.caller, prepared.errorCode);
        call.emit('error', self.errorToStatus(prepared.refusal, method));
        log.debug('Leaving the ' + method + ' stream handler. Refused.');
        return;
      }
      let open = true;
      // `cancelled` fires when the peer goes away. Without this listener a
      // rotation timer would go on writing to a dead stream, which grpc-js
      // reports as an unhandled error on the server.
      call.on('cancelled', function () {
        open = false;
        log.debug('spiffe: the ' + method +
                  ' stream was cancelled by the client.');
      });
      call.on('error', function (err) {
        open = false;
        log.debug('spiffe: the ' + method + ' stream ended with ' +
                  err.message);
      });
      Promise.resolve()
        .then(function () {
          return handler(call, function push(message) {
            log.debug("Entering push().");
            // The push callback a handler uses to send a later message — an
            // SVID that rotated, a bundle that changed. Guarded on `open`,
            // because the handler holds it across time and the client may be
            // long gone.
            if (!open) {
              log.debug("Leaving push().");
              return false;
            }
            call.write(message);
            log.debug("Leaving push().");
            return true;
          });
        })
        .then(function (first) {
          if (first && open) call.write(first);
          self.recordCall(surface, method, true, { streaming: true },
                          prepared.caller);
          log.debug('Leaving the ' + method + ' stream handler. The stream ' +
                    'stays open; a Workload API client treats it ending as a ' +
                    'fault.');
        })
        .catch(function (err) {
          const status = self.errorToStatus(err, method);
          self.recordCall(surface, method, false, { status: status.code },
                          prepared.caller,
                          self.failureCodeOf(call, err));
          open = false;
          call.emit('error', status);
          log.debug('Leaving the ' + method + ' stream handler. ' +
                    status.details);
        });
    };
  }

  // A bidirectional stream. Only `AttestAgent` and `SyncAuthorizedEntries` are
  // one, and both are request/response in practice — the client sends, the
  // server answers, and the stream closes. So the shape here is "for each
  // message the client sends, answer it", which is what those two do and is
  // much easier to get right than a general duplex.
  bidiStream(surface, method, handler) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SpiffeGrpc.bidiStream().");
    log.debug("Leaving SpiffeGrpc.bidiStream().");
    return function (call) {
      log.debug('Entering the ' + method + ' bidi handler.');
      const prepared = self.prepareCall(call, surface, method);
      if (prepared.refusal) {
        self.recordCall(surface, method, false,
                        { refused: prepared.refusal.message },
                        prepared.caller, prepared.errorCode);
        call.emit('error', self.errorToStatus(prepared.refusal, method));
        log.debug('Leaving the ' + method + ' bidi handler. Refused.');
        return;
      }
      call.on('data', function (request) {
        Promise.resolve()
          .then(function () { return handler(request, call); })
          .then(function (reply) {
            if (reply) call.write(reply);
          })
          .catch(function (err) {
            const status = self.errorToStatus(err, method);
            self.recordCall(surface, method, false, { status: status.code },
                            prepared.caller, self.failureCodeOf(call, err));
            call.emit('error', status);
          });
      });
      call.on('end', function () {
        self.recordCall(surface, method, true, { streaming: true },
                        prepared.caller);
        call.end();
        log.debug('Leaving the ' + method +
                  ' bidi handler. The client ended it.');
      });
      call.on('error', function (err) {
        log.debug('spiffe: the ' + method + ' bidi stream ended with ' +
                  err.message);
      });
    };
  }

  prepareSocketPath(socketPath, privateSocket) {
    const { log, path, fs, errorCodes } = this.deps;
    log.debug('Entering SpiffeGrpc.prepareSocketPath(). path=' + socketPath +
              ' private=' + !!privateSocket);
    const directory = path.dirname(socketPath);
    const existed = fs.existsSync(directory);
    try {
      // `mode` applies to every directory `recursive` creates and to none that
      // existed — which is the half this function wants.
      fs.mkdirSync(directory, { recursive: true,
                                mode: privateSocket ? PRIVATE_DIRECTORY_MODE
                                                    : PUBLIC_DIRECTORY_MODE });
      if (!existed) {
        // mkdir's mode is filtered through the umask; a chmod is not. Only the
        // leaf directory is ours to fix, and only because we just made it.
        fs.chmodSync(directory, privateSocket ? PRIVATE_DIRECTORY_MODE
                                              : PUBLIC_DIRECTORY_MODE);
      } else {
        this.warnAboutDirectory(directory, privateSocket);
      }
    } catch (e) {
      // The directory may exist already, which is not an error, or be
      // unwritable, which is — and which `bindAsync` will report in a moment
      // with the path in it. Nothing is lost by carrying on.
      log.debug('prepareSocketPath(): mkdir said ' + e.message +
                ', which bindAsync will report properly if it matters.');
    }
    try {
      const stat = fs.statSync(socketPath);
      if (stat.isSocket()) {
        fs.unlinkSync(socketPath);
        log.warn('spiffe: a stale socket was at ' + socketPath + ' and has ' +
                 'been removed. That is the ordinary leftover of a killed ' +
                 'process — but if another copy ' +
                 'of this service is running and ' +
                 'listening there, this one has just taken the path from it.');
      } else {
        // Something that is not a socket. NOT removed: this is a path from
        // configuration and deleting a regular file somebody named would be a
        // destructive act on the strength of a typo.
        log.error(errorCodes.tag('STS-SPIFFE-0009') +
                  'spiffe: ' + socketPath + ' exists and is not a socket, so ' +
                  'nothing here will bind it. It is left alone deliberately ' +
                  '— removing a file named in configuration on the strength ' +
                  'of a typo is not this service\'s decision to make.');
      }
    } catch (e) {
      // ENOENT is the ordinary case and needs no comment; anything else will be
      // reported by bindAsync with more context than there is here.
      log.debug('prepareSocketPath(): nothing at that path (' + e.code + ').');
    }
    log.debug('Leaving SpiffeGrpc.prepareSocketPath().');
  }

  // A directory somebody else made, holding a socket that matters. Reported and
  // never changed: the path came from configuration and may be shared on
  // purpose.
  warnAboutDirectory(directory, privateSocket) {
    const { log, fs } = this.deps;
    log.debug("Entering SpiffeGrpc.warnAboutDirectory().");
    try {
      const bits = fs.statSync(directory).mode & 0o777;
      if (privateSocket && (bits & 0o077)) {
        log.warn('spiffe: ' + directory + ' (mode ' +
                 bits.toString(8) + ') is ' +
                 'reachable by other users and holds the SPIRE Server API ' +
                 'socket, which is the trusted `local` entity. The socket ' +
                 'itself is made 0600 once bound, which is the lock that ' +
                 'matters; make the directory 0700 as well, or point ' +
                 'spiffe.serverSocket somewhere private.');
      } else if (!privateSocket && (bits & 0o022)) {
        log.warn('spiffe: ' + directory + ' (mode ' +
                 bits.toString(8) + ') is ' +
                 'WRITABLE by other users and holds the Workload API socket. ' +
                 'Anybody who can write there can unlink it and bind their ' +
                 'own, and every workload would then be answered by them. ' +
                 'Remove the group and world write bits.');
      }
    } catch (e) {
      // Could not stat a directory mkdir just said exists. bindAsync reports
      // anything that matters about the path; this was only a warning.
      log.debug('warnAboutDirectory(): stat said ' + e.message);
    }
    log.debug("Leaving SpiffeGrpc.warnAboutDirectory().");
  }

  // After a SPIRE Server API socket has bound: 0600, so that only this
  // process's uid can connect to the `local` entity. See the block above
  // prepareSocketPath. A failure is LOGGED LOUDLY and not thrown, for
  // bindOne()'s reason — but it is an error, because a `local` socket other
  // users can reach is an administrator credential lying on a filesystem.
  restrictSocket(socketPath) {
    const { log, fs, errorCodes } = this.deps;
    log.debug('Entering SpiffeGrpc.restrictSocket(). path=' + socketPath);
    try {
      fs.chmodSync(socketPath, PRIVATE_SOCKET_MODE);
    } catch (e) {
      log.error(errorCodes.tag('STS-SPIFFE-0010') +
                'spiffe: could not make the SPIRE Server API socket ' +
                socketPath + ' mode 0600 (' + e.message + '). Other users on ' +
                'this machine may be able to connect to it as the trusted ' +
                '`local` entity; turn spiffe.trustLocalSocket off or move ' +
                'the socket until this is fixed.');
      log.debug('Leaving SpiffeGrpc.restrictSocket(). It failed.');
      return false;
    }
    log.debug('Leaving SpiffeGrpc.restrictSocket().');
    return true;
  }

  // Build a server with a set of services on it. One function for both
  // surfaces, because they differ only in which services they carry and where
  // they bind.
  buildServer(services) {
    const { log, grpc } = this.deps;
    log.debug('Entering SpiffeGrpc.buildServer().');
    const server = new grpc.Server();
    services.forEach(function (entry) {
      server.addService(SERVICES[entry.name], entry.handlers);
    });
    log.debug('Leaving SpiffeGrpc.buildServer(). ' + services.length +
              ' service(s).');
    return server;
  }

  // Bind one address, and REPORT a failure rather than throwing it. That is the
  // rule every listener in this service follows — see `ldap_server.js` (and
  // `tls_server.js`, while it owned listeners) — and the reason is the same: a
  // port can already be taken, and the fourteen other protocol families here
  // are still useful when one listener is not.
  bindOne(server, address, credentials): Record<string, any> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SpiffeGrpc.bindOne().");
    log.debug("Leaving SpiffeGrpc.bindOne().");
    return new Promise(function (resolve) {
      server.bindAsync(address, credentials, function (err, port) {
        if (err) {
          log.error(errorCodes.tag('STS-SPIFFE-0011') +
                    'spiffe: could not bind ' + address + ': ' + err.message);
          resolve({ address: address, listening: false, error: err.message,
                    port: 0 });
          return;
        }
        resolve({ address: address, listening: true, error: '', port: port });
      });
    });
  }

  // ---------------------------------------------------------------------------
  // THE SPIRE SERVER API'S TLS CREDENTIALS — and the two things about them that
  // are easy to get wrong in opposite directions.
  //
  // A real `spire-server` binds its TCP port as mutual TLS: it presents its own
  // X509-SVID (`spiffe://<trust domain>/spire/server`) and asks the client for
  // one. So this mints exactly that, from the same authority every other SVID
  // here comes from, per start.
  //
  // **THE SERVER SVID IS NOT `tls_server.js`'S CERTIFICATE**, and must not
  // become it. That one is a leaf with `serverAuth` for a host; this one is an
  // identity in a trust domain. The two are unrelated trust decisions, which is
  // the same argument that keeps the SPIFFE CA separate from that module's —
  // see rule 3k. A client verifies this handshake against the TRUST BUNDLE,
  // which it fetched from the bundle endpoint, and not against any web PKI.
  //
  // **THE HANDSHAKE ASKS FOR A CERTIFICATE AND DOES NOT REQUIRE ONE.**
  // grpc-js's
  // `createSsl(roots, pairs, checkClientCertificate)` sets `requestCert` from
  // that third argument and leaves node's default `rejectUnauthorized: true` in
  // place, which would refuse the handshake of any client that presented
  // nothing — and `AttestAgent` is open to a caller with no SVID, because an
  // agent HAS no SVID until that call gives it one. A port that could not be
  // bootstrapped against is a port with no purpose. So the constructor options
  // are reached for and `rejectUnauthorized` is turned off, which is
  // `tls.RequestClientCert` — exactly what SPIRE does — and `spiffe_auth.ts`
  // then verifies what arrived itself, against the trust bundle rather than
  // against a system CA store.
  // `mtls.js` makes the same arrangement on the main HTTPS listener and the
  // note there says the same thing.
  //
  // A failure to mint is REPORTED and the caller falls back to plain: a
  // listener that did not come up at all would take the whole surface away for
  // a reason nobody could see, and `GET /spiffe` says which of the two it got.
  // ---------------------------------------------------------------------------
  async serverApiCredentials() {
    const { log, ca, spiffeId, config, grpc, errorCodes } = this.deps;
    log.debug('Entering SpiffeGrpc.serverApiCredentials().');
    await ca.ready();
    const identity = spiffeId.serverId(ca.trustDomain());
    // ---------------------------------------------------------------------
    // THE SERVER'S OWN CERTIFICATE GETS THE AUTHORITY'S LIFETIME, NOT AN
    // SVID'S, AND THE DIFFERENCE IS A SERVICE THAT STOPS ANSWERING AFTER AN
    // HOUR.
    //
    // This is not a workload SVID. It is a LISTENER'S certificate, minted
    // ONCE at `listen()` and handed to `grpc.ServerCredentials.createSsl()`,
    // which holds it for the life of the process — there is no way to swap it
    // afterwards without rebinding the socket. So with `spiffe.svidTtl` (an
    // hour by default) it expires while the listener is still up, and from
    // that moment every mutual-TLS client is refused with `certificate has
    // expired`.
    //
    // That failure names the CLIENT'S trust store rather than this server's
    // clock: a caller sees only that the certificate it was handed will not
    // verify, and the obvious first move is to re-fetch the bundle — which is
    // perfectly good and changes nothing. A fresh container hides it
    // completely, so it appears as a SPIRE Server API that works right after a
    // restart and not otherwise.
    //
    // `spiffe.caTtl` is the right bound because it is the true one: nothing
    // this authority signs can outlive it, and `issueLeaf()` clamps to the
    // authority's own notAfter anyway. What is left is that the listener's
    // certificate now lasts exactly as long as the trust domain it speaks
    // for.
    // ---------------------------------------------------------------------
    const svid = await ca.mintX509Svid(identity,
      { ttl: config.value('spiffe.caTtl') });
    const roots = await ca.x509BundleDer();
    const credentials = grpc.ServerCredentials.createSsl(
      // The roots are handed over as PEM: node's `ca` option takes PEM or DER,
      // and the bundle here is concatenated DER, which node reads as ONE
      // certificate and silently ignores the rest of. Every authority has to be
      // its own PEM block or a client signed by the second one is refused with
      // no way to tell why.
      //
      // **THE TRUST ANCHORS AND NOT THE AUTHORITIES (2026-09-11), AND THE
      // DIFFERENCE IS THE WHOLE POINT OF `trustAnchors` BEING A SEPARATE
      // LIST.** They were the same thing while the SPIFFE authority was
      // self-signed. It is now this realm's SPIFFE Issuing CA under the service
      // Root, and an Issuing CA is NOT a trust anchor: OpenSSL will not treat a
      // non-self-signed certificate in the truststore as one unless it is asked
      // to with `X509_V_FLAG_PARTIAL_CHAIN`, which node does not expose here.
      // So handing it the Issuing CA refuses every client with
      // `unable to get issuer certificate` — a message about the ANCHOR, on a
      // connection whose chain was complete. The Root anchors it, and a client
      // presenting [leaf, SPIFFE Issuing CA, Intermediate] builds a path to it.
      Buffer.from(ca.state().trustAnchors.map(function (anchor) {
        return anchor.certificatePem;
      }).join('\n'), 'utf8'),
      [{ private_key: Buffer.from(svid.privateKeyPem, 'utf8'),
         cert_chain: Buffer.from(svid.chainPem.join('\n'), 'utf8') }],
      true);
    try {
      // See the header. This is a reach into grpc-js's own options object and
      // it is deliberate: there is no argument for "request but do not
      // require", the difference matters here more than anywhere else in this
      // service, and the alternative is a bespoke ServerCredentials subclass
      // that would have to be kept in step with a library we do not otherwise
      // touch.
      credentials._getConstructorOptions().rejectUnauthorized = false;
    } catch (e) {
      log.error(errorCodes.tag('STS-SPIFFE-0012') +
                'spiffe: the SPIRE Server API ' +
                'TLS listener could not be set to ' +
                'request-but-not-require a client certificate (' + e.message +
                '). It will REFUSE any client that presents none, which ' +
                'means AttestAgent cannot be reached over TCP. This is a ' +
                'grpc-js change rather than anything a caller did.');
    }
    log.info('spiffe: the SPIRE Server API TCP listener is mutual TLS as ' +
             identity + ' (serial ' + svid.serialHex + ', ' + roots.length +
             ' bytes of trust bundle). A client verifies it against the ' +
             'bundle at the bundle endpoint, presents its own X509-SVID, and ' +
             'is authorized per method against SPIRE\'s own table — see GET ' +
             '/spiffe.');
    log.debug('Leaving SpiffeGrpc.serverApiCredentials().');
    return credentials;
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
const slot = new InstanceSlot<SpiffeGrpc>(
  'spiffe/spiffe_grpc',
  () => new SpiffeGrpc(SpiffeGrpc.defaultDeps()),
  SpiffeGrpc.wire,
  helpers.log);

// The service definitions, by the fully-qualified name the wire uses. Named
// in `SpiffeGrpc.wire()`, once, so that a typo in a service name is a
// `TypeError` at startup rather than a method nothing ever routes to. Loaded
// by the instance, so filled when the instance is installed (#50, R2).
let SERVICES: Record<ServiceName, any> | null = null;

// ---------------------------------------------------------------------------
// THE ONE CHECK THE SPECIFICATION REQUIRES, AND WHY IT IS ON IN A SERVICE THAT
// REFUSES ALMOST NOTHING.
//
// The SPIFFE Workload Endpoint specification says a client MUST send
// `workload.spiffe.io: true` on every call and a server MUST refuse a call
// without it. It is not a security check — anybody can send a header — and it
// is not authentication. It exists so that a caller cannot reach the Workload
// API BY ACCIDENT: the endpoint is usually a Unix socket with permissive
// filesystem permissions, and the header is a positive statement that the
// caller meant to talk to a Workload API.
//
// This service checks it, and that is a deliberate exception to its permissive
// posture, for one reason: **a client that omits it has a bug, and this is the
// only thing that will ever tell them.** Every real Workload API will refuse
// them; a mock that accepted it would let a client author ship code that works
// against this and against nothing else. `spiffe.requireSecurityHeader` turns
// it off for the case where somebody is deliberately testing something else.
//
// The refusal is `InvalidArgument`, which is what SPIRE answers.
// ---------------------------------------------------------------------------
const SECURITY_HEADER = 'workload.spiffe.io';

// ---------------------------------------------------------------------------
// THE gRPC SURFACES AS OPERATIONS: WHAT GOES TO A REQUEST WORKER (2026-09-12).
//
// `common/request_pool.js` dispatches HTTP by proxying, and non-HTTP work by
// OPERATION — a `{ kind, args }` pair the front process sends to a worker while
// keeping the socket and the framing. `ldap/ldap_server.js` was the first
// family to use it; this is the second, and the cut here is a different one
// because gRPC has a shape LDAP does not.
//
// **THE SEAM IS THIS FUNCTION AND NOT THE HANDLERS**, which is the whole reason
// it cost two files rather than forty-four. Every method on both surfaces is
// registered through `unary()`, `serverStream()` or `bidiStream()`, so wrapping
// here covers all of them by construction — and `spiffe_workload.ts` and
// `spiffe_api.ts` are not edited at all. That is `ldap_server.js`'s
// registration-point argument, met again: forty-two handlers each remembering
// to offer themselves to the pool is forty-two chances to forget, and what was
// forgotten would be invisible — the method would simply run in the front
// process and everything would work, slightly slower, for ever.
//
// ---------------------------------------------------------------------------
// A HANDLER READS EXACTLY TWO THINGS OFF THE CALL, WHICH IS WHAT MAKES THIS
// SMALLER THAN THE DIRECTORY'S CODEC.
//
// Counted across both surfaces: `call.request` (35 uses) and
// `call.spiffeCaller` (4). Nothing else — no headers, no deadline, no peer, no
// metadata. So what crosses is those two, and the worker is handed an object
// with exactly them on it.
//
// **AND AN ERROR NEEDS NO TABLE AT ALL.** `statusError()` is an `Error` with a
// NUMERIC gRPC status code on it, and the number IS the protocol — so a refusal
// crosses as `{ code, message }` and is rebuilt by the same constructor. The
// directory's `ldapErrorNamed()` had to look a class up on ldapjs's exports and
// validate what it found; here there is no class to look up.
//
// ---------------------------------------------------------------------------
// THREE THINGS STAY IN THE FRONT PROCESS, AND EACH IS A DIFFERENT REASON.
//
//   * **`prepareCall()`.** It reads the TRANSPORT (unix socket or TCP), the
//     peer address, the peer certificate and — for the Workload API — the
//     selectors derived from those (node cannot read a Unix socket's peer
//     credentials; see `spiffe_auth.ts`). Every one of those is a property
//     of a connection this process accepted, so a worker could not compute
//     them and must not guess. What crosses is its ANSWER: a plain `caller`
//     whose DNs `dnRfc4514()` has already rendered to strings.
//   * **`recordCall()`.** It is called from these wrappers rather than from any
//     handler, so it simply stays where it is — and that is worth having on
//     purpose rather than by accident: the counters behind `/admin/metrics` and
//     the audit row would otherwise land in whichever worker answered, and
//     `admin_stats.users` is one of the three stores that does not fan in.
//   * **The CALLBACK.** `callback(null, reply)` and `callback(status)` write to
//     the connection.
//
// ---------------------------------------------------------------------------
// AND THE STREAMS DO NOT CROSS AT ALL — SEE `serverStream()` BELOW.
// ---------------------------------------------------------------------------
const DISPATCHED_SURFACES = ['workload', 'server'];

// The handler behind each dispatched method, captured at registration. It is
// what a worker runs and what the front process falls back to.
const LOCAL_METHODS = new Map();

// ---------------------------------------------------------------------------
// BINDING.
//
// Two transports, and the Unix socket is the interesting one.
//
// **THE SOCKET IS THE ONE THING THIS SERVICE PUTS ON A FILESYSTEM**, and it is
// worth being exact about what that does and does not mean. Nothing is
// PERSISTED through it: it is a rendezvous point, it holds no bytes, it is
// unlinked when the listener closes, and a fresh process makes a fresh one. The
// alternative — TCP only — would have been filesystem-clean and unreachable by
// every real client, because `SPIFFE_ENDPOINT_SOCKET` means a `unix://` path to
// `go-spiffe`, to `spiffe-helper` and to the SPIRE agent.
//
// A STALE SOCKET IS UNLINKED BEFORE BINDING. A process killed with SIGKILL
// leaves the file behind, and `bind` on an existing path fails with EADDRINUSE
// — which reads exactly like "another copy of this service has the port" and is
// usually not. Unlinking first is what every Unix socket server does; the cost
// is that two copies of this service pointed at one path will fight, with the
// second winning silently, so the path is LOGGED at startup.
//
// ---------------------------------------------------------------------------
// **PERMISSIONS ARE STATED, SINCE 2026-09-12, AND THE TWO SURFACES ARE OPPOSITE
// CASES.** The directories were made with `mkdirSync(dir, {recursive: true})`
// and the socket left as grpc-js created it — both at the mercy of the
// process umask. That was fine for the Workload API and wrong for the other:
//
//   * **THE SPIRE SERVER API SOCKET IS THE `local` ENTITY.** A caller there is
//     trusted outright (`spiffe.trustLocalSocket`, on by default) and may do
//     everything an admin may — create a registration entry for any identity,
//     mint an SVID for it. SPIRE's own answer is that "the access control is
//     the socket's filesystem permissions", and this service had not set any.
//     So a directory it creates for that socket is 0700, and the socket is
//     chmod-ed 0600 once bound: connecting to a Unix socket needs WRITE on it,
//     so 0600 is "this process's uid and nobody else", in every mode — it is
//     a correctness defect for the authority `local` grants, not a mode policy.
//     A directory that ALREADY existed is not chmod-ed — it is a path from
//     configuration and may be shared — but one that is reachable by other
//     users is reported, because the socket's own mode is then the only lock.
//   * **THE WORKLOAD API SOCKET MUST BE REACHABLE BY OTHER USERS** — a
//     workload is typically another uid, and its specification forbids
//     authenticating the caller — so the socket keeps grpc-js's mode. What IS
//     fixed is the directory: 0755, never group- or world-WRITABLE, because a
//     writable directory lets anybody unlink the socket and bind their own in
//     its place, which would hand every workload an SVID from an authority of
//     the attacker's choosing.
// ---------------------------------------------------------------------------
const PRIVATE_DIRECTORY_MODE = 0o700;
const PUBLIC_DIRECTORY_MODE = 0o755;
const PRIVATE_SOCKET_MODE = 0o600;

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  SpiffeGrpc: SpiffeGrpc,
  installInstance: (instance: SpiffeGrpc): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  grpc: grpc,
  // Named by `SpiffeGrpc.wire()`, so read once the instance exists.
  get SERVICES(): Record<ServiceName, any> {
    log.debug("Entering SERVICES().");
    slot.get();
    log.debug("Leaving SERVICES().");
    return SERVICES;
  },
  SECURITY_HEADER: SECURITY_HEADER,
  methodsOf: slot.forward('methodsOf'),
  statusError: slot.forward('statusError'),
  invalidArgument: slot.forward('invalidArgument'),
  notFound: slot.forward('notFound'),
  permissionDenied: slot.forward('permissionDenied'),
  unavailable: slot.forward('unavailable'),
  unary: slot.forward('unary'),
  serverStream: slot.forward('serverStream'),
  bidiStream: slot.forward('bidiStream'),
  prepareSocketPath: slot.forward('prepareSocketPath'),
  restrictSocket: slot.forward('restrictSocket'),
  buildServer: slot.forward('buildServer'),
  bindOne: slot.forward('bindOne'),
  serverApiCredentials: slot.forward('serverApiCredentials'),
  // Exported for `tests/spire_api_access_policy.js`, which drives the two
  // decisions this function makes directly: the claim is about a DECISION and
  // not about an endpoint, so driving it over gRPC would mean standing up two
  // listeners and a certificate to assert one branch. That is the same
  // argument `tests/access_policy.js` makes at its own head.
  policyRefusal: slot.forward('policyRefusal'),
  enabled: slot.forward('enabled'),
  // ---------------------------------------------------------------------
  // THE OPERATION SEAM, EXPORTED FOR `tests/spiffe_operations.js` AND FOR
  // NOTHING ELSE IN THE SERVICE.
  //
  // The socket reaches these through `unary()` and a worker reaches
  // `performMethod()` through the table it registered, so no module here calls
  // any of them. They are exported because the claim they carry — that a
  // dispatched method is the same answer — can only be checked by running both
  // halves against each other.
  //
  // `localMethod()` is a FUNCTION rather than the Map, so that a caller cannot
  // install one: that table is what a worker runs, and a handle on it would be
  // a second door onto forty-two handlers.
  // ---------------------------------------------------------------------
  dispatchedMethodKinds: function () {
    log.debug("Entering dispatchedMethodKinds().");
    log.debug("Leaving dispatchedMethodKinds().");
    return Array.from(LOCAL_METHODS.keys()).sort();
  },
  localMethod: function (surface, method) {
    log.debug("Entering localMethod().");
    log.debug("Leaving localMethod().");
    return LOCAL_METHODS.get(slot.get().methodKind(surface, method));
  },
  methodKind: slot.forward('methodKind'),
  methodRequest: slot.forward('methodRequest'),
  performMethod: slot.forward('performMethod'),
  errorFromResult: slot.forward('errorFromResult')
};
