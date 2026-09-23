'use strict';
//
// File: spiffe_workload.ts
//
// ---------------------------------------------------------------------------
// THE SPIFFE WORKLOAD API — the second of the three server-side surfaces, and
// the one a workload actually talks to.
//
// Seven methods on one gRPC service, `SpiffeWorkloadAPI`, reached over a Unix
// domain socket (what `SPIFFE_ENDPOINT_SOCKET` means to every real client) or
// over TCP. It is a LIBRARY: it registers no HTTP route and starts no listener
// — `spiffe_server.ts` mounts these handlers — and it requires `helpers.js`,
// `config.js`, `audit.js`, `admin_stats.js`, `spiffe_id.ts`, `spiffe_ca.ts`,
// `spiffe_registry.ts` and `spiffe_grpc.ts`, none of which requires it back.
//
// ---------------------------------------------------------------------------
// THE CENTRAL FACT ABOUT THIS FILE: NO CREDENTIAL IS ASKED FOR HERE, AND THAT
// IS THE SPECIFICATION RATHER THAN THIS SERVICE'S PERMISSIVENESS
//
// The SPIFFE Workload Endpoint specification says the endpoint "MUST NOT
// require any direct authentication of its clients" and that "Transport Layer
// Security MUST NOT be required". A workload has no secret and no root of trust
// until this call gives it one, so there is nothing it could present. A mock
// that demanded a credential here would refuse every conforming client, which
// is why the mutual TLS the SPIRE Server API requires deliberately does not
// reach this surface.
//
// What a real endpoint does instead is ASCERTAIN the caller out of band: the
// agent asks the kernel about the peer of its Unix socket — pid, and from that
// uid, gid, executable path, container, Kubernetes pod — turns it into
// SELECTORS, and answers with the SVIDs of the registration entries whose
// selectors are a subset of those.
//
// **ON THE UNIX SOCKET THIS SERVICE DOES THE SAME SINCE 2026-09-21 (#40).**
// `spiffe_peer.ts` asks the kernel (SO_PEERCRED, through a native module
// built into the image) and `spiffe_workload_attestation.ts` runs the `unix`,
// `docker` and `k8s` attestors, once per connection at accept; every call
// then checks the process is still the one attested (`spiffe_grpc.ts`'s
// `prepareCall()`), and `spiffe_auth.workloadSelectors()` adds what they
// established. **OVER TCP IT ATTESTS WHAT NODE CAN SEE, WHICH IS LESS, AND
// SAYS SO**: the transport a call arrived on, the endpoint it reached, its
// peer address, and — only with `spiffe.acceptAssertedSelectors` on, and
// never in product — whatever the caller SAID about itself. Those types are
// spelt `transport:`, `endpoint:` and `peer:` rather than `unix:`: writing
// `unix:uid:1000` for a uid nothing read would be inventing an attested fact.
//
// Four consequences, all deliberate and all stated on `GET /spiffe` rather than
// left to be discovered:
//
//   * **Selector matching now decides the answer**, through
//     `spiffe_registry.selectorsMatch()` — SPIRE's subset rule. Neither
//     `GetAuthorizedEntries` nor the console's view (which calls
//     `entitledEntries()` with no caller) narrows by it. It used to be
//     implemented and unused here, because there was nothing to match against.
//     There is now. `spiffe.attestWorkloads` off restores the old answer —
//     every entry to every caller — in DEVELOPMENT MODE ONLY (#104,
//     `mode.servesUnattestedEntries()`): `auth.attestWorkloads()` reads it
//     through `mode.valueInForce()`, so a product realm narrows whatever is
//     stored.
//
//   * **In development any caller that can reach the TCP port can still
//     obtain an identity** (and, on the socket, any process when the native
//     module is missing). Nothing proves who it is; matching narrows WHICH
//     entries answer. **Product serves TCP only on a network declared to
//     authenticate source addresses, and answers only entries that select
//     something identifying** — `peer:` for TCP (#166, `entitledEntries()`
//     below, `spiffe_registry.ts`'s `answersWorkloads()`). And
//     `spiffe.autoCreateEntries` still invents one for a caller that matches
//     none. So the socket's filesystem permissions are still the only thing
//     standing between a process and an SVID here, which is the same statement
//     as "any bind succeeds" one directory over.
//
//   * **An INVENTED entry carries the caller's stable selectors** — its
//     transport and endpoint, and not its peer, whose port is ephemeral. That
//     is what stops a fresh entry being invented per connection until the
//     registry hits its cap, and it means the second caller of the same shape
//     MATCHES the first one's entry instead of inventing another.
//
//   * **`spiffe.autoCreateEntries` off is still the interesting setting.** With
//     it off, a caller matching no entry is answered with an EMPTY SVID list —
//     which is what a real agent does for an unregistered workload, and is the
//     only way to exercise a client's "I have no identity" path. That path is
//     the one most client libraries have and almost nobody runs.
//
// ---------------------------------------------------------------------------
// THE STREAMS ARE STREAMS, AND THAT IS THE SECOND THING TO GET RIGHT
//
// Five of the seven methods are server streams (two of them the unimplemented
// WIT methods), and a real client opens `FetchX509SVID` once and keeps it
// open for the life of the process. It
// expects a new `X509SVIDResponse` whenever anything changes — an SVID
// approaching expiry, an authority rotating, a federated bundle arriving.
//
// So these do not write once and end. `pushOnRotation()` below re-mints and
// re-writes at half the SVID lifetime, for as long as the client is there,
// which means a client's rotation handling is exercised BY DEFAULT rather than
// only if somebody waits an hour. A Workload API that answers once and ends the
// stream looks completely correct on the first fetch and puts `go-spiffe` into
// a reconnect loop.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SpiffeWorkload` takes the modules it uses through its constructor
// (`SpiffeWorkloadDeps`), and since #50's R2 the composition root builds the
// instance and installs it here. The module still exports its old names as
// FACADES forwarding to it, for the callers that are not converted; a process
// without the root builds a default when this module loads. `SpiffeWorkload` is
// exported for the root.
//
// **THE TABLES WHOSE ENTRIES CALL THIS MODULE** (`fetchX509Svid`,
// `fetchX509Bundles`, `fetchJwtSvid`, `fetchJwtBundles`, `validateJwtSvid`) are
// built by
// `build…()` methods, called at load where each was declared.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log } = helpers;
import config = require('../common/config');
// For `autoCreates()`: whether an entry may be invented for a caller that
// matches none. A leaf requiring only config.
import mode = require('../common/mode');
import audit = require('../common/audit');
// A LEAF. A handler marks the CALL with the condition before it throws a
// status, and `spiffe_grpc.ts`'s wrapper records it — see that file.
import errorCodes = require('../common/error_codes');
import stats = require('../common/admin_stats');
import spiffeId = require('./spiffe_id');
import ca = require('./spiffe_ca');
import registry = require('./spiffe_registry');
import rpc = require('./spiffe_grpc');
import auth = require('./spiffe_auth');

// What `SpiffeWorkload` needs from the rest of the service: the modules this
// file used to reach for itself, passed in so that the composition root can
// build one and a test can build one with stubs.
interface SpiffeWorkloadDeps {
  log: typeof log;
  config: typeof config;
  mode: typeof mode;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  stats: typeof stats;
  spiffeId: typeof spiffeId;
  ca: typeof ca;
  registry: typeof registry;
  rpc: typeof rpc;
  auth: typeof auth;
}

class SpiffeWorkload {
  constructor(private readonly deps: SpiffeWorkloadDeps) {
    deps.log.debug("Entering SpiffeWorkload.constructor().");
    deps.log.debug("Leaving SpiffeWorkload.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): SpiffeWorkloadDeps {
    helpers.log.debug("Entering SpiffeWorkload.defaultDeps().");
    helpers.log.debug("Leaving SpiffeWorkload.defaultDeps().");
    return {
      log: log,
      config: config,
      mode: mode,
      audit: audit,
      errorCodes: errorCodes,
      stats: stats,
      spiffeId: spiffeId,
      ca: ca,
      registry: registry,
      rpc: rpc,
      auth: auth
    };
  }

  trustDomain() {
    const { log, ca } = this.deps;
    log.debug("Entering SpiffeWorkload.trustDomain().");
    log.debug("Leaving SpiffeWorkload.trustDomain().");
    return ca.trustDomain();
  }

  // ---------------------------------------------------------------------------
  // WHICH IDENTITIES THE CALLER GETS.
  //
  // The one decision the header is about, made in one place so that all four
  // issuing methods answer consistently — a FetchX509SVID that returned three
  // identities and a FetchJWTSVID that returned one would be a mock that
  // contradicts itself.
  // ---------------------------------------------------------------------------
  entitledEntries(caller) {
    const { log, registry, auth, config, mode, spiffeId } = this.deps;
    log.debug('Entering SpiffeWorkload.entitledEntries().');
    const live = registry.allEntries().filter(function (entry) {
      return !entry.expired;
    });
    // The caller's selectors, where there is a caller. `caller` is absent when
    // the console asks this question — it is looking at the registry rather
    // than standing on a socket — and an absent caller means no narrowing,
    // which is the honest answer to "what is in here" as opposed to "what would
    // I get".
    const selectors = (caller && caller.selectors) || null;
    const narrow = !!(selectors && auth.attestWorkloads());
    // An entry that selects nothing identifying answers no caller in a
    // product realm (#166), however it got into the registry — the refusal
    // at the write is `checkRecord()`'s, and this is the read.
    const rows = (narrow ? live.filter(function (entry) {
      return registry.selectorsMatch(entry.selectors, selectors);
    }) : live).filter(function (entry) {
      return !caller || registry.answersWorkloads(entry);
    });
    if (narrow) {
      log.debug('entitledEntries(): ' + rows.length + ' of ' + live.length +
                ' entry/entries match [' +
                selectors.map(registry.selectorText).join(' ') + '].');
    }
    if (rows.length) {
      log.debug('Leaving SpiffeWorkload.entitledEntries(). ' + rows.length +
                ' entry/entries.');
      return rows;
    }
    // ---------------------------------------------------------------------
    // **TWO QUESTIONS, AND BOTH MUST SAY YES (2026-09-12).** The setting is the
    // operator's; `mode.autoCreates()` is the deployment's, and in product mode
    // it answers no whatever the setting holds — so `spiffe.autoCreateEntries`
    // cannot be left on by accident in a deployment and have every workload
    // that reaches the socket issued `spiffe://<domain>/workload`. That is rule
    // 2 of
    // `common/mode.js` read for SPIFFE: nothing is created because something
    // named it, and a caller that matched no entry is an unknown name.
    // ---------------------------------------------------------------------
    const settingSays = config.value('spiffe.autoCreateEntries');
    if (!settingSays || !mode.autoCreates()) {
      // The interesting answer. A real agent says exactly this to an
      // unregistered workload, and a client that has never seen it has never
      // run its own "I have no identity" path.
      log.info('spiffe: a workload asked for an SVID, no registration entry ' +
               (narrow ? 'matched its selectors' : 'exists') +
               (settingSays
                 ? ', and this realm is in product mode (global.mode), which ' +
                   'never invents one whatever spiffe.autoCreateEntries says'
                 : ', and spiffe.autoCreateEntries is off') +
               ' — so it is being answered with an empty SVID list, which is ' +
               'what a real agent does for an ' +
               'unregistered workload. Register ' +
               'it on /admin/spiffe/entries or through the SPIRE Server API.');
      log.debug('Leaving SpiffeWorkload.entitledEntries(). None, and none ' +
                'will be invented.');
      return [];
    }
    // Nothing matched and we are permitted to invent. ONE entry, named for what
    // it is, so that a person looking at /admin/spiffe/entries can see that
    // this service made it up rather than wondering who configured it.
    //
    // **IT CARRIES THE CALLER'S STABLE SELECTORS AND NOT ALL OF THEM.** The
    // peer is left off because its port is ephemeral: an entry selecting on
    // `peer:127.0.0.1` would match the next connection from that host, but one
    // selecting on the whole `127.0.0.1:53422` could never match anything
    // again, and a fresh entry would be invented per connection until the
    // registry hit
    // `spiffe.maxEntries`. With the transport and the endpoint on it, the
    // second caller of the same shape matches this entry rather than inventing
    // another.
    const inventedSelectors = (selectors || []).filter(function (selector) {
      return selector.type !== 'peer';
    });
    const id = spiffeId.make(this.trustDomain(), '/workload');
    const created = registry.createEntry({
      spiffeId: id,
      parentId: spiffeId.serverId(this.trustDomain()),
      selectors: inventedSelectors,
      description: 'Invented for a workload that matched no registration ' +
                   'entry (spiffe.autoCreateEntries).'
    }, 'auto', this.trustDomain(), '');
    if (!created.ok) {
      log.warn('spiffe: an entry could not be invented for an unmatched ' +
               'workload: ' + created.errors.join('; '));
      log.debug('Leaving SpiffeWorkload.entitledEntries(). None could be ' +
                'invented.');
      return [];
    }
    log.debug('Leaving SpiffeWorkload.entitledEntries(). One was invented.');
    return [created.entry];
  }

  // The federated bundles a holder of these entries should be given: the union
  // of every `federatesWith` on them, as a map keyed by the trust domain's
  // SPIFFE ID (not its bare name — the map key in both response messages is a
  // SPIFFE ID, and a bare name there is a map a client silently finds nothing
  // in).
  async federatedBundlesFor(entries) {
    const { log, ca, spiffeId } = this.deps;
    log.debug('Entering SpiffeWorkload.federatedBundlesFor().');
    const wanted = {};
    (entries || []).forEach(function (entry) {
      (entry.federatesWith || []).forEach(function (
          name) { wanted[name] = true; });
    });
    const out = {};
    Object.keys(wanted).forEach(function (name) {
      const der = ca.federatedX509BundleDer(name);
      if (der && der.length) {
        out[spiffeId.trustDomainId(name)] = der;
      } else {
        // A federation relationship configured before the bundle arrived. Not
        // an error and not silent: it is the ordinary order of events, and a
        // workload that gets no bundle for a trust domain its entry names has
        // no other way to find out why.
        log.debug('federatedBundlesFor(): ' + name + ' is named by an entry ' +
                  'and no bundle for it is held here, so nothing is sent for ' +
                  'it.');
      }
    });
    log.debug('Leaving SpiffeWorkload.federatedBundlesFor(). ' +
              Object.keys(out).length + ' ' +
        'bundle(s).');
    return out;
  }

  // ---------------------------------------------------------------------------
  // FetchX509SVID — the method everything else is built around.
  //
  // One `X509SVID` per entitled entry, each carrying the leaf chain, the
  // private key, and the trust domain's own X.509 bundle. All three are ASN.1
  // DER, NOT PEM, which is the single most common thing to get wrong here: a
  // PEM in these fields is a string a client will decode as DER and reject as
  // malformed, and the error names neither field.
  // ---------------------------------------------------------------------------
  // `observed`, when given, is told the SHORTEST lifetime among the SVIDs this
  // response carried — see `pushOnRotation()` for why the rotation timer needs
  // it.
  async buildX509Response(caller, observed) {
    const { log, ca, registry, stats, audit } = this.deps;
    log.debug('Entering SpiffeWorkload.buildX509Response().');
    const entries = this.entitledEntries(caller);
    const bundleDer = await ca.x509BundleDer();
    const svids = [];
    let shortest = 0;
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const svid = await ca.mintX509Svid(entry.spiffeId, {
        ttl: entry.x509SvidTtl,
        dnsNames: entry.dnsNames,
        hint: entry.hint
      });
      registry.noteSvidIssued(entry.id);
      // What the certificate ACTUALLY lives for, read off what was minted
      // rather than off the entry: `mintX509Svid()` clamps a leaf to its
      // issuer's own notAfter, so an entry's `x509SvidTtl` is an upper bound
      // and not a fact.
      const lifetime = svid.expiresAt - Math.floor(Date.now() / 1000);
      if (lifetime > 0 && (!shortest || lifetime < shortest)) {
        shortest = lifetime;
      }
      stats.recordSvid('X.509', {
        subject: entry.spiffeId, entryId: entry.id, serial: svid.serialHex,
        hint: entry.hint, expiresAt: svid.expiresAt,
        // The six facts about the certificate, for the directory entry this
        // identity gets. Passed at every X509-SVID mint rather than read back
        // there, because only the minting authority has the certificate — see
        // noteCertificateIssued() in admin_stats.js and certificateFacts() in
        // spiffe_ca.ts.
        certificate: svid.certificate
      });
      svids.push({
        spiffe_id: entry.spiffeId,
        x509_svid: svid.chainDer,
        x509_svid_key: svid.privateKeyDer,
        bundle: bundleDer,
        hint: entry.hint || ''
      });
    }
    audit.audit({
      action: 'spiffe.svid.issue', actor: '', protocol: 'SPIFFE Workload API',
      channel: 'grpc', target: svids.length === 1 ? svids[0].spiffe_id : '',
      summary: svids.length + ' X509-SVID(s) were issued over the Workload API',
      // The SVIDs themselves are never recorded — an X509-SVID is delivered
      // WITH ITS PRIVATE KEY, which makes this the sharpest case in the service
      // of audit.js's no-credential rule.
      detail: { count: svids.length,
                ids: svids.map(function (s) { return s.spiffe_id; }).join(' '),
                // WHICH SELECTORS DECIDED IT. Without this a row saying "two
                // SVIDs were issued" cannot be told from one saying "and here
                // is why those two" — and the second is the question somebody
                // reading this page after a client got nothing is asking.
                selectors: (((caller || {}).selectors) || [])
                  .map(registry.selectorText).join(' ') }
    });
    if (observed) {
      observed.shortest = shortest;
    }
    log.debug('Leaving SpiffeWorkload.buildX509Response(). ' + svids.length +
              ' SVID(s).');
    return {
      svids: svids,
      // No CRLs. SPIFFE has no revocation — the answer is a short lifetime and
      // rotation — and an empty list is the correct and conforming value rather
      // than a gap. Said here because a reader looking for revocation support
      // will look at this field first.
      crl: [],
      federated_bundles: await this.federatedBundlesFor(entries)
    };
  }

  // The rotation timer. Half the SVID lifetime, which is what SPIRE uses, and
  // it is what makes a client's rotation path run without anybody waiting an
  // hour.
  //
  // `push` returns false once the client has gone, which is what stops the
  // timer: a timer that outlived its stream would re-mint SVIDs for a workload
  // that is not there, and grpc-js reports a write to a dead stream as an
  // unhandled server error.
  //
  // ---------------------------------------------------------------------------
  // **HALF THE SHORTEST LIFETIME ACTUALLY SERVED, SINCE 2026-09-12.** It was
  // `max(30, spiffe.svidTtl / 2)` — the SERVICE default — while a registration
  // entry may carry its own `x509SvidTtl` and that one wins at the mint. So an
  // entry asking for a five-minute SVID was re-sent every half hour: the
  // workload held an expired certificate for twenty-five minutes of every
  // thirty, with nothing anywhere saying why. `lifetimeOf`, where given,
  // answers the shortest lifetime the LAST response carried, and the timer is
  // re-armed after every send so an entry edited mid-stream is followed on the
  // next rotation.
  //
  // **THE 30-SECOND FLOOR IS GONE FOR THE SAME REASON** — below a minute it
  // made the period LONGER than the lifetime. Every lifetime of a minute or
  // more gives exactly the period it gave before; the floor is one second,
  // which is only there so that an SVID clamped to nothing cannot spin the
  // loop.
  // ---------------------------------------------------------------------------
  rotationPeriod(lifetimeSeconds) {
    const { log, config } = this.deps;
    log.debug("Entering SpiffeWorkload.rotationPeriod().");
    const lifetime = Number(lifetimeSeconds) > 0
      ? Number(lifetimeSeconds) : config.value('spiffe.svidTtl');
    log.debug("Leaving SpiffeWorkload.rotationPeriod().");
    return Math.max(1, Math.floor(lifetime / 2));
  }

  pushOnRotation(push, buildResponse, label, lifetimeOf?) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering SpiffeWorkload.pushOnRotation().');
    const handle = { timer: null, stopped: false };
    function arm() {
      log.debug("Entering arm().");
      const period = self.rotationPeriod(lifetimeOf ? lifetimeOf() : 0);
      log.debug('pushOnRotation(): ' + label + ' will be re-sent in ' + period +
                ' second(s) while the client is there.');
      handle.timer = setTimeout(tick, period * 1000);
      // `unref` so a held-open stream cannot keep the process alive on its own.
      // Everything else in this service dies with the process and so should
      // this.
      if (handle.timer.unref) handle.timer.unref();
      log.debug("Leaving arm().");
    }

    function tick() {
      log.debug("Entering tick().");
      Promise.resolve()
        .then(buildResponse)
        .then(function (message) {
          if (!push(message)) {
            handle.stopped = true;
            log.debug('spiffe: the ' + label + ' rotation timer stopped; the ' +
                      'client has gone.');
            return;
          }
          arm();
        })
        .catch(function (err) {
          // A failure to re-mint must not take the stream down: the client is
          // holding a valid SVID until it expires, and an error here is better
          // reported than fatal. Re-armed, so the next rotation is still tried.
          log.error(errorCodes.tag('STS-SPIFFE-0030') +
                    'spiffe: could not re-send ' + label + ': ' + err.message);
          arm();
        });
      log.debug("Leaving tick().");
    }
    arm();
    log.debug('Leaving SpiffeWorkload.pushOnRotation().');
    return handle;
  }

  // THE WORK LOADING THIS MODULE USED TO DO WITH ITS OWN INSTANCE (#50, R2),
  // run by `common/instance_slot.ts` once for whichever instance is
  // installed: building the seven handlers, in the order loading this module
  // registered them with `spiffe_grpc.ts`, and the table of them.
  static wire(instance: SpiffeWorkload): void {
    helpers.log.debug("Entering SpiffeWorkload.wire().");
    const fetchX509Svid = instance.buildFetchX509Svid();

    const fetchX509Bundles = instance.buildFetchX509Bundles();

    const fetchJwtSvid = instance.buildFetchJwtSvid();

    const fetchJwtBundles = instance.buildFetchJwtBundles();

    const validateJwtSvid = instance.buildValidateJwtSvid();

    // FetchWITSVID and FetchWITBundles — DELIBERATELY UNIMPLEMENTED; see the
    // comment above `WIT_MESSAGE`.
    const fetchWitSvid = rpc.serverStream('workload', 'FetchWITSVID',
      async function (call) {
        errorCodes.mark(call, 'STS-SPIFFE-0029');
        throw rpc.statusError(rpc.grpc.status.UNIMPLEMENTED, WIT_MESSAGE);
      });

    const fetchWitBundles = rpc.serverStream('workload', 'FetchWITBundles',
      async function (call) {
        errorCodes.mark(call, 'STS-SPIFFE-0029');
        throw rpc.statusError(rpc.grpc.status.UNIMPLEMENTED, WIT_MESSAGE);
      });

    HANDLERS = {
      FetchX509SVID: fetchX509Svid,
      FetchX509Bundles: fetchX509Bundles,
      FetchJWTSVID: fetchJwtSvid,
      FetchJWTBundles: fetchJwtBundles,
      ValidateJWTSVID: validateJwtSvid,
      FetchWITSVID: fetchWitSvid,
      FetchWITBundles: fetchWitBundles
    };
    helpers.log.debug("Leaving SpiffeWorkload.wire().");
  }

  buildFetchX509Svid() {
    const { log, rpc, ca } = this.deps;
    const self = this;
    log.debug("Entering SpiffeWorkload.buildFetchX509Svid().");
    const fetchX509Svid = rpc.serverStream('workload', 'FetchX509SVID',
      async function (call, push) {
        await ca.ready();
        // The caller is captured ONCE and closed over, rather than read again
        // inside the timer. The stream outlives the call that opened it and the
        // rotation timer runs against a `call` whose metadata may be long gone
        // — and an SVID re-sent for a different set of selectors from the one
        // the client was first answered with would be a rotation that silently
        // changed the workload's identity.
        const caller = call.spiffeCaller;
        // The shortest lifetime the last response carried, written by every
        // build and read when the timer re-arms. The first response is built
        // BEFORE the timer is armed so the first period is already the entry's
        // rather than the service default.
        const observed = { shortest: 0 };
        const first = await self.buildX509Response(caller, observed);
        self.pushOnRotation(push,
                            function () { return self.buildX509Response(caller,
                                observed); },
                            'FetchX509SVID',
                            function () { return observed.shortest; });
        return first;
      });
    log.debug("Leaving SpiffeWorkload.buildFetchX509Svid().");
    return fetchX509Svid;
  }

  // ---------------------------------------------------------------------------
  // FetchX509Bundles — the trust bundles alone, with no SVID and no private
  // key.
  //
  // A separate method because a workload that only VERIFIES peers needs the
  // bundles and has no business being handed an identity. A client that fetches
  // SVIDs it never uses is a client holding private keys it does not need.
  // ---------------------------------------------------------------------------
  async buildX509BundlesResponse() {
    const { log, ca, spiffeId } = this.deps;
    log.debug('Entering SpiffeWorkload.buildX509BundlesResponse().');
    const bundles = {};
    const own = ca.trustDomainId();
    ca.federatedBundles().forEach(function (entry) {
      const key = spiffeId.trustDomainId(entry.trustDomain);
      // NEVER OVER THE REALM'S OWN KEY. `ca.federatedBundles()` already drops a
      // row named after a trust domain this service serves; this is the second
      // lock, and it is the one on the map a client actually reads — a
      // federated entry written into this key would replace the anchors a
      // workload checks its own trust domain's SVIDs against with somebody
      // else's.
      if (key === own) {
        return;
      }
      const der = ca.federatedX509BundleDer(entry.trustDomain);
      if (der && der.length) bundles[key] = der;
    });
    // WRITTEN LAST, so that no ordering of the loop above could leave anything
    // but this realm's own bundle under its own name.
    bundles[own] = await ca.x509BundleDer();
    log.debug('Leaving SpiffeWorkload.buildX509BundlesResponse(). ' +
              Object.keys(bundles).length + ' bundle(s).');
    return { crl: [], bundles: bundles };
  }

  buildFetchX509Bundles() {
    const { log, rpc, ca } = this.deps;
    const self = this;
    log.debug("Entering SpiffeWorkload.buildFetchX509Bundles().");
    const fetchX509Bundles = rpc.serverStream('workload', 'FetchX509Bundles',
      async function (call, push) {
        await ca.ready();
        self.pushOnRotation(push, self.buildX509BundlesResponse.bind(self),
                            'FetchX509Bundles');
        return await self.buildX509BundlesResponse();
      });
    log.debug("Leaving SpiffeWorkload.buildFetchX509Bundles().");
    return fetchX509Bundles;
  }

  // ---------------------------------------------------------------------------
  // FetchJWTSVID — unary, and the one method that takes a parameter that
  // matters.
  //
  // `audience` is REQUIRED and at least one. A JWT-SVID with no audience is a
  // bearer token good against anything that accepts one, which is why the
  // specification puts the audience in the request rather than in configuration
  // — and why this refuses an empty list rather than defaulting one. That
  // refusal is a conformance check of the same kind as the security header: a
  // client that omits the audience has a bug every real implementation will
  // report.
  //
  // `spiffe_id` is optional. Given, it narrows to that identity — and if the
  // caller is not entitled to it, the answer is an empty list rather than an
  // error, which is what SPIRE does: "you may not have that" and "there is no
  // such entry" are not distinguishable to a workload and should not be.
  // ---------------------------------------------------------------------------
  buildFetchJwtSvid() {
    const { log, rpc, ca, errorCodes, spiffeId, registry, stats,
            audit } = this.deps;
    const self = this;
    log.debug("Entering SpiffeWorkload.buildFetchJwtSvid().");
    const fetchJwtSvid = rpc.unary('workload', 'FetchJWTSVID',
                                   async function (call) {
      await ca.ready();
      const request = call.request || {};
      const audiences = (request.audience || []).map(function (a) {
        return String(a || '').trim();
      }).filter(Boolean);
      if (!audiences.length) {
        errorCodes.mark(call, 'STS-SPIFFE-0027');
        throw rpc.invalidArgument('FetchJWTSVID requires at least one ' +
                                  'audience. A JWT-SVID is a bearer ' +
                                  'credential — whoever holds it can present ' +
                                  'it — so the audience is what stops one ' +
                                  'issued for service A being replayed ' +
                                  'against service B. Every conforming ' +
                                  'Workload API refuses this call without ' +
                                  'one.');
      }
      const wanted = String(request.spiffe_id || '').trim();
      let entries = self.entitledEntries(call.spiffeCaller);
      if (wanted) {
        const parsed = spiffeId.parse(wanted);
        if (!parsed.ok) {
          errorCodes.mark(call, 'STS-SPIFFE-0028');
          throw rpc.invalidArgument('spiffe_id: ' + parsed.reason);
        }
        entries = entries.filter(function (entry) {
          return entry.spiffeId === parsed.id;
        });
      }
      const svids = [];
      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        const minted = await ca.mintJwtSvid(entry.spiffeId, audiences,
                                            { ttl: entry.jwtSvidTtl,
                                              hint: entry.hint });
        registry.noteSvidIssued(entry.id);
        stats.recordSvid('JWT', {
          subject: entry.spiffeId, entryId: entry.id, audiences: audiences,
          hint: entry.hint, expiresAt: minted.expiresAt
        });
        svids.push({ spiffe_id: entry.spiffeId, svid: minted.token,
                     hint: entry.hint || '' });
      }
      audit.audit({
        action: 'spiffe.svid.issue', actor: '', protocol: 'SPIFFE Workload API',
        channel: 'grpc', target: svids.length === 1 ? svids[0].spiffe_id : '',
        summary: svids.length +
                 ' JWT-SVID(s) were issued over the Workload API',
        // The audiences are recorded and the TOKENS are not. A JWT-SVID is a
        // bearer credential; a row holding one would be a credential on a web
        // page.
        detail: { count: svids.length, audience: audiences.join(' '),
                  selectors: (((call.spiffeCaller || {}).selectors) || [])
                    .map(registry.selectorText).join(' ') }
      });
      return { svids: svids };
    });
    log.debug("Leaving SpiffeWorkload.buildFetchJwtSvid().");
    return fetchJwtSvid;
  }

  // ---------------------------------------------------------------------------
  // FetchJWTBundles — the JWT verification keys, as JWK Sets.
  //
  // The map value is `bytes` holding a JWK Set document, which is the
  // structural difference from the X.509 bundles one method up: those are
  // concatenated DER, these are JSON. A client that treats them alike fails on
  // whichever it meets second.
  //
  // Only the `jwt-svid` keys go in. The bundle document this service publishes
  // at its bundle endpoint carries both kinds, and sending the X.509 half here
  // would be sending certificates to something that is going to parse them as
  // JWKs.
  // ---------------------------------------------------------------------------
  async jwtBundleFor(document) {
    const { log } = this.deps;
    log.debug("Entering SpiffeWorkload.jwtBundleFor().");
    const jwtKeys = (document.keys || []).filter(function (key) {
      return key.use === 'jwt-svid';
    });
    log.debug("Leaving SpiffeWorkload.jwtBundleFor().");
    return Buffer.from(JSON.stringify({ keys: jwtKeys }), 'utf8');
  }

  async buildJwtBundlesResponse() {
    const { log, ca, spiffeId } = this.deps;
    log.debug('Entering SpiffeWorkload.buildJwtBundlesResponse().');
    const bundles = {};
    const own = ca.trustDomainId();
    const federated = ca.federatedBundles();
    for (let i = 0; i < federated.length; i++) {
      const key = spiffeId.trustDomainId(federated[i].trustDomain);
      // Never over the realm's own key — see buildX509BundlesResponse().
      if (key === own) {
        continue;
      }
      bundles[key] = await this.jwtBundleFor(federated[i].document);
    }
    bundles[own] = await this.jwtBundleFor(await ca.bundle());
    log.debug('Leaving SpiffeWorkload.buildJwtBundlesResponse(). ' +
              Object.keys(bundles).length + ' bundle(s).');
    return { bundles: bundles };
  }

  buildFetchJwtBundles() {
    const { log, rpc, ca } = this.deps;
    const self = this;
    log.debug("Entering SpiffeWorkload.buildFetchJwtBundles().");
    const fetchJwtBundles = rpc.serverStream('workload', 'FetchJWTBundles',
      async function (call, push) {
        await ca.ready();
        self.pushOnRotation(push, self.buildJwtBundlesResponse.bind(self),
                            'FetchJWTBundles');
        return await self.buildJwtBundlesResponse();
      });
    log.debug("Leaving SpiffeWorkload.buildFetchJwtBundles().");
    return fetchJwtBundles;
  }

  // ---------------------------------------------------------------------------
  // ValidateJWTSVID — the one method in this whole family that says no.
  //
  // See the note in `spiffe_ca.validateJwtSvid()`: the point of this call is to
  // be told no, so a mock that said yes to everything would be useless to the
  // only person who would ever call it. It is the same exception
  // `/oauth2/userinfo` is among the token-reading endpoints.
  //
  // The `claims` field is a `google.protobuf.Struct`, which grpc-js builds from
  // a plain object — but only from JSON-shaped values. `aud` may be a string or
  // an array and both are fine; a `Buffer` or an `undefined` in there produces
  // a serialisation error naming the field and not the value.
  // ---------------------------------------------------------------------------
  buildValidateJwtSvid() {
    const { log, rpc, ca, audit, auth } = this.deps;
    const self = this;
    log.debug("Entering SpiffeWorkload.buildValidateJwtSvid().");
    const validateJwtSvid = rpc.unary('workload', 'ValidateJWTSVID',
                                      async function (call) {
      await ca.ready();
      const request = call.request || {};
      const result = await ca.validateJwtSvid(request.svid, request.audience);
      audit.audit({
        action: 'spiffe.svid.validate', actor: '',
        protocol: 'SPIFFE Workload API',
        channel: 'grpc', target: result.ok ? result.spiffeId : '',
        summary: 'A JWT-SVID was ' + (result.ok ? 'validated' : 'refused') +
                 ' at the Workload API',
        // The reason is recorded and the SVID is not.
        detail: result.ok ? { audience: String(request.audience || '') }
                          : { refused: result.reason },
        // THIS ROW carries the refusal's code, so the call is not marked below
        // and its own row does not count the same refusal twice.
        errorCode: result.ok ? '' : (result.errorCode || 'STS-SPIFFE-0037')
      });
      if (!result.ok) {
        throw rpc.invalidArgument(result.reason);
      }
      // ---------------------------------------------------------------------
      // A VERIFIED JWT-SVID IS A CREDENTIAL THAT WAS PRESENTED AND ACCEPTED, so
      // its subject reaches the authentication funnel and gets — or REUSES — a
      // directory entry, like every other accepted credential in this service.
      //
      // BELOW the refusal, deliberately: a JWT-SVID that failed its signature,
      // its audience or its clock records nothing, which is the rule
      // `/oid4vp/response` already follows about a presentation that did not
      // verify. And the identity recorded is the token's OWN subject rather
      // than the caller's — this method says "is this credential good", and the
      // holder of it is not necessarily the thing it names.
      //
      // No `once` key, so a token validated twice records twice. That is
      // correct here where it would be wrong for a connection: each call is a
      // fresh presentation of a bearer credential, and collapsing them would
      // hide a replay rather than tidy a duplicate.
      // ---------------------------------------------------------------------
      auth.recordIdentity({
        presented: result.spiffeId,
        protocol: 'SPIFFE',
        method: 'JWT-SVID (validated)',
        note:
          'a JWT-SVID naming this identity was presented at ValidateJWTSVID ' +
              'and verified against this trust domain\'s JWT authorities'
      });
      return { spiffe_id: result.spiffeId,
               claims: self.structFrom(result.claims) };
    });
    log.debug("Leaving SpiffeWorkload.buildValidateJwtSvid().");
    return validateJwtSvid;
  }

  // ---------------------------------------------------------------------------
  // A CLAIM SET AS A `google.protobuf.Struct`, BUILT BY HAND.
  //
  // This looks like something a library should do and no library here does it.
  // `@grpc/proto-loader` and protobufjs beneath it wrap exactly ONE well-known
  // type — `google.protobuf.Any` — so a plain JavaScript object assigned to a
  // Struct field serialises as a Struct with NO FIELDS. It does not throw and
  // it does not warn: `ValidateJWTSVID` answers 200 with the right `spiffe_id`
  // and
  // `claims: {}`, which reads as a token that carried no claims rather than as
  // a server that dropped them. That was this file's first version, and the
  // only reason it was caught is that a real client asked for the claims and
  // got none.
  //
  // So the shape is built explicitly. A Struct is `{ fields: { name: Value } }`
  // and a Value is a `oneof` of six — which is why each branch below sets
  // exactly ONE member: setting two leaves protobuf keeping whichever came
  // last, and a number silently becoming a string is the kind of thing a client
  // only notices when it compares `exp` against a clock.
  //
  // **AND THE MEMBER NAMES HERE ARE camelCase WHILE EVERY OTHER FIELD IN THIS
  // FAMILY IS snake_case.** That is not a slip and it cost an hour. `keepCase:
  // true` in `spiffe_grpc.ts` tells the loader not to camel-case the fields of
  // the files it PARSES — which is why the handlers say `spiffe_id` and
  // `x509_svid_key`. `google/protobuf/struct.proto` is not one of those files:
  // protobufjs carries the well-known types as pre-built descriptors whose JS
  // names are already camelCase, and `keepCase` never reaches them. So
  // `string_value` here serialises to NOTHING — no throw, no warning, a Struct
  // with the right field names and every value empty — and `stringValue` works.
  // The same is true of any other well-known type with fields; `Empty` and the
  // `BoolValue`/`StringValue` wrappers happen not to be affected, the first
  // because it has no fields and the second because its one field is called
  // `value` in both spellings.
  // ---------------------------------------------------------------------------
  structFrom(value) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SpiffeWorkload.structFrom().");
    const fields = {};
    Object.keys(value || {}).forEach(function (key) {
      fields[key] = self.valueFrom(value[key]);
    });
    log.debug("Leaving SpiffeWorkload.structFrom().");
    return { fields: fields };
  }

  valueFrom(value) {
    const { log } = this.deps;
    log.debug('Entering SpiffeWorkload.valueFrom().');
    if (value === null || value === undefined) {
      // NULL_VALUE is the zero of its enum, written by name because the loader
      // is configured with `enums: String`.
      log.debug('Leaving SpiffeWorkload.valueFrom().');
      return { nullValue: 'NULL_VALUE' };
    }
    if (typeof value === 'boolean') {
      log.debug('Leaving SpiffeWorkload.valueFrom().');
      return { boolValue: value };
    }
    if (typeof value === 'number') {
      // A non-finite number has no protobuf representation. It cannot arrive
      // from a verified JWT payload — JSON has no NaN — but a Struct that will
      // not serialise fails the whole call with a message about a field, so the
      // impossible case is answered rather than left to be discovered.
      log.debug('Leaving SpiffeWorkload.valueFrom().');
      return Number.isFinite(value) ? { numberValue: value }
                                    : { stringValue: String(value) };
    }
    if (typeof value === 'string') {
      log.debug('Leaving SpiffeWorkload.valueFrom().');
      return { stringValue: value };
    }
    if (Array.isArray(value)) {
      log.debug('Leaving SpiffeWorkload.valueFrom().');
      return { listValue: { values: value.map(this.valueFrom.bind(this)) } };
    }
    log.debug('Leaving SpiffeWorkload.valueFrom().');
    return { structValue: this.structFrom(value) };
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
const slot = new InstanceSlot<SpiffeWorkload>(
  'spiffe/spiffe_workload',
  () => new SpiffeWorkload(SpiffeWorkload.defaultDeps()),
  SpiffeWorkload.wire,
  helpers.log);

// ---------------------------------------------------------------------------
// FetchWITSVID and FetchWITBundles — DELIBERATELY UNIMPLEMENTED, and this is
// the one place in this family where that is the honest answer.
//
// WIT — the Workload Identity Token — is in the current `workloadapi.proto` and
// `wit-svid` is a `use` value the bundle specification names, so the methods
// are on the service and a client may call them. What is NOT settled anywhere
// this service could read is the TOKEN ITSELF: its header, its claim set, and
// how a `wit_svid_key` relates to it.
//
// Minting something JWS-shaped and calling it a WIT-SVID would be inventing a
// credential format. That is worse than not implementing it, and it is worse in
// the specific way this whole service is built to avoid: a client author would
// write code against this mock's invention, it would work here, and it would
// interoperate with nothing. The same reasoning that stops `wsfed.ts` from
// writing a second factor into an assertion that did not happen — it asks for
// one, since 2026-09-17, and refuses when it still did not.
//
// So: `Unimplemented`, with a message that says what it is and what it would
// take, rather than a silent empty response — which a client would read as "I
// am entitled to no WIT-SVIDs" and never ask about again.
// ---------------------------------------------------------------------------
const WIT_MESSAGE =
  'This service does not issue WIT-SVIDs. The methods are on the service ' +
  'because they are in the SPIFFE project\'s own workloadapi.proto, and ' +
  '`wit-svid` is a `use` value the bundle specification names — but the ' +
  'Workload Identity Token\'s own format is not settled in a specification ' +
  'this service could implement against. Minting something JWS-shaped and ' +
  'calling it a WIT-SVID would be inventing a credential format, which is ' +
  'the one thing a mock must not do: code written against the invention ' +
  'would work here and interoperate with nothing. X509-SVIDs and JWT-SVIDs ' +
  'are fully implemented.';

// The handler map, keyed by the method names `@grpc/proto-loader` produced.
// They are camelCase with the leading letter lowered — `fetchX509Svid`, not
// `FetchX509SVID` — which is the loader's convention and is NOT what the
// `.proto` says. Getting it wrong produces a server that starts, advertises the
// service, and answers `Unimplemented` to everything, with nothing in the logs.
//
// Built by `SpiffeWorkload.wire()` when the instance is installed (#50, R2):
// every handler is registered through `spiffe_grpc.ts`, whose instance the
// root has installed by then.
let HANDLERS: Record<string, any> | null = null;

// What this surface implements, for the pages that describe it. `implemented`
// is a claim rather than a count, and the two WIT methods say why they are not
// — a table that reported seven of seven would be the most misleading thing on
// the page.
const METHOD_NOTES = {
  FetchX509SVID: { implemented: true,
    what: 'One X509-SVID per registration entry, each with its private key ' +
          'and the trust domain bundle, all DER. The stream stays open and ' +
          're-sends at half the SVID lifetime, so a client\'s rotation ' +
          'handling runs without anybody waiting an hour.' },
  FetchX509Bundles: { implemented: true,
    what: 'The X.509 trust bundles alone — this trust domain\'s and every ' +
          'federated one\'s — with no identity and no private key.' },
  FetchJWTSVID: { implemented: true,
    what: 'A JWT-SVID per entitled identity for the audience(s) asked for. ' +
          'Refuses a call with no audience, which every conforming ' +
          'implementation does.' },
  FetchJWTBundles: { implemented: true,
    what: 'The JWT verification keys as JWK Sets — JSON, where the X.509 ' +
          'bundles are concatenated DER.' },
  ValidateJWTSVID: { implemented: true,
    what: 'Really verifies: signature against the trust domain\'s JWT ' +
          'authorities, exp with no leeway, the audience, and that the sub ' +
          'belongs to the trust domain whose key verified it. The one method ' +
          'here that says no.' },
  FetchWITSVID: { implemented: false, what: WIT_MESSAGE },
  FetchWITBundles: { implemented: false, what: WIT_MESSAGE }
};

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  SpiffeWorkload: SpiffeWorkload,
  installInstance: (instance: SpiffeWorkload): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // Built by `SpiffeWorkload.wire()`, so read once the instance exists.
  get HANDLERS(): Record<string, any> {
    log.debug("Entering HANDLERS().");
    slot.get();
    log.debug("Leaving HANDLERS().");
    return HANDLERS;
  },
  METHOD_NOTES: METHOD_NOTES,
  WIT_MESSAGE: WIT_MESSAGE,
  // Exported for the console's "what would this workload get" view, which asks
  // the same question the Workload API answers and must not compute it a second
  // way. Called with NO caller there, which means no selector narrowing — the
  // console is looking at the registry rather than standing on a socket, and
  // "what is in here" is a different question from "what would I get".
  entitledEntries: slot.forward('entitledEntries'),
  // For tests/ssf_spiffe_scim_hardening.js, which asserts the rotation period
  // follows the shortest lifetime served rather than the service default.
  rotationPeriod: slot.forward('rotationPeriod'),
  buildX509Response: slot.forward('buildX509Response')
};
