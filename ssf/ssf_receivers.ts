'use strict';

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SsfReceivers` takes node's `crypto`, the logger, `randomId()`,
// `iso()`, `common/crypto.js`, `cluster/cluster_secrets.ts`, `config`, `mode`,
// `realms`, `audit`, `ssf_subjects.js`, `ssf_events.js`, `ssf_streams.ts`,
// `ssf_http.ts` and the error-code registry through its constructor. The inbox
// store and the SURFACES table stay module-level declarations (a store becomes
// per realm where it is DECLARED), and the module still exports its old names
// from a TRANSITIONAL instance for `admin-ui/admin.ts`, `portal/portal.ts` and
// `ssf/ssf.ts`, which require it by those names.
// ---------------------------------------------------------------------------

//
// File: ssf_receivers.ts
//
// ===========================================================================
// THIS SERVICE'S OWN TWO SURFACES, AS SHARED SIGNALS RECEIVERS (2026-09-10).
//
// The admin console and the user portal are **registered receivers** of this
// service's own transmitter: each has a stream of its own, seeded per trust
// realm, asking for every CAEP and every RISC event type; each hosts a receive
// endpoint that a Security Event Token is POSTed to; and each draws what has
// arrived on a page of its own — `/admin/signals` and `/portal/signals`.
//
// **THIS IS THE SECOND TIME A SURFACE OF THIS SERVICE BECAME A CLIENT OF A
// PROTOCOL THIS SERVICE SPEAKS, AND THE ARGUMENT IS THE FIRST ONE'S.**
// `common/oidc_rp.ts` made both of them OpenID Connect relying parties on
// 2026-09-06, and its complaint was that this service's own two applications
// were the only applications in the process that did not use the protocol this
// service exists to demonstrate — a real relying party has no access to the
// provider's session store and these two read it. The same sentence is true a
// second time: a page drawing a security event by reaching into `caep.ts`'s
// register is not a receiver, it is this service reading its own notes. A
// receiver is something a stream was agreed with, that gets a signed document
// it has to verify, addressed to an audience it has to recognise.
//
// ---------------------------------------------------------------------------
// DELIVERY IS RFC 8935 PUSH, OVER THE LOOPBACK INTERFACE, AND IN-PROCESS
// DELIVERY WAS WRITTEN FIRST AND TAKEN OUT.
//
// Handing the SET to the inbox by function call would have skipped the body,
// the media type, the authorization header and the signature — which is to say
// it would have skipped everything a receiver does, leaving only the part that
// looks run. That is `oidc_rp.js`'s own argument about redeeming an
// authorization code in process, made again rather than cited, because this is
// a different protocol and the skipped steps are different steps.
//
// So the stream's `delivery.endpoint_url` is this service's own address and
// `ssf_http.ts` dials it like any other receiver — with its certificate pinned,
// the three lines `oidc_rp.js`'s back channel uses. `ssf_http.ts`'s
// `isOwnLoopback()` carries the two bounds that do not apply to this one
// address and why.
//
// **`ssf.pushDelivery` IS NOT ONE OF THE EXEMPTIONS.** With it off this service
// makes no outbound request at all and both internal receivers go silent. That
// is said at seeding time, on both inbox pages and in `status()` below, rather
// than left to be discovered as "the page shows nothing".
//
// ---------------------------------------------------------------------------
// THE STREAMS ARE IN EVERY REALM, AND FOR A REASON OF THEIR OWN.
//
// This section once argued that the streams were in every realm while the
// console's CLIENT entry was in the default realm only. That disagreement is
// gone: `applications.js` seeds `sts-admin-console` in every realm since
// 2026-09-11 (its row says why), and a realm has administrators of its own
// since 2026-09-14 (#32, `admin-ui/admin_scope.ts`). The streams' reason never
// depended on either. Events happen in the realm they happen in, streams are
// per realm (`ssf_streams.ts` argues why at length), and the console draws ONE
// REALM AT A TIME — so a console with no stream in `acme` would show an empty
// page in `acme` while `acme`'s sessions were being revoked.
//
// The rule underneath it: **a client entry is about signing somebody IN and a
// stream is about what HAPPENED**, and those two questions are answered
// separately even where, as now, the answers agree.
//
// ---------------------------------------------------------------------------
// THE INBOX IS A MAP KEYED BY `jti` AND NOT AN ARRAY, WHICH IS THE ONE PLACE
// THIS FILE DIFFERS FROM `ssf_streams.ts`'s `received` LIST ON PURPOSE.
//
// That list is `realms.arr({ merge: 'own' })` — each process keeps its own and
// they are never merged — and for the debugger's receiver that is right, since
// it is one list somebody watches on one page. These two are read by the ADMIN
// CONSOLE and the USER PORTAL, which under `workers.requestCount` are answered
// by whichever worker the pool chose while the pushes fan across all of them.
// An array merged `own` would show a reader whatever fraction of their signals
// happened to land on the worker drawing the page; an array merged `replace`
// would lose an append whenever two workers received at once.
//
// One row per SET, keyed `<surface>|<jti>`, written once and never rewritten,
// is neither: the change log carries each row to every process and there is no
// concurrent write to a row to lose. `persistence/CLAUDE.md`'s coordination is
// doing the work, which is the rule that file states — a store is shared by
// coordination, and anything that is not a row in a store is not.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route: the two receive endpoints
// and the two pages are registered by the two SURFACES, because a receiver
// hosts its own endpoint and a page belongs to the application it is a page
// of. It requires `helpers`, `config`, `realms`, `audit`, `mode`,
// `common/crypto.js`, `cluster/cluster_secrets.ts`, the error-code registry,
// `ssf_subjects`, `ssf_events`, `ssf_streams` and `ssf_http` — every one of
// them a library that registers nothing and none of which requires this file —
// so it can be required from `admin-ui/admin.ts` (18) and `portal/portal.ts`
// (just after `authn`, 8) without moving a route or closing a cycle, which is
// the test rule 3e sets.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
// For `deriveSharedCredential()` alone — see `receiverToken()`. A LIBRARY
// (rule 3): it registers no route, so requiring it here moves nothing and it
// cannot join a cycle.
import stsCrypto = require('../common/crypto');
// The secrets every node shares (2026-09-14, #46). A LIBRARY; see
// internalSecret().
import clusterSecrets = require('../cluster/cluster_secrets');
import config = require('../common/config');
// For `inventsClaimValues()` in `namesPerson()`. A leaf requiring only config.
import mode = require('../common/mode');
import realms = require('../common/realms');
import audit = require('../common/audit');
import subjects = require('./ssf_subjects');
import events = require('./ssf_events');
import streams = require('./ssf_streams');
import transport = require('./ssf_http');
// The error-code registry, a LEAF. accept() is handed the request and not the
// response — the surfaces send their own — so a refusal is marked on
// `req.res`, the response express attaches to every request, which is the
// object the call-log funnel reads the code from. It is never serialised.
import errorCodes = require('../common/error_codes');

// ---------------------------------------------------------------------------
// THE TWO SURFACES. This table is the whole register — there is no second list
// of them anywhere — and each row says what the surface IS rather than what it
// draws, because the drawing belongs to the surface.
//
// `sees` is the one member with a security consequence and it is the reason
// these are two rows rather than one with a loop over it:
//
//   * `all`  — every signal delivered in the realm being read. The console.
//   * `own`  — only the signals whose SUBJECT is the signed-in person. The
//              portal, where OWASP A01 is the rule the whole directory is
//              written under: no route there takes an identity from the
//              request, and a page that showed one person another person's
//              account lockout would be the same failure by a different door.
// ---------------------------------------------------------------------------
const SURFACES = [
  { id: 'admin-console',
    label: 'Admin console',
    // The seeded client entry's identifier, and the stream's `aud`. It is a
    // name this service really knows the surface by rather than one invented
    // here — `ssf_streams.ts` refuses to default an audience at all, and
    // inventing one for ourselves would be the same mistake made privately.
    audience: 'sts-admin-console',
    receivePath: '/admin/signals/receive',
    inboxPath: '/admin/signals',
    sees: 'all',
    what: 'This service\'s own administration console, at /admin. It takes ' +
          'every CAEP and RISC event delivered in the realm being read.' },
  { id: 'user-portal',
    label: 'User portal',
    audience: 'sts-user-portal',
    receivePath: '/portal/signals/receive',
    inboxPath: '/portal/signals',
    sees: 'own',
    what: 'This service\'s own user portal, at /portal. It takes every CAEP ' +
          'and RISC event in the realm, and each person is shown only the ' +
          'ones whose subject is them.' }
];

const SURFACE_BY_ID = {};
SURFACES.forEach(function (one) {
  SURFACE_BY_ID[one.id] = one;
});

// ---------------------------------------------------------------------------
// THE INBOXES. `<surface id>|<jti>` -> entry, one partition per trust realm.
// See the header for why it is a map rather than a list.
// ---------------------------------------------------------------------------
const inbox = realms.map({ persist: 'ssf_receivers.inbox' });

// ---------------------------------------------------------------------------
// THE BEARER TOKEN ON A SEEDED STREAM, AND WHY IT IS DERIVED RATHER THAN
// RANDOM (2026-09-11).
//
// It used to be `randomId(32)`, and that was correct in the only arrangement
// this service had when it was written: one process, which both transmits and
// receives, so the token minted at startup is the token checked on arrival.
//
// **A DISPATCHED SERVICE IS SEVERAL PROCESSES AND `seedStreams()` RUNS IN EVERY
// ONE OF THEM.** The front process and each request worker load the whole
// protocol stack, so each seeded its own pair of streams with its own random
// token — and these streams are minted state, which development mode does not
// persist and therefore does not coordinate, so nothing reconciled them. The
// transmitter ran in whichever process the event happened in and the loopback
// push landed on whichever worker the front process routed it to, so the two
// almost never matched: **every push this service made to itself was refused
// with "the wrong authorization header"**, retried, and refused again.
//
// It cost nothing visible and a great deal of everything else. Measured on
// 2026-09-11 during the SCIM bulk load: 132,546 refused pushes in half an hour
// across eight realms, on a service whose own inbox pages were simply empty —
// no assertion anywhere fails when a receiver hears nothing, because "nothing
// happened" and "everything was refused" look identical from a page.
//
// So the token is DERIVED: one secret per run, in the environment so that a
// forked worker inherits it, and an HMAC over the realm and the surface so that
// every process arrives at the same answer without being told, and so that the
// console's token is still not the portal's. `crypto.js` carries the
// derivation, because that is where this service does cryptography.
//
// **THE SECRET WAS PER RUN AND NEVER WRITTEN DOWN**, which kept the sentence
// above `randomId(32)` true: a credential this service mints for itself that
// nothing but this service's own transmitter has ever been given. The second
// half still holds; the first changed with #46, below — on a store several
// nodes share, the secret is kept there, sealed, so every node agrees on it.
// ---------------------------------------------------------------------------
const SECRET_VAR = 'STS_SSF_RECEIVER_SECRET';

// A received entry, a status and a drawn row are open records: members are
// added to each after it is built, as the JavaScript did.
interface Loose {
  [member: string]: any;
}

interface SsfReceiversDeps {
  nodeCrypto: typeof nodeCrypto;
  log: typeof helpers.log;
  randomId: typeof helpers.randomId;
  iso: typeof helpers.iso;
  stsCrypto: typeof stsCrypto;
  clusterSecrets: typeof clusterSecrets;
  config: typeof config;
  mode: typeof mode;
  realms: typeof realms;
  audit: typeof audit;
  subjects: typeof subjects;
  events: typeof events;
  streams: typeof streams;
  transport: typeof transport;
  errorCodes: typeof errorCodes;
}

class SsfReceivers {
  constructor(private readonly deps: SsfReceiversDeps) {
    deps.log.debug("Entering SsfReceivers.constructor().");
    deps.log.debug("Leaving SsfReceivers.constructor().");
  }

  surfaceOf(id?) {
    const { log } = this.deps;
    log.debug("Entering SsfReceivers.surfaceOf(). " + id);
    const row = SURFACE_BY_ID[String(id || '')] || null;
    log.debug("Leaving SsfReceivers.surfaceOf(). " + (row ? row.label :
                                                      '(none)'));
    return row;
  }

  enabled() {
    const { log, config } = this.deps;
    log.debug("Entering SsfReceivers.enabled().");
    const on = !!config.value('ssf.enabled') &&
               !!config.value('ssf.internalReceivers');
    log.debug("Leaving SsfReceivers.enabled(). " + on);
    return on;
  }

  private inboxLimit() {
    const { log, config } = this.deps;
    log.debug("Entering SsfReceivers.inboxLimit().");
    const value = Number(config.value('ssf.maxReceivedEvents'));
    const out = (Number.isFinite(value) && value > 0) ? value : 200;
    log.debug("Leaving SsfReceivers.inboxLimit(). " + out);
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE STREAM FOR ONE SURFACE IN THE REALM THAT IS AMBIENT.
  //
  // Found by walking this realm's streams rather than by holding an id, and
  // that is the same rule `oidc_rp.js` reads its client entry under: there are
  // four doors onto a stream — the management API, `/admin/ssf`,
  // `/admin-api/ssf` and the seeding below — and a remembered id would be the
  // copy that is wrong exactly when somebody has just deleted one.
  // ---------------------------------------------------------------------------
  // THE DERIVED ID FIRST, THE MARKER SECOND, AND THE ORDER IS THE POINT
  // (2026-09-12). `internalSurface` is set on the record after `createStream()`
  // returns and is not an SSF member, so it is the half of this lookup that can
  // go missing across a persisted round-trip — and a lookup that missed would
  // seed again, which with a derived id means OVERWRITING the stream that is
  // already there. That would quietly undo a pause, and "an existing stream is
  // left exactly as it is" is this function's whole job. The id is computed
  // from the realm and the surface, so it cannot be lost.
  streamFor(surfaceId?) {
    const { log, streams } = this.deps;
    log.debug("Entering SsfReceivers.streamFor(). " + surfaceId);
    const id = String(surfaceId || '');
    const surface = SURFACES.filter((one) => { return one.id === id; })[0];
    const all = streams.listStreams();
    const byId = surface
      ? all.filter((record) => {
          return record.stream_id === this.internalStreamId(surface);
        })[0]
      : null;
    const found = byId || all.filter((record) => {
      return record.internalSurface === id;
    })[0] || null;
    log.debug("Leaving SsfReceivers.streamFor(). " + (found ? found.stream_id :
                                                      '(none)'));
    return found;
  }

  // Where the push is sent: this process's own address, the ambient realm's
  // prefix, and the surface's receive path. The realm prefix is what keeps a
  // realm's signals inside it — a push to the unprefixed path would be received
  // in the DEFAULT realm's inbox and read there by somebody who was never shown
  // that realm.
  endpointFor(surface?) {
    const { log, realms, transport } = this.deps;
    log.debug("Entering SsfReceivers.endpointFor(). " + surface.id);
    const out = transport.loopbackOrigin() + realms.currentPrefix() +
                surface.receivePath;
    log.debug("Leaving SsfReceivers.endpointFor(). " + out);
    return out;
  }

  // **THE CLUSTER'S SINCE 2026-09-14 (#46).** Per run, a push from another
  // container's transmitter to this node's receiver carried a token derived
  // from a secret this node did not hold. `cluster/cluster_secrets.ts` owns it
  // now and keeps the environment channel described above: the front process
  // puts the shared value in `SECRET_VAR` before it forks.
  private internalSecret() {
    const { log, clusterSecrets } = this.deps;
    log.debug("Entering SsfReceivers.internalSecret().");
    const held = clusterSecrets.text('ssf-receiver');
    log.debug("Leaving SsfReceivers.internalSecret().");
    return held;
  }

  private receiverToken(surface?) {
    const { log, realms, stsCrypto } = this.deps;
    log.debug("Entering SsfReceivers.receiverToken().");
    log.debug("Leaving SsfReceivers.receiverToken().");
    return 'Bearer ' + stsCrypto.deriveSharedCredential(
      this.internalSecret(), 'ssf-internal-receiver', realms.currentId(),
          surface.id);
  }

  // ---------------------------------------------------------------------------
  // THE STREAM'S ID, DERIVED — AND THE SECOND HALF OF THE FIX THE TOKEN GOT ON
  // 2026-09-11 (2026-09-12).
  //
  // That day made the TOKEN the same in every process, because each process
  // seeded its own and every loopback push was refused. What it left alone was
  // the stream's IDENTITY: `createStream()` minted `'ssf-' + randomId(12)`, so
  // each process still created a stream OF ITS OWN. In development mode that is
  // invisible — minted state is per process and nothing reconciles it — but
  // with a persisted, coordinated store the duplicates are shared and they
  // SURVIVE, so they accumulate: the front process and each request worker seed
  // a pair per start, and every start adds more.
  //
  // **AND EVERY EVENT IS PUSHED TO ALL OF THEM.** `emitProtocolEvent()` fans
  // out to every stream that asks for the type, so the cost of one session
  // event grows with how many times this service has ever started. Measured on
  // a four-hour test stack: FOURTEEN streams in the default realm where two are
  // intended — seven pairs, at seven timestamps — and a bulk load logging `went
  // to 12 of 12 stream(s)` for 16,421 events, which is close to two hundred
  // thousand loopback pushes. The front process pinned at a full core and the
  // worker sockets answered EAGAIN 19,737 times.
  //
  // So the id is derived, and the two rules it has to satisfy are different
  // from the token's:
  //
  //   * **IT MUST NOT USE `internalSecret()`.** That secret was per RUN when
  //     this was written, and still is on a store that cannot share (#46 keeps
  //     it in a store that can) — it is generated at startup and put in the
  //     environment so a forked worker inherits it — which is exactly right for
  //     a credential and exactly wrong here: an id derived from it agrees
  //     across the processes of ONE run and changes on the next start, which is
  //     the accumulation this exists to stop, moved one level along.
  //   * **IT IS NOT A SECRET AND MUST NOT LOOK LIKE ONE.** A stream id is
  //     published on /admin/ssf and in every stream configuration. So it is the
  //     realm and the surface, written out, rather than a hash of them: a
  //     reader who sees `ssf-internal-default-admin-console` knows what it is,
  //     and a hash would only have hidden which of fourteen streams was which.
  //
  // Both components are already constrained to the charset: a realm id is
  // `common/realms.js`'s `/^[a-z0-9][a-z0-9-]{0,30}$/` and the two surface ids
  // are written out in SURFACES above.
  // ---------------------------------------------------------------------------
  private internalStreamId(surface?) {
    const { log, realms } = this.deps;
    log.debug("Entering SsfReceivers.internalStreamId().");
    log.debug("Leaving SsfReceivers.internalStreamId().");
    return 'ssf-internal-' + realms.currentId() + '-' + surface.id;
  }

  // ---------------------------------------------------------------------------
  // SEED THE TWO STREAMS INTO THE REALM THAT IS AMBIENT.
  //
  // Called once for the default realm and again from `realms.onCreate()` for
  // every realm made afterwards — the arrangement `applications.js`'s internal
  // client entries have, and for its reason.
  //
  // **AN EXISTING STREAM IS LEFT EXACTLY AS IT IS**, which is `seedInternal`'s
  // rule word for word: somebody who paused one of these, or narrowed the event
  // types on it, or deleted it, meant it. Deleting one takes that surface's
  // signals away until a restart, and the inbox page says so rather than
  // silently seeding another.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE ONES THAT ACCUMULATED BEFORE THE ID WAS DERIVED (2026-09-12).
  //
  // The fix above stops new duplicates: the id is the same in every process,
  // and `createStream()` writes with `store.set(stream_id, …)`, so a second
  // seeder overwrites rather than adds. It does nothing about the ones already
  // in a persisted store, and those are the expensive ones — a test stack four
  // hours old held fourteen where two belong, and every event was pushed to all
  // of them.
  //
  // **IT IDENTIFIES THEM BY WHERE THEY DELIVER, NOT BY THE MARKER.**
  // `streamFor()` reads `internalSurface`, which is set on the record AFTER
  // `createStream()` returns and is not an SSF member — and a marker is exactly
  // what may not have survived the round-trip that produced the duplicates in
  // the first place. The delivery endpoint is a core member of every stream
  // configuration, it is this realm's own loopback receive path, and it is
  // therefore the thing that cannot have been lost.
  //
  // **IT REFUSES TO TOUCH ANYTHING WITH THE DERIVED ID**, which is what keeps
  // this from eating the stream it is about to seed — and it says out loud what
  // it removed, because a stream disappearing is otherwise indistinguishable
  // from a receiver that was never registered.
  //
  // It runs in every process, which is harmless: deleting an id twice is a
  // no-op, and the alternative is a sweep that only happens in whichever
  // process somebody decided was special.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // AND ANOTHER REALM'S RECEIVER STREAM, WHICH IS A DIFFERENT DEFECT WITH THE
  // SAME COST (2026-09-14).
  //
  // `realms.js`'s `partitionId()` sent a replicated row for a realm this
  // process had not heard of yet into the DEFAULT partition, and a stream row
  // is minted milliseconds after the realm it belongs to. A dispatch run's
  // default realm held forty such streams — `ssf-internal-<other
  // realm>-admin-console` and its portal twin, one pair per realm a job created
  // — so every default-realm event was pushed forty-two times, and the forty
  // pushed into another realm's receiver were refused and queued for ever. The
  // partition is fixed; this removes what a store already holds.
  //
  // **BY ID, NOT BY ENDPOINT.** The endpoint names the other realm's prefix, so
  // it differs from this realm's by design, and the loopback origin may differ
  // between starts. A stream id beginning `ssf-internal-` is only ever set by
  // `seedStreams()` — `createStream()` takes it from the context and never from
  // a request body — so an id of that shape for this surface that is not this
  // realm's own is a leaked copy and nothing else.
  // ---------------------------------------------------------------------------
  private isOtherRealmsReceiver(record?, surface?, keep?) {
    const { log } = this.deps;
    log.debug("Entering SsfReceivers.isOtherRealmsReceiver().");
    const id = String((record && record.stream_id) || '');
    const out = id !== keep && id.indexOf('ssf-internal-') === 0 &&
                id.length > ('ssf-internal--' + surface.id).length &&
                id.slice(-(surface.id.length + 1)) === '-' + surface.id;
    log.debug("Leaving SsfReceivers.isOtherRealmsReceiver(). " + out);
    return out;
  }

  private sweepDuplicates(surface?) {
    const { log, audit, realms, streams } = this.deps;
    log.debug("Entering SsfReceivers.sweepDuplicates(). " + surface.id);
    const keep = this.internalStreamId(surface);
    const endpoint = this.endpointFor(surface);
    const stale = streams.listStreams().filter((record) => {
      return record.stream_id !== keep &&
             ((record.delivery &&
               record.delivery.method === streams.DELIVERY_PUSH &&
               String(record.delivery.endpoint_url || '') === endpoint) ||
              this.isOtherRealmsReceiver(record, surface, keep));
    });
    stale.forEach((record) => {
      streams.removeStream(record.stream_id);
      log.warn('ssf: removed ' + record.stream_id + ' (created ' +
               record.createdAt + ') from the "' + realms.currentId() +
               '" realm: it is a copy of this service\'s own ' + surface.label +
               ' receiver that does not belong here — a duplicate seeded ' +
               'before the stream id was derived, or another realm\'s ' +
               'receiver a replicated row put in this realm before it knew ' +
               'that realm. Every event was pushed to every copy. The ' +
               'surviving stream is ' +
               keep + '.');
    });
    if (stale.length) {
      audit.audit({ action: 'ssf.stream.swept', category: 'signals',
        protocol: 'SSF', channel: 'internal', outcome: 'success',
        target: surface.id,
        summary: 'Removed ' + stale.length + ' duplicate ' + surface.label +
          ' receiver stream(s) in the "' + realms.currentId() + '" realm',
        detail: { kept: keep,
                  removed:
                    stale.map((one) => { return one.stream_id; }) } });
    }
    log.debug("Leaving SsfReceivers.sweepDuplicates(). " + stale.length +
              ' removed.');
    return stale.length;
  }

  seedStreams() {
    const { log, audit, config, events, realms, streams } = this.deps;
    log.debug("Entering SsfReceivers.seedStreams(). realm=" +
              realms.currentId());
    if (!this.enabled()) {
      log.info('ssf: the admin console and the user portal were NOT ' +
               'registered as receivers in the "' + realms.currentId() +
                   '" realm; ' +
               (config.value('ssf.enabled') ? 'ssf.internalReceivers'
                                            : 'ssf.enabled') + ' is off.');
      log.debug("Leaving SsfReceivers.seedStreams(). Off.");
      return 0;
    }
    // WHAT THEY ASK FOR. Every CAEP type and every RISC type, which is what
    // this feature is for — and SSF's own two beside them, which is not scope
    // that crept in. `verification` is the ONLY end-to-end test a stream has: a
    // 200 from the management API says the configuration was accepted and says
    // nothing whatever about whether an event can reach the receiver, so a
    // receiver that could not be verified could not be shown to work at all.
    // `stream-updated` is the other, and its absence is the one a reader cannot
    // notice: a stream quietly paused at the transmitter looks exactly like a
    // service where nothing has happened lately.
    //
    // It is the REQUEST and not the answer. `createStream()` intersects it with
    // what this transmitter supports, so `caep.enabled` off means a stream that
    // asks for CAEP and is delivered none of it — which is the specification's
    // own arrangement and is visible on both `/admin/ssf` and the inbox page.
    const wanted = events.SSF_EVENTS.map((row) => {
      return row.uri;
    }).concat(events.CAEP_EVENT_URIS).concat(events.RISC_EVENT_URIS);

    let made = 0;
    SURFACES.forEach((surface) => {
      // Before anything is looked for: a store carried over from before the
      // id was derived may hold several of these. See sweepDuplicates().
      this.sweepDuplicates(surface);
      if (this.streamFor(surface.id)) {
        log.debug('seedStreams(): ' + surface.id + ' already has a stream in ' +
                  'this realm and it was left alone.');
        return;
      }
      const endpoint = this.endpointFor(surface);
      const created = streams.createStream({
        aud: surface.audience,
        events_requested: wanted,
        description: surface.label + ' (this service\'s own ' +
                     surface.inboxPath + ')',
        delivery: {
          method: streams.DELIVERY_PUSH,
          endpoint_url: endpoint,
          // A CREDENTIAL THIS SERVICE MINTS FOR ITSELF, per stream and per
          // start. It is what the receive endpoint checks, and it is the reason
          // that endpoint can sit outside the console's gate without being a
          // hole: `delivery.authorization_header` is the one member of a stream
          // configuration that IS a credential, and until this stream existed
          // nothing in this service ever set one — so the code path that sends
          // it had never run against a receiver that reads it.
          //
          // **DERIVED RATHER THAN RANDOM SINCE 2026-09-11**, so that the
          // several processes of a dispatched service seed the same token
          // without anybody telling them. See `receiverToken()` above for what
          // a random one cost.
          authorization_header: this.receiverToken(surface)
        }
      }, { issuer: this.issuerForSeeding(), principal: 'internal',
           // ON THE CONTEXT AND NOT IN THE BODY ABOVE — see createStream(). The
           // body is what a remote receiver sends at POST /ssf/stream, so an id
           // read from there would let one name another's stream.
           streamId: this.internalStreamId(surface) });
      if (!created.ok) {
        audit.failure('STS-SSF-0072', {
          action: 'service.failure', protocol: 'SSF', channel: 'internal',
          target: surface.id, outcome: 'error',
          summary: 'The ' + surface.label + ' could not be registered as a ' +
            'Shared Signals receiver in the "' + realms.currentId() + '" realm',
          detail: { why: created.errors.join(' ') } });
        log.warn('ssf: the ' + surface.label + ' was not registered as a ' +
                 'receiver in the "' + realms.currentId() + '" realm: ' +
                 created.errors.join(' ') + ' Nothing else is affected; that ' +
                 'surface answers exactly as it did, with an empty ' +
                 surface.inboxPath + '.');
        return;
      }
      // NOT AN SSF MEMBER, and that is why it is set here rather than passed to
      // `createStream()`. `streamConfiguration()` sends a receiver the members
      // SSF 1.0 defines and no others, so this one is invisible on the wire and
      // is only ever read by `streamFor()` above.
      created.stream.internalSurface = surface.id;
      streams.note(created.stream, 'created',
        'This is one of this service\'s own two receivers. It was seeded at ' +
        'startup and is an ORDINARY stream: pause it, narrow it or delete it ' +
        'and it stays that way until a restart.');
      made++;
    });
    if (made && !config.value('ssf.pushDelivery')) {
      log.warn('ssf: the admin console and the user portal are registered as ' +
               'receivers in the "' + realms.currentId() + '" realm and ' +
               'NOTHING WILL REACH THEM: ssf.pushDelivery is off, so this ' +
               'service makes no outbound request at all — including the ' +
               'one to itself. Both inbox pages say so. Turn it on, or ' +
               'accept that the events queue on the two streams and are ' +
               'visible on /admin/ssf.');
    }
    log.debug("Leaving SsfReceivers.seedStreams(). " + made + ' created.');
    return made;
  }

  // The issuer a seeded stream carries. There is no request to read a Host
  // header from at startup, which is the same wall `applications.js`'s
  // `internalBaseUrl()` and `helpers.js` meet. It is a starting value and not a
  // fact: a deployment behind a proxy that pins `ssf.issuer` or
  // `global.publicBaseUrl` gets that instead, here as everywhere else.
  //
  // **IT WAS `baseUrlOf(null) + realms.currentPrefix()` UNTIL 2026-09-12, AND
  // BOTH HALVES WERE WRONG.** `baseUrlOf()` already carries the prefix, so a
  // seeded stream in `acme` named `…/realm/acme/realm/acme`; and with no
  // request it answers `http://localhost:<port>` even on an HTTPS listener. It
  // is now the function `ssf.ts`'s `issuerFor(null)` is, so the two cannot
  // disagree — which they did about the prefix, too, because a configured
  // `ssf.issuer` was used verbatim here and in every realm. Both call
  // `transport.transmitterIssuer()`.
  private issuerForSeeding() {
    const { log, transport } = this.deps;
    log.debug("Entering SsfReceivers.issuerForSeeding().");
    const out = transport.transmitterIssuer(null);
    log.debug("Leaving SsfReceivers.issuerForSeeding(). " + out);
    return out;
  }

  // ---------------------------------------------------------------------------
  // TAKING DELIVERY. The whole of what a receive endpoint does, so that the two
  // surfaces' routes are three lines each and cannot come to disagree about
  // what a receiver checks.
  //
  // It returns `{ status, body, entry }` and sends nothing: the surfaces answer
  // with their own `res`, because a refusal drawn by the console and one drawn
  // by the portal are still that application's to send.
  //
  // **THE SHAPE OF A REFUSAL IS RFC 8935 SECTION 2.4's**, `{ err, description
  // }` with a 400 — the same document `/ssf/receive` answers with and the same
  // one this service's own transmitter reads back in `pushSet()`. A receiver of
  // ours that invented a different error shape would be a receiver this
  // service's transmitter could not report properly on.
  // ---------------------------------------------------------------------------
  accept(surfaceId?, req?): Loose {
    const { log, audit, config, errorCodes, events, iso, randomId, realms,
      transport } = this.deps;
    log.debug("Entering SsfReceivers.accept(). " + surfaceId);
    const surface = this.surfaceOf(surfaceId);
    if (!surface) {
      // Only this file's own two routes call this, so a bad id is a programming
      // error rather than a caller's — reported rather than thrown, because the
      // route it came from is answering an HTTP request.
      log.error(errorCodes.tag('STS-SSF-0064') +
                'ssf: accept() was called for "' + String(surfaceId) + '", ' +
                'which is not one of this service\'s receivers.');
      log.debug("Leaving SsfReceivers.accept(). No such surface.");
      errorCodes.mark(req && req.res, 'STS-SSF-0064');
      log.debug("Leaving SsfReceivers.accept().");
      return { status: 500, entry: null,
        body: { err: 'invalid_request',
          description: 'There is no internal receiver called "' +
                       String(surfaceId) + '".' } };
    }
    if (!this.enabled()) {
      log.debug("Leaving SsfReceivers.accept(). Off.");
      errorCodes.mark(req && req.res, 'STS-SSF-0065');
      log.debug("Leaving SsfReceivers.accept().");
      return { status: 501, entry: null,
        body: { err: 'invalid_request',
          description: 'This service is not running its own receivers (' +
            (config.value('ssf.enabled') ? 'ssf.internalReceivers'
                                         : 'ssf.enabled') + '). The ' +
            surface.label +
                ' has no stream and this endpoint accepts nothing.' }
      };
    }
    const record = this.streamFor(surface.id);
    if (!record) {
      log.debug("Leaving SsfReceivers.accept(). No stream.");
      errorCodes.mark(req && req.res, 'STS-SSF-0066');
      log.debug("Leaving SsfReceivers.accept().");
      return { status: 404, entry: null,
        body: { err: 'invalid_request',
          description: 'The ' + surface.label + ' has no stream in the "' +
            realms.currentId() + '" realm, so nothing is agreed to be ' +
            'delivered here. It is seeded at startup and is an ordinary ' +
            'stream — if it was deleted, it stays deleted until a restart.' } };
    }
    // -------------------------------------------------------------------------
    // THE CREDENTIAL. The stream's own `delivery.authorization_header`,
    // compared in constant time.
    //
    // **THIS IS THE CHECK THAT LETS THE CONSOLE'S ENDPOINT SIT OUTSIDE THE
    // CONSOLE'S GATE.** A push carries no console session by construction — it
    // is a server-to-server POST and must not present a browser's credentials —
    // so the gate could only ever refuse it. What arrives instead is the bearer
    // token this service minted for this stream, and which nothing but this
    // service's own transmitter has ever been given.
    //
    // `timingSafeEqual` needs equal lengths, so the lengths are compared first
    // and a mismatch is refused without the comparison. That leaks the LENGTH
    // of a 32-character random identifier, which is not a secret.
    // -------------------------------------------------------------------------
    const presented = String((req.headers || {}).authorization || '');
    const expected = String((record.delivery || {}).authorization_header || '');
    if (!expected || !this.sameSecret(presented, expected)) {
      log.warn('ssf: a push at ' + surface.receivePath + ' in the "' +
               realms.currentId() + '" realm presented ' +
               (presented ? 'the wrong authorization header'
                          : 'no authorization header') + ' and was refused.');
      audit.audit({ action: 'ssf.event.receive', category: 'signals',
        protocol: 'SSF', channel: 'http', outcome: 'failure',
        errorCode: 'STS-SSF-0067',
        target: record.stream_id,
        summary: 'A push at the ' + surface.label + '\'s receive endpoint ' +
                 'was refused: the authorization header did not match the ' +
                     'stream',
        detail: { surface: surface.id, presented: presented ? 'yes' : 'no' } });
      log.debug("Leaving SsfReceivers.accept(). Refused on the credential.");
      errorCodes.mark(req.res, 'STS-SSF-0067');
      log.debug("Leaving SsfReceivers.accept().");
      return { status: 401, entry: null,
        body: { err: 'access_denied',
          // WHICH OF THE TWO IT WAS, and it is deliberately said out loud.
          // "No header" and "the wrong header" send somebody to two different
          // places — one is a transmitter that was never told, the other is a
          // stream that has been recreated since — and a mock that answered
          // both with one sentence would send half its readers the wrong way.
          // It is not an oracle worth protecting: the value is a 32-character
          // random identifier minted per start, and a caller already knows
          // whether it sent one.
          description: presented
            ? 'This receiver checks the authorization_header on its own ' +
              'stream, and the one this request carried is not it. That ' +
              'value is minted per stream and per start, so a transmitter ' +
              'holding one from before a restart — or from a stream that ' +
              'has since been recreated — presents exactly this.'
            : 'This receiver checks the authorization_header on its own ' +
              'stream and this request carried none. It is minted per ' +
              'stream and per start, and only this service\'s own ' +
              'transmitter is ever given it.' } };
    }

    const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8')
      : (typeof req.body === 'string' ? req.body
        : String((req.body && req.body.token) || ''));
    const token = raw.trim();
    if (!token) {
      log.debug("Leaving SsfReceivers.accept(). Empty body.");
      errorCodes.mark(req.res, 'STS-SSF-0068');
      log.debug("Leaving SsfReceivers.accept().");
      return { status: 400, entry: null,
        body: { err: 'invalid_request',
          description: 'The body is empty. RFC 8935 section 2.1 puts the ' +
            'Security Event Token in the body as application/secevent+jwt, ' +
            'with no form encoding and no JSON wrapper around it.' } };
    }
    const contentType = String((req.headers || {})['content-type'] || '')
      .split(';')[0].trim().toLowerCase();
    const read = events.readSet(token);
    const verdict = events.verifySet(token, read.header);
    const claims = read.claims || {};
    const entry: Loose = {
      surface: surface.id,
      jti: String(claims.jti || ('no-jti-' + randomId(8))),
      at: iso(),
      token: token,
      contentType: contentType,
      // RECORDED AND NOT REFUSED, which is `/ssf/receive`'s decision and is
      // made again here rather than inherited: a transmitter that sends a SET
      // as `application/jwt` is very slightly wrong, the event did arrive, and
      // a receiver that refused it would be testing the transmitter's pedantry.
      // What it must not do is go unsaid, so it is a column on the page.
      correctMediaType: contentType === transport.SET_MEDIA_TYPE,
      header: read.header,
      claims: read.claims,
      problem: read.problem,
      verified: verdict.verified,
      verificationNote: verdict.note,
      summary: read.claims ? events.describeSet(read.claims) : null,
      stream: record.stream_id
    };
    // -------------------------------------------------------------------------
    // THE AUDIENCE CHECK, AND IT IS THE ONE THING THIS RECEIVER DOES THAT THE
    // DEBUGGER'S RECEIVER AT /ssf/receive DOES NOT.
    //
    // `ssf_streams.ts`'s header says why `aud` is required and never defaulted:
    // a receiver checks for ITSELF in it, and an audience this transmitter
    // invented would be one the receiver never learns it has to check. A
    // receiver that then did not check would make the whole argument decorative
    // — so this one checks, and answers `invalid_audience`, which is the
    // refusal `pushSet()` reports separately from a network failure precisely
    // because it is the most interesting thing a receiver ever says.
    //
    // It is recorded EITHER WAY. The entry is kept with `audienceOk` false, so
    // the page can show a SET that arrived addressed to somebody else rather
    // than the page showing nothing and the stream's log carrying the only
    // trace.
    // -------------------------------------------------------------------------
    entry.audienceOk =
        this.audienceNames(claims.aud).indexOf(surface.audience) >= 0;
    this.record_(surface.id, entry);
    audit.audit({ action: 'ssf.event.receive', category: 'signals',
      protocol: 'SSF', channel: 'http',
      outcome: (read.problem || !entry.audienceOk) ? 'failure' : 'success',
      errorCode: read.problem ? 'STS-SSF-0069'
        : (entry.audienceOk ? '' : 'STS-SSF-0070'),
      target: entry.jti,
      summary: 'A Security Event Token was delivered to the ' + surface.label +
               (entry.verified ? ' and verified' : ''),
      detail: { surface: surface.id, stream: record.stream_id,
        types: Object.keys(claims.events || {}),
        audienceOk: entry.audienceOk, contentType: contentType } });

    if (read.problem) {
      log.debug("Leaving SsfReceivers.accept(). Malformed.");
      errorCodes.mark(req.res, 'STS-SSF-0069');
      log.debug("Leaving SsfReceivers.accept().");
      return { status: 400, entry: entry,
        body: { err: 'invalid_request',
          description: read.problem +
            ' It has been recorded anyway and is on ' + surface.inboxPath +
            ', because what arrived is the question ' +
            'being asked.' } };
    }
    if (!entry.audienceOk) {
      log.warn('ssf: the ' + surface.label + ' was delivered ' + entry.jti +
               ' addressed to ' + JSON.stringify(claims.aud) + ', and it ' +
               'answers to "' + surface.audience + '". It is recorded and ' +
               'refused.');
      log.debug("Leaving SsfReceivers.accept(). Wrong audience.");
      errorCodes.mark(req.res, 'STS-SSF-0070');
      log.debug("Leaving SsfReceivers.accept().");
      return { status: 400, entry: entry,
        body: { err: 'invalid_audience',
          description: 'This receiver is "' + surface.audience + '" and that ' +
            'name is not in the `aud` of this Security Event Token. It has ' +
            'been recorded and is on ' + surface.inboxPath + '.' } };
    }
    if (!entry.verified && config.value('ssf.receiveRequireSignature')) {
      log.debug("Leaving SsfReceivers.accept(). Signature required.");
      errorCodes.mark(req.res, 'STS-SSF-0071');
      log.debug("Leaving SsfReceivers.accept().");
      return { status: 400, entry: entry,
        body: { err: 'invalid_key', description: entry.verificationNote } };
    }
    // 202 with an EMPTY body, which is what RFC 8935 section 2.3 says. A
    // document here would be something a transmitter could come to depend on
    // that no receiver has to send.
    log.debug("Leaving SsfReceivers.accept(). Accepted.");
    return { status: 202, entry: entry, body: null };
  }

  // `aud` is a string or an array of them — RFC 8417 leaves it as JWT's own
  // member — so both shapes are read rather than one being assumed.
  private audienceNames(value?) {
    const { log } = this.deps;
    log.debug("Entering SsfReceivers.audienceNames().");
    const out = Array.isArray(value) ? value.map(String)
      : (value ? [String(value)] : []);
    log.debug("Leaving SsfReceivers.audienceNames(). " + out.length + '.');
    return out;
  }

  private sameSecret(presented?, expected?) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering SsfReceivers.sameSecret().");
    const a = Buffer.from(String(presented), 'utf8');
    const b = Buffer.from(String(expected), 'utf8');
    if (a.length !== b.length) {
      log.debug("Leaving SsfReceivers.sameSecret(). Different lengths.");
      return false;
    }
    const same = nodeCrypto.timingSafeEqual(a, b);
    log.debug("Leaving SsfReceivers.sameSecret(). " + same);
    return same;
  }

  // The underscore is because `record` is the name this file uses for a stream
  // record everywhere else, and two meanings for one word in one file is how a
  // reader loses an hour.
  private record_(surfaceId?, entry?) {
    const { log } = this.deps;
    log.debug("Entering SsfReceivers.record_(). " + surfaceId);
    inbox.set(surfaceId + '|' + entry.jti, entry);
    // THE CAP, applied per surface and by age. `inbox` holds both surfaces'
    // rows, so the oldest row overall is not necessarily this surface's — a
    // portal nobody has opened must not lose its signals because the console is
    // busy.
    const mine = this.keysFor(surfaceId);
    const max = this.inboxLimit();
    if (mine.length > max) {
      mine.slice(0, mine.length - max).forEach((key) => {
        inbox.delete(key);
      });
    }
    log.debug("Leaving SsfReceivers.record_(). " + Math.min(mine.length, max) +
              ' held.');
    return entry;
  }

  // This surface's keys, oldest first. The sort is on `at` and falls back to
  // the key, because two SETs recorded in the same millisecond are otherwise in
  // whatever order the map hands them over — which is insertion order here and
  // is not insertion order after a restore from the store.
  private keysFor(surfaceId?) {
    const { log } = this.deps;
    log.debug("Entering SsfReceivers.keysFor(). " + surfaceId);
    const prefix = surfaceId + '|';
    const rows = [];
    inbox.forEach((entry, key) => {
      if (String(key).indexOf(prefix) === 0) {
        rows.push({ key: key, at: String((entry || {}).at || '') });
      }
    });
    rows.sort((a, b) => {
      if (a.at === b.at) {
        return a.key < b.key ? -1 : (a.key > b.key ? 1 : 0);
      }
      return a.at < b.at ? -1 : 1;
    });
    const out = rows.map((one) => { return one.key; });
    log.debug("Leaving SsfReceivers.keysFor(). " + out.length + '.');
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHAT ONE SURFACE HAS RECEIVED, NEWEST FIRST.
  //
  // `options.person` narrows it to the signals about one person and is what the
  // portal passes. See `isAbout()` for what that means and for the one rule
  // that decides every doubtful case.
  // ---------------------------------------------------------------------------
  listFor(surfaceId?, options?) {
    const { log } = this.deps;
    log.debug("Entering SsfReceivers.listFor(). " + surfaceId);
    const asked = options || {};
    const person = asked.person || null;
    const out = this.keysFor(surfaceId).map((key) => {
      return inbox.get(key);
    }).filter((entry) => {
      if (!entry) {
        return false;
      }
      if (!person) {
        return true;
      }
      return this.isAbout(entry, person);
    }).reverse();
    log.debug("Leaving SsfReceivers.listFor(). " + out.length + '.');
    return out;
  }

  // ---------------------------------------------------------------------------
  // IS THIS EVENT ABOUT THIS PERSON?
  //
  // **THE RULE THAT DECIDES EVERY DOUBTFUL CASE: WHEN IN DOUBT, NO.** Showing
  // one person another person's account lockout is a disclosure; failing to
  // show somebody one of their own is an incomplete page. Those are not the
  // same size of mistake, so an identifier this function cannot resolve to a
  // name — a phone number, an opaque id this service did not compose — is not a
  // match.
  //
  // It reads the subject in the shapes THIS SERVICE COMPOSES, which is what
  // `caep.ts`'s `subjectFor()` and `risc.ts`'s `subjectFor()` produce:
  //
  //   * CAEP sends SSF's COMPLEX subject, whose `user` member names the person
  //     and whose `session` member names the session. The person is in the
  //     member, so this walks into it — one level, because SSF section 4
  //     forbids a complex subject inside a complex subject.
  //   * RISC sends a plain identifier in whichever format `risc.subjectFormat`
  //     names, and its two IDENTIFIER events ignore that setting and use the
  //     person's email — the OLD one, since that is the whole content of the
  //     event. So `new-value` in the payload is read as well, or somebody's own
  //     address change would be the one event they could not see.
  //
  // **AND IT READS `subject_type` AS WELL AS `format`.**
  // `risc.googleSubjectType` renames that member on every RISC subject this
  // service sends, deliberately, because RISC section 3.1 says a relying party
  // needs code for both spellings. A matcher that read only `format` would hide
  // every RISC signal from every person the moment that setting went on —
  // silently, which is exactly the failure the setting exists to let somebody
  // find.
  // ---------------------------------------------------------------------------
  isAbout(entry?, person?) {
    const { log } = this.deps;
    log.debug("Entering SsfReceivers.isAbout().");
    const claims = (entry && entry.claims) || {};
    const subject = claims.sub_id;
    if (subject && this.matchesSubject(subject, person)) {
      log.debug("Leaving SsfReceivers.isAbout(). The subject names them.");
      return true;
    }
    // The new value of an identifier that changed. The subject carries the OLD
    // address by specification, so without this the one person who must see an
    // `identifier-changed` — the person whose address it was — stops seeing it
    // the moment it takes effect.
    const payloads = claims.events || {};
    const named = Object.keys(payloads).some((uri) => {
      const body = payloads[uri] || {};
      const moved = body['new-value'];
      return typeof moved === 'string' && this.namesPerson(moved, person);
    });
    log.debug("Leaving SsfReceivers.isAbout(). " + named);
    return named;
  }

  private matchesSubject(subject?, person?) {
    const { log, subjects } = this.deps;
    log.debug("Entering SsfReceivers.matchesSubject().");
    if (!subject || typeof subject !== 'object' || Array.isArray(subject)) {
      log.debug("Leaving SsfReceivers.matchesSubject(). Not a subject.");
      return false;
    }
    // `format` or RISC section 3.1's `subject_type` — see the header.
    const format = String(subject.format || subject.subject_type || '');
    if (!format) {
      // A COMPLEX SUBJECT. One level only.
      const hit = subjects.COMPLEX_MEMBER_NAMES.some((name) => {
        const member = subject[name];
        return member && typeof member === 'object' &&
               this.matchesSubject(member, person);
      });
      log.debug("Leaving SsfReceivers.matchesSubject(). Complex: " + hit);
      return hit;
    }
    if (format === 'aliases') {
      const list = Array.isArray(subject.identifiers) ? subject.identifiers :
          [];
      const hit = list.some((one) => {
        return this.matchesSubject(one, person);
      });
      log.debug("Leaving SsfReceivers.matchesSubject(). Aliases: " + hit);
      return hit;
    }
    if (format === 'issuer_subject_id') {
      const hit = this.namesPerson(subject.sub, person);
      log.debug("Leaving SsfReceivers.matchesSubject(). issuer_subject_id: " +
                hit);
      return hit;
    }
    if (format === 'opaque') {
      const hit = this.namesPerson(subject.id, person);
      log.debug("Leaving SsfReceivers.matchesSubject(). opaque: " + hit);
      return hit;
    }
    if (format === 'email') {
      const hit = this.namesPerson(subject.email, person);
      log.debug("Leaving SsfReceivers.matchesSubject(). email: " + hit);
      return hit;
    }
    if (format === 'account') {
      const hit = this.namesPerson(String(subject.uri || '')
        .replace(/^acct:/i, ''), person);
      log.debug("Leaving SsfReceivers.matchesSubject(). account: " + hit);
      return hit;
    }
    if (format === 'uri') {
      // `subjectForUser()` composes `<issuer>/users/<name>`. The tail is
      // compared rather than the whole string, because the issuer a seeded
      // stream carries is computed at startup and a deployment behind a proxy
      // legitimately has a different one on the event.
      const tail = String(subject.uri || '').split('/users/')[1] || '';
      const hit = tail ? this.namesPerson(tail, person) : false;
      log.debug("Leaving SsfReceivers.matchesSubject(). uri: " + hit);
      return hit;
    }
    if (format === 'decentralized_identifier') {
      const tail = String(subject.url || '').split(':').pop() || '';
      const hit = tail ? this.namesPerson(tail, person) : false;
      log.debug("Leaving SsfReceivers.matchesSubject(). did: " + hit);
      return hit;
    }
    // `phone_number`, and anything a future RFC adds. The `person` this is
    // handed carries no phone number (see namesPerson()), so an event carrying
    // one is about somebody this function cannot name — and the rule in the
    // header says what to do about that.
    log.debug("Leaving SsfReceivers.matchesSubject(). " + format + ': not ' +
              'resolvable to a person here.');
    return false;
  }

  // Whether one identifier VALUE is this person's. `person` is
  // `{ username, sub, mail }` — the portal's session and the entry behind it.
  private namesPerson(value?, person?) {
    const { log, mode } = this.deps;
    log.debug("Entering SsfReceivers.namesPerson().");
    const text = String(value || '').trim().toLowerCase();
    if (!text) {
      log.debug("Leaving SsfReceivers.namesPerson(). Empty.");
      return false;
    }
    const who = person || {};
    const names = [who.username, who.sub, who.mail].map((one) => {
      return String(one || '').trim().toLowerCase();
    }).filter(Boolean);
    if (names.indexOf(text) >= 0) {
      log.debug("Leaving SsfReceivers.namesPerson(). An exact name.");
      return true;
    }
    // The address this service INVENTS for somebody whose entry carries none —
    // `<name>@example.com`, in `subjectForUser()` and in `risc.ts`'s
    // `defaultEmailFor()`. It is a fact about those two functions rather than
    // about the person, which is why it is matched here and not added to the
    // list above as though it were an identifier they hold.
    //
    // **ONLY WHERE THOSE FUNCTIONS INVENT ONE (2026-09-12).** In product mode
    // they do not, so an `@example.com` address on an event did not come from
    // this service — and matching it to a person who never held it would be the
    // disclosure this function's header says to fail closed on.
    if (!mode.inventsClaimValues()) {
      log.debug("Leaving SsfReceivers.namesPerson(). No exact name, and " +
                "nothing is invented " +
                'in product mode.');
      return false;
    }
    const invented = names.map((one) => {
      return one.indexOf('@') > 0 ? one : one + '@example.com';
    });
    const hit = invented.indexOf(text) >= 0;
    log.debug("Leaving SsfReceivers.namesPerson(). Invented address: " + hit);
    return hit;
  }

  // ---------------------------------------------------------------------------
  // WHAT THE INBOX PAGE NEEDS TO SAY BEFORE IT SHOWS A SINGLE ROW.
  //
  // An empty inbox has FIVE causes and only one of them is "nothing has
  // happened". This is what tells them apart, and it is the reason both pages
  // draw a status block above the table rather than an empty table with a
  // hopeful heading. `ssf/CLAUDE.md` says the same thing about `caep`'s "no
  // stream takes it" line: "nothing arrived" is the commonest report about any
  // Shared Signals deployment and it is almost never what it looks like.
  // ---------------------------------------------------------------------------
  status(surfaceId?) {
    const { log, config, events, realms, streams } = this.deps;
    log.debug("Entering SsfReceivers.status(). " + surfaceId);
    const surface = this.surfaceOf(surfaceId);
    if (!surface) {
      log.debug("Leaving SsfReceivers.status(). No such surface.");
      return null;
    }
    const record = this.streamFor(surface.id);
    const out = {
      id: surface.id,
      label: surface.label,
      audience: surface.audience,
      receivePath: surface.receivePath,
      inboxPath: surface.inboxPath,
      sees: surface.sees,
      realm: realms.currentId(),
      enabled: this.enabled(),
      ssfEnabled: !!config.value('ssf.enabled'),
      internalReceivers: !!config.value('ssf.internalReceivers'),
      pushDelivery: !!config.value('ssf.pushDelivery'),
      caepEnabled: !!config.value('caep.enabled'),
      riscEnabled: !!config.value('risc.enabled'),
      held: this.keysFor(surface.id).length,
      max: this.inboxLimit(),
      stream: null,
      why: []
    };
    if (record) {
      out.stream = {
        stream_id: record.stream_id,
        iss: record.iss,
        aud: record.aud,
        status: record.status,
        statusReason: record.statusReason,
        endpoint_url: (record.delivery || {}).endpoint_url || '',
        delivers: record.events_delivered.length,
        requested: record.events_requested.length,
        caepDelivered: record.events_delivered.filter((uri) => {
          return events.CAEP_EVENT_URIS.indexOf(uri) >= 0;
        }).length,
        riscDelivered: record.events_delivered.filter((uri) => {
          return events.RISC_EVENT_URIS.indexOf(uri) >= 0;
        }).length,
        queued: streams.queueOf(record).length,
        counters: Object.assign({}, record.counters),
        lastPushAt: record.lastPushAt,
        lastPushError: record.lastPushError
      };
    }
    // EVERY REASON NOTHING WOULD ARRIVE, IN THE ORDER A READER SHOULD CHECK
    // THEM — the ones that stop everything first, the ones that narrow it
    // after.
    if (!out.ssfEnabled) {
      out.why.push('ssf.enabled is off, so this service is not a Shared ' +
        'Signals transmitter at all and nothing is built, queued or sent.');
    } else if (!out.internalReceivers) {
      out.why.push('ssf.internalReceivers is off, so this service does not ' +
        'register its own two surfaces as receivers. Everything else about ' +
        'Shared Signals is unaffected.');
    } else if (!record) {
      out.why.push('There is no stream for the ' + surface.label + ' in the "' +
        out.realm + '" realm. It is seeded at startup and is an ordinary ' +
        'stream, so if it was deleted at /admin/ssf or through /admin-api it ' +
        'stays deleted until a restart.');
    } else {
      if (!out.pushDelivery) {
        out.why.push('ssf.pushDelivery is off, so this service makes no ' +
          'outbound request — including the one to itself. Events are still ' +
          'built and QUEUED on the stream (' + out.stream.queued +
          ' waiting) ' +
          'and are visible at /admin/ssf; nothing reaches this page.');
      }
      if (record.status !== 'enabled') {
        out.why.push('The stream is ' + record.status + ' (' +
          record.statusReason + '). A PAUSED stream keeps queueing and a ' +
          'DISABLED one drops what arrives, which is the difference between ' +
          '"I was not listening" and "it did not happen".');
      }
      if (!out.caepEnabled) {
        out.why.push('caep.enabled is off, so no CAEP event type is ' +
          'supported and none is delivered on this stream however it was ' +
          'requested.');
      }
      if (!out.riscEnabled) {
        out.why.push('risc.enabled is off, so no RISC event type is ' +
          'supported and none is delivered on this stream.');
      }
      if (record.counters.failed) {
        out.why.push(record.counters.failed + ' push(es) to this receiver ' +
          'have failed and nothing here retries. The last said: ' +
          (record.lastPushError || '(no reason recorded)'));
      }
    }
    log.debug("Leaving SsfReceivers.status(). " + out.why.length +
              ' thing(s) to say.');
    return out;
  }

  // One entry as the pages and `/admin-api` draw it — the SET opened out, with
  // the token itself left off unless it is asked for. The token is the whole
  // document and is 1–4kB of base64url per row; a list of two hundred of them
  // is a page nobody can read and an API response nobody wanted.
  describeEntry(entry?, options?): Loose {
    const { log, events, subjects } = this.deps;
    log.debug("Entering SsfReceivers.describeEntry().");
    const asked = options || {};
    const claims = entry.claims || {};
    const uris = Object.keys(claims.events || {});
    const row = uris.length ? events.EVENT_BY_URI[uris[0]] : null;
    const out: Loose = {
      jti: entry.jti,
      at: entry.at,
      surface: entry.surface,
      stream: entry.stream,
      name: row ? row.name : (uris[0] || '(no event)'),
      types: uris,
      vocabulary: this.vocabularyOf(uris[0] || ''),
      issuer: String(claims.iss || ''),
      audience: this.audienceNames(claims.aud).join(', '),
      audienceOk: entry.audienceOk !== false,
      subject: claims.sub_id ? subjects.describeSubject(claims.sub_id) : '',
      payload: uris.length ? (claims.events[uris[0]] || {}) : {},
      verified: !!entry.verified,
      verificationNote: entry.verificationNote,
      contentType: entry.contentType,
      correctMediaType: !!entry.correctMediaType,
      problem: entry.problem || ''
    };
    if (asked.withToken) {
      out.token = entry.token;
    }
    log.debug("Leaving SsfReceivers.describeEntry(). " + out.name);
    return out;
  }

  // Which of the three vocabularies a type belongs to, read off the prefixes
  // `ssf_events.js` owns rather than by matching names — a fourth vocabulary
  // would then be one row there and nothing here.
  private vocabularyOf(uri?) {
    const { log, events } = this.deps;
    log.debug("Entering SsfReceivers.vocabularyOf().");
    const text = String(uri || '');
    let out = 'other';
    if (text.indexOf(events.CAEP_PREFIX) === 0) {
      out = 'CAEP';
    } else if (text.indexOf(events.RISC_PREFIX) === 0) {
      out = 'RISC';
    } else if (text.indexOf(events.SSF_PREFIX) === 0) {
      out = 'SSF';
    }
    log.debug("Leaving SsfReceivers.vocabularyOf(). " + out);
    return out;
  }

  // Everything one surface has, as one document: both doors answer with it, so
  // `/admin/signals?format=json` and GET /admin-api/signals cannot disagree.
  view(surfaceId?, options?) {
    const { log } = this.deps;
    log.debug("Entering SsfReceivers.view(). " + surfaceId);
    const asked = options || {};
    const rows = this.listFor(surfaceId, { person: asked.person || null });
    const out = {
      status: this.status(surfaceId),
      received: rows.map((entry) => {
        return this.describeEntry(entry, { withToken: !!asked.withToken });
      })
    };
    log.debug("Leaving SsfReceivers.view(). " + out.received.length +
              ' row(s).');
    return out;
  }

  // Drop one surface's inbox in this realm. It is the only write the pages
  // have, and it is deliberately not a delete of the STREAM: clearing what a
  // receiver has been shown and tearing down the agreement to send it more are
  // two different acts, and the second one is `/admin/ssf`'s.
  clearFor(surfaceId?) {
    const { log, realms } = this.deps;
    log.debug("Entering SsfReceivers.clearFor(). " + surfaceId);
    const keys = this.keysFor(surfaceId);
    keys.forEach((key) => {
      inbox.delete(key);
    });
    log.info('ssf: the ' + (this.surfaceOf(surfaceId) || {}).label + '\'s ' +
             'inbox in the "' + realms.currentId() + '" realm was cleared; ' +
             keys.length + ' event(s) dropped. The stream is untouched and ' +
             'goes on delivering.');
    log.debug("Leaving SsfReceivers.clearFor(). " + keys.length + ' dropped.');
    return keys.length;
  }
}

// THE TRANSITIONAL INSTANCE — see the header above.
const ssfReceivers = new SsfReceivers({
  nodeCrypto: nodeCrypto,
  log: helpers.log,
  randomId: helpers.randomId,
  iso: helpers.iso,
  stsCrypto: stsCrypto,
  clusterSecrets: clusterSecrets,
  config: config,
  mode: mode,
  realms: realms,
  audit: audit,
  subjects: subjects,
  events: events,
  streams: streams,
  transport: transport,
  errorCodes: errorCodes
});

export = {
  SsfReceivers: SsfReceivers,
  SURFACES: SURFACES,
  ADMIN: 'admin-console',
  PORTAL: 'user-portal',
  surfaceOf: ssfReceivers.surfaceOf.bind(ssfReceivers) as
    SsfReceivers['surfaceOf'],
  enabled: ssfReceivers.enabled.bind(ssfReceivers) as SsfReceivers['enabled'],
  seedStreams: ssfReceivers.seedStreams.bind(ssfReceivers) as
    SsfReceivers['seedStreams'],
  streamFor: ssfReceivers.streamFor.bind(ssfReceivers) as
    SsfReceivers['streamFor'],
  endpointFor: ssfReceivers.endpointFor.bind(ssfReceivers) as
    SsfReceivers['endpointFor'],
  accept: ssfReceivers.accept.bind(ssfReceivers) as SsfReceivers['accept'],
  listFor: ssfReceivers.listFor.bind(ssfReceivers) as SsfReceivers['listFor'],
  isAbout: ssfReceivers.isAbout.bind(ssfReceivers) as SsfReceivers['isAbout'],
  status: ssfReceivers.status.bind(ssfReceivers) as SsfReceivers['status'],
  describeEntry: ssfReceivers.describeEntry.bind(ssfReceivers) as
    SsfReceivers['describeEntry'],
  view: ssfReceivers.view.bind(ssfReceivers) as SsfReceivers['view'],
  clearFor: ssfReceivers.clearFor.bind(ssfReceivers) as
    SsfReceivers['clearFor']
};
