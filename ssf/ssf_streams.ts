'use strict';

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SsfStreams` takes the logger, `randomId()`, `iso()`, `config`, the
// error-code registry, `realms`, `ssf_subjects.js`, `ssf_events.js` and two
// LOADERS — for `applications.js` and `persistence.js`, which the functions
// below require lazily and still do — through its constructor. The stores stay
// module-level declarations (a store becomes per realm where it is DECLARED),
// and the module still exports its old names as FACADES forwarding to the
// instance the composition root builds (#50, R2), for the unconverted modules
// that require it. A process that loads this module without the root builds a
// default instance when the module loads.
// ---------------------------------------------------------------------------

//
// File: ssf_streams.ts
//
// ---------------------------------------------------------------------------
// THE STREAMS, THEIR SUBJECTS AND THEIR EVENT QUEUES.
//
// A STREAM is the whole of the relationship between a transmitter and a
// receiver: who the events are about, which types are delivered, and by which
// of the two delivery methods. Everything the Shared Signals Framework's
// management API does is a read or a write of one of these records, so this is
// where they live and it is the only place they live.
//
// ---------------------------------------------------------------------------
// IT IS PER REALM, AND THAT IS A DECISION RATHER THAN A CONVENTION.
//
// `realms.map()` rather than `new Map()`, for the reason `common/CLAUDE.md`
// gives and for one specific to this family: a stream carries an `iss`, and
// the issuer of a realm is that realm's own. A process-wide stream store would
// let a receiver create a stream in the default realm and read it back at
// `/realm/acme/ssf/stream` with a different issuer on it, which is not a
// tidiness problem — it is one receiver reading another tenant's delivery
// endpoint and authorization header.
//
// **AND THE SAME GOES FOR THE QUEUES.** They were on the stream record and so
// partitioned by construction; since 2026-09-13 they are stores of their own
// (`queued`, and `deadLetters` since 2026-09-14), each a `realms.map()` beside
// the streams, so they are partitioned the same way. That is the shape
// `common/CLAUDE.md` warns about getting half right: the two halves of one
// claim set held in two places and only one of them per realm.
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVICE KEEPS AND WHAT IT DOES NOT.
//
// Every store here is declared with `persist`, so `persistence/CLAUDE.md`'s
// minted-state rule decides what is kept: in development they are in memory
// and die with the process — the signing key is regenerated on every start
// there, so a queue of SETs restored from disk would be a queue of tokens
// nothing can verify, and a receiver that reconnects after a restart creates
// its stream again, which it has to be able to do anyway. In product mode on
// postgres they are written down and shared with every process (2026-09-06),
// beside keys that are kept too.
//
// ---------------------------------------------------------------------------
// EVERY LIMIT HERE IS A SETTING AND EVERY ONE OF THEM IS A REACHABLE
// NEGATIVE.
//
// A mock's job is to let a client's error paths run. `ssf.maxStreams`,
// `ssf.maxSubjectsPerStream` and `ssf.maxQueuedEvents` each produce a specific
// refusal a receiver would otherwise never see, and each says which setting it
// was — because "409" with no explanation is the least useful thing a mock can
// answer.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route. It requires `helpers.js`,
// `config.js`, the error-code registry, `realms.js`, `ssf_subjects.js` and
// `ssf_events.js` (and `applications.js` and `persistence.js` lazily), none of
// which requires it, so it cannot join a cycle.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import cacheRegistry = require('../common/cache_registry');
import replication = require('../persistence/persistence_replication');
import subjects = require('./ssf_subjects');
import events = require('./ssf_events');

// stream_id -> stream record, one partition per trust realm.
const streams = realms.map({ persist: 'ssf_streams.streams' });

// ---------------------------------------------------------------------------
// THE QUEUE IS A STORE OF ITS OWN, ONE ROW PER SET, AND NOT AN ARRAY ON THE
// RECORD (2026-09-13).
//
// It was `record.queue`, and two things were wrong with that in a service
// whose request workers share what they mint through the store.
//
//   * **NOTHING WROTE IT DOWN.** `realms.map()` journals a `set()` and a
//     `delete()`; `enqueue()` pushed onto an array already in the map and
//     `poll()` filtered it, and neither called either. So a SET queued by the
//     worker that handled `/admin-api/risc/emit` existed in that worker's
//     memory alone, and an acknowledgement taken by another worker removed it
//     from that other worker's copy alone. Measured in `dispatch` mode on
//     2026-09-13: `sts_ssf_allowed_events` polled a control stream straight
//     after an emission and got `[]`, and `sts_gnap_signals` acknowledged a
//     SET and was handed it again (RFC 8936 section 2.4). Six parallel polls
//     against the kept stack after one acknowledgement answered 0, 0, 1, 1,
//     1, 1 — two workers had the ack and four had the SET.
//   * **A `touch()` ON THE RECORD WOULD NOT HAVE BEEN ENOUGH**, and that is
//     why this is a second store rather than the one-line fix `caep.ts` got.
//     A record is whole-valued: the later write wins. A SET is queued by a
//     transmission that is often NOT inside the request that caused it — a
//     GNAP revocation answers and then signs — so the worker queueing it may
//     not yet have applied an acknowledgement another worker committed a
//     moment earlier, and a whole-record write from it would PUT THE
//     ACKNOWLEDGED SET BACK. The reverse race loses a SET outright. Both are
//     a security event delivered twice or never, which is the one thing this
//     family exists not to do.
//
// So each SET is a row keyed by its stream and its jti: queueing one is a new
// key nobody else writes, acknowledging one is a DELETE of that key, and the
// two cannot overwrite each other in any order. What stays on the record —
// counters, the log, `eventCounts` — is still whole-valued and a concurrent
// write can lose an increment or a line; that is a number on a console page,
// and `touch()` below at least makes it reach the store at all.
// ---------------------------------------------------------------------------
const queued = realms.map({ persist: 'ssf_streams.queued' });

// ---------------------------------------------------------------------------
// THE DEAD-LETTER QUEUE (2026-09-14): SETs this transmitter could not deliver,
// kept for inspection and then deleted.
//
// A push that failed used to stay on the live queue "until somebody asks for it
// again", and nothing ever did. The live queue is scanned and sorted on every
// event a stream is sent, so a receiver that refused everything made every
// later event slower for as long as the process lived — on a dispatch run
// forty streams each held 189 refused SETs and every one was re-scanned for
// every default-realm event.
//
// **A STORE OF ITS OWN, ONE ROW PER SET, FOR `queued`'s REASON**: moving a SET
// here is a delete of one key there and a set of one key here, so it cannot
// race an acknowledgement or a queueing in another process. Keyed exactly like
// `queued` — `<stream_id> <jti>` — so one stream's letters are a prefix scan.
//
// What goes in: a push that failed after `ssf.pushRetries`, a push that could
// not wait for a slot (`ssf.pushBacklog`), everything waiting when a stream is
// declared dead, and every SET sent to a dead stream — the last UNSIGNED, since
// signing a document nothing will receive is the cost this exists to stop; a
// probe signs it if it is ever pushed. Each carries the reason, the code and
// the receiver's status. What comes out: `ssf.deadLetterRetentionS` after it
// went in, the oldest past `ssf.deadLetterMaxPerStream`, a probe that
// delivered it, and everything when its stream is deleted.
// ---------------------------------------------------------------------------
const deadLetters = realms.map({ persist: 'ssf_streams.deadLetters' });

// What this service has RECEIVED, when the debugger is the transmitter and
// this service is the receiver. Also per realm, and capped the same way.
const received = realms.arr({ persist: 'ssf_streams.received', merge: 'own' });

// The two delivery method URNs of SSF 1.0 section 7.1.1. They are the RFC
// numbers as URNs rather than names, which catches everybody once: a stream
// asking for "push" is asking for nothing this specification defines.
const DELIVERY_PUSH = 'urn:ietf:rfc:8935';
const DELIVERY_POLL = 'urn:ietf:rfc:8936';

const DELIVERY_METHODS = [
  { method: DELIVERY_PUSH, name: 'Push (RFC 8935)',
    what: 'The transmitter POSTs each SET to a URL the receiver gave it. ' +
          'The receiver has to be reachable, which is what makes this the ' +
          'hard one for a browser: a page cannot be an HTTP server, so the ' +
          'debugger hosts its receiver endpoint in its api layer.' },
  { method: DELIVERY_POLL, name: 'Poll (RFC 8936)',
    what: 'The receiver POSTs to the transmitter and is handed whatever has ' +
          'queued up, acknowledging what it read. Nothing has to be ' +
          'reachable but the transmitter, which is why a browser can be a ' +
          'receiver over this method and not over the other one.' }
];

// Whether an event about this subject belongs on this stream. `defaultSubjects`
// is what decides it when the list is empty; see the header above.
// ---------------------------------------------------------------------------
// SUBJECT SCOPES (2026-09-12): a narrowing a PROTOCOL family puts on the
// streams its own applications own.
//
// GNAP's web applications are receivers whose streams carry events only about
// people who approved a grant to that application (gnap/gnap_signals.ts). That
// is a fact about GNAP's grants, which this module must not know, so it is a
// registered function consulted HERE — the one function CAEP, RISC and a
// by-hand emission all ask — rather than a filter at each of those call sites,
// which is the third place a new call site would forget.
//
// A scope answers `true`, `false` or `undefined` ("not my stream"). Only a
// `false` narrows: a scope can take events AWAY from a stream it owns and can
// never add one to a stream whose subject list did not cover it. Keyed by
// family so a module loaded twice (a test, a worker) replaces its own entry.
// ---------------------------------------------------------------------------
const subjectScopes = {};

// THE ORDER A SET WAS QUEUED IN, carried on the row. The rows of one realm are
// one Map, and a Map's insertion order is the order THIS process happened to
// learn of each row — which for a row another worker wrote is the order the
// change log was applied in, not the order the events happened. So the order
// is a member: the time it was queued, with a per-process counter to split a
// millisecond, and the jti as the last word between two processes that queued
// in the same one. RFC 8936 promises no order; a receiver reading a stream of
// account events would still rather have them in the order they happened.
let queueSequence = 0;

// ---------------------------------------------------------------------------
// DEAD LETTERS. See the header on `deadLetters` above.
// ---------------------------------------------------------------------------

// How many dead letters THIS PROCESS believes each stream holds, per realm, so
// the per-stream cap is not a scan of every letter on every letter. It is an
// estimate — a letter another process wrote reaches the store through
// `restore` and not through here — and `sweepDeadLetters()` rebuilds it from a
// scan each sweep, which is when the cap is enforced exactly.
const deadCounts = realms.keyed(function () { return new Map(); });

// Described to `/admin/caches` (#74, rule 3ap): a row per stream. A hit is a
// dead letter added to a stream whose count was already held.
const deadCountsCount = cacheRegistry.register({
  name: 'ssf.dead-letter-counts',
  title: 'Shared Signals dead-letter counts',
  description: 'An estimate of each stream\'s dead letters, kept so a new ' +
    'one can be checked against the per-stream cap without counting the ' +
    'queue. Letters another process wrote are not in it until the next ' +
    'sweep.',
  owner: 'ssf/ssf_streams.ts',
  scope: 'realm',
  settings: ['ssf.deadLetterMaxPerStream'],
  maxEntries: function (): number | null {
    return Number(config.value('ssf.maxStreams')) || null;
  },
  bound: 'Structural: one count per stream, and a realm holds at most ' +
    'ssf.maxStreams streams.',
  lifetime: function (): string {
    return 'No expiry: recounted at each dead-letter sweep, one entry per ' +
      'stream.';
  },
  entries: function (): unknown[] {
    const out: unknown[] = [];
    deadCounts.existing().forEach(function (counts: Map<string, number>,
                                            id: string): void {
      counts.forEach(function (n: number, stream: string): void {
        out.push({ realm: id, key: 'stream ' + stream + ': ' + n,
                   validUntil: null, basis: 'until the next sweep' });
      });
    });
    return out;
  }
});

// ---------------------------------------------------------------------------
// WHAT WAS DEAD-LETTERED SINCE THE LAST SWEEP, per process and per realm —
// what the sweep's ONE summary line reports. The user-visible rule is that an
// undeliverable SET is never logged on its own: a receiver that refuses
// everything would otherwise put a line per event in the log, which is what
// buried everything else on the run this was built for (30,698 lines in one
// second).
// ---------------------------------------------------------------------------
const tally = realms.keyed(function () {
  return { letters: 0, byStream: new Map(), byCode: new Map(), trimmed: 0 };
});

// A stream's `delivery` member, as the wire form carries it.
interface StreamDelivery {
  method: string;
  endpoint_url?: string;
  authorization_header?: string;
}

// `common/applications.js`, as far as this module reads it.
interface ApplicationsReader {
  ssfAllowedEventsFor(name: string): { identifier: string;
                                       values: string[] } | null;
}

// `persistence/persistence.js`, as far as this module reads it.
interface PersistenceReader {
  clusterStore(): unknown;
}

interface SsfStreamsDeps {
  log: typeof helpers.log;
  randomId: typeof helpers.randomId;
  iso: typeof helpers.iso;
  config: typeof config;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  subjects: typeof subjects;
  events: typeof events;
  loadApplications: () => ApplicationsReader;
  loadPersistence: () => PersistenceReader;
}

class SsfStreams {
  constructor(private readonly deps: SsfStreamsDeps) {
    deps.log.debug("Entering SsfStreams.constructor().");
    deps.log.debug("Leaving SsfStreams.constructor().");
  }

  private limit(key?, fallback?) {
    const { log, config } = this.deps;
    log.debug("Entering SsfStreams.limit(). " + key);
    const value = Number(config.value(key));
    const out = (Number.isFinite(value) && value > 0) ? value : fallback;
    log.debug("Leaving SsfStreams.limit(). " + out);
    return out;
  }

  // ---------------------------------------------------------------------------
  // CREATE.
  //
  // `asked` is the Stream Configuration the receiver posted. What comes back is
  // `{ ok, stream, errors }` — the record as this service will keep it, with
  // every member the transmitter owns filled in by this service and never by
  // the caller:
  //
  //   * `stream_id` is minted here. A receiver that could choose one could
  //     overwrite somebody else's stream.
  //   * `iss` is this realm's issuer. A stream whose issuer the receiver chose
  //     would produce SETs claiming to come from wherever it said.
  //   * `events_delivered` is the INTERSECTION of what the receiver requested
  //     and what this transmitter supports, which is the specification's own
  //     arrangement and the member most often confused with `events_requested`:
  //     one is the ask and the other is the answer, and a receiver that reads
  //     the first back as the second believes it will get event types nothing
  //     will send.
  // ---------------------------------------------------------------------------
  createStream(asked?, context?) {
    const { log, config, events, iso, randomId, subjects } = this.deps;
    log.debug("Entering SsfStreams.createStream().");
    const body = (asked && typeof asked === 'object') ? asked : {};
    const ctx = context || {};
    const errors = [];
    const store = streams;

    const max = this.limit('ssf.maxStreams', 25);
    if (store.size >= max) {
      errors.push('This transmitter is holding ' + store.size + ' stream(s) ' +
          'and ssf.maxStreams is ' + max + '. Delete one, or raise the ' +
          'setting on /admin/ssf.');
      log.debug("Leaving SsfStreams.createStream(). At the stream limit.");
      return { ok: false, stream: null, errors: errors };
    }

    const delivery = this.normaliseDelivery(body.delivery, errors);
    const audience = this.normaliseAudience(body.aud, ctx, errors);
    const requested = this.normaliseEventList(body.events_requested);
    const supported = events.supportedEventUris();
    const offered = requested.length
      ? requested.filter((uri) => {
          return supported.indexOf(uri) >= 0;
        })
      : supported.slice();
    // The OWNER'S ENTRY narrows it further (see allowedEventsFor()). Nothing is
    // noted on the stream here because the stream does not exist yet; the note
    // is written once it does, below.
    const delivered = this.narrowByApplication(null, offered, ctx &&
                                               ctx.principal);

    requested.forEach((uri) => {
      if (supported.indexOf(uri) < 0) {
        // NOT an error. SSF 1.0 section 7.1.1 says the transmitter answers with
        // what it WILL deliver, so an unsupported request is answered by its
        // absence from events_delivered rather than by a refusal — and a
        // receiver that compares the two lists finds out exactly this.
        log.debug('createStream(): "' + uri + '" was requested and is not ' +
                  'supported, so it is absent from events_delivered.');
      }
    });

    const format = String(body.format || '');
    if (format && subjects.FORMAT_NAMES.indexOf(format) < 0) {
      errors.push('"format" is "' + format + '", which is not one of RFC ' +
          '9493\'s eight Subject Identifier formats: ' +
          subjects.FORMAT_NAMES.join(', ') + '. It is the format this ' +
          'transmitter will name a DEFAULT subject in.');
    }

    const interval = Number(body.min_verification_interval);
    const configured = this.limit('ssf.minVerificationInterval', 60);
    if (Number.isFinite(interval) && interval > 0 && interval < configured) {
      errors.push('"min_verification_interval" is ' + interval + ' seconds ' +
          'and this transmitter will not go below ' + configured +
          ' (ssf.minVerificationInterval). The member is the TRANSMITTER\'s ' +
          'statement rather than the receiver\'s request, which is why a ' +
          'smaller value is refused instead of being accepted and ignored.');
    }

    if (errors.length) {
      log.debug("Leaving SsfStreams.createStream(). " + errors.length +
                ' problem(s).');
      return { ok: false, stream: null, errors: errors };
    }

    const now = iso();
    const record = {
      // THE ID IS THE CALLER'S ONLY WHEN THE CALLER IS THIS SERVICE, AND IT
      // RIDES ON `ctx` RATHER THAN ON `body` FOR ONE REASON (2026-09-12):
      // `body` is the REQUEST BODY at ssf.ts's POST /ssf/stream, so a
      // `stream_id` read from there would let a receiver name its own stream —
      // and therefore name somebody else's, which is a stream takeover with a
      // string as the only input. `contextOf()` builds its object from the
      // request's identity and never from what was sent, so nothing a client
      // writes can reach this.
      //
      // What supplies it is `ssf_receivers.ts`, which DERIVES the id for its
      // two internal streams so that every process of this service arrives at
      // the same one. See that file for why a random id was the wrong shape
      // there.
      stream_id: ctx && ctx.streamId
        ? String(ctx.streamId)
        : 'ssf-' + randomId(12),
      iss: String(ctx.issuer || ''),
      aud: audience,
      delivery: delivery,
      events_supported: supported.slice(),
      events_requested: requested.slice(),
      events_delivered: delivered,
      format: format,
      min_verification_interval: configured,
      description: String(body.description || ''),
      status: String(config.value('ssf.streamStatusOnCreate') || 'enabled'),
      statusReason: 'created',
      createdAt: now,
      updatedAt: now,
      createdBy: String(ctx.principal || '(unauthenticated)'),
      subjects: [],
      // NO `queue` MEMBER: the SETs waiting on this stream are rows in `queued`
      // above, read through queueOf(). See the header on that store.
      log: [],
      counters: { queued: 0, delivered: 0, failed: 0, acknowledged: 0,
        pollCalls: 0, pushCalls: 0, receiverErrors: 0 },
      // HOW MANY OF EACH TYPE THIS STREAM HAS BEEN SAID TO, uri -> count.
      //
      // The counters above are about the PIPE — how many went on the queue, how
      // many were delivered, how many the receiver refused — and none of them
      // can answer "how many session-revoked has this receiver been sent",
      // which is the question /admin/caep-sessions' per-application section
      // exists to answer. It cannot be derived either: the CAEP register counts
      // per SESSION and keeps only the last twenty-five events per row, so
      // summing its rings would be right until a busy session and wrong
      // afterwards.
      //
      // It never forgets and it is not a ring, for the same reason `counts` on
      // a register row is not: "how many have there been" and "which were the
      // last few" are two questions, and one store answering both gets the
      // first one wrong. It dies with the stream, which is the correct lifetime
      // — a receiver that deletes its stream and agrees another has started
      // again.
      eventCounts: {},
      lastPushError: '',
      lastPushAt: '',
      lastVerificationAt: 0
    };
    store.set(record.stream_id, record);
    if (offered.length !== delivered.length) {
      this.note(record, 'withheld', (offered.length - delivered.length) +
           ' event ' + 'type(s) this transmitter supports are not delivered, ' +
           'because ssfAllowedEvents on the owning application does not ' +
           'allow them: ' + offered.filter((uri) => {
             return delivered.indexOf(uri) < 0;
           }).join(', '));
    }
    this.note(record, 'created', 'The stream was created with ' +
         record.events_delivered.length + ' event type(s) and ' +
         this.deliveryName(record.delivery.method) + ' delivery.');
    log.debug("Leaving SsfStreams.createStream(). " + record.stream_id);
    return { ok: true, stream: record, errors: [] };
  }

  // ---------------------------------------------------------------------------
  // WHAT THE APPLICATION THAT OWNS A STREAM MAY BE SENT (2026-09-12).
  //
  // `ssfAllowedEvents` on an application entry is the one place in the registry
  // that LIMITS Shared Signals: a stream owned by that application carries only
  // the event types it names. Everything else on an entry is a declaration —
  // this is enforcement, asked for by name, and it is the reason the registry's
  // "declaring grants nothing" sentence now has an exception for this family.
  //
  // **ABSENT MEANS UNRESTRICTED.** An entry with no values, a principal no
  // entry answers to, and a stream nobody authenticated for all behave exactly
  // as every stream did before the attribute existed. What is restricted is
  // only what an operator wrote down.
  //
  // **SSF'S OWN TWO EVENTS ARE ALWAYS ALLOWED.** Verification and
  // stream-updated are about the PIPE; a receiver refused its verification
  // event could not find out that its stream works, which is the one question
  // those events answer.
  //
  // **IT IS ASKED TWICE AND BOTH ARE NEEDED.** At agreement, so
  // `events_delivered` tells the receiver the truth; and at DELIVERY
  // (`deliversEvent()`), because an operator tightening the entry after a
  // stream was agreed must stop what that stream receives from then on — a
  // limit that only applied to streams created afterwards would be one a
  // receiver escapes by creating its stream first.
  //
  // The owner is the stream's `createdBy`: the identifier the receiver
  // AUTHENTICATED as, found as an application identifier or among an entry's
  // `ssfReceiverId` values. `applications.js` is required lazily — it is a
  // library, and this file is loaded from places that never touch the registry.
  // ---------------------------------------------------------------------------
  // THE OWNER'S `ssfAllowedEvents`, read off the raw entry (2026-09-14). This
  // asked `applications.get()` and then `applications.list()` — a whole view of
  // every application in the realm, sealed keys opened — for every event on
  // every stream, which is what made a 2,412-session sweep block the process
  // for 58 seconds. `applications.ssfAllowedEventsFor()` does the same two
  // matches over the cached registry listing.
  private applicationFor(principal?) {
    const { log, loadApplications } = this.deps;
    log.debug("Entering SsfStreams.applicationFor().");
    const name = String(principal || '');
    if (!name || name === '(unauthenticated)') {
      log.debug("Leaving SsfStreams.applicationFor().");
      return null;
    }
    let applications;
    try {
      applications = loadApplications();
    } catch (e) {
      log.debug("Caught in SsfStreams.applicationFor(): " + ((e && e.message) ||
          e));
      log.debug("Leaving SsfStreams.applicationFor().");
      // No registry in this process: nothing is restricted.
      return null;
    }
    log.debug("Leaving SsfStreams.applicationFor().");
    return applications.ssfAllowedEventsFor(name);
  }

  allowedEventsFor(principal?) {
    const { log, events } = this.deps;
    log.debug("Entering SsfStreams.allowedEventsFor().");
    const entry = this.applicationFor(principal);
    const values = entry ? entry.values : [];
    if (!values.length) {
      log.debug("Leaving SsfStreams.allowedEventsFor().");
      return null;
    }
    const allowed = {};
    // SSF's own two, and this service's own signing-key event (#42, D4),
    // which is about the transmitter rather than anybody an entry could be
    // limiting a stream about.
    (events.SSF_EVENTS as any[]).concat(events.STS_EVENTS)
      .forEach((row: any) => {
        allowed[row.uri] = true;
      });
    values.forEach((value) => {
      const word = String(value).trim();
      const lower = word.toLowerCase();
      if (lower === 'caep') {
        events.CAEP_EVENT_URIS.forEach((uri) => { allowed[uri] = true; });
      } else if (lower === 'risc') {
        events.RISC_EVENT_URIS.forEach((uri) => { allowed[uri] = true; });
      } else if (events.EVENT_BY_URI[word]) {
        allowed[word] = true;
      }
    });
    log.debug("Leaving SsfStreams.allowedEventsFor().");
    return { application: entry.identifier, values: values.slice(),
             allowed: allowed };
  }

  private permits(restriction?, uri?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.permits().");
    log.debug("Leaving SsfStreams.permits().");
    return !restriction || !!restriction.allowed[String(uri)];
  }

  // The event types this stream would actually be sent right now: what was
  // agreed, less anything its owner's entry has since stopped allowing.
  effectiveDelivered(record?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.effectiveDelivered().");
    const restriction = this.allowedEventsFor(record.createdBy);
    log.debug("Leaving SsfStreams.effectiveDelivered().");
    return record.events_delivered.filter((uri) => {
      return this.permits(restriction, uri);
    });
  }

  // THE question every delivery path asks. A stream takes an event when it
  // agreed to and its owner is still allowed it.
  deliversEvent(record?, uri?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.deliversEvent().");
    log.debug("Leaving SsfStreams.deliversEvent().");
    return record.events_delivered.indexOf(String(uri)) >= 0 &&
           this.permits(this.allowedEventsFor(record.createdBy), uri);
  }

  // Narrow an agreed list by the owner's entry, noting what was withheld.
  private narrowByApplication(record?, delivered?, principal?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.narrowByApplication().");
    const restriction = this.allowedEventsFor(principal);
    if (!restriction) {
      log.debug("Leaving SsfStreams.narrowByApplication().");
      return delivered;
    }
    const withheld = delivered.filter((uri) => {
      return !this.permits(restriction, uri);
    });
    if (withheld.length) {
      log.info('ssf: ' + withheld.length + ' event type(s) were withheld ' +
                                           'from a stream for "' +
               restriction.application + '", whose entry allows only ' +
               restriction.values.join(', ') + ' (ssfAllowedEvents): ' +
                                           withheld.join(', '));
      if (record) {
        this.note(record, 'withheld', withheld.length + ' requested event ' +
             'type(s) are not allowed by ssfAllowedEvents on ' +
             '"' + restriction.application + '" and are ' +
                 'not delivered: ' +
             withheld.join(', '));
      }
    }
    log.debug("Leaving SsfStreams.narrowByApplication().");
    return delivered.filter((uri) => {
      return this.permits(restriction, uri);
    });
  }

  deliveryName(method?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.deliveryName().");
    const row = DELIVERY_METHODS.filter((one) => {
      return one.method === method;
    })[0];
    log.debug("Leaving SsfStreams.deliveryName().");
    return row ? row.name : String(method || '(none)');
  }

  // ---------------------------------------------------------------------------
  // The `delivery` member, which is the one part of a Stream Configuration a
  // receiver genuinely owns and the one with a security consequence: its
  // `endpoint_url` is a URL THIS SERVICE WILL DIAL. `ssf_http.ts` argues that
  // at length; what happens HERE is the shape check.
  // ---------------------------------------------------------------------------
  private normaliseDelivery(asked?, errors?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.normaliseDelivery().");
    const offered = this.offeredDeliveryMethods();
    const body = (asked && typeof asked === 'object' && !Array.isArray(asked))
      ? asked : {};
    const method = String(body.method || '');
    if (!method) {
      // SSF 1.0 makes `delivery` optional on a create and says the transmitter
      // picks. Poll is the safe default and the honest one: it dials nothing.
      const fallback = offered.indexOf(DELIVERY_POLL) >= 0
        ? DELIVERY_POLL : offered[0];
      log.debug("Leaving SsfStreams.normaliseDelivery(). Defaulted to " +
                fallback + '.');
      return { method: fallback, endpoint_url: '', authorization_header: '' };
    }
    if (offered.indexOf(method) < 0) {
      errors.push('"delivery.method" is "' + method + '". This transmitter ' +
          'offers ' + offered.join(' and ') + ' (ssf.deliveryMethods). Note ' +
          'the values are the RFC numbers as URNs — "push" and "poll" are ' +
          'not method identifiers, which catches everybody once.');
      log.debug("Leaving SsfStreams.normaliseDelivery(). Unoffered method.");
      return { method: method, endpoint_url: '', authorization_header: '' };
    }
    if (method === DELIVERY_POLL) {
      if (body.endpoint_url) {
        // RFC 8936's poll endpoint is the TRANSMITTER's, published in the
        // stream configuration by the transmitter. A receiver sending one is
        // describing an endpoint of its own that nothing will ever call, which
        // is worth saying rather than ignoring.
        errors.push('"delivery.endpoint_url" was sent with a POLL method. ' +
            'On poll delivery the endpoint is the TRANSMITTER\'s and this ' +
            'service publishes it in the stream configuration it hands back ' +
            '— a receiver-supplied one would be a URL nothing calls.');
      }
      log.debug("Leaving SsfStreams.normaliseDelivery(). Poll.");
      return { method: DELIVERY_POLL, endpoint_url: '',
        authorization_header: '' };
    }
    const url = String(body.endpoint_url || '');
    if (!url) {
      errors.push('"delivery.endpoint_url" is required for push delivery — ' +
          'it is where this transmitter POSTs each SET.');
    }
    log.debug("Leaving SsfStreams.normaliseDelivery(). Push.");
    return { method: DELIVERY_PUSH, endpoint_url: url,
      authorization_header: String(body.authorization_header || '') };
  }

  // Which delivery methods this deployment offers. A list, so that a client's
  // "you do not do push" path is reachable by configuration rather than by a
  // second service.
  offeredDeliveryMethods() {
    const { log, config } = this.deps;
    log.debug("Entering SsfStreams.offeredDeliveryMethods().");
    const asked = config.value('ssf.deliveryMethods');
    const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
    const chosen = [];
    list.map((one) => {
      return String(one).trim();
    }).filter(Boolean).forEach((name) => {
      const urn = name === 'push' ? DELIVERY_PUSH
        : name === 'poll' ? DELIVERY_POLL : name;
      const known = DELIVERY_METHODS.some((row) => {
        return row.method === urn;
      });
      if (!known) {
        log.warn('ssf.deliveryMethods names "' + name + '", which is not a ' +
                 'delivery method SSF defines. It is ignored.');
        return;
      }
      if (chosen.indexOf(urn) < 0) {
        chosen.push(urn);
      }
    });
    const out = chosen.length ? chosen : [DELIVERY_PUSH, DELIVERY_POLL];
    log.debug("Leaving SsfStreams.offeredDeliveryMethods(). " + out.length +
              '.');
    return out;
  }

  // The `aud` of every SET on this stream. A string or an array, exactly as the
  // receiver sent it, because RFC 8417's `aud` is JWT's `aud` and a receiver
  // that registered an array checks for itself in an array.
  //
  // **IT IS REQUIRED AND IT IS NOT DEFAULTED TO THE AUTHENTICATED CALLER**,
  // which is a decision rather than an omission and it is the one place this
  // module is stricter than the rest of this service. Defaulting was written
  // first and taken out: a receiver whose `aud` was invented for it never finds
  // out that the member is required, and the first real transmitter it meets
  // refuses every stream it creates. Worse, the audience a receiver checks for
  // ITSELF in would then be a name this service chose — so an event it should
  // refuse with `invalid_audience` would be one it accepts.
  //
  // The permissive posture everywhere else in this service is about
  // CREDENTIALS. This is a protocol member with a consequence at the far end,
  // and inventing one teaches a client something false.
  private normaliseAudience(asked?, context?, errors?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.normaliseAudience().");
    if (typeof asked === 'string' && asked !== '') {
      log.debug("Leaving SsfStreams.normaliseAudience(). One string.");
      return asked;
    }
    if (Array.isArray(asked)) {
      const list = asked.map((one) => {
        return String(one);
      }).filter(Boolean);
      if (!list.length) {
        errors.push('"aud" is an empty array. Every SET on this stream would ' +
            'be addressed to nobody.');
      }
      log.debug("Leaving SsfStreams.normaliseAudience(). " + list.length +
                ' value(s).');
      return list;
    }
    errors.push('"aud" is required — it is who the SETs on this stream are ' +
        'addressed to, and a receiver checks for ITSELF in it. It is not ' +
        'defaulted to whoever authenticated: an audience this transmitter ' +
        'invented would be one the receiver never learns it has to send, and ' +
        'an event it ought to refuse with invalid_audience would be one it ' +
        'accepts.');
    log.debug("Leaving SsfStreams.normaliseAudience(). Missing.");
    return '';
  }

  private normaliseEventList(asked?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.normaliseEventList().");
    const list = Array.isArray(asked) ? asked : [];
    const out = list.map((one) => {
      return String(one);
    }).filter(Boolean);
    log.debug("Leaving SsfStreams.normaliseEventList(). " + out.length + '.');
    return out;
  }

  getStream(id?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.getStream(). " + id);
    const record = streams.get(String(id || '')) || null;
    log.debug("Leaving SsfStreams.getStream(). " + (record ? 'found' :
                                                    'not found'));
    return record;
  }

  listStreams() {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.listStreams().");
    const out = [];
    streams.forEach((record) => {
      out.push(record);
    });
    out.sort((a, b) => {
      return String(a.createdAt).localeCompare(String(b.createdAt));
    });
    log.debug("Leaving SsfStreams.listStreams(). " + out.length + '.');
    return out;
  }

  // ---------------------------------------------------------------------------
  // A RECORD EDITED IN PLACE, REPORTED TO THE JOURNAL — `caep.ts`'s `touch()`,
  // for the same reason: every function below edits a record already in the
  // map, and `realms.map()` journals only a `set()`. Without it a stream's
  // status, subjects, agreement and counters reached the store as they were
  // CREATED and no other process ever saw a PATCH, a pause or a subject added.
  //
  // It re-sets the record only while it is still the one held. A record another
  // process's write has since REPLACED is a copy the store has let go of, and
  // writing it back would undo that write — so a caller that waited on
  // something asynchronous asks `liveRecord()` first and edits what that
  // answers.
  // ---------------------------------------------------------------------------
  touch(record?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.touch().");
    if (!record || !record.stream_id) {
      log.debug("Leaving SsfStreams.touch(). No record.");
      return false;
    }
    if (streams.get(record.stream_id) !== record) {
      log.debug("Leaving SsfStreams.touch(). Not the record held for " +
                record.stream_id + '.');
      return false;
    }
    // A RECORD WRITTEN BY AN EARLIER BUILD carries the queue as a member. It is
    // not migrated: nothing ever journalled a change to it, so what a stored
    // one holds is whatever happened to be waiting when the record was first
    // written — usually nothing — and adopting it could deliver a SET that was
    // acknowledged long ago. It is dropped the first time the record is
    // written.
    if (Object.prototype.hasOwnProperty.call(record, 'queue')) {
      delete record.queue;
    }
    streams.set(record.stream_id, record);
    log.debug("Leaving SsfStreams.touch(). " + record.stream_id);
    return true;
  }

  // The record held NOW for the stream `record` was read as, or `record` itself
  // when the stream has gone. What a caller that crossed an `await` edits: see
  // touch() above.
  liveRecord(record?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.liveRecord().");
    if (!record || !record.stream_id) {
      log.debug("Leaving SsfStreams.liveRecord(). No record.");
      return record;
    }
    const held = streams.get(record.stream_id);
    log.debug("Leaving SsfStreams.liveRecord(). " +
              (held ? (held === record ? 'unchanged' : 'replaced') : 'gone'));
    return held || record;
  }

  removeStream(id?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.removeStream(). " + id);
    const key = String(id || '');
    // ITS SETS GO WITH IT, as rows. They were members of the record and died
    // with it; as rows of their own they would otherwise outlive it in every
    // process, counted by nothing and polled by nobody.
    this.clearQueueFor(key);
    // And its dead letters: evidence about a stream that no longer exists.
    this.clearDeadLettersFor(key);
    const gone = streams.delete(key);
    log.debug("Leaving SsfStreams.removeStream(). " + gone);
    return gone;
  }

  // ---------------------------------------------------------------------------
  // UPDATE, in the two shapes SSF 1.0 section 7.1.1 gives it.
  //
  //   'replace'  (PUT)   every member the receiver may set is taken from the
  //                      body, and one it omits goes back to its default.
  //   'merge'    (PATCH) only the members present are changed.
  //
  // The distinction is the one every REST API has and the one every REST API
  // gets wrong in the same direction: a PUT that behaved like a PATCH would let
  // a receiver believe it had cleared `events_requested` when it had not, and
  // the symptom is event types still arriving after they were "removed".
  // ---------------------------------------------------------------------------
  updateStream(id?, asked?, mode?, context?) {
    const { log, events, iso, subjects } = this.deps;
    log.debug("Entering SsfStreams.updateStream(). " + id + ' ' + mode);
    const record = this.getStream(id);
    if (!record) {
      log.debug("Leaving SsfStreams.updateStream(). No such stream.");
      return { ok: false, stream: null,
        errors: ['No stream with stream_id "' + String(id) + '".'] };
    }
    const body = (asked && typeof asked === 'object') ? asked : {};
    const replace = mode === 'replace';
    const errors = [];
    const has = (name) => {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return Object.prototype.hasOwnProperty.call(body, name);
    };

    if (replace || has('delivery')) {
      const delivery = this.normaliseDelivery(body.delivery, errors);
      record.delivery = delivery;
    }
    if (replace || has('aud')) {
      record.aud = this.normaliseAudience(body.aud, context, errors);
    }
    if (replace || has('events_requested')) {
      const requested = this.normaliseEventList(body.events_requested);
      const supported = events.supportedEventUris();
      record.events_requested = requested;
      record.events_supported = supported.slice();
      record.events_delivered = this.narrowByApplication(record,
          requested.length
        ? requested.filter((uri) => {
            return supported.indexOf(uri) >= 0;
          })
        : supported.slice(), record.createdBy);
    }
    if (replace || has('format')) {
      const format = String(body.format || '');
      if (format && subjects.FORMAT_NAMES.indexOf(format) < 0) {
        errors.push('"format" is "' + format + '", which is not one of RFC ' +
            '9493\'s eight Subject Identifier formats.');
      } else {
        record.format = format;
      }
    }
    if (replace || has('description')) {
      record.description = String(body.description || '');
    }

    if (errors.length) {
      log.debug("Leaving SsfStreams.updateStream(). " + errors.length +
                ' problem(s).');
      return { ok: false, stream: null, errors: errors };
    }
    record.updatedAt = iso();
    this.note(record, 'updated', (replace ? 'Replaced' : 'Merged') +
         ' — now delivering ' + record.events_delivered.length +
         ' event type(s) over ' + this.deliveryName(record.delivery.method) +
             '.');
    this.touch(record);
    log.debug("Leaving SsfStreams.updateStream(). Updated.");
    return { ok: true, stream: record, errors: [] };
  }

  // ---------------------------------------------------------------------------
  // STATUS.
  //
  // Three values, and the middle one is the one worth knowing about: a PAUSED
  // stream keeps QUEUEING and delivers nothing, so the events that happened
  // while it was paused are still there when it is enabled again. A DISABLED
  // one drops them. SSF 1.0 section 7.1.2 says exactly that, and it is the
  // difference between "I was not listening" and "it did not happen" — which is
  // the whole reason a Shared Signals receiver has a pause at all.
  // ---------------------------------------------------------------------------
  setStatus(id?, status?, reason?) {
    const { log, events, iso } = this.deps;
    log.debug("Entering SsfStreams.setStatus(). " + id + ' -> ' + status);
    const record = this.getStream(id);
    if (!record) {
      log.debug("Leaving SsfStreams.setStatus(). No such stream.");
      return { ok: false, stream: null,
        errors: ['No stream with stream_id "' + String(id) + '".'] };
    }
    if (events.STATUSES.indexOf(status) < 0) {
      log.debug("Leaving SsfStreams.setStatus(). Unknown status.");
      return { ok: false, stream: null,
        errors: ['"' + String(status) + '" is not a stream status. SSF 1.0 ' +
          'section 7.1.2 defines ' + events.STATUSES.join(', ') + '.'] };
    }
    const before = record.status;
    record.status = status;
    record.statusReason = String(reason || '');
    record.updatedAt = iso();
    const waiting = this.queueOf(record).length;
    if (status === 'disabled' && waiting) {
      // Deliberate, and the sentence above is why. A disabled stream is not a
      // paused one: what was waiting is dropped, and the count is reported so
      // that a reader can see it happen rather than discovering later that the
      // queue is empty.
      this.note(record, 'status', 'Disabled — ' + waiting +
           ' queued event(s) were DROPPED. A paused stream would have kept ' +
           'them; that is the whole difference between the two.');
      this.clearQueueFor(record.stream_id);
    } else {
      this.note(record, 'status', before + ' -> ' + status +
           (reason ? ' (' + reason + ')' : ''));
    }
    this.touch(record);
    log.debug("Leaving SsfStreams.setStatus(). " + before + ' -> ' + status);
    return { ok: true, stream: record, errors: [] };
  }

  // ---------------------------------------------------------------------------
  // SUBJECTS.
  //
  // A stream's subject list is who it is about. `ssf.defaultSubjects` decides
  // what an empty list MEANS, and the two answers are opposites:
  //
  //   ALL    the stream is about everybody, and the list NARROWS nothing —
  //          adding a subject to it is redundant.
  //   NONE   the stream is about nobody until somebody is added.
  //
  // This service publishes the value in its metadata (`default_subjects`),
  // because a receiver that guesses wrong either gets every event in the estate
  // or gets none, and both look like a broken transmitter.
  // ---------------------------------------------------------------------------
  addSubject(id?, subject?, verified?, options?) {
    const { log, iso, subjects } = this.deps;
    log.debug("Entering SsfStreams.addSubject(). " + id);
    const record = this.getStream(id);
    if (!record) {
      log.debug("Leaving SsfStreams.addSubject(). No such stream.");
      return { ok: false, errors: ['No stream with stream_id "' +
        String(id) + '".'] };
    }
    const verdict = subjects.validateSubjectId(subject, {
      path: 'subject',
      criticalMembers: (options || {}).criticalMembers || []
    });
    if (!verdict.ok) {
      log.debug("Leaving SsfStreams.addSubject(). Invalid subject.");
      return { ok: false, errors: verdict.errors };
    }
    const max = this.limit('ssf.maxSubjectsPerStream', 100);
    const key = subjects.subjectKey(subject);
    const existing = record.subjects.filter((one) => {
      return one.key === key;
    })[0];
    if (existing) {
      existing.verified = verified !== false;
      existing.updatedAt = iso();
      this.touch(record);
      log.debug("Leaving SsfStreams.addSubject(). Already present.");
      return { ok: true, errors: [], added: false, subject: existing };
    }
    if (record.subjects.length >= max) {
      log.debug("Leaving SsfStreams.addSubject(). At the subject limit.");
      return { ok: false, errors: ['This stream already names ' +
        record.subjects.length + ' subject(s) and ssf.maxSubjectsPerStream ' +
        'is ' + max + '.'] };
    }
    const entry = {
      key: key,
      subject: subject,
      // RFC-wise this is the `verified` member of the Add Subject request: the
      // receiver saying it has already checked that the subject is one it cares
      // about. This service records it and refuses nothing on it, which is the
      // posture the rest of the service takes — see ssf/CLAUDE.md.
      verified: verified !== false,
      addedAt: iso(),
      updatedAt: iso()
    };
    record.subjects.push(entry);
    record.updatedAt = iso();
    this.note(record, 'subject', 'Added ' + subjects.describeSubject(subject) +
         (entry.verified ? '' : ' (unverified)'));
    this.touch(record);
    log.debug("Leaving SsfStreams.addSubject(). Added.");
    return { ok: true, errors: [], added: true, subject: entry };
  }

  removeSubject(id?, subject?) {
    const { log, iso, subjects } = this.deps;
    log.debug("Entering SsfStreams.removeSubject(). " + id);
    const record = this.getStream(id);
    if (!record) {
      log.debug("Leaving SsfStreams.removeSubject(). No such stream.");
      return { ok: false, errors: ['No stream with stream_id "' +
        String(id) + '".'] };
    }
    const verdict = subjects.validateSubjectId(subject, { path: 'subject' });
    if (!verdict.ok) {
      log.debug("Leaving SsfStreams.removeSubject(). Invalid subject.");
      return { ok: false, errors: verdict.errors };
    }
    const key = subjects.subjectKey(subject);
    const before = record.subjects.length;
    record.subjects = record.subjects.filter((one) => {
      return one.key !== key;
    });
    record.updatedAt = iso();
    const removed = before !== record.subjects.length;
    this.note(record, 'subject', (removed ? 'Removed ' : 'Asked to remove ') +
         subjects.describeSubject(subject) +
         (removed ? '' : ', which was not on this stream. SSF 1.0 says a ' +
          'remove is idempotent, so this is a 204 rather than a 404.'));
    this.touch(record);
    log.debug("Leaving SsfStreams.removeSubject(). " + removed);
    return { ok: true, errors: [], removed: removed };
  }

  setSubjectScope(family?, fn?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.setSubjectScope().");
    if (typeof fn !== 'function') {
      delete subjectScopes[String(family)];
      log.debug("Leaving SsfStreams.setSubjectScope().");
      return;
    }
    subjectScopes[String(family)] = fn;
    log.debug("Leaving SsfStreams.setSubjectScope().");
  }

  private scopeRefuses(record?, subject?) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SsfStreams.scopeRefuses().");
    log.debug("Leaving SsfStreams.scopeRefuses().");
    return Object.keys(subjectScopes).some((family) => {
      let answer;
      try {
        answer = subjectScopes[family](record, subject);
      } catch (e) {
        // A scope that throws narrows nothing: delivery is not allowed to fail
        // on another family's bookkeeping. Logged, because it is a defect
        // there.
        log.warn(errorCodes.tag('STS-SSF-0076') + 'ssf: the ' + family +
                 ' subject scope threw and was ignored: ' + e.message);
        return false;
      }
      return answer === false;
    });
  }

  streamCoversSubject(record?, subject?) {
    const { log, config, subjects } = this.deps;
    log.debug("Entering SsfStreams.streamCoversSubject().");
    if (!subject) {
      // An event with no subject — the two SSF events — is about the STREAM and
      // goes to it whatever its subject list says.
      log.debug("Leaving SsfStreams.streamCoversSubject(). No subject; " +
          "always.");
      return true;
    }
    if (this.scopeRefuses(record, subject)) {
      log.debug("Leaving SsfStreams.streamCoversSubject(). A family's " +
                "subject scope refuses it.");
      return false;
    }
    if (record.subjects.length) {
      const key = subjects.subjectKey(subject);
      const covered = record.subjects.some((one) => {
        return one.key === key;
      });
      if (covered) {
        log.debug("Leaving SsfStreams.streamCoversSubject(). Named exactly.");
        return true;
      }
      // -------------------------------------------------------------------
      // A COMPLEX SUBJECT IS COVERED BY A STREAM THAT NAMES ANY ONE OF ITS
      // MEMBERS, AND WITHOUT THIS RULE CAEP WOULD DELIVER NOTHING.
      //
      // A receiver adds the PERSON to a stream — that is the subject it has,
      // and the only one it can name in advance. A CAEP event about that
      // person names a SESSION of theirs, which SSF 1.0 section 4 expresses as
      // a complex subject whose `user` member is exactly the identifier the
      // receiver added. Those two are different `subjectKey()`s, so an
      // exact-match test refuses every session event to the receiver that
      // asked for the person — silently, because a transmitter's refusal to
      // send is not a message anybody receives.
      //
      // It is deliberately ONE LEVEL and not recursive: a complex subject may
      // not nest another (SSF section 4), so a member is always a plain
      // identifier and there is nothing below it to walk.
      // -------------------------------------------------------------------
      if (!subject.format) {
        const members = subjects.COMPLEX_MEMBER_NAMES.filter((name) => {
          return subject[name] && typeof subject[name] === 'object';
        });
        const viaMember = members.some((name) => {
          const memberKey = subjects.subjectKey(subject[name]);
          return record.subjects.some((one) => {
            return one.key === memberKey;
          });
        });
        log.debug("Leaving SsfStreams.streamCoversSubject(). By member: " +
                  viaMember);
        return viaMember;
      }
      log.debug("Leaving SsfStreams.streamCoversSubject(). false");
      return false;
    }
    const all = String(config.value('ssf.defaultSubjects') || 'ALL')
      .toUpperCase() === 'ALL';
    log.debug("Leaving SsfStreams.streamCoversSubject(). Empty list; " + all);
    return all;
  }

  // ---------------------------------------------------------------------------
  // THE QUEUE.
  //
  // Every SET goes on the stream's queue whatever the delivery method is, and
  // push takes it off again straight away. That is one path rather than two,
  // and it is what makes a stream that FAILS to push recoverable: the event is
  // still there, `counters.failed` says what happened, and the console can show
  // it. A push implementation that signed and posted in one breath would lose
  // the event on the first refused connection with nothing to show for it.
  //
  // **THE QUEUE IS ROWS IN `queued`, ONE PER SET** — see the header on that
  // store for why it stopped being an array on the record. Everything here that
  // changes what is waiting does it with a `set()` of one SET's key or a
  // `delete()` of one, and never by writing the queue back whole.
  // ---------------------------------------------------------------------------

  // The row a SET is kept under. The stream comes first so that a receiver
  // acknowledging a jti can only ever remove a SET from ITS OWN stream: a jti
  // is random and unique, but a key that did not say whose it was would make
  // that a property of the generator rather than of this store.
  private queueKey(streamId?, jti?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.queueKey().");
    log.debug("Leaving SsfStreams.queueKey().");
    return String(streamId) + ' ' + String(jti);
  }

  private queueOrder() {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.queueOrder().");
    queueSequence = (queueSequence + 1) % 1000;
    log.debug("Leaving SsfStreams.queueOrder().");
    return Date.now() * 1000 + queueSequence;
  }

  // What is waiting on a stream, oldest first. A SCAN of the realm's rows
  // rather than an index, because an index would be a second copy of this store
  // that a row applied from another process has to remember to update — and the
  // scan is bounded: `ssf.maxStreams` streams of `ssf.maxQueuedEvents` each.
  queueOf(record?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.queueOf().");
    if (!record || !record.stream_id) {
      log.debug("Leaving SsfStreams.queueOf(). No record.");
      return [];
    }
    const prefix = this.queueKey(record.stream_id, '');
    const out = [];
    queued.forEach((entry, key) => {
      if (String(key).indexOf(prefix) === 0 && entry) {
        out.push(entry);
      }
    });
    out.sort((a, b) => {
      const left = Number(a.order) || 0;
      const right = Number(b.order) || 0;
      if (left !== right) {
        return left - right;
      }
      return String(a.jti).localeCompare(String(b.jti));
    });
    log.debug("Leaving SsfStreams.queueOf(). " + out.length + ' waiting on ' +
              record.stream_id + '.');
    return out;
  }

  // One SET off a stream's queue — acknowledged, refused, or pushed. Answers
  // whether it was there, which is what `counters.acknowledged` counts. The
  // delete is journalled whether or not this process held the row, for
  // `realms.map()`'s reason: a row this process never learnt of may still be in
  // the store, and an acknowledgement that only removed the rows it could see
  // would leave that one to be delivered again.
  dequeue(record?, jti?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.dequeue(). " + (record && record.stream_id));
    if (!record || !record.stream_id) {
      log.debug("Leaving SsfStreams.dequeue(). No record.");
      return false;
    }
    const gone = queued.delete(this.queueKey(record.stream_id, jti));
    log.debug("Leaving SsfStreams.dequeue(). " + gone);
    return gone;
  }

  // Everything waiting on a stream, dropped: a disable, and a removal. Returns
  // how many went.
  private clearQueueFor(streamId?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.clearQueueFor(). " + streamId);
    const prefix = this.queueKey(streamId, '');
    const keys = [];
    queued.forEach((entry, key) => {
      if (String(key).indexOf(prefix) === 0) {
        keys.push(key);
      }
    });
    keys.forEach((key) => {
      queued.delete(key);
    });
    log.debug("Leaving SsfStreams.clearQueueFor(). " + keys.length +
              ' dropped.');
    return keys.length;
  }

  enqueue(record?, entry?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.enqueue(). " + record.stream_id);
    if (record.status === 'disabled') {
      log.debug("Leaving SsfStreams.enqueue(). The stream is disabled.");
      return { ok: false, reason: 'the stream is disabled' };
    }
    const max = this.limit('ssf.maxQueuedEvents', 200);
    const waiting = this.queueOf(record);
    let over = waiting.length - max + 1;
    while (over > 0 && waiting.length) {
      // The OLDEST goes, not the newest. A receiver that has stopped reading is
      // most likely to want what has happened LATELY, and a queue that refused
      // new events would make a transmitter stop recording because a receiver
      // stopped listening.
      const dropped = waiting.shift();
      this.dequeue(record, dropped.jti);
      this.note(record, 'queue', 'The queue was full (ssf.maxQueuedEvents=' +
           max + '), so the oldest event (' + dropped.jti + ') was dropped.');
      over -= 1;
    }
    entry.stream_id = record.stream_id;
    if (!entry.order) {
      entry.order = this.queueOrder();
    }
    queued.set(this.queueKey(record.stream_id, entry.jti), entry);
    record.counters.queued += 1;
    this.touch(record);
    log.debug("Leaving SsfStreams.enqueue(). " + (waiting.length + 1) +
              ' waiting.');
    return { ok: true, reason: '' };
  }

  deadLettersOf(record?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.deadLettersOf().");
    if (!record || !record.stream_id) {
      log.debug("Leaving SsfStreams.deadLettersOf(). No record.");
      return [];
    }
    const prefix = this.queueKey(record.stream_id, '');
    const out = [];
    deadLetters.forEach((letter, key) => {
      if (String(key).indexOf(prefix) === 0 && letter) {
        out.push(letter);
      }
    });
    out.sort((a, b) => {
      const left = Number(a.deadAtMs) || 0;
      const right = Number(b.deadAtMs) || 0;
      if (left !== right) {
        return left - right;
      }
      return String(a.jti).localeCompare(String(b.jti));
    });
    log.debug("Leaving SsfStreams.deadLettersOf(). " + out.length + ' on ' +
              record.stream_id + '.');
    return out;
  }

  // EVERY DEAD LETTER IN THE AMBIENT REALM, in no particular order — what
  // Monitoring → Shared Signals → Dead letters counts (2026-09-14). One scan of
  // the realm's own partition: another realm's letters are not filtered out
  // here, they are in a different Map. The caller sorts and aggregates; this
  // hands back the rows exactly as they are held, token included, so a caller
  // drawing them must drop it (`ssf_dead_letter_report.ts` does).
  allDeadLetters() {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.allDeadLetters().");
    const out = [];
    deadLetters.forEach((letter, key) => {
      if (letter) {
        out.push(Object.assign({ stream_id: String(key).split(' ')[0] },
                               letter));
      }
    });
    log.debug("Leaving SsfStreams.allDeadLetters(). " + out.length + '.');
    return out;
  }

  // Delete the oldest of one stream's letters until it holds `max`. Answers how
  // many went.
  private trimDeadLetters(streamId?, max?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.trimDeadLetters(). " + streamId);
    const letters = this.deadLettersOf({ stream_id: streamId });
    let dropped = 0;
    while (letters.length > max) {
      const oldest = letters.shift();
      deadLetters.delete(this.queueKey(streamId, oldest.jti));
      dropped += 1;
    }
    deadCounts().set(streamId, letters.length);
    log.debug("Leaving SsfStreams.trimDeadLetters(). " + dropped + ' dropped.');
    return dropped;
  }

  addDeadLetter(record?, entry?, why?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.addDeadLetter(). " + (record &&
        record.stream_id));
    if (!record || !record.stream_id || !entry || !entry.jti) {
      log.debug("Leaving SsfStreams.addDeadLetter(). Nothing to add.");
      return false;
    }
    const reason = why || {};
    const now = Date.now();
    const letter = {
      stream_id: record.stream_id,
      jti: entry.jti,
      token: entry.token || '',
      claims: entry.claims || null,
      queuedAt: entry.queuedAt || '',
      deadAt: new Date(now).toISOString(),
      deadAtMs: now,
      reason: String(reason.why || ''),
      errorCode: String(reason.errorCode || ''),
      status: Number(reason.status) || 0,
      signed: !!entry.token
    };
    deadLetters.set(this.queueKey(record.stream_id, entry.jti), letter);
    record.counters.deadLettered = (record.counters.deadLettered || 0) + 1;
    const counts = deadCounts();
    if (counts.has(record.stream_id)) {
      deadCountsCount.hit();
    } else {
      deadCountsCount.miss();
    }
    const held = (counts.get(record.stream_id) || 0) + 1;
    counts.set(record.stream_id, held);
    const max = this.limit('ssf.deadLetterMaxPerStream', 1000);
    const seen = tally();
    if (held > max) {
      seen.trimmed += this.trimDeadLetters(record.stream_id, max);
    }
    seen.letters += 1;
    seen.byStream.set(record.stream_id,
                      (seen.byStream.get(record.stream_id) || 0) + 1);
    if (letter.errorCode) {
      seen.byCode.set(letter.errorCode,
                      (seen.byCode.get(letter.errorCode) || 0) + 1);
    }
    // THE RECORD IS NOT WRITTEN HERE. `counters.deadLettered` rides along with
    // the stream's next write; writing the whole record — its log included —
    // for every letter to a dead stream would be the per-event write load dead
    // streams exist to remove. The letter itself is written above.
    log.debug("Leaving SsfStreams.addDeadLetter(). " + held + ' held.');
    return true;
  }

  // Everything waiting on a stream, moved to its dead-letter queue — what a
  // stream being declared dead does. Answers how many moved.
  private moveQueueToDeadLetters(record?, why?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.moveQueueToDeadLetters(). " +
              record.stream_id);
    const waiting = this.queueOf(record);
    waiting.forEach((entry) => {
      this.addDeadLetter(record, entry, why);
      this.dequeue(record, entry.jti);
    });
    log.debug("Leaving SsfStreams.moveQueueToDeadLetters(). " + waiting.length +
              '.');
    return waiting.length;
  }

  removeDeadLetter(record?, jti?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.removeDeadLetter().");
    const gone = deadLetters.delete(this.queueKey(record.stream_id, jti));
    if (gone) {
      const counts = deadCounts();
      counts.set(record.stream_id,
                 Math.max(0, (counts.get(record.stream_id) || 1) - 1));
    }
    log.debug("Leaving SsfStreams.removeDeadLetter(). " + gone);
    return gone;
  }

  clearDeadLettersFor(streamId?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.clearDeadLettersFor(). " + streamId);
    const prefix = this.queueKey(streamId, '');
    const keys = [];
    deadLetters.forEach((letter, key) => {
      if (String(key).indexOf(prefix) === 0) {
        keys.push(key);
      }
    });
    keys.forEach((key) => {
      deadLetters.delete(key);
    });
    deadCounts().delete(String(streamId));
    log.debug("Leaving SsfStreams.clearDeadLettersFor(). " + keys.length +
              ' dropped.');
    return keys.length;
  }

  // ---------------------------------------------------------------------------
  // ONE SWEEP OF THE AMBIENT REALM'S DEAD LETTERS: delete what is older than
  // `ssf.deadLetterRetentionS` or belongs to no stream, enforce the per-stream
  // cap exactly, rebuild the counts, and hand back — and reset — what was
  // dead-lettered since the last sweep, for the caller's one summary line.
  // ---------------------------------------------------------------------------
  sweepDeadLetters(nowMs?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.sweepDeadLetters().");
    const now = Number(nowMs) || Date.now();
    const keepMs = this.limit('ssf.deadLetterRetentionS', 3600) * 1000;
    const expired = [];
    const orphaned = [];
    const perStream = new Map();
    deadLetters.forEach((letter, key) => {
      const streamId = String(key).split(' ')[0];
      if (!letter || !streams.has(streamId)) {
        orphaned.push(key);
        return;
      }
      if ((Number(letter.deadAtMs) || 0) + keepMs <= now) {
        expired.push(key);
        return;
      }
      perStream.set(streamId, (perStream.get(streamId) || 0) + 1);
    });
    expired.concat(orphaned).forEach((key) => {
      deadLetters.delete(key);
    });
    const max = this.limit('ssf.deadLetterMaxPerStream', 1000);
    const seen = tally();
    const counts = deadCounts();
    counts.clear();
    perStream.forEach((held, streamId) => {
      if (held > max) {
        seen.trimmed += this.trimDeadLetters(streamId, max);
      } else {
        counts.set(streamId, held);
      }
    });
    const out = { expired: expired.length, orphaned: orphaned.length,
      held: Array.from(counts.values()).reduce(function (n: number,
                                                         one: number) {
        return n + one;
      }, 0),
      letters: seen.letters, trimmed: seen.trimmed,
      byStream: Array.from(seen.byStream.entries()),
      byCode: Array.from(seen.byCode.entries()) };
    seen.letters = 0;
    seen.trimmed = 0;
    seen.byStream.clear();
    seen.byCode.clear();
    log.debug("Leaving SsfStreams.sweepDeadLetters(). " + out.expired +
              ' expired, ' + out.letters + ' new.');
    return out;
  }

  // ---------------------------------------------------------------------------
  // DEAD STREAMS (2026-09-14).
  //
  // A push stream whose pushes have ALL failed for `ssf.deadStreamTimeoutS` is
  // dead. The state is four members on the record, so it replicates with it:
  //
  //   failingSinceMs   the first failure after the last success; 0 while pushes
  //                    are succeeding
  //   deadSinceMs      when it was declared dead; 0 while it is alive
  //   nextProbeAtMs    when a sweep may next push one dead letter as a probe
  //   deadReason       the failure that pushed it over, for the page
  //
  // It is NOT an SSF status. `enabled`, `paused` and `disabled` are the
  // receiver's and the operator's words with meanings SSF 1.0 section 7.1.2
  // defines, and a transmitter that rewrote one because a receiver was down
  // would tell the receiver it had been paused by somebody. A dead stream is
  // still `enabled`; it is this transmitter that has stopped dialling it.
  // ---------------------------------------------------------------------------
  deadTimeoutMs() {
    const { log, config } = this.deps;
    log.debug("Entering SsfStreams.deadTimeoutMs().");
    const raw = Number(config.value('ssf.deadStreamTimeoutS'));
    log.debug("Leaving SsfStreams.deadTimeoutMs().");
    return Number.isFinite(raw) && raw > 0 ? raw * 1000 : 0;
  }

  isDead(record?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.isDead().");
    log.debug("Leaving SsfStreams.isDead().");
    return !!(record && Number(record.deadSinceMs) > 0);
  }

  // A push failed. Answers `{ declaredDead, moved }`: whether this failure is
  // the one that declared the stream dead, and how many waiting SETs that moved
  // to the dead-letter queue.
  notePushFailure(record?, why?, nowMs?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.notePushFailure(). " + record.stream_id);
    const now = Number(nowMs) || Date.now();
    const timeout = this.deadTimeoutMs();
    if (!(Number(record.failingSinceMs) > 0)) {
      record.failingSinceMs = now;
      // ONE LINE ON THE STREAM'S OWN LOG PER RUN OF FAILURES, not per failure:
      // the failures themselves are the dead letters, each with its reason.
      this.note(record, 'failing', 'Pushes are failing: ' +
           String((why && why.why) || '?') + ' Undeliverable SETs go to the ' +
           'dead-letter queue' + (timeout ?
                                  ', and if nothing is delivered for ' +
           Math.round(timeout / 1000) + 's the stream is declared dead.' :
               '.'));
    }
    if (this.isDead(record) || !timeout ||
        now - record.failingSinceMs < timeout) {
      this.touch(record);
      log.debug("Leaving SsfStreams.notePushFailure(). Not declared dead.");
      return { declaredDead: false, moved: 0 };
    }
    record.deadSinceMs = now;
    record.nextProbeAtMs = now + timeout;
    record.deadReason = String((why && why.why) || '');
    const moved = this.moveQueueToDeadLetters(record, {
      why: 'the stream was declared dead: ' + record.deadReason,
      errorCode: 'STS-SSF-0093' });
    this.note(record, 'dead', 'Declared DEAD after ' +
         Math.round(timeout / 1000) + 's of failed pushes ' +
         '(ssf.deadStreamTimeoutS). Nothing more is pushed to it; ' + moved +
         ' waiting SET(s) and every later one go to its ' +
         'dead-letter queue, and one is pushed as a probe every ' +
         Math.round(timeout / 1000) + 's. Last failure: ' + record.deadReason);
    log.debug("Leaving SsfStreams.notePushFailure(). Declared dead; " + moved +
              ' moved.');
    return { declaredDead: true, moved: moved };
  }

  // A push succeeded. Answers whether that revived a dead stream.
  notePushSuccess(record?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.notePushSuccess(). " + record.stream_id);
    const wasDead = this.isDead(record);
    const wasFailing = Number(record.failingSinceMs) > 0;
    record.failingSinceMs = 0;
    if (!wasDead) {
      if (wasFailing) {
        this.touch(record);
      }
      log.debug("Leaving SsfStreams.notePushSuccess(). It was alive.");
      return false;
    }
    record.deadSinceMs = 0;
    record.nextProbeAtMs = 0;
    record.deadReason = '';
    this.note(record, 'revived', 'A push was delivered, so the stream is ' +
         'alive again and is pushed to as before. Its dead-letter queue is ' +
         'kept for inspection until ssf.deadLetterRetentionS passes.');
    log.debug("Leaving SsfStreams.notePushSuccess(). Revived.");
    return true;
  }

  // An operator reviving a stream by hand. It is alive at once; one more
  // failure before a success does not declare it dead again until the timeout
  // has run out afresh.
  revive(record?, reason?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.revive(). " + record.stream_id);
    if (!this.isDead(record)) {
      log.debug("Leaving SsfStreams.revive(). It is not dead.");
      return false;
    }
    record.deadSinceMs = 0;
    record.nextProbeAtMs = 0;
    record.deadReason = '';
    record.failingSinceMs = 0;
    this.note(record, 'revived', 'Revived by hand' +
         (reason ? ' (' + reason + ')' : '') + '. It is pushed to as before.');
    log.debug("Leaving SsfStreams.revive().");
    return true;
  }

  // A sweep found no dead letter to probe with. HALF-OPEN: the stream is tried
  // again with its next SET, and failingSinceMs is set so that one failure
  // declares it dead again at once rather than after a fresh timeout.
  halfOpen(record?, nowMs?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.halfOpen(). " + record.stream_id);
    const now = Number(nowMs) || Date.now();
    record.deadSinceMs = 0;
    record.nextProbeAtMs = 0;
    record.failingSinceMs = now - this.deadTimeoutMs();
    this.note(record, 'half-open', 'Its dead letters have all expired, so ' +
         'there is nothing to probe with: the next SET will be pushed, and a ' +
         'failure declares the stream dead again at once.');
    log.debug("Leaving SsfStreams.halfOpen().");
  }

  // ONE MORE OF A TYPE HAS BEEN SAID TO THIS STREAM.
  //
  // Called from `transmit()` beside `caep.noteTransmitted()`, and at the same
  // moment for the same reason that function gives: the count is of what this
  // transmitter SAID, so it moves when the SET exists and goes on the queue,
  // before anybody knows whether it will be delivered. A queued event on a poll
  // stream has been said, and counting at delivery would make a poll stream
  // look like a transmitter that never says anything.
  //
  // It counts EVERY type rather than only CAEP's eight — the record belongs to
  // this module and SSF's own two travel on the same streams — and the CAEP
  // report picks out the ones it is about.
  countEvent(record?, uri?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.countEvent(). " + uri);
    if (!record || !uri) {
      log.debug("Leaving SsfStreams.countEvent(). Nothing to count.");
      return;
    }
    if (!record.eventCounts) {
      record.eventCounts = {};
    }
    record.eventCounts[uri] = (record.eventCounts[uri] || 0) + 1;
    this.touch(record);
    log.debug("Leaving SsfStreams.countEvent(). " + record.eventCounts[uri] +
        ' of that ' + 'type.');
  }

  // Whether this store is shared by processes that do not see each other's
  // writes at once: a claim store exists (postgres). LAZY, because this file is
  // a library several tests load alone.
  private sharesAcrossNodes() {
    const { log, loadPersistence } = this.deps;
    log.debug("Entering SsfStreams.sharesAcrossNodes().");
    let shared = false;
    try {
      shared = !!loadPersistence().clusterStore();
    } catch (e) {
      log.debug("Caught in SsfStreams.sharesAcrossNodes(): " + ((e &&
          e.message) || e));
      shared = false;
    }
    log.debug("Leaving SsfStreams.sharesAcrossNodes(). " + shared);
    return shared;
  }

  // RFC 8936's poll. `ack` names what the receiver has now stored, so those
  // come off the queue; `setErrs` names what it REFUSED, and those come off too
  // — a receiver that cannot process an event will not process it next time
  // either, and a transmitter that kept redelivering would poll-loop forever.
  // The error is recorded on the stream so the refusal is visible to a person.
  poll(record?, request?) {
    const { log, iso } = this.deps;
    log.debug("Entering SsfStreams.poll(). " + record.stream_id);
    const asked = (request && typeof request === 'object') ? request : {};
    record.counters.pollCalls += 1;
    const acks = Array.isArray(asked.ack) ? asked.ack.map(String) : [];
    const errs = (asked.setErrs && typeof asked.setErrs === 'object')
      ? asked.setErrs : {};
    acks.forEach((jti) => {
      if (this.dequeue(record, jti)) {
        record.counters.acknowledged += 1;
      }
    });
    Object.keys(errs).forEach((jti) => {
      const problem = errs[jti] || {};
      this.dequeue(record, jti);
      record.counters.receiverErrors += 1;
      this.note(record, 'error', 'The receiver REFUSED ' + jti + ': ' +
           String(problem.err || '(no err)') + ' — ' +
           String(problem.description || '(no description)') + '. It is off ' +
           'the queue: a receiver that could not process an event will not ' +
           'process it next time either, and redelivering would poll-loop.');
    });
    this.touch(record);

    if (record.status !== 'enabled') {
      log.debug("Leaving SsfStreams.poll(). The stream is " + record.status +
                '.');
      return { sets: {}, moreAvailable: false, status: record.status };
    }

    const cap = this.limit('ssf.pollMaxEvents', 20);
    const wanted = Number(asked.maxEvents);
    const take = (Number.isFinite(wanted) && wanted >= 0)
      ? Math.min(wanted, cap) : cap;
    const sets = {};
    const waiting = this.queueOf(record);
    const shared = this.sharesAcrossNodes();
    waiting.slice(0, take).forEach((one) => {
      sets[one.jti] = one.token;
      // THE FIRST DELIVERY IS WRITTEN AND A REDELIVERY IS NOT. `deliveredAt` is
      // when the receiver was first handed it, and the row is re-set only then:
      // a write of a SET's row is the one thing that could put back a SET
      // another worker has just deleted on an acknowledgement, so a poll that
      // hands out what it already handed out changes nothing and writes
      // nothing.
      //
      // **AND ON A STORE SHARED BY SEVERAL NODES IT IS NOT WRITTEN AT ALL
      // (2026-09-14, #46).** "Just deleted" is a replication interval between
      // two workers and a CONCURRENT acknowledgement between two nodes: a poll
      // on B handing out a SET for the first time while the receiver's ack of
      // it commits on A writes the row back after the delete, and the SET is
      // queued again for ever — until it is acknowledged a second time. So
      // there the mark stays in this process's memory: `deliveredAt` is what
      // this node saw, and `counters.delivered` may count one SET once per node
      // that first handed it out, which is a number on a page. What is never
      // done is resurrect an acknowledged SET.
      if (!one.counted) {
        one.counted = true;
        one.deliveredAt = iso();
        record.counters.delivered += 1;
        if (!shared) {
          queued.set(this.queueKey(record.stream_id, one.jti), one);
        }
      }
    });
    const more = waiting.length > take;
    this.touch(record);
    log.debug("Leaving SsfStreams.poll(). " + Object.keys(sets).length +
              ' set(s), more=' + more);
    return { sets: sets, moreAvailable: more, status: record.status };
  }

  // One line on a stream's own log, which is what the console draws. Capped for
  // the reason the queue is: a stream nobody deletes would otherwise grow
  // without bound in a process that never restarts.
  note(record?, kind?, text?) {
    const { log, iso } = this.deps;
    log.debug("Entering SsfStreams.note(). " + kind);
    record.log.push({ at: iso(), kind: kind, text: String(text) });
    const max = this.limit('ssf.maxStreamLogEntries', 200);
    if (record.log.length > max) {
      record.log.splice(0, record.log.length - max);
    }
    this.touch(record);
    log.debug("Leaving SsfStreams.note().");
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS SERVICE HAS RECEIVED, when the roles are the other way round.
  //
  // The debugger can be a TRANSMITTER, and something has to be at the far end
  // of its push. `POST /ssf/receive` is that, and this is where what arrives is
  // kept — so a person can see, on `/admin/ssf`, that the thing they sent
  // actually landed. It is deliberately NOT a stream: nothing was configured,
  // nothing is delivered onwards, and treating it as one would invite the
  // question of which stream a bare SET belongs to, which has no answer.
  // ---------------------------------------------------------------------------
  recordReceived(entry?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.recordReceived().");
    const list = received;
    list.push(entry);
    const max = this.limit('ssf.maxReceivedEvents', 200);
    if (list.length > max) {
      list.splice(0, list.length - max);
    }
    log.debug("Leaving SsfStreams.recordReceived(). " + list.length + ' held.');
    return entry;
  }

  // EVERY PROCESS'S, NOT ONLY THIS ONE'S (2026-09-18). `received` is
  // `merge: 'own'`, so what another node or request worker received — or this
  // node before a restart that could not take its old origin back — reaches
  // this process as a contribution, and a list of this process's alone showed
  // a push that landed on the other node as never having arrived. Oldest
  // first, as the list always was, and bounded by the same setting.
  listReceived() {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.listReceived().");
    let all: any[] = received.slice();
    replication.remoteRows('ssf_streams.received', undefined, '')
      .forEach(function (theirs: unknown): void {
        if (Array.isArray(theirs)) {
          all = all.concat(theirs);
        }
      });
    all.sort(function (a: any, b: any): number {
      return String((a && a.at) || '').localeCompare(String((b && b.at) || ''));
    });
    const max = this.limit('ssf.maxReceivedEvents', 200);
    const out = all.length > max ? all.slice(all.length - max) : all;
    log.debug("Leaving SsfStreams.listReceived(). " + out.length + '.');
    return out;
  }

  // THIS PROCESS'S list only: another process's contribution is its row in
  // the store, and it clears its own when asked there. A clear answered by one
  // node of several therefore leaves what the others received on the page.
  clearReceived() {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.clearReceived().");
    const list = received;
    const gone = list.length;
    list.length = 0;
    log.debug("Leaving SsfStreams.clearReceived(). " + gone + ' dropped.');
    return gone;
  }

  // The wire form of a stream configuration — what a receiver gets back from
  // the management API. It is NOT the record: `subjects`, the queue, the log
  // and the counters are this service's own bookkeeping and no member of SSF
  // 1.0's Stream Configuration, so sending them would be inventing members a
  // receiver might come to depend on.
  streamConfiguration(record?, options?) {
    const { log } = this.deps;
    log.debug("Entering SsfStreams.streamConfiguration(). " + record.stream_id);
    const settings = options || {};
    const delivery: StreamDelivery = { method: record.delivery.method };
    if (record.delivery.method === DELIVERY_PUSH) {
      delivery.endpoint_url = record.delivery.endpoint_url;
      if (record.delivery.authorization_header && settings.includeSecrets) {
        // ONLY back to the receiver that set it, and never on a console page or
        // in the management API's listing: it is a credential belonging to
        // somebody else's endpoint. `includeSecrets` is set by exactly one
        // caller for that reason.
        delivery.authorization_header = record.delivery.authorization_header;
      }
    } else {
      delivery.endpoint_url = settings.pollEndpoint || '';
    }
    const out = {
      stream_id: record.stream_id,
      iss: record.iss,
      aud: record.aud,
      events_supported: record.events_supported,
      events_requested: record.events_requested,
      // What this stream would be sent NOW: an owner's ssfAllowedEvents
      // tightened after agreement narrows it here too, so a receiver reading
      // its own configuration is told what delivery will actually do.
      events_delivered: this.effectiveDelivered(record),
      delivery: delivery,
      min_verification_interval: record.min_verification_interval,
      format: record.format,
      description: record.description
    };
    log.debug("Leaving SsfStreams.streamConfiguration().");
    return out;
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): SsfStreamsDeps {
    helpers.log.debug("Entering SsfStreams.defaultDeps().");
    helpers.log.debug("Leaving SsfStreams.defaultDeps().");
    return {
      log: helpers.log,
      randomId: helpers.randomId,
      iso: helpers.iso,
      config: config,
      errorCodes: errorCodes,
      realms: realms,
      subjects: subjects,
      events: events,
      loadApplications: function (): ApplicationsReader {
        return require('../common/applications');
      },
      loadPersistence: function (): PersistenceReader {
        return require('../persistence/persistence');
      }
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SsfStreams>(
  'ssf/ssf_streams',
  () => new SsfStreams(SsfStreams.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  SsfStreams: SsfStreams,
  installInstance: (instance: SsfStreams): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  setSubjectScope: slot.forward('setSubjectScope'),
  DELIVERY_PUSH: DELIVERY_PUSH,
  DELIVERY_POLL: DELIVERY_POLL,
  DELIVERY_METHODS: DELIVERY_METHODS,
  offeredDeliveryMethods: slot.forward('offeredDeliveryMethods'),
  deliveryName: slot.forward('deliveryName'),
  createStream: slot.forward('createStream'),
  getStream: slot.forward('getStream'),
  listStreams: slot.forward('listStreams'),
  updateStream: slot.forward('updateStream'),
  removeStream: slot.forward('removeStream'),
  setStatus: slot.forward('setStatus'),
  addSubject: slot.forward('addSubject'),
  removeSubject: slot.forward('removeSubject'),
  streamCoversSubject: slot.forward('streamCoversSubject'),
  allowedEventsFor: slot.forward('allowedEventsFor'),
  deliversEvent: slot.forward('deliversEvent'),
  effectiveDelivered: slot.forward('effectiveDelivered'),
  enqueue: slot.forward('enqueue'),
  queueOf: slot.forward('queueOf'),
  dequeue: slot.forward('dequeue'),
  deadLettersOf: slot.forward('deadLettersOf'),
  allDeadLetters: slot.forward('allDeadLetters'),
  deadTimeoutMs: slot.forward('deadTimeoutMs'),
  addDeadLetter: slot.forward('addDeadLetter'),
  removeDeadLetter: slot.forward('removeDeadLetter'),
  clearDeadLettersFor: slot.forward('clearDeadLettersFor'),
  sweepDeadLetters: slot.forward('sweepDeadLetters'),
  isDead: slot.forward('isDead'),
  notePushFailure: slot.forward('notePushFailure'),
  notePushSuccess: slot.forward('notePushSuccess'),
  revive: slot.forward('revive'),
  halfOpen: slot.forward('halfOpen'),
  touch: slot.forward('touch'),
  liveRecord: slot.forward('liveRecord'),
  countEvent: slot.forward('countEvent'),
  poll: slot.forward('poll'),
  note: slot.forward('note'),
  recordReceived: slot.forward('recordReceived'),
  listReceived: slot.forward('listReceived'),
  clearReceived: slot.forward('clearReceived'),
  streamConfiguration: slot.forward('streamConfiguration')
};
