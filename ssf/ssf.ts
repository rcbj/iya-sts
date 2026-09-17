'use strict';
//
// File: ssf.ts
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS FRAMEWORK (OpenID SSF 1.0, final 2 September 2025), AND
// THE FOUR IETF SPECIFICATIONS IT IS ASSEMBLED FROM.
//
// The seventeenth protocol family here, and the first one that TALKS BACK.
// Every other family in this service answers a request; this one delivers an
// event nobody asked for, at the moment it happens, to somebody who agreed in
// advance to be told.
//
// THE PROBLEM IT SOLVES, because it is not obvious from the endpoints. SAML
// and OpenID Connect authenticate at ONE INSTANT. After that the relying party
// holds a session or a token that stays good for its lifetime — often hours —
// whatever happens next. Fire somebody at ten and their session works until
// the token expires. Shortening lifetimes trades security for load and
// friction; Shared Signals inverts it, and the identity provider says when
// something changed.
//
// **SSF IS THE PIPE AND NOT THE VOCABULARY**, which is the single most
// important thing to know before reading this file. It defines how two parties
// agree a stream, who the events are about (RFC 9493 subject identifiers), what
// they travel in (RFC 8417 Security Event Tokens) and how they get there (RFC
// 8935 push, RFC 8936 poll) — and it defines exactly TWO events of its own,
// both about the pipe. The vocabularies are CAEP (what happened to a session)
// and RISC (what happened to an account), and they are the second and third
// parts of this work. **Everything in this directory is written so that adding
// one is rows in `ssf_events.js`'s table and nothing else**: the envelope, the
// subject grammar, the delivery, the queues, the stream management and the
// console are all vocabulary-independent, and a design that made any of them
// specific to the two rows there would have to be undone twice.
//
// ---------------------------------------------------------------------------
// THE ENDPOINTS, AND WHY THE PATHS ARE THIS SERVICE'S CHOICE.
//
// SSF publishes every endpoint in its configuration metadata rather than
// fixing a path, so a receiver DISCOVERS them and none of these names is
// normative:
//
//   GET  /.well-known/ssf-configuration   the transmitter's metadata. NEVER
//                                         gated — a receiver has to read what
//                                         the endpoints are before it can
//                                         authenticate to one.
//   GET  /ssf                             a page about this family. Not an
//                                         SSF endpoint; a real transmitter
//                                         publishes nothing like it.
//   POST/GET/PATCH/PUT/DELETE /ssf/stream the stream management API
//   GET/POST /ssf/status                  read and set a stream's status
//   POST /ssf/subjects/add                add a subject
//   POST /ssf/subjects/remove             remove one
//   POST /ssf/verify                      ask for a verification event
//   POST /ssf/poll                        RFC 8936 delivery
//   POST /ssf/receive                     THE ROLES REVERSED: a SET pushed AT
//                                         this service, so the debugger can be
//                                         the transmitter
//   GET  /ssf/received                    what has arrived that way
//
// **THE SUBJECT PATHS USE A SLASH AND NOT A COLON.** SSF's own examples write
// `/subjects:add`, and express reads `:add` as a ROUTE PARAMETER — so a route
// registered that way matches `/ssf/subjectsANYTHING` and matches the literal
// path only by accident. The metadata publishes what is actually registered,
// which is what a receiver reads, so nothing about this is visible on the
// wire; it is written down because the next person to "fix" the paths will
// reach for the colon.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS IN THE REQUIRE ORDER, WHICH IS A DEPENDENCY AND NOT A
// PREFERENCE.
//
// **After `oauth-oidc/oauth2.ts`**, transitively: `ssf_auth.ts` requires
// `oauth-oidc/dpop.ts` for `presentedAccessToken()`, and although that module
// registers no route it is loaded by oauth2.js anyway — requiring it first
// from here would be harmless, and requiring it first is not what decides the
// line. **After `admin-ui/admin.ts`**, which is what does: the console page
// and the settings block come from that module, exactly as `scim.js`'s do.
// Until #50's R1 requiring it earlier would have dragged every `/admin` route
// ahead of the protocol endpoints; requiring it registers nothing now, and
// the ROUTE half of this constraint is the order of the `register()` calls in
// `common/protocol_stack.ts`, where this module's come after the console's.
// The LOAD half stands: the slots this file fills must exist when it runs.
// **Before `sts_metadata.js`**, which is last for everybody.
//
// It is NOT one of the inverted hooks (rule 3e). Both directions were tested,
// as that rule requires: there is no cycle — `admin.js` knows nothing about
// SSF — and no route moves: `/admin` was already registered by the time this
// file was read, and since #50's R1 no require registers a route of a
// converted module at all. So it is a plain require.
//
// ---------------------------------------------------------------------------
// WHAT THIS FAMILY DELIBERATELY DOES NOT DO.
//
// **IT DOES NOT RETRY A FAILED PUSH BY DEFAULT.** RFC 8935 permits it;
// `ssf_http.ts` argues at length why a mock must not, and `ssf.pushRetries`
// (0 by default) is the deployment's way to ask. A client that answers 500 to
// the first push and 202 to the second would look, from its own logs, like a
// client that works.
//
// ~~IT GENERATES NO EVENT ON ITS OWN.~~ **It does since CAEP (2026-09-03)
// and RISC**: SSF defines no event about a session or an account, so the
// vocabularies are what let this transmitter emit on a sign-in, a sign-out
// or a directory change (`caep.autoEmit`, `risc.autoEmit`). The SSF pipe
// itself still emits only what was asked for — `/ssf/verify`, `/admin/ssf`
// or the management API. `ssf/CLAUDE.md`, *What this family deliberately
// does not do*, has the history.
//
// **IT VERIFIES NOTHING ABOUT A SUBJECT.** A stream may name a person who has
// never been here, and this service will happily transmit about them. That is
// the same posture as everywhere else — see the front page — and it is what a
// receiver's "I do not know this subject" path needs.
//
// **A `verified: true` ON AN ADD SUBJECT REQUEST IS RECORDED AND BELIEVED.**
// SSF lets a receiver say it has already confirmed the subject is one it cares
// about, and a real transmitter may then skip a confirmation step. There is no
// confirmation step here to skip, so the member is kept and shown and refuses
// nothing.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape:
//
//   * **`SharedSignals` TAKES EVERY MODULE IT USES THROUGH ITS CONSTRUCTOR**
//     (`SharedSignalsDeps`): the shared express app, the helpers and the
//     logger, the settings, the realm registry, the registers, the console
//     (for its three slots), `authn` and the directory (for their observers),
//     and the eleven `ssf/` libraries. The family's own libraries are typed as
//     `typeof` their modules, so this file checks the same whether each of them
//     is JavaScript or TypeScript. `cluster/cluster_capabilities.js` arrives as
//     a LOADER, because the original required it part way down the file and
//     the instance still does, at the same point.
//   * **`registerRoutes(app)` HOLDS EVERY ROUTE, IN THE ORIGINAL ORDER**, and
//     `installHooks()` the five things this file hands to other modules at
//     require time — the console's signals, CAEP and RISC slots, `authn`'s
//     session observer and the directory's account observer — in the order the
//     original filled them.
//   * **THE COMPOSITION ROOT BUILDS THE INSTANCE (#50, R2)**:
//     `common/protocol_stack.ts` builds `SharedSignals` from `defaultDeps()`
//     and installs it, and the module's old names are FACADES that forward
//     to it, for the JavaScript callers. The `wire` step runs what loading
//     the module used to do with its instance, in the original's order:
//     schedules the dead-letter sweep, provides `ssf.delivery`, installs the
//     hooks and seeds this service's own two receivers. It does NOT register
//     the routes (#50, R1): the root calls `registerRoutes(app)` at the point
//     in the route order where requiring this module used to register them —
//     so the route order and every other load-time effect are what they
//     were. A process that loads this module without the root builds a
//     default instance, wired the same way, when the module loads.
//   * **THE DEAD-LETTER SWEEP'S TIMER STAYS A MODULE-LEVEL `let`**, as it was:
//     one per process, whatever builds the class.
// ---------------------------------------------------------------------------

import app = require('../common/app');
// `allSigningKeys`, `STS`, node's `crypto` and `common/crypto` left this list
// on 2026-09-10 with the three functions that read a received SET — they are
// `ssf_events.js`'s now, where `buildSet()` and `signSet()` already were. See
// the note above POST /ssf/receive.
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import stats = require('../common/admin_stats');
import audit = require('../common/audit');
import applications = require('../common/applications');
import adminConsole = require('../admin-ui/admin');
import authn = require('../authn/authn');
import subjects = require('./ssf_subjects');
import events = require('./ssf_events');
// The CAEP session register. A LIBRARY, and the require goes THIS WAY ONLY:
// that module holds the register and answers what an event WOULD be, and this
// one holds transmit(), the streams and the deliveries and therefore decides
// where it goes. A require the other way would be a cycle. See its header.
import caep = require('./caep');
// The RISC account register, on the same terms and for the same reason: it
// holds the register and answers what an event WOULD be, and this file holds
// transmit(), the streams and the deliveries and therefore decides where it
// goes. See its header.
import risc = require('./risc');
// THE DIRECTORY, for the account observer alone. The require goes in the
// ORDINARY direction — `common/protocol_stack.ts` loads ldap/ldap_server.js
// at 21 and this file at 23b — so it moves no route and closes no cycle, and
// rule 3e's test therefore asks for no slot. `scim/scim.ts` requires it the
// same way. What travels back the other direction is one function: see
// riscAutoEmit().
import directory = require('../ldap/ldap_server');
import streams = require('./ssf_streams');
// THIS SERVICE'S OWN TWO RECEIVERS. A LIBRARY (rule 3) — the two receive
// endpoints and the two inbox pages are registered by the SURFACES, because a
// receiver hosts its own endpoint; what this module does with it is SEED the
// streams, which is why the require is here and not only there. A process that
// loaded `admin-ui/admin.ts` and not this file would have an inbox page and no
// stream behind it, and the page says exactly that rather than looking empty.
import receivers = require('./ssf_receivers');
import transport = require('./ssf_http');
// What the dead-letter queues hold, counted, for Monitoring → Shared Signals →
// Dead letters. A LIBRARY (rule 3) that registers nothing; the sweep below
// tells it what each sweep found, and the console slot hands its report out.
import deadLetterReport = require('./ssf_dead_letter_report');
import ssfAuth = require('./ssf_auth');
// SEVERAL NODES (2026-09-14, #46 section 6): one report per stream health
// transition, one prober for the cluster, and a GNAP key proof spent across
// every node before the gate reads it. A LIBRARY; see its header.
import ssfCluster = require('./ssf_cluster');
// The error-code registry, a LEAF. An HTTP refusal is marked on the response
// (the call-log funnel records it); a refusal with no response of its own — a
// transmission, a console action, an automatic emission — is an audit row.
import errorCodes = require('../common/error_codes');

// A loose JSON-shaped object: the reports, stream records and results this
// file builds and passes on. Their shapes are the libraries' own, and those
// libraries are being typed one at a time (#50), so this stays `any` rather
// than a shape that a newly typed library would then fail to match.
type Json = any;

// The express request and response, as far as this file reads them.
type Req = any;
type Res = any;

// What `transmit()` answers. It never rejects.
interface TransmitReport {
  ok: boolean;
  delivered: boolean;
  jti: string;
  why?: string;
  [member: string]: any;
}

// What every automatic emission answers. It never rejects either.
interface EmitResult {
  sent: number;
  streams: number;
  why?: string;
  [member: string]: any;
}

// The part of `cluster/cluster_capabilities.js` this file uses.
interface Capabilities {
  provide(name: string): void;
}

interface SharedSignalsDeps {
  app: typeof app;
  log: typeof helpers.log;
  helpers: typeof helpers;
  config: typeof config;
  realms: typeof realms;
  // Not read here: required for the order it was always required in.
  stats: typeof stats;
  audit: typeof audit;
  applications: typeof applications;
  adminConsole: typeof adminConsole;
  authn: typeof authn;
  subjects: typeof subjects;
  events: typeof events;
  caep: typeof caep;
  risc: typeof risc;
  directory: typeof directory;
  streams: typeof streams;
  receivers: typeof receivers;
  transport: typeof transport;
  deadLetterReport: typeof deadLetterReport;
  ssfAuth: typeof ssfAuth;
  ssfCluster: typeof ssfCluster;
  errorCodes: typeof errorCodes;
  // `cluster/cluster_capabilities.js`, required when `provideCapability()`
  // runs — which is where the original required it.
  loadCapabilities(): Capabilities;
}

// The dead-letter sweep's timer: one per process. See scheduleSweep().
let sweepTimer = null;

class SharedSignals {
  // The well-known suffix RFC 8414's registry carries for this document. It
  // is `ssf-configuration` and NOT `ssf-configuration.json`, and not under
  // `/openid-configuration` either — a receiver fetches this exact path.
  static readonly WELL_KNOWN = '/.well-known/ssf-configuration';

  // The six actions of the signals slot; see consoleAction().
  static readonly CONSOLE_ACTIONS: string[] = ['status', 'delete', 'transmit',
    'clear-received', 'revive', 'clear-dead-letters'];

  // The three actions of the CAEP slot; see caepAction().
  static readonly CAEP_CONSOLE_ACTIONS: string[] = ['emit', 'reset-session',
                                                    'clear'];

  // The three actions of the RISC slot; see riscAction().
  static readonly RISC_CONSOLE_ACTIONS: string[] = ['emit', 'reset-account',
                                                    'clear'];

  constructor(private readonly deps: SharedSignalsDeps) {
    deps.log.debug('Entering SharedSignals.constructor().');
    deps.log.debug('Leaving SharedSignals.constructor().');
  }

  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug('Entering SharedSignals.enabled().');
    const on = config.value('ssf.enabled') !== false;
    log.debug('Leaving SharedSignals.enabled(). ' + on);
    return on;
  }

  // The `iss` of this transmitter. Empty configuration means this realm's base
  // URL, which is the right answer almost always — see ssf.issuer.
  //
  // -------------------------------------------------------------------------
  // **THREE FIXES ON 2026-09-12, AND THE FIRST WAS WRONG IN EVERY REALM BUT
  // THE DEFAULT ONE.**
  //
  //   1. `baseUrlOf()` ALREADY carries the realm prefix — that one line is why
  //      eighty call sites are realm-aware — and this appended it again. So in
  //      `acme` the issuer was `…/realm/acme/realm/acme`, as were the
  //      configuration, status, subject and verification endpoints and the
  //      `jwks_uri`: a receiver discovering an acme stream dialled URLs that
  //      do not exist, and matched every SET's `iss` against a string no SET
  //      carried. The default realm's prefix is empty, which is why nothing
  //      noticed.
  //   2. With no request — the CAEP expiry sweep runs on a timer — the base
  //      was `baseUrlOf(null)`, which is `http://localhost:<port>` whatever the
  //      listener speaks. `transport.ownBaseUrl()` is the same base computed
  //      honestly: `global.publicBaseUrl`, or the loopback origin in the right
  //      scheme.
  //   3. **A CONFIGURED `ssf.issuer` IS PER REALM.** It was returned verbatim
  //      in every realm, so two realms of one process transmitted under ONE
  //      issuer — two transmitters claiming one name, which a receiver
  //      matching `iss` against the issuer it discovered is entitled to treat
  //      as one. Now: a value the REALM carries is used as it stands (an
  //      operator who set it there meant exactly that string), and a
  //      PROCESS-WIDE value is given the realm's prefix, the way `baseUrlOf()`
  //      gives it to the base. It is not in `realms.js`'s NAMED_BY_REALM,
  //      which seeds a value when a realm is created: that would miss every
  //      realm created before the setting was pinned, and an issuer is a URL
  //      whose realm form this service already defines — the prefix — so
  //      deriving it here is the one answer that cannot go stale.
  // -------------------------------------------------------------------------
  //
  // The computation is `ssf_http.ts`'s `transmitterIssuer()`, because
  // `ssf_receivers.ts` needs the same answer for a seeded stream and cannot
  // require this file (this file requires it).
  private issuerFor(req: Req): string {
    const { log, transport } = this.deps;
    log.debug('Entering SharedSignals.issuerFor().');
    const value = transport.transmitterIssuer(req);
    log.debug('Leaving SharedSignals.issuerFor(). ' + value);
    return value;
  }

  private ssfBase(req: Req): string {
    const { log } = this.deps;
    const { baseUrlOf } = this.deps.helpers;
    log.debug('Entering SharedSignals.ssfBase().');
    const value = baseUrlOf(req) + '/ssf';
    log.debug('Leaving SharedSignals.ssfBase(). ' + value);
    return value;
  }

  private criticalMembers(): string[] {
    const { log, config, subjects } = this.deps;
    log.debug('Entering SharedSignals.criticalMembers().');
    const asked = config.value('ssf.criticalSubjectMembers');
    const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
    const out = list.map(function (one) {
      return String(one).trim();
    }).filter(function (name) {
      if (!name) {
        return false;
      }
      if (subjects.COMPLEX_MEMBER_NAMES.indexOf(name) < 0) {
        log.warn('ssf.criticalSubjectMembers names "' + name + '", which is ' +
                 'not one of the six complex subject members SSF defines. It ' +
                 'is not published — a critical member a receiver cannot ' +
                 'recognise would make every complex subject refusable.');
        return false;
      }
      return true;
    });
    log.debug('Leaving SharedSignals.criticalMembers(). ' + out.length + '.');
    return out;
  }

  // -------------------------------------------------------------------------
  // THE REFUSAL SHAPE.
  //
  // RFC 8935 section 2.4 gives `{err, description}` and this family uses it
  // for every refusal on every endpoint, not only on a push — one document a
  // receiver learns once. The err values are the SET Error Codes registry's:
  // `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`,
  // `authentication_failed`, `access_denied`.
  // -------------------------------------------------------------------------
  // error-code: none — the helper itself; every caller marks its own code.
  private fail(res: Res, status: number, err: string, description: string,
               headers?: Json): void {
    const { log } = this.deps;
    log.debug('Entering SharedSignals.fail(). ' + status + ' ' + err);
    const extra = headers || {};
    Object.keys(extra).forEach(function (name) {
      res.set(name, extra[name]);
    });
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify({ err: err, description: description }, null, 2));
    log.debug('Leaving SharedSignals.fail().');
  }

  // Answers 501 rather than 404 when the family is switched off: the feature
  // is off, the URL is not wrong, and those are different sentences to a
  // client.
  private offCheck(res: Res): boolean {
    const { log, errorCodes } = this.deps;
    log.debug('Entering SharedSignals.offCheck().');
    if (this.enabled()) {
      log.debug('Leaving SharedSignals.offCheck(). On.');
      return false;
    }
    errorCodes.mark(res, 'STS-SSF-0001');
    this.fail(res, 501, 'invalid_request',
      'The Shared Signals Framework is turned off on this service ' +
      '(ssf.enabled). The routes stay registered and answer 501 rather than ' +
      '404, because the feature being off and the URL being wrong are ' +
      'different sentences to a client. ' + SharedSignals.WELL_KNOWN +
      ' still answers, so a receiver can discover that this service speaks ' +
      'SSF and is not currently doing it.');
    log.debug('Leaving SharedSignals.offCheck(). Off.');
    return true;
  }

  // The credential check every protected endpoint makes. Returns the
  // decision, or null having already answered.
  private gate(req: Req, res: Res, need: string): Json | null {
    const { log, ssfAuth, errorCodes } = this.deps;
    log.debug('Entering SharedSignals.gate(). need=' + need);
    const decision: Json = ssfAuth.authenticate(req, need);
    if (decision.ok) {
      log.debug('Leaving SharedSignals.gate(). Allowed.');
      return decision;
    }
    // The code was chosen where the condition was decided, in ssf_auth.ts.
    errorCodes.mark(res, decision.errorCode || 'STS-SSF-0010');
    this.fail(res, decision.status, decision.err, decision.description,
              decision.headers);
    log.debug('Leaving SharedSignals.gate(). Refused.');
    return null;
  }

  private jsonBody(req: Req): Json | null {
    const { log } = this.deps;
    log.debug('Entering SharedSignals.jsonBody().');
    const raw = req.body;
    if (raw && typeof raw === 'object' && !Buffer.isBuffer(raw)) {
      log.debug('Leaving SharedSignals.jsonBody(). Already parsed.');
      return raw;
    }
    const text = Buffer.isBuffer(raw) ? raw.toString('utf8')
      : String(raw == null ? '' : raw);
    if (!text.trim()) {
      log.debug('Leaving SharedSignals.jsonBody(). Empty.');
      return {};
    }
    try {
      const parsed = JSON.parse(text);
      log.debug('Leaving SharedSignals.jsonBody(). Parsed.');
      return (parsed && typeof parsed === 'object') ? parsed : {};
    } catch (e) {
      log.debug("Caught in SharedSignals.jsonBody(): " +
                ((e && e.message) || e));
      // Not JSON. The caller reports it as a refusal naming the body rather
      // than throwing, because a 500 on a malformed body tells a client
      // nothing about what it sent.
      log.debug('Leaving SharedSignals.jsonBody(). Not JSON.');
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // TRANSMIT ONE EVENT ON ONE STREAM.
  //
  // The one path both delivery methods take, which is what makes a failed
  // push recoverable: the SET is built, signed, queued, and only THEN — for a
  // push stream — taken off the queue and posted. A push implementation that
  // signed and posted in one breath would lose the event on the first refused
  // connection with nothing to show for it.
  //
  // Returns a promise of a report; it never rejects, because two of its three
  // callers are answering an HTTP request that must not become a 500 over a
  // receiver being down.
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // A TRANSMISSION THAT DID NOT HAPPEN, RECORDED.
  //
  // transmit() answers with a report and never with a response — two of its
  // callers are answering an HTTP request and the third is an automatic
  // emission nobody is waiting on — so the refusal is an AUDIT ROW, one per
  // stream it was refused on, carrying the condition's code. Returns the
  // report unchanged, so a caller's `return` is exactly what it was. The `why`
  // is this service's own sentence about a stream and an event type; it
  // carries no credential and no token.
  // -------------------------------------------------------------------------
  private transmitRefused(code: string, record: Json, uri: string,
                          report: TransmitReport,
                          outcome?: string): TransmitReport {
    const { log, audit, events } = this.deps;
    log.debug('Entering SharedSignals.transmitRefused(). ' + code);
    audit.failure(code, {
      protocol: 'SSF', channel: 'http',
      target: String((record && record.stream_id) || ''),
      outcome: outcome || 'refused',
      summary: 'A ' + ((events.EVENT_BY_URI[uri] || {}).name || 'Security ' +
        'Event Token') + ' was not transmitted on ' +
        String((record && record.stream_id) || 'a stream'),
      detail: { type: String(uri || ''),
                why: String((report || {} as Json).why || '') }
    });
    log.debug('Leaving SharedSignals.transmitRefused().');
    return report;
  }

  transmit(record: Json, options?: Json): Promise<TransmitReport> {
    const { log, audit, events, streams, subjects, transport,
            errorCodes } = this.deps;
    const { iso } = this.deps.helpers;
    log.debug('Entering SharedSignals.transmit(). ' + record.stream_id);
    const asked = options || {};
    const uri = String(asked.uri || '');
    if (record.events_delivered.indexOf(uri) < 0) {
      log.debug('Leaving SharedSignals.transmit(). Not an agreed type.');
      return Promise.resolve(this.transmitRefused('STS-SSF-0026', record, uri,
        {
          ok: false, delivered: false, jti: '',
          why: 'This stream does not deliver "' + uri + '". It delivers ' +
               (record.events_delivered.length
                 ? record.events_delivered.join(', ')
                 : 'nothing at all') + ' — the intersection of what the ' +
               'receiver requested and what this transmitter supports.' }));
    }
    // THE OWNER'S ENTRY, asked at the moment of delivery rather than only when
    // the stream was agreed — see ssf_streams.ts's allowedEventsFor().
    if (!streams.deliversEvent(record, uri)) {
      log.debug('Leaving SharedSignals.transmit(). Not allowed by the ' +
                'owning application.');
      return Promise.resolve(this.transmitRefused('STS-SSF-0081', record, uri,
        {
          ok: false, delivered: false, jti: '',
          why: 'The application that owns this stream ("' +
               record.createdBy + '") ' +
               'is not allowed ' +
               '"' + uri + '": ssfAllowedEvents on its entry does not ' +
               'name it or its profile. Add it there, or ask for an event ' +
               'type it does allow.' }));
    }
    const verdict: Json = events.validateEvent(uri, asked.payload);
    if (!verdict.ok) {
      log.debug('Leaving SharedSignals.transmit(). The payload is invalid.');
      return Promise.resolve(this.transmitRefused('STS-SSF-0027', record, uri,
        {
          ok: false, delivered: false, jti: '',
          why: verdict.errors.join(' ') }));
    }
    // -----------------------------------------------------------------------
    // AN EVENT WHOSE ROW SAYS IT MUST NAME SOMEBODY, THAT NAMES NOBODY.
    //
    // Every CAEP event is `subject: 'required'` and SSF's own two are
    // `subject: 'none'` — they are about the STREAM, and a receiver that
    // insisted on a subject could not be verified. So this is a check on the
    // ROW rather than a branch naming a vocabulary, which is what keeps
    // `ssf_events.js`'s promise: RISC's rows are `required` too, and adding
    // them did not change this line.
    //
    // It is refused rather than carried because of what the omission MEANS. A
    // session-revoked with no `sub_id` says a session was revoked and does not
    // say whose; a receiver cannot act on it and cannot report anything useful
    // about it, so it is dropped at the far end with no error anybody sees —
    // which is the failure this whole family exists to make visible.
    // -----------------------------------------------------------------------
    const row: Json = events.EVENT_BY_URI[uri];
    if (row && row.subject === 'required' && !asked.subject) {
      log.debug('Leaving SharedSignals.transmit(). No subject on an event ' +
                'that needs one.');
      return Promise.resolve(this.transmitRefused('STS-SSF-0028', record, uri,
        {
          ok: false, delivered: false, jti: '',
          why: '"' + uri + '" must carry a subject and this one carries ' +
               'none. A ' + row.name + ' with no sub_id says something ' +
               'happened and does not say to whom, so a receiver drops it ' +
               'with no error anybody sees. CAEP\'s subject is normally ' +
               'SSF\'s COMPLEX one — the person is not revoked, one session ' +
               'of theirs is.' }));
    }
    // AND THE OTHER KIND OF WRONG SUBJECT, WHICH IS A WARNING RATHER THAN A
    // REFUSAL. The refusal above is MECHANICAL — an event with no subject can
    // be matched against no stream, so it goes to nobody or to everybody and
    // neither is what was meant. This one is a CONFORMANCE opinion: RISC's two
    // identifier events say their subject must be an email address or a phone
    // number, and an event carrying an iss_sub pair instead is perfectly
    // deliverable and merely wrong. Refusing to send one would remove the
    // ability to find out what a receiver does with it. See subjectAdvice().
    events.subjectAdvice(uri, asked.subject).forEach(function (note) {
      log.warn('ssf: ' + note);
    });
    if (asked.subject && !streams.streamCoversSubject(record, asked.subject)) {
      log.debug('Leaving SharedSignals.transmit(). Not a subject on this ' +
                'stream.');
      return Promise.resolve(this.transmitRefused('STS-SSF-0029', record, uri,
        {
          ok: false, delivered: false, jti: '',
          why: 'This stream names ' + record.subjects.length +
               ' subject(s) and ' +
               subjects.describeSubject(asked.subject) + ' is not one of ' +
               'them. A stream with an EMPTY list is about everybody or ' +
               'nobody depending on ssf.defaultSubjects, which this ' +
               'transmitter publishes as default_subjects.' }));
    }

    const claims: Json = events.buildSet({
      issuer: record.iss,
      audience: record.aud,
      uri: uri,
      payload: asked.payload || {},
      subject: asked.subject || null,
      txn: asked.txn || '',
      toe: typeof asked.toe === 'number' ? asked.toe : undefined
    });

    // -----------------------------------------------------------------------
    // A DEAD PUSH STREAM IS NOT PUSHED TO, AND ITS SET IS NOT EVEN SIGNED
    // (2026-09-14). See ssf_streams.ts's DEAD STREAMS. The SET goes to the
    // stream's dead-letter queue as its claims — signing a document nothing
    // will receive is the cost this exists to stop, and a probe signs it if it
    // is ever pushed. Nothing is logged here: the sweep's summary line is
    // where an undeliverable SET is counted.
    //
    // **A VERIFICATION EVENT IS PUSHED ANYWAY.** A receiver asking to verify
    // its stream is evidence it is listening again, and the push is the probe
    // it asked for — a success revives the stream.
    // -----------------------------------------------------------------------
    if (record.delivery.method === streams.DELIVERY_PUSH &&
        streams.isDead(record) &&
        uri !== events.SSF_PREFIX + 'verification') {
      streams.addDeadLetter(record, { jti: claims.jti, token: '',
        claims: claims, queuedAt: iso() }, {
        why: 'the stream is dead (ssf.deadStreamTimeoutS); it is not pushed ' +
             'to until a probe or an operator revives it',
        errorCode: 'STS-SSF-0096' });
      log.debug('Leaving SharedSignals.transmit(). The stream is dead; ' +
                'dead-lettered.');
      return Promise.resolve({ ok: false, delivered: false,
        deadLettered: true, jti: claims.jti, claims: claims,
        why: 'This stream is DEAD — its pushes all failed for ' +
             'ssf.deadStreamTimeoutS — so the event was put on its ' +
             'dead-letter queue and not pushed. Revive it on /admin/ssf or ' +
             'with POST /admin-api/ssf/revive.' });
    }

    log.debug("Leaving SharedSignals.transmit().");
    return events.signSet(claims).then((token): TransmitReport |
                                           Promise<TransmitReport> => {
      // THE RECORD HELD NOW, AND NOT THE ONE READ BEFORE THE SIGNATURE.
      // Signing may go to the worker pool and take seconds, and in a service
      // whose request workers share the stream store another process's write
      // can REPLACE this record in the meantime — a PATCH, a pause, a poll's
      // counters. Editing the copy read above and writing it back would undo
      // that write; streams.touch() refuses to, so the edit would be lost
      // instead. See ssf_streams.ts's touch().
      record = streams.liveRecord(record);
      // COUNTED HERE, which is after the SET exists and before anybody knows
      // whether it will be delivered — because what /admin/caep-sessions
      // reports is what this transmitter SAID about a session, and a queued
      // event on a poll stream has been said. Whether it arrived is the
      // stream's own counters, three lines down, and conflating the two would
      // make a poll stream look like a transmitter that never says anything.
      this.deps.caep.noteTransmitted(record, claims);
      // AND THE ACCOUNT REGISTER, on exactly the same terms. Neither call
      // knows about the other and each answers null for an event of the
      // other's vocabulary, which is what keeps this line from being a branch
      // naming a profile — the third vocabulary added a call and changed
      // nothing here.
      this.deps.risc.noteTransmitted(record, claims);
      // AND ON THE STREAM, per type. The line above counts what was said about
      // a SESSION; this counts what was said to a RECEIVER, and neither can be
      // derived from the other — the register keeps the last twenty-five
      // events per session and the stream keeps a total per type. See
      // countEvent().
      streams.countEvent(record, asked.uri);
      const entry = { jti: claims.jti, token: token, claims: claims,
        queuedAt: iso(), deliveredAt: '', counted: false };
      const queued: Json = streams.enqueue(record, entry);
      if (!queued.ok) {
        log.debug('Leaving SharedSignals.transmit(). Not queued.');
        return this.transmitRefused('STS-SSF-0030', record, uri, {
          ok: false, delivered: false, jti: claims.jti, token: token,
          claims: claims,
          why: 'The event was built and signed and NOT queued, because ' +
               queued.reason + '. A disabled stream drops what is waiting; ' +
               'a PAUSED one would have kept this.' });
      }
      audit.audit({ action: 'ssf.event.transmit', category: 'signals',
        protocol: 'SSF', channel: 'http', outcome: 'success',
        target: record.stream_id,
        summary: 'Queued ' + (events.EVENT_BY_URI[uri] || {} as Json).name +
          ' on ' + record.stream_id,
        detail: { jti: claims.jti, type: uri,
          subject: asked.subject
            ? subjects.describeSubject(asked.subject) : '' } });
      if (record.delivery.method !== streams.DELIVERY_PUSH) {
        streams.note(record, 'queued', 'Queued ' + claims.jti +
          ' for the receiver to poll.');
        log.debug('Leaving SharedSignals.transmit(). Queued for poll.');
        return { ok: true, delivered: false, jti: claims.jti, token: token,
          claims: claims,
          why: 'Queued. This is a poll stream, so nothing is sent until the ' +
               'receiver asks at ' + '/ssf/poll.' };
      }
      record.counters.pushCalls += 1;
      // Through the retrying door, which with `ssf.pushRetries` at its default
      // of 0 is exactly one push — see ssf_http.ts.
      return transport.pushSetWithRetries(record.delivery.endpoint_url, token,
        {
          authorizationHeader: record.delivery.authorization_header
        }).then((result: Json): TransmitReport => {
        // The push was a network round trip, so the same reason as above.
        record = streams.liveRecord(record);
        record.lastPushAt = iso();
        if (result.ok) {
          record.counters.delivered += 1;
          entry.counted = true;
          entry.deliveredAt = iso();
          // Off the queue as ONE ROW'S DELETE — see ssf_streams.ts's `queued`.
          streams.dequeue(record, entry.jti);
          record.lastPushError = '';
          streams.note(record, 'push', 'Delivered ' + claims.jti + ' to ' +
            record.delivery.endpoint_url +
            (result.why ? ' — ' + result.why : ''));
          if (streams.notePushSuccess(record)) {
            this.streamRevived(record, 'a push of ' + claims.jti +
                                       ' was delivered');
          }
          log.debug('Leaving SharedSignals.transmit(). Pushed.');
          return { ok: true, delivered: true, jti: claims.jti, token: token,
            claims: claims, status: result.status, why: result.why };
        }
        record.counters.failed += 1;
        record.lastPushError = result.why;
        // -------------------------------------------------------------------
        // UNDELIVERABLE: OFF THE LIVE QUEUE AND ONTO THE DEAD-LETTER QUEUE
        // (2026-09-14), WITH NO LOG LINE AND NO AUDIT ROW OF ITS OWN.
        //
        // It stayed on the live queue "until somebody asks for it again", and
        // nobody did; and every failure wrote an `ssf.event.refused` audit row
        // whose code put a line in the service log — 30,698 of them in one
        // second on the run this was built for, when a sweep of expired
        // sessions revoked 1,398 sessions to twenty dead streams. The dead
        // letter carries the reason, the code and the receiver's status for
        // inspection, and the sweep logs ONE summary line of how many there
        // were. `ssf.pushRetries` has already been spent: a final failure.
        // -------------------------------------------------------------------
        streams.dequeue(record, entry.jti);
        streams.addDeadLetter(record, entry, { why: result.why,
          errorCode: result.errorCode || 'STS-SSF-0032',
          status: result.status });
        const verdict: Json = streams.notePushFailure(record, result);
        if (verdict.declaredDead) {
          this.streamDeclaredDead(record, verdict.moved);
        }
        log.debug('Leaving SharedSignals.transmit(). The push failed; ' +
                  'dead-lettered.');
        return { ok: false, delivered: false, deadLettered: true,
          jti: claims.jti, token: token,
          claims: claims, status: result.status, err: result.err,
          why: result.why };
      });
    }).catch((e): TransmitReport => {
      log.debug('Caught in SharedSignals.transmit(): ' +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SSF-0031') +
                'ssf: a Security Event Token could not be signed: ' +
                e.message);
      log.debug('Leaving SharedSignals.transmit(). The signature failed.');
      return this.transmitRefused('STS-SSF-0031', record, uri, {
        ok: false, delivered: false, jti: '',
        why: 'The event could not be signed with ' +
             events.signingAlgorithm() + ': ' + e.message +
             '. Check ssf.signingAlgorithm.' }, 'error');
    });
  }

  // -------------------------------------------------------------------------
  // A STREAM DECLARED DEAD, AND ONE REVIVED (2026-09-14). One audit row and
  // one log line for each — the only per-stream lines this machinery writes.
  // -------------------------------------------------------------------------
  private streamDeclaredDead(record: Json, moved: number): void {
    const { log, realms, ssfCluster } = this.deps;
    log.debug('Entering SharedSignals.streamDeclaredDead(). ' +
              record.stream_id);
    // ONCE FOR THE CLUSTER (2026-09-14, #46): two nodes pushing to one dead
    // receiver both cross the timeout. See ssf_cluster.ts's transitionOnce().
    // What is captured is what the row says NOW, before any await.
    const realmId = realms.currentId();
    const reason = record.deadReason || '?';
    const endpoint = record.delivery.endpoint_url;
    const streamId = record.stream_id;
    ssfCluster.transitionOnce('dead', streamId, () => {
      this.reportStreamDead(streamId, realmId, endpoint, moved, reason);
    });
    log.debug('Leaving SharedSignals.streamDeclaredDead().');
  }

  private reportStreamDead(streamId: string, realmId: string,
                           endpoint: string, moved: number,
                           reason: string): void {
    const { log, audit, config } = this.deps;
    log.debug('Entering SharedSignals.reportStreamDead(). ' + streamId);
    // The audit row's code writes the one log line (audit.js's logFailure()).
    audit.audit({ action: 'ssf.stream.dead', category: 'signals',
      protocol: 'SSF', channel: 'http', outcome: 'failure',
      errorCode: 'STS-SSF-0093', target: streamId,
      summary: 'ssf: stream ' + streamId + ' in the "' +
        realmId + '" realm was declared DEAD after ' +
        config.value('ssf.deadStreamTimeoutS') + 's of failed pushes to ' +
        endpoint + '; ' + moved + ' waiting SET(s) moved ' +
        'to its dead-letter queue and nothing more is pushed until a probe ' +
        'or an operator revives it. Last failure: ' + reason,
      detail: { endpoint: endpoint, moved: moved, why: reason } });
    log.debug('Leaving SharedSignals.reportStreamDead().');
  }

  private streamRevived(record: Json, how: string): void {
    const { log, audit, realms, ssfCluster } = this.deps;
    log.debug('Entering SharedSignals.streamRevived(). ' + record.stream_id);
    const streamId = record.stream_id;
    const realmId = realms.currentId();
    // Once for the cluster, for streamDeclaredDead()'s reason.
    ssfCluster.transitionOnce('revived', streamId, function () {
      audit.audit({ action: 'ssf.stream.revived', category: 'signals',
        protocol: 'SSF', channel: 'http', outcome: 'success',
        target: streamId,
        summary: 'The dead stream ' + streamId + ' was revived: ' + how });
      log.info('ssf: stream ' + streamId + ' in the "' + realmId +
               '" realm is alive again (' + how + ') and is pushed to as ' +
               'before.');
    });
    log.debug('Leaving SharedSignals.streamRevived().');
  }

  // -------------------------------------------------------------------------
  // THE SWEEP (2026-09-14): per process, every `ssf.deadLetterSweepS`, in
  // every realm — delete expired dead letters, probe the dead streams that are
  // due, and log ONE line per realm summarising what was dead-lettered since
  // the last sweep. It is the only place an undeliverable SET is logged.
  //
  // **EVERY PROCESS SWEEPS.** The dead-letter store is shared, so a delete
  // made twice is a no-op; the counts being summarised are each process's
  // own, so four processes log four lines about four different sets of
  // pushes. A probe sets `nextProbeAtMs` on the record before it pushes, which
  // replicates, so processes rarely probe the same stream in the same period
  // — and one extra probe is harmless.
  //
  // **BUT IN ACTIVE-ACTIVE MODE ONE PROCESS PROBES (2026-09-14, #46).**
  // "Rarely" was a replication interval inside one container and became every
  // node at once across several, each probe a signed push at a receiver
  // already known to be down, and each half-open decision a whole-record
  // write the others could revert. `ssfCluster.leadsProbes()` names one front
  // process for the cluster; every other process still sweeps its letters and
  // logs its summary.
  // -------------------------------------------------------------------------
  private probeDeadStream(record: Json, now: number): Promise<boolean> {
    const { log, config, realms, streams, events, transport } = this.deps;
    log.debug('Entering SharedSignals.probeDeadStream(). ' + record.stream_id);
    const timeout = Number(config.value('ssf.deadStreamTimeoutS')) * 1000;
    record.nextProbeAtMs = now + (timeout > 0 ? timeout : 300000);
    streams.touch(record);
    const oldest: Json = streams.deadLettersOf(record)[0];
    if (!oldest) {
      streams.halfOpen(record, now);
      log.info('ssf: stream ' + record.stream_id + ' in the "' +
               realms.currentId() + '" realm is dead with nothing left to ' +
               'probe with; its next SET will be pushed as the probe.');
      log.debug('Leaving SharedSignals.probeDeadStream(). Half-open.');
      return Promise.resolve(false);
    }
    const signed: Promise<string> = oldest.token
      ? Promise.resolve(oldest.token)
      : events.signSet(oldest.claims);
    log.debug('Leaving SharedSignals.probeDeadStream(). Probing with ' +
              oldest.jti + '.');
    return signed.then(function (token) {
      return transport.pushSetGated(record.delivery.endpoint_url, token, {
        authorizationHeader: record.delivery.authorization_header });
    }).then((result: Json) => {
      const live: Json = streams.liveRecord(record);
      if (!result.ok) {
        log.debug('SharedSignals.probeDeadStream(): ' + live.stream_id +
                  ' is still dead: ' + result.why);
        return false;
      }
      streams.removeDeadLetter(live, oldest.jti);
      live.counters.delivered += 1;
      if (streams.notePushSuccess(live)) {
        this.streamRevived(live, 'a probe push of the dead letter ' +
                                 oldest.jti + ' was delivered');
      }
      return true;
    }).catch(function (e) {
      log.debug('Caught in SharedSignals.probeDeadStream(): ' +
                ((e && e.message) || e));
      return false;
    });
  }

  private sweepSignalsRealm(now: number): Promise<Json> {
    const { log, realms, streams, errorCodes, ssfCluster,
            deadLetterReport } = this.deps;
    log.debug('Entering SharedSignals.sweepSignalsRealm(). ' +
              realms.currentId());
    const summary: Json = streams.sweepDeadLetters(now);
    const dead = streams.listStreams().filter(function (record) {
      return record.delivery.method === streams.DELIVERY_PUSH &&
             streams.isDead(record);
    });
    if (summary.letters || summary.trimmed) {
      const top = summary.byStream.sort(function (a, b) {
        return b[1] - a[1];
      }).slice(0, 5).map(function (pair) {
        return pair[0] + ' ' + pair[1];
      }).join(', ');
      log.warn(errorCodes.tag('STS-SSF-0094') + 'ssf: ' + summary.letters +
               ' Security Event Token(s) could not be delivered in the "' +
               realms.currentId() + '" realm since the last sweep and are ' +
               'on dead-letter queues (' + summary.byStream.length +
               ' stream(s)' +
               (top ? '; most: ' + top : '') + '; by code: ' +
               summary.byCode.map(function (pair) {
                 return pair[0] + ' ' + pair[1];
               }).join(', ') + '). ' + summary.held + ' dead letter(s) ' +
               'held, ' + summary.expired + ' expired and deleted, ' +
               summary.trimmed + ' deleted over ' +
               'ssf.deadLetterMaxPerStream; ' + dead.length +
               ' dead stream(s). Inspect them on /admin/ssf.');
    } else if (summary.expired || summary.orphaned) {
      log.info('ssf: ' + summary.expired + ' dead letter(s) older than ' +
               'ssf.deadLetterRetentionS and ' + summary.orphaned + ' of ' +
               'deleted streams were removed in the "' + realms.currentId() +
               '" realm; ' + summary.held + ' held.');
    }
    const due = ssfCluster.leadsProbes() ? dead.filter(function (record) {
      return !(Number(record.nextProbeAtMs) > now);
    }) : [];
    // THE MONITORING PAGE'S SWEEP HISTORY. Noted here and not in
    // `sweepDeadLetters()`, because the dead-stream and probe counts are only
    // known here — and before the probes run, so a probe that throws cannot
    // leave a sweep unrecorded.
    deadLetterReport.noteSweep(summary, { nowMs: now,
                                          deadStreams: dead.length,
                                          probes: due.length });
    log.debug('Leaving SharedSignals.sweepSignalsRealm(). ' + due.length +
              ' probe(s).');
    return Promise.all(due.map((record) => {
      return this.probeDeadStream(record, now);
    })).then(function () {
      return summary;
    });
  }

  sweepSignals(): Promise<unknown> {
    const { log, realms, errorCodes } = this.deps;
    log.debug('Entering SharedSignals.sweepSignals().');
    const now = Date.now();
    const all = realms.list();
    let chain: Promise<unknown> = Promise.resolve();
    all.forEach((realm) => {
      chain = chain.then(() => {
        return realms.run(realm, () => {
          try {
            return this.sweepSignalsRealm(now);
          } catch (e) {
            log.debug('Caught in SharedSignals.sweepSignals(): ' +
                      ((e && e.message) || e));
            log.error(errorCodes.tag('STS-SSF-0097') + 'ssf: the ' +
                      'dead-letter sweep failed in the "' + realm.id +
                      '" realm: ' + ((e && e.message) || e));
            return null;
          }
        });
      });
    });
    log.debug('Leaving SharedSignals.sweepSignals(). ' + all.length +
              ' realm(s).');
    return chain.catch(function (e) {
      log.error(errorCodes.tag('STS-SSF-0097') + 'ssf: the dead-letter ' +
                'sweep failed: ' + ((e && e.message) || e));
    });
  }

  scheduleSweep(): void {
    const { log, config } = this.deps;
    log.debug('Entering SharedSignals.scheduleSweep().');
    const seconds = Math.max(5,
                             Number(config.value('ssf.deadLetterSweepS')) ||
                             60);
    const again = () => {
      this.scheduleSweep();
    };
    sweepTimer = setTimeout(() => {
      this.sweepSignals().then(again, again);
    }, seconds * 1000);
    // A sweep must not keep a process that has finished everything else alive
    // — `npm test` loads this file and would otherwise wait out the interval.
    if (sweepTimer.unref) {
      sweepTimer.unref();
    }
    log.debug('Leaving SharedSignals.scheduleSweep(). ' + seconds + 's.');
  }

  // -------------------------------------------------------------------------
  // `ssf.delivery` (#46 section 6), AT REQUIRE TIME like every capability —
  // the code being loaded is the capability (cluster/CLAUDE.md). What it
  // stands for, and where each half is: an acknowledged SET is not delivered
  // again by another node (the barrier for a sequential ack then poll, and
  // `ssf_streams.ts`'s poll no longer writing a row back on a shared store for
  // a concurrent one); a session's end emits one event (`authn.js`'s
  // sessionEndOnce()); stream health is reported once and probed by one node,
  // and a GNAP proof on these endpoints is spent across the cluster
  // (`ssf_cluster.ts`). `ssf/CLAUDE.md` argues all four and what stays per
  // process.
  // -------------------------------------------------------------------------
  provideCapability(): void {
    const { log, loadCapabilities } = this.deps;
    log.debug('Entering SharedSignals.provideCapability().');
    const capabilities = loadCapabilities();
    capabilities.provide('ssf.delivery');
    log.debug('Leaving SharedSignals.provideCapability().');
  }

  // -------------------------------------------------------------------------
  // THE TRANSMITTER CONFIGURATION METADATA (SSF 1.0 section 6).
  //
  // NEVER GATED. See ssf_auth.ts's header — a transmitter whose discovery
  // document needs a credential is one nothing can bootstrap against.
  //
  // It answers whether or not `ssf.enabled` is on, and that is deliberate: a
  // receiver that finds this document and then a 501 has learned something
  // specific, where a 404 would leave it unable to tell "this service does not
  // speak SSF" from "the path is wrong".
  // -------------------------------------------------------------------------
  metadata(req: Req): Json {
    const { log, config, streams, ssfAuth } = this.deps;
    const { baseUrlOf } = this.deps.helpers;
    log.debug('Entering SharedSignals.metadata().');
    const base = this.ssfBase(req);
    const doc = {
      spec_version: '1_0-final',
      issuer: this.issuerFor(req),
      // baseUrlOf() carries the realm prefix already; see issuerFor().
      jwks_uri: baseUrlOf(req) + '/oauth2/jwks',
      delivery_methods_supported: streams.offeredDeliveryMethods(),
      configuration_endpoint: base + '/stream',
      status_endpoint: base + '/status',
      add_subject_endpoint: base + '/subjects/add',
      remove_subject_endpoint: base + '/subjects/remove',
      verification_endpoint: base + '/verify',
      critical_subject_members: this.criticalMembers(),
      default_subjects: String(config.value('ssf.defaultSubjects') || 'ALL')
        .toUpperCase(),
      authorization_schemes: ssfAuth.schemesForMetadata()
    };
    log.debug('Leaving SharedSignals.metadata().');
    return doc;
  }

  // -------------------------------------------------------------------------
  // THE STREAM MANAGEMENT API (SSF 1.0 section 7.1.1).
  //
  // One path, five methods, which is the specification's own shape: the
  // `configuration_endpoint` IS the resource. `?stream_id=` selects one on the
  // three methods that need one; a GET without it lists every stream this
  // caller could reach, which is what SSF says a transmitter answers.
  //
  // **PATCH AND PUT ARE NOT THE SAME AND THE DIFFERENCE IS REAL.** PUT
  // replaces — a member the receiver omits goes back to its default — and
  // PATCH merges. A PUT that behaved like a PATCH would let a receiver believe
  // it had cleared `events_requested` when it had not, and the symptom is
  // event types still arriving after they were removed.
  // -------------------------------------------------------------------------
  private contextOf(req: Req, decision: Json | null): Json {
    const { log } = this.deps;
    log.debug('Entering SharedSignals.contextOf().');
    const out = { issuer: this.issuerFor(req),
      principal: String((decision || {}).principal || '') };
    log.debug('Leaving SharedSignals.contextOf().');
    return out;
  }

  private streamView(req: Req, record: Json, decision: Json | null): Json {
    const { log, streams } = this.deps;
    log.debug('Entering SharedSignals.streamView().');
    const view: Json = streams.streamConfiguration(record, {
      pollEndpoint: this.ssfBase(req) + '/poll',
      // The receiver's own authorization_header goes back ONLY to a caller
      // that just wrote it, and never onto a console page or into the
      // management API's listing: it is a credential belonging to somebody
      // else's endpoint.
      includeSecrets: !!(decision && !decision.anonymous)
    });
    log.debug('Leaving SharedSignals.streamView().');
    return view;
  }

  private updateRoute(req: Req, res: Res, mode: string): void {
    const { log, audit, streams, errorCodes } = this.deps;
    log.debug('Entering SharedSignals.updateRoute(). ' + mode);
    if (this.offCheck(res)) {
      log.debug('Leaving SharedSignals.updateRoute(). Off.');
      return;
    }
    const decision = this.gate(req, res, 'write');
    if (!decision) {
      log.debug('Leaving SharedSignals.updateRoute(). Refused.');
      return;
    }
    const body = this.jsonBody(req);
    if (!body) {
      errorCodes.mark(res, 'STS-SSF-0011');
      this.fail(res, 400, 'invalid_request', 'The request body is not JSON.');
      log.debug('Leaving SharedSignals.updateRoute(). Not JSON.');
      return;
    }
    const id = String(body.stream_id || req.query.stream_id || '');
    const record: Json = streams.getStream(id);
    if (!record) {
      errorCodes.mark(res, 'STS-SSF-0014');
      this.fail(res, 404, 'invalid_request',
        'No stream with stream_id "' + id + '". The id goes in the body as ' +
        'stream_id, or in the query string.');
      log.debug('Leaving SharedSignals.updateRoute(). No such stream.');
      return;
    }
    const updated: Json = streams.updateStream(id, body, mode,
                                               this.contextOf(req, decision));
    if (!updated.ok) {
      errorCodes.mark(res, 'STS-SSF-0015');
      this.fail(res, 400, 'invalid_request', updated.errors.join(' '));
      log.debug('Leaving SharedSignals.updateRoute(). Refused.');
      return;
    }
    audit.audit({ action: 'ssf.stream.update', category: 'signals',
      protocol: 'SSF', channel: 'http', actor: decision.principal, target: id,
      summary: 'A Shared Signals stream was ' +
        (mode === 'replace' ? 'replaced' : 'merged'),
      detail: { events: updated.stream.events_delivered } });
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(this.streamView(req, updated.stream, decision),
                            null, 2));
    log.debug('Leaving SharedSignals.updateRoute(). ' + id);
  }

  // -------------------------------------------------------------------------
  // EVERY ROUTE THIS FAMILY REGISTERS, in the order the original file
  // registered them (rule 1). Called by `common/protocol_stack.ts` (#50, R1),
  // not at load. The comments above each are the original's.
  // -------------------------------------------------------------------------
  registerRoutes(app: typeof import('../common/app')): void {
    const { log, config, audit, applications, events, streams, subjects,
            transport, ssfCluster, errorCodes } = this.deps;
    const { iso, nowSec, xmlEscape } = this.deps.helpers;
    const WELL_KNOWN = SharedSignals.WELL_KNOWN;
    log.debug('Entering SharedSignals.registerRoutes().');

    app.get(WELL_KNOWN, (req, res) => {
      log.debug('Entering GET ' + WELL_KNOWN + '.');
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(this.metadata(req), null, 2));
      log.debug('Leaving GET ' + WELL_KNOWN + '.');
    });

    app.post('/ssf/stream', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering POST /ssf/stream.');
      if (this.offCheck(res)) {
        log.debug('Leaving POST /ssf/stream. Off.');
        return;
      }
      const decision = this.gate(req, res, 'write');
      if (!decision) {
        log.debug('Leaving POST /ssf/stream. Refused.');
        return;
      }
      const body = this.jsonBody(req);
      if (!body) {
        errorCodes.mark(res, 'STS-SSF-0011');
        this.fail(res, 400, 'invalid_request',
          'The request body is not JSON. A Stream Configuration is a JSON ' +
          'object; see ' + WELL_KNOWN + ' for what this transmitter ' +
          'supports.');
        log.debug('Leaving POST /ssf/stream. Not JSON.');
        return;
      }
      // The push endpoint is checked HERE as well as at push time, and that
      // is the half that matters to a receiver: a stream whose endpoint can
      // never be dialled is refused when it is created rather than accepted
      // and then silently delivering nothing.
      if (body.delivery && body.delivery.method === streams.DELIVERY_PUSH) {
        const problem = transport.urlProblem(body.delivery.endpoint_url);
        if (problem) {
          errorCodes.mark(res, 'STS-SSF-0012');
          this.fail(res, 400, 'invalid_request',
            'delivery.endpoint_url cannot be dialled by this transmitter: ' +
            problem + '. It is refused now rather than at delivery time, ' +
            'because a stream that is accepted and then silently delivers ' +
            'nothing is the worst outcome available here.');
          log.debug('Leaving POST /ssf/stream. Undiallable endpoint.');
          return;
        }
      }
      const created: Json = streams.createStream(body,
                                                 this.contextOf(req,
                                                                decision));
      if (!created.ok) {
        errorCodes.mark(res, 'STS-SSF-0013');
        this.fail(res, 400, 'invalid_request', created.errors.join(' '));
        log.debug('Leaving POST /ssf/stream. Refused.');
        return;
      }
      // The receiver as an APPLICATION. It is a sighting rather than a
      // declaration — somebody presented an identifier and it was accepted —
      // so it goes through seen() like every other family's, under a kind of
      // its own. What an operator DECLARES about a receiver ahead of time is
      // the `ssf` checkbox and the two fields on /admin/applications/new.
      if (decision.principal) {
        applications.seen({
          identifier: String(decision.principal),
          kind: 'ssf-receiver',
          protocol: 'SSF',
          fields: { ssfReceiverId: String(decision.principal) }
        });
      }
      audit.audit({ action: 'ssf.stream.create', category: 'signals',
        protocol: 'SSF', channel: 'http', actor: decision.principal,
        target: created.stream.stream_id,
        summary: 'A Shared Signals stream was created over ' +
          streams.deliveryName(created.stream.delivery.method),
        detail: { events: created.stream.events_delivered,
          endpoint: created.stream.delivery.endpoint_url } });
      res.status(201).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(this.streamView(req, created.stream, decision),
                              null, 2));
      log.debug('Leaving POST /ssf/stream. ' + created.stream.stream_id);
    });

    app.get('/ssf/stream', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering GET /ssf/stream.');
      if (this.offCheck(res)) {
        log.debug('Leaving GET /ssf/stream. Off.');
        return;
      }
      const decision = this.gate(req, res, 'read');
      if (!decision) {
        log.debug('Leaving GET /ssf/stream. Refused.');
        return;
      }
      const id = String(req.query.stream_id || '');
      if (!id) {
        const list = streams.listStreams().map((record) => {
          return this.streamView(req, record, decision);
        });
        res.status(200).type('application/json')
           .set('Cache-Control', 'no-store')
           .send(JSON.stringify(list, null, 2));
        log.debug('Leaving GET /ssf/stream. ' + list.length + ' stream(s).');
        return;
      }
      const record: Json = streams.getStream(id);
      if (!record) {
        errorCodes.mark(res, 'STS-SSF-0014');
        this.fail(res, 404, 'invalid_request',
          'No stream with stream_id "' + id + '". A GET with no stream_id ' +
          'lists every stream this transmitter holds.');
        log.debug('Leaving GET /ssf/stream. No such stream.');
        return;
      }
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(this.streamView(req, record, decision), null,
                              2));
      log.debug('Leaving GET /ssf/stream. ' + id);
    });

    app.put('/ssf/stream', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering PUT /ssf/stream.');
      this.updateRoute(req, res, 'replace');
      log.debug('Leaving PUT /ssf/stream.');
    });

    app.patch('/ssf/stream', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering PATCH /ssf/stream.');
      this.updateRoute(req, res, 'merge');
      log.debug('Leaving PATCH /ssf/stream.');
    });

    app.delete('/ssf/stream', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering DELETE /ssf/stream.');
      if (this.offCheck(res)) {
        log.debug('Leaving DELETE /ssf/stream. Off.');
        return;
      }
      const decision = this.gate(req, res, 'write');
      if (!decision) {
        log.debug('Leaving DELETE /ssf/stream. Refused.');
        return;
      }
      const body = this.jsonBody(req) || {};
      const id = String(body.stream_id || req.query.stream_id || '');
      if (!streams.getStream(id)) {
        errorCodes.mark(res, 'STS-SSF-0014');
        this.fail(res, 404, 'invalid_request',
          'No stream with stream_id "' + id + '".');
        log.debug('Leaving DELETE /ssf/stream. No such stream.');
        return;
      }
      streams.removeStream(id);
      audit.audit({ action: 'ssf.stream.delete', category: 'signals',
        protocol: 'SSF', channel: 'http', actor: decision.principal,
        target: id,
        summary: 'A Shared Signals stream was deleted' });
      res.status(204).set('Cache-Control', 'no-store').end();
      log.debug('Leaving DELETE /ssf/stream. ' + id);
    });

    // -----------------------------------------------------------------------
    // THE STATUS ENDPOINT (SSF 1.0 section 7.1.2).
    //
    // The three values and what separates them: a PAUSED stream keeps
    // queueing and delivers nothing, so what happened while it was paused is
    // still there when it is enabled again; a DISABLED one drops it. That is
    // the difference between "I was not listening" and "it did not happen",
    // which is the whole reason a Shared Signals receiver has a pause at all.
    //
    // A change here emits a **stream-updated** event on the stream itself, if
    // the receiver agreed that type — which is the one event a receiver gets
    // without asking for it, and the one whose absence is hardest to notice.
    // -----------------------------------------------------------------------
    app.get('/ssf/status', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering GET /ssf/status.');
      if (this.offCheck(res)) {
        log.debug('Leaving GET /ssf/status. Off.');
        return;
      }
      const decision = this.gate(req, res, 'read');
      if (!decision) {
        log.debug('Leaving GET /ssf/status. Refused.');
        return;
      }
      const id = String(req.query.stream_id || '');
      const record: Json = streams.getStream(id);
      if (!record) {
        errorCodes.mark(res, 'STS-SSF-0014');
        this.fail(res, 404, 'invalid_request',
          'No stream with stream_id "' + id + '".');
        log.debug('Leaving GET /ssf/status. No such stream.');
        return;
      }
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({ stream_id: record.stream_id,
           status: record.status, reason: record.statusReason }, null, 2));
      log.debug('Leaving GET /ssf/status. ' + record.status);
    });

    app.post('/ssf/status', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering POST /ssf/status.');
      if (this.offCheck(res)) {
        log.debug('Leaving POST /ssf/status. Off.');
        return;
      }
      const decision = this.gate(req, res, 'write');
      if (!decision) {
        log.debug('Leaving POST /ssf/status. Refused.');
        return;
      }
      const body = this.jsonBody(req);
      if (!body) {
        errorCodes.mark(res, 'STS-SSF-0011');
        this.fail(res, 400, 'invalid_request',
                  'The request body is not JSON.');
        log.debug('Leaving POST /ssf/status. Not JSON.');
        return;
      }
      const id = String(body.stream_id || '');
      const changed: Json = streams.setStatus(id, String(body.status || ''),
                                              String(body.reason || ''));
      if (!changed.ok) {
        const status = streams.getStream(id) ? 400 : 404;
        errorCodes.mark(res, status === 404 ? 'STS-SSF-0014' : 'STS-SSF-0016');
        this.fail(res, status, 'invalid_request', changed.errors.join(' '));
        log.debug('Leaving POST /ssf/status. Refused.');
        return;
      }
      audit.audit({ action: 'ssf.stream.status', category: 'signals',
        protocol: 'SSF', channel: 'http', actor: decision.principal,
        target: id,
        summary: 'The stream is now ' + changed.stream.status,
        detail: { reason: changed.stream.statusReason } });
      const answer = { stream_id: changed.stream.stream_id,
        status: changed.stream.status, reason: changed.stream.statusReason };
      // Tell the receiver IN BAND as well, if it agreed the type. A disabled
      // stream cannot carry it — enqueue() refuses — and that is correct
      // rather than a gap: there is nowhere for it to go and nothing to poll
      // it from.
      this.transmit(changed.stream, {
        uri: events.SSF_PREFIX + 'stream-updated',
        payload: { status: changed.stream.status,
          reason: changed.stream.statusReason || 'set at ' + iso() }
      }).then(function (report) {
        log.debug('POST /ssf/status: the stream-updated event was ' +
                  (report.ok ? 'transmitted'
                             : 'not transmitted: ' + report.why));
      });
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(answer, null, 2));
      log.debug('Leaving POST /ssf/status. ' + changed.stream.status);
    });

    // -----------------------------------------------------------------------
    // ADD AND REMOVE SUBJECT (SSF 1.0 sections 7.1.3 and 7.1.4).
    //
    // Both answer 204 with no body on success, which is what the
    // specification says and is worth not "improving": a receiver that gets a
    // 200 with a document has been given something to depend on that no
    // transmitter has to send.
    //
    // A REMOVE IS IDEMPOTENT — removing a subject that is not there is a 204
    // and not a 404. That is the specification's own rule and it is the right
    // one: a receiver tidying up after a crash must not have to know what it
    // had already removed.
    // -----------------------------------------------------------------------
    app.post('/ssf/subjects/add', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering POST /ssf/subjects/add.');
      if (this.offCheck(res)) {
        log.debug('Leaving POST /ssf/subjects/add. Off.');
        return;
      }
      const decision = this.gate(req, res, 'write');
      if (!decision) {
        log.debug('Leaving POST /ssf/subjects/add. Refused.');
        return;
      }
      const body = this.jsonBody(req);
      if (!body) {
        errorCodes.mark(res, 'STS-SSF-0011');
        this.fail(res, 400, 'invalid_request',
                  'The request body is not JSON.');
        log.debug('Leaving POST /ssf/subjects/add. Not JSON.');
        return;
      }
      const id = String(body.stream_id || '');
      if (!streams.getStream(id)) {
        errorCodes.mark(res, 'STS-SSF-0014');
        this.fail(res, 404, 'invalid_request',
          'No stream with stream_id "' + id + '".');
        log.debug('Leaving POST /ssf/subjects/add. No such stream.');
        return;
      }
      const added: Json = streams.addSubject(id, body.subject,
        body.verified !== false,
        { criticalMembers: this.criticalMembers() });
      if (!added.ok) {
        errorCodes.mark(res, 'STS-SSF-0017');
        this.fail(res, 400, 'invalid_request', added.errors.join(' '));
        log.debug('Leaving POST /ssf/subjects/add. Refused.');
        return;
      }
      audit.audit({ action: 'ssf.subject.change', category: 'signals',
        protocol: 'SSF', channel: 'http', actor: decision.principal,
        target: id,
        summary: 'A subject was added to ' + id,
        detail: { subject: subjects.describeSubject(body.subject),
          verified: body.verified !== false } });
      res.status(204).set('Cache-Control', 'no-store').end();
      log.debug('Leaving POST /ssf/subjects/add.');
    });

    app.post('/ssf/subjects/remove', ssfCluster.spendGnapProof,
      (req, res) => {
      log.debug('Entering POST /ssf/subjects/remove.');
      if (this.offCheck(res)) {
        log.debug('Leaving POST /ssf/subjects/remove. Off.');
        return;
      }
      const decision = this.gate(req, res, 'write');
      if (!decision) {
        log.debug('Leaving POST /ssf/subjects/remove. Refused.');
        return;
      }
      const body = this.jsonBody(req);
      if (!body) {
        errorCodes.mark(res, 'STS-SSF-0011');
        this.fail(res, 400, 'invalid_request',
                  'The request body is not JSON.');
        log.debug('Leaving POST /ssf/subjects/remove. Not JSON.');
        return;
      }
      const id = String(body.stream_id || '');
      if (!streams.getStream(id)) {
        errorCodes.mark(res, 'STS-SSF-0014');
        this.fail(res, 404, 'invalid_request',
          'No stream with stream_id "' + id + '".');
        log.debug('Leaving POST /ssf/subjects/remove. No such stream.');
        return;
      }
      const removed: Json = streams.removeSubject(id, body.subject);
      if (!removed.ok) {
        errorCodes.mark(res, 'STS-SSF-0018');
        this.fail(res, 400, 'invalid_request', removed.errors.join(' '));
        log.debug('Leaving POST /ssf/subjects/remove. Refused.');
        return;
      }
      audit.audit({ action: 'ssf.subject.change', category: 'signals',
        protocol: 'SSF', channel: 'http', actor: decision.principal,
        target: id,
        summary: 'A subject was removed from ' + id,
        detail: { subject: subjects.describeSubject(body.subject),
          wasThere: removed.removed } });
      res.status(204).set('Cache-Control', 'no-store').end();
      log.debug('Leaving POST /ssf/subjects/remove. ' + removed.removed);
    });

    // -----------------------------------------------------------------------
    // THE VERIFICATION ENDPOINT (SSF 1.0 section 7.1.5).
    //
    // THE ONLY END-TO-END TEST A STREAM HAS. Everything else a receiver can do
    // — create the stream, read it back, add a subject — exercises the
    // management API and proves nothing about whether an event can actually
    // be delivered.
    //
    // The `state` a receiver sends comes back UNCHANGED in the event, and it
    // is the only thing tying the event to the request: a receiver watching
    // two streams cannot otherwise tell which one just answered.
    //
    // **THE RATE LIMIT IS PUBLISHED AND NOT ENFORCED BY DEFAULT**, which is
    // the pair `ssf.minVerificationInterval` and `ssf.verificationRateLimit`
    // make: a receiver sees a realistic interval in its stream configuration
    // and may verify as often as it likes, and turning the second one on makes
    // the 429 reachable.
    // -----------------------------------------------------------------------
    app.post('/ssf/verify', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering POST /ssf/verify.');
      if (this.offCheck(res)) {
        log.debug('Leaving POST /ssf/verify. Off.');
        return;
      }
      const decision = this.gate(req, res, 'write');
      if (!decision) {
        log.debug('Leaving POST /ssf/verify. Refused.');
        return;
      }
      const body = this.jsonBody(req);
      if (!body) {
        errorCodes.mark(res, 'STS-SSF-0011');
        this.fail(res, 400, 'invalid_request',
                  'The request body is not JSON.');
        log.debug('Leaving POST /ssf/verify. Not JSON.');
        return;
      }
      const id = String(body.stream_id || '');
      const record: Json = streams.getStream(id);
      if (!record) {
        errorCodes.mark(res, 'STS-SSF-0014');
        this.fail(res, 404, 'invalid_request',
          'No stream with stream_id "' + id + '".');
        log.debug('Leaving POST /ssf/verify. No such stream.');
        return;
      }
      const interval = Number(record.min_verification_interval) || 0;
      const since = nowSec() - Number(record.lastVerificationAt || 0);
      if (config.value('ssf.verificationRateLimit') && interval > 0 &&
          record.lastVerificationAt && since < interval) {
        res.set('Retry-After', String(interval - since));
        errorCodes.mark(res, 'STS-SSF-0019');
        this.fail(res, 429, 'invalid_request',
          'This stream was verified ' + since + ' second(s) ago and its ' +
          'min_verification_interval is ' + interval + '. That interval is ' +
          'published on every stream configuration and is normally NOT ' +
          'enforced here — ssf.verificationRateLimit turns the refusal on, ' +
          'so that a receiver\'s back-off path is reachable at all.');
        log.debug('Leaving POST /ssf/verify. Too soon.');
        return;
      }
      record.lastVerificationAt = nowSec();
      // Reported to the journal: `ssf.verificationRateLimit` reads it back,
      // and a worker that never learnt of it would let a receiver verify as
      // often as the pool had workers.
      streams.touch(record);
      this.transmit(record, {
        uri: events.SSF_PREFIX + 'verification',
        payload: typeof body.state === 'string' && body.state !== ''
          ? { state: body.state } : {}
      }).then((report) => {
        if (!report.ok) {
          // A 202 was already the wrong answer here: the receiver asked
          // whether the pipe works and the answer is no. The refusal names
          // why, which is the whole value of the request.
          errorCodes.mark(res, 'STS-SSF-0020');
          this.fail(res, 400, 'invalid_request',
            'The verification event was not delivered: ' + report.why);
          log.debug('Leaving POST /ssf/verify. Not delivered.');
          return;
        }
        res.status(204).set('Cache-Control', 'no-store').end();
        log.debug('Leaving POST /ssf/verify. ' + report.jti);
      });
    });

    // -----------------------------------------------------------------------
    // POLL DELIVERY (RFC 8936).
    //
    // The receiver comes HERE, so nothing is dialled and a browser can be a
    // receiver over this method — which is exactly why the debugger's page
    // works with no api behind it on poll and needs one on push.
    //
    // `ack` names what the receiver has stored and `setErrs` what it REFUSED,
    // and both come off the queue. The second one catches people out and is
    // worth the sentence: a receiver that could not process an event will not
    // process it next time either, so redelivering would poll-loop forever.
    // The refusal is recorded on the stream instead, where a person can see
    // it.
    //
    // `returnImmediately` is honoured as "yes" always: this service does not
    // hold a request open. RFC 8936 permits a transmitter to answer
    // immediately in any case, and long-polling a mock would tie up a socket
    // to demonstrate nothing.
    // -----------------------------------------------------------------------
    app.post('/ssf/poll', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering POST /ssf/poll.');
      if (this.offCheck(res)) {
        log.debug('Leaving POST /ssf/poll. Off.');
        return;
      }
      const decision = this.gate(req, res, 'read');
      if (!decision) {
        log.debug('Leaving POST /ssf/poll. Refused.');
        return;
      }
      const body = this.jsonBody(req);
      if (!body) {
        errorCodes.mark(res, 'STS-SSF-0011');
        this.fail(res, 400, 'invalid_request',
                  'The request body is not JSON.');
        log.debug('Leaving POST /ssf/poll. Not JSON.');
        return;
      }
      const id = String(body.stream_id || req.query.stream_id || '');
      const record: Json = streams.getStream(id);
      if (!record) {
        errorCodes.mark(res, 'STS-SSF-0014');
        this.fail(res, 404, 'invalid_request',
          'No stream with stream_id "' + id + '". RFC 8936 has no ' +
          'stream_id member — a real poll endpoint is per stream, and this ' +
          'transmitter publishes one URL, so the id goes in the body or the ' +
          'query string. The stream configuration says so in ' +
          'delivery.endpoint_url.');
        log.debug('Leaving POST /ssf/poll. No such stream.');
        return;
      }
      if (record.delivery.method !== streams.DELIVERY_POLL) {
        errorCodes.mark(res, 'STS-SSF-0021');
        this.fail(res, 400, 'invalid_request',
          'Stream ' + id + ' is a PUSH stream (' + record.delivery.method +
          '), so its events are POSTed to ' + record.delivery.endpoint_url +
          ' and there is nothing here to collect. Change the delivery ' +
          'method on the stream first.');
        log.debug('Leaving POST /ssf/poll. Not a poll stream.');
        return;
      }
      const result: Json = streams.poll(record, body);
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({ sets: result.sets,
           moreAvailable: result.moreAvailable }, null, 2));
      log.debug('Leaving POST /ssf/poll. ' + Object.keys(result.sets).length +
                ' set(s).');
    });

    // -----------------------------------------------------------------------
    // THE ROLES REVERSED: A SET PUSHED **AT** THIS SERVICE.
    //
    // The debugger can be a transmitter, and something has to be at the far
    // end of its push. This is that, and it is what makes the debugger's
    // "send an event" half testable at all.
    //
    // **IT ACCEPTS A SET WHOSE SIGNATURE DOES NOT VERIFY, BY DEFAULT, AND
    // REPORTS WHY.** That is this service's ordinary posture and it is
    // exactly right for a debugger: a receiver that refused an unverifiable
    // event could not show anybody WHAT arrived or WHY it did not verify,
    // which is the question being asked. `ssf.receiveRequireSignature` turns
    // the 400 on, which is what a real receiver does and is the negative a
    // transmitter needs to be able to reach.
    //
    // The verification is against THIS SERVICE'S OWN key, because that is the
    // only key it has. A SET signed by somebody else is reported as "not
    // verifiable here" rather than as invalid — those are different sentences
    // and conflating them would be a receiver blaming a transmitter for its
    // own missing key.
    // -----------------------------------------------------------------------
    // THE READING AND THE VERIFICATION ARE `ssf_events.js`'s SINCE 2026-09-10,
    // AND THEY MOVED BECAUSE A SECOND RECEIVER ARRIVED.
    // `publicKeyForHeader()`, `verifyReceivedSet()` and `readSetForDisplay()`
    // were private to this file while this endpoint was the only thing in the
    // service that ever read a SET it was handed. The admin console and the
    // user portal are receivers of their own now (`ssf/ssf_receivers.ts`),
    // with a receive endpoint each, and three receivers reading a SET three
    // ways would be three opinions about what arrived. `events.readSet()` and
    // `events.verifySet()` are the same code in the file that owns the
    // envelope — building a SET and reading one back are the two directions
    // of one format.

    app.post('/ssf/receive', (req, res) => {
      log.debug('Entering POST /ssf/receive.');
      if (this.offCheck(res)) {
        log.debug('Leaving POST /ssf/receive. Off.');
        return;
      }
      if (!config.value('ssf.receiveEnabled')) {
        errorCodes.mark(res, 'STS-SSF-0022');
        this.fail(res, 501, 'invalid_request',
          'This service is not accepting pushed events (ssf.receiveEnabled). ' +
          'It is a RECEIVER only for the debugger\'s benefit — the roles ' +
          'reversed — and turning it off leaves the transmitter half working.');
        log.debug('Leaving POST /ssf/receive. Off.');
        return;
      }
      const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8')
        : (typeof req.body === 'string' ? req.body
          : String((req.body && req.body.token) || ''));
      const token = raw.trim();
      if (!token) {
        errorCodes.mark(res, 'STS-SSF-0023');
        this.fail(res, 400, 'invalid_request',
          'The body is empty. RFC 8935 section 2.1 puts the Security Event ' +
          'Token in the body as application/secevent+jwt, with no form ' +
          'encoding and no JSON wrapper around it.');
        log.debug('Leaving POST /ssf/receive. Empty body.');
        return;
      }
      const contentType = String((req.headers || {})['content-type'] || '')
        .split(';')[0].trim().toLowerCase();
      const read: Json = events.readSet(token);
      const verdict: Json = events.verifySet(token, read.header);
      const verified = verdict.verified;
      const verificationNote = verdict.note;
      if (!verified && config.value('ssf.receiveRequireSignature')) {
        errorCodes.mark(res, 'STS-SSF-0024');
        this.fail(res, 400, 'invalid_key', verificationNote);
        log.debug('Leaving POST /ssf/receive. Signature required.');
        return;
      }
      const entry = {
        at: iso(),
        token: token,
        contentType: contentType,
        correctMediaType: contentType === transport.SET_MEDIA_TYPE,
        header: read.header,
        claims: read.claims,
        problem: read.problem,
        verified: verified,
        verificationNote: verificationNote,
        summary: read.claims ? events.describeSet(read.claims) : null
      };
      streams.recordReceived(entry);
      audit.audit({ action: 'ssf.event.receive', category: 'signals',
        protocol: 'SSF', channel: 'http',
        outcome: read.problem ? 'failure' : 'success',
        errorCode: read.problem ? 'STS-SSF-0025' : '',
        target: String((read.claims || {}).jti || ''),
        summary: 'A Security Event Token was pushed at this service' +
          (verified ? ' and verified' : ''),
        detail: { types: Object.keys((read.claims || {}).events || {}),
          contentType: contentType } });
      if (read.problem) {
        errorCodes.mark(res, 'STS-SSF-0025');
        this.fail(res, 400, 'invalid_request', read.problem +
          ' It has been recorded anyway and is on /admin/ssf, because what ' +
          'arrived is the question being asked.');
        log.debug('Leaving POST /ssf/receive. Malformed.');
        return;
      }
      // 202 with an EMPTY body, which is what RFC 8935 section 2.3 says. A
      // document here would be something a transmitter could come to depend
      // on that no receiver has to send.
      res.status(202).set('Cache-Control', 'no-store').end();
      log.debug('Leaving POST /ssf/receive. Accepted.');
    });

    app.get('/ssf/received', ssfCluster.spendGnapProof, (req, res) => {
      log.debug('Entering GET /ssf/received.');
      if (this.offCheck(res)) {
        log.debug('Leaving GET /ssf/received. Off.');
        return;
      }
      const decision = this.gate(req, res, 'read');
      if (!decision) {
        log.debug('Leaving GET /ssf/received. Refused.');
        return;
      }
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({ received: streams.listReceived() }, null, 2));
      log.debug('Leaving GET /ssf/received.');
    });

    app.get('/ssf', (req, res) => {
      log.debug('Entering GET /ssf.');
      const info = this.description(req);
      if (String(req.query.format || '').toLowerCase() === 'json') {
        res.status(200).set('Cache-Control', 'no-store').json(info);
        log.debug('Leaving GET /ssf. JSON.');
        return;
      }
      const endpointRows = info.endpoints.map(function (row) {
        return '<tr><td><code>' + xmlEscape(row.method) +
          '</code></td><td><code>' +
          xmlEscape(row.path) + '</code></td><td>' + xmlEscape(row.what) +
          '</td></tr>';
      }).join('');
      const eventRows = info.eventTypes.map(function (row) {
        return '<tr><td>' + xmlEscape(row.name) + '</td><td><code>' +
          xmlEscape(row.uri) + '</code></td><td>' +
          (row.offered ? 'offered' : 'NOT offered') + '</td><td>' +
          xmlEscape(row.what) + '</td></tr>';
      }).join('');
      const formatRows = info.subjectFormats.map(function (row) {
        return '<tr><td><code>' + xmlEscape(row.format) +
          '</code></td><td><code>' +
          xmlEscape(row.members.join(', ')) + '</code></td><td>' +
          xmlEscape(row.what) + '</td></tr>';
      }).join('');
      const streamRows = info.streams.length
        ? info.streams.map(function (row) {
            return '<tr><td><code>' + xmlEscape(row.stream_id) +
              '</code></td><td>' + xmlEscape(row.status) + '</td><td>' +
              xmlEscape(streams.deliveryName(row.delivery)) + '</td><td>' +
              row.subjects + '</td><td>' + row.queued + '</td><td>' +
              row.counters.delivered + ' delivered, ' + row.counters.failed +
              ' failed</td></tr>';
          }).join('')
        : '<tr><td colspan="6">No streams. A receiver creates one by ' +
          'POSTing a Stream Configuration to the configuration endpoint ' +
          'above.</td></tr>';
      const negativeRows = info.reachableNegatives.map(function (row) {
        return '<tr><td>' + xmlEscape(row.what) + '</td><td>' +
          xmlEscape(row.answer) + '</td></tr>';
      }).join('');
      const schemeRows = info.authentication.schemes.map(function (row) {
        return '<tr><td>' + xmlEscape(row.name) + '</td><td><code>' +
          xmlEscape(row.spec_urn) + '</code></td><td>' + xmlEscape(row.what) +
          '</td></tr>';
      }).join('');

      const inner = '<h1>Shared Signals — a transmitter lives here</h1>' +
        '<p class="sub">OpenID SSF 1.0 (final, 2 September 2025) over RFC ' +
        '8417 Security Event Tokens, RFC 9493 subject identifiers, and RFC ' +
        '8935 / 8936 delivery. The issuer is <code>' +
        xmlEscape(info.issuer) +
        '</code>. ' + (info.enabled ? '' : '<strong>Turned off</strong> ' +
          '(<code>ssf.enabled</code>) — every endpoint but the metadata ' +
          'answers 501. ') + 'This page is not an SSF endpoint; a real ' +
        'transmitter publishes nothing like it.</p>' +
        '<div class="warn"><strong>SSF is the PIPE and not the ' +
        'vocabulary.</strong> ' +
        'It defines how two parties agree a stream, who the events are ' +
        'about, what they travel in and how they get there &mdash; and ' +
        'exactly TWO events of its own, both about the pipe. The ' +
        'vocabularies are CAEP (what happened to a session) and RISC (what ' +
        'happened to an account), and neither is here yet. <strong>Nothing ' +
        'generates an event on its own</strong>: every SET this service ' +
        'transmits was asked for, at the verification endpoint, on ' +
        '<a href="/admin/ssf">the console page</a> or through the ' +
        'management API.</div>' +
        '<h2>Discovery</h2>' +
        '<p>Everything below is published at <code>' +
        xmlEscape(info.metadataUrl) + '</code>, which is <strong>never ' +
        'gated</strong> &mdash; a receiver has to be able to read what the ' +
        'endpoints are before it can authenticate to one.</p>' +
        '<h2>Endpoints</h2>' +
        '<table><tr><th>Method</th><th>Path</th><th>What</th></tr>' +
        endpointRows + '</table>' +
        '<h2>Event types</h2>' +
        '<table><tr><th>Name</th><th>URI</th><th>State</th><th>What</th>' +
        '</tr>' +
        eventRows + '</table>' +
        '<p>Every SET is signed with <code>' +
        xmlEscape(info.signingAlgorithm) + '</code> (<code>' +
        'ssf.signingAlgorithm</code>), through the same signer every other ' +
        'JWT here goes through &mdash; so the post-quantum algorithms are ' +
        'available: ML-DSA at three sizes, SLH-DSA at two, and the six ' +
        'composite ML-DSA + traditional ones. This is the document most ' +
        'worth signing that way: a SET records that something happened and ' +
        'RFC 8417 section 4.1.4 forbids it to expire, so it is read long ' +
        'after it was written.</p>' +
        '<h2>Subject identifier formats (RFC 9493)</h2>' +
        '<table><tr><th>format</th><th>Members</th><th>What</th></tr>' +
        formatRows + '</table>' +
        '<p>A <strong>complex</strong> subject has no <code>format</code> ' +
        'and carries any of <code>' +
        xmlEscape(info.complexSubjectMembers.map(function (row) {
          return row.name;
        }).join('</code>, <code>')) + '</code>, each itself a subject ' +
        'identifier. That is what makes &ldquo;this session was ' +
        'revoked&rdquo; expressible: the person is not revoked, one session ' +
        'of theirs is. Critical members here: <code>' +
        xmlEscape(info.criticalSubjectMembers.join(', ') || '(none)') +
        '</code>.</p>' +
        '<h2>Authentication</h2>' +
        '<p>SSF 1.0 section 8 requires these endpoints to be protected and ' +
        'has the transmitter PUBLISH what it accepts, in ' +
        '<code>authorization_schemes</code> &mdash; so a receiver discovers ' +
        'how to authenticate rather than guessing. It is ' +
        (info.authentication.required ? 'ON' : 'OFF (<code>unreachable ' +
          'since 2026-09-06</code>)') + '. ' +
        xmlEscape(info.authentication.note) +
        '</p><table><tr><th>Scheme</th><th>spec_urn</th><th>What</th></tr>' +
        schemeRows + '</table>' +
        '<h2>Streams right now</h2>' +
        '<table><tr><th>stream_id</th><th>Status</th><th>Delivery</th>' +
        '<th>Subjects</th><th>Queued</th><th>Events</th></tr>' + streamRows +
        '</table>' +
        '<h2>What it deliberately does not do</h2><ul>' +
        info.doesNotDo.map(function (text) {
          return '<li>' + xmlEscape(text) + '</li>';
        }).join('') + '</ul>' +
        '<h2>Things you can make fail</h2>' +
        '<table><tr><th>Do this</th><th>Get this</th></tr>' + negativeRows +
        '</table>' +
        '<p class="sub"><a href="/ssf?format=json">This page as JSON</a> ' +
        '&middot; <a href="' + xmlEscape(info.metadataUrl) + '">the ' +
        'transmitter metadata</a> &middot; <a href="/admin/ssf">the console ' +
        'page</a> &middot; <a href="/oauth2/jwks">the key every SET is ' +
        'signed with</a></p>';
      res.status(200).type('html').set('Cache-Control', 'no-store')
         .send(this.pageShell('Shared Signals Framework', inner));
      log.debug('Leaving GET /ssf.');
    });

    log.debug('Leaving SharedSignals.registerRoutes().');
  }

  // -------------------------------------------------------------------------
  // WHAT THIS SURFACE IS, AS DATA. Shared by the page below and by
  // `?format=json`, so the two cannot disagree — the same reason
  // /admin/sts-metadata reads the router.
  // -------------------------------------------------------------------------
  description(req: Req): Json {
    const { log, config, events, streams, subjects, transport,
            ssfAuth } = this.deps;
    const { baseUrlOf } = this.deps.helpers;
    log.debug('Entering SharedSignals.description().');
    const WELL_KNOWN = SharedSignals.WELL_KNOWN;
    const base = this.ssfBase(req);
    const out = {
      enabled: this.enabled(),
      issuer: this.issuerFor(req),
      metadataUrl: baseUrlOf(req) + WELL_KNOWN,
      metadata: this.metadata(req),
      signingAlgorithm: events.signingAlgorithm(),
      delivery: streams.DELIVERY_METHODS.map(function (row) {
        return { method: row.method, name: row.name, what: row.what,
          offered: streams.offeredDeliveryMethods().indexOf(row.method) >= 0 };
      }),
      push: {
        allowed: transport.pushAllowed(),
        allowInsecure: transport.allowInsecure(),
        allowedHosts: transport.allowedHosts(),
        retries: config.value('ssf.pushRetries'),
        maxResponseBytes: transport.maxBodyBytes(),
        note: config.value('ssf.pushRetries') > 0
          ? 'A failed push is tried again up to ' +
            config.value('ssf.pushRetries') + ' time(s) (ssf.pushRetries) — ' +
            'only a connection failure, a timeout, a 5xx or a 429, never a ' +
            'receiver\'s 400 refusal.'
          : 'Nothing here retries a failed push by default (ssf.pushRetries ' +
            'is 0): a client that answers 500 to the first and 202 to the ' +
            'second would look, from its own logs, like a client that works.'
      },
      eventTypes: events.EVENTS.map(function (row) {
        return { uri: row.uri, name: row.name, family: row.family,
          subject: row.subject, what: row.what,
          offered: events.supportedEventUris().indexOf(row.uri) >= 0,
          members: row.members.map(function (member) {
            return { name: member.name, required: member.required,
              what: member.what };
          }) };
      }),
      subjectFormats: subjects.FORMATS.map(function (row) {
        return { format: row.format, members: row.members, what: row.what,
          example: row.example };
      }),
      complexSubjectMembers: subjects.COMPLEX_MEMBERS,
      criticalSubjectMembers: this.criticalMembers(),
      authentication: ssfAuth.describe(),
      streams: streams.listStreams().map(function (record) {
        return { stream_id: record.stream_id, status: record.status,
          delivery: record.delivery.method,
          events_delivered: record.events_delivered,
          subjects: record.subjects.length,
          queued: streams.queueOf(record).length,
          counters: record.counters, createdAt: record.createdAt,
          lastPushError: record.lastPushError };
      }),
      received: streams.listReceived().length,
      endpoints: [
        { method: 'GET', path: WELL_KNOWN,
          what: 'The transmitter configuration metadata. NEVER gated — a ' +
                'receiver has to read what the endpoints are before it can ' +
                'authenticate to one.' },
        { method: 'POST', path: base + '/stream',
          what: 'Create a stream. The transmitter mints the stream_id, sets ' +
                'the iss, and answers with events_delivered — the ' +
                'INTERSECTION of what was requested and what is supported.' },
        { method: 'GET', path: base + '/stream',
          what: 'Read one stream (?stream_id=) or list them all.' },
        { method: 'PUT', path: base + '/stream',
          what: 'REPLACE a stream configuration. A member omitted goes back ' +
                'to its default.' },
        { method: 'PATCH', path: base + '/stream',
          what: 'MERGE into a stream configuration. Only what is present ' +
                'changes.' },
        { method: 'DELETE', path: base + '/stream',
          what: 'Delete a stream.' },
        { method: 'GET', path: base + '/status',
          what: 'Read a stream\'s status.' },
        { method: 'POST', path: base + '/status',
          what: 'Set it to enabled, paused or disabled, and emit a ' +
                'stream-updated event on the stream itself.' },
        { method: 'POST', path: base + '/subjects/add',
          what: 'Add a subject. 204, no body. A SLASH and not a colon — ' +
                'SSF\'s examples write subjects:add, and express reads :add ' +
                'as a ' +
                'route parameter.' },
        { method: 'POST', path: base + '/subjects/remove',
          what: 'Remove one. 204, and IDEMPOTENT: removing a subject that is ' +
                'not there is a 204 rather than a 404.' },
        { method: 'POST', path: base + '/verify',
          what: 'Ask for a verification event. The only end-to-end test a ' +
                'stream has.' },
        { method: 'POST', path: base + '/poll',
          what: 'RFC 8936 poll delivery. ack what you stored, setErrs what ' +
                'you refused.' },
        { method: 'POST', path: base + '/receive',
          what: 'THE ROLES REVERSED: a SET pushed AT this service, so a ' +
                'client can be the transmitter. Not an SSF endpoint.' },
        { method: 'GET', path: base + '/received',
          what: 'What has arrived that way. Not an SSF endpoint either.' }
      ],
      reachableNegatives: [
        { what: 'Create a stream asking for delivery.method "push"',
          answer: '400 invalid_request — the values are the RFC numbers as ' +
                  'URNs (urn:ietf:rfc:8935), which catches everybody once' },
        { what: 'Add a subject with an extra member',
          answer: '400 invalid_request naming the member. RFC 9493 closes ' +
                  'each format\'s member set' },
        { what: 'Nest an aliases identifier inside another',
          answer: '400 invalid_request — RFC 9493 section 3.2.8 forbids it' },
        { what: 'Poll a PUSH stream',
          answer: '400 invalid_request naming the endpoint its events go to' },
        { what: 'Verify a disabled stream',
          answer: '400 invalid_request — a disabled stream drops what is ' +
                  'queued, so there is nowhere for the event to go' },
        { what: 'Ask for an event type the stream does not deliver',
          answer: '400 invalid_request listing what it does deliver' },
        { what: 'Read a stream with a token carrying only ' +
                ssfAuth.scopeRead() + ', then change it',
          answer: '403 access_denied naming the scope' },
        { what: 'Set ssf.verificationRateLimit and verify twice',
          answer: '429 with Retry-After' },
        { what: 'Set ssf.breakSetSignature',
          answer: 'Every SET is signed and then broken by one character, so ' +
                  'a ' +
                  'receiver that does not verify accepts an unsigned event' },
        { what: 'Set ssf.legacySubClaim',
          answer: 'A deprecated `sub` claim appears beside `sub_id`' }
      ],
      doesNotDo: [
        'It does not retry a failed push unless ssf.pushRetries says to, ' +
          'and that is 0 by default. RFC 8935 permits a retry; a mock that ' +
          'retried would make a receiver\'s one-shot failure invisible.',
        'It generates no event on its own. Nothing watches a session — every ' +
          'SET was asked for. SSF defines no event about a session, so a ' +
          'transmitter that invented one would be inventing a vocabulary. ' +
          'That changes with CAEP.',
        'It verifies nothing about a subject. A stream may name somebody who ' +
          'has never been here, which is what a receiver\'s "I do not know ' +
          'this subject" path needs.',
        'A `verified: true` on an Add Subject request is believed. There is ' +
          'no confirmation step here to skip.',
        'Streams are in memory and die with the process, like everything ' +
          'else this service mints — the signing key is regenerated on every ' +
          'start, so a restored queue would be tokens nothing can verify.'
      ]
    };
    log.debug('Leaving SharedSignals.description().');
    return out;
  }

  private pageShell(title: string, inner: string): string {
    const { log } = this.deps;
    const { xmlEscape } = this.deps.helpers;
    log.debug('Entering SharedSignals.pageShell().');
    log.debug('Leaving SharedSignals.pageShell().');
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>' + xmlEscape(title) + '</title><style>' +
      'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
      'background:#f4f4f7;margin:0;padding:2rem;color:#222;line-height:1.45}' +
      '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
      'padding:24px 28px;max-width:60rem;margin:0 auto;' +
      'box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
      'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}' +
      'h2{font-size:1em;margin:1.4em 0 .4em}' +
      'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
      '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;' +
      'border-radius:5px;font-size:.82em;margin:0 0 16px}' +
      'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;' +
      'font-size:.85em}' +
      'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;' +
      'vertical-align:top}th{background:#f0f0f5}' +
      'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
      'font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;' +
      'border-radius:3px;word-break:break-all}a{color:#12107c}' +
      'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
      '</style></head><body><div class="card">' + inner +
      '</div></body></html>\n';
  }

  // ---------------------------------------------------------------------------
  // WHAT THE CONSOLE AND THE MANAGEMENT API CALL.
  //
  // `admin-ui/admin.ts` cannot require this module — it is loaded before it,
  // and until #50's R1 a require the other way would have moved every SSF
  // route ahead of the console's own (rule 1); requiring it registers nothing
  // now, and the cycle below is reason enough. So this fills a slot on
  // `admin.js`, exactly as `ldap_server.js` and `crypto_metadata.js` do, and
  // it carries ONE object:
  // the reader and the six actions together, validated whole when it is
  // installed, because a partial one would leave `/admin/ssf` able to list
  // streams and unable to change any of them.
  //
  // Rule 3e's test was applied both ways round, as it requires. A require from
  // `admin.js` to here CLOSES A CYCLE (this file requires that one for the page
  // shell and the gate). A require from here to `admin.js` is what already
  // happens and is fine. So a slot is the answer rather than an indirection
  // added by analogy.
  // ---------------------------------------------------------------------------
  consoleReport(req: Req): Json {
    const { log, config, subjects, events, streams, transport } = this.deps;
    log.debug('Entering SharedSignals.consoleReport().');
    const info = this.description(req);
    info.streamDetail = streams.listStreams().map((record) => {
      return {
        stream_id: record.stream_id,
        iss: record.iss,
        aud: record.aud,
        status: record.status,
        statusReason: record.statusReason,
        delivery: { method: record.delivery.method,
          // NEVER the authorization_header: it is a credential belonging to
          // somebody else's endpoint, and a console page is the one place it
          // must not appear. streamConfiguration()'s `includeSecrets` is what
          // guards the other direction.
          endpoint_url: record.delivery.endpoint_url },
        events_delivered: record.events_delivered,
        events_requested: record.events_requested,
        format: record.format,
        description: record.description,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
        createdBy: record.createdBy,
        counters: record.counters,
        lastPushError: record.lastPushError,
        lastPushAt: record.lastPushAt,
        subjects: record.subjects.map((one) => {
          return { text: subjects.describeSubject(one.subject),
            verified: one.verified, addedAt: one.addedAt,
            subject: one.subject };
        }),
        queue: streams.queueOf(record).map((one) => {
          return { jti: one.jti, queuedAt: one.queuedAt,
            deliveredAt: one.deliveredAt,
            summary: events.describeSet(one.claims) };
        }),
        // DEAD OR ALIVE, and what could not be delivered (2026-09-14). The
        // dead letters are newest first and carry no token — a SET is a signed
        // statement about somebody, and a console page is not where it goes.
        dead: streams.isDead(record),
        deadSince: Number(record.deadSinceMs) > 0
          ? new Date(Number(record.deadSinceMs)).toISOString() : '',
        deadReason: record.deadReason || '',
        failingSince: Number(record.failingSinceMs) > 0
          ? new Date(Number(record.failingSinceMs)).toISOString() : '',
        nextProbeAt: Number(record.nextProbeAtMs) > 0
          ? new Date(Number(record.nextProbeAtMs)).toISOString() : '',
        deadLetters: streams.deadLettersOf(record).reverse().map((one) => {
          return { jti: one.jti, queuedAt: one.queuedAt, deadAt: one.deadAt,
            reason: one.reason, errorCode: one.errorCode, status: one.status,
            signed: one.signed,
            summary: one.claims ? events.describeSet(one.claims) : null };
        }),
        log: record.log.slice().reverse()
      };
    });
    info.deadLetters = {
      retentionS: config.value('ssf.deadLetterRetentionS'),
      maxPerStream: config.value('ssf.deadLetterMaxPerStream'),
      deadStreamTimeoutS: config.value('ssf.deadStreamTimeoutS'),
      pushes: transport.pushGateState()
    };
    info.receivedDetail = streams.listReceived().slice().reverse();
    log.debug('Leaving SharedSignals.consoleReport().');
    return info;
  }

  // ---------------------------------------------------------------------------
  // A CONSOLE OR MANAGEMENT API ACTION THIS FAMILY REFUSED, RECORDED.
  //
  // The action functions below hand a result to the console's responder rather
  // than answering a request themselves, so the code cannot be marked on a
  // response here. It is an audit row instead, and the result — which that
  // responder serialises for /admin-api — is returned untouched and carries no
  // code. The errors are this service's own sentences; no credential is in
  // them.
  // ---------------------------------------------------------------------------
  private actionRefused(code: string, protocol: string, name: string,
                        result: Json): Promise<Json> {
    const { log, audit } = this.deps;
    log.debug('Entering SharedSignals.actionRefused(). ' + code);
    audit.failure(code, {
      protocol: protocol, channel: 'http',
      target: String(name || ''),
      summary: 'The ' + protocol + ' console action "' + String(name || '') +
        '" was refused',
      detail: { why: ((result || {}).errors || []).join(' ') }
    });
    log.debug('Leaving SharedSignals.actionRefused().');
    return Promise.resolve(result);
  }

  // The six actions the console's forms and `POST /admin-api/ssf/:action` share
  // — one function, so the two doors cannot disagree about what happened.
  consoleAction(name: string, body?: Json, req?: Req): Promise<Json> {
    const { log, audit, events, streams } = this.deps;
    const { numberWord } = this.deps.helpers;
    log.debug('Entering SharedSignals.consoleAction(). ' + name);
    const asked = body || {};
    const id = String(asked.stream_id || '');
    if (name === 'delete') {
      if (!streams.getStream(id)) {
        log.debug('Leaving SharedSignals.consoleAction(). No such stream.');
        return this.actionRefused('STS-SSF-0045', 'SSF', name, { ok: false,
          errors: ['No stream with stream_id "' + id + '".'] });
      }
      streams.removeStream(id);
      audit.audit({ action: 'ssf.stream.delete', category: 'signals',
        protocol: 'SSF', channel: 'http', target: id,
        summary: 'A Shared Signals stream was deleted from the console' });
      log.debug('Leaving SharedSignals.consoleAction(). Deleted.');
      return Promise.resolve({ ok: true, message: 'Stream ' + id + ' deleted.',
        errors: [] });
    }
    if (name === 'status') {
      const changed: Json = streams.setStatus(id, String(asked.status || ''),
                                        String(asked.reason || ''));
      if (!changed.ok) {
        log.debug('Leaving SharedSignals.consoleAction(). Refused.');
        return this.actionRefused(streams.getStream(id) ? 'STS-SSF-0046'
          : 'STS-SSF-0045', 'SSF', name, { ok: false, errors: changed.errors });
      }
      audit.audit({ action: 'ssf.stream.status', category: 'signals',
        protocol: 'SSF', channel: 'http', target: id,
        summary: 'The stream is now ' + changed.stream.status });
      log.debug("Leaving SharedSignals.consoleAction().");
      return this.transmit(changed.stream, {
        uri: events.SSF_PREFIX + 'stream-updated',
        payload: { status: changed.stream.status,
          reason: changed.stream.statusReason || 'set from the console' }
      }).then((report) => {
        log.debug('Leaving SharedSignals.consoleAction(). Status set.');
        return { ok: true, errors: [],
          message: 'Stream ' + id + ' is now ' + changed.stream.status + '. ' +
            (report.ok
              ? 'A stream-updated event was ' + (report.delivered
                ? 'delivered.' : 'queued for the receiver to poll.')
              : 'No stream-updated event went with it: ' + report.why),
          report: report };
      });
    }
    if (name === 'transmit') {
      const record: Json = streams.getStream(id);
      if (!record) {
        log.debug('Leaving SharedSignals.consoleAction(). No such stream.');
        return this.actionRefused('STS-SSF-0045', 'SSF', name, { ok: false,
          errors: ['No stream with stream_id "' + id + '".'] });
      }
      let payload = asked.payload;
      if (typeof payload === 'string') {
        try {
          payload = JSON.parse(payload || '{}');
        } catch (e) {
          log.debug('Caught in SharedSignals.consoleAction(): ' +
                    ((e && e.message) || e));
          log.debug('Leaving SharedSignals.consoleAction(). ' +
                    'The payload is not JSON.');
          return this.actionRefused('STS-SSF-0047', 'SSF', name, { ok: false,
            errors: ['The event payload is not JSON: ' + e.message] });
        }
      }
      let subject = asked.subject;
      if (typeof subject === 'string' && subject.trim()) {
        try {
          subject = JSON.parse(subject);
        } catch (e) {
          log.debug('Caught in SharedSignals.consoleAction(): ' +
                    ((e && e.message) || e));
          log.debug('Leaving SharedSignals.consoleAction(). ' +
                    'The subject is not JSON.');
          return this.actionRefused('STS-SSF-0048', 'SSF', name, { ok: false,
            errors: ['The subject is not JSON: ' + e.message] });
        }
      } else if (typeof subject === 'string') {
        subject = null;
      }
      log.debug("Leaving SharedSignals.consoleAction().");
      return this.transmit(record, { uri: String(asked.type || ''),
        payload: payload || {}, subject: subject || null,
        txn: String(asked.txn || '') }).then((report) => {
        log.debug('Leaving SharedSignals.consoleAction(). Transmitted.');
        return { ok: report.ok, errors: report.ok ? [] : [report.why],
          message: report.ok
            ? (report.delivered
              ? 'Delivered ' + report.jti + ' to the receiver.'
              : 'Queued ' + report.jti + ' for the receiver to poll.')
            : report.why,
          report: report };
      });
    }
    if (name === 'clear-received') {
      const gone = streams.clearReceived();
      log.debug('Leaving SharedSignals.consoleAction(). Cleared.');
      return Promise.resolve({ ok: true, errors: [],
        message: gone + ' received event(s) dropped.' });
    }
    // REVIVE A DEAD PUSH STREAM BY HAND (2026-09-14): it is pushed to again at
    // once. Refused for a stream that is not dead, which is a refusal a caller
    // can act on — reviving a live stream would do nothing and report success.
    if (name === 'revive') {
      const record: Json = streams.getStream(id);
      if (!record) {
        log.debug('Leaving SharedSignals.consoleAction(). No such stream.');
        return this.actionRefused('STS-SSF-0045', 'SSF', name, { ok: false,
          errors: ['No stream with stream_id "' + id + '".'] });
      }
      if (!streams.revive(record, String(asked.reason || ''))) {
        log.debug('Leaving SharedSignals.consoleAction(). Not dead.');
        return this.actionRefused('STS-SSF-0095', 'SSF', name, { ok: false,
          errors: ['Stream ' + id + ' is not dead, so there is nothing to ' +
                   'revive. A stream is declared dead when its pushes have ' +
                   'all ' +
                   'failed for ssf.deadStreamTimeoutS.'] });
      }
      this.streamRevived(record, 'revived by hand');
      log.debug('Leaving SharedSignals.consoleAction(). Revived.');
      return Promise.resolve({ ok: true, errors: [],
        message: 'Stream ' + id + ' is alive again and will be pushed to. ' +
                 'Its ' +
                 'dead-letter queue is kept until ssf.deadLetterRetentionS ' +
                 'passes.' });
    }
    // EMPTY A STREAM'S DEAD-LETTER QUEUE BY HAND. What is dropped was already
    // undeliverable; nothing is sent.
    if (name === 'clear-dead-letters') {
      const record: Json = streams.getStream(id);
      if (!record) {
        log.debug('Leaving SharedSignals.consoleAction(). No such stream.');
        return this.actionRefused('STS-SSF-0045', 'SSF', name, { ok: false,
          errors: ['No stream with stream_id "' + id + '".'] });
      }
      const gone = streams.clearDeadLettersFor(id);
      audit.audit({ action: 'ssf.deadletter.clear', category: 'signals',
        protocol: 'SSF', channel: 'http', target: id,
        summary: gone + ' dead letter(s) dropped from ' + id });
      log.debug('Leaving SharedSignals.consoleAction(). Dead letters cleared.');
      return Promise.resolve({ ok: true, errors: [],
        message: gone + ' dead letter(s) dropped from ' + id + '.' });
    }
    // THE REFUSAL IS SPELLED THE WAY EVERY OTHER ACTION HANDLER HERE SPELLS IT,
    // AND IT WAS NOT UNTIL 2026-09-01. It said `"x" is not an action on this
    // resource. The ones that are: …`, which reads perfectly well and is
    // INVISIBLE to the two checks that actually depend on this sentence:
    // `tests/vendored/admin_api.js` requires /unknown action/i before it will
    // parse the list — that is the console/API parity check, so /ssf's four
    // actions were being compared against nothing — and
    // `tests/vendored/sts_admin_api_operations.js` matches `Unknown action "x".
    // <count phrase>: <list>.` across every documented resource, which is what
    // caught it. The lesson is the one `helpers.numberWord()`'s header already
    // states: this sentence is not prose, it is READ, and a handler that writes
    // it its own way turns a check off with nothing failing.
    //
    // The count comes from the LIST rather than from a word typed beside it,
    // for the same reason: `applicationsAction()` said "The six are" over seven
    // for a fortnight.
    log.debug('Leaving SharedSignals.consoleAction(). Unknown action.');
    return this.actionRefused('STS-SSF-0049', 'SSF', name, { ok: false,
      errors: ['Unknown action "' + String(name) + '". The ' +
        numberWord(SharedSignals.CONSOLE_ACTIONS.length) + ' are: ' +
        SharedSignals.CONSOLE_ACTIONS.join(', ') + '.'] });
  }
  // ---------------------------------------------------------------------------
  // AUTOMATIC EMISSION — THE ONE PLACE IN THIS SERVICE WHERE AN ENDPOINT IS NOT
  // WHAT STARTS THE WORK.
  //
  // Every other protocol family here answers a request. This function is called
  // because somebody signed in, presented a session or signed out, and it makes
  // a Security Event Token go out to whoever agreed to be told. That is what
  // CAEP is FOR, and it is the sentence on `GET /ssf`'s *what it deliberately
  // does not do* list that had to change: while the only vocabulary was the
  // pipe's own, "this service generates no event on its own" was honest,
  // because SSF defines no event about a session and a transmitter that
  // invented one would have been inventing a vocabulary. CAEP is that
  // vocabulary.
  //
  // `caep.autoEmit` puts the old behaviour back rather than leaving it only in
  // the history of this file, and `GET /ssf` reads the setting rather than
  // asserting either sentence.
  //
  // **THE DIVISION OF LABOUR.** `caep.ts` decides WHAT the event would be and
  // updates the register whether or not anything is sent; this decides WHERE it
  // goes. That is why the register shows a session with a count of zero — which
  // is the answer to "why did nothing arrive?" nine times out of ten, and the
  // answer is *nobody asked for that type*.
  //
  // **IT RETURNS A PROMISE AND NOBODY AWAITS IT.** `authn.js` calls this from
  // inside a sign-out and does not wait, deliberately: a push delivery takes as
  // long as somebody else's endpoint does, and a sign-out that blocked on a
  // receiver's TCP timeout would be a sign-out that hangs. Every outcome is
  // logged and recorded on the stream, which is where a person looks anyway.
  // ---------------------------------------------------------------------------
  caepAutoEmit(notice?: Json): Promise<EmitResult> {
    const { log, subjects, events, caep, streams, errorCodes } = this.deps;
    log.debug('Entering SharedSignals.caepAutoEmit().');
    if (!this.enabled()) {
      log.debug('Leaving SharedSignals.caepAutoEmit(). SSF is off.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    // THE ISSUER IS ADDED HERE AND NOT IN `authn.js`, because it is an SSF fact
    // and that module has no business knowing one. It matters more than it
    // looks: the subject names the person by ISSUER and subject, and a receiver
    // matches that `iss` against the issuer it discovered — so an event built
    // with the wrong one names somebody the receiver has never heard of and is
    // refused, which reads at the far end as a bad subject rather than as a
    // misconfigured transmitter.
    const due: Json = caep.observe(Object.assign({}, notice || {},
        { issuer: this.issuerFor((notice || {}).req || null) }));
    if (!due) {
      log.debug('Leaving SharedSignals.caepAutoEmit(). Nothing is due.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    const candidates = streams.listStreams().filter((record) => {
      return streams.deliversEvent(record, due.uri) &&
             streams.streamCoversSubject(record, due.subject);
    });
    if (!candidates.length) {
      // SAID ONCE, AT INFO, AND IT IS THE MOST USEFUL LINE THIS FEATURE
      // PRODUCES. "Nothing arrived" is the commonest report about any Shared
      // Signals deployment and its commonest cause is this: the event happened,
      // the transmitter built it, and no stream had asked for that type or
      // covered that subject. The register carries the same fact for the page.
      log.info('caep: a ' + due.uri.slice(events.CAEP_PREFIX.length) + ' is ' +
               'due for session ' + due.row.sessionId + ' and NO STREAM ' +
               'takes it — ' + streams.listStreams().length + ' stream(s) ' +
               'exist, and none both delivers that type and covers ' +
               subjects.describeSubject(due.subject) + '. The event is ' +
               'recorded on /admin/caep-sessions with nothing sent.');
      due.row.notes.push('A ' + due.uri.slice(events.CAEP_PREFIX.length) +
          ' was due and no stream takes it.');
      due.row.notes = due.row.notes.slice(-5);
      log.debug('Leaving SharedSignals.caepAutoEmit(). No stream takes it.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    log.debug("Leaving SharedSignals.caepAutoEmit().");
    return Promise.all(candidates.map((record) => {
      return this.transmit(record, { uri: due.uri, payload: due.payload,
        subject: due.subject, toe: due.payload.event_timestamp });
    })).then((reports) => {
      const sent = reports.filter((one) => {
        return one.ok;
      }).length;
      log.info('caep: ' + due.uri.slice(events.CAEP_PREFIX.length) + ' for ' +
               'session ' + due.row.sessionId + ' went to ' + sent + ' of ' +
               candidates.length + ' stream(s).');
      log.debug('Leaving SharedSignals.caepAutoEmit(). ' + sent + ' sent.');
      return { sent: sent, streams: candidates.length, reports: reports };
    }).catch((e) => {
      log.debug('Caught in SharedSignals.caepAutoEmit(): ' +
                ((e && e.message) || e));
      // Swallowed HERE as well as in authn.js, and not redundantly: that catch
      // covers this function throwing synchronously and this one covers a
      // rejected promise nobody is waiting on, which node reports as an
      // unhandled rejection and — depending on the flags — ends the process.
      log.error(errorCodes.tag('STS-SSF-0056') +
                'caep: automatic emission failed: ' + e.message);
      log.debug('Leaving SharedSignals.caepAutoEmit(). Failed.');
      return { sent: 0, streams: candidates.length, why: e.message };
    });
  }

  // ---------------------------------------------------------------------------
  // A CAEP EVENT A PROTOCOL FAMILY OBSERVED ABOUT SOMETHING THAT IS NOT A
  // SIGN-ON SESSION.
  //
  // `caepAutoEmit()` above is fed by `authn.js`, and its subject is always a
  // row in the CAEP session register. GNAP (2026-09-12) is the first family
  // whose sessions are not sign-on sessions — a grant is a DELEGATED session
  // between a client instance and a resource owner, with a revocation of its
  // own — so it needs the same delivery without the register.
  // `gnap/gnap_signals.ts` argues why a revoked grant is a `session-revoked` at
  // all.
  //
  // **THE CALLER BUILDS THE SUBJECT AND THIS BUILDS EVERYTHING ELSE**, for
  // `caepAutoEmit()`'s division of labour: the payload through
  // `caep.buildPayload()` so there is one shape for every CAEP event this
  // service sends, and the candidate streams through `streamCoversSubject()` so
  // a family's subject scope (`ssf_streams.setSubjectScope()`) is honoured here
  // exactly as it is for a sign-on session.
  //
  // **IT NEVER REJECTS.** A grant revocation does not wait on somebody else's
  // push endpoint, and a failure is logged, coded and recorded on the stream.
  // ---------------------------------------------------------------------------
  emitProtocolEvent(asked?: Json): Promise<EmitResult> {
    const { log, audit, subjects, events, caep, streams,
            errorCodes } = this.deps;
    log.debug('Entering SharedSignals.emitProtocolEvent().');
    const options = asked || {};
    const protocol = String(options.protocol || 'a protocol');
    if (!this.enabled()) {
      log.debug('Leaving SharedSignals.emitProtocolEvent(). SSF is off.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    const type = String(options.type || '');
    const uri = type.indexOf(events.CAEP_PREFIX) === 0 ? type :
                events.CAEP_PREFIX + type;
    const row: Json = events.EVENT_BY_URI[uri];
    if (!row || row.family !== 'caep') {
      log.warn(errorCodes.tag('STS-SSF-0073') + 'ssf: ' + protocol + ' asked ' +
          'for a CAEP "' +
               type + '", which is not one of CAEP\'s event types; nothing ' +
                      'was ' +
                      'sent.');
      log.debug('Leaving SharedSignals.emitProtocolEvent(). Not a CAEP type.');
      return Promise.resolve({ sent: 0, streams: 0,
                               why: 'not a CAEP event type' });
    }
    let payload;
    try {
      payload = caep.buildPayload(uri, options.values || {}, {
        initiatingEntity: String(options.initiatingEntity || 'system'),
        reasonAdmin: String(options.reasonAdmin || ''),
        reasonUser: String(options.reasonUser || '')
      });
    } catch (e) {
      log.debug('Caught in SharedSignals.emitProtocolEvent(): ' +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SSF-0075') + 'ssf: a CAEP ' + row.name +
          ' ' +
          'from ' + protocol +
                ' could not be built: ' + e.message);
      log.debug('Leaving SharedSignals.emitProtocolEvent(). ' +
                'The payload could not be built.');
      return Promise.resolve({ sent: 0, streams: 0, why: e.message });
    }
    const verdict: Json = events.validateEvent(uri, payload);
    if (!verdict.ok) {
      log.warn(errorCodes.tag('STS-SSF-0074') + 'ssf: a CAEP ' + row.name +
          ' ' +
          'from ' + protocol +
               ' is not a valid event and was not sent: ' +
          verdict.errors.join(' '));
      log.debug('Leaving SharedSignals.emitProtocolEvent(). ' +
                'The payload is invalid.');
      return Promise.resolve({ sent: 0, streams: 0,
                               why: verdict.errors.join(' ') });
    }
    const subject = options.subject;
    const candidates = streams.listStreams().filter((record) => {
      return streams.deliversEvent(record, uri) &&
             (!subject || streams.streamCoversSubject(record, subject));
    });
    if (!candidates.length) {
      // The same line caepAutoEmit() says, for the same reason: "nothing
      // arrived" is almost always "no stream asked for that type".
      log.info('ssf: a ' + row.name + ' from ' + protocol + ' is due about ' +
               (subject ? subjects.describeSubject(subject) : 'nobody') + ' ' +
                   'and NO STREAM takes it.');
      log.debug('Leaving SharedSignals.emitProtocolEvent(). ' +
                'No stream takes it.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    audit.audit({ action: 'caep.event.emit', category: 'signals',
      protocol: 'CAEP', channel: 'http',
      target: subject && subject.session ? String(subject.session.id || '')
                                         : '',
      summary: 'A CAEP ' + row.name + ' was emitted for ' + protocol,
      detail: { type: uri, streams: candidates.length, via: protocol } });
    log.debug("Leaving SharedSignals.emitProtocolEvent().");
    return Promise.all(candidates.map((record) => {
      return this.transmit(record, { uri: uri, payload: payload,
        subject: subject,
        toe: payload.event_timestamp });
    })).then((reports) => {
      const sent = reports.filter((one) => {
        return one.ok;
      }).length;
      log.info('ssf: ' + row.name + ' from ' + protocol + ' went to ' + sent +
          ' ' +
          'of ' +
               candidates.length + ' stream(s).');
      log.debug('Leaving SharedSignals.emitProtocolEvent(). ' +
                '' + sent + ' sent.');
      return { sent: sent, streams: candidates.length, reports: reports };
    }).catch((e) => {
      log.debug('Caught in SharedSignals.emitProtocolEvent(): ' +
                ((e && e.message) || e));
      // A rejected promise nobody waits on would be an unhandled rejection.
      log.error(errorCodes.tag('STS-SSF-0075') + 'ssf: a CAEP ' + row.name +
          ' ' +
          'from ' + protocol +
                ' could not be delivered: ' + e.message);
      log.debug('Leaving SharedSignals.emitProtocolEvent(). Failed.');
      return { sent: 0, streams: candidates.length, why: e.message };
    });
  }

  // ---------------------------------------------------------------------------
  // THE CAEP CONSOLE AND MANAGEMENT API.
  //
  // `/admin/caep`, `/admin/caep-sessions` and `/admin-api/caep` reach this
  // directory through `admin.setCaepReporter()`, the NINTH slot, for exactly
  // the reasons the eighth exists: a require from `admin.js` to this file would
  // close a cycle, and one from `mgmt-api/admin_api.ts` would have moved every
  // `/ssf` route ahead of the management API's own — until #50's R1; it would
  // now move this family's LOAD (its stores, hooks and slots) to 19 instead.
  //
  // `action` returns a PROMISE, like the signals slot's and for the same
  // reason: emitting an event signs a JWS — possibly on the worker pool — and
  // then POSTs it to somebody else's endpoint.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // WHAT THIS TRANSMITTER HAS SAID TO EACH RECEIVER, ACROSS EVERY SESSION.
  //
  // The register answers "what has been said about this SESSION" and the
  // streams table answers "what would this stream take". Neither answers the
  // question an operator actually arrives with once more than one receiver
  // exists: **is the receiver I am testing getting anything, and what.**
  //
  // **THE JOIN IS `createdBy` AND NOT `aud`, AND THAT IS WORTH KNOWING BECAUSE
  // THE OBVIOUS ONE IS WRONG.** A stream's `aud` is what the RECEIVER asked its
  // SETs to be addressed to — required, never defaulted, and deliberately not
  // taken from whoever authenticated (see `normaliseAudience()`). The
  // application entry is created from the principal that CREATED the stream, so
  // `createdBy` is the field that names the same thing the registry does. They
  // are usually the same string, and a receiver that sends a different `aud` is
  // doing something legitimate that this table then shows: the row carries
  // both.
  //
  // **AN APPLICATION WITH NO STREAM IS A ROW AND NOT AN OMISSION.** It is the
  // commonest state a receiver under test is in — declared here, nothing agreed
  // yet — and a table that showed only receivers with streams would answer
  // "where is my application" with silence. Every count is zero and the row
  // says which of the two states it is in.
  //
  // **A STREAM WITH NO APPLICATION IS COUNTED TOO**, under one row for all of
  // them. That happened while these endpoints could be left unauthenticated
  // (`ssf.authRequired`, removed 2026-09-06): there is no principal, so nothing
  // was recorded in the registry, and the events are real. Dropping them would
  // make the totals here disagree with the totals two tables up.
  // ---------------------------------------------------------------------------
  private caepApplications(): Json[] {
    const { log, applications, events, caep, streams } = this.deps;
    log.debug('Entering SharedSignals.caepApplications().');
    const caepUris = events.CAEP_EVENT_URIS;
    const all = streams.listStreams();

    // sessionId -> the streams anything went out on, so a receiver's session
    // count is the register's own answer rather than a second tally that could
    // drift from it.
    const sessionsByStream = {};
    caep.list().forEach((row) => {
      (row.streams || []).forEach((id) => {
        if (!sessionsByStream[id]) {
          sessionsByStream[id] = {};
        }
        sessionsByStream[id][row.sessionId] = true;
      });
    });

    function blank(identifier, name, registered) {
      log.debug("Entering blank().");
      const counts = {};
      caepUris.forEach((uri) => {
        counts[uri] = 0;
      });
      log.debug("Leaving blank().");
      return { identifier: identifier, name: name, registered: registered,
        dn: '', declared: false, streams: [], streamCount: 0, enabled: 0,
        deliveries: [], audiences: [], takes: [], counts: counts, total: 0,
        sessions: 0, queued: 0, delivered: 0, failed: 0, acknowledged: 0,
        receiverErrors: 0, lastPushAt: '', lastPushError: '' };
    }

    const rows = {};
    const order = [];
    function rowFor(identifier, name, registered) {
      log.debug("Entering rowFor().");
      if (!rows[identifier]) {
        rows[identifier] = blank(identifier, name, registered);
        order.push(identifier);
      }
      log.debug("Leaving rowFor().");
      return rows[identifier];
    }

    // EVERY APPLICATION THAT SUPPORTS CAEP, whether or not it has a stream. It
    // is the Shared Signals family in the registry: declared with the `ssf`
    // checkbox, seen when a stream was created, or holding an `ssfReceiverId`
    // somebody wrote by hand.
    applications.list().forEach((entry) => {
      const declared = (entry.allowedProtocols || []).indexOf('ssf') >= 0;
      const seen = (entry.recordedProtocols || []).indexOf('ssf') >= 0;
      const receiverId =
          ((entry.attributes || {}).ssfReceiverId || [])[0] || '';
      if (!declared && !seen && !receiverId) {
        return;
      }
      const row = rowFor(receiverId || entry.identifier,
                         entry.name || entry.identifier, true);
      row.dn = entry.dn || '';
      row.declared = declared;
      row.endpoints = ((entry.attributes ||
                        {}).ssfDeliveryEndpoint || []).slice();
    });

    const NOBODY = '(no application — the stream was agreed unauthenticated)';
    all.forEach((record) => {
      const who = String(record.createdBy || '');
      const known = who && who !== '(unauthenticated)';
      const row = rowFor(known ? who : NOBODY, known ? who : NOBODY, false);
      row.streams.push(record.stream_id);
      row.streamCount += 1;
      if (record.status === 'enabled') {
        row.enabled += 1;
      }
      const delivery = streams.deliveryName(record.delivery.method);
      if (row.deliveries.indexOf(delivery) < 0) {
        row.deliveries.push(delivery);
      }
      const aud = Array.isArray(record.aud) ? record.aud.join(' ')
                                            : String(record.aud || '');
      if (aud && row.audiences.indexOf(aud) < 0) {
        row.audiences.push(aud);
      }
      caepUris.forEach((uri) => {
        if (streams.deliversEvent(record, uri)) {
          const short = uri.slice(events.CAEP_PREFIX.length);
          if (row.takes.indexOf(short) < 0) {
            row.takes.push(short);
          }
        }
        const n = (record.eventCounts || {})[uri] || 0;
        row.counts[uri] += n;
        row.total += n;
      });
      row.queued += record.counters.queued;
      row.delivered += record.counters.delivered;
      row.failed += record.counters.failed;
      row.acknowledged += record.counters.acknowledged;
      row.receiverErrors += record.counters.receiverErrors;
      if (record.lastPushAt > row.lastPushAt) {
        row.lastPushAt = record.lastPushAt;
      }
      if (record.lastPushError) {
        row.lastPushError = record.lastPushError;
      }
    });

    // DISTINCT SESSIONS, counted across the receiver's streams together — a
    // session an application was told about on two of its streams is one
    // session, and adding per-stream counts would say two.
    order.forEach((identifier) => {
      const row = rows[identifier];
      const seen = {};
      row.streams.forEach((id) => {
        Object.keys(sessionsByStream[id] || {}).forEach((sessionId) => {
          seen[sessionId] = true;
        });
      });
      row.sessions = Object.keys(seen).length;
    });

    // Busiest first, then by name, so the receiver something is happening to is
    // at the top and the order is stable when nothing is happening at all.
    const out = order.map((identifier) => {
      return rows[identifier];
    });
    out.sort((a, b) => {
      if (b.total !== a.total) {
        return b.total - a.total;
      }
      if (b.streamCount !== a.streamCount) {
        return b.streamCount - a.streamCount;
      }
      return String(a.identifier).localeCompare(String(b.identifier));
    });
    log.debug('Leaving SharedSignals.caepApplications(). ' +
              '' + out.length + ' receiver(s).');
    return out;
  }

  caepReport(req?: Req): Json {
    const { log, subjects, events, caep, streams } = this.deps;
    log.debug('Entering SharedSignals.caepReport().');
    const report: Json = caep.report();
    report.issuer = this.issuerFor(req);
    report.ssfEnabled = this.enabled();
    // WHICH STREAMS WOULD TAKE A CAEP EVENT AT ALL, computed rather than
    // configured, because it is the question the page exists to answer second:
    // a reader who has seen a session with a count of zero wants to know
    // whether ANY stream would have taken one.
    // PER RECEIVER, ACROSS EVERY SESSION — the section /admin/caep-sessions
    // draws under the streams table. See this.caepApplications().
    report.applications = this.caepApplications();
    report.streams = streams.listStreams().map((record) => {
      const takes = events.CAEP_EVENT_URIS.filter((uri) => {
        return streams.deliversEvent(record, uri);
      });
      return { stream_id: record.stream_id, aud: record.aud,
        status: record.status, delivery: record.delivery.method,
        subjects: record.subjects.length,
        takes: takes.map((uri) => {
          return uri.slice(events.CAEP_PREFIX.length);
        }) };
    });
    log.debug('Leaving SharedSignals.caepReport(). ' +
              '' + report.tracked + ' session(s).');
    return report;
  }

  // Emit one CAEP event BY HAND. Two of the eight describe things nothing here
  // does — no device reports compliance to this service and no risk engine
  // talks to it — so this is the only way they are ever produced, and it is why
  // the action exists rather than the page being read-only. (Five are emitted
  // automatically — `caep.autoEmitTypes` — and `token-claims-change` only by
  // GNAP, `gnap/gnap_signals.ts`.)
  private caepEmit(asked: Json): Promise<Json> {
    const { log, audit, subjects, events, caep, streams } = this.deps;
    log.debug('Entering SharedSignals.caepEmit().');
    const uri = String(asked.type || '').indexOf(events.CAEP_PREFIX) === 0
      ? String(asked.type)
      : events.CAEP_PREFIX + String(asked.type || '');
    const row: Json = events.EVENT_BY_URI[uri];
    if (!row || row.family !== 'caep') {
      log.debug('Leaving SharedSignals.caepEmit(). Not a CAEP event type.');
      return this.actionRefused('STS-SSF-0050', 'CAEP', 'emit', { ok: false,
        errors: [
        '"' + String(asked.type || '') + '" is not one of CAEP\'s eight ' +
        'event ' +
        'types. They are: ' + events.CAEP_EVENT_URIS.map((one) => {
          return one.slice(events.CAEP_PREFIX.length);
        }).join(', ') + '.'] });
    }
    const sessionId = String(asked.session_id || '');
    const known: Json = caep.get(sessionId);
    if (!known) {
      log.debug('Leaving SharedSignals.caepEmit(). No such session.');
      return this.actionRefused('STS-SSF-0051', 'CAEP', 'emit', { ok: false,
        errors: [
        'No session "' + sessionId + '" is tracked here. A CAEP event is ' +
        'ABOUT a session — the subject names one — so there is nothing to ' +
        'compose a subject from. Sign somebody in, or pick a row from ' +
        '/admin/caep-sessions.'] });
    }
    let values = asked.payload;
    if (typeof values === 'string' && values.trim()) {
      try {
        values = JSON.parse(values);
      } catch (e) {
        log.debug('Caught in SharedSignals.caepEmit(): ' +
                  ((e && e.message) || e));
        log.debug('Leaving SharedSignals.caepEmit(). The payload is not JSON.');
        return this.actionRefused('STS-SSF-0047', 'CAEP', 'emit', { ok: false,
          errors: ['The event payload is not JSON: ' + e.message] });
      }
    }
    const payload: Json = caep.buildPayload(uri, values || {}, {
      initiatingEntity: String(asked.initiating_entity || 'admin'),
      reasonAdmin: String(asked.reason_admin || '') ||
        'Emitted by hand from the console.',
      reasonUser: String(asked.reason_user || '')
    });
    const verdict: Json = events.validateEvent(uri, payload);
    if (!verdict.ok) {
      log.debug('Leaving SharedSignals.caepEmit(). The payload is invalid.');
      return this.actionRefused('STS-SSF-0052', 'CAEP', 'emit',
                           { ok: false, errors: verdict.errors });
    }
    const subject = caep.subjectFor(known);
    const candidates = streams.listStreams().filter((record) => {
      return streams.deliversEvent(record, uri) &&
             streams.streamCoversSubject(record, subject);
    });
    audit.audit({ action: 'caep.event.emit', category: 'signals',
      protocol: 'CAEP', channel: 'http', target: sessionId,
      summary: 'A CAEP ' + row.name + ' was emitted by hand for session ' +
        sessionId,
      detail: { type: uri, streams: candidates.length } });
    if (!candidates.length) {
      // The register is still told, so the page shows the state change even
      // though nothing was sent — which is the honest report and is what makes
      // "nothing arrived" traceable to "nobody asked" rather than to a bug.
      const applied: Json = caep.applyToState(known, uri, payload);
      log.debug('Leaving SharedSignals.caepEmit(). No stream takes it.');
      if (!applied.ok) {
        // The register's one hard rule refused the state change the hand
        // emission would have made; the result below says which.
        audit.failure('STS-SSF-0053', {
          protocol: 'CAEP', channel: 'http',
          target: sessionId,
          summary: 'A hand-emitted CAEP ' + row.name + ' was refused by the ' +
            'session register for session ' + sessionId,
          detail: { type: uri, why: applied.errors.join(' ') } });
      }
      log.debug("Leaving SharedSignals.caepEmit().");
      return Promise.resolve({ ok: applied.ok, errors: applied.errors,
        warnings: applied.warnings,
        message: applied.ok
          ? 'Nothing was sent: no stream both delivers "' +
            uri.slice(events.CAEP_PREFIX.length) + '" and covers ' +
            subjects.describeSubject(subject) + '. The session\'s state was ' +
            'still updated, so the change is on this page.'
          : applied.errors.join(' ') });
    }
    log.debug("Leaving SharedSignals.caepEmit().");
    return Promise.all(candidates.map((record) => {
      return this.transmit(record, { uri: uri, payload: payload,
        subject: subject,
        toe: payload.event_timestamp });
    })).then((reports) => {
      const sent = reports.filter((one) => {
        return one.ok;
      }).length;
      log.debug('Leaving SharedSignals.caepEmit(). ' +
                '' + sent + ' of ' + reports.length + '.');
      return { ok: sent > 0,
        errors: sent > 0 ? [] : reports.map((one) => {
          return one.why;
        }),
        message: sent + ' of ' + reports.length + ' stream(s) took the ' +
          row.name + '.',
        reports: reports };
    });
  }

  caepAction(name: string, body?: Json): Promise<Json> {
    const { log, caep } = this.deps;
    const { numberWord } = this.deps.helpers;
    log.debug('Entering SharedSignals.caepAction(). ' + name);
    const asked = body || {};
    if (name === 'emit') {
      log.debug("Leaving SharedSignals.caepAction().");
      return this.caepEmit(asked);
    }
    if (name === 'reset-session') {
      const row: Json = caep.reset(String(asked.session_id || ''));
      if (!row) {
        log.debug('Leaving SharedSignals.caepAction(). No such session.');
        return this.actionRefused('STS-SSF-0054', 'CAEP', name, { ok: false,
          errors: ['No session "' + String(asked.session_id || '') + '" is ' +
                   'tracked here.'] });
      }
      log.debug('Leaving SharedSignals.caepAction(). Reset.');
      return Promise.resolve({ ok: true, errors: [],
        message: 'The CAEP state of session ' + row.sessionId + ' was reset. ' +
          'The sign-in itself is untouched — this page is about what has ' +
          'been ' +
          'SAID about that session, and nobody has been signed out.' });
    }
    if (name === 'clear') {
      const gone = caep.clear();
      log.debug('Leaving SharedSignals.caepAction(). Cleared.');
      return Promise.resolve({ ok: true, errors: [],
        message: gone + ' session row(s) dropped. Nothing was signed out: ' +
          'this register is a record of what was said, and clearing it ' +
          'forgets the record rather than ending anything.' });
    }
    // Spelled the way every other action handler here spells it, with the count
    // from the list rather than from a word typed beside it. That sentence is
    // READ — `tests/vendored/admin_api.js` requires /unknown action/i before it
    // will parse the list, and `sts_admin_api_operations.js` matches the whole
    // shape — so a handler that writes it its own way turns two checks off with
    // nothing failing.
    log.debug('Leaving SharedSignals.caepAction(). Unknown action.');
    return this.actionRefused('STS-SSF-0055', 'CAEP', name, { ok: false,
      errors: ['Unknown action "' + String(name) + '". The ' +
        numberWord(SharedSignals.CAEP_CONSOLE_ACTIONS.length) + ' are: ' +
        SharedSignals.CAEP_CONSOLE_ACTIONS.join(', ') + '.'] });
  }

  // ---------------------------------------------------------------------------
  // THE SECOND THING THIS SERVICE DOES WITHOUT BEING ASKED, AND IT IS ASKED FOR
  // BY A DIFFERENT EVENT ENTIRELY.
  //
  // CAEP made this service emit because somebody signed in, presented a session
  // or signed out — three acts in the AUTHENTICATION layer, all reached through
  // `authn.startSession()` and its two siblings. RISC makes it emit because its
  // own DIRECTORY changed: a person deleted, an account marked inactive, a mail
  // address moved. Those are acts in the PROVISIONING layer and they reach this
  // service over SCIM, over LDAP and from the console alike, which is why the
  // observer sits on `ldap_server.js`'s store rather than on any one door.
  //
  // **THE DIVISION OF LABOUR IS `caepAutoEmit()`'s EXACTLY**, with one
  // difference that is the specification's rather than this file's: `observe()`
  // answers with a LIST. One directory write can be two RISC events — `active`
  // going false AND an identifier moving — and a version of this that took the
  // first would drop the second silently, which in a protocol with no
  // missing-event error is a transmitter that lies by omission.
  //
  // **IT RETURNS A PROMISE AND NOBODY AWAITS IT**, for the reason the CAEP half
  // gives: `ldap_server.js` calls this from inside a write and does not wait,
  // because a push delivery takes as long as somebody else's endpoint does and
  // an `ldapmodify` that blocked on a receiver's TCP timeout would be a
  // directory whose writes depend on a third party being up.
  // ---------------------------------------------------------------------------
  riscAutoEmit(notice?: Json): Promise<EmitResult> {
    const { log, risc, errorCodes } = this.deps;
    log.debug('Entering SharedSignals.riscAutoEmit().');
    if (!this.enabled()) {
      log.debug('Leaving SharedSignals.riscAutoEmit(). SSF is off.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    // THE ISSUER IS ADDED HERE AND NOT IN `ldap_server.js`, because it is an
    // SSF fact and the directory has no business knowing one. It matters for
    // the same reason it does in the CAEP half: an `iss_sub` subject names the
    // person by ISSUER and subject, and a receiver matches that `iss` against
    // the issuer it discovered.
    const due: Json = risc.observe(Object.assign({}, notice || {},
        { issuer: this.issuerFor(null) }));
    if (!due.length) {
      log.debug('Leaving SharedSignals.riscAutoEmit(). Nothing is due.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    log.debug("Leaving SharedSignals.riscAutoEmit().");
    return Promise.all(due.map((one) => {
      return this.sendOneRiscEvent(one);
    })).then((results) => {
      const sent = results.reduce((total, one) => {
        return total + one.sent;
      }, 0);
      log.debug('Leaving SharedSignals.riscAutoEmit(). ' + sent + ' sent.');
      return { sent: sent, streams: results.length, results: results };
    }).catch((e) => {
      log.debug('Caught in SharedSignals.riscAutoEmit(): ' +
                ((e && e.message) || e));
      // Swallowed here as well as in `ldap_server.js`'s noteAccountChange(),
      // and not redundantly: that catch covers this function throwing
      // synchronously and this one covers a rejected promise nobody is waiting
      // on, which node reports as an unhandled rejection and — depending on the
      // flags — ends the process.
      log.error(errorCodes.tag('STS-SSF-0063') +
                'risc: automatic emission failed: ' + e.message);
      log.debug('Leaving SharedSignals.riscAutoEmit(). Failed.');
      return { sent: 0, streams: 0, why: e.message };
    });
  }

  // One due event onto every stream that agreed to the type and covers the
  // account. Split out of riscAutoEmit() because that function now has a list
  // to walk and the body was the same three paragraphs each time round.
  private sendOneRiscEvent(due: Json): Promise<EmitResult> {
    const { log, subjects, events, risc, streams } = this.deps;
    log.debug('Entering SharedSignals.sendOneRiscEvent(). ' + due.uri);
    const candidates = streams.listStreams().filter((record) => {
      return streams.deliversEvent(record, due.uri) &&
             streams.streamCoversSubject(record, due.subject);
    });
    if (!candidates.length) {
      // SAID ONCE, AT INFO, and it is the most useful line this feature
      // produces, for the reason the CAEP half's is: "nothing arrived" is the
      // commonest report about any Shared Signals deployment and its commonest
      // cause is this — the act happened, the transmitter built the event, and
      // no stream had asked for that type or covered that subject.
      log.info('risc: a ' + due.uri.slice(events.RISC_PREFIX.length) + ' is ' +
               'due for account ' + due.row.accountId + ' and NO STREAM ' +
               'takes it — ' + streams.listStreams().length +
               ' stream(s) exist, and ' +
               'none both delivers that type and covers ' +
               subjects.describeSubject(due.subject) + '. The event is ' +
               'recorded on /admin/risc-accounts with nothing sent.');
      due.row.notes.push('A ' + due.uri.slice(events.RISC_PREFIX.length) +
          ' was due and no stream takes it.');
      due.row.notes = due.row.notes.slice(-5);
      // AND THE REGISTER STILL FOLLOWS THE ACT. The ordinary path applies the
      // state on the way back through `noteTransmitted()`, which reads a token
      // that here was never built — so without this line, deleting a person
      // from a service with no RISC stream agreed would leave a row saying the
      // account is still active. Nothing would fail; the page would simply be
      // wrong about it, and being wrong would look exactly like a service where
      // nothing had been deleted. See risc.applyDue().
      risc.applyDue(due);
      log.debug('Leaving SharedSignals.sendOneRiscEvent(). ' +
                'No stream takes it.');
      return Promise.resolve({ sent: 0, streams: 0, uri: due.uri });
    }
    log.debug("Leaving SharedSignals.sendOneRiscEvent().");
    return Promise.all(candidates.map((record) => {
      return this.transmit(record, { uri: due.uri, payload: due.payload,
        subject: due.subject, toe: due.payload.event_timestamp });
    })).then((reports) => {
      const sent = reports.filter((one) => {
        return one.ok;
      }).length;
      log.info('risc: ' + due.uri.slice(events.RISC_PREFIX.length) + ' for ' +
               'account ' + due.row.accountId + ' went to ' + sent + ' of ' +
               candidates.length + ' stream(s).');
      log.debug('Leaving SharedSignals.sendOneRiscEvent(). ' + sent + ' sent.');
      return { sent: sent, streams: candidates.length, uri: due.uri,
        reports: reports };
    });
  }

  // ---------------------------------------------------------------------------
  // WHAT AN ADMINISTRATOR DID TO SOMEBODY'S CREDENTIALS, SAID OVER RISC AND
  // CAEP (2026-09-13).
  //
  // A password reset, a reset link, a key or an authenticator app taken off,
  // every second factor disabled — performed on a person's /admin/users page or
  // through /admin-api/users, and the password a reset link sets on
  // /portal/reset-password. None of those is a directory write RISC's observer
  // can read a meaning off (a password hash moving says nothing about who
  // required what) and none is a SESSION CAEP's register could hang an event
  // on, so the two functions below are asked by name, through
  // `ssf/account_signals.ts`, by the doors that know what they did.
  //
  // **THEY TAKE THE SAME SWITCHES THE AUTOMATIC EMISSIONS DO.** `caep.autoEmit`
  // and `caep.autoEmitTypes` (the act `credential`), `risc.autoEmit` and
  // `risc.autoEmitTypes` (`credentialChangeRequired`, `recoveryChanged`), the
  // RISC opt-out gate, and every stream's own agreed types and subjects. So
  // "which streams get it" has one answer however the event came about.
  //
  // **THEY NEVER REJECT**, for `riscAutoEmit()`'s reason: the credential change
  // has already happened, and a receiver's push endpoint being down must not
  // turn it into a failure on the page that made it.
  // ---------------------------------------------------------------------------
  emitRiscAccountAct(notice?: Json): Promise<EmitResult> {
    const { log, risc, errorCodes } = this.deps;
    log.debug('Entering SharedSignals.emitRiscAccountAct().');
    if (!this.enabled()) {
      log.debug('Leaving SharedSignals.emitRiscAccountAct(). SSF is off.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    let due;
    try {
      due = risc.observeAct(Object.assign({}, notice || {},
                                          { issuer: this.issuerFor(null) }));
    } catch (e) {
      log.debug('Caught in SharedSignals.emitRiscAccountAct(): ' +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SSF-0090') + 'risc: an administrator\'s ' +
                'act could not be turned into an event: ' + e.message);
      log.debug('Leaving SharedSignals.emitRiscAccountAct(). Failed.');
      return Promise.resolve({ sent: 0, streams: 0, why: e.message });
    }
    if (!due.length) {
      log.debug('Leaving SharedSignals.emitRiscAccountAct(). Nothing is due.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    log.debug('Leaving SharedSignals.emitRiscAccountAct().');
    return Promise.all(due.map((one) => {
      return this.sendOneRiscEvent(one);
    })).then((results) => {
      const sent = results.reduce((total, one) => {
        return total + one.sent;
      }, 0);
      return { sent: sent, streams: results.length, results: results };
    }).catch((e) => {
      log.debug('Caught in SharedSignals.emitRiscAccountAct(): ' +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SSF-0090') + 'risc: an administrator\'s ' +
                'act could not be delivered: ' + e.message);
      return { sent: 0, streams: 0, why: e.message };
    });
  }

  // CAEP's credential-change, about a PERSON. The subject is SSF's complex one
  // with only `user` in it — the issuer/subject pair a receiver already holds
  // from an ID Token — which is what `caep.ts`'s own subject is minus the
  // session, so a stream that names the person covers it by the member rule in
  // `streamCoversSubject()`, exactly as it covers that person's sessions.
  emitCredentialChange(asked?: Json): Promise<EmitResult> {
    const { log, audit, subjects, events, caep, streams,
            errorCodes } = this.deps;
    const { subjectForName: helpersSubjectFor } = this.deps.helpers;
    log.debug('Entering SharedSignals.emitCredentialChange().');
    const options = asked || {};
    const username = String(options.username || '');
    if (!this.enabled() || !username) {
      log.debug('Leaving SharedSignals.emitCredentialChange(). ' +
                'SSF is off or nobody named.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    if (caep.autoEmitActs().indexOf('credential') < 0) {
      log.info('caep: a credential-change about ' + username + ' was NOT ' +
               'emitted: caep.enabled, caep.autoEmit or caep.autoEmitTypes ' +
               'excludes it.');
      log.debug('Leaving SharedSignals.emitCredentialChange(). ' +
                'Not an emitted act.');
      return Promise.resolve({ sent: 0, streams: 0, why: 'not emitted' });
    }
    const uri = events.CAEP_PREFIX + 'credential-change';
    let payload;
    try {
      payload = caep.buildPayload(uri, {
        credential_type: String(options.credentialType || 'password'),
        change_type: String(options.changeType || 'update'),
        friendly_name: String(options.friendlyName || '')
      }, {
        initiatingEntity: String(options.initiatingEntity || 'admin'),
        reasonAdmin: String(options.reasonAdmin || ''),
        reasonUser: String(options.reasonUser || '')
      });
    } catch (e) {
      log.debug('Caught in SharedSignals.emitCredentialChange(): ' +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SSF-0091') + 'caep: a credential-change ' +
                'about ' + username + ' could not be built: ' + e.message);
      log.debug('Leaving SharedSignals.emitCredentialChange(). Not built.');
      return Promise.resolve({ sent: 0, streams: 0, why: e.message });
    }
    const verdict: Json = events.validateEvent(uri, payload);
    if (!verdict.ok) {
      log.error(errorCodes.tag('STS-SSF-0091') + 'caep: a credential-change ' +
                'about ' + username + ' is not a valid event: ' +
                verdict.errors.join(' '));
      log.debug('Leaving SharedSignals.emitCredentialChange(). Invalid.');
      return Promise.resolve({ sent: 0, streams: 0,
                               why: verdict.errors.join(' ') });
    }
    // The person's own subject, as every token names them (2026-09-14).
    const subject = { user: { format: 'issuer_subject_id',
      iss: this.issuerFor(null),
      sub: helpersSubjectFor(username) || username } };
    const candidates = streams.listStreams().filter((record) => {
      return streams.deliversEvent(record, uri) &&
             streams.streamCoversSubject(record, subject);
    });
    audit.audit({ action: 'caep.event.auto', category: 'signals',
      protocol: 'CAEP', channel: 'http', target: username,
      summary: 'A CAEP credential-change (' + payload.credential_type + ', ' +
        payload.change_type + ') is due for ' + username,
      detail: { type: uri, streams: candidates.length,
                via: String(options.via || '') } });
    if (!candidates.length) {
      log.info('caep: a credential-change about ' + username +
               ' is due and NO ' +
               'STREAM takes it — none both delivers that type and covers ' +
               subjects.describeSubject(subject) + '.');
      log.debug('Leaving SharedSignals.emitCredentialChange(). ' +
                'No stream takes it.');
      return Promise.resolve({ sent: 0, streams: 0 });
    }
    log.debug('Leaving SharedSignals.emitCredentialChange().');
    return Promise.all(candidates.map((record) => {
      return this.transmit(record, { uri: uri, payload: payload,
        subject: subject,
        toe: payload.event_timestamp });
    })).then((reports) => {
      const sent = reports.filter((one) => {
        return one.ok;
      }).length;
      log.info('caep: credential-change (' + payload.credential_type + ', ' +
               payload.change_type + ') about ' + username + ' went to ' +
               sent + ' of ' + candidates.length + ' stream(s).');
      return { sent: sent, streams: candidates.length, reports: reports };
    }).catch((e) => {
      log.debug('Caught in SharedSignals.emitCredentialChange(): ' +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SSF-0091') + 'caep: a credential-change ' +
                'about ' + username + ' could not be delivered: ' + e.message);
      return { sent: 0, streams: candidates.length, why: e.message };
    });
  }

  // ---------------------------------------------------------------------------
  // THE RISC CONSOLE AND MANAGEMENT API.
  //
  // `/admin/risc`, `/admin/risc-accounts` and `/admin-api/risc` reach this
  // directory through `admin.setRiscReporter()`, the TENTH slot, for exactly
  // the reasons the eighth and ninth exist: a require from `admin.js` to this
  // file would close a cycle, and one from `mgmt-api/admin_api.ts` would have
  // moved every `/ssf` route ahead of the management API's own — until #50's
  // R1; it would now move this family's LOAD to 19 instead.
  // ---------------------------------------------------------------------------

  // WHAT THIS TRANSMITTER HAS SAID TO EACH RECEIVER ABOUT ACCOUNTS. It is
  // `caepApplications()`'s shape and it is a second function rather than a
  // parameter on that one, because the two answer different questions about
  // different registers and a single function taking a vocabulary would be the
  // branch this whole directory is written to avoid.
  private riscApplications(): Json[] {
    const { log, applications, events, risc, streams } = this.deps;
    log.debug('Entering SharedSignals.riscApplications().');
    const riscUris = events.RISC_EVENT_URIS;
    const all = streams.listStreams();

    const accountsByStream = {};
    risc.list().forEach((row) => {
      (row.streams || []).forEach((id) => {
        if (!accountsByStream[id]) {
          accountsByStream[id] = {};
        }
        accountsByStream[id][row.accountId] = true;
      });
    });

    function blank(identifier, name, registered) {
      log.debug("Entering blank().");
      const counts = {};
      riscUris.forEach((uri) => {
        counts[uri] = 0;
      });
      log.debug("Leaving blank().");
      return { identifier: identifier, name: name, registered: registered,
        dn: '', declared: false, streams: [], streamCount: 0, enabled: 0,
        deliveries: [], audiences: [], takes: [], counts: counts, total: 0,
        accounts: 0, queued: 0, delivered: 0, failed: 0, acknowledged: 0,
        receiverErrors: 0, lastPushAt: '', lastPushError: '' };
    }

    const rows = {};
    const order = [];
    function rowFor(identifier, name, registered) {
      log.debug("Entering rowFor().");
      if (!rows[identifier]) {
        rows[identifier] = blank(identifier, name, registered);
        order.push(identifier);
      }
      log.debug("Leaving rowFor().");
      return rows[identifier];
    }

    applications.list().forEach((entry) => {
      const declared = (entry.allowedProtocols || []).indexOf('ssf') >= 0;
      const seen = (entry.recordedProtocols || []).indexOf('ssf') >= 0;
      const receiverId =
          ((entry.attributes || {}).ssfReceiverId || [])[0] || '';
      if (!declared && !seen && !receiverId) {
        return;
      }
      const row = rowFor(receiverId || entry.identifier,
                         entry.name || entry.identifier, true);
      row.dn = entry.dn || '';
      row.declared = declared;
      row.endpoints = ((entry.attributes || {}).ssfDeliveryEndpoint || [])
        .slice();
    });

    const NOBODY = '(no application — the stream was agreed unauthenticated)';
    all.forEach((record) => {
      const who = String(record.createdBy || '');
      const known = who && who !== '(unauthenticated)';
      const row = rowFor(known ? who : NOBODY, known ? who : NOBODY, false);
      row.streams.push(record.stream_id);
      row.streamCount += 1;
      if (record.status === 'enabled') {
        row.enabled += 1;
      }
      const delivery = streams.deliveryName(record.delivery.method);
      if (row.deliveries.indexOf(delivery) < 0) {
        row.deliveries.push(delivery);
      }
      const aud = Array.isArray(record.aud) ? record.aud.join(' ')
                                            : String(record.aud || '');
      if (aud && row.audiences.indexOf(aud) < 0) {
        row.audiences.push(aud);
      }
      riscUris.forEach((uri) => {
        if (streams.deliversEvent(record, uri)) {
          const short = uri.slice(events.RISC_PREFIX.length);
          if (row.takes.indexOf(short) < 0) {
            row.takes.push(short);
          }
        }
        const n = (record.eventCounts || {})[uri] || 0;
        row.counts[uri] += n;
        row.total += n;
      });
      row.queued += record.counters.queued;
      row.delivered += record.counters.delivered;
      row.failed += record.counters.failed;
      row.acknowledged += record.counters.acknowledged;
      row.receiverErrors += record.counters.receiverErrors;
      if (record.lastPushAt > row.lastPushAt) {
        row.lastPushAt = record.lastPushAt;
      }
      if (record.lastPushError) {
        row.lastPushError = record.lastPushError;
      }
    });

    order.forEach((identifier) => {
      const row = rows[identifier];
      const seen = {};
      row.streams.forEach((id) => {
        Object.keys(accountsByStream[id] || {}).forEach((accountId) => {
          seen[accountId] = true;
        });
      });
      row.accounts = Object.keys(seen).length;
    });

    const out = order.map((identifier) => {
      return rows[identifier];
    });
    out.sort((a, b) => {
      if (b.total !== a.total) {
        return b.total - a.total;
      }
      if (b.streamCount !== a.streamCount) {
        return b.streamCount - a.streamCount;
      }
      return String(a.identifier).localeCompare(String(b.identifier));
    });
    log.debug('Leaving SharedSignals.riscApplications(). ' +
              '' + out.length + ' receiver(s).');
    return out;
  }

  riscReport(req?: Req): Json {
    const { log, subjects, events, risc, streams } = this.deps;
    log.debug('Entering SharedSignals.riscReport().');
    const report: Json = risc.report();
    report.issuer = this.issuerFor(req);
    report.ssfEnabled = this.enabled();
    report.applications = this.riscApplications();
    report.streams = streams.listStreams().map((record) => {
      const takes = events.RISC_EVENT_URIS.filter((uri) => {
        return streams.deliversEvent(record, uri);
      });
      return { stream_id: record.stream_id, aud: record.aud,
        status: record.status, delivery: record.delivery.method,
        subjects: record.subjects.length,
        takes: takes.map((uri) => {
          return uri.slice(events.RISC_PREFIX.length);
        }) };
    });
    log.debug('Leaving SharedSignals.riscReport(). ' +
              '' + report.tracked + ' account(s).');
    return report;
  }

  // ---------------------------------------------------------------------------
  // EMIT ONE RISC EVENT BY HAND.
  //
  // Eight of the fourteen describe things nothing here does — no breach corpus
  // is searched by this service and no recovery flow runs in it — so this is
  // the only way they are produced (the other six are `risc.autoEmitTypes`).
  // **AND FOUR OF THOSE EIGHT CHANGE REAL STATE WHEN THEY GO**: RISC section
  // 2.8 defines each opt-out event as *"the account is in the X state"* rather
  // than as a report that it moved, so emitting one is the transition. That is
  // why `applyToState()` runs on the way out and not only on the way back
  // through `noteTransmitted()`.
  //
  // **AN ACCOUNT THIS SERVICE HAS NEVER HELD IS ACCEPTED**, which is the
  // opposite of what `caepEmit()` does with an unknown session, and the reason
  // is what the two events are ABOUT. A CAEP event names a session, and a
  // session identifier this service never minted is one it can compose no
  // subject from. An account is a person, this service can name any person at
  // all, and a debugger pointed at this transmitter is entitled to ask it to
  // say something about somebody who has never signed in — which is exactly the
  // state a RISC receiver is in most of the time, since RISC is aimed ACROSS
  // providers and the account it warns you about is usually one you have never
  // seen.
  // ---------------------------------------------------------------------------
  private riscEmit(asked: Json): Promise<Json> {
    const { log, audit, subjects, events, caep, risc, streams } = this.deps;
    log.debug('Entering SharedSignals.riscEmit().');
    const uri = String(asked.type || '').indexOf(events.RISC_PREFIX) === 0
      ? String(asked.type)
      : events.RISC_PREFIX + String(asked.type || '');
    const row: Json = events.EVENT_BY_URI[uri];
    if (!row || row.family !== 'risc') {
      log.debug('Leaving SharedSignals.riscEmit(). Not a RISC event type.');
      return this.actionRefused('STS-SSF-0057', 'RISC', 'emit', { ok: false,
        errors: [
        '"' + String(asked.type || '') + '" is not one of RISC\'s fourteen ' +
        'event types. They are: ' + events.RISC_EVENT_URIS.map((one) => {
          return one.slice(events.RISC_PREFIX.length);
        }).join(', ') + '.'] });
    }
    const accountId = String(asked.account_id || '');
    if (!accountId) {
      log.debug('Leaving SharedSignals.riscEmit(). No account named.');
      return this.actionRefused('STS-SSF-0058', 'RISC', 'emit', { ok: false,
        errors: [
        'A RISC event is ABOUT an account — the subject names one and, for ' +
        'eleven of the fourteen types, the subject is the entire message — ' +
        'so ' +
        'there is nothing to compose one from. Name an account, or pick a ' +
        'row ' +
        'from /admin/risc-accounts.'] });
    }
    const known: Json = risc.rowFor(accountId, { iss: this.issuerFor(null) });
    let values = asked.payload;
    if (typeof values === 'string' && values.trim()) {
      try {
        values = JSON.parse(values);
      } catch (e) {
        log.debug('Caught in SharedSignals.riscEmit(): ' +
                  ((e && e.message) || e));
        log.debug('Leaving SharedSignals.riscEmit(). The payload is not JSON.');
        return this.actionRefused('STS-SSF-0047', 'RISC', 'emit', { ok: false,
          errors: ['The event payload is not JSON: ' + e.message] });
      }
    }
    const payload: Json = risc.buildPayload(uri, values || {}, {
      reasonAdmin: String(asked.reason_admin || '') ||
        'Emitted by hand from the console.',
      reasonUser: String(asked.reason_user || '')
    });
    const verdict: Json = events.validateEvent(uri, payload);
    if (!verdict.ok) {
      log.debug('Leaving SharedSignals.riscEmit(). The payload is invalid.');
      return this.actionRefused('STS-SSF-0052', 'RISC', 'emit',
                           { ok: false, errors: verdict.errors });
    }
    // THE STATE MACHINE'S ONE HARD RULE, ASKED BEFORE ANYTHING IS BUILT. The
    // register is updated on the way BACK through `noteTransmitted()`, so a
    // refusal enforced only there would fire on an event that has already been
    // signed, queued and delivered — which is not a refusal, it is a note in a
    // log about something a receiver has already acted on. See risc.refusals().
    const hard = risc.refusals(known, uri);
    if (hard.length) {
      log.debug('Leaving SharedSignals.riscEmit(). ' +
                'Refused by the state machine.');
      return this.actionRefused('STS-SSF-0059', 'RISC', 'emit',
                           { ok: false, errors: hard });
    }
    const subject = risc.subjectFor(known, uri);
    const advice = events.subjectAdvice(uri, subject)
      .concat(verdict.warnings || []);
    // THE GATE RUNS BEFORE THE STREAMS ARE LOOKED AT, deliberately: an account
    // that has opted out is one this transmitter has agreed to stop talking
    // about, and "no stream takes it" would be the wrong reason to report.
    //
    // **AND A SUPPRESSED EVENT CHANGES NO STATE HERE, WHERE A SUPPRESSED
    // AUTOMATIC ONE DOES.** That looks inconsistent and is the honest reading
    // of what each path is about. In `risc.observe()` the DIRECTORY really
    // changed — somebody was deleted, `active` really did go false — so the
    // register follows the act whether or not anybody was told, which is the
    // same rule `caep.ts`'s observer follows and the reason a row can show a
    // state nobody received an event about. Here the act IS the emission:
    // nothing happened except that somebody asked this service to say
    // something, and it did not. Applying the state would leave a register
    // asserting that an account was purged on the strength of a message that
    // was never sent.
    const allowed: Json = risc.gate(known, uri);
    if (!allowed.send) {
      known.suppressed += 1;
      log.debug('Leaving SharedSignals.riscEmit(). ' +
                'Suppressed by the opt-out gate.');
      return this.actionRefused('STS-SSF-0060', 'RISC', 'emit',
                           { ok: false, errors: [allowed.why],
                             warnings: advice });
    }
    const candidates = streams.listStreams().filter((record) => {
      return streams.deliversEvent(record, uri) &&
             streams.streamCoversSubject(record, subject);
    });
    audit.audit({ action: 'risc.event.emit', category: 'signals',
      protocol: 'RISC', channel: 'http', target: accountId,
      summary: 'A RISC ' + row.name + ' was emitted by hand for account ' +
        accountId,
      detail: { type: uri, streams: candidates.length } });
    if (!candidates.length) {
      // The register is still told, so the page shows the state change even
      // though nothing was sent — which is what makes "nothing arrived"
      // traceable to "nobody asked" rather than to a bug.
      const applied: Json = risc.applyToState(known, uri, payload);
      log.debug('Leaving SharedSignals.riscEmit(). No stream takes it.');
      if (!applied.ok) {
        // The same hard rule risc.refusals() applies above, reached from the
        // register's own copy of it — one condition, one code.
        audit.failure('STS-SSF-0059', {
          protocol: 'RISC', channel: 'http',
          target: accountId,
          summary: 'A hand-emitted RISC ' + row.name + ' was refused by the ' +
            'account register for account ' + accountId,
          detail: { type: uri, why: applied.errors.join(' ') } });
      }
      log.debug("Leaving SharedSignals.riscEmit().");
      return Promise.resolve({ ok: applied.ok, errors: applied.errors,
        warnings: applied.warnings.concat(advice),
        message: applied.ok
          ? 'Nothing was sent: no stream both delivers "' +
            uri.slice(events.RISC_PREFIX.length) + '" and covers ' +
            subjects.describeSubject(subject) + '. The account\'s state was ' +
            'still updated, so the change is on this page.'
          : applied.errors.join(' ') });
    }
    log.debug("Leaving SharedSignals.riscEmit().");
    return Promise.all(candidates.map((record) => {
      return this.transmit(record, { uri: uri, payload: payload,
        subject: subject,
        toe: payload.event_timestamp });
    })).then((reports) => {
      const sent = reports.filter((one) => {
        return one.ok;
      }).length;
      log.debug('Leaving SharedSignals.riscEmit(). ' +
                '' + sent + ' of ' + reports.length + '.');
      return { ok: sent > 0,
        errors: sent > 0 ? [] : reports.map((one) => {
          return one.why;
        }),
        warnings: advice,
        message: sent + ' of ' + reports.length + ' stream(s) took the ' +
          row.name + '.',
        reports: reports };
    });
  }

  riscAction(name: string, body?: Json): Promise<Json> {
    const { log, risc } = this.deps;
    const { numberWord } = this.deps.helpers;
    log.debug('Entering SharedSignals.riscAction(). ' + name);
    const asked = body || {};
    if (name === 'emit') {
      log.debug("Leaving SharedSignals.riscAction().");
      return this.riscEmit(asked);
    }
    if (name === 'reset-account') {
      const row: Json = risc.reset(String(asked.account_id || ''));
      if (!row) {
        log.debug('Leaving SharedSignals.riscAction(). No such account.');
        return this.actionRefused('STS-SSF-0061', 'RISC', name, { ok: false,
          errors: ['No account "' + String(asked.account_id || '') + '" is ' +
                   'tracked here.'] });
      }
      log.debug('Leaving SharedSignals.riscAction(). Reset.');
      return Promise.resolve({ ok: true, errors: [],
        message: 'The RISC state of account ' + row.accountId + ' was reset. ' +
          'The directory entry is untouched — this page is about what has ' +
          'been SAID about that account, and nobody has been disabled or ' +
          'deleted.' });
    }
    if (name === 'clear') {
      const gone = risc.clear();
      log.debug('Leaving SharedSignals.riscAction(). Cleared.');
      return Promise.resolve({ ok: true, errors: [],
        message: gone + ' account row(s) dropped. Nothing in the directory ' +
          'changed: this register is a record of what was said, and clearing ' +
          'it forgets the record rather than deleting anybody.' });
    }
    // Spelled the way every other action handler here spells it, with the count
    // from the list rather than from a word typed beside it. That sentence is
    // READ by `tests/vendored/admin_api.js` and by
    // `sts_admin_api_operations.js`, so a handler that writes it its own way
    // turns two checks off with nothing failing.
    log.debug('Leaving SharedSignals.riscAction(). Unknown action.');
    return this.actionRefused('STS-SSF-0062', 'RISC', name, { ok: false,
      errors: ['Unknown action "' + String(name) + '". The ' +
        numberWord(SharedSignals.RISC_CONSOLE_ACTIONS.length) + ' are: ' +
        SharedSignals.RISC_CONSOLE_ACTIONS.join(', ') + '.'] });
  }

  // Monitoring → Shared Signals → Dead letters and
  // GET /admin-api/ssf/dead-letters (2026-09-14), read inside the ambient
  // realm. A member of THE SIGNALS SLOT rather than a slot of its own: it
  // reads the same family through the same require, and rule 3e's test for a
  // new slot is a new cycle or a moved route, neither of which a second reader
  // adds.
  deadLetters(): Json {
    const { log, deadLetterReport } = this.deps;
    log.debug('Entering SharedSignals.deadLetters().');
    const out: Json = deadLetterReport.report();
    log.debug('Leaving SharedSignals.deadLetters(). ' + out.totals.held +
              ' held.');
    return out;
  }

  // Every event type, and whether this transmitter offers it: the signals
  // slot's `eventTypes`.
  signalEventTypes(): Json[] {
    const { log, events } = this.deps;
    log.debug("Entering SharedSignals.signalEventTypes().");
    log.debug("Leaving SharedSignals.signalEventTypes().");
    return events.EVENTS.map(function (row) {
      return { uri: row.uri, name: row.name,
        offered: events.supportedEventUris().indexOf(row.uri) >= 0 };
    });
  }

  // CAEP's eight, with their members: the CAEP slot's `eventTypes`.
  caepEventTypes(): Json[] {
    const { log, events } = this.deps;
    log.debug("Entering SharedSignals.caepEventTypes().");
    log.debug("Leaving SharedSignals.caepEventTypes().");
    return events.CAEP_EVENTS.map(function (row) {
      return { uri: row.uri, name: row.name,
        short: row.uri.slice(events.CAEP_PREFIX.length),
        subject: row.subject,
        offered: events.supportedEventUris().indexOf(row.uri) >= 0,
        members: row.members.map(function (member) {
          return { name: member.name, required: !!member.required,
            type: member.type, values: member.values || [],
            what: member.what };
        }),
        required: row.required.slice(),
        what: row.what };
    });
  }

  // RISC's fourteen, with their members: the RISC slot's `eventTypes`.
  riscEventTypes(): Json[] {
    const { log, events } = this.deps;
    log.debug("Entering SharedSignals.riscEventTypes().");
    log.debug("Leaving SharedSignals.riscEventTypes().");
    return events.RISC_EVENTS.map(function (row) {
      return { uri: row.uri, name: row.name,
        short: row.uri.slice(events.RISC_PREFIX.length),
        subject: row.subject,
        subjectFormats: (row.subjectFormats || []).slice(),
        deprecated: String(row.deprecated || ''),
        offered: events.supportedEventUris().indexOf(row.uri) >= 0,
        members: row.members.map(function (member) {
          return { name: member.name, required: !!member.required,
            type: member.type, values: member.values || [],
            what: member.what };
        }),
        required: row.required.slice(),
        what: row.what };
    });
  }

  // -------------------------------------------------------------------------
  // WHAT THIS FILE HANDS TO OTHER MODULES AT REQUIRE TIME, in the order the
  // original filled them: the console's signals slot, `authn`'s session
  // observer, the console's CAEP slot, the directory's account observer and
  // the console's RISC slot. The reasons for each are above the method each
  // one carries (consoleReport(), caepAutoEmit(), caepReport(),
  // riscAutoEmit(), riscReport()).
  // -------------------------------------------------------------------------
  installHooks(): void {
    const { log, adminConsole, authn, directory, events,
            subjects } = this.deps;
    log.debug('Entering SharedSignals.installHooks().');
    adminConsole.setSignalsReporter({
      report: this.consoleReport.bind(this),
      // See deadLetters().
      deadLetters: this.deadLetters.bind(this),
      action: this.consoleAction.bind(this),
      actions: SharedSignals.CONSOLE_ACTIONS,
      eventTypes: this.signalEventTypes.bind(this),
      statuses: events.STATUSES,
      subjectFormats: subjects.FORMATS
    });

    // The inverted hook, filled at require time. `authn.js` is 8 in the
    // require order and this module is 23b, so this is the only direction
    // that works — see setSessionObserver()'s header over there.
    authn.setSessionObserver(this.caepAutoEmit.bind(this));

    adminConsole.setCaepReporter({
      report: this.caepReport.bind(this),
      action: this.caepAction.bind(this),
      actions: SharedSignals.CAEP_CONSOLE_ACTIONS,
      eventTypes: this.caepEventTypes.bind(this)
    });

    // The inverted hook, filled at require time. `ldap/ldap_server.js` is 21
    // in the require order and this module is 23b, so the require above goes
    // the ordinary way and only the FUNCTION travels back — see
    // setAccountObserver() over there.
    directory.setAccountObserver(this.riscAutoEmit.bind(this));

    adminConsole.setRiscReporter({
      report: this.riscReport.bind(this),
      action: this.riscAction.bind(this),
      actions: SharedSignals.RISC_CONSOLE_ACTIONS,
      eventTypes: this.riscEventTypes.bind(this)
    });
    log.debug('Leaving SharedSignals.installHooks().');
  }

  // =========================================================================
  // AND THIS SERVICE'S OWN TWO SURFACES ARE REGISTERED AS RECEIVERS
  // (2026-09-10).
  //
  // One stream each, per trust realm, asking for every CAEP and every RISC
  // event type. `ssf/ssf_receivers.ts` carries the whole argument — why
  // delivery is a real RFC 8935 push over the loopback interface rather than a
  // function call, why the streams are in every realm, and what an empty inbox
  // page can mean.
  //
  // **THE DEFAULT REALM IS SEEDED HERE AND EVERY LATER REALM FROM
  // `onCreate()`**, which is the arrangement `applications.js`'s internal
  // client entries have and is made for its reason: a realm created at runtime
  // is a whole logical copy of this service, and a copy whose console could
  // not be told anything would be a copy with a page that is empty for a
  // reason nobody could see.
  //
  // It is at require time rather than from `server.js`'s `listen()` because
  // it binds nothing and opens nothing — it writes two rows into a store this
  // process already holds. What it DOES need is `ssf_streams.ts`,
  // `ssf_events.js` and the realm registry, all of which are above this line.
  // =========================================================================
  seedOwnReceivers(): void {
    const { log, receivers, realms } = this.deps;
    log.debug('Entering SharedSignals.seedOwnReceivers().');
    receivers.seedStreams();
    realms.onCreate(function (id) {
      log.debug('Entering the SSF internal receiver seeder. id=' + id);
      realms.run(realms.get(id), function () {
        receivers.seedStreams();
      });
      log.debug('Leaving the SSF internal receiver seeder.');
    });
    log.debug('Leaving SharedSignals.seedOwnReceivers().');
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): SharedSignalsDeps {
    helpers.log.debug("Entering SharedSignals.defaultDeps().");
    helpers.log.debug("Leaving SharedSignals.defaultDeps().");
    return {
      app: app,
      log: helpers.log,
      helpers: helpers,
      config: config,
      realms: realms,
      stats: stats,
      audit: audit,
      applications: applications,
      adminConsole: adminConsole,
      authn: authn,
      subjects: subjects,
      events: events,
      caep: caep,
      risc: risc,
      directory: directory,
      streams: streams,
      receivers: receivers,
      transport: transport,
      deadLetterReport: deadLetterReport,
      ssfAuth: ssfAuth,
      ssfCluster: ssfCluster,
      errorCodes: errorCodes,
      loadCapabilities: function (): Capabilities {
        return require('../cluster/cluster_capabilities');
      }
    };
  }

  // What loading this module did with its instance before R2 (#50), run once
  // for whichever instance is installed, in the original file's order: the
  // sweep, the capability, the hooks, the receivers. The routes, which came
  // between the capability and the hooks, are registered by the composition
  // root right after it installs the instance.
  static wire(instance: SharedSignals): void {
    helpers.log.debug('Entering SharedSignals.wire().');
    instance.scheduleSweep();
    instance.provideCapability();
    instance.installHooks();
    instance.seedOwnReceivers();
    helpers.log.debug('Leaving SharedSignals.wire().');
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
const slot = new InstanceSlot<SharedSignals>(
  'ssf/ssf',
  () => new SharedSignals(SharedSignals.defaultDeps()),
  SharedSignals.wire,
  helpers.log);
// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  installInstance: (instance: SharedSignals): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  SharedSignals: SharedSignals,
  WELL_KNOWN: SharedSignals.WELL_KNOWN,
  metadata: slot.forward('metadata'),
  description: slot.forward('description'),
  transmit: slot.forward('transmit'),
  sweepSignals: slot.forward('sweepSignals'),
  consoleReport: slot.forward('consoleReport'),
  consoleAction: slot.forward('consoleAction'),
  CONSOLE_ACTIONS: SharedSignals.CONSOLE_ACTIONS,
  caepAutoEmit: slot.forward('caepAutoEmit'),
  emitProtocolEvent: slot.forward('emitProtocolEvent'),
  caepReport: slot.forward('caepReport'),
  caepAction: slot.forward('caepAction'),
  CAEP_CONSOLE_ACTIONS: SharedSignals.CAEP_CONSOLE_ACTIONS,
  riscAutoEmit: slot.forward('riscAutoEmit'),
  // What an administrator did to somebody's credentials (2026-09-13); reached
  // through `ssf/account_signals.ts`.
  emitRiscAccountAct: slot.forward('emitRiscAccountAct'),
  emitCredentialChange: slot.forward('emitCredentialChange'),
  riscReport: slot.forward('riscReport'),
  riscAction: slot.forward('riscAction'),
  RISC_CONSOLE_ACTIONS: SharedSignals.RISC_CONSOLE_ACTIONS,
  receivers: receivers
};
