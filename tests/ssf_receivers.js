'use strict';
//
// File: ssf_receivers.js
//
// ===========================================================================
// THIS SERVICE'S OWN TWO SURFACES AS SHARED SIGNALS RECEIVERS, IN PROCESS.
//
// `ssf/ssf_receivers.ts` is what makes the admin console and the user portal
// receivers rather than pages that read this service's own notes: a stream
// each, a receive endpoint each, and an inbox each. Most of that belongs over
// HTTP and is not here — that a sign-in really does put a Security Event Token
// through the loopback push and out the other side is asserted by driving the
// running service, and it was.
//
// ---------------------------------------------------------------------------
// WHAT IS HERE IS THE FOUR THINGS THAT CANNOT BE DRIVEN FROM OUTSIDE.
//
//   * **THE PER-PERSON FILTER, INCLUDING ITS NEGATIVE.** The portal narrows
//     one stream's deliveries to the signed-in person, and the assertion that
//     matters is that somebody ELSE's event is not shown. Over HTTP that needs
//     two signed-in browsers and still only covers the subject shapes those
//     two sign-ins happen to produce; here every shape this service can
//     compose is put in front of it, including the ones a setting has to be
//     changed to reach.
//
//   * **THE FAIL-CLOSED RULE.** An identifier this service cannot resolve to
//     an account — a phone number, an opaque id it did not compose — is NOT a
//     match. That is a decision about a case that produces NOTHING, and a
//     page showing nothing is what a working filter and a broken one look
//     like from outside.
//
//   * **`isOwnLoopback()`, WHICH CARRIES TWO EXEMPTIONS.** A URL that is this
//     process's own address skips `ssf.pushAllowedHosts` and the https rule.
//     The assertion worth having is the refusal — that
//     `https://evil.example/?x=<our own origin>` is not us — and there is no
//     way to ask a running service that question without pointing it at a
//     host called evil.example.
//
//   * **THE INBOX CAP, PER SURFACE.** Both surfaces' rows are in one map, so
//     the bug available is a busy console evicting a quiet portal's signals.
//     Reaching `ssf.maxReceivedEvents` over HTTP means minting two hundred
//     sessions.
//
// The SUBJECT SHAPES are the part to read first. Eleven of RISC's fourteen
// events carry no payload at all, so the subject IS the message — and RISC
// section 3.1 has this service rename `format` to `subject_type` on every RISC
// subject when `risc.googleSubjectType` is on. A filter reading only `format`
// hides every RISC signal from every person the moment that setting goes on,
// silently, which is the exact failure that setting exists to let somebody
// find.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const config = require('../common/config');
// For the derivation a SECOND process of this service would make — see the
// token assertions in section B.
const stsCrypto = require('../common/crypto');
const realms = require('../common/realms');
const transport = require('../ssf/ssf_http');
const streams = require('../ssf/ssf_streams');
const events = require('../ssf/ssf_events');
const receivers = require('../ssf/ssf_receivers');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'ssf_receivers',
  level: process.env.LOG_LEVEL || 'info' });

const ALICE = { username: 'alice', sub: 'urn:sts:user:alice',
                mail: 'alice@example.com' };
const BOB = { username: 'bob', sub: 'urn:sts:user:bob', mail: '' };

// A delivered entry in the shape `accept()` records one, with only the members
// `isAbout()` reads filled in. Written here rather than by pushing a real SET
// because what is under test is the READING of a subject, and a real SET would
// add a signature and a clock to a question about neither.
function delivered(subject, payload, uri) {
  log.debug("Entering delivered().");
  log.debug("Leaving delivered().");
  return { surface: receivers.PORTAL, jti: 'j' + Math.random().toString(16)
    .slice(2, 10), at: new Date().toISOString(),
    claims: { sub_id: subject,
      events: (function () {
        const map = {};
        map[uri || events.CAEP_EVENT_URIS[0]] = payload || {};
        return map;
      })() } };
}

function run(t) {
  log.debug("Entering run().");
  config.setOverride('ssf.enabled', 'true');
  config.setOverride('ssf.internalReceivers', 'true');

  // -----------------------------------------------------------------------
  t.log.info('A. the two surfaces, and what tells them apart');
  // -----------------------------------------------------------------------
  t.equal(receivers.SURFACES.length, 2,
          'there are exactly two internal receivers: the admin console and ' +
          'the user portal');
  t.equal(receivers.surfaceOf(receivers.ADMIN).sees, 'all',
          'the console sees every signal delivered in the realm it is reading');
  t.equal(receivers.surfaceOf(receivers.PORTAL).sees, 'own',
          'the portal shows a person only the signals about them — the one ' +
          'member on these rows with a security consequence, which is why ' +
          'they are two rows rather than one with a loop over it');
  t.equal(receivers.surfaceOf(receivers.ADMIN).audience, 'sts-admin-console',
          'each stream is addressed to the seeded client entry\'s own ' +
          'identifier — a name this service really knows the surface by ' +
          'rather than one invented here, since ssf_streams.js refuses to ' +
          'default an audience at all');
  t.check(!receivers.surfaceOf('no-such-surface'),
          'and an id that is not one of them resolves to nothing rather ' +
          'than to a default');

  // -----------------------------------------------------------------------
  t.log.info('B. the seeded streams');
  // -----------------------------------------------------------------------
  receivers.seedStreams();
  const consoleStream = receivers.streamFor(receivers.ADMIN);
  const portalStream = receivers.streamFor(receivers.PORTAL);
  t.check(!!consoleStream && !!portalStream,
          'seeding puts a stream in this realm for each surface');
  t.check(consoleStream.stream_id !== portalStream.stream_id,
          'and they are two streams rather than one shared — each receiver ' +
          'has its own agreement, its own queue and its own credential');

  const caepOn = events.CAEP_EVENT_URIS.every(function (uri) {
    return consoleStream.events_delivered.indexOf(uri) >= 0;
  });
  const riscOn = events.RISC_EVENT_URIS.every(function (uri) {
    return consoleStream.events_delivered.indexOf(uri) >= 0;
  });
  t.check(caepOn, 'every CAEP event type is delivered on it — all ' +
          events.CAEP_EVENT_URIS.length);
  t.check(riscOn, 'and every RISC event type — all ' +
          events.RISC_EVENT_URIS.length);
  const ssfOn = events.SSF_EVENTS.every(function (row) {
    return consoleStream.events_delivered.indexOf(row.uri) >= 0;
  });
  t.check(ssfOn,
          'AND SSF\'s OWN TWO, which is not scope that crept in: a ' +
          'verification event is the only end-to-end test a stream has, so a ' +
          'receiver that could not be verified could not be shown to work at ' +
          'all');

  t.check(/^Bearer \S+$/.test(consoleStream.delivery.authorization_header),
          'the stream carries an authorization_header this service minted ' +
          'for itself — the one member of a stream configuration that IS a ' +
          'credential, and until these streams existed nothing here ever set ' +
          'one');
  t.check(consoleStream.delivery.authorization_header !==
          portalStream.delivery.authorization_header,
          'and the two are different, so a token that reaches one receiver ' +
          'does not open the other');
  t.equal(consoleStream.delivery.endpoint_url,
          transport.loopbackOrigin() + '/admin/signals/receive',
          'the endpoint is this process\'s own loopback address and the ' +
          'surface\'s receive path');

  const madeAgain = receivers.seedStreams();
  t.equal(madeAgain, 0,
          'SEEDING AGAIN CREATES NOTHING. An existing stream is left exactly ' +
          'as it is — somebody who paused one of these, narrowed it or ' +
          'deleted it meant it, which is applications.js\'s seeding rule ' +
          'word for word');

  // -----------------------------------------------------------------------
  // THE TOKEN IS THE SAME IN EVERY PROCESS OF THIS SERVICE (2026-09-11).
  //
  // `seedStreams()` runs at startup in the front process AND in every request
  // worker, and these streams are minted state, which development mode neither
  // persists nor coordinates — so nothing reconciles them afterwards. With a
  // random token each process seeded a different one, the transmitter ran in
  // one process and the loopback push landed on another, and every push this
  // service made to itself was refused: 132,546 of them in half an hour,
  // measured on 2026-09-11, with nothing anywhere failing because an inbox
  // that was never delivered to and an inbox that refused everything look
  // exactly alike.
  //
  // This is what a second process would compute. It is asserted through the
  // DERIVATION rather than by starting one, because the property is that two
  // processes agree WITHOUT talking — so a test that made them talk would be
  // testing the wrong thing.
  // -----------------------------------------------------------------------
  const secret = process.env.STS_SSF_RECEIVER_SECRET;
  t.check(!!secret,
          'seeding put a per-run secret in the environment, which is how a ' +
          'forked request worker gets it — request_pool.js forks with a copy ' +
          'of process.env');
  const asASibling = 'Bearer ' + stsCrypto.deriveSharedCredential(
    secret, 'ssf-internal-receiver', realms.currentId(), receivers.ADMIN);
  t.equal(consoleStream.delivery.authorization_header, asASibling,
          'AND ANOTHER PROCESS OF THIS SERVICE DERIVES THE SAME TOKEN for ' +
          'the same realm and the same surface, so a push transmitted in one ' +
          'and received in another is not refused');
  t.check(asASibling !== 'Bearer ' + stsCrypto.deriveSharedCredential(
            'a different run\'s secret', 'ssf-internal-receiver',
            realms.currentId(), receivers.ADMIN),
          'while a service started with a different secret derives a ' +
          'different one — the token still dies with the run');
  t.check(asASibling !== 'Bearer ' + stsCrypto.deriveSharedCredential(
            secret, 'ssf-internal-receiver', 'some-other-realm',
            receivers.ADMIN),
          'and a different realm derives a different one, so a token minted ' +
          'for one logical copy of this service does not open another\'s');

  // -----------------------------------------------------------------------
  // -----------------------------------------------------------------------
  // B2. ONE STREAM PER SURFACE HOWEVER MANY PROCESSES SEED IT (2026-09-12).
  //
  // The check above — seed, seed again, nothing made — passes in ONE process
  // and always will: the second call finds the first call's record in the same
  // in-memory store. What it cannot see is the arrangement that actually
  // happens, and the one this service runs in `dispatch` mode: the front
  // process and every request worker load the protocol stack and each calls
  // `seedStreams()`, against a store that is SHARED because it is persisted
  // and coordinated.
  //
  // With a random id each of them created a stream of its own and the store
  // kept them all. Measured on a four-hour test stack: fourteen streams in the
  // default realm where two belong, seven pairs at seven timestamps, and a
  // bulk load pushing every one of 16,421 events to twelve of them.
  //
  // The three claims below are what makes that impossible rather than
  // unlikely.
  // -----------------------------------------------------------------------
  t.log.info('B2. one stream per surface, however many processes seed it');

  const consoleSurface = receivers.SURFACES.filter(function (one) {
    return one.id === 'admin-console';
  })[0];
  const derivedId = 'ssf-internal-' + realms.currentId() + '-admin-console';
  t.equal(consoleStream.stream_id, derivedId,
          'THE ID IS DERIVED FROM THE REALM AND THE SURFACE, so every ' +
          'process of this service computes the same one without being told ' +
          '— which is `receiverToken()`\'s argument, one member along');

  // A SECOND PROCESS, simulated where it matters: the store has the record and
  // this process has never set the marker on it. That is what a freshly forked
  // request worker sees, and with the old lookup it seeded a duplicate.
  const marker = consoleStream.internalSurface;
  delete consoleStream.internalSurface;
  const madeWithoutMarker = receivers.seedStreams();
  t.equal(madeWithoutMarker, 0,
          'A PROCESS THAT NEVER SET THE MARKER STILL FINDS THE STREAM, ' +
          'because the lookup asks for the derived id first — the marker is ' +
          'not an SSF member and is the half of this that a persisted ' +
          'round-trip can lose');
  t.equal(streams.listStreams().filter(function (record) {
    return record.stream_id === derivedId;
  }).length, 1, 'and there is still exactly one of it');
  consoleStream.internalSurface = marker;

  // THE ONES THAT ACCUMULATED BEFORE THE ID WAS DERIVED. A store carried over
  // holds several per surface, with random ids, all delivering to the same
  // loopback path — and every event went to all of them.
  const legacy = streams.createStream({
    events_requested: [events.CAEP_EVENT_URIS[0]],
    description: 'a duplicate from before the id was derived',
    delivery: { method: streams.DELIVERY_PUSH,
                endpoint_url: transport.loopbackOrigin() +
                              realms.currentPrefix() +
                              consoleSurface.receivePath,
                authorization_header: 'Bearer whatever' }
  }, { issuer: 'https://example.test', principal: 'internal',
       audience: consoleSurface.audience });
  t.check(legacy.ok, 'a legacy duplicate can be created for the test to sweep',
          legacy.ok ? 'made ' + legacy.stream.stream_id
                    : legacy.errors.join(' '));
  const sweptAway = receivers.seedStreams();
  t.equal(sweptAway, 0, 'seeding over a legacy duplicate creates nothing new');
  t.equal(streams.listStreams().filter(function (record) {
    return record.stream_id === legacy.stream.stream_id;
  }).length, 0,
          'AND THE DUPLICATE IS GONE. It is identified by where it DELIVERS ' +
          'rather than by the marker, because the marker is exactly what may ' +
          'not have survived the round-trip that produced it');
  t.equal(streams.listStreams().filter(function (record) {
    return record.stream_id === derivedId;
  }).length, 1, 'and the derived stream is the one left standing');

  // AND THE ID MUST NOT MOVE WITH THE PER-RUN SECRET. `receiverToken()` is
  // derived from `internalSecret()`, which is regenerated at every start and
  // inherited through the environment — right for a credential, and fatal
  // here: an id that changed per start would agree across the processes of one
  // run and accumulate a fresh set on the next, which is the whole defect
  // moved one level along.
  //
  // Asserted THROUGH seedStreams() rather than by rebuilding the id here: a
  // test that recomputes the string it is checking proves only that two copies
  // of one expression agree, which is what the first version of this did.
  const before = process.env.STS_SSF_RECEIVER_SECRET;
  process.env.STS_SSF_RECEIVER_SECRET =
    require('crypto').randomBytes(32).toString('base64');
  const madeAfterRotation = receivers.seedStreams();
  t.equal(madeAfterRotation, 0,
          'THE ID DOES NOT MOVE WITH THE PER-RUN SECRET — rotating it seeds ' +
          'nothing, because the id is the realm and the surface. An id ' +
          'derived from that secret would agree across the processes of one ' +
          'run and mint a fresh set on the next start, which is this whole ' +
          'defect moved one level along');
  t.equal(streams.listStreams().filter(function (record) {
    return record.stream_id === derivedId;
  }).length, 1, 'and it is still the same single stream');
  if (before === undefined) {
    delete process.env.STS_SSF_RECEIVER_SECRET;
  } else {
    process.env.STS_SSF_RECEIVER_SECRET = before;
  }

  // -----------------------------------------------------------------------
  // B3. ANOTHER REALM'S RECEIVER STREAM IN THIS REALM IS SWEPT (2026-09-14).
  //
  // A replicated row for a realm a process had not heard of yet landed in the
  // DEFAULT partition (`realms.js`'s `partitionId()`), so a dispatch run's
  // default realm held forty other realms' receiver streams and pushed every
  // event to all of them. Such a copy delivers to ANOTHER realm's prefix, so
  // the endpoint test above cannot see it; it is found by its id, which only
  // `seedStreams()` ever sets. A receiver's own stream beside it must survive.
  // -----------------------------------------------------------------------
  t.log.info('B3. another realm\'s receiver stream in this realm is swept');
  const leakedId = 'ssf-internal-some-other-realm-admin-console';
  const leaked = streams.createStream({
    events_requested: [events.CAEP_EVENT_URIS[0]],
    description: 'another realm\'s receiver, put here by a replicated row',
    delivery: { method: streams.DELIVERY_PUSH,
                endpoint_url: transport.loopbackOrigin() +
                              '/realm/some-other-realm' +
                              consoleSurface.receivePath,
                authorization_header: 'Bearer whatever' }
  }, { issuer: 'https://example.test', principal: 'internal',
       streamId: leakedId, audience: consoleSurface.audience });
  const ordinary = streams.createStream({
    events_requested: [events.CAEP_EVENT_URIS[0]],
    delivery: { method: streams.DELIVERY_POLL }
  }, { issuer: 'https://example.test', principal: 'a-receiver' });
  t.check(leaked.ok && leaked.stream.stream_id === leakedId && ordinary.ok,
          'a leaked copy and an ordinary receiver\'s stream are created',
          JSON.stringify([leaked.errors, ordinary.errors]));
  t.equal(receivers.seedStreams(), 0,
          'seeding over the leaked copy creates nothing new');
  t.equal(streams.listStreams().filter(function (record) {
    return record.stream_id === leakedId;
  }).length, 0,
          'THE OTHER REALM\'S RECEIVER STREAM IS GONE, although it delivers ' +
          'to a prefix that is not this realm\'s');
  t.equal(streams.listStreams().filter(function (record) {
    return record.stream_id === ordinary.stream.stream_id;
  }).length, 1,
          'and an ordinary receiver\'s stream is left alone — only an id of ' +
          'the seeded shape is swept');
  t.equal(streams.listStreams().filter(function (record) {
    return record.stream_id === derivedId;
  }).length, 1, 'and this realm\'s own receiver stream is still there');
  streams.removeStream(ordinary.stream.stream_id);

  t.log.info('C. isOwnLoopback(), and the two exemptions it carries');
  // -----------------------------------------------------------------------
  const mine = transport.loopbackOrigin();
  t.check(transport.isOwnLoopback(mine + '/portal/signals/receive'),
          'this process\'s own address is recognised');
  t.check(!transport.isOwnLoopback('https://evil.example/x?u=' + mine),
          'A URL THAT MERELY CONTAINS OUR ORIGIN IS NOT US. It is an ORIGIN ' +
          'comparison and never a substring match — a receiver whose ' +
          'endpoint is https://evil.example/?x=https://127.0.0.1:8081/ must ' +
          'not inherit the allowlist exemption or the http one');
  t.check(!transport.isOwnLoopback('https://127.0.0.1:1/x'),
          'and neither is another port on this host: it is this LISTENER, ' +
          'not this machine');
  t.check(!transport.isOwnLoopback('not a url at all'),
          'an unparseable string is not ours either — urlProblem() says what ' +
          'is wrong with it a few lines later, and the only question here is ' +
          'whether it is ours');

  // -----------------------------------------------------------------------
  t.log.info('D. is this event about this person — every shape this service ' +
             'composes');
  // -----------------------------------------------------------------------

  // CAEP: SSF's complex subject, whose `user` member names the person and
  // whose `session` member names one session of theirs.
  const complex = { format: 'complex', user: { format: 'iss_sub',
      iss: 'https://sts.example.com', sub: 'urn:sts:user:alice' },
    session: { format: 'opaque', id: 'sess-1' } };
  t.check(receivers.isAbout(delivered(complex), ALICE),
          'A COMPLEX SUBJECT IS READ ONE LEVEL IN. Every CAEP event names a ' +
          'SESSION, and the person is in the `user` member — an exact-match ' +
          'test on the whole subject would hide every session event from the ' +
          'person it is about');
  t.check(!receivers.isAbout(delivered(complex), BOB),
          'AND IT IS NOT BOB\'S. The assertion this whole page rests on: ' +
          'showing one person another person\'s account lockout is a ' +
          'disclosure, and it is the case a running service cannot be asked ' +
          'about without two browsers');

  t.check(receivers.isAbout(delivered({ format: 'iss_sub',
      iss: 'x', sub: 'alice' }), ALICE),
          'a plain iss_sub naming the username matches — RISC\'s ' +
          'default format');
  t.check(receivers.isAbout(delivered({ format: 'opaque', id: 'alice' }),
                            ALICE),
          'so does an opaque id this service composed from the name');
  t.check(receivers.isAbout(delivered({ format: 'email',
      email: 'alice@example.com' }), ALICE),
          'so does the address on her entry');
  t.check(receivers.isAbout(delivered({ format: 'email',
      email: 'bob@example.com' }), BOB),
          'AND THE ADDRESS THIS SERVICE INVENTS FOR SOMEBODY WHOSE ENTRY ' +
          'CARRIES NONE — <name>@example.com, in subjectForUser() and in ' +
          'risc.js\'s defaultEmailFor(). It is a fact about those two ' +
          'functions rather than about the person, so it is matched and not ' +
          'held as though she owned it');
  t.check(receivers.isAbout(delivered({ format: 'account',
      uri: 'acct:alice@example.com' }), ALICE),
          'so does an acct: URI');
  t.check(receivers.isAbout(delivered({ format: 'uri',
      uri: 'https://elsewhere.example/users/alice' }), ALICE),
          'AND A uri SUBJECT IS MATCHED ON ITS TAIL rather than whole: the ' +
          'issuer a seeded stream carries is computed at startup, and a ' +
          'deployment behind a proxy legitimately has a different one on the ' +
          'event');
  t.check(receivers.isAbout(delivered({ format: 'did',
      url: 'did:example:alice' }), ALICE),
          'and a DID composed the way subjectForUser() composes one');
  t.check(receivers.isAbout(delivered({ format: 'aliases', identifiers: [
      { format: 'phone_number', phone_number: '+15550000' },
      { format: 'email', email: 'alice@example.com' }] }), ALICE),
          'an aliases subject matches if ANY of its identifiers does, which ' +
          'is what that format means');

  // RISC section 3.1's rename.
  t.check(receivers.isAbout(delivered({ subject_type: 'iss_sub',
      iss: 'x', sub: 'alice' }), ALICE),
          'AND `subject_type` IS READ AS WELL AS `format`. ' +
          'risc.googleSubjectType renames that member on every RISC subject ' +
          'this service sends, deliberately, because RISC section 3.1 says a ' +
          'relying party needs code for both spellings — so a filter reading ' +
          'only `format` would hide every RISC signal from every person the ' +
          'moment that setting went on, with no symptom at either end');

  // The identifier events.
  t.check(receivers.isAbout(delivered({ format: 'email',
      email: 'old-alice@example.com' },
      { 'new-value': 'alice@example.com' },
      events.RISC_PREFIX + 'identifier-changed'), ALICE),
          'AN identifier-changed IS HERS EVEN THOUGH ITS SUBJECT IS THE OLD ' +
          'ADDRESS. RISC says the subject MUST carry the old value, so ' +
          'without reading `new-value` the one person who must see that ' +
          'event stops seeing it at exactly the moment it takes effect');
  t.check(!receivers.isAbout(delivered({ format: 'email',
      email: 'old-bob@example.com' },
      { new_value: 'alice@example.com' },
      events.RISC_PREFIX + 'identifier-changed'), ALICE),
          'and `new_value` with an underscore is NOT read — the one ' +
          'hyphenated member name in the whole of Shared Signals, which a ' +
          'transmitter typing it from habit gets wrong; the generator does ' +
          'not silently correct it and neither does this');

  // -----------------------------------------------------------------------
  t.log.info('E. and the cases it deliberately refuses');
  // -----------------------------------------------------------------------
  t.check(!receivers.isAbout(delivered({ format: 'phone_number',
      phone_number: '+15550000' }), ALICE),
          'A PHONE NUMBER IS NOT A MATCH. There is no number on a directory ' +
          'entry here, so an event carrying one is about somebody this ' +
          'service cannot name — and when in doubt the answer is no, because ' +
          'failing to show somebody one of their own signals is an ' +
          'incomplete page and showing them somebody else\'s is a disclosure');
  t.check(!receivers.isAbout(delivered({ format: 'opaque',
      id: 'e3b0c44298fc1c14' }), ALICE),
          'and neither is an opaque id this service did not compose');
  t.check(!receivers.isAbout(delivered(null), ALICE),
          'AND AN EVENT WITH NO SUBJECT IS NOBODY\'S. SSF\'s own two are ' +
          'about the STREAM — a verification and a stream-updated go to the ' +
          'console, which sees everything, and appear on no person\'s page');
  t.check(!receivers.isAbout(delivered({ format: 'iss_sub',
      iss: 'x', sub: '' }), ALICE),
          'an empty identifier matches nobody, rather than matching ' +
          'everybody whose own value happens to be empty');

  // -----------------------------------------------------------------------
  t.log.info('F. the inbox, and the cap that is applied PER SURFACE');
  // -----------------------------------------------------------------------
  receivers.clearFor(receivers.ADMIN);
  receivers.clearFor(receivers.PORTAL);
  config.setOverride('ssf.maxReceivedEvents', '5');

  const bearer = { admin: consoleStream.delivery.authorization_header,
                   portal: portalStream.delivery.authorization_header };

  // One SET each for the portal, then twenty for the console. What is being
  // asserted is that the portal still has its one.
  deliverSigned(t, receivers.PORTAL, bearer.portal, ALICE);
  for (let i = 0; i < 20; i++) {
    deliverSigned(t, receivers.ADMIN, bearer.admin, BOB, true);
  }
  t.equal(receivers.listFor(receivers.ADMIN, {}).length, 5,
          'the console\'s inbox is capped at ssf.maxReceivedEvents');
  t.equal(receivers.listFor(receivers.PORTAL, {}).length, 1,
          'AND THE PORTAL STILL HAS ITS ONE. Both surfaces\' rows live in ' +
          'one map, so the bug available here is a busy console evicting a ' +
          'quiet portal\'s signals — which is the one kind of loss nobody ' +
          'would notice, because an empty page is also what nothing having ' +
          'happened looks like');

  config.setOverride('ssf.maxReceivedEvents', '200');

  // -----------------------------------------------------------------------
  t.log.info('G. what a receiver refuses');
  // -----------------------------------------------------------------------
  const noCredential = receivers.accept(receivers.ADMIN,
    { headers: {}, body: 'a.b.c' });
  t.equal(noCredential.status, 401,
          'a push with no authorization header is refused');
  const wrongCredential = receivers.accept(receivers.ADMIN,
    { headers: { authorization: 'Bearer not-the-one' }, body: 'a.b.c' });
  t.equal(wrongCredential.status, 401, 'and so is one with the wrong value');
  t.check(wrongCredential.body.description !== noCredential.body.description,
          'AND THE TWO SAY DIFFERENT THINGS. "No header" and "the wrong ' +
          'header" send somebody to two different places — a transmitter ' +
          'that was never told, against a stream that has been recreated ' +
          'since — and one sentence for both would send half its readers the ' +
          'wrong way');

  const empty = receivers.accept(receivers.ADMIN,
    { headers: { authorization: bearer.admin }, body: '' });
  t.equal(empty.status, 400, 'an empty body is refused');
  t.equal(empty.body.err, 'invalid_request',
          'in RFC 8935 section 2.4\'s shape, which is the same document this ' +
          'service\'s own transmitter reads back in pushSet()');

  const malformed = receivers.accept(receivers.ADMIN,
    { headers: { authorization: bearer.admin }, body: 'not-a-jws' });
  t.equal(malformed.status, 400, 'and so is something that is not a JWS');
  t.check(!!malformed.entry,
          'AND IT IS RECORDED ANYWAY. What arrived is the question being ' +
          'asked, and a receiver that dropped what it refused would leave ' +
          'the transmitter\'s log as the only evidence it ever came');

  // -----------------------------------------------------------------------
  t.log.info('H. the audience, which is the check /ssf/receive does not make');
  // -----------------------------------------------------------------------
  const misaddressed = events.signSetSync(events.buildSet({
    issuer: consoleStream.iss, audience: 'somebody-else',
    uri: events.CAEP_EVENT_URIS[0],
    payload: { event_timestamp: Math.floor(Date.now() / 1000) },
    subject: { format: 'complex',
      user: { format: 'iss_sub', iss: 'x', sub: 'alice' },
      session: { format: 'opaque', id: 's' } } }));
  const wrongAud = receivers.accept(receivers.ADMIN,
    { headers: { authorization: bearer.admin,
      'content-type': 'application/secevent+jwt' }, body: misaddressed });
  t.equal(wrongAud.status, 400,
          'a SET addressed to somebody else is refused');
  t.equal(wrongAud.body.err, 'invalid_audience',
          'WITH THE REFUSAL THE SPECIFICATION NAMES. ssf_streams.js requires ' +
          '`aud` and never defaults it precisely so that a receiver checks ' +
          'for itself in it — a receiver that then did not check would make ' +
          'that whole argument decorative');
  t.check(wrongAud.entry && wrongAud.entry.audienceOk === false,
          'and it is recorded with audienceOk false, so the page can show a ' +
          'misaddressed event rather than showing nothing');

  // -----------------------------------------------------------------------
  t.log.info('H2. the issuer and the explicit type (#144, SSF 1.0 sections ' +
             '4.1.6 and 4.1.1)');
  // -----------------------------------------------------------------------
  const foreignIssuer = events.signSetSync(events.buildSet({
    issuer: 'https://another-transmitter.example', audience:
      consoleSurface.audience,
    uri: events.CAEP_EVENT_URIS[0],
    payload: { event_timestamp: Math.floor(Date.now() / 1000) },
    subject: { format: 'complex',
      user: { format: 'iss_sub', iss: 'x', sub: 'alice' },
      session: { format: 'opaque', id: 's' } } }));
  const wrongIss = receivers.accept(receivers.ADMIN,
    { headers: { authorization: bearer.admin,
      'content-type': 'application/secevent+jwt' }, body: foreignIssuer });
  t.check(wrongIss.status === 400 && wrongIss.body.err === 'invalid_issuer',
          'A SET WHOSE iss IS NOT THE STREAM\'S IS REFUSED with ' +
          'invalid_issuer: section 4.1.6 says a receiver MUST check it, and ' +
          'this one did not until #144',
          JSON.stringify(wrongIss.body));
  t.check(wrongIss.entry && wrongIss.entry.issuerOk === false,
          'and it is recorded with issuerOk false');
  // An UNtyped token: the right issuer, audience and signature key, and no
  // `typ` in its header.
  const signer = require('../common/helpers');
  const untypedClaims = events.buildSet({
    issuer: consoleStream.iss, audience: consoleSurface.audience,
    uri: events.CAEP_EVENT_URIS[0],
    payload: { event_timestamp: Math.floor(Date.now() / 1000) },
    subject: { format: 'complex',
      user: { format: 'iss_sub', iss: 'x', sub: 'alice' },
      session: { format: 'opaque', id: 's' } } });
  // `signJwt()` writes no `typ` at all — the untyped case.
  const untyped = signer.signJwt(untypedClaims);
  const noTyp = receivers.accept(receivers.ADMIN,
    { headers: { authorization: bearer.admin,
      'content-type': 'application/secevent+jwt' }, body: untyped });
  t.check(noTyp.status === 400 && noTyp.body.err === 'invalid_request' &&
          /secevent\+jwt/.test(noTyp.body.description),
          'AND A TOKEN THAT IS NOT typ secevent+jwt IS REFUSED (section ' +
          '4.1.1: SSF events MUST be explicitly typed)',
          JSON.stringify(noTyp.body));

  // -----------------------------------------------------------------------
  t.log.info('I. status(), which is what an empty page has to say');
  // -----------------------------------------------------------------------
  const healthy = receivers.status(receivers.ADMIN);
  t.equal(healthy.why.length, 0,
          'with everything on and a stream in place there is nothing to ' +
          'explain');
  config.setOverride('ssf.pushDelivery', 'false');
  const quiet = receivers.status(receivers.ADMIN);
  t.check(quiet.why.join(' ').indexOf('ssf.pushDelivery') >= 0,
          'AND ssf.pushDelivery OFF IS NAMED. It is the one bound in ' +
          'ssf_http.js these receivers do NOT get an exemption from, so with ' +
          'it off both of them go silent — which is the cause of an empty ' +
          'page that looks least like a setting and most like nothing having ' +
          'happened');
  config.setOverride('ssf.pushDelivery', 'true');

  config.setOverride('ssf.enabled', 'false');
  const off = receivers.status(receivers.ADMIN);
  t.check(off.why.join(' ').indexOf('ssf.enabled') >= 0,
          'the transmitter being off is named first, because it stops ' +
          'everything and the rest only narrow it');
  const refused = receivers.accept(receivers.ADMIN,
    { headers: { authorization: bearer.admin }, body: 'a.b.c' });
  t.equal(refused.status, 501,
          'and the endpoint answers 501 while it is off, rather than ' +
          'accepting into an inbox nothing will draw');
  config.setOverride('ssf.enabled', 'true');

  // -----------------------------------------------------------------------
  t.log.info('J. clearing');
  // -----------------------------------------------------------------------
  const held = receivers.listFor(receivers.ADMIN, {}).length;
  t.check(held > 0, 'the console is holding something to clear');
  const gone = receivers.clearFor(receivers.ADMIN);
  t.equal(gone, held, 'clearing drops every row and says how many');
  t.check(!!receivers.streamFor(receivers.ADMIN),
          'AND THE STREAM SURVIVES. Clearing what a receiver has been shown ' +
          'and tearing down the agreement to send it more are two different ' +
          'acts, and only the first one is on that page');
  t.equal(receivers.listFor(receivers.PORTAL, {}).length, 1,
          'and the portal\'s inbox is untouched by the console\'s Clear');
  log.debug("Leaving run().");
}

// One real signed SET, delivered the way `accept()` takes one. It is signed
// rather than faked here because the entry's `verified` is part of what the
// cap test is holding — a row that failed to verify is still a row.
function deliverSigned(t, surface, bearer, person, quiet) {
  log.debug("Entering deliverSigned().");
  // The stream's own issuer: SSF 1.0 section 4.1.6 has the receiver refuse
  // any other (#144), which section H2 below asserts.
  const claims = events.buildSet({
    issuer: receivers.streamFor(surface).iss,
    audience: receivers.surfaceOf(surface).audience,
    uri: events.CAEP_EVENT_URIS[0],
    payload: { event_timestamp: Math.floor(Date.now() / 1000) },
    subject: { format: 'complex', user: { format: 'iss_sub',
        iss: 'https://sts.example.com', sub: person.sub },
      session: { format: 'opaque', id: 's-' + Math.random() } } });
  const token = events.signSetSync(claims);
  const taken = receivers.accept(surface, {
    headers: { authorization: bearer,
      'content-type': 'application/secevent+jwt' },
    body: token });
  if (!quiet) {
    t.equal(taken.status, 202,
            'a properly credentialled, properly addressed SET is accepted ' +
            'with RFC 8935 section 2.3\'s 202 and an empty body');
  }
  log.debug("Leaving deliverSigned().");
  return taken;
}

module.exports = {
  name: 'ssf_receivers',
  describe: 'this service\'s own console and portal as Shared Signals ' +
            'receivers: the seeded streams, the loopback exemptions, and the ' +
            'per-person filter that must fail closed',
  run: run
};
