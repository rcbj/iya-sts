'use strict';
//
// File: ldap_operations.js
//
// ===========================================================================
// THE DIRECTORY, RUN IN A PROCESS THAT HOLDS NO SOCKET.
//
// `common/request_pool.js` has had an OPERATION channel since it was written —
// a `{ kind, args }` pair the front process sends to a worker so that the work
// behind a non-HTTP listener can leave the thread holding every socket this
// service has. Until 2026-09-12 nothing filled it: no module called
// `request_worker.register()`, no module called `runOperation()`, and
// the dispatch list named no operation kind by default. The mechanism existed
// and no protocol used it.
//
// `ldap/ldap_server.js` is the first, and this file is the contract.
//
// ---------------------------------------------------------------------------
// WHY THE CLAIM NEEDS A TEST OF ITS OWN RATHER THAN AN END-TO-END JOB.
//
// The claim is not "the directory works" — `sts_directory_bulk_load_ldap.js`
// drives five thousand entries over a real socket in three stacks, and
// `sts_global_logout.js` binds there too. The claim here is narrower and
// nothing over the wire can see it: **an operation run through the codec
// produces the same answer as the same handler called directly.**
//
// A job driving 389 cannot tell those apart, because in both cases it is
// talking to a socket that answers correctly. The way this breaks is the way
// every serialisation boundary breaks — a field that does not cross, an error
// that arrives as the wrong result code, a search whose entries lose their
// attribute selection — and each of those produces a service that is WRONG in
// one mode and right in the other two, which is exactly the shape
// `tests/ldap_logout.js` was written for after one cost a whole mode of a run.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED, AND WHAT DELIBERATELY IS NOT.
//
// Every section drives `ldapServer.performOperation()` — the function a worker
// runs — against a request built by `ldapServer.operationRequest()`, the
// function the front process builds one with. So the two halves of the codec
// are held against each other and against the handlers, with no port, no fork
// and no container.
//
// What it does NOT do is fork a worker or bind 389. The first would make this
// file a stack rather than a test; the second is the bulk-load job's, over a
// real socket, in three stacks.
//
// **AND IT DOES NOT ASSERT THE MECHANISM AGAINST ITSELF.** Section 1 compares
// a dispatched answer with the answer the handler gives when called directly
// — two different paths to one result — rather than comparing the codec's
// output with a copy of what the codec was expected to produce.
//
// ---------------------------------------------------------------------------
// THE MUTATION RECORD, AND THE ONE THAT SURVIVED.
//
// Ten mutants, nine caught: the bound DN not crossing (2 red), the compare's
// answer dropped (2), every refusal rebuilt as a generic error (3), the
// worker's message id used instead of the response's (1), a bind that does not
// stamp the socket (1), a bind that publishes no snapshot (1), a refusal that
// also ends the response (1), the attribute selection ignored (3), and `unbind`
// added to the dispatchable list (1).
//
// **SECTION 9 EXISTS BECAUSE OF THE SECOND OF THOSE.** Before it, sections 1
// to 8 drove only `performOperation()` — the WORKER's half — and a mutation in
// `applyOperationResult()` passed all 25 assertions. The two halves run in two
// processes and each has to be driven; that is the shape of this seam and it is
// the thing to remember when the next protocol family is wired up.
//
// **THE SURVIVOR IS RECORDED RATHER THAN COUNTED**, per tests/CLAUDE.md's rule.
// `performOperation()`'s guard for a handler that neither ends nor fails can be
// removed without failing anything here, because **none of the seven handlers
// can reach that state** — the one that could was the search's size-limit
// branch, and `ldap/CLAUDE.md` records it hanging every client for ever until
// it was fixed on 2026-09-06. The guard is defensive against that defect coming
// back one process further away, where it would be even harder to see, and it
// is kept for that rather than because a mutant demanded it. Reaching it would
// mean installing a probe handler, and `localHandler()` is deliberately a
// getter with no setter beside it.
// ===========================================================================

const ldapServer = require('../ldap/ldap_server');
const worker = require('../common/request_worker');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'ldap_operations',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;

// ---------------------------------------------------------------------------
// A REQUEST AS THE SOCKET PRESENTS ONE. Only the members the seven handlers
// actually read, which is what `operationRequest()` walks — a fuller fake
// would be asserting against a shape nothing here uses.
//
// `connection` carries the two things a handler asks a connection for: whether
// it is encrypted, and who is bound on it. `cn=anonymous` is what ldapjs seeds
// an unbound connection with, and `boundDnOf()` reads it back as the absence
// of a bind.
// ---------------------------------------------------------------------------
function socketRequest(fields) {
  log.debug("Entering socketRequest().");
  const ldap = require('ldapjs');
  const req = {
    connection: { encrypted: false,
                  ldap: { bindDN: fields.boundDn || 'cn=anonymous',
                          id: fields.connectionId || 'test-connection-1' },
                  remoteAddress: '127.0.0.1', remotePort: 40000 }
  };
  req.dn = ldap.parseDN(fields.dn === undefined ? BASE : fields.dn);
  if (fields.credentials !== undefined) {
    req.credentials = fields.credentials;
  }
  if (fields.attributes !== undefined) { req.attributes = fields.attributes; }
  if (fields.changes !== undefined) { req.changes = fields.changes; }
  if (fields.newRdn !== undefined) { req.newRdn = fields.newRdn; }
  if (fields.newSuperior !== undefined) {
    req.newSuperior = fields.newSuperior;
  }
  if (fields.attribute !== undefined) { req.attribute = fields.attribute; }
  if (fields.value !== undefined) { req.value = fields.value; }
  if (fields.scope !== undefined) { req.scope = fields.scope; }
  if (fields.filter !== undefined) {
    req.filter = ldap.parseFilter(fields.filter);
  }
  if (fields.sizeLimit !== undefined) { req.sizeLimit = fields.sizeLimit; }
  log.debug("Leaving socketRequest().");
  return req;
}

// The whole round trip: describe the request the way the front process does,
// then run it the way a worker does.
function dispatched(operation, fields) {
  log.debug("Entering dispatched().");
  const shape = ldapServer.operationRequest(operation, socketRequest(fields));
  log.debug("Leaving dispatched().");
  // THROUGH JSON, WHICH IS NOT DECORATION. The channel is a structured clone,
  // so anything that survives JSON survives it — and a shape carrying a class
  // instance, a function or an `undefined` would pass a comparison made on the
  // object itself and lose the member in a real worker. Going through it here
  // is how that stops being possible.
  return ldapServer.performOperation(operation,
                                     JSON.parse(JSON.stringify(shape)));
}

// The same handler called the way the socket calls it, collecting what it
// wrote. This is the CONTROL — the answer the front process would give — and
// it deliberately does not go near the codec.
function directly(operation, fields) {
  log.debug("Entering directly().");
  const handler = ldapServer.localHandler(operation);
  const req = socketRequest(fields);
  const out = { entries: [], ended: false, endArg: undefined, failure: null };
  const res = {
    messageId: 7,
    send: function (entry) {
      log.debug("Entering send().");
      out.entries.push({
        objectName: String(entry.objectName),
        attributes: (entry.attributes || []).map(function (a) {
          return { type: String(a.type),
                   values: (a.values || []).map(String) };
        })
      });
      log.debug("Leaving send().");
    },
    end: function (arg) {
      log.debug("Entering end().");
      out.ended = true;
      out.endArg = arg;
      log.debug("Leaving end().");
    }
  };
  handler(req, res, function (err) { if (err) { out.failure = err; } });
  log.debug("Leaving directly().");
  return out;
}

// ---------------------------------------------------------------------------
// 1. THE SAME SEARCH, BOTH WAYS, COMPARED ENTRY FOR ENTRY.
//
// This is the section the file exists for. A subtree search of `ou=users` goes
// through the codec and is run directly, and the two answers are compared as
// whole objects — DNs, attribute names, attribute values and their order.
//
// **THE COMPARISON IS THE ASSERTION AND A COUNT WOULD NOT BE.** The way a
// serialisation boundary breaks a search is not by losing entries, it is by
// losing the ATTRIBUTE SELECTION — `toSearchEntry()` decides which attributes
// go back, and a codec that ran the selection in the wrong process, or rebuilt
// the message from the stored entry instead of from what the handler sent,
// would answer the right number of entries with the wrong contents in them.
// ---------------------------------------------------------------------------
function checkASearchAgrees(t) {
  log.debug("Entering checkASearchAgrees().");
  t.log.info('=== a search gives the same answer through the codec ===');

  const fields = { dn: USERS, scope: 2, filter: '(objectClass=*)' };
  const viaPool = dispatched('search', fields);
  const control = directly('search', fields);

  t.check(viaPool.ok === true,
          'the dispatched search succeeded',
          'it answered ' + JSON.stringify(viaPool.error || '(no error)'));
  t.check(control.entries.length > 0,
          'the directory has entries to compare (' + control.entries.length +
          ')',
          'a search returning nothing would make every comparison below pass ' +
          'by having nothing to compare — which is the way a test like this ' +
          'is usually wrong');
  t.check(JSON.stringify(viaPool.entries) === JSON.stringify(control.entries),
          'every entry, attribute and value is identical through the codec',
          'the two paths disagree.\n  through the pool: ' +
          JSON.stringify(viaPool.entries).slice(0, 400) +
          '\n  directly:        ' +
          JSON.stringify(control.entries).slice(0, 400));
  log.debug("Leaving checkASearchAgrees().");
}

// ---------------------------------------------------------------------------
// 2. THE ATTRIBUTE SELECTION CROSSES, WHICH IS THE HALF A COUNT CANNOT SEE.
//
// Asking for one attribute must answer with one attribute. If the selection
// ran in the wrong process — or the front process rebuilt each entry from the
// store rather than from what the worker sent — this is the section that goes
// red while section 1 stays green, because section 1 asks for everything.
// ---------------------------------------------------------------------------
function checkTheAttributeSelectionCrosses(t) {
  log.debug("Entering checkTheAttributeSelectionCrosses().");
  t.log.info('=== a narrowed attribute list is honoured in the worker ===');

  const narrow = dispatched('search', { dn: USERS, scope: 2,
                                        filter: '(objectClass=*)',
                                        attributes: ['cn'] });
  t.check(narrow.ok === true, 'the narrowed search succeeded',
          narrow.error || '');

  const names = [];
  narrow.entries.forEach(function (entry) {
    entry.attributes.forEach(function (attribute) {
      if (names.indexOf(attribute.type.toLowerCase()) < 0) {
        names.push(attribute.type.toLowerCase());
      }
    });
  });
  t.check(names.length > 0 && names.every(function (n) { return n === 'cn'; }),
          'only the requested attribute came back (' +
          (names.join(', ') || 'none') + ')',
          'the selection did not cross the codec — the answer carries ' +
          names.length + ' attribute name(s) where it should carry one');
  log.debug("Leaving checkTheAttributeSelectionCrosses().");
}

// ---------------------------------------------------------------------------
// 3. A REFUSAL CROSSES AS THE SAME LDAP RESULT CODE.
//
// A worker cannot send an ldapjs error object, so a refusal travels as a name
// and a message and is rebuilt by `ldapErrorNamed()`. **The result code is the
// whole of what a client acts on** — an LDAP client's error handling is built
// around 32 and 68, not around the sentence — so a codec that rebuilt every
// refusal as a generic failure would leave every negative path in every client
// behaving differently, while a search test went on passing.
//
// Both directions are checked: the code a worker's refusal rebuilds to, and
// that the refusal is refused at all rather than arriving as a success.
// ---------------------------------------------------------------------------
function checkARefusalKeepsItsResultCode(t) {
  log.debug("Entering checkARefusalKeepsItsResultCode().");
  t.log.info('=== a refusal crosses as its own LDAP result code ===');

  const missing = 'uid=nobody-at-all,' + USERS;
  const viaPool = dispatched('del', { dn: missing });
  const control = directly('del', { dn: missing });

  t.check(viaPool.ok === false,
          'a delete of a missing entry is refused through the codec',
          'it came back ok — a refusal that arrives as a success answers ' +
          'LDAP_SUCCESS for an operation that did nothing');
  t.check(!!control.failure,
          'and is refused when the handler is called directly',
          'the control did not refuse, so this section is comparing nothing');

  const rebuilt = ldapServer.ldapErrorNamed(viaPool.errorName, viaPool.error);
  t.check(rebuilt.code === control.failure.code,
          'the rebuilt error carries the same result code (' + rebuilt.code +
          ')',
          'the client would be told ' + rebuilt.code + ' where the front ' +
          'process tells it ' + control.failure.code);
  t.check(rebuilt.name === control.failure.name,
          'and the same error (' + rebuilt.name + ')',
          'rebuilt as ' + rebuilt.name + ', not ' + control.failure.name);
  log.debug("Leaving checkARefusalKeepsItsResultCode().");
}

// ---------------------------------------------------------------------------
// 4. AN ERROR NAME THIS PROCESS CANNOT REBUILD BECOMES AN LDAP ERROR ANYWAY.
//
// `ldapErrorNamed()` looks the name up on ldapjs's own exports rather than in
// a hand-written code table, so the interesting failure is what it does with
// something that is not an error constructor. The answer has to be a refusal —
// LDAP_OPERATIONS_ERROR — and never a success, because the operation genuinely
// failed and the only thing in doubt is how to say so.
//
// **`createServer` IS THE PROBE ON PURPOSE.** It is a real, callable export of
// that module, so a lookup that checked only "is this a function" would build
// one and hand the client something that is not an error at all.
// ---------------------------------------------------------------------------
function checkAnUnknownRefusalIsStillARefusal(t) {
  log.debug("Entering checkAnUnknownRefusalIsStillARefusal().");
  t.log.info('=== an unrebuildable error name is still an LDAP error ===');

  const unknown = ldapServer.ldapErrorNamed('NoSuchThingError', 'invented');
  t.check(typeof unknown.code === 'number',
          'an unknown error name rebuilds to something with a result code (' +
          unknown.code + ')',
          'the client would be handed an object with no result code on it');
  t.check(unknown.message.indexOf('invented') >= 0,
          'and keeps the original wording',
          'the reason the worker gave was lost, which leaves the one ' +
          'sentence that says what happened nowhere at all');

  const notAnError = ldapServer.ldapErrorNamed('createServer', 'not an error');
  t.check(typeof notAnError.code === 'number' && notAnError.code === 1,
          'an export that is callable but is not an error becomes ' +
          'LDAP_OPERATIONS_ERROR',
          'it came back as code ' + notAnError.code + ' — a name lookup that ' +
          'accepts any callable export can hand a client an ldapjs Server');
  log.debug("Leaving checkAnUnknownRefusalIsStillARefusal().");
}

// ---------------------------------------------------------------------------
// 5. A WRITE THROUGH THE CODEC IS A WRITE, AND IS READ BACK THROUGH IT.
//
// The add and the search are two separate operations, so this also asserts the
// thing the whole feature rests on: an entry written by one operation is there
// for the next. In this process that is trivially true — one store — and
// asserting it here is what makes the SHAPE right, so that the same two calls
// across two workers are held together by the read barrier rather than by
// luck.
// ---------------------------------------------------------------------------
function checkAWriteCrosses(t) {
  log.debug("Entering checkAWriteCrosses().");
  t.log.info('=== an add through the codec is visible to a search through it ' +
             '===');

  const dn = 'uid=codec-probe,' + USERS;
  const added = dispatched('add', {
    dn: dn,
    attributes: [{ type: 'objectClass', values: ['top', 'inetOrgPerson'] },
                 { type: 'uid', values: ['codec-probe'] },
                 { type: 'cn', values: ['Codec Probe'] },
                 { type: 'sn', values: ['Probe'] }]
  });
  t.check(added.ok === true, 'the add succeeded through the codec',
          added.error || '');

  const found = dispatched('search', { dn: dn, scope: 0,
                                       filter: '(objectClass=*)' });
  t.check(found.ok === true && found.entries.length === 1,
          'and the entry is found by a search through the codec',
          'the search answered ' + found.entries.length + ' entry/entries');

  // THE VALUES CROSSED, not merely the DN. An add whose attributes were lost
  // in the codec would still produce a findable entry.
  const cn = found.entries.length
    ? (found.entries[0].attributes.filter(function (a) {
        return a.type.toLowerCase() === 'cn';
      })[0] || {}).values
    : null;
  t.check(!!cn && cn.indexOf('Codec Probe') >= 0,
          'and carries the attribute values the add sent',
          'cn came back as ' + JSON.stringify(cn));

  // TIDIED UP, because this store is module-wide and every later file in the
  // run reads it — tests/CLAUDE.md's rule about process-wide state.
  const removed = dispatched('del', { dn: dn });
  t.check(removed.ok === true, 'and the probe entry is deleted again',
          removed.error || '');
  log.debug("Leaving checkAWriteCrosses().");
}

// ---------------------------------------------------------------------------
// 6. A COMPARE'S ANSWER IS THE ARGUMENT TO `res.end()`, AND IT IS A BOOLEAN.
//
// `compare` is the one operation whose RESULT is a value rather than a status:
// `res.end(matched)` is how ldapjs sends compareTrue or compareFalse. A codec
// that dropped the argument would answer compareFalse for every compare that
// matched — a refusal that looks exactly like a correct negative answer, which
// is the hardest kind of wrong there is.
//
// Both answers are asserted, because a codec that hard-coded either one would
// pass a test that only checked the other.
// ---------------------------------------------------------------------------
function checkACompareCarriesItsAnswer(t) {
  log.debug("Entering checkACompareCarriesItsAnswer().");
  t.log.info('=== a compare carries its true/false answer across ===');

  const hit = dispatched('compare', { dn: USERS, attribute: 'ou',
                                      value: 'users' });
  t.check(hit.ok === true && hit.endArg === true,
          'a compare that matches answers true through the codec',
          'endArg came back as ' + JSON.stringify(hit.endArg));

  const miss = dispatched('compare', { dn: USERS, attribute: 'ou',
                                       value: 'not-the-value' });
  t.check(miss.ok === true && miss.endArg === false,
          'and one that does not match answers false',
          'endArg came back as ' + JSON.stringify(miss.endArg));
  log.debug("Leaving checkACompareCarriesItsAnswer().");
}

// ---------------------------------------------------------------------------
// 7. THE BOUND DN CROSSES, WHICH IS THE ONE FACT A WORKER CANNOT DERIVE.
//
// The connection belongs to the front process, so who is bound on it is the
// front process's to state. Every audit row an operation writes reads it
// through `boundDnOf()`, and a codec that dropped it would file every
// directory operation in the service against nobody — with the operation
// itself working perfectly.
//
// The absence has to cross too, and it is not the same as the empty string:
// ldapjs seeds an unbound connection with `cn=anonymous`, and `boundDnOf()`
// exists to read that back as "nobody". A stub that put an empty string there
// would take the other branch of the one function whose whole job is that
// distinction.
// ---------------------------------------------------------------------------
function checkTheBoundIdentityCrosses(t) {
  log.debug("Entering checkTheBoundIdentityCrosses().");
  t.log.info('=== the bound DN travels with the operation ===');

  const bound = 'uid=alice,' + USERS;
  const shape = ldapServer.operationRequest('search',
    socketRequest({ dn: USERS, scope: 2, filter: '(objectClass=*)',
                    boundDn: bound }));
  t.check(shape.boundDn === bound,
          'the bound DN is on the request the worker is sent',
          'it came across as ' + JSON.stringify(shape.boundDn));

  const rebuilt = ldapServer.operationContext('search', shape);
  t.check(String(rebuilt.connection.ldap.bindDN) === bound,
          'and is on the connection the worker rebuilds',
          'the worker would see ' +
          JSON.stringify(String(rebuilt.connection.ldap.bindDN)));

  const anonymous = ldapServer.operationContext('search',
    ldapServer.operationRequest('search',
      socketRequest({ dn: USERS, scope: 2, filter: '(objectClass=*)' })));
  t.check(String(anonymous.connection.ldap.bindDN).toLowerCase() ===
          'cn=anonymous',
          'and an unbound connection is rebuilt as cn=anonymous rather than ' +
          'as an empty DN',
          'it was rebuilt as ' +
          JSON.stringify(String(anonymous.connection.ldap.bindDN)) +
          ', which boundDnOf() reads differently');

  const channel = ldapServer.operationRequest('search',
    socketRequest({ dn: USERS, scope: 2, filter: '(objectClass=*)' }));
  t.check(channel.channel === 'ldap',
          'and the channel crosses, so an audit row says LDAP or LDAPS',
          'the channel came across as ' + JSON.stringify(channel.channel));
  log.debug("Leaving checkTheBoundIdentityCrosses().");
}

// ---------------------------------------------------------------------------
// 8. EVERY DISPATCHABLE OPERATION IS REGISTERED, AND `unbind` IS NOT.
//
// Two halves of one rule, and the second is the interesting one. `unbind` ends
// a CONNECTION, which is a file descriptor the front process holds — so there
// is nothing in it for a worker to do, and registering it would offer a
// sign-out that could not sign anybody out.
//
// The first half is the drift check: an operation added to the table and never
// registered is one that silently keeps running in the front process, which
// nothing anywhere would report.
// ---------------------------------------------------------------------------
function checkTheOperationTableAgrees(t) {
  log.debug("Entering checkTheOperationTableAgrees().");
  t.log.info('=== the registered operations are the dispatchable ones ===');

  // ---------------------------------------------------------------------
  // THE REGISTRATION IS DRIVEN IN THE STATE IT HAPPENS IN, WHICH IS A REQUEST
  // WORKER (2026-09-12).
  //
  // `registerWorkerOperations()` returns early unless `STS_REQUEST_WORKER` is
  // set, because requiring `common/request_worker.js` pulls
  // `common/service_state.ts` in at module scope and a front process would be
  // filling a table nothing there ever reads. `spiffe_grpc.js` carries the
  // argument and the test it cost.
  //
  // So this section puts the process into that state for the length of its own
  // assertions and puts it back — tests/CLAUDE.md's rule, and it matters more
  // than usual here because the variable it sets is the one the pool reads to
  // decide whether it is a worker at all.
  // ---------------------------------------------------------------------
  const hadMarker = process.env.STS_REQUEST_WORKER;
  let registered = [];
  try {
    process.env.STS_REQUEST_WORKER = '1';
    ldapServer.registerWorkerOperations();
    registered = Array.from(worker.OPERATIONS.keys()).filter(function (k) {
      return k.indexOf('ldap.') === 0;
    }).sort();
  } finally {
    if (hadMarker === undefined) {
      delete process.env.STS_REQUEST_WORKER;
    } else {
      process.env.STS_REQUEST_WORKER = hadMarker;
    }
  }
  const expected = ldapServer.dispatchableOperations().map(function (o) {
    return 'ldap.' + o;
  }).sort();

  t.check(JSON.stringify(registered) === JSON.stringify(expected),
          'every dispatchable operation is registered with the worker (' +
          registered.join(', ') + ')',
          'registered ' + JSON.stringify(registered) + ' against a table of ' +
          JSON.stringify(expected) + '. An operation in the table and not in ' +
          'the worker goes on running in the front process with nothing ' +
          'saying so');

  t.check(registered.indexOf('ldap.unbind') < 0,
          'and unbind is NOT registered',
          'unbind ends a connection, which is a file descriptor only the ' +
          'front process holds — a worker cannot close one and must not be ' +
          'offered the chance to try');

  // AND EVERY REGISTERED OPERATION HAS A HANDLER BEHIND IT. The registration
  // happens after the seven `server.*` calls precisely so that it does; a call
  // placed before them would register seven operations that throw in the
  // worker, where the failure reaches a reader as nothing at all.
  const unbacked = ldapServer.dispatchableOperations().filter(function (o) {
    return typeof ldapServer.localHandler(o) !== 'function';
  });
  t.check(unbacked.length === 0,
          'and each has its handler captured',
          'no handler captured for: ' + unbacked.join(', ') + '. This is ' +
          'what registering before the handlers are installed looks like');
  log.debug("Leaving checkTheOperationTableAgrees().");
}

// ---------------------------------------------------------------------------
// 9. AND THE FRONT-PROCESS HALF, WHICH A WORKER-SIDE TEST CANNOT SEE.
//
// **THIS SECTION EXISTS BECAUSE A MUTANT SURVIVED WITHOUT IT.** Sections 1 to 8
// drive `performOperation()` — the function a WORKER runs — so a mutation in
// `applyOperationResult()`, which runs in the FRONT process, passed every one
// of them. Breaking the compare so that `res.end()` is called with no argument
// (answering compareFalse for every compare that matched, a refusal that looks
// exactly like a correct negative answer) went unnoticed by 25 assertions.
//
// The two halves are two functions in two processes and each needs driving.
// What is asserted here is everything that only happens on this side: the
// `SearchEntry` messages and the id they carry, the compare's argument, the
// error rebuilt onto `next()`, and the two effects on the SOCKET that a worker
// is structurally unable to perform.
// ---------------------------------------------------------------------------
function applied(operation, fields, result) {
  log.debug("Entering applied().");
  const req = socketRequest(fields || {});
  const out = { sent: [], ended: false, endArg: undefined, failure: null,
                nexted: false, req: req };
  const res = {
    messageId: 99,
    send: function (entry) {
      log.debug("Entering send().");
      out.sent.push(entry);
      log.debug("Leaving send().");
    },
    end: function (arg) {
      log.debug("Entering end().");
      out.ended = true;
      out.endArg = arg;
      log.debug("Leaving end().");
    }
  };
  ldapServer.applyOperationResult(operation, req, res, function (err) {
    out.nexted = true;
    if (err) { out.failure = err; }
  }, result);
  log.debug("Leaving applied().");
  return out;
}

function checkTheFrontProcessHalf(t) {
  log.debug("Entering checkTheFrontProcessHalf().");
  t.log.info('=== the front process writes what the worker decided ===');

  // A SEARCH: the entries become real messages carrying THIS response's id.
  const search = applied('search', { dn: USERS, scope: 2,
                                     filter: '(objectClass=*)' },
    { ok: true,
      entries: [{ objectName: 'uid=x,' + USERS,
                  attributes: [{ type: 'cn', values: ['X'] }] }],
      endArg: undefined });
  t.check(search.sent.length === 1 && search.ended === true,
          'a dispatched search sends its entries and then ends',
          'sent ' + search.sent.length + ', ended=' + search.ended);
  t.check(search.sent.length === 1 && search.sent[0].messageId === 99,
          'and every entry carries the real response\'s message id',
          'it carried ' + (search.sent[0] || {}).messageId + ' rather than ' +
          '99 — ldapjs throws "SearchEntry messageId mismatch" for every ' +
          'search after the first on a connection');
  t.check(search.sent.length === 1 &&
          String(search.sent[0].objectName) === 'uid=x,' + USERS,
          'and names the entry the worker sent',
          'objectName came out as ' +
          JSON.stringify(String((search.sent[0] || {}).objectName)));

  // A COMPARE: the answer IS the argument to end(). This is the mutant.
  const compareTrue = applied('compare', { dn: USERS },
                              { ok: true, entries: [], endArg: true });
  t.check(compareTrue.endArg === true,
          'a compare that matched ends with true',
          'it ended with ' + JSON.stringify(compareTrue.endArg) + ' — a ' +
          'dropped argument answers compareFalse for every compare that ' +
          'matched, which looks exactly like a correct negative answer');
  const compareFalse = applied('compare', { dn: USERS },
                               { ok: true, entries: [], endArg: false });
  t.check(compareFalse.endArg === false,
          'and one that did not ends with false',
          'it ended with ' + JSON.stringify(compareFalse.endArg));

  // AND AN OPERATION WITH NO ARGUMENT STILL ENDS. `undefined` is how every
  // other operation answers, so a branch that only handled a value would leave
  // an add sending no result message at all.
  const added = applied('add', { dn: USERS },
                        { ok: true, entries: [], endArg: undefined });
  t.check(added.ended === true && added.endArg === undefined,
          'an operation with no answer still sends its result message',
          'ended=' + added.ended + ' — a handler that ends nothing hangs the ' +
          'client for ever, which is the defect ldap/CLAUDE.md records');

  // A REFUSAL: rebuilt onto next(), and nothing is sent or ended.
  const refused = applied('del', { dn: USERS },
                          { ok: false, errorName: 'NoSuchObjectError',
                            error: 'no such entry' });
  t.check(!!refused.failure && refused.failure.code === 32,
          'a refusal reaches next() as the right result code',
          'the client would be told ' +
          (refused.failure ? refused.failure.code : '(nothing)'));
  t.check(refused.ended === false && refused.sent.length === 0,
          'and nothing is sent or ended beside it',
          'a refusal that also ends sends two result messages for one ' +
          'operation');
  log.debug("Leaving checkTheFrontProcessHalf().");
}

// ---------------------------------------------------------------------------
// 10. THE TWO SOCKET EFFECTS OF A BIND, WHICH ONLY THIS PROCESS CAN PERFORM.
//
// The worker decides whether the bind succeeds; the connection is a file
// descriptor it does not hold. So `applyOperationResult()` stamps
// `stsBoundAt` and publishes the connection snapshot, and if it did not:
//
//   * `/admin/sessions` would report a directory connection as live and not
//     since when — the one fact a reader wants about a session with no expiry;
//   * and every request worker's mirror would show the socket as UNBOUND, so a
//     global sign-out would find nobody to sign out. That is the bug
//     `tests/ldap_logout.js` exists for, reached from the other end.
//
// **A REFUSED BIND MUST DO NEITHER**, which is the half that would otherwise
// go unnoticed: stamping a refused bind dates a session that never started.
// ---------------------------------------------------------------------------
function checkTheBindTouchesTheSocket(t, done) {
  log.debug("Entering checkTheBindTouchesTheSocket().");
  t.log.info('=== a dispatched bind still reaches the socket ===');

  let published = 0;
  ldapServer.setConnectionWatcher(function () { published++; });

  const ok = applied('bind', { dn: 'uid=alice,' + USERS },
                     { ok: true, entries: [], endArg: undefined });
  t.check(typeof ok.req.connection.stsBoundAt === 'number' &&
          ok.req.connection.stsBoundAt > 0,
          'a successful bind stamps the connection it was made on',
          'stsBoundAt is ' + JSON.stringify(ok.req.connection.stsBoundAt) +
          ' — /admin/sessions would report the connection as live and not ' +
          'since when');

  const refused = applied('bind', { dn: 'uid=alice,' + USERS },
                          { ok: false, errorName: 'InvalidCredentialsError',
                            error: 'no' });
  t.check(refused.req.connection.stsBoundAt === undefined,
          'and a refused bind stamps nothing',
          'a refused bind dated the connection, which would report a session ' +
          'that never started');

  // THE PUBLISH IS DEFERRED, for the reason publishConnectionsSoon() carries:
  // ldapjs sets the bound DN only after the handler chain has returned, so a
  // snapshot taken inline belongs to nobody.
  t.check(published === 0,
          'the snapshot is not published inline',
          'published ' + published + ' time(s) inside the call — ldapjs has ' +
          'not set the bound DN yet, so every row would be keyless');
  setImmediate(function () {
    t.check(published === 1,
            'and is published on the next tick',
            'published ' + published + ' time(s) — a worker\'s mirror would ' +
            'show this socket as unbound, so a global sign-out would find ' +
            'nobody to sign out');
    ldapServer.setConnectionWatcher(null);
    done();
  });
  log.debug("Leaving checkTheBindTouchesTheSocket().");
}

// ---------------------------------------------------------------------------
// 11. A SIZE-LIMITED SEARCH IS A PARTIAL ANSWER PLUS A REFUSAL, AND BOTH HALVES
// HAVE TO CROSS.
//
// **THIS IS THE ONE REAL DEFECT THE FIRST VERSION OF THIS FILE SHIPPED WITH.**
// `performOperation()` returned only the error when a handler failed, and the
// search handler's size-limit branch sends N entries and THEN fails with
// `SizeLimitExceededError` — RFC 4511 section 4.5.2, where the entries already
// sent are a valid partial answer and result code 4 is how the client learns it
// is partial. So a size-limited search in a worker answered **zero entries and
// code 4** where the front process answers `ldap.sizeLimit` entries and code 4.
//
// **A CLIENT THAT HANDLES CODE 4 CORRECTLY IS THE ONE IT MISLEADS**, which is
// what makes it worth a section rather than a line: the whole point of that
// branch is to tell a client its answer is incomplete, and this told it an
// empty answer was incomplete.
//
// **NOTHING ROUTINE REACHES THIS BRANCH.** `ldap.sizeLimit` is 500 and the
// seeded directory holds about thirty entries, so the only thing in either
// suite that gets there is `sts_directory_bulk_load_ldap.js` — over a socket,
// in a stack, and dispatched only in the `dispatch` mode, whose
// `workers.dispatch` is `*`. The section asks the client's `sizeLimit`
// instead, which `maxSearchResults()` honours when it is the smaller of the
// two, so the branch is reachable against a seeded directory.
// ---------------------------------------------------------------------------
function checkAPartialAnswerSurvives(t) {
  log.debug("Entering checkAPartialAnswerSurvives().");
  t.log.info('=== a size-limited search keeps its entries AND its code ===');

  const fields = { dn: USERS, scope: 2, filter: '(objectClass=*)',
                   sizeLimit: 2 };
  const viaPool = dispatched('search', fields);
  const control = directly('search', fields);

  t.check(control.entries.length === 2 && !!control.failure,
          'the control sends a partial answer and then refuses (' +
          control.entries.length + ' entries, ' +
          (control.failure ? control.failure.name : 'no failure') + ')',
          'the size-limit branch was not reached, so this section is ' +
          'comparing nothing — ldap.sizeLimit may have changed, or the ' +
          'directory may hold fewer entries than the limit asked for');

  t.check(viaPool.ok === false &&
          viaPool.errorName === 'SizeLimitExceededError',
          'the dispatched search refuses with the same error',
          'it answered ok=' + viaPool.ok + ' ' + (viaPool.errorName || ''));
  t.check(JSON.stringify(viaPool.entries) === JSON.stringify(control.entries),
          'AND CARRIES THE ENTRIES IT HAD ALREADY SENT (' +
          (viaPool.entries || []).length + ')',
          'the partial answer was dropped: ' +
          ((viaPool.entries || []).length) + ' entries through the pool ' +
          'against ' + control.entries.length + ' directly. A client that ' +
          'reads result code 4 — which is the only reason that branch sends ' +
          'one — would report an empty answer as incomplete and be believed');

  // AND THE FRONT PROCESS PUTS THEM ON THE WIRE BEFORE IT REFUSES. Carrying
  // them across and then dropping them here would be the same bug one function
  // later, which is why both halves are asserted.
  const written = applied('search', fields, viaPool);
  t.check(written.sent.length === control.entries.length,
          'and the front process sends them before it refuses (' +
          written.sent.length + ')',
          'it sent ' + written.sent.length + ' of ' + control.entries.length);
  t.check(!!written.failure && written.failure.code === 4,
          'with result code 4 after them',
          'the client was told ' +
          (written.failure ? written.failure.code : '(nothing)'));
  t.check(written.ended === false,
          'and no result message beside the refusal',
          'ldapjs turns the error handed to next() into the ' +
          'SearchResultDone, so an end() as well would be two of them');
  log.debug("Leaving checkAPartialAnswerSurvives().");
}

// ---------------------------------------------------------------------------
// 12. THE THREE SHAPES THE PROBE DID NOT COVER.
//
// Driving this over a real socket exercised bind, search, add, compare, modify
// and delete. These three were reachable and untested, and two of them are the
// shapes most likely to break in a codec rather than in a handler.
//
//   * **The ROOT DSE** is a search with an EMPTY base, and it is the first
//     thing every LDAP client does — a client that does not yet know the base
//     DN asks for it. An empty DN through `parseDN()` and back is exactly the
//     kind of value a serialisation boundary turns into something else.
//   * **`modifyDN`** is the only operation carrying TWO DNs, so it is the only
//     one whose request shape can lose one of them and still look sane.
//   * **An empty `newSuperior`** means "keep the parent" and is not the same as
//     a missing one; the handler derives the parent from the original DN.
// ---------------------------------------------------------------------------
function checkTheRemainingShapes(t) {
  log.debug("Entering checkTheRemainingShapes().");
  t.log.info('=== the root DSE and modifyDN cross ===');

  const dse = dispatched('search', { dn: '', scope: 0,
                                     filter: '(objectClass=*)' });
  t.check(dse.ok === true && (dse.entries || []).length === 1,
          'a root DSE search answers one entry through the codec',
          'ok=' + dse.ok + ' entries=' + (dse.entries || []).length +
          ' — an empty base DN did not survive the round trip, which breaks ' +
          'discovery for every client that does not already know the base');
  const contexts = dse.ok && dse.entries.length
    ? dse.entries[0].attributes.filter(function (a) {
        return a.type.toLowerCase() === 'namingcontexts';
      })
    : [];
  t.check(contexts.length === 1 && contexts[0].values.length > 0,
          'and publishes the naming contexts a client discovers realms from',
          'namingContexts came back as ' + JSON.stringify(contexts));

  const src = 'uid=rename-probe,' + USERS;
  const dst = 'uid=renamed-probe,' + USERS;
  const made = dispatched('add', {
    dn: src,
    attributes: [{ type: 'objectClass', values: ['top', 'inetOrgPerson'] },
                 { type: 'uid', values: ['rename-probe'] },
                 { type: 'sn', values: ['Probe'] }]
  });
  t.check(made.ok === true, 'an entry to rename was created', made.error || '');

  // AN EMPTY newSuperior MEANS "KEEP THE PARENT", which is what a plain
  // `ldapmodrdn` sends.
  const moved = dispatched('modifyDN', { dn: src, newRdn: 'uid=renamed-probe',
                                         newSuperior: '' });
  t.check(moved.ok === true, 'modifyDN succeeds through the codec',
          moved.error || '');

  const there = dispatched('search', { dn: dst, scope: 0,
                                       filter: '(objectClass=*)' });
  t.check(there.ok === true && (there.entries || []).length === 1,
          'and the entry is at its new DN',
          'the search answered ' + (there.entries || []).length +
          ' — both DNs have to cross, and only one of them is req.dn');

  const old = dispatched('search', { dn: src, scope: 0,
                                     filter: '(objectClass=*)' });
  t.check(old.ok === false,
          'and is gone from the old one',
          'the original DN still resolves, so the rename copied rather than ' +
          'moved');

  // ---------------------------------------------------------------------
  // AND A MOVE, WHICH IS THE ONLY CASE THAT READS `newSuperior` AT ALL.
  //
  // **A MUTANT SURVIVED WITHOUT THIS.** Blanking `newSuperior` in the request
  // shape changed nothing, because the rename above sends it EMPTY — and an
  // empty one means "keep the parent", which the handler derives from the
  // original DN. So the one field carrying a second container was covered only
  // by the value that makes it irrelevant.
  //
  // A move to a different container is what tells the two apart: with
  // `newSuperior` lost, the entry would be renamed in place under `ou=users`
  // and the search below would find nothing where it was asked to go.
  // ---------------------------------------------------------------------
  const GROUPS = 'ou=groups,' + BASE;
  const moveTo = 'uid=renamed-probe,' + GROUPS;
  const moved2 = dispatched('modifyDN', { dn: dst, newRdn: 'uid=renamed-probe',
                                          newSuperior: GROUPS });
  t.check(moved2.ok === true,
          'a modifyDN naming a new parent succeeds',
          moved2.error || '');
  const landed = dispatched('search', { dn: moveTo, scope: 0,
                                        filter: '(objectClass=*)' });
  t.check(landed.ok === true && (landed.entries || []).length === 1,
          'and the entry is under the container it named',
          'it is not at ' + moveTo + ' — newSuperior did not cross, so the ' +
          'entry was renamed in place under its old parent');
  const notLeftBehind = dispatched('search', { dn: dst, scope: 0,
                                               filter: '(objectClass=*)' });
  t.check(notLeftBehind.ok === false,
          'and is not still under the old one',
          'the entry is in both containers, so the move copied');

  dispatched('del', { dn: moveTo });
  dispatched('del', { dn: dst });
  log.debug("Leaving checkTheRemainingShapes().");
}

function run(t) {
  log.debug("Entering run().");
  checkASearchAgrees(t);
  checkTheAttributeSelectionCrosses(t);
  checkARefusalKeepsItsResultCode(t);
  checkAnUnknownRefusalIsStillARefusal(t);
  checkAWriteCrosses(t);
  checkACompareCarriesItsAnswer(t);
  checkTheBoundIdentityCrosses(t);
  checkTheOperationTableAgrees(t);
  checkTheFrontProcessHalf(t);
  checkAPartialAnswerSurvives(t);
  checkTheRemainingShapes(t);
  log.debug("Leaving run().");
  // The one section with a tick in it, so `run()` answers a promise the runner
  // awaits — see tests/run.js, which handles both shapes.
  return new Promise(function (resolve) {
    checkTheBindTouchesTheSocket(t, resolve);
  });
}

module.exports = {
  name: 'ldap_operations',
  describe: 'the directory as an operation: what crosses to a request ' +
            'worker, that a dispatched answer is the same answer, and that a ' +
            'refusal keeps its LDAP result code',
  run: run
};
