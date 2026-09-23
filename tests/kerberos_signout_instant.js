'use strict';
//
// File: kerberos_signout_instant.js
//
// ===========================================================================
// A KERBEROS SIGN-OUT OUTLIVES THE NEXT AS EXCHANGE (#111, 2026-09-23).
//
// `/logout` stamps a sign-out instant on the principal, and the KDC refuses a
// TGS-REQ whose ticket was authenticated before it with KDC_ERR_TGT_REVOKED
// (20). Until #111 the next successful AS exchange CLEARED that instant — so
// the moment a signed-out person ran `kinit` again, every ticket-granting
// ticket from before the sign-out (a renewal of one included, since a renewal
// keeps authtime) was accepted again, for up to its renew-till. This file is
// the in-process guard for the fix, `kerberos/CLAUDE.md` argues the design:
//
//   A. THE STAMP'S ARITHMETIC, on `krb5_principals.js`'s own functions: the
//      whole-second boundary, the horizon (the latest a ticket from before
//      the stamp can still be valid), the development-only undo as a THIRD
//      instant, and the stamp taken on the KDC's clock (`krb5.clockOffset`).
//   B. THE MERGE, at the accessors both persistence doors call
//      (`realms.sharedMap()`'s restore): each sign-out field is the LATER of
//      the held and the incoming value, for a configured principal and for a
//      runtime-made one alike — so another node's older copy of the row can
//      never unstamp a sign-out.
//   C. THE EXCHANGES, the KDC driven in process with `tests/vendored/
//      krb5_wire.js` (the job client, written apart from the KDC): sign in,
//      sign out in the first part of a second, the old TGT refused 20, a NEW
//      AS exchange in the same second answered after the boundary and its TGT
//      accepted, the OLD TGT still refused, a RENEWAL of the old TGT refused,
//      a renewal of the new one keeping its authtime and accepted — and the
//      same with the KDC's clock moved by `krb5.clockOffset`.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first.
//
// The cases that decide this are about one second and one clock: a sign-out
// and an AS exchange landing in the SAME second (the reason the old code gave
// for clearing), and a KDC whose clock is deliberately moved. Over HTTP both
// are a race against a network and a container's clock; here the file chooses
// the millisecond. The same exchanges over a real socket are
// `tests/vendored/sts_kerberos_signout.js`, in both modes. The behaviour is
// the same in both modes (#111's decision 3, no predicate), so this file runs
// the development database this process built.
//
// Everything it touches is put back: its probe principals are removed, the
// configured account's sign-out fields restored, and every override cleared.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const wire = require('./vendored/krb5_wire.js');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'kerberos_signout_instant',
  level: process.env.LOG_LEVEL || 'info' });

const FIELDS = ['signedOutAt', 'signOutHorizon', 'signOutClearedAt'];

function iso(value) {
  log.debug("Entering iso().");
  log.debug("Leaving iso().");
  if (!value) {
    return null;
  }
  return new Date(value).toISOString();
}

function store() {
  log.debug("Entering store().");
  log.debug("Leaving store().");
  return realms.handleFor('krb5.principals');
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// Until the wall clock is in the first `within` ms of a second, so what the
// file does next lands in that second.
async function earlyInASecond(within) {
  log.debug("Entering earlyInASecond().");
  while (Date.now() % 1000 >= within) {
    await pause(1000 - (Date.now() % 1000) + 1);
  }
  log.debug("Leaving earlyInASecond().");
}

// The KDC, in process: the bytes a client sends in, the bytes it answers out.
function inProcess() {
  log.debug("Entering inProcess().");
  log.debug("Leaving inProcess().");
  return {
    label: 'the KDC in process',
    send: function (bytes) {
      log.debug("Entering send().");
      log.debug("Leaving send().");
      return kdc.handleMessage(Buffer.from(bytes)).then(function (reply) {
        return Buffer.from(reply);
      });
    }
  };
}

function withOverride(key, value, fn) {
  log.debug("Entering withOverride(). " + key);
  config.setOverride(key, value);
  const done = function () {
    log.debug("Entering done().");
    config.clearOverride(key);
    log.debug("Leaving done().");
  };
  let result;
  try {
    result = fn();
  } catch (e) {
    log.debug("Caught in withOverride(): " + ((e && e.message) || e));
    done();
    throw e;
  }
  log.debug("Leaving withOverride().");
  return Promise.resolve(result).then(function (value2) {
    done();
    return value2;
  }, function (e) {
    log.debug("Caught in withOverride(): " + ((e && e.message) || e));
    done();
    throw e;
  });
}

// ---------------------------------------------------------------------------
// A. THE ARITHMETIC.
// ---------------------------------------------------------------------------
async function theArithmetic(t) {
  log.debug("Entering theArithmetic().");
  t.log.info('=== A. the boundary, the horizon, the undo and the clock ===');
  t.equal(iso(principals.signOutBoundary('2026-01-02T03:04:05.000Z')),
          '2026-01-02T03:04:05.000Z',
          'a stamp on a whole second is its own boundary');
  t.equal(iso(principals.signOutBoundary('2026-01-02T03:04:05.001Z')),
          '2026-01-02T03:04:06.000Z',
          'A STAMP WITH MILLISECONDS IS ROUNDED UP to the next whole ' +
          'second — the smallest authtime newer than it');
  t.equal(principals.signOutBoundary(null), null, 'no stamp, no boundary');

  const name = 'signout-arith-' + process.pid +
               Math.random().toString(36).slice(2, 6);
  const probe = principals.findOrCreateUser([name]);
  const key = name + '@' + principals.REALM;
  try {
    t.check(!!probe, 'a development principal to stamp', name);
    t.equal(principals.signedOutAt([name]), null, 'which starts unstamped');

    const before = Date.now();
    principals.signOut([name]);
    const stamp = principals.signedOutAt([name]);
    t.check(!!stamp && stamp.getTime() >= before &&
            stamp.getTime() <= Date.now(),
            'signOut() stamps now on the KDC\'s clock (no offset set)',
            iso(stamp));
    const longest = Math.max(Number(config.value('krb5.ticketLifetimeSeconds')),
                             Number(config.value('krb5.renewLifetimeSeconds')));
    const skew = Number(config.value('krb5.clockSkew'));
    t.equal(iso(principals.signOutHorizon([name])),
            iso(stamp.getTime() + (longest + skew) * 1000),
            'THE HORIZON IS THE STAMP PLUS THE LONGER OF THE TICKET AND ' +
            'RENEW LIFETIMES, PLUS THE CLOCK SKEW — the latest a ticket from ' +
            'before it can still be presented or renewed');
    t.check(principals.signedOutPrincipals().some(function (one) {
      return one.principal === key;
    }), 'and it is listed among the signed-out principals');

    // Past the horizon the stamp answers as none.
    const held = principals.find([name]);
    const keptHorizon = held.signOutHorizon;
    held.signOutHorizon = new Date(Date.now() - 1000);
    t.equal(principals.signedOutAt([name]), null,
            'PAST ITS HORIZON A STAMP IS NO LONGER IN FORCE — nothing is ' +
            'swept, it simply answers as none');
    t.check(!principals.signedOutPrincipals().some(function (one) {
      return one.principal === key;
    }), 'and is not listed');
    held.signOutHorizon = keptHorizon;
    t.equal(iso(principals.signedOutAt([name])), iso(stamp),
            'inside its horizon it is in force again');

    // A second sign-out never shortens the horizon.
    const lowered = await withOverride('krb5.renewLifetimeSeconds', 60,
      async function () {
        await pause(5);
        principals.signOut([name]);
        return principals.signOutHorizon([name]);
      });
    t.equal(iso(lowered), iso(keptHorizon),
            'A LATER SIGN-OUT UNDER SHORTER LIFETIMES KEEPS THE LONGER ' +
            'HORIZON — the first sign-out\'s tickets are still out there');

    // The development-only undo, as a third instant.
    const was = principals.clearSignOut([name]);
    t.check(!!was, 'clearSignOut() reports the stamp it cleared', iso(was));
    t.equal(principals.signedOutAt([name]), null,
            'and the stamp is no longer in force');
    t.check(!!held.signedOutAt && !!held.signOutClearedAt,
            'THE UNDO DOES NOT NULL THE STAMP: it writes signOutClearedAt ' +
            'beside it, which a merge by the later instant can carry',
            JSON.stringify({ at: iso(held.signedOutAt),
                             cleared: iso(held.signOutClearedAt) }));
    await pause(5);
    principals.signOut([name]);
    t.check(!!principals.signedOutAt([name]),
            'and the next sign-out, being later, beats it');

    // The KDC's clock.
    const offset = 120;
    const onTheKdcClock = await withOverride('krb5.clockOffset', offset,
      function () {
        const at = Date.now();
        principals.signOut([name]);
        return { at: at, stamp: principals.signedOutAt([name]) };
      });
    const drift = onTheKdcClock.stamp.getTime() - onTheKdcClock.at;
    t.check(drift >= offset * 1000 && drift < offset * 1000 + 1000,
            'SIGNOUT() STAMPS ON THE KDC\'S CLOCK: krb5.clockOffset moves ' +
            'the stamp exactly as it moves authtime', drift + ' ms');
  } finally {
    store().remove('', key);
  }
  log.debug("Leaving theArithmetic().");
}

// ---------------------------------------------------------------------------
// B. THE MERGE, AT THE ACCESSORS BOTH DOORS CALL.
// ---------------------------------------------------------------------------
function theMerge(t) {
  log.debug("Entering theMerge().");
  t.log.info('=== B. each sign-out field merges as the later instant ===');
  const handle = store();
  const spn = String(config.value('krb5.servicePrincipal')).split('/');
  const key = spn.join('/') + '@' + principals.REALM;
  const web = principals.find(spn);
  t.check(!!web && principals.isConfigured(spn),
          'the acceptor\'s account is a CONFIGURED principal here');
  if (!web) {
    log.debug("Leaving theMerge().");
    return;
  }
  const saved = {};
  FIELDS.forEach(function (f) {
    saved[f] = web[f];
  });
  const T1 = '2026-01-02T03:04:05.000Z';
  const T2 = '2026-05-06T07:08:09.000Z';
  const FAR = new Date(Date.now() + 86400000).toISOString();
  const autoName = 'signout-merge-' + process.pid +
                   Math.random().toString(36).slice(2, 6);
  const autoKey = autoName + '@' + principals.REALM;
  const row = function (base, fields) {
    log.debug("Entering row().");
    log.debug("Leaving row().");
    return Object.assign(JSON.parse(JSON.stringify(base)), fields);
  };
  try {
    // A configured principal.
    handle.restore('', key, row(web, { signedOutAt: T2,
                                       signOutHorizon: FAR,
                                       signOutClearedAt: null }));
    t.equal(iso(principals.signedOutAt(spn)), T2,
            'a restored stamp reaches a configured principal');
    handle.restore('', key, row(web, { signedOutAt: T1,
                                       signOutHorizon: FAR,
                                       signOutClearedAt: null }));
    t.equal(iso(principals.signedOutAt(spn)), T2,
            'AN OLDER INCOMING STAMP DOES NOT MOVE A NEWER ONE BACK — the ' +
            'last-writer race of 2026-09-14 is gone');
    handle.restore('', key, row(web, { signedOutAt: null,
                                       signOutHorizon: null,
                                       signOutClearedAt: null }));
    t.equal(iso(principals.signedOutAt(spn)), T2,
            'AND A ROW WITH NO STAMP AT ALL DOES NOT UNSTAMP IT — which is ' +
            'what the AS exchange\'s clear used to write');
    handle.restore('', key, row(web, { signOutClearedAt: T1 }));
    t.equal(iso(principals.signedOutAt(spn)), T2,
            'an undo OLDER than the stamp does not clear it');
    const later = new Date(Date.parse(T2) + 1000).toISOString();
    handle.restore('', key, row(web, { signOutClearedAt: later }));
    t.equal(principals.signedOutAt(spn), null,
            'A REPLICATED UNDO LATER THAN THE STAMP CLEARS IT');
    const newest = new Date(Date.parse(T2) + 5000).toISOString();
    handle.restore('', key, row(web, { signedOutAt: newest }));
    t.equal(iso(principals.signedOutAt(spn)), newest,
            'and a replicated sign-out later than that undo is in force ' +
            'again');
    t.equal(iso(web.signOutClearedAt), later,
            'with the undo still held beside it, merged rather than dropped');

    // A runtime-made principal, restored whole — except the sign-out.
    const made = principals.findOrCreateUser([autoName]);
    t.check(!!made && made.autoCreated === true,
            'an auto-created principal to restore over');
    made.signedOutAt = T2;
    made.signOutHorizon = FAR;
    const older = row(made, { signedOutAt: T1, kvno: 9,
                              description: 'from another node' });
    handle.restore('', autoKey, older);
    const after = principals.find([autoName]);
    t.check(!!after && after.kvno === 9 &&
            after.description === 'from another node',
            'a runtime-made row is still restored whole',
            after && JSON.stringify({ kvno: after.kvno }));
    t.equal(iso(principals.signedOutAt([autoName])), T2,
            'BUT ITS SIGN-OUT IS THE LATER OF THE TWO — another node\'s ' +
            'older copy of a person\'s row does not unstamp them');
    handle.restore('', autoKey, row(after, { signedOutAt: newest }));
    t.equal(iso(principals.signedOutAt([autoName])), newest,
            'while a newer incoming stamp is taken');
  } finally {
    FIELDS.forEach(function (f) {
      web[f] = saved[f];
    });
    handle.remove('', autoKey);
  }
  log.debug("Leaving theMerge().");
}

// ---------------------------------------------------------------------------
// C. THE EXCHANGES.
// ---------------------------------------------------------------------------
async function signIn(transport, name) {
  log.debug("Entering signIn(). " + name);
  const r = await wire.asExchange(transport, principals.REALM, name,
    { password: String(config.value('krb5.userPassword')) });
  log.debug("Leaving signIn().");
  return r;
}

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return result && !result.ok && result.error ? result.error.code : null;
}

async function theExchanges(t, offsetSeconds) {
  log.debug("Entering theExchanges(). offset=" + offsetSeconds);
  const label = offsetSeconds ? ' (krb5.clockOffset ' + offsetSeconds + ' s)'
                              : '';
  t.log.info('=== C. AS, sign-out, AS again, TGS and RENEW' + label + ' ===');
  const transport = inProcess();
  const realm = principals.REALM;
  const name = 'signout-wire-' + process.pid +
               Math.random().toString(36).slice(2, 6);
  const krbtgt = { type: 2, name: ['krbtgt', realm] };
  const spn = String(config.value('krb5.servicePrincipal')).split('/');
  const service = { type: 3, name: spn };
  try {
    const first = await signIn(transport, name);
    t.check(!!first.tgt && first.tgt.flagNames.indexOf('renewable') !== -1,
            'sign in: a renewable TGT for ' + name + label,
            JSON.stringify(first.second || first.first).slice(0, 300));
    if (!first.tgt) {
      log.debug("Leaving theExchanges().");
      return;
    }
    const old = first.tgt;
    t.check((await wire.tgsExchange(transport, old, service)).ok,
            'the TGT buys a service ticket before the sign-out');

    // The sign-out and the next AS exchange in the SAME second: the case the
    // old clear existed for.
    await pause(1000);
    await earlyInASecond(300);
    principals.signOut([name], realm);
    const stamp = principals.signedOutAt([name], realm);
    const boundary = principals.signOutBoundary(stamp);
    const refused = await wire.tgsExchange(transport, old, service);
    t.equal(codeOf(refused), 20,
            'SIGNED OUT: the TGT from before it is refused ' +
            'KDC_ERR_TGT_REVOKED (20)');

    const second = await signIn(transport, name);
    t.check(!!second.tgt,
            'A NEW AS EXCHANGE SUCCEEDS — signing out is not being locked out',
            JSON.stringify(second.second || second.first).slice(0, 300));
    if (!second.tgt) {
      log.debug("Leaving theExchanges().");
      return;
    }
    const fresh = second.tgt;
    t.check(fresh.authtime.getTime() >= boundary.getTime(),
            'AND ITS AUTHTIME IS AT OR AFTER THE SIGN-OUT\'S WHOLE SECOND — ' +
            'the exchange waited for it rather than clearing the stamp',
            'authtime ' + iso(fresh.authtime) + ', stamp ' + iso(stamp) +
            ', boundary ' + iso(boundary));
    t.equal(iso(principals.signedOutAt([name], realm)), iso(stamp),
            'THE AS EXCHANGE LEFT THE STAMP WHERE IT WAS');

    const newTicket = await wire.tgsExchange(transport, fresh, service);
    t.check(newTicket.ok, 'the NEW TGT buys a service ticket',
            newTicket.error && newTicket.error.toString());
    const stillRefused = await wire.tgsExchange(transport, old, service);
    t.equal(codeOf(stillRefused), 20,
            'THE OLD TGT IS STILL REFUSED 20 after a new AS exchange — #111');
    const renewedOld = await wire.tgsExchange(transport, old, krbtgt, realm,
                                              { renew: true });
    t.equal(codeOf(renewedOld), 20,
            'A RENEWAL OF THE OLD TGT IS REFUSED 20 — a renewal keeps ' +
            'authtime, so it cannot launder a signed-out ticket');
    const renewedNew = await wire.tgsExchange(transport, fresh, krbtgt, realm,
                                              { renew: true });
    t.check(renewedNew.ok &&
            iso(renewedNew.authtime) === iso(fresh.authtime),
            'a renewal of the NEW TGT is accepted and keeps its authtime',
            renewedNew.ok ? iso(renewedNew.authtime)
                          : renewedNew.error && renewedNew.error.toString());
    if (renewedNew.ok) {
      t.check((await wire.tgsExchange(transport, renewedNew, service)).ok,
              'and the renewed TGT buys a service ticket');
    }

    // The development-only undo, which this process's mode opens.
    if (!offsetSeconds) {
      principals.clearSignOut([name], realm);
      t.check((await wire.tgsExchange(transport, old, service)).ok,
              'restore-kerberos\'s clearSignOut() puts the old TGT back ' +
              'into service (development only)');
    }
  } finally {
    store().remove('', name + '@' + realm);
  }
  log.debug("Leaving theExchanges().");
}

module.exports = {
  name: 'kerberos_signout_instant',
  describe: 'a Kerberos sign-out instant outlives the next AS exchange, is ' +
            'compared in whole seconds on the KDC\'s clock, is bounded by a ' +
            'horizon and merges as the later instant (#111)',
  run: async function (t) {
    log.debug("Entering run().");
    t.check(config.value('logout.kerberosSignOut') === true,
            'logout.kerberosSignOut is on, as by default');
    await theArithmetic(t);
    theMerge(t);
    await theExchanges(t, 0);
    // Inside krb5.clockSkew, so the client's own timestamps (taken on the
    // real clock) are still accepted while the KDC's authtime and stamp move.
    await withOverride('krb5.clockOffset', 120, function () {
      return theExchanges(t, 120);
    });
    log.debug("Leaving run().");
  }
};
