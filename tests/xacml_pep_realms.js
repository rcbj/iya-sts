'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'xacml_pep_realms',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: xacml_pep_realms.js
//
// ===========================================================================
// A REMOTE PEP IS REGISTERED IN A REALM, AND THE OTHER REALMS SAY WHERE IT IS.
//
// **THIS FILE EXISTS BECAUSE AN EMPTY LIST HAD TWO CAUSES AND NAMED NEITHER.**
// `ou=peps` is per realm, like the policy repository it serves, and every page
// in that console draws ONE realm. So `/admin/xacml/peps` and the remote half
// of `/admin/xacml/monitor` said *no remote Policy Enforcement Point has
// registered* in two completely different situations:
//
//   1. none anywhere in this process — the ordinary state of a fresh service;
//   2. none IN THE REALM BEING READ, while another realm holds one and is
//      enforcing with it right now.
//
// The second is not hypothetical: it is the only state a RUNNING suite
// produces. `tests/vendored/sts_xacml_remote_pep.js` drives the `xacml-pep/`
// container against a THROWAWAY REALM (`XACML_PEP_REALM`, `pep-e2e` by
// default), so a registration made by that job has never been in the default
// realm and never will be — and somebody who ran `./local-run-tests.sh` (a
// launcher that left its stack up, removed 2026-09-16) and then opened the
// monitor page was told nothing had registered, which was true
// of the realm they were reading and false of the process they were reading it
// in.
//
// That is `/admin/realms`'s own lesson made again — **a predicate that is false
// for two reasons must not be rendered as a message that names one of them** —
// and this file is what stops it coming back.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// What is under test is a MODULE CONTRACT: what `elsewhere()` answers about a
// register that is partitioned by realm. Asserting it over HTTP would mean
// REGISTERING a remote PEP over HTTP, which needs a client certificate chaining
// to an anchor in this service's truststore whose subject DN resolves to an
// entry holding `REMOTE_PEPS` — a launcher, a credential and a second
// container, all of which `sts_xacml_remote_pep.js` already builds to assert
// something else. This drives the registry directly and asserts both halves in
// milliseconds.
//
// It also covers what that job does not drive at all: a realm REMOVED, and the
// row going with it. That job used to remove its realm at teardown; it leaves
// it standing since 2026-09-06 (tests/CLAUDE.md, *No job removes a realm*), so
// after a green suite the row is still there and the default realm's pages
// name the realm holding it.
// ===========================================================================

delete process.env.CONFIG_FILE;

module.exports = {
  name: 'xacml_pep_realms',
  describe: 'a remote PEP registered in one realm is invisible in another\'s ' +
            'list and REPORTED in its answer — the empty list that had two ' +
            'causes',
  run: function (t) {
    log.debug("Entering run().");
    const realms = require('../common/realms');
    // The directory IS `ou=peps`. Requiring it seeds the default realm's
    // subtree and fills the registry's directory slot; without it every call
    // below answers "no directory" and this file would pass by asserting
    // nothing — which is why the first assertion checks that the register is
    // readable at all rather than merely empty.
    require('../ldap/ldap_server');
    const peps = require('../xacml/xacml_pep_registry');

    const REALM = 'peprealm';

    // A registration, in the shape `/xacml/pep/register` writes one. Nothing
    // here checks a certificate: what is under test is the REGISTER, and the
    // gate in front of it is `sts_xacml_remote_pep.js`'s subject.
    function registerOne(name) {
      log.debug("Entering registerOne().");
      log.debug("Leaving registerOne().");
      return peps.register({
        name: name,
        identity: 'cn=' + name + ',ou=users,dc=example,dc=com',
        certificateSubject: 'CN=' + name,
        thumbprint: 'test-' + name,
        authenticated: true,
        bias: 'deny',
        resource: 'https://example.test/api'
      });
    }

    t.check(peps.directoryInstalled(),
            'the registry has a directory to read, so an empty list below is ' +
            'a real answer rather than a missing store');

    // -------------------------------------------------------------------
    // THE ORDINARY SERVICE: nothing anywhere.
    // -------------------------------------------------------------------
    t.equal(peps.all().length, 0,
            'the default realm holds no remote PEP before this file writes ' +
            'one');
    t.equal(peps.elsewhere().length, 0,
            'AND NO OTHER REALM HOLDS ONE EITHER — the answer that lets the ' +
            'page say "in this realm or in any other" instead of a sentence ' +
            'that could mean two things');

    const realm = realms.create({ id: REALM, name: 'PEP realm' });
    if (!realm) {
      t.check(false, 'the throwaway realm could not be created, so the ' +
                     'per-realm assertions did not run');
      log.debug("Leaving run().");
      return;
    }

    const written = realms.run(realms.get(REALM), function () {
      return registerOne('remote-pep-1');
    });
    t.check(!!written && written.ok !== false,
            'registering a PEP inside the realm answered ok');

    // -------------------------------------------------------------------
    // THE REALM SEES IT; THE DEFAULT REALM DOES NOT — AND SAYS WHERE IT IS.
    // -------------------------------------------------------------------
    const insideList = realms.run(realms.get(REALM), function () {
      return peps.all();
    });
    t.equal(insideList.length, 1,
            'the realm the PEP registered in lists it');
    const insideElsewhere = realms.run(realms.get(REALM), function () {
      return peps.elsewhere();
    });
    t.equal(insideElsewhere.length, 0,
            'and reports no OTHER realm holding one — the realm you are ' +
            'standing in is never in its own "elsewhere", or every page ' +
            'would point at itself');

    t.equal(peps.all().length, 0,
            'THE DEFAULT REALM STILL LISTS NONE, which is correct and is ' +
            'exactly the state that read as "nothing has registered" before ' +
            'this change');
    const outside = peps.elsewhere();
    t.equal(outside.length, 1,
            'AND THIS IS THE ASSERTION THE FILE IS FOR: it reports that ' +
            'another realm holds one, so an empty list can no longer be read ' +
            'as an empty process');
    t.equal((outside[0] || {}).id, REALM,
            'naming the realm to look in');
    t.equal((outside[0] || {}).count, 1,
            'and how many are there — "somewhere else" without a count is a ' +
            'hint a reader cannot act on');

    // -------------------------------------------------------------------
    // AND REMOVING THE REALM TAKES THE ROW WITH IT.
    //
    // This was what a COMPLETED `sts_xacml_remote_pep.js` run left behind
    // until 2026-09-06, when the suite stopped removing the realms it creates.
    // Removing a realm by hand is still how the row goes, and then "none
    // anywhere" is the honest answer even while a PEP container is still
    // running and still polling: the register that held the row went away
    // with the realm.
    // -------------------------------------------------------------------
    realms.remove(REALM);
    t.equal(peps.elsewhere().length, 0,
            'with the realm gone the answer is "none anywhere" again, which ' +
            'is what a passing suite really does leave behind');
    log.debug("Leaving run().");
  }
};
