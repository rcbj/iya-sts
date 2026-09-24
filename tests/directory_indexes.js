'use strict';
//
// File: directory_indexes.js
//
// ===========================================================================
// THE TWO INDEXES BESIDE THE STORE, AND THE ONE PROPERTY NEITHER MAY COST.
//
// `ldap/ldap_server.js` keeps two caches over the embedded directory — a
// username index behind `existingUserEntry()` and a group index behind
// `groupsOfUser()` — and both are kept current by stamping a
// `directoryVersion` forward across writes that provably cannot have changed
// them. That stamping is what made a create constant-time on 2026-09-07;
// `ldap/CLAUDE.md` has the measurements and the argument.
//
// **A PERFORMANCE FIX IS NOT WHAT THIS FILE TESTS.** A cache that is merely
// slow is a cache that works. What these assertions guard is the thing the
// stamping could take away and a benchmark would never notice: that **a write
// is visible to the very next read**. `groupsOfUser()` is read once per token —
// every access token, every ID Token and both SAML assertions — and the reason
// it has no TTL is written out beside it: an `ldapadd` has to change the very
// next token, because that is the thing somebody came to a mock directory to
// watch. A stamp that skipped an invalidation it should have made would leave
// that read answering out of a stale index, and the symptom would be a `groups`
// claim that is correct-looking, verifiable, and wrong.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS RATHER THAN OVER HTTP.
//
// `tests/CLAUDE.md`'s rule is "can it be asserted by driving the running
// service over HTTP?", and a stale index CAN be seen that way — a token whose
// `groups` claim is missing a group somebody was just added to. What cannot be
// seen that way is WHICH of the two indexes answered, or whether the index was
// rebuilt or kept, and those are the distinctions the stamping introduces. A
// test that drove HTTP would pass just as happily against a version of this
// module with no indexes in it at all, which is the shape of test that stops
// guarding a thing the day somebody rewrites it.
//
// The interleaving is the whole method. A single write followed by a single
// read passes against any implementation; what finds a bad stamp is a write of
// the kind that IS invalidating, followed by writes of the kind that are NOT,
// followed by the read — because a stamp applied one step too widely is
// exactly a cache that survives a change it should not have survived.
// ===========================================================================

const ldap = require('../ldap/ldap_server');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'directory_indexes',
  level: process.env.LOG_LEVEL || 'info' });

// A distinct prefix per run, because nothing in this suite deletes anything and
// two runs in one process would otherwise meet each other's people.
const RUN = 'idx' + require('crypto').randomBytes(3).toString('hex');
const person = function (n) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return RUN + '-p' + n;
};

const team = function (n) {
  log.debug("Entering team().");
  log.debug("Leaving team().");
  return RUN + '-g' + n;
};

// ---------------------------------------------------------------------------
// THE USERNAME INDEX: one entry per person, however the name is spelled and
// whatever else has been written since.
// ---------------------------------------------------------------------------
function checkTheUsernameIndex(t) {
  log.debug("Entering checkTheUsernameIndex().");
  t.log.info('=== the username index still refuses a second entry ===');

  const first = ldap.createUser(person(1), { invent: false });
  t.check(first.ok, 'a person can be created', first.ok ? first.dn :
          JSON.stringify(first.errors));

  const again = ldap.createUser(person(1), { invent: false });
  t.check(again.ok === false && !!again.existing,
          'and creating them a second time is refused, naming the entry that ' +
          'already holds the name — the one-entry-per-person rule, which is ' +
          'what existingUserEntry() is FOR and what the index must not weaken',
          again.existing ? again.existing.dn : JSON.stringify(again.errors));

  const shouted = ldap.createUser(person(1).toUpperCase(), { invent: false });
  t.check(shouted.ok === false,
          'refused case-insensitively too, which the walk this index ' +
          'replaced did by lower-casing both sides',
          JSON.stringify(shouted.ok));

  // THE INTERLEAVING. Every one of these is a write, and each stamps the index
  // forward rather than rebuilding it. If the stamp were wrong — a name folded
  // in under the wrong key, or a version moved on a write that did change the
  // index — the refusal above would stop happening somewhere in here.
  for (let i = 0; i < 25; i++) {
    const made = ldap.createUser(person(100 + i), { invent: true });
    if (!made.ok) {
      t.check(false, 'person ' + (100 + i) + ' was created',
              JSON.stringify(made.errors));
      log.debug("Leaving checkTheUsernameIndex().");
      return;
    }
  }
  t.check(true, '25 more people were created, each one a write that keeps ' +
          'the index rather than rebuilding it', '25');

  const stillRefused = ldap.createUser(person(1), { invent: false });
  t.check(stillRefused.ok === false,
          'AND THE FIRST PERSON IS STILL FOUND after all of them — a stamp ' +
          'that lost an entry would show here and nowhere earlier',
          JSON.stringify(stillRefused.ok));

  const middle = ldap.createUser(person(112), { invent: false });
  t.check(middle.ok === false,
          'and so is one created in the middle of the run, through the ' +
          '`invent: true` path that applyVcAttributes() writes to',
          middle.existing ? middle.existing.dn : JSON.stringify(middle.ok));
  log.debug("Leaving checkTheUsernameIndex().");
}

// ---------------------------------------------------------------------------
// THE GROUP INDEX: the property with a token on the end of it.
//
// The stamp rests on a narrow invariant — a non-group entry contributes to
// neither half of that index — so what has to be asserted is the boundary of
// it: a GROUP write is seen immediately, and no number of person writes on
// either side of it changes that.
// ---------------------------------------------------------------------------
function checkTheGroupIndex(t) {
  log.debug("Entering checkTheGroupIndex().");
  t.log.info('=== a group write is visible to the very next read ===');

  const who = person(2);
  ldap.createUser(who, { invent: false });
  // Read first, deliberately: this BUILDS the index, so everything below is
  // exercising the kept-and-stamped path rather than a cold cache that would
  // have been rebuilt anyway.
  t.check(ldap.groupsOfUser(who).groups.length === 0,
          'a new person is in no group, and asking has built the index',
          '0');

  const group = ldap.createGroup(team(1));
  t.check(group.ok, 'a group was created', group.ok ? group.dn :
          JSON.stringify(group.errors));

  const added = ldap.addGroupMember(team(1), who);
  t.check(added.ok, 'and the person was added to it', added.ok ? 'yes' :
          JSON.stringify(added.errors));

  const now = ldap.groupsOfUser(who);
  t.check(now.groups.length === 1,
          'THE VERY NEXT READ SEES IT. This is the assertion the whole ' +
          'version-keyed design exists to keep, and the one a stamp applied ' +
          'too widely would take away — a group write is not a write the ' +
          'index may survive',
          JSON.stringify(now.groups.map(function (g) { return g.cn; })));

  // Now the shape that actually finds a bad stamp: person writes AROUND the
  // group write. Each of these keeps the index; none of them may resurrect a
  // state from before the membership existed.
  for (let i = 0; i < 20; i++) {
    ldap.createUser(person(200 + i), { invent: true });
  }
  const after = ldap.groupsOfUser(who);
  t.check(after.groups.length === 1,
          'and 20 person creates afterwards do not lose it — a person write ' +
          'keeps this index by design, so it must keep the CURRENT one',
          String(after.groups.length));

  const second = ldap.createUser(person(3), { invent: true });
  t.check(second.ok, 'a second person exists', second.ok ? 'yes' : 'no');
  t.check(ldap.groupsOfUser(person(3)).groups.length === 0,
          'who is in no group — a kept index must not hand somebody else\'s ' +
          'membership to a person created after it was stamped',
          '0');

  ldap.addGroupMember(team(1), person(3));
  t.check(ldap.groupsOfUser(person(3)).groups.length === 1,
          'until they are added, and that read is immediate too',
          '1');
  t.check(ldap.groupsOfUser(who).groups.length === 1,
          'and the first person is unaffected by it',
          '1');

  // A SECOND GROUP, created after the index has been stamped forward many
  // times. A group create is itself a write the index may not survive — it is
  // a group by placement, so groupRuleFor() answers truthy and the stamp
  // declines.
  const other = ldap.createGroup(team(2));
  t.check(other.ok, 'a second group was created after all of that', other.ok ?
          other.dn : JSON.stringify(other.errors));
  ldap.addGroupMember(team(2), who);
  const both = ldap.groupsOfUser(who);
  t.check(both.groups.length === 2,
          'and the person is now in BOTH — a group CREATE is also a write ' +
          'this index may not survive, which is a different case from the ' +
          'membership write above and fails separately',
          JSON.stringify(both.groups.map(function (g) { return g.cn; })
                                    .sort()));
  log.debug("Leaving checkTheGroupIndex().");
}

// ---------------------------------------------------------------------------
// The two indexes are independent, and a write that keeps one may not be
// assumed to keep the other. Asserted together because the bug that would
// produce it — one shared "is it current" flag — is the tidy-looking mistake.
// ---------------------------------------------------------------------------
function checkTheyDoNotShareAnAnswer(t) {
  log.debug("Entering checkTheyDoNotShareAnAnswer().");
  t.log.info('=== the two indexes answer separately ===');

  const who = person(4);
  ldap.createUser(who, { invent: false });
  ldap.createGroup(team(3));
  ldap.addGroupMember(team(3), who);

  // A GROUP write invalidates the group index and is irrelevant to the
  // username one. Both have to be right afterwards.
  t.check(ldap.groupsOfUser(who).groups.length === 1,
          'after a group write the group index is right',
          '1');
  const dup = ldap.createUser(who, { invent: false });
  t.check(dup.ok === false,
          'and the username index is still right too — a group write must ' +
          'not have been allowed to disturb it, nor to be taken as ' +
          'permission to keep it when it should have been rebuilt',
          JSON.stringify(dup.ok));
  log.debug("Leaving checkTheyDoNotShareAnAnswer().");
}

// ---------------------------------------------------------------------------
// THE TWO-WRITE SHAPE, which is what a SCIM create actually is and which is
// where this went wrong twice.
//
// `scim.js` calls `createUser()` and then `writePerson()` with the SCIM
// attributes merged over the entry — so every create through that door ends
// with putEntry() OVERWRITING the entry it just made. The first index
// implementation declined to follow an overwrite, which was safe and cost the
// entire benefit on that one door; the second follows it precisely, which
// means it now has to get the harder half right: a name the entry NO LONGER
// answers to must stop resolving to it.
// ---------------------------------------------------------------------------
function checkTheOverwriteShape(t) {
  log.debug("Entering checkTheOverwriteShape().");
  t.log.info('=== an entry rewritten in place, as a SCIM create rewrites it ' +
             '===');

  const who = person(5);
  const made = ldap.createUser(who, { invent: true });
  t.check(made.ok, 'a person was created', made.ok ? made.dn : 'no');

  const before = ldap.readPerson(made.dn);
  const rewritten = ldap.writePerson(made.dn,
    Object.assign({}, before.attributes, { title: ['Engineer'] }));
  t.check(rewritten.ok, 'and the entry was written again in place — the ' +
          'second half of what a SCIM create ' +
          'does', rewritten.ok ? 'yes' : 'no');

  const dup = ldap.createUser(who, { invent: false });
  t.check(dup.ok === false,
          'they are STILL found by name afterwards. An overwrite that ' +
          'dropped the entry out of the index would let the same person be ' +
          'created twice',
          dup.existing ? dup.existing.dn : JSON.stringify(dup.ok));

  // AND THE HARDER HALF: a name it stops answering to must stop resolving.
  // `uid` is what SCIM's userName maps to, so this is a real edit rather than
  // a contrived one.
  const renamedTo = person(6);
  const changed = ldap.writePerson(made.dn,
    Object.assign({}, before.attributes, { uid: [renamedTo] }));
  t.check(changed.ok, 'the uid on the entry was changed',
          changed.ok ? 'yes' : 'no');

  const byNew = ldap.createUser(renamedTo, { invent: false });
  t.check(byNew.ok === false,
          'the NEW name now resolves to it',
          byNew.existing ? byNew.existing.dn : JSON.stringify(byNew.ok));

  // The entry is still AT `uid=<who>,...` — the DN did not move, only the
  // attribute — so the old name is still its RDN value and still answers.
  // What must not happen is the index disagreeing with a fresh walk about it,
  // whichever way that walk goes.
  const walked = ldap.existingUserEntry(who);
  const viaCreate = ldap.createUser(who, { invent: false });
  t.check((walked ? false : true) === viaCreate.ok,
          'and the index and the create door agree about the old name — ' +
          'which is the assertion that catches a stale mapping in either ' +
          'direction',
          JSON.stringify({ found: !!walked, createRefused: !viaCreate.ok }));

  // -------------------------------------------------------------------------
  // A NAME THE ENTRY STOPS ANSWERING TO, which is the harder half of following
  // an overwrite and the half the section above CANNOT reach.
  //
  // Above, the DN is `uid=<name>,ou=users`, so the old uid is also the RDN
  // value and survives the edit either way — there is nothing to remove and a
  // mutant that removed nothing would pass. The shape that reaches it is an
  // entry whose RDN is NOT its uid, which is an ORDINARY entry here rather
  // than a contrived one: a client certificate's is `cn=<CN>,ou=users` and
  // carries no uid at all until something writes one.
  // -------------------------------------------------------------------------
  t.log.info('=== a name the entry stops answering to ===');
  const rdnDn = 'cn=' + RUN + ' Rdn,' + ldap.usersDn();
  const base = { objectClass: ['inetOrgPerson'], cn: [RUN + ' Rdn'],
                 sn: ['Rdn'] };
  const first = ldap.writePerson(rdnDn,
    Object.assign({}, base, { uid: [RUN + '-uidone'] }));
  t.check(first.ok, 'an entry whose RDN is not its uid was written', rdnDn);
  t.check(!!ldap.existingUserEntry(RUN + '-uidone'),
          'it answers to its uid', 'yes');
  t.check(!!ldap.existingUserEntry(RUN + ' Rdn'),
          'and to its RDN value, which is the pair the index holds', 'yes');

  const second = ldap.writePerson(rdnDn,
    Object.assign({}, base, { uid: [RUN + '-uidtwo'] }));
  t.check(second.ok, 'and then its uid was changed', 'yes');

  t.check(!ldap.existingUserEntry(RUN + '-uidone'),
          'THE OLD UID NO LONGER RESOLVES. An overwrite that folded the new ' +
          'names in without taking the departed ones out would leave this ' +
          'name pointing at somebody who does not answer to it — and the ' +
          'one-entry-per-person rule would then refuse a create for a name ' +
          'nobody holds',
          JSON.stringify(!!ldap.existingUserEntry(RUN + '-uidone')));
  t.check(!!ldap.existingUserEntry(RUN + '-uidtwo'),
          'the new uid does', 'yes');
  t.check(!!ldap.existingUserEntry(RUN + ' Rdn'),
          'and the RDN value still does — it never went away, so removing it ' +
          'would be the opposite mistake',
          'yes');

  // The name is genuinely free again, which is the consequence that matters at
  // the door rather than in the cache.
  const reclaim = ldap.createUser(RUN + '-uidone', { invent: false });
  t.check(reclaim.ok,
          'and the departed name can be given to somebody else, which is ' +
          'what "no longer resolves" has to MEAN at the create door',
          reclaim.ok ? reclaim.dn : JSON.stringify(reclaim.errors));
  log.debug("Leaving checkTheOverwriteShape().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheUsernameIndex(t);
  checkTheOverwriteShape(t);
  checkTheGroupIndex(t);
  checkTheyDoNotShareAnAnswer(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_indexes',
  describe: 'the username and group indexes: a write is visible to the very ' +
            'next read, however many kept-index writes surround it',
  run: run
};
