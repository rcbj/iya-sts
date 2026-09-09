'use strict';
//
// File: directory_group_writes.js
//
// ===========================================================================
// CREATING A GROUP BY HAND, AND PUTTING SOMEBODY IN ONE.
//
// `createGroup()` and `addGroupMember()` arrived on 2026-09-06 and are what
// `createUser()` is to a person. Until that day there was no by-hand door onto
// a group at all: `/admin/groups` and `/admin-api/groups` were both READS, so
// the only two ways to put a group in this directory were an `ldapadd` on the
// raw socket and `POST /scim/v2/Groups`.
//
// **WHY IN PROCESS, when the console and the API both drive these over HTTP.**
// What is asserted here is the REFUSALS and the idempotence — the decisions
// that live in `ldap_server.js` rather than in either door — and three of them
// cannot be made over HTTP without leaving the damage behind or arranging a
// second realm to hold it. `tests/CLAUDE.md` carries the rule and this is the
// exception it names: a module contract, no port, under a second.
//
// The two doors are covered where they live:
// `tests/vendored/sts_admin_console.js` presses both controls in a browser and
// reads the membership back as a resolved DN, and
// `tests/vendored/sts_directory_bulk_load_api.js` drives the two operations
// five thousand times. Neither of those can assert what a refusal SAYS.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const dir = require('../ldap/ldap_server');

// Create a realm, hand it to `fn`, and remove it however that goes. The realm
// table is process-wide and a realm left behind changes what a later test
// resolves — the same shape `realm_directory_lookups.js` uses, and the reason
// these writes are not made in the default realm at all.
function withRealm(t, id, fn) {
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    return undefined;
  }
  try {
    return realms.run(made.realm, function () { return fn(made.realm); });
  } finally {
    realms.remove(id);
  }
}

// ---------------------------------------------------------------------------
// 1. WHAT A GROUP MAY BE CALLED.
//
// The name becomes the `cn` AND the RDN, so the rules are the ones a DN
// imposes — and they are `createUser()`'s rules read from the one place they
// are written, `nameUsableInDn()`, rather than a second list that could drift.
// ---------------------------------------------------------------------------
function checkTheNameRules(t) {
  t.log.info('what a group may be called');

  withRealm(t, 'dgw-names', function () {
    // NOT `developers`, WHICH IS SEEDED IN EVERY REALM. The first version of
    // this file used it and failed, which is the seed doing its job: every
    // realm gets `cn=developers` and `cn=directory-admins` at creation, so a
    // test that picks either is asserting against a group it did not make.
    const made = dir.createGroup('dgw-developers', { origin: 'test' });
    t.equal(made.ok, true, 'an ordinary name is accepted');
    t.check(String(made.dn).indexOf('cn=dgw-developers,ou=groups') === 0,
            'and it goes to cn=<name>,ou=groups', made.dn);

    const again = dir.createGroup('dgw-developers', { origin: 'test' });
    t.equal(again.ok, false, 'creating it twice is refused');
    t.check(String((again.errors || []).join(' ')).indexOf(made.dn) >= 0,
            'and the refusal NAMES the entry that is already there — a caller ' +
            'that gets it looks for what it collided with');

    const seeded = dir.createGroup('developers', { origin: 'test' });
    t.equal(seeded.ok, false,
            'and a group the realm seeds is refused by the same rule, which ' +
            'is how this file found out it was seeded');

    // A DN, which is the refusal worth having: a caller pasting
    // `cn=developers,ou=groups,…` MEANS that group, and what they would get
    // without this is a second group whose name is the first one's DN.
    const dn = dir.createGroup('cn=developers,ou=groups,dc=example,dc=com',
                               { origin: 'test' });
    t.equal(dn.ok, false, 'a DN is refused rather than escaped into a name');

    const comma = dir.createGroup('two,parts', { origin: 'test' });
    t.equal(comma.ok, false,
            'and so is a name carrying a character RFC 4514 reserves in a DN');
    t.check(String((comma.errors || []).join(' ')).indexOf('4514') > 0,
            'the refusal says which rule it is, so it is not read as a bug');

    const empty = dir.createGroup('   ', { origin: 'test' });
    t.equal(empty.ok, false, 'and an empty name is refused');
  });
}

// ---------------------------------------------------------------------------
// 2. AN EMPTY GROUP, WHICH RFC 4519 SAYS SHOULD NOT EXIST.
//
// `member` is MUST on a `groupOfNames`. This directory is schemaless and SCIM
// already creates one, so this door does too — a console stricter than SCIM
// about the same store would be two doors disagreeing about what is in it.
// Asserted rather than assumed, because it is the sort of "obviously wrong"
// behaviour somebody would helpfully fix.
// ---------------------------------------------------------------------------
function checkTheEmptyGroup(t) {
  t.log.info('an empty group');

  withRealm(t, 'dgw-empty', function () {
    const made = dir.createGroup('nobody-in-here', { origin: 'test' });
    t.equal(made.ok, true, 'a group with no members is created');
    t.equal(made.members.length, 0, 'and it holds no membership values');

    const read = dir.readGroupEntry(made.dn);
    t.check(!!read, 'it reads back as a group', made.dn);
    t.equal((read.members || []).length, 0, 'with nobody in it');
    t.check((read.attributes.objectClass || read.attributes.objectclass || [])
              .join(',').toLowerCase().indexOf('groupofnames') >= 0,
            'and it is a groupOfNames, so it counts as a group by BOTH of ' +
            'groupRuleFor()\'s rules rather than by placement alone');
  });
}

// ---------------------------------------------------------------------------
// 3. WHERE A MEMBERSHIP VALUE POINTS.
//
// The person's OWN entry wherever it is. A grant that wrote the `uid=` form
// beside an entry created under some other RDN would dangle next to the person
// it was meant to name — which is the bug `admin_rbac.js`'s `memberValueFor()`
// exists to avoid, and this is the same rule at a second door.
// ---------------------------------------------------------------------------
function checkWhereTheValuePoints(t) {
  t.log.info('where a membership value points');

  withRealm(t, 'dgw-members', function () {
    const person = dir.createUser('dgw-alice', { origin: 'test' });
    t.equal(person.ok, true, 'a person to put in it');

    const group = dir.createGroup('dgw-team', { origin: 'test' });
    const added = dir.addGroupMember('dgw-team', 'dgw-alice',
                                     { origin: 'test' });
    t.equal(added.ok, true, 'adding them by NAME is accepted');
    t.equal(added.changed, true, 'and it changed something');
    t.equal(added.member, person.dn,
            'and the value written is their own entry DN rather than the ' +
            'name that was typed');
    t.equal(added.present, true, 'so it RESOLVES');
    t.equal(added.attribute, 'member',
            'written onto `member`, which is what this service\'s group ' +
            'claim, the console and RFC 4519 all read first');

    // THE GROUP BY DN AS WELL AS BY cn, because the two callers arrive with
    // different things in hand: the console's form is on a page whose rows are
    // DNs, and a script has the name it just created them under.
    const byDn = dir.addGroupMember(group.dn, 'dgw-bob', { origin: 'test' });
    t.equal(byDn.ok, true, 'the group may be named by its whole DN too');

    // A MEMBER THAT NAMES NOTHING IS WRITTEN, NOT REFUSED. Refusing would make
    // the dangling state /admin/groups exists to report impossible to produce
    // from this door, and this directory does no referential integrity in
    // either direction.
    t.equal(byDn.present, false,
            'somebody with no entry is a DANGLING member and is written anyway');

    const read = dir.readGroupEntry(group.dn);
    t.equal((read.members || []).length, 2, 'the group holds both values');
    t.equal(read.members.filter(function (m) { return m.present; }).length, 1,
            'and exactly one of them resolves — which is the state the ' +
            'console reports as memberCount 2, presentCount 1');
  });
}

// ---------------------------------------------------------------------------
// 4. IDEMPOTENCE, AND THE THINGS IT MUST NOT DO.
//
// `admin_rbac.js`'s `grant()` rule: adding somebody already in the group is
// the state the caller wanted, so it answers ok with `changed: false`. A 400
// would make a script that adds on every run fail on its second one — and the
// bulk-load jobs are exactly such a script.
// ---------------------------------------------------------------------------
function checkIdempotenceAndRefusals(t) {
  t.log.info('idempotence, and what it refuses');

  withRealm(t, 'dgw-again', function () {
    dir.createUser('dgw-carol', { origin: 'test' });
    const group = dir.createGroup('dgw-twice', { origin: 'test' });

    const first = dir.addGroupMember('dgw-twice', 'dgw-carol', { origin: 'test' });
    const second = dir.addGroupMember('dgw-twice', 'dgw-carol', { origin: 'test' });
    t.equal(first.changed, true, 'the first add changes something');
    t.equal(second.ok, true, 'the second is NOT an error');
    t.equal(second.changed, false, 'and reports that it changed nothing');
    t.equal((dir.readGroupEntry(group.dn).members || []).length, 1,
            'and the group still holds ONE value — two would be one ' +
            'membership written twice');

    // IT DOES NOT CREATE THE GROUP AS A SIDE EFFECT. A typo in a name would
    // then be a new group rather than an error, which is the worst shape this
    // operation could take: the caller sees success and the person is in
    // nothing anybody will look at.
    const missing = dir.addGroupMember('dgw-no-such-group', 'dgw-carol',
                                       { origin: 'test' });
    t.equal(missing.ok, false, 'adding to a group that does not exist is refused');
    t.check(dir.readGroupEntry(dir.groupDnFor('dgw-no-such-group')) === null,
            'and it did NOT create it on the way past');

    // AN ENTRY THAT IS NOT A GROUP. `groupRuleFor()` decides, and an entry
    // under ou=users is not one however it is named.
    const person = dir.createUser('dgw-dave', { origin: 'test' });
    const notAGroup = dir.addGroupMember(person.dn, 'dgw-carol',
                                         { origin: 'test' });
    t.equal(notAGroup.ok, false,
            'and so is adding a member to something that is not a group');

    t.equal(dir.addGroupMember('dgw-twice', '', { origin: 'test' }).ok, false,
            'naming no member is refused');
    t.equal(dir.addGroupMember('', 'dgw-carol', { origin: 'test' }).ok, false,
            'and so is naming no group');
  });
}

// ---------------------------------------------------------------------------
// 5. NOTHING IS EVER WRITTEN ONTO THE PERSON, AND THE ENTRY KEEPS ITS SHAPE.
//
// `memberOf` is maintained by nothing here — it is not even a standard
// attribute — so a value written there is one no other door in this service can
// take away, which is why `admin_rbac.js` REFUSES a revoke of a membership held
// that way. And `entryDN` is SYNTHESISED by `entryObject()` rather than stored,
// so writing a read object straight back would turn it into a real attribute:
// the one thing every door onto this directory is told never to do.
// ---------------------------------------------------------------------------
function checkWhatIsNotWritten(t) {
  t.log.info('what is not written');

  withRealm(t, 'dgw-untouched', function () {
    const person = dir.createUser('dgw-erin', { origin: 'test' });
    const group = dir.createGroup('dgw-clean', { origin: 'test' });
    dir.addGroupMember('dgw-clean', 'dgw-erin', { origin: 'test' });

    const entry = dir.objectFor('dgw-erin');
    const held = {};
    Object.keys((entry && entry.attributes) || {}).forEach(function (name) {
      held[name.toLowerCase()] = true;
    });
    t.check(!held.memberof,
            'the PERSON gained no memberOf — nothing here maintains it, and a ' +
            'value written there is one no other door can take away',
            person.dn);

    // Read the stored group back and look for the synthesised attribute having
    // become a real one. It is asserted after an ADD rather than after a
    // create, because the add is the operation that reads the whole entry and
    // writes it back — which is exactly where this goes wrong.
    const stored = dir.readGroupEntry(group.dn);
    const names = Object.keys(stored.attributes).map(function (n) {
      return n.toLowerCase();
    });
    t.check(names.indexOf('entrydn') < 0 ||
            (stored.attributes.entryDN || []).length === 1,
            'and the group did not gain a stored entryDN from being read and ' +
            'written back');
  });
}

function run(t) {
  checkTheNameRules(t);
  checkTheEmptyGroup(t);
  checkWhereTheValuePoints(t);
  checkIdempotenceAndRefusals(t);
  checkWhatIsNotWritten(t);
}

module.exports = {
  name: 'directory_group_writes',
  describe: 'createGroup() and addGroupMember(): the names they refuse, the ' +
            'dangling member they allow, and the person they never touch',
  run: run
};
