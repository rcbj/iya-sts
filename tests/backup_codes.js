'use strict';
//
// File: backup_codes.js
//
// ===========================================================================
// RECOVERY CODES: THE ONE MECHANISM HERE WITH NO SPECIFICATION TO CHECK
// AGAINST, WHICH IS WHY THIS FILE IS LONGER THAN IT LOOKS LIKE IT SHOULD BE.
//
// `tests/totp.js` beside it opens by saying that RFC 4226 and RFC 6238 publish
// test vectors, so there is an EXTERNAL answer to check the arithmetic
// against — and that this is the reason it was worth implementing TOTP rather
// than taking a library.
//
// **THIS FILE HAS THE OPPOSITE PROBLEM.** Nobody ever wrote a specification
// for a recovery code. There are no vectors, no external answer, and every
// property below is one this service chose. A test that only re-stated those
// choices would be a second copy of `common/backup_codes.ts` written in
// assertions — it would pass for ever and would catch nothing.
//
// So what is asserted here is deliberately not "does it do what the code
// says". It is the four claims the FEATURE makes, each of which is a claim a
// person is relying on and each of which is breakable by an innocent edit:
//
//   1. **A SET IS GENERATED WHEN THE PERSON ASKS, AND STORED ONLY WHEN THEY
//      CONFIRM** — enrolling a second factor ADVISES a set and issues none.
//      (Until 2026-09-11 enrolling issued one; the section says why that
//      reversed.)
//   2. **WHAT IS STORED IS A HASH**, so nothing can show a code again — and a
//      second set REPLACES the first, which is the sharp edge the page warns
//      about. (Until 2026-09-11 a set was issued ONCE and sealed.)
//   3. **A CODE IS SPENT** — each works exactly once, and a replay is refused
//      BY NAME rather than as a wrong code.
//   4. **A SET IS NEVER A WAY IN AND NEVER THE FACTOR DEMANDED.** Holding
//      codes must not make `mfaRequired` true and must never become
//      `secondFactor`, or a sign-in would ask for something the person cannot
//      be asked for.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION `tests/CLAUDE.md` ASKS FIRST.
//
// Claims 2 and 3 need to reach INSIDE the credential store. "A hash is
// stored" means reading the bytes on the entry, and the codes themselves are
// never on the wire after the one page that shows a new set at
// `/portal/mfa`; the third claim's interesting case is a directory write
// that FAILS, which no HTTP request can ask for.
//
// The over-HTTP half is `tests/vendored/sts_portal_backup_codes.js`, which
// drives the portal and the sign-in door with a code it reads off the page.
// The two are not substitutes: this one says the rules hold, and that one says
// the doors are wired up.
//
// ---------------------------------------------------------------------------
// **ONE CLAIM IS NOT TESTED HERE AND THIS IS THE RECORD OF IT**, because this
// repository's convention is that a gap is written down where the thing lives
// rather than discovered later by somebody assuming it was covered.
//
// `verifyBackupCode()` REFUSES a code that verified when the spend will not
// write — the opposite of what `verifyTotp()` does with its counter, and
// argued at length in `common/credentials.ts`: a one-time code that cannot be
// counted is replayable for ninety seconds, and a recovery code that cannot be
// marked spent works for ever. **Nothing here reaches that branch**, and the
// reason is worth stating so that the next person does not waste the hour:
//
//   * It needs the credential store's WRITE to fail while its READ succeeds.
//     `ldap/ldap_server.js` fails both together — there is one `locateEntry()`
//     behind them — so no arrangement of realms, missing entries or settings
//     produces the state.
//   * `credentials.setDirectory()` would install a half-broken table, and
//     there is no way to put the real one back: those functions are
//     deliberately not exported by `ldap/ldap_server.js`, and
//     `credentials.js` deliberately offers no getter. Leaving a broken store
//     behind would break every later file in this process, which run in one.
//   * The route that used to remain — sealing with no key-encryption key —
//     disappeared on 2026-09-11: a set of hashes is stored unsealed, so
//     `writeBackupCodesRecord()` has no sealing step left to fail.
//
// Exporting a hook table from `ldap/ldap_server.js` purely so that this branch
// could be reached was considered and refused: production API whose only
// caller is a test is worse than a written-down gap. What IS asserted below is
// the property the branch exists to protect — **no refusal, of any reason,
// ever spends a code** — which is the half a future edit is likely to break.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const backupCodes = require('../common/backup_codes');
const credentials = require('../common/credentials');
const totp = require('../common/totp');
// REQUIRED FOR ITS SIDE EFFECT, which is the whole reason this line is not a
// tidy-up candidate: requiring `ldap/ldap_server.js` is what fills
// `credentials.setDirectory()`, and without it every function under test
// answers "no credential store is installed" and every assertion below passes
// vacuously.
const ldap = require('../ldap/ldap_server');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'backup_codes',
  level: process.env.LOG_LEVEL || 'info' });

// A name per section, because the directory is a process-wide store here and a
// shared one would make each section depend on the order of the ones above it.
let counter = 0;
function somebody() {
  log.debug("Entering somebody().");
  counter++;
  const name = 'backupprobe' + counter;
  ldap.createUser(name, {});
  log.debug("Leaving somebody().");
  return name;
}

// Enrol an authenticator app the way `/portal/mfa` does — two steps, with the
// code computed here. It is written out rather than stubbed because the WHOLE
// POINT of claims 1 and 2 is which real call issues a set.
function enrolAuthenticator(name) {
  log.debug("Entering enrolAuthenticator().");
  const begun = credentials.beginTotpEnrolment(name,
                                               { base: 'https://localhost' });
  const code = totp.codeAt(begun.secret, Date.now(), begun);
  log.debug("Leaving enrolAuthenticator().");
  return credentials.confirmTotpEnrolment(name, code);
}

// ENROL AND THEN ASK FOR A SET, WHICH IS TWO ACTS SINCE 2026-09-11 AND USED TO
// BE ONE. Every section below that needs somebody holding usable codes goes
// through this, because the enrolment no longer hands any back — and the
// codes it returns are the ONLY copy that will ever exist, which is the whole
// of what the change means for a caller.
function enrolAndTakeCodes(name) {
  log.debug("Entering enrolAndTakeCodes().");
  enrolAuthenticator(name);
  const begun = credentials.beginBackupCodes(name);
  if (!begun.ok) {
    log.debug("Leaving enrolAndTakeCodes().");
    return null;
  }
  const done = credentials.confirmBackupCodes(name, begun.handle);
  log.debug("Leaving enrolAndTakeCodes().");
  return done.ok ? begun.codes : null;
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== a code: the shape, and the properties that are chosen ===');
  const set = backupCodes.generate({ count: 10, length: 10 });
  t.equal(set.length, 10, 'a set is the number of codes asked for');
  t.check(set.every(function (c) { return c.length === 10; }),
          'and every code is the length asked for');
  t.check(set.every(function (c) {
            return c.split('').every(function (ch) {
              return backupCodes.ALPHABET.indexOf(ch) >= 0;
            });
          }),
          'every character is in the declared alphabet');
  // THE PROPERTY THE ALPHABET WAS CHOSEN FOR, asserted rather than trusted —
  // this is the one thing about this mechanism somebody might "tidy" by
  // reaching for a hex or base64 encoder, and the failure it would cause
  // reaches a person transcribing a code off paper months later rather than
  // any test.
  '01l8B'.split('').forEach(function (ch) {
    if (ch === 'B') {
      t.check(backupCodes.ALPHABET.indexOf(ch) >= 0,
              'B is in the alphabet — it is 8 that is excluded, not its ' +
              'lookalike');
      return;
    }
    t.check(backupCodes.ALPHABET.indexOf(ch) < 0,
            'the confusable "' + ch + '" is not in the alphabet');
  });
  t.check(new Set(set).size === set.length,
          'the codes in one set are distinct — a duplicate would be a code ' +
          'that still reads as unused after being spent, which is the one ' +
          'property a single-use credential may not have');

  t.log.info('=== what a person may type, and what they may not ===');
  const one = set[0];
  const printed = backupCodes.formatted(one, 5);
  t.equal(printed.length, 11, 'the printed form has the dash in it');
  t.check(backupCodes.matches(printed, one),
          'this service accepts back the rendering it printed', printed);
  t.check(backupCodes.matches(printed.toLowerCase(), one),
          'and the lower case somebody types it in');
  t.check(backupCodes.matches(' ' + printed.replace('-', ' ') + ' ', one),
          'and spaces wherever they put them');
  // A DIFFERENT last character, chosen rather than typed: `'X'` looks like a
  // fine wrong answer and is a real character of this alphabet, so one code in
  // thirty-two ends with it and the assertion would pass on a broken
  // comparison roughly ninety-seven per cent of the time.
  const otherChar = backupCodes.ALPHABET[
    (backupCodes.ALPHABET.indexOf(one[one.length - 1]) + 1) % 32];
  t.check(!backupCodes.matches(one.slice(0, -1) + otherChar, one),
          'a wrong character is a wrong code',
          one + ' vs ' + one.slice(0, -1) + otherChar);
  t.check(!backupCodes.wellFormed('hunter2!'),
          'a password typed into the box is refused on its SHAPE, so it is ' +
          'never compared against the set');
  t.check(backupCodes.wellFormed(printed),
          'and the printed form is well formed');

  t.log.info('=== CLAIM 1: a set is generated WHEN THE PERSON ASKS, and ' +
             'nothing is stored until they confirm ===');

  // **THIS SECTION REVERSED ON 2026-09-11 AND THE OLD CLAIM IS WORTH KEEPING
  // IN VIEW.** It read *a set is issued by the ACT of enrolling*, and asserted
  // that `enrolAuthenticator()` came back carrying ten codes nobody had asked
  // for. That protected a real population — the people who never think to ask
  // — and it cannot survive hashing: a hash can only be made while the code is
  // in the clear, so an automatic issue would store a credential the person
  // never saw.
  const alice = somebody();
  t.check(!credentials.backupCodeStatus(alice).present,
          'a person who has enrolled nothing holds no recovery codes');
  const enrolled = enrolAuthenticator(alice);
  t.check(enrolled.ok, 'the authenticator app enrolled',
          (enrolled.errors || []).join(' '));
  t.check(!credentials.backupCodeStatus(alice).present,
          'AND THE ENROLMENT ISSUED NOTHING. A set is no longer a side ' +
          'effect of enrolling a second factor');
  t.check(enrolled.recoveryAdvised,
          'but it SAYS SO — `recoveryAdvised` is what replaced the automatic ' +
          'issue, and it is the whole of what is left of that protection');
  t.check(credentials.mechanismsFor(alice).recoveryAdvised,
          'and the flag is on `mechanismsFor()` too, so any surface can draw ' +
          'the prompt rather than only the page that saw the enrolment');

  const begun = credentials.beginBackupCodes(alice);
  t.check(begun.ok, 'asking generates a set', (begun.errors || []).join(' '));
  t.equal(begun.codes.length, backupCodes.settings().count,
          'the codes come back in the clear — this is the ONLY moment they ' +
          'exist, and the caller\'s one chance to put them in front of the ' +
          'person');
  t.check(!begun.replacing, 'and it reports that it is replacing nothing');

  // **THE ASSERTION THIS WHOLE DESIGN RESTS ON.** Between the two presses the
  // set is in this process's memory and nowhere else, so a person who closes
  // the tab has lost nothing and changed nothing.
  t.check(!credentials.backupCodeStatus(alice).present,
          'AND STILL NOTHING IS STORED. The codes have been shown and the ' +
          'entry is untouched');
  t.equal(credentials.verifyBackupCode(alice, begun.codes[0]).reason, 'none',
          'and a code that has been SHOWN but not confirmed works NOWHERE — ' +
          'which is what the page has to say in as many words, because ' +
          'somebody who writes them down and never presses the button is ' +
          'holding a page of strings that do nothing');

  const confirmed = credentials.confirmBackupCodes(alice, begun.handle);
  t.check(confirmed.ok, 'confirming stores them',
          (confirmed.errors || []).join(' '));
  const status = credentials.backupCodeStatus(alice);
  t.check(status.present && status.usable, 'and NOW the set is on their entry');
  t.equal(status.remaining, status.total, 'with every code unused');
  t.check(!credentials.mechanismsFor(alice).recoveryAdvised,
          'and the prompt stops, because it is only true while it is true');

  t.log.info('=== CLAIM 2: what is stored is a HASH, and nothing can show ' +
             'a code again ===');

  // **THE SECOND REVERSAL.** This section used to assert that the codes were
  // ENCRYPTED and could be read back — which was the whole reason they were
  // not hashed, and the reason `/portal/mfa` had a *Show my recovery codes*
  // button.
  // **READ THROUGH THE STATUS AND NOT THROUGH A RAW ACCESSOR**, which is the
  // point of `hashed` being on it: every page that reports on a set needs to
  // know how it is stored, and none of them should be opening the entries to
  // find out. An earlier version of this section reached for an unexported
  // reader and SILENTLY SKIPPED — the `if` was simply false — which is the
  // shape of test that passes while asserting nothing.
  const stored = credentials.backupCodeStatus(alice);
  t.check(stored.hashed,
          'the stored set reports itself as HASHED — scrypt, the same form ' +
          '`userPassword` is stored in, which is rule 3r: one place this ' +
          'service hashes a secret it will later check');
  t.check(!stored.legacy, 'and not as a legacy set');
  t.check(!stored.sealed,
          'and NOT sealed. The vault used to be encrypted under the ' +
          'key-encryption key so a page could show the codes back; hashes ' +
          'are not secret, and `userPassword` sits in the clear beside them');
  // The assertion the whole change was made for, made against the bytes on
  // the entry rather than against a flag this service sets about itself.
  const entryView = ldap.objectFor(alice);
  const raw = String(((entryView && entryView.entry &&
    (entryView.entry.attributes ||
     entryView.entry)) || {}).stsBackupCodes || '');
  t.check(raw.length > 0, 'the set really is on the directory entry');
  t.check(!begun.codes.some(function (code) { return raw.indexOf(code) >= 0; }),
          'AND NOT ONE OF THE CODES APPEARS IN IT. This is the assertion the ' +
          'change was made for, and it is made against the stored value ' +
          'rather than against anything this service says about itself');
  t.check(/\$scrypt\$/.test(raw),
          'what is there instead is scrypt hashes');
  const shown = credentials.revealBackupCodes(alice);
  t.check(!shown.ok && shown.impossible,
          'and reading a set back is IMPOSSIBLE rather than merely refused — ' +
          'the function is kept as an explaining refusal so that a caller ' +
          'left over from an older build gets a sentence rather than `is not ' +
          'a function`');
  t.check(/hash/i.test((shown.errors || []).join(' ')),
          'and it says why, in terms of what is stored');

  t.log.info('=== generating again REPLACES, which is the sharp edge ===');

  // The old rule was ONCE and its reason was that a printed list must not stop
  // working with nothing having said so. That protection is now a SENTENCE on
  // the page rather than a refusal in the store — and this pins that the
  // behaviour it warns about is real, because a warning about something that
  // does not happen is worse than none.
  const replacement = credentials.beginBackupCodes(alice);
  t.check(replacement.ok && replacement.replacing,
          'a replacement set can be generated, and it REPORTS that it will ' +
          'replace — which is what the page says before it shows anything');
  t.check(credentials.verifyBackupCode(alice, begun.codes[1]).ok,
          'and the FIRST set still works while the replacement is unconfirmed');
  t.check(credentials.confirmBackupCodes(alice, replacement.handle).ok,
          'confirming the replacement set succeeds');
  t.equal(credentials.verifyBackupCode(alice, begun.codes[2]).reason,
          'mismatch',
          'AND NOW THE FIRST SET IS DEAD. Every code on the old list stops ' +
          'working the moment the new one is confirmed');
  t.check(credentials.verifyBackupCode(alice, replacement.codes[0]).ok,
          'and the replacement set works');

  t.log.info('=== a pending set can be thrown away, and expires ===');

  const throwaway = credentials.beginBackupCodes(alice);
  t.check(credentials.discardBackupCodes(alice, throwaway.handle).discarded,
          'a pending set can be discarded without being stored');
  t.check(!credentials.confirmBackupCodes(alice, throwaway.handle).ok,
          'after which it cannot be confirmed');
  t.check(credentials.verifyBackupCode(alice, replacement.codes[1]).ok,
          'and discarding changed nothing about the set they already had');

  const stranger = somebody();
  const mine = credentials.beginBackupCodes(alice);
  t.check(!credentials.confirmBackupCodes(stranger, mine.handle).ok,
          'and one person cannot confirm another\'s pending set — the handle ' +
          'is checked against the name, so two tabs cannot confirm each ' +
          'other\'s codes');
  credentials.discardBackupCodes(alice, mine.handle);

  t.log.info('=== an operator\'s Clear is a plain removal now ===');
  const cleared = credentials.removeBackupCodes(alice);
  t.check(cleared.ok, 'the set is cleared');
  t.check(!credentials.backupCodeStatus(alice).present, 'and is gone');
  t.check(credentials.mechanismsFor(alice).recoveryAdvised,
          'and the person is advised to generate one again — where the Clear ' +
          'used to RE-ARM an automatic issue, it now simply makes the prompt ' +
          'true again');

  t.log.info('=== CLAIM 3: a code is spent, once, and says so ===');
  const bob = somebody();
  const bobsCodes = enrolAndTakeCodes(bob);
  const spend = credentials.verifyBackupCode(bob,
    backupCodes.formatted(bobsCodes[2], 5).toLowerCase());
  t.check(spend.ok, 'a code verifies, in the rendering this service printed');
  t.equal(spend.remaining, bobsCodes.length - 1, 'and one fewer remains');
  const replay = credentials.verifyBackupCode(bob, bobsCodes[2]);
  t.check(!replay.ok, 'the same code does not work twice');
  t.equal(replay.reason, 'spent',
          'AND THE REFUSAL IS "spent" RATHER THAN "mismatch" — somebody ' +
          'working down a printed list and re-typing the one they crossed ' +
          'out needs to be told to use the next one, not that their list is ' +
          'dead');
  const wrong = credentials.verifyBackupCode(bob, 'AAAAAAAAAA');
  t.equal(wrong.reason, 'mismatch',
          'a code that was never issued is a mismatch');
  const junk = credentials.verifyBackupCode(bob, 'hunter2!');
  t.equal(junk.reason, 'shape',
          'and something that is not the shape of a code is refused before ' +
          'the set is walked at all');
  t.equal(credentials.backupCodeStatus(bob).remaining, bobsCodes.length - 1,
          'none of the three refusals spent anything');

  t.log.info('=== NO REFUSAL, OF ANY REASON, EVER SPENDS A CODE ===');
  // The property the un-reachable branch in the header exists to protect,
  // asserted from the outside. A single-use credential has exactly two ways to
  // go wrong: one that works twice, and one that is consumed by an attempt
  // that failed. The replay check above covers the first; this covers the
  // second, across every refusal this function can produce.
  const before = credentials.backupCodeStatus(bob).remaining;
  ['AAAAAAAAAA', 'hunter2!', bobsCodes[2], '', '2222222222']
    .forEach(function (attempt) {
      credentials.verifyBackupCode(bob, attempt);
    });
  t.equal(credentials.backupCodeStatus(bob).remaining, before,
          'five refusals — a mismatch, a bad shape, a replay, an empty ' +
          'string and another mismatch — spent nothing between them');
  const stillWorks = credentials.verifyBackupCode(bob, bobsCodes[4]);
  t.check(stillWorks.ok,
          'and a code that was never accepted is still good afterwards');

  t.log.info('=== CLAIM 4: a set is never a way in, and never the factor ===');
  const carol = somebody();
  // A PASSWORD FIRST, because the last assertion in this section is about
  // `usable` — *can this person sign in at all* — and somebody with no
  // credential of any kind cannot, for reasons that have nothing to do with
  // recovery codes. Without this the assertion would fail for the wrong reason
  // and read as the feature having broken something.
  credentials.setPassword(carol, 'probe-password');
  const carolCodes = enrolAndTakeCodes(carol);
  t.check(carolCodes && carolCodes.length, 'carol holds a set');
  const mech = credentials.mechanismsFor(carol);
  t.equal(mech.secondFactor, 'totp',
          'the factor she is asked for is the one she ENROLLED, never the ' +
          'recovery codes');
  t.check(mech.backupCodes.present && mech.backupCodes.remaining > 0,
          'and the codes are reported beside it as a status');
  t.check(mech.backupCodes.total !== undefined &&
          mech.backupCodes.codes === undefined,
          'THE STATUS CARRIES NO CODES — one function answers how many are ' +
          'left and a different one answers what they are, so a page that ' +
          'wanted the first cannot render the second by accident');

  // THE ASSERTION THAT PROTECTS THE SIGN-IN SCREEN. If holding codes ever made
  // `mfaRequired` true on its own, a person whose set was issued and whose
  // second factor was then cleared would be asked at sign-in for a factor they
  // do not hold — a lockout produced by the recovery mechanism itself.
  credentials.removeTotp(carol);
  const after = credentials.mechanismsFor(carol);
  t.check(after.backupCodes.present,
          'with the authenticator cleared she still holds the set');
  t.check(!after.mfaRequired,
          'AND NO SECOND FACTOR IS DEMANDED. Recovery codes must never make ' +
          'this true on their own, or an account whose only second factor ' +
          'was cleared would be asked for one it cannot produce');
  t.equal(after.secondFactor, '', 'and there is no factor to ask for');
  t.check(after.usable,
          'and she can still sign in — a recovery code has never been a way ' +
          'in on its own and this does not change that');

  t.log.info('=== a security key ADVISES a set only in the `mfa` role ===');
  // **THIS SECTION USED TO ASSERT AN ISSUE AND NOW ASSERTS AN ADVICE**, which
  // is the same distinction one tier down: the condition that mattered was
  // never "does a key issue codes" but "is this key a SECOND FACTOR". A
  // `primary` key is a way IN, so there is no second-factor step for a
  // recovery code to stand in for and a set would be strings no screen ever
  // asks for.
  const dave = somebody();
  const primary = credentials.addKey(dave, {
    credentialId: 'probe-primary-1', publicKeyJwk: { kty: 'OKP' },
    signCount: 0, label: 'probe'
  }, 'primary');
  t.check(primary.ok, 'a primary key enrols', (primary.errors || []).join(' '));
  t.check(!primary.recoveryAdvised,
          'AND ADVISES NO RECOVERY CODES — it is a credential rather than a ' +
          'second factor, and its lost-key story is an operator and an ' +
          'activation link');
  t.check(!credentials.mechanismsFor(dave).recoveryAdvised,
          'and `mechanismsFor()` agrees, so the portal draws no prompt for ' +
          'somebody who has only a passwordless key');
  const mfaKey = credentials.addKey(dave, {
    credentialId: 'probe-mfa-1', publicKeyJwk: { kty: 'OKP' },
    signCount: 0, label: 'probe'
  }, 'mfa');
  t.check(mfaKey.ok, 'an mfa key enrols', (mfaKey.errors || []).join(' '));
  t.check(mfaKey.recoveryAdvised,
          'and THAT one advises a set, because it is a second factor');
  t.check(String(mfaKey.recoveryNote).length > 40,
          'and carries the sentence the portal shows, rather than leaving ' +
          'each surface to invent its own wording for the same fact');
  t.check(credentials.beginBackupCodes(dave).ok,
          'and the person can then generate one, which is the only way a set ' +
          'now comes to exist');

  t.log.info('=== a set this process cannot read is UNUSABLE, never absent ' +
             '===');
  // The unreadable state itself is a LEGACY SEALED set under a rotated
  // key-encryption key, which this process cannot arrange — a hashed set
  // (every set since 2026-09-11) is not sealed and has nothing to fail to
  // open. What IS checked here is the reachable neighbour: a set with every
  // code spent is still PRESENT, reported by its counts, and replaced only
  // when the person generates a new one.
  const erin = somebody();
  const erinCodes = enrolAndTakeCodes(erin);
  erinCodes.forEach(function (code) {
    credentials.verifyBackupCode(erin, code);
  });
  const exhausted = credentials.backupCodeStatus(erin);
  t.check(exhausted.present, 'a set with every code spent is still PRESENT');
  t.equal(exhausted.remaining, 0, 'with nothing left');
  t.equal(exhausted.used, exhausted.total, 'and everything used');
  // **THE OLD CLAIM HERE WAS "NOTHING REISSUES OVER IT" AND IT IS GONE WITH
  // THE ONCE RULE.** It asserted that `ensureBackupCodes()` refused to issue
  // over a set with every code spent — the sharpest case of that rule, because
  // reissuing would make a printed list go dead at a moment nothing
  // announced. A person generates their own set now, so what replaces it is
  // that the SPENT SET IS STILL THERE until they do, and that the page has
  // something true to tell them.
  t.check(credentials.mechanismsFor(erin).backupCodes.present,
          'a set with every code spent is still PRESENT rather than ' +
          'disappearing, so the page can say "you have used all ten" instead ' +
          'of "you have none"');
  t.check(!credentials.mechanismsFor(erin).recoveryAdvised,
          'and the person is NOT advised to generate one, because they have ' +
          'a set — the prompt is about holding none at all, and an exhausted ' +
          'set is reported by its own counts');
  const replacementForErin = credentials.beginBackupCodes(erin);
  t.check(replacementForErin.ok && replacementForErin.replacing,
          'they can generate a new one, and it reports that it replaces — ' +
          'which is what the page says before it shows anything');
  t.check(credentials.confirmBackupCodes(erin, replacementForErin.handle).ok,
          'and confirming it succeeds');
  t.equal(credentials.backupCodeStatus(erin).remaining,
          backupCodes.settings().count,
          'after which they hold a full set again');

  t.log.info('=== a set written by an OLDER build still works ===');

  // **THE ONE COMPATIBILITY CLAIM THIS CHANGE OWES.** A set stored before
  // 2026-09-11 holds the CODES, not hashes — and somebody is holding it on
  // paper. Refusing it would be this mechanism breaking in exactly the way it
  // exists to prevent: a printed list going dead with nothing having said so.
  //
  // The legacy record is built here rather than mocked, because what is under
  // test is that `backupCodesOf()` NORMALISES it and that the comparison
  // branches PER ENTRY.
  const frank = somebody();
  enrolAuthenticator(frank);
  const legacyCodes = backupCodes.generate({ count: 3, length: 10 });
  const legacyRecord = JSON.stringify({
    version: 1, total: 3, remaining: 3,
    generatedAt: Date.now(), lastUsedAt: 0, sealed: false,
    vault: JSON.stringify(legacyCodes.map(function (code) {
      return { code: code, usedAt: 0 };
    }))
  });
  // **WRITTEN THROUGH `writePerson()` AND NOT THROUGH THE CREDENTIAL STORE**,
  // which is the only way to produce this state: every writer in
  // `credentials.js` now stores hashes, so a version 1 record cannot be made
  // by asking that module for one. It has to be put on the entry directly,
  // which is exactly how the record got there in the first place — an older
  // build of this service wrote it.
  const view = ldap.objectFor(frank);
  const entry = (view && view.entry) || null;
  const attrs = entry ? Object.assign({}, entry.attributes || entry) : null;
  let wrote = false;
  if (attrs) {
    attrs.stsBackupCodes = legacyRecord;
    wrote = !!(ldap.writePerson(view.dn, attrs) || {}).ok;
  }
  if (wrote) {
    const readBack = credentials.backupCodeStatus(frank);
    t.check(readBack.present && readBack.usable,
            'a version 1 record is READ and is usable rather than being ' +
            'reported as unreadable');
    t.check(readBack.legacy && !readBack.hashed,
            'and it says so: the stored values are codes rather than hashes');
    t.equal(readBack.total, 3,
            'and it is normalised to the same shape a hashed set has, so no ' +
            'reader below has to know which kind it got');
    const legacyVerdict = credentials.verifyBackupCode(frank, legacyCodes[1]);
    t.check(legacyVerdict.ok,
            'AND A CODE FROM IT STILL VERIFIES. Somebody is holding this on ' +
            'paper and it must not stop working because this service changed ' +
            'how it stores new ones');
    t.equal(legacyVerdict.remaining, 2, 'and spending one works normally');
    t.check(!credentials.verifyBackupCode(frank, legacyCodes[1]).ok,
            'including the replay refusal');
    t.check(credentials.mechanismsFor(frank).backupCodes.present,
            'and the console counts it like any other set');
    // #70: the spend REWROTE the set, and until then it came back labelled
    // `hashed` while holding codes.
    t.check(credentials.backupCodeStatus(frank).legacy,
            'and after the spend rewrote it, it is still reported as a ' +
            'LEGACY set of codes rather than relabelled as hashes');
  } else {
    t.log.warn('this directory would not take a hand-written record, so the ' +
               'legacy-set path is not covered by this run.');
  }

  t.log.info('=== a LEGACY set stays SEALED where the key persists ===');

  // **#70.** A set an older build sealed in product mode holds CODES. Every
  // spend rewrites it, and the writer used to write every set in the clear —
  // so the first spend published the remaining working codes on the entry.
  // Product mode cannot be turned on in this process, so the two keystore
  // answers that decide it are stood in for, and put back in `finally`:
  // `persists()` says the key outlives the process, and `seal()`/`open()`
  // are a marked round trip, so the bytes on the entry show which happened.
  const keystore = require('../common/keystore');
  const grace = somebody();
  enrolAuthenticator(grace);
  const sealedCodes = backupCodes.generate({ count: 3, length: 10 });
  const MARK = 'test-sealed:';
  const realPersists = keystore.persists;
  const realSeal = keystore.seal;
  const realOpen = keystore.open;
  try {
    keystore.persists = function () {
      return true;
    };
    keystore.seal = function (text) {
      return MARK + Buffer.from(String(text)).toString('base64');
    };
    keystore.open = function (text) {
      const value = String(text || '');
      return value.indexOf(MARK) === 0
        ? Buffer.from(value.slice(MARK.length), 'base64').toString()
        : null;
    };
    const sealedRecord = JSON.stringify({
      version: 1, total: 3, remaining: 3,
      generatedAt: Date.now(), lastUsedAt: 0, sealed: true,
      vault: keystore.seal(JSON.stringify(sealedCodes.map(function (code) {
        return { code: code, usedAt: 0 };
      })))
    });
    const graceView = ldap.objectFor(grace);
    const graceEntry = (graceView && graceView.entry) || null;
    const graceAttrs = graceEntry ?
      Object.assign({}, graceEntry.attributes || graceEntry) : null;
    let graceWrote = false;
    if (graceAttrs) {
      graceAttrs.stsBackupCodes = sealedRecord;
      graceWrote = !!(ldap.writePerson(graceView.dn, graceAttrs) || {}).ok;
    }
    t.check(graceWrote, 'a sealed version 1 record can be put on an entry');
    if (graceWrote) {
      const spent = credentials.verifyBackupCode(grace, sealedCodes[0]);
      t.check(spent.ok, 'a code from a SEALED legacy set verifies');
      const after = ldap.objectFor(grace);
      const afterRaw = String(((after && after.entry &&
        (after.entry.attributes || after.entry)) || {}).stsBackupCodes || '');
      let afterRecord = {};
      try {
        afterRecord = JSON.parse(afterRaw);
      } catch (e) {
        log.debug('Caught in run(): ' + ((e && e.message) || e));
      }
      t.check(afterRecord.sealed === true &&
              String(afterRecord.vault || '').indexOf(MARK) === 0,
              'AND THE REWRITE IS SEALED AGAIN — the spend did not put the ' +
              'set in the clear', afterRecord.sealed);
      t.check(!sealedCodes.some(function (code) {
        return afterRaw.indexOf(code) >= 0;
      }), 'so not one of the remaining codes appears on the entry');
      t.check(afterRecord.hashed === false,
              'and the record does not claim to hold hashes');
      t.check(!credentials.verifyBackupCode(grace, sealedCodes[0]).ok &&
              credentials.verifyBackupCode(grace, sealedCodes[1]).ok,
              'and it still works: the spent code is refused and the next ' +
              'one verifies through the resealed vault');
    }
    keystore.seal = function () {
      return null;
    };
    const refused = credentials.verifyBackupCode(grace, sealedCodes[2]);
    t.check(!refused.ok && refused.reason === 'store',
            'and a legacy set that CANNOT be sealed is not rewritten in the ' +
            'clear: the spend is refused instead', refused.reason);
  } finally {
    keystore.persists = realPersists;
    keystore.seal = realSeal;
    keystore.open = realOpen;
  }

  t.log.info('=== the asynchronous door refuses in the SAME ORDER ===');

  // `verifyBackupCode()` and `verifyBackupCodeAsync()` share one
  // `backupPrepare()`, which is this file's own shape (`verifyPrepare()` /
  // `verifyFinish()`) and exists so the two doors cannot come to disagree
  // about WHEN to say no. Asserted over the refusals that cost no hashing,
  // because those are the ones a second implementation would get wrong.
  const gail = somebody();
  const gailCodes = enrolAndTakeCodes(gail);
  const cases = [
    ['hunter2!', 'shape'],
    ['AAAAAAAAAA', 'mismatch']
  ];
  log.debug("Leaving run().");
  return cases.reduce(function (chain, pair) {
    return chain.then(function () {
      const sync = credentials.verifyBackupCode(gail, pair[0]);
      return credentials.verifyBackupCodeAsync(gail, pair[0])
        .then(function (async) {
          t.equal(sync.reason, pair[1],
                  'the synchronous door refuses "' + pair[0] + '" as ' +
                  pair[1]);
          t.equal(async.reason, sync.reason,
                  'and the asynchronous door gives the SAME reason — one ' +
                  'reading, two doors');
        });
    });
  }, Promise.resolve()).then(function () {
    return credentials.verifyBackupCodeAsync(gail, gailCodes[0])
      .then(function (good) {
        t.check(good.ok,
                'and a real code verifies through the asynchronous door');
        t.equal(good.remaining, gailCodes.length - 1,
                'and is spent exactly once by it');
        return credentials.verifyBackupCodeAsync(gail, gailCodes[0]);
      })
      .then(function (replay) {
        t.equal(replay.reason, 'spent',
                'and a replay through it is refused as spent, which is the ' +
                'spend really having been written rather than reported');
      });
  }).then(function () {
    return rest(t);
  });
}

function rest(t) {
  log.debug("Entering rest().");
  t.log.info('=== the report the console and /admin/crypto-metadata draw ===');
  const report = backupCodes.report();
  t.equal(report.alphabetSize, 32, 'the alphabet size is reported');
  t.equal(report.bitsPerCode, 50,
          'and the entropy at the default length — the number that decides ' +
          'whether the mechanism is worth anything, said in bits rather than ' +
          'left for a reader to derive from a length and an alphabet');
  t.check(/constantTimeEquals/.test(report.comparison),
          'the comparison is named', report.comparison);
  // THIS ASSERTED /AES-256-GCM/ UNTIL 2026-09-12, which is to say it pinned
  // the stale sentence in place for a day after the design reversed: the
  // codes have been scrypt hashes since 2026-09-11. It asserts the design now,
  // and that the old claim is gone rather than merely joined by the new one.
  t.check(/scrypt HASH/.test(report.atRest),
          'and so is what protects them at rest — a hash, since 2026-09-11',
          report.atRest);
  t.check(!/ENCRYPTED and not hashed/i.test(report.atRest),
          'and the report no longer says the codes are encrypted rather than ' +
          'hashed, which /admin/crypto-metadata was printing', report.atRest);

  // ZERO IS A LEGAL GROUP SIZE. `|| 5` read it as absent and printed every
  // code broken into fives on a deployment that asked for them unbroken.
  const config = require('../common/config');
  try {
    config.setOverride('backupCodes.groupSize', '0');
    t.equal(backupCodes.settings().groupSize, 0,
            'backupCodes.groupSize=0 is honoured as zero rather than read as ' +
            'absent and replaced with five');
    t.equal(backupCodes.formatted('ABCDEFGHJK',
                                  backupCodes.settings().groupSize),
            'ABCDEFGHJK',
            'and a code is then printed unbroken, as the row says');
  } finally {
    config.clearOverride('backupCodes.groupSize');
  }
  t.equal(backupCodes.settings().groupSize, 5,
          'and cleared, the default is five again');
  log.debug("Leaving rest().");
}

module.exports = {
  name: 'backup_codes',
  describe: 'recovery codes: generated when the person ASKS, shown once and ' +
            'stored — as scrypt hashes — only when they confirm they have ' +
            'kept them; nothing written before that and a shown code working ' +
            'nowhere until it is; confirming REPLACES; a set written by an ' +
            'older build still verifies; spent exactly once with a failed ' +
            'spend refusing; the two verification doors refusing in one ' +
            'order; and never a way in or the factor a sign-in demands',
  run: run
};
