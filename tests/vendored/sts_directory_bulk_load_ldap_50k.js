"use strict";
//
// File: sts_directory_bulk_load_ldap_50k.js
//
// ===========================================================================
// FIFTY THOUSAND PEOPLE THROUGH THE LDAP INTERFACE, AND WHY THAT IS A
// DIFFERENT QUESTION FROM FIVE THOUSAND.
//
// `sts_directory_bulk_load_ldap.js` beside this file adds five thousand over
// the raw socket and is the door-to-door COMPARISON — its numbers are read
// against the SCIM and `/admin-api` jobs, which is why all three share sizes.
// This one asks something that comparison cannot: **does the add path stay
// constant-time when the directory is an order of magnitude bigger?**
//
// It is worth asking separately because the answer was NO until 2026-09-07,
// and the way it was wrong is the way this kind of thing is usually wrong: a
// create walked the whole realm to enforce one-entry-per-person, so the cost
// per person rose with the number of people already there — 0.73ms at the five
// hundredth and 13.45ms at the five thousandth. At five thousand that reads as
// a slow service. At fifty thousand it is a service that stops. The fix was an
// index, and this job is what would notice if it were ever lost: a quadratic
// hidden inside five thousand adds is a plausible-looking number, and inside
// fifty thousand it is a job that does not finish.
//
// ---------------------------------------------------------------------------
// IT DRIVES THE OTHER JOB'S FILE RATHER THAN COPYING IT.
//
// Everything about the LDAP door — the connect, the bind, the add, the
// read-back over SEARCH, the refusal shapes that are peculiar to this protocol
// — lives in `sts_directory_bulk_load_ldap.js`, and this file `require`s it.
// The alternative was a second copy of the ldapjs client, and this repository
// has been clear about what that costs: `tests/CLAUDE.md`'s rule is that each
// job owns its own DOOR, which is an argument for three jobs driving three
// protocols and NOT an argument for two jobs driving one protocol twice. Two
// copies of the same client would be two implementations of the same
// handshake, drifting.
//
// What this file owns is the SCALE and the NAMES, which is all that differs.
//
// ---------------------------------------------------------------------------
// THE THREE VARIABLES, AND EACH IS SET FOR A REASON.
//
//   BULK_USERS=50000        the point of the job.
//
//   BULK_GROUPS=1           and one member. The question here is the USER add
//   BULK_MEMBERS_PER_GROUP=1  path at scale; the group and membership phases
//                           are the other job's to measure, and running them
//                           at this size would add fifty thousand membership
//                           writes to a job that is not about them. They
//                           cannot be ZERO — `bulk.checkSizes()` refuses that,
//                           and rightly: a size of nought is a phase that
//                           silently measures nothing — so they are the
//                           smallest number that still exercises the code.
//
//   BULK_DOOR=ldap50k       so the two LDAP jobs do not collide. They run in
//                           one suite against one directory that nothing
//                           deletes from, and `bulk.stampFor()` builds every
//                           invented name out of the door and the run stamp —
//                           so two jobs sharing a door would meet on every
//                           name and be refused LDAP_ENTRY_ALREADY_EXISTS
//                           fifty thousand times, which names the
//                           one-entry-per-person rule and has nothing to do
//                           with it.
//
// **THEY ARE SET ONLY IF NOT ALREADY SET**, so a person narrowing this by hand
// — `BULK_USERS=2000 node sts_directory_bulk_load_ldap_50k.js` — gets what they
// asked for. That is the same courtesy `bulk_load.js` extends to its own
// defaults.
//
// ---------------------------------------------------------------------------
// WHAT IT COSTS, AND THE TWO SETTINGS THAT HAVE TO GIVE.
//
// The shared preflight raises `ldap.maxEntries` from what the directory
// already holds plus what this job is about to add, so fifty thousand is
// accommodated without anything here naming a number. It LEAVES IT RAISED, for
// the reason that file argues: a ceiling restored under fifty thousand new
// entries is a service that refuses the next create by anybody.
//
// Its MANIFEST entry carries a watchdog of its own and a generous one. At the
// measured 0.45ms per add this is about half a minute of adds; the watchdog is
// not sized for that but for the failure it exists to report — a quadratic
// come back, where the last thousand cost fifty times the first and the job
// has to be allowed to reach the end and SAY so rather than being killed part
// way and reported as a timeout, which names nothing.
//
// IT IS LAST IN THE MANIFEST, after the other three bulk jobs, because it
// leaves the directory an order of magnitude larger than they found it and
// every job that walks a page or reads a register should have run first.
// ===========================================================================

function setDefault(name, value) {
  if (process.env[name] === undefined || process.env[name] === "") {
    process.env[name] = value;
  }
}

setDefault("BULK_USERS", "50000");
setDefault("BULK_GROUPS", "1");
setDefault("BULK_MEMBERS_PER_GROUP", "1");
setDefault("BULK_DOOR", "ldap50k");

// AND THEN THE JOB ITSELF. It reads those variables at load and runs `main()`
// on its own, so there is nothing to call here — which is also why the
// assignments above have to happen BEFORE this line rather than after it.
require("./sts_directory_bulk_load_ldap.js");
