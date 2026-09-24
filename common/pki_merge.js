// @ts-check
'use strict';
//
// File: pki_merge.js
//
// ===========================================================================
// ONE CERTIFICATE AUTHORITY ROW, WRITTEN BY SEVERAL NODES AT ONCE
// (2026-09-14, #46 section 1).
//
// Everything `common/pki.js` knows about a scope is ONE sealed row of
// `sts_keys` — `pki:<scope>` holds the Intermediate, the Issuing CAs, every
// certificate they recorded, the RFC 7523 key pairs and enrolled leaves they
// issued, the workbench's objects, and the REVOCATION LIST of each authority.
// Every change to any of it was READ THE ROW, CHANGE IT, WRITE THE WHOLE ROW
// BACK. On one node that is fine, because the in-memory row is the authority
// and the store a mirror of it. On two, it is issue #46's security finding:
// node A revokes a certificate, node B issues an ACME certificate a moment
// later from its copy of the row — which does not have the revocation yet —
// and B's save throws the revocation out of the store for good, while B's
// OCSP responder answers `good` for it.
//
// **THE WRITE IS NOW A THREE-WAY MERGE, DONE UNDER THE ROW'S LOCK**
// (`persistence_postgres.js`'s `mergeKeys()`), and this file is the merge.
// `base` is the row as this process last read or wrote it, `mine` is what it
// wants to write, `theirs` is what the store holds now. Nothing here decrypts,
// encrypts or talks to a store: `keystore.js` holds the key-encryption key and
// hands this module JSON, which is what lets
// `tests/cluster_key_pki_agreement.js` drive every rule below without one.
//
// ---------------------------------------------------------------------------
// WHY A MERGE AND NOT A ROW PER REVOCATION. The obvious alternative was to
// move the revocation list and the issued register out of the row into rows
// of their own. It is the more normal schema and it is the BIGGER change: a
// fourth row family in `sts_keys` (or a new table), a second restore, a second
// replication applier, and every one of the six readers of `row.revoked` and
// `row.issuedKeyPairs` moved off a synchronous map lookup that the OCSP
// responder and `revocation_status.js` sit on. The merge keeps every reader
// exactly where it was and changes ONE function — the write — which is where
// the loss happened. What it costs is that the merge has to know which members
// of the row are which KIND of data, and that is the table below.
//
// ---------------------------------------------------------------------------
// THE RULES, BY KIND OF MEMBER.
//
//   * **A REVOCATION IS NEVER LOST.** `revoked[<ca>]` is a UNION by serial.
//     The one entry a merge may remove is a `certificateHold` that `mine`
//     released (present in `base`, gone from `mine`) or `theirs` released —
//     RFC 5280 makes every other reason permanent, so no writer can have
//     meant to remove one, and a copy that lacks it is merely a stale copy.
//     Two entries for one serial keep the EARLIER date (`pki_revocation.js`'s
//     own idempotence rule: a validator may act on the first moment it was
//     told).
//   * **AN ISSUED SERIAL IS NEVER LOST.** `issuedKeyPairs` is a UNION by
//     serial, less what has expired (RFC 5280 section 3.3 lets a list forget
//     an expired certificate, and the writers already drop them).
//   * **THE CRL NUMBER IN THE REGISTER ONLY GOES UP.** Each writer bumps it by
//     one per change, so two concurrent changes from the same base land at
//     base + both bumps rather than at the larger of two equal numbers.
//   * **A TIER IS FIRST WRITER WINS.** The Root, an Intermediate, an Issuing
//     CA: when `mine` and `theirs` BOTH replaced one since `base`, with
//     different certificates, `theirs` — which committed first — is kept and
//     the member is reported in `lost`. A node that built a Root at the same
//     moment as another must adopt the other's rather than replace it,
//     because the other has already issued Intermediates under it; `pki.js`
//     reads `lost` and says so.
//   * **A RECORDED CERTIFICATE SLOT IS FIRST WRITER WINS TOO**, and the
//     displaced record's SERIAL is kept, in `issuedKeyPairs` — the certificate
//     exists, a relying party may hold it, and an OCSP responder with no record
//     of its serial would answer `unknown` about it.
//   * **EVERYTHING ELSE IS A PLAIN THREE-WAY MERGE**: a member only `mine`
//     changed is `mine`'s (a deletion included), one only `theirs` changed is
//     `theirs`'s, and one both changed differently is `theirs`'s.
//
// **WHAT THIS DOES NOT PROTECT, SAID RATHER THAN DISCOVERED.** `base` is the
// row this process last took from the store. An operation that read the row,
// awaited, and saves a copy built from what it read — while another node's
// row was adopted underneath it — looks, to a three-way merge, like a writer
// that deleted the other node's additions. That window existed inside one
// container already (the request pool's PKI channel is last write wins), the
// barrier narrows it to concurrent requests, and the two members where losing
// an addition is a SECURITY fault — the revocation lists and the issued
// register — are unions precisely so that it cannot reach them.
//
// A LEAF (rule 3): it registers no route, requires only bunyan and config, and
// holds no state.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({ name: 'pki_merge' });
config.registerLogger(log);

// The members a row may hold that are one CA TIER each, and the map of them.
const TIER_MEMBERS = ['root', 'intermediate'];
const TIER_MAP_MEMBERS = ['issuing'];

// ---------------------------------------------------------------------------
// A CANONICAL SPELLING, for "did this member change". `JSON.stringify` keeps
// insertion order, and the same certificate record built by two code paths —
// parsed from the store, or assembled with `Object.assign` — would compare
// unequal and turn an unchanged member into a conflict.
// ---------------------------------------------------------------------------
function canonical(value) {
  log.debug("Entering canonical().");
  if (value === undefined) {
    log.debug("Leaving canonical(). Undefined.");
    return '(undefined)';
  }
  const out = JSON.stringify(value, function (key, one) {
    if (one && typeof one === 'object' && !Array.isArray(one)) {
      const sorted = {};
      Object.keys(one).sort().forEach(function (name) {
        sorted[name] = one[name];
      });
      return sorted;
    }
    return one;
  });
  log.debug("Leaving canonical().");
  return out;
}

function same(a, b) {
  log.debug("Entering same().");
  log.debug("Leaving same().");
  return canonical(a) === canonical(b);
}

// A serial as `pki_revocation.js` compares them — lower case, no separators,
// no leading zeros. A copy of that module's `normalSerial()` rather than a
// require of it, because that module requires `pki.js`, which requires the
// keystore, which requires this: a cycle (rule 2).
function normalSerial(text) {
  log.debug("Entering normalSerial().");
  const hex = String(text || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  log.debug("Leaving normalSerial().");
  return hex.replace(/^0+/, '') || '0';
}

// The three-way answer for one member, and whether it was a conflict.
function pick(base, mine, theirs) {
  log.debug("Entering pick().");
  if (same(mine, base)) {
    log.debug("Leaving pick(). Only theirs may have changed.");
    return { value: theirs, conflict: false };
  }
  if (same(theirs, base) || same(mine, theirs)) {
    log.debug("Leaving pick(). Only mine changed.");
    return { value: mine, conflict: false };
  }
  log.debug("Leaving pick(). Both changed; theirs committed first.");
  return { value: theirs, conflict: true };
}

// Rest parameters rather than `arguments` (#50): the type checker reads a
// function that names no parameter as taking none.
function keysOf(...objects) {
  log.debug("Entering keysOf().");
  const seen = Object.create(null);
  const out = [];
  objects.forEach(function (object) {
    Object.keys(object || {}).forEach(function (key) {
      if (!seen[key]) {
        seen[key] = true;
        out.push(key);
      }
    });
  });
  log.debug("Leaving keysOf().");
  return out;
}

// A record displaced from a certificate slot, as the issued register keeps
// one: serial, subject, expiry, what it was — never a key.
function displacedRecord(slot, record) {
  log.debug("Entering displacedRecord().");
  log.debug("Leaving displacedRecord().");
  return {
    serialHex: record.serialHex,
    subject: record.subject || '',
    notAfter: record.notAfter || '',
    identifier: String(slot),
    subjectKind: 'displaced',
    purpose: 'displaced:' + String(slot),
    useCase: record.useCase || String(slot).split(':')[0],
    issuedAt: new Date(Number(record.createdAt) || Date.now()).toISOString()
  };
}

// A map of CA tiers or of certificate records, keyed; first writer wins on a
// conflict. `onConflict(key, mineValue)` is told what was not kept.
function mergeKeyed(base, mine, theirs, onConflict) {
  log.debug("Entering mergeKeyed().");
  const b = base || {};
  const m = mine || {};
  const t = theirs || {};
  const out = {};
  keysOf(t, m, b).forEach(function (key) {
    const answer = pick(b[key], m[key], t[key]);
    if (answer.conflict) {
      onConflict(key, m[key]);
    }
    if (answer.value !== undefined) {
      out[key] = answer.value;
    }
  });
  log.debug("Leaving mergeKeyed().");
  return out;
}

// The workbench's objects, an array keyed by `id`, in `theirs`' order with
// `mine`'s additions after.
function mergeObjects(base, mine, theirs) {
  log.debug("Entering mergeObjects().");
  function byId(list) {
    log.debug("Entering byId().");
    const out = {};
    (list || []).forEach(function (one) {
      if (one && one.id !== undefined) {
        out[String(one.id)] = one;
      }
    });
    log.debug("Leaving byId().");
    return out;
  }
  const merged = mergeKeyed(byId(base), byId(mine), byId(theirs),
                            function () {});
  const order = keysOf(byId(theirs), byId(mine));
  log.debug("Leaving mergeObjects().");
  return order.filter(function (id) {
    return merged[id] !== undefined;
  }).map(function (id) {
    return merged[id];
  });
}

// THE ISSUED REGISTER: a union by serial, less what has expired.
function mergeIssued(mine, theirs, extra, nowMs) {
  log.debug("Entering mergeIssued().");
  const seen = Object.create(null);
  const out = [];
  [theirs || [], mine || [], extra || []].forEach(function (list) {
    list.forEach(function (one) {
      if (!one || !one.serialHex) {
        return;
      }
      const key = normalSerial(one.serialHex) + '/' + String(one.useCase || '');
      if (seen[key]) {
        return;
      }
      if (one.notAfter && new Date(one.notAfter).getTime() <= nowMs) {
        return;
      }
      seen[key] = true;
      out.push(one);
    });
  });
  log.debug("Leaving mergeIssued(). " + out.length + " record(s).");
  return out;
}

// ONE AUTHORITY'S REVOCATION LIST: a union, less a hold one side released.
function mergeRevokedList(base, mine, theirs) {
  log.debug("Entering mergeRevokedList().");
  function bySerial(list) {
    log.debug("Entering bySerial().");
    const out = {};
    (list || []).forEach(function (one) {
      if (one && one.serialHex) {
        out[normalSerial(one.serialHex)] = one;
      }
    });
    log.debug("Leaving bySerial().");
    return out;
  }
  const b = bySerial(base);
  const m = bySerial(mine);
  const t = bySerial(theirs);
  const out = [];
  keysOf(t, m, b).forEach(function (serial) {
    const inBase = b[serial];
    const inMine = m[serial];
    const inTheirs = t[serial];
    const hold = inBase && inBase.reason === 'certificateHold';
    // A RELEASE: the hold was in the base, and one side took it out while
    // the other left it exactly as it was.
    if (hold && !inMine && (!inTheirs || same(inTheirs, inBase))) {
      return;
    }
    if (hold && !inTheirs && same(inMine, inBase)) {
      return;
    }
    const candidates = [inTheirs, inMine, inBase].filter(Boolean);
    if (!candidates.length) {
      return;
    }
    // THE EARLIER DATE WINS between two entries for one serial.
    candidates.sort(function (x, y) {
      return new Date(x.revokedAt).getTime() - new Date(y.revokedAt).getTime();
    });
    out.push(inTheirs && inMine && !same(inTheirs, inMine)
      ? candidates[0]
      : (inTheirs || inMine || inBase));
  });
  log.debug("Leaving mergeRevokedList(). " + out.length + " entry(ies).");
  return out;
}

function mergeRevoked(base, mine, theirs) {
  log.debug("Entering mergeRevoked().");
  const out = {};
  const b = base || {};
  const m = mine || {};
  const t = theirs || {};
  keysOf(t, m, b).forEach(function (caId) {
    const list = mergeRevokedList(b[caId], m[caId], t[caId]);
    if (list.length || m[caId] || t[caId]) {
      out[caId] = list;
    }
  });
  log.debug("Leaving mergeRevoked().");
  return out;
}

function mergeCrlNumbers(base, mine, theirs) {
  log.debug("Entering mergeCrlNumbers().");
  const out = {};
  const b = base || {};
  const m = mine || {};
  const t = theirs || {};
  keysOf(t, m, b).forEach(function (caId) {
    const was = Number(b[caId]) || 0;
    const mineNow = Number(m[caId]) || 0;
    const theirsNow = Number(t[caId]) || 0;
    out[caId] = (mineNow > was && theirsNow > was)
      ? theirsNow + (mineNow - was)
      : Math.max(mineNow, theirsNow, was);
  });
  log.debug("Leaving mergeCrlNumbers().");
  return out;
}

function mergeCount(base, mine, theirs) {
  log.debug("Entering mergeCount().");
  const was = Number(base) || 0;
  const m = Number(mine) || 0;
  const t = Number(theirs) || 0;
  if (same(mine, base)) {
    log.debug("Leaving mergeCount().");
    return theirs;
  }
  if (same(theirs, base)) {
    log.debug("Leaving mergeCount().");
    return mine;
  }
  // A rebuild RESETS the count (`buildScopeNow()`), and a reset is not an
  // increment to add.
  log.debug("Leaving mergeCount().");
  return (m < was || t < was) ? Math.min(m, t) : t + (m - was);
}


// ---------------------------------------------------------------------------
// A CERTIFICATE THIS ROW PUBLISHES MAY NOT BE ON ITS OWN CRL (2026-09-22).
//
// The two rules above are each right and they can contradict one another: a
// TIER is first writer wins, and a REVOCATION is never lost. So a node that
// rebuilt a branch — superseding the Intermediate it replaced — and then did
// NOT get its new tier into the row leaves the union carrying a revocation of
// the certificate the row still publishes. `sts_pki_distribution_points`
// found exactly that in `cluster` mode: *lists CN=sts Intermediate CA … as
// REVOKED, and this service is publishing that certificate right now*.
//
// **THE INVARIANT IS THE NARROW ONE AND IT IS NOT A THIRD POLICY**: whatever
// the row publishes as a live tier is not revoked BY THIS ROW. Nothing else
// is touched — a revocation of anything that is not a live tier is permanent,
// as RFC 5280 requires, and the tier that won is untouched.
//
// It answers WHAT IT DROPPED rather than doing it quietly, because the drop is
// evidence of the lost write above it: `pki.js` logs it, so the race stays
// visible instead of being tidied away.
// ---------------------------------------------------------------------------
function liveTierSerials(row) {
  log.debug("Entering liveTierSerials().");
  const out = {};
  function note(tier) {
    log.debug("Entering note().");
    if (tier && tier.serialHex) {
      out[normalSerial(tier.serialHex)] = true;
    }
    log.debug("Leaving note().");
  }
  TIER_MEMBERS.forEach(function (member) {
    note(row[member]);
  });
  TIER_MAP_MEMBERS.forEach(function (member) {
    const held = row[member] || {};
    Object.keys(held).forEach(function (key) {
      note(held[key]);
    });
  });
  log.debug("Leaving liveTierSerials(). " + Object.keys(out).length +
            " live tier(s).");
  return out;
}

function liveAgain(row) {
  log.debug("Entering liveAgain().");
  const live = liveTierSerials(row);
  const dropped = [];
  const lists = row.revoked || {};
  Object.keys(lists).forEach(function (ca) {
    const kept = (lists[ca] || []).filter(function (one) {
      if (one && one.serialHex && live[normalSerial(one.serialHex)]) {
        dropped.push({ ca: ca, serialHex: one.serialHex,
                       reason: String((one && one.reason) || '') });
        return false;
      }
      return true;
    });
    lists[ca] = kept;
  });
  log.debug("Leaving liveAgain(). " + dropped.length + " dropped.");
  return dropped;
}
// ---------------------------------------------------------------------------
// THE LIVE TIERS OF `row` THAT `lists` CALL SUPERSEDED (2026-09-24). A
// supersession is what a rebuild writes when it replaces a tier, it is
// permanent (RFC 5280 section 5.3.1: only `certificateHold` is undone), and
// so a row publishing a tier some other row supersedes is a copy made BEFORE
// that rebuild. `keystore.js`'s adoptPki() refuses such a copy arriving over
// the request pool's channel. `lists` is one or more `revoked` members.
// Answers the serials, normalised.
// ---------------------------------------------------------------------------
function supersededLiveTiers(row, lists) {
  log.debug("Entering supersededLiveTiers().");
  const live = liveTierSerials(row || {});
  const found = [];
  (lists || []).forEach(function (revoked) {
    Object.keys(revoked || {}).forEach(function (ca) {
      (revoked[ca] || []).forEach(function (one) {
        const serial = one && one.serialHex ? normalSerial(one.serialHex) : '';
        if (serial && live[serial] && String(one.reason) === 'superseded' &&
            found.indexOf(serial) < 0) {
          found.push(serial);
        }
      });
    });
  });
  log.debug("Leaving supersededLiveTiers(). " + found.length + " found.");
  return found;
}

// ---------------------------------------------------------------------------
// THE MERGE. Returns `{ row, lost, displaced }`: the row to write, the tier
// members `mine` changed and did not get (`root`, `intermediate`,
// `issuing.<use case>`, `certs.<slot>`), and how many displaced certificate
// records were kept in the issued register.
// ---------------------------------------------------------------------------
function merge(base, mine, theirs, options) {
  log.debug("Entering merge().");
  const b = base || {};
  const m = mine || {};
  const t = theirs || {};
  const nowMs = Number((options && options.now) || Date.now());
  const lost = [];
  const displaced = [];
  const row = {};
  keysOf(t, m, b).forEach(function (member) {
    if (member === 'tiers') {
      // Composed on the way out by `pki.js` and never stored.
      return;
    }
    if (member === 'revoked') {
      row.revoked = mergeRevoked(b.revoked, m.revoked, t.revoked);
      return;
    }
    if (member === 'crlNumbers') {
      row.crlNumbers = mergeCrlNumbers(b.crlNumbers, m.crlNumbers,
                                       t.crlNumbers);
      return;
    }
    if (member === 'issuedKeyPairs') {
      // Filled after `certs`, which may add displaced serials to it.
      return;
    }
    if (member === 'objects') {
      row.objects = mergeObjects(b.objects, m.objects, t.objects);
      return;
    }
    if (member === 'issuedCount') {
      const count = mergeCount(b.issuedCount, m.issuedCount, t.issuedCount);
      if (count !== undefined) {
        row.issuedCount = count;
      }
      return;
    }
    if (member === 'certs') {
      const certs = mergeKeyed(b.certs, m.certs, t.certs,
                               function (slot, was) {
                                 lost.push('certs.' + slot);
                                 if (was && was.serialHex) {
                                   displaced.push(displacedRecord(slot, was));
                                 }
                               });
      if (m.certs !== undefined || t.certs !== undefined) {
        row.certs = certs;
      }
      return;
    }
    if (TIER_MAP_MEMBERS.indexOf(member) >= 0) {
      const merged = mergeKeyed(b[member], m[member], t[member],
                                function (key) {
                                  lost.push(member + '.' + key);
                                });
      if (m[member] !== undefined || t[member] !== undefined) {
        row[member] = merged;
      }
      return;
    }
    const answer = pick(b[member], m[member], t[member]);
    if (answer.conflict && TIER_MEMBERS.indexOf(member) >= 0) {
      lost.push(member);
    }
    if (answer.value !== undefined) {
      row[member] = answer.value;
    }
  });
  if (m.issuedKeyPairs || t.issuedKeyPairs || displaced.length) {
    row.issuedKeyPairs = mergeIssued(m.issuedKeyPairs, t.issuedKeyPairs,
                                     displaced, nowMs);
  }
  const published = liveAgain(row);
  log.debug("Leaving merge(). " + lost.length + " member(s) lost, " +
            displaced.length + " displaced, " + published.length +
            " revocation(s) of a live tier dropped.");
  return { row: row, lost: lost, displaced: displaced.length,
           published: published };
}

module.exports = {
  merge: merge,
  // The invariant on its own, for `keystore.js`: a row is sealed through one
  // path when nobody else has written it and through `merge()` when somebody
  // has, and a certificate the row publishes may not be on its own CRL
  // either way. See liveAgain()'s own block.
  dropRevocationsOfLiveTiers: liveAgain,
  supersededLiveTiers: supersededLiveTiers,
  canonical: canonical,
  normalSerial: normalSerial,
  // The issued-register record for a certificate a slot no longer holds, for
  // `pki.js`'s `certify()` (#185): one shape for both callers.
  displacedRecord: displacedRecord
};
