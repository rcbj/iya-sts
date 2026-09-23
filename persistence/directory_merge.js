// @ts-check
'use strict';
//
// File: persistence/directory_merge.js
//
// ===========================================================================
// TWO NODES WRITING ONE DIRECTORY ENTRY, AND WHAT SURVIVES (2026-09-14, #46
// section 3).
//
// `sts_ldap_entries.attrs` is a whole row. Until this file the flush wrote
// `ON CONFLICT DO UPDATE SET attrs = EXCLUDED.attrs`, so of two nodes that each
// added a member to one group the one that committed second wrote its copy —
// the group as it knew it plus ITS member — over the other's. Nothing failed;
// one member was simply not in the group any more, on every node. Two adds of
// one DN replaced each other the same way, password hash included.
//
// **A THREE-WAY MERGE, BECAUSE THE FLUSH ALREADY HOLDS ALL THREE SIDES.**
//
//   * BASE   — `persistence.js`'s shadow: the entry as this process last wrote
//              it or last applied it from the store. It is what the change was
//              made AGAINST.
//   * MINE   — the live entry, which is what the change produced.
//   * THEIRS — the row in the store, read under `SELECT … FOR UPDATE` inside
//              the flush's own transaction, so nothing can move it before the
//              merged value is written.
//
// An attribute only one side changed takes that side. An attribute both changed
// is merged by VALUE where the attribute is a list (a group's `member`, an
// entry's `objectClass`, the security keys) — theirs, minus what mine removed,
// plus what mine added — and otherwise MINE wins, because a password, an
// authenticator secret or a registration document that came out as the union
// of two writes would be two credentials or no document.
//
// **WHICH ATTRIBUTE IS A LIST IS A TABLE PLUS ONE RULE.** This directory is
// schemaless and holds every value as an array, so the array cannot say. So:
// `SINGLE` is always whole-valued (the credentials, the timestamps); `MULTI` is
// always merged by value (the attributes this service itself appends to); and
// anything else is merged by value if ANY of the three sides holds more than
// one value — which is what a list looks like — and whole-valued otherwise. The
// rule alone would get a group with no members wrong (every side holds at most
// one value), which is why `member` is in the table.
//
// **`entryUUID` DECIDES WHETHER TWO WRITES ARE ONE ENTRY.** It is assigned by
// the add and carried through every overwrite (`ldap/ldap_server.js`), so:
//
//   * an add whose DN the store already holds under a DIFFERENT entryUUID is a
//     second entry colliding with the first, and the FIRST COMMITTED WINS —
//     this process's copy is replaced by the stored one (`STS-STORE-0052`). A
//     merge would give the loser's password to the winner's person.
//   * the same entryUUID with no base (a seeded entry, whose value is a name-
//     based UUID every node computes alike, or a retry of this process's own
//     write) is one entry and is merged against an EMPTY base, which unions
//     lists and takes mine for a conflicting single value.
//   * a row GONE from the store that this process had seen was deleted by
//     another node, and the delete wins (`STS-STORE-0053`) — unless mine
//     carries a different entryUUID than the base, which is this process
//     deleting and re-creating the DN inside one flush.
//
// A LIBRARY with no requires (rule 3): the postgres driver calls it inside the
// transaction and `persistence.js` calls it again for a write that raced the
// flush, and `tests/cluster_lww_stores.js` calls it with nothing else loaded.
// ===========================================================================

// Always whole-valued: a credential, or a value whose meaning is the pair it
// forms with another whole-valued attribute (a password and its history).
const SINGLE = ['userpassword', 'pwdhistory', 'pwdchangedtime',
                'ststotpcredential', 'stsbackupcodes', 'stsactivationtoken',
                'stsactivationexpires', 'appregistrationjson',
                'stsapppassword', 'stsidaverification',
                'stsselfissuedsubject', 'stsdevicesecrethash',
                'stsdevicesession', 'stscibausercode'];

// Always merged by value: lists this service appends to itself.
const MULTI = ['member', 'uniquemember', 'memberof', 'objectclass',
               'description', 'oauthconsent', 'stswebauthncredential',
               'x509subject', 'didsubject', 'spiffesubject', 'authnmethod',
               'federationattribute', 'federationissuer',
               'federationrelationship', 'federationlink'];

// A HOT PATH, AND EVERY FUNCTION IN THIS FILE IS ON IT: `same()`, `uuidOf()`,
// `countOf()`, `listOf()`, `mergeValues()`, `mergeAttributes()`,
// `mergeEntry()` and `canonicalJson()` run once per attribute, or once per
// entry, of every row a flush writes. So no Entering/Leaving pair in any of
// them, for the reason `usernameKeysOf()` in ldap_server.js gives — at `debug`
// the pairs would be several lines per attribute of every entry a bulk load
// writes, and would drown the log.
function same(a, b) {
  return JSON.stringify(a === undefined ? null : a) ===
         JSON.stringify(b === undefined ? null : b);
}

function uuidOf(entry) {
  const value = entry && entry.attributes &&
                (entry.attributes.entryuuid || [])[0];
  return value ? String(value).toLowerCase() : '';
}

function countOf(values) {
  return Array.isArray(values) ? values.length : (values === undefined ? 0 : 1);
}

function listOf(values) {
  if (values === undefined || values === null) {
    return [];
  }
  return Array.isArray(values) ? values.slice(0) : [values];
}

// THEIRS, MINUS WHAT MINE REMOVED FROM BASE, PLUS WHAT MINE ADDED TO IT — in
// theirs' order with mine's additions after, so two nodes merging the same
// pair produce the same array. Undefined when nothing is left, which the
// caller reads as "the attribute is gone".
function mergeValues(base, mine, theirs) {
  const b = listOf(base).map(String);
  const m = listOf(mine).map(String);
  const removed = b.filter(function (v) { return m.indexOf(v) < 0; });
  const added = m.filter(function (v) { return b.indexOf(v) < 0; });
  const out = listOf(theirs).map(String).filter(function (v) {
    return removed.indexOf(v) < 0;
  });
  added.forEach(function (v) {
    if (out.indexOf(v) < 0) {
      out.push(v);
    }
  });
  return out.length ? out : undefined;
}

function mergeAttributes(base, mine, theirs) {
  const b = (base && base.attributes) || {};
  const m = (mine && mine.attributes) || {};
  const t = (theirs && theirs.attributes) || {};
  const names = [];
  [m, t, b].forEach(function (side) {
    Object.keys(side).forEach(function (name) {
      if (names.indexOf(name) < 0) {
        names.push(name);
      }
    });
  });
  const out = {};
  names.forEach(function (name) {
    let value;
    if (same(m[name], b[name])) {
      value = t[name];
    } else if (same(t[name], b[name]) || same(m[name], t[name])) {
      value = m[name];
    } else if (name === 'modifytimestamp') {
      // Generalized time, which sorts as a string.
      value = String(listOf(m[name])[0] || '') >
              String(listOf(t[name])[0] || '') ? m[name] : t[name];
    } else if (name === 'createtimestamp' || name === 'entryuuid') {
      value = t[name] !== undefined ? t[name] : m[name];
    } else if (SINGLE.indexOf(name) >= 0) {
      value = m[name];
    } else if (MULTI.indexOf(name) >= 0 || countOf(b[name]) > 1 ||
               countOf(m[name]) > 1 || countOf(t[name]) > 1) {
      value = mergeValues(b[name], m[name], t[name]);
    } else {
      value = m[name];
    }
    if (value !== undefined) {
      out[name] = value;
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// THE ONE QUESTION. `base`, `mine` and `theirs` are entries —
// `{ dn, attributes, createdAt, modifiedAt, origin }` — or null (base: this
// process believed the DN held nothing; theirs: the store holds nothing).
//
// Answers `{ outcome, entry }`:
//   'mine'    — write mine as it is (nothing of theirs is lost by doing so);
//   'merged'  — write `entry`, which differs from mine;
//   'theirs'  — the store's entry wins whole; write nothing, take `entry` here;
//   'deleted' — another node deleted it; write nothing, remove it here.
// ---------------------------------------------------------------------------
function mergeEntry(base, mine, theirs) {
  if (!mine) {
    // A delete is written as a delete and never reaches here; answered for a
    // caller that merges a replicated row into a pending local delete.
    return { outcome: 'deleted', entry: null };
  }
  const mu = uuidOf(mine);
  if (!theirs) {
    if (!base) {
      return { outcome: 'mine', entry: mine };
    }
    const bu = uuidOf(base);
    if (mu && bu && mu !== bu) {
      // Deleted and added again HERE, inside one flush.
      return { outcome: 'mine', entry: mine };
    }
    return { outcome: 'deleted', entry: null };
  }
  const tu = uuidOf(theirs);
  let effectiveBase = base;
  if (!base) {
    if (mu && tu && mu !== tu) {
      return { outcome: 'theirs', entry: theirs };
    }
    effectiveBase = { attributes: {} };
  } else {
    const bu = uuidOf(base);
    if (bu && tu && tu !== bu) {
      // The store holds a different entry at this DN than the one this
      // process based its change on: deleted and created again elsewhere. If
      // mine is a re-creation too, the one that committed first wins.
      return { outcome: 'theirs', entry: theirs };
    }
    if (bu && mu && mu !== bu) {
      // Deleted and created again here: the old entry's changes elsewhere are
      // changes to an entry that no longer exists.
      return { outcome: 'mine', entry: mine };
    }
  }
  const attributes = mergeAttributes(effectiveBase, mine, theirs);
  const merged = {
    dn: mine.dn,
    attributes: attributes,
    createdAt: theirs.createdAt || mine.createdAt || null,
    modifiedAt: String(mine.modifiedAt || '') >= String(theirs.modifiedAt || '')
      ? (mine.modifiedAt || null) : (theirs.modifiedAt || null)
  };
  const origin = theirs.origin || mine.origin;
  if (origin) {
    merged.origin = origin;
  }
  if (same(attributes, mine.attributes)) {
    return { outcome: 'mine', entry: mine };
  }
  return { outcome: 'merged', entry: merged };
}

// The canonical JSON of an entry read out of the store, in the key order a
// live entry has (`putEntry()` builds dn, attributes, createdAt, modifiedAt,
// origin). The shadow compares strings, so a row that arrived with another
// key order would otherwise look changed on every flush.
function canonicalJson(entry) {
  if (!entry) {
    return null;
  }
  const out = { dn: entry.dn, attributes: entry.attributes || {},
                createdAt: entry.createdAt || null,
                modifiedAt: entry.modifiedAt || entry.createdAt || null };
  if (entry.origin) {
    out.origin = entry.origin;
  }
  return JSON.stringify(out);
}

module.exports = {
  SINGLE: SINGLE,
  MULTI: MULTI,
  mergeEntry: mergeEntry,
  mergeValues: mergeValues,
  canonicalJson: canonicalJson
};
