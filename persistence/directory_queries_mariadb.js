// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence/directory_queries_mariadb.js
//
// ===========================================================================
// THE DIRECTORY'S LOOKUPS, SPELT FOR MARIADB (#677, phase 3b).
//
// `directory_queries.js` is the one copy of every question the directory asks
// the store, in PostgreSQL's text. This is the SAME LIST OF QUESTIONS under the
// same names, with the same arguments and the same answers
// (`directory_queries.answerOf()` reads both), asked of MariaDB's schema.
// What differs is how a value is found, because MariaDB has no GIN:
//
//   * A LOOKUP BY VALUE IS A ROW OF `sts_ldap_entry_keys`, `(realm, kind, k,
//     dn_key)`, written by the driver in the entry's own transaction
//     (`directory_portable.js`) from the same `directory_codec` index the
//     JSON columns are filled from. `jsonb @> '["k"]'` over a GIN index is
//     `kind = ? AND k = ?` over the key table's primary key: one index range,
//     holding exactly the entries that carry the value, in `dn_key` order. The
//     entry is then one primary-key read. Kinds: `name`, `mail`, `uuid`,
//     `class`, `value` (PostgreSQL's `value_keys`), `attr` (the asked
//     attribute names, `ASKED_ATTRIBUTES`, where PostgreSQL has its partial
//     `sts_ldap_entries_asked_names`) and `dek` (`dek_keys`' ids).
//   * `k` IS AT MOST 344 CHARACTERS (`mariadb/CLAUDE.md`). A lookup form longer
//     than that — possible only where nothing seals, since a keyed digest is
//     43 — is stored and asked as `#` and the SHA-256 of it in hex
//     (`tableKey()`), on both sides, so the lookup still finds it. Digested,
//     not refused: the value is the KEY of a lookup, never shown, and refusing
//     it would refuse the entry. Neither `#` nor a digest's alphabet is in
//     either form the codec writes (a keyed digest is base64url; a clear form
//     is `<kind>\n<value>`), so the three cannot meet.
//   * NO LATERAL. PostgreSQL bounds a subtree page with a LATERAL walk per
//     parent; here the realm's distinct parents are read by the same loose
//     index scan (a recursive CTE whose step is a correlated `MIN()` — one
//     descent of `(realm, parent_key, dn_key)` each), and each kept parent's
//     page is its own `(SELECT … ORDER BY dn_key LIMIT n)` branch of one
//     UNION ALL, so the cost is still parents plus rows answered and never the
//     realm. Several statements where PostgreSQL sends one: a question here is
//     a function that ASKS (`ask(name, text, values)` answering rows), not a
//     statement it builds, because there is no synchronous bridge on MariaDB
//     to hand one statement to (`persistence/CLAUDE.md`).
//   * A row comparison `(a, b) > (?, ?)` is written out as `a > ? OR (a = ?
//     AND b > ?)`, which MariaDB's range optimiser takes; it does not take the
//     row form as a range.
//
// THE SESSION (`knex_store.js`): PIPES_AS_CONCAT is set, but `CONCAT()` is
// written here so a statement does not depend on it; and NO_BACKSLASH_ESCAPES
// is OFF, so `ESCAPE '\\'` in a statement's text is ONE backslash, which is
// the escape `directory_queries.likeEscaped()` writes.
//
// THE DIFFERENCES IN WHAT IS ANSWERED, each on purpose:
//   * `rdnPage` visits every child, where PostgreSQL's skip-scan visits one
//     row per distinct `rdn_value` (`rdnRange()`'s note): a person's RDN is
//     their `uid`, unique under `ou=users`, so the two agree on everything
//     this service writes.
//   * `anyWithAttribute` for a counted attribute asks whether the SUM of the
//     key's shards is above zero; PostgreSQL asks whether any shard is, which
//     a shard holding +1 beside one holding -1 would answer yes.
//
// A LIBRARY: it requires `directory_queries.js` (for the lists, keying and
// bounds it shares), bunyan, and `common/crypto` lazily for `tableKey()`'s
// digest. It sends nothing itself.
// ===========================================================================

const bunyan = require('bunyan');
const directoryQueries = require('./directory_queries');

const log = bunyan.createLogger({ name: 'sts-directory-queries-mariadb' });

// The longest `sts_ldap_entry_keys.k` (`mariadb/CLAUDE.md`).
const KEY_LIMIT = 344;

// The columns every lookup selects, on the entry's alias `e`.
const COLUMNS = 'e.realm, e.dn_key, e.dn, e.attrs, e.origin, e.created_at, ' +
                'e.modified_at';

// How many parents' pages one UNION ALL carries.
const PARENTS_PER_STATEMENT = 200;

// The kinds of `sts_ldap_entry_keys`.
const KINDS = Object.freeze(['name', 'mail', 'uuid', 'class', 'value',
                             'attr', 'dek']);

// The names already said to have no index, so the log says it once a name.
const unindexedNoted = new Set();

/**
 * A lookup form as `sts_ldap_entry_keys.k` holds it: itself, or `#` and its
 * SHA-256 in hex when it is longer than the column (see the header).
 *
 * @param form - the lookup form (`directory_codec.lookupOf()`), or a name
 * @returns the column value
 */
function tableKey(form) {
  log.debug("Entering tableKey().");
  const text = String(form == null ? '' : form);
  // VARCHAR counts characters, so the test counts code points.
  if (Array.from(text).length <= KEY_LIMIT) {
    log.debug("Leaving tableKey().");
    return text;
  }
  const hex = require('../common/crypto').digest('sha256',
    Buffer.from(text, 'utf8'), 'hex');
  log.debug("Leaving tableKey(). Digested.");
  return '#' + hex;
}

/**
 * `n` placeholders, comma-separated.
 *
 * @param n - how many
 * @returns the SQL
 */
function marks(n) {
  log.debug("Entering marks().");
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push('?');
  }
  log.debug("Leaving marks().");
  return out.join(', ');
}

/**
 * "Strictly under a base" (or the base itself with `self`) for a column, and
 * its values: `right(col, n) = CONCAT(',', base)`, PostgreSQL's suffix test.
 *
 * @param column - the column (`e.dn_key`, `k.dn_key`, `parent_key`)
 * @param baseKey - the base's normalised DN
 * @param self - true to include the base itself
 * @returns `{ text, values }`
 */
function under(column, baseKey, self) {
  log.debug("Entering under().");
  const base = String(baseKey);
  const strict = 'RIGHT(' + column + ', ?) = CONCAT(\',\', ?)';
  const values = [directoryQueries.suffixLength(base), base];
  log.debug("Leaving under().");
  return self
    ? { text: '(' + column + ' = ? OR ' + strict + ')',
        values: [base].concat(values) }
    : { text: strict, values: values };
}

/**
 * The key-table form of one lookup argument.
 *
 * @param arg - `{ key }` from `directory_codec.keyArgs()`, or a raw value
 * @param kind - the codec's kind prefix for a raw value
 * @param lower - whether a raw value is lower-cased
 * @returns `k`
 */
function keyOf(arg, kind, lower) {
  log.debug("Entering keyOf().");
  log.debug("Leaving keyOf().");
  return tableKey(directoryQueries.keyed(arg, kind, lower));
}

/**
 * Entries found through the key table: one kind, one or more `k`, in
 * `dn_key` order, each entry once.
 *
 * @param ask - `(name, text, values)` answering rows
 * @param name - the question's name, for the statement
 * @param o - `{ realm, kind, keys, where?, limit?, offset?, after? }`;
 *   `where` is `{ text, values }` over `e.`
 * @returns the rows
 */
function byKeyRows(ask, name, o) {
  log.debug("Entering byKeyRows(). " + name);
  if (!o.keys.length) {
    log.debug("Leaving byKeyRows(). Nothing asked.");
    return Promise.resolve([]);
  }
  const values = [String(o.realm), o.kind].concat(o.keys);
  let inner = 'SELECT DISTINCT dn_key FROM sts_ldap_entry_keys WHERE realm = ' +
              '? AND kind = ? AND k IN (' + marks(o.keys.length) + ')';
  if (o.after !== undefined) {
    inner += ' AND dn_key > ?';
    values.push(String(o.after));
  }
  values.push(String(o.realm));
  let text = 'SELECT ' + COLUMNS + ' FROM (' + inner + ') AS u JOIN ' +
             'sts_ldap_entries AS e ON e.realm = ? AND e.dn_key = u.dn_key';
  if (o.where) {
    text += ' WHERE ' + o.where.text;
    o.where.values.forEach(function (one) {
      values.push(one);
    });
  }
  text += ' ORDER BY e.dn_key';
  if (o.limit !== undefined) {
    text += ' LIMIT ?';
    values.push(Number(o.limit));
    if (o.offset !== undefined) {
      text += ' OFFSET ?';
      values.push(Number(o.offset));
    }
  }
  log.debug("Leaving byKeyRows().");
  return ask(name, text, values);
}

// ---------------------------------------------------------------------------
// THE REALMS AND THE PARENTS, BY A LOOSE INDEX SCAN. Each step of the CTE is
// a correlated `MIN()` above the last value, which the optimiser answers with
// one descent of an index whose prefix it is (`sts_ldap_entries_realm`,
// `sts_ldap_entries_parent`), so the cost is the number of distinct values,
// never the rows. A NULL is the end.
// ---------------------------------------------------------------------------

/**
 * Every realm the directory holds an entry of.
 *
 * @param ask - `(name, text, values)` answering rows
 * @returns the realm ids, in order
 */
function realmsOf(ask) {
  log.debug("Entering realmsOf().");
  log.debug("Leaving realmsOf().");
  return ask('realms',
    'WITH RECURSIVE realms(realm) AS (SELECT MIN(realm) FROM ' +
    'sts_ldap_entries UNION ALL SELECT (SELECT MIN(e.realm) FROM ' +
    'sts_ldap_entries AS e WHERE e.realm > r.realm) FROM realms AS r WHERE ' +
    'r.realm IS NOT NULL) SELECT realm FROM realms WHERE realm IS NOT NULL',
    []).then(function (rows) {
    return rows.map(function (row) {
      return String(row.realm);
    });
  });
}

/**
 * A realm's distinct parents, optionally only those that are a base or
 * under it.
 *
 * @param ask - `(name, text, values)` answering rows
 * @param realm - the realm id
 * @param baseKey - a base to keep only the parents at or under, or null
 * @returns the parents, in order
 */
function parentsOf(ask, realm, baseKey) {
  log.debug("Entering parentsOf().");
  const values = [String(realm), String(realm)];
  let keep = '';
  if (baseKey !== null && baseKey !== undefined) {
    const at = under('parent_key', baseKey, true);
    keep = ' AND ' + at.text;
    at.values.forEach(function (one) {
      values.push(one);
    });
  }
  log.debug("Leaving parentsOf().");
  return ask('parents',
    'WITH RECURSIVE parents(parent_key) AS (SELECT MIN(parent_key) FROM ' +
    'sts_ldap_entries WHERE realm = ? UNION ALL SELECT (SELECT ' +
    'MIN(e.parent_key) FROM sts_ldap_entries AS e WHERE e.realm = ? AND ' +
    'e.parent_key > p.parent_key) FROM parents AS p WHERE p.parent_key IS ' +
    'NOT NULL) SELECT parent_key FROM parents WHERE parent_key IS NOT NULL' +
    keep, values).then(function (rows) {
    return rows.map(function (row) {
      return String(row.parent_key);
    });
  });
}

/**
 * One parent's rows after a cursor, at most `limit`, as a UNION branch: the
 * `(realm, parent_key, dn_key)` index's range, in its order.
 *
 * @param columns - the columns, on `e.`
 * @param realm - the realm id
 * @param parent - the parent's key
 * @param after - the cursor
 * @param limit - the most rows, or null for every row
 * @returns `{ text, values }`
 */
function childBranch(columns, realm, parent, after, limit) {
  log.debug("Entering childBranch().");
  const values = [String(realm), String(parent), String(after)];
  let text = '(SELECT ' + columns + ' FROM sts_ldap_entries AS e FORCE ' +
             'INDEX (sts_ldap_entries_parent) WHERE e.realm = ? AND ' +
             'e.parent_key = ? AND e.dn_key > ? ORDER BY e.dn_key';
  if (limit !== null) {
    text += ' LIMIT ?';
    values.push(Number(limit));
  }
  log.debug("Leaving childBranch().");
  return { text: text + ')', values: values };
}

/**
 * The first `limit` rows strictly under a base (and the base itself with
 * `self`), in key order after a cursor: the parents at or under the base,
 * each one's first `limit` rows after the cursor, merged.
 *
 * @param ask - `(name, text, values)` answering rows
 * @param name - the question's name
 * @param columns - the columns, on `e.`, `e.dn_key` among them
 * @param realm - the realm id
 * @param baseKey - the base, not ''
 * @param after - the cursor
 * @param limit - the page size
 * @param self - true to include the base itself
 * @returns the rows
 */
async function subtreeRows(ask, name, columns, realm, baseKey, after, limit,
                           self) {
  log.debug("Entering subtreeRows(). " + name);
  const parents = await parentsOf(ask, realm, baseKey);
  let found = [];
  if (self) {
    found = found.concat(await ask(name + '.self', 'SELECT ' + columns +
      ' FROM sts_ldap_entries AS e WHERE e.realm = ? AND e.dn_key = ? AND ' +
      'e.dn_key > ?', [String(realm), String(baseKey), String(after)]));
  }
  for (let at = 0; at < parents.length; at += PARENTS_PER_STATEMENT) {
    const branches = parents.slice(at, at + PARENTS_PER_STATEMENT)
      .map(function (parent) {
        return childBranch(columns, realm, parent, after, limit);
      });
    const values = [];
    branches.forEach(function (one) {
      one.values.forEach(function (v) {
        values.push(v);
      });
    });
    values.push(Number(limit));
    found = found.concat(await ask(name, 'SELECT * FROM (' +
      branches.map(function (one) {
        return one.text;
      }).join(' UNION ALL ') + ') AS s ORDER BY dn_key LIMIT ?', values));
  }
  found.sort(function (a, b) {
    return a.dn_key < b.dn_key ? -1 : a.dn_key > b.dn_key ? 1 : 0;
  });
  log.debug("Leaving subtreeRows().");
  return found.slice(0, limit);
}

/**
 * A subtree page in either form: the suffix test over the realm's keys for
 * the base '' (PostgreSQL's form, which no caller asks), the parents
 * otherwise.
 *
 * @param ask - `(name, text, values)` answering rows
 * @param name - the question's name
 * @param columns - the columns, on `e.`
 * @param realm - the realm id
 * @param baseKey - the base
 * @param afterKey - the cursor
 * @param limit - the page size, unbounded
 * @param self - true to include the base itself
 * @returns the rows
 */
function subtreePage(ask, name, columns, realm, baseKey, afterKey, limit,
                     self) {
  log.debug("Entering subtreePage(). " + name);
  const n = directoryQueries.pageSize(limit);
  const after = String(afterKey || '');
  if (String(baseKey) === '') {
    const at = under('e.dn_key', '', self);
    log.debug("Leaving subtreePage(). The realm.");
    return ask(name, 'SELECT ' + columns + ' FROM sts_ldap_entries AS e ' +
      'WHERE e.realm = ? AND ' + at.text + ' AND e.dn_key > ? ORDER BY ' +
      'e.dn_key LIMIT ?', [String(realm)].concat(at.values, [after, n]));
  }
  log.debug("Leaving subtreePage().");
  return subtreeRows(ask, name, columns, realm, baseKey, after, n, !!self);
}

/**
 * Whether a holder question has the key table behind it; says once when not.
 *
 * @param name - the attribute name, lower-cased
 * @returns true for an asked name
 */
function asked(name) {
  log.debug("Entering asked().");
  if (directoryQueries.ASKED_ATTRIBUTES.indexOf(name) >= 0) {
    log.debug("Leaving asked(). Asked.");
    return true;
  }
  if (!unindexedNoted.has(name)) {
    unindexedNoted.add(name);
    log.warn('directory_queries_mariadb: the holders of `' + name + '` are ' +
             'asked of the store, and no key row answers for that name — ' +
             'it is answered by a scan of the realm\'s rows. Add it to ' +
             'ASKED_ATTRIBUTES if it is asked on a request or a job (#618).');
  }
  log.debug("Leaving asked(). Not asked.");
  return false;
}

/**
 * The scan form of "holds the attribute", for a name with no key rows.
 *
 * @param name - the attribute name
 * @returns `{ text, values }` over `e.`
 */
function holdsScan(name) {
  log.debug("Entering holdsScan().");
  log.debug("Leaving holdsScan().");
  return { text: 'JSON_CONTAINS(e.attr_names, ?)',
           values: [JSON.stringify(String(name))] };
}

/**
 * The holders of an asked name under a base, as key-table rows: the inner
 * SELECT the holder questions share.
 *
 * @param realm - the realm id
 * @param baseKey - the base
 * @param name - the attribute name
 * @returns `{ text, values }`, ordered by `dn_key`
 */
function holderKeys(realm, baseKey, name) {
  log.debug("Entering holderKeys().");
  const at = under('k.dn_key', baseKey, false);
  log.debug("Leaving holderKeys().");
  return { text: 'FROM sts_ldap_entry_keys AS k WHERE k.realm = ? AND ' +
                 'k.kind = \'attr\' AND k.k = ? AND ' + at.text,
           values: [String(realm), tableKey(name)].concat(at.values) };
}

// ===========================================================================
// THE QUESTIONS, by `directory_queries.js`'s names and arguments.
// ===========================================================================

function byKeys(ask, realm, keys) {
  log.debug("Entering byKeys().");
  const list = (keys || []).map(String);
  if (!list.length) {
    log.debug("Leaving byKeys(). None.");
    return Promise.resolve([]);
  }
  log.debug("Leaving byKeys().");
  return ask('byKeys', 'SELECT ' + COLUMNS + ' FROM sts_ldap_entries AS e ' +
    'WHERE e.realm = ? AND e.dn_key IN (' + marks(list.length) + ') ORDER ' +
    'BY e.dn_key', [String(realm)].concat(list));
}

/**
 * The entries under a container answering to ANY of a list of names, by RDN
 * value or by a `name` key: `byName()` (at most two) and `withNames()`.
 *
 * @param ask - `(name, text, values)` answering rows
 * @param name - the question's name
 * @param realm - the realm id
 * @param parentKey - the container
 * @param names - raw names or `{ key, rdn }`
 * @param limit - the most rows, or null
 * @returns the rows
 */
function namedRows(ask, name, realm, parentKey, names, limit) {
  log.debug("Entering namedRows(). " + name);
  const list = Array.isArray(names) ? names : [];
  if (!list.length) {
    log.debug("Leaving namedRows(). None.");
    return Promise.resolve([]);
  }
  const rdns = list.map(function (one) {
    return one && typeof one === 'object'
      ? String(one.rdn || '')
      : String(one == null ? '' : one).trim().toLowerCase();
  });
  const keys = list.map(function (one) {
    return keyOf(one, 'name', true);
  });
  const values = [String(realm), String(parentKey)].concat(rdns,
    [String(realm)], keys, [String(realm), String(parentKey)]);
  let text = 'SELECT ' + COLUMNS + ' FROM (SELECT dn_key FROM ' +
    'sts_ldap_entries FORCE INDEX (sts_ldap_entries_rdn) WHERE realm = ? ' +
    'AND parent_key = ? AND rdn_value IN (' + marks(rdns.length) + ') UNION ' +
    'SELECT dn_key FROM sts_ldap_entry_keys WHERE realm = ? AND kind = ' +
    '\'name\' AND k IN (' + marks(keys.length) + ')) AS u JOIN ' +
    'sts_ldap_entries AS e ON e.realm = ? AND e.dn_key = u.dn_key WHERE ' +
    'e.parent_key = ? ORDER BY e.dn_key';
  if (limit !== null) {
    text += ' LIMIT ?';
    values.push(Number(limit));
  }
  log.debug("Leaving namedRows().");
  return ask(name, text, values);
}

function byName(ask, realm, parentKey, name) {
  log.debug("Entering byName().");
  log.debug("Leaving byName().");
  return namedRows(ask, 'byName', realm, parentKey, [name], 2);
}

function withNames(ask, realm, parentKey, names) {
  log.debug("Entering withNames().");
  log.debug("Leaving withNames().");
  return namedRows(ask, 'withNames', realm, parentKey, names, null);
}

function byUuid(ask, realm, uuid) {
  log.debug("Entering byUuid().");
  log.debug("Leaving byUuid().");
  return byKeyRows(ask, 'byUuid', { realm: realm, kind: 'uuid',
                                    keys: [keyOf(uuid, 'uuid', true)],
                                    limit: 8 });
}

function withUuids(ask, realm, uuids) {
  log.debug("Entering withUuids().");
  const keys = (Array.isArray(uuids) ? uuids : []).map(function (one) {
    return keyOf(one, 'uuid', true);
  });
  log.debug("Leaving withUuids().");
  return byKeyRows(ask, 'withUuids', { realm: realm, kind: 'uuid',
                                       keys: keys });
}

function byMail(ask, realm, mail, limit) {
  log.debug("Entering byMail().");
  log.debug("Leaving byMail().");
  return byKeyRows(ask, 'byMail', {
    realm: realm, kind: 'mail', keys: [keyOf(mail, 'mail', true)],
    limit: directoryQueries.pageSize(limit) });
}

function byAttribute(ask, realm, attribute, value, limit, parentKey) {
  log.debug("Entering byAttribute().");
  const name = String(attribute).toLowerCase();
  log.debug("Leaving byAttribute().");
  return byKeyRows(ask, 'byAttribute', {
    realm: realm, kind: 'value',
    keys: [keyOf(value, 'attr:' + name, false)],
    where: parentKey ? { text: 'e.parent_key = ?',
                         values: [String(parentKey)] } : undefined,
    limit: directoryQueries.pageSize(limit) });
}

function equalUnder(ask, realm, baseKey, kind, value, limit) {
  log.debug("Entering equalUnder().");
  if (kind !== 'name' && kind !== 'mail') {
    log.debug("Leaving equalUnder(). No such kind.");
    return Promise.reject(new Error('directory_queries: equalUnder has no ' +
                                    'kind ' + String(kind)));
  }
  log.debug("Leaving equalUnder().");
  return byKeyRows(ask, 'equalUnder', {
    realm: realm, kind: kind, keys: [keyOf(value, kind, true)],
    where: under('e.dn_key', baseKey, true),
    limit: directoryQueries.pageSize(limit) });
}

function page(ask, realm, baseKey, afterKey, limit, options) {
  log.debug("Entering page().");
  const o = options || {};
  if (o.oneLevel) {
    const one = childBranch(COLUMNS, realm, baseKey, afterKey || '',
                            directoryQueries.pageSize(limit));
    log.debug("Leaving page(). One level.");
    return ask('page', one.text.slice(1, -1), one.values);
  }
  log.debug("Leaving page().");
  return subtreePage(ask, 'page', COLUMNS, realm, baseKey, afterKey, limit,
                     !!o.self);
}

function count(ask, realm, baseKey) {
  log.debug("Entering count().");
  log.debug("Leaving count().");
  return ask('count', 'SELECT CAST(COALESCE(SUM(n), 0) AS SIGNED) AS n FROM ' +
    'sts_ldap_counts WHERE realm = ? AND base_key = ? AND attribute = \'\'',
    [String(realm), String(baseKey || '')]);
}

function countHolding(ask, realm, baseKey, attribute) {
  log.debug("Entering countHolding().");
  const name = String(attribute).toLowerCase();
  if (directoryQueries.COUNTED_ATTRIBUTES.indexOf(name) >= 0) {
    log.debug("Leaving countHolding(). Counted.");
    return ask('countHolding', 'SELECT CAST(COALESCE(SUM(CASE WHEN ' +
      'attribute = \'\' THEN n ELSE 0 END), 0) AS SIGNED) AS n, ' +
      'CAST(COALESCE(SUM(CASE WHEN attribute = ? THEN n ELSE 0 END), 0) AS ' +
      'SIGNED) AS holding FROM sts_ldap_counts WHERE realm = ? AND ' +
      'base_key = ? AND attribute IN (\'\', ?)',
      [name, String(realm), String(baseKey), name]);
  }
  const at = under('e.dn_key', baseKey, false);
  const holds = holdsScan(name);
  log.debug("Leaving countHolding(). Counted by a scan.");
  return ask('countHolding', 'SELECT CAST(COUNT(*) AS SIGNED) AS n, ' +
    'CAST(COALESCE(SUM(' + holds.text + '), 0) AS SIGNED) AS holding FROM ' +
    'sts_ldap_entries AS e WHERE e.realm = ? AND ' + at.text,
    holds.values.concat([String(realm)], at.values));
}

function hasChild(ask, realm, key) {
  log.debug("Entering hasChild().");
  log.debug("Leaving hasChild().");
  return ask('hasChild', 'SELECT 1 AS one FROM sts_ldap_entries WHERE realm ' +
    '= ? AND parent_key = ? LIMIT 1', [String(realm), String(key)]);
}

/**
 * The holders of an attribute under a base, a page in key order: after a
 * cursor (`withAttribute`) or past an offset (`withAttributeAt`).
 *
 * @param ask - `(name, text, values)` answering rows
 * @param name - the question's name
 * @param o - `{ realm, baseKey, attribute, after?, offset?, limit }`
 * @returns the rows
 */
function holderRows(ask, name, o) {
  log.debug("Entering holderRows(). " + name);
  const attr = String(o.attribute).toLowerCase();
  const tail = (o.offset !== undefined ? ' LIMIT ? OFFSET ?' : ' LIMIT ?');
  const tailValues = o.offset !== undefined
    ? [Number(o.limit), Number(o.offset)] : [Number(o.limit)];
  if (asked(attr)) {
    const keys = holderKeys(o.realm, o.baseKey, attr);
    const values = keys.values.slice();
    let inner = 'SELECT k.dn_key ' + keys.text;
    if (o.after !== undefined) {
      inner += ' AND k.dn_key > ?';
      values.push(String(o.after));
    }
    inner += ' ORDER BY k.dn_key' + tail;
    log.debug("Leaving holderRows(). By the key rows.");
    return ask(name, 'SELECT ' + COLUMNS + ' FROM (' + inner + ') AS u ' +
      'JOIN sts_ldap_entries AS e ON e.realm = ? AND e.dn_key = u.dn_key ' +
      'ORDER BY e.dn_key', values.concat(tailValues, [String(o.realm)]));
  }
  const at = under('e.dn_key', o.baseKey, false);
  const holds = holdsScan(attr);
  const values = [String(o.realm)].concat(at.values, holds.values);
  let text = 'SELECT ' + COLUMNS + ' FROM sts_ldap_entries AS e WHERE ' +
             'e.realm = ? AND ' + at.text + ' AND ' + holds.text;
  if (o.after !== undefined) {
    text += ' AND e.dn_key > ?';
    values.push(String(o.after));
  }
  log.debug("Leaving holderRows(). By a scan.");
  return ask(name, text + ' ORDER BY e.dn_key' + tail,
             values.concat(tailValues));
}

function withAttribute(ask, realm, baseKey, attribute, afterKey, limit) {
  log.debug("Entering withAttribute().");
  log.debug("Leaving withAttribute().");
  return holderRows(ask, 'withAttribute', {
    realm: realm, baseKey: baseKey, attribute: attribute,
    after: String(afterKey || ''), limit: directoryQueries.pageSize(limit) });
}

function withAttributeAt(ask, realm, baseKey, attribute, offset, limit) {
  log.debug("Entering withAttributeAt().");
  log.debug("Leaving withAttributeAt().");
  return holderRows(ask, 'withAttributeAt', {
    realm: realm, baseKey: baseKey, attribute: attribute,
    offset: Math.max(0, Math.floor(Number(offset) || 0)),
    limit: directoryQueries.pageSize(limit) });
}

/**
 * How many entries under a base hold an attribute, counted no further than
 * `most` when it is given.
 *
 * @param ask - `(name, text, values)` answering rows
 * @param name - the question's name
 * @param realm - the realm id
 * @param baseKey - the base
 * @param attribute - the attribute name
 * @param most - the bound, or null
 * @returns the rows: one, `n`
 */
function holderCount(ask, name, realm, baseKey, attribute, most) {
  log.debug("Entering holderCount(). " + name);
  const attr = String(attribute).toLowerCase();
  let inner;
  let values;
  if (asked(attr)) {
    const keys = holderKeys(realm, baseKey, attr);
    inner = 'SELECT 1 AS one ' + keys.text;
    values = keys.values.slice();
  } else {
    const at = under('e.dn_key', baseKey, false);
    const holds = holdsScan(attr);
    inner = 'SELECT 1 AS one FROM sts_ldap_entries AS e WHERE e.realm = ? ' +
            'AND ' + at.text + ' AND ' + holds.text;
    values = [String(realm)].concat(at.values, holds.values);
  }
  if (most !== null) {
    inner += ' LIMIT ?';
    values.push(Math.max(1, Math.floor(Number(most) || 0)));
  }
  log.debug("Leaving holderCount().");
  return ask(name, 'SELECT CAST(COUNT(*) AS SIGNED) AS n FROM (' + inner +
             ') AS held', values);
}

function countWithAttribute(ask, realm, baseKey, attribute) {
  log.debug("Entering countWithAttribute().");
  log.debug("Leaving countWithAttribute().");
  return holderCount(ask, 'countWithAttribute', realm, baseKey, attribute,
                     null);
}

function countWithAttributeUpTo(ask, realm, baseKey, attribute, limit) {
  log.debug("Entering countWithAttributeUpTo().");
  log.debug("Leaving countWithAttributeUpTo().");
  return holderCount(ask, 'countWithAttributeUpTo', realm, baseKey,
                     attribute, limit);
}

function anyWithAttribute(ask, realm, attribute) {
  log.debug("Entering anyWithAttribute().");
  const name = String(attribute).toLowerCase();
  if (directoryQueries.COUNTED_ATTRIBUTES.indexOf(name) >= 0) {
    log.debug("Leaving anyWithAttribute(). Counted.");
    return ask('anyWithAttribute', 'SELECT 1 AS one FROM (SELECT SUM(n) AS ' +
      't FROM sts_ldap_counts WHERE realm = ? AND base_key = \'\' AND ' +
      'attribute = ?) AS s WHERE s.t > 0', [String(realm), name]);
  }
  if (asked(name)) {
    log.debug("Leaving anyWithAttribute(). By the key rows.");
    return ask('anyWithAttribute', 'SELECT 1 AS one FROM ' +
      'sts_ldap_entry_keys WHERE realm = ? AND kind = \'attr\' AND k = ? ' +
      'LIMIT 1', [String(realm), tableKey(name)]);
  }
  const holds = holdsScan(name);
  log.debug("Leaving anyWithAttribute(). By a scan.");
  return ask('anyWithAttribute', 'SELECT 1 AS one FROM sts_ldap_entries AS ' +
    'e WHERE e.realm = ? AND ' + holds.text + ' LIMIT 1',
    [String(realm)].concat(holds.values));
}

function classesUnder(ask, realm, baseKey, classes) {
  log.debug("Entering classesUnder().");
  const keys = (classes || []).map(function (one) {
    return keyOf(one, 'class', true);
  });
  log.debug("Leaving classesUnder().");
  return byKeyRows(ask, 'classesUnder', {
    realm: realm, kind: 'class', keys: keys,
    where: under('e.dn_key', baseKey, false) });
}

/**
 * The entries of a parent created or changed in a span (`timeBetween()`).
 *
 * @param ask - `(name, text, values)` answering rows
 * @param name - the question's name
 * @param column - `created_at` or `modified_at`
 * @param args - realm, parent, lo, hi, limit
 * @returns the rows
 */
function timeBetween(ask, name, column, args) {
  log.debug("Entering timeBetween(). " + name);
  log.debug("Leaving timeBetween().");
  return ask(name, 'SELECT ' + COLUMNS + ' FROM sts_ldap_entries AS e ' +
    'WHERE e.realm = ? AND e.parent_key = ? AND e.parent_key LIKE ' +
    '\'ou=users,%\' AND e.' + column + ' >= ? AND e.' + column + ' < ? ' +
    'ORDER BY e.' + column + ', e.dn_key LIMIT ?',
    [String(args[0]), String(args[1]), String(args[2] || ''),
     String(args[3] || '99999999999999Z'),
     directoryQueries.pageSize(args[4])]);
}

function createdBetween(ask, realm, parentKey, lo, hi, limit) {
  log.debug("Entering createdBetween().");
  log.debug("Leaving createdBetween().");
  return timeBetween(ask, 'createdBetween', 'created_at',
                     [realm, parentKey, lo, hi, limit]);
}

function modifiedBetween(ask, realm, parentKey, lo, hi, limit) {
  log.debug("Entering modifiedBetween().");
  log.debug("Leaving modifiedBetween().");
  return timeBetween(ask, 'modifiedBetween', 'modified_at',
                     [realm, parentKey, lo, hi, limit]);
}

function namesUnder(ask, realm, baseKey, afterKey, limit) {
  log.debug("Entering namesUnder().");
  log.debug("Leaving namesUnder().");
  return subtreePage(ask, 'namesUnder', 'e.dn_key, e.dn, e.origin, e.attrs',
                     realm, baseKey, afterKey, limit, false);
}

function keysUnder(ask, realm, baseKey, afterKey, limit) {
  log.debug("Entering keysUnder().");
  log.debug("Leaving keysUnder().");
  return subtreePage(ask, 'keysUnder', 'e.dn_key, e.dn', realm, baseKey,
                     afterKey, limit, false);
}

/**
 * The origin condition over `e.`, and its values.
 *
 * @param origin - an origin, `unstated`, or '' for any
 * @returns `{ text, values }`, the text '' or starting ` AND`
 */
function originWhere(origin) {
  log.debug("Entering originWhere().");
  const wanted = origin === undefined || origin === null ? '' :
    String(origin);
  log.debug("Leaving originWhere().");
  if (!wanted) {
    return { text: '', values: [] };
  }
  if (wanted === 'unstated') {
    return { text: ' AND (e.origin IS NULL OR e.origin = \'\')', values: [] };
  }
  return { text: ' AND e.origin = ?', values: [wanted] };
}

function realmPage(ask, realm, afterKey, limit, options) {
  log.debug("Entering realmPage().");
  const o = options || {};
  const origin = originWhere(o.origin);
  log.debug("Leaving realmPage().");
  return ask('realmPage', 'SELECT ' + COLUMNS + ' FROM sts_ldap_entries AS ' +
    'e WHERE e.realm = ? AND e.dn_key > ?' + origin.text + ' ORDER BY ' +
    'e.dn_key LIMIT ? OFFSET ?',
    [String(realm), String(afterKey || '')].concat(origin.values,
      [directoryQueries.pageSize(limit),
       Math.max(0, Math.floor(Number(o.offset) || 0))]));
}

function realmCount(ask, realm, origin) {
  log.debug("Entering realmCount().");
  const where = originWhere(origin);
  log.debug("Leaving realmCount().");
  return ask('realmCount', 'SELECT CAST(COUNT(*) AS SIGNED) AS n FROM ' +
    'sts_ldap_entries AS e WHERE e.realm = ?' + where.text,
    [String(realm)].concat(where.values));
}

function originCounts(ask, realm) {
  log.debug("Entering originCounts().");
  log.debug("Leaving originCounts().");
  return ask('originCounts', 'SELECT COALESCE(NULLIF(origin, \'\'), ' +
    '\'unstated\') AS origin, CAST(COUNT(*) AS SIGNED) AS n FROM ' +
    'sts_ldap_entries WHERE realm = ? GROUP BY 1', [String(realm)]);
}

/**
 * Every entry except those strictly under the windowed containers: the
 * realms, each realm's parents, and every kept parent's rows a page at a
 * time — `residentOnly()`'s rows in its order, never a test of every row.
 * Asked only by a windowed worker, which MariaDB refuses; kept so the
 * question has one answer on either engine.
 *
 * @param ask - `(name, text, values)` answering rows
 * @param windowed - `[{ realm, baseKey }]`
 * @returns the rows
 */
async function residentOnly(ask, windowed) {
  log.debug("Entering residentOnly().");
  const list = windowed || [];
  const out = [];
  const realms = await realmsOf(ask);
  for (const realm of realms) {
    const containers = list.filter(function (one) {
      return String(one.realm) === realm;
    }).map(function (one) {
      return String(one.baseKey);
    });
    const parents = await parentsOf(ask, realm, null);
    for (const parent of parents) {
      const windowedHere = containers.some(function (c) {
        return parent === c || parent.slice(-(c.length + 1)) === ',' + c;
      });
      if (windowedHere) {
        continue;
      }
      let after = '';
      for (;;) {
        const one = childBranch(COLUMNS, realm, parent, after,
                                directoryQueries.MAX_PAGE);
        const rows = await ask('residentOnly', one.text.slice(1, -1),
                               one.values);
        rows.forEach(function (row) {
          out.push(row);
        });
        if (rows.length < directoryQueries.MAX_PAGE) {
          break;
        }
        after = rows[rows.length - 1].dn_key;
      }
    }
  }
  out.sort(function (a, b) {
    if (a.realm !== b.realm) {
      return a.realm < b.realm ? -1 : 1;
    }
    return a.dn_key < b.dn_key ? -1 : a.dn_key > b.dn_key ? 1 : 0;
  });
  log.debug("Leaving residentOnly(). " + out.length + ".");
  return out;
}

/**
 * The walk and the skip of a numbered page, as `directory_queries.js` caps
 * them: the walk reads at most 100,000 rows past the cursor.
 *
 * @param offset - rows to skip
 * @param limit - the page size
 * @returns `{ take, skip }`, `take` the LIMIT after the OFFSET
 */
function walkOf(offset, limit) {
  log.debug("Entering walkOf().");
  const skip = Math.max(0, Math.min(100000, Math.floor(Number(offset) || 0)));
  const walk = Math.min(skip + directoryQueries.pageSize(limit), 100000);
  log.debug("Leaving walkOf().");
  return { take: Math.max(0, walk - skip), skip: skip };
}

function rdnPage(ask, realm, parentKey, afterRdn, limit, options) {
  log.debug("Entering rdnPage().");
  const o = options || {};
  const needle = String(o.needle || '').toLowerCase();
  const w = walkOf(o.offset, limit);
  if (!w.take) {
    log.debug("Leaving rdnPage(). Past the walk.");
    return Promise.resolve([]);
  }
  const values = [String(realm), String(parentKey),
                  String(afterRdn || '').toLowerCase()];
  let filter = '';
  if (needle) {
    // LOCATE, not LIKE, so the needle cannot be a wildcard; and only for a
    // needle, because an empty one is found everywhere.
    filter = ' AND LOCATE(?, e.rdn_value) > 0';
    values.push(needle);
  }
  log.debug("Leaving rdnPage().");
  return ask('rdnPage', 'SELECT ' + COLUMNS + ', e.rdn_value FROM ' +
    'sts_ldap_entries AS e FORCE INDEX (sts_ldap_entries_rdn) WHERE e.realm ' +
    '= ? AND e.parent_key = ? AND e.rdn_value > ?' + filter + ' ORDER BY ' +
    'e.rdn_value LIMIT ? OFFSET ?', values.concat([w.take, w.skip]));
}

function rdnCount(ask, realm, parentKey, needle) {
  log.debug("Entering rdnCount().");
  const wanted = String(needle || '').toLowerCase();
  const values = [String(realm), String(parentKey)];
  let filter = '';
  if (wanted) {
    filter = ' AND LOCATE(?, rdn_value) > 0';
    values.push(wanted);
  }
  log.debug("Leaving rdnCount().");
  return ask('rdnCount', 'SELECT CAST(COUNT(*) AS SIGNED) AS n FROM ' +
    'sts_ldap_entries WHERE realm = ? AND parent_key = ?' + filter, values);
}

function containerPage(ask, realm, parentKey, offset, limit) {
  log.debug("Entering containerPage().");
  const w = walkOf(offset, limit);
  if (!w.take) {
    log.debug("Leaving containerPage(). Past the walk.");
    return Promise.resolve([]);
  }
  log.debug("Leaving containerPage().");
  return ask('containerPage', 'SELECT ' + COLUMNS + ' FROM sts_ldap_entries ' +
    'AS e FORCE INDEX (sts_ldap_entries_parent) WHERE e.realm = ? AND ' +
    'e.parent_key = ? AND e.dn_key > \'\' ORDER BY e.dn_key LIMIT ? OFFSET ?',
    [String(realm), String(parentKey), w.take, w.skip]);
}

function uidContains(ask, realm, parentKey, needle, limit) {
  log.debug("Entering uidContains().");
  const wanted = String(needle || '').toLowerCase();
  log.debug("Leaving uidContains().");
  // `'\\'` in the text is one backslash: NO_BACKSLASH_ESCAPES is off.
  return ask('uidContains', 'SELECT ' + COLUMNS + ' FROM sts_ldap_entries ' +
    'AS e WHERE e.realm = ? AND e.parent_key = ? AND e.parent_key LIKE ' +
    '\'ou=users,%\' AND e.rdn_value LIKE ? ESCAPE \'\\\\\' LIMIT ?',
    [String(realm), String(parentKey),
     '%' + directoryQueries.likeEscaped(wanted) + '%',
     directoryQueries.pageSize(limit)]);
}

// The questions by name: `directory_queries.QUERIES`' names, each the same
// arguments after `ask`.
const QUERIES = {
  byKeys: byKeys,
  byName: byName,
  byUuid: byUuid,
  withUuids: withUuids,
  byMail: byMail,
  byAttribute: byAttribute,
  equalUnder: equalUnder,
  page: page,
  count: count,
  countHolding: countHolding,
  hasChild: hasChild,
  withAttribute: withAttribute,
  countWithAttribute: countWithAttribute,
  countWithAttributeUpTo: countWithAttributeUpTo,
  withAttributeAt: withAttributeAt,
  withNames: withNames,
  createdBetween: createdBetween,
  modifiedBetween: modifiedBetween,
  anyWithAttribute: anyWithAttribute,
  classesUnder: classesUnder,
  namesUnder: namesUnder,
  realmPage: realmPage,
  realmCount: realmCount,
  originCounts: originCounts,
  keysUnder: keysUnder,
  residentOnly: residentOnly,
  rdnPage: rdnPage,
  rdnCount: rdnCount,
  containerPage: containerPage,
  uidContains: uidContains
};

/**
 * Asks a named question.
 *
 * @param ask - `(name, text, values)` answering a promise of rows
 * @param name - one of the names in `QUERIES`
 * @param args - its arguments, in order, keyed by `directory_codec.keyArgs()`
 * @returns a promise of the rows, for `directory_queries.answerOf()`
 */
function run(ask, name, args) {
  log.debug("Entering run(). " + name);
  const f = Object.prototype.hasOwnProperty.call(QUERIES, name)
    ? QUERIES[name] : null;
  if (!f) {
    log.debug("Leaving run(). Unknown.");
    return Promise.reject(new Error('directory_queries: no query called ' +
                                    String(name)));
  }
  log.debug("Leaving run().");
  return Promise.resolve().then(function () {
    return f.apply(null, [ask].concat(Array.isArray(args) ? args : []));
  });
}

module.exports = {
  COLUMNS: COLUMNS,
  KEY_LIMIT: KEY_LIMIT,
  KINDS: KINDS,
  QUERIES: QUERIES,
  run: run,
  tableKey: tableKey,
  marks: marks,
  realmsOf: realmsOf,
  parentsOf: parentsOf
};
