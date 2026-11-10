// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_entry_reads.js
//
// ---------------------------------------------------------------------------
// A DIRECTORY ATTRIBUTE IS READ THROUGH THE CONCEPT THAT DECLARES IT (#1579).
//
// `models/domain/` says what each attribute of an entry means, and
// `common/domain_map.ts` reads an entry by it: `fromEntry()` for a concept,
// `fieldOf()` for one field. This holds the service to that. It walks every
// service source outside the store and fails on a read of a MODELLED
// attribute by its LDAP name — `entry.attributes.mail`, `attrs.entryuuid`,
// `first('stsMailVerifyToken')`, `valuesOf(row, 'oauthClientId')` — unless
// the file and the name are in EXCEPTIONS below, each with the reason no
// concept field can say it. A new exception is argued there, in the
// module at the read, and in models/CLAUDE.md.
//
// What is NOT walked, and why:
//   * the store: `ldap/ldap_server.js`, `ldap/directory_*.ts` and
//     `persistence/`, which hold entries by name because that is what a
//     directory is;
//   * the browser bundles (`web_*.ts`): they read an API answer, never an
//     entry, and the answer's shape is the API model's;
//   * the generated classes, the model's own tools and importers, and the
//     tests.
//
// It also asserts `DomainMap.fieldOf()` against `fromEntry()`, which every
// read here was moved onto.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'model_entry_reads',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');

// Directories that are not this service's source.
const SKIP_DIRS = ['node_modules', 'tests', 'models', 'rust', 'deploy',
  'companion', 'docs', 'types', 'postgres', 'mariadb', 'xacml-pep',
  'openbao', 'icap-clamav', 'apidocs', '.git', 'embedded', 'node-ldapjs'];

// The store and what only describes the model.
const SKIP_FILES = [
  'ldap/ldap_server.js',
  'common/domain_classes.ts',
  'common/domain_map.ts',
  'common/directory_model.ts',
  'common/directory_model_catalog.ts',
  'common/model_emit.ts',
  'common/postgres_import.ts',
  'common/mariadb_import.ts'
];

// THE ARGUED EXCEPTIONS: a file, the modelled names it reads by name, and
// why. `*` is every name, for a module whose reads are a table's.
const EXCEPTIONS = {
  'common/applications.js': {
    names: '*',
    why: 'the application register: its codec turns an entry into the ' +
      'record its SCHEMA (the model\'s generated table) describes and back, ' +
      'and a concept is read-only'
  },
  'common/cell_rehome.ts': {
    names: '*',
    why: 'moves a whole entry between cells, rewriting the attributes that ' +
      'cannot move as they are'
  },
  'common/cell_sessions.ts': {
    names: ['memberOf'],
    why: 'writes memberOf onto a projection and refuses it on a write; ' +
      'neither is a read'
  },
  'scim/scim.ts': {
    names: ['preferredLanguage', 'manager', 'federationLink', 'member'],
    why: 'a SCIM request converted to the attributes it writes, before it ' +
      'is an entry'
  },
  'spiffe/spiffe_registry.ts': {
    names: '*',
    why: 'the registration and agent entries it writes, built by name'
  },
  'common/attribute_policy.ts': {
    names: ['cn', 'givenName', 'sn', 'stsAttributeSingleValued'],
    why: 'a write body read by its first non-empty value, and a flag whose ' +
      'unreadable value must read as multi-valued, which the concept leaves ' +
      'out'
  },
  'report/sources.ts': {
    names: ['mail', 'objectClass'],
    why: 'every address an index found the entry by, and the classes the ' +
      'model states by @entry rather than as an attribute'
  },
  'scim/scim_map.ts': {
    names: ['scimExternalId'],
    why: 'written onto a group, which no group object declares'
  },
  'common/certificate_pins.ts': {
    names: '*',
    why: 'the audit reports each pin as <application> <attribute>, so the ' +
      'attribute is the answer'
  },
  'gnap/gnap_subject.ts': {
    names: ['telephoneNumber'],
    why: 'the claim catalogue\'s values, which an attribute source may ' +
      'supply as well as the entry; a concept reads only the entry'
  },
  'scim/scim_client.ts': {
    names: ['entryDN'],
    why: 'builds the attribute map a SCIM filter is matched against'
  }
};

// Words too common to be told from an attribute in a call: a quoted `id` or
// `name` is a JSON member, an XML attribute or a field far more often.
const GENERIC = ['id', 'name', 'key', 'kind', 'role', 'type', 'value',
  'label', 'status', 'owner', 'title', 'source', 'realm', 'host', 'info',
  'description'];

// The calls that read an attribute by name, with a modelled name quoted in
// them: `first('mail')`, `valuesOf(row, 'oauthClientId')`.
const READERS = '(?:first|firstValue|firstOf|firstFieldValue|valuesOf|' +
  'valuesAt|listOf|allValues|one|attr|attribute|attributeOf|reportAttr|' +
  'reportAttrList|nonEmpty|fieldValues|fieldOf)';

/**
 * Every attribute name the directory objects and the concepts declare.
 *
 * @returns lower-cased name to canonical name
 */
function modelledNames() {
  log.debug("Entering modelledNames().");
  const names = new Map();
  ['directory', 'domain'].forEach(function (dir) {
    const where = path.join(ROOT, 'models', dir);
    fs.readdirSync(where).filter(function (one) {
      return one.endsWith('.tsp');
    }).forEach(function (file) {
      const text = fs.readFileSync(path.join(where, file), 'utf8');
      const patterns = dir === 'directory'
        ? [/^\s+`?([A-Za-z][A-Za-z0-9]*)`?\??:/gm]
        : [/attr: "([A-Za-z][A-Za-z0-9-]*)"/g];
      patterns.forEach(function (re) {
        let m = re.exec(text);
        while (m) {
          names.set(m[1].toLowerCase(), m[1]);
          m = re.exec(text);
        }
      });
    });
  });
  log.debug("Leaving modelledNames(). " + names.size);
  return names;
}

/**
 * The browser bundles an image build writes, as `build-typescript.sh`'s
 * `bundle_surface` lines name them: built from the `web_*.ts` this does not
 * walk, and no source.
 *
 * @returns the paths
 */
function bundles() {
  log.debug("Entering bundles().");
  const script = fs.readFileSync(path.join(ROOT, 'build-typescript.sh'),
    'utf8').replace(/\\\n/g, ' ');
  const out = new Set();
  script.split('\n').filter(function (line) {
    return /^bundle_surface /.test(line);
  }).forEach(function (line) {
    (line.match(/\S+\.js\b/g) || []).forEach(function (one) {
      out.add(one);
    });
  });
  log.debug("Leaving bundles(). " + out.size);
  return out;
}

/**
 * Every service source to walk, relative to the root. A compiled `.js`
 * beside its `.ts` is the same file, and only the `.ts` is walked.
 *
 * @returns the paths
 */
function sources() {
  log.debug("Entering sources().");
  const built = bundles();
  const out = [];
  const walk = function (dir) {
    fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })
      .forEach(function (one) {
        const rel = dir ? dir + '/' + one.name : one.name;
        if (one.isDirectory()) {
          if (SKIP_DIRS.indexOf(one.name) < 0) {
            walk(rel);
          }
          return;
        }
        if (!/\.(ts|js)$/.test(one.name) || /\.d\.ts$/.test(one.name) ||
            /^web_/.test(one.name) || SKIP_FILES.indexOf(rel) >= 0 ||
            /^persistence\//.test(rel) || /^ldap\/directory_/.test(rel) ||
            built.has(rel)) {
          return;
        }
        if (/\.js$/.test(one.name) &&
            fs.existsSync(path.join(ROOT, rel.replace(/\.js$/, '.ts')))) {
          return;
        }
        out.push(rel);
      });
  };
  walk('');
  log.debug("Leaving sources(). " + out.length);
  return out;
}

/**
 * The by-name reads of modelled attributes in one line of source.
 *
 * @param line - the line, its comment already removed
 * @param names - from `modelledNames()`
 * @returns the canonical names read
 */
function readsIn(line, names) {
  log.debug("Entering readsIn().");
  const found = [];
  const note = function (raw, loweredOnly) {
    const name = String(raw).split(';')[0];
    const canonical = names.get(name.toLowerCase());
    if (!canonical || GENERIC.indexOf(canonical) >= 0) {
      return;
    }
    // A lower-cased spelling of a camel-case name is a store's key, and
    // nothing else is spelt so; a name already all lower case (`mail`)
    // is too common a word to be one on its own.
    if (loweredOnly && (canonical === name || name !== name.toLowerCase())) {
      return;
    }
    found.push(canonical);
  };
  // A member read is looked for with the strings blanked, so that a URL
  // or a sentence naming an attribute is not a read of it; a call is
  // looked for in the line as written, since its name is a string.
  const bare = line.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g,
    "''");
  const patterns = [
    [/\.attributes\s*\.\s*([A-Za-z][A-Za-z0-9]*)/g, false, bare],
    [/\.attributes\s*\[\s*['"]([A-Za-z][A-Za-z0-9;-]*)['"]\s*\]/g, false,
      line],
    [/\.([a-z][a-z0-9]*)\b(?!\s*\()/g, true, bare],
    [new RegExp('\\b' + READERS + '\\(\\s*(?:[^,()\'"]+,\\s*)?[\'"]' +
      '([A-Za-z][A-Za-z0-9;-]*)[\'"]', 'g'), false, line]
  ];
  patterns.forEach(function (row) {
    const re = row[0];
    let m = re.exec(row[2]);
    while (m) {
      note(m[1], row[1]);
      m = re.exec(row[2]);
    }
  });
  log.debug("Leaving readsIn().");
  return found;
}

/**
 * A line without its `//` comment, or '' for a comment line.
 *
 * @param line - the line
 * @returns the code
 */
function codeOf(line) {
  log.debug("Entering codeOf().");
  if (/^\s*(\/\/|\*|\/\*)/.test(line)) {
    log.debug("Leaving codeOf(). A comment.");
    return '';
  }
  const at = line.indexOf(' // ');
  log.debug("Leaving codeOf().");
  return at >= 0 ? line.slice(0, at) : line;
}

/**
 * Walks the service and fails on a by-name read nobody argued.
 *
 * @param t - the assertions
 */
function walkSources(t) {
  log.debug("Entering walkSources().");
  const names = modelledNames();
  t.check(names.size > 500, 'the model declares the directory\'s names',
    String(names.size));
  const files = sources();
  t.check(files.length > 300, 'the service sources are found',
    String(files.length));
  const unargued = [];
  const used = new Set();
  files.forEach(function (rel) {
    const allowed = EXCEPTIONS[rel];
    fs.readFileSync(path.join(ROOT, rel), 'utf8').split('\n')
      .forEach(function (line, i) {
        readsIn(codeOf(line), names).forEach(function (name) {
          if (allowed && (allowed.names === '*' ||
              allowed.names.indexOf(name) >= 0)) {
            used.add(rel);
            return;
          }
          unargued.push(rel + ':' + (i + 1) + ' reads ' + name);
        });
      });
  });
  t.check(unargued.length === 0, 'no modelled attribute is read by name ' +
    'outside the store and the argued exceptions; read it through its ' +
    'concept (DomainMap.fieldOf or the class in common/domain_classes.ts), ' +
    'or argue it in EXCEPTIONS here, at the read and in models/CLAUDE.md',
    unargued.slice(0, 40).join('\n'));
  Object.keys(EXCEPTIONS).forEach(function (rel) {
    t.check(used.has(rel), 'the exception for ' + rel + ' is still needed',
      EXCEPTIONS[rel].why);
  });
  log.debug("Leaving walkSources().");
}

/**
 * `fieldOf()` reads a field exactly as `fromEntry()` does.
 *
 * @param t - the assertions
 */
function fieldOf(t) {
  log.debug("Entering fieldOf().");
  const DomainMap = require('../common/domain_map');
  const entry = { uid: ['alice'], mail: ['a@example.com', 'b@example.com'],
    entryuuid: ['00000000-0000-4000-8000-000000000001'],
    pwdaccountlockedtime: ['20260101000000Z'],
    stsmailverifytoken: ['hash'] };
  t.equal(DomainMap.fieldOf('User', 'username', entry),
    DomainMap.fromEntry('User', entry).username,
    'one field is what the concept holds');
  t.equal(DomainMap.fieldOf('User', 'email', entry), 'a@example.com',
    'transform first takes the first value');
  t.equal(DomainMap.fieldOf('DirectoryEntry', 'entryUuid', entry),
    '00000000-0000-4000-8000-000000000001',
    'any entry\'s entryUUID is DirectoryEntry\'s');
  t.equal(DomainMap.fieldOf('Credential', 'lockedSince', entry),
    '20260101000000Z', 'a lock is the Credential\'s');
  t.equal(DomainMap.fieldOf('User', 'displayName', entry), undefined,
    'an attribute the entry lacks is absent');
  t.equal(DomainMap.fieldOf('Credential', 'mailVerifyToken', entry), 'hash',
    'a secret field is answered when it is the field named');
  t.equal(DomainMap.fromEntry('Credential', entry).mailVerifyToken,
    undefined, 'and is still left out of the concept unless asked for');
  let threw = false;
  try {
    DomainMap.fieldOf('User', 'realm', entry);
  } catch (e) {
    log.debug("Caught in fieldOf(): " + ((e && e.message) || e));
    threw = /No stored field/.test(String(e && e.message));
  }
  t.check(threw, 'a derived field has no attribute to read');
  log.debug("Leaving fieldOf().");
}

async function run(t) {
  log.debug("Entering run().");
  fieldOf(t);
  walkSources(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_entry_reads',
  describe: 'a directory attribute is read through the concept that ' +
    'declares it (#1579)',
  run: run
};
