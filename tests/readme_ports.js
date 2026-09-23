'use strict';
//
// File: readme_ports.js
//
// ===========================================================================
// THE README'S PORTS TABLE, AGAINST THE TABLE THAT DECIDES THE PORTS.
//
// `README.md` grew a *The ports* section on 2026-09-07 — ten bindings, their
// settings, their environment variables. It is the most useful kind of table
// and the kind this repository has already been bitten by twice: a job count
// written into the root CLAUDE.md beside `tests/vendored/MANIFEST.js` went
// stale twice, which is why tests/CLAUDE.md now says "`MANIFEST.js` IS THE
// COUNT" and writes no number of its own.
//
// A ports table cannot be read off the running router the way
// `/admin/sts-metadata` reads its endpoint list, and that is the whole reason
// this file exists: **a raw socket registers no route, so the one mechanism
// this service already has for keeping a list honest cannot see any of the
// nine numbers in that table.** What it can be held to is `config.js`'s
// SETTINGS, which is where every one of them is actually decided.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Every claim here is a comparison between two FILES in this repository —
// `README.md` and `common/config.js` — which no running service could be
// asked. It is the same shape as `postgres_schema.js` (a SQL script against
// the driver) and `xacml_pep.js`'s COPY-set check (a Dockerfile against a
// module list). Nothing here binds a port or reads one.
//
// ---------------------------------------------------------------------------
// IT CHECKS BOTH DIRECTIONS, because only one of them is the obvious one.
//
//   * a port setting with no row  — a listener added and undocumented, which
//     is the failure people expect
//   * a row naming no setting     — what a RENAME produces, and the one that
//     goes unnoticed: the table still looks complete
//
// That is `sts_metadata.js`'s drift report, applied to a table that cannot be
// generated. The DEFAULTS are compared too: a row that names the right setting
// and the wrong number is worse than a missing row, because a reader acts on
// it.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run, or the
// defaults it reads would be that file's rather than the table's.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const config = require('../common/config');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'readme_ports',
  level: process.env.LOG_LEVEL || 'info' });

const README = path.join(__dirname, '..', 'README.md');

// Ports on OTHER hosts that this service connects to, named by a setting
// whose key happens to end in `Port`. Listed by name, each with its reason
// where it is read, because a rule on the shape of the key cannot tell a
// listener from a destination.
const DIALLED = ['mail.smtpPort'];

// The settings that name something this service BINDS. A port or a socket
// path, and nothing else — `spiffe.trustLocalSocket` is a policy about the
// socket rather than the socket, so the filter is on the shape of the VALUE as
// well as on the name.
function bindingSettings() {
  log.debug("Entering bindingSettings().");
  log.debug("Leaving bindingSettings().");
  return config.SETTINGS.filter(function (s) {
    // A port whose DEFAULT is 0 is not a binding: `pki.distributionPort` and
    // `pki.distributionLdapPort` are ports this service WRITES into a
    // certificate, and 0 is how they say "the listener's own".
    // A port this service DIALS is not a binding either: `mail.smtpPort`
    // (#63) is the RELAY's port, the address of somebody else's listener.
    if (DIALLED.indexOf(s.key) >= 0) {
      return false;
    }
    if (/[Pp]ort$/.test(s.key)) {
      return typeof s.dflt === 'number' && s.dflt > 0;
    }
    if (/Socket$/.test(s.key)) {
      return typeof s.dflt === 'string' && s.dflt.indexOf('/') === 0;
    }
    return false;
  });
}

// The rows of the two tables under `### The ports`, as text. Bounded at the
// next heading so that a `| ... |` line further down the README — and there are
// hundreds, the settings table among them — cannot be read as a port row.
function portsSection() {
  log.debug("Entering portsSection().");
  const text = fs.readFileSync(README, 'utf8');
  const start = text.indexOf('\n### The ports\n');
  if (start < 0) {
    log.debug("Leaving portsSection().");
    return null;
  }
  const rest = text.slice(start + 1);
  const end = rest.indexOf('\n### ');
  log.debug("Leaving portsSection().");
  return end < 0 ? rest : rest.slice(0, end);
}

function run(t) {
  log.debug("Entering run().");
  const section = portsSection();
  if (!t.check(!!section, 'README.md has a `### The ports` section',
               'the section this file exists to check is gone; either it was ' +
               'renamed — in which case rename it here too — or a table that ' +
               'was being kept honest has been deleted')) {
    log.debug("Leaving run().");
    // Every assertion below reads it. Stopping is the honest outcome: a run
    // that reported twenty passes against an empty string would be the exact
    // thing this file is written to prevent one file over.
    return;
  }

  const settings = bindingSettings();
  t.check(settings.length >= 10,
          'config.js declares the bindings this table is about',
          settings.length + ' found: ' +
          settings.map(function (s) { return s.key; }).join(', '));

  // -----------------------------------------------------------------------
  // 1. EVERY BINDING IS IN THE TABLE, with its key, its variable and its
  //    default. Three separate assertions per setting rather than one, because
  //    "the row is missing" and "the row says 8080" are different failures and
  //    a reader acts on the second.
  // -----------------------------------------------------------------------
  t.log.info('=== every binding config.js declares has a row ===');
  settings.forEach(function (s) {
    const named = section.indexOf('`' + s.key + '`') >= 0;
    t.check(named, s.key + ' is named in the ports table',
            'a listener this service binds and the README does not mention. ' +
            'It cannot be caught by /admin/sts-metadata: that page walks the ' +
            'Express router and a raw socket registers no route');
    if (!named) {
      return;
    }
    t.check(section.indexOf('`' + s.env + '`') >= 0,
            'and its environment variable ' + s.env + ' is there too',
            'the variable is how a reader actually changes it');
    t.check(section.indexOf(String(s.dflt)) >= 0,
            'and its default (' + s.dflt + ') appears in the section',
            'a row naming the right setting and the wrong number is worse ' +
            'than a missing row, because a reader acts on it');
  });

  // -----------------------------------------------------------------------
  // 2. AND THE TABLE NAMES NOTHING THAT IS NOT A SETTING.
  //
  //    THIS IS THE DIRECTION A RENAME BREAKS, and the one nothing else would
  //    notice: `ldap.tlsPort` becoming `ldap.ldapsPort` leaves a table that is
  //    still ten rows long, still looks complete, and sends a reader to a
  //    setting that no longer exists. Section 1 above passes on it only
  //    because the new key would be missing — which reports the wrong half of
  //    what happened.
  // -----------------------------------------------------------------------
  t.log.info('=== and the table names no setting this service has not got ===');
  const known = new Set(config.SETTINGS.map(function (s) { return s.key; }));
  const cited = (section.match(/`[a-z][a-zA-Z0-9]*\.[a-zA-Z0-9]+`/g) || [])
    .map(function (m) { return m.slice(1, -1); });
  const unknown = Array.from(new Set(cited)).filter(function (key) {
    return !known.has(key);
  });
  t.equal(unknown.join(', '), '',
          'every dotted name in the ports section is a real setting');

  // -----------------------------------------------------------------------
  // 3. THE COUNT IN THE PROSE, which is the number this repository has been
  //    bitten by before. The sentence above the table says how many bindings
  //    there are, and a sentence is exactly the thing that does not get
  //    updated when an eleventh is added.
  //
  //    It is TEN against NINE SETTINGS on purpose: the KDC binds TCP and UDP
  //    from one `krb5.kdcPort`, so the number of BINDINGS is one more than the
  //    number of port settings. That arithmetic is written into the assertion
  //    rather than into a constant, so adding a listener moves both halves.
  // -----------------------------------------------------------------------
  t.log.info('=== the count in the prose ===');
  const ports = settings.filter(function (s) {
    return typeof s.dflt === 'number';
  });
  const bindings = ports.length + 1;   // the KDC's UDP socket
  const claimed = /^\s*(\w+) bindings across (\w+) numbers/m.exec(section);
  const WORDS = { eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12,
                  thirteen: 13, fourteen: 14 };
  t.check(!!claimed,
          'the section states how many bindings there are',
          'the sentence above the table should open "N bindings across M ' +
          'numbers"; without it this check cannot hold the prose to anything');
  if (claimed) {
    t.equal(WORDS[claimed[1].toLowerCase()], bindings,
            'and the number of BINDINGS it claims is right');
    t.equal(WORDS[claimed[2].toLowerCase()], ports.length,
            'and the number of distinct PORT NUMBERS with it — one fewer, ' +
            'because the KDC binds TCP and UDP from one setting');
  }

  // -----------------------------------------------------------------------
  // 4. THE DOCKERFILE EXPOSES WHAT THE TABLE LISTS.
  //
  //    `EXPOSE` publishes nothing and is metadata only, which is exactly why
  //    it goes stale quietly: a port added to the service and not to the
  //    Dockerfile costs nothing at runtime and leaves `docker run -P` — the
  //    one command that reads it — silently short. The table is the list; this
  //    holds the image to it.
  // -----------------------------------------------------------------------
  t.log.info('=== the Dockerfile EXPOSEs every one of them ===');
  const dockerfile = fs.readFileSync(path.join(__dirname, '..', 'Dockerfile'),
                                     'utf8');
  const exposed = new Set((dockerfile.match(/^EXPOSE\s+(\S+)/gm) || [])
    .map(function (line) { return line.split(/\s+/)[1].split('/')[0]; }));
  ports.forEach(function (s) {
    t.check(exposed.has(String(s.dflt)),
            'the Dockerfile EXPOSEs ' + s.dflt + ' (' + s.key + ')',
            'EXPOSE publishes nothing, so a missing one costs nothing at ' +
            'runtime and leaves `docker run -P` short with no error anywhere');
  });
  // AND THE KDC'S UDP SOCKET NAMED SEPARATELY, which is the one EXPOSE that a
  // port list alone would not produce: 88 appears twice in that file, `/tcp`
  // and `/udp`, and a reader who saw only one would conclude this KDC does not
  // answer datagrams.
  t.check(/^EXPOSE\s+88\/udp\s*$/m.test(dockerfile),
          'and names 88/udp separately from 88/tcp',
          'both transports are bound from one setting, so only the ' +
          'Dockerfile says out loud that the datagram socket is there');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'readme_ports',
  describe: "the README's ports table against config.js and the Dockerfile",
  run: run
};
