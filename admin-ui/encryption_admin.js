'use strict';
//
// File: encryption_admin.js
//
// ===========================================================================
// MONITORING > ENCRYPTION: ONE CONSOLE PAGE, `/admin/encryption` (2026-09-11).
//
// **WHAT IS ENCRYPTED IN THE STORE, WITH WHICH KEY, UNDER WHICH ALGORITHM,
// AND HOW MUCH OF IT HAS HAPPENED.**
//
// ---------------------------------------------------------------------------
// WHY IT IS IN MONITORING AND NOT UNDER PROTOCOLS, AND WHY IT IS NOT A SECTION
// OF `/admin/crypto-metadata`.
//
// `admin-ui/CLAUDE.md`'s filing rule is that a page goes where the QUESTION it
// answers goes, rather than where the module that draws it lives. Two pages
// were candidates to absorb this one and each answers a different question:
//
//   * **`/admin/crypto-metadata`** answers *what does this service DO when it
//     signs, verifies, encrypts or decrypts* — the algorithms, per protocol
//     family, read out of the module that performs each. It is CONFIGURATION,
//     it is the same on a service that has been running for a month and one
//     that started a second ago, and it is filed under Protocols with the rest
//     of what this service IS.
//   * **`/admin/keys`** answers *what signing keys does this realm hold* —
//     one realm, the public halves, the residency policy.
//
// This one answers **what has been encrypted AT REST, and how often**, which
// is a question about traffic: the numbers go up while somebody watches. That
// is the same argument `/admin/xacml/monitor` and `/admin/scim/monitor` are
// each filed under Monitoring on, made a third time rather than cited —
// `console-section-by-question` is the rule and this is an instance of it.
//
// **IT IS ONE PAGE AND NOT A THIRD COPY OF ANYTHING.** Every figure on it is
// read from the module that owns the fact: the ALGORITHM from
// `crypto.js`'s `KEK_PARAMETERS` (the same rule `crypto_metadata.js` follows —
// an algorithm this service performs must be in a table there rather than in a
// literal on a page), the KEY from `secrets.describe()`, the STATE from
// `keystore.report()`, the STORE from `persistence.describe()`, and the COUNTS
// from `crypto.js`'s own tally. Nothing here computes a second opinion about
// any of them.
//
// ---------------------------------------------------------------------------
// IT DRAWS NO CIPHERTEXT AND NO PLAINTEXT, AND THAT IS A RULE RATHER THAN AN
// OMISSION.
//
// A page about encryption is the page somebody will want to put a sample on,
// and the cost of one is out of all proportion to what it shows: a sealed
// value is a private key, a TOTP shared secret or somebody's recovery codes,
// and a console page that printed either half of one would be handing over
// exactly what the sealing exists to protect. What this page shows is
// COUNTS, SHAPES and NAMES. `/admin/ldap/directory` is where a reader who
// genuinely wants to see a `$aesgcm$…` envelope goes, and it shows it under a
// heading saying the registry as the directory sees it.
//
// **NOR DOES IT HAVE A CONTROL.** There is nothing here to press: rotating the
// key-encryption key is a deployment act (`secrets.js` reads one; it never
// writes one), and a *decrypt this* button would be the one door in this
// service onto material no door is supposed to have. The page is a report, and
// `/admin/keys` — which does have an export — is where taking a key out is
// argued.
// ===========================================================================

const app = require('../common/app');
const admin = require('./admin');
const { log } = require('../common/helpers');
const config = require('../common/config');
const crypto = require('../common/crypto');
const keystore = require('../common/keystore');
const secrets = require('../common/secrets');
const mode = require('../common/mode');
const persistence = require('../persistence/persistence');
const minted = require('../persistence/persistence_minted');

// ---------------------------------------------------------------------------
// WHAT IS SEALED, AND WHAT DELIBERATELY IS NOT.
//
// **THIS TABLE IS THE PAGE'S ONE PIECE OF WRITTEN-DOWN KNOWLEDGE AND IT IS
// WORTH BEING HONEST ABOUT THAT.** Every other figure here is read from the
// module that owns it; this is a list of WHERE sealed data lives, and no
// module publishes that — a store holds a column of strings and cannot say
// which of them are key material.
//
// It is kept honest in two ways rather than by care. The `label` on each row
// is the label the CALL SITE passes to `keystore.seal()`, so a row whose
// label never appears in the accounting is a row describing something that
// never happens — and `tests/encryption_page.js` asserts that every label the
// tally can produce has a row here and the reverse. And the NOT-SEALED half is
// listed beside the sealed half on the same table, because the interesting
// question about a page like this is almost always *is X encrypted* and a
// table that lists only the yeses answers it by silence.
// ---------------------------------------------------------------------------
const DATA_CLASSES = [
  {
    label: 'signing-keys',
    what: 'This service’s own signing keys, one row per trust realm — and, ' +
          'in the same row since 2026-09-12, that realm’s OpenID4VCI ' +
          'credential request-encryption key',
    where: 'the `sts_keys` row family in the persistence store',
    sealed: true,
    why: 'A private key that outlives the process. In product mode these are ' +
         'generated ONCE and read back on every start, which is what lets a ' +
         'token issued yesterday verify today — and is exactly why the ' +
         'row cannot be in the clear. What is resident in this process is ' +
         'the CIPHERTEXT: `keys.plaintextRetention` decides how long a ' +
         'decrypted key is kept after it has been used.'
  },
  {
    label: 'pki-hierarchy',
    what: 'The certificate authority: the service Root, every Intermediate, ' +
          'and every Issuing CA',
    where: 'the `pki:<realm>` rows of that same family',
    sealed: true,
    why: 'CA private keys, which never leave this process at all. They are ' +
         'in the SAME row family and under the same key deliberately: a ' +
         'store of `pki.js`’s own would have been a second answer to ' +
         '*where does this service keep a private key*, and the second ' +
         'answer is the one nobody remembers to rotate.'
  },
  {
    label: 'application-private-key',
    what: 'The assertion signing key pairs `/admin/pki` issues to ' +
          'applications — `oauthAssertionPrivateKey` and ' +
          '`oauthSamlAssertionPrivateKey`',
    where: 'attributes on the application’s own entry under ' +
           '`ou=applications`',
    sealed: true,
    why: 'This was the LAST private key material in this service stored in ' +
         'the clear, until 2026-09-10. It is sealed AT REST and opened for a ' +
         'reader that came through `applications.js` — so ' +
         '`/admin/applications` still hands an operator the PEM they came ' +
         'to collect, while an `ldapsearch` on TCP 389, an LDIF file, a ' +
         'database row and a backup of either hold `$aesgcm$…`.'
  },
  {
    label: 'gnap-shared-key',
    what: 'A GNAP client instance’s shared secret for a key reference — ' +
          '`gnapSymmetricKey` (RFC 9635 section 7.1.1)',
    where: 'an attribute on the application’s own entry under ' +
           '`ou=applications`',
    sealed: true,
    why: 'Whoever holds it can sign GNAP requests AS that client instance: ' +
         'an HMAC key is both halves of the credential. Sealed at rest under ' +
         'the process key-encryption key when keys persist, opened for a ' +
         'reader that came through `applications.js`, and withheld from LDAP ' +
         'readers in product mode.'
  },
  {
    label: 'gnap-macaroon-key',
    what: 'A GNAP resource server’s macaroon root key — `gnapMacaroonKey` ' +
          '(RFC 9767 section 2.2)',
    where: 'an attribute on the resource server’s application entry under ' +
           '`ou=applications`',
    sealed: true,
    why: 'A macaroon is verified with its ROOT key, and the same key can mint ' +
         'one: whoever holds it can issue tokens that resource server will ' +
         'accept. The key is derived per resource server from the realm ' +
         'secret, and written onto the entry — sealed — only so the resource ' +
         'server’s operator has somewhere to collect it.'
  },
  {
    label: 'person-private-key',
    what: 'The assertion signing key pair `/admin/pki` issues to a PERSON — ' +
          '`stsAssertionPrivateKey` (2026-09-11)',
    where: 'an attribute on that person’s own entry under `ou=users`',
    sealed: true,
    why: 'The same mechanism as the application’s above and deliberately not ' +
         'a new one, with one difference that is a fact about the two ' +
         'holders: an application’s private key is OPENED for a reader that ' +
         'came through `applications.js`, and nothing draws a person’s entry ' +
         'through a module that would open theirs — so this one is handed ' +
         'over ONCE, by the act that creates it, and is ciphertext ' +
         'everywhere afterwards. A console page that printed a person’s ' +
         'private key on every visit was the alternative.'
  },
  {
    label: 'kerberos-keys',
    what: 'Stored Kerberos long-term keys — a directory person\'s, derived ' +
          'from their own password (`stsKrb5Keys`), and a service ' +
          'principal\'s random ones (`krb5ServiceKeys`) (2026-09-12)',
    where: 'an attribute on the person’s entry under `ou=users`, or on the ' +
           'service’s application entry under `ou=applications`',
    sealed: true,
    why: 'PASSWORD-EQUIVALENT: a Kerberos long-term key is what the password ' +
         'is turned into, and whoever holds it can obtain tickets as that ' +
         'principal without knowing the password. So it is sealed wherever the ' +
         'key-encryption key outlives the process, the name and a stamp of the ' +
         'password hash are sealed WITH it so a value cannot be moved to ' +
         'another entry or kept past a password change, and it is WITHHELD — ' +
         'ciphertext included — from every page, every LDAP search and every ' +
         '`/admin-api` reply. A service principal\'s key leaves this service ' +
         'once, as the keytab its create or rotate hands over.'
  },
  {
    label: 'totp-secret',
    what: 'The RFC 6238 shared secret of everybody who has enrolled an ' +
          'authenticator app — `stsTotpCredential`',
    where: 'an attribute on the person’s own entry under `ou=users`',
    sealed: true,
    why: 'THE ONE CREDENTIAL IN THIS DIRECTORY THAT CAN BE READ BACK. ' +
         'Verifying a code means COMPUTING it, so this cannot be hashed the ' +
         'way `userPassword` is — and `/admin/ldap/directory` prints ' +
         'every attribute of every entry by design, so without the seal a ' +
         'directory dump would print a working second factor.'
  },
  {
    label: 'recovery-codes',
    what: 'The set of single-use recovery codes issued by enrolling a second ' +
          'factor',
    where: 'the sealed `vault` inside `stsBackupCodes`, on the person’s ' +
           'entry',
    sealed: true,
    why: 'Encrypted RATHER THAN HASHED, and the reason is a product ' +
         'decision rather than a cryptographic one: a person may read their ' +
         'remaining codes back at `/portal/mfa`. **That reversed on ' +
         '2026-09-11 and this row is kept for the sets written before it** — ' +
         'a new set is HASHED with scrypt and is not sealed at all, because ' +
         'a hash is not a secret. The COUNTS sit outside the ' +
         'sealed blob, so every page that reports *7 of 10 unused* can do so ' +
         'without opening it — including for a set this process cannot ' +
         'decrypt.'
  },
  {
    label: 'minted-rows',
    what: 'Everything this process MINTS — sessions, tokens, ' +
          'authorization codes, artifacts, Kerberos principals, the replay ' +
          'caches, the counters and the audit log',
    where: 'the minted row families, PRODUCT MODE ON POSTGRES ONLY',
    sealed: true,
    why: 'The newest and the largest by volume. It is product-and-postgres ' +
         'only because that is the only configuration in which any of it ' +
         'persists at all: development mode regenerates the signing key on ' +
         'every start, so a restored token would verify against nothing, and ' +
         'the `ldif` store writes whole files per flush and holds none of it ' +
         'in either mode.'
  },
  // ------------------------------------------------------------------------
  // AND THE OTHER HALF. Each of these is a thing a reader will look for, and
  // each is absent for a REASON rather than by oversight.
  // ------------------------------------------------------------------------
  {
    label: null,
    what: 'Passwords — `userPassword`, and the activation tokens beside ' +
          'them',
    where: 'an attribute on the person’s entry',
    sealed: false,
    why: 'HASHED, not encrypted, and that is stronger rather than weaker. ' +
         'scrypt with N at 2^15, and nothing in this service can read one ' +
         'back — which is the rule: a secret this service VERIFIES is ' +
         'hashed, and a secret it must PRESENT is encrypted. The two ' +
         'mechanisms above are the second kind and say so.'
  },
  {
    label: null,
    what: 'Client secrets — `oauthClientSecret`, `fedClientSecret`, and ' +
          'the RFC 7592 registration access tokens',
    where: 'attributes on application and federation entries',
    sealed: false,
    why: 'IN THE CLEAR, and it is the honest state of a service that ' +
         'authenticates nobody: a federation relationship’s secret is ' +
         'SENT to somebody else’s token endpoint, so it has to be ' +
         'recoverable, and anybody who can read this directory can already ' +
         'authenticate as that client. Sealing them would hide the fact ' +
         'rather than change it. This is why the directory pages moved ' +
         'behind the console gate in the first place.'
  },
  {
    label: null,
    what: 'The eleven post-quantum keys per realm, the TLS server ' +
          'certificate, and the SPIFFE authorities',
    where: 'memory, for the life of the process',
    sealed: false,
    why: 'NOT PERSISTED AT ALL, in either mode, so there is nothing at rest ' +
         'to seal. All three are named in `common/mode.js`’s `NOT_YET` ' +
         'rather than left to be discovered, because *not stored* and *not ' +
         'protected* read the same from outside and are not the same thing.'
  }
];

// ---------------------------------------------------------------------------
// THE MODEL. Built once and rendered twice — HTML and `?format=json` — which
// is `respond()`'s contract and the reason `/admin-api/encryption` cannot
// disagree with the page (rule 7).
// ---------------------------------------------------------------------------
function encryptionJson() {
  log.debug('Entering encryptionJson().');
  const report = keystore.report();
  const accounting = crypto.kekAccounting();
  const byLabel = Object.create(null);
  accounting.labels.forEach(function (row) {
    byLabel[row.label] = row;
  });
  const store = describeStore();

  const classes = DATA_CLASSES.map(function (one) {
    const seen = one.label ? byLabel[one.label] : null;
    return {
      what: one.what,
      where: one.where,
      sealed: one.sealed,
      label: one.label,
      why: one.why,
      // NULL rather than ZERO for a class with no label, and the difference
      // is the point: zero means *this is sealed and has not happened yet*,
      // and null means *there is nothing here to count*. One number could
      // only have said the first, about rows that are in the clear.
      encryptions: one.sealed ? ((seen && seen.encryptions) || 0) : null,
      decryptions: one.sealed ? ((seen && seen.decryptions) || 0) : null,
      failures: one.sealed ? ((seen && seen.failures) || 0) : null,
      lastAt: seen && seen.lastAt ? new Date(seen.lastAt).toISOString() : null
    };
  });

  // A LABEL THE TALLY PRODUCED AND THIS TABLE DOES NOT KNOW. It is REPORTED
  // rather than dropped, for `user_graph.js`'s reason about an unknown grant:
  // a call site added without a row here shows up as a line on the page
  // instead of as a number that quietly does not add up.
  const known = DATA_CLASSES.map(function (one) { return one.label; })
    .filter(Boolean);
  const unclassified = accounting.labels.filter(function (row) {
    return known.indexOf(row.label) < 0;
  });

  const out = {
    what: 'What this service encrypts AT REST, with which key, under which ' +
          'algorithm, and how much of it has happened in this process.',
    mode: mode.current(),
    // ---------------------------------------------------------------------
    // THE KEY. `keystore.persists()` and `keystore.sealed()` are DIFFERENT
    // QUESTIONS and both are reported, because the pair is what tells a
    // reader which of two very different states they are in. Development
    // mode HAS a key-encryption key — an ephemeral one, generated per run, so
    // that the request-worker pool can share minted rows — and it persists
    // nothing. A page reporting only `sealed` would say "encrypted" about a
    // service whose key dies with the process.
    // ---------------------------------------------------------------------
    key: {
      present: !!report.kekRead,
      persists: !!report.persisting,
      ephemeral: !!report.kekRead && !report.persisting,
      provider: report.kek.provider,
      providerLabel: report.kek.label,
      providerKnown: !!report.kek.known,
      where: report.kek.where,
      providers: report.kek.providers,
      note: report.persisting
        ? 'The key-encryption key is read from the provider above at ' +
          'startup, before the listener binds. This service never generates ' +
          'it and never writes it down, and a service that cannot read it ' +
          'does NOT start — it does not generate a replacement and ' +
          'carry on, because that would stop every token it has ever issued ' +
          'from verifying, silently, at somebody else’s relying party.'
        : 'This service is in development mode, so nothing it holds outlives ' +
          'the process and the key-encryption key is EPHEMERAL: generated ' +
          'per run, never written down, and used only so that the ' +
          'request-worker pool can share minted rows within one run. ' +
          'Sealing a directory attribute under it would be WORSE than the ' +
          'clear — the entry survives a restart in the `ldif` and ' +
          '`postgres` stores and the key does not, so the value would come ' +
          'back as permanent garbage. That is why the test at every write ' +
          'site is `keystore.persists()` rather than `keystore.sealed()`.'
    },
    algorithm: crypto.KEK_PARAMETERS,
    algorithmNote:
      'AES-256-GCM and deliberately not CBC: GCM is AUTHENTICATED, so a ' +
      'ciphertext somebody altered fails to decrypt instead of yielding a ' +
      'subtly different key. A signing key that decrypted to the wrong bytes ' +
      'would produce signatures nothing can verify, and the failure would ' +
      'surface at a relying party as "the signature is invalid" — as ' +
      'far from the cause as it is possible to get. The key-encryption key ' +
      'NEVER ENCRYPTS ANYTHING DIRECTLY: every record derives a subkey of ' +
      'its own with HKDF-SHA256 over a random salt, so no record’s IV ' +
      'matters to any other — and a single key encrypting many records ' +
      'under many IVs is one IV-reuse bug away from catastrophic in GCM.',
    // ---------------------------------------------------------------------
    // THE TWO LIMITS OF EVERYTHING ABOVE (2026-09-12), and they are on the
    // JSON as well as on the page for `pki_admin.js`'s `revocationNote`
    // reason: a caller that reads the class table and not the caveat comes
    // away believing this service encrypts more than it does, and a machine
    // reader has no page to have read it on.
    //
    // BOTH ARE QUESTIONS SOMEBODY ASKS AFTER READING THE TABLE, which is why
    // they are here rather than in a file nobody opens: *is a realm a
    // boundary* and *what covers the rest of the database*.
    // ---------------------------------------------------------------------
    boundaries: {
      // Answered as a FIELD and not only as prose, so a test or a dashboard
      // can assert it rather than matching on a sentence.
      perRealmKey: false,
      realms:
        'THERE IS ONE KEY-ENCRYPTION KEY FOR THIS SERVICE, NOT ONE PER TRUST ' +
        'REALM. It is read once at startup and used for every sealed value in ' +
        'every realm. Each record does get a key of its own — HKDF over a ' +
        'random salt per record — but the derivation takes no realm, so the ' +
        'separation is per RECORD and not per TENANT. What is per realm is the ' +
        'material being sealed (each realm has its own signing keys and its ' +
        'own branch of the certificate authority), not the key that seals it. ' +
        'So a realm is NOT a cryptographic boundary at rest: whoever can read ' +
        'this key can open every realm\'s sealed data, and rotating it rotates ' +
        'every realm at once.',
      storage:
        'EVERYTHING NOT IN THE TABLE ABOVE IS PLAINTEXT IN THE STORE — the ' +
        'directory entries, the groups, the applications, the realms and the ' +
        'settings, and in development mode very nearly all of it. This service ' +
        'seals credentials and private keys and nothing else, deliberately: ' +
        'column-level encryption leaves the plaintext in the write-ahead log, ' +
        'in temporary files when a sort spills, in a pg_dump, on replicas and ' +
        'in query logs, so the layer that covers a whole store belongs UNDER ' +
        'the database rather than inside it. That layer is the operator\'s — ' +
        'LUKS or an encrypted ZFS dataset under PGDATA, a cloud disk with a ' +
        'customer-managed key, or one of the PostgreSQL forks that has TDE, ' +
        'since the community build has none. docs/encryption-at-rest.md is ' +
        'this repository\'s write-up of the options.',
      // The one deployment mistake that makes everything above decorative, and
      // the one this repository's own compose stack invites by mounting a key
      // file beside the database volume.
      keyResidency:
        'AND THE KEY MUST NOT LIVE ON THE DISK IT PROTECTS. A key file on the ' +
        'same unencrypted volume as the store hands both halves to whoever ' +
        'takes the volume; that is fine for a development stack and is why ' +
        'the `file` provider is the default, and it is not a deployment. ' +
        'keys.kekProvider selects a secret store instead.'
    },
    store: store,
    classes: classes,
    unclassified: unclassified,
    accounting: {
      operations: accounting.operations,
      encryptions: accounting.encryptions,
      decryptions: accounting.decryptions,
      failures: accounting.failures,
      plaintextBytes: accounting.plaintextBytes,
      ciphertextBytes: accounting.ciphertextBytes,
      since: new Date(accounting.startedAt).toISOString(),
      firstAt: accounting.firstAt
        ? new Date(accounting.firstAt).toISOString() : null,
      lastAt: accounting.lastAt
        ? new Date(accounting.lastAt).toISOString() : null,
      labels: accounting.labels
    },
    accountingNote:
      'Counted at the ONE funnel both operations pass through — ' +
      '`crypto.js`’s `encryptWithKek()` and `decryptWithKek()` — ' +
      'rather than at the call sites, because a total assembled from call ' +
      'sites is wrong the first time somebody adds another one and is wrong ' +
      'SILENTLY. The breakdown below is by a LABEL each call site passes; a ' +
      'caller that passes none is still counted, under `(unlabelled)`. ' +
      'THESE ARE PROCESS-WIDE AND NOT PER REALM — a key-encryption key ' +
      'belongs to the process, so partitioning the count by realm would be ' +
      'counting the realm a request happened to be in — and they are ' +
      'in memory, so a restart is how you get an empty one.',
    failuresNote:
      'A FAILURE IS ALMOST ALWAYS THE WRONG KEY-ENCRYPTION KEY — a ' +
      'rotated secret, or a store carried between deployments — and it ' +
      'is its own figure rather than being folded into the decryptions, ' +
      'because nine hundred decryptions and nine hundred decryptions with ' +
      'four hundred failures are very different reports. What happens next ' +
      'depends on what was being read: a signing key that will not open is ' +
      'FATAL at startup, a session row is dropped, and a second factor that ' +
      'will not open makes that person unable to sign in until an operator ' +
      'clears the enrolment — never silently absent, which would remove ' +
      'a security control.',
    // NO CIPHERTEXT AND NO PLAINTEXT IS ON THIS PAGE, said in the JSON as
    // well as in the markup, because a machine reading this may be about to
    // ask where the samples are.
    noSamples:
      'Neither a sealed value nor an opened one appears anywhere on this ' +
      'page or in this document. A sealed value is a private key, a shared ' +
      'secret or somebody’s recovery codes, and printing either half of ' +
      'one would hand over exactly what the sealing exists to protect. ' +
      '/admin/ldap/directory is where a `$aesgcm$…` envelope can be ' +
      'seen, under a heading that says it is the store as the directory ' +
      'sees it.'
  };
  log.debug('Leaving encryptionJson(). ' + out.accounting.operations +
            ' operation(s).');
  return out;
}

// The store, from the module that owns it. **`activeMode()` AND NOT `mode()`,
// which is the whole of the difference worth knowing here:** the first is the
// SETTING and the second is what the driver actually opened, and they part
// company exactly when it matters — a `postgres` store that would not open
// falls back, so a page reading the setting would report that everything this
// process mints is being sealed into a database it never reached.
//
// It is WRAPPED for the reason every other reporter on this console is: the
// page is about encryption and the store is context, so a persistence layer
// that will not answer costs a sentence rather than a stack trace.
function describeStore() {
  log.debug('Entering describeStore().');
  let active = '';
  let mintedOn = false;
  try {
    active = typeof persistence.activeMode === 'function'
      ? String(persistence.activeMode() || '') : '';
    mintedOn = typeof minted.enabled === 'function' ? !!minted.enabled() : false;
  } catch (e) {
    // Swallowed deliberately: a store that throws while describing itself is
    // still a store, and the page's subject is the encryption rather than the
    // persistence layer. The fallback below reports the SETTING and says so.
    log.debug('describeStore(): the persistence layer would not answer: ' +
              e.message);
  }
  const setting = String(config.value('persistence.mode') || 'memory');
  log.debug('Leaving describeStore(). active=' + (active || setting));
  return {
    mode: active || setting,
    configuredMode: setting,
    // A DRIVER THAT FELL BACK IS SAID OUT LOUD rather than smoothed over, on
    // `/admin/persistence`'s own argument about reporting two facts instead of
    // one tick.
    fellBack: !!active && active !== setting,
    persistsMinted: mintedOn,
    note: 'Sealing protects what is WRITTEN DOWN, so what the store holds ' +
          'decides how much of the table above is reachable by anybody at ' +
          'all. A `memory` store writes nothing, so nothing in it survives ' +
          'this process to be read.'
  };
}

// ---------------------------------------------------------------------------
// THE PAGE.
// ---------------------------------------------------------------------------
function bytes(n) {
  const num = Number(n) || 0;
  if (num < 1024) {
    return num + ' B';
  }
  if (num < 1024 * 1024) {
    return (num / 1024).toFixed(1) + ' KB';
  }
  return (num / (1024 * 1024)).toFixed(1) + ' MB';
}

function when(iso) {
  return iso ? admin.esc(String(iso).replace('T', ' ').replace(/\..*$/, 'Z'))
             : '<span class="muted">never</span>';
}

function classesTable(json) {
  log.debug('Entering classesTable().');
  const rows = json.classes.map(function (one) {
    // The two halves of the table are told apart by a WORD in a cell rather
    // than by two tables, because the reading a person came for is the
    // comparison — *is this encrypted and is that* — and two tables make that
    // a scroll.
    const mark = one.sealed
      ? '<span class="ok">sealed</span>'
      : '<span class="muted">not sealed</span>';
    const counts = one.sealed
      ? admin.esc(String(one.encryptions)) + ' out, ' +
        admin.esc(String(one.decryptions)) + ' in' +
        (one.failures
          ? ' <span class="bad">' + admin.esc(String(one.failures)) +
            ' failed</span>' : '')
      : '<span class="muted">&mdash;</span>';
    return '<tr><td>' + one.what + '</td>' +
           '<td><code>' + admin.esc(one.where) + '</code></td>' +
           '<td>' + mark +
           (one.label ? '<br><code>' + admin.esc(one.label) + '</code>' : '') +
           '</td>' +
           '<td>' + counts + '</td>' +
           '<td>' + when(one.lastAt) + '</td>' +
           '<td class="why">' + one.why + '</td></tr>';
  }).join('');
  log.debug('Leaving classesTable().');
  return '<table class="grid"><thead><tr>' +
         '<th>What</th><th>Where it lives</th><th>At rest</th>' +
         '<th>Operations</th><th>Last</th><th>Why</th>' +
         '</tr></thead><tbody>' + rows + '</tbody></table>';
}

function unclassifiedBlock(json) {
  if (!json.unclassified.length) {
    return '';
  }
  return admin.warn(
    '<p><strong>' + json.unclassified.length + ' label(s) were counted that ' +
    'this page has no row for:</strong> ' +
    json.unclassified.map(function (row) {
      return '<code>' + admin.esc(row.label) + '</code> (' +
             row.encryptions + ' out, ' + row.decryptions + ' in)';
    }).join(', ') + '.</p>' +
    '<p>That is a call site somebody added without adding a row to ' +
    '<code>DATA_CLASSES</code> in <code>admin-ui/encryption_admin.js</code>. ' +
    'It is drawn rather than dropped on purpose: the alternative is a table ' +
    'that goes on looking complete while the totals above it do not add up ' +
    'to the rows below.</p>');
}

function renderEncryption(req, res) {
  log.debug('Entering renderEncryption().');
  const json = encryptionJson();

  const tiles = '<div class="tiles">' +
    admin.tile(String(json.accounting.operations), 'operations') +
    admin.tile(String(json.accounting.encryptions), 'encryptions') +
    admin.tile(String(json.accounting.decryptions), 'decryptions') +
    admin.tile(String(json.accounting.failures), 'failed to open') +
    admin.tile(json.key.present
      ? (json.key.persists ? 'durable' : 'ephemeral') : 'none',
      'key-encryption key') +
    admin.tile(json.mode, 'mode') +
    '</div>';

  const what = admin.note(
    '<p>This page answers <strong>what this service encrypts at rest, with ' +
    'which key, under which algorithm, and how much of it has happened</strong>. ' +
    'It is under Monitoring rather than beside the other two cryptography ' +
    'pages because of what it is: <a href="/admin/crypto-metadata">the ' +
    'crypto report</a> says what this service <em>does</em> when it signs or ' +
    'encrypts and reads the same on a service that started a second ago, and ' +
    '<a href="/admin/keys">the keys page</a> says what one realm ' +
    '<em>holds</em>. The numbers here go up while you watch.</p>' +
    '<p><strong>Neither a sealed value nor an opened one appears on this ' +
    'page.</strong> A sealed value is a private key, an authenticator&rsquo;s ' +
    'shared secret or somebody&rsquo;s recovery codes, and printing either ' +
    'half of one would hand over exactly what the sealing exists to protect. ' +
    'There is no control here either: rotating the key-encryption key is a ' +
    'deployment act &mdash; this service reads one and never writes one &mdash; ' +
    'and a <em>decrypt this</em> button would be the one door onto material ' +
    'no door is supposed to have.</p>',
    'What this page is, and the two things it deliberately has not got');

  const keyBlock = admin.note(
    '<p>The key-encryption key is read by <code>common/secrets.js</code> ' +
    'from <strong>' + admin.esc(json.key.providerLabel) + '</strong> ' +
    '(<code>' + admin.esc(json.key.provider) + '</code>), once, at startup ' +
    'and before the listener binds. <code>file</code> is the default because ' +
    'it needs nothing: Kubernetes mounts a Secret as a file, Docker mounts a ' +
    'secret as a file, and every other provider here is that same idea with ' +
    'somebody else&rsquo;s access control in front of it.</p>' +
    '<p>' + json.key.note + '</p>' +
    '<p><strong>A key shorter than 32 bytes is REFUSED rather than ' +
    'stretched.</strong> Stretching would let a four-character password ' +
    'protect every signing key this service holds while the log said ' +
    'AES-256. Hex is tried before base64, because a 64-character hex string ' +
    'is also valid base64 and reading it that way produces 48 different ' +
    'bytes.</p>' +
    '<p class="muted">Available providers: ' +
    json.key.providers.map(function (one) {
      return '<code>' + admin.esc(one.id) + '</code> ' + admin.esc(one.label);
    }).join(', ') + '. <code>keys.kekProvider</code> selects one.</p>',
    'Where the key comes from');

  // **THE LIMITS, DRAWN AS A WARNING RATHER THAN A NOTE.** Everything else on
  // this page says what IS encrypted, and a reader who stops there comes away
  // believing more than is true — which is the shape of mistake this console
  // draws in amber everywhere else.
  const boundsBlock = admin.warn(
    '<p>' + admin.esc(json.boundaries.realms) + '</p>' +
    '<p>' + admin.esc(json.boundaries.storage) + '</p>' +
    '<p>' + admin.esc(json.boundaries.keyResidency) + '</p>',
    'What this key does not separate, and what this page does not cover');

  const algBlock = admin.note(
    '<p>' + json.algorithmNote + '</p>' +
    '<table class="grid"><tbody>' +
    [['Cipher', json.algorithm.cipher],
     ['Key', json.algorithm.keyBits + '-bit'],
     ['Nonce', json.algorithm.ivBits + '-bit, random per record'],
     ['Authentication tag', json.algorithm.tagBits + '-bit'],
     ['Key derivation', json.algorithm.kdf + ', ' +
      json.algorithm.kdfSaltBits + '-bit random salt per record'],
     ['Derivation info', json.algorithm.kdfInfo],
     ['Envelope', json.algorithm.envelope]].map(function (pair) {
      return '<tr><th>' + admin.esc(pair[0]) + '</th><td><code>' +
             admin.esc(String(pair[1])) + '</code></td></tr>';
    }).join('') +
    '</tbody></table>' +
    '<p class="muted">Every figure in that table is read out of ' +
    '<code>common/crypto.js</code>&rsquo;s own <code>KEK_PARAMETERS</code> ' +
    'rather than written down here &mdash; the same rule ' +
    '<a href="/admin/crypto-metadata">the crypto report</a> follows about ' +
    'reading an algorithm table from the module that performs the algorithm, ' +
    'so this page cannot go on looking complete while being wrong.</p>',
    'The algorithm, and why it is authenticated');

  const countsBlock = admin.note(
    '<p>' + json.accountingNote + '</p><p>' + json.failuresNote + '</p>' +
    '<p class="muted">Since ' + when(json.accounting.since) +
    '. First operation ' + when(json.accounting.firstAt) +
    ', most recent ' + when(json.accounting.lastAt) + '. ' +
    admin.esc(bytes(json.accounting.plaintextBytes)) + ' of plaintext has ' +
    'passed through, producing ' +
    admin.esc(bytes(json.accounting.ciphertextBytes)) +
    ' of ciphertext.</p>',
    'How the counting works, and what a failure means');

  const storeBlock = admin.note(
    '<p>' + json.store.note + ' This service is on the <strong>' +
    admin.esc(json.store.mode) + '</strong> store, and what it MINTS ' +
    (json.store.persistsMinted ? 'IS' : 'is NOT') + ' persisted.</p>',
    'The store underneath all of it');

  admin.respond(req, res, json, 'Encryption', '/admin/encryption',
                tiles + what +
                '<h3>What is encrypted, and what is not</h3>' +
                classesTable(json) +
                unclassifiedBlock(json) +
                '<h3>The key</h3>' + keyBlock + boundsBlock +
                '<h3>The algorithm</h3>' + algBlock +
                '<h3>The counting</h3>' + countsBlock +
                storeBlock);
  log.debug('Leaving renderEncryption().');
}

app.get('/admin/encryption', function (req, res) {
  log.debug('Entering GET /admin/encryption.');
  renderEncryption(req, res);
  log.debug('Leaving GET /admin/encryption.');
});

log.info('The encryption report is at /admin/encryption: what this service ' +
         'seals at rest, with which key and under which algorithm, and how ' +
         'many encryptions and decryptions have happened in this process.');

module.exports = {
  // For `mgmt-api/admin_api.js`. Rule 7 — the page and the operation read one
  // function, so the API cannot report a different number from the console.
  encryptionView: encryptionJson,
  // For `tests/encryption_page.js`, which checks the table against the labels
  // the call sites actually pass. Exported for `pki_authoring.js`'s reason: a
  // class described here and never sealed, or sealed and never described, is
  // an error nothing else in this service can see.
  dataClasses: function () { return DATA_CLASSES.slice(); }
};
