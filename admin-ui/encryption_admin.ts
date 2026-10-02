// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: encryption_admin.ts
//
// ===========================================================================
// MONITORING > ENCRYPTION: ONE CONSOLE PAGE, `/admin/encryption` (2026-09-11).
//
// **WHAT IS ENCRYPTED IN THE STORE, WITH WHICH KEY, UNDER WHICH ALGORITHM,
// AND HOW MUCH OF IT HAS HAPPENED.**
//
// ---------------------------------------------------------------------------
// WHY IT IS IN MONITORING, AND WHY IT IS NOT A SECTION OF
// `/admin/crypto-metadata`.
//
// `admin-ui/CLAUDE.md`'s filing rule is that a page goes where the QUESTION it
// answers goes, rather than where the module that draws it lives. Two pages
// were candidates to absorb this one and each answers a different question:
//
//   * **`/admin/crypto-metadata`** answers *what does this service DO when it
//     signs, verifies, encrypts or decrypts* — the algorithms, per protocol
//     family, read out of the module that performs each. It is CONFIGURATION,
//     it is the same on a service that has been running for a month and one
//     that started a second ago, and it is filed under Server configuration
//     with the rest of what this service IS.
//   * **`/admin/keys`** answers *what signing keys does this realm hold* —
//     one realm, the public halves, the residency policy.
//
// This one answers **what has been encrypted AT REST, and how often**, which
// is a question about traffic: the numbers go up while somebody watches. That
// is the same argument `/admin/xacml/monitor` and `/admin/scim/monitor` are
// each filed under Monitoring on, made a third time rather than cited — the
// filing rule above is the rule and this is an instance of it.
//
// **IT IS ONE PAGE AND NOT A THIRD COPY OF ANYTHING.** Every figure on it is
// read from the module that owns the fact: the ALGORITHM from
// `crypto.js`'s `KEK_PARAMETERS` (the same rule `crypto_metadata.ts` follows —
// an algorithm this service performs must be in a table there rather than in a
// literal on a page), the KEY from `secrets.describe()`, the STATE from
// `keystore.report()`, the STORE from `persistence.activeMode()`, and the
// COUNTS from `crypto.js`'s own tally. Nothing here computes a second opinion
// about any of them.
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
// **ITS ONLY CONTROLS MOVE KEYS AND SHOW NOTHING (#391 P2).** Rotating the
// key-encryption key is still a deployment act (`secrets.js` reads one; it
// never writes one), and a *decrypt this* button would still be the one door
// in this service onto material no door is supposed to have. What it has is
// the two acts on the DATA encryption keys an operator may ask for — rotate
// them now, and run the re-encryption pass now — each queuing a run of
// `common/data_key_rotation.ts`'s jobs, Admin Write, beside the list of keys
// (ids, realms, classes and states; never a key). `/admin/keys` — which does
// have an export — is where taking a key out is argued.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that has a route (rule 1): `EncryptionAdmin`
// takes the console shell, the settings, the cryptography funnel, the
// keystore, the secret reader, the mode, both persistence modules and the
// logger through its constructor, and its `registerRoutes(app)` holds the
// page's one route. `DATA_CLASSES` stays a module-level table. The module
// exports `registerRoutes(app)`, which `common/protocol_stack.ts` calls at
// 18b, where requiring this module used to register the route (#50, R1) —
// requiring it registers nothing. It also exports `encryptionView` and
// `dataClasses`, for `mgmt-api/admin_api.ts` and
// `tests/encryption_report.js`.
//
// R2 (#50): the composition root builds the instance and installs it; this
// module builds none of its own, and its exports are FACADES that forward to
// that instance, for the JavaScript callers. A process without the root
// builds a default instance at load, as loading this module always did.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import admin = require('./admin');
import helpers = require('../common/helpers');
import config = require('../common/config');
import crypto = require('../common/crypto');
import keystore = require('../common/keystore');
import secrets = require('../common/secrets');
import mode = require('../common/mode');
import persistence = require('../persistence/persistence');
import minted = require('../persistence/persistence_minted');
import InstanceSlot = require('../common/instance_slot');

type Req = any;
type Res = any;
type Json = any;

interface EncryptionAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  config: typeof config;
  crypto: typeof crypto;
  keystore: typeof keystore;
  // Not read by any method today; passed so the require above is kept (an
  // import nothing uses is dropped by the compiler) and so the composition
  // root hands this page the same secret reader `keystore` uses.
  secrets: typeof secrets;
  mode: typeof mode;
  persistence: typeof persistence;
  minted: typeof minted;
  // Lazily, both: the rotation module is built at 23b-ii, after this page,
  // and the console's views are a module this page reaches only to page.
  dataKeyRotation: () => Json;
  adminViews: () => Json;
}

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
// never happens — and `tests/encryption_report.js` asserts that every label
// the tally can produce has a row here and the reverse. And the NOT-SEALED
// half is listed beside the sealed half on the same table, because the
// interesting question about a page like this is almost always *is X
// encrypted* and a table that lists only the yeses answers it by silence.
// ---------------------------------------------------------------------------
/**
 * Every class of data the store holds, sealed or not: what it is, where it
 * lives, whether it is sealed, the label its encryptions are tallied under, and
 * why.
 */
const DATA_CLASSES = [
  {
    label: 'data-keys',
    what: 'The data encryption keys themselves (#391): one per realm per ' +
          'data class below, each wrapped and unwrapped under the ' +
          'key-encryption key',
    where: 'the `dek:<scope>:<realm>` rows of `sts_keys`',
    sealed: true,
    why: 'Envelope encryption: every value is encrypted under a data ' +
         'encryption key, and only the data encryption keys are encrypted ' +
         'under the key-encryption key. A wrap counts here as an encryption ' +
         'and an unwrap as a decryption; a process unwraps each key once and ' +
         'holds it, so these figures stay small whatever is sealed.'
  },
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
    label: 'client-secret',
    what: 'An application’s OAuth client secrets — `oauthClientSecret`, ' +
          'one sealed record per secret (the secret, its id, expiry and ' +
          'description)',
    where: 'an attribute on the application’s own entry under ' +
           '`ou=applications`',
    sealed: true,
    why: 'Whoever holds one authenticates as that client, and it is also ' +
         'the HMAC key of `client_secret_jwt` and of HS256 ID Tokens. ' +
         'Sealed at rest since 2026-10-01 under a durable key-encryption ' +
         'key, opened for a ' +
         'reader that came through `applications.js`, and withheld from ' +
         'LDAP readers in product mode. A value written before then stays ' +
         'in the clear until the secret is next written.'
  },
  {
    label: 'registration-access-token',
    what: 'An application’s RFC 7592 registration access token — ' +
          '`appRegistrationAccessToken`',
    where: 'an attribute on the application’s own entry under ' +
           '`ou=applications`',
    sealed: true,
    why: 'Whoever holds it reads, changes or deletes the client’s ' +
         'registration, and the read hands back the client secret. Sealed ' +
         'at rest since 2026-10-01 under a durable key-encryption key, ' +
         'opened for the RFC 7592 endpoints and for a reader that came ' +
         'through `applications.js`.'
  },
  {
    label: 'federation-client-secret',
    what: 'A federation relationship’s client secret — `fedClientSecret`, ' +
          'this service’s own credential at the partner’s token endpoint',
    where: 'an attribute on the relationship’s entry under ' +
           '`ou=federations`',
    sealed: true,
    why: 'It is SENT to somebody else’s service, so it must be recoverable ' +
         '— sealed, not hashed. Sealed at rest since 2026-10-01 under a ' +
         'durable key-encryption key; no page and no API reply returns it.'
  },
  {
    label: 'directory',
    what: 'Every directory entry’s attributes, whole — people, groups, ' +
          'applications, devices, federation relationships',
    where: '`sts_ldap_entries.attrs`, one blob per entry, in a PostgreSQL ' +
           'store; each blob names the entry it belongs to',
    sealed: true,
    why: 'rcbj’s decision on #391 (phase 6): a copy of the directory table ' +
         'is not a list of people. The DN stays readable, and so do the ' +
         'attribute NAMES; the values a lookup compares are kept as keyed ' +
         'digests beside the blob. A value sealed on its own (a TOTP ' +
         'secret, Kerberos keys) is sealed again inside it. A file (ldif) ' +
         'store holds entries as the filesystem protects them.'
  },
  {
    label: 'minted-key',
    what: 'The NAME a minted row is filed under — often the credential ' +
          'itself: a session id, a SAML artifact, a token id',
    where: '`sts_minted.key_sealed`, beside a keyed digest in `key`; and ' +
           'the change-log rows (`sts_changes.key`) that tell other ' +
           'processes about it',
    sealed: true,
    why: 'A session id is the cookie and an artifact is redeemed by ' +
         'presenting it, so a name in the clear was a usable credential in ' +
         'a dump. Since #222 the row is found by the name\'s keyed digest ' +
         'and the name is sealed, opened only by a restore or a change\'s ' +
         'reader.'
  },
  {
    label: 'used-assertion',
    what: 'The used-assertion history’s issuer, assertion id, client and ' +
          'subject — who presented which RFC 7523 or RFC 7522 document ' +
          'about whom',
    where: 'the `issuer`, `identifier`, `client_id` and `subject` columns ' +
           'of `sts_used_assertions`, in a database store',
    sealed: true,
    why: 'They name people and relationships in a table every node shares. ' +
         'Sealed since #222; the row is still found by its digest key, and ' +
         'the console’s text search is done in memory over the newest ' +
         'rows. A file (ldif) store holds them as the filesystem protects ' +
         'them: it reads them back before the keystore has started.'
  },
  {
    label: 'setting-secret',
    what: 'A secret setting changed while the service runs — today ' +
          '`scim.digestPassword`, the HTTP Digest password every SCIM ' +
          'username shares',
    where: 'the saved settings: `sts_appconfig` for the service, ' +
           '`sts_realms.overrides` for a realm',
    sealed: true,
    why: 'A setting marked secret is a credential, and the saved settings ' +
         'are otherwise plain JSON. Sealed where it is written down since ' +
         '#222 (`persistence/sealed_settings.js`); the running ' +
         'configuration, the console and the API see it as before.'
  },
  {
    label: 'identity-verifications',
    what: 'A person’s identity verifications — `stsIdaVerification` ' +
          '(OpenID Connect for Identity Assurance), whose evidence carries ' +
          'document numbers',
    where: 'an attribute on the person’s entry',
    sealed: true,
    why: 'Not a credential, but personal data no backup should carry ' +
         'readable. Sealed at rest since 2026-10-01 under a durable ' +
         'key-encryption key — the home cell’s where there is one — and ' +
         'withheld from every LDAP read.'
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
    why: 'A macaroon is verified with its ROOT key, and the same key can ' +
         'mint one: whoever holds it can issue tokens that resource server ' +
         'will accept. The key is derived per resource server from the realm ' +
         'secret, and written onto the entry — sealed — only so the resource ' +
         'server’s operator has somewhere to collect it.'
  },
  {
    label: 'person-private-key',
    what: 'The assertion signing key pairs `/admin/pki` issues to a PERSON — ' +
          '`stsAssertionPrivateKey` (2026-09-11) and, for RFC 7522, ' +
          '`stsSamlAssertionPrivateKey` (2026-09-13)',
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
    label: 'federation-encryption-key',
    what: 'A federation relationship’s encryption private key (#168) — ' +
          'what a partner’s encrypted assertion or ID Token is ' +
          'decrypted with, one row per key in `fedEncryptionKey`',
    where: 'the relationship’s own entry under `ou=federations`',
    sealed: true,
    why: 'Whoever holds it reads every assertion that partner encrypted to ' +
         'this service — the person’s identifier and attributes, the ' +
         'very thing the encryption keeps out of the browser. Sealed at rest ' +
         'wherever keys persist, and withheld — ciphertext included — from ' +
         'every LDAP search, page and `/admin-api` reply, which carry the ' +
         'certificate and the public key only.'
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
         'principal without knowing the password. So it is sealed wherever ' +
         'the key-encryption key outlives the process, the name and a stamp ' +
         'of the password hash are sealed WITH it so a value cannot be moved ' +
         'to another entry or kept past a password change, and it is ' +
         'WITHHELD — ciphertext included — from every page, every LDAP ' +
         'search and every `/admin-api` reply. A service principal\'s key ' +
         'leaves this service once, as the keytab its create or rotate hands ' +
         'over.'
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
    what: 'Client secrets, RFC 7592 registration access tokens and ' +
          'federation client secrets, WITHOUT a durable key-encryption key',
    where: 'attributes on application and federation entries',
    sealed: false,
    why: 'In the clear only where the process holds no durable ' +
         'key-encryption key — development mode, or a product-mode realm ' +
         'on a development container — because sealing under an ephemeral ' +
         'key would leave a credential that opens to nothing after a ' +
         'restart. With a durable key all three are sealed: see their ' +
         'rows above.'
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

/**
 * Monitoring → Encryption: what is encrypted in the store, with which key,
 * under which algorithm, and how much of it has happened.
 */
class EncryptionAdmin {
  /**
   * See the module's `DATA_CLASSES`.
   */
  static readonly DATA_CLASSES = DATA_CLASSES;

  /**
   * The four acts of `POST /admin/encryption/data-keys` and
   * `POST /admin-api/encryption/:action` (rule 7).
   */
  static readonly ACTIONS = ['rotate-data-keys', 'reencrypt-data-keys',
                             'count-data-keys', 'rotate-kek'];

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the console, settings, crypto, the keystore and the mode
   */
  constructor(private readonly deps: EncryptionAdminDeps) {
    deps.log.debug("Entering EncryptionAdmin.constructor().");
    deps.log.debug("Leaving EncryptionAdmin.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): EncryptionAdminDeps {
    helpers.log.debug("Entering EncryptionAdmin.defaultDeps().");
    helpers.log.debug("Leaving EncryptionAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      config: config,
      crypto: crypto,
      keystore: keystore,
      secrets: secrets,
      mode: mode,
      persistence: persistence,
      minted: minted,
      dataKeyRotation: function (): Json {
        return require('../common/data_key_rotation');
      },
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE MODEL. Built once and rendered twice — HTML and `?format=json` — which
  // is `respond()`'s contract and the reason `/admin-api/encryption` cannot
  // disagree with the page (rule 7).
  // ---------------------------------------------------------------------------
  /**
   * Builds the page's model, the one object behind the page, its `?format=json`
   * and `/admin-api/encryption` (rule 7).
   *
   * @param query - the request's query, which pages the data keys
   *   (`dataKeysPage`, `per`); none for the first page
   * @returns the key-encryption key, the data classes, the data encryption
   * keys and the encryption and decryption counts of this process
   */
  encryptionJson(query?: Json): Json {
    const { log, crypto, keystore, mode } = this.deps;
    const self = this;
    log.debug('Entering EncryptionAdmin.encryptionJson().');
    const report = keystore.report();
    const accounting = crypto.kekAccounting();
    const byLabel = Object.create(null);
    accounting.labels.forEach(function (row) {
      byLabel[row.label] = row;
    });
    const store = self.describeStore();

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
        // THE KEY IN A KEY MANAGEMENT SERVICE (#391 P5): its name there, never
        // a key — a KMS key has no bytes this process could show.
        inKms: !!report.kekInKms,
        kmsKey: report.kekKms ? String(report.kekKms.label || '') : null,
        providerKnown: !!report.kek.known,
        where: report.kek.where,
        providers: report.kek.providers,
        note: report.persisting
          ? 'The key-encryption key is read from the provider above at ' +
            'startup, before the listener binds. This service never ' +
            'generates it and never writes it down, and a service that ' +
            'cannot read it does NOT start — it does not generate a ' +
            'replacement and carry on, because that would stop every token ' +
            'it has ever issued from verifying, silently, at somebody else’s ' +
            'relying party.'
          : 'This service is in development mode, so nothing it holds ' +
            'outlives the process and the key-encryption key is EPHEMERAL: ' +
            'generated per run, never written down, and used only so that ' +
            'the request-worker pool can share minted rows within one run. ' +
            'Sealing a directory attribute under it would be WORSE than the ' +
            'clear — the entry survives a restart in the `ldif` and ' +
            '`postgres` stores and the key does not, so the value would come ' +
            'back as permanent garbage. That is why the test at every write ' +
            'site is `keystore.persists()` rather than `keystore.sealed()`.'
      },
      algorithm: crypto.KEK_PARAMETERS,
      dataKeys: self.dataKeysJson(query || {}),
      algorithmNote:
        'AES-256-GCM and deliberately not CBC: GCM is AUTHENTICATED, so a ' +
        'ciphertext somebody altered fails to decrypt instead of yielding a ' +
        'subtly different key. A signing key that decrypted to the wrong ' +
        'bytes would produce signatures nothing can verify, and the failure ' +
        'would surface at a relying party as "the signature is invalid" — as ' +
        'far from the cause as it is possible to get. The key-encryption key ' +
        'NEVER ENCRYPTS A VALUE (#391): every value is encrypted under a ' +
        'data encryption key — 256 random bits, one per realm per data ' +
        'class — and the data encryption keys are what the key-encryption ' +
        'key wraps. A process unwraps each once and holds it, so a key ' +
        'held in a key management service is asked per data key, never per ' +
        'value, and rotating the key-encryption key re-wraps a handful of ' +
        'keys rather than re-encrypting the store.',
      // ---------------------------------------------------------------------
      // THE TWO LIMITS OF EVERYTHING ABOVE (2026-09-12), and they are on the
      // JSON as well as on the page for `pki_admin.ts`'s `revocationNote`
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
        perRealmDataKey: true,
        realms:
          'THERE IS ONE KEY-ENCRYPTION KEY FOR THIS SERVICE, NOT ONE PER ' +
          'TRUST REALM, AND A DATA ENCRYPTION KEY PER REALM PER DATA CLASS ' +
          '(#391). No data encryption key is shared between realms, so a ' +
          'value of one realm is never sealed under a key another realm\'s ' +
          'values are. But every data encryption key is wrapped under the ' +
          'one key-encryption key, so a realm is NOT an independent ' +
          'boundary at rest: whoever can read that key can unwrap every ' +
          'realm\'s data keys, and rotating it re-wraps every realm\'s at ' +
          'once.',
        storage:
          'EVERYTHING NOT IN THE TABLE ABOVE IS PLAINTEXT IN THE STORE — the ' +
          'directory entries, the groups, the applications, the realms and ' +
          'the settings, and in development mode very nearly all of it. This ' +
          'service seals credentials and private keys and nothing else, ' +
          'deliberately: column-level encryption leaves the plaintext in the ' +
          'write-ahead log, in temporary files when a sort spills, in a ' +
          'pg_dump, on replicas and in query logs, so the layer that covers ' +
          'a whole store belongs UNDER the database rather than inside it. ' +
          'That layer is the operator\'s — LUKS or an encrypted ZFS dataset ' +
          'under PGDATA, a cloud disk with a customer-managed key, or one of ' +
          'the PostgreSQL forks that has TDE, since the community build has ' +
          'none. docs/encryption-at-rest.md is this repository\'s write-up ' +
          'of the options.',
        // The one deployment mistake that makes everything above decorative,
        // and the one this repository's own compose stack invites by mounting a
        // key file beside the database volume.
        keyResidency:
          'AND THE KEY MUST NOT LIVE ON THE DISK IT PROTECTS. A key file on ' +
          'the same unencrypted volume as the store hands both halves to ' +
          'whoever takes the volume; that is fine for a development stack ' +
          'and is why the `file` provider is the default, and it is not a ' +
          'deployment. keys.kekProvider selects a secret store instead.'
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
        '`crypto.js`’s `encryptWithDek()` and `decryptWithDek()`, with ' +
        'the data encryption keys’ own wraps and unwraps under ' +
        '`data-keys` — ' +
        'rather than at the call sites, because a total assembled from call ' +
        'sites is wrong the first time somebody adds another one and is ' +
        'wrong SILENTLY. The breakdown below is by a LABEL each call site ' +
        'passes; a caller that passes none is still counted, under ' +
        '`(unlabelled)`. THESE ARE PROCESS-WIDE AND NOT PER REALM — a ' +
        'key-encryption key belongs to the process, so partitioning the ' +
        'count by realm would be counting the realm a request happened to be ' +
        'in — and they are in memory, so a restart is how you get an empty ' +
        'one.',
      failuresNote:
        'A FAILURE IS ALMOST ALWAYS THE WRONG KEY-ENCRYPTION KEY — a ' +
        'rotated secret, or a store carried between deployments — and it ' +
        'is its own figure rather than being folded into the decryptions, ' +
        'because nine hundred decryptions and nine hundred decryptions with ' +
        'four hundred failures are very different reports. What happens next ' +
        'depends on what was being read: a signing key that will not open is ' +
        'FATAL at startup, a session row is dropped, and a second factor ' +
        'that will not open makes that person unable to sign in until an ' +
        'operator clears the enrolment — never silently absent, which would ' +
        'remove a security control.',
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
    log.debug('Leaving EncryptionAdmin.encryptionJson(). ' +
              out.accounting.operations + ' operation(s).');
    return out;
  }

  // The store, from the module that owns it. **`activeMode()` AND NOT `mode()`,
  // which is the whole of the difference worth knowing here:** the first is
  // what the driver actually opened and the second is the SETTING. They part
  // company only before the configured store has opened — `activeMode()` is
  // `memory` until then, and a store that cannot open stops the service — so a
  // page reading the setting would report that everything this process mints is
  // being sealed into a database it has not reached yet.
  //
  // It is WRAPPED for the reason every other reporter on this console is: the
  // page is about encryption and the store is context, so a persistence layer
  // that will not answer costs a sentence rather than a stack trace.
  private describeStore(): Json {
    const { log, config, persistence, minted } = this.deps;
    log.debug('Entering EncryptionAdmin.describeStore().');
    let active = '';
    let mintedOn = false;
    try {
      active = typeof persistence.activeMode === 'function'
        ? String(persistence.activeMode() || '') : '';
      mintedOn = typeof minted.enabled === 'function' ? !!minted.enabled() :
                 false;
    } catch (e) {
      // Swallowed deliberately: a store that throws while describing itself is
      // still a store, and the page's subject is the encryption rather than the
      // persistence layer. The fallback below reports the SETTING and says so.
      log.debug('Caught in EncryptionAdmin.describeStore(): the ' +
                'persistence layer would not answer: ' + e.message);
    }
    const setting = String(config.value('persistence.mode') || 'memory');
    log.debug('Leaving EncryptionAdmin.describeStore(). active=' +
              (active || setting));
    return {
      mode: active || setting,
      configuredMode: setting,
      // A DRIVER THAT FELL BACK IS SAID OUT LOUD rather than smoothed over, on
      // `/admin/persistence`'s own argument about reporting two facts instead
      // of one tick.
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
  private bytes(n: Json): string {
    const { log } = this.deps;
    log.debug("Entering EncryptionAdmin.bytes().");
    const num = Number(n) || 0;
    if (num < 1024) {
      log.debug("Leaving EncryptionAdmin.bytes().");
      return num + ' B';
    }
    if (num < 1024 * 1024) {
      log.debug("Leaving EncryptionAdmin.bytes().");
      return (num / 1024).toFixed(1) + ' KB';
    }
    log.debug("Leaving EncryptionAdmin.bytes().");
    return (num / (1024 * 1024)).toFixed(1) + ' MB';
  }

  private when(iso: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering EncryptionAdmin.when().");
    log.debug("Leaving EncryptionAdmin.when().");
    return iso ? admin.esc(String(iso).replace('T', ' ').replace(/\..*$/, 'Z'))
               : '<span class="muted">never</span>';
  }

  private classesTable(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug('Entering EncryptionAdmin.classesTable().');
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
             (one.label ? '<br><code>' + admin.esc(one.label) + '</code>'
                        : '') +
             '</td>' +
             '<td>' + counts + '</td>' +
             '<td>' + self.when(one.lastAt) + '</td>' +
             '<td class="why">' + one.why + '</td></tr>';
    }).join('');
    log.debug('Leaving EncryptionAdmin.classesTable().');
    return '<table class="grid"><thead><tr>' +
           '<th>What</th><th>Where it lives</th><th>At rest</th>' +
           '<th>Operations</th><th>Last</th><th>Why</th>' +
           '</tr></thead><tbody>' + rows + '</tbody></table>';
  }

  private unclassifiedBlock(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering EncryptionAdmin.unclassifiedBlock().");
    if (!json.unclassified.length) {
      log.debug("Leaving EncryptionAdmin.unclassifiedBlock().");
      return '';
    }
    log.debug("Leaving EncryptionAdmin.unclassifiedBlock().");
    return admin.warn(
      '<p><strong>' + json.unclassified.length + ' label(s) were counted ' +
      'that ' +
      'this page has no row for:</strong> ' +
      json.unclassified.map(function (row) {
        return '<code>' + admin.esc(row.label) + '</code> (' +
               row.encryptions + ' out, ' + row.decryptions + ' in)';
      }).join(', ') + '.</p>' +
      '<p>That is a call site somebody added without adding a row to ' +
      '<code>DATA_CLASSES</code> in ' +
      '<code>admin-ui/encryption_admin.ts</code>. It is drawn rather than ' +
      'dropped on purpose: the alternative is a table that goes on looking ' +
      'complete while the totals above it do not add up to the rows ' +
      'below.</p>');
  }

  // ---------------------------------------------------------------------------
  // THE DATA ENCRYPTION KEYS (#391 P2): every DEK this process holds, by id,
  // realm, class and state — never a key — paged, with the lifecycle's
  // settings and whether its jobs run. The STATE is computed here from the
  // keystore's own `active`, `activateAt` and `status`, so it is the
  // keystore's answer and not a second opinion.
  // ---------------------------------------------------------------------------
  /**
   * Builds the data-key section of the model.
   *
   * @param query - the request's query, for paging
   * @returns `{ lifecycle, counts, keys, paging }`
   */
  dataKeysJson(query: Json): Json {
    const { log, keystore, dataKeyRotation, adminViews } = this.deps;
    log.debug('Entering EncryptionAdmin.dataKeysJson().');
    const now = Date.now();
    const counts = { current: 0, pending: 0, superseded: 0, destroyed: 0,
                     derived: 0 };
    let counted = 0;
    const rows = keystore.dataKeys().map(function (d: Json): Json {
      const state = d.status === 'destroyed' ? 'destroyed'
        : d.derived ? 'derived'
          : d.active ? 'current'
            : (d.activateAt > now ? 'pending' : 'superseded');
      counts[state] += 1;
      counted = Math.max(counted, Number(d.countedAt) || 0);
      // AGE is from creation; VALUES is the last count of what is sealed
      // under it (`keys.data-key-count`), null where it was never counted.
      return { id: d.id, realm: d.realm, cls: d.cls, scope: d.scope,
               alg: d.alg || 'aes-256-gcm', state: state,
               createdAt: d.createdAt
                 ? new Date(d.createdAt).toISOString() : null,
               activateAt: d.activateAt
                 ? new Date(d.activateAt).toISOString() : null,
               ageDays: d.createdAt
                 ? Math.max(0, Math.floor((now - d.createdAt) / 86400000))
                 : null,
               values: d.values === undefined ? null : d.values,
               countedAt: d.countedAt
                 ? new Date(d.countedAt).toISOString() : null };
    });
    let lifecycle: Json = null;
    try {
      lifecycle = dataKeyRotation().lifecycleView();
    } catch (e) {
      log.debug('Caught in EncryptionAdmin.dataKeysJson(): ' +
                ((e && (e as Error).message) || e));
      lifecycle = null;
    }
    const paged = adminViews().pagedRows(query, rows,
                                         { name: 'dataKeys', noun: 'keys' });
    const out = {
      lifecycle: lifecycle, counts: counts, total: rows.length,
      lastCounted: counted ? new Date(counted).toISOString() : null,
      keys: paged.shown,
      paging: adminViews().pagingJson(paged.paging),
      note: 'One data encryption key per realm and data class seals every ' +
            'value of that class; the key-encryption key only wraps the data ' +
            'keys. A ROTATED data key is superseded: it still opens what it ' +
            'sealed, nothing new is sealed under it, and the re-encryption ' +
            'job re-seals what it sealed and then destroys it. A DERIVED key ' +
            'is made from the key-encryption key per run where nothing ' +
            'outlives the process, and is never stored or rotated.'
    };
    Object.defineProperty(out, 'pagingRaw',
                          { value: paged.paging, enumerable: false });
    log.debug('Leaving EncryptionAdmin.dataKeysJson(). ' + rows.length + '.');
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE TWO ACTS, and the one function the console's form and
  // `POST /admin-api/encryption/:action` both call (rule 7). Each QUEUES a run
  // of `common/data_key_rotation.ts`'s jobs rather than doing the work in the
  // request: a re-encryption pass walks the store.
  // ---------------------------------------------------------------------------
  /**
   * Queues a rotation of the data encryption keys, or a re-encryption pass.
   *
   * @param req - the request, for the actor
   * @param body - `action` (`rotate-data-keys` or `reencrypt-data-keys`), and
   *   for a rotation an optional `realm` and `cls`
   * @param via - how it was asked for, for the audit record
   * @returns `ok` with the run's id and a link to it, or a refusal
   */
  dataKeysAction(req: Req, body: Json, via: string): Json {
    const { log, dataKeyRotation } = this.deps;
    log.debug('Entering EncryptionAdmin.dataKeysAction().');
    const b = body || {};
    const action = String(b.action || '').trim();
    if (EncryptionAdmin.ACTIONS.indexOf(action) < 0) {
      log.debug('Leaving EncryptionAdmin.dataKeysAction(). Unknown action.');
      return { ok: false, errorCode: 'STS-ADMIN-0012', status: 400,
               errors: ['Unknown action "' + action + '". The actions here ' +
                        'are: ' + EncryptionAdmin.ACTIONS.join(', ') + '.'] };
    }
    let actor = '';
    try {
      const state = require('../admin-core/admin_views').gateStateFor(req);
      actor = String((state && state.username) || '');
    } catch (e) {
      log.debug('Caught in EncryptionAdmin.dataKeysAction(): ' +
                ((e && (e as Error).message) || e));
      actor = '';
    }
    const channel = /management API/.test(via) ? 'http' : 'console';
    const realm = b.realm === undefined || b.realm === null ||
      String(b.realm).trim() === '' ? undefined : String(b.realm).trim();
    const cls = String(b.cls || '').trim() || undefined;
    const who = { requestedBy: actor, via: via, channel: channel };
    const answer = action === 'rotate-data-keys'
      ? dataKeyRotation().requestRotation(Object.assign({ realm: realm,
                                                          cls: cls }, who))
      : action === 'reencrypt-data-keys'
        ? dataKeyRotation().requestReencryption(who)
        : action === 'count-data-keys'
          ? dataKeyRotation().requestCount(who)
          : dataKeyRotation().requestKekRotation(who);
    if (!answer.ok) {
      log.debug('Leaving EncryptionAdmin.dataKeysAction(). Refused.');
      return { ok: false, errorCode: answer.errorCode,
               status: answer.status || 400, errors: [answer.why] };
    }
    log.debug('Leaving EncryptionAdmin.dataKeysAction(). ' + answer.runId);
    return {
      ok: true, accepted: true, runId: answer.runId,
      href: '/admin/scheduler?run=' + encodeURIComponent(answer.runId),
      message: (action === 'rotate-data-keys'
        ? 'A rotation of ' + (realm !== undefined || cls
          ? 'the data encryption keys' + (realm !== undefined
            ? ' of the realm "' + realm + '"' : '') +
            (cls ? ' for the class "' + cls + '"' : '')
          : 'every data encryption key')
        : action === 'reencrypt-data-keys' ? 'A re-encryption pass'
          : action === 'count-data-keys'
            ? 'A count of the values under every data encryption key'
            : 'A rotation of the key-encryption key in its key management ' +
              'service') +
        ' was queued as run ' + answer.runId + '. It runs on the ' +
        'scheduler\'s leader at its next tick.'
    };
  }

  // The section drawn under the algorithm: the lifecycle, the keys, and —
  // for Admin Write, where keys are stored — the two forms. No script.
  private renderDataKeys(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug('Entering EncryptionAdmin.renderDataKeys().');
    const dk = json.dataKeys;
    const life = dk.lifecycle;
    const status = !life ? '<p class="warn">The data-key rotation module ' +
        'is not loaded in this process, so nothing here can be rotated.</p>'
      : '<p>' + (life.on
        ? (life.scheduled
          ? 'Every data encryption key is rotated after <strong>' +
            admin.esc(String(life.rotationDays)) + ' day(s)</strong> ' +
            '(<code>keys.dataKeyRotationDays</code>); a new key is used ' +
            admin.esc(String(life.activationLeadSeconds)) + ' second(s) ' +
            'after it is published, and a replaced key is destroyed no ' +
            'sooner than ' + admin.esc(String(life.retireAfterDays)) +
            ' day(s) after, once nothing is sealed under it.'
          : 'Scheduled rotation is <strong>off</strong>: ' +
            admin.esc(life.scheduleOffReason) + '. A rotation by hand ' +
            'still works.')
        : 'Nothing is rotated here: ' + admin.esc(life.offReason) + '.') +
      ' Data stored in the directory is sealed with <code>' +
      admin.esc(life.directoryCipher) + '</code> ' +
      '(<code>keys.directoryCipher</code>); everything else with ' +
      '<code>aes-256-gcm</code>.</p>' +
      (life.on ? '<p>' + (life.counting
        ? 'What is sealed under each key is counted once a day ' +
          '(<code>keys.data-key-count</code>)' + (dk.lastCounted
            ? ', last at ' + admin.esc(dk.lastCounted) : ', and has not ' +
              'been counted yet') + '.'
        : 'Values are not counted: ' + admin.esc(life.countOffReason) +
          '.') + '</p>' : '');
    const tiles = '<div class="tiles">' +
      admin.tile(String(dk.counts.current), 'current') +
      admin.tile(String(dk.counts.pending), 'waiting to be used') +
      admin.tile(String(dk.counts.superseded), 'superseded') +
      admin.tile(String(dk.counts.destroyed), 'destroyed') +
      admin.tile(String(dk.counts.derived), 'derived per run') +
      '</div>';
    const params = this.deps.adminViews().pageParamsOf(req.query || {});
    const nav = admin.pageNavPair('/admin/encryption', params, dk.pagingRaw);
    const table = dk.keys.length
      ? nav.head + '<table class="grid"><thead><tr><th>Realm</th>' +
        '<th>Class</th><th>Cipher</th><th>State</th><th>Created</th>' +
        '<th>Used from</th><th>Age (days)</th><th>Values</th>' +
        '<th>Key id</th></tr></thead><tbody>' +
        dk.keys.map(function (k: Json): string {
          return '<tr><td><code>' + admin.esc(k.realm) + '</code></td>' +
            '<td><code>' + admin.esc(k.cls) + '</code></td>' +
            '<td><code>' + admin.esc(k.alg) + '</code></td>' +
            '<td>' + admin.esc(k.state) + '</td>' +
            '<td>' + admin.esc(k.createdAt || '—') + '</td>' +
            '<td>' + admin.esc(k.activateAt || '—') + '</td>' +
            '<td>' + admin.esc(k.ageDays === null ? '—'
                                                  : String(k.ageDays)) +
            '</td>' +
            '<td' + (k.countedAt ? ' title="counted ' +
                     admin.esc(k.countedAt) + '"' : '') + '>' +
            admin.esc(k.values === null ? '—' : String(k.values)) + '</td>' +
            '<td>' + admin.clipped(k.id, 40) + '</td></tr>';
        }).join('') + '</tbody></table>' + nav.foot
      : '<p class="muted">No data encryption key is held yet: one is made ' +
        'the first time a value of its realm and class is sealed.</p>';
    let forms = '';
    if (life && life.on && admin.mayWrite(req)) {
      forms = '<h4>Rotate by hand</h4>' +
        '<form method="post" action="/admin/encryption/data-keys">' +
        '<input type="hidden" name="action" value="rotate-data-keys">' +
        '<label>Realm (empty for every realm): <input type="text" ' +
        'name="realm" id="data-keys-realm" autocomplete="off"></label> ' +
        '<label>Class (empty for every class): <input type="text" ' +
        'name="cls" id="data-keys-cls" autocomplete="off"></label> ' +
        '<button type="submit" id="data-keys-rotate">Rotate data keys' +
        '</button></form>' +
        '<p class="muted">Each key gets a successor, used once it has been ' +
        'published; what the old key sealed is re-sealed by the ' +
        're-encryption job.</p>' +
        '<form method="post" action="/admin/encryption/data-keys">' +
        '<input type="hidden" name="action" value="reencrypt-data-keys">' +
        '<button type="submit" id="data-keys-reencrypt">Re-encrypt now' +
        '</button> — re-seals what is still under a superseded key, and ' +
        'destroys a superseded key nothing is sealed under that has been ' +
        'superseded long enough.</form>' +
        (life.counting
          ? '<form method="post" action="/admin/encryption/data-keys">' +
            '<input type="hidden" name="action" value="count-data-keys">' +
            '<button type="submit" id="data-keys-count">Count now</button> ' +
            '&mdash; counts what is sealed under every key, in one pass of ' +
            'the store.</form>'
          : '') +
        '<h4>Rotate the key-encryption key</h4>' +
        (life.kekRotation
          ? '<form method="post" action="/admin/encryption/data-keys">' +
            '<input type="hidden" name="action" value="rotate-kek">' +
            '<button type="submit" id="kek-rotate">Rotate the ' +
            'key-encryption key</button> &mdash; the key management ' +
            'service makes a new version, and every data key is re-wrapped ' +
            'under it. The earlier version stays: data keys other nodes ' +
            'wrapped under it still unwrap. The identity this service runs ' +
            'as must be allowed to rotate the key, which the deployments ' +
            'here do not grant: they rotate it on the KMS\'s own ' +
            'schedule.</form>'
          : '<p class="muted">Not from here: ' +
            admin.esc(life.kekRotationOffReason) + '.</p>');
    }
    log.debug('Leaving EncryptionAdmin.renderDataKeys().');
    return status + tiles + '<p class="muted">' + admin.esc(dk.note) +
           '</p>' + table + forms;
  }

  private renderEncryption(req: Req, res: Res): void {
    const { log, admin } = this.deps;
    const self = this;
    log.debug('Entering EncryptionAdmin.renderEncryption().');
    const json = self.encryptionJson(req.query || {});

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
      'which key, under which algorithm, and how much of it has ' +
      'happened</strong>. It is under Monitoring rather than beside the ' +
      'other two cryptography pages because of what it is: <a ' +
      'href="/admin/crypto-metadata">the crypto report</a> says what this ' +
      'service <em>does</em> when it signs or encrypts and reads the same on ' +
      'a service that started a second ago, and <a href="/admin/keys">the ' +
      'keys page</a> says what one realm <em>holds</em>. The numbers here go ' +
      'up while you watch.</p><p><strong>Neither a sealed value nor an ' +
      'opened one appears on this page.</strong> A sealed value is a private ' +
      'key, an authenticator&rsquo;s shared secret or somebody&rsquo;s ' +
      'recovery codes, and printing either half of one would hand over ' +
      'exactly what the sealing exists to protect. Its only controls rotate ' +
      'the data encryption keys, re-seal and count what they sealed, and ' +
      'rotate a key-encryption key that is in a key management service ' +
      '(which makes the new version itself), and they show nothing. A ' +
      'key-encryption key READ into this process is rotated by deploying ' +
      'its successor &mdash; this service reads one and never writes one ' +
      '&mdash; and a <em>decrypt this</em> button would be the one door ' +
      'onto material no door is supposed to have.</p>',
      'What this page is, and the two things it deliberately has not got');

    const keyBlock = admin.note(
      '<p>The key-encryption key is read by <code>common/secrets.js</code> ' +
      'from <strong>' + admin.esc(json.key.providerLabel) + '</strong> ' +
      '(<code>' + admin.esc(json.key.provider) + '</code>)' +
      (json.key.kmsKey ? ' &mdash; <strong>' + admin.esc(json.key.kmsKey) +
        '</strong>, which never leaves it: the service holds a handle, ' +
        'not the key, and asks it to wrap and unwrap each data key' : '') +
      ', once, at startup ' +
      'and before the listener binds. <code>file</code> is the default ' +
      'because it needs nothing: Kubernetes mounts a Secret as a file, ' +
      'Docker mounts a secret as a file, and every other provider here is ' +
      'that same idea with somebody else&rsquo;s access control in front of ' +
      'it.</p><p>' + json.key.note + '</p>' +
      '<p><strong>A key shorter than 32 bytes is REFUSED rather than ' +
      'stretched.</strong> Stretching would let a four-character password ' +
      'protect every signing key this service holds while the log said ' +
      'AES-256. Hex is tried before base64, because a 64-character hex ' +
      'string is also valid base64 and reading it that way produces 48 ' +
      'different bytes.</p><p class="muted">Available providers: ' +
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
       ['Data keys', json.algorithm.dataKeys],
       ['Data key wrapping', json.algorithm.dekWrap],
       ['Authenticated data', json.algorithm.aad],
       ['Envelope', json.algorithm.envelope]].map(function (pair) {
        return '<tr><th>' + admin.esc(pair[0]) + '</th><td><code>' +
               admin.esc(String(pair[1])) + '</code></td></tr>';
      }).join('') +
      '</tbody></table>' +
      '<p class="muted">Every figure in that table is read out of ' +
      '<code>common/crypto.js</code>&rsquo;s own <code>KEK_PARAMETERS</code> ' +
      'rather than written down here &mdash; the same rule ' +
      '<a href="/admin/crypto-metadata">the crypto report</a> follows about ' +
      'reading an algorithm table from the module that performs the ' +
      'algorithm, so this page cannot go on looking complete while being ' +
      'wrong.</p>',
      'The algorithm, and why it is authenticated');

    const countsBlock = admin.note(
      '<p>' + json.accountingNote + '</p><p>' + json.failuresNote + '</p>' +
      '<p class="muted">Since ' + self.when(json.accounting.since) +
      '. First operation ' + self.when(json.accounting.firstAt) +
      ', most recent ' + self.when(json.accounting.lastAt) + '. ' +
      admin.esc(self.bytes(json.accounting.plaintextBytes)) +
      ' of plaintext has ' +
      'passed through, producing ' +
      admin.esc(self.bytes(json.accounting.ciphertextBytes)) +
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
                  self.classesTable(json) +
                  self.unclassifiedBlock(json) +
                  '<h3>The key</h3>' + keyBlock + boundsBlock +
                  '<h3>The algorithm</h3>' + algBlock +
                  '<h3>The data encryption keys</h3>' +
                  self.renderDataKeys(req, json) +
                  '<h3>The counting</h3>' + countsBlock +
                  storeBlock);
    log.debug('Leaving EncryptionAdmin.renderEncryption().');
  }

  // For `tests/encryption_report.js`, which checks the table against the
  // labels the call sites actually pass. Exported for `pki_authoring.js`'s
  // reason: a class described here and never sealed, or sealed and never
  // described, is an error nothing else in this service can see.
  /**
   * Answers the data-class table, for the test that checks it against the
   * labels the call sites pass.
   *
   * @returns the data classes
   */
  dataClasses(): typeof DATA_CLASSES {
    const { log } = this.deps;
    log.debug("Entering EncryptionAdmin.dataClasses().");
    log.debug("Leaving EncryptionAdmin.dataClasses().");
    return DATA_CLASSES.slice();
  }

  /**
   * Registers `GET /admin/encryption`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering EncryptionAdmin.registerRoutes().");
    app.get('/admin/encryption', function (req, res) {
      log.debug('Entering GET /admin/encryption.');
      self.renderEncryption(req, res);
      log.debug('Leaving GET /admin/encryption.');
    });
    // THE DATA-KEY ACTS (#391 P2). Admin Write; a service page, so a realm's
    // own administrator never reaches it (`admin_scope.ts`).
    app.post('/admin/encryption/data-keys', function (req, res) {
      log.debug('Entering POST /admin/encryption/data-keys.');
      if (!admin.mayWrite(req)) {
        require('../common/error_codes').mark(res, 'STS-ADMIN-0012');
        admin.respondToAction(req, res, '/admin/encryption', { ok: false,
          errors: ['Rotating data encryption keys needs the Admin Write ' +
                   'role.'] });
        log.debug('Leaving POST /admin/encryption/data-keys. Read-only.');
        return;
      }
      const result = self.dataKeysAction(req, helpers.parseBody(req),
                                         'the admin console');
      if (!result.ok) {
        require('../common/error_codes').mark(res,
          result.errorCode || 'STS-ADMIN-0012');
      }
      admin.respondToAction(req, res,
                            result.ok ? result.href : '/admin/encryption',
                            result);
      log.debug('Leaving POST /admin/encryption/data-keys. ' + result.ok);
    });
    log.debug("Leaving EncryptionAdmin.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<EncryptionAdmin>(
  'admin-ui/encryption_admin',
  () => new EncryptionAdmin(EncryptionAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

helpers.log.info('The encryption report is at /admin/encryption: what this ' +
                 'service seals at rest, with which key and under which ' +
                 'algorithm, and how many encryptions and decryptions have ' +
                 'happened in this process.');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Monitoring → Encryption, `/admin/encryption`: what this service seals at
 * rest, with which key and under which algorithm, and how many encryptions and
 * decryptions have happened in this process.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  EncryptionAdmin: EncryptionAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: EncryptionAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts`. Rule 7 — the page and the operation read one
  // function, so the API cannot report a different number from the console.
  encryptionView: slot.forward('encryptionJson'),
  // For `mgmt-api/admin_api.ts`'s `/encryption/:action` (rule 7, #391 P2).
  dataKeysAction: slot.forward('dataKeysAction'),
  // For `tests/encryption_report.js` — see `EncryptionAdmin.dataClasses()`.
  dataClasses: slot.forward('dataClasses')
};
