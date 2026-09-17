'use strict';
//
// File: admin-ui/crypto_metadata.ts
//
// ---------------------------------------------------------------------------
// GET /admin/crypto-metadata — WHAT THIS SERVICE DOES WITH CRYPTOGRAPHY, for
// every identity service it advertises, and with which algorithms.
//
// `/admin/sts-metadata` answers "what can I call, and what specification is it
// pretending to implement". This page answers the question that sits underneath
// it and that nothing here could answer before: **when this service signs,
// verifies, encrypts or decrypts something, what does it actually use** — which
// digest, which signature algorithm, which cipher, which key, and which of the
// several higher-level envelopes (JWS, JWE, XMLDSIG, XML Encryption,
// WS-Security, COSE, X.509) that primitive is wrapped in.
//
// It was worth a page of its own for a reason this repository has met before:
// the answer was spread over eleven modules and four vendored ones, and every
// prose statement of it was a copy that could drift. `common/crypto.js`
// centralised the CODE in 2026-08-27 and did not centralise the DESCRIPTION —
// so "which algorithms does this thing speak" was still answered by reading
// six tables in four files, and the console, which exists precisely so that
// nobody has to, said nothing about any of them.
//
// ---------------------------------------------------------------------------
// EVERY TABLE ON THIS PAGE IS READ FROM THE MODULE THAT PERFORMS THE
// ALGORITHM. THAT IS THE WHOLE DESIGN, AND IT IS `sts_metadata.js`'S
// ARGUMENT ONE LEVEL DOWN.
//
// That page walks the live express router rather than keeping a list of routes,
// because a hand-kept list next to the routes goes stale the first time
// somebody adds one and the failure is silent in the worst direction — the page
// still looks complete. An algorithm table is the same shape of thing. So:
//
//   JWS signature algorithms   `stsCrypto.JWS_ALGS`, which is THE table for
//                              this service — dpop.js had a second one once and
//                              that is how DPoP came to accept a different set
//                              from everything else for no reason anybody chose.
//   post-quantum and composite `pqJose.PQ_ALGS` / `pqJose.COMPOSITES`
//   JWE                        `stsCrypto.JWE_ALGS`, `JWE_DECRYPT_ALGS`,
//                              `JWE_ENCS`
//   XML signature / digest /   `xmldsig.SIG_METHODS`, `DIGEST_METHODS`,
//   canonicalization           `C14N_METHODS` — the VENDORED module, which is
//                              the other end of most of these exchanges
//   XML encryption             `stsCrypto.BLOCK_CIPHERS`, `KEY_TRANSPORTS`
//   Kerberos encryption types  `krb5crypto.ETYPES`, and the decode-only names
//                              read back through `etypeName()` rather than
//                              copied — see `kerberosEtypes()`
//   SPIFFE authority keys      `spiffeCa.KEY_TYPES`
//   WebAuthn                   `webauthn.COSE_ALGS` / `COSE_CURVES`
//   DPoP                       `dpop.SIGNING_ALGS`, which is a FILTER over the
//                              shared table and must stay visible as one
//   client authentication      `clientAuth.SYMMETRIC_METHODS` / `ASYMMETRIC_METHODS`
//   ID Token / UserInfo        `oauth2.ID_TOKEN_SIGNING_ALGS` /
//                              `USERINFO_SIGNING_ALGS`
//   the TLS certificate        `tlsServer.serverCertificate()`
//   the signing keys           `helpers.stsKeysFor()`, for the AMBIENT REALM
//
// Only two things here are written by hand, and both are things no table can
// hold: the per-family prose in `FAMILIES` (what each identity service signs
// and why) and `STANDARDS` (which document an envelope comes from and how much
// of it is really implemented). Both follow `sts_metadata.js`'s rule for the
// same reason — written CONSERVATIVELY, saying where this service does LESS
// than the specification, because a list that overstates is worse than no list
// at all in a tool people use to learn these specifications.
//
// ---------------------------------------------------------------------------
// THE FAMILY LIST IS CHECKED AGAINST `sts_metadata.js` RATHER THAN AGREED WITH
// IT, AND THAT IS WHY THERE IS A SLOT.
//
// The page reports on the identity services this mock ADVERTISES, so the list
// of them must be the same list `/admin/sts-metadata` draws its cards from. Two
// tables naming the same protocol families (fourteen when this was written,
// more than twenty now) are two tables that will disagree the first time
// another arrives — and the disagreement would be invisible,
// because each page would look complete on its own.
//
// So `sts_metadata.js` hands its `PROTOCOLS` over at its own require time
// (`setProtocolFamilies()`), and this page reports BOTH directions of drift the
// way that page reports both directions of endpoint drift: a family this mock
// advertises with no crypto profile here, and a profile here naming a family
// that is not advertised. A slot rather than a require because rule 3e's test
// answers yes — a `require('../sts_metadata')` from this file would load that
// module HERE, and its one constraint is that it is required LAST, so the
// require would take the last module in `common/protocol_stack.ts` and make
// it not last. (`sts_metadata.js` is still JavaScript, so requiring it still
// registers its routes; #50's R1 did not change this.)
//
// The slot is optional in the only direction that matters: with nothing in it
// the page draws its own table and says the check did not run, rather than
// failing. A process that loaded this module and not that one is not a process
// whose crypto report should be a 500.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS IN THE REQUIRE ORDER, AND WHY EVERY REQUIRE BELOW IS A CACHE
// HIT.
//
// `common/protocol_stack.ts` requires this module at 20a — after
// `tls/tls_server` (20) and before `ldap/ldap_server` (21) — and registers
// its routes on the next line. That position is a DEPENDENCY and not a
// preference: this file reads tables out of many other modules (eleven when
// this was written; the list below names the originals), and requiring one
// of them that the stack has not yet loaded would REGISTER ITS ROUTES HERE
// (rule 1). **Since #50's R1 (2026-09-16) that is true only of the modules
// still written in JavaScript** — `tls/tls_server.js` below, and
// `kerberos/krb5_kdc.js`, which loads `krb5_crypto`; a converted module
// registers nothing when required,
// and the composition root registers its routes at its own place — but an
// early require of a converted one would still run its load-time work (its
// slot fills, its stores) out of the order the stack argues. At 20a every one
// of them is already loaded, so every require below is a cache hit that
// registers nothing and moves nothing:
//
//   common/crypto, common/pq_jose, the vendored xmldsig and bbs2023   leaves
//   kerberos/krb5_crypto                loaded at 15 by krb5_kdc
//   authn/webauthn                      loaded at 8 by authn.js
//   oauth-oidc/{oauth2,dpop,client_auth,mtls}   loaded at 9
//   spiffe/spiffe_ca                    loaded at 18, by admin-core/ under
//                                       admin.js
//   admin-ui/admin                      loaded at 18 — the SHELL, and the gate
//   tls/tls_server                      loaded at 20, for its certificate
//
// The gate is admin.js's one `app.use('/admin', ...)`, registered at 18 (by
// `common/protocol_stack.ts`'s `register()` call for `admin-ui/admin`) and
// therefore above this route: express applies middleware only to routes added
// after it, so this page is behind the console's sign-on and its two roles by
// construction, exactly like `/admin/sts-metadata`. Nothing here repeats that
// check — a second opinion about who may read this page is a second thing to
// get wrong.
//
// **THIS PAGE PUBLISHES NO PRIVATE KEY AND NO SECRET.** It names key TYPES,
// key identifiers, curve names, certificate fingerprints and validity dates —
// everything a caller can already read off `/oauth2/jwks`,
// `/tls/server-certificate` and the SPIFFE bundle endpoint — and nothing that
// is not already published somewhere. That is a rule for anything added here
// later, not an observation about what is here now: this is a console page
// about cryptography, which makes it exactly the page somebody would think to
// put a private key on.

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that has routes (rule 1):
//
//   * **`CryptoMetadata` TAKES EVERY MODULE IT READS THROUGH ITS
//     CONSTRUCTOR** — the shell, the logger, `common/crypto.js` and the other
//     modules whose tables this page reports — as `CryptoMetadataDeps`. The
//     five modules this file required INSIDE functions (the revocation
//     policy, GNAP's three libraries, ACME's, EST's two and SCEP's) arrive as
//     LOADER FUNCTIONS, called where the requires were, so they stay lazy:
//     each is required after this file in the require order, and GNAP's
//     biscuit format pays for a WebAssembly module at load.
//   * **`FAMILIES` IS BUILT BY THE CONSTRUCTOR**, because every row's
//     `algorithms()` reads a module the constructor was given. `STANDARDS` is
//     plain data and stays a module-level constant.
//   * **`registerRoutes(app)` HOLDS THE THREE ROUTES** in their old order.
//     The module exports it, and `common/protocol_stack.ts` calls it at 20a,
//     where requiring this module used to register them (#50, R1) —
//     requiring the module registers nothing. It also exports every old name
//     — `setProtocolFamilies` (the slot `sts_metadata.js` fills) and the rest,
//     `FAMILIES` and `STANDARDS` as the same arrays.
//   * **R2 (#50): THE COMPOSITION ROOT BUILDS THE INSTANCE** and installs it;
//     this module builds none of its own. The exports are FACADES that
//     forward to that instance, for the JavaScript callers, and `FAMILIES` is
//     a getter onto the instance's table. Filling `admin.js`'s
//     `setCryptoReporter()` slot is `CryptoMetadata.wire()`, run when the
//     instance is installed. A process without the root builds a default
//     instance at load, as loading this module always did.
//   * **THE FOUR REQUIRES THAT CAME AFTER `module.exports`** — node's
//     `crypto`, the vendored `key_material.js`, `common/pki` (twice, under two
//     names) and `common/keystore` — are in the import block now. They are
//     leaves that register nothing and are already loaded by 18a, so reading
//     them before the routes rather than after changes nothing.
//   * **THE SLOT STATE** — the list `setProtocolFamilies()` was given — stays
//     a module-level `let` with one writer, the setter, now a method.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import config = require('../common/config');
// THE ERROR CODES (common/error_codes.js, a leaf). The key export marks its
// refusals on the RESULT under the non-enumerable Symbol `mark()` uses, so
// `/admin-api/keys/export` sends the same JSON and this page reads the code
// back with `errorCodes.codeOf()` to mark its own response.
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
// The console's SHELL and its prose helpers, exactly as `../sts_metadata.js`
// takes them: `respond()` answers ?format=json itself and wraps the body in the
// two columns, and `note()`/`warn()`/`bullet()`/`tip()` are what make prose on
// a console page fold instead of being a wall of text. Nothing about what this
// page SAYS comes from that module.
import admin = require('./admin');
// THE ONE PLACE THIS SERVICE SIGNS, VERIFIES, ENCRYPTS AND DECRYPTS, and
// therefore the source of most of this page. `stsCrypto.xmldsig` is the
// vendored module re-exported, which is taken from here rather than required
// again so that there stays exactly one spelling of it in the process.
import stsCrypto = require('../common/crypto');
import pqJose = require('../common/pq_jose');
import bbs2023 = require('../common/vendored/bbs2023.js');
import krb5crypto = require('../kerberos/krb5_crypto');
import spiffeCa = require('../spiffe/spiffe_ca');
import webauthn = require('../authn/webauthn');
// The ceremony's OPTIONS, for the row below. A LIBRARY (rule 3): it registers
// no route, and it requires only `config`, `helpers` and the verifier above —
// so this line can neither move a route nor close a cycle, which is the test
// every require in this file's list has to pass.
import webauthnPolicy = require('../authn/webauthn_policy');
// RFC 6238's own algorithm table, read from the module that performs the
// algorithm — this page's whole design. A LIBRARY (rule 3) that registers no
// route, so requiring it here cannot move one, and it is already loaded by
// `common/credentials.ts` long before this line.
import totp = require('../common/totp');
import backupCodes = require('../common/backup_codes');
import dpop = require('../oauth-oidc/dpop');
import clientAuth = require('../oauth-oidc/client_auth');
import mtls = require('../oauth-oidc/mtls');
import oauth2 = require('../oauth-oidc/oauth2');
// RFC 9701's lists, read off the library that signs and encrypts the JWT
// introspection response rather than written out here.
import introspectionJwt = require('../oauth-oidc/introspection_jwt');
// RFC 9101's request object lists, read off the application registry, which
// reads them off `common/crypto.js` — the tables `request_object.js` verifies
// and decrypts against.
import applicationRegistry = require('../common/applications');
import tlsServer = require('../tls/tls_server');
// A certificate's details in a dialog over this page (2026-09-13): the model's
// fingerprint, and the one renderer `/admin/pki` draws the same dialog with.
// Both are libraries and register nothing, so this require moves no route.
import certificateDetails = require('../common/certificate_details');
import certificateDialog = require('./certificate_dialog');
import certificateViews = require('../admin-core/certificate_views');
// Which key pairs use a post-quantum algorithm, and the one icon that says so
// (2026-09-13) — `/admin/pki` draws with the same pair. See pqc_badge.ts.
import pqcSupport = require('../common/pqc_support');
import pqcBadge = require('./pqc_badge');

import scimAuth = require('../scim/scim_auth');
// The Shared Signals event catalogue and its gate. BOTH ARE LIBRARIES that
// register no route — `ssf/ssf.ts`, which has routes, is deliberately NOT
// required here: `common/protocol_stack.ts` loads it after this module, so
// requiring it would have registered every /ssf endpoint and the well-known
// document AT THIS POINT in the router (rule 1), ahead of ldap, scim and
// spiffe. Since #50's R1 (2026-09-16) such a require would register no route
// — the stack registers SSF's at 23b wherever the module was loaded — but it
// would still load the whole family, and fill its slots on the console, from
// inside this one's require. What this page needs is the algorithm and the
// scheme list, and those are exactly what the two leaves hold. `ssf_auth`
// requires `oauth-oidc/dpop`, which this file already requires two lines up,
// so it is a cache hit like every other require here.
import ssfEvents = require('../ssf/ssf_events');
import ssfAuth = require('../ssf/ssf_auth');

// THE KEY PAIRS' OWN REQUIRES, which sat below `module.exports` in the
// JavaScript — see the TypeScript header above for why they are here now.
import nodeCrypto = require('crypto');
// The debugger's own keystore code, vendored. Named `keystore` here because
// `keyMaterial()` below is this file's REPORT on the keys and this is the
// thing that EXPORTS them — two different jobs that would otherwise share a
// name three hundred lines apart.
import keystore = require('../common/vendored/key_material.js');
// THE CERTIFICATE AUTHORITY'S OWN REPORT. A LIBRARY (rule 3) requiring
// `config`, `crypto`, `keystore`, `realms` and the two vendored PKI modules —
// it registers no route, so this require can move nothing and close nothing.
import pki = require('../common/pki');
// **AND `stsKeystore` FOR THIS SERVICE'S OWN, WHICH IS A THIRD NAME IN THE
// SAME NEIGHBOURHOOD ON PURPOSE.** `keyMaterial()` reports on the keys,
// `keystore` above EXPORTS them, and this one decides whether they persist and
// how long a decrypted private key may sit in memory. The header on
// `renderKeyPairs()` records what a name collision in this file already cost;
// a fourth thing called `keystore` would have been the same 500 a third time.
// A LEAF (rule 3): it registers nothing and requires nothing this file does
// not already have loaded.
import stsKeystore = require('../common/keystore');
// The certificate authority, for WHICH AUTHORITY certified each key. A LEAF
// (rule 3w): it registers no route, so requiring it here moves nothing. The
// same module as `pki` above, under the name the key-pair code reads it by.
import stsPki = require('../common/pki');
import InstanceSlot = require('../common/instance_slot');

// ---------------------------------------------------------------------------
// THE HIGHER-LEVEL STANDARDS — the envelopes the primitives above travel in.
//
// A reader who knows that this service signs with RSA-SHA256 still does not
// know whether that signature is a JWS, an enveloped XMLDSIG, a detached
// signature over a query string or a `<wsse:Security>` header, and those are
// four different documents with four different failure modes. This table is
// that layer, and every row is keyed by the short name `FAMILIES` above cites
// in its `envelopes` — so a family naming an envelope that is not here is
// reported by `driftReport()` rather than rendering as a dead link.
//
// `coverage` MUST START `full`, `partial` OR `mock`, which is the rule
// `sts_metadata.js` states for its own specification list and which is worth
// more here than there: this is a page about cryptography, and a page about
// cryptography that overstates what it implements is actively dangerous to
// somebody using it to learn.
//
// **WS-SECURITY IS THE ROW TO READ BEFORE ARGUING WITH THIS TABLE**, and it is
// the one people ask about by two names that are not specifications. There is
// no OASIS document called "WS-Integrity" and none called "WS-Encryption": WSS
// (Web Services Security: SOAP Message Security) is one specification, and the
// integrity half is XML Signature applied to the SOAP Body and Timestamp
// through a `<wsse:Security>` header, while the confidentiality half is XML
// Encryption applied the same way. This service does NEITHER of those, and
// saying so plainly is the point of the row: what it does is put a SIGNED SAML
// ASSERTION inside a SOAP body, which is the SAML Token Profile and not
// message-level security. The vendored `xmldsig.js` can produce a real
// `<wsse:Security>` signature — `signSoapMessage()` is in it, and the debugger
// uses it — and nothing here calls it.
// ---------------------------------------------------------------------------
const STANDARDS = [
  { key: 'jws', name: 'JWS — JSON Web Signature',
    specs: ['RFC 7515', 'RFC 7518 (JWA)', 'RFC 8037 (EdDSA)',
            'RFC 8812 (ES256K)', 'RFC 9964 (AKP / ML-DSA)'],
    coverage: 'full for the algorithms listed below. Compact ' +
              'serialization is produced and read everywhere; the FLATTENED ' +
              'JSON serialization is read by exactly one family, ACME, ' +
              'because RFC 8555 section 6.2 requires it (each request is ' +
              'recomposed into compact form and verified by the same ' +
              'function). The general JSON serialization is neither produced ' +
              'nor read; nothing here asks for one.',
    what: 'The envelope for every token this service mints and every ' +
          'assertion it is handed. ONE TABLE FOR THE WHOLE SERVICE — ' +
          '`common/crypto.js`\'s `JWS_ALGS` — because there were two once, ' +
          'and that is how DPoP came to accept a different set of algorithms ' +
          'from everything else for no reason anybody chose.' },
  { key: 'jwe', name: 'JWE — JSON Web Encryption',
    specs: ['RFC 7516', 'RFC 7518'],
    coverage: 'partial: compact serialization, and it ENCRYPTS with a longer ' +
              'list than it DECRYPTS with. That asymmetry is deliberate — ' +
              'what it receives is encrypted to the RSA key it publishes, ' +
              'and it holds no EC private key to agree with.',
    what: 'An encrypted UserInfo response, and anything a client sends ' +
          'encrypted to this service\'s key. The CBC-HMAC family is here ' +
          'because `A128CBC-HS256` is what an OpenID Connect client gets by ' +
          'DEFAULT: register `userinfo_encrypted_response_alg` and say ' +
          'nothing about `enc`, and section 2 of the registration ' +
          'specification has chosen it for you.' },
  { key: 'jwk', name: 'JWK — JSON Web Key and JWK Set',
    specs: ['RFC 7517', 'RFC 7638 (thumbprint)'],
    coverage: 'full for publication. The published JWKS carries NO `alg` ' +
              'member, and its absence is deliberate: RFC 7517 section 4.4 ' +
              'makes it optional and says it names the INTENDED algorithm, ' +
              'and one RSA key here signs six of them. It said `RS256` until ' +
              '2026-08-28 and that was a promise the service had stopped ' +
              'keeping — Web Crypto refuses to import a JWK whose `alg` ' +
              'disagrees with the operation asked of it.',
    what: 'How every public key here is published, and how a client\'s own ' +
          'key is read. The RFC 7638 thumbprint is what DPoP binds to.' },
  { key: 'jwt', name: 'JWT — JSON Web Token',
    specs: ['RFC 7519', 'RFC 9068 (JWT access tokens)'],
    coverage: 'full for what it mints; `partial` for what it reads, because ' +
              'it verifies no access token it did not issue except at ' +
              'UserInfo.',
    what: 'The claim set inside the JWS. `oauth2.clockSkewS` is applied ' +
          'wherever this service reads back a token it signed, in ONE place ' +
          'since 2026-08-27 — four of the ten call sites that used to do it ' +
          'had quietly stopped.' },
  { key: 'thumbprint', name: 'JWK Thumbprint',
    specs: ['RFC 7638'],
    coverage: 'full for RSA, EC, OKP and oct, which is every key type the ' +
              'RFC defines members for. THERE IS NO THUMBPRINT FOR `AKP`, ' +
              'the post-quantum key type, and that is why the PQ algorithms ' +
              'are excluded from DPoP.',
    what: 'One canonicalization, one SHA-256, one place — there were two ' +
          'implementations of it here before 2026-08-27.' },
  { key: 'dpop', name: 'DPoP — Demonstrating Proof of Possession',
    specs: ['RFC 9449'],
    coverage: 'full: all twelve of section 4.3\'s checks, the `cnf.jkt` ' +
              'binding on access AND refresh tokens, `dpop_jkt`, `jti` ' +
              'replay detection and the nonce handshake in both shapes. NOT ' +
              'required — nonce mode makes proofs fresher, not mandatory.',
    what: 'The sender constraint that makes a stolen access token worthless ' +
          'without the key. Its algorithm list is a FILTER over the shared ' +
          'JWS table — asymmetric, and not post-quantum — rather than a ' +
          'table of its own.' },
  { key: 'mtls', name: 'Mutual TLS client authentication and certificate ' +
                       'binding',
    specs: ['RFC 8705'],
    coverage: 'partial: both client authentication methods and the ' +
              'certificate-bound access token. It turns a verified ' +
              'certificate into a THUMBPRINT and never into a login.',
    what: '`x5t#S256` is the base64url SHA-256 of the certificate\'s DER — ' +
          'the DER, not the PEM, which is the mistake that looks right in a ' +
          'log and matches nothing.' },
  { key: 'pkce', name: 'PKCE — Proof Key for Code Exchange',
    specs: ['RFC 7636'],
    coverage: 'full for `S256` and `plain`. In RFC 9700 mode `plain` is ' +
              'withdrawn and the advertised list becomes `S256` alone.',
    what: 'SHA-256 over the code verifier. The one place in this service ' +
          'where a hash is the whole of a security property.' },
  { key: 'xmldsig', name: 'XML Signature',
    specs: ['XMLDSIG-CORE (W3C)', 'RFC 4051 / RFC 6931 (xmldsig-more)',
            'RFC 9231 (RSASSA-PSS)'],
    coverage: 'partial: this service SIGNS with RSA-SHA256 alone, and ' +
              'VERIFIES anything in the table below — RSA, RSASSA-PSS, ECDSA ' +
              'and HMAC across four digests. Enveloped signatures only; it ' +
              'produces no detached or enveloping signature except the ' +
              'Redirect binding\'s, which is a different mechanism.',
    what: 'The envelope for every XML document this service mints. Since ' +
          '2026-08-27 it is the parent project\'s own `xmldsig.js`, vendored ' +
          'byte-identical, which is THE OTHER END of most of these exchanges ' +
          '— so both sides canonicalize with the same code, and a ' +
          'disagreement about c14n cannot be invisible until it is a ' +
          'signature that verifies on one side and not the other.' },
  { key: 'xmlenc', name: 'XML Encryption',
    specs: ['XMLENC-CORE1 (W3C)', 'xmlenc11 (AES-GCM)'],
    coverage: 'partial: four block ciphers and two key transports, wrapping ' +
              'one element at a time. It is not the vendored ' +
              'implementation and that is a deliberate exception — the ' +
              'output of the two is already byte-compatible, and what this ' +
              'one has that the other does not is the DIAGNOSIS.',
    what: 'Every message this deliberately says out loud: the two CBC ' +
          'ciphers are NOT authenticated and `rsa-1_5` is broken by ' +
          'Bleichenbacher. Both are offered because real service providers ' +
          'require them and a mock that offered only the safe choice could ' +
          'not be used to show what the unsafe one does.' },
  { key: 'c14n', name: 'Canonical XML',
    specs: ['Canonical XML 1.0', 'Exclusive XML Canonicalization 1.0'],
    coverage: 'partial: both algorithms and both `#WithComments` twins. C14N ' +
              '1.1 is NOT offered — its whole difference is how `xml:base`, ' +
              '`xml:lang` and `xml:space` inherit into a detached subtree, ' +
              'the engine does not implement that inheritance, and an option ' +
              'naming a method it does not perform is worse than an absent ' +
              'one.',
    what: 'EXCLUSIVE IS LOAD-BEARING AND IS THE DEFAULT EVERYWHERE HERE. An ' +
          'assertion is signed standalone and then embedded inside an RSTR, ' +
          'a Response or a `wresult` that declares prefixes of its own, so ' +
          'INCLUSIVE c14n would pull those ancestor declarations into the ' +
          'digest at verification time — the signature then fails for every ' +
          'relying party while verifying perfectly here, which is the worst ' +
          'shape of bug to chase.' },
  { key: 'wss', name: 'WS-Security (SOAP Message Security)',
    specs: ['WS-Security 1.1 (OASIS)', 'WSS SAML Token Profile 1.1'],
    coverage: 'mock, and this row is the one to read before asking for ' +
              '"WS-Integrity" or "WS-Encryption" — neither is a document ' +
              'that exists. WSS is one specification whose integrity half is ' +
              'XML Signature over the SOAP Body and Timestamp inside a ' +
              '`<wsse:Security>` header and whose confidentiality half is ' +
              'XML Encryption applied the same way. THIS SERVICE DOES ' +
              'NEITHER. It signs no SOAP envelope, encrypts no SOAP body, ' +
              'produces no Timestamp and verifies no message-level signature ' +
              'on a request.',
    what: 'What it DOES is the SAML Token Profile: a signed SAML assertion ' +
          'carried inside a SOAP body, with a ' +
          '`<wsse:SecurityTokenReference>` naming it by `KeyIdentifier`, and ' +
          'a `<wsse:BinarySecurityToken>` where an X.509 token was asked ' +
          'for. It READS a requester\'s `<wsse:Security>` header for a ' +
          'credential and for the certificate to encrypt to. The vendored ' +
          '`xmldsig.js` CAN produce a real `<wsse:Security>` signature — ' +
          '`signSoapMessage()` is in it and the debugger uses it — and ' +
          'nothing here calls it.' },
  { key: 'krb5', name: 'Kerberos v5 cryptography',
    specs: ['RFC 3961 (framework)', 'RFC 3962 (AES-SHA1)',
            'RFC 8009 (AES-SHA2)', 'RFC 4757 (RC4-HMAC)'],
    coverage: 'partial: four AES profiles and RC4-HMAC performed, DES and ' +
              '3DES decode-only. Simplified profile, key derivation by key ' +
              'usage, confounder and CTS all real — the vector tests reach ' +
              'each layer individually, because a passing end-to-end ' +
              'encryption can hide two compensating errors.',
    what: 'THE ONLY FAMILY HERE WITH NO PUBLIC-KEY CRYPTOGRAPHY IN IT. ' +
          'Confidentiality and integrity both come from one long-term ' +
          'symmetric key, which is exactly why this is the one door in this ' +
          'service that really verifies a credential.' },
  { key: 'gssapi', name: 'GSS-API / SPNEGO',
    specs: ['RFC 4121 (Kerberos GSS mechanism)', 'RFC 4178 (SPNEGO)',
            'RFC 4559 (HTTP Negotiate)'],
    coverage: 'partial: the Kerberos mechanism only, with the MIC exchange. ' +
              'No NTLM, no mechanism negotiation worth the name — there is ' +
              'one mechanism to negotiate.',
    what: 'The wrapper that carries an AP-REQ over HTTP. It adds no ' +
          'cryptography of its own: the MIC is a Kerberos checksum computed ' +
          'with the mechanism\'s key.' },
  { key: 'x509', name: 'X.509 / PKIX',
    specs: ['RFC 5280'],
    // **THIS ROW SAID EVERY CERTIFICATE WAS SELF-SIGNED, WITH NO CRL, NO OCSP
    // AND NO PATH LONGER THAN ONE, until 2026-09-17 (#70)** — six days after
    // `common/pki.js` made every key pair a leaf of one service Root
    // (`common/CLAUDE.md` 3w) and `pki/pki_service.ts` began publishing a CRL
    // and an OCSP responder per CA (`docs/pki.md`).
    coverage: 'partial: one Root for the service, an Intermediate per trust ' +
              'realm (and one for the process) and an Issuing CA per use ' +
              'case, so a leaf path is four certificates long and an SVID ' +
              'under a SPIFFE downstream CA five. RFC 5280 CRLs and RFC 6960 ' +
              'OCSP are published per CA, and a presented certificate is ' +
              'checked against them under pki.revocationCheck. Kept only ' +
              'in PRODUCT mode, where the keystore persists; in DEVELOPMENT ' +
              'mode the hierarchy is rebuilt at every start. With no ' +
              'hierarchy (pki.autoBuild off) a key keeps the self-signed ' +
              'certificate it was born with, and a realm\'s SPIFFE ' +
              'authority falls back to a self-signed one.',
    what: 'The CA key is the hierarchy\'s, chosen on /admin/pki ' +
          '(`pki.keyAlgorithm`, RSA 2048 by default; the SPIFFE Issuing CA ' +
          'prefers EC P-256); the signing key is RSA 2048, and the TLS ' +
          'certificate is whatever `tls.certificateAlgorithms` asks for. ' +
          '`spiffe.x509KeyType` decides the key in each SVID. THE ' +
          'SUBJECTALTNAME IS THE ONLY PLACE THE NAMES ARE on the TLS ' +
          'certificate — RFC 6125 has said the CN is ignored since 2011.' },
  { key: 'tls', name: 'TLS',
    specs: ['RFC 8446 (1.3)', 'RFC 5246 (1.2)'],
    // "UNNARROWED … NO CIPHER SUITE, NO PROTOCOL FLOOR" stopped being true on
    // 2026-09-12, when `tls.minVersion` and `tls.ciphers` arrived
    // (`ldap/CLAUDE.md`, *THE SOCKETS*); corrected 2026-09-17 (#70), with the
    // debugger listener added to the sockets that share the certificate.
    coverage: 'mock: node\'s OpenSSL defaults, except where two settings ' +
              'narrow them on LDAPS 636 and the main port — ' +
              '`tls.minVersion` (TLS 1.2 by default) and `tls.ciphers` ' +
              '(node\'s list when empty). This service chooses no curve; ' +
              'what else it configures is which sockets are TLS and which ' +
              'certificate they serve.',
    what: 'LDAPS 636, the main port and the debugger listener share one ' +
          'certificate. ' +
          '`STS_HTTPS=false` is the supported way back to plain HTTP, not an ' +
          'escape hatch.' },
  { key: 'cose', name: 'COSE — CBOR Object Signing and Encryption',
    specs: ['RFC 9052', 'RFC 9053'],
    coverage: 'partial: COSE_Key parsing and signature verification for the ' +
              'algorithms below. It writes no COSE structure and reads no ' +
              'COSE_Encrypt.',
    what: 'How a WebAuthn credential\'s public key arrives. The CBOR reader ' +
          'and the COSE mapping are this repository\'s own and share no code ' +
          'with the debugger\'s, which is what makes the two an independent ' +
          'check on each other.' },
  { key: 'webauthn', name: 'WebAuthn Level 3',
    specs: ['W3C WebAuthn Level 3', 'FIDO CTAP2'],
    coverage: 'partial: the relying party\'s half. Registration and ' +
              'assertion signatures are really verified; attestation ' +
              'STATEMENTS are parsed and not chased.',
    what: 'The signature covers `authenticatorData || ' +
          'SHA-256(clientDataJSON)` and the RP ID hash inside that ' +
          'authenticator data is compared byte for byte against SHA-256 of ' +
          'the origin\'s domain.' },
  { key: 'digest', name: 'HTTP Digest Access Authentication',
    specs: ['RFC 7616'],
    coverage: 'partial: `qop=auth` with SHA-256, SHA-512-256 and MD5 and ' +
              'their `-sess` variants, with nonce counts, stale nonces and ' +
              '`Authentication-Info`. No `qop=auth-int`.',
    what: 'ONE OF THE TWO PLACES IN THIS SERVICE WHERE A PASSWORD IS REALLY ' +
          'CHECKED, and it has to be: the password is an input to the hash, ' +
          'so a server that accepted anything could not compute the response ' +
          'the client is expecting.' },
  { key: 'hoba', name: 'HOBA — HTTP Origin-Bound Authentication',
    specs: ['RFC 7486'],
    coverage: 'partial: algorithm 0 (RSA-SHA256) only, with the signature ' +
              'really verified against the registered key.',
    what: 'A password replacement: the client holds a key pair scoped to one ' +
          'origin, registers the public half, and signs a blob of nonce, ' +
          'algorithm, origin, realm, key id and the server\'s challenge. ' +
          'ANYBODY MAY REGISTER A KEY — that is the turnstile — but a ' +
          'signature that does not verify against the key registered under ' +
          'that `kid` is refused.' },
  { key: 'sdjwt', name: 'SD-JWT and SD-JWT VC',
    specs: ['draft-ietf-oauth-selective-disclosure-jwt',
            'draft-ietf-oauth-sd-jwt-vc'],
    coverage: 'partial: `_sd` digests with `_sd_alg: sha-256`, disclosures, ' +
              'and the `dc+sd-jwt` type. Key binding is by the wallet\'s ' +
              'proof of possession at issuance.',
    what: 'Selective disclosure by hashing: the credential carries the ' +
          'DIGEST of each claim and the holder hands over the ones it ' +
          'chooses to reveal.' },
  { key: 'dataintegrity', name: 'Data Integrity / BBS',
    specs: ['W3C VC Data Integrity', 'bbs-2023 cryptosuite',
            'draft-irtf-cfrg-bbs-signatures'],
    coverage: 'partial: issue, verify a base proof, and verify a DERIVED ' +
              'proof. BLS12381-SHA-256 ciphersuite.',
    what: 'THE ONLY PAIRING-BASED SIGNATURE IN THIS SERVICE, and the only ' +
          'selective disclosure here that is not hashing. What must be ' +
          'shared with the far end is the CANONICAL FORM — bbs-2023 signs ' +
          'canonicalized RDF statements — which is why the JSON-LD contexts ' +
          'are vendored rather than fetched.' },
  { key: 'did', name: 'DID Core and DIF domain linkage',
    specs: ['W3C DID Core', 'did:web', 'DIF Well Known DID Configuration'],
    coverage: 'partial: `did:web` resolution, a document publishing this ' +
              'service\'s keys, and the domain linkage credential.',
    what: 'How a wallet finds the key that verifies a credential whose ' +
          '`iss` is a DID. The BBS key is published as ' +
          '`publicKeyMultibase` because it has no JWK representation to be ' +
          'forced into.' },
  { key: 'httpsig', name: 'HTTP Message Signatures and Digest Fields',
    specs: ['RFC 9421', 'RFC 9530', 'RFC 8941 (Structured Field Values)'],
    coverage: 'partial: request and response signing and verification with ' +
              'every derived component and component parameter, multiple ' +
              'signatures, and Content-Digest with sha-256 and sha-512. ' +
              'Repr-Digest and the Want- fields are not implemented.',
    what: 'GNAP\'s preferred key proof. THE SIGNATURE BASE IS THE THING BOTH ' +
          'ENDS MUST BUILD IDENTICALLY, byte for byte, from a message each ' +
          'of them parsed separately — so the structured-field serializer is ' +
          'written out in `gnap/gnap_sf.ts` rather than borrowed, and held ' +
          'to the RFC\'s own test vectors.' },
  { key: 'macaroon', name: 'Macaroons',
    specs: ['Macaroons (NDSS 2014)', 'libmacaroons V2 binary format'],
    coverage: 'partial: first-party caveats and attenuation. No third-party ' +
              'caveats, so no discharge macaroons.',
    what: 'A bearer credential whose holder can NARROW it without asking ' +
          'anybody, by appending a caveat and re-keying the HMAC chain. The ' +
          'verifier must hold the root key, which is why a macaroon is the ' +
          'one GNAP format with no public verification material.' },
  { key: 'biscuit', name: 'Biscuit',
    specs: ['Biscuit specification (biscuitsec.org)'],
    coverage: 'partial: Ed25519 root and block signatures, Datalog facts, ' +
              'checks and attenuation blocks, verified by an authorizer run ' +
              'under limits. No third-party blocks.',
    what: 'A public-key token a holder can attenuate OFFLINE, like a ' +
          'macaroon, but verifiable by anybody holding the root public key. ' +
          'Its authorization logic is Datalog carried inside the token, so ' +
          'the verifier ALWAYS runs with time and iteration limits.' },
  // CMS (2026-09-13), for SCEP — the one family here whose messages are CMS
  // signed and enveloped data rather than certs-only containers.
  { key: 'cms', name: 'CMS — Cryptographic Message Syntax',
    specs: ['RFC 5652', 'RFC 8894 section 3'],
    coverage: 'partial: SignedData with one signer and signed attributes, ' +
              'verified over the attribute bytes as received and written ' +
              'DER-sorted; EnvelopedData with KeyTransRecipientInfo (RSA ' +
              'PKCS#1 v1.5 and OAEP) and AES-CBC content; degenerate ' +
              'certs-only SignedData with certificates and CRLs. No ' +
              'KeyAgreeRecipientInfo, no authenticated or compressed data, ' +
              'no countersignatures.',
    what: 'The envelope SCEP (scep/scep_cms.ts) reads and writes: a request ' +
          'signed by the requester and encrypted to the RA, and a CertRep ' +
          'signed by the RA whose certificate is encrypted to the requester.' }
];

// One identity service's row: the four verbs, the prose, the envelopes it
// cites from STANDARDS, and its algorithm table, read when it is called.
interface Family {
  name: string;
  signs: string;
  verifies: string;
  encrypts: string;
  decrypts: string;
  hashes: string;
  keys?: string;
  whatItDoesNot?: string;
  envelopes: string[];
  algorithms: () => any[];
}

// Everything a `CryptoMetadata` reads. Named for the modules, because what
// this page reports IS those modules' tables.
interface CryptoMetadataDeps {
  log: typeof helpers.log;
  // The console's HTML escaper, `helpers.xmlEscape`.
  esc: typeof helpers.xmlEscape;
  baseUrlOf: typeof helpers.baseUrlOf;
  stsKeysFor: typeof helpers.stsKeysFor;
  parseBody: typeof helpers.parseBody;
  config: typeof config;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  admin: typeof admin;
  stsCrypto: typeof stsCrypto;
  // `stsCrypto.xmldsig`, the vendored module re-exported.
  xmldsig: typeof stsCrypto.xmldsig;
  pqJose: typeof pqJose;
  bbs2023: typeof bbs2023;
  krb5crypto: typeof krb5crypto;
  spiffeCa: typeof spiffeCa;
  webauthn: typeof webauthn;
  webauthnPolicy: typeof webauthnPolicy;
  totp: typeof totp;
  backupCodes: typeof backupCodes;
  dpop: typeof dpop;
  clientAuth: typeof clientAuth;
  mtls: typeof mtls;
  oauth2: typeof oauth2;
  introspectionJwt: typeof introspectionJwt;
  applicationRegistry: typeof applicationRegistry;
  tlsServer: typeof tlsServer;
  certificateDetails: typeof certificateDetails;
  certificateDialog: typeof certificateDialog;
  certificateViews: typeof certificateViews;
  pqcSupport: typeof pqcSupport;
  pqcBadge: typeof pqcBadge;
  scimAuth: typeof scimAuth;
  ssfEvents: typeof ssfEvents;
  ssfAuth: typeof ssfAuth;
  nodeCrypto: typeof nodeCrypto;
  keystore: typeof keystore;
  pki: typeof pki;
  stsKeystore: typeof stsKeystore;
  stsPki: typeof stsPki;
  // THE LAZY REQUIRES (see the header), called where the requires were.
  loadRevocationStatus: () => any;
  loadGnapHttpsig: () => any;
  loadGnapKeys: () => any;
  loadGnapTokens: () => any;
  loadAcmeJws: () => any;
  loadEstCodec: () => any;
  loadEstKeyMaterial: () => any;
  loadScepCms: () => any;
}

// ---------------------------------------------------------------------------
// THE SLOT `sts_metadata.js` FILLS. See the header for why it is a slot: a
// require in the obvious direction would load the module whose one constraint
// is that it is required LAST.
//
// It is validated when it is installed rather than when it is read, which is
// the rule `admin.js`'s `setLogoutReader()` follows and for the same reason —
// a half-usable list installed quietly would produce a drift report that is
// wrong rather than absent, and a wrong drift report is worse than none.
// ---------------------------------------------------------------------------
let advertisedFamilies = null;

class CryptoMetadata {
  static readonly STANDARDS = STANDARDS;

  // THE IDENTITY SERVICES, built once when the instance is — at load, for the
  // transitional instance, which is when the table was built before.
  readonly families: Family[];

  constructor(private readonly deps: CryptoMetadataDeps) {
    deps.log.debug("Entering CryptoMetadata.constructor().");
    this.families = this.buildFamilies();
    deps.log.debug("Leaving CryptoMetadata.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  static defaultDeps(): CryptoMetadataDeps {
    helpers.log.debug("Entering CryptoMetadata.defaultDeps().");
    helpers.log.debug("Leaving CryptoMetadata.defaultDeps().");
    return {
      log: helpers.log,
      esc: helpers.xmlEscape,
      baseUrlOf: helpers.baseUrlOf,
      stsKeysFor: helpers.stsKeysFor,
      parseBody: helpers.parseBody,
      config: config,
      errorCodes: errorCodes,
      realms: realms,
      admin: admin,
      stsCrypto: stsCrypto,
      xmldsig: stsCrypto.xmldsig,
      pqJose: pqJose,
      bbs2023: bbs2023,
      krb5crypto: krb5crypto,
      spiffeCa: spiffeCa,
      webauthn: webauthn,
      webauthnPolicy: webauthnPolicy,
      totp: totp,
      backupCodes: backupCodes,
      dpop: dpop,
      clientAuth: clientAuth,
      mtls: mtls,
      oauth2: oauth2,
      introspectionJwt: introspectionJwt,
      applicationRegistry: applicationRegistry,
      tlsServer: tlsServer,
      certificateDetails: certificateDetails,
      certificateDialog: certificateDialog,
      certificateViews: certificateViews,
      pqcSupport: pqcSupport,
      pqcBadge: pqcBadge,
      scimAuth: scimAuth,
      ssfEvents: ssfEvents,
      ssfAuth: ssfAuth,
      nodeCrypto: nodeCrypto,
      keystore: keystore,
      pki: pki,
      stsKeystore: stsKeystore,
      stsPki: stsPki,
      loadRevocationStatus: function () {
        return require('../common/revocation_status');
      },
      loadGnapHttpsig: function () {
        return require('../gnap/gnap_httpsig');
      },
      loadGnapKeys: function () {
        return require('../gnap/gnap_keys');
      },
      loadGnapTokens: function () {
        return require('../gnap/gnap_tokens');
      },
      loadAcmeJws: function () {
        return require('../acme/acme_jws');
      },
      loadEstCodec: function () {
        return require('../est/est_codec');
      },
      loadEstKeyMaterial: function () {
        return require('../common/vendored/key_material');
      },
      loadScepCms: function () {
        return require('../scep/scep_cms');
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE SLOT THIS MODULE FILLS, so that `/admin-api/crypto` can mirror this
  // page without `mgmt-api/admin_api.ts` requiring this file. Rule 3e's test
  // answers yes in both directions and that is why it is a slot rather than a
  // require:
  //
  //   * a require from `admin_api.js` (19) to this module (20a) would MOVE
  //     ROUTES — `tls/tls_server.js`'s six, which this file requires for the
  //     server certificate, ahead of the management API's own routes and of
  //     ldap, scim and spiffe. (It moved this page's own as well until #50's
  //     R1; `common/protocol_stack.ts` registers those at 20a now, wherever
  //     the module is loaded.)
  //   * a require from `admin.js` (18) to this module would CLOSE A CYCLE:
  //     this file requires that one for the shell.
  //
  // It carries one function and is validated when it is installed, for the
  // same reason `setLogoutReader()` is: a page that could be drawn and an API
  // that could not would be the parity rule failing silently, which is the
  // one thing that rule exists to make impossible.
  //
  // It was load-time work with this module's own instance until #50's R2; the
  // slot runs it now, once, for whichever instance is installed.
  // -------------------------------------------------------------------------
  static wire(instance: CryptoMetadata): void {
    helpers.log.debug("Entering CryptoMetadata.wire().");
    if (typeof admin.setCryptoReporter === 'function') {
      // ONE OBJECT, VALIDATED WHOLE by the setter, which is the shape
      // `setLogoutReader()` uses and for the same reason: a filler that
      // installed the report and not the export would leave
      // `/admin-api/keys` answering and `/admin-api/keys/export` not, which
      // is the parity rule failing silently.
      admin.setCryptoReporter({
        report: instance.cryptoJson.bind(instance),
        keys: instance.keysJson.bind(instance),
        exportKey: instance.exportKey.bind(instance)
      });
    } else {
      // An older copy of admin.js, which is a real possibility while this
      // repository is vendored into another one. The PAGE still works — its
      // route is registered by the composition root through
      // `registerRoutes()` and does not go through the slot — and only the API
      // mirror is missing, which is what this line says rather than leaving a
      // 404 to be explained.
      log.error(errorCodes.tag('STS-ADMIN-0596') +
                'crypto metadata: this build of admin-ui/admin.ts offers no ' +
                'setCryptoReporter(), so /admin/crypto-metadata is drawn and ' +
                'GET /admin-api/crypto will not answer.');
    }
    helpers.log.debug("Leaving CryptoMetadata.wire().");
  }

  private refused(code, result) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering CryptoMetadata.refused().");
    log.debug("Leaving CryptoMetadata.refused().");
    return errorCodes.mark(result, code);
  }

  // ---------------------------------------------------------------------------
  // THE IDENTITY SERVICES THIS MOCK ADVERTISES, AND WHAT EACH ONE DOES WITH
  // CRYPTOGRAPHY.
  //
  // One row per protocol family on `/admin/sts-metadata`'s cards, and the
  // `name` of each is that page's name for it CHARACTER FOR CHARACTER — that is
  // what `driftReport()` below joins on, so a row renamed here and not there is
  // reported rather than silently unmatched.
  //
  // The four verbs are separated on purpose and are not four ways of saying
  // "uses crypto". A family that SIGNS is minting something a relying party
  // will believe; one that VERIFIES is making a decision it could get wrong;
  // one that ENCRYPTS is protecting somebody else's data with somebody else's
  // key; one that DECRYPTS is holding a private key that a caller can aim
  // ciphertext at. They are different exposures and this service does a
  // different amount of each — federation VERIFIES and barely signs, SAML 2.0
  // does all four — so a table that collapsed them would hide the one
  // distinction a reader came for.
  //
  // `algorithms` is a FUNCTION and never a list, because everything it names is
  // read from the module that performs it at the moment the page is drawn. A
  // family whose algorithms are settable at runtime (SAML 2.0's two encryption
  // settings) therefore shows what this realm is configured with right now
  // rather than what the defaults are.
  //
  // An empty string for a verb means this service does not do it in that
  // family, and every one of those is a documented non-goal rather than an
  // oversight — `federation/CLAUDE.md` on decrypting a partner's assertion
  // (`saml/CLAUDE.md` on verifying an AuthnRequest signature was the other,
  // until #37 reversed it on 2026-09-17). The page prints
  // them as "—" and the `whatItDoesNot` line beside them says which.
  // ---------------------------------------------------------------------------
  private buildFamilies(): Family[] {
    const { log, config, stsCrypto, bbs2023, spiffeCa, webauthn, webauthnPolicy,
            totp, backupCodes, dpop, clientAuth, mtls, oauth2, introspectionJwt,
            applicationRegistry, tlsServer, xmldsig, scimAuth, ssfEvents,
            ssfAuth, pki, loadRevocationStatus, loadGnapHttpsig, loadGnapKeys,
            loadGnapTokens, loadAcmeJws, loadEstCodec, loadEstKeyMaterial,
            loadScepCms } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.buildFamilies().");
    log.debug("Leaving CryptoMetadata.buildFamilies().");
    return [
      // ----------------------------------------------------------------------
      // PKI MINTS AN X.509 CERTIFICATE FOR SOMETHING THAT IS NOT THIS SERVICE —
      // the first family here that did; ACME, EST and SCEP (below) have done so
      // too since 2026-09-13. TLS issues its own listener certificate and
      // SPIFFE issues SVIDs for workloads it also authenticates; this issues a
      // signing key pair to an APPLICATION (or a person) and hands both halves
      // over.
      //
      // The algorithm tables are read from `common/vendored/x509.js` — the
      // module that performs the encoding — through `common/pki.js`'s
      // `report()`, which is this page's rule applied to its newest family: a
      // list written out here would describe something this service does not do
      // the first time an algorithm was added to that table.
      // ----------------------------------------------------------------------
      {
        // `signs`, `verifies` and `keys` described one three-tier hierarchy
        // PER REALM, ending at the realm's own Root, until 2026-09-17 (#70);
        // it has been one Root for the service since 2026-09-11, and the
        // realm boundary is the Intermediate (`common/CLAUDE.md` 3w).
        name: 'PKI',
        signs: 'CERTIFICATES. The Root signs itself once for the service; ' +
               'it signs an Intermediate per trust realm and one for the ' +
               'process; each Intermediate signs an Issuing CA per use case; ' +
               'and each Issuing CA signs the leaves of its use case — the ' +
               'service\'s own signing and listener keys, and the key pairs ' +
               'issued to applications and people. The signature ' +
               'algorithm is the one chosen for the hierarchy and is ' +
               'constrained by the ISSUER\'s key family rather than the ' +
               'subject\'s, which is the mistake ' +
               '`common/vendored/x509.js`\'s own header spends a paragraph ' +
               'on: importing a key under one digest and signing with ' +
               'another produces a certificate whose declared algorithm and ' +
               'actual signature disagree, and `openssl verify` reports it ' +
               'as a bad signature naming neither.',
        verifies: 'A CERTIFICATE PATH. When an RFC 7523 assertion arrives ' +
                  'carrying an `x5c` header, every link is checked — the ' +
                  'signature, the issuer name and the validity window — and ' +
                  'the path must END AT THE SERVICE ROOT AND PASS THROUGH ' +
                  'THIS REALM\'S OWN INTERMEDIATE. The second half is the ' +
                  'realm boundary: every realm shares the Root, so a chain ' +
                  'that merely reaches it proves nothing about which realm ' +
                  'issued it — and one anchored somewhere else verifies ' +
                  'every link and proves nothing here at all.',
        encrypts: 'Nothing itself. In PRODUCT mode the hierarchy it built is ' +
                  'sealed AES-256-GCM under the key-encryption key, by ' +
                  'common/keystore.js, in the same `sts_keys` row family as ' +
                  'the signing keys — this module hands it over and does not ' +
                  'do the encryption.',
        decrypts: 'Nothing.',
        keys: 'ONE ROOT KEY PAIR FOR THE SERVICE, an Intermediate for each ' +
              'trust realm and one for the process, an Issuing CA under ' +
              'each per use case, plus one per key pair issued. The CA ' +
              'private keys never leave this process. An application\'s ' +
              'DOES: it is handed over once, at issuance, and written onto ' +
              'that application\'s directory ' +
              'entry under `oauthAssertionPrivateKey` — **sealed AES-256-GCM ' +
              'under the same key-encryption key as the hierarchy above it ' +
              'wherever that key outlives the process**, so a directory ' +
              'dump, an ldif file, a database row or a backup holds ' +
              'ciphertext. The console and the management API open it for a ' +
              'caller that holds a credential, because an issued key pair an ' +
              'operator cannot collect is an issued key pair nobody can use. ' +
              'In DEVELOPMENT mode it is written in the clear, where the ' +
              'key-encryption key is ephemeral and would not survive the ' +
              'restart the entry does. This service keeps NO second copy ' +
              'either way. AND SINCE 2026-09-11 A PERSON MAY HOLD ONE TOO, ' +
              'under `stsAssertionPrivateKey` on their own `ou=users` entry, ' +
              'sealed under the same key and by the same mechanism. The ' +
              'difference is the way OUT: an application\'s is opened for a ' +
              'credentialed reader by `applications.js`, and a person\'s is ' +
              'handed over once by the issue and never again, because ' +
              'nothing here draws a person\'s entry through a module that ' +
              'would open it.',
        hashes: 'SHA-256 by default for the certificate signature, and ' +
                'SHA-384 or SHA-512 where the hierarchy was built with them. ' +
                'SHA-256 again for the certificate thumbprints and for the ' +
                'RFC 7638 JWK thumbprint the issued `kid` is derived from — ' +
                'a kid is derived from the key material everywhere in this ' +
                'service, so two instances cannot publish one name over two ' +
                'keys. **SHA-1 IS OFFERED AND IS MARKED WEAK**: "does my ' +
                'stack refuse a SHA-1 certificate?" is a question a debugger ' +
                'should be able to ask, and nothing defaults to it.',
        // The KEY from STANDARDS, not the display name — the drift check
        // compares these against `STANDARDS`'s `key` in both directions, and
        // 'X.509' was reported as an envelope with no row within a minute of
        // being written. `jwk` is here beside it because what an issued key
        // pair is HANDED OVER as is a JWK Set carrying `x5c` and `x5t#S256`.
        envelopes: ['x509', 'jwk'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          const report = pki.report();
          log.debug("Leaving algorithms().");
          return [
            { what: 'Certificate encoding',
              how: 'X.509 v3, DER, through pkijs and asn1js — ' +
                   'common/vendored/x509.js, the parent project\'s own PKI ' +
                   'code, byte-identical. One encoder for this service and ' +
                   'for that project\'s PKI / X.509 page.' },
            { what: 'CA key algorithms offered',
              how: report.keyAlgorithms.map(function (one) { return one.id; })
                .join(', ') },
            { what: 'Certificate signature algorithms offered',
              how: report.signatureAlgorithms.map(function (one) {
                return one.id + (one.weak ? ' (weak, on purpose)' : '');
              }).join(', ') },
            { what: 'The three tiers',
              how: report.tiers.map(function (one) {
                return one.label + ' (pathLen ' +
                  (one.pathLen === null || one.pathLen === undefined
                    ? 'unconstrained' : one.pathLen) + ', ' + one.years +
                  ' years)';
              }).join('; ') },
            { what: 'Certificate thumbprint', how: 'SHA-256 over the DER' },
            { what: 'The issued key\'s `kid`',
              how: 'RFC 7638 JWK thumbprint, SHA-256, truncated to 16 ' +
                   'characters' },
            // Two rows rather than one since 2026-09-11, because the one row
            // said `NONE` and the answer is now different in the two
            // directions. Collapsing them would lose exactly the distinction
            // that matters.
            { what: 'Revocation published',
              how: 'RFC 5280 CRLs and RFC 6960 OCSP, ONE OF EACH PER ' +
                   'CERTIFICATE AUTHORITY — a list is signed by an issuer, ' +
                   'so a list per realm would have no valid issuer. Signed ' +
                   'with the CA itself rather than a delegated responder ' +
                   'certificate (RFC 6960 section 4.2.2.2), so a client ' +
                   'verifies with the anchor it already has. Every ' +
                   'certificate this service issues names its own CRL over ' +
                   'plain http and ldap and its responder in an Authority ' +
                   'Information Access — never https or ldaps, which RFC ' +
                   '5280 section 8 says a CA SHOULD NOT write into an ' +
                   'extension.' },
            // **THIS ROW SAID `NONE` UNTIL 2026-09-12** — nothing fetched a CRL
            // and nothing asked a responder, so a certificate revoked on
            // /admin/pki still authenticated here. It is read from the module
            // that performs the check now, which is this page's rule, so it
            // names the policy in force rather than a policy somebody once
            // wrote down.
            { what: 'Revocation checked',
              how:
                loadRevocationStatus().describePolicy().sentence },
            { what: 'Revocation check — how a foreign CRL is trusted',
              how: 'Its signature is verified against the ISSUER\'s ' +
                   'certificate (the next certificate up the presented ' +
                   'chain), its issuer name must match, a critical extension ' +
                   'this service does not implement makes it unusable (RFC ' +
                   '5280 section 6.3.3), and it is used until its nextUpdate ' +
                   'or pki.revocationCrlMaxAgeS, whichever is sooner. The ' +
                   'transport is not certificate-checked: the signature is ' +
                   'the authentication, and a CRL server\'s own certificate ' +
                   'commonly chains to the CA being checked. An INDIRECT CRL ' +
                   'is verified against the certificate of the cRLIssuer the ' +
                   'presented certificate names, which must carry cRLSign ' +
                   'and chain to the presented path — taken from the chain, ' +
                   'this service\'s authorities, ' +
                   'pki.revocationCrlIssuersFile, or the caIssuers address ' +
                   'in the CRL\'s own Authority Information Access; a DELTA ' +
                   'against the same signer as its base. Lists are fetched ' +
                   'over http, https or ldaps (plain ldap only when ' +
                   'pki.revocationLdap allows it); an ldaps directory\'s ' +
                   'certificate must chain to node\'s store or ' +
                   'pki.revocationLdapCaFile.' },
            { what: 'Revocation check — how a foreign OCSP response is trusted',
              how: 'The request carries a SHA-1 CertID (the RFC 5019 ' +
                   'profile\'s identifier, not a signature) and a 32-octet ' +
                   'nonce. The response must be signed by the certificate\'s ' +
                   'issuer, or by a delegated responder whose certificate ' +
                   'the issuer signed with id-kp-OCSPSigning (RFC 6960 ' +
                   'section 4.2.2.2); a different nonce echoed back is ' +
                   'refused as a replay; thisUpdate and nextUpdate must be ' +
                   'fresh within pki.revocationClockSkewS. A delegated ' +
                   'responder\'s OWN status is looked up on the CRL its ' +
                   'certificate names (never over OCSP) unless it carries ' +
                   'id-pkix-ocsp-nocheck; a revoked one\'s answers are not ' +
                   'used, and an unknown one\'s are not used under ' +
                   'hard-fail.' },
            { what: 'Revocation check — a REGISTERED certificate',
              how: 'A certificate registered rather than presented — an RFC ' +
                   '7523 key\'s x5c, an RFC 7522 certificate, ' +
                   'fedSigningCertificate or a federation partner key\'s ' +
                   'x5c, a certificate in oid4vp.trustedIssuerCertificates — ' +
                   'is checked the same way when it verifies a signature, ' +
                   'its issuers fetched from its own caIssuers address. A ' +
                   'bare key with no certificate has nothing to check and is ' +
                   'reported as such.' },
            { what: 'Where the CA private keys live', how: report.residency }
          ];
        }
      },
      // THE USER PORTAL IS THE ONLY FAMILY HERE WHOSE CRYPTOGRAPHY IS ENTIRELY
      // ABOUT SECRETS AT REST. Every other row on this page is about a
      // credential being SIGNED, VERIFIED or ENCRYPTED in flight; this one
      // signs nothing and issues nothing. What it does is decide whether a
      // presented password is the stored one, and protect two values that must
      // never be readable from a directory dump.
      {
        name: 'User portal',
        signs: 'Nothing. The portal issues no token, no assertion and no ' +
               'certificate — it changes credentials rather than minting them.',
        verifies: 'A PRESENTED PASSWORD, against the scrypt hash on the ' +
                  'person\'s own entry, and an ACTIVATION TOKEN against the ' +
                  'scrypt hash of the one that was issued. Both comparisons ' +
                  'are constant-time through common/crypto.js — a ' +
                  'byte-by-byte early return on either is a timing oracle. A ' +
                  'WebAuthn assertion is verified too, but by ' +
                  'authn/webauthn.js, which is where the ceremony lives.',
        encrypts: 'Nothing.',
        decrypts: 'Nothing.',
        keys: 'None of its own. The CSRF token is an HMAC-SHA256 under a key ' +
              'generated per process and deliberately NOT persisted — a CSRF ' +
              'token is only meaningful for the life of a session, a session ' +
              'does not survive a restart, so a key that did would protect ' +
              'nothing and be one more secret at rest.',
        hashes: 'SCRYPT (RFC 7914, N=2^15, r=8, p=1) for both the password ' +
                'and the activation token, each with 16 random bytes of ' +
                'salt, stored as `$scrypt$N$r$p$salt$hash` so the cost can ' +
                'be raised later without invalidating what is already ' +
                'stored. **NOT a digest**: a password is low-entropy and a ' +
                'fast hash over one is a wordlist away from being the ' +
                'password. SHA-256 under an HMAC for the CSRF token, which ' +
                'is a different job — authenticity of a form, not protection ' +
                'of a secret at rest.',
        // AN ARRAY, like every other row. Nothing this family protects travels
        // anywhere — every value is at rest in the embedded directory — so the
        // list is empty, and saying that as an empty list rather than as a
        // sentence is what keeps the page able to render it.
        envelopes: [],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            { what: 'Password and activation token at rest',
              how: 'scrypt, N=32768, r=8, p=1, 32-byte key, 16-byte random ' +
                   'salt' },
            { what: 'Comparing either', how: 'constant-time equality' },
            { what: 'CSRF token',
              how: 'HMAC-SHA256 over the session id under a per-process key' }
          ];
        }
      },
      // XACML IS THE ONE FAMILY HERE THAT PERFORMS NO CRYPTOGRAPHY AT ALL, and
      // saying so is the point of the row rather than an admission. A PDP reads
      // a policy and a request and returns a decision; nothing is signed,
      // nothing is verified, nothing is encrypted, and no key is involved
      // anywhere in the decision path. A reader who does not find XACML on this
      // page would reasonably wonder whether the page is incomplete — which is
      // exactly what the drift check between this table and sts_metadata.js's
      // PROTOCOLS exists to prevent, in both directions.
      //
      // What that costs, and it is worth knowing: a decision travels over
      // whatever the transport gives it and carries no integrity of its own.
      // The REMOTE PEP (phase five) is where that matters, and the answer there
      // is the same one: it REGISTERS over mutual TLS and PULLS the repository
      // over the same connection, which is the tls/ family's cryptography and
      // not this one's. The policies it pulls are not signed, so a PEP trusts
      // the transport for them exactly as it trusts it for everything else.
      { name: 'GNAP',
        signs: 'THE FIVE ACCESS TOKEN FORMATS, three of which are not JWTs. ' +
               'jwt-signed goes through the same signer as every other JWT ' +
               'here (`typ: GNAP`); biscuit and zcap are signed with the ' +
               'realm\'s Ed25519 key (Biscuit\'s own block signature, and ' +
               'Ed25519Signature2020 over a ZCAP-LD capability); a macaroon ' +
               'is an HMAC-SHA256 chain under a key derived per resource ' +
               'server. It also signs an HTTP response with RFC 9421 when a ' +
               'client instance asks for one.',
        verifies: 'EVERY REQUEST A CLIENT INSTANCE MAKES, by the key it ' +
                  'presented: an RFC 9421 HTTP message signature (with the ' +
                  'body covered by an RFC 9530 Content-Digest), a mutual TLS ' +
                  'certificate, a detached JWS over the body or an attached ' +
                  'JWS carrying it. A key rotation is verified under BOTH ' +
                  'keys. A resource server calling introspection or ' +
                  'registration is proofed the same way, and every token ' +
                  'format is verified at introspection and at the ' +
                  'demonstration resource server.',
        encrypts: 'jwt-encrypted: a signed GNAP JWT inside a JWE — to the ' +
                  'resource server\'s own key (RSA-OAEP-256 or ' +
                  'ECDH-ES+A256KW, with `gnap.jweEnc`) when its application ' +
                  'entry carries one, otherwise `dir` with A256GCM under a ' +
                  'realm-derived key so only this authorization server can ' +
                  'open it.',
        decrypts: 'A jwt-encrypted token encrypted under `dir`, at ' +
                  'introspection. A token encrypted to a resource server\'s ' +
                  'key is opaque here, which is the point of encrypting to ' +
                  'it.',
        keys: 'The client instance\'s key is the client\'s identity — a JWK, ' +
              'a certificate, a certificate thumbprint or a reference to a ' +
              'key on the application entry. A shared symmetric key ' +
              '(gnapSymmetricKey) and a macaroon root key (gnapMacaroonKey) ' +
              'are sealed at rest under the process key-encryption key. The ' +
              'macaroon and dir keys are HKDF-SHA256 derivations of the ' +
              'realm secret with a domain separator each.',
        hashes: 'SHA-256 and SHA-512 for Content-Digest; the section 4.2.3 ' +
                'interaction hash in any Named Information hash method node ' +
                'computes (SHA-2 and SHA-3, truncated forms included); ' +
                'SHA-256 for a JWK thumbprint, a certificate thumbprint and ' +
                'a remembered approval\'s digest; SHA-256 of the access ' +
                'token for `ath` in a JWS proof.',
        whatItDoesNot: 'IT DOES NOT ACCEPT AN UNPROOFED REQUEST FOR A BOUND ' +
                       'TOKEN, and there is no setting that makes it: a GNAP ' +
                       'key proof is the protocol rather than a hardening ' +
                       'option. What is optional is a BEARER token, which ' +
                       'gnap.bearerTokens turns off. Macaroon third-party ' +
                       'caveats, Biscuit third-party blocks and ZCAP ' +
                       'invocation proofs are not implemented.',
        envelopes: ['httpsig', 'jws', 'jwe', 'jwt', 'jwk', 'thumbprint', 'mtls',
                    'tls',
                    'macaroon', 'biscuit', 'dataintegrity'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          // Required HERE rather than at the top: this module is 20a in the
          // require order and GNAP is 23d. The libraries register no route, so
          // loading them early would move nothing — but the biscuit format
          // instantiates a WebAssembly module at load, and a report nobody
          // opened should not pay it.
          const httpsig = loadGnapHttpsig();
          const gnapKeys = loadGnapKeys();
          const gnapTokens = loadGnapTokens();
          log.debug("Leaving algorithms().");
          return [
            ['Access token formats', gnapTokens.FORMATS],
            ['Key proofing methods', gnapKeys.PROOF_METHODS],
            ['Key formats', gnapKeys.KEY_FORMATS.concat(['reference'])],
            ['HTTP message signature algorithms',
             Object.keys(httpsig.ALGORITHMS)],
            ['Content-Digest algorithms', httpsig.DIGEST_ALGORITHMS],
            ['jwt-encrypted content encryption, through gnap.jweEnc',
             [String(config.value('gnap.jweEnc') || 'A256GCM')]]
          ];
        } },

      { name: 'XACML',
        signs: 'Nothing. A decision is not a token and carries no signature.',
        verifies: 'Nothing in the decision path. The remote PEP\'s client ' +
                  'certificate is verified by the TLS layer (see TLS / ' +
                  'mutual TLS), not here.',
        encrypts: 'Nothing.',
        decrypts: 'Nothing.',
        keys: 'None. No key of any kind takes part in reaching a decision.',
        hashes: 'ONE, AND IT IS NOT SECURITY. The remote PEP\'s sync token ' +
                'is a SHA-256 over the documents of every enabled policy ' +
                'plus which one is the root — a cheap way for a PEP to ask ' +
                '"has anything changed" and get a 304, and nothing more. It ' +
                'authenticates nothing and is not compared against anything ' +
                'a caller supplies as a credential, so it would still be ' +
                'correct as a CRC.',
        whatItDoesNot: 'It signs no decision, so a decision that travelled ' +
                       'between two processes carries no integrity of its ' +
                       'own and rests entirely on the transport. That is the ' +
                       'position rather than a gap: signing a decision would ' +
                       'need a PEP to hold a key and verify it, and this ' +
                       'service\'s whole premise is that the interesting ' +
                       'part is the policy rather than the plumbing.',
        // THREE ROWS OF THIS TABLE SAY "NOTHING", AND THIS ONE MUST STILL CARRY
        // THE FIELDS. `cryptoJson()` calls `envelopes.slice(0)` and
        // `algorithms()` on every row without checking, deliberately — a row is
        // the whole shape or it is not a row — and this one was missing both
        // from phase one until phase five, which made GET /admin-api/crypto
        // answer 500 rather than reporting a family that does no cryptography.
        // The empty list and the empty table are the right answer here and are
        // what the page draws as an em dash.
        envelopes: [],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Nothing is signed, verified, encrypted or decrypted here', []],
            ['The remote PEP sync token, which is a change detector rather ' +
             'than a security mechanism', ['SHA-256']]
          ];
        } },
      { name: 'OAuth2 / OIDC',
        signs: 'Every access token and refresh token, and the ID Token, with ' +
               'the realm\'s RSA key as RS256. A client that registers ' +
               '`id_token_signed_response_alg` gets that algorithm instead, ' +
               'for its ID Token and its back-channel Logout Token alike ' +
               '(section 2.4: the same keys as ID Tokens), ' +
               'out of the shared JWS table — every curve, both Edwards ' +
               'curves, and the post-quantum and composite ones. A signed ' +
               'UserInfo response the same way, plus the HMAC family (signed ' +
               'with that client\'s own `client_secret`, which is why it ' +
               'needs no published key) and `none`. **AND AN RFC 9701 JWT ' +
               'INTROSPECTION RESPONSE** (2026-09-13), typed ' +
               '`token-introspection+jwt`, in RS256 or the ' +
               '`introspection_signed_response_alg` the resource server ' +
               'registered — the same table and the HMAC family, never ' +
               '`none`.',
        verifies: 'A REQUEST OBJECT (RFC 9101, 2026-09-13), signed by the ' +
                  'client with a key it registered or with its secret, and ' +
                  'DECRYPTS one encrypted to this realm\'s published `use: ' +
                  '"enc"` RSA or EC key or to that secret. DPoP proofs (RFC ' +
                  '9449), `private_key_jwt` and `client_secret_jwt` client ' +
                  'assertions, and every access token it is handed at a ' +
                  'protected endpoint — against its own JWKS, with ' +
                  '`oauth2.clockSkewS` applied. **AND AN XML SIGNATURE**, ' +
                  'which is the one thing in this family that is not a JWS: ' +
                  'RFC 7522 puts a SAML 2.0 assertion in the same two ' +
                  'request parameters RFC 7523 puts a JWT in, so the token ' +
                  'endpoint verifies an enveloped XML Signature over a ' +
                  '<saml:Assertion> through the same vendored engine ' +
                  '`/saml2` signs with. It is checked against a certificate ' +
                  'REGISTERED against the asserting party and never against ' +
                  'one that merely chains to this realm\'s CA — which is ' +
                  'stricter than the `x5c` path RFC 7523 allows, because a ' +
                  'chain proves the realm issued a key and says nothing ' +
                  'about which application holds it.',
        encrypts: 'A UserInfo response for a client that registered ' +
                  '`userinfo_encrypted_response_alg`, and a JWT ' +
                  'introspection response for one that registered ' +
                  '`introspection_encrypted_response_alg`: JWE compact, ' +
                  'RSA-OAEP or ECDH-ES to the client\'s own key, a Nested ' +
                  'JWT when signed. **AND EVERY REFRESH TOKEN** ' +
                  '(2026-09-12): the signed JWT is sealed as a nested JWT ' +
                  '(`cty: JWT`, RFC 7519 section 11.2) to THIS REALM\'s own ' +
                  'keys, under `oauth2.refreshTokenEncryptionAlg` and `…Enc` ' +
                  '— any key management algorithm the shared JWE table ' +
                  'implements, to the realm\'s RSA key, EC key or a secret ' +
                  'of its own. No client ever sees or needs those keys.',
        decrypts: 'A JWE encrypted to this service\'s RSA key, RSA-OAEP-256 ' +
                  'only — a shorter list than it encrypts with on purpose, ' +
                  'because it holds no EC private key to agree with. **AND A ' +
                  'REFRESH TOKEN**, under whichever algorithm its own header ' +
                  'names, before the refresh grant, introspection, ' +
                  'revocation or token exchange reads anything in it; an ' +
                  'unencrypted refresh token is refused.',
        hashes: '`at_hash` and `c_hash` are the left half of the SHA-256 of ' +
                'the token; PKCE `S256` is SHA-256 over the verifier; ' +
                '`cnf.jkt` is an RFC 7638 JWK Thumbprint (SHA-256) and ' +
                '`cnf["x5t#S256"]` is the SHA-256 of the client ' +
                'certificate\'s DER.',
        whatItDoesNot: 'It verifies no access token it did not issue, except ' +
                       'at UserInfo, and it follows no `jwks_uri` — an ' +
                       'inline `jwks` on the registration is the only key it ' +
                       'will read.',
        envelopes: ['jws', 'jwe', 'jwk', 'jwt', 'thumbprint', 'dpop', 'mtls',
                    'pkce'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Tokens this service mints by default', ['RS256']],
            ['ID Token, when a client registers one',
             oauth2.ID_TOKEN_SIGNING_ALGS],
            ['UserInfo response', oauth2.USERINFO_SIGNING_ALGS],
            ['JWT introspection response (RFC 9701)',
             introspectionJwt.SIGNING_ALGS],
            ['JWT introspection response encryption (RFC 9701)',
             introspectionJwt.ENCRYPTION_ALGS],
            ['Request object signature (RFC 9101)',
             applicationRegistry.REQUEST_OBJECT_SIGNING_ALGS],
            ['Request object decryption (RFC 9101)',
             applicationRegistry.REQUEST_OBJECT_ENCRYPTION_ALGS],
            ['DPoP proof', dpop.SIGNING_ALGS],
            ['Client assertion', clientAuth.SYMMETRIC_METHODS
              .concat(clientAuth.ASYMMETRIC_METHODS)],
            // **OUT IS THE ASYMMETRIC HALF AND IN IS THE WHOLE TABLE, AND THEY
            // WERE THE SAME LIST UNTIL crypto.js GREW ONE.** This row read
            // `JWE_ALGS` and was right while that constant held only the RSA
            // and ECDH families; the day the AESKW, AESGCMKW, PBES2 and `dir`
            // families arrived it started advertising, on the page that is
            // meant to describe what this service DOES, key management no
            // outward surface here will ever use — both callers of
            // `encryptJweCompact()` encrypt to a recipient's published key and
            // hold no shared secret with it, which is the argument
            // `JWE_ASYMMETRIC_ALGS` exists to carry. `userinfo_encryption_alg_
            // values_supported` never moved, and `tests/vendored/admin_api.js`
            // is what compared the two.
            ['JWE key management (out)', stsCrypto.JWE_ASYMMETRIC_ALGS],
            ['JWE key management (in)', stsCrypto.JWE_DECRYPT_ALGS],
            ['JWE content encryption', Object.keys(stsCrypto.JWE_ENCS)],
            // THE REFRESH-TOKEN ENVELOPE (2026-09-12). The WHOLE table rather
            // than the asymmetric half, because this is the one JWE here
            // encrypted to a key THIS SERVICE holds — its own RSA and EC keys
            // and a secret of the realm's — so every family is genuinely in
            // use. Read off the table that performs it, like every row here.
            ['Refresh token encryption (to this realm\'s own keys)',
             stsCrypto.JWE_ALGS]
          ];
        } },

      { name: 'Federation',
        signs: 'The SAML 2.0 `<AuthnRequest>` it sends a foreign identity ' +
               'provider, enveloped, RSA-SHA256 over exclusive c14n — the ' +
               'same signer every other document here goes through.',
        verifies: 'THE WHOLE POINT OF THE FEATURE. A partner\'s SAML ' +
                  'Response and the Assertion inside it, each checked ' +
                  'SEPARATELY and each against the certificate configured on ' +
                  'the relationship — never against a certificate the ' +
                  'document carries in its own `ds:KeyInfo`, which is the ' +
                  'check a naive implementation skips. A partner\'s ID Token ' +
                  'as an ordinary JWS against the partner\'s published keys.',
        encrypts: '',
        decrypts: '',
        hashes: 'Whatever the partner\'s `DigestMethod` names, out of the ' +
                'vendored table below.',
        whatItDoesNot: 'It does not decrypt an assertion a partner ' +
                       'encrypted, and it does not consume a federated ' +
                       'sign-out. THE GATE IS ON THE SIGNER AND NOT ON THE ' +
                       'SUBJECT: past a verified signature any username is ' +
                       'accepted. This is the one surface here where a ' +
                       'missing check is an authentication bypass for every ' +
                       'protocol in the process — see federation/CLAUDE.md.',
        envelopes: ['xmldsig', 'c14n', 'jws'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Outbound request signature',
             ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']],
            ['Inbound signature, any of',
             stsCrypto.xmlSignatureAlgorithms().verified.map(
               function (row) {
                 return row.uri;
               })],
            ['Inbound ID Token', stsCrypto.JWS_ASYMMETRIC_ALGS]
          ];
        } },

      { name: 'SAML 2.0',
        signs: 'Assertions, Responses, LogoutRequests and the ' +
               'per-service-provider metadata — enveloped, RSA-SHA256, ' +
               'EXCLUSIVE canonicalization, with the `<ds:Signature>` ' +
               'immediately after `<Issuer>` where the schema puts it. The ' +
               'HTTP Redirect binding is signed differently and that is the ' +
               'specification\'s doing rather than this service\'s: it is a ' +
               'DETACHED signature over the octets of the query string, with ' +
               '`SigAlg` naming the algorithm as a parameter.',
        verifies: 'A service provider\'s AuthnRequest, LogoutRequest and ' +
                  'LogoutResponse and ArtifactResolve signatures (since ' +
                  '2026-09-17) — the Redirect binding\'s detached query ' +
                  'signature, the SimpleSign binding\'s over the form ' +
                  'values, or an enveloped one — against the service ' +
                  'provider\'s REGISTERED certificates (RSA, EC, EdDSA, ' +
                  'DSA, ML-DSA, SLH-DSA), never the one in the request; a ' +
                  'consumed metadata document\'s own signature against the ' +
                  'entry\'s certificate or the realm\'s trust anchors; and ' +
                  'its own artifacts. A service ' +
                  'provider\'s `<EncryptedID>` is decrypted rather than ' +
                  'verified.',
        encrypts: 'The assertion in a Response, as `<EncryptedAssertion>`, ' +
                  'and the NameID in a LogoutRequest as `<EncryptedID>` — ' +
                  'per application, to the certificate held on its entry. ' +
                  'SIGNED FIRST AND THEN ENCRYPTED, which is the order every ' +
                  'service provider expects: the signature is inside the ' +
                  'ciphertext and is what survives decryption.',
        decrypts: 'An `<EncryptedID>` a service provider sends in a ' +
                  'LogoutRequest, to the realm\'s RSA key.',
        hashes: 'SHA-256 for the Reference digest; SHA-1 inside ' +
                'RSA-OAEP-MGF1P, because that is what the URI MEANS rather ' +
                'than a choice this service made.',
        whatItDoesNot: 'It does not accept a SHA-1 signature unless ' +
                       'saml.allowSha1Signatures is on, nor MD5, a MAC or ' +
                       'a stateful hash-based signature at all. A service ' +
                       'provider it holds no certificate for, with ' +
                       'encryption turned on, gets the assertion IN CLEAR, ' +
                       'loudly, in development, and is refused in product; ' +
                       'one whose metadata publishes an encryption key is ' +
                       'encrypted to in both.',
        envelopes: ['xmldsig', 'xmlenc', 'c14n'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Signature',
             ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']],
            ['Inbound signature, any of',
             stsCrypto.xmlSignatureAlgorithms().verified.map(
               function (row) {
                 return row.uri;
               })],
            ['Block cipher (saml2.encryptionAlgorithm)',
             [String(config.value('saml2.encryptionAlgorithm'))]],
            ['Key transport (saml2.keyTransportAlgorithm)',
             [String(config.value('saml2.keyTransportAlgorithm'))]],
            ['Block ciphers offered', Object.keys(stsCrypto.BLOCK_CIPHERS)],
            ['Key transports offered', Object.keys(stsCrypto.KEY_TRANSPORTS)]
          ];
        } },

      { name: 'SAML 1.1',
        signs: 'Assertions and Browser/POST Responses, RSA-SHA256 over ' +
               'exclusive c14n, through the same signer. The PLACEMENT ' +
               'differs and the reason is the grammar rather than the ' +
               'crypto: a 1.1 assertion has no `<Issuer>` ELEMENT — in 1.1 ' +
               'the issuer is an ATTRIBUTE — so "after the issuer" is not a ' +
               'position that exists and the signature goes LAST. A Response ' +
               'signs FIRST, ahead of the assertion it carries.',
        verifies: 'Its own artifacts, for the mock relying party.',
        encrypts: '',
        decrypts: '',
        hashes: 'SHA-256 for the Reference digest.',
        whatItDoesNot: 'SAML 1.1 has no encryption at all — ' +
                       '`<EncryptedAssertion>` arrived with 2.0 — and no ' +
                       'request message to verify a signature on. The ' +
                       'reference URI names `AssertionID` or `ResponseID`, ' +
                       'which is the whole reason the shared signer resolves ' +
                       'an id by SEARCHING for one rather than being told ' +
                       'its name.',
        envelopes: ['xmldsig', 'c14n'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Signature',
             ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']]
          ];
        } },

      { name: 'WS-Federation',
        signs: 'The SAML assertion inside the `wresult`, in whichever ' +
               'version the relying party asked for, through the shared ' +
               'signer.',
        verifies: 'The mock relying party at `/wsfed/rp` verifies that ' +
                  'assertion check by check, and is told WHICH element to ' +
                  'verify rather than taking the first `<ds:Signature>` in ' +
                  'the document — the defect four separate verifiers here ' +
                  'used to have.',
        encrypts: '',
        decrypts: '',
        hashes: 'SHA-256 for the Reference digest.',
        whatItDoesNot: 'It fakes no `wauth` — a demand the session cannot ' +
                       'meet is a step-up, and an AuthenticationMethod is ' +
                       'what the session did — and dereferences no ' +
                       '`wreqptr` — ' +
                       'fetching a URL somebody registered is a server-side ' +
                       'request forgery with a citation attached.',
        envelopes: ['xmldsig', 'c14n', 'wss'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Signature',
             ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']]
          ];
        } },

      { name: 'WS-Trust',
        signs: 'The SAML assertion in the RequestSecurityTokenResponse, 1.1 ' +
               'or 2.0, through the shared signer.',
        verifies: 'It READS a requester\'s `<wsse:Security>` credential and ' +
                  'the `<ds:X509Certificate>` in a signed request — the ' +
                  'latter to find out who to ENCRYPT to. It checks no ' +
                  'password behind it.',
        encrypts: 'With `?encrypt=1`, the issued 2.0 assertion, to the ' +
                  'certificate found in the request signature. Same two ' +
                  'tables as SAML 2.0, because it is the same code — ' +
                  '`saml/saml2.ts` re-exports it.',
        decrypts: '',
        hashes: 'SHA-256 for the Reference digest.',
        whatItDoesNot: 'It polices no delegation: an RST asking for a token ' +
                       'for somebody else is answered. And it produces no ' +
                       'signed SOAP envelope of its own — see WS-Security ' +
                       'below, which is the row that says what this service ' +
                       'does and does not do with that specification.',
        envelopes: ['xmldsig', 'xmlenc', 'c14n', 'wss'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Signature',
             ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']],
            ['Block ciphers offered', Object.keys(stsCrypto.BLOCK_CIPHERS)],
            ['Key transports offered', Object.keys(stsCrypto.KEY_TRANSPORTS)]
          ];
        } },

      { name: 'Kerberos',
        signs: 'Nothing, in the public-key sense — THIS IS THE ONE FAMILY ' +
               'HERE WITH NO ASYMMETRIC CRYPTOGRAPHY IN IT AT ALL. Integrity ' +
               'comes from a keyed checksum (HMAC-SHA1-96, HMAC-SHA-256-128, ' +
               'HMAC-SHA-384-192 or HMAC-MD5) under a key derived from the ' +
               'long-term key for that message\'s key usage number.',
        verifies: 'Pre-authentication, every AP-REQ authenticator, and the ' +
                  'checksums above. THIS IS THE ONE DOOR IN THIS SERVICE ' +
                  'THAT REALLY VERIFIES A CREDENTIAL, and it is not a policy ' +
                  'choice: in Kerberos the password IS the key, so a KDC ' +
                  'that accepted anything would still have to pick a key the ' +
                  'client could not guess. The permissiveness moved into the ' +
                  'ACCOUNT POLICY instead — one shared password, an account ' +
                  'created for any name.',
        encrypts: 'Every encrypted part of every message: the AS-REP ' +
                  'enc-part, the ticket, the authenticator, the TGS-REP. AES ' +
                  'in CTS mode with a confounder, or RC4-HMAC.',
        decrypts: 'The same, in the other direction, including a real ' +
                  'service ticket presented at `/authn/spnego`.',
        hashes: 'PBKDF2-HMAC-SHA1 (RFC 3962) or PBKDF2-HMAC-SHA-256/384 (RFC ' +
                '8009) for string-to-key; MD4 (the NT hash) for RC4-HMAC, ' +
                'which is unsalted and is why salt discovery matters only ' +
                'for AES.',
        whatItDoesNot: 'No PKINIT, so no certificate ever enters a Kerberos ' +
                       'exchange here. DES and 3DES are DECODE-ONLY — named ' +
                       'so a capture renders honestly, never performed.',
        envelopes: ['krb5', 'gssapi'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [['Encryption types performed', self.kerberosEtypes().performed
            .map(function (row) { return row.id + ' ' + row.name; })]];
        } },

      { name: 'SPNEGO',
        signs: 'Nothing of its own. The MIC in a `negTokenResp` is a ' +
               'Kerberos checksum over the negotiation, computed with the ' +
               'mechanism\'s key.',
        verifies: 'The AP-REQ inside the GSS token, through the Kerberos ' +
                  'acceptor — including the replay cache, which is the one ' +
                  'check at this door whose absence would be a security bug ' +
                  'rather than a fidelity one.',
        encrypts: '',
        decrypts: 'The AP-REQ authenticator, under the service\'s long-term ' +
                  'key.',
        hashes: 'Whatever the negotiated encryption type\'s checksum uses.',
        whatItDoesNot: 'It adds no check of its own on top of the ' +
                       'acceptor\'s, and it negotiates no mechanism but ' +
                       'Kerberos v5.',
        envelopes: ['krb5', 'gssapi'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [['Negotiated mechanism',
                   ['Kerberos v5 (1.2.840.113554.1.2.2)']]];
        } },

      // **`signs` SAID "FROM A SELF-SIGNED AUTHORITY GENERATED AT START" UNTIL
      // 2026-09-17 (#70)**, six days after the X.509 authority became the
      // realm's SPIFFE Issuing CA under the service Root
      // (`spiffe/spiffe_ca.ts`, `spiffe/CLAUDE.md`). The self-signed authority
      // is the FALLBACK of a realm with no hierarchy, and `keyMaterial()`'s
      // `authoritySource` says which one a realm is using.
      { name: 'SPIFFE',
        signs: 'X509-SVIDs, under this realm\'s SPIFFE Issuing CA — a CA ' +
               'under the realm\'s Intermediate and the service Root, so the ' +
               'bundle publishes the Root and an SVID carries the Issuing CA ' +
               'and the Intermediate in its chain. A realm with no hierarchy ' +
               'falls back to a self-signed authority, which is then its own ' +
               'anchor. JWT-SVIDs are ordinary JWS, from a JWT authority ' +
               'generated per start in either mode. Each key type fixes both ' +
               'the certificate signature algorithm and the JWS `alg` — a ' +
               'certificate whose declared algorithm and actual signature ' +
               'disagree parses perfectly and is refused with a message ' +
               'about a signature, naming neither hash.',
        verifies: 'An X509-SVID over mutual TLS on the SPIRE Server API\'s ' +
                  'TCP port, and a JWT-SVID at `ValidateJWTSVID`.',
        encrypts: '',
        decrypts: '',
        hashes: 'SHA-256 over the SVID DER wherever one is recorded, and the ' +
                'certificate signature\'s own digest, which follows the key ' +
                'type.',
        whatItDoesNot: 'It attests no workload and no node — what the ' +
                       'Workload API lacks is ATTESTATION, not ' +
                       'authentication, and its specification says it MUST ' +
                       'NOT authenticate. It records no SVID it mints, so ' +
                       'one is revoked only by naming its serial by hand; ' +
                       'revoking the realm\'s SPIFFE Issuing CA on ' +
                       '/admin/pki is what refuses every SVID under it at ' +
                       'the SPIRE Server API. The directory records who ' +
                       'may still be ISSUED one, which is a different ' +
                       'claim. Ed25519 is available for an X509-SVID key ' +
                       '(and a self-signed fallback authority) and NOT for ' +
                       'the JWT authority, ' +
                       'which is a limit of `jsonwebtoken` and not of the ' +
                       'specification.',
        envelopes: ['x509', 'jws', 'jwk', 'mtls'],
        // **TWO ROWS HERE NAMED ONE KEY FOR ANOTHER UNTIL 2026-09-17 (#70).**
        // `X.509 authority in this process` printed `spiffe.x509KeyType`,
        // which decides the key in each SVID and — since the authority became
        // the realm's Issuing CA — the authority's only on the self-signed
        // fallback. The authority's own key type is read off the authority
        // now, as `keyMaterial()` already did. Both settings are read in the
        // AMBIENT realm, so the rows say "this realm".
        algorithms: function () {
          log.debug("Entering algorithms().");
          const authority = (spiffeCa.state().x509Authorities || [])[0];
          log.debug("Leaving algorithms().");
          return [
            ['Key types offered (SVID, fallback authority, JWT authority)',
             spiffeCa.KEY_TYPES.map(function (t) {
               // `', no JWT'` printed `ed25519 (ed25519, no JWT) )` until
               // 2026-09-17 — a closing parenthesis inside the string too.
               return t.id + ' (' + t.sigAlg + (t.jwtAlg ? ', ' + t.jwtAlg
                                                         : ', no JWT') + ')';
             })],
            ['X.509 authority in this realm',
             [authority
               ? String(authority.keyType) + ' — ' +
                 (authority.source === 'pki'
                   ? 'this realm\'s SPIFFE Issuing CA, under the service Root'
                   : 'self-signed: this realm has no certificate authority')
               : 'none yet']],
            ['X509-SVID key in this realm',
             [String(config.value('spiffe.x509KeyType'))]],
            ['JWT authority in this realm',
             [String(config.value('spiffe.jwtKeyType'))]]
          ];
        } },

      { name: 'SCIM',
        signs: 'Nothing. It MINTS no credential — it is the one family here ' +
               'that only ever checks them.',
        verifies: 'A credential in any of the six schemes RFC 7644 section 2 ' +
                  'names, and TWO OF THE SIX ARE REALLY VERIFIED: HTTP ' +
                  'Digest computes the response over the configured ' +
                  'password, and a HOBA signature is checked against the ' +
                  'public key the client registered. The other four are ' +
                  'turnstiles — any password but one passes Basic, and the ' +
                  'OAuth ones need only a token this service issued carrying ' +
                  '`scim:read` or `scim:write`.',
        encrypts: '',
        decrypts: '',
        hashes: 'RFC 7616 Digest: SHA-256, SHA-512-256 and MD5, each with ' +
                'its `-sess` variant, offered strongest first because ' +
                'section 3.7 says so and because a client takes the first it ' +
                'understands. Each is checked against the openssl this ' +
                'process actually has, so a challenge never names an ' +
                'algorithm the server cannot compute.',
        whatItDoesNot: 'It deactivates nobody on `active: false`, and it ' +
                       'stores no password of its own — the Digest password ' +
                       'is a setting.',
        envelopes: ['digest', 'hoba', 'jws', 'dpop', 'mtls'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Authentication schemes', scimAuth.SCHEMES.map(function (s) {
              return s.name;
            })],
            ['Digest', (scimAuth.DIGEST_ALGORITHMS || []).map(function (row) {
              return row.token;
            })],
            ['HOBA', ['RSA-SHA256 (algorithm ' +
                      String(scimAuth.HOBA_ALG_RSA_SHA256) + ')']]
          ];
        } },

      { name: 'Shared Signals',
        signs: 'EVERY SECURITY EVENT TOKEN, and it is the document in this ' +
               'service most worth thinking about the algorithm for. A SET ' +
               'records that something HAPPENED and RFC 8417 section 4.1.4 ' +
               'forbids it to expire, so it is read long after it was ' +
               'written — which is the case a harvest-now-decrypt-later ' +
               'argument is actually about. The signature goes through the ' +
               'SAME signer every other JWT here goes through, so ' +
               '`ssf.signingAlgorithm` reaches the whole table: RS256 by ' +
               'default, the PS and ES families, EdDSA, and the post-quantum ' +
               'ones — ML-DSA at three sizes, SLH-DSA at two, and the six ' +
               'composite ML-DSA + traditional algorithms. An SLH-DSA ' +
               'signature takes seconds and runs on the worker pool, so this ' +
               'service answers throughout and the receiver waits.',
        verifies: 'A Security Event Token pushed AT this service at `POST ' +
                  '/ssf/receive` — the roles reversed — against its own ' +
                  'JWKS, which is the only key it has. A SET signed by ' +
                  'anybody else is reported as NOT VERIFIABLE HERE rather ' +
                  'than as invalid, and is ACCEPTED anyway unless ' +
                  '`ssf.receiveRequireSignature` is on: a receiver that ' +
                  'refused could not show anybody what arrived or why it did ' +
                  'not verify, which is the question being asked. It also ' +
                  'verifies the access token on every stream management ' +
                  'call, through the same check every other protected ' +
                  'endpoint here uses.',
        encrypts: 'Nothing. SSF has no encrypted-SET profile — RFC 8417 ' +
                  'permits a JWE-wrapped SET and neither this service nor ' +
                  'any deployed transmitter emits one, so what protects an ' +
                  'event in transit is TLS on the delivery endpoint, which ' +
                  'is why `ssf.pushAllowInsecure` ships OFF.',
        decrypts: 'Nothing, for the same reason.',
        hashes: 'Whatever the chosen signature algorithm implies, and ' +
                'nothing of its own: a SET carries no digest of anything the ' +
                'way an ID Token carries `at_hash`.',
        whatItDoesNot: 'IT SIGNS BADLY ON PURPOSE WHEN ASKED TO. ' +
                       '`ssf.breakSetSignature` changes ONE CHARACTER of the ' +
                       'signature after signing, so a receiver that does not ' +
                       'verify accepts an event nothing signed. It is a ' +
                       'character rather than a truncation deliberately: a ' +
                       'truncated signature fails the base64url decode and ' +
                       'is reported as a MALFORMED token, which is a ' +
                       'different bug from a bad one for whoever is being ' +
                       'tested.',
        envelopes: ['jws', 'jwt', 'jwk', 'dpop', 'tls'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Security Event Tokens, right now',
             [ssfEvents.signingAlgorithm()]],
            ['Any of, through ssf.signingAlgorithm',
             stsCrypto.JWS_ASYMMETRIC_ALGS],
            ['Authentication schemes', ssfAuth.SCHEMES.map(function (one) {
              return one.name;
            })]
          ];
        } },

      // **`verifies` AND `hashes` DESCRIBED DEVELOPMENT MODE AS THE WHOLE
      // SERVICE UNTIL 2026-09-17 (#70)** — "every bind succeeds" and "no
      // `userPassword` is stored" — five days after product mode began
      // verifying binds and authorizing writes, and the LDAP add and modify
      // began storing a scrypt hash like every other door (both 2026-09-12;
      // `ldap/CLAUDE.md`, `common/credentials.ts`). Both modes are stated,
      // as the TOTP and PKI rows state theirs.
      { name: 'LDAP',
        signs: 'Nothing.',
        verifies: 'A simple bind\'s password, in PRODUCT mode, against the ' +
                  'entry\'s scrypt `userPassword` — after refusing an ' +
                  'anonymous bind, any bind on the plain port 389, an empty ' +
                  'password and a DN or address past its failed-bind limit. ' +
                  'Writes are then authorized there (an administrator ' +
                  'anything, anybody else a few attributes of their own ' +
                  'entry) and a read needs a bind. In DEVELOPMENT mode every ' +
                  'bind succeeds — any DN, any password, anonymous, on 389 ' +
                  'and on 636 alike — and nothing is authorized. In both ' +
                  'modes the one password spelled `invalid` is refused, so a ' +
                  'client\'s failure path can be exercised.',
        encrypts: 'The LDAPS listener on 636 is TLS, on the certificate ' +
                  '`tls/tls_server.js` holds — certified under the service ' +
                  'Root — which the main port and the debugger listener ' +
                  'present too. One set of handlers and one store sit behind ' +
                  'both directory ports.',
        decrypts: 'The same connection, in the other direction.',
        hashes: '`userPassword` is stored as a scrypt hash in BOTH modes, ' +
                'through crypto.hashSecret(), whichever door wrote it — an ' +
                'LDAP add or modify included. Product mode refuses a value ' +
                'sent already hashed, which cannot be held to the password ' +
                'policy; development keeps one as given, which is how a ' +
                'directory moves between two instances.',
        whatItDoesNot: 'It answers NO SASL MECHANISM — the root DSE omits ' +
                       '`supportedSASLMechanisms` rather than publishing it ' +
                       'empty, because an LDAP attribute always has at least ' +
                       'one value and an empty one is not a weaker claim, it ' +
                       'is a malformed one. So no GSSAPI bind, no EXTERNAL ' +
                       'bind, and no StartTLS: 636 is TLS from the first ' +
                       'byte.',
        envelopes: ['tls'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [['LDAPS transport',
                   ['TLS, on the shared server certificate']]];
        } },

      // **THIS ROW DESCRIBED THE ARRANGEMENT BEFORE 2026-09-11 UNTIL
      // 2026-09-17 (#70)**: three self-signed certificates, none persisted,
      // and a verified client certificate turned into a login nowhere. Since
      // 2026-09-11 every one is a leaf of the service Root (`common/pki.js`,
      // `tls/CLAUDE.md`), and a verified client certificate has been a sign-in
      // since 2026-09-05 — at `GET /tls/sign-in` since 2026-09-16. LDAPS 636
      // asks for no client certificate (`docs/pki.md`), so it left `verifies`.
      { name: 'PKI / X.509',
        signs: 'Nothing itself — the certificates this service PRESENTS are ' +
               'issued by `common/pki.js` (the PKI row above) over keys made ' +
               'here. The SIGNING certificate is the realm\'s RSA 2048 key, ' +
               'certified twice, by the JOSE and the XML Issuing CAs. The ' +
               'TLS SERVER certificate is issued by the TLS Issuing CA ' +
               'under the process Intermediate, over a key generated at ' +
               'every start, with the subjectAltName that is the only ' +
               'place the names are, because RFC 6125 has said the CN is ' +
               'ignored since 2011. SPIFFE\'s authority is the realm\'s ' +
               'SPIFFE Issuing CA. All of them chain to one Root, which ' +
               'PRODUCT mode keeps in the ' +
               'keystore and DEVELOPMENT mode rebuilds at every start. With ' +
               'no hierarchy, or with `tls.certificateFile` set, the ' +
               'certificate is self-signed or the one supplied.',
        verifies: 'A client certificate presented on the main port (or on ' +
                  'the debugger listener, which asks the same way), against ' +
                  'the truststore\'s anchors (the service Root among them ' +
                  'under `tls.trustIssuedClientCertificates`), with its ' +
                  'revocation checked under `pki.revocationCheck` — and ' +
                  'then `GET /tls/sign-in` turns a verified one into a ' +
                  'SESSION in the realm of the authority that signed it, ' +
                  'while RFC 8705 client authentication binds it to a ' +
                  'token. LDAPS 636 asks for no client certificate.',
        encrypts: 'Every byte on LDAPS 636 and, when `global.https` is on ' +
                  '(every appconfig file in env/ sets it, since 2026-08-30), ' +
                  'on the main port and the debugger listener. The key ' +
                  'exchange is node\'s OpenSSL default; on 636 and the main ' +
                  'port the protocol floor is ' +
                  '`tls.minVersion` (TLS 1.2 by default) and the suites ' +
                  '`tls.ciphers` (node\'s list when empty).',
        decrypts: 'The same.',
        hashes: 'SHA-256, everywhere a certificate is named: over the DER ' +
                'for RFC 8705\'s `x5t#S256` confirmation and `/tls`\'s ' +
                'fingerprint, and over the public key for the SPKI pin the ' +
                'test suite carries.',
        whatItDoesNot: 'The first fetch of the anchor cannot be verified — ' +
                       'there is no plain listener left to fetch it from, so ' +
                       'it is made with verification off. In DEVELOPMENT ' +
                       'mode that fetch is owed again after every restart, ' +
                       'because the Root is rebuilt; in PRODUCT mode, and ' +
                       'with a supplied certificate, it is owed once. An ' +
                       'application\'s certificate is refused as a sign-in: ' +
                       'it is an RFC 8705 client credential.',
        envelopes: ['x509', 'tls', 'mtls'],
        // **THE `Server certificate` ROW SAID "self-signed" UNCONDITIONALLY
        // UNTIL 2026-09-17 (#70)**, a literal beside a certificate that had
        // stopped being one. It is read off the certificate now, as
        // `keyMaterial()`'s signing row is.
        algorithms: function () {
          log.debug("Entering algorithms().");
          const cert = tlsServer.serverCertificate();
          log.debug("Leaving algorithms().");
          return [
            ['Server certificate', [self.listenerCertificateSummary(cert)]],
            ['Certificate binding', [mtls.CONFIRMATION_MEMBER +
                                     ' — SHA-256 over the DER, base64url']]
          ];
        } },

      { name: 'WebAuthn / CTAP',
        signs: 'Nothing. The AUTHENTICATOR signs; this service is the ' +
               'relying party, which is the half that only ever checks.',
        verifies: 'The registration attestation and every assertion: the ' +
                  'signature over `authenticatorData || ' +
                  'SHA-256(clientDataJSON)`, against the COSE public key the ' +
                  'credential registered.',
        encrypts: '',
        decrypts: '',
        hashes: 'SHA-256 twice over — the client data hash the signature ' +
                'covers, and the RP ID hash inside the authenticator data ' +
                'that is compared byte for byte against SHA-256 of the ' +
                'origin\'s domain.',
        whatItDoesNot: 'It validates no attestation STATEMENT whatever ' +
                       '`webauthn.attestation` asks for — the certificate ' +
                       'chain a packed or TPM attestation carries is parsed ' +
                       'and not chased, and there is no metadata service, no ' +
                       'vendor trust anchor and no model allow-list here. ' +
                       'The registration offers fewer algorithms than the ' +
                       'verifier ACCEPTS, which is deliberate: what a ' +
                       'platform authenticator actually produces is what a ' +
                       'person came here to see. The one ceremony option ' +
                       'this service also CHECKS is ' +
                       '`webauthn.userVerification`, because the UV flag is ' +
                       'inside the bytes the authenticator signed.',
        envelopes: ['cose', 'webauthn'],
        // ---------------------------------------------------------------------
        // THE OFFERED LIST WAS TYPED HERE UNTIL 2026-09-10 AND IT IS A SETTING
        // NOW.
        //
        // It read `['ES256 (-7)', 'RS256 (-257)']` — correct while the
        // ceremony's `pubKeyCredParams` was a literal in a string in
        // `authn/authn.ts`, and wrong the moment `webauthn.algorithms` could
        // move it. That is precisely the drift this page exists to prevent, so
        // it is read from the module that BUILDS the offer, exactly as the TOTP
        // row below reads `inUse` off the live setting. The ACCEPTED list stays
        // the verifier's own table, because those are two different facts and
        // the gap between them is what the row's last sentence is about.
        // ---------------------------------------------------------------------
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Offered at registration',
             webauthnPolicy.algorithmsOffered().map(function (name) {
               return name + ' (' + webauthnPolicy.ALG_IDS[name] + ')';
             })],
            ['Accepted at verification',
             Object.keys(webauthn.COSE_ALGS).map(function (k) {
               return webauthn.COSE_ALGS[k] + ' (' + k + ')';
             })],
            ['Curves', Object.keys(webauthn.COSE_CURVES).map(function (k) {
              return webauthn.COSE_CURVES[k];
            })],
            ['User verification',
             [webauthnPolicy.settings().userVerification +
              (webauthnPolicy.requireUserVerification()
                ? ' — requested AND checked against the signed UV flag'
                : ' — requested only; nothing is refused on it')]]
          ];
        } },

      // ---------------------------------------------------------------------
      // ONE-TIME PASSWORDS (2026-09-10). The row that most needs saying out
      // loud, because it is the one place on this page where SHA-1 is the
      // RECOMMENDED value rather than a legacy one — and the reason is not
      // compatibility with something old, it is that HMAC-SHA-1 over a counter
      // is a keyed MAC and not a collision-resistant digest, so SHA-1's
      // weaknesses do not reach it.
      //
      // The algorithm table is READ FROM `common/totp.ts`, which is this page's
      // whole design: the table lives with the code that performs the
      // algorithm, and `inUse` comes off the live setting so the report says
      // what this deployment actually does rather than what the module can do.
      { name: 'One-time passwords (TOTP)',
        signs: 'Nothing that leaves this service. An HOTP value IS a ' +
               'truncated HMAC — RFC 4226 section 5.3 — so this family ' +
               'computes a keyed MAC and then compares it, which is why the ' +
               'primitive lives in common/crypto.js beside every other ' +
               'signature here rather than in the module that decides the ' +
               'policy.',
        verifies: 'A presented code, by computing the HMAC for every time ' +
                  'step in the skew window and comparing in constant time. ' +
                  'EVERY step is computed even after a match, deliberately: ' +
                  'returning early would make the time taken depend on WHICH ' +
                  'step matched, which is a better oracle than the digit ' +
                  'comparison this bothers to make constant-time.',
        encrypts: 'The shared secret at rest, in PRODUCT mode — AES-256-GCM ' +
                  'under the same key-encryption key that protects the ' +
                  'signing keys, through common/keystore.js. In DEVELOPMENT ' +
                  'mode it is stored as base32, because the key-encryption ' +
                  'key there is generated per run and sealing would mean an ' +
                  'authenticator that silently stopped working at the next ' +
                  'restart.',
        decrypts: 'The same secret, to verify a code. **THIS IS THE ONE ' +
                  'CREDENTIAL IN THIS SERVICE THAT CAN BE READ BACK** — a ' +
                  'password is a scrypt hash and can only be compared ' +
                  'against, and verifying a one-time code means COMPUTING ' +
                  'it. That is not a weakness in RFC 6238; it is what ' +
                  '"shared secret" means, and it is exactly why this ' +
                  'mechanism is a SECOND factor here and can never be made a ' +
                  'first one.',
        hashes: 'SHA-1, SHA-256 or SHA-512, inside the HMAC and nowhere else.',
        whatItDoesNot: 'It never tells anybody what the current code is, and ' +
                       'it never enrols anybody at a sign-in screen — ' +
                       'enrolment means being shown a secret, so it happens ' +
                       'where the person is already authenticated or holds ' +
                       'an activation link. There is no counter-based HOTP ' +
                       'as an authentication mechanism, and no ' +
                       'resynchronisation protocol: the skew window is the ' +
                       'whole of what is offered for a drifting clock.',
        envelopes: [],
        algorithms: function () {
          log.debug("Entering algorithms().");
          const report = totp.report();
          log.debug("Leaving algorithms().");
          return [
            ['HMAC (the enrolled parameter, not a live one)',
             report.algorithms.map(function (one) {
               return one.name +
                 (one.inUse ? ' — what a NEW enrolment gets' : '');
             })],
            ['Truncation', [report.truncation]],
            ['Shared secret', [String(report.secretBits) + '-bit, ' +
                               report.encoding]],
            ['Live settings', [String(report.digits) + ' digits, every ' +
                               String(report.period) + ' seconds, ' +
                               String(report.window) + ' step(s) of skew ' +
                               'forgiven either side']]
          ];
        } },

      // ---------------------------------------------------------------------
      // RECOVERY CODES (2026-09-10). A family that SIGNS NOTHING and verifies
      // no signature, with a row anyway because what it keeps at rest is a set
      // of live credentials.
      //
      // **IT WAS WRITTEN WHEN THE SET WAS ENCRYPTED, AND ITS PROSE SAID SO
      // UNTIL 2026-09-17 (#70).** Since 2026-09-11 a person GENERATES a set on
      // `/portal/mfa`, is shown it once, and each code is stored as a scrypt
      // HASH that nothing can show again (`common/backup_codes.ts`'s header,
      // `common/CLAUDE.md` 3y). The `At rest` row, read from `report()`, had
      // been right since 2026-09-12; `verifies`, `encrypts`, `decrypts`,
      // `hashes` and `whatItDoesNot` were rewritten to match it, and the
      // `Comparison` row now names the hash comparison a running service
      // makes as well as the string one a legacy set still gets.
      //
      // The table is read from `common/backup_codes.ts`, which is this page's
      // design everywhere: the facts live with the code that performs them.
      // ---------------------------------------------------------------------
      { name: 'Recovery codes',
        signs: 'Nothing. There is no MAC and no signature anywhere in this ' +
               'mechanism — a recovery code is a random string checked ' +
               'against a stored hash of one, which is the whole difference ' +
               'from the TOTP row above where the "code" is a truncated HMAC.',
        verifies: 'A presented code, against EVERY entry in the person\'s ' +
                  'set — each a scrypt hash checked with ' +
                  'crypto.verifySecret(), in parallel on the worker pool at ' +
                  'the sign-in screen — and all of them are checked even ' +
                  'after a match, so the time taken does not depend on WHICH ' +
                  'code matched. The shape is checked first, so a password ' +
                  'typed into the box is refused on its characters and costs ' +
                  'no hashing at all. An entry written before 2026-09-11 is ' +
                  'the code itself and is compared with ' +
                  'crypto.constantTimeEquals().',
        encrypts: '',
        decrypts: 'Only a set written before 2026-09-11 in PRODUCT mode, ' +
                  'which was sealed AES-256-GCM under the key-encryption key ' +
                  'and is opened through common/keystore.js to check a code. ' +
                  'Nothing written since is encrypted.',
        hashes: 'EVERY CODE, ONE SCRYPT HASH EACH, through ' +
                'crypto.hashSecret() — the same function and stored form as ' +
                'userPassword and stsActivationToken — at the one moment the ' +
                'codes exist in the clear: when the person confirms they ' +
                'have saved them. The hashes are not secret and are stored ' +
                'in the clear as one JSON array on the person\'s entry, with ' +
                'the counts beside it, so a console can say "7 of 10 unused" ' +
                'without walking the array.',
        whatItDoesNot: 'It never shows a stored code again — not to the ' +
                       'console, /admin-api or the person who owns it: a set ' +
                       'is shown ONCE, on the response that generated it, ' +
                       'and is not stored at all until its owner confirms ' +
                       'it. It never generates a set by itself: a person ' +
                       'generates one on /portal/mfa, and enrolling a second ' +
                       'factor only raises a prompt to do so. Confirming a ' +
                       'new set replaces the old one, and an operator\'s ' +
                       'Clear removes a set without issuing another. A set ' +
                       'written by an older build is not migrated. And there ' +
                       'is no counter-based or derived scheme here: these ' +
                       'are random strings and nothing about one code says ' +
                       'anything about the next.',
        envelopes: [],
        algorithms: function () {
          log.debug("Entering algorithms().");
          const report = backupCodes.report();
          log.debug("Leaving algorithms().");
          return [
            ['Generation', [report.source]],
            ['Entropy', [String(report.bitsPerCode) + ' bits per code, ' +
                         String(report.count) + ' codes of ' +
                         String(report.length) + ' characters out of an ' +
                         'alphabet of ' + String(report.alphabetSize)]],
            ['Alphabet', [report.alphabet + ' — the base32 characters, ' +
                          'chosen here because no pair of them is ' +
                          'confusable and NOT shared with the TOTP row ' +
                          'above']],
            ['Comparison', [report.comparisonOfAHash,
                            'A set written before 2026-09-11: ' +
                            report.comparison]],
            ['At rest', [report.atRest]]
          ];
        } },

      { name: 'Verifiable Credentials (OID4VCI / OID4VP)',
        signs: 'An SD-JWT VC as an RS256 JWS with `_sd_alg: sha-256`, and a ' +
               'W3C `ldp_vc` with a `bbs-2023` Data Integrity proof — ' +
               'BLS12-381-SHA-256, which is a pairing-based signature and ' +
               'the only one in this service. Its key is not a JWK and is ' +
               'published as `publicKeyMultibase` rather than being forced ' +
               'into one it does not fit.',
        verifies: 'A wallet\'s proof of possession at the credential ' +
                  'endpoint, which must be an ASYMMETRIC JWS — never a MAC ' +
                  'and never `none` — and a presentation at the verifier, ' +
                  'including a DERIVED bbs-2023 proof, which is what ' +
                  'selective disclosure looks like when it is not an SD-JWT.',
        encrypts: '',
        decrypts: '',
        hashes: 'SHA-256 for every SD-JWT disclosure digest, and inside the ' +
                'BBS ciphersuite for the message mapping.',
        whatItDoesNot: 'It verifies nothing in a credential\'s VALUES, which ' +
                       'are invented, and a verified presentation signs ' +
                       'somebody in only at /authn/wallet, only for a ' +
                       'holder-bound SD-JWT VC this realm issued — never ' +
                       'at the bar door, and never on a foreign issuer\'s ' +
                       'signature.',
        envelopes: ['jws', 'sdjwt', 'dataintegrity', 'did'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          log.debug("Leaving algorithms().");
          return [
            ['Credential signing', ['RS256', bbs2023.CRYPTOSUITE]],
            ['Wallet proof of possession', stsCrypto.JWS_ASYMMETRIC_ALGS],
            ['Disclosure digest', ['sha-256']]
          ];
        } },
      // ===== ACME family (acme/) =====
      // ACME (RFC 8555, 2026-09-13). The tables are read LAZILY from
      // acme/acme_jws.ts, which is the module that verifies with them, because
      // acme/ is required at 23e and this file at 20a.
      { name: 'ACME',
        signs: 'Every certificate it hands out, with this realm\'s ACME ' +
               'Issuing CA key, through common/pki.js\'s issueEnrolled(). ' +
               'Nothing else: an ACME response is plain JSON over TLS, and a ' +
               'Replay-Nonce carries an HMAC rather than a signature.',
        verifies: 'Every request\'s flattened JWS, with the account key ' +
                  'named by jwk or kid and only the algorithm the header ' +
                  'named (through common/crypto.js\'s verifyCompactJws); a ' +
                  'key-change\'s inner JWS with the new key; an External ' +
                  'Account Binding\'s HMAC with the key issued under its ' +
                  'kid, in constant time and in every mode; and the CSR\'s ' +
                  'proof of possession in common/cert_enrollment.ts.',
        encrypts: 'The External Account Binding HMAC key, sealed with ' +
                  'AES-256-GCM under the key-encryption key onto the entry ' +
                  'it was issued for, wherever that key outlives the process.',
        decrypts: 'That HMAC key, to verify a binding. Nothing on the wire.',
        keys: 'One ACME Issuing CA key per trust realm under the realm ' +
              'Intermediate; each account\'s public key (RSA of at least ' +
              '2048 bits, P-256/P-384/P-521 or Ed25519), kept as a public ' +
              'JWK and found by its RFC 7638 thumbprint; the client\'s own ' +
              'key for every certificate; and a per-run secret the ' +
              'Replay-Nonce MAC is derived under, shared with forked request ' +
              'workers and never written down.',
        hashes: 'SHA-256 for the account key thumbprint (RFC 7638), for the ' +
                'Replay-Nonce MAC and for each certificate\'s thumbprint on ' +
                'the entry record.',
        whatItDoesNot: 'No private key is ever seen: ACME is CSR-only. A ' +
                       'post-quantum account key is refused, because its key ' +
                       'type has no RFC 7638 thumbprint and an account is ' +
                       'found by its key. A KEM key cannot be certified, ' +
                       'because it cannot sign the proof of possession. The ' +
                       'JWS is the FLATTENED JSON serialization RFC 8555 ' +
                       'requires, which this service reads only here.',
        envelopes: ['jws', 'jwk', 'thumbprint', 'x509', 'tls'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          const acmeJws = loadAcmeJws();
          log.debug("Leaving algorithms().");
          return [
            ['Account key signatures', acmeJws.ACCOUNT_ALGS.slice()],
            ['External Account Binding MACs', acmeJws.EAB_ALGS.slice()],
            ['Revocation reasons accepted from a subscriber',
             Object.keys(acmeJws.REVOCATION_REASONS).map(function (code) {
               return code + ' ' + acmeJws.REVOCATION_REASONS[code];
             })],
            ['Certificate container', ['application/pem-certificate-chain']]
          ];
        } },
      // ===== EST family (est/) ===== EST (RFC 7030, 2026-09-13). The tables
      // are read LAZILY from the modules that use them — est/est_codec.ts for
      // what csrattrs advertises, the vendored key-material module for what
      // /serverkeygen generates — because est/ is required at 23f and this file
      // at 20a.
      { name: 'EST',
        signs: 'Every certificate it hands out, with this realm\'s EST ' +
               'Issuing CA key, through common/pki.js\'s issueEnrolled() — ' +
               'the same encoder every other certificate here comes from. ' +
               'The certs-only CMS messages it returns are DEGENERATE: a ' +
               'SignedData with certificates and no signer, so they carry no ' +
               'signature of their own and are trusted for the certificates ' +
               'inside them.',
        verifies: 'The PKCS#10 proof of possession — the request\'s ' +
                  'signature with its own public key, classical and ' +
                  'post-quantum, in common/cert_enrollment.ts — and, for ' +
                  'certificate authentication, the client certificate\'s ' +
                  'path to this realm\'s Intermediate and the service Root ' +
                  'with revocation consulted. A /serverkeygen template is ' +
                  'not verified: its key is replaced.',
        encrypts: 'The private key of a server-generated key pair, sealed ' +
                  'with AES-256-GCM under the key-encryption key onto the ' +
                  'entry, wherever that key outlives the process. It is NOT ' +
                  'encrypted to the client (RFC 7030 section 4.4.1.2): a ' +
                  'request asking for that is refused, and the key travels ' +
                  'inside TLS only.',
        decrypts: 'Nothing on the wire.',
        keys: 'One EST Issuing CA key per trust realm, under the realm ' +
              'Intermediate; the client\'s own key for everything it ' +
              'enrolls; and for /serverkeygen a key pair generated here in ' +
              'the template\'s algorithm (ML-KEM included, for ' +
              'key-encipherment), returned once.',
        hashes: 'SHA-256 for each certificate\'s thumbprint on the entry ' +
                'record.',
        whatItDoesNot: 'Full CMC, tls-unique channel binding (TLS 1.3 has ' +
                       'none) and an encrypted server-generated key. A KEM ' +
                       'key cannot be enrolled with /simpleenroll, because ' +
                       'it cannot sign the proof of possession.',
        envelopes: ['x509', 'tls'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          const codec = loadEstCodec();
          const keys = loadEstKeyMaterial();
          log.debug("Leaving algorithms().");
          return [
            ['CSR signature algorithms advertised by /csrattrs',
             codec.SIGNATURE_ALGORITHMS.map(function (one) {
               return one.name;
             })],
            ['Server-generated key algorithms', keys.keyAlgIds()],
            ['Private key container', ['PKCS#8 (RFC 5958), base64']],
            ['Certificate container', ['CMS SignedData, certs-only (RFC 5652)']]
          ];
        } },
      // ===== SCEP family (scep/) ===== SCEP (RFC 8894, 2026-09-13). Every
      // table is read LAZILY from scep/scep_cms.ts, which performs the
      // algorithms, because scep/ is required at 23g and this file at 20a.
      { name: 'SCEP',
        signs: 'Every certificate it issues, with this realm\'s SCEP Issuing ' +
               'CA key through common/pki.js\'s issueEnrolled(); and every ' +
               'CertRep, with the RA key — CMS SignedData over DER-sorted ' +
               'signed attributes, sha256WithRSAEncryption (SHA-384/512 when ' +
               'the request used them).',
        verifies: 'The requester\'s SignedData signature over its signed ' +
                  'attributes and the messageDigest of the content (SHA-256, ' +
                  'SHA-384, SHA-512; RSA or ECDSA signers are verified, and ' +
                  'an ECDSA one is then refused because no reply can be ' +
                  'encrypted to it); the PKCS#10 proof of possession; for ' +
                  'RenewalReq, GetCert and GetCRL the signer certificate\'s ' +
                  'path to this realm\'s Intermediate with revocation ' +
                  'consulted; and the challenge password, as a constant-time ' +
                  'SHA-256 comparison.',
        encrypts: 'A SUCCESS CertRep\'s certs-only content, to the ' +
                  'requester\'s signer certificate: RSAES-PKCS1-v1_5 key ' +
                  'transport and the AES-CBC key size the request used.',
        decrypts: 'The pkcsPKIEnvelope with the RA private key: ' +
                  'RSAES-PKCS1-v1_5 (through node-forge, because node ' +
                  'refuses PKCS#1 v1.5 private decryption) or RSAES-OAEP, ' +
                  'then AES-128/192/256-CBC. A failed unwrap is replaced by ' +
                  'random key bytes so a padding error and a wrong key are ' +
                  'one answer.',
        keys: 'One SCEP Issuing CA key per trust realm, and one RA key pair ' +
              'per realm — RSA of scep.raKeyAlgorithm, a leaf of that CA, ' +
              'kept in the realm\'s PKI row (sealed with the hierarchy in ' +
              'product mode) and re-issued within thirty days of expiry. The ' +
              'requester\'s key is never seen.',
        hashes: 'SHA-256 of a challenge secret, of a CSR and of a signer key ' +
                'for transaction idempotence; the message digest algorithms ' +
                'above.',
        whatItDoesNot: 'SHA-1 or MD5 signatures, DES or 3DES content ' +
                       'encryption (refused badAlg), a non-RSA requester ' +
                       'key, KeyAgreeRecipientInfo, GetNextCACert and ' +
                       'PENDING.',
        envelopes: ['cms', 'x509'],
        algorithms: function () {
          log.debug("Entering algorithms().");
          const table = loadScepCms().algorithms();
          log.debug("Leaving algorithms().");
          return [
            ['Request digests accepted', table.digests],
            ['Request signatures verified', table.signatures],
            ['Content ciphers accepted', table.ciphers],
            ['Key transports accepted', table.keyTransports],
            ['Refused digests', table.refusedDigests],
            ['Refused ciphers', table.refusedCiphers],
            ['CertRep signature', [table.replySignature]],
            ['CertRep key transport', [table.replyKeyTransport]]
          ];
        } },
    ];
  }

  setProtocolFamilies(protocols) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering CryptoMetadata.setProtocolFamilies().");
    if (!Array.isArray(protocols)) {
      log.error(errorCodes.tag('STS-ADMIN-0595') +
                'crypto metadata: setProtocolFamilies() was given ' +
                typeof protocols + ' rather than an array, and was ignored. ' +
                'The crypto page will say the drift check did not run.');
      log.debug("Leaving CryptoMetadata.setProtocolFamilies(). Refused.");
      return;
    }
    const named = protocols.filter(function (row) {
      return row && typeof row.name === 'string' && row.name;
    });
    if (named.length !== protocols.length) {
      log.error(errorCodes.tag('STS-ADMIN-0595') +
                'crypto metadata: setProtocolFamilies() was given ' +
                (protocols.length - named.length) + ' row(s) with no name, ' +
                'and was ignored whole. A partial list would produce a drift ' +
                'report that is wrong rather than absent.');
      log.debug("Leaving CryptoMetadata.setProtocolFamilies(). Refused.");
      return;
    }
    advertisedFamilies = named.map(function (row) { return row.name; });
    log.debug("Leaving CryptoMetadata.setProtocolFamilies(). " +
              advertisedFamilies.length + " advertised family/families.");
  }

  // Both directions of drift, the way `/admin/sts-metadata` reports both
  // directions of endpoint drift. `checked: false` means the slot was never
  // filled — which the page says out loud rather than rendering two empty lists
  // that look like a clean bill of health.
  driftReport() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.driftReport().");
    if (!advertisedFamilies) {
      log.debug("Leaving CryptoMetadata.driftReport(). The slot was never " +
                "filled.");
      return { checked: false, undescribed: [], stale: [], envelopes: [] };
    }
    const described = self.families.map(function (row) { return row.name; });
    const known = STANDARDS.map(function (row) { return row.key; });
    const report = {
      checked: true,
      // A family this mock advertises with no crypto profile here.
      undescribed: advertisedFamilies.filter(function (name) {
        return described.indexOf(name) < 0;
      }),
      // A profile here naming a family that is not advertised — what a rename
      // produces, and the direction that is otherwise invisible.
      stale: described.filter(function (name) {
        return advertisedFamilies.indexOf(name) < 0;
      }),
      // A family citing an envelope with no row in STANDARDS, which would
      // otherwise render as a dead cross-reference.
      envelopes: []
    };
    self.families.forEach(function (row) {
      (row.envelopes || []).forEach(function (key) {
        if (known.indexOf(key) < 0 && report.envelopes.indexOf(key) < 0) {
          report.envelopes.push(row.name + ' → ' + key);
        }
      });
    });
    log.debug("Leaving CryptoMetadata.driftReport(). " +
              report.undescribed.length + " undescribed, " +
              report.stale.length + " stale, " +
              report.envelopes.length + " unknown envelope(s).");
    return report;
  }

  // ---------------------------------------------------------------------------
  // THE KEY MATERIAL THIS PROCESS HOLDS, FOR THE AMBIENT REALM.
  //
  // A realm has its own signing key (`realms.keyed()` in helpers.js), so this
  // reads whichever realm the console is being viewed in — the same rule every
  // settings form on this console follows. The TLS certificate is NOT per realm
  // and the table says so, because a TLS handshake has no path to put a realm
  // segment in; the SPIFFE authority IS per realm since 2026-09-11, while its
  // trust domain and sockets are the service's (see the `spiffe` row below).
  //
  // **IT DOES NOT CALL `allSigningKeys()`, AND THAT IS THE ONE THING TO KNOW
  // BEFORE CHANGING THIS FUNCTION.** The post-quantum keys are made on FIRST
  // USE — one SLH-DSA keygen is most of two seconds — so a metadata page that
  // reached for them would spend that on every view, in a realm where nobody
  // had asked for a post-quantum signature. It reads `keys.pqKeys` instead,
  // which is present only once something has brought them into being, and
  // reports honestly which of the two states this realm is in.
  // ---------------------------------------------------------------------------
  // THE SHA-256 OF A CERTIFICATE THIS PAGE LINKS TO, or '' where the key has
  // none (2026-09-13). It is the handle a details dialog is opened by, and it
  // is public for the reason every fingerprint on this page is.
  private certificateFingerprint(pem) {
    const { log, certificateDetails } = this.deps;
    log.debug("Entering CryptoMetadata.certificateFingerprint().");
    if (!pem) {
      log.debug("Leaving CryptoMetadata.certificateFingerprint(). None.");
      return '';
    }
    try {
      log.debug("Leaving CryptoMetadata.certificateFingerprint().");
      return certificateDetails.fingerprintOf(pem);
    } catch (e) {
      log.debug("Caught in CryptoMetadata.certificateFingerprint(): " +
                ((e && e.message) || e));
      log.debug("Leaving CryptoMetadata.certificateFingerprint(). Unreadable.");
      return '';
    }
  }

  // The certificate this realm's JOSE Issuing CA issued over one slot, as a
  // fingerprint. The DEFAULT realm's scope is the empty string, which is what
  // `pki.js` addresses it by.
  private slotCertificateFingerprint(slot) {
    const { log, realms, pki } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.slotCertificateFingerprint().");
    let held = null;
    try {
      held = pki.publishedCertificateFor(
        realms.currentId() === realms.DEFAULT_ID ? '' : realms.currentId(),
        'jose', slot);
    } catch (e) {
      log.debug("Caught in CryptoMetadata.slotCertificateFingerprint(): " +
                ((e && e.message) || e));
      held = null;
    }
    log.debug("Leaving CryptoMetadata.slotCertificateFingerprint().");
    return held ? self.certificateFingerprint(held.certificatePem) : '';
  }

  // ---------------------------------------------------------------------------
  // WHAT THE LISTENER CERTIFICATE IS, IN ONE LINE, READ OFF THE CERTIFICATE
  // (2026-09-17, #70).
  //
  // The PKI / X.509 row printed `RSA 2048, SHA-256, self-signed` as a literal
  // for five days after `common/pki.js` began certifying this key under the
  // service Root — the same drift the signing row in `keyMaterial()` records.
  // So the key, the issuer and the chain are read from the PEM
  // `tls/tls_server.js` presents, by node's own parser: the key's type and
  // size from its public key, and "self-signed" only where the certificate
  // names itself as issuer AND its own key verifies it. The issuer is printed
  // as the certificate spells it rather than as "the service Root", because a
  // `tls.certificateFile` leaf has a chain too and it is not this service's.
  // The signature algorithm is left out: node's X509Certificate does not
  // report one on every version this runs on, and a guess would be the
  // literal again.
  // ---------------------------------------------------------------------------
  listenerCertificateSummary(cert: { certPem?: string; chainPem?: string[];
                                     notAfter?: string }): string {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering CryptoMetadata.listenerCertificateSummary().");
    const held = cert || {};
    const validTo = ', valid to ' + String(held.notAfter || '');
    let read: InstanceType<typeof nodeCrypto.X509Certificate> | null = null;
    try {
      read = new nodeCrypto.X509Certificate(String(held.certPem || ''));
    } catch (e) {
      log.debug("Caught in CryptoMetadata.listenerCertificateSummary(): " +
                ((e && e.message) || e));
      read = null;
    }
    if (!read) {
      log.debug("Leaving CryptoMetadata.listenerCertificateSummary(). " +
                "Unreadable.");
      return 'not readable by node' + validTo;
    }
    const details: { modulusLength?: number; namedCurve?: string } =
      read.publicKey.asymmetricKeyDetails || {};
    const type = String(read.publicKey.asymmetricKeyType || 'unknown key')
      .toUpperCase();
    const key = details.modulusLength
      ? type + ' ' + details.modulusLength
      : (details.namedCurve ? type + ' ' + details.namedCurve : type);
    let selfSigned = false;
    try {
      selfSigned = read.checkIssued(read) && read.verify(read.publicKey);
    } catch (e) {
      // A key type node's verify() does not take. Not self-signed as far as
      // this line can say, which prints the issuer — the more useful answer.
      log.debug("Caught in CryptoMetadata.listenerCertificateSummary(): " +
                ((e && e.message) || e));
      selfSigned = false;
    }
    const above = (held.chainPem || []).length;
    const issuer = selfSigned
      ? 'self-signed'
      : 'issued by ' + read.issuer.split('\n').join(', ') +
        (above ? ' (presented with ' + above + ' certificate' +
                 (above === 1 ? '' : 's') + ' above it)' : '');
    log.debug("Leaving CryptoMetadata.listenerCertificateSummary(). " +
              "selfSigned=" + selfSigned);
    return key + ', ' + issuer + validTo;
  }

  keyMaterial() {
    const { log, stsKeysFor, config, realms, pqJose, bbs2023, spiffeCa,
            tlsServer } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.keyMaterial().");
    const keys = stsKeysFor();
    const cert = tlsServer.serverCertificate();
    const spiffe = spiffeCa.state();
    const out = {
      realm: realms.currentId(),
      regeneratedEveryStart: true,
      signing: {
        kty: 'RSA', bits: 2048, alg: 'RS256', kid: String(keys.kid || ''),
        // What the key PUBLISHES, which stopped being a self-signed certificate
        // on 2026-09-11; this string said *self-signed, SHA-256, serial 02,
        // five years* until the certificate became openable from this page and
        // the dialog beside it said otherwise.
        certificate: (keys.certChainPem || []).length
          ? 'issued by this realm\'s JOSE Issuing CA under the service Root'
          : 'self-signed',
        certificateFingerprint: self.certificateFingerprint(keys.certPem),
        what: 'The realm\'s one RSA key. It signs every access token, every ' +
              'refresh token, the default ID Token, and every XML document ' +
              'this service mints.'
      },
      curveKeys: (keys.extraKeys || []).map(function (one) {
        return { alg: one.alg, kty: one.publicJwk.kty,
                 crv: one.publicJwk.crv || '', kid: one.publicJwk.kid,
                 certificateFingerprint: self.slotCertificateFingerprint(
                   one.publicJwk.crv ? one.alg + ':' + one.publicJwk.crv
                                     : one.alg) };
      }),
      postQuantum: {
        algorithms: pqJose.PQ_ALGS.slice(0),
        generated: Array.isArray(keys.pqKeys),
        keys: (keys.pqKeys || []).map(function (one) {
          return { alg: one.alg, kty: 'AKP', kid: one.publicJwk.kid,
                   certificateFingerprint:
                     self.slotCertificateFingerprint(one.alg) };
        }),
        what: 'Made on FIRST USE rather than at start — one SLH-DSA keygen ' +
              'is most of two seconds, which would be paid by every realm ' +
              'whether or not anybody asked for a post-quantum signature. ' +
              'The first JWKS fetch on a realm is what brings them into ' +
              'being.'
      },
      bbs: {
        cryptosuite: bbs2023.CRYPTOSUITE,
        curve: 'BLS12-381 G2, SHA-256 ciphersuite',
        what: 'Made on first use, like the post-quantum keys. It is ' +
              'published as `publicKeyMultibase` on the DID document rather ' +
              'than as a JWK, because a BLS key has no JWK representation to ' +
              'be forced into.'
      },
      tls: {
        subject: cert.subject,
        names: cert.names,
        fingerprint256: cert.fingerprint256,
        // Every certificate the listeners present, the ML-DSA ones included,
        // as the handle a details dialog opens by.
        certificates: (typeof tlsServer.serverCertificateChains === 'function'
          ? tlsServer.serverCertificateChains() : []).map(function (one) {
            return { algorithm: one.algorithm,
                     certificateFingerprint: self.certificateFingerprint(
                       one.certPem) };
          }),
        notAfter: cert.notAfter,
        perRealm: false,
        // This said *RSA 2048, SHA-256, self-signed, serial 03, two years*
        // until 2026-09-17 (#70), six days after the key was certified under
        // the service Root; the key and issuer are read off the certificate
        // now, as the PKI / X.509 family row reads them.
        what: self.listenerCertificateSummary(cert) + '. The key is ' +
              'generated at every start and certified by the TLS Issuing CA ' +
              'under the process Intermediate wherever a hierarchy exists — ' +
              'unless `tls.certificateFile` supplies the pair instead. ' +
              'Shared by LDAPS 636 and — when `global.https` is on — the ' +
              'main port and the debugger listener.'
      },
      spiffe: {
        enabled: spiffe.enabled,
        ready: spiffe.ready,
        // **PER REALM SINCE 2026-09-11, AND THE TRUST DOMAIN IS NOT.** The
        // authority that SIGNS an SVID is this realm's SPIFFE Issuing CA; the
        // trust domain name, the four sockets and the anchor are the service's.
        // Reporting `perRealm: false` as this row did would say the whole
        // family was shared, which is the half of it that stopped being true.
        perRealm: true,
        trustDomain: spiffe.trustDomain,
        // WHERE THE AUTHORITY CAME FROM — `pki` (this realm's SPIFFE Issuing CA
        // under the service Root) or `self-signed` (a realm with no branch).
        // The whole subject of this page is *what does this service actually
        // do when it signs*, and "signed by an authority nobody vouched for"
        // versus "by one that chains to the Root on /admin/pki" is exactly that
        // question for SVIDs.
        authoritySource: spiffe.authoritySource || '',
        // The SVID's OWN key algorithm, which is still `spiffe.x509KeyType`.
        svidKeyType: String(config.value('spiffe.x509KeyType')),
        // What the AUTHORITY holds, which is the Issuing CA's key and is chosen
        // on /admin/pki. These were one field while this module built its own
        // authority out of `spiffe.x509KeyType`; they are two keys now and a
        // single field would report one of them under the other's name.
        authorityKeyType: (spiffe.x509Authorities || [])[0]
          ? String((spiffe.x509Authorities || [])[0].keyType) : '',
        x509KeyType: String(config.value('spiffe.x509KeyType')),
        jwtKeyType: String(config.value('spiffe.jwtKeyType')),
        x509Authorities: (spiffe.x509Authorities || []).length,
        // The ACTIVE authority's certificate, as the handle a details dialog
        // opens by (2026-09-13).
        authorityFingerprint: self.certificateFingerprint(
          ((spiffe.x509Authorities || [])[0] || {}).certificatePem),
        trustAnchors: (spiffe.trustAnchors || []).length,
        jwtAuthorities: (spiffe.jwtAuthorities || []).length
      }
    };
    log.debug("Leaving CryptoMetadata.keyMaterial(). realm=" + out.realm +
              ", " + out.curveKeys.length +
              " curve key(s), post-quantum keys " +
              (out.postQuantum.generated ? "generated" : "not yet made") + ".");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE KERBEROS ENCRYPTION TYPES, READ BACK OUT OF THE CODEC RATHER THAN
  // COPIED.
  //
  // `kerberos/` is VENDORED — those eight modules are not editable here — so
  // the decode-only names cannot be exported and must not be transcribed. They
  // ARE reachable: `etypeName()` answers for anything either table knows and
  // returns `etype-N` for anything neither does, and `isSupportedEtype()` says
  // which of the two tables answered. So walking the assigned range and keeping
  // what is named is the codec's own list, obtained without editing it and
  // without a second copy to drift.
  //
  // The range is 1..26 because that is where every etype this codec has heard
  // of lives; a number outside it simply produces no row, which is the honest
  // answer for an etype nothing here can name.
  // ---------------------------------------------------------------------------
  kerberosEtypes() {
    const { log, krb5crypto } = this.deps;
    log.debug("Entering CryptoMetadata.kerberosEtypes().");
    const performed = [];
    const decodeOnly = [];
    for (let id = 1; id <= 26; id++) {
      const name = krb5crypto.etypeName(id);
      if (name === 'etype-' + id) {
        continue;
      }
      (krb5crypto.isSupportedEtype(id) ? performed : decodeOnly)
        .push({ id: id, name: name });
    }
    log.debug("Leaving CryptoMetadata.kerberosEtypes(). " + performed.length +
              " performed, " + decodeOnly.length + " decode-only.");
    return {
      performed: performed,
      decodeOnly: decodeOnly,
      preference: (krb5crypto.DEFAULT_ETYPE_PREFERENCE || []).slice(0)
    };
  }

  // ---------------------------------------------------------------------------
  // HASHING. Every digest this service computes, and what for.
  //
  // Three of the four lists below are DERIVED, and the fourth — `fixed` — is
  // the one that cannot be: "SHA-256, because RFC 7638 says the thumbprint is
  // SHA-256" is a fact about a specification rather than a row in a table, and
  // there is nowhere to read it from. Each of those rows therefore names the
  // mechanism it belongs to, so a reader can check it against the standard
  // rather than against this page.
  //
  // `weak` is separate and is not a scolding. SHA-1, MD5 and MD4 are all here
  // on purpose: SHA-1 because XMLDSIG's original 2000 recommendation is what a
  // great many deployed relying parties still send, MD5 and MD4 because
  // RC4-HMAC is what most of the installed base of Kerberos clients falls back
  // to. A mock that offered only the safe choice could not be used to show what
  // the unsafe one does — which is this service's whole argument, made once
  // here rather than four times below.
  // ---------------------------------------------------------------------------
  hashing() {
    const { log, stsCrypto, xmldsig, scimAuth } = this.deps;
    log.debug("Entering CryptoMetadata.hashing().");
    const jws = [];
    stsCrypto.JWS_SIGNING_ALGS.forEach(function (alg) {
      const spec = stsCrypto.JWS_ALGS[alg];
      if (spec.hash && jws.indexOf(spec.hash) < 0) {
        jws.push(spec.hash);
      }
    });
    const out = {
      // The digests a JWS in this service is built on. `null` for EdDSA
      // (Ed25519 hashes internally, which is what `crypto.sign(null, ...)`
      // means) and for the post-quantum ones, which is why the list is shorter
      // than the algorithm list.
      jws: jws,
      xmlDigestMethods: Object.keys(xmldsig.DIGEST_METHODS).map(function (uri) {
        return { uri: uri, label: xmldsig.DIGEST_METHODS[uri].label };
      }),
      scimDigest: (scimAuth.DIGEST_ALGORITHMS || []).map(function (row) {
        return { token: row.token, hash: row.hash };
      }),
      fixed: [
        { where: 'RFC 7638 JWK Thumbprint', hash: 'SHA-256',
          what: 'The canonical JWK, hashed. It is what `cnf.jkt` binds a ' +
                'DPoP-bound token to, and it is why the post-quantum ' +
                'algorithms cannot be used for DPoP — RFC 7638 defines the ' +
                'required members for RSA, EC, OKP and oct, and `AKP` is on ' +
                'none of those lists.' },
        { where: 'RFC 8705 `x5t#S256`', hash: 'SHA-256',
          what: 'Over the certificate\'s DER, base64url. The DER and not the ' +
                'PEM, which is the mistake that looks right in a log and ' +
                'matches nothing.' },
        { where: 'PKCE `S256`', hash: 'SHA-256',
          what: 'Over the code verifier. In RFC 9700 mode `plain` is ' +
                'withdrawn and this becomes the only method advertised.' },
        { where: 'OIDC `at_hash` / `c_hash`', hash: 'SHA-256, left half',
          what: 'Section 3.1.3.6: the left-most half of the digest of the ' +
                'ASCII token, base64url. The half is the part people leave ' +
                'out.' },
        { where: 'SD-JWT `_sd_alg`', hash: 'sha-256',
          what: 'Every disclosure digest in an SD-JWT VC.' },
        { where: 'WebAuthn client data hash', hash: 'SHA-256',
          what: 'The signature covers `authenticatorData || ' +
                'SHA-256(clientDataJSON)`, and the RP ID hash inside that ' +
                'authenticator data is SHA-256 of the origin\'s domain, ' +
                'compared byte for byte.' },
        { where: 'SPIFFE SVID identity', hash: 'SHA-256',
          what: 'Over the SVID\'s DER, wherever an issuance is recorded ' +
                'against a directory entry.' },
        { where: 'Key identifiers (`kid`)', hash: 'SHA-256, truncated',
          what: 'A `kid` names a KEY and is therefore DERIVED from the ' +
                'key\'s own public material. It was a constant once, so two ' +
                'instances of this mock published one name over two ' +
                'different keys — a verifier matches the kid exactly, tries ' +
                'that key, and reports a bad signature.' },
        { where: 'Kerberos string-to-key',
          hash: 'PBKDF2-HMAC-SHA1 / SHA-256 / SHA-384',
          what: 'RFC 3962 for the AES-SHA1 profiles and RFC 8009 for the ' +
                'AES-SHA2 ones. The iteration count and the salt come off ' +
                'the KDC\'s ETYPE-INFO2.' }
      ],
      weak: [
        { hash: 'SHA-1', where: 'XMLDSIG `#sha1` and `rsa-sha1`; ' +
                'RSA-OAEP-MGF1P; Kerberos etypes 17 and 18\'s HMAC-SHA1-96',
          why: 'The XMLDSIG spellings are the original 2000 recommendation ' +
               'and are what a great many deployed relying parties still ' +
               'send. `rsa-oaep-mgf1p` IS SHA-1 by definition — the URI ' +
               'means it — and the newer `rsa-oaep` carries its digest in a ' +
               'child element and is deliberately not offered, because a ' +
               'service provider that can do that can do GCM too. ' +
               'HMAC-SHA1-96 in RFC 3962 is a MAC rather than a ' +
               'collision-resistance claim and is what Active Directory uses ' +
               'to this day.' },
        { hash: 'MD5', where: 'Kerberos RC4-HMAC (etype 23); HTTP Digest',
          why: 'RC4-HMAC is what most of the installed base of Kerberos ' +
               'clients falls back to, and MD5 Digest is what most of the ' +
               'installed base of Digest clients speaks. Both are offered ' +
               'LAST and neither is a recommendation.' },
        { hash: 'MD4', where: 'The NT hash, inside RC4-HMAC\'s string-to-key',
          why: 'It is what the etype is. It is unsalted, which is why salt ' +
               'discovery matters only for AES.' }
      ]
    };
    log.debug("Leaving CryptoMetadata.hashing(). " + out.jws.length +
              " JWS digest(s), " + out.fixed.length + " fixed use(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // SIGNATURES AND MACS. Four tables, all read from the module that performs
  // the algorithm.
  //
  // The JWS rows carry `asymmetric` and `postQuantum` because several
  // specifications say "an asymmetric algorithm, never a MAC and never none" —
  // DPoP proofs (RFC 9449 section 4.2), OID4VCI proofs of possession and
  // request objects are all in that class — and because the post-quantum split
  // is what the section further down is built on. Both are computed from the
  // shared table rather than listed, so neither can fall behind it.
  // ---------------------------------------------------------------------------
  signatures() {
    const { log, stsCrypto, pqJose, bbs2023, webauthn, dpop, xmldsig,
            scimAuth } = this.deps;
    log.debug("Entering CryptoMetadata.signatures().");
    const composites = Object.keys(pqJose.COMPOSITES || {});
    const verifiedXml = stsCrypto.xmlSignatureAlgorithms().verified.map(
      function (row) {
        return row.uri;
      });
    const out = {
      jws: stsCrypto.JWS_SIGNING_ALGS.map(function (alg) {
        const spec = stsCrypto.JWS_ALGS[alg];
        return {
          alg: alg,
          family: spec.family,
          kty: spec.kty || 'oct',
          crv: spec.crv || '',
          hash: spec.hash || '',
          asymmetric: stsCrypto.JWS_ASYMMETRIC_ALGS.indexOf(alg) >= 0,
          postQuantum: spec.family === 'pq',
          composite: composites.indexOf(alg) >= 0,
          dpop: dpop.SIGNING_ALGS.indexOf(alg) >= 0
        };
      }),
      xml: Object.keys(xmldsig.SIG_METHODS).map(function (uri) {
        const spec = xmldsig.SIG_METHODS[uri];
        return { uri: uri, label: spec.label, family: spec.family,
                 hash: spec.hash, keyKind: spec.keyKind,
                 // WHETHER AN INBOUND SIGNATURE MADE WITH IT IS VERIFIED
                 // (common/crypto.js section 1a, #37 follow-up) — the table
                 // names families only a browser page can sign with.
                 verifiedHere: verifiedXml.indexOf(uri) >= 0,
                 // What this service will SIGN with, as opposed to verify. One
                 // row, and it is worth saying which: six signers used to type
                 // this URI out separately.
                 signsWith: uri ===
                   'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' };
      }),
      canonicalization: Object.keys(xmldsig.C14N_METHODS).map(function (uri) {
        const spec = xmldsig.C14N_METHODS[uri];
        return { uri: uri, label: spec.label, exclusive: spec.exclusive,
                 comments: spec.comments,
                 // Exclusive without comments is the default at every call site
                 // here and no caller overrides it — see the c14n row in
                 // STANDARDS for why that is load-bearing rather than a taste.
                 usedHere: spec.exclusive && !spec.comments };
      }),
      cose: Object.keys(webauthn.COSE_ALGS).map(function (id) {
        return { coseAlg: Number(id), jose: webauthn.COSE_ALGS[id] };
      }),
      other: [
        { name: bbs2023.CRYPTOSUITE,
          what: 'BLS12-381 G2 with the SHA-256 ciphersuite, as a W3C Data ' +
                'Integrity proof. The only pairing-based signature here, and ' +
                'the only selective disclosure that is not hashing.' },
        { name: 'HOBA algorithm ' + String(scimAuth.HOBA_ALG_RSA_SHA256) +
                ' (RSA-SHA256)',
          what: 'RFC 7486. Over a blob of nonce, algorithm, origin, realm, ' +
                'key id and the server\'s challenge, against a public key ' +
                'the client registered.' },
        { name: 'Kerberos keyed checksums',
          what: 'HMAC-SHA1-96 (etypes 17, 18), HMAC-SHA-256-128 (19), ' +
                'HMAC-SHA-384-192 (20) and HMAC-MD5 (23), each under a key ' +
                'derived from the long-term key for that message\'s KEY ' +
                'USAGE NUMBER. The usage numbers are the thing that goes ' +
                'wrong: the wrong one produces a checksum mismatch and no ' +
                'other symptom.' },
        { name: 'X.509 certificate signatures',
          what: 'SHA-256 with RSA for the signing and TLS certificates; ' +
                'whatever `spiffe.x509KeyType` implies for an SVID.' }
      ]
    };
    log.debug("Leaving CryptoMetadata.signatures(). " + out.jws.length +
              " JWS, " + out.xml.length + " XML, " + out.cose.length +
              " COSE.");
    return out;
  }

  // ---------------------------------------------------------------------------
  // ENCRYPTION AND KEY TRANSPORT.
  //
  // The XML half shows the CONFIGURED choice beside the offered list, because
  // both are runtime settings on `/admin/saml2` and a page that showed only
  // what is possible would not answer "what will the next assertion actually
  // use".
  // ---------------------------------------------------------------------------
  encryption() {
    const { log, config, stsCrypto } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.encryption().");
    const out = {
      jwe: {
        // The asymmetric half, on the row above's argument: what this service
        // may use when IT encrypts is decided by holding the recipient's public
        // key, and what it will open is the whole table.
        keyManagementOut: stsCrypto.JWE_ASYMMETRIC_ALGS.slice(0),
        keyManagementIn: stsCrypto.JWE_DECRYPT_ALGS.slice(0),
        contentEncryption: Object.keys(stsCrypto.JWE_ENCS).map(function (enc) {
          const spec = stsCrypto.JWE_ENCS[enc];
          return { enc: enc, bits: spec.bits, mode: spec.mode,
                   cekBytes: spec.cekBytes,
                   authenticated: true,
                   // Both modes authenticate; they differ in HOW, and the
                   // difference is where the bug was. A CBC-HMAC CEK carries a
                   // MAC key in FRONT of the AES key, which is why `cekBytes`
                   // is twice `bits/8` — splitting it the wrong way round is a
                   // ciphertext that decrypts to garbage with a valid tag.
                   note: spec.mode === 'gcm'
                     ? 'AEAD: one key, one tag.'
                     : 'The CEK is a MAC key followed by the AES key, and ' +
                       'the ' +
                       'tag is HMAC-' + String(spec.hash).toUpperCase() +
                       ' truncated to half its length.' };
        })
      },
      xml: {
        blockCiphers: Object.keys(stsCrypto.BLOCK_CIPHERS).map(function (name) {
          const spec = stsCrypto.BLOCK_CIPHERS[name];
          return { name: name, uri: spec.uri, keyBits: spec.keyBytes * 8,
                   mode: spec.mode, ivBytes: spec.ivBytes,
                   authenticated: spec.tagBytes > 0 };
        }),
        keyTransports: Object.keys(stsCrypto.KEY_TRANSPORTS).map(function (
          name) {
          const spec = stsCrypto.KEY_TRANSPORTS[name];
          return { name: name, uri: spec.uri, scheme: spec.scheme,
                   safe: spec.scheme === 'RSA-OAEP' };
        }),
        configured: {
          blockCipher: String(config.value('saml2.encryptionAlgorithm')),
          keyTransport: String(config.value('saml2.keyTransportAlgorithm')),
          encryptAssertion: !!config.value('saml2.encryptAssertion'),
          encryptLogoutNameId: !!config.value('saml2.encryptLogoutNameId')
        }
      },
      kerberos: self.kerberosEtypes(),
      tls: {
        // "UNNARROWED" and "TWO SOCKETS" were both corrected on 2026-09-17
        // (#70): `tls.minVersion` and `tls.ciphers` have narrowed 636 and the
        // main port since 2026-09-12, and `debugger/debugger_server.ts`
        // presents the same certificate when `global.https` is on.
        what: 'Node\'s OpenSSL defaults, except the protocol floor ' +
              '(`tls.minVersion`, TLS 1.2 by default) and the cipher list ' +
              '(`tls.ciphers`, node\'s when empty) on LDAPS 636 and the ' +
              'main port. This service chooses no curve — what else it ' +
              'configures is which sockets are TLS and which certificate ' +
              'they serve.',
        // THREE SOCKETS SINCE 2026-09-16, and it was five: the 8443 and 9443
        // listeners were deleted, so the certificate this service mints is
        // presented by the main port, LDAPS 636 and the debugger listener.
        sockets: ['main port (when global.https is on)', 'LDAPS 636',
                  'debugger listener (when global.https is on)']
      }
    };
    log.debug("Leaving CryptoMetadata.encryption(). " +
              out.xml.blockCiphers.length + " XML cipher(s), " +
              out.kerberos.performed.length +
              " Kerberos etype(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // POST-QUANTUM READINESS, SURFACE BY SURFACE.
  //
  // THE HEADLINE IS ONE SENTENCE AND IT IS NOT THE FLATTERING ONE: this
  // service's SIGNATURES are partly post-quantum and its KEY ESTABLISHMENT is
  // entirely classical. Those two halves are in very different positions and a
  // page that reported "we support ML-DSA" without separating them would be the
  // kind of claim this repository exists not to make.
  //
  // The reason they differ is the threat and not the effort. A signature is
  // verified at the moment it is presented, so a signature algorithm that falls
  // to a quantum computer in 2035 is a problem in 2035. A KEY AGREEMENT is not:
  // ciphertext captured today can be kept and opened when the machine arrives,
  // which is what "harvest now, decrypt later" names. So the surface that most
  // needs a post-quantum answer here is the one that has none — no ML-KEM key
  // establishment happens in this process, in JWE, in XML Encryption or in TLS.
  // (EST's `/serverkeygen` can GENERATE an ML-KEM key pair for a client since
  // 2026-09-13; that hands a key over, it agrees none.)
  //
  // THE THIRD CATEGORY IS THE ONE PEOPLE GET WRONG. Symmetric ciphers and
  // hashes are not broken by Shor's algorithm; Grover's costs a square root,
  // which is answered by doubling the key. AES-256 and SHA-384 are therefore in
  // a perfectly good position, AES-128 and SHA-256 are at a reduced margin that
  // NIST still considers adequate, and RC4, MD5 and MD4 are broken for reasons
  // that have nothing to do with quantum computers at all. So Kerberos here —
  // the one family with no public-key cryptography in it — is the family least
  // affected, which is exactly the opposite of what its reputation suggests.
  //
  // `state` is one of:
  //   `pq`         a post-quantum algorithm can be selected on this surface
  //                today
  //   `classical`  it cannot, and the algorithm is one Shor's algorithm breaks
  //   `symmetric`  no public-key cryptography is involved; Grover applies and
  //                the margin is what the key length says
  // ---------------------------------------------------------------------------
  postQuantum() {
    const { log, stsCrypto, pqJose } = this.deps;
    log.debug("Entering CryptoMetadata.postQuantum().");
    const composites = Object.keys(pqJose.COMPOSITES || {});
    const pure = pqJose.PQ_ALGS.filter(function (alg) {
      return composites.indexOf(alg) < 0;
    });
    const out = {
      algorithms: {
        mlDsa: pure.filter(function (a) { return a.indexOf('ML-DSA') === 0; }),
        slhDsa: pure.filter(function (a) {
          return a.indexOf('SLH-DSA') === 0;
        }),
        composite: composites.map(function (alg) {
          const spec = pqJose.COMPOSITES[alg];
          return { alg: alg, mlDsa: spec.ml, traditional: spec.trad,
                   prehash: spec.ph, domainSeparator: spec.label };
        }),
        keyType: 'AKP (RFC 9964)',
        what: 'ML-DSA is FIPS 204 and SLH-DSA is FIPS 205 — a lattice ' +
              'signature and a hash-based one, which are different bets and ' +
              'are both here for that reason. The six COMPOSITES are ' +
              'draft-ietf-jose-pq-composite-sigs: one ML-DSA signature and ' +
              'one traditional signature over the same message, both of ' +
              'which must verify, so the pair is no weaker than its stronger ' +
              'half. Each carries a DOMAIN SEPARATOR into both the composite ' +
              'message and the ML-DSA context string, which is what stops a ' +
              'signature made for one composite being replayed as another.',
        independence: 'The lattice PRIMITIVE is @noble/post-quantum, shared ' +
                      'with the debugger because there is no second ' +
                      'implementation of ML-DSA to be had — node has none. ' +
                      'EVERYTHING AROUND IT is written here from the ' +
                      'specifications, and the traditional half of every ' +
                      'composite runs on node\'s OpenSSL rather than on the ' +
                      'curve library the far end uses. That is where the ' +
                      'cross-check has any value: a shared misunderstanding ' +
                      'about the framing would agree with itself perfectly ' +
                      'and interoperate with nothing.'
      },
      signatures: [
        { surface: 'ID Token', state: 'pq',
          how: 'A client registers `id_token_signed_response_alg`, and the ' +
               'advertised list IS the shared JWS table — so every ML-DSA, ' +
               'SLH-DSA and composite algorithm is selectable.' },
        { surface: 'Signed UserInfo response', state: 'pq',
          how: 'The post-quantum entries are taken from the shared table by ' +
               'a filter rather than listed, so this list cannot fall behind ' +
               'it.' },
        { surface: 'JWKS publication', state: 'pq',
          how: 'Every post-quantum key is published as an `AKP` JWK with a ' +
               '`kid` of its own, so a client can actually VERIFY one rather ' +
               'than merely be offered it. They are made on FIRST USE, which ' +
               'is what makes the first JWKS fetch on a realm slow.' },
        { surface: 'Access tokens and refresh tokens', state: 'classical',
          how: 'RS256, always. `signJwt()` is the one path that records a ' +
               'token in the console\'s counters and it signs with the ' +
               'realm\'s RSA key.' },
        { surface: 'DPoP proofs', state: 'classical',
          how: 'DELIBERATELY, and it is the most interesting exclusion here. ' +
               'A DPoP proof is bound through `cnf.jkt`, the RFC 7638 JWK ' +
               'Thumbprint — and RFC 7638 defines the required members for ' +
               'RSA, EC, OKP and oct only. An ML-DSA key is `kty: "AKP"`, ' +
               'for which no thumbprint is registered, so a proof signed ' +
               'with one would verify perfectly and bind to NOTHING. The gap ' +
               'is in the binding, not in the signature.' },
        { surface: 'Every XML signature — SAML 2.0, SAML 1.1, WS-Federation, ' +
                   'WS-Trust, federation', state: 'classical',
          how: 'RSA-SHA256. XMLDSIG has no registered post-quantum ' +
               'SignatureMethod, so there is nothing to select: this is a ' +
               'gap in the specification stack rather than in this service.' },
        { surface: 'X.509 certificates and SPIFFE SVIDs', state: 'classical',
          how: 'RSA 2048 or an elliptic curve. The SPIFFE authority key ' +
               'types are EC P-256/384/521, RSA 2048/4096 and Ed25519 — all ' +
               'broken by Shor.' },
        { surface: 'Verifiable credentials', state: 'classical',
          how: 'RS256 for an SD-JWT VC, and `bbs-2023` for an `ldp_vc` — a ' +
               'pairing-based signature, which is if anything MORE exposed ' +
               'than plain ECDSA.' },
        { surface: 'WebAuthn assertions', state: 'classical',
          how: 'ES256, RS256 or EdDSA, and it is not this service\'s choice: ' +
               'the AUTHENTICATOR signs, and COSE registers no post-quantum ' +
               'algorithm that a platform authenticator produces.' }
      ],
      keyEstablishment: {
        state: 'classical',
        mechanisms: stsCrypto.JWE_ALGS
          .concat(Object.keys(stsCrypto.KEY_TRANSPORTS).map(function (name) {
            return stsCrypto.KEY_TRANSPORTS[name].scheme + ' (XML ' + name +
              ')';
          }))
          .concat(['TLS key exchange — node\'s OpenSSL defaults']),
        what: 'EVERY ONE OF THEM IS BROKEN BY SHOR\'S ALGORITHM, and there ' +
              'is no ML-KEM anywhere in this process — not in JWE, not in ' +
              'XML Encryption, not on any of the five TLS sockets. THIS IS ' +
              'THE HALF THAT MATTERS SOONEST: a signature is checked when it ' +
              'is presented, so a signature algorithm that falls in 2035 is ' +
              'a problem in 2035, while ciphertext captured today can be ' +
              'kept and opened when the machine arrives. Nothing this ' +
              'service encrypts is a real secret, which is why this is a ' +
              'fidelity gap here and would be a serious one anywhere else.',
        whatWouldClose: 'draft-ietf-jose-pq-kem would add `ML-KEM` as a JWE ' +
                        '`alg`, and a hybrid TLS group (X25519MLKEM768) ' +
                        'needs only an OpenSSL that offers it. Neither is ' +
                        'here, and this row says so rather than leaving the ' +
                        'post-quantum signatures above to imply otherwise.'
      },
      symmetric: {
        state: 'symmetric',
        what: 'Grover\'s algorithm costs a square root rather than breaking ' +
              'these outright, so the answer is key length. AES-256 and ' +
              'SHA-384 are unaffected in any practical sense; AES-128 and ' +
              'SHA-256 keep a reduced margin that is still considered ' +
              'adequate. KERBEROS IS THEREFORE THE FAMILY HERE LEAST ' +
              'AFFECTED BY ANY OF THIS — it is the only one with no ' +
              'public-key cryptography in it at all — which is the opposite ' +
              'of what its reputation suggests. What is wrong with RC4-HMAC, ' +
              'MD5 and MD4 has nothing to do with quantum computers.',
        strongest: 'aes256-cts-hmac-sha384-192 (etype 20), AES-256-GCM for ' +
                   'XML Encryption, A256GCM for JWE.'
      }
    };
    log.debug("Leaving CryptoMetadata.postQuantum(). " +
              out.algorithms.mlDsa.length + " ML-DSA, " +
              out.algorithms.slhDsa.length + " SLH-DSA, " +
              out.algorithms.composite.length + " composite.");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE WHOLE REPORT, ONCE. Both the page and `GET /admin-api/crypto` are built
  // from this — the API mirrors the console rather than computing its own
  // answer, which is rule 7 and is why the parity check is a property of the
  // code rather than a promise in a comment.
  // ---------------------------------------------------------------------------
  cryptoJson(base) {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.cryptoJson().");
    const report = {
      issuer: base,
      realm: realms.currentId(),
      generatedAt: new Date().toISOString(),
      oneModule: 'common/crypto.js is the one place this service signs, ' +
                 'verifies, encrypts and decrypts. Before 2026-08-27 it did ' +
                 'all four in about twenty places, including six XML signers ' +
                 'and four XML signature verifiers.',
      drift: self.driftReport(),
      keys: self.keyMaterial(),
      families: self.families.map(function (row) {
        return {
          name: row.name,
          signs: row.signs, verifies: row.verifies,
          encrypts: row.encrypts, decrypts: row.decrypts,
          hashes: row.hashes,
          whatItDoesNot: row.whatItDoesNot,
          envelopes: row.envelopes.slice(0),
          algorithms: row.algorithms().map(function (pair) {
            return { what: pair[0], values: pair[1] };
          })
        };
      }),
      hashing: self.hashing(),
      signatures: self.signatures(),
      encryption: self.encryption(),
      postQuantum: self.postQuantum(),
      standards: STANDARDS.map(function (row) {
        return { key: row.key, name: row.name, specs: row.specs.slice(0),
                 coverage: row.coverage, what: row.what };
      })
    };
    log.debug("Leaving CryptoMetadata.cryptoJson(). " + report.families.length +
              " family/families, " + report.standards.length + " standard(s).");
    return report;
  }

  // --- rendering
  // --------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // PROSE FOR THE PAGE. The tables above are written with `backticks` around
  // identifiers, because the SAME strings are served as JSON at `?format=json`
  // and on `/admin-api/crypto`, where the convention every description in this
  // service follows is markdown — `mgmt-api/admin_api.ts`'s operation
  // descriptions are full of them.
  //
  // So the conversion belongs HERE, in the renderer, and nowhere else: the JSON
  // keeps its backticks and the page gets `<code>`. ESCAPING HAPPENS FIRST and
  // the substitution second, which is the order that matters — the content
  // between a pair of backticks has already been through `esc()` by the time
  // this looks at it, so nothing inside one can close the element it is about
  // to be put in.
  // ---------------------------------------------------------------------------
  private prose(text) {
    const { log, esc } = this.deps;
    log.debug("Entering CryptoMetadata.prose().");
    log.debug("Leaving CryptoMetadata.prose().");
    return esc(String(text == null ? '' : text))
      .replace(/`([^`]+)`/g, '<code>$1</code>');
  }

  // A list of algorithm names as code chips. Empty renders as an em dash rather
  // than as nothing, because an empty cell and a cell this function has not
  // reached look identical and only one of them is a fact.
  private chips(values) {
    const { log, esc } = this.deps;
    log.debug("Entering CryptoMetadata.chips().");
    if (!values || !values.length) {
      log.debug("Leaving CryptoMetadata.chips().");
      return '<span class="why">—</span>';
    }
    log.debug("Leaving CryptoMetadata.chips().");
    return values.map(function (one) {
      return '<code>' + esc(String(one)) + '</code>';
    }).join(' ');
  }

  // One verb's cell in the family table. An empty string means this service
  // does not do it in that family, which is a claim and is drawn as one.
  private verbCell(text) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.verbCell().");
    if (!text) {
      log.debug("Leaving CryptoMetadata.verbCell().");
      return '<span class="why">does not</span>';
    }
    log.debug("Leaving CryptoMetadata.verbCell().");
    return self.prose(text);
  }

  private anchorFor(name) {
    const { log } = this.deps;
    log.debug("Entering CryptoMetadata.anchorFor().");
    log.debug("Leaving CryptoMetadata.anchorFor().");
    return 'fam-' + String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  private renderFamilies(report) {
    const { log, esc, admin } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderFamilies().");
    let html = '<h2 id="families">The identity services this mock ' +
      'advertises</h2><p class="lead">One row per protocol family on <a ' +
      'href="/admin/sts-metadata">Service metadata</a>, with what each does ' +
      'with cryptography. The four verbs are kept apart on purpose: signing ' +
      'is minting something a relying party will believe, verifying is a ' +
      'decision that can be got wrong, encrypting uses somebody else\'s key, ' +
      'and decrypting means holding a private key a caller can aim ' +
      'ciphertext at. Those are four different exposures and this service ' +
      'does a different amount of each.</p>';

    const drift = report.drift;
    if (!drift.checked) {
      html += admin.warn('<strong>The family list was not checked against ' +
                         'the ' +
        'service metadata.</strong> This page names the identity services it ' +
        'reports on, and <code>/admin/sts-metadata</code> names the ones ' +
        'this process advertises; normally that module hands its list over ' +
        'at require time and both directions of drift are reported here. It ' +
        'did not, so the table below is this file\'s own word for what the ' +
        'service offers.');
    } else if (drift.undescribed.length || drift.stale.length ||
               drift.envelopes.length) {
      html += admin.warn('<strong>This page and the service metadata ' +
                         'disagree.' +
        '</strong> ' +
        (drift.undescribed.length
          ? 'Advertised with no crypto profile here: ' +
            self.chips(drift.undescribed) + '. '
          : '') +
        (drift.stale.length
          ? 'Profiled here and not advertised — which is what a rename ' +
            'produces: ' + self.chips(drift.stale) + '. '
          : '') +
        (drift.envelopes.length
          ? 'Citing an envelope with no row in the standards table: ' +
            self.chips(drift.envelopes) + '. '
          : '') +
        'Both directions are reported rather than reconciled, for the reason ' +
        '<code>/admin/sts-metadata</code> reports both directions of ' +
        'endpoint drift: the one that is silent is the one that costs an ' +
        'afternoon.');
    } else {
      html += '<p class="why">Checked against the service metadata: all ' +
        esc(report.families.length) + ' advertised families have a profile ' +
        'here, none is profiled that is not advertised, and every envelope ' +
        'cited has a row below.</p>';
    }

    html += '<table><thead><tr><th class="n">Identity service</th>' +
      '<th>Signs</th><th>Verifies</th><th>Encrypts</th><th>Decrypts</th>' +
      '</tr></thead><tbody>' +
      report.families.map(function (row) {
        return '<tr><td class="n"><a href="#' + esc(self.anchorFor(row.name)) +
          '">' + esc(row.name) + '</a></td>' +
          '<td>' + self.verbCell(row.signs) + '</td>' +
          '<td>' + self.verbCell(row.verifies) + '</td>' +
          '<td>' + self.verbCell(row.encrypts) + '</td>' +
          '<td>' + self.verbCell(row.decrypts) + '</td></tr>';
      }).join('') + '</tbody></table>';

    report.families.forEach(function (row) {
      html += '<h3 id="' + esc(self.anchorFor(row.name)) + '">' +
        esc(row.name) + '</h3>' +
        '<table><tbody>' +
        '<tr><th class="n">Hashing</th><td>' + self.prose(row.hashes) +
        '</td></tr>' +
        row.algorithms.map(function (group) {
          return '<tr><th class="n">' + esc(group.what) + '</th><td>' +
            self.chips(group.values) + '</td></tr>';
        }).join('') +
        '<tr><th class="n">Envelopes</th><td>' +
        row.envelopes.map(function (key) {
          const std = STANDARDS.filter(function (s) {
            return s.key === key;
          })[0];
          return std ? '<a href="#std-' + esc(key) + '">' + esc(std.name) +
                       '</a>' : '<code>' + esc(key) + '</code>';
        }).join(', ') + '</td></tr>' +
        '</tbody></table>' +
        admin.note('<strong>What it deliberately does not do.</strong> ' +
                   self.prose(row.whatItDoesNot));
    });
    log.debug("Leaving CryptoMetadata.renderFamilies().");
    return html;
  }

  // A "View details" link on a key row, opening the certificate dialog over
  // this page and closing back to this section. Nothing where the key holds no
  // certificate — a BBS key, a post-quantum key not made yet.
  private certificateLink(fingerprint, text?) {
    const { log, certificateDialog } = this.deps;
    log.debug("Entering CryptoMetadata.certificateLink().");
    const html = certificateDialog.link('/admin/crypto-metadata', fingerprint,
                                        'keys', text);
    log.debug("Leaving CryptoMetadata.certificateLink().");
    return html ? '<br>' + html : '';
  }

  private renderKeys(report) {
    const { log, esc, admin } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderKeys().");
    const keys = report.keys;
    let html = '<h2 id="keys">The key material this process holds</h2><p ' +
      'class="lead">Every key here is generated at start and none of them is ' +
      'persisted, in any persistence mode. That is deliberate and two things ' +
      'depend on it: the <code>kid</code> is derived from the key material, ' +
      'so two instances of this mock cannot publish one name over two ' +
      'different keys, and every document that carries or describes a key is ' +
      'served <code>Cache-Control: no-store</code>. <strong>The signing keys ' +
      'are per trust realm; the TLS certificate and the SPIFFE authorities ' +
      'are not.</strong> This shows realm <code>' + esc(keys.realm) +
      '</code>.</p>';

    html += '<table><thead><tr><th class="n">Key</th><th>Type</th>' +
      '<th>Identifier</th><th>Scope</th></tr></thead><tbody>' +
      '<tr><td class="n">Signing key</td><td><code>RSA 2048</code> ' +
      '<code>RS256</code></td><td><code>' + esc(keys.signing.kid) +
      '</code>' + self.certificateLink(keys.signing.certificateFingerprint) +
      '</td><td>this realm</td></tr>' +
      keys.curveKeys.map(function (one) {
        return '<tr><td class="n">Curve key</td><td><code>' + esc(one.alg) +
          '</code> <code>' + esc(one.kty) +
          (one.crv ? '</code> <code>' + esc(one.crv) : '') +
          '</code></td><td><code>' + esc(one.kid) +
          '</code>' + self.certificateLink(one.certificateFingerprint) +
          '</td><td>this realm</td></tr>';
      }).join('') +
      (keys.postQuantum.generated
        ? keys.postQuantum.keys.map(function (one) {
            return '<tr><td class="n">Post-quantum key</td><td><code>' +
              esc(one.alg) + '</code> <code>AKP</code></td><td><code>' +
              esc(one.kid) + '</code>' +
              self.certificateLink(one.certificateFingerprint) +
              '</td><td>this realm</td></tr>';
          }).join('')
        : '<tr><td class="n">Post-quantum keys</td><td><code>AKP</code>, ' +
          esc(keys.postQuantum.algorithms.length) +
          ' algorithms</td><td><span class="why">not made yet in this realm' +
          '</span></td><td>this realm</td></tr>') +
      '<tr><td class="n">BBS key</td><td><code>' +
      esc(keys.bbs.cryptosuite) + '</code> ' + esc(keys.bbs.curve) +
      '</td><td><span class="why">published as publicKeyMultibase</span></td>' +
      '<td>this realm</td></tr>' +
      '<tr><td class="n">TLS certificate</td><td><code>RSA 2048</code> ' +
      '<code>SHA-256</code></td><td><code>' + esc(keys.tls.fingerprint256) +
      '</code>' + (keys.tls.certificates || []).map(function (one) {
        return self.certificateLink(one.certificateFingerprint,
                               'View details (' + one.algorithm + ')');
      }).join('') + '</td><td>the process</td></tr>' +
      '<tr><td class="n">SPIFFE X.509 authority</td><td><code>' +
      esc(keys.spiffe.authorityKeyType || keys.spiffe.x509KeyType) +
      '</code></td><td>' +
      (keys.spiffe.ready
        ? esc(keys.spiffe.x509Authorities) + ' authority/ies, ' +
          (keys.spiffe.authoritySource === 'pki'
            ? 'this realm\'s <a href="/admin/pki">SPIFFE Issuing CA</a>'
            : '<span class="why">self-signed &mdash; this realm has no ' +
              'certificate authority</span>') +
          self.certificateLink(keys.spiffe.authorityFingerprint)
        : '<span class="why">not started</span>') +
      '</td><td>this realm</td></tr>' +
      '<tr><td class="n">SPIFFE X509-SVID key</td><td><code>' +
      esc(keys.spiffe.svidKeyType) + '</code></td><td><span class="why">the ' +
      'key in each SVID, generated per mint &mdash; not the authority\'s' +
      '</span></td><td>this realm</td></tr>' +
      '<tr><td class="n">SPIFFE JWT authority</td><td><code>' +
      esc(keys.spiffe.jwtKeyType) + '</code></td><td>' +
      (keys.spiffe.ready ? esc(keys.spiffe.jwtAuthorities) + ' authority/ies'
                         : '<span class="why">not started</span>') +
      '</td><td>the process</td></tr>' +
      '</tbody></table>';

    html += admin.note('<strong>The post-quantum and BBS keys are made on ' +
      'first use, not at start.</strong> ' + self.prose(keys.postQuantum.what) +
      ' The consequence a reader meets is that the first JWKS fetch on a ' +
      'realm is slow — about two seconds, nearly all of it one SLH-DSA ' +
      'keygen — and every one after it is not.');
    html += admin.note('<strong>Nothing on this page is a secret.</strong> ' +
                       'Key ' +
      'types, key identifiers, curve names, certificate fingerprints and ' +
      'validity dates are all readable already from <code>/oauth2/jwks</code>' +
      ', <code>/tls/server-certificate</code> and the SPIFFE bundle ' +
      'endpoint. That is a rule for anything added here later rather than an ' +
      'observation about what is here now: a page about cryptography is ' +
      'exactly the page somebody would think to put a private key on.');
    log.debug("Leaving CryptoMetadata.renderKeys().");
    return html;
  }

  private renderHashing(report) {
    const { log, esc, admin } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderHashing().");
    const h = report.hashing;
    let html = '<h2 id="hashing">Hashing</h2>' +
      '<p class="lead">Every digest this service computes. The first three ' +
      'tables are read from the modules that compute them; the fourth cannot ' +
      'be, because "SHA-256, because RFC 7638 says so" is a fact about a ' +
      'specification and not a row in a table — so each of those names the ' +
      'mechanism it belongs to.</p>';

    html += '<table><tbody>' +
      '<tr><th class="n">Digests behind the JWS algorithms</th><td>' +
      self.chips(h.jws) + ' <span class="why">EdDSA and the post-quantum ' +
      'algorithms name none — Ed25519 hashes internally and ML-DSA takes the ' +
      'message</span></td></tr>' +
      '<tr><th class="n">HTTP Digest (SCIM)</th><td>' +
      self.chips(h.scimDigest.map(function (r) { return r.token; })) +
      ' <span class="why">strongest first, and each checked against the ' +
      'openssl this process actually has</span></td></tr>' +
      '</tbody></table>';

    html += '<h3>XML DigestMethod</h3><table><thead><tr><th class="n">' +
            'URI</th>' +
      '<th>Label</th></tr></thead><tbody>' +
      h.xmlDigestMethods.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>Fixed uses</h3><table><thead><tr><th class="n">Where</th>' +
      '<th>Digest</th><th>What</th></tr></thead><tbody>' +
      h.fixed.map(function (row) {
        return '<tr><td class="n">' + self.prose(row.where) +
          '</td><td><code>' + esc(row.hash) + '</code></td><td>' +
          self.prose(row.what) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>The weak ones, and why they are here</h3>' +
      admin.note('<strong>None of these is an oversight and none is a ' +
        'recommendation.</strong> This service exists to exercise other ' +
        'people\'s clients, and a mock that offered only the safe choice ' +
        'could not be used to show what the unsafe one does. Each row says ' +
        'which ' +
        'installed base asks for it.') +
      '<table><thead><tr><th class="n">Digest</th><th>Where</th><th>Why</th>' +
      '</tr></thead><tbody>' +
      h.weak.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.hash) + '</code></td><td>' +
          self.prose(row.where) + '</td><td>' + self.prose(row.why) +
          '</td></tr>';
      }).join('') + '</tbody></table>';
    log.debug("Leaving CryptoMetadata.renderHashing().");
    return html;
  }

  private renderSignatures(report) {
    const { log, esc, admin } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderSignatures().");
    const s = report.signatures;
    let html = '<h2 id="signatures">Signatures and MACs</h2>' +
      '<p class="lead">Read from the module that performs each one. The JWS ' +
      'table is <em>the</em> table for this service — there were two once, ' +
      'which is how DPoP came to accept a different set of algorithms from ' +
      'everything else for no reason anybody chose.</p>';

    html += '<h3>JWS</h3><table><thead><tr><th class="n">alg</th><th>' +
      'Family</th><th>Key</th><th>Digest</th><th>Asymmetric</th><th>DPoP</th>' +
      '</tr></thead><tbody>' +
      s.jws.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.alg) + '</code></td>' +
          '<td>' + esc(row.family) +
          (row.composite ? ' <span class="why">composite</span>' : '') +
          '</td>' +
          '<td><code>' + esc(row.kty) + '</code>' +
          (row.crv ? ' <code>' + esc(row.crv) + '</code>' : '') + '</td>' +
          '<td>' + (row.hash ? '<code>' + esc(row.hash) + '</code>'
                             : '<span class="why">none</span>') + '</td>' +
          '<td>' + (row.asymmetric ? 'yes' : 'no — a MAC') + '</td>' +
          '<td>' + (row.dpop ? 'yes' : 'no') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      admin.note('<strong>The DPoP column is a filter over this table and ' +
                 'not ' +
        'a table of its own.</strong> It excludes the HMAC family because ' +
        'RFC 9449 section 4.2 requires an asymmetric algorithm, and it ' +
        'excludes every post-quantum one because a DPoP proof is bound ' +
        'through the RFC 7638 thumbprint — which is defined for RSA, EC, OKP ' +
        'and oct and not for <code>AKP</code>. A proof signed with ML-DSA ' +
        'would verify perfectly and bind to nothing, which is worse than a ' +
        'refusal.');

    html += '<h3>XML SignatureMethod</h3>' +
      '<p class="lead">This service <strong>signs</strong> with one of these ' +
      'and <strong>verifies</strong> any of them — the asymmetry is the ' +
      'point of the vendored implementation, which is the other end of most ' +
      'of these exchanges.</p><table><thead><tr><th class="n">URI</th><th>' +
      'Label</th><th>Key</th><th>Signs with</th></tr></thead><tbody>' +
      s.xml.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td><td><code>' + esc(row.keyKind) +
          '</code></td><td>' + (row.signsWith ? 'yes' : '<span class="why">' +
          'verify only</span>') + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>Canonicalization</h3>' +
      '<table><thead><tr><th class="n">URI</th><th>Label</th>' +
      '<th>Used here</th></tr></thead><tbody>' +
      s.canonicalization.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td><td>' + (row.usedHere
            ? 'yes — the default at every call site'
            : '<span class="why">read only</span>') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      admin.note('<strong>Exclusive canonicalization is load-bearing here ' +
                 'and ' +
        'not a matter of taste.</strong> An assertion is signed as a ' +
        'standalone document and then embedded inside an RSTR, a Response or ' +
        'a <code>wresult</code> that declares prefixes of its own. Inclusive ' +
        'c14n would pull those ancestor declarations into the digest at ' +
        'verification time, so the signature would fail for every relying ' +
        'party while verifying perfectly here — the worst shape of bug to ' +
        'chase. C14N 1.1 is not offered at all: its whole difference is how ' +
        '<code>xml:base</code>, <code>xml:lang</code> and <code>' +
        'xml:space</code> inherit into a detached subtree, this engine does ' +
        'not implement that inheritance, and an option naming a method it ' +
        'does not perform is worse than an absent one.');

    html += '<h3>COSE (WebAuthn)</h3><table><thead><tr>' +
      '<th class="n">COSE alg</th><th>JOSE name</th></tr></thead><tbody>' +
      s.cose.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.coseAlg) +
          '</code></td><td><code>' + esc(row.jose) + '</code></td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>Everything else</h3><table><thead><tr><th class="n">' +
            'What</th>' +
      '<th>Detail</th></tr></thead><tbody>' +
      s.other.map(function (row) {
        return '<tr><td class="n">' + esc(row.name) + '</td><td>' +
          self.prose(row.what) + '</td></tr>';
      }).join('') + '</tbody></table>';
    log.debug("Leaving CryptoMetadata.renderSignatures().");
    return html;
  }

  private renderEncryption(report) {
    const { log, esc, admin } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderEncryption().");
    const e = report.encryption;
    let html = '<h2 id="encryption">Encryption and key transport</h2><p ' +
      'class="lead">What this service encrypts with, and — separately — what ' +
      'it will decrypt. The two lists are different on purpose in both JOSE ' +
      'and XML, and the reason is the same each time: it holds one private ' +
      'key of each kind and can encrypt to anybody\'s.</p>';

    html += '<h3>JWE</h3><table><tbody>' +
      '<tr><th class="n">Key management, encrypting</th><td>' +
      self.chips(e.jwe.keyManagementOut) + '</td></tr>' +
      '<tr><th class="n">Key management, decrypting</th><td>' +
      // **IT IS THE LONGER LIST NOW AND THIS NOTE SAID "shorter on purpose".**
      // It was written when the decrypt list was `['RSA-OAEP-256']` alone; the
      // symmetric families arrived in `crypto.js` and the two lists swapped
      // ends, leaving the page explaining an asymmetry in the direction it no
      // longer has.
      self.chips(e.jwe.keyManagementIn) + ' <span class="why">longer on ' +
      'purpose, and it is the row above that is narrow: this service ' +
      'encrypts OUTWARD to a recipient\'s published key and shares no secret ' +
      'with it, so it offers the asymmetric families only — while what ' +
      'ARRIVES may be wrapped with a key the sender already holds, and a ' +
      'caller picks by what it has rather than by what this table ' +
      'permits</span></td></tr>' +
      '</tbody></table><table><thead><tr><th class="n">enc</th><th>Bits</th>' +
      '<th>Mode</th><th>CEK</th><th>Note</th></tr></thead><tbody>' +
      e.jwe.contentEncryption.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.enc) + '</code></td><td>' +
          esc(row.bits) + '</td><td><code>' + esc(row.mode) +
          '</code></td><td>' + esc(row.cekBytes) + ' bytes</td><td>' +
          esc(row.note) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      admin.note('<strong>The CBC-HMAC family is here because it is what an ' +
        'OpenID Connect client gets by default.</strong> Register <code>' +
        'userinfo_encrypted_response_alg</code> and say nothing about <code>' +
        'enc</code>, and section 2 of the registration specification has ' +
        'chosen <code>A128CBC-HS256</code> for you. A service that spoke ' +
        'only AES-GCM would refuse the commonest encrypted response there ' +
        'is, and would look to the client like it had refused the request.');

    html += '<h3>XML Encryption</h3>' +
      '<p class="lead">The configured choice is what the next encrypted ' +
      'assertion will actually use; both settings are editable on ' +
      '<a href="/admin/saml2">SAML 2.0</a>. Right now: block cipher <code>' +
      esc(e.xml.configured.blockCipher) + '</code>, key transport <code>' +
      esc(e.xml.configured.keyTransport) + '</code>, assertions ' +
      (e.xml.configured.encryptAssertion ? 'encrypted' : 'not encrypted') +
      ', logout NameID ' +
      (e.xml.configured.encryptLogoutNameId ? 'encrypted' : 'not encrypted') +
      '.</p>' +
      '<table><thead><tr><th class="n">Block cipher</th><th>URI</th>' +
      '<th>Key</th><th>Authenticated</th></tr></thead><tbody>' +
      e.xml.blockCiphers.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.name) +
          '</code></td><td><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.keyBits) + '-bit ' + esc(row.mode) + '</td><td>' +
          (row.authenticated ? 'yes' : '<strong>no</strong>') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<table><thead><tr><th class="n">Key transport</th><th>URI</th>' +
      '<th>Scheme</th></tr></thead><tbody>' +
      e.xml.keyTransports.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.name) +
          '</code></td><td><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.scheme) + (row.safe ? '' : ' — <strong>broken</strong>') +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      admin.warn('<strong>Two of these are unsafe and are offered ' +
        'anyway.</strong> The CBC ciphers are not authenticated — that is ' +
        'the property CBC has, not a defect in this service — and what this ' +
        'service does about it when READING is parse the result and refuse ' +
        'anything that is not well-formed XML, which catches ordinary ' +
        'corruption and is not integrity. <code>rsa-1_5</code> is ' +
        'RSAES-PKCS1-v1_5, which Bleichenbacher\'s adaptive ' +
        'chosen-ciphertext attack is against exactly. Both are here because ' +
        'a great many deployed service providers accept nothing else, which ' +
        'is a fact about the world that a client library is entitled to be ' +
        'tested against. Nothing this service encrypts is a real secret. ' +
        '<code>rsa-oaep-mgf1p</code> is SHA-1 by definition — the URI means ' +
        'it — and the newer <code>rsa-oaep</code> carries its digest in a ' +
        'child element and is deliberately not offered, because a service ' +
        'provider that can read that one can do GCM too and this list exists ' +
        'for the ones that cannot.');

    html += '<h3>Kerberos encryption types</h3>' +
      '<table><thead><tr><th class="n">etype</th><th>Name</th>' +
      '<th>Performed</th></tr></thead><tbody>' +
      e.kerberos.performed.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.id) +
          '</code></td><td><code>' + esc(row.name) +
          '</code></td><td>yes</td></tr>';
      }).join('') +
      e.kerberos.decodeOnly.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.id) +
          '</code></td><td><code>' + esc(row.name) +
          '</code></td><td><span class="why">decode only</span></td></tr>';
      }).join('') + '</tbody></table>' +
      admin.note('<strong>The decode-only rows are named rather than left as ' +
        'bare numbers, and that is the whole reason they are in the ' +
        'codec.</strong> A packet capture or a KDC\'s advertised list ' +
        'containing one of them renders honestly instead of showing an ' +
        'integer nobody can look up. DES was removed from Windows Server ' +
        '2025 and is not performed here either. This table is read back out ' +
        'of the codec through its own <code>etypeName()</code>, not copied — ' +
        'those modules are vendored and cannot be edited to export a list.');

    html += '<h3>TLS</h3>' + admin.note('<strong>' + self.prose(e.tls.what) +
      '</strong> The sockets: ' + self.chips(e.tls.sockets) + '.');
    log.debug("Leaving CryptoMetadata.renderEncryption().");
    return html;
  }

  private renderPostQuantum(report) {
    const { log, esc, admin } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderPostQuantum().");
    const pq = report.postQuantum;
    let html = '<h2 id="post-quantum">Post-quantum readiness</h2>' +
      '<p class="lead"><strong>The headline is one sentence and it is not ' +
      'the flattering one: this service\'s signatures are partly ' +
      'post-quantum and its key establishment is entirely ' +
      'classical.</strong> Those two halves are in very different positions, ' +
      'and a page that said "supports ML-DSA" without separating them would ' +
      'be making the kind of claim this repository exists not to make.</p>' +
      admin.note('<strong>The two halves differ because of the threat, not ' +
                 'the ' +
        'effort.</strong> A signature is verified at the moment it is ' +
        'presented, so a signature algorithm that falls to a quantum ' +
        'computer in 2035 is a problem in 2035. A key agreement is not: ' +
        'ciphertext captured today can be kept and opened when the machine ' +
        'arrives, which is what "harvest now, decrypt later" names. So the ' +
        'surface here that ' +
        'most needs a post-quantum answer is the one that has none.') +
      admin.note('<strong>Symmetric cryptography is a third category and is ' +
        'the one people get wrong.</strong> ' + self.prose(pq.symmetric.what) +
        ' The strongest this service performs: ' +
        self.prose(pq.symmetric.strongest));

    html += '<h3>The post-quantum algorithms this service holds</h3>' +
      '<table><tbody>' +
      '<tr><th class="n">ML-DSA (FIPS 204)</th><td>' +
      self.chips(pq.algorithms.mlDsa) +
      '</td></tr>' +
      '<tr><th class="n">SLH-DSA (FIPS 205)</th><td>' +
      self.chips(pq.algorithms.slhDsa) +
      '</td></tr>' +
      '<tr><th class="n">Key type</th><td><code>' + esc(pq.algorithms.keyType) +
      '</code></td></tr>' +
      '</tbody></table>' +
      '<table><thead><tr><th class="n">Composite</th><th>ML-DSA half</th>' +
      '<th>Traditional half</th><th>Domain separator</th></tr></thead><tbody>' +
      pq.algorithms.composite.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.alg) +
          '</code></td><td><code>' + esc(row.mlDsa) +
          '</code></td><td><code>' + esc(row.traditional) +
          '</code></td><td><code>' + esc(row.domainSeparator) +
          '</code></td></tr>';
      }).join('') + '</tbody></table>' +
      admin.note('<strong>What the composites buy, and what the domain ' +
        'separator is for.</strong> ' + self.prose(pq.algorithms.what)) +
      admin.note('<strong>Where the independence is, and where it is ' +
                 'not.</strong> ' +
        self.prose(pq.algorithms.independence));

    html += '<h3>Signatures, surface by surface</h3>' +
      '<table><thead><tr><th class="n">Surface</th><th>State</th><th>How</th>' +
      '</tr></thead><tbody>' +
      pq.signatures.map(function (row) {
        return '<tr><td class="n">' + esc(row.surface) + '</td><td>' +
          (row.state === 'pq'
            ? '<strong>post-quantum available</strong>'
            : '<span class="why">classical only</span>') +
          '</td><td>' + self.prose(row.how) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>Key establishment</h3>' +
      admin.warn('<strong>Every key establishment mechanism in this process ' +
                 'is ' +
        'classical.</strong> ' + self.prose(pq.keyEstablishment.what)) +
      '<table><tbody><tr><th class="n">Mechanisms</th><td>' +
      self.chips(pq.keyEstablishment.mechanisms) + '</td></tr>' +
      '<tr><th class="n">What would close it</th><td>' +
      self.prose(pq.keyEstablishment.whatWouldClose) +
      '</td></tr></tbody></table>';
    log.debug("Leaving CryptoMetadata.renderPostQuantum().");
    return html;
  }

  private renderStandards(report) {
    const { log, esc } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderStandards().");
    let html = '<h2 id="standards">The higher-level standards</h2><p ' +
      'class="lead">Knowing that this service signs with RSA-SHA256 does not ' +
      'say whether that signature is a JWS, an enveloped XMLDSIG, a detached ' +
      'signature over a query string or a <code>&lt;wsse:Security&gt;</code> ' +
      'header — four different documents with four different failure modes. ' +
      'This is that layer. <strong>Every coverage note starts ' +
      '<code>full</code>, <code>partial</code> or <code>mock</code></strong> ' +
      'and says what is missing, which is the rule <a ' +
      'href="/admin/sts-metadata">Service metadata</a> follows and which is ' +
      'worth more here: a page about cryptography that overstates what it ' +
      'implements is actively dangerous to somebody using it to learn.</p>';

    html += report.standards.map(function (row) {
      return '<h3 id="std-' + esc(row.key) + '">' + esc(row.name) + '</h3>' +
        '<table><tbody>' +
        '<tr><th class="n">Specifications</th><td>' + self.chips(row.specs) +
        '</td></tr>' +
        '<tr><th class="n">Coverage</th><td>' + self.prose(row.coverage) +
        '</td></tr><tr><th ' +
        'class="n">What it is here</th><td>' + self.prose(row.what) +
        '</td></tr>' +
        '</tbody></table>';
    }).join('');
    log.debug("Leaving CryptoMetadata.renderStandards().");
    return html;
  }

  private renderInner(report) {
    const { log, esc, admin } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderInner().");
    let html = '<p class="lead">What this service does when it signs, ' +
      'verifies, encrypts or decrypts something — for every identity service ' +
      'it advertises, with the algorithms each one really uses and the ' +
      'higher-level envelope each is wrapped in. <strong>Every algorithm ' +
      'table below is read from the module that performs the ' +
      'algorithm</strong>, the way <a href="/admin/sts-metadata">Service ' +
      'metadata</a> reads its endpoint list off the live router, so none of ' +
      'it can claim something this service does not do.</p>';

    html += '<p><a class="btn" href="/admin/crypto-metadata?format=json" ' +
      'download="crypto-metadata.json" title="The whole of this page as ' +
      'JSON: every identity service, every algorithm table, the post-quantum ' +
      'posture and the standards list">Download all of this as JSON</a> ' +
      '<span class="why">' + esc(report.families.length) +
      ' identity services, ' + esc(report.signatures.jws.length) +
      ' JWS algorithms, ' + esc(report.standards.length) +
      ' standards</span></p>';

    html += admin.note('<strong>There is one place in this service that ' +
                       'signs, ' +
      'verifies, encrypts and decrypts, and this page is its ' +
      'report.</strong> Before 2026-08-27 all four happened in about twenty ' +
      'places: six independent XML signers, four independent XML signature ' +
      'verifiers, ten <code>jwt.verify()</code> calls of which four had ' +
      'quietly stopped applying the configured clock skew, two RFC 7638 ' +
      'thumbprints and two self-signed certificate builders. None of that ' +
      'was carelessness — each was written where it was needed and the ' +
      'copies agreed on the day they were made. What it cost is on the ' +
      'record: every SAML 1.1 assertion this service ever issued carried an ' +
      '<code>Id="_0"</code> attribute the schema does not have, and three of ' +
      'the four verifiers took the FIRST <code>&lt;ds:Signature&gt;</code> ' +
      'in the document — which on a Response carrying a signed assertion is ' +
      'the assertion\'s, so a caller asking "is this Response signed by us" ' +
      'was answered about a different element and told yes.');

    html += '<p class="lead">On this page: ' +
      '<a href="#families">the identity services</a> &middot; ' +
      '<a href="#keys">key material</a> &middot; ' +
      '<a href="#hashing">hashing</a> &middot; ' +
      '<a href="#signatures">signatures and MACs</a> &middot; ' +
      '<a href="#encryption">encryption</a> &middot; ' +
      '<a href="#post-quantum">post-quantum readiness</a> &middot; ' +
      '<a href="#standards">the standards</a></p>';

    html += self.renderFamilies(report);
    html += self.renderKeys(report);
    html += self.renderHashing(report);
    html += self.renderSignatures(report);
    html += self.renderEncryption(report);
    html += self.renderPostQuantum(report);
    html += self.renderStandards(report);
    log.debug("Leaving CryptoMetadata.renderInner().");
    return html;
  }

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, baseUrlOf, parseBody, errorCodes, admin, certificateDialog,
            certificateViews } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.registerRoutes().");
    // ------------------------------------------------------------------------
    // THE ROUTE. Behind the console's gate by construction — admin.js's one
    // `app.use('/admin', ...)` is registered at 18 and express applies
    // middleware only to routes added after it, and `common/protocol_stack.ts`
    // calls this at 20a (#50, R1). Nothing here repeats that check.
    //
    // `admin.respond()` answers `?format=json` itself, which keeps the
    // machine-readable form byte-for-byte the shape every other console page's
    // is: 200, `Cache-Control: no-store`, and the JSON this file builds.
    // ------------------------------------------------------------------------
    app.get('/admin/crypto-metadata', function (req, res) {
      log.debug("Entering the crypto metadata endpoint.");
      const report: any = self.cryptoJson(baseUrlOf(req));
      if (!certificateDialog.requested(req)) {
        admin.respond(req, res, report, 'Cryptography',
                      '/admin/crypto-metadata', self.renderInner(report));
        log.debug("Leaving the crypto metadata endpoint. " +
                  report.families.length + " identity service(s), " +
                  report.standards.length + " standard(s).");
        return;
      }
      // A CERTIFICATE'S DETAILS OVER THE PAGE (2026-09-13) — `/admin/pki`'s
      // route does the same with the same two modules; see
      // certificate_dialog.ts.
      const draw = function (view) {
        log.debug("Entering draw().");
        report.certificateDetails = view;
        admin.respond(req, res, report, 'Cryptography',
                      '/admin/crypto-metadata',
                      self.renderInner(report) +
                      certificateDialog.dialog('/admin/crypto-metadata', view,
                                               req.query.from));
        log.debug("Leaving draw().");
      };
      certificateViews.detailsView(req).then(function (view) {
        if (!view.ok) {
          errorCodes.mark(res, errorCodes.codeOf(view) || 'STS-ADMIN-0641');
        }
        draw(view);
        log.debug("Leaving the crypto metadata endpoint. With a certificate " +
                  "dialog.");
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-ADMIN-0642') + 'crypto_metadata: the ' +
                  'certificate details view failed: ' + e.message);
        errorCodes.mark(res, 'STS-ADMIN-0642');
        draw({ ok: false, errors: ['The certificate could not be opened: ' +
                                   e.message] });
      });
    });

    // ------------------------------------------------------------------------
    // THE KEY PAGE'S TWO ROUTES. Behind the console's gate for the same reason
    // the page above is — admin.js's one `app.use('/admin', ...)` is registered
    // at 18 and express applies middleware only to routes added after it.
    //
    // The POST is the one form in this console whose answer is a FILE rather
    // than a page. Everything else here goes through `respondToAction()`, which
    // 303s back to where the reader was with a notice on the query string; a
    // download cannot, because the thing that was asked for IS the response
    // body. A refusal DOES go back as a page, so a bad password or an
    // impossible format reads like every other refusal in this console.
    // ------------------------------------------------------------------------
    app.get('/admin/keys', function (req, res) {
      log.debug("Entering the key pairs endpoint.");
      const report = self.keysJson(baseUrlOf(req));
      admin.respond(req, res, report, 'Key pairs', '/admin/keys',
                    self.renderKeyPairs(report));
      log.debug("Leaving the key pairs endpoint. " + report.keys.length +
                " key(s).");
    });

    app.post('/admin/keys/export', function (req, res) {
      log.debug("Entering the key export endpoint.");
      // ADMIN WRITE, asked for explicitly. Every other read on this console
      // needs Admin Read; this one hands over a private key, so it is held to
      // the stronger of the two roles — and it is a GET-shaped act done as a
      // POST for exactly that reason.
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-ADMIN-0588');
        res.status(403).type('text/plain').set('Cache-Control', 'no-store')
           .send('Exporting a key pair needs the Admin Write role. Reading ' +
                 'this console needs Admin Read; taking a private key out of ' +
                 'it needs the other one.');
        log.debug("Leaving the key export endpoint. Refused: no Admin Write.");
        return;
      }
      const body = parseBody(req);
      self.exportKey(String(body.key || ''), String(body.format || 'pem'),
                String(body.password || '')).then(function (result) {
        if (!result.ok) {
          // A refusal is a PAGE, so it reads like every other refusal here.
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-ADMIN-0593');
          self.respondToKeyRefusal(req, res, result.errors[0]);
          log.debug("Leaving the key export endpoint. Refused.");
          return;
        }
        // ONE FILE IS THE BODY; SEVERAL ARE A ZIP THIS SERVICE WILL NOT BUILD.
        // The DER export is two files (private and public), and rather than
        // take a zip dependency for it the private half is sent and the page
        // says the public half is derivable from it — which it is, with one
        // openssl command that the status line names.
        const file = result.files[0];
        const data = Buffer.isBuffer(file.data) ? file.data
          : (typeof file.data === 'string' ? Buffer.from(file.data, 'utf8')
             : Buffer.from(file.data));
        res.status(200)
           .set('Content-Type', file.mime || 'application/octet-stream')
           .set('Content-Disposition', 'attachment; filename="' +
                String(file.name).replace(/[^A-Za-z0-9._-]/g, '_') + '"')
           .set('Cache-Control', 'no-store')
           .send(data);
        log.debug("Leaving the key export endpoint. Sent " + file.name + ", " +
                  data.length + " bytes.");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-ADMIN-0594');
        self.respondToKeyRefusal(req, res, 'The export failed: ' + e.message);
        log.debug("Leaving the key export endpoint. Threw: " + e.message);
      });
    });
    log.debug("Leaving CryptoMetadata.registerRoutes().");
  }

  // A refusal from the export, answered the way the caller asked. A JSON caller
  // gets JSON; a browser gets sent back to the page with the reason on the
  // query string, which is what `respondToAction()` does for every other form
  // here.
  private respondToKeyRefusal(req, res, message) {
    const { log } = this.deps;
    log.debug("Entering CryptoMetadata.respondToKeyRefusal().");
    const type = String(req.headers['content-type'] || '');
    if (/json/i.test(type)) {
      // error-code: none — a transport helper; both callers mark the response
      // with the specific code first
      res.status(400).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify({ ok: false, errors: [message] }, null, 2));
      log.debug("Leaving CryptoMetadata.respondToKeyRefusal(). Answered JSON.");
      return;
    }
    res.set('Cache-Control', 'no-store')
       .redirect(303, '/admin/keys?error=' +
                 encodeURIComponent(String(message).slice(0, 500)));
    log.debug("Leaving CryptoMetadata.respondToKeyRefusal(). Redirected.");
  }

  // ===========================================================================
  // THE KEY PAIRS, AND TAKING THEM AWAY (2026-08-30)
  // ===========================================================================
  //
  // `/admin/keys` is the page, and it is the deliberate opposite of the one
  // above it. `/admin/crypto-metadata` publishes NO private key and says so
  // twice; this one exists to hand them over. Both statements are true and the
  // distinction is the whole design: a report about what this service can do is
  // something to leave lying around, and a private key is not.
  //
  // **WHY IT IS DEFENSIBLE HERE AND WOULD NOT BE ANYWHERE ELSE.** In
  // development mode every key in this process is generated at start, lives
  // only in memory, and dies with the process (where the keystore persists them
  // — product mode — the page says the opposite out loud; see `keysJson()`).
  // None of them protects anything: the service checks no password in
  // development mode, validates no token it did not mint, and says so on every
  // page. What a person actually needs, constantly, is the far end of an
  // exchange — a keystore to put in a Java truststore, a PEM for `openssl
  // s_client`, a JWK to paste into a client. Making them re-derive that from
  // `/oauth2/jwks` and a screenshot is the friction this page removes.
  //
  // It is behind the console gate and needs **Admin Write**, which is a
  // stronger requirement than any other read on this console — because this is
  // the one page where reading IS taking.
  //
  // **THE EXPORT IS `common/vendored/key_material.js`'s, NOT A SECOND ONE.**
  // That is the debugger's own keystore code, vendored here, and it already
  // does the four formats with a password: PEM, DER, JWK and PKCS#12. Writing a
  // second exporter beside it would be the thing this repository argues against
  // everywhere — and it would be the WORSE copy, because that one is what the
  // debugger's PKI page has been exercised through.
  //
  // **PKCS#12 IS OFFERED ONLY WHERE THERE IS A CERTIFICATE**, and the refusal
  // is the vendored module's own rather than a rule invented here: a .p12 wraps
  // a private key in a certificate, and this service holds one for the RSA
  // signing key, the TLS key and (since 2026-09-11) the curve keys, and for
  // nothing else — the post-quantum keys' certificates travel with their JWK,
  // below. The alternative — minting a throwaway self-signed certificate so the
  // format "works" — would hand somebody a keystore containing a certificate
  // this service has never used and will never present, which is worse than a
  // clear no.
  //
  // **THE POST-QUANTUM KEYS ARE JWK-ONLY, and that is RFC 9964 rather than a
  // gap.** An ML-DSA key is `kty: "AKP"`; there is no PKCS#8 encoding for it
  // here, so PEM, DER and PKCS#12 have nothing to write. The BBS key is not
  // offered at all: it is a raw scalar published as `publicKeyMultibase`, with
  // no standard private encoding to export it in, and offering a format that
  // silently produced something no library would read would be worse than
  // leaving it off.
  // ---------------------------------------------------------------------------

  // One row per key pair this process holds. `formats` is computed rather than
  // listed, because the answer differs per key for two different reasons — no
  // certificate, or no PKCS#8 encoding — and a hand-kept list would have to
  // repeat both.
  // The authority that certified one slot in the current realm, or null where
  // the key is still carrying the self-signed certificate it was born with. A
  // LEAF read (rule 3w): `pki.js` registers no route and this is a map lookup.
  private certifierOf(useCaseId, slot) {
    const { log, realms, stsPki } = this.deps;
    log.debug("Entering CryptoMetadata.certifierOf().");
    try {
      const held = stsPki.certificateFor(realms.currentId() === 'default' ? ''
                                           : realms.currentId(),
                                         useCaseId, slot);
      log.debug("Leaving CryptoMetadata.certifierOf().");
      return held ? { subject: held.subject, issuedBy: held.useCase,
                      notAfter: held.notAfter, pinned: !!held.pinned } : null;
    } catch (e) {
      log.debug("Caught in CryptoMetadata.certifierOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving CryptoMetadata.certifierOf().");
      // No hierarchy in this process. The key reports none, which is what this
      // service did before one existed.
      return null;
    }
  }

  keyInventory() {
    const { log, stsKeysFor, realms, pqJose, tlsServer,
            pqcSupport } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.keyInventory().");
    const keys = stsKeysFor();
    const cert = tlsServer.serverCertificate();
    const rows = [];

    rows.push({
      id: 'sts-rsa',
      label: 'Signing key',
      alg: 'RS256', kty: 'RSA', crv: '', bits: 2048,
      kid: String(keys.kid || ''),
      scope: 'realm', realm: realms.currentId(),
      hasCertificate: true,
      // WHICH AUTHORITY CERTIFIED IT (2026-09-11). A key that reports no issuer
      // is one still carrying the self-signed certificate it was born with, and
      // the difference is the whole of what the hierarchy bought — so it is a
      // field rather than something a reader infers from a subject line.
      certifiedBy: self.certifierOf('jose', 'RS256'),
      formats: ['pem', 'der', 'jwk', 'pkcs12'],
      usedFor: [
        'Every access token and refresh token, and the default ID Token ' +
        '(RS256).',
        'Every XML document this service mints — SAML 2.0 and 1.1 assertions ' +
        'and responses, WS-Federation, WS-Trust, per-service-provider ' +
        'metadata, and the outbound federation AuthnRequest.',
        'Decrypting a JWE or an EncryptedID sent to this service.',
        'Published at /oauth2/jwks and in every metadata document.'
      ]
    });

    (keys.extraKeys || []).forEach(function (one) {
      const jwk = one.publicJwk;
      rows.push({
        id: 'sts-' + String(jwk.kid || one.alg),
        label: (jwk.crv || one.alg) + ' key',
        alg: one.alg, kty: jwk.kty, crv: jwk.crv || '', bits: 0,
        kid: String(jwk.kid || ''),
        scope: 'realm', realm: realms.currentId(),
        certifiedBy: self.certifierOf('jose', jwk.crv
          ? (one.alg + ':' + jwk.crv) : one.alg),
        // **A CURVE KEY HAS A CERTIFICATE SINCE 2026-09-11**, issued by this
        // realm's JOSE Issuing CA — so PKCS#12, which needs one, is offered
        // where there is one. It was `false` and three formats for as long as
        // these keys existed, because nothing had ever certified them.
        hasCertificate: !!self.certifierOf('jose', jwk.crv
          ? (one.alg + ':' + jwk.crv) : one.alg),
        formats: self.certifierOf('jose', jwk.crv ? (one.alg + ':' + jwk.crv)
                                             : one.alg)
          ? ['pem', 'der', 'jwk', 'pkcs12'] : ['pem', 'der', 'jwk'],
        usedFor: [
          'An ID Token for a client that registered ' +
          'id_token_signed_response_alg: ' + one.alg + '.',
          'A signed UserInfo response for a client that registered it.',
          'Published at /oauth2/jwks so a client can verify one.'
        ]
      });
    });

    // THE POST-QUANTUM KEYS ARE REPORTED WHETHER OR NOT THEY EXIST YET, and the
    // row says which. They are made on first use — one SLH-DSA keygen is most
    // of two seconds — so this page must not be the thing that makes them: a
    // metadata screen that costs two seconds a view, in a realm where nobody
    // asked for a post-quantum signature, is a screen somebody learns not to
    // open. `/oauth2/jwks` is what brings them into being.
    const pq = Array.isArray(keys.pqKeys) ? keys.pqKeys : [];
    pqJose.PQ_ALGS.forEach(function (alg) {
      const made = pq.filter(function (k) { return k.alg === alg; })[0];
      rows.push({
        id: 'sts-pq-' + alg.toLowerCase(),
        label: alg,
        alg: alg, kty: 'AKP', crv: '', bits: 0,
        kid: made ? String(made.publicJwk.kid || '') : '',
        scope: 'realm', realm: realms.currentId(),
        // **ISSUED FROM THIS REALM'S JOSE ISSUING CA SINCE 2026-09-13**, and
        // `false` for as long as these keys existed before that. The slot is
        // the algorithm, as `common/pki.js`'s `certifyPqKeys()` files it.
        certifiedBy: made ? self.certifierOf('jose', alg) : null,
        hasCertificate: !!(made && self.certifierOf('jose', alg)),
        generated: !!made,
        // RFC 9964's key type, for which there is no PKCS#8 encoding here — so
        // still no PKCS#12 either, certificate or not: that format wraps a
        // private key. The certificate travels with the JWK export instead.
        formats: made ? ['jwk'] : [],
        usedFor: [
          'An ID Token or a signed UserInfo response for a client that ' +
          'registered ' + alg + '.',
          'Published at /oauth2/jwks as an AKP JWK.',
          'NOT usable for DPoP: RFC 7638 registers no thumbprint for AKP, so ' +
          'a proof signed with one would verify and bind to nothing.'
        ]
      });
    });

    rows.push({
      id: 'tls-server',
      label: 'TLS server certificate',
      alg: 'RS256', kty: 'RSA', crv: '', bits: 2048,
      kid: '', fingerprint: cert.fingerprint256,
      scope: 'process',
      subject: cert.subject, names: cert.names, notAfter: cert.notAfter,
      hasCertificate: true,
      formats: ['pem', 'der', 'jwk', 'pkcs12'],
      usedFor: [
        'LDAPS on 636.',
        'The main port, when global.https is on.',
        'Published as a certificate at /tls/server-certificate — this page ' +
        'is the only place the PRIVATE half is available.'
      ]
    });

    // WHETHER EACH ONE USES A POST-QUANTUM ALGORITHM (2026-09-13), from the one
    // classifier `/admin/pki` asks too: `null` for a classical key, otherwise
    // the kind (`pq` or `composite` here), the algorithm, a label and the
    // standard. On the row rather than decided by the page, so
    // `GET /admin-api/keys` answers what the icon on `/admin/keys` says.
    rows.forEach(function (row) {
      row.pqc = pqcSupport.of({ algorithms: [row.alg] });
    });
    log.debug("Leaving CryptoMetadata.keyInventory(). " + rows.length +
              " key(s).");
    return rows;
  }

  // The PEM pair for one row, or null where there is none to give. Kept apart
  // from keyInventory() because that function is a REPORT and is safe to call
  // anywhere, and this one reaches for private key material.
  // PKCS#1 IN, PKCS#8 OUT, ALWAYS, AND A REAL BUG IS WHY.
  //
  // `selfSignedRsaCertificate()` builds its key with forge, and forge writes
  // `-----BEGIN RSA PRIVATE KEY-----` — PKCS#1. The vendored exporter documents
  // its input as PKCS#8 and means it: PEM passed through untouched and looked
  // fine, while JWK came back "Invalid keyData" and PKCS#12 came back "Cannot
  // create 'PrivateKeyInfo' from ASN.1 object". Two of four formats failing
  // with messages naming neither the encoding nor the key is exactly the shape
  // of bug this normalisation exists to make impossible.
  //
  // node re-encodes it for nothing — `createPrivateKey()` reads either and
  // `export({type: 'pkcs8'})` writes the one every other tool expects — so this
  // is one call rather than a conversion worth arguing about, and it runs for
  // every key rather than for the two that needed it: a curve key that already
  // arrives as PKCS#8 comes out byte for byte the same.
  private toPkcs8(pem) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering CryptoMetadata.toPkcs8().");
    log.debug("Leaving CryptoMetadata.toPkcs8().");
    return nodeCrypto.createPrivateKey(pem).export({ type: 'pkcs8',
                                                     format: 'pem' });
  }

  private pemsFor(id) {
    const { log, stsKeysFor, realms, tlsServer, nodeCrypto,
            stsPki } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.pemsFor(). id=" + id);
    const keys = stsKeysFor();
    if (id === 'sts-rsa') {
      const pub = nodeCrypto.createPublicKey(keys.privateKeyPem)
        .export({ type: 'spki', format: 'pem' });
      log.debug("Leaving CryptoMetadata.pemsFor(). The signing key.");
      return { privatePem: self.toPkcs8(keys.privateKeyPem), publicPem: pub,
               desc: { kind: 'rsa', hash: 'SHA-256' },
               // The chain with it where the key is certified — see the curve
               // branch below for why a `.p12` wants the path and not the leaf.
               certs: [keys.certPem].concat(keys.certChainPem || []) };
    }
    if (id === 'tls-server') {
      const cert = tlsServer.serverCertificate();
      const pub = nodeCrypto.createPublicKey(cert.privateKeyPem)
        .export({ type: 'spki', format: 'pem' });
      log.debug("Leaving CryptoMetadata.pemsFor(). The TLS key.");
      return { privatePem: self.toPkcs8(cert.privateKeyPem), publicPem: pub,
               desc: { kind: 'rsa', hash: 'SHA-256' },
               certs: [cert.certPem] };
    }
    const extra = (keys.extraKeys || []).filter(function (one) {
      return 'sts-' + String(one.publicJwk.kid || one.alg) === id;
    })[0];
    if (extra) {
      const priv = extra.privateKey.export({ type: 'pkcs8', format: 'pem' });
      const pub = nodeCrypto.createPublicKey(extra.privateKey)
        .export({ type: 'spki', format: 'pem' });
      // **AND ITS CERTIFICATE, SINCE 2026-09-11.** A curve key had none for as
      // long as it existed, so `certs` was empty and PKCS#12 — which has
      // nowhere to put a bare key — was not offered. It is issued by this
      // realm's JOSE Issuing CA now, so the format is offered and the file has
      // to contain what the format needs. **THE CHAIN GOES IN TOO**: a `.p12`
      // holding a leaf and no path is importable as a key rather than as an
      // identity, which is the difference keytool and Windows both care about.
      const certified = self.certifierOf('jose', extra.publicJwk.crv
        ? (extra.alg + ':' + extra.publicJwk.crv) : extra.alg);
      const held = certified
        ? stsPki.publishedCertificateFor(
            realms.currentId() === 'default' ? '' : realms.currentId(),
            'jose', extra.publicJwk.crv
              ? (extra.alg + ':' + extra.publicJwk.crv) : extra.alg)
        : null;
      log.debug("Leaving CryptoMetadata.pemsFor(). A curve key.");
      return { privatePem: priv, publicPem: pub,
               desc: { kind: extra.publicJwk.kty === 'OKP' ? 'okp' : 'ec',
                       curve: extra.publicJwk.crv },
               certs: held ? [held.certificatePem].concat(held.chainPem) : [] };
    }
    log.debug("Leaving CryptoMetadata.pemsFor(). No PEM pair for this key.");
    return null;
  }

  // ---------------------------------------------------------------------------
  // THE EXPORT ITSELF. Answers rather than throws, for the reason
  // `decryptElement()` answers: every refusal here is something a person can
  // act on — a format this key has no encoding for, a PKCS#12 with no password,
  // a key that has not been generated yet — and an exception would reach the
  // browser as a 500 with none of that in it.
  // ---------------------------------------------------------------------------
  async exportKey(id, format, password) {
    const { log, stsKeysFor, realms, keystore, stsPki } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.exportKey(). id=" + id + ", format=" +
              format);
    const row =
        self.keyInventory().filter(function (one) { return one.id === id; })[0];
    if (!row) {
      log.debug("Leaving CryptoMetadata.exportKey(). No such key.");
      return self.refused('STS-ADMIN-0589', { ok: false, errors: ['There is ' +
          'no key called "' + id + '" ' +
        'in this realm. The list on the page is what this process holds; a ' +
        'key named here and not there is usually a realm switch away.'] });
    }
    if (!row.formats.length) {
      log.debug("Leaving CryptoMetadata.exportKey(). Nothing to export.");
      return self.refused('STS-ADMIN-0590', { ok: false, errors: [row.label +
          ' cannot be exported' +
        (row.generated === false
          ? ' because it has not been generated yet. The post-quantum keys ' +
            'are made on first use — fetch /oauth2/jwks in this realm and ' +
            'come back.'
          : '.')] });
    }
    if (row.formats.indexOf(format) < 0) {
      log.debug("Leaving CryptoMetadata.exportKey(). Unsupported format.");
      return self.refused('STS-ADMIN-0591', { ok: false, errors: [row.label +
          ' cannot be exported as ' +
        format + '. It offers ' + row.formats.join(', ') + '.' +
        (format === 'pkcs12' && !row.hasCertificate
          ? ' PKCS#12 wraps a private key in a CERTIFICATE, and this service ' +
            'holds none for this key — only the signing key and the TLS key ' +
            'have one. Minting a throwaway certificate so the format worked ' +
            'would hand you a keystore this service has never presented.'
          : '')] });
    }

    // The post-quantum keys are a JWK and nothing else, and they are not a PEM
    // pair, so they do not go through the vendored exporter at all.
    if (row.kty === 'AKP') {
      const made = (stsKeysFor().pqKeys || []).filter(function (k) {
        return k.alg === row.alg;
      })[0];
      if (!made) {
        log.debug("Leaving CryptoMetadata.exportKey(). The key vanished " +
                  "between the list and here.");
        return self.refused('STS-ADMIN-0590', { ok: false,
            errors: [row.label + ' has not been generated yet.'] });
      }
      // The PUBLIC half only. There is no interoperable private encoding for an
      // AKP key to hand over — RFC 9964 defines the public members and the seed
      // handling is still moving — so exporting a private half here would be
      // inventing a format, and a file no library reads is worse than a refusal
      // that says why.
      const text = JSON.stringify(made.publicJwk, null, 2);
      const files = [{ name: row.alg.toLowerCase() + '-public.jwk.json',
                       data: text, mime: 'application/jwk+json' }];
      // AND THE CERTIFICATE THIS REALM'S JOSE ISSUING CA ISSUED OVER IT
      // (2026-09-13), leaf first with the chain under it and without the Root —
      // public, and the one thing about this key a relying party could not get
      // from the JWKS.
      let held = null;
      try {
        held = stsPki.publishedCertificateFor(
          realms.currentId() === 'default' ? '' : realms.currentId(),
          'jose', row.alg);
      } catch (e) {
        log.debug("Caught in CryptoMetadata.exportKey(): " +
                  ((e && e.message) || e));
        held = null;
      }
      if (held) {
        files.push({ name: row.alg.toLowerCase() + '-chain.pem',
                     data: [held.certificatePem].concat(held.chainPem).join(''),
                     mime: 'application/x-pem-file' });
      }
      log.debug("Leaving CryptoMetadata.exportKey(). An AKP public JWK.");
      return { ok: true, publicOnly: true,
               files: files,
               status: 'The PUBLIC half of ' + row.alg + ' as an AKP JWK' +
                       (held ? '; the certificate this realm\'s JOSE Issuing ' +
                               'CA issued over it, with its chain, is the ' +
                               'second file — which the management API ' +
                               'returns and a browser download, being one ' +
                               'file, does not' : '') +
                       '. There is no interoperable private encoding for ' +
                       'this key type to hand over, so the private half ' +
                       'stays in the process.' };
    }

    const pems = self.pemsFor(id);
    if (!pems) {
      log.debug("Leaving CryptoMetadata.exportKey(). No PEM pair.");
      return self.refused('STS-ADMIN-0592', { ok: false, errors: ['No key ' +
          'pair is available for ' + row.label +
        ' in this realm.'] });
    }
    try {
      const result = await keystore.exportKeyPair({
        format: format,
        privatePem: pems.privatePem,
        publicPem: pems.publicPem,
        desc: pems.desc,
        password: String(password || ''),
        baseName: id,
        friendlyName: row.label,
        certs: pems.certs,
        alg: row.alg,
        use: 'sig'
      });
      log.debug("Leaving CryptoMetadata.exportKey(). " + result.files.length +
                " file(s).");
      return { ok: true, files: result.files, status: result.status };
    } catch (e) {
      // The vendored module's own refusals — a PKCS#12 with no password, an
      // unreadable key — reach the page as themselves. They are better
      // sentences than anything this file would write over the top of them.
      log.debug("Leaving CryptoMetadata.exportKey(). The exporter refused: " +
                e.message);
      return self.refused('STS-ADMIN-0593', { ok: false, errors: [e.message] });
    }
  }

  keysJson(base) {
    const { log, realms, keystore, stsKeystore } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.keysJson().");
    const rows = self.keyInventory();
    // **`regeneratedEveryStart` WAS THE CONSTANT `true` AND THAT STOPPED BEING
    // TRUE ON 2026-09-06.** Where the keystore is in use the signing keys are
    // generated once and read back, so a resource asserting the opposite was
    // telling a caller that a key it had just exported would be gone after a
    // restart — which is the reassurance somebody would act on. It is read from
    // the keystore now. (The TLS key and the SPIFFE JWT authority really are
    // per start; the SPIFFE X.509 authority stopped being on 2026-09-11, when
    // it became a realm's Issuing CA. `keyInventory()`'s rows carry `scope`.)
    const store = stsKeystore.report();
    const out = {
      issuer: base,
      realm: realms.currentId(),
      regeneratedEveryStart: !store.persisting,
      // WHAT IS DECRYPTED RIGHT NOW, and the policy that decides. It is the
      // only way to see from outside that the residency window is what it
      // claims to be — a page saying "nothing is decrypted" has to be believed,
      // so it says which realms ARE and lets a reader watch the number change.
      residency: {
        persisting: store.persisting,
        retention: store.retention,
        plaintextTtlS: store.plaintextTtlS,
        note: store.retentionNote,
        realmsHeld: store.realmsHeld,
        plaintextHeld: store.plaintextHeld
      },
      formats: keystore.keystoreFormats(),
      keys: rows,
      warning: 'THIS RESOURCE LISTS KEYS; the export operation beside it ' +
               'HANDS OVER PRIVATE KEY MATERIAL. ' +
               (store.persisting
                 ? 'The signing keys of this realm are GENERATED ONCE AND ' +
                   'WRITTEN DOWN, encrypted, so one exported here goes on ' +
                   'signing after a restart — and a copy taken out of this ' +
                   'console goes on verifying against a live JWKS.'
                 : 'Every key here is generated at start, lives only in ' +
                   'memory and dies with the process, and none of them ' +
                   'protects anything — this service checks no password and ' +
                   'validates no token it did not mint.')
    };
    log.debug("Leaving CryptoMetadata.keysJson(). " + rows.length + " key(s).");
    return out;
  }

  // NAMED `renderKeyPairs` AND NOT `renderKeys`, AND A 500 IS WHY. This file
  // already had a `renderKeys()` — the KEY MATERIAL section of
  // /admin/crypto-metadata — and a second function declaration of that name
  // silently replaced it, so the page above started calling this one and threw
  // `report.keys.map is not a function` on a report that has no `keys`. Two
  // functions, one name, nine hundred lines apart: exactly what the `keystore`
  // import a few hundred lines up was renamed to avoid, met a second time
  // because the first rename fixed the symptom rather than teaching the lesson.
  // ---------------------------------------------------------------------------
  // HOW LONG A DECRYPTED PRIVATE KEY IS IN MEMORY (2026-09-06).
  //
  // A REPORT AND NOT A CONTROL, and that is rule 7 read exactly rather than a
  // gap. Everything on it is either a SETTING — drawn on `/admin/config` with
  // the rest of the Key material group, because that is where its group's row
  // in `SETTING_HOMES` sends it — or an observation. A *Purge now* button was
  // considered and refused: the one POST this page has answers with a FILE
  // rather than a page (see the routes above), so a second action here would be
  // the one form in this console whose two buttons answer in two different
  // shapes, and what it would buy is shortening a window the timer shortens
  // anyway.
  //
  // **THE NUMBER IS THE POINT.** A page that only named the policy would be
  // describing a promise; naming the realms whose key is decrypted RIGHT NOW is
  // something a reader can watch change, which is the only way an operator can
  // tell this is working rather than configured.
  // ---------------------------------------------------------------------------
  private renderResidency(residency) {
    const { log, esc, admin } = this.deps;
    log.debug("Entering CryptoMetadata.renderResidency().");
    if (!residency.persisting) {
      log.debug("Leaving CryptoMetadata.renderResidency(). Not persisting.");
      return admin.note('<strong>Nothing here is held encrypted in memory, ' +
        'because nothing here is written down.</strong> This service ' +
        'generates its signing key at start and keeps it for as long as it ' +
        'runs — there is no ciphertext for a decrypted key to be purged back ' +
        'TO, so <code>keys.plaintextRetention</code> means nothing in this ' +
        'configuration. It is the keystore that makes it apply, and <code>' +
        'keys.source</code> is what turns that on.');
    }
    const held = residency.plaintextHeld || [];
    const all = residency.realmsHeld || [];
    let html = '<h2 id="residency">How long a private key stays decrypted</h2>';
    html += admin.note('<strong>What this process holds is the ' +
      'CIPHERTEXT.</strong> A realm\'s signing key is decrypted when ' +
      'something signs with it and dropped again ' +
      '— ' + esc(residency.note || '') + '. It narrows a WINDOW ' +
      'and nothing more: the key-encryption key is resident too, so anybody ' +
      'who can read this process\'s memory at a moment of their choosing can ' +
      'wait for the next signature. What it takes away is the value of a ' +
      'SNAPSHOT — a core dump, a swapped page, a debugger attached for a ' +
      'moment — of material that used to sit here for weeks.');
    html += '<table><thead><tr><th class="n">Realm</th><th>Held</th>' +
      '<th>Decrypted right now</th></tr></thead><tbody>' +
      (all.length
        ? all.map(function (id) {
            const open = held.indexOf(id) >= 0;
            return '<tr><td class="n"><code>' + esc(id || 'default') +
              '</code></td><td>encrypted, ' +
              'AES-256-GCM</td><td>' + (open ? '<strong>yes</strong>'
                             : '<span class="why">no</span>') + '</td></tr>';
          }).join('')
        : '<tr><td colspan="3"><span class="why">no realm has stored key ' +
          'material yet</span></td></tr>') +
      '</tbody></table>';
    html += admin.note('A realm reads <strong>no</strong> here until ' +
                       'something ' +
      'signs for it, and goes back to <strong>no</strong> on its own. ' +
      'Reading this page does not decrypt anything: the key list above is ' +
      'built from the PUBLIC half — certificates, key identifiers, public ' +
      'JWKs — which the key set holds in the clear precisely so that ' +
      'discovery and this console never touch a private key. Exporting one ' +
      'does.');
    log.debug("Leaving CryptoMetadata.renderResidency(). " + held.length +
              " decrypted.");
    return html;
  }

  private renderKeyPairs(report) {
    const { log, esc, admin, pqcBadge } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadata.renderKeyPairs().");
    const residency = report.residency || {};
    let html = '<p class="lead">Every key pair this process holds, what each ' +
      'one is used for, and a way to take it away. <strong>The signing keys ' +
      'are per trust realm</strong> — this shows <code>' + esc(report.realm) +
      '</code> — and the TLS certificate belongs to the process.</p>';

    // **THE OLD WARNING SAID THESE KEYS DIE WITH THE PROCESS, FULL STOP.** That
    // was true of every key in this service until the keystore landed, and it
    // is the sentence that makes handing a private key to a browser defensible
    // — so leaving it standing on a service whose signing key now OUTLIVES the
    // process would be this console's most consequential untruth. It is
    // computed.
    html += admin.warn('<strong>THIS PAGE HANDS OVER PRIVATE KEYS, and it is ' +
      'the only one here that does.</strong> <a ' +
      'href="/admin/crypto-metadata">Cryptography</a> next door publishes ' +
      'key types, identifiers and fingerprints and deliberately no key ' +
      'material at all; this one is the other half. ' +
      (residency.persisting
        ? '<strong>This realm\'s signing keys are PERSISTED</strong>, so a ' +
          'key exported here is not a throwaway: it goes on signing after a ' +
          'restart, and anything signed with a copy of it goes on verifying ' +
          'against this service\'s live JWKS. The TLS and SPIFFE keys below ' +
          'are still per start. '
        : 'It is defensible because of what these keys are: generated at ' +
          'start, held only in memory, dead when the process exits, and ' +
          'protecting nothing — this service checks no password and ' +
          'validates ' +
          'no token it did not mint. ') +
      'It needs <strong>Admin Write</strong>, which is a stronger ' +
      'requirement than any other read on this console, because here reading ' +
      'IS taking.');

    html += self.renderResidency(residency);

    html += admin.note('<strong>The exporter is the debugger\'s own, ' +
      'vendored.</strong> <code>common/vendored/key_material.js</code> does ' +
      'the four formats with a password — PEM, DER, JWK and PKCS#12 — and is ' +
      'the same code the debugger\'s PKI page has been exercised through. A ' +
      'second exporter beside it would be the worse copy.');

    html += pqcBadge.legend();

    html += '<h2 id="keys">The key pairs</h2>' +
      '<table><thead><tr><th class="n">Key</th><th>Type</th><th>' +
      'Identifier</th><th>Scope</th><th>Formats</th></tr></thead><tbody>' +
      report.keys.map(function (row) {
        return '<tr><td class="n"><a href="#key-' + esc(row.id) + '">' +
          esc(row.label) + '</a></td>' +
          '<td><code>' + esc(row.alg) + '</code> <code>' + esc(row.kty) +
          '</code>' + (row.crv ? ' <code>' + esc(row.crv) + '</code>' : '') +
          (row.bits ? ' ' + esc(row.bits) + '-bit' : '') +
          pqcBadge.badge(row.pqc) + '</td>' +
          '<td>' + (row.kid ? '<code>' + esc(row.kid) + '</code>'
                    : (row.fingerprint ?
                       '<code>' + esc(row.fingerprint) + '</code>'
                       : '<span class="why">' +
                         (row.generated === false ? 'not made yet' : 'none') +
                         '</span>')) + '</td>' +
          '<td>' + (row.scope === 'realm' ? 'this realm' : 'the process') +
          '</td><td>' + (row.formats.length ? self.chips(row.formats)
                    : '<span class="why">not exportable</span>') + '</td></tr>';
      }).join('') + '</tbody></table>';

    report.keys.forEach(function (row) {
      html += '<h3 id="key-' + esc(row.id) + '">' + esc(row.label) +
        pqcBadge.badge(row.pqc) + '</h3>' +
        '<table><tbody><tr><th class="n">Used for</th><td><ul>' +
        row.usedFor.map(function (what) {
          return '<li>' + self.prose(what) + '</li>';
        }).join('') + '</ul></td></tr>' +
        (row.subject ? '<tr><th class="n">Subject</th><td><code>' +
          esc(row.subject) + '</code></td></tr>' : '') +
        (row.names ? '<tr><th class="n">Names</th><td>' +
          self.chips(row.names) + '</td></tr>' : '') +
        (row.notAfter ? '<tr><th class="n">Valid to</th><td>' +
          esc(row.notAfter) + '</td></tr>' : '') +
        '</tbody></table>' +
        self.keyExportForm(row);
    });
    log.debug("Leaving CryptoMetadata.renderKeyPairs().");
    return html;
  }

  // ---------------------------------------------------------------------------
  // ONE FORM PER KEY, and it is a real form with a real button because this
  // console runs no script (`script-src 'none'`). The POST answers with the
  // FILE rather than with a redirect, which is the one place in this console a
  // form does not come back as a page — a download is what was asked for, and a
  // 303 to a page saying "your key is ready" would be a page with nothing on
  // it.
  // ---------------------------------------------------------------------------
  private keyExportForm(row) {
    const { log, esc, admin } = this.deps;
    log.debug("Entering CryptoMetadata.keyExportForm().");
    if (!row.formats.length) {
      log.debug("Leaving CryptoMetadata.keyExportForm().");
      return admin.note('<strong>Not exportable.</strong> ' +
        (row.generated === false
          ? 'The post-quantum keys are made on FIRST USE — one SLH-DSA ' +
            'keygen is most of two seconds — so this page deliberately does ' +
            'not make them. Fetch <code>/oauth2/jwks</code> in this realm ' +
            'and come back.'
          : 'There is no interoperable encoding for this key to hand over.'));
    }
    log.debug("Leaving CryptoMetadata.keyExportForm().");
    return '<form method="post" action="/admin/keys/export" class="formrow">' +
      '<input type="hidden" name="key" value="' + esc(row.id) + '">' +
      '<label for="fmt-' + esc(row.id) + '">Keystore format</label> ' +
      '<select id="fmt-' + esc(row.id) + '" name="format">' +
      row.formats.map(function (f) {
        return '<option value="' + esc(f) + '">' + esc(f.toUpperCase()) +
          (f === 'pkcs12' ? ' (.p12 — password required)' : '') + '</option>';
      }).join('') + '</select> ' +
      '<label for="pw-' + esc(row.id) + '">Password</label> ' +
      '<input type="password" id="pw-' + esc(row.id) + '" name="password" ' +
      'placeholder="required for PKCS#12; encrypts the private half of the ' +
      'rest"> <button type="submit">Download</button>' +
      (row.kty === 'AKP'
        ? admin.note('<strong>The PUBLIC half only.</strong> RFC 9964 ' +
                     'defines ' +
          'the public members of an AKP key and the private seed handling is ' +
          'still moving, so there is no interoperable private encoding to ' +
          'hand over. A file no library reads would be worse than saying so.')
        : admin.note('<strong>A password is REQUIRED for PKCS#12 and ' +
                     'optional ' +
          'for the other three</strong>, where it encrypts the private half ' +
          '(PKCS#8 for PEM and DER, PBES2 as a .jwe for JWK). Leave it empty ' +
          'and the private key comes out in the clear, which is usually what ' +
          'you want from a mock and is never what you want anywhere else.')) +
      '</form>';
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
const slot = new InstanceSlot<CryptoMetadata>(
  'admin-ui/crypto_metadata',
  () => new CryptoMetadata(CryptoMetadata.defaultDeps()),
  CryptoMetadata.wire,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

const log = helpers.log;

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  CryptoMetadata: CryptoMetadata,
  installInstance: (instance: CryptoMetadata): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // The instance's table, read when asked (#50, R2): the same array the
  // installed instance holds.
  get FAMILIES() {
    return slot.get().families;
  },
  STANDARDS: STANDARDS,
  // Filled by ../sts_metadata.js at ITS require time — see the header for why
  // this direction and not the other.
  setProtocolFamilies: slot.forward('setProtocolFamilies'),
  // For the tests, which assert these against what the modules that perform
  // the algorithms actually offer rather than against a list in a test.
  driftReport: slot.forward('driftReport'),
  keyMaterial: slot.forward('keyMaterial'),
  kerberosEtypes: slot.forward('kerberosEtypes'),
  hashing: slot.forward('hashing'),
  signatures: slot.forward('signatures'),
  encryption: slot.forward('encryption'),
  postQuantum: slot.forward('postQuantum'),
  cryptoJson: slot.forward('cryptoJson'),
  keyInventory: slot.forward('keyInventory'),
  keysJson: slot.forward('keysJson'),
  exportKey: slot.forward('exportKey')
};
