'use strict';
//
// File: pki_authoring.js
//
// ===========================================================================
// THE CERTIFICATE & KEY CONFIGURATION PANE: THE FORM, THE GRAMMARS, AND WHAT
// COMES OUT THE OTHER END.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// `tests/vendored/sts_pki_workbench.js` drives this pane over HTTP and is the
// other half of this. What is HERE is the four things that cannot be asserted
// by driving a running service:
//
//   * **THE FORM AGAINST THE PAGE.** The field table is declared in
//     `common/pki_authoring.js` and DRAWN in `admin-ui/pki_admin.js`, and the
//     two going out of step is the failure this arrangement is most likely to
//     produce — a field parsed and never drawn falls to its default on every
//     round trip, and one drawn and never parsed is a control that does
//     nothing. NEITHER IS AN ERROR ANYWHERE. Over HTTP there is nothing to
//     compare the page against; here both lists are values.
//   * **THE SIX LINE GRAMMARS AND THEIR REFUSALS.** What the pane must refuse
//     is the interesting half — a subjectAltName line with no type, a name
//     constraint with no verb — and each refusal has to NAME the line. A test
//     that only checks the accepted forms passes just as happily against a
//     parser that drops what it cannot read, which is the one outcome that
//     matters here because a certificate quietly missing a name VERIFIES.
//   * **THE THREE SUBJECT RULES.** "A Common Name somebody typed is never
//     overwritten" is a statement about two calls with a person's edit in
//     between, and there is no request that expresses it.
//   * **WHAT IS STORED AGAINST WHAT IS HANDED OUT.** `view()` drops every
//     private key; over HTTP the evidence for that is the absence of a string.
//
// The fifth thing is the encoder, and it is deliberately NOT re-asserted here:
// `common/vendored/x509.js` is the parent project's own file, held to roughly
// 240 certificates against OpenSSL over there. What this file checks is that
// the FORM reaches it — that a box ticked on the page is an extension in the
// certificate — which is this repository's half of the seam.
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const authoring = require('../common/pki_authoring');
const pki = require('../common/pki');
const x509 = require('../common/vendored/x509');
// The page. Requiring it registers `/admin/pki` and starts nothing (see the
// root CLAUDE.md's
// *Socket owners start their listeners from `listen()`*), so an
// in-process test may require it and no port is bound.
const pkiAdmin = require('../admin-ui/pki_admin');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'pki_authoring',
  level: process.env.LOG_LEVEL || 'info' });

// A realm per section, so that nothing below depends on the order the sections
// run in — every one of these is a partition of the keystore's PKI map, and a
// section reusing another's realm would be a test that passes because of what
// the section above it left behind.
const FORM = 'pane-form';
const ISSUE = 'pane-issue';
const STORE = 'pane-store';
const EXPORT = 'pane-export';

// The harness has `check` and `equal` and no `throws`, and these grammars
// REFUSE by throwing with the grammar in the message — which is the half worth
// asserting, because a parser that silently dropped a line it could not read
// would pass every positive case here. So: one helper, and it checks the
// MESSAGE as well as the throw.
function refuses(t, fn, pattern, what) {
  log.debug("Entering refuses().");
  let threw = null;
  try {
    fn();
  } catch (e) {
    threw = e;
  }
  if (!threw) {
    t.check(false, what, 'it did not refuse at all');
    log.debug("Leaving refuses().");
    return;
  }
  t.check(pattern.test(threw.message), what, threw.message);
  log.debug("Leaving refuses().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== every declared field is drawn, and every drawn field is ' +
             'declared ===');

  const json = pkiAdmin.pkiView(undefined, authoring.defaultDraft(FORM));
  const html = pkiAdmin.paneHtml(json, json.workbench.draft);
  const drawn = new Set();
  const matcher = /name="(pki_[A-Za-z0-9_]+)"/g;
  let hit;
  while ((hit = matcher.exec(html)) !== null) {
    drawn.add(hit[1]);
  }
  const missing = authoring.FIELD_NAMES.filter(function (name) {
    return !drawn.has(name);
  });
  const extra = Array.from(drawn).filter(function (name) {
    return authoring.FIELD_NAMES.indexOf(name) < 0;
  });
  t.equal(missing.join(', '), '',
          'every field the parser reads is on the page — one that is not ' +
          'falls back to its default on every round trip, which is a control ' +
          'that silently undoes itself rather than an error');
  t.equal(extra.join(', '), '',
          'and every field on the page is one the parser reads — one that is ' +
          'not is a control that does nothing at all');
  t.check(authoring.FIELD_NAMES.length > 100,
          'the pane really is the whole thing: ' +
          authoring.FIELD_NAMES.length + ' fields',
          String(authoring.FIELD_NAMES.length));

  // The three vocabularies are READ FROM THE ENCODER rather than written out,
  // which is `crypto_metadata.js`'s rule applied to a form: a checkbox for a
  // bit the encoder does not have cannot exist, and a bit it gains appears
  // here the day it is added.
  x509.KEY_USAGE_BITS.forEach(function (bit) {
    t.check(drawn.has('pki_ku_' + bit.name),
            'the keyUsage bit ' + bit.name + ' has a box, and it is there ' +
            'because the encoder declares it rather than because somebody ' +
            'typed it');
  });
  t.equal(Object.keys(x509.EKU_OIDS).filter(function (name) {
            return !drawn.has('pki_eku_' + name);
          }).join(', '), '',
          'and so does every extendedKeyUsage purpose the encoder knows');
  t.equal(x509.NS_CERT_TYPE_BITS.filter(function (bit) {
            return !drawn.has('pki_ns_' + bit.name);
          }).map(function (bit) { return bit.name; }).join(', '), '',
          'and every Netscape certificate type');

  t.log.info('=== a flag is PRESENT-or-ABSENT, because an unticked box posts ' +
             'nothing ===');
  const posted = authoring.draftFrom({ pki_ext_bc: '1', pki_dn_cn: '  spaced  ',
                                       pki_private_key: '  PEM\n  ' });
  t.check(posted.pki_ext_bc === true,
          'a checkbox that arrives is true');
  t.check(posted.pki_ext_ku === false,
          'and one that does not arrive is false rather than undefined — an ' +
          'unticked box posts nothing, so there is no third state to read');
  t.equal(posted.pki_dn_cn, 'spaced',
          'a text field is trimmed');
  t.equal(posted.pki_private_key, '  PEM\n  ',
          'and a KEY field is not: PEM has meaningful line breaks, and a ' +
          'field whose whole content is a wire format is the one place a ' +
          'trim is a change');
  // **A BROWSER CANNOT PRODUCE THESE AND `/admin-api` CAN**, which is why the
  // reading is not `!!raw`. A JSON caller that sends `"false"` or `"0"` for a
  // box it means to leave clear is writing the word for OFF, and reading it as
  // true turns an extension on in a certificate nobody asked for. It was a
  // surviving mutant that put this assertion here — the fixture had only ever
  // posted `'1'` and an absence, which `!!raw` gets right.
  const worded = authoring.draftFrom({ pki_ext_ku: 'false', pki_save_keys: '0',
                                       pki_ext_bc: '1' });
  t.check(worded.pki_ext_ku === false && worded.pki_save_keys === false,
          'a checkbox posted as the WORD "false" or as "0" is false, which a ' +
          'browser cannot send and a JSON caller can');
  t.check(worded.pki_ext_bc === true,
          'and one posted as "1" beside them is still true');
  // **AND A REAL BOOLEAN IS TAKEN AT ITS WORD**, which is the shape every
  // action's reply carries: `draft` is JSON, its flags are booleans, and the
  // contract is "post back what came back". Without it a `false` matched none
  // of the cases above and read as TRUE, so `apply-profile` followed by
  // `issue-certificate` turned every cleared box on —
  // `tests/vendored/sts_pki_workbench.js` found it on its first run and this
  // is the in-process half of that fix.
  const round = authoring.draftFrom({ pki_reuse_key: false, pki_ext_bc: true });
  t.check(round.pki_reuse_key === false && round.pki_ext_bc === true,
          'a JSON boolean round-trips as itself, which is what makes ' +
          '"post back what came back" true of this API');

  t.log.info('=== the six line grammars, and what each of them REFUSES ===');

  const names = authoring.parseAltNames([
    'dns:example.test', 'ip:10.0.0.1', 'email:a@b.test',
    'uri:https://example.test/x', 'upn:user@EXAMPLE.TEST',
    'krb5:host/x@EXAMPLE.TEST', 'rid:1.2.3.4', 'dirname:CN=alt,O=Example',
    'othername:1.2.3.4:DANDYWJj']);
  t.equal(names.length, 9, 'all nine general-name forms parse');
  t.equal(names[6].kind, 'registeredID',
          'and `rid` is spelled registeredID on the way out, which is the ' +
          'encoder\'s word rather than the form\'s');
  refuses(t, function () { authoring.parseAltNames(['example.test']); },
           /has no type/,
           'a name with no type is REFUSED and the message names the line — ' +
           'dropping it would produce a certificate silently missing the ' +
           'name somebody typed, which verifies');
  refuses(t, function () { authoring.parseAltNames(['nonsense:x']); },
           /Unknown alternative name type/,
           'and so is a type this encoder does not have');
  refuses(t, function () { authoring.parseAltNames(['othername:1.2.3.4']); },
           /needs an OID and a base64/,
           'an othername without its value is refused with the shape it wants');

  const aia = authoring.parseAccessDescriptions(
    ['ocsp:http://ocsp.test', 'caissuers:http://ca.test/c.cer',
     '1.3.6.1.5.5.7.48.5:http://other.test']);
  t.equal(aia[1].method, 'caIssuers',
          'an access method is canonicalised to the encoder\'s spelling');
  t.equal(aia[2].method, '1.3.6.1.5.5.7.48.5',
          'and one this page does not name is passed through as the OID it ' +
          'is, which is what makes the form open-ended rather than a list of ' +
          'four');
  refuses(t, function () { authoring.parseAccessDescriptions(['http-ocsp']); },
           /has no method/, 'a line with no method is refused');

  const policies = authoring.parsePolicies(
    ['1.2.3|cps=https://x.test/cps|notice=Test only', '2.5.29.32.0']);
  t.equal(policies[0].cps + ' / ' + policies[0].notice,
          'https://x.test/cps / Test only',
          'both RFC 5280 qualifiers parse off one line');
  t.equal(policies[1].oid, '2.5.29.32.0',
          'and a bare policy OID needs neither');

  const mappings = authoring.parsePolicyMappings(['1.2.3=4.5.6']);
  t.equal(mappings[0].issuer + '->' + mappings[0].subject, '1.2.3->4.5.6',
          'a policy mapping is issuer=subject');
  refuses(t, function () { authoring.parsePolicyMappings(['1.2.3']); },
           /issuer oid/, 'and one without the `=` is refused');

  const constraints = authoring.parseNameConstraints(
    ['permit dns:example.test', 'exclude ip:10.0.0.0/8']);
  t.equal(constraints.permitted.length + '/' + constraints.excluded.length,
          '1/1', 'name constraints split into permitted and excluded');
  t.equal(constraints.excluded[0].value, '10.0.0.0/8',
          'and an IP constraint keeps its PREFIX — a name constraint\'s ' +
          'iPAddress is the address followed by its MASK, which is the one ' +
          'place a general name is not simply an address');
  refuses(t, function () { authoring.parseNameConstraints(['dns:x.test']); },
           /permit|exclude/, 'a constraint with no verb is refused');
  refuses(t,
           function () {
             authoring.parseNameConstraints(['allow dns:x.test']);
           },
           /starts with "permit"/,
           'and so is one with a verb this page does not have, rather than ' +
           'its being read as one of the two that it is not');

  const custom = authoring.parseCustomExtensions(
    ['1.2.3|critical|DANDYWJj', '1.2.4|-|DANDYWJj']);
  t.check(custom[0].critical && !custom[1].critical,
          'a custom extension\'s critical flag is `critical` or `-`');
  refuses(t, function () { authoring.parseCustomExtensions(['1.2.3|-']); },
           /base64 DER/, 'and one missing its value is refused');

  t.log.info('=== a subject is an ORDERED sequence, and the extra lines keep ' +
             'their order ===');
  const subject = authoring.subjectFrom(authoring.draftFrom({
    pki_dn_cn: 'leaf', pki_dn_o: 'Acme', pki_dn_c: 'US',
    pki_dn_extra: 'businessCategory=Private Organization\n' +
                  '1.3.6.1.4.1.311.60.2.1.3=US'
  }));
  t.equal(subject.map(function (one) {
            return one.name || one.oid;
          }).join(','),
          'CN,O,C,businessCategory,1.3.6.1.4.1.311.60.2.1.3',
          'the named boxes in ENCODING order, then the extra lines as ' +
          'written — a Name is an ordered RDNSequence and a reordered DN is ' +
          'a different name that chains to nothing');
  t.check(subject[3].name === 'businessCategory' && subject[4].oid,
          'a name the encoder knows goes in BY NAME and one it does not goes ' +
          'in by OID, which is what lets a DN carry an attribute this page ' +
          'has never heard of');
  refuses(t, function () {
             authoring.subjectFrom(authoring.draftFrom(
               { pki_dn_extra: 'no equals sign here' }));
           }, /NAME=value/, 'an extra line with no `=` is refused');

  t.log.info('=== applying a profile: what it rewrites, and the one thing it ' +
             'must not ===');
  let draft = authoring.defaultDraft(FORM);
  t.equal(draft.pki_profile, 'root-ca',
          'the form opens on the first profile');
  t.check(draft.pki_ext_bc && draft.pki_bc_ca && draft.pki_ku_keyCertSign,
          'with the boxes a Root CA carries already ticked');
  t.check(/^[0-9a-f]{32}$/.test(draft.pki_serial),
          'and a random 128-bit serial already in the box, so that the value ' +
          'about to be signed is visible and editable before the certificate ' +
          'exists',
          draft.pki_serial);

  const asked = authoring.applyProfile(draft, 'tls-server');
  t.check(!asked.pki_bc_ca && asked.pki_eku_serverAuth,
          'switching to TLS Server clears cA and ticks serverAuth');
  t.equal(asked.pki_dn_cn, 'server',
          'and the Common Name follows, because an intermediate called ' +
          '"RootCA" chains correctly and reads as a bug for as long as it ' +
          'takes somebody to notice');
  t.equal(asked.pki_san, 'dns:server',
          'the subjectAltName is derived from the CN for a serverAuth ' +
          'profile — for a TLS server that is the difference between a ' +
          'certificate a client accepts and one it does not, because every ' +
          'current browser ignores the Common Name');
  t.equal(asked.pki_validity_years, String(x509.profile('tls-server').years),
          'and the validity is the profile\'s own rather than the last one\'s');

  // THE RULE THAT CANNOT BE ASSERTED OVER HTTP: a name somebody typed.
  const typed = authoring.applyProfile(
    Object.assign({}, asked, { pki_dn_cn: 'www.example.test' }), 'issuing-ca');
  t.equal(typed.pki_dn_cn, 'www.example.test',
          'a Common Name somebody TYPED survives a profile change — this ' +
          'runs on every profile change and once on every redraw, so a name ' +
          'typed a minute ago would otherwise be replaced by a page that had ' +
          'merely been submitted');
  t.check(typed.pki_bc_ca,
          'while the extension boxes still follow the new profile, which is ' +
          'the half that must move');

  t.log.info('=== which algorithms an approach allows ===');
  const any = authoring.keyAlgorithms('any');
  const classical = authoring.keyAlgorithms('classical');
  const pure = authoring.keyAlgorithms('pure');
  const composite = authoring.keyAlgorithms('composite');
  t.check(any.length > classical.length && classical.length === 7,
          'the classical approach is the seven algorithms a certificate has ' +
          'carried since RFC 5280, and `any` is more than that',
          classical.length + ' of ' + any.length);
  t.check(pure.every(function (one) { return one.kind === 'pqc'; }),
          'the pure approach offers no classical algorithm at all');
  t.check(composite.every(function (one) {
            return one.family === 'Composite ML-DSA';
          }) && composite.length > 0,
          'and the composite approach offers exactly the composite family');
  t.check(pure.some(function (one) { return one.signs === false; }),
          'ML-KEM is OFFERED and marked as unable to sign — it is a ' +
          'legitimate SUBJECT key (an encryption certificate is exactly a ' +
          'certificate over one) and can never be an ISSUER key, and a page ' +
          'that hid it would be hiding a real case');
  t.check(authoring.alternativeKeyAlgorithms().every(function (one) {
            return one.kind === 'pqc' && one.signs;
          }),
          'the alternative key\'s menu is the post-quantum algorithms that ' +
          'can SIGN — a hybrid certificate whose second key is also RSA is a ' +
          'certificate signed twice by the same century');

  t.log.info('=== the form reaches the encoder: every extension lands ===');
  const loaded = authoring.applyProfile(authoring.defaultDraft(ISSUE),
                                        'root-ca');
  Object.assign(loaded, {
    pki_key_alg: 'ec-p256',
    pki_dn_cn: 'Everything Root',
    pki_ext_san: true, pki_san: 'dns:ca.example.test\nip:10.0.0.1',
    pki_ext_aia: true, pki_aia: 'ocsp:http://ocsp.example.test',
    pki_ext_cdp: true, pki_cdp: 'http://crl.example.test/root.crl',
    pki_ext_policies: true,
    pki_policies: '1.3.6.1.4.1.99999.1.1|cps=https://x.test/cps',
    pki_ext_name_constraints: true, pki_nc_critical: true,
    pki_name_constraints: 'permit dns:example.test\nexclude ip:10.0.0.0/8',
    pki_ext_ns_comment: true, pki_ns_comment: 'from the pane',
    pki_ext_tls_feature: true, pki_tls_feature: '5',
    pki_custom_extensions: '1.3.6.1.4.1.99999.7.7|critical|DANDYWJj',
    pki_gen_csr: true
  });
  const issued = await authoring.issue(ISSUE, loaded);
  t.check(issued.ok, 'a certificate carrying every kind of extension issues',
          (issued.errors || []).join(' '));
  // **READ BACK BY OID AND NOT BY NAME.** `tests/pki.js` records the mutant
  // that survived a round because the assertion matched on an extension NAME
  // the encoder never writes; an OID is what is actually in the DER, so a
  // renamed table entry cannot make this pass or fail.
  const described = await x509.describeCertificate(
      issued.object.certificatePem);
  const byOid = {};
  (described.extensions || []).forEach(function (one) {
    byOid[one.oid] = one;
  });
  [['2.5.29.19', 'basicConstraints'], ['2.5.29.15', 'keyUsage'],
   ['2.5.29.17', 'subjectAltName'],
   ['1.3.6.1.5.5.7.1.1', 'authorityInfoAccess'],
   ['2.5.29.31', 'cRLDistributionPoints'], ['2.5.29.32', 'certificatePolicies'],
   ['2.5.29.30', 'nameConstraints'],
   ['2.16.840.1.113730.1.13', 'the Netscape comment'],
   ['1.3.6.1.5.5.7.1.24', 'the TLS feature'],
   ['1.3.6.1.4.1.99999.7.7', 'an extension this page has never heard of']
  ].forEach(function (pair) {
    t.check(!!byOid[pair[0]],
            'the certificate carries ' + pair[1] + ' (' + pair[0] + '), ' +
            'which means the box on the form reached the encoder');
  });
  const san = JSON.stringify((byOid['2.5.29.17'] || {}).value || []);
  t.check(/ca\.example\.test/.test(san) && /10\.0\.0\.1/.test(san),
          'both subjectAltName entries are in it, in the forms the grammar ' +
          'promised', san);
  const nc = JSON.stringify((byOid['2.5.29.30'] || {}).value || {});
  t.check(/10\.0\.0\.0/.test(nc) && /(255\.0\.0\.0|\/8)/.test(nc),
          'and the excluded name constraint carries its MASK, which is the ' +
          'encoding detail the prefix grammar exists for', nc);
  t.check(byOid['1.3.6.1.4.1.99999.7.7'].critical === true,
          'and the custom extension is CRITICAL because the line said so — ' +
          'the flag a validator must reject an unknown extension for is the ' +
          'one thing about it a form can get wrong invisibly');
  t.check(String(issued.object.csrPem).indexOf('CERTIFICATE REQUEST') >= 0,
          'the certification request was built beside it, from the SAME ' +
          'subject and key pair — a request assembled from a second reading ' +
          'of the form would differ in ways nobody could see');

  t.log.info('=== the serial moves, and that is not cosmetic ===');
  t.check(issued.draft.pki_serial !== loaded.pki_serial &&
          /^[0-9a-f]{32}$/.test(issued.draft.pki_serial),
          'the form comes back with a FRESH serial — one that stayed put ' +
          'would be re-used by the next certificate the same authority ' +
          'signs, and two certificates from one issuer sharing a serial are ' +
          'indistinguishable to anything that revokes, caches or pins by ' +
          '(issuer, serial)');

  t.log.info('=== the signature is constrained by the ISSUER\'s key ===');
  const mismatch = await authoring.issue(ISSUE, Object.assign({},
    authoring.applyProfile(authoring.defaultDraft(ISSUE), 'root-ca'),
    { pki_key_alg: 'ec-p256', pki_sig_alg: 'sha256-rsa' }));
  t.check(!mismatch.ok, 'an EC key asked to make an RSA signature is refused');
  t.check(/can produce/.test((mismatch.errors || []).join(' ')),
          'and the refusal LISTS what that key can produce — the page cannot ' +
          'narrow the menu without a script, so the sentence has to',
          (mismatch.errors || []).join(' '));

  t.log.info('=== the store, and the two buttons that must not touch each ' +
             'other ===');
  const first = await authoring.issue(STORE, Object.assign({},
    authoring.applyProfile(authoring.defaultDraft(STORE), 'root-ca'),
    { pki_key_alg: 'ec-p256', pki_dn_cn: 'Store Root' }));
  t.check(first.ok, 'a self-signed CA is issued into an empty realm',
          (first.errors || []).join(' '));
  t.equal(pki.objects(STORE).length, 1, 'and the store holds it');
  t.check(pki.issuers(STORE).some(function (one) {
            return one.id === first.object.id;
          }),
          'it is offered as an ISSUER, because it is a CA whose private key ' +
          'is here — offering one that cannot sign produces a Web Crypto ' +
          'error two clicks later naming neither the authority nor the key');

  const leaf = await authoring.issue(STORE, Object.assign({},
    authoring.applyProfile(authoring.defaultDraft(STORE), 'tls-server'),
    { pki_key_alg: 'ec-p256', pki_dn_cn: 'leaf.example.test',
      pki_issuer: first.object.id }));
  t.check(leaf.ok, 'and a leaf is issued from it',
          (leaf.errors || []).join(' '));
  t.equal(authoring.chainFor(STORE,
                             pki.objectFor(STORE, leaf.object.id)).length,
          1, 'the chain above that leaf is its issuer and nothing else');

  // BUILDING THE HIERARCHY MUST NOT EMPTY THE STORE, and clearing it must not
  // either. They are two things in one keystore row, and one button meaning
  // both would be the worst kind of surprise on a page that holds key
  // material.
  const built = await pki.buildChain(STORE, { organisation: 'Acme' });
  t.check(built.ok, 'the three-tier hierarchy is built in the same realm',
          (built.errors || []).join(' '));
  t.equal(pki.objects(STORE).length, 2,
          'and the objects the pane issued are STILL THERE — a button ' +
          'labelled "build the certificate authority" has no business ' +
          'discarding somebody\'s key pairs');
  t.equal(pki.issuers(STORE).length, 4,
          'the issuer list is now the three tiers plus the CA this pane ' +
          'issued — FOUR and not five, because the leaf beside it is not a ' +
          'certificate authority and offering it would produce an encoder ' +
          'error two clicks later naming neither');

  pki.clearChain(STORE);
  t.check(!pki.hasChain(STORE), 'removing the hierarchy removes the tiers');
  t.equal(pki.objects(STORE).length, 2,
          'and LEAVES the objects, which is the same rule read the other way');

  const cleared = pki.clearObjects(STORE);
  t.check(cleared.ok && cleared.removed === 2,
          'clearing the store removes them and says how many');
  t.check(!pki.objects(STORE).length && !pki.hasChain(STORE),
          'and with neither left the realm holds nothing at all');

  t.log.info('=== what is stored against what is handed out ===');
  const view = authoring.view(ISSUE, authoring.defaultDraft(ISSUE));
  t.check(JSON.stringify(view.objects).indexOf('PRIVATE KEY') < 0,
          'no PRIVATE KEY block appears anywhere in the reported store — ' +
          'this is the assertion that would otherwise be an absence nobody ' +
          'could see');
  t.check(view.objects.every(function (one) {
            return String(one.certificatePem).indexOf('BEGIN CERTIFICATE') >= 0;
          }),
          'and every certificate is there in full, because a certificate is ' +
          'the half of a key pair meant to be handed around');
  t.check(view.objects[0].hasPrivateKey === true,
          'the report SAYS whether the key is held rather than showing it, ' +
          'which is what the store table needs to know to offer the Use and ' +
          'Export buttons');

  t.log.info('=== "keep the private key" is the one field that means ' +
             'something different from the page this is modelled on ===');
  const discarded = await authoring.issue(EXPORT, Object.assign({},
    authoring.applyProfile(authoring.defaultDraft(EXPORT), 'root-ca'),
    { pki_key_alg: 'ec-p256', pki_dn_cn: 'No Key Kept',
      pki_save_keys: false }));
  t.check(discarded.ok, 'a certificate issues with the box cleared',
          (discarded.errors || []).join(' '));
  t.check(!pki.objectFor(EXPORT, discarded.object.id).privateKeyPem,
          'and its private key is NOT in the store — on the debugger\'s page ' +
          'that box keeps the key out of localStorage; here there is no ' +
          'browser store, so it keeps it out of this realm\'s keystore row');
  t.check(!pki.issuers(EXPORT).some(function (one) {
            return one.id === discarded.object.id;
          }),
          'so it is not offered as an issuer either, which is the ' +
          'consequence rather than a second rule');
  t.check(/NOT KEPT/.test(discarded.why),
          'and the reply says so, because a CA that cannot sign is not ' +
          'something to discover later',
          discarded.why);

  t.log.info('=== the export matrix is the one every other key here goes ' +
             'through ===');
  const kept = await authoring.issue(EXPORT, Object.assign({},
    authoring.applyProfile(authoring.defaultDraft(EXPORT), 'root-ca'),
    { pki_key_alg: 'ec-p256', pki_dn_cn: 'Exportable' }));
  t.check(kept.ok, 'a certificate to export', (kept.errors || []).join(' '));
  const base = authoring.defaultDraft(EXPORT);

  const pem = await authoring.exportKeys(EXPORT,
    Object.assign({}, base, { pki_ks_format: 'pem' }), kept.object.id);
  t.check(pem.ok && String(pem.files[0].data).indexOf('BEGIN CERTIFICATE') >= 0,
          'PEM carries the key pair AND the certificate in one file',
          (pem.errors || []).join(' '));

  const p12 = await authoring.exportKeys(EXPORT,
    Object.assign({}, base, { pki_ks_format: 'pkcs12',
                              pki_ks_password: 'changeit' }),
    kept.object.id);
  t.check(p12.ok && p12.files[0].name.slice(-4) === '.p12',
          'PKCS#12 produces a .p12', (p12.errors || []).join(' '));

  const nopass = await authoring.exportKeys(EXPORT,
    Object.assign({}, base, { pki_ks_format: 'pkcs12' }), kept.object.id);
  t.check(!nopass.ok && /password/i.test((nopass.errors || []).join(' ')),
          'and PKCS#12 without a password is refused BY THE EXPORT MODULE ' +
          'rather than by this page — the refusal is the one /admin/keys ' +
          'already gives, because it is the same function');

  const nothing = await authoring.exportKeys(EXPORT, base, '');
  t.check(!nothing.ok,
          'exporting with no object selected and no key pair in the boxes is ' +
          'refused rather than producing an empty file');

  const missingOne = await authoring.exportKeys(EXPORT, base, 'leaf-nope');
  t.check(!missingOne.ok && /no object/i.test(missingOne.errors.join(' ')),
          'and naming an object that is not there is refused by name');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_authoring',
  describe: 'The Certificate & Key Configuration pane: the form against the ' +
            'page that draws it, the six line grammars and what each ' +
            'refuses, the three subject rules a profile change must and must ' +
            'not break, the approach filters, every extension reaching the ' +
            'encoder, the store against the hierarchy, and what is handed out',
  run: run
};
