'use strict';
//
// File: identity_assurance.js
//
// ===========================================================================
// OPENID CONNECT FOR IDENTITY ASSURANCE 1.0 (#127, 2026-09-23). rcbj's
// answers: an administrator records a verification (console and API), and a
// wallet or certificate sign-in records one of its own; development invents
// one under `urn:sts:demo` for a person with none, and product releases
// recorded ones only; all four evidence types; `value`/`values` enforced on
// the verification and nowhere else; aggregated and distributed claims left
// to #147.
//
// Held here, in process, against the real directory:
//
//   1. section 6's request rules, and the claims request carrying the
//      element through `oauth2.parseClaimsRequest()`;
//   2. recording: each evidence type checked, the refusals, the values taken
//      from the entry;
//   3. the answer: a framework asked for by value, evidence filtered by type,
//      only the members asked for, `max_age` on `time`;
//   4. a verified value the entry no longer holds is not released;
//   5. development's invented verification, and product's none;
//   6. the automatic sources: a certificate's subject, a wallet's
//      disclosures, each replacing its predecessor;
//   7. `oauth2.requestedClaimsOf()` putting `verified_claims` in the answer,
//      and discovery's section 7 members;
//   8. the Identity verifications block on a person's console page.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const ldap = require('../ldap/ldap_server');
const ida = require('../common/identity_assurance');
const oauth2 = require('../oauth-oidc/oauth2');

const log = require('bunyan').createLogger({ name: 'identity_assurance',
  level: process.env.LOG_LEVEL || 'info' });

const PASSPORT = {
  trust_framework: 'urn:sts:local',
  assurance_level: 'substantial',
  evidence: [{ type: 'document',
    check_details: [{ check_method: 'vpip' }],
    document_details: { type: 'passport', document_number: 'X1234567',
      issuer: { name: 'Passport Office', country_code: 'GBR' },
      date_of_issuance: '2020-01-02', date_of_expiry: '2030-01-01' } }]
};

function run(t) {
  log.debug("Entering run().");
  config.setOverride('oauth2.idaTrustFrameworks', 'urn:sts:local,eidas');
  try {
    body(t);
  } finally {
    config.clearOverride('oauth2.idaTrustFrameworks');
    config.clearOverride('global.mode');
  }
  log.debug("Leaving run().");
}

function body(t) {
  log.debug("Entering body().");
  t.log.info('=== 1. section 6\'s request rules ===');
  const ok = ida.parseRequest({ verification: { trust_framework: null },
                                claims: { given_name: null } }, 'userinfo');
  t.check(ok.elements && ok.elements.length === 1,
          '1a. one object is one element', JSON.stringify(ok));
  t.check(/verification is required/.test(ida.parseRequest(
    { claims: { given_name: null } }, 'userinfo').error || ''),
          '1b. no verification is refused');
  t.check(/trust_framework is required/.test(ida.parseRequest(
    { verification: {}, claims: { given_name: null } }, 'userinfo').error ||
    ''), '1c. no trust_framework member is refused');
  t.check(/may not be empty/.test(ida.parseRequest(
    { verification: { trust_framework: null }, claims: {} }, 'id_token')
    .error || ''), '1d. empty claims are refused');
  t.check(/purpose/.test(ida.parseRequest(
    { verification: { trust_framework: null },
      claims: { given_name: { purpose: 'ab' } } }, 'userinfo').error || '') &&
    /purpose/.test(ida.parseRequest(
    { verification: { trust_framework: { purpose: 'x'.repeat(301) } },
      claims: { given_name: null } }, 'userinfo').error || ''),
          '1e. a purpose under 3 or over 300 characters is refused');
  t.check(/max_age/.test(ida.parseRequest(
    { verification: { trust_framework: null, time: { max_age: -1 } },
      claims: { given_name: null } }, 'userinfo').error || ''),
          '1f. a negative max_age is refused');
  const parsed = oauth2.parseClaimsRequest(JSON.stringify({
    userinfo: { email: null, verified_claims: [
      { verification: { trust_framework: null },
        claims: { given_name: null } }] } }));
  t.check(!parsed.error && Array.isArray(parsed.claims.userinfo
                                           .verified_claims) &&
          parsed.claims.userinfo.email === null,
          '1g. the claims request carries verified_claims beside ordinary ' +
          'claims', JSON.stringify(parsed));
  const again = oauth2.parseClaimsRequest(parsed.claims);
  t.check(!again.error && again.claims.userinfo.verified_claims.length === 1,
          '1h. and the parsed form parses again (the token carries it)');
  t.check(/verification is required/.test(oauth2.parseClaimsRequest(
    { id_token: { verified_claims: { claims: { name: null } } } }).error ||
    ''), '1i. a malformed element refuses the whole claims request');

  t.log.info('=== 2. recording ===');
  const made = ldap.createUser('ida-alice', { invent: false,
    attributes: { givenName: 'Alice', sn: 'Liddell' } });
  t.check(made.ok, '2a. a person with a given name and surname',
          JSON.stringify(made.errors || ''));
  const kept = ida.record('ida-alice', { verification: PASSPORT,
    claims: ['given_name', 'family_name'] }, 'tester');
  t.check(kept.ok && kept.record.claims.given_name === 'Alice' &&
          kept.record.claims.family_name === 'Liddell' &&
          /^\d{4}-\d{2}-\d{2}T/.test(kept.record.verification.time),
          '2b. recorded, with the values the entry holds and time defaulted',
          JSON.stringify(kept));
  const refused = function (verification, claims) {
    return ida.record('ida-alice', { verification: verification,
                                     claims: claims || ['given_name'] },
                      'tester');
  };
  t.check(/not one this service is configured for/.test(refused(
    { trust_framework: 'de_aml' }).error || ''),
          '2c. an unconfigured framework is refused');
  t.check(/not one this service/.test(refused(
    { trust_framework: 'urn:sts:demo' }).error || ''),
          '2d. urn:sts:demo can never be recorded');
  t.check(/document_details.type/.test(refused({
    trust_framework: 'eidas',
    evidence: [{ type: 'document', document_details: { type: 'library' } }]
  }).error || ''), '2e. a document type outside the vocabulary is refused');
  t.check(/serial_number is required/.test(refused({
    trust_framework: 'eidas',
    evidence: [{ type: 'electronic_signature', signature_type: 'qes',
                 issuer: 'CN=CA' }] }).error || ''),
          '2f. an electronic_signature without its serial is refused');
  t.check(/attestation is required/.test(refused({
    trust_framework: 'eidas', evidence: [{ type: 'vouch' }] }).error || ''),
          '2g. a vouch without its attestation is refused');
  t.check(/check_method/.test(refused({
    trust_framework: 'eidas',
    evidence: [{ type: 'electronic_record', record: { type: 'tax' },
                 check_details: [{ check_method: 'guess' }] }] }).error ||
    ''), '2h. an unknown check method is refused');
  t.check(/not a claim a verification covers/.test(refused(
    { trust_framework: 'eidas' }, ['picture']).error || ''),
          '2i. a claim nobody verifies is refused');
  t.check(/holds no value for birth_family_name/.test(refused(
    { trust_framework: 'eidas' }, ['birth_family_name']).error || ''),
          '2j. a claim the entry holds nothing for is refused');
  const vouched = ida.record('ida-alice', { verification: {
    trust_framework: 'eidas', time: '2020-01-01T00:00:00Z',
    evidence: [{ type: 'vouch', attestation: {
      type: 'written_attestation', voucher: { name: 'Bob' } } }] },
    claims: ['given_name'] }, 'tester');
  t.check(vouched.ok && ida.list('ida-alice').length === 2 &&
          ida.list('ida-alice')[0].id === vouched.record.id,
          '2k. a second record, newest first');
  const form = ida.fromForm({ trust_framework: 'eidas',
    evidence_type: 'electronic_signature', signature_type: 'qes',
    signature_issuer: 'CN=Issuer', serial_number: '0A', claim_given_name: 'on',
    claim_family_name: 'on', document_type: 'passport' });
  t.check(form.verification.evidence[0].issuer === 'CN=Issuer' &&
          !form.verification.evidence[0].document_details &&
          form.claims.join() === 'given_name,family_name',
          '2l. the console\'s flat fields become the element, one ' +
          'checkbox per claim', JSON.stringify(form));

  t.log.info('=== 3. the answer ===');
  const answer = function (element) {
    return ida.respond('ida-alice', [element], false).value;
  };
  const any = answer({ verification: { trust_framework: null },
                       claims: { given_name: null, email: null } });
  t.check(any && any.verification.trust_framework === 'eidas' &&
          any.claims.given_name === 'Alice' && !('email' in any.claims) &&
          Object.keys(any.verification).join() === 'trust_framework',
          '3a. the newest satisfying record, only the members asked for, ' +
          'and no claim it did not cover', JSON.stringify(any));
  const local = answer({ verification: {
    trust_framework: { value: 'urn:sts:local' },
    evidence: [{ type: { value: 'document' },
                 document_details: { type: null } }] },
    claims: { given_name: null, family_name: null } });
  t.check(local && local.verification.trust_framework === 'urn:sts:local' &&
          local.verification.evidence.length === 1 &&
          local.verification.evidence[0].type === 'document' &&
          local.verification.evidence[0].document_details.type ===
            'passport' &&
          local.verification.evidence[0].document_details.document_number ===
            undefined &&
          local.claims.family_name === 'Liddell',
          '3b. value on trust_framework and evidence type choose the ' +
          'passport; only document_details.type is returned',
          JSON.stringify(local));
  t.check(answer({ verification: { trust_framework: { value: 'de_aml' } },
                   claims: { given_name: null } }) === undefined,
          '3c. a framework no record is under: verified_claims is omitted');
  t.check(answer({ verification: { trust_framework: null,
                     evidence: [{ type: { value: 'electronic_record' } }] },
                   claims: { given_name: null } }) === undefined,
          '3d. an evidence type no record carries: omitted');
  const fresh = answer({ verification: { trust_framework: null,
                           time: { max_age: 3600 } },
                         claims: { given_name: null } });
  t.check(fresh && fresh.verification.trust_framework === 'urn:sts:local' &&
          /^\d{4}-/.test(fresh.verification.time),
          '3e. max_age passes over the 2020 vouch to the recent passport',
          JSON.stringify(fresh));
  const both = ida.respond('ida-alice', [
    { verification: { trust_framework: { value: 'eidas' } },
      claims: { given_name: null } },
    { verification: { trust_framework: { value: 'urn:sts:local' } },
      claims: { family_name: null } }], false).value;
  t.check(Array.isArray(both) && both.length === 2,
          '3f. two elements asked, an array of two answered');

  // #187, section 5.7.4: `value`/`values` on a claim INSIDE verified_claims
  // are enforced — a claim that does not fulfil them is omitted, and an
  // element left with none is omitted whole.
  const unmetValue = answer({ verification: { trust_framework: null },
    claims: { given_name: { value: 'Somebody Else' }, family_name: null } });
  t.check(unmetValue && !('given_name' in unmetValue.claims) &&
          unmetValue.claims.family_name === 'Liddell',
          '3g. a claim whose value does not match is omitted (5.7.4); the ' +
          'rest of the element stands', JSON.stringify(unmetValue));
  t.check(answer({ verification: { trust_framework: null },
    claims: { given_name: { values: ['Bob', 'Carol'] } } }) === undefined,
          '3h. and an element left with no claim is omitted whole');
  const metValue = answer({ verification: { trust_framework: null },
    claims: { given_name: { value: 'Alice' } } });
  t.check(metValue && metValue.claims.given_name === 'Alice',
          '3i. a matching value is released', JSON.stringify(metValue));

  t.log.info('=== 4. a value the entry no longer holds ===');
  const entry = ldap.existingUserEntry('ida-alice');
  entry.attributes.givenname = ['Alicia'];
  const stale = answer({ verification: { trust_framework: null },
                         claims: { given_name: null, family_name: null } });
  t.check(stale && !('given_name' in stale.claims) &&
          stale.claims.family_name === 'Liddell',
          '4a. the changed given name is not released as verified; the ' +
          'unchanged surname is', JSON.stringify(stale));
  entry.attributes.givenname = ['Alice'];

  t.log.info('=== 5. development invents, product does not ===');
  ldap.createUser('ida-nobody', { invent: false,
    attributes: { givenName: 'Nobody' } });
  const demo = ida.respond('ida-nobody',
    [{ verification: { trust_framework: null },
       claims: { given_name: null } }], false).value;
  t.check(demo && demo.verification.trust_framework === 'urn:sts:demo' &&
          demo.claims.given_name === 'Nobody',
          '5a. development: an invented verification under urn:sts:demo',
          JSON.stringify(demo));
  t.check(ida.respond('ida-nobody',
    [{ verification: { trust_framework: { value: 'eidas' } },
       claims: { given_name: null } }], false).value === undefined,
          '5b. which a request naming a real framework never matches');
  config.setOverride('global.mode', 'product');
  t.check(ida.respond('ida-nobody',
    [{ verification: { trust_framework: null },
       claims: { given_name: null } }], false).value === undefined &&
          ida.discoveryMetadata().trust_frameworks_supported
            .indexOf('urn:sts:demo') < 0,
          '5c. product: nothing, and urn:sts:demo is not published');
  config.clearOverride('global.mode');

  t.log.info('=== 6. the automatic sources ===');
  const cert = ida.recordAutomatic('ida-alice', 'certificate',
    { claims: { name: 'Somebody Else', given_name: 'Alice' },
      issuer: 'CN=Realm Intermediate', serial: '01AB',
      notBefore: '2026-09-01T00:00:00Z' });
  t.check(cert.ok && cert.record.claims.given_name === 'Alice' &&
          !('name' in cert.record.claims) &&
          cert.record.verification.trust_framework === 'urn:sts:local' &&
          cert.record.verification.evidence[0].type ===
            'electronic_signature' &&
          cert.record.verification.evidence[0].serial_number === '01AB',
          '6a. a certificate records only what the entry agrees with, as ' +
          'an electronic_signature under the first framework',
          JSON.stringify(cert));
  ida.recordAutomatic('ida-alice', 'certificate',
    { claims: { given_name: 'Alice' }, issuer: 'CN=X', serial: '02' });
  t.check(ida.list('ida-alice').filter(function (one) {
    return one.source === 'certificate';
  }).length === 1, '6b. the next one replaces it');
  const wallet = ida.recordAutomatic('ida-alice', 'wallet',
    { claims: { family_name: 'Liddell' }, format: 'dc+sd-jwt' });
  t.check(wallet.ok && wallet.record.verification.evidence[0].type ===
            'electronic_record' &&
          wallet.record.verification.evidence[0].check_details[0]
            .check_method === 'vcrypt',
          '6c. a wallet records an electronic_record checked vcrypt');
  t.check(!ida.recordAutomatic('ida-alice', 'wallet',
    { claims: { family_name: 'Other' } }).ok,
          '6d. nothing the entry agrees with records nothing');
  config.setOverride('oauth2.idaAutomaticVerifications', false);
  t.check(/off/.test(ida.recordAutomatic('ida-alice', 'wallet',
    { claims: { family_name: 'Liddell' } }).skipped || ''),
          '6e. and the setting switches both off');
  config.clearOverride('oauth2.idaAutomaticVerifications');
  const all = ida.list('ida-alice');
  t.check(ida.remove('ida-alice', all[0].id).ok &&
          ida.list('ida-alice').length === all.length - 1 &&
          !ida.remove('ida-alice', 'no-such-id').ok,
          '6f. a record is removed by id, an unknown id refused');

  t.log.info('=== 7. the claims request and discovery ===');
  const request = oauth2.parseClaimsRequest({ userinfo: {
    family_name: null,
    verified_claims: { verification: { trust_framework: null },
                       claims: { family_name: null } } } }).claims;
  const asked = oauth2.requestedClaimsOf(request, 'userinfo', 'ida-alice',
                                         null);
  t.check(asked.claims.family_name === 'Liddell' &&
          asked.claims.verified_claims &&
          asked.claims.verified_claims.claims.family_name === 'Liddell' &&
          asked.unknown.indexOf('verified_claims') < 0,
          '7a. requestedClaimsOf() answers verified_claims beside the ' +
          'ordinary claim, and does not report it unknown',
          JSON.stringify(asked.claims));
  const meta = ida.discoveryMetadata();
  t.check(meta.verified_claims_supported === true &&
          meta.trust_frameworks_supported.join() ===
            'urn:sts:local,eidas,urn:sts:demo' &&
          meta.evidence_supported.length === 4 &&
          meta.documents_supported.indexOf('passport') >= 0 &&
          meta.claims_in_verified_claims_supported.indexOf('nationalities') >=
            0,
          '7b. discovery: the frameworks (demo in development), four ' +
          'evidence types, the vocabularies', JSON.stringify(meta));

  t.log.info('=== 8. the console block ===');
  const admin = require('../admin-ui/admin');
  const consolePage = new admin.AdminConsole(admin.AdminConsole.defaultDeps());
  const drawn = consolePage.mfaSection({ name: 'ida-alice' }, 'ida-alice',
    { write: true }, '').html;
  t.check(/<h3>Identity verifications<\/h3>/.test(drawn) &&
          /name="action" value="record-verification"/.test(drawn) &&
          /name="action" value="remove-verification"/.test(drawn) &&
          /name="claim_given_name"/.test(drawn) &&
          /<option value="eidas">/.test(drawn),
          '8a. a person\'s page lists their verifications with a Remove ' +
          'each, and a form that records one');
  const readOnly = consolePage.mfaSection({ name: 'ida-alice' }, 'ida-alice',
    { write: false }, '').html;
  t.check(!/value="record-verification"/.test(readOnly) &&
          /needs <strong>Admin Write<\/strong>/.test(readOnly),
          '8b. and without Admin Write, no form');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'identity assurance',
  describe: 'OpenID Connect for Identity Assurance 1.0 (#127): recording ' +
            'verifications, section 6\'s request rules and filters, the ' +
            'automatic sources, development\'s demo and product\'s none',
  run: run
};
