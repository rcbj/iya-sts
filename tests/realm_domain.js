'use strict';
//
// File: realm_domain.js
//
// ===========================================================================
// A TRUST REALM'S DNS DOMAIN (2026-09-18).
//
// A realm carries a domain beside its id, name and description — iyasec.io,
// dev.iyasec.io, craptastic.net — and it is the root of every NAME the realm
// invents: its directory is a tree of its own at the RFC 2247 mapping of it,
// and its Kerberos realm, SPIFFE trust domain, entity IDs and invented mail
// addresses are built from it when the realm is created. rcbj's three
// decisions are what this file holds:
//
//   A. the domain's shape, and its normalisation;
//   B. a realm with none is `<id>.<global.domain>` — the tree every realm had
//      before domains existed — and one with its own is rooted there;
//   C. the names seeded from it, URNs for the entity IDs;
//   D. no two realms share a domain (the default realm's included), and ONE
//      INSIDE ANOTHER'S IS ALLOWED;
//   E. it is FIXED once the realm exists;
//   F. the directory: each realm a naming context of its own, a nested realm
//      a separate tree whose entries a search from the parent cannot see, and
//      a DN in no realm's tree refused;
//   G. the invented mail address is in the ambient realm's domain.
//
// WHY IN PROCESS: every refusal here is the realm REGISTRY's, one door below
// `/admin-api/realms`, and the directory half is driven through
// `performOperation()` — the socket's own handlers without the socket —
// which is `crl_directory_publication.js`'s arrangement.
// `tests/vendored/sts_admin_api_operations.js` and `sts_admin_console.js`
// carry the same claims over HTTP and on the console's form.
//
// Every realm this file makes is removed again.
//
// Mutation-tested against six through a require hook, all caught: the
// uniqueness check removed (2 red), the fixed-at-creation check removed (1),
// `inNamingContext()` reading only the default realm's base (3), the second
// `function inRealmOf` put back in ldap_server.js (4), `realmFor()` taking the
// FIRST containing base rather than the deepest (2), and an omitted domain not
// built from global.domain (3).
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const ldap = require('../ldap/ldap_server');

const log = require('bunyan').createLogger({ name: 'realm_domain',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const PLAIN = 'rd-plain-' + STAMP;
const OWN = 'rd-own-' + STAMP;
const PARENT = 'rd-parent-' + STAMP;
const CHILD = 'rd-child-' + STAMP;
const OWN_DOMAIN = 'craptastic-' + STAMP + '.net';
const PARENT_DOMAIN = 'iyasec-' + STAMP + '.test';
const CHILD_DOMAIN = 'dev.' + PARENT_DOMAIN;

function search(base, scope, filter) {
  log.debug("Entering search().");
  log.debug("Leaving search().");
  return ldap.performOperation('search', {
    dn: base, boundDn: '', channel: 'ldap', scope: scope,
    filter: filter || '(objectclass=*)', attributes: [], sizeLimit: 0 });
}

// The base the DIRECTORY answers for a realm — `ldap.baseDn()` with the realm
// ambient, which is what every DN the directory writes is built from.
function ldapBaseOf(id) {
  log.debug("Entering ldapBaseOf(). id=" + id);
  const realm = id === realms.DEFAULT_ID ? realms.DEFAULT_REALM
                                          : realms.get(id);
  log.debug("Leaving ldapBaseOf().");
  return realms.run(realm, function () {
    return ldap.baseDn();
  });
}

function namingContexts() {
  log.debug("Entering namingContexts().");
  const dse = search('', 0);
  // `performOperation()` hands attributes back as `{ type, values }` rows.
  const entry = (dse.entries || [])[0] || { attributes: [] };
  const row = [].concat(entry.attributes || []).filter(function (one) {
    return String(one.type).toLowerCase() === 'namingcontexts';
  })[0];
  const values = row ? [].concat(row.values) : [];
  log.debug("Leaving namingContexts(). " + values.length);
  return values.map(function (one) {
    return String(one).toLowerCase();
  });
}

function create(t, spec, what) {
  log.debug("Entering create(). id=" + spec.id);
  const made = realms.create(Object.assign({ name: spec.id,
    description: 'Created by ' + __filename }, spec));
  t.check(made.ok, what, (made.errors || []).join(' '));
  log.debug("Leaving create().");
  return made.ok ? made.realm : null;
}

function theShape(t) {
  log.debug("Entering theShape().");
  t.log.info('=== A. what a domain is ===');
  const refusedAs = function (domain) {
    return errorCodes.codeOf(realms.create({ id: 'rd-shape-' + STAMP,
                                             domain: domain }));
  };
  t.equal(refusedAs('localhost'), 'STS-CORE-0099',
          'a single label is not a realm\'s domain — a DN of one dc= and a ' +
          'Kerberos realm of one word are what nothing expects');
  t.equal(refusedAs('example.123'), 'STS-CORE-0099',
          'nor is a name whose top-level label is all digits (an address)');
  t.equal(refusedAs('bad_label.example'), 'STS-CORE-0099',
          'nor one with a character a DNS label may not hold');
  t.equal(refusedAs('-lead.example'), 'STS-CORE-0099',
          'nor a label that begins with a hyphen');
  t.equal(refusedAs(new Array(65).join('a') + '.example'), 'STS-CORE-0099',
          'nor a label longer than 63 characters');
  t.check(!realms.get('rd-shape-' + STAMP),
          'and a refused domain leaves no realm behind');
  t.equal(realms.normalizeDomain('  Mixed.Example.COM. '),
          'mixed.example.com',
          'a domain is lower-cased, trimmed and loses a trailing dot');
  t.equal(realms.normalizeDomain('bücher.example'), 'xn--bcher-kva.example',
          'an internationalised domain is kept in its ASCII (A-label) form, ' +
          'the only one a DN, a principal or a SPIFFE ID can carry');
  t.equal(realms.baseDnOfDomain('iyasec.io'), 'dc=iyasec,dc=io',
          'the base DN is RFC 2247\'s mapping, one dc= per label in order');
  log.debug("Leaving theShape().");
}

function theDefaultAndTheOwn(t) {
  log.debug("Entering theDefaultAndTheOwn().");
  t.log.info('=== B, C. a realm\'s domain, and what is seeded from it ===');
  const home = realms.domainOf(realms.DEFAULT_ID);
  t.check(!!home, 'the default realm has a domain — global.domain', home);

  const plain = create(t, { id: PLAIN },
                       'a realm is created with no domain given');
  if (plain) {
    t.equal(plain.domain, PLAIN + '.' + home,
            'and is given <id>.<global.domain>');
    t.equal(realms.baseDnOf(PLAIN),
            'dc=' + PLAIN + ',' + realms.baseDnOf(realms.DEFAULT_ID),
            'which is exactly the dc=<id> beneath the default realm\'s base ' +
            'every realm had before domains existed');
    t.equal(ldapBaseOf(PLAIN), realms.baseDnOf(PLAIN),
            'and the directory roots the realm there');
  }

  const own = create(t, { id: OWN, domain: OWN_DOMAIN.toUpperCase() },
                     'a realm is created with a domain of its own');
  if (own) {
    t.equal(own.domain, OWN_DOMAIN, 'kept normalised, in lower case');
    t.equal(ldapBaseOf(OWN), 'dc=' + OWN_DOMAIN.split('.')[0] + ',dc=net',
            'its directory is a TREE OF ITS OWN, not a branch of the default ' +
            'realm\'s');
    const seeded = own.overrides;
    t.equal(seeded['saml2.entityId'], 'urn:' + OWN_DOMAIN + ':idp',
            'the SAML 2.0 entityID is a URN built from the domain');
    t.equal(seeded['saml11.providerId'], 'urn:' + OWN_DOMAIN + ':idp:saml11',
            'and so is the SAML 1.1 providerID');
    t.check(['wsfed.entityId', 'wstrust.issuer', 'saml.issuer']
              .every(function (key) {
                return seeded[key] === 'urn:' + OWN_DOMAIN + ':sts';
              }),
            'the three that share a name by default share urn:<domain>:sts',
            JSON.stringify([seeded['wsfed.entityId'],
                            seeded['wstrust.issuer'], seeded['saml.issuer']]));
    t.equal(seeded['spiffe.trustDomain'], OWN_DOMAIN,
            'the SPIFFE trust domain IS the domain');
    t.equal(seeded['krb5.realm'], OWN_DOMAIN.toUpperCase(),
            'the Kerberos realm is the domain in capitals');
    t.check(!('krb5.servicePrincipal' in seeded),
            'the Kerberos service principal is NOT seeded — its host is an ' +
            'address, and the KDC derives HTTP/web.<domain> from the realm\'s ' +
            'Kerberos domain itself');
    t.equal(String(seeded['krb5.enabled']), 'false',
            'and Kerberos is still created OFF — naming the realm is not ' +
            'turning on a KDC');
    t.check(String(seeded['oid4vp.clientId'] || '').slice(-(OWN.length + 1)) ===
              '-' + OWN,
            'the OpenID4VP client id is a client id, not a name in a domain, ' +
            'and keeps the id suffix it always had',
            String(seeded['oid4vp.clientId']));
  }

  const chosen = create(t, { id: 'rd-chosen-' + STAMP,
                             domain: 'chosen-' + STAMP + '.test',
                             overrides: { 'saml2.entityId': 'urn:x:mine' } },
                        'a realm is created with an entityID of the caller\'s');
  if (chosen) {
    t.equal(chosen.overrides['saml2.entityId'], 'urn:x:mine',
            'and the caller\'s wins over the one seeded from the domain');
    realms.remove(chosen.id);
  }
  log.debug("Leaving theDefaultAndTheOwn().");
}

function uniquenessAndNesting(t) {
  log.debug("Entering uniquenessAndNesting().");
  t.log.info('=== D. unique, and nesting allowed ===');
  const twin = realms.create({ id: 'rd-twin-' + STAMP, domain: OWN_DOMAIN });
  t.equal(errorCodes.codeOf(twin), 'STS-CORE-0100',
          'a second realm may not take a domain another realm has',
          JSON.stringify(twin.errors || []));
  const asDefault = realms.create({ id: 'rd-home-' + STAMP,
    domain: realms.domainOf(realms.DEFAULT_ID) });
  t.equal(errorCodes.codeOf(asDefault), 'STS-CORE-0100',
          'nor the DEFAULT realm\'s, which is global.domain');
  t.check(!realms.get('rd-twin-' + STAMP) && !realms.get('rd-home-' + STAMP),
          'and neither refusal left a realm behind');
  create(t, { id: PARENT, domain: PARENT_DOMAIN },
         'a realm is created for ' + PARENT_DOMAIN);
  create(t, { id: CHILD, domain: CHILD_DOMAIN },
         'AND ONE INSIDE IT, ' + CHILD_DOMAIN + ' — a domain inside another ' +
         'realm\'s is allowed, Active Directory\'s child domain');
  log.debug("Leaving uniquenessAndNesting().");
}

function fixedOnceCreated(t) {
  log.debug("Entering fixedOnceCreated().");
  t.log.info('=== E. fixed once the realm exists ===');
  const moved = realms.update(OWN, { domain: 'moved.' + OWN_DOMAIN });
  t.equal(errorCodes.codeOf(moved), 'STS-CORE-0101',
          'an update may not change the domain — it is in every DN the ' +
          'realm holds', JSON.stringify(moved.errors || []));
  t.equal(realms.domainOf(OWN), OWN_DOMAIN, 'and the domain is unchanged');
  const same = realms.update(OWN, { domain: OWN_DOMAIN.toUpperCase(),
                                    description: 'same domain' });
  t.check(same.ok, 'the same domain again is not a change, and the rest of ' +
          'the update goes through', (same.errors || []).join(' '));
  log.debug("Leaving fixedOnceCreated().");
}

function theDirectory(t) {
  log.debug("Entering theDirectory().");
  t.log.info('=== F. a tree per realm on the one socket ===');
  const contexts = namingContexts();
  [realms.DEFAULT_ID, OWN, PARENT, CHILD].forEach(function (id) {
    t.check(contexts.indexOf(ldapBaseOf(id).toLowerCase()) >= 0,
            'the root DSE publishes ' + ldapBaseOf(id) +
            ' as a naming context', JSON.stringify(contexts));
  });

  const ownUsers = search('ou=users,' + ldapBaseOf(OWN), 0);
  t.check(ownUsers.ok && ownUsers.entries.length === 1,
          'a realm rooted OUTSIDE the default realm\'s tree is reachable on ' +
          'the socket — its ou=users answers a base search',
          JSON.stringify({ ok: ownUsers.ok, errorName: ownUsers.errorName }));

  // And a realm with NO domain of its own, beneath the default realm's base —
  // the layout every realm had before domains. It is here because a second
  // `function inRealmOf` in ldap_server.js (#74) replaced the socket's for a
  // day, and every LDAP operation on ANY realm's DN answered from the default
  // realm's store: this base search answered noSuchObject.
  const plainUsers = search('ou=users,' + ldapBaseOf(PLAIN), 0);
  t.check(plainUsers.ok && plainUsers.entries.length === 1,
          'a realm beneath the default realm\'s base is answered from its OWN ' +
          'store, not the default realm\'s',
          JSON.stringify({ ok: plainUsers.ok,
                           errorName: plainUsers.errorName }));

  const nowhere = search('dc=nobody-' + STAMP + ',dc=invalid', 0);
  t.check(!nowhere.ok && nowhere.errorName === 'NoSuchObjectError',
          'a DN in no realm\'s tree is refused as outside every naming ' +
          'context', JSON.stringify({ ok: nowhere.ok,
                                      errorName: nowhere.errorName }));

  const parentBase = ldapBaseOf(PARENT).toLowerCase();
  const childBase = ldapBaseOf(CHILD).toLowerCase();
  t.equal(childBase, 'dc=dev,' + parentBase,
          'the child realm\'s base nests inside the parent\'s by name');
  const fromParent = search(parentBase, 2);
  const leaked = (fromParent.entries || []).filter(function (entry) {
    const dn = entry.objectName.toLowerCase().replace(/\s*,\s*/g, ',');
    return dn === childBase || dn.slice(-(childBase.length + 1)) ===
           ',' + childBase;
  });
  t.check(fromParent.ok && fromParent.entries.length > 0 &&
          leaked.length === 0,
          'A SUBTREE SEARCH FROM THE PARENT CANNOT SEE THE CHILD\'S ENTRIES — ' +
          'each realm is a store of its own and the DN picks the deepest',
          leaked.length + ' leaked of ' +
          (fromParent.entries || []).length);
  const fromChild = search('ou=users,' + childBase, 0);
  t.check(fromChild.ok && fromChild.entries.length === 1,
          'and the child\'s tree is answered from the child\'s store',
          JSON.stringify({ ok: fromChild.ok,
                           errorName: fromChild.errorName }));
  log.debug("Leaving theDirectory().");
}

function theInventedMail(t) {
  log.debug("Entering theInventedMail().");
  t.log.info('=== G. the invented address ===');
  const inOwn = realms.run(realms.get(OWN), function () {
    return realms.inventedMailOf('alice');
  });
  t.equal(inOwn, 'alice@' + OWN_DOMAIN,
          'a development-mode person is invented an address in the ambient ' +
          'realm\'s domain');
  t.equal(realms.inventedMailOf('bob@elsewhere.test'), 'bob@elsewhere.test',
          'and a name that is already an address is left as it is');
  log.debug("Leaving theInventedMail().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    theShape(t);
    theDefaultAndTheOwn(t);
    uniquenessAndNesting(t);
    fixedOnceCreated(t);
    theDirectory(t);
    theInventedMail(t);
  } finally {
    // EVERY realm this run stamped, nested ones first — not only the four it
    // meant to keep: a refusal that stopped refusing (a mutant, a regression)
    // creates one too, and a realm left behind fails realm_isolation.js.
    realms.list().filter(function (realm) {
      return realm.id.indexOf(STAMP) >= 0;
    }).map(function (realm) {
      return realm.id;
    }).sort(function (a, b) {
      return a === CHILD ? -1 : (b === CHILD ? 1 : 0);
    }).forEach(function (id) {
      realms.remove(id);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_domain',
  describe: 'a trust realm\'s DNS domain: its shape, the default of ' +
            '<id>.<global.domain>, the names seeded from it, uniqueness with ' +
            'nesting allowed, fixed once created, a directory tree per realm ' +
            'and the invented address',
  run: run
};
