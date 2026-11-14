// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/uma_owner_policy.js
//
// ---------------------------------------------------------------------------
// A RESOURCE OWNER'S OWN DOCUMENT (#1168 phase 3, #1192), in process, in a
// throwaway realm:
//
//   A. the form's writes read back as the same cards: a person, a group,
//      anyone in the realm, a claim, with an expiry, an acr and "ask me";
//      the document is created at the first share from the default
//      template, its PolicyId the owner's, its version counted on
//   B. every refusal: another owner's resource, an unregistered scope,
//      an unknown person, the owner themselves, an unknown group, a bad
//      claim, a past expiry
//   C. a custom rule is preserved and drawn as one; a rule edited by hand
//      out of the share shape stops being a card
//   D. the bounds: uma.maxOwnerRules and uma.maxOwnerPolicyBytes
//   E. THROUGH THE REAL ENGINE: each share permits exactly whom it names,
//      for the scopes it names, until its expiry; "ask me" carries the
//      approval obligation; a stranger is denied
//   F. ALFA editing: refused while off; on, a document replaced, every RPT
//      over the owner's resources revoked
//   G. removing a share revokes the RPTs that carried it, and only those
//   H. the owner's deletion forgets the document, the resources and the
//      RPTs
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'uma_owner_policy',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  require('../common/config');
  require('../common/app');
  const ldap = require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const config = require('../common/config');
  const helpers = require('../common/helpers');
  const errorCodes = require('../common/error_codes');
  const store = require('../uma/uma_store');
  const owner = require('../uma/uma_owner_policy');
  const surface = require('../uma/uma');
  const stats = require('../common/admin_stats');
  const xml = require('../xacml/xacml_xml');
  const pdp = require('../xacml/xacml_pdp');
  const model = require('../xacml/xacml_model');
  const templates = require('../xacml/xacml_templates');
  const xacmlRequest = require('../xacml/xacml_request');

  const id = 'umaown-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  try {
    await realms.run(made.realm, async function () {
      ['uo-ann', 'uo-bob', 'uo-cat'].forEach(function (name) {
        ldap.createUser(name, { invent: false });
      });
      ldap.createGroup('uo-team', { origin: 'test', members: ['uo-bob'] });
      const ann = helpers.subjectForName('uo-ann');
      const bob = helpers.subjectForName('uo-bob');
      const cat = helpers.subjectForName('uo-cat');
      t.check(/^urn:uuid:/.test(ann) && /^urn:uuid:/.test(bob),
              'setup: three people with subjects');
      const photo = store.saveResource({ owner: ann, ownerKind: 'user',
        resourceServer: 'photos', resource_scopes: ['view', 'edit', 'print'],
        name: 'Holiday' });
      const notes = store.saveResource({ owner: ann, ownerKind: 'user',
        resourceServer: 'notes', resource_scopes: ['read'] });
      const bobs = store.saveResource({ owner: bob, ownerKind: 'user',
        resourceServer: 'photos', resource_scopes: ['view'] });

      // --- A ---------------------------------------------------------
      let before = owner.view(ann);
      t.check(before.ok && !before.stored && before.shares.length === 0,
              'A1. before any share there is no stored document',
              JSON.stringify(before));
      const future = new Date(Date.now() + 86400000).toISOString()
        .replace(/\.\d+Z$/, 'Z');
      const one = owner.share(ann, { resource: photo._id,
        scopes: ['view', 'print'], recipientKind: 'person',
        recipient: 'uo-bob', expires: future, acr: 'phr', askMe: 'on' });
      const two = owner.share(ann, { resource: photo._id, scopes: 'view',
        recipientKind: 'group', recipient: 'uo-team' });
      const three = owner.share(ann, { resource: notes._id,
        scopes: ['read'], recipientKind: 'realm' });
      const four = owner.share(ann, { resource: notes._id,
        scopes: ['read'], recipientKind: 'claim', claim: 'email',
        recipient: 'x@example.com' });
      t.check(one.ok && two.ok && three.ok && four.ok,
              'A2. four shares are written',
              JSON.stringify([one, two, three, four]));
      const view = owner.view(ann);
      const byId = {};
      view.shares.forEach(function (s) {
        byId[s.id] = s;
      });
      const s1 = byId[one.share && one.share.id] || {};
      t.check(view.stored && view.shares.length === 4 &&
              !view.custom.length && view.rules === 5 &&
              s1.recipient && s1.recipient.kind === 'person' &&
              s1.recipient.value === bob && s1.recipient.label === 'uo-bob' &&
              s1.scopes.join() === 'view,print' && s1.expires === future &&
              s1.acr === 'phr' && s1.askMe === true,
              'A3. read back from the DOCUMENT, every share is the same card ' +
              'the form wrote', JSON.stringify(view.shares));
      const s2 = byId[two.share && two.share.id] || {};
      const s4 = byId[four.share && four.share.id] || {};
      t.check(s2.recipient && s2.recipient.kind === 'group' &&
              s2.recipient.label === 'uo-team' &&
              s4.recipient.kind === 'claim' && s4.recipient.claim === 'email' &&
              s4.recipient.value === 'x@example.com' &&
              (byId[three.share.id] || {}).recipient.kind === 'realm',
              'A4. a group, anyone in the realm, and a claim each read back');
      const doc = owner.documentOf(ann);
      t.check(doc.policy.id === templates.umaOwnerPolicyId(ann) &&
              doc.version === '1.4' &&
              doc.policy.rules[0].id === templates.UMA_ATTRIBUTE.OWNER_SELF_RULE,
              'A5. the document starts from the default template: its ' +
              'PolicyId the owner\'s, owner-self kept, version counted on',
              doc.policy.id + ' ' + doc.version);

      // --- B ---------------------------------------------------------
      const refused = function (given, code) {
        const r = owner.share(ann, given);
        return !r.ok && r.code === code && errorCodes.codeOf(r) === code;
      };
      t.check(refused({ resource: bobs._id, scopes: ['view'],
                        recipientKind: 'realm' }, 'STS-UMA-0300') &&
              refused({ resource: photo._id, scopes: ['delete'],
                        recipientKind: 'realm' }, 'STS-UMA-0301') &&
              refused({ resource: photo._id, scopes: [],
                        recipientKind: 'realm' }, 'STS-UMA-0301') &&
              refused({ resource: photo._id, scopes: ['view'],
                        recipientKind: 'person', recipient: 'nobody-here' },
                      'STS-UMA-0302') &&
              refused({ resource: photo._id, scopes: ['view'],
                        recipientKind: 'person', recipient: 'uo-ann' },
                      'STS-UMA-0302') &&
              refused({ resource: photo._id, scopes: ['view'],
                        recipientKind: 'group', recipient: 'no-group' },
                      'STS-UMA-0303') &&
              refused({ resource: photo._id, scopes: ['view'],
                        recipientKind: 'claim', claim: 'bad name',
                        recipient: 'x' }, 'STS-UMA-0304') &&
              refused({ resource: photo._id, scopes: ['view'],
                        recipientKind: 'realm', expires: '2001-01-01' },
                      'STS-UMA-0305'),
              'B1. every refusal under its code: another owner\'s resource, ' +
              'an unregistered or no scope, nobody, the owner, no group, a ' +
              'bad claim, a past expiry');

      // --- E: through the engine ------------------------------------
      const policy = owner.documentOf(ann).policy;
      const decide = function (party, scope, resourceId) {
        const request = new xacmlRequest.AuthorizationRequest({}).uma({
          realm: id, layer: 'owner', scope: scope,
          resource: { id: resourceId, owner: ann, ownerKind: 'user' },
          requestingParty: Object.assign({ known: true,
                                           isOwner: party.id === ann },
                                         party) }).build();
        return pdp.evaluate(policy, request, { repository: null,
                                               resolver: null });
      };
      const asBob = decide({ id: bob, acr: 'phr' }, 'view', photo._id);
      t.check(asBob.decision === model.DECISION.PERMIT &&
              asBob.obligations.some(function (o) {
                return o.id === templates.UMA_ATTRIBUTE.APPROVAL_OBLIGATION;
              }),
              'E1. bob at phr may view, with the approval obligation (ask ' +
              'me each time)', JSON.stringify(asBob));
      t.equal(decide({ id: bob }, 'edit', photo._id).decision,
              model.DECISION.DENY, 'E2. but not edit, which no share names');
      t.equal(decide({ id: bob, groups: [] }, 'print', photo._id).decision,
              model.DECISION.DENY,
              'E3. nor print without the acr the share requires');
      const team = ldap.normalizeDn(ldap.groupDnFor('uo-team'));
      const asTeam = decide({ id: cat, groups: [team] }, 'view', photo._id);
      t.check(asTeam.decision === model.DECISION.PERMIT &&
              !asTeam.obligations.length,
              'E4. a member of the group may view, with no obligation',
              JSON.stringify(asTeam));
      t.equal(decide({ id: cat }, 'view', photo._id).decision,
              model.DECISION.DENY, 'E5. a stranger is denied');
      t.equal(decide({ id: cat }, 'read', notes._id).decision,
              model.DECISION.PERMIT,
              'E6. anyone signed in may read the notes');
      t.equal(decide({ id: ann }, 'edit', photo._id).decision,
              model.DECISION.PERMIT, 'E7. the owner reaches their own');

      // --- C: a custom rule -----------------------------------------
      const customDoc = Object.assign({}, policy, { rules:
        policy.rules.concat([{ id: 'my-own-rule', effect: 'Permit',
          description: 'mine', target: null, condition: null,
          obligations: [], advice: [] }]) });
      store.saveOwnerPolicy(ann, xml.writePolicy(customDoc),
                            { version: '1.4', rules: 6 });
      const tampered = JSON.parse(JSON.stringify(policy));
      tampered.rules.forEach(function (r) {
        if (r.id === templates.UMA_ATTRIBUTE.SHARE_RULE_PREFIX +
                     three.share.id) {
          r.description = 'edited by hand';
        }
      });
      let withCustom = owner.view(ann);
      t.check(withCustom.shares.length === 4 && withCustom.custom.length === 1 &&
              withCustom.custom[0].id === 'my-own-rule' &&
              /permit/i.test(withCustom.custom[0].alfa),
              'C1. a rule the form did not write is drawn as a custom rule ' +
              'with its ALFA, and the shares stay cards',
              JSON.stringify(withCustom.custom));
      store.saveOwnerPolicy(ann, xml.writePolicy(tampered),
                            { version: '1.5', rules: 5 });
      withCustom = owner.view(ann);
      t.check(withCustom.shares.length === 3 && withCustom.custom.length === 1,
              'C2. a share edited by hand out of the form\'s shape is no ' +
              'longer a card: the card cannot say what the rule does not',
              JSON.stringify(withCustom.custom.map(function (c) {
                return c.id;
              })));

      // --- D: the bounds ---------------------------------------------
      config.setOverride('uma.maxOwnerRules', 5);
      const tooMany = owner.share(ann, { resource: notes._id,
        scopes: ['read'], recipientKind: 'realm' });
      config.setOverride('uma.maxOwnerRules', 500);
      config.setOverride('uma.maxOwnerPolicyBytes', 4096);
      const tooBig = owner.share(ann, { resource: notes._id,
        scopes: ['read'], recipientKind: 'realm' });
      config.setOverride('uma.maxOwnerPolicyBytes', 262144);
      t.check(!tooMany.ok && tooMany.code === 'STS-UMA-0003' &&
              !tooBig.ok && tooBig.code === 'STS-UMA-0002' &&
              owner.view(ann).shares.length === 3,
              'D1. past uma.maxOwnerRules and uma.maxOwnerPolicyBytes a ' +
              'share is refused and the document left as it was',
              JSON.stringify([tooMany, tooBig]));

      // --- G: unshare revokes what it carried -----------------------
      const rpt = function (jti, resourceId, scopes) {
        store.saveRpt({ jti: jti, owners: [ann], requestingParty: bob,
          resourceServer: 'photos', exp: Math.floor(Date.now() / 1000) + 600,
          permissions: [{ resource_id: resourceId,
                          resource_scopes: scopes }] });
      };
      const jtiA = 'uo-a-' + Date.now();
      const jtiB = 'uo-b-' + Date.now();
      rpt(jtiA, photo._id, ['view']);
      rpt(jtiB, notes._id, ['read']);
      const gone = owner.unshare(ann, two.share.id);
      t.check(gone.ok && gone.revoked === 1 && stats.isRevoked(jtiA) &&
              !stats.isRevoked(jtiB) && !store.rpt(jtiA) && !!store.rpt(jtiB),
              'G1. removing a share revokes the RPTs over its resource and ' +
              'scopes, and only those', JSON.stringify(gone));
      const again = owner.unshare(ann, two.share.id);
      t.check(!again.ok && again.code === 'STS-UMA-0308',
              'G2. removing it again is STS-UMA-0308');

      // --- F: ALFA ----------------------------------------------------
      const off = owner.setAlfa(ann, 'namespace x { }');
      t.check(!off.ok && off.code === 'STS-UMA-0306',
              'F1. ALFA editing is refused while uma.ownerAlfaEditing is off');
      config.setOverride('uma.ownerAlfaEditing', true);
      const editing = owner.view(ann);
      const bad = owner.setAlfa(ann, 'this is not alfa');
      const good = owner.setAlfa(ann, editing.alfa);
      config.setOverride('uma.ownerAlfaEditing', false);
      t.check(editing.alfaEditing && /policy/.test(editing.alfa) &&
              !bad.ok && bad.code === 'STS-UMA-0307' && good.ok &&
              good.revoked === 1 && stats.isRevoked(jtiB) &&
              owner.documentOf(ann).policy.id ===
                templates.umaOwnerPolicyId(ann),
              'F2. on, the whole document is ALFA; one that does not parse ' +
              'is refused, one that does replaces it (PolicyId kept) and ' +
              'revokes every RPT over the owner\'s resources',
              JSON.stringify([bad, good]));

      // --- H: the owner deleted ---------------------------------------
      const jtiC = 'uo-c-' + Date.now();
      rpt(jtiC, photo._id, ['view']);
      const forgot = surface.forgetOwner(ann, 'a test');
      t.check(forgot.resources === 2 && forgot.rpts === 1 &&
              forgot.document === true && !store.ownerPolicy(ann) &&
              !store.resource(photo._id) && stats.isRevoked(jtiC) &&
              !!store.resource(bobs._id),
              'H1. forgetting an owner removes their document and resources ' +
              'and revokes their RPTs; another owner\'s stay',
              JSON.stringify(forgot));
      const jtiD = 'uo-d-' + Date.now();
      store.saveRpt({ jti: jtiD, owners: [bob], requestingParty: ann,
        resourceServer: 'photos', exp: Math.floor(Date.now() / 1000) + 600,
        permissions: [{ resource_id: bobs._id, resource_scopes: ['view'] }] });
      store.saveOwnerPolicy(bob, xml.writePolicy(templates.build(
        'uma-owner-default', { owner: bob }, {}).policy), { rules: 1 });
      const deleted = ldap.deletePerson(ldap.locateEntry('uo-bob').dn);
      t.check(!store.ownerPolicy(bob) && !store.resource(bobs._id) &&
              stats.isRevoked(jtiD),
              'H2. deleting the person from the directory forgets the same, ' +
              'through the directory\'s account observer',
              JSON.stringify(deleted));
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'uma_owner_policy',
  describe: 'a resource owner\'s own UMA document (#1168 phase 3): the ' +
            'share form\'s rules read back as cards, refusals, custom ' +
            'rules, bounds, the engine, ALFA editing, revocation on ' +
            'withdrawal and on deletion',
  run: run
};
