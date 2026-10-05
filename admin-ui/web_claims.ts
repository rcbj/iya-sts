// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_claims.ts
//
// ---------------------------------------------------------------------------
// CUSTOM CLAIMS, SAML ATTRIBUTES AND USERINFO CLAIMS, DRAWN FROM THEIR VIEWS
// ALONE (#446, 2026-10-05).
//
// Draws the three claim-set pages — `/admin/claims`, `/admin/saml-attributes`
// and `/admin/userinfo-claims` — from the answers of their management API
// operations: each set's typed claims and ticked directory attributes, what
// they would carry for one person, the groups claim and the forms that change
// them.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/claims` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

// WHICH PLACEHOLDERS ACTUALLY EXPAND IN AN ASSERTION, which is not the list the
// claims page advertises and is worth being exact about rather than tidy.
//
// A placeholder is expanded against the CONTEXT the issuance path hands
// admin_stats.expandValue(), and the two assertion builders hand it
// `{ subject, audience }` — saml2.ts and saml11.ts, the same one line each —
// where oauth2.js hands a token's whole claim context. So `${username}`,
// `${email}` and the rest of PLACEHOLDERS reach an assertion as the characters
// they were written as. That is the documented behaviour of an unknown
// placeholder (it names itself rather than silently becoming empty), and it is
// not a defect of this page — but a page that recited the JWT list under a SAML
// heading would be telling somebody their attribute will carry a name when it
// will carry `${username}`. `${now}` and `${iso}` are computed inside
// expandValue() and so work everywhere.
const SAML_PLACEHOLDERS = ['subject', 'audience', 'now', 'iso'];

/**
 * Draws the three claim-set pages — `/admin/claims`, `/admin/saml-attributes`
 * and `/admin/userinfo-claims` — from the answers of their management API
 * operations: each set's typed claims and ticked directory attributes, what
 * they would carry for one person, the groups claim and the forms that change
 * them.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ClaimsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static claimsBody(ctx, json) {
    const pageUrl = '/admin/claims?user=' +
                    encodeURIComponent(json.preview.user);
    // ONE read of the directory and one invented persona for the whole page,
    // not one per set: both tables show the same catalogue of values for the
    // same person, and a read of one entry per section would be one that
    // exists only because the sections were written separately.
    const values = json.preview;

    const inner = kit.note('What to add to every <strong>token</strong> ' +
      'this service ' +
      'issues <em>from now on</em>. Nothing already issued changes — a ' +
      'token is a signed document and this page cannot reach inside one. ' +
      'Two sets, because an OAuth 2.0 access token and an OIDC ID Token go ' +
      'to different readers: one to a resource server and one to a client, ' +
      'and the interesting configuration is usually the one where they ' +
      'DIFFER.') +

      kit.note('The other three sets are next door. <strong>The UserInfo ' +
      'response is configured on <a href="/admin/userinfo-claims">UserInfo ' +
      'claims</a></strong>, beside this page — separate because that ' +
      'response is rebuilt on every call rather than issued once, so a ' +
      'change there reaches a client that is already holding its tokens. ' +
      '<strong>SAML 2.0 and SAML 1.1 assertions are on <a ' +
      'href="/admin/saml-attributes">Custom SAML attributes</a></strong>, ' +
      'under SAML, because those two spell an attribute differently enough ' +
      'from a JWT claim — and from each other — that one page had to ' +
      'explain three vocabularies before a reader could change one. The ' +
      'store is the same one whichever page is used, and so is the audit ' +
      'row.') +

      ClaimsPage.claimHalvesNote('jwt') +

      ClaimsPage.claimPreviewForm('/admin/claims', json.preview.user, values) +

      kit.warn('<strong>Custom claims are additive.</strong> A configured ' +
      'claim is added to what the protocol already puts in the token and ' +
      'never replaces one. The names this service sets itself are refused ' +
      'rather than silently ignored: ' +
      kit.codeList(json.reservedJwtClaims) + '. Every one of them is ' +
      'load-bearing somewhere here — an <code>exp</code> settable from a ' +
      'web form would produce tokens that fail to verify with nothing ' +
      'pointing back at this page. The list is a JWT rule and only a JWT ' +
      'rule: an <a href="/admin/saml-attributes">assertion attribute</a> ' +
      'called <code>exp</code> collides with nothing and is allowed.') +

      '<h2>The two token sets</h2>' +
      json.sets.map(function (set) {
        return ClaimsPage.claimSetSection(set.id, json, pageUrl);
      }).join('') +

      ClaimsPage.groupClaimSection(json.groups, json.preview.user) +

      ClaimsPage.attributeCatalogueNotes('jwt') +

      ClaimsPage.claimValueNotes('jwt', json.placeholders) +

      ClaimsPage.replaceSetForm(json.sets, pageUrl, 'jwt');

    return inner;
  }

  // ---------------------------------------------------------------------------
  // THE PROSE BOTH PAGES NEED, WRITTEN ONCE.
  //
  // /admin/claims and /admin/saml-attributes are the same two halves — a typed
  // entry and a ticked directory attribute — put into two different
  // vocabularies, so most of what each page has to explain is one explanation.
  // It is factored into these four helpers rather than copied, because the copy
  // that is not edited alongside the other is the one a reader believes: two
  // pages disagreeing about what `${username}` does, or about whether a typed
  // entry wins, would be worse than either page saying nothing.
  //
  // `family` is 'jwt' or 'saml' and is the ONLY thing that varies. Where the
  // two genuinely differ — a JWT value is typed and a SAML one is always text,
  // a JWT nests and an assertion cannot — the difference is stated rather than
  // generalised away, because that pair of facts is exactly what somebody
  // comparing an ID Token with an assertion has come here to find.
  // ---------------------------------------------------------------------------
  /**
   * Draws the note explaining a set's two halves, typed entries and
   * directory attributes, in the vocabulary of the family.
   *
   * @param family - "jwt", "saml" or "userinfo"
   * @returns the note as HTML
   */
  static claimHalvesNote(family) {
    const noun = family === 'saml' ? 'attribute' : 'claim';
    const carrier = family === 'saml' ? 'assertion'
                  : (family === 'userinfo' ? 'UserInfo response' : 'token');
    return kit.note('Each set has <strong>two halves</strong>. A <em>typed ' +
                     noun +
      '</em> is a name and a value somebody wrote here, the same for ' +
      'everybody except where it carries a <code>${placeholder}</code>. A ' +
      '<em>directory attribute</em> is ticked from the catalogue below and ' +
      'its value is whatever that person\'s entry under ' +
      '<code>ou=users</code> says — so an <code>ldapmodify</code> changes ' +
      'the next ' + carrier + ', ' +
      'and an LDAP client and a relying party pointed at this service are ' +
      'shown the same person. That is the half worth exercising, and until ' +
      'the catalogue existed only a Verifiable Credential could do it.');
  }

  // The "show me somebody" form. It is a GET form posting to the page's own
  // path, so the preview user survives in the URL and every action form on the
  // page can carry it into its redirect — see claimsPageUrl().
  /**
   * Draws the GET form that chooses whose values the page previews, with a
   * note on whether they come from a directory entry or are generated.
   *
   * @param path - the page's path
   * @param previewUser - the username being previewed
   * @param values - the preview user's attribute values
   * @returns the form as HTML
   */
  static claimPreviewForm(path, previewUser, values) {
    return '<form method="get" action="' + kit.esc(path) +
           '"><div class="formrow">' +
      '<label for="user">Show the values for</label>' +
      '<input type="text" id="user" name="user" size="20" value="' +
      kit.esc(previewUser) + '"><button ' +
      'class="secondary">Show</button>' +
      kit.note((values.entryFound
        ? 'This person has an entry in the directory, so the values marked ' +
          '<em>directory</em> are what an LDAP client reads from it.'
        : 'This person has no entry in the directory — nobody has ' +
          'authenticated as them and nothing was added by hand — so every ' +
          'value below is generated. It will be the same one next time: the ' +
          'invented person is seeded from the username.')) + '</div></form>';
  }

  // One set, rendered: what is in it, a way to remove each, and a way to add
  // another. The three sets differ in the extra field each needs, which is why
  // the form is built from the set's kind rather than being one form four
  // times.
  //
  // IT IS THE SAME FUNCTION ON BOTH PAGES and only the NOUN changes: a JWT set
  // carries claims and a SAML set carries attributes, which is what each
  // protocol's own readers call them, and a page headed "Custom SAML
  // attributes" whose tables said "claim" would be teaching the wrong word for
  // the thing it is about to put in an assertion. Everything else — the two
  // halves, the three buttons, the precedence — is one behaviour and is drawn
  // once.
  /**
   * Draws one claim set: its typed claims or attributes with Remove, Add and
   * Clear forms, followed by its directory attribute half.
   *
   * Shared by the claims and SAML attribute pages; the noun and the SAML
   * NameFormat or namespace column follow the set.
   *
   * @param setId - the claim set's id
   * @param previewUser - the username being previewed
   * @param values - the preview user's attribute values
   * @param pageUrl - the URL the forms post to
   * @returns the section as HTML
   */
  static claimSetSection(setId, json, pageUrl) {
    const set = json.sets.filter(function (one) {
      return one.id === setId;
    })[0];
    const claims = set.claims;
    const isSaml2 = setId === 'saml2';
    const isSaml11 = setId === 'saml11';
    const isSaml = isSaml2 || isSaml11;
    const isUserinfo = setId === 'userinfo';
    const noun = isSaml ? 'attribute' : 'claim';
    // Three carriers now, and the third is the one that is not ISSUED: a
    // UserInfo response is built on every call, so the sentence this word ends
    // up in ("these tokens carry only what the protocol puts in them") has to
    // say `responses` or it will be describing a signed document that does not
    // exist.
    const carrier = isSaml ? 'assertions' :
                    (isUserinfo ? 'UserInfo responses' : 'tokens');
    const extraHeader = isSaml2 ? '<th>NameFormat</th>' :
                        (isSaml11 ? '<th>AttributeNamespace</th>' : '');
    // ATTRIBUTE CLAIMS' THREE HELPS (#94), from the model the /admin-api
    // replies carry too: what each attribute row would carry for the
    // previewed person, which partners' release lists withhold a claim, and
    // the attributes worth offering in the form's pick-list.
    const who = json.preview.user;
    const previewRows = set.attributeClaimPreview;
    const lists = json.withholding;
    const withheld = set.withheldFrom;
    const choices = json.attributeChoices;

    const rows = claims.map(function (claim) {
      const extraCell = isSaml2 ? '<td>' + kit.esc(claim.nameFormat || '—') +
                        '</td>'
                      : (isSaml11 ?
                         '<td>' + kit.shortened(claim.namespace, 44) +
                         '</td>' : '');
      return '<tr><td><code>' + kit.esc(claim.name) + '</code></td>' +
             extraCell +
        // AN ATTRIBUTE CLAIM (#94) shows where its value comes from.
        '<td>' + (claim.attribute
          ? '&larr; <code>' + kit.esc(claim.attribute) + '</code>' +
            '<span class="sub"> directory attribute' +
            (claim.multi ? ', every value' : '') +
            (claim.type && claim.type !== 'string'
              ? ', as ' + kit.esc(claim.type) : '') + '</span>'
          : '<code>' + kit.esc(claim.value) + '</code>') +
        // WHAT IT WOULD CARRY FOR THE PREVIEWED PERSON (#94).
        (claim.attribute ? (function () {
          const seen = previewRows.filter(function (one) {
            return one.name === claim.name;
          })[0];
          return '<br><span class="sub">for <code>' + kit.esc(who) +
            '</code>: ' + (seen && seen.carried
              ? '<code>' + kit.esc(JSON.stringify(seen.value)) + '</code>'
              : 'nothing &mdash; their entry has no ' +
                kit.esc(claim.attribute)) + '</span>';
        })() : '') +
        // WHO WOULD NOT GET IT (#94): a partner whose release list does not
        // name it.
        (withheld[claim.name] ? '<br><span class="state-revoked">withheld ' +
          'from ' + withheld[claim.name].map(function (id) {
            return '<a href="/admin/federation?relationship=' +
                   encodeURIComponent(id) + '">' + kit.esc(id) + '</a>';
          }).join(', ') + '</span><span class="sub"> &mdash; not on ' +
          'their release list</span>' : '') + '</td>' +
        '<td><form method="post" action="' + kit.esc(pageUrl) +
        '" class="inline">' +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
        '<input type="hidden" name="name" value="' + kit.esc(claim.name) +
        '"><button class="secondary">Remove</button></form></td></tr>';
    }).join('');

    const extraInput = isSaml2
      ? '<label for="nf-' + setId + '">NameFormat</label>' +
        '<input type="text" id="nf-' + setId +
        '" name="nameFormat" size="28" ' +
                                               'placeholder="(optional)">'
      : (isSaml11
        ? '<label for="ns-' + setId + '">Namespace</label>' +
          '<input type="text" id="ns-' + setId +
          '" name="namespace" size="34" ' +
                                                 'placeholder="' +
          kit.esc(json.defaultSaml11Namespace) + '">'
        : '');

    return '<h3>' + kit.esc(set.label) + ' <code>' + kit.esc(setId) +
           '</code></h3>' +
      // The two halves in this order because the second is the one that changes
      // per person, and a reader who has just pressed Update wants to see the
      // table they pressed it under rather than scroll past a form they did not
      // touch. The headings say which half is which: they are configured
      // separately, audited separately, and only one of them can be wrong in a
      // way the directory explains.
      '<p class="sub">Typed ' + noun + 's &mdash; a name and a value, the ' +
      'same for everybody.</p><table><tr><th>Name</th>' + extraHeader +
      '<th>Value</th><th></th></tr>' +
      (rows ||
       '<tr><td colspan="' + (extraHeader ? 4 : 3) + '">No custom ' + noun +
       ' ' +
               'is configured; ' +
               'these ' + carrier + ' carry only what the protocol puts in ' +
                                    'them.</td></tr>') + '</table><form ' +
      'method="post" action="' + kit.esc(pageUrl) + '"><div class="formrow">' +
        '<input type="hidden" name="action" value="add">' +
        '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
        '<label for="n-' + setId + '">Name</label>' +
        '<input type="text" id="n-' + setId + '" name="name" size="20">' +
        extraInput +
        '<label for="v-' + setId + '">Value</label>' +
        '<input type="text" id="v-' + setId + '" name="value" size="28">' +
        '<button>Add</button>' +
        '</div></form>' +
      // AN ATTRIBUTE CLAIM (#94): any directory attribute, under a name of
      // the administrator's choosing — where the half below offers only the
      // catalogue, under the names the catalogue fixes.
      '<form method="post" action="' + kit.esc(pageUrl) + '"><div ' +
        'class="formrow">' +
        '<input type="hidden" name="action" value="add-attribute-claim">' +
        '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
        '<label for="an-' + setId + '">Name</label>' +
        '<input type="text" id="an-' + setId + '" name="name" size="20">' +
        '<label for="aa-' + setId + '">from the attribute</label>' +
        '<input type="text" id="aa-' + setId + '" name="attribute" ' +
        'size="20" placeholder="e.g. costCenter" list="ac-' + setId + '">' +
        // THE PICK-LIST (#94): what this realm's attribute sources and
        // federation mappings write, so a name is chosen rather than
        // guessed; any other name may still be typed.
        '<datalist id="ac-' + setId + '">' + choices.map(function (one) {
          return '<option value="' + kit.esc(one.attribute) + '" label="' +
                 kit.esc(one.attribute + ' (' + one.from.join(', ') + ')') +
                 '">';
        }).join('') + '</datalist>' +
        '<label><input type="checkbox" name="multi" value="true"> every ' +
        'value</label>' +
        (isSaml ? '' : '<label for="at-' + setId + '">as</label><select ' +
          'id="at-' + setId + '" name="type">' +
          ['string', 'number', 'boolean', 'json'].map(function (type) {
            return '<option value="' + type + '">' + type + '</option>';
          }).join('') + '</select>') +
        '<button>Add</button></div></form>' +
      '<p class="sub">A ' + noun + ' from a directory attribute carries ' +
      'the value on the entry of the person the ' +
      (isSaml ? 'assertion' : (isUserinfo ? 'response' : 'token')) +
      ' is about &mdash; any attribute, not only the catalogue below. Only ' +
      'the directory: a person whose entry lacks it gets none. A secret, a ' +
      'binary value or an attribute this service keeps is refused.' +
      (choices.length ? ' The attribute field offers the ' + choices.length +
        ' this realm\'s attribute sources and federation mappings write.'
                      : '') + '</p>' +
      // THE RELEASE WARNING (#94), where it applies: a claim added here does
      // not reach a partner whose release list does not name it.
      (lists.length ? kit.warn('<strong>' + lists.length + ' federation ' +
        'partner(s) have a release list</strong> (' +
        lists.map(function (one) {
          return '<a href="/admin/federation?relationship=' +
                 encodeURIComponent(one.id) + '">' + kit.esc(one.id) +
                 '</a>';
        }).join(', ') + '): a ' + noun + ' added here reaches them only ' +
        'once its name is added to their <code>fedRelease</code>.') : '') +
      (claims.length
        ? '<form method="post" action="' + kit.esc(pageUrl) +
          '" class="inline">' +
          '<input type="hidden" name="action" value="clear">' +
          '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
          '<button class="secondary">Clear this set</button></form>'
        : '') +
      '<p class="sub">Directory attributes &mdash; a value read off each ' +
      'person\'s own entry.</p>' +
      ClaimsPage.claimAttributeSection(setId, json, pageUrl);
  }

  // ---------------------------------------------------------------------------
  // THE DIRECTORY ATTRIBUTE HALF OF ONE SET.
  //
  // A checkbox per attribute type in the catalogue, a column saying what it
  // would put in a token for the person being previewed, and three buttons. It
  // is repeated for each of the four sets rather than being one table with four
  // checkbox columns, because the four sets are chosen for different reasons —
  // an access token goes to a resource server and an ID Token goes to a client,
  // and the interesting configuration is usually the one where they DIFFER. A
  // single grid would make four independent decisions look like one, and would
  // have to post all four sets at once, so changing the ID Token would rewrite
  // the access token's selection as a side effect.
  //
  // THE THREE BUTTONS ARE THREE FORMS, and unticking a box in one of the other
  // three sets' tables does nothing to this one: only the form that is
  // submitted sends anything, so each Update button carries exactly its own
  // set's boxes. That is worth stating because a page with four checkbox tables
  // and one Update button would be the obvious design and would be wrong in the
  // direction nobody notices — it would clear the three sets whose tables were
  // rendered before the reader ticked anything.
  // ---------------------------------------------------------------------------
  /**
   * Draws the directory attribute half of one claim set: a checkbox per
   * catalogue attribute with its value for the preview user, and the
   * Update, Select all and Delete all forms.
   *
   * @param setId - the claim set's id
   * @param previewUser - the username being previewed
   * @param values - the preview user's attribute values
   * @param pageUrl - the URL the forms post to
   * @returns the section as HTML
   */
  static claimAttributeSection(setId, json, pageUrl) {
    const selected = json.sets.filter(function (one) {
      return one.id === setId;
    })[0].attributes;
    const values = json.preview;

    const rows = json.attributeCatalogue.map(function (row) {
      const on = !!row.sets[setId];
      const found = values.byLdap[row.ldap.toLowerCase()];
      // `description` is the one row with no generator: this service writes it
      // on every entry itself, to record the protocols that person has used. So
      // it is the one attribute whose value is a real fact, and it is absent
      // rather than invented for somebody with no entry.
      const valueCell = found
        ? '<td><code>' + kit.esc(found.value) + '</code></td><td>' +
          kit.esc(found.source) + '</td>'
        : '<td><span class="state-none">—</span></td><td>' +
          (row.generated ? 'would be generated' : 'the entry\'s own') + '</td>';
      return '<tr><td><input type="checkbox" name="attribute" value="' +
        kit.esc(row.ldap) + '"' +
        (on ? ' checked' : '') + '></td>' +
        '<td><code>' + kit.esc(row.ldap) + '</code></td>' +
        '<td>' + kit.esc(row.schema) + '</td>' +
        '<td><code>' + kit.esc(row.claim) + '</code></td>' +
        valueCell + '</tr>';
    }).join('');

    return kit.note((selected.length
        ? 'Carries ' + selected.length + ' directory attribute(s): ' +
          kit.codeList(selected) + '.'
        : 'Carries no directory attribute. Tick some and press Update.')) +
      '<form method="post" action="' + kit.esc(pageUrl) + '">' +
      '<input type="hidden" name="action" value="attributes">' +
      '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
      '<table><tr><th>In</th><th>LDAP attribute</th><th>Defined by</th>' +
      '<th>' +
      (setId === 'saml2' || setId === 'saml11' ? 'Attribute name' : 'Claim') +
      '</th><th>For ' + kit.esc(json.preview.user) + '</th><th>Source</th></tr>' +
      rows + '</table><div class="formrow"><button>Update</button><span ' +
      'class="note">The ticked boxes become the whole selection for this ' +
      'set: unticking is how an attribute is ' +
      'removed.</span></div></form><div class="formrow"><form method="post" ' +
      'action="' + kit.esc(pageUrl) + '" class="inline">' +
      '<input type="hidden" name="action" value="attributes-all">' +
      '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
      '<button class="secondary">Select all</button></form> ' +
      '<form method="post" action="' + kit.esc(pageUrl) + '" class="inline">' +
      '<input type="hidden" name="action" value="attributes-clear">' +
      '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
      '<button class="secondary">Delete all</button></form>' +
      kit.note('Both act immediately — there is no script on this page, so ' +
      'these are form posts and not a way of ticking the boxes above.') +
      '</div>';
  }

  // ---------------------------------------------------------------------------
  // THE GROUPS CLAIM, on the page that already answers "what will the next
  // token carry".
  //
  // READ-ONLY here, and that is a decision rather than an omission. Its four
  // settings live in config.js's table, which means /admin/config and POST
  // /admin-api/config/set already change them — a second form here would be a
  // second door to one setting, which is exactly the two-stores mistake this
  // service keeps out of everything else. So this section reports and links;
  // the parity rule (a control gets an API operation in the same commit) is
  // satisfied by there being no new control.
  //
  // What it does add is the thing no configuration page can: what the claim
  // WOULD say about the person being previewed, built by groupsOf() — the same
  // function the issuance path calls — so a preview that agreed with the page
  // and disagreed with the token is not possible.
  // ---------------------------------------------------------------------------
  /**
   * Draws the read-only groups claim section: whether the claim is on, and
   * what it would carry for the preview user, built by groupsOf().
   *
   * @param previewUser - the username being previewed
   * @returns the section as HTML
   */
  static groupClaimSection(groups, previewUser) {
    const state = groups;
    const answer = groups.preview;
    const rows = answer.groups.map(function (group) {
      // WHY this group is in the list, which is the whole of the memberOf
      // disagreement in one cell: `member` and its two siblings are the GROUP
      // saying so, memberOf is the PERSON saying so, and this directory
      // maintains neither from the other.
      const how = group.via.length
        ? group.via.map(function (name) {
          return '<code>' + kit.esc(name) + '</code>';
        }).join(', ')
        : '';
      const counted = group.via.length || state.memberOfCounts;
      return '<tr><td><code>' + kit.esc(group.dn) + '</code></td>' +
        '<td>' + kit.esc(group.cn) + '</td>' +
        '<td>' + (how || '&mdash;') +
        (group.viaMemberOf
          ? (how ? ', ' : '') + 'the person\'s own <code>memberOf</code>' +
            (state.memberOfCounts ? '' : ' <em>(not counted)</em>')
          : '') + '</td>' +
        '<td>' + (counted ? 'yes' : 'no') + '</td></tr>';
    }).join('');

    const values = answer.values.length
      ? kit.note('The claim <code>' + kit.esc(state.claim) + '</code> ' +
        'would carry ' +
        kit.codeList(answer.values) + '.')
      : kit.note('No claim at all for this person &mdash; not an empty ' +
        'list, absent. ' +
        kit.esc(answer.reason));

    return '<h2>The groups claim</h2>' +
      kit.note('The one thing on this page that is <strong>not</strong> ' +
      'chosen per set: with <code>groups.claim</code> on, all four carry it, ' +
      'for anybody who is a member of a group in <a href="/admin/groups">the ' +
      'embedded directory</a>. The membership is read at the moment a token ' +
      'is minted, so an <code>ldapmodify</code> changes the next one, and ' +
      'somebody in no group gets no claim rather than an empty list &mdash; ' +
      'which is why this can be on by default without changing what an ' +
      'existing client receives.') +

      '<div class="' + (state.enabled && !state.problem ? 'note' : 'warn') +
      '">' +
      (state.enabled
        ? (state.problem
            ? '<strong>On, and not arriving.</strong> ' +
              kit.esc(state.problem)
            : '<strong>On.</strong> Every access token, ID Token and both ' +
              'SAML assertions carry ' +
              '<code>' + kit.esc(state.claim) + '</code>, each value being ' +
              (state.valueForm === 'dn' ? 'the group\'s whole DN' : 'the ' +
                  'group\'s <code>cn</code>') +
              '. A person\'s own <code>memberOf</code> ' +
              (state.memberOfCounts ? 'counts' : 'does NOT count') + ' as ' +
                  'membership.')
        : '<strong>Off.</strong> No token or assertion carries a groups ' +
          'claim. Turn it on with <code>groups.claim</code>.') +
      ' Change any of it on <a href="/admin/groups">the groups page</a>, ' +
      'which draws all four: ' + kit.codeList(state.settings) + '.' +
      (state.loaded ? '' : ' <strong>The embedded directory is not loaded in ' +
                           'this process</strong>, so there are no groups to ' +
                           'read.') +
      '</div>' +

      kit.warn('<strong>Carrying a group is not granting one.</strong> No ' +
      'endpoint here reads this claim and nothing decides anything on it ' +
      '&mdash; the same sentence <a href="/admin/groups">the groups page</a> ' +
      'has always carried, and the half of it that changed is that a token ' +
      'now says so out loud.') +

      kit.note('A typed claim above, and a ticked directory attribute ' +
      'above, both win over this one where the names collide: those were ' +
      'named on this page about this service, and this comes from a setting ' +
      'and a directory.') +

      '<h3>What ' + kit.esc(previewUser) + ' would get</h3>' +
      values +
      (answer.groups.length
        ? '<table><tr><th>Group</th><th>cn</th><th>Named ' +
          'by</th><th>Counted</th></tr>' +
          rows + '</table>'
        : kit.note(kit.esc(previewUser) + ' is named by no group here' +
          (answer.entryFound ? '' :
           ', and has no entry in the directory either') + '. ' +
          'The entry would be at <code>' + kit.esc(answer.dn) + '</code>.'));
  }

  /**
   * Draws the notes on where a directory attribute's value comes from and
   * what it does not do: one catalogue, independent selections, nesting,
   * which name wins, and that nothing here is verified.
   *
   * @param family - "jwt", "saml" or "userinfo"
   * @returns the heading and notes as HTML
   */
  static attributeCatalogueNotes(family) {
    const saml = family === 'saml';
    // THE OTHER PAGES, AS A LIST, because there are three of them now and there
    // were two when this was written. It said "the other page" and named one,
    // which was a sentence that could only ever be right while the number was
    // two — and the day a third arrived it would have gone on reading correctly
    // while telling a reader that one of the two places their selection does
    // NOT apply is the only one. Derived from `family` in one place so that a
    // fourth page is one entry rather than three sentences to find.
    const OTHER_PAGES = {
      jwt: ['<a href="/admin/userinfo-claims">the UserInfo claims page</a>',
            '<a href="/admin/saml-attributes">the SAML attributes page</a>'],
      userinfo: ['<a href="/admin/claims">the custom claims page</a>',
                 '<a href="/admin/saml-attributes">the SAML attributes ' +
                 'page</a>'],
      saml: ['<a href="/admin/claims">the custom claims page</a>',
             '<a href="/admin/userinfo-claims">the UserInfo claims page</a>']
    };
    const OTHER_THINGS = {
      jwt: 'a UserInfo response or an assertion carries',
      userinfo: 'an access token, an ID Token or an assertion carries',
      saml: 'an access token, an ID Token or a UserInfo response carries'
    };
    const otherPage = (OTHER_PAGES[family] || OTHER_PAGES.jwt).join(' and ');
    const otherThing = OTHER_THINGS[family] || OTHER_THINGS.jwt;
    return '<h2>Where a directory attribute comes from, and what it does not ' +
           'do</h2>' +
      kit.note('The catalogue is of <strong>LDAP attribute types</strong> ' +
        'and not of ' +
      (saml ? 'attribute names' : 'claim names') + ', and it is the same ' +
                                                        'catalogue ' +
      otherPage + ' and <a href="/admin/vc">the credential claims page</a> ' +
      'choose from — one list of spellings, because two would eventually ' +
      'disagree about what <code>schacDateOfBirth</code> is called while ' +
      'both looked right. The value is the one on that person\'s entry under ' +
      '<code>ou=users</code>; where the entry has nothing, it is invented ' +
      'from the username — the same invented person every time, across ' +
      'restarts, in obviously fictional ranges. Three rows are not RFC ' +
      '4519/4524/2798: there is no standard attribute type for a birthdate ' +
      'or a nationality, so the SCHAC schema\'s names are borrowed rather ' +
      'than invented.') +
      kit.note('The <strong>five selections are independent</strong>, and ' +
      'that is the point of having five: an access token carrying ' +
      '<code>employee_number</code> and a SAML 2.0 assertion carrying ' +
      '<code>email</code> is a normal arrangement and a single list could ' +
      'not express it. What is on this page is independent of ' +
      'what ' + otherThing + ' ' +
          '— ticked on ' +
      otherPage + ' — and of what a <a href="/admin/vc">credential</a> ' +
      'carries and what the <a href="/admin/vc-verifier-config">Verifier ' +
      'asks for</a>, deliberately: that is what keeps "issue a credential ' +
      'carrying a claim the access token does not" reachable.') +
      (saml
        ? kit.note('A <strong>nested</strong> claim cannot stay nested ' +
          'here. A SAML Attribute\'s content model is a name and text ' +
          'values, so <code>address.locality</code> arrives as an attribute ' +
          'whose NAME is the dotted path, where a JWT would carry a ' +
          '<code>locality</code> member of an <code>address</code> object ' +
          '(OIDC Core 5.1.1). Both families then call one claim by one name, ' +
          'which is the property somebody comparing an ID Token with an ' +
          'assertion needs.')
        : kit.note('A <strong>nested</strong> claim stays nested in a JWT: ' +
          '<code>address.locality</code> is a <code>locality</code> member ' +
          'of an <code>address</code> object, which is what OIDC Core 5.1.1 ' +
          'defines. A SAML Attribute has no way to spell that — the content ' +
          'model is a name and text values — so the assertion carries the ' +
          'dotted path as the attribute\'s name. Both families then call one ' +
          'claim by one name, which is the property somebody comparing an ID ' +
          'Token with an assertion needs.')) +
      kit.note('<strong>A typed ' + (saml ? 'attribute' : 'claim') + ' of ' +
      'the same name wins.</strong> Somebody who wrote <code>email</code> by ' +
      'hand on the set that also has <code>mail</code> ticked has said ' +
      'something specific, and the specific thing beats the general one. In ' +
      'an assertion that has to be a filter rather than an overwrite: two ' +
      '<code>&lt;Attribute&gt;</code> elements with one name would leave a ' +
      'relying party reading whichever the builder emitted first.') +
      (saml
        ? kit.note('<strong>And the protocol\'s own attribute beats ' +
          'both</strong>, which is worth knowing before it is discovered in ' +
          'an assertion. A SAML 2.0 assertion sets <code>name</code> from ' +
          'the sign-in and a WS-Federation one sets the whole identity claim ' +
          'list, so ticking <code>cn</code>, <code>givenName</code>, ' +
          '<code>sn</code>, <code>uid</code> or <code>mail</code> may change ' +
          'nothing a relying party sees. The rule is not this page\'s: a ' +
          'configured attribute is ADDED to an assertion and never ' +
          'substituted into one, because an attribute a relying party keys ' +
          'off that a web form could displace would break a sign-in ' +
          'somewhere that looks nothing like this page.')
        : kit.note('<strong>And the protocol\'s own claim beats ' +
          'both</strong>, which is worth knowing before it is discovered on ' +
          'a token. An ID Token always carries <code>name</code>, ' +
          '<code>given_name</code>, <code>family_name</code>, ' +
          '<code>preferred_username</code> and <code>email</code> built from ' +
          'the sign-in, so ticking <code>cn</code>, <code>givenName</code>, ' +
          '<code>sn</code>, <code>uid</code> or <code>mail</code> <em>on ' +
          'that set</em> changes nothing the client sees — the same five ' +
          'reach an access token, where the protocol sets none of them, and ' +
          'reach it from the directory. The rule is not new and is not this ' +
          'page\'s: a configured claim is added to a token and never ' +
          'substituted into one, because a claim a relying party keys off ' +
          'that a web form could displace would break a sign-in somewhere ' +
          'that looks nothing like this page.')) +
      kit.note('<strong>None of it is verified and none of it grants ' +
      'anything.</strong> This service authenticates nobody — the username ' +
      'typed at the sign-in screen is the identity in everything it issues — ' +
      'so a birthdate from here is a birthdate from a web form. No endpoint ' +
      'here reads one of these back or decides anything on one. That is true ' +
      'of the groups claim as well: it is carried, and a group on that ' +
      'person\'s entry still grants them nothing &mdash; see <a ' +
      'href="/admin/groups">the groups page</a>.');
  }

  /**
   * Draws the Values section: which placeholders a value may carry, and
   * whether a value is typed (JWT, UserInfo) or always text (SAML).
   *
   * @param family - "jwt", "saml" or "userinfo"
   * @returns the heading and notes as HTML
   */
  static claimValueNotes(family, placeholders) {
    const saml = family === 'saml';
    return '<h2>Values</h2>' +
      kit.note('A value may contain <code>${placeholders}</code>, because a ' +
      'value that can only be a constant cannot exercise the thing worth ' +
      'testing — that an ' +
      (saml ? 'attribute' : 'claim') + ' carrying the signed-in user\'s ' +
      'identity reaches the relying party. ' +
      (saml
        ? 'The ones an ASSERTION expands are ' +
          kit.codeList(SAML_PLACEHOLDERS) +
          ', and that is a shorter list than <a href="/admin/claims">the ' +
          'token page\'s</a> on purpose rather than by oversight: an ' +
          'assertion is built from a subject and an audience, so the names a ' +
          'JWT context carries — <code>${username}</code>, ' +
          '<code>${email}</code> and the rest — have nothing to expand ' +
          'against here and arrive as the characters they were written as. ' +
          '<code>${subject}</code> is the one that carries the signed-in ' +
          'identity.'
        : 'The ones understood are ' + kit.codeList(placeholders) +
          '.') +
      ' An unknown one is left as it was written rather than replaced with ' +
      'nothing: <code>${dept}</code> that silently became an empty string is ' +
      'a bug that looks like a configuration mistake, and one that still ' +
      'says <code>${dept}</code> names itself.') +
      (saml
        ? kit.note('<strong>A SAML attribute value is never typed.</strong> ' +
          'The XML content model is text, so <code>true</code> and ' +
          '<code>{"a":1}</code> reach the relying party as the characters ' +
          'they were written as — which is the opposite of what the same ' +
          'value does in a JWT, where it would arrive as a boolean and an ' +
          'object. That difference is worth knowing rather than discovering: ' +
          'a client library that parses an assertion attribute into a ' +
          'boolean is doing that on its own.')
        : kit.note('A ' + (family === 'userinfo' ? 'UserInfo' : 'JWT') + ' ' +
          'claim value is typed: text that unambiguously looks like JSON — ' +
          'an object, an array, a bare ' +
          '<code>true</code>/<code>false</code>/<code>null</code>, or a ' +
          'number — is used as that JSON, and anything else is a string. One ' +
          'consequence, stated rather than left to be discovered: a claim ' +
          'whose value is genuinely the four characters <code>true</code> ' +
          'cannot be configured, because a text field cannot tell the two ' +
          'apart. Write <code>"true"</code>, which parses as the JSON ' +
          'string. <a href="/admin/saml-attributes">SAML attribute ' +
          'values</a> are never typed — the XML content model is text.'));
  }

  // The "replace a whole set" form, which is the one a test wants: POST the
  // same thing as JSON and get JSON back. The SELECT is built from the ids the
  // page carries, so the SAML page cannot offer a token set and the claims page
  // cannot offer an assertion one — the same restriction claimsAction()'s
  // `allowed` enforces on the way in, said in the markup so it is not only a
  // refusal.
  /**
   * Draws the "Replace a whole set" form, which replaces a set's typed
   * entries from a JSON list and leaves its directory attributes alone.
   *
   * @param ids - the claim set ids the page may offer
   * @param pageUrl - the URL the form posts to
   * @param family - "saml" for attributes, anything else for claims
   * @returns the heading, note and form as HTML
   */
  static replaceSetForm(sets, pageUrl, family) {
    const options = sets.map(function (one) {
      return '<option value="' + kit.esc(one.id) + '">' +
             kit.esc(one.label) + '</option>';
    }).join('');
    const noun = family === 'saml' ? 'attributes' : 'claims';
    return '<h2>Replace a whole set</h2>' +
      kit.note('The form a test wants. POST the same thing as JSON to get ' +
      'JSON back. This replaces the ' +
      '<em>typed</em> ' + noun + ' only; the directory attributes ' +
      'ticked above are a separate action (<code>attributes</code>) and are ' +
      'left alone by it.') +
      '<form method="post" action="' + kit.esc(pageUrl) + '">' +
        '<input type="hidden" name="action" value="replace">' +
        '<div class="formrow"><label for="set">Set</label>' +
        '<select id="set" name="set">' + options + '</select></div><textarea ' +
        'name="claims" spellcheck="false">[{"name": "dept", "value": ' +
        '"engineering"}, {"name": "on_behalf_of", "value": ' +
        '"${username}"}]</textarea><div ' +
        'class="formrow"><button>Replace</button></div></form>';
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static samlAttributesBody(ctx, json) {
    const pageUrl = '/admin/saml-attributes?user=' +
                    encodeURIComponent(json.preview.user);
    const values = json.preview;

    const inner = kit.note('What to add to every <strong>SAML ' +
      'assertion</strong> this ' +
      'service issues <em>from now on</em>. Nothing already issued changes ' +
      '— an assertion is a signed document and this page cannot reach ' +
      'inside one. Two sets, because SAML 2.0 and SAML 1.1 spell an ' +
      'attribute differently enough that one list could not serve both: ' +
      '2.0 has <code>Name</code> and an optional <code>NameFormat</code>, ' +
      'and 1.1 has <code>AttributeName</code> and a required ' +
      '<code>AttributeNamespace</code>.') +

      kit.note('<strong>Where these assertions come from.</strong> The ' +
      'SAML 2.0 set reaches every assertion <a ' +
      'href="/admin/sts-metadata">WS-Trust</a> issues with a 2.0 token ' +
      'type; the SAML 1.1 set reaches the 1.1 ones, which is what ' +
      '<strong>WS-Federation\'s passive requestor profile</strong> carries ' +
      '— so the 1.1 half is the one a browser sign-in exercises. There is ' +
      'no SAML 2.0 Web SSO profile here, deliberately, so no assertion of ' +
      'that kind reaches a browser: the 2.0 set is exercised by a WS-Trust ' +
      'client.') +

      kit.note('Tokens are next door. <strong>The OAuth 2.0 access token ' +
      'and the OIDC ID Token are configured on <a ' +
      'href="/admin/claims">Custom claims</a></strong>, and the ' +
      '<strong>UserInfo response on <a ' +
      'href="/admin/userinfo-claims">UserInfo claims</a></strong>, both ' +
      'under OAuth2 / OIDC. The store behind all three pages is one store ' +
      '— the same five sets, the same <code>ldapmodify</code>-visible ' +
      'directory attributes, and one row in <a href="/admin/audit">the ' +
      'audit log</a> per change whichever page made it.') +

      ClaimsPage.claimHalvesNote('saml') +

      ClaimsPage.claimPreviewForm('/admin/saml-attributes', json.preview.user,
                            values) +

      kit.warn('<strong>Custom attributes are additive.</strong> A ' +
      'configured attribute is added to what the protocol already puts in ' +
      'the assertion and never replaces one — a SAML 2.0 assertion sets ' +
      '<code>name</code> from the sign-in and a WS-Federation one sets the ' +
      'whole identity claim list, and neither can be displaced from here. ' +
      '<strong>The reserved list on <a href="/admin/claims">the claims ' +
      'page</a> does not apply to these two sets</strong>: those names are ' +
      'load-bearing in a JWT, and an assertion attribute called ' +
      '<code>exp</code> or <code>scope</code> collides with nothing. What ' +
      'is refused here is the same thing that is refused there — an entry ' +
      'with no name, and two entries of one name, because the second would ' +
      'win silently.') +

      '<h2>The two assertion sets</h2>' +
      json.sets.map(function (set) {
        return ClaimsPage.claimSetSection(set.id, json, pageUrl);
      }).join('') +

      ClaimsPage.groupClaimSection(json.groups, json.preview.user) +

      ClaimsPage.attributeCatalogueNotes('saml') +

      ClaimsPage.claimValueNotes('saml', json.placeholders) +

      '<h2>The SAML 1.1 namespace</h2>' +
      kit.note('A SAML 1.1 attribute is a NAME IN A NAMESPACE, and an ' +
      'attribute configured without one gets ' +
      '<code>' + kit.esc(json.defaultSaml11Namespace) + '</code> — the ' +
      'claim namespace every WS-Federation relying party already reads. ' +
      'That default is why an attribute added with a name and a value ' +
      'alone arrives somewhere useful instead of in a namespace nothing ' +
      'looks in. SAML 2.0 has no equivalent: <code>NameFormat</code> is ' +
      'optional there and is left off unless it is typed.') +

      ClaimsPage.replaceSetForm(json.sets, pageUrl, 'saml');

    return inner;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static userinfoClaimsBody(ctx, json) {
    const raw = json.request;
    const pageUrl = '/admin/userinfo-claims?user=' +
                    encodeURIComponent(json.preview.user) +
                    (raw ? '&request=' + encodeURIComponent(raw) : '');
    // ONE read of the directory for the whole page, exactly as /admin/claims
    // does: the set's table and the request preview describe the same person,
    // and two reads of one entry could answer one page with two versions of
    // them.
    const values = json.preview;

    const inner = kit.note('What to put in every <strong>UserInfo ' +
      'response</strong> ' +
      'this service returns. <strong>This is the one claims page with no ' +
      '&ldquo;nothing already issued changes&rdquo; warning on it, and ' +
      'that is the point of it existing.</strong> An access token, an ID ' +
      'Token and both assertions are signed documents: a claim added to ' +
      'one of those sets reaches a client at its next sign-in and never ' +
      'reaches what it already holds. This response is built on <em>every ' +
      'call</em>, so a claim added here reaches the next <code>GET ' +
      '/oauth2/userinfo</code> from a client that signed in an hour ago ' +
      'and has done nothing since.') +

      kit.note('Tokens and assertions are next door. The OAuth 2.0 access ' +
      'token and the OIDC ID Token are on <a href="/admin/claims">Custom ' +
      'claims</a>; SAML 2.0 and SAML 1.1 are on <a ' +
      'href="/admin/saml-attributes">Custom SAML attributes</a>. ' +
      '<strong>The store behind all three pages is one store</strong> ' +
      '&mdash; the same five sets, the same ' +
      '<code>ldapmodify</code>-visible directory attributes, and one row ' +
      'in <a href="/admin/audit">the audit log</a> per change whichever ' +
      'page made it.') +

      ClaimsPage.claimHalvesNote('userinfo') +

      ClaimsPage.claimPreviewForm('/admin/userinfo-claims', json.preview.user,
                            values) +

      kit.warn('<strong>Custom claims are additive here too.</strong> A ' +
      'configured claim is added to what OpenID Connect Core section 5.4 ' +
      'already puts in the response for the scopes the token carries, and ' +
      'never replaces one. The names this service sets itself are refused ' +
      'rather than silently ignored: ' +
      kit.codeList(json.reservedJwtClaims) + '. ' +
      'That list is the same one <a href="/admin/claims">the claims ' +
      'page</a> enforces and it applies HERE for a reason worth stating, ' +
      'because <a href="/admin/saml-attributes">the SAML page</a> does not ' +
      'enforce it: <code>sub</code> is REQUIRED in this response (Core ' +
      '5.3.2, and a client MUST check it against the ID Token\'s), and ' +
      'when a client has registered a ' +
      '<code>userinfo_signed_response_alg</code> the whole response is a ' +
      'JWT carrying <code>iss</code>, <code>aud</code> and ' +
      '<code>exp</code>. Every name on that list is load-bearing in at ' +
      'least one of those two shapes.') +

      '<h2>The UserInfo claim set</h2>' +
      json.sets.map(function (set) {
        return ClaimsPage.claimSetSection(set.id, json, pageUrl);
      }).join('') +

      ClaimsPage.groupClaimSection(json.groups, json.preview.user) +

      '<h2>What a client can ask for &mdash; ' +
      'OpenID Connect Core section 5.5</h2>' +
      kit.note('<strong>This is the one claim set a CLIENT can add ' +
      'to.</strong> Section 5.5 lets a client send a <code>claims</code> ' +
      'request parameter at the authorization endpoint naming individual ' +
      'claims it wants back from this endpoint, and since 2026-08-26 this ' +
      'service parses it, refuses a malformed one by name, carries it on ' +
      'the authorization code and <em>inside the access token</em>, and ' +
      'answers it by reading the named claims off that person\'s entry ' +
      'under <code>ou=users</code>. ' +
      '<code>claims_parameter_supported</code> in <a ' +
      'href="/.well-known/openid-configuration">the discovery document</a> ' +
      'said <code>false</code> until that day.') +

      kit.note('<strong>Four layers, and the last one wins.</strong> (1) ' +
      'the set configured on this page, which is what everybody gets; (2) ' +
      'section 5.4\'s scope-driven claims &mdash; <code>profile</code> and ' +
      '<code>email</code>, the one place in this service where a scope ' +
      'genuinely changes an answer; (3) the claims a client asked for BY ' +
      'NAME, read off the directory; (4) <code>sub</code>, which nothing ' +
      'may displace. <strong>Layer 3 beating layer 2 is the one choice ' +
      'here that is not obvious</strong>, so it is said out loud: a scope ' +
      'asks for a category and a request names a claim, and answering ' +
      '<code>{"email":null}</code> with the invented <code>' +
      kit.esc(json.inventedEmail) + '</code> while the entry ' +
      'holds a real <code>mail</code> would defeat the only reason the ' +
      'feature is worth having.') +

      ClaimsPage.requestableClaimsSection(json.claimsRequest) +

      '<h3>Try one</h3>' +
      ClaimsPage.claimsRequestSection(json.preview.user, raw,
                                json.claimsRequest) +

      kit.tip('<strong>NON-SPEC: this endpoint also takes a claims ' +
      'request directly.</strong> Section 5.3.1 defines no request ' +
      'parameters at all &mdash; an access token and nothing else &mdash; ' +
      'and <code>/oauth2/userinfo</code> accepts one anyway, because ' +
      'exercising section 5.5 through the specified route means running a ' +
      'whole authorization flow per variation. Two spellings: ' +
      '<code>?claims={"userinfo":{"birthdate":null}}</code>, the section ' +
      '5.5 structure whole, and ' +
      '<code>?claim=birthdate&amp;claim=address</code>, one name each. ' +
      'Both work on GET and on a form-encoded POST. It is a ' +
      '<strong>union</strong> with what the access token carries and can ' +
      'never take a claim away from it &mdash; what the client was ' +
      'authorized for is what the token says. A malformed one is refused ' +
      '<code>invalid_request</code>, because ignoring a debugging ' +
      'parameter that was typed wrong produces the same response as one ' +
      'that was never sent.') +

      kit.warn('<strong><code>essential</code>, <code>value</code> and ' +
      '<code>values</code> are carried and not enforced</strong>, and that ' +
      'is the honest reading of section 5.5.1 rather than a shortfall. An ' +
      '<em>essential</em> claim is a statement about what the CLIENT will ' +
      'do without it, and the same section says a server MUST NOT return ' +
      'an error because a requested claim is unavailable &mdash; so an ' +
      'essential claim this service cannot produce is absent and logged. ' +
      '<em>value</em> and <em>values</em> ask for a claim to come back ' +
      'with a particular value, which this service could satisfy by ' +
      'echoing it and deliberately does not: everything it says about a ' +
      'person comes from the directory or the invented persona, and a ' +
      'UserInfo response that agreed with whatever a client asked it to ' +
      'say would be the one surface here that cannot be used to test ' +
      'anything. The mismatch is reported instead.') +

      ClaimsPage.attributeCatalogueNotes('userinfo') +

      ClaimsPage.claimValueNotes('userinfo', json.placeholders) +

      ClaimsPage.replaceSetForm(json.sets, pageUrl, 'userinfo');

    return inner;
  }

  // The vocabulary table: every name a client may put in a claims request.
  /**
   * Draws the table of every claim name a client may put in a claims
   * request, with the attribute each is answered from.
   *
   * @returns the heading, note and table as HTML
   */
  static requestableClaimsSection(claimsRequest) {
    const rows = claimsRequest.requestable.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.claim) + '</code></td><td>' +
        (row.grouped ? '<em>the whole claim</em>' : kit.esc(row.label)) +
        '</td><td><code>' + kit.esc(row.ldap) + '</code></td></tr>';
    }).join('');
    const persona = claimsRequest.fromTheSignIn.map(function (name) {
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td>Invented ' +
        'from the username at sign-in</td><td><span ' +
        'class="state-none">&mdash;</span></td></tr>';
    }).join('');
    return '<h3>What a client may ask for</h3>' +
      kit.note('A request may name a claim by its <strong>flat ' +
      'name</strong> (<code>birthdate</code>, <code>address.locality</code>) ' +
      'or, for a nested one, by its <strong>top-level name</strong> alone ' +
      '(<code>address</code>) &mdash; which is the spelling section 5.5.1\'s ' +
      'own example uses and which returns the whole Address Claim of OIDC ' +
      'Core 5.1.1 as one object. A <strong>language tag</strong> is part of ' +
      'the name (Core 5.2): <code>family_name#ja-Kana-JP</code> is answered ' +
      'under exactly that name, with the value this service holds &mdash; it ' +
      'keeps one value per attribute, so the tag changes the spelling of the ' +
      'member and not the content.') +
      '<table><tr><th>Claim</th><th>What it is</th><th>From ' +
      'attribute</th></tr>' +
      rows + persona + '</table>';
  }

  // The "what would this request return" form and its answer. A GET form onto
  // the page's own path, exactly as the preview-user form is and for the same
  // reason: the request survives in the URL, so every action form on the page
  // carries it into its redirect and a reader who ticks a box does not lose
  // what they typed.
  /**
   * Draws the claims request form and what that request's userinfo member
   * would return for the preview user.
   *
   * A request that would be refused is shown with the client's error rather
   * than corrected; ignored members, absent and essential claims and value
   * mismatches are each reported.
   *
   * @param previewUser - the username being previewed
   * @param raw - the claims request as typed
   * @param preview - the computed preview of that request
   * @returns the form and its answer as HTML
   */
  static claimsRequestSection(previewUser, raw, claimsRequest) {
    const preview = claimsRequest.preview;
    const form = '<form method="get" action="/admin/userinfo-claims">' +
      '<input type="hidden" name="user" value="' + kit.esc(previewUser) +
      '"><div class="formrow"><label for="request">A claims ' +
      'request</label><input type="text" id="request" name="request" ' +
      'size="72" spellcheck="false" value="' +
      kit.esc(raw) + '" ' +
      'placeholder=\'{"userinfo":{"birthdate":null,"address":null}}\'>' +
      '<button ' +
      'class="secondary">Show what it returns</button></div></form>';

    if (!preview.asked) {
      return form + kit.note('Nothing asked for yet. Paste the ' +
        '<code>claims</code> parameter a client would send &mdash; the whole ' +
        'section 5.5 object, <code>userinfo</code> member and all &mdash; ' +
        'and this shows what ' +
        kit.esc(previewUser) + ' would get back, computed by the same two ' +
        'functions the <code>/oauth2/userinfo</code> endpoint calls.');
    }
    if (!preview.ok) {
      return form + kit.warn('<strong>This request would be ' +
        'refused</strong> at the authorization endpoint with ' +
        '<code>invalid_request</code>, and the client would be told: ' +
        kit.esc(preview.error) + ' That is the answer a client gets, shown ' +
        'here rather than corrected &mdash; a console that quietly fixed a ' +
        'malformed request would be the one place this mistake is invisible.');
    }

    const rows = preview.report.map(function (item) {
      return '<tr><td><code>' + kit.esc(item.requested) + '</code></td>' +
        '<td><code>' + kit.esc(item.claim) + '</code></td><td>' +
        (item.ldap ? '<code>' + kit.esc(item.ldap) + '</code>' : '&mdash;') +
        '</td><td><code>' + kit.esc(item.value) + '</code></td><td>' +
        kit.esc(item.source) + '</td></tr>';
    }).join('');

    return form +
      (preview.ignoredMembers.length
        ? kit.warn('This request carries the top-level member(s) ' +
          kit.codeList(preview.ignoredMembers) +
          ', which section 5.5 does not define. They are <strong>ignored and ' +
          'not refused</strong>: the section says other members MAY be ' +
          'defined, so one this service has never heard of is a client that ' +
          'knows something this one does not. The two acted on are ' +
          kit.codeList(claimsRequest.members) + '.')
        : '') +
      (preview.idTokenNames.length
        ? kit.note('The <code>id_token</code> member asks for ' +
          kit.codeList(preview.idTokenNames) +
          '. Those are answered where the ID Token is built and are not part ' +
          'of the table below, which is the <code>userinfo</code> member ' +
          'alone.')
        : '') +
      (rows
        ? '<table><tr><th>Asked for</th><th>Claim returned</th><th>From ' +
          'attribute</th><th>Value ' +
          'for ' + kit.esc(previewUser) + '</th><th>Source</th></tr>' + rows +
          '</table>'
        : kit.note('Nothing in this request resolves to a claim this ' +
                    'service can produce.')) +
      (preview.unresolvable.length
        ? kit.note('<strong>Absent, and not an error.</strong> ' +
          kit.codeList(preview.unresolvable) + ' &mdash; neither the ' +
          'attribute catalogue nor the sign-in can ' +
          'produce ' + (preview.unresolvable.length > 1 ? 'those' : 'that') +
          '. Section 5.5.1 says a server MUST NOT return an error because a ' +
          'requested claim is unavailable, so the response simply lacks it ' +
          'and the log says so.')
        : '') +
      (preview.essentialAndAbsent.length
        ? kit.warn('<strong>Marked essential and still absent:</strong> ' +
          kit.codeList(preview.essentialAndAbsent) + '. That is still not ' +
          'an error &mdash; <code>essential</code> is a statement about what ' +
          'the CLIENT will do without the claim, not an instruction to this ' +
          'server. It is logged at warn level so it can be found.')
        : '') +
      (preview.valueMismatches.length
        ? kit.warn('<strong>A value was asked for and a different one is ' +
                    'held:</strong> ' +
          kit.esc(preview.valueMismatches.join('; ')) + '. The value HELD ' +
          'is what is returned. This service could echo back whatever a ' +
          'request asked it to assert and deliberately does not: everything ' +
          'it says about a person comes from the directory or the invented ' +
          'persona, and a mock that agreed with the request could not be ' +
          'used to test anything.')
        : '') +
      kit.note((preview.entryFound
        ? kit.esc(previewUser) + ' has an entry under ' +
          '<code>ou=users</code>, so a value marked <em>directory</em> is ' +
          'what an <code>ldapsearch</code> reads.'
        : kit.esc(previewUser) + ' has no entry in the directory, so every ' +
          'value above is invented from the username &mdash; the same ' +
          'invented person every time, across restarts.'));
  }
}

export = ClaimsPage;
