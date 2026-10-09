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
    const t = ctx.t;
    const pageUrl = '/admin/claims?user=' +
                    encodeURIComponent(json.preview.user);
    // ONE read of the directory and one invented persona for the whole page,
    // not one per set: both tables show the same catalogue of values for the
    // same person, and a read of one entry per section would be one that
    // exists only because the sections were written separately.
    const values = json.preview;

    // A sentence that runs into a link (markup with an href, which a message
    // may not carry) is split around it (#539).
    const inner = kit.note(t.html('consoleClaims.jwtIntro')) +

      kit.note(t.html('consoleClaims.jwtNextDoorA') +
      '<a href="/admin/userinfo-claims">' +
      t.html('consoleClaims.linkUserinfoClaims') + '</a>' +
      t.html('consoleClaims.jwtNextDoorB') + '<a ' +
      'href="/admin/saml-attributes">' +
      t.html('consoleClaims.linkSamlAttributes') + '</a>' +
      t.html('consoleClaims.jwtNextDoorC')) +

      ClaimsPage.claimHalvesNote('jwt', t) +

      ClaimsPage.claimPreviewForm('/admin/claims', json.preview.user, values,
                                  t) +

      kit.warn(t.html('consoleClaims.jwtAdditiveA') +
      kit.codeList(json.reservedJwtClaims) +
      t.html('consoleClaims.jwtAdditiveB') +
      '<a href="/admin/saml-attributes">' +
      t.html('consoleClaims.linkAssertionAttribute') + '</a>' +
      t.html('consoleClaims.jwtAdditiveC')) +

      '<h2>' + t.html('consoleClaims.jwtSetsHeading') + '</h2>' +
      json.sets.map(function (set) {
        return ClaimsPage.claimSetSection(set.id, json, pageUrl, t);
      }).join('') +

      ClaimsPage.groupClaimSection(json.groups, json.preview.user, t) +

      ClaimsPage.attributeCatalogueNotes('jwt', t) +

      ClaimsPage.claimValueNotes('jwt', json.placeholders, t) +

      ClaimsPage.replaceSetForm(json.sets, pageUrl, 'jwt', t);

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
   * @param t - the page's translator (#539)
   * @returns the note as HTML
   */
  static claimHalvesNote(family, t) {
    // The noun and the carrier go in as select parameters, so a translation
    // can inflect around them; `${placeholder}` holds braces a message may
    // not, so it is a parameter too (#539).
    return kit.note(t.html('consoleClaims.halves',
                           { noun: family === 'saml' ? 'attribute' : 'claim',
                             carrier: family,
                             placeholder: '${placeholder}' }));
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
   * @param t - the page's translator (#539)
   * @returns the form as HTML
   */
  static claimPreviewForm(path, previewUser, values, t) {
    return '<form method="get" action="' + kit.esc(path) +
           '"><div class="formrow">' +
      '<label for="user">' + t.html('consoleClaims.showValuesFor') +
      '</label>' +
      '<input type="text" id="user" name="user" size="20" value="' +
      kit.esc(previewUser) + '"><button ' +
      'class="secondary">' + t.html('consoleClaims.show') + '</button>' +
      kit.note((values.entryFound
        ? t.html('consoleClaims.previewFound')
        : t.html('consoleClaims.previewInvented'))) + '</div></form>';
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
   * @param t - the page's translator (#539); none means the default,
   *   English in node
   * @returns the section as HTML
   */
  static claimSetSection(setId, json, pageUrl, t?) {
    // admin.ts's server-side caller passes no translator and is drawn in the
    // default one, English in node (#539).
    t = t || kit.context().t;
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
    const carrier = isSaml ? 'saml' : (isUserinfo ? 'userinfo' : 'jwt');
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
            '<span class="sub">' +
            t.html('consoleClaims.directoryAttribute') +
            (claim.multi ? t.html('consoleClaims.everyValueSuffix') : '') +
            (claim.type && claim.type !== 'string'
              ? t.html('consoleClaims.asType', { type: claim.type }) : '') +
            '</span>'
          : '<code>' + kit.esc(claim.value) + '</code>') +
        // WHAT IT WOULD CARRY FOR THE PREVIEWED PERSON (#94).
        (claim.attribute ? (function () {
          const seen = previewRows.filter(function (one) {
            return one.name === claim.name;
          })[0];
          return '<br><span class="sub">' +
            t.html('consoleClaims.forWho', { who: who }) + (seen && seen.carried
              ? '<code>' + kit.esc(JSON.stringify(seen.value)) + '</code>'
              : t.html('consoleClaims.entryHasNo',
                       { attribute: claim.attribute })) + '</span>';
        })() : '') +
        // WHO WOULD NOT GET IT (#94): a partner whose release list does not
        // name it.
        (withheld[claim.name] ? '<br><span class="state-revoked">' +
          t.html('consoleClaims.withheldFrom') + withheld[claim.name]
            .map(function (id) {
              return '<a href="/admin/federation?relationship=' +
                     encodeURIComponent(id) + '">' + kit.esc(id) + '</a>';
            }).join(', ') + '</span><span class="sub">' +
          t.html('consoleClaims.notOnReleaseList') + '</span>' : '') +
        '</td>' +
        '<td><form method="post" action="' + kit.esc(pageUrl) +
        '" class="inline">' +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
        '<input type="hidden" name="name" value="' + kit.esc(claim.name) +
        '"><button class="secondary">' + t.html('consoleClaims.remove') +
        '</button></form></td></tr>';
    }).join('');

    const extraInput = isSaml2
      ? '<label for="nf-' + setId + '">NameFormat</label>' +
        '<input type="text" id="nf-' + setId +
        '" name="nameFormat" size="28" ' +
                                               'placeholder="' +
        kit.esc(t.text('consoleClaims.optionalPlaceholder')) + '">'
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
      '<p class="sub">' + t.html('consoleClaims.typedHalf', { noun: noun }) +
      '</p><table><tr><th>' + t.html('consoleClaims.colName') + '</th>' +
      extraHeader +
      '<th>' + t.html('consoleClaims.colValue') + '</th><th></th></tr>' +
      (rows ||
       '<tr><td colspan="' + (extraHeader ? 4 : 3) + '">' +
       t.html('consoleClaims.noCustom', { noun: noun, carrier: carrier }) +
       '</td></tr>') + '</table><form ' +
      'method="post" action="' + kit.esc(pageUrl) + '"><div class="formrow">' +
        '<input type="hidden" name="action" value="add">' +
        '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
        '<label for="n-' + setId + '">' + t.html('consoleClaims.name') +
        '</label>' +
        '<input type="text" id="n-' + setId + '" name="name" size="20">' +
        extraInput +
        '<label for="v-' + setId + '">' + t.html('consoleClaims.value') +
        '</label>' +
        '<input type="text" id="v-' + setId + '" name="value" size="28">' +
        '<button>' + t.html('consoleClaims.add') + '</button>' +
        '</div></form>' +
      // AN ATTRIBUTE CLAIM (#94): any directory attribute, under a name of
      // the administrator's choosing — where the half below offers only the
      // catalogue, under the names the catalogue fixes.
      '<form method="post" action="' + kit.esc(pageUrl) + '"><div ' +
        'class="formrow">' +
        '<input type="hidden" name="action" value="add-attribute-claim">' +
        '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
        '<label for="an-' + setId + '">' + t.html('consoleClaims.name') +
        '</label>' +
        '<input type="text" id="an-' + setId + '" name="name" size="20">' +
        '<label for="aa-' + setId + '">' +
        t.html('consoleClaims.fromAttribute') + '</label>' +
        '<input type="text" id="aa-' + setId + '" name="attribute" ' +
        'size="20" placeholder="' +
        kit.esc(t.text('consoleClaims.egCostCenter')) + '" list="ac-' +
        setId + '">' +
        // THE PICK-LIST (#94): what this realm's attribute sources and
        // federation mappings write, so a name is chosen rather than
        // guessed; any other name may still be typed.
        '<datalist id="ac-' + setId + '">' + choices.map(function (one) {
          return '<option value="' + kit.esc(one.attribute) + '" label="' +
                 kit.esc(one.attribute + ' (' + one.from.join(', ') + ')') +
                 '">';
        }).join('') + '</datalist>' +
        '<label><input type="checkbox" name="multi" value="true"> ' +
        t.html('consoleClaims.everyValue') + '</label>' +
        (isSaml ? '' : '<label for="at-' + setId + '">' +
          t.html('consoleClaims.as') + '</label><select ' +
          'id="at-' + setId + '" name="type">' +
          ['string', 'number', 'boolean', 'json'].map(function (type) {
            return '<option value="' + type + '">' + type + '</option>';
          }).join('') + '</select>') +
        '<button>' + t.html('consoleClaims.add') + '</button></div></form>' +
      '<p class="sub">' +
      t.html('consoleClaims.attributeClaimNote',
             { noun: noun, carrier: carrier }) +
      (choices.length
        ? t.html('consoleClaims.attributeChoicesNote', { n: choices.length })
        : '') + '</p>' +
      // THE RELEASE WARNING (#94), where it applies: a claim added here does
      // not reach a partner whose release list does not name it.
      (lists.length ? kit.warn(t.html('consoleClaims.releaseListsA',
                                      { n: lists.length }) +
        lists.map(function (one) {
          return '<a href="/admin/federation?relationship=' +
                 encodeURIComponent(one.id) + '">' + kit.esc(one.id) +
                 '</a>';
        }).join(', ') + t.html('consoleClaims.releaseListsB',
                               { noun: noun })) : '') +
      (claims.length
        ? '<form method="post" action="' + kit.esc(pageUrl) +
          '" class="inline">' +
          '<input type="hidden" name="action" value="clear">' +
          '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
          '<button class="secondary">' + t.html('consoleClaims.clearSet') +
          '</button></form>'
        : '') +
      '<p class="sub">' + t.html('consoleClaims.directoryHalf') + '</p>' +
      ClaimsPage.claimAttributeSection(setId, json, pageUrl, t);
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
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static claimAttributeSection(setId, json, pageUrl, t) {
    const selected = json.sets.filter(function (one) {
      return one.id === setId;
    })[0].attributes;
    const values = json.preview;
    // THE KERBEROS PAC SET (#498) draws the same table from the same
    // catalogue: each row's column is the PAC claim id it becomes, and a
    // value is the entry's own, every value — never generated.
    const pac = json.attributeCatalogue.some(function (row) {
      return !!row.pacClaimId;
    });

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
          (pac ? t.html('consoleClaims.noneOnEntry')
               : row.generated ? t.html('consoleClaims.wouldBeGenerated')
               : t.html('consoleClaims.entrysOwn')) +
          '</td>';
      return '<tr><td><input type="checkbox" name="attribute" value="' +
        kit.esc(row.ldap) + '"' +
        (on ? ' checked' : '') + '></td>' +
        '<td><code>' + kit.esc(row.ldap) + '</code></td>' +
        '<td>' + kit.esc(row.schema) + '</td>' +
        '<td><code>' + kit.esc(pac ? row.pacClaimId : row.claim) +
        '</code></td>' +
        valueCell + '</tr>';
    }).join('');

    return kit.note((selected.length
        ? t.html('consoleClaims.carries', { n: selected.length }) +
          kit.codeList(selected) + '.'
        : t.html('consoleClaims.carriesNone'))) +
      '<form method="post" action="' + kit.esc(pageUrl) + '">' +
      '<input type="hidden" name="action" value="attributes">' +
      '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
      '<table><tr><th>' + t.html('consoleClaims.colIn') + '</th><th>' +
      t.html('consoleClaims.colLdap') + '</th><th>' +
      t.html('consoleClaims.colDefinedBy') + '</th>' +
      '<th>' +
      (pac ? t.html('consoleClaims.colPacClaimId')
           : setId === 'saml2' || setId === 'saml11'
             ? t.html('consoleClaims.colAttributeName')
             : t.html('consoleClaims.colClaim')) +
      '</th><th>' + t.html('consoleClaims.colFor',
                           { user: json.preview.user }) + '</th><th>' +
      t.html('consoleClaims.colSource') + '</th></tr>' +
      rows + '</table><div class="formrow"><button>' +
      t.html('consoleClaims.update') + '</button><span ' +
      'class="note">' + t.html('consoleClaims.tickedNote') +
      '</span></div></form><div class="formrow"><form method="post" ' +
      'action="' + kit.esc(pageUrl) + '" class="inline">' +
      '<input type="hidden" name="action" value="attributes-all">' +
      '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
      '<button class="secondary">' + t.html('consoleClaims.selectAll') +
      '</button></form> ' +
      '<form method="post" action="' + kit.esc(pageUrl) + '" class="inline">' +
      '<input type="hidden" name="action" value="attributes-clear">' +
      '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
      '<button class="secondary">' + t.html('consoleClaims.deleteAll') +
      '</button></form>' +
      kit.note(t.html('consoleClaims.bothImmediate')) +
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
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static groupClaimSection(groups, previewUser, t) {
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
          ? (how ? ', ' : '') + t.html('consoleClaims.ownMemberOf') +
            (state.memberOfCounts ? ''
                                  : ' <em>' +
                                    t.html('consoleClaims.notCounted') +
                                    '</em>')
          : '') + '</td>' +
        '<td>' + (counted ? t.html('consoleClaims.yes')
                          : t.html('consoleClaims.no')) + '</td></tr>';
    }).join('');

    // The reason a person gets no claim is the view's sentence, drawn as it
    // comes (#539).
    const values = answer.values.length
      ? kit.note(t.html('consoleClaims.groupsWouldCarry',
                        { claim: state.claim }) +
        kit.codeList(answer.values) + '.')
      : kit.note(t.html('consoleClaims.groupsNoClaim') +
        kit.esc(answer.reason));

    // The "not arriving" branch is a problem banner built from the view's
    // own sentence, and stays English with it (#539).
    return '<h2>' + t.html('consoleClaims.groupsHeading') + '</h2>' +
      kit.note(t.html('consoleClaims.groupsNoteA') +
      '<a href="/admin/groups">' +
      t.html('consoleClaims.linkEmbeddedDirectory') + '</a>' +
      t.html('consoleClaims.groupsNoteB')) +

      '<div class="' + (state.enabled && !state.problem ? 'note' : 'warn') +
      '">' +
      (state.enabled
        ? (state.problem
            ? '<strong>On, and not arriving.</strong> ' +
              kit.esc(state.problem)
            : t.html('consoleClaims.groupsOn',
                     { claim: state.claim,
                       form: state.valueForm === 'dn' ? 'dn' : 'cn',
                       counts: state.memberOfCounts ? 'yes' : 'no' }))
        : t.html('consoleClaims.groupsOff')) +
      t.html('consoleClaims.groupsChangeA') +
      '<a href="/admin/groups">' + t.html('consoleClaims.linkGroupsPage') +
      '</a>' + t.html('consoleClaims.groupsChangeB') +
      kit.codeList(state.settings) + '.' +
      (state.loaded ? '' : t.html('consoleClaims.directoryNotLoaded')) +
      '</div>' +

      kit.warn(t.html('consoleClaims.notGrantingA') +
      '<a href="/admin/groups">' + t.html('consoleClaims.linkGroupsPage') +
      '</a>' + t.html('consoleClaims.notGrantingB')) +

      kit.note(t.html('consoleClaims.typedWins')) +

      '<h3>' + t.html('consoleClaims.wouldGet', { user: previewUser }) +
      '</h3>' +
      values +
      (answer.groups.length
        ? '<table><tr><th>' + t.html('consoleClaims.colGroup') +
          '</th><th>cn</th><th>' + t.html('consoleClaims.colNamedBy') +
          '</th><th>' + t.html('consoleClaims.colCounted') + '</th></tr>' +
          rows + '</table>'
        : kit.note(t.html('consoleClaims.noGroup',
                          { user: previewUser,
                            found: answer.entryFound ? 'yes' : 'no',
                            dn: answer.dn })));
  }

  /**
   * Draws the notes on where a directory attribute's value comes from and
   * what it does not do: one catalogue, independent selections, nesting,
   * which name wins, and that nothing here is verified.
   *
   * @param family - "jwt", "saml" or "userinfo"
   * @param t - the page's translator (#539)
   * @returns the heading and notes as HTML
   */
  static attributeCatalogueNotes(family, t) {
    const saml = family === 'saml';
    // THE OTHER PAGES, AS A LIST, because there are three of them now and there
    // were two when this was written. It said "the other page" and named one,
    // which was a sentence that could only ever be right while the number was
    // two — and the day a third arrived it would have gone on reading correctly
    // while telling a reader that one of the two places their selection does
    // NOT apply is the only one. Derived from `family` in one place so that a
    // fourth page is one entry rather than three sentences to find.
    const userinfoPage = '<a href="/admin/userinfo-claims">' +
      t.html('consoleClaims.pageUserinfo') + '</a>';
    const samlPage = '<a href="/admin/saml-attributes">' +
      t.html('consoleClaims.pageSaml') + '</a>';
    const claimsPage = '<a href="/admin/claims">' +
      t.html('consoleClaims.pageClaims') + '</a>';
    const OTHER_PAGES = {
      jwt: [userinfoPage, samlPage],
      userinfo: [claimsPage, samlPage],
      saml: [claimsPage, userinfoPage]
    };
    // What the other pages' carriers are, as the `family` a message selects
    // on (#539): the words are the catalog's.
    const otherPage = (OTHER_PAGES[family] || OTHER_PAGES.jwt)
      .join(t.html('consoleClaims.and'));
    return '<h2>' + t.html('consoleClaims.catalogueHeading') + '</h2>' +
      kit.note(t.html('consoleClaims.catalogueA', { family: family }) +
      otherPage + t.html('consoleClaims.and') + '<a href="/admin/vc">' +
      t.html('consoleClaims.linkCredentialClaims') + '</a>' +
      t.html('consoleClaims.catalogueB')) +
      kit.note(t.html('consoleClaims.selectionsA', { family: family }) +
      otherPage + t.html('consoleClaims.selectionsB') +
      '<a href="/admin/vc">' + t.html('consoleClaims.linkCredential') +
      '</a>' + t.html('consoleClaims.selectionsC') +
      '<a href="/admin/vc-verifier-config">' +
      t.html('consoleClaims.linkVerifierAsks') + '</a>' +
      t.html('consoleClaims.selectionsD')) +
      (saml
        ? kit.note(t.html('consoleClaims.nestedSaml'))
        : kit.note(t.html('consoleClaims.nestedJwt'))) +
      kit.note(t.html('consoleClaims.typedSameName', { family: family })) +
      (saml
        ? kit.note(t.html('consoleClaims.protocolWinsSaml'))
        : kit.note(t.html('consoleClaims.protocolWinsJwt'))) +
      kit.note(t.html('consoleClaims.notVerified') +
      '<a href="/admin/groups">' + t.html('consoleClaims.linkGroupsPage') +
      '</a>.');
  }

  /**
   * Draws the Values section: which placeholders a value may carry, and
   * whether a value is typed (JWT, UserInfo) or always text (SAML).
   *
   * @param family - "jwt", "saml" or "userinfo"
   * @param t - the page's translator (#539)
   * @returns the heading and notes as HTML
   */
  static claimValueNotes(family, placeholders, t) {
    const saml = family === 'saml';
    // `${...}` placeholders hold braces and `{"a":1}` holds quotes a parameter
    // would escape, so the first go in as parameters and the second stays in
    // the code between two messages (#539).
    const ph = { ph: '${placeholders}', username: '${username}',
                 email: '${email}', subject: '${subject}', dept: '${dept}' };
    return '<h2>' + t.html('consoleClaims.valuesHeading') + '</h2>' +
      kit.note(t.html('consoleClaims.valuesA',
                      { ph: ph.ph, family: family }) +
      (saml
        ? t.html('consoleClaims.valuesSamlA') +
          kit.codeList(SAML_PLACEHOLDERS) +
          t.html('consoleClaims.valuesSamlB') +
          '<a href="/admin/claims">' + t.html('consoleClaims.linkTokenPage') +
          '</a>' +
          t.html('consoleClaims.valuesSamlC',
                 { username: ph.username, email: ph.email,
                   subject: ph.subject })
        : t.html('consoleClaims.valuesJwt') + kit.codeList(placeholders) +
          '.') +
      t.html('consoleClaims.valuesUnknown', { dept: ph.dept })) +
      (saml
        ? kit.note(t.html('consoleClaims.samlUntypedA') + '{"a":1}' +
          t.html('consoleClaims.samlUntypedB'))
        : kit.note(t.html('consoleClaims.jwtTypedA', { family: family }) +
          '<a href="/admin/saml-attributes">' +
          t.html('consoleClaims.linkSamlValues') + '</a>' +
          t.html('consoleClaims.jwtTypedB')));
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
   * @param t - the page's translator (#539)
   * @returns the heading, note and form as HTML
   */
  static replaceSetForm(sets, pageUrl, family, t) {
    const options = sets.map(function (one) {
      return '<option value="' + kit.esc(one.id) + '">' +
             kit.esc(one.label) + '</option>';
    }).join('');
    return '<h2>' + t.html('consoleClaims.replaceHeading') + '</h2>' +
      kit.note(t.html('consoleClaims.replaceNote', { family: family })) +
      '<form method="post" action="' + kit.esc(pageUrl) + '">' +
        '<input type="hidden" name="action" value="replace">' +
        '<div class="formrow"><label for="set">' +
        t.html('consoleClaims.set') + '</label>' +
        '<select id="set" name="set">' + options + '</select></div><textarea ' +
        'name="claims" spellcheck="false">[{"name": "dept", "value": ' +
        '"engineering"}, {"name": "on_behalf_of", "value": ' +
        '"${username}"}]</textarea><div ' +
        'class="formrow"><button>' + t.html('consoleClaims.replace') +
        '</button></div></form>';
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static samlAttributesBody(ctx, json) {
    const t = ctx.t;
    const pageUrl = '/admin/saml-attributes?user=' +
                    encodeURIComponent(json.preview.user);
    const values = json.preview;

    const inner = kit.note(t.html('consoleClaims.samlIntro')) +

      kit.note(t.html('consoleClaims.samlWhereA') + '<a ' +
      'href="/admin/sts-metadata">WS-Trust</a>' +
      t.html('consoleClaims.samlWhereB')) +

      kit.note(t.html('consoleClaims.samlNextA') + '<a ' +
      'href="/admin/claims">' + t.html('consoleClaims.linkCustomClaims') +
      '</a>' + t.html('consoleClaims.samlNextB') + '<a ' +
      'href="/admin/userinfo-claims">' +
      t.html('consoleClaims.linkUserinfoClaims') + '</a>' +
      t.html('consoleClaims.samlNextC') + '<a href="/admin/audit">' +
      t.html('consoleClaims.linkAuditLog') + '</a>' +
      t.html('consoleClaims.perChange')) +

      ClaimsPage.claimHalvesNote('saml', t) +

      ClaimsPage.claimPreviewForm('/admin/saml-attributes', json.preview.user,
                            values, t) +

      kit.warn(t.html('consoleClaims.samlAdditiveA') +
      '<a href="/admin/claims">' + t.html('consoleClaims.linkClaimsPage') +
      '</a>' + t.html('consoleClaims.samlAdditiveB')) +

      '<h2>' + t.html('consoleClaims.samlSetsHeading') + '</h2>' +
      json.sets.map(function (set) {
        return ClaimsPage.claimSetSection(set.id, json, pageUrl, t);
      }).join('') +

      ClaimsPage.groupClaimSection(json.groups, json.preview.user, t) +

      ClaimsPage.attributeCatalogueNotes('saml', t) +

      ClaimsPage.claimValueNotes('saml', json.placeholders, t) +

      '<h2>' + t.html('consoleClaims.samlNsHeading') + '</h2>' +
      kit.note(t.html('consoleClaims.samlNs',
                      { ns: json.defaultSaml11Namespace })) +

      ClaimsPage.replaceSetForm(json.sets, pageUrl, 'saml', t);

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
    const t = ctx.t;
    const raw = json.request;
    const pageUrl = '/admin/userinfo-claims?user=' +
                    encodeURIComponent(json.preview.user) +
                    (raw ? '&request=' + encodeURIComponent(raw) : '');
    // ONE read of the directory for the whole page, exactly as /admin/claims
    // does: the set's table and the request preview describe the same person,
    // and two reads of one entry could answer one page with two versions of
    // them.
    const values = json.preview;

    // The JSON examples hold quotes a parameter would escape, so they stay in
    // the code between two messages (#539).
    const inner = kit.note(t.html('consoleClaims.uiIntro')) +

      kit.note(t.html('consoleClaims.uiNextA') + '<a href="/admin/claims">' +
      t.html('consoleClaims.linkCustomClaims') + '</a>' +
      t.html('consoleClaims.uiNextB') + '<a ' +
      'href="/admin/saml-attributes">' +
      t.html('consoleClaims.linkSamlAttributes') + '</a>' +
      t.html('consoleClaims.uiNextC') + '<a href="/admin/audit">' +
      t.html('consoleClaims.linkAuditLog') + '</a>' +
      t.html('consoleClaims.perChange')) +

      ClaimsPage.claimHalvesNote('userinfo', t) +

      ClaimsPage.claimPreviewForm('/admin/userinfo-claims', json.preview.user,
                            values, t) +

      kit.warn(t.html('consoleClaims.uiAdditiveA') +
      kit.codeList(json.reservedJwtClaims) +
      t.html('consoleClaims.uiAdditiveB') + '<a href="/admin/claims">' +
      t.html('consoleClaims.linkClaimsPage') + '</a>' +
      t.html('consoleClaims.uiAdditiveC') +
      '<a href="/admin/saml-attributes">' +
      t.html('consoleClaims.linkSamlPage') + '</a>' +
      t.html('consoleClaims.uiAdditiveD')) +

      '<h2>' + t.html('consoleClaims.uiSetHeading') + '</h2>' +
      json.sets.map(function (set) {
        return ClaimsPage.claimSetSection(set.id, json, pageUrl, t);
      }).join('') +

      ClaimsPage.groupClaimSection(json.groups, json.preview.user, t) +

      '<h2>' + t.html('consoleClaims.uiAskHeading') + '</h2>' +
      kit.note(t.html('consoleClaims.uiOneSetA') + '<a ' +
      'href="/.well-known/openid-configuration">' +
      t.html('consoleClaims.linkDiscovery') + '</a>' +
      t.html('consoleClaims.uiOneSetB')) +

      kit.note(t.html('consoleClaims.uiLayersA') + '{"email":null}' +
      t.html('consoleClaims.uiLayersB', { email: json.inventedEmail })) +

      ClaimsPage.requestableClaimsSection(json.claimsRequest, t) +

      '<h3>' + t.html('consoleClaims.uiTryHeading') + '</h3>' +
      ClaimsPage.claimsRequestSection(json.preview.user, raw,
                                json.claimsRequest, t) +

      kit.tip(t.html('consoleClaims.uiNonSpecA') +
      '{"userinfo":{"birthdate":null}}' +
      t.html('consoleClaims.uiNonSpecB')) +

      kit.warn(t.html('consoleClaims.uiEssential')) +

      ClaimsPage.attributeCatalogueNotes('userinfo', t) +

      ClaimsPage.claimValueNotes('userinfo', json.placeholders, t) +

      ClaimsPage.replaceSetForm(json.sets, pageUrl, 'userinfo', t);

    return inner;
  }

  // The vocabulary table: every name a client may put in a claims request.
  /**
   * Draws the table of every claim name a client may put in a claims
   * request, with the attribute each is answered from.
   *
   * @param t - the page's translator (#539)
   * @returns the heading, note and table as HTML
   */
  static requestableClaimsSection(claimsRequest, t) {
    const rows = claimsRequest.requestable.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.claim) + '</code></td><td>' +
        (row.grouped ? t.html('consoleClaims.wholeClaim')
                     : kit.esc(row.label)) +
        '</td><td><code>' + kit.esc(row.ldap) + '</code></td></tr>';
    }).join('');
    const persona = claimsRequest.fromTheSignIn.map(function (name) {
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td>' +
        t.html('consoleClaims.inventedAtSignIn') + '</td><td><span ' +
        'class="state-none">&mdash;</span></td></tr>';
    }).join('');
    return '<h3>' + t.html('consoleClaims.reqHeading') + '</h3>' +
      kit.note(t.html('consoleClaims.reqNote')) +
      '<table><tr><th>' + t.html('consoleClaims.colClaim') + '</th><th>' +
      t.html('consoleClaims.colWhatItIs') + '</th><th>' +
      t.html('consoleClaims.colFromAttribute') + '</th></tr>' +
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
   * @param t - the page's translator (#539)
   * @returns the form and its answer as HTML
   */
  static claimsRequestSection(previewUser, raw, claimsRequest, t) {
    const preview = claimsRequest.preview;
    const form = '<form method="get" action="/admin/userinfo-claims">' +
      '<input type="hidden" name="user" value="' + kit.esc(previewUser) +
      '"><div class="formrow"><label for="request">' +
      t.html('consoleClaims.aClaimsRequest') +
      '</label><input type="text" id="request" name="request" ' +
      'size="72" spellcheck="false" value="' +
      kit.esc(raw) + '" ' +
      'placeholder=\'{"userinfo":{"birthdate":null,"address":null}}\'>' +
      '<button ' +
      'class="secondary">' + t.html('consoleClaims.showReturns') +
      '</button></div></form>';

    if (!preview.asked) {
      return form + kit.note(t.html('consoleClaims.nothingAsked',
                                    { user: previewUser }));
    }
    // A refusal, shown as the client would be told it: a refusal's words
    // stay English (#539).
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
        ? kit.warn(t.html('consoleClaims.ignoredA') +
          kit.codeList(preview.ignoredMembers) +
          t.html('consoleClaims.ignoredB') +
          kit.codeList(claimsRequest.members) + '.')
        : '') +
      (preview.idTokenNames.length
        ? kit.note(t.html('consoleClaims.idTokenA') +
          kit.codeList(preview.idTokenNames) +
          t.html('consoleClaims.idTokenB'))
        : '') +
      (rows
        ? '<table><tr><th>' + t.html('consoleClaims.colAskedFor') +
          '</th><th>' + t.html('consoleClaims.colClaimReturned') +
          '</th><th>' + t.html('consoleClaims.colFromAttribute') +
          '</th><th>' + t.html('consoleClaims.colValueFor',
                               { user: previewUser }) +
          '</th><th>' + t.html('consoleClaims.colSource') + '</th></tr>' +
          rows +
          '</table>'
        : kit.note(t.html('consoleClaims.nothingResolves'))) +
      (preview.unresolvable.length
        ? kit.note(t.html('consoleClaims.absentA') +
          kit.codeList(preview.unresolvable) +
          t.html('consoleClaims.absentB',
                 { n: preview.unresolvable.length }))
        : '') +
      (preview.essentialAndAbsent.length
        ? kit.warn(t.html('consoleClaims.essentialA') +
          kit.codeList(preview.essentialAndAbsent) +
          t.html('consoleClaims.essentialB'))
        : '') +
      (preview.valueMismatches.length
        ? kit.warn(t.html('consoleClaims.mismatchA') +
          kit.esc(preview.valueMismatches.join('; ')) +
          t.html('consoleClaims.mismatchB'))
        : '') +
      kit.note((preview.entryFound
        ? t.html('consoleClaims.requestEntryFound', { user: previewUser })
        : t.html('consoleClaims.requestNoEntry', { user: previewUser })));
  }

  // ---------------------------------------------------------------------------
  // THE KERBEROS PAC CLAIMS PAGE (#493), `/admin/kerberos/claims`, drawn from
  // `GET /admin-api/kerberos/claims`. The sixth set of the same store, with
  // the two things only a PAC claim has: a TYPE on every row (the four of
  // [MS-ADTS] 2.2.18.2) and a claim ID, `ad://ext/<name>:<hex>`, derived from
  // the row's name and shown beside it so a service's access rule can be
  // written against it. Since #498 it has the catalogue half the other pages
  // have, drawn by claimAttributeSection() from the same members of the
  // reply: the ticked attributes are string claims of every value on the
  // entry, under the rows.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/kerberos/claims`: the PAC claim set with its claim ids, the
   * forms that change it and one person's preview.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/kerberos/claims`
   * @returns the body as HTML
   */
  static kerberosClaimsBody(ctx, json) {
    const t = ctx.t;
    const set = json.sets[0];
    const setId = set.id;
    const pageUrl = '/admin/kerberos/claims?user=' +
                    encodeURIComponent(json.preview.user);
    const typeOptions = function () {
      return json.types.map(function (type) {
        return '<option value="' + kit.esc(type) + '">' + kit.esc(type) +
               '</option>';
      }).join('');
    };
    const rows = set.claims.map(function (claim) {
      return '<tr><td><code>' + kit.esc(claim.name) + '</code><br><span ' +
        'class="sub"><code>' + kit.esc(claim.claimId) + '</code></span></td>' +
        '<td>' + kit.esc(claim.type || 'string') + '</td><td>' +
        (claim.attribute
          ? '&larr; <code>' + kit.esc(claim.attribute) + '</code><span ' +
            'class="sub">' + t.html('consoleClaims.directoryAttribute') +
            (claim.multi ? t.html('consoleClaims.everyValueSuffix') : '') +
            '</span>'
          : '<code>' + kit.esc(claim.value) + '</code>') + '</td><td>' +
        (ctx.write
          ? '<form method="post" action="' + kit.esc(pageUrl) +
            '" class="inline"><input type="hidden" name="action" ' +
            'value="remove"><input type="hidden" name="set" value="' +
            kit.esc(setId) + '"><input type="hidden" name="name" value="' +
            kit.esc(claim.name) + '"><button class="secondary">' +
            t.html('consoleClaims.remove') + '</button></form>'
          : '') + '</td></tr>';
    }).join('');
    const preview = json.preview.claims.length
      ? '<table><tr><th>' + t.html('consoleClaims.colClaimId') + '</th><th>' +
        t.html('consoleClaims.colType') + '</th><th>' +
        t.html('consoleClaims.colValues') + '</th>' +
        '<th>' + t.html('consoleClaims.colFrom') + '</th></tr>' +
        json.preview.claims.map(function (claim) {
          return '<tr><td><code>' + kit.esc(claim.id) + '</code></td><td>' +
            kit.esc(claim.type) + '</td><td><code>' +
            kit.esc(claim.values.join(', ')) + '</code></td><td>' +
            kit.esc(claim.from) + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('consoleClaims.pacNothing') + '</p>';
    // The precedence and the claim-id format are the view's sentences, drawn
    // as they come (#539).
    return (json.enabled
      ? kit.note(t.html('consoleClaims.pacOn', { setting: json.setting }))
      : kit.warn(t.html('consoleClaims.pacOff', { setting: json.setting }) +
        '<a href="/admin/kerberos">' +
        t.html('consoleClaims.linkKerberosSettings') + '</a>.')) +
      kit.note(t.html('consoleClaims.pacNoteA') +
        kit.esc(json.precedence) + t.html('consoleClaims.pacNoteB')) +
      '<h2>' + kit.esc(set.label) + ' <code>' + kit.esc(setId) + '</code>' +
      '</h2><table><tr><th>' + t.html('consoleClaims.colNameAndId') +
      '</th><th>' + t.html('consoleClaims.colType') + '</th><th>' +
      t.html('consoleClaims.colValue') +
      '</th><th></th></tr>' + (rows || '<tr><td colspan="4">' +
        t.html('consoleClaims.pacNoClaims') + '</td></tr>') + '</table>' +
      kit.note(t.html('consoleClaims.claimIdIs') + kit.esc(json.idFormat)) +
      (ctx.write
        ? '<form method="post" action="' + kit.esc(pageUrl) + '"><div ' +
          'class="formrow"><input type="hidden" name="action" value="add">' +
          '<input type="hidden" name="set" value="' + kit.esc(setId) + '">' +
          '<label for="kn">' + t.html('consoleClaims.name') +
          '</label><input type="text" id="kn" ' +
          'name="name" size="20" placeholder="department">' +
          '<label for="kt">' + t.html('consoleClaims.type') +
          '</label><select id="kt" name="type">' +
          typeOptions() + '</select><label for="kv">' +
          t.html('consoleClaims.value') + '</label>' +
          '<input type="text" id="kv" name="value" size="28" ' +
          'placeholder="${username}"><button>' + t.html('consoleClaims.add') +
          '</button></div></form>' +
          '<form method="post" action="' + kit.esc(pageUrl) + '"><div ' +
          'class="formrow"><input type="hidden" name="action" ' +
          'value="add-attribute-claim"><input type="hidden" name="set" ' +
          'value="' + kit.esc(setId) + '"><label for="kan">' +
          t.html('consoleClaims.name') + '</label>' +
          '<input type="text" id="kan" name="name" size="20"><label ' +
          'for="kaa">' + t.html('consoleClaims.fromAttribute') +
          '</label><input type="text" id="kaa" ' +
          'name="attribute" size="20" placeholder="' +
          kit.esc(t.text('consoleClaims.egDepartmentNumber')) + '" ' +
          'list="kac"><datalist id="kac">' +
          json.attributeChoices.map(function (one) {
            return '<option value="' + kit.esc(one.attribute) + '">';
          }).join('') + '</datalist><label><input type="checkbox" ' +
          'name="multi" value="true"> ' + t.html('consoleClaims.everyValue') +
          '</label><label ' +
          'for="kat">' + t.html('consoleClaims.as') +
          '</label><select id="kat" name="type">' +
          typeOptions() + '</select><button>' + t.html('consoleClaims.add') +
          '</button></div></form>' +
          (set.claims.length
            ? '<form method="post" action="' + kit.esc(pageUrl) +
              '" class="inline"><input type="hidden" name="action" ' +
              'value="clear"><input type="hidden" name="set" value="' +
              kit.esc(setId) + '"><button class="secondary">' +
              t.html('consoleClaims.clearSet') + '</button></form>'
            : '')
        : '') +
      kit.note(t.html('consoleClaims.pacPlaceholdersA') +
        kit.codeList(json.placeholders) +
        t.html('consoleClaims.pacPlaceholdersB')) +
      '<h2>' + t.html('consoleClaims.dirAttrsHeading') + '</h2>' +
      kit.note(t.html('consoleClaims.pacTick')) +
      ClaimsPage.claimAttributeSection(setId, json, pageUrl, t) +
      '<h2>' + t.html('consoleClaims.tgtHeading') + '</h2>' +
      '<form method="get" action="/admin/kerberos/claims"><div ' +
      'class="formrow"><label for="kuser">' + t.html('consoleClaims.for') +
      '</label><input type="text" ' +
      'id="kuser" name="user" size="20" value="' +
      kit.esc(json.preview.user) + '"><button class="secondary">' +
      t.html('consoleClaims.show') + '</button></div></form>' + preview +
      kit.note(t.html('consoleClaims.tgtNote'));
  }
}

export = ClaimsPage;
