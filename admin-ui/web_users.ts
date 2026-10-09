// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_users.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → USERS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/users` from the answer of `GET /admin-api/users`: everybody
// this realm knows about, from the directory and from what it has seen,
// filtered by name, protocol and second factor, and paged.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:usersListPage` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import ApplicationsPage = require('./web_applications');
import GroupsPage = require('./web_groups');
import TokensPage = require('./web_tokens');

type Json = any;

// THE PAGE'S TRANSLATOR, ESCAPING AS THIS PAGE ALWAYS ESCAPED (#539). A
// name, a DN, a reason from the view fills many of these messages, and an
// apostrophe in one was drawn by `kit.esc()` as `&apos;` where the
// translator's escaping writes `&#39;`: the same character in different
// bytes, and the console's browser jobs compare bytes. So a message WITH
// parameters has its `&#39;` written as `&apos;`; no message of this
// page's catalog carries a literal `&#39;` for this to change. Every other
// member is the translator's own, through the prototype, and wrapping a
// wrapped translator changes nothing.
const kitEscaping = function (translator: Json): Json {
  const wrapped = Object.create(translator);
  wrapped.html = function (key: string, params?: Json): string {
    const out = translator.html(key, params);
    return params ? out.replace(/&#39;/g, '&apos;') : out;
  };
  return wrapped;
};

// The application section's sentences, said about a person: who holds the
// private key is the one thing that changes.
// A function of the page's translator since #539, built once per draw.
const personKeySourceSentences = function (t: Json): Json {
  return {
    'issued': t.html('consoleUsers.keySource.issued'),
    'uploaded-realm-ca': t.html('consoleUsers.keySource.uploadedRealmCa'),
    'uploaded-external-ca':
      t.html('consoleUsers.keySource.uploadedExternalCa'),
    'unrecorded': t.html('consoleUsers.keySource.unrecorded')
  };
};

/**
 * Draws `/admin/users` from the answer of `GET /admin-api/users`: everybody
 * this realm knows about, from the directory and from what it has seen,
 * filtered by name, protocol and second factor, and paged.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
// THE IDENTITY VERIFICATION FORM'S TOOLTIPS (OpenID Connect for Identity
// Assurance 1.0), one per field: the element of `verified_claims` each fills,
// as `identity_assurance.ts`'s `fromForm()` builds it.
// A function of the page's translator since #539, built once per draw.
const idaTips = function (t: Json): Json {
  return {
    framework: t.text('consoleUsers.idaTips.framework'),
    level: t.text('consoleUsers.idaTips.level'),
    time: t.text('consoleUsers.idaTips.time'),
    evidence: t.text('consoleUsers.idaTips.evidence'),
    check: t.text('consoleUsers.idaTips.check'),
    documentType: t.text('consoleUsers.idaTips.documentType'),
    documentNumber: t.text('consoleUsers.idaTips.documentNumber'),
    issuer: t.text('consoleUsers.idaTips.issuer'),
    country: t.text('consoleUsers.idaTips.country'),
    issued: t.text('consoleUsers.idaTips.issued'),
    expires: t.text('consoleUsers.idaTips.expires'),
    recordType: t.text('consoleUsers.idaTips.recordType'),
    recordSource: t.text('consoleUsers.idaTips.recordSource'),
    vouchType: t.text('consoleUsers.idaTips.vouchType'),
    reference: t.text('consoleUsers.idaTips.reference'),
    voucher: t.text('consoleUsers.idaTips.voucher'),
    signatureType: t.text('consoleUsers.idaTips.signatureType'),
    signatureIssuer: t.text('consoleUsers.idaTips.signatureIssuer'),
    serial: t.text('consoleUsers.idaTips.serial'),
    created: t.text('consoleUsers.idaTips.created')
  };
};

// THE DIRECTORY ENTRY TAB'S THREE ONE-ATTRIBUTE FORMS' TOOLTIPS, by the
// action's first word.
// A function of the page's translator since #539, built once per draw.
const entryTips = function (t: Json): Json {
  return {
    set: { attribute: t.text('consoleUsers.entryTips.setAttribute'),
           value: t.text('consoleUsers.entryTips.setValue'),
           button: t.text('consoleUsers.entryTips.setButton') },
    add: { attribute: t.text('consoleUsers.entryTips.addAttribute'),
           value: t.text('consoleUsers.entryTips.addValue'),
           button: t.text('consoleUsers.entryTips.addButton') },
    remove: { attribute: t.text('consoleUsers.entryTips.removeAttribute'),
              value: t.text('consoleUsers.entryTips.removeValue'),
              button: t.text('consoleUsers.entryTips.removeButton') }
  };
};

class UsersPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its translator's (#539 phase 6); what the view
    // carries — names, protocols, realms — is drawn as it comes.
    const t = kitEscaping(ctx.t);
    const wantedText = json.filter.q || '';
    const wantedProtocol = json.filter.protocol || '';
    const wantedFactor = json.filter.factor || '';
    // #221: service accounts only, or everybody else.
    const wantedKind = json.filter.kind || '';
    const paging = json.paging;
    const shown = json.users;
    const factorCounts = json.factors;
    const filterParams = { q: wantedText, protocol: wantedProtocol,
                           factor: wantedFactor, kind: wantedKind,
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/users', filterParams, paging);
    // THE FILTER FORM'S TOOLTIPS, each on its label and its control.
    const tips = {
      q: kit.tip(t.text('consoleUsers.body.tipQ')),
      protocol: kit.tip(t.text('consoleUsers.body.tipProtocol')),
      factor: kit.tip(t.text('consoleUsers.body.tipFactor')),
      kind: kit.tip(t.text('consoleUsers.body.tipKind')),
      per: kit.tip(t.text('consoleUsers.body.tipPer')),
      filter: kit.tip(t.text('consoleUsers.body.tipFilter')),
      create: kit.tip(t.text('consoleUsers.body.tipCreate'))
    };

    // Sessions are counted per user here rather than fetched per row inside the
    // loop: one pass over the session map instead of one per user, and more
    // importantly one definition of "active" for the list and the drill-down
    // both.
    const listView = kit.listViewOf('/admin/users', ctx.query);
    const rows = shown.map(function (row) {
      // The link carries the list AS IT IS BEING VIEWED, which is what lets the
      // trail on the other side come back to this page of this filter rather
      // than to the top of everything. See kit.listViewOf().
      const href = '/admin/users' + kit.queryWith(listView, { user: row.key });
      // Shortened for the same reason the metrics page's Who column is, and the
      // Decentralized Identity endpoints are what made it reach this table too:
      // a did:jwk is a couple of hundred characters of base64url with not one
      // place in it a browser will break a line, so drawn in full it sets this
      // cell's minimum width and pushes every column after it off the card —
      // including the rows of people whose names are three letters long. 40
      // keeps an ordinary DID whole, and shortens a `urn:uuid:` subject (45
      // characters); kit.shortened() puts the rest in the title attribute, so
      // nothing is lost, only hidden. THREE CELLS ARRIVED ON 2026-09-10 WITH
      // THE ROSTER `/admin/mfa` USED TO DRAW: where the row came from, what the
      // person can sign in WITH, and what they are asked for as a SECOND
      // factor. They are here rather than on a page of their own because the
      // question *who holds no second factor* is a question about the people
      // this table already lists, and a second table of the same people would
      // be a second answer to who they are.
      // A SERVICE ACCOUNT IS TAGGED (#221): it is a person, so it is on this
      // list, and the tag is what tells a reader it is a program's account.
      return '<tr><td><a href="' + kit.esc(href) + '">' +
             kit.shortened(row.name, 40) +
        '</a>' + (row.serviceAccount
          ? ' <span class="tag" title="' +
            kit.esc(t.text('consoleUsers.body.serviceAccountTitle')) + '">' +
            t.html('consoleUsers.body.serviceAccount') + '</span>' : '') +
        '</td><td>' +
        UsersPage.sourceCell(t, row, json.registryKeeps) + '</td><td ' +
        'class="' + (row.authenticated ? 'state-valid' : 'state-none') + '">' +
          (row.authenticated ? row.authentications + '&times;' :
           t.html('consoleUsers.body.never')) + '</td><td>' +
           UsersPage.credentialCell(t, row.factors) +
           '</td><td>' +
        UsersPage.secondFactorCell(t, row.factors) + '</td><td>' +
        kit.esc(row.protocols.map(function (f) { return f.protocol; })
          .join(', ') ||
                 '—') + '</td><td>' +
        kit.esc(row.realms.map(function (r) { return r.realm; }).join(', ') ||
                 '—') +
        '</td><td ' +
        'class="num">' + row.liveSessions + '</td>' +
        '<td class="num">' + row.tokens.issued + '</td>' +
        '<td class="num state-valid">' + row.tokens.valid + '</td>' +
        // EXPIRED IS ITS OWN COLUMN. It was counted in userRows() and shown
        // nowhere, so this table drew "12 issued, 1 valid" and left the other
        // eleven to be read as revoked, forgotten or broken. They are none of
        // those: a token whose lifetime ran out is the ordinary end of a token,
        // and it is the specific thing somebody comes to this page to check
        // after a client started being refused. Same clock as everywhere else —
        // tokenStateOf(), which applies oauth2.clockSkewS.
        '<td class="num state-expired">' + row.tokens.expired + '</td>' +
        '<td class="num state-revoked">' + row.tokens.revoked + '</td>' +
        '<td class="num">' + row.artifacts + '</td>' +
        '<td>' + kit.esc(row.firstAt ? kit.whenText(row.firstAt) : '—') +
        '</td><td>' + kit.esc(kit.whenText(row.lastActivityAt)) + '</td>' +
        '<td><a href="' + kit.esc(href) + '">' +
        t.html('consoleUsers.body.sessionsAndTokens') + '</a></td></tr>';
    }).join('');

    const protocolOptions = [''].concat(json.protocols)
                                .map(function (p) {
      return '<option value="' + kit.esc(p) + '"' +
             (p === wantedProtocol ? ' ' +
          'selected' : '') + '>' +
             kit.esc(p || t.text('consoleUsers.body.anyProtocol')) +
             '</option>';
    }).join('');
    const perOptions = kit.perPageOptions(paging.perPage);

    // THE SECOND-FACTOR COUNTS (2026-09-10), over the WHOLE population rather
    // than the page. A tile that counted one page of twenty would answer a
    // question nobody asked. Since #352 they come from `peopleCensus()`, one
    // pass over the directory, and only the rows drawn below are decorated —
    // `admin-core/CLAUDE.md`, *The users list pages before it decorates*.
    const inner = '<div class="tiles">' +
        kit.tile(json.known, t.text('consoleUsers.body.tilePeople')) +
        kit.tile(json.authenticatedHere,
                 t.text('consoleUsers.body.tileAuthenticated')) +
        kit.tile(json.known - json.authenticatedHere,
                  t.text('consoleUsers.body.tileNeverHere')) +
        kit.tile(json.withActiveSession,
                 t.text('consoleUsers.body.tileActive')) +
        kit.tile(factorCounts.withSecond,
                 t.text('consoleUsers.body.tileSecond')) +
        kit.tile(factorCounts.passwordOnly,
                 t.text('consoleUsers.body.tilePasswordOnly')) +
        kit.tile(factorCounts.noCredential,
                 t.text('consoleUsers.body.tileNoWayIn')) +
      '</div>' +
      // ---------------------------------------------------------------------
      // WHAT THIS TABLE IS A LIST OF, AND IT CHANGED ON 2026-09-10.
      //
      // It was "every userid this service has been given as part of an
      // interaction that succeeded" — the SEEN registry, and the note said so.
      // It is the UNION of that with this realm's directory people now, because
      // the second-factor roster that used to live on `/admin/mfa` moved onto
      // these columns and that roster's whole value is the people who have
      // NEVER signed in. See peopleRows().
      // ---------------------------------------------------------------------
      kit.note(t.html('consoleUsers.body.everybody')) +
      (json.store
        ? ''
        : kit.warn(t.html('consoleUsers.body.noDirectory'))) +
      (json.capped
        ? kit.warn(t.html('consoleUsers.body.capped',
                          { scanned: String(json.scanned),
                            limit: String(json.scanLimit) }))
        : '') +
      // The "Show them" link carries an href, so it is code between two
      // pieces of the sentence.
      (factorCounts.unreadable
        ? kit.warn(t.html('consoleUsers.body.unreadable',
                          { count: String(factorCounts.unreadable) }) +
          '<a href="' +
          kit.esc('/admin/users' + kit.queryWith({ factor: 'unreadable' },
            {})) +
          '">' + t.html('consoleUsers.body.showThem') + '</a>.')
        : '') +
      // WHERE AN ISSUED SPIFFE IDENTITY LANDS ON THIS TABLE, said here because
      // the row it produces is easy to misread. It has an artifact and NO
      // authentication, so it falls in the "seen only as a subject" tile above
      // — which is exactly right and is what that tile has always been for.
      // Counting an issuance as a sign-in would be the wrong answer twice over:
      // receiving a credential is not presenting one, and an agent holding
      // FetchX509SVID open re-mints every half-lifetime, so one workload left
      // running overnight would read as several hundred authentications.
      kit.note(t.html('consoleUsers.body.spiffeBefore') +
      '<a href="/admin/ldap/directory">' +
      t.html('consoleUsers.body.theDirectory') + '</a>' +
      t.html('consoleUsers.body.spiffeAnd') + '<a href="/admin/spiffe">' +
      'SPIFFE</a>.') +
      kit.warn(t.html('consoleUsers.body.oneRow')) +

      '<form method="get" action="/admin/users"><div class="formrow">' +
        '<label for="q"' + tips.q + '>' +
        t.html('consoleUsers.body.nameContains') + '</label>' +
        '<input type="text" id="q" name="q" size="20"' + tips.q +
        ' value="' + kit.esc(wantedText) +
      '"><label ' +
        'for="protocol"' + tips.protocol + '>' +
        t.html('consoleUsers.body.authenticatedThrough') + '</label>' +
        '<select id="protocol" name="protocol"' + tips.protocol + '>' +
        protocolOptions + '</select>' +
        // THE SECOND-FACTOR FILTER (2026-09-10), which is what `/admin/mfa` was
        // for. `none` is the one an operator actually comes here to run, and it
        // is the reason this page's population had to widen: the people most
        // likely to hold no second factor are the ones who have never signed
        // in.
        '<label for="factor"' + tips.factor + '>' +
        t.html('consoleUsers.body.secondFactor') + '</label>' +
        '<select id="factor" name="factor"' + tips.factor + '>' +
        [['', t.text('consoleUsers.body.factorAnyState')],
         ['any', t.text('consoleUsers.body.factorHoldsOne')],
         ['totp', t.text('consoleUsers.body.factorTotp')],
         ['key', t.text('consoleUsers.body.factorKey')],
         ['none', t.text('consoleUsers.body.factorNone')],
         ['unreadable', t.text('consoleUsers.body.factorUnreadable')]].map(
             function (pair) {
          return '<option value="' + kit.esc(pair[0]) + '"' +
                 (wantedFactor === pair[0] ? ' selected' : '') + '>' +
                 kit.esc(pair[1]) + '</option>';
        }).join('') + '</select>' +
        // #221: a service account is a person, tagged; this narrows to
        // them, or leaves them out.
        '<label for="kind"' + tips.kind + '>' +
        t.html('consoleUsers.body.kind') + '</label>' +
        '<select id="kind" name="kind"' + tips.kind + '>' +
        [['', t.text('consoleUsers.body.kindEverybody')],
         ['service', t.text('consoleUsers.body.kindService')],
         ['person', t.text('consoleUsers.body.kindPerson')]]
          .map(function (pair) {
          return '<option value="' + kit.esc(pair[0]) + '"' +
                 (wantedKind === pair[0] ? ' selected' : '') + '>' +
                 kit.esc(pair[1]) + '</option>';
        }).join('') + '</select>' +
        '<label for="per"' + tips.per + '>' +
        t.html('consoleUsers.body.perPage') + '</label>' +
        '<select id="per" name="per"' + tips.per + '>' +
      perOptions + '</select><button ' +
        'class="secondary"' + tips.filter + '>' +
        t.html('consoleUsers.body.filter') + '</button>' +
        (wantedText || wantedProtocol || wantedFactor || wantedKind
          ? ' <a href="/admin/users">' + t.html('consoleUsers.body.clear') +
            '</a>'
          : '') +
      '</div></form>' +

      // ---------------------------------------------------------------------
      // THE ONE CONTROL ON THIS PAGE, AND SINCE 2026-09-06 IT IS A DOOR RATHER
      // THAN A DEED.
      //
      // It used to be a POST: type a name, press Create, and a person appeared
      // — with a full name, an email address, a date of birth, a street, a
      // locality, a region, a postal code and a nationality, all INVENTED. That
      // was the original design and it had a real justification (an entry has
      // to have values or an issued credential asserts nothing), but it meant
      // the console could create exactly one kind of person: a fictional one,
      // whose every detail then had to be corrected from outside this console.
      //
      // So the button now takes the reader to `/admin/users/new`, where every
      // field a person here has is a box, only the username is required, an
      // empty box records NO VALUE, the invented person is a button rather than
      // the default, and the person can be given a password or an activation
      // link at the moment they are created — none of which fits in a
      // `.formrow` under a table of everybody this service has ever seen.
      //
      // **IT IS A GET FORM AND NOT A POST**, which is what makes it a link with
      // a text box in front of it: nothing is written by pressing it, and the
      // typed name arrives as `?user=` on the page that does the writing. The
      // POST handler on this path is UNCHANGED and still creates — it is what
      // `POST /admin-api/users/create` mirrors (rule 7), and what a test
      // drives.
      // ---------------------------------------------------------------------
      '<form method="get" action="/admin/users/new">' +
        '<div class="formrow">' +
          '<label for="new-username"' + tips.create + '>' +
          t.html('consoleUsers.body.createAUser') +
          '</label>' +
          '<input type="text" id="new-username" name="user" size="20" ' +
                 'placeholder="' +
                 kit.esc(t.text('consoleUsers.body.usernameHint')) + '"' +
                 tips.create + '>' +
          '<button' + kit.tip(t.text('consoleUsers.body.tipGo')) +
          '>' + t.html('consoleUsers.body.createGo') + '</button>' +
        '</div>' +
        kit.note('<strong>' + t.html('consoleUsers.body.takesYou') +
        '<a href="/admin/users/new">' + t.html('consoleUsers.body.newUser') +
        '</a></strong>' + t.html('consoleUsers.body.takesYouRest',
                                 { count: json.personFieldCount })) +
        // THE REALM'S OWN CONTAINER, ASKED FOR RATHER THAN BUILT HERE. This
        // read `ou=users,` + the one base DN setting until 2026-08-25,
        // which is the NAMING CONTEXT and is the default realm's container
        // only: under /realm/acme the page named a DN in a different realm than
        // the one the button writes to, and named it on the very control whose
        // whole subject is where the entry goes. `ldap_server.js` answers the
        // question for the ambient realm, and the fallback is the old string
        // for the build with no directory loaded, where the slot is empty and
        // there is no realm to ask about anyway.
        kit.note(t.html('consoleUsers.body.putsAnEntry',
                        { container: json.newUserContainer })) +
      '</form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleUsers.body.thUser') + '</th><th>' +
      t.html('consoleUsers.body.thKnownFrom') + '</th><th>' +
      t.html('consoleUsers.body.thAuthenticated') + '</th><th>' +
      t.html('consoleUsers.body.thCanSignIn') + '</th><th>' +
      t.html('consoleUsers.body.thSecondFactor') + '</th><th>' +
      t.html('consoleUsers.body.thProtocols') + '</th><th>' +
      t.html('consoleUsers.body.thRealms') + '</th><th ' +
      'class="num">' + t.html('consoleUsers.body.thSessions') +
      '</th><th class="num">' + t.html('consoleUsers.body.thTokens') +
      '</th><th ' +
      'class="num">' + t.html('consoleUsers.body.thValid') +
      '</th><th class="num">' + t.html('consoleUsers.body.thExpired') +
      '</th><th ' +
      'class="num">' + t.html('consoleUsers.body.thRevoked') +
      '</th><th class="num">' + t.html('consoleUsers.body.thArtifacts') +
      '</th><th>' + t.html('consoleUsers.body.thFirstSeen') + '</th><th>' +
      t.html('consoleUsers.body.thLastActivity') + '</th><th></th></tr>' +
      (rows ||
       '<tr><td colspan="16">' + t.html('consoleUsers.body.nobodyMatches') +
       '</td></tr>') + '</table>' +
      nav.foot +
      // The numbers are parameters rather than a plural's `#`, which would
      // format them (1,000) where this page always drew them bare.
      kit.note(t.html('consoleUsers.body.matched', {
        matched: json.matched, one: json.matched === 1 ? 'yes' : 'no',
        known: json.known })) +
      kit.note(t.html('consoleUsers.body.inMemory',
                      { keeps: json.registryKeeps }));

    return inner;
  }

  // WHAT THIS PERSON CAN ACTUALLY GET IN WITH, which is a different question
  // from the Second factor column beside it and is the one an operator asks
  // first. A second factor is never a way in on its own — neither a one-time
  // code nor an `mfa` key — so a person with an entry, no password and no
  // `primary` key cannot sign in at all however much is enrolled on them. That
  // state is the ordinary one for somebody provisioned and not yet activated,
  // and saying "none" plainly is what sends the reader to the activation link
  // on their row.
  /**
   * Draws what a person can sign in with (a password and primary security
   * keys), or "nothing yet" when they hold neither.
   *
   * @param t - the page's translator
   * @param factors - the person's credential facts, or null when unknown
   * @returns the cell's HTML
   */
  static credentialCell(t, factors) {
    if (!factors) {
      return '<span class="state-none">' +
             t.html('consoleUsers.credentialCell.unknown') + '</span>';
    }
    const parts = [];
    if (factors.password) {
      parts.push(t.text('consoleUsers.credentialCell.password'));
    }
    if (factors.primaryKeys) {
      parts.push(t.text(factors.primaryKeys > 1
        ? 'consoleUsers.credentialCell.primaryKeys'
        : 'consoleUsers.credentialCell.primaryKey',
        { count: factors.primaryKeys }));
    }
    if (!parts.length) {
      return '<span class="state-expired" title="' +
        kit.esc(t.text('consoleUsers.credentialCell.nothingTitle')) +
        '">' + t.html('consoleUsers.credentialCell.nothingYet') + '</span>';
    }
    return kit.esc(parts.join(' + '));
  }

  // The Second factor cell, drawn the same way in the list and on the
  // drill-down so that the two cannot say different things about one person. It
  // is a function rather than two pieces of markup for the reason every other
  // shared cell here is one: this one carries the `unreadable` state, and a
  // second copy of that branch would be the copy that forgot it.
  /**
   * Draws a person's second factors (security keys and authenticator app),
   * marking an enrolment this process cannot read.
   *
   * @param t - the page's translator
   * @param factors - the person's credential facts, or null when unknown
   * @returns the cell's HTML, "none" when no second factor is required
   */
  static secondFactorCell(t, factors) {
    if (!factors) {
      return '<span class="state-none">' +
             t.html('consoleUsers.credentialCell.unknown') + '</span>';
    }
    if (!factors.mfaRequired) {
      return '<span class="state-none">' +
             t.html('consoleUsers.secondFactorCell.none') + '</span>';
    }
    // Each part is markup already (the cell joins them unescaped, as it
    // always did), so the words are drawn with t.html.
    const parts = [];
    if (factors.mfaKeys) {
      parts.push(t.html(factors.mfaKeys > 1
        ? 'consoleUsers.secondFactorCell.securityKeys'
        : 'consoleUsers.secondFactorCell.securityKey',
        { count: factors.mfaKeys }));
    }
    if (factors.totp) {
      parts.push(factors.totpUsable
        ? t.html('consoleUsers.secondFactorCell.totp')
        : '<span class="state-expired" title="' +
          kit.esc(t.text('consoleUsers.secondFactorCell.unreadableTitle', {
            why: (factors.totpDetail && factors.totpDetail.why) ||
                 t.text('consoleUsers.secondFactorCell.unusable') })) +
          '">' + t.html('consoleUsers.secondFactorCell.unreadable') +
          '</span>');
    }
    return parts.join(' + ');
  }

  // WHERE THIS ROW CAME FROM. Two sources and three answers, and the third —
  // both — is the ordinary one: nearly every door that creates a directory
  // entry also calls `stats.noteKnownIdentity()`. The interesting rows are the
  // ones that are only one, and they mean different things: DIRECTORY alone is
  // somebody the registry has forgotten or never held (it is capped at
  // `stats.MAX_USERS` and the directory is not), and SEEN alone is an identity
  // with no entry — a client, an LDAP bind DN, or a subject something was
  // issued for without anybody being present.
  /**
   * Draws where a users-list row came from: both, the directory alone, or
   * seen by this service alone.
   *
   * @param t - the page's translator
   * @param row - a row of the users list
   * @param registryKeeps - how many identities the registry keeps
   *   (`stats.MAX_USERS`)
   * @returns the cell's HTML
   */
  static sourceCell(t, row, registryKeeps) {
    const seen = !!(row.authenticated || row.knownBy !== 'directory');
    if (seen && row.inDirectory) {
      return '<span class="state-valid" title="' +
        kit.esc(t.text('consoleUsers.sourceCell.bothTitle')) +
                 '">' + t.html('consoleUsers.sourceCell.both') + '</span>';
    }
    if (row.inDirectory) {
      return '<span title="' +
        kit.esc(t.text('consoleUsers.sourceCell.directoryTitle',
                       { keeps: registryKeeps })) +
                 '">' + t.html('consoleUsers.sourceCell.directory') +
                 '</span>';
    }
    return '<span title="' +
      kit.esc(t.text('consoleUsers.sourceCell.seenTitle')) +
      '">' + t.html('consoleUsers.sourceCell.seen') + '</span>';
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static newUserBody(ctx, json) {
    // The page's words are its translator's (#539 phase 6); the fields,
    // their groups and the ways in are the view's and drawn as they come.
    const t = kitEscaping(ctx.t);
    const given = json.prefill || {};
    const values = given.fields || {};
    const username = json.username;
    const credential = json.credential;
    const realm = json.realm;
    const container = json.container;
    const development = !!json.offersExampleData;
    const view = String(given.view || '') === 'advanced' ? 'advanced'
      : 'simple';
    // THE BOXES' VALUES: a redraw ("+", the bin, the view switch) keeps every
    // box as it was, an empty one included; otherwise what was posted, or
    // what Fill invented.
    const gridValues = given.draft
      ? kit.gridValuesFromDraft(given.draft, json.longTextAttributes)
      : {};
    if (!given.draft) {
      Object.keys(values).forEach(function (name) {
        gridValues[name] = [].concat(values[name] === undefined ||
                                     values[name] === null
          ? [] : values[name]).map(String);
      });
    }

    // NO DIRECTORY IN THIS PROCESS. The form is left OUT rather than drawn and
    // refused, which is `newApplicationPage()`'s shape and is right for the
    // same reason: `createUser()` would answer with exactly this sentence, and
    // a form whose only possible outcome is that message is a control that lies
    // about what it does.
    let inner;
    if (!json.directory) {
      inner = kit.warn(t.html('consoleUsers.newUserBody.noDirBefore') +
        '<a href="/admin/users">' + t.html('consoleUsers.newUserBody.users') +
        '</a>' + t.html('consoleUsers.newUserBody.noDirAfter'));
    } else {

      inner = '<div class="tiles">' +
          kit.tile(UsersPage.newUserFieldRows(json, 'advanced').length,
                    t.text('consoleUsers.newUserBody.tileFields')) +
          kit.tile(1, t.text('consoleUsers.newUserBody.tileRequired')) +
          kit.tile(json.credentials.length,
                   t.text('consoleUsers.newUserBody.tileWaysIn')) +
          kit.tile(development ? t.text('consoleUsers.newUserBody.yes')
                               : t.text('consoleUsers.newUserBody.no'),
                   t.text('consoleUsers.newUserBody.tileExample')) +
        '</div>' +

        kit.note(t.html('consoleUsers.newUserBody.lands',
                        { container: container,
                          realm: realm ? realm.name : 'Default' })) +

        kit.note(t.html('consoleUsers.newUserBody.notSecondStore')) +

        // Two links in the warning, so it is three messages around them.
        kit.warn(t.html('consoleUsers.newUserBody.emptyBefore') +
        '<a href="/admin/users">' + t.html('consoleUsers.newUserBody.users') +
        '</a>' + t.html('consoleUsers.newUserBody.emptyMiddle') +
        '<a href="/admin/vc">' +
        t.html('consoleUsers.newUserBody.credentialClaims') + '</a>' +
        t.html('consoleUsers.newUserBody.emptyAfter')) +

        '<form method="post" action="/admin/users/new" class="newapp"><input ' +
        'type="hidden" name="action" value="create"><h2>' +
        t.html('consoleUsers.newUserBody.whoHeading') + '</h2><div ' +
        'class="formrow"><label for="new-username">' +
        t.html('consoleUsers.newUserBody.username') + '</label><input ' +
        'type="text" id="new-username" name="username" size="28" ' +
        'maxlength="256" required ' +
        'value="' + kit.esc(username) + '" placeholder="' +
        kit.esc(t.text('consoleUsers.newUserBody.usernameHint')) +
        '"></div>' +
        kit.note(t.html('consoleUsers.newUserBody.onlyRequired')) +

        '<h2>' + t.html('consoleUsers.newUserBody.howHeading') + '</h2>' +
        '<table><tr><th>' + t.html('consoleUsers.newUserBody.thChoose') +
        '</th><th>' + t.html('consoleUsers.newUserBody.thOption') +
        '</th><th>' + t.html('consoleUsers.newUserBody.thMeans') +
        '</th></tr>' +
        json.credentials.map(function (choice) {
          return UsersPage.credentialChoiceRow(choice, credential);
        }).join('') +
        '</table><div class="formrow"><label ' +
        'for="new-password">' + t.html('consoleUsers.newUserBody.password') +
        '</label><input type="password" ' +
        'id="new-password" name="password" size="28" maxlength="1024" ' +
        'autocomplete="new-password"><label ' +
        'for="new-password-confirm">' +
        t.html('consoleUsers.newUserBody.again') + '</label><input ' +
        'type="password" ' +
        'id="new-password-confirm" name="passwordConfirm" size="28" ' +
        'maxlength="1024" autocomplete="new-password"></div>' +
        // The policy link sits inside the <strong>, so the sentence is
        // messages around both.
        kit.note(t.html('consoleUsers.newUserBody.passwordReadOnly') +
        '<strong>' + t.html('consoleUsers.newUserBody.mustMeet') +
        '<a href="/admin/policies">' +
        t.html('consoleUsers.newUserBody.passwordPolicy') + '</a>' +
        (json.passwordPolicy && json.passwordPolicy.enforced
          ? '</strong>' + t.html('consoleUsers.newUserBody.enforcedHere',
              { rules: json.passwordPolicy.rules.join('; ') })
          : t.html('consoleUsers.newUserBody.inProductMode') + '</strong>' +
            t.html('consoleUsers.newUserBody.notChecked')) +
        t.html('consoleUsers.newUserBody.passwordRefused')) +
        kit.mailLinkBox(t.text('consoleUsers.newUserBody.activationLink'),
                        json.mailAvailable, t) +

        // A SERVICE ACCOUNT FROM THE START (#221): the box, its owner and its
        // push destination, checked before the person is created — so a
        // refused owner creates nobody.
        '<h2>' + t.html('consoleUsers.newUserBody.saHeading') + '</h2>' +
        '<div class="formrow"><label><input type="checkbox" ' +
        'name="serviceAccount" value="true"' +
        (given.serviceAccount === 'true' || given.serviceAccount === true
          ? ' checked' : '') + '> ' +
        t.html('consoleUsers.newUserBody.saLabel') + '</label></div>' +
        // The owner's placeholder was drawn unescaped (its apostrophe as
        // itself), so it is drawn as markup: a translation holds no quote.
        '<div class="formrow"><label>' +
        t.html('consoleUsers.newUserBody.owner') + ' <input ' +
        'type="text" name="owner" size="40" value="' +
        kit.esc(given.owner || '') + '" placeholder="' +
        t.html('consoleUsers.newUserBody.ownerHint') + '"></label></div>' +
        '<div class="formrow"><label>' +
        t.html('consoleUsers.newUserBody.destination') + ' <input ' +
        'type="text" ' +
        'name="destination" size="40" value="' +
        kit.esc(given.destination || '') + '"></label><label>' +
        t.html('consoleUsers.newUserBody.secretName') + ' ' +
        '<input type="text" name="secretName" size="28" value="' +
        kit.esc(given.secretName || '') + '"></label></div>' +
        kit.note(t.html('consoleUsers.newUserBody.saBefore') + '<a ' +
        'href="/admin/policies#serviceAccount">' +
        t.html('consoleUsers.newUserBody.saPolicy') + '</a>' +
        t.html('consoleUsers.newUserBody.saAfter')) +

        // THE FIELD GRID (rcbj, 2026-10-01): the same typed fields, under the
        // same group headings, as a person's Attributes tab, drawn from
        // `ldap/person_editor.ts` and the credential catalogue — so this form
        // and the tab cannot offer different attributes, and a create holds
        // every value to the rules an edit does. The simplified view is the
        // names and contact details somebody creating a person usually has; the
        // advanced view is every field. The switch, "+" and the bin are submit
        // buttons that redraw this form with everything typed kept.
        '<h2>' + (view === 'advanced'
          ? t.html('consoleUsers.newUserBody.everythingHeading')
          : t.html('consoleUsers.newUserBody.whatHeading')) + '</h2>' +
        kit.note(t.html('consoleUsers.newUserBody.gridBefore') +
        '<a href="/admin/vc">' +
        t.html('consoleUsers.newUserBody.credentialClaims') + '</a>' +
        t.html('consoleUsers.newUserBody.gridAfter')) +
        (development
          ? kit.note(t.html('consoleUsers.newUserBody.uidNote'))
          : '') +
        '<input type="hidden" name="view" value="' + kit.esc(view) + '">' +
        '<div class="formrow fg-view"><span class="sub">' +
        (view === 'advanced'
          ? t.html('consoleUsers.newUserBody.advancedView')
          : t.html('consoleUsers.newUserBody.simpleView')) +
        '</span><button type="submit" class="secondary" name="switchview" ' +
        'value="' + (view === 'advanced' ? 'simple' : 'advanced') +
        '" formaction="/admin/users/new" formnovalidate' +
        kit.tip(t.text('consoleUsers.newUserBody.switchTip')) + '>' +
        (view === 'advanced'
          ? t.html('consoleUsers.newUserBody.showSimple')
          : t.html('consoleUsers.newUserBody.showAdvanced')) +
        '</button></div>' +
        UsersPage.newUserFieldGrid(t, json, view, gridValues,
          given.draft || null) +

        // TWO SUBMITS, AND ONLY ONE OF THEM CARRIES A NAME. `action=create` is
        // a
        // HIDDEN FIELD, the way every other form on this console spells its
        // action, and Create is an ordinary unnamed button; Fill carries
        // `fill=yes` of its own and the handler reads that FIRST, so a press of
        // it cannot be mistaken for a create even though `action` still says
        // create.
        //
        // **THE ALTERNATIVE — TWO BUTTONS BOTH NAMED `action` — LOOKS TIDIER
        // AND
        // BREAKS TWO THINGS.** A form with two controls of one name has a
        // `RadioNodeList` at `form.elements.action` rather than an element, and
        // `.value` on one of those is empty unless they are radios: so anything
        // that finds a form by the action it posts — which is how this
        // console's
        // own browser suite finds every form it presses — stops finding this
        // one.
        // And a browser that submitted BOTH values (a hidden field plus a named
        // button) would post `action` twice, which is precisely the ambiguity
        // `common/validation.js` refuses everywhere else rather than resolving.
        '<div class="formrow">' +
          '<button type="submit">' +
          t.html('consoleUsers.newUserBody.createUser') + '</button>' +
          (development
            ? ' <button type="submit" name="fill" value="yes" ' +
              'class="secondary">' +
              t.html('consoleUsers.newUserBody.fill') + '</button>'
            : '') +
        '</div>' +

        (development
          ? kit.note(t.html('consoleUsers.newUserBody.fillNote'))
          : kit.warn(t.html('consoleUsers.newUserBody.productBefore') +
            '<a href="/admin/config">' +
            t.html('consoleUsers.newUserBody.configuration') + '</a>' +
            t.html('consoleUsers.newUserBody.productAfter'))) +

        // THE INVENTION SWITCH, AND IT IS A HIDDEN FIELD RATHER THAN A CHOICE.
        // This page's whole promise is that nothing is made up unless the
        // button
        // that makes it up was pressed, so `invent=no` is what it always sends;
        // the invented person is reachable from here through Fill, where it is
        // visible and editable, and through the API for a caller that wants the
        // old behaviour.
        '<input type="hidden" name="invent" value="no">' +
        '</form>' +

        kit.note(t.html('consoleUsers.newUserBody.persistBefore') +
        '<a href="/admin/persistence">' +
        t.html('consoleUsers.newUserBody.persistence') + '</a>' +
        t.html('consoleUsers.newUserBody.persistAfter') +
        (json.persistence.persistsDirectory
          ? t.html('consoleUsers.newUserBody.persistYes',
                   { mode: json.persistence.mode })
          : t.html('consoleUsers.newUserBody.persistNo'))) +

        kit.warn(t.html('consoleUsers.newUserBody.notOnUsersBefore') + '<a ' +
        'href="/admin/ldap/directory">' +
        t.html('consoleUsers.newUserBody.theDirectory') + '</a>' +
        t.html('consoleUsers.newUserBody.notOnUsersAfter')) +

        kit.note(t.html('consoleUsers.newUserBody.populateBefore') + '<a ' +
          'href="/admin/vc">' +
        t.html('consoleUsers.newUserBody.credentialClaims') + '</a>' +
        t.html('consoleUsers.newUserBody.populateAfter')) +

        kit.note('<a href="/admin/users">' +
        t.html('consoleUsers.newUserBody.users') + '</a> &middot; <a ' +
        'href="/admin/ldap/directory">' +
        t.html('consoleUsers.newUserBody.everyEntry') + '</a> ' +
        '&middot; <a href="/admin/vc">' +
        t.html('consoleUsers.newUserBody.credentialClaims') +
        '</a> &middot; <a ' +
        'href="/admin-api/docs#operation/createUser">' +
        t.html('consoleUsers.newUserBody.sameAct') + '</a>.');

    }

    return inner;
  }

  /**
   * Draws one way in a new person can be given as a radio-button row.
   *
   * @param choice - the credential choice (id, label, what)
   * @param chosen - the id of the choice already selected
   * @returns the row as HTML
   */
  static credentialChoiceRow(choice, chosen) {
    const id = 'cred-' + choice.id;
    return '<tr><td><input type="radio" id="' + kit.esc(id) +
           '" name="credential" ' +
                                                          'value="' +
      kit.esc(choice.id) + '"' + (chosen === choice.id ? ' checked' : '') +
      '></td><td><label for="' + kit.esc(id) + '"><strong>' +
      kit.esc(choice.label) +
                                                          '</strong></label>' +
                                                          '</td><td ' +
      'class="why">' + kit.note(choice.what) + '</td></tr>';
  }

  /**
   * Draws `/admin/users/new`'s field grid: the view's fields under the
   * person field groups' headings.
   *
   * @param t - the page's translator
   * @param json - the form's answer (`fieldRows`, `fieldGroups`)
   * @param view - `simple` or `advanced`
   * @param values - the boxes' values by attribute
   * @param draft - the posted form of a redraw, or null on a first draw. A
   *   list the form did not draw before (a first draw, or a field the view
   *   switch has just added) gets one empty box, which a create reads as no
   *   value; a list the form did draw keeps its boxes as posted
   * @returns the grid as HTML
   */
  static newUserFieldGrid(t, json, view, values, draft) {
    const rows = UsersPage.newUserFieldRows(json, view);
    // ONE BOX FOR A LIST ON THE FIRST DRAW: cn, sn and the telephone numbers
    // are multi-valued in their RFCs, and a form showing only "+" for the
    // names a person is created with reads as a form with no name boxes.
    const drawn = {};
    Object.keys(draft || {}).forEach(function (key) {
      if (key.indexOf('field.') === 0) {
        drawn[key.slice('field.'.length).replace(/\.\d+$/, '')] = true;
      }
    });
    if (draft && draft.grow) {
      drawn[String(draft.grow)] = true;
    }
    if (draft && draft.drop) {
      drawn[String(draft.drop).replace(/\.\d+$/, '')] = true;
    }
    rows.forEach(function (row) {
      if (row.type === 'array' && !drawn[row.attribute] &&
          !(values[row.attribute] || []).length) {
        values[row.attribute] = [''];
      }
    });
    const html = json.fieldGroups.map(function (group) {
      const mine = rows.filter(function (row) {
        return row.group === group.id;
      });
      if (!mine.length) {
        return '';
      }
      return '<div class="fg-group"><h3' + kit.tip(group.what) + '>' +
        kit.esc(group.label) + '</h3><div class="fg">' +
        mine.map(function (row) {
          return kit.fieldGridCell(row, values,
                                    { redraw: '/admin/users/new' }, t);
        }).join('') + '</div></div>';
    }).join('');
    return html;
  }

  /**
   * The fields `/admin/users/new` draws, as field grid rows: every attribute
   * a person's Attributes tab edits, and the credential catalogue's others
   * (the address), each with its group, example and tooltip.
   *
   * @param json - the form's answer, whose `fieldRows` are every field
   * @param view - `simple` or `advanced`
   * @returns the rows, in group order
   */
  static newUserFieldRows(json, view) {
    // Every field the form can draw is the answer's (`fieldRows`, built by
    // `admin_views.newUserFieldRows()` since #446); a view is a filter.
    const shown = json.fieldRows.filter(function (row) {
      return view === 'advanced' || row.simple;
    });
    return shown;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    // The page's words are its translator's (#539 phase 6), and every
    // section below is handed it; what the view carries is drawn as it
    // comes.
    const t = kitEscaping(ctx.t);
    const row = json.user;
    const page = json.page;
    const key = page.key;
    const params = page.params;
    const back = page.back;
    const counts = page.counts;
    const gate = { write: ctx.write };
    // THE TWO SECTIONS ARE MARKUP, AND THE LAYER HANDS BACK ONLY THEIR JSON.
    // The first pass of the 2026-09-12 split read `view.directory` and
    // `view.mfa` here and concatenated their `.html` — which the layer never
    // builds — so the directory entry and the second factors vanished from
    // this page while `/admin-api/users?user=` went on answering both. Since
    // #446 both are drawn from that answer, so the page and the resource keep
    // one source for what those panels say.
    const directory = UsersPage.ldapObjectSection(t, row, json.ldap,
                                                  json.subject);
    const mfa = UsersPage.mfaSection(t, row, key, gate, back, page.mfa);
    const sessionsNav = kit.pageNavPair('/admin/users', params,
                                         json.sessionsPaging, t);
    // A session's tokens arrive with it, paged, and the block draws that page.
    const sessionBlocks = json.sessions.map(function (session) {
      return UsersPage.sessionBlock(t, session, { shown: session.tokens,
                                          paging: session.tokensPaging },
                               back, params);
    }).join('');

    // ONE NAME PER LIST, and it is the name the reply's array carries: the
    // parameter is `<array>Page` and the paging object beside it is
    // `<array>Paging`. Shortening these two to `endedPage` and
    // `sessionlessPage` read better and was wrong — a caller reading
    // `tokensWithNoSession` in the reply had to be told separately that the
    // parameter moving it was called something else, which is the sort of thing
    // a document gets right and a client author never finds.
    const endedNav = kit.pageNavPair('/admin/users', params,
                                      json.tokensOnEndedSessionsPaging, t);
    const sessionlessNav = kit.pageNavPair('/admin/users', params,
                                            json.tokensWithNoSessionPaging, t);
    const artifactNav = kit.pageNavPair('/admin/users', params,
                                         json.artifactsPaging, t);

    const inner = (page.riskAsked ? UsersPage.riskBadge(t, json.risk) : '') +
      '<div class="tiles">' +
        kit.tile(row.authentications,
                 t.text('consoleUsers.detail.tileAuthentications')) +
        kit.tile(row.protocols.length,
                 t.text('consoleUsers.detail.tileProtocols')) +
        kit.tile(counts.live, t.text('consoleUsers.detail.tileSessions')) +
        kit.tile(counts.tokens, t.text('consoleUsers.detail.tileTokens')) +
        kit.tile(counts.valid, t.text('consoleUsers.detail.tileValid')) +
        kit.tile(counts.expired, t.text('consoleUsers.detail.tileExpired')) +
        kit.tile(counts.artifacts,
                  t.text('consoleUsers.detail.tileArtifacts')) +
      '</div>' +
      // A PERSON'S PAGE AS TABS (rcbj, 2026-10-01), the application page's
      // model: one tab per part of the page, the Attributes tab a typed field
      // grid one sub-tab per group, and Credentials one sub-tab per kind of
      // credential. `kit.tabbedPanels()` argues the mechanism: a control's
      // answer lands at a fragment inside its own tab, so the tab is shown
      // again.
      kit.tabbedPanels('usertabs', [
        { id: 'utab-overview', label: t.text('consoleUsers.detail.tabOverview'),
          html:
      kit.note(t.html('consoleUsers.detail.overviewBefore',
                      { name: row.name }) +
      '<a href="/admin/users">' + t.html('consoleUsers.detail.oneRow') +
      '</a>' +
      (row.authenticated
        ? t.html('consoleUsers.detail.presented',
                 { count: row.authentications })
        : t.html('consoleUsers.detail.neverAuthenticated')) +
      (row.isClient
        ? t.html('consoleUsers.detail.isClient')
        : '')) +

      // THE SAME PERSON AS A PICTURE. This page is the LEDGER — every token
      // with its state and its revoke button, grouped by the session it was
      // issued on — and the diagram is the RELATIONSHIPS: who holds what, by
      // which grant, and who delegated in their name. Neither is the other's
      // summary, so the link says which question the other page answers rather
      // than offering itself as "more detail".
      kit.note('<a class="btn" href="' +
        kit.esc('/admin/delegation/user' + kit.queryWith({ user: key }, {})) +
        '">' + t.html('consoleUsers.detail.seePicture') + '</a> ' +
      t.html('consoleUsers.detail.pictureNote')) +

      '<h2>' + t.html('consoleUsers.detail.namesHeading') + '</h2>' +
      kit.note(t.html('consoleUsers.detail.namesNote')) +
      '<table><tr><th>' + t.html('consoleUsers.detail.thPresented') +
      '</th><th class="num">' + t.html('consoleUsers.detail.thTimes') +
      '</th></tr>' +
      (row.forms.map(function (form) {
        return '<tr><td><code>' + kit.esc(form.form) +
               '</code></td><td class="num">' + form.count + '</td></tr>';
      }).join('') || '<tr><td colspan="2">—</td></tr>') + '</table>' +
      (row.realms.length
        ? kit.note(t.html('consoleUsers.detail.kerberosRealms') +
          kit.codeList(row.realms.map(function (r) { return r.realm; })) + '.')
        : '') +

      '<h2>' + t.html('consoleUsers.detail.howHeading') + '</h2><table><tr>' +
      '<th>' + t.html('consoleUsers.detail.thProtocol') + '</th><th ' +
      'class="num">' + t.html('consoleUsers.detail.thTimes') + '</th><th>' +
      t.html('consoleUsers.detail.thMethods') + '</th><th>' +
      t.html('consoleUsers.detail.thLast') + '</th></tr>' +
      (row.protocols.map(function (family) {
        return '<tr><td>' + kit.esc(family.protocol) + '</td>' +
          '<td class="num">' + family.count + '</td>' +
          '<td>' + kit.esc(family.methods.map(function (m) {
            return m.method + ' ×' + m.count;
          }).join('; ')) + '</td>' +
          '<td>' + kit.esc(kit.whenText(family.lastAt)) + '</td></tr>';
      }).join('') || '<tr><td colspan="4">' +
        t.html('consoleUsers.detail.neverHere') + '</td></tr>') +
        '</table>' +
      UsersPage.authenticationTable(t, row, page.maxEventsPerUser) },
        { id: 'utab-activity', label: t.text('consoleUsers.detail.tabActivity'),
          html:
      kit.perPageForm('/admin/users', 'user', key,
                       json.artifactsPaging.perPage,
                       t.html('consoleUsers.detail.blocksNote',
                              { blocks: page.blocksPerPage,
                                per: page.perPage }),
                       kit.filterOnly(kit.listViewOf('/admin/users',
                                                       ctx.query)), t) +

      '<h2>' + t.html('consoleUsers.detail.sessionsHeading') + '</h2>' +
      kit.note(t.html('consoleUsers.detail.sessionsNote')) +
      sessionsNav.head +
      (sessionBlocks || kit.note(t.html('consoleUsers.detail.noSession'))) +
      sessionsNav.foot +

      (counts.ended
        ? '<h3>' + t.html('consoleUsers.detail.endedHeading') + '</h3>' +
          kit.note(t.html('consoleUsers.detail.endedNote')) +
          endedNav.head +
          UsersPage.userTokenTable(t, json.tokensOnEndedSessions, back, '') +
          endedNav.foot
        : '') +

      (counts.sessionless
        ? '<h3>' + t.html('consoleUsers.detail.sessionlessHeading') +
          '</h3>' +
          kit.note(t.html('consoleUsers.detail.sessionlessNote')) +
          sessionlessNav.head +
          UsersPage.userTokenTable(t, json.tokensWithNoSession, back, '') +
          sessionlessNav.foot
        : '') +

      '<h2>' + t.html('consoleUsers.detail.artifactsHeading') + '</h2>' +
      kit.note(t.html('consoleUsers.detail.artifactsNote')) +
      artifactNav.head + UsersPage.userArtifactTable(t, json.artifacts) +
      artifactNav.foot },
        { id: 'utab-attributes',
          label: t.text('consoleUsers.detail.tabAttributes'), html:
          UsersPage.personFieldsSection(t, key, json.attributeEditor, gate,
                                   back, json.state, page.fieldGroups) },
        { id: 'utab-credentials',
          label: t.text('consoleUsers.detail.tabCredentials'), html:
          kit.subTabbedPanels(t.text('consoleUsers.detail.tabCredentials'), [
            // What they sign IN with, as a second factor or alone.
            { id: 'ucred-factors',
              label: t.text('consoleUsers.detail.tabFactors'), html: mfa },
            // What an administrator can do to their password and second
            // factors (2026-09-13); a reset signs the person out as well.
            { id: 'ucred-password',
              label: t.text('consoleUsers.detail.tabPassword'),
              html: UsersPage.userCredentialControlsSection(t, key,
                                                       json.factors,
                                                       gate, back,
                                                       page.delegation) },
            // Whether they are a SERVICE ACCOUNT (#221), and its rotation.
            { id: 'ucred-service',
              label: t.text('consoleUsers.detail.tabService'),
              html: UsersPage.serviceAccountSection(t, key,
                                                    json.serviceAccount,
                                                    gate, back) },
            // What they can SIGN a grant with (2026-09-13).
            { id: 'ucred-keys', label: t.text('consoleUsers.detail.tabKeys'),
              html: UsersPage.userCredentialsSection(t, key, page.keyPairs,
                                                gate, back) },
            // Their Kerberos account, and a keytab for it (#59).
            { id: 'ucred-kerberos', label: 'Kerberos',
              html: UsersPage.userKerberosSection(t, key, json.kerberos,
                                                  gate) }
          ]) },
        // Which partners' subjects sign them in (#109): a link is another way
        // in, so it has a tab of its own beside Credentials.
        { id: 'utab-federation',
          label: t.text('consoleUsers.detail.tabFederation'),
          html: UsersPage.userFederationLinksSection(t, key,
            { shown: json.federationLinks, paging: json.federationLinksPaging },
            gate, back, params, page.serviceProviders) },
        // The GNAP grants they are the resource owner of (#432 phase 7): a
        // grant is access they gave an application, so it has a tab of its
        // own beside the links, with a Revoke per grant.
        { id: 'utab-gnap', label: t.text('consoleUsers.detail.tabGnap'),
          html: UsersPage.userGnapGrantsSection(t, key,
            { rows: json.gnapGrants, paging: json.gnapGrantsPaging,
              cells: json.gnapGrantsCells }, gate, params) },
        // Every attribute the entry holds, and the one-attribute forms the
        // Attributes tab replaced as the usual door (#228).
        { id: 'utab-entry', label: t.text('consoleUsers.detail.tabEntry'),
          html: directory +
            UsersPage.userAttributesSection(t, key, json.attributeEditor,
                                       gate, back) },
        { id: 'utab-signout', label: t.text('consoleUsers.detail.tabSignOut'),
          html:
      // ---------------------------------------------------------------------
      // TWO BUTTONS, AND THE ORDER IS THE ARGUMENT (2026-09-05).
      //
      // There was ONE here and it was labelled "Revoke everything for <name>",
      // which is what somebody reaching for a global sign-out would press. It
      // revoked JWTs and nothing else — so the person stayed SIGNED IN, and the
      // next `/oauth2/authorize`, `/wsfed`, `/saml2/sso` or `/saml11/sso`
      // request minted a fresh set of tokens on the spot. From the outside that
      // is close to a no-op, and the label said the opposite.
      //
      // The narrow act is worth keeping — "take these credentials out of
      // circulation and leave the session alone" is a real thing to want, and
      // it is what `/oauth2/revoke` does — so it stayed, renamed to say what it
      // does. What was ADDED is the act the old label promised, and it is the
      // SAME one `/admin/logout` performs: `logoutReader.terminate()` with an
      // empty selection, which walks every family (eleven since #38) in
      // `endOrder` so the
      // front-channel notifications are built before the session they hang off
      // is destroyed. A second implementation here would be a second answer to
      // "what is a live session", which is the thing rule 3m exists to prevent.
      //
      // The global one is FIRST because it is the one the old label described.
      // ---------------------------------------------------------------------
      '<h2>' + t.html('consoleUsers.detail.signOutHeading') + '</h2>' +
      kit.note(t.html('consoleUsers.detail.signOutBefore') + '<a ' +
      'href="' + kit.esc('/admin/logout' + kit.queryWith({}, { user: key })) +
      '">' + t.html('consoleUsers.detail.signOutPage') + '</a>' +
      t.html('consoleUsers.detail.signOutAfter')) +
      kit.note(t.html('consoleUsers.detail.cannotDo')) +
      '<form method="post" action="/admin/logout">' +
        '<input type="hidden" name="action" value="global">' +
        '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
        '<input type="hidden" name="from" value="users">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        '<div class="formrow"><button class="danger"' +
        kit.tip(t.text('consoleUsers.detail.signOutTip')) + '>' +
        t.html('consoleUsers.detail.signOutButton', { name: row.name }) +
        '</button></div></form>' +

      '<h2>' + t.html('consoleUsers.detail.revokeHeading') + '</h2>' +
      kit.note(t.html('consoleUsers.detail.revokeNote')) +
      '<form method="post" action="/admin/tokens">' +
        '<input type="hidden" name="action" value="revoke-user">' +
        '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
        '<input type="hidden" name="from" value="users">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        '<div class="formrow"><button class="danger"' +
        kit.tip(t.text('consoleUsers.detail.revokeTip')) + '>' +
        t.html('consoleUsers.detail.revokeButton', { name: row.name }) +
        '</button></div></form>' }
      ]);

    return inner;
  }

  // One session and everything issued on it. This is the answer to the question
  // the page exists for — "what does this person hold right now, and where did
  // it come from" — so the session's own facts and its tokens are drawn as one
  // block rather than as two tables somebody has to join by eye.
  //
  // Its token table is PAGED, and paged separately from every other block on
  // the page. One browser session can hold most of the five thousand tokens
  // this service remembers — a refresh grant in a loop is all it takes — so the
  // block that answers "what does this person hold right now" is the one table
  // here that can genuinely run away, and a single `page` shared with the block
  // above it would move both. Hence a page parameter named after the session
  // id: it names the block it moves, so a bookmark still moves the same session
  // after the list around it has changed, which an index into the session list
  // would not.
  /**
   * Draws one sign-on session's facts and a paged table of the tokens
   * issued on it.
   *
   * @param t - the page's translator
   * @param session - the session
   * @param tokenPage - the page of its tokens, with its paging
   * @param back - the list to return to after a revoke
   * @param params - the page's query, for the pager's links
   * @returns the block as HTML
   */
  static sessionBlock(t, session, tokenPage, back, params) {
    const nav = kit.pageNavPair('/admin/users', params, tokenPage.paging, t);
    const html = '<h3>' + t.html('consoleUsers.sessionBlock.session') + ' ' +
      kit.shortened(session.id, 12) + ' &mdash; ' +
      '<span class="' + (session.expired ? 'state-expired' : 'state-valid') +
      '">' +
      (session.expired ? t.html('consoleUsers.sessionBlock.expired')
                       : t.html('consoleUsers.sessionBlock.active')) +
      '</span></h3>' +
      '<table><tr><th>' + t.html('consoleUsers.sessionBlock.thSignedIn') +
      '</th><th>' + t.html('consoleUsers.sessionBlock.thLastAuth') +
      '</th><th>' + t.html('consoleUsers.sessionBlock.thExpires') +
      '</th><th>amr</th><th>acr</th>' +
      '<th>' + t.html('consoleUsers.sessionBlock.thWsfed') + '</th></tr>' +
      '<tr><td>' + kit.esc(kit.whenText(session.startedAt)) + '</td>' +
      '<td>' + kit.esc(kit.whenText(session.authTime)) +
      (session.authentications > 1 ? ' (' + session.authentications + ')' :
       '') +
      '</td>' +
      '<td>' + kit.esc(kit.whenText(session.expires)) + '</td>' +
      '<td>' + kit.esc(session.amr || '—') + '</td>' +
      '<td>' + kit.esc(session.acr || '—') + '</td>' +
      '<td>' +
      (session.wsfedRealms.length ? kit.esc(session.wsfedRealms.join(', ')) :
       '—') +
      '</td></tr></table>' +
      nav.head +
      UsersPage.userTokenTable(t, tokenPage.shown, back,
        t.text('consoleUsers.sessionBlock.nothingIssued')) +
      nav.foot;
    return html;
  }

  // One user's tokens as a table. The columns are the ones that differ WITHIN a
  // user: their name and subject are the same on every row by construction and
  // are stated once above the table instead of repeated down it.
  /**
   * Draws one person's tokens as a table, with a Revoke or Restore button
   * on each token that can be revoked.
   *
   * @param t - the page's translator
   * @param records - the token records
   * @param back - the list to return to after a revoke
   * @param empty - the text of the row drawn when there are none
   * @returns the table as HTML
   */
  static userTokenTable(t, records, back, empty) {
    const rows = records.map(function (record) {
      const button = record.revocable
        ? '<form method="post" action="/admin/tokens" class="inline">' +
          '<input type="hidden" name="action" value="' +
          (record.revoked ? 'restore' : 'revoke') + '"><input ' +
          'type="hidden" name="target" value="' + kit.esc(record.jti) + '">' +
          '<input type="hidden" name="from" value="users">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<button class="' + (record.revoked ? 'secondary' : 'danger') + '">' +
          (record.revoked ? t.html('consoleUsers.userTokenTable.restore')
                          : t.html('consoleUsers.userTokenTable.revoke')) +
          '</button></form>'
        : '<span class="state-none" title="' +
          kit.esc(t.text('consoleUsers.userTokenTable.notRevocable')) +
          '">—</span>';
      return '<tr><td>' + kit.esc(record.kind) + '</td>' +
        '<td class="' + TokensPage.stateClass(record.state) + '">' +
        kit.esc(record.state) +
        '</td><td>' + kit.esc(record.grant || '—') + '</td><td>' +
        kit.esc(record.client_id || '—') + '</td><td>' +
        kit.esc(record.scope || '—') +
        '</td><td>' + (record.jkt ? 'DPoP' : 'Bearer') + '</td><td>' +
        kit.esc(kit.whenText(record.issuedAt)) + '</td><td>' +
        kit.esc(record.exp ? kit.whenText(record.exp * 1000) : '—') +
        '</td><td>' +
        kit.shortened(record.jti, 12) + '</td><td>' + button + '</td></tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleUsers.userTokenTable.thToken') +
      '</th><th>' + t.html('consoleUsers.userTokenTable.thState') +
      '</th><th>' + t.html('consoleUsers.userTokenTable.thGrant') +
      '</th><th>' + t.html('consoleUsers.userTokenTable.thClient') +
      '</th><th>' + t.html('consoleUsers.userTokenTable.thScope') +
      '</th><th>' + t.html('consoleUsers.userTokenTable.thPresented') +
      '</th><th>' + t.html('consoleUsers.userTokenTable.thIssued') +
      '</th><th>' + t.html('consoleUsers.sessionBlock.thExpires') +
      '</th><th>jti</th><th></th></tr>' +
      (rows || '<tr><td colspan="10">' + kit.esc(empty) + '</td></tr>') +
      '</table>';
  }

  // The artifacts that are not JWTs. One table for all three kinds, with a
  // single Detail column, because an assertion's audience, a ticket's service
  // and enc-type and a credential's configuration id are each the one thing
  // worth reading about that row and giving each its own column would leave two
  // thirds of the table empty.
  /**
   * Draws one person's artifacts that are not JWTs (assertions, tickets,
   * credentials) as one table with a single Detail column.
   *
   * @param t - the page's translator
   * @param records - the artifact records
   * @returns the table as HTML
   */
  static userArtifactTable(t, records) {
    const rows = records.map(function (record) {
      // Plain text, escaped whole below as it always was.
      const detail = record.service
        ? t.text('consoleUsers.userArtifactTable.service',
                 { service: record.service }) +
          (record.etype ? ', ' + record.etype : '') +
          (record.realm ? t.text('consoleUsers.userArtifactTable.realm',
                                 { realm: record.realm }) : '')
        : (record.audience
          ? t.text('consoleUsers.userArtifactTable.audience',
                   { audience: record.audience })
          : (record.configId
            ? t.text('consoleUsers.userArtifactTable.configuration',
                     { id: record.configId })
            : ''));
      return '<tr><td>' + kit.esc(record.kind) + '</td>' +
        '<td class="' + TokensPage.stateClass(record.state) + '">' +
        kit.esc(record.state) +
        '</td><td>' + kit.esc(detail || '—') + '</td><td>' +
        (record.id ? kit.shortened(record.id, 20) : '<span ' +
          'class="state-none" title="' +
          kit.esc(t.text('consoleUsers.userArtifactTable.noIdTitle')) +
          '">—</span>') + '</td>' +
        '<td>' + kit.esc(kit.whenText(record.issuedAt)) + '</td><td>' +
        kit.esc(record.expiresAt ? kit.whenText(record.expiresAt) : '—') +
        '</td></tr>';
    }).join('');
    return '<table><tr><th>' +
           t.html('consoleUsers.userArtifactTable.thArtifact') + '</th><th>' +
           t.html('consoleUsers.userTokenTable.thState') + '</th><th>' +
           t.html('consoleUsers.userArtifactTable.thDetail') + '</th><th>' +
           t.html('consoleUsers.userArtifactTable.thIdentifier') +
           '</th><th>' + t.html('consoleUsers.userTokenTable.thIssued') +
           '</th><th>' + t.html('consoleUsers.sessionBlock.thExpires') +
           '</th></tr>' +
      (rows ||
       '<tr><td colspan="6">' + t.html('consoleUsers.userArtifactTable.none') +
       '</td></tr>') +
      '</table>';
  }

  // How they authenticated, most recent first. The whole point of the table is
  // the Method column: "sign-in screen (password)" and "AS-REQ with
  // PA-ENC-TIMESTAMP" are both authentications and only one of them checked
  // anything.
  /**
   * Draws how a person authenticated, most recent first, with a note when
   * older events have been forgotten past the per-user cap.
   *
   * @param t - the page's translator
   * @param row - the person's record in the identity register
   * @param maxEvents - how many events the register keeps per person
   *   (`stats.MAX_EVENTS_PER_USER`)
   * @returns the table as HTML
   */
  static authenticationTable(t, row, maxEvents) {
    const rows = row.events.slice().reverse().map(function (event) {
      return '<tr><td>' + kit.esc(kit.whenText(event.at)) + '</td>' +
        '<td>' + kit.esc(event.protocol) + '</td>' +
        '<td>' + kit.esc(event.method) + '</td>' +
        '<td>' + kit.esc(event.presented) + '</td>' +
        // Where it came from (2026-09-19), linked to every audit row from
        // that address. A dash for an event recorded before events carried
        // one, or for an act that came over no socket.
        '<td>' + (event.address
          ? '<a href="/admin/audit?address=' +
            encodeURIComponent(event.address) + '"><code>' +
            kit.esc(event.address) + '</code></a>'
          : '<span class="state-none" title="' +
            kit.esc(t.text('consoleUsers.authenticationTable.noAddressTitle')) +
            '">—</span>') + '</td>' +
        '<td>' + kit.esc(event.amr || '—') + '</td>' +
        '<td>' + kit.esc(event.acr || '—') + '</td>' +
        '<td>' + kit.esc(event.client_id || '—') + '</td>' +
        '<td>' + (event.sessionId ? kit.shortened(event.sessionId, 10) : '—') +
        '</td><td>' + kit.esc(event.note || '') + '</td></tr>';
    }).join('');
    return '<table><tr><th>' +
      t.html('consoleUsers.authenticationTable.thWhen') + '</th><th>' +
      t.html('consoleUsers.detail.thProtocol') + '</th><th>' +
      t.html('consoleUsers.authenticationTable.thMethod') + '</th><th>' +
      t.html('consoleUsers.userTokenTable.thPresented') + '</th><th>' +
      t.html('consoleUsers.authenticationTable.thFrom') +
      '</th><th>amr</th><th>acr</th><th>' +
      t.html('consoleUsers.userTokenTable.thClient') + '</th>' +
      '<th>' + t.html('consoleUsers.sessionBlock.session') + '</th><th>' +
      t.html('consoleUsers.authenticationTable.thNote') + '</th></tr>' +
      (rows || '<tr><td colspan="10">' +
               t.html('consoleUsers.authenticationTable.none') +
               '</td></tr>') +
      '</table>' +
      (row.eventsForgotten > 0
        ? kit.note(t.html('consoleUsers.authenticationTable.forgotten', {
            max: maxEvents,
            total: row.eventsForgotten + row.events.length }))
        : '');
  }

  // -------------------------------------------------------------------------
  // THE PERSON'S CURRENT RISK, LARGE AND IN COLOUR (#62; rcbj asked for it
  // exactly so): the first thing on their page, the level in the colour an
  // administrator reads at a glance — green, amber, red, grey for nobody
  // assessed yet — with the score, the level it came from, when it moved,
  // what moved it, and a link to the assessments behind it. No script: a
  // styled block, as every tile on this page is.
  // -------------------------------------------------------------------------
  static riskBadge(t: any, standing: any): string {
    const level = standing ? String(standing.level || 'UNSCORED')
                           : 'UNKNOWN';
    const palette: Record<string, string[]> = {
      LOW: ['#188038', '#ffffff'], MEDIUM: ['#f9ab00', '#202124'],
      HIGH: ['#d93025', '#ffffff'], UNSCORED: ['#5f6368', '#ffffff'],
      UNKNOWN: ['#dadce0', '#202124'] };
    const colours = palette[level] || palette.UNKNOWN;
    const when = function (ms: number): string {
      return ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 16) +
                  ' UTC' : '';
    };
    const facts = standing
      ? t.html('consoleUsers.riskBadge.score',
               { score: Number(standing.score).toPrecision(3) }) +
        (standing.previousLevel ? ' &middot; ' +
          t.html('consoleUsers.riskBadge.was',
                 { level: standing.previousLevel }) : '') +
        (standing.crossedAt ? ' &middot; ' +
          t.html('consoleUsers.riskBadge.since',
                 { when: when(standing.crossedAt) }) : '') +
        (standing.reason ? '<br>' + t.html('consoleUsers.riskBadge.because',
                                           { reason: standing.reason }) : '')
      : t.html('consoleUsers.riskBadge.notAssessed');
    return '<div class="risk-badge" style="display:flex;align-items:center;' +
      'gap:28px;margin:14px 0 18px;padding:20px 28px;border-radius:14px;' +
      'background:' + colours[0] + ';color:' + colours[1] + '">' +
      '<div style="font-size:3em;font-weight:800;letter-spacing:.05em;' +
      'line-height:1">' + kit.esc(level) + '</div>' +
      '<div style="font-size:1.05em;line-height:1.5"><div style="font-size:' +
      '1.3em;font-weight:700">' + t.html('consoleUsers.riskBadge.current') +
      '</div>' + facts +
      '<div style="margin-top:6px"><a style="color:inherit;font-weight:600" ' +
      'href="' + kit.esc(standing && standing.subject
        ? '/admin/risk?subject=' + encodeURIComponent(standing.subject) +
          '#risk-assessments'
        : '/admin/risk') + '">' + t.html('consoleUsers.riskBadge.assessments') +
      '</a></div>' +
      '</div></div>';
  }

  // The whole section, as HTML and as the object that goes into ?format=json.
  // Both come out of one call so that the page and the JSON cannot disagree
  // about what the directory holds, which is the same rule /admin/ldap/*
  // follows for its own five views.
  //
  // `row` is the user record: it is what tells a missing entry apart from an
  // entry that was never going to exist. Four of the five reasons for an
  // absence are facts about the USER rather than about the directory — a client
  // is not a person, an LDAP bind presents a DN and not a user name, an
  // identity that only ever appeared as the subject of something never
  // authenticated at all — and a section that said only "not found" would send
  // a reader to look for a bug in the directory.
  /**
   * Draws the user page's section on this person's LDAP entry, or why
   * there is none, with the directory listeners' state.
   *
   * @param t - the page's translator
   * @param row - the person's record in the identity register
   * @param info - the answer's `ldap`: the directory's report on their entry,
   *   null when no directory is loaded
   * @param subject - the answer's `subject`
   * @returns the section as HTML
   */
  static ldapObjectSection(t, row, info, subject) {
    const heading = '<h2>' + t.html('consoleUsers.ldapObjectSection.heading') +
      '</h2>';
    if (!info) {
      return heading +
        kit.note(t.html('consoleUsers.ldapObjectSection.noDirectory'));
    }
    const link = kit.note('<a href="/admin/ldap/service">' +
      t.html('consoleGroups.groupsLinks.service') + '</a> &middot; ' +
      '<a href="/admin/ldap/directory">' +
      t.html('consoleGroups.groupsLinks.directory') + '</a> &middot; ' +
      '<a href="/admin/ldap/directory?format=json">' +
      t.html('consoleGroups.groupsLinks.json') + '</a>.');
    // Said on every branch, including the ones with an entry: the entry can be
    // there and the socket down, and a reader who trusts this page to mean "an
    // LDAP client can fetch this" needs to know which.
    const listener = GroupsPage.directoryListenerWarning(t, info,
      GroupsPage.ENTRY_SUBJECT);
    // The other entries are markup (each in its <code>), so the sentence is
    // a message before them and one after.
    const alsoNamed = info.alsoNamed.length
      ? kit.note(t.html(info.alsoNamed.length === 1
          ? 'consoleUsers.ldapObjectSection.alsoNamedOne'
          : 'consoleUsers.ldapObjectSection.alsoNamedMany',
          { count: info.alsoNamed.length }) +
        kit.codeList(info.alsoNamed) +
        t.html('consoleUsers.ldapObjectSection.alsoNamedRest'))
      : '';

    if (!info.found) {
      // Why not, in the order that makes the first true one the real answer.
      // The DN is quoted with it, EXCEPT where the identity is an LDAP bind DN
      // — there the name this console files the person under is itself a DN, so
      // the place an entry would have gone is `uid=<a whole DN>,ou=users,...`,
      // and leading with that reads as a malformed directory rather than as the
      // explanation that follows it.
      let because;
      let intro = t.html('consoleUsers.ldapObjectSection.noEntry',
                         { dn: info.dn });
      if (!info.autoCreateUsers) {
        because = t.html('consoleUsers.ldapObjectSection.autoCreateOff');
      } else if (row.isClient) {
        because = t.html('consoleUsers.ldapObjectSection.isClient');
      } else if (!row.authenticated) {
        because = t.html('consoleUsers.ldapObjectSection.neverAuthenticated');
      } else if (row.protocols.length === 1 &&
                 row.protocols[0].protocol === 'ldap') {
        intro = t.html('consoleUsers.ldapObjectSection.nothingSeeded');
        because = t.html('consoleUsers.ldapObjectSection.ldapBind',
                         { usersDn: info.usersDn });
      } else if (info.full) {
        because = t.html('consoleUsers.ldapObjectSection.full',
                         { max: info.maxEntries });
      } else {
        because = t.html('consoleUsers.ldapObjectSection.gone');
      }
      return heading + listener +
        kit.note(intro + ' ' + because) + alsoNamed + link;
    }

    const entry = info.entry;

    const html = heading + listener +
      kit.note(t.html('consoleUsers.ldapObjectSection.entryNote',
                      { port: info.port, dn: entry.dn })) +
      '<table><tr><th>DN</th><th>' +
      t.html('consoleGroups.body.thOrigin') + '</th><th>' +
      t.html('consoleGroups.detail.thCreated') + '</th><th>' +
      t.html('consoleGroups.body.thModified') + '</th></tr><tr><td><code>' +
      kit.esc(entry.dn) + '</code></td>' +
      '<td>' + kit.esc(entry.origin) + '</td>' +
      '<td><code>' + kit.esc(entry.createdAt) + '</code></td>' +
      '<td><code>' + kit.esc(entry.modifiedAt) + '</code></td></tr></table>' +
      // THE SUBJECT (2026-09-14), which is no longer derivable from the name:
      // what every token issued to this person carries in `sub`.
      '<p>' + t.html('consoleUsers.ldapObjectSection.subject', {
        subject: subject || t.text('consoleUsers.ldapObjectSection.none') }) +
      '</p>' +
      kit.note(t.html('consoleUsers.ldapObjectSection.subjectNote')) +
      kit.note(t.html('consoleUsers.ldapObjectSection.timestamps')) +
      GroupsPage.attributeTable(entry, t) +
      kit.note(t.html('consoleUsers.ldapObjectSection.attributesNote')) +
      alsoNamed + link;

    return html;
  }

  /**
   * Draws the user page's section on what a person can sign in with and
   * their second factors: authenticator app, security keys, recovery code
   * counts, app passwords, devices, self-issued IDs and verifications.
   *
   * Recovery codes are shown as counts, never as codes.
   *
   * @param t - the page's translator
   * @param row - the person's record in the identity register
   * @param key - the person's key
   * @param state - the gate state; `write` draws the controls
   * @param back - the list to return to after an action
   * @returns an object of html (the section) and json (its ?format=json
   *   object, null when no credential store is installed)
   */
  static mfaSection(t, row, key, state, back, data) {
    const heading = '<h2 id="second-factors">' +
                    t.html('consoleUsers.mfaSection.heading') + '</h2>';
    if (!data.storable) {
      return heading + kit.note(t.html('consoleUsers.mfaSection.noStore'));
    }

    const mech = data.mech;
    const totpLive = data.totp;
    const keyLive = data.webauthn;
    const recoveryLive = data.recovery;
    const mfaKeys = (mech.keys || []).filter(function (
        one) { return one.role === 'mfa'; });
    const primaryKeys = (mech.keys || []).filter(function (
        one) { return one.role === 'primary'; });
    const carryBack = '<input type="hidden" name="back" value="' +
                      kit.esc(back) +
                      '"><input ' +
                      'type="hidden" name="from" value="users">';

    // WHAT THEY CAN GET IN WITH, first and on its own, because it is the
    // question underneath the other two: a person with no password and no
    // primary key cannot sign in at all, however much is enrolled on them, and
    // an operator reading a long list of second factors on such an account
    // would otherwise draw exactly the wrong conclusion.
    // The second factor the sign-in screen asks for is one word of a
    // `select`, so each sentence stays whole for a translator.
    const whatTh = '<table class="key"><tr><th>' +
      t.html('consoleUsers.mfaSection.thWhat') + '</th><th>' +
      t.html('consoleUsers.mfaSection.thAnswer') + '</th></tr>';
    const wayIn = whatTh +
      '<tr><th>' + t.html('consoleUsers.mfaSection.password') + '</th><td>' +
      (mech.password
        ? '<span class="state-valid">' + t.html('consoleUsers.mfaSection.set') +
          '</span>' + t.html('consoleUsers.mfaSection.passwordSet')
        : '<span class="state-none">' +
          t.html('consoleUsers.secondFactorCell.none') + '</span>') +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleUsers.mfaSection.primaryKey') +
      '</th><td>' + (primaryKeys.length
        ? '<span class="state-valid">' + kit.esc(String(primaryKeys.length)) +
          '</span>' + t.html('consoleUsers.mfaSection.primaryKeyNote')
        : '<span class="state-none">' +
          t.html('consoleUsers.secondFactorCell.none') + '</span>') +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleUsers.mfaSection.canSignIn') +
      '</th><td>' + (mech.usable
        ? '<span class="state-valid">' + t.html('consoleUsers.mfaSection.yes') +
          '</span>'
        : '<strong class="state-expired">' +
          t.html('consoleUsers.mfaSection.noCaps') + '</strong>' +
          t.html('consoleUsers.mfaSection.cannotSignIn')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleUsers.mfaSection.demanded') + '</th><td>' +
      (mech.mfaRequired
        ? '<span class="state-valid">' + t.html('consoleUsers.mfaSection.yes') +
          '</span>' + t.html('consoleUsers.mfaSection.asksFor', {
            factor: mech.secondFactor === 'webauthn'
              ? (mech.totp ? 'webauthnOrTotp' : 'webauthn')
              : (mech.secondFactor === 'totp' ? 'totp'
                : (mech.secondFactor === 'email-link' ? 'emailLink'
                                                       : 'emailCode')) })
        : '<span class="state-none">' + t.html('consoleUsers.mfaSection.no') +
          '</span>' + t.html('consoleUsers.mfaSection.notDemanded')) +
          '</td></tr>' +
      '</table>';

    // --- the authenticator app -----------------------------------------------
    const d: any = mech.totpDetail || {};
    const totpChanged = (d.digits && d.digits !== totpLive.digits) ||
      (d.period && d.period !== totpLive.period) ||
      (d.algorithm && d.algorithm !== totpLive.algorithm);
    const totpBlock = '<h3>' + t.html('consoleUsers.mfaSection.totpHeading') +
      '</h3>' +
      (!mech.totp
        ? kit.note('<strong>' + t.html('consoleUsers.mfaSection.noneEnrolled') +
          '</strong> ' +
          (totpLive.enabled
            ? t.html('consoleUsers.mfaSection.totpSelf')
            : t.html('consoleUsers.mfaSection.totpOffBefore') +
              '<a href="/admin/policies#authn">' +
              t.html('consoleUsers.mfaSection.policies') + '</a>' +
              t.html('consoleUsers.mfaSection.totpOffMiddle') + '<a ' +
              'href="/admin/totp">TOTP MFA</a>' +
              t.html('consoleUsers.mfaSection.totpOffAfter')))
        : (!mech.totpUsable
            ? kit.warn(t.html('consoleUsers.mfaSection.totpUnreadable', {
                why: d.why ||
                  t.text('consoleUsers.secondFactorCell.unusable') }))
            : whatTh +
              '<tr><th>' + t.html('consoleUsers.mfaSection.code') +
              '</th><td>' + t.html('consoleUsers.mfaSection.codeParams', {
                digits: String(d.digits || 6),
                algorithm: String(d.algorithm || 'SHA1')
                  .replace(/^SHA/, 'SHA-'),
                period: String(d.period || 30) }) +
              '<a href="/admin/totp">' +
              t.html('consoleUsers.mfaSection.theSettings') + '</a>' +
              t.html('consoleUsers.mfaSection.codeParamsAfter') +
                (totpChanged
                  ? t.html('consoleUsers.mfaSection.totpDiffers', {
                      digits: String(totpLive.digits),
                      algorithm: String(totpLive.algorithm)
                        .replace(/^SHA/, 'SHA-'),
                      period: String(totpLive.period) })
                  : '') + '</td></tr>' +
              '<tr><th>' + t.html('consoleUsers.mfaSection.skew') +
              '</th><td>' + t.html('consoleUsers.mfaSection.skewNote',
                                   { window: String(totpLive.window) }) +
              '</td></tr><tr><th>' +
              t.html('consoleUsers.mfaSection.sharedSecret') + '</th><td>' +
              (d.sealed
                ? '<span class="state-valid">' +
                  t.html('consoleUsers.mfaSection.sealed') + '</span>' +
                  t.html('consoleUsers.mfaSection.sealedBefore') + '<a ' +
                  'href="/admin/ldap/directory">' +
                  t.html('consoleUsers.mfaSection.directoryPage') + '</a>' +
                  t.html('consoleUsers.mfaSection.showsCiphertext')
                : t.html('consoleUsers.mfaSection.inTheClear')) +
                  '</td></tr>' +
              '<tr><th>' + t.html('consoleUsers.mfaSection.enrolled') +
              '</th><td>' +
                kit.esc(d.enrolledAt ? kit.whenText(d.enrolledAt) :
                         t.text('consoleUsers.mfaSection.notRecorded')) +
                '</td></tr>' +
              '<tr><th>' + t.html('consoleUsers.mfaSection.lastCode') +
              '</th><td>' +
                kit.esc(d.lastUsedAt ? kit.whenText(d.lastUsedAt)
                                     : t.text('consoleUsers.body.never')) +
                t.html('consoleUsers.mfaSection.lastCodeNote') +
                '</td></tr></table>')) +
      (mech.totp && state.write
        ? '<form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" value="clear-totp">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          carryBack +
          '<div class="formrow"><button class="danger" title="' +
          kit.esc(t.text('consoleUsers.mfaSection.clearTotpTitle')) +
          '">' + t.html('consoleUsers.mfaSection.clearTotp') +
          '</button></div></form>' +
          kit.note(t.html('consoleUsers.mfaSection.clearTotpNote'))
        : (mech.totp
            ? kit.note(t.html('consoleUsers.mfaSection.clearingNeedsWrite'))
            : ''));

    // --- passkeys
    // --------------------------------------------------------
    // PASSKEYS (#470): the person's own page groups them as *passkeys on
    // your devices* and *passkeys on security keys*, and this table says
    // which beside each, with the name the portal draws (the label, else the
    // provider's or the group's), the provider, when it was last used and
    // the backup state — and a Rename for Admin Write, through the same
    // `renameKey()` the person's own Rename calls (rcbj's decision D).
    const keyRow = function (one) {
      const backup = one.backupEligible === true
        ? (one.backupState === true
          ? t.text('consoleUsers.mfaSection.backedUp')
          : t.text('consoleUsers.mfaSection.notBackedUp'))
        : (one.backupEligible === false
          ? t.text('consoleUsers.mfaSection.deviceBound') : '—');
      return '<tr><td>' +
        kit.esc(one.name || one.label ||
                t.text('consoleUsers.mfaSection.passkey')) +
        (one.provider && one.provider !== one.name
          ? '<div class="note">' + kit.esc(one.provider) + '</div>' : '') +
        // The device serial an enterprise attestation named (#532).
        (one.deviceSerial
          ? '<div class="note">' +
            t.html('consoleUsers.mfaSection.serial',
                   { serial: one.deviceSerial }) +
            '</div>' : '') +
        (state.write
          ? '<details><summary>' + t.html('consoleUsers.mfaSection.rename') +
            '</summary>' +
            '<form method="post" action="/admin/users">' +
            '<input type="hidden" name="action" value="rename-key">' +
            '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
            '<input type="hidden" name="credentialId" value="' +
            kit.esc(one.credentialId || '') + '">' + carryBack +
            '<input type="text" name="label" maxlength="60" value="' +
            kit.esc(one.name || one.label || '') + '" aria-label="' +
            kit.esc(one.name
              ? t.text('consoleUsers.mfaSection.newNameFor',
                       { name: one.name })
              : t.text('consoleUsers.mfaSection.newNameForThis')) + '">' +
            '<button>' + t.html('consoleUsers.mfaSection.save') +
            '</button></form></details>'
          : '') + '</td>' +
        '<td>' + kit.esc(one.group === 'security-key'
          ? t.text('consoleUsers.mfaSection.onSecurityKey')
          : t.text('consoleUsers.mfaSection.onDevices')) + '</td>' +
        '<td>' + (one.role === 'primary'
          ? '<span class="state-valid" title="' +
            kit.esc(t.text('consoleUsers.mfaSection.primaryTitle')) + '">' +
            t.html('consoleUsers.mfaSection.primary') + '</span>'
          : t.html('consoleUsers.mfaSection.secondFactor')) +
        // WHETHER IT SIGNS IN WITH NO USERNAME (#474), from the view, whose
        // sentence is drawn as it comes after the translated lead.
        (one.role === 'primary' && one.withoutUsername
          ? '<div class="note">' +
            kit.esc(t.text('consoleUsers.mfaSection.withoutUsername',
                           { text: one.withoutUsername.text })) +
            '</div>' : '') + '</td>' +
        // `kit.shortened()` EMITS ITS OWN `<code title=…>` AND ESCAPES THE
        // TEXT, so there is neither a kit.esc() nor a wrapper here. The first
        // version had both, and the cell rendered the literal characters
        // `<code title=…>`.
        '<td>' + kit.shortened(one.credentialId || '', 24) + '</td>' +
        '<td class="num">' + kit.esc(String(one.signCount || 0)) + '</td>' +
        // THE SIGNATURE ALGORITHM (2026-10-01): the one this key signs with,
        // and so the one every sign-in with it is verified with.
        '<td>' + UsersPage.algorithmCell(t, one.algorithm) + '</td>' +
        '<td>' + UsersPage.attestationCell(t, one.attestation, one.aaguid) +
        '</td>' +
        '<td>' + kit.esc(backup) +
        (Array.isArray(one.transports) && one.transports.length
          ? '<div class="note">' + kit.esc(one.transports.join(', ')) +
            '</div>'
          : '') + '</td>' +
        '<td>' +
        kit.esc(one.enrolledAt ? kit.whenText(one.enrolledAt) : '—') +
        '</td><td>' +
        kit.esc(one.lastUsedAt ? kit.whenText(one.lastUsedAt)
                               : t.text('consoleUsers.body.never')) +
        '</td><td>' + (state.write
          ? '<form method="post" action="/admin/users">' +
            '<input type="hidden" name="action" value="clear-key">' +
            '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
            '<input type="hidden" name="credentialId" value="' +
            kit.esc(one.credentialId || '') + '">' + carryBack +
            '<button class="danger" title="' +
            kit.esc(one.role === 'primary'
              ? t.text('consoleUsers.mfaSection.removePrimaryTitle')
              : t.text('consoleUsers.mfaSection.removeTitle')) + '">' +
            t.html('consoleUsers.mfaSection.remove') + '</button></form>'
          : '') + '</td></tr>';
    };
    const allKeys = mfaKeys.concat(primaryKeys);
    const keysBlock = '<h3>' + t.html('consoleUsers.mfaSection.keysHeading') +
      '</h3>' +
      (allKeys.length
        ? '<table><tr><th>' + t.html('consoleUsers.mfaSection.thName') +
          '</th><th>' + t.html('consoleUsers.mfaSection.thWhere') +
          '</th><th>' + t.html('consoleUsers.mfaSection.thRole') + '</th>' +
          '<th>' + t.html('consoleUsers.mfaSection.thCredentialId') +
          '</th>' +
          '<th class="num">' + t.html('consoleUsers.mfaSection.thSignCount') +
          '</th><th>' + t.html('consoleUsers.mfaSection.thAlgorithm') +
          '</th>' +
          '<th>' + t.html('consoleUsers.mfaSection.thAttestation') +
          '</th><th>' + t.html('consoleUsers.mfaSection.thBackup') +
          '</th>' +
          '<th>' + t.html('consoleUsers.mfaSection.thCreated') + '</th><th>' +
          t.html('consoleUsers.mfaSection.thLastUsed') +
          '</th><th></th></tr>' +
          allKeys.map(keyRow).join('') + '</table>' +
          kit.note(t.html('consoleUsers.mfaSection.signCountNote'))
        : kit.note('<strong>' +
          t.html('consoleUsers.mfaSection.noneRegistered') +
          '</strong> ' +
          (keyLive.enabled
            ? t.html('consoleUsers.mfaSection.keysSelf')
            : t.html('consoleUsers.mfaSection.keysOffBefore') + '<a ' +
              'href="/admin/webauthn">WebAuthn</a>' +
              t.html('consoleUsers.mfaSection.keysOffAfter')))) +
      (allKeys.length && !state.write
        ? kit.note(t.html('consoleUsers.mfaSection.keysNeedWrite')) :
          '') +
      kit.note(t.html('consoleUsers.mfaSection.realmAllows', {
        primary: keyLive.primaryAllowed ? 'yes' : 'no',
        mfa: keyLive.mfaAllowed ? 'yes' : 'no',
        max: String(keyLive.maxKeysPerPerson) }) +
      '<a href="/admin/webauthn">WebAuthn</a>' +
      t.html('consoleUsers.mfaSection.realmAllowsAfter'));

    // --- the recovery codes
    // --------------------------------------------------- **THE COUNTS AND
    // NEVER THE CODES**, which is why this block reads `mech.backupCodes` — a
    // status object — and there is no call anywhere in this console to the
    // codes themselves. There is no such door anywhere any more — a set is
    // stored as scrypt hashes since 2026-09-11 — and an administrative door
    // that showed somebody's recovery codes would hand a working second factor
    // to whoever holds Admin Read, which is the same refusal this page already
    // makes about enrolling an authenticator app from here. The person's own
    // `/portal/mfa` is the only reader.
    const b = mech.backupCodes || { present: false, total: 0, remaining: 0 };
    const recoveryBlock = '<h3>' +
      t.html('consoleUsers.mfaSection.recoveryHeading') + '</h3>' +
      (!b.present
        ? kit.note('<strong>' + t.html('consoleUsers.mfaSection.noneIssued') +
          '</strong> ' +
          (recoveryLive.enabled
            ? t.html('consoleUsers.mfaSection.recoveryAuto')
            : t.html('consoleUsers.mfaSection.recoveryOffBefore') +
              '<a href="/admin/policies#authn">' +
              t.html('consoleUsers.mfaSection.policies') + '</a>' +
              t.html('consoleUsers.mfaSection.recoveryOffMiddle') + '<a ' +
              'href="/admin/backup-codes">' +
              t.html('consoleUsers.mfaSection.recoveryCodes') + '</a>' +
              t.html('consoleUsers.mfaSection.recoveryOffAfter')))
        : (!b.usable
            ? kit.warn(t.html('consoleUsers.mfaSection.recoveryUnreadable', {
                why: b.why ||
                  t.text('consoleUsers.mfaSection.setUnusable') }))
            : whatTh +
              '<tr><th>' + t.html('consoleUsers.mfaSection.unused') +
              '</th><td>' +
                (b.remaining === 0
                  ? '<strong class="state-revoked">0</strong>' +
                    t.html('consoleUsers.mfaSection.allUsed',
                           { total: String(b.total) })
                  : (b.remaining <= 3
                      // `state-expired` is this console's AMBER, despite the
                      // name — see the stylesheet. Nearly out is a warning and
                      // not a failure, which is exactly what that colour says
                      // everywhere else on this page.
                      ? '<span class="state-expired">' +
                        kit.esc(String(b.remaining)) +
                        '</span>' +
                        t.html('consoleUsers.mfaSection.nearlyOut',
                               { total: String(b.total) })
                      : '<span class="state-valid">' +
                        kit.esc(String(b.remaining)) +
                        '</span>' +
                        t.html('consoleUsers.mfaSection.ofTotal',
                               { total: String(b.total) }))) +
                '</td></tr>' +
              '<tr><th>' + t.html('consoleUsers.mfaSection.issued') +
              '</th><td>' +
                kit.esc(b.generatedAt ? kit.whenText(b.generatedAt) :
                         t.text('consoleUsers.mfaSection.notRecorded')) +
                t.html('consoleUsers.mfaSection.issuedOnce') + '</td></tr>' +
              '<tr><th>' + t.html('consoleUsers.mfaSection.lastUsed') +
              '</th><td>' +
                kit.esc(b.lastUsedAt ? kit.whenText(b.lastUsedAt)
                                     : t.text('consoleUsers.body.never')) +
                '</td></tr>' +
              '<tr><th>' + t.html('consoleUsers.mfaSection.stored') +
              '</th><td>' + (b.sealed
                ? '<span class="state-valid">' +
                  t.html('consoleUsers.mfaSection.encrypted') + '</span>' +
                  t.html('consoleUsers.mfaSection.encryptedBefore') + '<a ' +
                  'href="/admin/ldap/directory">' +
                  t.html('consoleUsers.mfaSection.directoryPage') + '</a>' +
                  t.html('consoleUsers.mfaSection.showsCiphertext')
                : t.html('consoleUsers.mfaSection.asShown')) +
                t.html('consoleUsers.mfaSection.notHashed') +
                '</td></tr></table>' +
              kit.note(t.html('consoleUsers.mfaSection.neverShown')))) +
      (b.present && state.write
        ? '<form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" value="clear-backup-codes">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          carryBack +
          '<div class="formrow"><button class="danger" title="' +
          kit.esc(t.text('consoleUsers.mfaSection.clearCodesTitle')) +
          '">' + t.html('consoleUsers.mfaSection.clearCodes') +
          '</button></div></form>' +
          kit.note(t.html('consoleUsers.mfaSection.clearCodesNote'))
        : (b.present
            ? kit.note(t.html('consoleUsers.mfaSection.clearingNeedsWrite'))
            : ''));

    // --- app passwords (#101, 2026-09-22) ---------------------------------
    // WHAT THIS PERSON USES AT THE FIVE DOORS THAT TAKE ONLY A PASSWORD. The
    // list — name, id, scope, made, last used, never a hash — with a Revoke
    // per row, and a form that makes one and answers it ONCE on the page
    // `usersPost()` draws. `POST /admin-api/users/create-app-password` and
    // `revoke-app-password` are the same two acts (rule 7), and `GET
    // /admin-api/users/app-passwords` is this list, paged.
    const held = data.appPasswords;
    const doorsView = data.doors;
    const appRow = function (one) {
      return '<tr><td>' + kit.esc(one.name) + '</td><td><code>' +
        kit.esc(one.id) + '</code></td><td>' +
        kit.esc((one.doorLabels || one.doors).join(', ')) + '</td><td>' +
        kit.esc(one.createdAt ? kit.whenText(one.createdAt) : '—') +
        (one.createdBy
          ? t.html('consoleUsers.mfaSection.by', { who: one.createdBy })
          : '') +
        '</td><td>' +
        kit.esc(one.lastUsedAt ? kit.whenText(one.lastUsedAt) +
                 (one.lastUsedDoor ? ' (' + one.lastUsedDoor + ')' : '')
                 : t.text('consoleUsers.body.never')) + '</td><td>' +
        (state.write
          ? '<form method="post" action="/admin/users">' +
            '<input type="hidden" name="action" value="revoke-app-password">' +
            '<input type="hidden" name="user" value="' + kit.esc(key) +
            '"><input type="hidden" name="id" value="' + kit.esc(one.id) +
            '"><input type="hidden" name="from" value="user">' +
            '<input type="hidden" name="back" value="' + kit.esc(back) +
            '"><button class="danger" type="submit"' +
            kit.tip(t.text('consoleUsers.mfaSection.revokeAppTip')) + '>' +
            t.html('consoleUsers.userTokenTable.revoke') + '</button></form>'
          : '') + '</td></tr>';
    };
    const appPasswordsBlock = '<h3>' +
      t.html('consoleUsers.mfaSection.appHeading') + '</h3>' +
      kit.note(kit.esc(doorsView.sentence)) +
      (held.unreadable
        ? kit.warn(t.html('consoleUsers.mfaSection.appUnreadable'))
        : (held.passwords.length
            ? '<table><tr><th>' + t.html('consoleUsers.mfaSection.thName') +
              '</th><th>' + t.html('consoleUsers.mfaSection.thId') +
              '</th><th>' + t.html('consoleUsers.mfaSection.thAcceptedAt') +
              '</th>' +
              '<th>' + t.html('consoleUsers.mfaSection.thMade') + '</th><th>' +
              t.html('consoleUsers.mfaSection.thLastUsed') +
              '</th><th></th></tr>' +
              held.passwords.map(appRow).join('') + '</table>'
            : kit.note(t.html('consoleUsers.mfaSection.appNone')))) +
      (state.write
        ? '<form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" value="create-app-password">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          '<input type="hidden" name="from" value="user">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<div class="formrow"><label' +
          kit.tip(t.text('consoleUsers.mfaSection.appNameTip')) + '>' +
          t.html('consoleUsers.mfaSection.thName') + ' <input type="text" ' +
          'name="name" maxlength="64" required></label></div>' +
          '<div class="formrow">' +
          // ONE NAME FOR THE COLUMN, a value per door (#446): the static
          // console sends this form as JSON, where a repeated name is the
          // operation's `doors` list. (The portal's server-read form keeps
          // `door_<door>` — a form parser there keeps the last of a name.)
          // The tooltips are common/app_passwords.ts's DOORS, said again
          // here because a renderer requires nothing but its own kind.
          [['ldap', t.text('consoleUsers.mfaSection.doorLdap')],
           ['wstrust', t.text('consoleUsers.mfaSection.doorWstrust')],
           ['scim', t.text('consoleUsers.mfaSection.doorScim')],
           ['ssf', t.text('consoleUsers.mfaSection.doorSsf')],
           ['est', t.text('consoleUsers.mfaSection.doorEst')]]
            .map(function (door) {
            return '<label' +
                   kit.tip(t.text('consoleUsers.mfaSection.acceptAt',
                                  { door: door[1] })) +
                   '><input type="checkbox" ' +
                   'name="doors" value="' + kit.esc(door[0]) + '"> ' +
                   kit.esc(door[0]) + '</label> ';
          }).join('') + '</div><div class="formrow"><button type="submit" ' +
          'title="' + kit.esc(t.text('consoleUsers.mfaSection.makeAppTitle')) +
          '">' + t.html('consoleUsers.mfaSection.makeApp') +
          '</button></div></form>' +
          kit.note(t.html('consoleUsers.mfaSection.shownOnce'))
        : kit.note(t.html('consoleUsers.mfaSection.appNeedsWrite')));

    // --- identity verifications (#127, 2026-09-23) ------------------------
    // WHAT A CLIENT'S `verified_claims` REQUEST IS ANSWERED FROM (OpenID
    // Connect for Identity Assurance 1.0). The list — framework, evidence,
    // the claims covered, where it came from — with a Remove per row, and a
    // form that records one: a single evidence element as flat fields, which
    // `identity_assurance.ts`'s `fromForm()` turns into the element the API
    // takes as JSON. With no script, every type's fields are drawn and those
    // of the types not chosen are ignored. `POST
    // /admin-api/users/record-verification` and `remove-verification` are
    // the same two acts (rule 7), and `GET /admin-api/users/verifications`
    // is this list, paged.
    const ida = data.verifications;
    const IDA_TIPS = idaTips(t);
    const option = function (value, label?) {
      return '<option value="' + kit.esc(value) + '">' +
             kit.esc(label || value) + '</option>';
    };
    const select = function (name, values, blank?, tip?) {
      return '<select name="' + name + '"' + kit.tip(tip || '') + '>' +
             (blank ? option('', blank) : '') +
             values.map(function (one) {
               return option(one);
             }).join('') + '</select>';
    };
    const field = function (label, name, placeholder?, tip?) {
      return '<label' + kit.tip(tip || '') + '>' + kit.esc(label) +
             ' <input type="text" name="' +
             name + '" maxlength="256"' + (placeholder
               ? ' placeholder="' + kit.esc(placeholder) + '"' : '') +
             '></label> ';
    };
    const idaRow = function (one) {
      const v = one.verification || {};
      return '<tr><td><code>' + kit.esc(v.trust_framework || '') +
        '</code>' + (v.assurance_level
          ? ' (' + kit.esc(v.assurance_level) + ')' : '') + '</td><td>' +
        kit.esc((v.evidence || []).map(function (e) {
          const detail = (e.document_details && e.document_details.type) ||
                         (e.record && e.record.type) ||
                         (e.attestation && e.attestation.type) ||
                         e.signature_type || '';
          return e.type + (detail ? ' — ' + detail : '');
        }).join('; ') || t.text('consoleUsers.mfaSection.noEvidence')) +
        '</td><td>' +
        kit.esc(Object.keys(one.claims || {}).join(', ')) + '</td><td>' +
        kit.esc(v.time ? kit.whenText(v.time) : '—') + '</td><td>' +
        kit.esc(one.source || '') + (one.by ? ' (' + kit.esc(one.by) +
                                      ')' : '') + '</td><td>' +
        (state.write
          ? '<form method="post" action="/admin/users">' +
            '<input type="hidden" name="action" value="remove-verification">' +
            '<input type="hidden" name="user" value="' + kit.esc(key) +
            '"><input type="hidden" name="id" value="' + kit.esc(one.id) +
            '"><input type="hidden" name="from" value="user">' +
            '<input type="hidden" name="back" value="' + kit.esc(back) +
            '"><button class="danger" type="submit"' +
            kit.tip(t.text('consoleUsers.mfaSection.removeVerificationTip')) +
            '>' + t.html('consoleUsers.mfaSection.remove') + '</button></form>'
          : '') + '</td></tr>';
    };
    const verificationsBlock = '<h3>' +
      t.html('consoleUsers.mfaSection.idaHeading') + '</h3>' +
      kit.note(t.html('consoleUsers.mfaSection.idaNote') +
                (data.inventsClaimValues
                  ? t.html('consoleUsers.mfaSection.idaInvents')
                  : t.html('consoleUsers.mfaSection.idaNothing'))) +
      (ida.verifications.length
        ? '<table><tr><th>' + t.html('consoleUsers.mfaSection.thFramework') +
          '</th><th>' + t.html('consoleUsers.mfaSection.thEvidence') +
          '</th>' +
          '<th>' + t.html('consoleUsers.mfaSection.thClaims') + '</th><th>' +
          t.html('consoleUsers.mfaSection.thVerified') + '</th><th>' +
          t.html('consoleUsers.mfaSection.thSource') + '</th><th></th></tr>' +
          ida.verifications.map(idaRow).join('') + '</table>'
        : kit.note('<strong>' + t.html('consoleUsers.mfaSection.noneRecorded') +
                   '</strong>')) +
      (state.write && ida.trustFrameworks.length
        ? '<form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" value="record-verification">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          '<input type="hidden" name="from" value="user">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<div class="formrow"><label' + kit.tip(IDA_TIPS.framework) +
          '>' + t.html('consoleUsers.mfaSection.thFramework') + ' ' +
          select('trust_framework', ida.trustFrameworks) + '</label> ' +
          field(t.text('consoleUsers.mfaSection.assuranceLevel'),
                'assurance_level', '', IDA_TIPS.level) +
          field(t.text('consoleUsers.mfaSection.verifiedAt'), 'time',
                t.text('consoleUsers.mfaSection.timeHint'), IDA_TIPS.time) +
          '</div><div class="formrow"><label' + kit.tip(IDA_TIPS.evidence) +
          '>' + t.html('consoleUsers.mfaSection.thEvidence') + ' ' +
          select('evidence_type', ida.evidenceTypes,
                 t.text('consoleUsers.mfaSection.noEvidence')) + '</label> ' +
          '<label' + kit.tip(IDA_TIPS.check) + '>' +
          t.html('consoleUsers.mfaSection.checkMethod') + ' ' +
          select('check_method', ida.checkMethods,
                 t.text('consoleUsers.mfaSection.noEvidence')) +
          '</label></div>' +
          '<div class="formrow"><strong>document:</strong> <label' +
          kit.tip(IDA_TIPS.documentType) + '>' +
          t.html('consoleUsers.mfaSection.type') + ' ' +
          select('document_type', ida.documentTypes) + '</label> ' +
          field(t.text('consoleUsers.mfaSection.number'), 'document_number',
                '', IDA_TIPS.documentNumber) +
          field(t.text('consoleUsers.mfaSection.issuer'), 'issuer_name', '',
                IDA_TIPS.issuer) +
          field(t.text('consoleUsers.mfaSection.issuerCountry'),
                'issuer_country', 'DEU', IDA_TIPS.country) +
          field(t.text('consoleUsers.mfaSection.issued'), 'date_of_issuance',
                'YYYY-MM-DD', IDA_TIPS.issued) +
          field(t.text('consoleUsers.mfaSection.expires'), 'date_of_expiry',
                'YYYY-MM-DD', IDA_TIPS.expires) +
          '</div>' +
          '<div class="formrow"><strong>electronic_record:</strong> ' +
          '<label' + kit.tip(IDA_TIPS.recordType) + '>' +
          t.html('consoleUsers.mfaSection.type') + ' ' +
          select('record_type', ida.electronicRecordTypes) +
          '</label> ' + field(t.text('consoleUsers.mfaSection.thSource'),
                               'source_name', '',
                               IDA_TIPS.recordSource) + '</div>' +
          '<div class="formrow"><strong>vouch:</strong> <label' +
          kit.tip(IDA_TIPS.vouchType) + '>' +
          t.html('consoleUsers.mfaSection.type') + ' ' +
          select('attestation_type', ida.attestationTypes) + '</label> ' +
          field(t.text('consoleUsers.mfaSection.reference'),
                'reference_number', '', IDA_TIPS.reference) +
          field(t.text('consoleUsers.mfaSection.voucher'), 'voucher_name', '',
                IDA_TIPS.voucher) + '</div>' +
          '<div class="formrow"><strong>electronic_signature:</strong> ' +
          field(t.text('consoleUsers.mfaSection.signatureType'),
                'signature_type', '', IDA_TIPS.signatureType) +
          field(t.text('consoleUsers.mfaSection.issuer'), 'signature_issuer',
                '', IDA_TIPS.signatureIssuer) +
          field(t.text('consoleUsers.mfaSection.serialNumber'),
                'serial_number', '', IDA_TIPS.serial) +
          field(t.text('consoleUsers.mfaSection.created'), 'created_at',
                '2026-09-23T10:00:00Z', IDA_TIPS.created) + '</div>' +
          '<div class="formrow">' +
          t.html('consoleUsers.mfaSection.claimsVerified') + ' ' +
          ida.verifiableClaims.map(function (claim) {
            // One field per claim, as the app-password doors are: a form
            // body keeps only the last of a repeated name.
            return '<label' +
                   kit.tip(t.text('consoleUsers.mfaSection.recordClaimTip',
                                  { claim: claim })) +
                   '><input type="checkbox" name="claim_' +
                   kit.esc(claim) + '" value="on"> ' + kit.esc(claim) +
                   '</label> ';
          }).join('') + '</div><div class="formrow"><button ' +
          'type="submit" title="' +
          kit.esc(t.text('consoleUsers.mfaSection.recordTitle')) +
          '">' + t.html('consoleUsers.mfaSection.record') +
          '</button></div></form>'
        : (state.write
            ? kit.note(t.html('consoleUsers.mfaSection.noFrameworkBefore') +
                        '<a href="/admin/oauth2">OAuth 2.0 / OIDC</a>' +
                        t.html('consoleUsers.mfaSection.noFrameworkAfter'))
            : kit.note(t.html('consoleUsers.mfaSection.idaNeedsWrite'))));

    // --- devices (#130, 2026-09-23) ----------------------------------------
    // THE PERSON'S DEVICES: the entries in ou=devices they own, each linked
    // to the applications that used it, with whether its Native SSO secret
    // is live, and a Remove each. `GET /admin-api/users/devices` and `POST
    // /admin-api/users/remove-device` are the same (rule 7).
    const deviceView = data.devices;
    const deviceRow = function (one) {
      return '<tr><td><a href="/admin/devices?device=' +
        encodeURIComponent(one.id) + '">' + kit.esc(one.label) +
        '</a><br><code>' + kit.esc(one.id) + '</code></td><td>' +
        (one.applications.length
          ? one.applications.map(function (dn) {
              return '<code>' + kit.esc(dn) + '</code>';
            }).join('<br>') : '—') + '</td><td>' +
        (one.nativeSso
          ? (one.sessionLive ? t.html('consoleUsers.mfaSection.live')
                             : t.html('consoleUsers.mfaSection.sessionEnded'))
          : t.html('consoleUsers.secondFactorCell.none')) + '</td><td>' +
        kit.esc(one.lastUsed ? kit.whenText(one.lastUsed) : '—') +
        '</td><td>' +
        (state.write
          ? '<form method="post" action="/admin/users">' +
            '<input type="hidden" name="action" value="remove-device">' +
            '<input type="hidden" name="user" value="' + kit.esc(key) +
            '"><input type="hidden" name="id" value="' + kit.esc(one.id) +
            '"><input type="hidden" name="from" value="user">' +
            '<input type="hidden" name="back" value="' + kit.esc(back) +
            '"><button class="danger" type="submit"' +
            kit.tip(t.text('consoleUsers.mfaSection.removeDeviceTip')) +
            '>' + t.html('consoleUsers.mfaSection.remove') + '</button></form>'
          : '') + '</td></tr>';
    };
    const devicesBlock = '<h3>' +
      t.html('consoleUsers.mfaSection.devicesHeading') + '</h3>' +
      kit.note(t.html('consoleUsers.mfaSection.devicesBefore') +
                '<a href="/admin/devices">' +
                t.html('consoleUsers.mfaSection.devicesLink') + '</a>.') +
      (deviceView.devices.length
        ? '<table><tr><th>' + t.html('consoleUsers.mfaSection.thDevice') +
          '</th><th>' + t.html('consoleUsers.mfaSection.thApplications') +
          '</th>' +
          '<th>Native SSO</th><th>' +
          t.html('consoleUsers.mfaSection.thLastUsed') +
          '</th><th></th></tr>' +
          deviceView.devices.map(deviceRow).join('') + '</table>'
        : kit.note('<strong>' + t.html('consoleUsers.mfaSection.none') +
                   '</strong>')) +
      (state.write ? ''
        : kit.note(t.html('consoleUsers.mfaSection.removeNeedsWrite')));

    // --- self-issued IDs (#129, 2026-09-23) --------------------------------
    // THE WALLET KEYS WHOSE SIOPv2 ID TOKEN SIGNS THIS PERSON IN. The list
    // with a Remove each, and a form that enrols one BY VALUE — the
    // administrator's door; the person's own proves the key on
    // `/portal/self-issued`. `POST /admin-api/users/enrol-self-issued-subject`
    // and `remove-self-issued-subject` are the same two acts (rule 7), and
    // `GET /admin-api/users/self-issued-subjects` is this list.
    const siopView = data.selfIssued;
    const siopRow = function (one) {
      return '<tr><td><code>' + kit.esc(one.subject) + '</code></td><td>' +
        kit.esc(one.label || '') + '</td><td>' +
        kit.esc(one.enrolledAt ? kit.whenText(one.enrolledAt) : '—') +
        (one.by ? t.html('consoleUsers.mfaSection.by', { who: one.by }) : '') +
        '</td><td>' +
        (state.write
          ? '<form method="post" action="/admin/users">' +
            '<input type="hidden" name="action" ' +
            'value="remove-self-issued-subject">' +
            '<input type="hidden" name="user" value="' + kit.esc(key) +
            '"><input type="hidden" name="subject" value="' +
            kit.esc(one.subject) + '"><input type="hidden" name="from" ' +
            'value="user"><input type="hidden" name="back" value="' +
            kit.esc(back) + '"><button class="danger" ' +
            'type="submit"' +
            kit.tip(t.text('consoleUsers.mfaSection.removeSiopTip')) +
            '>' + t.html('consoleUsers.mfaSection.remove') + '</button></form>'
          : '') + '</td></tr>';
    };
    const selfIssuedBlock = '<h3>' +
      t.html('consoleUsers.mfaSection.siopHeading') + '</h3>' +
      kit.note(t.html('consoleUsers.mfaSection.siopNote',
                      { on: siopView.signInEnabled ? 'yes' : 'no' })) +
      (siopView.subjects.length
        ? '<table><tr><th>' + t.html('consoleUsers.mfaSection.thSubject') +
          '</th><th>' + t.html('consoleUsers.mfaSection.thLabel') +
          '</th><th>' + t.html('consoleUsers.mfaSection.enrolled') + '</th>' +
          '<th></th></tr>' + siopView.subjects.map(siopRow).join('') +
          '</table>'
        : kit.note(t.html('consoleUsers.mfaSection.siopNone'))) +
      (state.write
        ? '<form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" ' +
          'value="enrol-self-issued-subject">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          '<input type="hidden" name="from" value="user">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<div class="formrow"><label' +
          kit.tip(t.text('consoleUsers.mfaSection.siopSubjectTip')) + '>' +
          t.html('consoleUsers.mfaSection.thSubject') + ' <input ' +
          'type="text" name="subject" size="60" maxlength="2048" required ' +
          'placeholder="' +
          kit.esc(t.text('consoleUsers.mfaSection.siopSubjectHint')) +
          '"></label> <label' +
          kit.tip(t.text('consoleUsers.mfaSection.siopLabelTip')) + '>' +
          t.html('consoleUsers.mfaSection.thLabel') + ' ' +
          '<input type="text" name="label" maxlength="64"></label></div>' +
          '<div class="formrow"><button type="submit" title="' +
          kit.esc(t.text('consoleUsers.mfaSection.enrolTitle')) + '">' +
          t.html('consoleUsers.mfaSection.enrol') + '</button>' +
          '</div></form>'
        : kit.note(t.html('consoleUsers.mfaSection.siopNeedsWrite')));

    const html = heading +
      kit.note(t.html('consoleUsers.mfaSection.leadBefore',
                      { name: row.name }) +
      '<a href="/admin/totp">TOTP MFA</a>' +
      t.html('consoleUsers.mfaSection.leadAnd') +
      '<a href="/admin/webauthn">WebAuthn</a>' +
      t.html('consoleUsers.mfaSection.leadAfter')) +
      wayIn + totpBlock + UsersPage.emailFactorBlock(t, key, mech, state,
                                                carryBack, data.mail) +
      keysBlock + recoveryBlock + appPasswordsBlock +
      devicesBlock + selfIssuedBlock + verificationsBlock;

    // ONE SOURCE for what this panel says (2026-09-12): the layer builds it,
    // this draws it — and since #446 draws it from the answer's `page.mfa`.
    return html;
  }

  // The drill-down. Returns null when the identity is not one this service
  // knows, which the route below turns into an honest empty page rather than a
  // 404: a user can genuinely be forgotten to the cap between the click and the
  // page.
  // ===========================================================================
  // ONE PERSON'S SECOND FACTORS, ON THEIR OWN ROW (2026-09-10).
  //
  // **THIS IS WHERE `/admin/mfa`'s PER-PERSON HALF WENT.** That page listed
  // everybody and gave each row a Clear button; the roster is columns on the
  // list above now and this is the detail. What it buys is the thing a page of
  // forty people could not have: this section can say what the enrolment IS —
  // which digest, how many digits, how long a step, when it was set up, when it
  // was last used, whether the secret is sealed — and it can list a person's
  // security keys one at a time with the role each is in.
  //
  // ---------------------------------------------------------------------------
  // TWO MECHANISMS, AND THE WEBAUTHN HALF IS THE ONE THAT NEEDS EXPLAINING.
  //
  // A WebAuthn key is here only where it is a SECOND FACTOR — the `mfa` role. A
  // `primary` key is a way IN rather than a second factor, so it is reported
  // under what this person can sign in with and not as an MFA credential.
  // `credentials.js`'s ROLES table is what tells them apart, and this section
  // reads it rather than deciding.
  //
  // ---------------------------------------------------------------------------
  // THE TWO REMOVALS ARE NOT THE SAME ACT AND THE BUTTONS SAY SO.
  //
  // Clearing an authenticator app CANNOT lock anybody out: a one-time code is
  // never a primary credential here, so clearing one drops the account to one
  // factor and never to none. Removing a security KEY can — it may be the only
  // credential there is — so it goes through `credentials.removeKey()`, which
  // refuses to remove the last way in. An operator must not be able to do what
  // the person themselves is stopped from doing.
  // ===========================================================================
  // THE EMAILED SECOND FACTOR (#64) on a person's page: whether they opted
  // in, whether it is being used and why not, and the one control an operator
  // has over it — clearing it. There is no Turn On: the opt-in is the
  // person's (D8), and an operator who wanted them asked for a second factor
  // requires one, which the sign-in screen then asks them to set up.
  //
  // Beside it, the ADDRESS (#64 P2): what `mail` holds, whether it is
  // verified and by whom, and — for Admin Write — a form to set it, which
  // marks it verified because an administrator is a trusted source.
  /**
   * Draws a person's email address and emailed second factor, with the
   * Admin Write forms to turn the factor off, set an `aud_sub` and set the
   * address.
   *
   * An address set here is marked verified.
   *
   * @param t - the page's translator
   * @param key - the person's key
   * @param mech - the person's mechanisms from credentials.mechanismsFor()
   * @param state - the gate state; `write` draws the forms
   * @param carryBack - hidden inputs carrying the way back
   * @param mail - `status` (`mailFactor.status()`), `usable` (whether the
   *   realm can send mail) and `audSubs` (`credentials.audSubsOf()`)
   * @returns the block as HTML
   */
  static emailFactorBlock(t, key, mech, state, carryBack, mail) {
    const mf = mech.mailFactor || { held: '', optedIn: '', why: '' };
    const status = mail.status;
    const mailUsable = mail.usable;
    const out = '<h3>' + t.html('consoleUsers.emailFactorBlock.heading') +
      '</h3>' +
      '<table class="key"><tr><th>' +
      t.html('consoleUsers.mfaSection.thWhat') + '</th><th>' +
      t.html('consoleUsers.mfaSection.thAnswer') + '</th></tr>' +
      '<tr><th>' + t.html('consoleUsers.emailFactorBlock.address') +
      '</th><td>' + (status.address
        ? '<code>' + kit.esc(status.address) + '</code> — ' +
          (status.verified
            ? '<span class="state-valid">' +
              t.html('consoleUsers.emailFactorBlock.verified') + '</span>'
            : '<span class="state-none">' +
              t.html('consoleUsers.emailFactorBlock.notVerified') + '</span>')
        : '<span class="state-none">' +
          t.html('consoleUsers.secondFactorCell.none') + '</span>') +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleUsers.emailFactorBlock.factor') +
      '</th><td>' + (mf.optedIn
        ? (mf.held
          ? '<span class="state-valid">' +
            t.html('consoleUsers.emailFactorBlock.on') + '</span>' +
            t.html('consoleUsers.emailFactorBlock.onNote', { held: mf.held })
          : t.html('consoleUsers.emailFactorBlock.chosen',
                   { opted: mf.optedIn, why: mf.why }))
        : '<span class="state-none">' +
          t.html('consoleUsers.emailFactorBlock.off') + '</span>' +
          t.html('consoleUsers.emailFactorBlock.offBefore') +
          '<a href="/admin/policies#authn">' +
          t.html('consoleUsers.emailFactorBlock.authnPolicy') + '</a>' +
          t.html('consoleUsers.emailFactorBlock.offAfter')) + '</td></tr>' +
      (status.failures
        ? '<tr><th>' + t.html('consoleUsers.emailFactorBlock.failures') +
          '</th><td>' +
          kit.esc(String(status.failures)) + '</td></tr>' : '') +
      '</table>' +
      (state.write && mf.optedIn
        ? '<form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" value="clear-email-factor">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          carryBack + '<div class="formrow"><button class="danger"' +
          kit.tip(t.text('consoleUsers.emailFactorBlock.turnOffTip')) + '>' +
          t.html('consoleUsers.emailFactorBlock.turnOff') +
          '</button></div></form>'
        : '') +
      // THE ACCOUNT IDS CLIENTS KNOW THIS PERSON BY (#148): each sent as the
      // ID Token's `aud_sub` to that client (Enterprise Extensions 2.3).
      (state.write
        ? '<div id="aud-sub"><p class="sub">' +
          t.html('consoleUsers.emailFactorBlock.accountIds') + ' ' +
          (mail.audSubs.map(
            (v: string) => '<code>' + kit.esc(v) + '</code>').join(', ') ||
            t.html('consoleUsers.secondFactorCell.none')) +
          '</p><form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" value="set-aud-sub">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          carryBack + '<div class="formrow"><label' +
          kit.tip(t.text('consoleUsers.emailFactorBlock.clientTip')) +
          '>client_id <input ' +
          'type="text" name="client" size="24" maxlength="256" required>' +
          '</label> <label' +
          kit.tip(t.text('consoleUsers.emailFactorBlock.audSubTip')) +
          '>aud_sub <input type="text" ' +
          'name="value" size="24" maxlength="255"></label> <button ' +
          'type="submit"' +
          kit.tip(t.text('consoleUsers.emailFactorBlock.setTip')) + '>' +
          t.html('consoleUsers.emailFactorBlock.set') +
          '</button></div></form></div>'
        : '') +
      (state.write
        ? '<form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" value="set-mail">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          carryBack + '<div class="formrow"><label' +
          kit.tip(t.text('consoleUsers.emailFactorBlock.addressTip')) + '>' +
          t.html('consoleUsers.emailFactorBlock.address') + ' <input ' +
          'type="email" name="mail" size="40" maxlength="254" required ' +
          'value="' + kit.esc(status.address) + '"></label> ' +
          '<button type="submit"' +
          kit.tip(t.text('consoleUsers.emailFactorBlock.setAddressTip')) +
          '>' + t.html('consoleUsers.emailFactorBlock.setAddress') +
          '</button></div></form>' +
          kit.note(t.html('consoleUsers.emailFactorBlock.setNote',
                          { usable: mailUsable ? 'yes' : 'no' }))
        : kit.note(t.html('consoleUsers.emailFactorBlock.needsWrite')));
    return out;
  }

  // A STORED KEY'S SIGNATURE ALGORITHM (2026-10-01), `credentials.
  // keyAlgorithm()`'s answer: the JOSE name and COSE identifier, marked
  // post-quantum (ML-DSA) or insecure (RS1). The answer carries it on each
  // key as `algorithm` since #446, and this draws it.
  /**
   * Draws a key's algorithm, marked post-quantum or insecure.
   *
   * @param t - the page's translator
   * @param algorithm - what `credentials.keyAlgorithm()` answered
   * @returns the cell's HTML
   */
  static algorithmCell(t, algorithm) {
    return '<code>' + kit.esc(algorithm.text) + '</code>' +
      (algorithm.postQuantum
        ? ' <span class="state-valid">' +
          t.html('consoleUsers.algorithmCell.postQuantum') + '</span>' : '') +
      (algorithm.insecure
        ? ' <span class="state-revoked">' +
          t.html('consoleUsers.algorithmCell.insecure') + '</span>' : '');
  }

  // A key's attestation, for its row (#105): what the statement proved, or
  // "claimed" where nothing was verified — the AAGUID then is only what the
  // authenticator data said.
  /**
   * Describes a WebAuthn key's attestation for its row: verified and
   * trusted or untrusted, or only claimed when nothing was verified.
   *
   * @param t - the page's translator
   * @param att - the key's recorded attestation, if any
   * @param aaguid - the authenticator's AAGUID, if any
   * @returns the description as HTML
   */
  static attestationCell(t, att, aaguid) {
    // The tooltips are built of plain-text pieces and escaped whole, as
    // they always were.
    if (!att || !att.verified) {
      return '<span class="state-none" title="' +
        kit.esc(t.text('consoleUsers.attestationCell.claimedTitle') +
                 (att && att.format
                   ? t.text('consoleUsers.attestationCell.formatPolicy',
                            { format: att.format, policy: att.policy })
                   : '') +
                 t.text('consoleUsers.attestationCell.claimedTitleAfter')) +
        '">' + t.html('consoleUsers.attestationCell.claimed') +
        (aaguid ? ' <code>' + kit.esc(aaguid) + '</code>' : '') + '</span>';
    }
    return '<span class="' + (att.trusted ? 'state-valid' : 'state-none') +
      '" title="' + kit.esc(t.text('consoleUsers.attestationCell.formatType',
                                   { format: att.format, type: att.type }) +
      (att.trusted
        ? (att.anchor === 'mds'
          ? t.text('consoleUsers.attestationCell.chainedMds')
          : t.text('consoleUsers.attestationCell.chainedAnchor'))
        : t.text('consoleUsers.attestationCell.notChained')) +
      (att.certificationLevel ? ', ' + att.certificationLevel : '') +
      '.') + '">' + (att.trusted
        ? t.html('consoleUsers.attestationCell.trusted')
        : t.html('consoleUsers.attestationCell.untrusted')) + '</span>' +
      (att.model ? ' — ' + kit.esc(att.model) : '') +
      ' <code>' + kit.esc(att.format) + '</code>' +
      UsersPage.androidRevocationText(t, att);
  }

  // What Google's Android attestation status list said of an android-key
  // chain (#256): good, revoked or suspended with the serial, or unchecked
  // with why — and, for a key registered before the check, nothing to say.
  static androidRevocationText(t, att) {
    const r = att && att.androidRevocation;
    if (!att || att.format !== 'android-key') {
      return '';
    }
    if (!r) {
      return ' <small class="state-none">' +
        t.html('consoleUsers.androidRevocationText.unknown') + '</small>';
    }
    const status = String(r.status || 'unchecked');
    return ' <small class="' + (status === 'good' ? 'state-valid'
      : status === 'unchecked' ? 'state-none' : 'state-expired') + '">' +
      (status === 'good'
        ? t.html('consoleUsers.androidRevocationText.notRevoked')
        : status === 'unchecked'
          ? t.html('consoleUsers.androidRevocationText.unchecked',
                   { why: r.why || '' })
          : t.html('consoleUsers.androidRevocationText.revoked', {
              status: status.toUpperCase(), serial: r.serial || '' }) +
            (r.reason ? ' (' + kit.esc(r.reason) + ')' : '')) +
      (r.listVersion
        ? t.html('consoleUsers.androidRevocationText.list',
                 { version: r.listVersion })
        : '') + '</small>';
  }

  // ---------------------------------------------------------------------------
  // A PERSON'S CREDENTIALS: THEIR RFC 7523 AND RFC 7522 KEY PAIRS, ON THEIR OWN
  // PAGE (2026-09-13).
  //
  // The application page's Credentials section, for a person. Per profile: the
  // key pair on their entry and where it came from, and the controls that
  // REPLACE it — issue one from this realm's certificate authority, or upload a
  // certificate the person already holds (this realm's alone, or another
  // authority's with its whole chain) — and take it off.
  //
  // **THE SAME ACTIONS AND NOT NEW ONES.** Issue is `/admin/pki`'s `issue` with
  // `target=person`, posted to `/admin/pki/person` because what comes back is a
  // PRIVATE KEY and that route answers with a page rather than a redirect;
  // Upload is `upload-certificate` and Take off is `revoke`, both to
  // `/admin/pki`. All three carry `from`, so the handler sends the reader back
  // here through userReturnTo(), and all three are `/admin-api/pki/{action}`
  // with no second operation — moving a form is not moving an action.
  //
  // **WHAT IS DIFFERENT FROM THE APPLICATION'S IS THE PRIVATE KEY.** An
  // application's is readable afterwards through `applications.view()`; a
  // person's is not readable by anybody, so this section says whether one is
  // held and the issue page is the one place it is ever shown.
  //
  // **THE CONTROLS NEED ADMIN WRITE AND ARE DRAWN ONLY FOR IT**, the
  // second-factor section's rule beside it: a button whose only outcome is the
  // gate's refusal is a control that can only fail.
  // ---------------------------------------------------------------------------
  /**
   * Draws a person's RFC 7523 and RFC 7522 key pairs, one per profile, with
   * the Admin Write forms that issue, upload or take one off through
   * /admin/pki.
   *
   * @param t - the page's translator
   * @param key - the person's key
   * @param state - the person's credential state (storable, found,
   *   username, ca, purposes)
   * @param gate - the gate state; `write` draws the forms
   * @param back - the list to return to after an action
   * @returns the section as HTML
   */
  static userCredentialsSection(t, key, state, gate, back) {
    const PERSON_KEY_SOURCE_SENTENCES = personKeySourceSentences(t);
    const hidden = function (name, value) {
      return '<input type="hidden" name="' + name + '" value="' +
             kit.esc(value) +
             '">';
    };
    const heading = '<h2 id="credentials">' +
      t.html('consoleUsers.userCredentialsSection.heading') + '</h2>' +
      kit.note(t.html('consoleUsers.userCredentialsSection.lead'));
    if (!state.storable) {
      return heading +
        kit.warn(t.html('consoleUsers.userCredentialsSection.noDirectory'),
                 t.text(
                   'consoleUsers.userCredentialsSection.noDirectoryLabel'));
    }
    if (!state.found) {
      return heading +
        kit.note(t.html('consoleUsers.userCredentialsSection.noEntry',
                        { key: key }));
    }
    const username = state.username;
    const algOptions = state.ca.keyAlgorithms.map(function (one) {
      return '<option value="' + kit.esc(one.id) + '">' + kit.esc(one.label) +
             '</option>';
    }).join('');
    const purposeHtml = state.purposes.map(function (p) {
      const names = p.attributes;
      const anchor = 'credentials-' + p.id;
      const chainCells = p.chain.length
        ? '<ol>' + p.chain.map(function (link) {
            return '<li>' + ApplicationsPage.certificateCells(link, t) +
                   '</li>';
          }).join('') + '</ol>'
        : (p.held
          ? '<span class="state-none">' +
            t.html('consoleUsers.userCredentialsSection.noneStored') +
            '</span>'
          : '&mdash;');
      const managed = p.held
        ? '<table><tr><th>' +
          t.html('consoleUsers.userCredentialsSection.thFact') + '</th><th>' +
          t.html('consoleUsers.userCredentialsSection.thValue') +
          '</th></tr>' +
          '<tr><td>' + t.html('consoleUsers.mfaSection.thSource') +
          '<div class="sub"><code>' + kit.esc(names.source) +
          '</code></div></td><td><code>' + kit.esc(p.source) + '</code>' +
          '<div class="sub">' + (PERSON_KEY_SOURCE_SENTENCES[p.source] ||
                                 kit.esc(p.source)) + '</div></td></tr>' +
          '<tr><td>' +
          t.html('consoleUsers.userCredentialsSection.certificate') +
          '<div class="sub"><code>' +
          kit.esc(names.certificate) +
          '</code></div></td><td>' +
          ApplicationsPage.certificateCells(p.certificate, t) +
          '</td></tr>' +
          '<tr><td>' + t.html('consoleUsers.userCredentialsSection.chain') +
          '<div class="sub"><code>' + kit.esc(names.chain) +
          '</code></div></td><td>' + chainCells + '</td></tr>' +
          '<tr><td>' + t.html('consoleUsers.userCredentialsSection.handle') +
          '<div class="sub"><code>' + kit.esc(names.handle) +
          '</code></div></td><td><code>' + kit.esc(p.handle || '—') +
          '</code> <span class="sub">(' + kit.esc(p.handleLabel) +
          ')</span></td></tr>' +
          '<tr><td>' +
          t.html('consoleUsers.userCredentialsSection.privateKey') +
          '<div class="sub"><code>' +
          kit.esc(names.privateKey) + '</code></div></td><td>' +
          (p.privateKeyHeld
            ? '<span class="state-valid">' +
              t.html('consoleUsers.userCredentialsSection.heldHere') +
              '</span>' +
              (state.sealsAtRest
                ? t.html('consoleUsers.userCredentialsSection.sealedAtRest')
                : '') +
              '<div class="sub">' +
              t.html('consoleUsers.userCredentialsSection.shownOnce') +
              '</div>'
            : '<span class="state-none">' +
              t.html('consoleUsers.userCredentialsSection.notHeld') +
              '</span><div class="sub">' +
              t.html('consoleUsers.userCredentialsSection.theyKeep') +
              '</div>') +
          '</td></tr>' +
          '<tr><td>' +
          t.html('consoleUsers.userCredentialsSection.assertsAs') +
          '<div class="sub"><code>' + kit.esc(names.issuer) +
          '</code></div></td><td>' + p.effectiveIssuers.map(function (iss) {
            return '<code>' + kit.esc(iss) + '</code>';
          }).join('<br>') + (p.issuers.length ? ''
            : ' <span class="sub">' +
              t.html('consoleUsers.userCredentialsSection.ownName') +
              '</span>') + '</td></tr></table>'
        : kit.note(t.html('consoleUsers.userCredentialsSection.noneHeld')) +
          // The issuers are markup (each in its <code>), so the sentence is
          // two messages around them.
          (p.issuers.length
            ? kit.note(
                t.html('consoleUsers.userCredentialsSection.declaredBefore') +
                p.issuers.map(function (iss) {
                  return '<code>' + kit.esc(iss) + '</code>';
                }).join(', ') +
                t.html('consoleUsers.userCredentialsSection.declaredAfter'))
            : '');

      if (!gate.write) {
        return '<h3 id="' + anchor + '">' + kit.esc(p.label) + '</h3>' +
               managed +
          kit.note(t.html('consoleUsers.userCredentialsSection.needsWrite'));
      }
      const issueForm = state.ca.available
        ? '<form method="post" action="/admin/pki/person">' +
          '<div class="formrow">' + hidden('action', 'issue') +
          hidden('target', 'person') + hidden('from', '/admin/users') +
          hidden('back', back) + hidden('identifier', username) +
          hidden('purpose', p.id) +
          '<label for="' + anchor + '-alg">' +
          t.html('consoleUsers.userCredentialsSection.keyAlgorithm') +
          '</label>' +
          '<select id="' + anchor + '-alg" name="leafKeyAlg">' +
          '<option value="">' +
          t.html('consoleUsers.userCredentialsSection.caDefault',
                 { alg: state.ca.keyAlg }) +
          '</option>' + algOptions + '</select>' +
          '<label for="' + anchor + '-days">' +
          t.html('consoleUsers.userCredentialsSection.days') + '</label>' +
          '<input type="number" id="' + anchor + '-days" name="days" min="1" ' +
          'value="' + kit.esc(String(state.ca.leafLifetimeDays)) + '">' +
          '<label for="' + anchor + '-issuer">' +
          t.html('consoleUsers.userCredentialsSection.declaredIssuer') +
          '</label>' +
          '<input id="' + anchor + '-issuer" name="issuer" placeholder="' +
          kit.esc(t.text('consoleUsers.userCredentialsSection.issuerHint')) +
          '">' +
          '<button type="submit">' + (p.held
            ? t.html('consoleUsers.userCredentialsSection.replaceIssue')
            : t.html('consoleUsers.userCredentialsSection.issue')) +
          '</button>' +
          '</div></form>'
        : kit.note(t.html('consoleUsers.userCredentialsSection.noCaBefore') +
                    '<a href="/admin/pki">' +
                    t.html('consoleUsers.userCredentialsSection.buildOne') +
                    '</a>' +
                    t.html('consoleUsers.userCredentialsSection.noCaAfter'));

      const uploadForm = '<form method="post" action="/admin/pki">' +
        hidden('action', 'upload-certificate') + hidden('target', 'person') +
        hidden('from', '/admin/users') + hidden('back', back) +
        hidden('identifier', username) + hidden('purpose', p.id) +
        '<div class="formrow"><label for="' + anchor + '-cert"' +
        kit.tip(t.text('consoleUsers.userCredentialsSection.certTip')) + '>' +
        t.html('consoleUsers.userCredentialsSection.certPem') +
        '</label><textarea id="' + anchor + '-cert" name="certificate" ' +
        'rows="6" required' +
        kit.tip(t.text('consoleUsers.userCredentialsSection.certAreaTip')) +
        ' placeholder="-----BEGIN ' +
        'CERTIFICATE-----"></textarea></div><div class="formrow"><label ' +
        'for="' + anchor + '-chain"' +
        kit.tip(t.text('consoleUsers.userCredentialsSection.chainTip')) +
        '>' + t.html('consoleUsers.userCredentialsSection.chainPem') +
        '</label><textarea id="' +
        anchor +
        '-chain" name="chain" rows="6"' +
        kit.tip(t.text('consoleUsers.userCredentialsSection.chainAreaTip')) +
        ' placeholder="-----BEGIN ' +
        'CERTIFICATE-----"></textarea></div><div class="formrow"><button ' +
        'type="submit"' +
        kit.tip(t.text('consoleUsers.userCredentialsSection.uploadTip')) +
        '>' +
        (p.held ? t.html('consoleUsers.userCredentialsSection.replaceUpload')
                : t.html('consoleUsers.userCredentialsSection.upload')) +
        '</button></div></form>';

      const takeOff = p.held || p.issuers.length
        ? '<form method="post" action="/admin/pki">' +
          '<div class="formrow">' + hidden('action', 'revoke') +
          hidden('target', 'person') + hidden('from', '/admin/users') +
          hidden('back', back) + hidden('identifier', username) +
          hidden('purpose', p.id) +
          '<button type="submit" class="danger"' +
          kit.tip(t.text('consoleUsers.userCredentialsSection.takeOffTip')) +
          '>' + t.html('consoleUsers.userCredentialsSection.takeOff') +
          '</button><span class="sub">' +
          t.html('consoleUsers.userCredentialsSection.notRevocation') +
          '</span></div></form>'
        : '';

      return '<h3 id="' + anchor + '">' + kit.esc(p.label) + '</h3>' +
             managed +
        '<h4>' + t.html('consoleUsers.userCredentialsSection.replaceHeading') +
        '</h4>' +
        kit.note(t.html('consoleUsers.userCredentialsSection.replaceNote')) +
        issueForm + uploadForm + takeOff;
    }).join('');
    return heading + purposeHtml +
      (state.selfService
        ? kit.note(t.html('consoleUsers.userCredentialsSection.selfService'))
        : '');
  }

  // ---------------------------------------------------------------------------
  // RESET A PASSWORD, ISSUE A RESET LINK, DISABLE PASSKEYS, DISABLE OR REQUIRE
  // MFA — ON THE PERSON'S OWN PAGE (2026-09-13).
  //
  // Six controls over six actions on `usersAction()`
  // (`admin-core/admin_actions.ts` argues each), posted to `/admin/users` with
  // `from=user` so the reader lands back here, and mirrored at
  // `POST /admin-api/users/{action}`.
  //
  // **A RESET ANSWERS WITH A PAGE**, because what it hands back exists once —
  // see the users action endpoint. **EVERY CONTROL IS DRAWN FOR ADMIN WRITE
  // ONLY**, the rule the two sections above follow: a button whose only outcome
  // is the gate's refusal is a control that can only fail. And a control that
  // cannot do anything for THIS person is not drawn at all — no Disable
  // passkeys button for somebody with no primary key — with a sentence saying
  // why it is absent.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE PERSON'S FEDERATION LINKS (#109, 2026-09-22): which partner's subject
  // signs them in, through which relationship. A table with a Remove per link,
  // and a form to add one — the console half of `POST /admin-api/users/
  // federation-link` and `/federation-unlink` (rule 7), both of which reach
  // `admin-core/admin_actions.ts`'s federationLinkAction(). Paged, like every
  // list on this page.
  // ---------------------------------------------------------------------------
  /**
   * Draws a person's federation links, paged, with a Remove per link and a
   * form to add one for Admin Write.
   *
   * @param t - the page's translator
   * @param key - the person's key
   * @param page - the page of links, with its paging
   * @param gate - the gate state; `write` draws the forms
   * @param back - the list to return to after an action
   * @param params - the page's query, for the pager's links
   * @param relationships - the service-provider relationships a link may
   *   name (`fedId`, `fedPeer`)
   * @returns the section as HTML
   */
  static userFederationLinksSection(t, key, page, gate, back, params,
                                    relationships) {
    const heading = '<h2 id="federation-links">' +
      t.html('consoleUsers.federationLinks.heading') + '</h2>' +
      kit.note(t.html('consoleUsers.federationLinks.lead'));
    const nav = kit.pageNavPair('/admin/users', params, page.paging, t);
    const form = function (action, fields, label, danger) {
      return '<form method="post" action="/admin/users">' +
        '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
        '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
        '<input type="hidden" name="from" value="user">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        fields + '<div class="formrow"><button' +
        (danger ? ' class="danger"' : '') + '>' + kit.esc(label) +
        '</button></div></form>';
    };
    const rows = page.shown.length
      ? '<table><tr><th>' +
        t.html('consoleUsers.federationLinks.thRelationship') +
        '</th><th>' + t.html('consoleUsers.mfaSection.issuer') +
        '</th><th>' + t.html('consoleUsers.mfaSection.thSubject') + '</th>' +
        '<th></th></tr>' + page.shown.map(function (one) {
          return '<tr><td><code>' + kit.esc(one.relationship) + '</code>' +
            (one.relationshipExists ? ''
              : ' <span class="sub">' +
                t.html('consoleUsers.federationLinks.noSuch') +
                '</span>') +
            '</td><td><code>' + kit.esc(one.issuer) + '</code></td>' +
            '<td><code>' + kit.esc(one.subject) + '</code></td><td>' +
            (gate.write
              ? form('federation-unlink', '<input type="hidden" name="link" ' +
                     'value="' + kit.esc(one.link) + '">',
                     t.text('consoleUsers.mfaSection.remove'), true)
              : '') + '</td></tr>';
        }).join('') + '</table>'
      : kit.note(t.html('consoleUsers.federationLinks.none'));
    if (!gate.write) {
      return heading + nav.head + rows + nav.foot +
        kit.note(t.html('consoleUsers.federationLinks.needsWrite'));
    }
    // The issuer's placeholder was drawn unescaped (its apostrophe as
    // itself), so it is drawn as markup: a translation holds no quote.
    const add = relationships.length
      ? '<h3>' + t.html('consoleUsers.federationLinks.linkHeading') +
        '</h3>' +
        form('federation-link',
          '<div class="formrow"><label>' +
          t.html('consoleUsers.federationLinks.thRelationship') +
          ' <select ' +
          'name="relationship">' + relationships.map(function (one) {
            return '<option value="' + kit.esc(one.fedId) + '">' +
              kit.esc(one.fedId) + ' — ' +
              kit.esc(one.fedPeer ||
                t.text('consoleUsers.federationLinks.noPartner')) +
              '</option>';
          }).join('') + '</select></label></div>' +
          '<div class="formrow"><label>' +
          t.html('consoleUsers.mfaSection.thSubject') + ' <input ' +
          'type="text" ' +
          'name="subject" size="42"' +
          kit.tip(t.text('consoleUsers.federationLinks.subjectTip')) +
          '></label>' +
          '</div><div class="formrow"><label>' +
          t.html('consoleUsers.mfaSection.issuer') + ' <input type="text" ' +
          'name="issuer" size="42" placeholder="' +
          t.html('consoleUsers.federationLinks.issuerHint') +
          '"></label></div>',
          t.text('consoleUsers.federationLinks.link'), false)
      : kit.note(t.html('consoleUsers.federationLinks.noRelationship'));
    return heading + nav.head + rows + nav.foot + add;
  }

  // ---------------------------------------------------------------------------
  // THE PERSON'S GNAP GRANTS (#432 phase 7, 2026-10-03): every grant they are
  // the resource owner of — approved at an interaction, or acted on through a
  // verified assertion — with the rights it holds, the tokens issued under
  // it, why it ended, and a Revoke for one with something live left. The
  // facts are `gnap/gnap_console.ts`'s `personGrantsView()` through
  // `admin_views.ts` (`gnapGrants` in /admin-api/users?user=), the same view
  // the person's own /portal/gnap draws; Revoke posts to /admin/gnap's
  // `revoke-grant` naming the person too, so a stale page cannot end a
  // stranger's grant (STS-GNAP-0792), and lands back on this tab.
  // ---------------------------------------------------------------------------
  /**
   * Draws a person's GNAP grants tab: each grant they are the resource owner
   * of, its rights, tokens and finalization, and a Revoke (#432 phase 7).
   *
   * @param t - the page's translator
   * @param key - the person
   * @param gnap - `{ rows, paging, cells }` from the view
   * @param gate - the console gate's state for this request
   * @param params - the page's query, for the paging links
   * @returns the tab's HTML
   */
  static userGnapGrantsSection(t, key, gnap, gate, params) {
    const view = gnap || { rows: [], paging: null, cells: null };
    const when = function (seconds) {
      return seconds ? kit.whenText(seconds * 1000) : '—';
    };
    const rightText = function (right) {
      if (typeof right === 'string') {
        return '<code>' + kit.esc(right) + '</code>';
      }
      const parts = [];
      ['actions', 'locations', 'datatypes', 'privileges'].forEach(
          function (dimension) {
        if (Array.isArray(right[dimension]) && right[dimension].length) {
          parts.push(dimension + ': ' + right[dimension].join(', '));
        }
      });
      if (right.identifier) {
        parts.push('identifier: ' + right.identifier);
      }
      if (right.limits !== undefined) {
        parts.push('limits: ' + JSON.stringify(right.limits));
      }
      return '<code>' + kit.esc(right.type || '') + '</code>' +
        (parts.length ? ' <span class="sub">' + kit.esc(parts.join('; ')) +
                        '</span>' : '');
    };
    const heading = '<h2 id="gnap-grants">' +
      t.html('consoleUsers.userGnapGrantsSection.heading') + '</h2>' +
      kit.note(t.html('consoleUsers.userGnapGrantsSection.lead')) +
      (view.cells && view.cells.multiCell
        ? kit.note(t.html('consoleUsers.userGnapGrantsSection.thisCell',
                          { cell: view.cells.cell }) + ' ' +
                    kit.esc(view.cells.note))
        : '');
    if (!view.rows.length) {
      return heading +
        kit.note(t.html('consoleUsers.userGnapGrantsSection.none'));
    }
    const nav = view.paging
      ? kit.pageNavPair('/admin/users', params,
                         Object.assign({}, view.paging,
                                       { param: 'gnapGrantsPage' }), t)
      : { head: '', foot: '' };
    const rows = '<table><tr><th>' +
      t.html('consoleUsers.userGnapGrantsSection.thGrant') + '</th><th>' +
      t.html('consoleUsers.userTokenTable.thClient') + '</th><th>' +
      t.html('consoleUsers.userTokenTable.thState') + '</th>' +
      '<th>' + t.html('consoleUsers.userGnapGrantsSection.thRights') +
      '</th><th>' + t.html('consoleUsers.body.thTokens') + '</th><th>' +
      t.html('consoleUsers.userGnapGrantsSection.thLifetime') +
      '</th><th></th></tr>' +
      view.rows.map(function (row) {
        const tokens = row.tokens.length
          ? row.tokens.map(function (token) {
              return kit.esc((token.label ? token.label + ' · ' : '') +
                              token.format + ' · ' + token.state) +
                ' <span class="sub">' +
                t.html('consoleUsers.userGnapGrantsSection.until',
                       { when: when(token.expiresAt) }) +
                '</span>';
            }).join('<br>')
          : '<span class="sub">' +
            t.html('consoleUsers.secondFactorCell.none') + '</span>';
        const control = row.revocable && gate.write
          ? '<form method="post" action="/admin/gnap">' +
            '<input type="hidden" name="action" value="revoke-grant">' +
            '<input type="hidden" name="grant" value="' + kit.esc(row.id) +
            '"><input type="hidden" name="user" value="' + kit.esc(key) +
            '"><button type="submit" class="danger">' +
            t.html('consoleUsers.userTokenTable.revoke') + '</button></form>'
          : '';
        return '<tr><td><code>' + kit.esc(row.id) + '</code></td>' +
          '<td><a href="/admin/applications?application=' +
          encodeURIComponent(row.client || '') + '">' +
          kit.esc(row.clientName || row.client || '') + '</a></td>' +
          '<td>' + kit.esc(row.state) +
          (row.finalization ? '<div class="sub">' +
            kit.esc(row.finalization.reason) + '</div>' : '') + '</td>' +
          '<td>' + (row.rights.map(rightText).join('<br>') || '—') +
          '<div class="sub">' + kit.esc(row.rightsAre) + '</div></td>' +
          '<td>' + tokens + '</td><td>' +
          kit.esc(when(row.grantExpiresAt)) + '</td><td>' + control +
          '</td></tr>';
      }).join('') + '</table>';
    return heading + nav.head + rows + nav.foot +
      (gate.write ? ''
        : kit.note(t.html('consoleUsers.userGnapGrantsSection.needsWrite')));
  }

  // ---------------------------------------------------------------------------
  // THE PERSON'S KERBEROS ACCOUNT (#59, 2026-09-22): the principal, what this
  // realm's KDC holds for them — the PUBLIC half, never a key — and "Reset
  // password and download keytab".
  //
  // **THE ONE CONTROL IS A PASSWORD RESET**, and the section says so before
  // the button does. A keytab is derived from a password in hand and this
  // service holds none of this person's, so the only password an
  // administrator can derive one from is a password they set now — typed, or
  // generated and never shown (`kerberos/krb5_person_keys.ts`,
  // `personKeytab()`). The form posts to `/admin/kerberos/principals`, the
  // page every other Kerberos key act goes through, and whose answer is the
  // shown-once keytab page.
  // ---------------------------------------------------------------------------
  /**
   * Draws a person's Kerberos account (principal and key facts, never a
   * key) and, for Admin Write on an enabled account, the form that resets
   * their password and downloads a keytab.
   *
   * @param t - the page's translator
   * @param key - the person's key
   * @param kerberos - the realm's KDC and this person's key state
   * @param gate - the gate state; `write` draws the form
   * @returns the section as HTML
   */
  static userKerberosSection(t, key, kerberos, gate) {
    const heading = '<h2 id="kerberos">Kerberos</h2>';
    if (!kerberos || !kerberos.kdc) {
      return heading +
        kit.note(t.html('consoleUsers.userKerberosSection.noKdc', {
          realm: (kerberos && kerberos.trustRealm) || '',
          reason: (kerberos && kerberos.reason) ||
            t.text('consoleUsers.userKerberosSection.krb5Off') }));
    }
    if (!kerberos.person) {
      return heading +
        kit.note(t.html('consoleUsers.userKerberosSection.noEntry'));
    }
    const keys = kerberos.keys;
    const etypeList = function (etypes) {
      return (etypes || []).map(function (one) {
        return '<code>' + kit.esc(one.name) + '</code>';
      }).join(' ');
    };
    const state = '<table class="key">' +
      '<tr><th>' + t.html('consoleUsers.userKerberosSection.principal') +
      '</th><td><code>' + kit.esc(kerberos.principal) +
      '</code></td></tr>' +
      '<tr><th>KDC</th><td>' + (kerberos.productKdc
        ? t.html('consoleUsers.userKerberosSection.productKdc')
        : t.html('consoleUsers.userKerberosSection.developmentKdc')) +
      '</td></tr>' +
      (kerberos.productKdc
        ? '<tr><th>' + t.html('consoleUsers.userKerberosSection.keys') +
          '</th><td>' + (keys
            ? 'kvno ' + kit.esc(String(keys.kvno)) + ' ' +
              etypeList(keys.etypes) + (keys.current ? ''
                : ' — <span class="state-invalid">' +
                  t.html('consoleUsers.userKerberosSection.notCurrent') +
                  '</span>' +
                  t.html('consoleUsers.userKerberosSection.refusedUntil')) +
              (keys.derivedAt ? '<br><span class="sub">' +
                t.html('consoleUsers.userKerberosSection.derived',
                       { at: keys.derivedAt }) +
                (keys.derivedOn
                  ? t.html('consoleUsers.userKerberosSection.derivedOn',
                           { on: keys.derivedOn })
                  : '') + '</span>' : '')
            : '<span class="state-none">' +
              t.html('consoleUsers.userKerberosSection.noneYet') +
              '</span>' +
              t.html('consoleUsers.userKerberosSection.getThem')) +
          '</td></tr>' +
          '<tr><th>' + t.html('consoleUsers.userKerberosSection.previous') +
          '</th><td>' + (keys &&
            keys.retained.length
            ? keys.retained.map(function (one) {
                return 'kvno ' + kit.esc(String(one.kvno)) +
                       t.html('consoleUsers.userKerberosSection.retainedUntil',
                              { at: one.expiresAt });
              }).join('<br>')
            : '<span class="state-none">' +
              t.html('consoleUsers.secondFactorCell.none') + '</span>') +
          '</td></tr>'
        : '') +
      (kerberos.disabled
        ? '<tr><th>' + t.html('consoleUsers.userKerberosSection.account') +
          '</th><td><strong class="state-expired">' +
          t.html('consoleUsers.userKerberosSection.disabled') +
          '</strong>' +
          t.html('consoleUsers.userKerberosSection.revoked') + '</td></tr>'
        : '') +
      '</table>';
    const why = kit.note(t.html('consoleUsers.userKerberosSection.why'));
    if (!gate.write) {
      return heading + state + why +
        kit.note(t.html('consoleUsers.userKerberosSection.needsWrite'));
    }
    if (kerberos.disabled) {
      return heading + state + why +
        kit.note(t.html('consoleUsers.userKerberosSection.enableFirst'));
    }
    const form = '<h3>' +
      t.html('consoleUsers.userKerberosSection.resetHeading') +
      '</h3>' +
      kit.warn(t.html('consoleUsers.userKerberosSection.resetWarn',
                      { key: key })) +
      '<form method="post" action="/admin/kerberos/principals">' +
      '<input type="hidden" name="action" value="reset-person-keytab">' +
      '<input type="hidden" name="username" value="' + kit.esc(key) + '">' +
      '<input type="hidden" name="from" value="user">' +
      '<div class="formrow"><label for="krb5-keytab-password"' +
      kit.tip(t.text('consoleUsers.userKerberosSection.passwordTip')) + '>' +
      t.html('consoleUsers.userKerberosSection.newPassword') +
      '</label><input type="password" id="krb5-keytab-password" ' +
      'name="password" autocomplete="new-password" size="30"' +
      kit.tip(t.text('consoleUsers.userKerberosSection.passwordAreaTip')) +
      '></div>' +
      '<div class="formrow"><label' +
      kit.tip(t.text('consoleUsers.userKerberosSection.randomTip')) +
      '><input type="checkbox" name="random" ' +
      'value="true"> ' + t.html('consoleUsers.userKerberosSection.random') +
      '</label></div>' +
      '<div class="formrow"><button class="danger" type="submit" title="' +
      kit.esc(t.text('consoleUsers.userKerberosSection.resetTitle')) + '">' +
      t.html('consoleUsers.userKerberosSection.resetHeading') +
      '</button></div></form>';
    return heading + state + why + form;
  }

  // ---------------------------------------------------------------------------
  // A PERSON'S ATTRIBUTES AS A TYPED FIELD GRID (rcbj, 2026-10-01), the
  // application page's model: one sub-tab per group of
  // `ldap/person_editor.ts`'s FIELD_GROUPS, each its own form with its own
  // Save, a single value a text box and a list one box per value with + and
  // the bin, an example of a valid value as every box's placeholder and the
  // attribute's sentence as its tooltip.
  //
  // **It posts to `/admin/users/edit`**, for `/admin/applications/edit`'s
  // reason: a refused save comes back to THIS page with every box as the
  // reader left it, and "+" and the bin redraw it with one box more or fewer
  // and write nothing. Save is `update-fields`, the action
  // `POST /admin-api/users/update-fields` calls, so every rule a one-attribute
  // edit holds still holds. `present` names every field the tab drew, so a
  // box emptied on the page clears it.
  //
  // **The address is not a field**: `set-mail` marks what it writes verified
  // and tells the former address, so its form heads the Contact tab.
  // ---------------------------------------------------------------------------
  /**
   * Draws a person's attributes as a typed field grid, one sub-tab per group
   * with its own Save, and the address form on the Contact tab.
   *
   * @param t - the page's translator
   * @param key - the person's key
   * @param editor - `personEditor.editorFor()`'s answer, or null
   * @param gate - the gate state; `write` draws the forms
   * @param back - the list to return to after an action
   * @param state - a redraw: `draft` (the posted form) and `error`; null
   *   for none
   * @param groups - `personEditor.FIELD_GROUPS`, the sub-tabs in order
   * @returns the section as HTML
   */
  static personFieldsSection(t, key, editor, gate, back, state, groups) {
    const heading = '<h2 id="person-fields">' +
      t.html('consoleUsers.personFieldsSection.heading') + '</h2>';
    if (!editor) {
      return heading +
        kit.note(t.html('consoleUsers.personFieldsSection.noEntry'));
    }
    const draft = state && state.draft ? state.draft : null;
    const values = {};
    editor.attributes.forEach(function (row) {
      values[row.name] = row.values.map(String);
    });
    if (draft) {
      const posted = kit.gridValuesFromDraft(draft);
      String(draft.present || '').split(/[\s,]+/).forEach(function (name) {
        if (name && Object.prototype.hasOwnProperty.call(values, name)) {
          values[name] = posted[name] || [];
        }
      });
    }
    const naming = editor.attributes.filter(function (row) {
      return !row.editable;
    });
    const gridRow = function (row) {
      return {
        attribute: row.name,
        type: row.multi ? 'array' : 'string',
        what: row.label + ' — ' + row.schema + '.' +
              (row.note
                ? t.text('consoleUsers.personFieldsSection.takes',
                         { note: row.note })
                : '') +
              (row.must ? t.text('consoleUsers.personFieldsSection.must')
                        : '') +
              (row.multi ? ''
                         : t.text('consoleUsers.personFieldsSection.single')),
        example: row.example,
        forText: row.label +
          (row.must ? t.text('consoleUsers.personFieldsSection.required')
                    : ''),
        families: [], everyFamily: true,
        // Shown by the sub-tab's simple view (#500); a field every person
        // must hold is always shown.
        simple: !!row.simple || !!row.must
      };
    };
    const mailForm = gate.write
      ? '<h3 id="mail">' +
        t.html('consoleUsers.personFieldsSection.mailHeading') + '</h3>' +
        '<form method="post" action="/admin/users">' +
        '<input type="hidden" name="action" value="set-mail">' +
        '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
        '<input type="hidden" name="from" value="user">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        '<div class="formrow"><label for="personmail"' +
        kit.tip(t.text('consoleUsers.personFieldsSection.mailTip')) +
        '>' + t.html('consoleUsers.personFieldsSection.setAddressTo') +
        '</label><input type="email" id="personmail" ' +
        'name="mail" size="34" required value="' +
        kit.esc(String(editor.mail || '')) + '" placeholder="' +
        kit.esc(t.text('consoleUsers.personFieldsSection.mailHint')) + '"' +
        kit.tip(t.text('consoleUsers.personFieldsSection.mailAreaTip')) +
        '><button type="submit"' +
        kit.tip(t.text('consoleUsers.personFieldsSection.setMailTip')) +
        '>' + t.html('consoleUsers.emailFactorBlock.setAddress') +
        '</button>' +
        '<span class="sub">' +
        t.html('consoleUsers.personFieldsSection.verifiedNote') +
        '</span></div></form>'
      : '<h3 id="mail">' +
        t.html('consoleUsers.personFieldsSection.mailHeading') + '</h3>' +
        (editor.mail
          ? '<p><code>' + kit.esc(editor.mail) + '</code></p>'
          : kit.note(t.html('consoleUsers.mfaSection.none')));
    const panels = groups.map(function (group) {
      const mine = editor.attributes.filter(function (row) {
        return row.editable && row.group === group.id;
      });
      const contact = group.id === 'contact' ? mailForm : '';
      if (!mine.length) {
        return { id: 'ufg-' + group.id, label: group.label, html: contact };
      }
      if (!gate.write) {
        return { id: 'ufg-' + group.id, label: group.label,
          html: contact + '<table><tr><th>' +
            t.html('consoleGroups.attributeTable.thName') + '</th><th>' +
            t.html('consoleUsers.personFieldsSection.thWhat') + '</th>' +
            '<th>' + t.html('consoleGroups.attributeTable.thValues') +
            '</th></tr>' + mine.map(function (row) {
              return '<tr><td><code>' + kit.esc(row.name) + '</code></td>' +
                '<td>' + kit.esc(row.label) + '</td><td>' +
                (row.values.length
                  ? row.values.map(function (one) {
                    return '<code>' + kit.esc(one) + '</code>';
                  }).join('<br>')
                  : '<span class="state-none">' +
                    t.html('consoleUsers.secondFactorCell.none') +
                    '</span>') + '</td></tr>';
            }).join('') + '</table>' };
      }
      // THE SUB-TAB'S TWO VIEWS (#500), the application page's: the
      // simplified one unless this is a redraw of this sub-tab's own form
      // posted from the advanced one.
      const rows = mine.map(gridRow);
      const views = kit.hasViews(rows);
      const advancedRows = rows.filter(function (row) {
        return !row.simple;
      });
      const viewSwitch = !views ? ''
        : kit.viewSwitch(group.label,
            !!draft && String(draft.group || '') === group.id &&
              String(draft.view || '') === 'advanced',
            advancedRows.length,
            advancedRows.filter(function (row) {
              return (values[row.attribute] || []).some(function (v) {
                return String(v).trim() !== '';
              });
            }).length, t);
      const cells = rows.map(function (row) {
        return kit.fieldGridCell(row, values,
                                  { redraw: '/admin/users/edit',
                                    views: views }, t);
      }).join('');
      return { id: 'ufg-' + group.id, label: group.label,
        html: contact + kit.note(kit.esc(group.what)) +
          '<form method="post" action="/admin/users/edit#ufg-' +
          kit.esc(group.id) + '" class="appgrid">' +
          '<input type="hidden" name="action" value="update-fields">' +
          '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
          '<input type="hidden" name="from" value="user">' +
          '<input type="hidden" name="group" value="' + kit.esc(group.id) +
          '">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<input type="hidden" name="present" value="' +
          kit.esc(mine.map(function (row) { return row.name; }).join(' ')) +
          '">' +
          // THE DEFAULT BUTTON, first in the form: Enter in a box presses
          // the first submit button, which would otherwise be a "+" or a bin.
          '<button type="submit" class="default-submit" tabindex="-1" ' +
          'aria-hidden="true">' + t.html('consoleUsers.mfaSection.save') +
          '</button>' + viewSwitch +
          '<div class="fg">' + cells + '</div>' +
          '<div class="formrow"><button type="submit"' +
          kit.tip(t.text('consoleUsers.personFieldsSection.saveTip')) + '>' +
          t.html('consoleUsers.personFieldsSection.saveGroup',
                 { group: group.label.toLowerCase() }) +
          '</button></div></form>' };
    });
    return heading +
      (state && state.error && state.error.length
        ? kit.flash('<div class="err"><strong>Not everything was saved.' +
            '</strong><ul>' + state.error.map(function (one) {
              return '<li>' + kit.esc(one) + '</li>';
            }).join('') + '</ul></div>')
        : '') +
      kit.note(t.html('consoleUsers.personFieldsSection.lead',
                      { dn: editor.dn })) +
      // The attributes not on the tabs are markup (each in its <code>), so
      // the sentence is messages around them.
      (naming.length
        ? kit.note(t.html('consoleUsers.personFieldsSection.notOnTabs') +
            ' ' + naming.map(function (row) {
              return t.html('consoleUsers.personFieldsSection.namesEntry',
                            { name: row.name });
            }).join('; ') +
            t.html('consoleUsers.personFieldsSection.namingRest'))
        : kit.note(t.html('consoleUsers.personFieldsSection.notOnTabs') +
            ' ' + t.html('consoleUsers.personFieldsSection.notOnTabsList') +
            '<a href="/admin/groups">' +
            t.html('consoleGroups.body.tileGroups') + '</a>).')) +
      (gate.write ? ''
        : kit.note(t.html('consoleUsers.personFieldsSection.needsWrite'))) +
      kit.subTabbedPanels(t.text('consoleUsers.personFieldsSection.heading'),
                          panels);
  }

  // -------------------------------------------------------------------------
  // CHANGE ONE ATTRIBUTE BY NAME (#228, 2026-09-26): the application page's
  // three forms, for a person. What may be changed, and every refusal, are
  // `ldap/person_editor.ts`'s; this draws its answer. The Set select offers
  // every attribute this entry lets be edited, Add to only the multi-valued
  // ones, and Remove from only those that hold a value — so a form cannot
  // offer what the action would refuse for the plainest reason. Since the
  // page became tabs (2026-10-01) the Attributes tab is the usual door and
  // these are on the Directory entry tab, folded, as the application page's
  // are; the address form moved to the Attributes tab's Contact group.
  // -------------------------------------------------------------------------
  /**
   * Draws the forms that set, add to and remove from one of a person's
   * editable attributes by name, from ldap/person_editor.ts's answer.
   *
   * @param t - the page's translator
   * @param key - the person's key
   * @param editor - the person editor's answer, or null with no entry
   * @param gate - the gate state; `write` draws the forms
   * @param back - the list to return to after an action
   * @returns the section as HTML
   */
  static userAttributesSection(t, key, editor, gate, back) {
    const ENTRY_TIPS = entryTips(t);
    const heading = '<h2 id="attributes">' +
      t.html('consoleUsers.userAttributesSection.heading') + '</h2>';
    if (!editor) {
      return heading +
        kit.note(t.html('consoleUsers.userAttributesSection.noEntry'));
    }
    const usable = editor.attributes.filter(function (row) {
      return row.editable;
    });
    const option = function (row) {
      return '<option value="' + kit.esc(row.name) + '">' +
        kit.esc(row.name + ' — ' + row.label +
                 (row.values.length ? ' (' + row.values.length + ')' : '')) +
        '</option>';
    };
    // The label and the button were one string split at its first word
    // until #539; a translation has no such first word, so they are two.
    const form = function (action, label, button, rows, required,
                           placeholder) {
      const id = action.slice(0, action.indexOf('-'));
      return '<form method="post" action="/admin/users">' +
        '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
        '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
        '<input type="hidden" name="from" value="user">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        '<div class="formrow"><label for="' + id + 'personattr"' +
        kit.tip(ENTRY_TIPS[id].attribute) + '>' + label +
        '</label><select id="' + id + 'personattr" name="attribute"' +
        kit.tip(ENTRY_TIPS[id].attribute) + '>' +
        rows.map(option).join('') + '</select><label for="' + id +
        'personval"' + kit.tip(ENTRY_TIPS[id].value) + '>' +
        (id === 'set' ? t.html('consoleUsers.userAttributesSection.to')
                      : t.html('consoleUsers.userAttributesSection.theValue')) +
        '</label>' +
        '<input type="text" id="' + id + 'personval" name="value" size="34"' +
        (required ? ' required' : '') + kit.tip(ENTRY_TIPS[id].value) +
        ' placeholder="' + kit.esc(placeholder) + '"><button type="submit"' +
        kit.tip(ENTRY_TIPS[id].button) + '>' +
        button + '</button></div></form>';
    };
    const listing = '<details><summary>' +
      t.html('consoleUsers.userAttributesSection.listingSummary') +
      '</summary>' +
      '<table><tr><th>' + t.html('consoleGroups.attributeTable.thName') +
      '</th><th>' + t.html('consoleGroups.attributeTable.thValues') +
      '</th><th>' + t.html('consoleUsers.userAttributesSection.thSchema') +
      '</th>' +
      '<th>' + t.html('consoleUsers.userAttributesSection.thTakes') +
      '</th></tr>' +
      editor.attributes.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.name) + '</code> ' +
          kit.esc(row.label) + '</td><td>' +
          (row.multi ? t.html('consoleUsers.userAttributesSection.several')
                     : t.html('consoleUsers.userAttributesSection.one')) +
          (row.must ? t.html('consoleUsers.userAttributesSection.required')
                    : '') +
          '</td><td>' + kit.esc(row.schema) +
          '</td><td>' + (row.editable
            ? kit.esc(row.note ||
                      t.text('consoleUsers.userAttributesSection.text'))
            : '<span class="state-none">' + kit.esc(row.why) + '</span>') +
          '</td></tr>';
      }).join('') + '</table>' +
      '<table><tr><th>' +
      t.html('consoleUsers.userAttributesSection.notOffered') + '</th><th>' +
      t.html('consoleUsers.userAttributesSection.why') + '</th></tr>' +
      editor.withheld.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.name) + '</code> ' +
          kit.esc(row.label) + '</td><td>' + kit.esc(row.why) + '</td></tr>';
      }).join('') + '</table></details>';
    const explain = kit.note(
      t.html('consoleUsers.userAttributesSection.explain',
                                    { dn: editor.dn })) +
      kit.note(t.html('consoleUsers.userAttributesSection.willNotBefore') +
      '<a href="/admin/groups">' + t.html('consoleGroups.body.tileGroups') +
      '</a>' + t.html('consoleUsers.userAttributesSection.willNotAfter'));
    if (!gate.write) {
      return heading + explain +
        kit.note(t.html('consoleUsers.personFieldsSection.needsWrite')) +
        listing;
    }
    const multi = usable.filter(function (row) {
      return row.multi;
    });
    const held = usable.filter(function (row) {
      return row.values.length > 0;
    });
    return heading + explain +
      form('set-attribute', t.html('consoleUsers.userAttributesSection.set'),
           t.html('consoleUsers.userAttributesSection.setButton'), usable,
           false, t.text('consoleUsers.userAttributesSection.emptyClears')) +
      (multi.length
        ? form('add-attribute',
               t.html('consoleUsers.userAttributesSection.addTo'),
               t.html('consoleUsers.userAttributesSection.addButton'), multi,
               true, '')
        : '') +
      (held.length
        ? form('remove-attribute',
               t.html('consoleUsers.userAttributesSection.removeFrom'),
               t.html('consoleUsers.userAttributesSection.removeButton'),
               held, true, '')
        : '') +
      listing;
  }

  /**
   * Draws the controls over a person's password, passkeys, second factors,
   * account and delegation: reset, reset link, disable or require MFA,
   * disable or enable, and who may act for them.
   *
   * Every control is drawn for Admin Write only and posts to /admin/users.
   *
   * @param t - the page's translator
   * @param key - the person's key
   * @param factors - the person's credential facts, or null with no store
   * @param gate - the gate state; `write` draws the forms
   * @param back - the list to return to after an action
   * @param delegation - who may act for them
   *   (`credentials.delegationFactsFor()`), or {}
   * @returns the section as HTML
   */
  static userCredentialControlsSection(t, key, factors, gate, back,
                                       delegation) {
    const heading = '<h2 id="credential-controls">' +
      t.html('consoleUsers.controls.heading') + '</h2>';
    if (!factors) {
      return heading +
        kit.note(t.html('consoleUsers.controls.noStore'));
    }
    const requirement = factors.mfaRequirement ||
      { required: false, byUser: false, byRealm: false };
    const link = factors.passwordResetLink;
    const holdsSecond = factors.totp || factors.mfaKeys > 0 ||
      !!(factors.backupCodes && factors.backupCodes.present);
    const state = '<table class="key"><tr><th>' +
      t.html('consoleUsers.mfaSection.thWhat') + '</th><th>' +
      t.html('consoleUsers.controls.thNow') +
      '</th></tr>' +
      '<tr><th>' + t.html('consoleUsers.userKerberosSection.account') +
      '</th><td>' + (factors.disabled
        ? '<strong class="state-expired">' +
          t.html('consoleUsers.userKerberosSection.disabled') + '</strong>' +
          t.html('consoleUsers.controls.everyDoor')
        : '<span class="state-valid">' +
          t.html('consoleUsers.controls.enabled') +
          '</span>') + '</td></tr>' +
      '<tr><th>' + t.html('consoleUsers.mfaSection.password') + '</th><td>' +
      (factors.password
        ? '<span class="state-valid">' + t.html('consoleUsers.mfaSection.set') +
          '</span>'
        : '<span class="state-none">' +
          t.html('consoleUsers.secondFactorCell.none') + '</span>') +
      (factors.passwordChangeRequired
        ? t.html('consoleUsers.controls.mustChange')
        : '') +
      '</td></tr><tr><th>' +
      t.html('consoleUsers.controls.resetLink') +
      '</th><td>' + (link
        ? (link.expired
            ? '<span class="state-expired">' +
              t.html('consoleUsers.controls.expired') +
              '</span>'
            : '<span class="state-valid">' +
              t.html('consoleUsers.controls.outstanding') +
              '</span>' +
              t.html('consoleUsers.controls.until',
                     { at: new Date(link.expires).toISOString() }))
        : '<span class="state-none">' +
          t.html('consoleUsers.secondFactorCell.none') + '</span>') +
      '</td></tr>' +
      '<tr><th>' +
      t.html('consoleUsers.controls.passwordless') +
      '</th><td>' + (factors.primaryKeys > 0
        ? '<span class="state-valid">' + kit.esc(String(factors.primaryKeys)) +
          '</span>' +
          t.html('consoleUsers.controls.primaryKeys')
        : '<span class="state-none">' +
          t.html('consoleUsers.secondFactorCell.none') + '</span>') +
      '</td></tr>' +
      '<tr><th>' +
      t.html('consoleUsers.controls.required') +
      '</th><td>' + (requirement.required
        ? '<strong>' + t.html('consoleUsers.mfaSection.yes') +
          '</strong> — ' + [requirement.byUser
            ? t.html('consoleUsers.controls.onAccount')
            : '', requirement.byRealm
            ? t.html('consoleUsers.controls.byRealm') +
              '<a href="/admin/policies#authn">' +
              t.html('consoleUsers.emailFactorBlock.authnPolicy') + '</a>)'
            : ''].filter(Boolean)
              .join(' ' +
                    t.html('consoleUsers.controls.and') +
                    ' ') +
          (factors.mfaRequired
            ? t.html('consoleUsers.controls.holdOne')
            : t.html('consoleUsers.controls.holdNone'))
        : '<span class="state-none">' + t.html('consoleUsers.mfaSection.no') +
          '</span>') + '</td></tr></table>';
    const signalsNote =
      kit.note(t.html('consoleUsers.controls.signals'));
    if (!gate.write) {
      return heading + state + signalsNote +
        kit.note(
          t.html('consoleUsers.controls.needsWrite'));
    }
    // `extra` is markup for the form's own fields (#146): the reset forms'
    // "compromised" box and the disable form's RISC reason — the console half
    // of what `/admin-api/users` takes, per rule 7.
    const form = function (action, label, title, danger, extra?) {
      return '<form method="post" action="/admin/users">' +
        '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
        '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
        '<input type="hidden" name="from" value="user">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        (extra || '') +
        '<div class="formrow"><button' + (danger ? ' class="danger"' : '') +
        ' title="' + kit.esc(title) + '">' + label + '</button></div></form>';
    };
    const compromisedBox = '<div class="formrow"><label' +
      kit.tip(t.text(
        'consoleUsers.controls.compromisedTip')) +
      '><input ' +
      'type="checkbox" name="compromised" value="true"> ' +
      t.html('consoleUsers.controls.compromised') +
      '</label></div>';
    const reset = '<h3>' +
      t.html('consoleUsers.controls.resetHeading') +
      '</h3>' +
      kit.note(t.html('consoleUsers.controls.resetNote')) +
      kit.note(
        t.html('consoleUsers.controls.compromisedNote')) +
      form('reset-password',
           t.html('consoleUsers.controls.resetPassword'),
           t.text('consoleUsers.controls.resetTitle'),
           true, compromisedBox) +
      form('issue-password-reset',
           t.html('consoleUsers.controls.issueLink'),
           t.text('consoleUsers.controls.issueLinkTitle'),
           true, compromisedBox +
           kit.mailLinkBox(
             t.text('consoleUsers.controls.theLink'),
             undefined, t));
    const passkeys = '<h3>' +
      t.html('consoleUsers.controls.passwordlessHeading') +
      '</h3>' + (factors.primaryKeys > 0
      ? (factors.password
          ? kit.note(t.html(
              'consoleUsers.controls.disableKeysNote',
              { count: String(factors.primaryKeys) })) +
            form('disable-primary-keys',
                 t.html('consoleUsers.controls.disableKeys'),
                 t.text(
                   'consoleUsers.controls.disableKeysTitle'),
                 true)
          : kit.warn(t.html(
              'consoleUsers.controls.noPassword')))
      : kit.note(t.html('consoleUsers.controls.noKeys')));
    const mfa = '<h3>' + t.html('consoleUsers.detail.tabFactors') + '</h3>' +
      (holdsSecond
      ? kit.note(t.html('consoleUsers.controls.disableMfaNote',
                        { required: requirement.required ? 'yes' : 'no' })) +
        form('disable-mfa',
             t.html('consoleUsers.controls.disableMfa'),
             t.text('consoleUsers.controls.disableMfaTitle'),
             true)
      : kit.note(t.html('consoleUsers.controls.noSecond'))) +
      (requirement.byUser
        ? kit.note(t.html('consoleUsers.controls.requiredOfThem')) +
          form('stop-requiring-mfa',
               t.html('consoleUsers.controls.stopRequiring'),
               t.text(
                 'consoleUsers.controls.stopRequiringTitle'),
               false)
        : kit.note(t.html('consoleUsers.controls.requireNote') +
                    (requirement.byRealm
                      ? t.html(
                          'consoleUsers.controls.realmRequires') +
                        '<a href="/admin/policies#authn">' +
                        t.html('consoleUsers.emailFactorBlock.authnPolicy') +
                        '</a>).'
                      : '')) +
          form('require-mfa',
               t.html('consoleUsers.controls.requireMfa'),
               t.text(
                 'consoleUsers.controls.requireMfaTitle'),
               false));
    // THE ACCOUNT ITSELF (2026-09-17, #36 follow-up): disable, which ends
    // everything the person holds, and enable. `common/account_state.ts`.
    const account = '<h3>' +
      t.html('consoleUsers.controls.accountHeading') +
      '</h3>' + (factors.disabled
      ? kit.note(t.html('consoleUsers.controls.enableNote')) +
        form('enable',
             t.html('consoleUsers.controls.enable'),
             t.text('consoleUsers.controls.enableTitle'),
             false)
      : kit.note(t.html('consoleUsers.controls.disableNote')) +
        form('disable',
             t.html('consoleUsers.controls.disable'),
             t.text('consoleUsers.controls.disableTitle'),
             true,
             '<div class="formrow"><label' +
             kit.tip(t.text(
               'consoleUsers.controls.reasonTip')) +
             '>' + t.html('consoleUsers.controls.reason') +
             ' <select name="riscReason"><option value="">' +
             t.html('consoleUsers.controls.noneGiven') +
             '</option><option value="hijacking">' +
             t.html('consoleUsers.controls.hijacking') +
             '</option><option value="bulk-account">' +
             t.html('consoleUsers.controls.bulk') +
             '</option>' +
             '</select></label></div>'));
    // WHO MAY ACT FOR THEM (#108, 2026-09-23): the person's half of the
    // WS-Trust and token-exchange delegation policy. POST
    // /admin-api/users/set-not-delegated and /set-may-act are the same acts.
    const facts = delegation || {};
    const delegationBlock = '<h3 id="delegation">' +
      t.html('consoleUsers.controls.delegationHeading') +
      '</h3>' +
      kit.note(t.html('consoleUsers.controls.delegationBefore') +
        '<a href="/admin/delegation#delegation-policy">' +
        t.html('consoleUsers.controls.thePolicy') + '</a>' +
        t.html('consoleUsers.controls.delegationAfter', {
          set: facts.notDelegated ? 'yes' : 'no',
          has: facts.mayAct ? 'yes' : 'no',
          mayAct: facts.mayAct || '' })) +
      form('set-not-delegated', facts.notDelegated
        ? t.html('consoleUsers.controls.allow')
        : t.html('consoleUsers.controls.never'),
           t.text('consoleUsers.controls.notDelegatedTitle'),
           !facts.notDelegated,
           '<input type="hidden" name="value" value="' +
           (facts.notDelegated ? 'false' : 'true') + '">') +
      form('set-may-act',
           t.html('consoleUsers.controls.setMayAct'),
           t.text('consoleUsers.controls.setMayActTitle'),
           false,
           '<div class="formrow"><label' +
           kit.tip(t.text(
             'consoleUsers.controls.delegateTip')) +
           '>' + t.html('consoleUsers.controls.delegateDn') +
           ' <input type="text" ' +
           'name="delegate" size="60" value="' +
           kit.esc(facts.mayAct || '') + '" placeholder="' +
           kit.esc(t.text(
             'consoleUsers.controls.delegateHint')) +
           '"></label></div>') +
      // AND AS WHAT (#186): the semantics this person allows, and their
      // default — facts the exchange policy reads for WS-Trust, the token
      // exchange and Kerberos alike. POST
      // /admin-api/users/set-delegation-semantics is the same act.
      form('set-delegation-semantics',
           t.html('consoleUsers.controls.setSemantics'),
           t.text(
             'consoleUsers.controls.setSemanticsTitle'),
           false,
           '<div class="formrow">' +
           [['delegation', t.text(
              'consoleUsers.controls.delegationTip')],
            ['impersonation', t.text(
              'consoleUsers.controls.impersonationTip')]]
             .map(function (pair) {
             const one = pair[0];
             return '<label' + kit.tip(pair[1]) + '><input ' +
               'type="checkbox" name="semantics" value="' +
               one + '"' + ((facts.semantics || []).indexOf(one) >= 0
                 ? ' checked' : '') + '> ' + one + '</label> ';
           }).join('') + '</div><div class="formrow"><label' +
           kit.tip(t.text(
             'consoleUsers.controls.defaultTip')) +
           '>' + t.html('consoleUsers.controls.default') +
           ' ' +
           '<select name="default">' +
           ['', 'delegation', 'impersonation'].map(function (one) {
             return '<option value="' + one + '"' +
               (String(facts.defaultSemantics || '') === one
                 ? ' selected' : '') + '>' +
               (one || t.html(
                 'consoleUsers.controls.noDefault')) +
               '</option>';
           }).join('') + '</select></label></div>');
    return heading + state + signalsNote + account + reset + passkeys + mfa +
      delegationBlock;
  }

  /**
   * Draws a person's Service account tab (#221): whether they are one, its
   * owner, push destination and rotation, what the realm's policy lets it
   * do, and — for Admin Write — the forms that set, change or clear it and
   * rotate its password now.
   *
   * @param t - the page's translator
   * @param key - the person's key
   * @param account - `json.serviceAccount`, or null for an ordinary person
   * @param gate - the gate state; `write` draws the forms
   * @param back - the list to return to after an action
   * @returns the section as HTML
   */
  static serviceAccountSection(t, key, account, gate, back) {
    const heading = '<h2 id="service-account">' +
      t.html('consoleUsers.detail.tabService') + '</h2>';
    const lead = kit.note(
      t.html('consoleUsers.serviceAccountSection.leadBefore') +
      '<a href="/admin/policies#serviceAccount">' +
      t.html('consoleUsers.newUserBody.saPolicy') + '</a>' +
      t.html('consoleUsers.serviceAccountSection.leadAfter'));
    const state = account
      ? '<table class="key"><tr><th>' +
        t.html('consoleUsers.mfaSection.thWhat') + '</th><th>' +
        t.html('consoleUsers.controls.thNow') +
        '</th></tr>' +
        '<tr><th>' + t.html('consoleUsers.serviceAccountSection.owner') +
        '</th><td>' + (account.owner
          ? '<code>' + kit.esc(account.owner) + '</code> (' +
            kit.esc(account.ownerKind ||
                    t.text('consoleUsers.credentialCell.unknown')) + ')'
          : '<span class="state-none">' +
            t.html('consoleUsers.secondFactorCell.none') + '</span>') +
        '</td></tr>' +
        '<tr><th>' + t.html('consoleServiceAccounts.thDestination') +
        '</th><td>' + (account.destination
          ? t.html('consoleUsers.serviceAccountSection.destination', {
              destination: account.destination,
              secret: account.secretName || '' })
          : '<span class="state-none">' +
            t.html('consoleUsers.serviceAccountSection.neverRotated') +
            '</span>') + '</td></tr>' +
        '<tr><th>' + t.html('consoleServiceAccounts.thRotated') +
        '</th><td>' +
          kit.esc(account.rotatedAt || t.text('consoleUsers.body.never')) +
          (account.previousPasswordUntil
            ? t.html('consoleUsers.serviceAccountSection.previousUntil',
                     { at: account.previousPasswordUntil }) : '') +
          '</td></tr>' +
        '<tr><th>' + t.html('consoleUsers.serviceAccountSection.rotation') +
        '</th><td>' + (account.rotation.rotates
          ? t.html('consoleUsers.serviceAccountSection.on') +
            (account.rotation.nextDueAt
              ? t.html('consoleUsers.serviceAccountSection.nextDue',
                       { at: account.rotation.nextDueAt }) : '')
          : '<span class="state-none">' +
            t.html('consoleUsers.serviceAccountSection.off', {
              where: account.rotation.enabled ? 'account' : 'realm' }) +
            '</span>') +
          (account.rotation.failures
            ? ' — <strong' + (account.rotation.alarm
                ? ' class="state-expired"' : '') + '>' +
              t.html('consoleUsers.serviceAccountSection.failures',
                     { count: String(account.rotation.failures) }) +
              '</strong>' +
              t.html('consoleUsers.serviceAccountSection.lastError',
                     { error: account.rotation.lastError || '' })
            : '') + '</td></tr>' +
        '<tr><th>' + t.html('consoleUsers.serviceAccountSection.policyLets') +
        '</th><td>' +
          (account.policy.exemptFromSecondFactor
            ? t.html('consoleUsers.serviceAccountSection.skipSecond')
            : t.html('consoleUsers.serviceAccountSection.meetSecond')) +
          (account.policy.allowBrowserSignIn
            ? t.html('consoleUsers.serviceAccountSection.browser')
            : t.html('consoleUsers.serviceAccountSection.noBrowser')) +
          t.html('consoleUsers.serviceAccountSection.use', {
            doors: account.policy.doors.join(', ') ||
              t.text('consoleUsers.serviceAccountSection.noDoor') }) +
        '</td></tr></table>'
      : kit.note(t.html('consoleUsers.serviceAccountSection.ordinary',
                        { key: key }));
    if (!gate.write) {
      return heading + lead + state +
        kit.note(t.html('consoleUsers.serviceAccountSection.needsWrite'));
    }
    const field = function (name, label, value, placeholder, tip) {
      return '<div class="formrow"><label' + kit.tip(tip) + '>' + label +
        ' <input type="text" ' +
        'name="' + name + '" size="60" value="' + kit.esc(value || '') +
        '" placeholder="' + kit.esc(placeholder) + '"></label></div>';
    };
    const form = function (action, label, title, extra, danger?) {
      return '<form method="post" action="/admin/users">' +
        '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
        '<input type="hidden" name="user" value="' + kit.esc(key) + '">' +
        '<input type="hidden" name="from" value="user">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        extra +
        '<div class="formrow"><button' + (danger ? ' class="danger"' : '') +
        ' title="' + kit.esc(title) + '">' + label + '</button></div></form>';
    };
    const fields = field('owner', t.html('consoleUsers.newUserBody.owner'),
                         account && account.owner,
                         t.text('consoleUsers.newUserBody.ownerHint'),
                         t.text(
                           'consoleUsers.serviceAccountSection.ownerTip')) +
      field('destination', t.html('consoleUsers.newUserBody.destination'),
            account && account.destination,
            'cn=vault-prod,ou=applications,...',
            t.text('consoleUsers.serviceAccountSection.destinationTip')) +
      field('secretName',
            t.html('consoleUsers.serviceAccountSection.secretName'),
            account && account.secretName, 'iya/svc-backup',
            t.text('consoleUsers.serviceAccountSection.secretTip'));
    const set = form('set-service-account', account
      ? t.html('consoleUsers.serviceAccountSection.save')
      : t.html('consoleUsers.serviceAccountSection.make'),
      t.text('consoleUsers.serviceAccountSection.saveTitle'),
      '<input type="hidden" name="serviceAccount" value="true">' + fields) +
      (account ? ''
        : kit.note(t.html('consoleUsers.serviceAccountSection.endsSessions')));
    const rotate = account && account.destination
      ? '<h3>' + t.html('consoleUsers.serviceAccountSection.rotateHeading') +
        '</h3>' +
        kit.note(t.html('consoleUsers.serviceAccountSection.rotateNote')) +
        form('rotate-password',
             t.html('consoleUsers.serviceAccountSection.rotateNow'),
             t.text('consoleUsers.serviceAccountSection.rotateTitle'), '')
      : '';
    const clear = account
      ? form('set-service-account',
             t.html('consoleUsers.serviceAccountSection.ordinaryButton'),
             t.text('consoleUsers.serviceAccountSection.ordinaryTitle'),
             '<input type="hidden" name="serviceAccount" value="false">', true)
      : '';
    return heading + lead + state + set + rotate + clear;
  }

  // Not a 404: this service has simply never seen the name, or has forgotten
  // it to the cap since the link was drawn. Both are answers rather than
  // errors, and a 404 here would send a test looking for a routing problem.
  /**
   * Draws `/admin/users?user=` for a name nothing here knows.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer: `user`, `known: false` and `registryKeeps`
   * @returns the body as HTML
   */
  static unknown(ctx, json) {
    const t = kitEscaping(ctx.t);
    return kit.note(t.html('consoleUsers.unknown.note', {
      user: json.user, keeps: json.registryKeeps })) +
      // The same href the trail's section crumb carries, so the two ways
      // back off this page cannot land in different places.
      kit.note('<a href="' +
      kit.esc('/admin/users' +
              kit.queryWith(kit.listViewOf('/admin/users', ctx.query), {})) +
      '">' + t.html('consoleUsers.unknown.back') + '</a>.');
  }
}

export = UsersPage;
