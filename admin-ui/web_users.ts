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

type Json = any;

/**
 * Draws `/admin/users` from the answer of `GET /admin-api/users`: everybody
 * this realm knows about, from the directory and from what it has seen,
 * filtered by name, protocol and second factor, and paged.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class UsersPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const wantedText = json.filter.q || '';
    const wantedProtocol = json.filter.protocol || '';
    const wantedFactor = json.filter.factor || '';
    const paging = json.paging;
    const shown = json.users;
    const factorCounts = json.factors;
    const filterParams = { q: wantedText, protocol: wantedProtocol,
                           factor: wantedFactor,
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/users', filterParams, paging);

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
      return '<tr><td><a href="' + kit.esc(href) + '">' +
             kit.shortened(row.name, 40) +
        '</a></td><td>' +
        UsersPage.sourceCell(row, json.registryKeeps) + '</td><td ' +
        'class="' + (row.authenticated ? 'state-valid' : 'state-none') + '">' +
          (row.authenticated ? row.authentications + '&times;' :
           'never') + '</td><td>' + UsersPage.credentialCell(row.factors) +
           '</td><td>' +
        UsersPage.secondFactorCell(row.factors) + '</td><td>' +
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
        '<td><a href="' + kit.esc(href) + '">sessions and tokens ' +
                                      '&rsaquo;</a></td></tr>';
    }).join('');

    const protocolOptions = [''].concat(json.protocols)
                                .map(function (p) {
      return '<option value="' + kit.esc(p) + '"' +
             (p === wantedProtocol ? ' ' +
          'selected' : '') + '>' +
             kit.esc(p || 'any protocol') + '</option>';
    }).join('');
    const perOptions = kit.perPageOptions(paging.perPage);

    // THE SECOND-FACTOR COUNTS (2026-09-10), over the WHOLE population rather
    // than the page. A tile that counted one page of twenty would answer a
    // question nobody asked. Since #352 they come from `peopleCensus()`, one
    // pass over the directory, and only the rows drawn below are decorated —
    // `admin-core/CLAUDE.md`, *The users list pages before it decorates*.
    const inner = '<div class="tiles">' +
        kit.tile(json.known, 'people') +
        kit.tile(json.authenticatedHere, 'authenticated here') +
        kit.tile(json.known - json.authenticatedHere,
                  'never signed in here') +
        kit.tile(json.withActiveSession, 'with an active session') +
        kit.tile(factorCounts.withSecond, 'hold a second factor') +
        kit.tile(factorCounts.passwordOnly, 'password only') +
        kit.tile(factorCounts.noCredential, 'no way in yet') +
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
      kit.note('<strong>Everybody this realm knows about</strong>, from two ' +
      'places and the Known from column says which. <strong>SEEN</strong> is ' +
      'every userid this service has been given as part of an interaction ' +
      'that succeeded — the name typed at either sign-in screen, the one on ' +
      'a password grant, the subject of a WS-Security ' +
      '<code>UsernameToken</code>, the client principal in a Kerberos AS-REQ ' +
      'or an accepted AP-REQ, and the subject of an exchanged token; a ' +
      'request that was REFUSED records nothing. <strong>DIRECTORY</strong> ' +
      'is an entry under <code>ou=users</code>, however it got there. Most ' +
      'people are both. Click a name for its sessions, everything issued to ' +
      'it, and the second factors it holds.') +
      (json.store
        ? ''
        : kit.warn('<strong>No directory is loaded in this ' +
          'process</strong>, so this is the SEEN half alone and the ' +
          'second-factor columns say <em>unknown</em> rather than ' +
          '<em>none</em>. Those are different answers and the second one is ' +
          'the dangerous one to guess.')) +
      (json.capped
        ? kit.warn('This realm holds ' + kit.esc(String(json.scanned)) +
                    ' ' +
          'people and only the ' +
          'first ' + kit.esc(String(json.scanLimit)) + ' were read ' +
          'for the credential columns. Reading a credential per person ' +
          'happens on the one thread that answers every socket this service ' +
          'holds, so the scan stops rather than stalling the service.')
        : '') +
      (factorCounts.unreadable
        ? kit.warn('<strong>' + kit.esc(String(factorCounts.unreadable)) +
                    ' ' +
          'authenticator enrolment(s) cannot be read by this ' +
          'process</strong> — almost always a shared secret sealed under a ' +
          'key-encryption key that has since been rotated. Those people are ' +
          'REFUSED at the code step rather than let through on one factor, ' +
          'so they cannot sign in at all until the enrolment is cleared on ' +
          'their own row and set up again. <a href="' +
          kit.esc('/admin/users' + kit.queryWith({ factor: 'unreadable' },
            {})) +
          '">Show them</a>.')
        : '') +
      // WHERE AN ISSUED SPIFFE IDENTITY LANDS ON THIS TABLE, said here because
      // the row it produces is easy to misread. It has an artifact and NO
      // authentication, so it falls in the "seen only as a subject" tile above
      // — which is exactly right and is what that tile has always been for.
      // Counting an issuance as a sign-in would be the wrong answer twice over:
      // receiving a credential is not presenting one, and an agent holding
      // FetchX509SVID open re-mints every half-lifetime, so one workload left
      // running overnight would read as several hundred authentications.
      kit.note('<strong>An identity this trust domain has only ISSUED a ' +
      'certificate to is here with <em>never</em> in the Authenticated ' +
      'column</strong> &mdash; it counts under &ldquo;seen only as a ' +
      'subject&rdquo;. Being issued a credential is not presenting one, and ' +
      'an agent re-mints every half-hour, so counting issuances would turn ' +
      'one workload into hundreds of sign-ins. It also gets a directory ' +
      'entry under <code>ou=users</code> carrying the certificate it ' +
      'currently holds &mdash; see <a href="/admin/ldap/directory">the ' +
      'directory</a> and <a href="/admin/spiffe">SPIFFE</a>.') +
      kit.warn('<strong>One row is one local name, across every ' +
      'protocol.</strong> The same person arrives here as <code>alice</code> ' +
      'at the login screen, her <code>urn:uuid:</code> subject in every ' +
      'token and <code>alice@STS.MOCK</code> as a Kerberos principal, and ' +
      'showing three rows for that would be a worse answer than one — the ' +
      'premise of this service is that the name you type is who you are in ' +
      'every protocol at once. What it costs: two different people called ' +
      '<code>alice</code> in two Kerberos realms are one row here. The ' +
      'Realms column is what makes that visible. Case is never collapsed, ' +
      'because nothing in this service treats <code>Alice</code> and ' +
      '<code>alice</code> as one.') +

      '<form method="get" action="/admin/users"><div class="formrow">' +
        '<label for="q">Name contains</label>' +
        '<input type="text" id="q" name="q" size="20" value="' +
        kit.esc(wantedText) +
      '"><label ' +
        'for="protocol">Authenticated through</label><select id="protocol" ' +
        'name="protocol">' + protocolOptions + '</select>' +
        // THE SECOND-FACTOR FILTER (2026-09-10), which is what `/admin/mfa` was
        // for. `none` is the one an operator actually comes here to run, and it
        // is the reason this page's population had to widen: the people most
        // likely to hold no second factor are the ones who have never signed
        // in.
        '<label for="factor">Second factor</label>' +
        '<select id="factor" name="factor">' +
        [['', 'any state'], ['any', 'holds one'], ['totp', 'authenticator app'],
         ['key', 'security key'], ['none', 'holds none'],
         ['unreadable', 'enrolment this process cannot read']].map(
             function (pair) {
          return '<option value="' + kit.esc(pair[0]) + '"' +
                 (wantedFactor === pair[0] ? ' selected' : '') + '>' +
                 kit.esc(pair[1]) + '</option>';
        }).join('') + '</select>' +
        '<label for="per">Per page</label><select id="per" name="per">' +
      perOptions + '</select><button ' +
        'class="secondary">Filter</button>' +
        (wantedText || wantedProtocol || wantedFactor
          ? ' <a href="/admin/users">clear</a>' : '') +
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
          '<label for="new-username">Create a user</label>' +
          '<input type="text" id="new-username" name="user" size="20" ' +
                 'placeholder="username">' +
          '<button>Create &rsaquo;</button>' +
        '</div>' +
        kit.note('<strong>Takes you to <a href="/admin/users/new">New ' +
        'user</a></strong>, carrying whatever name you type here, and ' +
        'creates nobody by itself. There you fill in as few or as many of ' +
        'the ' + json.personFieldCount + ' ' +
        'attributes a person in this directory can carry as you like — only ' +
        'the username is required, and <strong>a box left empty records no ' +
        'value</strong> — and choose how they first get in: a password you ' +
        'type, one generated and shown once, a single-use activation link ' +
        'shown once, or nothing at all. There is a button there that fills ' +
        'the form in with the invented person this service would have made ' +
        'up, which is what this button used to do without asking.') +
        kit.note('Puts an entry in the embedded LDAP directory at ' +
        // THE REALM'S OWN CONTAINER, ASKED FOR RATHER THAN BUILT HERE. This
        // read `ou=users,` + the one base DN setting until 2026-08-25,
        // which is the NAMING CONTEXT and is the default realm's container
        // only: under /realm/acme the page named a DN in a different realm than
        // the one the button writes to, and named it on the very control whose
        // whole subject is where the entry goes. `ldap_server.js` answers the
        // question for the ambient realm, and the fallback is the old string
        // for the build with no directory loaded, where the slot is empty and
        // there is no realm to ask about anyway.
        '<code>uid=&lt;name&gt;,' + kit.esc(json.newUserContainer) +
          '</code>. ' +
        '<strong>One entry per person:</strong> a name that is already here ' +
        'is refused, whichever protocol brought them and whatever attribute ' +
        'their entry is named by — the same refusal an <code>ldapadd</code>, ' +
        'a SCIM create and <code>POST /admin-api/users/create</code> get, ' +
        'because all of them call one function. The new user will not appear ' +
        'in the table below until they authenticate somewhere: that is who ' +
        'this service has SEEN, and this is what the directory HOLDS.') +
      '</form>' +
      nav.head +
      '<table><tr><th>User</th><th>Known ' +
      'from</th><th>Authenticated</th><th>Can sign in with</th><th>Second ' +
      'factor</th><th>Protocols</th><th>Realms</th><th ' +
      'class="num">Sessions</th><th class="num">Tokens</th><th ' +
      'class="num">Valid</th><th class="num">Expired</th><th ' +
      'class="num">Revoked</th><th class="num">Artifacts</th><th>First ' +
      'seen</th><th>Last activity</th><th></th></tr>' +
      (rows ||
       '<tr><td colspan="16">Nobody matches. Nothing has authenticated ' +
               'here yet unless a filter above is hiding ' +
               'it.</td></tr>') + '</table>' +
      nav.foot +
      kit.note(json.matched + ' identit' +
                (json.matched === 1 ? 'y' : 'ies') +
      ' match; ' + json.known + ' known in total, most recently active ' +
      'first. An identity marked <em>never</em> under Authenticated has been ' +
      'issued something without ever presenting a credential here: an ' +
      'exchanged token from another issuer, a WS-Trust ' +
      '<code>OnBehalfOf</code>, or a Kerberos S4U request that a service ' +
      'made in their name. Listing them is the point — a users page that ' +
      'showed only the sign-ins would deny the existence of subjects the ' +
      'tokens page is showing at the same moment.') +
      kit.note('All of it is in memory and dies with the process, and the ' +
      'registry holds the most recent ' + json.registryKeeps + ' identities.');

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
   * @param factors - the person's credential facts, or null when unknown
   * @returns the cell's HTML
   */
  static credentialCell(factors) {
    if (!factors) {
      return '<span class="state-none">unknown</span>';
    }
    const parts = [];
    if (factors.password) {
      parts.push('password');
    }
    if (factors.primaryKeys) {
      parts.push(factors.primaryKeys + ' primary key' +
                 (factors.primaryKeys > 1 ? 's' : ''));
    }
    if (!parts.length) {
      return '<span class="state-expired" title="' +
        kit.esc('No password and no primary security key, so nobody can ' +
                 'sign in as this person. A second factor is never a way in ' +
                 'by itself. An activation link on their own row is how they ' +
                 'come to hold one.') +
        '">nothing yet</span>';
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
   * @param factors - the person's credential facts, or null when unknown
   * @returns the cell's HTML, "none" when no second factor is required
   */
  static secondFactorCell(factors) {
    if (!factors) {
      return '<span class="state-none">unknown</span>';
    }
    if (!factors.mfaRequired) {
      return '<span class="state-none">none</span>';
    }
    const parts = [];
    if (factors.mfaKeys) {
      parts.push(factors.mfaKeys + ' security key' +
                 (factors.mfaKeys > 1 ? 's' : ''));
    }
    if (factors.totp) {
      parts.push(factors.totpUsable
        ? 'authenticator app'
        : '<span class="state-expired" title="' +
          kit.esc('This process cannot read the enrolment: ' +
                   ((factors.totpDetail && factors.totpDetail.why) ||
                    'the stored value is unusable') +
                   '. Their codes cannot be checked, so they are REFUSED ' +
                   'rather than let through on one factor. Clear it and let ' +
                   'them enrol again.') +
          '">authenticator app (unreadable)</span>');
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
   * @param row - a row of the users list
   * @param registryKeeps - how many identities the registry keeps
   *   (`stats.MAX_USERS`)
   * @returns the cell's HTML
   */
  static sourceCell(row, registryKeeps) {
    const seen = !!(row.authenticated || row.knownBy !== 'directory');
    if (seen && row.inDirectory) {
      return '<span class="state-valid" title="' +
        kit.esc('This service has seen this identity AND the directory ' +
                 'holds an entry for it. That is the ordinary state.') +
                 '">both</span>';
    }
    if (row.inDirectory) {
      return '<span title="' +
        kit.esc('An entry under ou=users that this service\'s own registry ' +
                 'does not hold. The registry keeps the most recent ' +
                 registryKeeps +
                 ' identities and the directory is not capped, so a realm ' +
                 'that has been bulk loaded has many of these.') +
                 '">directory</span>';
    }
    return '<span title="' +
      kit.esc('This service has seen this identity and there is no ' +
               'directory entry for it — a client, an LDAP bind DN, or a ' +
               'subject something was issued for with nobody present. Their ' +
               'row says which.') +
      '">seen</span>';
  }
}

export = UsersPage;
