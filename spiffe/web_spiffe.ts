// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_spiffe.ts
//
// ---------------------------------------------------------------------------
// SPIFFE, DRAWN FROM ITS VIEWS ALONE (#446, 2026-10-05).
//
// Draws SPIFFE's console pages — the registration entries, the attested agents
// and the brokers, and their drill-downs — from the answers of `GET
// /admin-api/spiffe/*`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:spiffeEntriesListPage` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

// THE WORDS ARE THE `consoleSpiffe` CATALOG'S (#539, 2026-10-09).
//
// Every heading, label, button and paragraph this file writes is a message in
// `common/locales/consoleSpiffe/`, drawn through the page's translator
// (`ctx.t`, handed to the static helpers as `t`), and the English catalog
// holds exactly the text these pages drew before, entities and all. What the
// VIEW says — the server's sentences about entities, attestors, the TCP port,
// and every refusal and error — is drawn as it comes, in English.
//
// A VALUE OR A LINK GOES INTO A MESSAGE THROUGH A SLOT. A message's own
// parameters are escaped by `web_messages.ts`, which writes an apostrophe as
// `&#39;`, where `kit.esc()` — what these pages always used — writes
// `&apos;`; and a link or a `<code>` list is markup a message may not carry.
// So `compose()` hands the message a marker per part, and puts the part —
// escaped by `kit.esc()` or built as markup here — where the marker landed.
// The sentence stays whole for a translator, and the English stays the bytes
// it was.
const SLOT = '\u0001';

/**
 * Draws SPIFFE's console pages — the registration entries, the attested agents
 * and the brokers, and their drill-downs — from the answers of `GET
 * /admin-api/spiffe/*`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SpiffePage {
  /**
   * Draws one message with parts put into it: each part's slot is handed to
   * `draw` as the message's parameter, and replaced in what it returns by
   * the part itself, which is already HTML.
   *
   * @param parts - the parts, by parameter name, as HTML
   * @param draw - formats the message, given the slots
   * @returns the message as HTML
   */
  static compose(parts, draw) {
    const slots = {};
    Object.keys(parts).forEach(function (name) {
      slots[name] = SLOT + name + SLOT;
    });
    return String(draw(slots)).replace(
      new RegExp(SLOT + '([A-Za-z0-9]+)' + SLOT, 'g'),
      function (whole, name) {
        return name in parts ? String(parts[name]) : whole;
      });
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static entries(ctx, json) {
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/spiffe/entries', ctx.query);
    const rows = json.entries.map(function (entry) {
      return '<tr><td><a href="/admin/spiffe/entries' +
        kit.queryWith(listView, { entry: entry.id }) + '"><code>' +
        kit.esc(entry.spiffeId) + '</code></a>' +
        (entry.expired ? ' <strong>' + t.html('consoleSpiffe.expired') +
                         '</strong>' : '') +
        '<br><span class="note"><code>' + kit.esc(entry.id) +
        '</code></span></td>' +
        '<td>' + kit.esc(entry.selectorTexts.join(', ') ||
                          t.text('consoleSpiffe.selectorsNoneEvery')) +
        '</td>' +
        '<td>' + kit.esc(entry.origin) + '</td>' +
        '<td>' + kit.esc(entry.hint || '—') + '</td>' +
        '<td>' + entry.svidsIssued + '</td>' +
        '<td>' + SpiffePage.compose({ n: entry.revisionNumber },
          function (s) {
            return t.html('consoleSpiffe.revisionShort', s);
          }) + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="6">' + t.html('consoleSpiffe.noEntryMatches') +
      '</td></tr>';
    const originOptions = ['<option value="">' +
      t.html('consoleSpiffe.everyOrigin') + '</option>'].concat(
      json.origins.map(function (name) {
        return '<option value="' + kit.esc(name) + '"' +
          (json.filter.origin === name ? ' selected' : '') + '>' +
          kit.esc(name) +
          '</option>';
      })).join('');
    const inner = SpiffePage.spiffePostureNote(t,
                                               json.serverApiAuthenticated) +
      kit.note(SpiffePage.compose({ total: kit.esc(json.total),
                                    max: kit.esc(json.max),
                                    container: kit.esc(json.container) },
        function (s) {
          return t.html('consoleSpiffe.entriesCount', s);
        })) +
      '<form method="get" action="/admin/spiffe/entries"><div ' +
      'class="formrow"><label for="q">' + t.html('consoleSpiffe.search') +
      '</label>' +
      '<input id="q" name="q" value="' + kit.esc(json.filter.q) +
      '" size="28" ' +
      'placeholder="' +
      kit.esc(t.text('consoleSpiffe.entriesSearchPlaceholder')) + '">' +
      '<label for="origin">' + t.html('consoleSpiffe.origin') + '</label>' +
      '<select id="origin" name="origin">' + originOptions + '</select>' +
      '<label for="per">' + t.html('consoleSpiffe.rows') + '</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(json.paging.perPage) +
      '</select><button class="secondary">' +
      t.html('consoleSpiffe.filter') + '</button>' +
      kit.note(t.html('consoleSpiffe.originNote')) +
      '</div></form><table><tr><th>' +
      t.html('consoleSpiffe.thSpiffeIdEntryId') + '</th><th>' +
      t.html('consoleSpiffe.selectors') + '</th><th>' +
      t.html('consoleSpiffe.origin') + '</th><th>' +
      t.html('consoleSpiffe.hint') + '</th><th>' +
      t.html('consoleSpiffe.svids') + '</th>' +
      '<th>' +
      t.html('consoleSpiffe.revision') + '</th></tr>' + rows + '</table>' +
      kit.pageNavPair('/admin/spiffe/entries', kit.filterOnly(listView),
                       json.paging).head +
      SpiffePage.spiffeCreateEntryForm(t, json.trustDomain);
    return inner;
  }

  // The warning that goes at the top of all three, written once. It is the
  // SPIFFE analogue of the "a group here grants nothing" line on /admin/groups,
  // and it matters more, because what comes out of these pages is a credential
  // another service will believe. The banner every SPIFFE page carries. It is a
  // FUNCTION rather than a constant now, because half of what it says depends
  // on a setting that can be off: a fixed string would go on describing mutual
  // TLS on a port that had been bound plain, which is the silent disagreement
  // this repository keeps warning about.
  //
  // TWO PARAGRAPHS, and the split is the point — the two surfaces are
  // authenticated differently because their specifications say opposite things,
  // and a single sentence covering both was what made the old note wrong in one
  // direction as soon as one of them changed.
  /**
   * Draws the banner every SPIFFE page carries: that a Workload API caller
   * is not attested, and whether the SPIRE Server API requires mutual TLS.
   *
   * @param t - the page's translator
   * @param enforced - whether the SPIRE Server API authenticates its
   *   callers (`spiffeAuth.authRequired()`)
   * @returns the two notes as HTML
   */
  static spiffePostureNote(t, enforced) {
    return kit.warn(t.html('consoleSpiffe.postureNotAttested')) +
      '<div class="' + (enforced ? 'note' : 'warn') + '">' +
      (enforced
        ? t.html('consoleSpiffe.postureServerApiMtls')
        : t.html('consoleSpiffe.postureServerApiOpen')) +
      ' ' + SpiffePage.compose({ link: '<a href="/spiffe">GET /spiffe</a>' },
        function (s) {
          return t.html('consoleSpiffe.postureSeeSpiffe', s);
        }) + '</div>';
  }

  /**
   * Draws the form that creates a SPIFFE registration entry.
   *
   * @param t - the page's translator
   * @param trustDomain - the realm's trust domain, for the placeholder
   * @returns the form as HTML
   */
  static spiffeCreateEntryForm(t, trustDomain) {
    return '<h2>' + t.html('consoleSpiffe.createEntryHeading') + '</h2>' +
      kit.note(t.html('consoleSpiffe.createEntryNote')) +
      '<form method="post" action="/admin/spiffe/entries"><div ' +
      'class="formrow"><input type="hidden" name="action" value="create">' +
      '<label for="e-id">' + t.html('consoleSpiffe.spiffeId') + '</label>' +
      '<input id="e-id" name="spiffeId" size="40" placeholder="spiffe://' +
      kit.esc(trustDomain) + '/ns/default/sa/web"><label ' +
      'for="e-parent">' + t.html('consoleSpiffe.parent') +
      '</label><input id="e-parent" name="parentId" ' +
      'size="34" placeholder="' +
      kit.esc(t.text('consoleSpiffe.thisServer')) + '"></div><div ' +
      'class="formrow"><label for="e-sel">' +
      t.html('consoleSpiffe.selectors') + '</label><input id="e-sel" ' +
      'name="selectors" size="40" placeholder="unix:uid:1000, ' +
      'k8s:ns:default"><label for="e-dns">' +
      t.html('consoleSpiffe.dnsNames') + '</label><input id="e-dns" ' +
      'name="dnsNames" size="26" placeholder="web.default.svc"></div><div ' +
      'class="formrow"><label for="e-x509ttl">' +
      t.html('consoleSpiffe.x509SvidTtl') + '</label><input ' +
      'id="e-x509ttl" name="x509SvidTtl" size="6" placeholder="3600"><label ' +
      'for="e-jwtttl">' + t.html('consoleSpiffe.jwtSvidTtl') +
      '</label><input id="e-jwtttl" ' +
      'name="jwtSvidTtl" size="6" placeholder="300"><label ' +
      'for="e-hint">' + t.html('consoleSpiffe.hint') +
      '</label><input id="e-hint" name="hint" size="12" ' +
      'placeholder="internal"><label for="e-fed">' +
      t.html('consoleSpiffe.federatesWith') +
      '</label><input id="e-fed" name="federatesWith" size="20" ' +
      'placeholder="other.example"><button>' +
      t.html('consoleSpiffe.create') + '</button>' +
      kit.note(t.html('consoleSpiffe.selectorsSyntaxNote')) +
      '</div></form>';
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static agents(ctx, json) {
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/spiffe/agents', ctx.query);
    const rows = json.agents.map(function (agent) {
      return '<tr><td><a href="/admin/spiffe/agents' +
        kit.queryWith(listView, { agent: agent.id }) + '"><code>' +
        kit.esc(agent.id) + '</code></a></td>' +
        '<td>' + kit.esc(agent.attestationType) + '</td>' +
        '<td>' + (agent.banned
          ? '<strong>' + t.html('consoleSpiffe.banned') + '</strong>'
          : t.html('consoleSpiffe.active')) +
        '</td><td>' + agent.attestations + '</td>' +
        '<td>' + kit.esc(agent.lastSeen || '—') + '</td></tr>';
    }).join('') || '<tr><td colspan="5">' +
      t.html('consoleSpiffe.noAgents') + '</td></tr>';
    const inner = SpiffePage.spiffePostureNote(t,
                                               json.serverApiAuthenticated) +
      kit.note(SpiffePage.compose({ total: kit.esc(json.total),
                                    max: kit.esc(json.max) },
        function (s) {
          return t.html('consoleSpiffe.agentsCount', s);
        })) +
      kit.note(t.html('consoleSpiffe.nodeAttestationNote')) +
      '<form method="get" action="/admin/spiffe/agents"><div class="formrow">' +
      '<label for="q">' + t.html('consoleSpiffe.search') + '</label>' +
      '<input id="q" name="q" value="' + kit.esc(json.filter.q) +
      '" size="30" placeholder="' +
      kit.esc(t.text('consoleSpiffe.agentsSearchPlaceholder')) + '"><label ' +
      'for="per">' + t.html('consoleSpiffe.rows') +
      '</label><select id="per" name="per">' +
      kit.perPageOptions(json.paging.perPage) +
      '</select><button class="secondary">' +
      t.html('consoleSpiffe.filter') + '</button></div></form>' +
      '<table><tr><th>' + t.html('consoleSpiffe.agent') + '</th><th>' +
      t.html('consoleSpiffe.attestor') + '</th><th>' +
      t.html('consoleSpiffe.state') + '</th>' +
      '<th>' + t.html('consoleSpiffe.attestations') + '</th><th>' +
      t.html('consoleSpiffe.lastSeen') + '</th></tr>' + rows + '</table>' +
      kit.pageNavPair('/admin/spiffe/agents', kit.filterOnly(listView),
                       json.paging).head;
    return inner;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static brokers(ctx, json) {
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/spiffe/brokers', ctx.query);
    const back = '<input type="hidden" name="back" value="' +
                 kit.esc(kit.queryWith(listView, {})) + '">';
    const rows = json.brokers.map(function (one) {
      // A broker's problem is a refusal, and a refusal stays English.
      return '<tr><td><code>' + kit.esc(one.id) + '</code></td><td>' +
        (one.problem ? '<strong>refused:</strong> ' + kit.esc(one.problem)
                     : kit.esc(one.referenceTypes.join(', '))) +
        '</td><td><form method="post" action="/admin/spiffe/brokers">' +
        '<input type="hidden" name="action" value="remove"><input ' +
        'type="hidden" name="id" value="' + kit.esc(one.id) + '">' + back +
        '<button class="danger">' + t.html('consoleSpiffe.remove') +
        '</button></form></td></tr>';
    }).join('') || '<tr><td colspan="3">' +
      t.html('consoleSpiffe.noBrokers') + '</td></tr>';
    const listening = json.listeners.filter(function (b) {
      return b.listening;
    }).map(function (b) {
      return '<code>' + kit.esc(b.address) + '</code>';
    }).join(', ');
    const where = listening
      ? SpiffePage.compose({ addresses: listening }, function (s) {
          return t.html('consoleSpiffe.brokersListeningOn', s);
        })
      : SpiffePage.compose({ port: kit.esc(json.port) }, function (s) {
          return t.html('consoleSpiffe.brokersNotListening', s);
        });
    const inner = kit.note(SpiffePage.compose({ where: where },
        function (s) {
          return t.html('consoleSpiffe.brokersIntro', s);
        })) +
      kit.note(t.html('consoleSpiffe.brokersPidNote')) +
      '<form method="get" action="/admin/spiffe/brokers"><div ' +
      'class="formrow"><label for="q">' + t.html('consoleSpiffe.search') +
      '</label><input id="q" name="q" ' +
      'value="' + kit.esc(json.filter.q) + '" size="30" placeholder="' +
      kit.esc(t.text('consoleSpiffe.brokersSearchPlaceholder')) +
      '"><label for="per">' + t.html('consoleSpiffe.rows') +
      '</label><select ' +
      'id="per" name="per">' + kit.perPageOptions(json.paging.perPage) +
      '</select><button class="secondary">' +
      t.html('consoleSpiffe.filter') + '</button></div></form>' +
      '<table><tr><th>' + t.html('consoleSpiffe.broker') + '</th><th>' +
      t.html('consoleSpiffe.mayReference') + '</th><th></th></tr>' +
      rows + '</table>' +
      kit.pageNavPair('/admin/spiffe/brokers', kit.filterOnly(listView),
                       json.paging).head +
      '<h2>' + t.html('consoleSpiffe.authorizeBroker') + '</h2>' +
      '<form method="post" action="/admin/spiffe/brokers"><div ' +
      'class="formrow"><input type="hidden" name="action" value="set">' +
      back + '<label for="b-id">' + t.html('consoleSpiffe.spiffeId') +
      '</label><input id="b-id" name="id" ' +
      'size="44" placeholder="spiffe://' + kit.esc(json.trustDomain) +
      '/ns/mesh/sa/node-proxy"></div><div class="formrow"><label><input ' +
      'type="checkbox" name="referenceTypes" value="pid"> pid ' +
      '(WorkloadPIDReference)</label><label><input type="checkbox" ' +
      'name="referenceTypes" value="k8s"> ' +
      t.html('consoleSpiffe.refK8s') + '</label><label><input ' +
      'type="checkbox" name="referenceTypes" value="*"> ' +
      t.html('consoleSpiffe.refBoth') + '</label>' +
      '<button>' + t.html('consoleSpiffe.save') + '</button>' +
      kit.note(t.html('consoleSpiffe.brokerSaveNote')) + '</div></form>';
    return inner;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static entry(ctx, json) {
    const t = ctx.t;
    const entry = json.found ? json.entry : null;
    const listView = kit.listViewOf('/admin/spiffe/entries', ctx.query);
    const back = kit.queryWith(listView, {});
    let inner;
    if (!entry) {
      inner = kit.note(SpiffePage.compose({ id: kit.esc(json.id) },
                 function (s) {
                   return t.html('consoleSpiffe.entryNotFound', s);
                 })) +
                 '<p><a href="/admin/spiffe/entries' + kit.esc(back) +
                 '">' + t.html('consoleSpiffe.backToEntries') + '</a>.</p>';
    } else {
      const attributeRows = Object.keys(entry.attributes || {}).sort()
        .map(function (name) {
          const value = entry.attributes[name];
          return '<tr><td><code>' + kit.esc(name) + '</code></td><td>' +
            kit.esc(Array.isArray(value) ? value.join(' | ') : String(value)) +
            '</td></tr>';
        }).join('');
      const carried = '<input type="hidden" name="back" value="' +
                      kit.esc(back) +
                      '"><input ' +
                      'type="hidden" name="entry" value="' + kit.esc(entry.id) +
                      '">';
      // Two whole sentences rather than a clause added to one, so a
      // translator can say "has expired" where their language puts it.
      const lives = { id: kit.esc(entry.id),
                      revision: kit.esc(entry.revisionNumber),
                      origin: kit.esc(entry.origin),
                      dn: kit.esc(entry.dn) };
      inner = SpiffePage.spiffePostureNote(t, json.serverApiAuthenticated) +
        '<h2><code>' + kit.esc(entry.spiffeId) + '</code></h2>' +
        kit.note(entry.expired
          ? SpiffePage.compose(lives, function (s) {
              return t.html('consoleSpiffe.entryLivesExpired', s);
            })
          : SpiffePage.compose(lives, function (s) {
              return t.html('consoleSpiffe.entryLives', s);
            })) +
        '<table><tr><th>' + t.html('consoleSpiffe.field') + '</th><th>' +
        t.html('consoleSpiffe.value') + '</th></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.parent') +
        '</td><td><code>' + kit.esc(entry.parentId) +
        '</code></td></tr><tr><td>' + t.html('consoleSpiffe.selectors') +
        '</td><td>' +
        kit.esc(entry.selectorTexts.join(', ') ||
                 t.text('consoleSpiffe.selectorsNoneThisEntry')) +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.dnsNames') + '</td><td>' +
        kit.esc(entry.dnsNames.join(', ') || '—') +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.federatesWith') + '</td><td>' +
        kit.esc(entry.federatesWith.join(', ') || '—') + '</td></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.x509SvidTtl') + '</td><td>' +
        (entry.x509SvidTtl ||
         SpiffePage.compose({ ttl: kit.esc(json.defaults.x509SvidTtl) },
           function (s) {
             return t.html('consoleSpiffe.ttlDefault', s);
           })) +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.jwtSvidTtl') + '</td><td>' +
        (entry.jwtSvidTtl ||
         SpiffePage.compose({ ttl: kit.esc(json.defaults.jwtSvidTtl) },
           function (s) {
             return t.html('consoleSpiffe.ttlDefault', s);
           })) +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.hint') + '</td><td>' +
        kit.esc(entry.hint || '—') + '</td></tr>' +
        '<tr><td>admin / downstream / storeSvid</td><td>' +
        (entry.admin ? 'admin' : '') + (entry.downstream ? ' downstream' : '') +
        (entry.storeSvid ? ' storeSvid' : '') +
        ((entry.admin || entry.downstream || entry.storeSvid) ? '' : '—') +
        ' <span class="note">' + t.html('consoleSpiffe.flagsNeverRead') +
        '</span></td></tr><tr><td>' + t.html('consoleSpiffe.svidsIssued') +
        '</td><td>' + entry.svidsIssued +
        (entry.lastSvidAt
          ? SpiffePage.compose({ at: kit.esc(entry.lastSvidAt) },
              function (s) {
                return t.html('consoleSpiffe.mostRecently', s);
              })
          : '') +
        '</td></tr></table>' +

        '<h3>' + t.html('consoleSpiffe.changeIt') + '</h3>' +
        kit.note(t.html('consoleSpiffe.changeItNote')) +
        '<form method="post" action="/admin/spiffe/entries"><div ' +
        'class="formrow"><input type="hidden" name="action" value="update">' +
        carried +
        '<label for="u-field">' + t.html('consoleSpiffe.field') + '</label>' +
        '<select id="u-field" name="field">' +
        ['spiffeId', 'parentId', 'selectors', 'dnsNames', 'federatesWith',
         'x509SvidTtl', 'jwtSvidTtl', 'hint', 'expiresAt', 'admin',
           'downstream',
         'storeSvid'].map(function (name) {
          return '<option value="' + kit.esc(name) + '">' + kit.esc(name) +
                 '</option>';
        }).join('') + '</select>' +
        '<label for="u-value">' + t.html('consoleSpiffe.value') + '</label>' +
        '<input id="u-value" name="value" size="40">' +
        '<button>' + t.html('consoleSpiffe.set') + '</button>' +
        '<span class="note">' + t.html('consoleSpiffe.setFieldNote') +
        '</span>' +
        '</div></form>' +
        '<form method="post" action="/admin/spiffe/entries"><div ' +
        'class="formrow"><input type="hidden" name="action" value="delete">' +
        carried +
        '<button class="danger">' + t.html('consoleSpiffe.deleteEntry') +
        '</button>' +
        kit.note(t.html('consoleSpiffe.deleteEntryNote')) + '</div></form>' +

        '<h3>' + t.html('consoleSpiffe.directoryEntry') + '</h3>' +
        '<p>' + t.html('consoleSpiffe.directoryEntryNote') + '</p>' +
        '<table><tr><th>' + t.html('consoleSpiffe.attribute') + '</th><th>' +
        t.html('consoleSpiffe.value') + '</th></tr>' + attributeRows +
        '</table>';
    }
    return inner;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static agent(ctx, json) {
    const t = ctx.t;
    const agent = json.found ? json.agent : null;
    const listView = kit.listViewOf('/admin/spiffe/agents', ctx.query);
    const back = kit.queryWith(listView, {});
    let inner;
    if (!agent) {
      inner = '<p>' + SpiffePage.compose({ id: kit.esc(json.id) },
                 function (s) {
                   return t.html('consoleSpiffe.agentNotFound', s);
                 }) +
                 '</p><p><a href="/admin/spiffe/agents' +
                 kit.esc(back) +
                 '">' + t.html('consoleSpiffe.backToAgents') + '</a>.</p>';
    } else {
      const attributeRows = Object.keys(agent.attributes || {}).sort()
        .map(function (name) {
          const value = agent.attributes[name];
          return '<tr><td><code>' + kit.esc(name) + '</code></td><td>' +
            kit.esc(Array.isArray(value) ? value.join(' | ') : String(value)) +
            '</td></tr>';
        }).join('');
      const carried = '<input type="hidden" name="back" value="' +
                      kit.esc(back) +
                      '"><input ' +
                      'type="hidden" name="agent" value="' + kit.esc(agent.id) +
                      '">';
      inner = SpiffePage.spiffePostureNote(t, json.serverApiAuthenticated) +
        '<h2><code>' + kit.esc(agent.id) + '</code></h2>' +
        kit.note(SpiffePage.compose({
            type: kit.esc(agent.attestationType),
            count: kit.esc(agent.attestations),
            first: kit.esc(agent.firstSeen),
            last: kit.esc(agent.lastSeen),
            dn: kit.esc(agent.dn) },
          function (s) {
            return t.html('consoleSpiffe.agentHeader', s);
          })) +
        '<table><tr><th>' + t.html('consoleSpiffe.field') + '</th><th>' +
        t.html('consoleSpiffe.value') + '</th></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.state') + '</td><td>' +
        (agent.banned
          ? t.html('consoleSpiffe.bannedExplained')
          : t.html('consoleSpiffe.active')) + '</td></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.itsDirectoryEntry') + '</td><td>' +
        t.html('consoleSpiffe.itsDirectoryEntryText') +
        ' <span class="note">' + t.html('consoleSpiffe.notACertStatus') +
        '</span></td></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.canReattest') + '</td><td>' +
        (agent.canReattest ? t.html('consoleSpiffe.yes')
                           : t.html('consoleSpiffe.no')) +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleSpiffe.selectors') + '</td><td>' +
        kit.esc(agent.selectorTexts.join(', ') || '—') +
        ' <span class="note">' + t.html('consoleSpiffe.claimedNeverVerified') +
        '</span></td></tr>' +
        '<tr><td>SVID</td><td>' + kit.esc(agent.svidHash || '—') +
        (agent.expiresAt
          ? SpiffePage.compose({
              at: kit.esc(new Date(agent.expiresAt * 1000).toISOString()) },
              function (s) {
                return t.html('consoleSpiffe.expiresAt', s);
              })
          : '') +
        '</td></tr></table>' +
        '<form method="post" action="/admin/spiffe/agents"><div ' +
        'class="formrow"><input type="hidden" name="action" value="' +
        (agent.banned ? 'unban' : 'ban') + '">' + carried +
        '<button class="' + (agent.banned ? 'secondary' : 'danger') + '">' +
        (agent.banned ? t.html('consoleSpiffe.unbanAgent')
                      : t.html('consoleSpiffe.banAgent')) + '</button>' +
        kit.note(t.html('consoleSpiffe.banNote')) +
        '</div></form>' +
        '<form method="post" action="/admin/spiffe/agents"><div ' +
        'class="formrow"><input type="hidden" name="action" value="delete">' +
        carried +
        '<button class="danger">' + t.html('consoleSpiffe.deleteAgent') +
        '</button>' +
        kit.note(t.html('consoleSpiffe.deleteAgentNote')) + '</div></form>' +
        '<h3>' + t.html('consoleSpiffe.directoryEntry') + '</h3>' +
        '<table><tr><th>' + t.html('consoleSpiffe.attribute') + '</th><th>' +
        t.html('consoleSpiffe.value') + '</th></tr>' + attributeRows +
        '</table>';
    }
    return inner;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static overview(ctx, json) {
    const t = ctx.t;
    const state = json.authorityState;
    const x509Rows = state.x509Authorities.map(function (authority) {
      return '<tr><td><code>' + kit.esc(authority.id) + '</code></td><td>' +
        (authority.active
          ? '<strong>' + t.html('consoleSpiffe.active') + '</strong>' :
         t.html('consoleSpiffe.retiredPublished')) +
        '</td><td>' + kit.esc(authority.keyType) + '</td><td>' +
        kit.esc(authority.notAfter) + '</td><td><code>' +
        kit.esc(authority.subject) +
        '</code></td></tr>';
    }).join('');
    const jwtRows = state.jwtAuthorities.map(function (authority) {
      return '<tr><td><code>' + kit.esc(authority.id) + '</code></td><td>' +
        (authority.active
          ? '<strong>' + t.html('consoleSpiffe.active') + '</strong>' :
         t.html('consoleSpiffe.retiredPublished')) +
        '</td><td>' + kit.esc(authority.keyType) + ' / ' +
        kit.esc(authority.alg) +
        '</td><td>' + kit.esc(new Date(authority.createdAt).toISOString()) +
        '</td><td>&mdash;</td></tr>';
    }).join('');
    const federatedRows = state.federated.map(function (entry) {
      return '<tr><td><code>' + kit.esc(entry.trustDomainId) +
             '</code></td><td>' +
        SpiffePage.compose({ x509: entry.x509Keys, jwt: entry.jwtKeys },
          function (s) {
            return t.html('consoleSpiffe.keyCounts', s);
          }) + '</td><td>' +
        kit.esc(entry.bundleEndpointProfile) + '<br><span class="note">' +
        kit.esc(entry.bundleEndpointUrl ||
                t.text('consoleSpiffe.noEndpointUrl')) +
        '</span></td><td>' + kit.esc(entry.sequence) + '</td><td>' +
        '<form method="post" action="/admin/spiffe" class="inline">' +
        '<input type="hidden" name="action" value="federation-remove">' +
        '<input type="hidden" name="trustDomain" value="' +
        kit.esc(entry.trustDomain) + '"><button ' +
        'class="danger">' + t.html('consoleSpiffe.remove') +
        '</button></form> <a ' +
        'href="/spiffe/federated/' + encodeURIComponent(entry.trustDomain) +
        '">' + t.html('consoleSpiffe.document') + '</a></td></tr>';
    }).join('') ||
      '<tr><td colspan="5">' + t.html('consoleSpiffe.noFederation') +
      '</td></tr>';
    const pkiLink = '<a href="/admin/pki">' +
      t.html('consoleSpiffe.pkiManageLink') + '</a>';
    const buildLink = '<a href="/admin/pki">' +
      t.html('consoleSpiffe.pkiBuildLink') + '</a>';
    const chain = json.authorities.chainSubjects.length
      ? ' (' + json.authorities.chainSubjects.map(function (subject) {
          return '<code>' + kit.esc(subject) + '</code>';
        }).join(' &rarr; ') + ')'
      : '';
    const adminIds = json.authentication.adminIds.map(function (id) {
      return '<code>' + kit.esc(id) + '</code>';
    }).join(', ');

    const inner = SpiffePage.spiffePostureNote(t,
                                               json.serverApiAuthenticated) +
      (json.enabled ? '' : kit.warn(t.html('consoleSpiffe.spiffeOff'))) +
      // The authority's build error is a failure, and stays English.
      (json.ready ? '' : kit.warn((json.error
        ? 'The issuing authority could not be built, so nothing here will ' +
          'issue an SVID: ' + kit.esc(json.error)
        : t.html('consoleSpiffe.authorityGenerating')))) +

      '<h2>' + t.html('consoleSpiffe.trustDomainHeading') + '</h2>' +
      kit.note(SpiffePage.compose({
          trustDomainId: kit.esc(json.trustDomainId),
          serverId: kit.esc(json.serverId ||
                            t.text('consoleSpiffe.notYet')) },
        function (s) {
          return t.html('consoleSpiffe.trustDomainNote', s);
        })) +
      kit.note(SpiffePage.compose({
          link: '<a href="' + kit.esc(json.bundle.path) + '"><code>' +
                kit.esc(json.bundle.path) + '</code></a>',
          sequence: kit.esc(json.bundle.sequence),
          hint: kit.esc(json.bundle.refreshHint) },
        function (s) {
          return t.html('consoleSpiffe.bundleNote', s);
        })) +

      '<h2>' + t.html('consoleSpiffe.authorities') + '</h2>' +
      // ---------------------------------------------------------------------
      // THE X.509 AUTHORITY CAME FROM ONE OF TWO PLACES AND THIS PAGE SAYS
      // WHICH (2026-09-11).
      //
      // The two differ in the one thing an operator has to ACT on — what to
      // install as a trust anchor and how often — so the note is branched
      // rather than generalised into a sentence true of both. A page that read
      // the same either way would be describing a self-signed authority's
      // maintenance burden to somebody who no longer has one, or hiding it from
      // somebody who does.
      // ---------------------------------------------------------------------
      (json.authorities.source === 'pki'
        ? kit.note(SpiffePage.compose({
              pkiLink: pkiLink, chain: chain,
              maxRetained: kit.esc(json.authorities.maxRetained) },
            function (s) {
              return t.html('consoleSpiffe.authorityPki', s);
            }))
        : kit.warn(SpiffePage.compose({
              buildLink: buildLink,
              maxRetained: kit.esc(json.authorities.maxRetained) },
            function (s) {
              return t.html('consoleSpiffe.authoritySelfSigned', s);
            }))) +
      '<table><tr><th>' + t.html('consoleSpiffe.id') + '</th><th>' +
      t.html('consoleSpiffe.state') + '</th><th>' +
      t.html('consoleSpiffe.key') + '</th><th>' +
      t.html('consoleSpiffe.until') + '</th>' +
      '<th>' + t.html('consoleSpiffe.subject') + '</th></tr>' + x509Rows +
      jwtRows + '</table>' +
      // **WHAT SIGNS AND WHAT IS TRUSTED ARE TWO TABLES.** They were one, and
      // could be, while a self-signed authority was both. See `/spiffe`'s own
      // version of this note.
      '<h3>' + t.html('consoleSpiffe.whatConsumerTrusts') + '</h3>' +
      '<table><tr><th>' + t.html('consoleSpiffe.anchor') + '</th><th>' +
      t.html('consoleSpiffe.subject') + '</th><th>' +
      t.html('consoleSpiffe.until') + '</th></tr>' +
      (json.authorities.trustAnchors || []).map(function (anchor) {
        return '<tr><td><code>' + kit.esc(anchor.id) +
               '</code></td><td><code>' +
          kit.esc(anchor.subject) + '</code></td><td>' +
          kit.esc(anchor.notAfter) +
          '</td></tr>';
      }).join('') + '</table>' +
      '<form method="post" action="/admin/spiffe"><div class="formrow">' +
      '<input type="hidden" name="action" value="rotate">' +
      '<label for="which">' + t.html('consoleSpiffe.rotate') + '</label>' +
      '<select id="which" name="which">' +
      '<option value="x509">' + t.html('consoleSpiffe.rotateX509') +
      '</option>' +
      '<option value="jwt">' + t.html('consoleSpiffe.rotateJwt') +
      '</option>' +
      '<option value="both">' + t.html('consoleSpiffe.rotateBoth') +
      '</option></select>' +
      '<button>' + t.html('consoleSpiffe.rotate') + '</button>' +
      '<span class="note">' + t.html('consoleSpiffe.rotateNote') +
      '</span>' +
      '</div></form>' +

      '<h2>' + t.html('consoleSpiffe.grpcListeners') + '</h2>' +
      kit.note(t.html('consoleSpiffe.grpcListenersNote')) +
      '<table><tr><th>' + t.html('consoleSpiffe.surface') + '</th><th>' +
      t.html('consoleSpiffe.realm') + '</th><th>' +
      t.html('consoleSpiffe.address') + '</th><th>' +
      t.html('consoleSpiffe.state') +
      '</th>' +
      '<th>' + t.html('consoleSpiffe.callerPresents') + '</th></tr>' +
      SpiffePage.spiffeListenerRows(t, json.listeners.workloadApi,
        'Workload API') +
      SpiffePage.spiffeListenerRows(t, json.listeners.serverApi,
        'SPIRE Server API') +
      SpiffePage.spiffeListenerRows(t, json.listeners.brokerApi || [],
                              'SPIFFE Broker API') +
      '</table>' +

      SpiffePage.spiffeWorkloadAttestation(t, json.workloadAttestation) +

      '<h2>' + t.html('consoleSpiffe.whoMayCall') + '</h2>' +
      '<p>' + kit.esc(json.authentication.what || '') + '</p>' +
      kit.note(t.html('consoleSpiffe.anyOfNote')) +
      '<table><tr><th>' + t.html('consoleSpiffe.entity') + '</th><th>' +
      t.html('consoleSpiffe.whatItMeans') + '</th></tr>' +
      json.authentication.entities.map(function (entity) {
        return '<tr><td><code>' + kit.esc(entity.id) + '</code></td><td>' +
          kit.esc(entity.what) + '</td></tr>';
      }).join('') + '</table>' +
      kit.note((json.authentication.adminIds.length
        ? SpiffePage.compose({ ids: adminIds }, function (s) {
            return t.html('consoleSpiffe.adminIdsList', s);
          })
        : t.html('consoleSpiffe.adminIdsNone')) + ' ' +
        SpiffePage.compose({
            entriesLink: '<a href="/admin/spiffe/entries">' +
                         t.html('consoleSpiffe.entriesPageLink') + '</a>' },
          function (s) {
            return t.html('consoleSpiffe.adminIdsOtherWay', s);
          })) +
      kit.note((json.authentication.attestWorkloads
        ? t.html('consoleSpiffe.workloadSelectorsDecide')
        : t.html('consoleSpiffe.workloadSelectorsDecideNothing')) + ' ' +
        SpiffePage.compose({
            header: kit.esc(json.authentication.assertedSelectorHeader) },
          function (s) {
            return json.authentication.acceptAssertedSelectors
              ? t.html('consoleSpiffe.assertedBelieved', s)
              : t.html('consoleSpiffe.assertedIgnored', s);
          }) + ' ' + t.html('consoleSpiffe.bothSwitchesInForce')) +
      '<h3>' + t.html('consoleSpiffe.perMethodTable') + '</h3>' +
      kit.note(t.html('consoleSpiffe.perMethodNote')) +
      '<table><tr><th>' + t.html('consoleSpiffe.method') + '</th><th>' +
      t.html('consoleSpiffe.allowedTo') + '</th></tr>' +
      json.authentication.policy.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.method) + '</code></td><td>' +
          kit.esc(row.allow.join(', ')) + '</td></tr>';
      }).join('') + '</table>' +

      '<h2>' + t.html('consoleSpiffe.federatedHeading') + '</h2>' +
      kit.note(t.html('consoleSpiffe.federatedNote')) +
      '<table><tr><th>' + t.html('consoleSpiffe.trustDomain') + '</th><th>' +
      t.html('consoleSpiffe.keys') + '</th><th>' +
      t.html('consoleSpiffe.profileEndpoint') + '</th><th>' +
      t.html('consoleSpiffe.sequence') + '</th><th></th></tr>' +
      federatedRows +
      '</table><form ' +
      'method="post" action="/admin/spiffe"><div class="formrow"><input ' +
      'type="hidden" name="action" value="federation-set"><label ' +
      'for="fed-td">' + t.html('consoleSpiffe.trustDomain') +
      '</label><input id="fed-td" ' +
      'name="trustDomain" placeholder="other.example" size="24"><label ' +
      'for="fed-url">' + t.html('consoleSpiffe.bundleEndpointUrl') +
      '</label><input id="fed-url" ' +
      'name="bundleEndpointUrl" placeholder="https://other.example/bundle" ' +
      'size="34"><label for="fed-profile">' +
      t.html('consoleSpiffe.profile') + '</label><select ' +
      'id="fed-profile" name="bundleEndpointProfile"><option ' +
      'value="https_web">https_web</option><option ' +
      'value="https_spiffe">https_spiffe</option></select></div><div ' +
      'class="formrow"><label for="fed-doc">' +
      t.html('consoleSpiffe.bundleDocument') + '</label><textarea ' +
      'id="fed-doc" name="document" rows="6" cols="80" ' +
      'placeholder=\'{"keys":[{"kty":"EC","use":"x509-svid","x5c":["..."]}],' +
      '"spiffe_sequence":1,"spiffe_refresh_hint":300}\'></textarea><button>' +
      t.html('consoleSpiffe.set') + '</button>' +
      kit.note(t.html('consoleSpiffe.jwkSetNote')) +
      '</div></form>' +

      '<h2>' + t.html('consoleSpiffe.elsewhere') + '</h2><ul>' +
      '<li><a href="/admin/spiffe/entries">' +
      t.html('consoleSpiffe.registrationEntries') + '</a> &mdash; ' +
      SpiffePage.compose({ n: kit.esc(json.counts.entries),
                           max: kit.esc(json.counts.maxEntries) },
        function (s) {
          return t.html('consoleSpiffe.ofAtMost', s);
        }) +
      '</li>' +
      '<li><a href="/admin/spiffe/agents">' +
      t.html('consoleSpiffe.attestedAgents') + '</a> &mdash; ' +
      SpiffePage.compose({ n: kit.esc(json.counts.agents),
                           max: kit.esc(json.counts.maxAgents) },
        function (s) {
          return t.html('consoleSpiffe.ofAtMost', s);
        }) +
      '</li><li><a href="/admin/spiffe/brokers">' +
      t.html('consoleSpiffe.brokerApiBrokers') + '</a> &mdash; ' +
      t.html('consoleSpiffe.brokerApiBrokersWhat') +
      '</li><li><a href="/spiffe">' +
      t.html('consoleSpiffe.whatThisIs') +
      '</a></li><li><a href="/admin/ldap/spiffe">' +
      t.html('consoleSpiffe.containersSchema') +
      '</a></li><li><a href="/admin-api/spiffe">' +
      t.html('consoleSpiffe.sameOverJson') + '</a></li></ul>' +
      // The spiffe.* rows (thirty-four as of 2026-09-16), on the page about
      // the trust domain rather than on /admin/config. The two lists below
      // them — the registration entries and the agents — are a STORE and are
      // edited on their own pages; these are the settings that decide what an
      // SVID minted against any entry looks like.
      SettingsForms.forms(json.settingsForms, '/admin/spiffe',
                         undefined, t);
    return inner;
  }

  // A listener row, and the fourth column is WHAT A CALLER HAS TO PRESENT ON
  // IT. Not decoration: the four sockets have three different postures — plain,
  // plain-and-trusted-as-local, and mutual TLS — and a reader who cannot see
  // which is which meets the difference as a handshake failure with no message.
  // The same courtesy /tls says about which port needs verification turned off.
  // **THE REALM IS A COLUMN SINCE 2026-09-12**, and it is the first thing a
  // reader of this table needs: the listeners are per realm now, so two rows
  // with the same surface and different addresses are two TRUST DOMAINS rather
  // than one surface on two transports. A table without it would report four
  // Workload API rows and leave the reader to work out which service they
  // belong to from the port.
  /**
   * Draws one SPIFFE surface's listeners as table rows: realm, address,
   * whether it bound, and what a caller must present.
   *
   * @param t - the page's translator
   * @param bindings - the surface's listener bindings
   * @param what - the surface's name, for the first column (a product name,
   *   drawn as it is)
   * @returns the rows as HTML, or one row saying nothing is bound
   */
  static spiffeListenerRows(t, bindings, what) {
    if (!bindings.length) {
      return '<tr><td colspan="5">' +
        SpiffePage.compose({ what: kit.esc(what) }, function (s) {
          return t.html('consoleSpiffe.nothingBound', s);
        }) + '</td></tr>';
    }
    // `default` is the default realm's name rather than a word, and a
    // bind failure is an error: both are drawn as they are.
    return bindings.map(function (binding) {
      return '<tr><td>' + kit.esc(what) + '</td><td>' +
        kit.esc(binding.realm || 'default') + '</td><td><code>' +
        kit.esc(binding.address) +
        '</code>' +
        (binding.tls ? ' <span class="note">' +
                       t.html('consoleSpiffe.mutualTls') + '</span>' : '') +
        '</td><td>' + (binding.listening ? t.html('consoleSpiffe.listening')
          : '<strong>did not bind</strong> &mdash; ' +
            kit.esc(binding.error)) +
        '</td><td>' + kit.esc(binding.authentication || '') + '</td></tr>';
    }).join('');
  }

  // WORKLOAD ATTESTATION ON THE UNIX SOCKET (#40 phase four): whether the
  // kernel can be asked at all, which attestors run, and each connection
  // open now with what it was attested as.
  /**
   * Draws the Workload API's attestation state: whether the native module
   * is loaded, the TCP port's posture, the attestors and open connections.
   *
   * @param t - the page's translator
   * @param state - the attestation state; optional in effect
   * @returns the section as HTML, or an empty string when there is no state
   */
  static spiffeWorkloadAttestation(t, state) {
    if (!state) {
      return '';
    }
    // `state.problem`, `tcp.state` and `tcp.why` are the view's words.
    const kernel = state.nativeModule
      ? t.html('consoleSpiffe.nativeLoaded')
      : (state.unattestedSocketServed
        ? SpiffePage.compose({ problem: kit.esc(state.problem) },
            function (s) {
              return t.html('consoleSpiffe.nativeMissingUnattested', s);
            })
        : SpiffePage.compose({ problem: kit.esc(state.problem) },
            function (s) {
              return t.html('consoleSpiffe.nativeMissingNotServed', s);
            }));
    // THE TCP PORT (#166): what the realm's posture is and whether its port
    // is listening. A product realm serves it only where the network is
    // declared to authenticate source addresses, on a named address.
    const tcp = state.tcp || null;
    const tcpLine = tcp
      ? ' ' + SpiffePage.compose({
          state: kit.esc(tcp.state),
          where: tcp.port
            ? ' (' + kit.esc(tcp.host + ':' + tcp.port) + ', ' +
              (tcp.listening ? t.html('consoleSpiffe.listening')
                             : t.html('consoleSpiffe.notListening')) + ')'
            : '',
          why: kit.esc(tcp.why) },
        function (s) {
          return t.html('consoleSpiffe.tcpPort', s);
        })
      : '';
    const out = '<h2>' + t.html('consoleSpiffe.workloadAttestation') +
      '</h2>' + kit.note(kernel +
      tcpLine + ' ' +
      SpiffePage.compose({
          unknown: state.unknownConfigured.length
            ? SpiffePage.compose({
                names: state.unknownConfigured.map(function (name) {
                  return '<code>' + kit.esc(name) + '</code>';
                }).join(', ') },
                function (s) {
                  return t.html('consoleSpiffe.attestorsUnknown', s);
                })
            : '' },
        function (s) {
          return t.html('consoleSpiffe.attestorsWhich', s);
        })) +
      '<table><tr><th>' + t.html('consoleSpiffe.attestor') + '</th><th>' +
      t.html('consoleSpiffe.runs') + '</th><th>' +
      t.html('consoleSpiffe.whatItVerifies') + '</th>' +
      '</tr>' + state.attestors.map(function (a) {
        return '<tr><td><code>' + kit.esc(a.type) + '</code></td><td>' +
          (a.enabled ? t.html('consoleSpiffe.yes')
                     : t.html('consoleSpiffe.no')) + '</td><td>' +
          kit.esc(a.verifies) +
          '</td></tr>';
      }).join('') + '</table>' +
      (state.connections.length
        ? '<table><tr><th>' + t.html('consoleSpiffe.connection') +
          '</th><th>pid</th><th>uid</th>' +
          '<th>gid</th><th>' + t.html('consoleSpiffe.selectors') +
          '</th><th>' + t.html('consoleSpiffe.state') + '</th></tr>' +
          state.connections.map(function (c) {
            // A refusal stays English; a note is the view's.
            return '<tr><td><code>' + kit.esc(c.tag) + '</code></td><td>' +
              kit.esc(String(c.pid)) + '</td><td>' + kit.esc(String(c.uid)) +
              '</td><td>' + kit.esc(String(c.gid)) + '</td><td>' +
              kit.esc(String(c.selectors)) + '</td><td>' +
              kit.esc(c.error ? 'refused: ' + c.error
                               : (c.note ||
                                  t.text('consoleSpiffe.attested'))) +
              '</td></tr>';
          }).join('') + '</table>'
        : kit.note(t.html('consoleSpiffe.noConnection')));
    return out;
  }
}

export = SpiffePage;
