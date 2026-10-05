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

/**
 * Draws SPIFFE's console pages — the registration entries, the attested agents
 * and the brokers, and their drill-downs — from the answers of `GET
 * /admin-api/spiffe/*`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SpiffePage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static entries(ctx, json) {
    const listView = kit.listViewOf('/admin/spiffe/entries', ctx.query);
    const rows = json.entries.map(function (entry) {
      return '<tr><td><a href="/admin/spiffe/entries' +
        kit.queryWith(listView, { entry: entry.id }) + '"><code>' +
        kit.esc(entry.spiffeId) + '</code></a>' +
        (entry.expired ? ' <strong>(expired)</strong>' : '') +
        '<br><span class="note"><code>' + kit.esc(entry.id) +
        '</code></span></td>' +
        '<td>' + kit.esc(entry.selectorTexts.join(', ') ||
                          '(none — matches every workload)') + '</td>' +
        '<td>' + kit.esc(entry.origin) + '</td>' +
        '<td>' + kit.esc(entry.hint || '—') + '</td>' +
        '<td>' + entry.svidsIssued + '</td>' +
        '<td>rev ' + entry.revisionNumber + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="6">No registration entry matches.</td></tr>';
    const originOptions = ['<option value="">every origin</option>'].concat(
      json.origins.map(function (name) {
        return '<option value="' + kit.esc(name) + '"' +
          (json.filter.origin === name ? ' selected' : '') + '>' +
          kit.esc(name) +
          '</option>';
      })).join('');
    const inner = SpiffePage.spiffePostureNote(json.serverApiAuthenticated) +
      kit.note(kit.esc(json.total) + ' registration entry/entries, of at ' +
        'most ' +
      kit.esc(json.max) + ' (<code>spiffe.maxEntries</code>). The store is ' +
      'the embedded directory under <code>' + kit.esc(json.container) +
      '</code>: an <code>ldapmodify</code> there, a form here and the SPIRE ' +
      'Server API\'s <code>BatchUpdateEntry</code> are three doors onto one ' +
      'entry, and nothing caches it &mdash; so a change takes effect on the ' +
      'next SVID.') +
      '<form method="get" action="/admin/spiffe/entries"><div ' +
      'class="formrow"><label for="q">Search</label>' +
      '<input id="q" name="q" value="' + kit.esc(json.filter.q) +
      '" size="28" ' +
      'placeholder="a SPIFFE ID, a selector, an entry id">' +
      '<label for="origin">Origin</label>' +
      '<select id="origin" name="origin">' + originOptions + '</select>' +
      '<label for="per">Rows</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(json.paging.perPage) +
      '</select><button class="secondary">Filter</button>' +
      kit.note('Origin is how the entry got here: <code>seed</code> ' +
      'at startup, <code>console</code>, <code>api</code>, ' +
      '<code>grpc</code>, <code>auto</code> (invented for a workload that ' +
      'matched nothing) or <code>ldap</code>.') +
      '</div></form><table><tr><th>SPIFFE ID / entry ' +
      'id</th><th>Selectors</th><th>Origin</th><th>Hint</th><th>SVIDs</th>' +
      '<th>' +
      'Revision</th></tr>' + rows + '</table>' +
      kit.pageNavPair('/admin/spiffe/entries', kit.filterOnly(listView),
                       json.paging).head +
      SpiffePage.spiffeCreateEntryForm(json.trustDomain);
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
   * @param enforced - whether the SPIRE Server API authenticates its
   *   callers (`spiffeAuth.authRequired()`)
   * @returns the two notes as HTML
   */
  static spiffePostureNote(enforced) {
    return kit.warn('<strong>Nothing here is attested.</strong> A real ' +
      'SPIFFE agent reads the peer credentials of its socket — pid, uid, ' +
      'gid, and from those the executable, the container, the pod — and ' +
      'hands a workload only the identities those selectors match. Node ' +
      'cannot read them at all, so this service identifies a Workload API ' +
      'caller by the transport it arrived on, the endpoint it reached and ' +
      'its peer address, and nothing else. Those DO now decide which entries ' +
      'answer (<code>spiffe.attestWorkloads</code>), and they prove nothing ' +
      'about who is calling: anybody who can reach the socket can still get ' +
      'an identity. Node attestation is not: an agent below attested with a ' +
      'type its realm accepts and an attestor here verified, or it was ' +
      'refused.') +
      '<div class="' + (enforced ? 'note' : 'warn') + '">' +
      (enforced
        ? '<strong>The SPIRE Server API is the exception.</strong> Its TCP ' +
          'port is mutual TLS: a caller presents an X509-SVID from this ' +
          'trust domain, and every method is authorized against SPIRE\'s own ' +
          'table — so an entry marked <code>admin</code> or ' +
          '<code>downstream</code> below now decides what its holder may do. ' +
          'Its Unix socket is the <code>local</code> entity and needs no ' +
          'credential. The Workload API is deliberately untouched: its ' +
          'specification says a client MUST NOT be required to authenticate.'
        : '<strong>And nobody is authenticated on the SPIRE Server API ' +
          'either.</strong> That port is plain gRPC, any caller can create a ' +
          'registration entry granting any identity here and then collect an ' +
          'SVID for it, and the <code>admin</code> and ' +
          '<code>downstream</code> flags below are recorded and read by ' +
          'nothing. It is restart-only, because it decides how the socket is ' +
          'bound.') +
      ' <a href="/spiffe">GET /spiffe</a> has the whole table and the full ' +
      'list of what is and is not checked.</div>';
  }

  /**
   * Draws the form that creates a SPIFFE registration entry.
   *
   * @param trustDomain - the realm's trust domain, for the placeholder
   * @returns the form as HTML
   */
  static spiffeCreateEntryForm(trustDomain) {
    return '<h2>Create a registration entry</h2>' +
      kit.note('The SPIFFE ID must be in this trust domain and outside the ' +
      'reserved <code>/spire</code> path &mdash; those two refusals are the ' +
      'whole of what is checked. The parent defaults to this server\'s own ' +
      'identity, which is what SPIRE uses for an entry describing a workload ' +
      'rather than a node.') +
      '<form method="post" action="/admin/spiffe/entries"><div ' +
      'class="formrow"><input type="hidden" name="action" value="create">' +
      '<label for="e-id">SPIFFE ID</label>' +
      '<input id="e-id" name="spiffeId" size="40" placeholder="spiffe://' +
      kit.esc(trustDomain) + '/ns/default/sa/web"><label ' +
      'for="e-parent">Parent</label><input id="e-parent" name="parentId" ' +
      'size="34" placeholder="(this server)"></div><div ' +
      'class="formrow"><label for="e-sel">Selectors</label><input id="e-sel" ' +
      'name="selectors" size="40" placeholder="unix:uid:1000, ' +
      'k8s:ns:default"><label for="e-dns">DNS names</label><input id="e-dns" ' +
      'name="dnsNames" size="26" placeholder="web.default.svc"></div><div ' +
      'class="formrow"><label for="e-x509ttl">X509-SVID TTL</label><input ' +
      'id="e-x509ttl" name="x509SvidTtl" size="6" placeholder="3600"><label ' +
      'for="e-jwtttl">JWT-SVID TTL</label><input id="e-jwtttl" ' +
      'name="jwtSvidTtl" size="6" placeholder="300"><label ' +
      'for="e-hint">Hint</label><input id="e-hint" name="hint" size="12" ' +
      'placeholder="internal"><label for="e-fed">Federates ' +
      'with</label><input id="e-fed" name="federatesWith" size="20" ' +
      'placeholder="other.example"><button>Create</button>' +
      kit.note('Selectors, DNS names and trust domains are ' +
      'comma-separated. A selector is <code>type:value</code>, split on the ' +
      'FIRST colon only &mdash; so <code>docker:label:app:web</code> is type ' +
      '<code>docker</code>.') + '</div></form>';
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static agents(ctx, json) {
    const listView = kit.listViewOf('/admin/spiffe/agents', ctx.query);
    const rows = json.agents.map(function (agent) {
      return '<tr><td><a href="/admin/spiffe/agents' +
        kit.queryWith(listView, { agent: agent.id }) + '"><code>' +
        kit.esc(agent.id) + '</code></a></td>' +
        '<td>' + kit.esc(agent.attestationType) + '</td>' +
        '<td>' + (agent.banned ? '<strong>banned</strong>' : 'active') +
        '</td><td>' + agent.attestations + '</td>' +
        '<td>' + kit.esc(agent.lastSeen || '—') + '</td></tr>';
    }).join('') || '<tr><td colspan="5">No agent has attested here. An agent ' +
      'appears when it calls <code>AttestAgent</code> on the SPIRE Server ' +
      'API.</td></tr>';
    const inner = SpiffePage.spiffePostureNote(json.serverApiAuthenticated) +
      kit.note(kit.esc(json.total) + ' agent(s), of at most ' +
                kit.esc(json.max) +
      ' (<code>spiffe.maxAgents</code>). These entries are a RECORD rather ' +
      'than configuration &mdash; everything on them was written by this ' +
      'service when an agent attested &mdash; which is why nothing about an ' +
      'agent is editable and only the ban is.') +
      kit.note('<strong>Node attestation is verified or refused.</strong> ' +
      'An agent here attested with a type its realm names in ' +
      '<code>spiffe.nodeAttestors</code> and an attestor verified, and its ' +
      'selectors are the ones that attestor derived.') +
      '<form method="get" action="/admin/spiffe/agents"><div class="formrow">' +
      '<label for="q">Search</label>' +
      '<input id="q" name="q" value="' + kit.esc(json.filter.q) +
      '" size="30" placeholder="an agent id, an attestor, a selector"><label ' +
      'for="per">Rows</label><select id="per" name="per">' +
      kit.perPageOptions(json.paging.perPage) +
      '</select><button class="secondary">Filter</button></div></form>' +
      '<table><tr><th>Agent</th><th>Attestor</th><th>State</th>' +
      '<th>Attestations</th><th>Last seen</th></tr>' + rows + '</table>' +
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
    const listView = kit.listViewOf('/admin/spiffe/brokers', ctx.query);
    const back = '<input type="hidden" name="back" value="' +
                 kit.esc(kit.queryWith(listView, {})) + '">';
    const rows = json.brokers.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.id) + '</code></td><td>' +
        (one.problem ? '<strong>refused:</strong> ' + kit.esc(one.problem)
                     : kit.esc(one.referenceTypes.join(', '))) +
        '</td><td><form method="post" action="/admin/spiffe/brokers">' +
        '<input type="hidden" name="action" value="remove"><input ' +
        'type="hidden" name="id" value="' + kit.esc(one.id) + '">' + back +
        '<button class="danger">Remove</button></form></td></tr>';
    }).join('') || '<tr><td colspan="3">No broker is authorized, so every ' +
      'call to the SPIFFE Broker API is refused PERMISSION_DENIED.</td></tr>';
    const listening = json.listeners.filter(function (b) {
      return b.listening;
    }).map(function (b) {
      return '<code>' + kit.esc(b.address) + '</code>';
    }).join(', ');
    const inner = kit.note('The SPIFFE Broker API (Incubating) lets a ' +
      'trusted ' +
      'infrastructure component ask for the SVIDs of a workload it ' +
      'REFERENCES — a process id, or a Kubernetes pod — which this service ' +
      'attests itself before answering. It is served with mutual TLS on ' +
      '<code>spiffe.grpcHost</code> and <code>spiffe.brokerPort</code> (' +
      (listening ? 'listening on ' + listening
                 : 'not listening in this realm: <code>spiffe.brokerPort' +
                   '</code> is ' + kit.esc(json.port)) + '). A caller ' +
      'presents an X509-SVID, and one whose SPIFFE ID is not listed here is ' +
      'refused.') +
      kit.note('<strong>A process id means something only on the node it ' +
      'was read on.</strong> The endpoint is TCP, so allow ' +
      '<code>pid</code> only to a broker running on this host; ' +
      '<code>k8s</code> resolves a pod in this node\'s kubelet pod list.') +
      '<form method="get" action="/admin/spiffe/brokers"><div ' +
      'class="formrow"><label for="q">Search</label><input id="q" name="q" ' +
      'value="' + kit.esc(json.filter.q) + '" size="30" placeholder="a ' +
      'SPIFFE ID or a reference type"><label for="per">Rows</label><select ' +
      'id="per" name="per">' + kit.perPageOptions(json.paging.perPage) +
      '</select><button class="secondary">Filter</button></div></form>' +
      '<table><tr><th>Broker</th><th>May reference</th><th></th></tr>' +
      rows + '</table>' +
      kit.pageNavPair('/admin/spiffe/brokers', kit.filterOnly(listView),
                       json.paging).head +
      '<h2>Authorize a broker</h2>' +
      '<form method="post" action="/admin/spiffe/brokers"><div ' +
      'class="formrow"><input type="hidden" name="action" value="set">' +
      back + '<label for="b-id">SPIFFE ID</label><input id="b-id" name="id" ' +
      'size="44" placeholder="spiffe://' + kit.esc(json.trustDomain) +
      '/ns/mesh/sa/node-proxy"></div><div class="formrow"><label><input ' +
      'type="checkbox" name="referenceTypes" value="pid"> pid ' +
      '(WorkloadPIDReference)</label><label><input type="checkbox" ' +
      'name="referenceTypes" value="k8s"> k8s (a pod)</label><label><input ' +
      'type="checkbox" name="referenceTypes" value="*"> * (both)</label>' +
      '<button>Save</button>' +
      kit.note('A broker already listed has its reference types replaced. ' +
      'An ID from a federated trust domain is verified against that ' +
      'domain\'s bundle.') + '</div></form>';
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
    const entry = json.found ? json.entry : null;
    const listView = kit.listViewOf('/admin/spiffe/entries', ctx.query);
    const back = kit.queryWith(listView, {});
    let inner;
    if (!entry) {
      inner = kit.note('No registration entry has the id <code>' +
                           kit.esc(json.id) +
                 '</code>. It may have been deleted &mdash; from this page, ' +
                 'with <code>BatchDeleteEntry</code>, or with an ' +
                 '<code>ldapdelete</code> under ' +
                 '<code>ou=entries,ou=spiffe</code>, which are three doors ' +
                 'onto one store.') +
                 '<p><a href="/admin/spiffe/entries' + kit.esc(back) +
                 '">Back to the entries</a>.</p>';
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
      inner = SpiffePage.spiffePostureNote(json.serverApiAuthenticated) +
        '<h2><code>' + kit.esc(entry.spiffeId) + '</code></h2>' +
        kit.note('Entry <code>' + kit.esc(entry.id) + '</code>, revision ' +
        kit.esc(entry.revisionNumber) + ', created by <code>' +
        kit.esc(entry.origin) +
        '</code>. It lives at <code>' + kit.esc(entry.dn) + '</code>' +
        (entry.expired ? ' and <strong>has expired</strong> &mdash; it is ' +
          'kept ' +
          'and reported rather than deleted, because an entry that vanished ' +
            'is ' +
          'indistinguishable from one nobody created' : '') + '.') +
        '<table><tr><th>Field</th><th>Value</th></tr>' +
        '<tr><td>Parent</td><td><code>' + kit.esc(entry.parentId) +
        '</code></td></tr><tr><td>Selectors</td><td>' +
        kit.esc(entry.selectorTexts.join(', ') ||
                 '(none — this entry matches every workload)') + '</td></tr>' +
        '<tr><td>DNS names</td><td>' +
        kit.esc(entry.dnsNames.join(', ') || '—') +
        '</td></tr>' +
        '<tr><td>Federates with</td><td>' +
        kit.esc(entry.federatesWith.join(', ') || '—') + '</td></tr>' +
        '<tr><td>X509-SVID TTL</td><td>' +
        (entry.x509SvidTtl ||
         ('default (' + kit.esc(json.defaults.x509SvidTtl) + ')')) +
        '</td></tr>' +
        '<tr><td>JWT-SVID TTL</td><td>' +
        (entry.jwtSvidTtl ||
         ('default (' + kit.esc(json.defaults.jwtSvidTtl) + ')')) +
        '</td></tr>' +
        '<tr><td>Hint</td><td>' + kit.esc(entry.hint || '—') + '</td></tr>' +
        '<tr><td>admin / downstream / storeSvid</td><td>' +
        (entry.admin ? 'admin' : '') + (entry.downstream ? ' downstream' : '') +
        (entry.storeSvid ? ' storeSvid' : '') +
        ((entry.admin || entry.downstream || entry.storeSvid) ? '' : '—') +
        ' <span class="note">recorded and never read &mdash; nothing here ' +
        'decides anything on one</span></td></tr><tr><td>SVIDs ' +
        'issued</td><td>' + entry.svidsIssued +
        (entry.lastSvidAt ? ', most recently ' + kit.esc(entry.lastSvidAt) :
         '') +
        '</td></tr></table>' +

        '<h3>Change it</h3>' +
        kit.note('Only the DECLARED half is editable here &mdash; what the ' +
        'entry may DO. The derived half (the revision number, the SVID ' +
        'counter, when it was created) is what HAPPENED, and a form that ' +
          'could ' +
        'rewrite it would make this page lie about the service\'s own ' +
        'behaviour. <code>ldapmodify</code> reaches everything: refusing it ' +
        'here is the difference between offering an operation and merely not ' +
        'preventing it.') +
        '<form method="post" action="/admin/spiffe/entries"><div ' +
        'class="formrow"><input type="hidden" name="action" value="update">' +
        carried +
        '<label for="u-field">Field</label>' +
        '<select id="u-field" name="field">' +
        ['spiffeId', 'parentId', 'selectors', 'dnsNames', 'federatesWith',
         'x509SvidTtl', 'jwtSvidTtl', 'hint', 'expiresAt', 'admin',
           'downstream',
         'storeSvid'].map(function (name) {
          return '<option value="' + kit.esc(name) + '">' + kit.esc(name) +
                 '</option>';
        }).join('') + '</select>' +
        '<label for="u-value">Value</label>' +
        '<input id="u-value" name="value" size="40">' +
        '<button>Set</button>' +
        '<span class="note">A list field takes comma-separated values and an ' +
        'empty value clears it. A boolean takes true or false.</span>' +
        '</div></form>' +
        '<form method="post" action="/admin/spiffe/entries"><div ' +
        'class="formrow"><input type="hidden" name="action" value="delete">' +
        carried +
        '<button class="danger">Delete this entry</button>' +
        kit.note('Whatever holds an SVID minted from it keeps that SVID ' +
          'until ' +
        'it expires. SPIFFE has no revocation &mdash; the answer is a short ' +
        'lifetime, which is why the default is an hour.') + '</div></form>' +

        '<h3>The directory entry</h3>' +
        '<p>Every attribute, operational ones included. This is the store ' +
        'rather than a description of it.</p>' +
        '<table><tr><th>Attribute</th><th>Value</th></tr>' + attributeRows +
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
    const agent = json.found ? json.agent : null;
    const listView = kit.listViewOf('/admin/spiffe/agents', ctx.query);
    const back = kit.queryWith(listView, {});
    let inner;
    if (!agent) {
      inner = '<p>No agent has attested here as <code>' +
                 kit.esc(json.id) +
                 '</code>.</p><p><a href="/admin/spiffe/agents' +
                 kit.esc(back) +
                 '">Back to the agents</a>.</p>';
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
      inner = SpiffePage.spiffePostureNote(json.serverApiAuthenticated) +
        '<h2><code>' + kit.esc(agent.id) + '</code></h2>' +
        kit.note('Attested with <code>' + kit.esc(agent.attestationType) +
                  '</code>, ' +
        kit.esc(agent.attestations) + ' time(s), first at ' +
        kit.esc(agent.firstSeen) +
        ' and most recently at ' + kit.esc(agent.lastSeen) + '. It lives at ' +
          '<code>' +
        kit.esc(agent.dn) + '</code> &mdash; the RDN is a digest of the ' +
        'SPIFFE ID, because a SPIFFE ID is too long for a readable one, so ' +
        '<strong>the cn is not the identity here</strong>: ' +
        '<code>spiffeAgentId</code> is.') +
        '<table><tr><th>Field</th><th>Value</th></tr>' +
        '<tr><td>State</td><td>' + (agent.banned
          ? '<strong>banned</strong> — AttestAgent refuses it, which is one ' +
            'of ' +
            'the few refusals in this service and is what keeps the button ' +
            'below from being a lie'
          : 'active') + '</td></tr>' +
        '<tr><td>Its directory entry</td><td>' +
        'Every identity this trust domain issues an X509-SVID to has one ' +
          'under ' +
        '<code>ou=users</code>, carrying the current certificate as the same ' +
        'six <code>x509*</code> attributes a verified TLS client certificate ' +
        'writes. Banning or deleting this agent marks that entry ' +
        '<code>spiffeCredentialStatus: revoked</code> and never removes it; ' +
        'unbanning marks it active again. <span class="note">That is not a ' +
        'certificate status. SPIFFE has no revocation, nothing reads the ' +
          'flag ' +
        'back, and whatever SVID this agent holds keeps working until it ' +
        'expires.</span></td></tr>' +
        '<tr><td>Can reattest</td><td>' + (agent.canReattest ? 'yes' : 'no') +
        '</td></tr>' +
        '<tr><td>Selectors</td><td>' +
        kit.esc(agent.selectorTexts.join(', ') || '—') +
        ' <span class="note">claimed, never verified</span></td></tr>' +
        '<tr><td>SVID</td><td>' + kit.esc(agent.svidHash || '—') +
        (agent.expiresAt ? ', expires ' +
          kit.esc(new Date(agent.expiresAt * 1000).toISOString()) : '') +
        '</td></tr></table>' +
        '<form method="post" action="/admin/spiffe/agents"><div ' +
        'class="formrow"><input type="hidden" name="action" value="' +
        (agent.banned ? 'unban' : 'ban') + '">' + carried +
        '<button class="' + (agent.banned ? 'secondary' : 'danger') + '">' +
        (agent.banned ? 'Unban' : 'Ban') + ' this agent</button>' +
        kit.note('A banned agent is refused at <code>AttestAgent</code> with ' +
        '<code>PermissionDenied</code>. Whatever SVID it already holds keeps ' +
        'working until it expires &mdash; there is no revocation in SPIFFE.') +
        '</div></form>' +
        '<form method="post" action="/admin/spiffe/agents"><div ' +
        'class="formrow"><input type="hidden" name="action" value="delete">' +
        carried +
        '<button class="danger">Delete this agent</button>' +
        kit.note('It reappears the next time it attests, because ' +
        'attestation is not checked &mdash; deleting is forgetting, not ' +
        'revoking.') + '</div></form>' +
        '<h3>The directory entry</h3>' +
        '<table><tr><th>Attribute</th><th>Value</th></tr>' + attributeRows +
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
    const state = json.authorityState;
    const x509Rows = state.x509Authorities.map(function (authority) {
      return '<tr><td><code>' + kit.esc(authority.id) + '</code></td><td>' +
        (authority.active ? '<strong>active</strong>' :
         'retired, still published') +
        '</td><td>' + kit.esc(authority.keyType) + '</td><td>' +
        kit.esc(authority.notAfter) + '</td><td><code>' +
        kit.esc(authority.subject) +
        '</code></td></tr>';
    }).join('');
    const jwtRows = state.jwtAuthorities.map(function (authority) {
      return '<tr><td><code>' + kit.esc(authority.id) + '</code></td><td>' +
        (authority.active ? '<strong>active</strong>' :
         'retired, still published') +
        '</td><td>' + kit.esc(authority.keyType) + ' / ' +
        kit.esc(authority.alg) +
        '</td><td>' + kit.esc(new Date(authority.createdAt).toISOString()) +
        '</td><td>&mdash;</td></tr>';
    }).join('');
    const federatedRows = state.federated.map(function (entry) {
      return '<tr><td><code>' + kit.esc(entry.trustDomainId) +
             '</code></td><td>' +
        entry.x509Keys + ' x509, ' + entry.jwtKeys + ' jwt</td><td>' +
        kit.esc(entry.bundleEndpointProfile) + '<br><span class="note">' +
        kit.esc(entry.bundleEndpointUrl || '(no endpoint URL recorded)') +
        '</span></td><td>' + kit.esc(entry.sequence) + '</td><td>' +
        '<form method="post" action="/admin/spiffe" class="inline">' +
        '<input type="hidden" name="action" value="federation-remove">' +
        '<input type="hidden" name="trustDomain" value="' +
        kit.esc(entry.trustDomain) + '"><button ' +
        'class="danger">Remove</button></form> <a ' +
        'href="/spiffe/federated/' + encodeURIComponent(entry.trustDomain) +
        '">document</a></td></tr>';
    }).join('') ||
      '<tr><td colspan="5">None. This trust domain federates with ' +
      'nobody.</td></tr>';

    const inner = SpiffePage.spiffePostureNote(json.serverApiAuthenticated) +
      (json.enabled ? '' : kit.warn('SPIFFE is turned OFF ' +
        '(<code>spiffe.enabled</code>): the bundle endpoint answers 404 and ' +
        'every gRPC call is refused with <code>Unavailable</code>. Turn it ' +
        'back on in the settings at the foot of this page; it needs no ' +
        'restart.')) +
      (json.ready ? '' : kit.warn((json.error
        ? 'The issuing authority could not be built, so nothing here will ' +
          'issue an SVID: ' + kit.esc(json.error)
        : 'The issuing authority is still being generated &mdash; an ' +
          'RSA-4096 key takes a few seconds. Reload.'))) +

      '<h2>The trust domain</h2>' +
      kit.note('This service is the issuing authority for <code>' +
      kit.esc(json.trustDomainId) + '</code>. Its own identity as a SPIFFE ' +
      'server is <code>' + kit.esc(json.serverId || '(not yet)') +
      '</code>, and every ' +
      'registration entry hangs beneath that by default. The trust domain is ' +
      'restart-only (<code>spiffe.trustDomain</code>): every authority ' +
      'certificate names it.') +
      kit.note('The bundle is published at <a href="' +
                kit.esc(json.bundle.path) +
      '"><code>' + kit.esc(json.bundle.path) +
      '</code></a> &mdash; sequence <code>' +
      kit.esc(json.bundle.sequence) + '</code>, refresh hint ' +
      kit.esc(json.bundle.refreshHint) + ' seconds. The sequence changes ' +
      'whenever the bundle does and never otherwise, which is what lets a ' +
      'consumer tell &ldquo;I have the current bundle&rdquo; from &ldquo;I ' +
      'have a bundle&rdquo;.') +

      '<h2>Authorities</h2>' +
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
        ? kit.note('The X.509 authority is this realm\'s <strong>SPIFFE ' +
          'Issuing CA</strong>, under this service\'s own Root &mdash; ' +
          '<a href="/admin/pki">manage it on the PKI page</a>, where it is ' +
          'one of the Issuing CAs in this realm\'s branch. So the trust ' +
          'anchor a consumer installs is the <strong>Root</strong>, which ' +
          'every realm shares and which also covers LDAPS 636, the main port ' +
          'and every token this service signs: one anchor, installed once. ' +
          'An X509-SVID carries the Issuing CA and this realm\'s ' +
          'Intermediate in its own chain' +
          (json.authorities.chainSubjects.length
            ? ' (' + json.authorities.chainSubjects.map(function (subject) {
                return '<code>' + kit.esc(subject) + '</code>';
              }).join(' &rarr; ') + ')'
            : '') + '. <strong>Rotating it re-issues that Issuing CA and ' +
          'leaves the anchor alone</strong>, so the bundle does not change, ' +
          'nothing has to be re-fetched, and SVIDs minted under the old ' +
          'authority go on verifying &mdash; which is the whole difference ' +
          'from the self-signed arrangement this replaced. The JWT authority ' +
          'has no certificate and no hierarchy to hang from: it is generated ' +
          'per start and rotating it still prepends, keeping at most ' +
          kit.esc(json.authorities.maxRetained) + '.')
        : kit.warn('This realm has <strong>no certificate ' +
          'authority</strong>, so its X.509 authority is ' +
          '<strong>self-signed</strong> and IS the trust anchor &mdash; ' +
          'generated per start and held in memory, exactly like the STS ' +
          'signing key and the TLS certificate, so a workload holding a ' +
          'bundle from before a restart will fail to verify every SVID ' +
          'minted after it. Rotating PREPENDS a new authority and keeps the ' +
          'old one published: an SVID minted a minute ago has to go on ' +
          'verifying, which is what a bundle is for. At most ' +
          kit.esc(json.authorities.maxRetained) + ' are retained, and past ' +
          'that the oldest is dropped &mdash; anything it signed stops ' +
          'verifying at that moment. <a href="/admin/pki">Build this ' +
          'realm\'s certificate authority</a> to put the SPIFFE authority ' +
          'under this service\'s Root instead.')) +
      '<table><tr><th>Id</th><th>State</th><th>Key</th><th>Until</th>' +
      '<th>Subject</th></tr>' + x509Rows + jwtRows + '</table>' +
      // **WHAT SIGNS AND WHAT IS TRUSTED ARE TWO TABLES.** They were one, and
      // could be, while a self-signed authority was both. See `/spiffe`'s own
      // version of this note.
      '<h3>What a consumer trusts</h3>' +
      '<table><tr><th>Anchor</th><th>Subject</th><th>Until</th></tr>' +
      (json.authorities.trustAnchors || []).map(function (anchor) {
        return '<tr><td><code>' + kit.esc(anchor.id) +
               '</code></td><td><code>' +
          kit.esc(anchor.subject) + '</code></td><td>' +
          kit.esc(anchor.notAfter) +
          '</td></tr>';
      }).join('') + '</table>' +
      '<form method="post" action="/admin/spiffe"><div class="formrow">' +
      '<input type="hidden" name="action" value="rotate">' +
      '<label for="which">Rotate</label>' +
      '<select id="which" name="which">' +
      '<option value="x509">the X.509 authority</option>' +
      '<option value="jwt">the JWT authority</option>' +
      '<option value="both">both</option></select>' +
      '<button>Rotate</button>' +
      '<span class="note">New SVIDs are signed with the new authority ' +
      'immediately; existing ones keep verifying until they expire.</span>' +
      '</div></form>' +

      '<h2>The gRPC listeners</h2>' +
      kit.note('Neither <code>/admin/sts-metadata</code> nor this page can ' +
      'see a socket, so this table is the only place that reports whether ' +
      'each one actually bound. The DEFAULT realm\'s four are bound when the ' +
      'process starts and stay bound with <code>spiffe.enabled</code> off — ' +
      'they answer <code>Unavailable</code>, because a socket that vanished ' +
      'would read as a service that had stopped. EVERY OTHER REALM\'S are ' +
      'bound when <code>spiffe.enabled</code> is turned on for it, on the ' +
      'address <code>spiffe.grpcHost</code> names for that realm — the ' +
      'endpoint address is the only thing a SPIFFE client has to name a ' +
      'tenant with, because the gRPC method name is fixed by the ' +
      'specification.') +
      '<table><tr><th>Surface</th><th>Realm</th><th>Address</th><th>State' +
      '</th>' +
      '<th>What a caller presents</th></tr>' +
      SpiffePage.spiffeListenerRows(json.listeners.workloadApi,
        'Workload API') +
      SpiffePage.spiffeListenerRows(json.listeners.serverApi,
        'SPIRE Server API') +
      SpiffePage.spiffeListenerRows(json.listeners.brokerApi || [],
                              'SPIFFE Broker API') +
      '</table>' +

      SpiffePage.spiffeWorkloadAttestation(json.workloadAttestation) +

      '<h2>Who may call the SPIRE Server API</h2>' +
      '<p>' + kit.esc(json.authentication.what || '') + '</p>' +
      kit.note('A caller may be several of these at once and the check asks ' +
      'whether it is <em>any</em> of the ones a method allows, which is what ' +
      'SPIRE\'s own policy does: the <code>spire-server</code> CLI on this ' +
      'host is <code>local</code>, and an agent that also holds an entry ' +
      'marked <code>admin</code> is both.') +
      '<table><tr><th>Entity</th><th>What it means</th></tr>' +
      json.authentication.entities.map(function (entity) {
        return '<tr><td><code>' + kit.esc(entity.id) + '</code></td><td>' +
          kit.esc(entity.what) + '</td></tr>';
      }).join('') + '</table>' +
      kit.note('Administrators by configuration ' +
      '(<code>spiffe.adminIds</code>, in the ' +
      'settings at the foot of this page): ' +
      (json.authentication.adminIds.length
        ? json.authentication.adminIds.map(function (id) {
            return '<code>' + kit.esc(id) + '</code>';
          }).join(', ') + '. '
        : 'none. ') +
      'The other way to make one is to mark a registration entry ' +
      '<code>admin</code> on <a href="/admin/spiffe/entries">the entries ' +
      'page</a>; SPIRE has both, and neither is cached, so either takes ' +
      'effect on the next call.') +
      kit.note('Workload API selectors: a caller there is identified as ' +
      '<code>transport:</code>, <code>endpoint:</code>, ' +
      '<code>peer:</code> over TCP, and on the Unix socket by what the ' +
      'workload attestors established (above), and ' +
      (json.authentication.attestWorkloads
        ? 'those decide which entries answer it ' +
          '(<code>spiffe.attestWorkloads</code>).'
        : 'that decides nothing at the moment &mdash; ' +
          '<code>spiffe.attestWorkloads</code> is off, so every caller is ' +
          'answered with every entry.') +
      ' Asserted selectors (<code>' +
      kit.esc(json.authentication.assertedSelectorHeader) + '</code>) are ' +
      (json.authentication.acceptAssertedSelectors
        ? '<strong>believed</strong>, and nothing verifies them.'
        : 'ignored (<code>spiffe.acceptAssertedSelectors</code> is off, ' +
          'or this realm is in product mode, where it is never in force).') +
      ' Both switches are what is IN FORCE: in product mode ' +
      '<code>spiffe.attestWorkloads</code> is always on and asserted ' +
      'selectors are never believed, whatever is stored, and neither can ' +
      'be changed to the looser value there.') +
      '<h3>The per-method table</h3>' +
      kit.note('Copied from SPIRE\'s own <code>policy_data.json</code> ' +
      'rather than reasoned out: a table derived from what each method ' +
      '&ldquo;obviously&rdquo; needs disagrees with SPIRE in two or three ' +
      'places, and the client author who meets the disagreement cannot tell ' +
      'which end is wrong. <code>any</code> means the method is open here ' +
      'and in a real server too &mdash; <code>AttestAgent</code> because an ' +
      'agent has no SVID until that call gives it one, ' +
      '<code>GetBundle</code> because a trust bundle is public.') +
      '<table><tr><th>Method</th><th>Allowed to</th></tr>' +
      json.authentication.policy.map(function (row) {
        return '<tr><td><code>' + kit.esc(row.method) + '</code></td><td>' +
          kit.esc(row.allow.join(', ')) + '</td></tr>';
      }).join('') + '</table>' +

      '<h2>Federated trust domains</h2>' +
      kit.note('<strong>A foreign bundle is given to this service and never ' +
      'fetched by it.</strong> The federation specification has a bundle ' +
      'endpoint URL in the relationship and a real implementation polls it; ' +
      'this one records the URL and refuses to follow it, because fetching a ' +
      'URL somebody registered in order to obtain a credential-verification ' +
      'key is a server-side request forgery with a citation attached &mdash; ' +
      'the same refusal this service gives WS-Federation\'s ' +
      '<code>wreqptr</code> and a client\'s <code>jwks_uri</code>. Paste the ' +
      'bundle in below, or push it with <code>BatchSetFederatedBundle</code>' +
      '.') +
      '<table><tr><th>Trust domain</th><th>Keys</th><th>Profile / ' +
      'endpoint</th><th>Sequence</th><th></th></tr>' + federatedRows +
      '</table><form ' +
      'method="post" action="/admin/spiffe"><div class="formrow"><input ' +
      'type="hidden" name="action" value="federation-set"><label ' +
      'for="fed-td">Trust domain</label><input id="fed-td" ' +
      'name="trustDomain" placeholder="other.example" size="24"><label ' +
      'for="fed-url">Bundle endpoint URL</label><input id="fed-url" ' +
      'name="bundleEndpointUrl" placeholder="https://other.example/bundle" ' +
      'size="34"><label for="fed-profile">Profile</label><select ' +
      'id="fed-profile" name="bundleEndpointProfile"><option ' +
      'value="https_web">https_web</option><option ' +
      'value="https_spiffe">https_spiffe</option></select></div><div ' +
      'class="formrow"><label for="fed-doc">Bundle document</label><textarea ' +
      'id="fed-doc" name="document" rows="6" cols="80" ' +
      'placeholder=\'{"keys":[{"kty":"EC","use":"x509-svid","x5c":["..."]}],' +
      '"spiffe_sequence":1,"spiffe_refresh_hint":300}\'></textarea><button>' +
      'Set</button>' +
      kit.note('A JWK Set. Every key needs <code>use</code> of ' +
      '<code>x509-svid</code>, <code>jwt-svid</code> or ' +
      '<code>wit-svid</code>: a consumer MUST IGNORE one without it, so a ' +
      'bundle of keys missing that member verifies nothing and reports no ' +
      'error, which is why it is refused here rather than stored.') +
      '</div></form>' +

      '<h2>Elsewhere</h2><ul>' +
      '<li><a href="/admin/spiffe/entries">Registration entries</a> &mdash; ' +
      kit.esc(json.counts.entries) + ' of at most ' +
      kit.esc(json.counts.maxEntries) +
      '</li>' +
      '<li><a href="/admin/spiffe/agents">Attested agents</a> &mdash; ' +
      kit.esc(json.counts.agents) + ' of at most ' +
      kit.esc(json.counts.maxAgents) +
      '</li><li><a href="/admin/spiffe/brokers">SPIFFE Broker API ' +
      'brokers</a> &mdash; who may ask for a referenced workload\'s SVIDs' +
      '</li><li><a href="/spiffe">What this is, and what it does not ' +
      'check</a></li><li><a href="/admin/ldap/spiffe">The containers and ' +
      'their schema</a></li><li><a href="/admin-api/spiffe">The same, over ' +
      'JSON</a></li></ul>' +
      // The spiffe.* rows (thirty-four as of 2026-09-16), on the page about
      // the trust domain rather than on /admin/config. The two lists below
      // them — the registration entries and the agents — are a STORE and are
      // edited on their own pages; these are the settings that decide what an
      // SVID minted against any entry looks like.
      SettingsForms.forms(json.settingsForms, '/admin/spiffe');
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
   * @param bindings - the surface's listener bindings
   * @param what - the surface's name, for the first column
   * @returns the rows as HTML, or one row saying nothing is bound
   */
  static spiffeListenerRows(bindings, what) {
    if (!bindings.length) {
      return '<tr><td colspan="5">Nothing bound for ' + kit.esc(what) + '. ' +
        'Either both transports are off in configuration, or the process has ' +
        'not finished starting.</td></tr>';
    }
    return bindings.map(function (binding) {
      return '<tr><td>' + kit.esc(what) + '</td><td>' +
        kit.esc(binding.realm || 'default') + '</td><td><code>' +
        kit.esc(binding.address) +
        '</code>' +
        (binding.tls ? ' <span class="note">(mutual TLS)</span>' : '') +
        '</td><td>' + (binding.listening ? 'listening'
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
   * @param state - the attestation state; optional in effect
   * @returns the section as HTML, or an empty string when there is no state
   */
  static spiffeWorkloadAttestation(state) {
    if (!state) {
      return '';
    }
    const kernel = state.nativeModule
      ? 'The native module is loaded: each connection to the Workload ' +
        'API\'s Unix socket is attested when it is accepted, and every call ' +
        'on it checks that the process is still the one attested.'
      : (state.unattestedSocketServed
        ? '<strong>The native module is not loaded, so the Unix socket is ' +
          'served UNATTESTED</strong> (development): ' +
          kit.esc(state.problem)
        : '<strong>The native module is not loaded, so the Unix socket is ' +
          'NOT SERVED</strong> (product): ' + kit.esc(state.problem));
    // THE TCP PORT (#166): what the realm's posture is and whether its port
    // is listening. A product realm serves it only where the network is
    // declared to authenticate source addresses, on a named address.
    const tcp = state.tcp || null;
    const tcpLine = tcp
      ? ' The Workload API TCP port is <strong>' + kit.esc(tcp.state) +
        '</strong>' + (tcp.port
          ? ' (' + kit.esc(tcp.host + ':' + tcp.port) + ', ' +
            (tcp.listening ? 'listening' : 'not listening') + ')'
          : '') + ': ' + kit.esc(tcp.why) + '.'
      : '';
    const out = '<h2>Workload attestation</h2>' + kit.note(kernel +
      tcpLine +
      ' A TCP caller is never attested. Which attestors run is ' +
      '<code>spiffe.workloadAttestors</code>' +
      (state.unknownConfigured.length
        ? '; it names ' + state.unknownConfigured.map(function (t) {
            return '<code>' + kit.esc(t) + '</code>';
          }).join(', ') + ', which nothing here implements'
        : '') + '.') +
      '<table><tr><th>Attestor</th><th>Runs</th><th>What it verifies</th>' +
      '</tr>' + state.attestors.map(function (a) {
        return '<tr><td><code>' + kit.esc(a.type) + '</code></td><td>' +
          (a.enabled ? 'yes' : 'no') + '</td><td>' + kit.esc(a.verifies) +
          '</td></tr>';
      }).join('') + '</table>' +
      (state.connections.length
        ? '<table><tr><th>Connection</th><th>pid</th><th>uid</th>' +
          '<th>gid</th><th>Selectors</th><th>State</th></tr>' +
          state.connections.map(function (c) {
            return '<tr><td><code>' + kit.esc(c.tag) + '</code></td><td>' +
              kit.esc(String(c.pid)) + '</td><td>' + kit.esc(String(c.uid)) +
              '</td><td>' + kit.esc(String(c.gid)) + '</td><td>' +
              kit.esc(String(c.selectors)) + '</td><td>' +
              kit.esc(c.error ? 'refused: ' + c.error
                               : (c.note || 'attested')) + '</td></tr>';
          }).join('') + '</table>'
        : kit.note('No connection is open on the socket now.'));
    return out;
  }
}

export = SpiffePage;
