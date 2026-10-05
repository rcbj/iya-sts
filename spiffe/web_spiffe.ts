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
}

export = SpiffePage;
