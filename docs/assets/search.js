// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// The documentation search. It runs in the browser, which is why it has
// no Entering/Leaving pair: there is no service log here. The match
// itself is a function of the index and the query, so a test can require
// this file and call it. The index is <version>/search-index.json,
// written by .github/scripts/docs-search-index.js when the site is built,
// and fetched the first time a reader searches that version.
(function (factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  if (typeof document !== 'undefined') {
    api.boot();
  }
})(function () {
  function termsOf(query) {
    var parts = String(query || '').toLowerCase().trim().split(/\s+/);
    var out = [];
    var seen = {};
    var i;
    for (i = 0; i < parts.length && out.length < 8; i++) {
      if (parts[i].length < 2 || seen[parts[i]]) {
        continue;
      }
      seen[parts[i]] = true;
      out.push(parts[i]);
    }
    return out;
  }

  function safeUrl(base, url, hash) {
    var root;
    if (!/^\/[A-Za-z0-9._~/-]*$/.test(url || '')) {
      return '';
    }
    if (hash && !/^[A-Za-z0-9._~-]+$/.test(hash)) {
      hash = '';
    }
    root = String(base || '/');
    if (root.charAt(root.length - 1) === '/') {
      root = root.slice(0, -1);
    }
    if (!/^\/[A-Za-z0-9._~/-]*$/.test(root) && root !== '') {
      return '';
    }
    return root + url + (hash ? '#' + hash : '');
  }

  function snippet(page, terms) {
    var body = page.b || '';
    var lower = body.toLowerCase();
    var at = -1;
    var term = '';
    var i;
    var h;
    var start;
    var end;
    var text;
    for (i = 0; i < terms.length; i++) {
      var found = lower.indexOf(terms[i]);
      if (found >= 0 && (at < 0 || found < at)) {
        at = found;
        term = terms[i];
      }
    }
    if (at < 0) {
      for (h = 0; h < (page.h || []).length; h++) {
        if (page.h[h][1].toLowerCase().indexOf(terms[0]) >= 0) {
          return page.h[h][1];
        }
      }
      return '';
    }
    start = Math.max(0, at - 70);
    end = Math.min(body.length, at + term.length + 110);
    text = body.slice(start, end).trim();
    if (start > 0) {
      text = '\u2026' + text;
    }
    if (end < body.length) {
      text += '\u2026';
    }
    return text;
  }

  // Every term has to occur. A hit in the title outranks a heading, and
  // a heading outranks the body, so the page that is about the words
  // comes first. `where` is the heading to open, when one matched.
  function searchPages(pages, query) {
    var terms = termsOf(query);
    var out = [];
    var i;
    if (!terms.length) {
      return out;
    }
    for (i = 0; i < pages.length; i++) {
      var page = pages[i];
      var title = (page.tl || page.t || '').toLowerCase();
      var body = (page.bl || page.b || '').toLowerCase();
      var heads = page.h || [];
      var score = 0;
      var where = '';
      var ok = true;
      var t;
      for (t = 0; t < terms.length; t++) {
        var term = terms[t];
        var inTitle = title.indexOf(term) >= 0;
        var headHit = -1;
        var h;
        var inBody = body.indexOf(term) >= 0;
        for (h = 0; h < heads.length; h++) {
          if (String(heads[h][1]).toLowerCase().indexOf(term) >= 0) {
            headHit = h;
            break;
          }
        }
        if (!inTitle && headHit < 0 && !inBody) {
          ok = false;
          break;
        }
        if (inTitle) {
          score += 30;
        }
        if (headHit >= 0) {
          score += 12;
          if (!where) {
            where = heads[headHit][0];
          }
        }
        if (inBody) {
          score += 1;
        }
      }
      if (!ok) {
        continue;
      }
      out.push({
        page: page,
        score: score,
        where: where,
        snippet: snippet(page, terms)
      });
    }
    out.sort(function (a, b) {
      return b.score - a.score ||
        String(a.page.t).localeCompare(String(b.page.t));
    });
    return out.slice(0, 20);
  }

  function appendHighlighted(parent, text, terms) {
    var lower = text.toLowerCase();
    var i = 0;
    while (i < text.length) {
      var next = -1;
      var which = '';
      var t;
      var at;
      for (t = 0; t < terms.length; t++) {
        at = lower.indexOf(terms[t], i);
        if (at >= 0 && (next < 0 || at < next)) {
          next = at;
          which = terms[t];
        }
      }
      if (next < 0) {
        parent.appendChild(document.createTextNode(text.slice(i)));
        return;
      }
      if (next > i) {
        parent.appendChild(document.createTextNode(text.slice(i, next)));
      }
      var mark = document.createElement('mark');
      mark.textContent = text.slice(next, next + which.length);
      parent.appendChild(mark);
      i = next + which.length;
    }
  }

  function boot() {
    var root = document.querySelector('.doc-search');
    if (!root) {
      return;
    }
    var form = root.querySelector('form');
    var input = form.querySelector('input[type="search"]');
    var panel = root.querySelector('.doc-search-panel');
    var pageBox = document.getElementById('doc-search-page');
    var base = root.getAttribute('data-base') || '/';
    var indexUrl = root.getAttribute('data-index') || '';
    var label = root.getAttribute('data-label') || 'this version';
    var hidden = form.querySelector('input[name="v"]');
    var params = new URLSearchParams(window.location.search);
    var asked = params.get('v');
    var cache = null;
    var cacheUrl = '';
    var gen = 0;
    var active = -1;
    var shown = [];
    var timer = 0;

    if (asked && /^v[0-9.]+$/.test(asked)) {
      if (hidden) {
        hidden.value = asked;
      }
      indexUrl = indexUrl.replace(
        /\/v[0-9.]+\/search-index\.json$/,
        '/' + asked + '/search-index.json');
      label = asked.replace(/^v/, '');
    }
    if (params.get('q')) {
      input.value = params.get('q');
    }

    function open() {
      panel.hidden = false;
      input.setAttribute('aria-expanded', 'true');
    }

    function close() {
      panel.hidden = true;
      input.setAttribute('aria-expanded', 'false');
      active = -1;
      shown = [];
    }

    function status(container, message) {
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
      var p = document.createElement('p');
      p.className = 'doc-search-status';
      p.textContent = message;
      container.appendChild(p);
    }

    function fill(container, results, terms) {
      var list;
      var count;
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
      count = document.createElement('p');
      count.className = 'doc-search-status';
      count.textContent = results.length ?
        results.length + (results.length === 1 ? ' page' : ' pages') :
        'Nothing in ' + label + ' matches that.';
      container.appendChild(count);
      if (!results.length) {
        return;
      }
      list = document.createElement('ul');
      results.forEach(function (hit) {
        var li = document.createElement('li');
        var a = document.createElement('a');
        var title = document.createElement('span');
        var href = safeUrl(base, hit.page.u, hit.where);
        if (!href) {
          return;
        }
        a.href = href;
        a.className = 'doc-search-hit';
        title.className = 'doc-search-title';
        appendHighlighted(title, hit.page.t || hit.page.u, terms);
        a.appendChild(title);
        if (hit.snippet) {
          var snip = document.createElement('span');
          snip.className = 'doc-search-snippet';
          appendHighlighted(snip, hit.snippet, terms);
          a.appendChild(snip);
        }
        li.appendChild(a);
        list.appendChild(li);
      });
      container.appendChild(list);
    }

    function markActive() {
      var links = panel.querySelectorAll('a');
      var i;
      for (i = 0; i < links.length; i++) {
        if (i === active) {
          links[i].classList.add('doc-search-active');
        } else {
          links[i].classList.remove('doc-search-active');
        }
      }
      if (active >= 0 && links[active]) {
        links[active].scrollIntoView({ block: 'nearest' });
      }
    }

    function load() {
      if (cache && cacheUrl === indexUrl) {
        return Promise.resolve(cache);
      }
      cacheUrl = indexUrl;
      cache = null;
      return fetch(indexUrl, { headers: { 'Accept': 'application/json' } })
        .then(function (res) {
          if (!res.ok) {
            throw new Error('status ' + res.status);
          }
          return res.json();
        })
        .then(function (data) {
          var pages = data && data.pages ? data.pages : [];
          pages.forEach(function (page) {
            page.tl = String(page.t || '').toLowerCase();
            page.bl = String(page.b || '').toLowerCase();
          });
          cache = pages;
          return pages;
        });
    }

    function run() {
      var q = input.value;
      var terms = termsOf(q);
      var mine = ++gen;
      if (!terms.length) {
        close();
        if (pageBox) {
          while (pageBox.firstChild) {
            pageBox.removeChild(pageBox.firstChild);
          }
        }
        return;
      }
      status(panel, 'Searching ' + label + '\u2026');
      open();
      load().then(function (pages) {
        var version;
        if (mine !== gen) {
          return;
        }
        shown = searchPages(pages, q);
        active = -1;
        fill(panel, shown, terms);
        if (pageBox) {
          fill(pageBox, shown, terms);
        }
        if (pageBox && hidden) {
          version = new URL(window.location.href);
          version.searchParams.set('v', hidden.value);
          version.searchParams.set('q', q);
          window.history.replaceState(null, '',
            version.pathname + version.search);
        }
      }, function () {
        if (mine !== gen) {
          return;
        }
        status(panel,
          'The search index for ' + label + ' is not available.');
        open();
      });
    }

    form.addEventListener('submit', function (event) {
      var links;
      event.preventDefault();
      if (active >= 0) {
        links = panel.querySelectorAll('a');
        if (links[active]) {
          window.location.href = links[active].href;
          return;
        }
      }
      run();
    });
    input.addEventListener('input', function () {
      window.clearTimeout(timer);
      timer = window.setTimeout(run, 150);
    });
    input.addEventListener('keydown', function (event) {
      var links = panel.querySelectorAll('a');
      if (event.key === 'Escape') {
        close();
        return;
      }
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        if (!links.length) {
          return;
        }
        active = Math.min(links.length - 1, active + 1);
        markActive();
        return;
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault();
        active = Math.max(-1, active - 1);
        markActive();
      }
    });
    document.addEventListener('click', function (event) {
      if (!root.contains(event.target)) {
        close();
      }
    });
    if (input.value) {
      run();
    }
  }

  return {
    termsOf: termsOf,
    safeUrl: safeUrl,
    searchPages: searchPages,
    boot: boot
  };
});
