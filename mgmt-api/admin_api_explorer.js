// @ts-check
//
// File: admin_api_explorer.js
//
// ---------------------------------------------------------------------------
// THIS FILE RUNS IN A BROWSER. It is not a node module and nothing requires
// it; it is one of the seven scripts the root CLAUDE.md lists.
//
// admin_api_docs.js reads it off disk at require time and
// GET /admin/api-explorer/explorer.js (`admin-ui/api_explorer.js`; it was
// /admin-api/docs/explorer.js until 2026-09-09) sends it verbatim, which is
// why it is a file rather than a string constant in that module: a 400-line
// program inside a JavaScript string is a program nobody can read a diff of.
//
// Two consequences follow from where it runs, and both are exemptions from this
// repository's code style rather than oversights:
//
//   * **No bunyan.** There is no `require` here and no logger to reach, so the
//     `log` below is CONSOLE-BACKED and has bunyan's shape — which is what the
//     parent project gives `extension/src/*` and every other file that cannot
//     reach bunyan, and what lets the Entering/Leaving lines and the handled
//     exceptions be written here the way they are everywhere else. Its level is
//     info, as this service's is by default, so the debug lines are silent in a
//     reader's console. What a log line would have said to a PERSON is on the
//     page instead: every call shows its status, its timing and its whole
//     response body, and a failure shows the error where the response would
//     have been. Code handed to `driver.executeScript` is still exempt.
//   * **It is served under a RELAXED Content-Security-Policy** — `script-src
//     'self'` on this page, where the service default is `script-src 'none'`
//     and only the root CLAUDE.md's scripted pages relax it, each naming one
//     resource. That is why this is a separate resource and not an
//     inline block: `'self'` is enough for a file and `'unsafe-inline'` would
//     have been required for a block, and `'unsafe-inline'` is the clause that
//     would make the relaxation matter.
//
// It builds every node with createElement and textContent and never assigns
// innerHTML. The spec it renders is this service's own, so that is belt and
// braces rather than a control — but the response bodies it displays are not
// necessarily, and those go through the same path.
// ---------------------------------------------------------------------------
(function () {
  'use strict';

  // The console-backed logger the header describes. Its own four methods are
  // the one place the Entering/Leaving convention cannot apply: a log line
  // inside log.debug() would be infinite recursion.
  var LEVELS = { debug: 20, info: 30, warn: 40, error: 50 };
  var LOG_LEVEL = LEVELS.info;
  // `any` for the type checker (#50): the methods pass `arguments` on, which
  // it reads as taking none.
  /** @type {any} */
  var log = {
    debug: function () {
      if (LOG_LEVEL <= LEVELS.debug) {
        console.debug.apply(console, arguments);
      }
    },
    info: function () {
      if (LOG_LEVEL <= LEVELS.info) {
        console.info.apply(console, arguments);
      }
    },
    warn: function () {
      if (LOG_LEVEL <= LEVELS.warn) {
        console.warn.apply(console, arguments);
      }
    },
    error: function () {
      console.error.apply(console, arguments);
    }
  };

  var root = document.getElementById('app');
  var SPEC_URL = root.getAttribute('data-spec');
  // The trust realm this page is being read in, as a path prefix — empty in the
  // default realm, '/realm/acme' in a realm called acme. Every request this
  // explorer makes is prefixed with it, because the paths in the OpenAPI
  // document are the paths the routes are REGISTERED at and no route in this
  // service carries a realm. Without it, Try it inside a realm would call the
  // default realm's API: the call would succeed and it would have changed the
  // wrong service. See the comment on page() in admin_api_docs.js.
  var REALM_PREFIX = root.getAttribute('data-realm-prefix') || '';
  // ---------------------------------------------------------------------
  // THE ACCESS TOKEN (2026-09-09), AND WHY A PAGE IS GIVEN ONE AT ALL.
  //
  // `/admin-api` requires an OAuth 2.0 access token. This page is drawn by
  // the ADMIN CONSOLE, which authenticates the person reading it and knows
  // which of the two roles they hold — so the console mints a token carrying
  // exactly those scopes and puts it here. A reader with Admin Read alone
  // gets `admin:read`, and pressing Try it on a POST gets them a 403 from
  // the same policy that would refuse them anywhere else.
  //
  // **IT IS NOT A WAY ROUND THE GATE AND MUST NEVER BECOME ONE.** The token
  // is minted for the person already through the console's own gate, with
  // their own permissions and no more; the API still checks it on every
  // call, exactly as it does for a machine. What the console removes is the
  // step where a person copies a credential from a terminal into a form.
  //
  // Empty is a supported state: the page still renders every operation and
  // still shows the curl line, and Try it will be refused. That is what a
  // reader gets if the console could not mint one, and it is better than a
  // page that will not draw.
  // ---------------------------------------------------------------------
  var TOKEN = root.getAttribute('data-token') || '';

  // --- small DOM helpers ----------------------------------------------------
  function el(tag, className, text) {
    log.debug("Entering el().");
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    log.debug("Leaving el().");
    return node;
  }

  function add(parent, child) {
    log.debug("Entering add().");
    parent.appendChild(child);
    log.debug("Leaving add().");
    return child;
  }

  // The three pieces of Markdown the descriptions in the document actually use:
  // a blank line between paragraphs, **bold**, and `code`. Rendered by walking
  // the text and creating nodes, rather than by building a string of markup —
  // the whole page is written that way, and a "just this once" innerHTML is how
  // a page that renders a response body stops being safe.
  function inline(parent, text) {
    log.debug("Entering inline().");
    var pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
    var last = 0;
    var match = pattern.exec(text);
    while (match) {
      if (match.index > last) {
        parent.appendChild(
          document.createTextNode(text.slice(last, match.index)));
      }
      var piece = match[0];
      if (piece.charAt(0) === '`') {
        add(parent, el('code', '', piece.slice(1, -1)));
      } else {
        add(parent, el('strong', '', piece.slice(2, -2)));
      }
      last = match.index + piece.length;
      match = pattern.exec(text);
    }
    if (last < text.length) {
      parent.appendChild(document.createTextNode(text.slice(last)));
    }
    log.debug("Leaving inline().");
  }

  function prose(parent, text, className) {
    log.debug("Entering prose().");
    String(text || '').split('\n\n').forEach(function (para) {
      if (!para.trim()) {
        return;
      }
      inline(add(parent, el('p', className || 'prose')), para.trim());
    });
    log.debug("Leaving prose().");
  }

  // --- the spec -------------------------------------------------------------
  function operationsOf(spec) {
    log.debug("Entering operationsOf().");
    var out = [];
    Object.keys(spec.paths).forEach(function (path) {
      Object.keys(spec.paths[path]).forEach(function (method) {
        var operation = spec.paths[path][method];
        out.push({
          method: method.toUpperCase(),
          path: path,
          operation: operation,
          tag: (operation.tags || ['Other'])[0]
        });
      });
    });
    log.debug("Leaving operationsOf().");
    return out;
  }

  function tagsOf(spec, operations) {
    log.debug("Entering tagsOf().");
    // The document's own order, then anything an operation named that the tag
    // list did not — so a tag added to an operation and forgotten in the list
    // still gets a section rather than vanishing.
    var order = (spec.tags || []).map(function (t) { return t.name; });
    operations.forEach(function (row) {
      if (order.indexOf(row.tag) < 0) {
        order.push(row.tag);
      }
    });
    log.debug("Leaving tagsOf().");
    return order;
  }

  function describedBy(spec, name) {
    log.debug("Entering describedBy().");
    var found = (spec.tags || []).filter(function (t) {
      return t.name === name;
    })[0];
    log.debug("Leaving describedBy().");
    return found ? found.description : '';
  }

  // --- one operation --------------------------------------------------------
  function bodyExampleOf(operation) {
    log.debug("Entering bodyExampleOf().");
    var content = operation.requestBody && operation.requestBody.content;
    var schema = content && content['application/json'] &&
                 content['application/json'].schema;
    if (!schema) {
      log.debug("Leaving bodyExampleOf().");
      return null;
    }
    var examples = schema.examples || [];
    log.debug("Leaving bodyExampleOf().");
    return JSON.stringify(examples.length ? examples[0] : {}, null, 2);
  }

  function curlFor(method, url, body) {
    log.debug("Entering curlFor().");
    var parts = ["curl -i -X " + method + " '" + url + "'"];
    // THE HEADER IS IN THE CURL LINE TOO, and it is the reason that line is
    // worth showing: a copied command that omitted the credential would fail
    // with a 401 for a reason the page had not mentioned. The token is
    // printed in full because the whole point of the line is to be pasted
    // into a terminal — it is a short-lived credential for the person
    // already reading this console, which is where it came from.
    if (TOKEN) {
      parts.push("-H 'Authorization: Bearer " + TOKEN + "'");
    }
    if (body !== null && body !== undefined && body !== '') {
      parts.push("-H 'Content-Type: application/json'");
      // Single quotes inside a single-quoted shell word have to be closed,
      // escaped and reopened. The bodies here rarely contain one, and a curl
      // line that silently would not run is worse than a long one.
      parts.push("-d '" + String(body).replace(/'/g, "'\\''") + "'");
    }
    log.debug("Leaving curlFor().");
    return parts.join(' \\\n  ');
  }

  function urlFor(row, inputs) {
    log.debug("Entering urlFor().");
    var query = [];
    Object.keys(inputs).forEach(function (name) {
      var value = inputs[name].value;
      if (value === '') {
        return;
      }
      query.push(encodeURIComponent(name) + '=' + encodeURIComponent(value));
    });
    log.debug("Leaving urlFor().");
    return REALM_PREFIX + row.path +
           (query.length ? '?' + query.join('&') : '');
  }

  function renderResult(into, status, ms, text) {
    log.debug("Entering renderResult().");
    into.textContent = '';
    var head = add(into, el('div', 'resulthead'));
    var cls = status >= 200 && status < 300 ? 'ok'
            : (status === 0 ? 'err' : 'bad');
    add(head, el('span', 'status ' + cls, status === 0 ? 'failed' : status));
    add(head, el('span', 'ms', ms + ' ms'));
    var pretty = text;
    try {
      pretty = JSON.stringify(JSON.parse(text), null, 2);
    } catch (e) {
      // Not JSON — an HTML error page, or a script. Shown as it arrived, which
      // is the useful thing when the answer was not the expected shape.
      log.debug('Caught in renderResult(): ' + ((e && e.message) || e));
      pretty = text;
    }
    add(into, el('pre', 'body', pretty));
    log.debug("Leaving renderResult().");
  }

  function renderOperation(row, spec) {
    log.debug("Entering renderOperation().");
    var wrap = el('div', 'op');
    var head = add(wrap, el('button', 'ophead'));
    head.setAttribute('type', 'button');
    add(head, el('span', 'method m-' + row.method.toLowerCase(), row.method));
    add(head, el('span', 'path', row.path));
    add(head, el('span', 'summary', row.operation.summary || ''));

    var detail = add(wrap, el('div', 'opbody'));
    detail.style.display = 'none';
    head.addEventListener('click', function () {
      detail.style.display = detail.style.display === 'none' ? 'block' : 'none';
    });

    prose(detail, row.operation.description);

    var form = add(detail, el('div', 'form'));
    var inputs = {};
    (row.operation.parameters || []).forEach(function (parameter) {
      var line = add(form, el('div', 'field'));
      var id = row.operation.operationId + '-' + parameter.name;
      var label = add(line, el('label', '', parameter.name));
      label.setAttribute('for', id);
      var input = add(line, el('input', ''));
      input.setAttribute('type', 'text');
      input.setAttribute('id', id);
      if (parameter.schema && parameter.schema.default !== undefined) {
        input.setAttribute('placeholder', String(parameter.schema.default));
      }
      inputs[parameter.name] = input;
      prose(line, parameter.description, 'hint');
    });

    var bodyBox = null;
    var example = bodyExampleOf(row.operation);
    if (example !== null) {
      var bodyField = add(form, el('div', 'field wide'));
      add(bodyField, el('label', '', 'request body (JSON)'));
      bodyBox = add(bodyField, el('textarea', ''));
      bodyBox.value = example;
      bodyBox.setAttribute('spellcheck', 'false');
      bodyBox.setAttribute('rows', String(
        Math.min(12, example.split('\n').length + 1)));
    }

    var controls = add(detail, el('div', 'controls'));
    var run = add(controls, el('button', 'run', 'Try it'));
    run.setAttribute('type', 'button');
    var curlLine = add(detail, el('pre', 'curl'));
    var result = add(detail, el('div', 'result'));

    function refreshCurl() {
      log.debug("Entering refreshCurl().");
      curlLine.textContent = curlFor(row.method,
                                     location.origin + urlFor(row, inputs),
                                     bodyBox ? bodyBox.value : null);
      log.debug("Leaving refreshCurl().");
    }
    Object.keys(inputs).forEach(function (name) {
      inputs[name].addEventListener('input', refreshCurl);
    });
    if (bodyBox) {
      bodyBox.addEventListener('input', refreshCurl);
    }
    refreshCurl();

    run.addEventListener('click', function () {
      var url = urlFor(row, inputs);
      var options = { method: row.method, headers: {} };
      if (TOKEN) {
        options.headers.Authorization = 'Bearer ' + TOKEN;
      }
      if (bodyBox) {
        options.headers['Content-Type'] = 'application/json';
        options.body = bodyBox.value;
      }
      result.textContent = '';
      add(result, el('div', 'pending', 'calling ' + row.method + ' ' + url +
                                       ' …'));
      var started = Date.now();
      fetch(url, options).then(function (response) {
        return response.text().then(function (text) {
          renderResult(result, response.status, Date.now() - started, text);
        });
      }).catch(function (error) {
        // Shown rather than logged, for the reason at the top of this file: the
        // page is the only place a person is looking.
        renderResult(result, 0, Date.now() - started, String(error));
      });
    });
    log.debug("Leaving renderOperation().");
    return wrap;
  }

  // --- the page -------------------------------------------------------------
  function render(spec) {
    log.debug("Entering render().");
    root.textContent = '';
    var operations = operationsOf(spec);

    var header = add(root, el('header', 'head'));
    add(header, el('h1', '', spec.info.title));
    var meta = add(header, el('p', 'meta'));
    add(meta, el('span', 'version', 'v' + spec.info.version));
    add(meta, el('span', 'count', operations.length + ' operations'));
    var specLink = add(meta, el('a', '', 'OpenAPI document'));
    specLink.setAttribute('href', SPEC_URL);
    var consoleLink = add(meta, el('a', '', 'the console this mirrors'));
    consoleLink.setAttribute('href', REALM_PREFIX + '/admin');

    prose(header, spec.info.description, 'lede');

    var filterRow = add(root, el('div', 'filter'));
    var filterLabel = add(filterRow, el('label', '', 'filter'));
    filterLabel.setAttribute('for', 'filter');
    var filter = add(filterRow, el('input', ''));
    filter.setAttribute('id', 'filter');
    filter.setAttribute('type', 'text');
    filter.setAttribute('placeholder', 'revoke, claims, /users …');

    var sections = [];
    tagsOf(spec, operations).forEach(function (tag) {
      var rows = operations.filter(function (row) { return row.tag === tag; });
      if (!rows.length) {
        return;
      }
      var section = add(root, el('section', 'tag'));
      add(section, el('h2', '', tag));
      prose(section, describedBy(spec, tag), 'tagnote');
      var nodes = rows.map(function (row) {
        return { row: row, node: add(section, renderOperation(row, spec)) };
      });
      sections.push({ section: section, nodes: nodes });
    });

    filter.addEventListener('input', function () {
      var needle = filter.value.trim().toLowerCase();
      sections.forEach(function (entry) {
        var visible = 0;
        entry.nodes.forEach(function (item) {
          var hay = (item.row.method + ' ' + item.row.path + ' ' +
                     (item.row.operation.summary || '')).toLowerCase();
          var shown = !needle || hay.indexOf(needle) >= 0;
          item.node.style.display = shown ? 'block' : 'none';
          if (shown) {
            visible += 1;
          }
        });
        entry.section.style.display = visible ? 'block' : 'none';
      });
    });
    log.debug("Leaving render().");
  }

  // The document is read from the CONSOLE's own path rather than from
  // `/admin-api/openapi.json`, so it arrives on the console session this page
  // was drawn with and needs no token of its own. See
  // admin-ui/api_explorer.js.
  fetch(SPEC_URL).then(function (response) {
    return response.json();
  }).then(render).catch(function (error) {
    root.textContent = '';
    add(root, el('h1', '', 'The OpenAPI document could not be read'));
    add(root, el('pre', 'body', SPEC_URL + '\n\n' + String(error)));
  });
}());
