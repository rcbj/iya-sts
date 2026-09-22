'use strict';
//
// File: spiffe_agent_path.ts
//
// ---------------------------------------------------------------------------
// SPIRE'S AGENT PATH TEMPLATES (#40, 2026-09-21).
//
// `x509pop` and `sshpop` let an operator choose the path of the agent's
// SPIFFE ID with `agent_path_template`, a Go `text/template` evaluated over
// what the attestor verified (`pkg/common/agentpathtemplate`): the defaults
// are `/{{ .PluginName }}/{{ .Fingerprint }}` and, for x509pop's spiffe mode,
// `/{{ .PluginName }}/{{ .SVIDPathTrimmed }}`. SPIRE hands the template a
// curated list of sprig functions and runs it with `missingkey=error`.
//
// THIS IS A SUBSET, AND IT SAYS WHERE IT ENDS. Go's template language has
// conditionals, ranges, variables and a hundred-odd functions on that list; an
// agent path needs a field or two and perhaps a string function. What is here:
//
//   * text, and actions `{{ … }}` with the `{{-` / `-}}` trim markers;
//   * a pipeline of commands joined by `|`, the previous value passed as the
//     LAST argument, as Go passes it;
//   * operands: a field path (`.Subject.CommonName`, `.URISanSelectors.k`),
//     `.` itself, a double- or back-quoted string, an integer;
//   * the functions in `FUNCTIONS` below — sprig's string, hash and encoding
//     functions from SPIRE's list, with sprig's argument order.
//
// Anything else — `if`, `range`, `with`, a variable, a function not in the
// table — is REFUSED when the template is parsed, naming what was not
// understood. A template that silently rendered something different from
// what SPIRE renders would give an agent a different identity here than it
// has there, which is worse than refusing to start it.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
const { log } = helpers;

type Operand =
  { kind: 'field'; path: string[] } |
  { kind: 'string'; value: string } |
  { kind: 'number'; value: number };

interface Command {
  // A function name, or '' for a bare operand.
  fn: string;
  args: Operand[];
}

type Node = { kind: 'text'; text: string } |
            { kind: 'action'; pipeline: Command[] };

// sprig's functions, with sprig's argument order (the piped value LAST).
const FUNCTIONS: Record<string, (...args: any[]) => any> = {
  lower: function (s) {
    return String(s).toLowerCase();
  },
  upper: function (s) {
    return String(s).toUpperCase();
  },
  trim: function (s) {
    return String(s).trim();
  },
  trimAll: function (cut, s) {
    const chars = String(cut);
    let out = String(s);
    while (out.length && chars.indexOf(out[0]) >= 0) out = out.slice(1);
    while (out.length && chars.indexOf(out[out.length - 1]) >= 0) {
      out = out.slice(0, -1);
    }
    return out;
  },
  trimPrefix: function (prefix, s) {
    const text = String(s);
    return text.indexOf(String(prefix)) === 0
      ? text.slice(String(prefix).length) : text;
  },
  trimSuffix: function (suffix, s) {
    const text = String(s);
    const tail = String(suffix);
    return tail && text.slice(-tail.length) === tail
      ? text.slice(0, -tail.length) : text;
  },
  replace: function (from, to, s) {
    return String(s).split(String(from)).join(String(to));
  },
  trunc: function (n, s) {
    const text = String(s);
    const count = Number(n);
    return count >= 0 ? text.slice(0, count) : text.slice(count);
  },
  nospace: function (s) {
    return String(s).replace(/\s+/g, '');
  },
  sha1sum: function (s) {
    return nodeCrypto.createHash('sha1').update(String(s), 'utf8')
      .digest('hex');
  },
  sha256sum: function (s) {
    return nodeCrypto.createHash('sha256').update(String(s), 'utf8')
      .digest('hex');
  },
  b64enc: function (s) {
    return Buffer.from(String(s), 'utf8').toString('base64');
  },
  b32enc: function (s) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bytes = Buffer.from(String(s), 'utf8');
    let bits = 0;
    let value = 0;
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
    while (out.length % 8) out += '=';
    return out;
  },
  quote: function (s) {
    return JSON.stringify(String(s));
  },
  base: function (s) {
    const parts = String(s).replace(/\/+$/, '').split('/');
    return parts[parts.length - 1] || '/';
  }
};

interface AgentPathDeps {
  log: typeof log;
}

class AgentPathTemplate {
  private readonly nodes: Node[];

  // Parses `text`; throws an Error naming what it could not understand.
  constructor(readonly text: string,
              private readonly deps: AgentPathDeps = { log: log }) {
    deps.log.debug("Entering AgentPathTemplate.constructor().");
    this.nodes = this.parse(String(text || ''));
    deps.log.debug("Leaving AgentPathTemplate.constructor().");
  }

  parse(text: string): Node[] {
    const { log } = this.deps;
    log.debug("Entering AgentPathTemplate.parse().");
    const nodes: Node[] = [];
    let rest = text;
    while (rest.length) {
      const open = rest.indexOf('{{');
      if (open < 0) {
        nodes.push({ kind: 'text', text: rest });
        break;
      }
      let before = rest.slice(0, open);
      let inner = rest.slice(open + 2);
      const close = inner.indexOf('}}');
      if (close < 0) {
        log.debug("Leaving AgentPathTemplate.parse(). Unclosed.");
        // error-code: none — a configuration error, reported by the caller
        // under its own code
        throw new Error('an action is opened with {{ and never closed');
      }
      let body = inner.slice(0, close);
      rest = inner.slice(close + 2);
      if (body.charAt(0) === '-' && /\s/.test(body.charAt(1))) {
        before = before.replace(/\s+$/, '');
        body = body.slice(1);
      }
      if (body.slice(-1) === '-' && /\s/.test(body.slice(-2, -1))) {
        rest = rest.replace(/^\s+/, '');
        body = body.slice(0, -1);
      }
      if (before) nodes.push({ kind: 'text', text: before });
      nodes.push({ kind: 'action', pipeline: this.pipeline(body.trim()) });
    }
    log.debug("Leaving AgentPathTemplate.parse(). " + nodes.length +
              " node(s).");
    return nodes;
  }

  // A pipeline: commands separated by `|`, outside quotes.
  pipeline(body: string): Command[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AgentPathTemplate.pipeline().");
    if (!body) {
      log.debug("Leaving AgentPathTemplate.pipeline(). Empty.");
      // error-code: none — see parse()
      throw new Error('an action {{ }} is empty');
    }
    const words = this.tokens(body);
    const commands: Command[] = [];
    let current: string[] = [];
    words.forEach(function (word) {
      if (word === '|') {
        commands.push(self.command(current));
        current = [];
      } else {
        current.push(word);
      }
    });
    commands.push(this.command(current));
    log.debug("Leaving AgentPathTemplate.pipeline().");
    return commands;
  }

  tokens(body: string): string[] {
    const { log } = this.deps;
    log.debug("Entering AgentPathTemplate.tokens().");
    const out: string[] = [];
    const pattern = /\s*("(?:[^"\\]|\\.)*"|`[^`]*`|\||[^\s|"`]+)/g;
    let match;
    let consumed = 0;
    while ((match = pattern.exec(body)) !== null) {
      out.push(match[1]);
      consumed = pattern.lastIndex;
    }
    if (body.slice(consumed).trim()) {
      log.debug("Leaving AgentPathTemplate.tokens(). Unreadable.");
      // error-code: none — see parse()
      throw new Error('could not read "' + body.slice(consumed) + '"');
    }
    log.debug("Leaving AgentPathTemplate.tokens().");
    return out;
  }

  command(words: string[]): Command {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AgentPathTemplate.command().");
    if (!words.length) {
      log.debug("Leaving AgentPathTemplate.command(). Empty.");
      // error-code: none — see parse()
      throw new Error('a pipeline has an empty command');
    }
    const head = words[0];
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(head)) {
      if (!Object.prototype.hasOwnProperty.call(FUNCTIONS, head)) {
        log.debug("Leaving AgentPathTemplate.command(). Unsupported.");
        // error-code: none — see parse()
        throw new Error('"' + head + '" is not supported here — this ' +
                        'server evaluates field references and the ' +
                        'functions ' + Object.keys(FUNCTIONS).join(', ') +
                        ', and refuses the rest of Go\'s template language ' +
                        'rather than rendering it differently from SPIRE');
      }
      log.debug("Leaving AgentPathTemplate.command(). A function.");
      return { fn: head, args: words.slice(1).map(function (word) {
        return self.operand(word);
      }) };
    }
    if (words.length > 1) {
      log.debug("Leaving AgentPathTemplate.command(). Arguments to a value.");
      // error-code: none — see parse()
      throw new Error('"' + head + '" is a value and cannot take arguments');
    }
    log.debug("Leaving AgentPathTemplate.command(). An operand.");
    return { fn: '', args: [this.operand(head)] };
  }

  operand(word: string): Operand {
    const { log } = this.deps;
    log.debug("Entering AgentPathTemplate.operand().");
    if (word === '.') {
      log.debug("Leaving AgentPathTemplate.operand(). Dot.");
      return { kind: 'field', path: [] };
    }
    if (/^(\.[A-Za-z_][A-Za-z0-9_-]*)+$/.test(word)) {
      log.debug("Leaving AgentPathTemplate.operand(). A field.");
      return { kind: 'field', path: word.slice(1).split('.') };
    }
    if (word.charAt(0) === '"') {
      log.debug("Leaving AgentPathTemplate.operand(). A string.");
      return { kind: 'string', value: JSON.parse(word) };
    }
    if (word.charAt(0) === '`') {
      log.debug("Leaving AgentPathTemplate.operand(). A raw string.");
      return { kind: 'string', value: word.slice(1, -1) };
    }
    if (/^-?\d+$/.test(word)) {
      log.debug("Leaving AgentPathTemplate.operand(). A number.");
      return { kind: 'number', value: parseInt(word, 10) };
    }
    log.debug("Leaving AgentPathTemplate.operand(). Unsupported.");
    // error-code: none — see parse()
    throw new Error('"' + word + '" is not supported here (variables, ' +
                    'method calls and keywords are not)');
  }

  // Render over `data`. A field that is not there is an error, as SPIRE's
  // `missingkey=error` makes it.
  execute(data: Record<string, any>): string {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AgentPathTemplate.execute().");
    const out = this.nodes.map(function (node) {
      if (node.kind === 'text') {
        return node.text;
      }
      let value: any = undefined;
      node.pipeline.forEach(function (command, index) {
        const args = command.args.map(function (arg) {
          return self.value(arg, data);
        });
        if (index > 0) args.push(value);
        value = command.fn ? FUNCTIONS[command.fn].apply(null, args)
                           : args[0];
      });
      return self.print(value);
    }).join('');
    log.debug("Leaving AgentPathTemplate.execute().");
    return out;
  }

  value(operand: Operand, data: Record<string, any>): any {
    const { log } = this.deps;
    log.debug("Entering AgentPathTemplate.value().");
    if (operand.kind !== 'field') {
      log.debug("Leaving AgentPathTemplate.value(). A literal.");
      return operand.value;
    }
    let at: any = data;
    for (let i = 0; i < operand.path.length; i++) {
      const key = operand.path[i];
      if (at === null || at === undefined || typeof at !== 'object' ||
          !Object.prototype.hasOwnProperty.call(at, key)) {
        log.debug("Leaving AgentPathTemplate.value(). Missing.");
        // error-code: none — reported by the attestor under its own code
        throw new Error('map has no entry for key "' + key + '" (' +
                        '.' + operand.path.slice(0, i + 1).join('.') + ')');
      }
      at = at[key];
    }
    log.debug("Leaving AgentPathTemplate.value().");
    return at;
  }

  // Go's default formatting of the kinds a field here can hold.
  print(value: any): string {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AgentPathTemplate.print().");
    log.debug("Leaving AgentPathTemplate.print().");
    if (value === null || value === undefined) {
      return '<no value>';
    }
    if (Array.isArray(value)) {
      return '[' + value.map(function (one) {
        return self.print(one);
      }).join(' ') + ']';
    }
    return String(value);
  }
}

export = {
  AgentPathTemplate: AgentPathTemplate,
  FUNCTIONS: Object.keys(FUNCTIONS)
};
