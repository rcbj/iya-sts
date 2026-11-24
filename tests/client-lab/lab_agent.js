#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/client-lab/lab_agent.js
//
// ===========================================================================
// THE CLIENT LAB'S AGENT (#2056): how a protocol job, which runs in the
// tests container, drives the real clients and the virtual cards in this
// one. tests/CLAUDE.md, *THE CLIENT LAB*, argues it.
//
//   GET  /health              200 once both cards answer (or none were
//                             asked for); the readers and the card serials
//   POST /run                 one program, its argv, its stdin, its exit
//                             code, stdout and stderr
//   PUT  /files/<path>        a file into the lab's work directory
//   GET  /files/<path>        a file out of it
//
// **ONLY THE CLIENTS, NEVER A SHELL.** `/run` executes a program by name
// from a fixed list — the clients the lab exists for and the scripts in
// `bin/` — with `execFile`, so an argument is an argument and never shell
// syntax. A path under `/files` is relative to the work directory and may
// not leave it. The lab listens on an unpublished port of the stack's
// private bridge and holds nothing but keys it made for this run, so this
// is a guard against a job's mistake, not against an attacker.
//
// No dependency: node's own http, child_process and fs. The log is JSON
// lines on stdout in bunyan's shape, so `00-client-lab.log` reads like the
// others.
// ===========================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const PORT = Number(process.env.CLIENT_LAB_PORT || 9610);
const LAB = path.join(__dirname);
const WORK = process.env.CLIENT_LAB_WORK || '/run/client-lab/work';
const RUN = '/run/client-lab';
const LEVELS = { trace: 10, debug: 20, info: 30, warn: 40, error: 50 };
const LEVEL = LEVELS[String(process.env.LOG_LEVEL || 'info')] || 30;
const MAX_BODY = 16 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60000;
const MAX_TIMEOUT_MS = 600000;

// The clients a job may run, by name (tests/CLAUDE.md, *THE CLIENT LAB*,
// says what each is for). `bin/` adds the lab's own scripts.
const CLIENTS = Object.freeze([
  'gpg', 'gpgconf', 'gpg-connect-agent', 'gpgsm',
  'yubico-piv-tool', 'pkcs11-tool', 'pkcs15-tool', 'opensc-tool',
  'piv-tool', 'opensc-explorer',
  'ssh', 'ssh-keygen', 'ssh-add', 'ssh-agent', 'scp', 'sftp',
  'sendmail', 'mailx', 'postqueue', 'postconf',
  'oathtool', 'pamtester',
  'kinit', 'klist', 'kdestroy', 'kvno',
  'ldapmodify', 'ldapsearch',
  'curl', 'openssl'
]);

// THE LOGGER ITSELF, and a hot path: no Entering/Leaving pair, which would
// log every log line (root CLAUDE.md, *Code style*). The same for `log`'s
// four methods below.
function line(level, msg) {
  if (LEVELS[level] < LEVEL) {
    return;
  }
  process.stdout.write(JSON.stringify({ name: 'client-lab',
    hostname: require('os').hostname(), pid: process.pid,
    level: LEVELS[level], msg: msg, time: new Date().toISOString(),
    v: 0 }) + '\n');
}

const log = {
  debug: function (msg) {
    line('debug', msg);
  },
  info: function (msg) {
    line('info', msg);
  },
  warn: function (msg) {
    line('warn', msg);
  },
  error: function (msg) {
    line('error', msg);
  }
};

// The program a name stands for, or null when it is not one a job may run.
function programOf(name) {
  log.debug("Entering programOf(). " + name);
  const text = String(name || '');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(text)) {
    log.debug("Leaving programOf(). Not a name.");
    return null;
  }
  const own = path.join(LAB, 'bin', text);
  if (fs.existsSync(own)) {
    log.debug("Leaving programOf(). The lab's own.");
    return own;
  }
  if (CLIENTS.indexOf(text) >= 0) {
    log.debug("Leaving programOf(). A client.");
    return text;
  }
  log.debug("Leaving programOf(). Not allowed.");
  return null;
}

// A path under the work directory, or null for one that would leave it.
function workPath(rel) {
  log.debug("Entering workPath().");
  let decoded = '';
  try {
    decoded = decodeURIComponent(String(rel || ''));
  } catch (e) {
    log.debug("Caught in workPath(): " + ((e && e.message) || e));
    // A path that is not percent-encoded properly names no file.
    log.debug("Leaving workPath(). Undecodable.");
    return null;
  }
  const full = path.resolve(WORK, decoded);
  if (!decoded || (full !== WORK && full.indexOf(WORK + path.sep) !== 0)) {
    log.debug("Leaving workPath(). Outside.");
    return null;
  }
  log.debug("Leaving workPath().");
  return full;
}

function send(res, status, body, type) {
  log.debug("Entering send(). " + status);
  const payload = Buffer.isBuffer(body) ? body
    : Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'content-type': type || 'application/json',
                          'content-length': payload.length,
                          'cache-control': 'no-store' });
  res.end(payload);
  log.debug("Leaving send().");
}

function readBody(req) {
  log.debug("Entering readBody().");
  log.debug("Leaving readBody().");
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let size = 0;
    req.on('data', function (chunk) {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error('the body is over ' + MAX_BODY + ' bytes'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', function () {
      resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

// One program run to completion. stdin is a string, or base64 when
// `stdinBase64` is given; the answer carries both forms of stdout.
function runProgram(spec) {
  log.debug("Entering runProgram().");
  const s = spec || {};
  const program = programOf(s.program);
  if (!program) {
    log.debug("Leaving runProgram(). Not allowed.");
    return Promise.resolve({ status: 400, body: { ok: false,
      error: 'The lab runs only its clients and the scripts in bin/; "' +
             String(s.program || '') + '" is neither.' } });
  }
  const args = Array.isArray(s.args) ? s.args.map(String) : [];
  const timeout = Math.min(Number(s.timeoutMs) || DEFAULT_TIMEOUT_MS,
                           MAX_TIMEOUT_MS);
  const env = Object.assign({}, process.env, s.env || {});
  const cwd = s.cwd ? workPath(s.cwd) : WORK;
  if (!cwd) {
    log.debug("Leaving runProgram(). Bad cwd.");
    return Promise.resolve({ status: 400, body: { ok: false,
      error: 'cwd must be a directory under the work directory.' } });
  }
  fs.mkdirSync(cwd, { recursive: true });
  const input = typeof s.stdinBase64 === 'string'
    ? Buffer.from(s.stdinBase64, 'base64')
    : Buffer.from(String(s.stdin || ''));
  log.info('run ' + String(s.program) + ' ' + JSON.stringify(args));
  log.debug("Leaving runProgram(). Started.");
  return new Promise(function (resolve) {
    const child = childProcess.execFile(program, args, {
      cwd: cwd, env: env, timeout: timeout, maxBuffer: MAX_BODY,
      encoding: 'buffer' }, function (err, stdout, stderr) {
      const code = err ? (typeof err.code === 'number' ? err.code : -1) : 0;
      if (err && typeof err.code !== 'number') {
        log.warn('run ' + String(s.program) + ': ' +
                 ((err && err.message) || err));
      }
      resolve({ status: 200, body: {
        ok: code === 0, code: code,
        signal: (err && err.signal) || null,
        killed: !!(err && err.killed),
        stdout: Buffer.from(stdout || '').toString('utf8'),
        stdoutBase64: Buffer.from(stdout || '').toString('base64'),
        stderr: Buffer.from(stderr || '').toString('utf8') } });
    });
    child.stdin.on('error', function (e) {
      // A program that exits without reading its stdin closes the pipe
      // under us; its own exit code is the answer.
      log.debug("Caught in runProgram(): " + ((e && e.message) || e));
    });
    child.stdin.end(input);
  });
}

// The readers pcscd sees and the cards' serials, and whether each card is
// in its reader.
function health() {
  log.debug("Entering health().");
  let readers = '';
  try {
    readers = childProcess.execFileSync('opensc-tool', ['-l'],
      { encoding: 'utf8', timeout: 10000 });
  } catch (e) {
    log.debug("Caught in health(): " + ((e && e.message) || e));
    // pcscd not yet up: no reader, so not healthy.
    readers = '';
  }
  const wanted = process.env.CLIENT_LAB_CARDS === 'none' ? []
    : ['Virtual PCD 00 00', 'Virtual PCD 00 01'];
  const present = wanted.filter(function (name) {
    return new RegExp('Yes\\s.*' + name).test(readers);
  });
  let installed = true;
  for (const card of ['openpgp', 'piv']) {
    if (wanted.length &&
        !fs.existsSync(path.join(RUN, card + '.install'))) {
      installed = false;
    }
  }
  let serial = '';
  try {
    serial = fs.readFileSync(path.join(RUN, 'openpgp-serial'), 'utf8')
      .trim();
  } catch (e) {
    log.debug("Caught in health(): " + ((e && e.message) || e));
    // Not written yet: the cards have not started.
    serial = '';
  }
  const ok = present.length === wanted.length && installed;
  log.debug("Leaving health(). " + ok);
  return { ok: ok, readers: present, openpgpSerial: serial,
           pivReader: 'Virtual PCD 00 01',
           openpgpReader: 'Virtual PCD 00 00' };
}

async function handle(req, res) {
  log.debug("Entering handle(). " + req.method + ' ' + req.url);
  const url = new URL(req.url, 'http://client-lab');
  if (req.method === 'GET' && url.pathname === '/health') {
    const h = health();
    send(res, h.ok ? 200 : 503, h);
    log.debug("Leaving handle(). Health.");
    return;
  }
  if (req.method === 'POST' && url.pathname === '/run') {
    let spec = null;
    try {
      spec = JSON.parse((await readBody(req)).toString('utf8'));
    } catch (e) {
      log.debug("Caught in handle(): " + ((e && e.message) || e));
      send(res, 400, { ok: false, error: 'The body is not JSON: ' +
                       ((e && e.message) || e) });
      log.debug("Leaving handle(). Not JSON.");
      return;
    }
    const answer = await runProgram(spec);
    send(res, answer.status, answer.body);
    log.debug("Leaving handle(). Run.");
    return;
  }
  if (url.pathname.indexOf('/files/') === 0) {
    const file = workPath(url.pathname.slice('/files/'.length));
    if (!file) {
      send(res, 400, { ok: false, error: 'A file is named by a path ' +
                       'under the work directory.' });
      log.debug("Leaving handle(). Bad path.");
      return;
    }
    if (req.method === 'PUT') {
      const body = await readBody(req);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, body, { mode: 0o600 });
      send(res, 200, { ok: true, path: file, bytes: body.length });
      log.debug("Leaving handle(). Written.");
      return;
    }
    if (req.method === 'GET') {
      if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
        send(res, 404, { ok: false, error: 'No such file.' });
        log.debug("Leaving handle(). No file.");
        return;
      }
      send(res, 200, fs.readFileSync(file), 'application/octet-stream');
      log.debug("Leaving handle(). Read.");
      return;
    }
  }
  send(res, 404, { ok: false, error: 'Not a lab endpoint.' });
  log.debug("Leaving handle(). Unrouted.");
}

function main() {
  log.debug("Entering main().");
  fs.mkdirSync(WORK, { recursive: true, mode: 0o700 });
  const server = http.createServer(function (req, res) {
    handle(req, res).then(null, function (e) {
      log.error('the agent failed a request: ' + ((e && e.stack) || e));
      if (!res.headersSent) {
        send(res, 500, { ok: false, error: String((e && e.message) || e) });
      }
    });
  });
  server.listen(PORT, '0.0.0.0', function () {
    log.info('the client lab agent listens on ' + PORT);
  });
  log.debug("Leaving main().");
}

main();
