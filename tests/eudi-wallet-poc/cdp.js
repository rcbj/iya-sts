// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// Minimal CDP driver for the headless Chrome on :9222.
//   node cdp.js goto <url>
//   node cdp.js eval '<expression>'          prints the value as JSON
//   node cdp.js wait '<expression>' [ms]     until the expression is truthy
//   node cdp.js shot <file.png>
'use strict';
const WS = require('../node_modules/ws');
const fs = require('fs');

async function target() {
  const list = await (await fetch('http://127.0.0.1:' + (process.env.CDP_PORT || 9222) + '/json/list')).json();
  const page = list.find(t => t.type === 'page');
  if (!page) throw new Error('no page target');
  return page.webSocketDebuggerUrl;
}

async function main() {
  const [cmd, arg, extra] = process.argv.slice(2);
  const ws = new WS(await target());
  await new Promise((ok, no) => { ws.on('open', ok); ws.on('error', no); });
  let id = 0;
  const pending = new Map();
  ws.on('message', m => {
    const msg = JSON.parse(m);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  });
  const send = (method, params = {}) => new Promise(ok => {
    const n = ++id; pending.set(n, ok); ws.send(JSON.stringify({ id: n, method, params }));
  });
  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) {
      throw new Error(JSON.stringify(r.result.exceptionDetails.exception || r.result.exceptionDetails));
    }
    return r.result && r.result.result ? r.result.result.value : undefined;
  };
  try {
    if (cmd === 'goto') {
      await send('Page.navigate', { url: arg });
      await new Promise(r => setTimeout(r, 1500));
      console.log(JSON.stringify(await evaluate('location.href')));
    } else if (cmd === 'eval') {
      console.log(JSON.stringify(await evaluate(arg), null, 1));
    } else if (cmd === 'wait') {
      const until = Date.now() + Number(extra || 20000);
      for (;;) {
        let v;
        try { v = await evaluate(arg); } catch (e) { v = undefined; }
        if (v) { console.log(JSON.stringify(v)); break; }
        if (Date.now() > until) {
          console.log('TIMEOUT at ' + await evaluate('location.href'));
          process.exitCode = 1; break;
        }
        await new Promise(r => setTimeout(r, 500));
      }
    } else if (cmd === 'shot') {
      const r = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(arg, Buffer.from(r.result.data, 'base64'));
      console.log(arg);
    } else {
      throw new Error('unknown command ' + cmd);
    }
  } finally {
    ws.close();
  }
}
main().catch(e => { console.error(e.message || e); process.exit(1); });
