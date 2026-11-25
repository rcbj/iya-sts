// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: console_steps.js
//
// ===========================================================================
// WHAT A REAL ADMINISTRATOR DOES AFTER PRESSING SAVE IN THE STATIC CONSOLE,
// WHEN THE CONSOLE ASKS FOR SOMETHING FIRST (#2196).
//
// **THIS IS A HELPER AND NOT A JOB**, and it is OURS (`MANIFEST.js`'s
// LOCAL_HELPERS). The browser jobs that press console forms — the admin
// console walk, the paranoid PKI page, the certificate sign-in editors, the
// XACML editor, the per-tab accounts, the realm's late forms — go through it
// after a press, so that each completes what the console asks for the way a
// person at the keyboard would, and none of them weakens a check to get past
// it.
//
// WHAT THE CONSOLE MAY ASK FOR, after a Save, since two changes landed:
//
//   * **#2161 / PR #2173, A RECENT SIGN-IN.** Every `/admin-api` POST of the
//     role, realm, PKI, key and configuration families, and every Security
//     Administrator change, needs a sign-in within
//     `account.recentAuthMinutes` (15 in product). Older, and the answer is
//     401 with RFC 9470's `insufficient_user_authentication` and `max_age`
//     (STS-API-0145). The console's runtime (`admin-ui/web_runtime.ts`)
//     answers that with a fresh sign-in.
//   * **#2168 / PR #2189, THE WRITE SCOPE BY A SECOND AUTHORIZATION.** The
//     console signs in with read scopes only; the first write meets a 403
//     `insufficient_scope` naming the scope, and the runtime asks for it in
//     a POPUP (`common/web_spa_client.ts`, `stepUp()`): `prompt=none` while
//     the session holds, and for `admin:security` `prompt=none max_age=300`
//     and then `prompt=login max_age=0`, which waits for the bar's Continue.
//     The popup's callback hands the code back over a BroadcastChannel and
//     closes, and the write is sent again from memory.
//
// SO AFTER A PRESS, THIS WATCHES FOR, AND COMPLETES, THREE THINGS:
//
//   (a) THE CONSOLE'S OWN WINDOW SENT TO THE SIGN-IN SCREEN — a sign-in on
//       the page (`leaveToSignIn()`, `leaveForStepUp()`, the bar's "Sign in
//       on this page"). The job's own credentials are typed, any second
//       factor offer is passed, and the console is waited for. The runtime
//       puts the page back with a note that NOTHING WAS SENT, so the answer
//       says `leftToSignIn` and the caller presses again — as a person does.
//   (b) A POPUP — a window that was not there before the press. It is
//       switched to, a sign-in in it is completed, it is waited for until it
//       closes itself, and the job is switched back to its own window.
//   (c) THE BARS: the step's (`#step-bar`, its Continue is
//       `[data-step=open]`) and the ended session's (`#reauth-bar`, "Sign in
//       again" is `[data-reauth=popup]`). The button that opens the window
//       is pressed, and the window is (b).
//
// **IT NEVER SWALLOWS A REFUSAL.** It presses only the buttons that OPEN a
// sign-in, never Cancel; it signs in only as the account the caller names;
// and it decides nothing about the answer. A step that ends refused —
// the bar's "Permission to make this change was not given", a reader whose
// write token carries no write scope, another account — is reported as
// `stepRefused` with the bar's words and left on the page, and the
// refusal the caller asserts (a handler's 400, a reader's 403) is what the
// caller reads afterwards exactly as before. What tells a step from a
// refusal is the caller's own `settled()`: it says when THE ANSWER to the
// press is in, and a job that reads the browser's network record knows
// which responses were the runtime's challenges (`isStepChallenge()`) and
// which was the form's.
// ===========================================================================

const { By } = require("selenium-webdriver");

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require("bunyan").createLogger({ name: "console_steps",
  level: process.env.LOG_LEVEL || "info" });

// How long a press may take to settle when a step is under way: a fresh
// sign-in in a popup is a screen, a second factor offer and two redirects.
const STEP_TIMEOUT_MS = 90000;
// How long a press with NO step in sight is given to settle before this
// hands back to the caller, which then waits and asserts as it always did.
const QUIET_MS = 10000;
// How long a step that was seen must stay quiet — no window, no bar, no
// sign-in screen — before it is taken to have ended without sending the
// write again.
const IDLE_MS = 3000;
// How long a sign-in screen may still be showing after it was submitted
// before the sign-in is taken not to have gone through.
const STUCK_MS = 20000;
// Between two looks at the windows and the page.
const POLL_MS = 100;

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// WHETHER A RECORDED RESPONSE IS ONE OF THE RUNTIME'S CHALLENGES rather than
// the answer to the form: RFC 6750's `insufficient_scope` (a 403 that starts
// a step), RFC 9470's `insufficient_user_authentication` (a 401 that starts a
// fresh sign-in) and RFC 9449's `use_dpop_nonce` (a 401 sent again at once).
// `headers` is a map of lower-cased names, as the jobs record them. A 403
// WITHOUT the challenge — a reader refused a role — is NOT one: that is a
// refusal and the caller's to assert.
function isStepChallenge(status, headers) {
  log.debug("Entering isStepChallenge().");
  const challenge = String((headers || {})["www-authenticate"] || "");
  const answer = (status === 403 && /insufficient_scope/.test(challenge)) ||
    (status === 401 &&
     /insufficient_user_authentication|use_dpop_nonce/.test(challenge));
  log.debug("Leaving isStepChallenge(). " + answer);
  return answer;
}

// THE SIGN-IN SCREEN, wherever the driver is now: the console's own window
// or a popup. One look and at most one act per call, so that the loop that
// calls it sees a window close or a page change between acts.
//
// Answers 'typed' (a form was filled and submitted), 'ignored' (a second
// factor offer was passed), 'screen' (a sign-in page with nothing to do
// yet), 'off' (not a sign-in page) or 'gone' (the window closed).
const LOOK = `
  if (document.readyState !== 'complete') { return { at: 'loading' }; }
  const path = location.pathname.replace(/^\\/realm\\/[^/]+/, '');
  const onSignIn = /^\\/authn\\//.test(path);
  const ignore = document.getElementById('mfa-setup-ignore');
  const user = document.querySelector("input[name='username']");
  const secret = document.querySelector("input[name='password']");
  const visible = function (e) {
    return !!e && e.checkVisibility() && !e.disabled;
  };
  return { at: onSignIn ? 'signin' : 'off', path: path,
           href: location.href,
           text: document.body ? document.body.innerText.slice(0, 300) : '',
           ignore: !!ignore && visible(ignore),
           user: visible(user), userLocked: !!user && user.readOnly,
           userValue: user ? user.value : '',
           secret: visible(secret) };
`;

// What WebDriver says of a window that has closed.
const WINDOW_GONE =
  /no such window|target window already closed|web view not found/i;

async function signInStep(driver, credentials, done, where) {
  log.debug("Entering signInStep().");
  const seen = await driver.executeScript(LOOK).catch(function (e) {
    // A window that closed under the look, or a document torn down.
    log.debug("Caught in signInStep(): " + ((e && e.message) || e));
    return { at: WINDOW_GONE.test(String(e && e.message)) ? "gone"
                                                          : "loading" };
  });
  if (where && seen.href) {
    // What the window showed last, for a report of one that never closed.
    where.href = seen.href;
    where.text = seen.text;
  }
  if (seen.at !== "signin") {
    log.debug("Leaving signInStep(). " + seen.at);
    return seen.at === "gone" ? "gone" : "off";
  }
  if (seen.ignore) {
    // AN ADMINISTRATOR IS OFFERED A SECOND FACTOR on the way (#246), and
    // the suite passes it, as rcbj asked ("just click ignore for the time
    // being").
    await driver.findElement(By.id("mfa-setup-ignore")).click()
      .catch(function (e) {
        log.debug("Caught pressing ignore: " + ((e && e.message) || e));
      });
    log.debug("Leaving signInStep(). Ignored a second factor offer.");
    return "ignored";
  }
  if (!seen.user && !seen.secret) {
    log.debug("Leaving signInStep(). A sign-in page with nothing to type.");
    return "screen";
  }
  // ONE SUBMIT PER PAGE: a page already submitted is left to answer.
  if (done[seen.href]) {
    log.debug("Leaving signInStep(). Already submitted here.");
    return "screen";
  }
  const who = credentials();
  if (seen.user && !seen.userLocked && seen.userValue !== who.username) {
    const field = await driver.findElement(By.css("input[name='username']"));
    await field.clear();
    await field.sendKeys(who.username);
  }
  let form = null;
  if (seen.secret) {
    const secret = await driver.findElement(By.css("input[name='password']"));
    await secret.clear();
    await secret.sendKeys(who.password);
    form = secret;
  } else {
    form = await driver.findElement(By.css("input[name='username']"));
  }
  // THE SIGN-IN FORM'S OWN BUTTON, not the page's first: the screen carries
  // a language chooser, a form of its own with a submit button (#539). And
  // never Cancel.
  const button = await form.findElement(By.xpath(
    "ancestor::form//button[@id='kc-login'] | " +
    "ancestor::form//button[@type='submit' and not(@value='cancel')] | " +
    "ancestor::form//input[@type='submit']"));
  done[seen.href] = true;
  await button.click();
  log.info("[steps] signed in again as " + who.username + " at " +
           seen.path + ".");
  log.debug("Leaving signInStep(). Typed.");
  return "typed";
}

// THE STATE OF THE CONSOLE'S OWN WINDOW: where it is, and which bar is up
// with which buttons.
const BARS = `
  const step = document.getElementById('step-bar');
  const reauth = document.getElementById('reauth-bar');
  const path = location.pathname.replace(/^\\/realm\\/[^/]+/, '');
  return {
    signIn: /^\\/authn\\//.test(path),
    step: step ? (step.textContent || '').trim() : null,
    stepOpen: !!(step && step.querySelector('[data-step=open]')),
    reauth: reauth ? (reauth.textContent || '').trim() : null,
    reauthPopup: !!(reauth && reauth.querySelector('[data-reauth=popup]')),
    drawn: document.readyState === 'complete' &&
      !/\\/admin\\/callback$/.test(path) &&
      !!document.querySelector('.pagehead') &&
      !/^Signing in/.test((document.querySelector('p.lede') || {})
        .textContent || '')
  };
`;

// The words the step's bar ends on when it did not get the scope
// (`SpaClient.stepWords()`, in English; a translated console says them in its
// own language, and the bar is reported either way).
const STEP_ENDED = /not given|could not be had|another account/i;

// A WATCHER FOR ONE DRIVER. `options.credentials()` answers the account the
// job is signed in as, `{ username, password }` — asked each time, because a
// job may switch who it is. `options.home()`, when given, answers the
// handle of the window the job works in; otherwise it is the one current
// when `before()` is called.
function forDriver(driver, options) {
  log.debug("Entering forDriver().");
  const opts = options || {};
  const credentials = opts.credentials || function () {
    return { username: "", password: "" };
  };
  const say = opts.log && opts.log.info ? opts.log.info.bind(opts.log)
    : function () {};

  // Before the press: the windows there are, and the one the job is in.
  async function before() {
    log.debug("Entering before().");
    const home = opts.home ? await opts.home()
      : await driver.getWindowHandle();
    const handles = await driver.getAllWindowHandles();
    log.debug("Leaving before().");
    return { home: home, handles: handles, at: Date.now() };
  }

  // A POPUP, completed: switched to, signed in where it asks, waited for
  // until it closes itself, and the job switched back.
  async function throughThePopup(handle, home, deadline) {
    log.debug("Entering throughThePopup().");
    const done = {};
    const where = { href: "", text: "" };
    let typed = false;
    let typedAt = 0;
    await driver.switchTo().window(handle).catch(function (e) {
      // It closed before it could be reached: a silent step.
      log.debug("Caught switching to the popup: " + ((e && e.message) || e));
    });
    while (Date.now() < deadline) {
      const open = await driver.getAllWindowHandles();
      if (open.indexOf(handle) < 0) {
        break;
      }
      const did = await signInStep(driver, credentials, done, where)
        .catch(function (e) {
          log.debug("Caught in the popup: " + ((e && e.message) || e));
          return "gone";
        });
      if (did === "typed") {
        typed = true;
        typedAt = Date.now();
      }
      if (did === "screen" && typed && Date.now() - typedAt > STUCK_MS) {
        // THE SCREEN DID NOT TAKE THE SIGN-IN: a refusal, or an account
        // that screen does not know. Not typed again, and not waited out.
        log.warn("[steps] the sign-in in the console's window did not go " +
                 "through within " + STUCK_MS + " ms.");
        break;
      }
      if (did === "gone") {
        // Asked again: a closed window is confirmed by the handle list.
        await pause(POLL_MS);
        continue;
      }
      await pause(POLL_MS);
    }
    await driver.switchTo().window(home);
    const stillOpen = (await driver.getAllWindowHandles()).indexOf(handle) >= 0;
    if (stillOpen) {
      log.warn("[steps] a window the console opened never closed; it is " +
               "at " + where.href + ": " +
               JSON.stringify(where.text.replace(/\s+/g, " ")));
    }
    log.debug("Leaving throughThePopup(). typed=" + typed +
              " stillOpen=" + stillOpen);
    return { typed: typed, stillOpen: stillOpen };
  }

  // AFTER THE PRESS, until the answer to it is in or nothing is left to
  // complete. `options`:
  //   * `settled()` — true when the answer to the press is in (required);
  //   * `stepping()` — true when the caller sees a step under way that this
  //     cannot (a challenge in the network record), which keeps the wait
  //     going past QUIET_MS;
  //   * `timeoutMs`, `quietMs`, `idleMs` — the bounds.
  //
  // IT ENDS ON THE FIRST OF FOUR: `settled()`; a step that was seen and has
  // gone quiet for `idleMs` — no new window, no bar, no sign-in screen — which
  // is a step that ended without sending the write again (a reader whose
  // second authorization carried no write scope: the refusal is the first
  // answer, and the caller reads it); the console back on its page after a
  // sign-in on it; or, with no step seen at all, `quietMs` gone by.
  //
  // Answers `{ popups, signIns, continued, leftToSignIn, stepRefused,
  // settled, stillOpen }`.
  async function after(start, options2) {
    log.debug("Entering after().");
    const o = options2 || {};
    const settled = o.settled || async function () {
      return false;
    };
    const stepping = o.stepping || async function () {
      return false;
    };
    const began = Date.now();
    const deadline = began + (o.timeoutMs || STEP_TIMEOUT_MS);
    const quiet = o.quietMs || QUIET_MS;
    const idle = o.idleMs || IDLE_MS;
    const out = { popups: 0, signIns: 0, continued: 0, leftToSignIn: false,
                  stepRefused: null, settled: false, stillOpen: false };
    const handled = {};
    const done = {};
    let busy = false;
    let lastActivity = began;
    const active = function () {
      busy = true;
      lastActivity = Date.now();
    };
    while (Date.now() < deadline) {
      // (b) A WINDOW THAT WAS NOT THERE BEFORE THE PRESS.
      const handles = await driver.getAllWindowHandles();
      const fresh = handles.filter(function (h) {
        return start.handles.indexOf(h) < 0 && !handled[h];
      });
      for (const handle of fresh) {
        handled[handle] = true;
        out.popups += 1;
        active();
        const went = await throughThePopup(handle, start.home, deadline);
        if (went.typed) {
          out.signIns += 1;
        }
        if (went.stillOpen) {
          out.stillOpen = true;
        }
        active();
      }
      // (a) and (c), in the job's own window.
      const page = await driver.executeScript(BARS).catch(function (e) {
        log.debug("Caught reading the bars: " + ((e && e.message) || e));
        return null;
      });
      if (page && page.signIn && !busy && !(await stepping())) {
        // A SIGN-IN SCREEN NO STEP ASKED FOR — a Sign out pressed, which
        // lands there on purpose — is the caller's to read, and nobody is
        // signed in here.
        break;
      }
      if (page && page.signIn) {
        active();
        const did = await signInStep(driver, credentials, done);
        if (did === "typed") {
          out.signIns += 1;
          out.leftToSignIn = true;
        }
        await pause(POLL_MS);
        continue;
      }
      if (page && page.stepOpen) {
        // CONTINUE: the step asks something of the person, who presses it.
        active();
        out.continued += 1;
        await driver.findElement(By.css("#step-bar [data-step=open]"))
          .click().catch(function (e) {
            log.debug("Caught pressing Continue: " + ((e && e.message) || e));
          });
        say("[steps] the console asked for a sign-in to make this change; " +
            "Continue pressed.");
        await pause(POLL_MS);
        continue;
      }
      if (page && page.reauthPopup) {
        active();
        out.continued += 1;
        await driver.findElement(By.css("#reauth-bar [data-reauth=popup]"))
          .click().catch(function (e) {
            log.debug("Caught pressing Sign in again: " +
                      ((e && e.message) || e));
          });
        say("[steps] the console said the session ended; Sign in again " +
            "pressed.");
        await pause(POLL_MS);
        continue;
      }
      if (page && page.reauth && !page.reauthPopup) {
        // The ended session's bar with only "Sign in on this page": what a
        // person presses when no window can be opened.
        active();
        await driver.findElement(By.css("#reauth-bar [data-reauth=page]"))
          .click().catch(function (e) {
            log.debug("Caught pressing Sign in on this page: " +
                      ((e && e.message) || e));
          });
        await pause(POLL_MS);
        continue;
      }
      if (page && page.step) {
        if (STEP_ENDED.test(page.step)) {
          // THE STEP ENDED WITHOUT THE SCOPE. Left on the page and
          // reported; the refusal it ends in is the caller's to read.
          out.stepRefused = page.step;
        } else {
          // "Getting permission…": a silent step, its window not yet back.
          active();
        }
      }
      if (out.leftToSignIn) {
        // BACK ON THE PAGE, which the console says sent nothing — whatever
        // `settled()` makes of a page drawn afresh: the caller presses
        // again.
        if (page && page.drawn) {
          break;
        }
        await pause(POLL_MS);
        continue;
      }
      if (await settled()) {
        out.settled = true;
        break;
      }
      // A CHALLENGE THE CALLER SAW is a step begun, even where its window
      // came and went between two looks.
      if (!busy && await stepping()) {
        active();
      }
      if (busy && Date.now() - lastActivity > idle) {
        break;
      }
      if (!busy && Date.now() - began > quiet) {
        break;
      }
      await pause(POLL_MS);
    }
    if (out.popups || out.signIns || out.continued) {
      say("[steps] after the press: " + out.popups + " popup(s), " +
          out.signIns + " sign-in(s), " + out.continued + " button(s) " +
          "pressed" + (out.leftToSignIn ? ", the page left to sign in" : "") +
          (out.stepRefused ? ", the step ended: " + out.stepRefused : "") +
          (out.settled ? ", answered" : ", no answer to the press yet") +
          ".");
    }
    log.debug("Leaving after(). " + JSON.stringify(out));
    return out;
  }

  // A PRESS, COMPLETED: `pressOnce(again)` clicks (and fills, where the page
  // has to be filled again), the steps are completed, and where the page left
  // to sign in — which sends nothing — it is pressed ONCE more, as a person
  // does when the console says nothing was sent. `options2` is `after()`'s.
  async function press(pressOnce, options2) {
    log.debug("Entering press().");
    let start = await before();
    await pressOnce(false);
    let out = await after(start, options2);
    if (out.leftToSignIn) {
      say("[steps] the console left to sign in and sent nothing; pressed " +
          "again.");
      start = await before();
      await pressOnce(true);
      const again = await after(start, options2);
      again.pressedAgain = true;
      again.signIns += out.signIns;
      out = again;
    }
    log.debug("Leaving press().");
    return out;
  }

  log.debug("Leaving forDriver().");
  return { before: before, after: after, press: press };
}

module.exports = {
  forDriver: forDriver,
  isStepChallenge: isStepChallenge,
  STEP_TIMEOUT_MS: STEP_TIMEOUT_MS,
  QUIET_MS: QUIET_MS
};
