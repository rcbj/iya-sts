'use strict';
//
// File: service_state.js
//
// ---------------------------------------------------------------------------
// BRINGING THIS PROCESS'S STATE UP, IN THE ONE ORDER THERE IS.
//
// Four asynchronous steps, and **the order between them is a dependency rather
// than a preference** — each one's argument is written out below, verbatim,
// where it has always been. The sequence lived in `server.js` until 2026-09-07
// and moved here for the reason `protocol_stack.js` moved: it acquired a second
// reader.
//
// `server.js` runs it and then binds the sockets. `common/request_worker.js`
// runs it and binds none of them — and it MUST run it, which is the whole
// reason this file exists. A worker that skipped these steps would come up with
// an empty store, no signing keys, none of what this service minted, and — the
// one that matters for dispatch — **no coordination**, so it would hold its own
// private copy of the directory and never see another process's writes.
//
// A second copy of this sequence would be a second answer to "is this process
// up to date", and the two would disagree in the way that is hardest to see:
// one process coordinating and another quietly not.
// ---------------------------------------------------------------------------

const persistence = require('../persistence/persistence');
// The keystore, for the product-mode key material. A LEAF (rule 3).
const keystore = require('./keystore');

function start() {
  return persistence.start().then(function (started) {
  // THE SIGNING KEYS, AFTER THE STORE AND BEFORE ANYTHING SIGNS.
  //
  // It is a second asynchronous step in the same chain for the same reason the
  // first one is: reading a key-encryption key from AWS, GCP, Azure or Vault is
  // a network call, and `helpers.js` builds a key set inside a PROPERTY READ
  // that cannot await. So everything asynchronous happens here, and what is
  // left is a synchronous map lookup.
  //
  // **A FAILURE HERE IS FATAL AND FALLS INTO THE SAME catch.** A product-mode
  // service that cannot read its signing keys and starts anyway generates new
  // ones, and every token, assertion and signed document it ever issued stops
  // verifying — silently, at somebody else's relying party. Refusing to start
  // is the only honest answer, and it is the same argument persistence makes
  // about its own store one line up.
  return keystore.start().then(function (keys) {
    // -----------------------------------------------------------------------
    // AND THEN WHAT THIS PROCESS MINTED — A THIRD ASYNCHRONOUS STEP, AND IT
    // CANNOT BE ANYTHING ELSE (2026-09-06).
    //
    // Every persisted minted row is sealed under the key-encryption key, and
    // that key does not exist until the line above has resolved — reading it
    // from AWS, GCP, Azure or Vault is a network call. So this cannot join
    // `persistence.start()`'s chain, where the directory, the realms and the
    // settings are restored: it has to come after the keystore.
    //
    // AND BEFORE `bind()`, which is the half that matters to somebody using
    // the service. The listener opens with the sessions already back, so a
    // browser that was signed in before the restart is signed in on its next
    // request rather than being turned away and let in a moment later.
    //
    // **A FAILURE HERE IS FATAL AND FALLS INTO THE SAME catch**, for the
    // keystore's reason read one step along: a process that was told to
    // persist its sessions and comes up empty while presenting itself as the
    // one that was persisting has lost them, silently, and the only place that
    // would ever show is somebody being signed out for no reason. It does
    // nothing at all in development mode, in memory mode and on an ldif
    // store — see persistence_minted.js, which says which and why.
    // -----------------------------------------------------------------------
    return persistence.restoreMinted().then(function (mintedResult) {
      // ---------------------------------------------------------------------
      // AND THEN COORDINATION, WHICH IS LAST AND HAS TO BE.
      //
      // It takes the change log's high-water mark and treats everything below
      // it as already applied — which is only true once this process really
      // HAS restored everything: the settings, the realms, the directory, the
      // keys and the minted rows. Starting it any earlier would mark changes
      // as seen that this process had not seen, and they would never be
      // applied by anything.
      //
      // **A FAILURE HERE IS NOT FATAL, WHICH IS THE OPPOSITE OF THE TWO STEPS
      // ABOVE**, and the asymmetry is the argument: a process that cannot read
      // its own signing keys is lying about what it issues, and a process that
      // cannot read the change log is simply the process this service was
      // before 2026-09-06 — correct about its own copy, and alone with it. It
      // starts, says so loudly, and keeps trying on its timer.
      // ---------------------------------------------------------------------
      return persistence.coordinate().then(function (coordinating) {
        return { started: started, keys: keys, minted: mintedResult,
                 coordinating: coordinating };
      });
    });
  });
  });
}

module.exports = {
  start: start
};
