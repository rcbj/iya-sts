// ---------------------------------------------------------------------------
// TYPES THE JAVASCRIPT CANNOT STATE FOR ITSELF (#50, 2026-09-16).
//
// Declarations only: nothing here is loaded at runtime. They exist for the
// type checker `tests/typecheck.js` runs over the files that carry
// `// @ts-check`, and they are the shared shapes the TypeScript conversion
// (ticket #50) builds its interfaces from.
//
// Every member is one this service really sets. A property added here without
// a writer is a lie the checker will then believe, so a new one names the
// module that assigns it.
// ---------------------------------------------------------------------------

import 'http';

declare module 'http' {
  interface IncomingMessage {
    // `common/request_worker.js`: the pool ticket and the protocol worker the
    // front process named in its routing headers, stashed before the headers
    // are stripped.
    stsPoolTicket?: number;
    stsProtocolWorker?: number;
  }
}
