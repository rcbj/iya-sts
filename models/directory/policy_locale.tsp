// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/policy_locale.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/locale_policy.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

// ON A PERSON (#539): what population wrote, so a page can tell the
// policy's language from the person's own.
@entry(#{
  id: "policy.locale",
  source: "policy_kinds:locale",
  container: "ou=localePolicies",
  ownContainer: true,
  authored: true,
  objectClasses: #[
    #{
      name: "stsLocalePolicy",
      what: "This service's class for a locale policy: the language a realm's pages fall back to and gives a new person. Named by the PROFILE (`cn=default`, or a named profile an application or a group names)."
    }
  ]
})
model PolicyLocale {
  @attr(#{
    what: "A BCP 47 language tag (RFC 5646), such as en, fr-CA or zh-TW. Pages are drawn in it when the request, the person's preferredLanguage, the language chooser and the browser name nothing a catalog answers; dates and numbers are formatted for it even where no catalog does. Mail to a person whose entry names no language is written in it. Replaces the setting mail.defaultLanguage.",
    field: #{key: "defaultLocale", type: "locale", dflt: "en", label: "Default language and region"}
  })
  stsLocaleDefault?: unknown;
  @attr(#{
    what: "ON BY DEFAULT. A person entry created in this realm without a preferredLanguage (RFC 2798 section 2.7) is given the default language above as one — by the console, the management API, SCIM, a federated or self-service sign-up, or a bulk load. A named profile applies where the application that caused the creation names it, or one of the person's groups does. Existing entries are never rewritten.",
    field: #{key: "populatePreferredLanguage", type: "bool", dflt: true, label: "Give a new person this language"}
  })
  stsLocalePopulatePreferredLanguage?: boolean;
  @attr(#{
    what: "Which named locale policy wins where several are named for a page: the lowest, from 1 to 1000.",
    selector: #{key: "precedence"}
  })
  stsLocalePrecedence?: unknown;
  @attr(#{
    what: "What the profile is for, for the next person."
  })
  description?: unknown;
}

@entry(#{
  id: "policy.locale",
  source: "policy_kinds:locale",
  onPerson: true
})
model PolicyLocaleOnPerson {
  @attr(#{what: "The preferredLanguage the locale policy gave this person when their entry was created. While preferredLanguage still equals it, it is the POLICY's choice and a page ranks it below the browser's language; once anybody sets another, it is the person's. Written by this service only."})
  stsPreferredLanguagePopulated?: unknown;
}
