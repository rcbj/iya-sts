// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/service_account.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/service_accounts.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "serviceAccount",
  source: "./service_accounts",
  container: "ou=users",
  ownContainer: false,
  authored: true,
  noAttributes: true,
  objectClasses: #[
    #{
      name: "stsServiceAccount",
      what: "AUXILIARY. This service's class for a SERVICE ACCOUNT: a person entry used by a program, governed by the realm's service-account policy (ou=serviceAccountPolicies) (#221)."
    }
  ]
})
model ServiceAccount {
}

@entry(#{
  id: "serviceAccount",
  source: "./service_accounts",
  onPerson: true
})
model ServiceAccountOnPerson {
  @attr(#{
    what: "TRUE on a service account. Absent: an ordinary person. Asked through common/service_accounts.ts's isServiceAccount(), never read directly."
  })
  stsServiceAccount?: DirectoryBoolean;
  @attr(#{
    what: "The DN of a person or group answerable for the account; one value per owner."
  })
  stsServiceAccountOwner?: (DirectoryDn)[];
  @attr(#{
    what: "The DN of the application entry (a push destination) a rotated password is written to."
  })
  stsSecretDestination?: string;
  @attr(#{
    what: "The name or path of the secret at that destination. It must already exist: a push never creates one."
  })
  stsSecretName?: string;
  @attr(#{
    what: "When the password was last rotated (GeneralizedTime)."
  })
  stsPasswordRotatedAt?: DirectoryTime;
  @attr(#{
    what: "The previous password's scrypt hash, accepted until stsPreviousPasswordExpires. Withheld from every read."
  })
  stsPreviousPassword?: string;
  @attr(#{
    what: "When the previous password stops being accepted (ms since the epoch)."
  })
  stsPreviousPasswordExpires?: DirectoryTime;
  @attr(#{
    what: "Consecutive failed rotations, reset by a success."
  })
  stsRotationFailures?: DirectoryInteger;
  @attr(#{
    what: "The error code of the last failed rotation."
  })
  stsRotationLastError?: string;
  @attr(#{
    what: "When the rotation job last tried this account (ms)."
  })
  stsRotationLastAttempt?: DirectoryTime;
  @attr(#{
    what: "TRUE: the account's owners may not administer it through /admin-api (#607) — an administrator's mark, read by the access-control policy's owner rule. Absent is FALSE."
  })
  stsOwnerProtected?: DirectoryBoolean;
  @attr(#{
    what: "The named service-account policy that governs this account (#1240): `default` or a policy in ou=serviceAccountPolicies of this realm. Absent is `default`. Only a service account may hold it, and it is cleared with stsServiceAccount."
  })
  stsServiceAccountPolicy?: string;
}
