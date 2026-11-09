// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/policy_password.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/password_policy.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

// THE TWO THAT GO ON A PERSON rather than on the policy. Listed here
// because this module is what gives them their meaning, and in
// `ldap/ldap_server.js`'s own list because that is where an attribute a
// person's entry carries is named.
@entry(#{
  id: "policy.password",
  source: "policy_kinds:password",
  container: "ou=passwordPolicies",
  ownContainer: true,
  authored: true,
  objectClasses: #[
    #{
      name: "pwdPolicy",
      what: "draft-behera-ldap-password-policy's class for a password policy entry. `pwdAttribute` names the attribute the policy governs, and here that is always `userPassword`."
    },
    #{
      name: "stsPasswordPolicy",
      what: "This service's own class, carrying the composition rules and the generated length the draft has no attribute for. The entry is named by the PROFILE: `cn=default`, or a named policy's name."
    }
  ]
})
model PolicyPassword {
  @attr(#{
    what: "The attribute this policy governs: `userPassword`."
  })
  pwdAttribute?: unknown;
  @attr(#{
    what: "The shortest password this service will set, counted in characters (Unicode code points, so an emoji is one). The attribute is draft-behera-ldap-password-policy's. Twelve is the default; NIST SP 800-63B asks for at least 8, and 15 where a password is the only factor.",
    field: #{key: "minLength", type: "int", dflt: 12, min: 1, max: 1024, label: "Minimum length", unit: "characters"}
  })
  pwdMinLength?: int32;
  @attr(#{
    what: "How many of a person's PREVIOUS passwords are remembered and refused. The current password is always refused as well while this is above 0, so 5 means a new password may be none of the last six. 0 turns the rule off. The draft's attribute, with the draft's meaning. Each remembered password is kept as the hash it was already stored as (argon2id or scrypt), in pwdHistory on the person's own entry, and checking a new password costs one hash comparison per one remembered.",
    field: #{key: "history", type: "int", dflt: 5, min: 0, max: 24, label: "Previous passwords that may not be reused", unit: "passwords"}
  })
  pwdInHistory?: int32;
  // NO COMPOSITION RULES (#1444, ASVS 5.0.0 6.2.5). The three rows stay so the
  // entry's shape does not change; crossFieldProblems() refuses any other value.
  @attr(#{
    what: "Always 0. A policy that asks for symbols is refused: ASVS 5.0.0 6.2.5 requires that a password of any composition be accepted, so length is what this policy asks for.",
    field: #{key: "minSymbols", type: "int", dflt: 0, min: 0, max: 16, label: "Minimum number of symbols", unit: "symbols"}
  })
  stsPwdMinSymbols?: int32;
  @attr(#{
    what: "Always off. A policy that requires an uppercase letter is refused: ASVS 5.0.0 6.2.5 requires that a password of any composition be accepted.",
    field: #{key: "requireUppercase", type: "bool", dflt: false, label: "Require an uppercase letter"}
  })
  stsPwdRequireUppercase?: boolean;
  @attr(#{
    what: "Always off. A policy that requires a number is refused: ASVS 5.0.0 6.2.5 requires that a password of any composition be accepted.",
    field: #{key: "requireDigit", type: "bool", dflt: false, label: "Require a number"}
  })
  stsPwdRequireDigit?: boolean;
  @attr(#{
    what: "How long a password this service MAKES UP is — for a new user created from the console or /admin-api, an operator's Generate, and the product-mode bootstrap account. It must be at least the minimum length and at least twice the symbol count plus two. Twenty characters from a 90-character alphabet is about 130 bits.",
    field: #{key: "generatedLength", type: "int", dflt: 20, min: 12, max: 128, label: "Length of a generated password", unit: "characters"}
  })
  stsPwdGeneratedLength?: int32;
  // -------------------------------------------------------------------------
  // HOW A PASSWORD IS STORED (2026-10-22, #847). The algorithm a NEWLY
  // stored password is hashed with, and both algorithms' parameters. Every
  // bound is OWASP's Password Storage Cheat Sheet minimum or above, in both
  // modes (rcbj's decision 2), and `common/crypto.js` clamps to the same
  // floors whatever this table says. A stored hash names its own algorithm
  // and parameters, so changing these reaches the NEXT password set and, at
  // a person's next verified sign-in, their stored hash (`credentials.ts`'s
  // upgrade). OPTIONAL: a save written before these rows existed keeps them.
  // -------------------------------------------------------------------------
  //
  // THE DEFAULT IS scrypt AT THE PRE-#847 PARAMETERS (rcbj, 2026-10-22,
  // #820), which every stored password already is; argon2id is selectable.
  // OWASP's scrypt pairs are reported, not enforced, until #872 makes
  // OWASP's minimum the default.
  // -------------------------------------------------------------------------
  @attr(#{
    what: "The algorithm a newly stored password is hashed with: scrypt (RFC 7914), the default, or argon2id (RFC 9106, the OWASP Password Storage Cheat Sheet's first choice). A stored hash names its own algorithm and parameters and keeps verifying; one that is not in this algorithm with these parameters is hashed again at the person's next verified sign-in. Client secrets, activation tokens, recovery codes and app passwords are not passwords and stay scrypt.",
    field: #{key: "hashAlgorithm", type: "enum", dflt: "scrypt", optional: true, label: "Password hash algorithm"}
  })
  stsPwdHashAlgorithm?: string;
  @attr(#{
    what: "The memory one argon2id hash uses, in kibibytes (m). 19456 KiB (19 MiB) is OWASP's minimum and the least this service will write. Raising it makes a stolen store slower to attack, and every sign-in uses that much more memory.",
    field: #{key: "argon2Memory", type: "int", optional: true, label: "argon2id memory", unit: "KiB"}
  })
  stsPwdArgon2Memory?: int32;
  @attr(#{
    what: "How many passes argon2id makes over its memory (t). 2 is OWASP's minimum at 19 MiB; each pass adds the same time again.",
    field: #{key: "argon2Iterations", type: "int", optional: true, label: "argon2id iterations", unit: "passes"}
  })
  stsPwdArgon2Iterations?: int32;
  @attr(#{
    what: "How many lanes argon2id divides its memory into (p). It is part of the hash, not a thread count: node computes a hash on one thread whatever this says. 1 is OWASP's figure.",
    field: #{key: "argon2Parallelism", type: "int", optional: true, label: "argon2id parallelism", unit: "lanes"}
  })
  stsPwdArgon2Parallelism?: int32;
  @attr(#{
    what: "scrypt's CPU and memory cost for a newly stored password while the algorithm is scrypt, as a power of two: 15 (the default) is N=32768. OWASP's table pairs it with the parallelism: 2^17 with p=1, 2^16 with p=2, 2^15 with p=3, 2^14 with p=5, or 2^13 with p=10. The default, 2^15 with p=1, is below it.",
    field: #{key: "scryptLogN", type: "int", optional: true, label: "scrypt cost (log2 of N)"}
  })
  stsPwdScryptLogN?: int32;
  @attr(#{
    what: "scrypt's block size for a newly stored password while the algorithm is scrypt. Memory is about 128 × N × r bytes; 8 is the figure RFC 7914 and OWASP give.",
    field: #{key: "scryptBlockSize", type: "int", optional: true, label: "scrypt block size (r)"}
  })
  stsPwdScryptBlockSize?: int32;
  @attr(#{
    what: "scrypt's parallelism for a newly stored password while the algorithm is scrypt. Node computes it on one thread, so a higher value costs time rather than cores; the cost's description lists the pairs OWASP accepts.",
    field: #{key: "scryptParallelism", type: "int", optional: true, label: "scrypt parallelism (p)"}
  })
  stsPwdScryptParallelism?: int32;
  @attr(#{
    what: "Which named password policy wins where several are named for one person: the lowest, from 1 to 1000.",
    selector: #{key: "precedence"}
  })
  stsPasswordPrecedence?: unknown;
  @attr(#{
    what: "What the profile is for, for the next person."
  })
  description?: unknown;
}

@entry(#{
  id: "policy.password",
  source: "policy_kinds:password",
  onPerson: true
})
model PolicyPasswordOnPerson {
  @attr(#{what: "One value per remembered previous password, in the draft's form `time#syntaxOID#length#data` — the data being the hash that password was stored under, never the password. Maintained by this service and refused on an LDAP add or modify, because a history anybody can edit is a history anybody can empty."})
  pwdHistory?: unknown;
  @attr(#{what: "When the password was last set, as a GeneralizedTime. Maintained by this service."})
  pwdChangedTime?: unknown;
}
