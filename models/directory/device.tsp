// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/device.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/devices.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "device",
  source: "./devices",
  container: "ou=devices",
  ownContainer: false,
  authored: true,
  objectClasses: #[
    #{
      name: "device",
      where: "RFC 4519 section 3.4",
      standard: true,
      what: "cn, and the standard owner and description."
    },
    #{
      name: "stsDevice",
      where: "this service (#130, #164)",
      standard: false,
      what: "Every stsDevice* attribute below: the owner's kind, the applications, the keys, attestation, compliance, status, the descriptive labels, the enrolment and Native SSO."
    }
  ]
})
model Device {
  @attr(#{
    kind: "single",
    what: "The device id, a UUID."
  })
  cn?: string;
  @attr(#{
    kind: "single",
    what: "The DN of its one owner: a person or an application."
  })
  owner?: string;
  @attr(#{
    kind: "single",
    what: "person or application."
  })
  stsDeviceOwnerKind?: string;
  @attr(#{
    kind: "single",
    what: "Its label."
  })
  description?: string;
  @attr(#{
    kind: "multi",
    what: "The DN of every application that used it."
  })
  @link(#{to: "application", cardinality: "multi", owns: false, what: "The applications that used this device."})
  stsDeviceApplication?: string[];
  @attr(#{
    kind: "multi",
    what: "One JSON value per key: id, kind (x509, jwk, webauthn), thumbprint, label, added, addedBy, proof, attestation and the public material. Never a secret."
  })
  stsDeviceKey?: string[];
  @attr(#{
    kind: "multi",
    what: "<kind>:<thumbprint> per key, derived from stsDeviceKey on every write so an LDAP filter can find a device by its key."
  })
  stsDeviceKeyThumbprint?: string[];
  @attr(#{
    kind: "multi",
    what: "The credential id of each linked WebAuthn key, derived from stsDeviceKey on every write so a sign-in finds its device by index."
  })
  stsDeviceCredentialId?: string[];
  @attr(#{
    kind: "multi",
    what: "The id of each key attested by an Android chain whose serials were kept, derived from stsDeviceKey on every write so the Android attestation recheck reads only the devices holding one (#615)."
  })
  stsDeviceAndroidKey?: string[];
  @attr(#{
    kind: "single",
    what: "attested when any key's attestation was verified, else self-asserted. Derived on every write."
  })
  stsDeviceAttestation?: string;
  @attr(#{
    kind: "single",
    what: "compliant or not-compliant; absent is unknown."
  })
  stsDeviceCompliance?: string;
  @attr(#{
    kind: "single",
    what: "JSON: the last compliance change — status, previous, at, source (admin, mdm, test-control, caep), actor, reason."
  })
  stsDeviceComplianceChange?: string;
  @attr(#{
    kind: "single",
    what: "compromised; absent is active."
  })
  stsDeviceStatus?: string;
  @attr(#{
    kind: "single",
    what: "JSON: the last status change."
  })
  stsDeviceStatusChange?: string;
  @attr(#{
    kind: "single",
    what: "LOW, MEDIUM or HIGH (CAEP's risk levels); absent is unassessed. Set by risk scoring and by a compromise."
  })
  stsDeviceRiskLevel?: string;
  @attr(#{
    kind: "single",
    what: "JSON: the last risk level change — level, previous, at, source (risk, compromise, admin), actor, reason."
  })
  stsDeviceRiskChange?: string;
  @attr(#{
    kind: "single",
    what: "JSON: a remembered browser's state (#265) — the token generation, when it and the one before were issued, the browser it was bound to, and when the second factor was last given on it. No token and no secret."
  })
  stsDeviceBrowser?: string;
  @attr(#{
    kind: "single",
    what: "ios, ipados, android, macos, windows, linux, chromeos or other."
  })
  stsDevicePlatform?: string;
  @attr(#{
    kind: "single",
    what: "Descriptive."
  })
  stsDeviceModel?: string;
  @attr(#{
    kind: "single",
    what: "Descriptive."
  })
  stsDeviceOs?: string;
  @attr(#{
    kind: "single",
    what: "JSON: method (native-sso, admin, portal, est, scep), at, actor."
  })
  stsDeviceEnrolment?: string;
  @attr(#{
    kind: "single",
    sensitive: true,
    what: "SHA-256 of its Native SSO device_secret. Withheld from every LDAP read."
  })
  stsDeviceSecretHash?: string;
  @attr(#{
    kind: "single",
    what: "The sign-on session the secret is good for."
  })
  stsDeviceSession?: string;
  @attr(#{
    kind: "single",
    what: "When it was last used, ISO 8601."
  })
  stsDeviceLastUsed?: string;
}
