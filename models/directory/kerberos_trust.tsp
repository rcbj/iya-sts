// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/kerberos_trust.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "kerberosTrust",
  source: "catalogue",
  container: "ou=kerberosTrusts",
  ownContainer: true,
  authored: true,
  section: "ldap/ldap_server.js OWN_NAMES",
  note: "One entry per trust with another Kerberos realm.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "stsKrb5Trust",
      standard: false,
      what: "This service's class for this register."
    }
  ]
})
model KerberosTrust {
  @attr(#{
    kind: "single",
    what: "The trust's whole record as one JSON value: the partner Kerberos realm, its NetBIOS name and domain SID, the type, the trust attributes and which keys are held. The attributes beside it mirror it for an ldapsearch. Written by the console and the management API."
  })
  stsKrb5TrustData?: DirectoryJson;
  @attr(#{
    kind: "single",
    what: "The trust's keys or shared passwords, as one JSON value sealed where keys persist. Withheld from every directory read."
  })
  stsKrb5TrustKeys?: string;
  @attr(#{
    kind: "single",
    what: "The partner Kerberos realm, lower-cased, as Active Directory's trustedDomain object names it ([MS-ADTS] 6.1.6.7). A mirror of the record, written with it."
  })
  trustPartner?: string;
  @attr(#{
    kind: "single",
    what: "The partner's NetBIOS domain name ([MS-ADTS] 6.1.6.7). A mirror of the record, written with it."
  })
  flatName?: string;
  @attr(#{
    kind: "single",
    what: "The partner domain's SID, where the trust names one ([MS-ADTS] 6.1.6.7). A mirror of the record, written with it."
  })
  securityIdentifier?: string;
  @attr(#{
    kind: "single",
    what: "1 inbound, 2 outbound, 3 both ([MS-ADTS] 6.1.6.7.12). Derived from which keys the trust holds: the incoming key accepts the partner's tickets, the outgoing key refers this realm's people to the partner."
  })
  trustDirection?: DirectoryInteger;
  @attr(#{
    kind: "single",
    what: "The trust's attribute bits as one integer ([MS-ADTS] 6.1.6.7.9). A mirror of the record, written with it."
  })
  trustAttributes?: DirectoryInteger;
  @attr(#{
    kind: "single",
    what: "2 where the partner is an Active Directory domain (the record names its SID), 3 for any other Kerberos realm ([MS-ADTS] 6.1.6.7.15). Derived, written with the record."
  })
  trustType?: DirectoryInteger;
}
