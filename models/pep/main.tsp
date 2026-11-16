// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The entry point of the remote PEP's model (#1830), compiled by
// models/tools/generate_pep.mjs. Separate from models/main.tsp: the PEP is a
// container of its own, and nothing here is served by the Node service.

import "./pep_service.tsp";
import "./pep_authzen.tsp";
import "./pep_proxy.tsp";
import "./pep_control_plane.tsp";
