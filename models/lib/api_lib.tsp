// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the API namespace of the abstract model (#1390). The types
// in `models/api/` carry the structure of each schema; `@js` carries whatever
// JSON Schema says that a TypeSpec type does not.

import "./api_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.ApiLib;

extern dec apiDocument(target: Namespace, top: valueof unknown);
extern dec endpoint(target: Operation, path: valueof string,
  method: valueof string, detail: valueof unknown);
extern dec js(target: unknown, extras: valueof unknown);
extern dec hoisted(target: unknown);
extern dec component(target: unknown);
extern dec projects(target: unknown, concept: valueof string);
