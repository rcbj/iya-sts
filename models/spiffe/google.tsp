// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/spiffe/google.tsp
//
// THE WELL-KNOWN TYPES THE SPIFFE PROTOS USE (#1579), as protobufjs defines
// them. **`keepCase: true` does not reach them**, so a `Struct`'s value is
// built with camelCase members (`stringValue`, not `string_value`) while
// every other message here is snake_case — and the wrong spelling
// serialises to NOTHING, with no throw and no warning (`spiffe/CLAUDE.md`,
// TWO gRPC TRAPS). That is why these are written as protobufjs reads them,
// and why the build holds them to that rather than to Google's `.proto`.

import "../lib/spiffe_lib.tsp";
using IyaSts.SpiffeLib;

namespace IyaSts.Spiffe.Google {
  @message("google.protobuf.Struct")
  model Struct {
    @field(1)
    fields?: Record<Value>;
  }

  @message("google.protobuf.Value")
  model Value {
    @field(1)
    @oneof("kind")
    nullValue?: NullValue;

    @field(2)
    @oneof("kind")
    numberValue?: float64;

    @field(3)
    @oneof("kind")
    stringValue?: string;

    @field(4)
    @oneof("kind")
    boolValue?: boolean;

    @field(5)
    @oneof("kind")
    structValue?: Struct;

    @field(6)
    @oneof("kind")
    listValue?: ListValue;
  }

  @protoEnum("google.protobuf.NullValue")
  enum NullValue {
    NULL_VALUE: 0
  }

  @message("google.protobuf.ListValue")
  model ListValue {
    @field(1)
    values?: Value[];
  }

  @message("google.protobuf.Any")
  model Any {
    @field(1)
    type_url?: string;

    @field(2)
    value?: bytes;
  }

  @message("google.protobuf.BoolValue")
  model BoolValue {
    @field(1)
    value?: boolean;
  }

  @message("google.protobuf.StringValue")
  model StringValue {
    @field(1)
    value?: string;
  }

  @message("google.protobuf.Empty")
  model Empty {}
}
