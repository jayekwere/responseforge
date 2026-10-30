import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOperation } from "../web/contract.js";

test("operation contract rejects foreign tenant and unknown commands", () => {
  assert.throws(() => parseOperation({ operation: "execute", tenant: "other" }));
  assert.throws(() => parseOperation({ operation: "arbitrary-shell" }));
  assert.equal(parseOperation({ operation: "list" }).operation, "list");
});
