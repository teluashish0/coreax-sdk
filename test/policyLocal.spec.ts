import { describe, expect, it } from "vitest";

import {
  matchesAllowlist,
  normalizeAllowlist,
  parsePolicyYaml,
} from "../src/policy";

describe("local CoreAX policy utilities", () => {
  it("treats missing or malformed allowlists as empty", () => {
    expect(normalizeAllowlist(undefined)).toEqual([]);
    expect(normalizeAllowlist("read@1.0")).toEqual([]);
    expect(matchesAllowlist(undefined, "read@1.0")).toBe(false);
    expect(matchesAllowlist([], "read@1.0")).toBe(false);
  });

  it("matches only explicitly configured tool references", () => {
    expect(matchesAllowlist(["read@1.0"], "read@1.0")).toBe(true);
    expect(matchesAllowlist(["read@1.0"], "delete@1.0")).toBe(false);
    expect(
      matchesAllowlist(
        ["mcp://records/read@1.0"],
        "read@1.0",
        { serverName: "records" },
      ),
    ).toBe(true);
  });

  it("validates YAML before returning a native policy", () => {
    expect(
      parsePolicyYaml(`
version: 1
tools:
  allow:
    - read@1.0
enforcement:
  denyOn:
    - tool_not_in_allowlist
`),
    ).toMatchObject({
      version: 1,
      tools: { allow: ["read@1.0"] },
    });
    expect(() =>
      parsePolicyYaml(`
version: 1
tools:
  allow: "*"
enforcement:
  denyOn: []
`),
    ).toThrow("Invalid CoreAX policy");
  });
});
