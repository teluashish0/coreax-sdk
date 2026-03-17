import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import sec0, {
  getSec0PackageInfo,
  SEC0_PACKAGE_NAME,
  SEC0_RESERVED,
  SEC0_RESERVED_MESSAGE,
} from "../src";

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

describe("sec0 package surface", () => {
  const packageDir = path.resolve(__dirname, "..");
  const packageJson = readJson(path.join(packageDir, "package.json"));

  it("keeps the canonical placeholder package identity", () => {
    expect(packageJson.name).toBe("sec0");
    expect(packageJson.description).toContain("Reserved placeholder");
    expect(packageJson.sideEffects).toBe(false);
    expect(packageJson.dependencies ?? {}).toEqual({});
    expect(Object.keys(packageJson.exports)).toEqual([".", "./package.json"]);
  });

  it("exports reservation metadata for npm consumers", () => {
    const info = getSec0PackageInfo();

    expect(SEC0_PACKAGE_NAME).toBe("sec0");
    expect(SEC0_RESERVED).toBe(true);
    expect(SEC0_RESERVED_MESSAGE).toContain("reserved");
    expect(info).toEqual({
      name: "sec0",
      reserved: true,
      message: SEC0_RESERVED_MESSAGE,
    });
    expect(sec0).toEqual(info);
  });
});
