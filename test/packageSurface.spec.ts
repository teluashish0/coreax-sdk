import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function siblingPackagePath(packageDir: string, packageName: string): string {
  const candidates = [
    path.join(packageDir, "..", packageName, "package.json"),
    path.join(packageDir, "..", "..", packageName, "package.json"),
  ];
  const resolved = candidates.find((candidate) => fs.existsSync(candidate));
  if (!resolved) {
    throw new Error(`missing sibling package manifest for ${packageName}`);
  }
  return resolved;
}

describe("sec0-sdk package surface", () => {
  const packageDir = path.resolve(__dirname, "..");
  const packageJson = readJson(path.join(packageDir, "package.json"));
  const middlewareIndexPath = path.join(packageDir, "src", "middleware", "index.ts");

  it("keeps the canonical OSS sec0 export surface on the workspace package", () => {
    expect(packageJson.name).toBe("sec0-sdk");

    const expectedSubpaths = [
      ".",
      "./policy",
      "./evaluator",
      "./signer",
      "./runtime-adapter",
      "./core",
      "./agent-state",
      "./mandate-ap2",
      "./audit",
      "./otel",
      "./middleware",
      "./escalation",
      "./guard",
      "./governance",
      "./instrumentation",
      "./gateway",
      "./integrations/openclaw",
    ];

    for (const subpath of expectedSubpaths) {
      expect(packageJson.exports).toHaveProperty(subpath);
    }
  });

  it("prevents legacy standalone copies from reclaiming canonical package identities", () => {
    const legacyPackages = [
      {
        path: siblingPackagePath(packageDir, "sec0-client-sdk"),
        canonicalName: "@sec0/client-sdk",
      },
    ];

    for (const legacyPackage of legacyPackages) {
      const legacyManifest = readJson(legacyPackage.path);
      expect(legacyManifest.private).toBe(true);
      expect(legacyManifest.name).not.toBe(legacyPackage.canonicalName);
    }
  });

  it("keeps middleware/index.ts as a thin public barrel", () => {
    const middlewareIndex = fs.readFileSync(middlewareIndexPath, "utf8");
    const lineCount = middlewareIndex.trim().split("\n").length;

    expect(lineCount).toBeLessThan(140);
    expect(middlewareIndex).toContain('export * from "./securityMiddleware";');
    expect(middlewareIndex).not.toContain("const SDK_VERSION");
    expect(middlewareIndex).not.toContain("export const sec0SecurityMiddleware =");
  });
});
