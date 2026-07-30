import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

interface ModuleExportTarget {
  types: string;
  default: string;
}

interface PackageManifest {
  name: string;
  private: boolean;
  version: string;
  description: string;
  license: string;
  author: string;
  packageManager: string;
  engines: Record<string, string>;
  main: string;
  types: string;
  exports: Record<string, ModuleExportTarget | string>;
  files: string[];
  publishConfig: Record<string, string>;
  scripts: Record<string, string>;
  repository: Record<string, string>;
  homepage: string;
  bugs: Record<string, string>;
  keywords: string[];
}

const PACKAGE_DIR = path.resolve(__dirname, "..");
const PACKAGE_JSON_PATH = path.join(PACKAGE_DIR, "package.json");
const packageJson = JSON.parse(
  fs.readFileSync(PACKAGE_JSON_PATH, "utf8"),
) as PackageManifest;

const CANONICAL_MODULE_SUBPATHS = [
  ".",
  "./policy",
  "./evaluator",
  "./signer",
  "./runtime-adapter",
  "./core",
  "./audit",
  "./middleware",
  "./escalation",
  "./guard",
  "./governance",
  "./runtime-risk",
  "./policy-learning",
  "./instrumentation",
  "./integrations/custom-agent",
] as const;

const CANONICAL_EXPORTS = [
  ...CANONICAL_MODULE_SUBPATHS,
  "./package.json",
] as const;

function moduleStem(subpath: (typeof CANONICAL_MODULE_SUBPATHS)[number]): string {
  return subpath === "." ? "" : subpath.slice(2);
}

function expectedExportTarget(
  subpath: (typeof CANONICAL_MODULE_SUBPATHS)[number],
): ModuleExportTarget {
  const stem = moduleStem(subpath);
  const outputStem = stem ? `./dist/${stem}/index` : "./dist/index";
  return {
    types: `${outputStem}.d.ts`,
    default: `${outputStem}.js`,
  };
}

function sourceEntrypoint(
  subpath: (typeof CANONICAL_MODULE_SUBPATHS)[number],
): string {
  const stem = moduleStem(subpath);
  return path.join(PACKAGE_DIR, "src", stem, "index.ts");
}

describe("@coreax/sdk package surface", () => {
  it("uses the canonical standalone 1.0.0 metadata", () => {
    expect(packageJson).toMatchObject({
      name: "@coreax/sdk",
      private: false,
      version: "1.0.0",
      description:
        "Standalone deterministic security boundary for untrusted AI and agent actions.",
      license: "Apache-2.0",
      author: "WormAI, Inc.",
      packageManager: "npm@10.8.2",
      engines: {
        node: ">=20",
      },
      main: "dist/index.js",
      types: "dist/index.d.ts",
      files: [
        "dist",
        "public/coreax-image.png",
        "README.md",
        "LICENSE",
        "NOTICE",
      ],
      publishConfig: {
        access: "public",
      },
      repository: {
        type: "git",
        url: "git+https://github.com/teluashish0/coreax-sdk.git",
      },
      homepage: "https://github.com/teluashish0/coreax-sdk#readme",
      bugs: {
        url: "https://github.com/teluashish0/coreax-sdk/issues",
      },
      keywords: [
        "coreax",
        "security",
        "ai",
        "agents",
        "guardrails",
        "governance",
        "audit",
        "runtime-risk",
        "policy-learning",
      ],
    });
    expect(packageJson.scripts.prepublishOnly).toBe(
      "npm run publish:guard && npm run verify",
    );
  });

  it("declares exactly the canonical public subpaths", () => {
    expect(Object.keys(packageJson.exports)).toEqual(CANONICAL_EXPORTS);
  });

  it.each(CANONICAL_MODULE_SUBPATHS)(
    "maps %s to matching JavaScript, declarations, and a source entrypoint",
    (subpath) => {
      const target = packageJson.exports[subpath];
      expect(target).toEqual(expectedExportTarget(subpath));

      const sourcePath = sourceEntrypoint(subpath);
      expect(fs.statSync(sourcePath).isFile()).toBe(true);
      expect(fs.readFileSync(sourcePath, "utf8").trim()).not.toBe("");
    },
  );

  it("exports only the package manifest as a JSON subpath", () => {
    expect(packageJson.exports["./package.json"]).toBe("./package.json");
    expect(fs.statSync(PACKAGE_JSON_PATH).isFile()).toBe(true);
  });
});
