import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assertStandaloneTree } from "./standalone-scan.mjs";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result.stdout;
}

function relativeFiles(directory) {
  const files = [];

  function visit(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(
          `Build output must not contain symbolic links: ${path.relative(
            directory,
            fullPath,
          )}`,
        );
      }
      if (entry.isDirectory()) {
        visit(fullPath);
        continue;
      }
      if (!entry.isFile()) {
        throw new Error(
          `Build output contains an unsupported entry: ${path.relative(
            directory,
            fullPath,
          )}`,
        );
      }
      files.push(
        path.relative(directory, fullPath).split(path.sep).join("/"),
      );
    }
  }

  visit(directory);
  return files.sort();
}

function expectedBuildFiles(root) {
  const sourceRoot = path.join(root, "src");
  const expected = [];
  for (const source of relativeFiles(sourceRoot)) {
    if (!source.endsWith(".ts") || source.endsWith(".d.ts")) continue;
    const stem = source.slice(0, -".ts".length);
    expected.push(
      `${stem}.d.ts`,
      `${stem}.d.ts.map`,
      `${stem}.js`,
      `${stem}.js.map`,
    );
  }
  return expected.sort();
}

function assertExactBuildManifest(root, expected) {
  const distRoot = path.join(root, "dist");
  if (!fs.existsSync(distRoot) || !fs.statSync(distRoot).isDirectory()) {
    throw new Error("Clean build did not create a dist directory");
  }
  const actual = relativeFiles(distRoot);
  const expectedSet = new Set(expected);
  const actualSet = new Set(actual);
  const missing = expected.filter((file) => !actualSet.has(file));
  const stale = actual.filter((file) => !expectedSet.has(file));
  if (missing.length || stale.length) {
    const details = [
      ...missing.map((file) => ` - missing dist/${file}`),
      ...stale.map((file) => ` - stale dist/${file}`),
    ].join("\n");
    throw new Error(`Build manifest does not match current source:\n${details}`);
  }
}

const root = process.cwd();
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "coreax-pack-"));
try {
  const npmCli = process.env.npm_execpath;
  if (!npmCli) throw new Error("npm_execpath is unavailable");
  const expectedDistFiles = expectedBuildFiles(root);
  run(process.execPath, [npmCli, "run", "build"], { cwd: root });
  assertExactBuildManifest(root, expectedDistFiles);

  const output = run(process.execPath, [
    npmCli,
    "pack",
    "--json",
    "--ignore-scripts",
    "--pack-destination",
    temporary,
  ]);
  const metadata = JSON.parse(output);
  const tarball = path.join(temporary, metadata[0].filename);
  const extracted = path.join(temporary, "extracted");
  fs.mkdirSync(extracted);
  run("tar", ["-xzf", tarball, "-C", extracted]);
  const packageRoot = path.join(extracted, "package");

  assertStandaloneTree(packageRoot, { ignoredDirectories: [] });
  assertExactBuildManifest(packageRoot, expectedDistFiles);
  const allowedTopLevel = new Set([
    "dist",
    "LICENSE",
    "NOTICE",
    "README.md",
    "package.json",
    "public",
  ]);
  const unexpected = fs
    .readdirSync(packageRoot)
    .filter((entry) => !allowedTopLevel.has(entry));
  if (unexpected.length) {
    throw new Error(`Unexpected tarball entries: ${unexpected.join(", ")}`);
  }
  const packagedPublicFiles = relativeFiles(
    path.join(packageRoot, "public"),
  );
  if (
    packagedPublicFiles.length !== 1 ||
    packagedPublicFiles[0] !== "coreax-image.png"
  ) {
    throw new Error(
      `Unexpected public assets: ${packagedPublicFiles.join(", ")}`,
    );
  }

  const packageJson = JSON.parse(
    fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"),
  );
  for (const [subpath, target] of Object.entries(packageJson.exports)) {
    if (subpath === "./package.json") continue;
    for (const relativeTarget of Object.values(target)) {
      const file = path.join(packageRoot, String(relativeTarget));
      if (!fs.existsSync(file)) {
        throw new Error(`Missing built export ${subpath}: ${relativeTarget}`);
      }
    }
  }
  console.log(
    `Tarball verified: ${metadata[0].filename} (${metadata[0].entryCount} entries)`,
  );
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
