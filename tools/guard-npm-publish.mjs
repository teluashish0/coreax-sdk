import fs from "node:fs";
import path from "node:path";

function fail(message) {
  console.error(`[publish-guard] ${message}`);
  process.exit(1);
}

const packageJsonPath = path.resolve(process.cwd(), "package.json");

if (!fs.existsSync(packageJsonPath)) {
  fail(`package.json not found in ${process.cwd()}`);
}

const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));

if (pkg.private === true) {
  fail(
    `${pkg.name} is intentionally private. Publishing is blocked until a dedicated release change explicitly sets private=false.`,
  );
}

if (process.env.SEC0_ALLOW_PUBLISH !== "1") {
  fail("Publishing is blocked by default. Set SEC0_ALLOW_PUBLISH=1 for explicit release intent.");
}

if (process.env.SEC0_PUBLISH_PACKAGE !== pkg.name) {
  fail(`SEC0_PUBLISH_PACKAGE must be set to ${pkg.name}.`);
}

if (!process.env.CI && process.env.SEC0_ALLOW_LOCAL_PUBLISH !== "1") {
  fail("Local publishing is blocked. Publish from CI, or set SEC0_ALLOW_LOCAL_PUBLISH=1 explicitly.");
}

const provenanceConfig =
  process.env.npm_config_provenance ?? process.env.NPM_CONFIG_PROVENANCE ?? "";
const provenanceEnabled = String(provenanceConfig).toLowerCase() === "true";
if (process.env.CI && !provenanceEnabled && process.env.SEC0_ALLOW_NO_PROVENANCE !== "1") {
  fail("npm provenance is required in CI. Re-run with --provenance or set SEC0_ALLOW_NO_PROVENANCE=1 intentionally.");
}

if (!process.env.CI && !provenanceEnabled) {
  console.warn("[publish-guard] Local publish proceeding without npm provenance.");
}

if (!pkg.version || pkg.version === "0.0.0") {
  fail("Package version must be set before publishing.");
}
