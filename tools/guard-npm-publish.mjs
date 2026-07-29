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

if (process.env.COREAX_PUBLISH_APPROVED !== "1") {
  fail("Publishing is blocked without COREAX_PUBLISH_APPROVED=1.");
}

if (process.env.COREAX_PUBLISH_PACKAGE !== pkg.name) {
  fail(`COREAX_PUBLISH_PACKAGE must be set to ${pkg.name}.`);
}

if (process.env.COREAX_PUBLISH_VERSION !== pkg.version) {
  fail(`COREAX_PUBLISH_VERSION must be set to ${pkg.version}.`);
}

if (!process.env.CI && process.env.COREAX_LOCAL_PUBLISH_APPROVED !== "1") {
  fail("Local publishing is blocked without COREAX_LOCAL_PUBLISH_APPROVED=1.");
}

if (
  process.env.CI &&
  (process.env.GITHUB_REF_TYPE !== "tag" ||
    process.env.GITHUB_REF_NAME !== `v${pkg.version}`)
) {
  fail(`CI publishing requires the exact v${pkg.version} tag.`);
}

const provenanceConfig =
  process.env.npm_config_provenance ?? process.env.NPM_CONFIG_PROVENANCE ?? "";
const provenanceEnabled = String(provenanceConfig).toLowerCase() === "true";
if (process.env.CI && !provenanceEnabled) {
  fail("npm provenance is required in CI.");
}

if (!process.env.CI && !provenanceEnabled) {
  console.warn("[publish-guard] Local publish proceeding without npm provenance.");
}

if (!pkg.version || pkg.version === "0.0.0") {
  fail("Package version must be set before publishing.");
}
