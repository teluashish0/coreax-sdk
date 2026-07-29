import fs from "node:fs";

const allowedLicenses = new Set([
  "0BSD",
  "Apache-2.0",
  "BSD-3-Clause",
  "BlueOak-1.0.0",
  "ISC",
  "MIT",
  "MPL-2.0",
  "Unlicense",
]);

const lockfile = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const findings = [];
const counts = new Map();

for (const [packagePath, metadata] of Object.entries(
  lockfile.packages ?? {},
)) {
  if (!packagePath || metadata.link === true) continue;
  const license = metadata.license;
  if (typeof license !== "string" || !license.trim()) {
    findings.push(`${packagePath}: missing license metadata`);
    continue;
  }
  counts.set(license, (counts.get(license) ?? 0) + 1);
  if (!allowedLicenses.has(license)) {
    findings.push(`${packagePath}: unreviewed license ${license}`);
  }
}

if (findings.length > 0) {
  throw new Error(
    `Dependency license audit failed:\n${findings
      .map((finding) => ` - ${finding}`)
      .join("\n")}`,
  );
}

const summary = [...counts.entries()]
  .sort(([left], [right]) => left.localeCompare(right))
  .map(([license, count]) => `${license}:${count}`)
  .join(", ");
console.log(`Dependency licenses verified (${summary}).`);
