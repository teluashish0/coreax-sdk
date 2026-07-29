import fs from "node:fs";
import path from "node:path";
import { assertStandaloneTree } from "./standalone-scan.mjs";

const root = path.resolve(process.argv[2] ?? ".");
assertStandaloneTree(root);

const forbiddenSdkIo = [
  {
    label: "environment-variable read",
    pattern: /\bprocess\s*\.\s*env\b/,
  },
  {
    label: "implicit fetch",
    pattern: /\bfetch\s*\(/,
  },
  {
    label: "implicit HTTP client",
    pattern: /\b(?:https?|net|tls)\s*\.\s*(?:request|get|connect|createConnection)\s*\(/,
  },
  {
    label: "implicit socket client",
    pattern: /\bnew\s+WebSocket\s*\(/,
  },
];

const sourceRoot = path.join(root, "src");
const sdkIoFindings = [];

function scanSource(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      scanSource(fullPath);
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;
    const source = fs.readFileSync(fullPath, "utf8");
    for (const rule of forbiddenSdkIo) {
      if (rule.pattern.test(source)) {
        sdkIoFindings.push(
          `${path.relative(root, fullPath)}: ${rule.label}`,
        );
      }
    }
  }
}

scanSource(sourceRoot);
if (sdkIoFindings.length > 0) {
  throw new Error(
    `Standalone SDK I/O scan failed:\n${sdkIoFindings
      .map((finding) => ` - ${finding}`)
      .join("\n")}`,
  );
}
console.log("Standalone repository boundary verified.");
