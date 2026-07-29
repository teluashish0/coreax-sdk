import fs from "node:fs";
import path from "node:path";

const retiredBrand = ["s", "e", "c", "0"].join("");
const retiredAgentIntegration = ["open", "claw"].join("");
const awsArnPrefix = ["arn", "aws"].join(":");
const forbiddenText = [
  {
    label: "retired product branding",
    pattern: new RegExp(retiredBrand, "i"),
  },
  {
    label: "retired agent-specific integration",
    pattern: new RegExp(retiredAgentIntegration, "i"),
  },
  {
    label: "private key material",
    pattern: /-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)* )?PRIVATE KEY-----/,
  },
  {
    label: "database connection URL",
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'`]+/i,
  },
  {
    label: "cloud object URI",
    pattern: /\b(?:s3|gs|az):\/\/[^\s"'`]+/i,
  },
  {
    label: "cloud resource identifier",
    pattern: new RegExp(
      `\\b(?:${awsArnPrefix}:[^\\s"'\\\`]+|[a-z0-9._%+-]+@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com|AccountKey=[A-Za-z0-9+/=]{20,})\\b`,
      "i",
    ),
  },
  {
    label: "AWS access key",
    pattern: /\bAKIA[A-Z0-9]{16}\b/,
  },
  {
    label: "high-confidence credential",
    pattern:
      /\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|npm_[A-Za-z0-9]{20,})\b/,
  },
  {
    label: "bearer credential",
    pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/i,
  },
];

const forbiddenPath = [
  {
    label: "retired product branding in filename",
    pattern: new RegExp(retiredBrand, "i"),
  },
  {
    label: "retired agent-specific integration in filename",
    pattern: new RegExp(retiredAgentIntegration, "i"),
  },
  {
    label: "environment file",
    pattern: /(^|\/)\.env(?:\.|$)/i,
  },
  {
    label: "private key file",
    pattern: /\.(?:pem|p12|pfx|key)$/i,
  },
  {
    label: "backup artifact",
    pattern: /\.(?:bak|backup|dump|sql)$/i,
  },
  {
    label: "backend artifact",
    pattern: /(^|\/)(?:prisma|migrations|pages\/api|workers?|queues?)(?:\/|$)/i,
  },
];

function isProbablyText(buffer) {
  if (buffer.includes(0)) return false;
  const sample = buffer.subarray(0, Math.min(buffer.length, 8_192));
  let control = 0;
  for (const byte of sample) {
    if (byte < 9 || (byte > 13 && byte < 32)) control += 1;
  }
  return sample.length === 0 || control / sample.length < 0.02;
}

export function scanStandaloneTree(rootDirectory, options = {}) {
  const root = path.resolve(rootDirectory);
  const ignored = new Set(
    options.ignoredDirectories ?? [".git", "node_modules", "dist"],
  );
  const findings = [];

  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && ignored.has(entry.name)) continue;
      const fullPath = path.join(directory, entry.name);
      const relativePath = path.relative(root, fullPath).split(path.sep).join("/");

      for (const rule of forbiddenPath) {
        if (rule.pattern.test(relativePath)) {
          findings.push({ path: relativePath, reason: rule.label });
        }
      }

      if (entry.isDirectory()) {
        visit(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const content = fs.readFileSync(fullPath);
      if (!isProbablyText(content)) continue;
      const text = content.toString("utf8");
      for (const rule of forbiddenText) {
        if (rule.pattern.test(text)) {
          findings.push({ path: relativePath, reason: rule.label });
        }
      }
    }
  }

  visit(root);
  return findings;
}

export function assertStandaloneTree(rootDirectory, options) {
  const findings = scanStandaloneTree(rootDirectory, options);
  if (findings.length === 0) return;
  const details = findings
    .map((finding) => ` - ${finding.path}: ${finding.reason}`)
    .join("\n");
  throw new Error(`Standalone boundary scan failed:\n${details}`);
}
