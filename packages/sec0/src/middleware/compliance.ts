import { sha256Hex } from "../signer";
import type { AgentGuardFinding } from "./agentGuard";

export type AgentGuardScanFn = (text: string) => Promise<AgentGuardFinding[]> | AgentGuardFinding[];

type ComplianceRuleLocation = "input" | "output" | "both" | "run";
type ComplianceRuleSeverity = "low" | "medium" | "high" | "critical";

type CompiledComplianceRuleApp = {
  policyId: string;
  policyName: string;
  packId: string;
  packName: string;
  ruleId: string;
  location: ComplianceRuleLocation;
  severity: ComplianceRuleSeverity;
  message: string;
  tags: string[];
  type: "regex" | "nl";
  patterns?: RegExp[];
  instruction?: string;
  threshold?: number;
};

function normalizeCompliancePattern(raw: string): { source: string; flags: string } {
  const trimmed = String(raw || "").trim();
  if (trimmed.startsWith("(?i)")) return { source: trimmed.slice(4), flags: "i" };
  return { source: trimmed, flags: "i" };
}

function snippetAround(text: string, re: RegExp): string {
  try {
    const m = text.match(re);
    if (!m) return "";
    const i = (m as any).index ?? 0;
    const start = Math.max(0, i - 40);
    const end = Math.min(text.length, i + (m[0]?.length || 0) + 40);
    return text.slice(start, end);
  } catch {
    return "";
  }
}

export function buildCompliancePackScanners(opts: {
  policyObj: any;
  tenant?: string;
  nlEvaluator?: (input: {
    instruction: string;
    text: string;
    threshold: number;
    llmJudge?: { provider: "openai" | "anthropic"; apiKey?: string; model?: string };
  }) => Promise<{ score: number; matched: boolean; evidence: string } | null>;
}): {
  enabled: boolean;
  onScanPrompt?: AgentGuardScanFn;
  onScanOutput?: AgentGuardScanFn;
  onScanRun?: AgentGuardScanFn;
  ruleAppsCount: number;
} {
  try {
    const policyObj = opts.policyObj;
    const tenantKey = String(opts.tenant || "").trim();

    const llmJudgeCfg = (() => {
      const j = policyObj?.llm_judge || policyObj?.compliance?.llm_judge;
      if (!j || typeof j !== "object") return undefined;
      const prov = String(j.provider || "").toLowerCase();
      if (prov !== "openai" && prov !== "anthropic") return undefined;
      return {
        provider: prov as "openai" | "anthropic",
        apiKey: String(j.api_key || "").trim() || undefined,
        model: String(j.model || "").trim() || undefined,
      };
    })();

    type NlEvalCached = { score: number; matched: boolean; evidence: string; expiresAt: number };
    const nlCache: Map<string, NlEvalCached> = new Map();
    const nlEval = async (input: {
      instruction: string;
      text: string;
      threshold: number;
    }): Promise<NlEvalCached | null> => {
      if (!opts.nlEvaluator) return null;
      const instruction = String(input.instruction || "").trim();
      const threshold = Number.isFinite(input.threshold) ? Math.max(0, Math.min(100, Math.round(input.threshold))) : 50;
      const textRaw = String(input.text || "");
      const text = textRaw.length > 8000 ? textRaw.slice(0, 8000) : textRaw;
      if (!instruction || !text.trim()) return null;

      const cacheKey = sha256Hex(
        Buffer.from(
          JSON.stringify({
            tenant: tenantKey,
            provider: llmJudgeCfg?.provider,
            instruction,
            threshold,
            text,
          }),
        ),
      );
      const hit = nlCache.get(cacheKey);
      const now = Date.now();
      if (hit && hit.expiresAt > now) return hit;

      try {
        const evaluated = await opts.nlEvaluator({
          instruction,
          text,
          threshold,
          ...(llmJudgeCfg ? { llmJudge: llmJudgeCfg } : {}),
        });
        if (!evaluated) return null;
        const out: NlEvalCached = {
          score: evaluated.score,
          matched: evaluated.matched,
          evidence: evaluated.evidence,
          expiresAt: now + 5 * 60 * 1000,
        };
        nlCache.set(cacheKey, out);
        return out;
      } catch {
        return null;
      }
    };

    const compliance = policyObj?.compliance;
    const packs: any[] = Array.isArray(compliance?.packs) ? compliance.packs : [];
    const policies: any[] = Array.isArray(compliance?.policies) ? compliance.policies : [];
    if (!packs.length || !policies.length) return { enabled: false, ruleAppsCount: 0 };

    const packById = new Map<string, any>();
    for (const p of packs) {
      const id = typeof p?.id === "string" ? p.id.trim() : "";
      const name = typeof p?.name === "string" ? p.name.trim() : "";
      if (!id || !name) continue;
      packById.set(id, p);
    }

    const apps: CompiledComplianceRuleApp[] = [];
    for (const pol of policies) {
      if (!pol || pol.enabled !== true) continue;
      const policyId = typeof pol.id === "string" ? pol.id.trim() : "";
      if (!policyId) continue;
      const policyName = (typeof pol.name === "string" ? pol.name.trim() : "") || policyId;
      const packIds: string[] = Array.isArray(pol.pack_ids) ? pol.pack_ids.map((x: any) => String(x)) : [];
      for (const packIdRaw of packIds) {
        const packId = String(packIdRaw || "").trim();
        if (!packId) continue;
        const pack = packById.get(packId);
        if (!pack) continue;
        const packName = (typeof pack.name === "string" ? pack.name.trim() : "") || packId;
        const rules: any[] = Array.isArray(pack.rules) ? pack.rules : [];
        for (const r of rules) {
          const ruleId = typeof r?.id === "string" ? r.id.trim() : "";
          if (!ruleId) continue;
          const location: ComplianceRuleLocation =
            r.location === "input" || r.location === "output" || r.location === "both" || r.location === "run"
              ? r.location
              : "both";
          const severity: ComplianceRuleSeverity =
            r.severity === "low" || r.severity === "medium" || r.severity === "high" || r.severity === "critical"
              ? r.severity
              : "medium";
          const message =
            typeof r.message === "string" && r.message.trim()
              ? r.message.trim()
              : `Compliance rule matched (${packName}:${ruleId})`;
          const typeRaw = (typeof r?.type === "string" ? r.type.trim().toLowerCase() : "") as any;
          const ruleType: "regex" | "nl" | null =
            typeRaw === "nl" ? "nl" : typeRaw === "regex" || !typeRaw ? "regex" : null;
          if (!ruleType) continue;

          let patterns: RegExp[] | undefined;
          let instruction: string | undefined;
          let threshold: number | undefined;

          if (ruleType === "nl") {
            instruction = typeof r?.instruction === "string" ? r.instruction.trim() : "";
            const thr = Number(r?.threshold);
            threshold = Number.isFinite(thr) ? Math.max(0, Math.min(100, Math.round(thr))) : undefined;
            if (!instruction || threshold === undefined) continue;
          } else {
            const patternsRaw: string[] = Array.isArray(r.patterns) ? r.patterns.map((x: any) => String(x)) : [];
            const compiled: RegExp[] = [];
            for (const p of patternsRaw) {
              try {
                const { source, flags } = normalizeCompliancePattern(p);
                if (!source) continue;
                compiled.push(new RegExp(source, flags));
              } catch {
                continue;
              }
            }
            if (compiled.length === 0) continue;
            patterns = compiled;
          }

          const tagSet = new Set<string>();
          tagSet.add(`pack:${packId}`);
          tagSet.add(`policy:${policyId}`);
          tagSet.add(`rule:${ruleId}`);
          tagSet.add(`rule_type:${ruleType}`);
          const extraTags: string[] = Array.isArray(r.tags) ? r.tags.map((x: any) => String(x)) : [];
          for (const t of extraTags) if (t) tagSet.add(t);

          apps.push({
            policyId,
            policyName,
            packId,
            packName,
            ruleId,
            location,
            severity,
            message,
            tags: Array.from(tagSet),
            type: ruleType,
            ...(patterns ? { patterns } : {}),
            ...(instruction ? { instruction } : {}),
            ...(threshold !== undefined ? { threshold } : {}),
          });
        }
      }
    }

    if (apps.length === 0) return { enabled: false, ruleAppsCount: 0 };
    const hasRunRules = apps.some((app) => app.location === "run");

    const scan = async (text: string, loc: "input" | "output" | "run"): Promise<AgentGuardFinding[]> => {
      if (!text || !text.trim()) return [];
      const out: AgentGuardFinding[] = [];
      const maxFindings = 50;
      for (const app of apps) {
        if (loc === "run") {
          if (app.location !== "run") continue;
        } else if (app.location !== "both" && app.location !== loc) {
          continue;
        }

        if (app.type === "regex") {
          const patterns = Array.isArray(app.patterns) ? app.patterns : [];
          for (const re of patterns) {
            if (!re.test(text)) continue;
            out.push({
              code: "agent_policy_violation",
              severity: app.severity as any,
              location: loc,
              message: app.message,
              evidence: snippetAround(text, re),
              tags: app.tags,
              policy_id: app.policyId,
              pack_id: app.packId,
              rule_id: app.ruleId,
              policy_name: app.policyName,
              pack_name: app.packName,
            } as any);
            break;
          }
          if (out.length >= maxFindings) break;
          continue;
        }

        const instruction = String(app.instruction || "").trim();
        const threshold = typeof app.threshold === "number" ? app.threshold : 50;
        if (!instruction) continue;
        const scored = await nlEval({ instruction, text, threshold });
        if (!scored || !scored.matched) continue;
        const scoreText = `score=${scored.score} threshold=${threshold}`;
        const evidence = scored.evidence ? `${scoreText}; ${scored.evidence}` : scoreText;
        out.push({
          code: "agent_policy_violation",
          severity: app.severity as any,
          location: loc,
          message: app.message,
          evidence,
          tags: app.tags,
          policy_id: app.policyId,
          pack_id: app.packId,
          rule_id: app.ruleId,
          policy_name: app.policyName,
          pack_name: app.packName,
        } as any);
        if (out.length >= maxFindings) break;
      }
      return out;
    };

    return {
      enabled: true,
      ruleAppsCount: apps.length,
      onScanPrompt: (text: string) => scan(text, "input"),
      onScanOutput: (text: string) => scan(text, "output"),
      ...(hasRunRules ? { onScanRun: (text: string) => scan(text, "run") } : {}),
    };
  } catch {
    return { enabled: false, ruleAppsCount: 0 };
  }
}
