import * as fs from "node:fs";
import { functionCodeHash } from "./registryState";
import type { DastFinding, DastManager, DastOptions, DastSeverity } from "./dast";
import { maxSeverityOf as maxDastSeverity } from "./dast";
import type { MiddlewareInvocationState } from "./invocationState";
import { persistScanRawIfConfigured, type UploadApiConfig } from "./rawPayloads";
import type { SastFinding, SastHook, SastManager, SastOptions, Severity } from "./sast";
import { maxSeverityOf as maxSastSeverity } from "./sast";

type ToolSpan = { tool: string; startLine: number; endLine: number };
type FileScan = {
  status: "pass" | "fail" | "pending";
  findings: any[];
  scanId?: string;
  raw?: any;
  raw_key?: string;
  updatedAt: number;
};

export type ScanExecutionResult<TFinding> = {
  didRun: boolean;
  status?: "pass" | "fail" | "pending";
  findings?: TFinding[];
  scanId?: string;
  rawKey?: string;
  block: { block: boolean; reason?: string };
  handlerHash: string;
  scopeKey?: string;
};

type CreateScanPipelineOptions = {
  server: { name: string; version: string };
  tenant?: string;
  registrySnapshotHash: string;
  requireUploadConfig: () => UploadApiConfig;
  debugSastEnabled?: boolean;
  debugDastEnabled?: boolean;
  semgrepFallbackScan: SastHook;
  now?: () => number;
  readFile?: (filePath: string) => string;
  persistRaw?: typeof persistScanRawIfConfigured;
};

export function createScanPipeline(opts: CreateScanPipelineOptions) {
  const readFile = opts.readFile ?? ((filePath: string) => fs.readFileSync(filePath, "utf8"));
  const persistRaw = opts.persistRaw ?? persistScanRawIfConfigured;
  const now = opts.now ?? (() => Date.now());
  const spansByFilePath: Map<string, ToolSpan[]> = new Map();
  const fileScanCache: Map<string, FileScan> = new Map();

  const debugSastLog = (...args: any[]) => {
    if (!opts.debugSastEnabled) return;
    try {
      console.log("[sec0-middleware][sast]", ...args);
    } catch {}
  };

  const debugDastLog = (...args: any[]) => {
    if (!opts.debugDastEnabled) return;
    try {
      console.log("[sec0-middleware][dast]", ...args);
    } catch {}
  };

  const computeToolSpans = (filePath: string): ToolSpan[] => {
    try {
      const content = readFile(filePath);
      const spans: ToolSpan[] = [];
      const re = /tool\(\s*'([^']+)'\s*,\s*withSec0Meta\(\s*async\s*\([^)]*\)\s*=>\s*\{/g;
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const tool = match[1];
        let idx = re.lastIndex - 1;
        let depth = 0;
        let startIdx = idx;
        let endIdx = idx;
        for (let i = idx; i < content.length; i++) {
          const ch = content.charAt(i);
          if (ch === "{") {
            depth++;
            if (depth === 1) startIdx = i;
          } else if (ch === "}") {
            depth--;
            if (depth === 0) {
              endIdx = i;
              re.lastIndex = i;
              break;
            }
          }
        }
        const pre = content.slice(0, startIdx);
        const startLine = (pre.match(/\n/g)?.length || 0) + 1;
        const block = content.slice(startIdx, endIdx + 1);
        const endLine = startLine + (block.match(/\n/g)?.length || 0);
        spans.push({ tool, startLine, endLine });
      }
      debugSastLog("computed spans", { filePath, count: spans.length });
      return spans;
    } catch {
      return [];
    }
  };

  const scanFileIfNeeded = async (filePath: string): Promise<FileScan> => {
    const cached = fileScanCache.get(filePath);
    if (cached && cached.status !== "pending") return cached;
    const handlerHash = functionCodeHash(filePath);
    const result = await opts.semgrepFallbackScan({
      server: opts.server,
      tool: "FILE",
      handlerHash,
      filePath,
    });
    const fileScan: FileScan = {
      status: result.status,
      findings: (result.findings || []) as any[],
      scanId: result.scanId,
      raw: (result as any)?.raw,
      raw_key: (result as any)?.raw_key,
      updatedAt: now(),
    };
    fileScanCache.set(filePath, fileScan);
    return fileScan;
  };

  return {
    async runSast(input: {
      tool: string;
      handler: any;
      currentHandler: any;
      toolFilePath?: string;
      manager: SastManager;
      state: MiddlewareInvocationState;
      addAttrs: (attrs: Record<string, any>) => void;
      runOnChangeOnly: boolean;
      blockOnChange?: SastOptions["block_on_change"];
      blockOnSeverity?: SastOptions["block_on_severity"];
    }): Promise<ScanExecutionResult<SastFinding>> {
      const handlerHash = (input.currentHandler as any)?.__sec0_handler_hash || functionCodeHash(input.currentHandler);
      const shouldRunNow =
        input.state.toolCodeChanged ||
        input.state.serverCodeChanged ||
        (!input.runOnChangeOnly && !input.manager.getCached(handlerHash));
      if (!shouldRunNow) {
        return { didRun: false, block: { block: false }, handlerHash };
      }

      debugSastLog("using filePath", { tool: input.tool, filePath: input.toolFilePath || null });
      let block: { block: boolean; reason?: string } = { block: false };
      if (input.toolFilePath) {
        if (!spansByFilePath.has(input.toolFilePath)) {
          spansByFilePath.set(input.toolFilePath, computeToolSpans(input.toolFilePath));
        }
        const fileResult = await scanFileIfNeeded(input.toolFilePath);
        const spans = spansByFilePath.get(input.toolFilePath) || [];
        const span = spans.find((entry) => entry.tool === input.tool);
        const findings = span
          ? (fileResult.findings || []).filter((finding: any) => {
              const line = Number((finding && (finding.startLine ?? finding.start?.line)) || 0);
              const fileOk = !finding.file || String(finding.file).endsWith(input.toolFilePath!);
              return fileOk && line >= span.startLine && line <= span.endLine;
            })
          : [];
        input.state.sast.status = fileResult.status;
        input.state.sast.findings = findings as any;
        input.state.sast.scanId = fileResult.scanId;
        input.state.sast.didRun = true;
        if (findings.length) {
          const max = maxSastSeverity(findings as any);
          if (max) input.addAttrs({ "sast.max_severity": max });
        }
        if ((fileResult as any).raw && !(fileResult as any).raw_key) {
          const key = await persistRaw({
            tenant: opts.tenant,
            level: "middleware",
            kind: "sast",
            scanId: fileResult.scanId || handlerHash.slice(0, 12),
            raw: (fileResult as any).raw,
            uploadConfig: opts.requireUploadConfig(),
          });
          if (key) {
            (fileResult as any).raw_key = key;
            input.state.sast.rawKey = key;
          }
        } else if ((fileResult as any).raw_key) {
          input.state.sast.rawKey = (fileResult as any).raw_key;
        }
        block = input.manager.shouldBlock(
          { status: fileResult.status, findings } as any,
          input.blockOnChange,
          input.blockOnSeverity,
        );
      } else {
        const cached = input.manager.ensureScan(handlerHash, {
          server: opts.server,
          tool: input.tool,
          handlerHash,
          source: Function.prototype.toString.call(input.handler),
        });
        if (cached.status === "pending") {
          const result = await opts.semgrepFallbackScan({
            server: opts.server,
            tool: input.tool,
            handlerHash,
            source: Function.prototype.toString.call(input.handler),
          });
          (cached as any).status = result.status;
          (cached as any).findings = result.findings;
          (cached as any).scanId = result.scanId;
          (cached as any).raw = (result as any)?.raw;
          (cached as any).updatedAt = now();
        }
        input.state.sast.status = cached.status;
        input.state.sast.findings = cached.findings as any;
        input.state.sast.scanId = cached.scanId;
        input.state.sast.didRun = true;
        if (cached.findings?.length) {
          const max = maxSastSeverity(cached.findings as any);
          if (max) input.addAttrs({ "sast.max_severity": max });
        }
        if ((cached as any).raw && !cached.raw_key) {
          const key = await persistRaw({
            tenant: opts.tenant,
            level: "middleware",
            kind: "sast",
            scanId: cached.scanId || handlerHash.slice(0, 12),
            raw: (cached as any).raw,
            uploadConfig: opts.requireUploadConfig(),
          });
          if (key) {
            (cached as any).raw_key = key;
            input.state.sast.rawKey = key;
          }
        } else if (cached.raw_key) {
          input.state.sast.rawKey = cached.raw_key;
        }
        block = input.manager.shouldBlock(cached, input.blockOnChange, input.blockOnSeverity);
      }

      return {
        didRun: input.state.sast.didRun,
        status: input.state.sast.status,
        findings: input.state.sast.findings,
        scanId: input.state.sast.scanId,
        rawKey: input.state.sast.rawKey,
        block,
        handlerHash,
      };
    },

    async runDast(input: {
      tool: string;
      currentHandler: any;
      manager: DastManager;
      state: MiddlewareInvocationState;
      mode?: DastOptions["mode"];
      scope?: DastOptions["scope"];
      sandboxUrl?: string;
      runOnChangeOnly: boolean;
      blockOnChange?: DastOptions["block_on_change"];
      blockOnSeverity?: DastSeverity;
      blockOnCount?: DastOptions["block_on_count"];
      forceRawUpload?: boolean;
      enableDynamicBlockTtl?: boolean;
    }): Promise<ScanExecutionResult<DastFinding>> {
      const handlerHash = (input.currentHandler as any)?.__sec0_handler_hash || functionCodeHash(input.currentHandler);
      const scopeKey = input.scope === "server" ? opts.registrySnapshotHash : handlerHash;
      const shouldRun =
        input.state.toolCodeChanged ||
        input.state.serverCodeChanged ||
        (!input.runOnChangeOnly && !input.manager.getCached(scopeKey));
      const cached = shouldRun
        ? input.mode === "sync"
          ? await input.manager.ensureScanSync(scopeKey, {
              server: opts.server,
              tool: input.tool,
              handlerHash: scopeKey,
              sandboxUrl: input.sandboxUrl,
            })
          : input.manager.ensureScan(scopeKey, {
              server: opts.server,
              tool: input.tool,
              handlerHash: scopeKey,
              sandboxUrl: input.sandboxUrl,
            })
        : input.manager.getCached(scopeKey);

      debugDastLog("result", {
        tool: input.tool,
        mode: input.mode || "async",
        status: cached?.status,
        findings: (cached?.findings || []).length,
      });

      if (cached) {
        input.state.dast.status = cached.status;
        input.state.dast.findings = cached.findings as any;
        input.state.dast.scanId = cached.scanId;
        input.state.dast.didRun = true;
        if ((cached as any).raw && (!cached.raw_key || input.forceRawUpload)) {
          const key = await persistRaw({
            tenant: opts.tenant,
            level: "middleware",
            kind: "dast",
            scanId: cached.scanId || handlerHash.slice(0, 12),
            raw: (cached as any).raw,
            uploadConfig: opts.requireUploadConfig(),
          });
          if (key) {
            (cached as any).raw_key = key;
            input.state.dast.rawKey = key;
          }
        } else if (cached.raw_key) {
          input.state.dast.rawKey = cached.raw_key;
        }
      }

      const block = input.manager.shouldBlock(
        cached,
        input.blockOnChange,
        input.blockOnSeverity,
        input.blockOnCount,
      );
      if (block.block && input.enableDynamicBlockTtl && block.reason === "dast_failed") {
        input.manager.setDynamicBlock(input.tool);
      }

      return {
        didRun: input.state.dast.didRun,
        status: input.state.dast.status,
        findings: input.state.dast.findings,
        scanId: input.state.dast.scanId,
        rawKey: input.state.dast.rawKey,
        block,
        handlerHash,
        scopeKey,
      };
    },
  };
}
