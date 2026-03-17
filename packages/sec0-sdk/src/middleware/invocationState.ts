import type { EscalationCreateResult } from "../core/contracts";
import type { AgentGuardFinding } from "./agentGuard";
import type { DastFinding } from "./dast";
import type { SastFinding } from "./sast";

export type MiddlewareDecision = "allow" | "deny";
export type MiddlewareScanStatus = "pass" | "fail" | "pending" | undefined;

export interface MiddlewareScanState<TFinding> {
  status?: MiddlewareScanStatus;
  findings?: TFinding[];
  scanId?: string;
  rawKey?: string;
  didRun: boolean;
}

export interface MiddlewareInvocationState {
  decision: MiddlewareDecision;
  violation: string | null;
  result: any;
  error: Error | null;
  escalationResult: EscalationCreateResult | null;
  escalationFailure: string | null;
  inputHash: string | null;
  outputHash: string | null;
  handlerSwapDetected: boolean;
  serverCodeChanged: boolean;
  registryMutation: boolean;
  toolCodeChanged: boolean;
  versionChanged: boolean;
  previousVersion?: string;
  decisionReason?: string;
  riskTags: string[];
  egressDomain?: string;
  fsPath?: string;
  authObj?: Record<string, unknown>;
  contextualEvaluatorFinding: any | null;
  contextualEvaluatorViolation: string | null;
  contextualAgentFindings: AgentGuardFinding[];
  agentFindings?: AgentGuardFinding[];
  agentGuardRawKey?: string;
  sast: MiddlewareScanState<SastFinding>;
  dast: MiddlewareScanState<DastFinding>;
}

export function createMiddlewareInvocationState(): MiddlewareInvocationState {
  return {
    decision: "allow",
    violation: null,
    result: null,
    error: null,
    escalationResult: null,
    escalationFailure: null,
    inputHash: null,
    outputHash: null,
    handlerSwapDetected: false,
    serverCodeChanged: false,
    registryMutation: false,
    toolCodeChanged: false,
    versionChanged: false,
    previousVersion: undefined,
    decisionReason: undefined,
    riskTags: [],
    egressDomain: undefined,
    fsPath: undefined,
    authObj: undefined,
    contextualEvaluatorFinding: null,
    contextualEvaluatorViolation: null,
    contextualAgentFindings: [],
    agentFindings: undefined,
    agentGuardRawKey: undefined,
    sast: {
      status: undefined,
      findings: undefined,
      scanId: undefined,
      rawKey: undefined,
      didRun: false,
    },
    dast: {
      status: undefined,
      findings: undefined,
      scanId: undefined,
      rawKey: undefined,
      didRun: false,
    },
  };
}
