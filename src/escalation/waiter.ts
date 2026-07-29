import {
  EscalationAbortError,
  EscalationNotFoundError,
  EscalationTimeoutError,
} from "./errors";
import type { EscalationState, EscalationWaitOptions } from "./types";

export interface WaitForEscalationResolutionInput {
  escalationId: string;
  getState: (escalationId: string) => Promise<EscalationState | null>;
  options?: EscalationWaitOptions;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

function positiveInteger(
  value: number | undefined,
  fallback: number,
  label: string,
): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive finite number`);
  }
  return Math.max(1, Math.floor(value));
}

function abortIfNeeded(signal: AbortSignal | undefined, escalationId: string): void {
  if (signal?.aborted) {
    throw new EscalationAbortError(escalationId);
  }
}

export async function waitForEscalationResolution(
  input: WaitForEscalationResolutionInput,
): Promise<EscalationState> {
  const now = input.now ?? (() => Date.now());
  const sleep =
    input.sleep ??
    ((milliseconds: number) =>
      new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const timeoutMs = positiveInteger(
    input.options?.timeoutMs,
    10 * 60 * 1000,
    "timeoutMs",
  );
  const pollIntervalMs = positiveInteger(
    input.options?.pollIntervalMs,
    250,
    "pollIntervalMs",
  );
  const startedAt = now();

  while (true) {
    abortIfNeeded(input.options?.signal, input.escalationId);
    const state = await input.getState(input.escalationId);
    if (!state) {
      throw new EscalationNotFoundError(input.escalationId);
    }
    if (state.status !== "pending") {
      return state;
    }
    if (now() - startedAt >= timeoutMs) {
      throw new EscalationTimeoutError(input.escalationId, timeoutMs);
    }
    await sleep(pollIntervalMs);
    abortIfNeeded(input.options?.signal, input.escalationId);
  }
}
