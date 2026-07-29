import {
  computeBehaviorDrift,
  type BehaviorDriftConfigOverrides,
} from "./behaviorDrift";
import {
  computeDataExposureRisk,
  type DataExposureConfig,
} from "./dataExposure";
import {
  computeGoldenPathDrift,
  type GoldenPathDriftConfig,
} from "./goldenPathDrift";
import {
  computeMandateDeviation,
  type MandateDeviationConfig,
} from "./mandateDeviation";
import {
  computeCrossNodePropagation,
  computeStatePersistence,
  scoreStatePersistenceViolations,
  statePersistenceSignals,
  type StatePersistenceConfig,
} from "./statePersistence";
import type {
  RuntimeRiskAssessment,
  RuntimeRiskEvent,
  RuntimeRiskNodeAssessment,
  RuntimeRiskSignal,
  RuntimeRiskSubscores,
  SensitiveStateRule,
} from "./types";
import {
  assertUniqueEventIds,
  clamp,
  finiteConfigNumber,
  safeIdentifier,
  safeModelVersion,
  sortedEvents,
  toIso,
} from "./util";

export type RuntimeRiskConfig = {
  modelVersion: string;
  maximumSignals: number;
  behaviorDrift?: BehaviorDriftConfigOverrides;
  goldenPathDrift?: Partial<GoldenPathDriftConfig>;
  statePersistence?: Partial<StatePersistenceConfig>;
  dataExposure?: Partial<DataExposureConfig>;
  mandateDeviation?: Partial<MandateDeviationConfig>;
};

export const DEFAULT_RUNTIME_RISK_CONFIG: RuntimeRiskConfig = Object.freeze({
  modelVersion: "coreax-runtime-risk-v1",
  maximumSignals: 100,
});

export type AssessRunRiskInput = {
  runId: string;
  events: readonly RuntimeRiskEvent[];
  baselineEvents?: readonly RuntimeRiskEvent[];
  sensitiveStateRules?: readonly SensitiveStateRule[];
  config?: Partial<RuntimeRiskConfig>;
};

function sortedSignals(
  signals: readonly RuntimeRiskSignal[],
  maximum: number,
): RuntimeRiskSignal[] {
  return [...signals]
    .sort(
      (left, right) =>
        right.score - left.score ||
        left.code.localeCompare(right.code) ||
        (left.hop?.eventId ?? "").localeCompare(right.hop?.eventId ?? ""),
    )
    .slice(0, Math.max(0, Math.floor(maximum)));
}

function emptySubscores(): RuntimeRiskSubscores {
  return {
    behavior_drift: 0,
    golden_path_drift: 0,
    state_persistence: 0,
    data_exposure_risk: 0,
    mandate_deviation: 0,
  };
}

function withModelVersion<T extends { modelVersion?: string }>(
  config: T | undefined,
  modelVersion: string,
): T & { modelVersion: string } {
  return { ...(config ?? ({} as T)), modelVersion: config?.modelVersion ?? modelVersion };
}

function assertRunEvents(
  runId: string,
  events: readonly RuntimeRiskEvent[],
): void {
  if (typeof runId !== "string" || !runId.trim()) {
    throw new TypeError("runId must be a non-empty string");
  }
  if (runId !== runId.trim()) {
    throw new TypeError("runId must not contain surrounding whitespace");
  }
  for (const event of events) {
    if (typeof event.runId !== "string" || !event.runId.trim()) {
      throw new TypeError(
        `event ${safeIdentifier(event.id)} is missing runId`,
      );
    }
    if (typeof event.nodeId !== "string" || !event.nodeId.trim()) {
      throw new TypeError(`event ${safeIdentifier(event.id)} is missing nodeId`);
    }
    if (
      event.nodeId !== event.nodeId.trim() ||
      event.runId !== event.runId.trim()
    ) {
      throw new TypeError(
        `event ${safeIdentifier(event.id)} has a non-canonical identifier`,
      );
    }
    if (event.runId !== runId) {
      throw new RangeError(
        `event ${safeIdentifier(event.id)} belongs to a different run`,
      );
    }
  }
}

function assertBaselineEvents(events: readonly RuntimeRiskEvent[]): void {
  for (const event of events) {
    if (typeof event.runId !== "string" || !event.runId.trim()) {
      throw new TypeError(
        `baseline event ${safeIdentifier(event.id)} is missing runId`,
      );
    }
    if (typeof event.nodeId !== "string" || !event.nodeId.trim()) {
      throw new TypeError(
        `baseline event ${safeIdentifier(event.id)} is missing nodeId`,
      );
    }
    if (
      event.nodeId !== event.nodeId.trim() ||
      event.runId !== event.runId.trim()
    ) {
      throw new TypeError(
        `baseline event ${safeIdentifier(event.id)} has a non-canonical identifier`,
      );
    }
  }
}

/**
 * Assess an entire run using only caller-provided events and configuration.
 *
 * The aggregate is a maximum, so a severe deterministic boundary violation
 * cannot be diluted by unrelated low-risk nodes or subscores.
 */
export function assessRunRisk(
  input: AssessRunRiskInput,
): RuntimeRiskAssessment {
  assertRunEvents(input.runId, input.events);
  assertBaselineEvents(input.baselineEvents ?? []);
  assertUniqueEventIds([
    ...input.events,
    ...(input.baselineEvents ?? []),
  ]);
  const modelVersion = safeModelVersion(
    input.config?.modelVersion ?? DEFAULT_RUNTIME_RISK_CONFIG.modelVersion,
  );
  const maximumSignals = finiteConfigNumber(
    input.config?.maximumSignals ??
      DEFAULT_RUNTIME_RISK_CONFIG.maximumSignals,
    "runtimeRisk.maximumSignals",
    { minimum: 1, maximum: 10_000, integer: true },
  );
  const config: RuntimeRiskConfig = {
    ...DEFAULT_RUNTIME_RISK_CONFIG,
    ...input.config,
    modelVersion,
    maximumSignals,
  };
  const events = sortedEvents(input.events);
  const baseline = sortedEvents(
    (input.baselineEvents ?? []).filter(
      (event) => event.runId !== input.runId,
    ),
  );
  const rules = input.sensitiveStateRules ?? [];

  const eventsByNode = new Map<string, RuntimeRiskEvent[]>();
  for (const event of events) {
    const nodeEvents = eventsByNode.get(event.nodeId) ?? [];
    nodeEvents.push(event);
    eventsByNode.set(event.nodeId, nodeEvents);
  }
  const baselineByNode = new Map<string, RuntimeRiskEvent[]>();
  for (const event of baseline) {
    const nodeEvents = baselineByNode.get(event.nodeId) ?? [];
    nodeEvents.push(event);
    baselineByNode.set(event.nodeId, nodeEvents);
  }
  const crossNodeViolations = computeCrossNodePropagation({
    eventsByNode,
    sensitiveStateRules: rules,
    config: config.statePersistence,
  });
  const currentNodeIds = new Set(events.map((event) => event.nodeId));
  const baselineNodeIds = new Set(baseline.map((event) => event.nodeId));
  const assessCrossNodePath =
    currentNodeIds.size > 1 || baselineNodeIds.size > 1;
  const crossNodeGoldenPath = assessCrossNodePath
    ? computeGoldenPathDrift({
        nodeId: "cross-node",
        events,
        baselineEvents: baseline,
        includeNodeIdInToken: true,
        config: withModelVersion(
          config.goldenPathDrift,
          config.modelVersion,
        ),
      })
    : null;
  const eventNodeById = new Map(
    events.map(
      (event) => [safeIdentifier(event.id), event.nodeId] as const,
    ),
  );

  const nodes: RuntimeRiskNodeAssessment[] = [];
  for (const [nodeId, nodeEvents] of [...eventsByNode.entries()].sort(
    ([left], [right]) => left.localeCompare(right),
  )) {
    const nodeBaseline = baselineByNode.get(nodeId) ?? [];
    const excludedStateKeys = new Set<string>([
      ...(config.behaviorDrift?.string?.excludeLeafKeys ?? []),
      ...rules.map((rule) => rule.key),
    ]);
    const behavior = computeBehaviorDrift({
      nodeId,
      events: nodeEvents,
      baselineEvents: nodeBaseline,
      config: {
        ...withModelVersion(config.behaviorDrift, config.modelVersion),
        string: {
          ...config.behaviorDrift?.string,
          excludeLeafKeys: excludedStateKeys,
        },
      },
    });
    const goldenPath = computeGoldenPathDrift({
      nodeId,
      events: nodeEvents,
      baselineEvents: nodeBaseline,
      config: withModelVersion(config.goldenPathDrift, config.modelVersion),
    });
    const crossNodeDeviations =
      crossNodeGoldenPath?.evidence.deviations.filter(
        (deviation) =>
          deviation.hop &&
          eventNodeById.get(deviation.hop.eventId) === nodeId,
      ) ?? [];
    const crossNodeSignals =
      crossNodeGoldenPath?.signals.filter(
        (signal) =>
          signal.hop && eventNodeById.get(signal.hop.eventId) === nodeId,
      ) ?? [];
    const hasCrossNodeFinding =
      crossNodeDeviations.length > 0 || crossNodeSignals.length > 0;
    const goldenPathScore = hasCrossNodeFinding
      ? Math.max(goldenPath.score, crossNodeGoldenPath?.score ?? 0)
      : goldenPath.score;
    const persistence = computeStatePersistence({
      nodeId,
      events: nodeEvents,
      sensitiveStateRules: rules,
      config: withModelVersion(config.statePersistence, config.modelVersion),
    });
    const persistenceViolations = [
      ...persistence.evidence.violations,
      ...(crossNodeViolations.get(safeIdentifier(nodeId)) ?? []),
    ].sort(
      (left, right) =>
        left.kind.localeCompare(right.kind) ||
        left.key.localeCompare(right.key) ||
        left.firstSeen.eventId.localeCompare(right.firstSeen.eventId),
    );
    const persistenceScore = scoreStatePersistenceViolations(
      persistenceViolations,
      config.statePersistence,
    );
    const persistenceRiskSignals = statePersistenceSignals(
      nodeId,
      nodeEvents,
      persistenceViolations,
      withModelVersion(config.statePersistence, config.modelVersion),
    );
    const exposure = computeDataExposureRisk({
      nodeId,
      events: nodeEvents,
      config: withModelVersion(config.dataExposure, config.modelVersion),
    });
    const mandate = computeMandateDeviation({
      nodeId,
      events: nodeEvents,
      config: withModelVersion(config.mandateDeviation, config.modelVersion),
    });

    const subscores: RuntimeRiskSubscores = {
      behavior_drift: behavior.score,
      golden_path_drift: goldenPathScore,
      state_persistence: persistenceScore,
      data_exposure_risk: exposure.score,
      mandate_deviation: mandate.score,
    };
    const overallScore = clamp(Math.max(...Object.values(subscores)), 0, 100);
    const orderedNodeEvents = sortedEvents(nodeEvents);
    nodes.push({
      runId: safeIdentifier(input.runId),
      nodeId: safeIdentifier(nodeId),
      eventCount: orderedNodeEvents.length,
      firstTimestamp: toIso(orderedNodeEvents[0].timestamp),
      lastTimestamp: toIso(
        orderedNodeEvents[orderedNodeEvents.length - 1].timestamp,
      ),
      overallScore,
      subscores,
      signals: sortedSignals(
        [
          ...behavior.signals,
          ...goldenPath.signals,
          ...crossNodeSignals,
          ...persistenceRiskSignals,
          ...exposure.signals,
          ...mandate.signals,
        ],
        config.maximumSignals,
      ),
      evidence: {
        behaviorDrift: behavior.evidence,
        goldenPathDrift: {
          ...goldenPath.evidence,
          ...(hasCrossNodeFinding && crossNodeGoldenPath
            ? {
                crossNode: {
                  score: crossNodeGoldenPath.score,
                  baseline: crossNodeGoldenPath.evidence.baseline,
                  expected: crossNodeGoldenPath.evidence.expected,
                  observed: crossNodeGoldenPath.evidence.observed,
                  deviations: crossNodeDeviations,
                },
              }
            : {}),
        },
        statePersistence: { violations: persistenceViolations },
        dataExposureRisk: exposure.evidence,
        mandateDeviation: mandate.evidence,
      },
    });
  }

  const subscores = emptySubscores();
  for (const node of nodes) {
    for (const subtype of Object.keys(subscores) as Array<
      keyof RuntimeRiskSubscores
    >) {
      subscores[subtype] = Math.max(
        subscores[subtype],
        node.subscores[subtype],
      );
    }
  }
  const overallScore = clamp(Math.max(...Object.values(subscores)), 0, 100);
  return {
    runId: safeIdentifier(input.runId),
    nodeCount: nodes.length,
    eventCount: events.length,
    ...(events.length > 0
      ? {
          firstTimestamp: toIso(events[0].timestamp),
          lastTimestamp: toIso(events[events.length - 1].timestamp),
        }
      : {}),
    overallScore,
    subscores,
    signals: sortedSignals(
      nodes.flatMap((node) => node.signals),
      config.maximumSignals,
    ),
    nodes,
    model: { version: config.modelVersion, aggregation: "maximum" },
  };
}
