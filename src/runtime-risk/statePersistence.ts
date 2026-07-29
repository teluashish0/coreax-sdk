import type {
  RiskComputationResult,
  RuntimeRiskEvent,
  RuntimeRiskSignal,
  RuntimeStateScope,
  SensitiveStateRule,
  StatePersistenceEvidence,
  StatePersistenceViolation,
} from "./types";
import {
  RUNTIME_STATE_SCOPES,
  assertUniqueEventIds,
  clamp,
  finiteConfigNumber,
  getScopeState,
  looksSensitiveString,
  privacyHash,
  safeIdentifier,
  safeModelVersion,
  severityFromScore,
  sortedEvents,
  timestampMilliseconds,
  toHop,
} from "./util";

export type StatePersistenceConfig = {
  modelVersion: string;
  maximumPersistedHops: number;
  aggregateSignalThreshold: number;
  retentionViolationScore: number;
  scopeViolationScore: number;
  crossNodeScore: number;
  detectSensitiveValues: boolean;
  maximumDetectedValuesPerHop: number;
};

export const DEFAULT_STATE_PERSISTENCE_CONFIG: StatePersistenceConfig =
  Object.freeze({
    modelVersion: "coreax-runtime-risk-v1",
    maximumPersistedHops: 2,
    aggregateSignalThreshold: 60,
    retentionViolationScore: 25,
    scopeViolationScore: 20,
    crossNodeScore: 15,
    detectSensitiveValues: true,
    maximumDetectedValuesPerHop: 8,
  });

export type StatePersistenceInput = {
  nodeId: string;
  events: readonly RuntimeRiskEvent[];
  sensitiveStateRules?: readonly SensitiveStateRule[];
  config?: Partial<StatePersistenceConfig>;
};

type Occurrence = {
  index: number;
  event: RuntimeRiskEvent;
  scope: RuntimeStateScope;
};

type TrackedValue = {
  displayKey: string;
  valueSha256: string;
  expectedScope?: RuntimeStateScope;
  expectedMaximumHops: number;
  detected: boolean;
  occurrences: Occurrence[];
};

type DetectedSensitiveValue = {
  classification: "pii" | "credential" | "secret";
  valueSha256: string;
  scope: RuntimeStateScope;
};

function resolvedConfig(
  overrides: Partial<StatePersistenceConfig> | undefined,
): StatePersistenceConfig {
  const merged = { ...DEFAULT_STATE_PERSISTENCE_CONFIG, ...overrides };
  if (typeof merged.detectSensitiveValues !== "boolean") {
    throw new TypeError(
      "statePersistence.detectSensitiveValues must be boolean",
    );
  }
  return {
    ...merged,
    modelVersion: safeModelVersion(merged.modelVersion),
    maximumPersistedHops: finiteConfigNumber(
      merged.maximumPersistedHops,
      "statePersistence.maximumPersistedHops",
      { minimum: 0, maximum: 1_000_000, integer: true },
    ),
    aggregateSignalThreshold: finiteConfigNumber(
      merged.aggregateSignalThreshold,
      "statePersistence.aggregateSignalThreshold",
      { minimum: 0, maximum: 100 },
    ),
    retentionViolationScore: finiteConfigNumber(
      merged.retentionViolationScore,
      "statePersistence.retentionViolationScore",
      { minimum: 1, maximum: 100 },
    ),
    scopeViolationScore: finiteConfigNumber(
      merged.scopeViolationScore,
      "statePersistence.scopeViolationScore",
      { minimum: 1, maximum: 100 },
    ),
    crossNodeScore: finiteConfigNumber(
      merged.crossNodeScore,
      "statePersistence.crossNodeScore",
      { minimum: 1, maximum: 100 },
    ),
    maximumDetectedValuesPerHop: finiteConfigNumber(
      merged.maximumDetectedValuesPerHop,
      "statePersistence.maximumDetectedValuesPerHop",
      {
        minimum: merged.detectSensitiveValues ? 1 : 0,
        maximum: 10_000,
        integer: true,
      },
    ),
  };
}

function normalizeRules(
  rules: readonly SensitiveStateRule[],
): SensitiveStateRule[] {
  const output = new Map<string, SensitiveStateRule>();
  for (const [index, rule] of rules.entries()) {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
      throw new TypeError(
        `sensitiveStateRules[${index}] must be an object`,
      );
    }
    if (!RUNTIME_STATE_SCOPES.includes(rule.scope)) {
      throw new TypeError(
        `sensitiveStateRules[${index}].scope must be a supported runtime scope`,
      );
    }
    if (
      typeof rule.key !== "string" ||
      !rule.key.trim() ||
      rule.key !== rule.key.trim()
    ) {
      throw new TypeError(
        `sensitiveStateRules[${index}].key must be a canonical non-empty string`,
      );
    }
    const key = rule.key;
    const maxHops =
      rule.maxHops === undefined
        ? undefined
        : finiteConfigNumber(rule.maxHops, "sensitiveStateRule.maxHops", {
            minimum: 0,
            maximum: 1_000_000,
            integer: true,
          });
    const identity = `${rule.scope}:${key}`;
    if (output.has(identity)) {
      throw new TypeError(
        `sensitiveStateRules[${index}] duplicates an earlier scope/key rule`,
      );
    }
    output.set(identity, {
      scope: rule.scope,
      key,
      ...(maxHops !== undefined ? { maxHops } : {}),
    });
  }
  return [...output.values()].sort(
    (left, right) =>
      left.key.localeCompare(right.key) || left.scope.localeCompare(right.scope),
  );
}

function classificationForSensitiveString(
  value: string,
): DetectedSensitiveValue["classification"] | undefined {
  const bounded = value.trim().slice(0, 2048);
  if (!bounded) return undefined;
  if (/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(bounded)) return "pii";
  if (
    /\bAKIA[0-9A-Z]{16}\b/.test(bounded) ||
    /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(
      bounded,
    )
  ) {
    return "credential";
  }
  return looksSensitiveString(bounded) ? "secret" : undefined;
}

function detectSensitiveValues(
  state: RuntimeRiskEvent["state"],
  maximum: number,
): DetectedSensitiveValue[] {
  const limit = Math.max(0, Math.floor(maximum));
  if (limit === 0) return [];
  const byScope = new Map<
    RuntimeStateScope,
    Map<string, DetectedSensitiveValue>
  >();
  const walk = (
    scope: RuntimeStateScope,
    value: unknown,
    depth: number,
  ): void => {
    const scoped = byScope.get(scope) ?? new Map<string, DetectedSensitiveValue>();
    byScope.set(scope, scoped);
    if (scoped.size >= limit || depth > 4 || value == null) return;
    if (typeof value === "string") {
      const classification = classificationForSensitiveString(value);
      if (!classification) return;
      const valueSha256 = privacyHash(value);
      scoped.set(valueSha256, {
        classification,
        valueSha256,
        scope,
      });
      return;
    }
    if (Array.isArray(value)) {
      for (const entry of value) {
        walk(scope, entry, depth + 1);
        if (scoped.size >= limit) return;
      }
      return;
    }
    if (typeof value !== "object") return;
    for (const [, entry] of Object.entries(
      value as Record<string, unknown>,
    ).sort(([left], [right]) => left.localeCompare(right))) {
      walk(scope, entry, depth + 1);
      if (scoped.size >= limit) return;
    }
  };
  for (const scope of RUNTIME_STATE_SCOPES) {
    walk(scope, getScopeState(state, scope), 0);
  }
  const queues = RUNTIME_STATE_SCOPES.map((scope) =>
    [...(byScope.get(scope)?.values() ?? [])].sort((left, right) =>
      left.valueSha256.localeCompare(right.valueSha256),
    ),
  );
  const output: DetectedSensitiveValue[] = [];
  for (let index = 0; output.length < limit; index += 1) {
    let added = false;
    for (const queue of queues) {
      const entry = queue[index];
      if (!entry) continue;
      output.push(entry);
      added = true;
      if (output.length >= limit) break;
    }
    if (!added) break;
  }
  return output;
}

function track(
  tracked: Map<string, TrackedValue>,
  identity: string,
  value: Omit<TrackedValue, "occurrences">,
  occurrence: Occurrence,
): void {
  const existing = tracked.get(identity);
  if (existing) {
    existing.occurrences.push(occurrence);
    return;
  }
  tracked.set(identity, { ...value, occurrences: [occurrence] });
}

function persistenceViolations(
  tracked: Map<string, TrackedValue>,
): StatePersistenceViolation[] {
  const violations: StatePersistenceViolation[] = [];
  for (const value of [...tracked.values()].sort((left, right) =>
    left.displayKey.localeCompare(right.displayKey),
  )) {
    const occurrences = [...value.occurrences].sort(
      (left, right) => left.index - right.index,
    );
    const first = occurrences[0];
    const last = occurrences[occurrences.length - 1];
    const persistedHops = last.index - first.index + 1;
    const observedScopes = [
      ...new Set(occurrences.map((occurrence) => occurrence.scope)),
    ].sort();
    if (persistedHops > value.expectedMaximumHops) {
      violations.push({
        key: value.displayKey,
        kind: value.detected
          ? "unexpected_retention"
          : "sensitive_persisted",
        firstSeen: toHop(first.event),
        lastSeen: toHop(last.event),
        persistedHops,
        expectedMaxHops: value.expectedMaximumHops,
        valueSha256: value.valueSha256,
        observedScopes,
      });
    }
    if (value.expectedScope) {
      const unexpectedScopes = new Set(
        occurrences
          .map((occurrence) => occurrence.scope)
          .filter((scope) => scope !== value.expectedScope),
      );
      for (const scope of [...unexpectedScopes].sort()) {
        const scopedOccurrences = occurrences.filter(
          (occurrence) => occurrence.scope === scope,
        );
        violations.push({
          key: `${scope}:${value.displayKey.split(":").slice(1).join(":")}`,
          kind: "scope_violation",
          firstSeen: toHop(scopedOccurrences[0].event),
          lastSeen: toHop(scopedOccurrences[scopedOccurrences.length - 1].event),
          persistedHops:
            scopedOccurrences[scopedOccurrences.length - 1].index -
            scopedOccurrences[0].index +
            1,
          valueSha256: value.valueSha256,
          observedScopes: [scope],
        });
      }
    }
  }
  return violations;
}

export function scoreStatePersistenceViolations(
  violations: readonly StatePersistenceViolation[],
  config?: Partial<StatePersistenceConfig>,
): number {
  const resolved = resolvedConfig(config);
  return clamp(
    violations.reduce((sum, violation) => {
      switch (violation.kind) {
        case "scope_violation":
          return sum + resolved.scopeViolationScore;
        case "cross_node_propagation":
          return sum + resolved.crossNodeScore;
        case "sensitive_persisted":
        case "unexpected_retention":
          return sum + resolved.retentionViolationScore;
      }
    }, 0),
    0,
    100,
  );
}

export function statePersistenceSignals(
  nodeId: string,
  events: readonly RuntimeRiskEvent[],
  violations: readonly StatePersistenceViolation[],
  config?: Partial<StatePersistenceConfig>,
): RuntimeRiskSignal[] {
  const resolved = resolvedConfig(config);
  const score = scoreStatePersistenceViolations(violations, resolved);
  if (score < resolved.aggregateSignalThreshold || violations.length === 0) {
    return [];
  }
  const ordered = sortedEvents(events);
  return [
    {
      code: "state_persistence:aggregate",
      subtype: "state_persistence",
      severity: severityFromScore(score),
      score,
      title: "State persistence risk",
      message: `${violations.length} persistence violations for node ${safeIdentifier(nodeId)}`,
      evidence: { violationCount: violations.length },
      ...(ordered.length > 0 ? { hop: toHop(ordered[ordered.length - 1]) } : {}),
    },
  ];
}

export function computeStatePersistence(
  input: StatePersistenceInput,
): RiskComputationResult<StatePersistenceEvidence> {
  const config = resolvedConfig(input.config);
  const rules = normalizeRules(input.sensitiveStateRules ?? []);
  const events = sortedEvents(input.events);
  const tracked = new Map<string, TrackedValue>();

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const explicitlyTrackedHashes = new Set<string>();
    for (const rule of rules) {
      for (const scope of RUNTIME_STATE_SCOPES) {
        const values = getScopeState(event.state, scope);
        if (!values || !Object.prototype.hasOwnProperty.call(values, rule.key)) {
          continue;
        }
        const valueSha256 = privacyHash(values[rule.key]);
        explicitlyTrackedHashes.add(valueSha256);
        track(
          tracked,
          `${rule.scope}:${rule.key}:${valueSha256}`,
          {
            displayKey: `${rule.scope}:${safeIdentifier(rule.key)}`,
            valueSha256,
            expectedScope: rule.scope,
            expectedMaximumHops:
              rule.maxHops ?? config.maximumPersistedHops,
            detected: false,
          },
          { index, event, scope },
        );
      }
    }
    if (!config.detectSensitiveValues) continue;
    const detected = detectSensitiveValues(
      event.state,
      Math.max(0, Math.floor(config.maximumDetectedValuesPerHop)),
    );
    for (const value of detected) {
      if (explicitlyTrackedHashes.has(value.valueSha256)) continue;
      track(
        tracked,
        `DETECTED:${value.classification}:${value.valueSha256}`,
        {
          displayKey: `DETECTED:${value.classification}:${value.valueSha256}`,
          valueSha256: value.valueSha256,
          expectedMaximumHops: config.maximumPersistedHops,
          detected: true,
        },
        { index, event, scope: value.scope },
      );
    }
  }

  const violations = persistenceViolations(tracked);
  const score = scoreStatePersistenceViolations(violations, config);
  return {
    score,
    evidence: { violations },
    signals: statePersistenceSignals(
      input.nodeId,
      events,
      violations,
      config,
    ),
    modelVersion: config.modelVersion,
  };
}

export type CrossNodePropagationInput = {
  eventsByNode:
    | ReadonlyMap<string, readonly RuntimeRiskEvent[]>
    | Readonly<Record<string, readonly RuntimeRiskEvent[]>>;
  sensitiveStateRules: readonly SensitiveStateRule[];
  config?: Partial<StatePersistenceConfig>;
};

function eventsByNodeEntries(
  input: CrossNodePropagationInput["eventsByNode"],
): Array<[string, readonly RuntimeRiskEvent[]]> {
  return input instanceof Map
    ? [...input.entries()]
    : Object.entries(input);
}

export function computeCrossNodePropagation(
  input: CrossNodePropagationInput,
): Map<string, StatePersistenceViolation[]> {
  const config = resolvedConfig(input.config);
  const rules = normalizeRules(input.sensitiveStateRules);
  const entries = eventsByNodeEntries(input.eventsByNode).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  assertUniqueEventIds(entries.flatMap(([, events]) => [...events]));
  type CrossNodeOccurrence = {
    event: RuntimeRiskEvent;
    scope: RuntimeStateScope;
  };
  const occurrences = new Map<
    string,
    {
      displayKey: string;
      valueSha256: string;
      byNode: Map<string, CrossNodeOccurrence[]>;
    }
  >();
  const addOccurrence = (
    identity: string,
    displayKey: string,
    valueSha256: string,
    nodeId: string,
    occurrence: CrossNodeOccurrence,
  ): void => {
    const tracked = occurrences.get(identity) ?? {
      displayKey,
      valueSha256,
      byNode: new Map<string, CrossNodeOccurrence[]>(),
    };
    const observed = tracked.byNode.get(nodeId) ?? [];
    if (
      !observed.some(
        (entry) =>
          entry.event.id === occurrence.event.id &&
          entry.scope === occurrence.scope,
      )
    ) {
      observed.push(occurrence);
    }
    tracked.byNode.set(nodeId, observed);
    occurrences.set(identity, tracked);
  };

  for (const [nodeId, nodeEvents] of entries) {
    for (const event of sortedEvents(nodeEvents)) {
      for (const rule of rules) {
        for (const scope of RUNTIME_STATE_SCOPES) {
          const values = getScopeState(event.state, scope);
          if (
            !values ||
            !Object.prototype.hasOwnProperty.call(values, rule.key)
          ) {
            continue;
          }
          const valueSha256 = privacyHash(values[rule.key]);
          const identity = `VALUE:${valueSha256}`;
          addOccurrence(
            identity,
            `${rule.scope}:${safeIdentifier(rule.key)}`,
            valueSha256,
            nodeId,
            { event, scope },
          );
        }
      }
      if (!config.detectSensitiveValues) continue;
      for (const detected of detectSensitiveValues(
        event.state,
        Math.max(0, Math.floor(config.maximumDetectedValuesPerHop)),
      )) {
        addOccurrence(
          `VALUE:${detected.valueSha256}`,
          `DETECTED:${detected.classification}`,
          detected.valueSha256,
          nodeId,
          { event, scope: detected.scope },
        );
      }
    }
  }

  const output = new Map<string, StatePersistenceViolation[]>();
  for (const tracked of [...occurrences.values()].sort(
    (left, right) =>
      left.displayKey.localeCompare(right.displayKey) ||
      left.valueSha256.localeCompare(right.valueSha256),
  )) {
    const nodeIds = [...tracked.byNode.keys()].sort();
    if (nodeIds.length < 2) continue;
    const safeNodeIds = nodeIds.map(safeIdentifier);
    for (const nodeId of nodeIds) {
      const outputNodeId = safeIdentifier(nodeId);
      const observed = [...(tracked.byNode.get(nodeId) ?? [])].sort(
        (left, right) =>
          timestampMilliseconds(left.event.timestamp) -
            timestampMilliseconds(right.event.timestamp) ||
          left.event.id.localeCompare(right.event.id) ||
          left.scope.localeCompare(right.scope),
      );
      if (observed.length === 0) continue;
      const observedScopes = [
        ...new Set(observed.map((occurrence) => occurrence.scope)),
      ].sort();
      const observedEvents = sortedEvents(
        [...new Map(observed.map(({ event }) => [event.id, event])).values()],
      );
      const violations = output.get(outputNodeId) ?? [];
      violations.push({
        key: tracked.displayKey.startsWith("DETECTED:")
          ? `${observedScopes.join("+")}:${tracked.displayKey}`
          : tracked.displayKey,
        kind: "cross_node_propagation",
        firstSeen: toHop(observedEvents[0]),
        lastSeen: toHop(observedEvents[observedEvents.length - 1]),
        persistedHops: observedEvents.length,
        valueSha256: tracked.valueSha256,
        nodeIds: safeNodeIds,
        observedScopes,
      });
      output.set(outputNodeId, violations);
    }
  }
  return output;
}
