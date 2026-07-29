import {
  EvaluatorActiveStateSchema,
  EvaluatorEvidenceEventSchema,
  type EvaluatorActiveState,
  type EvaluatorActiveStateClaim,
  type EvaluatorEvidenceEvent,
} from "./types";
import { compactText, hashFingerprint, normalizeString } from "./classification";

function stableKey(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 200);
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(
      value
        .map((entry) => normalizeString(entry))
        .filter(Boolean),
    ),
  );
}

function inferredEventId(event: Omit<EvaluatorEvidenceEvent, "eventId">): string {
  return `evt_${hashFingerprint({
    kind: event.kind,
    claimGroup: event.claimGroup,
    claim: event.claim,
    summary: event.summary,
    status: event.status,
    provenanceRef: event.provenanceRef,
    entities: event.entityRefs,
  }).slice(0, 24)}`;
}

function timestamp(value: string | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function evaluatorEvidenceAxisKey(event: EvaluatorEvidenceEvent): string {
  const claimGroup = stableKey(event.claimGroup ?? "");
  if (claimGroup) return claimGroup;
  const entityAxis = event.entityRefs
    .map((entity) =>
      stableKey(
        `${entity.role ?? ""}:${entity.type ?? ""}:${entity.id ?? entity.label ?? ""}`,
      ),
    )
    .filter(Boolean)
    .join("_");
  if (entityAxis) return stableKey(`${event.kind}_${entityAxis}`);
  return stableKey(event.kind || event.claim || event.summary) || "evidence";
}

export function normalizeEvaluatorEvidenceEvents(
  value: unknown,
): EvaluatorEvidenceEvent[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const eventIds = new Map<string, string>();
  const events: Array<{ event: EvaluatorEvidenceEvent; index: number }> = [];

  for (const [index, rawEvent] of value.entries()) {
    const event = EvaluatorEvidenceEventSchema.parse(rawEvent);
    const normalized: EvaluatorEvidenceEvent = {
      ...event,
      eventId: event.eventId || inferredEventId(event),
      summary: compactText(event.summary, 2000),
      entityRefs: [...event.entityRefs],
      relatedEventIds: stringArray(event.relatedEventIds),
      contradictionLinks: stringArray(event.contradictionLinks),
      recoveryLinks: stringArray(event.recoveryLinks),
    };
    const identity = hashFingerprint(normalized);
    const priorIdentity = eventIds.get(normalized.eventId!);
    if (priorIdentity && priorIdentity !== identity) {
      throw new Error(
        `Conflicting evaluator evidence event id "${normalized.eventId}"`,
      );
    }
    eventIds.set(normalized.eventId!, identity);
    if (seen.has(identity)) continue;
    seen.add(identity);
    events.push({ event: normalized, index });
  }

  return events
    .sort((left, right) => {
      const leftTime = timestamp(left.event.timestamp);
      const rightTime = timestamp(right.event.timestamp);
      if (leftTime !== null && rightTime !== null && leftTime !== rightTime) {
        return leftTime - rightTime;
      }
      if (leftTime !== null && rightTime === null) return -1;
      if (leftTime === null && rightTime !== null) return 1;
      return left.index - right.index;
    })
    .map(({ event }) => event);
}

type ClaimBucket = {
  key: string;
  events: EvaluatorEvidenceEvent[];
};

type BucketResolution = {
  unresolved: EvaluatorEvidenceEvent[];
  validRecoveryEventIds: Set<string>;
  validRecoveryTargetIds: Set<string>;
};

function isProvenLaterRecovery(
  recovery: EvaluatorEvidenceEvent,
  target: EvaluatorEvidenceEvent,
): boolean {
  const recoveryTime = timestamp(recovery.timestamp);
  const targetTime = timestamp(target.timestamp);
  return (
    recoveryTime !== null &&
    targetTime !== null &&
    recoveryTime > targetTime
  );
}

function resolveBucketRecovery(bucket: ClaimBucket): BucketResolution {
  const unresolved = new Map<string, EvaluatorEvidenceEvent>();
  const validRecoveryEventIds = new Set<string>();
  const validRecoveryTargetIds = new Set<string>();

  for (const event of bucket.events) {
    const eventId = event.eventId!;
    if (event.status === "failed" || event.status === "contradicted") {
      unresolved.set(eventId, event);
      continue;
    }
    if (event.status !== "recovered" && event.status !== "superseded") {
      continue;
    }
    const recoveryTargets = event.recoveryLinks.filter((targetId) => {
      const target = unresolved.get(targetId);
      return target !== undefined && isProvenLaterRecovery(event, target);
    });
    if (recoveryTargets.length === 0) continue;
    validRecoveryEventIds.add(eventId);
    for (const targetId of recoveryTargets) {
      validRecoveryTargetIds.add(targetId);
      unresolved.delete(targetId);
    }
  }

  return {
    unresolved: [...unresolved.values()],
    validRecoveryEventIds,
    validRecoveryTargetIds,
  };
}

function evidenceBuckets(
  events: readonly EvaluatorEvidenceEvent[],
): Map<string, ClaimBucket> {
  const buckets = new Map<string, ClaimBucket>();
  for (const event of events) {
    const key = evaluatorEvidenceAxisKey(event);
    const bucket = buckets.get(key) ?? { key, events: [] };
    bucket.events.push(event);
    buckets.set(key, bucket);
  }
  return buckets;
}

/**
 * Returns only failure/contradiction event ids cleared by an explicitly linked
 * recovery on the same normalized evidence axis with a strictly later,
 * comparable timestamp.
 */
export function validatedEvaluatorRecoveryTargetIds(
  rawEvents: unknown,
): Set<string> {
  const targets = new Set<string>();
  for (const bucket of evidenceBuckets(
    normalizeEvaluatorEvidenceEvents(rawEvents),
  ).values()) {
    for (const targetId of resolveBucketRecovery(bucket)
      .validRecoveryTargetIds) {
      targets.add(targetId);
    }
  }
  return targets;
}

function claimFromBucket(
  bucket: ClaimBucket,
  category: "verified" | "unresolved" | "superseded" | "contradicted",
  resolution: BucketResolution,
): EvaluatorActiveStateClaim {
  const latest =
    category === "unresolved" || category === "contradicted"
      ? resolution.unresolved.at(-1) ?? bucket.events[bucket.events.length - 1]
      : bucket.events[bucket.events.length - 1];
  const supportingEventIds: string[] = [];
  const contradictingEventIds: string[] = [];
  const recoveryEventIds: string[] = [];
  const provenanceRefs: string[] = [];
  const confidenceValues: number[] = [];

  for (const event of bucket.events) {
    if (
      event.status === "supported" ||
      event.status === "observed"
    ) {
      if (event.eventId) supportingEventIds.push(event.eventId);
    }
    if (event.status === "failed" || event.status === "contradicted") {
      if (event.eventId) contradictingEventIds.push(event.eventId);
    }
    if (
      (event.status === "recovered" || event.status === "superseded") &&
      event.eventId &&
      resolution.validRecoveryEventIds.has(event.eventId)
    ) {
      if (event.eventId) recoveryEventIds.push(event.eventId);
      recoveryEventIds.push(
        ...event.recoveryLinks.filter((eventId) =>
          resolution.validRecoveryTargetIds.has(eventId),
        ),
      );
    }
    contradictingEventIds.push(...event.contradictionLinks);
    if (event.provenanceRef) provenanceRefs.push(event.provenanceRef);
    if (typeof event.confidence === "number") {
      confidenceValues.push(event.confidence);
    }
  }

  const confidence =
    confidenceValues.length > 0
      ? Number(
          (
            confidenceValues.reduce((sum, value) => sum + value, 0) /
            confidenceValues.length
          ).toFixed(4),
        )
      : null;

  return {
    key: bucket.key,
    claim: latest.claim || latest.summary,
    summary: latest.summary,
    confidence,
    supportingEventIds: stringArray(supportingEventIds),
    contradictingEventIds: stringArray(contradictingEventIds),
    recoveryEventIds: stringArray(recoveryEventIds),
    provenanceRefs: stringArray(provenanceRefs).sort(),
    entities: latest.entityRefs,
    metadata: {
      propositionState: category,
      eventCount: bucket.events.length,
    },
  };
}

/**
 * Compiles chronological evidence into the currently active proposition for
 * each claim axis. Only a linked recovery with a strictly later, comparable
 * timestamp clears a failure or contradiction.
 */
export function compileEvaluatorActiveState(
  rawEvents: unknown,
): EvaluatorActiveState {
  const events = normalizeEvaluatorEvidenceEvents(rawEvents);
  const buckets = evidenceBuckets(events);

  const activeState: EvaluatorActiveState = {
    verifiedClaims: [],
    unresolvedClaims: [],
    supersededClaims: [],
    contradictedClaims: [],
    retrievalHints: [],
    compacted: false,
  };

  for (const bucket of [...buckets.values()].sort((left, right) =>
    left.key.localeCompare(right.key),
  )) {
    const latest = bucket.events[bucket.events.length - 1];
    const resolution = resolveBucketRecovery(bucket);
    const latestUnresolved = resolution.unresolved.at(-1);
    if (latestUnresolved?.status === "contradicted") {
      activeState.contradictedClaims.push(
        claimFromBucket(bucket, "contradicted", resolution),
      );
    } else if (latestUnresolved?.status === "failed") {
      activeState.unresolvedClaims.push(
        claimFromBucket(bucket, "unresolved", resolution),
      );
    } else if (
      latest.status === "superseded" &&
      latest.eventId &&
      resolution.validRecoveryEventIds.has(latest.eventId)
    ) {
      activeState.supersededClaims.push(
        claimFromBucket(bucket, "superseded", resolution),
      );
    } else {
      activeState.verifiedClaims.push(
        claimFromBucket(bucket, "verified", resolution),
      );
    }
  }

  activeState.retrievalHints = activeState.unresolvedClaims.map(
    (claim) => claim.claim,
  );
  return EvaluatorActiveStateSchema.parse(activeState);
}

function mergeClaims(
  explicitState: EvaluatorActiveState,
  compiledState: EvaluatorActiveState,
): EvaluatorActiveState {
  type Category =
    | "verifiedClaims"
    | "unresolvedClaims"
    | "supersededClaims"
    | "contradictedClaims";
  const categories: Category[] = [
    "verifiedClaims",
    "unresolvedClaims",
    "supersededClaims",
    "contradictedClaims",
  ];
  const categoryRank: Record<Category, number> = {
    verifiedClaims: 0,
    supersededClaims: 1,
    unresolvedClaims: 2,
    contradictedClaims: 3,
  };
  const validatedRecoveryIdsByKey = new Map<string, Set<string>>();
  for (const category of categories) {
    for (const claim of compiledState[category]) {
      if (claim.recoveryEventIds.length === 0) continue;
      const ids =
        validatedRecoveryIdsByKey.get(claim.key) ?? new Set<string>();
      claim.recoveryEventIds.forEach((eventId) => ids.add(eventId));
      validatedRecoveryIdsByKey.set(claim.key, ids);
    }
  }
  const resolved = new Map<
    string,
    { category: Category; claim: EvaluatorActiveStateClaim }
  >();

  const addClaim = (
    category: Category,
    rawClaim: EvaluatorActiveStateClaim,
    source: "explicit" | "compiled",
  ) => {
    const validatedRecoveryIds = validatedRecoveryIdsByKey.get(rawClaim.key);
    const claim =
      source === "explicit"
        ? {
            ...rawClaim,
            recoveryEventIds: rawClaim.recoveryEventIds.filter((eventId) =>
              validatedRecoveryIds?.has(eventId),
            ),
          }
        : rawClaim;
    const existing = resolved.get(claim.key);
    if (!existing) {
      resolved.set(claim.key, { category, claim });
      return;
    }
    if (categoryRank[category] > categoryRank[existing.category]) {
      resolved.set(claim.key, { category, claim });
      return;
    }
    if (categoryRank[category] >= categoryRank[existing.category]) return;

    // A weaker state may replace an unresolved/contradicted state only when a
    // compiled, chronologically valid recovery targets that exact event.
    if (source !== "compiled" || claim.recoveryEventIds.length === 0) return;
    const blockingEventIds = new Set(existing.claim.contradictingEventIds);
    if (
      claim.recoveryEventIds.some((eventId) =>
        blockingEventIds.has(eventId),
      )
    ) {
      resolved.set(claim.key, { category, claim });
    }
  };

  for (const category of categories) {
    for (const claim of explicitState[category]) {
      addClaim(category, claim, "explicit");
    }
  }
  for (const category of categories) {
    for (const claim of compiledState[category]) {
      addClaim(category, claim, "compiled");
    }
  }

  const merged: EvaluatorActiveState = {
    verifiedClaims: [],
    unresolvedClaims: [],
    supersededClaims: [],
    contradictedClaims: [],
    retrievalHints: stringArray([
      ...explicitState.retrievalHints,
      ...compiledState.retrievalHints,
    ]),
    compacted: explicitState.compacted || compiledState.compacted,
  };
  for (const { category, claim } of [...resolved.values()].sort((left, right) =>
    left.claim.key.localeCompare(right.claim.key),
  )) {
    merged[category].push(claim);
  }
  return merged;
}

export function resolveEvaluatorActiveState(input: {
  explicitState?: EvaluatorActiveState;
  evidenceEvents?: unknown;
}): EvaluatorActiveState {
  const explicit = EvaluatorActiveStateSchema.parse(
    input.explicitState ?? {
      verifiedClaims: [],
      unresolvedClaims: [],
      supersededClaims: [],
      contradictedClaims: [],
      retrievalHints: [],
      compacted: false,
    },
  );
  const compiled = compileEvaluatorActiveState(input.evidenceEvents ?? []);
  return EvaluatorActiveStateSchema.parse(mergeClaims(explicit, compiled));
}

export function deriveRuntimeErrorEvidenceEvents(
  errors: readonly string[],
): EvaluatorEvidenceEvent[] {
  return normalizeEvaluatorEvidenceEvents(
    errors.map((error) => ({
      kind: "runtime_error",
      claim: `A recent execution dependency failed: ${error}`,
      claimGroup: `runtime_error_${stableKey(error).slice(0, 80)}`,
      summary: compactText(error, 1000),
      status: "failed",
      source: "runtime",
      entityRefs: [],
      relatedEventIds: [],
      contradictionLinks: [],
      recoveryLinks: [],
    })),
  );
}
