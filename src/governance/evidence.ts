import type {
  GovernanceEvidenceCompactionOptions,
  GovernanceEvidenceEntityRef,
  GovernanceEvidenceEvent,
  GovernanceEvidenceEventStatus,
  GovernanceJsonObject,
  GovernanceSubmission,
} from "./types";
import { GovernanceValidationError } from "./errors";
import {
  governanceSha256,
  normalizeGovernanceJsonObject,
  stringArray,
  timestampMs,
} from "./validation";

const EVIDENCE_STATUSES = new Set<GovernanceEvidenceEventStatus>([
  "supported",
  "observed",
  "failed",
  "contradicted",
  "recovered",
  "superseded",
]);

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function normalizeEntityRefs(value: unknown): GovernanceEvidenceEntityRef[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((entry) => entry && typeof entry === "object" && !Array.isArray(entry))
    .map((entry) => {
      const source = asObject(entry);
      return {
        ...(optionalText(source.id) ? { id: optionalText(source.id) } : {}),
        ...(optionalText(source.type) ? { type: optionalText(source.type) } : {}),
        ...(optionalText(source.role) ? { role: optionalText(source.role) } : {}),
        ...(optionalText(source.label) ? { label: optionalText(source.label) } : {}),
        ...(source.metadata && typeof source.metadata === "object"
          ? {
              metadata: normalizeGovernanceJsonObject(
                source.metadata,
                "evidence entity metadata",
              ),
            }
          : {}),
      };
    });
}

function normalizedStatus(value: unknown): GovernanceEvidenceEventStatus {
  if (!EVIDENCE_STATUSES.has(value as GovernanceEvidenceEventStatus)) {
    throw new GovernanceValidationError("Invalid governance evidence status");
  }
  return value as GovernanceEvidenceEventStatus;
}

export function normalizeGovernanceEvidenceEvents(
  value: unknown,
  options: GovernanceEvidenceCompactionOptions = {},
): GovernanceEvidenceEvent[] {
  if (!Array.isArray(value)) return [];
  const maxSummaryLength = Number.isFinite(options.maxSummaryLength)
    ? Math.max(32, Math.floor(options.maxSummaryLength!))
    : 1_000;

  return value
    .map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        throw new GovernanceValidationError(
          "Governance evidence must contain only event objects",
        );
      }
      const source = asObject(entry);
      const kind = String(source.kind ?? "").trim();
      const claim = optionalText(source.claim);
      const summary = String(source.summary ?? claim ?? "").trim();
      if (!kind || !summary) {
        throw new GovernanceValidationError(
          "Governance evidence requires kind and summary",
        );
      }
      const confidence =
        typeof source.confidence === "number" &&
        Number.isFinite(source.confidence)
          ? Math.max(0, Math.min(1, source.confidence))
          : undefined;
      const eventTimestamp = optionalText(source.timestamp);
      if (eventTimestamp) {
        timestampMs(eventTimestamp, "evidence.timestamp");
      }
      const event: GovernanceEvidenceEvent = {
        kind,
        summary: summary.slice(0, maxSummaryLength),
        status: normalizedStatus(source.status),
        ...(optionalText(source.eventId)
          ? { eventId: optionalText(source.eventId) }
          : {}),
        ...(eventTimestamp ? { timestamp: eventTimestamp } : {}),
        ...(optionalText(source.source)
          ? { source: optionalText(source.source) }
          : {}),
        ...(claim ? { claim } : {}),
        ...(optionalText(source.claimGroup)
          ? { claimGroup: optionalText(source.claimGroup) }
          : {}),
        ...(confidence !== undefined ? { confidence } : {}),
        ...(optionalText(source.provenanceRef)
          ? { provenanceRef: optionalText(source.provenanceRef) }
          : {}),
        entityRefs: normalizeEntityRefs(source.entityRefs),
        relatedEventIds: stringArray(source.relatedEventIds),
        contradictionLinks: stringArray(source.contradictionLinks),
        recoveryLinks: stringArray(source.recoveryLinks),
        ...(source.metadata && typeof source.metadata === "object"
          ? {
              metadata: normalizeGovernanceJsonObject(
                source.metadata,
                "evidence metadata",
              ),
            }
          : {}),
      };
      event.eventId ??= `evidence-${governanceSha256({
        kind: event.kind,
        claim: event.claim ?? null,
        claimGroup: event.claimGroup ?? null,
        summary: event.summary,
        status: event.status,
        source: event.source ?? null,
        provenanceRef: event.provenanceRef ?? null,
      }).slice(0, 24)}`;
      return event;
    });
}

function recoveryAxis(event: GovernanceEvidenceEvent): string | null {
  const claimGroup = event.claimGroup?.trim().toLowerCase();
  if (claimGroup) return `group:${claimGroup}`;
  const claim = event.claim?.trim().toLowerCase();
  if (claim) return `claim:${claim}`;
  const entities = (event.entityRefs ?? [])
    .map((entity) =>
      [entity.role, entity.type, entity.id ?? entity.label]
        .map((value) => value?.trim().toLowerCase() ?? "")
        .join(":"),
    )
    .filter((value) => value.replace(/:/g, ""))
    .sort();
  return entities.length > 0
    ? `entities:${event.kind.trim().toLowerCase()}:${entities.join("|")}`
    : null;
}

function recoveryIsLater(
  failed: GovernanceEvidenceEvent,
  failedIndex: number,
  recovery: GovernanceEvidenceEvent,
  recoveryIndex: number,
): boolean {
  if (recoveryIndex <= failedIndex) return false;
  if (!failed.timestamp && !recovery.timestamp) return true;
  if (!failed.timestamp || !recovery.timestamp) return false;
  return (
    timestampMs(recovery.timestamp, "recovery.timestamp") >
    timestampMs(failed.timestamp, "failed.timestamp")
  );
}

export function unresolvedGovernanceEvidence(
  events: readonly GovernanceEvidenceEvent[],
): GovernanceEvidenceEvent[] {
  const normalized = normalizeGovernanceEvidenceEvents(events);
  const unresolved = new Map<
    string,
    { event: GovernanceEvidenceEvent; index: number }
  >();

  normalized.forEach((event, index) => {
    const eventId = event.eventId!;
    if (event.status === "failed" || event.status === "contradicted") {
      unresolved.set(eventId, { event, index });
      return;
    }
    if (event.status !== "recovered" && event.status !== "superseded") return;
    const axis = recoveryAxis(event);
    if (!axis) return;
    for (const targetId of event.recoveryLinks ?? []) {
      const target = unresolved.get(targetId);
      if (
        target &&
        recoveryAxis(target.event) === axis &&
        recoveryIsLater(target.event, target.index, event, index)
      ) {
        unresolved.delete(targetId);
      }
    }
  });

  return [...unresolved.values()].map(({ event }) => event);
}

const STATUS_PRIORITY: Record<GovernanceEvidenceEventStatus, number> = {
  contradicted: 60,
  recovered: 55,
  failed: 50,
  supported: 35,
  observed: 25,
  superseded: 10,
};

export function compactGovernanceEvidence(
  events: readonly GovernanceEvidenceEvent[],
  options: GovernanceEvidenceCompactionOptions = {},
): GovernanceEvidenceEvent[] {
  const normalized = normalizeGovernanceEvidenceEvents(events, options);
  const latestById = new Map<string, { event: GovernanceEvidenceEvent; index: number }>();
  normalized.forEach((event, index) => {
    const prior = latestById.get(event.eventId!);
    if (
      prior &&
      governanceSha256(prior.event) !== governanceSha256(event)
    ) {
      throw new GovernanceValidationError(
        `Conflicting governance evidence event id "${event.eventId}"`,
      );
    }
    latestById.set(event.eventId!, { event, index });
  });
  const deduplicated = [...latestById.values()];
  const maxEvents = Number.isFinite(options.maxEvents)
    ? Math.max(1, Math.floor(options.maxEvents!))
    : 64;
  if (deduplicated.length <= maxEvents) {
    return deduplicated.map(({ event }) => event);
  }

  const referenced = new Set(
    deduplicated.flatMap(({ event }) => [
      ...(event.relatedEventIds ?? []),
      ...(event.contradictionLinks ?? []),
      ...(event.recoveryLinks ?? []),
    ]),
  );
  const chosen = deduplicated
    .map((entry) => ({
      ...entry,
      score:
        STATUS_PRIORITY[entry.event.status] +
        (referenced.has(entry.event.eventId!) ? 100 : 0) +
        ((entry.event.contradictionLinks?.length ?? 0) > 0 ? 20 : 0) +
        ((entry.event.recoveryLinks?.length ?? 0) > 0 ? 20 : 0),
    }))
    .sort((left, right) => right.score - left.score || right.index - left.index)
    .slice(0, maxEvents)
    .sort((left, right) => left.index - right.index);
  return chosen.map(({ event }) => event);
}

export function collectInlineGovernanceEvidence(
  submission: Pick<
    GovernanceSubmission,
    "evidence_events" | "state_slice" | "metadata" | "provenance"
  >,
  options: GovernanceEvidenceCompactionOptions = {},
): GovernanceEvidenceEvent[] {
  const stateSlice = asObject(submission.state_slice);
  const metadata = asObject(submission.metadata);
  const provenanceMetadata = asObject(submission.provenance?.metadata);
  return compactGovernanceEvidence(
    normalizeGovernanceEvidenceEvents(
      [
        ...(submission.evidence_events ?? []),
        ...(Array.isArray(stateSlice.evidence_events)
          ? stateSlice.evidence_events
          : []),
        ...(Array.isArray(metadata.evidence_events)
          ? metadata.evidence_events
          : []),
        ...(Array.isArray(provenanceMetadata.evidence_events)
          ? provenanceMetadata.evidence_events
          : []),
      ],
      options,
    ),
    options,
  );
}
