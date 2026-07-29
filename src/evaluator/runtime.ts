import { type EvaluatorInput, type EvaluatorInputPatch } from "./types";

function cloneArray<T>(value: T[] | undefined): T[] | undefined {
  return Array.isArray(value) ? [...value] : undefined;
}

export function asEvaluatorRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function mergeEvaluatorInput(
  base: EvaluatorInput,
  extra?: EvaluatorInputPatch | null,
): EvaluatorInput {
  if (!extra) return base;
  return {
    ...base,
    ...(extra as EvaluatorInput),
    action: {
      ...base.action,
      ...(extra.action || {}),
      ...(extra.action?.tool ? { tool: { ...(base.action.tool || {}), ...extra.action.tool } } : {}),
      ...(extra.action?.target ? { target: { ...(base.action.target || {}), ...extra.action.target } } : {}),
      ...(extra.action?.data ? { data: { ...(base.action.data || {}), ...extra.action.data } } : {}),
    },
    actor: { ...base.actor, ...(extra.actor || {}) },
    purpose: { ...base.purpose, ...(extra.purpose || {}) },
    authority: {
      ...base.authority,
      ...(extra.authority || {}),
      ...(extra.authority?.grantedScopes ? { grantedScopes: [...extra.authority.grantedScopes] } : {}),
      ...(extra.authority?.allowedBoundaries ? { allowedBoundaries: [...extra.authority.allowedBoundaries] } : {}),
      ...(extra.authority?.approvals ? { approvals: [...extra.authority.approvals] } : {}),
      ...(extra.authority?.delegations ? { delegations: [...extra.authority.delegations] } : {}),
    },
    runtimeContext: ({
      ...base.runtimeContext,
      ...(extra.runtimeContext || {}),
      ...(extra.runtimeContext?.workflowState ? { workflowState: { ...extra.runtimeContext.workflowState } } : {}),
      ...(extra.runtimeContext?.conversationState
        ? { conversationState: { ...extra.runtimeContext.conversationState } }
        : {}),
      ...(extra.runtimeContext?.unresolvedPrerequisites
        ? { unresolvedPrerequisites: [...extra.runtimeContext.unresolvedPrerequisites] }
        : {}),
      ...(extra.runtimeContext?.verifiedPrerequisites
        ? { verifiedPrerequisites: [...extra.runtimeContext.verifiedPrerequisites] }
        : {}),
      ...(extra.runtimeContext?.evidenceEvents
        ? { evidenceEvents: [...extra.runtimeContext.evidenceEvents] }
        : {}),
      ...(extra.runtimeContext?.activeState
        ? {
            activeState: {
              ...base.runtimeContext.activeState,
              ...extra.runtimeContext.activeState,
              ...(extra.runtimeContext.activeState.verifiedClaims
                ? {
                    verifiedClaims: [
                      ...extra.runtimeContext.activeState.verifiedClaims,
                    ],
                  }
                : {}),
              ...(extra.runtimeContext.activeState.unresolvedClaims
                ? {
                    unresolvedClaims: [
                      ...extra.runtimeContext.activeState.unresolvedClaims,
                    ],
                  }
                : {}),
              ...(extra.runtimeContext.activeState.supersededClaims
                ? {
                    supersededClaims: [
                      ...extra.runtimeContext.activeState.supersededClaims,
                    ],
                  }
                : {}),
              ...(extra.runtimeContext.activeState.contradictedClaims
                ? {
                    contradictedClaims: [
                      ...extra.runtimeContext.activeState.contradictedClaims,
                    ],
                  }
                : {}),
              ...(extra.runtimeContext.activeState.retrievalHints
                ? {
                    retrievalHints: [
                      ...extra.runtimeContext.activeState.retrievalHints,
                    ],
                  }
                : {}),
            },
          }
        : {}),
      ...(extra.runtimeContext?.retrievedEvidence
        ? {
            retrievedEvidence: {
              ...base.runtimeContext.retrievedEvidence,
              ...extra.runtimeContext.retrievedEvidence,
              ...(extra.runtimeContext.retrievedEvidence.events
                ? {
                    events: [
                      ...extra.runtimeContext.retrievedEvidence.events,
                    ],
                  }
                : {}),
              ...(extra.runtimeContext.retrievedEvidence.retrievalHints
                ? {
                    retrievalHints: [
                      ...extra.runtimeContext.retrievedEvidence.retrievalHints,
                    ],
                  }
                : {}),
            },
          }
        : {}),
    }) as EvaluatorInput["runtimeContext"],
    ...(extra.proposal
      ? {
          proposal: {
            ...(base.proposal || {}),
            ...extra.proposal,
            ...(extra.proposal.toolCall
              ? {
                  toolCall: {
                    ...(base.proposal?.toolCall || {}),
                    ...extra.proposal.toolCall,
                    ...(extra.proposal.toolCall.arguments
                      ? {
                          arguments: {
                            ...(base.proposal?.toolCall?.arguments || {}),
                            ...extra.proposal.toolCall.arguments,
                          },
                        }
                      : {}),
                  },
                }
              : {}),
          } as EvaluatorInput["proposal"],
        }
      : {}),
    ...(extra.graphContext
      ? { graphContext: [...extra.graphContext] as EvaluatorInput["graphContext"] }
      : {}),
    ...(extra.orchestrationState
      ? {
          orchestrationState: {
            ...(base.orchestrationState || {}),
            ...extra.orchestrationState,
            ...(extra.orchestrationState.signalCodes
              ? { signalCodes: [...extra.orchestrationState.signalCodes] }
              : {}),
            ...(extra.orchestrationState.missingFacts
              ? { missingFacts: [...extra.orchestrationState.missingFacts] }
              : {}),
          } as EvaluatorInput["orchestrationState"],
        }
      : {}),
    sourceUse: {
      ...base.sourceUse,
      ...(extra.sourceUse || {}),
      ...(extra.sourceUse?.sources ? { sources: [...extra.sourceUse.sources] } : {}),
    },
    constraints: ({
      ...base.constraints,
      ...(extra.constraints || {}),
      ...(extra.constraints?.hard ? { hard: [...extra.constraints.hard] } : {}),
      ...(extra.constraints?.soft ? { soft: [...extra.constraints.soft] } : {}),
      ...(extra.constraints?.requiredPrerequisites
        ? { requiredPrerequisites: [...extra.constraints.requiredPrerequisites] }
        : {}),
      ...(extra.constraints?.requiredApprovals
        ? { requiredApprovals: [...extra.constraints.requiredApprovals] }
        : {}),
      ...(extra.constraints?.forbiddenBoundaries
        ? { forbiddenBoundaries: [...extra.constraints.forbiddenBoundaries] }
        : {}),
      ...(extra.constraints?.disclosureBudget
        ? {
            disclosureBudget: {
              ...(base.constraints.disclosureBudget || {}),
              ...extra.constraints.disclosureBudget,
              maxClassifications: cloneArray(
                extra.constraints.disclosureBudget.maxClassifications ??
                  base.constraints.disclosureBudget?.maxClassifications ??
                  [],
              ) || [],
            } as NonNullable<EvaluatorInput["constraints"]["disclosureBudget"]>,
          }
        : {}),
    }) as EvaluatorInput["constraints"],
    workflowSlice: {
      ...base.workflowSlice,
      ...(extra.workflowSlice || {}),
      ...(extra.workflowSlice?.parentSubmissionIds
        ? { parentSubmissionIds: [...extra.workflowSlice.parentSubmissionIds] }
        : {}),
      ...(extra.workflowSlice?.boundaryCrossings
        ? { boundaryCrossings: [...extra.workflowSlice.boundaryCrossings] }
        : {}),
    },
    decisionHistory: {
      ...base.decisionHistory,
      ...(extra.decisionHistory || {}),
      ...(extra.decisionHistory?.priorDecisions
        ? { priorDecisions: [...extra.decisionHistory.priorDecisions] }
        : {}),
      ...(extra.decisionHistory?.priorDenies
        ? { priorDenies: [...extra.decisionHistory.priorDenies] }
        : {}),
      ...(extra.decisionHistory?.priorEscalations
        ? { priorEscalations: [...extra.decisionHistory.priorEscalations] }
        : {}),
      ...(extra.decisionHistory?.priorClarifications
        ? {
            priorClarifications: [
              ...extra.decisionHistory.priorClarifications,
            ],
          }
        : {}),
      ...(extra.decisionHistory?.priorHumanResolutions
        ? {
            priorHumanResolutions: [
              ...extra.decisionHistory.priorHumanResolutions,
            ],
          }
        : {}),
    } as EvaluatorInput["decisionHistory"],
    executionHistory: {
      ...base.executionHistory,
      ...(extra.executionHistory || {}),
      ...(extra.executionHistory?.recentExecutions
        ? { recentExecutions: [...extra.executionHistory.recentExecutions] }
        : {}),
      ...(extra.executionHistory?.recentOutcomes
        ? { recentOutcomes: [...extra.executionHistory.recentOutcomes] }
        : {}),
    } as EvaluatorInput["executionHistory"],
    reflectionHistory: {
      ...base.reflectionHistory,
      ...(extra.reflectionHistory || {}),
      ...(extra.reflectionHistory?.recentReflections
        ? {
            recentReflections: [
              ...extra.reflectionHistory.recentReflections,
            ],
          }
        : {}),
      ...(extra.reflectionHistory?.persistentMissingFacts
        ? {
            persistentMissingFacts: [
              ...extra.reflectionHistory.persistentMissingFacts,
            ],
          }
        : {}),
    } as EvaluatorInput["reflectionHistory"],
    ...(extra.stateDeltas
      ? { stateDeltas: [...extra.stateDeltas] as EvaluatorInput["stateDeltas"] }
      : {}),
    ...(extra.auditEvidence
      ? {
          auditEvidence: [
            ...extra.auditEvidence,
          ] as EvaluatorInput["auditEvidence"],
        }
      : {}),
    derivedFacts: {
      ...base.derivedFacts,
      ...(extra.derivedFacts || {}),
      ...Object.fromEntries(
        [
          "missingApprovals",
          "verifiedFacts",
          "missingFacts",
          "supersededMissingFacts",
          "suggestedQuestions",
          "suggestedSources",
          "resumeConditions",
          "retryReasons",
          "recentToolErrors",
          "persistentReflectionMissingFacts",
          "contradictoryState",
        ]
          .filter(
            (key) =>
              Array.isArray(
                (extra.derivedFacts as Record<string, unknown> | undefined)?.[
                  key
                ],
              ),
          )
          .map((key) => [
            key,
            [
              ...((extra.derivedFacts as Record<string, unknown>)[
                key
              ] as unknown[]),
            ],
          ]),
      ),
    } as EvaluatorInput["derivedFacts"],
    metadata: {
      ...(base.metadata || {}),
      ...(extra.metadata || {}),
    },
  };
}

export function defaultContextualEvaluatorEligible(input: EvaluatorInput): boolean {
  if (input.action.sideEffect || input.action.crossesBoundary || input.action.disclosure) return true;
  if ((input.runtimeContext.unresolvedPrerequisites || []).length > 0) return true;
  if ((input.sourceUse.sources || []).length > 0) return true;
  const dataClasses = input.action.data?.classifications || [];
  return dataClasses.length > 0;
}
