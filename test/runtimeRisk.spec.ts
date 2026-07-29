import { describe, expect, it } from "vitest";

import {
  assessRunRisk,
  computeBehaviorDrift,
  computeDataExposureRisk,
  computeGoldenPathDrift,
  computeMandateDeviation,
  computeStatePersistence,
  DEFAULT_CHARACTER_NGRAM_VECTORIZER_CONFIG,
  vectorizeCharacterNgrams,
  type RuntimeRiskEvent,
  type SensitiveStateRule,
} from "../src/runtime-risk";

const BASE_TIME = Date.UTC(2026, 0, 1);
const isoAt = (milliseconds: number): string =>
  new Date(milliseconds).toISOString();
const secretFixture = (body: string): string =>
  ["sk", body].join("-");

function riskEvent(
  input: Partial<RuntimeRiskEvent> &
    Pick<RuntimeRiskEvent, "id" | "runId" | "nodeId">,
): RuntimeRiskEvent {
  return {
    timestamp: isoAt(BASE_TIME),
    nodeType: "tool",
    server: "local",
    tool: "read@1.0.0",
    decision: "allow",
    operation: "read",
    ...input,
  };
}

function baselineRuns(
  nodeId: string,
  count = 6,
  tools: readonly string[] = ["read@1.0.0"],
): RuntimeRiskEvent[] {
  return Array.from({ length: count }, (_, runIndex) =>
    tools.map((tool, eventIndex) =>
      riskEvent({
        id: `baseline-${nodeId}-${runIndex}-${eventIndex}`,
        runId: `baseline-run-${runIndex}`,
        nodeId,
        timestamp: isoAt(
          BASE_TIME + runIndex * 10_000 + eventIndex * 100,
        ),
        tool,
        operation: tool.startsWith("read") ? "read" : "summarize",
        latencyMs: 10,
      }),
    ),
  ).flat();
}

describe("runtime risk", () => {
  it("reports an unready baseline without treating missing history as drift", () => {
    const events = [
      riskEvent({ id: "current", runId: "run-current", nodeId: "node-a" }),
    ];
    const baseline = [
      riskEvent({ id: "base-1", runId: "base-run-1", nodeId: "node-a" }),
      riskEvent({ id: "base-2", runId: "base-run-2", nodeId: "node-a" }),
    ];

    const behavior = computeBehaviorDrift({
      nodeId: "node-a",
      events,
      baselineEvents: baseline,
    });
    const path = computeGoldenPathDrift({
      nodeId: "node-a",
      events,
      baselineEvents: baseline,
    });

    expect(behavior.score).toBe(0);
    expect(behavior.evidence.baseline).toMatchObject({
      ready: false,
      reason: "insufficient_events",
      eventCount: 2,
    });
    expect(path.score).toBe(0);
    expect(path.evidence.expected.source).toBe("none");
    expect(path.signals).toEqual([]);
  });

  it("uses inclusive thresholds for deterministic exposure signals", () => {
    const events = [
      riskEvent({
        id: "exposure",
        runId: "run-exposure",
        nodeId: "node-a",
        exposures: [
          {
            sink: "egress",
            detector: "rule",
            classification: "secret",
            severity: "high",
          },
        ],
      }),
    ];

    const atBoundary = computeDataExposureRisk({
      nodeId: "node-a",
      events,
      config: { aggregateSignalThreshold: 35 },
    });
    const aboveBoundary = computeDataExposureRisk({
      nodeId: "node-a",
      events,
      config: { aggregateSignalThreshold: 35.0001 },
    });

    expect(atBoundary.score).toBe(35);
    expect(atBoundary.signals).toHaveLength(1);
    expect(aboveBoundary.score).toBe(35);
    expect(aboveBoundary.signals).toHaveLength(0);
  });

  it("detects a novel tool and an unexpected learned path", () => {
    const baseline = baselineRuns("node-a", 6, [
      "read@1.0.0",
      "summarize@1.0.0",
    ]);
    const events = [
      riskEvent({
        id: "current-1",
        runId: "run-current",
        nodeId: "node-a",
        timestamp: isoAt(BASE_TIME + 100_000),
        tool: "read@2.0.0",
        latencyMs: 10,
      }),
      riskEvent({
        id: "current-2",
        runId: "run-current",
        nodeId: "node-a",
        timestamp: isoAt(BASE_TIME + 100_100),
        tool: "publish_external@1.0.0",
        operation: "summarize",
        latencyMs: 10,
      }),
    ];

    const behavior = computeBehaviorDrift({
      nodeId: "node-a",
      events,
      baselineEvents: baseline,
    });
    const path = computeGoldenPathDrift({
      nodeId: "node-a",
      events,
      baselineEvents: baseline,
      config: { transitionSignalNll: 2 },
    });

    expect(
      behavior.evidence.features.find((feature) => feature.key === "TOOL:tool"),
    ).toMatchObject({
      kind: "categorical",
      currentValue: "publish_external",
      contribution: 15,
    });
    expect(path.score).toBeGreaterThan(0);
    expect(path.evidence.deviations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "unexpected_token",
          atIndex: 1,
        }),
      ]),
    );
  });

  it("detects cross-node path drift and a node absent from the baseline", () => {
    const baseline = Array.from({ length: 3 }, (_, runIndex) => {
      const runId = `cross-baseline-${runIndex}`;
      const start = BASE_TIME + runIndex * 10_000;
      return [
        riskEvent({
          id: `${runId}-read`,
          runId,
          nodeId: "reader",
          timestamp: isoAt(start),
          tool: "read@1.0.0",
        }),
        riskEvent({
          id: `${runId}-summarize`,
          runId,
          nodeId: "summarizer",
          timestamp: isoAt(start + 100),
          tool: "summarize@1.0.0",
          operation: "summarize",
        }),
      ];
    }).flat();
    const assessment = assessRunRisk({
      runId: "cross-current",
      baselineEvents: baseline,
      events: [
        riskEvent({
          id: "cross-current-read",
          runId: "cross-current",
          nodeId: "reader",
          timestamp: isoAt(BASE_TIME + 100_000),
          tool: "read@1.0.0",
        }),
        riskEvent({
          id: "cross-current-publish",
          runId: "cross-current",
          nodeId: "novel-publisher",
          timestamp: isoAt(BASE_TIME + 100_100),
          tool: "publish@1.0.0",
          operation: "publish",
        }),
      ],
    });

    const novelNode = assessment.nodes.find(
      (node) => node.nodeId === "novel-publisher",
    );
    expect(novelNode?.subscores.golden_path_drift).toBeGreaterThanOrEqual(60);
    expect(novelNode?.evidence.goldenPathDrift.crossNode).toMatchObject({
      expected: { source: "learned" },
      deviations: [
        expect.objectContaining({
          kind: "unexpected_token",
          hop: expect.objectContaining({ eventId: "cross-current-publish" }),
        }),
      ],
    });
    expect(
      novelNode?.signals.map((signal) => signal.code),
    ).toContain("golden_path_drift:novel_token");
  });

  it("detects retention and same-value cross-node propagation", () => {
    const secretValue = secretFixture("1234567890abcdefghijklmnop");
    const events = [
      riskEvent({
        id: "node-a-1",
        runId: "run-state",
        nodeId: "node-a",
        timestamp: isoAt(BASE_TIME),
        state: { AGENT: { sessionToken: secretValue } },
      }),
      riskEvent({
        id: "node-a-2",
        runId: "run-state",
        nodeId: "node-a",
        timestamp: isoAt(BASE_TIME + 100),
        state: { AGENT: { sessionToken: secretValue } },
      }),
      riskEvent({
        id: "node-a-3",
        runId: "run-state",
        nodeId: "node-a",
        timestamp: isoAt(BASE_TIME + 200),
        state: { AGENT: { sessionToken: secretValue } },
      }),
      riskEvent({
        id: "node-b-1",
        runId: "run-state",
        nodeId: "node-b",
        timestamp: isoAt(BASE_TIME + 300),
        state: { AGENT: { sessionToken: secretValue } },
      }),
    ];

    const assessment = assessRunRisk({
      runId: "run-state",
      events,
      sensitiveStateRules: [{ scope: "AGENT", key: "sessionToken" }],
    });

    expect(assessment.subscores.state_persistence).toBe(40);
    expect(
      assessment.nodes
        .find((node) => node.nodeId === "node-a")
        ?.evidence.statePersistence.violations.map(
          (violation) => violation.kind,
        ),
    ).toEqual(
      expect.arrayContaining([
        "sensitive_persisted",
        "cross_node_propagation",
      ]),
    );
    const serialized = JSON.stringify(assessment);
    expect(serialized).not.toContain(secretValue);
    expect(serialized).toMatch(/[a-f0-9]{64}/);
  });

  it("does not call different sensitive values cross-node propagation", () => {
    const assessment = assessRunRisk({
      runId: "run-distinct-state",
      events: [
        riskEvent({
          id: "node-a",
          runId: "run-distinct-state",
          nodeId: "node-a",
          state: {
            AGENT: {
              sessionToken: secretFixture("aaaaaaaaaaaaaaaa11111111"),
            },
          },
        }),
        riskEvent({
          id: "node-b",
          runId: "run-distinct-state",
          nodeId: "node-b",
          state: {
            AGENT: {
              sessionToken: secretFixture("bbbbbbbbbbbbbbbb22222222"),
            },
          },
        }),
      ],
      sensitiveStateRules: [{ scope: "AGENT", key: "sessionToken" }],
    });

    expect(assessment.subscores.state_persistence).toBe(0);
    expect(
      assessment.nodes.flatMap(
        (node) => node.evidence.statePersistence.violations,
      ),
    ).toEqual([]);
  });

  it("detects sensitive values in every scope and preserves observed scopes", () => {
    const secretValue = secretFixture("crossscope1234567890abcdef");
    const assessment = assessRunRisk({
      runId: "run-auto-sensitive",
      events: [
        riskEvent({
          id: "auto-sensitive-tool",
          runId: "run-auto-sensitive",
          nodeId: "node-a",
          timestamp: isoAt(BASE_TIME),
          state: { TOOL: { payload: secretValue } },
        }),
        riskEvent({
          id: "auto-sensitive-server",
          runId: "run-auto-sensitive",
          nodeId: "node-b",
          timestamp: isoAt(BASE_TIME + 100),
          state: { SERVER: { copied: secretValue } },
        }),
      ],
    });

    const nodeAPropagation = assessment.nodes
      .find((node) => node.nodeId === "node-a")
      ?.evidence.statePersistence.violations.find(
        (violation) => violation.kind === "cross_node_propagation",
      );
    const nodeBPropagation = assessment.nodes
      .find((node) => node.nodeId === "node-b")
      ?.evidence.statePersistence.violations.find(
        (violation) => violation.kind === "cross_node_propagation",
      );
    expect(nodeAPropagation).toMatchObject({
      observedScopes: ["TOOL"],
    });
    expect(nodeBPropagation).toMatchObject({
      observedScopes: ["SERVER"],
    });
    expect(JSON.stringify(assessment)).not.toContain(secretValue);
  });

  it("never emits a secret embedded in a state key name", () => {
    const secretKey = secretFixture("secretkeyname1234567890abcdef");
    const events = [0, 1, 2].map((index) =>
      riskEvent({
        id: `secret-key-${index}`,
        runId: "run-secret-key",
        nodeId: "node-a",
        timestamp: isoAt(BASE_TIME + index * 100),
        state: { AGENT: { [secretKey]: "same-value" } },
      }),
    );
    const assessment = assessRunRisk({
      runId: "run-secret-key",
      events,
      sensitiveStateRules: [{ scope: "AGENT", key: secretKey }],
    });
    const serialized = JSON.stringify(assessment);

    expect(serialized).not.toContain(secretKey);
    expect(
      assessment.nodes[0].evidence.statePersistence.violations[0]?.key,
    ).toMatch(/^AGENT:sha256:[a-f0-9]{64}$/);
  });

  it("scores explicit and tagged data exposure without copying rule text", () => {
    const privateRuleId = "internal-sensitive-egress-rule";
    const result = computeDataExposureRisk({
      nodeId: "node-a",
      events: [
        riskEvent({
          id: "exposure",
          runId: "run-exposure",
          nodeId: "node-a",
          riskTags: ["egress_violation"],
          guardFindings: 2,
          exposures: [
            {
              sink: "agent_state",
              detector: "classifier",
              classification: "pii",
              severity: "critical",
              ruleId: privateRuleId,
            },
          ],
        }),
      ],
    });

    expect(result.score).toBe(100);
    expect(result.evidence.exposures).toHaveLength(3);
    expect(result.evidence.exposures[0]).toMatchObject({
      sink: "agent_state",
      classification: "pii",
      severity: "critical",
    });
    expect(JSON.stringify(result)).not.toContain(privateRuleId);
  });

  it("scores malformed explicit exposure labels critically without echoing them", () => {
    const rawSink = secretFixture("malicious-sink-label-1234567890");
    const rawDetector = secretFixture("malicious-detector-1234567890");
    const rawClassification = secretFixture(
      "malicious-classification-1234567890",
    );
    const rawSeverity = secretFixture(
      "malicious-severity-1234567890",
    );
    const rawRule = secretFixture("malicious-rule-1234567890");
    const result = computeDataExposureRisk({
      nodeId: "node-a",
      events: [
        riskEvent({
          id: "malformed-exposure",
          runId: "run-malformed-exposure",
          nodeId: "node-a",
          exposures: [
            {
              sink: rawSink,
              detector: rawDetector,
              classification: rawClassification,
              severity: rawSeverity,
              ruleId: rawRule,
            } as never,
          ],
        }),
      ],
    });
    const serialized = JSON.stringify(result);

    expect(result.score).toBe(50);
    expect(result.evidence.exposures[0]).toMatchObject({
      sink: "unknown",
      detector: "rule",
      classification: "unknown",
      severity: "critical",
      ruleIdSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    for (const raw of [
      rawSink,
      rawDetector,
      rawClassification,
      rawSeverity,
      rawRule,
    ]) {
      expect(serialized).not.toContain(raw);
    }
  });

  it("detects AP2 mandate deviation and hashes mandate identifiers", () => {
    const rawCartId = "cart-private-42";
    const rawIssuer = "did:example:private-issuer";
    const result = computeMandateDeviation({
      nodeId: "payment-node",
      events: [
        riskEvent({
          id: "payment-1",
          runId: "run-payment",
          nodeId: "payment-node",
          reasonCode: "ap2_mandate_missing",
          mandate: {
            cartId: rawCartId,
            issuerDid: rawIssuer,
            violations: ["ap2_cart_constraint_failed"],
          },
        }),
      ],
    });

    expect(result.score).toBe(80);
    expect(result.evidence.violations.map((violation) => violation.code)).toEqual(
      ["ap2_cart_constraint_failed", "ap2_mandate_missing"],
    );
    expect(result.evidence.context.cartIdSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.evidence.context.issuerDidSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(result)).not.toContain(rawCartId);
    expect(JSON.stringify(result)).not.toContain(rawIssuer);
  });

  it("detects mandate context changes without exposing either context", () => {
    const originalCart = "cart-private-original";
    const changedCart = "cart-private-replaced";
    const result = computeMandateDeviation({
      nodeId: "payment-node",
      events: [
        riskEvent({
          id: "payment-context-1",
          runId: "run-payment-context",
          nodeId: "payment-node",
          mandate: {
            intentId: "intent-1",
            cartId: originalCart,
            constraintsSha256: "a".repeat(64),
          },
        }),
        riskEvent({
          id: "payment-context-2",
          runId: "run-payment-context",
          nodeId: "payment-node",
          timestamp: isoAt(BASE_TIME + 1),
          mandate: {
            intentId: "intent-1",
            cartId: changedCart,
            constraintsSha256: "b".repeat(64),
          },
        }),
      ],
    });

    expect(result.evidence.violations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "mandate_cart_changed",
          source: "context",
        }),
        expect.objectContaining({
          code: "mandate_constraints_changed",
          source: "context",
        }),
      ]),
    );
    expect(JSON.stringify(result)).not.toContain(originalCart);
    expect(JSON.stringify(result)).not.toContain(changedCart);
  });

  it("detects mandate context deletion after a field is established", () => {
    const result = computeMandateDeviation({
      nodeId: "payment-node",
      events: [
        riskEvent({
          id: "mandate-present",
          runId: "run-mandate-deletion",
          nodeId: "payment-node",
          mandate: {
            cartId: "cart-private",
            constraintsSha256: "a".repeat(64),
          },
        }),
        riskEvent({
          id: "mandate-deleted",
          runId: "run-mandate-deletion",
          nodeId: "payment-node",
          timestamp: isoAt(BASE_TIME + 1),
        }),
      ],
    });

    expect(result.score).toBe(80);
    expect(result.evidence.violations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "mandate_cart_missing" }),
        expect.objectContaining({ code: "mandate_constraints_missing" }),
      ]),
    );
  });

  it("detects premature golden-path termination using the learned END transition", () => {
    const baseline = baselineRuns("node-a", 6, [
      "read@1.0.0",
      "summarize@1.0.0",
      "publish@1.0.0",
    ]);
    const events = [
      riskEvent({
        id: "prefix-read",
        runId: "run-prefix",
        nodeId: "node-a",
        timestamp: isoAt(BASE_TIME + 100_000),
        tool: "read@1.0.0",
      }),
      riskEvent({
        id: "prefix-summarize",
        runId: "run-prefix",
        nodeId: "node-a",
        timestamp: isoAt(BASE_TIME + 100_100),
        tool: "summarize@1.0.0",
        operation: "summarize",
      }),
    ];

    const result = computeGoldenPathDrift({
      nodeId: "node-a",
      events,
      baselineEvents: baseline,
    });

    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.evidence.deviations).toContainEqual(
      expect.objectContaining({
        kind: "unexpected_transition",
        atIndex: 2,
        details: expect.objectContaining({
          to: "__END__",
          observedCount: 0,
        }),
      }),
    );
  });

  it("rejects duplicate event IDs in current and baseline inputs", () => {
    const duplicate = [
      riskEvent({
        id: "duplicate-event",
        runId: "run-duplicate",
        nodeId: "node-a",
      }),
      riskEvent({
        id: "duplicate-event",
        runId: "run-duplicate",
        nodeId: "node-b",
        timestamp: isoAt(BASE_TIME + 1),
      }),
    ];

    expect(() =>
      assessRunRisk({ runId: "run-duplicate", events: duplicate }),
    ).toThrow(/event IDs must be unique/);
    expect(() =>
      computeGoldenPathDrift({
        nodeId: "node-a",
        events: [duplicate[0]],
        baselineEvents: [
          riskEvent({
            ...duplicate[0],
            runId: "baseline-1",
          }),
          riskEvent({
            ...duplicate[0],
            runId: "baseline-2",
          }),
        ],
      }),
    ).toThrow(/event IDs must be unique/);
  });

  it("rejects identifiers that collide after output normalization", () => {
    expect(() =>
      assessRunRisk({
        runId: "run-normalized",
        events: [
          riskEvent({
            id: "event-normalized",
            runId: "run-normalized",
            nodeId: "node-a",
          }),
          riskEvent({
            id: " event-normalized ",
            runId: "run-normalized",
            nodeId: "node-b",
            timestamp: isoAt(BASE_TIME + 1),
          }),
        ],
      }),
    ).toThrow(/surrounding whitespace/);

    expect(() =>
      assessRunRisk({
        runId: "run-normalized",
        events: [
          riskEvent({
            id: "event-a",
            runId: "run-normalized",
            nodeId: " node-a ",
          }),
        ],
      }),
    ).toThrow(/non-canonical identifier/);
  });

  it("rejects non-finite and weakening numeric configuration", () => {
    const current = [
      riskEvent({
        id: "numeric-config",
        runId: "run-numeric-config",
        nodeId: "node-a",
      }),
    ];
    const baseline = baselineRuns("node-a");
    const calls = [
      () =>
        assessRunRisk({
          runId: "run-numeric-config",
          events: current,
          config: { maximumSignals: Number.NaN },
        }),
      () =>
        computeBehaviorDrift({
          nodeId: "node-a",
          events: current,
          baselineEvents: baseline,
          config: { weights: { tool: Number.POSITIVE_INFINITY } },
        }),
      () =>
        computeGoldenPathDrift({
          nodeId: "node-a",
          events: current,
          baselineEvents: baseline,
          config: { smoothingAlpha: Number.NaN },
        }),
      () =>
        computeStatePersistence({
          nodeId: "node-a",
          events: current,
          config: { retentionViolationScore: 0 },
        }),
      () =>
        computeDataExposureRisk({
          nodeId: "node-a",
          events: current,
          config: { maximumExposures: Number.POSITIVE_INFINITY },
        }),
      () =>
        computeMandateDeviation({
          nodeId: "node-a",
          events: current,
          config: { maximumViolations: -1 },
        }),
      () =>
        vectorizeCharacterNgrams("example", {
          ...DEFAULT_CHARACTER_NGRAM_VECTORIZER_CONFIG,
          dimensions: Number.POSITIVE_INFINITY,
        }),
    ];

    for (const call of calls) expect(call).toThrow(/finite|at least/);
  });

  it("sanitizes secret-like run, node, event, trace, and model identifiers", () => {
    const runId = secretFixture("run-identifier-1234567890");
    const nodeId = secretFixture("node-identifier-1234567890");
    const eventId = secretFixture("event-identifier-1234567890");
    const traceId = secretFixture("trace-identifier-1234567890");
    const modelVersion = secretFixture("model-identifier-1234567890");
    const assessment = assessRunRisk({
      runId,
      events: [
        riskEvent({
          id: eventId,
          runId,
          nodeId,
          traceId,
          riskTags: ["egress_violation"],
        }),
      ],
      config: { modelVersion },
    });
    const serialized = JSON.stringify(assessment);

    for (const raw of [runId, nodeId, eventId, traceId, modelVersion]) {
      expect(serialized).not.toContain(raw);
    }
    expect(assessment.runId).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(assessment.nodes[0].nodeId).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(assessment.nodes[0].evidence.dataExposureRisk.exposures[0].hop.eventId)
      .toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("produces byte-stable assessments from identical explicit inputs", () => {
    const secretValue = secretFixture(
      "abcdef1234567890abcdef1234567890",
    );
    const input = {
      runId: "run-deterministic",
      events: [
        riskEvent({
          id: "event-1",
          runId: "run-deterministic",
          nodeId: "node-a",
          timestamp: "2026-01-02T00:00:00.000Z",
          state: { AGENT: { apiKey: secretValue } },
          riskTags: ["sensitive_state_egress"],
        }),
      ],
      baselineEvents: baselineRuns("node-a"),
      sensitiveStateRules: [{ scope: "AGENT" as const, key: "apiKey" }],
    };

    const first = JSON.stringify(assessRunRisk(input));
    const second = JSON.stringify(assessRunRisk(input));

    expect(first).toBe(second);
    expect(first).not.toContain(secretValue);
    expect(JSON.parse(first)).toMatchObject({
      overallScore: 50,
      subscores: { data_exposure_risk: 50 },
      model: {
        version: "coreax-runtime-risk-v1",
        aggregation: "maximum",
      },
    });
  });

  it("rejects ambiguous, numeric, and impossible runtime timestamps", () => {
    const base = riskEvent({
      id: "invalid-time",
      runId: "run-invalid-time",
      nodeId: "node-a",
    });
    for (const timestamp of [
      "2026-01-01T00:00:00",
      "2026-02-30T00:00:00Z",
      BASE_TIME as unknown as string,
    ]) {
      expect(() =>
        assessRunRisk({
          runId: "run-invalid-time",
          events: [{ ...base, timestamp }],
        }),
      ).toThrow(/RFC3339|timestamp/);
    }
  });

  it("fails closed on malformed or duplicate sensitive-state rules", () => {
    const event = riskEvent({
      id: "rule-validation",
      runId: "run-rule-validation",
      nodeId: "node-a",
    });
    const invalidRules = [
      [{ scope: "UNKNOWN", key: "token" }],
      [{ scope: "AGENT", key: "" }],
      [{ scope: "AGENT", key: " token" }],
      [
        { scope: "AGENT", key: "token" },
        { scope: "AGENT", key: "token" },
      ],
    ];

    for (const sensitiveStateRules of invalidRules) {
      expect(() =>
        assessRunRisk({
          runId: "run-rule-validation",
          events: [event],
          sensitiveStateRules:
            sensitiveStateRules as unknown as SensitiveStateRule[],
        }),
      ).toThrow(/sensitiveStateRules/);
    }
  });
});
