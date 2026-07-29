import type {
  GuardApprovalAction,
  GuardApprovalTransport,
} from "./types";

export function createNoopApprovalTransport(): GuardApprovalTransport {
  return {
    platform: "none",
    capabilities: {
      interactiveActions: false,
      cards: false,
    },
    async sendPending() {},
    async sendResolved() {},
    parseApprovalAction(): GuardApprovalAction | null {
      return null;
    },
  };
}
