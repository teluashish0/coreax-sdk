import type { CoreaxNodeKind } from "./configuration";
import {
  wrapCoreaxFunction,
  type CoreaxSpecializedWrapperOptions,
} from "./wrappers";

export type CoreaxDecoratorOptions = CoreaxSpecializedWrapperOptions;
export type CoreaxDecoratorInput =
  | string
  | CoreaxDecoratorOptions
  | undefined;

function normalizeDecoratorInput(
  input: CoreaxDecoratorInput,
): CoreaxDecoratorOptions {
  if (typeof input === "string") return { key: input };
  return input ?? {};
}

function inferredMethodKey(
  target: object,
  propertyKey: string | symbol,
): string {
  const constructorName =
    "constructor" in target &&
    typeof target.constructor === "function" &&
    target.constructor.name
      ? target.constructor.name
      : "Anonymous";
  return `${constructorName}.${String(propertyKey)}`;
}

function createCoreaxDecorator(
  kind: CoreaxNodeKind,
  input?: CoreaxDecoratorInput,
): MethodDecorator {
  const options = normalizeDecoratorInput(input);
  return (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor,
  ): PropertyDescriptor => {
    if (!descriptor || typeof descriptor.value !== "function") {
      throw new TypeError(
        `@coreax.${kind} can only be applied to a class method`,
      );
    }
    const key = options.key?.trim() || inferredMethodKey(target, propertyKey);
    descriptor.value = wrapCoreaxFunction(descriptor.value, {
      ...options,
      kind,
      key,
    });
    return descriptor;
  };
}

export function coreaxAgent(input?: CoreaxDecoratorInput): MethodDecorator {
  return createCoreaxDecorator("agent", input);
}

export function coreaxOrchestrator(input?: CoreaxDecoratorInput): MethodDecorator {
  return createCoreaxDecorator("orchestrator", input);
}

export function coreaxServer(input?: CoreaxDecoratorInput): MethodDecorator {
  return createCoreaxDecorator("server", input);
}

export function coreaxMiddleware(input?: CoreaxDecoratorInput): MethodDecorator {
  return createCoreaxDecorator("middleware", input);
}

export function coreaxTool(input?: CoreaxDecoratorInput): MethodDecorator {
  return createCoreaxDecorator("tool", input);
}

export function coreaxSkill(input?: CoreaxDecoratorInput): MethodDecorator {
  return createCoreaxDecorator("skill", input);
}

export type CoreaxDecoratorNamespace = Readonly<{
  agent: typeof coreaxAgent;
  orchestrator: typeof coreaxOrchestrator;
  server: typeof coreaxServer;
  middleware: typeof coreaxMiddleware;
  tool: typeof coreaxTool;
  skill: typeof coreaxSkill;
}>;

export const coreax: CoreaxDecoratorNamespace = Object.freeze({
  agent: coreaxAgent,
  orchestrator: coreaxOrchestrator,
  server: coreaxServer,
  middleware: coreaxMiddleware,
  tool: coreaxTool,
  skill: coreaxSkill,
});

export const coreaxDecorators = Object.freeze({
  "coreax-agent": coreaxAgent,
  "coreax-orchestrator": coreaxOrchestrator,
  "coreax-server": coreaxServer,
  "coreax-middleware": coreaxMiddleware,
  "coreax-tool": coreaxTool,
  "coreax-skill": coreaxSkill,
});
