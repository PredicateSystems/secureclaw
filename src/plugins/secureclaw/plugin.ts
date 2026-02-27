/**
 * SecureClaw Plugin Implementation
 *
 * Integrates Predicate Authority for pre-execution authorization
 * and post-execution verification into OpenClaw's hook system.
 *
 * Uses predicate-claw (openclaw-predicate-provider) for authorization
 * via the GuardedProvider class, which communicates with the
 * rust-predicate-authorityd sidecar.
 */

import {
  GuardedProvider,
  ActionDeniedError,
  SidecarUnavailableError,
  type GuardRequest,
  type GuardTelemetry,
  type DecisionTelemetryEvent,
  type DecisionAuditExporter,
} from "predicate-claw";
import type {
  OpenClawPluginDefinition,
  OpenClawPluginApi,
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
  PluginHookAfterToolCallEvent,
  PluginHookSessionStartEvent,
  PluginHookSessionEndEvent,
  PluginHookToolContext,
  PluginHookSessionContext,
} from "../types.js";
import { type SecureClawConfig, defaultConfig, loadConfigFromEnv, mergeConfig } from "./config.js";
import { extractAction, extractResource, redactResource } from "./resource-extractor.js";

export interface SecureClawPluginOptions extends Partial<SecureClawConfig> {}

/**
 * Create the SecureClaw plugin instance.
 */
export function createSecureClawPlugin(
  options: SecureClawPluginOptions = {},
): OpenClawPluginDefinition {
  // Merge config: defaults -> env -> explicit options
  const envConfig = loadConfigFromEnv();
  const config = mergeConfig(mergeConfig(defaultConfig, envConfig), options);

  // Session tracking for audit trail
  let currentSessionId: string | undefined;
  let sessionStartTime: number | undefined;
  const toolCallMetrics: Map<string, { count: number; blocked: number }> = new Map();

  return {
    id: "secureclaw",
    name: "SecureClaw",
    description: "Zero-trust security middleware with pre-authorization and post-verification",
    version: "1.0.0",

    async activate(api: OpenClawPluginApi) {
      const log = api.logger;

      // Create telemetry handler for logging decisions
      const telemetry: GuardTelemetry = {
        onDecision(event: DecisionTelemetryEvent) {
          if (config.verbose) {
            const status =
              event.outcome === "allow"
                ? "ALLOWED"
                : event.outcome === "deny"
                  ? "BLOCKED"
                  : "ERROR";
            log.info(
              `[SecureClaw] ${status}: ${event.action} on ${event.resource} (${event.reason ?? "no reason"})`,
            );
          }
        },
      };

      // Create audit exporter if needed
      const auditExporter: DecisionAuditExporter = {
        async exportDecision(_event: DecisionTelemetryEvent) {
          // TODO: Send to centralized audit log (e.g., via OTLP)
          // For now, this is a no-op placeholder
          // In production:
          // 1. Send to centralized audit log
          // 2. Include correlation IDs for tracing
          // 3. Ensure tamper-proof storage
        },
      };

      // Create GuardedProvider instance from predicate-claw SDK
      const guardedProvider = new GuardedProvider({
        principal: config.principal,
        config: {
          baseUrl: config.sidecarUrl,
          failClosed: config.failClosed,
          timeoutMs: 5000, // 5 second timeout for tool calls
          maxRetries: 0,
          backoffInitialMs: 100,
        },
        telemetry,
        auditExporter,
      });

      if (config.verbose) {
        log.info(`[SecureClaw] Activating with principal: ${config.principal}`);
        log.info(`[SecureClaw] Sidecar URL: ${config.sidecarUrl}`);
        log.info(`[SecureClaw] Fail closed: ${config.failClosed}`);
        log.info(`[SecureClaw] Post-verification: ${config.enablePostVerification}`);
      }

      // =======================================================================
      // Hook: session_start - Initialize audit trail
      // =======================================================================
      api.on(
        "session_start",
        (event: PluginHookSessionStartEvent, _ctx: PluginHookSessionContext) => {
          currentSessionId = event.sessionId;
          sessionStartTime = Date.now();
          toolCallMetrics.clear();

          if (config.verbose) {
            log.info(`[SecureClaw] Session started: ${event.sessionId}`);
          }
        },
        { priority: 100 }, // High priority to run early
      );

      // =======================================================================
      // Hook: session_end - Finalize audit trail
      // =======================================================================
      api.on(
        "session_end",
        (event: PluginHookSessionEndEvent, _ctx: PluginHookSessionContext) => {
          const duration = sessionStartTime ? Date.now() - sessionStartTime : 0;

          if (config.verbose) {
            log.info(`[SecureClaw] Session ended: ${event.sessionId}`);
            log.info(`[SecureClaw] Duration: ${duration}ms`);
            log.info(`[SecureClaw] Tool metrics:`);
            for (const [tool, metrics] of toolCallMetrics) {
              log.info(`  ${tool}: ${metrics.count} calls, ${metrics.blocked} blocked`);
            }
          }

          // Reset state
          currentSessionId = undefined;
          sessionStartTime = undefined;
          toolCallMetrics.clear();
        },
        { priority: 100 },
      );

      // =======================================================================
      // Hook: before_tool_call - Pre-execution authorization gate
      // =======================================================================
      api.on(
        "before_tool_call",
        async (
          event: PluginHookBeforeToolCallEvent,
          ctx: PluginHookToolContext,
        ): Promise<PluginHookBeforeToolCallResult | void> => {
          const { toolName, params } = event;
          const action = extractAction(toolName);
          const resource = extractResource(toolName, params);

          // Track metrics
          const metrics = toolCallMetrics.get(toolName) ?? { count: 0, blocked: 0 };
          metrics.count++;
          toolCallMetrics.set(toolName, metrics);

          if (config.verbose) {
            log.info(`[SecureClaw] Pre-auth: ${action} on ${redactResource(resource)}`);
          }

          try {
            // Build guard request for predicate-claw SDK
            const guardRequest: GuardRequest = {
              action,
              resource,
              args: params,
              context: {
                session_id: currentSessionId ?? ctx.sessionKey,
                tenant_id: config.tenantId,
                user_id: config.userId,
                agent_id: ctx.agentId,
                source: "secureclaw",
              },
            };

            // Use guardOrThrow which handles fail-open/fail-closed internally
            await guardedProvider.guardOrThrow(guardRequest);

            // If we get here, the action was allowed
            return undefined;
          } catch (error) {
            // Handle ActionDeniedError - action was explicitly denied by policy
            if (error instanceof ActionDeniedError) {
              metrics.blocked++;
              toolCallMetrics.set(toolName, metrics);

              const reason = error.message ?? "denied_by_policy";
              if (config.verbose) {
                log.warn(`[SecureClaw] BLOCKED: ${action} - ${reason}`);
              }

              return {
                block: true,
                blockReason: `[SecureClaw] Action blocked: ${reason}`,
              };
            }

            // Handle SidecarUnavailableError - sidecar is down
            if (error instanceof SidecarUnavailableError) {
              // In fail-closed mode (handled by guardOrThrow), this error is thrown
              // In fail-open mode, guardOrThrow returns null instead of throwing
              metrics.blocked++;
              toolCallMetrics.set(toolName, metrics);

              log.error(`[SecureClaw] Sidecar error (fail-closed): ${error.message}`);
              return {
                block: true,
                blockReason: `[SecureClaw] Authorization service unavailable (fail-closed mode)`,
              };
            }

            // Unknown error - treat as sidecar unavailable
            const errorMessage = error instanceof Error ? error.message : String(error);
            if (config.failClosed) {
              metrics.blocked++;
              toolCallMetrics.set(toolName, metrics);

              log.error(`[SecureClaw] Unknown error (fail-closed): ${errorMessage}`);
              return {
                block: true,
                blockReason: `[SecureClaw] Authorization service unavailable (fail-closed mode)`,
              };
            }

            log.warn(`[SecureClaw] Unknown error (fail-open): ${errorMessage}`);
            return undefined; // Allow in fail-open mode
          }
        },
        { priority: 1000 }, // Very high priority - security checks first
      );

      // =======================================================================
      // Hook: after_tool_call - Post-execution verification
      // =======================================================================
      api.on(
        "after_tool_call",
        async (event: PluginHookAfterToolCallEvent, _ctx: PluginHookToolContext): Promise<void> => {
          if (!config.enablePostVerification) {
            return;
          }

          const { toolName, params, result, error, durationMs } = event;
          const action = extractAction(toolName);
          const resource = extractResource(toolName, params);

          if (config.verbose) {
            log.info(
              `[SecureClaw] Post-verify: ${action} on ${redactResource(resource)} ` +
                `(${durationMs ?? 0}ms, error: ${error ? "yes" : "no"})`,
            );
          }

          // For browser operations, verify DOM state
          if (action.startsWith("browser.")) {
            await verifyBrowserState(toolName, params, result, log, config.verbose);
          }

          // For file operations, verify write success
          if (action === "fs.write" && !error) {
            await verifyFileWrite(toolName, params, result, log, config.verbose);
          }
        },
        { priority: 100 },
      );

      log.info("[SecureClaw] Plugin activated - all tool calls will be authorized");
    },
  };
}

/**
 * Verify browser state after browser operations (placeholder for Snapshot Engine).
 */
async function verifyBrowserState(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
  log: { info: (msg: string) => void; warn: (msg: string) => void },
  verbose: boolean,
): Promise<void> {
  // TODO: Integrate with Snapshot Engine for DOM diffing
  // This is a placeholder for post-execution verification

  if (verbose) {
    log.info(`[SecureClaw] Browser verification: ${toolName} (placeholder)`);
  }

  // In full implementation:
  // 1. Capture DOM snapshot after operation
  // 2. Compare against expected state from pre-operation snapshot
  // 3. Verify only authorized changes occurred
  // 4. Flag any unexpected DOM mutations
}

/**
 * Verify file write operations completed as expected.
 */
async function verifyFileWrite(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
  log: { info: (msg: string) => void; warn: (msg: string) => void },
  verbose: boolean,
): Promise<void> {
  // TODO: Implement file verification
  // This is a placeholder for post-execution verification

  if (verbose) {
    log.info(`[SecureClaw] File write verification: ${toolName} (placeholder)`);
  }

  // In full implementation:
  // 1. Read file after write
  // 2. Compute hash of written content
  // 3. Compare against intent_hash from authorization
  // 4. Flag any discrepancies
}
