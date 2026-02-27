/**
 * SecureClaw Plugin Implementation
 *
 * Integrates Predicate Authority for pre-execution authorization
 * and post-execution verification into OpenClaw's hook system.
 */

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
import {
  type SecureClawConfig,
  defaultConfig,
  loadConfigFromEnv,
  mergeConfig,
} from "./config.js";
import {
  extractAction,
  extractResource,
  redactResource,
} from "./resource-extractor.js";

export interface SecureClawPluginOptions extends Partial<SecureClawConfig> {}

interface AuthorizationDecision {
  allow: boolean;
  reason?: string;
  mandateId?: string;
}

interface AuthorizationRequest {
  principal: string;
  action: string;
  resource: string;
  intent_hash: string;
  labels?: string[];
}

/**
 * Simple stable JSON serialization for intent hashing.
 */
function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableJson(v)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([a], [b]) => a.localeCompare(b),
    );
    return `{${entries
      .map(([k, v]) => `${JSON.stringify(k)}:${stableJson(v)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * Compute SHA-256 hash of intent parameters.
 */
async function computeIntentHash(params: Record<string, unknown>): Promise<string> {
  const encoded = stableJson(params);
  // Use Web Crypto API for Node.js 18+
  const encoder = new TextEncoder();
  const data = encoder.encode(encoded);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

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
        (event: PluginHookSessionStartEvent, ctx: PluginHookSessionContext) => {
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
        (event: PluginHookSessionEndEvent, ctx: PluginHookSessionContext) => {
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
            // Compute intent hash for request verification
            const intentHash = await computeIntentHash(params);

            // Build authorization request
            const authRequest: AuthorizationRequest = {
              principal: config.principal,
              action,
              resource,
              intent_hash: intentHash,
              labels: buildLabels(ctx, config),
            };

            // Call Predicate Authority sidecar
            const decision = await authorizeWithSidecar(
              authRequest,
              config.sidecarUrl,
              config.verbose ? log : undefined,
            );

            if (!decision.allow) {
              metrics.blocked++;
              toolCallMetrics.set(toolName, metrics);

              const reason = decision.reason ?? "denied_by_policy";
              if (config.verbose) {
                log.warn(`[SecureClaw] BLOCKED: ${action} - ${reason}`);
              }

              return {
                block: true,
                blockReason: `[SecureClaw] Action blocked: ${reason}`,
              };
            }

            if (config.verbose) {
              log.info(`[SecureClaw] ALLOWED: ${action} (mandate: ${decision.mandateId ?? "none"})`);
            }

            // Allow the tool call to proceed
            return undefined;
          } catch (error) {
            // Handle sidecar unavailability
            const errorMessage = error instanceof Error ? error.message : String(error);

            if (config.failClosed) {
              metrics.blocked++;
              toolCallMetrics.set(toolName, metrics);

              log.error(`[SecureClaw] Sidecar error (fail-closed): ${errorMessage}`);
              return {
                block: true,
                blockReason: `[SecureClaw] Authorization service unavailable (fail-closed mode)`,
              };
            }

            log.warn(`[SecureClaw] Sidecar error (fail-open): ${errorMessage}`);
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
        async (
          event: PluginHookAfterToolCallEvent,
          ctx: PluginHookToolContext,
        ): Promise<void> => {
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

          // Log to audit trail
          await emitAuditEvent({
            sessionId: currentSessionId,
            action,
            resource: redactResource(resource),
            toolName,
            success: !error,
            error: error,
            durationMs,
            timestamp: new Date().toISOString(),
            principal: config.principal,
            tenantId: config.tenantId,
            userId: config.userId,
          });
        },
        { priority: 100 },
      );

      log.info("[SecureClaw] Plugin activated - all tool calls will be authorized");
    },
  };
}

/**
 * Build labels for authorization request context.
 */
function buildLabels(
  ctx: PluginHookToolContext,
  config: SecureClawConfig,
): string[] {
  const labels: string[] = [];

  if (ctx.agentId) {
    labels.push(`agent:${ctx.agentId}`);
  }
  if (ctx.sessionKey) {
    labels.push(`session:${ctx.sessionKey}`);
  }
  if (config.tenantId) {
    labels.push(`tenant:${config.tenantId}`);
  }
  if (config.userId) {
    labels.push(`user:${config.userId}`);
  }

  labels.push("source:secureclaw");

  return labels;
}

/**
 * Call the Predicate Authority sidecar for authorization.
 */
async function authorizeWithSidecar(
  request: AuthorizationRequest,
  sidecarUrl: string,
  log?: { info: (msg: string) => void },
): Promise<AuthorizationDecision> {
  const url = `${sidecarUrl}/authorize`;

  if (log) {
    log.info(`[SecureClaw] Calling sidecar: ${url}`);
  }

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(5000), // 5 second timeout
  });

  if (!response.ok) {
    throw new Error(`Sidecar returned ${response.status}: ${response.statusText}`);
  }

  const decision = (await response.json()) as AuthorizationDecision;
  return decision;
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

/**
 * Emit an audit event for logging/compliance.
 */
async function emitAuditEvent(event: {
  sessionId?: string;
  action: string;
  resource: string;
  toolName: string;
  success: boolean;
  error?: string;
  durationMs?: number;
  timestamp: string;
  principal: string;
  tenantId?: string;
  userId?: string;
}): Promise<void> {
  // TODO: Send to audit log collector
  // For now, this is a no-op placeholder

  // In production:
  // 1. Send to centralized audit log (e.g., via OTLP)
  // 2. Include correlation IDs for tracing
  // 3. Ensure tamper-proof storage
}
