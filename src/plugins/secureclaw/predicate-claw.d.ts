/**
 * Type declarations for predicate-claw SDK
 *
 * predicate-claw is the TypeScript SDK for integrating with
 * Predicate Authority's rust-predicate-authorityd sidecar.
 */

declare module "predicate-claw" {
  /**
   * Guard request sent to the sidecar for authorization.
   */
  export interface GuardRequest {
    /** The action being performed (e.g., "fs.read", "shell.exec") */
    action: string;
    /** The resource being accessed (e.g., file path, command) */
    resource: string;
    /** Optional arguments/parameters for the action */
    args?: Record<string, unknown>;
    /** Additional context for the authorization decision */
    context?: {
      session_id?: string;
      tenant_id?: string;
      user_id?: string;
      agent_id?: string;
      source?: string;
      [key: string]: unknown;
    };
  }

  /**
   * Telemetry event emitted after each authorization decision.
   */
  export interface DecisionTelemetryEvent {
    /** The action that was evaluated */
    action: string;
    /** The resource that was accessed */
    resource: string;
    /** The outcome of the authorization decision */
    outcome: "allow" | "deny" | "error";
    /** Human-readable reason for the decision */
    reason?: string;
    /** Timestamp of the decision */
    timestamp?: number;
    /** Duration of the decision in milliseconds */
    durationMs?: number;
    /** Mandate ID if the action was allowed */
    mandateId?: string;
  }

  /**
   * Telemetry handler for logging/monitoring authorization decisions.
   */
  export interface GuardTelemetry {
    /** Called after each authorization decision */
    onDecision: (event: DecisionTelemetryEvent) => void;
  }

  /**
   * Audit exporter for persisting authorization decisions.
   */
  export interface DecisionAuditExporter {
    /** Export a decision for audit logging */
    exportDecision: (event: DecisionTelemetryEvent) => Promise<void>;
  }

  /**
   * Configuration for the GuardedProvider.
   */
  export interface GuardedProviderConfig {
    /** Base URL of the predicate-authorityd sidecar */
    baseUrl: string;
    /** Whether to fail closed (block) when sidecar is unavailable */
    failClosed: boolean;
    /** Request timeout in milliseconds */
    timeoutMs?: number;
    /** Maximum number of retries */
    maxRetries?: number;
    /** Initial backoff delay in milliseconds */
    backoffInitialMs?: number;
  }

  /**
   * Options for creating a GuardedProvider.
   */
  export interface GuardedProviderOptions {
    /** The principal (agent identity) making requests */
    principal: string;
    /** Configuration for the sidecar connection */
    config: GuardedProviderConfig;
    /** Optional telemetry handler */
    telemetry?: GuardTelemetry;
    /** Optional audit exporter */
    auditExporter?: DecisionAuditExporter;
  }

  /**
   * Error thrown when an action is denied by policy.
   */
  export class ActionDeniedError extends Error {
    constructor(message: string);
    name: "ActionDeniedError";
  }

  /**
   * Error thrown when the sidecar is unavailable.
   */
  export class SidecarUnavailableError extends Error {
    constructor(message: string);
    name: "SidecarUnavailableError";
  }

  /**
   * The main class for making guarded requests to the sidecar.
   */
  export class GuardedProvider {
    constructor(options: GuardedProviderOptions);

    /**
     * Guard a request and throw if denied.
     *
     * @param request The guard request
     * @returns The mandate ID if allowed, null if fail-open allowed
     * @throws ActionDeniedError if the action is denied by policy
     * @throws SidecarUnavailableError if the sidecar is unavailable (fail-closed mode)
     */
    guardOrThrow(request: GuardRequest): Promise<string | null>;
  }
}
