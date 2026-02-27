/**
 * SecureClaw Configuration
 */

export interface SecureClawConfig {
  /** Agent principal identifier for authorization requests */
  principal: string;

  /** Path to YAML policy file */
  policyFile: string;

  /** Predicate Authority sidecar URL */
  sidecarUrl: string;

  /** Fail closed when sidecar is unavailable (default: true) */
  failClosed: boolean;

  /** Enable post-execution verification via Snapshot Engine (default: true) */
  enablePostVerification: boolean;

  /** Enable verbose logging */
  verbose: boolean;

  /** Session ID for audit trail correlation */
  sessionId?: string;

  /** Tenant ID for multi-tenant deployments */
  tenantId?: string;

  /** User ID for audit attribution */
  userId?: string;
}

export const defaultConfig: SecureClawConfig = {
  principal: "agent:secureclaw",
  policyFile: "./policies/default.yaml",
  sidecarUrl: "http://127.0.0.1:9120",
  failClosed: true,
  enablePostVerification: true,
  verbose: false,
};

export function loadConfigFromEnv(): Partial<SecureClawConfig> {
  return {
    principal: process.env.SECURECLAW_PRINCIPAL,
    policyFile: process.env.SECURECLAW_POLICY,
    sidecarUrl: process.env.PREDICATE_SIDECAR_URL,
    failClosed: process.env.SECURECLAW_FAIL_OPEN !== "true",
    enablePostVerification: process.env.SECURECLAW_VERIFY !== "false",
    verbose: process.env.SECURECLAW_VERBOSE === "true",
    tenantId: process.env.SECURECLAW_TENANT_ID,
    userId: process.env.SECURECLAW_USER_ID,
  };
}

export function mergeConfig(
  base: SecureClawConfig,
  overrides: Partial<SecureClawConfig>,
): SecureClawConfig {
  return {
    ...base,
    ...Object.fromEntries(
      Object.entries(overrides).filter(([_, v]) => v !== undefined),
    ),
  } as SecureClawConfig;
}
