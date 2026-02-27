/**
 * SecureClaw Environment Configuration
 *
 * All SecureClaw settings can be configured via environment variables.
 * This file documents and validates all supported environment variables.
 */

export interface SecureClawEnvConfig {
  /** Agent principal identifier (default: "agent:secureclaw") */
  SECURECLAW_PRINCIPAL?: string;

  /** Path to YAML policy file (default: "./policies/default.yaml") */
  SECURECLAW_POLICY?: string;

  /** Predicate Authority sidecar URL (default: "http://127.0.0.1:9120") */
  PREDICATE_SIDECAR_URL?: string;

  /** Set to "true" to fail-open when sidecar is unavailable (default: false) */
  SECURECLAW_FAIL_OPEN?: string;

  /** Set to "false" to disable post-execution verification (default: true) */
  SECURECLAW_VERIFY?: string;

  /** Set to "true" for verbose logging (default: false) */
  SECURECLAW_VERBOSE?: string;

  /** Tenant ID for multi-tenant deployments */
  SECURECLAW_TENANT_ID?: string;

  /** User ID for audit attribution */
  SECURECLAW_USER_ID?: string;

  /** Set to "true" to completely disable SecureClaw */
  SECURECLAW_DISABLED?: string;
}

/**
 * Check if SecureClaw is enabled via environment.
 */
export function isSecureClawEnabled(): boolean {
  return process.env.SECURECLAW_DISABLED !== "true";
}

/**
 * Get all SecureClaw environment variables with their current values.
 */
export function getSecureClawEnv(): SecureClawEnvConfig {
  return {
    SECURECLAW_PRINCIPAL: process.env.SECURECLAW_PRINCIPAL,
    SECURECLAW_POLICY: process.env.SECURECLAW_POLICY,
    PREDICATE_SIDECAR_URL: process.env.PREDICATE_SIDECAR_URL,
    SECURECLAW_FAIL_OPEN: process.env.SECURECLAW_FAIL_OPEN,
    SECURECLAW_VERIFY: process.env.SECURECLAW_VERIFY,
    SECURECLAW_VERBOSE: process.env.SECURECLAW_VERBOSE,
    SECURECLAW_TENANT_ID: process.env.SECURECLAW_TENANT_ID,
    SECURECLAW_USER_ID: process.env.SECURECLAW_USER_ID,
    SECURECLAW_DISABLED: process.env.SECURECLAW_DISABLED,
  };
}

/**
 * Print SecureClaw configuration for debugging.
 */
export function printSecureClawConfig(): void {
  const env = getSecureClawEnv();
  console.log("SecureClaw Configuration:");
  console.log("  SECURECLAW_PRINCIPAL:", env.SECURECLAW_PRINCIPAL ?? "(default: agent:secureclaw)");
  console.log("  SECURECLAW_POLICY:", env.SECURECLAW_POLICY ?? "(default: ./policies/default.yaml)");
  console.log("  PREDICATE_SIDECAR_URL:", env.PREDICATE_SIDECAR_URL ?? "(default: http://127.0.0.1:9120)");
  console.log("  SECURECLAW_FAIL_OPEN:", env.SECURECLAW_FAIL_OPEN ?? "(default: false)");
  console.log("  SECURECLAW_VERIFY:", env.SECURECLAW_VERIFY ?? "(default: true)");
  console.log("  SECURECLAW_VERBOSE:", env.SECURECLAW_VERBOSE ?? "(default: false)");
  console.log("  SECURECLAW_TENANT_ID:", env.SECURECLAW_TENANT_ID ?? "(not set)");
  console.log("  SECURECLAW_USER_ID:", env.SECURECLAW_USER_ID ?? "(not set)");
  console.log("  SECURECLAW_DISABLED:", env.SECURECLAW_DISABLED ?? "(default: false)");
}

/**
 * Environment variable documentation for README.
 */
export const ENV_DOCS = `
## SecureClaw Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| \`SECURECLAW_PRINCIPAL\` | \`agent:secureclaw\` | Agent identity for authorization requests |
| \`SECURECLAW_POLICY\` | \`./policies/default.yaml\` | Path to YAML policy file |
| \`PREDICATE_SIDECAR_URL\` | \`http://127.0.0.1:9120\` | Predicate Authority sidecar endpoint |
| \`SECURECLAW_FAIL_OPEN\` | \`false\` | Set to \`true\` to allow actions when sidecar is unavailable |
| \`SECURECLAW_VERIFY\` | \`true\` | Set to \`false\` to disable post-execution verification |
| \`SECURECLAW_VERBOSE\` | \`false\` | Set to \`true\` for detailed logging |
| \`SECURECLAW_TENANT_ID\` | *(none)* | Tenant ID for multi-tenant deployments |
| \`SECURECLAW_USER_ID\` | *(none)* | User ID for audit attribution |
| \`SECURECLAW_DISABLED\` | \`false\` | Set to \`true\` to completely disable SecureClaw |
`;
