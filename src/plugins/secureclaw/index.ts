/**
 * SecureClaw Plugin
 *
 * Zero-trust security middleware for OpenClaw.
 * Intercepts all tool calls with pre-authorization and post-verification.
 */

// Core plugin
export { createSecureClawPlugin, type SecureClawPluginOptions } from "./plugin.js";

// Resource extraction utilities
export {
  extractResource,
  extractAction,
  redactResource,
  isSensitiveResource,
} from "./resource-extractor.js";

// Configuration
export type { SecureClawConfig } from "./config.js";
export { defaultConfig, loadConfigFromEnv, mergeConfig } from "./config.js";

// Environment variables
export { isSecureClawEnabled, getSecureClawEnv, printSecureClawConfig, ENV_DOCS } from "./env.js";

// Auto-registration
export { autoRegisterSecureClaw, getSecureClawPlugin } from "./auto-register.js";
