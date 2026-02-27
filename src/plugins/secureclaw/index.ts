/**
 * SecureClaw Plugin
 *
 * Zero-trust security middleware for OpenClaw.
 * Intercepts all tool calls with pre-authorization and post-verification.
 */

export { createSecureClawPlugin, type SecureClawPluginOptions } from "./plugin.js";
export { extractResource, extractAction } from "./resource-extractor.js";
export type { SecureClawConfig } from "./config.js";
