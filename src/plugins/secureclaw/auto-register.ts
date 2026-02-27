/**
 * SecureClaw Auto-Registration
 *
 * This module is imported early in the OpenClaw boot sequence to
 * auto-register the SecureClaw security plugin.
 */

import { isSecureClawEnabled } from "./env.js";
import { createSecureClawPlugin } from "./plugin.js";

/**
 * Auto-register SecureClaw with the plugin system.
 * Returns the plugin definition for manual registration if needed.
 */
export function autoRegisterSecureClaw(): ReturnType<typeof createSecureClawPlugin> | null {
  if (!isSecureClawEnabled()) {
    console.log("[SecureClaw] Disabled via SECURECLAW_DISABLED=true");
    return null;
  }

  const plugin = createSecureClawPlugin();

  console.log("[SecureClaw] Security middleware initialized");
  console.log("[SecureClaw] All tool calls will be authorized before execution");

  return plugin;
}

/**
 * Get the SecureClaw plugin without auto-registering.
 * Use this for manual plugin registration.
 */
export function getSecureClawPlugin(): ReturnType<typeof createSecureClawPlugin> {
  return createSecureClawPlugin();
}

// Export for direct import
export { createSecureClawPlugin } from "./plugin.js";
export { isSecureClawEnabled } from "./env.js";
