#!/usr/bin/env node

/**
 * SecureClaw CLI Entry Point
 *
 * This is the main entry point for SecureClaw - a zero-trust security
 * fork of OpenClaw with pre-authorization and post-verification.
 *
 * SecureClaw automatically intercepts all tool calls and enforces
 * authorization policies before execution.
 */

import module from "node:module";

// Enable compile cache for faster startup
if (module.enableCompileCache && !process.env.NODE_DISABLE_COMPILE_CACHE) {
  try {
    module.enableCompileCache();
  } catch {
    // Ignore errors
  }
}

// Print SecureClaw banner
const showBanner = process.env.SECURECLAW_QUIET !== "true";
if (showBanner) {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║                                                              ║");
  console.log("║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗          ║");
  console.log("║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝          ║");
  console.log("║   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗            ║");
  console.log("║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝            ║");
  console.log("║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗          ║");
  console.log("║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝          ║");
  console.log("║                    ██████╗██╗      █████╗ ██╗    ██╗         ║");
  console.log("║                   ██╔════╝██║     ██╔══██╗██║    ██║         ║");
  console.log("║                   ██║     ██║     ███████║██║ █╗ ██║         ║");
  console.log("║                   ██║     ██║     ██╔══██║██║███╗██║         ║");
  console.log("║                   ╚██████╗███████╗██║  ██║╚███╔███╔╝         ║");
  console.log("║                    ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝          ║");
  console.log("║                                                              ║");
  console.log("║      Zero-Trust Security for AI Agents                       ║");
  console.log("║      https://predicatesystems.ai/docs/secure-claw            ║");
  console.log("║                                                              ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  console.log("");
}

// Check if SecureClaw is disabled
if (process.env.SECURECLAW_DISABLED === "true") {
  console.warn("⚠️  SecureClaw security is DISABLED via SECURECLAW_DISABLED=true");
  console.warn("⚠️  Tool calls will NOT be authorized. This is NOT recommended.");
  console.warn("");
}

const isModuleNotFoundError = (err) =>
  err && typeof err === "object" && "code" in err && err.code === "ERR_MODULE_NOT_FOUND";

const installProcessWarningFilter = async () => {
  for (const specifier of ["./dist/warning-filter.js", "./dist/warning-filter.mjs"]) {
    try {
      const mod = await import(specifier);
      if (typeof mod.installProcessWarningFilter === "function") {
        mod.installProcessWarningFilter();
        return;
      }
    } catch (err) {
      if (isModuleNotFoundError(err)) {
        continue;
      }
      throw err;
    }
  }
};

await installProcessWarningFilter();

const tryImport = async (specifier) => {
  try {
    await import(specifier);
    return true;
  } catch (err) {
    if (isModuleNotFoundError(err)) {
      return false;
    }
    throw err;
  }
};

// Import SecureClaw plugin and register it
// Note: The plugin is automatically registered via the bundled plugin system
// This import ensures the security hooks are active before any tool calls

if (await tryImport("./dist/entry.js")) {
  // OK
} else if (await tryImport("./dist/entry.mjs")) {
  // OK
} else {
  throw new Error("secureclaw: missing dist/entry.(m)js (build output).");
}