import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type {
  PluginHookBeforeToolCallEvent,
  PluginHookAfterToolCallEvent,
  PluginHookSessionStartEvent,
  PluginHookSessionEndEvent,
  PluginHookToolContext,
  PluginHookSessionContext,
} from "../types.js";
import { createSecureClawPlugin } from "./plugin.js";

// Use vi.hoisted to define mocks that will be available when vi.mock is hoisted
const { mockGuardOrThrow, ActionDeniedError, SidecarUnavailableError } = vi.hoisted(() => {
  const mockGuardOrThrow = vi.fn();

  class ActionDeniedError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "ActionDeniedError";
    }
  }

  class SidecarUnavailableError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "SidecarUnavailableError";
    }
  }

  return { mockGuardOrThrow, ActionDeniedError, SidecarUnavailableError };
});

// Mock predicate-claw SDK
vi.mock("predicate-claw", () => {
  class MockGuardedProvider {
    guardOrThrow = mockGuardOrThrow;
  }

  return {
    GuardedProvider: MockGuardedProvider,
    ActionDeniedError,
    SidecarUnavailableError,
  };
});

describe("SecureClaw Plugin", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("createSecureClawPlugin", () => {
    it("creates a plugin with correct metadata", () => {
      const plugin = createSecureClawPlugin();

      expect(plugin.id).toBe("secureclaw");
      expect(plugin.name).toBe("SecureClaw");
      expect(plugin.version).toBe("1.0.0");
      expect(plugin.description?.toLowerCase()).toContain("zero-trust");
    });

    it("accepts custom options", () => {
      const plugin = createSecureClawPlugin({
        principal: "agent:custom",
        sidecarUrl: "http://localhost:9999",
        failClosed: false,
        verbose: true,
      });

      expect(plugin).toBeDefined();
    });
  });

  describe("before_tool_call hook", () => {
    it("blocks tool call when sidecar denies", async () => {
      const plugin = createSecureClawPlugin({ verbose: false });

      // Mock API to capture registered hooks
      const registeredHooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: {
          info: vi.fn(),
          warn: vi.fn(),
          error: vi.fn(),
        },
        on: vi.fn((hookName: string, handler: Function) => {
          registeredHooks.set(hookName, handler);
        }),
      };

      // Activate plugin
      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Mock SDK to throw ActionDeniedError
      mockGuardOrThrow.mockRejectedValueOnce(new ActionDeniedError("policy_violation"));

      // Get the before_tool_call handler
      const beforeToolCall = registeredHooks.get("before_tool_call");
      expect(beforeToolCall).toBeDefined();

      // Call the handler
      const event: PluginHookBeforeToolCallEvent = {
        toolName: "Bash",
        params: { command: "rm -rf /" },
      };
      const ctx: PluginHookToolContext = {
        toolName: "Bash",
        agentId: "test-agent",
        sessionKey: "test-session",
      };

      const result = await beforeToolCall!(event, ctx);

      expect(result).toEqual({
        block: true,
        blockReason: expect.stringContaining("policy_violation"),
      });
    });

    it("allows tool call when sidecar approves", async () => {
      const plugin = createSecureClawPlugin({ verbose: false });

      const registeredHooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: {
          info: vi.fn(),
          warn: vi.fn(),
          error: vi.fn(),
        },
        on: vi.fn((hookName: string, handler: Function) => {
          registeredHooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Mock SDK to return mandate ID (allowed)
      mockGuardOrThrow.mockResolvedValueOnce("mandate-123");

      const beforeToolCall = registeredHooks.get("before_tool_call");
      const event: PluginHookBeforeToolCallEvent = {
        toolName: "Read",
        params: { file_path: "/src/index.ts" },
      };
      const ctx: PluginHookToolContext = {
        toolName: "Read",
      };

      const result = await beforeToolCall!(event, ctx);

      // Should return undefined (allow)
      expect(result).toBeUndefined();
    });

    it("blocks in fail-closed mode when sidecar unavailable", async () => {
      const plugin = createSecureClawPlugin({
        failClosed: true,
        verbose: false,
      });

      const registeredHooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: {
          info: vi.fn(),
          warn: vi.fn(),
          error: vi.fn(),
        },
        on: vi.fn((hookName: string, handler: Function) => {
          registeredHooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Mock SDK to throw SidecarUnavailableError
      mockGuardOrThrow.mockRejectedValueOnce(new SidecarUnavailableError("Connection refused"));

      const beforeToolCall = registeredHooks.get("before_tool_call");
      const event: PluginHookBeforeToolCallEvent = {
        toolName: "Bash",
        params: { command: "echo hello" },
      };
      const ctx: PluginHookToolContext = {
        toolName: "Bash",
      };

      const result = await beforeToolCall!(event, ctx);

      expect(result).toEqual({
        block: true,
        blockReason: expect.stringContaining("unavailable"),
      });
    });

    it("allows in fail-open mode when sidecar unavailable", async () => {
      const plugin = createSecureClawPlugin({
        failClosed: false,
        verbose: false,
      });

      const registeredHooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: {
          info: vi.fn(),
          warn: vi.fn(),
          error: vi.fn(),
        },
        on: vi.fn((hookName: string, handler: Function) => {
          registeredHooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Mock SDK to return null (fail-open behavior from guardOrThrow)
      mockGuardOrThrow.mockResolvedValueOnce(null);

      const beforeToolCall = registeredHooks.get("before_tool_call");
      const event: PluginHookBeforeToolCallEvent = {
        toolName: "Read",
        params: { file_path: "/src/index.ts" },
      };
      const ctx: PluginHookToolContext = {
        toolName: "Read",
      };

      const result = await beforeToolCall!(event, ctx);

      // Should return undefined (allow in fail-open)
      expect(result).toBeUndefined();
    });
  });

  describe("session hooks", () => {
    it("tracks session start and end", async () => {
      const plugin = createSecureClawPlugin({ verbose: true });

      const registeredHooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: {
          info: vi.fn(),
          warn: vi.fn(),
          error: vi.fn(),
        },
        on: vi.fn((hookName: string, handler: Function) => {
          registeredHooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Session start
      const sessionStart = registeredHooks.get("session_start");
      expect(sessionStart).toBeDefined();

      const startEvent: PluginHookSessionStartEvent = {
        sessionId: "test-session-123",
      };
      const startCtx: PluginHookSessionContext = {
        sessionId: "test-session-123",
      };

      sessionStart!(startEvent, startCtx);

      expect(mockApi.logger.info).toHaveBeenCalledWith(expect.stringContaining("Session started"));

      // Session end
      const sessionEnd = registeredHooks.get("session_end");
      expect(sessionEnd).toBeDefined();

      const endEvent: PluginHookSessionEndEvent = {
        sessionId: "test-session-123",
        messageCount: 10,
        durationMs: 5000,
      };

      sessionEnd!(endEvent, startCtx);

      expect(mockApi.logger.info).toHaveBeenCalledWith(expect.stringContaining("Session ended"));
    });
  });

  describe("after_tool_call hook", () => {
    it("logs tool execution for verification", async () => {
      const plugin = createSecureClawPlugin({
        enablePostVerification: true,
        verbose: true,
      });

      const registeredHooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: {
          info: vi.fn(),
          warn: vi.fn(),
          error: vi.fn(),
        },
        on: vi.fn((hookName: string, handler: Function) => {
          registeredHooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      const afterToolCall = registeredHooks.get("after_tool_call");
      expect(afterToolCall).toBeDefined();

      const event: PluginHookAfterToolCallEvent = {
        toolName: "Read",
        params: { file_path: "/src/index.ts" },
        result: "file contents...",
        durationMs: 50,
      };
      const ctx: PluginHookToolContext = {
        toolName: "Read",
      };

      await afterToolCall!(event, ctx);

      expect(mockApi.logger.info).toHaveBeenCalledWith(expect.stringContaining("Post-verify"));
    });

    it("skips verification when disabled", async () => {
      const plugin = createSecureClawPlugin({
        enablePostVerification: false,
        verbose: true,
      });

      const registeredHooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: {
          info: vi.fn(),
          warn: vi.fn(),
          error: vi.fn(),
        },
        on: vi.fn((hookName: string, handler: Function) => {
          registeredHooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      const afterToolCall = registeredHooks.get("after_tool_call");

      const event: PluginHookAfterToolCallEvent = {
        toolName: "Read",
        params: { file_path: "/src/index.ts" },
        result: "file contents...",
        durationMs: 50,
      };
      const ctx: PluginHookToolContext = {
        toolName: "Read",
      };

      await afterToolCall!(event, ctx);

      // Should not log post-verify when disabled
      expect(mockApi.logger.info).not.toHaveBeenCalledWith(expect.stringContaining("Post-verify"));
    });
  });
});
