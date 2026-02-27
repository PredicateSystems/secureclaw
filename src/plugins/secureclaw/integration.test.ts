import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { createSecureClawPlugin } from "./plugin.js";
import { extractAction, extractResource } from "./resource-extractor.js";

/**
 * Integration tests for SecureClaw plugin.
 *
 * These tests verify the full authorization flow from tool call
 * to predicate-claw SDK to decision enforcement.
 *
 * Note: These tests mock the predicate-claw SDK but test the full plugin integration.
 * For live sidecar tests, see the e2e test suite.
 */

// Create mock function outside vi.mock for access
const mockGuardOrThrow = vi.fn();

// Mock error class
class MockActionDeniedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ActionDeniedError";
  }
}

// Mock predicate-claw SDK
vi.mock("predicate-claw", () => {
  class MockSidecarUnavailableError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "SidecarUnavailableError";
    }
  }

  class MockGuardedProvider {
    guardOrThrow = mockGuardOrThrow;
  }

  return {
    GuardedProvider: MockGuardedProvider,
    ActionDeniedError: MockActionDeniedError,
    SidecarUnavailableError: MockSidecarUnavailableError,
  };
});

// Alias for use in tests
const ActionDeniedError = MockActionDeniedError;

describe("SecureClaw Integration", () => {
  // Track all hook registrations
  let mockLogger: {
    info: ReturnType<typeof vi.fn>;
    warn: ReturnType<typeof vi.fn>;
    error: ReturnType<typeof vi.fn>;
  };

  beforeAll(() => {
    mockLogger = {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  describe("Full authorization flow", () => {
    it("blocks sensitive file access with detailed reason", async () => {
      const plugin = createSecureClawPlugin({
        principal: "agent:test",
        sidecarUrl: "http://test-sidecar:8787",
        failClosed: true,
        verbose: true,
      });

      const hooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: mockLogger,
        on: vi.fn((hookName: string, handler: Function) => {
          hooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Mock SDK to deny .ssh access
      mockGuardOrThrow.mockRejectedValueOnce(new ActionDeniedError("sensitive_resource_blocked"));

      const beforeToolCall = hooks.get("before_tool_call")!;

      // Try to read SSH key
      const result = await beforeToolCall(
        {
          toolName: "Read",
          params: { file_path: "/home/user/.ssh/id_rsa" },
        },
        { toolName: "Read", agentId: "test-agent" },
      );

      expect(result).toMatchObject({
        block: true,
        blockReason: expect.stringContaining("sensitive_resource_blocked"),
      });

      // Verify SDK was called with correct action/resource
      expect(mockGuardOrThrow).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "fs.read",
          resource: "/home/user/.ssh/id_rsa",
        }),
      );
    });

    it("allows safe operations and tracks metrics", async () => {
      const plugin = createSecureClawPlugin({
        verbose: true,
      });

      const hooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: mockLogger,
        on: vi.fn((hookName: string, handler: Function) => {
          hooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Start session
      const sessionStart = hooks.get("session_start")!;
      sessionStart({ sessionId: "integration-test-123" }, { sessionId: "integration-test-123" });

      // Mock SDK to allow with mandate ID
      mockGuardOrThrow.mockResolvedValue("mandate-abc");

      const beforeToolCall = hooks.get("before_tool_call")!;

      // Multiple tool calls
      for (const file of ["index.ts", "utils.ts", "config.ts"]) {
        const result = await beforeToolCall(
          {
            toolName: "Read",
            params: { file_path: `/src/${file}` },
          },
          { toolName: "Read" },
        );
        expect(result).toBeUndefined(); // Allowed
      }

      // End session - should log metrics
      const sessionEnd = hooks.get("session_end")!;
      sessionEnd(
        { sessionId: "integration-test-123", messageCount: 5, durationMs: 1000 },
        { sessionId: "integration-test-123" },
      );

      // Verify metrics logged
      expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining("Tool metrics"));
    });

    it("handles shell command authorization", async () => {
      const plugin = createSecureClawPlugin({ verbose: false });

      const hooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: mockLogger,
        on: vi.fn((hookName: string, handler: Function) => {
          hooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Test dangerous command - should be denied
      mockGuardOrThrow.mockRejectedValueOnce(new ActionDeniedError("dangerous_shell_command"));

      const beforeToolCall = hooks.get("before_tool_call")!;

      const dangerousResult = await beforeToolCall(
        {
          toolName: "Bash",
          params: { command: "rm -rf /" },
        },
        { toolName: "Bash" },
      );

      expect(dangerousResult).toMatchObject({
        block: true,
      });

      // Test safe command - should be allowed
      mockGuardOrThrow.mockResolvedValueOnce("safe-cmd");

      const safeResult = await beforeToolCall(
        {
          toolName: "Bash",
          params: { command: "npm test" },
        },
        { toolName: "Bash" },
      );

      expect(safeResult).toBeUndefined();
    });
  });

  describe("Action and resource extraction", () => {
    it("correctly maps OpenClaw tools to Predicate actions", () => {
      // File operations
      expect(extractAction("Read")).toBe("fs.read");
      expect(extractAction("Write")).toBe("fs.write");
      expect(extractAction("Edit")).toBe("fs.write");
      expect(extractAction("Glob")).toBe("fs.list");

      // Shell
      expect(extractAction("Bash")).toBe("shell.exec");

      // Network
      expect(extractAction("WebFetch")).toBe("http.request");

      // Browser
      expect(extractAction("computer-use:navigate")).toBe("browser.navigate");
      expect(extractAction("computer-use:click")).toBe("browser.interact");

      // Agent
      expect(extractAction("Task")).toBe("agent.spawn");
    });

    it("extracts resources from various param formats", () => {
      // Standard file_path
      expect(extractResource("Read", { file_path: "/app/src/main.ts" })).toBe("/app/src/main.ts");

      // Alternative path key
      expect(extractResource("Read", { path: "/app/config.json" })).toBe("/app/config.json");

      // Bash command
      expect(extractResource("Bash", { command: "npm install" })).toBe("npm install");

      // URL
      expect(extractResource("WebFetch", { url: "https://api.example.com" })).toBe(
        "https://api.example.com",
      );

      // Browser navigation
      expect(extractResource("computer-use:navigate", { url: "https://app.example.com" })).toBe(
        "https://app.example.com",
      );
    });
  });

  describe("Error handling", () => {
    it("handles sidecar timeout gracefully", async () => {
      const plugin = createSecureClawPlugin({
        failClosed: true,
        verbose: false,
      });

      const hooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: mockLogger,
        on: vi.fn((hookName: string, handler: Function) => {
          hooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Mock timeout via generic error (SDK converts to appropriate error)
      mockGuardOrThrow.mockRejectedValueOnce(new Error("Timeout"));

      const beforeToolCall = hooks.get("before_tool_call")!;

      const result = await beforeToolCall(
        {
          toolName: "Read",
          params: { file_path: "/src/index.ts" },
        },
        { toolName: "Read" },
      );

      // Should block in fail-closed mode
      expect(result).toMatchObject({
        block: true,
        blockReason: expect.stringContaining("unavailable"),
      });
    });

    it("handles SDK throwing ActionDeniedError correctly", async () => {
      const plugin = createSecureClawPlugin({
        failClosed: true,
        verbose: false,
      });

      const hooks: Map<string, Function> = new Map();
      const mockApi = {
        logger: mockLogger,
        on: vi.fn((hookName: string, handler: Function) => {
          hooks.set(hookName, handler);
        }),
      };

      await plugin.activate?.(
        mockApi as unknown as Parameters<NonNullable<typeof plugin.activate>>[0],
      );

      // Mock SDK throwing ActionDeniedError (policy denied)
      mockGuardOrThrow.mockRejectedValueOnce(new ActionDeniedError("no_matching_allow_rule"));

      const beforeToolCall = hooks.get("before_tool_call")!;

      const result = await beforeToolCall(
        {
          toolName: "Read",
          params: { file_path: "/src/index.ts" },
        },
        { toolName: "Read" },
      );

      // Should block with policy reason
      expect(result).toMatchObject({
        block: true,
        blockReason: expect.stringContaining("no_matching_allow_rule"),
      });
    });
  });
});
