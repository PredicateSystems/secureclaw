import { describe, it, expect } from "vitest";
import {
  extractAction,
  extractResource,
  isSensitiveResource,
  redactResource,
} from "./resource-extractor.js";

describe("extractAction", () => {
  it("maps file read tools to fs.read", () => {
    expect(extractAction("Read")).toBe("fs.read");
  });

  it("maps file write tools to fs.write", () => {
    expect(extractAction("Write")).toBe("fs.write");
    expect(extractAction("Edit")).toBe("fs.write");
    expect(extractAction("MultiEdit")).toBe("fs.write");
  });

  it("maps Glob to fs.list", () => {
    expect(extractAction("Glob")).toBe("fs.list");
  });

  it("maps Bash to shell.exec", () => {
    expect(extractAction("Bash")).toBe("shell.exec");
  });

  it("maps Task to agent.spawn", () => {
    expect(extractAction("Task")).toBe("agent.spawn");
  });

  it("maps web tools to http.request", () => {
    expect(extractAction("WebFetch")).toBe("http.request");
    expect(extractAction("WebSearch")).toBe("http.request");
  });

  it("maps browser tools correctly", () => {
    expect(extractAction("computer-use:screenshot")).toBe("browser.screenshot");
    expect(extractAction("computer-use:click")).toBe("browser.interact");
    expect(extractAction("computer-use:type")).toBe("browser.interact");
    expect(extractAction("computer-use:navigate")).toBe("browser.navigate");
  });

  it("returns generic action for unknown tools", () => {
    expect(extractAction("CustomTool")).toBe("tool.customtool");
    expect(extractAction("MyPlugin")).toBe("tool.myplugin");
  });
});

describe("extractResource", () => {
  describe("file operations", () => {
    it("extracts file_path from Read params", () => {
      expect(extractResource("Read", { file_path: "/src/index.ts" })).toBe("/src/index.ts");
    });

    it("extracts file_path from Write params", () => {
      expect(extractResource("Write", { file_path: "/src/new.ts", content: "..." })).toBe(
        "/src/new.ts",
      );
    });

    it("extracts file_path from Edit params", () => {
      expect(
        extractResource("Edit", { file_path: "/src/edit.ts", old_string: "a", new_string: "b" }),
      ).toBe("/src/edit.ts");
    });

    it("handles missing file path", () => {
      expect(extractResource("Read", {})).toBe("file:unknown");
    });
  });

  describe("Glob operations", () => {
    it("extracts pattern from Glob params", () => {
      expect(extractResource("Glob", { pattern: "**/*.ts" })).toBe("**/*.ts");
    });

    it("handles missing pattern", () => {
      expect(extractResource("Glob", {})).toBe("*");
    });
  });

  describe("Bash operations", () => {
    it("extracts command from Bash params", () => {
      expect(extractResource("Bash", { command: "npm test" })).toBe("npm test");
    });

    it("truncates long commands", () => {
      const longCommand =
        "npm run build && npm test && npm run lint && npm run format && echo done";
      const result = extractResource("Bash", { command: longCommand });
      expect(result.length).toBeLessThanOrEqual(100);
      expect(result).toContain("npm");
    });

    it("handles missing command", () => {
      expect(extractResource("Bash", {})).toBe("bash:unknown");
    });
  });

  describe("network operations", () => {
    it("extracts URL from WebFetch params", () => {
      expect(extractResource("WebFetch", { url: "https://example.com/api" })).toBe(
        "https://example.com/api",
      );
    });

    it("extracts query from WebSearch params", () => {
      expect(extractResource("WebSearch", { query: "typescript tutorial" })).toBe(
        "search:typescript tutorial",
      );
    });
  });

  describe("browser operations", () => {
    it("extracts URL from navigate params", () => {
      expect(extractResource("computer-use:navigate", { url: "https://example.com" })).toBe(
        "https://example.com",
      );
    });

    it("returns browser:current for other browser operations", () => {
      expect(extractResource("computer-use:screenshot", {})).toBe("browser:current");
      expect(extractResource("computer-use:click", { x: 100, y: 200 })).toBe("browser:current");
    });
  });

  describe("Task operations", () => {
    it("extracts prompt prefix from Task params", () => {
      const result = extractResource("Task", { prompt: "Search for files containing the error" });
      expect(result).toContain("task:");
      expect(result.length).toBeLessThanOrEqual(60);
    });
  });
});

describe("isSensitiveResource", () => {
  it("detects SSH paths", () => {
    expect(isSensitiveResource("/home/user/.ssh/id_rsa")).toBe(true);
    expect(isSensitiveResource("~/.ssh/config")).toBe(true);
  });

  it("detects AWS credentials", () => {
    expect(isSensitiveResource("/home/user/.aws/credentials")).toBe(true);
    expect(isSensitiveResource("aws_secret_key")).toBe(true);
  });

  it("detects environment files", () => {
    expect(isSensitiveResource(".env")).toBe(true);
    expect(isSensitiveResource(".env.local")).toBe(true);
    expect(isSensitiveResource("/app/.env.production")).toBe(true);
  });

  it("detects key files", () => {
    expect(isSensitiveResource("server.pem")).toBe(true);
    expect(isSensitiveResource("private.key")).toBe(true);
    expect(isSensitiveResource("id_ed25519")).toBe(true);
  });

  it("detects credential files", () => {
    expect(isSensitiveResource("credentials.json")).toBe(true);
    expect(isSensitiveResource("secrets.yaml")).toBe(true);
    expect(isSensitiveResource("api_key.txt")).toBe(true);
  });

  it("allows safe paths", () => {
    expect(isSensitiveResource("/src/index.ts")).toBe(false);
    expect(isSensitiveResource("README.md")).toBe(false);
    expect(isSensitiveResource("package.json")).toBe(false);
    expect(isSensitiveResource("/app/dist/bundle.js")).toBe(false);
  });
});

describe("redactResource", () => {
  it("redacts sensitive resources", () => {
    expect(redactResource("/home/user/.ssh/id_rsa")).toBe("[REDACTED]");
    expect(redactResource(".env.local")).toBe("[REDACTED]");
    expect(redactResource("credentials.json")).toBe("[REDACTED]");
  });

  it("passes through safe resources", () => {
    expect(redactResource("/src/index.ts")).toBe("/src/index.ts");
    expect(redactResource("package.json")).toBe("package.json");
  });
});
