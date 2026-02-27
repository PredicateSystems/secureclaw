/**
 * Resource Extractor
 *
 * Maps OpenClaw tool calls to Predicate Authority action/resource pairs.
 */

export type ActionResource = {
  action: string;
  resource: string;
};

/**
 * Extract the action type from a tool name.
 */
export function extractAction(toolName: string): string {
  // Map OpenClaw tool names to Predicate action categories
  const actionMap: Record<string, string> = {
    // File system operations
    Read: "fs.read",
    Write: "fs.write",
    Edit: "fs.write",
    Glob: "fs.list",
    MultiEdit: "fs.write",

    // Shell/process operations
    Bash: "shell.exec",
    Task: "agent.spawn",

    // Network operations
    WebFetch: "http.request",
    WebSearch: "http.request",

    // Browser automation
    "computer-use:screenshot": "browser.screenshot",
    "computer-use:click": "browser.interact",
    "computer-use:type": "browser.interact",
    "computer-use:scroll": "browser.interact",
    "computer-use:navigate": "browser.navigate",

    // Notebook operations
    NotebookRead: "notebook.read",
    NotebookEdit: "notebook.write",

    // MCP tool calls
    mcp_tool: "mcp.call",
  };

  return actionMap[toolName] ?? `tool.${toolName.toLowerCase()}`;
}

/**
 * Extract the resource identifier from tool parameters.
 */
export function extractResource(toolName: string, params: Record<string, unknown>): string {
  switch (toolName) {
    // File operations - extract path
    case "Read":
    case "Write":
    case "Edit":
    case "MultiEdit":
      return extractFilePath(params);

    // Glob - extract pattern as resource
    case "Glob":
      return typeof params.pattern === "string" ? params.pattern : "*";

    // Bash - extract command (first 100 chars for safety)
    case "Bash":
      return extractBashCommand(params);

    // Network operations - extract URL
    case "WebFetch":
    case "WebSearch":
      return typeof params.url === "string"
        ? params.url
        : typeof params.query === "string"
          ? `search:${params.query}`
          : "unknown";

    // Browser operations - extract URL or target
    case "computer-use:navigate":
      return typeof params.url === "string" ? params.url : "browser:current";

    case "computer-use:screenshot":
    case "computer-use:click":
    case "computer-use:type":
    case "computer-use:scroll":
      return "browser:current";

    // Task/Agent spawning
    case "Task":
      return typeof params.prompt === "string"
        ? `task:${params.prompt.slice(0, 50)}`
        : "task:unknown";

    // Notebook operations
    case "NotebookRead":
    case "NotebookEdit":
      return typeof params.notebook_path === "string" ? params.notebook_path : "notebook:unknown";

    // MCP tools - extract tool name and server
    case "mcp_tool":
      return extractMcpResource(params);

    default:
      // For unknown tools, try common parameter names
      return (
        extractFilePath(params) ||
        (typeof params.path === "string" ? params.path : null) ||
        (typeof params.target === "string" ? params.target : null) ||
        `${toolName}:params`
      );
  }
}

function extractFilePath(params: Record<string, unknown>): string {
  // Try common file path parameter names
  const pathKeys = ["file_path", "filePath", "path", "file", "filename"];
  for (const key of pathKeys) {
    if (typeof params[key] === "string") {
      return params[key];
    }
  }
  return "file:unknown";
}

function extractBashCommand(params: Record<string, unknown>): string {
  const command = params.command;
  if (typeof command !== "string") {
    return "bash:unknown";
  }

  // Truncate long commands but preserve the essential part
  const maxLen = 100;
  if (command.length <= maxLen) {
    return command;
  }

  // Try to preserve the command name and first argument
  const parts = command.split(/\s+/);
  const cmdName = parts[0] ?? "cmd";
  const firstArg = parts[1] ?? "";

  return `${cmdName} ${firstArg}...`.slice(0, maxLen);
}

function extractMcpResource(params: Record<string, unknown>): string {
  const server =
    typeof params.server === "string"
      ? params.server
      : typeof params.mcp_server === "string"
        ? params.mcp_server
        : "unknown";
  const tool =
    typeof params.tool === "string"
      ? params.tool
      : typeof params.tool_name === "string"
        ? params.tool_name
        : "unknown";
  return `mcp:${server}/${tool}`;
}

/**
 * Check if a resource path should be considered sensitive.
 * Used for redaction in audit logs.
 */
export function isSensitiveResource(resource: string): boolean {
  const lowered = resource.toLowerCase();
  const sensitivePatterns = [
    "/.ssh/",
    "/etc/passwd",
    "/etc/shadow",
    "id_rsa",
    "id_ed25519",
    "credentials",
    ".env",
    "secret",
    "token",
    "password",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    ".pem",
    ".key",
    "aws_",
    "gcp_",
    "azure_",
  ];

  return sensitivePatterns.some((pattern) => lowered.includes(pattern));
}

/**
 * Redact sensitive resources for safe logging.
 */
export function redactResource(resource: string): string {
  if (isSensitiveResource(resource)) {
    return "[REDACTED]";
  }
  return resource;
}
