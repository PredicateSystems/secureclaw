# SecureClaw Architecture

## How SecureClaw Works

SecureClaw adds a **zero-trust security layer** to OpenClaw by intercepting every tool call and enforcing authorization policies before execution.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AI AGENT (OpenClaw)                            │
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │    Read     │    │    Write    │    │    Bash     │    │  WebFetch   │  │
│  │    Tool     │    │    Tool     │    │    Tool     │    │    Tool     │  │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘  │
│         │                  │                  │                  │         │
│         └──────────────────┴────────┬─────────┴──────────────────┘         │
│                                     │                                       │
│                                     ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     SECURECLAW PLUGIN                                │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │  before_tool_call Hook                                       │    │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │    │   │
│  │  │  │  Extract    │  │  Build      │  │  Call               │  │    │   │
│  │  │  │  Action &   │──│  Guard      │──│  guardOrThrow()     │  │    │   │
│  │  │  │  Resource   │  │  Request    │  │  via SDK            │  │    │   │
│  │  │  └─────────────┘  └─────────────┘  └──────────┬──────────┘  │    │   │
│  │  └───────────────────────────────────────────────┼─────────────┘    │   │
│  └──────────────────────────────────────────────────┼──────────────────┘   │
│                                                     │                       │
└─────────────────────────────────────────────────────┼───────────────────────┘
                                                      │
                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PREDICATE-CLAW SDK                                 │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  GuardedProvider                                                     │   │
│  │  • Formats authorization request                                     │   │
│  │  • Handles fail-open/fail-closed modes                               │   │
│  │  • Emits telemetry events                                            │   │
│  │  • Manages retries and timeouts                                      │   │
│  └──────────────────────────────────────────────────┬──────────────────┘   │
│                                                     │                       │
└─────────────────────────────────────────────────────┼───────────────────────┘
                                                      │
                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PREDICATE AUTHORITY SIDECAR (Rust)                       │
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐ │
│  │  Policy Engine  │    │  Decision       │    │  Audit Log              │ │
│  │  ┌───────────┐  │    │  Evaluator      │    │  ┌───────────────────┐  │ │
│  │  │ ALLOW     │  │    │                 │    │  │ • Decision ID     │  │ │
│  │  │ rules     │  │    │  principal +    │    │  │ • Timestamp       │  │ │
│  │  ├───────────┤  │───▶│  action +       │───▶│  │ • Action/Resource │  │ │
│  │  │ DENY      │  │    │  resource       │    │  │ • Outcome         │  │ │
│  │  │ rules     │  │    │  = ALLOW/DENY   │    │  │ • Mandate ID      │  │ │
│  │  └───────────┘  │    │                 │    │  └───────────────────┘  │ │
│  └─────────────────┘    └─────────────────┘    └─────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Request Flow

```
┌──────────┐     ┌───────────┐     ┌────────────┐     ┌──────────┐     ┌──────────┐
│  Agent   │     │ SecureClaw│     │ predicate- │     │ Sidecar  │     │  Tool    │
│  Request │     │  Plugin   │     │ claw SDK   │     │ (Rust)   │     │ Execution│
└────┬─────┘     └─────┬─────┘     └─────┬──────┘     └────┬─────┘     └────┬─────┘
     │                 │                 │                 │                 │
     │  Tool Call      │                 │                 │                 │
     │  (Read /etc/    │                 │                 │                 │
     │   passwd)       │                 │                 │                 │
     │────────────────▶│                 │                 │                 │
     │                 │                 │                 │                 │
     │                 │  Extract:       │                 │                 │
     │                 │  action=fs.read │                 │                 │
     │                 │  resource=      │                 │                 │
     │                 │  /etc/passwd    │                 │                 │
     │                 │─────────────────▶                 │                 │
     │                 │                 │                 │                 │
     │                 │                 │  POST /authorize│                 │
     │                 │                 │  {principal,    │                 │
     │                 │                 │   action,       │                 │
     │                 │                 │   resource}     │                 │
     │                 │                 │────────────────▶│                 │
     │                 │                 │                 │                 │
     │                 │                 │                 │  Evaluate       │
     │                 │                 │                 │  Policies       │
     │                 │                 │                 │  ────────┐      │
     │                 │                 │                 │          │      │
     │                 │                 │                 │◀─────────┘      │
     │                 │                 │                 │                 │
     │                 │                 │  DENY:          │                 │
     │                 │                 │  sensitive_file │                 │
     │                 │                 │◀────────────────│                 │
     │                 │                 │                 │                 │
     │                 │  ActionDenied   │                 │                 │
     │                 │  Error          │                 │                 │
     │                 │◀────────────────│                 │                 │
     │                 │                 │                 │                 │
     │  BLOCKED:       │                 │                 │                 │
     │  Action blocked │                 │                 │                 │
     │  sensitive_file │                 │                 │                 │
     │◀────────────────│                 │                 │                 │
     │                 │                 │                 │                 │
     │                 │                 │                 │         Tool NOT│
     │                 │                 │                 │         Executed│
     │                 │                 │                 │                 │
```

## OpenClaw vs SecureClaw Security Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OPENCLAW (Original)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────────────┐   │
│  │   Agent     │────────▶│    Tool     │────────▶│   System Resource   │   │
│  │  (LLM)      │ Direct  │  Execution  │ Direct  │   (Files, Network,  │   │
│  │             │ Access  │             │ Access  │    Shell, etc.)     │   │
│  └─────────────┘         └─────────────┘         └─────────────────────┘   │
│                                                                             │
│  ⚠️  NO AUTHORIZATION GATE                                                  │
│  ⚠️  Agent has direct access to all tools                                   │
│  ⚠️  No policy enforcement                                                  │
│  ⚠️  No audit trail                                                         │
│  ⚠️  Relies on LLM's judgment for safety                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

                                    vs

┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURECLAW (Enhanced)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Agent     │───▶│ SecureClaw  │───▶│  Predicate  │───▶│   System    │  │
│  │   (LLM)     │    │   Plugin    │    │  Authority  │    │  Resource   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                            │                  │                             │
│                            │                  │                             │
│                     ┌──────▼──────┐    ┌──────▼──────┐                     │
│                     │  BLOCKED    │    │   ALLOW     │                     │
│                     │  if denied  │    │   with      │                     │
│                     │             │    │   mandate   │                     │
│                     └─────────────┘    └─────────────┘                     │
│                                                                             │
│  ✅ Zero-trust authorization gate                                           │
│  ✅ Policy-based access control                                             │
│  ✅ Immutable audit trail                                                   │
│  ✅ Fail-closed mode for critical environments                              │
│  ✅ LLM cannot bypass security policies                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Features Comparison

| Feature                   | OpenClaw         | SecureClaw                |
| ------------------------- | ---------------- | ------------------------- |
| Tool execution            | Direct           | Policy-gated              |
| Authorization             | None             | Pre-execution check       |
| Policy engine             | None             | Predicate Authority       |
| Audit logging             | Limited          | Full decision trail       |
| Fail mode                 | N/A              | Fail-open or fail-closed  |
| Sensitive file protection | User prompt only | Policy-enforced block     |
| Shell command filtering   | None             | Policy-based allow/deny   |
| Network request control   | None             | URL/domain policies       |
| Multi-tenant support      | None             | Principal-based isolation |

## Policy Example

```json
{
  "policies": [
    {
      "id": "block-sensitive-files",
      "effect": "DENY",
      "actions": ["fs.read", "fs.write"],
      "resources": ["/etc/passwd", "/etc/shadow", "**/.ssh/**", "**/.env", "**/credentials*"],
      "reason": "Sensitive system files are blocked"
    },
    {
      "id": "allow-project-files",
      "effect": "ALLOW",
      "actions": ["fs.read", "fs.write"],
      "resources": ["/home/*/projects/**"],
      "principals": ["agent:claude-code"]
    },
    {
      "id": "block-dangerous-commands",
      "effect": "DENY",
      "actions": ["shell.exec"],
      "resources": ["rm -rf /*", "sudo *", "chmod 777 *", "curl * | bash"],
      "reason": "Dangerous shell commands are blocked"
    }
  ]
}
```

## Component Summary

| Component                       | Role                                            | Technology           |
| ------------------------------- | ----------------------------------------------- | -------------------- |
| **SecureClaw Plugin**           | Intercepts tool calls, extracts action/resource | TypeScript           |
| **predicate-claw SDK**          | Client library for authorization requests       | TypeScript           |
| **Predicate Authority Sidecar** | Policy evaluation, decision engine              | Rust                 |
| **Policy Store**                | Defines allow/deny rules                        | JSON/YAML            |
| **Audit Log**                   | Records all authorization decisions             | Tamper-proof storage |

## Why SecureClaw is More Secure

1. **Defense in Depth**: Even if an LLM is jailbroken or manipulated, the external policy engine enforces security boundaries.

2. **Least Privilege**: Policies can restrict agents to only the resources they need, following the principle of least privilege.

3. **Audit Trail**: Every authorization decision is logged with timestamp, action, resource, and outcome for compliance and forensics.

4. **Fail-Closed Mode**: In high-security environments, if the sidecar is unavailable, all tool calls are blocked rather than allowed.

5. **Separation of Concerns**: Security policy enforcement is decoupled from the AI agent, preventing prompt injection from bypassing security.

6. **Multi-Tenant Isolation**: Different principals (agents, users, tenants) can have different permission sets.

## Getting Started

```bash
# Install SecureClaw
npm install secureclaw

# Start the Predicate Authority sidecar
predicate-authorityd --config policy.json

# Configure SecureClaw plugin
export SECURECLAW_SIDECAR_URL=http://localhost:8787
export SECURECLAW_FAIL_CLOSED=true
```

See the [SecureClaw Plugin documentation](./secureclaw-plugin.md) for detailed configuration options.
