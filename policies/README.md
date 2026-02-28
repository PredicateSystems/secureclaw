# SecureClaw Policy Templates

This directory contains policy templates for the SecureClaw authorization harness. Policies define what actions your AI agent is allowed to perform, enforced by the `predicate-authorityd` Rust sidecar.

> **Supported Formats:** The Python SDK (`predicate_authority`) supports both **YAML** and **JSON**. The file extension (`.yaml`, `.yml`, or `.json`) determines the parser used. YAML is recommended for human editing.

## Quick Start

```bash
# Start SecureClaw with a policy
secureclaw gateway --port 18789 --policy-file policies/strict.json

# Or set via environment variable
export SECURECLAW_POLICY_FILE=policies/strict-web-only.json
secureclaw gateway --port 18789
```

## Available Templates

| Policy                                           | Use Case                         | Filesystem       | Shell              | Network              |
| ------------------------------------------------ | -------------------------------- | ---------------- | ------------------ | -------------------- |
| **[strict.json](strict.json)**                   | Production default               | Workspace only   | Safe commands      | HTTPS only           |
| **[strict-web-only.json](strict-web-only.json)** | Browser automation, web scraping | BLOCKED          | BLOCKED            | HTTPS allowlist only |
| **[read-only-local.json](read-only-local.json)** | Code review, documentation       | READ only        | Safe commands only | HTTPS GET only       |
| **[audit-only.json](audit-only.json)**           | Agent profiling, development     | ALLOWED (logged) | ALLOWED (logged)   | ALLOWED (logged)     |

---

## Policy Templates

### 1. Strict (`strict.json`) - Recommended Default

**Purpose:** Balanced production policy with workspace isolation.

**Allows:**

- Filesystem read everywhere, write only in workspace directories
- Safe shell commands (ls, cat, grep, git, npm, etc.)
- HTTPS requests to any domain
- Full browser interactions

**Blocks:**

- Access to sensitive files (`.env`, `.ssh/`, credentials)
- Writes outside workspace directories
- Dangerous shell commands (`rm -rf`, `sudo`, etc.)
- Non-HTTPS protocols

**Best for:** General-purpose secure agent deployment.

```bash
secureclaw gateway --policy-file policies/strict.json
```

### 2. Strict Web-Only (`strict-web-only.json`)

**Purpose:** Lock down agents to browser-only operations with no local access.

**Allows:**

- Browser navigation to allowlisted HTTPS domains
- Browser interactions (click, type, read) with snapshot verification
- Screenshot and DOM extraction

**Blocks:**

- ALL filesystem operations (`fs.*`)
- ALL shell/system execution (`bash`, `exec`, `os.*`)
- Non-HTTPS protocols (`http://`, `file://`, `data:`)
- Sensitive form field interactions (password, credit card)

**Best for:** Web scraping bots, form-filling agents, UI testing automation.

```bash
secureclaw gateway --policy-file policies/strict-web-only.json
```

### 3. Read-Only Local (`read-only-local.json`)

**Purpose:** Allow context gathering without modification capabilities.

**Allows:**

- Filesystem read operations (`fs.read`, `fs.list`, `fs.stat`)
- Safe shell commands (`cat`, `grep`, `find`, `git status`, `git log`)
- HTTPS GET requests
- Browser read operations (screenshot, extract)

**Blocks:**

- Filesystem writes (`fs.write`, `fs.create`, `fs.delete`)
- Dangerous shell commands (`rm`, `sudo`, `chmod`, `git push`)
- HTTP mutation methods (POST, PUT, PATCH, DELETE)
- Access to credential files (`.env`, `.ssh/`, `.aws/`)

**Best for:** Code review agents, documentation generators, codebase analysis.

```bash
secureclaw gateway --policy-file policies/read-only-local.json
```

### 4. Audit Only (`audit-only.json`)

**Purpose:** Profile agent behavior before writing restrictive policies.

**Allows:**

- ALL actions (requires `audit_enabled` label to confirm logging is active)

**Blocks:**

- Only catastrophic commands (`rm -rf /`, fork bombs)

**Best for:** Initial agent onboarding, understanding action patterns, development.

```bash
# Start in audit mode
secureclaw gateway --policy-file policies/audit-only.json

# Review authorization logs
tail -f /var/log/secureclaw/audit.jsonl
```

> ⚠️ **WARNING:** Audit-only provides NO security protection. Use only in development/staging or with fully trusted agents.

---

## Policy Schema (JSON)

Each policy file contains a `rules` array evaluated in order. Rules are matched using glob patterns.

```json
{
  "version": "1.0",
  "rules": [
    {
      "name": "rule-identifier",
      "effect": "allow",
      "principals": ["agent:*", "agent:my-browser-bot"],
      "actions": ["fs.read", "browser.*"],
      "resources": ["https://example.com*", "/home/*/projects/*"],
      "required_labels": ["mfa_verified", "snapshot_captured"]
    }
  ]
}
```

### Required Fields

| Field        | Type                  | Description                                |
| ------------ | --------------------- | ------------------------------------------ |
| `name`       | string                | Unique identifier for logging/debugging    |
| `effect`     | `"allow"` or `"deny"` | Action to take when rule matches           |
| `principals` | string[]              | WHO can perform the action (glob patterns) |
| `actions`    | string[]              | WHAT actions are covered (glob patterns)   |
| `resources`  | string[]              | ON WHAT resources (glob patterns)          |

### Optional Fields

| Field                  | Type     | Description                                              |
| ---------------------- | -------- | -------------------------------------------------------- |
| `required_labels`      | string[] | Verification labels that must be present (default: `[]`) |
| `max_delegation_depth` | number   | Max delegation chain depth                               |

## Evaluation Order

1. **DENY rules are evaluated first** - Any matching DENY immediately blocks the action
2. **ALLOW rules are checked** - Must match AND have all required_labels present
3. **Default DENY** - If no rules match, action is blocked (fail-closed)

## Pattern Matching

Patterns use glob-style matching:

| Pattern                  | Matches                                  |
| ------------------------ | ---------------------------------------- |
| `*`                      | Anything                                 |
| `agent:*`                | Any agent identity                       |
| `fs.*`                   | `fs.read`, `fs.write`, `fs.delete`, etc. |
| `https://*.example.com*` | Any subdomain of example.com             |
| `/home/*/projects/**`    | Any file under any user's projects dir   |
| `element:button[*`       | Button elements with any attributes      |

## Creating Custom Policies

1. **Start with audit-only** to understand your agent's behavior:

   ```bash
   secureclaw gateway --policy-file policies/audit-only.json
   # Run your agent workflows
   # Review logs to see what actions are requested
   ```

2. **Copy the closest template** as a starting point:

   ```bash
   cp policies/read-only-local.json policies/my-agent.json
   ```

3. **Customize the rules** based on observed behavior:
   - Add domains to navigation allowlists
   - Allow specific shell commands your agent needs
   - Block sensitive file paths

4. **Test with your agent** before deploying:
   ```bash
   secureclaw gateway --policy-file policies/my-agent.json --verbose
   ```

## Environment Variables

| Variable                 | Description                                                  |
| ------------------------ | ------------------------------------------------------------ |
| `SECURECLAW_POLICY_FILE` | Path to policy JSON file                                     |
| `SECURECLAW_FAIL_CLOSED` | Set `true` to block if sidecar unavailable (default: `true`) |
| `SECURECLAW_SIDECAR_URL` | Sidecar endpoint (default: `http://127.0.0.1:8787`)          |

## Hot Reload

Policies can be reloaded without restarting the gateway:

```bash
# Use the API endpoint
curl -X POST http://127.0.0.1:8787/policy/reload \
  -H "Content-Type: application/json" \
  -d @policies/strict.json
```

## Additional Resources

- [Security Architecture](../docs/secureclaw-architecture.md) - How the authorization harness works
- [Predicate Authority Docs](https://docs.predicatesystems.com) - Full sidecar documentation
- [Policy Examples](examples/) - More specialized policy templates
