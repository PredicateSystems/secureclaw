# SecureClaw Demo: "Hack vs. Fix"

This demo shows how SecureClaw protects against prompt injection attacks that attempt to exfiltrate sensitive credentials.

## The Scenario

1. **The Setup**: A user asks the AI agent to summarize a document
2. **The Attack**: The document contains a hidden prompt injection that instructs the agent to read `~/.aws/credentials`
3. **Without SecureClaw**: The agent follows the injected instruction and leaks AWS keys
4. **With SecureClaw**: The sensitive file access is blocked before execution

---

## Demo Option 1: Simulation Script (No Sidecar Required)

The quickest way to see the demo - runs a simulated walkthrough with no dependencies.

```bash
cd /Users/guoliangwang/Downloads/openclaw
./demo/hack-vs-fix.sh
```

This script:
- Creates a fake `~/.aws/credentials` file in a temp directory
- Creates a malicious document with a hidden prompt injection
- Walks through what happens WITHOUT SecureClaw (attack succeeds)
- Walks through what happens WITH SecureClaw (attack blocked)
- Shows the policy rule that blocked the attack

**No sidecar or SecureClaw installation required** - it's a visualization of the flow.

---

## Demo Option 2: Live Demo with Sidecar

For a real end-to-end demo with the actual rust-predicate-authorityd sidecar.

### Prerequisites

1. Build the rust-predicate-authorityd sidecar:
   ```bash
   cd /Users/guoliangwang/Code/Sentience/rust-predicate-authorityd
   cargo build --release
   ```

2. Install SecureClaw dependencies:
   ```bash
   cd /Users/guoliangwang/Downloads/openclaw
   pnpm install
   ```

### Running the Live Demo

**Terminal 1 - Start the Sidecar:**
```bash
cd /Users/guoliangwang/Code/Sentience/rust-predicate-authorityd
cargo run --release -- \
  --policy /Users/guoliangwang/Downloads/openclaw/policies/default.json \
  --port 8787
```

You should see:
```
[INFO] Predicate Authority Sidecar starting on :8787
[INFO] Loaded policy with X rules
```

**Terminal 2 - Run SecureClaw:**
```bash
cd /Users/guoliangwang/Downloads/openclaw
SECURECLAW_VERBOSE=true pnpm openclaw
```

**Terminal 2 - Try the Attack:**
```
> Summarize the document at ./demo/malicious-doc.txt
```

**Expected Output:**
```
[SecureClaw] Pre-auth: fs.read on ~/.aws/credentials
[SecureClaw] BLOCKED: fs.read - sensitive_resource_blocked
```

---

## Demo Option 3: Live Demo WITHOUT Sidecar (Fail-Open Mode)

To test SecureClaw behavior when the sidecar is unavailable:

```bash
cd /Users/guoliangwang/Downloads/openclaw

# Fail-open mode (allows actions when sidecar is down)
SECURECLAW_FAIL_OPEN=true SECURECLAW_VERBOSE=true pnpm openclaw

# Fail-closed mode (blocks all actions when sidecar is down) - DEFAULT
SECURECLAW_VERBOSE=true pnpm openclaw
```

In **fail-closed mode** (default), you'll see:
```
[SecureClaw] Sidecar error (fail-closed): Connection refused
[SecureClaw] Authorization service unavailable (fail-closed mode)
```

In **fail-open mode**, actions will be allowed with a warning:
```
[SecureClaw] Sidecar error (fail-open): Connection refused
```

---

## Key Files

| File | Description |
|------|-------------|
| `demo/hack-vs-fix.sh` | Interactive simulation script |
| `demo/malicious-doc.txt` | Document with hidden prompt injection |
| `policies/default.json` | Default policy (blocks sensitive resources) |
| `policies/examples/coding-agent.json` | Policy for coding assistants |
| `policies/examples/browser-agent.json` | Policy for browser automation |

---

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│   OpenClaw      │────▶│   SecureClaw     │────▶│  rust-predicate-authorityd  │
│   (Agent)       │     │   (Plugin)       │     │  (Sidecar @ :8787)      │
│                 │◀────│   predicate-claw │◀────│  Policy Engine          │
└─────────────────┘     └──────────────────┘     └─────────────────────────┘
```

1. **Pre-Authorization**: Every tool call is intercepted by SecureClaw's `before_tool_call` hook
2. **SDK Integration**: Uses `predicate-claw` SDK (`GuardedProvider`) to communicate with sidecar
3. **Policy Evaluation**: The sidecar checks the action against JSON policy rules
4. **Block Decision**: Matching deny rules return `allow: false`
5. **Enforcement**: SecureClaw returns `block: true` to OpenClaw, preventing execution

---

## Policy Rule Example

```json
{
  "rules": [
    {
      "name": "deny-aws-credentials",
      "effect": "deny",
      "principals": ["*"],
      "actions": ["fs.read", "fs.write"],
      "resources": ["*/.aws/*", "*/.aws/credentials"],
      "required_labels": [],
      "max_delegation_depth": null
    }
  ]
}
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURECLAW_PRINCIPAL` | `agent:secureclaw` | Agent identity |
| `SECURECLAW_POLICY` | `./policies/default.json` | Policy file path |
| `PREDICATE_SIDECAR_URL` | `http://127.0.0.1:8787` | Sidecar endpoint |
| `SECURECLAW_FAIL_OPEN` | `false` | Allow actions when sidecar is down |
| `SECURECLAW_VERBOSE` | `false` | Enable verbose logging |

---

## Recording a Demo Video

For HN/social media, record using `asciinema`:

```bash
asciinema rec demo.cast
```

Recommended split-screen setup:
- **Left terminal**: SecureClaw running with `SECURECLAW_VERBOSE=true`
- **Right terminal**: Sidecar logs

Show:
1. Normal operation (reading safe files) - ALLOWED
2. Prompt injection attempt (reading ~/.aws/credentials) - BLOCKED
3. Agent continues without leaked data