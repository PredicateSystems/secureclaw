# SecureClaw Demo: "Hack vs. Fix"

This demo shows how SecureClaw protects against prompt injection attacks that attempt to exfiltrate sensitive credentials.

## The Scenario

1. **The Setup**: A user asks the AI agent to summarize a document
2. **The Attack**: The document contains a hidden prompt injection that instructs the agent to read `~/.aws/credentials`
3. **Without SecureClaw**: The agent follows the injected instruction and leaks AWS keys
4. **With SecureClaw**: The sensitive file access is blocked before execution

## Running the Demo

### Interactive Script

```bash
./demo/hack-vs-fix.sh
```

This walks through the attack scenario step-by-step with colored output.

### Live Demo with SecureClaw

1. Start the Predicate Authority sidecar (rust-predicate-authorityd):
   ```bash
   # From the rust-predicate-authorityd directory
   cargo run -- --policy ../openclaw/policies/default.json --port 8787
   ```

2. Run SecureClaw:
   ```bash
   secureclaw
   ```

3. Try the prompt injection:
   ```
   > Summarize the document at ./demo/malicious-doc.txt
   ```

4. Observe the blocked access in the SecureClaw logs:
   ```
   [SecureClaw] BLOCKED: fs.read on ~/.aws/credentials - sensitive_resource_blocked
   ```

## Key Files

- `hack-vs-fix.sh` - Interactive demo script
- `malicious-doc.txt` - Document with hidden prompt injection
- `../policies/default.json` - Policy that blocks sensitive resource access

## How It Works

1. **Pre-Authorization**: Every tool call is intercepted by SecureClaw's `before_tool_call` hook
2. **SDK Integration**: Uses `predicate-claw` (GuardedProvider) to communicate with the sidecar
3. **Policy Evaluation**: The Predicate Authority sidecar checks the action against policy rules
4. **Block Decision**: The `deny-aws-credentials` rule matches `*/.aws/*` and returns `allow: false`
5. **Enforcement**: SecureClaw returns `block: true` to OpenClaw, preventing the file read

## Policy Rule (JSON format for rust-predicate-authorityd)

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

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│   OpenClaw      │────▶│   SecureClaw     │────▶│  rust-predicate-authorityd  │
│   (Agent)       │     │   (Plugin)       │     │  (Sidecar @ :8787)      │
│                 │◀────│   predicate-claw │◀────│  Policy Engine          │
└─────────────────┘     └──────────────────┘     └─────────────────────────┘
```

## Recording a Demo Video

For HN/social media, record:

1. Terminal split-screen:
   - Left: SecureClaw running
   - Right: Sidecar logs

2. Show:
   - Normal operation (reading safe files)
   - Prompt injection attempt
   - Block message in real-time
   - Agent continuing without leaked data

Use `asciinema` for terminal recording:
```bash
asciinema rec demo.cast
```