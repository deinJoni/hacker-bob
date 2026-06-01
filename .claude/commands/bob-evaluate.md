---
description: Run or resume a Hacker Bob bug bounty evaluate.
allowed-tools:
  - Skill
argument-hint: "[target-url | resume <domain> [force-merge]] [--no-auth] [--normal|--paranoid|--yolo] [--deep] [--egress <profile>] [--block-internal-hosts|--allow-internal-hosts]"
---
Run or resume a Hacker Bob bug bounty evaluate.

Invoke the installed `bob-evaluate-runner` skill with the operator's arguments:

```text
$ARGUMENTS
```

Treat `$ARGUMENTS` as the `bob-evaluate-runner` skill's exact input and follow that skill's guardrails.
