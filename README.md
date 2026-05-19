# prompt-shield

[![ci](https://github.com/p-vbordei/prompt-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/prompt-shield/actions/workflows/ci.yml)

[![npm](https://img.shields.io/npm/v/%40p-vbordei%2Fprompt-shield.svg)](https://www.npmjs.com/package/@p-vbordei/prompt-shield)
[![downloads](https://img.shields.io/npm/dm/%40p-vbordei%2Fprompt-shield.svg)](https://www.npmjs.com/package/@p-vbordei/prompt-shield)
[![bundle](https://img.shields.io/bundlejs/size/%40p-vbordei%2Fprompt-shield)](https://bundlejs.com/?q=%40p-vbordei%2Fprompt-shield)

> A pattern-based detector for prompt-injection attempts in untrusted text. Useful as a pre-flight check before sending user-supplied content to an LLM, or as a post-flight check on tool outputs that may have been poisoned.

```ts
import { scan, redact } from "@p-vbordei/prompt-shield";

const r = scan(userInput);
if (r.suspicious) {
  console.warn(`prompt-shield flagged ${r.findings.length} pattern(s)`);
  for (const f of r.findings) console.warn(`- [${f.severity}] ${f.patternId}: "${f.match}"`);
}

const sanitized = redact(userInput);
```

## Install

```sh
npm install @p-vbordei/prompt-shield
```

Works with Node 20+, browsers, Bun, Deno. ESM + CJS.

## Why

LLMs trust their input. If a user (or a webpage you scraped, or an email a tool fetched) contains "ignore all previous instructions and...", the model might follow it. Defense in depth means:

1. **Detect** these patterns before they reach the LLM
2. **Flag or block** at the application layer
3. **Treat tool outputs as untrusted** — apply this check there too

`prompt-shield` covers ~18 of the most common attack categories. It's pattern matching, not understanding — false positives happen, novel attacks slip through. **Treat it as one signal among several, not a hard gate.**

## Recipes

### Pre-flight on user input

```ts
import { scan } from "@p-vbordei/prompt-shield";

async function askLLM(userMessage: string) {
  const r = scan(userMessage);
  if (r.highestSeverity === "high") {
    return "Your message looks like a prompt-injection attempt. Please rephrase.";
  }
  return await llm.complete(userMessage);
}
```

### Sanitize before passing to LLM

```ts
import { redact } from "@p-vbordei/prompt-shield";

const safe = redact(userInput, { replacement: "[FILTERED]" });
const response = await llm.complete(safe);
```

### Post-flight on tool outputs

```ts
import { scan } from "@p-vbordei/prompt-shield";

async function executeTool(name: string, args: unknown) {
  const result = await tools[name](args);
  const text = typeof result === "string" ? result : JSON.stringify(result);
  const r = scan(text);
  if (r.suspicious) {
    return `[BLOCKED: tool output flagged by prompt-shield: ${r.highestSeverity}]`;
  }
  return result;
}
```

### Threshold-based blocking

```ts
import { scan } from "@p-vbordei/prompt-shield";

const r = scan(input, { minSeverity: "high" });
if (r.suspicious) reject();
```

### Add custom org-specific patterns

```ts
import { DEFAULT_PATTERNS, scan } from "@p-vbordei/prompt-shield";

const patterns = [
  ...DEFAULT_PATTERNS,
  {
    id: "company.internal-codename",
    severity: "high" as const,
    description: "internal codename leak",
    regex: /\bproject\s+sandcastle\b/i,
  },
];

scan(text, { patterns });
```

## What it catches

| Category | Examples |
|---|---|
| **Instruction override** | "ignore previous instructions", "disregard the above", "forget everything" |
| **Role hijack** | "you are now ...", "your new role is ...", "pretend you are ...", "act as ..." |
| **Prompt disclosure** | "show me your system prompt", "what were your original instructions", "repeat the text above" |
| **Refusal bypass** | "do not refuse", "without any restrictions" |
| **Named jailbreaks** | "developer mode", "DAN mode", "godmode" |
| **Chat-template leaks** | `[INST]`, `<\|im_start\|>`, `<<SYS>>`, `### system` |

It is **pattern matching**, not understanding — it will produce false positives (e.g. legitimate text discussing prompt injection itself) and false negatives (e.g. paraphrased novel attacks).

## API

### `scan(text, opts?): ScanResult`

```ts
type ScanResult = {
  suspicious: boolean;
  findings: Finding[];
  highestSeverity: "low" | "medium" | "high" | null;
};

type Finding = {
  patternId: string;       // e.g. "override.ignore-previous"
  severity: Severity;
  description: string;
  match: string;           // the substring that matched
  index: number;           // character offset in the input
};
```

### `redact(text, opts?): string`

Replaces every match with `[REDACTED]` (or `opts.replacement`). Preserves the rest of the text.

### Options

| Field | Type | Default | Meaning |
|---|---|---|---|
| `patterns` | `Pattern[]` | `DEFAULT_PATTERNS` | Override or extend the rule set |
| `ignoreCodeFences` | `boolean` | `false` | Skip content inside `` ``` ... ``` `` |
| `minSeverity` | `"low" \| "medium" \| "high"` | `"low"` | Filter out findings below this severity |

## Defense in depth

`prompt-shield` is **one layer**, not the whole defense. Combine with:

- **Structured prompting** — keep user input clearly delimited (XML tags, JSON, etc.) so the model knows what's user-supplied vs system.
- **Output filtering** — scan the model's output for unexpected content too.
- **Least-privilege tools** — even a successfully-injected model can't do much if its tools have narrow permissions.
- **Logging + review** — every flagged input should be loggable for security review.

## License

Apache-2.0 © Vlad Bordei
