# prompt-shield

[![ci](https://github.com/p-vbordei/prompt-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/prompt-shield/actions/workflows/ci.yml)

[![npm](https://img.shields.io/npm/v/%40p-vbordei%2Fprompt-shield.svg)](https://www.npmjs.com/package/@p-vbordei/prompt-shield)
[![downloads](https://img.shields.io/npm/dm/%40p-vbordei%2Fprompt-shield.svg)](https://www.npmjs.com/package/@p-vbordei/prompt-shield)
[![bundle](https://img.shields.io/bundlejs/size/%40p-vbordei%2Fprompt-shield)](https://bundlejs.com/?q=%40p-vbordei%2Fprompt-shield)

A pattern-based detector for prompt-injection attempts in untrusted text. Useful as a pre-flight check before sending user-supplied content to an LLM, or as a post-flight check on tool outputs that may have been poisoned.

```ts
import { scan, redact } from "@p-vbordei/prompt-shield";

const r = scan(userInput);
if (r.suspicious) {
  console.warn(`prompt-shield flagged ${r.findings.length} pattern(s)`);
  for (const f of r.findings) console.warn(`- [${f.severity}] ${f.patternId}: "${f.match}"`);
}

// Or strip the suspicious bits in place:
const sanitized = redact(userInput);
```

## Install

```sh
npm install @p-vbordei/prompt-shield
```

## What it catches

The default rule set covers the most common categories. Each finding has a `severity` of `low`, `medium`, or `high`.

| Category | Examples |
|---|---|
| **Instruction override** | "ignore previous instructions", "disregard the above", "forget everything" |
| **Role hijack** | "you are now ...", "your new role is ...", "pretend you are ...", "act as ..." |
| **Prompt disclosure** | "show me your system prompt", "what were your original instructions", "repeat the text above" |
| **Refusal bypass** | "do not refuse", "without any restrictions" |
| **Named jailbreaks** | "developer mode", "DAN mode", "godmode" |
| **Chat-template leaks** | `[INST]`, `<\|im_start\|>`, `<<SYS>>`, `### system` |

It is **pattern matching**, not understanding — it will produce false positives (e.g. legitimate text discussing the topic of prompt injection itself) and false negatives (e.g. paraphrased novel attacks). Treat it as one signal among several, not a hard gate.

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
| `ignoreCodeFences` | `boolean` | `false` | Skip content inside `` ``` ... ``` `` (useful when scanning model output that quotes code) |
| `minSeverity` | `"low" \| "medium" \| "high"` | `"low"` | Filter out findings below this severity |

### Adding your own rules

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

## License

Apache-2.0 © Vlad Bordei
