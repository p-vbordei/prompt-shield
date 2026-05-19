export type Severity = "low" | "medium" | "high";

export interface Pattern {
  id: string;
  regex: RegExp;
  severity: Severity;
  description: string;
}

export interface Finding {
  patternId: string;
  severity: Severity;
  description: string;
  match: string;
  index: number;
}

export interface ScanResult {
  suspicious: boolean;
  findings: Finding[];
  highestSeverity: Severity | null;
}

const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3 };

/**
 * Default pattern set covering the most common prompt-injection vectors:
 * instruction-override phrases, role hijacks, prompt-disclosure probes, and
 * raw chat-template tokens that leak through user input.
 *
 * All patterns use the `i` flag and the `g` flag is added at scan time.
 */
export const DEFAULT_PATTERNS: readonly Pattern[] = Object.freeze([
  {
    id: "override.ignore-previous",
    severity: "high",
    description: "instruction-override phrase",
    regex: /\bignore\s+(?:(?:the|all|any|every)\s+(?:of\s+the\s+)?)?(?:above|previous|prior|earlier|preceding|all|any)\s+(?:instructions?|prompts?|rules?|messages?|directions?|commands?)\b/i,
  },
  {
    id: "override.disregard",
    severity: "high",
    description: "instruction-override phrase",
    regex: /\bdisregard\s+(?:(?:the|all|any)\s+)?(?:above|previous|prior|earlier|all|any)\s+(?:instructions?|prompts?|rules?|messages?)\b/i,
  },
  {
    id: "override.forget",
    severity: "medium",
    description: "instruction-override phrase",
    regex: /\bforget\s+(?:everything|all\s+(?:previous|prior)|what\s+(?:i|you)\s+(?:said|told))\b/i,
  },
  {
    id: "role.you-are-now",
    severity: "medium",
    description: "role-override attempt",
    regex: /\byou\s+(?:are|will\s+be)\s+now\b/i,
  },
  {
    id: "role.new-role",
    severity: "high",
    description: "role-override attempt",
    regex: /\byour\s+(?:new|next|updated)\s+(?:role|instructions?|task|persona|identity)\s+(?:is|are)\b/i,
  },
  {
    id: "role.pretend",
    severity: "medium",
    description: "role-override attempt",
    regex: /\bpretend\s+(?:you\s+are|to\s+be|that\s+you)\b/i,
  },
  {
    id: "role.act-as",
    severity: "low",
    description: "potential role-override",
    regex: /\bact\s+(?:as|like)\s+(?:a|an|the)\b/i,
  },
  {
    id: "disclosure.reveal-prompt",
    severity: "high",
    description: "prompt-disclosure probe",
    regex: /\b(?:reveal|show|print|display|output|repeat|leak|expose)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)\b/i,
  },
  {
    id: "disclosure.what-were-you-told",
    severity: "medium",
    description: "prompt-disclosure probe",
    regex: /\bwhat\s+(?:are|were|is)\s+(?:your|the)\s+(?:original\s+|initial\s+|system\s+)?(?:instructions?|prompt|rules?)\b/i,
  },
  {
    id: "disclosure.repeat-above",
    severity: "medium",
    description: "prompt-disclosure probe",
    regex: /\brepeat\s+(?:the\s+)?(?:text\s+)?above\b/i,
  },
  {
    id: "refusal.do-not-refuse",
    severity: "medium",
    description: "refusal-bypass phrase",
    regex: /\b(?:do\s+not|don'?t|never)\s+(?:refuse|decline|say\s+no|apologi[sz]e)\b/i,
  },
  {
    id: "refusal.no-restrictions",
    severity: "medium",
    description: "refusal-bypass phrase",
    regex: /\bwithout\s+(?:any\s+)?(?:restrictions?|filters?|limitations?|warnings?|disclaimers?)\b/i,
  },
  {
    id: "jailbreak.named",
    severity: "high",
    description: "named jailbreak preset",
    regex: /\b(?:developer\s+mode|jailbreak|dan\s+mode|do\s+anything\s+now|godmode)\b/i,
  },
  {
    id: "template.llama-inst",
    severity: "medium",
    description: "chat-template token",
    regex: /\[\/?INST\]/,
  },
  {
    id: "template.llama-sys",
    severity: "high",
    description: "chat-template token",
    regex: /<<\/?SYS>>/,
  },
  {
    id: "template.im-start-end",
    severity: "high",
    description: "chat-template token",
    regex: /<\|im_(?:start|end)\|>/,
  },
  {
    id: "template.role-header",
    severity: "medium",
    description: "synthetic role header",
    regex: /^[\s>*-]*###\s*(?:system|user|assistant|instruction)\b/im,
  },
  {
    id: "template.synthetic-turn",
    severity: "medium",
    description: "synthetic role turn",
    regex: /^[\s>*-]*(?:system|assistant)\s*:\s*you\s+(?:must|will|should|are)\b/im,
  },
]);

export interface ScanOptions {
  /** Patterns to use. Defaults to `DEFAULT_PATTERNS`. */
  patterns?: readonly Pattern[];
  /** Skip content inside fenced code blocks (``` ... ```). Default false. */
  ignoreCodeFences?: boolean;
  /** Minimum severity to report. Default "low". */
  minSeverity?: Severity;
}

function stripCodeFences(text: string): string {
  // Replace fence content with spaces of equal length so character offsets are preserved.
  return text.replace(/```[\s\S]*?```/g, (m) => " ".repeat(m.length));
}

/**
 * Scan text for prompt-injection patterns. Never throws; returns a structured result.
 */
export function scan(text: string, opts: ScanOptions = {}): ScanResult {
  if (typeof text !== "string" || !text) {
    return { suspicious: false, findings: [], highestSeverity: null };
  }
  const patterns = opts.patterns ?? DEFAULT_PATTERNS;
  const haystack = opts.ignoreCodeFences ? stripCodeFences(text) : text;
  const minRank = SEVERITY_RANK[opts.minSeverity ?? "low"];
  const findings: Finding[] = [];
  for (const p of patterns) {
    if (SEVERITY_RANK[p.severity] < minRank) continue;
    const flags = p.regex.flags.includes("g") ? p.regex.flags : p.regex.flags + "g";
    const re = new RegExp(p.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(haystack)) !== null) {
      findings.push({
        patternId: p.id,
        severity: p.severity,
        description: p.description,
        match: m[0],
        index: m.index,
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  findings.sort((a, b) => a.index - b.index);
  let highest: Severity | null = null;
  for (const f of findings) {
    if (highest === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[highest]) {
      highest = f.severity;
    }
  }
  return {
    suspicious: findings.length > 0,
    findings,
    highestSeverity: highest,
  };
}

/**
 * Replace each match with `replacement` (default `[REDACTED]`).
 */
export function redact(text: string, opts: ScanOptions & { replacement?: string } = {}): string {
  const replacement = opts.replacement ?? "[REDACTED]";
  const result = scan(text, opts);
  if (!result.findings.length) return text;
  // Apply replacements right-to-left so earlier indices stay valid.
  let out = text;
  for (let i = result.findings.length - 1; i >= 0; i--) {
    const f = result.findings[i]!;
    out = out.slice(0, f.index) + replacement + out.slice(f.index + f.match.length);
  }
  return out;
}
