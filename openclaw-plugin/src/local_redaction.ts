// Local, synchronous redaction for places where an API call is impossible
// (OpenClaw's tool_result_persist hook is synchronous). Pattern-based only:
// it catches common structured identifiers, not names or free-text PII —
// full NER tokenization runs through the VeriSwarm API on inputs.

interface PiiPattern {
  entity: string;
  re: RegExp;
  accept?: (match: string) => boolean;
}

// Luhn checksum over the digits of a candidate payment card number.
export function passesLuhn(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// Order matters: cards and SSNs run before phone numbers so their digits are
// not partially consumed by the broader phone pattern. Replacement markers
// contain no digits, so later patterns never match inside them.
const PII_PATTERNS: PiiPattern[] = [
  { entity: "EMAIL", re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  {
    entity: "CREDIT_CARD",
    re: /(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])/g,
    accept: passesLuhn,
  },
  { entity: "US_SSN", re: /(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)/g },
  {
    entity: "PHONE",
    re: /(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\w)/g,
  },
  {
    entity: "IP_ADDRESS",
    re: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g,
  },
];

export interface LocalRedaction {
  text: string;
  entities: Set<string>;
}

export function redactPiiPatterns(text: string): LocalRedaction {
  const entities = new Set<string>();
  let out = text;
  for (const { entity, re, accept } of PII_PATTERNS) {
    out = out.replace(re, (match) => {
      if (accept && !accept(match)) return match;
      entities.add(entity);
      return `[VS:${entity}:local]`;
    });
  }
  return { text: out, entities };
}

// Synchronous counterpart of the async walker in index.ts: rebuilds `value`
// with every string leaf (and, when `keys` is set, every object key) passed
// through `fn`. Only the current path is tracked for cycle detection, so a
// value referenced twice is still visited twice. Never mutates the input.
export function mapStringLeavesSync(
  value: unknown,
  fn: (text: string) => string,
  options: { keys?: boolean } = {},
  ancestors = new Set<object>()
): { value: unknown; changed: boolean } {
  if (typeof value === "string") {
    const next = fn(value);
    return { value: next, changed: next !== value };
  }
  if (!value || typeof value !== "object" || ancestors.has(value)) {
    return { value, changed: false };
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      let changed = false;
      const next = value.map((item) => {
        const mapped = mapStringLeavesSync(item, fn, options, ancestors);
        changed ||= mapped.changed;
        return mapped.value;
      });
      return changed ? { value: next, changed } : { value, changed };
    }
    let changed = false;
    const next: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const nextKey = options.keys ? fn(key) : key;
      const mapped = mapStringLeavesSync(child, fn, options, ancestors);
      changed ||= mapped.changed || nextKey !== key;
      next[nextKey] = mapped.value;
    }
    return changed ? { value: next, changed } : { value, changed };
  } finally {
    ancestors.delete(value);
  }
}
