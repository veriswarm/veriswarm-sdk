import { describe, it, expect } from "vitest";
import { mapStringLeavesSync, passesLuhn, redactPiiPatterns } from "../src/local_redaction.js";

describe("redactPiiPatterns", () => {
  it.each([
    ["email", "reach me at alice.smith+x@example.co.uk now", "EMAIL"],
    ["US SSN", "ssn 123-45-6789.", "US_SSN"],
    ["US phone", "call (415) 555-0132 today", "PHONE"],
    ["E.164 phone", "call +1 415-555-0132", "PHONE"],
    ["card (Luhn-valid)", "card 4111 1111 1111 1111 exp", "CREDIT_CARD"],
    ["IPv4", "host 10.0.12.254 is up", "IP_ADDRESS"],
  ])("redacts %s", (_label, input, entity) => {
    const out = redactPiiPatterns(input);
    expect(out.entities).toEqual(new Set([entity]));
    expect(out.text).toContain(`[VS:${entity}:local]`);
  });

  it("leaves Luhn-invalid digit runs, invalid SSNs and non-IPs alone", () => {
    const input = "order 4111 1111 1111 1112, ssn 000-12-3456, version 999.1.1.1";
    expect(redactPiiPatterns(input)).toEqual({ text: input, entities: new Set() });
  });

  it("redacts several entities in one string", () => {
    const out = redactPiiPatterns("alice@example.com 123-45-6789 192.168.1.1");
    expect(out.text).toBe("[VS:EMAIL:local] [VS:US_SSN:local] [VS:IP_ADDRESS:local]");
  });
});

describe("passesLuhn", () => {
  it("accepts valid and rejects invalid numbers", () => {
    expect(passesLuhn("4242424242424242")).toBe(true);
    expect(passesLuhn("4242424242424241")).toBe(false);
    expect(passesLuhn("42424")).toBe(false);
  });
});

describe("mapStringLeavesSync", () => {
  const upper = (s: string) => s.toUpperCase();

  it("visits shared references on every path and maps keys when asked", () => {
    const shared = { k: "v" };
    const out = mapStringLeavesSync({ a: shared, b: shared, list: ["x"] }, upper, { keys: true });
    expect(out.value).toEqual({ A: { K: "V" }, B: { K: "V" }, LIST: ["X"] });
    expect(shared).toEqual({ k: "v" });
  });

  it("returns the same object when nothing changes and survives cycles", () => {
    const cyclic: Record<string, unknown> = { n: 1 };
    cyclic.self = cyclic;
    const out = mapStringLeavesSync(cyclic, (s) => s);
    expect(out.changed).toBe(false);
    expect(out.value).toBe(cyclic);
  });
});

describe("mapStringLeavesSync — key safety", () => {
  it("keeps an own __proto__ key as data, not a prototype", () => {
    const input = JSON.parse('{"__proto__":{"x":"a"},"b":"a"}');
    const out = mapStringLeavesSync(input, (s) => s.toUpperCase()).value as any;

    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(Object.getOwnPropertyDescriptor(out, "__proto__")?.value).toEqual({ x: "A" });
    expect(out.b).toBe("A");
  });

  it("suffixes a rewritten key that collides instead of overwriting", () => {
    const redact = (s: string) => (s.startsWith("secret") ? "[R]" : s);
    const out = mapStringLeavesSync({ secretA: 1, "[R]": 2, secretB: 3 }, redact, { keys: true }).value;

    expect(out).toEqual({ "[R]": 2, "[R]#2": 1, "[R]#3": 3 });
  });
});
