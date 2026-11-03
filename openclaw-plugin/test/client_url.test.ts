/**
 * The plugin sends x-api-key / x-agent-api-key on every request, so apiUrl
 * must point at the intended host over https (localhost http for dev only).
 */
import { describe, it, expect } from "vitest";
import { VeriSwarmClient } from "../src/client.js";

const make = (apiUrl: string) => new VeriSwarmClient({ apiKey: "vsk_test", apiUrl } as any);

describe("VeriSwarmClient apiUrl validation", () => {
  it.each([
    "https://api.veriswarm.ai@attacker.example",
    "https://user:pass@api.veriswarm.ai",
    "http://localhost@attacker.example",
  ])("rejects userinfo in %s", (apiUrl) => {
    expect(() => make(apiUrl)).toThrow(/must not contain credentials/);
  });

  it.each(["http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"])(
    "accepts local dev http %s",
    (apiUrl) => {
      expect(() => make(apiUrl)).not.toThrow();
    }
  );

  it.each(["http://api.veriswarm.ai", "http://localhost.evil.test", "http://[::2]:8000"])(
    "rejects non-local http %s",
    (apiUrl) => {
      expect(() => make(apiUrl)).toThrow(/https/);
    }
  );
});
