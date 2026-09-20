import { describe, it, expect } from "vitest";
import { VeriSwarmClient } from "../src/client.js";

describe("VeriSwarmClient URL validation", () => {
  it("rejects apiUrl values with username or password", () => {
    expect(
      () =>
        new VeriSwarmClient({
          apiUrl: "https://api.veriswarm.ai@attacker.example",
          apiKey: "vsk_test",
          agentId: "agt_test",
        })
    ).toThrow("apiUrl must not include username or password");
  });
});
