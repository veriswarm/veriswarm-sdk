import { describe, it, expect, vi, beforeEach } from "vitest";
import { VeriSwarmClient } from "../veriswarm_client.mjs";

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function call(i = 0) {
  const [url, init] = fetch.mock.calls[i];
  return { url: new URL(url), init, body: init.body === undefined ? undefined : JSON.parse(init.body) };
}

let client;
beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({})));
  client = new VeriSwarmClient({ baseUrl: "https://api.test", apiKey: "vsk_x", accountToken: "acct" });
});

describe("reputationLookup", () => {
  it("sends agent_ref (the server's required query param)", async () => {
    await client.reputationLookup("my-agent@example.com");
    const { url } = call();
    expect(url.pathname).toBe("/v1/public/reputation/lookup");
    expect(url.searchParams.get("agent_ref")).toBe("my-agent@example.com");
    expect(url.searchParams.has("slug")).toBe(false);
  });

  it("rejects an empty reference", async () => {
    await expect(client.reputationLookup("")).rejects.toThrow(/agentRef/);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("updateGuardPolicy", () => {
  it("sends is_active as a query param with no body", async () => {
    await client.updateGuardPolicy(7, { isActive: false });
    const { url, init } = call();
    expect(init.method).toBe("PATCH");
    expect(url.pathname).toBe("/v1/suite/guard/policies/7");
    expect(url.searchParams.get("is_active")).toBe("false");
    expect(init.body).toBeUndefined();
  });

  it("accepts the server field name is_active", async () => {
    await client.updateGuardPolicy(7, { is_active: true });
    expect(call().url.searchParams.get("is_active")).toBe("true");
  });

  it("rejects a non-boolean is_active instead of sending an invalid request", async () => {
    await expect(client.updateGuardPolicy(7, { enabled: false })).rejects.toThrow(/isActive/);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("updateGuardFinding", () => {
  it("sends new_status as a query param with no body", async () => {
    await client.updateGuardFinding(3, { newStatus: "resolved" });
    const { url, init } = call();
    expect(init.method).toBe("PATCH");
    expect(url.pathname).toBe("/v1/suite/guard/findings/3");
    expect(url.searchParams.get("new_status")).toBe("resolved");
    expect(init.body).toBeUndefined();
  });

  it("accepts new_status and the documented status alias", async () => {
    await client.updateGuardFinding(3, { new_status: "mitigated" });
    await client.updateGuardFinding(3, { status: "false_positive" });
    expect(call(0).url.searchParams.get("new_status")).toBe("mitigated");
    expect(call(1).url.searchParams.get("new_status")).toBe("false_positive");
  });

  it("rejects a missing status", async () => {
    await expect(client.updateGuardFinding(3, {})).rejects.toThrow(/newStatus/);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("setIpAllowlist", () => {
  it("sends the server's ip_allowlist string built from a CIDR list", async () => {
    await client.setIpAllowlist({ cidrs: ["10.0.0.0/8", " 192.168.1.0/24 "] });
    expect(call().body).toEqual({ ip_allowlist: "10.0.0.0/8,192.168.1.0/24" });
  });

  it("accepts a comma-separated string", async () => {
    await client.setIpAllowlist({ cidrs: "10.0.0.0/8, 172.16.0.0/12" });
    expect(call().body).toEqual({ ip_allowlist: "10.0.0.0/8,172.16.0.0/12" });
  });

  it.each([[[]], [""], [" , "], [undefined]])(
    "refuses an empty CIDR list while enabled (the server would treat it as disable): %j",
    async (cidrs) => {
      await expect(client.setIpAllowlist({ cidrs })).rejects.toThrow(/enabled: false/);
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("disables only when explicitly asked", async () => {
    await client.setIpAllowlist({ cidrs: ["10.0.0.0/8"], enabled: false });
    expect(call().body).toEqual({ ip_allowlist: "" });
  });

  it("never sends the old cidrs/enabled shape", async () => {
    await client.setIpAllowlist({ cidrs: ["10.0.0.0/8"] });
    expect(Object.keys(call().body)).toEqual(["ip_allowlist"]);
  });
});
