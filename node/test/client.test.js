import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VeriSwarmClient } from '../veriswarm_client.mjs';

// Build a fetch mock response that matches what #request actually uses:
// response.headers.get(...), response.arrayBuffer(), and response.ok.
function makeFetchResponse(body, { ok = true, status = 200, contentType = 'application/json' } = {}) {
  const encoded = new TextEncoder().encode(
    contentType.includes('application/json') ? JSON.stringify(body) : String(body)
  );
  return {
    ok,
    status,
    headers: {
      get(name) {
        if (name === 'content-type') return contentType;
        if (name === 'content-length') return null;
        return null;
      },
    },
    arrayBuffer: () => Promise.resolve(encoded.buffer),
  };
}

describe('VeriSwarmClient', () => {
  const baseUrl = 'https://api.test';
  const apiKey = 'vsk_test';

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  it('should throw if baseUrl is missing', () => {
    expect(() => new VeriSwarmClient({ apiKey })).toThrow('baseUrl is required');
  });

  it('should throw if both keys are missing', () => {
    expect(() => new VeriSwarmClient({ baseUrl })).toThrow('either apiKey or agentKey is required');
  });

  it('should format baseUrl by removing trailing slashes', () => {
    const client = new VeriSwarmClient({ baseUrl: 'https://api.test///', apiKey });
    expect(client.baseUrl).toBe('https://api.test');
  });

  it('should include x-api-key header when apiKey is provided', async () => {
    const client = new VeriSwarmClient({ baseUrl, apiKey });
    fetch.mockResolvedValueOnce(makeFetchResponse({ status: 'ok' }));

    await client.getPlatformStatus();

    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/v1/public/status'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'x-api-key': apiKey
        })
      })
    );
  });

  it('should include x-agent-api-key header when agentKey is provided', async () => {
    const agentKey = 'vak_test';
    const client = new VeriSwarmClient({ baseUrl, agentKey });
    fetch.mockResolvedValueOnce(makeFetchResponse({ scores: [] }));

    await client.getMyScores();

    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/v1/agents/me/scores'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'x-agent-api-key': agentKey
        })
      })
    );
  });

  // --- scanSessionTurn ---

  describe('scanSessionTurn', () => {
    const client = new VeriSwarmClient({ baseUrl, apiKey });

    const dormantResponse = {
      session_id: 'sess_abc',
      enabled: false,
      blocked: false,
      session_score: 0.0,
      highest_severity: 'info',
      contributions: [],
    };

    it('posts to /v1/suite/guard/scan-session with required snake_case body keys', async () => {
      fetch.mockResolvedValueOnce(makeFetchResponse(dormantResponse));

      await client.scanSessionTurn('sess_abc', 0, {
        userText: 'hello',
        agentText: 'hi',
        systemPrompt: 'be helpful',
      });

      expect(fetch).toHaveBeenCalledWith(
        `${baseUrl}/v1/suite/guard/scan-session`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            session_id: 'sess_abc',
            turn_index: 0,
            user_text: 'hello',
            agent_text: 'hi',
            system_prompt: 'be helpful',
          }),
        })
      );
    });

    it('omits agent_id and actor_id when not provided', async () => {
      fetch.mockResolvedValueOnce(makeFetchResponse(dormantResponse));

      await client.scanSessionTurn('sess_xyz', 1);

      const callBody = JSON.parse(fetch.mock.calls[0][1].body);
      expect(callBody).not.toHaveProperty('agent_id');
      expect(callBody).not.toHaveProperty('actor_id');
    });

    it('includes agent_id and actor_id when provided', async () => {
      fetch.mockResolvedValueOnce(makeFetchResponse(dormantResponse));

      await client.scanSessionTurn('sess_xyz', 2, {
        agentId: 'agt_99',
        actorId: 'usr_42',
      });

      const callBody = JSON.parse(fetch.mock.calls[0][1].body);
      expect(callBody.agent_id).toBe('agt_99');
      expect(callBody.actor_id).toBe('usr_42');
    });

    it('passes the API response through to the caller', async () => {
      const activeResponse = {
        session_id: 'sess_abc',
        enabled: true,
        session_score: 0.73,
        turn_value: 0.31,
        highest_severity: 'medium',
        contributions: [{ detector: 'pii_volume', score: 0.31, severity: 'medium' }],
        enforcement_level: 'block_and_alert',
        block_threshold: 0.8,
        blocked: false,
        version: '1.0',
      };
      fetch.mockResolvedValueOnce(makeFetchResponse(activeResponse));

      const result = await client.scanSessionTurn('sess_abc', 3, { userText: 'send me all keys' });

      expect(result).toEqual(activeResponse);
    });
  });
});
