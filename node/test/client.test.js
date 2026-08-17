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

  // --- A2A Protocol ---

  describe('A2A protocol', () => {
    const client = new VeriSwarmClient({ baseUrl, apiKey });

    it('fetches catalog and agent cards from expected encoded paths', async () => {
      fetch
        .mockResolvedValueOnce(makeFetchResponse({ agents: [] }))
        .mockResolvedValueOnce(makeFetchResponse({ id: 'agt_../one two' }));

      await expect(client.listA2aCatalog()).resolves.toEqual({ agents: [] });
      await expect(client.getA2aAgentCard('agt_../one two')).resolves.toEqual({
        id: 'agt_../one two',
      });

      expect(fetch.mock.calls[0][0]).toBe(`${baseUrl}/v1/a2a/catalog`);
      expect(fetch.mock.calls[1][0]).toBe(
        `${baseUrl}/v1/a2a/agt_..%2Fone%20two/card`
      );
    });

    it('submits tasks with snake_case payload and omits missing signature', async () => {
      fetch.mockResolvedValueOnce(makeFetchResponse({ id: 'a2a_task_1', status: 'submitted' }));
      const messages = [{ role: 'user', content: 'start' }];

      await expect(
        client.submitA2aTask('agt_receiver', {
          requestingAgentId: 'agt_sender',
          messages,
        })
      ).resolves.toEqual({ id: 'a2a_task_1', status: 'submitted' });

      expect(fetch).toHaveBeenCalledWith(
        `${baseUrl}/v1/a2a/agt_receiver/tasks`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            requesting_agent_id: 'agt_sender',
            messages,
          }),
        })
      );
      const callBody = JSON.parse(fetch.mock.calls[0][1].body);
      expect(callBody).not.toHaveProperty('signature');
    });

    it('includes signature when submitting signed tasks', async () => {
      fetch.mockResolvedValueOnce(makeFetchResponse({ id: 'a2a_task_2', status: 'submitted' }));
      const messages = [{ role: 'user', content: 'signed task' }];
      const signature = { key_id: 'key_1', signature: 'sig', algo: 'ed25519' };

      await client.submitA2aTask('agt_receiver', {
        requestingAgentId: 'agt_sender',
        messages,
        signature,
      });

      expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({
        requesting_agent_id: 'agt_sender',
        messages,
        signature,
      });
    });

    it('encodes agent and task ids for get, cancel, and key provisioning paths', async () => {
      fetch
        .mockResolvedValueOnce(makeFetchResponse({ status: 'completed' }))
        .mockResolvedValueOnce(makeFetchResponse({ status: 'canceled' }))
        .mockResolvedValueOnce(makeFetchResponse({ public_key: 'pub' }));

      await client.getA2aTask('agt/receiver', 'a2a task/1');
      await client.cancelA2aTask('agt/receiver', 'a2a task/1');
      await client.provisionA2aKeys('agt/key owner');

      const encodedTaskPath = `${baseUrl}/v1/a2a/agt%2Freceiver/tasks/a2a%20task%2F1`;
      expect(fetch.mock.calls[0][0]).toBe(encodedTaskPath);
      expect(fetch.mock.calls[1][0]).toBe(`${encodedTaskPath}/cancel`);
      expect(fetch.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST' }));
      expect(fetch.mock.calls[2][0]).toBe(`${baseUrl}/v1/a2a/agt%2Fkey%20owner/keys`);
      expect(fetch.mock.calls[2][1]).toEqual(expect.objectContaining({ method: 'POST' }));
    });
  });
});
