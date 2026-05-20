import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VeriSwarmClient } from '../veriswarm_client.mjs';

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
    
    fetch.mockResolvedValueOnce({
      ok: true,
      headers: new Map([['content-type', 'application/json']]),
      json: () => Promise.resolve({ status: 'ok' }),
    });

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
    
    fetch.mockResolvedValueOnce({
      ok: true,
      headers: new Map([['content-type', 'application/json']]),
      json: () => Promise.resolve({ status: 'ok' }),
    });

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
});
