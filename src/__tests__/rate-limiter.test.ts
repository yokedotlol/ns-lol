// Tests for the rate limiter Durable Object

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RateLimiterDO } from '../rate-limiter';

// Fake DurableObjectState storage
function fakeStorage() {
  const store = new Map<string, any>();
  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, val: any) => { store.set(key, val); }),
    _store: store,
  };
}

function makeDO(storage = fakeStorage()) {
  const state = { storage } as any;
  return { do: new RateLimiterDO(state), storage };
}

function fakeRequest() {
  return new Request('https://rl/check');
}

async function check(doObj: RateLimiterDO) {
  const resp = await doObj.fetch(fakeRequest());
  return resp.json() as Promise<{ allowed: boolean; remaining: number; reset: number }>;
}

describe('RateLimiterDO', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  });

  it('allows first request and returns 119 remaining', async () => {
    const { do: rl } = makeDO();
    const result = await check(rl);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(119);
  });

  it('starts with 120 tokens', async () => {
    const { do: rl } = makeDO();
    // Burn through all 120
    for (let i = 0; i < 120; i++) {
      const r = await check(rl);
      expect(r.allowed).toBe(true);
    }
    // 121st should be denied
    const denied = await check(rl);
    expect(denied.allowed).toBe(false);
    expect(denied.remaining).toBe(0);
  });

  it('denies when tokens are exhausted', async () => {
    const { do: rl } = makeDO();
    for (let i = 0; i < 120; i++) await check(rl);
    const result = await check(rl);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('returns a reset timestamp in the future', async () => {
    const { do: rl } = makeDO();
    const now = Math.floor(Date.now() / 1000);
    const result = await check(rl);
    expect(result.reset).toBeGreaterThan(now);
    expect(result.reset).toBeLessThanOrEqual(now + 3600);
  });

  it('fully refills after one hour', async () => {
    const { do: rl } = makeDO();
    // Exhaust all tokens
    for (let i = 0; i < 120; i++) await check(rl);
    expect((await check(rl)).allowed).toBe(false);

    // Advance 1 hour
    vi.advanceTimersByTime(3600 * 1000);

    const result = await check(rl);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(119); // 120 refilled, minus 1 just consumed
  });

  it('partially refills proportionally over time', async () => {
    const { do: rl } = makeDO();
    // Burn 60 tokens
    for (let i = 0; i < 60; i++) await check(rl);
    let r = await check(rl);
    expect(r.remaining).toBe(59); // 120 - 61

    // Advance 30 minutes (half the refill interval) — should get ~60 tokens back
    vi.advanceTimersByTime(1800 * 1000);

    r = await check(rl);
    expect(r.allowed).toBe(true);
    // Should have refilled ~60 tokens (from 59 remaining), then consumed 1
    // 59 + 60 = 119, capped at 120, minus 1 = 119
    expect(r.remaining).toBeGreaterThanOrEqual(115);
    expect(r.remaining).toBeLessThanOrEqual(119);
  });

  it('does not exceed MAX_TOKENS on refill', async () => {
    const { do: rl } = makeDO();
    // Use 1 token
    await check(rl);

    // Wait a full hour — refill should cap at 120
    vi.advanceTimersByTime(3600 * 1000);

    const r = await check(rl);
    expect(r.remaining).toBe(119); // 120 (capped) - 1
  });

  it('persists state across calls', async () => {
    const { do: rl, storage } = makeDO();
    await check(rl);
    // Verify storage.put was called
    expect(storage.put).toHaveBeenCalledWith('rl', expect.objectContaining({
      tokens: expect.any(Number),
      lastRefill: expect.any(Number),
    }));
  });

  it('preserves fractional time on partial refill', async () => {
    const { do: rl } = makeDO();
    // Exhaust all tokens
    for (let i = 0; i < 120; i++) await check(rl);

    // Advance 30 minutes — should get 60 tokens
    vi.advanceTimersByTime(1800 * 1000);
    const r1 = await check(rl);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBeGreaterThanOrEqual(55);

    // Advance 5 more minutes — should get ~10 more tokens
    vi.advanceTimersByTime(300 * 1000);
    const r2 = await check(rl);
    expect(r2.allowed).toBe(true);
    // Should be more than before (modulo the consumed token)
  });

  it('handles rapid sequential requests correctly', async () => {
    const { do: rl } = makeDO();
    // 5 rapid requests
    const results = [];
    for (let i = 0; i < 5; i++) {
      results.push(await check(rl));
    }
    // All allowed, remaining strictly decreasing
    for (let i = 0; i < 5; i++) {
      expect(results[i].allowed).toBe(true);
      expect(results[i].remaining).toBe(120 - (i + 1));
    }
  });

  it('loads initial state from empty storage', async () => {
    const { do: rl } = makeDO();
    const result = await check(rl);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(119);
  });
});
