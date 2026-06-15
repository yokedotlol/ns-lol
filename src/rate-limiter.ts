// Rate limiter — Durable Object, same pattern as certs.lol
// 120 requests per hour per IP

interface RateLimitState {
  tokens: number;
  lastRefill: number;
}

const MAX_TOKENS = 120;
const REFILL_INTERVAL = 3600; // 1 hour in seconds

export class RateLimiterDO {
  private state: DurableObjectState;
  private data: RateLimitState | null = null;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  private async load(): Promise<RateLimitState> {
    if (this.data) return this.data;
    this.data = (await this.state.storage.get<RateLimitState>('rl')) || {
      tokens: MAX_TOKENS,
      lastRefill: Math.floor(Date.now() / 1000),
    };
    return this.data;
  }

  async fetch(_request: Request): Promise<Response> {
    const rl = await this.load();
    const now = Math.floor(Date.now() / 1000);

    // Refill tokens based on time elapsed
    const elapsed = now - rl.lastRefill;
    if (elapsed >= REFILL_INTERVAL) {
      rl.tokens = MAX_TOKENS;
      rl.lastRefill = now;
    } else {
      const refill = Math.floor((elapsed / REFILL_INTERVAL) * MAX_TOKENS);
      rl.tokens = Math.min(MAX_TOKENS, rl.tokens + refill);
      if (refill > 0) rl.lastRefill = now;
    }

    const allowed = rl.tokens > 0;
    if (allowed) rl.tokens--;

    await this.state.storage.put('rl', rl);

    const reset = rl.lastRefill + REFILL_INTERVAL;
    return new Response(JSON.stringify({
      allowed,
      remaining: Math.max(0, rl.tokens),
      reset,
    }));
  }
}
