// ns.lol — Fast, API-first DNS toolkit
// Worker entry point: routing, content negotiation, rate limiting

export { RateLimiterDO } from './rate-limiter';

export interface Env {
  CACHE: KVNamespace;
  RATE_LIMITER: DurableObjectNamespace;
}

import { handleDNSRequest } from './handler';
import { renderSPA } from './spa';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Accept',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // Health check
    if (path === '/health') {
      return json({ status: 'ok', service: 'ns.lol' });
    }

    // Home page / SPA
    if (path === '/' || path === '') {
      if (wantsJSON(request)) {
        return json({
          service: 'ns.lol',
          description: 'Fast, API-first DNS toolkit',
          usage: 'GET /example.com — full DNS report',
          endpoints: {
            lookup: 'GET /:domain',
            record: 'GET /:domain/:type',
            propagation: 'GET /:domain/propagation',
            health_report: 'GET /:domain/health',
            email: 'GET /:domain/email',
            security: 'GET /:domain/security',
            api_docs: 'GET /api/docs',
          },
          family: {
            dns: 'https://ns.lol',
            tls: 'https://certs.lol',
            domains: 'https://yoke.lol',
          },
        });
      }
      return new Response(renderSPA({}, '/', ''), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    // Static assets
    if (path === '/favicon.ico') {
      return new Response(null, { status: 204 });
    }

    // Rate limiting
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rlId = env.RATE_LIMITER.idFromName(clientIP);
    const rlStub = env.RATE_LIMITER.get(rlId);
    const rlResp = await rlStub.fetch('https://rl/check');
    const rl = await rlResp.json() as { allowed: boolean; remaining: number; reset: number };

    const rateLimitHeaders: Record<string, string> = {
      'X-RateLimit-Limit': '120',
      'X-RateLimit-Remaining': String(rl.remaining),
      'X-RateLimit-Reset': String(rl.reset),
    };

    if (!rl.allowed) {
      return json(
        { error: 'Rate limit exceeded', retry_after: rl.reset - Math.floor(Date.now() / 1000) },
        429,
        { ...rateLimitHeaders, 'Retry-After': String(rl.reset - Math.floor(Date.now() / 1000)) }
      );
    }

    // Route DNS requests
    try {
      const result = await handleDNSRequest(url, env);

      if (wantsJSON(request)) {
        return json(result, 200, {
          ...rateLimitHeaders,
          'Cache-Control': result._cache_control || 'public, max-age=60',
        });
      }

      // Browser gets SPA with data embedded
      const domainSlug = url.pathname.split('/').filter(Boolean)[0] || '';
      return new Response(renderSPA(result, url.pathname, domainSlug), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          ...rateLimitHeaders,
        },
      });
    } catch (err: any) {
      const status = err.status || 400;
      const message = err.message || 'Bad request';
      if (wantsJSON(request)) {
        return json({ error: message }, status, rateLimitHeaders);
      }
      return new Response(renderSPA({ error: message }, url.pathname, url.pathname.split('/').filter(Boolean)[0] || ''), {
        status,
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...rateLimitHeaders },
      });
    }
  },
};

function wantsJSON(request: Request): boolean {
  const accept = request.headers.get('Accept') || '';
  const ua = request.headers.get('User-Agent') || '';
  if (accept.includes('application/json') || accept.includes('application/dns-json')) return true;
  if (accept.includes('text/html')) return false;
  // CLI tools get JSON
  if (/^(curl|httpie|wget|HTTPie)/i.test(ua)) return true;
  return false;
}

function json(data: any, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data, null, 2) + '\n', {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      ...extraHeaders,
    },
  });
}
