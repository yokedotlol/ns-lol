// ns.lol — Fast, API-first DNS toolkit
// Worker entry point: routing, content negotiation, rate limiting

export { RateLimiterDO } from './rate-limiter';

export interface Env {
  CACHE: KVNamespace;
  RATE_LIMITER: DurableObjectNamespace;
  PROBE_URL?: string;  // e.g. https://ns-lol-probe.fly.dev
  PROBE_KEY?: string;  // auth secret for the Fly probe
}

import { handleDNSRequest, formatDig, privacyPage, termsPage, docsPage, sitemapXml } from './handler';
import { renderSPA } from './spa';

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https://yoke.lol; frame-ancestors 'none'; base-uri 'self'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
};

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
          ...SECURITY_HEADERS,
        },
      });
    }

    // Health check
    if (path === '/health') {
      return json({ status: 'ok', service: 'ns.lol' });
    }

    // robots.txt
    if (path === '/robots.txt') {
      return plainText('User-agent: *\nAllow: /\nSitemap: https://ns.lol/sitemap.xml\n');
    }

    // sitemap.xml
    if (path === '/sitemap.xml') {
      return new Response(sitemapXml(), {
        headers: {
          'Content-Type': 'application/xml; charset=utf-8',
          ...SECURITY_HEADERS,
        },
      });
    }

    // MTA-STS policy (mta-sts.ns.lol)
    if (url.hostname === 'mta-sts.ns.lol' && path === '/.well-known/mta-sts.txt') {
      return plainText(
        'version: STSv1\n' +
        'mode: enforce\n' +
        'mx: route1.mx.cloudflare.net\n' +
        'mx: route2.mx.cloudflare.net\n' +
        'mx: route3.mx.cloudflare.net\n' +
        'max_age: 86400\n'
      );
    }

    // security.txt
    if (path === '/.well-known/security.txt') {
      return plainText(
        'Contact: mailto:hello@ns.lol\n' +
        'Preferred-Languages: en\n' +
        'Canonical: https://ns.lol/.well-known/security.txt\n' +
        'Expires: 2027-06-01T00:00:00.000Z\n'
      );
    }

    // Privacy page
    if (path === '/privacy') {
      return htmlResponse(privacyPage());
    }

    // Terms page
    if (path === '/terms') {
      return htmlResponse(termsPage());
    }

    // API docs (HTML)
    if (path === '/docs') {
      return htmlResponse(docsPage());
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
            numeric: 'GET /:domain/:number (custom QTYPE)',
            any: 'GET /:domain/any',
            trace: 'GET /:domain/trace',
            propagation: 'GET /:domain/propagation',
            health_report: 'GET /:domain/health',
            email: 'GET /:domain/email',
            security: 'GET /:domain/security',
            batch: 'POST /batch {"domains":["a.com","b.com"]}',
            api_docs: 'GET /api/docs',
          },
          family: {
            dns: 'https://ns.lol',
            tls: 'https://certs.lol',
            domains: 'https://yoke.lol',
          },
        });
      }
      if (wantsPlainText(request)) {
        return plainText(
          '; ns.lol — Fast, API-first DNS toolkit\n' +
          '; Usage: curl -sH "Accept: text/plain" https://ns.lol/example.com\n' +
          '; JSON:  curl -s https://ns.lol/example.com | jq\n' +
          '; Docs:  https://ns.lol/api/docs\n'
        );
      }
      return new Response(renderSPA({}, '/', ''), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=60',
          ...SECURITY_HEADERS,
        },
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
      const result = await handleDNSRequest(url, request, env);

      // dig-style plain text output
      if (wantsPlainText(request)) {
        return plainText(formatDig(result), rateLimitHeaders);
      }

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
          'Cache-Control': 'public, max-age=60',
          ...SECURITY_HEADERS,
          ...rateLimitHeaders,
        },
      });
    } catch (err: any) {
      const status = err.status || 400;
      const message = err.message || 'Bad request';

      if (wantsPlainText(request)) {
        return plainText(`; ERROR: ${message}\n`, rateLimitHeaders, status);
      }
      if (wantsJSON(request)) {
        return json({ error: message }, status, rateLimitHeaders);
      }
      return new Response(renderSPA({ error: message }, url.pathname, url.pathname.split('/').filter(Boolean)[0] || ''), {
        status,
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS, ...rateLimitHeaders },
      });
    }
  },
};

function wantsPlainText(request: Request): boolean {
  const accept = request.headers.get('Accept') || '';
  // text/plain explicitly requested (not as a wildcard)
  if (accept.includes('text/plain') && !accept.includes('text/html')) return true;
  return false;
}

function wantsJSON(request: Request): boolean {
  const accept = request.headers.get('Accept') || '';
  const ua = request.headers.get('User-Agent') || '';
  if (accept.includes('application/json') || accept.includes('application/dns-json')) return true;
  if (accept.includes('text/html')) return false;
  if (accept.includes('text/plain')) return false;
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
      ...SECURITY_HEADERS,
      ...extraHeaders,
    },
  });
}

function plainText(text: string, extraHeaders: Record<string, string> = {}, status = 200): Response {
  return new Response(text, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      ...SECURITY_HEADERS,
      ...extraHeaders,
    },
  });
}

function htmlResponse(html: string): Response {
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
      ...SECURITY_HEADERS,
    },
  });
}
