// ns.lol — Fast, API-first DNS toolkit
// Worker entry point: routing, content negotiation, rate limiting

export { RateLimiterDO } from './rate-limiter';

export interface Env {
  CACHE: KVNamespace;
  RATE_LIMITER: DurableObjectNamespace;
  PROBE_URL?: string;  // e.g. https://ns-lol-probe.fly.dev
  PROBE_KEY?: string;  // auth secret for the Fly probe
  ADMIN_KEY?: string;  // admin key for /usage dashboard
  /** Yoke domain intelligence service binding (.lol family) */
  YOKE?: Fetcher;
  /** Shared key for .lol family service bindings */
  SERVICE_KEY?: string;
}

import { handleDNSRequest, formatDig, privacyPage, termsPage, docsPage, cliPage, aboutPage, sitemapXml, INSTALL_SCRIPT } from './handler';
import { renderSPA } from './spa';
import { OG_PNG_B64, TOUCH_ICON_B64, ICON_192_B64, ICON_512_B64 } from './og-image';
import { trackLookup, handleUsage } from './usage';
import { renderStatusPage } from './status';

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '0',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https://yoke.lol; frame-ancestors 'none'; base-uri 'self'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
};

function cspWithNonce(nonce: string): string {
  return "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https://yoke.lol; frame-ancestors 'none'; base-uri 'self'";
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
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

    // MTA-STS policy file (served from mta-sts.ns.lol)
    if (url.hostname === 'mta-sts.ns.lol' && path === '/.well-known/mta-sts.txt') {
      return new Response(
        'version: STSv1\nmode: enforce\nmx: route1.mx.cloudflare.net\nmx: route2.mx.cloudflare.net\nmx: route3.mx.cloudflare.net\nmax_age: 604800\n',
        { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' } },
      );
    }
    if (url.hostname === 'mta-sts.ns.lol') {
      return new Response('Not found', { status: 404 });
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
        'Contact: https://github.com/yokedotlol/ns-lol/issues\n' +
        'Preferred-Languages: en\n' +
        'Canonical: https://ns.lol/.well-known/security.txt\n' +
        'Expires: 2027-06-01T00:00:00.000Z\n'
      );
    }

    // llms.txt
    if (path === '/llms.txt') {
      return plainText(llmsTxt());
    }

    // ARD ai-catalog.json — Agentic Resource Discovery
    if (path === '/.well-known/ai-catalog.json') {
      const catalog = {
        specVersion: "1.0",
        host: {
          displayName: "ns.lol",
          identifier: "did:web:ns.lol",
          documentationUrl: "https://ns.lol/api/docs",
        },
        entries: [
          {
            identifier: "urn:air:ns.lol:api:dns-toolkit",
            displayName: "ns.lol DNS Toolkit API",
            type: "application/openapi+json",
            url: "https://ns.lol/api/docs",
            description: "Free DNS toolkit API — distributed lookups from 20+ global resolvers, propagation checks, deep SPF analysis with lookup budget tracking, email auth (SPF/DKIM/DMARC), DNSSEC validation, health monitoring. No auth required.",
            representativeQueries: [
              "check DNS propagation for a domain",
              "lookup MX records for example.com",
              "validate DNSSEC for a domain",
              "check SPF and DMARC records",
              "deep SPF analysis with lookup budget",
              "trace DNS delegation chain",
            ],
          },
        ],
      };
      return new Response(JSON.stringify(catalog, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=86400' },
      });
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

    // Alias: /api/docs → /docs (other .lol tools use /api/docs)
    if (path === '/api/docs') {
      return Response.redirect('https://ns.lol/docs', 301);
    }

    // CLI docs page
    if (path === '/cli') {
      return htmlResponse(cliPage());
    }

    // About page
    if (path === '/about') {
      return htmlResponse(aboutPage());
    }

    // Install script
    if (path === '/install.sh') {
      return new Response(INSTALL_SCRIPT, {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          ...SECURITY_HEADERS,
        },
      });
    }

    // Usage dashboard (admin, before rate limiter)
    if (path === '/usage') {
      return handleUsage(request, env);
    }

    // Public status page
    if (path === '/status') {
      return renderStatusPage(env);
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
            http: 'https://xhttp.lol',
            email: 'https://vrfy.lol',
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
      const nonce = crypto.randomUUID();
      return new Response(renderSPA({}, '/', '', nonce), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          ...SECURITY_HEADERS,
          'Content-Security-Policy': cspWithNonce(nonce),
        },
      });
    }

    // Static assets
    if (path === '/favicon.svg') {
      return new Response(faviconSvg(), {
        headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=604800', ...SECURITY_HEADERS },
      });
    }

    if (path === '/favicon.ico') {
      const binary = Uint8Array.from(atob(FAVICON_ICO_B64), c => c.charCodeAt(0));
      return new Response(binary, {
        headers: { 'Content-Type': 'image/vnd.microsoft.icon', 'Cache-Control': 'public, max-age=604800', ...SECURITY_HEADERS },
      });
    }

    if (path === '/bimi-logo.svg') {
      return new Response(bimiSvg(), {
        headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=604800', ...SECURITY_HEADERS },
      });
    }

    // OG image
    if (path === '/og.png') {
      const raw = OG_PNG_B64;
      const binary = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
      return new Response(binary, {
        headers: {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=86400',
          ...SECURITY_HEADERS,
        },
      });
    }

    // Apple touch icon
    if (path === '/apple-touch-icon.png') {
      const raw = TOUCH_ICON_B64;
      const binary = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
      return new Response(binary, {
        headers: {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=604800',
          ...SECURITY_HEADERS,
        },
      });
    }

    // PWA icons
    if (path === '/icon-192.png') {
      const binary = Uint8Array.from(atob(ICON_192_B64), c => c.charCodeAt(0));
      return new Response(binary, {
        headers: {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=604800',
          ...SECURITY_HEADERS,
        },
      });
    }

    if (path === '/icon-512.png') {
      const binary = Uint8Array.from(atob(ICON_512_B64), c => c.charCodeAt(0));
      return new Response(binary, {
        headers: {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=604800',
          ...SECURITY_HEADERS,
        },
      });
    }

    // PWA manifest
    if (path === '/manifest.json') {
      return new Response(JSON.stringify({
        name: "ns.lol",
        short_name: "ns",
        icons: [
          { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
          { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
        ],
        display: "standalone",
        background_color: "#0a0a0f",
        theme_color: "#22d2ee",
      }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'public, max-age=86400',
          ...SECURITY_HEADERS,
        },
      });
    }

    // Cache probe — skip rate limiting for cached results (cache hits are free)
    const probeParts = url.pathname.split('/').filter(Boolean);
    const probeDomain = probeParts[0];
    const probeAction = probeParts[1]?.toLowerCase();
    const probeForce = url.searchParams.get('force') === 'true';
    const probeExplain = url.searchParams.get('explain') === 'true';
    let skipRateLimit = false;
    if (probeDomain && !probeForce && !probeExplain && probeAction !== 'propagation') {
      try {
        const probeCacheKey = `dns:${probeDomain}:${probeAction || 'full'}`;
        skipRateLimit = !!(await env.CACHE.get(probeCacheKey, 'text'));
      } catch { /* cache probe failure → fall through to rate limiting */ }
    }

    // Rate limiting — only fresh lookups count
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    let rl = { allowed: true, remaining: 120, reset: 0 };
    if (!skipRateLimit) {
      const rlId = env.RATE_LIMITER.idFromName(clientIP);
      const rlStub = env.RATE_LIMITER.get(rlId);
      const rlResp = await rlStub.fetch('https://rl/check');
      rl = await rlResp.json() as { allowed: boolean; remaining: number; reset: number };
    }

    const rateLimitHeaders: Record<string, string> = {
      'X-RateLimit-Limit': '120',
      'X-RateLimit-Remaining': String(rl.remaining),
      'X-RateLimit-Reset': String(rl.reset),
    };

    if (!rl.allowed) {
      const rlTarget = url.pathname.split('/').filter(Boolean)[0] || 'unknown';
      ctx.waitUntil(trackLookup(env, { target: rlTarget, endpoint: 'rate_limited', cache_hit: false, rate_limited: true }));
      return json(
        { error: 'Rate limit exceeded', retry_after: rl.reset - Math.floor(Date.now() / 1000) },
        429,
        { ...rateLimitHeaders, 'Retry-After': String(rl.reset - Math.floor(Date.now() / 1000)) }
      );
    }

    // Route DNS requests
    try {
      const result = await handleDNSRequest(url, request, env);

      // Track the lookup
      const pathParts = url.pathname.split('/').filter(Boolean);
      const lookupTarget = pathParts[0] || 'unknown';
      const lookupEndpoint = pathParts[1] || 'lookup';
      ctx.waitUntil(trackLookup(env, {
        target: lookupTarget,
        endpoint: lookupEndpoint,
        cache_hit: !!result._cached,
      }));

      const cacheStatus = result._cached ? 'HIT' : 'MISS';

      // dig-style plain text output
      if (wantsPlainText(request)) {
        return plainText(formatDig(result), { ...rateLimitHeaders, 'X-Cache': cacheStatus });
      }

      if (wantsJSON(request)) {
        return json(result, 200, {
          ...rateLimitHeaders,
          'X-Cache': cacheStatus,
          'Cache-Control': result._cache_control || 'public, max-age=300',
        });
      }

      // Browser gets SPA with data embedded
      const domainSlug = url.pathname.split('/').filter(Boolean)[0] || '';
      const nonce = crypto.randomUUID();
      return new Response(renderSPA(result, url.pathname, domainSlug, nonce, { remaining: rl.remaining, limit: 120 }), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          ...SECURITY_HEADERS,
          'Content-Security-Policy': cspWithNonce(nonce),
          ...rateLimitHeaders,
          'X-Cache': cacheStatus,
        },
      });
    } catch (err: any) {
      const status = err.status || 400;
      const message = err.message || 'Bad request';

      // Track the error
      const errParts = url.pathname.split('/').filter(Boolean);
      const errTarget = errParts[0] || 'unknown';
      const errEndpoint = errParts[1] || 'lookup';
      ctx.waitUntil(trackLookup(env, {
        target: errTarget,
        endpoint: errEndpoint,
        cache_hit: false,
        error: true,
        detail: message,
      }));

      if (wantsPlainText(request)) {
        return plainText(`; ERROR: ${message}\n`, rateLimitHeaders, status);
      }
      if (wantsJSON(request)) {
        return json({ error: message }, status, rateLimitHeaders);
      }
      const nonce = crypto.randomUUID();
      return new Response(renderSPA({ error: message }, url.pathname, url.pathname.split('/').filter(Boolean)[0] || '', nonce, { remaining: rl.remaining, limit: 120 }), {
        status,
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS, 'Content-Security-Policy': cspWithNonce(nonce), ...rateLimitHeaders },
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
      'Vary': 'Accept, Accept-Encoding',
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

function llmsTxt(): string {
  return [
    '# ns.lol',
    '',
    '> Fast, API-first DNS toolkit',
    '',
    'ns.lol provides instant DNS lookups, propagation monitoring, zone health checks,',
    'email DNS auditing, and security analysis. No accounts required. No tracking.',
    '',
    '## API',
    '',
    'All endpoints accept Accept: application/json (default for curl/CLI),',
    'Accept: text/plain (dig-style output), and text/html (browser UI).',
    '',
    '- GET / — Service info',
    '- GET /:domain — Full DNS report (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, HTTPS, SVCB, DS, DNSKEY)',
    '- GET /:domain/:type — Specific record type (55+ named types, or any numeric QTYPE 1-65535)',
    '- GET /:domain/any — ANY query',
    '- GET /:domain/trace — Authority chain trace',
    '- GET /:domain/propagation — Multi-resolver propagation check',
    '- GET /:domain/health — Zone health report with grading',
    '- GET /:domain/email — Email DNS audit (MX, SPF, DKIM, DMARC, DANE)',
    '- GET /:domain/spf — Deep SPF analysis (recursive include tree, lookup budget, term explanations)',
    '- GET /:domain/security — Security analysis (DNSSEC, CAA, HTTPS records)',
    '- POST /batch — Batch lookup: {"domains": ["a.com", "b.com"]}',
    '',
    '## Rate Limits',
    '',
    '120 requests/hour per IP. Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset.',
    '',
    '## CLI',
    '',
    'Wraps the ns.lol API — distributed DNS checks across 13 global resolvers. No accounts, no API keys.',
    '- Install: brew install yokedotlol/tap/ns',
    '- Or: curl -sSL https://ns.lol/install.sh | bash',
    '- Docs: https://ns.lol/cli',
    '',
    '## Family',
    '',
    '- [yoke.lol](https://yoke.lol) — Domain analysis',
    '- [certs.lol](https://certs.lol) — TLS certificate checker',
    '- [xhttp.lol](https://xhttp.lol) — HTTP response debugger',
    '- [vrfy.lol](https://vrfy.lol) — Email validation',
    '- [ns.lol](https://ns.lol) — DNS toolkit (this site)',
    '',
    '## Contact',
    '',
    '- GitHub: https://github.com/yokedotlol/ns-lol',
    '',
  ].join('\n');
}

// Base64-encoded multi-size ICO — favicon.ico (16/32/48px)
const FAVICON_ICO_B64 = "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CP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/3t1XP/58bz/ZF9L/wwICP8MCAj/DAgI/wwICP8pJB7/+fG8/7Kshv8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/e3Vc//nxvP9kX0v/DAgI/wwICP8MCAj/DAgI/ykkHv/58bz/sqyG/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP97dVz/+fG8/2RfS/8MCAj/DAgI/wwICP8MCAj/KSQe//nxvP+yrIb/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/3t1XP/58bz/ZF9L/wwICP8MCAj/DAgI/wwICP8pJB7/+fG8/7Kshv8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/e3Vc//nxvP9kX0v/DAgI/wwICP8MCAj/DAgI/ykkHv/58bz/sqyG/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP97dVz/+fG8/2RfS/8MCAj/DAgI/wwICP8MCAj/KSQe//nxvP+yrIb/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/3t1XP/58bz/Z2JN/wwICP8MCAj/DAgI/wwICP8pJB7/+fG8/7Kshv8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/e3Vc//nxvP+DfWL/DAgI/wwICP8MCAj/DAgI/ykkHv/58bz/sqyG/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP97dVz/+fG8/8fAlv8MCAj/DAgI/wwICP8MCAj/Ozcs//nxvP+yrIb/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/3t1XP/58bz/+fG8/313Xv8MCAj/DAgI/w0JCf+dl3b/+fG8/5OMbv8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/e3Vc//nxvP+qo4D/+fG8/9PMn/+oon//0cqe//nxvP/07Lj/Ozcs/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP97dVz/+fG8/0Q/Mv94clr/6OGv//nxvP/p4bD/vbaO/0dCNP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8PCwr/Eg0M/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8zLy//DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/5KQkP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/7Ozs/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP//////qaio/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/rq2t////////////rq2t/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/6moqP//////////////////////7e3t/5eVlf88ODj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/My8v/5KQkP/s7Oz///////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAwAAAAYAAAAAEAIAAAAAAAACQAAF4nAABeJwAAAAAAAAAAAAD///////////Ly8v+6uLj/WFZW/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/BgIC/ycjI/+TkpL/3t3d////////////8/Pz/8jHx/9zcXH/MC0t/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/CQUF/xkVFf9RTk7/oqGh/9zb2//9/f3/zs3N/3t5ef8hHR3/BwMD/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8KBgb/T0xM/4+Njf/y8vL/kI6O/yEdHf8OCgr/CgYG/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8LBwf/GRUV/yYiIv/GxcX/aGZm/wYCAv8KBgb/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/CQUF/wYCAv+Ihob/TElJ/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP9LSEj/LCkp/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8hHR3/FxMT/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/CgYH/wcDBP8EAQL/BgIE/wkGBv8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8LBwf/BwME/wQAAv8GAgP/CQUG/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/FRAO/yIeGf8wLCT/KSQe/xgUEf8OCgr/CwcI/wwICP8MCAj/DAgI/w0JCP8QDAv/Ix4Z/zIuJf8qJh//GhUS/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwj/NjIo/3t1XP/BupL/mpN0/0hDNv8XExH/CQUG/wwICP8MCAj/CwcH/w8LCv8fGxb/fXhe/8rCmP+jnHr/T0o7/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/QTww/5aQcf/r5bP/u7WO/1dSQf8aFhP/CQUG/wwICP8MCAj/CwcH/w8LC/8jHxr/mJNz//bwu//HwJb/YFpH/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/m3q3/tq+J/1VPP/8aFRL/CQUG/wwICP8MCAj/CwcH/w8LCv8jHhn/lI5w//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/m3q3/tq+J/1VPP/8aFRL/CQUG/wwICP8MCAj/CwcH/w8LCv8jHhn/lI5w//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/m3q3/tq+J/1VPP/8aFRL/CQUG/wwICP8MCAj/CwcH/w8LCv8jHhn/lI5w//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/m3q3/tq+J/1VPP/8aFRL/CQUG/wwICP8MCAj/CwcH/w8LCv8jHhn/lI5w//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/m3q3/tq+J/1VPP/8aFRL/CQUG/wwICP8MCAj/CwcH/w8LCv8jHhn/lI5w//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/m3q3/tq+J/1RPP/8aFRL/CQUG/wwICP8MCAj/CwcH/w8LCv8jHhn/lI5w//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/m3q3/tq+J/1VQP/8aFhL/CQUG/wwICP8MCAj/CwcH/w8LCv8jHhn/lI5w//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/m3q3/t7CK/1ZRQP8aFhP/CQUG/wwICP8MCAj/CwcH/w8LCv8jHhn/lI5w//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5KLbf/l3q3/vreP/2FbSP8cGBT/CAQF/wwICP8MCAj/CwcH/w8LCv8iHhn/lI5v//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5GLbf/l3q3/zcWa/3dyWv8gHBf/BwME/wwICP8MCAj/CwcH/xAMC/8lIBv/lo9x//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5GLbf/l3a3/5d2t/52Xdv8oJB7/BgID/wwICP8MCAj/CgcH/xIODP8vKiP/nJZ2//Dotf/BupH/XVdF/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5GKbf/l3a3/+fG8/8rDmP9cV0X/HRkV/wUBA/8GAgP/AwAB/xURD/9YU0L/uLGK/+3ls/+2r4n/VlFA/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5GKbf/l3a3/+vK9/9/XqP+jnXv/XlhG/ysnIP8mIhz/JSAb/0M+Mf+YkXL/3NWm/+fgr/+Zk3P/RD8z/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/Pzov/5GLbf/l3a3/29Sm/8C5kf/e16j/z8ec/6ukgf+TjW7/m5V1/7qzjP/h2ar/+PC8/9rSpP9nYk3/JSEb/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwf/QTww/5aQcf/r5bP/vLeP/4F7Yf+zrIf/2dKk/+risf/h2an/5d2s/+vjsf/m3q7/xr+V/4qEaP82MSj/Eg4N/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wsHB/8LBwj/NjIo/3t2Xf/BupL/iIJm/z86L/9cV0X/lY9w/8fAlv/Ryp7/zcab/7+4kP+ln33/bWhS/zMuJv8TDw3/CgYH/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/FRAO/yIeGf8xLCT/JSAb/xYRD/8bFxT/KCQe/zUwJ/84NCr/NjEo/zArI/8rJh//HxsW/xMPDf8NCQn/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/CgYH/wcDBP8EAQL/BwME/woGBv8JBQX/BwME/wYCA/8HAwT/BgID/wUBAv8GAgP/CAQF/woGB/8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8LBwf/CwcH/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8SDg7/DwsL/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8sKCj/HBkZ/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP9hXl7/ODQ0/wsHB/8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP+ioaH/WVZW/woGBv8LBwf/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/CwcH/wsHB//f39//eHZ2/woGBv8KBgb/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/CwcH/wsHB//6+vr/rqys/0lGRv8TDw//BgIC/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/woGBv8HAwP/Mi4u/1tYWP//////4uHh/6Cenv8/PDz/Ew8P/woGBv8LBwf/CwcH/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8LBwf/CgYG/w4KCv8gHBz/dXJy/769vf///////Pz8/+Pi4v+joqL/S0hI/woGBv8KBgb/CwcH/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8LBwf/BgIC/yAcHP94dXX/x8bG//Pz8/////////////r6+v/k4+P/r66u/3l2dv9bWFj/Ozg4/yAcHP8QDAz/CwcH/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/FBAQ/ygkJP9JRkb/Z2Rk/4+Njf/My8v/8fDw////////////////////////////+vr6/+Hg4P+npaX/aWZm/zMwMP8TDw//CgYG/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/DAgI/wwICP8MCAj/HBgY/0NAQP+CgID/w8LC//Hx8f/9/f3///////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

function faviconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#08080c"/>
  <text x="16" y="24" font-family="monospace" font-weight="500" font-size="22"
        fill="#bcf1f9" text-anchor="middle">n</text>
</svg>`;
}

function bimiSvg(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"
     viewBox="0 0 512 512" width="512" height="512">
  <title>ns BIMI Logo</title>
  <rect width="512" height="512" fill="#0a0a0f"/>
  <text x="175" y="330" font-size="280"
        fill="#22d2ee" opacity="0.15">n</text>
  <text x="175" y="330" font-size="280"
        fill="#22d2ee" opacity="0.25">n</text>
  <text x="175" y="330" font-size="280"
        fill="#bcf1f9">n</text>
  <rect x="310" y="135" width="80" height="200" rx="2" fill="#22d2ee"/>
</svg>`;
}
