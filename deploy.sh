#!/bin/bash
set -e
cd "$(dirname "$0")"

# Source Cloudflare credentials
if [[ -f ~/.wrangler/.env ]]; then
  source ~/.wrangler/.env
  export CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID
fi

if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then
  echo "❌ CLOUDFLARE_API_TOKEN not set. Source ~/.wrangler/.env or export it."
  exit 1
fi

echo "🔍 Type checking..."
npx tsc --noEmit

echo "🚀 Deploying to Cloudflare Workers..."
npx wrangler deploy

echo "✅ Deployed to ns.lol"
echo ""
echo "🧪 Quick smoke test..."
curl -s https://ns.lol/health | python3 -m json.tool
echo ""
echo "📊 Full report test..."
curl -s https://ns.lol/google.com -H "Accept: application/dns-json" | python3 -m json.tool | head -20
