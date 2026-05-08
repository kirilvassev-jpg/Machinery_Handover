import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const ALLOWED_ORIGIN  = Deno.env.get('ALLOWED_ORIGIN')           ?? '';
const SUPABASE_URL    = Deno.env.get('SUPABASE_URL')              ?? '';
const SUPABASE_KEY    = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';
// Azure AD tenant and API app-registration ID (set in Supabase Edge Function secrets)
const AZURE_TENANT_ID = Deno.env.get('AZURE_TENANT_ID')           ?? '';
const AZURE_APP_ID    = Deno.env.get('AZURE_APP_ID')               ?? '';

const corsHeaders = {
  'Access-Control-Allow-Origin':  ALLOWED_ORIGIN || '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age':       '86400',
};

// ── JWKS cache — refreshed at most once per hour ──────────────────────────
interface JwkKey { kid: string; kty: string; n: string; e: string; [k: string]: unknown }
let jwksCache: { keys: JwkKey[]; fetchedAt: number } | null = null;
const JWKS_TTL_MS = 3_600_000;

async function getJwks(): Promise<JwkKey[]> {
  const now = Date.now();
  if (jwksCache && now - jwksCache.fetchedAt < JWKS_TTL_MS) return jwksCache.keys;
  const url = `https://login.microsoftonline.com/${AZURE_TENANT_ID}/discovery/v2.0/keys`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const { keys } = await res.json() as { keys: JwkKey[] };
  jwksCache = { keys, fetchedAt: now };
  return keys;
}

/**
 * Verifies an Azure AD (RS256) JWT cryptographically using Microsoft's JWKS.
 * Returns the user's email on success, or null on any failure.
 */
async function verifyAzureJwt(token: string): Promise<string | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const b64decode = (s: string) => atob(s.replace(/-/g, '+').replace(/_/g, '/'));

  let header: { alg: string; kid: string };
  let payload: Record<string, unknown>;
  try {
    header  = JSON.parse(b64decode(parts[0]));
    payload = JSON.parse(b64decode(parts[1]));
  } catch { return null; }

  // Reject expired tokens
  const exp = payload.exp as number | undefined;
  if (!exp || exp < Math.floor(Date.now() / 1000)) {
    console.warn('[proxy] JWT expired');
    return null;
  }

  // Issuer must contain our tenant
  const iss = payload.iss as string | undefined;
  if (AZURE_TENANT_ID && !iss?.includes(AZURE_TENANT_ID)) {
    console.warn('[proxy] Invalid issuer:', iss);
    return null;
  }

  // Audience must match our API app registration
  const aud = payload.aud as string | undefined;
  if (AZURE_APP_ID && aud !== `api://${AZURE_APP_ID}` && aud !== AZURE_APP_ID) {
    console.warn('[proxy] Invalid audience:', aud);
    return null;
  }

  if (header.alg !== 'RS256') {
    console.warn('[proxy] Unexpected alg:', header.alg);
    return null;
  }

  // Cryptographic signature verification via JWKS
  try {
    const keys = await getJwks();
    const jwk  = keys.find(k => k.kid === header.kid);
    if (!jwk) {
      console.warn('[proxy] No JWK found for kid:', header.kid);
      return null;
    }

    const publicKey = await crypto.subtle.importKey(
      'jwk',
      jwk as unknown as JsonWebKey,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );

    const signedData = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const sigBytes   = Uint8Array.from(b64decode(parts[2]), c => c.charCodeAt(0));

    const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, sigBytes, signedData);
    if (!valid) {
      console.warn('[proxy] JWT signature verification failed');
      return null;
    }
  } catch (e) {
    console.error('[proxy] JWT crypto error:', e);
    return null;
  }

  const email = (payload.preferred_username ?? payload.upn ?? payload.email) as string | undefined;
  return email ?? null;
}

// ── Main handler ──────────────────────────────────────────────────────────
Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // ── 1. Verify JWT ─────────────────────────────────────────────────────────
  const authHeader = req.headers.get('Authorization') ?? '';
  const jwt = authHeader.replace(/^Bearer\s+/i, '');
  if (!jwt) return json({ error: 'Unauthorized' }, 401);

  let userEmail: string | null = null;

  // Try Supabase Auth first (supports Supabase-issued tokens)
  const supabaseAnon = createClient(SUPABASE_URL, Deno.env.get('SUPABASE_ANON_KEY') ?? '');
  const { data: { user } } = await supabaseAnon.auth.getUser(jwt);
  if (user?.email) {
    userEmail = user.email;
  } else {
    // Azure AD token — verify signature cryptographically via JWKS
    userEmail = await verifyAzureJwt(jwt);
  }

  if (!userEmail) return json({ error: 'Unauthorized' }, 401);

  // ── 2. Parse action ───────────────────────────────────────────────────────
  let body: Record<string, unknown>;
  try { body = await req.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  const urlAction = new URL(req.url).pathname.split('/').pop()?.toLowerCase() ?? '';
  const action = (urlAction || String(body.action ?? '')).toLowerCase();

  const ALLOWED_ACTIONS = ['read', 'zachisli', 'otchisli'];
  if (!ALLOWED_ACTIONS.includes(action)) {
    return json({ error: `Invalid action. Allowed: ${ALLOWED_ACTIONS.join(', ')}` }, 400);
  }

  // ── 3. Admin check for write operations ───────────────────────────────────
  if (action !== 'read') {
    const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_KEY);
    const { data: adminRow } = await supabaseAdmin
      .from('machinery_admins')
      .select('email')
      .eq('email', userEmail.toLowerCase())
      .maybeSingle();

    if (!adminRow) {
      console.warn(`[proxy] FORBIDDEN: ${userEmail} attempted ${action}`);
      return json({ error: 'Forbidden: administrator access required' }, 403);
    }
  }

  // ── 4. Resolve Power Automate URL ─────────────────────────────────────────
  const flowUrlMap: Record<string, string | undefined> = {
    read:     Deno.env.get('FLOW_READ_URL'),
    zachisli: Deno.env.get('FLOW_ZACHISLI_URL'),
    otchisli: Deno.env.get('FLOW_OTCHISLI_URL'),
  };
  const flowUrl = flowUrlMap[action];
  if (!flowUrl) {
    console.error(`[proxy] Missing env var for action: ${action}`);
    return json({ error: 'Server misconfiguration: flow URL not set' }, 500);
  }

  // ── 5. Forward to Power Automate ──────────────────────────────────────────
  const payload = (body.payload ?? body) as Record<string, unknown>;
  delete payload.action;

  const flowSecret = Deno.env.get('FLOW_SECRET');
  if (flowSecret) {
    payload.secret = flowSecret;
  }

  console.log(`[proxy] ${userEmail} → ${action}`);
  const flowRes = await fetch(flowUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const responseText = await flowRes.text();
  console.log(`[proxy] Power Automate → ${flowRes.status}`);

  return new Response(responseText, {
    status: flowRes.status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
});

function json(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
