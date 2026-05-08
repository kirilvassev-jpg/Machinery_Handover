import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const ALLOWED_ORIGIN = Deno.env.get('ALLOWED_ORIGIN') ?? '';
const SUPABASE_URL   = Deno.env.get('SUPABASE_URL')              ?? '';
const SUPABASE_KEY   = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';

const corsHeaders = {
  'Access-Control-Allow-Origin':  ALLOWED_ORIGIN || '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age':       '86400',
};

function getEmailFromJwt(authHeader: string | null): string | null {
  if (!authHeader?.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '=='.slice(0, (4 - base64.length % 4) % 4);
    const payload = JSON.parse(atob(padded)) as Record<string, unknown>;
    const exp = payload.exp as number | undefined;
    if (!exp || exp < Math.floor(Date.now() / 1000)) return null;
    const email = (
      payload.preferred_username ??
      payload.unique_name ??
      payload.upn ??
      payload.email
    ) as string | undefined;
    return email?.toLowerCase() ?? null;
  } catch { return null; }
}

// ── Main handler ──────────────────────────────────────────────────────────
Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // ── 1. Extract email from JWT (decode only, no signature verification) ────
  const userEmail = getEmailFromJwt(req.headers.get('Authorization'));
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
