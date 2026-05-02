import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const ALLOWED_ORIGIN = Deno.env.get('ALLOWED_ORIGIN') ?? '';
const SUPABASE_URL   = Deno.env.get('SUPABASE_URL')   ?? '';
const SUPABASE_KEY   = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''; // service role key

const corsHeaders = {
  'Access-Control-Allow-Origin':  ALLOWED_ORIGIN || '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age':       '86400',
};

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // ── 1. Verify JWT (Supabase Auth) ─────────────────────────────────────────
  const authHeader = req.headers.get('Authorization') ?? '';
  const jwt = authHeader.replace(/^Bearer\s+/i, '');
  if (!jwt) {
    return json({ error: 'Unauthorized' }, 401);
  }

  // Use anon client just to verify the token and get user email
  const supabaseAnon = createClient(SUPABASE_URL, Deno.env.get('SUPABASE_ANON_KEY') ?? '');
  const { data: { user }, error: authErr } = await supabaseAnon.auth.getUser(jwt);

  // The app uses MSAL tokens (Azure AD), not Supabase Auth tokens.
  // We decode the JWT ourselves to extract the email claim.
  let userEmail: string | null = null;
  if (user?.email) {
    userEmail = user.email;
  } else {
    // Decode Azure AD JWT payload (no signature verification — EasyAuth/Supabase does that)
    try {
      const payload = JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
      userEmail = payload.preferred_username ?? payload.upn ?? payload.email ?? null;
    } catch {
      return json({ error: 'Invalid token' }, 401);
    }
  }

  if (!userEmail) {
    return json({ error: 'Cannot determine user identity' }, 401);
  }

  // ── 2. Parse action ───────────────────────────────────────────────────────
  let body: Record<string, unknown>;
  try { body = await req.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  // Support both flat action routing (URL path) and body action field
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
  // Remove internal fields before forwarding
  delete payload.action;

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
