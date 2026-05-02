'use strict';

const { app } = require('@azure/functions');

/**
 * Azure Function proxy for Power Automate flow calls.
 *
 * Security model:
 *  - EasyAuth (Azure App Service Authentication) validates the Bearer token
 *    before the request reaches this function.
 *  - The authenticated user's email is read from the x-ms-client-principal header.
 *  - READ action: allowed for all authenticated users.
 *  - ZACHISLI / OTCHISLI: allowed only for users in the machinery_admins table
 *    (checked via Supabase service-role key — never exposed to the client).
 *  - Power Automate URLs live exclusively in Azure environment variables.
 *  - CORS is restricted to ALLOWED_ORIGIN env var.
 */
app.http('proxy', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous', // EasyAuth handles Bearer token validation
  route: 'proxy',
  handler: async (request, context) => {
    const allowedOrigin = process.env.ALLOWED_ORIGIN || '';
    const corsHeaders = {
      'Access-Control-Allow-Origin': allowedOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    };

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return { status: 204, headers: corsHeaders };
    }

    // --- Identity check via EasyAuth principal header ---
    const principalHeader = request.headers.get('x-ms-client-principal');
    if (!principalHeader) {
      return {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Unauthorized: no identity found' }),
      };
    }

    const userEmail = extractEmailFromPrincipal(principalHeader);
    if (!userEmail) {
      return {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Unauthorized: cannot determine user identity' }),
      };
    }
    context.log(`[proxy] authenticated user: ${userEmail}`);

    // --- Parse request body ---
    let body;
    try {
      body = await request.json();
    } catch {
      return {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Invalid JSON body' }),
      };
    }

    const action = (body?.action || '').toUpperCase();
    const payload = body?.payload ?? {};

    const allowedActions = ['READ', 'ZACHISLI', 'OTCHISLI'];
    if (!allowedActions.includes(action)) {
      return {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: `Invalid action. Allowed: ${allowedActions.join(', ')}` }),
      };
    }

    // --- Admin-only enforcement for write operations ---
    if (action !== 'READ') {
      const isAdmin = await checkAdminRole(userEmail);
      if (!isAdmin) {
        context.warn(`[proxy] FORBIDDEN: ${userEmail} attempted ${action}`);
        return {
          status: 403,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Forbidden: administrator access required' }),
        };
      }
    }

    // --- Resolve Power Automate URL from environment ---
    const flowUrlMap = {
      READ:     process.env.FLOW_READ_URL,
      ZACHISLI: process.env.FLOW_ZACHISLI_URL,
      OTCHISLI: process.env.FLOW_OTCHISLI_URL,
    };
    const flowUrl = flowUrlMap[action];
    if (!flowUrl) {
      context.error(`[proxy] Missing env variable for action: ${action}`);
      return {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Server misconfiguration: flow URL not set' }),
      };
    }

    // --- Forward to Power Automate ---
    try {
      context.log(`[proxy] forwarding ${action} to Power Automate`);
      const flowRes = await fetch(flowUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const responseText = await flowRes.text();
      context.log(`[proxy] Power Automate responded: ${flowRes.status}`);

      return {
        status: flowRes.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: responseText || '{}',
      };
    } catch (err) {
      context.error('[proxy] Error calling Power Automate:', err.message);
      return {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: `Flow communication error: ${err.message}` }),
      };
    }
  },
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extracts the user's email from the EasyAuth x-ms-client-principal header.
 * The header value is a base64-encoded JSON object produced by Azure AAD EasyAuth v2.
 */
function extractEmailFromPrincipal(principalHeader) {
  try {
    const decoded = Buffer.from(principalHeader, 'base64').toString('utf8');
    const principal = JSON.parse(decoded);

    // EasyAuth v2 sets userDetails to UPN / email for AAD
    if (principal.userDetails && principal.userDetails.includes('@')) {
      return principal.userDetails.toLowerCase();
    }

    // Fallback: scan the claims array
    const claims = Array.isArray(principal.claims) ? principal.claims : [];
    const emailTypes = [
      'preferred_username',
      'upn',
      'email',
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
    ];
    for (const typ of emailTypes) {
      const claim = claims.find(c => c.typ === typ);
      if (claim?.val && claim.val.includes('@')) {
        return claim.val.toLowerCase();
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Checks whether an email exists in the Supabase machinery_admins table.
 * Uses the service-role key (server-side only — never sent to the browser).
 */
async function checkAdminRole(email) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_KEY;
  if (!supabaseUrl || !supabaseKey) return false;

  try {
    const url =
      `${supabaseUrl}/rest/v1/machinery_admins` +
      `?email=eq.${encodeURIComponent(email)}&select=email&limit=1`;
    const res = await fetch(url, {
      headers: {
        apikey: supabaseKey,
        Authorization: `Bearer ${supabaseKey}`,
        'Content-Type': 'application/json',
        Prefer: 'count=none',
      },
    });
    const data = await res.json();
    return Array.isArray(data) && data.length > 0;
  } catch {
    return false;
  }
}
