import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const ALLOWED_ORIGIN = Deno.env.get('ALLOWED_ORIGIN') ?? '';
const SUPABASE_URL   = Deno.env.get('SUPABASE_URL')   ?? '';
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
    if (!exp || exp < Math.floor(Date.now() / 1000)) {
      console.warn('[proxy] JWT изтекъл');
      return null;
    }
    const email = (
      payload.preferred_username ??
      payload.unique_name ??
      payload.upn ??
      payload.email
    ) as string | undefined;
    return email?.toLowerCase() ?? null;
  } catch (e) {
    console.error('[proxy] JWT decode грешка:', e);
    return null;
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const userEmail = getEmailFromJwt(req.headers.get('Authorization'));
  if (!userEmail) {
    return json({ error: 'Unauthorized — невалиден или изтекъл токен' }, 401);
  }
  console.log(`[proxy] потребител: ${userEmail}`);

  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* празно тяло */ }

  const urlAction = new URL(req.url).pathname.split('/').pop()?.toLowerCase() ?? '';
  const action    = (urlAction || String(body.action ?? '')).toLowerCase();

  const ALLOWED_ACTIONS = ['read', 'zachisli', 'otchisli', 'catalog-replace', 'catalog-upsert'];
  if (!ALLOWED_ACTIONS.includes(action)) {
    return json({ error: `Невалидно действие: ${action}` }, 400);
  }

  if (action !== 'read') {
    const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_KEY);
    const { data: adminRow } = await supabaseAdmin
      .from('machinery_admins')
      .select('email')
      .eq('email', userEmail)
      .maybeSingle();
    if (!adminRow) {
      console.warn(`[proxy] ЗАБРАНЕНО: ${userEmail} → ${action}`);
      return json({ error: 'Forbidden — изисква се администраторска роля' }, 403);
    }

    if (action === 'catalog-replace') {
      const machines = body.machines as Array<{kod:string,ime:string,kat:string,cena:number}> | undefined;
      if (!Array.isArray(machines) || machines.length === 0) {
        return json({ error: 'Невалидни данни — липсва масив machines' }, 400);
      }
      const db = createClient(SUPABASE_URL, SUPABASE_KEY);
      const { error: delErr } = await db.from('machinery_catalog').delete().not('kod', 'is', null);
      if (delErr) {
        console.error('[proxy] catalog-replace delete error:', delErr);
        return json({ error: 'Грешка при изтриване: ' + delErr.message }, 500);
      }
      const rows = machines.map(m => ({ kod: m.kod, ime: m.ime, kat: m.kat, cena: m.cena, updated_at: new Date().toISOString() }));
      const BATCH = 500;
      for (let i = 0; i < rows.length; i += BATCH) {
        const { error: insErr } = await db.from('machinery_catalog').insert(rows.slice(i, i + BATCH));
        if (insErr) {
          console.error('[proxy] catalog-replace insert error:', insErr);
          return json({ error: 'Грешка при запис: ' + insErr.message }, 500);
        }
      }
      console.log(`[proxy] catalog-replace: ${machines.length} машини от ${userEmail}`);
      return json({ ok: true, count: machines.length }, 200);
    }

    if (action === 'catalog-upsert') {
      const machines = body.machines as Array<{kod:string,ime:string,kat:string,cena:number}> | undefined;
      if (!Array.isArray(machines) || machines.length === 0) {
        return json({ error: 'Невалидни данни — липсва масив machines' }, 400);
      }
      const db = createClient(SUPABASE_URL, SUPABASE_KEY);
      const rows = machines.map(m => ({ kod: m.kod, ime: m.ime, kat: m.kat, cena: m.cena, updated_at: new Date().toISOString() }));
      const BATCH = 500;
      for (let i = 0; i < rows.length; i += BATCH) {
        const { error: upsErr } = await db.from('machinery_catalog').upsert(rows.slice(i, i + BATCH), { onConflict: 'kod' });
        if (upsErr) {
          console.error('[proxy] catalog-upsert error:', upsErr);
          return json({ error: 'Грешка при запис: ' + upsErr.message }, 500);
        }
      }
      console.log(`[proxy] catalog-upsert: ${machines.length} машини от ${userEmail}`);
      return json({ ok: true, count: machines.length }, 200);
    }
  }

  const flowUrlMap: Record<string, string | undefined> = {
    read:     Deno.env.get('FLOW_READ_URL'),
    zachisli: Deno.env.get('FLOW_ZACHISLI_URL'),
    otchisli: Deno.env.get('FLOW_OTCHISLI_URL'),
  };
  const flowUrl = flowUrlMap[action];
  if (!flowUrl) {
    return json({ error: 'Грешна конфигурация — Flow URL не е зададен' }, 500);
  }

  const payload = { ...(body.payload ?? body) } as Record<string, unknown>;
  delete payload.action;
  const flowSecret = Deno.env.get('FLOW_SECRET');
  if (flowSecret) payload.secret = flowSecret;

  console.log(`[proxy] ${userEmail} → ${action}`);
  try {
    const flowRes = await fetch(flowUrl, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    const responseText = await flowRes.text();
    console.log(`[proxy] Power Automate → ${flowRes.status}`);
    return new Response(responseText, {
      status:  flowRes.status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (e) {
    console.error('[proxy] Грешка:', e);
    return json({ error: 'Грешка при свързване с Power Automate' }, 502);
  }
});

function json(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
