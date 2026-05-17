 import { createClient } from '@supabase/supabase-js';

process.noDeprecation = true;

// ─────────────────────────────
// CONFIG
// ─────────────────────────────
const rateMap = new Map();
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ─────────────────────────────
// RATE LIMIT (per IP or user)
// ─────────────────────────────
function rateLimit(req, res, max = 20) {
  const ip =
    req.headers['x-forwarded-for'] ||
    req.socket?.remoteAddress ||
    'unknown';

  const now = Date.now();
  let entry = rateMap.get(ip) || { count: 0, reset: now + 60000 };

  if (now > entry.reset) {
    entry = { count: 0, reset: now + 60000 };
  }

  entry.count++;
  rateMap.set(ip, entry);

  res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));

  if (entry.count > max) {
    res.status(429).json({
      error: 'Too many requests. Try again later.'
    });
    return false;
  }

  return true;
}

// ─────────────────────────────
// TURNSTILE VERIFY
// ─────────────────────────────
async function verifyTurnstile(token, ip) {
  if (!token || token.length < 10) return false;

  if (!TURNSTILE_SECRET_KEY) return true;

  try {
    const form = new URLSearchParams();
    form.append('secret', TURNSTILE_SECRET_KEY);
    form.append('response', token);
    if (ip) form.append('remoteip', ip);

    const resp = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      { method: 'POST', body: form }
    );

    const data = await resp.json();
    return data.success === true;
  } catch {
    return false;
  }
}

// ─────────────────────────────
// AUTH HELPER
// ─────────────────────────────
async function getUser(req, res) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');

  if (!token) {
    res.status(401).json({ error: 'Missing token' });
    return null;
  }

  const { data, error } = await supabase.auth.getUser(token);

  if (error || !data?.user) {
    res.status(401).json({ error: 'Invalid session' });
    return null;
  }

  return data.user;
}

// ─────────────────────────────
// MAIN HANDLER
// ─────────────────────────────
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(204).end();

  const action = req.query.action;

  // ─────────────────────────────
  // SEND MESSAGE
  // ─────────────────────────────
  if (req.method === 'POST' && action === 'send-message') {
    if (!rateLimit(req, res, 10)) return;

    const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress;
    const ok = await verifyTurnstile(req.body?.captchaToken, ip);

    if (!ok) {
      return res.status(400).json({ error: 'Captcha failed' });
    }

    const user = await getUser(req, res);
    if (!user) return;

    const message = (req.body?.message || '').trim().slice(0, 2000);
    if (!message) {
      return res.status(400).json({ error: 'Message required' });
    }

    await supabase.from('site_sections').insert({
      section: 'message',
      data: {
        user_id: user.id,
        message,
        created_at: new Date().toISOString()
      }
    });

    return res.json({ success: true });
  }

  // ─────────────────────────────
  // SUBMIT RESOURCE
  // ─────────────────────────────
  if (req.method === 'POST' && action === 'submit-resource') {
    if (!rateLimit(req, res, 10)) return;

    const user = await getUser(req, res);
    if (!user) return;

    const body = req.body || {};

    const title = (body.title || '').trim().slice(0, 200);
    const description = (body.description || '').trim().slice(0, 2000);

    if (!title || !description) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    await supabase.from('resource_submissions').insert({
      title,
      description,
      author: body.author || null,
      level: body.level || null,
      category: body.category || null,
      tag: body.tag || null,
      file_url: body.file_url || null,
      file_size: body.file_size || null,
      submitted_by: user.id,
      status: 'pending'
    });

    return res.json({ success: true });
  }

  // ─────────────────────────────
  // GET MESSAGES
  // ─────────────────────────────
  if (req.method === 'GET' && action === 'get-messages') {
    const user = await getUser(req, res);
    if (!user) return;

    const { data: admin } = await supabase
      .from('admin_users')
      .select('user_id')
      .eq('user_id', user.id)
      .maybeSingle();

    const isAdmin = !!admin;

    let query = supabase
      .from('site_sections')
      .select('data, created_at')
      .eq('section', 'message')
      .order('created_at', { ascending: false });

    if (!isAdmin) {
      query = query.eq('data->>user_id', user.id);
    }

    const { data } = await query;

    return res.json({
      isAdmin,
      messages: (data || []).map(r => ({
        ...r.data,
        created_at: r.created_at
      }))
    });
  }

  return res.status(404).json({ error: 'Unknown action' });
}
