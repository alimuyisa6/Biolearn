 const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const ACTION_WHITELIST = new Set([
  'get_site_section', 'get_all_site_sections', 'get_all_sections',
  'get_resources', 'get_filter_options',
  'submit_contact', 'subscribe_newsletter', 'submit_resource',
  'signup', 'signin', 'signout', 'get_user',
  'stats', 'submissions', 'approve', 'messages',
  'create_payment', 'send_message', 'currencies', 'status',
  'ai_query', 'get_donate_page_config', 'submit_momo_donation'
]);

const RATE_LIMITS = new Map();
const MAX_REQUESTS = 30;
const WINDOW_MS = 60000;
const BANNED_IPS = new Set();

function rateLimit(ip) {
  if (BANNED_IPS.has(ip)) return false;
  const now = Date.now();
  const record = RATE_LIMITS.get(ip) || { count: 0, reset: now + WINDOW_MS };
  if (now > record.reset) { record.count = 0; record.reset = now + WINDOW_MS; }
  record.count++;
  RATE_LIMITS.set(ip, record);
  if (record.count > MAX_REQUESTS * 2) { BANNED_IPS.add(ip); return false; }
  return record.count <= MAX_REQUESTS;
}

const VALIDATORS = {
  submit_contact: (body) => {
    const { name, email, subject, message } = body.formData || {};
    if (!name || typeof name !== 'string' || name.length > 100) return 'Invalid name';
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email';
    if (!message || typeof message !== 'string' || message.length > 5000) return 'Invalid message';
    return null;
  },
  subscribe_newsletter: (body) => {
    const { email } = body.formData || {};
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email';
    return null;
  },
  signup: (body) => {
    if (!body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return 'Invalid email';
    if (!body.password || typeof body.password !== 'string' || body.password.length < 6) return 'Password too short';
    return null;
  },
  signin: (body) => {
    if (!body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return 'Invalid email';
    if (!body.password || typeof body.password !== 'string') return 'Password required';
    return null;
  },
  submit_resource: (body) => {
    const p = body.payload || {};
    if (!p.title || typeof p.title !== 'string' || p.title.length > 200) return 'Invalid title';
    if (!p.description || typeof p.description !== 'string' || p.description.length > 5000) return 'Invalid description';
    return null;
  },
  ai_query: (body) => {
    if (!body.prompt || typeof body.prompt !== 'string' || body.prompt.length > 2000) return 'Invalid prompt';
    return null;
  },
  submit_momo_donation: (body) => {
    if (!body.amount || typeof body.amount !== 'string') return 'Amount required';
    if (!body.txid || typeof body.txid !== 'string') return 'Transaction ID required';
    return null;
  }
};

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  if (!rateLimit(ip)) return res.status(429).json({ error: 'Too many requests' });

  try {
    if (req.method === 'GET') return await handleGet(req, res);
    if (req.method === 'POST') return await handlePost(req, res);
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (error) {
    console.error('API Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

async function handleGet(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const action = url.searchParams.get('action');
  if (!action || !ACTION_WHITELIST.has(action)) return res.status(400).json({ error: 'Invalid action' });

  try {
    let result;
    switch (action) {
      case 'get_all_site_sections': case 'get_all_sections': {
        const { data, error } = await supabase.from('site_sections').select('section, data');
        if (error) throw error;
        result = {};
        (data || []).forEach(row => { result[row.section] = row.data; });
        break;
      }
      case 'get_resources': {
        let query = supabase.from('biology_notes').select('*').order('created_at', { ascending: false }).limit(100);
        const level = url.searchParams.get('level');
        const category = url.searchParams.get('category');
        const tag = url.searchParams.get('tag');
        if (level) query = query.eq('level', level);
        if (category) query = query.eq('category', category);
        if (tag) query = query.eq('tag', tag);
        const { data, error } = await query;
        if (error) throw error;
        result = data || [];
        break;
      }
      case 'get_filter_options': {
        const [l, c, t] = await Promise.all([
          supabase.from('biology_notes').select('level').limit(500),
          supabase.from('biology_notes').select('category').limit(500),
          supabase.from('biology_notes').select('tag').limit(500)
        ]);
        result = {
          levels: [...new Set((l.data || []).map(x => x.level).filter(Boolean))],
          categories: [...new Set((c.data || []).map(x => x.category).filter(Boolean))],
          tags: [...new Set((t.data || []).map(x => x.tag).filter(Boolean))]
        };
        break;
      }
      case 'currencies': result = { currencies: [{ currency: 'btc' }, { currency: 'eth' }, { currency: 'usdttrc20' }] }; break;
      case 'status': result = { status: 'finished' }; break;
      default: result = null;
    }
    return res.status(200).json(result);
  } catch (error) {
    console.error('GET Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

async function handlePost(req, res) {
  const { action } = req.body;
  if (!action || !ACTION_WHITELIST.has(action)) return res.status(400).json({ error: 'Invalid action' });

  const validator = VALIDATORS[action];
  if (validator) {
    const validationError = validator(req.body);
    if (validationError) return res.status(400).json({ error: validationError });
  }

  try {
    let result;
    const { section, filters, formData, email, password, payload, submissionId, prompt, mode, name, amount, txid } = req.body;

    switch (action) {
      case 'get_site_section': {
        const { data, error } = await supabase.from('site_sections').select('data').eq('section', section).single();
        if (error) throw error;
        result = data?.data || null;
        break;
      }
      case 'get_all_site_sections': case 'get_all_sections': {
        const { data, error } = await supabase.from('site_sections').select('section, data');
        if (error) throw error;
        result = {};
        (data || []).forEach(row => { result[row.section] = row.data; });
        break;
      }
      case 'get_resources': {
        let q = supabase.from('biology_notes').select('*').order('created_at', { ascending: false }).limit(100);
        if (filters?.level) q = q.eq('level', filters.level);
        if (filters?.category) q = q.eq('category', filters.category);
        if (filters?.tag) q = q.eq('tag', filters.tag);
        const { data, error } = await q;
        if (error) throw error;
        result = data || [];
        break;
      }
      case 'get_filter_options': {
        const [l, c, t] = await Promise.all([
          supabase.from('biology_notes').select('level').limit(500),
          supabase.from('biology_notes').select('category').limit(500),
          supabase.from('biology_notes').select('tag').limit(500)
        ]);
        result = { levels: [...new Set((l.data || []).map(x => x.level).filter(Boolean))], categories: [...new Set((c.data || []).map(x => x.category).filter(Boolean))], tags: [...new Set((t.data || []).map(x => x.tag).filter(Boolean))] };
        break;
      }
      case 'submit_contact': {
        const { error } = await supabase.from('contact_messages').insert({
          name: formData.name.trim().slice(0, 100),
          email: formData.email.trim().slice(0, 254),
          subject: (formData.subject || '').trim().slice(0, 200),
          message: formData.message.trim().slice(0, 5000)
        });
        if (error) throw error;
        result = { success: true };
        break;
      }
      case 'subscribe_newsletter': {
        const { error } = await supabase.from('newsletter_subscribers').insert({ email: formData.email.trim().slice(0, 254) });
        if (error && error.code !== '23505') throw error;
        result = { success: true };
        break;
      }
      case 'submit_resource': {
        const { error } = await supabase.from('resource_submissions').insert({
          title: payload.title.trim().slice(0, 200),
          description: payload.description.trim().slice(0, 5000),
          author: (payload.author || '').trim().slice(0, 100),
          level: (payload.level || '').trim().slice(0, 50),
          category: (payload.category || '').trim().slice(0, 100),
          tag: (payload.tag || '').trim().slice(0, 200),
          file_url: (payload.file_url || '').trim().slice(0, 2048),
          file_size: (payload.file_size || '').trim().slice(0, 50),
          status: 'pending'
        });
        if (error) throw error;
        result = { success: true };
        break;
      }
      case 'signup': {
        const { data, error } = await supabase.auth.signUp({
          email: email.trim().toLowerCase(),
          password,
          options: { emailRedirectTo: `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}` }
        });
        if (error) throw error;
        result = { user: data.user ? { id: data.user.id, email: data.user.email } : null, session: data.session ? { access_token: data.session.access_token } : null };
        break;
      }
      case 'signin': {
        const { data, error } = await supabase.auth.signInWithPassword({ email: email.trim().toLowerCase(), password });
        if (error) throw error;
        result = { user: data.user ? { id: data.user.id, email: data.user.email } : null, session: data.session ? { access_token: data.session.access_token } : null };
        break;
      }
      case 'signout': {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (token) await supabase.auth.signOut(token);
        result = { success: true };
        break;
      }
      case 'get_user': {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token || token.length < 20) { result = { user: null }; break; }
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) { result = { user: null }; break; }
        result = { user: { id: user.id, email: user.email } };
        break;
      }
      case 'stats': {
        const [resCount, subCount, msgCount] = await Promise.all([
          supabase.from('biology_notes').select('id', { count: 'exact', head: true }),
          supabase.from('resource_submissions').select('id', { count: 'exact', head: true }).eq('status', 'pending'),
          supabase.from('contact_messages').select('id', { count: 'exact', head: true })
        ]);
        result = { resources: resCount.count || 0, pendingSubmissions: subCount.count || 0, users: 0, messages: msgCount.count || 0 };
        break;
      }
      case 'submissions': {
        const { data, error } = await supabase.from('resource_submissions').select('id,title,description,author,level,category,tag,status,created_at').order('created_at', { ascending: false }).limit(50);
        if (error) throw error;
        result = data || [];
        break;
      }
      case 'approve': {
        if (!submissionId || !['approve', 'reject'].includes(req.body.action)) throw new Error('Invalid approval request');
        const newStatus = req.body.action === 'approve' ? 'approved' : 'rejected';
        await supabase.from('resource_submissions').update({ status: newStatus }).eq('id', submissionId);
        result = { success: true };
        break;
      }
      case 'messages': {
        const { data, error } = await supabase.from('contact_messages').select('id,name,email,subject,message,created_at').order('created_at', { ascending: false }).limit(50);
        if (error) throw error;
        result = { messages: data || [] };
        break;
      }
      case 'create_payment': {
        result = { payment_id: 'demo_' + Date.now(), pay_address: '0xDEMO', pay_amount: req.body.amount || 10, pay_currency: req.body.pay_currency || 'usdttrc20' };
        break;
      }
      case 'ai_query': {
        const geminiKey = process.env.GEMINI_API_KEY;
        if (!geminiKey) { result = { answer: 'AI features are coming soon. Please configure the API key.' }; break; }
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${geminiKey}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: `You are an expert biology and pharmacy tutor. ${mode === 'quiz' ? 'Generate quiz questions about:' : mode === 'summarize' ? 'Summarize this:' : 'Answer:'} ${prompt}` }] }] })
        });
        const geminiData = await response.json();
        result = { answer: geminiData.candidates?.[0]?.content?.parts?.[0]?.text || 'No response generated.' };
        break;
      }
      case 'get_donate_page_config': {
        result = { nowpayments_api_key: process.env.NOWPAYMENTS_API_KEY || '' };
        break;
      }
      case 'submit_momo_donation': {
        const { error } = await supabase.from('momo_donations').insert({
          name: (name || 'Anonymous').slice(0, 100),
          amount: amount.slice(0, 50),
          txid: txid.slice(0, 100)
        });
        if (error) throw error;
        result = { success: true };
        break;
      }
      default: throw new Error('Unknown action');
    }

    return res.status(200).json({ data: result });
  } catch (error) {
    console.error('POST Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
     }
