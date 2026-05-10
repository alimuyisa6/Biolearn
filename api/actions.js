 process.noDeprecation = true;
import { createClient } from '@supabase/supabase-js';

// Rate limiter
var rateMap = new Map();
function rateLimit(req, res, max) {
  max = max || 10;
  var ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  var now = Date.now();
  var entry = rateMap.get(ip) || { count: 0, reset: now + 60000 };
  if (now > entry.reset) { entry = { count: 0, reset: now + 60000 }; }
  entry.count++;
  rateMap.set(ip, entry);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));
  if (entry.count > max) { res.status(429).json({ error: 'Too many requests. Try again in a minute.' }); return false; }
  return true;
}

var ALLOWED_ORIGIN = process.env.VERCEL_URL ? 'https://' + process.env.VERCEL_URL : '*';

// Authenticate user from Bearer token
async function authenticate(req, res) {
  var auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) { res.status(401).json({ error: 'Authentication required' }); return null; }
  var token = auth.split('Bearer ')[1];
  if (!token || token.length > 2000) { res.status(401).json({ error: 'Invalid token' }); return null; }
  var supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  var { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) { res.status(401).json({ error: 'Invalid or expired token' }); return null; }
  return { user: user, supabase: supabase };
}

// Sanitize string input
function sanitize(str, maxLen) {
  if (typeof str !== 'string') return '';
  str = str.replace(/<[^>]*>/g, '').trim();
  return str.substring(0, maxLen || 2000);
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();

  var action = req.query.action;

  // POST send-message — rate limited: 1 per IP per 24h
  if (req.method === 'POST' && action === 'send-message') {
    if (!rateLimit(req, res, 1)) return; // 1 per window
    var auth = await authenticate(req, res);
    if (!auth) return;

    var message = sanitize(req.body?.message, 2000);
    if (!message) return res.status(400).json({ error: 'Message required' });

    // Check 24h limit per user
    var { data: recent } = await auth.supabase
      .from('site_sections')
      .select('created_at')
      .eq('section', 'message')
      .eq('data->>user_id', auth.user.id)
      .order('created_at', { ascending: false })
      .limit(1);
    if (recent && recent.length) {
      var diff = (Date.now() - new Date(recent[0].created_at).getTime()) / 36e5;
      if (diff < 24) return res.status(429).json({ error: 'One message per 24 hours. Please wait ' + Math.ceil(24 - diff) + ' hours.' });
    }

    var { error } = await auth.supabase.from('site_sections').insert({
      section: 'message',
      data: { user_id: auth.user.id, message: message, created_at: new Date().toISOString() }
    });
    if (error) return res.status(500).json({ error: 'Failed to send message' });
    return res.status(201).json({ success: true });
  }

  // POST submit-resource — rate limited: 5 per IP per minute
  if (req.method === 'POST' && action === 'submit-resource') {
    if (!rateLimit(req, res, 5)) return;
    var auth = await authenticate(req, res);
    if (!auth) return;

    var title = sanitize(req.body?.title, 200);
    var description = sanitize(req.body?.description, 2000);
    if (!title || !description) return res.status(400).json({ error: 'Title and description required' });

    var author = sanitize(req.body?.author, 100);
    var level = ['O-Level', 'A-Level'].indexOf(req.body?.level) !== -1 ? req.body.level : null;
    var category = sanitize(req.body?.category, 100);
    var tag = sanitize(req.body?.tag, 200);
    var fileUrl = sanitize(req.body?.file_url, 500);
    var fileSize = sanitize(req.body?.file_size, 50);

    // Validate URL if provided
    if (fileUrl && !/^https?:\/\//.test(fileUrl)) return res.status(400).json({ error: 'Invalid file URL' });

    var { error } = await auth.supabase.from('resource_submissions').insert({
      title: title, description: description, author: author || null,
      level: level, category: category || null, tag: tag || null,
      file_url: fileUrl || null, file_size: fileSize || null,
      submitted_by: auth.user.id, status: 'pending'
    });
    if (error) return res.status(500).json({ error: 'Submission failed' });
    return res.status(201).json({ success: true });
  }

  // GET get-messages
  if (req.method === 'GET' && action === 'get-messages') {
    var auth = await authenticate(req, res);
    if (!auth) return;

    var isAdmin = false;
    var { data: adminRow } = await auth.supabase.from('admin_users').select('user_id').eq('user_id', auth.user.id).maybeSingle();
    if (adminRow) isAdmin = true;

    var query = auth.supabase.from('site_sections').select('data, created_at').eq('section', 'message').order('created_at', { ascending: false });
    if (!isAdmin) query = query.eq('data->>user_id', auth.user.id);
    var { data, error } = await query;
    if (error) return res.status(500).json({ error: 'Failed to fetch messages' });
    var messages = (data || []).map(function(row) { return Object.assign({}, row.data, { created_at: row.created_at }); });
    return res.status(200).json({ messages: messages, isAdmin: isAdmin });
  }

  return res.status(400).json({ error: 'Unknown action' });
     }
