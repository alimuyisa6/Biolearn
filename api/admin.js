 process.noDeprecation = true;
import { createClient } from '@supabase/supabase-js';

// Rate limiter: 30 admin requests per IP per minute
var rateMap = new Map();
function rateLimit(req, res, max) {
  max = max || 30;
  var ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  var now = Date.now();
  var entry = rateMap.get(ip) || { count: 0, reset: now + 60000 };
  if (now > entry.reset) { entry = { count: 0, reset: now + 60000 }; }
  entry.count++;
  rateMap.set(ip, entry);
  if (entry.count > max) { res.status(429).json({ error: 'Too many requests' }); return false; }
  return true;
}

var ALLOWED_ORIGIN = process.env.VERCEL_URL ? 'https://' + process.env.VERCEL_URL : '*';

async function authenticateAdmin(req, res) {
  var auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) { res.status(401).json({ error: 'Authentication required' }); return null; }
  var token = auth.split('Bearer ')[1];
  if (!token || token.length > 2000) { res.status(401).json({ error: 'Invalid token' }); return null; }
  var supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  var { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) { res.status(401).json({ error: 'Invalid credentials' }); return null; }
  var { data: adminRow } = await supabase.from('admin_users').select('user_id').eq('user_id', user.id).maybeSingle();
  if (!adminRow) { res.status(403).json({ error: 'Admin access required' }); return null; }
  return { user: user, supabase: supabase };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!rateLimit(req, res, 60)) return;

  var auth = await authenticateAdmin(req, res);
  if (!auth) return;

  var action = req.query.action;
  var body = req.body || {};

  // stats
  if (req.method === 'GET' && action === 'stats') {
    try {
      var [{ count: resources }, { count: pending }, { count: messages }] = await Promise.all([
        auth.supabase.from('biology_notes').select('*', { count: 'exact', head: true }),
        auth.supabase.from('resource_submissions').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
        auth.supabase.from('site_sections').select('*', { count: 'exact', head: true }).eq('section', 'message')
      ]);
      var { data: { users }, error: userError } = await auth.supabase.auth.admin.listUsers();
      if (userError) throw userError;
      return res.status(200).json({ resources: resources||0, pendingSubmissions: pending||0, users: (users||[]).length, messages: messages||0 });
    } catch (e) { return res.status(500).json({ error: 'Stats unavailable' }); }
  }

  // submissions
  if (req.method === 'GET' && action === 'submissions') {
    var q = auth.supabase.from('resource_submissions').select('*').order('created_at', { ascending: false });
    if (req.query.status) q = q.eq('status', req.query.status);
    var { data, error } = await q;
    if (error) return res.status(500).json({ error: 'Failed to fetch submissions' });
    return res.status(200).json(data);
  }

  // approve
  if (req.method === 'POST' && action === 'approve') {
    var { submissionId, action: subAction } = body;
    if (!submissionId || !['approve', 'reject'].includes(subAction)) return res.status(400).json({ error: 'Invalid request' });
    var { data: sub } = await auth.supabase.from('resource_submissions').select('*').eq('id', submissionId).single();
    if (!sub || sub.status !== 'pending') return res.status(400).json({ error: 'Cannot process' });
    if (subAction === 'approve') {
      await auth.supabase.from('biology_notes').insert({
        title: sub.title, description: sub.description, author: sub.author,
        level: sub.level, category: sub.category, tag: sub.tag,
        file_url: sub.file_url, file_size: sub.file_size,
        section_type: sub.level ? sub.level + ' Notes' : 'All Resources'
      });
    }
    await auth.supabase.from('resource_submissions').update({ status: subAction === 'approve' ? 'approved' : 'rejected' }).eq('id', submissionId);
    return res.status(200).json({ success: true });
  }

  // upload
  if (req.method === 'POST' && action === 'upload') {
    var { title, description } = body;
    if (!title || !description) return res.status(400).json({ error: 'Title and description required' });
    await auth.supabase.from('biology_notes').insert({
      title: title.trim(), description: description.trim(), author: (body.author||'').trim()||null,
      level: body.level||null, category: body.category||null, tag: body.tag||null,
      file_url: body.file_url||null, file_size: body.file_size||null,
      section_type: body.level ? body.level + ' Notes' : 'All Resources'
    });
    return res.status(201).json({ success: true });
  }

  // users
  if (req.method === 'GET' && action === 'users') {
    var { data: authUsers } = await auth.supabase.auth.admin.listUsers();
    var { data: blocked } = await auth.supabase.from('blocked_users').select('user_id');
    var blockedSet = new Set((blocked||[]).map(function(b){return b.user_id;}));
    return res.status(200).json((authUsers.users||[]).map(function(u){ return { id:u.id, email:u.email, created_at:u.created_at, last_sign_in_at:u.last_sign_in_at, blocked:blockedSet.has(u.id) }; }));
  }

  // block
  if (req.method === 'POST' && action === 'block') {
    var { userId, block } = body;
    if (!userId || typeof block !== 'boolean') return res.status(400).json({ error: 'Invalid' });
    if (block) { await auth.supabase.from('blocked_users').upsert({ user_id: userId }); }
    else { await auth.supabase.from('blocked_users').delete().eq('user_id', userId); }
    return res.status(200).json({ success: true });
  }

  // delete-user
  if (req.method === 'DELETE' && action === 'delete-user') {
    if (!body.userId) return res.status(400).json({ error: 'Missing user ID' });
    await auth.supabase.auth.admin.deleteUser(body.userId);
    await auth.supabase.from('blocked_users').delete().eq('user_id', body.userId);
    return res.status(200).json({ success: true });
  }

  // notify
  if (req.method === 'POST' && action === 'notify') {
    if (!body.message) return res.status(400).json({ error: 'Message required' });
    await auth.supabase.from('notifications').insert({ message: body.message.trim(), sender_id: auth.user.id, recipient_all: !!body.recipient_all });
    return res.status(201).json({ success: true });
  }

  // messages
  if (req.method === 'GET' && action === 'messages') {
    var { data } = await auth.supabase.from('site_sections').select('data, created_at').eq('section', 'message').order('created_at', { ascending: false });
    return res.status(200).json({ messages: (data||[]).map(function(r){ return Object.assign({}, r.data, { created_at: r.created_at }); }) });
  }

  return res.status(400).json({ error: 'Unknown action' });
  }
