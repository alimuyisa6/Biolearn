 import { createClient } from '@supabase/supabase-js';

async function getUser(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return null;
  const token = authHeader.split('Bearer ')[1];
  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return null;
  return { user, supabase };
}

export default async function handler(req, res) {
  const action = req.query.action;

  // POST /api/actions?action=send-message
  if (req.method === 'POST' && action === 'send-message') {
    const auth = await getUser(req);
    if (!auth) return res.status(401).json({ error: 'Invalid token' });
    const { user, supabase } = auth;

    const { message } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'Message required' });
    if (message.length > 2000) return res.status(400).json({ error: 'Message too long' });

    // Rate limit (24h)
    const { data: recent } = await supabase
      .from('site_sections')
      .select('data')
      .eq('section', 'message')
      .eq('data->>user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(1);
    if (recent?.length) {
      const diff = (Date.now() - new Date(recent[0].data.created_at)) / 36e5;
      if (diff < 24) return res.status(429).json({ error: 'Rate limited' });
    }

    const { error } = await supabase.from('site_sections').insert({
      section: 'message',
      data: { user_id: user.id, message: message.trim(), created_at: new Date().toISOString() }
    });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json({ success: true });
  }

  // POST /api/actions?action=submit-resource
  if (req.method === 'POST' && action === 'submit-resource') {
    const auth = await getUser(req);
    if (!auth) return res.status(401).json({ error: 'Invalid token' });
    const { user, supabase } = auth;

    const { title, description, author, level, category, tag, file_url, file_size } = req.body;
    if (!title?.trim() || !description?.trim()) return res.status(400).json({ error: 'Title and description required' });
    if (file_url && !/^https?:\/\//.test(file_url)) return res.status(400).json({ error: 'Invalid file URL' });

    const { error } = await supabase.from('resource_submissions').insert({
      title: title.trim(), description: description.trim(), author: author?.trim() || null,
      level: level || null, category: category || null, tag: tag || null,
      file_url: file_url || null, file_size: file_size || null,
      submitted_by: user.id, status: 'pending'
    });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json({ success: true });
  }

  // GET /api/actions?action=get-messages
  if (req.method === 'GET' && action === 'get-messages') {
    const auth = await getUser(req);
    if (!auth) return res.status(401).json({ error: 'Invalid token' });
    const { user, supabase } = auth;

    const { data: adminRow } = await supabase
      .from('admin_users')
      .select('user_id')
      .eq('user_id', user.id)
      .maybeSingle();
    const isAdmin = !!adminRow;

    let query = supabase
      .from('site_sections')
      .select('data, created_at')
      .eq('section', 'message')
      .order('created_at', { ascending: false });

    if (!isAdmin) query = query.eq('data->>user_id', user.id);

    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    const messages = (data || []).map(row => ({ ...row.data, created_at: row.created_at }));
    return res.status(200).json({ messages, isAdmin });
  }

  return res.status(400).json({ error: 'Unknown action' });
}
