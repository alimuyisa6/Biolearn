import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  // Verify admin
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = authHeader.split('Bearer ')[1];
  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: 'Invalid token' });

  const { data: adminRow } = await supabase
    .from('admin_users')
    .select('user_id')
    .eq('user_id', user.id)
    .maybeSingle();
  if (!adminRow) return res.status(403).json({ error: 'Forbidden' });

  const action = req.query.action || req.body?.action;

  // GET /api/admin?action=stats
  if (req.method === 'GET' && action === 'stats') {
    const [{ count: resourceCount }, { count: submissionCount }, { count: userCount }, { count: msgCount }] = await Promise.all([
      supabase.from('biology_notes').select('*', { count: 'exact', head: true }),
      supabase.from('resource_submissions').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
      supabase.from('auth.users').select('*', { count: 'exact', head: true }),
      supabase.from('site_sections').select('*', { count: 'exact', head: true }).eq('section', 'message')
    ]);
    return res.status(200).json({ resources: resourceCount, pendingSubmissions: submissionCount, users: userCount, messages: msgCount });
  }

  // GET /api/admin?action=submissions
  if (req.method === 'GET' && action === 'submissions') {
    const statusFilter = req.query.status;
    let query = supabase.from('resource_submissions').select('*').order('created_at', { ascending: false });
    if (statusFilter) query = query.eq('status', statusFilter);
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // POST /api/admin?action=approve
  if (req.method === 'POST' && action === 'approve') {
    const { submissionId, action: subAction } = req.body;
    if (!submissionId || !['approve', 'reject'].includes(subAction))
      return res.status(400).json({ error: 'Invalid request' });

    const { data: submission, error: fetchError } = await supabase
      .from('resource_submissions').select('*').eq('id', submissionId).single();
    if (fetchError || !submission) return res.status(404).json({ error: 'Submission not found' });
    if (submission.status !== 'pending')
      return res.status(400).json({ error: 'Already processed' });

    if (subAction === 'approve') {
      const { error: insertError } = await supabase.from('biology_notes').insert({
        title: submission.title, description: submission.description, author: submission.author,
        level: submission.level, category: submission.category, tag: submission.tag,
        file_url: submission.file_url, file_size: submission.file_size,
        section_type: submission.level ? `${submission.level} Notes` : 'All Resources'
      });
      if (insertError) return res.status(500).json({ error: insertError.message });
    }

    const { error: updateError } = await supabase
      .from('resource_submissions')
      .update({ status: subAction === 'approve' ? 'approved' : 'rejected' })
      .eq('id', submissionId);
    if (updateError) return res.status(500).json({ error: updateError.message });
    return res.status(200).json({ success: true });
  }

  // POST /api/admin?action=upload
  if (req.method === 'POST' && action === 'upload') {
    const { title, description, author, level, category, tag, file_url, file_size } = req.body;
    if (!title?.trim() || !description?.trim())
      return res.status(400).json({ error: 'Title and description required' });
    const { error } = await supabase.from('biology_notes').insert({
      title: title.trim(), description: description.trim(), author: author?.trim() || null,
      level: level || null, category: category || null, tag: tag || null,
      file_url: file_url || null, file_size: file_size || null,
      section_type: level ? `${level} Notes` : 'All Resources'
    });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json({ success: true });
  }

  // GET /api/admin?action=users
  if (req.method === 'GET' && action === 'users') {
    const { data: users, error } = await supabase
      .from('auth.users')
      .select('id, email, created_at, last_sign_in_at');
    if (error) return res.status(500).json({ error: error.message });
    const { data: blocked } = await supabase.from('blocked_users').select('user_id');
    const blockedIds = new Set((blocked || []).map(b => b.user_id));
    const result = (users || []).map(u => ({ ...u, blocked: blockedIds.has(u.id) }));
    return res.status(200).json(result);
  }

  // POST /api/admin?action=block
  if (req.method === 'POST' && action === 'block') {
    const { userId, block } = req.body;
    if (!userId || typeof block !== 'boolean') return res.status(400).json({ error: 'Invalid request' });
    if (block) {
      await supabase.from('blocked_users').upsert({ user_id: userId });
    } else {
      await supabase.from('blocked_users').delete().eq('user_id', userId);
    }
    return res.status(200).json({ success: true });
  }

  // DELETE /api/admin?action=delete-user
  if (req.method === 'DELETE' && action === 'delete-user') {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'Missing user ID' });
    const { error } = await supabase.from('auth.users').delete().eq('id', userId);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  // POST /api/admin?action=notify
  if (req.method === 'POST' && action === 'notify') {
    const { message, recipient_all } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'Message required' });
    await supabase.from('notifications').insert({
      message: message.trim(),
      sender_id: user.id,
      recipient_all: !!recipient_all
    });
    return res.status(201).json({ success: true });
  }

  return res.status(400).json({ error: 'Unknown admin action' });
}
