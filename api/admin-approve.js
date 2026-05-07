import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = authHeader.split('Bearer ')[1];

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: 'Invalid token' });

  const { data: adminRow } = await supabase.from('admin_users').select('user_id').eq('user_id', user.id).maybeSingle();
  if (!adminRow) return res.status(403).json({ error: 'Forbidden' });

  const { submissionId, action } = req.body;
  if (!submissionId || !['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'Invalid request' });

  const { data: submission, error: fetchError } = await supabase.from('resource_submissions').select('*').eq('id', submissionId).single();
  if (fetchError || !submission) return res.status(404).json({ error: 'Submission not found' });
  if (submission.status !== 'pending') return res.status(400).json({ error: 'Submission already processed' });

  if (action === 'approve') {
    const { error: insertError } = await supabase.from('biology_notes').insert({
      title: submission.title,
      description: submission.description,
      author: submission.author,
      level: submission.level,
      category: submission.category,
      tag: submission.tag,
      file_url: submission.file_url,
      file_size: submission.file_size,
      section_type: submission.level ? `${submission.level} Notes` : 'All Resources'
    });
    if (insertError) return res.status(500).json({ error: insertError.message });
  }
  const { error: updateError } = await supabase.from('resource_submissions').update({ status: action === 'approve' ? 'approved' : 'rejected' }).eq('id', submissionId);
  if (updateError) return res.status(500).json({ error: updateError.message });
  res.status(200).json({ success: true });
}
