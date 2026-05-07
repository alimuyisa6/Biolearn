import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'DELETE') return res.status(405).end();

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = authHeader.split('Bearer ')[1];

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: 'Invalid token' });

  const { data: adminRow } = await supabase.from('admin_users').select('user_id').eq('user_id', user.id).maybeSingle();
  if (!adminRow) return res.status(403).json({ error: 'Forbidden' });

  const { id, table } = req.body; // table = 'biology_notes' or 'resource_submissions'
  if (!id || !['biology_notes', 'resource_submissions'].includes(table)) return res.status(400).json({ error: 'Invalid request' });

  const { error } = await supabase.from(table).delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.status(200).json({ success: true });
}
