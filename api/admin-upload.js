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

  const { title, description, author, level, category, tag, file_url, file_size } = req.body;
  if (!title?.trim() || !description?.trim()) return res.status(400).json({ error: 'Title and description required' });

  const { error: insertError } = await supabase.from('biology_notes').insert({
    title: title.trim(),
    description: description.trim(),
    author: author?.trim() || null,
    level: level || null,
    category: category || null,
    tag: tag || null,
    file_url: file_url || null,
    file_size: file_size || null,
    section_type: level ? `${level} Notes` : 'All Resources'
  });

  if (insertError) return res.status(500).json({ error: insertError.message });
  res.status(201).json({ success: true });
}
