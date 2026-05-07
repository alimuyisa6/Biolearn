import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  let query = supabase.from('biology_notes').select('*');
  const { level, category, tag } = req.query;
  if (level) query = query.eq('level', level);
  if (category) query = query.eq('category', category);
  if (tag) query = query.eq('tag', tag);
  query = query.limit(1000);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  res.status(200).json(data);
}
