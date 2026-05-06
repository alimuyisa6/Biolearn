import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).end();
    return;
  }

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const [{ data: levels }, { data: categories }] = await Promise.all([
    supabase.from('biology_notes').select('level', { distinct: true }),
    supabase.from('biology_notes').select('category', { distinct: true })
  ]);

  const levelValues = (levels || []).map(r => r.level).filter(Boolean);
  const categoryValues = (categories || []).map(r => r.category).filter(Boolean);

  res.status(200).json({ levels: levelValues, categories: categoryValues });
}
