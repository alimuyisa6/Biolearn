import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).end();
  }

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const [{ data: levels }, { data: categories }] = await Promise.all([
    supabase.from('biology_notes').select('level', { distinct: true }),
    supabase.from('biology_notes').select('category', { distinct: true })
  ]);

  return res.status(200).json({
    levels: (levels || []).map(r => r.level).filter(Boolean),
    categories: (categories || []).map(r => r.category).filter(Boolean)
  });
}
