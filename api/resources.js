import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  // Only allow GET requests
  if (req.method !== 'GET') {
    res.status(405).end();
    return;
  }

  // Create a Supabase client using the secret service role key
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  let query = supabase.from('biology_notes').select('*');

  // Apply filter query parameters (same names as frontend)
  const { level, category, tag } = req.query;
  if (level) query = query.eq('level', level);
  if (category) query = query.eq('category', category);
  if (tag) query = query.eq('tag', tag);

  query = query.limit(1000); // safety cap

  const { data, error } = await query;
  if (error) {
    res.status(500).json({ error: error.message });
    return;
  }

  res.status(200).json(data);
}
