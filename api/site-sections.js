import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const { data, error } = await supabase
    .from('site_sections')
    .select('section, data');

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.status(200).json(data);
}
