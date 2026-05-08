import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const action = req.query.action;

  // GET /api/data?action=site-sections
  if (action === 'site-sections') {
    const { data, error } = await supabase
      .from('site_sections')
      .select('section, data');
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // GET /api/data?action=resources&level=…&category=…&tag=…
  if (action === 'resources') {
    let query = supabase.from('biology_notes').select('*');
    const { level, category, tag } = req.query;
    if (level) query = query.eq('level', level);
    if (category) query = query.eq('category', category);
    if (tag) query = query.eq('tag', tag);
    query = query.limit(1000);
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // GET /api/data?action=filter-options
  if (action === 'filter-options') {
    const [{ data: levels }, { data: categories }] = await Promise.all([
      supabase.from('biology_notes').select('level', { distinct: true }),
      supabase.from('biology_notes').select('category', { distinct: true })
    ]);
    return res.status(200).json({
      levels: (levels || []).map(r => r.level).filter(Boolean),
      categories: (categories || []).map(r => r.category).filter(Boolean)
    });
  }

  // GET /api/data?action=note&id=…
  if (action === 'note') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Missing note id' });
    const { data, error } = await supabase
      .from('biology_notes')
      .select('*')
      .eq('id', id)
      .single();
    if (error) return res.status(404).json({ error: 'Note not found' });
    return res.status(200).json(data);
  }

  return res.status(400).json({ error: 'Unknown data action' });
}
