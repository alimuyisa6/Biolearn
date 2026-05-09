process.noDeprecation = true;
import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const action = req.query.action;

  // GET /api/page-data?action=blog
  if (action === 'blog') {
    const { data, error } = await supabase
      .from('site_sections')
      .select('data')
      .eq('section', 'blog')
      .single();
    if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
    return res.status(200).json(data?.data || null);
  }

  // GET /api/page-data?action=about
  if (action === 'about') {
    const { data, error } = await supabase
      .from('site_sections')
      .select('data')
      .eq('section', 'about')
      .single();
    if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
    return res.status(200).json(data?.data || null);
  }

  // GET /api/page-data?action=footer
  if (action === 'footer') {
    const { data, error } = await supabase
      .from('site_sections')
      .select('data')
      .eq('section', 'footer')
      .single();
    if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
    return res.status(200).json(data?.data || null);
  }

  // GET /api/page-data?action=faqs
  if (action === 'faqs') {
    const { data, error } = await supabase
      .from('site_sections')
      .select('data')
      .eq('section', 'faqs')
      .single();
    if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
    return res.status(200).json(data?.data || null);
  }

  // GET /api/page-data?action=guidelines
  if (action === 'guidelines') {
    const { data, error } = await supabase
      .from('site_sections')
      .select('data')
      .eq('section', 'guidelines')
      .single();
    if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
    return res.status(200).json(data?.data || null);
  }

  // GET /api/page-data?action=resources-page
  if (action === 'resources-page') {
    const { data, error } = await supabase
      .from('site_sections')
      .select('data')
      .eq('section', 'resources_page')
      .single();
    if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
    return res.status(200).json(data?.data || null);
  }

  return res.status(400).json({ error: 'Unknown page data action' });
      }
