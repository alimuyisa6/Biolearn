// api/query.js
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { action, section, filters, formData } = req.body;
    let result;

    switch (action) {
      case 'get_all_site_sections': {
        const { data, error } = await supabase.from('site_sections').select('section, data');
        if (error) throw error;
        result = {};
        (data || []).forEach(row => { result[row.section] = row.data; });
        break;
      }
      case 'get_resources': {
        let query = supabase.from('biology_notes').select('*').order('created_at', { ascending: false });
        if (filters?.level) query = query.eq('level', filters.level);
        if (filters?.category) query = query.eq('category', filters.category);
        if (filters?.tag) query = query.eq('tag', filters.tag);
        const { data, error } = await query;
        if (error) throw error;
        result = data || [];
        break;
      }
      case 'get_filter_options': {
        const [l, c, t] = await Promise.all([
          supabase.from('biology_notes').select('level'),
          supabase.from('biology_notes').select('category'),
          supabase.from('biology_notes').select('tag')
        ]);
        result = {
          levels: [...new Set((l.data || []).map(x => x.level).filter(Boolean))],
          categories: [...new Set((c.data || []).map(x => x.category).filter(Boolean))],
          tags: [...new Set((t.data || []).map(x => x.tag).filter(Boolean))]
        };
        break;
      }
      case 'submit_contact': {
        const { error } = await supabase.from('contact_messages').insert(formData);
        if (error) throw error;
        result = { success: true };
        break;
      }
      case 'subscribe_newsletter': {
        const { error } = await supabase.from('newsletter_subscribers').insert({ email: formData.email });
        if (error && error.code !== '23505') throw error;
        result = { success: true };
        break;
      }
      default:
        throw new Error(`Unknown action: ${action}`);
    }

    return res.status(200).json({ data: result });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
};
