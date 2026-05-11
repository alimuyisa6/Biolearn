 // api/query.js - Vercel Serverless Function
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { action, section, filters, formData, email, password } = req.body;
    let result;

    switch (action) {
      // ============ SITE SECTIONS ============
      case 'get_site_section': {
        const { data, error } = await supabase
          .from('site_sections').select('data').eq('section', section).single();
        if (error) throw error;
        result = data?.data || null;
        break;
      }

      case 'get_all_site_sections': {
        const { data, error } = await supabase
          .from('site_sections').select('section, data');
        if (error) throw error;
        result = {};
        (data || []).forEach(row => { result[row.section] = row.data; });
        break;
      }

      // ============ BIOLOGY NOTES ============
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

      // ============ CONTACT FORM ============
      case 'submit_contact': {
        if (!formData || !formData.name || !formData.email || !formData.subject || !formData.message) {
          throw new Error('All fields are required');
        }
        const { error } = await supabase
          .from('contact_messages')
          .insert({
            name: formData.name,
            email: formData.email,
            subject: formData.subject,
            message: formData.message
          });
        if (error) throw error;
        result = { success: true, message: 'Message sent successfully' };
        break;
      }

      // ============ NEWSLETTER ============
      case 'subscribe_newsletter': {
        if (!formData || !formData.email) throw new Error('Email is required');
        const { error } = await supabase
          .from('newsletter_subscribers')
          .insert({ email: formData.email });
        if (error && error.code !== '23505') throw error;
        result = { success: true, message: 'Subscribed successfully' };
        break;
      }

      // ============ AUTH ============
      case 'signup': {
        if (!email || !password) throw new Error('Email and password required');
        const { data, error } = await supabase.auth.signUp({ email, password });
        if (error) throw error;
        result = { user: data.user, session: data.session };
        break;
      }

      case 'signin': {
        if (!email || !password) throw new Error('Email and password required');
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        result = { user: data.user, session: data.session };
        break;
      }

      case 'signout': {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (token) {
          await supabase.auth.signOut(token);
        }
        result = { success: true };
        break;
      }

      case 'get_user': {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) { result = { user: null }; break; }
        const { data, error } = await supabase.auth.getUser(token);
        if (error || !data.user) { result = { user: null }; break; }
        result = { user: { id: data.user.id, email: data.user.email } };
        break;
      }

      default:
        throw new Error(`Unknown action: ${action}`);
    }

    return res.status(200).json({ data: result });
  } catch (error) {
    console.error('API Error:', error.message);
    return res.status(400).json({ error: error.message });
  }
};
