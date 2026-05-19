const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Cache-Control', 'no-store, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pageId = url.searchParams.get('page_id') || 'all';

  try {
    let query = supabase.from('app_features').select('*').eq('is_enabled', true);
    if (pageId !== 'all') query = query.eq('page_id', pageId);
    query = query.order('display_order');

    const { data, error } = await query;
    if (error) throw error;
    if (!data || data.length === 0) return res.status(200).json([]);

    const token = req.headers.authorization?.replace('Bearer ', '');
    let userId = null;

    if (token && pageId === 'quiz') {
      const crypto = require('crypto');
      const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');
      const hashedToken = hashToken(token);
      const { data: session } = await supabase.from('user_sessions').select('user_id').eq('session_token_hash', hashedToken).eq('is_active', true).maybeSingle();
      if (session) userId = session.user_id;
    }

    if (pageId === 'quiz' && userId) {
      const { data: userSettings } = await supabase.from('user_feature_settings').select('feature_key, is_enabled, custom_settings').eq('user_id', userId);
      const userMap = new Map();
      (userSettings || []).forEach(s => userMap.set(s.feature_key, s));

      const result = data.map(feature => {
        const override = userMap.get(feature.feature_key);
        return {
          feature_key: feature.feature_key,
          feature_name: feature.feature_name,
          description: feature.description,
          page_id: feature.page_id,
          category: feature.category,
          settings: feature.settings,
          is_enabled: feature.is_enabled,
          display_order: feature.display_order,
          user_enabled: override ? override.is_enabled : true,
          user_settings: override ? (override.custom_settings || {}) : {}
        };
      });
      return res.status(200).json(result);
    }

    const result = data.map(f => ({
      feature_key: f.feature_key,
      feature_name: f.feature_name,
      description: f.description,
      page_id: f.page_id,
      category: f.category,
      settings: f.settings,
      is_enabled: f.is_enabled,
      display_order: f.display_order,
      user_enabled: true,
      user_settings: {}
    }));
    return res.status(200).json(result);

  } catch (error) {
    console.error('App Features Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
};
