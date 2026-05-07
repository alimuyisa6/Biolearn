import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }
  const token = authHeader.split('Bearer ')[1];

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  // Verify JWT
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: 'Invalid token' });

  // Check admin status
  const { data: adminRow } = await supabase
    .from('admin_users')
    .select('user_id')
    .eq('user_id', user.id)
    .maybeSingle();

  const isAdmin = !!adminRow;

  // Query messages
  let query = supabase
    .from('site_sections')
    .select('data, created_at')
    .eq('section', 'message')
    .order('created_at', { ascending: false });

  if (!isAdmin) {
    query = query.eq('data->>user_id', user.id);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  const messages = (data || []).map(row => ({
    ...row.data,
    created_at: row.created_at
  }));

  res.status(200).json({ messages, isAdmin });
}
