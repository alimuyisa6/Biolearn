import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }
  const token = authHeader.split('Bearer ')[1];

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: 'Invalid token' });

  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'Message required' });
  if (message.length > 2000) return res.status(400).json({ error: 'Too long' });

  const { data: recent } = await supabase
    .from('site_sections')
    .select('data')
    .eq('section', 'message')
    .eq('data->>user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(1);

  if (recent?.length) {
    const diff = (Date.now() - new Date(recent[0].data.created_at)) / 36e5;
    if (diff < 24) return res.status(429).json({ error: 'Rate limited' });
  }

  const { error: insertError } = await supabase
    .from('site_sections')
    .insert({
      section: 'message',
      data: { user_id: user.id, message: message.trim(), created_at: new Date().toISOString() }
    });

  if (insertError) return res.status(500).json({ error: insertError.message });

  res.status(201).json({ success: true });
    }
