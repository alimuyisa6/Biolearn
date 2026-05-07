import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).end();
  }

  // --- Verify user token ---
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }
  const token = authHeader.split('Bearer ')[1];

  // Admin client for all DB operations
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  // Validate JWT and get user
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  // --- Validate payload ---
  const { message } = req.body;
  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'Message cannot be empty' });
  }
  if (message.length > 2000) {
    return res.status(400).json({ error: 'Message too long (max 2000 characters)' });
  }

  // --- 24‑hour rate limit ---
  const { data: recent } = await supabase
    .from('site_sections')
    .select('data')
    .eq('section', 'message')
    .eq('data->>user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(1);

  if (recent && recent.length > 0) {
    const lastCreated = new Date(recent[0].data.created_at);
    const diffHours = (Date.now() - lastCreated.getTime()) / (1000 * 60 * 60);
    if (diffHours < 24) {
      return res.status(429).json({ error: 'You can only send one message per 24 hours.' });
    }
  }

  // --- Insert message ---
  const { error: insertError } = await supabase
    .from('site_sections')
    .insert({
      section: 'message',
      data: {
        user_id: user.id,
        message: message.trim(),
        created_at: new Date().toISOString()
      }
    });

  if (insertError) {
    console.error('message insert error:', insertError.message);
    return res.status(500).json({ error: insertError.message });
  }

  return res.status(201).json({ success: true });
}
