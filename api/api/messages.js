import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).end();
    return;
  }

  // Verify the user is authenticated
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    res.status(401).json({ error: 'Missing token' });
    return;
  }
  const token = authHeader.replace('Bearer ', '');

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) {
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  // Body validation
  const { message } = req.body;
  if (!message || !message.trim() || message.length > 2000) {
    res.status(400).json({ error: 'Invalid message' });
    return;
  }

  // ---- 24‑hour rate limit ----
  const { data: recent } = await supabase
    .from('site_sections')
    .select('data')
    .eq('section', 'message')
    .eq('data->>user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(1);

  if (recent && recent.length > 0) {
    const diff = (Date.now() - new Date(recent[0].data.created_at)) / 36e5;
    if (diff < 24) {
      res.status(429).json({ error: 'You can only send one message per 24 hours.' });
      return;
    }
  }

  // Insert message
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
    res.status(500).json({ error: insertError.message });
    return;
  }

  res.status(201).json({ success: true });
}
