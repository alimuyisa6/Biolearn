import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  // --- Verify user token ---
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

  // --- Validate payload ---
  const { title, description, author, level, category, tag, file_url, file_size } = req.body;

  if (!title || typeof title !== 'string' || !title.trim()) {
    return res.status(400).json({ error: 'Title is required.' });
  }
  if (!description || typeof description !== 'string' || !description.trim()) {
    return res.status(400).json({ error: 'Description is required.' });
  }
  if (title.length > 200) return res.status(400).json({ error: 'Title too long (max 200 chars)' });
  if (description.length > 2000) return res.status(400).json({ error: 'Description too long (max 2000 chars)' });
  if (author && author.length > 100) return res.status(400).json({ error: 'Author name too long' });
  if (file_url && !/^https?:\/\//.test(file_url)) {
    return res.status(400).json({ error: 'Invalid file URL (must start with https://)' });
  }

  // --- Insert submission ---
  const { error: insertError } = await supabase
    .from('resource_submissions')
    .insert({
      title: title.trim(),
      description: description.trim(),
      author: author?.trim() || null,
      level: level || null,
      category: category || null,
      tag: tag || null,
      file_url: file_url || null,
      file_size: file_size || null,
      submitted_by: user.id,
      status: 'pending'
    });

  if (insertError) {
    console.error('Submission error:', insertError.message);
    return res.status(500).json({ error: 'Failed to submit resource.' });
  }

  return res.status(201).json({ success: true, message: 'Resource submitted for review.' });
    }
