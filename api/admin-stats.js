import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  // Verify admin (same pattern as admin-submissions)
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = authHeader.split('Bearer ')[1];

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: 'Invalid token' });

  const { data: adminRow } = await supabase.from('admin_users').select('user_id').eq('user_id', user.id).maybeSingle();
  if (!adminRow) return res.status(403).json({ error: 'Forbidden' });

  // Collect counts
  const [{ count: resourceCount }, { count: submissionCount }, { count: userCount }, { count: msgCount }] = await Promise.all([
    supabase.from('biology_notes').select('*', { count: 'exact', head: true }),
    supabase.from('resource_submissions').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
    supabase.from('auth.users').select('*', { count: 'exact', head: true }), // need service_role to query auth
    supabase.from('site_sections').select('*', { count: 'exact', head: true }).eq('section', 'message')
  ]);

  // Note: querying auth.users directly from a function using service_role works because we use createClient with service_role.
  const { count: userCountFinal } = await supabase.from('auth.users').select('*', { count: 'exact', head: true });

  res.status(200).json({
    resources: resourceCount,
    pendingSubmissions: submissionCount,
    users: userCountFinal,
    messages: msgCount
  });
}
