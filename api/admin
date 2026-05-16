import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

const SUPER_ADMIN_EMAIL = 'alimuyisa6@gmail.com';

const json = (res, data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

const auth = async (req) => {
  const token = req.headers.get('authorization')?.split(' ')[1];
  if (!token) return null;

  const { data } = await supabase.auth.getUser(token);
  return data?.user || null;
};

export default async function handler(req) {
  const url = new URL(req.url);
  const path = url.pathname.replace('/api/admin', '');
  const method = req.method;

  const user = await auth(req);
  if (!user && path !== '/check') return json(null, { error: 'Unauthorized' }, 401);

  // ── CHECK ADMIN ──
  if (path === '/check') {
    if (user?.email === SUPER_ADMIN_EMAIL) {
      await supabase.from('admin_master').upsert({
        admin_id: user.id,
        admin_email: user.email,
        admin_role: 'super_admin',
        is_active: true
      });
    }

    const { data: admin } = await supabase
      .from('admin_master')
      .select('*')
      .eq('admin_id', user?.id)
      .maybeSingle();

    return json(null, {
      isAdmin: !!admin,
      role: admin?.admin_role || 'user'
    });
  }

  // ── STATS ──
  if (path === '/stats') {
    const [{ count: notes }, { count: subs }, users] = await Promise.all([
      supabase.from('biology_notes').select('*', { count: 'exact', head: true }),
      supabase.from('resource_submissions').select('*', { count: 'exact', head: true }),
      supabaseAdmin.auth.admin.listUsers()
    ]);

    return json(null, {
      resources: (notes || 0) + (subs || 0),
      users: users.data?.users?.length || 0
    });
  }

  // ── RESOURCES LIST ──
  if (path === '/resources' && method === 'GET') {
    const [a, b] = await Promise.all([
      supabase.from('biology_notes').select('*'),
      supabase.from('resource_submissions').select('*')
    ]);

    return json(null, {
      resources: [
        ...(a.data || []).map(x => ({ ...x, source: 'notes' })),
        ...(b.data || []).map(x => ({ ...x, source: 'submissions' }))
      ]
    });
  }

  // ── UPLOAD ──
  if (path === '/resources/upload' && method === 'POST') {
    const form = await req.formData();
    const file = form.get('file');

    const name = crypto.randomUUID() + '.' + file.name.split('.').pop();
    const pathFile = `resources/${name}`;

    await supabaseAdmin.storage.from('resources').upload(pathFile, file);

    const { data } = supabaseAdmin.storage.from('resources').getPublicUrl(pathFile);

    const insert = await supabase.from('biology_notes').insert({
      title: form.get('title'),
      description: form.get('description'),
      file_url: data.publicUrl,
      category: form.get('category'),
      level: form.get('level')
    }).select().single();

    return json(null, insert);
  }

  // ── USERS ──
  if (path === '/users') {
    const users = await supabaseAdmin.auth.admin.listUsers();
    return json(null, { users: users.data?.users || [] });
  }

  return json(null, { error: 'Not found' }, 404);
}
