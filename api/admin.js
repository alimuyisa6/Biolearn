 const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Supabase clients
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );

  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname.replace('/api/admin', '').replace(/\/$/, '') || '/';
  const method = req.method;

  const body =
    req.body && typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};

  const token = (req.headers.authorization || '').replace('Bearer ', '');

  // ───── Auth user ─────
  let user = null;
  if (token) {
    const { data } = await supabase.auth.getUser(token);
    user = data?.user || null;
  }

  // ───── Admin record fetch ─────
  let admin = null;

  if (user) {
    const { data } = await supabase
      .from('admin_master')
      .select('*')
      .eq('admin_id', user.id)
      .eq('is_active', true)
      .single();

    admin = data || null;
  }

  const isAdmin = !!admin;

  // ───── Auto promote (safe bootstrap only) ─────
  if (user && user.email === 'alimuyisa6@gmail.com' && !admin) {
    await supabase.from('admin_master').insert({
      admin_id: user.id,
      admin_email: user.email,
      admin_role: 'super_admin',
      permissions: {
        can_manage_users: true,
        can_manage_resources: true,
        can_manage_site_sections: true,
        can_view_analytics: true,
        can_manage_admins: true,
        can_delete_items: true,
        can_upload_files: true
      },
      is_active: true,
      login_count: 0
    });
  }

  // ───── Public endpoints ─────
  if (path === '/test') return res.json({ ok: true });

  if (path === '/check') {
    return res.json({
      isAdmin,
      email: user?.email || null,
      role: admin?.admin_role || null,
      permissions: admin?.permissions || {}
    });
  }

  // ───── Block non-admins ─────
  if (!isAdmin) {
    return res.status(401).json({ error: 'Admin access required' });
  }

  // ───── Update admin stats ─────
  await supabase
    .from('admin_master')
    .update({
      last_login: new Date().toISOString(),
      login_count: (admin.login_count || 0) + 1,
      last_action_at: new Date().toISOString()
    })
    .eq('admin_id', user.id);

  // ───── Stats ─────
  if (path === '/stats') {
    const { count: resources } = await supabase
      .from('biology_notes')
      .select('*', { count: 'exact', head: true });

    const { data: usersList } = await supabase.auth.admin.listUsers();

    return res.json({
      resources: resources || 0,
      users: usersList?.users?.length || 0
    });
  }

  // ───── Resources list ─────
  if (path === '/resources' && method === 'GET') {
    const { data: notes } = await supabase
      .from('biology_notes')
      .select('*')
      .order('created_at', { ascending: false });

    const { data: subs } = await supabase
      .from('resource_submissions')
      .select('*')
      .order('created_at', { ascending: false });

    return res.json({
      resources: [...(notes || []), ...(subs || [])]
    });
  }

  // ───── Single resource ─────
  if (path.startsWith('/resources/') && method === 'GET') {
    const id = path.split('/')[2];

    let { data } = await supabase
      .from('biology_notes')
      .select('*')
      .eq('id', id)
      .single();

    if (!data) {
      const { data: sub } = await supabase
        .from('resource_submissions')
        .select('*')
        .eq('id', id)
        .single();

      data = sub;
    }

    return res.json({ resource: data || null });
  }

  // ───── Update resource ─────
  if (path.startsWith('/resources/') && method === 'PUT') {
    const id = path.split('/')[2];

    await supabase.from('biology_notes').update(body).eq('id', id);
    await supabase.from('resource_submissions').update(body).eq('id', id);

    return res.json({ success: true });
  }

  // ───── Delete resource ─────
  if (path.startsWith('/resources/') && method === 'DELETE') {
    const id = path.split('/')[2];

    await supabase.from('biology_notes').delete().eq('id', id);
    await supabase.from('resource_submissions').delete().eq('id', id);

    return res.json({ success: true });
  }

  // ───── Site sections ─────
  if (path === '/site-sections' && method === 'GET') {
    const { data } = await supabase.from('site_sections').select('*');
    return res.json({ sections: data || [] });
  }

  if (path.startsWith('/site-sections/') && method === 'PUT') {
    const section = path.split('/')[2];

    const { data: existing } = await supabase
      .from('site_sections')
      .select('id')
      .eq('section', section)
      .single();

    if (existing) {
      await supabase
        .from('site_sections')
        .update({
          data: body,
          updated_at: new Date().toISOString()
        })
        .eq('section', section);
    } else {
      await supabase.from('site_sections').insert({
        section,
        data: body
      });
    }

    return res.json({ success: true });
  }

  // ───── Users list with admin mapping ─────
  if (path === '/users' && method === 'GET') {
    const { data } = await supabase.auth.admin.listUsers();
    const { data: admins } = await supabase.from('admin_master').select('*');

    const map = new Map((admins || []).map(a => [a.admin_id, a]));

    return res.json({
      users: (data?.users || []).map(u => {
        const a = map.get(u.id);

        return {
          id: u.id,
          email: u.email,
          admin_role: a?.admin_role || null,
          permissions: a?.permissions || {},
          is_admin: !!a,
          is_locked: a?.is_locked || false
        };
      })
    });
  }

  // ───── Promote user to admin ─────
  if (path.startsWith('/users/') && path.endsWith('/make-admin')) {
    const userId = path.split('/')[2];

    await supabase.from('admin_master').upsert({
      admin_id: userId,
      admin_email: body.email || null,
      admin_role: body.role || 'content_manager',
      is_active: true
    });

    return res.json({ success: true });
  }

  // ───── Lock admin ─────
  if (path.startsWith('/users/') && path.endsWith('/lock')) {
    const userId = path.split('/')[2];

    await supabase
      .from('admin_master')
      .update({
        is_locked: body.lock,
        lock_reason: body.reason || null
      })
      .eq('admin_id', userId);

    return res.json({ success: true });
  }

  return res.status(404).json({ error: 'Route not found' });
};
