const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname.replace('/api/admin', '').replace(/\/$/, '') || '/';
    const method = req.method;
    const body = req.body ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body) : {};
    const token = (req.headers.authorization || '').replace('Bearer ', '');

    // Get user from token
    let user = null;
    if (token) {
      try {
        const { data } = await supabase.auth.getUser(token);
        user = data?.user || null;
      } catch(e) {}
    }

    // Auto-promote your email
    if (user && user.email === 'alimuyisa6@gmail.com') {
      const { data: existing } = await supabase.from('admin_master').select('*').eq('admin_id', user.id).single();
      if (!existing) {
        await supabase.from('admin_master').insert({
          admin_id: user.id, admin_email: user.email,
          admin_role: 'super_admin', permissions: {}, is_active: true
        });
        await supabase.from('admin_users').insert({ user_id: user.id });
      }
    }

    // Check if admin
    let isAdmin = false;
    if (user) {
      const { data: admin } = await supabase.from('admin_master').select('*').eq('admin_id', user.id).eq('is_active', true).single();
      const { data: adminUser } = await supabase.from('admin_users').select('*').eq('user_id', user.id).single();
      isAdmin = !!(admin || adminUser);
    }

    // === PUBLIC ROUTES ===
    if (path === '/test') return res.status(200).json({ ok: true, time: Date.now() });
    if (path === '/check') return res.status(200).json({ isAdmin, email: user?.email || null });

    // === PROTECTED ROUTES ===
    if (!isAdmin) return res.status(401).json({ error: 'Admin access required' });

    // === STATS ===
    if (path === '/stats') {
      const { count: c1 } = await supabase.from('biology_notes').select('*', { count: 'exact', head: true });
      const { data: { users } } = await supabaseAdmin.auth.admin.listUsers();
      return res.status(200).json({ resources: c1 || 0, users: users?.length || 0 });
    }

    // === RESOURCES LIST ===
    if (path === '/resources' && method === 'GET') {
      const { data: notes } = await supabase.from('biology_notes').select('*').order('created_at', { ascending: false });
      const { data: subs } = await supabase.from('resource_submissions').select('*').order('created_at', { ascending: false });
      return res.status(200).json({ resources: [...(notes||[]), ...(subs||[])] });
    }

    // === SINGLE RESOURCE ===
    if (path.startsWith('/resources/') && method === 'GET') {
      const id = path.split('/')[2];
      let { data: r } = await supabase.from('biology_notes').select('*').eq('id', id).single();
      if (!r) { const { data: s } = await supabase.from('resource_submissions').select('*').eq('id', id).single(); r = s; }
      return r ? res.status(200).json({ resource: r }) : res.status(404).json({ error: 'Not found' });
    }

    // === UPDATE RESOURCE ===
    if (path.startsWith('/resources/') && method === 'PUT') {
      const id = path.split('/')[2];
      let { error } = await supabase.from('biology_notes').update(body).eq('id', id);
      if (error) { const { error: e2 } = await supabase.from('resource_submissions').update(body).eq('id', id); if (e2) throw e2; }
      return res.status(200).json({ success: true });
    }

    // === DELETE RESOURCE ===
    if (path.startsWith('/resources/') && method === 'DELETE') {
      const id = path.split('/')[2];
      let { error } = await supabase.from('biology_notes').delete().eq('id', id);
      if (error) { const { error: e2 } = await supabase.from('resource_submissions').delete().eq('id', id); if (e2) throw e2; }
      return res.status(200).json({ success: true });
    }

    // === UPLOAD ===
    if (path === '/resources/upload' && method === 'POST') {
      const { data: r, error } = await supabase.from('biology_notes').insert({
        title: body.title, description: body.description,
        file_url: body.file_url, file_size: body.file_size || 'Unknown',
        category: body.category, level: body.level,
        tag: body.tags || '', author: user.email
      }).select().single();
      if (error) throw error;
      return res.status(200).json({ success: true, resource: r });
    }

    // === SITE SECTIONS ===
    if (path === '/site-sections' && method === 'GET') {
      const { data: sections } = await supabase.from('site_sections').select('*');
      return res.status(200).json({ sections });
    }

    if (path.startsWith('/site-sections/') && method === 'PUT') {
      const section = path.split('/')[2];
      const { data: existing } = await supabase.from('site_sections').select('id').eq('section', section).single();
      if (existing) await supabase.from('site_sections').update({ data: body }).eq('section', section);
      else await supabase.from('site_sections').insert({ section, data: body });
      return res.status(200).json({ success: true });
    }

    // === USERS ===
    if (path === '/users' && method === 'GET') {
      const { data: { users } } = await supabaseAdmin.auth.admin.listUsers();
      return res.status(200).json({ users: users.map(u => ({ id: u.id, email: u.email })) });
    }

    if (path.startsWith('/users/') && path.endsWith('/make-admin')) {
      await supabase.from('admin_users').insert({ user_id: path.split('/')[2] });
      return res.status(200).json({ success: true });
    }

    if (path.startsWith('/users/') && path.endsWith('/lock')) {
      await supabase.from('admin_master').update({ is_locked: body.lock }).eq('admin_id', path.split('/')[2]);
      return res.status(200).json({ success: true });
    }

    return res.status(404).json({ error: 'Route not found', path });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
