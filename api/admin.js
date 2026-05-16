 // /api/admin.js - Vercel serverless function
const express = require('express');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

const SUPER_ADMIN_EMAIL = 'alimuyisa6@gmail.com';

const FULL_PERMISSIONS = {
    can_manage_users: true,
    can_manage_resources: true,
    can_manage_site_sections: true,
    can_view_analytics: true,
    can_manage_admins: true,
    can_delete_items: true,
    can_upload_files: true
};

// Middleware
app.use(express.json());

async function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) throw new Error('Invalid token');
        
        const { data: admin } = await supabase.from('admin_master').select('*').eq('admin_id', user.id).eq('is_active', true).single();
        const { data: adminUser } = await supabase.from('admin_users').select('*').eq('user_id', user.id).single();
        
        if (!admin && !adminUser) return res.status(403).json({ error: 'Admin access required' });
        if (admin && admin.is_locked) return res.status(403).json({ error: 'Account locked' });
        
        req.adminId = user.id;
        req.adminEmail = user.email;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ═══ ROUTES ═══

// Test endpoint
app.get('/api/admin/test', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
});

// Check admin status
app.get('/api/admin/check', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.json({ isAdmin: false });
    try {
        const token = authHeader.split(' ')[1];
        const { data: { user } } = await supabase.auth.getUser(token);
        if (!user) return res.json({ isAdmin: false });
        
        if (user.email === SUPER_ADMIN_EMAIL) {
            const { data: existing } = await supabase.from('admin_master').select('*').eq('admin_id', user.id).single();
            if (!existing) {
                await supabase.from('admin_master').insert({
                    admin_id: user.id, admin_email: user.email,
                    admin_role: 'super_admin', permissions: FULL_PERMISSIONS, is_active: true
                });
                await supabase.from('admin_users').insert({ user_id: user.id });
            }
        }
        
        const { data: admin } = await supabase.from('admin_master').select('*').eq('admin_id', user.id).single();
        const { data: adminUser } = await supabase.from('admin_users').select('*').eq('user_id', user.id).single();
        
        res.json({ isAdmin: !!(admin || adminUser), role: admin?.admin_role || 'admin', email: user.email });
    } catch (err) {
        res.json({ isAdmin: false });
    }
});

// Dashboard stats
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const { count: notesCount } = await supabase.from('biology_notes').select('*', { count: 'exact', head: true });
        const { count: subCount } = await supabase.from('resource_submissions').select('*', { count: 'exact', head: true }).eq('status', 'approved');
        const { data: { users } } = await supabaseAdmin.auth.admin.listUsers();
        res.json({ resources: (notesCount || 0) + (subCount || 0), users: users?.length || 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all resources
app.get('/api/admin/resources', verifyAdmin, async (req, res) => {
    try {
        const { data: notes } = await supabase.from('biology_notes').select('*').order('created_at', { ascending: false });
        const { data: submissions } = await supabase.from('resource_submissions').select('*').order('created_at', { ascending: false });
        const resources = [
            ...(notes || []).map(n => ({ ...n, source: 'biology_notes' })),
            ...(submissions || []).map(s => ({ ...s, source: 'resource_submissions' }))
        ];
        res.json({ resources });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get single resource
app.get('/api/admin/resources/:id', verifyAdmin, async (req, res) => {
    try {
        let { data: resource } = await supabase.from('biology_notes').select('*').eq('id', req.params.id).single();
        if (!resource) {
            const { data: sub } = await supabase.from('resource_submissions').select('*').eq('id', req.params.id).single();
            resource = sub;
        }
        if (!resource) return res.status(404).json({ error: 'Not found' });
        res.json({ resource });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Upload resource
app.post('/api/admin/resources/upload', verifyAdmin, upload.single('file'), async (req, res) => {
    const { title, description, category, level, tags } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    try {
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${crypto.randomBytes(16).toString('hex')}.${fileExt}`;
        const filePath = `resources/${fileName}`;
        
        const { error: uploadError } = await supabaseAdmin.storage.from('resources').upload(filePath, file.buffer, {
            contentType: file.mimetype, cacheControl: '3600'
        });
        if (uploadError) throw uploadError;
        
        const { data: { publicUrl } } = supabaseAdmin.storage.from('resources').getPublicUrl(filePath);
        
        const { data: resource, error: dbError } = await supabase.from('biology_notes').insert({
            title, description, file_url: publicUrl,
            file_size: `${(file.size / 1024 / 1024).toFixed(2)} MB`,
            category, level, tag: tags || '', author: req.adminEmail
        }).select().single();
        
        if (dbError) throw dbError;
        res.json({ success: true, resource });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update resource
app.put('/api/admin/resources/:id', verifyAdmin, async (req, res) => {
    try {
        let { error } = await supabase.from('biology_notes').update(req.body).eq('id', req.params.id);
        if (error) {
            const { error: subError } = await supabase.from('resource_submissions').update(req.body).eq('id', req.params.id);
            if (subError) throw subError;
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete resource
app.delete('/api/admin/resources/:id', verifyAdmin, async (req, res) => {
    try {
        let { error } = await supabase.from('biology_notes').delete().eq('id', req.params.id);
        if (error) {
            const { error: subError } = await supabase.from('resource_submissions').delete().eq('id', req.params.id);
            if (subError) throw subError;
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Approve submission
app.post('/api/admin/resources/:id/approve', verifyAdmin, async (req, res) => {
    try {
        const { data: sub } = await supabase.from('resource_submissions').select('*').eq('id', req.params.id).single();
        if (!sub) throw new Error('Not found');
        
        await supabase.from('biology_notes').insert({
            title: sub.title, description: sub.description,
            file_url: sub.file_url, file_size: sub.file_size,
            category: sub.category, level: sub.level,
            tag: sub.tag, author: sub.author
        });
        await supabase.from('resource_submissions').update({ status: 'approved' }).eq('id', req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Site sections
app.get('/api/admin/site-sections', verifyAdmin, async (req, res) => {
    try {
        const { data: sections } = await supabase.from('site_sections').select('*').order('created_at', { ascending: false });
        res.json({ sections });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/site-sections/:section', verifyAdmin, async (req, res) => {
    try {
        const { data: existing } = await supabase.from('site_sections').select('id').eq('section', req.params.section).single();
        let result;
        if (existing) {
            result = await supabase.from('site_sections').update({ data: req.body }).eq('section', req.params.section).select();
        } else {
            result = await supabase.from('site_sections').insert({ section: req.params.section, data: req.body }).select();
        }
        if (result.error) throw result.error;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Users
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const { data: { users } } = await supabaseAdmin.auth.admin.listUsers();
        const { data: admins } = await supabase.from('admin_master').select('*');
        const { data: adminUsers } = await supabase.from('admin_users').select('*');
        
        const usersWithRoles = users.map(user => ({
            id: user.id, email: user.email,
            created_at: user.created_at, last_sign_in: user.last_sign_in_at,
            admin_role: admins?.find(a => a.admin_id === user.id)?.admin_role || (adminUsers?.find(a => a.user_id === user.id) ? 'admin' : 'user'),
            is_admin: !!(admins?.find(a => a.admin_id === user.id) || adminUsers?.find(a => a.user_id === user.id)),
            is_locked: admins?.find(a => a.admin_id === user.id)?.is_locked || false
        }));
        res.json({ users: usersWithRoles });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/users/:user_id/make-admin', verifyAdmin, async (req, res) => {
    try {
        await supabase.from('admin_users').insert({ user_id: req.params.user_id });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/users/:user_id/lock', verifyAdmin, async (req, res) => {
    try {
        await supabase.from('admin_master').update({
            is_locked: req.body.lock,
            lock_reason: req.body.lock ? req.body.reason : null
        }).eq('admin_id', req.params.user_id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Export for Vercel
module.exports = app;
