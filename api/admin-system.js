 // admin-system.js - Matches actual database structure
const express = require('express');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// ═══════════════════════════════════
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

// ============ AUTH MIDDLEWARE ============
async function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const token = authHeader.split(' ')[1];
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) throw new Error('Invalid token');
        
        // Check admin_master
        const { data: admin } = await supabase
            .from('admin_master')
            .select('*')
            .eq('admin_id', user.id)
            .eq('is_active', true)
            .single();
        
        // Also check admin_users as fallback
        const { data: adminUser } = await supabase
            .from('admin_users')
            .select('*')
            .eq('user_id', user.id)
            .single();
        
        if (!admin && !adminUser) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        if (admin && admin.is_locked) {
            return res.status(403).json({ error: 'Account locked' });
        }
        
        req.adminId = user.id;
        req.adminEmail = user.email;
        req.adminRole = admin?.admin_role || 'admin';
        req.adminPermissions = admin?.permissions || FULL_PERMISSIONS;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ============ LOGIN ============
router.post('/admin/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const { data: auth, error: authError } = await supabase.auth.signInWithPassword({ email, password });
        if (authError) throw authError;
        
        const userId = auth.user.id;
        
        // Auto-promote super admin
        if (email === SUPER_ADMIN_EMAIL) {
            const { data: existing } = await supabase
                .from('admin_master')
                .select('*')
                .eq('admin_id', userId)
                .single();
            
            if (!existing) {
                await supabase.from('admin_master').insert({
                    admin_id: userId,
                    admin_email: email,
                    admin_role: 'super_admin',
                    permissions: FULL_PERMISSIONS,
                    is_active: true,
                    login_count: 0
                });
                await supabase.from('admin_users').insert({ user_id: userId });
            }
        }
        
        // Check if admin
        const { data: admin } = await supabase
            .from('admin_master')
            .select('*')
            .eq('admin_id', userId)
            .eq('is_active', true)
            .single();
        
        const { data: adminUser } = await supabase
            .from('admin_users')
            .select('*')
            .eq('user_id', userId)
            .single();
        
        if (!admin && !adminUser) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        // Update login
        if (admin) {
            await supabase.from('admin_master')
                .update({ last_login: new Date().toISOString(), login_count: (admin.login_count || 0) + 1 })
                .eq('admin_id', userId);
        }
        
        res.json({
            success: true,
            token: auth.session.access_token,
            admin: { role: admin?.admin_role || 'admin', email }
        });
        
    } catch (err) {
        res.status(401).json({ error: err.message });
    }
});

// ============ DASHBOARD STATS ============
router.get('/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const { count: resourcesCount } = await supabase
            .from('biology_notes')
            .select('*', { count: 'exact', head: true });
        
        const { count: submissionsCount } = await supabase
            .from('resource_submissions')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'approved');
        
        const { data: { users } } = await supabaseAdmin.auth.admin.listUsers();
        
        res.json({
            resources: (resourcesCount || 0) + (submissionsCount || 0),
            users: users?.length || 0,
            downloads: 0
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ RESOURCES (biology_notes + resource_submissions) ============
router.get('/admin/resources', verifyAdmin, async (req, res) => {
    try {
        const { data: notes, error: notesError } = await supabase
            .from('biology_notes')
            .select('*')
            .order('created_at', { ascending: false });
        
        const { data: submissions, error: subError } = await supabase
            .from('resource_submissions')
            .select('*')
            .order('created_at', { ascending: false });
        
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
router.get('/admin/resources/:id', verifyAdmin, async (req, res) => {
    try {
        // Try biology_notes first
        let { data: resource } = await supabase
            .from('biology_notes')
            .select('*')
            .eq('id', req.params.id)
            .single();
        
        // Try resource_submissions
        if (!resource) {
            const { data: submission } = await supabase
                .from('resource_submissions')
                .select('*')
                .eq('id', req.params.id)
                .single();
            resource = submission;
        }
        
        if (!resource) throw new Error('Not found');
        res.json({ resource });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Upload resource
router.post('/admin/resources/upload', verifyAdmin, upload.single('file'), async (req, res) => {
    const { title, description, category, level, tags, section_type } = req.body;
    const file = req.file;
    
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    
    try {
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${crypto.randomBytes(16).toString('hex')}.${fileExt}`;
        const filePath = `resources/${fileName}`;
        
        const { error: uploadError } = await supabaseAdmin.storage
            .from('resources')
            .upload(filePath, file.buffer, {
                contentType: file.mimetype,
                cacheControl: '3600'
            });
        
        if (uploadError) throw uploadError;
        
        const { data: { publicUrl } } = supabaseAdmin.storage
            .from('resources')
            .getPublicUrl(filePath);
        
        // Insert into biology_notes (tag is text, not array)
        const { data: resource, error: dbError } = await supabase
            .from('biology_notes')
            .insert({
                title,
                description,
                file_url: publicUrl,
                file_size: `${(file.size / 1024 / 1024).toFixed(2)} MB`,
                category,
                level,
                tag: tags || '',
                section_type: section_type || 'resources',
                author: req.adminEmail
            })
            .select()
            .single();
        
        if (dbError) throw dbError;
        
        res.json({ success: true, resource });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update resource
router.put('/admin/resources/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    
    try {
        // Try biology_notes
        let { error } = await supabase
            .from('biology_notes')
            .update(updates)
            .eq('id', id);
        
        if (error) {
            // Try resource_submissions
            const { error: subError } = await supabase
                .from('resource_submissions')
                .update(updates)
                .eq('id', id);
            if (subError) throw subError;
        }
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete resource
router.delete('/admin/resources/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    
    try {
        let { error } = await supabase.from('biology_notes').delete().eq('id', id);
        if (error) {
            const { error: subError } = await supabase.from('resource_submissions').delete().eq('id', id);
            if (subError) throw subError;
        }
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Approve submission
router.post('/admin/resources/:id/approve', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    
    try {
        const { data: submission } = await supabase
            .from('resource_submissions')
            .select('*')
            .eq('id', id)
            .single();
        
        if (!submission) throw new Error('Submission not found');
        
        // Move to biology_notes
        await supabase.from('biology_notes').insert({
            title: submission.title,
            description: submission.description,
            file_url: submission.file_url,
            file_size: submission.file_size,
            category: submission.category,
            level: submission.level,
            tag: submission.tag,
            author: submission.author
        });
        
        // Update submission status
        await supabase.from('resource_submissions')
            .update({ status: 'approved' })
            .eq('id', id);
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ SITE SECTIONS (section + data columns) ============
router.get('/admin/site-sections', verifyAdmin, async (req, res) => {
    try {
        const { data: sections, error } = await supabase
            .from('site_sections')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        res.json({ sections });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.put('/admin/site-sections/:section', verifyAdmin, async (req, res) => {
    const { section } = req.params;
    const data = req.body;
    
    try {
        const { data: existing } = await supabase
            .from('site_sections')
            .select('id')
            .eq('section', section)
            .single();
        
        let result;
        if (existing) {
            result = await supabase
                .from('site_sections')
                .update({ data })
                .eq('section', section)
                .select();
        } else {
            result = await supabase
                .from('site_sections')
                .insert({ section, data })
                .select();
        }
        
        if (result.error) throw result.error;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ USERS ============
router.get('/admin/users', verifyAdmin, async (req, res) => {
    try {
        const { data: { users } } = await supabaseAdmin.auth.admin.listUsers();
        
        const { data: admins } = await supabase.from('admin_master').select('*');
        const { data: adminUsers } = await supabase.from('admin_users').select('*');
        
        const usersWithRoles = users.map(user => ({
            id: user.id,
            email: user.email,
            created_at: user.created_at,
            last_sign_in: user.last_sign_in_at,
            admin_role: admins?.find(a => a.admin_id === user.id)?.admin_role || 
                       (adminUsers?.find(a => a.user_id === user.id) ? 'admin' : 'user'),
            is_admin: !!(admins?.find(a => a.admin_id === user.id) || adminUsers?.find(a => a.user_id === user.id)),
            is_active: admins?.find(a => a.admin_id === user.id)?.is_active !== false,
            is_locked: admins?.find(a => a.admin_id === user.id)?.is_locked || false
        }));
        
        res.json({ users: usersWithRoles });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.post('/admin/users/:user_id/make-admin', verifyAdmin, async (req, res) => {
    const { user_id } = req.params;
    
    try {
        await supabase.from('admin_users').insert({ user_id });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.put('/admin/users/:user_id/lock', verifyAdmin, async (req, res) => {
    const { user_id } = req.params;
    const { lock, reason } = req.body;
    
    try {
        await supabase.from('admin_master')
            .update({ is_locked: lock, lock_reason: lock ? reason : null })
            .eq('admin_id', user_id);
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ ANALYTICS ============
router.get('/admin/analytics/dashboard', verifyAdmin, async (req, res) => {
    try {
        const { data: notes } = await supabase.from('biology_notes').select('*');
        const { data: submissions } = await supabase.from('resource_submissions').select('*');
        
        res.json({
            analytics: {
                total_resources: (notes?.length || 0) + (submissions?.length || 0),
                popular_resources: (notes || []).slice(0, 10).map(n => ({ title: n.title, downloads: 0 }))
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ CHECK ADMIN ============
router.get('/admin/check', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.json({ isAdmin: false });
    
    try {
        const token = authHeader.split(' ')[1];
        const { data: { user } } = await supabase.auth.getUser(token);
        if (!user) return res.json({ isAdmin: false });
        
        // Auto-promote super admin
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
        
        res.json({
            isAdmin: !!(admin || adminUser),
            role: admin?.admin_role || 'admin',
            email: user.email
        });
    } catch (err) {
        res.json({ isAdmin: false });
    }
});

module.exports = router;
