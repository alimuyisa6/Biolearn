 // admin-system.js - Complete admin system with auth.users ID check
const express = require('express');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// ═══════════════════════════════════════════
// SUPER ADMIN EMAIL - Auto-promoted on login
// ═══════════════════════════════════════════
const SUPER_ADMIN_EMAIL = 'alimuyisa6@gmail.com';

const DEFAULT_ADMIN_PERMISSIONS = {
    can_manage_users: true,
    can_manage_resources: true,
    can_manage_site_sections: true,
    can_view_analytics: true,
    can_manage_admins: true,
    can_delete_items: true,
    can_upload_files: true
};

const DEFAULT_EDITOR_PERMISSIONS = {
    can_manage_users: false,
    can_manage_resources: true,
    can_manage_site_sections: true,
    can_view_analytics: true,
    can_manage_admins: false,
    can_delete_items: false,
    can_upload_files: true
};

// ============ AUTHENTICATION MIDDLEWARE ============
async function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    
    try {
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) throw new Error('Invalid token');
        
        // Check admin_master table by admin_id (which is auth.users id)
        const { data: admin, error: adminError } = await supabase
            .from('admin_master')
            .select('*')
            .eq('admin_id', user.id)
            .eq('is_active', true)
            .single();
        
        if (adminError || !admin) {
            await logToAdminMaster(null, 'unauthorized_access', { 
                email: user.email, 
                user_id: user.id,
                path: req.path 
            });
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        if (admin.is_locked) {
            return res.status(403).json({ 
                error: `Account locked: ${admin.lock_reason || 'Contact super administrator'}` 
            });
        }
        
        req.admin = admin;
        req.admin.email = user.email;
        req.admin.auth_id = user.id;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Helper to log actions
async function logToAdminMaster(adminId, action, details = {}) {
    try {
        if (adminId) {
            const { data: admin } = await supabase
                .from('admin_master')
                .select('action_log')
                .eq('admin_id', adminId)
                .single();
            
            const newLog = [...(admin?.action_log || []), {
                timestamp: new Date().toISOString(),
                action: action,
                details: details,
                ip: details.ip || 'unknown'
            }];
            
            const trimmedLogs = newLog.slice(-1000);
            
            await supabase
                .from('admin_master')
                .update({ 
                    action_log: trimmedLogs,
                    last_action_at: new Date().toISOString()
                })
                .eq('admin_id', adminId);
        }
    } catch (err) {
        console.error('Failed to log action:', err);
    }
}

// Auto-promote super admin email
async function ensureSuperAdmin(userId, email) {
    if (email !== SUPER_ADMIN_EMAIL) return null;
    
    try {
        // Check if already exists
        const { data: existing } = await supabase
            .from('admin_master')
            .select('*')
            .eq('admin_id', userId)
            .single();
        
        if (existing) {
            // Ensure super_admin role
            if (existing.admin_role !== 'super_admin') {
                await supabase
                    .from('admin_master')
                    .update({
                        admin_role: 'super_admin',
                        permissions: DEFAULT_ADMIN_PERMISSIONS,
                        updated_at: new Date().toISOString()
                    })
                    .eq('admin_id', userId);
            }
            return existing;
        }
        
        // Create super admin
        const { data: admin, error } = await supabase
            .from('admin_master')
            .insert({
                admin_id: userId,
                admin_email: email,
                admin_role: 'super_admin',
                permissions: DEFAULT_ADMIN_PERMISSIONS,
                is_active: true,
                is_locked: false,
                login_count: 0,
                resources_managed: { total_uploads: 0, total_downloads: 0 },
                sections_modified: {},
                action_log: [],
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .select()
            .single();
        
        if (error) throw error;
        
        await logToAdminMaster(admin.admin_id, 'super_admin_auto_created', { email });
        console.log(`✅ Super admin auto-created for: ${email}`);
        
        return admin;
        
    } catch (err) {
        console.error('Failed to ensure super admin:', err);
        return null;
    }
}

// ============ ADMIN AUTHENTICATION ============
router.post('/admin/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        // Authenticate with Supabase auth.users
        const { data: auth, error: authError } = await supabase.auth.signInWithPassword({
            email, password
        });
        
        if (authError) throw authError;
        
        const userId = auth.user.id;
        
        // Auto-promote super admin email
        await ensureSuperAdmin(userId, email);
        
        // Check admin_master table by admin_id (auth.users id)
        const { data: admin, error: adminError } = await supabase
            .from('admin_master')
            .select('*')
            .eq('admin_id', userId)
            .single();
        
        if (adminError && adminError.code === 'PGRST116') {
            // Not in admin_master - needs approval
            return res.status(403).json({ 
                error: 'Account not authorized. Contact super administrator.',
                needs_approval: true 
            });
        }
        
        if (!admin || !admin.is_active) {
            return res.status(403).json({ error: 'Account inactive or locked' });
        }
        
        if (admin.is_locked) {
            return res.status(403).json({ 
                error: `Account locked: ${admin.lock_reason || 'Contact administrator'}` 
            });
        }
        
        // Update login info
        await supabase
            .from('admin_master')
            .update({ 
                last_login: new Date().toISOString(),
                login_count: (admin.login_count || 0) + 1,
                session_token: crypto.randomBytes(32).toString('hex'),
                updated_at: new Date().toISOString()
            })
            .eq('admin_id', userId);
        
        await logToAdminMaster(userId, 'admin_login', { email });
        
        console.log(`✅ Admin login: ${email} (${admin.admin_role})`);
        
        res.json({
            success: true,
            token: auth.session.access_token,
            admin: {
                id: userId,
                role: admin.admin_role,
                permissions: admin.permissions,
                email: auth.user.email
            }
        });
        
    } catch (err) {
        await logToAdminMaster(null, 'failed_login_attempt', { 
            email, 
            error: err.message 
        });
        res.status(401).json({ error: err.message });
    }
});

// ============ RESOURCE MANAGEMENT ============
router.post('/admin/resources/upload', verifyAdmin, upload.single('file'), async (req, res) => {
    const { title, description, category, level, tags, section_type } = req.body;
    const file = req.file;
    
    if (!req.admin.permissions.can_upload_files && !req.admin.permissions.can_manage_resources) {
        await logToAdminMaster(req.admin.admin_id, 'unauthorized_upload_attempt', { title });
        return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    if (!file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
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
        
        const { data: resource, error: dbError } = await supabase
            .from('resources')
            .insert({
                title: title,
                description: description,
                file_url: publicUrl,
                file_size: `${(file.size / 1024 / 1024).toFixed(2)} MB`,
                file_type: file.mimetype,
                category: category,
                level: level,
                tags: tags ? tags.split(',').map(t => t.trim()) : [],
                section_type: section_type || 'resources',
                author: req.admin.email,
                downloads: 0,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .select()
            .single();
        
        if (dbError) throw dbError;
        
        // Update admin stats
        const resourcesManaged = req.admin.resources_managed || { total_uploads: 0, total_downloads: 0 };
        resourcesManaged.total_uploads = (resourcesManaged.total_uploads || 0) + 1;
        resourcesManaged.last_upload = new Date().toISOString();
        
        await supabase
            .from('admin_master')
            .update({ resources_managed: resourcesManaged })
            .eq('admin_id', req.admin.admin_id);
        
        await logToAdminMaster(req.admin.admin_id, 'resource_uploaded', {
            resource_id: resource.id,
            title: title,
            size: file.size
        });
        
        res.json({ success: true, resource: resource });
        
    } catch (err) {
        await logToAdminMaster(req.admin.admin_id, 'resource_upload_failed', { error: err.message });
        res.status(500).json({ error: err.message });
    }
});

// Get all resources
router.get('/admin/resources', verifyAdmin, async (req, res) => {
    try {
        const { data: resources, error } = await supabase
            .from('resources')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        res.json({ resources });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get single resource
router.get('/admin/resources/:id', verifyAdmin, async (req, res) => {
    try {
        const { data: resource, error } = await supabase
            .from('resources')
            .select('*')
            .eq('id', req.params.id)
            .single();
        
        if (error) throw error;
        res.json({ resource });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update resource
router.put('/admin/resources/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    
    if (!req.admin.permissions.can_manage_resources) {
        return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    try {
        const { data: resource, error } = await supabase
            .from('resources')
            .update({
                ...updates,
                updated_at: new Date().toISOString()
            })
            .eq('id', id)
            .select()
            .single();
        
        if (error) throw error;
        
        await logToAdminMaster(req.admin.admin_id, 'resource_updated', { 
            resource_id: id, 
            updates 
        });
        
        res.json({ success: true, resource });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete resource
router.delete('/admin/resources/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    
    if (!req.admin.permissions.can_delete_items) {
        return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    try {
        const { data: resource } = await supabase
            .from('resources')
            .select('file_url')
            .eq('id', id)
            .single();
        
        if (resource && resource.file_url) {
            const filePath = resource.file_url.split('/').pop();
            await supabaseAdmin.storage
                .from('resources')
                .remove([`resources/${filePath}`]);
        }
        
        const { error } = await supabase
            .from('resources')
            .delete()
            .eq('id', id);
        
        if (error) throw error;
        
        await logToAdminMaster(req.admin.admin_id, 'resource_deleted', { resource_id: id });
        res.json({ success: true });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ SITE SECTIONS MANAGEMENT ============
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

router.put('/admin/site-sections/:section_type', verifyAdmin, async (req, res) => {
    const { section_type } = req.params;
    const content = req.body;
    
    if (!req.admin.permissions.can_manage_site_sections) {
        return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    try {
        const { data: existing } = await supabase
            .from('site_sections')
            .select('id')
            .eq('section_type', section_type)
            .single();
        
        let result;
        if (existing) {
            result = await supabase
                .from('site_sections')
                .update({
                    content: content,
                    updated_at: new Date().toISOString(),
                    updated_by: req.admin.email
                })
                .eq('section_type', section_type)
                .select();
        } else {
            result = await supabase
                .from('site_sections')
                .insert({
                    section_type: section_type,
                    content: content,
                    created_by: req.admin.email,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                })
                .select();
        }
        
        if (result.error) throw result.error;
        
        const sectionsModified = req.admin.sections_modified || {};
        sectionsModified[section_type] = new Date().toISOString();
        
        await supabase
            .from('admin_master')
            .update({ sections_modified: sectionsModified })
            .eq('admin_id', req.admin.admin_id);
        
        await logToAdminMaster(req.admin.admin_id, 'site_section_updated', { section_type });
        res.json({ success: true, section: result.data[0] });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ USER MANAGEMENT ============
router.get('/admin/users', verifyAdmin, async (req, res) => {
    if (!req.admin.permissions.can_manage_users) {
        return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    try {
        const { data: users, error } = await supabaseAdmin.auth.admin.listUsers();
        if (error) throw error;
        
        const { data: admins } = await supabase
            .from('admin_master')
            .select('admin_id, admin_role, permissions, is_active, is_locked');
        
        const usersWithRoles = users.users.map(user => ({
            id: user.id,
            email: user.email,
            created_at: user.created_at,
            last_sign_in: user.last_sign_in_at,
            admin_role: admins?.find(a => a.admin_id === user.id)?.admin_role || 'user',
            is_admin: !!admins?.find(a => a.admin_id === user.id),
            is_active: admins?.find(a => a.admin_id === user.id)?.is_active !== false,
            is_locked: admins?.find(a => a.admin_id === user.id)?.is_locked || false
        }));
        
        res.json({ users: usersWithRoles });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Make user an admin
router.post('/admin/users/:user_id/make-admin', verifyAdmin, async (req, res) => {
    const { user_id } = req.params;
    const { role, permissions } = req.body;
    
    if (req.admin.admin_role !== 'super_admin') {
        return res.status(403).json({ error: 'Only super admins can add new admins' });
    }
    
    try {
        const { data: user } = await supabaseAdmin.auth.admin.getUserById(user_id);
        if (!user) throw new Error('User not found');
        
        const { data: existing } = await supabase
            .from('admin_master')
            .select('*')
            .eq('admin_id', user_id)
            .single();
        
        if (existing) {
            // Update existing
            await supabase
                .from('admin_master')
                .update({
                    admin_role: role || 'content_manager',
                    permissions: permissions || DEFAULT_EDITOR_PERMISSIONS,
                    is_active: true,
                    updated_at: new Date().toISOString()
                })
                .eq('admin_id', user_id);
        } else {
            // Create new
            await supabase
                .from('admin_master')
                .insert({
                    admin_id: user_id,
                    admin_email: user.user.email,
                    admin_role: role || 'content_manager',
                    permissions: permissions || DEFAULT_EDITOR_PERMISSIONS,
                    is_active: true,
                    is_locked: false,
                    login_count: 0,
                    resources_managed: { total_uploads: 0, total_downloads: 0 },
                    sections_modified: {},
                    action_log: [],
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                });
        }
        
        await logToAdminMaster(req.admin.admin_id, 'admin_added', { 
            new_admin_id: user_id, 
            new_admin_email: user.user.email,
            role: role 
        });
        
        res.json({ success: true });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Lock/Unlock user
router.put('/admin/users/:user_id/lock', verifyAdmin, async (req, res) => {
    const { user_id } = req.params;
    const { lock, reason } = req.body;
    
    if (req.admin.admin_role !== 'super_admin') {
        return res.status(403).json({ error: 'Only super admins can lock/unlock accounts' });
    }
    
    try {
        await supabase
            .from('admin_master')
            .update({
                is_locked: lock,
                lock_reason: lock ? reason : null,
                updated_at: new Date().toISOString()
            })
            .eq('admin_id', user_id);
        
        await logToAdminMaster(req.admin.admin_id, lock ? 'admin_locked' : 'admin_unlocked', { 
            target_admin: user_id,
            reason: reason 
        });
        
        res.json({ success: true });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ ANALYTICS & DASHBOARD ============
router.get('/admin/analytics/dashboard', verifyAdmin, async (req, res) => {
    if (!req.admin.permissions.can_view_analytics) {
        return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    try {
        const { data: resources } = await supabase
            .from('resources')
            .select('downloads, created_at, category, title');
        
        const { data: admins } = await supabase
            .from('admin_master')
            .select('admin_role, login_count, created_at, admin_email');
        
        const { data: recentActivity } = await supabase
            .from('admin_master')
            .select('admin_email, action_log, last_action_at')
            .order('last_action_at', { ascending: false })
            .limit(20);
        
        const analytics = {
            total_resources: resources?.length || 0,
            total_downloads: resources?.reduce((sum, r) => sum + (r.downloads || 0), 0) || 0,
            resources_by_category: resources?.reduce((acc, r) => {
                acc[r.category || 'uncategorized'] = (acc[r.category || 'uncategorized'] || 0) + 1;
                return acc;
            }, {}),
            popular_resources: resources
                ?.sort((a, b) => (b.downloads || 0) - (a.downloads || 0))
                .slice(0, 10)
                .map(r => ({ title: r.title, downloads: r.downloads })),
            total_admins: admins?.length || 0,
            admins_by_role: admins?.reduce((acc, a) => {
                acc[a.admin_role] = (acc[a.admin_role] || 0) + 1;
                return acc;
            }, {}),
            recent_activity: recentActivity?.map(a => ({
                admin: a.admin_email,
                last_action: a.last_action_at,
                recent_actions: a.action_log?.slice(-5)
            })) || []
        };
        
        res.json({ analytics });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ IMAGE UPLOAD ============
router.post('/admin/upload/image', verifyAdmin, upload.single('image'), async (req, res) => {
    const { section_type } = req.body;
    const file = req.file;
    
    if (!req.admin.permissions.can_upload_files) {
        return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    if (!file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    try {
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${crypto.randomBytes(16).toString('hex')}.${fileExt}`;
        const filePath = `images/${fileName}`;
        
        const { error: uploadError } = await supabaseAdmin.storage
            .from('images')
            .upload(filePath, file.buffer, {
                contentType: file.mimetype,
                cacheControl: '3600'
            });
        
        if (uploadError) throw uploadError;
        
        const { data: { publicUrl } } = supabaseAdmin.storage
            .from('images')
            .getPublicUrl(filePath);
        
        await logToAdminMaster(req.admin.admin_id, 'image_uploaded', { 
            section: section_type,
            url: publicUrl 
        });
        
        res.json({ success: true, url: publicUrl });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ DASHBOARD STATS ============
router.get('/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const { count: resourcesCount } = await supabase
            .from('resources')
            .select('*', { count: 'exact', head: true });
        
        const { data: resources } = await supabase
            .from('resources')
            .select('downloads');
        
        const totalDownloads = resources?.reduce((sum, r) => sum + (r.downloads || 0), 0) || 0;
        
        const { data: { users } } = await supabaseAdmin.auth.admin.listUsers();
        
        res.json({
            resources: resourcesCount || 0,
            downloads: totalDownloads,
            users: users?.length || 0,
            online: 0
        });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ CREATE FIRST SUPER ADMIN (also checks your email) ============
router.post('/admin/setup/first-admin', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const { count } = await supabase
            .from('admin_master')
            .select('*', { count: 'exact', head: true });
        
        if (count > 0 && email !== SUPER_ADMIN_EMAIL) {
            return res.status(403).json({ error: 'Admin already exists. Use regular admin login.' });
        }
        
        let userId;
        const { data: existingUser } = await supabaseAdmin.auth.admin.getUserByEmail(email);
        
        if (!existingUser) {
            const { data: newUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
                email: email,
                password: password,
                email_confirm: true
            });
            if (createError) throw createError;
            userId = newUser.user.id;
        } else {
            userId = existingUser.user.id;
        }
        
        const isSuperAdmin = email === SUPER_ADMIN_EMAIL;
        
        const { data: admin, error } = await supabase
            .from('admin_master')
            .insert({
                admin_id: userId,
                admin_email: email,
                admin_role: isSuperAdmin ? 'super_admin' : 'content_manager',
                permissions: isSuperAdmin ? DEFAULT_ADMIN_PERMISSIONS : DEFAULT_EDITOR_PERMISSIONS,
                is_active: true,
                is_locked: false,
                login_count: 0,
                resources_managed: { total_uploads: 0, total_downloads: 0 },
                sections_modified: {},
                action_log: [],
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .select()
            .single();
        
        if (error) throw error;
        
        await logToAdminMaster(admin.admin_id, 'admin_created', { email, role: admin.admin_role });
        
        res.json({ 
            success: true, 
            message: `Admin created: ${admin.admin_role}`,
            admin: { email, role: admin.admin_role }
        });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ CHECK ADMIN STATUS ============
router.get('/admin/check', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.json({ isAdmin: false });
    }
    
    try {
        const token = authHeader.split(' ')[1];
        const { data: { user }, error } = await supabase.auth.getUser(token);
        
        if (error || !user) return res.json({ isAdmin: false });
        
        // Auto-promote super admin
        await ensureSuperAdmin(user.id, user.email);
        
        const { data: admin } = await supabase
            .from('admin_master')
            .select('admin_role, permissions, is_active')
            .eq('admin_id', user.id)
            .eq('is_active', true)
            .single();
        
        res.json({
            isAdmin: !!admin,
            role: admin?.admin_role || null,
            permissions: admin?.permissions || null,
            email: user.email
        });
        
    } catch (err) {
        res.json({ isAdmin: false });
    }
});

module.exports = router;
