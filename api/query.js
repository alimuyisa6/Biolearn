const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const REQUIRED_ENV_VARS = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY'];
const MISSING_VARS = REQUIRED_ENV_VARS.filter(varName => !process.env[varName]);
if (MISSING_VARS.length > 0) {
  console.error(`Missing required environment variables: ${MISSING_VARS.join(', ')}`);
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie || '';
  return Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const [k, ...v] = c.trim().split('=');
      return [k.trim(), decodeURIComponent(v.join('='))];
    })
  );
}

async function checkPersistentBan(ip) {
  try {
    const { data } = await supabase
      .from('ip_bans')
      .select('banned_until')
      .eq('ip_address', ip)
      .gt('banned_until', new Date().toISOString())
      .maybeSingle();
    return !!data;
  } catch (e) { return false; }
}

async function persistBan(ip, durationMs, reason) {
  try {
    await supabase.from('ip_bans').upsert({
      ip_address: ip,
      banned_until: new Date(Date.now() + durationMs).toISOString(),
      reason: reason || 'rate_limit',
      updated_at: new Date().toISOString()
    }, { onConflict: 'ip_address' });
  } catch (e) {}
}

const ACTION_WHITELIST = new Set([
  'get_site_section', 'get_all_site_sections', 'get_all_sections',
  'get_resources', 'get_filter_options',
  'submit_contact', 'subscribe_newsletter', 'submit_resource',
  'signup', 'signin', 'signout', 'get_user', 'refresh_session',
  'stats', 'submissions', 'approve', 'messages',
  'create_payment', 'send_message', 'currencies', 'status',
  'ai_query', 'get_donate_page_config', 'submit_momo_donation',
  'get_quizzes', 'get_quiz', 'complete_quiz', 'add_reaction', 'get_user_progress',
  'verify_turnstile',
  'get_quiz_topics', 'get_quiz_questions', 'submit_quiz_answers', 'check_daily_retry', 'add_quiz_questions_batch',
  'get_quiz_block', 'submit_quiz_block',
  'check_quiz_answer',
  'update_site_section', 'update_user_role', 'update_user_lock',
  'get_admin_users', 'get_newsletter_subscribers', 'get_donations',
  'get_app_features', 'update_app_feature', 'toggle_feature',
  'get_leaderboard', 'get_user_stats',
  'toggle_favorite', 'record_view', 'record_download', 'record_daily_visit',
  'get_user_favorites', 'get_recent_views', 'submit_rating',
  'get_all_ratings', 'get_user_ratings', 'request_resource',
  'get_user_achievements', 'get_user_streak',
  'request_chat', 'get_chat_messages', 'send_chat_message', 'delete_chat_message',
  'admin_get_pending_requests', 'admin_accept_chat', 'admin_reject_chat',
  'admin_update_presence', 'admin_get_active_chats', 'check_admin_online',
  'upload_file',
  'update_user_presence',
  'get_online_users',
  'save_achievement',
  'get_public_stats',
  'get_flashcards', 'toggle_flashcard_known', 'get_known_flashcards',
  'get_community_activity',
  'submit_weekly_challenge',
  'get_section_headings', 'update_section_headings',
  'check_flashcard_answer', 'rate_flashcard', 'toggle_flashcard_bookmark',
  'like_resource', 'comment_resource', 'get_resource_interactions',
  'submit_mood', 'get_flashcard_progress'
]);

const PUBLIC_ACTIONS = new Set([
  'get_site_section', 'get_all_site_sections', 'get_all_sections',
  'get_resources', 'get_filter_options', 'get_quizzes', 'get_quiz',
  'currencies', 'status', 'get_donate_page_config',
  'subscribe_newsletter', 'submit_contact', 'submit_resource',
  'signup', 'signin', 'verify_turnstile',
  'get_quiz_topics',
  'check_quiz_answer',
  'get_app_features', 'get_leaderboard',
  'get_all_ratings',
  'check_admin_online',
  'get_public_stats',
  'get_flashcards', 'get_community_activity',
  'get_section_headings',
  'check_flashcard_answer',
  'get_resource_interactions'
]);

const CSRF_PROTECTED_ACTIONS = new Set([
  'submit_contact', 'subscribe_newsletter', 'submit_resource',
  'signup', 'signin', 'submit_momo_donation', 'complete_quiz', 'add_reaction',
  'submit_quiz_answers', 'add_quiz_questions_batch', 'submit_quiz_block',
  'update_site_section', 'update_user_role', 'update_user_lock',
  'toggle_feature',
  'toggle_favorite', 'record_view', 'record_download', 'record_daily_visit',
  'submit_rating', 'request_resource',
  'upload_file',
  'update_user_presence',
  'save_achievement',
  'toggle_flashcard_known',
  'submit_weekly_challenge',
  'update_section_headings',
  'rate_flashcard', 'toggle_flashcard_bookmark',
  'like_resource', 'comment_resource', 'submit_mood'
]);

const ADMIN_ACTIONS = new Set([
  'approve', 'submissions', 'messages', 'stats',
  'update_site_section', 'update_user_role', 'update_user_lock',
  'get_admin_users', 'get_newsletter_subscribers', 'get_donations',
  'add_quiz_questions_batch',
  'update_app_feature',
  'admin_get_pending_requests', 'admin_accept_chat', 'admin_reject_chat',
  'admin_update_presence', 'admin_get_active_chats', 'get_online_users',
  'update_section_headings'
]);

const RATE_LIMITS = new Map();
const AUTH_ATTEMPTS = new Map();
const ADMIN_FAILED = new Map();
const BANNED_IPS = new Set();
const BANNED_UNTIL = new Map();
const MAX_REQUESTS = 120;
const WINDOW_MS = 60000;
const AUTH_MAX_ATTEMPTS = 15;
const AUTH_WINDOW_MS = 300000;
const BAN_DURATION_MS = 5 * 60 * 1000;
const ADMIN_LOCK_THRESHOLD = 5;
const ADMIN_LOCK_DURATION_MS = 24 * 60 * 60 * 1000;

const responseCache = new Map();
const CACHE_TTL = 120000;
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_REFRESH_WINDOW_MS = 24 * 60 * 60 * 1000;

function getCachedResponse(cacheKey) {
  const cached = responseCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) return cached.data;
  responseCache.delete(cacheKey);
  return null;
}

function setCachedResponse(cacheKey, data) {
  responseCache.set(cacheKey, { data, timestamp: Date.now() });
  if (responseCache.size > 200) {
    const oldestKey = responseCache.keys().next().value;
    responseCache.delete(oldestKey);
  }
}

function sanitizeInput(input, maxLength = null) {
  if (typeof input !== 'string') return input;
  let cleaned = input.replace(/\0/g, '').replace(/[\x00-\x1F\x7F]/g, '');
  cleaned = cleaned.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  cleaned = cleaned.replace(/javascript:/gi, '');
  cleaned = cleaned.replace(/on\w+\s*=/gi, '');
  cleaned = cleaned.replace(/<iframe/gi, '');
  cleaned = cleaned.replace(/<object/gi, '');
  cleaned = cleaned.replace(/<embed/gi, '');
  if (maxLength && cleaned.length > maxLength) cleaned = cleaned.substring(0, maxLength);
  return cleaned.trim();
}

function generateSessionToken() {
  return crypto.randomBytes(48).toString('base64url');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function createUserSession(userId, userEmail, ip, userAgent) {
  const sessionToken = generateSessionToken();
  const hashedToken = hashToken(sessionToken);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();
  const { error } = await supabase.from('user_sessions').insert({
    user_id: userId, session_token_hash: hashedToken, ip_address: ip,
    user_agent: (userAgent || '').substring(0, 500), expires_at: expiresAt, is_active: true
  });
  if (error) throw error;
  return { access_token: sessionToken, expires_at: expiresAt };
}

async function validateSession(token) {
  if (!token || token.length < 20) return null;
  const hashedToken = hashToken(token);
  const { data, error } = await supabase.from('user_sessions').select('user_id, expires_at, is_active').eq('session_token_hash', hashedToken).eq('is_active', true).single();
  if (error || !data) return null;
  if (new Date(data.expires_at) < new Date()) {
    await supabase.from('user_sessions').update({ is_active: false }).eq('session_token_hash', hashedToken);
    return null;
  }
  return data;
}

async function refreshSessionIfNeeded(token) {
  const session = await validateSession(token);
  if (!session) return null;
  const expiresAt = new Date(session.expires_at);
  const now = new Date();
  if (expiresAt.getTime() - now.getTime() < SESSION_REFRESH_WINDOW_MS) {
    const newExpiresAt = new Date(now.getTime() + SESSION_DURATION_MS).toISOString();
    const hashedToken = hashToken(token);
    await supabase.from('user_sessions').update({ expires_at: newExpiresAt }).eq('session_token_hash', hashedToken);
    return { ...session, expires_at: newExpiresAt, refreshed: true };
  }
  return { ...session, refreshed: false };
}

async function isUserAdmin(userId, ip) {
  if (!userId) return false;
  const { data } = await supabase.from('admin_master')
    .select('admin_role, permissions, is_active, is_locked, ip_whitelist')
    .eq('admin_id', userId)
    .eq('is_active', true)
    .maybeSingle();
  if (!data) return null;
  if (data.ip_whitelist && data.ip_whitelist.length > 0) {
    if (!data.ip_whitelist.includes(ip)) {
      return null;
    }
  }
  return data;
}

async function trackFailedAdminAttempt(userId, ip, userAgent) {
  const fingerprint = crypto.createHash('sha256')
    .update(`${ip}:${userAgent}`)
    .digest('hex')
    .substring(0, 16);
  const key = userId ? `user:${userId}` : `fp:${fingerprint}`;
  const attempts = ADMIN_FAILED.get(key) || { count: 0, firstAttempt: Date.now() };
  attempts.count++;
  ADMIN_FAILED.set(key, attempts);
  if (attempts.count >= ADMIN_LOCK_THRESHOLD) {
    if (userId) {
      await supabase.from('user_sessions').update({ is_active: false }).eq('user_id', userId);
    }
    BANNED_IPS.add(ip);
    BANNED_UNTIL.set(ip, Date.now() + ADMIN_LOCK_DURATION_MS);
    persistBan(ip, ADMIN_LOCK_DURATION_MS, 'admin_brute_force');
  }
}

function rateLimit(ip, action = null) {
  if (BANNED_IPS.has(ip)) {
    const banUntil = BANNED_UNTIL.get(ip);
    if (banUntil && banUntil > Date.now()) return false;
    BANNED_IPS.delete(ip); BANNED_UNTIL.delete(ip);
  }
  const now = Date.now();
  const isAuthAction = action === 'signin' || action === 'signup';
  const maxAllowed = isAuthAction ? AUTH_MAX_ATTEMPTS : MAX_REQUESTS;
  const windowMs = isAuthAction ? AUTH_WINDOW_MS : WINDOW_MS;
  const attemptMap = isAuthAction ? AUTH_ATTEMPTS : RATE_LIMITS;
  const record = attemptMap.get(ip) || { count: 0, reset: now + windowMs };
  if (now > record.reset) { record.count = 0; record.reset = now + windowMs; }
  record.count++; attemptMap.set(ip, record);
  if (record.count > maxAllowed * 2) {
    BANNED_IPS.add(ip); BANNED_UNTIL.set(ip, now + BAN_DURATION_MS);
    persistBan(ip, BAN_DURATION_MS, 'rate_limit_exceeded');
    setTimeout(() => { BANNED_IPS.delete(ip); BANNED_UNTIL.delete(ip); }, BAN_DURATION_MS);
    return false;
  }
  return record.count <= maxAllowed;
}

function trackFailedAuth(ip, email) {
  const key = `${ip}:${email}`;
  const attempts = AUTH_ATTEMPTS.get(key) || { count: 0, firstAttempt: Date.now() };
  attempts.count++; AUTH_ATTEMPTS.set(key, attempts);
  if (attempts.count >= 10) {
    BANNED_UNTIL.set(ip, Date.now() + 15 * 60 * 1000);
    persistBan(ip, 15 * 60 * 1000, 'auth_brute_force');
    setTimeout(() => { BANNED_UNTIL.delete(ip); AUTH_ATTEMPTS.delete(key); }, 15 * 60 * 1000);
    return true;
  }
  return false;
}

function resetFailedAuth(ip, email) { AUTH_ATTEMPTS.delete(`${ip}:${email}`); }

function logSecurityEvent(event, details, req) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(), requestId: req.requestId, event,
    ip: req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown',
    userAgent: (req.headers['user-agent'] || '').substring(0, 200), details
  }));
}

async function verifyTurnstile(token, ip) {
  if (!token) return false;
  try {
    const secretKey = process.env.TURNSTILE_SECRET_KEY;
    if (!secretKey) return true;
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: secretKey, response: token, remoteip: ip })
    });
    const data = await response.json();
    return data.success === true;
  } catch(e) { return true; }
}

function calculateStreak(activities) {
  if (!activities || !activities.length) return 0;
  let streak = 0;
  const sorted = activities.filter(a => a.passed).sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at));
  if (!sorted.length) return 0;
  let currentDate = new Date(sorted[0].completed_at).toDateString();
  for (let i = 0; i < sorted.length; i++) {
    const activityDate = new Date(sorted[i].completed_at).toDateString();
    if (i === 0) { streak = 1; currentDate = activityDate; }
    else {
      const prevDate = new Date(currentDate); prevDate.setDate(prevDate.getDate() - 1);
      if (activityDate === prevDate.toDateString()) { streak++; currentDate = activityDate; }
      else if (activityDate === currentDate) { continue; }
      else { break; }
    }
  }
  return streak;
}

const VALIDATORS = {
  submit_contact: (body) => {
    const { name, email, subject, message } = body.formData || {};
    const sn = sanitizeInput(name, 100), ss = sanitizeInput(subject, 200), sm = sanitizeInput(message, 5000);
    if (!sn || sn.length < 2) return 'Invalid name';
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email';
    if (!sm || sm.length < 10) return 'Message too short';
    body.formData.name = sn; body.formData.subject = ss; body.formData.message = sm;
    return null;
  },
  subscribe_newsletter: (body) => {
    const { email } = body.formData || {};
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email';
    return null;
  },
  signup: (body) => {
    if (!body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return 'Invalid email';
    if (!body.password || typeof body.password !== 'string' || body.password.length < 8) return 'Password must be at least 8 characters';
    return null;
  },
  signin: (body) => {
    if (!body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return 'Invalid email';
    if (!body.password || typeof body.password !== 'string') return 'Password required';
    return null;
  },
  submit_resource: (body) => {
    const p = body.payload || {};
    if (!p.title || typeof p.title !== 'string' || p.title.length > 200) return 'Invalid title';
    if (!p.description || typeof p.description !== 'string' || p.description.length > 5000) return 'Invalid description';
    return null;
  },
  update_site_section: (body) => {
    if (!body.section || typeof body.section !== 'string') return 'Section name required';
    if (body.data === undefined) return 'Data required';
    return null;
  },
  update_section_headings: (body) => {
    if (!body.headings || typeof body.headings !== 'object') return 'Headings object required';
    return null;
  },
  update_user_role: (body) => {
    if (!body.userId) return 'User ID required';
    if (!body.role || !['admin', 'user'].includes(body.role)) return 'Invalid role';
    return null;
  },
  update_user_lock: (body) => {
    if (!body.userId) return 'User ID required';
    if (typeof body.lock !== 'boolean') return 'Lock status required';
    return null;
  },
  toggle_feature: (body) => {
    if (!body.feature_key) return 'Feature key required';
    if (typeof body.is_enabled !== 'boolean') return 'Enabled status required';
    return null;
  },
  ai_query: (body) => { if (!body.prompt || typeof body.prompt !== 'string' || body.prompt.length > 2000) return 'Invalid prompt'; return null; },
  submit_momo_donation: (body) => { if (!body.amount || !body.txid) return 'Missing required fields'; return null; },
  complete_quiz: (body) => { if (!body.quiz_id || typeof body.quiz_id !== 'number') return 'Invalid quiz ID'; return null; },
  add_reaction: (body) => { if (!body.quiz_id || !body.reaction_type) return 'Invalid reaction'; return null; },
  verify_turnstile: (body) => { if (!body.token) return 'Token required'; return null; },
  submit_quiz_answers: (body) => {
    if (!body.level || !body.topic) return 'Level and topic required';
    if (!body.answers || !Array.isArray(body.answers) || body.answers.length === 0) return 'Answers required';
    return null;
  },
  submit_quiz_block: (body) => {
    if (!body.level || !body.topic || typeof body.block_number !== 'number') return 'Level, topic, and block number required';
    if (!body.answers || !Array.isArray(body.answers) || body.answers.length === 0) return 'Answers required';
    return null;
  },
  check_quiz_answer: (body) => {
    if (!body.question_id) return 'Question ID required';
    if (!body.selected_option) return 'Selected option required';
    if (!['A','B','C','D'].includes(body.selected_option)) return 'Invalid option';
    return null;
  },
  add_quiz_questions_batch: (body) => {
    if (!body.level || !['O-Level','A-Level','Pharmacy'].includes(body.level)) return 'Invalid level';
    if (!body.topic || !body.questions || !Array.isArray(body.questions) || body.questions.length === 0) return 'Questions required';
    for (const q of body.questions) {
      if (!q.question_text || !q.option_a || !q.option_b || !q.option_c || !q.option_d) return 'All options required';
      if (!q.correct_option || !['A','B','C','D'].includes(q.correct_option.toUpperCase())) return 'Invalid correct option';
      if (!q.explanation) return 'Explanation required';
    }
    return null;
  },
  toggle_favorite: (body) => {
    if (!body.resource_id) return 'resource_id required';
    return null;
  },
  record_view: (body) => {
    if (!body.resource_id) return 'resource_id required';
    return null;
  },
  record_download: (body) => {
    if (!body.resource_id) return 'resource_id required';
    return null;
  },
  submit_rating: (body) => {
    if (!body.resource_id) return 'resource_id required';
    if (!body.rating || typeof body.rating !== 'number' || body.rating < 1 || body.rating > 5) return 'rating must be between 1 and 5';
    return null;
  },
  request_resource: (body) => {
    if (!body.title || typeof body.title !== 'string' || body.title.trim().length === 0) return 'title required';
    return null;
  },
  save_achievement: (body) => {
    if (!body.badge || typeof body.badge !== 'object') return 'badge required';
    return null;
  },
  get_flashcards: (body) => null,
  get_section_headings: (body) => null,
  toggle_flashcard_known: (body) => {
    if (!body.flashcard_id) return 'flashcard_id required';
    return null;
  },
  get_known_flashcards: (body) => null,
  get_community_activity: (body) => null,
  submit_weekly_challenge: (body) => {
    if (!body.week_start) return 'week_start required';
    if (body.selected_option !== undefined && body.selected_option !== null && typeof body.selected_option !== 'number') return 'selected_option must be a number';
    return null;
  },
  check_flashcard_answer: (body) => {
    if (!body.flashcard_id) return 'flashcard_id required';
    if (!body.user_answer || typeof body.user_answer !== 'string') return 'user_answer required';
    return null;
  },
  rate_flashcard: (body) => {
    if (!body.flashcard_id) return 'flashcard_id required';
    if (!body.difficulty || !['easy','medium','hard'].includes(body.difficulty)) return 'Invalid difficulty';
    return null;
  },
  toggle_flashcard_bookmark: (body) => {
    if (!body.flashcard_id) return 'flashcard_id required';
    return null;
  },
  like_resource: (body) => {
    if (!body.resource_id) return 'resource_id required';
    return null;
  },
  comment_resource: (body) => {
    if (!body.resource_id) return 'resource_id required';
    if (!body.comment || typeof body.comment !== 'string' || body.comment.trim().length === 0) return 'Comment required';
    return null;
  },
  get_resource_interactions: (body) => {
    if (!body.resource_id) return 'resource_id required';
    return null;
  },
  submit_mood: (body) => {
    if (!body.mood) return 'Mood required';
    return null;
  },
  get_flashcard_progress: (body) => null
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of RATE_LIMITS) { if (now > record.reset) RATE_LIMITS.delete(ip); }
  for (const [key, attempts] of AUTH_ATTEMPTS) { if (now - attempts.firstAttempt > 3600000) AUTH_ATTEMPTS.delete(key); }
  for (const [key, attempts] of ADMIN_FAILED) { if (now - attempts.firstAttempt > ADMIN_LOCK_DURATION_MS) ADMIN_FAILED.delete(key); }
}, 60000);

module.exports = async (req, res) => {
  const requestId = crypto.randomBytes(8).toString('hex');
  req.requestId = requestId;
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://aliverbiopharm.com').split(',').map(o => o.trim());
  const requestOrigin = req.headers.origin || '';
  const corsOrigin = allowedOrigins.includes(requestOrigin) ? requestOrigin : allowedOrigins[0];
  res.setHeader('Access-Control-Allow-Origin', corsOrigin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token, X-Request-ID, X-Turnstile-Token, X-Session-Token, Cookie');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Cache-Control', 'no-store, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Request-ID', requestId);
  if (req.method === 'OPTIONS') return res.status(200).end();
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  const isBanned = await checkPersistentBan(ip);
  if (isBanned) {
    logSecurityEvent('PERSISTENT_BAN_BLOCKED', { ip }, req);
    return res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
  }
  if (!rateLimit(ip, req.body?.action)) {
    logSecurityEvent('RATE_LIMIT_EXCEEDED', { method: req.method, action: req.body?.action }, req);
    return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
  }
  if (req.method === 'GET') return await handleGet(req, res);
  if (req.method === 'POST') return await handlePost(req, res);
  return res.status(405).json({ error: 'Method not allowed' });
};

async function handleGet(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const action = url.searchParams.get('action');
  if (!action || !ACTION_WHITELIST.has(action)) return res.status(400).json({ error: 'Invalid action' });
  const cacheKey = `GET:${action}:${url.searchParams.toString()}`;
  if (action !== 'get_quiz' && action !== 'get_user_progress' && action !== 'get_app_features') {
    const cached = getCachedResponse(cacheKey);
    if (cached) return res.status(200).json(cached);
  }
  const cookies = parseCookies(req);
  const token = cookies.session || '';
  let userId = null;
  if (token) { try { const session = await validateSession(token); if (session) userId = session.user_id; } catch(e) {} }
  try {
    let result;
    switch (action) {
      case 'get_section_headings': {
        const { data, error } = await supabase.from('site_sections').select('data').eq('section', 'section_headings').single();
        if (error && error.code !== 'PGRST116') throw error;
        result = data?.data || {
          team_title: 'Meet Our Expert Faculty',
          team_subtitle: 'Learn from distinguished pharmacologists, molecular biologists, and clinical researchers with decades of combined teaching experience.',
          flashcards_title: 'Flashcard Decks',
          flashcards_subtitle: 'Active recall is the most effective way to retain complex scientific concepts. Flip each card to reveal detailed answers and mark your progress.',
          courses_title: 'Learning Resources',
          courses_subtitle: 'Browse our comprehensive library of biology and pharmacy materials. Download notes, past papers, lab manuals, and study guides curated by subject experts.',
          testimonials_title: 'Learner Success Stories',
          testimonials_subtitle: 'Hear from students who transformed their understanding of biology and pharmacy through our structured learning approach.',
          pricing_title: 'Membership Plans',
          pricing_subtitle: 'Choose the plan that fits your learning journey. All plans include access to our complete resource library with regular updates.',
          faq_title: 'Frequently Asked Questions',
          faq_subtitle: 'Quick answers to common questions about our platform, courses, resources, and membership options.',
          contact_title: 'Get in Touch',
          contact_subtitle: 'Have questions or feedback about our platform? Our dedicated support team typically responds within 24 hours.',
          blog_title: 'Latest Articles & Insights',
          blog_subtitle: 'Stay informed with the latest developments in biology, pharmacy, and life sciences from our expert contributors.'
        };
        break;
      }
      case 'get_app_features': {
        const pageId = url.searchParams.get('page_id') || 'all';
        let query = supabase.from('app_features').select('*').eq('is_enabled', true);
        if (pageId !== 'all') query = query.eq('page_id', pageId);
        query = query.order('display_order');
        const { data, error } = await query;
        if (error) throw error;
        if (!data || data.length === 0) { result = []; break; }
        if (pageId === 'quiz' && userId) {
          const { data: userSettings } = await supabase.from('user_feature_settings').select('feature_key, is_enabled, custom_settings').eq('user_id', userId);
          const userMap = new Map(); (userSettings || []).forEach(s => userMap.set(s.feature_key, s));
          result = data.map(feature => {
            const override = userMap.get(feature.feature_key);
            return { feature_key: feature.feature_key, feature_name: feature.feature_name, description: feature.description, page_id: feature.page_id, category: feature.category, settings: feature.settings, is_enabled: feature.is_enabled, display_order: feature.display_order, user_enabled: override ? override.is_enabled : true, user_settings: override ? (override.custom_settings || {}) : {} };
          });
        } else {
          result = data.map(f => ({ feature_key: f.feature_key, feature_name: f.feature_name, description: f.description, page_id: f.page_id, category: f.category, settings: f.settings, is_enabled: f.is_enabled, display_order: f.display_order, user_enabled: true, user_settings: {} }));
        }
        break;
      }
      case 'get_all_site_sections': case 'get_all_sections': {
        const { data, error } = await supabase.from('site_sections').select('section, data');
        if (error) throw error;
        result = {}; (data || []).forEach(row => { result[row.section] = row.data; });
        if (!result.section_headings) {
          result.section_headings = {
            team_title: 'Meet Our Expert Faculty',
            team_subtitle: 'Learn from distinguished pharmacologists, molecular biologists, and clinical researchers with decades of combined teaching experience.',
            flashcards_title: 'Flashcard Decks',
            flashcards_subtitle: 'Active recall is the most effective way to retain complex scientific concepts. Flip each card to reveal detailed answers and mark your progress.',
            courses_title: 'Learning Resources',
            courses_subtitle: 'Browse our comprehensive library of biology and pharmacy materials. Download notes, past papers, lab manuals, and study guides curated by subject experts.',
            testimonials_title: 'Learner Success Stories',
            testimonials_subtitle: 'Hear from students who transformed their understanding of biology and pharmacy through our structured learning approach.',
            pricing_title: 'Membership Plans',
            pricing_subtitle: 'Choose the plan that fits your learning journey. All plans include access to our complete resource library with regular updates.',
            faq_title: 'Frequently Asked Questions',
            faq_subtitle: 'Quick answers to common questions about our platform, courses, resources, and membership options.',
            contact_title: 'Get in Touch',
            contact_subtitle: 'Have questions or feedback about our platform? Our dedicated support team typically responds within 24 hours.',
            blog_title: 'Latest Articles & Insights',
            blog_subtitle: 'Stay informed with the latest developments in biology, pharmacy, and life sciences from our expert contributors.'
          };
        }
        if (!userId) {
          setCachedResponse(cacheKey, result);
        }
        break;
      }
      case 'get_resources': {
        let query = supabase.from('biology_notes').select('id,title,description,author,level,category,tag,section_type,file_url,file_size,created_at').order('created_at', { ascending: false }).limit(100);
        const level = url.searchParams.get('level'), category = url.searchParams.get('category'), tag = url.searchParams.get('tag');
        if (level) query = query.eq('level', level);
        if (category) query = query.eq('category', category);
        if (tag) query = query.eq('tag', tag);
        const { data, error } = await query; if (error) throw error; result = data || [];
        break;
      }
      case 'get_filter_options': {
        const [l, c, t] = await Promise.all([supabase.from('biology_notes').select('level').limit(500), supabase.from('biology_notes').select('category').limit(500), supabase.from('biology_notes').select('tag').limit(500)]);
        result = { levels: [...new Set((l.data||[]).map(x=>x.level).filter(Boolean))], categories: [...new Set((c.data||[]).map(x=>x.category).filter(Boolean))], tags: [...new Set((t.data||[]).map(x=>x.tag).filter(Boolean))] };
        break;
      }
      case 'get_quizzes': {
        const category = url.searchParams.get('category');
        let query = supabase.from('quizzes').select('id,title,category,description,total_points,difficulty,time_limit,is_active,attempt_count,avg_score,passing_score').eq('is_active', true);
        if (category && category !== 'all') query = query.eq('category', category);
        const { data, error } = await query.order('id'); if (error) throw error;
        if (userId && data && data.length) {
          const quizIds = data.map(q=>q.id);
          const { data: progress } = await supabase.from('user_quiz_activity').select('quiz_id,score,total_possible,percentage,passed,completed_at').eq('user_id',userId).in('quiz_id',quizIds);
          const pm = new Map(); if (progress) progress.forEach(p=>pm.set(p.quiz_id,p));
          result = data.map(q=>({...q, user_progress: pm.get(q.id)||null}));
        } else { result = (data||[]).map(q=>({...q, user_progress: null})); }
        break;
      }
      case 'get_quiz': {
        const quizId = parseInt(url.searchParams.get('id'));
        if (!quizId||isNaN(quizId)) return res.status(400).json({error:'Quiz ID required'});
        const { data, error } = await supabase.from('quizzes').select('*').eq('id',quizId).eq('is_active',true).single();
        if (error) throw error; if (!data) return res.status(404).json({error:'Quiz not found'}); result = data;
        break;
      }
      case 'get_user_progress': {
        if (!userId) { result = []; break; }
        const { data, error } = await supabase.from('user_quiz_activity').select('id,quiz_id,score,total_possible,percentage,passed,completed_at,time_taken').eq('user_id',userId).order('completed_at',{ascending:false}).limit(50);
        if (error) throw error; result = data || [];
        break;
      }
      case 'currencies': result = { currencies: [{currency:'btc'},{currency:'eth'},{currency:'usdttrc20'}] }; break;
      case 'status': result = { status:'finished' }; break;
      case 'get_flashcards': {
        const category = url.searchParams.get('category');
        let query = supabase.from('flashcards').select('*').order('created_at', { ascending: false });
        if (category) query = query.eq('category', category);
        const { data, error } = await query;
        if (error) throw error;
        result = data || [];
        break;
      }
      default: result = null;
    }
    if (action !== 'get_quiz' && action !== 'get_user_progress' && action !== 'get_app_features') setCachedResponse(cacheKey, result);
    return res.status(200).json(result);
  } catch (error) { console.error('GET Error:', error.message); return res.status(500).json({error:'Internal server error'}); }
}

async function handlePost(req, res) {
  const { action } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  if (!action || !ACTION_WHITELIST.has(action)) return res.status(400).json({ error: 'Invalid action' });
  const validator = VALIDATORS[action];
  if (validator) { const ve = validator(req.body); if (ve) return res.status(400).json({error:ve}); }
  const cookies = parseCookies(req);
  const token = cookies.session || '';
  let userId = null;
  let userEmail = null;
  let adminData = null;
  if (token) {
    try {
      const session = await refreshSessionIfNeeded(token);
      if (session) {
        if (session.refreshed) {
          res.setHeader('X-Session-Refreshed', 'true');
          res.setHeader('X-Session-Expires', session.expires_at);
        }
        userId = session.user_id;
        const { data: { user } } = await supabase.auth.admin.getUserById(session.user_id);
        if (user) userEmail = user.email;
        adminData = await isUserAdmin(session.user_id, ip);
      }
    } catch(e) {}
  }

  if (ADMIN_ACTIONS.has(action) && !adminData) {
    await trackFailedAdminAttempt(userId, ip, req.headers['user-agent'] || '');
    return res.status(500).json({ error: 'Internal server error - Access denied' });
  }

  try {
    let result;
    const { section, filters, formData, email, password, payload, submissionId, prompt, mode, name, amount, txid } = req.body;
    switch (action) {
      case 'get_section_headings': {
        const { data, error } = await supabase.from('site_sections').select('data').eq('section', 'section_headings').single();
        if (error && error.code !== 'PGRST116') throw error;
        result = data?.data || {
          team_title: 'Meet Our Expert Faculty',
          team_subtitle: 'Learn from distinguished pharmacologists, molecular biologists, and clinical researchers with decades of combined teaching experience.',
          flashcards_title: 'Flashcard Decks',
          flashcards_subtitle: 'Active recall is the most effective way to retain complex scientific concepts. Flip each card to reveal detailed answers and mark your progress.',
          courses_title: 'Learning Resources',
          courses_subtitle: 'Browse our comprehensive library of biology and pharmacy materials. Download notes, past papers, lab manuals, and study guides curated by subject experts.',
          testimonials_title: 'Learner Success Stories',
          testimonials_subtitle: 'Hear from students who transformed their understanding of biology and pharmacy through our structured learning approach.',
          pricing_title: 'Membership Plans',
          pricing_subtitle: 'Choose the plan that fits your learning journey. All plans include access to our complete resource library with regular updates.',
          faq_title: 'Frequently Asked Questions',
          faq_subtitle: 'Quick answers to common questions about our platform, courses, resources, and membership options.',
          contact_title: 'Get in Touch',
          contact_subtitle: 'Have questions or feedback about our platform? Our dedicated support team typically responds within 24 hours.',
          blog_title: 'Latest Articles & Insights',
          blog_subtitle: 'Stay informed with the latest developments in biology, pharmacy, and life sciences from our expert contributors.'
        };
        break;
      }
      case 'update_section_headings': {
        if (!adminData) return res.status(403).json({ error: 'Admin access required' });
        const { headings } = req.body;
        const { data: existing } = await supabase.from('site_sections').select('id').eq('section', 'section_headings').maybeSingle();
        if (existing) {
          await supabase.from('site_sections').update({ data: headings }).eq('section', 'section_headings');
        } else {
          await supabase.from('site_sections').insert({ section: 'section_headings', data: headings });
        }
        responseCache.delete('all_sections');
        responseCache.delete('GET:get_all_site_sections:');
        responseCache.delete('GET:get_all_sections:');
        result = { success: true };
        break;
      }
      case 'refresh_session': {
        if (!token) return res.status(401).json({ error: 'No session token' });
        const session = await refreshSessionIfNeeded(token);
        if (!session) return res.status(401).json({ error: 'Invalid or expired session' });
        result = { success: true, expires_at: session.expires_at, refreshed: session.refreshed };
        break;
      }
      case 'verify_turnstile': { result = { success: await verifyTurnstile(req.body.token, ip) }; break; }
      case 'get_site_section': {
        const ck = `section:${section}`; const cached = getCachedResponse(ck);
        if (cached) { result = cached; break; }
        const { data, error } = await supabase.from('site_sections').select('data').eq('section', section).single();
        if (error) throw error; result = data?.data || null; setCachedResponse(ck, result);
        break;
      }
      case 'get_all_site_sections': case 'get_all_sections': {
        const ck = 'all_sections'; const cached = getCachedResponse(ck);
        if (cached) { result = cached; break; }
        const { data, error } = await supabase.from('site_sections').select('section, data');
        if (error) throw error; result = {}; (data||[]).forEach(row=>{result[row.section]=row.data;});
        if (!result.section_headings) {
          result.section_headings = {
            team_title: 'Meet Our Expert Faculty',
            team_subtitle: 'Learn from distinguished pharmacologists, molecular biologists, and clinical researchers with decades of combined teaching experience.',
            flashcards_title: 'Flashcard Decks',
            flashcards_subtitle: 'Active recall is the most effective way to retain complex scientific concepts. Flip each card to reveal detailed answers and mark your progress.',
            courses_title: 'Learning Resources',
            courses_subtitle: 'Browse our comprehensive library of biology and pharmacy materials. Download notes, past papers, lab manuals, and study guides curated by subject experts.',
            testimonials_title: 'Learner Success Stories',
            testimonials_subtitle: 'Hear from students who transformed their understanding of biology and pharmacy through our structured learning approach.',
            pricing_title: 'Membership Plans',
            pricing_subtitle: 'Choose the plan that fits your learning journey. All plans include access to our complete resource library with regular updates.',
            faq_title: 'Frequently Asked Questions',
            faq_subtitle: 'Quick answers to common questions about our platform, courses, resources, and membership options.',
            contact_title: 'Get in Touch',
            contact_subtitle: 'Have questions or feedback about our platform? Our dedicated support team typically responds within 24 hours.',
            blog_title: 'Latest Articles & Insights',
            blog_subtitle: 'Stay informed with the latest developments in biology, pharmacy, and life sciences from our expert contributors.'
          };
        }
        if (adminData) {
          try {
            const { data: users } = await supabase.auth.admin.listUsers({ perPage: 100 });
            const { data: admins } = await supabase.from('admin_master').select('*');
            const adminMap = new Map(); (admins||[]).forEach(a => adminMap.set(a.admin_id, a));
            result.users = { list: (users?.users || []).map(u => ({ id: u.id, email: u.email, is_admin: adminMap.has(u.id), admin_role: adminMap.get(u.id)?.admin_role || null, is_locked: adminMap.get(u.id)?.is_locked || false, created_at: u.created_at })) };
          } catch(e) { result.users = { list: [] }; }
        }
        if (!adminData) {
          setCachedResponse('all_sections', result);
        }
        break;
      }
      case 'get_resources': {
        let q = supabase.from('biology_notes').select('id,title,description,author,level,category,tag,section_type,file_url,file_size,created_at').order('created_at',{ascending:false}).limit(100);
        if (filters?.level) q = q.eq('level',filters.level);
        if (filters?.category) q = q.eq('category',filters.category);
        if (filters?.tag) q = q.eq('tag',filters.tag);
        const { data, error } = await q; if (error) throw error; result = data || [];
        break;
      }
      case 'get_filter_options': {
        const ck = 'filter_options'; const cached = getCachedResponse(ck);
        if (cached) { result = cached; break; }
        const [l,c,t] = await Promise.all([supabase.from('biology_notes').select('level').limit(500),supabase.from('biology_notes').select('category').limit(500),supabase.from('biology_notes').select('tag').limit(500)]);
        result = {levels:[...new Set((l.data||[]).map(x=>x.level).filter(Boolean))],categories:[...new Set((c.data||[]).map(x=>x.category).filter(Boolean))],tags:[...new Set((t.data||[]).map(x=>x.tag).filter(Boolean))]};
        setCachedResponse(ck, result);
        break;
      }
      case 'get_quiz_topics': {
        const { level } = req.body;
        if (!level) return res.status(400).json({ error: 'Level required' });
        const { data, error } = await supabase.from('quiz_topics').select('id,topic_name,display_order').eq('level',level).eq('is_active',true).order('display_order');
        if (error) throw error;
        const topics = (data||[]).map(t => ({...t,question_count:0,total_blocks:0,completed_blocks:[],locked_blocks:[]}));
        if (topics.length > 0) {
          const topicNames = topics.map(t=>t.topic_name);
          const { data: counts } = await supabase.from('quiz_questions').select('topic').eq('level',level).in('topic',topicNames).eq('is_active',true);
          const countMap = new Map(); if (counts) counts.forEach(c=>{ countMap.set(c.topic, (countMap.get(c.topic)||0)+1); });
          topics.forEach(t => { t.question_count = countMap.get(t.topic_name) || 0; t.total_blocks = Math.ceil(t.question_count / 10); });
          if (userId) {
            const { data: blocks } = await supabase.from('user_quiz_activity').select('topic, block_number, completed_at').eq('user_id',userId).eq('level',level).in('topic',topicNames).order('completed_at',{ascending:false});
            const todayStr = new Date().toISOString().slice(0,10);
            const latestAttempts = new Map();
            (blocks || []).forEach(b => {
              const key = `${b.topic}_${b.block_number}`;
              if (!latestAttempts.has(key) || new Date(b.completed_at) > new Date(latestAttempts.get(key).completed_at)) { latestAttempts.set(key, b); }
            });
            topics.forEach(t => {
              const completed = []; const locked = [];
              for (let i = 0; i < t.total_blocks; i++) {
                const key = `${t.topic_name}_${i}`; const attempt = latestAttempts.get(key);
                if (attempt) { completed.push(i); const attemptDate = new Date(attempt.completed_at).toISOString().slice(0,10); if (attemptDate === todayStr) locked.push(i); }
              }
              t.completed_blocks = completed; t.locked_blocks = locked;
            });
          }
        }
        result = topics;
        break;
      }
      case 'get_quiz_block': {
        const { level: ql, topic: qt, block_number: bn } = req.body;
        if (!ql || !qt || bn === undefined) return res.status(400).json({ error: 'Level, topic, and block number required' });
        const offset = bn * 10;
        const { data, error } = await supabase.from('quiz_questions').select('id,question_text,option_a,option_b,option_c,option_d,difficulty').eq('level',ql).eq('topic',qt).eq('is_active',true).order('id').range(offset, offset + 9);
        if (error) throw error;
        const shuffled = (data||[]).sort(()=>Math.random()-0.5);
        result = { block_number: bn, questions: shuffled, total_in_block: shuffled.length };
        break;
      }
      case 'get_quiz_questions': {
        const { level: ql, topic: qt, count: qc } = req.body;
        if (!ql || !qt) return res.status(400).json({ error: 'Level and topic required' });
        const questionCount = Math.min(qc || 10, 50);
        const { data, error } = await supabase.from('quiz_questions').select('id,question_text,option_a,option_b,option_c,option_d,difficulty').eq('level',ql).eq('topic',qt).eq('is_active',true).limit(questionCount);
        if (error) throw error;
        const shuffled = (data||[]).sort(()=>Math.random()-0.5);
        result = shuffled;
        break;
      }
      case 'check_quiz_answer': {
        const { question_id, selected_option } = req.body;
        const { data: question, error } = await supabase.from('quiz_questions').select('id,correct_option,option_a,option_b,option_c,option_d').eq('id',question_id).single();
        if (error || !question) return res.status(404).json({ error: 'Question not found' });
        const isCorrect = selected_option === question.correct_option;
        const optionMap = { A: question.option_a, B: question.option_b, C: question.option_c, D: question.option_d };
        result = { correct: isCorrect, correct_option: question.correct_option, correct_answer_text: optionMap[question.correct_option] };
        break;
      }
      case 'submit_quiz_block': {
        if (!userId) return res.status(401).json({ error: 'Authentication required.' });
        const { level: sl, topic: st, block_number: sbn, answers: sa, time_taken: stt, achievements } = req.body;
        if (!sa || !Array.isArray(sa) || sa.length === 0) return res.status(400).json({ error: 'Answers required' });
        const todayStart = new Date().toISOString().slice(0,10) + 'T00:00:00Z';
        const { data: existingAttempt } = await supabase.from('user_quiz_activity').select('id').eq('user_id', userId).eq('level', sl).eq('topic', st).eq('block_number', sbn).gte('completed_at', todayStart).maybeSingle();
        if (existingAttempt) { return res.status(429).json({ error: 'You have already attempted this block today. Please try again tomorrow.' }); }
        const questionIds = sa.map(a => a.id);
        const { data: questions, error: qe } = await supabase.from('quiz_questions').select('id,correct_option,explanation,question_text,option_a,option_b,option_c,option_d,difficulty').in('id',questionIds);
        if (qe) throw qe;
        const qMap = new Map(); (questions||[]).forEach(q => qMap.set(q.id, q));
        let score = 0;
        const graded = sa.map(answer => {
          const q = qMap.get(answer.id);
          if (!q) return { id: answer.id, question: 'Question unavailable', userAnswer: 'X', correctAnswer: 'N/A', userAnswerText: 'Not answered', correctAnswerText: 'N/A', isCorrect: false, explanation: 'Removed.' };
          const userOpt = answer.selectedOption || 'X';
          const isCorrect = userOpt === q.correct_option;
          if (isCorrect) score++;
          const allOpts = { A: q.option_a, B: q.option_b, C: q.option_c, D: q.option_d };
          return { id: q.id, question: q.question_text, userAnswer: userOpt, correctAnswer: q.correct_option, userAnswerText: allOpts[userOpt] || 'Not answered', correctAnswerText: allOpts[q.correct_option], isCorrect, explanation: q.explanation };
        });
        const total = sa.length, percentage = Math.round((score / total) * 100), passed = percentage >= 70;
        const { error: ie } = await supabase.from('user_quiz_activity').insert({ user_id: userId, level: sl, topic: st, block_number: sbn, score, total_questions: total, percentage, passed, answers: graded, time_taken: stt || 0, completed_at: new Date().toISOString() });
        if (ie) throw ie;
        if (achievements && Array.isArray(achievements)) {
          const achievementInserts = achievements.map(badge => ({ user_id: userId, interaction_type: 'achievement', metadata: { badge: badge.id || badge, ...badge } }));
          await supabase.from('user_interactions').insert(achievementInserts);
        }
        result = { score, total, percentage, passed, answers: graded, block_number: sbn };
        break;
      }
      case 'submit_quiz_answers': {
        if (!userId) return res.status(401).json({ error: 'Authentication required.' });
        const { level: sl, topic: st, answers: sa, time_taken: stt } = req.body;
        if (!sa || !Array.isArray(sa) || sa.length === 0) return res.status(400).json({ error: 'Answers required' });
        const questionIds = sa.map(a => a.id);
        const { data: questions, error: qe } = await supabase.from('quiz_questions').select('id,correct_option,explanation,question_text,option_a,option_b,option_c,option_d,difficulty').in('id',questionIds);
        if (qe) throw qe;
        const qMap = new Map(); (questions||[]).forEach(q => qMap.set(q.id, q));
        let score = 0;
        const graded = sa.map(answer => {
          const q = qMap.get(answer.id);
          if (!q) return { id: answer.id, question: 'Question unavailable', userAnswer: 'X', correctAnswer: 'N/A', userAnswerText: 'Not answered', correctAnswerText: 'N/A', isCorrect: false, explanation: 'Removed.' };
          const userOpt = answer.selectedOption || 'X';
          const isCorrect = userOpt === q.correct_option;
          if (isCorrect) score++;
          const allOpts = { A: q.option_a, B: q.option_b, C: q.option_c, D: q.option_d };
          return { id: q.id, question: q.question_text, userAnswer: userOpt, correctAnswer: q.correct_option, userAnswerText: allOpts[userOpt] || 'Not answered', correctAnswerText: allOpts[q.correct_option], isCorrect, explanation: q.explanation };
        });
        const total = sa.length, percentage = Math.round((score / total) * 100), passed = percentage >= 70;
        const { error: ie } = await supabase.from('user_quiz_activity').insert({ user_id: userId, level: sl, topic: st, score, total_questions: total, percentage, passed, answers: graded, time_taken: stt || 0, completed_at: new Date().toISOString() });
        if (ie) throw ie;
        result = { score, total, percentage, passed, answers: graded };
        break;
      }
      case 'check_daily_retry': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { level: rl, topic: rt, block_number: rbn } = req.body;
        let query = supabase.from('user_quiz_activity').select('completed_at,passed').eq('user_id',userId).eq('level',rl).eq('topic',rt);
        if (rbn !== undefined) query = query.eq('block_number', rbn);
        query = query.order('completed_at',{ascending:false}).limit(1);
        const { data, error } = await query;
        if (error) throw error;
        const last = data && data[0];
        if (!last) { result = { can_retry: true, reason: null, locked_blocks: [] }; }
        else {
          const today = new Date(); const lastDate = new Date(last.completed_at);
          const sameDay = today.toDateString() === lastDate.toDateString();
          if (rbn !== undefined) { result = { can_retry: !sameDay, reason: sameDay ? 'You have already attempted this block today. Please try again tomorrow.' : null }; }
          else {
            const { data: allBlocks } = await supabase.from('user_quiz_activity').select('block_number,completed_at').eq('user_id',userId).eq('level',rl).eq('topic',rt).order('completed_at',{ascending:false});
            const lockedBlocks = [];
            if (allBlocks) { allBlocks.forEach(b => { if (new Date(b.completed_at).toDateString() === today.toDateString()) lockedBlocks.push(b.block_number); }); }
            result = { can_retry: true, locked_blocks: lockedBlocks };
          }
        }
        break;
      }
      case 'add_quiz_questions_batch': {
        if (!adminData) return res.status(403).json({ error: 'Admin access required' });
        const { level: bl, topic: bt, batch_name: bn, questions: bq } = req.body;
        if (!bl||!bt||!bq||!Array.isArray(bq)) return res.status(400).json({error:'Invalid batch data'});
        const { data: batch, error: bae } = await supabase.from('quiz_batches').insert({batch_name:bn||'Batch '+new Date().toISOString(),level:bl,topic:bt,question_count:bq.length,imported_by:userId}).select().single();
        if (bae) throw bae;
        const qb = bq.map(q=>({level:bl,topic:bt,question_text:q.question_text,option_a:q.option_a,option_b:q.option_b,option_c:q.option_c,option_d:q.option_d,correct_option:q.correct_option.toUpperCase(),explanation:q.explanation,difficulty:q.difficulty||'medium',batch_id:batch.id}));
        const { error: qie } = await supabase.from('quiz_questions').insert(qb);
        if (qie) throw qie;
        result = { success: true, batch_id: batch.id, questions_added: bq.length };
        break;
      }
      case 'get_quizzes': {
        const category = filters?.category || req.body.category;
        let query = supabase.from('quizzes').select('id,title,category,description,total_points,difficulty,time_limit,is_active,attempt_count,avg_score,passing_score').eq('is_active',true);
        if (category&&category!=='all') query=query.eq('category',category);
        const { data, error } = await query.order('id'); if (error) throw error;
        if (userId&&data&&data.length) {
          const qids=data.map(q=>q.id); const { data: progress } = await supabase.from('user_quiz_activity').select('quiz_id,score,total_possible,percentage,passed,completed_at').eq('user_id',userId).in('quiz_id',qids);
          const pm=new Map(); if(progress)progress.forEach(p=>pm.set(p.quiz_id,p));
          result=data.map(q=>({...q,user_progress:pm.get(q.id)||null}));
        } else { result=(data||[]).map(q=>({...q,user_progress:null})); }
        break;
      }
      case 'get_quiz': {
        const quizId=parseInt(req.body.id); if(!quizId||isNaN(quizId))return res.status(400).json({error:'Quiz ID required'});
        const {data,error}=await supabase.from('quizzes').select('*').eq('id',quizId).eq('is_active',true).single();
        if(error)throw error; if(!data)return res.status(404).json({error:'Quiz not found'}); result=data;
        break;
      }
      case 'get_user_progress': {
        if(!userId){result=[];break;}
        const {data,error}=await supabase.from('user_quiz_activity').select('id,quiz_id,level,topic,block_number,score,total_possible,percentage,passed,completed_at,time_taken').eq('user_id',userId).order('completed_at',{ascending:false}).limit(50);
        if(error)throw error; result=data||[];
        break;
      }
      case 'get_app_features': {
        const { page_id } = req.body;
        let query = supabase.from('app_features').select('*').eq('is_enabled', true);
        if (page_id && page_id !== 'all') query = query.eq('page_id', page_id);
        query = query.order('display_order');
        const { data, error } = await query;
        if (error) throw error;
        if (!data || data.length === 0) { result = []; break; }
        if (page_id === 'quiz' && userId) {
          const { data: userSettings } = await supabase.from('user_feature_settings').select('feature_key, is_enabled, custom_settings').eq('user_id', userId);
          const userMap = new Map(); (userSettings || []).forEach(s => userMap.set(s.feature_key, s));
          result = data.map(feature => {
            const override = userMap.get(feature.feature_key);
            return { feature_key: feature.feature_key, feature_name: feature.feature_name, description: feature.description, page_id: feature.page_id, category: feature.category, settings: feature.settings, is_enabled: feature.is_enabled, display_order: feature.display_order, user_enabled: override ? override.is_enabled : feature.is_enabled, user_settings: override ? (override.custom_settings || {}) : {} };
          });
        } else { result = data.map(f => ({ feature_key: f.feature_key, feature_name: f.feature_name, description: f.description, page_id: f.page_id, category: f.category, settings: f.settings, is_enabled: f.is_enabled, display_order: f.display_order, user_enabled: f.is_enabled, user_settings: {} })); }
        break;
      }
      case 'toggle_feature': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { feature_key, is_enabled } = req.body;
        const { data: existing } = await supabase.from('user_feature_settings').select('id').eq('user_id', userId).eq('feature_key', feature_key).maybeSingle();
        if (existing) { await supabase.from('user_feature_settings').update({ is_enabled }).eq('id', existing.id); }
        else { await supabase.from('user_feature_settings').insert({ user_id: userId, feature_key, is_enabled }); }
        result = { success: true };
        break;
      }
      case 'get_leaderboard': {
        const { level, topic, limit } = req.body;
        let query = supabase.from('user_quiz_activity').select('user_id, score, total_questions, percentage, level, topic, completed_at').eq('passed', true).order('percentage', { ascending: false }).order('completed_at', { ascending: false }).limit(limit || 20);
        if (level) query = query.eq('level', level);
        if (topic) query = query.eq('topic', topic);
        const { data, error } = await query;
        if (error) throw error;
        const leaderboard = []; const userMap = new Map();
        for (const entry of (data || [])) {
          if (!userMap.has(entry.user_id)) {
            try { const { data: { user } } = await supabase.auth.admin.getUserById(entry.user_id); if (user) { userMap.set(entry.user_id, { name: user.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User', avatar: user.user_metadata?.avatar_url || null }); } }
            catch(e) { userMap.set(entry.user_id, { name: 'User', avatar: null }); }
          }
          leaderboard.push({ ...entry, user: userMap.get(entry.user_id) });
        }
        result = leaderboard;
        break;
      }
      case 'get_user_stats': {
        const targetUserId = adminData ? (req.body.user_id || userId) : userId;
        if (!targetUserId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_quiz_activity').select('*').eq('user_id', targetUserId).order('completed_at', { ascending: false });
        if (error) throw error;
        const all = data || [];
        const passed = all.filter(a => a.passed);
        const uniqueTopics = [...new Set(all.map(a => a.topic))];
        result = { total_blocks_attempted: all.length, total_blocks_passed: passed.length, average_score: all.length ? Math.round(all.reduce((s, a) => s + a.percentage, 0) / all.length) : 0, best_score: all.length ? Math.max(...all.map(a => a.percentage)) : 0, topics_attempted: uniqueTopics.length, streak: calculateStreak(all), recent_activity: all.slice(0, 10) };
        break;
      }
      case 'get_user_favorites': {
        const targetUserId = adminData ? (req.body.user_id || userId) : userId;
        if (!targetUserId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_interactions').select('resource_id, resources:biology_notes(title)').eq('user_id', targetUserId).eq('interaction_type', 'favorite').order('created_at', { ascending: false });
        if (error) throw error;
        result = (data || []).map(f => ({ resource_id: f.resource_id, title: f.resources?.title || null }));
        break;
      }
      case 'get_user_ratings': {
        const targetUserId = adminData ? (req.body.user_id || userId) : userId;
        if (!targetUserId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_interactions').select('resource_id, value').eq('user_id', targetUserId).eq('interaction_type', 'rating');
        if (error) throw error;
        const userRatings = {};
        (data || []).forEach(r => { userRatings[r.resource_id] = r.value; });
        result = userRatings;
        break;
      }
      case 'get_user_achievements': {
        const targetUserId = adminData ? (req.body.user_id || userId) : userId;
        if (!targetUserId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_interactions').select('metadata').eq('user_id', targetUserId).eq('interaction_type', 'achievement');
        if (error) throw error;
        const badges = (data || []).map(d => d.metadata?.badge).filter(Boolean);
        result = badges.map(b => ({ badge: b }));
        break;
      }
      case 'get_user_streak': {
        const targetUserId = adminData ? (req.body.user_id || userId) : userId;
        if (!targetUserId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_interactions').select('created_at').eq('user_id', targetUserId).eq('interaction_type', 'daily_visit').order('created_at', { ascending: false });
        if (error) throw error;
        const dates = (data || []).map(d => new Date(d.created_at).toISOString().slice(0,10));
        let streak = 0;
        const today = new Date().toISOString().slice(0,10);
        let checkDate = today;
        const dateSet = new Set(dates);
        if (!dateSet.has(checkDate)) {
          const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0,10);
          if (!dateSet.has(yesterday)) { result = { count: 0 }; break; }
          checkDate = yesterday;
        }
        while (dateSet.has(checkDate)) {
          streak++;
          const d = new Date(checkDate);
          d.setDate(d.getDate() - 1);
          checkDate = d.toISOString().slice(0,10);
        }
        result = { count: streak };
        break;
      }
      case 'update_app_feature': {
        const { feature_key, settings, is_enabled } = req.body;
        await supabase.from('app_features').update({ settings, is_enabled, updated_at: new Date().toISOString() }).eq('feature_key', feature_key);
        result = { success: true };
        break;
      }
      case 'submit_contact': {
        const email = formData.email.trim().slice(0,254);
        const twentyFourHoursAgo = new Date(Date.now() - 24*60*60*1000).toISOString();
        const { data: recent } = await supabase.from('contact_messages').select('id').eq('email', email).gte('created_at', twentyFourHoursAgo).limit(1);
        if (recent && recent.length > 0) { return res.status(429).json({ error: 'You can only send one message every 24 hours. Please try again later.' }); }
        const { error } = await supabase.from('contact_messages').insert({ name: formData.name.trim().slice(0,100), email: email, subject: (formData.subject || '').trim().slice(0,200), message: formData.message.trim().slice(0,5000) });
        if (error) throw error;
        result = { success: true };
        break;
      }
      case 'subscribe_newsletter': { const {error}=await supabase.from('newsletter_subscribers').insert({email:formData.email.trim().slice(0,254)}); if(error&&error.code!=='23505')throw error; result={success:true}; break; }
      case 'submit_resource': { const {error}=await supabase.from('resource_submissions').insert({title:payload.title.trim().slice(0,200),description:payload.description.trim().slice(0,5000),author:(payload.author||'').trim().slice(0,100),level:(payload.level||'').trim().slice(0,50),category:(payload.category||'').trim().slice(0,100),tag:(payload.tag||'').trim().slice(0,200),file_url:(payload.file_url||'').trim().slice(0,2048),file_size:(payload.file_size||'').trim().slice(0,50),status:'pending'}); if(error)throw error; result={success:true}; break; }
      case 'signup': { if(!rateLimit(ip,'signup'))return res.status(429).json({error:'Please wait a moment.'}); if (password.length < 8) return res.status(400).json({error:'Password must be at least 8 characters.'}); const {data,error}=await supabase.auth.signUp({email:email.trim().toLowerCase(),password,options:{emailRedirectTo:`${req.headers['x-forwarded-proto']||'https'}://${req.headers.host}`}}); if(error){if(error.code==='user_already_exists')return res.status(200).json({data:{user:null,session:null,message:'Account exists. Check your email.'}});trackFailedAuth(ip,email);throw error;} resetFailedAuth(ip,email); if (data.session) { const cs = await createUserSession(data.user.id, data.user.email, ip, req.headers['user-agent']); const cookieValue = `session=${cs.access_token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}; Path=/`; res.setHeader('Set-Cookie', cookieValue); result = { user: { id: data.user.id, email: data.user.email } }; } else { result = { user: null }; } break; }
      case 'signin': { if(!rateLimit(ip,'signin'))return res.status(429).json({error:'Please wait a moment.'}); const {data,error}=await supabase.auth.signInWithPassword({email:email.trim().toLowerCase(),password}); if(error){const banned=trackFailedAuth(ip,email);if(banned)return res.status(429).json({error:'Too many failed attempts. Account locked for 15 minutes.'});throw error;} resetFailedAuth(ip,email); const session = await createUserSession(data.user.id, data.user.email, ip, req.headers['user-agent']); const cookieValue = `session=${session.access_token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}; Path=/`; res.setHeader('Set-Cookie', cookieValue); result = { user: { id: data.user.id, email: data.user.email } }; break; }
      case 'signout': { if (token) { const ht = hashToken(token); await supabase.from('user_sessions').update({ is_active: false }).eq('session_token_hash', ht); } res.setHeader('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/'); result={success:true}; break; }
      case 'get_user': { if(!userId){result={user:null};break;} result={ user: { id: userId, email: userEmail, is_admin: !!adminData, admin_role: adminData?.admin_role || null, permissions: adminData?.permissions || null, is_locked: adminData?.is_locked || false } }; break; }
      case 'complete_quiz': { if(!userId)return res.status(401).json({error:'Please sign in.'}); const {quiz_id,score,total,percentage,passed,answers,time_taken}=req.body; const {data:existing}=await supabase.from('user_quiz_activity').select('id').eq('user_id',userId).eq('quiz_id',quiz_id).maybeSingle(); if(existing){await supabase.from('user_quiz_activity').update({score,total_possible:total,percentage,passed,answers,time_taken,completed_at:new Date().toISOString()}).eq('id',existing.id);}else{await supabase.from('user_quiz_activity').insert({user_id:userId,quiz_id,score,total_possible:total,percentage,passed,answers,time_taken,completed_at:new Date().toISOString()});} try{await supabase.rpc('update_quiz_stats',{quiz_id_input:quiz_id});}catch(e){} result={success:true,passed,percentage}; break; }
      case 'add_reaction': { if(!userId)return res.status(401).json({error:'Please sign in.'}); const {error}=await supabase.from('user_quiz_activity').update({reaction:req.body.reaction_type}).eq('user_id',userId).eq('quiz_id',req.body.quiz_id); if(error&&error.code!=='PGRST116')throw error; result={success:true}; break; }
      case 'stats': { const ck='stats'; const cached=getCachedResponse(ck); if(cached){result=cached;break;} const [rc,sc,mc]=await Promise.all([supabase.from('biology_notes').select('id',{count:'exact',head:true}),supabase.from('resource_submissions').select('id',{count:'exact',head:true}).eq('status','pending'),supabase.from('contact_messages').select('id',{count:'exact',head:true})]); result={resources:rc.count||0,pendingSubmissions:sc.count||0,messages:mc.count||0}; setCachedResponse(ck,result); break; }
      case 'submissions': { const {data,error}=await supabase.from('resource_submissions').select('id,title,description,author,level,category,tag,status,created_at').order('created_at',{ascending:false}).limit(50); if(error)throw error; result=data||[]; break; }
      case 'approve': { if(!submissionId||!['approve','reject','delete'].includes(req.body.action))throw new Error('Invalid approval action'); if (req.body.action === 'delete') { const { data: sub } = await supabase.from('resource_submissions').select('id').eq('id', submissionId).maybeSingle(); if (sub) { await supabase.from('resource_submissions').delete().eq('id', submissionId); } else { await supabase.from('biology_notes').delete().eq('id', submissionId); } } else { await supabase.from('resource_submissions').update({status:req.body.action==='approve'?'approved':'rejected'}).eq('id',submissionId); } result={success:true}; break; }
      case 'messages': { const {data,error}=await supabase.from('contact_messages').select('id,name,email,subject,message,created_at').order('created_at',{ascending:false}).limit(50); if(error)throw error; result={messages:data||[]}; break; }
      case 'create_payment': { result={payment_id:'demo_'+Date.now(),pay_address:'0xDEMO',pay_amount:req.body.amount||10,pay_currency:req.body.pay_currency||'usdttrc20'}; break; }
      case 'ai_query': { const gk=process.env.GEMINI_API_KEY; if(!gk){result={answer:'AI features coming soon.'};break;} const rp=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${gk}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contents:[{parts:[{text:`You are an expert biology and pharmacy tutor. ${mode==='quiz'?'Generate quiz questions about:':mode==='summarize'?'Summarize this:':'Answer:'} ${prompt}`}]}]})}); const gd=await rp.json(); result={answer:gd.candidates?.[0]?.content?.parts?.[0]?.text||'No response generated.'}; break; }
      case 'get_donate_page_config': { result={nowpayments_api_key:process.env.NOWPAYMENTS_API_KEY||''}; break; }
      case 'submit_momo_donation': { const {error}=await supabase.from('momo_donations').insert({name:(name||'Anonymous').slice(0,100),amount:String(amount || '').slice(0,50),txid:txid.slice(0,100)}); if(error)throw error; result={success:true}; break; }
      case 'update_site_section': { const { section: sec, data: secData } = req.body; const { data: existing } = await supabase.from('site_sections').select('id').eq('section', sec).maybeSingle(); if (existing) { await supabase.from('site_sections').update({ data: secData }).eq('section', sec); } else { await supabase.from('site_sections').insert({ section: sec, data: secData }); } responseCache.delete('all_sections'); result = { success: true }; break; }
      case 'update_user_role': { const { userId: targetUserId, role } = req.body; if (role === 'admin') { const { data: existingAdmin } = await supabase.from('admin_master').select('id').eq('admin_id', targetUserId).maybeSingle(); if (!existingAdmin) { await supabase.from('admin_master').insert({ admin_id: targetUserId, admin_email: (await supabase.auth.admin.getUserById(targetUserId)).data?.user?.email || '', admin_role: 'content_manager', permissions: { can_manage_resources: true, can_manage_site_sections: true, can_view_analytics: true, can_upload_files: true } }); } else { await supabase.from('admin_master').update({ admin_role: 'content_manager', is_active: true }).eq('admin_id', targetUserId); } } result = { success: true }; break; }
      case 'update_user_lock': { const { userId: targetUserId, lock, reason } = req.body; await supabase.from('admin_master').update({ is_locked: lock, lock_reason: reason || null }).eq('admin_id', targetUserId); result = { success: true }; break; }
      case 'get_admin_users': { const { data } = await supabase.from('admin_master').select('*'); result = data || []; break; }
      case 'get_newsletter_subscribers': { const { data } = await supabase.from('newsletter_subscribers').select('*').order('created_at', { ascending: false }); result = data || []; break; }
      case 'get_donations': { const { data } = await supabase.from('momo_donations').select('*').order('created_at', { ascending: false }).limit(50); result = data || []; break; }
      case 'toggle_favorite': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { resource_id } = req.body;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', resource_id).eq('interaction_type', 'favorite').maybeSingle();
        if (existing) { await supabase.from('user_interactions').delete().eq('id', existing.id); result = { favorited: false }; }
        else { await supabase.from('user_interactions').insert({ user_id: userId, resource_id, interaction_type: 'favorite' }); result = { favorited: true }; }
        break;
      }
      case 'record_view': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        await supabase.from('user_interactions').insert({ user_id: userId, resource_id: req.body.resource_id, interaction_type: 'view' });
        result = { success: true };
        break;
      }
      case 'record_download': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        await supabase.from('user_interactions').insert({ user_id: userId, resource_id: req.body.resource_id, interaction_type: 'download' });
        result = { success: true };
        break;
      }
      case 'record_daily_visit': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const today = new Date().toISOString().slice(0,10);
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('interaction_type', 'daily_visit').gte('created_at', `${today}T00:00:00Z`).lte('created_at', `${today}T23:59:59Z`).limit(1);
        if (!existing || existing.length === 0) { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'daily_visit' }); }
        result = { success: true };
        break;
      }
      case 'get_recent_views': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const limit = req.body.limit || 5;
        const { data, error } = await supabase.from('user_interactions').select('resource_id, created_at, resources:biology_notes(title)').eq('user_id', userId).eq('interaction_type', 'view').order('created_at', { ascending: false }).limit(limit);
        if (error) throw error;
        result = (data || []).map(v => ({ resource_id: v.resource_id, title: v.resources?.title || null, created_at: v.created_at }));
        break;
      }
      case 'submit_rating': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { resource_id, rating, metadata } = req.body;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', resource_id).eq('interaction_type', 'rating').maybeSingle();
        if (existing) { await supabase.from('user_interactions').update({ value: rating, metadata: metadata || {}, created_at: new Date().toISOString() }).eq('id', existing.id); }
        else { await supabase.from('user_interactions').insert({ user_id: userId, resource_id, interaction_type: 'rating', value: rating, metadata: metadata || {} }); }
        result = { success: true };
        break;
      }
      case 'get_all_ratings': {
        const { data, error } = await supabase.from('user_interactions').select('resource_id, value').eq('interaction_type', 'rating');
        if (error) throw error;
        const agg = {};
        (data || []).forEach(r => { if (!agg[r.resource_id]) agg[r.resource_id] = { sum: 0, count: 0 }; agg[r.resource_id].sum += r.value; agg[r.resource_id].count += 1; });
        const resultObj = {};
        for (const [rid, { sum, count }] of Object.entries(agg)) { resultObj[rid] = { avg: +(sum / count).toFixed(1), count }; }
        result = resultObj;
        break;
      }
      case 'request_resource': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'resource_request', metadata: { title: sanitizeInput(req.body.title, 200), description: sanitizeInput(req.body.description || '', 1000) } });
        result = { success: true };
        break;
      }
      case 'save_achievement': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { badge } = req.body;
        await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'achievement', metadata: { badge: badge.id || badge, ...badge } });
        result = { success: true };
        break;
      }
      case 'get_public_stats': {
        const ck = 'public_stats'; const cached = getCachedResponse(ck);
        if (cached) { result = cached; break; }
        try {
          const [resCount, downCount, quizCount, usersCount] = await Promise.all([
            supabase.from('biology_notes').select('id', { count: 'exact', head: true }),
            supabase.from('user_interactions').select('id', { count: 'exact', head: true }).eq('interaction_type', 'download'),
            supabase.from('user_quiz_activity').select('id', { count: 'exact', head: true }),
            supabase.from('user_interactions').select('user_id', { count: 'exact', head: true, distinct: true })
          ]);
          result = { resources_count: resCount.count || 0, downloads_count: downCount.count || 0, quiz_attempts: quizCount.count || 0, users_count: usersCount.count || 0 };
          setCachedResponse(ck, result);
        } catch (err) { result = { resources_count: 0, downloads_count: 0, quiz_attempts: 0, users_count: 0 }; }
        break;
      }
      case 'request_chat': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { data: existingRoom } = await supabase.from('chat_rooms').select('id, status').eq('user_id', userId).neq('status', 'closed').maybeSingle();
        if (existingRoom) { result = { room_id: existingRoom.id, status: existingRoom.status }; break; }
        const { data: room, error: roomErr } = await supabase.from('chat_rooms').insert({ user_id: userId, status: 'requested' }).select().single();
        if (roomErr) throw roomErr;
        const { data: freeAdmin } = await supabase.from('admin_master').select('admin_id').eq('is_online', true).eq('is_busy', false).eq('is_active', true).limit(1).maybeSingle();
        if (freeAdmin) { await supabase.from('chat_rooms').update({ assigned_admin: freeAdmin.admin_id, status: 'active' }).eq('id', room.id); await supabase.from('admin_master').update({ is_busy: true, current_room: room.id }).eq('admin_id', freeAdmin.admin_id); room.status = 'active'; }
        result = { room_id: room.id, status: room.status };
        break;
      }
      case 'get_chat_messages': {
        const { room_id } = req.body;
        if (!room_id) return res.status(400).json({ error: 'room_id required' });
        if (!adminData) { const { data: room } = await supabase.from('chat_rooms').select('user_id').eq('id', room_id).single(); if (!room || room.user_id !== userId) return res.status(403).json({ error: 'Access denied' }); }
        let query = supabase.from('chat_messages').select('*').eq('room_id', room_id).order('created_at', { ascending: true });
        if (!adminData) query = query.eq('deleted_by_user', false);
        const { data, error } = await query; if (error) throw error; result = data || [];
        break;
      }
      case 'send_chat_message': {
        const { room_id, message } = req.body;
        if (!room_id || !message) return res.status(400).json({ error: 'room_id and message required' });
        if (!adminData) { const { data: room } = await supabase.from('chat_rooms').select('user_id,status').eq('id', room_id).single(); if (!room || room.user_id !== userId || room.status !== 'active') return res.status(403).json({ error: 'Not allowed' }); }
        else { const { data: room } = await supabase.from('chat_rooms').select('assigned_admin').eq('id', room_id).single(); if (!room || room.assigned_admin !== userId) return res.status(403).json({ error: 'Not your conversation' }); }
        const senderType = adminData ? 'admin' : 'user';
        const { data: msg, error } = await supabase.from('chat_messages').insert({ room_id, sender_type: senderType, content: sanitizeInput(message, 2000) }).select().single();
        if (error) throw error; result = msg;
        break;
      }
      case 'delete_chat_message': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { message_id } = req.body;
        const { data: msg } = await supabase.from('chat_messages').select('room_id').eq('id', message_id).single();
        if (!msg) return res.status(404).json({ error: 'Message not found' });
        const { data: room } = await supabase.from('chat_rooms').select('user_id').eq('id', msg.room_id).single();
        if (!room || room.user_id !== userId) return res.status(403).json({ error: 'Access denied' });
        await supabase.from('chat_messages').update({ deleted_by_user: true }).eq('id', message_id);
        result = { success: true };
        break;
      }
      case 'admin_get_pending_requests': {
        if (!adminData) return res.status(403).json({ error: 'Admin access required' });
        const { data, error } = await supabase.from('chat_rooms').select('id, user_id, requested_at, status').eq('status', 'requested').order('requested_at', { ascending: true });
        if (error) throw error;
        const requests = [];
        for (const r of (data || [])) { try { const { data: { user } } = await supabase.auth.admin.getUserById(r.user_id); const userName = user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User'; requests.push({ ...r, user_name: userName }); } catch { requests.push({ ...r, user_name: 'User' }); } }
        result = requests;
        break;
      }
      case 'admin_accept_chat': {
        if (!adminData) return res.status(403).json({ error: 'Admin access required' });
        const { room_id } = req.body;
        const { data: room } = await supabase.from('chat_rooms').select('status').eq('id', room_id).single();
        if (!room || room.status !== 'requested') return res.status(400).json({ error: 'Invalid request' });
        await supabase.from('chat_rooms').update({ status: 'active', assigned_admin: userId }).eq('id', room_id);
        await supabase.from('admin_master').update({ is_busy: true, current_room: room_id }).eq('admin_id', userId);
        result = { success: true };
        break;
      }
      case 'admin_reject_chat': {
        if (!adminData) return res.status(403).json({ error: 'Admin access required' });
        const { room_id } = req.body;
        await supabase.from('chat_rooms').update({ status: 'closed' }).eq('id', room_id).eq('status', 'requested');
        result = { success: true };
        break;
      }
      case 'admin_update_presence': {
        if (!adminData) return res.status(403).json({ error: 'Admin access required' });
        const { is_online, is_busy } = req.body;
        const update = {};
        if (typeof is_online === 'boolean') update.is_online = is_online;
        if (typeof is_busy === 'boolean') { update.is_busy = is_busy; if (!is_busy) update.current_room = null; }
        await supabase.from('admin_master').update(update).eq('admin_id', userId);
        result = { success: true };
        break;
      }
      case 'admin_get_active_chats': {
        if (!adminData) return res.status(403).json({ error: 'Admin access required' });
        const { data, error } = await supabase.from('chat_rooms').select('id, user_id, status, requested_at').eq('assigned_admin', userId).neq('status', 'closed').order('requested_at', { ascending: false });
        if (error) throw error;
        const chats = [];
        for (const r of (data || [])) { try { const { data: { user } } = await supabase.auth.admin.getUserById(r.user_id); const userName = user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User'; chats.push({ ...r, user_name: userName }); } catch { chats.push({ ...r, user_name: 'User' }); } }
        result = chats;
        break;
      }
      case 'check_admin_online': {
        const { data } = await supabase.from('admin_master').select('is_online, is_busy').eq('is_active', true).limit(1).maybeSingle();
        result = data ? { online: data.is_online, busy: data.is_busy } : { online: false, busy: false };
        break;
      }
      case 'upload_file': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { file_name, file_data } = req.body;
        if (!file_name || !file_data) return res.status(400).json({ error: 'file_name and file_data required' });
        const MAX_SIZE = 10 * 1024 * 1024;
        const base64Len = file_data.length - (file_data.indexOf(',') + 1);
        if (base64Len * 0.75 > MAX_SIZE) return res.status(400).json({ error: 'File too large (max 10 MB)' });
        const ext = file_name.split('.').pop().toLowerCase();
        const allowed = ['pdf','doc','docx','ppt','pptx','xls','xlsx','txt','zip'];
        if (!allowed.includes(ext)) return res.status(400).json({ error: 'Invalid file type' });
        const mimeMap = { pdf: 'application/pdf', doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', txt: 'text/plain', zip: 'application/zip' };
        const contentType = mimeMap[ext] || 'application/octet-stream';
        try {
          const buf = Buffer.from(file_data.replace(/^data:.*?;base64,/, ''), 'base64');
          const path = `uploads/${userId}/${Date.now()}_${sanitizeInput(file_name, 100)}`;
          const { data, error } = await supabase.storage.from('resources').upload(path, buf, { contentType });
          if (error) throw error;
          const { data: { publicUrl } } = supabase.storage.from('resources').getPublicUrl(path);
          result = { url: publicUrl, size: (buf.length / (1024*1024)).toFixed(2) + ' MB' };
        } catch(e) { return res.status(500).json({ error: 'Upload failed: ' + e.message }); }
        break;
      }
      case 'update_user_presence': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        await supabase.from('user_presence').upsert({ user_id: userId, last_seen: new Date().toISOString() }, { onConflict: 'user_id' });
        result = { success: true };
        break;
      }
      case 'get_online_users': {
        if (!adminData) return res.status(403).json({ error: 'Admin access required' });
        const { data, error } = await supabase.from('user_presence').select('user_id, last_seen').gte('last_seen', new Date(Date.now() - 5 * 60 * 1000).toISOString()).order('last_seen', { ascending: false });
        if (error) throw error;
        const users = [];
        for (const p of (data || [])) { try { const { data: { user } } = await supabase.auth.admin.getUserById(p.user_id); const userName = user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User'; users.push({ user_id: p.user_id, name: userName, last_seen: p.last_seen }); } catch { users.push({ user_id: p.user_id, name: 'User', last_seen: p.last_seen }); } }
        result = users;
        break;
      }
      case 'get_flashcards': {
        const { category } = req.body || {};
        let query = supabase.from('flashcards').select('*').order('created_at', { ascending: false });
        if (category) query = query.eq('category', category);
        const { data, error } = await query;
        if (error) throw error;
        result = data || [];
        break;
      }
      case 'toggle_flashcard_known': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { flashcard_id } = req.body;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('interaction_type', 'flashcard_known').eq('metadata->>flashcard_id', String(flashcard_id)).maybeSingle();
        if (existing) { await supabase.from('user_interactions').delete().eq('id', existing.id); result = { known: false }; }
        else { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'flashcard_known', resource_id: null, metadata: { flashcard_id: flashcard_id } }); result = { known: true }; }
        break;
      }
      case 'get_known_flashcards': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_interactions').select('metadata').eq('user_id', userId).eq('interaction_type', 'flashcard_known');
        if (error) throw error;
        result = (data || []).map(row => row.metadata?.flashcard_id).filter(Boolean);
        break;
      }
      case 'get_community_activity': {
        const { data: downloads } = await supabase.from('user_interactions').select('created_at, resource_id, resources:biology_notes(title)').eq('interaction_type', 'download').order('created_at', { ascending: false }).limit(5);
        const { data: quizCompletions } = await supabase.from('user_quiz_activity').select('completed_at, level, topic, percentage').eq('passed', true).order('completed_at', { ascending: false }).limit(5);
        const activities = [];
        (downloads || []).forEach(d => { const title = d.resources?.title || 'a resource'; activities.push({ type: 'download', message: `A learner downloaded "${title}"`, time: d.created_at }); });
        (quizCompletions || []).forEach(q => { activities.push({ type: 'quiz', message: `A learner passed a ${q.level} quiz on ${q.topic} with ${q.percentage}%`, time: q.completed_at }); });
        activities.sort((a, b) => new Date(b.time) - new Date(a.time));
        result = activities.slice(0, 10);
        break;
      }
      case 'submit_weekly_challenge': {
        const { week_start, selected_option } = req.body;
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { data: existing } = await supabase.from('user_interactions').select('metadata').eq('user_id', userId).eq('interaction_type', 'weekly_challenge_answer').eq('metadata->>week_start', week_start).maybeSingle();
        if (selected_option === null || selected_option === undefined) {
          if (existing) { const metadata = existing.metadata || {}; const { data: wcData } = await supabase.from('site_sections').select('data').eq('section', 'weekly_challenge').single(); const challenge = wcData?.data || {}; result = { already_answered: true, selected_option: metadata.selected_option, correct: metadata.is_correct, explanation: challenge.explanation || '' }; }
          else { result = { already_answered: false }; }
        } else {
          if (existing) return res.status(409).json({ error: 'Already answered this week' });
          const { data: wcData } = await supabase.from('site_sections').select('data').eq('section', 'weekly_challenge').single();
          const challenge = wcData?.data || {};
          const isCorrect = selected_option === challenge.correct;
          await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'weekly_challenge_answer', resource_id: null, metadata: { week_start, selected_option, is_correct: isCorrect } });
          result = { already_answered: true, selected_option, correct: isCorrect, explanation: challenge.explanation || '' };
        }
        break;
      }
      case 'check_flashcard_answer': {
        const { flashcard_id, user_answer } = req.body;
        const { data: card, error } = await supabase.from('flashcards').select('back_text').eq('id', flashcard_id).single();
        if (error || !card) return res.status(404).json({ error: 'Flashcard not found' });
        const correctAnswer = (card.back_text || '').trim();
        const userAnswerTrimmed = user_answer.trim();
        const isCorrect = correctAnswer.toLowerCase() === userAnswerTrimmed.toLowerCase();
        result = { correct: isCorrect, correct_answer: correctAnswer };
        break;
      }
      case 'rate_flashcard': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { flashcard_id, difficulty } = req.body;
        const difficultyValue = difficulty === 'easy' ? 3 : difficulty === 'medium' ? 2 : 1;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', flashcard_id).eq('interaction_type', 'rating').eq('metadata->>type', 'flashcard_difficulty').maybeSingle();
        if (existing) { await supabase.from('user_interactions').update({ value: difficultyValue, metadata: { difficulty, type: 'flashcard_difficulty' }, created_at: new Date().toISOString() }).eq('id', existing.id); }
        else { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'rating', resource_id: flashcard_id, value: difficultyValue, metadata: { difficulty, type: 'flashcard_difficulty' } }); }
        result = { success: true };
        break;
      }
      case 'toggle_flashcard_bookmark': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { flashcard_id } = req.body;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', flashcard_id).eq('interaction_type', 'favorite').eq('metadata->>type', 'flashcard_bookmark').maybeSingle();
        if (existing) { await supabase.from('user_interactions').delete().eq('id', existing.id); result = { bookmarked: false }; }
        else { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'favorite', resource_id: flashcard_id, metadata: { type: 'flashcard_bookmark' } }); result = { bookmarked: true }; }
        break;
      }
      case 'like_resource': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { resource_id } = req.body;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', resource_id).eq('interaction_type', 'favorite').eq('metadata->>type', 'like').maybeSingle();
        if (existing) { await supabase.from('user_interactions').delete().eq('id', existing.id); }
        else { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'favorite', resource_id: resource_id, metadata: { type: 'like' } }); }
        const { count } = await supabase.from('user_interactions').select('id', { count: 'exact', head: true }).eq('resource_id', resource_id).eq('interaction_type', 'favorite').eq('metadata->>type', 'like');
        result = { liked: !existing, like_count: count || 0 };
        break;
      }
      case 'comment_resource': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { resource_id, comment } = req.body;
        await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'review', resource_id: resource_id, metadata: { comment: sanitizeInput(comment, 1000) } });
        result = { success: true };
        break;
      }
      case 'get_resource_interactions': {
        const { resource_id } = req.body;
        const { count: likeCount } = await supabase.from('user_interactions').select('id', { count: 'exact', head: true }).eq('resource_id', resource_id).eq('interaction_type', 'favorite').eq('metadata->>type', 'like');
        const { data: comments } = await supabase.from('user_interactions').select('metadata, created_at, user_id').eq('resource_id', resource_id).eq('interaction_type', 'review').order('created_at', { ascending: false }).limit(20);
        const commentList = [];
        if (comments) {
          for (const c of comments) {
            try { const { data: { user } } = await supabase.auth.admin.getUserById(c.user_id); const userName = user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, x => x.toUpperCase()) : 'User'; commentList.push({ comment: c.metadata?.comment || '', user_name: userName, created_at: c.created_at }); }
            catch { commentList.push({ comment: c.metadata?.comment || '', user_name: 'User', created_at: c.created_at }); }
          }
        }
        result = { like_count: likeCount || 0, comments: commentList };
        break;
      }
      case 'submit_mood': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { mood, message } = req.body;
        await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'mood', resource_id: null, metadata: { mood, message: sanitizeInput(message || '', 500) } });
        result = { success: true };
        break;
      }
      case 'get_flashcard_progress': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { data: knownCards } = await supabase.from('user_interactions').select('metadata').eq('user_id', userId).eq('interaction_type', 'flashcard_known');
        const knownIds = (knownCards || []).map(row => row.metadata?.flashcard_id).filter(Boolean);
        const { data: allCards } = await supabase.from('flashcards').select('category');
        const progress = {};
        (allCards || []).forEach(card => { if (!progress[card.category]) progress[card.category] = { reviewed: 0, total: 0 }; progress[card.category].total++; });
        if (knownIds.length > 0) {
          const { data: knownCardData } = await supabase.from('flashcards').select('category').in('id', knownIds);
          (knownCardData || []).forEach(card => { if (progress[card.category]) progress[card.category].reviewed++; });
        }
        result = progress;
        break;
      }
      default: throw new Error('Unknown action');
    }
    responseCache.delete('all_sections'); responseCache.delete('stats');
    return res.status(200).json({ data: result });
  } catch (error) { console.error('POST Error:', error.message); logSecurityEvent('POST_ERROR',{action,error:error.message},req); return res.status(500).json({error:'Internal server error'}); }
}
