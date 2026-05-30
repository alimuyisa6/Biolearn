const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

 const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
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
  'get_flashcards', 'get_flashcard_decks', 'get_flashcard_deck',
  'create_flashcard_deck', 'update_flashcard_deck', 'delete_flashcard_deck',
  'add_flashcard_cards', 'remove_flashcard_card',
  'toggle_flashcard_known', 'get_known_flashcards',
  'get_community_activity',
  'submit_weekly_challenge',
  'get_section_headings', 'update_section_headings',
  'check_flashcard_answer', 'rate_flashcard', 'toggle_flashcard_bookmark',
  'like_resource', 'comment_resource', 'get_resource_interactions',
  'submit_mood', 'get_flashcard_progress',
  'get_category_suggestions',
  'track_page_activity', 'get_page_activity',
  'update_newsletter_subscriber', 'delete_quiz_topic',
  'get_pdfs_by_level', 'check_pdf_restriction', 'track_pdf_preview', 'track_pdf_download',
   'get_notes_structure', 'get_note_content', 'get_note_preview', 'toggle_note_reaction', 'get_note_reactions',
 'update_user_restriction',
  'get_notes_by_level',
'save_reading_progress', 'get_reading_progress', 'get_continue_reading'
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
  'get_flashcards', 'get_flashcard_decks', 'get_flashcard_deck',
  'get_community_activity',
  'get_section_headings',
  'check_flashcard_answer',
  'get_resource_interactions',
  'get_pdfs_by_level',
 'get_notes_structure', 'get_note_content', 'get_note_preview', 'toggle_note_reaction', 'get_note_reactions',
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
  'create_flashcard_deck', 'update_flashcard_deck', 'delete_flashcard_deck',
  'add_flashcard_cards', 'remove_flashcard_card',
  'toggle_flashcard_known',
  'submit_weekly_challenge',
  'update_section_headings',
  'rate_flashcard', 'toggle_flashcard_bookmark',
  'like_resource', 'comment_resource', 'submit_mood',
  'track_page_activity',
  'update_newsletter_subscriber', 'delete_quiz_topic',
  'track_pdf_preview', 'track_pdf_download',
  'get_notes_structure', 'get_note_content', 'toggle_note_reaction', 'get_note_reactions',
  'update_user_restriction',
  'get_notes_by_level',
'save_reading_progress'
]);

const ADMIN_ACTIONS = new Set([
  'approve', 'submissions', 'messages', 'stats',
  'update_site_section', 'update_user_role', 'update_user_lock',
  'get_admin_users', 'get_newsletter_subscribers', 'get_donations',
  'add_quiz_questions_batch',
  'update_app_feature',
  'admin_get_pending_requests', 'admin_accept_chat', 'admin_reject_chat',
  'admin_update_presence', 'admin_get_active_chats', 'get_online_users',
  'update_section_headings',
  'create_flashcard_deck', 'update_flashcard_deck', 'delete_flashcard_deck',
  'add_flashcard_cards', 'remove_flashcard_card',
  'get_page_activity',
  'update_newsletter_subscriber', 'delete_quiz_topic',
  'update_user_restriction'
]);

const SUPER_ADMIN_ONLY_ACTIONS = new Set([
  'messages', 'stats',
  'update_user_role', 'update_user_lock',
  'get_admin_users', 'get_donations',
  'admin_get_pending_requests', 'admin_accept_chat', 'admin_reject_chat',
  'admin_get_active_chats', 'get_online_users',
  'get_page_activity',
  'delete_flashcard_deck', 'delete_quiz_topic',
  'update_user_restriction'
]);

const CONTENT_MANAGER_ACTIONS = new Set([
  'submit_resource', 'upload_file',
  'create_flashcard_deck', 'update_flashcard_deck', 'add_flashcard_cards', 'remove_flashcard_card',
  'update_section_headings', 'update_site_section',
  'add_quiz_questions_batch',
  'update_app_feature',
  'approve', 'submissions',
  'get_newsletter_subscribers', 'update_newsletter_subscriber',
  'admin_update_presence'
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
    .select('admin_id, admin_role, permissions, is_active, is_locked, ip_whitelist')
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

function rateLimit(ip, action = null, isSuperAdmin = false) {
  if (isSuperAdmin) return true;
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
  update_user_restriction: (body) => {
    if (!body.userId) return 'User ID required';
    if (!body.restriction_type || !['locked', 'suspended', 'disabled', 'remove'].includes(body.restriction_type)) return 'Invalid restriction type';
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
  toggle_favorite: (body) => { if (!body.resource_id) return 'resource_id required'; return null; },
  record_view: (body) => { if (!body.resource_id) return 'resource_id required'; return null; },
  record_download: (body) => { if (!body.resource_id) return 'resource_id required'; return null; },
  submit_rating: (body) => {
    if (!body.resource_id) return 'resource_id required';
    if (!body.rating || typeof body.rating !== 'number' || body.rating < 1 || body.rating > 5) return 'rating must be between 1 and 5';
    return null;
  },
  request_resource: (body) => { if (!body.title || typeof body.title !== 'string' || body.title.trim().length === 0) return 'title required'; return null; },
  save_achievement: (body) => { if (!body.badge || typeof body.badge !== 'object') return 'badge required'; return null; },
  get_flashcards: (body) => null,
  get_flashcard_decks: (body) => null,
  get_flashcard_deck: (body) => { if (!body.deck_id) return 'deck_id required'; return null; },
  create_flashcard_deck: (body) => {
    if (!body.title || typeof body.title !== 'string' || body.title.trim().length === 0) return 'Title required';
    if (!body.cards || !Array.isArray(body.cards) || body.cards.length === 0) return 'Cards required';
    return null;
  },
  update_flashcard_deck: (body) => {
    if (!body.deck_id) return 'deck_id required';
    if (!body.title || typeof body.title !== 'string' || body.title.trim().length === 0) return 'Title required';
    return null;
  },
  delete_flashcard_deck: (body) => { if (!body.deck_id) return 'deck_id required'; return null; },
  add_flashcard_cards: (body) => {
    if (!body.deck_id) return 'deck_id required';
    if (!body.cards || !Array.isArray(body.cards) || body.cards.length === 0) return 'Cards required';
    return null;
  },
  remove_flashcard_card: (body) => { if (!body.card_id) return 'card_id required'; return null; },
  get_section_headings: (body) => null,
  toggle_flashcard_known: (body) => { if (!body.flashcard_id) return 'flashcard_id required'; return null; },
  get_known_flashcards: (body) => null,
  get_community_activity: (body) => null,
  submit_weekly_challenge: (body) => { if (!body.week_start) return 'week_start required'; return null; },
  check_flashcard_answer: (body) => { if (!body.flashcard_id) return 'flashcard_id required'; if (!body.user_answer || typeof body.user_answer !== 'string') return 'user_answer required'; return null; },
  rate_flashcard: (body) => { if (!body.flashcard_id) return 'flashcard_id required'; if (!body.difficulty || !['easy','medium','hard'].includes(body.difficulty)) return 'Invalid difficulty'; return null; },
  toggle_flashcard_bookmark: (body) => { if (!body.flashcard_id) return 'flashcard_id required'; return null; },
  like_resource: (body) => { if (!body.resource_id) return 'resource_id required'; return null; },
  comment_resource: (body) => { if (!body.resource_id) return 'resource_id required'; if (!body.comment || typeof body.comment !== 'string' || body.comment.trim().length === 0) return 'Comment required'; return null; },
  get_resource_interactions: (body) => { if (!body.resource_id) return 'resource_id required'; return null; },
  submit_mood: (body) => { if (!body.mood) return 'Mood required'; return null; },
  get_flashcard_progress: (body) => null,
  get_category_suggestions: (body) => null,
  track_page_activity: (body) => null,
  get_page_activity: (body) => null,
  update_newsletter_subscriber: (body) => { if (!body.id) return 'id required'; return null; },
  delete_quiz_topic: (body) => { if (!body.topic || !body.level) return 'topic and level required'; return null; },
  track_pdf_download: (body) => { if (!body.pdf_id) return 'pdf_id required'; return null; },
  get_notes_structure: (body) => { return null; },
   get_note_preview: (body) => { if (!body.subtopic_id) return 'subtopic_id required'; return null; },
  toggle_note_reaction: (body) => { if (!body.note_id) return 'note_id required'; if (!body.reaction_type) return 'reaction_type required'; return null; },
  get_note_reactions: (body) => { if (!body.note_id) return 'note_id required'; return null; },
save_reading_progress: (body) => {
  if (!body.note_id) return 'note_id required';
  if (typeof body.scroll_percentage !== 'number') return 'scroll_percentage required';
  if (body.scroll_percentage < 0 || body.scroll_percentage > 100) return 'scroll_percentage must be between 0 and 100';
  return null;
},
get_reading_progress: (body) => {
  if (!body.note_id) return 'note_id required';
  return null;
},
get_continue_reading: (body) => {
  return null;
}
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
  const cookies = parseCookies(req);
  const token = cookies.session || '';
  let isSuperAdmin = false;
  if (token) {
    try {
      const session = await validateSession(token);
      if (session) {
        const adminData = await isUserAdmin(session.user_id, ip);
        if (adminData && adminData.admin_role === 'super_admin') {
          isSuperAdmin = true;
        }
      }
    } catch(e) {}
  }
  if (!rateLimit(ip, req.body?.action, isSuperAdmin)) {
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
        result = data?.data || {};
        break;
      }
      case 'get_app_features': {
        const pageId = url.searchParams.get('page_id') || 'all';
        let query = supabase.from('app_features').select('*').eq('is_enabled', true);
        if (pageId !== 'all') query = query.eq('page_id', pageId);
        query = query.order('display_order');
        const { data, error } = await query;
        if (error) throw error;
        result = (data || []).map(f => ({ feature_key: f.feature_key, feature_name: f.feature_name, description: f.description, page_id: f.page_id, category: f.category, settings: f.settings, is_enabled: f.is_enabled, display_order: f.display_order, user_enabled: true, user_settings: {} }));
        break;
      }
      case 'get_all_site_sections': case 'get_all_sections': {
        const { data, error } = await supabase.from('site_sections').select('section, data');
        if (error) throw error;
        result = {}; (data || []).forEach(row => { result[row.section] = row.data; });
        if (!userId) setCachedResponse(cacheKey, result);
        break;
      }
      case 'get_resources': {
        let query = supabase.from('biology_notes').select('id,title,description,author,level,category,tag,section_type,file_url,file_size,download_count,created_at').order('created_at', { ascending: false }).limit(100);
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
      case 'get_flashcards': {
        const category = url.searchParams.get('category');
        let query = supabase.from('flashcards').select('*').order('created_at', { ascending: false });
        if (category) query = query.eq('category', category);
        const { data, error } = await query;
        if (error) throw error;
        result = data || [];
        break;
      }
      case 'get_flashcard_decks': {
        const { data, error } = await supabase.from('flashcard_decks').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        result = data || [];
        break;
      }
      case 'get_flashcard_deck': {
        const deckId = url.searchParams.get('deck_id');
        if (!deckId) return res.status(400).json({ error: 'deck_id required' });
        const { data: deck, error: deckErr } = await supabase.from('flashcard_decks').select('*').eq('id', deckId).single();
        if (deckErr) throw deckErr;
        if (!deck) return res.status(404).json({ error: 'Deck not found' });
        const { data: cards, error: cardsErr } = await supabase.from('flashcard_cards').select('*').eq('deck_id', deckId).order('id');
        if (cardsErr) throw cardsErr;
        result = { ...deck, cards: cards || [] };
        break;
      }
      case 'get_pdfs_by_level': {
        const level = url.searchParams.get('level');
        if (!level) return res.status(400).json({ error: 'Level required' });
        const { data, error } = await supabase
          .from('pdf_resources')
          .select('id, title, author, level, topic, subtopic, file_url, file_size, download_count, preview_count')
          .eq('level', level)
          .eq('is_active', true)
          .order('topic', { ascending: true })
          .order('title', { ascending: true });
        if (error) throw error;
        result = { pdfs: data || [] };
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

  if (adminData && SUPER_ADMIN_ONLY_ACTIONS.has(action) && adminData.admin_role !== 'super_admin') {
    return res.status(403).json({ error: 'Access denied. Super admin only.' });
  }

  if (adminData && adminData.admin_role !== 'super_admin' && !CONTENT_MANAGER_ACTIONS.has(action) && ADMIN_ACTIONS.has(action)) {
    return res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
  }

  try {
    let result;
    const { section, filters, formData, email, password, payload, submissionId, prompt, mode, name, amount, txid, room_id, message, is_online, is_busy, feature_key, is_enabled, settings, level, topic, questions, batch_name, deck_id, title, description, category, cards, card_id, difficulty, resource_id, rating, comment, badge, week_start, selected_option, flashcard_id, user_answer, user_id, page, metadata, userId: targetUserId, restriction_type, duration_hours, reason } = req.body;
    switch (action) {
      case 'get_all_site_sections': case 'get_all_sections': {
        const { data, error } = await supabase.from('site_sections').select('section, data');
        if (error) throw error;
        result = {};
        (data || []).forEach(row => { result[row.section] = row.data; });
        
        const { data: authUsers, error: authError } = await supabase.auth.admin.listUsers();
        if (!authError && authUsers?.users) {
          const { data: restrictions } = await supabase.from('user_restrictions').select('user_id, restriction_type, expires_at');
          const restrictionMap = new Map();
          (restrictions || []).forEach(r => restrictionMap.set(r.user_id, { type: r.restriction_type, expires_at: r.expires_at }));
          
          result.users = {
            list: authUsers.users.map(u => {
              const restriction = restrictionMap.get(u.id);
              return {
                id: u.id,
                email: u.email,
                restriction_type: restriction?.type || null,
                restriction_expires_at: restriction?.expires_at || null,
                created_at: u.created_at,
                last_active: u.last_sign_in_at || u.updated_at
              };
            })
          };
        } else {
          result.users = { list: [] };
        }
        break;
      }
      case 'get_category_suggestions': {
        const [resources, flashcardDecks, quizTopics] = await Promise.all([
          supabase.from('biology_notes').select('category, level, section_type').limit(500),
          supabase.from('flashcard_decks').select('category, level').limit(500),
          supabase.from('quiz_topics').select('level').limit(500)
        ]);
        const categories = [...new Set([...(resources.data||[]).map(r=>r.category).filter(Boolean), ...(flashcardDecks.data||[]).map(d=>d.category).filter(Boolean)])];
        const levels = [...new Set([...(resources.data||[]).map(r=>r.level).filter(Boolean), ...(flashcardDecks.data||[]).map(d=>d.level).filter(Boolean), ...(quizTopics.data||[]).map(t=>t.level).filter(Boolean)])];
        const sections = [...new Set((resources.data||[]).map(r=>r.section_type).filter(Boolean))];
        result = { categories, levels, sections };
        break;
      }
      case 'get_flashcard_decks': {
        const { data, error } = await supabase.from('flashcard_decks').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        const decks = [];
        for (const deck of (data || [])) {
          const { count } = await supabase.from('flashcard_cards').select('id', { count: 'exact', head: true }).eq('deck_id', deck.id);
          decks.push({ ...deck, card_count: count || 0 });
        }
        result = decks;
        break;
      }
      case 'get_flashcard_deck': {
        const deckId = req.body.deck_id || deck_id;
        if (!deckId) return res.status(400).json({ error: 'deck_id required' });
        const { data: deck, error: deckErr } = await supabase.from('flashcard_decks').select('*').eq('id', deckId).single();
        if (deckErr) throw deckErr;
        if (!deck) return res.status(404).json({ error: 'Deck not found' });
        const { data: cards, error: cardsErr } = await supabase.from('flashcard_cards').select('*').eq('deck_id', deckId).order('id');
        if (cardsErr) throw cardsErr;
        result = { ...deck, cards: cards || [] };
        break;
      }
      case 'create_flashcard_deck': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const deckTitle = req.body.title || title;
        const deckDesc = req.body.description || description || '';
        const deckCat = req.body.category || category || '';
        const deckLevel = req.body.level || level || '';
        const deckCards = req.body.cards || cards || [];
        const author = userEmail ? userEmail.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'Admin';
        const { data: deck, error: deckErr } = await supabase.from('flashcard_decks').insert({
          title: sanitizeInput(deckTitle, 200),
          description: sanitizeInput(deckDesc, 1000),
          category: sanitizeInput(deckCat, 100),
          level: sanitizeInput(deckLevel, 50),
          author: author,
          created_by: userId
        }).select().single();
        if (deckErr) throw deckErr;
        if (deckCards.length > 0) {
          const cardInserts = deckCards.map((card, index) => ({
            deck_id: deck.id,
            front_text: sanitizeInput(card.front, 500),
            back_text: sanitizeInput(card.back, 2000),
            position: index
          }));
          await supabase.from('flashcard_cards').insert(cardInserts);
        }
        result = { success: true, deck_id: deck.id };
        responseCache.delete('all_sections');
        break;
      }
      case 'update_flashcard_deck': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const deckId = req.body.deck_id || deck_id;
        const deckTitle = req.body.title || title;
        const deckDesc = req.body.description || description || '';
        const deckCat = req.body.category || category || '';
        const deckLevel = req.body.level || level || '';
        const deckCards = req.body.cards || cards || [];
        await supabase.from('flashcard_decks').update({
          title: sanitizeInput(deckTitle, 200),
          description: sanitizeInput(deckDesc, 1000),
          category: sanitizeInput(deckCat, 100),
          level: sanitizeInput(deckLevel, 50),
          updated_at: new Date().toISOString()
        }).eq('id', deckId);
        if (deckCards.length > 0) {
          await supabase.from('flashcard_cards').delete().eq('deck_id', deckId);
          const cardInserts = deckCards.map((card, index) => ({
            deck_id: deckId,
            front_text: sanitizeInput(card.front, 500),
            back_text: sanitizeInput(card.back, 2000),
            position: index
          }));
          await supabase.from('flashcard_cards').insert(cardInserts);
        }
        result = { success: true };
        responseCache.delete('all_sections');
        break;
      }
      case 'delete_flashcard_deck': {
        const deckId = req.body.deck_id || deck_id;
        await supabase.from('flashcard_cards').delete().eq('deck_id', deckId);
        await supabase.from('flashcard_decks').delete().eq('id', deckId);
        result = { success: true };
        responseCache.delete('all_sections');
        break;
      }
      case 'add_flashcard_cards': {
        const deckId = req.body.deck_id || deck_id;
        const deckCards = req.body.cards || cards || [];
        const cardInserts = deckCards.map((card, index) => ({
          deck_id: deckId,
          front_text: sanitizeInput(card.front, 500),
          back_text: sanitizeInput(card.back, 2000),
          position: index
        }));
        await supabase.from('flashcard_cards').insert(cardInserts);
        result = { success: true };
        break;
      }
      case 'remove_flashcard_card': {
        const cardId = req.body.card_id || card_id;
        await supabase.from('flashcard_cards').delete().eq('id', cardId);
        result = { success: true };
        break;
      }
      case 'track_page_activity': {
        const pageName = req.body.page || page || 'unknown';
        const pageMetadata = req.body.metadata || metadata || {};
        if (userId) {
          await supabase.from('page_activity').insert({
            user_id: userId,
            page: sanitizeInput(pageName, 100),
            metadata: pageMetadata,
            ip_address: ip,
            user_agent: (req.headers['user-agent'] || '').substring(0, 500)
          });
        } else {
          await supabase.from('page_activity').insert({
            page: sanitizeInput(pageName, 100),
            metadata: pageMetadata,
            ip_address: ip,
            user_agent: (req.headers['user-agent'] || '').substring(0, 500),
            is_anonymous: true
          });
        }
        result = { success: true };
        break;
      }
      case 'get_page_activity': {
        if (!adminData || adminData.admin_role !== 'super_admin') return res.status(403).json({ error: 'Super admin access required' });
        const { data, error } = await supabase.from('page_activity').select('*').order('created_at', { ascending: false }).limit(100);
        if (error) throw error;
        const activities = [];
        for (const act of (data || [])) {
          const activity = { ...act };
          if (act.user_id) {
            try {
              const { data: { user } } = await supabase.auth.admin.getUserById(act.user_id);
              activity.user_email = user?.email || 'Unknown';
              activity.user_name = user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User';
            } catch { activity.user_email = 'Unknown'; activity.user_name = 'User'; }
          }
          activities.push(activity);
        }
        result = activities;
        break;
      }
      case 'submit_contact': {
        const emailAddr = (formData?.email || email || '').trim().slice(0,254);
        const twentyFourHoursAgo = new Date(Date.now() - 24*60*60*1000).toISOString();
        const { data: recent } = await supabase.from('contact_messages').select('id').eq('email', emailAddr).gte('created_at', twentyFourHoursAgo).limit(1);
        if (recent && recent.length > 0) {
          return res.status(429).json({ error: 'You can only send one message every 24 hours. Please try again later.' });
        }
        const nameVal = (formData?.name || name || '').trim().slice(0,100);
        const subjectVal = (formData?.subject || '').trim().slice(0,200);
        const messageVal = (formData?.message || message || '').trim().slice(0,5000);
        const { error: insertErr } = await supabase.from('contact_messages').insert({
          name: sanitizeInput(nameVal, 100),
          email: emailAddr,
          subject: sanitizeInput(subjectVal, 200),
          message: sanitizeInput(messageVal, 5000)
        });
        if (insertErr) throw insertErr;
        result = { success: true };
        break;
      }
      case 'subscribe_newsletter': {
        const subscriberEmail = (formData?.email || email || '').trim().slice(0,254);
        const { error } = await supabase.from('newsletter_subscribers').insert({ email: subscriberEmail });
        if (error && error.code !== '23505') throw error;
        result = { success: true };
        break;
      }
      case 'signup': {
        if(!rateLimit(ip,'signup'))return res.status(429).json({error:'Please wait a moment.'});
        const userEmail = (email || '').trim().toLowerCase();
        const userPassword = password || '';
        if (userPassword.length < 8) return res.status(400).json({error:'Password must be at least 8 characters.'});
        const {data,error:signupErr}=await supabase.auth.signUp({email:userEmail,password:userPassword,options:{emailRedirectTo:`${req.headers['x-forwarded-proto']||'https'}://${req.headers.host}`}});
        if(signupErr){if(signupErr.code==='user_already_exists')return res.status(200).json({data:{user:null,session:null,message:'Account exists. Check your email.'}});trackFailedAuth(ip,userEmail);throw signupErr;}
        resetFailedAuth(ip,userEmail);
        if (data.session) { const cs = await createUserSession(data.user.id, data.user.email, ip, req.headers['user-agent']); const cookieValue = `session=${cs.access_token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}; Path=/`; res.setHeader('Set-Cookie', cookieValue); result = { user: { id: data.user.id, email: data.user.email } }; }
        else { result = { user: null }; }
        break;
      }
 case 'signin': {
  if(!rateLimit(ip,'signin'))return res.status(429).json({error:'Please wait a moment.'});
  const userEmail = (email || '').trim().toLowerCase();
  const userPassword = password || '';
  
  const {data,error:signinErr}=await supabase.auth.signInWithPassword({email:userEmail,password:userPassword});
  if(signinErr){const banned=trackFailedAuth(ip,userEmail);if(banned)return res.status(429).json({error:'Too many failed attempts. Account locked for 15 minutes.'});throw signinErr;}
  resetFailedAuth(ip,userEmail);
  
  const { data: restriction } = await supabase
    .from('user_restrictions')
    .select('restriction_type, lock_reason, expires_at')
    .eq('user_id', data.user.id)
    .maybeSingle();
  
  if (restriction) {
    if (restriction.restriction_type === 'disabled') {
      try { await supabase.auth.admin.updateUserById(data.user.id, { ban_duration: '1000y' }); } catch(e) {}
      return res.status(403).json({ error: 'Your account has been permanently disabled. Contact support.' });
    }
    if (restriction.restriction_type === 'suspended') {
      try { await supabase.auth.admin.updateUserById(data.user.id, { ban_duration: '1000y' }); } catch(e) {}
      return res.status(403).json({ error: restriction.lock_reason || 'Your account has been suspended. Contact support.' });
    }
    if (restriction.restriction_type === 'locked') {
      if (restriction.expires_at && new Date(restriction.expires_at) > new Date()) {
        const hoursLeft = Math.ceil((new Date(restriction.expires_at) - new Date()) / (1000 * 60 * 60));
        return res.status(403).json({ error: `Your account is locked. Try again in ${hoursLeft} hours.` });
      } else {
        await supabase.from('user_restrictions').delete().eq('user_id', data.user.id);
      }
    }
  }
  
  const session = await createUserSession(data.user.id, data.user.email, ip, req.headers['user-agent']);
  const cookieValue = `session=${session.access_token}; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}; Path=/`;
  res.setHeader('Set-Cookie', cookieValue);
  result = { user: { id: data.user.id, email: data.user.email } };
  break;
}
      case 'signout': {
        if (token) { const ht = hashToken(token); await supabase.from('user_sessions').update({ is_active: false }).eq('session_token_hash', ht); }
        res.setHeader('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/');
        result={success:true};
        break;
      }
      case 'get_user': {
        if(!userId){result={user:null};break;}
        let restriction = null;
        const { data: restrictionData } = await supabase
          .from('user_restrictions')
          .select('restriction_type, lock_reason, expires_at')
          .eq('user_id', userId)
          .maybeSingle();
        if (restrictionData) restriction = restrictionData;
        result={ user: { id: userId, email: userEmail, is_admin: !!adminData, admin_role: adminData?.admin_role || null, permissions: adminData?.permissions || null, restriction: restriction } };
        break;
      }
      case 'update_user_restriction': {
        const targetUserId = req.body.userId || user_id;
        const restrictionType = req.body.restriction_type || restriction_type;
        const lockReason = req.body.reason || reason || '';
        const durationHours = req.body.duration_hours || duration_hours || 24;
        
        if (!targetUserId || !restrictionType) {
          return res.status(400).json({ error: 'userId and restriction_type required' });
        }
        
        if (restrictionType === 'disabled') {
          await supabase.from('user_restrictions').upsert({
            user_id: targetUserId,
            restriction_type: 'disabled',
            lock_reason: sanitizeInput(lockReason, 200),
            locked_by: userId,
            locked_at: new Date().toISOString(),
            is_permanent: true,
            updated_at: new Date().toISOString()
          }, { onConflict: 'user_id' });
          try {
            await supabase.auth.admin.updateUserById(targetUserId, { ban_duration: '1000y' });
          } catch(e) {}
        } else if (restrictionType === 'suspended') {
          await supabase.from('user_restrictions').upsert({
            user_id: targetUserId,
            restriction_type: 'suspended',
            lock_reason: sanitizeInput(lockReason, 200),
            locked_by: userId,
            locked_at: new Date().toISOString(),
            is_permanent: true,
            updated_at: new Date().toISOString()
          }, { onConflict: 'user_id' });
        } else if (restrictionType === 'locked') {
          const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000).toISOString();
          await supabase.from('user_restrictions').upsert({
            user_id: targetUserId,
            restriction_type: 'locked',
            lock_reason: sanitizeInput(lockReason, 200),
            locked_by: userId,
            locked_at: new Date().toISOString(),
            expires_at: expiresAt,
            is_permanent: false,
            updated_at: new Date().toISOString()
          }, { onConflict: 'user_id' });
        } else if (restrictionType === 'remove') {
          await supabase.from('user_restrictions').delete().eq('user_id', targetUserId);
          try {
            await supabase.auth.admin.updateUserById(targetUserId, { ban_duration: '0s' });
          } catch(e) {}
        }
        
        result = { success: true };
        break;
      }
      case 'get_chat_messages': {
        if (!room_id) return res.status(400).json({ error: 'room_id required' });
        if (!adminData) { const { data: room } = await supabase.from('chat_rooms').select('user_id').eq('id', room_id).single(); if (!room || room.user_id !== userId) return res.status(403).json({ error: 'Access denied' }); }
        let query = supabase.from('chat_messages').select('*').eq('room_id', room_id).order('created_at', { ascending: true });
        if (!adminData) query = query.eq('deleted_by_user', false);
        const { data, error } = await query;
        if (error) throw error;
        result = (data || []).map(msg => ({
          ...msg,
          created_at: msg.created_at,
          formatted_time: new Date(msg.created_at).toISOString()
        }));
        break;
      }
      case 'send_chat_message': {
        if (!room_id || !message) return res.status(400).json({ error: 'room_id and message required' });
        if (!adminData) {
          const { data: room } = await supabase.from('chat_rooms').select('user_id,status').eq('id', room_id).single();
          if (!room || room.user_id !== userId || room.status !== 'active') return res.status(403).json({ error: 'Not allowed' });
          const twentyFourHoursAgo = new Date(Date.now() - 24*60*60*1000).toISOString();
          const { data: recentMsg } = await supabase.from('chat_messages').select('id').eq('room_id', room_id).eq('sender_type', 'user').gte('created_at', twentyFourHoursAgo).limit(1);
          if (recentMsg && recentMsg.length > 0) {
            return res.status(429).json({ error: 'You can only send one message every 24 hours. Please wait.' });
          }
        }
        const senderType = adminData ? 'admin' : 'user';
        const { data: msg, error } = await supabase.from('chat_messages').insert({
          room_id,
          sender_type: senderType,
          content: sanitizeInput(message, 2000),
          created_at: new Date().toISOString()
        }).select().single();
        if (error) throw error;
        result = { ...msg, formatted_time: new Date(msg.created_at).toISOString() };
        break;
      }
      case 'delete_chat_message': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const messageId = req.body.message_id;
        if (!messageId) return res.status(400).json({ error: 'message_id required' });
        const { data: msg } = await supabase.from('chat_messages').select('room_id').eq('id', messageId).single();
        if (!msg) return res.status(404).json({ error: 'Message not found' });
        const { data: room } = await supabase.from('chat_rooms').select('user_id').eq('id', msg.room_id).single();
        if (!room || room.user_id !== userId) return res.status(403).json({ error: 'Access denied' });
        await supabase.from('chat_messages').update({ deleted_by_user: true }).eq('id', messageId);
        result = { success: true };
        break;
      }
      case 'admin_get_pending_requests': {
        const { data, error } = await supabase.from('chat_rooms').select('id, user_id, requested_at, status').eq('status', 'requested').order('requested_at', { ascending: true });
        if (error) throw error;
        const requests = [];
        for (const r of (data || [])) {
          try {
            const { data: { user } } = await supabase.auth.admin.getUserById(r.user_id);
            requests.push({ ...r, user_name: user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User', requested_at: r.requested_at });
          } catch { requests.push({ ...r, user_name: 'User', requested_at: r.requested_at }); }
        }
        result = requests;
        break;
      }
      case 'admin_accept_chat': {
        const { data: room } = await supabase.from('chat_rooms').select('status').eq('id', room_id).single();
        if (!room || room.status !== 'requested') return res.status(400).json({ error: 'Invalid request' });
        await supabase.from('chat_rooms').update({ status: 'active', assigned_admin: userId }).eq('id', room_id);
        await supabase.from('admin_master').update({ is_busy: true, current_room: room_id }).eq('admin_id', userId);
        result = { success: true };
        break;
      }
      case 'admin_reject_chat': {
        await supabase.from('chat_rooms').update({ status: 'closed' }).eq('id', room_id).eq('status', 'requested');
        result = { success: true };
        break;
      }
      case 'admin_update_presence': {
        const update = {};
        if (typeof is_online === 'boolean') update.is_online = is_online;
        if (typeof is_busy === 'boolean') { update.is_busy = is_busy; if (!is_busy) update.current_room = null; }
        await supabase.from('admin_master').update(update).eq('admin_id', userId);
        result = { success: true };
        break;
      }
      case 'admin_get_active_chats': {
        const { data, error } = await supabase.from('chat_rooms').select('id, user_id, status, requested_at, created_at').eq('assigned_admin', userId).neq('status', 'closed').order('requested_at', { ascending: false });
        if (error) throw error;
        const chats = [];
        for (const r of (data || [])) {
          try {
            const { data: { user } } = await supabase.auth.admin.getUserById(r.user_id);
            chats.push({ ...r, user_name: user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User' });
          } catch { chats.push({ ...r, user_name: 'User' }); }
        }
        result = chats;
        break;
      }
      case 'update_user_lock': {
        const targetUserId = req.body.userId || user_id;
        const lockStatus = req.body.lock !== undefined ? req.body.lock : false;
        const lockReason = req.body.reason || (lockStatus ? 'Locked by admin' : 'Unlocked by admin');
        if (lockStatus) {
          await supabase.from('admin_master').update({ is_locked: true, lock_reason: sanitizeInput(lockReason, 200) }).eq('admin_id', targetUserId);
        } else {
          await supabase.from('admin_master').update({ is_locked: false, lock_reason: null }).eq('admin_id', targetUserId);
        }
        result = { success: true };
        break;
      }
      case 'update_user_role': {
        const targetUserId = req.body.userId || user_id;
        const targetRole = req.body.role || 'admin';
        if (targetRole === 'super_admin') {
          return res.status(403).json({ error: 'Cannot promote to super admin via API' });
        }
        if (targetRole === 'admin' || targetRole === 'content_manager' || targetRole === 'resource_manager') {
          const { data: existingAdmin } = await supabase.from('admin_master').select('id').eq('admin_id', targetUserId).maybeSingle();
          if (!existingAdmin) {
            const { data: { user } } = await supabase.auth.admin.getUserById(targetUserId);
            await supabase.from('admin_master').insert({
              admin_id: targetUserId,
              admin_email: user?.email || '',
              admin_role: targetRole,
              permissions: { can_manage_resources: true, can_manage_site_sections: targetRole !== 'resource_manager', can_view_analytics: true, can_upload_files: true }
            });
          } else {
            await supabase.from('admin_master').update({ admin_role: targetRole, is_active: true }).eq('admin_id', targetUserId);
          }
        }
        result = { success: true };
        break;
      }
      case 'update_site_section': {
        const secName = req.body.section || section;
        const secData = req.body.data || {};
        const { data: existing } = await supabase.from('site_sections').select('id').eq('section', secName).maybeSingle();
        if (existing) { await supabase.from('site_sections').update({ data: secData }).eq('section', secName); }
        else { await supabase.from('site_sections').insert({ section: secName, data: secData }); }
        responseCache.delete('all_sections');
        result = { success: true };
        break;
      }
      case 'update_section_headings': {
        const headings = req.body.headings || {};
        const { data: existing } = await supabase.from('site_sections').select('id').eq('section', 'section_headings').maybeSingle();
        if (existing) { await supabase.from('site_sections').update({ data: headings }).eq('section', 'section_headings'); }
        else { await supabase.from('site_sections').insert({ section: 'section_headings', data: headings }); }
        responseCache.delete('all_sections');
        result = { success: true };
        break;
      }
      case 'submit_resource': {
        const resourcePayload = payload || {};
        const { error } = await supabase.from('resource_submissions').insert({
          title: sanitizeInput(resourcePayload.title || '', 200),
          description: sanitizeInput(resourcePayload.description || '', 5000),
          author: sanitizeInput(resourcePayload.author || '', 100),
          level: sanitizeInput(resourcePayload.level || '', 50),
          category: sanitizeInput(resourcePayload.category || '', 100),
          tag: sanitizeInput(resourcePayload.tag || '', 200),
          section_type: sanitizeInput(resourcePayload.section_type || '', 100),
          file_url: sanitizeInput(resourcePayload.file_url || '', 2048),
          file_size: sanitizeInput(resourcePayload.file_size || '', 50),
          status: 'pending'
        });
        if (error) throw error;
        result = { success: true };
        break;
      }
      case 'approve': {
        if (!submissionId) throw new Error('submissionId required');
        const approveAction = req.body.action || 'approve';
        if (approveAction === 'delete') {
          const { data: sub } = await supabase.from('resource_submissions').select('id').eq('id', submissionId).maybeSingle();
          if (sub) { await supabase.from('resource_submissions').delete().eq('id', submissionId); }
          else { await supabase.from('biology_notes').delete().eq('id', submissionId); }
        } else if (approveAction === 'approve') {
          const { data: sub } = await supabase.from('resource_submissions').select('*').eq('id', submissionId).single();
          if (sub) {
            await supabase.from('biology_notes').insert({
              title: sub.title, description: sub.description, author: sub.author,
              level: sub.level, category: sub.category, tag: sub.tag,
              section_type: sub.section_type, file_url: sub.file_url, file_size: sub.file_size
            });
            await supabase.from('resource_submissions').update({ status: 'approved' }).eq('id', submissionId);
          }
        } else {
          await supabase.from('resource_submissions').update({ status: 'rejected' }).eq('id', submissionId);
        }
        result = { success: true };
        break;
      }
      case 'submissions': {
        const { data, error } = await supabase.from('resource_submissions').select('*').order('created_at', { ascending: false }).limit(50);
        if (error) throw error; result = data || [];
        break;
      }
      case 'messages': {
        const { data, error } = await supabase.from('contact_messages').select('*').order('created_at', { ascending: false }).limit(50);
        if (error) throw error; result = { messages: data || [] };
        break;
      }
      case 'stats': {
        const ck = 'stats'; const cached = getCachedResponse(ck);
        if (cached) { result = cached; break; }
        const [rc, sc, mc] = await Promise.all([
          supabase.from('biology_notes').select('id', { count: 'exact', head: true }),
          supabase.from('resource_submissions').select('id', { count: 'exact', head: true }).eq('status', 'pending'),
          supabase.from('contact_messages').select('id', { count: 'exact', head: true })
        ]);
        result = { resources: rc.count || 0, pendingSubmissions: sc.count || 0, messages: mc.count || 0, donations: 0 };
        setCachedResponse(ck, result);
        break;
      }
      case 'get_resources': {
        let q = supabase.from('biology_notes').select('id,title,description,author,level,category,tag,section_type,file_url,file_size,download_count,created_at').order('created_at', { ascending: false }).limit(100);
        if (filters?.level) q = q.eq('level', filters.level);
        if (filters?.category) q = q.eq('category', filters.category);
        if (filters?.tag) q = q.eq('tag', filters.tag);
        const { data, error } = await q; if (error) throw error; result = data || [];
        break;
      }
      case 'get_filter_options': {
        const ck = 'filter_options'; const cached = getCachedResponse(ck);
        if (cached) { result = cached; break; }
        const [l, c, t] = await Promise.all([supabase.from('biology_notes').select('level').limit(500), supabase.from('biology_notes').select('category').limit(500), supabase.from('biology_notes').select('tag').limit(500)]);
        result = { levels: [...new Set((l.data||[]).map(x=>x.level).filter(Boolean))], categories: [...new Set((c.data||[]).map(x=>x.category).filter(Boolean))], tags: [...new Set((t.data||[]).map(x=>x.tag).filter(Boolean))] };
        setCachedResponse(ck, result);
        break;
      }
      case 'get_quiz_topics': {
        if (!level) return res.status(400).json({ error: 'Level required' });
        const { data, error } = await supabase.from('quiz_topics').select('id,topic_name,display_order').eq('level', level).eq('is_active', true).order('display_order');
        if (error) throw error;
        const topics = (data || []).map(t => ({ ...t, question_count: 0 }));
        if (topics.length > 0) {
          const topicNames = topics.map(t => t.topic_name);
          const { data: counts } = await supabase.from('quiz_questions').select('topic').eq('level', level).in('topic', topicNames).eq('is_active', true);
          const countMap = new Map(); if (counts) counts.forEach(c => { countMap.set(c.topic, (countMap.get(c.topic) || 0) + 1); });
          topics.forEach(t => { t.question_count = countMap.get(t.topic_name) || 0; });
        }
        result = topics;
        break;
      }
      case 'get_quiz_questions': {
        if (!level || !topic) return res.status(400).json({ error: 'Level and topic required' });
        const { data, error } = await supabase.from('quiz_questions').select('id,question_text,option_a,option_b,option_c,option_d,difficulty,explanation,correct_option').eq('level', level).eq('topic', topic).eq('is_active', true).order('id');
        if (error) throw error; result = data || [];
        break;
      }
      case 'add_quiz_questions_batch': {
        if (!level || !topic || !questions || !Array.isArray(questions)) return res.status(400).json({ error: 'Invalid batch data' });
        const { data: existingTopic } = await supabase.from('quiz_topics').select('id').eq('level', level).eq('topic_name', topic).maybeSingle();
        let topicId;
        if (existingTopic) {
          topicId = existingTopic.id;
        } else {
          const { data: newTopic } = await supabase.from('quiz_topics').insert({ level, topic_name: topic, is_active: true }).select().single();
          topicId = newTopic.id;
        }
        const qb = questions.map(q => ({
          level, topic, question_text: sanitizeInput(q.question_text, 1000),
          option_a: sanitizeInput(q.option_a, 500), option_b: sanitizeInput(q.option_b, 500),
          option_c: sanitizeInput(q.option_c, 500), option_d: sanitizeInput(q.option_d, 500),
          correct_option: q.correct_option.toUpperCase(),
          explanation: sanitizeInput(q.explanation, 2000),
          difficulty: q.difficulty || 'medium', batch_name: batch_name || 'Batch ' + new Date().toISOString()
        }));
        const { error: qie } = await supabase.from('quiz_questions').insert(qb);
        if (qie) throw qie;
        result = { success: true, questions_added: questions.length };
        break;
      }
      case 'delete_quiz_topic': {
        if (!topic || !level) return res.status(400).json({ error: 'topic and level required' });
        await supabase.from('quiz_questions').delete().eq('level', level).eq('topic', topic);
        await supabase.from('quiz_topics').delete().eq('level', level).eq('topic_name', topic);
        result = { success: true };
        break;
      }
      case 'get_all_ratings': {
        const { data, error } = await supabase.from('user_interactions').select('resource_id, value').eq('interaction_type', 'rating');
        if (error) throw error;
        const agg = {};
        (data || []).forEach(r => { if (!agg[r.resource_id]) agg[r.resource_id] = { sum: 0, count: 0, distribution: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 } }; agg[r.resource_id].sum += r.value; agg[r.resource_id].count += 1; if (agg[r.resource_id].distribution[r.value] !== undefined) agg[r.resource_id].distribution[r.value]++; });
        const resultObj = {};
        for (const [rid, { sum, count, distribution }] of Object.entries(agg)) { resultObj[rid] = { avg: +(sum / count).toFixed(1), count, distribution }; }
        result = resultObj;
        break;
      }
      case 'get_leaderboard': {
        let query = supabase.from('user_quiz_activity').select('user_id, score, total_questions, percentage, level, topic, completed_at').eq('passed', true).order('percentage', { ascending: false }).order('completed_at', { ascending: false }).limit(req.body.limit || 20);
        if (req.body.level) query = query.eq('level', req.body.level);
        const { data, error } = await query;
        if (error) throw error;
        const leaderboard = [];
        for (const entry of (data || [])) {
          try {
            const { data: { user } } = await supabase.auth.admin.getUserById(entry.user_id);
            leaderboard.push({ ...entry, user: { name: user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User', email: user?.email || null } });
          } catch { leaderboard.push({ ...entry, user: { name: 'User', email: null } }); }
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
        result = { total_blocks_attempted: all.length, total_blocks_passed: passed.length, average_score: all.length ? Math.round(all.reduce((s, a) => s + a.percentage, 0) / all.length) : 0, best_score: all.length ? Math.max(...all.map(a => a.percentage)) : 0, topics_attempted: [...new Set(all.map(a => a.topic))].length, streak: calculateStreak(all), recent_activity: all.slice(0, 10) };
        break;
      }
      case 'get_user_favorites': {
        const targetUserId = adminData ? (req.body.user_id || userId) : userId;
        if (!targetUserId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_interactions').select('resource_id').eq('user_id', targetUserId).eq('interaction_type', 'favorite').order('created_at', { ascending: false });
        if (error) throw error;
        const favorites = [];
        for (const f of (data || [])) {
          const { data: resource } = await supabase.from('biology_notes').select('title').eq('id', f.resource_id).maybeSingle();
          favorites.push({ resource_id: f.resource_id, title: resource?.title || 'Unknown' });
        }
        result = favorites;
        break;
      }
      case 'get_recent_views': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const limit = req.body.limit || 5;
        const { data, error } = await supabase.from('user_interactions').select('resource_id, created_at').eq('user_id', userId).eq('interaction_type', 'view').order('created_at', { ascending: false }).limit(limit);
        if (error) throw error;
        const views = [];
        for (const v of (data || [])) {
          const { data: resource } = await supabase.from('biology_notes').select('title').eq('id', v.resource_id).maybeSingle();
          views.push({ resource_id: v.resource_id, title: resource?.title || 'Unknown', created_at: v.created_at });
        }
        result = views;
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
        result = (data || []).map(d => ({ badge: d.metadata?.badge || 'Unknown' }));
        break;
      }
      case 'get_user_streak': {
        const targetUserId = adminData ? (req.body.user_id || userId) : userId;
        if (!targetUserId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_interactions').select('created_at').eq('user_id', targetUserId).eq('interaction_type', 'daily_visit').order('created_at', { ascending: false });
        if (error) throw error;
        const dates = (data || []).map(d => new Date(d.created_at).toISOString().slice(0, 10));
        let streak = 0;
        const today = new Date().toISOString().slice(0, 10);
        let checkDate = today;
        const dateSet = new Set(dates);
        if (!dateSet.has(checkDate)) {
          const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
          if (!dateSet.has(yesterday)) { result = { count: 0 }; break; }
          checkDate = yesterday;
        }
        while (dateSet.has(checkDate)) {
          streak++;
          const d = new Date(checkDate);
          d.setDate(d.getDate() - 1);
          checkDate = d.toISOString().slice(0, 10);
        }
        result = { count: streak };
        break;
      }
      case 'get_admin_users': {
        const { data } = await supabase.from('admin_master').select('*');
        result = (data || []).map(a => ({
          admin_id: a.admin_id,
          admin_email: a.admin_email,
          admin_role: a.admin_role,
          permissions: a.permissions,
          is_active: a.is_active,
          is_locked: a.is_locked || false,
          last_login: a.last_login || null
        }));
        break;
      }
      case 'get_newsletter_subscribers': {
        const { data } = await supabase.from('newsletter_subscribers').select('*').order('created_at', { ascending: false });
        result = data || [];
        break;
      }
      case 'update_newsletter_subscriber': {
        const subscriberId = req.body.id;
        const subscriberActive = req.body.is_active !== undefined ? req.body.is_active : true;
        await supabase.from('newsletter_subscribers').update({ is_active: subscriberActive }).eq('id', subscriberId);
        result = { success: true };
        break;
      }
      case 'get_donations': {
        const { data } = await supabase.from('momo_donations').select('*').order('created_at', { ascending: false }).limit(50);
        result = data || [];
        break;
      }
      case 'get_app_features': {
        let query = supabase.from('app_features').select('*').eq('is_enabled', true);
        const pageId = req.body.page_id || 'all';
        if (pageId !== 'all') query = query.eq('page_id', pageId);
        query = query.order('display_order');
        const { data, error } = await query;
        if (error) throw error;
        result = (data || []).map(f => ({ feature_key: f.feature_key, feature_name: f.feature_name, description: f.description, page_id: f.page_id, category: f.category, settings: f.settings, is_enabled: f.is_enabled, display_order: f.display_order, user_enabled: true, user_settings: {} }));
        break;
      }
      case 'update_app_feature': {
        await supabase.from('app_features').update({ settings: settings || {}, is_enabled: is_enabled !== undefined ? is_enabled : true, updated_at: new Date().toISOString() }).eq('feature_key', feature_key);
        result = { success: true };
        break;
      }
      case 'toggle_favorite': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const rid = req.body.resource_id || resource_id;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', rid).eq('interaction_type', 'favorite').maybeSingle();
        if (existing) { await supabase.from('user_interactions').delete().eq('id', existing.id); result = { favorited: false }; }
        else { await supabase.from('user_interactions').insert({ user_id: userId, resource_id: rid, interaction_type: 'favorite' }); result = { favorited: true }; }
        break;
      }
      case 'record_view': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        await supabase.from('user_interactions').insert({ user_id: userId, resource_id: req.body.resource_id || resource_id, interaction_type: 'view' });
        result = { success: true };
        break;
      }
      case 'record_download': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        await supabase.from('user_interactions').insert({ user_id: userId, resource_id: req.body.resource_id || resource_id, interaction_type: 'download' });
        result = { success: true };
        break;
      }
      case 'record_daily_visit': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const today = new Date().toISOString().slice(0, 10);
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('interaction_type', 'daily_visit').gte('created_at', `${today}T00:00:00Z`).lte('created_at', `${today}T23:59:59Z`).limit(1);
        if (!existing || existing.length === 0) { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'daily_visit' }); }
        result = { success: true };
        break;
      }
      case 'submit_rating': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const rid = req.body.resource_id || resource_id;
        const val = req.body.rating || rating;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', rid).eq('interaction_type', 'rating').maybeSingle();
        if (existing) { await supabase.from('user_interactions').update({ value: val, created_at: new Date().toISOString() }).eq('id', existing.id); }
        else { await supabase.from('user_interactions').insert({ user_id: userId, resource_id: rid, interaction_type: 'rating', value: val }); }
        result = { success: true };
        break;
      }
      case 'get_flashcards': {
        const cat = req.body.category || category;
        let query = supabase.from('flashcard_cards').select('*, flashcard_decks!inner(title, category, level, author)').order('created_at', { ascending: false });
        if (cat) query = query.eq('flashcard_decks.category', cat);
        const { data, error } = await query;
        if (error) throw error;
        result = (data || []).map(card => ({
          id: card.id,
          deck_id: card.deck_id,
          front_text: card.front_text,
          back_text: card.back_text,
          image_url: card.image_url,
          audio_url: card.audio_url,
          position: card.position,
          created_at: card.created_at,
          category: card.flashcard_decks?.category || 'General',
          level: card.flashcard_decks?.level || '',
          author: card.flashcard_decks?.author || '',
          title: card.flashcard_decks?.title || ''
        }));
        break;
      }
      case 'toggle_flashcard_known': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const fid = req.body.flashcard_id || flashcard_id;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', fid).eq('interaction_type', 'flashcard_known').maybeSingle();
        if (existing) { await supabase.from('user_interactions').delete().eq('id', existing.id); result = { known: false }; }
        else { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'flashcard_known', resource_id: fid }); result = { known: true }; }
        break;
      }
      case 'get_known_flashcards': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { data, error } = await supabase.from('user_interactions').select('resource_id').eq('user_id', userId).eq('interaction_type', 'flashcard_known');
        if (error) throw error;
        result = (data || []).map(row => row.resource_id);
        break;
      }
      case 'check_flashcard_answer': {
        const fid = req.body.flashcard_id || flashcard_id;
        const ua = req.body.user_answer || user_answer || '';
        const { data: card, error } = await supabase.from('flashcard_cards').select('back_text').eq('id', fid).single();
        if (error || !card) return res.status(404).json({ error: 'Flashcard not found' });
        const correctAnswer = (card.back_text || '').trim();
        const userAnswerTrimmed = ua.trim();
        const isCorrect = correctAnswer.toLowerCase() === userAnswerTrimmed.toLowerCase();
        result = { correct: isCorrect, correct_answer: correctAnswer };
        break;
      }
      case 'rate_flashcard': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const fid = req.body.flashcard_id || flashcard_id;
        const diff = req.body.difficulty || difficulty;
        const difficultyValue = diff === 'easy' ? 3 : diff === 'medium' ? 2 : 1;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', fid).eq('interaction_type', 'rating').maybeSingle();
        if (existing) { await supabase.from('user_interactions').update({ value: difficultyValue, metadata: { difficulty: diff, type: 'flashcard_difficulty' }, created_at: new Date().toISOString() }).eq('id', existing.id); }
        else { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'rating', resource_id: fid, value: difficultyValue, metadata: { difficulty: diff, type: 'flashcard_difficulty' } }); }
        result = { success: true };
        break;
      }
      case 'toggle_flashcard_bookmark': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const fid = req.body.flashcard_id || flashcard_id;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', fid).eq('interaction_type', 'favorite').maybeSingle();
        if (existing) { await supabase.from('user_interactions').delete().eq('id', existing.id); result = { bookmarked: false }; }
        else { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'favorite', resource_id: fid }); result = { bookmarked: true }; }
        break;
      }
      case 'like_resource': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const rid = req.body.resource_id || resource_id;
        const { data: existing } = await supabase.from('user_interactions').select('id').eq('user_id', userId).eq('resource_id', rid).eq('interaction_type', 'favorite').maybeSingle();
        if (existing) { await supabase.from('user_interactions').delete().eq('id', existing.id); }
        else { await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'favorite', resource_id: rid }); }
        const { count } = await supabase.from('user_interactions').select('id', { count: 'exact', head: true }).eq('resource_id', rid).eq('interaction_type', 'favorite');
        result = { liked: !existing, like_count: count || 0 };
        break;
      }
      case 'comment_resource': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const rid = req.body.resource_id || resource_id;
        const comm = req.body.comment || comment;
        await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'review', resource_id: rid, metadata: { comment: sanitizeInput(comm, 1000) } });
        result = { success: true };
        break;
      }
      case 'get_resource_interactions': {
        const rid = req.body.resource_id || resource_id;
        const { count: likeCount } = await supabase.from('user_interactions').select('id', { count: 'exact', head: true }).eq('resource_id', rid).eq('interaction_type', 'favorite');
        const { data: comments } = await supabase.from('user_interactions').select('metadata, created_at, user_id').eq('resource_id', rid).eq('interaction_type', 'review').order('created_at', { ascending: false }).limit(20);
        const commentList = [];
        if (comments) {
          for (const c of comments) {
            try { const { data: { user } } = await supabase.auth.admin.getUserById(c.user_id); commentList.push({ comment: c.metadata?.comment || '', user_name: user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, x => x.toUpperCase()) : 'User', created_at: c.created_at }); }
            catch { commentList.push({ comment: c.metadata?.comment || '', user_name: 'User', created_at: c.created_at }); }
          }
        }
        result = { like_count: likeCount || 0, comments: commentList };
        break;
      }
      case 'submit_mood': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'mood', resource_id: null, metadata: { mood: req.body.mood, message: sanitizeInput(req.body.message || '', 500) } });
        result = { success: true };
        break;
      }
      case 'get_flashcard_progress': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { data: knownCards } = await supabase.from('user_interactions').select('resource_id').eq('user_id', userId).eq('interaction_type', 'flashcard_known');
        const knownIds = (knownCards || []).map(row => row.resource_id).filter(Boolean);
        const { data: allCards } = await supabase.from('flashcard_cards').select('deck_id');
        const progress = {};
        const deckCardCounts = {};
        (allCards || []).forEach(card => { if (!deckCardCounts[card.deck_id]) deckCardCounts[card.deck_id] = { reviewed: 0, total: 0 }; deckCardCounts[card.deck_id].total++; });
        if (knownIds.length > 0) {
          const { data: knownCardData } = await supabase.from('flashcard_cards').select('deck_id').in('id', knownIds);
          (knownCardData || []).forEach(card => { if (deckCardCounts[card.deck_id]) deckCardCounts[card.deck_id].reviewed++; });
        }
        for (const [deckId, counts] of Object.entries(deckCardCounts)) {
          const { data: deck } = await supabase.from('flashcard_decks').select('title').eq('id', deckId).maybeSingle();
          progress[deckId] = { ...counts, title: deck?.title || 'Unknown Deck' };
        }
        result = progress;
        break;
      }
      case 'get_community_activity': {
        const { data: downloads } = await supabase.from('user_interactions').select('created_at, resource_id').eq('interaction_type', 'download').order('created_at', { ascending: false }).limit(5);
        const { data: quizCompletions } = await supabase.from('user_quiz_activity').select('completed_at, level, topic, percentage').eq('passed', true).order('completed_at', { ascending: false }).limit(5);
        const activities = [];
        for (const d of (downloads || [])) {
          const { data: resource } = await supabase.from('biology_notes').select('title').eq('id', d.resource_id).maybeSingle();
          activities.push({ type: 'download', message: `A learner downloaded "${resource?.title || 'a resource'}"`, time: d.created_at });
        }
        (quizCompletions || []).forEach(q => { activities.push({ type: 'quiz', message: `A learner passed a ${q.level} quiz on ${q.topic} with ${q.percentage}%`, time: q.completed_at }); });
        activities.sort((a, b) => new Date(b.time) - new Date(a.time));
        result = activities.slice(0, 10);
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
      case 'submit_weekly_challenge': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const ws = req.body.week_start || week_start;
        const so = req.body.selected_option !== undefined ? req.body.selected_option : selected_option;
        const { data: existing } = await supabase.from('user_interactions').select('metadata').eq('user_id', userId).eq('interaction_type', 'weekly_challenge_answer').eq('resource_id', ws).maybeSingle();
        if (so === null || so === undefined) {
          result = existing ? { already_answered: true, selected_option: existing.metadata?.selected_option, correct: existing.metadata?.is_correct } : { already_answered: false };
        } else {
          if (existing) return res.status(409).json({ error: 'Already answered this week' });
          const { data: wcData } = await supabase.from('site_sections').select('data').eq('section', 'weekly_challenge').single();
          const challenge = wcData?.data || {};
          const isCorrect = so === challenge.correct;
          await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'weekly_challenge_answer', resource_id: ws, metadata: { selected_option: so, is_correct: isCorrect } });
          result = { already_answered: true, selected_option: so, correct: isCorrect, explanation: challenge.explanation || '' };
        }
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
        const { data, error } = await supabase.from('user_presence').select('user_id, last_seen').gte('last_seen', new Date(Date.now() - 5 * 60 * 1000).toISOString()).order('last_seen', { ascending: false });
        if (error) throw error;
        const users = [];
        for (const p of (data || [])) {
          try { const { data: { user } } = await supabase.auth.admin.getUserById(p.user_id); users.push({ user_id: p.user_id, name: user?.email ? user.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'User', last_seen: p.last_seen }); }
          catch { users.push({ user_id: p.user_id, name: 'User', last_seen: p.last_seen }); }
        }
        result = users;
        break;
      }
      case 'save_achievement': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const achievementBadge = req.body.badge || badge;
        await supabase.from('user_interactions').insert({ user_id: userId, interaction_type: 'achievement', metadata: { badge: achievementBadge.id || achievementBadge, ...achievementBadge } });
        result = { success: true };
        break;
      }
      case 'get_public_stats': {
        const ck = 'public_stats'; const cached = getCachedResponse(ck);
        if (cached) { result = cached; break; }
        try {
          const [resCount, downCount, quizCount, resourcesUsers, authUsers] = await Promise.all([
            supabase.from('biology_notes').select('id', { count: 'exact', head: true }),
            supabase.from('user_interactions').select('id', { count: 'exact', head: true }).eq('interaction_type', 'download'),
            supabase.from('user_quiz_activity').select('id', { count: 'exact', head: true }),
            supabase.from('user_interactions').select('user_id').eq('interaction_type', 'download'),
            supabase.auth.admin.listUsers()
          ]);
          const uniqueUsers = new Set();
          if (resourcesUsers.data) {
            resourcesUsers.data.forEach(item => {
              if (item.user_id) uniqueUsers.add(item.user_id);
            });
          }
          const totalRegisteredUsers = authUsers.data?.users?.length || 0;
          result = {
            resources_count: resCount.count || 0,
            downloads_count: downCount.count || 0,
            quiz_attempts: quizCount.count || 0,
            users_count: totalRegisteredUsers
          };
          setCachedResponse(ck, result);
        } catch (err) {
          console.error('Stats error:', err);
          result = { resources_count: 0, downloads_count: 0, quiz_attempts: 0, users_count: 0 };
        }
        break;
      }
      case 'check_admin_online': {
        const { data } = await supabase.from('admin_master').select('is_online, is_busy').eq('is_active', true).limit(1).maybeSingle();
        result = data ? { online: data.is_online, busy: data.is_busy } : { online: false, busy: false };
        break;
      }
      case 'complete_quiz': {
        if (!userId) return res.status(401).json({ error: 'Please sign in.' });
        const { quiz_id, score, total, percentage, passed, answers, time_taken } = req.body;
        const { data: existing } = await supabase.from('user_quiz_activity').select('id').eq('user_id', userId).eq('quiz_id', quiz_id).maybeSingle();
        if (existing) { await supabase.from('user_quiz_activity').update({ score, total_possible: total, percentage, passed, answers, time_taken, completed_at: new Date().toISOString() }).eq('id', existing.id); }
        else { await supabase.from('user_quiz_activity').insert({ user_id: userId, quiz_id, score, total_possible: total, percentage, passed, answers, time_taken, completed_at: new Date().toISOString() }); }
        try { await supabase.rpc('update_quiz_stats', { quiz_id_input: quiz_id }); } catch(e) {}
        result = { success: true, passed, percentage };
        break;
      }
      case 'check_quiz_answer': {
        const { question_id, selected_option } = req.body;
        const { data: question, error } = await supabase.from('quiz_questions').select('id,correct_option,option_a,option_b,option_c,option_d').eq('id', question_id).single();
        if (error || !question) return res.status(404).json({ error: 'Question not found' });
        const isCorrect = selected_option === question.correct_option;
        result = { correct: isCorrect, correct_option: question.correct_option, correct_answer_text: { A: question.option_a, B: question.option_b, C: question.option_c, D: question.option_d }[question.correct_option] };
        break;
      }
      case 'submit_quiz_block': {
        if (!userId) return res.status(401).json({ error: 'Authentication required.' });
        const { level: sl, topic: st, block_number: sbn, answers: sa, time_taken: stt, achievements } = req.body;
        if (!sa || !Array.isArray(sa) || sa.length === 0) return res.status(400).json({ error: 'Answers required' });
        const todayStart = new Date().toISOString().slice(0, 10) + 'T00:00:00Z';
        const { data: existingAttempt } = await supabase.from('user_quiz_activity').select('id').eq('user_id', userId).eq('level', sl).eq('topic', st).eq('block_number', sbn).gte('completed_at', todayStart).maybeSingle();
        if (existingAttempt) { return res.status(429).json({ error: 'You have already attempted this block today. Please try again tomorrow.' }); }
        const questionIds = sa.map(a => a.id);
        const { data: questions, error: qe } = await supabase.from('quiz_questions').select('id,correct_option,explanation,question_text,option_a,option_b,option_c,option_d,difficulty').in('id', questionIds);
        if (qe) throw qe;
        const qMap = new Map(); (questions || []).forEach(q => qMap.set(q.id, q));
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
        const { data: questions, error: qe } = await supabase.from('quiz_questions').select('id,correct_option,explanation,question_text,option_a,option_b,option_c,option_d,difficulty').in('id', questionIds);
        if (qe) throw qe;
        const qMap = new Map(); (questions || []).forEach(q => qMap.set(q.id, q));
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
        let query = supabase.from('user_quiz_activity').select('completed_at,passed').eq('user_id', userId).eq('level', rl).eq('topic', rt);
        if (rbn !== undefined) query = query.eq('block_number', rbn);
        query = query.order('completed_at', { ascending: false }).limit(1);
        const { data, error } = await query;
        if (error) throw error;
        const last = data && data[0];
        if (!last) { result = { can_retry: true, reason: null, locked_blocks: [] }; }
        else {
          const today = new Date(); const lastDate = new Date(last.completed_at);
          const sameDay = today.toDateString() === lastDate.toDateString();
          if (rbn !== undefined) { result = { can_retry: !sameDay, reason: sameDay ? 'You have already attempted this block today. Please try again tomorrow.' : null }; }
          else {
            const { data: allBlocks } = await supabase.from('user_quiz_activity').select('block_number,completed_at').eq('user_id', userId).eq('level', rl).eq('topic', rt).order('completed_at', { ascending: false });
            const lockedBlocks = [];
            if (allBlocks) { allBlocks.forEach(b => { if (new Date(b.completed_at).toDateString() === today.toDateString()) lockedBlocks.push(b.block_number); }); }
            result = { can_retry: true, locked_blocks: lockedBlocks };
          }
        }
        break;
      }
      case 'get_quiz_block': {
        const { level: ql, topic: qt, block_number: bn } = req.body;
        if (!ql || !qt || bn === undefined) return res.status(400).json({ error: 'Level, topic, and block number required' });
        const offset = bn * 10;
        const { data, error } = await supabase.from('quiz_questions').select('id,question_text,option_a,option_b,option_c,option_d,difficulty').eq('level', ql).eq('topic', qt).eq('is_active', true).order('id').range(offset, offset + 9);
        if (error) throw error;
        result = { block_number: bn, questions: (data || []).sort(() => Math.random() - 0.5), total_in_block: (data || []).length };
        break;
      }
      case 'check_pdf_restriction': {
        const pdfId = req.body.pdf_id;
        const restrictionType = req.body.restriction_type;
        if (!pdfId || !restrictionType) {
          return res.status(400).json({ error: 'pdf_id and restriction_type required' });
        }
        let targetUserId = userId;
        if (!targetUserId) {
          result = { is_restricted: false };
          break;
        }
        const { data, error } = await supabase
          .from('pdf_user_restrictions')
          .select('is_restricted, restriction_reason, expires_at')
          .eq('user_id', targetUserId)
          .eq('pdf_id', pdfId)
          .eq('restriction_type', restrictionType)
          .gt('expires_at', new Date().toISOString())
          .maybeSingle();
        if (error && error.code !== 'PGRST116') throw error;
        if (data && data.is_restricted) {
          result = { is_restricted: true, reason: data.restriction_reason || 'Restricted by administrator' };
        } else {
          result = { is_restricted: false };
        }
        break;
      }
      case 'track_pdf_preview': {
        const pdfId = req.body.pdf_id;
        if (!pdfId) return res.status(400).json({ error: 'pdf_id required' });
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { data: current } = await supabase
          .from('pdf_resources')
          .select('preview_count')
          .eq('id', pdfId)
          .single();
        if (current) {
          await supabase
            .from('pdf_resources')
            .update({ preview_count: (current.preview_count || 0) + 1 })
            .eq('id', pdfId);
        }
        await supabase
          .from('user_interactions')
          .insert({
            user_id: userId,
            interaction_type: 'view',
            resource_id: pdfId,
            metadata: { pdf_id: pdfId, action: 'preview' }
          });
        result = { success: true };
        break;
      }
      case 'track_pdf_download': {
        const pdfId = req.body.pdf_id;
        if (!pdfId) return res.status(400).json({ error: 'pdf_id required' });
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const { data: current } = await supabase
          .from('pdf_resources')
          .select('download_count')
          .eq('id', pdfId)
          .single();
        if (current) {
          await supabase
            .from('pdf_resources')
            .update({ download_count: (current.download_count || 0) + 1 })
            .eq('id', pdfId);
        }
        await supabase
          .from('user_interactions')
          .insert({
            user_id: userId,
            interaction_type: 'download',
            resource_id: pdfId,
            metadata: { pdf_id: pdfId, action: 'download' }
          });
        result = { success: true };
        break;
      }
      case 'get_notes_structure': {
        const { data, error } = await supabase
          .from('notes_structure')
          .select('*')
          .order('level_order', { ascending: true })
          .order('topic_order', { ascending: true })
          .order('subtopic_order', { ascending: true });
        if (error) throw error;
        result = data || [];
        break;
      }
      case 'get_note_content': {
        const subtopicId = req.body.subtopic_id;
        const { data, error } = await supabase
          .from('note_contents')
          .select('*')
          .eq('subtopic_id', subtopicId)
          .single();
        if (error) throw error;
        result = data;
        break;
      }
  
  case 'get_notes_by_level': {
  if (!userId) return res.status(401).json({ error: 'Please sign in to access notes.' });
  
  const level = req.body.level;
  if (!level) return res.status(400).json({ error: 'Level required' });
  
  const { data, error } = await supabase
    .from('notes_structure')
    .select('subtopic_id, subtopic_name, topic, level, read_time, word_count')
    .eq('level', level)
    .order('topic_order', { ascending: true })
    .order('subtopic_order', { ascending: true });
  
  if (error) throw error;
  
  const notes = [];
  for (const item of (data || [])) {
    const { data: contentData } = await supabase
      .from('note_contents')
      .select('content')
      .eq('subtopic_id', item.subtopic_id)
      .maybeSingle();
    
    const plainText = contentData?.content?.replace(/<[^>]*>/g, '') || '';
    const preview = plainText.substring(0, 120) + (plainText.length > 120 ? '...' : '');
    
    notes.push({
      id: item.subtopic_id,
      title: item.subtopic_name,
      topic: item.topic,
      level: item.level,
      preview: preview,
      read_time: item.read_time || Math.ceil(plainText.split(/\s+/).length / 200) + ' min read',
      word_count: item.word_count || plainText.split(/\s+/).length
    });
  }
  
  result = notes;
  break;
}
     case 'get_note_preview': {
  const subtopicId = req.body.subtopic_id;
  if (!subtopicId) return res.status(400).json({ error: 'subtopic_id required' });
  
  const { data, error } = await supabase
    .from('note_contents')
    .select('content, title')
    .eq('subtopic_id', subtopicId)
    .single();
  
  if (error) throw error;
  
  const plainText = data?.content?.replace(/<[^>]*>/g, '') || '';
  const preview = plainText.substring(0, 400) + (plainText.length > 400 ? '...' : '');
  
  result = {
    subtopic_id: subtopicId,
    title: data?.title || '',
    preview: preview,
    read_time: Math.ceil(plainText.split(/\s+/).length / 200)
  };
  break;
 }
     case 'toggle_note_reaction': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        const noteId = req.body.note_id;
        const reactionType = req.body.reaction_type;
        const { data: existing } = await supabase
          .from('note_reactions')
          .select('id, reaction_type')
          .eq('user_id', userId)
          .eq('note_id', noteId)
          .maybeSingle();
        if (existing) {
          if (existing.reaction_type === reactionType) {
            await supabase.from('note_reactions').delete().eq('id', existing.id);
            result = { reacted: false, reaction_type: null };
          } else {
            await supabase.from('note_reactions').update({ reaction_type: reactionType }).eq('id', existing.id);
            result = { reacted: true, reaction_type: reactionType };
          }
        } else {
          await supabase.from('note_reactions').insert({
            user_id: userId,
            note_id: noteId,
            reaction_type: reactionType
          });
          result = { reacted: true, reaction_type: reactionType };
        }
        const { count } = await supabase
          .from('note_reactions')
          .select('id', { count: 'exact', head: true })
          .eq('note_id', noteId);
        result.count = count || 0;
        break;
      }
      case 'get_note_reactions': {
        const noteId = req.body.note_id;
        const { data, error } = await supabase
          .from('note_reactions')
          .select('reaction_type, user_id, created_at')
          .eq('note_id', noteId);
        if (error) throw error;
        const reactionCounts = { like: 0, love: 0, helpful: 0 };
        (data || []).forEach(r => {
          if (reactionCounts[r.reaction_type] !== undefined) reactionCounts[r.reaction_type]++;
        });
        let userReaction = null;
        if (userId) {
          const userReact = (data || []).find(r => r.user_id === userId);
          if (userReact) userReaction = userReact.reaction_type;
        }
        result = { counts: reactionCounts, user_reaction: userReaction, total: (data || []).length };
        break;
      }
    case 'save_reading_progress': {
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  const { note_id, scroll_percentage, scroll_position, time_spent, completed } = req.body;
  
  const numericNoteId = parseInt(note_id, 10);
  const finalResourceId = isNaN(numericNoteId) ? 0 : numericNoteId;
  
  const { data: existing } = await supabase
    .from('user_interactions')
    .select('id, metadata, value')
    .eq('user_id', userId)
    .eq('interaction_type', 'reading_progress')
    .filter('metadata->>note_id', 'eq', note_id)
    .maybeSingle();
  
  if (existing) {
    const currentTimeSpent = (existing.metadata?.time_spent || 0) + (time_spent || 0);
    await supabase
      .from('user_interactions')
      .update({
        value: scroll_percentage,
        metadata: {
          note_id: note_id,
          scroll_position: scroll_position || existing.metadata?.scroll_position || 0,
          time_spent: currentTimeSpent,
          completed: completed || false,
          last_updated: new Date().toISOString()
        },
        created_at: new Date().toISOString()
      })
      .eq('id', existing.id);
  } else {
    await supabase
      .from('user_interactions')
      .insert({
        user_id: userId,
        interaction_type: 'reading_progress',
        resource_id: finalResourceId,
        value: scroll_percentage,
        metadata: {
          note_id: note_id,
          scroll_position: scroll_position || 0,
          time_spent: time_spent || 0,
          completed: completed || false,
          started_at: new Date().toISOString()
        }
      });
  }
  result = { success: true };
  break;
}
    
case 'get_reading_progress': {
  if (!userId) {
    result = null;
    break;
  }
  const { note_id } = req.body;
  
  const { data, error } = await supabase
    .from('user_interactions')
    .select('value, metadata, created_at')
    .eq('user_id', userId)
    .eq('interaction_type', 'reading_progress')
    .filter('metadata->>note_id', 'eq', note_id)
    .maybeSingle();
  
  if (error) throw error;
  result = data ? {
    scroll_percentage: data.value || 0,
    scroll_position: data.metadata?.scroll_position || 0,
    completed: data.metadata?.completed || false,
    last_accessed: data.created_at,
    time_spent: data.metadata?.time_spent || 0
  } : null;
  break;
}
case 'get_continue_reading': {
  if (!userId) {
    result = [];
    break;
  }
  const { limit = 10 } = req.body;
  const { data, error } = await supabase
    .from('user_interactions')
    .select('resource_id, value, metadata, created_at')
    .eq('user_id', userId)
    .eq('interaction_type', 'reading_progress')
    .neq('value', 100)
    .gt('value', 5)
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw error;
  const notes = [];
  for (const item of (data || [])) {
    const { data: noteData } = await supabase
      .from('notes_structure')
      .select('subtopic_name, topic, level')
      .eq('subtopic_id', item.resource_id)
      .maybeSingle();
    if (noteData) {
      notes.push({
        note_id: item.resource_id,
        title: noteData.subtopic_name,
        topic: noteData.topic,
        level: noteData.level,
        progress_percentage: item.value,
        last_accessed: item.created_at
      });
    }
  }
  result = notes;
  break;
}
 
     default: throw new Error('Unknown action: ' + action);
    }
    responseCache.delete('all_sections'); responseCache.delete('stats');
    return res.status(200).json({ data: result });
  } catch (error) {
    console.error('POST Error:', error.message);
    logSecurityEvent('POST_ERROR', { action, error: error.message }, req);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
