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
  'get_quiz_block', 'submit_quiz_block'
]);

const PUBLIC_ACTIONS = new Set([
  'get_site_section', 'get_all_site_sections', 'get_all_sections',
  'get_resources', 'get_filter_options', 'get_quizzes', 'get_quiz',
  'currencies', 'status', 'get_donate_page_config',
  'subscribe_newsletter', 'submit_contact', 'submit_resource',
  'signup', 'signin', 'verify_turnstile',
  'get_quiz_topics'
]);

const CSRF_PROTECTED_ACTIONS = new Set([
  'submit_contact', 'subscribe_newsletter', 'submit_resource',
  'signup', 'signin', 'submit_momo_donation', 'complete_quiz', 'add_reaction',
  'submit_quiz_answers', 'add_quiz_questions_batch', 'submit_quiz_block'
]);

const RATE_LIMITS = new Map();
const AUTH_ATTEMPTS = new Map();
const BANNED_IPS = new Set();
const BANNED_UNTIL = new Map();
const MAX_REQUESTS = 120;
const WINDOW_MS = 60000;
const AUTH_MAX_ATTEMPTS = 15;
const AUTH_WINDOW_MS = 300000;
const BAN_DURATION_MS = 5 * 60 * 1000;

const responseCache = new Map();
const CACHE_TTL = 120000;
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const SESSION_REFRESH_WINDOW_MS = 24 * 60 * 60 * 1000; // Refresh if within 24hrs of expiry

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
    user_id: userId,
    session_token_hash: hashedToken,
    ip_address: ip,
    user_agent: (userAgent || '').substring(0, 500),
    expires_at: expiresAt,
    is_active: true
  });
  
  if (error) throw error;
  
  return {
    access_token: sessionToken,
    expires_at: expiresAt
  };
}

async function validateSession(token) {
  if (!token || token.length < 20) return null;
  
  const hashedToken = hashToken(token);
  const { data, error } = await supabase
    .from('user_sessions')
    .select('user_id, expires_at, is_active')
    .eq('session_token_hash', hashedToken)
    .eq('is_active', true)
    .single();
    
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

function rateLimit(ip, action = null) {
  if (BANNED_IPS.has(ip)) {
    const banUntil = BANNED_UNTIL.get(ip);
    if (banUntil && banUntil > Date.now()) return false;
    BANNED_IPS.delete(ip);
    BANNED_UNTIL.delete(ip);
  }
  const now = Date.now();
  const isAuthAction = action === 'signin' || action === 'signup';
  const maxAllowed = isAuthAction ? AUTH_MAX_ATTEMPTS : MAX_REQUESTS;
  const windowMs = isAuthAction ? AUTH_WINDOW_MS : WINDOW_MS;
  const attemptMap = isAuthAction ? AUTH_ATTEMPTS : RATE_LIMITS;
  const record = attemptMap.get(ip) || { count: 0, reset: now + windowMs };
  if (now > record.reset) { record.count = 0; record.reset = now + windowMs; }
  record.count++;
  attemptMap.set(ip, record);
  if (record.count > maxAllowed * 2) {
    BANNED_IPS.add(ip);
    BANNED_UNTIL.set(ip, now + BAN_DURATION_MS);
    setTimeout(() => { BANNED_IPS.delete(ip); BANNED_UNTIL.delete(ip); }, BAN_DURATION_MS);
    return false;
  }
  return record.count <= maxAllowed;
}

function trackFailedAuth(ip, email) {
  const key = `${ip}:${email}`;
  const attempts = AUTH_ATTEMPTS.get(key) || { count: 0, firstAttempt: Date.now() };
  attempts.count++;
  AUTH_ATTEMPTS.set(key, attempts);
  if (attempts.count >= 10) {
    BANNED_UNTIL.set(ip, Date.now() + 15 * 60 * 1000);
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
  add_quiz_questions_batch: (body) => {
    if (!body.level || !['O-Level','A-Level','Pharmacy'].includes(body.level)) return 'Invalid level';
    if (!body.topic || !body.questions || !Array.isArray(body.questions) || body.questions.length === 0) return 'Questions required';
    for (const q of body.questions) {
      if (!q.question_text || !q.option_a || !q.option_b || !q.option_c || !q.option_d) return 'All options required';
      if (!q.correct_option || !['A','B','C','D'].includes(q.correct_option.toUpperCase())) return 'Invalid correct option';
      if (!q.explanation) return 'Explanation required';
    }
    return null;
  }
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of RATE_LIMITS) { if (now > record.reset) RATE_LIMITS.delete(ip); }
  for (const [key, attempts] of AUTH_ATTEMPTS) { if (now - attempts.firstAttempt > 3600000) AUTH_ATTEMPTS.delete(key); }
}, 60000);

module.exports = async (req, res) => {
  const requestId = crypto.randomBytes(8).toString('hex');
  req.requestId = requestId;
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token, X-Request-ID, X-Turnstile-Token, X-Session-Token');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Cache-Control', 'no-store, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Request-ID', requestId);
  if (req.method === 'OPTIONS') return res.status(200).end();
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
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
  if (action !== 'get_quiz' && action !== 'get_user_progress') {
    const cached = getCachedResponse(cacheKey);
    if (cached) return res.status(200).json(cached);
  }
  const token = req.headers.authorization?.replace('Bearer ', '') || req.headers['x-session-token'];
  let userId = null;
  if (token) { 
    try { 
      const session = await validateSession(token);
      if (session) userId = session.user_id;
    } catch(e) {} 
  }
  try {
    let result;
    switch (action) {
      case 'get_all_site_sections': case 'get_all_sections': {
        const { data, error } = await supabase.from('site_sections').select('section, data');
        if (error) throw error;
        result = {}; (data || []).forEach(row => { result[row.section] = row.data; });
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
      default: result = null;
    }
    if (action !== 'get_quiz' && action !== 'get_user_progress') setCachedResponse(cacheKey, result);
    return res.status(200).json(result);
  } catch (error) { console.error('GET Error:', error.message); return res.status(500).json({error:'Internal server error'}); }
}

async function handlePost(req, res) {
  const { action } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  if (!action || !ACTION_WHITELIST.has(action)) return res.status(400).json({ error: 'Invalid action' });
  
  const validator = VALIDATORS[action];
  if (validator) { const ve = validator(req.body); if (ve) return res.status(400).json({error:ve}); }
  
  const token = req.headers.authorization?.replace('Bearer ', '') || req.headers['x-session-token'];
  let userId = null;
  let userEmail = null;
  if (token) {
    try {
      const session = await refreshSessionIfNeeded(token);
      if (session) {
        userId = session.user_id;
        const { data: { user } } = await supabase.auth.admin.getUserById(session.user_id);
        if (user) userEmail = user.email;
      }
    } catch(e) {}
  }
  
  try {
    let result;
    const { section, filters, formData, email, password, payload, submissionId, prompt, mode, name, amount, txid } = req.body;
    
    switch (action) {
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
        if (error) throw error; result = {}; (data||[]).forEach(row=>{result[row.section]=row.data;}); setCachedResponse(ck, result);
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
        const topics = (data||[]).map(t => ({...t, question_count: 0, completed_blocks: 0}));
        if (topics.length > 0) {
          const topicNames = topics.map(t=>t.topic_name);
          const { data: counts } = await supabase.from('quiz_questions').select('topic').eq('level',level).in('topic',topicNames).eq('is_active',true);
          const countMap = new Map(); if (counts) counts.forEach(c=>{ countMap.set(c.topic, (countMap.get(c.topic)||0)+1); });
          topics.forEach(t=>{ t.question_count = countMap.get(t.topic_name) || 0; });
          
          if (userId) {
            const { data: blocks } = await supabase.from('user_quiz_activity').select('topic, block_number, completed_at').eq('user_id',userId).eq('level',level).in('topic',topicNames);
            const blockMap = new Map();
            if (blocks) {
              blocks.forEach(b => {
                const key = `${b.topic}_${b.block_number}`;
                if (!blockMap.has(key)) blockMap.set(key, []);
                blockMap.get(key).push(b.completed_at);
              });
            }
            topics.forEach(t => {
              const totalBlocks = Math.ceil((countMap.get(t.topic_name) || 0) / 10);
              let completedBlocks = 0;
              for (let i = 0; i < totalBlocks; i++) {
                const key = `${t.topic_name}_${i}`;
                if (blockMap.has(key)) {
                  const attempts = blockMap.get(key);
                  const today = new Date().toDateString();
                  const hasRecent = attempts.some(a => new Date(a).toDateString() === today);
                  if (hasRecent) completedBlocks++;
                }
              }
              t.completed_blocks = completedBlocks;
              t.total_blocks = totalBlocks;
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
        const { data, error } = await supabase.from('quiz_questions').select('*').eq('level',ql).eq('topic',qt).eq('is_active',true).order('id').range(offset, offset + 9);
        if (error) throw error;
        const shuffled = (data||[]).sort(()=>Math.random()-0.5);
        result = {
          block_number: bn,
          questions: shuffled.map(q=>({id:q.id,question_text:q.question_text,option_a:q.option_a,option_b:q.option_b,option_c:q.option_c,option_d:q.option_d,difficulty:q.difficulty})),
          total_in_block: shuffled.length
        };
        break;
      }
      case 'get_quiz_questions': {
        const { level: ql, topic: qt, count: qc } = req.body;
        if (!ql || !qt) return res.status(400).json({ error: 'Level and topic required' });
        const questionCount = Math.min(qc || 10, 50);
        const { data, error } = await supabase.from('quiz_questions').select('*').eq('level',ql).eq('topic',qt).eq('is_active',true).limit(questionCount);
        if (error) throw error;
        const shuffled = (data||[]).sort(()=>Math.random()-0.5);
        result = shuffled.map(q=>({id:q.id,question_text:q.question_text,option_a:q.option_a,option_b:q.option_b,option_c:q.option_c,option_d:q.option_d,difficulty:q.difficulty}));
        break;
      }
      case 'submit_quiz_block': {
        if (!userId) return res.status(401).json({ error: 'Authentication required. Please sign in to save your results.' });
        const { level: sl, topic: st, block_number: sbn, answers: sa, time_taken: stt } = req.body;
        if (!sa || !Array.isArray(sa) || sa.length === 0) return res.status(400).json({ error: 'Answers required' });
        
        const questionIds = sa.map(a => a.id);
        const { data: questions, error: qe } = await supabase.from('quiz_questions').select('id,correct_option,explanation,question_text,option_a,option_b,option_c,option_d,difficulty').in('id',questionIds);
        if (qe) throw qe;
        
        const qMap = new Map(); (questions||[]).forEach(q => qMap.set(q.id, q));
        
        let score = 0;
        const graded = sa.map(answer => {
          const q = qMap.get(answer.id);
          if (!q) return { id: answer.id, question: 'Question unavailable', userAnswer: 'X', correctAnswer: 'N/A', userAnswerText: 'Not answered', correctAnswerText: 'N/A', isCorrect: false, explanation: 'This question has been removed.' };
          
          const userOpt = answer.selectedOption || 'X';
          const correctOpt = q.correct_option;
          const isCorrect = userOpt === correctOpt;
          if (isCorrect) score++;
          
          const allOpts = { A: q.option_a, B: q.option_b, C: q.option_c, D: q.option_d };
          
          return {
            id: q.id, question: q.question_text, userAnswer: userOpt, correctAnswer: correctOpt,
            userAnswerText: allOpts[userOpt] || 'Not answered', correctAnswerText: allOpts[correctOpt],
            isCorrect, explanation: q.explanation, difficulty: q.difficulty
          };
        });
        
        const total = sa.length;
        const percentage = Math.round((score / total) * 100);
        const passed = percentage >= 70;
        const userName = userEmail ? userEmail.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'Learner';
        
        const { error: ie } = await supabase.from('user_quiz_activity').insert({
          user_id: userId, level: sl, topic: st, block_number: sbn, score, total_questions: total,
          percentage, passed, answers: graded, time_taken: stt || 0
        });
        if (ie) throw ie;
        
        result = { score, total, percentage, passed, answers: graded, userName, userEmail, block_number: sbn };
        break;
      }
      case 'submit_quiz_answers': {
        if (!userId) return res.status(401).json({ error: 'Authentication required. Please sign in to save your results.' });
        const { level: sl, topic: st, answers: sa, time_taken: stt } = req.body;
        if (!sa || !Array.isArray(sa) || sa.length === 0) return res.status(400).json({ error: 'Answers required' });
        
        const questionIds = sa.map(a => a.id);
        const { data: questions, error: qe } = await supabase.from('quiz_questions').select('id,correct_option,explanation,question_text,option_a,option_b,option_c,option_d,difficulty').in('id',questionIds);
        if (qe) throw qe;
        
        const qMap = new Map(); (questions||[]).forEach(q => qMap.set(q.id, q));
        
        let score = 0;
        const graded = sa.map(answer => {
          const q = qMap.get(answer.id);
          if (!q) return { id: answer.id, question: 'Question unavailable', userAnswer: 'X', correctAnswer: 'N/A', userAnswerText: 'Not answered', correctAnswerText: 'N/A', isCorrect: false, explanation: 'This question has been removed.' };
          
          const userOpt = answer.selectedOption || 'X';
          const correctOpt = q.correct_option;
          const isCorrect = userOpt === correctOpt;
          if (isCorrect) score++;
          
          const allOpts = { A: q.option_a, B: q.option_b, C: q.option_c, D: q.option_d };
          
          return {
            id: q.id, question: q.question_text, userAnswer: userOpt, correctAnswer: correctOpt,
            userAnswerText: allOpts[userOpt] || 'Not answered', correctAnswerText: allOpts[correctOpt],
            isCorrect, explanation: q.explanation, difficulty: q.difficulty
          };
        });
        
        const total = sa.length;
        const percentage = Math.round((score / total) * 100);
        const passed = percentage >= 70;
        const userName = userEmail ? userEmail.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : 'Learner';
        
        const { error: ie } = await supabase.from('user_quiz_activity').insert({
          user_id: userId, level: sl, topic: st, score, total_questions: total,
          percentage, passed, answers: graded, time_taken: stt || 0
        });
        if (ie) throw ie;
        
        result = { score, total, percentage, passed, answers: graded, userName, userEmail };
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
          if (rbn !== undefined) {
            result = { can_retry: !sameDay, reason: sameDay ? 'You have already attempted this block today. Please try again tomorrow.' : null };
          } else {
            const { data: allBlocks } = await supabase.from('user_quiz_activity').select('block_number,completed_at').eq('user_id',userId).eq('level',rl).eq('topic',rt).order('completed_at',{ascending:false});
            const lockedBlocks = [];
            if (allBlocks) {
              allBlocks.forEach(b => {
                if (new Date(b.completed_at).toDateString() === today.toDateString()) lockedBlocks.push(b.block_number);
              });
            }
            result = { can_retry: true, locked_blocks: lockedBlocks };
          }
        }
        break;
      }
      case 'add_quiz_questions_batch': {
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
      case 'submit_contact': { const {error}=await supabase.from('contact_messages').insert({name:formData.name.trim().slice(0,100),email:formData.email.trim().slice(0,254),subject:(formData.subject||'').trim().slice(0,200),message:formData.message.trim().slice(0,5000)}); if(error)throw error; result={success:true}; break; }
      case 'subscribe_newsletter': { const {error}=await supabase.from('newsletter_subscribers').insert({email:formData.email.trim().slice(0,254)}); if(error&&error.code!=='23505')throw error; result={success:true}; break; }
      case 'submit_resource': { const {error}=await supabase.from('resource_submissions').insert({title:payload.title.trim().slice(0,200),description:payload.description.trim().slice(0,5000),author:(payload.author||'').trim().slice(0,100),level:(payload.level||'').trim().slice(0,50),category:(payload.category||'').trim().slice(0,100),tag:(payload.tag||'').trim().slice(0,200),file_url:(payload.file_url||'').trim().slice(0,2048),file_size:(payload.file_size||'').trim().slice(0,50),status:'pending'}); if(error)throw error; result={success:true}; break; }
      case 'signup': {
        if(!rateLimit(ip,'signup'))return res.status(429).json({error:'Please wait a moment.'});
        if (password.length < 8) return res.status(400).json({error:'Password must be at least 8 characters.'});
        const {data,error}=await supabase.auth.signUp({email:email.trim().toLowerCase(),password,options:{emailRedirectTo:`${req.headers['x-forwarded-proto']||'https'}://${req.headers.host}`}});
        if(error){if(error.code==='user_already_exists')return res.status(200).json({data:{user:null,session:null,message:'Account exists. Check your email.'}});trackFailedAuth(ip,email);throw error;}
        resetFailedAuth(ip,email);
        let session = null;
        if (data.session) {
          const cs = await createUserSession(data.user.id, data.user.email, ip, req.headers['user-agent']);
          session = cs;
        }
        result={user:data.user?{id:data.user.id,email:data.user.email}:null,session};
        break;
      }
      case 'signin': {
        if(!rateLimit(ip,'signin'))return res.status(429).json({error:'Please wait a moment.'});
        const {data,error}=await supabase.auth.signInWithPassword({email:email.trim().toLowerCase(),password});
        if(error){const banned=trackFailedAuth(ip,email);if(banned)return res.status(429).json({error:'Too many failed attempts. Account locked for 15 minutes.'});throw error;}
        resetFailedAuth(ip,email);
        const session = await createUserSession(data.user.id, data.user.email, ip, req.headers['user-agent']);
        result={user:data.user?{id:data.user.id,email:data.user.email}:null,session};
        break;
      }
      case 'signout': {
        if (token) {
          const hashedToken = hashToken(token);
          await supabase.from('user_sessions').update({ is_active: false }).eq('session_token_hash', hashedToken);
        }
        result={success:true};
        break;
      }
      case 'get_user': {
        if(!userId){result={user:null};break;}
        result={user:{id:userId,email:userEmail}};
        break;
      }
      case 'complete_quiz': { if(!userId)return res.status(401).json({error:'Please sign in.'}); const {quiz_id,score,total,percentage,passed,answers,time_taken}=req.body; const {data:existing}=await supabase.from('user_quiz_activity').select('id').eq('user_id',userId).eq('quiz_id',quiz_id).maybeSingle(); if(existing){await supabase.from('user_quiz_activity').update({score,total_possible:total,percentage,passed,answers,time_taken,completed_at:new Date().toISOString()}).eq('id',existing.id);}else{await supabase.from('user_quiz_activity').insert({user_id:userId,quiz_id,score,total_possible:total,percentage,passed,answers,time_taken,completed_at:new Date().toISOString()});} try{await supabase.rpc('update_quiz_stats',{quiz_id_input:quiz_id});}catch(e){} result={success:true,passed,percentage}; break; }
      case 'add_reaction': { if(!userId)return res.status(401).json({error:'Please sign in.'}); const {error}=await supabase.from('user_quiz_activity').update({reaction:req.body.reaction_type}).eq('user_id',userId).eq('quiz_id',req.body.quiz_id); if(error&&error.code!=='PGRST116')throw error; result={success:true}; break; }
      case 'stats': { const ck='stats'; const cached=getCachedResponse(ck); if(cached){result=cached;break;} const [rc,sc,mc]=await Promise.all([supabase.from('biology_notes').select('id',{count:'exact',head:true}),supabase.from('resource_submissions').select('id',{count:'exact',head:true}).eq('status','pending'),supabase.from('contact_messages').select('id',{count:'exact',head:true})]); result={resources:rc.count||0,pendingSubmissions:sc.count||0,messages:mc.count||0}; setCachedResponse(ck,result); break; }
      case 'submissions': { const {data,error}=await supabase.from('resource_submissions').select('id,title,description,author,level,category,tag,status,created_at').order('created_at',{ascending:false}).limit(50); if(error)throw error; result=data||[]; break; }
      case 'approve': { if(!submissionId||!['approve','reject'].includes(req.body.action))throw new Error('Invalid approval'); await supabase.from('resource_submissions').update({status:req.body.action==='approve'?'approved':'rejected'}).eq('id',submissionId); result={success:true}; break; }
      case 'messages': { const {data,error}=await supabase.from('contact_messages').select('id,name,email,subject,message,created_at').order('created_at',{ascending:false}).limit(50); if(error)throw error; result={messages:data||[]}; break; }
      case 'create_payment': { result={payment_id:'demo_'+Date.now(),pay_address:'0xDEMO',pay_amount:req.body.amount||10,pay_currency:req.body.pay_currency||'usdttrc20'}; break; }
      case 'ai_query': { const gk=process.env.GEMINI_API_KEY; if(!gk){result={answer:'AI features coming soon.'};break;} const rp=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${gk}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contents:[{parts:[{text:`You are an expert biology and pharmacy tutor. ${mode==='quiz'?'Generate quiz questions about:':mode==='summarize'?'Summarize this:':'Answer:'} ${prompt}`}]}]})}); const gd=await rp.json(); result={answer:gd.candidates?.[0]?.content?.parts?.[0]?.text||'No response generated.'}; break; }
      case 'get_donate_page_config': { result={nowpayments_api_key:process.env.NOWPAYMENTS_API_KEY||''}; break; }
      case 'submit_momo_donation': { const {error}=await supabase.from('momo_donations').insert({name:(name||'Anonymous').slice(0,100),amount:amount.slice(0,50),txid:txid.slice(0,100)}); if(error)throw error; result={success:true}; break; }
      default: throw new Error('Unknown action');
    }
    responseCache.delete('all_sections'); responseCache.delete('stats');
    return res.status(200).json({ data: result });
  } catch (error) { console.error('POST Error:', error.message); logSecurityEvent('POST_ERROR',{action,error:error.message},req); return res.status(500).json({error:'Internal server error'}); }
}
