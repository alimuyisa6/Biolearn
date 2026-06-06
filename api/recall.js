const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

process.on('unhandledRejection', (err) => {
  console.error(JSON.stringify({ level: 'error', event: 'unhandledRejection', error: err.message, stack: err.stack }));
});

const CACHE_TTL = {
  TOPICS: 60 * 60 * 1000,
  FIRST_VISIT: 5 * 60 * 1000,
  STATS: 30 * 1000,
  DASHBOARD: 30 * 1000,
};
const cache = new Map();
const pendingRequests = new Map();
const rateLimitMemory = new Map();
const globalRateLimit = { count: 0, resetTime: Date.now() + 1000 };
const MAX_GLOBAL_REQUESTS_PER_SECOND = 1000;

function cleanupExpiredCache() {
  const now = Date.now();
  for (const [key, entry] of cache.entries()) {
    if (entry.expires <= now) cache.delete(key);
  }
}
setInterval(cleanupExpiredCache, 5 * 60 * 1000).unref();

function cleanupExpiredNonces() {
  supabase.from('request_nonces').delete().lt('expires_at', new Date().toISOString()).then(() => {}).catch(() => {});
}
setInterval(cleanupExpiredNonces, 60 * 60 * 1000).unref();

function cleanupRateLimitMemory() {
  const now = Date.now();
  for (const [key, record] of rateLimitMemory.entries()) {
    const cutoff = now - 60000;
    record.timestamps = record.timestamps.filter(t => t > cutoff);
    if (record.timestamps.length === 0) rateLimitMemory.delete(key);
  }
}
setInterval(cleanupRateLimitMemory, 60000).unref();

function getCached(key) {
  const entry = cache.get(key);
  if (entry && Date.now() < entry.expires) return entry.value;
  cache.delete(key);
  return null;
}

function setCached(key, value, ttl) {
  cache.set(key, { value, expires: Date.now() + ttl });
  if (cache.size > 500) {
    const oldest = [...cache.entries()].sort((a, b) => a[1].expires - b[1].expires)[0];
    cache.delete(oldest[0]);
  }
}

function invalidateUserCache(userId) {
  cache.delete(`stats:${userId}`);
  cache.delete(`dashboard:${userId}`);
}

async function dedupe(key, fn) {
  if (pendingRequests.has(key)) return pendingRequests.get(key);
  const promise = fn().finally(() => pendingRequests.delete(key));
  pendingRequests.set(key, promise);
  return promise;
}

function withTimeout(promise, ms = 8000) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Database timeout')), ms))
  ]);
}

async function retry(fn, retries = 3, delay = 500) {
  let lastError;
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (i < retries - 1) await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastError;
}

function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
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

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const trustedProxy = process.env.TRUSTED_PROXY === 'true';
  if (trustedProxy && forwarded) return forwarded.split(',')[0].trim();
  return req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown';
}

async function logSecurityEvent(event) {
  try {
    await supabase.from('security_logs').insert(event);
  } catch (e) {}
}

async function checkRateLimit(ip, userId, action) {
  const now = Date.now();
  if (globalRateLimit.resetTime <= now) {
    globalRateLimit.count = 0;
    globalRateLimit.resetTime = now + 1000;
  }
  globalRateLimit.count++;
  if (globalRateLimit.count > MAX_GLOBAL_REQUESTS_PER_SECOND) {
    await logSecurityEvent({ user_id: userId || 'anonymous', action, ip_address: ip, details: 'Global rate limit exceeded', success: false });
    return false;
  }

  const userKey = userId ? `user:${userId}:${action}` : null;
  const ipKey = `ip:${ip}:${action}`;
  const burstWindow = 10000;
  const burstLimit = 20;
  const minuteLimit = 60;

  function checkAndUpdate(key, limit, windowMs) {
    const record = rateLimitMemory.get(key);
    if (!record) {
      rateLimitMemory.set(key, { timestamps: [now], count: 1 });
      return true;
    }
    const cutoff = now - windowMs;
    record.timestamps = record.timestamps.filter(t => t > cutoff);
    if (record.timestamps.length >= limit) return false;
    record.timestamps.push(now);
    rateLimitMemory.set(key, record);
    return true;
  }

  if (userKey && !checkAndUpdate(userKey, minuteLimit, 60000)) return false;
  if (!checkAndUpdate(ipKey, burstLimit, burstWindow)) return false;
  if (userId && !checkAndUpdate(`${userKey}:burst`, burstLimit, burstWindow)) return false;
  return true;
}

 async function getUserFromSession(req) {
  const cookies = parseCookies(req);

  console.log("COOKIE HEADER:", req.headers.cookie);
  console.log("SESSION COOKIE:", cookies.session);

  const token = cookies.session || '';

  if (!token || token.length < 20) {
    console.log("AUTH FAIL: Missing or short token");
    return null;
  }

  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');

  console.log("TOKEN HASH:", hashedToken);

  const { data, error } = await supabase
    .from('user_sessions')
    .select('user_id, expires_at, is_active, csrf_secret')
    .eq('session_token_hash', hashedToken)
    .eq('is_active', true)
    .maybeSingle();

  console.log("SESSION QUERY:", {
    error,
    data
  });

  if (error || !data) {
    console.log("AUTH FAIL: Session not found");
    return null;
  }

  console.log("EXPIRES:", data.expires_at);
  console.log("NOW:", new Date().toISOString());

  if (new Date(data.expires_at) < new Date()) {
    console.log("AUTH FAIL: Session expired");
    return null;
  }

  console.log("AUTH SUCCESS:", data.user_id);

  return {
    user_id: data.user_id,
    csrf_secret: data.csrf_secret
  };
}

function verifyCsrf(req, secret, userId, ip) {
  const token = req.headers['x-csrf-token'];
  if (!token) {
    logSecurityEvent({ user_id: userId, action: 'csrf_missing', ip_address: ip, details: 'Missing CSRF token', success: false });
    throw new Error('Invalid CSRF token');
  }
  try {
    const [timestamp, hmac] = token.split('.');
    if (!timestamp || !hmac) throw new Error();
    const ts = parseInt(timestamp, 10);
    if (Date.now() - ts > 5 * 60 * 1000) throw new Error();
    const expectedHmac = crypto.createHmac('sha256', secret).update(timestamp).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expectedHmac))) throw new Error();
  } catch (e) {
    logSecurityEvent({ user_id: userId, action: 'csrf_invalid', ip_address: ip, details: 'Invalid CSRF token', success: false });
    throw new Error('Invalid CSRF token');
  }
}

async function rotateSession(userId, oldTokenHash) {
  const newToken = crypto.randomBytes(32).toString('hex');
  const newHash = crypto.createHash('sha256').update(newToken).digest('hex');
  const csrfSecret = crypto.randomBytes(32).toString('hex');
  await supabase
    .from('user_sessions')
    .update({ session_token_hash: newHash, csrf_secret: csrfSecret, updated_at: new Date() })
    .eq('session_token_hash', oldTokenHash);
  return { newToken, newCsrfSecret: csrfSecret };
}

function isValidLevel(level) {
  return level === 'O-Level' || level === 'A-Level' || level === 'Pharmacy';
}

function isValidTopic(topic) {
  if (topic === null || topic === undefined) return true;
  return /^[a-zA-Z0-9\s\-]{1,50}$/.test(topic);
}

function isValidSessionId(id) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
}

function isValidQuestionId(id) {
  return Number.isInteger(id) && id > 0;
}

function isValidUserAnswer(answer) {
  return typeof answer === 'string' && answer.length <= 500;
}

function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

async function checkReplayAttack(nonce, userId, action, ttlMs = 60000) {
  const now = Date.now();
  const { data } = await supabase
    .from('request_nonces')
    .select('nonce')
    .eq('nonce', nonce)
    .eq('user_id', userId)
    .maybeSingle();
  if (data) return false;
  await supabase.from('request_nonces').insert({
    nonce,
    user_id: userId,
    action,
    expires_at: new Date(now + ttlMs).toISOString()
  });
  return true;
}

function normalizeString(s) {
  return s.toLowerCase().trim().replace(/[^a-z0-9]/g, '');
}

function containsConcept(sentence, concept) {
  const escaped = concept.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`\\b${escaped}\\b`, 'i').test(sentence);
}

function isNegatedConcept(sentence, concept) {
  const escaped = concept.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`\\bnot\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\bis\\s+not\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\bare\\s+not\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\bwas\\s+not\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\bwere\\s+not\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\bisn't\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\baren't\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\bwasn't\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\bweren't\\s+${escaped}\\b`, 'i'),
    new RegExp(`\\bincorrect\\s*[:\\-]?\\s*${escaped}\\b`, 'i')
  ];
  return patterns.some(p => p.test(sentence));
}

function containsExactPhrase(sentence, phrase) {
  return sentence.toLowerCase().includes(phrase.toLowerCase().trim());
}

function levenshteinDistance(a, b) {
  const matrix = Array(b.length + 1).fill(null).map(() => Array(a.length + 1).fill(null));
  for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j++) matrix[j][0] = j;
  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      const indicator = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(matrix[j][i-1] + 1, matrix[j-1][i] + 1, matrix[j-1][i-1] + indicator);
    }
  }
  return matrix[b.length][a.length];
}

function calculateRecallStrength(userAnswer, correctAnswer, alternateAnswers = [], commonMistakes = []) {
  const normalizedAnswer = normalizeString(userAnswer);
  const acceptedAnswers = [
    { term: correctAnswer, explanation: null, isPrimary: true },
    ...(alternateAnswers || []).map(a => ({ term: a.term, explanation: a.explanation || null, isPrimary: false }))
  ];
  for (const item of acceptedAnswers) {
    const concept = item.term;
    const normalizedConcept = normalizeString(concept);
    if (normalizedAnswer === normalizedConcept) {
      return { strength: 'excellent', matched: concept, xp: 10, explanation: item.explanation, isPrimary: item.isPrimary };
    }
    const isSingleWord = !concept.includes(' ');
    if (isSingleWord) {
      if (containsConcept(userAnswer, concept) && !isNegatedConcept(userAnswer, concept)) {
        return { strength: 'excellent', matched: concept, xp: 10, explanation: item.explanation, isPrimary: item.isPrimary };
      }
    } else {
      if (containsExactPhrase(userAnswer, concept)) {
        return { strength: 'excellent', matched: concept, xp: 10, explanation: item.explanation, isPrimary: item.isPrimary };
      }
    }
  }
  for (const mistake of (commonMistakes || [])) {
    if (containsConcept(userAnswer, mistake.term) && !isNegatedConcept(userAnswer, mistake.term)) {
      return { strength: 'developing', matched: mistake.term, xp: 3, isCommonMistake: true, mistakeExplanation: mistake.explanation };
    }
  }
  for (const item of acceptedAnswers) {
    const concept = item.term;
    const normalizedConcept = normalizeString(concept);
    const distance = levenshteinDistance(normalizedAnswer, normalizedConcept);
    const maxLen = Math.max(normalizedAnswer.length, normalizedConcept.length);
    const similarity = maxLen === 0 ? 1 : 1 - distance / maxLen;
    if (normalizedConcept.length >= 5 && similarity >= 0.85) {
      return { strength: 'strong', matched: concept, xp: 7, explanation: item.explanation, isPrimary: item.isPrimary, note: `The expected term is "${concept}". Your spelling variation was accepted.` };
    }
  }
  return { strength: 'developing', matched: correctAnswer, xp: 3 };
}

async function handleCheckSession(userId, { level, topic }, ip) {
  if (!isValidLevel(level)) throw new Error('Invalid level');
  if (!isValidTopic(topic)) throw new Error('Invalid topic');
  const today = new Date().toISOString().split('T')[0];
  const topicKey = topic || 'all';
  const { data } = await supabase
    .from('user_topic_completion')
    .select('last_completed')
    .eq('user_id', userId)
    .eq('topic_key', topicKey)
    .maybeSingle();
  if (data?.last_completed === today) {
    return { available: false, message: 'You already completed this topic today. Come back tomorrow for more practice.' };
  }
  return { available: true };
}

async function handleGetSession(userId, { level, topic }, ip) {
  if (!isValidLevel(level)) throw new Error('Invalid level');
  if (!isValidTopic(topic)) throw new Error('Invalid topic');
  const today = new Date().toISOString().split('T')[0];
  const topicKey = topic || 'all';

  let query = supabase
    .from('recall_sessions')
    .select('session_id, current_index, user_answers, question_ids, all_question_ids, topic, is_active')
    .eq('user_id', userId)
    .eq('level', level)
    .gte('created_at', today)
    .eq('is_active', true);
  if (topic) query = query.eq('topic', topic);
  else query = query.is('topic', null);
  const { data: existing } = await query.maybeSingle();
  if (existing && existing.question_ids?.length) {
    const { data: questions } = await supabase
      .from('recall_questions_bank')
      .select('id, question_text, topic')
      .in('id', existing.question_ids);
    const ordered = existing.question_ids.map(id => questions?.find(q => q.id === id)).filter(Boolean);
    return {
      session_id: existing.session_id,
      questions: ordered.map(q => ({ id: q.id, text: q.question_text, topic: q.topic, concepts: [] })),
      current_index: existing.current_index || 0,
      user_answers: existing.user_answers || [],
      has_more: existing.question_ids.length < (existing.all_question_ids?.length || 0)
    };
  }

  const { data: completion } = await supabase
    .from('user_topic_completion')
    .select('last_completed')
    .eq('user_id', userId)
    .eq('topic_key', topicKey)
    .maybeSingle();
  if (completion?.last_completed === today) throw new Error('You already completed this topic today. Come back tomorrow.');

  const { data: weakConcepts } = await supabase
    .from('user_weak_concepts')
    .select('concept')
    .eq('user_id', userId);
  const weakSet = new Set((weakConcepts || []).map(w => w.concept));

  let qQuery = supabase
    .from('recall_questions_bank')
    .select('id, question_text, topic, correct_answer, alternate_answers')
    .eq('level', level)
    .eq('is_active', true);
  if (topic) qQuery = qQuery.eq('topic', topic);
  const { data: rawQuestions } = await qQuery;
  if (!rawQuestions?.length) throw new Error('No questions available for this topic yet. Please check back later.');

  const weakQs = rawQuestions.filter(q => weakSet.has(q.correct_answer));
  const normalQs = rawQuestions.filter(q => !weakSet.has(q.correct_answer));
  shuffleArray(normalQs);
  const allSelected = [...weakQs, ...normalQs].slice(0, 20);
  const allQuestionIds = allSelected.map(q => q.id);
  const firstBatchIds = allQuestionIds.slice(0, 5);

  const { data: newSession, error: sessionError } = await supabase
    .from('recall_sessions')
    .insert({
      user_id: userId,
      level,
      topic: topic || null,
      question_ids: firstBatchIds,
      all_question_ids: allQuestionIds,
      current_index: 0,
      user_answers: [],
      is_active: true
    })
    .select('session_id')
    .single();
  if (sessionError) throw new Error(`Failed to create session: ${sessionError.message}`);

  const firstQuestions = allSelected.slice(0, 5).map(q => ({
    id: q.id,
    text: q.question_text,
    topic: q.topic,
    concepts: [q.correct_answer, ...(q.alternate_answers?.map(a => a.term) || [])]
  }));

  return {
    session_id: newSession.session_id,
    questions: firstQuestions,
    has_more: allQuestionIds.length > 5
  };
}

async function handleContinueSession(userId, { session_id }, ip) {
  if (!isValidSessionId(session_id)) throw new Error('Invalid session ID');
  const { data: session, error: sessionError } = await supabase
    .from('recall_sessions')
    .select('question_ids, all_question_ids, current_index, user_answers, level, topic')
    .eq('session_id', session_id)
    .eq('user_id', userId)
    .maybeSingle();
  if (sessionError || !session) throw new Error('Session not found');

  const currentIds = session.question_ids || [];
  const allIds = session.all_question_ids || [];
  const nextStart = currentIds.length;
  const nextBatch = allIds.slice(nextStart, nextStart + 5);

  if (nextBatch.length === 0) return { has_more: false, questions: [] };

  const newQuestionIds = [...currentIds, ...nextBatch];
  const { error: updateError } = await supabase
    .from('recall_sessions')
    .update({ question_ids: newQuestionIds })
    .eq('session_id', session_id);
  if (updateError) throw new Error(`Failed to load more questions: ${updateError.message}`);

  const { data: questions } = await supabase
    .from('recall_questions_bank')
    .select('id, question_text, topic, correct_answer, alternate_answers')
    .in('id', nextBatch);
  const ordered = nextBatch.map(id => questions?.find(q => q.id === id)).filter(Boolean);
  const formatted = ordered.map(q => ({
    id: q.id,
    text: q.question_text,
    topic: q.topic,
    concepts: [q.correct_answer, ...(q.alternate_answers?.map(a => a.term) || [])]
  }));

  return {
    has_more: newQuestionIds.length < allIds.length,
    questions: formatted
  };
}

async function handleRestoreSession(userId, { session_id }, ip) {
  if (!isValidSessionId(session_id)) throw new Error('Invalid session ID');
  const { data: session } = await supabase
    .from('recall_sessions')
    .select('session_id, current_index, user_answers, question_ids, all_question_ids, is_active')
    .eq('session_id', session_id)
    .eq('user_id', userId)
    .maybeSingle();
  if (!session) throw new Error('Session not found');
  if (session.question_ids?.length) {
    const { data: questions } = await supabase
      .from('recall_questions_bank')
      .select('id, question_text, topic')
      .in('id', session.question_ids);
    const ordered = session.question_ids.map(id => questions?.find(q => q.id === id)).filter(Boolean);
    return {
      session_id: session.session_id,
      current_index: session.current_index || 0,
      questions: ordered.map(q => ({ id: q.id, text: q.question_text, topic: q.topic, concepts: [] })),
      user_answers: session.user_answers || [],
      is_active: session.is_active,
      has_more: session.question_ids.length < (session.all_question_ids?.length || 0)
    };
  }
  return {
    session_id: session.session_id,
    current_index: session.current_index || 0,
    questions: [],
    user_answers: session.user_answers || [],
    is_active: session.is_active,
    has_more: false
  };
}

async function handleSubmitAnswer(userId, params, ip) {
  const { session_id, question_id, user_answer, nonce } = params;
  if (!isValidSessionId(session_id)) throw new Error('Invalid session ID');
  if (!isValidQuestionId(question_id)) throw new Error('Invalid question ID');
  if (!isValidUserAnswer(user_answer)) throw new Error('Invalid answer');
  if (!nonce || typeof nonce !== 'string' || nonce.length < 16) throw new Error('Invalid request');
  const replayOk = await checkReplayAttack(nonce, userId, 'answer', 30000);
  if (!replayOk) throw new Error('Duplicate request');

  const today = new Date().toISOString().split('T')[0];

  const { data: session, error: sessionError } = await supabase
    .from('recall_sessions')
    .select('session_id, current_index, user_answers, question_ids, is_active, topic, version')
    .eq('session_id', session_id)
    .eq('user_id', userId)
    .maybeSingle();
  if (sessionError || !session) throw new Error('Session not found');
  if (!session.is_active) throw new Error('This session is already completed');
  if (session.current_index >= session.question_ids.length) throw new Error('All questions already answered in this batch');

  const alreadyAnswered = session.user_answers?.some(a => a.question_id === question_id);
  if (alreadyAnswered) {
    await logSecurityEvent({ user_id: userId, action: 'duplicate_answer', ip_address: ip, details: `Question ${question_id} already answered`, success: false });
    throw new Error('Question already answered');
  }

  const { data: questionBank, error: questionError } = await supabase
    .from('recall_questions_bank')
    .select('correct_answer, correct_explanation, alternate_answers, common_mistakes')
    .eq('id', question_id)
    .single();
  if (questionError || !questionBank) throw new Error('Question not found');

  const result = calculateRecallStrength(
    user_answer,
    questionBank.correct_answer,
    questionBank.alternate_answers,
    questionBank.common_mistakes
  );

  const newUserAnswers = [...(session.user_answers || []), {
    question_id,
    answer: user_answer,
    strength: result.strength,
    xp_earned: result.xp,
    answered_at: new Date().toISOString()
  }];
  const newIndex = session.current_index + 1;
  const completed = newIndex >= session.question_ids.length;

  const { error: updateError } = await supabase
    .from('recall_sessions')
    .update({
      user_answers: newUserAnswers,
      current_index: newIndex,
      is_active: !completed,
      completed_at: completed ? new Date().toISOString() : null,
      version: (session.version || 0) + 1
    })
    .eq('session_id', session_id)
    .eq('version', session.version || 0);
  if (updateError || (updateError && updateError.code === 'PGRST116')) {
    throw new Error('Concurrent modification, please retry');
  }

  const statsQuery = await supabase
    .from('user_recall_stats')
    .select('total_xp, recall_level, current_streak, mastery, best_streak, best_mastery, milestones')
    .eq('user_id', userId)
    .maybeSingle();
  let stats = statsQuery.data || {
    total_xp: 0,
    recall_level: 1,
    current_streak: 0,
    mastery: {},
    best_streak: 0,
    best_mastery: 0,
    milestones: []
  };

  const newTotalXp = (stats.total_xp || 0) + result.xp;
  const newRecallLevel = Math.floor(newTotalXp / 100) + 1;

  const currentMastery = stats.mastery || {};
  let newMastery = { ...currentMastery };
  const topicName = session.topic || 'General';
  if (result.strength === 'excellent') newMastery[topicName] = Math.min(100, (currentMastery[topicName] || 0) + 5);
  else if (result.strength === 'strong') newMastery[topicName] = Math.min(100, (currentMastery[topicName] || 0) + 2);
  else newMastery[topicName] = Math.max(0, (currentMastery[topicName] || 100) - 3);

  if (result.strength === 'developing') {
    await supabase
      .from('user_weak_concepts')
      .upsert({ user_id: userId, concept: questionBank.correct_answer }, { onConflict: 'user_id,concept' });
  }

  let newStreak = stats.current_streak || 0;
  const lastDate = stats.last_session_date;
  if (lastDate === today) {
  } else if (lastDate === new Date(Date.now() - 86400000).toISOString().split('T')[0]) {
    newStreak = (stats.current_streak || 0) + 1;
  } else {
    newStreak = 1;
  }

  await supabase
    .from('user_daily_activity')
    .upsert({ user_id: userId, activity_date: today, count: 1 }, { onConflict: 'user_id,activity_date' });

  await supabase
    .from('user_topic_stats')
    .upsert({
      user_id: userId,
      topic: topicName,
      xp: result.xp,
      streak: 1,
      last_activity_date: today
    }, { onConflict: 'user_id,topic' });

  let milestones = stats.milestones || [];
  if (newRecallLevel > (stats.recall_level || 1) && !milestones.includes(`Level ${newRecallLevel}`)) {
    milestones.push(`Level ${newRecallLevel}`);
    await supabase.from('user_milestones').insert({ user_id: userId, milestone: `Level ${newRecallLevel}` });
    await logSecurityEvent({ user_id: userId, action: 'milestone', ip_address: ip, details: `Reached level ${newRecallLevel}`, success: true });
  }
  if (newStreak === 7 && !milestones.includes('7 Day Streak')) {
    milestones.push('7 Day Streak');
    await supabase.from('user_milestones').insert({ user_id: userId, milestone: '7 Day Streak' });
  }
  if (newStreak === 30 && !milestones.includes('30 Day Streak')) {
    milestones.push('30 Day Streak');
    await supabase.from('user_milestones').insert({ user_id: userId, milestone: '30 Day Streak' });
  }
  if (newStreak === 100 && !milestones.includes('100 Day Streak')) {
    milestones.push('100 Day Streak');
    await supabase.from('user_milestones').insert({ user_id: userId, milestone: '100 Day Streak' });
  }

  let bestStreak = stats.best_streak || 0;
  if (newStreak > bestStreak) bestStreak = newStreak;
  const masteryValues = Object.values(newMastery);
  const avgMastery = masteryValues.length ? masteryValues.reduce((a,b)=>a+b,0)/masteryValues.length : 0;
  let bestMastery = stats.best_mastery || 0;
  if (avgMastery > bestMastery) bestMastery = avgMastery;

  const { error: statsUpsertError } = await supabase
    .from('user_recall_stats')
    .upsert({
      user_id: userId,
      total_xp: newTotalXp,
      recall_level: newRecallLevel,
      current_streak: newStreak,
      last_session_date: today,
      total_questions: (stats.total_questions || 0) + 1,
      excellent_count: (stats.excellent_count || 0) + (result.strength === 'excellent' ? 1 : 0),
      strong_count: (stats.strong_count || 0) + (result.strength === 'strong' ? 1 : 0),
      developing_count: (stats.developing_count || 0) + (result.strength === 'developing' ? 1 : 0),
      mastery: newMastery,
      best_streak: bestStreak,
      best_mastery: bestMastery,
      milestones: milestones
    }, { onConflict: 'user_id' });
  if (statsUpsertError) throw new Error(`Failed to update stats: ${statsUpsertError.message}`);

  supabase.from('recall_xp_log').insert({
    user_id: userId,
    amount: result.xp,
    reason: result.strength,
    session_id,
    question_id
  }).catch(() => {});

  invalidateUserCache(userId);

  const relatedConcepts = [
    questionBank.correct_answer,
    ...(questionBank.alternate_answers?.map(a => a.term) || [])
  ];

  if (completed) {
    const topicKey = session.topic || 'all';
    await supabase
      .from('user_topic_completion')
      .upsert({ user_id: userId, topic_key: topicKey, last_completed: today }, { onConflict: 'user_id,topic_key' });
  }

  return {
    strength: result.strength,
    xp: result.xp,
    matched: result.matched,
    feedback: {
      correct_answer: questionBank.correct_answer,
      answer_explanation: questionBank.correct_explanation || null,
      related_concepts: relatedConcepts,
      common_mistakes: questionBank.common_mistakes || []
    },
    common_mistake_explanation: result.mistakeExplanation || null,
    study_note: result.note || null
  };
}

async function handleCompleteSession(userId, { session_id }, ip) {
  if (!isValidSessionId(session_id)) throw new Error('Invalid session ID');
  const { data: session, error: sessionError } = await supabase
    .from('recall_sessions')
    .select('user_answers, topic, is_active')
    .eq('session_id', session_id)
    .eq('user_id', userId)
    .maybeSingle();
  if (sessionError) throw new Error(`Session not found: ${sessionError.message}`);
  if (!session) throw new Error('Session not found');
  if (!session.is_active) {
    return { success: true, xp_earned_total: 0, streak_updated: 0, already_completed: true };
  }
  const totalXpEarned = session?.user_answers?.reduce((sum, a) => sum + (a.xp_earned || 0), 0) || 0;
  const { error: updateError } = await supabase
    .from('recall_sessions')
    .update({ is_active: false, completed_at: new Date().toISOString() })
    .eq('session_id', session_id);
  if (updateError) throw new Error(`Failed to complete session: ${updateError.message}`);

  const today = new Date().toISOString().split('T')[0];
  const topicKey = session.topic || 'all';
  await supabase
    .from('user_topic_completion')
    .upsert({ user_id: userId, topic_key: topicKey, last_completed: today }, { onConflict: 'user_id,topic_key' });

  const { data: stats } = await supabase
    .from('user_recall_stats')
    .select('total_sessions, current_streak')
    .eq('user_id', userId)
    .single();
  if (stats) {
    await supabase
      .from('user_recall_stats')
      .update({ total_sessions: (stats.total_sessions || 0) + 1 })
      .eq('user_id', userId);
  }
  return { success: true, xp_earned_total: totalXpEarned, streak_updated: stats?.current_streak || 0 };
}

async function handleGetStats(userId, ip) {
  const cacheKey = `stats:${userId}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  const { data: stats } = await supabase
    .from('user_recall_stats')
    .select('total_xp, current_streak, mastery, excellent_count, strong_count, developing_count, recall_level, total_questions, best_streak, best_mastery, milestones, selected_level')
    .eq('user_id', userId)
    .maybeSingle();
  if (!stats) {
    const empty = {
      total_xp: 0,
      streak_days: 0,
      mastery_percent: 0,
      excellent: 0,
      strong: 0,
      developing: 0,
      topic_mastery: {},
      heatmap: {},
      weak_concepts: [],
      recall_level: 1,
      achievements: [],
      topic_xp: {},
      topic_streak: {},
      selected_level: null,
      milestones: [],
      best_streak: 0,
      best_mastery: 0,
      total_questions: 0
    };
    setCached(cacheKey, empty, CACHE_TTL.STATS);
    return empty;
  }
  const masteryValues = Object.values(stats.mastery || {});
  const masteryPercent = masteryValues.length ? Math.round(masteryValues.reduce((a,b)=>a+b,0)/masteryValues.length) : 0;
  const { data: daily } = await supabase
    .from('user_daily_activity')
    .select('activity_date, count')
    .eq('user_id', userId);
  const heatmap = {};
  (daily || []).forEach(d => { heatmap[d.activity_date] = d.count; });
  const { data: topics } = await supabase
    .from('user_topic_stats')
    .select('topic, xp, streak')
    .eq('user_id', userId);
  const topicXp = {};
  const topicStreak = {};
  (topics || []).forEach(t => { topicXp[t.topic] = t.xp; topicStreak[t.topic] = t.streak; });
  const { data: weaks } = await supabase
    .from('user_weak_concepts')
    .select('concept')
    .eq('user_id', userId);
  const weakConcepts = (weaks || []).map(w => w.concept);
  const { data: milestones } = await supabase
    .from('user_milestones')
    .select('milestone')
    .eq('user_id', userId);
  const milestoneList = (milestones || []).map(m => m.milestone);
  const result = {
    total_xp: stats.total_xp || 0,
    streak_days: stats.current_streak || 0,
    mastery_percent: masteryPercent,
    excellent: stats.excellent_count || 0,
    strong: stats.strong_count || 0,
    developing: stats.developing_count || 0,
    topic_mastery: stats.mastery || {},
    heatmap: heatmap,
    weak_concepts: weakConcepts,
    recall_level: stats.recall_level || 1,
    achievements: [],
    topic_xp: topicXp,
    topic_streak: topicStreak,
    selected_level: stats.selected_level || null,
    milestones: milestoneList,
    best_streak: stats.best_streak || 0,
    best_mastery: stats.best_mastery || 0,
    total_questions: stats.total_questions || 0
  };
  setCached(cacheKey, result, CACHE_TTL.STATS);
  return result;
}

async function handleGetAchievements(userId, ip) {
  const { data: stats } = await supabase
    .from('user_recall_stats')
    .select('total_xp, current_streak, mastery, total_questions')
    .eq('user_id', userId)
    .single();
  if (!stats) return [];
  const xpTotal = stats.total_xp || 0;
  const streak = stats.current_streak || 0;
  const mastery = stats.mastery || {};
  const totalQuestions = stats.total_questions || 0;
  return [
    { key: 'firstRecall', title: 'First Recall', icon: 'fa-fire', unlocked: xpTotal > 0 },
    { key: 'tenQuestions', title: '10 Questions', icon: 'fa-bolt', unlocked: totalQuestions >= 10 },
    { key: 'fiftyQuestions', title: '50 Questions', icon: 'fa-trophy', unlocked: totalQuestions >= 50 },
    { key: 'hundredQuestions', title: '100 Questions', icon: 'fa-crown', unlocked: totalQuestions >= 100 },
    { key: 'sevenStreak', title: '7 Day Streak', icon: 'fa-fire', unlocked: streak >= 7 },
    { key: 'thirtyStreak', title: '30 Day Streak', icon: 'fa-star', unlocked: streak >= 30 },
    { key: 'hundredStreak', title: '100 Day Streak', icon: 'fa-gem', unlocked: streak >= 100 },
    { key: 'geneticsMaster', title: 'Genetics Master', icon: 'fa-dna', unlocked: (mastery.Genetics || 0) >= 80 },
    { key: 'cellMaster', title: 'Cell Biology Master', icon: 'fa-microscope', unlocked: (mastery['Cell Biology'] || 0) >= 80 },
    { key: 'pharmaMaster', title: 'Pharmacology Master', icon: 'fa-capsules', unlocked: (mastery.Pharmacology || 0) >= 80 }
  ];
}

async function handleGetDashboard(userId, ip) {
  const cacheKey = `dashboard:${userId}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  const { data: stats } = await supabase
    .from('user_recall_stats')
    .select('total_xp, recall_level, current_streak, best_streak, best_mastery, total_questions, selected_level')
    .eq('user_id', userId)
    .single();
  if (!stats) {
    const empty = { level: 1, xp: 0, xpToNext: 100, progressPercent: 0, streak: 0, bestStreak: 0, bestMastery: 0, totalQuestions: 0, milestones: [], dailyChallenge: { completed: 0, target: 10, progressPercent: 0 }, gardenStage: 'seedling', subjectIllustration: 'fa-flask', quote: 'Welcome! Start your first recall session.', brainEnergy: 100 };
    setCached(cacheKey, empty, CACHE_TTL.DASHBOARD);
    return empty;
  }
  const today = new Date().toISOString().split('T')[0];
  const { data: daily } = await supabase
    .from('user_daily_activity')
    .select('count')
    .eq('user_id', userId)
    .eq('activity_date', today)
    .maybeSingle();
  const dailyQuestions = daily?.count || 0;
  const progressPercent = (stats.total_xp % 100);
  let gardenStage = 'seedling';
  if (stats.current_streak >= 100) gardenStage = 'tree';
  else if (stats.current_streak >= 30) gardenStage = 'tree';
  else if (stats.current_streak >= 7) gardenStage = 'seedling';
  const subjectIllustration = {
    'O-Level': 'fa-microscope',
    'A-Level': 'fa-dna',
    'Pharmacy': 'fa-capsules'
  };
  const quotes = [
    '"The cell is the basic unit of life." - Schleiden & Schwann',
    '"Knowledge grows through active recall."',
    '"Practice makes progress, not perfect."',
    '"The brain learns by retrieval, not repetition."'
  ];
  const randomQuote = quotes[Math.floor(Math.random() * quotes.length)];
  const { data: milestones } = await supabase
    .from('user_milestones')
    .select('milestone')
    .eq('user_id', userId);
  const milestoneList = (milestones || []).map(m => m.milestone);
  const result = {
    level: stats.recall_level || 1,
    xp: stats.total_xp || 0,
    xpToNext: 100 - (stats.total_xp % 100),
    progressPercent,
    streak: stats.current_streak || 0,
    bestStreak: stats.best_streak || 0,
    bestMastery: stats.best_mastery || 0,
    totalQuestions: stats.total_questions || 0,
    milestones: milestoneList,
    dailyChallenge: { completed: dailyQuestions, target: 10, progressPercent: (dailyQuestions / 10) * 100 },
    gardenStage,
    subjectIllustration: subjectIllustration[stats.selected_level] || 'fa-flask',
    quote: randomQuote,
    brainEnergy: 100
  };
  setCached(cacheKey, result, CACHE_TTL.DASHBOARD);
  return result;
}

async function getTopicsForLevel(level, ip) {
  if (!isValidLevel(level)) throw new Error('Invalid level');
  const cacheKey = `topics:${level}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  const { data, error } = await supabase
    .from('recall_questions_bank')
    .select('topic')
    .eq('level', level)
    .eq('is_active', true);
  if (error) throw error;
  if (!data || data.length === 0) return [];
  const uniqueTopics = [...new Set(data.map(row => row.topic))];
  const result = uniqueTopics.map(t => ({ name: t, icon: 'fa-book' }));
  setCached(cacheKey, result, CACHE_TTL.TOPICS);
  return result;
}

async function checkFirstVisit(userId, level, topic, ip) {
  if (!isValidLevel(level)) throw new Error('Invalid level');
  if (!isValidTopic(topic)) throw new Error('Invalid topic');
  const cacheKey = `firstVisit:${userId}:${level}:${topic || 'null'}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  let query = supabase
    .from('recall_sessions')
    .select('id')
    .eq('user_id', userId)
    .eq('level', level);
  if (topic) query = query.eq('topic', topic);
  else query = query.is('topic', null);
  const { data, error } = await query.limit(1);
  if (error) throw error;
  const result = { firstVisit: !data || data.length === 0 };
  setCached(cacheKey, result, CACHE_TTL.FIRST_VISIT);
  return result;
}

async function isSuperAdmin(userId) {
  const { data, error } = await supabase
    .from('admin_master')
    .select('admin_role')
    .eq('admin_id', userId)
    .maybeSingle();
  if (error || !data) return false;
  return data.admin_role === 'super_admin';
}

module.exports = async (req, res) => {
  const nonce = generateNonce();
  const csp = `default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'nonce-${nonce}'; style-src 'self' https://fonts.googleapis.com 'nonce-${nonce}'; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self' /api/recall`;
  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');

  const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://aliverbiopharm.com').split(',').map(o => o.trim());
  const requestOrigin = req.headers.origin;
  if (allowedOrigins.includes(requestOrigin)) res.setHeader('Access-Control-Allow-Origin', requestOrigin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Session-Token, Cookie');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = getClientIp(req);
  let contentType = req.headers['content-type'] || '';
  if (req.method === 'POST' && !contentType.match(/^application\/json(;.*)?$/)) {
    return res.status(415).json({ error: 'Unsupported Media Type' });
  }

  let rawBody = '';
  let bodySize = 0;
  req.on('data', chunk => {
    bodySize += chunk.length;
    if (bodySize > 10240) {
      req.destroy();
      if (!res.headersSent) res.status(413).json({ error: 'Payload Too Large' });
    } else {
      rawBody += chunk;
    }
  });
  await new Promise((resolve, reject) => {
    req.on('end', resolve);
    req.on('error', reject);
  });
  if (bodySize > 10240) return;

  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Authentication required. Please sign in.' });

  if (!(await checkRateLimit(ip, user.user_id, 'recall'))) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const method = req.method;
  const action = url.searchParams.get('action');

  if (pathname.includes('/debug') || action === 'debug') {
    return res.status(404).json({ error: 'Not found' });
  }

  let handler = null;
  let params = {};

  if (action) {
    switch (action) {
      case 'stats':
        handler = handleGetStats;
        break;
      case 'session':
        handler = handleGetSession;
        params = { level: url.searchParams.get('level'), topic: url.searchParams.get('topic') };
        break;
      case 'session_check':
        handler = handleCheckSession;
        params = { level: url.searchParams.get('level'), topic: url.searchParams.get('topic') };
        break;
      case 'restore_session':
        handler = handleRestoreSession;
        params = { session_id: url.searchParams.get('session_id') };
        break;
      case 'continue':
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed. Use POST for continue.' });
        verifyCsrf(req, user.csrf_secret, user.user_id, ip);
        try { params = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
        handler = handleContinueSession;
        break;
      case 'answer':
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed. Use POST for answer.' });
        verifyCsrf(req, user.csrf_secret, user.user_id, ip);
        try { params = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
        if (!params.nonce) params.nonce = generateNonce();
        handler = handleSubmitAnswer;
        break;
      case 'complete':
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed. Use POST for complete.' });
        verifyCsrf(req, user.csrf_secret, user.user_id, ip);
        try { params = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
        handler = handleCompleteSession;
        break;
      case 'topics':
        {
          const level = url.searchParams.get('level');
          if (!level) return res.status(400).json({ error: 'Level required' });
          const topics = await getTopicsForLevel(level, ip);
          return res.status(200).json({ data: topics });
        }
      case 'first_visit':
        {
          const level = url.searchParams.get('level');
          const topic = url.searchParams.get('topic');
          if (!level) return res.status(400).json({ error: 'Level required' });
          const result = await checkFirstVisit(user.user_id, level, topic, ip);
          return res.status(200).json({ data: result });
        }
      case 'get_selected_level':
        {
          const { data, error } = await supabase
            .from('user_recall_stats')
            .select('selected_level')
            .eq('user_id', user.user_id)
            .maybeSingle();
          if (error) throw error;
          const isAdmin = await isSuperAdmin(user.user_id);
          return res.status(200).json({ data: { selected_level: data?.selected_level || null, is_super_admin: isAdmin } });
        }
      case 'set_selected_level':
        {
          verifyCsrf(req, user.csrf_secret, user.user_id, ip);
          let bodyParams = {};
          try { bodyParams = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
          const { level } = bodyParams;
          if (!level) return res.status(400).json({ error: 'Level required' });
          if (!isValidLevel(level)) return res.status(400).json({ error: 'Invalid level value' });
          const { data: existing } = await supabase
            .from('user_recall_stats')
            .select('selected_level')
            .eq('user_id', user.user_id)
            .maybeSingle();
          const isAdmin = await isSuperAdmin(user.user_id);
          if (existing?.selected_level && !isAdmin) return res.status(400).json({ error: 'Level already set and cannot be changed' });
          await supabase.from('user_recall_stats').upsert({ user_id: user.user_id, selected_level: level }, { onConflict: 'user_id' });
          invalidateUserCache(user.user_id);
          return res.status(200).json({ data: { success: true } });
        }
      case 'achievements':
        handler = handleGetAchievements;
        break;
      case 'dashboard':
        handler = handleGetDashboard;
        break;
      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  } else {
    if (method === 'GET' && (pathname === '/api/recall/session/check' || pathname === '/session/check')) {
      handler = handleCheckSession;
      params = { level: url.searchParams.get('level'), topic: url.searchParams.get('topic') };
    } else if (method === 'GET' && (pathname === '/api/recall/session' || pathname === '/session')) {
      handler = handleGetSession;
      params = { level: url.searchParams.get('level'), topic: url.searchParams.get('topic') };
    } else if (method === 'GET' && (pathname.match(/^\/api\/recall\/session\/[a-f0-9-]+$/) || pathname.match(/^\/session\/[a-f0-9-]+$/))) {
      handler = handleRestoreSession;
      params = { session_id: pathname.split('/').pop() };
    } else if (method === 'GET' && (pathname === '/api/recall/stats' || pathname === '/stats')) {
      handler = handleGetStats;
    } else if (method === 'POST' && (pathname === '/api/recall/continue' || pathname === '/continue')) {
      verifyCsrf(req, user.csrf_secret, user.user_id, ip);
      try { params = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
      handler = handleContinueSession;
    } else if (method === 'POST' && (pathname === '/api/recall/answer' || pathname === '/answer')) {
      verifyCsrf(req, user.csrf_secret, user.user_id, ip);
      try { params = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
      if (!params.nonce) params.nonce = generateNonce();
      handler = handleSubmitAnswer;
    } else if (method === 'POST' && (pathname === '/api/recall/complete' || pathname === '/complete')) {
      verifyCsrf(req, user.csrf_secret, user.user_id, ip);
      try { params = JSON.parse(rawBody); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
      handler = handleCompleteSession;
    }
  }

  if (!handler) return res.status(404).json({ error: 'Endpoint not found' });

  const dedupeKey = `${handler.name}:${user.user_id}:${JSON.stringify(params)}`;
  const startTime = Date.now();

  try {
    const result = await retry(() => withTimeout(dedupe(dedupeKey, () => handler(user.user_id, params, ip)), 10000));
    const duration = Date.now() - startTime;
    if (duration > 3000) {
      console.error(JSON.stringify({ level: 'warn', event: 'slow_query', handler: handler.name, duration, userId: user.user_id }));
    }
    res.status(200).json({ data: result });
  } catch (error) {
    console.error(JSON.stringify({ level: 'error', event: 'handler_error', handler: handler.name, error: error.message, userId: user.user_id }));
    const status = error.message === 'Question already answered' || error.message.includes('already completed') ? 400 : 500;
    res.status(status).json({ error: 'An internal error occurred. Please try again later.' });
  }
};
