const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function getUserFromSession(req) {
  const cookies = parseCookies(req);
  const token = cookies.session || '';
  if (!token || token.length < 20) return null;
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const { data, error } = await supabase
    .from('user_sessions')
    .select('user_id, expires_at, is_active')
    .eq('session_token_hash', hashedToken)
    .eq('is_active', true)
    .single();
  if (error || !data) return null;
  if (new Date(data.expires_at) < new Date()) return null;
  return { user_id: data.user_id };
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
  return req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
}

const rateLimitMap = new Map();
function checkRateLimit(ip, action) {
  const now = Date.now();
  const key = `${ip}:${action}`;
  const record = rateLimitMap.get(key) || { count: 0, reset: now + 60000 };
  if (now > record.reset) { record.count = 0; record.reset = now + 60000; }
  record.count++;
  rateLimitMap.set(key, record);
  return record.count <= 60;
}

function normalizeString(s) {
  return s.toLowerCase().trim().replace(/[^a-z0-9]/g, '');
}

function wordSplit(str) {
  return str.toLowerCase().trim().split(/\s+/).filter(w => w.length > 0);
}

function containsConcept(sentence, concept) {
  const escaped = concept.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`\\b${escaped}\\b`, 'i');
  return regex.test(sentence);
}

function isNegatedConcept(sentence, concept) {
  const escaped = concept.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const negationPatterns = [
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
  return negationPatterns.some(pattern => pattern.test(sentence));
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
    ...(alternateAnswers || []).map(a => ({
      term: a.term,
      explanation: a.explanation || null,
      isPrimary: false
    }))
  ];
  for (const item of acceptedAnswers) {
    const concept = item.term;
    const normalizedConcept = normalizeString(concept);
    if (normalizedAnswer === normalizedConcept) {
      return {
        strength: 'excellent',
        matched: concept,
        xp: 10,
        explanation: item.explanation,
        isPrimary: item.isPrimary
      };
    }
    const isSingleWord = !concept.includes(' ');
    if (isSingleWord) {
      if (containsConcept(userAnswer, concept) && !isNegatedConcept(userAnswer, concept)) {
        return {
          strength: 'excellent',
          matched: concept,
          xp: 10,
          explanation: item.explanation,
          isPrimary: item.isPrimary
        };
      }
    } else {
      if (containsExactPhrase(userAnswer, concept)) {
        return {
          strength: 'excellent',
          matched: concept,
          xp: 10,
          explanation: item.explanation,
          isPrimary: item.isPrimary
        };
      }
    }
  }
  for (const mistake of (commonMistakes || [])) {
    if (containsConcept(userAnswer, mistake.term) && !isNegatedConcept(userAnswer, mistake.term)) {
      return {
        strength: 'developing',
        matched: mistake.term,
        xp: 3,
        isCommonMistake: true,
        mistakeExplanation: mistake.explanation
      };
    }
  }
  for (const item of acceptedAnswers) {
    const concept = item.term;
    const normalizedConcept = normalizeString(concept);
    const distance = levenshteinDistance(normalizedAnswer, normalizedConcept);
    const maxLen = Math.max(normalizedAnswer.length, normalizedConcept.length);
    const similarity = maxLen === 0 ? 1 : 1 - distance / maxLen;
    if (normalizedConcept.length >= 5 && similarity >= 0.85) {
      return {
        strength: 'strong',
        matched: concept,
        xp: 7,
        explanation: item.explanation,
        isPrimary: item.isPrimary,
        note: `The expected term is "${concept}". Your spelling variation was accepted.`
      };
    }
  }
  return { strength: 'developing', matched: correctAnswer, xp: 3 };
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

async function handleCheckSession(userId, params) {
  const { level, topic } = params;
  const today = new Date().toISOString().split('T')[0];
  let query = supabase
    .from('recall_sessions')
    .select('id')
    .eq('user_id', userId)
    .eq('level', level)
    .gte('created_at', today)
    .eq('is_active', false);
  if (topic) {
    query = query.eq('topic', topic);
  } else {
    query = query.is('topic', null);
  }
  const { data: existingSession } = await query.maybeSingle();
  if (existingSession) return { available: false, message: 'Daily session already completed' };
  return { available: true };
}

async function handleGetSession(userId, params) {
  const { level, topic } = params;
  const today = new Date().toISOString().split('T')[0];
  let query = supabase
    .from('recall_sessions')
    .select('*')
    .eq('user_id', userId)
    .eq('level', level)
    .gte('created_at', today)
    .eq('is_active', true);
  if (topic) {
    query = query.eq('topic', topic);
  } else {
    query = query.is('topic', null);
  }
  const { data: existing } = await query.maybeSingle();
  if (existing && existing.questions && existing.questions.length > 0) {
    return {
      session_id: existing.session_id,
      questions: existing.questions,
      current_index: existing.current_index || 0,
      user_answers: existing.user_answers || []
    };
  }
  let completedQuery = supabase
    .from('recall_sessions')
    .select('id')
    .eq('user_id', userId)
    .eq('level', level)
    .gte('created_at', today)
    .eq('is_active', false);
  if (topic) {
    completedQuery = completedQuery.eq('topic', topic);
  } else {
    completedQuery = completedQuery.is('topic', null);
  }
  const { data: completed } = await completedQuery.maybeSingle();
  if (completed) throw new Error('Daily session already completed');

  const { data: userStats } = await supabase
    .from('user_recall_stats')
    .select('weak_concepts')
    .eq('user_id', userId)
    .maybeSingle();
  const weakConcepts = userStats?.weak_concepts || [];

  let questionQuery = supabase
    .from('recall_questions_bank')
    .select('id, question_text, topic, correct_answer, correct_explanation, alternate_answers, common_mistakes')
    .eq('level', level)
    .eq('is_active', true);
  if (topic) {
    questionQuery = questionQuery.eq('topic', topic);
  }
  const { data: rawQuestions, error: questionError } = await questionQuery.limit(10);

  const questions = rawQuestions?.map(q => ({
    id: q.id,
    text: q.question_text,
    topic: q.topic,
    correct_answer: q.correct_answer,
    alternate_answers: q.alternate_answers
  }));

  if (questionError) throw new Error(`Question query failed: ${questionError.message}`);
  if (!questions || questions.length === 0) throw new Error('No questions available for this level and topic');

  let prioritizedQuestions = [...questions].sort((a, b) => {
    const aWeak = weakConcepts.includes(a.correct_answer) ? -1 : 0;
    const bWeak = weakConcepts.includes(b.correct_answer) ? -1 : 0;
    return aWeak - bWeak;
  });

  for (let i = prioritizedQuestions.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [prioritizedQuestions[i], prioritizedQuestions[j]] = [prioritizedQuestions[j], prioritizedQuestions[i]];
  }

  const sessionQuestions = prioritizedQuestions.map((q) => ({
    id: q.id,
    text: q.text,
    topic: q.topic,
    concepts: [q.correct_answer, ...(q.alternate_answers?.map(a => a.term) || [])]
  }));

  const { data: newSession } = await supabase
    .from('recall_sessions')
    .insert({ user_id: userId, level, topic: topic || null, questions: sessionQuestions, current_index: 0, user_answers: [], is_active: true })
    .select()
    .single();

  return { session_id: newSession.session_id, questions: sessionQuestions };
}

async function handleRestoreSession(userId, params) {
  const { session_id } = params;
  const { data: session } = await supabase
    .from('recall_sessions')
    .select('*')
    .eq('session_id', session_id)
    .eq('user_id', userId)
    .maybeSingle();
  if (!session) throw new Error('Session not found');
  return { session_id: session.session_id, current_index: session.current_index || 0, questions: session.questions, user_answers: session.user_answers || [], is_active: session.is_active };
}

async function handleSubmitAnswer(userId, params) {
  const { session_id, question_id, user_answer } = params;
  const { data: session } = await supabase
    .from('recall_sessions')
    .select('*')
    .eq('session_id', session_id)
    .eq('user_id', userId)
    .maybeSingle();
  if (!session) throw new Error('Session not found');
  const question = session.questions?.find(q => q.id === question_id);
  if (!question) throw new Error('Question not found in this session');
  const alreadyAnswered = session.user_answers?.some(a => a.question_id === question_id);
  if (alreadyAnswered) throw new Error('Question already answered');
  const { data: questionBank } = await supabase
    .from('recall_questions_bank')
    .select('correct_answer, correct_explanation, alternate_answers, common_mistakes')
    .eq('id', question_id)
    .single();
  if (!questionBank) throw new Error('Question bank entry not found');
  const result = calculateRecallStrength(
    user_answer,
    questionBank.correct_answer,
    questionBank.alternate_answers,
    questionBank.common_mistakes
  );
  const updatedAnswers = [...(session.user_answers || []), { question_id, answer: user_answer, strength: result.strength, xp_earned: result.xp, answered_at: new Date().toISOString() }];
  await supabase
    .from('recall_sessions')
    .update({ user_answers: updatedAnswers, current_index: (session.current_index || 0) + 1, updated_at: new Date().toISOString() })
    .eq('session_id', session_id);
  const today = new Date().toISOString().split('T')[0];
  const { data: existingStats } = await supabase
    .from('user_recall_stats')
    .select('*')
    .eq('user_id', userId)
    .maybeSingle();

  if (existingStats) {
    const newTotalXp = (existingStats.total_xp || 0) + result.xp;
    const newRecallLevel = Math.floor(newTotalXp / 100) + 1;

    const currentMastery = existingStats.mastery || {};
    let newMastery = { ...currentMastery };
    if (result.strength === 'excellent') newMastery[question.topic] = Math.min(100, (currentMastery[question.topic] || 0) + 5);
    else if (result.strength === 'strong') newMastery[question.topic] = Math.min(100, (currentMastery[question.topic] || 0) + 2);
    else newMastery[question.topic] = Math.max(0, (currentMastery[question.topic] || 100) - 3);

    let newWeakConcepts = existingStats.weak_concepts || [];
    if (result.strength === 'developing') {
      const weakConcept = questionBank.correct_answer;
      if (!newWeakConcepts.includes(weakConcept)) {
        newWeakConcepts.push(weakConcept);
      }
    }

    let newStreak = existingStats.current_streak || 0;
    const lastDate = existingStats.last_session_date;
    if (lastDate === today) {}
    else if (lastDate === new Date(Date.now() - 86400000).toISOString().split('T')[0]) newStreak = (existingStats.current_streak || 0) + 1;
    else newStreak = 1;

    const dailyActivity = existingStats.daily_activity || {};
    dailyActivity[today] = (dailyActivity[today] || 0) + 1;

    let topicXp = existingStats.topic_xp || {};
    let topicStreak = existingStats.topic_streak || {};
    let lastTopicDate = existingStats.last_topic_date || {};

    topicXp[question.topic] = (topicXp[question.topic] || 0) + result.xp;

    if (lastTopicDate[question.topic] === today) {
    } else if (lastTopicDate[question.topic] === new Date(Date.now() - 86400000).toISOString().split('T')[0]) {
      topicStreak[question.topic] = (topicStreak[question.topic] || 0) + 1;
    } else {
      topicStreak[question.topic] = 1;
    }
    lastTopicDate[question.topic] = today;

    await supabase
      .from('user_recall_stats')
      .update({
        total_xp: newTotalXp,
        recall_level: newRecallLevel,
        current_streak: newStreak,
        longest_streak: Math.max(existingStats.longest_streak || 0, newStreak),
        last_session_date: today,
        total_questions: (existingStats.total_questions || 0) + 1,
        excellent_count: (existingStats.excellent_count || 0) + (result.strength === 'excellent' ? 1 : 0),
        strong_count: (existingStats.strong_count || 0) + (result.strength === 'strong' ? 1 : 0),
        developing_count: (existingStats.developing_count || 0) + (result.strength === 'developing' ? 1 : 0),
        mastery: newMastery,
        weak_concepts: newWeakConcepts,
        daily_activity: dailyActivity,
        topic_xp: topicXp,
        topic_streak: topicStreak,
        last_topic_date: lastTopicDate
      })
      .eq('user_id', userId);
  } else {
    const topicXp = { [question.topic]: result.xp };
    const topicStreak = { [question.topic]: 1 };
    const lastTopicDate = { [question.topic]: today };
    let newWeakConcepts = [];
    if (result.strength === 'developing') {
      newWeakConcepts = [questionBank.correct_answer];
    }
    await supabase.from('user_recall_stats').insert({
      user_id: userId,
      total_xp: result.xp,
      recall_level: 1,
      current_streak: 1,
      last_session_date: today,
      total_questions: 1,
      excellent_count: result.strength === 'excellent' ? 1 : 0,
      strong_count: result.strength === 'strong' ? 1 : 0,
      developing_count: result.strength === 'developing' ? 1 : 0,
      mastery: { [question.topic]: result.strength === 'excellent' ? 85 : (result.strength === 'strong' ? 70 : 50) },
      weak_concepts: newWeakConcepts,
      daily_activity: { [today]: 1 },
      topic_xp: topicXp,
      topic_streak: topicStreak,
      last_topic_date: lastTopicDate
    });
  }

  try {
    await supabase.from('recall_xp_log').insert({ user_id: userId, amount: result.xp, reason: result.strength, session_id: session_id, question_id: question_id });
  } catch (e) {}

    feedback: {
    correct_answer: questionBank.correct_answer,

    answer_explanation:
      questionBank.correct_explanation || null,

    related_concepts: relatedConcepts,

    common_mistakes:
      questionBank.common_mistakes || []
  },

  common_mistake_explanation:
    result.mistakeExplanation || null,

  study_note:
    result.note || null
};
}

async function handleCompleteSession(userId, params) {
  const { session_id } = params;
  const { data: session } = await supabase.from('recall_sessions').select('user_answers').eq('session_id', session_id).eq('user_id', userId).single();
  const totalXpEarned = session?.user_answers?.reduce((sum, a) => sum + (a.xp_earned || 0), 0) || 0;
  await supabase.from('recall_sessions').update({ is_active: false, completed_at: new Date().toISOString() }).eq('session_id', session_id).eq('user_id', userId);
  const { data: stats } = await supabase.from('user_recall_stats').select('total_sessions, current_streak').eq('user_id', userId).single();
  if (stats) await supabase.from('user_recall_stats').update({ total_sessions: (stats.total_sessions || 0) + 1 }).eq('user_id', userId);
  return { success: true, xp_earned_total: totalXpEarned, streak_updated: stats?.current_streak || 0 };
}

async function handleGetStats(userId, params) {
  const { level } = params;
  const { data: stats } = await supabase.from('user_recall_stats').select('*').eq('user_id', userId).maybeSingle();
  if (!stats) {
    return {
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
      selected_level: null
    };
  }
  const masteryValues = Object.values(stats.mastery || {});
  const masteryPercent = masteryValues.length > 0 ? Math.round(masteryValues.reduce((a, b) => a + b, 0) / masteryValues.length) : 0;

  return {
    total_xp: stats.total_xp || 0,
    streak_days: stats.current_streak || 0,
    mastery_percent: masteryPercent,
    excellent: stats.excellent_count || 0,
    strong: stats.strong_count || 0,
    developing: stats.developing_count || 0,
    topic_mastery: stats.mastery || {},
    heatmap: stats.daily_activity || {},
    weak_concepts: stats.weak_concepts || [],
    recall_level: stats.recall_level || 1,
    achievements: stats.achievements || [],
    topic_xp: stats.topic_xp || {},
    topic_streak: stats.topic_streak || {},
    selected_level: stats.selected_level || null
  };
}

async function getTopicsForLevel(level) {
  const { data, error } = await supabase
    .from('recall_questions_bank')
    .select('topic')
    .eq('level', level)
    .eq('is_active', true);
  if (error) throw error;
  if (!data || data.length === 0) return [];
  const uniqueTopics = [...new Set(data.map(row => row.topic))];
  return uniqueTopics;
}

async function checkFirstVisit(userId, level, topic) {
  let query = supabase
    .from('recall_sessions')
    .select('id')
    .eq('user_id', userId)
    .eq('level', level);
  if (topic) {
    query = query.eq('topic', topic);
  } else {
    query = query.is('topic', null);
  }
  const { data, error } = await query.limit(1);
  if (error) throw error;
  return { firstVisit: !data || data.length === 0 };
}

module.exports = async (req, res) => {
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://aliverbiopharm.com').split(',').map(o => o.trim());
  const requestOrigin = req.headers.origin || '';
  const corsOrigin = allowedOrigins.includes(requestOrigin) ? requestOrigin : allowedOrigins[0];
  res.setHeader('Access-Control-Allow-Origin', corsOrigin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Session-Token, Cookie');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = getClientIp(req);
  if (!checkRateLimit(ip, 'recall')) return res.status(429).json({ error: 'Too many requests. Please try again later.' });

  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Authentication required. Please sign in.' });

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const method = req.method;
  const actionParam = url.searchParams.get('action');

  if (pathname === '/api/recall/debug' || actionParam === 'debug') {
    const { data, error } = await supabase
      .from('recall_questions_bank')
      .select('id, level, is_active, question_text')
      .limit(10);
    return res.status(200).json({
      rows_found: data?.length || 0,
      sample: data,
      error: error?.message || null,
      supabase_url_prefix: process.env.SUPABASE_URL ? process.env.SUPABASE_URL.substring(0, 40) + '…' : 'missing'
    });
  }

  let handler = null;
  let params = {};

  if (actionParam) {
    switch (actionParam) {
      case 'stats':
        handler = handleGetStats;
        params = { level: url.searchParams.get('level') };
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
      case 'answer':
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed. Use POST for answer.' });
        handler = handleSubmitAnswer;
        let body = '';
        await new Promise((resolve) => { req.on('data', chunk => body += chunk); req.on('end', resolve); });
        try {
          params = JSON.parse(body);
        } catch (e) {
          return res.status(400).json({ error: 'Invalid JSON body' });
        }
        break;
      case 'complete':
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed. Use POST for complete.' });
        handler = handleCompleteSession;
        let body2 = '';
        await new Promise((resolve) => { req.on('data', chunk => body2 += chunk); req.on('end', resolve); });
        try {
          params = JSON.parse(body2);
        } catch (e) {
          return res.status(400).json({ error: 'Invalid JSON body' });
        }
        break;
      case 'topics':
        {
          const level = url.searchParams.get('level');
          if (!level) return res.status(400).json({ error: 'Level required' });
          const topics = await getTopicsForLevel(level);
          return res.status(200).json({ data: topics });
        }
      case 'first_visit':
        {
          const level = url.searchParams.get('level');
          const topic = url.searchParams.get('topic');
          if (!level) return res.status(400).json({ error: 'Level required' });
          const result = await checkFirstVisit(user.user_id, level, topic);
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
          let body = '';
          await new Promise((resolve) => { req.on('data', chunk => body += chunk); req.on('end', resolve); });
          let bodyParams = {};
          try {
            bodyParams = JSON.parse(body);
          } catch (e) {
            return res.status(400).json({ error: 'Invalid JSON body' });
          }
          const { level } = bodyParams;
          if (!level) return res.status(400).json({ error: 'Level required' });
          const { data: existing } = await supabase
            .from('user_recall_stats')
            .select('selected_level')
            .eq('user_id', user.user_id)
            .maybeSingle();
          const isAdmin = await isSuperAdmin(user.user_id);
          if (existing?.selected_level && !isAdmin) {
            return res.status(400).json({ error: 'Level already set and cannot be changed' });
          }
          await supabase
            .from('user_recall_stats')
            .upsert({ user_id: user.user_id, selected_level: level }, { onConflict: 'user_id' });
          return res.status(200).json({ data: { success: true } });
        }
      default:
        return res.status(400).json({ error: `Unknown action: ${actionParam}` });
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
      params = { level: url.searchParams.get('level') };
    } else if (method === 'POST' && (pathname === '/api/recall/answer' || pathname === '/answer')) {
      handler = handleSubmitAnswer;
      let body = '';
      await new Promise((resolve) => { req.on('data', chunk => body += chunk); req.on('end', resolve); });
      try {
        params = JSON.parse(body);
      } catch (e) {
        return res.status(400).json({ error: 'Invalid JSON body' });
      }
    } else if (method === 'POST' && (pathname === '/api/recall/complete' || pathname === '/complete')) {
      handler = handleCompleteSession;
      let body = '';
      await new Promise((resolve) => { req.on('data', chunk => body += chunk); req.on('end', resolve); });
      try {
        params = JSON.parse(body);
      } catch (e) {
        return res.status(400).json({ error: 'Invalid JSON body' });
      }
    }
  }

  if (!handler) return res.status(404).json({ error: 'Endpoint not found' });

  try {
    const result = await handler(user.user_id, params);
    res.status(200).json({ data: result });
  } catch (error) {
    console.error('Recall API error:', error.message);
    const status = error.message === 'Question already answered' || error.message.includes('already completed') ? 400 : 500;
    res.status(status).json({ error: error.message });
  }
};
