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
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.headers['x-real-ip'] || 'unknown';
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

function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
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
  const topicKey = topic || 'all';
  const { data: stats } = await supabase
    .from('user_recall_stats')
    .select('topic_completion')
    .eq('user_id', userId)
    .maybeSingle();
  const completion = stats?.topic_completion || {};
  if (completion[topicKey] === today) {
    return { available: false, message: 'Daily session already completed for this topic' };
  }
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
  if (topic) query = query.eq('topic', topic);
  else query = query.is('topic', null);
  const { data: existing } = await query.maybeSingle();
  if (existing && existing.questions && existing.questions.length > 0) {
    return {
      session_id: existing.session_id,
      questions: existing.questions,
      current_index: existing.current_index || 0,
      user_answers: existing.user_answers || []
    };
  }
  const topicKey = topic || 'all';
  const { data: stats } = await supabase
    .from('user_recall_stats')
    .select('topic_completion')
    .eq('user_id', userId)
    .maybeSingle();
  const completion = stats?.topic_completion || {};
  if (completion[topicKey] === today) {
    throw new Error('Daily session already completed');
  }
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
  if (topic) questionQuery = questionQuery.eq('topic', topic);
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

  const weakQuestions = questions.filter(q => weakConcepts.includes(q.correct_answer));
  const normalQuestions = questions.filter(q => !weakConcepts.includes(q.correct_answer));
  shuffleArray(normalQuestions);
  const prioritizedQuestions = [...weakQuestions, ...normalQuestions];

  const sessionQuestions = prioritizedQuestions.map((q) => ({
    id: q.id,
    text: q.text,
    topic: q.topic,
    concepts: [q.correct_answer, ...(q.alternate_answers?.map(a => a.term) || [])]
  }));

  const { data: newSession, error: sessionError } = await supabase
    .from('recall_sessions')
    .insert({ user_id: userId, level, topic: topic || null, questions: sessionQuestions, current_index: 0, user_answers: [], is_active: true })
    .select()
    .single();

  if (sessionError) throw new Error(`Failed to create session: ${sessionError.message}`);

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
  if (!session.is_active) throw new Error('Session already completed');
  if (session.current_index >= session.questions.length) {
    await supabase.from('recall_sessions').update({ is_active: false }).eq('session_id', session_id);
    throw new Error('All questions already answered');
  }
  const question = session.questions?.find(q => q.id === question_id);
  if (!question) throw new Error('Question not found in this session');
  const alreadyAnswered = session.user_answers?.some(a => a.question_id === question_id);
  if (alreadyAnswered) {
    return { strength: 'already_answered', xp: 0, matched: question.concepts?.[0] || 'concept', feedback: {} };
  }

  const { data: questionBank, error: qError } = await supabase
    .from('recall_questions_bank')
    .select('correct_answer, correct_explanation, alternate_answers, common_mistakes')
    .eq('id', question_id)
    .single();
  if (qError || !questionBank) throw new Error('Question bank entry not found');

  const result = calculateRecallStrength(user_answer, questionBank.correct_answer, questionBank.alternate_answers, questionBank.common_mistakes);

  const updatedAnswers = [...(session.user_answers || []), { question_id, answer: user_answer, strength: result.strength, xp_earned: result.xp, answered_at: new Date().toISOString() }];
  const { error: updateError } = await supabase
    .from('recall_sessions')
    .update({ user_answers: updatedAnswers, current_index: (session.current_index || 0) + 1, updated_at: new Date().toISOString() })
    .eq('session_id', session_id);
  if (updateError) throw new Error(`Failed to update session: ${updateError.message}`);

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
      if (!newWeakConcepts.includes(weakConcept)) newWeakConcepts.push(weakConcept);
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

    let milestones = existingStats.milestones || [];
    if (newRecallLevel > (existingStats.recall_level || 1) && !milestones.includes(`Level ${newRecallLevel}`)) {
      milestones.push(`Level ${newRecallLevel}`);
    }
    if (newStreak === 7 && !milestones.includes('7 Day Streak')) milestones.push('7 Day Streak');
    if (newStreak === 30 && !milestones.includes('30 Day Streak')) milestones.push('30 Day Streak');
    if (newStreak === 100 && !milestones.includes('100 Day Streak')) milestones.push('100 Day Streak');

    let bestStreak = existingStats.best_streak || 0;
    if (newStreak > bestStreak) bestStreak = newStreak;

    const avgMastery = Object.values(newMastery).reduce((a,b)=>a+b,0) / (Object.keys(newMastery).length || 1);
    let bestMastery = existingStats.best_mastery || 0;
    if (avgMastery > bestMastery) bestMastery = avgMastery;

    const { error: statsUpdateError } = await supabase
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
        last_topic_date: lastTopicDate,
        milestones: milestones,
        best_streak: bestStreak,
        best_mastery: bestMastery
      })
      .eq('user_id', userId);
    if (statsUpdateError) throw new Error(`Failed to update stats: ${statsUpdateError.message}`);
  } else {
    let newWeakConcepts = [];
    if (result.strength === 'developing') newWeakConcepts = [questionBank.correct_answer];
    const milestones = ['First Recall'];
    const { error: insertError } = await supabase.from('user_recall_stats').insert({
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
      topic_xp: { [question.topic]: result.xp },
      topic_streak: { [question.topic]: 1 },
      last_topic_date: { [question.topic]: today },
      milestones: milestones,
      best_streak: 1,
      best_mastery: result.strength === 'excellent' ? 85 : (result.strength === 'strong' ? 70 : 50)
    });
    if (insertError) throw new Error(`Failed to insert stats: ${insertError.message}`);
  }

  try {
    await supabase.from('recall_xp_log').insert({ user_id: userId, amount: result.xp, reason: result.strength, session_id: session_id, question_id: question_id });
  } catch (e) {}

  const relatedConcepts = [
    questionBank.correct_answer,
    ...(questionBank.alternate_answers?.map(a => a.term) || [])
  ];

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

async function handleCompleteSession(userId, params) {
  const { session_id } = params;
  const { data: session, error: sessionError } = await supabase.from('recall_sessions').select('user_answers, topic').eq('session_id', session_id).eq('user_id', userId).single();
  if (sessionError) throw new Error(`Session not found: ${sessionError.message}`);
  const totalXpEarned = session?.user_answers?.reduce((sum, a) => sum + (a.xp_earned || 0), 0) || 0;
  const { error: updateError } = await supabase.from('recall_sessions').update({ is_active: false, completed_at: new Date().toISOString() }).eq('session_id', session_id).eq('user_id', userId);
  if (updateError) throw new Error(`Failed to complete session: ${updateError.message}`);
  
  const today = new Date().toISOString().split('T')[0];
  const topicKey = session.topic || 'all';
  const { data: stats } = await supabase
    .from('user_recall_stats')
    .select('topic_completion')
    .eq('user_id', userId)
    .maybeSingle();
  const topicCompletion = stats?.topic_completion || {};
  topicCompletion[topicKey] = today;
  await supabase
    .from('user_recall_stats')
    .update({ topic_completion: topicCompletion })
    .eq('user_id', userId);
  
  const { data: stats2, error: statsError } = await supabase.from('user_recall_stats').select('total_sessions, current_streak').eq('user_id', userId).single();
  if (statsError && statsError.code !== 'PGRST116') throw new Error(`Stats fetch error: ${statsError.message}`);
  if (stats2) {
    const { error: incError } = await supabase.from('user_recall_stats').update({ total_sessions: (stats2.total_sessions || 0) + 1 }).eq('user_id', userId);
    if (incError) throw new Error(`Failed to increment sessions: ${incError.message}`);
  }
  return { success: true, xp_earned_total: totalXpEarned, streak_updated: stats2?.current_streak || 0 };
}

async function handleGetStats(userId, params) {
  const { level } = params;
  const { data: stats, error: statsError } = await supabase.from('user_recall_stats').select('*').eq('user_id', userId).maybeSingle();
  if (statsError) throw new Error(`Stats fetch error: ${statsError.message}`);
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
      selected_level: null,
      milestones: [],
      best_streak: 0,
      best_mastery: 0,
      total_questions: 0
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
    selected_level: stats.selected_level || null,
    milestones: stats.milestones || [],
    best_streak: stats.best_streak || 0,
    best_mastery: stats.best_mastery || 0,
    total_questions: stats.total_questions || 0
  };
}

async function handleGetAchievements(userId) {
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

async function handleGetDashboard(userId) {
  const { data: stats, error } = await supabase
    .from('user_recall_stats')
    .select('total_xp, recall_level, current_streak, best_streak, best_mastery, total_questions, milestones, daily_activity, selected_level')
    .eq('user_id', userId)
    .single();
  if (error || !stats) {
    return { level: 1, xp: 0, xpToNext: 100, progressPercent: 0, streak: 0, bestStreak: 0, bestMastery: 0, totalQuestions: 0, milestones: [], dailyChallenge: { completed: 0, target: 10, progressPercent: 0 }, gardenStage: 'seedling', subjectIllustration: 'fa-flask', quote: 'Welcome! Start your first recall session.', brainEnergy: 100 };
  }
  const today = new Date().toISOString().split('T')[0];
  const dailyQuestions = (stats.daily_activity || {})[today] || 0;
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
  return {
    level: stats.recall_level || 1,
    xp: stats.total_xp || 0,
    xpToNext: 100 - (stats.total_xp % 100),
    progressPercent,
    streak: stats.current_streak || 0,
    bestStreak: stats.best_streak || 0,
    bestMastery: stats.best_mastery || 0,
    totalQuestions: stats.total_questions || 0,
    milestones: stats.milestones || [],
    dailyChallenge: { completed: dailyQuestions, target: 10, progressPercent: (dailyQuestions / 10) * 100 },
    gardenStage,
    subjectIllustration: subjectIllustration[stats.selected_level] || 'fa-flask',
    quote: randomQuote,
    brainEnergy: 100
  };
}

function getTopicIcon(topic) {
  const lower = topic.toLowerCase();
  if (lower.includes('genetics') || lower.includes('dna')) return 'fa-dna';
  if (lower.includes('cell')) return 'fa-microscope';
  if (lower.includes('physiology') || lower.includes('nervous') || lower.includes('brain')) return 'fa-brain';
  if (lower.includes('microbiology')) return 'fa-bacteria';
  if (lower.includes('pharmacology') || lower.includes('antibiotics') || lower.includes('drug')) return 'fa-capsules';
  if (lower.includes('biochemistry') || lower.includes('enzyme')) return 'fa-flask';
  if (lower.includes('respiration')) return 'fa-lungs';
  if (lower.includes('photosynthesis')) return 'fa-leaf';
  if (lower.includes('membrane')) return 'fa-shield';
  if (lower.includes('pharmacokinetics')) return 'fa-chart-line';
  return 'fa-book';
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
  return uniqueTopics.map(t => ({ name: t, icon: getTopicIcon(t) }));
}

async function checkFirstVisit(userId, level, topic) {
  let query = supabase
    .from('recall_sessions')
    .select('id')
    .eq('user_id', userId)
    .eq('level', level);
  if (topic) query = query.eq('topic', topic);
  else query = query.is('topic', null);
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
        try { params = JSON.parse(body); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
        break;
      case 'complete':
        if (method !== 'POST') return res.status(405).json({ error: 'Method not allowed. Use POST for complete.' });
        handler = handleCompleteSession;
        let body2 = '';
        await new Promise((resolve) => { req.on('data', chunk => body2 += chunk); req.on('end', resolve); });
        try { params = JSON.parse(body2); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
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
          try { bodyParams = JSON.parse(body); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
          const { level } = bodyParams;
          if (!level) return res.status(400).json({ error: 'Level required' });
          const { data: existing } = await supabase
            .from('user_recall_stats')
            .select('selected_level')
            .eq('user_id', user.user_id)
            .maybeSingle();
          const isAdmin = await isSuperAdmin(user.user_id);
          if (existing?.selected_level && !isAdmin) return res.status(400).json({ error: 'Level already set and cannot be changed' });
          await supabase.from('user_recall_stats').upsert({ user_id: user.user_id, selected_level: level }, { onConflict: 'user_id' });
          return res.status(200).json({ data: { success: true } });
        }
      case 'achievements':
        handler = handleGetAchievements;
        break;
      case 'dashboard':
        handler = handleGetDashboard;
        break;
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
      try { params = JSON.parse(body); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
    } else if (method === 'POST' && (pathname === '/api/recall/complete' || pathname === '/complete')) {
      handler = handleCompleteSession;
      let body = '';
      await new Promise((resolve) => { req.on('data', chunk => body += chunk); req.on('end', resolve); });
      try { params = JSON.parse(body); } catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
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
