 const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const ACTION_WHITELIST = new Set([
  'get_quizzes', 'get_quiz', 'complete_quiz',
  'get_user_progress', 'add_reaction', 'get_stats'
]);

const RATE_LIMITS = new Map();
const MAX_REQUESTS = 60;
const WINDOW_MS = 60000;
const BANNED_IPS = new Set();

function rateLimit(ip) {
  if (BANNED_IPS.has(ip)) return false;
  const now = Date.now();
  const record = RATE_LIMITS.get(ip) || { count: 0, reset: now + WINDOW_MS };
  if (now > record.reset) { record.count = 0; record.reset = now + WINDOW_MS; }
  record.count++;
  RATE_LIMITS.set(ip, record);
  if (record.count > MAX_REQUESTS * 2) { BANNED_IPS.add(ip); return false; }
  return record.count <= MAX_REQUESTS;
}

function getUserId(token) {
  if (!token || token.length < 20) return null;
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return payload.sub;
  } catch (e) { return null; }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  if (!rateLimit(ip)) return res.status(429).json({ error: 'Too many requests' });

  try {
    if (req.method === 'GET') return await handleGet(req, res);
    if (req.method === 'POST') return await handlePost(req, res);
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (error) {
    console.error('Quiz API Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

async function handleGet(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const action = url.searchParams.get('action');
  
  if (!action || !ACTION_WHITELIST.has(action)) {
    return res.status(400).json({ error: 'Invalid action' });
  }

  const token = req.headers.authorization?.replace('Bearer ', '');
  const userId = getUserId(token);

  try {
    let result;

    switch (action) {
      case 'get_quizzes': {
        const category = url.searchParams.get('category');
        let query = supabase.from('quizzes').select('*').eq('is_active', true);
        if (category && category !== 'all') {
          query = query.eq('category', category);
        }
        const { data, error } = await query.order('id');
        if (error) throw error;

        if (userId && data.length) {
          const quizIds = data.map(q => q.id);
          const { data: activity } = await supabase
            .from('user_quiz_activity')
            .select('quiz_id, score, percentage, passed, completed_at')
            .in('quiz_id', quizIds)
            .eq('user_id', userId);
          
          const activityMap = new Map();
          if (activity) activity.forEach(a => activityMap.set(a.quiz_id, a));
          
          result = data.map(quiz => ({
            ...quiz,
            user_progress: activityMap.get(quiz.id) || null
          }));
        } else {
          result = data;
        }
        break;
      }

      case 'get_quiz': {
        const quizId = parseInt(url.searchParams.get('id'));
        if (!quizId) return res.status(400).json({ error: 'Quiz ID required' });
        
        const { data, error } = await supabase
          .from('quizzes')
          .select('*')
          .eq('id', quizId)
          .single();
        if (error) throw error;
        
        result = data;
        break;
      }

      case 'get_user_progress': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        
        const { data, error } = await supabase
          .from('user_quiz_activity')
          .select('*, quizzes(id, title, category, total_points)')
          .eq('user_id', userId)
          .order('completed_at', { ascending: false });
        if (error) throw error;
        
        result = data;
        break;
      }

      case 'get_stats': {
        const quizId = parseInt(url.searchParams.get('quiz_id'));
        if (!quizId) return res.status(400).json({ error: 'Quiz ID required' });
        
        const { data: activity } = await supabase
          .from('user_quiz_activity')
          .select('percentage')
          .eq('quiz_id', quizId);
        
        const totalAttempts = activity?.length || 0;
        const avgScore = totalAttempts > 0 
          ? Math.round(activity.reduce((sum, a) => sum + (a.percentage || 0), 0) / totalAttempts) 
          : 0;
        
        result = { totalAttempts, avgScore };
        break;
      }

      default:
        result = null;
    }
    
    return res.status(200).json({ data: result });
  } catch (error) {
    console.error('GET Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

async function handlePost(req, res) {
  const { action } = req.body;
  const token = req.headers.authorization?.replace('Bearer ', '');
  const userId = getUserId(token);
  
  if (!action || !ACTION_WHITELIST.has(action)) {
    return res.status(400).json({ error: 'Invalid action' });
  }

  try {
    let result;

    switch (action) {
      case 'complete_quiz': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        
        const { quiz_id, score, total, percentage, passed, answers, time_taken } = req.body;
        
        const { data: existing } = await supabase
          .from('user_quiz_activity')
          .select('id')
          .eq('user_id', userId)
          .eq('quiz_id', quiz_id)
          .maybeSingle();
        
        if (existing) {
          const { error } = await supabase
            .from('user_quiz_activity')
            .update({
              score, total_possible: total, percentage, passed,
              answers, time_taken, completed_at: new Date()
            })
            .eq('id', existing.id);
          if (error) throw error;
        } else {
          const { error } = await supabase
            .from('user_quiz_activity')
            .insert({
              user_id: userId, quiz_id, score, total_possible: total,
              percentage, passed, answers, time_taken, completed_at: new Date()
            });
          if (error) throw error;
        }
        
        try {
          await supabase.rpc('update_quiz_stats', { quiz_id_input: quiz_id });
        } catch(e) {}
        
        result = { success: true, passed, percentage };
        break;
      }

      case 'add_reaction': {
        if (!userId) return res.status(401).json({ error: 'Authentication required' });
        
        const { quiz_id, reaction_type } = req.body;
        
        const { error } = await supabase
          .from('user_quiz_activity')
          .update({ reaction: reaction_type })
          .eq('user_id', userId)
          .eq('quiz_id', quiz_id);
        
        if (error && error.code !== 'PGRST116') throw error;
        
        result = { success: true };
        break;
      }

      default:
        throw new Error('Unknown action');
    }

    return res.status(200).json({ data: result });
  } catch (error) {
    console.error('POST Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
