 const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action, category, id } = req.body;
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  let userId = null;
  if (token) {
    try {
      const { data: { user } } = await supabase.auth.getUser(token);
      if (user) userId = user.id;
    } catch(e) {}
  }

  try {
    if (action === 'get_quizzes') {
      let query = supabase.from('quizzes').select('*').eq('is_active', true);
      if (category && category !== 'all') {
        query = query.eq('category', category);
      }
      const { data, error } = await query.order('id');
      if (error) throw error;
      return res.status(200).json({ success: true, data });
    }
    
    if (action === 'get_quiz') {
      const { data, error } = await supabase
        .from('quizzes')
        .select('*')
        .eq('id', id)
        .single();
      if (error) throw error;
      return res.status(200).json({ success: true, data });
    }
    
    if (action === 'complete_quiz') {
      if (!userId) return res.status(401).json({ error: 'Login required' });
      
      const { quiz_id, score, total, percentage, passed, answers, time_taken } = req.body;
      
      const { data: existing } = await supabase
        .from('user_quiz_activity')
        .select('id')
        .eq('user_id', userId)
        .eq('quiz_id', quiz_id)
        .maybeSingle();
      
      if (existing) {
        await supabase
          .from('user_quiz_activity')
          .update({ score, total_possible: total, percentage, passed, answers, time_taken, completed_at: new Date() })
          .eq('id', existing.id);
      } else {
        await supabase
          .from('user_quiz_activity')
          .insert({ user_id: userId, quiz_id, score, total_possible: total, percentage, passed, answers, time_taken, completed_at: new Date() });
      }
      
      return res.status(200).json({ success: true, passed, percentage });
    }
    
    if (action === 'get_user_progress') {
      if (!userId) return res.status(401).json({ error: 'Login required' });
      
      const { data, error } = await supabase
        .from('user_quiz_activity')
        .select('*, quizzes(id, title, category, total_points)')
        .eq('user_id', userId)
        .order('completed_at', { ascending: false });
      if (error) throw error;
      
      return res.status(200).json({ success: true, data });
    }
    
    if (action === 'add_reaction') {
      if (!userId) return res.status(401).json({ error: 'Login required' });
      
      const { quiz_id, reaction_type } = req.body;
      
      await supabase
        .from('user_quiz_activity')
        .update({ reaction: reaction_type })
        .eq('user_id', userId)
        .eq('quiz_id', quiz_id);
      
      return res.status(200).json({ success: true });
    }
    
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (error) {
    console.error('Error:', error.message);
    return res.status(500).json({ error: error.message });
  }
};
