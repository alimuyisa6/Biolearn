 process.noDeprecation = true;
import { createClient } from '@supabase/supabase-js';

// Rate limiter: 60 requests per IP per minute
var rateMap = new Map();
function rateLimit(req, res, max) {
  max = max || 60;
  var ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  var now = Date.now();
  var entry = rateMap.get(ip) || { count: 0, reset: now + 60000 };
  if (now > entry.reset) { entry = { count: 0, reset: now + 60000 }; }
  entry.count++;
  rateMap.set(ip, entry);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));
  if (entry.count > max) { res.status(429).json({ error: 'Too many requests. Slow down.' }); return false; }
  return true;
}

// Allowed origins
var ALLOWED_ORIGIN = process.env.VERCEL_URL ? 'https://' + process.env.VERCEL_URL : '*';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  if (!rateLimit(req, res, 120)) return; // 120 req/min for data endpoints

  var supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  var action = req.query.action;

  // site-sections
  if (action === 'site-sections') {
    var { data, error } = await supabase.from('site_sections').select('section, data');
    if (error) return res.status(500).json({ error: 'Database error' });
    return res.status(200).json(data);
  }

  // resources
  if (action === 'resources') {
    var { level, category, tag } = req.query;
    var query = supabase.from('biology_notes').select('*').limit(1000);
    if (level && /^[A-Za-z0-9\-\s]+$/.test(level)) query = query.eq('level', level);
    if (category && /^[A-Za-z0-9\-\s&]+$/.test(category)) query = query.eq('category', category);
    if (tag && /^[A-Za-z0-9\-\s,]+$/.test(tag)) query = query.eq('tag', tag);
    var { data, error } = await query;
    if (error) return res.status(500).json({ error: 'Database error' });
    return res.status(200).json(data);
  }

  // filter-options
  if (action === 'filter-options') {
    var [{ data: levels }, { data: categories }] = await Promise.all([
      supabase.from('biology_notes').select('level', { distinct: true }),
      supabase.from('biology_notes').select('category', { distinct: true })
    ]);
    return res.status(200).json({
      levels: (levels || []).map(function(r) { return r.level; }).filter(Boolean),
      categories: (categories || []).map(function(r) { return r.category; }).filter(Boolean)
    });
  }

  // note
  if (action === 'note') {
    var id = req.query.id;
    if (!id || !/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid note id' });
    var { data, error } = await supabase.from('biology_notes').select('*').eq('id', id).single();
    if (error) return res.status(404).json({ error: 'Note not found' });
    return res.status(200).json(data);
  }

  return res.status(400).json({ error: 'Unknown action' });
                                            }
