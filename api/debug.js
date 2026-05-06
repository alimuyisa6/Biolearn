export default async function handler(req, res) {
  res.status(200).json({
    supabaseUrl: process.env.SUPABASE_URL || 'MISSING',
    keyExists: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
    keyLength: (process.env.SUPABASE_SERVICE_ROLE_KEY || '').length,
    keyFirst10: (process.env.SUPABASE_SERVICE_ROLE_KEY || '').slice(0, 10)
  });
}
