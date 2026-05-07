export default async function handler(req, res) {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!key) {
    return res.status(200).json({ error: 'Key missing' });
  }

  const parts = key.split('.');
  if (parts.length !== 3) {
    return res.status(200).json({ error: 'Invalid JWT format' });
  }

  try {
    // Decode the payload part of the JWT (base64url)
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64').toString('utf8')
    );
    return res.status(200).json({
      role: payload.role,
      exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'none'
    });
  } catch (e) {
    return res.status(200).json({ error: 'Decode failed', raw: parts[1] });
  }
}
