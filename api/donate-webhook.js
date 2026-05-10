  process.noDeprecation = true;
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
var IPN_SECRET = '/WgeK+CVDcH5L+x+NDf5aZKBgfezSnz5';

function sortObj(o) { if (o === null || typeof o !== 'object') return o; return Object.keys(o).sort().reduce(function(r,k){ r[k] = sortObj(o[k]); return r; }, {}); }

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  try {
    var body = req.body, sig = req.headers['x-nowpayments-sig'];
    var sorted = sortObj(body), hmac = crypto.createHmac('sha512', IPN_SECRET); hmac.update(JSON.stringify(sorted));
    if (sig && hmac.digest('hex') !== sig) return res.status(403).json({ error: 'Invalid signature' });
    if (body.payment_status === 'finished' || body.payment_status === 'confirmed') {
      var supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
      await supabase.from('resource_submissions').insert({ title: 'Crypto: ' + (body.pay_amount||'') + ' ' + (body.pay_currency||'').toUpperCase(), description: 'Invoice: ' + body.invoice_id, author: body.purchaser_name||'Crypto Supporter', level: 'Donation', category: 'Crypto', tag: 'crypto-donation', status: 'approved' });
      var { data: dr } = await supabase.from('site_sections').select('data').eq('section', 'donors').single();
      var donors = (dr&&dr.data&&dr.data.donors) ? dr.data.donors : [];
      donors.unshift({ name: body.purchaser_name||'Crypto Supporter', amount: (body.pay_amount||'') + ' ' + (body.pay_currency||'').toUpperCase(), date: new Date().toISOString().split('T')[0] });
      if (donors.length > 20) donors = donors.slice(0,20);
      await supabase.from('site_sections').upsert({ section: 'donors', data: { donors: donors } });
    }
    return res.status(200).json({ success: true });
  } catch (e) { return res.status(500).json({ error: e.message }); }
}
