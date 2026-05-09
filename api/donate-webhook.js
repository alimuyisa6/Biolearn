process.noDeprecation = true;
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

var IPN_SECRET = '/WgeK+CVDcH5L+x+NDf5aZKBgfezSnz5'; // Generate in Dashboard → Payment Settings → IPN

function sortObject(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  return Object.keys(obj).sort().reduce(function(result, key) {
    result[key] = sortObject(obj[key]);
    return result;
  }, {});
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  try {
    var body = req.body;
    var receivedSig = req.headers['x-nowpayments-sig'];

    // Verify HMAC signature
    var sorted = sortObject(body);
    var hmac = crypto.createHmac('sha512', IPN_SECRET);
    hmac.update(JSON.stringify(sorted));
    var computedSig = hmac.digest('hex');

    if (receivedSig && computedSig !== receivedSig) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    if (body.payment_status === 'finished' || body.payment_status === 'confirmed') {
      var supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

      // Store donation
      await supabase.from('resource_submissions').insert({
        title: 'Crypto: ' + (body.pay_amount || '') + ' ' + (body.pay_currency || '').toUpperCase(),
        description: 'Invoice: ' + body.invoice_id,
        author: body.purchaser_name || 'Crypto Supporter',
        level: 'Donation',
        category: 'Crypto',
        tag: 'crypto-donation',
        status: 'approved'
      });

      // Update donor wall
      var { data: donorRow } = await supabase.from('site_sections').select('data').eq('section', 'donors').single();
      var donors = (donorRow && donorRow.data && donorRow.data.donors) ? donorRow.data.donors : [];
      donors.unshift({
        name: body.purchaser_name || 'Crypto Supporter',
        amount: (body.pay_amount || '') + ' ' + (body.pay_currency || '').toUpperCase(),
        date: new Date().toISOString().split('T')[0]
      });
      if (donors.length > 20) donors = donors.slice(0, 20);
      await supabase.from('site_sections').upsert({ section: 'donors', data: { donors: donors } });
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
