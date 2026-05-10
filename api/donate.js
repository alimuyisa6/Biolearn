 process.noDeprecation = true;
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

var KEY = 'TNS7XTK-KRCM4ZD-N52126H-MHCGXAP';
var IPN_SECRET = '/WgeK+CVDcH5L+x+NDf5aZKBgfezSnz5';

function sortObj(o) { if (o === null || typeof o !== 'object') return o; return Object.keys(o).sort().reduce(function(r,k){ r[k] = sortObj(o[k]); return r; }, {}); }

export default async function handler(req, res) {
  var action = req.query.action;

  // ── GET /api/donate?action=currencies ──
  if (req.method === 'GET' && action === 'currencies') {
    try {
      var r = await fetch('https://api.nowpayments.io/v1/currencies?fixed_rate=true', { headers: { 'x-api-key': KEY } });
      if (!r.ok) return res.status(502).json({ error: 'Currencies unavailable' });
      var d = await r.json();
      return res.status(200).json({ currencies: d.currencies || [] });
    } catch (e) { return res.status(500).json({ error: e.message }); }
  }

  // ── GET /api/donate?action=status&id=xxx ──
  if (req.method === 'GET' && action === 'status') {
    var id = req.query.id;
    if (!id) return res.status(400).json({ error: 'Missing id' });
    try {
      var sr = await fetch('https://api.nowpayments.io/v1/invoice/' + id, { headers: { 'x-api-key': KEY } });
      if (!sr.ok) return res.status(502).json({ error: 'Status check failed', status: 'unknown' });
      var sd = await sr.json();
      return res.status(200).json({ status: sd.invoice_status });
    } catch (e) { return res.status(500).json({ error: e.message }); }
  }

  // ── POST /api/donate?action=create ──
  if (req.method === 'POST' && action === 'create') {
    try {
      var { amount, pay_currency } = req.body;
      if (!amount || isNaN(amount) || amount <= 0) return res.status(400).json({ error: 'Valid amount required.' });
      if (!pay_currency) return res.status(400).json({ error: 'Select a coin.' });
      var ir = await fetch('https://api.nowpayments.io/v1/invoice', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
        body: JSON.stringify({ price_amount: Number(amount), price_currency: 'usd', pay_currency: pay_currency, order_id: 'BL-' + Date.now(), order_description: 'BioLearn Donation', ipn_callback_url: 'https://' + req.headers.host + '/api/donate?action=webhook' })
      });
      if (!ir.ok) { var e = await ir.json().catch(function(){return{};}); return res.status(ir.status).json({ error: e.message || 'Failed' }); }
      var inv = await ir.json();
      return res.status(200).json({ invoice_id: inv.invoice_id, pay_address: inv.pay_address, pay_amount: inv.pay_amount, pay_currency: inv.pay_currency });
    } catch (e) { return res.status(500).json({ error: e.message }); }
  }

  // ── POST /api/donate?action=webhook ──
  if (req.method === 'POST' && action === 'webhook') {
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

  return res.status(400).json({ error: 'Unknown action. Use ?action=currencies | status | create | webhook' });
}
