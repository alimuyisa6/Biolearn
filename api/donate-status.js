process.noDeprecation = true;

var NOWPAYMENTS_API_KEY = '56GM15R-BTDMSTD-HR9BSKN-MD4MF';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();
  var id = req.query.id;
  if (!id) return res.status(400).json({ error: 'Missing id' });

  try {
    var r = await fetch('https://api.nowpayments.io/v1/invoice/' + id, {
      headers: { 'x-api-key': NOWPAYMENTS_API_KEY }
    });
    if (!r.ok) return res.status(502).json({ error: 'NowPayments error' });
    var d = await r.json();
    return res.status(200).json({ status: d.invoice_status });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
