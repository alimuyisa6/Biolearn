process.noDeprecation = true;

// ── Your secret API key goes here ONLY ──
var NOWPAYMENTS_API_KEY = '56GM15R-BTDMSTD-HR9BSKN-MD4MF';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  try {
    var { amount, pay_currency } = req.body;
    if (!amount || !pay_currency) return res.status(400).json({ error: 'Missing amount or currency' });

    // Create invoice via NowPayments
    var invRes = await fetch('https://api.nowpayments.io/v1/invoice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': NOWPAYMENTS_API_KEY },
      body: JSON.stringify({
        price_amount: amount,
        price_currency: 'usd',
        pay_currency: pay_currency,
        order_id: 'BL-' + Date.now(),
        order_description: 'BioLearn Donation',
        ipn_callback_url: 'https://' + req.headers.host + '/api/donate-webhook'
      })
    });

    if (!invRes.ok) {
      var err = await invRes.json().catch(function() { return {}; });
      return res.status(invRes.status).json({ error: err.message || 'Invoice creation failed' });
    }

    var invoice = await invRes.json();
    return res.status(200).json({
      invoice_id: invoice.invoice_id,
      pay_address: invoice.pay_address,
      pay_amount: invoice.pay_amount,
      pay_currency: invoice.pay_currency,
      price_amount: invoice.price_amount,
      invoice_url: invoice.invoice_url
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
