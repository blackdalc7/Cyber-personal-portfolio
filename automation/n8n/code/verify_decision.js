// Verify 02's signed decision webhook before anything acts on it: secret, fresh timestamp, HMAC over the raw
// body, and no replays (signatures are remembered for 10 minutes). The webhook node keeps the raw body.
const crypto = require('crypto');
const secret = $env.DECISION_WEBHOOK_SECRET || '';
const item = $input.first();
const headers = item.json.headers || {};
// Only the exact bytes 02 signed can be verified: re-serialising the parsed body changes them (Python writes 1.0,
// JavaScript writes 1), so without the webhook's rawBody option every request is refused.
const raw = item.binary && item.binary.data
  ? (await this.helpers.getBinaryDataBuffer(0, 'data')).toString('utf8')
  : null;
const ts = String(headers['x-soar-timestamp'] || '');
const sig = String(headers['x-soar-signature'] || '');
const state = $getWorkflowStaticData('global');
state.sigs = state.sigs || {};
const now = Date.now() / 1000;
for (const [s, t] of Object.entries(state.sigs)) {
  if (now - t > 600) delete state.sigs[s];
}

let valid = false;
let reason = '';
if (secret.length < 32) reason = 'DECISION_WEBHOOK_SECRET is not set';
else if (raw === null) reason = 'raw body missing (enable rawBody on the webhook node)';
else if (!/^\d+$/.test(ts) || Math.abs(now - Number(ts)) > 300) reason = 'stale or missing timestamp';
else if (!sig.startsWith('sha256=')) reason = 'missing signature';
else if (state.sigs[sig]) reason = 'replayed request';
else {
  const expected = crypto.createHmac('sha256', secret).update(`${ts}.${raw}`).digest('hex');
  const given = Buffer.from(sig.slice(7), 'utf8');
  const want = Buffer.from(expected, 'utf8');
  valid = given.length === want.length && crypto.timingSafeEqual(given, want);
  if (!valid) reason = 'bad signature';
}
let event = null;
if (valid) {
  try {
    event = JSON.parse(raw);
    state.sigs[sig] = now;
  } catch (e) {
    valid = false;
    reason = 'body is not JSON';
  }
}
return [{ json: { valid, reason, event } }];
