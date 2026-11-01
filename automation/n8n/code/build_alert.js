// Turn a finding into 02's generic alert, add host context from the hub, and sign it exactly as 02 expects:
// X-SOAR-Signature = "sha256=" + HMAC-SHA256(secret, "<timestamp>." + body). Needs NODE_FUNCTION_ALLOW_BUILTIN=crypto.
const crypto = require('crypto');
const SEVERITY = { 0: 'low', 1: 'low', 2: 'low', 3: 'medium', 4: 'high', 5: 'critical', 6: 'critical' };
const hub = $env.WF_HUB_URL;
const token = $env.WF_HUB_TOKEN || '';
const secret = $env.SOAR_WEBHOOK_SECRET || '';
if (secret.length < 32) throw new Error('SOAR_WEBHOOK_SECRET is not set (>= 32 chars, same as 02 WEBHOOK_SHARED_SECRET)');

const out = [];
for (const item of $input.all()) {
  const f = item.json;
  const techniques = Array.isArray(f.techniques) ? f.techniques : [];
  let context = '';
  if (f.hostname) {
    try {
      const related = await this.helpers.httpRequest({
        method: 'GET',
        url: `${hub}/api/findings`,
        qs: { hostname: f.hostname, since: Number(f.time) - 3600 * 1000, limit: 50 },
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        json: true,
      });
      const seen = [...new Set(related.flatMap((r) => r.techniques || []))].sort();
      context = `\n\nHost context (last hour): ${related.length} findings on ${f.hostname}` +
        (seen.length ? `, techniques ${seen.join(', ')}` : '') + '.';
    } catch (e) {
      context = '\n\nHost context unavailable (hub did not answer).';
    }
  }
  const alert = {
    id: `wf-${f.uid}`,
    title: String(f.finding_title || 'Watchfloor finding').slice(0, 200),
    severity: SEVERITY[f.severity_id] || 'medium',
    source: `watchfloor:${f.product || 'unknown'}`,
    timestamp: Number(f.time) / 1000,
    description: `${f.message || f.finding_title || ''}\nTechniques: ${techniques.join(', ') || 'none'}\n` +
      `Watchfloor finding: ${f.uid}${context}`,
  };
  if (f.hostname) alert.host = f.hostname;
  if (f.src_ip) alert.source_ip = f.src_ip;
  const body = JSON.stringify(alert);
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = 'sha256=' + crypto.createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
  out.push({ json: { uid: f.uid, body, ts, sig } });
}
return out;
