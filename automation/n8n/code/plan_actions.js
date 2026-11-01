// Decide what follows a decision: an approved containment starts evidence collection in 09 (signed request),
// and every decision is posted to the team channel if NOTIFY_WEBHOOK_URL is set.
const crypto = require('crypto');
const ev = $input.first().json.event || {};
const inc = ev.incident || {};
const who = inc.decided_by || 'someone';
const what = `${inc.id} (${inc.title || 'untitled'})`;
const TEXT = {
  'incident.approved': `${who} approved isolating ${inc.host} for ${what}. Collecting evidence now.`,
  'incident.rejected': `${who} rejected isolation for ${what}. No action taken.`,
  'incident.remediated': `${inc.host} is isolated for ${what}.`,
  'incident.failed': `Isolation of ${inc.host} FAILED for ${what}. Check 02's audit trail.`,
  'incident.expired': `Nobody decided on ${what} in time. The approval expired; escalate.`,
};
const out = {
  event: ev.event,
  incident_id: inc.id,
  host: inc.host,
  text: TEXT[ev.event] || `${ev.event} for ${what}`,
  notify: Boolean($env.NOTIFY_WEBHOOK_URL),
  collect: false,
};
const secret = $env.EVIDENCE_SHARED_SECRET || '';
if (ev.event === 'incident.approved' && inc.host && inc.id && secret.length >= 32) {
  const request = {
    incident_id: inc.id,
    host: inc.host,
    requested_by: 'n8n:watchfloor-decision',
    reason: `Containment approved in 02: ${inc.title || ''}`.slice(0, 500),
  };
  if (inc.detected_at) request.around_ms = Math.round(Number(inc.detected_at) * 1000);
  if (inc.decided_by) request.decided_by = String(inc.decided_by).slice(0, 100);
  const body = JSON.stringify(request);
  const ts = String(Math.floor(Date.now() / 1000));
  Object.assign(out, {
    collect: true,
    collect_body: body,
    collect_ts: ts,
    collect_sig: 'sha256=' + crypto.createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex'),
  });
}
return [{ json: out }];
