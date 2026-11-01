// Forward each Watchfloor Detection Finding once. Seen uids live in the workflow's static data for 6 hours
// (n8n persists static data for active, production executions).
const state = $getWorkflowStaticData('global');
state.seen = state.seen || {};
const now = Date.now();
for (const [uid, t] of Object.entries(state.seen)) {
  if (now - t > 6 * 3600 * 1000) delete state.seen[uid];
}
const out = [];
for (const item of $input.all()) {
  const f = item.json;
  if (!f || !f.uid || f.class_uid !== 2004) continue;
  if (f.product === 'soar-bot') continue; // 02's own incidents come back through the hub: never loop them
  if (state.seen[f.uid]) continue;
  state.seen[f.uid] = now;
  out.push({ json: f });
}
return out;
