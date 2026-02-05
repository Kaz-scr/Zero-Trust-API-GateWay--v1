const API_BASE = '/api/dashboard';

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const parts = [];
  if (h > 0) parts.push(h + 'h');
  if (m > 0) parts.push(m + 'm');
  parts.push(s + 's');
  return parts.join(' ');
}

async function fetchStats() {
  const res = await fetch(API_BASE + '/stats');
  if (!res.ok) throw new Error('Stats fetch failed');
  return res.json();
}

async function fetchAudit() {
  const res = await fetch(API_BASE + '/audit?limit=50');
  if (!res.ok) throw new Error('Audit fetch failed');
  return res.json();
}

async function fetchPolicies() {
  const res = await fetch(API_BASE + '/policies');
  if (!res.ok) throw new Error('Policies fetch failed');
  return res.json();
}

function renderStats(data) {
  document.getElementById('allow-count').textContent = data.allow;
  document.getElementById('deny-count').textContent = data.deny;
  document.getElementById('uptime').textContent = formatUptime(data.uptime_seconds);
}

function renderAudit(data) {
  const tbody = document.getElementById('audit-body');
  if (!data.entries || data.entries.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">No entries yet</td></tr>';
    return;
  }
  tbody.innerHTML = data.entries.map(e => `
    <tr>
      <td>${escapeHtml(e.timestamp)}</td>
      <td>${escapeHtml(e.method)}</td>
      <td>${escapeHtml(e.path)}</td>
      <td class="decision-${e.decision.toLowerCase()}">${escapeHtml(e.decision)}</td>
      <td>${escapeHtml(e.reason)}</td>
    </tr>
  `).join('');
}

function renderPolicies(data) {
  const tbody = document.getElementById('policies-body');
  if (!data.policies || data.policies.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty">No policies loaded</td></tr>';
    return;
  }
  tbody.innerHTML = data.policies.map(p => `
    <tr>
      <td>${escapeHtml(p.method)}</td>
      <td>${escapeHtml(p.path)}</td>
      <td>${escapeHtml((p.roles || []).join(', '))}</td>
    </tr>
  `).join('');
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

async function refresh() {
  try {
    const [stats, audit, policies] = await Promise.all([
      fetchStats(),
      fetchAudit(),
      fetchPolicies()
    ]);
    renderStats(stats);
    renderAudit(audit);
    renderPolicies(policies);
  } catch (err) {
    console.error('Dashboard refresh failed:', err);
  }
}

refresh();
setInterval(refresh, 3000);
