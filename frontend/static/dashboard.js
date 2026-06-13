/* ═══════════════════════════════════════════════════════
   dashboard.js — Main Dashboard Controller
   Socket.IO, Detector forms, Alert feed, Gauge animation
   ═══════════════════════════════════════════════════════ */

'use strict';

// ── State ──────────────────────────────────────────────
let alertCount = 0;
let recentDetections = [];
const MAX_PACKETS = 80;
const MAX_LOGS    = 50;
let packetRows = 0;
let logRows    = 0;

// ── Socket.IO ──────────────────────────────────────────
const SOCK_OPTS = { transports: ['websocket', 'polling'] };
const sockMetrics = io('/metrics', SOCK_OPTS);
const sockPackets = io('/packets', SOCK_OPTS);
const sockLogs    = io('/logs', SOCK_OPTS);
const sockAlerts  = io('/alerts', SOCK_OPTS);

// ── Connection status ──────────────────────────────────
let connectedCount = 0;
function onConnected() {
  connectedCount++;
  if (connectedCount >= 4) setStatus('online', 'System Online');
}
function onDisconnected() {
  connectedCount = Math.max(0, connectedCount - 1);
  if (connectedCount < 4) setStatus('offline', 'Reconnecting...');
}

sockMetrics.on('connect', onConnected);
sockPackets.on('connect', onConnected);
sockLogs.on('connect', onConnected);
sockAlerts.on('connect', onConnected);
sockMetrics.on('disconnect', onDisconnected);
sockPackets.on('disconnect', onDisconnected);
sockLogs.on('disconnect', onDisconnected);
sockAlerts.on('disconnect', onDisconnected);

// ── Metrics ────────────────────────────────────────────
sockMetrics.on('metrics_update', data => {
  updateCharts(data);
  updateOverviewMetrics(data);
});

function updateOverviewMetrics(d) {
  setEl('cpuVal',  d.cpu + '%');
  setEl('ramVal',  d.ram + '%');
  setEl('diskRVal', d.disk_read_kbps  + ' KB/s');
  setEl('diskWVal', d.disk_write_kbps + ' KB/s');
  setEl('procVal', d.processes);

  setBarWidth('cpuBarFill',  d.cpu);
  setBarWidth('ramBarFill',  d.ram);
  setBarWidth('diskRBarFill', Math.min((d.disk_read_kbps  / 500) * 100, 100));
  setBarWidth('diskWBarFill', Math.min((d.disk_write_kbps / 500) * 100, 100));

  // Color CPU bar
  const cpuFill = document.getElementById('cpuBarFill');
  if (cpuFill) cpuFill.style.background = d.cpu > 90 ? '#ff4444' : d.cpu > 70 ? '#ffaa00' : '#00ff88';
}

// ── Packets ────────────────────────────────────────────
sockPackets.on('packet_update', pkt => {
  const feed = document.getElementById('packetFeed');
  if (!feed) return;

  if (packetRows === 0) feed.innerHTML = '';

  const row = document.createElement('div');
  row.className = 'packet-row' + (pkt.is_threat ? ' threat' : '');

  const ts = new Date(pkt.timestamp).toLocaleTimeString();
  const flags = pkt.threat_flags.join(', ');

  row.innerHTML = `
    <span class="packet-ip">${pkt.src_ip}</span>
    <span class="packet-ip">${pkt.dst_ip}</span>
    <span class="packet-proto">${pkt.protocol}</span>
    <span class="packet-size">${pkt.size}B</span>
    <span class="packet-flag">${flags || pkt.service}</span>
  `;

  feed.prepend(row);
  packetRows++;
  if (packetRows > MAX_PACKETS) {
    feed.lastChild && feed.removeChild(feed.lastChild);
    packetRows = MAX_PACKETS;
  }
});

// ── Logs ───────────────────────────────────────────────
sockLogs.on('log_update', ev => {
  const feed = document.getElementById('logFeed');
  if (!feed) return;

  if (logRows === 0) feed.innerHTML = '';

  const row = document.createElement('div');
  const lcls = `log-level-${ev.level}`;
  row.className = `log-row ${lcls}`;

  const ts = new Date(ev.timestamp).toLocaleTimeString();
  row.innerHTML = `
    <span class="log-ts">${ts}</span>
    <span class="log-badge log-badge-${ev.level}">${ev.level}</span>
    <span class="log-src">[${ev.source}]</span>
    <span class="log-msg">${escHtml(ev.message)}</span>
  `;

  feed.prepend(row);
  logRows++;
  if (logRows > MAX_LOGS) {
    feed.lastChild && feed.removeChild(feed.lastChild);
    logRows = MAX_LOGS;
  }
});

// ── Alerts ─────────────────────────────────────────────
sockAlerts.on('new_alert', alert => {
  addAlertCard(alert);
  alertCount++;
  updateAlertBadge();
  showToast(`🚨 ${alert.severity} — ${alert.engine.replace('_', ' ')}`, 'alert');
});

// ── Tab Switching ──────────────────────────────────────
function switchTab(tab, title) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

  const panel = document.getElementById('panel' + cap(tab));
  const nav = document.getElementById('nav' + cap(tab));
  const pageTitle = document.getElementById('pageTitle');
  
  if (panel) panel.classList.add('active');
  if (nav) nav.classList.add('active');
  if (pageTitle && title) pageTitle.textContent = title;

  if (tab === 'monitor') {
    // Init charts only when the panel is visible (canvases have real dimensions)
    setTimeout(() => initCharts(), 100);
  }
  if (tab === 'alerts') {
    alertCount = 0;
    updateAlertBadge();
  }
}

function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

// ── Stat Updates (formerly Gauges) ─────────────────────
function updateGauge(name, score, label) {
  const val = document.getElementById(`gauge${name}Val`);
  const status = document.getElementById(`gauge${name}Status`);

  let colorClass = 'text-green';
  if (score > 0.65) colorClass = 'text-red';
  else if (score > 0.35) colorClass = 'text-amber';

  if (val) {
    val.textContent = Math.round(score * 100) + '%';
    val.className = `stat-value ${colorClass}`;
  }
  if (status) {
    status.textContent = label;
  }
}

// ── Detector: Network Anomaly ──────────────────────────
async function runNetworkDetect() {
  const payload = {
    src_bytes:       +getVal('net_src_bytes'),
    dst_bytes:       +getVal('net_dst_bytes'),
    duration:        +getVal('net_duration'),
    num_connections: +getVal('net_num_conn'),
    packet_rate:     +getVal('net_pkt_rate'),
    protocol_type:   +getVal('net_proto'),
    flag:            +getVal('net_flag'),
  };
  await runDetector('network', '/api/detect/network', payload, 'Network', (r) => {
    updateGauge('Network', r.score, r.result);
  });
}

function demoNetwork() {
  // Anomalous packet burst scenario
  setVal('net_src_bytes', 48);
  setVal('net_dst_bytes', 9800000);
  setVal('net_duration', 0.1);
  setVal('net_num_conn', 4500);
  setVal('net_pkt_rate', 12000);
  document.getElementById('net_proto').value = 2;  // ICMP
  document.getElementById('net_flag').value  = 3;  // RSTO
  runNetworkDetect();
}

// ── Detector: Malware ──────────────────────────────────
async function runMalwareDetect() {
  const payload = {
    file_size:            +getVal('mal_file_size'),
    num_sections:         +getVal('mal_num_sections'),
    num_imports:          +getVal('mal_num_imports'),
    num_exports:          +getVal('mal_num_exports'),
    has_overlay:          +document.getElementById('mal_has_overlay').value,
    entropy:              +getVal('mal_entropy'),
    virtual_size:         +getVal('mal_virtual_size'),
    suspicious_api_calls: +getVal('mal_suspicious_api'),
    packer_detected:      +document.getElementById('mal_packer').value,
  };
  await runDetector('malware', '/api/detect/malware', payload, 'Malware', (r) => {
    updateGauge('Malware', r.score, r.result);
  });
}

function demoMalware() {
  // Packed malware sample
  setVal('mal_file_size', 65536);
  setVal('mal_num_sections', 14);
  setVal('mal_num_imports', 320);
  setVal('mal_num_exports', 0);
  document.getElementById('mal_has_overlay').value = 1;
  setVal('mal_entropy', 7.8);
  setVal('mal_virtual_size', 4194304);
  setVal('mal_suspicious_api', 38);
  document.getElementById('mal_packer').value = 1;
  runMalwareDetect();
}

// ── Detector: Phishing ─────────────────────────────────
async function runPhishingDetect() {
  const payload = {
    text:          getVal('phish_text'),
    sender_domain: getVal('phish_sender'),
  };
  await runDetector('phishing', '/api/detect/phishing', payload, 'Phishing', (r) => {
    updateGauge('Phishing', r.score, r.result);
  });
}

function demoPhishing() {
  document.getElementById('phish_text').value =
    `URGENT: Account Suspended — Verify Immediately
Dear Customer, your account has been locked due to suspicious activity.
Click HERE to verify: http://192.168.99.254/secure-login
Failure to verify within 24 hours will result in permanent suspension.
Act NOW to avoid losing access! Limited time — claim your FREE security check.`;
  document.getElementById('phish_sender').value = 'noreply@paypa1-secure.net';
  runPhishingDetect();
}

// ── Generic Detector Runner ────────────────────────────
async function runDetector(name, url, payload, gaugeName, onSuccess) {
  const btn = document.getElementById('btn' + cap(name));
  const resultEl = document.getElementById('result' + cap(name));

  btn.disabled = true;
  btn.textContent = '⟳ Analyzing...';
  resultEl.className = 'detector-result';
  resultEl.innerHTML = '<span style="color:var(--text-muted)">Processing...</span>';

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const r = await resp.json();

    if (r.error) throw new Error(r.error);

    // Determine result class
    let cls = 'result-clean';
    if (r.score > 0.65) cls = 'result-danger';
    else if (r.score > 0.35) cls = 'result-warn';

    const scoreColor = r.score > 0.65 ? '#ff4444' : r.score > 0.35 ? '#ffaa00' : '#00ff88';

    const indicatorsHtml = (r.indicators || [])
      .map(i => `<div class="result-indicator">▸ ${escHtml(i)}</div>`)
      .join('');

    resultEl.className = `detector-result ${cls}`;
    resultEl.innerHTML = `
      <div class="result-header">
        <span class="result-label" style="color:${scoreColor}">${escHtml(r.result)}</span>
        <span class="result-confidence" style="color:${scoreColor}">${Math.round(r.score * 100)}%</span>
      </div>
      <div class="result-engine">Engine: ${escHtml(r.engine)} · ${new Date(r.timestamp).toLocaleTimeString()}</div>
      <div class="result-indicators">${indicatorsHtml}</div>
    `;

    onSuccess(r);
    addRecentDetection(r);

    // Trigger alert if high confidence
    if (r.score > 0.7) {
      showToast(`⚠ High threat: ${r.result} (${Math.round(r.score*100)}%)`, 'alert');
    }

  } catch (e) {
    resultEl.className = 'detector-result result-danger';
    resultEl.innerHTML = `<span style="color:var(--red)">Error: ${escHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ Analyze';
  }
}

// ── Recent Detections table ────────────────────────────
function addRecentDetection(r) {
  recentDetections.unshift(r);
  if (recentDetections.length > 10) recentDetections.pop();

  const tbody = document.getElementById('recentDetectionsTbody');
  if (!tbody) return;

  tbody.innerHTML = recentDetections.map(d => {
    const color = d.score > 0.65 ? '#ff4444' : d.score > 0.35 ? '#ffaa00' : '#00ff88';
    const ts = new Date(d.timestamp).toLocaleTimeString();
    const indicator = (d.indicators && d.indicators[0]) ? escHtml(d.indicators[0]) : '—';
    return `<tr>
      <td>${escHtml(d.engine)}</td>
      <td style="color:${color};font-weight:600">${escHtml(d.result)}</td>
      <td style="color:${color}">${Math.round(d.score * 100)}%</td>
      <td style="color:var(--text-muted);font-size:10px">${indicator}</td>
      <td style="color:var(--text-dim)">${ts}</td>
    </tr>`;
  }).join('');
}

// ── Alert Card ─────────────────────────────────────────
function addAlertCard(alert) {
  const feed = document.getElementById('alertsFeed');
  if (!feed) return;

  const empty = feed.querySelector('.alert-empty');
  if (empty) feed.removeChild(empty);

  const card = document.createElement('div');
  card.className = 'alert-card';

  const ts = new Date(alert.timestamp || Date.now()).toLocaleTimeString();
  const score = alert.score ? Math.round(alert.score * 100) + '%' : '';
  const source = alert.source === 'groq' ? '⚡ Groq LLM' : '📝 Template';
  const id = 'alert_body_' + Date.now();
  const scoreColor = alert.severity === 'CRITICAL' ? '#ff2222' : alert.severity === 'HIGH' ? '#ff4444' : alert.severity === 'MEDIUM' ? '#ffaa00' : '#6699ff';

  card.innerHTML = `
    <div class="alert-card-header" onclick="toggleAlert('${id}')">
      <span class="severity-badge severity-${alert.severity}">${alert.severity}</span>
      <span class="alert-engine">${(alert.engine || '').replace(/_/g, ' ')}</span>
      <span class="alert-ts">${ts}</span>
      <i data-lucide="chevron-down" class="text-muted" style="width: 16px; height: 16px; margin-left: auto;"></i>
    </div>
    <div class="alert-card-body" id="${id}">
      <p class="alert-summary">${escHtml(alert.summary || '')}</p>
      <div class="alert-action"><i data-lucide="arrow-right" style="width: 12px; height: 12px; display: inline-block; margin-right: 4px;"></i>${escHtml(alert.action || '')}</div>
      <p class="text-xs text-dim mt-3">Generated by ${source} • Confidence: ${score}</p>
    </div>
  `;

  feed.prepend(card);
  if (window.lucide) window.lucide.createIcons({ root: card });
}

function toggleAlert(id) {
  const body = document.getElementById(id);
  if (body) body.classList.toggle('open');
}

function clearAlerts() {
  const feed = document.getElementById('alertsFeed');
  if (feed) feed.innerHTML = `
    <div class="alert-empty text-center py-10">
      <i data-lucide="check-circle" class="alert-empty-icon text-muted mx-auto" style="width: 48px; height: 48px;"></i>
      <p class="text-muted mt-2">All systems clear. No active alerts.</p>
    </div>
  `;
  if (window.lucide && feed) window.lucide.createIcons({ root: feed });
  alertCount = 0;
  updateAlertBadge();
}

function updateAlertBadge() {
  const badge = document.getElementById('alertBadge');
  if (!badge) return;
  badge.textContent = alertCount;
  badge.classList.toggle('visible', alertCount > 0);
}

// ── Toast ──────────────────────────────────────────────
function showToast(msg, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ── Status ─────────────────────────────────────────────
function setStatus(state, text) {
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  if (dot) dot.className = `status-dot ${state}`;
  if (txt) txt.textContent = text;
}

// ── Clock ──────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('headerTime');
  if (el) el.textContent = new Date().toLocaleString();
}
setInterval(updateClock, 1000);
updateClock();

// ── Utilities ──────────────────────────────────────────
function getVal(id)       { const el = document.getElementById(id); return el ? el.value : ''; }
function setVal(id, v)    { const el = document.getElementById(id); if (el) el.value = v; }
function setEl(id, text)  { const el = document.getElementById(id); if (el) el.textContent = text; }
function setBarWidth(id, pct) { const el = document.getElementById(id); if (el) el.style.width = Math.min(pct, 100) + '%'; }
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function exportCSV() {
  alert("Exporting CSV... (Mock Functionality)");
}

// ── Init ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }
  
  // Do NOT call initCharts() here — canvases are in hidden panel (zero size)
  // Charts are initialized when user clicks the Live Monitor tab
  setStatus('', 'Connecting...');
  fetch('/api/status')
    .then(r => r.json())
    .then(() => setStatus('online', 'Backend Online'))
    .catch(() => setStatus('offline', 'Backend Offline'));
});
