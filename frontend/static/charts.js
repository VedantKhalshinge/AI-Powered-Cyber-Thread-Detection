/* ═══════════════════════════════════════════════════════
   charts.js — Chart.js Live Rolling Window Charts
   ═══════════════════════════════════════════════════════ */

const CHART_POINTS = 60;

// Shared Y-axis style
const yAxis = {
  min: 0,
  max: 100,
  grid: { color: 'rgba(0,0,0,0.05)', drawBorder: false },
  ticks: {
    color: '#6B7280',
    font: { family: "'Inter', sans-serif", size: 11 },
    callback: v => v + '%',
    maxTicksLimit: 5,
  },
};

const xAxis = { display: false };

const lineDefaults = {
  tension: 0.4,
  borderWidth: 2,
  pointRadius: 0,
  pointHoverRadius: 0,
};

// ── Buffers — data stored before charts are visible ─────
const _buf = { cpu: [], ram: [], diskR: [], diskW: [] };

// ── Chart instances ─────────────────────────────────────
let cpuChart = null, ramChart = null, diskChart = null;
let _chartsReady = false;

function _makeData(n) { return Array(n).fill(0); }

function createGradient(ctx, color) {
  const g = ctx.createLinearGradient(0, 0, 0, 180);
  g.addColorStop(0, color + '55');
  g.addColorStop(1, color + '00');
  return g;
}

function initCharts() {
  // Only init when canvases exist and are in the DOM
  const cpuEl  = document.getElementById('cpuChart');
  const ramEl  = document.getElementById('ramChart');
  const diskEl = document.getElementById('diskChart');
  if (!cpuEl || !ramEl || !diskEl) return;

  // Destroy stale instances
  [cpuChart, ramChart, diskChart].forEach(c => c && c.destroy());

  const cpuCtx  = cpuEl.getContext('2d');
  const ramCtx  = ramEl.getContext('2d');
  const diskCtx = diskEl.getContext('2d');

  // ── CPU ────────────────────────────────────────────────
  cpuChart = new Chart(cpuCtx, {
    type: 'line',
    data: {
      labels: Array(CHART_POINTS).fill(''),
      datasets: [{
        ...lineDefaults,
        data: _makeData(CHART_POINTS),
        borderColor: '#2563EB', // Blue 600
        backgroundColor: createGradient(cpuCtx, '#2563EB'),
        fill: true,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false } },
      scales: { x: xAxis, y: { ...yAxis } },
    },
  });

  // ── RAM ────────────────────────────────────────────────
  ramChart = new Chart(ramCtx, {
    type: 'line',
    data: {
      labels: Array(CHART_POINTS).fill(''),
      datasets: [{
        ...lineDefaults,
        data: _makeData(CHART_POINTS),
        borderColor: '#10B981', // Emerald 500
        backgroundColor: createGradient(ramCtx, '#10B981'),
        fill: true,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false } },
      scales: { x: xAxis, y: { ...yAxis } },
    },
  });

  // ── Disk I/O ───────────────────────────────────────────
  diskChart = new Chart(diskCtx, {
    type: 'line',
    data: {
      labels: Array(CHART_POINTS).fill(''),
      datasets: [
        {
          ...lineDefaults,
          label: 'Read KB/s',
          data: _makeData(CHART_POINTS),
          borderColor: '#F59E0B', // Amber 500
          backgroundColor: createGradient(diskCtx, '#F59E0B'),
          fill: false,
        },
        {
          ...lineDefaults,
          label: 'Write KB/s',
          data: _makeData(CHART_POINTS),
          borderColor: '#EF4444', // Red 500
          backgroundColor: 'transparent',
          fill: false,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          display: true,
          labels: { color: '#6B7280', font: { family: "'Inter', sans-serif", size: 11 }, boxWidth: 12, padding: 12 },
        },
      },
      scales: {
        x: xAxis,
        y: {
          min: 0,
          grid: { color: 'rgba(0,0,0,0.05)', drawBorder: false },
          ticks: {
            color: '#6B7280',
            font: { family: "'Inter', sans-serif", size: 11 },
            maxTicksLimit: 5,
            callback: v => v >= 1000 ? (v/1000).toFixed(1)+'M' : v+'K',
          },
        },
      },
    },
  });

  _chartsReady = true;

  // Flush buffered data
  if (_buf.cpu.length) {
    _buf.cpu.forEach(v   => _appendTo(cpuChart,  v, 0));
    _buf.ram.forEach(v   => _appendTo(ramChart,   v, 0));
    _buf.diskR.forEach(v => _appendTo(diskChart,  v, 0));
    _buf.diskW.forEach(v => _appendTo(diskChart,  v, 1));
    _buf.cpu = []; _buf.ram = []; _buf.diskR = []; _buf.diskW = [];
    cpuChart.update('none');
    ramChart.update('none');
    diskChart.update('none');
  }
}

// ── Append one value to a chart dataset ────────────────
function _appendTo(chart, value, dsIdx) {
  if (!chart) return;
  const ds = chart.data.datasets[dsIdx];
  ds.data.push(value);
  if (ds.data.length > CHART_POINTS) ds.data.shift();
  chart.data.labels.push('');
  if (chart.data.labels.length > CHART_POINTS) chart.data.labels.shift();
}

// ── Called by dashboard.js on every metrics_update ─────
function updateCharts(data) {
  const cpu   = +(data.cpu               || 0);
  const ram   = +(data.ram               || 0);
  const diskR = +(data.disk_read_kbps    || 0);
  const diskW = +(data.disk_write_kbps   || 0);

  if (!_chartsReady) {
    // Buffer so history is available when user opens Live Monitor
    const push = (arr, v) => { arr.push(v); if (arr.length > CHART_POINTS) arr.shift(); };
    push(_buf.cpu,   cpu);
    push(_buf.ram,   ram);
    push(_buf.diskR, diskR);
    push(_buf.diskW, diskW);
    return;
  }

  _appendTo(cpuChart,  cpu,   0);
  _appendTo(ramChart,  ram,   0);
  _appendTo(diskChart, diskR, 0);
  _appendTo(diskChart, diskW, 1);

  cpuChart.update('none');
  ramChart.update('none');
  diskChart.update('none');
}
