/* ================================================
   dashboard.js
   Shared frontend behavior: theme toggle, live clock,
   counter animation, toasts, search, chart builders,
   heatmap, and SocketIO connection.
================================================ */

// ---------- Theme Toggle ----------
const THEME_STORAGE_KEY = "cloudsec-theme";
const SIDEBAR_STORAGE_KEY = "cloudsec-sidebar-collapsed";

function readStoredTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch (error) {
    return null;
  }
}

function readStoredSidebarState() {
  try {
    return localStorage.getItem(SIDEBAR_STORAGE_KEY);
  } catch (error) {
    return null;
  }
}

function applyTheme(theme, persist = true) {
  const nextTheme = theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", nextTheme);
  document.body.setAttribute("data-theme", nextTheme);

  const themeIcon = document.getElementById("themeIcon");
  if (themeIcon) {
    themeIcon.className = nextTheme === "dark" ? "bi bi-moon-stars-fill" : "bi bi-sun-fill";
  }

  const settingsSwitch = document.getElementById("settingsThemeSwitch");
  if (settingsSwitch) {
    settingsSwitch.checked = nextTheme === "dark";
  }

  if (persist) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch (error) {
      // Local storage may be unavailable in restricted browser contexts.
    }
  }
}

function applySidebarState(collapsed, persist = true) {
  const shouldCollapse = Boolean(collapsed);
  document.body.classList.toggle("sidebar-collapsed", shouldCollapse);

  const sidebarButton = document.getElementById("sidebarCollapseBtn");
  if (sidebarButton) {
    sidebarButton.setAttribute("aria-expanded", String(!shouldCollapse));
    const icon = sidebarButton.querySelector("i");
    if (icon) {
      icon.className = shouldCollapse ? "bi bi-layout-sidebar-inset-reverse" : "bi bi-layout-sidebar-inset";
    }
  }

  if (persist) {
    try {
      localStorage.setItem(SIDEBAR_STORAGE_KEY, shouldCollapse ? "1" : "0");
    } catch (error) {
      // Ignore storage failures in demo environments.
    }
  }
}

document.addEventListener("DOMContentLoaded", function () {
  applyTheme(readStoredTheme() || document.documentElement.getAttribute("data-theme") || "dark", false);
  applySidebarState(readStoredSidebarState() === "1", false);

  const deterrentMessage = "Developer tools and context menus are restricted in demo mode.";

  document.addEventListener("contextmenu", (event) => {
    event.preventDefault();
    showToast(deterrentMessage, "warning");
  });

  document.addEventListener("keydown", (event) => {
    const blocked = event.key === "F12" || (event.ctrlKey && event.shiftKey && ["I", "J", "C"].includes(event.key));
    if (blocked) {
      event.preventDefault();
      showToast(deterrentMessage, "warning");
    }
  });

  const themeBtn = document.getElementById("themeToggleBtn");
  const themeIcon = document.getElementById("themeIcon");
  const settingsSwitch = document.getElementById("settingsThemeSwitch");

  function toggleTheme() {
    const current = document.body.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    document.body.classList.add("theme-transition");
    applyTheme(next);
    window.setTimeout(() => document.body.classList.remove("theme-transition"), 280);
  }

  if (themeBtn) themeBtn.addEventListener("click", toggleTheme);
  if (settingsSwitch) {
    settingsSwitch.addEventListener("change", () => {
      document.body.classList.add("theme-transition");
      applyTheme(settingsSwitch.checked ? "dark" : "light");
      window.setTimeout(() => document.body.classList.remove("theme-transition"), 280);
    });
  }

  const sidebarCollapseBtn = document.getElementById("sidebarCollapseBtn");
  if (sidebarCollapseBtn) {
    sidebarCollapseBtn.addEventListener("click", () => {
      const collapsed = !document.body.classList.contains("sidebar-collapsed");
      applySidebarState(collapsed);
    });
  }

  // Mobile sidebar toggle
  const mobileToggle = document.getElementById("mobileSidebarToggle");
  const sidebar = document.getElementById("sidebar");
  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener("click", () => sidebar.classList.toggle("show"));
  }

  // Live clock
  function updateClock() {
    const el = document.getElementById("liveClock");
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleTimeString();
  }
  updateClock();
  setInterval(updateClock, 1000);

  // Counter animation
  document.querySelectorAll(".counter-animate").forEach((el) => {
    const target = parseInt(el.getAttribute("data-target"), 10) || 0;
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 40));
    const interval = setInterval(() => {
      current += step;
      if (current >= target) {
        current = target;
        clearInterval(interval);
      }
      el.textContent = current.toLocaleString();
    }, 25);
  });

  // Global search (client-side filter on dashboard table if present)
  const searchInput = document.getElementById("globalSearch");
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      const query = this.value.toLowerCase();
      const rows = document.querySelectorAll("#alertsTableBody tr");
      rows.forEach((row) => {
        row.style.display = row.textContent.toLowerCase().includes(query) ? "" : "none";
      });
    });
  }

  const dashboardConfig = document.getElementById("dashboardConfig");
  if (dashboardConfig) {
    const attackDistribution = JSON.parse(dashboardConfig.dataset.attackDistribution || "{}");
    const trafficPattern = JSON.parse(dashboardConfig.dataset.trafficPattern || "[]");
    const securityScore = parseInt(dashboardConfig.dataset.securityScore || "0", 10);

    const loadDemoBtn = document.getElementById("loadDemoBtn");
    if (loadDemoBtn) {
      loadDemoBtn.addEventListener("click", async () => {
        try {
          const response = await fetch(dashboardConfig.dataset.loadDemoUrl || "/load-demo-threats");
          const data = await response.json();
          const body = document.getElementById("alertsTableBody");
          if (body && Array.isArray(data.incidents)) {
            body.innerHTML = data.incidents.map((inc) => `
              <tr>
                <td>${inc.time}</td>
                <td><a class="ip-link text-decoration-none" href="/investigate/${inc.source_ip}">${inc.source_ip}</a></td>
                <td>${inc.destination_ip}</td>
                <td>${inc.attack_type}</td>
                <td><span class="badge-status badge-severity-${inc.severity}">${inc.severity}</span></td>
                <td>${inc.confidence}%</td>
                <td>${inc.assigned_to}</td>
                <td>${inc.status}</td>
                <td><a href="/investigate/${inc.source_ip}" class="btn btn-sm btn-outline-glass">Investigate</a></td>
              </tr>
            `).join('');
            showToast('Demo threats loaded successfully.', 'success');
          }
        } catch (error) {
          showToast('Unable to load demo threats right now.', 'danger');
        }
      });
    }

    initDashboardCharts(attackDistribution, trafficPattern, securityScore);
    initThreatHeatmap();
  }

  // SocketIO connection (used to push fixed demo incidents on connect)
  try {
    const socket = io();
    socket.on("connect", () => {
      console.log("[SocketIO] Connected to server.");
    });
    socket.on("incidents_update", (data) => {
      console.log("[SocketIO] Incidents received:", data.incidents.length);
      showToast(`Live incident feed synced (${data.incidents.length} incidents).`, "success");
    });
  } catch (e) {
    console.warn("SocketIO not available:", e);
  }
});

// ---------- Toast ----------
function showToast(message, type = "info") {
  const colors = {
    info: "#2563EB",
    success: "#22C55E",
    warning: "#F59E0B",
    danger: "#EF4444",
  };
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.style.background = "#0F172A";
  toast.style.border = `1px solid ${colors[type] || colors.info}`;
  toast.style.color = "#F8FAFC";
  toast.style.padding = "0.75rem 1rem";
  toast.style.borderRadius = "10px";
  toast.style.marginBottom = "0.5rem";
  toast.style.minWidth = "260px";
  toast.style.boxShadow = "0 8px 20px rgba(0,0,0,0.4)";
  toast.style.animation = "fadeInUp 0.3s ease forwards";
  toast.innerText = message;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = "opacity 0.4s ease";
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 400);
  }, 3000);
}

// ---------- Chart.js global defaults ----------
if (window.Chart) {
  Chart.defaults.color = "#94A3B8";
  Chart.defaults.borderColor = "rgba(148,163,184,0.15)";
}

const PALETTE = {
  accent: "#00E5FF",
  blue: "#2563EB",
  green: "#22C55E",
  orange: "#F59E0B",
  red: "#EF4444",
};

// ---------- Dashboard Charts ----------
function initDashboardCharts(attackDistribution, trafficPattern, securityScore) {
  // Live Traffic Chart (line)
  const trafficCtx = document.getElementById("liveTrafficChart");
  if (trafficCtx) {
    new Chart(trafficCtx, {
      type: "line",
      data: {
        labels: trafficPattern.map((_, i) => `T-${trafficPattern.length - i}`),
        datasets: [
          {
            label: "Packets / min",
            data: trafficPattern,
            borderColor: PALETTE.accent,
            backgroundColor: "rgba(0,229,255,0.12)",
            fill: true,
            tension: 0.35,
            pointRadius: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: "rgba(148,163,184,0.08)" } },
        },
        animation: { duration: 900, easing: "easeOutQuart" },
      },
    });
  }

  // Attack Distribution (doughnut)
  const attackCtx = document.getElementById("attackDistributionChart");
  if (attackCtx) {
    const labels = Object.keys(attackDistribution);
    const values = Object.values(attackDistribution);
    new Chart(attackCtx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [
          {
            data: values,
            backgroundColor: [PALETTE.red, PALETTE.blue, PALETTE.orange, PALETTE.accent, PALETTE.green],
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } },
        animation: { duration: 900 },
      },
    });
  }

  // Severity Gauge (doughnut styled as gauge)
  const gaugeCtx = document.getElementById("severityGaugeChart");
  if (gaugeCtx) {
    const score = securityScore;
    new Chart(gaugeCtx, {
      type: "doughnut",
      data: {
        labels: ["Score", "Remaining"],
        datasets: [
          {
            data: [score, 100 - score],
            backgroundColor: [
              score >= 80 ? PALETTE.green : score >= 60 ? PALETTE.orange : PALETTE.red,
              "rgba(148,163,184,0.12)",
            ],
            borderWidth: 0,
          },
        ],
      },
      options: {
        circumference: 180,
        rotation: 270,
        cutout: "75%",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        animation: { duration: 900 },
      },
    });

    const label = document.createElement("div");
    label.className = "gauge-value";
    label.textContent = score + " / 100";
    gaugeCtx.parentElement.appendChild(label);
  }
}

// ---------- Threat Heatmap ----------
function initThreatHeatmap() {
  const grid = document.getElementById("threatHeatmap");
  if (!grid) return;

  // Deterministic 4x12 heatmap: 4 rows (days) x 12 columns (2-hour blocks)
  // Values are fixed/demo, not randomly generated at runtime.
  const heatValues = [
    [1, 0, 0, 0, 0, 1, 2, 3, 2, 1, 0, 0],
    [0, 0, 1, 0, 0, 0, 1, 4, 3, 1, 0, 0],
    [0, 1, 0, 0, 1, 2, 3, 2, 1, 0, 0, 1],
    [0, 0, 0, 1, 0, 1, 2, 1, 0, 0, 0, 0],
  ];

  heatValues.forEach((row) => {
    row.forEach((value) => {
      const cell = document.createElement("div");
      cell.className = "heatmap-cell";
      let color = "rgba(148,163,184,0.1)";
      if (value === 1) color = "rgba(0,229,255,0.25)";
      else if (value === 2) color = "rgba(245,158,11,0.5)";
      else if (value >= 3) color = "rgba(239,68,68,0.7)";
      cell.style.background = color;
      cell.title = `${value} events`;
      grid.appendChild(cell);
    });
  });
}

// ---------- Analytics Page Charts ----------
function initAnalyticsCharts(weeklyLabels, weeklyCounts, attackTypeData, severityData, statusData) {
  const weeklyCtx = document.getElementById("weeklyChart");
  if (weeklyCtx) {
    new Chart(weeklyCtx, {
      type: "bar",
      data: {
        labels: weeklyLabels,
        datasets: [
          {
            label: "Incidents",
            data: weeklyCounts,
            backgroundColor: PALETTE.accent,
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
        animation: { duration: 900 },
      },
    });
  }

  const attackTypeCtx = document.getElementById("attackTypeChart");
  if (attackTypeCtx) {
    new Chart(attackTypeCtx, {
      type: "bar",
      data: {
        labels: Object.keys(attackTypeData),
        datasets: [
          {
            label: "Count",
            data: Object.values(attackTypeData),
            backgroundColor: [PALETTE.red, PALETTE.blue, PALETTE.orange, PALETTE.accent],
            borderRadius: 6,
          },
        ],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        animation: { duration: 900 },
      },
    });
  }

  const severityCtx = document.getElementById("severityChart");
  if (severityCtx) {
    new Chart(severityCtx, {
      type: "pie",
      data: {
        labels: Object.keys(severityData),
        datasets: [
          {
            data: Object.values(severityData),
            backgroundColor: [PALETTE.red, PALETTE.orange, PALETTE.blue, PALETTE.green],
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        animation: { duration: 900 },
      },
    });
  }

  const statusCtx = document.getElementById("statusChart");
  if (statusCtx) {
    new Chart(statusCtx, {
      type: "doughnut",
      data: {
        labels: Object.keys(statusData),
        datasets: [
          {
            data: Object.values(statusData),
            backgroundColor: [PALETTE.blue, PALETTE.orange, PALETTE.green, PALETTE.red],
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        animation: { duration: 900 },
      },
    });
  }
}
