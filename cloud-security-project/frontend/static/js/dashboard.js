/* ================================================
   dashboard.js
   Shared frontend behavior: theme toggle, live clock,
   counter animation, toasts, search, chart builders,
   heatmap, and SocketIO connection.
================================================ */

// ---------- Theme Toggle ----------
const THEME_STORAGE_KEY = "cloudsec-theme";
const SIDEBAR_STORAGE_KEY = "cloudsec-sidebar-collapsed";
const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

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
  document.body.classList.add("ui-loading");
  applyTheme(readStoredTheme() || document.documentElement.getAttribute("data-theme") || "dark", false);
  applySidebarState(readStoredSidebarState() === "1", false);
  initSplashScreen();
  initEnterpriseAnimations();
  initRippleTargets();
  initLoadingStates();
  initBackToTop();

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
    el.textContent = `${now.toLocaleDateString(undefined, { month: "short", day: "2-digit", year: "numeric" })} ${now.toLocaleTimeString()}`;
  }
  updateClock();
  setInterval(updateClock, 1000);

  // Counter animation
  document.querySelectorAll(".counter-animate").forEach((el) => {
    if (reduceMotion) {
      el.textContent = (parseInt(el.getAttribute("data-target"), 10) || 0).toLocaleString();
      return;
    }
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

    // The rest of the setup is now handled via the SOC page module lifecycle.
    window.setTimeout(() => document.body.classList.remove("ui-loading"), reduceMotion ? 0 : 520);
});

// ---------- Dashboard HTMX Page Module ----------
window.SOC.registerPage("dashboard", function(root) {
    let dashboardCleanup = [];
    const dashboardConfig = root.querySelector("#dashboardConfig");
    
    if (dashboardConfig) {
        const attackDistribution = JSON.parse(dashboardConfig.dataset.attackDistribution || "{}");
        const trafficPattern = JSON.parse(dashboardConfig.dataset.trafficPattern || "[]");
        const securityScore = parseInt(dashboardConfig.dataset.securityScore || "0", 10);

        const loadDemoBtn = root.querySelector("#loadDemoBtn");
        if (loadDemoBtn) {
            const handleLoadDemo = async () => {
                try {
                    const response = await fetch(dashboardConfig.dataset.loadDemoUrl || "/load-demo-threats");
                    const data = await response.json();
                    const body = root.querySelector("#alertsTableBody");
                    if (body && Array.isArray(data.incidents)) {
                        renderIncidentRows(body, data.incidents);
                        showToast('Demo threats loaded successfully.', 'success');
                    }
                } catch (error) {
                    showToast('Unable to load demo threats right now.', 'danger');
                }
            };
            loadDemoBtn.addEventListener("click", handleLoadDemo);
            dashboardCleanup.push(() => loadDemoBtn.removeEventListener("click", handleLoadDemo));
        }

        initDashboardCharts(attackDistribution, trafficPattern, securityScore);
        initThreatHeatmap();
    }

    const handleIncidentsUpdate = (evt) => {
        const data = evt.detail;
        const incidents = Array.isArray(data && data.incidents) ? data.incidents : [];
        console.log("[SocketIO/Dashboard] Incidents received:", incidents.length);
        showToast(`Live incident feed synced (${incidents.length} incidents).`, "success");
    };
    
    document.addEventListener("soc:incidents_update", handleIncidentsUpdate);
    dashboardCleanup.push(() => document.removeEventListener("soc:incidents_update", handleIncidentsUpdate));

    return function cleanup() {
        dashboardCleanup.forEach(fn => fn());
    };
});

function initSplashScreen() {
  const splash = document.getElementById("appSplash");
  const splashText = document.getElementById("splashText");
  if (!splash) return;

  const messages = [
    "Initializing AI Engine...",
    "Loading Threat Intelligence...",
    "Connecting Database...",
    "Preparing Dashboard...",
  ];
  let index = 0;
  if (splashText) {
    splashText.textContent = messages[index];
    const timer = window.setInterval(() => {
      index = (index + 1) % messages.length;
      splashText.textContent = messages[index];
    }, 420);
    window.setTimeout(() => window.clearInterval(timer), 1200);
  }

  window.setTimeout(() => {
    splash.classList.add("is-hidden");
    window.setTimeout(() => splash.remove(), 460);
  }, reduceMotion ? 0 : 900);
}

function initEnterpriseAnimations() {
  if (reduceMotion) return;
  const animated = document.querySelectorAll(".glass-card, .ai-panel, .status-card, .metric-card, .activity-item, .recommendation-item");
  animated.forEach((element, index) => {
    element.classList.add("enterprise-enter");
    element.style.animationDelay = `${Math.min(index * 60, 420)}ms`;
  });
}

function initRippleTargets() {
  const targets = document.querySelectorAll("button, .btn-cyan, .btn-outline-glass, .quick-action-btn, .social-login-btn, .theme-toggle-btn, .notif-btn");
  targets.forEach((target) => {
    target.classList.add("ripple-target");
    target.addEventListener("click", (event) => {
      if (reduceMotion) return;
      const rect = target.getBoundingClientRect();
      const ripple = document.createElement("span");
      ripple.className = "ui-ripple";
      ripple.style.left = `${event.clientX - rect.left}px`;
      ripple.style.top = `${event.clientY - rect.top}px`;
      target.appendChild(ripple);
      window.setTimeout(() => ripple.remove(), 440);
    });
  });
}

function initLoadingStates() {
  const loadingSelectors = [
    'a[href*="download-pdf"]',
    'a[href*="download-csv"]',
    "#loadDemoBtn",
    'button[onclick*="reload"]',
    'button[type="submit"]',
    'form[enctype="multipart/form-data"] button',
  ];

  document.querySelectorAll(loadingSelectors.join(",")).forEach((element) => {
    element.addEventListener("click", () => {
      element.classList.add("is-loading");
      const text = element.textContent.trim().toLowerCase();
      if (text.includes("pdf")) showToast("Generating PDF report...", "info");
      else if (text.includes("csv")) showToast("Preparing CSV export...", "info");
      else if (text.includes("process")) showToast("Prediction pipeline started...", "info");
      else if (text.includes("refresh")) showToast("Refreshing dashboard...", "info");
      window.setTimeout(() => {
        element.classList.remove("is-loading");
        if (text.includes("pdf")) showToast("Report generated.", "success");
        else if (text.includes("csv")) showToast("CSV export prepared.", "success");
        else if (text.includes("process")) showToast("Prediction completed.", "success");
      }, 900);
    });
  });
}

function buildTextCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value == null ? "" : String(value);
  return cell;
}

function buildInvestigationLink(ip, text, button = false) {
  const link = document.createElement("a");
  link.href = `/investigate/${encodeURIComponent(ip || "")}`;
  link.textContent = text == null ? "" : String(text);
  link.className = button ? "btn btn-sm btn-outline-glass" : "ip-link text-decoration-none";
  return link;
}

function renderIncidentRows(body, incidents) {
  body.replaceChildren();
  incidents.forEach((inc) => {
    const row = document.createElement("tr");

    row.appendChild(buildTextCell(inc.time));

    const sourceCell = document.createElement("td");
    sourceCell.appendChild(buildInvestigationLink(inc.source_ip, inc.source_ip));
    row.appendChild(sourceCell);

    row.appendChild(buildTextCell(inc.destination_ip));
    row.appendChild(buildTextCell(inc.attack_type));

    const severityCell = document.createElement("td");
    const severity = document.createElement("span");
    severity.className = `badge-status badge-severity-${String(inc.severity || "").replace(/[^A-Za-z0-9_-]/g, "")}`;
    severity.textContent = inc.severity || "";
    severityCell.appendChild(severity);
    row.appendChild(severityCell);

    row.appendChild(buildTextCell(`${inc.confidence || 0}%`));
    row.appendChild(buildTextCell(inc.assigned_to));
    row.appendChild(buildTextCell(inc.status));

    const actionCell = document.createElement("td");
    actionCell.appendChild(buildInvestigationLink(inc.source_ip, "Investigate", true));
    row.appendChild(actionCell);

    body.appendChild(row);
  });
}

function initBackToTop() {
  const button = document.getElementById("backToTop");
  if (!button) return;
  window.addEventListener("scroll", () => {
    button.classList.toggle("is-visible", window.scrollY > 360);
  }, { passive: true });
  button.addEventListener("click", () => window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" }));
}

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
  toast.style.animation = "toastIn 0.24s ease forwards";
  toast.innerText = message;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = "toastOut 0.28s ease forwards";
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
    window.replaceChart("liveTrafficChart", {
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
        animation: { duration: reduceMotion ? 0 : 480, easing: "easeOutQuart" },
      },
    });
  }

  // Attack Distribution (doughnut)
  const attackCtx = document.getElementById("attackDistributionChart");
  if (attackCtx) {
    const labels = Object.keys(attackDistribution);
    const values = Object.values(attackDistribution);
    window.replaceChart("attackDistributionChart", {
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
        animation: { duration: reduceMotion ? 0 : 480 },
      },
    });
  }

  // Severity Gauge (doughnut styled as gauge)
  const gaugeCtx = document.getElementById("severityGaugeChart");
  if (gaugeCtx) {
    const score = securityScore;
    window.replaceChart("severityGaugeChart", {
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
        animation: { duration: reduceMotion ? 0 : 480 },
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
    window.replaceChart("weeklyChart", {
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
        animation: { duration: reduceMotion ? 0 : 480 },
      },
    });
  }

  const attackTypeCtx = document.getElementById("attackTypeChart");
  if (attackTypeCtx) {
    window.replaceChart("attackTypeChart", {
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
        animation: { duration: reduceMotion ? 0 : 480 },
      },
    });
  }

  const severityCtx = document.getElementById("severityChart");
  if (severityCtx) {
    window.replaceChart("severityChart", {
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
        animation: { duration: reduceMotion ? 0 : 480 },
      },
    });
  }

  const statusCtx = document.getElementById("statusChart");
  if (statusCtx) {
    window.replaceChart("statusChart", {
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
        animation: { duration: reduceMotion ? 0 : 480 },
      },
    });
  }
}
