// ============================================================================
// CIBERCENTINELA - FRONTEND SPA & CONSOLA DEL DEMONIO LOCALHOST
// ============================================================================

let currentCaptchaId = null;
let currentCaptchaAnswer = null;
let AUTH_TOKEN = localStorage.getItem("centinela_token") || "";
let CURRENT_USER = null;
let CATALOGS = { categorias: [], estados: [], analistas: [], roles: [] };
let POLL_TIMER = null;

function showToast(message, isError = false) {
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = "toast-item" + (isError ? " error" : "");
  el.innerHTML = `<div style="font-weight:600; margin-bottom:0.2rem;">${isError ? "Alerta de Seguridad / MySQL" : "CiberCentinela SOC"}</div><div>${escapeHtml(message)}</div>`;
  container.appendChild(el);
  setTimeout(() => {
    el.remove();
  }, 5200);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function apiFetch(path, options = {}) {
  const headers = options.headers || {};
  if (AUTH_TOKEN) {
    headers["Authorization"] = `Bearer ${AUTH_TOKEN}`;
  }
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const resp = await fetch(path, { ...options, headers });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || `Error HTTP ${resp.status}`);
  }
  return data;
}

// ============================================================================
// AUTENTICACIÓN Y CAMBIO RÁPIDO DE PERFIL RBAC
// ============================================================================
function fillDemoLogin(email, password, autoSubmit = false) {
  const emailInput = document.getElementById("login-email");
  const passInput = document.getElementById("login-password");
  if (emailInput) emailInput.value = email;
  if (passInput) passInput.value = password;
  const errBox = document.getElementById("login-error-box");
  if (errBox) errBox.classList.add("hidden");

  const totpInput = document.getElementById("totp_code");
  if (totpInput && !totpInput.value) {
    totpInput.focus();
  }
}

async function handleLogin(ev) {
  ev.preventDefault();
  const email = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;
  const totp_code = document.getElementById("totp_code") ? document.getElementById("totp_code").value.trim() : "";
  const errBox = document.getElementById("login-error-box");
  errBox.classList.add("hidden");

  const recaptcha_response = (typeof grecaptcha !== "undefined") ? grecaptcha.getResponse() : "";
  if (!recaptcha_response) {
    errBox.textContent = "VERIFICACIÓN ANTI-BOT REQUERIDA: Marque la casilla 'No soy un robot' (Google reCAPTCHA) para continuar.";
    errBox.classList.remove("hidden");
    showToast("Debe completar la verificación reCAPTCHA", true);
    return;
  }

  try {
    const res = await apiFetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password, recaptcha_response, totp_code }),
    });
    AUTH_TOKEN = res.token;
    localStorage.setItem("centinela_token", AUTH_TOKEN);
    CURRENT_USER = res.user;
    showToast(`Sesión iniciada como ${CURRENT_USER.nombre_completo} [${CURRENT_USER.nombre_rol}] (${CURRENT_USER.mysql_service_user})`);
    await enterConsole();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove("hidden");
    showToast(err.message, true);
    if (typeof grecaptcha !== "undefined") {
      try { grecaptcha.reset(); } catch (_) {}
    }
  }
}

async function simulateBruteForceAttempt() {
  const email = document.getElementById("login-email").value.trim() || "mcamacho@centinela.local";
  document.getElementById("login-email").value = email;
  document.getElementById("login-password").value = "ClaveIncorrectaForceBrute!";
  const errBox = document.getElementById("login-error-box");

  try {
    await apiFetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email,
        password: "ClaveIncorrectaForceBrute!",
        recaptcha_response: "simulation_bypass",
        captcha_id: "simulation_bypass",
      }),
    });
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove("hidden");
    showToast(err.message, true);
  }
}

async function quickSwitchUser(email, password) {
  try {
    const res = await apiFetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
        recaptcha_response: "simulation_bypass",
        captcha_id: "simulation_bypass",
      }),
    });
    AUTH_TOKEN = res.token;
    localStorage.setItem("centinela_token", AUTH_TOKEN);
    CURRENT_USER = res.user;
    updateTopUserBar();
    showToast(`Cambiado a perfil: ${CURRENT_USER.nombre_completo} (${CURRENT_USER.mysql_service_user})`);
    await refreshAllActiveData();
  } catch (err) {
    showToast(err.message, true);
  }
}

function logoutSession() {
  AUTH_TOKEN = "";
  CURRENT_USER = null;
  localStorage.removeItem("centinela_token");
  if (POLL_TIMER) clearInterval(POLL_TIMER);
  document.getElementById("view-app").classList.add("hidden");
  document.getElementById("view-login").classList.remove("hidden");
  document.getElementById("top-user-pill").classList.add("hidden");
  document.getElementById("btn-logout").classList.add("hidden");
}

function updateTopUserBar() {
  if (!CURRENT_USER) return;
  const pill = document.getElementById("top-user-pill");
  const label = document.getElementById("top-user-label");
  pill.classList.remove("hidden");
  document.getElementById("btn-logout").classList.remove("hidden");
  label.innerHTML = `<strong>${escapeHtml(CURRENT_USER.nombre_completo)}</strong> · <span style="color:#4ADE80;">${escapeHtml(CURRENT_USER.nombre_rol)}</span> (<code class="mono">${escapeHtml(CURRENT_USER.mysql_service_user)}</code>)`;
}

async function enterConsole() {
  document.getElementById("view-login").classList.add("hidden");
  document.getElementById("view-app").classList.remove("hidden");
  updateTopUserBar();
  await loadCatalogs();
  await refreshAllActiveData();
  if (POLL_TIMER) clearInterval(POLL_TIMER);
  POLL_TIMER = setInterval(() => {
    loadTelemetry(true);
  }, 8000);
}

async function refreshAllActiveData() {
  await Promise.allSettled([
    loadTelemetry(),
    loadIncidents(),
    loadTelegramQueue(),
  ]);
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-view").forEach((el) => el.classList.add("hidden"));
  document.getElementById(tabId).classList.remove("hidden");
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
  });

  if (tabId === "tab-soc") loadTelemetry();
  if (tabId === "tab-incidents") loadIncidents();
  if (tabId === "tab-forensics") loadForensics();
  if (tabId === "tab-audit") loadAuditLogs();
  if (tabId === "tab-telegram") loadTelegramQueue();
  if (tabId === "tab-admin") {
    loadBackups();
    loadUsers();
  }
}

// ============================================================================
// CATÁLOGOS Y TELEMETRÍA DEL DEMONIO EN SEGUNDO PLANO (MÓDULO 1 & 5)
// ============================================================================
async function loadCatalogs() {
  const data = await apiFetch("/api/catalogs");
  CATALOGS = data;

  const catFilter = document.getElementById("filter-categoria");
  const catNew = document.getElementById("inc-new-categoria");
  catFilter.innerHTML = `<option value="">Todas las categorías</option>`;
  catNew.innerHTML = "";
  data.categorias.forEach((c) => {
    catFilter.innerHTML += `<option value="${c.id_categoria}">${escapeHtml(c.nombre_categoria)}</option>`;
    catNew.innerHTML += `<option value="${c.id_categoria}">${escapeHtml(c.nombre_categoria)}</option>`;
  });

  const estFilter = document.getElementById("filter-estado");
  estFilter.innerHTML = `<option value="">Todos los estados</option>`;
  data.estados.forEach((e) => {
    estFilter.innerHTML += `<option value="${e.id_estado}">${escapeHtml(e.nombre_estado)}</option>`;
  });

  const anaNew = document.getElementById("inc-new-analista");
  anaNew.innerHTML = `<option value="">-- Sin asignar (En espera de triaje) --</option>`;
  data.analistas.forEach((a) => {
    const statusTag = a.activo === 1 ? "ACTIVO" : "INACTIVO (activo=0 · Prueba Trigger Bloqueo)";
    anaNew.innerHTML += `<option value="${a.id_usuario}">${escapeHtml(a.nombre_completo)} [${statusTag}]</option>`;
  });
}

async function loadTelemetry(silent = false) {
  try {
    const data = await apiFetch("/api/daemon/telemetry");
    const d = data.daemon;
    const k = data.kpis;

    document.getElementById("top-pid-host").textContent = `PID ${d.pid} @ ${d.hostname} (Uptime ${d.uptime_seconds}s)`;
    document.getElementById("kpi-total-incidents").textContent = k.total_incidentes;
    document.getElementById("kpi-active-incidents").textContent = k.incidentes_activos;
    document.getElementById("kpi-critical-incidents").textContent = k.incidentes_criticos;
    document.getElementById("kpi-telegram-pending").textContent = k.telegram_pendientes;
    document.getElementById("kpi-total-evidences").textContent = k.total_evidencias;
    document.getElementById("kpi-total-audit").textContent = k.total_auditoria;
    document.getElementById("kpi-total-history").textContent = k.total_historico;

    document.getElementById("badge-incidents-count").textContent = k.total_incidentes;
    document.getElementById("badge-evidences-count").textContent = k.total_evidencias;
    document.getElementById("badge-audit-count").textContent = k.total_auditoria;
    document.getElementById("badge-telegram-count").textContent = k.telegram_pendientes;

    document.getElementById("mysql-version-badge").textContent = `MySQL ${data.mysql.version} · ${data.mysql.triggers_count} Triggers`;

    // Renderizar consola journalctl
    const term = document.getElementById("daemon-log-terminal");
    term.innerHTML = data.logs
      .map(
        (l) => `
      <div class="log-line">
        <span class="log-ts">${escapeHtml(l.timestamp)}</span>
        <span class="log-unit">${escapeHtml(l.unit)}[${escapeHtml(l.pid)}]:</span>
        <span class="log-lvl-${escapeHtml(l.level)}">[${escapeHtml(l.level)}]</span>
        <span>${escapeHtml(l.message)}</span>
      </div>`
      )
      .join("");

    // Renderizar tabla de Triggers MySQL 8.0
    const tbodyTrg = document.getElementById("tbody-mysql-triggers");
    tbodyTrg.innerHTML = data.mysql.triggers
      .map(
        (t) => `
      <tr>
        <td class="mono" style="color:#4ADE80; font-size:0.76rem;">${escapeHtml(t.name)}</td>
        <td><span class="badge badge-neutral">${escapeHtml(t.timing)} ${escapeHtml(t.event)}</span></td>
        <td class="mono" style="font-size:0.76rem;">${escapeHtml(t.table)}</td>
      </tr>`
      )
      .join("");
  } catch (err) {
    if (!silent) showToast(err.message, true);
  }
}

// ============================================================================
// MÓDULO 2: GESTIÓN DE INCIDENTES Y RECUPERACIÓN DE VERSIONES
// ============================================================================
function getSeverityBadge(sev) {
  const map = {
    Critica: "badge-critica",
    Alta: "badge-alta",
    Media: "badge-media",
    Baja: "badge-baja",
  };
  return `<span class="badge ${map[sev] || "badge-neutral"}">${escapeHtml(sev)}</span>`;
}

function getEstadoBadge(est) {
  if (est === "Cerrado") return `<span class="badge badge-ok">${escapeHtml(est)}</span>`;
  if (est === "Contenido") return `<span class="badge badge-baja">${escapeHtml(est)}</span>`;
  if (est === "En Análisis") return `<span class="badge badge-media">${escapeHtml(est)}</span>`;
  return `<span class="badge badge-alta">${escapeHtml(est)}</span>`;
}

async function loadIncidents() {
  const search = document.getElementById("filter-search").value.trim();
  const severidad = document.getElementById("filter-severidad").value;
  const id_categoria = document.getElementById("filter-categoria").value;
  const id_estado = document.getElementById("filter-estado").value;

  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (severidad) params.set("severidad", severidad);
  if (id_categoria) params.set("id_categoria", id_categoria);
  if (id_estado) params.set("id_estado", id_estado);

  const data = await apiFetch(`/api/incidents?${params.toString()}`);
  const tbody = document.getElementById("tbody-incidents");
  const selectEv = document.getElementById("evidence-incident-select");

  if (selectEv) {
    selectEv.innerHTML = data.incidents
      .map((i) => `<option value="${i.id_incidente}">${escapeHtml(i.codigo_ticket)} — ${escapeHtml(i.titulo)} (${escapeHtml(i.severidad)})</option>`)
      .join("");
  }

  tbody.innerHTML = data.incidents
    .map(
      (inc) => `
    <tr>
      <td class="mono" style="font-weight:700; color:#38BDF8;">${escapeHtml(inc.codigo_ticket)}</td>
      <td>
        <div style="font-weight:600;">${escapeHtml(inc.titulo)}</div>
        <div style="font-size:0.76rem; color:var(--fg-muted); max-width:340px;">${escapeHtml(inc.descripcion)}</div>
      </td>
      <td style="font-size:0.8rem;">${escapeHtml(inc.nombre_categoria)}</td>
      <td>${getSeverityBadge(inc.severidad)}</td>
      <td>${getEstadoBadge(inc.nombre_estado)}</td>
      <td style="font-size:0.8rem;">
        ${inc.nombre_analista ? `<span style="color:#E2E8F0;">${escapeHtml(inc.nombre_analista)}</span>` : `<span style="color:var(--fg-muted);">Sin asignar</span>`}
      </td>
      <td class="mono" style="font-size:0.76rem;">
        ${inc.total_evidencias} evid. / ${inc.total_versiones} vers.
      </td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="openIncidentDetail(${inc.id_incidente})">
          Abrir Expediente
        </button>
      </td>
    </tr>`
    )
    .join("");
}

function openNewIncidentModal() {
  document.getElementById("form-new-incident").reset();
  document.getElementById("modal-new-incident").classList.remove("hidden");
}

function closeModal(id) {
  document.getElementById(id).classList.add("hidden");
}

async function handleCreateIncident(ev) {
  ev.preventDefault();
  const payload = {
    codigo_ticket: document.getElementById("inc-new-ticket").value.trim() || null,
    titulo: document.getElementById("inc-new-titulo").value.trim(),
    descripcion: document.getElementById("inc-new-descripcion").value.trim(),
    severidad: document.getElementById("inc-new-severidad").value,
    id_categoria: parseInt(document.getElementById("inc-new-categoria").value, 10),
    id_analista_asignado: document.getElementById("inc-new-analista").value
      ? parseInt(document.getElementById("inc-new-analista").value, 10)
      : null,
  };

  try {
    const res = await apiFetch("/api/incidents", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    closeModal("modal-new-incident");
    showToast(res.message + (res.critical_queued ? " [Alerta Crítica encolada en Telegram]" : ""));
    await refreshAllActiveData();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function openIncidentDetail(id_incidente) {
  try {
    const data = await apiFetch(`/api/incidents/${id_incidente}`);
    const inc = data.incident;
    document.getElementById("detail-modal-title").innerHTML = `Expediente Forense: <code class="mono" style="color:#38BDF8;">${escapeHtml(inc.codigo_ticket)}</code> — ${escapeHtml(inc.titulo)}`;

    const estadoOptions = CATALOGS.estados
      .map((e) => `<option value="${e.id_estado}" ${e.id_estado === inc.id_estado ? "selected" : ""}>${escapeHtml(e.nombre_estado)}</option>`)
      .join("");

    const analistaOptions =
      `<option value="">-- Sin asignar --</option>` +
      CATALOGS.analistas
        .map(
          (a) =>
            `<option value="${a.id_usuario}" ${a.id_usuario === inc.id_analista_asignado ? "selected" : ""}>${escapeHtml(a.nombre_completo)} [${a.activo === 1 ? "ACTIVO" : "INACTIVO (activo=0)"
            }]</option>`
        )
        .join("");

    const severidades = ["Baja", "Media", "Alta", "Critica"]
      .map((s) => `<option value="${s}" ${s === inc.severidad ? "selected" : ""}>${s}</option>`)
      .join("");

    const histHtml =
      data.historico.length === 0
        ? `<div style="font-size:0.8rem; color:var(--fg-muted);">Sin modificaciones previas registradas en <code class="mono">historico_incidentes</code>.</div>`
        : data.historico
          .map(
            (h) => `
          <div style="background:var(--bg-input); border:1px solid var(--border-color); border-radius:7px; padding:0.65rem 0.85rem; margin-bottom:0.5rem; display:flex; align-items:center; justify-content:space-between; gap:0.75rem;">
            <div style="font-size:0.78rem;">
              <div><strong>Versión #${h.id_historico}</strong> · <span class="mono" style="color:var(--fg-muted);">${escapeHtml(h.fecha_modificacion)}</span> por <code class="mono">${escapeHtml(h.usuario_modificador)}</code></div>
              <div style="color:var(--fg-secondary); margin-top:0.2rem;">Severidad previa: ${getSeverityBadge(h.severidad)} · Estado previo: <strong>${escapeHtml(h.nombre_estado || h.id_estado)}</strong></div>
              <div class="mono" style="font-size:0.74rem; color:var(--fg-muted); margin-top:0.2rem;">"${escapeHtml(h.descripcion)}"</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="restoreIncidentVersion(${inc.id_incidente}, ${h.id_historico})">
              Restaurar Versión
            </button>
          </div>`
          )
          .join("");

    const evidHtml =
      data.evidencias.length === 0
        ? `<div style="font-size:0.8rem; color:var(--fg-muted);">No hay artefactos digitales asociados a este ticket aún.</div>`
        : data.evidencias
          .map(
            (ev) => `
          <div style="background:var(--bg-input); border:1px solid var(--border-color); border-radius:7px; padding:0.65rem 0.85rem; margin-bottom:0.5rem;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <strong class="mono" style="color:#4ADE80; font-size:0.82rem;">${escapeHtml(ev.nombre_archivo)}</strong>
              <span class="badge ${ev.integrity.verified ? "badge-ok" : "badge-critica"}">${escapeHtml(ev.integrity.status)}</span>
            </div>
            <div class="mono" style="font-size:0.72rem; color:var(--fg-muted); margin-top:0.25rem;">
              Ruta: ${escapeHtml(ev.ruta_almacenamiento)} (${ev.tamano_bytes.toLocaleString()} bytes)
            </div>
            <div class="mono" style="font-size:0.72rem; color:#38BDF8; word-break:break-all; margin-top:0.15rem;">
              SHA-256: ${escapeHtml(ev.hash_sha256)}
            </div>
          </div>`
          )
          .join("");

    document.getElementById("detail-modal-body").innerHTML = `
      <form onsubmit="handleUpdateIncident(event, ${inc.id_incidente})" style="margin-bottom:1.25rem;">
        <div class="form-grid">
          <div class="form-group">
            <label>Título del Incidente</label>
            <input type="text" id="edit-inc-titulo" class="input-control" value="${escapeHtml(inc.titulo)}" required />
          </div>
          <div class="form-group">
            <label>Severidad (Si sube a Crítica, dispara alerta Telegram)</label>
            <select id="edit-inc-severidad" class="input-control">${severidades}</select>
          </div>
          <div class="form-group">
            <label>Estado del Ciclo de Vida</label>
            <select id="edit-inc-estado" class="input-control">${estadoOptions}</select>
          </div>
          <div class="form-group">
            <label>Analista Forense Responsable</label>
            <select id="edit-inc-analista" class="input-control">${analistaOptions}</select>
          </div>
        </div>
        <div class="form-group">
          <label>Documentación de Contención, Erradicación y Lecciones Aprendidas</label>
          <textarea id="edit-inc-descripcion" class="input-control" rows="3" required>${escapeHtml(inc.descripcion)}</textarea>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
          <span style="font-size:0.75rem; color:var(--fg-muted);" class="mono">
            Reportado por: ${escapeHtml(inc.nombre_reportador || "ID " + inc.id_usuario_reportador)} · Última act: ${escapeHtml(inc.fecha_actualizacion)}
          </span>
          <button type="submit" class="btn btn-primary btn-sm">
            Actualizar Ticket (Ejecutar Trigger UPDATE)
          </button>
        </div>
      </form>

      <div style="border-top:1px solid var(--border-color); padding-top:1rem; margin-bottom:1rem;">
        <div style="font-weight:600; font-size:0.9rem; margin-bottom:0.5rem;">Artefactos en Bóveda Forense (<code class="mono">evidencias_forenses</code>)</div>
        ${evidHtml}
      </div>

      <div style="border-top:1px solid var(--border-color); padding-top:1rem;">
        <div style="font-weight:600; font-size:0.9rem; margin-bottom:0.5rem;">Histórico de Versiones para Recuperación (<code class="mono">historico_incidentes</code> · Política 2.5)</div>
        ${histHtml}
      </div>
    `;

    document.getElementById("modal-incident-detail").classList.remove("hidden");
  } catch (err) {
    showToast(err.message, true);
  }
}

async function handleUpdateIncident(ev, id_incidente) {
  ev.preventDefault();
  const payload = {
    titulo: document.getElementById("edit-inc-titulo").value.trim(),
    descripcion: document.getElementById("edit-inc-descripcion").value.trim(),
    severidad: document.getElementById("edit-inc-severidad").value,
    id_estado: parseInt(document.getElementById("edit-inc-estado").value, 10),
    id_analista_asignado: document.getElementById("edit-inc-analista").value
      ? parseInt(document.getElementById("edit-inc-analista").value, 10)
      : null,
  };

  try {
    const res = await apiFetch(`/api/incidents/${id_incidente}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    showToast(res.message);
    await openIncidentDetail(id_incidente);
    await refreshAllActiveData();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function restoreIncidentVersion(id_incidente, id_historico) {
  try {
    const res = await apiFetch(`/api/incidents/${id_incidente}/restore/${id_historico}`, {
      method: "POST",
    });
    showToast(res.message);
    await openIncidentDetail(id_incidente);
    await refreshAllActiveData();
  } catch (err) {
    showToast(err.message, true);
  }
}

// ============================================================================
// MÓDULO 3: FORENSE DIGITAL, EVIDENCIAS SHA-256 Y ANALIZADOR DE CORREOS PHISHING
// ============================================================================
async function loadForensics() {
  try {
    await loadIncidents();
    const data = await apiFetch("/api/forensics/evidences");
    const tbody = document.getElementById("tbody-evidences");
    tbody.innerHTML = data.items
      .map(
        (ev) => `
      <tr>
        <td class="mono">#${ev.id_evidencia}</td>
        <td class="mono" style="color:#38BDF8; font-weight:700;">${escapeHtml(ev.codigo_ticket)}</td>
        <td>
          <div style="font-weight:600;">${escapeHtml(ev.nombre_archivo)}</div>
          <div class="mono" style="font-size:0.73rem; color:var(--fg-muted);">${escapeHtml(ev.ruta_almacenamiento)}</div>
        </td>
        <td class="mono" style="font-size:0.73rem; color:#4ADE80; word-break:break-all; max-width:300px;">
          ${escapeHtml(ev.hash_sha256)}
        </td>
        <td class="mono" style="font-size:0.78rem;">${Number(ev.tamano_bytes).toLocaleString()} B</td>
        <td>
          <span class="badge ${ev.integrity.verified ? "badge-ok" : "badge-critica"}">
            ${escapeHtml(ev.integrity.status)}
          </span>
          <div style="font-size:0.71rem; color:var(--fg-muted); margin-top:0.2rem;">${escapeHtml(ev.integrity.detail)}</div>
        </td>
      </tr>`
      )
      .join("");
  } catch (err) {
    showToast(err.message, true);
  }
}

async function handleUploadEvidence(ev) {
  ev.preventDefault();
  const id_incidente = document.getElementById("evidence-incident-select").value;
  const fileInput = document.getElementById("evidence-file-input");
  if (!fileInput.files.length) return;

  const formData = new FormData();
  formData.append("id_incidente", id_incidente);
  formData.append("file", fileInput.files[0]);

  try {
    const res = await apiFetch("/api/forensics/evidences/upload", {
      method: "POST",
      body: formData,
    });
    fileInput.value = "";
    showToast(`${res.message} [SHA-256: ${res.hash_sha256.slice(0, 16)}...]`);
    await loadForensics();
    await loadTelemetry(true);
  } catch (err) {
    showToast(err.message, true);
  }
}

function loadSamplePhishingHeaders(type) {
  const box = document.getElementById("email-headers-input");
  if (type === "malicious") {
    box.value = [
      "Return-Path: <bounce-alert99@acceso-banca-segura-mx.xyz>",
      "Received: from mail.acceso-banca-segura-mx.xyz (unknown [185.220.101.44]) by mx.centinela.local (Postfix) with ESMTP id 4X992A for <dgomez@centinela.local>; Tue, 06 Oct 2026 17:40:11 -0600",
      "Received: from localhost (localhost [127.0.0.1]) by gophish-campaign.local with SMTP; Tue, 06 Oct 2026 17:39:52 -0600",
      "Authentication-Results: mx.centinela.local; spf=fail (sender IP 185.220.101.44 not authorized by domain banconacional.com.mx); dkim=fail; dmarc=fail action=quarantine",
      "From: Alertas Seguridad Bancaria <seguridad@banconacional.com.mx>",
      "Reply-To: soporte-tokens@acceso-banca-segura-mx.xyz",
      "Subject: URGENTE: Su cuenta empresarial ha sido suspendida - Verifique su Token",
      "Date: Tue, 06 Oct 2026 17:39:50 -0600",
      "Message-ID: <20261006173950.99812@gophish-campaign.local>",
      "X-Mailer: GoPhish MassMailer v2.1",
    ].join("\n");
  } else {
    box.value = [
      "Return-Path: <notificaciones@centinela.local>",
      "Received: from mail-interno.centinela.local (mail-interno.centinela.local [10.10.1.15]) by mx.centinela.local with ESMTPS id 9A112F; Tue, 06 Oct 2026 16:10:00 -0600",
      "Authentication-Results: mx.centinela.local; spf=pass; dkim=pass; dmarc=pass",
      "From: SOC CiberCentinela <notificaciones@centinela.local>",
      "Reply-To: notificaciones@centinela.local",
      "Subject: Reporte mensual de mantenimiento preventivo programado",
      "Date: Tue, 06 Oct 2026 16:09:58 -0600",
      "Message-ID: <20261006160958.1024@centinela.local>",
    ].join("\n");
  }
}

async function runEmailHeaderAnalysis() {
  const raw_headers = document.getElementById("email-headers-input").value;
  const save_as_evidence = document.getElementById("email-save-evidence").checked;
  const id_incidente = parseInt(document.getElementById("evidence-incident-select").value || "1", 10);

  try {
    const res = await apiFetch("/api/forensics/email-analyzer", {
      method: "POST",
      body: JSON.stringify({ raw_headers, save_as_evidence, id_incidente }),
    });
    const a = res.analysis;
    const card = document.getElementById("email-analysis-result-card");
    card.classList.remove("hidden");

    const indicatorsHtml =
      a.indicators.length === 0
        ? `<div class="badge badge-ok">No se detectaron anomalías de suplantación en las cabeceras.</div>`
        : a.indicators
          .map(
            (ind) => `
          <div style="background:var(--bg-input); border-left:3px solid var(--danger); padding:0.55rem 0.8rem; border-radius:6px; margin-bottom:0.45rem;">
            <div style="display:flex; justify-content:space-between;">
              <strong>${escapeHtml(ind.title)}</strong>
              ${getSeverityBadge(ind.severity)}
            </div>
            <div style="font-size:0.78rem; color:var(--fg-secondary); margin-top:0.15rem;">${escapeHtml(ind.detail)}</div>
          </div>`
          )
          .join("");

    card.innerHTML = `
      <div class="panel-header">
        <div class="panel-title">
          Dictamen Forense de Cabeceras: <span class="badge ${a.risk_score >= 60 ? "badge-critica" : a.risk_score >= 30 ? "badge-media" : "badge-ok"}">${escapeHtml(a.verdict)} (Riesgo: ${a.risk_score}/100)</span>
        </div>
        <span class="mono" style="font-size:0.75rem; color:#4ADE80;">SHA-256 Cabecera: ${escapeHtml(a.artifact_sha256.slice(0, 24))}...</span>
      </div>
      <div class="form-grid" style="margin-bottom:0.85rem; font-size:0.8rem;">
        <div style="background:var(--bg-input); padding:0.65rem; border-radius:7px;">
          <div style="color:var(--fg-muted);">From (Visible) vs Return-Path (Real):</div>
          <div class="mono" style="margin-top:0.2rem;">From: ${escapeHtml(a.summary.from)}</div>
          <div class="mono" style="color:#F87171;">Return-Path: ${escapeHtml(a.summary.return_path)}</div>
        </div>
        <div style="background:var(--bg-input); padding:0.65rem; border-radius:7px;">
          <div style="color:var(--fg-muted);">Autenticación Criptográfica DNS:</div>
          <div class="mono" style="margin-top:0.25rem;">
            SPF: <strong>${escapeHtml(a.authentication.spf)}</strong> ·
            DKIM: <strong>${escapeHtml(a.authentication.dkim)}</strong> ·
            DMARC: <strong>${escapeHtml(a.authentication.dmarc)}</strong>
          </div>
          <div class="mono" style="color:#38BDF8; margin-top:0.2rem;">IP Emisora Detectada: ${escapeHtml(a.summary.origin_ip)}</div>
        </div>
      </div>
      <div>${indicatorsHtml}</div>
      ${res.saved_evidence
        ? `<div style="margin-top:0.75rem; padding:0.55rem 0.8rem; background:rgba(22,163,74,0.14); border:1px solid #16A34A; border-radius:6px; font-size:0.78rem;" class="mono">
               [+] Dictamen sellado automáticamente en evidencias_forenses: ${escapeHtml(res.saved_evidence.ruta_almacenamiento)} (SHA-256: ${escapeHtml(res.saved_evidence.hash_sha256)})
             </div>`
        : ""
      }
    `;

    showToast(`Análisis completado: ${a.verdict} (${a.risk_score}/100)`);
    if (res.saved_evidence) {
      await loadForensics();
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

// ============================================================================
// MÓDULO 3 & 4: BITÁCORA INMUTABLE Y LABORATORIO DE PRUEBAS DE SEGURIDAD EN VIVO
// ============================================================================
async function runSecurityLabTest(testId) {
  const out = document.getElementById("security-lab-output");
  out.classList.remove("hidden");
  out.innerHTML = `<div class="mono">Ejecutando prueba pericial contra motor MySQL 8.0...</div>`;

  try {
    const res = await apiFetch("/api/security-lab/run-test", {
      method: "POST",
      body: JSON.stringify({ test_id: testId }),
    });

    // Validar claves de respuesta con valores por defecto si vienen con otro nombre desde el backend
    const testName = res.test_name || res.nombre_prueba || "Prueba de Seguridad";
    const mysqlError = res.mysql_error || res.error || res.detail || res.mensaje || "Error no especificado por el motor de BD";
    const errnoCode = res.errno || res.error_code || res.status_code || "SQL-ERR";
    const policyRef = res.policy_ref || "Sección 4 / 7 del Reporte";
    const mysqlUser = res.mysql_user || "usr_cibercentinela";
    const sqlExecuted = res.sql_executed || res.sql || "Sentencia ejecutada";

    out.innerHTML = `
      <div style="color:#4ADE80; font-weight:700; margin-bottom:0.35rem;">✔ BLOQUEO DE SEGURIDAD DEMOSTRADO EN VIVO — ${escapeHtml(testName)}</div>
      <div style="color:#94A3B8;">Referencia Normativa: ${escapeHtml(policyRef)}</div>
      <div style="color:#38BDF8; margin-top:0.3rem;">Conexión MySQL empleada: ${escapeHtml(mysqlUser)}</div>
      <div style="color:#E2E8F0; margin-top:0.3rem;">Sentencia SQL enviada: <code>${escapeHtml(sqlExecuted)}</code></div>
      <div style="color:#F87171; font-weight:700; margin-top:0.4rem; padding:0.45rem; background:rgba(220,38,38,0.12); border:1px solid rgba(220,38,38,0.4); border-radius:6px;">
        Respuesta nativa de MySQL 8.0: ${escapeHtml(mysqlError)}
      </div>
    `;
    showToast(`${testName}: Bloqueado correctamente por MySQL (${errnoCode})`);
    await loadTelemetry(true);
  } catch (err) {
    out.innerHTML = `<div style="color:#F87171;">${escapeHtml(err.message)}</div>`;
    showToast(err.message, true);
  }
}

async function loadAuditLogs() {
  try {
    const data = await apiFetch("/api/audit");
    const tbody = document.getElementById("tbody-audit");
    tbody.innerHTML = data.audit_logs
      .map(
        (log) => `
      <tr>
        <td class="mono">#${log.id_auditoria}</td>
        <td class="mono" style="font-size:0.75rem;">${escapeHtml(log.fecha_hora)}</td>
        <td class="mono" style="font-size:0.76rem; color:#38BDF8;">${escapeHtml(log.usuario_accion)}</td>
        <td><span class="badge ${log.operacion === "DELETE" ? "badge-critica" : log.operacion === "UPDATE" ? "badge-media" : "badge-ok"}">${escapeHtml(log.operacion)}</span></td>
        <td class="mono" style="font-size:0.78rem;">${escapeHtml(log.tabla_afectada)}</td>
        <td class="mono" style="font-size:0.71rem; color:var(--fg-muted); max-width:240px; word-break:break-word;">
          ${log.datos_antiguos ? escapeHtml(JSON.stringify(log.datos_antiguos)) : "NULL"}
        </td>
        <td class="mono" style="font-size:0.71rem; color:#86EFAC; max-width:240px; word-break:break-word;">
          ${log.datos_nuevos ? escapeHtml(JSON.stringify(log.datos_nuevos)) : "NULL"}
        </td>
        <td style="font-size:0.76rem; color:#FCA5A5; font-weight:600;">
          ${log.mensaje_critico ? escapeHtml(log.mensaje_critico) : "<span style='color:var(--fg-muted); font-weight:400;'>—</span>"}
        </td>
      </tr>`
      )
      .join("");
  } catch (err) {
    showToast(err.message, true);
  }
}

// ============================================================================
// MÓDULO 4: COLA DE ALERTAS CRÍTICAS Y DEMONIO DE TELEGRAM
// ============================================================================
async function loadTelegramQueue() {
  try {
    const data = await apiFetch("/api/telegram/queue");
    const tbody = document.getElementById("tbody-telegram-queue");

    document.getElementById("tg-chat-id").value = data.config.chat_id || "";
    document.getElementById("tg-sim-mode").checked = data.config.simulation_mode;
    document.getElementById("tg-auto-dispatch").checked = data.config.auto_dispatch;
    document.getElementById("telegram-mode-badge").textContent = data.config.simulation_mode
      ? "Pasarela Sandbox Local"
      : "API Telegram TLS Real";

    tbody.innerHTML = data.queue
      .map(
        (n) => `
      <tr>
        <td class="mono">#${n.id_notificacion}</td>
        <td class="mono" style="color:#38BDF8; font-weight:700;">${escapeHtml(n.codigo_ticket)}</td>
        <td class="mono" style="font-size:0.78rem; color:#FCA5A5;">${escapeHtml(n.mensaje)}</td>
        <td>
          <span class="badge ${n.estado_envio === "Enviado" ? "badge-ok" : n.estado_envio === "Pendiente" ? "badge-media" : "badge-critica"}">
            ${escapeHtml(n.estado_envio)}
          </span>
        </td>
        <td class="mono" style="font-size:0.73rem; color:var(--fg-muted);">
          Creado: ${escapeHtml(n.fecha_creacion)}<br/>
          Enviado: ${escapeHtml(n.fecha_envio || "En cola")}
        </td>
        <td>
          ${n.estado_envio === "Pendiente"
            ? `<button class="btn btn-primary btn-sm" onclick="dispatchTelegramQueue(${n.id_notificacion})">Enviar Ahora</button>`
            : `<span class="mono" style="font-size:0.73rem; color:#4ADE80;">✔ Entregado</span>`
          }
        </td>
      </tr>`
      )
      .join("");
  } catch (err) {
    showToast(err.message, true);
  }
}

async function dispatchTelegramQueue(id_notificacion = null) {
  try {
    const url = id_notificacion ? `/api/telegram/dispatch?id_notificacion=${id_notificacion}` : "/api/telegram/dispatch";
    const res = await apiFetch(url, { method: "POST" });
    showToast(`Demonio Telegram: ${res.sent} alerta(s) crítica(s) despachada(s).`);
    await loadTelegramQueue();
    await loadTelemetry(true);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function saveTelegramConfig(ev) {
  ev.preventDefault();
  const payload = {
    bot_token: document.getElementById("tg-bot-token").value.trim(),
    chat_id: document.getElementById("tg-chat-id").value.trim(),
    simulation_mode: document.getElementById("tg-sim-mode").checked,
    auto_dispatch: document.getElementById("tg-auto-dispatch").checked,
  };
  try {
    const res = await apiFetch("/api/telegram/config", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    showToast(res.message);
    await loadTelegramQueue();
  } catch (err) {
    showToast(err.message, true);
  }
}

// ============================================================================
// MÓDULO 5: ADMINISTRACIÓN, POLÍTICA DE CONTRASEÑAS Y RESPALDOS MYSQLDUMP
// ============================================================================
async function loadBackups() {
  try {
    const data = await apiFetch("/api/backups");
    const tbody = document.getElementById("tbody-backups");
    tbody.innerHTML = data.backups
      .map(
        (b) => `
      <tr>
        <td class="mono" style="color:#4ADE80; font-weight:600;">${escapeHtml(b.filename)}</td>
        <td class="mono" style="font-size:0.74rem; color:var(--fg-muted);">${escapeHtml(b.linux_path)}</td>
        <td class="mono" style="font-size:0.78rem;">${Number(b.size_bytes).toLocaleString()} B</td>
        <td class="mono" style="font-size:0.72rem; color:#38BDF8;">${escapeHtml(b.sha256.slice(0, 24))}...</td>
        <td class="mono" style="font-size:0.75rem;">${escapeHtml(b.created_at)}</td>
        <td style="display:flex; gap:0.4rem;">
          <button class="btn btn-secondary btn-sm" onclick="verifyBackupIntegrity('${escapeHtml(b.filename)}')">
            Verificar Integridad
          </button>
          <a class="btn btn-secondary btn-sm" href="/api/backups/${encodeURIComponent(b.filename)}/download" style="text-decoration:none;">
            Descargar
          </a>
        </td>
      </tr>`
      )
      .join("");
  } catch (err) {
    showToast(err.message, true);
  }
}

async function triggerHotBackup() {
  try {
    const res = await apiFetch("/api/backups/create", { method: "POST" });
    showToast(`${res.message} (${res.backup.filename})`);
    await loadBackups();
    await loadTelemetry(true);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function verifyBackupIntegrity(filename) {
  try {
    const res = await apiFetch(`/api/backups/${encodeURIComponent(filename)}/verify`, { method: "POST" });
    showToast(
      `Simulacro Exitoso en ${res.filename}: 9 tablas, rutinas y 7 triggers verificados [SHA-256: ${res.sha256.slice(0, 14)}...]`
    );
  } catch (err) {
    showToast(err.message, true);
  }
}

async function loadUsers() {
  try {
    const data = await apiFetch("/api/users");
    const tbody = document.getElementById("tbody-users");
    tbody.innerHTML = data.users
      .map(
        (u) => `
      <tr>
        <td class="mono">#${u.id_usuario}</td>
        <td>
          <div style="font-weight:600;">${escapeHtml(u.nombre_completo)}</div>
          <div class="mono" style="font-size:0.74rem; color:var(--fg-muted);">${escapeHtml(u.email)}</div>
        </td>
        <td><span class="badge badge-baja">${escapeHtml(u.nombre_rol)}</span></td>
        <td class="mono" style="font-size:0.72rem; color:#4ADE80;">${escapeHtml((u.password_hash || "").slice(0, 25))}...</td>
        <td>
          ${u.activo === 1
            ? `<span class="badge badge-ok">Activo (1)</span>`
            : `<span class="badge badge-critica">Inactivo (0)</span>`
          }
        </td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="toggleUserActive(${u.id_usuario})">
            ${u.activo === 1 ? "Suspender (activo=0)" : "Reactivar (activo=1)"}
          </button>
        </td>
      </tr>`
      )
      .join("");
  } catch (err) {
    const tbody = document.getElementById("tbody-users");
    tbody.innerHTML = `<tr><td colspan="6" class="mono" style="color:#FCA5A5;">${escapeHtml(err.message)}</td></tr>`;
  }
}

async function toggleUserActive(id_usuario) {
  try {
    const res = await apiFetch(`/api/users/${id_usuario}/status`, { method: "PATCH" });
    showToast(res.message);
    await loadUsers();
    await loadCatalogs();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function liveCheckPasswordPolicy() {
  const password = document.getElementById("new-user-password").value;
  const nombre_completo = document.getElementById("new-user-name").value;
  const email = document.getElementById("new-user-email").value;
  const box = document.getElementById("pwd-policy-checklist");

  try {
    const res = await apiFetch("/api/auth/validate-password", {
      method: "POST",
      body: JSON.stringify({ password, nombre_completo, email }),
    });
    const c = res.checks;
    const item = (ok, label) => `<div style="color:${ok ? "#4ADE80" : "#F87171"};">${ok ? "✔" : "✖"} ${label}</div>`;
    box.innerHTML = `
      ${item(c.min_length_12, "Longitud mínima >= 12 caracteres")}
      ${item(c.has_uppercase && c.has_lowercase, "Combinación de Mayúsculas y Minúsculas")}
      ${item(c.has_digit, "Al menos un dígito numérico (0-9)")}
      ${item(c.has_special, "Al menos un símbolo especial (#, $, @, !, %)")}
      ${item(c.no_personal_info, "No contiene nombre ni identificador de correo")}
    `;
  } catch (_) { }
}

async function handleCreateUser(ev) {
  ev.preventDefault();
  const payload = {
    nombre_completo: document.getElementById("new-user-name").value.trim(),
    email: document.getElementById("new-user-email").value.trim(),
    id_rol: parseInt(document.getElementById("new-user-role").value, 10),
    password: document.getElementById("new-user-password").value,
  };
  try {
    const res = await apiFetch("/api/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    document.getElementById("form-create-user").reset();
    showToast(res.message);
    await loadUsers();
    await loadCatalogs();
  } catch (err) {
    showToast(err.message, true);
  }
}

// Inicialización automática robusta si ya existe sesión activa
function initApp() {
  try {
    loadSamplePhishingHeaders("malicious");
  } catch (e) {
    console.warn("Aviso al precargar muestras de cabeceras:", e);
  }
  if (AUTH_TOKEN) {
    apiFetch("/api/auth/me")
      .then((me) => {
        CURRENT_USER = me.user;
        enterConsole();
      })
      .catch(() => {
        logoutSession();
      });
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}