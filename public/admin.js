'use strict';

const LOGIN_FORM_ID = 'login-form';
const CONTENT_FORM_ID = 'admin-content-form';
const MAP_MIN_ZOOM = 1;
const MAP_MAX_ZOOM = 20;

let csrfTokenCache = null;
let adminMap = null;
let adminMarker = null;
let subtitleQuill = null;

async function getCsrfToken(forceRefresh = false) {
  if (!forceRefresh && csrfTokenCache) {
    return csrfTokenCache;
  }

  const response = await fetch('/api/csrf-token', {
    credentials: 'include',
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error('No se pudo obtener CSRF token');
  }

  const data = await response.json();
  csrfTokenCache = data.csrfToken;
  return csrfTokenCache;
}

async function requestJson(url, options = {}, requiresCsrf = false) {
  const headers = {
    Accept: 'application/json',
    ...(options.headers || {}),
  };

  if (requiresCsrf) {
    headers['CSRF-Token'] = await getCsrfToken();
  }

  const response = await fetch(url, {
    credentials: 'include',
    ...options,
    headers,
  });

  const isJson = response.headers.get('content-type')?.includes('application/json');
  const body = isJson ? await response.json() : null;

  return { response, body };
}

function setStatus(el, message, type = '') {
  if (!el) {
    return;
  }

  el.textContent = message;
  el.classList.remove('status--ok', 'status--error');

  if (type === 'ok') {
    el.classList.add('status--ok');
  }

  if (type === 'error') {
    el.classList.add('status--error');
  }
}

function parseStops(text) {
  return text
    .split('\n')
    .map((stop) => stop.trim())
    .filter(Boolean);
}

function formatStops(items) {
  if (!Array.isArray(items)) {
    return '';
  }

  return items.join('\n');
}

function looksLikeEmail(value) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
}

function parseRecipientList(text) {
  const raw = String(text || '');
  const parts = raw
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);

  const unique = [];
  const seen = new Set();

  parts.forEach((email) => {
    const lowered = email.toLowerCase();
    if (seen.has(lowered)) {
      return;
    }

    seen.add(lowered);
    unique.push(email);
  });

  return unique;
}

function formatRecipientList(items) {
  if (!Array.isArray(items)) {
    return '';
  }

  return items.join('\n');
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function parseMapCoordinates(form) {
  const lat = Number(form.elements.hipica_map_lat.value);
  const lng = Number(form.elements.hipica_map_lng.value);
  const zoom = Number(form.elements.hipica_map_zoom.value);
  const label = String(form.elements.hipica_map_label.value || '').trim();
  const rawOpenUrl = String(form.elements.hipica_map_openUrl.value || '').trim();

  if (!Number.isFinite(lat) || lat < -90 || lat > 90) {
    throw new Error('Latitud inválida. Debe estar entre -90 y 90.');
  }

  if (!Number.isFinite(lng) || lng < -180 || lng > 180) {
    throw new Error('Longitud inválida. Debe estar entre -180 y 180.');
  }

  if (!Number.isInteger(zoom) || zoom < MAP_MIN_ZOOM || zoom > MAP_MAX_ZOOM) {
    throw new Error(`Zoom inválido. Debe ser entero entre ${MAP_MIN_ZOOM} y ${MAP_MAX_ZOOM}.`);
  }

  if (!label || label.length > 120) {
    throw new Error('Etiqueta de mapa inválida (1-120 caracteres).');
  }

  let openUrl = '';
  if (rawOpenUrl) {
    let parsed;
    try {
      parsed = new URL(rawOpenUrl);
    } catch {
      throw new Error('openUrl debe ser una URL https válida o estar vacío.');
    }

    if (parsed.protocol !== 'https:') {
      throw new Error('openUrl debe usar https.');
    }

    openUrl = parsed.toString();
  }

  return { lat, lng, zoom, label, openUrl };
}

function getDraftMapCoordinates(form) {
  const lat = Number(form.elements.hipica_map_lat.value);
  const lng = Number(form.elements.hipica_map_lng.value);
  const zoomRaw = Number(form.elements.hipica_map_zoom.value);
  const label = String(form.elements.hipica_map_label.value || '').trim() || 'Ubicación';

  if (!Number.isFinite(lat) || lat < -90 || lat > 90) {
    return null;
  }

  if (!Number.isFinite(lng) || lng < -180 || lng > 180) {
    return null;
  }

  const zoom = Number.isInteger(zoomRaw) ? clamp(zoomRaw, MAP_MIN_ZOOM, MAP_MAX_ZOOM) : 14;
  return { lat, lng, zoom, label };
}

function updateMapFields(form, lat, lng) {
  form.elements.hipica_map_lat.value = lat.toFixed(6);
  form.elements.hipica_map_lng.value = lng.toFixed(6);
}

function setMapStatus(message, type = '') {
  const mapStatusEl = document.getElementById('map-status');
  if (!mapStatusEl) {
    return;
  }

  setStatus(mapStatusEl, message, type);
}

function syncMarkerPopup(label) {
  if (!adminMarker) {
    return;
  }

  const popupNode = document.createElement('span');
  popupNode.textContent = label;
  adminMarker.bindPopup(popupNode);
}

function movePreviewMarker(form, { recenter = false } = {}) {
  if (!adminMap || !adminMarker) {
    return;
  }

  const draft = getDraftMapCoordinates(form);
  if (!draft) {
    return;
  }

  adminMarker.setLatLng([draft.lat, draft.lng]);
  syncMarkerPopup(draft.label);

  if (recenter) {
    adminMap.setView([draft.lat, draft.lng], draft.zoom);
  }
}

function initAdminMapPreview(form) {
  const mapElement = document.getElementById('admin-map');
  const recenterButton = document.getElementById('map-reset-view');

  if (!mapElement) {
    return;
  }

  if (!window.L || typeof window.L.map !== 'function') {
    setMapStatus('No se pudo cargar Leaflet. El mapa no está disponible.', 'error');
    return;
  }

  const draft = getDraftMapCoordinates(form);
  if (!draft) {
    setMapStatus('Coordenadas iniciales inválidas para previsualizar el mapa.', 'error');
    return;
  }

  adminMap?.remove();
  adminMap = window.L.map(mapElement, {
    zoomControl: true,
    scrollWheelZoom: false,
  }).setView([draft.lat, draft.lng], draft.zoom);

  window.L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: MAP_MAX_ZOOM,
    attribution: '&copy; OpenStreetMap contributors',
  }).addTo(adminMap);

  adminMarker = window.L.marker([draft.lat, draft.lng], {
    draggable: true,
    autoPan: true,
  }).addTo(adminMap);

  syncMarkerPopup(draft.label);
  adminMarker.openPopup();

  adminMarker.on('dragend', () => {
    const position = adminMarker.getLatLng();
    updateMapFields(form, position.lat, position.lng);
    syncMarkerPopup(String(form.elements.hipica_map_label.value || 'Ubicación').trim() || 'Ubicación');
  });

  adminMap.on('click', (event) => {
    const { lat, lng } = event.latlng;
    adminMarker.setLatLng([lat, lng]);
    updateMapFields(form, lat, lng);
  });

  ['hipica_map_lat', 'hipica_map_lng', 'hipica_map_zoom', 'hipica_map_label'].forEach((fieldName) => {
    const field = form.elements[fieldName];
    field?.addEventListener('change', () => movePreviewMarker(form, { recenter: true }));
    field?.addEventListener('input', () => movePreviewMarker(form, { recenter: false }));
  });

  recenterButton?.addEventListener('click', () => {
    movePreviewMarker(form, { recenter: true });
  });

  setMapStatus('Mapa listo. Puedes arrastrar el marcador o hacer clic para moverlo.', 'ok');

  window.requestAnimationFrame(() => {
    adminMap?.invalidateSize();
  });
}

// ── Editor dinámico de eventos del día ───────────────────────

function createDiaItemRow(item = {}) {
  const row = document.createElement('div');
  row.className = 'dia-item-row';

  row.innerHTML = `
    <label>Hora<input type="text" class="dia-item-time" placeholder="17:00" value="${escapeAttr(item.time || '')}" maxlength="20" /></label>
    <label>Evento<input type="text" class="dia-item-title" placeholder="Ceremonia" value="${escapeAttr(item.title || '')}" maxlength="80" /></label>
    <label>Descripción<input type="text" class="dia-item-desc" placeholder="Jardín principal" value="${escapeAttr(item.desc || '')}" maxlength="180" /></label>
    <button type="button" class="dia-item-remove" title="Eliminar evento">✕</button>
  `;

  row.querySelector('.dia-item-remove').addEventListener('click', () => {
    row.remove();
  });

  return row;
}

function escapeAttr(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function initDiaItemsEditor(items) {
  const editor = document.getElementById('dia-items-editor');
  const addButton = document.getElementById('dia-add-item');

  if (!editor || !addButton) {
    return;
  }

  editor.innerHTML = '';

  if (Array.isArray(items)) {
    items.forEach((item) => {
      editor.appendChild(createDiaItemRow(item));
    });
  }

  addButton.addEventListener('click', () => {
    editor.appendChild(createDiaItemRow());
  });
}

function collectDiaItems() {
  const editor = document.getElementById('dia-items-editor');
  if (!editor) {
    return [];
  }

  const rows = editor.querySelectorAll('.dia-item-row');
  const items = [];

  rows.forEach((row) => {
    const time = row.querySelector('.dia-item-time')?.value.trim() || '';
    const title = row.querySelector('.dia-item-title')?.value.trim() || '';
    const desc = row.querySelector('.dia-item-desc')?.value.trim() || '';

    if (!time && !title && !desc) {
      return;
    }

    items.push({ time, title, desc });
  });

  return items;
}

// ── Visor de confirmaciones RSVP ────────────────────────────

function formatDate(isoString) {
  if (!isoString) {
    return '-';
  }

  try {
    return new Date(isoString).toLocaleString('es-ES', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return isoString;
  }
}

function renderRsvpList(submissions) {
  const container = document.getElementById('rsvp-list');
  if (!container) {
    return;
  }

  if (!submissions.length) {
    container.innerHTML = '<p class="muted">No hay confirmaciones recibidas todavía.</p>';
    return;
  }

  const attending = submissions.filter((s) => s.rsvp?.attending === 'yes').length;
  const notAttending = submissions.filter((s) => s.rsvp?.attending === 'no').length;
  const totalGuests = submissions
    .filter((s) => s.rsvp?.attending === 'yes')
    .reduce((sum, s) => sum + (s.rsvp?.guests || 0), 0);

  const summary = document.createElement('div');
  summary.style.cssText = 'display:flex;gap:1.5rem;flex-wrap:wrap;margin-bottom:1rem;';
  summary.innerHTML = `
    <span><strong>${submissions.length}</strong> <span class="muted">respuestas</span></span>
    <span><strong style="color:#16a34a">${attending}</strong> <span class="muted">asisten</span></span>
    <span><strong style="color:#b91c1c">${notAttending}</strong> <span class="muted">no asisten</span></span>
    <span><strong>${totalGuests}</strong> <span class="muted">personas confirmadas</span></span>
  `;

  const table = document.createElement('table');
  table.className = 'rsvp-table';
  table.innerHTML = `
    <thead>
      <tr>
        <th>Fecha</th>
        <th>Nombre</th>
        <th>Asiste</th>
        <th>La Pataleta</th>
        <th>Personas</th>
        <th>Contacto</th>
        <th>Bus</th>
        <th>Alergias / Comentarios</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;

  const tbody = table.querySelector('tbody');

  submissions.forEach((entry) => {
    const rsvp = entry.rsvp || {};
    const tr = document.createElement('tr');

    const busInfo = rsvp.bus?.needsBus
      ? `Sí · ${rsvp.bus.outboundStop || '-'} → ${rsvp.bus.returnStop || '-'}`
      : 'No';

    const pataletaLabel = rsvp.pataleta === 'yes' ? 'Sí' : rsvp.pataleta === 'no' ? 'No' : '-';

    const extras = [
      rsvp.allergies ? `Alergias: ${rsvp.allergies}` : '',
      rsvp.comments ? `Comentarios: ${rsvp.comments}` : '',
    ]
      .filter(Boolean)
      .join(' / ') || '-';

    tr.innerHTML = `
      <td>${formatDate(entry.timestamp)}</td>
      <td><strong>${escapeHtmlContent(rsvp.name || '-')}</strong></td>
      <td><span class="rsvp-badge rsvp-badge--${rsvp.attending === 'yes' ? 'yes' : 'no'}">${rsvp.attending === 'yes' ? 'Sí' : 'No'}</span></td>
      <td>${escapeHtmlContent(pataletaLabel)}</td>
      <td>${rsvp.guests || '-'}</td>
      <td>${escapeHtmlContent(rsvp.contact || '-')}</td>
      <td>${escapeHtmlContent(busInfo)}</td>
      <td class="muted">${escapeHtmlContent(extras)}</td>
    `;

    tbody.appendChild(tr);
  });

  container.innerHTML = '';
  container.appendChild(summary);
  container.appendChild(table);
}

function escapeHtmlContent(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function loadRsvpSubmissions() {
  const statusEl = document.getElementById('rsvp-status');
  const listEl = document.getElementById('rsvp-list');

  if (statusEl) {
    setStatus(statusEl, 'Cargando confirmaciones...', '');
  }

  if (listEl) {
    listEl.innerHTML = '';
  }

  try {
    const { response, body } = await requestJson('/api/admin/rsvp');

    if (!response.ok || !body) {
      setStatus(statusEl, 'No se pudieron cargar las confirmaciones.', 'error');
      return;
    }

    setStatus(statusEl, '', '');
    renderRsvpList(body.submissions || []);
  } catch {
    setStatus(statusEl, 'No se pudieron cargar las confirmaciones.', 'error');
  }
}

// ── Rellenar el formulario ───────────────────────────────────

function fillAdminForm(form, content) {
  form.elements.historia_heroOverline.value = content.historia.heroOverline;
  form.elements.historia_names.value = content.historia.names;
  if (subtitleQuill) {
    subtitleQuill.clipboard.dangerouslyPasteHTML(content.historia.subtitle || '');
  }
  form.elements.historia_title.value = content.historia.title || '';
  form.elements.historia_chipDate.value = content.historia.chipDate || '';
  form.elements.historia_chipVenue.value = content.historia.chipVenue || '';
  form.elements.historia_chipTime.value = content.historia.chipTime || '';
  form.elements.historia_heroCardSummary.value = content.historia.heroCardSummary || '';
  form.elements.historia_dresscode.value = content.historia.dresscode || '';
  form.elements.historia_headerDate.value = content.historia.headerDate || '';

  form.elements.dia_title.value = content.dia.title;
  initDiaItemsEditor(content.dia.items);

  form.elements.hipica_title.value = content.hipica.title;
  form.elements.hipica_locationTitle.value = content.hipica.locationTitle;
  form.elements.hipica_howToArrive.value = content.hipica.howToArrive;
  form.elements.hipica_parking.value = content.hipica.parking;
  form.elements.hipica_alojamientoTitle.value = content.hipica.alojamientoTitle || '';
  form.elements.hipica_alojamiento.value = content.hipica.alojamiento || '';
  form.elements.hipica_map_lat.value = content.hipica.map.lat;
  form.elements.hipica_map_lng.value = content.hipica.map.lng;
  form.elements.hipica_map_zoom.value = content.hipica.map.zoom;
  form.elements.hipica_map_label.value = content.hipica.map.label;
  form.elements.hipica_map_openUrl.value = content.hipica.map.openUrl;

  form.elements.asistencia_title.value = content.asistencia.title;
  form.elements.asistencia_rsvpNote.value = content.asistencia.rsvpNote;

  const notifications = content.admin?.notifications || {};
  form.elements.admin_notifications_rsvpEmailEnabled.checked = Boolean(notifications.rsvpEmailEnabled);
  form.elements.admin_notifications_rsvpRecipients.value = formatRecipientList(notifications.rsvpRecipients);
  form.elements.admin_notifications_subjectPrefix.value = String(notifications.subjectPrefix || '');
  form.elements.admin_notifications_fromName.value = String(notifications.fromName || '');
  form.elements.admin_notifications_replyToGuest.checked = Boolean(notifications.replyToGuest);

  form.elements.buses_enabled.checked = content.buses.enabled;
  form.elements.buses_stopsIda.value = formatStops(content.buses.stopsIda);
  form.elements.buses_stopsVuelta.value = formatStops(content.buses.stopsVuelta);

  form.elements.regalo_enabled.checked = content.regalo.enabled;
  form.elements.regalo_title.value = content.regalo.title;
  form.elements.regalo_message.value = content.regalo.message;
  form.elements.regalo_iban.value = content.regalo.iban;
  form.elements.regalo_bizum.value = content.regalo.bizum;

  form.elements.footer_deadlineText.value = content.footer.deadlineText;
  form.elements.footer_overline.value = content.footer.overline || '';
  form.elements.footer_title.value = content.footer.title || '';
}

// ── Recoger el payload del formulario ───────────────────────

function collectAdminFormPayload(form) {
  let mapData;

  try {
    mapData = parseMapCoordinates(form);
  } catch (error) {
    throw new Error(error.message);
  }

  const dayItems = collectDiaItems();
  if (!dayItems.length) {
    throw new Error('Añade al menos un evento al programa del día.');
  }

  const recipients = parseRecipientList(form.elements.admin_notifications_rsvpRecipients.value);
  if (recipients.length > 10) {
    throw new Error('Demasiados destinatarios (máximo 10).');
  }

  const invalidEmail = recipients.find((email) => !looksLikeEmail(email));
  if (invalidEmail) {
    throw new Error(`Email inválido en destinatarios: ${invalidEmail}`);
  }

  return {
    historia: {
      heroOverline: form.elements.historia_heroOverline.value,
      names: form.elements.historia_names.value,
      subtitle: subtitleQuill ? subtitleQuill.root.innerHTML : '',
      title: form.elements.historia_title.value,
      chipDate: form.elements.historia_chipDate.value,
      chipVenue: form.elements.historia_chipVenue.value,
      chipTime: form.elements.historia_chipTime.value,
      heroCardSummary: form.elements.historia_heroCardSummary.value,
      dresscode: form.elements.historia_dresscode.value,
      headerDate: form.elements.historia_headerDate.value,
    },
    dia: {
      title: form.elements.dia_title.value,
      items: dayItems,
    },
    hipica: {
      title: form.elements.hipica_title.value,
      locationTitle: form.elements.hipica_locationTitle.value,
      howToArrive: form.elements.hipica_howToArrive.value,
      parking: form.elements.hipica_parking.value,
      alojamientoTitle: form.elements.hipica_alojamientoTitle.value,
      alojamiento: form.elements.hipica_alojamiento.value,
      map: mapData,
    },
    asistencia: {
      title: form.elements.asistencia_title.value,
      rsvpNote: form.elements.asistencia_rsvpNote.value,
    },
    admin: {
      notifications: {
        rsvpEmailEnabled: form.elements.admin_notifications_rsvpEmailEnabled.checked,
        rsvpRecipients: recipients,
        subjectPrefix: form.elements.admin_notifications_subjectPrefix.value,
        fromName: form.elements.admin_notifications_fromName.value,
        replyToGuest: form.elements.admin_notifications_replyToGuest.checked,
      },
    },
    buses: {
      enabled: form.elements.buses_enabled.checked,
      stopsIda: parseStops(form.elements.buses_stopsIda.value),
      stopsVuelta: parseStops(form.elements.buses_stopsVuelta.value),
    },
    regalo: {
      enabled: form.elements.regalo_enabled.checked,
      title: form.elements.regalo_title.value,
      message: form.elements.regalo_message.value,
      iban: form.elements.regalo_iban.value,
      bizum: form.elements.regalo_bizum.value,
    },
    footer: {
      deadlineText: form.elements.footer_deadlineText.value,
      overline: form.elements.footer_overline.value,
      title: form.elements.footer_title.value,
    },
  };
}

// ── Página de login ──────────────────────────────────────────

async function initLoginPage() {
  const loginForm = document.getElementById(LOGIN_FORM_ID);
  if (!loginForm) {
    return;
  }

  const statusEl = document.getElementById('login-status');

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    setStatus(statusEl, 'Validando...', '');

    const formData = new FormData(loginForm);
    const user = String(formData.get('user') || '').trim();
    const password = String(formData.get('password') || '');

    if (!user || !password) {
      setStatus(statusEl, 'Completa usuario y contraseña.', 'error');
      return;
    }

    try {
      const { response, body } = await requestJson(
        '/login',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ user, password }),
        },
        true
      );

      if (!response.ok || !body?.ok) {
        setStatus(statusEl, 'Credenciales inválidas.', 'error');
        csrfTokenCache = null;
        return;
      }

      setStatus(statusEl, 'Acceso concedido. Redirigiendo...', 'ok');
      window.location.assign('/admin');
    } catch {
      setStatus(statusEl, 'No se pudo iniciar sesión.', 'error');
      csrfTokenCache = null;
    }
  });
}

// ── Página de administración ────────────────────────────────

async function initAdminPage() {
  const form = document.getElementById(CONTENT_FORM_ID);
  if (!form) {
    return;
  }

  // Inicializar editor de texto enriquecido Quill para el subtitle
  if (typeof Quill !== 'undefined' && document.getElementById('subtitle-editor')) {
    const AlignStyle = Quill.import('attributors/style/align');
    Quill.register(AlignStyle, true);

    subtitleQuill = new Quill('#subtitle-editor', {
      theme: 'snow',
      modules: {
        toolbar: [
          ['bold', 'italic', 'underline'],
          [{ color: [] }],
          [{ align: [] }],
          ['clean'],
        ],
      },
    });
  }

  const statusEl = document.getElementById('admin-status');
  const logoutButton = document.getElementById('logout-button');
  const viewRsvpButton = document.getElementById('view-rsvp-button');
  const closeRsvpButton = document.getElementById('close-rsvp-button');
  const rsvpPanel = document.getElementById('rsvp-panel');

  // Cargar contenido
  try {
    const { response, body } = await requestJson('/api/admin/content');

    if (!response.ok || !body) {
      setStatus(statusEl, 'No se pudo cargar el contenido.', 'error');
      return;
    }

    fillAdminForm(form, body);
    initAdminMapPreview(form);
    setStatus(statusEl, 'Contenido cargado.', 'ok');
  } catch {
    setStatus(statusEl, 'No se pudo cargar el contenido.', 'error');
  }

  // Guardar contenido
  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    let payload;
    try {
      payload = collectAdminFormPayload(form);
    } catch (error) {
      setStatus(statusEl, error.message, 'error');
      return;
    }

    setStatus(statusEl, 'Guardando cambios...', '');

    try {
      const { response, body } = await requestJson(
        '/api/content',
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        },
        true
      );

      if (!response.ok || !body?.ok) {
        setStatus(statusEl, 'Error al guardar cambios.', 'error');
        csrfTokenCache = null;
        return;
      }

      setStatus(statusEl, 'Guardado OK', 'ok');
    } catch {
      setStatus(statusEl, 'Error al guardar cambios.', 'error');
      csrfTokenCache = null;
    }
  });

  // Panel RSVPs
  viewRsvpButton?.addEventListener('click', () => {
    if (!rsvpPanel) {
      return;
    }

    rsvpPanel.hidden = false;
    viewRsvpButton.hidden = true;
    loadRsvpSubmissions();
  });

  closeRsvpButton?.addEventListener('click', () => {
    if (!rsvpPanel) {
      return;
    }

    rsvpPanel.hidden = true;
    viewRsvpButton.hidden = false;
  });

  // Logout
  logoutButton?.addEventListener('click', async () => {
    try {
      await requestJson('/logout', { method: 'POST' }, true);
    } catch {
      // Intencionalmente ignorado para garantizar salida de UI.
    }

    csrfTokenCache = null;
    window.location.assign('/login');
  });
}

initLoginPage();
initAdminPage();
