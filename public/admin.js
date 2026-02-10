const LOGIN_FORM_ID = 'login-form';
const CONTENT_FORM_ID = 'admin-content-form';
const MAP_MIN_ZOOM = 1;
const MAP_MAX_ZOOM = 20;

let csrfTokenCache = null;
let adminMap = null;
let adminMarker = null;

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

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function parseMapCoordinates(form) {
  const lat = Number(form.elements.logistica_map_lat.value);
  const lng = Number(form.elements.logistica_map_lng.value);
  const zoom = Number(form.elements.logistica_map_zoom.value);
  const label = String(form.elements.logistica_map_label.value || '').trim();
  const rawOpenUrl = String(form.elements.logistica_map_openUrl.value || '').trim();

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
  const lat = Number(form.elements.logistica_map_lat.value);
  const lng = Number(form.elements.logistica_map_lng.value);
  const zoomRaw = Number(form.elements.logistica_map_zoom.value);
  const label = String(form.elements.logistica_map_label.value || '').trim() || 'Ubicación';

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
  form.elements.logistica_map_lat.value = lat.toFixed(6);
  form.elements.logistica_map_lng.value = lng.toFixed(6);
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
    syncMarkerPopup(String(form.elements.logistica_map_label.value || 'Ubicación').trim() || 'Ubicación');
  });

  adminMap.on('click', (event) => {
    const { lat, lng } = event.latlng;
    adminMarker.setLatLng([lat, lng]);
    updateMapFields(form, lat, lng);
  });

  ['logistica_map_lat', 'logistica_map_lng', 'logistica_map_zoom', 'logistica_map_label'].forEach((fieldName) => {
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

function fillAdminForm(form, content) {
  form.elements.presentacion_heroOverline.value = content.presentacion.heroOverline;
  form.elements.presentacion_names.value = content.presentacion.names;
  form.elements.presentacion_subtitle.value = content.presentacion.subtitle;

  form.elements.dia_title.value = content.dia.title;
  form.elements.dia_items.value = JSON.stringify(content.dia.items, null, 2);

  form.elements.logistica_title.value = content.logistica.title;
  form.elements.logistica_locationTitle.value = content.logistica.locationTitle;
  form.elements.logistica_howToArrive.value = content.logistica.howToArrive;
  form.elements.logistica_parking.value = content.logistica.parking;
  form.elements.logistica_map_lat.value = content.logistica.map.lat;
  form.elements.logistica_map_lng.value = content.logistica.map.lng;
  form.elements.logistica_map_zoom.value = content.logistica.map.zoom;
  form.elements.logistica_map_label.value = content.logistica.map.label;
  form.elements.logistica_map_openUrl.value = content.logistica.map.openUrl;

  form.elements.asistencia_title.value = content.asistencia.title;
  form.elements.asistencia_rsvpNote.value = content.asistencia.rsvpNote;

  form.elements.buses_enabled.checked = content.buses.enabled;
  form.elements.buses_stopsIda.value = formatStops(content.buses.stopsIda);
  form.elements.buses_stopsVuelta.value = formatStops(content.buses.stopsVuelta);

  form.elements.regalo_enabled.checked = content.regalo.enabled;
  form.elements.regalo_title.value = content.regalo.title;
  form.elements.regalo_message.value = content.regalo.message;
  form.elements.regalo_iban.value = content.regalo.iban;
  form.elements.regalo_bizum.value = content.regalo.bizum;

  form.elements.footer_deadlineText.value = content.footer.deadlineText;
}

function collectAdminFormPayload(form) {
  let dayItems;
  let mapData;

  try {
    dayItems = JSON.parse(form.elements.dia_items.value);
  } catch {
    throw new Error('El campo dia.items[] debe ser JSON válido.');
  }

  try {
    mapData = parseMapCoordinates(form);
  } catch (error) {
    throw new Error(error.message);
  }

  return {
    presentacion: {
      heroOverline: form.elements.presentacion_heroOverline.value,
      names: form.elements.presentacion_names.value,
      subtitle: form.elements.presentacion_subtitle.value,
    },
    dia: {
      title: form.elements.dia_title.value,
      items: dayItems,
    },
    logistica: {
      title: form.elements.logistica_title.value,
      locationTitle: form.elements.logistica_locationTitle.value,
      howToArrive: form.elements.logistica_howToArrive.value,
      parking: form.elements.logistica_parking.value,
      map: mapData,
    },
    asistencia: {
      title: form.elements.asistencia_title.value,
      rsvpNote: form.elements.asistencia_rsvpNote.value,
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
    },
  };
}

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

async function initAdminPage() {
  const form = document.getElementById(CONTENT_FORM_ID);
  if (!form) {
    return;
  }

  const statusEl = document.getElementById('admin-status');
  const logoutButton = document.getElementById('logout-button');

  try {
    const { response, body } = await requestJson('/api/content');

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
