const THEME_KEY = 'wedding-theme';
const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

const root = document.documentElement;
const themeToggle = document.querySelector('#theme-toggle');
const stickyHeader = document.querySelector('.site-header');
const rsvpForm = document.querySelector('#rsvp-form');
const formStatus = document.querySelector('#form-status');
const busFields = document.querySelector('#bus-fields');
const busToggleInputs = document.querySelectorAll('input[name="bus"]');
const paradaIda = document.querySelector('#parada-ida');
const paradaVuelta = document.querySelector('#parada-vuelta');
const timelineGrid = document.querySelector('#timeline-grid');
const busCard = document.querySelector('.bus-card');
const giftSection = document.querySelector('#regalo');
const copyButtons = document.querySelectorAll('[data-copy]');
const copyStatus = document.querySelector('#copy-status');
const locationMapElement = document.querySelector('#location-map');
const locationMapFallback = document.querySelector('#location-map-fallback');
const locationOpenMaps = document.querySelector('#location-open-maps');

let publicMap = null;
let publicMarker = null;

function isReducedMotion() {
  return reducedMotionQuery.matches;
}

function readPreferredTheme() {
  const storedTheme = localStorage.getItem(THEME_KEY);
  if (storedTheme === 'light' || storedTheme === 'dark') {
    return storedTheme;
  }

  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function updateThemeButton(theme) {
  if (!themeToggle) {
    return;
  }

  const icon = themeToggle.querySelector('[data-theme-icon]');
  const label = themeToggle.querySelector('[data-theme-label]');
  const isDark = theme === 'dark';

  themeToggle.setAttribute('aria-pressed', String(isDark));
  themeToggle.setAttribute('aria-label', isDark ? 'Cambiar a tema claro' : 'Cambiar a tema oscuro');

  if (icon) {
    icon.textContent = isDark ? '☀︎' : '☾';
  }

  if (label) {
    label.textContent = isDark ? 'Tema claro' : 'Tema oscuro';
  }
}

function setTheme(theme) {
  root.setAttribute('data-theme', theme);
  updateThemeButton(theme);
}

function initThemeToggle() {
  setTheme(readPreferredTheme());

  if (!themeToggle) {
    return;
  }

  themeToggle.addEventListener('click', () => {
    const currentTheme = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';

    setTheme(nextTheme);
    localStorage.setItem(THEME_KEY, nextTheme);
  });
}

function setTextById(id, value) {
  if (typeof value !== 'string') {
    return;
  }

  const element = document.getElementById(id);
  if (!element) {
    return;
  }

  const cleanValue = value.trim();
  if (!cleanValue) {
    return;
  }

  element.textContent = cleanValue;
}

function populateSelectOptions(selectElement, values) {
  if (!selectElement || !Array.isArray(values)) {
    return;
  }

  const currentValue = selectElement.value;
  const placeholderLabel = selectElement.options[0]?.textContent || 'Selecciona una opción';

  selectElement.innerHTML = '';
  const placeholder = document.createElement('option');
  placeholder.value = '';
  placeholder.textContent = placeholderLabel;
  selectElement.append(placeholder);

  values.forEach((value) => {
    if (typeof value !== 'string' || !value.trim()) {
      return;
    }

    const option = document.createElement('option');
    option.value = value.trim();
    option.textContent = value.trim();
    selectElement.append(option);
  });

  if (currentValue && values.includes(currentValue)) {
    selectElement.value = currentValue;
  }
}

function updateCopyButtonValue(type, value) {
  const cleanValue = typeof value === 'string' ? value.trim() : '';
  if (!cleanValue) {
    return;
  }

  const button = document.querySelector(`[data-copy-type="${type}"]`);
  if (button) {
    button.dataset.copy = cleanValue;
  }
}

function hasValidMapCoordinates(mapData) {
  return (
    mapData &&
    typeof mapData === 'object' &&
    typeof mapData.lat === 'number' &&
    Number.isFinite(mapData.lat) &&
    mapData.lat >= -90 &&
    mapData.lat <= 90 &&
    typeof mapData.lng === 'number' &&
    Number.isFinite(mapData.lng) &&
    mapData.lng >= -180 &&
    mapData.lng <= 180
  );
}

function buildOsmOpenUrl(lat, lng, zoom = 14) {
  return `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lng}#map=${zoom}/${lat}/${lng}`;
}

function normalizeMapConfig(mapData) {
  if (!hasValidMapCoordinates(mapData)) {
    return null;
  }

  const zoom = Number.isInteger(mapData.zoom) && mapData.zoom >= 1 && mapData.zoom <= 20 ? mapData.zoom : 14;
  const label = typeof mapData.label === 'string' && mapData.label.trim() ? mapData.label.trim() : 'Ubicación';
  const openUrl =
    typeof mapData.openUrl === 'string' && mapData.openUrl.trim()
      ? mapData.openUrl.trim()
      : buildOsmOpenUrl(mapData.lat, mapData.lng, zoom);

  return {
    lat: mapData.lat,
    lng: mapData.lng,
    zoom,
    label,
    openUrl,
  };
}

function setOpenMapsUrl(url) {
  if (!locationOpenMaps) {
    return;
  }

  if (typeof url === 'string' && url.trim()) {
    locationOpenMaps.href = url.trim();
    locationOpenMaps.setAttribute('aria-disabled', 'false');
    return;
  }

  locationOpenMaps.removeAttribute('href');
  locationOpenMaps.setAttribute('aria-disabled', 'true');
}

function showMapFallback() {
  if (locationMapFallback) {
    locationMapFallback.hidden = false;
  }

  if (locationMapElement) {
    locationMapElement.setAttribute('aria-hidden', 'true');
  }
}

function hideMapFallback() {
  if (locationMapFallback) {
    locationMapFallback.hidden = true;
  }

  if (locationMapElement) {
    locationMapElement.removeAttribute('aria-hidden');
  }
}

function removePublicMap() {
  if (!publicMap) {
    return;
  }

  publicMap.remove();
  publicMap = null;
  publicMarker = null;
}

function initPublicMap(mapData) {
  if (!locationMapElement) {
    return;
  }

  const config = normalizeMapConfig(mapData);
  if (!config) {
    removePublicMap();
    setOpenMapsUrl('');
    showMapFallback();
    return;
  }

  setTextById('text-logistica-mapLabel', config.label);
  setOpenMapsUrl(config.openUrl);

  if (!window.L || typeof window.L.map !== 'function') {
    removePublicMap();
    showMapFallback();
    return;
  }

  try {
    removePublicMap();

    publicMap = window.L.map(locationMapElement, {
      zoomControl: true,
      scrollWheelZoom: false,
    }).setView([config.lat, config.lng], config.zoom);

    window.L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 20,
      attribution: '&copy; OpenStreetMap contributors',
    }).addTo(publicMap);

    publicMarker = window.L.marker([config.lat, config.lng]).addTo(publicMap);

    const popupText = document.createElement('span');
    popupText.textContent = config.label;
    publicMarker.bindPopup(popupText).openPopup();

    hideMapFallback();
    window.requestAnimationFrame(() => {
      publicMap?.invalidateSize();
    });
  } catch {
    removePublicMap();
    showMapFallback();
  }
}

function renderTimelineItems(items) {
  if (!timelineGrid || !Array.isArray(items) || items.length === 0) {
    return;
  }

  timelineGrid.innerHTML = '';

  items.forEach((item, index) => {
    if (!item || typeof item !== 'object') {
      return;
    }

    const card = document.createElement('article');
    card.className = 'card timeline-card reveal';
    card.dataset.reveal = '';
    card.setAttribute('role', 'listitem');

    if (index > 0 && index <= 2) {
      card.classList.add('reveal--delay-1');
    } else if (index > 2) {
      card.classList.add('reveal--delay-2');
    }

    const time = document.createElement('p');
    time.className = 'timeline-card__time';
    time.textContent = typeof item.time === 'string' ? item.time : '';

    const title = document.createElement('h3');
    title.className = 'title';
    title.textContent = typeof item.title === 'string' ? item.title : '';

    const desc = document.createElement('p');
    desc.className = 'muted';
    desc.textContent = typeof item.desc === 'string' ? item.desc : '';

    card.append(time, title, desc);
    timelineGrid.append(card);
  });
}

function applyPublicContent(content) {
  if (!content || typeof content !== 'object') {
    return;
  }

  setTextById('text-presentacion-heroOverline', content.presentacion?.heroOverline);
  setTextById('text-presentacion-names', content.presentacion?.names);
  setTextById('text-presentacion-names-brand', content.presentacion?.names);
  setTextById('text-presentacion-subtitle', content.presentacion?.subtitle);

  setTextById('dia-title', content.dia?.title);
  renderTimelineItems(content.dia?.items);

  setTextById('logistica-title', content.logistica?.title);
  setTextById('text-logistica-locationTitle', content.logistica?.locationTitle);
  setTextById('text-logistica-howToArrive', content.logistica?.howToArrive);
  setTextById('text-logistica-parking', content.logistica?.parking);
  initPublicMap(content.logistica?.map);

  setTextById('asistencia-title', content.asistencia?.title);
  setTextById('text-asistencia-rsvpNote', content.asistencia?.rsvpNote);

  if (typeof content.buses?.enabled === 'boolean' && busCard) {
    busCard.hidden = !content.buses.enabled;
  }

  populateSelectOptions(paradaIda, content.buses?.stopsIda);
  populateSelectOptions(paradaVuelta, content.buses?.stopsVuelta);

  if (typeof content.regalo?.enabled === 'boolean' && giftSection) {
    giftSection.hidden = !content.regalo.enabled;
  }

  setTextById('text-regalo-title', content.regalo?.title);
  setTextById('text-regalo-message', content.regalo?.message);
  setTextById('gift-iban', content.regalo?.iban);
  setTextById('gift-bizum', content.regalo?.bizum);
  updateCopyButtonValue('iban', content.regalo?.iban);
  updateCopyButtonValue('bizum', content.regalo?.bizum);

  setTextById('text-footer-deadline', content.footer?.deadlineText);
}

async function initPublicContent() {
  try {
    const response = await fetch('/api/content', {
      headers: {
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      initPublicMap(null);
      return;
    }

    const content = await response.json();
    applyPublicContent(content);
  } catch {
    initPublicMap(null);
  }
}

function scrollToAnchor(hash) {
  const target = document.querySelector(hash);
  if (!target) {
    return;
  }

  const headerOffset = stickyHeader ? stickyHeader.offsetHeight + 10 : 0;
  const top = target.getBoundingClientRect().top + window.scrollY - headerOffset;

  window.scrollTo({
    top,
    behavior: isReducedMotion() ? 'auto' : 'smooth',
  });
}

function initSmoothScroll() {
  const links = document.querySelectorAll('a[href^="#"]:not([href="#"])');

  links.forEach((link) => {
    link.addEventListener('click', (event) => {
      const hash = link.getAttribute('href');
      if (!hash || hash.length < 2) {
        return;
      }

      const target = document.querySelector(hash);
      if (!target) {
        return;
      }

      event.preventDefault();
      scrollToAnchor(hash);
      history.pushState(null, '', hash);
    });
  });
}

function setFormMessage(message, type = '') {
  if (!formStatus) {
    return;
  }

  formStatus.textContent = message;
  formStatus.classList.remove('is-success', 'is-error');

  if (type) {
    formStatus.classList.add(type);
  }
}

function updateBusVisibility() {
  if (!busFields) {
    return;
  }

  const selected = document.querySelector('input[name="bus"]:checked');
  const wantsBus = selected?.value === 'si';

  busFields.hidden = !wantsBus;

  if (paradaIda && paradaVuelta) {
    paradaIda.required = wantsBus;
    paradaVuelta.required = wantsBus;

    if (!wantsBus) {
      paradaIda.value = '';
      paradaVuelta.value = '';
      const obsBus = document.querySelector('#obs-bus');
      if (obsBus) {
        obsBus.value = '';
      }
    }
  }
}

function initBusToggle() {
  if (!busToggleInputs.length) {
    return;
  }

  busToggleInputs.forEach((input) => {
    input.addEventListener('change', updateBusVisibility);
  });

  updateBusVisibility();
}

function validateRsvpForm() {
  if (!rsvpForm) {
    return false;
  }

  const nombre = rsvpForm.querySelector('#nombre');
  const contacto = rsvpForm.querySelector('#contacto');
  const personas = rsvpForm.querySelector('#personas');
  const asistencia = rsvpForm.querySelector('input[name="asistencia"]:checked');
  const wantsBus = rsvpForm.querySelector('input[name="bus"]:checked')?.value === 'si';

  if (!rsvpForm.checkValidity()) {
    rsvpForm.reportValidity();
    setFormMessage('Revisa los campos obligatorios antes de enviar.', 'is-error');
    return false;
  }

  if (!nombre || nombre.value.trim().length < 2) {
    setFormMessage('Escribe un nombre válido.', 'is-error');
    nombre?.focus();
    return false;
  }

  if (!contacto || contacto.value.trim().length < 5) {
    setFormMessage('Añade un contacto válido.', 'is-error');
    contacto?.focus();
    return false;
  }

  if (!asistencia) {
    setFormMessage('Selecciona si asistirás al evento.', 'is-error');
    return false;
  }

  if (personas) {
    const total = Number(personas.value);
    if (Number.isNaN(total) || total < 1 || total > 8) {
      setFormMessage('El número de personas debe estar entre 1 y 8.', 'is-error');
      personas.focus();
      return false;
    }
  }

  if (wantsBus && (!paradaIda?.value || !paradaVuelta?.value)) {
    setFormMessage('Si solicitas bus, selecciona parada de ida y vuelta.', 'is-error');
    return false;
  }

  return true;
}

function initRsvpForm() {
  if (!rsvpForm) {
    return;
  }

  rsvpForm.addEventListener('submit', (event) => {
    event.preventDefault();
    setFormMessage('');

    if (!validateRsvpForm()) {
      return;
    }

    const nombre = rsvpForm.querySelector('#nombre')?.value.trim() || 'Invitado/a';
    const asistencia = rsvpForm.querySelector('input[name="asistencia"]:checked')?.value;
    const msg =
      asistencia === 'si'
        ? `Gracias, ${nombre}. Tu asistencia quedó registrada.`
        : `Gracias, ${nombre}. Hemos recibido tu respuesta.`;

    setFormMessage(msg, 'is-success');
    rsvpForm.reset();
    updateBusVisibility();
  });
}

function initHeaderScrollState() {
  if (!stickyHeader) {
    return;
  }

  const updateState = () => {
    stickyHeader.classList.toggle('is-scrolled', window.scrollY > 12);
  };

  updateState();
  window.addEventListener('scroll', updateState, { passive: true });
}

function getRevealElements() {
  const nodes = new Set([
    ...document.querySelectorAll('[data-reveal]'),
    ...document.querySelectorAll('.reveal'),
  ]);

  return Array.from(nodes);
}

function showAllRevealElements(elements) {
  elements.forEach((element) => {
    element.classList.add('reveal', 'is-visible');
  });
}

function initRevealOnScroll() {
  const revealElements = getRevealElements();
  if (!revealElements.length) {
    return;
  }

  if (isReducedMotion() || !('IntersectionObserver' in window)) {
    showAllRevealElements(revealElements);
    return;
  }

  revealElements.forEach((element) => {
    element.classList.add('reveal');
  });

  const observer = new IntersectionObserver(
    (entries, currentObserver) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) {
          return;
        }

        entry.target.classList.add('is-visible');
        currentObserver.unobserve(entry.target);
      });
    },
    {
      threshold: 0.14,
      rootMargin: '0px 0px -10% 0px',
    }
  );

  revealElements.forEach((element) => observer.observe(element));
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.setAttribute('readonly', '');
  textArea.style.position = 'absolute';
  textArea.style.left = '-9999px';
  document.body.append(textArea);
  textArea.select();
  document.execCommand('copy');
  textArea.remove();
}

function setCopyStatus(message) {
  if (!copyStatus) {
    return;
  }

  copyStatus.textContent = message;

  window.clearTimeout(setCopyStatus.timeoutId);
  setCopyStatus.timeoutId = window.setTimeout(() => {
    copyStatus.textContent = '';
  }, 1800);
}

function initCopyButtons() {
  if (!copyButtons.length) {
    return;
  }

  copyButtons.forEach((button) => {
    button.addEventListener('click', async () => {
      const value = button.dataset.copy?.trim();
      if (!value) {
        return;
      }

      try {
        await copyText(value);
        setCopyStatus('Copiado al portapapeles.');
      } catch {
        setCopyStatus('No se pudo copiar. Puedes hacerlo manualmente.');
      }
    });
  });
}

initThemeToggle();
initSmoothScroll();
initBusToggle();
initRsvpForm();
initHeaderScrollState();
initCopyButtons();

initPublicContent().finally(() => {
  initRevealOnScroll();
});
