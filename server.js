'use strict';

require('dotenv').config();

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const bcrypt = require('bcrypt');
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const session = require('express-session');
const nodemailer = require('nodemailer');
const validator = require('validator');

const app = express();

const {
  ADMIN_USER,
  ADMIN_PASSWORD_HASH,
  SESSION_SECRET,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  SMTP_SECURE,
  MAIL_FROM,
  PORT = '3000',
  NODE_ENV = 'development',
} = process.env;

const isProd = NODE_ENV === 'production';
const rootDir = __dirname;
const publicDir = path.join(rootDir, 'public');
const dataDir = path.join(rootDir, 'data');
const logsDir = path.join(rootDir, 'logs');
const leafletDistDir = path.join(rootDir, 'node_modules', 'leaflet', 'dist');
const publicIndexPath = path.join(publicDir, 'index.html');
const publicStylesPath = path.join(publicDir, 'styles.css');
const publicAppPath = path.join(publicDir, 'app.js');
const contentFilePath = path.join(dataDir, 'content.json');
const auditLogPath = path.join(logsDir, 'audit.log');
const rsvpSubmissionsPath = path.join(dataDir, 'rsvp-submissions.jsonl');

const DEFAULT_MAP = {
  lat: 39.8628,
  lng: -4.0273,
  zoom: 13,
  label: 'Ceremonia y celebración',
  openUrl: 'https://www.openstreetmap.org/?mlat=39.8628&mlon=-4.0273#map=13/39.8628/-4.0273',
};

const DEFAULT_NOTIFICATIONS = {
  rsvpEmailEnabled: true,
  rsvpRecipients: [],
  subjectPrefix: '[BODA] RSVP',
  fromName: 'Web Boda',
  replyToGuest: true,
};

const PUBLIC_ROOT_KEYS = [
  'presentacion',
  'dia',
  'logistica',
  'asistencia',
  'buses',
  'regalo',
  'footer',
];

const ADMIN_ROOT_KEYS = [...PUBLIC_ROOT_KEYS, 'admin'];

const RSVP_BODY_LIMIT = '10kb';
const RSVP_MIN_TIME_TO_SUBMIT_MS = 2000;
const RSVP_MAX_TIME_TO_SUBMIT_MS = 1000 * 60 * 60 * 24;

if (!ADMIN_USER || !ADMIN_PASSWORD_HASH || !SESSION_SECRET) {
  throw new Error(
    'Faltan variables de entorno obligatorias: ADMIN_USER, ADMIN_PASSWORD_HASH, SESSION_SECRET'
  );
}

if (!ADMIN_PASSWORD_HASH.startsWith('$2')) {
  throw new Error('ADMIN_PASSWORD_HASH debe ser un hash bcrypt válido.');
}

if (isProd) {
  app.set('trust proxy', 1);
}

app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'https://tile.openstreetmap.org'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  session({
    name: 'wedding.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: isProd,
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 2,
    },
  })
);

app.use(
  '/vendor/leaflet',
  express.static(leafletDistDir, {
    fallthrough: false,
    index: false,
    maxAge: isProd ? '7d' : 0,
    setHeaders(res) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
    },
  })
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler: async (req, res) => {
    await appendAuditLog('login_rate_limited', {
      ip: req.ip,
      ua: req.get('user-agent') || 'unknown',
    });

    res.status(429).json({ error: 'Demasiados intentos. Intenta más tarde.' });
  },
});

const rsvpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    await appendAuditLog('rsvp_rate_limited', {
      ip: req.ip,
      ua: req.get('user-agent') || 'unknown',
    });

    res.status(429).json({ error: 'Demasiadas solicitudes. Intenta más tarde.' });
  },
});

function hasExactKeys(obj, expectedKeys) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return false;
  }

  const keys = Object.keys(obj);
  if (keys.length !== expectedKeys.length) {
    return false;
  }

  return expectedKeys.every((key) => Object.prototype.hasOwnProperty.call(obj, key));
}

function sanitizeString(value, maxLength) {
  if (typeof value !== 'string') {
    return null;
  }

  const cleaned = value
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/[<>]/g, '')
    .trim();

  if (cleaned.length > maxLength) {
    return cleaned.slice(0, maxLength);
  }

  return cleaned;
}

function expectString(obj, key, maxLength, required = true) {
  const value = sanitizeString(obj[key], maxLength);
  if (value === null) {
    throw new Error('invalid');
  }

  if (required && value.length === 0) {
    throw new Error('invalid');
  }

  return value;
}

function expectBoolean(obj, key) {
  if (typeof obj[key] !== 'boolean') {
    throw new Error('invalid');
  }

  return obj[key];
}

function expectFiniteNumber(obj, key) {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error('invalid');
  }

  return value;
}

function expectNumberInRange(obj, key, min, max, { integer = false } = {}) {
  const value = expectFiniteNumber(obj, key);

  if (value < min || value > max) {
    throw new Error('invalid');
  }

  if (integer && !Number.isInteger(value)) {
    throw new Error('invalid');
  }

  return value;
}

function expectStringArray(value, maxItems = 20, itemMaxLength = 80) {
  if (!Array.isArray(value) || value.length > maxItems) {
    throw new Error('invalid');
  }

  const output = value.map((item) => {
    const clean = sanitizeString(item, itemMaxLength);
    if (clean === null || clean.length === 0) {
      throw new Error('invalid');
    }

    return clean;
  });

  return output;
}

function expectHttpsUrlOrEmpty(obj, key, maxLength = 300) {
  const value = expectString(obj, key, maxLength, false);
  if (!value) {
    return '';
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('invalid');
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('invalid');
  }

  return parsed.toString();
}

function expectOptionalString(obj, key, maxLength) {
  if (obj[key] === undefined || obj[key] === null) {
    return '';
  }

  return expectString(obj, key, maxLength, false);
}

function expectEmailArray(value, maxItems = 10) {
  if (!Array.isArray(value) || value.length > maxItems) {
    throw new Error('invalid');
  }

  const output = [];
  const seen = new Set();

  value.forEach((item) => {
    const clean = sanitizeString(item, 254);
    if (!clean) {
      throw new Error('invalid');
    }

    const normalized = clean.toLowerCase();
    if (seen.has(normalized)) {
      return;
    }

    if (!validator.isEmail(clean)) {
      throw new Error('invalid');
    }

    seen.add(normalized);
    output.push(clean);
  });

  return output;
}

function applyContentDefaults(rawContent) {
  if (!rawContent || typeof rawContent !== 'object' || Array.isArray(rawContent)) {
    return rawContent;
  }

  const sourceLogistica =
    rawContent.logistica && typeof rawContent.logistica === 'object' && !Array.isArray(rawContent.logistica)
      ? rawContent.logistica
      : {};

  const sourceMap =
    sourceLogistica.map && typeof sourceLogistica.map === 'object' && !Array.isArray(sourceLogistica.map)
      ? sourceLogistica.map
      : {};

  const sourceAdmin =
    rawContent.admin && typeof rawContent.admin === 'object' && !Array.isArray(rawContent.admin) ? rawContent.admin : {};

  const sourceNotifications =
    sourceAdmin.notifications && typeof sourceAdmin.notifications === 'object' && !Array.isArray(sourceAdmin.notifications)
      ? sourceAdmin.notifications
      : {};

  const notificationRecipients = Array.isArray(sourceNotifications.rsvpRecipients)
    ? sourceNotifications.rsvpRecipients
    : DEFAULT_NOTIFICATIONS.rsvpRecipients;

  return {
    ...rawContent,
    logistica: {
      ...sourceLogistica,
      map: {
        lat: Number.isFinite(sourceMap.lat) ? sourceMap.lat : DEFAULT_MAP.lat,
        lng: Number.isFinite(sourceMap.lng) ? sourceMap.lng : DEFAULT_MAP.lng,
        zoom: Number.isFinite(sourceMap.zoom) ? Math.round(sourceMap.zoom) : DEFAULT_MAP.zoom,
        label:
          typeof sourceMap.label === 'string' && sourceMap.label.trim()
            ? sourceMap.label
            : DEFAULT_MAP.label,
        openUrl:
          typeof sourceMap.openUrl === 'string' && sourceMap.openUrl.trim()
            ? sourceMap.openUrl
            : DEFAULT_MAP.openUrl,
      },
    },
    admin: {
      notifications: {
        rsvpEmailEnabled:
          typeof sourceNotifications.rsvpEmailEnabled === 'boolean'
            ? sourceNotifications.rsvpEmailEnabled
            : DEFAULT_NOTIFICATIONS.rsvpEmailEnabled,
        rsvpRecipients: notificationRecipients,
        subjectPrefix:
          typeof sourceNotifications.subjectPrefix === 'string'
            ? sourceNotifications.subjectPrefix
            : DEFAULT_NOTIFICATIONS.subjectPrefix,
        fromName:
          typeof sourceNotifications.fromName === 'string' ? sourceNotifications.fromName : DEFAULT_NOTIFICATIONS.fromName,
        replyToGuest:
          typeof sourceNotifications.replyToGuest === 'boolean'
            ? sourceNotifications.replyToGuest
            : DEFAULT_NOTIFICATIONS.replyToGuest,
      },
    },
  };
}

function validateAndNormalizeAdminContent(input) {
  if (!hasExactKeys(input, ADMIN_ROOT_KEYS)) {
    throw new Error('invalid');
  }

  const presentacion = input.presentacion;
  const dia = input.dia;
  const logistica = input.logistica;
  const asistencia = input.asistencia;
  const buses = input.buses;
  const regalo = input.regalo;
  const footer = input.footer;
  const admin = input.admin;

  if (!hasExactKeys(presentacion, ['heroOverline', 'names', 'subtitle'])) {
    throw new Error('invalid');
  }

  if (!hasExactKeys(dia, ['title', 'items'])) {
    throw new Error('invalid');
  }

  if (!hasExactKeys(logistica, ['title', 'locationTitle', 'howToArrive', 'parking', 'map'])) {
    throw new Error('invalid');
  }

  if (!hasExactKeys(logistica.map, ['lat', 'lng', 'zoom', 'label', 'openUrl'])) {
    throw new Error('invalid');
  }

  if (!hasExactKeys(asistencia, ['title', 'rsvpNote'])) {
    throw new Error('invalid');
  }

  if (!hasExactKeys(buses, ['enabled', 'stopsIda', 'stopsVuelta'])) {
    throw new Error('invalid');
  }

  if (!hasExactKeys(regalo, ['enabled', 'title', 'message', 'iban', 'bizum'])) {
    throw new Error('invalid');
  }

  if (!hasExactKeys(footer, ['deadlineText'])) {
    throw new Error('invalid');
  }

  if (!hasExactKeys(admin, ['notifications'])) {
    throw new Error('invalid');
  }

  if (
    !hasExactKeys(admin.notifications, [
      'rsvpEmailEnabled',
      'rsvpRecipients',
      'subjectPrefix',
      'fromName',
      'replyToGuest',
    ])
  ) {
    throw new Error('invalid');
  }

  if (!Array.isArray(dia.items) || dia.items.length < 1 || dia.items.length > 12) {
    throw new Error('invalid');
  }

  const dayItems = dia.items.map((item) => {
    if (!hasExactKeys(item, ['time', 'title', 'desc'])) {
      throw new Error('invalid');
    }

    return {
      time: expectString(item, 'time', 20),
      title: expectString(item, 'title', 80),
      desc: expectString(item, 'desc', 180),
    };
  });

  return {
    presentacion: {
      heroOverline: expectString(presentacion, 'heroOverline', 80),
      names: expectString(presentacion, 'names', 120),
      subtitle: expectString(presentacion, 'subtitle', 400),
    },
    dia: {
      title: expectString(dia, 'title', 120),
      items: dayItems,
    },
    logistica: {
      title: expectString(logistica, 'title', 120),
      locationTitle: expectString(logistica, 'locationTitle', 180),
      howToArrive: expectString(logistica, 'howToArrive', 400),
      parking: expectString(logistica, 'parking', 280),
      map: {
        lat: expectNumberInRange(logistica.map, 'lat', -90, 90),
        lng: expectNumberInRange(logistica.map, 'lng', -180, 180),
        zoom: expectNumberInRange(logistica.map, 'zoom', 1, 20, { integer: true }),
        label: expectString(logistica.map, 'label', 120),
        openUrl: expectHttpsUrlOrEmpty(logistica.map, 'openUrl', 300),
      },
    },
    asistencia: {
      title: expectString(asistencia, 'title', 120),
      rsvpNote: expectString(asistencia, 'rsvpNote', 180),
    },
    buses: {
      enabled: expectBoolean(buses, 'enabled'),
      stopsIda: expectStringArray(buses.stopsIda, 20, 80),
      stopsVuelta: expectStringArray(buses.stopsVuelta, 20, 80),
    },
    regalo: {
      enabled: expectBoolean(regalo, 'enabled'),
      title: expectString(regalo, 'title', 120),
      message: expectString(regalo, 'message', 320),
      iban: expectString(regalo, 'iban', 64),
      bizum: expectString(regalo, 'bizum', 40),
    },
    footer: {
      deadlineText: expectString(footer, 'deadlineText', 180),
    },
    admin: {
      notifications: {
        rsvpEmailEnabled: expectBoolean(admin.notifications, 'rsvpEmailEnabled'),
        rsvpRecipients: expectEmailArray(admin.notifications.rsvpRecipients, 10),
        subjectPrefix: expectOptionalString(admin.notifications, 'subjectPrefix', 80),
        fromName: expectOptionalString(admin.notifications, 'fromName', 60),
        replyToGuest: expectBoolean(admin.notifications, 'replyToGuest'),
      },
    },
  };
}

function toPublicContent(content) {
  return PUBLIC_ROOT_KEYS.reduce((acc, key) => {
    acc[key] = content[key];
    return acc;
  }, {});
}

function safeEqualStrings(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function createCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getOrCreateCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = createCsrfToken();
  }

  return req.session.csrfToken;
}

function requireCsrf(req, res, next) {
  const headerToken =
    req.get('csrf-token') || req.get('x-csrf-token') || req.get('x-xsrf-token') || req.body._csrf;

  const sessionToken = req.session?.csrfToken;

  if (!headerToken || !sessionToken || !safeEqualStrings(headerToken, sessionToken)) {
    return res.status(403).json({ error: 'Solicitud inválida' });
  }

  return next();
}

async function appendAuditLog(event, payload = {}) {
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    event,
    ...payload,
  });

  await fs.appendFile(auditLogPath, `${line}\n`, 'utf8');
}

async function appendRsvpSubmission(entry) {
  const line = JSON.stringify(entry);
  await fs.appendFile(rsvpSubmissionsPath, `${line}\n`, { encoding: 'utf8', mode: 0o600 });
}

function hashIp(ip) {
  try {
    return crypto.createHmac('sha256', SESSION_SECRET).update(String(ip || '')).digest('hex').slice(0, 32);
  } catch {
    return 'unknown';
  }
}

async function readContentFromDisk() {
  const raw = await fs.readFile(contentFilePath, 'utf8');
  const parsed = JSON.parse(raw);
  const withDefaults = applyContentDefaults(parsed);

  return validateAndNormalizeAdminContent(withDefaults);
}

async function writeContentAtomically(content) {
  const tmpPath = path.join(dataDir, `content.${crypto.randomUUID()}.tmp`);
  const serialized = `${JSON.stringify(content, null, 2)}\n`;

  await fs.writeFile(tmpPath, serialized, { encoding: 'utf8', mode: 0o600 });
  await fs.rename(tmpPath, contentFilePath);
}

function requireAdminApi(req, res, next) {
  if (req.session?.isAuthenticated === true) {
    return next();
  }

  return res.status(401).json({ error: 'No autorizado' });
}

function requireAdminPage(req, res, next) {
  if (req.session?.isAuthenticated === true) {
    return next();
  }

  return res.redirect('/login');
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isLikelyPhone(value) {
  if (typeof value !== 'string') {
    return false;
  }

  const trimmed = value.trim();
  if (!/^[+()\d\s.-]+$/.test(trimmed)) {
    return false;
  }

  const digits = trimmed.replace(/\D/g, '');
  return digits.length >= 7 && digits.length <= 20;
}

function parseClientMillis(value) {
  const raw = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(raw)) {
    throw new Error('invalid');
  }

  return Math.trunc(raw);
}

function validateAndNormalizeRsvpPayload(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('invalid');
  }

  const name = sanitizeString(input.name, 80);
  if (!name || name.length < 2) {
    throw new Error('invalid');
  }

  const contactRaw = sanitizeString(input.contact, 120);
  if (!contactRaw || contactRaw.length < 5) {
    throw new Error('invalid');
  }

  const contactEmail = validator.isEmail(contactRaw) ? contactRaw.toLowerCase() : '';
  if (!contactEmail && !isLikelyPhone(contactRaw)) {
    throw new Error('invalid');
  }

  const attending = sanitizeString(input.attending, 3);
  if (attending !== 'yes' && attending !== 'no') {
    throw new Error('invalid');
  }

  const guestsRaw = typeof input.guests === 'number' ? input.guests : Number(input.guests);
  if (!Number.isInteger(guestsRaw) || guestsRaw < 1 || guestsRaw > 6) {
    throw new Error('invalid');
  }

  const allergies = expectOptionalString(input, 'allergies', 500);
  const comments = expectOptionalString(input, 'comments', 500);

  const busInput = input.bus === undefined || input.bus === null ? {} : input.bus;
  if (typeof busInput !== 'object' || Array.isArray(busInput)) {
    throw new Error('invalid');
  }

  const needsBus = typeof busInput.needsBus === 'boolean' ? busInput.needsBus : false;
  const outboundStop = needsBus ? sanitizeString(busInput.outboundStop, 80) || '' : '';
  const returnStop = needsBus ? sanitizeString(busInput.returnStop, 80) || '' : '';
  const notes = needsBus ? sanitizeString(busInput.notes, 200) || '' : '';

  if (needsBus && (!outboundStop || !returnStop)) {
    throw new Error('invalid');
  }

  return {
    name,
    contact: contactRaw,
    contactEmail,
    attending,
    guests: guestsRaw,
    allergies,
    comments,
    bus: {
      needsBus,
      outboundStop,
      returnStop,
      notes,
    },
  };
}

function buildRsvpEmail({ rsvp, notifications, receivedAtIso }) {
  const prefix = sanitizeString(notifications.subjectPrefix || '', 80) || '';
  const fromName = sanitizeString(notifications.fromName || '', 60) || '';

  const subjectBase = prefix ? `${prefix} - ${rsvp.name} (${rsvp.attending})` : `RSVP - ${rsvp.name} (${rsvp.attending})`;
  const subject = sanitizeString(subjectBase, 200) || 'RSVP';

  const lines = [
    'RSVP recibido',
    '',
    `Fecha: ${receivedAtIso}`,
    `Nombre: ${rsvp.name}`,
    `Asiste: ${rsvp.attending}`,
    `Contacto: ${rsvp.contact}`,
    `Personas: ${rsvp.guests}`,
    `Alergias: ${rsvp.allergies || '-'}`,
    `Comentarios: ${rsvp.comments || '-'}`,
    `Bus: ${rsvp.bus.needsBus ? 'si' : 'no'}`,
  ];

  if (rsvp.bus.needsBus) {
    lines.push(`Parada ida: ${rsvp.bus.outboundStop || '-'}`);
    lines.push(`Parada vuelta: ${rsvp.bus.returnStop || '-'}`);
    lines.push(`Notas bus: ${rsvp.bus.notes || '-'}`);
  }

  const text = `${lines.join('\n')}\n`;

  const htmlRows = [
    ['Fecha', receivedAtIso],
    ['Nombre', rsvp.name],
    ['Asiste', rsvp.attending],
    ['Contacto', rsvp.contact],
    ['Personas', String(rsvp.guests)],
    ['Alergias', rsvp.allergies || '-'],
    ['Comentarios', rsvp.comments || '-'],
    ['Bus', rsvp.bus.needsBus ? 'si' : 'no'],
  ];

  if (rsvp.bus.needsBus) {
    htmlRows.push(['Parada ida', rsvp.bus.outboundStop || '-']);
    htmlRows.push(['Parada vuelta', rsvp.bus.returnStop || '-']);
    htmlRows.push(['Notas bus', rsvp.bus.notes || '-']);
  }

  const html = `<!doctype html>
<html>
  <body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:#ffffff;color:#111827;">
    <div style="max-width:640px;margin:0 auto;padding:24px;">
      <h2 style="margin:0 0 12px 0;font-size:18px;">RSVP recibido</h2>
      <table cellspacing="0" cellpadding="0" style="width:100%;border-collapse:collapse;">
        <tbody>
          ${htmlRows
            .map(
              ([label, value]) => `<tr>
            <td style="padding:10px 8px;border-bottom:1px solid #e5e7eb;width:180px;vertical-align:top;"><strong>${escapeHtml(
              label
            )}</strong></td>
            <td style="padding:10px 8px;border-bottom:1px solid #e5e7eb;">${escapeHtml(value)}</td>
          </tr>`
            )
            .join('')}
        </tbody>
      </table>
      <p style="margin:14px 0 0 0;font-size:12px;color:#6b7280;">Enviado desde la web de boda.</p>
    </div>
  </body>
</html>`;

  return {
    fromName,
    subject,
    text,
    html,
  };
}

function getSmtpTransporter() {
  const host = typeof SMTP_HOST === 'string' ? SMTP_HOST.trim() : '';
  const port = Number(SMTP_PORT);
  const secure = String(SMTP_SECURE || '').toLowerCase() === 'true';

  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('smtp_not_configured');
  }

  if (SMTP_USER && !SMTP_PASS) {
    throw new Error('smtp_not_configured');
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    disableFileAccess: true,
    disableUrlAccess: true,
  });
}

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/rsvp', rsvpLimiter, express.json({ limit: RSVP_BODY_LIMIT }), async (req, res) => {
  try {
    const honeypot = req.body?.company;
    const hpValue = typeof honeypot === 'string' ? honeypot.trim() : '';
    if (hpValue) {
      await appendAuditLog('rsvp_rejected_honeypot', {
        ip: req.ip,
        ua: req.get('user-agent') || 'unknown',
      });
      return res.status(400).json({ error: 'Solicitud inválida' });
    }

    const formLoadedAt = parseClientMillis(req.body?.formLoadedAt);
    const now = Date.now();
    const delta = now - formLoadedAt;
    if (delta < RSVP_MIN_TIME_TO_SUBMIT_MS || delta > RSVP_MAX_TIME_TO_SUBMIT_MS) {
      await appendAuditLog('rsvp_rejected_timing', {
        ip: req.ip,
        ua: req.get('user-agent') || 'unknown',
        deltaMs: delta,
      });
      return res.status(400).json({ error: 'Solicitud inválida' });
    }

    const normalized = validateAndNormalizeRsvpPayload(req.body);
    const receivedAtIso = new Date().toISOString();

    const ipHash = hashIp(req.ip);
    try {
      await appendRsvpSubmission({
        timestamp: receivedAtIso,
        ipHash,
        ua: sanitizeString(req.get('user-agent') || 'unknown', 200) || 'unknown',
        rsvp: normalized,
      });
    } catch {
      await appendAuditLog('rsvp_log_failed', { ip: req.ip });
    }

    let notifications = DEFAULT_NOTIFICATIONS;
    try {
      const content = await readContentFromDisk();
      notifications = content.admin?.notifications || DEFAULT_NOTIFICATIONS;
    } catch {
      await appendAuditLog('rsvp_email_skipped_content_error', { ip: req.ip });
      return res.json({ ok: true });
    }

    if (!notifications.rsvpEmailEnabled) {
      await appendAuditLog('rsvp_email_skipped_disabled', { ip: req.ip });
      return res.json({ ok: true });
    }

    if (!Array.isArray(notifications.rsvpRecipients) || notifications.rsvpRecipients.length === 0) {
      await appendAuditLog('rsvp_email_skipped_no_recipients', { ip: req.ip });
      return res.json({ ok: true });
    }

    const mailFrom = typeof MAIL_FROM === 'string' ? MAIL_FROM.trim() : '';
    if (!mailFrom || !validator.isEmail(mailFrom)) {
      await appendAuditLog('rsvp_email_skipped_missing_from', { ip: req.ip });
      return res.json({ ok: true });
    }

    const { fromName, subject, text, html } = buildRsvpEmail({ rsvp: normalized, notifications, receivedAtIso });

    const from = fromName ? `${fromName} <${mailFrom}>` : mailFrom;
    const message = {
      from,
      to: notifications.rsvpRecipients,
      subject,
      text,
      html,
    };

    if (notifications.replyToGuest && normalized.contactEmail) {
      message.replyTo = normalized.contactEmail;
    }

    try {
      const transporter = getSmtpTransporter();
      await transporter.sendMail(message);
      await appendAuditLog('rsvp_email_sent', {
        ip: req.ip,
        recipients: notifications.rsvpRecipients.length,
      });
    } catch (error) {
      await appendAuditLog('rsvp_email_failed', {
        ip: req.ip,
        code: typeof error?.code === 'string' ? error.code : 'unknown',
      });
    }

    return res.json({ ok: true });
  } catch {
    return res.status(400).json({ error: 'Solicitud inválida' });
  }
});

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

app.get('/', (_req, res) => {
  res.sendFile(publicIndexPath);
});

app.get('/styles.css', (_req, res) => {
  res.sendFile(publicStylesPath);
});

app.get('/app.js', (_req, res) => {
  res.sendFile(publicAppPath);
});

app.get('/login', (req, res) => {
  if (req.session?.isAuthenticated) {
    return res.redirect('/admin');
  }

  return res.sendFile(path.join(publicDir, 'login.html'));
});

app.get('/admin', requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});

app.get('/admin.css', (_req, res) => {
  res.sendFile(path.join(publicDir, 'admin.css'));
});

app.get('/admin.js', (_req, res) => {
  res.sendFile(path.join(publicDir, 'admin.js'));
});

app.get('/api/csrf-token', (req, res) => {
  const token = getOrCreateCsrfToken(req);

  req.session.save((error) => {
    if (error) {
      return res.status(500).json({ error: 'Error interno' });
    }

    return res.json({ csrfToken: token });
  });
});

app.post('/login', loginLimiter, requireCsrf, async (req, res) => {
  const user = typeof req.body.user === 'string' ? req.body.user.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!user || !password) {
    await appendAuditLog('login_failed', {
      reason: 'missing_credentials',
      ip: req.ip,
      ua: req.get('user-agent') || 'unknown',
    });

    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  const userMatches = safeEqualStrings(user, ADMIN_USER);
  const passMatches = userMatches ? await bcrypt.compare(password, ADMIN_PASSWORD_HASH) : false;

  if (!userMatches || !passMatches) {
    await appendAuditLog('login_failed', {
      reason: 'invalid_credentials',
      ip: req.ip,
      username: user,
      ua: req.get('user-agent') || 'unknown',
    });

    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  req.session.regenerate(async (regenerateError) => {
    if (regenerateError) {
      await appendAuditLog('login_failed', {
        reason: 'session_regenerate_error',
        ip: req.ip,
      });

      return res.status(500).json({ error: 'Error interno' });
    }

    req.session.isAuthenticated = true;
    req.session.username = ADMIN_USER;
    req.session.csrfToken = createCsrfToken();

    return req.session.save(async (saveError) => {
      if (saveError) {
        await appendAuditLog('login_failed', {
          reason: 'session_save_error',
          ip: req.ip,
        });

        return res.status(500).json({ error: 'Error interno' });
      }

      await appendAuditLog('login_success', {
        ip: req.ip,
        username: ADMIN_USER,
      });

      return res.json({ ok: true });
    });
  });
});

app.post('/logout', requireAdminApi, requireCsrf, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('wedding.sid', {
      httpOnly: true,
      secure: isProd,
      sameSite: 'strict',
    });

    res.json({ ok: true });
  });
});

app.get('/api/content', async (_req, res) => {
  try {
    const content = await readContentFromDisk();
    res.json(toPublicContent(content));
  } catch {
    res.status(500).json({ error: 'No se pudo cargar contenido' });
  }
});

app.get('/api/admin/content', requireAdminApi, async (req, res) => {
  try {
    const content = await readContentFromDisk();
    res.json(content);
  } catch {
    await appendAuditLog('admin_content_load_failed', {
      ip: req.ip,
      username: req.session.username || ADMIN_USER,
    });
    res.status(500).json({ error: 'No se pudo cargar contenido' });
  }
});

app.put('/api/content', requireAdminApi, requireCsrf, async (req, res) => {
  try {
    const withDefaults = applyContentDefaults(req.body);
    const normalizedContent = validateAndNormalizeAdminContent(withDefaults);
    await writeContentAtomically(normalizedContent);

    await appendAuditLog('content_updated', {
      ip: req.ip,
      username: req.session.username || ADMIN_USER,
    });

    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Solicitud inválida' });
  }
});

app.use((_error, _req, res, _next) => {
  return res.status(500).json({ error: 'Error interno' });
});

async function bootstrap() {
  await fs.mkdir(dataDir, { recursive: true });
  await fs.mkdir(logsDir, { recursive: true });

  try {
    const normalizedContent = await readContentFromDisk();
    await writeContentAtomically(normalizedContent);
  } catch {
    throw new Error('content.json no existe o no cumple el esquema esperado.');
  }

  app.listen(Number(PORT), () => {
    // eslint-disable-next-line no-console
    console.log(`Admin panel seguro activo en http://localhost:${PORT}`);
  });
}

bootstrap().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error.message);
  process.exit(1);
});
