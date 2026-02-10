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

const app = express();

const {
  ADMIN_USER,
  ADMIN_PASSWORD_HASH,
  SESSION_SECRET,
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

const DEFAULT_MAP = {
  lat: 39.8628,
  lng: -4.0273,
  zoom: 13,
  label: 'Ceremonia y celebración',
  openUrl: 'https://www.openstreetmap.org/?mlat=39.8628&mlon=-4.0273#map=13/39.8628/-4.0273',
};

const ROOT_KEYS = [
  'presentacion',
  'dia',
  'logistica',
  'asistencia',
  'buses',
  'regalo',
  'footer',
];

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

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

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
  };
}

function validateAndNormalizeContent(input) {
  if (!hasExactKeys(input, ROOT_KEYS)) {
    throw new Error('invalid');
  }

  const presentacion = input.presentacion;
  const dia = input.dia;
  const logistica = input.logistica;
  const asistencia = input.asistencia;
  const buses = input.buses;
  const regalo = input.regalo;
  const footer = input.footer;

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
  };
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

async function readContentFromDisk() {
  const raw = await fs.readFile(contentFilePath, 'utf8');
  const parsed = JSON.parse(raw);
  const withDefaults = applyContentDefaults(parsed);

  return validateAndNormalizeContent(withDefaults);
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

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

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
    res.json(content);
  } catch {
    res.status(500).json({ error: 'No se pudo cargar contenido' });
  }
});

app.put('/api/content', requireAdminApi, requireCsrf, async (req, res) => {
  try {
    const normalizedContent = validateAndNormalizeContent(req.body);
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
