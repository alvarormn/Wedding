# Secure Wedding Admin Panel

Panel de administración mínimo y seguro para editar textos de una web de boda.

## Stack

- Backend: Node.js + Express
- Persistencia: `data/content.json`
- Admin frontend: HTML + CSS + JavaScript vanilla
- Mapa: Leaflet servido localmente desde `node_modules` en `/vendor/leaflet/*`

## Instalación

1. Instala dependencias:

```bash
npm i
```

2. Crea tu archivo de entorno:

```bash
cp .env.example .env
```

3. Genera un hash bcrypt para la contraseña admin:

```bash
node -e "const bcrypt=require('bcrypt');bcrypt.hash(process.argv[1],12).then(h=>console.log(h));" "TuPasswordSuperSegura"
```

4. Pega ese hash en `ADMIN_PASSWORD_HASH` dentro de `.env`.

## Variables de entorno obligatorias

- `ADMIN_USER`
- `ADMIN_PASSWORD_HASH`
- `SESSION_SECRET`
- `PORT`
- `NODE_ENV`

Ejemplo en `.env.example`.

## Ejecutar

```bash
npm run dev
```

Servidor en `http://localhost:3000`.


## Checklist pre-push (recomendado)

Antes de hacer `git push`, valida localmente:

```bash
npm ci --no-audit --no-fund --ignore-scripts
node --check server.js
node --check public/app.js
node --check public/admin.js
node -e "JSON.parse(require('node:fs').readFileSync('data/content.json','utf8')); console.log('content.json OK')"
```

Además:
- Confirma que `.env` **no** está trackeado (solo `.env.example`).
- Revisa que `SESSION_SECRET` y `ADMIN_PASSWORD_HASH` se configuran solo en entorno seguro (GitHub/Render secrets).
- Verifica login/admin en local (`/login`, `/admin`) y web pública (`/`).

## Publicar en GitHub (repositorio)

1. Asegúrate de NO subir `.env` ni `node_modules` (ya están ignorados en `.gitignore`).
2. Inicializa git y haz tu primer commit:

```bash
git init
git branch -m main
git add .
git commit -m "Initial commit"
```

3. Crea un repositorio vacío en GitHub y añade el remoto:

```bash
git remote add origin https://github.com/TU_USUARIO/TU_REPO.git
git push -u origin main
```

## Despliegue en servidor de pruebas (Render)

1. Sube el proyecto a GitHub.
2. En Render crea un **Web Service** desde ese repositorio.
3. Render detectará `render.yaml` automáticamente.
4. Configura variables en Render:
   - `ADMIN_USER`
   - `ADMIN_PASSWORD_HASH`
   - `SESSION_SECRET`
   - `NODE_ENV=production` (ya definido en `render.yaml`)
5. Haz deploy y abre la URL pública que Render te asigna.

Comandos usados en Render:
- Build: `npm ci --no-audit --no-fund`
- Start: `npm start`
- Healthcheck: `GET /health`

Nota importante para pruebas:
- `data/content.json` se guarda en disco local del contenedor. En planes sin disco persistente, los cambios del admin pueden perderse tras redeploy/restart.

## Rutas

- `GET /` -> web pública (landing)
- `GET /styles.css` -> estilos de la web pública
- `GET /app.js` -> JavaScript de la web pública
- `GET /login` -> login admin
- `POST /login` -> autenticación (rate-limited)
- `POST /logout` -> cierre de sesión
- `GET /admin` -> panel (requiere sesión)
- `GET /api/content` -> contenido público
- `PUT /api/content` -> guardar contenido (requiere sesión + CSRF)
- `GET /api/csrf-token` -> token CSRF para formularios
- `GET /vendor/leaflet/*` -> assets locales de Leaflet (sin CDN)

## Seguridad implementada

- Password hasheada con bcrypt (validación solo server-side)
- Sesión con cookie `httpOnly`, `sameSite=strict`, `secure` en producción
- Rate limiting en `/login` por IP
- CSRF para operaciones de escritura (`POST`/`PUT`)
- Helmet + CSP estricta
- Validación server-side estricta del esquema JSON
- Sanitización básica de strings
- Logs de seguridad en `logs/audit.log`:
  - intentos fallidos de login
  - bloqueos por rate limit
  - cambios de contenido guardados
- Escritura atómica de `content.json` (tmp + rename)

## Notas de producción

- Ejecutar detrás de HTTPS (Nginx/reverse proxy o plataforma gestionada).
- Configurar `NODE_ENV=production`.
- Usar un `SESSION_SECRET` largo y aleatorio.
- El store en memoria de `express-session` es válido para desarrollo; en producción usar store persistente (Redis, etc.).

## Integración con la web pública

Desde la web pública consume el contenido así:

```js
const response = await fetch('/api/content');
const content = await response.json();
```

`/api/content` no expone secretos, solo textos públicos.
