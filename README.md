# LinguaLink Admin API

An Express + TypeScript admin backend for LinguaLink. Provides secure endpoints for moderation and operations: ban/unban users, manage roles (admin/moderator), grant language roles (validator/ambassador), and fetch platform statistics. Ships with Swagger docs and Supabase admin integration.

## Stack
- Node.js + TypeScript (ESM)
- Express, CORS, Helmet, rate limiting
- Swagger (swagger-jsdoc + swagger-ui-express)
- Supabase Admin client (@supabase/supabase-js)
- JWT-based admin auth
- Pino logging

## Getting started
1) Install dependencies
```bash
npm install
```

2) Environment variables (create `.env` in project root)
```
PORT=4000
CORS_ORIGINS=http://localhost:3000
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
ADMIN_JWT_SECRET=your_strong_random_secret
```
Notes:
- SUPABASE_SERVICE_ROLE_KEY must never be exposed to clients. Keep on server.
- Generate a strong secret (Windows PowerShell):
  ```powershell
  node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))'
  ```

3) Run in development
```bash
npm run dev
```
Browse Swagger UI at `http://localhost:4000/docs`.

4) Build and start
```bash
npm run build
npm start
```

## Auth (Admin)
All `/admin/*` routes require a Bearer JWT signed with `ADMIN_JWT_SECRET` and payload containing `role: "admin" | "superadmin"`.

Example (PowerShell) to mint a local token:
```powershell
$env:ADMIN_JWT_SECRET="your_secret_here"
node -e 'console.log(require("jsonwebtoken").sign({role:"admin",sub:"local-admin"}, process.env.ADMIN_JWT_SECRET,{expiresIn:"15m"}))'
```
Use in requests: `Authorization: Bearer <token>`

## Routes (initial)
- `GET /health` – liveness probe (no auth)
- `GET /docs` – Swagger UI
- `GET /admin/overview` – protected example returning basic counts

Planned modules:
- Users: ban/unban, admin promote/demote
- Language roles: grant/revoke validator/ambassador (per language)
- Stats: top languages/countries, growth, validation quality
- Audit: list admin actions

## Conventions
- Strict input validation with Zod (to be added on endpoints)
- Rate limit sensitive routes
- Write admin actions to an `admin_actions` audit table for traceability
- Prefer Postgres materialized views for heavy stats; refresh on schedule

## Deployment
- Any Node host (Render/Fly.io/Vercel functions)
- Ensure env vars are set; restrict `/docs` in production (IP allowlist or auth)
- Set `CORS_ORIGINS` to your dashboard origins

## Troubleshooting
- ESM dev errors: use `npm run dev` (tsx). Ensure `type: module` and tsconfig `module: NodeNext`.
- 401/403 on admin routes: ensure valid JWT signed with `ADMIN_JWT_SECRET` and `role` is `admin`/`superadmin`.
- Supabase errors: verify `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`.

---
Maintainers: keep secrets out of VCS; rotate `ADMIN_JWT_SECRET` and service role keys periodically.
