# M-RECRUITS

Cloudflare Worker + Static Assets + D1 (database) + R2 (files).

## Files
- `public/index.html` – whole frontend (plus `public/img/hero-team.jpg`)
- `worker.js` – backend API. It also creates all D1 tables automatically (see the top of the database block).
- `wrangler.toml` – bindings: `DB` (D1, ID already set), `MEDIA_BUCKET` (R2), `ASSETS`
- `package.json`, `.gitignore`

## Deploy
1. `npm install`
2. `npx wrangler login`
3. Create the R2 bucket once: `npx wrangler r2 bucket create m-recruits-media`
4. Set secrets (any long random text):
   - `npx wrangler secret put ADMIN_BOOTSTRAP_SECRET`
   - `npx wrangler secret put SESSION_SECRET`
5. `npm run deploy`
6. Open the site once. The first API call creates every table in D1 by itself.
7. Create the first admin (one time only, works only while no admin exists):
   ```
   curl -X POST https://YOUR-WORKER-URL/api/admin/bootstrap \
     -H "content-type: application/json" \
     -d '{"secret":"<ADMIN_BOOTSTRAP_SECRET>","email":"you@example.com","password":"at-least-12-characters"}'
   ```
8. Custom domain: Cloudflare dashboard > Workers > m-recruits > Settings > Domains & Routes. Then set `ALLOWED_ORIGIN` in `wrangler.toml` to that domain and deploy again.

## Local development
Create a file named `.dev.vars` (it is ignored by git) containing two lines, `ADMIN_BOOTSTRAP_SECRET=...` and `SESSION_SECRET=...`, then run `npm run dev`.

## Changing the database later
Edit the `TABLES`, `COLS` or `AFTER` lists at the top of `worker.js`, raise `SCHEMA_VERSION` by 1, deploy. It applies automatically.

## Not built yet
Admin panel screens (the admin API exists), settings/integrations vault, sitemap/robots, CSV export, interview scheduling.

## Admin panel
Open `https://YOUR-SITE/#/admin` (not shown in the menu). First time: use "First-time setup" with your `ADMIN_BOOTSTRAP_SECRET`, then sign in. Manage Jobs, Applications, Banners (Home only) and Categories there.
