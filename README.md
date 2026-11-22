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

## CV Writing & Revamping (paid service)
1. Admin > **CV Pricing**: add packages (New CV / Revamp) with price and currency.
2. Admin > **Payments**: add the bank account(s) customers should pay into. They are loaded from the database, never hardcoded.
3. Customers order at `#/cv` (or Services > CV Writing > Order), uploading their receipt.
4. Admin > **CV Orders**: check the transaction in your bank, then Approve or Reject payment, mark In Progress / Completed, and upload the finished PDF with **Send CV to Customer**.
5. Customers see the status under Profile > My CV Requests & Completed CVs, and can preview and download the PDF.
Files are kept in private R2 and are served only through the Worker.

### Sign-in gate and session length
When `GOOGLE_CLIENT_ID` is set, visitors must sign in with Google before they can open the site (the `#/admin` page is exempt). If `GOOGLE_CLIENT_ID` is not set, the site stays open so you are never locked out.
A sign-in lasts 1 year and renews itself whenever the person opens the site, so they are not asked to sign in again every day. They only need Google again if they sign out, clear their browser data, or you suspend the account.
