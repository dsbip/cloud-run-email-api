# Publishing this API reference to Confluence (via GitHub Pages)

This guide walks through the free, zero-app recommendation from earlier:
**host `docs.html` + `swagger.yaml` on GitHub Pages, then embed that URL in a
Confluence page using the Iframe macro.** End result: teammates open the
Confluence page and see the full interactive API reference — including the
`x-codeSamples` code panels — without installing anything.

Total one-time setup: ~5 minutes.
Ongoing cost: $0.

---

## What you'll end up with

- `https://dsbip.github.io/cloud-run-email-api/docs.html` — the Redoc-rendered
  API reference, publicly reachable over HTTPS.
- A Confluence page with an **Iframe** macro pointing at that URL. Every
  time you `git push` a swagger change to `master`, GitHub Pages re-publishes
  within ~60 seconds and the Confluence page shows the new version on
  next load.

---

## Prerequisites

- **Repo visibility:** GitHub Pages on the free tier requires a **public
  repository**. `dsbip/cloud-run-email-api` is currently public, so you're
  good. If you later make it private, you'll need GitHub Pro / Team /
  Enterprise to keep Pages working.
- **Files already in the repo:** `docs.html` and `swagger.yaml` at the
  repo root (both already committed — nothing to move).
- **Confluence permission:** ability to edit a Confluence page and insert
  the built-in **Iframe** macro. This macro is available on Confluence
  Cloud by default; on Server/DC it's the app named `confluence-iframe` or
  the "HTML Include" macro, both ship with Confluence.

---

## Part 1 — Turn on GitHub Pages

### Option A (recommended): Deploy straight from the `master` branch

Simplest possible setup, no workflow file needed.

1. Open the repo on GitHub: <https://github.com/dsbip/cloud-run-email-api>.
2. Click **Settings** (top-right of the repo nav bar — requires admin/owner
   access).
3. In the left sidebar, click **Pages**.
4. Under **Build and deployment**:
   - **Source:** `Deploy from a branch`
   - **Branch:** `master`
   - **Folder:** `/ (root)`
5. Click **Save**.
6. GitHub will start building. Refresh the page after ~30 seconds; the
   green box at the top will show:
   > Your site is live at
   > `https://dsbip.github.io/cloud-run-email-api/`

That root URL serves a directory listing (or your README rendered — GitHub
decides based on presence of `index.html`). The file you actually want to
link in Confluence is:

```
https://dsbip.github.io/cloud-run-email-api/docs.html
```

### Option B: Deploy via a GitHub Actions workflow

Use this only if you outgrow Option A — for example, if you want to
build the spec (lint, bundle, transform) before publishing, or if you
want deploys gated on a manual approval.

Create `.github/workflows/pages.yml` with:

```yaml
name: Deploy docs to GitHub Pages

on:
  push:
    branches: [master]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/checkout@v4

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          # Publish the whole repo root — small enough, and keeps
          # swagger.yaml next to docs.html so the relative spec-url works.
          path: .

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

Then in **Settings → Pages**, change **Source** to `GitHub Actions`.
Every push to `master` now publishes.

---

## Part 2 — Verify it works

1. In your browser, open
   <https://dsbip.github.io/cloud-run-email-api/docs.html>.
2. You should see the Redoc UI with three sections in the left nav
   (Health, Email) and a **Request samples** panel on the right of
   `POST /send-email` showing cURL / Python / Node / Go code with OIDC
   token generation.
3. If you get a 404, Pages is still building — wait a minute and retry.
4. If the left nav loads but the right panel is empty, `swagger.yaml`
   didn't load. Open DevTools → Network, look for the `swagger.yaml`
   request, and confirm it returns 200. If it's 404, make sure you
   committed `swagger.yaml` to `master` at the repo root.

---

## Part 3 — Embed in Confluence

### Confluence Cloud

1. Open the Confluence page where you want to publish the reference
   (or create a new one).
2. Click **Edit**.
3. Type `/iframe` → select **Iframe** from the slash-menu.
4. In the macro dialog:
   - **URL:** `https://dsbip.github.io/cloud-run-email-api/docs.html`
   - **Width:** `100%` (or a fixed pixel width if your page template
     is narrow)
   - **Height:** `1200` (or higher — Redoc's left nav scrolls
     independently, but the *outer* iframe doesn't auto-resize, so
     give it enough vertical space or users will see a nested
     scrollbar)
5. Click **Save** on the macro, then **Publish** the page.

### Confluence Server / Data Center

The native macro is called **HTML Include** or **iframe** (the exact
name depends on your admin's macro whitelist).

1. **Edit** the page.
2. Open the macro browser (**+** icon → *Other macros*).
3. Search for `iframe`. If the admin has whitelisted it, pick it.
   Otherwise ask the admin to whitelist `dsbip.github.io` under
   **Confluence admin → General Configuration → External Gadgets /
   Allowlist** (menu location varies by version).
4. Same field values as Cloud: URL, width `100%`, height `1200`.
5. **Save** and **Publish**.

---

## Things that commonly go wrong

| Symptom | Cause | Fix |
|---|---|---|
| Confluence shows a blank white rectangle | GitHub Pages sets `X-Frame-Options` only on a handful of paths; it should work for `*.github.io`. Double-check you used `dsbip.github.io`, **not** `raw.githubusercontent.com` — the latter sets `X-Frame-Options: deny` and will never embed. | Use the Pages URL. |
| 404 on `docs.html` | Pages build still running, or the file isn't on `master`. | Wait 60s; check **Settings → Pages** for the "site is live" banner. |
| Confluence says the URL is disallowed | Server/DC admin hasn't allowlisted the domain. | Ask admin to allowlist `dsbip.github.io`. |
| Redoc loads but shows "Failed to load spec" | Pages served `docs.html` but not `swagger.yaml`, or a CSP is blocking jsdelivr. | Confirm `swagger.yaml` is at the repo root; open DevTools → Console for the exact error. |
| Content is out of date | Your browser cached the old `swagger.yaml`. | Hard-refresh the Confluence page (`Ctrl+Shift+R`). Pages itself publishes within ~60s of a push. |

---

## If the repo ever has to go private

GitHub Pages on private repos requires a paid GitHub plan. Alternatives
that stay free:

- **Cloud Run, second service:** deploy `docs.html` + `swagger.yaml`
  together behind a tiny `nginx` container with `--allow-unauthenticated`
  (or behind IAP if you want auth).
- **GCS static site:** upload both files to a bucket with
  `gsutil web set`; serve from `storage.googleapis.com/<bucket>/`.
- **Netlify / Cloudflare Pages free tier:** point at the private
  repo (both support private sources on the free tier).

In all three cases, the Confluence-side setup (Iframe macro) is
identical — only the URL changes.

---

## Maintenance

Nothing special. Edit `swagger.yaml`, commit, push to `master`. GitHub
Pages republishes in under a minute, Confluence pulls the fresh version
on the next page load. No Confluence edit needed to pick up a spec
change — only re-edit the Confluence page if you want to change the
iframe height / width.
