# Publishing this API reference to Confluence (via GitHub Pages *or* GitLab Pages)

This guide walks through the free, zero-app recommendation from earlier:
**host `docs.html` + `swagger.yaml` on a Pages platform, then embed that URL
in a Confluence page using the Iframe macro.** End result: teammates open the
Confluence page and see the full interactive API reference — including the
`x-codeSamples` code panels — without installing anything.

Two paths are documented below: **GitHub Pages** (Part 1A) and
**GitLab Pages** (Part 1B). Pick whichever platform hosts your repo; Parts 2
and 3 (verification + Confluence embedding) are identical for both.

Total one-time setup: ~5 minutes.
Ongoing cost: $0.

---

## What you'll end up with

- A public HTTPS URL like one of these, depending on where the repo lives:
  - GitHub: `https://<user>.github.io/<repo>/docs.html`
  - GitLab.com: `https://<group>.gitlab.io/<repo>/docs.html`
  - Self-hosted GitLab: `https://<pages-host>/<group>/<repo>/docs.html`
- A Confluence page with an **Iframe** macro pointing at that URL. Every
  time you push a swagger change to the default branch, Pages re-publishes
  within ~60 seconds and Confluence shows the new version on next load.

---

## Prerequisites

- **Repo visibility (GitHub):** the free tier serves Pages **only for
  public repos**. Private repos require GitHub Pro / Team / Enterprise.
- **Repo visibility (GitLab):** free tier supports **public *and* private**
  Pages — but private Pages uses an OAuth redirect that **breaks iframe
  embedding**. So for Confluence, you want the Pages site itself to be
  publicly reachable even if the repo is private (see Part 1B below for
  how to split those).
- **Files already in the repo:** `docs.html` and `swagger.yaml` at the
  repo root (both already committed — nothing to move).
- **Confluence permission:** ability to edit a Confluence page and insert
  the built-in **Iframe** macro. This macro ships with Confluence Cloud;
  on Server/DC the macro is `iframe` or `HTML Include`, both built-in.

---

## Part 1A — GitHub Pages

### Option A (recommended): Deploy straight from the default branch

Simplest possible setup, no workflow file needed.

1. Open the repo on GitHub (e.g., <https://github.com/dsbip/cloud-run-email-api>).
2. Click **Settings** (top-right of the repo nav — requires admin access).
3. Left sidebar → **Pages**.
4. Under **Build and deployment**:
   - **Source:** `Deploy from a branch`
   - **Branch:** `master`
   - **Folder:** `/ (root)`
5. Click **Save**.
6. Refresh after ~30 seconds. The green box shows:
   > Your site is live at `https://dsbip.github.io/cloud-run-email-api/`

The file to link in Confluence is:

```
https://dsbip.github.io/cloud-run-email-api/docs.html
```

### Option B: Deploy via a GitHub Actions workflow

Use this only if you outgrow Option A — e.g., if you want to lint or
bundle the spec before publishing, or gate deploys on manual approval.

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
          path: .       # publish repo root — swagger.yaml sits next to docs.html

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

Then in **Settings → Pages**, change **Source** to `GitHub Actions`.
Every push to `master` now publishes.

---

## Part 1B — GitLab Pages

GitLab Pages has no UI toggle — it's driven entirely by a CI job named
`pages` that produces a `public/` directory as an artifact. Any repo with
that job + a working CI runner gets a Pages site automatically.

### Option A (recommended): Minimal `.gitlab-ci.yml`

Create `.gitlab-ci.yml` at the repo root with:

```yaml
pages:
  stage: deploy
  image: alpine:latest
  script:
    - mkdir -p public
    - cp docs.html public/
    - cp swagger.yaml public/
  artifacts:
    paths:
      - public
  rules:
    # Only publish from the default branch (mirrors the GitHub "deploy from
    # master" behaviour). Feature branches won't clobber the live site.
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

Commit and push. Then:

1. Open the project on GitLab (`gitlab.com/<group>/<repo>` or your
   self-hosted instance).
2. Left sidebar → **Build → Pipelines**. You should see the `pages` job
   run and go green in 30–60 seconds.
3. Left sidebar → **Deploy → Pages**. You'll see the live URL listed,
   typically:
   - gitlab.com: `https://<group>.gitlab.io/<repo>/`
   - Self-hosted: `https://<pages-host>/<group>/<repo>/`
4. Verify **Access Control** at that same Pages page:
   - If the repo is **public**, Pages is public by default → iframe will
     work.
   - If the repo is **private**, toggle **"Pages access control"** to
     **off/disabled** under *Settings → General → Visibility, project
     features, permissions → Pages* (or in newer GitLab: *Deploy →
     Pages → Access control*). This makes the Pages site publicly
     reachable *even though the code repo stays private* — which is
     exactly what you want for Confluence embedding.

The file to link in Confluence is:

```
https://<group>.gitlab.io/<repo>/docs.html
```

### Option B: With a linting / bundling step

If you want the pipeline to fail on bad swagger before publishing:

```yaml
stages: [test, deploy]

lint_spec:
  stage: test
  image: node:20-alpine
  script:
    - npx --yes @redocly/cli@1 lint swagger.yaml

pages:
  stage: deploy
  image: alpine:latest
  needs: [lint_spec]
  script:
    - mkdir -p public
    - cp docs.html public/
    - cp swagger.yaml public/
  artifacts:
    paths:
      - public
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

`@redocly/cli lint` is MIT-licensed; no GitLab/Redocly account required.

### Self-hosted GitLab specifics

Everything above works identically on self-hosted GitLab **if your admin
has enabled Pages** for the instance (it's on by default since GitLab 16).
If the pipeline passes but `Deploy → Pages` shows "Pages is disabled",
ask the admin to enable it in `gitlab.rb`.

Pages URL on self-hosted often looks like `https://pages.<your-gitlab>/
<group>/<repo>/` — grab the exact form from the *Deploy → Pages* panel
rather than assuming.

---

## Part 2 — Verify it works

Works the same on either platform. Substitute the URL you got at the end
of Part 1A or Part 1B.

1. In your browser, open `<your-pages-url>/docs.html`.
2. You should see the Redoc UI: Health + Email sections in the left nav,
   and a **Request samples** panel on the right of `POST /send-email`
   showing cURL / Python / Node / Go code with OIDC token generation.
3. Still 404? Pages is still building — wait 60 seconds and retry.
   - GitHub: *Settings → Pages* shows build status.
   - GitLab: *Build → Pipelines* shows the `pages` job status.
4. Left nav loads but right panel is empty? `swagger.yaml` didn't load.
   Open DevTools → Network → look for the `swagger.yaml` request.
   - If 404, confirm `swagger.yaml` is at the repo root on the default
     branch.
   - If 401/403, your GitLab Pages "Access control" toggle is still on.

---

## Part 3 — Embed in Confluence

Works identically regardless of which Pages platform you used.

### Confluence Cloud

1. Open (or create) the Confluence page.
2. Click **Edit**.
3. Type `/iframe` → select **Iframe** from the slash-menu.
4. In the macro dialog:
   - **URL:** your `<pages-url>/docs.html`
   - **Width:** `100%`
   - **Height:** `1200` (Redoc's left nav scrolls independently, but the
     outer iframe doesn't auto-resize, so give it room)
5. **Save** the macro, then **Publish** the page.

### Confluence Server / Data Center

1. **Edit** the page.
2. Macro browser (**+** → *Other macros*).
3. Search for `iframe`. If whitelisted, pick it; otherwise ask admin to
   whitelist your Pages domain under *Confluence admin → General
   Configuration → External Gadgets / Allowlist* (menu path varies by
   version).
4. Same fields as Cloud: URL, width `100%`, height `1200`.
5. **Save** → **Publish**.

---

## Things that commonly go wrong

| Symptom | Platform | Cause | Fix |
|---|---|---|---|
| Confluence shows a blank white rectangle | Both | Content-Security / `X-Frame-Options` blocks embedding | Confirm you used the Pages host (`*.github.io` / `*.gitlab.io`). **Never** use `raw.githubusercontent.com` or `gitlab.com/<group>/<repo>/-/raw/...` — both set `X-Frame-Options: deny` |
| 404 on `docs.html` | GitHub | Build still running, or file not on `master` | Wait 60s; check *Settings → Pages* for the "site is live" banner |
| 404 on `docs.html` | GitLab | `pages` job hasn't run, or ran but failed | Check *Build → Pipelines*; common causes: no runner attached, `.gitlab-ci.yml` syntax error, `public/` not produced |
| Confluence says the URL is disallowed | Both (Server/DC only) | Admin hasn't allowlisted the Pages domain | Ask admin to allowlist `github.io` / `gitlab.io` (or your self-hosted Pages host) |
| Redoc loads but shows "Failed to load spec" | Both | `swagger.yaml` 404, or a CSP is blocking jsdelivr | DevTools → Console for the exact error; confirm `swagger.yaml` sits next to `docs.html` in the published output |
| GitLab Pages site demands a login before loading | GitLab | Private-project Pages with access control on | Toggle off *Deploy → Pages → Access control* (or in older GitLab, *Settings → General → Pages*). This decouples the Pages site's public visibility from the repo's visibility |
| `pages` job fails with "public directory is missing" | GitLab | Script didn't actually produce `public/` (typo, wrong image, missing file) | Open the job log; verify `mkdir -p public` ran and the `cp` commands didn't silently fail |
| Content is out of date | Both | Browser / CDN cache | Hard-refresh the Confluence page (`Ctrl+Shift+R`); Pages itself publishes within ~60s |

---

## Private-repo scenarios — platform comparison

| Option | GitHub | GitLab |
|---|---|---|
| **Repo private + Pages public** | Paid plan (Pro/Team/Enterprise) | **Free** — set Pages Access Control to public |
| **Repo private + Pages gated** | Paid plan | **Free** — leave Access Control on (but iframe will not work cleanly; OAuth redirect breaks inside Confluence) |
| **Repo public** | Free | Free |

If the repo has to stay private **and** the Pages site must be gated (not
public), iframe embedding stops being practical on either platform. Fall
back to one of these:

- **Cloud Run, second service:** deploy `docs.html` + `swagger.yaml`
  behind a tiny nginx container, either with `--allow-unauthenticated`
  (for team-accessible docs) or gated by IAP.
- **GCS static site:** upload both files to a bucket, apply a
  public-read IAM policy, serve from
  `https://storage.googleapis.com/<bucket>/docs.html`.
- **Netlify / Cloudflare Pages free tier:** both support private
  source repos on the free tier and publish to a public URL.

Confluence-side setup (Iframe macro) is identical — only the URL
changes.

---

## Maintenance

Nothing special. Edit `swagger.yaml`, commit, push to the default
branch. Pages republishes in under a minute; Confluence pulls the fresh
version on next page load. No Confluence edit needed to pick up spec
changes — only re-edit the Confluence page if you want to change the
iframe height or width.
