# IPHS 400: Frontiers in AI

**Kenyon College — Integrated Program for Humane Studies (IPHS) — Fall 2026**

Course website for IPHS 400, a hands-on study of AI software engineering (AI-SWE):
configuring, extending, and orchestrating AI coding agents through a professional
software development lifecycle. This repository contains the site's source and
its test suite; course submissions, quizzes, and grades are handled separately
on Moodle.

- **Instructor:** Jon Chun
- **Schedule:** Tu/Th, 2:40–4:00 PM · Timberlake #5 (Evans Conference Room)
- **Live site:** https://theailab.net

## Repository Structure

```
.
├── index.html              # Home page
├── 404.html                 # Not-found page
├── core/                    # Syllabus, schedule, assignments, policies, about
│   ├── syllabus.html
│   ├── schedule.html
│   ├── assignments.html
│   ├── policies.html
│   └── about.html
├── weeks/                   # One page per week, week-01.html … week-15.html
├── css/
│   └── style.css            # Single shared stylesheet, no build step
├── netlify/functions/       # Login, session and Google sign-in functions
├── tests/                   # pytest suite validating the site
│   ├── conftest.py
│   ├── test_unit_html_structure.py
│   ├── test_integration_links.py
│   ├── test_e2e_site.py
│   ├── requirements.txt
│   └── js/                  # Node tests for the sign-in functions (node --test)
└── .github/workflows/       # CI: deploy to Netlify on push to main
```

The site is static HTML/CSS with no build step or JS framework. Every page
shares one stylesheet and a common header/nav/hero/footer skeleton. Login,
session and Google sign-in run as Netlify Functions in `netlify/functions/`.

## Local Development

Serve the site locally with Python's built-in HTTP server:

```bash
python3 -m http.server 8080
# then open http://localhost:8080/
```

No install step is required to view the static pages. The login, session and
Google sign-in functions only run under Netlify Dev (`npx netlify dev`, which
serves the site and the functions on `http://localhost:8888`); the plain
Python server above does not execute them. Use a separate test site, a
development Google client and a test session secret for local runs, never
production values.

## Running the Tests

The test suite (pytest + BeautifulSoup/lxml) validates structural and content
integrity of every page:

- `test_unit_html_structure.py` — every page has a DOCTYPE, title, stylesheet
  link, header, footer, and hero `<h1>`; no leftover template branding; no
  placeholder or stub content
- `test_integration_links.py` — every internal link resolves; navigation is
  identical across all pages; the schedule links to all 15 week pages
- `test_e2e_site.py` — required files/directories exist; exact page count;
  every page is reachable from `index.html` (no orphaned pages)

```bash
uv run --no-project --with pytest --with beautifulsoup4 --with lxml pytest tests/ -q
```

Run a single test file or test:

```bash
uv run --no-project --with pytest --with beautifulsoup4 --with lxml pytest tests/test_unit_html_structure.py -v
uv run --no-project --with pytest --with beautifulsoup4 --with lxml pytest tests/test_integration_links.py::TestNavConsistency::test_nav_links_resolve -v
```

The Node tests for the sign-in functions need no installed packages and make
no network requests:

```bash
node --test tests/js/*.test.mjs
```

## Deployment

The site deploys to Netlify automatically on every push to `main` via
[`.github/workflows/deploy-netlify.yml`](.github/workflows/deploy-netlify.yml).
The workflow publishes the repository root and requires two repository
secrets, set under **Settings → Secrets and variables → Actions**:

| Secret | Description |
|---|---|
| `NETLIFY_AUTH_TOKEN` | A Netlify personal access token |
| `NETLIFY_SITE_ID` | The target Netlify site's API ID |

Until those secrets are configured, the workflow run will fail at the deploy
step — everything else (checkout) will still succeed. Deployment can also be
triggered manually from the Actions tab (`workflow_dispatch`).

## Runtime configuration

The secrets above only deploy the site. The login and Google sign-in functions
and the course gate read their settings at runtime from the Netlify site
settings (Netlify UI, production context, Functions scope). Never put these
values in `netlify.toml`, in GitHub secrets, or in this repository. The values
below are placeholders only.

| Variable | Required / default | Purpose |
|---|---|---|
| `SESSION_SECRET` | existing, required | High-entropy secret that signs sessions; also the input for the separate OAuth key. Placeholder `<SESSION_SECRET>`. |
| `GATE_ENABLED` | existing | The literal `false` keeps the course gate off on the live site. Set `true` only in a separate, verified deploy. |
| `GOOGLE_OAUTH_ENABLED` | new; disabled unless exactly `true` | Kill switch for both Google sign-in endpoints. Any other value, or no value, returns 503 from them. |
| `GOOGLE_CLIENT_ID` | new | `<CLIENT_ID>.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | new, secret | `<GOOGLE_CLIENT_SECRET>` |
| `SITE_URL` | new, required | Exactly `https://theailab.net` in production; `http://localhost:8888` or `https://localhost:8888` locally. No path, query, credentials, fragment or trailing slash. |
| `ADMIN_EMAILS` | new; empty means no Google admins | Comma-separated exact Google emails that receive the admin role. Placeholder `<ADMIN_GOOGLE_EMAIL>`. No wildcards. |
| `AUTO_APPROVE_EMAILS` | new; optional, empty | Comma-separated exact Gmail or Kenyon roster emails approved automatically. |
| `AUTO_APPROVE_DOMAINS` | new; optional, empty | The only supported value is `kenyon.edu`, checked against Google's hosted-domain claim. |
| `ADMIN_NOTIFY_EMAIL` | new; optional | One instructor address notified of new pending accounts. Placeholder `<NOTIFICATION_EMAIL>`. If unset, check the admin queue directly. |
| `RESEND_API_KEY`, `MAIL_FROM` | existing, optional | Mail settings. Missing or failing mail never blocks the approval queue. |
| `ADMIN_BOOTSTRAP_SECRET` | existing | Recovery path for creating the first password admin. Keep it secured; disable it once Google admin access is tested. |
| `AWS_LAMBDA_JS_RUNTIME` | set in the Netlify UI | `nodejs22.x`, applied at deployment. |

Netlify captures these values at deploy time. **Redeploy after any change**,
including `GATE_ENABLED`, the kill switch, roster and admin lists, the client
secret and the session secret. To switch Google sign-in off, set
`GOOGLE_OAUTH_ENABLED` to `false` and redeploy; password login keeps working.
Rotating `SESSION_SECRET` and redeploying logs everyone out.

Rollout notes for the owner (full detail in the private spec,
`dev/tech-spec_implement-google-oauth_v2_20261011.md`, which is not published):

- **Phase 0, console setup:** create the Google Web OAuth client and consent
  branding, register the callback
  `https://theailab.net/.netlify/functions/google-callback`, and keep
  `GOOGLE_OAUTH_ENABLED` and `GATE_ENABLED` at `false` while preparing. Back up
  the user store privately first.
- **Phase 3, owner-led publication:** the owner reviews and commits the
  implementation, runs the guarded sync from the private repository, and pushes
  the public repository. Deploy with the kill switch off, verify that the Google
  endpoints return 503 and password login still works, then set
  `GOOGLE_OAUTH_ENABLED` to `true`, redeploy, and run the browser checks. Leave
  `GATE_ENABLED` at `false` during the soak.

## Content Source and Provenance

All course content (syllabus text, schedule, assignments, policies) is
sourced from the official Fall 2026 syllabus. The page layout, navigation
pattern, and stylesheet are adapted from a prior Kenyon course site
([`programminghumanity-org`](https://github.com/jon-chun)) for visual
consistency across Jon Chun's Kenyon course sites; no course content from
that site is reused here.

## License

See [LICENSE](LICENSE).
