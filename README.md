# CyberShield

> **Web Security SaaS for SMBs** — Scan any website for ~60 security vulnerabilities in under 90 seconds. No software installation required.

[![Live](https://img.shields.io/badge/Live-digitalcybershield.com-2dd4bf?style=flat-square)](https://digitalcybershield.com)
[![Stack](https://img.shields.io/badge/Stack-FastAPI%20·%20Supabase%20·%20Vercel-0d1117?style=flat-square)](#tech-stack)

---

## What It Does

CyberShield lets any business owner assess their website's security posture directly from a browser. The platform runs parallel async checks across 7 security categories and returns a scored, letter-graded report in 5–15 seconds.

**Check Categories:**
- SSL/TLS — certificate expiry, TLS version, weak ciphers, CT log, HSTS preload
- HTTP Security Headers — CSP (incl. unsafe-eval analysis), SRI audit, TRACE detection, sensitive path exposure
- Email Authentication — SPF, DKIM (11 selectors), DMARC policy strength, MTA-STS
- DNS — DNSSEC, CAA, AXFR zone transfer test, subdomain takeover detection (8 fingerprints)
- Open Ports — 15 ports (standard) to 50 ports (Max tier) including Docker API, K8s, etcd, Jupyter
- Malware / Reputation — VirusTotal 90-vendor consensus
- Sensitive Info Leak — /.env, /.git/config, backup files, phpinfo.php (Max tier)

**Scoring:** Critical (−22) · High (−12) · Medium (−6) · Low (−2) → Grades A+ through F

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5 / Vanilla JS — deployed on Vercel Edge Network |
| Backend API | FastAPI (Python 3.12) — deployed on Railway |
| Database | Supabase (PostgreSQL) |
| Authentication | Supabase Auth — email/password + Google OAuth SSO |
| Real-Time | Supabase WebSocket — live dashboard updates |
| Email | Resend API — scan reports and security alerts |
| Reputation | VirusTotal API — domain malware/phishing scoring |

---

## Subscription Tiers

| Feature | Free | Plus ($19/mo) | Max ($49/mo) |
|---|---|---|---|
| Domain Scans / Month | 5 | 50 | Unlimited |
| Security Checks | ~15 | ~35 | ~60 |
| Registered Domains | 1 | 5 | 20 |
| Code File Scans | 3 · 500 KB | 30 · 2 MB | Unlimited · 10 MB |
| Event Retention | 7 days | 90 days | 1 year |
| Auto-Scan Schedule | — | Weekly | Daily |
| Notifications | Email | Email + Slack + Discord | All channels |

---

## Repository Structure

```
CyberShield/
├── backend/
│   ├── main.py              # Scan engine + router (18 endpoints)
│   ├── customer_api.py      # Customer registration, domain management
│   ├── dashboard_api.py     # Dashboard data, resolve, rescan
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── vercel.json          # 20-route rewrite config
│   └── public/
│       ├── index.html       # Landing page
│       ├── dashboard.html   # Customer security dashboard (auth required)
│       ├── register.html    # Onboarding (email/password or Google SSO)
│       ├── blog*.html       # 12 bilingual (EN/KO) security posts
│       └── images/blog/     # SVG thumbnails for blog posts
├── sprint2/
│   └── agent/               # Go monitoring agent source (deprecated — kept for reference)
│       ├── main.go
│       ├── service_windows.go
│       └── go.mod
└── README.md
```

---

## API Reference

All endpoints hosted at `https://cybershield-10-production.up.railway.app`

### Scan Engine (`main.py`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/scan` | None | Standard domain scan — 6 modules |
| `POST` | `/scan/v2` | None | Tiered scan — Plus (10 modules) / Max (12 modules) |
| `POST` | `/scan/file` | None | Static code analysis — 14 vulnerability patterns |
| `GET` | `/health` | None | Service health check |

### Customer API (`customer_api.py`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/customer/register` | None | Register domain and create customer record |
| `POST` | `/customer/domain/add` | JWT | Add domain (Plus/Max only) |
| `DELETE` | `/customer/domain` | JWT | Remove a registered domain |
| `GET` | `/customer/domains` | JWT | List all domains with latest scan data |
| `POST` | `/customer/scan/trigger` | JWT | Trigger scan with quota enforcement |
| `POST` | `/customer/webhook` | JWT | Save Slack/Discord webhook URLs |
| `POST` | `/customer/schedule` | JWT | Update auto-scan schedule (Plus/Max only) |

### Dashboard API (`dashboard_api.py`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/dashboard/me` | JWT | Full dashboard data — score, chart, findings, events, quota |
| `GET` | `/dashboard/realtime-config` | JWT | Supabase Realtime subscription parameters |
| `POST` | `/dashboard/resolve` | JWT | Mark a finding as resolved |
| `POST` | `/dashboard/resolve-event` | JWT | Mark an event as reviewed |
| `POST` | `/dashboard/rescan` | JWT | Trigger immediate rescan |

---

## Local Development

### Backend

```bash
cd backend
pip install -r requirements.txt

# Set environment variables (do NOT hardcode these)
export RESEND_API_KEY="re_..."
export FROM_EMAIL="your@email.com"
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_KEY="your-service-role-key"
export SUPABASE_ANON_KEY="your-anon-key"
export VIRUSTOTAL_API_KEY="..."
export SITE_URL="http://localhost:3000"
export ADMIN_API_KEY="local_test"

uvicorn main:app --reload --port 8000
# Docs at http://localhost:8000/docs
```

### Frontend

```bash
cd frontend/public
python3 -m http.server 3000
```

For local API testing, update the `<meta name="api-url">` tag in `dashboard.html` and `register.html` to `http://localhost:8000`.

---

## Deployment

**Frontend (Vercel)** — auto-deploys on push:
```bash
git add -A && git commit -m "update" && git push
```
Vercel settings: Root Directory `./frontend` · Output Directory `public` · Framework: Other

**Backend (Railway):**
```bash
cd backend && railway up
```

**Required Environment Variables (Railway → Variables):**

| Variable | Purpose |
|---|---|
| `RESEND_API_KEY` | Email delivery |
| `FROM_EMAIL` | Sender address |
| `SUPABASE_URL` | Supabase project endpoint |
| `SUPABASE_KEY` | service_role key (server-side only) |
| `SUPABASE_ANON_KEY` | anon key for JWT verification |
| `VIRUSTOTAL_API_KEY` | Domain reputation scoring |
| `SITE_URL` | Base URL for internal calls |
| `ADMIN_API_KEY` | Auth for scheduled scan endpoint |

---

## Database Schema

5 core tables in Supabase PostgreSQL:

| Table | Purpose |
|---|---|
| `customers` | Customer records, domain, tier, webhook URLs |
| `scan_history` | Score trend data for 30-day chart |
| `scan_findings` | Persistent vulnerability records with resolve tracking |
| `scan_events` | Security event log — Realtime publication target |
| `customer_domains` | Multi-domain support per customer |

Initialise with: `Supabase → SQL Editor → sprint3_supabase_schema.sql → Run`

---

## Roadmap

- [ ] Stripe payment integration — auto-assign tier on subscription
- [ ] Railway cron job — automated weekly/daily scans for paid tiers
- [ ] CVE database correlation — match server versions against NVD records
- [ ] PDF security report export — downloadable for B2B reporting
- [ ] Multi-domain management UI — visual domain switcher

---

## Code Scanner — 14 Detected Patterns

Hardcoded API keys · Hardcoded secrets/passwords · AWS credentials · `os.getenv()` insecure fallbacks · SQL injection risks · JWT validation disabled (`verify=False`) · CORS wildcard (`*`) · Debug mode in production · Insecure deserialization (`pickle.loads`) · Open redirect · Path traversal (`../`) · Third-party service keys (Stripe, Twilio, SendGrid) · Email address exposure · Sensitive config exposure

---

*Built by [Jihun Baek](https://jihun.me) · June 2026*
