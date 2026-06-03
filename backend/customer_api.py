"""
CyberShield — Customer API (Direction 2: Domain Scan SaaS)

Replaces agent_api.py. No agent installation required.

Endpoints:
  POST /customer/register     — sign up + add first domain
  POST /customer/domain/add   — add another domain (Plus/Max)
  DELETE /customer/domain     — remove a domain
  GET  /customer/domains      — list all domains for this customer
  POST /customer/scan/trigger — manual scan trigger
  POST /customer/webhook      — save Slack/Discord webhook
  GET  /customer/schedule     — get scan schedule for customer
  POST /customer/schedule     — update scan schedule (Plus/Max only)
"""

import os, secrets, string, hashlib, logging, asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel
import httpx

logger = logging.getLogger("cybershield.customer")

customer_router = APIRouter()

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")

# ── Tier limits ───────────────────────────────────────────────────────────────
TIER_LIMITS = {
    "free": {
        "domains":              1,
        "scans_per_month":      5,
        "file_scans_per_month": 3,
        "file_max_kb":          500,
        "schedule":             None,        # no auto-scan
        "event_retention_days": 7,
        "scan_modules":         "basic",
    },
    "plus": {
        "domains":              5,
        "scans_per_month":      50,
        "file_scans_per_month": 30,
        "file_max_kb":          2048,
        "schedule":             "weekly",    # auto-scan once a week
        "event_retention_days": 90,
        "scan_modules":         "deep",
    },
    "max": {
        "domains":              20,
        "scans_per_month":      999999,
        "file_scans_per_month": 999999,
        "file_max_kb":          10240,
        "schedule":             "daily",     # auto-scan every day
        "event_retention_days": 365,
        "scan_modules":         "expert",
    },
}

TIER_SCAN_ENDPOINT = {
    "free":  "/scan",
    "plus":  "/scan/v2",
    "max":   "/scan/v2",
}

TIER_SCAN_PAYLOAD_EXTRA = {
    "free":  {},
    "plus":  {"tier": "plus"},
    "max":   {"tier": "max"},
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def generate_id(prefix="cust"):
    alphabet = string.ascii_lowercase + string.digits
    return f"{prefix}_{''.join(secrets.choice(alphabet) for _ in range(16))}"


async def sb_get(table: str, params: str, limit: int = 100) -> list:
    if not (SUPABASE_URL and SUPABASE_KEY):
        return []
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(
                f"{SUPABASE_URL}/rest/v1/{table}?{params}&limit={limit}",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
            )
        return r.json() if r.status_code == 200 else []
    except Exception as e:
        logger.error(f"sb_get {table}: {e}")
        return []


async def sb_insert(table: str, data: dict) -> dict | None:
    if not (SUPABASE_URL and SUPABASE_KEY):
        return None
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.post(
                f"{SUPABASE_URL}/rest/v1/{table}",
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=representation",
                },
                json=data,
            )
        if r.status_code in (200, 201):
            rows = r.json()
            return rows[0] if rows else {}
        logger.error(f"sb_insert {table} error {r.status_code}: {r.text[:200]}")
    except Exception as e:
        logger.error(f"sb_insert {table}: {e}")
    return None


async def sb_patch(table: str, params: str, data: dict):
    if not (SUPABASE_URL and SUPABASE_KEY):
        return
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            await c.patch(
                f"{SUPABASE_URL}/rest/v1/{table}?{params}",
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                    "Content-Type": "application/json",
                },
                json=data,
            )
    except Exception as e:
        logger.error(f"sb_patch {table}: {e}")


async def sb_delete(table: str, params: str):
    if not (SUPABASE_URL and SUPABASE_KEY):
        return
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            await c.delete(
                f"{SUPABASE_URL}/rest/v1/{table}?{params}",
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                },
            )
    except Exception as e:
        logger.error(f"sb_delete {table}: {e}")


async def verify_jwt(authorization: str | None) -> dict:
    """Verify Supabase JWT and return user payload."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Authorization header")
    token = authorization.split(" ", 1)[1]
    if not (SUPABASE_URL and SUPABASE_ANON_KEY):
        raise HTTPException(500, "Supabase not configured")
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(
                f"{SUPABASE_URL}/auth/v1/user",
                headers={"Authorization": f"Bearer {token}", "apikey": SUPABASE_ANON_KEY},
            )
        if r.status_code != 200:
            raise HTTPException(401, "Invalid or expired session")
        return r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(401, f"Auth error: {e}")


async def get_customer_by_email(email: str) -> dict | None:
    rows = await sb_get("customers", f"email=eq.{email}", 1)
    return rows[0] if rows else None


# ── Pydantic Models ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:           str
    domain:          str
    lang:            str = "ko"
    slack_webhook:   Optional[str] = ""
    discord_webhook: Optional[str] = ""

class DomainAddRequest(BaseModel):
    domain: str

class WebhookRequest(BaseModel):
    slack_webhook:   Optional[str] = ""
    discord_webhook: Optional[str] = ""

class ScheduleRequest(BaseModel):
    schedule: str   # "none" | "weekly" | "daily"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@customer_router.post("/customer/register")
async def register_customer(req: RegisterRequest):
    """
    Called when a logged-in user registers their first domain.
    Creates a customers row linked to their Supabase Auth email.
    No agent token is issued — authentication is done via Supabase JWT.
    """
    # Check if already registered
    existing = await get_customer_by_email(req.email)
    if existing:
        # Update domain if different, return existing customer
        if existing.get("domain") != req.domain:
            await sb_patch("customers", f"email=eq.{req.email}",
                           {"domain": req.domain})
        return {
            "customer_id": existing["customer_id"],
            "domain":      req.domain,
            "tier":        existing.get("tier", "free"),
            "message":     "Domain updated for existing account.",
        }

    customer_id = generate_id("cust")
    tier = "free"
    now = datetime.now(timezone.utc).isoformat()

    customer_data = {
        "customer_id":     customer_id,
        "email":           req.email,
        "domain":          req.domain,
        "lang":            req.lang,
        "tier":            tier,
        "slack_webhook":   req.slack_webhook or "",
        "discord_webhook": req.discord_webhook or "",
        "created_at":      now,
    }

    await sb_insert("customers", customer_data)

    # Insert into customer_domains table as well
    await sb_insert("customer_domains", {
        "customer_id": customer_id,
        "domain":      req.domain,
        "is_primary":  True,
        "added_at":    now,
        "next_scan_at": now,
    })

    logger.info(f"New customer registered: {customer_id} ({req.email}, {req.domain})")
    return {
        "customer_id": customer_id,
        "domain":      req.domain,
        "tier":        tier,
        "message":     "Account created. Run your first scan from the dashboard.",
    }


@customer_router.post("/customer/domain/add")
async def add_domain(req: DomainAddRequest,
                     authorization: Optional[str] = Header(None)):
    """Add another domain to monitor (Plus: up to 5, Max: up to 20)."""
    user  = await verify_jwt(authorization)
    email = user.get("email", "")
    cust  = await get_customer_by_email(email)
    if not cust:
        raise HTTPException(404, "Account not found. Register first.")

    tier  = cust.get("tier", "free")
    limit = TIER_LIMITS[tier]["domains"]

    # Count existing domains
    existing_domains = await sb_get(
        "customer_domains",
        f"customer_id=eq.{cust['customer_id']}", 100
    )
    if len(existing_domains) >= limit:
        raise HTTPException(403, {
            "error":      "domain_limit_reached",
            "message_ko": f"현재 요금제({tier})에서는 최대 {limit}개 도메인까지 등록 가능합니다.",
            "message_en": f"Your {tier} plan supports up to {limit} domain(s). Upgrade to add more.",
            "limit":      limit,
            "current":    len(existing_domains),
        })

    # Check not duplicate
    for d in existing_domains:
        if d.get("domain") == req.domain:
            raise HTTPException(409, "Domain already registered.")

    await sb_insert("customer_domains", {
        "customer_id": cust["customer_id"],
        "domain":      req.domain,
        "is_primary":  False,
        "added_at":    datetime.now(timezone.utc).isoformat(),
        "next_scan_at": datetime.now(timezone.utc).isoformat(),
    })
    logger.info(f"Domain added: {req.domain} for {cust['customer_id']}")
    return {"status": "ok", "domain": req.domain}


@customer_router.delete("/customer/domain")
async def remove_domain(domain: str,
                        authorization: Optional[str] = Header(None)):
    """Remove a domain from monitoring."""
    user  = await verify_jwt(authorization)
    email = user.get("email", "")
    cust  = await get_customer_by_email(email)
    if not cust:
        raise HTTPException(404, "Account not found.")

    await sb_delete(
        "customer_domains",
        f"customer_id=eq.{cust['customer_id']}&domain=eq.{domain}"
    )
    return {"status": "ok", "removed": domain}


@customer_router.get("/customer/domains")
async def list_domains(authorization: Optional[str] = Header(None)):
    """List all domains registered by this customer with latest scan info."""
    user  = await verify_jwt(authorization)
    email = user.get("email", "")
    cust  = await get_customer_by_email(email)
    if not cust:
        raise HTTPException(404, "Account not found.")

    cid     = cust["customer_id"]
    domains = await sb_get("customer_domains", f"customer_id=eq.{cid}", 100)

    # Enrich each domain with latest scan result
    enriched = []
    for d in domains:
        dom = d["domain"]
        history = await sb_get(
            "scan_history",
            f"customer_id=eq.{cid}&domain=eq.{dom}&order=scanned_at.desc",
            1,
        )
        latest = history[0] if history else {}
        enriched.append({
            "domain":       dom,
            "is_primary":   d.get("is_primary", False),
            "last_score":   latest.get("score"),
            "last_grade":   latest.get("grade"),
            "last_scanned": latest.get("scanned_at"),
            "next_scan_at": d.get("next_scan_at"),
            "added_at":     d.get("added_at"),
        })

    return {
        "customer_id": cid,
        "tier":        cust.get("tier", "free"),
        "domains":     enriched,
        "limits":      TIER_LIMITS.get(cust.get("tier", "free")),
    }


@customer_router.post("/customer/scan/trigger")
async def trigger_manual_scan(domain: Optional[str] = None,
                              authorization: Optional[str] = Header(None)):
    """
    Manually trigger a scan for a domain.
    Respects monthly scan quota.
    Returns immediately — scan runs in background.
    """
    user  = await verify_jwt(authorization)
    email = user.get("email", "")
    cust  = await get_customer_by_email(email)
    if not cust:
        raise HTTPException(404, "Account not found.")

    cid  = cust["customer_id"]
    tier = cust.get("tier", "free")

    # Use primary domain if none specified
    if not domain:
        domain = cust.get("domain", "")
    if not domain:
        raise HTTPException(400, "No domain specified or registered.")

    # Quota check
    limit = TIER_LIMITS[tier]["scans_per_month"]
    if limit < 999999:
        month_start = datetime.now(timezone.utc).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        ).isoformat()
        history = await sb_get(
            "scan_history",
            f"customer_id=eq.{cid}&scanned_at=gte.{month_start}&select=id",
            999,
        )
        used = len(history)
        if used >= limit:
            raise HTTPException(429, {
                "error":      "quota_exceeded",
                "message_ko": f"이번 달 스캔 횟수({limit}회)를 모두 사용했습니다. 업그레이드하면 더 많이 스캔할 수 있습니다.",
                "message_en": f"You've used all {limit} scans for this month. Upgrade for more.",
                "used":  used,
                "limit": limit,
                "tier":  tier,
            })

    # Kick off scan asynchronously via internal HTTP call
    site_url = os.getenv("SITE_URL", "https://cybershield-10-production.up.railway.app")
    scan_endpoint = f"{site_url}{TIER_SCAN_ENDPOINT[tier]}"
    payload = {
        "domain":      domain,
        "email":       email,
        "lang":        cust.get("lang", "ko"),
        "customer_id": cid,
        **TIER_SCAN_PAYLOAD_EXTRA[tier],
    }

    async def _run_scan():
        try:
            async with httpx.AsyncClient(timeout=120) as c:
                r = await c.post(scan_endpoint, json=payload)
                if r.status_code == 200:
                    logger.info(f"Background scan complete: {domain} ({tier})")
                    # Send webhook notification with scan result
                    result = r.json()
                    await send_scan_notification(cust, domain, result)
                else:
                    logger.warning(f"Background scan error {r.status_code}: {r.text[:200]}")
        except Exception as e:
            logger.error(f"Background scan failed for {domain}: {e}")

    asyncio.create_task(_run_scan())

    return {
        "status":      "queued",
        "domain":      domain,
        "tier":        tier,
        "message_ko":  f"{domain} 스캔이 시작됐습니다. 30~90초 후 대시보드에 업데이트됩니다.",
        "message_en":  f"Scan started for {domain}. Dashboard updates in 30–90 seconds.",
    }


@customer_router.post("/customer/webhook")
async def update_webhooks(req: WebhookRequest,
                          authorization: Optional[str] = Header(None)):
    """Update Slack / Discord webhook URLs."""
    user  = await verify_jwt(authorization)
    email = user.get("email", "")
    cust  = await get_customer_by_email(email)
    if not cust:
        raise HTTPException(404, "Account not found.")

    await sb_patch("customers", f"email=eq.{email}", {
        "slack_webhook":   req.slack_webhook or "",
        "discord_webhook": req.discord_webhook or "",
    })
    return {"status": "ok"}


@customer_router.get("/customer/schedule")
async def get_schedule(authorization: Optional[str] = Header(None)):
    """Get the current auto-scan schedule for this customer."""
    user  = await verify_jwt(authorization)
    email = user.get("email", "")
    cust  = await get_customer_by_email(email)
    if not cust:
        raise HTTPException(404, "Account not found.")

    tier     = cust.get("tier", "free")
    schedule = cust.get("scan_schedule") or TIER_LIMITS[tier]["schedule"] or "none"
    return {
        "tier":            tier,
        "schedule":        schedule,
        "allowed_values":  ["none"] if tier == "free" else ["none", "weekly", "daily"],
        "next_scan_at":    cust.get("next_scan_at"),
    }


@customer_router.post("/customer/schedule")
async def update_schedule(req: ScheduleRequest,
                          authorization: Optional[str] = Header(None)):
    """Update auto-scan schedule (Plus: weekly/none, Max: daily/weekly/none)."""
    user  = await verify_jwt(authorization)
    email = user.get("email", "")
    cust  = await get_customer_by_email(email)
    if not cust:
        raise HTTPException(404, "Account not found.")

    tier = cust.get("tier", "free")
    if tier == "free":
        raise HTTPException(403, {
            "error":      "upgrade_required",
            "message_ko": "자동 스캔 스케줄은 Plus 이상 요금제에서 사용 가능합니다.",
            "message_en": "Auto-scan schedule requires Plus or Max plan.",
        })

    allowed = {"plus": ["none", "weekly"], "max": ["none", "weekly", "daily"]}
    if req.schedule not in allowed.get(tier, []):
        raise HTTPException(400, f"Invalid schedule for {tier} tier. Allowed: {allowed[tier]}")

    now = datetime.now(timezone.utc)
    if req.schedule == "daily":
        next_scan = (now + timedelta(days=1)).isoformat()
    elif req.schedule == "weekly":
        next_scan = (now + timedelta(weeks=1)).isoformat()
    else:
        next_scan = None

    await sb_patch("customers", f"email=eq.{email}", {
        "scan_schedule": req.schedule,
        "next_scan_at":  next_scan,
    })
    return {
        "status":     "ok",
        "schedule":   req.schedule,
        "next_scan":  next_scan,
    }


# ── Scheduled scan runner (called by cron or daily task) ─────────────────────

@customer_router.post("/internal/run-scheduled-scans")
async def run_scheduled_scans(request: Request):
    """
    Internal endpoint — called by a cron job or Railway cron task.
    Finds all customers whose next_scan_at is in the past and runs their scan.
    Secured by ADMIN_API_KEY.
    """
    expected = os.getenv("ADMIN_API_KEY", "")
    provided = request.headers.get("x-admin-key", "")
    if not expected or provided != expected:
        raise HTTPException(403, "Unauthorized")

    now = datetime.now(timezone.utc).isoformat()
    due = await sb_get(
        "customers",
        f"next_scan_at=lte.{now}&scan_schedule=neq.none&select=customer_id,email,domain,tier,lang,scan_schedule",
        100,
    )

    triggered = []
    for cust in due:
        cid    = cust.get("customer_id")
        domain = cust.get("domain", "")
        tier   = cust.get("tier", "free")
        email  = cust.get("email", "")

        if not domain:
            continue

        # Compute next scan time
        schedule = cust.get("scan_schedule", "none")
        if schedule == "daily":
            next_t = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        elif schedule == "weekly":
            next_t = (datetime.now(timezone.utc) + timedelta(weeks=1)).isoformat()
        else:
            next_t = None

        # Update next_scan_at immediately so it won't be picked up again
        await sb_patch("customers", f"customer_id=eq.{cid}",
                       {"next_scan_at": next_t})

        # Run scan
        site_url = os.getenv("SITE_URL", "https://cybershield-10-production.up.railway.app")
        scan_ep  = f"{site_url}{TIER_SCAN_ENDPOINT.get(tier, '/scan')}"
        payload  = {"domain": domain, "email": email,
                    "lang": cust.get("lang", "ko"), "customer_id": cid,
                    **TIER_SCAN_PAYLOAD_EXTRA.get(tier, {})}

        async def _run(ep=scan_ep, pl=payload, c=cust, d=domain):
            try:
                async with httpx.AsyncClient(timeout=120) as cli:
                    r = await cli.post(ep, json=pl)
                    if r.status_code == 200:
                        await send_scan_notification(c, d, r.json())
                        logger.info(f"Scheduled scan done: {d}")
            except Exception as e:
                logger.error(f"Scheduled scan failed for {d}: {e}")

        asyncio.create_task(_run())
        triggered.append({"customer_id": cid, "domain": domain, "tier": tier})

    return {"triggered": len(triggered), "details": triggered}


# ── Scan result notification ──────────────────────────────────────────────────

async def send_scan_notification(customer: dict, domain: str, scan_result: dict):
    """Send Slack/Discord/Email notification after a scan completes."""
    lang   = customer.get("lang", "ko")
    score  = scan_result.get("score", 0)
    grade  = scan_result.get("grade", "?")
    ko     = lang == "ko"

    # Count findings by severity
    findings = scan_result.get("findings", []) or scan_result.get("preview_findings", [])
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high     = sum(1 for f in findings if f.get("severity") == "high")

    score_color = 0x00E5A0 if score >= 80 else (0xFFB547 if score >= 55 else 0xFF4D6A)

    if ko:
        title = f"🔍 {domain} 정기 보안 스캔 완료"
        desc  = f"보안 점수: **{score}/100** (등급 {grade})"
        if critical or high:
            desc += f"\n위험 발견: Critical {critical}개, High {high}개"
        else:
            desc += "\n⚠️ 심각한 취약점이 발견되지 않았습니다."
        footer = "CyberShield 자동 스캔"
    else:
        title = f"🔍 Security scan complete: {domain}"
        desc  = f"Score: **{score}/100** (Grade {grade})"
        if critical or high:
            desc += f"\nFindings: {critical} Critical, {high} High"
        else:
            desc += "\nNo critical vulnerabilities found."
        footer = "CyberShield Auto Scan"

    # ── Slack ─────────────────────────────────────────────────────────────────
    slack_webhook = customer.get("slack_webhook", "")
    if slack_webhook:
        try:
            msg = f"{'🔴' if score < 55 else '🟡' if score < 80 else '🟢'} {title}\n{desc}"
            async with httpx.AsyncClient(timeout=8) as c:
                await c.post(slack_webhook, json={"text": msg})
        except Exception as e:
            logger.error(f"Slack scan notification failed: {e}")

    # ── Discord ───────────────────────────────────────────────────────────────
    discord_webhook = customer.get("discord_webhook", "")
    if discord_webhook:
        try:
            embed = {
                "title":       title,
                "description": desc,
                "color":       score_color,
                "fields": [
                    {"name": "Score" if not ko else "점수",
                     "value": f"{score}/100", "inline": True},
                    {"name": "Grade" if not ko else "등급",
                     "value": grade, "inline": True},
                    {"name": "Critical" if not ko else "치명적",
                     "value": str(critical), "inline": True},
                ],
                "footer": {"text": footer},
            }
            async with httpx.AsyncClient(timeout=8) as c:
                await c.post(discord_webhook, json={"embeds": [embed]})
        except Exception as e:
            logger.error(f"Discord scan notification failed: {e}")

    # ── Email (Resend) ────────────────────────────────────────────────────────
    resend_key = os.getenv("RESEND_API_KEY", "")
    from_email = os.getenv("FROM_EMAIL", "alert@digitalcybershield.com")
    email_addr = customer.get("email", "")

    if resend_key and email_addr:
        bar_color = "#00e5a0" if score >= 80 else "#ffb547" if score >= 55 else "#ff4d6a"
        if ko:
            subject = f"[CyberShield] {domain} 보안 스캔 완료 — {score}/100 ({grade})"
            html = f"""
<div style="font-family:sans-serif;max-width:600px;margin:auto;background:#0a1422;color:#d4e4ff;padding:32px;border-radius:12px">
  <h2 style="color:#00e5a0;margin-top:0">🔍 정기 보안 스캔 완료</h2>
  <p style="color:#7a98c4">도메인: <strong style="color:#d4e4ff">{domain}</strong></p>
  <div style="background:#111a2e;border-radius:8px;padding:20px;text-align:center;margin:20px 0">
    <div style="font-size:48px;font-weight:700;color:{bar_color}">{score}</div>
    <div style="color:#7a98c4;font-size:14px">/100 · 등급 {grade}</div>
  </div>
  {'<p style="color:#ff4d6a">⚠ Critical ' + str(critical) + '개, High ' + str(high) + '개 취약점이 발견됐습니다.</p>' if critical or high else '<p style="color:#00e5a0">✅ 심각한 취약점이 없습니다.</p>'}
  <a href="https://digitalcybershield.com/dashboard" style="display:inline-block;background:#00e5a0;color:#050810;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;margin-top:12px">대시보드에서 확인 →</a>
  <p style="color:#3a5070;font-size:11px;margin-top:24px">CyberShield 자동 발송 · 수신 거부는 대시보드 설정에서</p>
</div>"""
        else:
            subject = f"[CyberShield] Scan complete: {domain} — {score}/100 ({grade})"
            html = f"""
<div style="font-family:sans-serif;max-width:600px;margin:auto;background:#0a1422;color:#d4e4ff;padding:32px;border-radius:12px">
  <h2 style="color:#00e5a0;margin-top:0">🔍 Security Scan Complete</h2>
  <p style="color:#7a98c4">Domain: <strong style="color:#d4e4ff">{domain}</strong></p>
  <div style="background:#111a2e;border-radius:8px;padding:20px;text-align:center;margin:20px 0">
    <div style="font-size:48px;font-weight:700;color:{bar_color}">{score}</div>
    <div style="color:#7a98c4;font-size:14px">/100 · Grade {grade}</div>
  </div>
  {'<p style="color:#ff4d6a">⚠ Found ' + str(critical) + ' Critical and ' + str(high) + ' High vulnerabilities.</p>' if critical or high else '<p style="color:#00e5a0">✅ No critical vulnerabilities found.</p>'}
  <a href="https://digitalcybershield.com/dashboard" style="display:inline-block;background:#00e5a0;color:#050810;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;margin-top:12px">View Dashboard →</a>
  <p style="color:#3a5070;font-size:11px;margin-top:24px">Sent automatically by CyberShield</p>
</div>"""

        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {resend_key}",
                             "Content-Type": "application/json"},
                    json={"from": f"CyberShield <{from_email}>",
                          "to": [email_addr], "subject": subject, "html": html},
                )
                if r.status_code in (200, 201):
                    logger.info(f"Scan email sent to {email_addr}")
        except Exception as e:
            logger.error(f"Scan email notification failed: {e}")
