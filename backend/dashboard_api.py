"""
CyberShield — Dashboard API (Direction 2: Domain Scan SaaS)

All data is scan-based. No agent required.

Endpoints:
  GET  /dashboard/me           — full dashboard data for logged-in user
  GET  /dashboard/realtime-config — Supabase Realtime subscription config
  POST /dashboard/resolve      — mark a scan finding as resolved
  POST /dashboard/resolve-event — mark a scan event as reviewed
  POST /dashboard/rescan       — trigger immediate rescan of primary domain
"""

import os, asyncio, logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import httpx

logger = logging.getLogger("cybershield.dashboard")

dashboard_router = APIRouter()

SUPABASE_URL      = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY      = os.getenv("SUPABASE_KEY", "")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")

# ── Helpers ───────────────────────────────────────────────────────────────────

async def verify_jwt(authorization):
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


async def sb_get(table, params, limit=100):
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


async def sb_patch(table, params, data):
    if not (SUPABASE_URL and SUPABASE_KEY):
        return
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            await c.patch(
                f"{SUPABASE_URL}/rest/v1/{table}?{params}",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                         "Content-Type": "application/json"},
                json=data,
            )
    except Exception as e:
        logger.error(f"sb_patch {table}: {e}")


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def time_ago(iso):
    try:
        dt  = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        sec = (datetime.now(timezone.utc) - dt).total_seconds()
        if sec < 60:    return "방금 전"
        if sec < 3600:  return f"{int(sec//60)}분 전"
        if sec < 86400: return f"{int(sec//3600)}시간 전"
        return f"{int(sec//86400)}일 전"
    except Exception:
        return ""

def _guide_url(category):
    return {"ssl":"/blog/ssl-guide","email":"/blog/dmarc-guide",
            "headers":"/blog/waf-setup-guide","dns":"/blog/dmarc-guide",
            "ports":"/blog/open-ports-guide","malware":"/blog/ransomware-prevention",
            "code":"/blog/ai-code-security"}.get(category,"")

def fmt_vuln(v):
    return {"id":v.get("id"),"category":v.get("category"),"severity":v.get("severity"),
            "title":v.get("title"),"title_ko":v.get("title_ko"),
            "desc":v.get("description"),"desc_ko":v.get("description_ko"),
            "fix":v.get("remediation"),"fix_ko":v.get("remediation_ko"),
            "found":v.get("found_at","")[:10],"guide":_guide_url(v.get("category","")),
            "resolved":v.get("resolved",False),"domain":v.get("domain","")}

def fmt_event(e):
    return {"id":e.get("id"),"type":e.get("event_type","scan_complete"),
            "severity":e.get("severity","info"),
            "title":e.get("title",""),"title_ko":e.get("title_ko",""),
            "desc":e.get("description",""),"desc_ko":e.get("description_ko",""),
            "domain":e.get("domain",""),"score":e.get("score"),"grade":e.get("grade"),
            "ago":time_ago(e.get("occurred_at") or e.get("created_at") or ""),
            "occurred_at":e.get("occurred_at"),"resolved":e.get("resolved",False)}


class ResolveReq(BaseModel):
    finding_id: str


@dashboard_router.get("/dashboard/me")
async def get_dashboard(authorization: Optional[str] = Header(None)):
    user  = await verify_jwt(authorization)
    email = user.get("email","")
    customers = await sb_get("customers", f"email=eq.{email}", 1)
    if not customers:
        raise HTTPException(404, {"error":"no_account",
            "message_ko":"등록된 계정이 없습니다. 도메인을 먼저 등록해주세요.",
            "message_en":"No account found. Please register your domain first."})

    cust = customers[0]
    cid  = cust["customer_id"]
    tier = cust.get("tier","free")
    now  = datetime.now(timezone.utc)

    retention_days = {"free":7,"plus":90,"max":365}.get(tier,7)
    cutoff     = (now - timedelta(days=retention_days)).isoformat()
    month_ago  = (now - timedelta(days=30)).isoformat()
    month_start = now.replace(day=1,hour=0,minute=0,second=0,microsecond=0).isoformat()

    vulns, hist, events, unresolved, scans_used_rows = await asyncio.gather(
        sb_get("scan_findings",f"customer_id=eq.{cid}&resolved=eq.false&order=severity_order.asc",100),
        sb_get("scan_history",f"customer_id=eq.{cid}&scanned_at=gte.{month_ago}&order=scanned_at.asc",60),
        sb_get("scan_events",f"customer_id=eq.{cid}&occurred_at=gte.{cutoff}&order=occurred_at.desc",50),
        sb_get("scan_events",f"customer_id=eq.{cid}&resolved=eq.false&order=occurred_at.desc",100),
        sb_get("scan_history",f"customer_id=eq.{cid}&scanned_at=gte.{month_start}&select=id",999),
    )

    cur   = int(cust.get("last_score") or 0)
    prev  = int(hist[-2]["score"]) if len(hist)>=2 else cur
    delta = cur - prev

    domain_rows = await sb_get("customer_domains",f"customer_id=eq.{cid}&order=is_primary.desc,added_at.asc",20)
    domains = [{"domain":d["domain"],"is_primary":d.get("is_primary",False),"next_scan":d.get("next_scan_at")}
               for d in domain_rows] or [{"domain":cust.get("domain",""),"is_primary":True,"next_scan":None}]

    scans_limit = {"free":5,"plus":50,"max":999999}.get(tier,5)
    scans_used  = len(scans_used_rows)
    top3 = sorted(vulns, key=lambda v: SEV_ORDER.get(v.get("severity","low"),4))[:3]
    schedule = cust.get("scan_schedule") or {"free":"none","plus":"weekly","max":"daily"}.get(tier,"none")

    return {
        "ts": now.isoformat(),
        "customer": {
            "customer_id": cid, "email": email,
            "domain":  cust.get("domain",""), "domains": domains,
            "tier":    tier, "lang": cust.get("lang","ko"),
            "schedule":    schedule,
            "next_scan_at": cust.get("next_scan_at"),
        },
        "score": {
            "current":      cur,
            "grade":        cust.get("last_grade","F"),
            "delta":        delta,
            "last_scanned": cust.get("last_scanned_at"),
        },
        "score_chart":       [{"date":h["scanned_at"],"score":h["score"]} for h in hist],
        "quota": {
            "used": scans_used, "limit": scans_limit,
            "unlimited": scans_limit>=999999,
            "remaining": max(0,scans_limit-scans_used) if scans_limit<999999 else 999999,
        },
        "top_actions": [{"id":v.get("id"),"severity":v.get("severity"),
                         "title":v.get("title"),"title_ko":v.get("title_ko"),
                         "action":v.get("remediation",""),"action_ko":v.get("remediation_ko",""),
                         "guide":_guide_url(v.get("category",""))} for v in top3],
        "events":            [fmt_event(e) for e in events],
        "unresolved_events": [fmt_event(e) for e in unresolved],
        "vulnerabilities":   [fmt_vuln(v) for v in vulns],
        "schedule_options": {
            "allowed": ["none"] if tier=="free" else (["none","weekly"] if tier=="plus" else ["none","weekly","daily"]),
            "current": schedule,
        },
    }


@dashboard_router.get("/dashboard/realtime-config")
async def get_realtime_config(authorization: Optional[str] = Header(None)):
    user  = await verify_jwt(authorization)
    email = user.get("email","")
    customers = await sb_get("customers", f"email=eq.{email}", 1)
    if not customers:
        raise HTTPException(404, "No account linked to this email")
    cid = customers[0]["customer_id"]
    return {"supabase_url":SUPABASE_URL,"anon_key":SUPABASE_ANON_KEY,
            "customer_id":cid,"channel":f"customer:{cid}",
            "table":"scan_events","filter":f"customer_id=eq.{cid}"}


@dashboard_router.post("/dashboard/resolve")
async def resolve_finding(req: ResolveReq, authorization: Optional[str] = Header(None)):
    user  = await verify_jwt(authorization)
    custs = await sb_get("customers",f"email=eq.{user.get('email','')}",1)
    if not custs: raise HTTPException(404,"Customer not found")
    await sb_patch("scan_findings",
        f"id=eq.{req.finding_id}&customer_id=eq.{custs[0]['customer_id']}",
        {"resolved":True,"resolved_at":datetime.now(timezone.utc).isoformat()})
    return {"status":"ok"}


@dashboard_router.post("/dashboard/resolve-event")
async def resolve_event(req: ResolveReq, authorization: Optional[str] = Header(None)):
    user  = await verify_jwt(authorization)
    custs = await sb_get("customers",f"email=eq.{user.get('email','')}",1)
    if not custs: raise HTTPException(404,"Customer not found")
    await sb_patch("scan_events",
        f"id=eq.{req.finding_id}&customer_id=eq.{custs[0]['customer_id']}",
        {"resolved":True,"resolved_at":datetime.now(timezone.utc).isoformat()})
    return {"status":"ok"}


@dashboard_router.post("/dashboard/rescan")
async def trigger_rescan(domain: Optional[str]=None, authorization: Optional[str]=Header(None)):
    user  = await verify_jwt(authorization)
    custs = await sb_get("customers",f"email=eq.{user.get('email','')}",1)
    if not custs: raise HTTPException(404,"Customer not found")
    cust   = custs[0]
    target = domain or cust.get("domain","")
    tier   = cust.get("tier","free")
    if not target: raise HTTPException(400,"No domain registered")

    site_url = os.getenv("SITE_URL","https://cybershield-10-production.up.railway.app")
    eps  = {"free":"/scan","plus":"/scan/v2","max":"/scan/v2"}
    extr = {"free":{},"plus":{"tier":"plus"},"max":{"tier":"max"}}

    from customer_api import send_scan_notification

    async def _run():
        try:
            async with httpx.AsyncClient(timeout=120) as c:
                r = await c.post(f"{site_url}{eps.get(tier,'/scan')}",
                    json={"domain":target,"email":cust.get("email",""),
                          "lang":cust.get("lang","ko"),"customer_id":cust["customer_id"],
                          **extr.get(tier,{})})
                if r.status_code==200:
                    await send_scan_notification(cust,target,r.json())
        except Exception as e:
            logger.error(f"Rescan failed for {target}: {e}")

    asyncio.create_task(_run())
    return {"status":"queued","domain":target,
            "message_ko":f"{target} 재스캔이 시작됐습니다. 30~90초 후 업데이트됩니다.",
            "message_en":f"Rescan started for {target}. Results appear in 30–90 seconds."}
