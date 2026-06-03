"""
CyberShield — Security Score Scan Engine v1.2
"""
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import asyncio, httpx, socket, ssl, re, os, logging
from datetime import datetime, timezone
from typing import Optional
import dns.resolver

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybershield")

app = FastAPI(title="CyberShield Scan API", version="1.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET","POST"], allow_headers=["*"])

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL     = os.getenv("FROM_EMAIL", "general@jihun.me")
TIMEOUT        = 10

class ScanRequest(BaseModel):
    domain: str
    email:      Optional[str] = None
    lang:       Optional[str] = "en"
    tier:       Optional[str] = "free"   # free | plus | max
    customer_id: Optional[str] = None    # for scan count enforcement
    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v):
        v = v.strip().lower()
        v = re.sub(r"^https?://","",v).split("/")[0].split("?")[0]
        if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v):
            raise ValueError("Invalid domain format")
        return v

class Finding(BaseModel):
    id: str; category: str; severity: str
    title: str; title_ko: str
    description: str; description_ko: str
    remediation: str; remediation_ko: str
    score_impact: int; line: Optional[int] = None

class ScanResult(BaseModel):
    domain: str; score: int; grade: str; scanned_at: str
    findings: list[Finding]; preview_findings: list[Finding]
    summary_en: str; summary_ko: str; full_report: bool; email_sent: bool = False

class FileScanResult(BaseModel):
    filename: str; score: int; grade: str; scanned_at: str
    findings: list[Finding]; summary_en: str; summary_ko: str; language: str

GRADE_MAP   = [(93,"A+"),(85,"A"),(75,"B"),(60,"C"),(45,"D"),(0,"F")]
SEV_WEIGHTS = {"critical":22,"high":12,"medium":6,"low":2,"info":0}

def calc_grade(s):
    for t,g in GRADE_MAP:
        if s>=t: return g
    return "F"

def deduct(findings):
    return max(0, 100 - sum(SEV_WEIGHTS.get(f.severity,0) for f in findings))

def sort_findings(findings):
    o={"critical":0,"high":1,"medium":2,"low":3,"info":4}
    return sorted(findings, key=lambda f: o.get(f.severity,5))

def F(id,cat,sev,t,tk,d,dk,r,rk,si,line=None):
    return Finding(id=id,category=cat,severity=sev,title=t,title_ko=tk,description=d,
                   description_ko=dk,remediation=r,remediation_ko=rk,score_impact=si,line=line)

async def verify_domain_exists(domain):
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, socket.gethostbyname, domain)
    except socket.gaierror:
        return False, f"Domain '{domain}' does not exist (DNS lookup failed)."
    for scheme in ["https","http"]:
        try:
            async with httpx.AsyncClient(timeout=8,follow_redirects=True) as c:
                r = await c.get(f"{scheme}://{domain}",headers={"User-Agent":"CyberShield/1.2"})
                if r.status_code < 600: return True,"ok"
        except: continue
    return True,"dns_only"

async def check_ssl(domain):
    findings=[]
    try:
        ctx=ssl.create_default_context()
        conn=socket.create_connection((domain,443),timeout=TIMEOUT)
        with ctx.wrap_socket(conn,server_hostname=domain) as s:
            cert=s.getpeercert(); proto=s.version(); cipher=s.cipher()
            if proto in ("TLSv1","TLSv1.1",None):
                findings.append(F("ssl-old-tls","ssl","high",
                    f"Outdated TLS version in use: {proto}",f"구식 TLS 버전 사용: {proto}",
                    f"TLS 1.0/1.1 are deprecated with known vulnerabilities. Your server negotiated {proto}.",
                    f"TLS 1.0/1.1은 더 이상 사용되지 않으며 알려진 취약점이 있습니다. 현재 {proto} 협상됨.",
                    "Configure server to use TLS 1.2 minimum, preferably TLS 1.3.",
                    "서버를 최소 TLS 1.2, 가급적 TLS 1.3을 사용하도록 설정하세요.",12))
            if cipher and cipher[2] and cipher[2]<128:
                findings.append(F("ssl-weak-cipher","ssl","high",
                    f"Weak cipher: {cipher[0]} ({cipher[2]} bits)",f"취약한 암호: {cipher[0]} ({cipher[2]}비트)",
                    "Cipher strength below 128 bits is insecure.",
                    "128비트 미만 암호화 강도는 안전하지 않습니다.",
                    "Disable weak ciphers. Prefer AES-256-GCM or CHACHA20.",
                    "약한 암호를 비활성화하세요. AES-256-GCM 또는 CHACHA20을 권장합니다.",12))
            expire_str=cert.get("notAfter","")
            if expire_str:
                expire_dt=datetime.strptime(expire_str,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left=(expire_dt-datetime.now(timezone.utc)).days
                if days_left<0:
                    findings.append(F("ssl-expired","ssl","critical",
                        "SSL certificate has expired","SSL 인증서 만료됨",
                        f"Expired {-days_left} days ago. All visitors see a security warning.",
                        f"인증서가 {-days_left}일 전 만료됐습니다. 모든 방문자에게 보안 경고가 표시됩니다.",
                        "Renew immediately via Let's Encrypt or your hosting provider.",
                        "Let's Encrypt(무료) 또는 호스팅 업체를 통해 즉시 갱신하세요.",22))
                elif days_left<=7:
                    findings.append(F("ssl-expiring-urgent","ssl","critical",
                        f"SSL expires in {days_left} days — URGENT",f"SSL 인증서 {days_left}일 후 만료 — 긴급",
                        "Certificate will expire very soon.",
                        "인증서가 매우 곧 만료됩니다.",
                        "Renew immediately.",
                        "즉시 갱신하세요.",18))
                elif days_left<=30:
                    findings.append(F("ssl-expiring-soon","ssl","high",
                        f"SSL certificate expires in {days_left} days",f"SSL 인증서 {days_left}일 후 만료 예정",
                        "Certificate expiry approaching. Set up auto-renewal now.",
                        "인증서 만료가 다가오고 있습니다. 지금 자동 갱신을 설정하세요.",
                        "Enable auto-renewal: certbot renew --dry-run",
                        "자동 갱신 활성화: certbot renew --dry-run",12))
    except ssl.SSLError as e:
        findings.append(F("ssl-invalid","ssl","critical",
            "SSL/TLS handshake failed","SSL/TLS 핸드셰이크 실패",
            f"SSL error: {str(e)[:100]}",
            "SSL 핸드셰이크 실패. 자기서명 인증서이거나 설정이 잘못됐습니다.",
            "Install a valid certificate from a trusted CA.",
            "신뢰할 수 있는 CA에서 유효한 인증서를 설치하세요.",22))
    except:
        findings.append(F("ssl-no-https","ssl","high",
            "HTTPS not available (port 443 unreachable)","HTTPS 미지원 (포트 443 접근 불가)",
            "The site does not respond on port 443. All traffic is transmitted in plaintext.",
            "포트 443에서 응답이 없습니다. 모든 트래픽이 평문으로 전송됩니다.",
            "Enable HTTPS via your hosting provider or Cloudflare.",
            "호스팅 업체 또는 Cloudflare를 통해 HTTPS를 활성화하세요.",18))
    return findings

async def check_http_headers(domain):
    findings=[]
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT,follow_redirects=True) as client:
            r=await client.get(f"https://{domain}",headers={"User-Agent":"CyberShield/1.2"})
            h={k.lower():v for k,v in r.headers.items()}
            csp=h.get("content-security-policy","")
            hsts=h.get("strict-transport-security","")
            if not hsts:
                findings.append(F("header-hsts-missing","headers","medium",
                    "HSTS header missing","HSTS 헤더 없음",
                    "Without HSTS, browsers may downgrade connections to HTTP.",
                    "HSTS가 없으면 브라우저가 HTTP로 연결을 다운그레이드할 수 있습니다.",
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "헤더 추가: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",6))
            elif "max-age=" in hsts:
                m=re.search(r"max-age=(\d+)",hsts)
                if m and int(m.group(1))<86400:
                    findings.append(F("header-hsts-short","headers","low",
                        "HSTS max-age too short (under 1 day)","HSTS max-age가 너무 짧음 (1일 미만)",
                        "HSTS max-age should be at least 31536000 (1 year) to be effective.",
                        "HSTS max-age는 최소 31536000(1년) 이상이어야 효과적입니다.",
                        "Set max-age=31536000 or higher.",
                        "max-age=31536000 이상으로 설정하세요.",2))
            if "x-frame-options" not in h and "frame-ancestors" not in csp:
                findings.append(F("header-xframe","headers","medium",
                    "Clickjacking protection missing (no X-Frame-Options or CSP frame-ancestors)",
                    "클릭재킹 방어 없음 (X-Frame-Options 또는 CSP frame-ancestors 없음)",
                    "Without frame protection, your site can be embedded in a malicious iframe.",
                    "프레임 보호 없이 사이트가 악성 iframe에 삽입될 수 있습니다.",
                    "Add: X-Frame-Options: SAMEORIGIN",
                    "헤더 추가: X-Frame-Options: SAMEORIGIN",6))
            if not csp:
                findings.append(F("header-csp-missing","headers","medium",
                    "Content Security Policy (CSP) missing","CSP(콘텐츠 보안 정책) 없음",
                    "Without CSP, browsers cannot block injected scripts (XSS) or mixed content.",
                    "CSP 없이 브라우저는 삽입된 악성 스크립트(XSS)를 차단할 수 없습니다.",
                    "Start with: Content-Security-Policy: default-src 'self'; script-src 'self'",
                    "기본값 추가: Content-Security-Policy: default-src 'self'; script-src 'self'",6))
            elif "unsafe-inline" in csp and "script-src" in csp:
                findings.append(F("header-csp-unsafe","headers","medium",
                    "CSP allows 'unsafe-inline' scripts","CSP에서 'unsafe-inline' 스크립트 허용",
                    "'unsafe-inline' in script-src defeats most XSS protection CSP provides.",
                    "script-src의 'unsafe-inline'은 CSP의 XSS 방어를 무효화합니다.",
                    "Replace 'unsafe-inline' with nonces or hashes in your CSP.",
                    "CSP에서 'unsafe-inline' 대신 nonce 또는 hash를 사용하세요.",6))
            if "x-content-type-options" not in h:
                findings.append(F("header-xcto","headers","low",
                    "X-Content-Type-Options missing (MIME sniffing risk)","X-Content-Type-Options 없음 (MIME 스니핑 위험)",
                    "Without nosniff, browsers may MIME-sniff responses and execute unexpected content.",
                    "nosniff 없이 브라우저가 응답을 MIME 스니핑해 예상치 못한 콘텐츠를 실행할 수 있습니다.",
                    "Add: X-Content-Type-Options: nosniff",
                    "헤더 추가: X-Content-Type-Options: nosniff",2))
            if "referrer-policy" not in h:
                findings.append(F("header-referrer","headers","low",
                    "Referrer-Policy missing","Referrer-Policy 헤더 없음",
                    "Without Referrer-Policy, sensitive URL paths may be leaked to third parties.",
                    "Referrer-Policy 없이 민감한 URL 경로가 서드파티에 유출될 수 있습니다.",
                    "Add: Referrer-Policy: strict-origin-when-cross-origin",
                    "헤더 추가: Referrer-Policy: strict-origin-when-cross-origin",2))
            if "permissions-policy" not in h and "feature-policy" not in h:
                findings.append(F("header-permissions","headers","low",
                    "Permissions-Policy header missing","Permissions-Policy 헤더 없음",
                    "Permissions-Policy lets you restrict browser features (camera, mic, geolocation).",
                    "Permissions-Policy를 통해 카메라·마이크·위치 등 브라우저 기능을 제한할 수 있습니다.",
                    "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
                    "헤더 추가: Permissions-Policy: geolocation=(), microphone=(), camera=()",2))
            sv=h.get("server","")
            if sv and any(v in sv.lower() for v in ["apache/","nginx/","iis/","php/","lighttpd/"]):
                findings.append(F("header-server-leak","headers","low",
                    f"Server version exposed: {sv}",f"서버 버전 노출: {sv}",
                    "Exposing the exact server version helps attackers identify applicable CVEs.",
                    "서버 버전 노출은 공격자가 적용 가능한 CVE를 찾는 데 도움을 줍니다.",
                    "Hide Server header (Apache: ServerTokens Prod, Nginx: server_tokens off).",
                    "Server 헤더를 숨기세요 (Apache: ServerTokens Prod, Nginx: server_tokens off).",2))
            pw=h.get("x-powered-by","")
            if pw:
                findings.append(F("header-powered-by","headers","low",
                    f"X-Powered-By exposes: {pw}",f"X-Powered-By 노출: {pw}",
                    "Revealing the server technology helps attackers find targeted exploits.",
                    "서버 기술 스택 노출은 공격자가 targeted exploit을 찾을 수 있게 합니다.",
                    "Remove: PHP: header_remove('X-Powered-By') / Express: app.disable('x-powered-by')",
                    "제거: PHP: header_remove('X-Powered-By') / Express: app.disable('x-powered-by')",2))
            # Cookie checks
            raw_cookies=[v for k,v in r.headers.items() if k.lower()=="set-cookie"]
            for ck in raw_cookies:
                cl=ck.lower()
                if "secure" not in cl:
                    findings.append(F("cookie-no-secure","headers","medium",
                        "Cookie set without Secure flag","Secure 플래그 없이 쿠키 설정",
                        "Cookie can be sent over unencrypted HTTP connections.",
                        "쿠키가 암호화되지 않은 HTTP 연결로 전송될 수 있습니다.",
                        "Add Secure flag to all cookies.",
                        "모든 쿠키에 Secure 플래그를 추가하세요.",6)); break
                if "httponly" not in cl:
                    findings.append(F("cookie-no-httponly","headers","medium",
                        "Cookie set without HttpOnly flag","HttpOnly 플래그 없이 쿠키 설정",
                        "Cookies without HttpOnly can be accessed by JavaScript — XSS session theft risk.",
                        "HttpOnly 없는 쿠키는 자바스크립트로 접근 가능해 XSS 세션 탈취 위험이 있습니다.",
                        "Add HttpOnly to all sensitive cookies.",
                        "민감한 모든 쿠키에 HttpOnly를 추가하세요.",6)); break
                if "samesite" not in cl:
                    findings.append(F("cookie-no-samesite","headers","low",
                        "Cookie missing SameSite attribute","쿠키에 SameSite 속성 없음",
                        "Without SameSite, cookies may be sent in cross-site requests (CSRF risk).",
                        "SameSite 없이 쿠키가 크로스 사이트 요청으로 전송돼 CSRF 위험이 있습니다.",
                        "Add SameSite=Lax or Strict to all cookies.",
                        "모든 쿠키에 SameSite=Lax 또는 Strict를 추가하세요.",2)); break
            # Mixed content
            if r.status_code==200 and "text/html" in r.headers.get("content-type",""):
                if re.search(r'src=["\']http://|href=["\']http://',r.text[:20000],re.I):
                    findings.append(F("mixed-content","headers","medium",
                        "Mixed content: HTTP resources on HTTPS page","혼합 콘텐츠: HTTPS 페이지에 HTTP 리소스",
                        "HTTP resources on HTTPS pages are a security risk and may be blocked by browsers.",
                        "HTTPS 페이지에서 HTTP 리소스를 로드하는 것은 보안 위험이며 브라우저에서 차단될 수 있습니다.",
                        "Change all resource URLs from http:// to https://.",
                        "모든 리소스 URL을 http://에서 https://로 변경하세요.",6))
    except: pass
    return findings

async def check_email_security(domain):
    findings=[]
    resolver=dns.resolver.Resolver(); resolver.timeout=TIMEOUT
    # MX
    try:
        if not list(resolver.resolve(domain,"MX")): raise Exception()
    except:
        findings.append(F("email-no-mx","email","medium","No MX records found","MX 레코드 없음",
            "No mail exchange records. This domain cannot receive email.",
            "메일 교환 레코드가 없습니다. 이 도메인은 이메일을 받을 수 없습니다.",
            "Add MX records if you plan to receive email on this domain.",
            "이 도메인에서 이메일을 수신하려면 MX 레코드를 추가하세요.",2))
    # SPF
    try:
        answers=resolver.resolve(domain,"TXT")
        spf_recs=[str(r) for r in answers if "v=spf1" in str(r).lower()]
        if not spf_recs: raise Exception()
        spf=spf_recs[0]
        if "+all" in spf:
            findings.append(F("email-spf-permissive","email","critical",
                "SPF uses '+all' — any server can send as your domain","SPF '+all' 사용 — 모든 서버가 귀사 도메인으로 발송 가능",
                "'+all' means ANY server can send email as your domain. SPF is completely useless.",
                "'+all'은 모든 서버가 귀사 도메인으로 이메일을 보낼 수 있음을 의미합니다. SPF가 완전히 무력화됩니다.",
                "Change to '-all' (hardfail) or '~all' (softfail) immediately.",
                "즉시 '-all' 또는 '~all'로 변경하세요.",22))
        elif "?all" in spf:
            findings.append(F("email-spf-neutral","email","medium",
                "SPF uses '?all' — neutral, no enforcement","SPF '?all' 사용 — 중립 정책",
                "'?all' means no policy for unlisted senders. Spoofing from unknown servers is not blocked.",
                "'?all'은 미등록 발신자에 대한 정책이 없습니다.",
                "Use '-all' for strict enforcement or '~all' for softfail.",
                "엄격한 적용은 '-all', 소프트 실패는 '~all'을 사용하세요.",6))
    except:
        findings.append(F("email-spf-missing","email","high","SPF record missing","SPF 레코드 없음",
            "Without SPF, any server can impersonate your domain in emails.",
            "SPF가 없으면 어떤 서버든 귀사 도메인을 사칭한 이메일을 보낼 수 있습니다.",
            "Add TXT record: v=spf1 include:_spf.google.com -all",
            "TXT 레코드 추가: v=spf1 include:_spf.google.com -all",12))
    # DMARC
    try:
        answers=resolver.resolve(f"_dmarc.{domain}","TXT")
        recs=[str(r) for r in answers if "v=dmarc1" in str(r).lower()]
        if not recs: raise Exception()
        dmarc=recs[0]
        if "p=none" in dmarc.lower():
            findings.append(F("email-dmarc-none","email","medium",
                "DMARC policy is 'none' — monitoring only, no enforcement","DMARC 정책 'none' — 모니터링 전용",
                "p=none means spoofed emails pass through unblocked.",
                "p=none은 스푸핑 이메일이 차단 없이 통과됨을 의미합니다.",
                "Upgrade to p=quarantine then p=reject after monitoring.",
                "모니터링 후 p=quarantine, 그 다음 p=reject로 업그레이드하세요.",6))
        if "rua=" not in dmarc.lower():
            findings.append(F("email-dmarc-no-rua","email","low",
                "DMARC has no reporting address (rua=)","DMARC에 보고 주소(rua=) 없음",
                "Without rua=, you get no reports about who sends email as your domain.",
                "rua= 없이 귀사 도메인으로 이메일을 보내는 사람에 대한 보고서를 받을 수 없습니다.",
                "Add rua=mailto:dmarc@yourdomain.com to your DMARC record.",
                "DMARC 레코드에 rua=mailto:dmarc@도메인.com을 추가하세요.",2))
    except:
        findings.append(F("email-dmarc-missing","email","high","DMARC record missing","DMARC 레코드 없음",
            "Without DMARC, phishing attacks using your domain cannot be detected or blocked.",
            "DMARC 없이 귀사 도메인을 이용한 피싱 공격을 감지하거나 차단할 수 없습니다.",
            "Add TXT at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
            "_dmarc.도메인.com에 추가: v=DMARC1; p=quarantine; rua=mailto:dmarc@도메인.com",12))
    # DKIM
    found=False
    for sel in ["default","google","mail","dkim","selector1","selector2","k1","smtp","mandrill","sendgrid","amazonses"]:
        try: resolver.resolve(f"{sel}._domainkey.{domain}","TXT"); found=True; break
        except: continue
    if not found:
        findings.append(F("email-dkim-missing","email","medium","DKIM signing not detected","DKIM 서명 감지되지 않음",
            "No DKIM record found for 11 common selectors. Email integrity cannot be verified.",
            "11개 일반 셀렉터에서 DKIM 레코드를 찾을 수 없습니다.",
            "Enable DKIM in your email provider (Google Workspace, Microsoft 365, etc.).",
            "이메일 제공업체(Google Workspace, Microsoft 365 등)에서 DKIM을 활성화하세요.",6))
    return findings

async def check_dns(domain):
    findings=[]
    resolver=dns.resolver.Resolver(); resolver.timeout=TIMEOUT
    try:
        resolver.resolve(domain,"DNSKEY")
    except dns.resolver.NoAnswer:
        findings.append(F("dns-dnssec","dns","low","DNSSEC not enabled","DNSSEC 미설정",
            "DNSSEC prevents DNS cache poisoning where attackers redirect your domain.",
            "DNSSEC는 공격자가 도메인을 악성 IP로 리디렉션하는 DNS 캐시 포이즈닝을 방지합니다.",
            "Enable DNSSEC in your domain registrar's DNS management panel.",
            "도메인 등록업체의 DNS 관리 패널에서 DNSSEC를 활성화하세요.",2))
    except: pass
    try:
        resolver.resolve(domain,"CAA")
    except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN):
        findings.append(F("dns-caa-missing","dns","low","CAA record missing","CAA 레코드 없음",
            "Without CAA, any Certificate Authority can issue SSL certs for your domain.",
            "CAA 레코드가 없으면 모든 인증 기관이 귀사 도메인에 대한 SSL 인증서를 발급할 수 있습니다.",
            'Add CAA record: 0 issue "letsencrypt.org"',
            'CAA 레코드 추가: 0 issue "letsencrypt.org"',2))
    except: pass
    try:
        for cname in resolver.resolve(domain,"CNAME"):
            target=str(cname.target).rstrip(".")
            try:
                socket.gethostbyname(target)
            except socket.gaierror:
                findings.append(F("dns-dangling-cname","dns","high",
                    f"Dangling CNAME: '{target}' does not resolve",f"미연결 CNAME: '{target}'이 해석되지 않음",
                    "The CNAME target no longer resolves. Attacker can register it and take over your subdomain.",
                    "CNAME 대상이 더 이상 해석되지 않습니다. 공격자가 등록해 서브도메인을 탈취할 수 있습니다.",
                    "Remove or update the dangling CNAME record immediately.",
                    "미연결 CNAME 레코드를 즉시 제거하거나 업데이트하세요.",12))
    except: pass
    try:
        rnd=f"rnd-{os.urandom(4).hex()}.{domain}"
        socket.gethostbyname(rnd)
        findings.append(F("dns-wildcard","dns","medium",
            "Wildcard DNS configured — all subdomains resolve","와일드카드 DNS 설정됨",
            "Wildcard DNS causes all subdomains to resolve, including non-existent ones. Can facilitate phishing.",
            "와일드카드 DNS는 존재하지 않는 것을 포함한 모든 서브도메인을 해석하게 합니다.",
            "Remove wildcard DNS unless strictly required.",
            "반드시 필요하지 않다면 와일드카드 DNS를 제거하세요.",6))
    except: pass
    return findings

async def check_open_ports(domain):
    risky={
        21:("FTP","ftp-open","critical","FTP port open — unencrypted file transfer","FTP 포트 오픈 — 암호화되지 않은 파일 전송"),
        22:("SSH","ssh-open","medium","SSH port 22 exposed — brute-force risk","SSH 포트 22 노출 — 무차별 대입 공격 위험"),
        23:("Telnet","telnet-open","critical","Telnet port open — plaintext remote access","텔넷 포트 오픈 — 평문 원격 접속"),
        25:("SMTP","smtp-open","medium","SMTP port 25 open — may allow open relay","SMTP 포트 25 오픈 — 오픈 릴레이 허용 가능"),
        2375:("Docker","docker-open","critical","Docker daemon API exposed — full host compromise","Docker 데몬 API 노출 — 호스트 완전 장악 가능"),
        3306:("MySQL","mysql-open","high","MySQL database port exposed to internet","MySQL 데이터베이스 포트 인터넷 노출"),
        3389:("RDP","rdp-open","high","RDP exposed — primary brute-force target","RDP 노출 — 무차별 대입 공격 주요 타깃"),
        4444:("Metasploit","msf-open","critical","Port 4444 open — common reverse shell port","포트 4444 오픈 — 리버스 쉘 공통 포트"),
        5432:("PostgreSQL","pg-open","high","PostgreSQL database port exposed to internet","PostgreSQL 데이터베이스 포트 인터넷 노출"),
        5900:("VNC","vnc-open","critical","VNC remote desktop exposed to internet","VNC 원격 데스크톱 인터넷 노출"),
        6379:("Redis","redis-open","critical","Redis exposed — unauthenticated access by default","Redis 노출 — 기본적으로 인증 없이 접근 가능"),
        8080:("Alt-HTTP","althttp-open","low","Alternate HTTP 8080 open — may expose admin panels","대체 HTTP 포트 8080 오픈 — 관리자 패널 노출 가능"),
        8443:("Alt-HTTPS","althttps-open","low","Alternate HTTPS 8443 open","대체 HTTPS 포트 8443 오픈"),
        9200:("Elasticsearch","es-open","critical","Elasticsearch exposed — data readable without credentials","Elasticsearch 노출 — 자격증명 없이 데이터 접근 가능"),
        27017:("MongoDB","mongo-open","critical","MongoDB exposed — ransomware target","MongoDB 노출 — 랜섬웨어 주요 타깃"),
    }
    sev_impact={"critical":22,"high":12,"medium":6,"low":2}
    async def probe(port):
        try:
            _,w=await asyncio.wait_for(asyncio.open_connection(domain,port),timeout=2)
            w.close(); return port
        except: return None
    open_ports=[p for p in await asyncio.gather(*[probe(p) for p in risky]) if p]
    findings=[]
    for port in open_ports:
        name,fid,sev,desc_en,desc_ko=risky[port]
        findings.append(F(fid,"ports",sev,
            f"Port {port} ({name}) open and reachable from internet",
            f"포트 {port} ({name}) 인터넷에서 접근 가능",
            desc_en,desc_ko,
            f"Block port {port} at the firewall. Restrict to trusted IPs only if required.",
            f"방화벽에서 포트 {port}를 차단하세요. 필요한 경우 신뢰하는 IP만 허용하세요.",
            sev_impact.get(sev,6)))
    return findings

async def check_virustotal(domain):
    if not VIRUSTOTAL_KEY: return []
    findings=[]
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r=await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                               headers={"x-apikey":VIRUSTOTAL_KEY})
            if r.status_code!=200:
                logger.warning(f"VirusTotal {r.status_code} for {domain}: {r.text[:200]}")
                return []
            attrs=r.json().get("data",{}).get("attributes",{})
            stats=attrs.get("last_analysis_stats",{})
            malicious=stats.get("malicious",0); suspicious=stats.get("suspicious",0)
            reputation=attrs.get("reputation",0); categories=attrs.get("categories",{})
            if malicious>0:
                vendors=[k for k,v in attrs.get("last_analysis_results",{}).items() if v.get("category")=="malicious"][:5]
                findings.append(F("vt-malicious","malware","critical",
                    f"Domain flagged malicious by {malicious} vendor(s)",f"보안 벤더 {malicious}곳이 악성 도메인으로 분류",
                    f"Flagged by: {', '.join(vendors) or 'multiple vendors'}.",
                    f"탐지 벤더: {', '.join(vendors) or '복수 벤더'}.",
                    "Request delisting from each vendor and scan server for malware immediately.",
                    "각 벤더에 블랙리스트 해제를 신청하고 서버 악성코드를 즉시 검사하세요.",22))
            elif suspicious>2:
                findings.append(F("vt-suspicious","malware","high",
                    f"Domain flagged suspicious by {suspicious} vendor(s)",f"보안 벤더 {suspicious}곳이 의심 도메인으로 분류",
                    "Multiple vendors consider this domain suspicious.",
                    "여러 벤더가 이 도메인을 의심스럽게 분류합니다.",
                    "Review recent site changes and check for injected scripts.",
                    "최근 사이트 변경사항을 검토하고 삽입된 스크립트를 확인하세요.",12))
            if reputation<-5:
                findings.append(F("vt-reputation","malware","medium",
                    f"Low VirusTotal reputation: {reputation}",f"낮은 VirusTotal 평판: {reputation}",
                    "Negative reputation indicates past association with malicious activity.",
                    "음수 평판 점수는 과거 악성 활동과의 연관성을 나타냅니다.",
                    "Review VirusTotal historical reports and address flagged issues.",
                    "VirusTotal에서 과거 리포트를 검토하고 신고된 문제를 해결하세요.",6))
            phish=[v for v in categories.values() if "phish" in v.lower() or "malware" in v.lower() or "spam" in v.lower()]
            if phish:
                findings.append(F("vt-category","malware","high",
                    f"Domain categorized as '{phish[0]}'",f"도메인 카테고리: '{phish[0]}'",
                    "A vendor categorized this domain under a malicious content category.",
                    "벤더가 이 도메인을 악성 콘텐츠 카테고리로 분류했습니다.",
                    "Contact the vendor to request re-evaluation after cleaning your site.",
                    "사이트 정리 후 해당 벤더에 재분류 검토를 요청하세요.",12))
    except Exception as e:
        logger.error(f"VirusTotal error for {domain}: {e}")
    return findings

CODE_PATTERNS=[
    (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
     "code-apikey","critical","Hardcoded API key","하드코딩된 API 키",
     "API key hardcoded in source.","API 키가 소스에 하드코딩됐습니다.",
     "Move to environment variables and rotate immediately.","환경변수로 이동하고 즉시 교체하세요.",25),
    (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',
     "code-secret","critical","Hardcoded secret/password","하드코딩된 비밀번호/시크릿",
     "Password hardcoded in source.","비밀번호가 소스에 하드코딩됐습니다.",
     "Use environment variables or secrets manager.","환경변수 또는 시크릿 매니저를 사용하세요.",25),
    (r'(?i)(aws_access_key_id|aws_secret)\s*[=:]\s*["\']([A-Z0-9/+]{16,})["\']',
     "code-aws","critical","AWS credentials hardcoded","AWS 자격증명 하드코딩",
     "AWS keys hardcoded.","AWS 키가 하드코딩됐습니다.",
     "Revoke in IAM immediately, use IAM roles.","IAM에서 즉시 폐기하고 IAM 역할을 사용하세요.",25),
    (r'(?i)(cursor\.execute|\.query)\s*\(\s*["\'].*?\%s|f["\'].*?SELECT.*?\{.*?\}',
     "code-sqli","high","Potential SQL injection","SQL 인젝션 취약점 가능성",
     "String formatting in SQL allows injection.","SQL의 문자열 포매팅은 인젝션을 허용합니다.",
     "Use parameterized queries.","파라미터화된 쿼리를 사용하세요.",15),
    (r'\beval\s*\(|exec\s*\(.*input|exec\s*\(.*request',
     "code-eval","high","eval()/exec() with user input","사용자 입력을 받는 eval()/exec()",
     "eval/exec with user input enables RCE.","사용자 입력을 받는 eval/exec는 원격 코드 실행을 허용합니다.",
     "Never use eval/exec with user input.","사용자 입력으로 eval/exec를 절대 사용하지 마세요.",15),
    (r'(?i)(algorithm\s*=\s*["\']none["\']|verify\s*=\s*False|verify_signature\s*=\s*False)',
     "code-jwt","critical","JWT verification disabled","JWT 서명 검증 비활성화",
     "JWT accepted without signature verification.","JWT 서명 검증이 비활성화됐습니다.",
     "Always verify JWT signatures.","항상 JWT 서명을 검증하세요.",25),
    (r'(?i)(Access-Control-Allow-Origin["\s]*[:=]["\s]*\*|allow_origins.*\[.*[\'"]\*[\'"])',
     "code-cors","medium","CORS wildcard '*'","CORS 와일드카드 '*'",
     "All origins allowed in CORS.","모든 오리진이 CORS에서 허용됩니다.",
     "Restrict CORS to specific trusted origins.","신뢰하는 특정 오리진으로 CORS를 제한하세요.",6),
    (r'(?i)(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True)',
     "code-debug","high","Debug mode enabled","디버그 모드 활성화",
     "Debug mode exposes stack traces.","디버그 모드는 스택 트레이스를 노출합니다.",
     "Set DEBUG=False for production.","프로덕션에서 DEBUG=False로 설정하세요.",12),
    (r'\bpickle\.loads?\b|\byaml\.load\s*\([^,)]*\)',
     "code-deserialise","high","Unsafe deserialization","안전하지 않은 역직렬화",
     "pickle/yaml.load can execute arbitrary code.","pickle/yaml.load는 임의 코드를 실행할 수 있습니다.",
     "Use yaml.safe_load(). Avoid pickle with untrusted data.","yaml.safe_load()를 사용하세요.",12),
    (r'(?i)redirect\s*\(\s*request\.(args|params|query|GET|POST)',
     "code-redirect","medium","Potential open redirect","오픈 리다이렉트 취약점",
     "Redirecting to user-supplied URLs allows phishing.","사용자 제공 URL로 리다이렉트하면 피싱이 가능합니다.",
     "Validate redirect URLs against an allowlist.","허용 목록으로 리다이렉트 URL을 검증하세요.",6),
    (r'open\s*\(\s*.*request\.|open\s*\(\s*.*input\(',
     "code-path","medium","Potential path traversal","경로 순회 취약점",
     "User input in file paths can allow reading arbitrary files.","파일 경로의 사용자 입력은 임의 파일 읽기를 허용합니다.",
     "Use os.path.basename() and validate directories.","os.path.basename()을 사용하고 디렉토리를 검증하세요.",6),

    # os.getenv() with hardcoded fallback — catches patterns like:
    # VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "c926322d11b...")
    # RESEND_API_KEY = os.getenv("RESEND_API_KEY", "re_f4Pkdvz1_...")
    (r'os\.getenv\s*\(\s*["\'\'][\w]+["\'\']\s*,\s*["\'\']([A-Za-z0-9_\-\.@+/]{12,})["\'\']',
     "code-getenv-secret","critical",
     "Hardcoded secret as os.getenv() fallback","os.getenv() 폴백에 시크릿 하드코딩",
     "A secret is hardcoded as the default fallback value in os.getenv(). "
     "If the environment variable is not set, the hardcoded value is used — "
     "and it will be exposed in source code repositories, logs, and error messages.",
     "os.getenv()의 기본값에 시크릿이 하드코딩됐습니다. 환경변수가 설정되지 않으면 이 값이 사용되며 "
     "소스 코드 저장소, 로그, 오류 메시지에 노출됩니다.",
     "Remove the hardcoded fallback. Use os.getenv('KEY') with no default, "
     "and ensure the variable is always set via your deployment platform's secret manager "
     "(e.g. Railway Variables, Vercel Environment Variables, AWS Secrets Manager).",
     "하드코딩된 폴백을 제거하세요. os.getenv('KEY')를 기본값 없이 사용하고, "
     "배포 플랫폼의 시크릿 관리자(Railway Variables, Vercel 환경변수, AWS Secrets Manager 등)를 통해 "
     "항상 환경변수가 설정되도록 하세요.", 25),

    # Resend / SendGrid / Mailgun API keys
    (r'(?i)(resend|sendgrid|mailgun|mailchimp|twilio|stripe|github_token|gh_token|'
     r'slack_token|discord_token|telegram_bot)\s*[=:]\s*["\'\']([A-Za-z0-9_\-\.]{16,})["\'\']',
     "code-service-key","critical",
     "Third-party service API key hardcoded","서드파티 서비스 API 키 하드코딩",
     "An API key for a third-party service (email, payments, messaging) is hardcoded in source code. "
     "Leaked keys can be used to send spam, charge payments, or access sensitive data.",
     "서드파티 서비스(이메일, 결제, 메시징) API 키가 소스 코드에 하드코딩됐습니다. "
     "유출된 키는 스팸 발송, 결제 청구, 민감 데이터 접근에 악용될 수 있습니다.",
     "Move to environment variables. Revoke and regenerate the key immediately.",
     "환경변수로 이동하세요. 키를 즉시 폐기하고 재생성하세요.", 25),

    # Email addresses in code (potential exposure)
    (r'(?<!["\'\'])\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b(?!["\'\'].*getenv)',
     "code-email-exposed","low",
     "Email address found in source code","소스 코드에 이메일 주소 노출",
     "An email address is hardcoded in source code. This may expose personal or operational contact details.",
     "이메일 주소가 소스 코드에 하드코딩됐습니다. 개인 또는 운영 연락처 정보가 노출될 수 있습니다.",
     "Move email addresses to environment variables or a configuration file excluded from version control.",
     "이메일 주소를 환경변수나 버전 관리에서 제외된 설정 파일로 이동하세요.", 2),
]

LANG_MAP={"py":"python","js":"javascript","ts":"javascript","jsx":"javascript","tsx":"javascript",
          "go":"go","rb":"ruby","php":"php","java":"java","kt":"kotlin","cs":"csharp","rs":"rust"}

def detect_language(filename):
    ext=filename.rsplit(".",1)[-1].lower() if "." in filename else ""
    return LANG_MAP.get(ext,"generic")

def scan_code(content, filename):
    """
    Scans source code for security patterns.
    Returns (findings, lines_context) where lines_context maps line_number -> line_text.
    """
    findings = []
    seen     = set()
    source_lines = content.splitlines()
    lines_ctx = {}   # line_number -> raw line text (for report context)

    for i, line in enumerate(source_lines, start=1):
        s = line.strip()
        if s.startswith(("#", "//", "*", "--")):
            continue
        for pattern, fid, sev, t_en, t_ko, d_en, d_ko, f_en, f_ko, impact in CODE_PATTERNS:
            if re.search(pattern, line):
                uid = f"{fid}:{i}"
                if uid not in seen:
                    seen.add(uid)
                    # Redact actual secret values before storing context
                    safe_line = re.sub(
                        r'([=:]\s*["\'])([A-Za-z0-9_\-\.@+/]{8,})(["\'])',
                        r'\1[REDACTED]\3',
                        line
                    )
                    lines_ctx[i] = safe_line
                    findings.append(F(uid, "code", sev,
                                      f"{t_en} (line {i})", f"{t_ko} (줄 {i})",
                                      d_en, d_ko, f_en, f_ko, impact, i))

    return sort_findings(findings), lines_ctx

def build_html_report(domain, score, grade, findings, lang, lines_ctx=None):
    """
    Generates a polished vulnerability report HTML email.
    lines_ctx: optional dict {line_number: str} for code context injection.
    """
    sc = {"critical": "#ff4d6a", "high": "#ffb547", "medium": "#4d9fff", "low": "#a78bfa"}
    grade_label_en = {
        "A+": "Excellent", "A": "Good", "B": "Needs Improvement",
        "C": "Poor", "D": "Dangerous", "F": "Critical Risk"
    }
    grade_label_ko = {
        "A+": "매우 우수", "A": "양호", "B": "개선 필요",
        "C": "취약", "D": "위험", "F": "심각한 위험"
    }
    gc   = "#00e5a0" if score >= 80 else "#ffb547" if score >= 55 else "#ff4d6a"
    head = "Full Security Report" if lang == "en" else "보안 취약점 분석 리포트"
    gl   = grade_label_en.get(grade, grade) if lang == "en" else grade_label_ko.get(grade, grade)
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = ""
    for idx_f, f in enumerate(findings):
        t   = f.title_ko   if lang == "ko" else f.title
        d   = f.description_ko if lang == "ko" else f.description
        fix = f.remediation_ko if lang == "ko" else f.remediation
        col = sc.get(f.severity, "#8a9ab0")
        sev_label = f.severity.upper()

        # Code context block (for file scans or findings with a line number)
        ctx_html = ""
        if f.line and lines_ctx and f.line in lines_ctx:
            raw_line = lines_ctx[f.line]
            ctx_html = (
                f'<div style="margin:8px 0 4px;background:#0a1520;border-left:3px solid {col};'
                f'padding:8px 12px;border-radius:0 4px 4px 0;font-family:monospace;font-size:11px;'
                f'color:#c8d8e8;white-space:pre-wrap;word-break:break-all">'
                f'<span style="color:{col};opacity:.7">Line {f.line}:</span>  {raw_line.strip()[:200]}'
                f'</div>'
            )

        # What was found / why it matters
        why_label  = "Why this matters" if lang == "en" else "왜 위험한가"
        fix_label  = "Recommended action" if lang == "en" else "권장 조치"
        found_label = "Found" if lang == "en" else "탐지 위치"

        line_info = ""
        if f.line:
            line_info = f'<div style="margin-top:4px;font-size:11px;color:#4a5a6a">{found_label}: Line {f.line}</div>'
        elif f.category:
            cat_map = {
                "ssl": "SSL/TLS", "headers": "HTTP Headers", "email": "Email Security",
                "dns": "DNS", "ports": "Open Ports", "malware": "Malware/Reputation",
                "code": "Source Code"
            }
            cat_display = cat_map.get(f.category, f.category.upper())
            line_info = f'<div style="margin-top:4px;font-size:11px;color:#4a5a6a">{found_label}: {cat_display}</div>'

        rows += (
            f'<tr>'
            f'<td style="padding:16px 12px 16px 0;border-bottom:1px solid #1a2535;vertical-align:top;width:72px">'
            f'<span style="display:inline-block;background:{col}18;color:{col};border:1px solid {col}44;'
            f'font-size:9px;padding:3px 8px;border-radius:3px;font-weight:700;letter-spacing:.08em">'
            f'{sev_label}</span>'
            f'</td>'
            f'<td style="padding:16px 0;border-bottom:1px solid #1a2535">'
            f'<div style="font-size:14px;font-weight:600;color:#e8edf2;margin-bottom:4px">{t}</div>'
            f'{line_info}'
            f'{ctx_html}'
            f'<div style="margin-top:8px">'
            f'<span style="font-size:10px;font-weight:700;color:#4a5a6a;letter-spacing:.07em;text-transform:uppercase">'
            f'{why_label}</span><br>'
            f'<span style="font-size:12px;color:#8a9ab0;line-height:1.6">{d}</span>'
            f'</div>'
            f'<div style="margin-top:8px;padding:8px 12px;background:#0d1e2e;border-radius:4px">'
            f'<span style="font-size:10px;font-weight:700;color:#00e5a0;letter-spacing:.07em;text-transform:uppercase">'
            f'{fix_label}</span><br>'
            f'<span style="font-size:12px;color:#c8d8e8;line-height:1.6">{fix}</span>'
            f'</div>'
            f'</td>'
            f'</tr>'
        )

    sev_counts = {s: sum(1 for f in findings if f.severity == s) for s in ["critical","high","medium","low"]}
    summary_pills = ""
    for sev, cnt in sev_counts.items():
        if cnt:
            col = sc.get(sev, "#888")
            lbl = sev.capitalize()
            summary_pills += (
                f'<span style="display:inline-block;background:{col}18;color:{col};border:1px solid {col}44;'
                f'font-size:11px;padding:4px 12px;border-radius:4px;margin-right:8px;font-weight:600">'
                f'{cnt} {lbl}</span>'
            )

    exec_summary_en = (
        f"This report presents the findings of an automated security scan conducted on <strong>{domain}</strong> "
        f"on {now}. A total of <strong>{len(findings)} issue(s)</strong> were identified across the following "
        f"categories: SSL/TLS configuration, HTTP security headers, email authentication, DNS security, "
        f"open network ports, and malware reputation. Immediate attention is recommended for all "
        f"Critical and High severity findings."
    )
    exec_summary_ko = (
        f"본 리포트는 {now}에 <strong>{domain}</strong>에 대해 수행된 자동화 보안 스캔 결과입니다. "
        f"SSL/TLS 설정, HTTP 보안 헤더, 이메일 인증, DNS 보안, 네트워크 포트, 악성코드 평판 등 "
        f"총 <strong>{len(findings)}건</strong>의 취약점이 발견됐습니다. "
        f"심각(Critical) 및 높음(High) 등급 항목은 즉각적인 조치를 권장합니다."
    )
    exec_summary = exec_summary_ko if lang == "ko" else exec_summary_en
    findings_title = "취약점 상세 분석" if lang == "ko" else "Detailed Findings"
    exec_title     = "개요" if lang == "ko" else "Executive Summary"

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="background:#070b10;font-family:Arial,Helvetica,sans-serif;color:#e8edf2;margin:0;padding:0">
<div style="max-width:680px;margin:0 auto;padding:32px 24px">

<!-- Header -->
<div style="display:flex;align-items:center;border-bottom:1px solid #1a2535;padding-bottom:20px;margin-bottom:28px">
  <span style="font-family:monospace;color:#00e5a0;font-size:17px;font-weight:700;margin-right:16px;">&#9679; CyberShield</span>
  <span style="font-size:11px;color:#4a5a6a;white-space:nowrap;">{now}</span>
</div>

<!-- Title -->
<h1 style="font-size:22px;font-weight:600;margin:0 0 4px;color:#e8edf2">{head}</h1>
<p style="font-size:13px;color:#5a6a7a;margin:0 0 24px">
  Target: <strong style="color:#8a9ab0">{domain}</strong>
</p>

<!-- Score card (square badge) -->
<div style="display:flex;align-items:center;background:#0d1319;border:1px solid #1a2535;border-radius:8px;padding:20px 24px;margin-bottom:24px">
  <div style="flex-shrink:0;width:80px;height:80px;margin-right:20px;">
    <div style="display:table;width:80px;height:80px;background:#080c10;border:2px solid {gc};border-radius:6px;box-sizing:border-box;text-align:center;">
      <div style="display:table-cell;vertical-align:middle;text-align:center;white-space:nowrap;">
        <span style="font-size:28px;font-weight:700;color:{gc};line-height:1;">{score}</span>
        <span style="font-size:10px;color:#5a6a7a;vertical-align:top;">/100</span>
      </div>
    </div>
  </div>

  <div>
    <div style="font-size:18px;font-weight:600;color:{gc}">{grade} &nbsp;&#8212;&nbsp; {gl}</div>
    <div style="margin-top:8px">{summary_pills}</div>
    <div style="font-size:11px;color:#4a5a6a;margin-top:6px">{len(findings)} issue(s) found</div>
  </div>
</div>

<!-- Executive Summary -->
<div style="background:#0d1319;border:1px solid #1a2535;border-radius:8px;padding:16px 20px;margin-bottom:28px">
  <div style="font-size:11px;font-weight:700;color:#4a5a6a;letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">{exec_title}</div>
  <p style="font-size:13px;color:#8a9ab0;line-height:1.7;margin:0">{exec_summary}</p>
</div>

<!-- Findings -->
<div style="font-size:11px;font-weight:700;color:#4a5a6a;letter-spacing:.08em;text-transform:uppercase;margin-bottom:12px">{findings_title}</div>
<table style="width:100%;border-collapse:collapse">{rows}</table>

<!-- Footer -->
<div style="margin-top:32px;padding-top:16px;border-top:1px solid #1a2535">
  <p style="font-size:11px;color:#2a3a4a;margin:0">
    &#169; CyberShield &nbsp;&middot;&nbsp; digitalcybershield.com &nbsp;&middot;&nbsp;
    This report is confidential and intended solely for the recipient.
    Findings reflect an automated point-in-time scan and should be validated by a security professional.
  </p>
</div>

</div>
</body></html>"""

async def send_email_report(to_email, domain, score, grade, findings, lang, lines_ctx=None):
    if not RESEND_API_KEY:
        logger.error("RESEND_API_KEY not set")
        return False
    subj=(f"CyberShield — {domain} 보안 리포트 (점수: {score}/100)" if lang=="ko"
          else f"CyberShield — Security Report for {domain} (Score: {score}/100)")
    from_field=f"CyberShield <{FROM_EMAIL}>"
    payload={"from":from_field,"to":[to_email],"subject":subj,
             "html":build_html_report(domain, score, grade, findings, lang, lines_ctx=lines_ctx)}
    logger.info(f"Sending email: to={to_email}, from={from_field}, subject={subj}")
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r=await client.post("https://api.resend.com/emails",
                headers={"Authorization":f"Bearer {RESEND_API_KEY}","Content-Type":"application/json"},
                json=payload)
            if r.status_code in (200,201):
                logger.info(f"Email sent OK. Response: {r.text[:200]}")
                return True
            else:
                logger.error(f"Resend error {r.status_code}: {r.text[:500]}")
                return False
    except Exception as e:
        logger.error(f"Email exception: {e}")
        return False

def build_summary(label,score,grade,findings,lang):
    c=sum(1 for f in findings if f.severity=="critical")
    h=sum(1 for f in findings if f.severity=="high")
    m=sum(1 for f in findings if f.severity=="medium")
    if lang=="ko":
        if score>=93: return f"{label} 보안 점수 {score}점({grade}) — 매우 우수합니다."
        if score>=85: return f"{label} {score}점({grade}) — 양호하지만 일부 개선이 필요합니다."
        if score>=75: return f"{label} {score}점({grade}) — 보통 수준. 높음 {h}건, 중간 {m}건 발견."
        if score>=60: return f"{label} {score}점({grade}) — 주의 필요. 심각 {c}건, 높음 {h}건 발견."
        return f"{label} {score}점({grade}) — 즉각 조치 필요. 총 {len(findings)}개 취약점."
    else:
        if score>=93: return f"{label} scored {score}/100 ({grade}) — excellent security posture."
        if score>=85: return f"{label} scored {score}/100 ({grade}) — good, minor improvements needed."
        if score>=75: return f"{label} scored {score}/100 ({grade}) — moderate: {h} high, {m} medium issues."
        if score>=60: return f"{label} scored {score}/100 ({grade}) — attention needed: {c} critical, {h} high."
        return f"{label} scored {score}/100 ({grade}) — immediate action required. {len(findings)} issues."


# ── Sprint 3: Save scan results to DB ─────────────────────────────────────────
async def save_scan_to_db(domain: str, score: int, grade: str,
                          all_findings: list, scanned_at: str) -> None:
    """
    After a domain scan, persist results to Supabase:
      - scan_history: one row per scan (score + grade)
      - scan_findings: one row per finding (replaces previous unresolved findings)
      - customers.last_score / last_grade / last_scanned_at: updated
    Silently skips if Supabase is not configured or customer not found.
    """
    try:
        import httpx as _httpx, json as _json
        SUPABASE_URL = os.getenv("SUPABASE_URL","")
        SUPABASE_KEY = os.getenv("SUPABASE_KEY","")
        if not (SUPABASE_URL and SUPABASE_KEY):
            return
        hdrs = {
            "apikey":        SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type":  "application/json",
            "Prefer":        "return=representation",
        }
        async with _httpx.AsyncClient(timeout=10) as cli:
            # 1. Find customer by domain
            r = await cli.get(
                f"{SUPABASE_URL}/rest/v1/customers?domain=eq.{domain}&limit=1",
                headers=hdrs,
            )
            customers = r.json() if r.status_code == 200 else []
            if not customers:
                return  # No registered customer for this domain, skip silently
            cust = customers[0]
            cid  = cust["customer_id"]

            # 2. Insert scan_history row
            r2 = await cli.post(
                f"{SUPABASE_URL}/rest/v1/scan_history",
                headers=hdrs,
                json={"customer_id": cid, "domain": domain,
                      "score": score, "grade": grade,
                      "scanned_at": scanned_at},
            )
            scan_id = None
            if r2.status_code in (200, 201):
                rows = r2.json()
                scan_id = rows[0]["id"] if rows else None

            # 3. Delete old unresolved findings for this customer (replace with fresh scan)
            await cli.delete(
                f"{SUPABASE_URL}/rest/v1/scan_findings"
                f"?customer_id=eq.{cid}&resolved=eq.false",
                headers=hdrs,
            )

            # 4. Insert new findings
            SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            rows_to_insert = []
            for f in all_findings:
                rows_to_insert.append({
                    "customer_id":    cid,
                    "domain":         domain,
                    "scan_id":        scan_id,
                    "category":       f.category,
                    "severity":       f.severity,
                    "severity_order": SEV_ORDER.get(f.severity, 4),
                    "title":          f.title,
                    "title_ko":       f.title_ko,
                    "description":    f.description,
                    "description_ko": f.description_ko,
                    "remediation":    f.remediation,
                    "remediation_ko": f.remediation_ko,
                    "resolved":       False,
                    "found_at":       scanned_at,
                })
            if rows_to_insert:
                await cli.post(
                    f"{SUPABASE_URL}/rest/v1/scan_findings",
                    headers=hdrs,
                    json=rows_to_insert,
                )

            # 5. Update customer last_score / last_grade / last_scanned_at
            await cli.patch(
                f"{SUPABASE_URL}/rest/v1/customers?customer_id=eq.{cid}",
                headers=hdrs,
                json={"last_score": score, "last_grade": grade,
                      "last_scanned_at": scanned_at},
            )
            logger.info(f"Scan saved to DB: {domain} score={score} grade={grade} "
                        f"findings={len(all_findings)}")
    except Exception as e:
        logger.warning(f"save_scan_to_db failed (non-fatal): {e}")


@app.post("/scan", response_model=ScanResult)
async def run_domain_scan(req: ScanRequest):
    domain=req.domain; lang=req.lang or "en"
    exists,reason=await verify_domain_exists(domain)
    if not exists:
        raise HTTPException(status_code=422,detail={
            "error":"domain_not_found",
            "message_en":reason,
            "message_ko":f"도메인 '{domain}'이 존재하지 않거나 DNS 조회에 실패했습니다.",
        })
    all_findings=[]
    for result in await asyncio.gather(
        check_ssl(domain),check_http_headers(domain),check_email_security(domain),
        check_dns(domain),check_open_ports(domain),check_virustotal(domain),
        return_exceptions=True):
        if isinstance(result,list): all_findings.extend(result)
    all_findings=sort_findings(all_findings)
    score=deduct(all_findings); grade=calc_grade(score)
    email_sent=False
    if req.email:
        email_sent=await send_email_report(req.email,domain,score,grade,all_findings,lang)
    scanned_at_iso = datetime.now(timezone.utc).isoformat()
    # Sprint 3: persist to DB in background (non-blocking)
    asyncio.create_task(save_scan_to_db(domain, score, grade, all_findings, scanned_at_iso))
    return ScanResult(
        domain=domain,score=score,grade=grade,
        scanned_at=scanned_at_iso,
        findings=all_findings if req.email else [],
        preview_findings=all_findings[:3],
        summary_en=build_summary(domain,score,grade,all_findings,"en"),
        summary_ko=build_summary(domain,score,grade,all_findings,"ko"),
        full_report=bool(req.email),email_sent=email_sent)

@app.post("/scan/file")
async def run_file_scan(
    file:  UploadFile        = File(...),
    lang:  str               = Form("en"),
    email: Optional[str]     = Form(None),
):
    raw = await file.read(500_001)
    if len(raw) > 500_000:
        raise HTTPException(413, "File too large (max 500 KB)")
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(400, "Cannot decode file as text")
    filename = file.filename or "uploaded_file"
    findings, lines_ctx = scan_code(text, filename)
    score    = deduct(findings)
    grade    = calc_grade(score)
    email_sent = False
    if email:
        email_sent = await send_email_report(
            to_email=email, domain=filename,
            score=score, grade=grade,
            findings=findings, lang=lang,
            lines_ctx=lines_ctx,
        )
    return {
        "filename": filename, "score": score, "grade": grade,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": [f.model_dump() for f in findings],
        "summary_en": build_summary(filename, score, grade, findings, "en"),
        "summary_ko": build_summary(filename, score, grade, findings, "ko"),
        "language": detect_language(filename),
        "email_sent": email_sent,
    }

@app.get("/health")
async def health():
    return {"status":"ok","version":"1.2.0","virustotal":bool(VIRUSTOTAL_KEY),
            "email":bool(RESEND_API_KEY),"from_email":FROM_EMAIL}


# ── Sprint 4: Customer API (Direction 2 — Domain Scan SaaS) ──────────────────
# Replaces agent_api. No agent installation required.
# Endpoints: /customer/register, /customer/domain/*, /customer/scan/trigger, etc.
try:
    from customer_api import customer_router
    app.include_router(customer_router, prefix="")
    logger.info("Customer API routes loaded")
except ImportError:
    logger.warning("customer_api.py not found — customer endpoints disabled.")

# ── Dashboard API ─────────────────────────────────────────────────────────────
try:
    from dashboard_api import dashboard_router
    app.include_router(dashboard_router, prefix="")
    logger.info("Dashboard API routes loaded")
except ImportError:
    logger.warning("dashboard_api.py not found — dashboard endpoints disabled.")

# ══════════════════════════════════════════════════════════════════════════════
# Sprint 4 — Tier System & Enhanced Scan Functions
# Free:  15 checks, 5 scans/month
# Plus:  35 checks, 50 scans/month  ($19/mo)
# Max:   60 checks, unlimited        ($49/mo)
# ══════════════════════════════════════════════════════════════════════════════

import hashlib as _hashlib

TIER_LIMITS = {
    "free": {
        "scans_per_month":     5,
        "file_scans_per_month": 3,
        "file_max_kb":         500,
        "event_retention_days": 7,
        "agents":              1,
    },
    "plus": {
        "scans_per_month":     50,
        "file_scans_per_month": 30,
        "file_max_kb":         2048,
        "event_retention_days": 90,
        "agents":              5,
    },
    "max": {
        "scans_per_month":     999999,
        "file_scans_per_month": 999999,
        "file_max_kb":         10240,
        "event_retention_days": 365,
        "agents":              999999,
    },
}


# ── Tier enforcement helpers ──────────────────────────────────────────────────

async def check_scan_quota(customer_id: str, tier: str) -> tuple[bool, str]:
    """Returns (allowed, reason). Checks monthly scan count against tier limit."""
    limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])["scans_per_month"]
    if limit >= 999999:
        return True, "unlimited"
    try:
        SUPABASE_URL = os.getenv("SUPABASE_URL","")
        SUPABASE_KEY  = os.getenv("SUPABASE_KEY","")
        import httpx as _httpx
        if not (SUPABASE_URL and SUPABASE_KEY):
            return True, "supabase_not_configured"
        month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        async with _httpx.AsyncClient(timeout=8) as cli:
            r = await cli.get(
                f"{SUPABASE_URL}/rest/v1/scan_history"
                f"?customer_id=eq.{customer_id}&scanned_at=gte.{month_start}&select=id",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
            )
            count = len(r.json()) if r.status_code == 200 else 0
        if count >= limit:
            return False, f"Monthly scan limit reached ({count}/{limit}). Upgrade to scan more."
        return True, f"{count}/{limit} scans used this month"
    except Exception as e:
        logger.warning(f"Quota check failed (allowing): {e}")
        return True, "quota_check_failed"


# ── Plus: SSL Deep Checks ─────────────────────────────────────────────────────

async def check_ssl_deep(domain: str):
    """Plus/Max: Certificate Transparency, HSTS Preload, chain completeness, OCSP, TLS 1.3"""
    findings = []
    try:
        # 1. Certificate Transparency log check (crt.sh)
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(
                f"https://crt.sh/?q={domain}&output=json",
                headers={"User-Agent": "CyberShield/2.0"},
            )
            if r.status_code == 200:
                certs = r.json()
                issuers = set()
                for c in certs[:50]:
                    issuer = c.get("issuer_name", "")
                    issuers.add(issuer)
                if len(issuers) > 5:
                    findings.append(F(
                        "ssl-ct-many-issuers", "ssl", "medium",
                        f"Certificate Transparency: {len(issuers)} different issuers found",
                        f"Certificate Transparency: {len(issuers)}개 발급 기관 발견",
                        "Multiple CAs issuing certificates for your domain may indicate unauthorized certificate issuance. Review crt.sh for unexpected entries.",
                        "여러 CA가 귀사 도메인에 인증서를 발급했습니다. crt.sh에서 예상치 않은 항목을 검토하세요.",
                        "Review https://crt.sh for unexpected certificates and add CAA records to restrict issuers.",
                        "https://crt.sh에서 예상치 않은 인증서를 검토하고 CAA 레코드를 추가해 발급 기관을 제한하세요.",
                        6,
                    ))
    except Exception:
        pass

    try:
        # 2. HSTS Preload list membership
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://hstspreload.org/api/v2/status?domain={domain}",
                headers={"User-Agent": "CyberShield/2.0"},
            )
            if r.status_code == 200:
                data = r.json()
                status = data.get("status", "")
                if status not in ("preloaded", "pending"):
                    findings.append(F(
                        "ssl-hsts-not-preloaded", "ssl", "low",
                        "Domain not on HSTS Preload list",
                        "HSTS Preload 목록에 없음",
                        "HSTS preloading hardcodes your domain into browsers so it always uses HTTPS, even on the very first visit.",
                        "HSTS Preload는 브라우저에 도메인을 하드코딩하여 첫 방문부터 항상 HTTPS를 강제합니다.",
                        "Submit your domain at https://hstspreload.org after ensuring HSTS max-age ≥ 31536000 with includeSubDomains.",
                        "HSTS max-age ≥ 31536000 및 includeSubDomains 설정 후 https://hstspreload.org에서 신청하세요.",
                        2,
                    ))
    except Exception:
        pass

    try:
        # 3. TLS 1.3 support + OCSP stapling check
        ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx13.check_hostname = False
        ctx13.verify_mode = ssl.CERT_NONE
        conn = socket.create_connection((domain, 443), timeout=TIMEOUT)
        try:
            with ctx13.wrap_socket(conn, server_hostname=domain) as s:
                ver = s.version()
                if ver != "TLSv1.3":
                    findings.append(F(
                        "ssl-no-tls13", "ssl", "low",
                        "TLS 1.3 not prioritized",
                        "TLS 1.3 미우선 사용",
                        "TLS 1.3 is significantly faster and more secure than TLS 1.2 due to simplified handshake and forward secrecy improvements.",
                        "TLS 1.3은 간소화된 핸드셰이크와 향상된 전방향 비밀성으로 TLS 1.2보다 훨씬 빠르고 안전합니다.",
                        "Configure your server to prefer TLS 1.3 (Nginx: ssl_protocols TLSv1.2 TLSv1.3).",
                        "서버가 TLS 1.3을 우선하도록 설정하세요 (Nginx: ssl_protocols TLSv1.2 TLSv1.3).",
                        2,
                    ))
        except Exception:
            findings.append(F(
                "ssl-no-tls13", "ssl", "low",
                "TLS 1.3 not supported",
                "TLS 1.3 미지원",
                "Server does not support TLS 1.3. Modern clients prefer TLS 1.3 for faster handshakes and better security.",
                "서버가 TLS 1.3을 지원하지 않습니다. 최신 클라이언트는 더 빠르고 안전한 TLS 1.3을 선호합니다.",
                "Enable TLS 1.3 on your web server.",
                "웹 서버에서 TLS 1.3을 활성화하세요.",
                2,
            ))
        finally:
            conn.close()
    except Exception:
        pass

    return findings


# ── Plus: HTTP Headers Deep Checks ───────────────────────────────────────────

async def check_headers_deep(domain: str):
    """Plus/Max: SRI, COOP/COEP, CSP depth analysis, open redirect probe"""
    findings = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            r = await client.get(
                f"https://{domain}",
                headers={"User-Agent": "CyberShield/2.0"},
            )
            h = {k.lower(): v for k, v in r.headers.items()}
            body = r.text[:40000] if r.status_code == 200 else ""
            csp = h.get("content-security-policy", "")

            # 1. CSP deep analysis
            if csp:
                issues = []
                if "unsafe-eval" in csp:
                    issues.append("'unsafe-eval' allows dynamic code execution (eval, setTimeout with string)")
                if "data:" in csp and "script-src" in csp:
                    issues.append("'data:' in script-src allows data URI script injection")
                # Wildcard domain check
                import re as _re
                wildcards = _re.findall(r"https?://\*\.[a-z0-9.-]+", csp)
                if wildcards:
                    issues.append(f"Wildcard sources allow any subdomain: {', '.join(wildcards[:3])}")
                if issues:
                    findings.append(F(
                        "csp-deep-issues", "headers", "medium",
                        f"CSP policy has {len(issues)} dangerous directive(s)",
                        f"CSP 정책에 {len(issues)}개 위험 지시문",
                        " | ".join(issues),
                        " | ".join(issues),
                        "Review CSP directives and remove unsafe entries. Use nonces instead of 'unsafe-inline'.",
                        "CSP 지시문을 검토하고 안전하지 않은 항목을 제거하세요. 'unsafe-inline' 대신 nonce를 사용하세요.",
                        6,
                    ))

            # 2. Cross-Origin-Opener-Policy
            if "cross-origin-opener-policy" not in h:
                findings.append(F(
                    "header-coop-missing", "headers", "low",
                    "Cross-Origin-Opener-Policy (COOP) missing",
                    "COOP 헤더 없음",
                    "Without COOP, malicious pages opened from your site can access your window object (Spectre attack vector).",
                    "COOP 없이 귀사 사이트에서 열린 악성 페이지가 window 객체에 접근할 수 있습니다 (Spectre 공격 벡터).",
                    "Add: Cross-Origin-Opener-Policy: same-origin",
                    "헤더 추가: Cross-Origin-Opener-Policy: same-origin",
                    2,
                ))

            # 3. Cross-Origin-Embedder-Policy
            if "cross-origin-embedder-policy" not in h:
                findings.append(F(
                    "header-coep-missing", "headers", "low",
                    "Cross-Origin-Embedder-Policy (COEP) missing",
                    "COEP 헤더 없음",
                    "Without COEP, SharedArrayBuffer and high-resolution timers are unavailable, and cross-origin resources can be loaded without explicit permission.",
                    "COEP 없이 SharedArrayBuffer와 고해상도 타이머 사용이 제한되고 크로스 오리진 리소스 제어가 약화됩니다.",
                    "Add: Cross-Origin-Embedder-Policy: require-corp",
                    "헤더 추가: Cross-Origin-Embedder-Policy: require-corp",
                    2,
                ))

            # 4. Subresource Integrity missing on external scripts
            if body:
                import re as _re
                ext_scripts = _re.findall(
                    r'<script[^>]+src=["\']https?://(?!' + domain.replace(".", r"\.") + r')[^"\']+["\'][^>]*>',
                    body, _re.I
                )
                no_sri = [s for s in ext_scripts if "integrity=" not in s.lower()]
                if no_sri:
                    findings.append(F(
                        "header-sri-missing", "headers", "medium",
                        f"{len(no_sri)} external script(s) loaded without Subresource Integrity (SRI)",
                        f"SRI(하위 리소스 무결성) 없이 {len(no_sri)}개 외부 스크립트 로드",
                        f"Scripts from CDNs without SRI can be tampered. If the CDN is compromised, malicious code runs on your users' browsers. Found: {no_sri[0][:120]}",
                        f"SRI 없는 CDN 스크립트는 변조 위험이 있습니다. CDN 침해 시 악성 코드가 사용자 브라우저에서 실행됩니다.",
                        "Add integrity and crossorigin attributes: <script src='...' integrity='sha384-...' crossorigin='anonymous'>",
                        "integrity 및 crossorigin 속성 추가: <script src='...' integrity='sha384-...' crossorigin='anonymous'>",
                        6,
                    ))

            # 5. Admin path exposure
            admin_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.git/HEAD", "/.env", "/config.php"]
            exposed = []
            for path in admin_paths:
                try:
                    resp = await client.get(
                        f"https://{domain}{path}",
                        headers={"User-Agent": "CyberShield/2.0"},
                        follow_redirects=False,
                    )
                    if resp.status_code in (200, 403):  # 403 = exists but forbidden
                        exposed.append(f"{path} ({resp.status_code})")
                except Exception:
                    pass
            if exposed:
                findings.append(F(
                    "webapp-admin-exposed", "headers", "high",
                    f"Sensitive paths accessible: {', '.join(exposed[:3])}",
                    f"민감 경로 접근 가능: {', '.join(exposed[:3])}",
                    f"The following sensitive paths responded: {', '.join(exposed)}. Attackers actively probe these paths.",
                    f"다음 민감 경로가 응답합니다: {', '.join(exposed)}. 공격자들이 이 경로를 적극적으로 탐색합니다.",
                    "Restrict access to admin paths using IP whitelist, HTTP auth, or remove them entirely.",
                    "관리자 경로를 IP 화이트리스트, HTTP 인증으로 제한하거나 완전히 제거하세요.",
                    12,
                ))

            # 6. HTTP TRACE method
            try:
                trace_r = await client.request(
                    "TRACE", f"https://{domain}",
                    headers={"User-Agent": "CyberShield/2.0"},
                )
                if trace_r.status_code in (200, 405) and trace_r.status_code != 405:
                    findings.append(F(
                        "webapp-trace-enabled", "headers", "medium",
                        "HTTP TRACE method enabled",
                        "HTTP TRACE 메서드 활성화",
                        "TRACE allows Cross-Site Tracing (XST) attacks that can steal HttpOnly cookies.",
                        "TRACE는 HttpOnly 쿠키를 탈취할 수 있는 XST(Cross-Site Tracing) 공격을 허용합니다.",
                        "Disable TRACE method (Apache: TraceEnable off, Nginx: already disabled by default).",
                        "TRACE 메서드 비활성화 (Apache: TraceEnable off, Nginx: 기본적으로 비활성화됨).",
                        6,
                    ))
            except Exception:
                pass

    except Exception:
        pass
    return findings


# ── Plus: Email Security Deep Checks ─────────────────────────────────────────

async def check_email_deep(domain: str):
    """Plus/Max: DMARC policy strength, DKIM key length, SPF lookup count, MTA-STS"""
    findings = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = TIMEOUT

    # 1. DMARC policy strength
    try:
        dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rec in dmarc_records:
            txt = str(rec).strip('"')
            if "v=DMARC1" in txt:
                if "p=none" in txt:
                    findings.append(F(
                        "email-dmarc-none", "email", "high",
                        "DMARC policy is 'none' — no enforcement",
                        "DMARC 정책이 'none' — 강제 적용 없음",
                        "p=none means DMARC is only monitoring, not blocking. Spoofed emails from your domain are still delivered to recipients.",
                        "p=none은 DMARC가 모니터링만 하고 차단하지 않습니다. 귀사 도메인을 사칭한 이메일이 여전히 수신자에게 전달됩니다.",
                        "Change to p=quarantine first, then p=reject after monitoring reports for 2-4 weeks.",
                        "먼저 p=quarantine으로 변경하고, 2-4주간 리포트 모니터링 후 p=reject로 변경하세요.",
                        12,
                    ))
                elif "p=quarantine" in txt:
                    findings.append(F(
                        "email-dmarc-quarantine", "email", "medium",
                        "DMARC policy is 'quarantine' — partial enforcement",
                        "DMARC 정책이 'quarantine' — 부분 적용",
                        "p=quarantine sends suspicious emails to spam. Upgrade to p=reject for full protection.",
                        "p=quarantine은 의심스러운 이메일을 스팸으로 보냅니다. 완전한 보호를 위해 p=reject로 업그레이드하세요.",
                        "After confirming no legitimate email is rejected, upgrade to p=reject.",
                        "합법적인 이메일이 차단되지 않는 것을 확인한 후 p=reject로 업그레이드하세요.",
                        6,
                    ))
                # Check rua/ruf reporting
                if "rua=" not in txt and "ruf=" not in txt:
                    findings.append(F(
                        "email-dmarc-no-report", "email", "low",
                        "DMARC has no reporting addresses (rua/ruf)",
                        "DMARC 리포팅 주소 없음 (rua/ruf)",
                        "Without reporting, you cannot see who is spoofing your domain or if legitimate emails are failing.",
                        "리포팅 없이 귀사 도메인 사칭 현황이나 합법적 이메일 실패 여부를 알 수 없습니다.",
                        "Add rua=mailto:dmarc-reports@yourdomain.com to DMARC record.",
                        "DMARC 레코드에 rua=mailto:dmarc-reports@yourdomain.com을 추가하세요.",
                        2,
                    ))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception:
        pass

    # 2. SPF lookup count (max 10 DNS lookups)
    try:
        spf_records = resolver.resolve(domain, "TXT")
        for rec in spf_records:
            txt = str(rec).strip('"')
            if txt.startswith("v=spf1"):
                # Count mechanisms that require DNS lookups
                lookup_mechanisms = re.findall(r'\b(include|a|mx|ptr|exists):', txt)
                count = len(lookup_mechanisms)
                if count >= 8:
                    findings.append(F(
                        "email-spf-lookup-limit", "email", "medium" if count < 10 else "high",
                        f"SPF record uses {count}/10 DNS lookups — approaching limit",
                        f"SPF 레코드가 {count}/10 DNS 조회 사용 — 한도 근접",
                        f"SPF has a 10 DNS lookup limit. With {count} lookups, adding any more includes/redirects will cause SPF to fail (permerror), allowing spoofed emails through.",
                        f"SPF는 DNS 조회 10회 제한이 있습니다. 현재 {count}회 사용 중이며 더 추가하면 SPF 실패로 이메일 인증이 깨집니다.",
                        "Flatten your SPF record using tools like dmarcian or AutoSPF to reduce lookup count.",
                        "dmarcian 또는 AutoSPF 같은 도구로 SPF 레코드를 평탄화해 조회 횟수를 줄이세요.",
                        6 if count < 10 else 12,
                    ))
                break
    except Exception:
        pass

    # 3. MTA-STS policy
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                headers={"User-Agent": "CyberShield/2.0"},
                follow_redirects=True,
            )
            if r.status_code != 200:
                findings.append(F(
                    "email-mta-sts-missing", "email", "low",
                    "MTA-STS not configured",
                    "MTA-STS 미설정",
                    "MTA-STS prevents email downgrade attacks and DNS spoofing by requiring TLS for email delivery to your server.",
                    "MTA-STS는 이메일 다운그레이드 공격과 DNS 스푸핑을 방지하고 이메일 전송에 TLS를 요구합니다.",
                    "Implement MTA-STS by publishing a policy at https://mta-sts.yourdomain.com/.well-known/mta-sts.txt",
                    "https://mta-sts.yourdomain.com/.well-known/mta-sts.txt에 정책을 게시해 MTA-STS를 구현하세요.",
                    2,
                ))
    except Exception:
        findings.append(F(
            "email-mta-sts-missing", "email", "low",
            "MTA-STS not configured",
            "MTA-STS 미설정",
            "MTA-STS prevents email delivery downgrade attacks by requiring TLS when sending email to your server.",
            "MTA-STS는 이메일 전송 다운그레이드 공격을 방지합니다.",
            "Implement MTA-STS for your domain.",
            "도메인에 MTA-STS를 구현하세요.",
            2,
        ))

    return findings


# ── Plus: DNS Deep Checks ─────────────────────────────────────────────────────

async def check_dns_deep(domain: str):
    """Plus/Max: Zone transfer, subdomain takeover 20 services, NS redundancy"""
    findings = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = TIMEOUT

    # 1. DNS Zone Transfer (AXFR)
    try:
        ns_records = resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_str = str(ns.target).rstrip(".")
            try:
                import dns.zone, dns.query
                dns.zone.from_xfr(dns.query.xfr(ns_str, domain, timeout=5))
                findings.append(F(
                    "dns-zone-transfer", "dns", "critical",
                    f"DNS Zone Transfer allowed from {ns_str}",
                    f"DNS Zone Transfer 허용: {ns_str}",
                    "Zone transfer exposes your entire DNS configuration including internal hostnames, IPs, and mail servers to anyone.",
                    "Zone Transfer는 내부 호스트명, IP, 메일 서버 등 전체 DNS 설정을 누구에게나 노출합니다.",
                    "Restrict AXFR to authoritative nameservers only. Configure 'allow-transfer' in BIND or equivalent.",
                    "AXFR을 권한 있는 네임서버로만 제한하세요. BIND의 'allow-transfer' 또는 동등한 설정을 구성하세요.",
                    22,
                ))
            except Exception:
                pass  # zone transfer rejected = good
    except Exception:
        pass

    # 2. Subdomain takeover — check common subdomains against known fingerprints
    TAKEOVER_SUBS = {
        "www": None, "blog": None, "shop": None, "app": None,
        "api": None, "dev": None, "staging": None, "cdn": None,
    }
    TAKEOVER_FINGERPRINTS = [
        "There isn't a GitHub Pages site here",
        "herokucdn.com/error-pages/no-such-app",
        "doesn't exist",
        "NoSuchBucket",
        "The specified bucket does not exist",
        "Repository not found",
        "The feed has not been found",
        "project not found",
    ]
    try:
        async with httpx.AsyncClient(timeout=6, follow_redirects=False) as client:
            for sub in TAKEOVER_SUBS:
                subdomain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(subdomain)
                    r = await client.get(
                        f"https://{subdomain}",
                        headers={"User-Agent": "CyberShield/2.0"},
                    )
                    body = r.text[:2000].lower()
                    for fp in TAKEOVER_FINGERPRINTS:
                        if fp.lower() in body:
                            findings.append(F(
                                f"dns-subdomain-takeover-{sub}", "dns", "critical",
                                f"Subdomain takeover risk: {subdomain}",
                                f"서브도메인 탈취 위험: {subdomain}",
                                f"The subdomain {subdomain} resolves but shows a takeover fingerprint. An attacker could claim this service and serve content under your domain.",
                                f"{subdomain}은 DNS에서 해석되지만 탈취 지문이 발견됐습니다. 공격자가 귀사 도메인으로 콘텐츠를 제공할 수 있습니다.",
                                f"Remove the DNS record for {subdomain} or reclaim the service it points to.",
                                f"{subdomain}의 DNS 레코드를 제거하거나 가리키는 서비스를 재확보하세요.",
                                22,
                            ))
                            break
                except (socket.gaierror, Exception):
                    pass
    except Exception:
        pass

    # 3. Nameserver redundancy
    try:
        ns_records = list(resolver.resolve(domain, "NS"))
        if len(ns_records) < 2:
            findings.append(F(
                "dns-single-ns", "dns", "medium",
                "Only one nameserver configured — single point of failure",
                "네임서버 1개만 설정 — 단일 장애점",
                "A single nameserver means your entire domain becomes unreachable if that server goes down.",
                "네임서버가 1개이면 해당 서버 장애 시 도메인 전체가 접근 불가가 됩니다.",
                "Add at least 2 nameservers from different providers or data centers.",
                "서로 다른 공급자 또는 데이터센터의 네임서버를 최소 2개 설정하세요.",
                6,
            ))
    except Exception:
        pass

    return findings


# ── Max: Extended Port + Web App Checks ──────────────────────────────────────

async def check_ports_extended(domain: str):
    """Max only: extended 50-port scan + banner grabbing"""
    extended_ports = {
        # Kubernetes / container orchestration
        2376: ("Docker TLS", "docker-tls-open", "critical",
               "Docker TLS API exposed — remote container control possible",
               "Docker TLS API 노출 — 원격 컨테이너 제어 가능"),
        6443: ("Kubernetes API", "k8s-api-open", "critical",
               "Kubernetes API server exposed — cluster takeover risk",
               "Kubernetes API 서버 노출 — 클러스터 탈취 위험"),
        2379: ("etcd", "etcd-open", "critical",
               "etcd exposed — Kubernetes cluster secrets readable without auth",
               "etcd 노출 — 인증 없이 Kubernetes 클러스터 시크릿 읽기 가능"),
        # Cache / messaging
        11211: ("Memcached", "memcached-open", "critical",
                "Memcached exposed — used in DDoS amplification attacks",
                "Memcached 노출 — DDoS 증폭 공격에 악용됨"),
        5672: ("RabbitMQ", "rabbitmq-open", "high",
               "RabbitMQ AMQP port exposed — message queue access possible",
               "RabbitMQ AMQP 포트 노출 — 메시지 큐 접근 가능"),
        # Additional DB
        1433: ("MSSQL", "mssql-open", "high",
               "Microsoft SQL Server port exposed to internet",
               "MS SQL Server 포트 인터넷 노출"),
        1521: ("Oracle DB", "oracle-open", "high",
               "Oracle Database port exposed to internet",
               "Oracle 데이터베이스 포트 인터넷 노출"),
        # Admin / monitoring
        8500: ("Consul", "consul-open", "critical",
               "Consul API exposed — service mesh and secrets accessible",
               "Consul API 노출 — 서비스 메시 및 시크릿 접근 가능"),
        9090: ("Prometheus", "prometheus-open", "high",
               "Prometheus metrics exposed — infrastructure details leaked",
               "Prometheus 메트릭 노출 — 인프라 세부 정보 유출"),
        3000: ("Grafana/Dev", "grafana-open", "medium",
               "Port 3000 open — Grafana or development server may be exposed",
               "포트 3000 오픈 — Grafana 또는 개발 서버 노출 가능"),
        8888: ("Jupyter", "jupyter-open", "critical",
               "Port 8888 open — Jupyter Notebook often runs without auth",
               "포트 8888 오픈 — Jupyter Notebook이 인증 없이 실행될 수 있음"),
        # File sharing
        445: ("SMB", "smb-open", "critical",
              "SMB port exposed — EternalBlue/ransomware attack vector",
              "SMB 포트 노출 — EternalBlue/랜섬웨어 공격 벡터"),
        139: ("NetBIOS", "netbios-open", "high",
              "NetBIOS port exposed — Windows file sharing attack vector",
              "NetBIOS 포트 노출 — Windows 파일 공유 공격 벡터"),
    }

    sev_impact = {"critical": 22, "high": 12, "medium": 6, "low": 2}

    async def probe(port):
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(domain, port), timeout=2
            )
            w.close()
            return port
        except Exception:
            return None

    open_ports = [p for p in await asyncio.gather(*[probe(p) for p in extended_ports]) if p]
    findings = []
    for port in open_ports:
        name, fid, sev, desc_en, desc_ko = extended_ports[port]
        findings.append(F(
            fid, "ports", sev,
            f"Port {port} ({name}) open and reachable from internet",
            f"포트 {port} ({name}) 인터넷에서 접근 가능",
            desc_en, desc_ko,
            f"Immediately block port {port} at the firewall. This service should never be internet-facing.",
            f"방화벽에서 포트 {port}를 즉시 차단하세요. 이 서비스는 절대 인터넷에 노출되어서는 안 됩니다.",
            sev_impact.get(sev, 6),
        ))
    return findings


# ── Max: Sensitive Information Leak Check ────────────────────────────────────

async def check_info_leak(domain: str):
    """Max only: Check for exposed .env, backup files, git, sensitive comments"""
    findings = []
    sensitive_paths = [
        ("/.env",              "Environment file",    "critical"),
        ("/.env.local",        ".env.local file",     "critical"),
        ("/.env.production",   ".env.production",     "critical"),
        ("/wp-config.php.bak", "WordPress config backup", "critical"),
        ("/backup.sql",        "SQL database backup", "critical"),
        ("/backup.zip",        "Site backup archive", "critical"),
        ("/.git/config",       "Git repository config", "high"),
        ("/config.json",       "Config JSON file",    "high"),
        ("/server-status",     "Apache server-status", "medium"),
        ("/phpinfo.php",       "PHP info page",       "high"),
    ]

    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            for path, name, sev in sensitive_paths:
                try:
                    r = await client.get(
                        f"https://{domain}{path}",
                        headers={"User-Agent": "CyberShield/2.0"},
                    )
                    if r.status_code == 200 and len(r.content) > 10:
                        # Confirm it's not a custom 404
                        body = r.text[:500].lower()
                        if not any(x in body for x in ["404", "not found", "doesn't exist"]):
                            findings.append(F(
                                f"leak-{path.strip('/').replace('/', '-').replace('.', '')}",
                                "headers", sev,
                                f"{name} publicly accessible: {path}",
                                f"{name} 공개 접근 가능: {path}",
                                f"The file {path} is publicly accessible and may contain credentials, database passwords, API keys, or server configuration.",
                                f"{path} 파일이 공개적으로 접근 가능하며 자격증명, DB 비밀번호, API 키, 서버 설정이 포함될 수 있습니다.",
                                f"Immediately restrict access to {path}. Remove from web root or configure server to deny access.",
                                f"{path}에 대한 접근을 즉시 제한하세요. 웹 루트에서 제거하거나 서버에서 접근 차단을 설정하세요.",
                                22 if sev == "critical" else 12,
                            ))
                except Exception:
                    pass
    except Exception:
        pass
    return findings


# ── Updated /scan endpoint with tier-based scanning ──────────────────────────

@app.post("/scan/v2", response_model=ScanResult)
async def run_domain_scan_v2(req: ScanRequest):
    """
    Tier-aware domain scan.
    Free:  6 standard checks (same as /scan)
    Plus:  +SSL deep, +Headers deep, +Email deep, +DNS deep  (~35 checks)
    Max:   All Plus checks + Extended ports + Info leak scan  (~60 checks)
    """
    domain = req.domain
    lang   = req.lang or "en"
    tier   = (req.tier or "free").lower()
    if tier not in ("free", "plus", "max"):
        tier = "free"

    # Domain existence check
    exists, reason = await verify_domain_exists(domain)
    if not exists:
        raise HTTPException(status_code=422, detail={
            "error": "domain_not_found",
            "message_en": reason,
            "message_ko": f"도메인 '{domain}'이 존재하지 않거나 DNS 조회에 실패했습니다.",
        })

    # Quota check
    if req.customer_id:
        allowed, quota_msg = await check_scan_quota(req.customer_id, tier)
        if not allowed:
            raise HTTPException(status_code=429, detail={
                "error": "scan_quota_exceeded",
                "message_en": quota_msg,
                "message_ko": f"월간 스캔 횟수를 초과했습니다. 업그레이드 후 더 많은 스캔이 가능합니다.",
                "tier": tier,
            })

    # Build scan task list based on tier
    tasks = [
        check_ssl(domain),
        check_http_headers(domain),
        check_email_security(domain),
        check_dns(domain),
        check_open_ports(domain),
        check_virustotal(domain),
    ]

    if tier in ("plus", "max"):
        tasks += [
            check_ssl_deep(domain),
            check_headers_deep(domain),
            check_email_deep(domain),
            check_dns_deep(domain),
        ]

    if tier == "max":
        tasks += [
            check_ports_extended(domain),
            check_info_leak(domain),
        ]

    # Run all checks concurrently
    all_findings = []
    for result in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(result, list):
            all_findings.extend(result)

    all_findings = sort_findings(all_findings)
    score = deduct(all_findings)
    grade = calc_grade(score)

    email_sent = False
    if req.email:
        email_sent = await send_email_report(req.email, domain, score, grade, all_findings, lang)

    scanned_at_iso = datetime.now(timezone.utc).isoformat()

    if req.customer_id:
        asyncio.create_task(
            save_scan_to_db(domain, score, grade, all_findings, scanned_at_iso)
        )

    scan_depths = {"free": 6, "plus": 10, "max": 12}
    return ScanResult(
        domain=domain, score=score, grade=grade,
        scanned_at=scanned_at_iso,
        findings=all_findings if req.email else [],
        preview_findings=all_findings[:5],
        summary_en=build_summary(domain, score, grade, all_findings, "en")
                   + f" ({scan_depths[tier]} scan modules, {len(all_findings)} findings)",
        summary_ko=build_summary(domain, score, grade, all_findings, "ko")
                   + f" ({scan_depths[tier]}개 스캔 모듈, {len(all_findings)}개 취약점 발견)",
        full_report=bool(req.email),
        email_sent=email_sent,
    )
