# CyberShield — Sprint 2: Security Agent v1

## 전체 구조 설명

```
Sprint 2 파일 구성
├── agent/
│   ├── main.go        ← 에이전트 핵심 로직 (Go, 크로스 플랫폼)
│   ├── exec.go        ← 명령어 실행 헬퍼
│   ├── go.mod         ← Go 모듈 파일 (외부 의존성 없음)
│   ├── install.sh     ← macOS 설치 스크립트 (launchd 서비스 등록)
│   └── install.ps1    ← Windows 설치 스크립트 (Windows Service 등록)
├── backend_additions/
│   └── agent_api.py   ← FastAPI 라우터 (기존 main.py에 추가)
└── onboarding/
    └── onboarding.html ← 고객 온보딩 페이지 (에이전트 설치 가이드)
```

---

## Step 1: 백엔드에 에이전트 API 추가

### 1-1. Supabase 프로젝트 생성 (무료)
1. https://supabase.com → 새 프로젝트 생성
2. Project Settings → API → `URL`과 `service_role` 키 복사
3. SQL Editor에서 아래 실행:

```sql
-- agent_api.py 파일 맨 아래 주석 안의 SQL을 복사해서 실행
```

### 1-2. Railway 환경변수 추가
Railway 대시보드 → Variables에 추가:
```
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_KEY=eyJhbGc...  (service_role key)
ADMIN_API_KEY=your_secret_admin_key_here
```

### 1-3. main.py 맨 아래에 추가
```python
from agent_api import agent_router
app.include_router(agent_router, prefix="")
```

### 1-4. requirements.txt에 추가 (불필요 — httpx 이미 있음)
supabase는 REST API로 직접 호출하므로 추가 패키지 필요 없음.

### 1-5. Railway 재배포
```bash
railway up
```

---

## Step 2: 에이전트 Go 바이너리 빌드

Go가 설치되어 있어야 합니다: https://go.dev/dl/

```bash
cd agent/

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o cybershield-agent .

# macOS (Apple Silicon M1/M2/M3)
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o cybershield-agent-arm64 .

# Windows 64bit
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o cybershield-agent.exe .

# Linux 64bit
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cybershield-agent-linux .
```

빌드 결과: 단일 바이너리, 외부 의존성 없음, 약 6-8 MB.

---

## Step 3: 온보딩 페이지 배포

`onboarding/onboarding.html`을 Vercel에 `install/index.html`로 배포:

```
frontend/
├── index.html         ← 기존 메인 페이지
├── install/
│   └── index.html     ← onboarding.html을 이 위치로 복사
```

URL: `https://cybershield.io/install`

---

## Step 4: 다운로드 파일 제공

Vercel의 `public/downloads/` 폴더에 빌드된 바이너리와 스크립트 업로드:

```
public/
├── downloads/
│   ├── cybershield-agent        ← macOS Intel 바이너리
│   ├── cybershield-agent-arm64  ← macOS M1 바이너리
│   ├── cybershield-agent.exe    ← Windows 바이너리
│   ├── install.sh               ← macOS 설치 스크립트
│   └── install.ps1              ← Windows 설치 스크립트
```

온보딩 페이지의 install 명령어는 이 파일들을 `curl`로 다운받는 방식.

---

## 에이전트 작동 방식 요약

### Free 티어에서 하는 일 (3가지)

**1. 로그인 이상 탐지 (30초마다)**
- macOS: `log show` 명령으로 최근 1분 로그 읽기
- Windows: Windows Event Log ID 4625 (로그인 실패) 읽기
- Linux: `/var/log/auth.log` 파싱
- 규칙: 동일 IP에서 30초 내 5회 이상 실패 → Critical 알림 발송

**2. 포트 변화 감지 (5분마다)**
- 127.0.0.1에서 15개 위험 포트 프로브 (2초 타임아웃)
- 이전 스냅샷과 비교 → 새로운 위험 포트 감지 시 알림
- 포트별 심각도: Redis/MongoDB/Docker = Critical, MySQL/RDP = High

**3. 악성 IP 연결 감지 (1시간마다)**
- 현재 TCP 연결 목록 추출 (netstat / ss)
- 외부 IP만 추출 → 백엔드 `/agent/check-ips` 전송
- 백엔드가 VirusTotal로 조회 후 악성 IP 목록 반환
- 악성 IP 연결 발견 시 Critical 알림

### 알림 채널 우선순위
1. Slack webhook (가장 빠름, 비개발자도 편리)
2. 카카오 알림톡 (한국 사용자)
3. 이메일 (항상 작동, Resend)

---

## 고객 온보딩 흐름

```
고객이 cybershield.io/install 방문
  → 이메일 + 도메인 입력
  → /agent/register 호출
  → agent_token + customer_id 발급
  → 설치 명령어 표시 (macOS/Windows/Linux)
  → 고객이 서버에서 1줄 명령어 실행
  → 에이전트 설치 완료 (자동 서비스 등록)
  → 첫 heartbeat 수신 → "에이전트 온라인" 확인
  → 테스트 알림 발송
```

---

## 이메일 수집 여부 확인

이제 `/agent/register`를 통해 온보딩하면:
1. Supabase `customers` 테이블에 이메일 + 도메인 자동 저장
2. Resend 대시보드 → Emails 탭에서 발송 기록 확인 가능
3. Railway 로그에서 `INFO: New customer registered` 확인 가능

Supabase Table Editor → customers 테이블에서 전체 고객 목록 직접 조회 가능.

---

## Sprint 2 완료 기준 (체크리스트)

- [ ] Supabase 테이블 생성 완료
- [ ] agent_api.py를 main.py에 통합 + Railway 재배포
- [ ] Go 에이전트 빌드 (macOS + Windows 바이너리)
- [ ] 온보딩 페이지 Vercel 배포 (`/install`)
- [ ] 내 맥/서버에 에이전트 설치 테스트
- [ ] 테스트 이벤트 발송 확인 (heartbeat → DB → 알림)
- [ ] 파일럿 고객 1명에게 설치 요청 + 피드백 수집
