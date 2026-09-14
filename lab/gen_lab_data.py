#!/usr/bin/env python3
"""핸드북 실습용 합성 보안 데이터 생성기.

실제 침해사고 증거는 쓰지 않는다. 시드와 생성기를 고정한 합성 자료이며,
UTF-8·LF로 저장한다. 생성 후 파일별 해시를 책의 대조값과 비교한다.

주소는 문서용으로 예약된 대역만 쓴다 (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24 / RFC 2606: example.com·example.net·example.org).
문서용 예약은 도메인의 비존재를 뜻하지 않으므로 외부 조회·접속에 사용하지 않는다.

    python3 gen_lab_data.py ~/handbook-lab/evidence

── 시간 설계 ──────────────────────────────────────────────────────────────
사건 하나의 절대 시각을 UTC 로 한 줄에 세워 두고, 로그마다 그 로그가 실제로
쓰는 표기로 렌더한다.

  access.log   +0900 (웹서버가 로컬 시간으로 남긴다)
  auth.log     syslog — 월/일/시각만, 타임존 표기 없음 (UTC 로 기록)
  winlog       UTC (Z)
  Zeek         epoch (UTC)

**표기가 갈리는 것은 일부러 심은 것이다.** 실제 사고에서 제일 자주 사람을 헷갈리게
하는 지점이다. 웹셸 경로 첫 접근은 UTC 17:10:43이고, 윈도우 셸 실행 18:24
보다 약 1시간 13분 앞선다. 변환 없이 숫자만 비교하면 순서가 뒤집힌다.
"""
import hashlib
import json
import pathlib
import random
import sys
from datetime import datetime, timedelta, timezone

SEED = 20260901
random.seed(SEED)

KST = timezone(timedelta(hours=9))
UTC = timezone.utc

ATTACKER = "203.0.113.77"          # 공격자
C2 = "198.51.100.203"              # C2
SCANNER = "198.51.100.14"          # 사내 취약점 스캐너 — 오탐 연습용
VICTIM = "192.0.2.41"              # 침해된 내부 호스트 (APP-SRV-02)

# 사건 절대 시각 (전부 UTC). 아래 표가 모든 로그의 기준이다.
def U(d, h, m, s=0):
    return datetime(2026, 8, d, h, m, s, tzinfo=UTC)

T = {
    "recon_start":  U(23, 16, 12),   # 웹 디렉터리 탐색 시작   (KST 08-24 01:12)
    "sqli_start":   U(23, 16, 45),   # SQLi 프로빙             (KST 01:45)
    "upload":       U(23, 17,  7),   # 웹셸 업로드 성공        (KST 02:07)
    "shell_start":  U(23, 17,  8),   # 웹셸 사용 시작          (KST 02:08)
    "brute_start":  U(23, 17, 31),   # SSH 브루트포스
    "brute_ok":     U(23, 17, 58, 44),
    "spray_start":  U(23, 18,  2),   # 윈도우 계정 스프레이
    "ntlm_ok":      U(23, 18, 19, 51),
    "proc_chain":   U(23, 18, 24),   # w3wp -> cmd -> powershell -enc
    "acct_create":  U(23, 18, 28),   # 4720 / 4732
    "svc_install":  U(23, 18, 31),   # 7045  ← 반드시 프로세스 기동보다 앞
    "svc_running":  U(23, 18, 33),   # wdu.exe 가 서비스로 떠 있음
    "beacon_start": U(23, 18, 35),
    "dns_start":    U(23, 19, 40),
    "snapshot":     U(23, 18, 41),   # processes.csv 를 뜬 시각
}

INTERNAL = [f"192.0.2.{i}" for i in range(10, 60)]
# 정상 클라이언트 풀은 넓게 잡는다. 좁으면 uniq -c 만으로 공격자가 눈에 띄어
# "빈도로는 못 찾는다"는 이 책의 첫 교훈이 성립하지 않는다.
# 198.51.100.147 은 일부러 남긴다 — 스캐너 198.51.100.14 를 grep 하면 같이 걸려서,
# 경계 없는 문자열 매칭이 왜 위험한지 실습에서 직접 보게 된다.
NORMAL_CLIENTS = ([f"198.51.100.{i}" for i in range(20, 160)]
                  + [f"192.0.2.{i}" for i in range(60, 200)])
UA_OK = [
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
     "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
     "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0 Safari/537.36"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) "
     "AppleWebKit/605.1.15 Version/18.2 Mobile/15E148 Safari/604.1"),
]
UA_ATK = "python-requests/2.32.3"
PAGES = ["/", "/index.html", "/login", "/search?q=laptop",
         "/products/482", "/cart", "/api/v1/items",
         "/static/app.css", "/static/app.js", "/favicon.ico",
         "/about", "/contact", "/api/v1/session"]

MANIFEST = []


def clf(t):
    """Apache combined 시각 — 웹서버는 +0900 으로 남긴다."""
    return t.astimezone(KST).strftime("%d/%b/%Y:%H:%M:%S %z")


def write_utf8(p: pathlib.Path, text: str):
    """운영체제의 줄바꿈 변환 없이 저장하며 기존 파일은 덮어쓰지 않는다."""
    with p.open("xb") as stream:
        stream.write(text.encode("utf-8"))


def write(p: pathlib.Path, lines, note):
    write_utf8(p, "\n".join(lines) + "\n")
    b = p.read_bytes()
    sha = hashlib.sha256(b).hexdigest()
    MANIFEST.append((p.name, len(lines), len(b), sha, note))
    print(f"  {p.name:22s} {len(lines):>7,}행 {len(b):>10,}B  "
          f"{sha[:16]}  {note[:60]}")


# ── 1. 웹 액세스 로그 ───────────────────────────────────────────────────────
def gen_access(out):
    rows = []
    # 실제 웹서버 트래픽은 고르지 않다. 소수의 클라이언트가 대부분의 요청을 만들고
    # 긴 꼬리가 붙는다(멱함수). 이걸 고르게 뿌리면 공격자의 142건이 곧바로 1위가 되어
    # "빈도로는 못 찾는다"는 이 책의 첫 교훈이 성립하지 않는다. 실제로 그렇게 만들었다가
    # 공격자가 1위로 튀어나와 다시 잡았다.
    weights = [1.0 / (i + 1) ** 0.75 for i in range(len(NORMAL_CLIENTS))]
    t = T["recon_start"] - timedelta(hours=14)
    for _ in range(13000):                                   # 정상 배경
        t += timedelta(seconds=random.randint(1, 12))
        code = random.choices([200, 200, 200, 304, 404, 302], [70, 10, 8, 6, 4, 2])[0]
        rows.append(f'{random.choices(NORMAL_CLIENTS, weights)[0]} - - [{clf(t)}] '
                    f'"GET {random.choice(PAGES)} HTTP/1.1" {code} '
                    f'{random.randint(180, 24000) if code == 200 else random.randint(0, 500)} '
                    f'"https://shop.example.com/" "{random.choice(UA_OK)}"')

    st = T["recon_start"] - timedelta(hours=5)               # 사내 스캐너 — 오탐 연습용
    for path in ["/admin", "/phpmyadmin", "/.git/config", "/wp-login.php", "/server-status",
                 "/.env", "/backup.zip", "/config.php.bak", "/test.php", "/api/swagger.json"]:
        st += timedelta(seconds=random.randint(2, 8))
        rows.append(f'{SCANNER} - - [{clf(st)}] "GET {path} HTTP/1.1" 404 162 "-" '
                    f'"Mozilla/5.0 (compatible; VulnScan/4.1; +https://sec.example.com/scanner)"')

    a = T["recon_start"]                                     # ① 디렉터리 탐색 403
    for i in range(118):
        a += timedelta(seconds=random.randint(6, 16))
        d = random.choice(["admin", "uploads", "backup", "console", "api/v1/debug",
                           "wp-admin", "cgi-bin", "manager", "phpinfo", "server-info"])
        rows.append(f'{ATTACKER} - - [{clf(a)}] "GET /{d}/ HTTP/1.1" 403 199 "-" "{UA_ATK}"')

    a = T["sqli_start"]                                      # ② SQLi 프로빙
    payloads = ["1%27%20OR%20%271%27%3D%271", "1%27%20UNION%20SELECT%20NULL--",
                "1%27%20AND%201%3D1--", "1%27%20AND%20SLEEP%285%29--",
                "1%27%20UNION%20SELECT%20NULL%2CNULL--", "1%27%20ORDER%20BY%2010--",
                "1%3B%20WAITFOR%20DELAY%20%2700%3A00%3A05%27--",
                "1%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--",
                "1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"]
    for pl in payloads:
        a += timedelta(seconds=random.randint(30, 110))
        code = 200 if "username" in pl else 500
        rows.append(f'{ATTACKER} - - [{clf(a)}] "GET /search?q={pl} HTTP/1.1" {code} '
                    f'{random.randint(400, 9000)} "-" "{UA_ATK}"')

    rows.append(f'{ATTACKER} - - [{clf(T["upload"])}] '                  # ③ 업로드 성공
                f'"POST /api/v1/upload HTTP/1.1" 200 84 "-" "{UA_ATK}"')

    a = T["shell_start"]                                     # ④ 웹셸 사용
    for i in range(14):
        a += timedelta(seconds=random.randint(30, 220))
        verb = "GET" if i in (0, 5) else "POST"
        rows.append(f'{ATTACKER} - - [{clf(a)}] "{verb} /uploads/th3m3.php HTTP/1.1" 200 '
                    f'{random.randint(120, 31000)} "-" "{UA_ATK}"')

    t2 = T["shell_start"]                                    # 침해 뒤에도 정상 트래픽
    for _ in range(3800):
        t2 += timedelta(seconds=random.randint(1, 11))
        rows.append(f'{random.choices(NORMAL_CLIENTS, weights)[0]} - - [{clf(t2)}] '
                    f'"GET {random.choice(PAGES)} HTTP/1.1" 200 {random.randint(180, 24000)} '
                    f'"https://shop.example.com/" "{random.choice(UA_OK)}"')

    rows.sort(key=lambda r: datetime.strptime(r.split("[")[1].split("]")[0],
                                              "%d/%b/%Y:%H:%M:%S %z"))
    write(out / "access.log", rows,
          "403 탐색 118 → SQLi 500 8·200 1 → 업로드 200 → 웹셸 14. 공격자는 요청량 20위/282 — 상위 19개가 전부 정상 사용자다")


# ── 2. SSH 인증 로그 ────────────────────────────────────────────────────────
def syslog_time(t):
    # %e 지원 여부에 의존하지 않도록 날짜의 공백 채움을 직접 한다.
    return f"{t:%b} {t.day:2d} {t:%H:%M:%S}"


def gen_auth(out):
    rows, host = [], "web-front-01"
    t = T["recon_start"] - timedelta(hours=16)
    for _ in range(1480):
        t += timedelta(seconds=random.randint(20, 300))
        rows.append(f"{syslog_time(t)} {host} sshd[{random.randint(1000, 99999)}]: "
                    f"Accepted publickey for {random.choice(['deploy', 'monitor', 'yuna', 'kenji'])} "
                    f"from {random.choice(INTERNAL)} port {random.randint(40000, 65000)} ssh2: "
                    f"RSA SHA256:{''.join(random.choices('ABCDEFabcdef0123456789+/', k=43))}")

    b = T["brute_start"]
    span = (T["brute_ok"] - T["brute_start"]).total_seconds()
    for i in range(220):
        b = T["brute_start"] + timedelta(seconds=span * i / 220)
        u = random.choice(["root", "admin", "deploy", "svc_backup"])
        rows.append(f"{syslog_time(b)} {host} sshd[{random.randint(1000, 99999)}]: "
                    f"Failed password for {u} from {ATTACKER} "
                    f"port {random.randint(40000, 65000)} ssh2")
    ok = T["brute_ok"]
    rows.append(f"{syslog_time(ok)} {host} sshd[41822]: Accepted password for "
                f"svc_backup from {ATTACKER} port 51204 ssh2")
    rows.append(f"{syslog_time(ok + timedelta(seconds=3))} {host} sshd[41822]: "
                f"pam_unix(sshd:session): session opened for user svc_backup by (uid=0)")
    c = ok
    for cmd in ["/usr/bin/id", "/bin/cat /etc/shadow", "/usr/bin/find / -name id_rsa",
                "/usr/bin/crontab -l"]:
        c += timedelta(seconds=random.randint(20, 120))
        rows.append(f"{syslog_time(c)} {host} sudo: svc_backup : TTY=pts/1 ; "
                    f"PWD=/home/svc_backup ; USER=root ; COMMAND={cmd}")
    write(out / "auth.log", rows,
          "Failed 220 → Accepted svc_backup 1 → sudo 4. syslog 라 타임존 표기가 없다(UTC)")


# ── 3. Windows 이벤트로그 ───────────────────────────────────────────────────
# base64 는 UTF-16LE 로 "Get-Process" 를 인코딩한 것뿐이다. 무해하다.
ENC_B64 = "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="
PS_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
W3WP = r"C:\Windows\System32\inetsrv\w3wp.exe"
CMD = r"C:\Windows\System32\cmd.exe"
WDU = r"C:\Windows\Temp\wdu.exe"
APPPOOL = "NETWORK SERVICE"      # IIS 워커가 도는 계정 — 자식도 이 계정을 물려받는다

# 침해 체인의 pid 는 winlog 와 processes.csv 가 같은 값을 쓴다.
PID_W3WP, PID_CMD, PID_PS, PID_WDU = 1520, 5820, 5896, 6014


def gen_winlog(out):
    rows = []
    hosts = ["FIN-WS-014", "FIN-WS-021", "HR-WS-003", "APP-SRV-02", "DC-01"]
    users = ["j.tanaka", "m.suzuki", "s.park", "a.chen", "svc_sql"]

    def ev(t, eid, host, extra):
        return json.dumps({"TimeCreated": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "EventID": eid,
                           "Computer": host, **extra}, ensure_ascii=False)

    t = T["recon_start"] - timedelta(hours=18)
    for _ in range(3200):
        t += timedelta(seconds=random.randint(3, 40))
        h, u = random.choice(hosts), random.choice(users)
        eid = random.choices([4624, 4634, 4688, 4672], [40, 30, 25, 5])[0]
        if eid == 4688:
            rows.append(ev(t, 4688, h, {
                "SubjectUserName": u, "ProcessId": random.randint(2000, 9000),
                "NewProcessName": random.choice([
                    r"C:\Windows\System32\svchost.exe",
                    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                    r"C:\Windows\System32\taskhostw.exe",
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe"]),
                "ParentProcessName": r"C:\Windows\explorer.exe", "CommandLine": ""}))
        else:
            rows.append(ev(t, eid, h, {"TargetUserName": u,
                                       "LogonType": random.choice([2, 7, 11]),
                                       "IpAddress": random.choice(INTERNAL)}))

    # ① 계정 스프레이 174건
    s0, s1 = T["spray_start"], T["ntlm_ok"]
    span = (s1 - s0).total_seconds()
    for i in range(174):
        a = s0 + timedelta(seconds=span * i / 174)
        rows.append(ev(a, 4625, "APP-SRV-02",
                       {"TargetUserName": random.choice(users + ["administrator", "backup_admin"]),
                        "LogonType": 3, "IpAddress": VICTIM, "Status": "0xC000006A"}))
    # ② NTLM 성공
    rows.append(ev(T["ntlm_ok"], 4624, "APP-SRV-02",
                   {"TargetUserName": "svc_sql", "LogonType": 3, "IpAddress": VICTIM,
                    "AuthenticationPackageName": "NTLM"}))
    # ③ w3wp → cmd → powershell -enc  (processes.csv 와 pid·계정·시각이 일치한다)
    pc = T["proc_chain"]
    rows.append(ev(pc, 4688, "APP-SRV-02",
                   {"SubjectUserName": APPPOOL, "ProcessId": PID_CMD,
                    "ParentProcessId": PID_W3WP, "NewProcessName": CMD,
                    "ParentProcessName": W3WP, "CommandLine": "cmd.exe /c whoami"}))
    rows.append(ev(pc + timedelta(seconds=5), 4688, "APP-SRV-02",
                   {"SubjectUserName": APPPOOL, "ProcessId": PID_PS,
                    "ParentProcessId": PID_CMD, "NewProcessName": PS_PATH,
                    "ParentProcessName": CMD,
                    "CommandLine": f"powershell.exe -nop -w hidden -enc {ENC_B64}"}))
    # ④ 계정 생성 — DC-01 에서 svc_sql 이 한다
    ac = T["acct_create"]
    rows.append(ev(ac, 4720, "DC-01",
                   {"TargetUserName": "svc_helpdesk", "SubjectUserName": "svc_sql"}))
    rows.append(ev(ac + timedelta(seconds=9), 4732, "DC-01",
                   {"TargetUserName": "svc_helpdesk", "GroupName": "Administrators",
                    "SubjectUserName": "svc_sql"}))
    # ⑤ 서비스 설치 — 반드시 프로세스 기동보다 앞선다
    rows.append(ev(T["svc_install"], 7045, "APP-SRV-02",
                   {"ServiceName": "WinDefendUpdate", "ImagePath": WDU,
                    "ServiceType": "user mode service", "StartType": "auto start"}))
    rows.append(ev(T["svc_running"], 4688, "APP-SRV-02",
                   {"SubjectUserName": "SYSTEM", "ProcessId": PID_WDU, "ParentProcessId": 868,
                    "NewProcessName": WDU,
                    "ParentProcessName": r"C:\Windows\System32\services.exe",
                    "CommandLine": "wdu.exe -s"}))
    rows.sort(key=lambda r: json.loads(r)["TimeCreated"])
    write(out / "winlog.jsonl", rows,
          "4625×174 → 4624 NTLM → 4688 w3wp>cmd>ps -enc → 4720/4732 → 7045 → wdu 기동")


# ── 4. Zeek conn / dns ──────────────────────────────────────────────────────
def gen_zeek(out):
    hdr = ["#separator \\x09",
           "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice"
           "\tduration\torig_bytes\tresp_bytes\tconn_state"]
    conn = list(hdr)

    def uid():
        return "C" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=13))

    t = T["recon_start"] - timedelta(hours=14)
    for _ in range(12000):
        t += timedelta(seconds=random.randint(1, 9))
        conn.append("\t".join([f"{t.timestamp():.6f}", uid(), random.choice(INTERNAL),
                               str(random.randint(32768, 61000)), random.choice(NORMAL_CLIENTS),
                               random.choice(["443", "443", "80", "53"]), "tcp",
                               random.choice(["ssl", "http", "dns", "-"]),
                               f"{random.uniform(0.05, 40):.6f}", str(random.randint(120, 90000)),
                               str(random.randint(200, 400000)), "SF"]))
    bt = T["beacon_start"]
    for _ in range(87):                       # 비컨 — 292초±11, 바이트 거의 일정
        bt += timedelta(seconds=292 + random.randint(-11, 11))
        conn.append("\t".join([
            f"{bt.timestamp():.6f}", uid(), VICTIM,
            str(random.randint(49152, 61000)),
            C2, "8443", "tcp", "ssl",
            f"{random.uniform(0.9, 1.4):.6f}",
            str(random.randint(1180, 1240)),
            str(random.randint(330, 355)), "SF"]))
    conn[2:] = sorted(conn[2:], key=lambda r: float(r.split("\t")[0]))
    write(out / "conn.log", conn,
          f"{VICTIM} → {C2}:8443 비컨 87회, 간격 292s±11, orig 1180~1240B 로 거의 일정")

    dns = ["#separator \\x09",
           "#fields\tts\tid.orig_h\tquery\tqtype_name\trcode_name\tanswers"]
    d = T["recon_start"] - timedelta(hours=14)
    normal = ["www.example.com", "api.example.com", "cdn.example.net", "mail.example.org",
              "update.example.com", "ntp.example.org", "shop.example.com"]
    for _ in range(8600):
        d += timedelta(seconds=random.randint(1, 12))
        dns.append("\t".join([f"{d.timestamp():.6f}", random.choice(INTERNAL),
                              random.choice(normal), "A", "NOERROR",
                              f"198.51.100.{random.randint(2, 250)}"]))
    dt, alpha = T["dns_start"], "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(613):                      # DNS 터널링
        dt += timedelta(seconds=random.randint(3, 14))
        label = "".join(random.choices(alpha, k=random.randint(32, 48)))
        dns.append("\t".join([f"{dt.timestamp():.6f}", VICTIM,
                              f"{label}.updates.example.net", "TXT", "NOERROR",
                              "TXT " + "".join(random.choices(alpha, k=random.randint(40, 90)))]))
    dns[2:] = sorted(dns[2:], key=lambda r: float(r.split("\t")[0]))
    write(out / "dns.log", dns,
          f"{VICTIM} 이 updates.example.net 로 TXT 613건, 라벨 32~48자 고엔트로피")


# ── 5. 프로세스 스냅샷 ──────────────────────────────────────────────────────
def gen_processes(out):
    """APP-SRV-02 를 T['snapshot'] 시각에 뜬 스냅샷. 침해 체인은 winlog 와 pid 가 같다."""
    rows = ["pid,ppid,user,name,path,cmdline,start_time"]
    sysproc = [
        (4, 0, "SYSTEM", "System", r"C:\Windows\System32\ntoskrnl.exe"),
        (628, 4, "SYSTEM", "smss.exe", r"C:\Windows\System32\smss.exe"),
        (712, 628, "SYSTEM", "csrss.exe", r"C:\Windows\System32\csrss.exe"),
        (804, 628, "SYSTEM", "wininit.exe", r"C:\Windows\System32\wininit.exe"),
        (868, 804, "SYSTEM", "services.exe", r"C:\Windows\System32\services.exe"),
        (3104, 1, "j.tanaka", "explorer.exe", r"C:\Windows\explorer.exe"),
    ]
    for pid, ppid, u, n, path in sysproc:
        rows.append(f'{pid},{ppid},{u},{n},{path},"{n}",'
                    f'{(T["snapshot"] - timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%SZ")}')

    # 정상 프로세스 다수 — 건초더미를 만든다
    names = ["svchost.exe", "taskhostw.exe", "SearchIndexer.exe", "MsMpEng.exe", "spoolsv.exe",
             "dllhost.exe", "conhost.exe", "RuntimeBroker.exe", "sihost.exe", "ctfmon.exe",
             "chrome.exe", "EXCEL.EXE", "OUTLOOK.EXE", "Teams.exe", "OneDrive.exe",
             "WmiPrvSE.exe", "lsass.exe", "fontdrvhost.exe", "audiodg.exe", "SgrmBroker.exe"]
    pid = 900
    for i in range(1190):
        pid += random.randint(2, 9)
        n = random.choice(names)
        parent = random.choice([868, 3104, 912, 868, 868])
        u = random.choice(["SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "j.tanaka", "svc_sql"])
        base = r"C:\Windows\System32" if n.endswith(".exe") and n[0].islower() \
            else r"C:\Program Files"
        st = T["snapshot"] - timedelta(minutes=random.randint(5, 2400))
        rows.append(f'{pid},{parent},{u},{n},{base}\\{n},"{n}",'
                    f'{st.strftime("%Y-%m-%dT%H:%M:%SZ")}')

    # 침해 체인 — winlog 와 pid·계정·시각이 일치한다
    chain = [
        (PID_W3WP, 868, APPPOOL, "w3wp.exe", W3WP,
         "w3wp.exe -ap DefaultAppPool", T["snapshot"] - timedelta(hours=6)),
        (PID_CMD, PID_W3WP, APPPOOL, "cmd.exe", CMD,
         "cmd.exe /c whoami", T["proc_chain"]),
        (PID_PS, PID_CMD, APPPOOL, "powershell.exe", PS_PATH,
         f"powershell.exe -nop -w hidden -enc {ENC_B64}", T["proc_chain"] + timedelta(seconds=5)),
        (PID_WDU, 868, "SYSTEM", "wdu.exe", WDU, "wdu.exe -s", T["svc_running"]),
    ]
    for p, pp, u, n, path, cl, st in chain:
        rows.append(f'{p},{pp},{u},{n},{path},"{cl}",{st.strftime("%Y-%m-%dT%H:%M:%SZ")}')

    write(out / "processes.csv", rows,
          f"체인 {PID_W3WP}>{PID_CMD}>{PID_PS} (계정 {APPPOOL}) + {PID_WDU} wdu.exe. winlog 와 pid 일치")


# ── 6. 의심 스크립트 (무해) ─────────────────────────────────────────────────
def gen_script(out):
    p = out / "suspicious.ps1"
    write_utf8(p, f"""# ─────────────────────────────────────────────────────────────
# 실습용 무해 샘플. 난독화 '형태'만 흉내낸 것으로 악성 동작은 없다.
# 다운로드·실행·네트워크 호출은 한 줄도 들어 있지 않다.
# 정적으로 읽고 디코드하는 연습에만 쓴다.
# ─────────────────────────────────────────────────────────────
$ErrorActionPreference = 'SilentlyContinue'

# 1) 실행할 명령처럼 보이게 감싼 문자열. 디코드하면 Get-Process 한 줄이다.
${{c`m`d}} = [Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String('{ENC_B64}'))

# 2) URL 처럼 보이는 문자열. 변수에 담기만 하고 호출하지 않는다.
#    문서용 예약 도메인이다. 실제 존재 여부와 무관하게 접속하지 않는다.
$u = 'aHR0cHM6Ly91cGRhdGVzLmV4YW1wbGUubmV0L3AudHh0'
$d = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($u))

# 3) 서비스 이름을 조각내 조립한다. 문자열 검색을 피하는 흔한 수법이다.
$svc = @('Win','Defend','Update') -join ''

# 4) 자주 같이 보이는 형태 — 여기서는 이름만 만들고 실행하지 않는다.
$t = @('New','-Object',' Net.We','bClient') -join ''

Write-Output "decoded-cmd : ${{c`m`d}}"
Write-Output "decoded-url : $d"
Write-Output "service-name: $svc"
Write-Output "assembled   : $t"

# 이 아래에 원래라면 다운로드와 실행이 붙는다. 의도적으로 넣지 않았다.
""")
    b = p.read_bytes()
    n = len(p.read_text(encoding="utf-8").splitlines())
    MANIFEST.append((p.name, n, len(b), hashlib.sha256(b).hexdigest(),
                     "Base64 2개(Get-Process / 예약 도메인 URL)·문자열 조립 2개. 조립한 명령의 실행 없음"))
    print(f"  {p.name:22s} {n:>7,}행 {len(b):>10,}B  {hashlib.sha256(b).hexdigest()[:16]}  "
          f"조립한 명령 실행 없음")


# ── 7. 지저분한 IOC 목록 ────────────────────────────────────────────────────
def gen_iocs(out):
    lines = [
        "슬랙에서 그대로 옮김. 표기 규칙 없음.",
        "",
        "hxxp://203.0.113.77/th3m3[.]php",
        "203[.]0[.]113[.]77",
        "203.0.113.77",
        "  198.51.100.203:8443  ",
        "updates[.]example[.]net",
        "hxxps://updates.example[.]net/p.txt",
        "MD5: D41D8CD98F00B204E9800998ECF8427E",
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA256: 5F2B7A1C9E4D8036A1B2C3D4E5F60718293A4B5C6D7E8F901A2B3C4D5E6F7081",
        "C:\\Windows\\Temp\\wdu.exe",
        "svc_helpdesk  <- 생성된 계정",
        "198.51.100.14   ※ 이건 우리 스캐너입니다",
        "WinDefendUpdate (서비스명)",
        "",
    ]
    write(out / "iocs_messy.txt", lines,
          "203.0.113.77 이 표기만 바꿔 3회. hxxp 2건. 해시 MD5 1·SHA256 2. 자산 1건 섞임")


# ── 8. 신뢰할 수 없는 대상 폴더 (9장) ───────────────────────────────────────
def gen_untrusted(out):
    """조사 대상을 흉내 낸 폴더. 안의 훅은 marker 파일에 한 줄 붙이는 것이 전부다."""
    d = out / "untrusted-sample"
    (d / ".claude").mkdir(parents=True, exist_ok=True)
    hook = ('{\n  "hooks": {\n    "PreToolUse": [\n      {\n        "matcher": "Bash",\n'
            '        "hooks": [\n          {\n            "type": "command",\n'
            '            "command": "echo \\"hook ran at $(date -u +%FT%TZ)\\" '
            '>> \\"$CLAUDE_PROJECT_DIR/../../derived/marker.txt\\""\n'
            '          }\n        ]\n      }\n    ]\n  }\n}\n')
    write_utf8(d / ".claude" / "settings.json", hook)
    write_utf8(d / "README.txt",
        "조사 대상을 흉내 낸 폴더다. 이 안의 .claude/settings.json 에는 훅이 하나 걸려 있다.\n"
        "그 훅은 marker 파일에 실행 시각 한 줄을 붙이는 것이 전부고, 파괴·네트워크 동작은 없다.\n"
        "비대화형 세션이 대상 폴더의 설정을 어떻게 취급하는지 자기 랩에서 확인하기 위한 장치다.\n")
    write_utf8(d / "notes.md", "# 대상 폴더 메모\n\n분석 대상처럼 보이게 둔 평범한 파일이다.\n")
    for f in sorted(d.rglob("*"), key=lambda p: p.relative_to(out).as_posix()):
        if f.is_file():
            b = f.read_bytes()
            MANIFEST.append((f.relative_to(out).as_posix(), len(b.splitlines()), len(b),
                             hashlib.sha256(b).hexdigest(), "9장 — 무해한 PreToolUse 훅 실습용"))
    print(f"  untrusted-sample/      파일 3개 — 무해한 PreToolUse 훅(마커에 한 줄 append)")


def gen_derived(out):
    d = out.parent / "derived"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "marker.txt"
    write_utf8(p, "baseline\n")
    b = p.read_bytes()
    MANIFEST.append(("../derived/marker.txt", 1, len(b), hashlib.sha256(b).hexdigest(),
                     "14장 훅 차단 실습 대상. 증거 원본이 아닌 파생 폴더의 마커"))
    print(f"  derived/marker.txt     1행 — 훅 실습 대상 (증거 원본 아님)")


# ── 매니페스트 ──────────────────────────────────────────────────────────────
def write_manifest(out):
    w = max(len(m[0]) for m in MANIFEST) + 2
    lines = [f"실습 랩 매니페스트 — seed {SEED}",
             "이 표와 자기 출력이 다르면 진도를 나가지 않는다. 데이터가 다르면 정답도 다르다.",
             "",
             f"{'파일':<{w}}{'행수':>9}{'바이트':>12}  sha256(앞16)     심어둔 신호"]
    for name, rows, b, sha, note in MANIFEST:
        lines.append(f"{name:<{w}}{rows:>9,}{b:>12,}  {sha[:16]}  {note}")
    # ⚠️ 증거 폴더 밖에 둔다. evidence/ 안에 두면 조사 세션이 이 파일을 먼저 읽고
    # "여기에 웹셸이 있다" 를 그대로 베낀다 — 실습이 성립하지 않는다. 실제로 그렇게
    # 만들었다가 모델이 매니페스트를 읽고 답을 맞히는 것을 보고 밖으로 뺐다.
    p = out.parent / "lab-manifest.txt"
    write_utf8(p, "\n".join(lines) + "\n")
    print(f"\n  ../lab-manifest.txt    {len(MANIFEST)}개 항목 — 정답 대조 기준표")
    print("     (증거 폴더 밖에 둔다. 안에 두면 조사 세션이 정답을 먼저 읽는다)")
    return p


def main():
    # Windows에서 파이프로 실행해도 한글 안내를 UTF-8로 출력한다.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    if len(sys.argv) > 2:
        raise SystemExit("사용법: python3 gen_lab_data.py 새_증거_폴더")
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "./evidence").expanduser()
    # 생성 도중 실패해도 기존 증거·훅 기록·매니페스트는 보존한다.
    for target in (out, out.parent / "derived" / "marker.txt", out.parent / "lab-manifest.txt"):
        if target.exists() or target.is_symlink():
            raise SystemExit("기존 자료가 있다. 덮어쓰지 않고 새 실습 폴더를 사용한다.")
    derived = out.parent / "derived"
    if derived.is_symlink() or (derived.exists() and not derived.is_dir()):
        raise SystemExit("derived가 일반 폴더가 아니다. 새 실습 폴더를 사용한다.")
    out.mkdir(parents=True, exist_ok=False)
    print(f"합성 실습 데이터 생성 (seed={SEED}) → {out}\n")
    gen_access(out)
    gen_auth(out)
    gen_winlog(out)
    gen_zeek(out)
    gen_processes(out)
    gen_script(out)
    gen_iocs(out)
    gen_untrusted(out)
    gen_derived(out)
    write_manifest(out)
    print("\n주소·도메인은 문서용 예약 값이다. 외부 조회·접속에 사용하지 않는다.")
    print("시각은 UTC 한 줄로 세우고 로그마다 그 로그의 표기로 렌더한다 —")
    print("access.log 는 +0900, winlog/Zeek 는 UTC. 표기가 갈리는 것은 일부러 심은 것이다.")


if __name__ == "__main__":
    main()
