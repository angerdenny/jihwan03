#!/usr/bin/env python3
"""
🤖 로봇 트래픽 실측 도구 - 최종 통합본 (캡처 + GeoIP 분석)

[이 프로그램이 하는 일 한눈에 보기]
  1) capture : 로봇이 보내는 패킷을 몰래(?) 읽어서 robot_traffic.csv 에 한 줄씩 기록
  2) analyze : 그 기록을 "도착지 IP별"로 묶고, 각 IP가 어느 나라/회사 것인지 조회
  3) 판정    : 국가/회사 정보로 "확인필요" 표시 (악성이라고 확정하지 않음)

[명령어]
  capture : 패킷 캡처 → robot_traffic.csv 저장 → 종료 즉시 자동 분석 → robot_traffic_analyzed.csv
  analyze : 이미 있는 robot_traffic.csv 만 다시 분석
  ifaces  : 네트워크 인터페이스(랜카드) 목록 보기

[실행 예 - Windows는 관리자 권한 터미널에서]
  python traffic.monitor.py                                  ← 인자 없이 실행하면 capture 시작 (로봇 IP 입력 안내)
  python traffic.monitor.py capture --robot-ip 192.168.137.25 --hours 72
  python traffic.monitor.py analyze

[준비]
  pip install scapy rich requests      (+ Windows는 Npcap 설치: https://npcap.com)

※ 판정은 자동 조회 기준의 "확인 필요" 표시입니다. 국가/ASN만으로 악성을 확정하지 않습니다.
"""

import argparse
import csv
import ipaddress
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

# rich: 터미널을 예쁘게 꾸미는 라이브러리 (표, 색깔, 패널 등)
# 없으면 설치하라는 메시지를 보여주고 종료합니다.
try:
    from rich.align import Align
    from rich.console import Console
    from rich.markup import escape
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
except ImportError:
    sys.exit("❌ rich 설치 필요: pip install rich")

console = Console()  # 화면 출력을 담당하는 객체

# ── 파일 이름과 CSV 헤더(열 제목) ──
RAW_DEFAULT = "robot_traffic.csv"            # 캡처 원본 (패킷 한 개당 한 줄)
OUT_DEFAULT = "robot_traffic_analyzed.csv"   # 분석 결과 (도착지 IP 한 개당 한 줄)
RAW_HEADER = ["시간", "출발지_IP", "도착지_IP", "프로토콜", "포트", "데이터크기(bytes)", "도메인"]
OUT_HEADER = ["순번", "도착지_IP", "도메인", "국가코드", "국가", "도시", "위도", "경도",
              "ASN", "패킷수", "데이터(bytes)", "포트", "판정"]

# ── 확인이 필요한 회사 번호(ASN) 목록 ──
# ASN: 인터넷 회사/기관마다 붙은 번호입니다. (예: AS4766 = Korea Telecom)
# China Unicom / China Telecom / Alibaba 등을 넣어 두었습니다.
# 이 목록에 있어도 "악성"으로 확정하지 않고 "확인필요"로만 표시합니다.
CHECK_ASN = {9808, 9809, 23724, 17816, 23650, 24400, 45090, 45102}

# ── 판정 결과 이름 (화면/CSV에 찍히는 글자와 색깔) ──
RISK = "❌ 위험"  # 현재 자동 판정에서는 사용하지 않습니다 (자동으로 위험을 확정하지 않음)
SAFE = "✅ 안전"
CHECK = "⚠️ 확인필요"
UNKNOWN = "❓ 조회불가"
VERDICT_STYLE = {RISK: "bold red", SAFE: "bold green", CHECK: "bold yellow", UNKNOWN: "bold yellow"}


def banner(text):
    """화면 위쪽에 제목 박스를 그립니다. (보여주기용)"""
    console.print(Align.center(Panel(f"[bold cyan]{text}[/bold cyan]", expand=False, style="bold blue")))
    console.print()


def fail(msg):
    """오류 메시지를 빨간 박스로 보여주고 프로그램을 끝냅니다."""
    console.print(Align.center(Panel(f"[bold red]❌ 오류[/bold red]\n{escape(str(msg))}", style="bold red")))
    sys.exit(1)


# ───────────────────────── 캡처 (1단계) ─────────────────────────
# 여기서는 "패킷을 읽어서 CSV에 적는 일"을 합니다.
# 패킷 = 인터넷으로 주고받는 데이터 조각 하나. 그 안에 출발지/도착지 IP 주소가 적혀 있습니다.

def is_admin():
    """관리자 권한인지 확인합니다. 패킷 캡처는 관리자 권한이 있어야 동작합니다."""
    if os.name == "nt":  # Windows
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0  # Linux/Mac: root(0)인지 확인


def cmd_ifaces(_args):
    """사용 가능한 네트워크 인터페이스(랜카드/와이파이 등) 이름을 보여줍니다.
    --iface 옵션에 넣을 이름을 여기서 확인합니다."""
    try:
        from scapy.all import show_interfaces
    except ImportError:
        fail("scapy 설치 필요: pip install scapy")
    show_interfaces()


def ask_robot_ip():
    """--robot-ip 를 안 줬을 때 직접 입력받습니다. 엔터만 치면 이 PC 전체를 기록합니다."""
    while True:
        ans = console.input("[yellow]🤖 로봇 IP를 입력하세요 (엔터 = 이 PC 전체 트래픽 기록): [/yellow]").strip()
        if not ans:
            return None
        try:
            ipaddress.ip_address(ans)  # IP 형식이 맞는지 검사 (틀리면 예외 발생)
            return ans
        except ValueError:
            console.print("[red]  올바른 IP 형식이 아닙니다. 예) 192.168.137.25[/red]")


def fmt_elapsed(sec):
    """초 단위 숫자를 '시:분:초' 글자로 바꿉니다. 예) 3725초 → 01:02:05"""
    h, rem = divmod(int(sec), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def cmd_capture(args):
    """[캡처 전체 흐름]
    ① 필요한 도구(scapy) 확인
    ② 측정 대상(로봇 IP) 정하기
    ③ 패킷이 올 때마다 on_packet() 실행 → CSV에 한 줄 기록
    ④ Ctrl+C 또는 시간 종료 → 파일 닫기 → 자동 분석(analyze) 실행
    """
    try:
        # scapy: 패킷을 가로채서 읽는 라이브러리
        # IP/TCP/UDP/DNS: 패킷 안의 층(IP층, TCP층 등)을 구분해서 읽는 도구
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSRR
    except ImportError:
        fail("scapy 설치 필요: pip install scapy  (Windows는 Npcap도 필요)")

    banner("로봇 트래픽 패킷 캡처 프로그램")

    if not is_admin():
        console.print("[yellow]⚠️  관리자 권한이 아닙니다. 캡처가 실패하면 관리자 권한으로 다시 실행하세요.[/yellow]\n")

    # 로봇 IP 정하기: 옵션으로 줬으면 그대로, 없고 직접 실행 중이면 물어봅니다.
    robot_ip = args.robot_ip
    if not robot_ip and sys.stdin.isatty():
        robot_ip = ask_robot_ip()
        console.print()
    if not robot_ip:
        console.print("[yellow]⚠️  로봇 IP 미지정 → 이 PC의 모든 트래픽을 기록합니다 (로봇 측정이 아닙니다).[/yellow]\n")

    # 설정 요약 표 (사용자가 무엇을 측정하는지 확인하도록 보여줍니다)
    info = Table(show_header=False, show_footer=False, padding=(0, 2))
    info.add_row("[yellow]📁 저장 위치[/yellow]", f"[white]{escape(os.path.abspath(args.output))}[/white]")
    info.add_row("[yellow]🤖 측정 대상[/yellow]", f"[white]{robot_ip or '이 PC 전체'}[/white]")
    info.add_row("[yellow]🔌 인터페이스[/yellow]", f"[white]{escape(args.iface) if args.iface else '기본값'}[/white]")
    info.add_row("[yellow]⏱️  측정 시간[/yellow]", f"[white]{args.hours}시간[/white]" if args.hours
                 else "[white]무제한 (Ctrl+C 로 종료)[/white]")
    info.add_row("[yellow]🛑 중지 방법[/yellow]", "[white]Ctrl+C  (종료하면 자동으로 분석 결과가 표시됩니다)[/white]")
    console.print(Align.center(info))
    console.print()

    # ── 캡처 중에 쓰는 상태 저장소 ──
    dns_map = {}  # IP → 도메인 이름 대응표. DNS 응답에서 모읍니다. (예: 142.250.x.x → google.com)
    stats = Counter()  # 개수 세기용. stats["total"], stats["TCP"] 같은 식으로 씁니다.
    last = {"dst": "-", "flush": time.time()}  # 최근 도착지 표시용 + 파일 저장 타이밍 기록
    started = time.time()

    # CSV 파일을 열고 제목 줄을 씁니다. 캡처 중에는 계속 이 파일에 한 줄씩 추가합니다.
    raw = open(args.output, "w", newline="", encoding="utf-8-sig")
    writer = csv.writer(raw)
    writer.writerow(RAW_HEADER)

    def learn_dns(pkt):
        """[DNS 응답에서 도메인 이름 배우기]
        '어떤 도메인을 찾았더니 이 IP가 나왔다'는 응답 패킷을 보고 dns_map에 기록합니다.
        나중에 IP만 보면 헷갈리니까 도메인 이름을 같이 적어주기 위해서입니다.
        DNS 응답 한 개에 여러 답이 들어 있을 수 있어서 while 문으로 하나씩 꺼냅니다.
        """
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if not getattr(dns, "ancount", 0):  # 답(answer) 개수가 0이면 할 일 없음
            return
        rr, guard = dns.an, 0  # rr: 답 한 줄. guard: 무한 반복 방지용 카운터
        while isinstance(rr, DNSRR) and guard < 50:
            guard += 1
            if rr.type == 1:  # type 1 = A 레코드 = "도메인 → IPv4 주소"
                try:
                    dns_map[str(rr.rdata)] = rr.rrname.decode(errors="ignore").rstrip(".")
                except Exception:
                    pass
            rr = rr.payload  # 다음 답으로 넘어갑니다

    def on_packet(pkt):
        """[패킷 한 개가 들어올 때마다 실행되는 함수]
        scapy의 sniff()가 패킷을 잡을 때마다 이 함수를 불러 줍니다.
        1) 출발지/도착지 IP를 꺼냄
        2) 로봇이 보낸 것만 골라냄
        3) 프로토콜(TCP/UDP)과 도착 포트를 확인
        4) CSV에 한 줄 기록
        """
        if IP not in pkt:  # IP 주소가 없는 패킷(예: 일부 제어 패킷)은 건너뜁니다
            return
        try:
            learn_dns(pkt)  # DNS 응답이면 도메인 대응표를 갱신합니다
            src, dst = pkt[IP].src, pkt[IP].dst  # 출발지 IP, 도착지 IP
            if robot_ip and src != robot_ip:
                return  # 로봇이 보낸 패킷이 아니면 기록하지 않습니다
            # 프로토콜 구분: TCP(웹 등 연결형), UDP(영상·DNS 등 비연결형)
            if pkt.haslayer(TCP):
                proto, port = "TCP", pkt[TCP].dport  # dport = 도착 포트 번호
            elif pkt.haslayer(UDP):
                proto, port = "UDP", pkt[UDP].dport
            else:
                proto, port = "Other", "N/A"
            # CSV에 한 줄 추가: 시간, 출발지, 도착지, 프로토콜, 포트, 크기, 도메인
            writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             src, dst, proto, port, len(pkt), dns_map.get(dst, "")])
            stats["total"] += 1
            stats[proto] += 1
            last["dst"] = f"{dst}:{port}" + (f"  ({dns_map[dst]})" if dst in dns_map else "")
        except Exception:
            return  # 이상한 패킷 하나 때문에 전체가 멈추지 않도록 무시합니다
        # 파일을 3초에 한 번씩 디스크에 저장합니다 (너무 자주 쓰면 느려지므로)
        now = time.time()
        if now - last["flush"] > 3:
            raw.flush()
            last["flush"] = now

    def live_view():
        """화면에 보이는 실시간 현황 표를 만듭니다. 1초마다 새로 그려집니다."""
        t = Table(title="📡 실시간 캡처 현황", show_header=False, padding=(0, 2))
        t.add_row("[cyan]경과 시간[/cyan]", f"[white]{fmt_elapsed(time.time() - started)}[/white]")
        t.add_row("[cyan]기록된 패킷[/cyan]", f"[yellow]{stats['total']:,}[/yellow]개")
        t.add_row("[cyan]TCP / UDP / 기타[/cyan]",
                  f"[green]{stats['TCP']:,}[/green] / [green]{stats['UDP']:,}[/green] / [green]{stats['Other']:,}[/green]")
        t.add_row("[cyan]최근 도착지[/cyan]", f"[white]{escape(last['dst'])}[/white]")
        return Align.center(t)

    # BPF 필터: 캡처 단계에서 미리 거르는 조건입니다. (scapy/libpcap 문법)
    # "ip and host 로봇IP" = 로봇 IP가 들어간 IP 패킷만 받습니다. 덕분에 처리량이 줄어듭니다.
    bpf = f"ip and host {robot_ip}" if robot_ip else "ip"
    timeout = int(args.hours * 3600) if args.hours else None  # 시간 제한(초). None이면 무제한

    console.print("[green]▶ 캡처 시작됨...[/green]\n")
    try:
        # sniff(): 패킷이 올 때마다 on_packet()을 호출합니다. timeout이 지나면 멈춥니다.
        with Live(get_renderable=live_view, console=console, refresh_per_second=1):
            sniff(prn=on_packet, store=False, filter=bpf, iface=args.iface, timeout=timeout)
        console.print("\n[bold blue]설정한 측정 시간이 끝나 캡처를 종료했습니다.[/bold blue]")
    except KeyboardInterrupt:  # Ctrl+C를 누르면 여기로 옵니다
        console.print("\n[bold blue]사용자가 캡처를 중지했습니다.[/bold blue]")
    except Exception as e:
        console.print(Align.center(Panel(
            f"[bold red]❌ 캡처 오류[/bold red]\n\n{escape(str(e))}\n\n"
            "Npcap 설치 여부 / 관리자 권한 / --iface 이름을 확인하세요.", style="bold red")))
    finally:
        # 정상 종료든 오류든 반드시 파일을 저장하고 닫습니다
        raw.flush()
        raw.close()

    # 캡처 종료 후 요약 표
    console.print()
    st = Table(title="📊 캡처 통계", show_header=True, header_style="bold magenta")
    st.add_column("항목", style="cyan")
    st.add_column("개수", style="green", justify="right")
    st.add_row("총 패킷", f"{stats['total']:,}")
    st.add_row("TCP", f"{stats['TCP']:,}")
    st.add_row("UDP", f"{stats['UDP']:,}")
    st.add_row("기타", f"{stats['Other']:,}")
    console.print(Align.center(st))
    console.print(Align.center(Panel(
        f"[bold green]✅ 캡처 완료![/bold green]\n\n"
        f"[cyan]소요 시간:[/cyan] [yellow]{fmt_elapsed(time.time() - started)}[/yellow]\n"
        f"[cyan]파일:[/cyan] [yellow]{escape(args.output)}[/yellow]",
        style="bold green", expand=False)))
    console.print()

    # 패킷이 하나도 없으면 분석할 게 없으니 안내하고 끝냅니다
    if stats["total"] == 0:
        console.print("[yellow]기록된 패킷이 없습니다. --robot-ip 값과 로봇 연결 방식(핫스팟/포트 미러링)을 확인하세요.[/yellow]")
        return
    if args.no_analyze:
        console.print("[bold blue]분석은 나중에: python traffic.monitor.py analyze[/bold blue]")
        return
    console.print("[bold blue]▶ 자동으로 분석을 시작합니다...[/bold blue]\n")
    analyze(args.output, args.result, args.allow_countries)
    if not args.keep_raw:
        os.remove(args.output)  # 분석이 끝나면 원본 CSV는 지웁니다 (--keep-raw를 주면 남김)
        console.print(f"[dim]원본 파일 삭제: {escape(args.output)}[/dim]")


# ───────────────────────── 분석 (2단계) ─────────────────────────
# 여기서는 "기록된 패킷을 IP별로 묶고, 각 IP의 국가/회사를 조회하는 일"을 합니다.

def is_public(ip):
    """이 IP가 인터넷에 있는 '외부 서버'인지 확인합니다.
    - 사설 IP(192.168.x.x, 10.x.x.x)는 우리 집/회사 내부라서 제외합니다.
    - 멀티캐스트(같은 망에 한꺼번에 뿌리는 주소), 루프백(127.x.x.x) 등도 제외합니다.
    Python의 ipaddress 모듈이 이런 대역을 구분해 줍니다.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # is_global: 인터넷에서 공개적으로 쓰는 주소인지 여부
    return a.is_global and not (a.is_multicast or a.is_reserved or a.is_loopback
                                or a.is_link_local or a.is_unspecified)


def parse_asn(as_field):
    """조회 결과의 "as" 글자에서 ASN 번호만 뽑습니다.
    예) "AS16509 Amazon.com, Inc." → 16509 (정수)
    """
    try:
        return int(str(as_field).split()[0].upper().replace("AS", ""))
    except (ValueError, IndexError):
        return None


def geo_lookup(ips, on_progress=None):
    """[IP 위치 조회]
    ip-api.com 이라는 무료 서비스에 IP 목록을 한꺼번에 보내고,
    각 IP의 국가/도시/좌표/회사(ASN) 정보를 받아옵니다.
    - 무료 제한: 요청 1번에 IP 100개, 분당 15번까지
    - 그래서 100개씩 나눠서 보내고, 사이사이 4.5초씩 쉽니다.
    - 응답이 429(요청 너무 많음)이면 기다렸다가 다시 시도합니다.
    결과는 {IP: 정보} 형태의 사전(dict)으로 돌려줍니다.
    """
    try:
        import requests  # 인터넷에 요청을 보내는 도구
    except ImportError:
        fail("requests 설치 필요: pip install requests")

    # 받고 싶은 정보 항목만 골라서 요청합니다 (필요 없는 정보는 안 받음)
    fields = "status,message,country,countryCode,city,lat,lon,as,query"
    result = {}
    total = (len(ips) + 99) // 100  # 100개 단위로 나눈 덩어리 수 (올림 계산)
    for n, i in enumerate(range(0, len(ips), 100), 1):
        chunk = ips[i:i + 100]  # 이번에 보낼 IP 묶음
        if on_progress:
            on_progress(n, total)
        for _ in range(3):  # 실패하면 최대 3번까지 다시 시도
            try:
                r = requests.post(f"http://ip-api.com/batch?fields={fields}&lang=en",
                                  json=chunk, timeout=20)
                if r.status_code == 200:  # 성공
                    for item in r.json():
                        result[item.get("query")] = item  # query = 조회한 IP
                    break
                if r.status_code == 429:  # 요청이 너무 많음 → 알려준 시간만큼 대기
                    time.sleep(int(r.headers.get("X-Ttl", "60")) + 1)
                    continue
                break
            except requests.RequestException:  # 인터넷 끊김 등 → 3초 쉬고 재시도
                time.sleep(3)
        if n < total:
            time.sleep(4.5)  # 분당 15회 제한을 지키기 위한 대기
    return result


def judge(info, allow):
    """[판정 규칙] 조회 결과 하나를 보고 한 줄 판정을 돌려줍니다.
    1) 조회가 안 됐으면         → ❓ 조회불가
    2) 중국(CN)이거나 확인 ASN 이면 → ⚠️ 확인필요   (악성 확정 아님!)
    3) 허용 국가 목록을 줬는데 그 밖이면 → ⚠️ 확인필요
    4) 나머지                    → ✅ 안전
    ※ 이 규칙은 "어디에 있는지"만 보고, "나쁜지"는 판단하지 않습니다.
    """
    if not info or info.get("status") != "success":
        return UNKNOWN
    cc = info.get("countryCode", "")  # 국가 코드 (예: CN, KR, US)
    if cc == "CN" or parse_asn(info.get("as")) in CHECK_ASN:
        return CHECK  # 중국 IP/통신사는 악성의 근거가 아니므로 직접 확인이 필요하다고만 표시
    if allow and cc not in allow:
        return CHECK
    return SAFE


def analyze(input_file, output_file, allow_countries=None):
    """[분석 전체 흐름]
    ① 원본 CSV 읽기 → 도착지 IP별로 개수/바이트/포트/도메인 모으기
    ② 외부 IP만 골라내기 (내부망 제외)
    ③ 외부 IP 위치 조회 (geo_lookup)
    ④ IP마다 판정 (judge)
    ⑤ 표로 보여주고, 결과 CSV로 저장
    ⑥ 최종 요약 박스 표시
    """
    banner("로봇 트래픽 분석 프로그램")

    if not os.path.exists(input_file):
        fail(f"{input_file} 을(를) 찾을 수 없습니다.\n먼저 capture 로 캡처하거나 --input 경로를 확인하세요.")
    # "JP,US" 같은 문자열을 {"JP", "US"} 집합으로 바꿉니다. 없으면 None.
    allow = {c.strip().upper() for c in allow_countries.split(",")} if allow_countries else None
    console.print(f"[green]✓[/green] 파일 로드: [cyan]{escape(input_file)}[/cyan]")

    # ① 도착지 IP별로 정보를 모을 저장소
    # defaultdict: 처음 보는 IP가 나와도 자동으로 빈 칸을 만들어 줍니다.
    dests = defaultdict(lambda: {"count": 0, "bytes": 0, "ports": set(), "domains": Counter()})
    total, first, last = 0, None, None
    with console.status("[cyan]패킷 분석 중...[/cyan]"):  # 빙글빙글 표시
        try:
            with open(input_file, newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):  # CSV 한 줄 = 사전 한 개 (열 제목을 키로 사용)
                    dst = (row.get("도착지_IP") or "").strip()
                    if not dst:
                        continue
                    d = dests[dst]
                    d["count"] += 1                      # 패킷 수 +1
                    try:
                        d["bytes"] += int(row.get("데이터크기(bytes)") or 0)  # 크기 누적
                    except ValueError:
                        pass
                    port = (row.get("포트") or "").strip()
                    if port and port != "N/A":
                        d["ports"].add(port)             # 같은 포트는 한 번만 (set)
                    if row.get("도메인"):
                        d["domains"][row["도메인"]] += 1  # 어떤 도메인이 몇 번 나왔는지
                    total += 1
                    t = row.get("시간")
                    first, last = first or t, t          # 처음/마지막 시간 기록
        except Exception as e:
            fail(f"파일 읽기 오류: {e}")

    # ② 외부 IP와 내부 IP 나누기
    internal = [ip for ip in dests if not is_public(ip)]
    public = [ip for ip in dests if is_public(ip)]

    console.print(f"[green]✓[/green] 측정 구간: [yellow]{first} ~ {last}[/yellow]")
    console.print(f"[green]✓[/green] 총 패킷: [yellow]{total:,}[/yellow]개")
    console.print(f"[green]✓[/green] 고유 도착지: [yellow]{len(dests)}[/yellow]개 "
                  f"(외부 {len(public)} / 내부망·멀티캐스트 {len(internal)} → 판정 제외)\n")

    # ③ 외부 IP만 위치 조회
    geo = {}
    if public:
        with console.status("[cyan]🌍 국가 정보 조회 중...[/cyan]") as status:
            geo = geo_lookup(public, lambda n, tot: status.update(
                f"[cyan]🌍 국가 정보 조회 중... ({n}/{tot})[/cyan]"))

    # ④ IP마다 한 줄씩 결과 만들기 (패킷 많은 순서로 정렬)
    rows = []
    for ip in sorted(public, key=lambda x: dests[x]["count"], reverse=True):
        d, info = dests[ip], geo.get(ip, {})
        ok = info.get("status") == "success"  # 조회 성공 여부
        rows.append({
            "ip": ip,
            "domain": d["domains"].most_common(1)[0][0] if d["domains"] else "",  # 가장 많이 나온 도메인
            "cc": info.get("countryCode", "") if ok else "",
            "country": info.get("country", "") if ok else "조회실패",
            "city": info.get("city", "") if ok else "",
            "lat": info.get("lat", "") if ok else "",
            "lon": info.get("lon", "") if ok else "",
            "asn": info.get("as", "") if ok else "",
            "count": d["count"], "bytes": d["bytes"],
            "ports": ",".join(sorted(d["ports"], key=lambda p: int(p) if p.isdigit() else 0)),
            "verdict": judge(info, allow),  # 판정
        })

    # ⑤ 화면에 결과 표 보여주기
    table = Table(title="조회 결과", show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=3)
    table.add_column("도착지 IP", style="cyan", no_wrap=True)
    table.add_column("국가", style="green")
    table.add_column("도메인", style="white", overflow="ellipsis", max_width=30)
    table.add_column("패킷", justify="right", style="yellow")
    table.add_column("판정")
    for i, r in enumerate(rows, 1):
        table.add_row(str(i), r["ip"], escape(r["country"]), escape(r["domain"]),
                      f"{r['count']:,}", f"[{VERDICT_STYLE[r['verdict']]}]{r['verdict']}[/]")
    console.print(table)
    if internal:
        console.print(f"\n[dim](참고) 내부망/멀티캐스트 {len(internal)}개는 판정에서 제외: "
                      f"{escape(', '.join(internal[:6]))}{' ...' if len(internal) > 6 else ''}[/dim]")
    console.print()

    # ⑤-2 결과를 CSV 파일로 저장 (대시보드에 올리는 용도)
    with console.status("[cyan]결과 저장 중...[/cyan]"):
        try:
            with open(output_file, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(OUT_HEADER)
                for i, r in enumerate(rows, 1):
                    w.writerow([i, r["ip"], r["domain"], r["cc"], r["country"], r["city"], r["lat"],
                                r["lon"], r["asn"], r["count"], r["bytes"], r["ports"], r["verdict"]])
        except Exception as e:
            fail(f"파일 저장 오류: {e}")
    console.print(f"[green]✓[/green] 분석 결과 저장: [cyan]{escape(output_file)}[/cyan]\n")

    # ⑥ 최종 요약 박스 (확정 표현 없이 '확인 필요' 수준까지만 표시)
    unknown = sum(r["verdict"] == UNKNOWN for r in rows)
    check = sum(r["verdict"] == CHECK for r in rows)
    head = (f"[cyan]분석 일시:[/cyan] {datetime.now():%Y년 %m월 %d일 %H:%M:%S}\n"
            f"[cyan]측정 구간:[/cyan] {first} ~ {last}\n"
            f"[cyan]총 패킷:[/cyan] [yellow]{total:,}[/yellow]개\n"
            f"[cyan]외부 도착지:[/cyan] [yellow]{len(public)}[/yellow]개  "
            f"[cyan]내부망 제외:[/cyan] [yellow]{len(internal)}[/yellow]개\n")
    if check or unknown:
        panel = Panel(f"[bold yellow]⚠️ 확인 필요[/bold yellow]\n\n{head}"
                      f"[cyan]국가/ASN 기준 확인 대상:[/cyan] [yellow]{check}개[/yellow]\n"
                      f"[cyan]조회불가:[/cyan] [yellow]{unknown}개[/yellow]\n\n"
                      f"[bold]자동 조회만으로는 악성 여부를 판단할 수 없습니다. 목적지를 직접 확인하세요.[/bold]",
                      style="bold yellow", expand=False)
    else:
        panel = Panel(f"[bold green]✅ 확인 대상 없음[/bold green]\n\n{head}"
                      f"[bold]국가/ASN 기준으로 확인할 도착지가 없습니다. (안전을 보장하지는 않습니다)[/bold]",
                      style="bold green", expand=False)
    console.print(Align.center(panel))
    console.print()
    console.print(f"[cyan]📁 결과 파일:[/cyan] [yellow]{escape(os.path.abspath(output_file))}[/yellow]")
    console.print("[dim]이 CSV 를 대시보드에 올리면 지도와 표에 표시됩니다.[/dim]\n")


# ───────────────────────── 실행 (명령어 읽기) ─────────────────────────
# 명령어 줄(터미널에 친 글)을 읽어서 맞는 함수를 실행합니다.
# 예) "capture --robot-ip 1.2.3.4" → capture 명령, robot_ip 값은 1.2.3.4
def main():
    p = argparse.ArgumentParser(description="로봇 트래픽 실측 도구 (캡처 + 분석)")
    sub = p.add_subparsers(dest="cmd", required=True)  # capture / analyze / ifaces 중 하나

    # capture 명령과 옵션들
    c = sub.add_parser("capture", help="패킷 캡처 후 자동 분석")
    c.add_argument("--robot-ip", help="로봇의 IP (지정하면 로봇이 보낸 패킷만 기록)")
    c.add_argument("--iface", help="캡처할 인터페이스 이름 (ifaces 명령으로 확인)")
    c.add_argument("--hours", type=float, default=None, help="측정 시간(시간). 생략하면 Ctrl+C 까지")
    c.add_argument("--output", default=RAW_DEFAULT, help=f"원본 저장 파일 (기본 {RAW_DEFAULT})")
    c.add_argument("--result", default=OUT_DEFAULT, help=f"분석 결과 파일 (기본 {OUT_DEFAULT})")
    c.add_argument("--allow-countries", help="허용 국가코드 (예: JP,US). 그 외는 '확인필요'")
    c.add_argument("--no-analyze", action="store_true", help="캡처만 하고 분석은 나중에")
    c.add_argument("--keep-raw", action="store_true", help="분석 후에도 원본 CSV 를 남김")
    c.set_defaults(func=cmd_capture)

    # analyze 명령과 옵션들 (이미 있는 CSV만 분석)
    a = sub.add_parser("analyze", help="기존 CSV 만 분석")
    a.add_argument("--input", default=RAW_DEFAULT)
    a.add_argument("--result", default=OUT_DEFAULT)
    a.add_argument("--allow-countries")
    a.set_defaults(func=lambda x: analyze(x.input, x.result, x.allow_countries))

    # ifaces 명령 (인터페이스 목록)
    i = sub.add_parser("ifaces", help="인터페이스 목록")
    i.set_defaults(func=cmd_ifaces)

    # 인자 없이 실행하면 capture를 자동으로 붙여서 실행합니다
    if len(sys.argv) == 1:
        sys.argv.append("capture")
    args = p.parse_args()
    args.func(args)


# 이 파일을 직접 실행했을 때만 main()을 부릅니다. (다른 파일에서 import 할 때는 실행 안 됨)
if __name__ == "__main__":
    main()