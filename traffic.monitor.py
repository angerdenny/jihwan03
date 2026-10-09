#!/usr/bin/env python3
"""
🤖 로봇 트래픽 실측 도구 - 최종 통합본 (캡처 + GeoIP 분석)

  capture : 패킷 캡처 → robot_traffic.csv 저장 → 종료 즉시 자동 분석 → robot_traffic_analyzed.csv
  analyze : 이미 있는 robot_traffic.csv 만 다시 분석
  ifaces  : 네트워크 인터페이스 목록 보기

실행 예 (Windows, 관리자 권한 터미널)
  python robot_traffic_monitor.py                         ← 그냥 실행하면 capture 시작 (로봇 IP 입력 안내)
  python robot_traffic_monitor.py capture --robot-ip 192.168.137.25 --hours 72
  python robot_traffic_monitor.py analyze

준비
  pip install scapy rich requests      (+ Npcap 설치: https://npcap.com)
"""

import argparse
import csv
import ipaddress
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

try:
    from rich.align import Align
    from rich.console import Console
    from rich.markup import escape
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
except ImportError:
    sys.exit("❌ rich 설치 필요: pip install rich")

console = Console()

RAW_DEFAULT = "robot_traffic.csv"
OUT_DEFAULT = "robot_traffic_analyzed.csv"
RAW_HEADER = ["시간", "출발지_IP", "도착지_IP", "프로토콜", "포트", "데이터크기(bytes)", "도메인"]
OUT_HEADER = ["순번", "도착지_IP", "도메인", "국가코드", "국가", "도시", "위도", "경도",
              "ASN", "패킷수", "데이터(bytes)", "포트", "판정"]

# 차단 ASN (China Unicom / China Telecom / Alibaba) - 필요하면 추가/수정
BLOCK_ASN = {9808, 9809, 23724, 17816, 23650, 24400, 45090, 45102}

RISK = "❌ 위험"
SAFE = "✅ 안전"
CHECK = "⚠️ 확인필요"
UNKNOWN = "❓ 조회불가"
VERDICT_STYLE = {RISK: "bold red", SAFE: "bold green", CHECK: "bold yellow", UNKNOWN: "bold yellow"}


def banner(text):
    console.print(Align.center(Panel(f"[bold cyan]{text}[/bold cyan]", expand=False, style="bold blue")))
    console.print()


def fail(msg):
    console.print(Align.center(Panel(f"[bold red]❌ 오류[/bold red]\n{escape(str(msg))}", style="bold red")))
    sys.exit(1)


# ───────────────────────── 캡처 ─────────────────────────
def is_admin():
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def cmd_ifaces(_args):
    try:
        from scapy.all import show_interfaces
    except ImportError:
        fail("scapy 설치 필요: pip install scapy")
    show_interfaces()


def ask_robot_ip():
    """--robot-ip 를 안 줬을 때 안내 입력 (엔터 = 이 PC 전체)"""
    while True:
        ans = console.input("[yellow]🤖 로봇 IP를 입력하세요 (엔터 = 이 PC 전체 트래픽 기록): [/yellow]").strip()
        if not ans:
            return None
        try:
            ipaddress.ip_address(ans)
            return ans
        except ValueError:
            console.print("[red]  올바른 IP 형식이 아닙니다. 예) 192.168.137.25[/red]")


def fmt_elapsed(sec):
    h, rem = divmod(int(sec), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def cmd_capture(args):
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSRR
    except ImportError:
        fail("scapy 설치 필요: pip install scapy  (Windows는 Npcap도 필요)")

    banner("로봇 트래픽 패킷 캡처 프로그램")

    if not is_admin():
        console.print("[yellow]⚠️  관리자 권한이 아닙니다. 캡처가 실패하면 관리자 권한으로 다시 실행하세요.[/yellow]\n")

    robot_ip = args.robot_ip
    if not robot_ip and sys.stdin.isatty():
        robot_ip = ask_robot_ip()
        console.print()
    if not robot_ip:
        console.print("[yellow]⚠️  로봇 IP 미지정 → 이 PC의 모든 트래픽을 기록합니다 (로봇 측정이 아닙니다).[/yellow]\n")

    info = Table(show_header=False, show_footer=False, padding=(0, 2))
    info.add_row("[yellow]📁 저장 위치[/yellow]", f"[white]{escape(os.path.abspath(args.output))}[/white]")
    info.add_row("[yellow]🤖 측정 대상[/yellow]", f"[white]{robot_ip or '이 PC 전체'}[/white]")
    info.add_row("[yellow]🔌 인터페이스[/yellow]", f"[white]{escape(args.iface) if args.iface else '기본값'}[/white]")
    info.add_row("[yellow]⏱️  측정 시간[/yellow]", f"[white]{args.hours}시간[/white]" if args.hours
                 else "[white]무제한 (Ctrl+C 로 종료)[/white]")
    info.add_row("[yellow]🛑 중지 방법[/yellow]", "[white]Ctrl+C  (종료하면 자동으로 분석 결과가 표시됩니다)[/white]")
    console.print(Align.center(info))
    console.print()

    dns_map = {}  # IP -> 도메인 (DNS 응답에서 수집)
    stats = Counter()
    last = {"dst": "-", "flush": time.time()}
    started = time.time()

    raw = open(args.output, "w", newline="", encoding="utf-8-sig")
    writer = csv.writer(raw)
    writer.writerow(RAW_HEADER)

    def learn_dns(pkt):
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if not getattr(dns, "ancount", 0):
            return
        rr, guard = dns.an, 0
        while isinstance(rr, DNSRR) and guard < 50:
            guard += 1
            if rr.type == 1:  # A 레코드
                try:
                    dns_map[str(rr.rdata)] = rr.rrname.decode(errors="ignore").rstrip(".")
                except Exception:
                    pass
            rr = rr.payload

    def on_packet(pkt):
        if IP not in pkt:
            return
        try:
            learn_dns(pkt)
            src, dst = pkt[IP].src, pkt[IP].dst
            if robot_ip and src != robot_ip:
                return  # 로봇이 보낸 패킷만 기록
            if pkt.haslayer(TCP):
                proto, port = "TCP", pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto, port = "UDP", pkt[UDP].dport
            else:
                proto, port = "Other", "N/A"
            writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             src, dst, proto, port, len(pkt), dns_map.get(dst, "")])
            stats["total"] += 1
            stats[proto] += 1
            last["dst"] = f"{dst}:{port}" + (f"  ({dns_map[dst]})" if dst in dns_map else "")
        except Exception:
            return
        now = time.time()
        if now - last["flush"] > 3:
            raw.flush()
            last["flush"] = now

    def live_view():
        t = Table(title="📡 실시간 캡처 현황", show_header=False, padding=(0, 2))
        t.add_row("[cyan]경과 시간[/cyan]", f"[white]{fmt_elapsed(time.time() - started)}[/white]")
        t.add_row("[cyan]기록된 패킷[/cyan]", f"[yellow]{stats['total']:,}[/yellow]개")
        t.add_row("[cyan]TCP / UDP / 기타[/cyan]",
                  f"[green]{stats['TCP']:,}[/green] / [green]{stats['UDP']:,}[/green] / [green]{stats['Other']:,}[/green]")
        t.add_row("[cyan]최근 도착지[/cyan]", f"[white]{escape(last['dst'])}[/white]")
        return Align.center(t)

    bpf = f"ip and host {robot_ip}" if robot_ip else "ip"
    timeout = int(args.hours * 3600) if args.hours else None

    console.print("[green]▶ 캡처 시작됨...[/green]\n")
    try:
        with Live(get_renderable=live_view, console=console, refresh_per_second=1):
            sniff(prn=on_packet, store=False, filter=bpf, iface=args.iface, timeout=timeout)
        console.print("\n[bold blue]설정한 측정 시간이 끝나 캡처를 종료했습니다.[/bold blue]")
    except KeyboardInterrupt:
        console.print("\n[bold blue]사용자가 캡처를 중지했습니다.[/bold blue]")
    except Exception as e:
        console.print(Align.center(Panel(
            f"[bold red]❌ 캡처 오류[/bold red]\n\n{escape(str(e))}\n\n"
            "Npcap 설치 여부 / 관리자 권한 / --iface 이름을 확인하세요.", style="bold red")))
    finally:
        raw.flush()
        raw.close()

    # 캡처 종료 요약
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

    if stats["total"] == 0:
        console.print("[yellow]기록된 패킷이 없습니다. --robot-ip 값과 로봇 연결 방식(핫스팟/포트 미러링)을 확인하세요.[/yellow]")
        return
    if args.no_analyze:
        console.print("[bold blue]분석은 나중에: python robot_traffic_monitor.py analyze[/bold blue]")
        return
    console.print("[bold blue]▶ 자동으로 분석을 시작합니다...[/bold blue]\n")
    analyze(args.output, args.result, args.allow_countries)
    if not args.keep_raw:
        os.remove(args.output)  # 분석 끝나면 원본 CSV 삭제
        console.print(f"[dim]원본 파일 삭제: {escape(args.output)}[/dim]")


# ───────────────────────── 분석 ─────────────────────────
def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # 멀티캐스트(224.0.0.0/4, 239.x 등)·브로드캐스트·예약 대역은 외부 서버가 아니므로 제외
    return a.is_global and not (a.is_multicast or a.is_reserved or a.is_loopback
                                or a.is_link_local or a.is_unspecified)


def parse_asn(as_field):
    # ip-api 의 "as" 필드 예: "AS16509 Amazon.com, Inc."
    try:
        return int(str(as_field).split()[0].upper().replace("AS", ""))
    except (ValueError, IndexError):
        return None


def geo_lookup(ips, on_progress=None):
    """ip-api.com 배치 조회 (무료: 요청당 100개, 분당 15요청)"""
    try:
        import requests
    except ImportError:
        fail("requests 설치 필요: pip install requests")

    fields = "status,message,country,countryCode,city,lat,lon,as,query"
    result = {}
    total = (len(ips) + 99) // 100
    for n, i in enumerate(range(0, len(ips), 100), 1):
        chunk = ips[i:i + 100]
        if on_progress:
            on_progress(n, total)
        for _ in range(3):
            try:
                r = requests.post(f"http://ip-api.com/batch?fields={fields}&lang=en",
                                  json=chunk, timeout=20)
                if r.status_code == 200:
                    for item in r.json():
                        result[item.get("query")] = item
                    break
                if r.status_code == 429:
                    time.sleep(int(r.headers.get("X-Ttl", "60")) + 1)
                    continue
                break
            except requests.RequestException:
                time.sleep(3)
        if n < total:
            time.sleep(4.5)  # 분당 15요청 제한
    return result


def judge(info, allow):
    if not info or info.get("status") != "success":
        return UNKNOWN
    cc = info.get("countryCode", "")
    if cc == "CN" or parse_asn(info.get("as")) in BLOCK_ASN:
        return RISK
    if allow and cc not in allow:
        return CHECK
    return SAFE


def analyze(input_file, output_file, allow_countries=None):
    banner("로봇 트래픽 분석 프로그램")

    if not os.path.exists(input_file):
        fail(f"{input_file} 을(를) 찾을 수 없습니다.\n먼저 capture 로 캡처하거나 --input 경로를 확인하세요.")
    allow = {c.strip().upper() for c in allow_countries.split(",")} if allow_countries else None
    console.print(f"[green]✓[/green] 파일 로드: [cyan]{escape(input_file)}[/cyan]")

    dests = defaultdict(lambda: {"count": 0, "bytes": 0, "ports": set(), "domains": Counter()})
    total, first, last = 0, None, None
    with console.status("[cyan]패킷 분석 중...[/cyan]"):
        try:
            with open(input_file, newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    dst = (row.get("도착지_IP") or "").strip()
                    if not dst:
                        continue
                    d = dests[dst]
                    d["count"] += 1
                    try:
                        d["bytes"] += int(row.get("데이터크기(bytes)") or 0)
                    except ValueError:
                        pass
                    port = (row.get("포트") or "").strip()
                    if port and port != "N/A":
                        d["ports"].add(port)
                    if row.get("도메인"):
                        d["domains"][row["도메인"]] += 1
                    total += 1
                    t = row.get("시간")
                    first, last = first or t, t
        except Exception as e:
            fail(f"파일 읽기 오류: {e}")

    internal = [ip for ip in dests if not is_public(ip)]
    public = [ip for ip in dests if is_public(ip)]

    console.print(f"[green]✓[/green] 측정 구간: [yellow]{first} ~ {last}[/yellow]")
    console.print(f"[green]✓[/green] 총 패킷: [yellow]{total:,}[/yellow]개")
    console.print(f"[green]✓[/green] 고유 도착지: [yellow]{len(dests)}[/yellow]개 "
                  f"(외부 {len(public)} / 내부망·멀티캐스트 {len(internal)} → 판정 제외)\n")

    geo = {}
    if public:
        with console.status("[cyan]🌍 국가 정보 조회 중...[/cyan]") as status:
            geo = geo_lookup(public, lambda n, tot: status.update(
                f"[cyan]🌍 국가 정보 조회 중... ({n}/{tot})[/cyan]"))

    rows = []
    for ip in sorted(public, key=lambda x: dests[x]["count"], reverse=True):
        d, info = dests[ip], geo.get(ip, {})
        ok = info.get("status") == "success"
        rows.append({
            "ip": ip,
            "domain": d["domains"].most_common(1)[0][0] if d["domains"] else "",
            "cc": info.get("countryCode", "") if ok else "",
            "country": info.get("country", "") if ok else "조회실패",
            "city": info.get("city", "") if ok else "",
            "lat": info.get("lat", "") if ok else "",
            "lon": info.get("lon", "") if ok else "",
            "asn": info.get("as", "") if ok else "",
            "count": d["count"], "bytes": d["bytes"],
            "ports": ",".join(sorted(d["ports"], key=lambda p: int(p) if p.isdigit() else 0)),
            "verdict": judge(info, allow),
        })

    # 조회 결과 표
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

    # CSV 저장
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

    # 최종 판정
    risk = sum(r["verdict"] == RISK for r in rows)
    unknown = sum(r["verdict"] == UNKNOWN for r in rows)
    check = sum(r["verdict"] == CHECK for r in rows)
    head = (f"[cyan]분석 일시:[/cyan] {datetime.now():%Y년 %m월 %d일 %H:%M:%S}\n"
            f"[cyan]측정 구간:[/cyan] {first} ~ {last}\n"
            f"[cyan]총 패킷:[/cyan] [yellow]{total:,}[/yellow]개\n"
            f"[cyan]외부 도착지:[/cyan] [yellow]{len(public)}[/yellow]개  "
            f"[cyan]내부망 제외:[/cyan] [yellow]{len(internal)}[/yellow]개\n")
    if risk:
        panel = Panel(f"[bold red]❌ 위험 판정[/bold red]\n\n{head}"
                      f"[cyan]중국/차단 ASN 경유:[/cyan] [red]{risk}개[/red]\n\n"
                      f"[bold]중국 또는 차단 ASN 서버 {risk}개로 통신합니다[/bold]",
                      style="bold red", expand=False)
    elif unknown or check:
        panel = Panel(f"[bold yellow]⚠️ 보류 (수동 확인 필요)[/bold yellow]\n\n{head}"
                      f"[cyan]중국/차단 ASN 경유:[/cyan] [green]0개[/green]\n"
                      f"[cyan]조회불가:[/cyan] [yellow]{unknown}개[/yellow]  "
                      f"[cyan]확인필요:[/cyan] [yellow]{check}개[/yellow]\n\n"
                      f"[bold]위험은 발견되지 않았지만 확인되지 않은 도착지가 있습니다[/bold]",
                      style="bold yellow", expand=False)
    else:
        panel = Panel(f"[bold green]✅ 안전 판정[/bold green]\n\n{head}"
                      f"[cyan]중국/차단 ASN 경유:[/cyan] [green]0개[/green]\n\n"
                      f"[bold]로봇이 중국 서버로 통신하지 않습니다[/bold]",
                      style="bold green", expand=False)
    console.print(Align.center(panel))
    console.print()
    console.print(f"[cyan]📁 결과 파일:[/cyan] [yellow]{escape(os.path.abspath(output_file))}[/yellow]")
    console.print("[dim]이 CSV 를 대시보드에 올리면 지도와 표에 표시됩니다.[/dim]\n")


# ───────────────────────── 실행 ─────────────────────────
def main():
    p = argparse.ArgumentParser(description="로봇 트래픽 실측 도구 (캡처 + 분석)")
    sub = p.add_subparsers(dest="cmd", required=True)

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

    a = sub.add_parser("analyze", help="기존 CSV 만 분석")
    a.add_argument("--input", default=RAW_DEFAULT)
    a.add_argument("--result", default=OUT_DEFAULT)
    a.add_argument("--allow-countries")
    a.set_defaults(func=lambda x: analyze(x.input, x.result, x.allow_countries))

    i = sub.add_parser("ifaces", help="인터페이스 목록")
    i.set_defaults(func=cmd_ifaces)

    if len(sys.argv) == 1:  # 인자 없이 실행하면 capture
        sys.argv.append("capture")
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
