# 로봇 트래픽 분석 시스템

로봇이 외부 서버와 어떤 통신을 하는지 실측하고, 위험 여부를 판정하는 도구입니다.

Python으로 패킷을 캡처하고 국가 및 소속 회사(ASN)를 분석한 뒤, 결과 CSV 파일을 HTML 대시보드에서 불러와 지도와 표로 확인할 수 있습니다.

## 주요 기능

- 로봇 IP 기준으로 송신 패킷만 캡처
- 도착지 IP의 국가, 도시, 소속 회사(ASN) 조회
- 중국 또는 차단 대상 ASN으로 통신하는지 자동 판정
- 분석 결과를 CSV로 저장 후 HTML 대시보드에서 지도와 표로 확인

## 파일 구성

| 파일 | 설명 |
|---|---|
| `traffic.monitor.py` | 패킷 캡처 및 분석 프로그램 |
| `robot_traffic_analyzed_normal.csv` | 정상 통신 분석 결과 (대시보드 입력용) |
| `robot_traffic_analyzed_danger.csv` | 위험 통신 분석 결과 (대시보드 입력용) |
| `robot_traffic_dashboard_final.html` | 결과를 지도와 표로 보여주는 대시보드 |

## 사용 방

1. 필요한 패키지를 설치합니다.

관리자 권한 터미널에서 아래 명령을 실행합니다.
- `--robot-ip`: 로봇의 IP 주소입니다. 지정하면 로봇이 보낸 패킷만 기록합니다.
- `--hours`: 측정 시간(시간 단위)입니다. 생략하면 Ctrl+C를 누를 때까지 측정합니다.
- `--allow-countries JP,US`: 허용 국가를 지정하면 그 밖의 국가는 "확인필요"로 표시합니다. (선택 사항)
- `--keep-raw`: 분석 후에도 원본 캡처 파일(`robot_traffic.csv`)을 남깁니다. (선택 사항)

- cd "파일 경로" ->python traffic.monitor.py capture --hours 0.05 혹은 python traffic.monitor.py capture --robot-ip 로봇IP --hours 0.05 입력합니다.

3. Windows에서는 [Npcap](https://npcap.com)도 설치해야 합니다.  명령어 pip install scapy rich requests 
4. 관리자 권한 터미널에서 캡처와 분석을 실행합니다.
5. 분석이 끝나면 `robot_traffic_analyzed.csv` 파일이 생성됩니다.
 `robot_traffic_dashboard_final.html`을 브라우저에서 열고 CSV 파일을 불러오면 결과를 지도와 표로 볼 수 있습니다.




## 주의 사항

- 캡처는 로봇 트래픽이 이 PC를 거쳐 가는 환경(핫스팟 또는 포트 미러링)에서만 정확하게 측정됩니다.
- 국가 정보는 IP 위치 데이터베이스 기반의 추정값이므로, "위험" 판정은 도메인과 서비스 목적을 함께 확인하세요.
