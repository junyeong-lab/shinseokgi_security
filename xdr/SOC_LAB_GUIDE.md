# 신석기백화점 XDR SOC — Wazuh 요청형 관제

검증 기준일: 2026-11-10. 기존 XDR 6개 판정기를 유지하고, Wazuh에서 이미 생성된 경보를 SOC-PC가 SSH로 요청할 때 가져와 분석하는 **수동 요청형(on-demand)** 실습이다. 실시간 지속 수집과 자동 차단은 구현하지 않았다.

## 구성

| 장비 | 실습 IP | 역할 |
| --- | --- | --- |
| SIEM | 10.10.247.10 | Wazuh Manager/Indexer/Dashboard, JSON 추출 |
| LOG | 10.10.247.20 | 중앙 rsyslog, Wazuh Agent |
| SOC-PC-1 | 10.10.247.30 | Windows 10, Node.js, XDR 분석 및 관제 UI |

| 저장소 파일 | 설치 위치 / 용도 |
| --- | --- |
| scripts/xdr-siem/export-rule100777.py | SIEM /usr/local/libexec/shinseokgi-xdr/export-rule100777.py — 단일 테스트 경보 |
| scripts/xdr-siem/export-recent.py | SIEM /usr/local/libexec/shinseokgi-xdr/export-recent.py — 최근 경보 최대 100건 |
| scripts/xdr-wazuh-remote.mjs | SOC-PC 단일 테스트 경보 원격 분석 |
| scripts/xdr-wazuh-analyze.mjs | SOC-PC 다중 경보 XDR 6개 모듈 선택 및 분석 |
| scripts/xdr-soc-dashboard.mjs | SOC-PC 로컬 웹 관제: http://127.0.0.1:5190 |

기존 xdr/brute-force, web-injection, known-cve, persistence, privilege, exfiltration의 decide.mjs 함수를 재사용한다. 교육용 fixtures 및 scripts/xdr-run.mjs는 유지한다.

## SOC-PC 실행

PowerShell에서 저장소 루트로 이동한 뒤 실행한다. Node.js 24 및 OpenSSH 클라이언트가 필요하다.

~~~powershell
node .\scripts\xdr-soc-dashboard.mjs
~~~

SOC-PC 브라우저에서 http://127.0.0.1:5190 접속 후 **Wazuh 경보 가져오기** 버튼을 누른다. PowerShell 콘솔에 SSH 비밀번호를 입력해 수집을 완료한다. 종료할 때 Ctrl+C.

단일 이벤트 검증:

~~~powershell
node .\scripts\xdr-wazuh-remote.mjs
~~~

CLI 다중 경보 분석 검증:

~~~powershell
ssh potato@10.10.247.10 "sudo -n /usr/bin/python3 /usr/local/libexec/shinseokgi-xdr/export-recent.py" | node .\scripts\xdr-wazuh-analyze.mjs
~~~

성공하면 BATCH_XDR_ANALYSIS_OK가 표시된다. SSH 비밀번호를 코드나 GitHub에 저장하지 않는다.

## SIEM 서버 복원

실습용 원격 추출기는 root 소유로 설치하고, 일반 사용자에게 파일 쓰기 권한을 주지 않는다. 아래 명령은 root에서 저장소 파일을 내려받은 디렉터리를 기준으로 실행한다.

~~~bash
install -d -o root -g root -m 0755 /usr/local/libexec/shinseokgi-xdr
install -o root -g root -m 0644 scripts/xdr-siem/export-rule100777.py /usr/local/libexec/shinseokgi-xdr/export-rule100777.py
install -o root -g root -m 0644 scripts/xdr-siem/export-recent.py /usr/local/libexec/shinseokgi-xdr/export-recent.py
python3 /usr/local/libexec/shinseokgi-xdr/export-recent.py | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["schema"],d["count"])'
~~~

기존 실습에서는 potato 계정에 다음 두 명령만 암호 없는 sudo 실행을 허용했다. sudoers 정책 변경 전후 visudo -c/visudo -cf로 구문을 검사해야 한다. SSH 자체의 비밀번호 인증은 유지하며 Wazuh 원본 alerts.json 권한은 변경하지 않는다.

~~~text
potato ALL=(root) NOPASSWD: /usr/bin/python3 /usr/local/libexec/shinseokgi-xdr/export-rule100777.py
potato ALL=(root) NOPASSWD: /usr/bin/python3 /usr/local/libexec/shinseokgi-xdr/export-recent.py
~~~

## 실제 검증 결과

- Wazuh 실제 경보 100건 요청형 추출 및 SOC-PC 원격 수집 성공.
- MITRE ATT&CK 기술 ID 포함 42건, 미포함 58건.
- XDR 판정 모듈 연결 39건, 분석 미대상 61건. 연결은 공격 탐지 확정이 아니다.
- 웹 관제 요약 100/39/61 표시, 경보 목록·상세·판정 근거 표시 성공.
- 장비 SOC-PC-1 필터: 44건, 상세 자동 연동 성공.
- Rule 60118 검색: 2건, 상세 Rule/판정 근거 자동 갱신 성공.
- 검색 60118 + 분석 미대상 필터: 0건, 이전 상세 초기화 성공.
- Rule 100777 단일 Windows 테스트 경보 원격 분석: record / confidence 0. 실제 공격 아님.

증빙사진 총 5장은 [Notion Phase 6](https://app.notion.com/p/3eb39ab9a0a3818c920ede5a18a3238a)에 기록했다.

## 범위 및 보안 제한

- 요청 시 기존 이벤트 최대 100건을 조회한다. 자동 실시간 감시/스트리밍/알림, 이벤트 영속 저장, 실제 침입공격 탐지 성능 검증 및 자동 차단 기능은 포함되지 않는다.
- MITRE ID는 관련 모듈 선택용 힌트이고 단독 공격 증거가 아니다. record는 안전함을 보장하지 않으며 block은 실제 차단 명령이 아닌 판정 결과다.
- JSON에는 필요한 메타데이터와 규칙 설명 일부만 추출한다. 인증정보, 경보 원문 전체, 사용자별 비밀정보는 GitHub에 저장하지 않는다.
- 서버 주소와 potato 계정은 별도 실습용 설정이다. 운영망에 그대로 적용하지 않는다.
