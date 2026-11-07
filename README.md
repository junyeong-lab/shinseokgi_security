# 신석기백화점 보안 시스템

GNS3 기반 신석기백화점 SI 실습용 보안 개발 저장소입니다. **직원용 앱과 IT 담당자용 관리 화면을 분리**해 복잡한 수업용 기능을 직원에게 노출하지 않습니다.

| 위치 | 역할 | 현재 상태 |
| --- | --- | --- |
| [employee-agent/](employee-agent/) | 직원의 내 PC 상태만 보여 주는 읽기 전용 앱 | Windows 10 VM 화면 실측 확인, EXE 빌드·VM 테스트 전 |
| 관리자 웹 콘솔 | IT 담당자의 접속 기록, Wazuh 탐지, XDR 분석 | 추후 구축 |
| [xdr/](xdr/) | XDR 모의 경보 판정 코드 | 실제 Wazuh 연동 전 |
| [kisa-checker/](kisa-checker/) | Linux 서버 취약점 점검기 | 실서버 검증 전 |
| [endpoint-agent/](endpoint-agent/) | 기존 ALEPH 직원용 원본 복사본(비교·참고용) | 신규 배포 대상 아님 |

역할과 구현 순서는 [ARCHITECTURE.md](ARCHITECTURE.md)를 참고하세요.

**직원용 개발판 실행:** Windows 10/11 + Node.js 22~24에서 `cd employee-agent` → `npm start` → 브라우저 `http://127.0.0.1:5189`. 확인 전에는 실제 직원 PC 배포 및 EXE 완성이라고 표시하지 않습니다.

**주의:** 원본 과제 저장소들은 변경하지 않았습니다. 이 저장소의 기존 ALEPH 수업용 복사본에는 배포 허가 확인이 필요한 내부 파생 모듈이 있으므로, 해당 폴더는 EXE 패키징/외부 배포에 포함하지 않습니다. 실제 직원 개인정보·비밀키·로그 원문을 공개 GitHub에 올리지 않습니다.
