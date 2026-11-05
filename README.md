# 신석기백화점 보안 시스템 개발

신석기백화점 GNS3 기반 SI 구축 프로젝트에서 사용할 보안 프로그램의 **개발용 복사본**입니다. 과제 제출용 원본 GitHub 저장소는 유지하고, 이 저장소에서만 추가 개발합니다.

## 폴더

- [endpoint-agent](endpoint-agent/) — 직원 PC에서 실행하는 올폿 에이전트(원본: [olpot-security_agent/on-client](https://github.com/junyeong-lab/olpot-security_agent/tree/main/on-client)). 기존 실행 틀과 의존 파일을 함께 복사했습니다. 가상 PC에서 실제 실행·검증은 별도로 진행합니다.
- [xdr](xdr/) — 올폿 XDR 예제 경보 판정 및 대응 후보 코드(원본: [choi-bujang-secret-vault/xdr](https://github.com/junyeong-lab/choi-bujang-secret-vault/tree/main/xdr)). `scripts/xdr-run.mjs` 실행기도 복사했습니다.
- [kisa-checker](kisa-checker/) — KISA 기술적 취약점 분석·평가 기준 참고, Rocky Linux 읽기 전용 점검기(원본: [vulnerability-checker](https://github.com/junyeong-lab/vulnerability-checker)). 실서버 최신 코드·판정 최종 검증 전입니다.

## 로컬 실행(테스트 전용)

- 에이전트: Node.js 24.19.0 환경에서 `cd endpoint-agent` → `npm start` (테스트용 브라우저 앱, 실환경 연동 별도)
- XDR: Node.js 22 이상에서 저장소 루트의 `node scripts/xdr-run.mjs brute-force` (모의 Wazuh 경보 사용)
- 취약점 점검기: Python 3.9 이상 Rocky Linux 테스트 환경에서 `cd kisa-checker` → `python3 main.py` (읽기 전용)

## 통합 보안 설계(구현 전)

직원 PC·서버 로그 → Wazuh 중앙 수집·탐지 → 올폿 XDR 경보 분석·대응 판단 → 방화벽 등 집행 장치에서 차단. 직원용 에이전트는 독립 실행부터 검증하고 향후 중앙으로 연동할 계획입니다. KISA 점검기는 별도 정기 취약점 평가 도구입니다.

**주의:** 현재 실제 Wazuh 경보 연동이나 방화벽 자동 차단은 구현·검증된 것으로 표시하지 않습니다. 원본 코드와 학습용 경보를 복사한 상태이며, 신석기 환경에서 실행·통합·정확성 검증은 앞으로 진행합니다. 비밀번호·API 키·실제 직원 PC 정보·점검 결과 파일은 공개 GitHub에 올리지 않습니다.
