"""KISA 취약점 점검 결과를 최소 정보 JSON으로 기록한다.

사용법:
    python3 report_json.py
    python3 report_json.py --output reports/manual-check.json

원본 설정은 변경하지 않는다. 보고서 파일은 새로 생성하며 덮어쓰지 않는다.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from checks.system_info import get_system_info
from checks.u01_root_remote import check_u01_combined
from checks.u02_password_policy import check_u02_password_policy
from checks.u03_account_lockout import check_u03_account_lockout
from checks.u04_password_file import check_u04_password_file
from checks.u05_unique_root_uid import check_u05_unique_root_uid
from checks.u06_su_restriction import check_u06_su_restriction
from checks.u16_passwd_permissions import check_u16_passwd_permissions
from checks.u18_shadow_permissions import check_u18_shadow_permissions

CHECKS = (
    check_u01_combined,
    check_u02_password_policy,
    check_u03_account_lockout,
    check_u04_password_file,
    check_u05_unique_root_uid,
    check_u06_su_restriction,
    check_u16_passwd_permissions,
    check_u18_shadow_permissions,
)

RESULTS = ("양호", "취약", "수동확인", "해당없음")


def build_report():
    items = [checker() for checker in CHECKS]
    tally = Counter(item.get("result", "수동확인") for item in items)
    return {
        "schema_version": "1.0",
        "standard": "KISA 2026 주요정보통신기반시설 기술적 취약점 상세가이드",
        "scope": "Rocky Linux 1차 읽기 전용 점검 U-01~U-06, U-16, U-18",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system": get_system_info(),
        "summary": {name: tally.get(name, 0) for name in RESULTS},
        "item_count": len(items),
        "items": items,
        "limitations": [
            "초기 개발 단계이며 U-01~U-03은 미검증 접속/인증 경로가 남아 있음",
            "실제 Rocky Linux 서버 검증 완료를 의미하지 않음",
            "계정·인증·네트워크 설정 및 파일을 자동 수정하지 않음",
            "U-04에서 비밀번호 또는 해시 값을 보고서에 기록하지 않음",
            "U-05는 로컬 /etc/passwd만 점검하며 외부 NSS/LDAP은 범위에서 제외",
            "U-06은 su/PAM 그룹 제한의 초기 메타데이터만 점검하며 PAM 실제 인증 흐름은 실서버 검증 필요",
            "U-16/U-18은 파일 소유자·권한 메타데이터만 확인하며 /etc/shadow 내용을 읽지 않음",
        ],
    }


def save_report(report, filename):
    destination = Path(filename)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(destination), flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return destination


def main():
    parser = argparse.ArgumentParser(description="KISA 점검 보고서 JSON 저장(읽기 전용)")
    parser.add_argument("--output", help="신규 보고서 저장 경로. 기존 파일 덮어쓰기 금지")
    options = parser.parse_args()

    report = build_report()
    date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    filename = options.output or f"reports/assessment_{date}.json"

    try:
        saved = save_report(report, filename)
    except (OSError, ValueError) as error:
        parser.exit(1, f"보고서 생성 실패: {error}\n")

    print("보고서 저장:", saved)
    print("점검 항목:", report["item_count"])
    print("결과 요약:", report["summary"])
    print("참고: 로컬 점검 코드이며 실제 서버 검증 및 조치 승인과 별개입니다.")


if __name__ == "__main__":
    main()
