"""KISA 2026 U-05: root 이외의 UID 0 금지, Rocky Linux 읽기 전용 점검.

범위는 로컬 /etc/passwd. NSS/LDAP 등 외부 계정 저장소는 별도 검증 대상.
"""
import platform
from pathlib import Path

from checks.u02_password_policy import _active_lines, _key_values

ID = "U-05"
NAME = "root 이외의 UID가 '0' 금지"


def _read_passwd():
    try:
        with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as stream:
            return [line.rstrip("\n") for line in stream if line.strip()]
    except OSError:
        return None


def _scan_uid_zero(lines):
    names = []
    malformed = 0
    checked = 0
    for line in lines:
        fields = line.split(":")
        if len(fields) != 7 or not fields[0]:
            malformed += 1
            continue
        checked += 1
        try:
            uid = int(fields[2])
        except ValueError:
            malformed += 1
            continue
        if uid < 0:
            malformed += 1
        elif uid == 0:
            names.append(fields[0])
    return {"checked_accounts": checked, "uid0_accounts": names,
            "malformed_lines": malformed}


def check_u05_unique_root_uid():
    if platform.system() != "Linux":
        return {"id": ID, "name": NAME, "result": "해당없음",
                "reason": "Linux 서버 전용 점검입니다.", "details": {},
                "recommendation": "Linux에서 재점검하십시오."}

    os_id = _key_values(_active_lines(Path("/etc/os-release"))).get("id", "")
    if os_id.strip('"').lower() != "rocky":
        return {"id": ID, "name": NAME, "result": "수동확인",
                "reason": "현재 Rocky Linux에 한정해 개발 중입니다.",
                "details": {}, "recommendation": "대상 OS의 UID 정책을 확인하십시오."}

    lines = _read_passwd()
    if lines is None:
        return {"id": ID, "name": NAME, "result": "수동확인",
                "reason": "/etc/passwd를 읽을 수 없습니다.", "details": {},
                "recommendation": "읽기 권한 및 파일 상태를 점검하십시오."}

    result = _scan_uid_zero(lines)
    aliases = [name for name in result["uid0_accounts"] if name != "root"]
    if aliases:
        status = "취약"
        reason = "로컬 /etc/passwd에서 root 외 UID 0 계정이 확인됐습니다: " + ", ".join(aliases)
    elif result["uid0_accounts"].count("root") != 1:
        status = "수동확인"
        reason = "root(UID 0) 계정 정보가 누락되거나 중복되어 확인이 필요합니다."
    elif result["malformed_lines"]:
        status = "수동확인"
        reason = "/etc/passwd에 해석할 수 없는 계정 레코드가 있어 판정을 보류합니다."
    else:
        status = "양호"
        reason = "로컬 /etc/passwd 기준 UID 0을 사용하는 계정은 root 하나입니다. 외부 NSS/LDAP 계정은 점검 범위 밖입니다."

    return {
        "id": ID, "name": NAME, "result": status,
        "reason": reason, "details": {**result, "scope": "/etc/passwd local accounts"},
        "recommendation": (
            "root 이외 계정에 UID 0을 부여하지 마십시오. UID 변경 또는 계정 제거는 "
            "파일 소유권·서비스 영향을 확인하고 승인과 백업 후 별도 진행하십시오."
        ),
    }
