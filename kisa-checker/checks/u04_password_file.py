"""KISA 2026 U-04: 비밀번호 파일 보호, Rocky Linux 읽기 전용 점검.

비밀번호 해시/원문은 결과, 로그, JSON에 절대 넣지 않는다.
U-04 판단은 shadow 사용 여부에 한정하며, 암호화 강도는 U-13 대상이다.
"""
import platform
from pathlib import Path

from checks.u02_password_policy import _active_lines, _key_values

ID = "U-04"
NAME = "비밀번호 파일 보호"


def _read_passwd_file():
    """주석 문법을 임의 적용하지 않고 계정 파일 원문을 메모리에서만 읽는다."""
    try:
        with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as stream:
            return [line.rstrip(chr(10)) for line in stream if line.strip()]
    except OSError:
        return None


def _classify_password_field(field):
    """보안상 두 번째 필드의 값 자체를 반환하지 않는다."""
    if field == "x":
        return "shadow"
    if not field:
        return "empty"
    if field.startswith(("!", "*")):
        return "locked"
    if field.startswith("$"):
        return "hash_in_passwd"
    return "unknown"


def _summarize_passwd(lines):
    summary = {"accounts": 0, "shadow": 0, "locked": 0,
               "empty": [], "hash_in_passwd": [], "unknown": [],
               "malformed_lines": 0}
    for line in lines:
        fields = line.rstrip("\n").split(":")
        if len(fields) != 7 or not fields[0]:
            summary["malformed_lines"] += 1
            continue
        username = fields[0]
        summary["accounts"] += 1
        group = _classify_password_field(fields[1])
        if group in ("shadow", "locked"):
            summary[group] += 1
        else:
            summary[group].append(username)
    return summary


def check_u04_password_file():
    if platform.system() != "Linux":
        return {"id": ID, "name": NAME, "result": "해당없음",
                "reason": "Linux 전용 점검입니다.", "details": {},
                "recommendation": "Linux 서버에서 실행하십시오."}

    os_id = _key_values(_active_lines(Path("/etc/os-release"))).get("id", "")
    if os_id.strip('"').lower() != "rocky":
        return {"id": ID, "name": NAME, "result": "수동확인",
                "reason": "현재 Rocky Linux에서만 판정 로직을 검증 대상으로 삼습니다.",
                "details": {}, "recommendation": "배포판에 따른 비밀번호 저장 구조를 확인하십시오."}

    passwd_lines = _read_passwd_file()
    if passwd_lines is None:
        return {"id": ID, "name": NAME, "result": "수동확인",
                "reason": "/etc/passwd 파일을 읽을 수 없습니다.",
                "details": {"passwd_readable": False},
                "recommendation": "점검 권한과 파일 상태를 확인하십시오."}

    stats = _summarize_passwd(passwd_lines)
    shadow_path = Path("/etc/shadow")
    shadow_exists = shadow_path.is_file() and not shadow_path.is_symlink()
    details = {"passwd_readable": True, "shadow_file_present": shadow_exists, **stats}
    problems = []
    if stats["empty"]:
        problems.append("비밀번호 필드가 비어 있는 계정 발견")
    if stats["shadow"] and not shadow_exists:
        problems.append("shadow 참조 계정이 있지만 /etc/shadow 파일이 없거나 비정상입니다")

    if problems:
        status = "취약"
        reason = "; ".join(problems)
    elif stats["accounts"] == 0 or stats["malformed_lines"]:
        status = "수동확인"
        reason = "계정 데이터가 비어 있거나 형식이 잘못된 행이 있어 확인이 필요합니다."
    elif stats["hash_in_passwd"] or stats["unknown"]:
        status = "수동확인"
        reason = "일부 계정의 비밀번호 필드가 shadow 참조가 아닙니다. 암호화 여부 및 저장 정책 확인이 필요합니다."
    elif not shadow_exists and stats["shadow"] == 0:
        status = "수동확인"
        reason = "shadow 파일이 없어 잠긴 계정 외의 인증 구조를 추가 확인해야 합니다."
    else:
        status = "양호"
        reason = "읽을 수 있는 /etc/passwd에서 비밀번호 원문 저장 징후 없이 shadow 참조 또는 잠금 표기를 확인했습니다. 암호화 강도는 별도 점검 대상입니다."

    return {
        "id": ID, "name": NAME, "result": status,
        "reason": reason, "details": details,
        "recommendation": (
            "/etc/passwd에 비밀번호 원문을 저장하지 않고 shadow 기반의 "
            "암호화된 비밀번호 관리 정책을 유지하십시오. 변경은 관리자 승인 후 수행하십시오."
        ),
    }
