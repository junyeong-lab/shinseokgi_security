"""KISA U-02 비밀번호 관리정책: Rocky Linux 읽기 전용 1차 점검.

설정을 변경하지 않으며, 적용 범위를 완전히 입증하지 못하면 '양호'로 단정하지 않는다.
"""
import os
import platform
import re
import subprocess
from pathlib import Path

ITEM_NAME = "비밀번호 관리정책 설정"
PWQUALITY_KEYS = ("minlen", "dcredit", "ucredit", "lcredit", "ocredit", "enforce_for_root")
PWHISTORY_KEYS = ("remember", "enforce_for_root")


def _active_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return [line.split("#", 1)[0].strip() for line in stream
                    if line.split("#", 1)[0].strip()]
    except OSError:
        return None


def _key_values(lines):
    values = {}
    for line in lines or []:
        match = re.match(r"^([A-Za-z_][A-Za-z_0-9]*)\s*(?:=\s*|\s+)(.*?)\s*$", line)
        if match:
            values[match.group(1).lower()] = match.group(2).strip()
        elif re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", line):
            values[line.lower()] = "enabled"
    return values


def _read_policy(file_path, keys, fragments_dir=None):
    lines = _active_lines(file_path)
    found_file = lines is not None
    merged = list(lines or [])
    fragment_paths = []
    if fragments_dir and fragments_dir.is_dir():
        fragment_paths = sorted(fragments_dir.glob("*.conf"))
        for extra in fragment_paths:
            fragment = _active_lines(extra)
            if fragment is not None:
                merged.extend(fragment)
    values = _key_values(merged)
    return {
        "readable": found_file,
        "fragment_count": len(fragment_paths),
        "values": {key: values.get(key, "확인필요") for key in keys},
    }


def _pam_modules(path):
    lines = _active_lines(path)
    if lines is None:
        return {"readable": False, "pwquality": "확인필요",
                "pwhistory": "확인필요", "unix": "확인필요"}
    joined = "\n".join(lines)
    return {
        "readable": True,
        "pwquality": "탐지" if re.search(r"\bpam_pwquality\.so\b", joined) else "미탐지",
        "pwhistory": "탐지" if re.search(r"\bpam_pwhistory\.so\b", joined) else "미탐지",
        "unix": "탐지" if re.search(r"\bpam_unix\.so\b", joined) else "미탐지",
    }


def _root_aging():
    try:
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        process = subprocess.run(
            ["chage", "-l", "root"], capture_output=True, text=True,
            timeout=10, env=env, check=False
        )
        if process.returncode != 0:
            return {"min_days": None, "max_days": None, "status": "확인필요"}
        aging = {"min_days": None, "max_days": None, "status": "수집"}
        for line in process.stdout.splitlines():
            name, divider, value = line.partition(":")
            if not divider:
                continue
            key = name.strip().lower()
            raw_value = value.strip()
            if not raw_value.isdigit():
                continue
            if key.startswith("minimum number of days between password change"):
                aging["min_days"] = int(raw_value)
            elif key.startswith("maximum number of days between password change"):
                aging["max_days"] = int(raw_value)
        if aging["min_days"] is None or aging["max_days"] is None:
            aging["status"] = "확인필요"
        return aging
    except (OSError, subprocess.TimeoutExpired):
        return {"min_days": None, "max_days": None, "status": "확인필요"}


def _age_issues(label, min_value, max_value):
    issues = []
    if min_value is not None and min_value < 1:
        issues.append(f"{label} 최소 사용 기간 {min_value}일 (권고: 1일 이상)")
    if max_value is not None and max_value > 90:
        issues.append(f"{label} 최대 사용 기간 {max_value}일 (권고: 90일 이하)")
    return issues


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def check_u02_password_policy():
    """현재 호스트를 조회만 한다. 양호 자동판정은 향후 PAM 실효 정책 검증 후 추가."""
    if platform.system() != "Linux":
        return {"id": "U-02", "name": ITEM_NAME, "result": "해당없음",
                "reason": "현재 Rocky Linux 대상 점검만 지원합니다.", "details": {},
                "recommendation": "Linux 서버에서 점검하십시오."}

    os_info = _key_values(_active_lines(Path("/etc/os-release")))
    os_id = os_info.get("id", "").replace(chr(34), "").lower()
    if os_id != "rocky":
        return {"id": "U-02", "name": ITEM_NAME, "result": "수동확인",
                "reason": f"현재 Rocky Linux 전용 1차 점검입니다 (OS ID: {os_id or '미확인'}).",
                "details": {}, "recommendation": "배포판별 PAM 및 정책 기준을 확인하십시오."}

    login_defs = _key_values(_active_lines(Path("/etc/login.defs")))
    login_min = _as_int(login_defs.get("pass_min_days"))
    login_max = _as_int(login_defs.get("pass_max_days"))
    root_aging = _root_aging()

    security = Path("/etc/security")
    details = {
        "login_defs": {
            "PASS_MIN_DAYS": login_min if login_min is not None else "확인필요",
            "PASS_MAX_DAYS": login_max if login_max is not None else "확인필요",
        },
        "root_aging": root_aging,
        "pwquality": _read_policy(
            security / "pwquality.conf", PWQUALITY_KEYS,
            security / "pwquality.conf.d"
        ),
        "pwhistory": _read_policy(
            security / "pwhistory.conf", PWHISTORY_KEYS,
            security / "pwhistory.conf.d"
        ),
        "pam": {
            "system-auth": _pam_modules(Path("/etc/pam.d/system-auth")),
            "password-auth": _pam_modules(Path("/etc/pam.d/password-auth")),
        },
    }
    issues = _age_issues("/etc/login.defs", login_min, login_max)
    issues.extend(_age_issues("root 계정", root_aging["min_days"], root_aging["max_days"]))

    if issues:
        outcome = "취약"
        reason = "확인된 비밀번호 사용 기간 설정 미흡: " + "; ".join(issues)
    else:
        outcome = "수동확인"
        reason = (
            "비밀번호 사용 기간의 명시적인 기준 미달은 확인되지 않았으나, "
            "PAM 인라인 옵션·정책 파일 포함 관계·계정별 적용 및 재사용 제한의 "
            "실효성을 검증하지 않아 양호로 확정할 수 없습니다."
        )

    return {
        "id": "U-02", "name": ITEM_NAME, "result": outcome,
        "reason": reason, "details": details,
        "recommendation": (
            "서비스 계정 영향도를 검토한 뒤 KISA 기준에 맞는 비밀번호 복잡성, "
            "최소/최대 사용 기간, 최근 4회 재사용 제한과 PAM 적용 여부를 확인하십시오. "
            "이 프로그램은 설정을 자동 변경하지 않습니다."
        ),
    }
