"""KISA U-03 계정 잠금 임계값: Rocky Linux 읽기 전용 1차 점검.

2026 KISA 가이드: 임계값 1~10회. 실제 PAM 연결/로그인 경로를 모두 확인하기
전에는 '양호'를 확정하지 않는다. 어떠한 설정도 변경하지 않는다.
"""
import platform
import re
from pathlib import Path

from checks.u02_password_policy import _active_lines, _key_values

ITEM_NAME = "계정 잠금 임계값 설정"
MAX_FAILURES = 10


def _parse_deny(text):
    """정수 범위를 검사한다. None이면 값을 확인할 수 없다는 의미."""
    try:
        value = int(str(text).strip())
        return value if value >= 0 else None
    except (TypeError, ValueError):
        return None


def _inline_deny(line):
    matches = re.findall(r"(?:^|\s)deny\s*=\s*(\d+)(?=\s|$)", line)
    return _parse_deny(matches[-1]) if matches else None


def _pam_faillock(path):
    lines = _active_lines(path)
    if lines is None:
        return {"readable": False, "module_lines": 0, "authfail": False,
                "inline_deny": [], "details": "파일을 읽지 못했습니다."}

    # PAM에서 주석을 제외한 실제 모듈 참조를 추출한다. '@include' 등 다른
    # 경로의 적용 및 옵션 우선순위는 실서버 검증이 필요하다.
    entries = []
    for line in lines:
        if re.search(r"\bpam_faillock\.so\b", line):
            entries.append(line)

    authfail = [line for line in entries
                if re.search(r"\bauthfail\b", line)]
    thresholds = [_inline_deny(line) for line in authfail]
    return {
        "readable": True,
        "module_lines": len(entries),
        "authfail": bool(authfail),
        "inline_deny": thresholds,
        "details": "활성 pam_faillock 참조 수집(설정 적용 여부는 추가 확인)",
    }


def _get_os_id():
    values = _key_values(_active_lines(Path("/etc/os-release")))
    return values.get("id", "").replace('"', "").strip().lower()


def _get_config():
    path = Path("/etc/security/faillock.conf")
    lines = _active_lines(path)
    values = _key_values(lines)
    return {
        "readable": lines is not None,
        "deny": _parse_deny(values.get("deny")),
        "raw_deny": values.get("deny", "미설정 또는 확인필요"),
    }


def check_u03_account_lockout():
    if platform.system() != "Linux":
        return {
            "id": "U-03", "name": ITEM_NAME, "result": "해당없음",
            "reason": "현재 Rocky Linux 서버 점검만 지원합니다.",
            "details": {}, "recommendation": "Linux 대상에서 재점검하십시오.",
        }

    distro = _get_os_id()
    if distro != "rocky":
        return {
            "id": "U-03", "name": ITEM_NAME, "result": "수동확인",
            "reason": f"Rocky Linux 전용 초기 구현입니다 (ID: {distro or '미확인'}).",
            "details": {}, "recommendation": "OS에 맞는 인증 스택을 확인하십시오.",
        }

    config = _get_config()
    pams = {
        "system-auth": _pam_faillock(Path("/etc/pam.d/system-auth")),
        "password-auth": _pam_faillock(Path("/etc/pam.d/password-auth")),
    }
    details = {"faillock_conf": config, "pam": pams}

    # 취약 판정은 설정이 실제 PAM authfail 경로에서 관찰되고,
    # 임계값이 명확히 0 또는 10 초과일 때에만 한다.
    issues = []
    all_authfail = all(entry["authfail"] for entry in pams.values())
    if all_authfail:
        for path, entry in pams.items():
            for deny in entry["inline_deny"]:
                if deny is not None and not 1 <= deny <= MAX_FAILURES:
                    issues.append(f"{path}: 인라인 deny={deny}")
        # faillock.conf 값은 authfail 인라인 설정에 의해 덮일 수 있으므로
        # 해당 경로에 인라인 값이 없을 때에만 결함 판단에 사용한다.
        if config["deny"] is not None and not 1 <= config["deny"] <= MAX_FAILURES:
            if all(not e["inline_deny"] or all(x is None for x in e["inline_deny"])
                   for e in pams.values()):
                issues.append(f"faillock.conf: deny={config['deny']}")

    if issues:
        result = "취약"
        reason = "잠금 임계값 기준(1~10회)을 벗어난 설정: " + "; ".join(issues)
    else:
        result = "수동확인"
        reason = (
            "읽기 전용으로 faillock.conf와 system-auth/password-auth를 수집했습니다. "
            "실제 모듈 적용 경로, authselect 관리 상태, SSH 인증과 계정별 "
            "예외 및 옵션 우선순위가 검증되지 않아 양호를 확정하지 않습니다."
        )

    return {
        "id": "U-03", "name": ITEM_NAME, "result": result,
        "reason": reason, "details": details,
        "recommendation": (
            "KISA 기준에 따라 로그인 실패 잠금 임계값을 10회 이하로 유지하십시오. "
            "PAM/Authselect 변경은 로그인 장애를 유발할 수 있으므로 "
            "백업과 복구 경로 확보 및 사용자 승인 후 별도로 진행해야 합니다."
        ),
    }
