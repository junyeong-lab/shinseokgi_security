"""KISA 2026 UNIX U-06: 사용자 계정 su 기능 제한 (읽기 전용).

공식 가이드 p.29-30: su 사용자를 특정 그룹으로 제한하는지 점검한다.
이 초기 구현은 /usr/bin/su 파일 모드/ACL과 /etc/pam.d/su,
로컬 /etc/group의 최소한의 메타데이터만 확인한다.
계정명, 그룹 구성원, 비밀번호/해시, 원본 PAM 내용은 수집하지 않는다.
PAM 전체 제어 흐름 및 NSS/SSSD를 확증하지 못하면 '수동확인'한다.
"""
import os
import platform
import re
import stat
from pathlib import Path

from checks.u02_password_policy import _active_lines, _key_values

ID = "U-06"
NAME = "사용자 계정 su 기능 제한"
SU_PATH = Path("/usr/bin/su")
PAM_PATH = Path("/etc/pam.d/su")


def _group_names():
    """로컬 그룹명과 GID만 사용하며 구성원은 버린다."""
    lines = _active_lines(Path("/etc/group"))
    if lines is None:
        return None
    groups = {}
    for line in lines:
        parts = line.split(":")
        if len(parts) != 4 or not parts[2].isdigit() or not parts[0]:
            continue
        groups[int(parts[2])] = parts[0]
    return groups


def _pam_wheel_summary(lines, known_groups):
    if lines is None:
        return {"readable": False, "wheel_module_count": 0,
                "restrictive_rule_found": False, "groups_verified": False,
                "complex_auth_flow": True}

    module_count = 0
    restrictive = False
    verified = False
    complex_flow = False
    for line in lines:
        # PAM의 bracket control과 include/substack은 단순 파서로 유효성을 확정할 수 없다.
        if re.match(r"^auth\s+(?:include|substack|\[)", line):
            complex_flow = True
        match = re.match(
            r"^auth\s+(required|requisite|sufficient|optional)\s+"
            r"(?:\S*/)?pam_wheel\.so(?:\s+(.*))?$",
            line,
        )
        if not match:
            if re.search(r"\bpam_wheel\.so\b", line):
                module_count += 1
                complex_flow = True
            continue
        module_count += 1
        control, raw_opts = match.groups()
        opts = (raw_opts or "").split()
        group_options = [opt[6:] for opt in opts if opt.startswith("group=")]
        group_name = group_options[-1] if group_options else "wheel"
        group_ok = known_groups is not None and group_name in known_groups.values()
        verified = verified or group_ok
        unsafe_options = {"deny", "trust", "root_only"}.intersection(opts)
        if control in ("required", "requisite") and not unsafe_options and group_ok:
            if "use_uid" in opts or group_options:
                restrictive = True
        if control not in ("required", "requisite") or unsafe_options:
            complex_flow = True

    return {
        "readable": True,
        "wheel_module_count": module_count,
        "restrictive_rule_found": restrictive,
        "groups_verified": verified,
        "complex_auth_flow": complex_flow,
    }


def _su_metadata(path, known_groups):
    """stat/ACL 메타데이터만 수집하며 su를 실행하지 않는다."""
    try:
        meta = path.lstat()
    except OSError:
        return {"readable": False, "group_restriction": False}

    if not stat.S_ISREG(meta.st_mode):
        return {
            "readable": True, "regular_file": False,
            "group_restriction": False,
            "world_executable": False,
        }

    mode = stat.S_IMODE(meta.st_mode)
    group_name = (known_groups or {}).get(meta.st_gid)
    try:
        # POSIX ACL이 있으면 단순 모드 비트만으로 접근 제한을 확정할 수 없다.
        extended_acl = "system.posix_acl_access" in os.listxattr(path)
        acl_state = "있음" if extended_acl else "없음"
    except (OSError, AttributeError):
        acl_state = "확인필요"

    group_gate = (
        stat.S_ISREG(meta.st_mode)
        and meta.st_uid == 0
        and bool(meta.st_mode & stat.S_ISUID)
        and bool(mode & stat.S_IXGRP)
        and not bool(mode & stat.S_IXOTH)
        and not bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
        and group_name is not None
        and acl_state == "없음"
    )
    return {
        "readable": True,
        "regular_file": stat.S_ISREG(meta.st_mode),
        "owner_is_root": meta.st_uid == 0,
        "setuid": bool(meta.st_mode & stat.S_ISUID),
        "mode_octal": format(mode, "04o"),
        "group_name": group_name or "미확인",
        "group_executable": bool(mode & stat.S_IXGRP),
        "world_executable": bool(mode & stat.S_IXOTH),
        "acl_status": acl_state,
        "group_restriction": group_gate,
    }


def check_u06_su_restriction():
    if platform.system() != "Linux":
        return {
            "id": ID, "name": NAME, "result": "해당없음",
            "reason": "Linux 전용 점검입니다.", "details": {},
            "recommendation": "Rocky Linux에서 확인하십시오.",
        }

    os_id = _key_values(_active_lines(Path("/etc/os-release"))).get("id", "")
    if os_id.strip('"').lower() != "rocky":
        return {
            "id": ID, "name": NAME, "result": "수동확인",
            "reason": "현재 Rocky Linux에 한정한 초기 점검입니다.",
            "details": {}, "recommendation": "대상 OS의 su 접근통제 설정을 확인하십시오.",
        }

    groups = _group_names()
    su = _su_metadata(SU_PATH, groups)
    pam = _pam_wheel_summary(_active_lines(PAM_PATH), groups)
    details = {"su_binary": su, "pam_su": pam, "local_group_readable": groups is not None}

    if su["group_restriction"]:
        status = "양호"
        reason = (
            "/usr/bin/su는 root 소유 setuid 일반 파일이며, 실행 권한이 "
            "로컬 특정 그룹으로 제한되고 기타 사용자 실행 권한 및 확장 ACL이 없습니다. "
            "PAM과 NSS의 전체 인증 경로는 별도 검증이 필요합니다."
        )
    elif pam["restrictive_rule_found"]:
        status = "수동확인"
        reason = (
            "PAM에서 특정 그룹으로 su를 제한하는 규칙이 탐지됐으나, "
            "PAM include/제어 흐름과 실제 인증 적용을 확인하지 못했습니다."
        )
    elif su.get("world_executable"):
        status = "수동확인"
        reason = (
            "/usr/bin/su의 기타 사용자 실행 권한이 있으며 확인된 PAM 그룹 제한이 없습니다. "
            "취약 가능성이 있으나 다른 접근통제 경로가 존재할 수 있어 수동확인이 필요합니다."
        )
    else:
        status = "수동확인"
        reason = (
            "su 실행 파일, 그룹 또는 PAM 접근통제의 유효성을 충분히 검증하지 못했습니다."
        )

    return {
        "id": ID, "name": NAME, "result": status,
        "reason": reason, "details": details,
        "recommendation": (
            "KISA U-06 기준에 따라 su 사용을 승인된 그룹으로 제한하십시오. "
            "PAM(auth required pam_wheel.so use_uid 등) 또는 su 실행 권한을 "
            "검토하되, 실제 설정 변경은 사용자 승인·백업·로그인 복구 경로 확보 후 진행하십시오."
        ),
    }
