"""KISA 2026 UNIX U-16: /etc/passwd 소유자·권한 점검.

가이드 p.41: 소유자 root, 권한 0644 이하. 실제 파일 내용은 열지 않는다.
권한 비교는 정수 크기 비교가 아닌 허용 비트 마스크를 사용한다.
"""
import platform
import stat
from pathlib import Path

from checks.u02_password_policy import _active_lines, _key_values

ID = "U-16"
NAME = "/etc/passwd 파일 소유자 및 권한 설정"


def _permission_result(path, allowed_bits, item_id, item_name):
    try:
        meta = path.lstat()  # symlink를 따라가지 않고 실제 경로 상태 확인
    except OSError:
        return {
            "id": item_id, "name": item_name, "result": "수동확인",
            "reason": "{} 파일 상태를 읽을 수 없습니다.".format(path),
            "details": {"path": str(path), "readable": False},
            "recommendation": "파일의 존재 여부와 소유자·권한을 별도 확인하십시오.",
        }

    mode = stat.S_IMODE(meta.st_mode)
    details = {
        "path": str(path), "regular_file": stat.S_ISREG(meta.st_mode),
        "owner_is_root": meta.st_uid == 0,
        "mode_octal": format(mode, "04o"),
        "allowed_mask": format(allowed_bits, "04o"),
    }
    if not details["regular_file"]:
        status = "수동확인"
        reason = "대상 경로가 일반 파일이 아니므로 심볼릭 링크 등 실제 파일 상태 확인이 필요합니다."
    elif meta.st_uid != 0:
        status = "취약"
        reason = "파일 소유자가 root(UID 0)가 아닙니다."
    elif mode & ~allowed_bits:
        status = "취약"
        reason = "파일 권한이 허용 비트 범위 {}을 벗어납니다.".format(
            format(allowed_bits, "04o")
        )
    else:
        status = "양호"
        reason = "파일 소유자는 root이고, 권한은 허용 비트 범위 {} 이내입니다.".format(
            format(allowed_bits, "04o")
        )

    return {
        "id": item_id, "name": item_name, "result": status,
        "reason": reason, "details": details,
        "recommendation": (
            "KISA {} 기준의 소유자 root·권한 {} 이하를 유지하십시오. "
            "설정 변경은 영향 검토와 사용자 승인 후 수행하십시오."
        ).format(item_id, format(allowed_bits, "04o")),
    }


def check_u16_passwd_permissions():
    if platform.system() != "Linux":
        return {"id": ID, "name": NAME, "result": "해당없음",
                "reason": "Linux 전용 점검입니다.", "details": {},
                "recommendation": "Linux 대상에서 점검하십시오."}
    os_id = _key_values(_active_lines(Path("/etc/os-release"))).get("id", "")
    if os_id.strip('"').lower() != "rocky":
        return {"id": ID, "name": NAME, "result": "수동확인",
                "reason": "현재 Rocky Linux에 한정해 구현했습니다.",
                "details": {}, "recommendation": "대상 OS의 파일 권한 정책을 확인하십시오."}
    return _permission_result(Path("/etc/passwd"), 0o644, ID, NAME)
