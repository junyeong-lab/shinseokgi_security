"""KISA 2026 UNIX U-18: /etc/shadow 소유자·권한 점검.

가이드 p.44: 소유자 root, 권한 0400 이하.
비밀번호 해시를 포함하는 /etc/shadow 내용은 절대 읽지 않는다.
"""
import platform
from pathlib import Path

from checks.u02_password_policy import _active_lines, _key_values
from checks.u16_passwd_permissions import _permission_result

ID = "U-18"
NAME = "/etc/shadow 파일 소유자 및 권한 설정"


def check_u18_shadow_permissions():
    if platform.system() != "Linux":
        return {"id": ID, "name": NAME, "result": "해당없음",
                "reason": "Linux 전용 점검입니다.", "details": {},
                "recommendation": "Linux 대상에서 점검하십시오."}
    os_id = _key_values(_active_lines(Path("/etc/os-release"))).get("id", "")
    if os_id.strip('"').lower() != "rocky":
        return {"id": ID, "name": NAME, "result": "수동확인",
                "reason": "현재 Rocky Linux에 한정해 구현했습니다.",
                "details": {}, "recommendation": "대상 OS의 파일 권한 정책을 확인하십시오."}
    return _permission_result(Path("/etc/shadow"), 0o400, ID, NAME)
