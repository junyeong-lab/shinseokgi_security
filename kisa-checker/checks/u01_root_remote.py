import platform
import subprocess


def check_u01():
    if platform.system() != "Linux":
        return {
            "id": "U-01",
            "name": "root 계정 원격 접속 제한",
            "result": "해당없음",
            "reason": "현재 Linux 점검 기능만 구현되어 있습니다."
        }

    ssh_status = check_ssh_service()

    if ssh_status == "중지":
        return {
            "id": "U-01",
            "name": "root 계정 원격 접속 제한",
            "result": "수동확인",
            "reason": "SSH 서비스가 중지되어 있습니다. Telnet 등 다른 원격 접속 서비스 확인이 필요합니다."
        }

    if ssh_status == "확인필요":
        return {
            "id": "U-01",
            "name": "root 계정 원격 접속 제한",
            "result": "수동확인",
            "reason": "SSH 서비스 실행 상태를 확인하지 못했습니다."
        }

    try:
        result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                "id": "U-01",
                "name": "root 계정 원격 접속 제한",
                "result": "수동확인",
                "reason": "SSH 유효 설정을 확인하지 못했습니다."
            }

        for line in result.stdout.splitlines():
            if line.lower().startswith("permitrootlogin "):
                setting = line.split(maxsplit=1)[1].strip().lower()

                if setting == "no":
                    status = "양호"
                    ssh_detail = "root 직접 SSH 로그인 차단"
                    reason = (
                        "PermitRootLogin=no. "
                        "SSH 기본 유효 설정에서 root 직접 로그인이 차단되어 있습니다. "
                        "Match 조건 및 다른 원격 접속 경로 확인이 필요합니다."
                    )

                elif setting == "yes":
                    status = "수동확인"
                    ssh_detail = "root 직접 SSH 로그인 허용 설정 — 취약 후보"
                    reason = (
                        "PermitRootLogin=yes. "
                        "root 직접 SSH 로그인을 허용하는 설정입니다. "
                        "Match 조건과 실제 적용 범위를 확인해야 합니다."
                    )

                elif setting in ("without-password", "prohibit-password"):
                    status = "수동확인"
                    ssh_detail = "root 공개키 SSH 로그인 허용 가능 — 취약 후보"
                    reason = (
                        f"PermitRootLogin={setting}. "
                        "root 비밀번호 인증은 제한되지만 공개키 인증이 가능할 수 있습니다. "
                        "Match 조건과 실제 적용 범위를 확인해야 합니다."
                    )

                elif setting == "forced-commands-only":
                    status = "수동확인"
                    ssh_detail = "root 제한 명령 실행 허용 가능 — 추가 확인"
                    reason = (
                        "PermitRootLogin=forced-commands-only. "
                        "특정 공개키에 지정된 명령 실행이 허용될 수 있습니다. "
                        "접속 목적과 적용 조건을 확인해야 합니다."
                    )

                else:
                    status = "수동확인"
                    ssh_detail = "알 수 없는 SSH 설정값 — 확인 필요"
                    reason = f"PermitRootLogin={setting}. 설정값 확인이 필요합니다."

                return {
                    "id": "U-01",
                    "name": "root 계정 원격 접속 제한",
                    "result": status,
                    "ssh_setting": setting,
                    "ssh_detail": ssh_detail,
                    "reason": reason
                }

        return {
            "id": "U-01",
            "name": "root 계정 원격 접속 제한",
            "result": "수동확인",
            "reason": "PermitRootLogin 유효 설정을 찾지 못했습니다."
        }

    except (OSError, subprocess.TimeoutExpired):
        return {
            "id": "U-01",
            "name": "root 계정 원격 접속 제한",
            "result": "수동확인",
            "reason": "SSH 설정 확인 명령을 실행하지 못했습니다."
        }

def check_ssh_service():
    if platform.system() != "Linux":
        return "해당없음"

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "sshd"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.stdout.strip() == "active":
            return "실행중"

        if result.stdout.strip() == "inactive":
            return "중지"

        return "확인필요"

    except (OSError, subprocess.TimeoutExpired):
        return "확인필요"

def check_telnet_service():
    if platform.system() != "Linux":
        return "해당없음"

    try:
        result = subprocess.run(
            ["ss", "-ltn"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return "확인필요"

        for line in result.stdout.splitlines()[1:]:
            columns = line.split()

            if len(columns) < 4:
                continue

            local_address = columns[3]

            if local_address.rsplit(":", 1)[-1] == "23":
                return "실행중"

        return "미탐지"

    except (OSError, subprocess.TimeoutExpired):
        return "확인필요"

def check_telnet_root_restriction():
    if platform.system() != "Linux":
        return "해당없음"

    try:
        with open("/etc/pam.d/login", "r", encoding="utf-8") as file:
            lines = file.readlines()

        for line in lines:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "pam_securetty.so" in line:
                return "설정확인"

        return "확인필요"

    except OSError:
        return "확인필요"

def check_securetty():
    if platform.system() != "Linux":
        return "해당없음"

    try:
        with open("/etc/securetty", "r", encoding="utf-8") as file:
            lines = file.readlines()

        terminals = []

        for line in lines:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            terminals.append(line)

        remote_terminals = [
            terminal for terminal in terminals
            if terminal.startswith("pts/")
        ]

        if remote_terminals:
            return {
                "status": "확인필요",
                "reason": f"root 허용 터미널 목록에 pts 항목이 있습니다: {remote_terminals}"
            }

        return {
            "status": "설정확인",
            "reason": "/etc/securetty에 pts/ 항목이 없습니다."
        }

    except OSError:
        return {
            "status": "확인필요",
            "reason": "/etc/securetty 파일을 읽을 수 없습니다."
        }

def collect_u01_details():
    ssh_service = check_ssh_service()
    telnet_service = check_telnet_service()
    telnet_pam = check_telnet_root_restriction()
    securetty = check_securetty()

    if telnet_service == "실행중":
        telnet_detail = "TCP 23번 포트 접속 대기 탐지 — Telnet 여부 및 root 로그인 제한 확인 필요"
    elif telnet_service == "미탐지":
        telnet_detail = "TCP 23번 포트 접속 대기 미탐지 — 다른 포트 및 실행 방식 확인 필요"
    else:
        telnet_detail = "Telnet 서비스 상태 확인 필요"

    return {
        "ssh_service": ssh_service,
        "telnet_service": telnet_service,
        "telnet_detail": telnet_detail,
        "telnet_pam": telnet_pam,
        "securetty": securetty
    }

def evaluate_u01(ssh_result, details, ssh_reason=""):
    ssh_status = details["ssh_service"]
    telnet_status = details["telnet_service"]

    if ssh_status == "실행중" and ssh_result == "취약":
        return {
            "result": "취약",
            "reason": ssh_reason or "SSH root 직접 로그인 허용이 확인되었습니다."
        }

    if telnet_status == "실행중":
        return {
            "result": "수동확인",
            "reason": (
                f"SSH 점검: {ssh_reason or '확인필요'} "
                "TCP 23번 포트에서 접속 대기가 확인되어 "
                "Telnet 여부 및 root 로그인 제한 확인이 필요합니다."
            )
        }

    if ssh_status == "실행중":
        return {
            "result": "수동확인",
            "reason": (
                f"SSH 점검: {ssh_reason or '확인필요'} "
                f"Telnet 탐지 결과: {telnet_status}. "
                "추가 접속 경로 확인이 필요합니다."
            )
        }

    return {
        "result": "수동확인",
        "reason": (
            f"SSH 상태: {ssh_status}, Telnet 탐지 결과: {telnet_status}. "
            "원격 접속 경로를 추가 확인해야 합니다."
        )
    }

def check_u01_combined():
    if platform.system() != "Linux":
        return {
            "id": "U-01",
            "name": "root 계정 원격 접속 제한",
            "result": "해당없음",
            "reason": "현재 Linux 점검 기능만 구현되어 있습니다.",
            "details": {}
        }

    details = collect_u01_details()

    ssh_status = details["ssh_service"]
    ssh_result = "수동확인"
    ssh_reason = ""

    details["ssh_setting"] = "확인필요"
    details["ssh_detail"] = "SSH 설정 미확인"

    if ssh_status == "실행중":
        ssh_check = check_u01()
        ssh_result = ssh_check["result"]
        ssh_reason = ssh_check["reason"]

        details["ssh_setting"] = ssh_check.get(
            "ssh_setting", "확인필요"
        )
        details["ssh_detail"] = ssh_check.get(
            "ssh_detail", "SSH 설정 미확인"
        )
    evaluation = evaluate_u01(
        ssh_result,
        details,
        ssh_reason
    )

    return {
        "id": "U-01",
        "name": "root 계정 원격 접속 제한",
        "result": evaluation["result"],
        "reason": evaluation["reason"],
        "details": details
    }