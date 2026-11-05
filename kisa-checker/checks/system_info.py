import platform
import socket


def get_linux_distribution():
    try:
        info = {}

        with open("/etc/os-release", "r", encoding="utf-8") as file:
            for line in file:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    info[key] = value.strip('"')

        return {
            "name": info.get("NAME", "Unknown"),
            "id": info.get("ID", "unknown"),
            "version": info.get("VERSION_ID", "Unknown")
        }

    except OSError:
        return {
            "name": "Unknown",
            "id": "unknown",
            "version": "Unknown"
        }


def get_system_info():
    info = {
        "os": platform.system(),
        "os_version": platform.release(),
        "kernel": platform.version(),
        "hostname": socket.gethostname()
    }

    if info["os"] == "Linux":
        info["distribution"] = get_linux_distribution()

    return info