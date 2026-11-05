
from checks.system_info import get_system_info

print("=" * 50)
print("KISA Vulnerability Assessment Engine")
print("=" * 50)

print("취약점 점검 엔진을 시작합니다.")

system_info = get_system_info()

print("\n[시스템 정보]")
print("운영체제:", system_info["os"])
print("OS 버전:", system_info["os_version"])
print("커널:", system_info["kernel"])
print("호스트명:", system_info["hostname"])

if "distribution" in system_info:
    distro = system_info["distribution"]
    print("배포판:", distro["name"])
    print("배포판 ID:", distro["id"])
    print("배포판 버전:", distro["version"])

from checks.u01_root_remote import check_u01_combined

u01 = check_u01_combined()

print("\n[U-01 root 계정 원격 접속 제한]")
print("점검 결과:", u01["result"])
print("판단 근거:", u01["reason"])

if u01["details"]:
    details = u01["details"]

    print("\n[U-01 세부 점검 결과]")
    print("SSH 서비스:", details["ssh_service"])
    print("SSH 설정값:", details["ssh_setting"])
    print("SSH 판단:", details["ssh_detail"])
    print("Telnet 탐지:", details["telnet_service"])
    print("Telnet 판단:", details["telnet_detail"])
    print("Telnet PAM:", details["telnet_pam"])
    print("securetty:", details["securetty"]["status"])

from checks.u02_password_policy import check_u02_password_policy

u02 = check_u02_password_policy()
print("\n[U-02 비밀번호 관리정책 설정]")
print("점검 결과:", u02["result"])
print("판단 근거:", u02["reason"])
print("조치 권고:", u02["recommendation"])

if u02["details"]:
    policy = u02["details"]
    print("\n[U-02 세부 점검 결과]")
    print("login.defs:", policy["login_defs"])
    print("root 계정 비밀번호 사용 기간:", policy["root_aging"])
    print("비밀번호 복잡성 설정:", policy["pwquality"])
    print("비밀번호 재사용 제한:", policy["pwhistory"])
    print("PAM 모듈:", policy["pam"])

from checks.u03_account_lockout import check_u03_account_lockout

u03 = check_u03_account_lockout()
print("\n[U-03 계정 잠금 임계값 설정]")
print("점검 결과:", u03["result"])
print("판단 근거:", u03["reason"])
print("조치 권고:", u03["recommendation"])

if u03["details"]:
    print("\n[U-03 세부 점검 결과]")
    print("faillock.conf:", u03["details"]["faillock_conf"])
    print("PAM 설정:", u03["details"]["pam"])

from checks.u04_password_file import check_u04_password_file
from checks.u05_unique_root_uid import check_u05_unique_root_uid
from checks.u06_su_restriction import check_u06_su_restriction
from checks.u16_passwd_permissions import check_u16_passwd_permissions
from checks.u18_shadow_permissions import check_u18_shadow_permissions

for checker in (
    check_u04_password_file,
    check_u05_unique_root_uid,
    check_u06_su_restriction,
    check_u16_passwd_permissions,
    check_u18_shadow_permissions,
):
    finding = checker()
    print("\n[{} {}]".format(finding["id"], finding["name"]))
    print("점검 결과:", finding["result"])
    print("판단 근거:", finding["reason"])
    print("조치 권고:", finding["recommendation"])
    if finding["details"]:
        print("수집 요약:", finding["details"])
