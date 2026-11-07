# 신석기백화점 직원용 PC 보안 앱

직원 자신의 Windows PC 상태만 보여주는 읽기 전용 로컬 앱입니다. XDR, 접속 기록, 관리자 기능은 별도 IT 관리자 콘솔로 분리합니다.

## 상태 조회
CPU, 메모리, 디스크, 네트워크 인터페이스, Windows 방화벽 프로필, 최근 24시간 Windows System/Application 오류·경고 건수를 표시합니다. 측정에 실패하면 확인 불가를 표시하고 보안 사고로 임의 단정하지 않습니다.

## 개발용 실행
Windows PowerShell에서 이 폴더로 이동하여 아래 명령을 실행합니다.

    npm.cmd test
    npm.cmd start

브라우저 주소는 http://127.0.0.1:5189 입니다.

## Windows EXE 제작 (Windows x64, Node.js 24)
Windows 호스트 PC에서 employee-agent 폴더로 이동한 뒤 다음을 실행합니다.

    npm.cmd install
    npm.cmd run build:exe

성공하면 dist/ShinseokgiEmployeeAgent.exe 파일이 생성됩니다. Node.js SEA 기능을 사용하므로 설치 대상 Windows PC에 Node.js가 따로 필요하지 않습니다. 단, 화면을 보기 위한 브라우저는 필요합니다. EXE 실행 시 로컬 서버를 열고 기본 브라우저를 실행하려고 시도합니다. EXE 콘솔 창을 닫으면 서버가 종료됩니다.

이것은 **서명되지 않은 개발·검증용 EXE**이며 Windows 10 가상 PC에서 실행·실측·종료·재시작을 테스트하기 전에는 배포 완료로 간주하지 않습니다. Windows SmartScreen 등의 보안 경고 가능성이 있으므로 외부 실제 배포에는 서명·신뢰·배포 정책이 추가로 필요합니다.

EXE에는 관리자용 XDR 코드나 ALEPH 수업용 모듈을 포함하지 않습니다. node_modules와 dist는 Git 추적에서 제외합니다.
