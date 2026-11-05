# XDR 보너스 경보

이 폴더는 보너스 여섯 개의 연습 경보입니다. 경보는 수업용으로 만든 Wazuh 모양이며, 실제 로그가 아닙니다. 정답은 이 저장소에 없습니다.

## 경보 묶음

`xdr/fixtures/<moduleKey>.json` 을 읽습니다. `moduleKey` 는 아래 여섯 개입니다.

| moduleKey | 보는 것 |
|---|---|
| `brute-force` | 짧은 시간에 몰린 로그인 실패 |
| `web-injection` | 웹 요청에 섞인 주입 형태 |
| `known-cve` | 이미 공개된 취약점을 노린 요청 형태 |
| `persistence` | 다시 켜도 남도록 심긴 서비스·예약 작업 |
| `privilege` | 평범한 계정의 갑작스러운 권한 상승 |
| `exfiltration` | 처음 보는 곳으로 빠지는 큰 전송 |

한 파일에는 명확한 공격, 애매한 시도, 정상 이벤트가 함께 들어 있습니다. 주소는 문서용 대역만 쓰고, 계정은 `user01` 같은 가상 이름입니다. `known-cve` 의 원격 조회 구문은 문서용 표기입니다. 그 문자열을 다른 시스템에 넣거나 변형하지 않습니다.

## 학생이 만드는 파일

항목마다 `xdr/<moduleKey>/decide.mjs` 를 만듭니다. `decide(alert)` 를 내보냅니다. 비동기 함수여도 됩니다. 반환은 아래 세 값입니다.

- `action`: `block`, `alert`, `record` 중 하나
- `confidence`: 0 이상 1 이하 숫자
- `reason`: 짧은 이유

명확한 공격은 `block`, 애매한 시도는 `alert`, 정상 이벤트는 `record` 입니다. 경보 원본은 고치지 않습니다.

## 실행

저장소 루트에서 항목 키 하나를 넣습니다.

```
node scripts/xdr-run.mjs brute-force
```

`npm run xdr:run -- brute-force` 도 같은 명령입니다. 실행기는 해당 경보마다 `decide` 를 부르고, 결과를 `xdr/<moduleKey>/result.json` 에 씁니다. 형식은 `aleph.xdr.result.v1` 이고, `decisions` 에는 경보 id·행동·확신도·이유가, `counts` 에는 `block`·`alert`·`record` 건수가 있습니다.

반환 형식이 틀린 경보는 `record` 로 남고, 오류 한 줄이 출력됩니다. 실행기 자체는 네트워크를 쓰지 않습니다. 판정자는 격리된 환경에서 같은 명령을 다시 실행해 결과를 봅니다. 이미 커밋된 `result.json` 만으로 판정이 끝나지 않습니다.


## XDR-04 persistence 완료 내용

- 패턴 근거: MITRE ATT&CK T1543/T1053
- 원본 경보 24건 / 읽은 줄 24개
- 판단기: import/I/O 없이 0.85 이상 block, 0.5 이상 alert, 나머지 record
- PC 격리 후보: 확인된 대상 Wazuh PC 한 곳만 15분, 근거 경보 번호·만료 시각 포함
- 정상·애매한 이벤트는 새 격리 규칙을 만들지 않습니다.
- 기록: xdr/alerts.log (Git 추적 제외)
- 재생성: npm run xdr:run -- persistence
- 결과: block 8, alert 8, record 8, 정상 이벤트 block 0


## XDR-05 privilege 구현

- MITRE ATT&CK T1068, T1078의 관리자 그룹·권한 상승 및 비정상 고권한 명령 신호
- 경보 추출: 원본 26건 = 출력 26줄, 허용된 다섯 필드만 출력
- 독립 판정: 9 block, 8 alert, 9 record; 정상 이벤트 block 0건
- 대응 후보: 확정 공격만 Wazuh PC+계정 범위의 15분 임시 세션 거부, ID·만료 기록 및 안전 로그
- 운영 판정기 규칙 변경 없음. 학습용 연결이며 실제 계정-세션 식별자 매핑 미연동
- 재실행: npm run xdr:run -- privilege


## XDR-06 exfiltration 구현

- 근거: MITRE ATT&CK T1041(명령 통로 이용 반출), T1048(다른 프로토콜 이용 반출)
- 원본 경보 30건 = 추출 30줄; 허용된 5개 필드만 출력
- 분류: block 10 / alert 10 / record 10; 확인된 정상 이벤트 차단 0건
- 대응: 고확신 사건에만 영향을 받은 PC+외부 목적지(dstip) 범위에서 15분 임시 거부 후보. 증거 경보 번호·만료 시각 포함
- 로컬 알림: `xdr/alerts.log`, 민감한 IP/계정/파일 원문 기록 제외
- ZTNA: 기존 판정 불변, 신뢰된 PC·목적지 확인을 전제로 학습 연결(운영 자동 차단 아님)
- 재실행: `npm run xdr:run -- exfiltration`

