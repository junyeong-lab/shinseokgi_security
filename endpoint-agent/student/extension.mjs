// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView({ api, onChange } = {}) {
  // 개인 관제 대시보드: 읽기 전용 API를 버튼을 누를 때만 조회한다.
  // 실제 PC 응답만 실측으로 받아들이고, 예시 값·확인 불가·다른 출처를 섞지 않는다.
  // 이력은 현재 페이지 메모리의 최근 12회만 보관하며 새로고침하면 초기화된다.
  const pcDashboard = { phase: 'idle', samples: [], message: '' };
  // 학생 신원 상세 정보의 접기 상태는 리렌더링 중에도 유지합니다.
  let identityDetailsOpen = false;
  const readableNumber = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
  const percent = value => readableNumber(value) && value <= 100 ? value : null;
  const bytes = value => readableNumber(value) ? (value / 1073741824).toFixed(1) + ' GB' : '확인 불가';
  const timeText = value => new Date(value).toLocaleString('ko-KR');
  const knownReason = {
    permission_denied: '일반 사용자 권한으로 읽을 수 없음',
    unsupported: '현재 운영체제에서 지원하지 않음',
    timeout: '조회 시간 초과',
  };
  const missingReason = metric => metric?.state !== 'ok'
    ? (knownReason[metric?.reason] ?? '항목 조회 실패 또는 응답 없음')
    : '측정값 형식 확인 불가';
  const localMetric = (data, name) => data?.metrics?.[name]?.state === 'ok' ? data.metrics[name] : null;
  const readPcSample = response => {
    if (response?.ok !== true) {
      const code = response?.error?.code;
      throw Error(code === 'NOT_ALLOWED' ? '학생 API 접근이 허용되지 않음'
        : code === 'REQUEST_TIMEOUT' || code === 'TIMEOUT' ? '요청 시간 초과'
        : code === 'PERMISSION_DENIED' ? '일반 사용자 권한으로 읽을 수 없음'
        : '실측 요청 실패 또는 응답 형식 확인 불가');
    }
    const data = response?.data;
    const at = data?.measuredAt;
    const timestamp = typeof at === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(at) ? Date.parse(at) : NaN;
    if (data?.schema !== 'aleph.on.pc-status.v1' || data?.source !== 'local-pc'
      || !Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > 60000) {
      throw Error('실측 출처 또는 측정 시각 확인 불가');
    }
    const cpu = localMetric(data, 'cpu');
    const memory = localMetric(data, 'memory');
    const disk = localMetric(data, 'disk');
    const events = localMetric(data, 'events');
    const network = localMetric(data, 'network');
    const firewall = localMetric(data, 'firewall');
    const networkValid = Number.isSafeInteger(network?.interfaceCount) && network.interfaceCount >= 0
      && Number.isSafeInteger(network?.ipv4Count) && network.ipv4Count >= 0;
    const profileNames = ['Domain', 'Private', 'Public'];
    const firewallValid = Array.isArray(firewall?.profiles) && firewall.profiles.length === 3
      && profileNames.every(name => firewall.profiles.filter(p => p?.name === name && typeof p.enabled === 'boolean').length === 1);
    const windowSince = typeof events?.since === 'string' && Number.isFinite(Date.parse(events.since))
      ? events.since : null;
    const cpuPercent = percent(cpu?.usagePercent);
    const memoryValid = readableNumber(memory?.usedBytes) && readableNumber(memory?.totalBytes)
      && memory.totalBytes > 0 && memory.usedBytes <= memory.totalBytes;
    const diskValid = readableNumber(disk?.freeBytes) && readableNumber(disk?.totalBytes)
      && disk.totalBytes > 0 && disk.freeBytes <= disk.totalBytes;
    const eventsValid = Number.isSafeInteger(events?.warningCount) && events.warningCount >= 0
      && Number.isSafeInteger(events?.errorCount) && events.errorCount >= 0
      && events.warningCount + events.errorCount <= 5000 && events.sampleLimit === 5000
      && typeof events.truncated === 'boolean';
    return Object.freeze({
      at, cpu: cpuPercent,
      memoryPercent: memoryValid ? (memory.usedBytes / memory.totalBytes) * 100 : null,
      memoryUsed: memoryValid ? memory.usedBytes : null,
      memoryTotal: memoryValid ? memory.totalBytes : null,
      diskFree: diskValid ? disk.freeBytes : null,
      diskTotal: diskValid ? disk.totalBytes : null,
      warnings: eventsValid ? events.warningCount : null,
      errors: eventsValid ? events.errorCount : null,
      eventsTruncated: eventsValid ? events.truncated : null,
      eventsSince: eventsValid ? windowSince : null,
      networkInterfaces: networkValid ? network.interfaceCount : null,
      networkIpv4: networkValid ? network.ipv4Count : null,
      firewallProfiles: firewallValid
        ? Object.freeze(profileNames.map(name => Object.freeze({
          name, enabled: firewall.profiles.find(p => p.name === name).enabled,
        }))) : null,
      reasons: {
        cpu: cpuPercent === null ? missingReason(data?.metrics?.cpu) : null,
        memory: !memoryValid ? missingReason(data?.metrics?.memory) : null,
        disk: !diskValid ? missingReason(data?.metrics?.disk) : null,
        events: !eventsValid ? missingReason(data?.metrics?.events) : null,
        network: !networkValid ? missingReason(data?.metrics?.network) : null,
        firewall: !firewallValid ? missingReason(data?.metrics?.firewall) : null,
      },
    });
  };
  // 학생 카드가 다시 그려져도 버튼의 키보드 초점은 유지한다.
  // 조회 중에도 버튼을 포커스 가능한 상태로 두고, 중복 요청은 함수에서 막는다.
  const publishDashboard = () => {
    const focused = document.activeElement?.getAttribute?.('data-olpot-read-pc') === 'true';
    if (typeof onChange === 'function') onChange();
    if (focused && typeof document.querySelector === 'function') {
      const next = document.querySelector('[data-olpot-read-pc="true"]');
      if (typeof next?.focus === 'function') next.focus({ preventScroll: true });
    }
  };
  const nextStep = reason => {
    if (typeof reason !== 'string') return '다시 조회해 확인하세요. 계속 실패하면 제공 「내 PC 상태」의 결과를 확인하세요.';
    if (reason.includes('권한') || reason.includes('허용되지')) {
      return '관리자 권한으로 실행하지 말고, 일반 사용자 계정의 읽기 권한을 담당자에게 확인하세요.';
    }
    if (reason.includes('시간 초과')) return '잠시 후 「다시 조회」를 눌러주세요. 계속 실패하면 앱 실행 상태를 확인하세요.';
    if (reason.includes('운영체제') || reason.includes('지원하지')) return '현재 PC에서 지원되는 조회 항목인지 확인하세요. 설정은 변경하지 마세요.';
    if (reason.includes('형식') || reason.includes('출처') || reason.includes('시각')) {
      return '응답 출처·형식·측정 시각을 확인하고 다시 조회하세요. 이전 값을 현재 값으로 사용하지 않습니다.';
    }
    return '「다시 조회」로 재확인하고, 계속 실패하면 제공 「내 PC 상태」의 오류 안내를 확인하세요.';
  };
  const updatePcDashboard = async () => {
    if (pcDashboard.phase === 'loading') return;
    pcDashboard.phase = 'loading';
    pcDashboard.message = '';
    publishDashboard();
    try {
      if (typeof api?.get !== 'function') throw Error('학생 PC 조회 API 지원 없음');
      const response = await api.get('/api/pc/status');
      const sample = readPcSample(response);
      pcDashboard.samples.push(sample);
      if (pcDashboard.samples.length > 12) pcDashboard.samples.shift();
      pcDashboard.phase = 'ok';
    } catch (error) {
      pcDashboard.phase = 'error';
      const known = ['학생 API 접근이 허용되지 않음', '요청 시간 초과', '일반 사용자 권한으로 읽을 수 없음',
        '실측 요청 실패 또는 응답 형식 확인 불가', '실측 출처 또는 측정 시각 확인 불가',
        '학생 PC 조회 API 지원 없음'];
      pcDashboard.message = error instanceof Error && known.includes(error.message)
        ? error.message : '연결 실패 또는 응답 확인 불가';
    } finally {
      publishDashboard();
    }
  };
  const renderPcDashboard = (root, me) => {
    const el = (parent, tag, value, className) => {
      const node = document.createElement(tag);
      if (className) node.className = className;
      if (value !== undefined) node.textContent = value;
      parent.appendChild(node);
      return node;
    };
    const section = el(root, 'section');
    section.setAttribute('data-olpot-dashboard', 'local-pc-comparison');
    section.setAttribute('aria-label', 'olpot 로컬 PC 관제 대시보드');
    // 기존 공통 CSS의 카드·행·태그를 재사용한다. inline style과 제공 UI 수정을 하지 않는다.
    const header = el(section, 'header', undefined, 'card');
    const titleRow = el(header, 'div', undefined, 'row');
    el(titleRow, 'h3', 'olpot · 내 PC 관제');
    el(titleRow, 'span', 'LOCAL PC · 읽기 전용', 'tag tag-student');
    el(header, 'p', '로컬 PC 실측과 SDP 원천 연결은 별도입니다. 실제로 읽은 수치에만 출처·시각·단위를 표시합니다.', 'muted');

    const controls = el(header, 'div', undefined, 'row');
    const action = el(controls, 'button', pcDashboard.phase === 'loading' ? '조회 중…' : '다시 조회', 'btn');
    action.type = 'button';
    action.setAttribute('data-olpot-read-pc', 'true');
    action.setAttribute('aria-disabled', pcDashboard.phase === 'loading' ? 'true' : 'false');
    action.setAttribute('aria-busy', pcDashboard.phase === 'loading' ? 'true' : 'false');
    action.setAttribute('aria-label', '로컬 PC 네트워크·방화벽·기록 및 실측 비교 다시 조회');
    action.addEventListener('click', () => { void updatePcDashboard(); });
    const samples = pcDashboard.samples;
    const last = pcDashboard.phase === 'ok' ? samples[samples.length - 1] : null;
    const previous = last && samples.length >= 2 ? samples[samples.length - 2] : null;
    const comparable = previous && Date.parse(last.at) > Date.parse(previous.at);
    const source = last ? (last.cpu === null && last.memoryPercent === null && last.diskFree === null
      && last.warnings === null && last.networkInterfaces === null && last.firewallProfiles === null
      ? '로컬 응답 확인 · 모든 측정값 확인 불가 · 확인 시각 ' : '일부 또는 전체 항목 실측 확인 · 이 PC · 최근 측정 ') + timeText(last.at)
      : pcDashboard.phase === 'loading' ? '실측 조회 중 · 현재값 대기'
      : pcDashboard.phase === 'error' ? '이번 조회 확인 불가 · 이전 이력은 현재값이 아님'
      : '미측정 · 현재 실측 데이터 없음';
    el(header, 'p', source, pcDashboard.phase === 'loading' ? 'state state-loading'
      : pcDashboard.phase === 'error' ? 'state state-error'
      : pcDashboard.phase === 'idle' ? 'state state-empty' : 'state').setAttribute('role', 'status');
    if (pcDashboard.phase === 'error') {
      el(header, 'p', '이번 조회 실패 · 이유: ' + pcDashboard.message + ' · 다음 행동: ' + nextStep(pcDashboard.message), 'state state-error');
    }

    // 사용자 구현 4개 카드: 장식 SVG 없이 상태값을 텍스트로 보여주고, 판단 근거는 HTML에 보존한다.
    const securityGrid = el(section, 'div', undefined, 'grid-2');
    const securityCard = (name, tag) => {
      const card = el(securityGrid, 'section', undefined, 'card student');
      const head = el(card, 'div', undefined, 'row');
      const heading = el(head, 'h3', name);
      heading.style.fontSize = '1.1rem';
      el(head, 'span', tag, 'tag');
      return card;
    };
    const measuredTime = last ? '측정 시각 ' + timeText(last.at) : '미측정';
    const unavailable = reason => {
      const why = reason || (pcDashboard.phase === 'error' ? pcDashboard.message : '실제 로컬 조회 전 또는 조회 중');
      return '확인 불가 · 이유: ' + why + ' · 다음 행동: ' + nextStep(why);
    };
    // 학생 카드 내부에서만 CSSOM으로 글자 크기를 지정합니다. 제공 CSS·DOM은 바꾸지 않습니다.
    // 장식 아이콘·컬러 배너 없이 2열 실측 지표와 접근성 있는 HTML 텍스트를 사용합니다.
    const metricRows = (card, items, description) => {
      const group = el(card, 'div', undefined, items.length === 2 ? 'grid-2' : undefined);
      group.setAttribute('role', 'group');
      group.setAttribute('aria-label', description);
      group.style.marginTop = '12px';
      for (const [value, label] of items) {
        const metric = el(group, 'div');
        const number = el(metric, 'strong', value);
        number.style.display = 'block';
        number.style.fontSize = '2rem';
        number.style.fontWeight = '750';
        number.style.lineHeight = '1.25';
        number.style.overflowWrap = 'anywhere';
        const caption = el(metric, 'p', label);
        caption.style.fontSize = '1rem';
        caption.style.margin = '4px 0 0';
        caption.style.lineHeight = '1.4';
        caption.style.color = 'var(--muted)';
      }
    };
    const evidence = (card, text) => {
      const details = el(card, 'details');
      el(details, 'summary', '측정 근거·해석 범위 보기');
      for (const sentence of text) el(details, 'p', sentence, 'muted');
    };
    const networkCard = securityCard('네트워크 구성',
      last?.networkInterfaces != null ? '로컬 PC 실측' : '측정 대기·확인 불가');
    if (last?.networkInterfaces != null) {
      metricRows(networkCard, [
        [last.networkInterfaces + '개', '네트워크 인터페이스'],
        [last.networkIpv4 + '개', 'IPv4 구성'],
      ], '로컬 PC 네트워크 인터페이스와 IPv4 구성 개수. 인터넷 접속 성공을 의미하지 않음.');
      el(networkCard, 'p', measuredTime + ' · 로컬 PC 실측', 'muted');
    } else {
      metricRows(networkCard, [['확인 불가', '네트워크 미측정']], '네트워크 구성 확인 불가');
      el(networkCard, 'p', unavailable(last?.reasons?.network));
    }
    el(networkCard, 'p', '구성 수치 · 인터넷 접속 성공을 뜻하지 않음', 'muted');
    evidence(networkCard, ['구성 개수만 조회하며 인터넷 접속이나 업무망 접근 허용을 증명하지 않습니다.',
      '출처: 읽기 전용 로컬 PC 조회 · ' + measuredTime]);

    const firewallCard = securityCard('Windows 방화벽 설정',
      last?.firewallProfiles ? '로컬 설정 실측' : '측정 대기·확인 불가');
    if (last?.firewallProfiles) {
      const enabled = last.firewallProfiles.filter(p => p.enabled).length;
      metricRows(firewallCard, [
        [enabled + '개', '켜진 방화벽 프로필'],
        [last.firewallProfiles.length + '개', '전체 프로필'],
      ], '로컬 PC 방화벽 설정. 켜진 프로필 ' + enabled + '개 / 전체 ' + last.firewallProfiles.length
        + '개. 전체 보안 안전 판정 아님.');
      const badges = el(firewallCard, 'div', undefined, 'row');
      for (const p of last.firewallProfiles) el(badges, 'span', p.name + ' · ' + (p.enabled ? '켜짐' : '꺼짐'), 'tag');
      el(firewallCard, 'p', measuredTime + ' · 로컬 PC 설정 실측', 'muted');
    } else {
      metricRows(firewallCard, [['확인 불가', '방화벽 설정 미측정']], '방화벽 설정 확인 불가');
      el(firewallCard, 'p', unavailable(last?.reasons?.firewall));
    }
    el(firewallCard, 'p', '설정만 확인 · 안전 판정 아님', 'muted');
    evidence(firewallCard, ['설정 읽기 전용 · 변경하지 않음 · 켜져 있어도 전체 보안이 안전하다는 뜻이 아닙니다.',
      '출처: 로컬 방화벽 설정 · ' + measuredTime]);

    const windowsCard = securityCard('최근 Windows 기록',
      last?.warnings != null ? 'System · Application' : '측정 대기·확인 불가');
    if (last?.warnings != null) {
      metricRows(windowsCard, [
        [last.warnings + '건', 'Windows 경고'],
        [last.errors + '건', 'Windows 오류'],
      ], '최근 24시간 Windows 기록 집계. 침해 탐지 결과 아님.');
      el(windowsCard, 'p', measuredTime + ' · 로컬 PC 실측', 'muted');
      if (last.eventsTruncated) el(windowsCard, 'p', '최대 5,000건까지만 확인한 일부 집계입니다.', 'state state-empty');
    } else {
      metricRows(windowsCard, [['확인 불가', 'Windows 기록 미측정']], '경고 및 오류 집계 확인 불가');
      el(windowsCard, 'p', unavailable(last?.reasons?.events));
    }
    el(windowsCard, 'p', '시스템 기록 건수 · 침해 탐지 결과 아님', 'muted');
    evidence(windowsCard, [
      last?.eventsSince ? '집계 시작 시각: ' + timeText(last.eventsSince) : '집계 시작 시각: 확인 불가',
      last?.eventsTruncated ? '최대 5,000건까지만 집계한 일부 결과. 전체 사건 수가 아닙니다.'
        : '최대 5,000건까지 확인한 집계 결과입니다.',
      '경고·오류 건수는 침해나 공격 탐지 결과가 아닙니다. 악성 행위 발생 여부를 판정하지 않습니다.',
    ]);

    const sdpCard = securityCard('SDP 연결 상태', '로컬 PC 실측과 별개');
    const sdpMode = me?.mode;
    const sdpKnownDisconnected = sdpMode === 'disconnected' || sdpMode === 'demo'
      || (me?.status === 'error' && me?.error?.code === 'ENGINE_NOT_CONNECTED');
    if (sdpKnownDisconnected) {
      metricRows(sdpCard, [['미연결', '원천 연결 확인 안 됨']], 'SDP 미연결 · PC 실측과 별개');
      if (sdpMode === 'demo') el(sdpCard, 'p', '예시 자료 모드 · 실제 연결 아님', 'state state-empty');
    } else if (me?.status === 'loading') {
      metricRows(sdpCard, [['확인 중', '연결 결과 대기']], 'SDP 연결 확인 중 · 아직 성공 판정 불가');
      el(sdpCard, 'p', '연결 성공 판정 전', 'state state-loading');
    } else {
      metricRows(sdpCard, [['확인 불가', '연결 성공 미검증']], 'SDP 연결 확인 불가 · 실제 접속 성공 미검증');
      el(sdpCard, 'p', '현재 신원·연결 모드만으로 실제 SDP 접속 성공을 검증할 수 없습니다.', 'state state-empty');
    }
    el(sdpCard, 'p', '로컬 PC 측정 성공 ≠ SDP 연결 성공', 'muted');
    evidence(sdpCard, ['로컬 PC 측정 성공 ≠ SDP 연결 성공. 원천 판정·실제 XDR 기록은 별도 연결 확인이 필요합니다.']);
    el(section, 'p', '핵심 기능 3가지 · ① PC 실측 변화 비교  ② CPU·메모리 실측 추이  ③ 기록·출처·다음 행동', 'notice');
    const issues = last ? [
      ['CPU', last.reasons.cpu], ['메모리', last.reasons.memory], ['디스크', last.reasons.disk],
      ['네트워크', last.reasons.network], ['Windows 방화벽', last.reasons.firewall],
      ['Windows 기록', last.reasons.events],
    ].filter(([_, reason]) => reason !== null && reason !== undefined) : [];
    if (issues.length) {
      const notice = el(section, 'section', undefined, 'card');
      el(notice, 'h4', '이번 조회에서 실패한 항목 · 다음 행동');
      const list = el(notice, 'ul');
      for (const [name, reason] of issues) {
        el(list, 'li', name + ': 확인 불가 · 이유: ' + reason + ' · 다음 행동: ' + nextStep(reason));
      }
    }
    const comparisonPanel = el(section, 'section');
    const compareHeading = el(comparisonPanel, 'h3', '① PC 실측 변화 비교');
    compareHeading.setAttribute('id', 'olpot-day4-comparison');
    el(comparisonPanel, 'p', '서로 다른 두 시각의 유효한 실측값만 비교합니다. 값이 없으면 확인 불가로 표시합니다.', 'muted');
    if (!comparable) el(comparisonPanel, 'p', '비교 대기: 서로 다른 측정 시각의 유효한 실측 결과 2회가 필요합니다. 위 「다시 조회」를 눌러주세요.', 'state state-empty');
    const grid = el(comparisonPanel, 'div', undefined, 'grid-2');
    const pct = v => v === null ? '확인 불가' : v.toFixed(1) + '%';
    // Student-only inline SVG: no external chart library, script, CSS override or sample values.
    // SVG shapes are generated only for validated real local measurements.
    const graphColors = Object.freeze({
      previous: '#99b8e8',
      cpu: '#276ce0',
      memory: '#7465d7',
      disk: '#249e92',
      events: '#d87533',
      error: '#c95b4e',
      text: '#23374f',
      muted: '#53677f',
      grid: '#dce4ef',
    });
    const svgNS = 'http://www.w3.org/2000/svg';
    const svgItem = (parent, tag, attributes = {}, label) => {
      const node = document.createElementNS(svgNS, tag);
      for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
      if (label !== undefined) node.textContent = String(label);
      parent.appendChild(node);
      return node;
    };
    const svgText = (parent, x, y, label, options = {}) => svgItem(parent, 'text', {
      x, y, fill: graphColors.text, 'font-family': 'system-ui, Malgun Gothic, sans-serif',
      'font-size': 12, ...options,
    }, label);
    const validPlotValue = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
    const axisCeiling = (values, unit) => {
      const maxValue = Math.max(0, ...values.filter(validPlotValue));
      const step = unit === '%' ? 10 : unit === 'GB' ? 10 : 5;
      const limit = Math.max(step, Math.ceil(maxValue * 1.15 / step) * step);
      return unit === '%' ? Math.min(100, limit) : limit;
    };
    const appendComparisonChart = (card, title, oldValue, newValue, unit, color, display) => {
      if (typeof document.createElementNS !== 'function' || !comparable
        || !validPlotValue(oldValue) || !validPlotValue(newValue)) return;
      const ceiling = axisCeiling([oldValue, newValue], unit);
      const chart = svgItem(card, 'svg', {
        viewBox: '0 0 360 148', width: '100%', height: 148,
        preserveAspectRatio: 'xMidYMid meet', role: 'img',
        'aria-label': title + ' 막대그래프. 이전 ' + display(oldValue) + ', 최근 ' + display(newValue)
          + '. 0부터 ' + ceiling + unit + '까지의 눈금.',
      });
      svgItem(chart, 'title', {}, title + ' · 이전과 최근 실측 비교');
      svgItem(chart, 'desc', {}, '이전: ' + display(oldValue) + ', 최근: ' + display(newValue)
        + '. 두 값은 동일한 0 기준에서 비교하며 자동 눈금의 최대값은 ' + ceiling + unit + '입니다.');
      svgText(chart, 14, 15, '눈금 0–' + ceiling + unit, { fill: graphColors.muted, 'font-size': 11 });
      for (const y of [48, 78, 110]) {
        svgItem(chart, 'line', { x1: 28, y1: y, x2: 333, y2: y, stroke: graphColors.grid, 'stroke-width': 1 });
      }
      const columns = [
        { x: 87, name: '이전', value: oldValue, fill: graphColors.previous },
        { x: 221, name: '최근', value: newValue, fill: color },
      ];
      for (const item of columns) {
        const height = Math.max(0, Math.min(78, item.value / ceiling * 78));
        if (height > 0) svgItem(chart, 'rect', {
          x: item.x, y: 109 - height, width: 54, height, rx: 7, ry: 7, fill: item.fill,
        });
        svgText(chart, item.x + 27, Math.max(29, 103 - height), display(item.value), {
          'text-anchor': 'middle', 'font-weight': 700, 'font-size': 13,
        });
        svgText(chart, item.x + 27, 132, item.name, {
          'text-anchor': 'middle', fill: graphColors.muted, 'font-size': 12,
        });
      }
    };
    const appendTrendChart = (parent, measurements) => {
      if (typeof document.createElementNS !== 'function') return;
      const usable = measurements.some(sample => validPlotValue(sample.cpu) || validPlotValue(sample.memoryPercent));
      if (!usable) return;
      const ceiling = axisCeiling(measurements.flatMap(sample => [sample.cpu, sample.memoryPercent]), '%');
      const svg = svgItem(parent, 'svg', {
        viewBox: '0 0 720 252', width: '100%', height: 252,
        preserveAspectRatio: 'xMidYMid meet', role: 'img',
        'aria-label': '최근 ' + measurements.length + '회 수동 측정 CPU·메모리 사용률 막대 추이. 자세한 시각과 수치는 아래 기록에 있습니다.',
      });
      svgItem(svg, 'title', {}, 'CPU·메모리 사용률 · 측정 시각 순서대로 비교');
      svgItem(svg, 'desc', {}, measurements.map((sample, index) =>
        (index + 1) + '번 ' + timeText(sample.at)
        + ' CPU ' + (validPlotValue(sample.cpu) ? sample.cpu.toFixed(1) + '%' : '확인 불가')
        + ', 메모리 ' + (validPlotValue(sample.memoryPercent) ? sample.memoryPercent.toFixed(1) + '%' : '확인 불가')).join('; '));
      const legend = [
        { x: 490, label: 'CPU', color: graphColors.cpu },
        { x: 590, label: '메모리', color: graphColors.memory },
      ];
      for (const item of legend) {
        svgItem(svg, 'rect', { x: item.x, y: 8, width: 12, height: 12, rx: 3, fill: item.color });
        svgText(svg, item.x + 18, 19, item.label, { fill: graphColors.muted, 'font-size': 12 });
      }
      const left = 48, top = 34, bottom = 199, width = 644, height = bottom - top;
      for (const fraction of [0, 0.25, 0.5, 0.75, 1]) {
        const y = bottom - fraction * height;
        svgItem(svg, 'line', { x1: left, y1: y, x2: left + width, y2: y,
          stroke: graphColors.grid, 'stroke-width': 1 });
        svgText(svg, left - 9, y + 4, String(Number((ceiling * fraction).toFixed(1))), {
          'text-anchor': 'end', fill: graphColors.muted, 'font-size': 11,
        });
      }
      const group = width / measurements.length;
      const barWidth = Math.min(20, group * 0.28);
      for (const [index, sample] of measurements.entries()) {
        const center = left + group * (index + 0.5);
        for (const info of [
          { value: sample.cpu, x: center - barWidth - 2, color: graphColors.cpu },
          { value: sample.memoryPercent, x: center + 2, color: graphColors.memory },
        ]) {
          if (!validPlotValue(info.value)) continue;
          const barHeight = Math.max(0, Math.min(height, info.value / ceiling * height));
          if (barHeight > 0) svgItem(svg, 'rect', {
            x: info.x, y: bottom - barHeight, width: barWidth, height: barHeight,
            rx: Math.min(5, barWidth / 3), ry: Math.min(5, barWidth / 3), fill: info.color,
          });
        }
        svgText(svg, center, 221, String(index + 1), {
          'text-anchor': 'middle', fill: graphColors.muted, 'font-size': 12,
        });
      }
      svgText(svg, left, 243, '단위: % · 세로 눈금 0–' + ceiling
        + '% · 가로 번호는 아래 실측 기록과 대응', { fill: graphColors.muted, 'font-size': 11 });
    };

    const gb = v => v === null ? '확인 불가' : bytes(v);
    const delta = (v, unit, places) => (v >= 0 ? '+' : '') + v.toFixed(places) + ' ' + unit;
    const comparison = (title, a, b, formatter, diff, unit, places, reasonA, reasonB, note, graphValue, graphUnit, graphColor) => {
      const card = el(grid, 'section', undefined, 'card student');
      el(card, 'h4', title);
      if (!comparable) {
        el(card, 'p', '확인 불가 · 유효한 두 시점의 측정 필요 · 다음 행동: 「다시 조회」로 두 번째 실측 기록');
      } else if (a === null || b === null) {
        el(card, 'p', '확인 불가 · ' + (a === null ? '이전: ' + (reasonA ?? '측정되지 않음') : '')
          + (a === null && b === null ? ' / ' : '')
          + (b === null ? '최근: ' + (reasonB ?? '측정되지 않음') : ''));
      } else {
        el(card, 'p', '변화 ' + delta(diff, unit, places), 'item-title');
      }
      if (graphValue && comparable && a !== null && b !== null) {
        appendComparisonChart(card, title, graphValue(a), graphValue(b), graphUnit, graphColor,
          value => graphUnit === 'GB' ? value.toFixed(1) + ' GB' : formatter(value));
      }
      if (previous && last) {
        el(card, 'p', '이전 실측 ' + timeText(previous.at) + ' · ' + (a === null ? '확인 불가 (' + reasonA + ')' : formatter(a)), 'muted');
        el(card, 'p', '최근 실측 ' + timeText(last.at) + ' · ' + (b === null ? '확인 불가 (' + reasonB + ')' : formatter(b)), 'muted');
      }
      el(card, 'p', note, 'muted');
    };
    comparison('CPU 사용률 변화', previous?.cpu ?? null, last?.cpu ?? null, pct,
      (last?.cpu ?? 0) - (previous?.cpu ?? 0), '%p', 1,
      previous?.reasons.cpu, last?.reasons.cpu, '사용률 차이(%p) · 높은 수치만으로 악성코드 판정 불가',
      value => value, '%', graphColors.cpu);
    comparison('메모리 사용률 변화', previous?.memoryPercent ?? null, last?.memoryPercent ?? null, pct,
      (last?.memoryPercent ?? 0) - (previous?.memoryPercent ?? 0), '%p', 1,
      previous?.reasons.memory, last?.reasons.memory, '실측 사용량/총량으로 계산한 비율의 차이(%p)',
      value => value, '%', graphColors.memory);
    comparison('디스크 여유 공간 변화', previous?.diskFree ?? null, last?.diskFree ?? null, gb,
      ((last?.diskFree ?? 0) - (previous?.diskFree ?? 0)) / 1073741824, 'GB', 2,
      previous?.reasons.disk, last?.reasons.disk, '앱이 설치된 디스크의 여유 공간 차이(GB)',
      value => value / 1073741824, 'GB', graphColors.disk);
    const windowsDiff = comparable && previous.warnings !== null && last.warnings !== null
      && previous.errors !== null && last.errors !== null;
    const eventsBox = el(grid, 'section', undefined, 'card student');
    el(eventsBox, 'h3', 'Windows 기록 집계 변화');
    el(eventsBox, 'p', windowsDiff
      ? '경고 ' + delta(last.warnings - previous.warnings, '건', 0)
        + ' · 오류 ' + delta(last.errors - previous.errors, '건', 0)
      : '확인 불가 · ' + (previous?.reasons.events ?? last?.reasons.events ?? '두 시점 측정 필요'), 'item-title');
    if (windowsDiff) {
      appendComparisonChart(eventsBox, 'Windows 경고 건수', previous.warnings, last.warnings, '건',
        graphColors.events, value => value + '건');
      appendComparisonChart(eventsBox, 'Windows 오류 건수', previous.errors, last.errors, '건',
        graphColors.error, value => value + '건');
    }
    if (previous && last) {
      el(eventsBox, 'p', '이전 실측 ' + timeText(previous.at) + ' · '
        + (previous.warnings === null ? '확인 불가 (' + previous.reasons.events + ')' : '경고 ' + previous.warnings + '건 · 오류 ' + previous.errors + '건'));
      el(eventsBox, 'p', '최근 실측 ' + timeText(last.at) + ' · '
        + (last.warnings === null ? '확인 불가 (' + last.reasons.events + ')' : '경고 ' + last.warnings + '건 · 오류 ' + last.errors + '건'));
    }
    el(eventsBox, 'p', '최근 24시간 집계의 시점별 차이일 뿐 신규 위협 건수가 아닙니다. 최대 5,000건만 읽습니다.'
      + (previous?.eventsTruncated || last?.eventsTruncated ? ' 일부 집계로 전체 증감을 알 수 없습니다.' : ''));

    const trend = el(section, 'section', undefined, 'card');
    const trendHeading = el(trend, 'h3', '② CPU·메모리 실측 추이');
    trendHeading.setAttribute('id', 'olpot-day4-trend');
    el(trend, 'p', '최근 12회 수동 조회 결과 · 각 값의 단위 % · 실제 측정점만 표시 · 새로고침 후 이력 초기화', 'muted');
    if (samples.length < 2) {
      el(trend, 'p', '추이 데이터 부족: 위 「다시 조회」를 눌러 서로 다른 시각의 실측 결과 2회를 기록하세요. 예시 그래프는 넣지 않습니다.', 'state state-empty');
    } else {
      appendTrendChart(trend, samples);
      const history = el(trend, 'ol', undefined, 'records');
      for (const [index, sample] of samples.entries()) {
        const entry = el(history, 'li', undefined, 'event');
        el(entry, 'h4', String(index + 1).padStart(2, '0') + ' · 실측 ' + timeText(sample.at));
        el(entry, 'p', 'CPU '
          + (sample.cpu === null ? '확인 불가 (' + sample.reasons.cpu + ')' : pct(sample.cpu))
          + ' · 메모리 ' + (sample.memoryPercent === null
            ? '확인 불가 (' + sample.reasons.memory + ')' : pct(sample.memoryPercent)), 'item-title');
        el(entry, 'p', '디스크 여유 ' + (sample.diskFree === null ? '확인 불가 (' + sample.reasons.disk + ')' : gb(sample.diskFree))
          + ' · Windows 경고 ' + (sample.warnings === null ? '확인 불가 (' + sample.reasons.events + ')' : sample.warnings + '건')
          + ' · 오류 ' + (sample.errors === null ? '확인 불가 (' + sample.reasons.events + ')' : sample.errors + '건'), 'muted');
      }
      el(trend, 'p', '가로 번호는 아래 기록 순서와 같습니다. 실제 측정하지 않은 시각의 값은 표시하거나 추정하지 않습니다.', 'muted');
    }
    const records = el(section, 'section', undefined, 'card');
    const recordsHeading = el(records, 'h3', '③ 기록·출처·다음 행동');
    recordsHeading.setAttribute('id', 'olpot-day4-records');
    el(records, 'p', '측정 출처: /api/pc/status (읽기 전용 로컬 PC API). 원본 데이터는 제공 「내 PC 상태」 기능과 동일한 경로에서 조회하며 설정값을 변경하지 않습니다.', 'item-title');
    const modes = { connected: '연결됨(실제 원천 데이터 별도 확인 필요)',
      disconnected: '연결 없음', demo: '예제 자료 · 실제 연결 아님', unknown: '확인 불가' };
    const mode = typeof me?.mode === 'string' && Object.hasOwn(modes, me.mode) ? me.mode : 'unknown';
    el(records, 'p', '신원·계정 데이터 모드: ' + modes[mode]
      + ' · SDP 연결 여부는 위의 별도 카드에서 확인하세요. 실제 접속·XDR 기록은 기존 「보안 기록」 메뉴에서 별도로 확인하세요.', 'muted');
    if (samples.length) {
      el(records, 'p', '이 페이지의 과거 실측 이력 ' + samples.length
        + '건 보유 · 브라우저를 새로고침하면 사라집니다. 영구 저장 기능이 아닙니다.', 'muted');
    }
    root.insertBefore(section, root.firstChild);
  };

  return {
    renderIdentity({ me, devices, sessions }) {
      // Render a fresh DOM tree for each snapshot; never retain the previous identity.
      const root = document.createElement('div');
      // 두 제공/학생 신원 카드의 동일 행 높이를 줄이기 위해 학생 상세만 접습니다.
      // 제공 카드의 DOM, CSS, 원본 API 응답은 변경하지 않습니다.
      const details = document.createElement('details');
      details.open = identityDetailsOpen;
      const visibleState = me?.status === 'loading' ? '불러오는 중'
        : me?.mode === 'disconnected' ? '연결 없음 (disconnected)'
        : me?.mode === 'demo' ? '예제 자료 (demo)'
        : me?.mode === 'connected' ? '연결 모드 (connected)'
        : me?.status === 'error' ? '연결 실패'
        : '확인 불가';
      const label = document.createElement('summary');
      label.textContent = '계정·기기·세션 상세 보기 · ' + visibleState;
      details.appendChild(label);
      details.addEventListener('toggle', () => { identityDetailsOpen = details.open; });
      root.appendChild(details);
      const text = (value) => typeof value === 'string' && value.trim() ? value : '확인 불가';
      const stateWithCode = (label, status) => `${label} (${text(status)})`;
      const deviceState = (status) => stateWithCode(({
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      })[status] || '확인 불가', status);
      const sessionState = (status) => stateWithCode(({
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      })[status] || '확인 불가', status);

      const add = (parent, tagName, content) => {
        const node = document.createElement(tagName);
        node.textContent = content;
        parent.appendChild(node);
        return node;
      };

      const section = (heading, resource, showData) => {
        const box = document.createElement('section');
        add(box, 'h3', heading);
        const mode = resource?.mode;
        if (mode === 'demo') add(box, 'p', '예제 자료');
        else if (mode === 'disconnected') add(box, 'p', '연결 없음');
        else if (mode === 'unknown') add(box, 'p', '확인 불가');

        if (resource?.status === 'loading') {
          add(box, 'p', '불러오는 중');
        } else if (resource?.status === 'error') {
          add(box, 'p', '연결 실패: ' + text(resource?.error?.message));
        } else if (resource?.status === 'ok') {
          showData(box, resource.data);
        } else {
          add(box, 'p', '확인 불가');
        }
        details.appendChild(box);
      };

      section('현재 계정·기기·세션', me, (box, data) => {
        const user = data?.user;
        const device = data?.device;
        const session = data?.session;
        add(box, 'p', '사용자: ' + text(user?.label) + ' (ID: ' + text(user?.id) + ')');
        add(box, 'p', '현재 기기: ' + text(device?.label) + ' (ID: ' + text(device?.id) + ') · 상태: ' + deviceState(device?.status));
        add(box, 'p', '현재 세션: ' + text(session?.id) + ' · 상태: ' + sessionState(session?.status));
      });

      section('기기 목록', devices, (box, data) => {
        if (!Array.isArray(data)) return add(box, 'p', '기기 정보 확인 불가');
        if (!data.length) return add(box, 'p', '표시할 기기가 없습니다.');
        const list = document.createElement('ul');
        for (const device of data) {
          add(list, 'li', text(device?.label) + ' (ID: ' + text(device?.id) + ') · 상태: ' + deviceState(device?.status));
        }
        box.appendChild(list);
      });

      section('세션 목록', sessions, (box, data) => {
        if (!Array.isArray(data)) return add(box, 'p', '세션 정보 확인 불가');
        if (!data.length) return add(box, 'p', '표시할 세션이 없습니다.');
        const list = document.createElement('ul');
        for (const session of data) {
          add(list, 'li', '세션 ID: ' + text(session?.id) + ' · 상태: ' + sessionState(session?.status));
        }
        box.appendChild(list);
      });

      // 관제 화면은 별도 전체 너비 학생 상태 영역에서 표시.
      return root;
    },
    renderDecision({ status, mode, data, error, appId } = {}) {
      // Only display the currently selected app's decision; the provided UI owns the request button.
      const root = document.createElement('section');
      const safeText = (value) =>
        typeof value === 'string' && value.trim() ? value : '확인 불가';
      const addText = (tagName, value) => {
        const node = document.createElement(tagName);
        node.textContent = value;
        root.appendChild(node);
      };

      const currentAppId = typeof appId === 'string' && appId.trim()
        ? appId
        : (status === 'ok' ? safeText(data?.appId) : '미선택');

      addText('h3', '업무 앱 접근 판정');
      if (mode === 'demo') addText('p', '예제 자료: 실제 접근 판정이 아닙니다.');
      else if (mode === 'disconnected') addText('p', '연결 없음');
      else if (mode === 'unknown') addText('p', '연결 상태 확인 불가');

      if (status === 'idle') {
        addText('p', '업무 앱을 선택한 뒤 접속 요청 버튼을 눌러주세요.');
        return root;
      }

      addText('p', '선택한 업무 앱 ID: ' + currentAppId);

      if (status === 'loading') {
        addText('p', '접근 판정 확인 중입니다. 아직 결과가 없습니다.');
        return root;
      }

      if (status === 'error') {
        addText('p', '접근 판정 요청 실패: ' + safeText(error?.message));
        addText('p', '요청 실패는 접근 허용(allow) 또는 접근 거부(deny) 판정이 아닙니다.');
        return root;
      }

      if (status !== 'ok') {
        addText('p', '판정 상태 확인 불가. 접근 허용으로 판단할 수 없습니다.');
        return root;
      }

      const labels = {
        allow: '접근 허용',
        deny: '접근 거부',
        challenge: '추가 인증 또는 확인 필요',
        unknown: '판정 확인 불가',
      };
      const rawDecision = data?.decision;
      const decision = typeof rawDecision === 'string'
        && Object.hasOwn(labels, rawDecision) ? rawDecision : 'unknown';

      addText('p', '접근 판정: ' + labels[decision] + ' (' + decision + ')');
      if (decision !== rawDecision && typeof rawDecision === 'string' && rawDecision.trim()) {
        addText('p', '인식되지 않은 서버 상태 코드: ' + rawDecision);
      }
      addText('p', '판정 이유: ' + safeText(data?.reason));
      addText('p', '판정 시각: ' + safeText(data?.checkedAt));

      if (decision === 'allow') {
        addText('p', '정책상 접근 허용이며 실제 업무 앱 접속 성공을 보장하지 않습니다.');
      } else if (decision === 'challenge') {
        addText('p', '추가 인증 또는 확인이 필요합니다. 이 보안 Agent가 인증 절차를 대신 수행하지 않습니다.');
      } else if (decision === 'unknown') {
        addText('p', '접근 허용 여부를 확인할 수 없습니다. 허용된 것으로 취급하지 않습니다.');
      }
      return root;
    },
    renderEvents({ status, mode, data, error } = {}) {
      const root = document.createElement('section');
      const add = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.appendChild(node);
        return node;
      };
      const readable = (value) =>
        typeof value === 'string' && value.trim() ? value : '확인 불가';
      const appKey = (event) =>
        typeof event?.appId === 'string' ? event.appId : '';

      add(root, 'h3', '내 접속 기록·XDR 경보');
      add(root, 'p', '서버에서 전달받은 본인 범위의 최근 접속 기록과 저장된 XDR 경보입니다. 전체 직원 이력이나 실시간 위협 탐지가 아닙니다.');
      if (mode === 'demo') add(root, 'p', '예제 자료: 실제 계정 기록이 아닙니다.');
      else if (mode === 'disconnected') add(root, 'p', '연결 없음');
      else if (mode === 'unknown') add(root, 'p', '연결 상태 확인 불가');

      if (status === 'loading') {
        add(root, 'p', '보안 기록을 불러오는 중입니다.');
        return root;
      }
      if (status === 'error') {
        const message = readable(error?.message);
        add(root, 'p', '기록을 불러오지 못했습니다: ' + message);
        if (error?.code === 'CONTRACT_MISMATCH' || error?.code === 'ENGINE_RESULT_UNVERIFIED') {
          add(root, 'p', '응답 형식 또는 원천 자료를 확인할 수 없습니다. 이전 기록을 표시하지 않습니다.');
        }
        return root;
      }
      if (status !== 'ok' || !Array.isArray(data)) {
        add(root, 'p', '기록을 불러오지 못했습니다: 자료를 확인할 수 없습니다.');
        return root;
      }
      if (data.length === 0) {
        add(root, 'p', '표시할 기록이 없습니다.');
        return root;
      }

      // Work only on a copy. Date.parse handles offsets as well as ISO timestamps.
      const timestamp = (event) => {
        const value = Date.parse(event?.at);
        return Number.isFinite(value) ? value : null;
      };
      const records = [...data].sort((a, b) => {
        const left = timestamp(a);
        const right = timestamp(b);
        if (left === null) return right === null ? 0 : 1;
        if (right === null) return -1;
        return right - left;
      });

      const names = {
        access: { allowed: '접근 허용', denied: '접근 거부', unknown: '확인 불가' },
        session: { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' },
        device: { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' },
      };
      const stateLabel = (group, raw) => {
        const valid = typeof raw === 'string' && Object.hasOwn(names[group], raw);
        const code = valid ? raw : 'unknown';
        const extra = !valid && typeof raw === 'string' && raw.trim()
          ? ' · 원본 코드: ' + raw : '';
        return names[group][code] + '(' + code + ')' + extra;
      };
      const kindLabel = (kind) => kind === 'access'
        ? '접속 기록(access)' : kind === 'xdr'
          ? 'XDR 경보(xdr)' : '확인 불가(' + readable(kind) + ')';

      const filters = document.createElement('div');
      root.appendChild(filters);
      const filterSelect = (title, values, describe) => {
        const label = document.createElement('label');
        label.textContent = title;
        const select = document.createElement('select');
        select.setAttribute('aria-label', title);
        const all = document.createElement('option');
        all.value = 'all';
        all.textContent = '전체';
        select.appendChild(all);
        for (const value of [...new Set(values)]) {
          const option = document.createElement('option');
          option.value = value;
          option.textContent = describe(value);
          select.appendChild(option);
        }
        label.appendChild(select);
        filters.appendChild(label);
        return select;
      };

      const kindFilter = filterSelect('기록 종류', records.map(event => event.kind), kindLabel);
      const appFilter = filterSelect('업무 앱', records.map(appKey),
        value => value ? value : '앱 확인 불가');
      const accessFilter = filterSelect('접속 상태',
        records.map(event => event.state?.access ?? 'unknown'),
        value => stateLabel('access', value));

      const count = add(root, 'p', '');
      const list = document.createElement('ul');
      root.appendChild(list);

      const addReferences = (parent, heading, references) => {
        add(parent, 'h4', heading);
        if (!Array.isArray(references) || references.length === 0) {
          add(parent, 'p', '없음');
          return;
        }
        const entries = document.createElement('ul');
        for (const item of references) {
          add(entries, 'li', 'ID: ' + readable(item?.id) + ' · 내용: ' + readable(item?.text));
        }
        parent.appendChild(entries);
      };

      const showDetail = (event) => {
        const detail = document.createElement('section');
        detail.setAttribute('data-student-event-detail', readable(event?.id));
        add(detail, 'h4', '기록 상세: ' + readable(event?.id));
        add(detail, 'p', '사건 ID: ' + readable(event?.id));
        add(detail, 'p', '업무 앱 ID: ' + (appKey(event) || '앱 확인 불가'));
        add(detail, 'p', '발생 시각: ' + readable(event?.at));
        addReferences(detail, '근거(evidence)', event?.evidence);
        addReferences(detail, '규칙(rules)', event?.rules);
        add(detail, 'h4', '사건 당시 상태');
        add(detail, 'p', '접속 상태: ' + stateLabel('access', event?.state?.access));
        add(detail, 'p', '세션 상태: ' + stateLabel('session', event?.state?.session));
        add(detail, 'p', '기기 상태: ' + stateLabel('device', event?.state?.device));
        // A supplied action is only a disabled notice: never send execution requests.
        if (Array.isArray(event?.supportedActions) && event.supportedActions.length > 0) {
          add(detail, 'p', '아직 지원하지 않는 조치입니다. 조치 실행 연결은 준비 중이며 어떤 조치도 실행하지 않습니다.');
          for (const action of event.supportedActions) {
            const unavailable = document.createElement('button');
            unavailable.type = 'button';
            unavailable.disabled = true;
            unavailable.setAttribute('aria-disabled', 'true');
            unavailable.textContent = readable(action) + ' 미지원';
            detail.appendChild(unavailable);
          }
        }
        return detail;
      };

      const draw = () => {
        // Filter only the provided array, with no new server request.
        const visible = records.filter(event =>
          (kindFilter.value === 'all' || event.kind === kindFilter.value) &&
          (appFilter.value === 'all' || appKey(event) === appFilter.value) &&
          (accessFilter.value === 'all' || (event.state?.access ?? 'unknown') === accessFilter.value));
        count.textContent = '표시 중인 본인 기록: ' + visible.length + '건 / 전달받은 ' + records.length + '건';
        list.replaceChildren(); // Also removes any expanded details on filter changes.
        if (visible.length === 0) {
          add(list, 'li', '선택한 조건에 맞는 기록이 없습니다.');
          return;
        }
        for (const event of visible) {
          const row = document.createElement('li');
          row.setAttribute('data-student-event-id', readable(event?.id));
          add(row, 'p', '사건 ID: ' + readable(event?.id));
          add(row, 'p', '시각: ' + readable(event?.at));
          add(row, 'p', '종류: ' + kindLabel(event?.kind));
          add(row, 'p', '업무 앱 ID: ' + (appKey(event) || '앱 확인 불가'));
          add(row, 'p', '요약: ' + readable(event?.summary));
          const button = document.createElement('button');
          button.type = 'button';
          button.textContent = readable(event?.id) + ' 상세';
          button.setAttribute('aria-expanded', 'false');
          let expanded = null;
          button.addEventListener('click', () => {
            if (expanded) {
              expanded.remove();
              expanded = null;
              button.setAttribute('aria-expanded', 'false');
            } else {
              expanded = showDetail(event);
              row.appendChild(expanded);
              button.setAttribute('aria-expanded', 'true');
            }
          });
          row.appendChild(button);
          list.appendChild(row);
        }
      };
      kindFilter.addEventListener('change', draw);
      appFilter.addEventListener('change', draw);
      accessFilter.addEventListener('change', draw);
      draw();
      return root;
    },
    renderStatus({ devices, sessions, notifications, diagnostics, mode } = {}) {
      const root = document.createElement('section');
      const add = (parent, tagName, content) => {
        const element = document.createElement(tagName);
        element.textContent = content;
        parent.appendChild(element);
        return element;
      };
      const safeText = (value) =>
        typeof value === 'string' && value.trim() ? value : '확인 불가';
      const statusText = (raw, labels) => {
        const recognized = typeof raw === 'string' && Object.hasOwn(labels, raw);
        const code = recognized ? raw : 'unknown';
        return labels[code] + ' (' + code + ')';
      };
      const devicesLabels = {
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      };
      const sessionsLabels = {
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      };
      const retryText = '재조회하려면 위쪽 「다시 불러오기」 버튼을 직접 누르세요. 자동 재요청하지 않습니다.';
      const modeText = {
        connected: '연결됨',
        demo: '예제 자료 · 실제 연결이 아닙니다',
        disconnected: '연결 없음',
        unknown: '연결 상태 확인 불가',
      };

      add(root, 'h3', '기기·세션·알림·도움정보');
      if (typeof mode === 'string' && Object.hasOwn(modeText, mode)) {
        add(root, 'p', '전체 연결 모드: ' + modeText[mode] + ' (' + mode + ')');
      }
      add(root, 'p', '기기는 현재 사용자에게 등록된 최대 100대까지 확인합니다. 세션은 현재 검증된 연결 1개만 조회하며 과거 세션 전체 목록이 아닙니다.');

      const resourceMode = (parent, resource) => {
        if (typeof resource?.mode === 'string' && Object.hasOwn(modeText, resource.mode)) {
          add(parent, 'p', '자료 모드: ' + modeText[resource.mode] + ' (' + resource.mode + ')');
        }
      };
      const errorLine = (parent, source, resource) => {
        const error = resource?.error;
        const code = safeText(error?.code);
        add(parent, 'p', source + ' 불러오기 실패: ' + safeText(error?.message) + ' · 오류 코드: ' + code);
        if (/TIMEOUT|TIMED_OUT/i.test(code) || /시간 초과|시간이 초과/.test(safeText(error?.message))) {
          add(parent, 'p', source + ' 조회 시간이 초과됐습니다.');
        }
        add(parent, 'p', retryText);
      };

      const renderList = (name, resource, labels, isDevice) => {
        const block = document.createElement('section');
        add(block, 'h4', name);
        resourceMode(block, resource);
        if (resource?.status === 'loading') {
          add(block, 'p', name + ' 정보를 불러오는 중입니다.');
        } else if (resource?.status === 'error') {
          errorLine(block, name, resource);
        } else if (resource?.status === 'ok') {
          if (!Array.isArray(resource.data)) {
            add(block, 'p', name + ' 자료를 확인할 수 없습니다.');
            add(block, 'p', retryText);
          } else if (resource.data.length === 0) {
            add(block, 'p', isDevice ? '등록된 기기가 없습니다.' : '현재 연결이 없습니다.');
          } else {
            const list = document.createElement('ul');
            for (const item of resource.data) {
              const label = isDevice ? safeText(item?.label) + ' (ID: ' + safeText(item?.id) + ')' : '세션 ID: ' + safeText(item?.id);
              add(list, 'li', label + ' · 상태: ' + statusText(item?.status, labels));
            }
            block.appendChild(list);
          }
        } else {
          add(block, 'p', name + ' 정보는 아직 조회되지 않았습니다.');
        }
        root.appendChild(block);
      };

      renderList('등록 기기', devices, devicesLabels, true);
      renderList('현재 세션', sessions, sessionsLabels, false);

      const alerts = document.createElement('section');
      add(alerts, 'h4', '보안 알림');
      if (Array.isArray(notifications) && notifications.length > 0) {
        const list = document.createElement('ul');
        for (const notice of notifications) {
          add(list, 'li', '자료(resource): ' + safeText(notice?.resource)
            + ' · 코드(code): ' + safeText(notice?.code)
            + ' · 메시지: ' + safeText(notice?.message));
        }
        alerts.appendChild(list);
      } else if (Array.isArray(notifications)) {
        add(alerts, 'p', '주의할 알림이 없습니다.');
      } else {
        add(alerts, 'p', '알림 목록을 확인할 수 없습니다.');
      }
      root.appendChild(alerts);

      const support = document.createElement('section');
      add(support, 'h4', '도움정보');
      resourceMode(support, diagnostics);
      add(support, 'p', '도움 요청에 필요한 비밀 없는 진단 항목만 표시합니다. 복사는 사용자가 아래 버튼을 눌렀을 때만 실행됩니다.');
      const safeDiagnosticValue = (value) => {
        if (typeof value !== 'string' || !value.trim() || value.length > 160
          || /(?:bearer\s+|sk-[A-Za-z0-9_-]{12,}|(?:token|secret|password|api.?key|private.?key)\s*[:=])/i.test(value)) {
          return '확인 불가';
        }
        return value;
      };
      let copyText = null;
      if (diagnostics?.status === 'loading') {
        add(support, 'p', '도움정보를 불러오는 중입니다.');
      } else if (diagnostics?.status === 'error') {
        errorLine(support, '도움정보', diagnostics);
        add(support, 'p', '진단 정보를 다시 조회하려면 제공 화면의 「도움정보 불러오기」 버튼을 직접 누르세요.');
      } else if (diagnostics?.status === 'ok') {
        const data = diagnostics.data;
        if (!data || typeof data !== 'object' || Array.isArray(data)) {
          add(support, 'p', '진단 정보 형식을 확인할 수 없습니다.');
        } else {
          // Explicit allowlist: never copy other server fields, credentials, AI data or configuration.
          const approved = {
            requestId: safeDiagnosticValue(data.requestId),
            component: safeDiagnosticValue(data.component),
            version: safeDiagnosticValue(data.version),
            checkedAt: safeDiagnosticValue(data.checkedAt),
            engine: {
              mode: safeDiagnosticValue(data.engine?.mode),
              code: safeDiagnosticValue(data.engine?.code),
            },
          };
          add(support, 'p', 'requestId: ' + approved.requestId);
          add(support, 'p', 'component: ' + approved.component);
          add(support, 'p', 'version: ' + approved.version);
          add(support, 'p', 'checkedAt: ' + approved.checkedAt);
          add(support, 'p', 'engine.mode: ' + approved.engine.mode);
          add(support, 'p', 'engine.code: ' + approved.engine.code);
          copyText = JSON.stringify(approved, null, 2);
          add(support, 'pre', copyText);
        }
      } else {
        add(support, 'p', '도움정보를 아직 조회하지 않았습니다. 제공 화면의 「도움정보 불러오기」 버튼을 직접 누르세요.');
      }

      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = '도움정보 복사';
      button.setAttribute('aria-label', '도움정보 복사');
      button.disabled = copyText === null;
      support.appendChild(button);
      const copyResult = add(support, 'p', '');
      if (copyText !== null) {
        button.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(copyText);
            copyResult.textContent = '도움정보를 복사했습니다. 복사 내용에 비밀번호·토큰·API 키가 없는지 확인한 후 공유하세요.';
          } catch {
            copyResult.textContent = '자동 복사를 사용할 수 없습니다. 위에 표시된 안전한 도움정보만 선택해 Ctrl+C로 직접 복사하세요.';
          }
        });
      }
      root.appendChild(support);
      // 제공 UI를 건드리지 않고 전체 너비 학생 영역에서 관제를 우선 표시.
      renderPcDashboard(root, { mode });
      return root;
    },
    renderVulnerabilities({ status = 'idle', mode, data, error } = {}) {
      // The UI is rebuilt for every supplied snapshot; never retain stale package rows.
      const root = document.createElement('section');
      const add = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.appendChild(node);
        return node;
      };
      const safeMessage = (value) => typeof value === 'string' && value.trim()
        && value.length <= 500 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)
        && !/(?:bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|(?:api[_ -]?key|authorization|token|password|secret|private[_ -]?key|비밀번호|토큰)\s*[:=]\s*\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i.test(value)
        ? value : '안전한 오류 메시지를 확인할 수 없습니다.';
      const safeCode = (value) => typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(value) ? value : null;
      const validTime = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null;
      const exactVersion = (value) => typeof value === 'string'
        && /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/.test(value);
      const scanLabels = {
        complete: '모두 조회(complete) · 승인된 공개 패키지 조회 완료',
        partial: '일부 조회 실패(partial) · 확인된 결과만 유지하며 실패 항목도 표시',
        not_checked: '아직 조회 안 함(not_checked) · 승인된 공개 조회 대상 패키지가 없어 OSV 조회를 수행하지 않음',
        not_configured: '조회 준비 미완료(not_configured) · 조회 대상 프로젝트 설정 필요',
        unverifiable: 'lock 파일 확인 불가(unverifiable) · package-lock.json 및 설치 목록을 검증할 수 없음',
      };
      const rowLabels = {
        known_vulnerabilities: '알려진 취약점 있음(known_vulnerabilities)',
        none_found: '조회한 범위에서 알려진 취약점 없음(none_found) · 패키지나 앱 전체의 안전을 보장하지 않음',
        unverifiable: '조회 확인 불가(unverifiable) · 취약점 없음으로 판단 금지',
      };
      add(root, 'h3', '설치 패키지와 OSV 취약점 조회');
      if (mode === 'demo') add(root, 'p', '예제 데이터(demo) · 실제 설치 상태 확인 아님');
      if (status === 'idle') {
        add(root, 'p', '설치 패키지 조회 전(idle) · 아직 확인된 결과가 없습니다.');
        add(root, 'p', '조회 전은 취약점 없음이 아닙니다. 제공 화면에서 설치 패키지 조회를 선택하세요.');
        return root;
      }
      if (status === 'loading') {
        add(root, 'p', '설치 패키지 조회 중(loading) · 현재 요청의 결과를 확인하는 중입니다.');
        add(root, 'p', '이전 조회 표를 현재 결과로 표시하지 않습니다. 취소·새 요청의 이전 응답은 제공 화면에서 배제됩니다.');
        return root;
      }
      if (status === 'error') {
        add(root, 'p', '설치 패키지 조회 실패(error) · 현재 조회는 완료되지 않았습니다.');
        const code = safeCode(error?.code);
        if (code) add(root, 'p', '오류 코드: ' + code);
        add(root, 'p', '조회 실패: ' + safeMessage(error?.message));
        if (code === 'CANCELLED' || code === 'REQUEST_CANCELLED') {
          add(root, 'p', '조회가 취소됐습니다. 뒤늦은 응답을 현재 결과로 표시하지 않습니다.');
        }
        add(root, 'p', '조회 실패는 취약점 없음이나 정상 상태가 아닙니다. 필요하면 제공 화면에서 직접 다시 조회하세요.');
        return root;
      }
      if (status !== 'ok' || !data || !Object.hasOwn(scanLabels, data.status)) {
        add(root, 'p', '조회 결과 확인 불가 · 응답 형식이나 상태를 확인할 수 없습니다.');
        return root;
      }

      add(root, 'p', '전체 조회 상태: ' + scanLabels[data.status]);
      if (safeCode(data.code)) add(root, 'p', '조회 상태 코드: ' + data.code);
      if (data.lockfileVersion !== undefined && data.lockfileVersion !== null) {
        add(root, 'p', '대조 원천: package-lock.json 및 node_modules 설치 메타데이터 · lockfileVersion: ' + String(data.lockfileVersion));
      }
      if (typeof data.lockfileHash === 'string' && data.lockfileHash) {
        add(root, 'p', 'lockfileHash: ' + data.lockfileHash);
        add(root, 'p', '패키지가 변경되면 다시 조회한 최신 lockfileHash와 결과를 확인하세요.');
      }
      if (validTime(data.checkedAt)) add(root, 'p', '전체 조회 시각(checkedAt): ' + data.checkedAt);
      if (Number.isSafeInteger(data.excluded?.count)) add(root, 'p', '조회 제외: ' + data.excluded.count + '건 · 제외 항목의 취약점 유무는 확인하지 않았습니다.');
      add(root, 'p', '각 패키지의 버전은 제공 서버가 설치 상태를 대조해 전달한 정확한 설치 버전입니다. ^1.2.0 같은 의존성 범위를 설치 버전으로 바꾸지 않습니다.');
      add(root, 'p', 'OSV는 알려진 취약점 데이터베이스입니다. 항목이 없거나 조회하지 못한 결과를 패키지·앱 전체의 안전으로 해석하지 않습니다.');

      if (['not_configured', 'not_checked', 'unverifiable'].includes(data.status)) {
        add(root, 'p', '설정 부족·승인 대상 없음·잠금 파일 확인 실패는 미조회 상태이며 취약점 없음이 아닙니다.');
        return root;
      }
      if (!Array.isArray(data.packages)) {
        add(root, 'p', '패키지 조회 데이터 확인 불가 · 결과를 정상 목록으로 표시하지 않습니다.');
        return root;
      }
      if (data.packages.length === 0) {
        add(root, 'p', data.status === 'partial'
          ? '일부 조회 실패(partial) · 확인된 패키지가 없으며, 취약점이 없다는 뜻은 아닙니다.'
          : '조회 결과에 표시할 패키지가 없습니다. 패키지나 앱 전체가 안전하다는 뜻은 아닙니다.');
        return root;
      }
      add(root, 'h4', '설치된 정확한 버전별 OSV 조회 결과');
      const table = document.createElement('table');
      const thead = document.createElement('thead');
      const head = document.createElement('tr');
      for (const heading of ['패키지', '정확한 설치 버전', '조회 상태', 'OSV 출처', '패키지 조회 시각', '취약점 ID 및 수정 시각']) {
        add(head, 'th', heading);
      }
      thead.appendChild(head);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');
      for (const pkg of data.packages) {
        const name = typeof pkg?.name === 'string' && pkg.name ? pkg.name : null;
        const version = exactVersion(pkg?.version) ? pkg.version : null;
        const row = document.createElement('tr');
        if (name && version) {
          row.setAttribute('data-student-package-name', name);
          row.setAttribute('data-student-package-version', version);
        }
        add(row, 'td', name || '패키지 이름 확인 불가');
        add(row, 'td', version || '정확한 설치 버전 확인 불가 · 범위값을 설치 버전으로 사용하지 않음');
        const findings = Array.isArray(pkg?.vulnerabilities) ? pkg.vulnerabilities : [];
        const label = pkg?.status === 'unverifiable' && findings.length > 0
          ? '일부 확인·전체 조회 확인 불가(unverifiable) · 이미 확인한 취약점 ID는 유지'
          : (Object.hasOwn(rowLabels, pkg?.status) ? rowLabels[pkg.status] : '패키지 조회 상태 확인 불가');
        add(row, 'td', label);
        add(row, 'td', typeof pkg?.source === 'string' && pkg.source ? pkg.source : '출처 확인 불가');
        add(row, 'td', validTime(pkg?.checkedAt) || '확인 시각 없음');
        const vulnerabilities = document.createElement('td');
        if (findings.length > 0) {
          const ul = document.createElement('ul');
          for (const item of findings) {
            const id = typeof item?.id === 'string' && item.id ? item.id : '취약점 ID 확인 불가';
            add(ul, 'li', '취약점 ID: ' + id + ' · modified: ' + (validTime(item?.modified) || '수정 시각 확인 불가'));
          }
          vulnerabilities.appendChild(ul);
        } else {
          add(vulnerabilities, 'span', pkg?.status === 'none_found'
            ? '조회된 범위에서 알려진 항목 없음'
            : '취약점 조회 결과 확인 불가 · 항목이 없다고 단정할 수 없음');
        }
        row.appendChild(vulnerabilities);
        tbody.appendChild(row);
      }
      table.appendChild(tbody);
      root.appendChild(table);
      if (data.status === 'partial') add(root, 'p', '부분 조회 결과: 이미 확인한 취약점 ID는 유지하고, 조회에 실패한 패키지는 확인 불가로 남깁니다.');
      add(root, 'p', '조회·취소는 제공 화면에서만 수행합니다. 학생 코드는 패키지·설정·API 요청을 변경하지 않습니다.');
      return root;
    },
    renderAiConnection({ status, mode, data, error, checkedAt, explanationAccepted } = {}) {
      const root = document.createElement('section');
      const line = (tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        root.appendChild(node);
        return node;
      };
      // Input errors are already normalized by the provided UI. Still suppress credentials
      // and unbounded/raw provider details before rendering them.
      const safeCode = (value) => typeof value === 'string'
        && /^[A-Z][A-Z0-9_]{1,79}$/.test(value) ? value : 'AI_REQUEST_UNVERIFIED';
      const safeMessage = (value) => typeof value === 'string' && value.length > 0
        && value.length <= 500
        && !/(?:bearer\s+\S+|sk-[A-Za-z0-9_-]{12,}|(?:api[_ -]?key|token|password|secret|private[_ -]?key)\s*[:=]\s*\S+|eyJ[A-Za-z0-9_-]{20,})/i.test(value)
        ? value : 'AI 연결 또는 응답을 안전하게 확인할 수 없습니다.';
      const modes = {
        demo: '예제 데이터(demo) · 실제 AI 연결 아님',
        disconnected: '연결 없음(disconnected)',
        unknown: '연결 상태 확인 불가(unknown)',
        connected: '연결됨(connected)',
      };
      line('h3', '알레프게이트 AI 연결 상태');
      if (typeof mode === 'string' && Object.hasOwn(modes, mode)) {
        line('p', '연결 모드: ' + modes[mode]);
      }

      if (status === 'idle') {
        line('p', 'AI 연결 점검 전입니다. 이전 점검 결과는 현재 결과가 아닙니다.');
        line('p', '보호 현황의 계정 연결과 앱 권한을 확인한 다음, 사용자가 「현재 API 연결 점검」을 직접 눌러주세요.');
        return root;
      }
      if (status === 'loading') {
        line('p', '현재 로그인과 앱 권한으로 AI 모델 응답을 점검하는 중입니다.');
        line('p', '아직 점검 결과나 사건 설명 결과가 없습니다. 필요하면 제공 화면의 「취소」를 직접 누르세요.');
        return root;
      }
      if (status === 'error') {
        const code = safeCode(error?.code);
        line('p', 'AI 연결 점검 실패 · 오류 코드: ' + code);
        line('p', '오류 메시지: ' + safeMessage(error?.message));
        const guidance = {
          ON_AI_PROVISIONING_PENDING: '운영 측 학생 앱 계정·이용 권한 준비 중입니다. 담당자에게 연결 및 앱 권한을 확인받으세요.',
          SUBJECT_SCOPE_UNVERIFIED: '현재 로그인·프로젝트·사건 범위를 확인할 수 없습니다. 담당자에게 계정 연결을 확인받으세요.',
          WB_CLCO_AUTH_REQUIRED: '인증 실패: 계정 및 앱 전용 연결을 다시 확인하고 담당자에게 문의하세요. Workbench 열쇠를 복사하지 마세요.',
          WB_CLCO_ACCESS_BLOCKED: '접근 제한: 학생 앱 이용 권한을 담당자에게 확인받으세요.',
          ON_AI_AUTHORIZATION_CHANGED: '앱 권한이 점검 도중 변경됐습니다. 담당자에게 현재 권한을 확인받으세요.',
          WB_CLCO_COHORT_BUDGET_EXHAUSTED: '반의 AI 사용량이 소진됐습니다. 담당자에게 확인받으세요.',
          WB_CLCO_LIMIT_REACHED: 'AI 이용 한도에 도달했습니다. 담당자에게 확인받으세요.',
          WB_CLCO_SESSION_CLOSED: '현재 AI 이용 시간이 아닙니다. 이용 가능 시간을 확인하세요.',
          WB_CLCO_RATE_LIMITED: '요청 제한 중입니다. 잠시 뒤 사용자가 직접 다시 점검하세요.',
          WB_CLCO_TIMEOUT: 'AI 연결 점검 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.',
          REQUEST_TIMEOUT: 'AI 연결 요청 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.',
          ENGINE_TIMEOUT: '원천 확인 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.',
          TIMEOUT: 'AI 연결 응답 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.',
          WB_CLCO_CANCELLED: '요청이 취소됐습니다. 이전 응답은 현재 결과가 아닙니다.',
          CANCELLED: '요청이 취소됐습니다. 이전 응답은 현재 결과가 아닙니다.',
          REQUEST_CANCELLED: '요청이 취소됐습니다. 이전 응답은 현재 결과가 아닙니다.',
          NETWORK_ERROR: '네트워크 연결을 확인한 뒤 사용자가 직접 다시 점검하세요.',
          SERVICE_UNAVAILABLE: 'AI 연결 서버 이용이 어렵습니다. 네트워크 상태를 확인하고 담당자에게 문의하세요.',
          MODEL_NOT_CONFIGURED: '서버에서 이용할 AI 모델이 설정되지 않았습니다. 담당자에게 모델 설정을 확인받으세요.',
          ON_AI_MODEL_LIST_EMPTY: '현재 앱에서 사용할 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정을 확인받으세요.',
          ON_AI_INVALID_INPUT: '사건 입력 자료를 검증할 수 없습니다. 기존 보안 기록을 확인하세요.',
          ON_AI_INVALID_OUTPUT: 'AI 응답 형식과 근거를 검증할 수 없습니다. 기존 보안 기록을 확인하세요.',
          AI_REQUEST_UNVERIFIED: 'AI 연결·이용 권한 또는 응답을 확인할 수 없습니다. 담당자에게 확인받으세요.',
        };
        line('p', '확인 및 복구 방법: ' + (guidance[code] ||
          '연결 또는 권한 상태를 확인할 수 없습니다. 담당자에게 확인받고 직접 다시 점검하세요.'));
        line('p', '점검 실패는 접근 성공이나 사건 설명 성공이 아닙니다. 자동 재시도하지 않습니다.');
        return root;
      }

      if (status !== 'ok') {
        line('p', 'AI 연결 상태를 확인할 수 없습니다. 점검에 성공한 것으로 표시하지 않습니다.');
        return root;
      }

      if (data?.transportChecked !== true || !Number.isInteger(data?.modelCount)
        || data.modelCount < 0 || !['test', 'verified'].includes(data?.audienceAuthorization)
        || typeof checkedAt !== 'string' || !Number.isFinite(Date.parse(checkedAt))) {
        line('p', 'AI 점검 응답을 검증할 수 없습니다. 정상 연결로 간주하지 않습니다.');
        return root;
      }

      if (data.audienceAuthorization === 'test') {
        line('p', 'AI 연결 상태: 시험 연결 점검(test) · 실제 게이트 앱 권한 확인 아님');
      } else {
        line('p', 'AI 연결 상태: 앱 권한 확인 후 점검(verified) · 해당 시각 기준의 모델 응답 확인');
      }
      line('p', '모델 응답 점검: 수행됨 (transportChecked: true)');
      line('p', '응답 모델 수(modelCount): ' + String(data.modelCount));
      line('p', '점검 시각(checkedAt): ' + checkedAt);
      if (data.modelCount === 0) {
        line('p', '사용 가능한 모델이 0개입니다. 담당자에게 모델 허용 상태를 확인받으세요.');
      }
      line('p', '모델 연결 점검만 수행했습니다. 사건 설명은 아직 실행하지 않았습니다.');
      line('p', '실제 사건 설명은 보안 기록에서 사건 하나를 선택해 별도로 요청·검증해야 합니다.');
      if (explanationAccepted === true) {
        // A check response never proves an explanation; use the separate explanation resource.
        line('p', '사건 설명 수용 여부는 이 점검 결과로 확정하지 않습니다.');
      }
      return root;
    },
    renderExplanation({ event, explanation, checkedAt } = {}) {
      // Each render returns a fresh tree: old explanations and success markers are not reused.
      const root = document.createElement('section');
      const line = (tag, value) => {
        const element = document.createElement(tag);
        element.textContent = value;
        root.appendChild(element);
        return element;
      };
      const lines = (heading, values) => {
        line('h4', heading);
        const list = document.createElement('ul');
        for (const value of values) {
          const item = document.createElement('li');
          item.textContent = value;
          list.appendChild(item);
        }
        root.appendChild(list);
      };
      const safeCode = (value) => typeof value === 'string'
        && /^[A-Z][A-Z0-9_]{1,79}$/.test(value) ? value : 'AI_REQUEST_UNVERIFIED';
      const safeMessage = (value) => typeof value === 'string' && value.length > 0
        && value.length <= 500
        && !/(?:bearer\s+\S+|sk-[A-Za-z0-9_-]{12,}|(?:api[_ -]?key|token|password|secret|private[_ -]?key)\s*[:=]\s*\S+|eyJ[A-Za-z0-9_-]{20,})/i.test(value)
        ? value : 'AI 사건 설명 응답을 안전하게 확인할 수 없습니다.';
      const state = explanation?.status;
      const eventId = typeof event?.id === 'string' && event.id.trim() ? event.id : null;
      line('h3', '선택한 보안 사건의 AI 설명');

      // A failure must be visible even when the provider could not select an event.
      if (state === 'error') {
        const code = safeCode(explanation?.error?.code);
        line('p', 'AI 설명 실패 · 오류 코드: ' + code);
        line('p', '오류 메시지: ' + safeMessage(explanation?.error?.message));
        if (code === 'ON_AI_INVALID_INPUT') {
          line('p', '근거 부족 또는 입력 오류: 설명에 필요한 사건 근거·규칙을 확인할 수 없어 설명할 수 없습니다.');
        } else if (code === 'ON_AI_INVALID_OUTPUT') {
          line('p', 'AI 설명을 사용할 수 없습니다. 근거 ID 누락·불일치, 지원하지 않는 조치, 비밀값 포함 또는 실행 완료 주장 등은 검증 실패 사유입니다.');
          line('p', 'AI가 이미 실행했다고 답한 설명은 사용할 수 없습니다. 실행 여부를 성공으로 간주하지 않습니다.');
        }
        if (eventId) line('p', '요청했던 사건 ID: ' + eventId);
        line('p', '보안 기록은 그대로 유지됩니다. AI 설명 실패는 과제 실패나 보안 조치 실행을 뜻하지 않습니다.');
        line('p', '실패·취소·시간 초과 후 이전 설명은 현재 결과가 아닙니다. 자동 재요청은 하지 않습니다.');
        return root;
      }
      if (!eventId) {
        line('p', '보안 기록에서 기록을 먼저 고르세요. 선택한 사건이 없어 AI 설명을 표시할 수 없습니다.');
        return root;
      }
      if (state === 'loading') {
        line('p', '설명 요청 중 · 아직 확인된 AI 설명은 없습니다.');
        line('p', '요청한 사건 ID: ' + eventId);
        return root;
      }
      if (!explanation || state === 'idle') {
        line('p', 'AI 사건 설명 요청 전입니다. 보안 기록에서 선택한 사건의 설명을 직접 요청하세요.');
        return root;
      }
      if (state !== 'ok') {
        line('p', 'AI 설명 상태를 확인할 수 없습니다. 보안 기록은 그대로 유지됩니다.');
        return root;
      }

      const data = explanation.data;
      const evidence = Array.isArray(event.evidence) ? event.evidence : [];
      const rules = Array.isArray(event.rules) ? event.rules : [];
      const supportedActions = Array.isArray(event.supportedActions) ? event.supportedActions : [];
      const evidenceIds = Array.isArray(data?.evidenceIds) ? data.evidenceIds : [];
      const proposals = Array.isArray(data?.proposals) ? data.proposals : null;
      const evidenceById = new Map(evidence.map((item) => [item?.id, item?.text]));
      const evidenceMatches = evidence.length > 0 && evidenceIds.length === evidence.length
        && new Set(evidenceIds).size === evidenceIds.length
        && new Set(evidence.map((item) => item?.id)).size === evidence.length
        && evidence.every((item) => typeof item?.id === 'string' && typeof item?.text === 'string' && item.text.trim())
        && evidenceIds.every((id) => typeof id === 'string' && evidenceById.has(id));
      const rulesPresent = rules.length > 0
        && rules.every((rule) => typeof rule?.id === 'string' && typeof rule?.text === 'string' && rule.text.trim());
      const validSummary = typeof data?.summary === 'string' && data.summary.trim().length > 0;
      const proposalsValid = proposals !== null && proposals.every((proposal) =>
        typeof proposal?.action === 'string' && supportedActions.includes(proposal.action)
        && typeof proposal.reason === 'string' && proposal.reason.trim()
        && Array.isArray(proposal.evidenceIds) && proposal.evidenceIds.length > 0
        && new Set(proposal.evidenceIds).size === proposal.evidenceIds.length
        && proposal.evidenceIds.every((id) => evidenceById.has(id)));
      const notExecuted = data?.executed === false && data?.requiresHumanConfirmation === true;

      // The upstream validator also checks this contract; reject malformed snapshots defensively.
      if (!validSummary || !evidenceMatches || !rulesPresent || !proposalsValid || !notExecuted) {
        line('p', 'AI 설명을 사용할 수 없습니다. 선택한 사건의 근거·규칙·응답 검증에 실패했습니다.');
        if (evidence.length === 0 || rules.length === 0) {
          line('p', '근거 부족 또는 입력 오류: 사건 근거·규칙이 없어 설명할 수 없습니다.');
        }
        if (!evidenceMatches) {
          line('p', '근거 불일치: AI가 인용한 근거 ID가 현재 사건의 근거 ID와 일치하지 않거나 누락·중복되었습니다. 없는 근거를 만들지 않습니다.');
        }
        if (data?.executed === true) {
          line('p', 'AI가 이미 실행했다고 답한 설명은 사용할 수 없습니다. 조치 실행 사실을 확인하지 않았습니다.');
        }
        if (!proposalsValid) {
          line('p', '지원하지 않는 조치나 잘못된 제안 근거는 사용할 수 없습니다.');
        }
        if (explanation?.error?.code) line('p', '오류 코드: ' + safeCode(explanation.error.code));
        line('p', '보안 기록은 그대로이며 보안 조치는 실행되지 않았습니다.');
        return root;
      }

      // Mark success only after matching every cited ID and rejecting invalid proposals.
      root.setAttribute('data-student-explanation-event', eventId);
      line('h4', 'AI 설명(참고용)');
      line('p', '사건 ID: ' + eventId);
      line('p', 'AI 설명 요약: ' + data.summary);
      if (typeof checkedAt === 'string' && Number.isFinite(Date.parse(checkedAt))) {
        line('p', '설명 응답 확인 시각: ' + checkedAt);
      }
      line('p', 'AI 설명은 참고용 해석입니다. 사실 판단은 사건 근거와 연동 시스템이 알려 준 현재 상태를 기준으로 합니다.');

      lines('인용한 근거 ID 및 근거 글', evidenceIds.map((id) => id + ' — ' + evidenceById.get(id)));
      lines('적용 규칙 ID 및 규칙 글', rules.map((rule) => rule.id + ' — ' + rule.text));

      line('h4', '현재 상태(원천 기록)');
      const stateItems = [
        ['access', '접속'], ['session', '세션'], ['device', '기기'],
      ];
      const unknownItems = [];
      for (const [key, label] of stateItems) {
        const value = event.state?.[key];
        if (value === 'unknown') {
          line('p', label + ': 확인 불가(unknown)');
          unknownItems.push(label + ': 확인 불가(unknown)');
        } else {
          line('p', label + ': ' + (typeof value === 'string' && value ? value : '확인 불가(값 없음)'));
        }
      }
      line('p', '확인 불가 상태: ' + (unknownItems.length > 0 ? unknownItems.join(', ') : '없음'));

      line('h4', '조치 제안');
      if (proposals.length === 0) {
        line('p', supportedActions.length === 0
          ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).'
          : 'AI가 이 사건에 제안한 조치가 없습니다. 근거를 확인하고 담당자가 판단하세요.');
      } else {
        lines('AI 조치 제안(미실행)', proposals.map((proposal) =>
          proposal.action + ' — 이유: ' + proposal.reason
          + ' · 근거 ID: ' + proposal.evidenceIds.join(', ')
          + ' · 사람 확인이 필요하며 아직 실행되지 않았습니다.'));
      }
      line('p', 'AI 제안은 실행 명령이 아닙니다. 사람 확인이 필요하며 어떤 보안 조치도 실행되지 않았습니다(executed:false).');
      return root;
    },
    renderAction({ status = 'idle', event, actionId, target, receipt, observation, message, confirmationExpiresAt, error } = {}) {
      // Each snapshot is rendered into a new tree. Do not keep old actions, requests, or results.
      const root = document.createElement('section');
      const line = (tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        root.appendChild(node);
        return node;
      };
      const safeId = (value) => typeof value === 'string' && value.trim().length > 0
        && value.length <= 128 && !/[\x00-\x1f]/.test(value)
        && !/(?:bearer\s+\S+|sk-[A-Za-z0-9_-]{12,}|(?:api[_ -]?key|token|password|secret|private[_ -]?key)\s*[:=]\s*\S+)/i.test(value)
        ? value : null;
      const safeMessage = (value) => typeof value === 'string' && value.trim().length > 0
        && value.length <= 500 && !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value)
        && !/(?:bearer\s+\S+|sk-[A-Za-z0-9_-]{12,}|(?:api[_ -]?key|authorization|token|password|secret|private[_ -]?key|비밀번호|토큰)\s*[:=]\s*\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i.test(value)
        ? value : null;
      const eventId = safeId(event?.id);
      const action = safeId(actionId);
      const targetId = safeId(target?.id);
      const requestId = safeId(receipt?.requestId);
      const receiptId = safeId(receipt?.receiptId);
      const receiptEventId = safeId(receipt?.eventId);
      const receiptActionId = safeId(receipt?.actionId);
      const generation = Number.isSafeInteger(target?.generation) && target.generation > 0 ? target.generation : null;
      const version = Number.isSafeInteger(receipt?.version) && receipt.version > 0 ? receipt.version : null;
      const observedAt = typeof observation?.observedAt === 'string'
        && Number.isFinite(Date.parse(observation.observedAt)) ? observation.observedAt : null;
      const receiptTarget = receipt?.target;
      const intentMismatch = Boolean(
        (receiptEventId && eventId && receiptEventId !== eventId)
        || (receiptActionId && action && receiptActionId !== action)
        || (receiptEventId && !eventId)
        || (receiptActionId && !action)
        || (receiptTarget?.id && targetId && receiptTarget.id !== targetId)
        || (receiptTarget?.generation != null && generation != null
          && receiptTarget.generation !== generation)
      );
      const supportedActions = Array.isArray(event?.supportedActions) ? event.supportedActions : null;

      line('h3', '보안 조치 요청 상태와 실제 결과');

      // A new idle snapshot must not inherit a prior request ID, receipt, or outcome.
      if (status === 'idle') {
        line('p', '아직 미실행(idle) · 조치 요청이나 효과 확인 결과가 없습니다.');
        line('p', safeMessage(message) || 'AI 제안만으로 조치가 실행되지 않습니다.');
        line('p', '현재 제공된 보안 기록에는 연동 시스템이 지원하는 조치가 없어 조치 준비 버튼이 나오지 않는 것이 정상입니다.');
        line('p', '조치 화면 취소는 이미 서버에 전달된 조치 효과를 되돌리지 않습니다.');
        return root;
      }

      if (intentMismatch) {
        line('p', '결과 불명(unknown) · 현재 사건·조치·대상과 서버 요청 기록의 연결이 일치하지 않습니다.');
        line('p', '이전 요청이나 다른 사건의 결과를 현재 조치의 성공으로 표시하지 않습니다.');
        line('p', '이미 전달된 요청이 있을 수 있으므로 새 집행 요청을 만들지 말고 연동 시스템 결과만 재조회하세요.');
        return root;
      }

      // Render state first, without treating a transport ACK as a confirmed effect.
      const confirmedEffect = status === 'succeeded'
        && observation?.effectApplied === true && observedAt !== null
        && eventId !== null && action !== null && targetId !== null
        && requestId !== null && receiptId !== null
        && (receipt?.status == null || receipt.status === 'succeeded');
      switch (status) {
        case 'loading':
          line('p', '조치 준비 또는 원천 결과 조회 중(loading) · 아직 요청 결과를 확인하지 못했습니다.');
          break;
        case 'prepared':
          line('p', '조치 준비됨·미실행(prepared) · 실제 대상을 확인하고 사람이 별도로 확인해야 집행할 수 있습니다.');
          break;
        case 'executing':
          line('p', '사람 확인 후 서버에 전달 중(executing) · 전송 중이며 실제 처리 결과는 아직 확인되지 않았습니다.');
          break;
        case 'pending':
          line('p', '서버 접수·처리 중(pending) · 접수 응답(ACK)은 요청 수신을 뜻할 뿐 보안 조치의 실제 효과가 아닙니다.');
          line('p', '실제 효과는 연동 시스템의 결과를 별도로 재조회한 뒤 확인해야 합니다.');
          break;
        case 'succeeded':
          if (confirmedEffect) {
            line('p', '연동 시스템 결과 재조회로 효과 확인(succeeded) · 실제 원천 효과가 관측되었습니다.');
            line('p', '관측 시각(observation.observedAt): ' + observedAt);
            line('p', 'effectApplied: true');
            line('p', '효과 확인 영수증(receiptId): ' + receiptId);
          } else {
            line('p', '결과 불명(unknown) · succeeded 상태만으로 실제 효과를 확인할 수 없습니다.');
            line('p', '유효한 원천 관측(effectApplied: true), 관측 시각 및 현재 요청·영수증을 확인할 수 없어 효과 성공으로 표시하지 않습니다.');
            line('p', '추가 집행 요청을 보내지 말고 연동 시스템 결과만 재조회하세요.');
          }
          break;
        case 'denied':
          line('p', '연동 시스템 거절(denied) · 서버 정책 또는 권한에 의해 조치가 거절되었습니다. 효과 확인 상태가 아닙니다.');
          break;
        case 'failed':
          line('p', '연동 시스템 처리 실패(failed) · 조치가 정상 처리됐음을 확인할 수 없습니다.');
          break;
        case 'unknown':
          line('p', '결과 불명(unknown) · 조치 성공으로도 효과 없음으로도 단정할 수 없습니다.');
          line('p', '같은 요청의 연동 시스템 결과만 재조회하세요. 확인 없이 집행 요청을 반복하지 마세요.');
          break;
        case 'expired':
          line('p', '사람 확인 기한 만료(expired) · 이 준비로는 집행할 수 없습니다. 현재 사건에서 다시 준비하세요.');
          line('p', '조치 화면 취소나 기한 만료는 이미 서버에 전달된 효과를 되돌리는 기능이 아닙니다.');
          break;
        case 'error':
          line('p', '조치 요청 처리 오류(error) · 요청이 정상 처리됐음을 확인할 수 없습니다.');
          break;
        default:
          line('p', '조치 상태 확인 불가(' + (safeId(status) || 'unknown') + ') · 효과를 확인하지 못했습니다.');
          line('p', '연동 시스템의 현재 상태를 확인하세요.');
      }

      // Only the current input snapshot is used for identifying this action.
      if (eventId) {
        line('p', '현재 사건 ID: ' + eventId);
        const evidence = Array.isArray(event?.evidence) ? event.evidence : [];
        const evidenceIds = evidence.map((item) => safeId(item?.id)).filter((id) => id !== null);
        line('p', '현재 사건 근거 ID: ' + (evidenceIds.length ? evidenceIds.join(', ') : '확인 불가'));
      }
      if (action) line('p', '조치 ID(actionId): ' + action);
      if (targetId) line('p', '실제 대상 ID(target.id): ' + targetId);
      if (generation !== null) line('p', '대상 세대(target.generation): ' + generation);
      if (requestId) line('p', '요청 ID(receipt.requestId): ' + requestId);
      if (receiptId) line('p', '접수 영수증 ID(receipt.receiptId): ' + receiptId);
      if (version !== null) line('p', '원천 결과 버전(receipt.version): ' + version);
      if (receipt?.status && safeId(receipt.status)) line('p', '원천 응답 상태(receipt.status): ' + receipt.status);
      if (receipt?.replayed === true) {
        line('p', '중복 조회·재전송 표시(replayed: true) · 기존 요청의 응답이며 새로운 집행이나 추가 효과를 뜻하지 않습니다.');
      } else if (receipt?.replayed === false) {
        line('p', '중복 처리 표시(replayed: false) · 중복 요청을 새로 생성하거나 실행하지 않습니다.');
      }
      if (receipt?.superseded === true) {
        line('p', '이전 결과가 최신 결과를 대체하지 않습니다(superseded). 같은 요청의 원천 결과를 재조회하세요.');
      }
      if (status === 'prepared' && typeof confirmationExpiresAt === 'string'
        && Number.isFinite(Date.parse(confirmationExpiresAt))) {
        line('p', '사람 확인 기한(confirmationExpiresAt): ' + confirmationExpiresAt);
        line('p', '확인 기한 이전에 제공 화면에서 실제 대상과 조치를 확인해야 합니다. 현재는 미실행입니다.');
      } else if (status === 'prepared') {
        line('p', '사람 확인 기한을 확인할 수 없습니다. 기한을 확인하기 전에는 집행 성공으로 보지 않습니다.');
      }

      const details = safeMessage(message);
      if (details && status !== 'idle') line('p', '상세 상태: ' + details);
      if (error) {
        const code = safeId(error?.code);
        if (code) line('p', '오류 코드(error.code): ' + code);
        line('p', '오류 메시지(error.message): ' + (safeMessage(error?.message) || '안전한 오류 메시지를 확인할 수 없습니다.'));
      }

      if (supportedActions?.length === 0) {
        line('p', '현재 연동 시스템에서 지원하는 조치가 없어 조치 준비 버튼이 나오지 않습니다(정상).');
      }
      if (status === 'prepared' || status === 'loading') {
        line('p', '조치 제안과 준비는 집행이 아닙니다. 실제 대상과 사람 확인을 거친 후에만 제공 화면이 처리합니다.');
      }
      line('p', '이 학생 화면은 상태 표시 전용입니다. 집행·결과 재조회·취소는 제공 화면에서만 수행합니다.');
      if (status === 'unknown' || (status === 'succeeded' && !confirmedEffect)) {
        line('p', '불명확한 원천 결과를 임의로 성공 또는 효과 없음으로 확정하지 않습니다.');
      }
      // Bind only coherent event/request pairs; never reuse old markers.
      if (eventId && requestId && (status !== 'succeeded' || confirmedEffect)) {
        root.setAttribute('data-student-action-event', eventId);
        root.setAttribute('data-student-action-request', requestId);
      }
      return root;
    },
  };
}
