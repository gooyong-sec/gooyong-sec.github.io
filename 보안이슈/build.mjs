// 사용법: node build.mjs
// 원본: 일일/*.md, 과거3년/*.md (사건 본문), ATTACK/매핑.psv (사건-기법 매핑), ATTACK/_catalog.psv (공식 기법 목록),
//       ATTACK/기법해설.psv·전술해설.psv·용어집.psv (쉬운 해설), 국내뉴스.psv (국내 뉴스 브리핑), 분류.psv
// 생성: ATTACK/NN-*.md (전술별), ATTACK/README.md, 과거3년/00-타임라인.md, 용어집.md, 국내뉴스.md, index.html (서버 없이 열리는 UI)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8').replace(/\r/g, '');
const write = (p, s) => fs.writeFileSync(path.join(ROOT, p), s, 'utf8');
const warn = (m) => console.warn('경고:', m);

// ATT&CK Enterprise v19.2 전술 (표시 순서)
const TACTICS = [
  ['TA0043', '정찰', 'Reconnaissance'], ['TA0042', '자원개발', 'Resource Development'],
  ['TA0001', '초기접근', 'Initial Access'], ['TA0002', '실행', 'Execution'],
  ['TA0003', '지속성', 'Persistence'], ['TA0004', '권한상승', 'Privilege Escalation'],
  ['TA0005', '스텔스', 'Stealth (구 Defense Evasion)'], ['TA0112', '방어약화', 'Defense Impairment'],
  ['TA0006', '자격증명접근', 'Credential Access'], ['TA0007', '탐색', 'Discovery'],
  ['TA0008', '횡적이동', 'Lateral Movement'], ['TA0009', '수집', 'Collection'],
  ['TA0011', 'C2', 'Command and Control'], ['TA0010', '유출', 'Exfiltration'],
  ['TA0040', '영향', 'Impact'],
].map(([id, ko, en], i) => ({ id, ko, en, file: `${String(i + 1).padStart(2, '0')}-${ko}.md` }));
const TAC = Object.fromEntries(TACTICS.map((t) => [t.id, t]));

const psv = (text) => text.split('\n').filter((l) => l.trim() && !l.startsWith('#')).map((l) => l.split('|'));

const catalog = psv(read('ATTACK/_catalog.psv')).map(([ta, id, name]) => ({ ta, id, name }));
const techName = new Map(catalog.map((c) => [c.id, c.name]));
const inTactic = new Set(catalog.map((c) => `${c.ta}|${c.id}`));

// ── 사건 파싱 ─────────────────────────────────────────────
function parseIncidents(file, text) {
  const res = [];
  let cur = null;
  for (const l of text.split('\n')) {
    const h = l.match(/^### \[([\w-]+)\] (.+)$/);
    if (h) { if (cur) res.push(cur); cur = { id: h[1], title: h[2].trim(), file, body: [] }; continue; }
    if (!cur) continue;
    if (/^(# |## |---\s*$)/.test(l)) { res.push(cur); cur = null; continue; }
    cur.body.push(l);
  }
  if (cur) res.push(cur);
  return res.map((r) => {
    const body = r.body.join('\n').trim().split('\n');
    const m = body[0] && body[0].match(/^> (날짜: .+)$/);
    const meta = {};
    if (m) m[1].split(' · ').forEach((kv) => { const i = kv.indexOf(': '); if (i > 0) meta[kv.slice(0, i).trim()] = kv.slice(i + 2).trim(); });
    else warn(`${r.id}: 메타 줄(> 날짜: ...) 없음`);
    return {
      id: r.id, title: r.title, file: r.file,
      date: meta['날짜'] || '', type: meta['유형'] || '', actor: meta['행위자'] || '',
      region: meta['지역'] || '', evidence: meta['근거'] || '',
      md: (m ? body.slice(1) : body).join('\n').trim(),
      easy: ((m ? body.slice(1) : body).join('\n').match(/^\*\*쉽게 말하면\*\*: (.+)$/m) || [])[1] || '',
      todo: ((m ? body.slice(1) : body).join('\n').match(/^\*\*먼저 할 일\(초보용\)\*\*: (.+)$/m) || [])[1] || '',
    };
  });
}

const listMd = (dir) => fs.readdirSync(path.join(ROOT, dir)).filter((f) => f.endsWith('.md')).sort();
const SKIP = new Set(['00-타임라인.md', '99-총평.md']);
const incidents = [];
for (const dir of ['과거3년', '일일']) {
  for (const f of listMd(dir)) {
    if (SKIP.has(f)) continue;
    incidents.push(...parseIncidents(`${dir}/${f}`, read(`${dir}/${f}`)));
  }
}
const incIds = new Set(incidents.map((i) => i.id));

// 원인 유형 분류 (분류.psv: 사건ID|주분류|보조분류...)  ※ 정의는 과거3년/99-총평.md의 표와 같다
const CLASSES = {
  A: '노출 장비·서비스 취약점', B: '자격 증명·MFA', C: '서드파티·공급망', D: '사회공학', E: '장기 체류·탐지 실패',
  F: '백업·복구 부재', G: '파괴·지정학', H: '인증·키 설계 결함', I: '클라이언트 취약점', J: '경위·원인 미공개',
};
const clsOf = Object.fromEntries(psv(read('분류.psv')).map(([id, ...c]) => [id, c.map((x) => x.trim()).filter(Boolean)]));
for (const i of incidents) {
  i.cls = clsOf[i.id] || [];
  if (!i.date) warn(`${i.id}: 날짜 없음`);
  if (!i.easy) warn(`${i.id}: '**쉽게 말하면**:' 문단 없음 (초보용 요약)`);
  if (!i.todo) warn(`${i.id}: '**먼저 할 일(초보용)**:' 문단 없음`);
  if (!i.cls.length) warn(`${i.id}: 분류.psv에 없음`);
  if (i.cls.some((c) => !CLASSES[c])) warn(`${i.id}: 알 수 없는 분류 ${i.cls}`);
}

// ── 매핑 검증 ────────────────────────────────────────────
const mappings = psv(read('ATTACK/매핑.psv')).map(([id, ta, tech, ev, ...note]) => ({
  id, ta, tech, parent: tech.split('.')[0], ev, note: note.join('|'),
}));
for (const m of mappings) {
  if (!incIds.has(m.id)) warn(`매핑의 사건 ID 없음: ${m.id}`);
  if (!TAC[m.ta]) warn(`알 수 없는 전술: ${m.ta} (${m.id})`);
  else if (!inTactic.has(`${m.ta}|${m.parent}`)) warn(`${m.parent}(${techName.get(m.parent) || '카탈로그에 없음'})은 ${m.ta}에 속하지 않음 (${m.id})`);
}

// ── 초보용 해설·국내뉴스 데이터 ─────────────────────────
const techNotes = Object.fromEntries(psv(read('ATTACK/기법해설.psv')).map(([id, ko, ...d]) => [id, [ko, d.join('|')]]));
const tacDesc = Object.fromEntries(psv(read('ATTACK/전술해설.psv')).map(([id, d, ...a]) => [id, [d, a.join('|')]]));
const glossary = psv(read('용어집.psv')).map(([t, ...d]) => [t, d.join('|')]);
const news = psv(read('국내뉴스.psv')).map(([date, cat, src, sum, url, rel]) => ({ date, cat, src, sum, url, rel: rel || '' }))
  .sort((a, b) => b.date.localeCompare(a.date));
for (const id of new Set(mappings.map((m) => m.parent))) if (!techNotes[id]) warn(`ATTACK/기법해설.psv에 ${id} 없음`);
for (const t of TACTICS) if (!tacDesc[t.id]) warn(`ATTACK/전술해설.psv에 ${t.id} 없음`);
for (const n of news) if (n.rel && !incIds.has(n.rel)) warn(`국내뉴스.psv: 알 수 없는 관련 사건 ${n.rel}`);

// ── 전술별 md 생성 ───────────────────────────────────────
const incById = new Map(incidents.map((i) => [i.id, i]));
const relLink = (i) => `../${i.file}`;
for (const f of fs.readdirSync(path.join(ROOT, 'ATTACK'))) if (/^\d\d-.+\.md$/.test(f)) fs.unlinkSync(path.join(ROOT, 'ATTACK', f));

const coverage = [];
for (const t of TACTICS) {
  const all = catalog.filter((c) => c.ta === t.id);
  const rows = mappings.filter((m) => m.ta === t.id).sort((a, b) => a.parent.localeCompare(b.parent) || a.tech.localeCompare(b.tech));
  const seen = new Set(rows.map((r) => r.parent));
  coverage.push({ t, seen: seen.size, total: all.length });
  const lines = [
    `# ${t.id} ${t.ko} (${t.en})`, '',
    `> **쉽게 말하면**: ${(tacDesc[t.id] || ['', ''])[0]} (비유: ${(tacDesc[t.id] || ['', ''])[1]})`, '',
    `> 자동 생성 파일 — 원본은 \`매핑.psv\`이며 직접 고치지 않는다. 기준: ATT&CK Enterprise v19.2. 공식 기법 ${all.length}개 중 ${seen.size}개에서 사례가 관측됐다.`, '',
  ];
  if (rows.length) {
    lines.push('| 기법 | 사건 | 날짜 | 근거 | 설명 |', '|------|------|------|------|------|');
    for (const r of rows) {
      const inc = incById.get(r.id);
      lines.push(`| ${r.tech} ${techName.get(r.parent) || ''}${techNotes[r.parent] ? ' — ' + techNotes[r.parent][0] : ''} | [${inc ? inc.title : r.id}](${inc ? relLink(inc) : '#'}) | ${inc ? inc.date : ''} | ${r.ev} | ${r.note} |`);
    }
  } else lines.push('아직 사례가 없다.');
  const rest = all.filter((c) => !seen.has(c.id));
  if (rest.length) lines.push('', `## 사례가 아직 없는 공식 기법 (${rest.length}개)`, '', rest.map((c) => `${c.id} ${c.name}`).join(' · '));
  write(`ATTACK/${t.file}`, lines.join('\n') + '\n');
}

const distinct = new Set(mappings.map((m) => m.parent));
const distinctAll = new Set(catalog.map((c) => c.id));
write('ATTACK/README.md', [
  '# MITRE ATT&CK 전술별 누적 정리', '',
  `기준: **ATT&CK Enterprise v19.2**. v19에서 TA0005는 *Defense Evasion*에서 **Stealth**로 개칭됐고 **Defense Impairment(TA0112)** 가 신설됐다. 과거 자료와 전술명이 다를 수 있으니 기법 ID로 비교한다.`, '',
  '> 이 폴더의 `NN-*.md`와 이 파일은 `node build.mjs`가 생성한다. **원본은 `매핑.psv`** (사건-기법 매핑)와 `_catalog.psv`(공식 기법 목록)다. 쉬운 한국어 해설은 `기법해설.psv`·`전술해설.psv`.', '',
  '| 파일 | 전술 | ID | 사례 있는 기법 / 공식 기법 |', '|------|------|----|------|',
  ...coverage.map(({ t, seen, total }) => `| [${t.file}](${t.file}) | ${t.ko} (${t.en}) | ${t.id} | ${seen} / ${total} |`), '',
  `전체: 서로 다른 상위 기법 ${distinct.size}개에서 사례가 관측됨 (공식 ${distinctAll.size}개). 사건 ${incidents.length}건, 매핑 ${mappings.length}행.`, '',
  '근거 수준: **확인**(벤더·CISA·연구기관 직접 확인) / **추정**(공개 자료에 없어 분석상 추정) / **후보**(조건이 확인되면 적용). 공격자 일방 주장은 표에 넣지 않고 일일 보고서에만 적는다.', '',
  '## 매일 갱신하는 법', '',
  '1. `일일/YYYY-MM-DD.md`에 사건을 `### [D<날짜>-<이름>]` 제목과 `> 날짜: … · 유형: … · 행위자: … · 지역: … · 근거: …` 메타 줄로 쓴다.',
  '2. `ATTACK/매핑.psv`에 `사건ID|전술|기법|근거|설명` 행을 추가한다.',
  '3. `node build.mjs`를 실행하면 전술별 파일, 타임라인, `index.html`이 갱신된다.', '',
].join('\n'));

// ── 타임라인 md ──────────────────────────────────────────
const sorted = [...incidents].sort((a, b) => a.date.localeCompare(b.date));
write('과거3년/00-타임라인.md', [
  '# 사건 타임라인 (2023-10 ~ 현재)', '',
  '> 자동 생성. 원본은 각 연도 파일과 `../일일/*.md`.', '',
  '| 날짜 | 사건 | 유형 | 행위자 | 근거 | 문서 |', '|------|------|------|------|------|------|',
  ...sorted.map((i) => `| ${i.date} | ${i.title} | ${i.type} | ${i.actor} | ${i.evidence} | [${path.basename(i.file)}](../${i.file}) |`), '',
].join('\n'));

// ── 용어집·국내뉴스 md ───────────────────────────────────
write('용어집.md', ['# 보안 용어집 (초보용)', '', '> 자동 생성. 원본은 `용어집.psv`. 보고서와 화면에서 이 용어가 처음 나오면 밑줄로 표시되고, 마우스를 올리면 뜻이 보인다.', '', '| 용어 | 쉬운 설명 |', '|------|------|', ...glossary.map(([t, d]) => `| ${t} | ${d} |`), ''].join('\n'));
const kr = incidents.filter((i) => i.region.includes('한국')).sort((a, b) => b.date.localeCompare(a.date));
write('국내뉴스.md', ['# 국내 보안 소식', '', '> 자동 생성. 원본은 `국내뉴스.psv`(뉴스 브리핑)와 각 사건 파일 중 `지역: 한국`인 사건.', '', '## 국내 주요 사건', '', '| 날짜 | 사건 | 유형 | 문서 |', '|------|------|------|------|', ...kr.map((i) => `| ${i.date} | ${i.title} | ${i.type} | [${path.basename(i.file)}](${i.file}) |`), '', '## 뉴스 브리핑', '', '| 날짜 | 분류 | 출처 | 요약 |', '|------|------|------|------|', ...news.map((n) => `| ${n.date} | ${n.cat} | [${n.src}](${n.url}) | ${n.sum} |`), ''].join('\n'));

// ── 문서 수집 (UI용) ────────────────────────────────────
const docs = [];
for (const dir of ['일일', '과거3년', 'ATTACK']) {
  for (const f of listMd(dir)) {
    const text = read(`${dir}/${f}`);
    docs.push({ path: `${dir}/${f}`, title: (text.match(/^# (.+)$/m) || [, f])[1], md: text });
  }
}
if (fs.existsSync(path.join(ROOT, 'README.md'))) docs.push({ path: 'README.md', title: '사용법', md: read('README.md') });
for (const f of ['용어집.md', '국내뉴스.md']) docs.push({ path: f, title: (read(f).match(/^# (.+)$/m) || [, f])[1], md: read(f) });

// ── UI용 데이터 다이어트: 사건 본문은 문서에서 잘라 쓰고(오프셋만 저장), 자동 생성 전술 파일은 뺀다 ──
const docsUi = docs.filter((d) => !/^ATTACK\/\d\d-/.test(d.path));
for (const i of incidents) {
  const d = docsUi.find((x) => x.path === i.file);
  const idx = d ? d.md.replace(/\r/g, '').indexOf(i.md) : -1;
  if (idx < 0) warn(`${i.id}: 문서에서 본문 위치를 찾지 못함`);
  i.s = idx; i.e = idx + i.md.length;
}
const incUi = incidents.map(({ md, ...r }) => r);

// ── index.html ───────────────────────────────────────────
const data = {
  built: new Date().toLocaleDateString('sv-SE'),
  tactics: TACTICS, catalog, incidents: incUi, mappings, docs: docsUi, classes: CLASSES, glossary, techNotes, tacDesc, news,
};
const json = JSON.stringify(data).replace(/</g, '\\u003c');
write('index.html', read('template.html').replace('/*__DATA__*/', `const DATA = ${json};`));

console.log(`사건 ${incidents.length}건 · 매핑 ${mappings.length}행 · 문서 ${docs.length}개 · 상위 기법 ${distinct.size}/${distinctAll.size} → index.html`);
