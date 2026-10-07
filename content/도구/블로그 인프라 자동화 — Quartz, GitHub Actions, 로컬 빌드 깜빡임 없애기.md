---
title: "블로그 인프라 자동화 — Quartz · GitHub Actions · 로컬 빌드 깜빡임 없애기"
tags:
  - Quartz
  - GitHubActions
  - 자동화
  - 블로그운영
---

이 블로그는 [Quartz](https://quartz.jzhao.xyz/)로 만들고 GitHub Pages에 올립니다. `content/`에 마크다운을 쓰고 push하면 GitHub Actions가 빌드해서 배포하는, 흔한 구조입니다. 그런데 운영하다 보니 이 "흔한 구조" 바깥에서 문제가 반복됐습니다. [보안이슈 ATT&CK 트래커](/security-issues/) 같은 Quartz가 모르는 정적 페이지를 하위 경로에 끼워 넣으면서 생긴 문제들이었어요.

이 글은 제가 직접 디버깅한 기록이 아닙니다. 저는 "안 보인다", "클릭이 안 된다" 같은 증상만 보고 Claude(AI)에게 전달했고, 원인 추적과 코드 수정은 Claude가 세션 안에서 직접 했습니다. 저는 결과를 확인하고 다음 지시를 내리는 역할이었어요. 이 블로그의 "AI를 진단 업무에 실제로 끌어다 쓰는 과정"이라는 컨셉 그대로, AI가 실제로 겪고 고친 과정을 순서대로 옮겨 적습니다.

## 문제 1: 로컬에서 빌드하는 걸 깜빡하면 사이트가 옛 내용 그대로

보안이슈 트래커는 `psv`(파이프 구분 텍스트) 소스를 `node build.mjs`로 돌려 `index.html` 하나를 생성하는 구조입니다([[보안이슈 트래커 빌드 후기 — psv와 build.mjs로 서버 없는 정적 도구 만들기|다음 글]]에서 자세히 다룹니다). 문제는 이 빌드가 **로컬에서만** 일어난다는 것. 소스 파일(`일일/*.md`, `*.psv`)만 고치고 `node build.mjs`를 깜빡한 채 push하면, 저장소엔 새 소스가 들어갔는데 실제 `index.html`은 갱신 전 상태로 배포됩니다. 실제로 이 실수가 한 번 났고, "왜 반영이 안 되냐"고 물었더니 Claude가 원인을 찾아냈습니다.

Claude가 고친 방법은 빌드 자체를 CI로 옮기는 것이었습니다. GitHub Actions `deploy.yml`에 한 줄 추가했습니다.

```yaml
- name: Build Quartz
  run: npx quartz build
- name: Build security-issues page from source
  run: node "보안이슈/build.mjs"
- name: Copy security-issues static page
  run: |
    mkdir -p public/security-issues
    cp "보안이슈/index.html" public/security-issues/index.html
```

이제 소스 파일만 push하면 CI가 매번 직접 `build.mjs`를 돌려서 최신 `index.html`을 만듭니다. 로컬 빌드는 오프라인에서 더블클릭으로 열어볼 때나 필요한, 선택사항이 됐습니다. 핵심은 "빌드 결과물을 커밋에 의존하지 말고, 커밋 시점에 다시 생성하게" 바꾼 것입니다.

## 문제 2: Quartz의 SPA 라우터가 외부 정적 페이지를 깨먹는다

제가 겪은 증상은 단순했습니다. 주소창에 `/security-issues/`를 직접 입력하면 멀쩡히 열리는데, 사이트 안에서 링크를 클릭하면 안 들어가지는 것. "클릭이 안 된다"고만 전달했고, 원인은 Claude가 Quartz 소스를 직접 읽어서 찾았습니다. Quartz는 `enableSPA: true`일 때 내부 링크 클릭을 가로채서 fetch로 받아 DOM을 갈아치우는데(페이지 전체 리로드 없이), `/security-issues/`는 Quartz가 만든 페이지가 아니라 완전히 다른 구조의 독립 HTML이라 SPA가 그걸 가로채서 끼워 넣으려 하면 깨지는 것이었습니다.

Claude가 Quartz의 라우터 코드(`spa.inline.ts`)를 읽고 찾아낸 답입니다.

```ts
const getOpts = ({ target }: Event) => {
  if (!isElement(target)) return
  if (target.attributes.getNamedItem("target")?.value === "_blank") return
  const a = target.closest("a")
  if (!a) return
  if ("routerIgnore" in a.dataset) return  // 여기
  ...
}
```

`data-router-ignore` 속성이 있으면 라우터가 그 링크를 건너뛰고 브라우저 기본 동작(전체 페이지 이동)을 하게 둡니다. 링크 하나에 속성 하나만 추가하면 끝입니다.

```html
<a href="/security-issues/" data-router-ignore>보안 이슈 · ATT&CK 정리</a>
```

Quartz 바깥의 정적 페이지로 링크를 걸 때는 이 속성이 거의 항상 필요하다고 보면 됩니다.

## 문제 3: CSS를 고쳤는데 안 보인다 — 알고 보니 10분 캐시

사이드바 링크 디자인을 여러 번 고치는 동안 매번 "안 바뀌었는데?"라고 물었습니다. Claude는 "서버는 이미 최신"이라고 했는데, 직접 보면 안 바뀐 것처럼 보이니 처음엔 의심이 들었습니다. Claude가 캐시를 무시하고 CSS만 다시 받아오는 코드를 짜서 직접 비교해 보여줬습니다.

```js
// Claude가 확인한 방법 — 캐시 무시하고 CSS만 다시 받아서 비교
const r = await fetch('https://.../index.css?bust=' + Date.now(), { cache: 'no-store' })
```

원인은 Quartz가 JS 파일은 content-hash를 붙여 캐시 무효화를 자동으로 해주는데, `index.css`는 파일명이 고정이라 그런 처리가 없다는 것이었습니다. GitHub Pages(Fastly CDN)의 기본 `max-age=600`과 브라우저 캐시가 겹쳐서, push 직후엔 서버는 최신인데 브라우저는 10분간 옛 CSS를 그대로 씁니다. 이 방법으로 "서버 쪽은 이미 최신인데 브라우저만 옛 캐시를 들고 있다"는 걸 몇 번이나 확인했습니다. 당장은 "하드 리프레시(Ctrl+Shift+R)로 보세요"로 넘겼지만, 근본 해법은 CSS도 JS처럼 content-hash 파일명으로 내보내게 Quartz 빌드 설정을 고치는 것입니다. 아직 미해결 과제로 남겨뒀습니다.

## 문제 4: 상시 감시 스크립트는 의외로 잘 안 떠 있다

처음엔 `auto-sync.ps1`이라는, 30초마다 `git status`를 확인해 변경이 있으면 자동으로 커밋·push하는 PowerShell 감시 스크립트가 있었습니다. "왜 자동 동기화가 안 되냐"고 물었더니, Claude가 실행 중인 프로세스 목록을 직접 확인해서 — 막상 그 스크립트가 꺼져 있다는 걸 찾아냈습니다. PowerShell 창을 계속 열어둬야 하는 구조라, 세션이 바뀌거나 창을 닫으면 조용히 죽어 있는 거죠. "자동화돼 있다"고 믿고 있었는데 실제로는 안 돌고 있었던 셈입니다. Claude가 세션에서 그 창을 다시 띄워봤는데도 금방 다시 죽는 걸 보고, 애초에 상시 프로세스에 의존하는 방식 자체가 이 환경에서 불안정하다는 걸 알게 됐습니다.

그래서 Claude가 상시 감시 대신, **루틴이 끝나는 시점에 한 번 실행하는 스크립트**로 바꿨습니다. 보안이슈 쪽은 `sync.ps1` 하나로 `build.mjs → git add(보안이슈 폴더만) → commit → push`를 순서대로 처리합니다. 상시 프로세스가 살아있는지 신경 쓸 필요가 없고, 루틴의 마지막 단계로 그냥 한 줄 실행하면 끝입니다.

```powershell
D:\98. blog\보안이슈\sync.ps1
```

이 스크립트를 처음 돌렸을 때 바로 파싱 에러가 났고, Claude가 PowerShell 5.1 특유의 함정을 하나 더 찾아냈습니다. 한글이 든 `.ps1` 파일을 UTF-8(BOM 없음)으로 저장하면 Windows PowerShell이 시스템 코드페이지로 잘못 읽어서 문자열이 깨지고 파싱 에러가 납니다. BOM을 붙여야 합니다.

```powershell
[System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($true))
```

그리고 `git push`를 `2>&1`로 캡처하면, git이 진행 상황을 stderr로 찍는 정상 동작까지 PowerShell이 에러로 취급해버립니다(`NativeCommandError`). 네이티브 명령의 출력은 굳이 리다이렉트하지 않는 게 안전하다는 걸 다시 확인했습니다.

## 지금 남은 구조

```
content/*.md, 보안이슈/*  (사람이 직접 편집)
        │ push
        ▼
GitHub Actions: npx quartz build + node 보안이슈/build.mjs
        │
        ▼
GitHub Pages 배포 (1~2분)
```

빌드 결과물을 신뢰하지 않고 커밋마다 다시 만들게 한 것, 라우터가 모르는 페이지엔 라우팅을 맡기지 않은 것, 캐시를 의심하고 직접 확인한 것, 상시 프로세스 대신 일회성 스크립트로 바꾼 것 — 네 가지 다 결국 "뭔가 자동으로 되고 있다고 믿지 말고 실제로 확인하자"는 같은 이야기였고, 그 확인과 수정을 실제로 한 건 전부 Claude였습니다. 저는 증상을 전달하고 결과를 지켜봤습니다.
