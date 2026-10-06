---
title: "Claude 작업을 Codex로 교차검증하기 — MCP로 두 AI 붙이기"
tags:
  - MCP
  - Codex
  - AI워크플로우
  - 교차검증
---

진단 도구를 Claude에 MCP로 붙이는 것과는 결이 다른 얘기입니다. 취약점 분석이든, 코드 리뷰든, 이 블로그 글 문장을 다듬는 작업이든 — Claude 혼자 끝낸 결과를 Claude 자신이 다시 검증하면 같은 사각지대를 못 보고 넘어가기 쉽습니다. 요즘은 작업 종류를 가리지 않고 거의 모든 것에 OpenAI의 [Codex CLI](https://github.com/openai/codex)를 MCP로 붙여서 2차 소견을 받고 있습니다. 이 글도, [[취약점 진단 툴에 MCP 붙이기 Ghidra Burp jadx]]의 문장 정리도, 실제로 이 방식을 거쳤습니다.

## 설치

Codex CLI를 설치하고 로그인부터 합니다.

```bash
npm i -g @openai/codex
codex login --api-key "<OPENAI_API_KEY>"
```

Codex CLI는 자체적으로 `mcp-server` 서브커맨드를 갖고 있어서, 별도 브리지 없이 그 자체로 MCP 서버가 됩니다. Claude Code라면 한 줄로 등록됩니다.

```bash
claude mcp add codex -- codex mcp-server
```

Claude Desktop이라면 `claude_desktop_config.json`에 직접 등록합니다.

```json
{
  "mcpServers": {
    "codex": {
      "command": "codex",
      "args": ["mcp-server"]
    }
  }
}
```

등록 후 Claude를 재시작하면 도구(🔨) 목록에 codex 관련 툴이 뜹니다. 서드파티 래퍼인 [tuannvm/codex-mcp-server](https://github.com/tuannvm/codex-mcp-server), [MarcEspuna/MCP-Codex-reviewer](https://github.com/MarcEspuna/MCP-Codex-reviewer)도 있는데, 세션별 승인 범위나 프롬프트 템플릿을 더 세밀히 제어하고 싶으면 이쪽을 씁니다.

## 이렇게 씁니다

작업이 끝난 뒤 "이거 Codex한테도 검토받아줘"라고 요청하면, Claude가 작업 요약과 확인할 쟁점을 정리해 Codex MCP 툴로 넘기고 돌아온 의견을 원문과 대조해 반영합니다. 코드 리뷰, 보안 분석, 글 문장 다듬기처럼 "Claude가 결과를 냈고 그 결과의 품질이 중요한" 모든 작업에 같은 패턴을 씁니다. 하나의 모델이 작성과 검토를 동시에 하면 자기 실수를 못 알아채는 경우가 실제로 있어서, 모델을 바꿔 한 번 더 보게 하는 것만으로 걸러지는 문제가 꽤 있습니다.

다만 교차 검토라고 결과를 무조건 합산하면 안 됩니다. Codex에 보내는 내용은 원문 전체가 아니라 비민감 요약 위주로 제한하고(코드 전체·로그·자격증명을 그대로 보내지 않기), Codex의 의견은 실제 코드·데이터와 대조해 맞는 것만 반영해야 합니다. 두 모델이 같은 실수를 공유할 수도 있다는 점은 변하지 않아서, 교차 검증이 검증 자체를 대체하지는 않습니다.

## 참고

- [OpenAI Codex CLI](https://github.com/openai/codex)
- [tuannvm/codex-mcp-server](https://github.com/tuannvm/codex-mcp-server)
- [MarcEspuna/MCP-Codex-reviewer](https://github.com/MarcEspuna/MCP-Codex-reviewer)
- [Model Context Protocol 공식](https://modelcontextprotocol.io)
