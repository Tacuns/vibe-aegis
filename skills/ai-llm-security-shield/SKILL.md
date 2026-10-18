---
name: ai-llm-security-shield
description: Audit AI and LLM features for prompt injection, denial-of-wallet (unbounded token spend), unsafe handling of model output, and over-privileged tool calls. Use whenever an app calls OpenAI, Anthropic, Gemini, an open-weight model, or implements RAG or agents.
---

# AI / LLM Security & Denial-of-Wallet Shield

An LLM endpoint is the only kind of API where **an attacker can spend your money directly**, and the only one where the data you process can rewrite the instructions you gave. Both failures are invisible in normal testing because the feature works exactly as intended.

## When to Trigger

- The project imports `openai`, `@anthropic-ai/sdk`, `@google/generative-ai`, `ai` (Vercel AI SDK), `langchain`, `llamaindex`, or calls a model endpoint directly
- The app does RAG, summarises user content, has a chatbot, or runs an agent with tools
- The user asks "is my AI feature safe?", "can someone drain my API credits?", "check my chatbot"

## 1. Denial-of-Wallet (the one that bills you tonight)

Unlike most abuse, this costs real money per request and scales with the attacker's patience.

Every model call needs **all four** controls. Three is not enough:

| Control | Why |
| :--- | :--- |
| **Authentication** | An unauthenticated model endpoint is a free API for the whole internet, billed to you |
| **Per-user and per-IP rate limits** | Authentication alone just means one free account spends unlimited money |
| **Input length cap** | Cost scales with input; a 200k-token paste costs far more than a chat message |
| **Explicit `max_tokens` / `maxTokens`** | Caps output. Without it a prompt can force maximum-length generations |

Also check: a **total spend ceiling** per user per day, streaming endpoints that abort when the client disconnects (otherwise a cancelled request still bills you to completion), and retry logic with a bounded attempt count — an unbounded retry loop on a failing provider multiplies cost.

Verify the cap is on the **call**, not merely in a config file that the call never reads.

## 2. Prompt Injection

Any text the model reads is untrusted input, not just the chat box. That includes retrieved documents, scraped pages, file uploads, email bodies, database fields other users wrote, and tool results.

- Keep the system prompt **static**. Never build it by string-concatenating user or retrieved content.
- Pass untrusted content in a **user/content role**, clearly delimited, and tell the model it is data to analyse, not instructions to follow.
- Treat "ignore previous instructions" defences as **mitigation, not a boundary**. There is no reliable way to make a model obey only your instructions. Design so that a successful injection still cannot cause harm.
- The real control is what sits **downstream**: if the model cannot reach anything dangerous, injection is a nuisance rather than a breach.

In RAG specifically, check tenant isolation on the retrieval query. If the vector search is not filtered by the requesting user's tenant, one user's question can retrieve another customer's documents — and the model will happily summarise them. This is IDOR wearing a new hat, and it is common.

## 3. Unsafe Output Handling

The model's output is untrusted too. It is shaped by whatever went in.

- Never pass model output into `eval()`, `new Function()`, a shell command, a raw SQL query, or `dangerouslySetInnerHTML` without sanitising.
- If the model returns markdown rendered as HTML, sanitise it — a model can be induced to emit `<img onerror=...>` or a `javascript:` link.
- If the model returns a URL that your server then fetches, you have SSRF. Allowlist the destination and block private ranges and the cloud metadata address.
- Validate structured output against a schema before use. "Usually returns valid JSON" is not a guarantee.

## 4. Agents And Tool Calls

Tool access converts a text bug into a real-world action.

- Give each tool the **narrowest** possible scope. A "read database" tool should read one table, scoped to the requesting user.
- Require **human confirmation** before any tool call that spends money, sends a message to a third party, deletes data, or changes auth and permissions.
- Bound the agent loop — a maximum step count and wall-clock timeout. An agent that loops forever is a wallet drain that looks like a hang.
- Log tool invocations with the triggering input, so an injection can be reconstructed afterwards.
- Remember the **lethal trifecta**: private data access + untrusted content + the ability to communicate externally. An agent with all three can be induced to exfiltrate. Remove one of the three.

## Investigation Protocol

1. Run `python3 .aegis/scripts/aegis_scan.py . --output .aegis/scan-report.json` and read `SEC-12`.
2. Enumerate every model call. For each, record: auth, rate limit, input cap, `max_tokens`, spend ceiling.
3. Map every text source that reaches a prompt. Mark each trusted or untrusted, and justify any "trusted".
4. Follow every output to where it is used. Look for the four unsafe sinks above.
5. For each tool, write down the worst thing it could do if the model were fully attacker-controlled. That is your actual blast radius.

## Reporting

Quantify the wallet risk concretely: "this endpoint has no auth and no token cap; at the configured model's rate, sustained abuse costs roughly $X/hour". A number drives a fix; "missing rate limiting" does not.

Be honest about the limits of prompt-injection defences. Never claim an app is "protected against prompt injection" — report what the blast radius is if injection succeeds, because eventually it will.
