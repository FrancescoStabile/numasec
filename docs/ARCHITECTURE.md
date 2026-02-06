# NumaSec Architecture

> Technical documentation for NumaSec's AI-driven security testing platform.

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [Core Components](#core-components)
3. [SOTA Prompt Engineering](#sota-prompt-engineering)
4. [Tool System](#tool-system)
5. [Context Management](#context-management)
6. [Error Recovery](#error-recovery)
7. [LLM Router](#llm-router)
8. [File Structure](#file-structure)

---

## Design Philosophy

### Single-Agent Architecture

NumaSec implements a unified agent architecture rather than a multi-agent system:

| Approach | Advantages | Trade-offs |
|----------|-----------|------------|
| **Multi-Agent** | Specialized roles, parallel execution | Higher coordination overhead, increased costs |
| **Single-Agent** | Simplified execution, lower latency | Requires sophisticated prompting |

NumaSec compensates for single-agent constraints through advanced prompt engineering and intelligent tool orchestration, achieving comparable accuracy at significantly reduced operational cost.

### Core Principles

1. **Tool Integration**: Leverage specialized security tools with guided usage patterns
2. **Resilient Execution**: Implement systematic error recovery strategies
3. **Context Preservation**: Maintain conversation continuity through intelligent trimming
4. **Evidence Collection**: Capture verifiable proof for all findings

---

## Core Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                 NUMASEC                                     │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   CLI       │  │   AGENT     │  │   ROUTER    │  │   STATE     │        │
│  │ (cli.py)    │◄─►│ (agent.py)  │◄─►│ (router.py) │  │ (state.py)  │        │
│  │             │  │             │  │             │  │             │        │
│  │ • UI/UX     │  │ • Core loop │  │ • DeepSeek  │  │ • Findings  │        │
│  │ • Rich TUI  │  │ • Prompts   │  │ • Claude    │  │ • Messages  │        │
│  │ • Commands  │  │ • Tools     │  │ • OpenAI    │  │ • Session   │        │
│  │             │  │             │  │ • Ollama    │  │ • Persist   │        │
│  └─────────────┘  └──────┬──────┘  └─────────────┘  └─────────────┘        │
│                          │                                                  │
│                          ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        TOOL REGISTRY                                 │   │
│  │                                                                      │   │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐            │   │
│  │  │ nmap   │ │ http   │ │browser │ │nuclei  │ │ file   │            │   │
│  │  │        │ │        │ │(8 tools)│ │        │ │ops     │            │   │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘            │   │
│  │                                                                      │   │
│  │  tools/__init__.py → Central registry with schemas                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### agent.py — Core Agent

The agent implements a continuous reasoning loop with the following flow:

1. **Message Management**: Appends user input to conversation history
2. **Context Optimization**: Trims messages using group-based algorithm (max 120k tokens)
3. **LLM Interaction**: Calls router with messages, tool schemas, and system prompt
4. **Response Handling**: 
   - If tool calls requested: Execute tools and feed results back
   - If text response: Yield output to user and complete

The loop continues iteratively, enabling multi-step reasoning, tool execution, and result analysis until completion criteria are met.

### router.py — Multi-Provider LLM

**LLMRouter** manages provider selection and failover logic:

- **Initialization**: Defines priority order (default: DeepSeek → Claude → OpenAI)
- **Failover Strategy**: On rate limit errors, automatically tries next provider
- **Error Handling**: Propagates non-recoverable errors (e.g., invalid requests)
- **Provider Exhaustion**: Raises exception if all providers fail

Implements automatic failover across configured providers for improved reliability.

### state.py — Persistence

**SessionState** manages session data and persistence:

- **Session Data**: Stores ID, messages, findings, cost, timestamp, and target
- **Auto-save**: Persists to `~/.numasec/sessions/{id}.json` after each update
- **Session Resume**: Loads previous session by ID with full context restoration

Enables session suspension and resumption for long-running assessments.

---

## Advanced Prompt Engineering

NumaSec implements five research-backed optimization techniques:

### 1. Few-Shot Examples (+55% accuracy)

**Structure**: Each tool has 2-3 example interactions showing:
- **Scenario**: User request context
- **Thinking**: Reasoning process before action
- **Tool Call**: Proper parameter usage
- **Result**: Expected output format
- **Follow-up**: How to interpret and act on results

Examples are integrated into the system prompt to guide correct tool usage patterns.

### 2. Chain-of-Thought (CoT)

The system prompt mandates explicit reasoning in `<thinking>` tags before every action:

1. **Goal Identification**: What needs to be accomplished?
2. **Context Assessment**: What information is available?
3. **Tool Selection**: Which tool is appropriate and why?
4. **Risk Analysis**: What could potentially fail?

Forces explicit reasoning steps before tool invocation, reducing execution errors.

### 3. Self-Correction (Reflexion)

When a tool fails, the agent injects a structured reflection prompt:

1. **Failure Analysis**: Why did the tool fail?
2. **Target Validation**: Is the target specification correct?
3. **Parameter Review**: Should different arguments be used?
4. **Alternative Strategies**: Are there other approaches?

Enables the model to analyze failures and adjust approach autonomously.

### 4. Error Recovery (23 Patterns)

**RecoveryStrategy** structure for each tool:

- **Pattern Matching**: Regex patterns identifying specific error types
- **Guidance**: Human-readable explanation of the issue and solution
- **Recovery Action**: Type of fix (modify_args, add_flag, inform_user)
- **New Parameters**: Suggested argument modifications

Examples include:
- Nmap: Root privilege issues, host down detection, network unreachability
- SQLmap: Parameter detection failures, connection errors
- Browser: Timeout handling, element not found, navigation failures

Provides structured guidance for common failure modes, improving recovery success rate.

### 5. Context Management (Group-Based Trimming)

**Problem**: LLMs require tool results immediately after tool calls. Naive trimming breaks sequences, causing 400 errors.

**Solution**: Group-based trimming algorithm:

1. **Group Formation**: Bundle assistant messages with their tool results as atomic units
2. **Token Calculation**: Compute token count per group
3. **Strategic Removal**: Delete oldest complete groups (never splits mid-sequence)
4. **Preservation**: Always keeps system prompt and recent context

Maintains API compliance by treating assistant-tool message pairs as atomic units during context reduction.

---

## Tool System

### Tool Registration

**TOOL_REGISTRY** structure:

- **Function Reference**: Points to actual implementation
- **JSON Schema**: Defines parameters with types, descriptions, and validation
- **Required Fields**: Marks mandatory vs optional parameters
- **Enums**: Restricts values to valid options (e.g., scan_type)

JSON Schema ensures type-safe parameter passing and clear tool interfaces.

### Browser Tools Architecture

**BrowserContextPool** manages Playwright contexts:

- **Pool Management**: Maintains up to 3 concurrent contexts with 5-minute TTL
- **Session Persistence**: Saves and restores cookies/localStorage per session
- **Lazy Initialization**: Creates contexts on-demand, reuses existing ones
- **State Management**: Loads previous state from disk for session continuity

Context pooling reduces initialization overhead and preserves session state across sequential operations.

### Browser vs HTTP

```
            ┌─────────────────────────────────────────┐
            │         When to use what?               │
            │                                         │
            │  http tool:                             │
            │  • API testing                          │
            │  • POST/PUT/DELETE                      │
            │  • Headers manipulation                 │
            │  • Response inspection                  │
            │                                         │
            │  browser_* tools:                       │
            │  • JavaScript-rendered pages (SPAs)     │
            │  • XSS testing (need screenshot proof)  │
            │  • Form interactions                    │
            │  • Session/cookie testing               │
            │  • Login flows                          │
            └─────────────────────────────────────────┘
```

Automatic detection logic suggests appropriate tool selection based on target characteristics.

---

## Context Management

### The Problem

LLM APIs have strict requirements:
1. Max token limit (e.g., 128k for DeepSeek)
2. Tool results MUST follow tool calls immediately
3. Breaking sequences = 400 Bad Request

### Naive Approach (Invalid)

**Simple deletion strategy** (removing oldest messages sequentially):

**Problem**: Can orphan tool results by removing the assistant message that called them, causing:
- API validation errors (400 Bad Request)
- Lost conversation context
- Broken tool call sequences

### Production Implementation

**Group-based trimming algorithm**:

1. **Build Groups**: Identify atomic message units (assistant + tools)
2. **Token Accounting**: Calculate per-group token counts
3. **Strategic Removal**: Delete oldest complete groups while preserving system prompt
4. **Validation**: Ensure recent context and all tool sequences remain intact

**Result:** Zero API errors from context issues.

---

## Error Recovery

### 23 Patterns for Common Failures

**Pattern Categories by Tool**:

**Nmap**:
- Root privilege requirements → suggest TCP connect scan
- Host detection failures → recommend ping skip flag
- Network unreachability → prompt target verification

**SQLmap**:
- Parameter detection issues → suggest explicit parameter specification
- Connection failures → retry with different methods

**Browser Tools**:
- Timeout errors → increase wait times
- Element not found → suggest alternative selectors
- Navigation failures → validate URL and retry

**Integration**: When tools fail, the agent:
1. Matches error text against known patterns
2. Retrieves appropriate recovery strategy
3. Appends guidance hint to tool output
4. LLM sees hint and adjusts next attempt

Improves retry success rate through targeted recovery strategies.

---

## LLM Router

### Provider Configuration

**Supported Providers**:

| Provider | Model | Cost/Test | Max Tokens |
|----------|-------|-----------|------------|
| DeepSeek | deepseek-chat | $0.12 | 128k |
| Claude | claude-sonnet-4 | $0.50 | 200k |
| OpenAI | gpt-4 | $0.80 | 128k |
| Ollama | Local | Free | Varies |

**Configuration includes**: API endpoints, token limits, pricing rates for cost tracking.

### Message Normalization

**Format Differences**:

- **DeepSeek**: Tool calls in assistant role, results as separate "tool" role
- **Claude**: Tool use embedded in content blocks
- **OpenAI**: Legacy function_call format

**Normalization Layer**: Converts NumaSec's internal message format to provider-specific schemas before API calls.

Enables transparent provider switching with unified conversation state.

---

## File Structure

```
src/numasec/
├── __init__.py          # Package exports
├── __main__.py          # Entry point (python -m numasec)
│
├── agent.py             # 🧠 Core agent loop (500 lines)
│   ├── Agent class
│   ├── run() method
│   ├── execute_tool()
│   └── SOTA prompts
│
├── router.py            # 🔀 Multi-LLM routing (400 lines)
│   ├── LLMRouter class
│   ├── Provider enum
│   └── normalize_messages()
│
├── context.py           # 📊 Context trimming (150 lines)
│   └── trim_context_window()
│
├── state.py             # 💾 Session management (200 lines)
│   ├── SessionState
│   ├── Finding
│   └── save/load
│
├── cost_tracker.py      # 💰 Cost tracking (100 lines)
│   └── CostTracker class
│
├── error_recovery.py    # 🛡️ 23 recovery patterns (350 lines)
│   ├── RecoveryStrategy
│   └── TOOL_PATTERNS
│
├── few_shot_examples.py # 🎯 Tool examples (400 lines)
│   └── EXAMPLES dict
│
├── cli/
│   ├── cli.py           # 💻 Main CLI (Rich TUI)
│   └── cyberpunk.py     # 🌆 Styling/themes
│
├── tools/
│   ├── __init__.py      # Tool registry
│   ├── recon.py         # nmap, httpx, subfinder
│   ├── exploit.py       # nuclei, sqlmap
│   ├── browser.py       # 🌐 Playwright tools (8)
│   └── browser_fallback.py
│
├── prompts/
│   └── system.md        # 📜 System prompt
│
└── knowledge/           # 📚 Attack patterns
    ├── xss_payloads.txt
    ├── sqli_payloads.txt
    └── ...
```

---

## Technical Decisions

### Primary Provider Selection

| Factor | DeepSeek | Claude | GPT-4 |
|--------|----------|--------|-------|
| Cost | $0.12/pentest | $0.50 | $0.80 |
| Tool calling | Excellent | Excellent | Good |
| Context window | 128k | 200k | 128k |
| Reliability | 99%+ | 99%+ | 99%+ |

DeepSeek offers optimal cost-performance ratio for security testing workloads.

### Browser Automation Framework

Playwright selection criteria:

1. **Async Architecture**: Native async/await support aligns with NumaSec's execution model
2. **Automatic Synchronization**: Built-in element state detection
3. **Context Isolation**: Clean session separation for concurrent testing
4. **Protocol Access**: Chrome DevTools Protocol integration for advanced scenarios
5. **Performance**: Optimized for headless execution

### Framework Selection

NumaSec implements a custom architecture rather than existing LLM frameworks:

| Framework | Design Constraints |
|-----------|--------------------|
| LangChain | High abstraction overhead, limited failure visibility |
| AutoGPT | Multi-agent coordination costs |
| CrewAI | Complex inter-agent communication |

Custom implementation provides fine-grained control over prompt engineering, error handling, and execution flow.

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to add:
- New tools (tools/)
- Recovery patterns (error_recovery.py)
- Few-shot examples (few_shot_examples.py)
- LLM providers (router.py)

---

<div align="center">

**Questions?** Open an issue or check [README.md](../README.md)

</div>
