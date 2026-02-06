# Contributing to NumaSec

Thank you for considering contributing to NumaSec! 🛡️

---

## Project Structure

```
src/numasec/
├── __init__.py          # Package exports (v3.0.0)
├── __main__.py          # Entry point
├── agent.py             # 🧠 v3 ReAct agent loop (extractors, planner, reflection)
├── router.py            # 🔀 Multi-LLM routing (DeepSeek, Claude, OpenAI, Ollama)
├── context.py           # 📊 Context window management (smart_trim_context)
├── state.py             # 💾 Session state (findings, messages)
├── session.py           # 💾 Session persistence (JSON)
├── target_profile.py    # 🎯 Structured memory (ports, endpoints, tech, creds, vulns)
├── extractors.py        # 🔬 14 auto-extractors (tool output → TargetProfile)
├── planner.py           # 📋 5-phase attack planner with auto-advance
├── reflection.py        # 🪞 Strategic reflection with tool-specific analysis
├── chains.py            # ⛓️ 14 escalation chains (SQLi→RCE, LFI→RCE, etc.)
├── knowledge_loader.py  # 📚 39-entry knowledge base with LRU cache
├── report.py            # 📄 Report generation (MD/HTML/JSON)
├── plugins.py           # 🔌 Plugin system (discover/load/scaffold)
├── cost_tracker.py      # 💰 Cost tracking per provider
├── error_recovery.py    # 🛡️ 23 error recovery patterns
├── few_shot_examples.py # 🎯 Few-shot examples per tool
├── config.py            # ⚙️ Config: YAML + .env + ENV loading
├── cli.py               # 💻 Rich CLI (cyberpunk theme)
├── renderer.py          # 🎨 ANSI streaming renderer
├── theme.py             # 🎨 UI theme
├── logging_config.py    # 📝 Structured logging
│
├── tools/
│   ├── __init__.py      # Tool registry (19 tools)
│   ├── recon.py         # nmap, httpx, subfinder, ffuf
│   ├── exploit.py       # nuclei, sqlmap, run_exploit
│   ├── browser.py       # 🌐 Playwright tools (8 browser_* tools)
│   └── browser_fallback.py
│
├── prompts/
│   └── system.md        # 📜 System prompt
│
└── knowledge/           # 📚 Attack patterns, cheatsheets (39 entries)
    ├── web_cheatsheet.md
    ├── linux_cheatsheet.md
    ├── attack_chains/   # LFI→RCE, SQLi→RCE, SSTI→RCE, upload→RCE
    ├── payloads/        # Command injection, PHP RCE, Python sandbox
    ├── web/             # Deserialization, JWT, GraphQL, NoSQL, LDAP
    └── ...
```

**~8,000 lines of Python** — Lean but powerful.

---

## Quick Start

```bash
# Clone
git clone https://github.com/FrancescoStabile/numasec.git
cd numasec

# Setup
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
playwright install chromium

# Set API key
cp .env.example .env
# Edit .env with your DEEPSEEK_API_KEY

# Run tests
pytest tests/ -v

# Run NumaSec
python -m numasec
```

---

## Code Standards

### Style
- **Formatter**: Ruff (line length 100)
- **Type hints**: All public functions
- **Docstrings**: Google style

```bash
# Format
ruff format src/

# Lint
ruff check src/

# Type check
mypy src/numasec
```

### Example

```python
async def my_function(target: str, timeout: int = 30) -> dict[str, Any]:
    """
    One-line summary.
    
    Args:
        target: Target URL or IP
        timeout: Timeout in seconds
        
    Returns:
        dict with results
        
    Raises:
        ValueError: If target is empty
    """
    if not target:
        raise ValueError("target cannot be empty")
    
    return {"status": "ok"}
```

---

## Adding Features

### New Tool

1. Add function in `tools/recon.py` or `tools/exploit.py`:

```python
async def my_tool(target: str, option: str = "default") -> str:
    """Run my_tool against target."""
    cmd = ["my_tool", target, "--option", option]
    stdout, stderr, code = await _run_command(cmd)
    return stdout if code == 0 else f"Error: {stderr}"
```

2. Add schema:

```python
TOOL_SCHEMAS["my_tool"] = {
    "description": "What my_tool does",
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target"},
            "option": {"type": "string", "default": "default"},
        },
        "required": ["target"],
    },
}
```

3. Register in `tools/__init__.py`:

```python
registry.register("my_tool", my_tool, TOOL_SCHEMAS["my_tool"])
```

4. Add few-shot examples in `few_shot_examples.py`:

```python
MY_TOOL_EXAMPLES = [
    ToolExample(
        scenario="User wants to scan target",
        thinking="Need to use my_tool for X",
        tool_name="my_tool",
        tool_args={"target": "example.com"},
        expected_result="Expected output",
        is_good=True,
    ),
]
```

### New Error Recovery Pattern

Add to `error_recovery.py`:

```python
MY_TOOL_PATTERNS = {
    "connection_error": {
        "indicators": ["connection refused", "timeout"],
        "strategy": RecoveryStrategy(
            guidance="Target may be down. Verify connectivity.",
            retry_tool="http",
        ),
    },
}
```

---

## Commit Messages

```
feat: Add XPath injection tool
fix: Fix browser session persistence
docs: Update CONTRIBUTING.md
test: Add tests for error recovery
refactor: Simplify context trimming
perf: Reduce token usage in prompts
```

---

## Pull Request Process

1. Fork the repo
2. Create feature branch: `git checkout -b feat/my-feature`
3. Make changes
4. Run tests: `pytest`
5. Run linter: `ruff check src/`
6. Commit with clear message
7. Push and create PR

---

## Testing

```bash
# All tests
pytest

# Specific test
pytest tests/unit/test_agent.py -v

# With coverage
pytest --cov=numasec
```

---

## Philosophy

1. **Simple > Complex** — One agent, good prompts, reliable tools
2. **Lean** — No bloat, ~8k lines total
3. **SOTA Prompts** — Few-shot, CoT, self-correction, error recovery
4. **Structured Intelligence** — Planner, extractors, reflection, chains
5. **Cost-Effective** — DeepSeek primary ($0.12/pentest)

---

## Questions?

Open an issue on GitHub.

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
