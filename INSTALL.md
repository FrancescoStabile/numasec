# Installation Guide

Complete installation instructions for NumaSec.

---

## Quick Start (2 minutes)

```bash
# 1. Install NumaSec
pip install numasec

# 2. Install browser (for XSS testing)
playwright install chromium

# 3. Set API key
export DEEPSEEK_API_KEY="sk-..."  # Get from platform.deepseek.com

# 4. Run
numasec
```

**That's it.** NumaSec is ready.

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| **Python** | 3.11+ |
| **RAM** | 2GB minimum |
| **Disk** | 200MB |
| **OS** | Linux, macOS, Windows (WSL2) |
| **Network** | Internet for LLM API |

---

## Installation Methods

### Method 1: PyPI (Recommended)

```bash
# Install NumaSec
pip install numasec

# Install Chromium for browser tools (XSS testing)
playwright install chromium

# Verify
numasec --version
```

### Method 2: With MCP Support (Claude Desktop, Cursor, VS Code)

```bash
# Install with MCP extras
pip install 'numasec[mcp]'

# Auto-configure Claude Desktop
numasec setup-claude

# Restart Claude Desktop — done!
```

### Method 2b: With PDF Report Support

```bash
# Install with PDF generation
pip install 'numasec[pdf]'

# Or install everything (MCP + PDF)
pip install 'numasec[mcp,pdf]'
```

**Or with `uv` (faster, isolated):**

```bash
uv tool install 'numasec[mcp]'
```

**Manual Cursor/VS Code config** — add to your MCP settings:

```json
{
  "mcpServers": {
    "numasec": {
      "command": "numasec",
      "args": ["--mcp"],
      "env": {
        "DEEPSEEK_API_KEY": "sk-your-key-here"
      }
    }
  }
}
```

### Method 3: From Source (Development)

```bash
# Clone
git clone https://github.com/FrancescoStabile/numasec.git
cd numasec

# Install in editable mode with all extras
pip install -e ".[dev,mcp,pdf]"

# Install browser
playwright install chromium

# Run tests
pytest
```

### Method 4: Container

```bash
# Build
podman build -t numasec .

# Run
podman run -it --network host \
  -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  numasec
```

---

## Configuration

### 🔑 API Keys (Automatic Setup)

**First Run - Interactive Setup:**

```bash
numasec
# NumaSec will detect no API keys and prompt you to set one up
# Config is saved to: ~/.numasec/config.yaml
```

**Manual Configuration:**

**Option 1: Config File (Recommended - Persistent)**
```bash
# Create/edit config file
nano ~/.numasec/config.yaml
```

```yaml
# ~/.numasec/config.yaml
DEEPSEEK_API_KEY: sk-your-key-here
# ANTHROPIC_API_KEY: sk-ant-...
# OPENAI_API_KEY: sk-...
```

**Option 2: Environment Variables (Session-Only)**
```bash
export DEEPSEEK_API_KEY="sk-..."      # Recommended - $0.12/pentest
export ANTHROPIC_API_KEY="sk-ant-..." # Fallback
export OPENAI_API_KEY="sk-..."        # Fallback
```

**Option 3: .env File (Project-Local)**
```bash
# .env file in your project directory
DEEPSEEK_API_KEY=sk-...
```

**Priority:** `ENV variables` > `.env file` > `~/.numasec/config.yaml`

**Get API Keys:**
- DeepSeek: https://platform.deepseek.com (cheapest, recommended)
- Claude: https://console.anthropic.com
- OpenAI: https://platform.openai.com
- Ollama: https://ollama.com (local, free, no key needed)

### Optional: Security Tools

NumaSec works standalone but is more powerful with:

**Linux (Debian/Ubuntu)**
```bash
sudo apt install -y nmap
pip install sqlmap
# nuclei: https://github.com/projectdiscovery/nuclei
```

**macOS**
```bash
brew install nmap sqlmap nuclei
```

---

## Verification

```bash
# Check version
numasec --version

# Test run
numasec
> what tools do you have?
```

---

## Troubleshooting

### API Key Not Found

```
Error: No LLM provider API key found
```

**Solution:**
```bash
export DEEPSEEK_API_KEY="sk-..."
# Permanent: add to ~/.bashrc or ~/.zshrc
```

### Playwright Not Installed

```
Error: Playwright browsers not installed
```

**Solution:**
```bash
playwright install chromium
```

### Import Error

```
ModuleNotFoundError: No module named 'numasec'
```

**Solution:**
```bash
# Verify Python version
python --version  # Must be 3.11+

# Reinstall
pip install --force-reinstall numasec
```

---

## Updating

```bash
pip install --upgrade numasec
playwright install chromium  # Update browser too
```

---

## Uninstalling

```bash
pip uninstall numasec
rm -rf ~/.numasec  # Remove session data (optional)
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEEPSEEK_API_KEY` | DeepSeek API key | None |
| `ANTHROPIC_API_KEY` | Claude API key | None |
| `OPENAI_API_KEY` | OpenAI API key | None |

---

## Optional Extras

| Extra | Install | Features |
|-------|---------|----------|
| `[mcp]` | `pip install 'numasec[mcp]'` | MCP server for Claude Desktop, Cursor, VS Code |
| `[pdf]` | `pip install 'numasec[pdf]'` | Professional PDF pentest reports (reportlab) |
| `[dev]` | `pip install 'numasec[dev]'` | pytest, mypy, ruff for development |
| `[all]` | `pip install 'numasec[all]'` | MCP + PDF (everything except dev tools) |

---

## Next Steps

1. **Quick Start**: `numasec` → `hack localhost:8080`
2. **Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
3. **MCP Setup**: [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md)
4. **Report Issues**: [GitHub Issues](https://github.com/FrancescoStabile/numasec/issues)
