# NumaSec Configuration Guide

NumaSec supports **3 methods** for configuring API keys, with automatic priority resolution.

## 🎯 Best Practices by Scenario

### Scenario 1: Single User Desktop/Laptop (✅ RECOMMENDED)

**Use:** `~/.numasec/config.yaml`

```bash
# First run - Interactive setup
numasec
> 🔧 NumaSec Configuration
> DeepSeek API Key: sk-... 
> Config saved to: ~/.numasec/config.yaml
```

**Advantages:**
- ✅ Setup once, works forever
- ✅ Works everywhere (all projects)
- ✅ Secure (file in home directory, not committed)
- ✅ Works in containers (volume mount)

**Config file:**
```yaml
# ~/.numasec/config.yaml
DEEPSEEK_API_KEY: sk-your-key-here
# ANTHROPIC_API_KEY: sk-ant-...
# OPENAI_API_KEY: sk-...
```

---

### Scenario 2: Container or Server (✅ RECOMMENDED)

**Use:** Environment variables

```bash
# Docker/Podman
docker run -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" numasec

# Shell
export DEEPSEEK_API_KEY="sk-..."
numasec
```

**Advantages:**
- ✅ Works in containers
- ✅ No files to manage
- ✅ Overrides config file (highest priority)
- ✅ Standard approach for server deployments

---

### Scenario 3: Project-Specific with Team

**Use:** `.env` file (in project directory)

```bash
cd /path/to/your/project

# Create .env (DON'T commit it!)
echo "DEEPSEEK_API_KEY=sk-..." > .env
echo ".env" >> .gitignore

# NumaSec finds it automatically
numasec
```

**Advantages:**
- ✅ Each project can use different API key
- ✅ Team members can have their own keys
- ✅ Standard format (python-dotenv, docker-compose, etc)

**Warning:**
- ⚠️ Add `.env` to `.gitignore`!
- ⚠️ Never commit API keys to git

---

## 🔐 Configuration Priority

NumaSec loads configuration in this order (last wins):

```
1. ~/.numasec/config.yaml  (base)
2. .env file               (project override)
3. ENV variables           (runtime override)
```

**Example:**

```bash
# config.yaml contains:
DEEPSEEK_API_KEY: sk-old-key

# .env contains:
DEEPSEEK_API_KEY=sk-project-key

# Shell:
export DEEPSEEK_API_KEY="sk-runtime-key"

# NumaSec will use: sk-runtime-key
```

---

## 🐳 Container Usage

NumaSec container **automatically mounts** `~/.numasec`:

```bash
# Build
./container-build.sh

# Run (automatic config)
./container-run.sh

# First container run:
> 📋 First-time setup detected
> NumaSec will ask for your API key on first run.
> Config will be saved to: ~/.numasec/config.yaml

# Container started:
numasec> hack localhost:3000
# Uses config from ~/.numasec/config.yaml
```

**Advantages:**
- ✅ Setup once, works in container
- ✅ Sessions persist between container runs
- ✅ Findings saved in `~/.numasec/sessions/`
- ✅ No need for `-e API_KEY=...` every time

---

## 📝 File Paths

| File | Purpose | Auto-Created |
|------|---------|--------------|
| `~/.numasec/config.yaml` | API keys persistent | ✅ First run |
| `~/.numasec/sessions/` | Session history | ✅ Auto |
| `.env` | Project-specific keys | ❌ Manual |
| `config.yaml.example` | Template | ❌ Copy manually |

---

## 🔒 Security

### ✅ DO

- Store keys in `~/.numasec/config.yaml` (home directory)
- Add `.env` to `.gitignore`
- Use environment variables in CI/CD
- Use secrets management (GitHub Secrets, Vault, etc)

### ❌ DON'T

- Commit API keys to git
- Share `config.yaml` with others
- Hardcode keys in code
- Store keys in public locations

---

## 🧪 Testing Config

```bash
# Check if config is loaded
numasec

# If you see this = config OK:
╔══════════════════════════════════════╗
║   NumaSec v3.0.0 - AI Pentester      ║
╚══════════════════════════════════════╝

# If you see this = config MISSING:
❌ No API keys configured. Run setup again or edit ~/.numasec/config.yaml

# Interactive setup:
numasec
> Follow prompts

# Manual check:
cat ~/.numasec/config.yaml
```

---

## 🆘 Troubleshooting

### "No API keys configured"

```bash
# Option 1: Interactive setup
numasec
# Follow prompts

# Option 2: Manual config
nano ~/.numasec/config.yaml
# Add: DEEPSEEK_API_KEY: sk-...

# Option 3: ENV variable
export DEEPSEEK_API_KEY="sk-..."
numasec
```

### "Config file not found"

```bash
# Auto-create
mkdir -p ~/.numasec
cp config.yaml.example ~/.numasec/config.yaml
nano ~/.numasec/config.yaml
```

### Container can't find config

```bash
# Verify mount
podman run -it --rm \
  -v "$HOME/.numasec:/root/.numasec" \
  numasec ls -la /root/.numasec

# Should show config.yaml and sessions/
```

---

## 🎓 Examples

### Desktop Developer

```bash
# Setup once
numasec
> DeepSeek API Key: sk-...
> ✅ Config saved

# Use forever
numasec
You: hack localhost:3000
```

### Container User

```bash
# First time
./container-run.sh
> Enter API key: sk-...
> ✅ Config saved to ~/.numasec/config.yaml

# Every time after
./container-run.sh
# Auto-loads from ~/.numasec/config.yaml
```

---

## 🚀 Conclusion

**Best solution = `~/.numasec/config.yaml`**

- Interactive automatic setup on first run
- Works everywhere (native, container, SSH)
- Persistent sessions and config
- Zero friction for the user

**Config priority:**
```
ENV > .env > config.yaml
```

**Get Started:**
```bash
numasec  # Follow automatic setup!
```
