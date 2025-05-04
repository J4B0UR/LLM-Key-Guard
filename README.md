<!-- Banner em estilo ASCII art -->
<p align="center">
  <img src="assets/banner.PNG" alt="LLM Key Guard Logo" width="100%"/>
</p>

<p align="center">
  <b>LLM KEY GUARD - by Jabour</b><br>
  <i>Find exposed LLM API keys in your codebase</i>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/version-1.0.0-green" alt="Version"></a>
  <a href="#"><img src="https://img.shields.io/badge/python-3.8+-blue" alt="Python"></a>
  <a href="#"><img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/developed%20by-Jabour-orange" alt="Developed by"></a>
</p>

<p align="center">
  A powerful security tool that detects and validates exposed AI API keys in your codebase.
</p>

---

## 📊 Alarming Statistics
- In 2023, more than 20,000 OpenAI API keys were exposed in public GitHub repositories
- Key exposures have resulted in unexpected costs of thousands of dollars for developers
- Many teams don't realize an exposure until they receive significant charges

## ✨ Key Features

### 🔍 Detection Capabilities
- **Multiple Sources**: Codebase, git history, and Slack channels
- **Provider Coverage**: All major AI providers (OpenAI, Anthropic, Google, etc.)
- **Pattern Recognition**: Advanced regex patterns for accurate detection
- **Git Integration**: Search current files, historical commits, and branch diffs
- **High Entropy Analysis**: Find generic high-entropy tokens that may be keys

### ✅ Validation & Security
- **API Validation**: Verify if found keys are active without causing charges
- **Zero External Dependency**: Keys never leave your system
- **Secure Configuration**: Store config in `.env` files
- **Environment Recognition**: Respects `.gitignore` files and exclusions

### 📈 Reporting & Integration
- **Rich Console Output**: Detailed, color-coded findings
- **Multiple Export Formats**: JSON reports for further processing
- **Slack Integration**: Send alerts directly to your channels
- **CI/CD Integration**: GitHub Actions and GitLab CI support
- **Python API**: Use as a library in your security tools

## 📋 Table of Contents

- [Supported Providers](#supported-providers)
- [Installation](#installation)
- [Quick Usage](#quick-usage)
- [Configuration](#configuration)
- [Command Reference](#command-reference)
- [Examples](#examples)
- [Recent Improvements](#recent-improvements)
- [CI/CD Integration](#cicd-integration)
- [Contributing](#contributing)
- [License](#license)

## Supported Providers

LLM Key Guard detects API keys from the following providers:

| Provider | Detection | Validation |
|----------|-----------|------------|
| OpenAI | ✅ | ✅ |
| Anthropic | ✅ | ✅ |
| Google Gemini | ✅ | ✅ |
| Hugging Face | ✅ | ✅ |
| Cohere | ✅ | ✅ |
| Mistral AI | ✅ | ✅ |
| Stability AI | ✅ | ✅ |
| Replicate | ✅ | ✅ |
| Azure OpenAI | ✅ | ✅ |
| Groq | ✅ | ✅ |
| Together AI | ✅ | ✅ |
| AI21 | ✅ | ✅ |
| DeepInfra | ✅ | ✅ |
| Aleph Alpha | ✅ | ✅ |
| Clarifai | ✅ | ✅ |
| Generic (high entropy) | ✅ | ❌ |

## 🚀 Installation

```bash
# Install from PyPI
pip install llm-key-guard
```

Or clone the repository and install locally:

```bash
# Clone the repository
git clone https://github.com/gjabour/llm-key-guard.git
cd llm-key-guard

# Install
pip install .
```

## 🔍 Quick Usage

### Scanning Modes

LLM Key Guard offers multiple scanning modes to cover all your security needs:

#### 1. Directory Scanning
Scan your codebase for exposed API keys:

```bash
# Scan current directory
llm-key-guard scan .

# Scan specific directory
llm-key-guard scan /path/to/project

# Validate found keys
llm-key-guard scan . --validate
```

#### 2. Git History Scanning
Find keys exposed in historical commits:

```bash
# Scan current repository history
llm-key-guard git-history

# Scan specific repository
llm-key-guard git-history /path/to/repo

# Limit scan to recent commits
llm-key-guard git-history --max-commits 50
```

#### 3. Git Diff Scanning
Compare branches to detect newly added keys:

```bash
# Compare current branch with main
llm-key-guard git-diff --base main

# Compare specific branches
llm-key-guard git-diff --base main --compare feature/new-feature
```

### Python API

```python
from llm_key_guard.scanner import scan_directory
from llm_key_guard.validator import KeyValidator
from llm_key_guard.reporter import create_console_report

# Scan directory
findings = list(scan_directory(
    "/path/to/project",
    max_workers=4,
    use_cache=True,
))

# Validate keys
validator = KeyValidator()
findings = validator.validate_findings(findings)

# Generate report
create_console_report(findings, validated=True)
```

## ⚙️ Configuration

### Integration Setup

For Slack and other integrations, configure the API keys:

1. **Run setup command**:
   ```bash
   llm-key-guard setup
   ```

2. **Edit the `.env` file**:
   ```
   # Slack integration
   SLACK_API_TOKEN=xoxb-xxxxxxxxxx-xxxxxxxxxxxxx
   
   # GitHub integration
   GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
   ```

3. **Validate your configuration**:
   ```bash
   llm-key-guard setup --validate
   ```

### Advanced Configuration File

Create a `.llm-key-guard.yaml` file in your project root:

```yaml
# LLM Key Guard Configuration
scan:
  ignore_git: true
  exclude_extensions:
    - .jpg
    - .png
    - .mp4
  exclude_dirs:
    - node_modules
    - venv
    - .git

validation:
  enabled: true
  timeout: 5  # seconds

reporting:
  min_confidence: medium  # low, medium, high
  
notifications:
  slack:
    enabled: false
    token: ${SLACK_TOKEN}  # Use environment variable
    channel: "#security"
```

## 🛠️ Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Scan for API keys in files, Slack or GitHub | `llm-key-guard scan .` |
| `git-history` | Scan git history for API keys | `llm-key-guard git-history` |
| `git-diff` | Scan git diff between branches | `llm-key-guard git-diff --base main` |
| `setup` | Create configuration files | `llm-key-guard setup` |
| `version` | Show version information | `llm-key-guard version` |
| `help` | Show detailed help | `llm-key-guard help` |

Common options:
- `--validate`: Validate found keys against provider APIs
- `--json FILE`: Export results to JSON file
- `--slack-report`: Send report to Slack channel
- `--severity`: Set minimum confidence level (low, medium, high)

For command-specific help:
```bash
llm-key-guard [command] --help
```

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: LLM Key Guard Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install llm-key-guard
    - name: Scan for leaked API keys
      run: |
        llm-key-guard scan --validate
```

### GitLab CI

```yaml
llm-key-guard:
  stage: test
  image: python:3.10
  script:
    - pip install llm-key-guard
    - llm-key-guard scan --validate
  only:
    - merge_requests
```

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for more details.

<p align="center">
  <a href="https://linkedin.com/in/yourprofile">LinkedIn</a> •
</p>