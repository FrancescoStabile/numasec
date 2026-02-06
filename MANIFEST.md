# MANIFEST.in - Package Data Files
#
# This file tells setuptools/hatchling which non-Python files to include
# in the package distribution (wheel and sdist).

# Documentation
include README.md
include LICENSE
include CHANGELOG.md
include INSTALL.md
include CONTRIBUTING.md
include SECURITY.md

# Knowledge base (critical for prompts)
recursive-include src/numasec/knowledge *.md
recursive-include src/numasec/knowledge *.txt
recursive-include src/numasec/knowledge *.json

# System prompts
recursive-include src/numasec/prompts *.md
recursive-include src/numasec/prompts *.txt


# Exclude compiled Python files
global-exclude __pycache__
global-exclude *.py[cod]
global-exclude *$py.class

# Exclude cache and temp files
global-exclude .DS_Store
global-exclude *.swp
global-exclude *.swo
global-exclude *~

# Exclude development files
exclude .gitignore
exclude .gitattributes
exclude pytest.ini
exclude .pre-commit-config.yaml
recursive-exclude tests *
recursive-exclude scripts *
recursive-exclude docs/notes *

# Exclude build artifacts
recursive-exclude build *
recursive-exclude dist *
recursive-exclude *.egg-info *
