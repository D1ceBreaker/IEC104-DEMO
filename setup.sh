#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Create / refresh virtual environment and install dependencies.
python3.9 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt