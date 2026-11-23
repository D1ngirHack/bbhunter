#!/usr/bin/env bash
# Pipeline completo de BBHunter de una sola llamada.
# Uso: bash scripts/run_pipeline.sh [--yes] [--pdf]
set -euo pipefail

cd "$(dirname "$0")/.."

# Activa el venv si existe
[ -f .venv/bin/activate ] && source .venv/bin/activate

bbhunter run "$@"
echo
echo "[*] Abre el panel para triar:  bbhunter dashboard"
