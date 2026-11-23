#!/usr/bin/env bash
# Instala las herramientas OSS de bug bounty en Kali Linux / Debian.
# Uso: bash scripts/install_tools.sh
set -euo pipefail

echo "[*] BBHunter — instalacion de herramientas (Kali/Debian)"

# --- Dependencias de sistema ---
if command -v apt >/dev/null 2>&1; then
  sudo apt update
  sudo apt install -y golang-go python3-venv python3-pip \
       libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev  # weasyprint (PDF)
fi

# --- Herramientas Go de ProjectDiscovery / dalfox ---
export GOBIN="${HOME}/go/bin"
mkdir -p "${GOBIN}"
case ":$PATH:" in *":${GOBIN}:"*) ;; *) export PATH="${PATH}:${GOBIN}";; esac

go_install () {
  echo "[*] instalando $1"
  go install "$2@latest"
}

go_install subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder
go_install httpx     github.com/projectdiscovery/httpx/cmd/httpx
go_install naabu     github.com/projectdiscovery/naabu/v2/cmd/naabu
go_install nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei
go_install dalfox    github.com/hahwul/dalfox/v2

# Plantillas de nuclei
if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates || true
fi

echo "[*] Anade esto a tu ~/.bashrc si no lo tienes:"
echo '    export PATH="$PATH:$HOME/go/bin"'

# --- Entorno Python de BBHunter ---
echo "[*] creando entorno virtual Python"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[pdf]"

echo "[*] Listo. Recuerda:"
echo "    1) source .venv/bin/activate"
echo "    2) bbhunter init   (y edita config/scope.yaml y config/settings.yaml)"
echo "    3) export ANTHROPIC_API_KEY=sk-ant-..."
