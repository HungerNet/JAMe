#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
    python="$VIRTUAL_ENV/bin/python"
elif [[ -x "$script_dir/.venv/bin/python" ]]; then
    python="$script_dir/.venv/bin/python"
elif command -v python3.10 >/dev/null 2>&1; then
    python="$(command -v python3.10)"
else
    printf 'JAMe requires Python 3.10 or newer. Create .venv and install dependencies first.\n' >&2
    exit 1
fi

if ! "$python" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    printf 'JAMe requires Python 3.10 or newer.\n' >&2
    exit 1
fi

PYTHONPATH="$script_dir${PYTHONPATH:+:$PYTHONPATH}" exec "$python" -m jame "$@"