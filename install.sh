#!/usr/bin/env bash
set -euo pipefail

supports_python() {
    "$1" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' >/dev/null 2>&1
}

if [[ -n "${JAME_PYTHON:-}" ]]; then
    python_command="$(command -v "$JAME_PYTHON" || true)"
    if [[ -z "$python_command" ]] || ! supports_python "$python_command"; then
        printf 'JAME_PYTHON must name an installed Python 3.10+ interpreter.\n' >&2
        exit 1
    fi
else
    python_command=''
    for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
        if command -v "$candidate" >/dev/null 2>&1 && supports_python "$candidate"; then
            python_command="$(command -v "$candidate")"
            break
        fi
    done
    if [[ -z "$python_command" ]]; then
        printf 'JAMe requires Python 3.10 or newer. Set JAME_PYTHON to its executable path.\n' >&2
        exit 1
    fi
fi

data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
if [[ "$data_home" != /* ]]; then
    data_home="$HOME/.local/share"
fi
install_dir="${JAME_INSTALL_DIR:-$data_home/jame}"
bin_dir="${JAME_BIN_DIR:-$HOME/.local/bin}"
if [[ "$install_dir" != /* || "$bin_dir" != /* ]]; then
    printf 'JAME_INSTALL_DIR and JAME_BIN_DIR must be absolute paths.\n' >&2
    exit 1
fi

venv_dir="$install_dir/venv"
venv_python="$venv_dir/bin/python"
entrypoint="$venv_dir/bin/jame"
command_path="$bin_dir/jame"

mkdir -p "$install_dir" "$bin_dir"
if [[ ! -x "$venv_python" ]]; then
    "$python_command" -m venv "$venv_dir"
fi
if ! supports_python "$venv_python"; then
    printf 'The existing JAMe environment does not use Python 3.10+. Remove %s and retry.\n' "$venv_dir" >&2
    exit 1
fi

"$venv_python" -m pip install --upgrade pip
"$venv_python" -m pip install --pre --upgrade mapres
"$venv_python" -m pip install --upgrade jame

if [[ -e "$command_path" || -L "$command_path" ]]; then
    if [[ ! -L "$command_path" || "$(readlink "$command_path")" != "$entrypoint" ]]; then
        printf 'Refusing to replace existing command at %s\n' "$command_path" >&2
        exit 1
    fi
fi
ln -sfn "$entrypoint" "$command_path"

path_line="export PATH=\"$bin_dir:\$PATH\""
add_path_line() {
    local startup_file="$1"
    touch "$startup_file"
    if ! grep -qxF -- "$path_line" "$startup_file"; then
        printf '\n%s\n' "$path_line" >> "$startup_file"
    fi
}

add_path_line "$HOME/.profile"
case "${SHELL##*/}" in
    bash) add_path_line "$HOME/.bashrc" ;;
    zsh) add_path_line "$HOME/.zshrc" ;;
esac

path_was_present=false
case ":$PATH:" in
    *":$bin_dir:"*) path_was_present=true ;;
esac
export PATH="$bin_dir:$PATH"
printf 'JAMe installed at %s\n' "$command_path"
"$command_path" --help

if [[ "$path_was_present" == false ]]; then
    printf 'Open a new shell or run: export PATH="%s:$PATH"\n' "$bin_dir"
fi