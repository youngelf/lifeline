# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.
#
# Shell prompt helper for bash and zsh.
#
# Usage in ~/.bashrc:
#   source /usr/share/lifeline/shell/lifeline-prompt.sh
#   PS1='$(lifeline_ps1 --bash --color) \u@\h:\w\$ '
#
# Usage in ~/.zshrc:
#   source /usr/share/lifeline/shell/lifeline-prompt.sh
#   setopt PROMPT_SUBST
#   PROMPT='$(lifeline_ps1 --zsh --color) %n@%m:%~%# '

lifeline_ps1() {
    local shell_arg="plain"
    local color_arg=""
    local stopped_arg=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --bash) shell_arg="bash" ;;
            --zsh) shell_arg="zsh" ;;
            --color) color_arg="--color" ;;
            --show-stopped) stopped_arg="--show-stopped" ;;
        esac
        shift
    done

    # Fast-exit when status file does not exist and --show-stopped was not asked.
    if [ ! -r /run/lifeline/status.json ] && [ -z "$stopped_arg" ]; then
        return 0
    fi

    if command -v lifelinectl >/dev/null 2>&1; then
        lifelinectl prompt --shell "$shell_arg" $color_arg $stopped_arg 2>/dev/null || true
    fi
}
