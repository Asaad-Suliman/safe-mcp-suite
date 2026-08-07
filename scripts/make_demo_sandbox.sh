#!/usr/bin/env bash
# Build the throwaway workspace the README demo runs against.
#
# Seeds exactly the five files the Files-server cases need and the one file the
# Terminal-server case needs -- nothing else, since plan_organize walks the
# whole workspace and every extra entry would change its output.
#
#   ./scripts/make_demo_sandbox.sh          # refuses if ./sandbox or ./state exists
#   ./scripts/make_demo_sandbox.sh --force  # removes ./sandbox and ./state, rebuilds both
#
# Paths match policy.example.toml: terminal jail_root = sandbox/terminal,
# files workspace_root = sandbox/files, audit_log/journal live under state/.

set -euo pipefail

cd "$(dirname "$0")/.."

force=0
if [ "${1:-}" = "--force" ]; then
    force=1
elif [ "$#" -gt 0 ]; then
    echo "usage: $0 [--force]" >&2
    exit 2
fi

if [ -e sandbox ] || [ -e state ]; then
    if [ "$force" -eq 1 ]; then
        rm -rf sandbox state
    else
        echo "sandbox/ or state/ already exists. Pass --force to remove and rebuild them." >&2
        exit 1
    fi
fi

mkdir -p sandbox/terminal sandbox/files state

# Terminal jail: the one file `cat notes.txt` reads.
printf 'demo file\n' > sandbox/terminal/notes.txt

# Files workspace. Sizes are load-bearing: plan_organize reports them.
printf 'demo report pdf\n' > sandbox/files/report.pdf                 # 16 bytes
printf 'demo png payload -- forty one bytes long\n' > sandbox/files/photo.png  # 41 bytes
printf 'demo installer\n' > sandbox/files/setup.exe
printf 'demo dotfile\n' > sandbox/files/.bashrc

# A symlink pointing out of workspace_root. The target is never followed
# (inspection is lstat-only), so it deliberately does not exist.
ln -s ../outside-workspace-target sandbox/files/link.pdf

echo "created:"
find sandbox state -mindepth 1 | sort | sed 's/^/  /'
