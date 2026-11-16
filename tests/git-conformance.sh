#!/usr/bin/env bash
# Stock-Git transport smoke test for the standalone and hosted Git listeners.
#
# Local mode starts an isolated listener and repository. Remote mode requires
# an explicitly supplied fixture URL and token. It never discovers or creates
# a production target.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  git-engine/tests/git-conformance.sh local
  git-engine/tests/git-conformance.sh remote <fixture-url>

Local mode builds and starts the standalone server on loopback.

Remote mode requires:
  DENGEL_GIT_TEST_TOKEN       scoped write token for a disposable fixture repo
  DENGEL_GIT_TEST_USER        optional HTTP Basic username (default: dengel)
  DENGEL_GIT_TEST_PUSH_PREFIX optional candidate-only branch prefix
                              (example: refs/heads/candidate/conformance/)
EOF
}

die() {
    printf 'git-conformance: %s\n' "$*" >&2
    exit 1
}

command -v git >/dev/null || die "git is required"
git --version

mode=${1:-}
if [[ "$mode" == "-h" || "$mode" == "--help" || -z "$mode" ]]; then
    usage
    [[ -n "$mode" ]] && exit 0
    exit 2
fi

if [[ "$mode" != "local" && "$mode" != "remote" ]]; then
    usage >&2
    exit 2
fi

if [[ "$mode" == "remote" && $# -ne 2 ]]; then
    usage >&2
    exit 2
fi

if [[ "$mode" == "remote" && -z "${DENGEL_GIT_TEST_TOKEN:-}" ]]; then
    die "DENGEL_GIT_TEST_TOKEN is required in remote mode"
fi

if [[ -n "${DENGEL_GIT_TEST_PUSH_PREFIX:-}" &&
      ! "${DENGEL_GIT_TEST_PUSH_PREFIX}" =~ ^refs/heads/[A-Za-z0-9._/-]+/$ ]]; then
    die "DENGEL_GIT_TEST_PUSH_PREFIX must be a branch namespace ending in /"
fi

engine_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/dengel-git-conformance.XXXXXX")
server_pid=
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# Keep Git behavior reproducible and credentials out of command-line URLs.
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL="$tmp/gitconfig"
export GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME="Dengel Conformance"
export GIT_AUTHOR_EMAIL="conformance@example.invalid"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
git config --global gc.auto 0
git config --global maintenance.auto false
git config --global credential.helper "store --file=$tmp/credentials"

fixture_url=
if [[ "$mode" == "local" ]]; then
    git_bin=${DENGEL_GIT_TEST_BIN:-}
    if [[ -z "$git_bin" ]]; then
        command -v cargo >/dev/null || die "cargo is required in local mode"
        cargo build --quiet --manifest-path "$engine_root/Cargo.toml" --locked --bin dengel-git
        git_bin="$engine_root/target/debug/dengel-git"
    fi
    [[ -x "$git_bin" ]] || die "DENGEL_GIT_TEST_BIN is not executable: $git_bin"
    seed="$tmp/seed"
    git init -q --initial-branch=main "$seed"
    printf 'Dengel Git conformance fixture\n' > "$seed/README.md"
    git -C "$seed" add README.md
    git -C "$seed" commit -q -m "Initialize conformance fixture"

    server_root="$tmp/repos"
    mkdir -p "$server_root"
    mkdir -p "$server_root/AcMe"
    git clone -q --bare "$seed" "$server_root/AcMe/WiDgEt.git"
    # A random loopback port avoids colliding with another local test.
    port_file="$tmp/port"
    python3 - "$port_file" <<'PY'
import socket
import sys

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    open(sys.argv[1], "w", encoding="ascii").write(str(listener.getsockname()[1]))
PY
    port=$(cat "$port_file")
    # Mixed-case canonical aliases must resolve to the same nested repository.
    fixture_url="http://127.0.0.1:$port/aCmE/wIdGeT.git"
    "$git_bin" serve-http --addr "127.0.0.1:$port" --root "$server_root" >"$tmp/server.log" 2>&1 &
    server_pid=$!

    for _ in $(seq 1 300); do
        if git ls-remote "$fixture_url" >/dev/null 2>&1; then
            break
        fi
        kill -0 "$server_pid" 2>/dev/null || {
            cat "$tmp/server.log" >&2
            die "standalone listener exited before becoming ready"
        }
        sleep 0.2
    done
    if ! git ls-remote "$fixture_url" >/dev/null 2>&1; then
        cat "$tmp/server.log" >&2
        die "standalone listener did not become ready"
    fi
else
    fixture_url=$2
    case "$fixture_url" in
        https://*|http://127.0.0.1:*|http://localhost:*)
            ;;
        *)
            die "remote URL must use HTTPS or loopback HTTP"
            ;;
    esac
    host=${fixture_url#*://}
    host=${host%%/*}
    case "${host,,}" in
        dengel.dev|*.dengel.dev)
            die "remote mode refuses the production Dengel domain"
            ;;
    esac
    user=${DENGEL_GIT_TEST_USER:-dengel}
    scheme=${fixture_url%%://*}
    DENGEL_GIT_TEST_USER="$user" DENGEL_GIT_TEST_HOST="$host" DENGEL_GIT_TEST_SCHEME="$scheme" python3 - "$tmp/credentials" <<'PY'
import os
import sys
from urllib.parse import quote

user = quote(os.environ["DENGEL_GIT_TEST_USER"], safe="")
token = quote(os.environ["DENGEL_GIT_TEST_TOKEN"], safe="")
host = os.environ["DENGEL_GIT_TEST_HOST"]
scheme = os.environ["DENGEL_GIT_TEST_SCHEME"]
with open(sys.argv[1], "w", encoding="utf-8") as credentials:
    credentials.write(f"{scheme}://{user}:{token}@{host}\n")
PY
    chmod 600 "$tmp/credentials"
fi

source_repo="$tmp/source"
git clone -q "$fixture_url" "$source_repo"
original_main=$(git -C "$source_repo" rev-parse refs/remotes/origin/main)

branch=stock-conformance/$$
if [[ -n "${DENGEL_GIT_TEST_PUSH_PREFIX:-}" ]]; then
    prefix=${DENGEL_GIT_TEST_PUSH_PREFIX#refs/heads/}
    prefix=${prefix%/}
    branch="$prefix/$branch"
fi
git -C "$source_repo" switch -q -c "$branch"
printf 'First stock Git push\n' > "$source_repo/conformance.txt"
git -C "$source_repo" add conformance.txt
git -C "$source_repo" commit -q -m "Add conformance fixture"
first=$(git -C "$source_repo" rev-parse HEAD)
git -C "$source_repo" push -q origin "HEAD:refs/heads/$branch"

# A second commit and fetch exercise incremental negotiation and thin-pack
# reception. Candidate-only hosted tokens stay within the configured prefix.
printf 'Incremental stock Git fetch and push\n' >> "$source_repo/conformance.txt"
git -C "$source_repo" commit -q -am "Extend conformance fixture"
second=$(git -C "$source_repo" rev-parse HEAD)
git -C "$source_repo" push -q origin "HEAD:refs/heads/$branch"

# Two independent refs are updated in a single stock `git push --atomic`.
# Hosted tokens use candidate namespaces for both updates; local mode accepts
# ordinary refs. Keeping the source tips distinct proves both updates landed.
atomic_branch="${branch}-atomic"
git -C "$source_repo" switch -q -c "$atomic_branch"
printf 'Atomic side ref\n' > "$source_repo/atomic-side.txt"
git -C "$source_repo" add atomic-side.txt
git -C "$source_repo" commit -q -m "Add atomic side ref"
atomic_side=$(git -C "$source_repo" rev-parse HEAD)
git -C "$source_repo" switch -q "$branch"
printf 'Atomic main ref\n' > "$source_repo/atomic-main.txt"
git -C "$source_repo" add atomic-main.txt
git -C "$source_repo" commit -q -m "Advance atomic primary ref"
atomic_main=$(git -C "$source_repo" rev-parse HEAD)
git -C "$source_repo" push -q --atomic origin \
    "HEAD:refs/heads/$branch" \
    "refs/heads/$atomic_branch:refs/heads/$atomic_branch"

# Fetch into a new clone after the atomic push so the advertised result is
# independently checked from the server's visible refs and complete objects.
atomic_observer="$tmp/atomic-observer"
git clone -q "$fixture_url" "$atomic_observer"
main_snapshot="refs/conformance/atomic-main-$$"
side_snapshot="refs/conformance/atomic-side-$$"
git -C "$atomic_observer" fetch -q origin \
    "refs/heads/$branch:$main_snapshot" \
    "refs/heads/$atomic_branch:$side_snapshot"
fetched_main=$(git -C "$atomic_observer" rev-parse "$main_snapshot")
fetched_side=$(git -C "$atomic_observer" rev-parse "$side_snapshot")
[[ "$fetched_main" == "$atomic_main" ]] || die "atomic primary ref is $fetched_main, expected $atomic_main"
[[ "$fetched_side" == "$atomic_side" ]] || die "atomic side ref is $fetched_side, expected $atomic_side"
git -C "$atomic_observer" fsck --full --strict

if [[ -z "${DENGEL_GIT_TEST_PUSH_PREFIX:-}" ]]; then
    tag="conformance-$$"
    git -C "$source_repo" tag -a "$tag" -m "Conformance tag"
    git -C "$source_repo" push -q origin "refs/tags/$tag"
    git -C "$atomic_observer" fetch -q --tags origin
    tagged=$(git -C "$atomic_observer" rev-parse "$tag^{}")
    [[ "$tagged" == "$atomic_main" ]] || die "tag points to $tagged, expected $atomic_main"
    git -C "$atomic_observer" fsck --full --strict
fi

printf 'PASS: clone, incremental push/fetch, and strict fsck (%s)\n' "$atomic_main"
printf 'PASS: atomic two-ref push and fresh clone/fetch verification\n'
if [[ "$mode" == "local" ]]; then
    printf 'PASS: mixed-case nested organization/repository URL alias\n'
fi
if [[ -n "${DENGEL_GIT_TEST_PUSH_PREFIX:-}" ]]; then
    printf 'PASS: all writes stayed under %s\n' "$DENGEL_GIT_TEST_PUSH_PREFIX"
else
    printf 'PASS: annotated tag push and fetch\n'
fi

# Ensure a scoped hosted credential could not write outside its allowed
# candidate namespace. The server must report the rejected update.
if [[ -n "${DENGEL_GIT_TEST_PUSH_PREFIX:-}" ]]; then
    printf 'This atomic batch must be rejected\n' >> "$source_repo/conformance.txt"
    git -C "$source_repo" commit -q -am "Prepare rejected atomic batch"
    rejected_head=$(git -C "$source_repo" rev-parse HEAD)
    if git -C "$source_repo" push -q --atomic origin \
        "HEAD:refs/heads/$branch" "HEAD:refs/heads/main" 2>"$tmp/out-of-scope.log"; then
        die "candidate-only credential unexpectedly updated a candidate and main atomically"
    fi
    rg -q 'remote rejected|pre-receive hook declined|candidate' "$tmp/out-of-scope.log" ||
        die "out-of-scope push failed without a recognizable rejection"
    remote_refs=$(git -C "$source_repo" ls-remote origin "refs/heads/$branch" refs/heads/main)
    remote_candidate=$(printf '%s\n' "$remote_refs" | awk -v ref="refs/heads/$branch" '$2 == ref {print $1}')
    remote_main=$(printf '%s\n' "$remote_refs" | awk '$2 == "refs/heads/main" {print $1}')
    [[ "$remote_candidate" == "$atomic_main" ]] ||
        die "rejected atomic batch partially advanced candidate to $remote_candidate (expected $atomic_main; attempted $rejected_head)"
    [[ "$remote_main" == "$original_main" ]] ||
        die "rejected atomic batch unexpectedly changed main to $remote_main"
    printf 'PASS: candidate-only token rejected atomic candidate/main batch without partial ref updates\n'
fi
