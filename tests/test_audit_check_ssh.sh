#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT/scripts/audit_check.sh"
MOCK_DIR=$(mktemp -d)
trap 'rm -rf "$MOCK_DIR"' EXIT

cat > "$MOCK_DIR/sshd" <<'MOCK'
#!/usr/bin/env bash
if [[ "${1:-}" == "-T" ]]; then
    cat <<'SETTINGS'
permitrootlogin prohibit-password
maxauthtries 5
permitemptypasswords yes
clientaliveinterval 30
clientalivecountmax 0
SETTINGS
    exit 0
fi
exit 2
MOCK
chmod +x "$MOCK_DIR/sshd"

output=$(PATH="$MOCK_DIR:$PATH" "$SCRIPT" | sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g')

check() {
    local expected="$1"
    if [[ "$output" != *"$expected"* ]]; then
        printf 'FAIL: missing expected output: %s\n' "$expected" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

check "[FAIL] PermitRootLogin is 'prohibit-password' for root at localhost (expected: no)"
check "[FAIL] MaxAuthTries is '5' (expected: 1-4)"
check "[FAIL] PermitEmptyPasswords is 'yes' (expected: no)"
check "[FAIL] ClientAliveInterval is '30' (expected: 1-15 seconds)"
check "[FAIL] ClientAliveCountMax is '0' (expected: 1-3)"
check "Audit Summary: 6 Passed, 6 Failed, 2 Warnings"
printf 'PASS: insecure effective SSH values are all flagged by audit_check.sh\n'
