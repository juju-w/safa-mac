#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  cat <<'EOF'
Usage: Scripts/scan-secrets.sh [--repository PATH] [--artifact ZIP]

Scan tracked source and an optional candidate archive for high-confidence signing or service secrets.
Only rule names and file paths are reported; matched values are never printed.
EOF
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
artifact_path=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository)
      [ "$#" -ge 2 ] || fail "--repository requires a value"
      repository_root="$2"
      shift 2
      ;;
    --artifact)
      [ "$#" -ge 2 ] || fail "--artifact requires a value"
      artifact_path="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) fail "unexpected argument: $1" ;;
  esac
done

/usr/bin/git -C "$repository_root" rev-parse --git-dir >/dev/null 2>&1 \
  || fail "--repository must identify a Git repository"
if [ -n "$artifact_path" ]; then
  [ -f "$artifact_path" ] && [ ! -L "$artifact_path" ] \
    || fail "--artifact must identify a regular zip file"
fi

rules='private-key|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----
github-token|gh[pousr]_[A-Za-z0-9]{36,}
aws-access-key|AKIA[0-9A-Z]{16}
slack-token|xox[baprs]-[A-Za-z0-9-]{20,}
private-ipv4|(^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$)
url-userinfo|https?://[^/@[:space:]:]+:[^/@[:space:]]+@'
failed=0

scan_git_rule() {
  rule_name=$1
  pattern=$2
  matches=$(/usr/bin/git -C "$repository_root" grep -Il -E -- "$pattern" -- 2>/dev/null || true)
  if [ -n "$matches" ]; then
    printf '%s\n' "error: ${rule_name} material found in tracked source:" >&2
    printf '%s\n' "$matches" >&2
    failed=1
  fi
}

while IFS='|' read -r rule_name pattern; do
  [ -n "$rule_name" ] || continue
  scan_git_rule "$rule_name" "$pattern"
done <<EOF
$rules
EOF

tracked_sensitive_names=$(/usr/bin/git -C "$repository_root" ls-files \
  | /usr/bin/grep -Ei '\.(p12|p8|mobileprovision|provisionprofile|key|pem)$' || true)
if [ -n "$tracked_sensitive_names" ]; then
  printf '%s\n' 'error: signing or private-key file found in tracked source:' >&2
  printf '%s\n' "$tracked_sensitive_names" >&2
  failed=1
fi

scan_extracted_rule() {
  scan_root=$1
  rule_name=$2
  pattern=$3
  matches=$(/usr/bin/grep -IlR -E -- "$pattern" "$scan_root" 2>/dev/null || true)
  if [ -n "$matches" ]; then
    printf '%s\n' "error: ${rule_name} material found in candidate artifact:" >&2
    printf '%s\n' "$matches" >&2
    failed=1
  fi
}

if [ -n "$artifact_path" ]; then
  scan_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/safa-secret-scan.XXXXXX")
  cleanup() {
    /bin/rm -rf -- "$scan_root"
  }
  trap cleanup EXIT HUP INT TERM
  /usr/bin/ditto -x -k "$artifact_path" "$scan_root"
  [ -z "$(/usr/bin/find "$scan_root" -type l -print -quit)" ] \
    || fail "candidate archive contains a symbolic link"

  sensitive_names=$(/usr/bin/find "$scan_root" -type f \
    \( -iname '*.p12' -o -iname '*.p8' -o -iname '*.key' -o -iname '*.pem' \) -print)
  if [ -n "$sensitive_names" ]; then
    printf '%s\n' 'error: signing or private-key file found in candidate artifact:' >&2
    printf '%s\n' "$sensitive_names" >&2
    failed=1
  fi

  while IFS='|' read -r rule_name pattern; do
    [ -n "$rule_name" ] || continue
    scan_extracted_rule "$scan_root" "$rule_name" "$pattern"
  done <<EOF
$rules
EOF
fi

[ "$failed" -eq 0 ] || exit 1
printf '%s\n' 'Secret scan passed.'
