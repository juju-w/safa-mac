#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tree_hasher="${repository_root}/Scripts/runtime-tree-sha256.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/safa-runtime-tree-test.XXXXXX")

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

[ -x "$tree_hasher" ]
sh -n "$tree_hasher"

first_app="${test_root}/first/SAFA.app"
second_app="${test_root}/second/SAFA.app"
mkdir -p "${first_app}/Contents/MacOS" "${first_app}/Contents/Resources"
printf '%s\n' 'synthetic executable' > "${first_app}/Contents/MacOS/safa"
printf '%s\n' 'synthetic resource' > "${first_app}/Contents/Resources/value.txt"
mkdir -p "$(dirname -- "$second_app")"
cp -R "$first_app" "$second_app"

first_digest=$($tree_hasher "$first_app")
second_digest=$($tree_hasher "$second_app")
printf '%s\n' "$first_digest" | grep -Eq '^[0-9a-f]{64}$'
[ "$first_digest" = "$second_digest" ]

printf '%s\n' 'changed resource' > "${second_app}/Contents/Resources/value.txt"
[ "$($tree_hasher "$second_app")" != "$first_digest" ]

ln -s value.txt "${second_app}/Contents/Resources/link.txt"
if $tree_hasher "$second_app" >/dev/null 2>&1; then
  printf '%s\n' 'tree hasher accepted a symbolic link' >&2
  exit 1
fi
rm "${second_app}/Contents/Resources/link.txt"

mkfifo "${second_app}/Contents/Resources/special"
if $tree_hasher "$second_app" >/dev/null 2>&1; then
  printf '%s\n' 'tree hasher accepted a special filesystem node' >&2
  exit 1
fi

printf '%s\n' 'Runtime tree SHA-256 contract passed.'
