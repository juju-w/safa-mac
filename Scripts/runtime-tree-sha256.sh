#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL

if [ "$#" -ne 1 ] || [ ! -d "$1" ] || [ -L "$1" ]; then
  exit 1
fi

tree_root=$1
if [ -n "$(/usr/bin/find "$tree_root" -type l -print -quit)" ]; then
  exit 1
fi
if [ -n "$(/usr/bin/find "$tree_root" ! -type d ! -type f -print -quit)" ]; then
  exit 1
fi

work_directory=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/safa-tree-sha256.XXXXXX")
cleanup() {
  /bin/rm -rf -- "$work_directory"
}
trap cleanup EXIT HUP INT TERM

file_list="${work_directory}/files"
manifest="${work_directory}/manifest"
(
  CDPATH= cd -- "$tree_root"
  /usr/bin/find . -type f -print | /usr/bin/sort > "$file_list"
  : > "$manifest"
  while IFS= read -r relative_path; do
    /usr/bin/shasum -a 256 "$relative_path" >> "$manifest"
  done < "$file_list"
)

/usr/bin/shasum -a 256 "$manifest" | /usr/bin/awk '{ print $1 }'
