#!/bin/sh
# Refreshes the vendored Public Suffix List the config crate compiles in.
#
# The list (crates/config/data/public_suffix_list.dat) drives
# selfhost_config::psl::registrable — which apex a name belongs to — for zone
# derivation and registrar sync alike. Mozilla updates it a few times a year;
# run this, check `cargo test -p selfhost-config psl`, and commit the diff.
set -eu

dest="$(dirname "$0")/../crates/config/data/public_suffix_list.dat"
url="https://publicsuffix.org/list/public_suffix_list.dat"

curl -fsS "$url" -o "$dest.tmp"
grep -q "===BEGIN ICANN DOMAINS===" "$dest.tmp" || {
    echo "downloaded file does not look like the Public Suffix List; keeping the old one" >&2
    rm -f "$dest.tmp"
    exit 1
}
mv "$dest.tmp" "$dest"
echo "updated $(wc -c < "$dest" | tr -d ' ') bytes: $dest"
