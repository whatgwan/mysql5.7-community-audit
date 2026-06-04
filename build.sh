#!/usr/bin/env bash
# Build login_audit.so locally. CI does this automatically
# this script mirrors that for local builds / testing.
#
# IMPORTANT: build on a toolchain matching the your mysql5.7.x runtime image
# (el7 / glibc 2.17) so the .so is ABI-compatible. Requires gcc-c++
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../deploy/compose/lib/plugin/login_audit.so}"
mkdir -p "$(dirname "$out")"

g++ -Wall -fPIC -shared -DMYSQL_DYNAMIC_PLUGIN -DMYSQL_ABI_CHECK \
    -I "$here" -I /usr/include -I /usr/include/mysql \
    -o "$out" "$here/login_audit.c"

# Sanity gate: a loadable plugin must export this symbol.
nm -D "$out" | grep -q _mysql_plugin_interface_version_
echo "Built: $out"
