#!/usr/bin/env bash
# Package crates for crates.io WITHOUT the registry build, for a graph that
# pins a dependency to git through `[patch.crates-io]`.
#
#   PINS="<git crates, one per line, from cargo tree>" \
#     scripts/package-git-pinned-crates.sh <title> [cargo package flags...] -- <crate>...
#
# `cargo package` drops `[patch]`, so a verify would compile against the
# registry's version of the pinned crate, a build that tests a dependency the
# tree does not use. This packages with `--no-verify`, which still checks each
# crate's metadata and that every path dependency names a version.
#
# Packaging still resolves every dependency against crates.io. A crate whose
# graph needs a pinned crate that has NO release there yet (vitaminc-normalize
# before vitaminc 0.6) cannot be packaged at all; that crate is left out with a
# warning and the rest are packaged without it. Any other failure fails the
# step. None of this weakens the release: `cargo publish` verifies against the
# registry and refuses these crates until the pins are registry versions.
set -euo pipefail

title="$1"
shift
flags=()
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
  flags+=("$1")
  shift
done
[ "$#" -gt 0 ] || { echo "usage: $0 <title> [flags...] -- <crate>..." >&2; exit 2; }
shift
remaining=("$@")

pinned_names="$(awk '{print $1}' <<<"${PINS:?PINS must list the git-pinned crates}" | sort -u)"
printf 'Built against git, so not verifiable against the registry:\n%s\n' "$PINS"
echo "::warning title=${title} not verified against the registry::They build against $(wc -l <<<"$PINS" | tr -d ' ') crate(s) pinned to git ([patch.crates-io]), which cargo package ignores, so the registry build was skipped and only the packaging was checked. The publish refuses them until the pins are registry versions."

while [ "${#remaining[@]}" -gt 0 ]; do
  args=()
  for crate in "${remaining[@]}"; do
    args+=(-p "$crate")
  done
  status=0
  out="$(cargo package --locked --no-verify --allow-dirty "${flags[@]}" "${args[@]}" 2>&1)" || status=$?
  printf '%s\n' "$out"
  [ "$status" -eq 0 ] && exit 0

  missing="$(sed -nE 's/.*no matching package named `([^`]+)` found.*/\1/p' <<<"$out" | head -n 1)"
  needer="$(sed -nE 's/.*required by package `([^ ]+) v.*/\1/p' <<<"$out" | head -n 1)"
  if [ -z "$missing" ] || [ -z "$needer" ] || ! grep -qxF "$missing" <<<"$pinned_names"; then
    echo "::error title=${title} failed to package::cargo package failed for a reason other than an unreleased git-pinned dependency; see the log above."
    exit "$status"
  fi
  kept=()
  for crate in "${remaining[@]}"; do
    [ "$crate" = "$needer" ] || kept+=("$crate")
  done
  if [ "${#kept[@]}" -eq "${#remaining[@]}" ]; then
    echo "::error title=${title} failed to package::${needer} needs ${missing}, which has no crates.io release, but ${needer} is not one of the crates being packaged."
    exit "$status"
  fi
  echo "::warning title=${needer} not packaged::${needer} needs ${missing}, pinned to git and not yet released on crates.io, so it cannot be packaged until that release."
  remaining=("${kept[@]+"${kept[@]}"}")
done
