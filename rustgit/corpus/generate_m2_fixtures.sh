#!/usr/bin/env bash
# Recipe for regenerating M2 (delta resolution) differential-test
# fixtures. Not run automatically - fixtures are not vendored into
# this repo (see corpus/README.md). Point RUSTGIT_FIXTURE at the
# resulting directories and run:
#   cargo test --test differential -- --ignored --nocapture
#
# Produces three fixtures under $OUT, each satisfying the harness's
# assert_fixture_is_adversarial guard (deltas present, max depth > 1,
# >=10% of objects deltified):
#   normal/       plain `git repack -a -d -f` - whatever chain depths
#                 git's own heuristics naturally produce. OFS_DELTA
#                 dominant (repack passes --delta-base-offset by default).
#   aggressive/   large --window/--depth to deliberately force deeper
#                 OFS_DELTA chains than a normal repack would produce.
#   ref-delta/    `git pack-objects` invoked directly, WITHOUT
#                 --delta-base-offset, so every delta base is encoded
#                 as a 20-byte oid (REF_DELTA) rather than an offset -
#                 this flavour barely shows up in a plain repack, since
#                 repack's default favors OFS_DELTA for compactness.

set -euo pipefail

SOURCE_REPO_URL="${1:-https://github.com/Byron/gitoxide.git}"
OUT="${2:-/tmp/rustgit-m2-fixtures}"

mkdir -p "$OUT"

echo "== cloning source once, reused for all three variants =="
rm -rf "$OUT/_source"
git clone --depth 200 "$SOURCE_REPO_URL" "$OUT/_source"

echo "== normal repack =="
rm -rf "$OUT/normal"
cp -r "$OUT/_source" "$OUT/normal"
git -C "$OUT/normal" repack -a -d -f -q
git -C "$OUT/normal" verify-pack -v "$OUT"/normal/.git/objects/pack/*.idx | tail -5

echo "== aggressive repack (window=250 depth=250) =="
rm -rf "$OUT/aggressive"
cp -r "$OUT/_source" "$OUT/aggressive"
git -C "$OUT/aggressive" repack -a -d -f -q --window=250 --depth=250
git -C "$OUT/aggressive" verify-pack -v "$OUT"/aggressive/.git/objects/pack/*.idx | tail -5

echo "== ref-delta-only pack (pack-objects, no --delta-base-offset) =="
rm -rf "$OUT/ref-delta"
cp -r "$OUT/_source" "$OUT/ref-delta"
cd "$OUT/ref-delta"
git rev-list --objects --all | git pack-objects .git/objects/pack/pack-refdelta -q
# Remove whatever pack(s) the clone/fetch left behind so exactly one
# .idx remains (find_single_pack_idx requires that).
find .git/objects/pack -name '*.pack' -o -name '*.idx' -o -name '*.rev' | \
  grep -v pack-refdelta | xargs rm -f
git verify-pack -v .git/objects/pack/*.idx | tail -5
cd - >/dev/null

echo "Fixtures ready under $OUT"
echo "Run e.g.:"
echo "  RUSTGIT_FIXTURE=$OUT/normal cargo test --test differential m2_codec_matches_oracle_normal_repack -- --ignored --nocapture"
echo "  RUSTGIT_FIXTURE=$OUT/aggressive cargo test --test differential m2_codec_matches_oracle_aggressive_repack -- --ignored --nocapture"
echo "  RUSTGIT_FIXTURE=$OUT/ref-delta cargo test --test differential m2_codec_matches_oracle_ref_delta_only -- --ignored --nocapture"
