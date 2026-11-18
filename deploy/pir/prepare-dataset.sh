#!/bin/sh
# KosherGuard PIR dataset preparation.
# STATUS: UNVERIFIED - never executed as an image; the same flow runs
# on pinned sources in .github/workflows/pir-local-interop.yml.
#
# One-step flow per Apple's pinned NEURLFilter testing instructions
# (pir-service-example @ bbb215355b87be40e081756d072f29cd8f9f000b,
# Sources/PIRService/PIRService.docc/TestingInstructionsNEURLFilter.md):
# Apple's PIRProcessDatabase takes the textpb export plus a JSON config
# and emits the servable shard files directly (sharding is configured
# here, no separate PIRShardDatabase step).
set -eu

INPUT=${1:-/dataset/dataset.txtpb}     # output of url-filter-server pir_export
WORK=${2:-/processed}
SHARD_COUNT=${SHARD_COUNT:-1}
FILE_STEM=${FILE_STEM:-url}

# EXCLUSIVE DEVICE-EXPORT BINDING: only the device-safe export may be
# processed for the NEURLFilter dataset. The generic export_textpb
# output carries allow VERDICTS, and under Apple's device semantics a
# keyword PRESENT in the dataset is BLOCKED - processing the generic
# export would block every explicitly allowed site. The device export
# (pir_export.export_device_textpb) is block-only and stamps this
# first-line marker; refuse anything without it instead of trusting
# an operator to pick the right exporter.
if ! head -n 1 "$INPUT" | grep -q '^# kosherguard-device-export-v1:'; then
    echo "prepare-dataset: refusing input - first line is not the" >&2
    echo "kosherguard device-export marker. Produce the input with" >&2
    echo "pir_export.export_device_textpb (block-only presence rows)," >&2
    echo "never the generic export_textpb (allow rows would block" >&2
    echo "allowed sites on device)." >&2
    exit 1
fi

mkdir -p "$WORK/out"

# Parameter values follow Apple's documented example; production
# parameter selection is an outstanding review item, not decided here.
cat > "$WORK/process-config.json" <<EOF
{
  "inputDatabase": "$INPUT",
  "outputDatabase": "$WORK/out/$FILE_STEM-SHARD_ID.bin",
  "outputPirParameters": "$WORK/out/$FILE_STEM-SHARD_ID.params.txtpb",
  "rlweParameters": "n_4096_logq_27_28_28_logt_5",
  "sharding": {"shardCount": $SHARD_COUNT},
  "trialsPerShard": 5
}
EOF

PIRProcessDatabase "$WORK/process-config.json"

echo "Processed $SHARD_COUNT shard(s) in $WORK/out ($FILE_STEM-<i>.bin +
$FILE_STEM-<i>.params.txtpb). Point the PIRService usecase config at
this directory with fileStem \"$FILE_STEM\" and shardCount $SHARD_COUNT;
the service loads files relative to its working directory. Service
configuration format is defined by the pinned apple/pir-service-example
commit; do not invent fields - copy its documented example and
substitute paths."
