#!/bin/sh
# KosherGuard PIR dataset preparation.
# STATUS: UNVERIFIED - never executed (no Swift toolchain here); each
# step is Apple's documented tooling, not our crypto.
#
# Pipeline: our textpb export -> Apple PIRShardDatabase -> Apple
# PIRProcessDatabase -> processed shards the PIRService serves.
# See apple/swift-homomorphic-encryption docs (PIRShardDatabase,
# PIRProcessDatabase) and apple/pir-service-example for service config.
set -eu

INPUT=${1:-/dataset/dataset.txtpb}     # output of url-filter-server pir_export
WORK=${2:-/processed}
SHARD_COUNT=${SHARD_COUNT:-16}

mkdir -p "$WORK/shards" "$WORK/out"

# 1. Split into disjoint shards (Apple PIRShardDatabase).
PIRShardDatabase \
    --input-database "$INPUT" \
    --output-database-prefix "$WORK/shards/shard-" \
    --shard-count "$SHARD_COUNT"

# 2. Process each shard into the servable PIR database (Apple
#    PIRProcessDatabase). Parameters (encryption/RLWE config) come from
#    Apple's documented defaults for keyword PIR; production parameter
#    selection is an outstanding review item, not decided here.
for shard in "$WORK"/shards/shard-*; do
    name=$(basename "$shard")
    PIRProcessDatabase \
        --input-database "$shard" \
        --output-database "$WORK/out/$name.pbtxt" \
        --output-evaluation-key-config "$WORK/out/$name.evalkey"
done

echo "Processed shards in $WORK/out - point the PIRService usecase
config at this directory. Service configuration format is defined by
the pinned apple/pir-service-example commit; do not invent fields -
copy its example config and substitute paths."
