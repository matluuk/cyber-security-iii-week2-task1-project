#!/bin/bash -eu

# Build script for protocol fuzzing project
# This script builds the fuzzing targets for ClusterFuzzLite using the existing Makefile

cd $SRC/project

# Set environment variables that the Makefile expects
export CC=clang
export CXX=clang++

# Use the existing Makefile to build the fuzzers
echo "Building fuzzing targets using Makefile..."
make fuzz-build

# Move the built fuzzers to the output directory
echo "Moving fuzzers to output directory..."
if [ -f "fuzz_deserialize" ]; then
    mv fuzz_deserialize $OUT/
    echo "✓ fuzz_deserialize moved to $OUT/"
fi

if [ -f "fuzz_roundtrip" ]; then
    mv fuzz_roundtrip $OUT/
    echo "✓ fuzz_roundtrip moved to $OUT/"
fi

# Optional: Copy any seed corpus or dictionaries if they exist
if [ -d "corpus" ]; then
    echo "Copying corpus files..."
    cp -r corpus/* $OUT/ || true
fi

if [ -f "protocol.dict" ]; then
    echo "Copying dictionary..."
    cp protocol.dict $OUT/
fi

echo "Build completed successfully using Makefile!"