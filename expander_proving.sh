#!/bin/bash

set -e

# Configuration
EXPANDER_REPO="https://github.com/PolyhedraZK/Expander.git"
EXPANDER_DIR="Expander"

BUILD_DIR="build"
CIRCUIT_FILE="build/circuit.txt"
WITNESS_FILE="build/witness.txt"
PROOF_FILE="build/proof.bin"


# Create "build" directory
if [ ! -d "$BUILD_DIR" ]; then
  echo "Creating build directory..."
  mkdir build
fi

# Step 1: Compile the circuit & get artifacts
echo "Step 1: Compiling the circuit..."
cargo r --release

# Step 2: Clone the Expander repository if it doesn't exist
if [ ! -d "$EXPANDER_DIR" ]; then
  echo "Step 2: Cloning the Expander repository..."
  git clone $EXPANDER_REPO
  cd $EXPANDER_DIR
  cargo run --bin=dev-setup --release
  cd -
fi

# Step 3: Run the Expander prover
echo "Step 3: Running the Expander prover..."
cd $EXPANDER_DIR
RUSTFLAGS="-C target-cpu=native" cargo run --bin expander-exec --release -- \
    -p Orion prove \
    -c ../$CIRCUIT_FILE \
    -w ../$WITNESS_FILE \
    -o ../$PROOF_FILE
cd - 

# Step 4: Run the Expander verifier
echo "Step 4: Running the Expander verifier..."
cd $EXPANDER_DIR
RUSTFLAGS="-C target-cpu=native" cargo run --bin expander-exec --release -- \
    -p Orion verify \
    -c ../$CIRCUIT_FILE \
    -w ../$WITNESS_FILE \
    -i ../$PROOF_FILE
cd -
