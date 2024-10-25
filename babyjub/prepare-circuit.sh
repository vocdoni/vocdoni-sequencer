#!/bin/bash

# check if the circuit is provided and exists
CIRCUIT="$1"
if [ -z "$CIRCUIT" ]; then
    echo "Please provide the path to the circom circuit file"
    exit 1
fi

# if artifacts directory is not provided, use the default one
if [ -z "$2" ]; then
    ARTIFACTS_DIR="$PWD/artifacts"
fi
if [ ! -d "$ARTIFACTS_DIR" ]; then
    mkdir "$ARTIFACTS_DIR"
fi

# check if npm is installed
if [ ! command -v npm &> /dev/null ]; then
    echo "npm is not installed"
    exit 1
fi

# check if cargo is installed
if [ ! command -v cargo &> /dev/null ]; then
    echo "npm is not installed"
    exit 1
fi

# check if circom is installed
if [ ! command -v circom --version &> /dev/null ]; then
    echo "circom is not installed, installing..."
    git clone https://github.com/iden3/circom.git
    cd circom
    cargo build --release
    cargo install --path circom
    circom --version
fi

# check if snarkjs is installed
if [ ! command -v snarkjs &> /dev/null ]; then
    echo "snarkjs is not installed, installing..."
    npm install -g snarkjs
fi

# install circomlib
npm install circomlib

# compile the circuit
circom $CIRCUIT --r1cs --wasm --sym -o $ARTIFACTS_DIR

# check if ptau file exists, if not download it from https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_20.ptau
if [ ! -f "$ARTIFACTS_DIR/ptau" ]; then
    echo "Downloading ptau file..."
    wget https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_12.ptau -O $ARTIFACTS_DIR/ptau
fi

# generate the trusted setup
NAME=$(basename $CIRCUIT .circom)
R1CS=$ARTIFACTS_DIR/$NAME.r1cs
snarkjs groth16 setup $R1CS $ARTIFACTS_DIR/ptau $ARTIFACTS_DIR/$NAME\_pkey.zkey

# export the verification key
snarkjs zkey export verificationkey $ARTIFACTS_DIR/$NAME\_pkey.zkey $ARTIFACTS_DIR/$NAME\_vkey.json

# mv wasm from $ARTIFACTS/$NAME_js/$NAME.wasm to $ARTIFACTS/$NAME.wasm
mv $ARTIFACTS_DIR/$NAME\_js/$NAME.wasm $ARTIFACTS_DIR/$NAME.wasm

# clean up
rm -rf ./node_modules package-lock.json package.json $ARTIFACTS_DIR/$NAME\_js