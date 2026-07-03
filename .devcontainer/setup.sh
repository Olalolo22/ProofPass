#!/bin/bash
set -e

echo "Updating Rust and adding Soroban target..."
rustup update stable
rustup target add wasm32-unknown-unknown

echo "Installing SP1 toolchain..."
curl -L https://sp1up.succinct.xyz | bash
export PATH="$HOME/.sp1/bin:$PATH"
sp1up

echo "Installing Stellar CLI..."
cargo install --locked stellar-cli --features opt

echo "✅ Devcontainer setup complete!"
