#!/bin/bash

echo "Adding Soroban target..."
rustup target add wasm32-unknown-unknown || echo "Failed to add target"

echo "Installing SP1 toolchain..."
curl -L https://sp1up.succinct.xyz | bash || echo "Failed to download sp1up"
export PATH="$HOME/.sp1/bin:$PATH"
sp1up || echo "Failed to run sp1up"

echo "Installing Stellar CLI (this might take a while, running in background)..."
# We run this in the background and pipe output to a log so it doesn't block the Codespace startup!
(cargo install --locked stellar-cli --features opt > ~/stellar-cli-install.log 2>&1) &

echo "✅ Devcontainer setup script finished!"
