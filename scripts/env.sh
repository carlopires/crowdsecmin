# Source this before building the musl target: ring needs a musl C compiler.
# Install once with: sudo apt-get install musl-tools
if ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1 && command -v musl-gcc >/dev/null 2>&1; then
    mkdir -p "$HOME/bin"
    ln -sf "$(command -v musl-gcc)" "$HOME/bin/x86_64-linux-musl-gcc"
fi
export PATH="$HOME/bin:$PATH"
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-musl-gcc}"
export AR_x86_64_unknown_linux_musl="${AR_x86_64_unknown_linux_musl:-ar}"
