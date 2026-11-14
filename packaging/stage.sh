#!/bin/bash
# Build nvmetea and stage the install tree used by the RPM and DEB recipes:
#   target/stage/nvmetea-<version>/{usr/bin,usr/share/man/man1,usr/share/*completions*,
#   usr/lib/systemd/system,etc/nvmetea-exporter.env,usr/share/doc/nvmetea,usr/share/licenses/nvmetea}
set -eu
cd "$(dirname "$0")/.."
export PATH=$HOME/.cargo/bin:$PATH
cargo build --release --locked -p nvmetea-cli
V=$(./target/release/nvmetea --version | awk '{print $2}')
S=target/stage/nvmetea-$V
rm -rf "$S"
install -D -m 0755 target/release/nvmetea "$S/usr/bin/nvmetea"
./target/release/nvmetea __man "$S/usr/share/man/man1"
gzip -9n "$S"/usr/share/man/man1/*.1
mkdir -p "$S/usr/share/bash-completion/completions" "$S/usr/share/zsh/site-functions" "$S/usr/share/fish/vendor_completions.d"
./target/release/nvmetea completions bash > "$S/usr/share/bash-completion/completions/nvmetea"
./target/release/nvmetea completions zsh > "$S/usr/share/zsh/site-functions/_nvmetea"
./target/release/nvmetea completions fish > "$S/usr/share/fish/vendor_completions.d/nvmetea.fish"
install -D -m 0644 packaging/systemd/nvmetea-exporter.service "$S/usr/lib/systemd/system/nvmetea-exporter.service"
install -D -m 0644 packaging/systemd/nvmetea-exporter.env "$S/etc/nvmetea-exporter.env"
install -D -m 0644 LICENSE "$S/usr/share/licenses/nvmetea/LICENSE"
install -D -m 0644 NOTICE "$S/usr/share/licenses/nvmetea/NOTICE"
for d in README.md docs/architecture.md docs/latency-model.md docs/kernel-compatibility.md docs/metrics.md docs/troubleshooting.md docs/schema/capture-v1.md docs/schema/capture-v1.schema.json; do
    [ -f "$d" ] && install -D -m 0644 "$d" "$S/usr/share/doc/nvmetea/$(basename "$d")"
done
echo "$S"
