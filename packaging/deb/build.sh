#!/bin/bash
# Build a .deb from the staged tree (run on Debian/Ubuntu: needs dpkg-deb).
# Not yet exercised on a Debian/Ubuntu builder: see docs/validation/phase-5.md.
set -eu
cd "$(dirname "$0")/../.."
command -v dpkg-deb >/dev/null || { echo "dpkg-deb not found (build on Debian/Ubuntu)" >&2; exit 2; }
S=$(packaging/stage.sh | tail -1)
V=${S##*-}
ARCH=$(dpkg --print-architecture)
D=target/deb/nvmetea_${V}_${ARCH}
rm -rf "$D"
mkdir -p "$D/DEBIAN" "$D/etc/default"
cp -a "$S/usr" "$D/"
install -m 0644 "$S/etc/nvmetea-exporter.env" "$D/etc/default/nvmetea-exporter"
# Debian keeps licenses in /usr/share/doc/<pkg>/copyright
mkdir -p "$D/usr/share/doc/nvmetea"
cat "$S/usr/share/licenses/nvmetea/LICENSE" "$S/usr/share/licenses/nvmetea/NOTICE" > "$D/usr/share/doc/nvmetea/copyright"
rm -rf "$D/usr/share/licenses"
DEPS=$(dpkg-shlibdeps -O -e"$D/usr/bin/nvmetea" 2>/dev/null | sed -n 's/^shlibs:Depends=//p' || true)
cat > "$D/DEBIAN/control" <<CTL
Package: nvmetea
Version: $V
Architecture: $ARCH
Maintainer: nvmetea maintainers
Depends: ${DEPS:-libelf1, zlib1g, libzstd1}
Section: admin
Priority: optional
Description: Linux NVMe/TCP initiator observability (read-only)
 Subsystems, controllers, queues, TCP connections and per-command stage
 timing of an NVMe/TCP initiator. TUI, JSON, captures and a Prometheus
 exporter (nvmetea-exporter.service). Observes only.
CTL
echo "/etc/default/nvmetea-exporter" > "$D/DEBIAN/conffiles"
dpkg-deb --root-owner-group --build "$D" target/deb/
