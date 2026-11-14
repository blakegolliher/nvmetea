#!/bin/bash
# Build the binary RPM into target/rpm/ (rpmbuild tree under target/, not ~/rpmbuild).
set -eu
cd "$(dirname "$0")/../.."
S=$(packaging/stage.sh | tail -1)
V=${S##*-}
T=$PWD/target/rpmbuild
rm -rf "$T"
mkdir -p "$T"/{SOURCES,SPECS,BUILD,RPMS,SRPMS} target/rpm
tar -C target/stage -czf "$T/SOURCES/nvmetea-$V.tar.gz" "nvmetea-$V"
rpmbuild -bb --define "_topdir $T" --define "nvmetea_version $V" packaging/rpm/nvmetea.spec
cp "$T"/RPMS/*/nvmetea-*.rpm target/rpm/
ls -l target/rpm/
