# Binary RPM from the tree staged by packaging/stage.sh (the BPF objects are
# compiled into the binary at build time; the target host needs no toolchain).
Name:           nvmetea
Version:        %{nvmetea_version}
Release:        1%{?dist}
Summary:        Linux NVMe/TCP initiator observability (read-only)
# userspace MIT; embedded BPF programs Dual MIT/GPL
License:        MIT AND (MIT OR GPL-2.0-only)
Source0:        nvmetea-%{version}.tar.gz
ExclusiveArch:  x86_64 aarch64
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}

%global debug_package %{nil}

%description
nvmetea shows NVMe/TCP subsystems, controllers, queues and TCP connections
of a Linux initiator, and where each command's time goes: local submission,
transmit, network/target, receive and completion. Passive data works
unprivileged; per-command telemetry uses CO-RE eBPF (root or CAP_BPF +
CAP_PERFMON). It only observes: it never writes to devices or changes
NVMe/TCP configuration. Includes a TUI, JSON output, captures with
comparison, and a Prometheus exporter (nvmetea-exporter.service).

%prep
%setup -q -n nvmetea-%{version}

%install
mkdir -p %{buildroot}
cp -a usr %{buildroot}/
install -D -m 0644 etc/nvmetea-exporter.env %{buildroot}%{_sysconfdir}/sysconfig/nvmetea-exporter

%post
%systemd_post nvmetea-exporter.service

%preun
%systemd_preun nvmetea-exporter.service

%postun
%systemd_postun_with_restart nvmetea-exporter.service

%files
%license /usr/share/licenses/nvmetea/LICENSE
%license /usr/share/licenses/nvmetea/NOTICE
%doc /usr/share/doc/nvmetea
/usr/bin/nvmetea
/usr/share/man/man1/nvmetea*.1.gz
/usr/share/bash-completion/completions/nvmetea
/usr/share/zsh/site-functions/_nvmetea
/usr/share/fish/vendor_completions.d/nvmetea.fish
%{_unitdir}/nvmetea-exporter.service
%config(noreplace) %{_sysconfdir}/sysconfig/nvmetea-exporter
