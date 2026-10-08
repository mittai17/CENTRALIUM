Name:           centralium-agent
Version:        0.1.0
Release:        1%{?dist}
Summary:        Centralium Endpoint Detection and Response Agent
License:        Apache-2.0
URL:            https://github.com/centralium/centralium
Source0:        %{name}-%{version}.tar.gz

BuildArch:      x86_64 aarch64
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  systemd-rpm-macros
Requires:       python3 >= 3.11
Requires:       systemd

%{?systemd_requires}

%description
Centralium is an autonomous host defense EDR agent featuring real-time
kernel collectors, behavioral analysis, offline response playbooks,
cryptographic quarantine, and prompt-injection resilient AI telemetry.

%prep
%autosetup -n centralium-%{version}

%build
%py3_build

%install
%py3_install
install -D -m 0644 packaging/systemd/centralium.service %{buildroot}%{_unitdir}/centralium.service
install -d -m 0700 %{buildroot}%{_sharedstatedir}/centralium
install -d -m 0750 %{buildroot}%{_localstatedir}/log/centralium
install -d -m 0750 %{buildroot}%{_sysconfdir}/centralium

%pre
getent group centralium >/dev/null || groupadd -r centralium
getent passwd centralium >/dev/null || \
    useradd -r -g centralium -d %{_sharedstatedir}/centralium -s /sbin/nologin \
    -c "Centralium EDR Agent" centralium
exit 0

%post
%systemd_post centralium.service

%preun
%systemd_preun centralium.service

%postun
%systemd_postun_with_restart centralium.service

%files
%license LICENSE
%doc README.md docs/
%{_bindir}/centralium
%{python3_sitelib}/centralium/
%{_unitdir}/centralium.service
%dir %attr(0750, root, centralium) %{_sysconfdir}/centralium
%dir %attr(0700, centralium, centralium) %{_sharedstatedir}/centralium
%dir %attr(0750, centralium, centralium) %{_localstatedir}/log/centralium

%changelog
* Wed Oct 08 2026 Centralium Security Team <security@centralium.dev> - 0.1.0-1
- Initial release with hardened sandboxing, AES-256-GCM quarantine and secret redaction.
