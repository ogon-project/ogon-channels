#
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

# norootforbuild

Name:            ogon-channels
Version:         1.0.0
Release:         1
Summary:         RDP channels for ogon
Group:           Productivity/Networking/RDP
License:         Apache-2.0
Url:             http://ogon-project.com
#PreReq:
Source:          ogon-channels.tar.xz
#Provides:
BuildRequires:   pkg-config
BuildRequires:   cmake >= 2.8.12
BuildRequires:   freerdp2-devel
BuildRequires:   gcc-c++
BuildRequires:	 libopenssl-devel
BuildRequires:   libxcb-devel
BuildRequires:   fuse-devel
BuildRequires:   libQt5Core-devel
BuildRequires:   libQt5Widgets-devel
BuildRequires:   libqt5-qtbase-common-devel
BuildRequires:   libQt5DBus-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
AutoReqProv:    on

%description
The ogon Remote Desktop Services provide graphical remote access to
desktop sessions and applications using the Remote Desktop Protocol
(RDP) and supports most modern RDP protocol extensions, bitmap
compression codecs and device redirections. ogon is build on the
FreeRDP library and is compatible with virtually any existing Remote
Desktop Client.

This package contains RDP channels like clipboard or drive redirection
for ogon.

%package devel
Requires: %{name} = %version
Group:      Development/Productivity/Networking/RDP
Summary:    Development files related to ogon channels

%description devel
The ogon Remote Desktop Services provide graphical remote access to
desktop sessions and applications using the Remote Desktop Protocol
(RDP) and supports most modern RDP protocol extensions, bitmap
compression codecs and device redirections. ogon is build on the
FreeRDP library and is compatible with virtually any existing Remote
Desktop Client.

This package contains files required for channel development.
 
%prep
%setup

%build
%cmake  -DCMAKE_BUILD_TYPE=RelWithDebInfo 
make VERBOSE=1 %{?jobs:-j%jobs}

%install
#export NO_BRP_STRIP_DEBUG=true
#export NO_DEBUGINFO_STRIP_DEBUG=true
#%%define __debug_install_post %{nil}
%cmake_install

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%_libdir/libogon-qtrdpchannelserver.so.*
%_libdir/libogon-qtrdpclipchannelserver.so.*
%_bindir/rdpclip
%_bindir/rdpdr

%files devel
%defattr(-,root,root)
%_libdir/pkgconfig/ogon-qtrdpchannelserver1.pc
%_libdir/pkgconfig/ogon-qtrdpclipchannelserver1.pc
%_includedir/ogon-channels1
%_libdir/libogon-qtrdpchannelserver.so
%_libdir/libogon-qtrdpclipchannelserver.so

%changelog
* Thu Jun 09 2016 - bernhard.miklautz@thincast.com
- Initial version
