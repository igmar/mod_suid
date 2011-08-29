Summary: Module to handle Apache vhosts onder their own UID 
Name: mod_suid
Version: 2.1
Release: 1

License: BSD
Url: http://www.palsenberg.com/index.php/plain/projects/apache_1_xx_mod_suid
Group: Applications/Internet
Source0: %{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
This module allows execution on scripts (yes, including PHP) onder the users
own UID / GID.

Optionally it can use lsm_rsuid, a Linux LSM kernel module that prevents
processes for regaining root privileges.

%prep

%setup -q 
%configure

%build
make

%install
# bah, but there is no other way
FILE=`apxs -q LIBEXECDIR`/mod_suid.so
echo $FILE > mod_suid.files
make INSTALL_ROOT=$RPM_BUILD_ROOT install 

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files -f mod_suid.files
%defattr(-,root,root)
%doc CHANGES.txt LICENSE.txt TODO README

%changelog
* Mon May 29 2006 Igmar Palsenberg <igmar@palsenberg.com>
  Upgraded to 2.1

* Thu May 5 2006 Igmar Palsenberg <igmar@palsenberg.com>
- Upgraded to 2.0

* Mon Jan 12 2004 Igmar Palsenberg <igmar@jdimedia.nl>
- Upgraded to 1.2

* Sat Feb 15 2003 Igmar Palsenberg <igmar@jdimedia.nl>
- Upgraded to mod_suid 1.1

* Wed Mar 6 2002 Igmar Palsenberg <igmar@jdimedia.nl>
- Initial version
