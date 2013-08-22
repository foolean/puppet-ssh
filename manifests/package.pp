# == Class: ssh::package
#
# Simple class to ensure the ssh server package is installed
#
# === Parameters
#
# None
#
# === Variables
#
# [*bsd_pkg_path*]
#   The PKG_PATH value to be used in the package type declaration
#   for FreeBSD and OpenBSD operating systems.
#
# [*operatingsystem*]
#   This class uses the facter 'operatingsystem' top-level
#   variable to determine which package or packages to install.
#   If the operating system hasn't been defined then an error
#   message is displayed and puppet processing continues.
#
# [*os_defined*]
#   Used by the ssh::server defined type to control processing
#   based on whether the ssh::package class has been configured
#   to handle the operating system or not.
#
# === Examples
#
#   include ssh::package
#
#   Note: This class is invoked from the ssh::server defined type. There
#         should be no reason to invoke this class directly.
#
# === Supported Operating Systems
#
#   * Centos
#   * Debian
#   * Fedora
#   * FreeBSD
#   * OpenSUSE
#   * OpenBSD
#   * RedHat
#   * SLES
#   * Ubuntu
#
# === Authors
#
#   Bennett Samowich <bennett@foolean.org>
#
# === Copyright
#
#   Copyright (c) 2013 Foolean.org
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and 
#   limitations under the License.
#
class ssh::package {
    
    # Dummy package for the purpose of controlling flow since the actual
    # package name will ultimately be dynamic.
    package { 'ssh-server-package': ensure => 'absent' }

    # The package names can be different depending on the operating system.
    # In some cases, such as OpenBSD, SSH is included as part of the base
    # installation.  We still want other SSH related resources to 'require'
    # the package.  In order to keep things consistent we use a dummy package
    # for OpenBSD and specify 'ensure => absent', which should always return
    # success.
    case $::operatingsystem {
        'centos','debian','fedora','redhat','ubuntu': {
            class { 'ssh::package::openssh-server': }
            $os_defined = true
        }

        # It may feel like a kludge but it works quite well as SSH is included
        # in the OpenBSD and FreeBSD operating systems and doesn't require an
        # actual package.
        'freebsd','openbsd': {
            $os_defined = true
        }

        'opensuse','sles': {
            include ssh::package::openssh
            $os_defined = true
        }

        default: {
            notify { "ssh_server_package_${::operatingsystem}_unknown":
                loglevel => 'alert',
                message  => "Unknown OS '${::operatingsystem}', skipping package install",
            }
            $os_defined = false
        }
    }
}
