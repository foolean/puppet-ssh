# == Class: ssh::client
#
#   Class to install and configure the ssh client.
#
# === Parameters
#
# [*host*]
#   A hash of hashes for each 'Host' section to be defined in the
#   global ssh_config file.
#
#   Note: Only the following configuration options are available
#         for use in the global ssh_config file.  This class can
#         be extended to handle more though most are better suited
#         for the user specific ~/.ssh/config file.
#
#   Current configurable options w/defaults:
#   * allowx11              => false
#   * ciphers               => [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ]
#   * protocol              => 2
#   * stricthostkeychecking => false
#
# === Variables
#
# [*bsd_pkg_path*]
#   The PKG_PATH setting for *BSD operating systems.  This value is
#   used for the 'source' attribute of the 'package' resource.
#
# [*ssh_config*]
#   Full path to the ssh_config file
#
# === Example
#
#   class { 'ssh::client': }
#
#   class { 'ssh::client':
#       host => {
#           "*.${domain}" => {
#               'forwardx11'             => true,
#               'forwardx11trusted'      => true,
#               'passwordauthentication' => false,
#               'port'                   => 2242,
#               'protocol'               => 2,
#               'sendenv'                => [
#                   'LANG', 'LC_CTYPE', 'LC_NUMERIC', 'LC_TIME', 'LC_COLLATE',
#                   'LC_MONETARY', 'LC_MESSAGES', 'LC_PAPER', 'LC_NAME',
#                   'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MEASUREMENT',
#                   'LC_IDENTIFICATION', 'LC_ALL'
#               ],
#               'stricthostkeychecking'  => true,
#           },
#       }
#   }
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
class ssh::client (
    $host = false
) {
    include ssh

    # Dummy package for the purpose of controlling flow since the actual
    # package name will ultimately be dynamic.
    package { 'ssh-client-package': ensure => 'absent' }

    # The package names can be different depending on the operating system.
    # In some cases, such as OpenBSD, SSH is included as part of the base
    # installation.  We still want other SSH related resources to 'require'
    # the package.  In order to keep things consistent we use a dummy package
    # for OpenBSD and specify 'ensure => absent', which should always return
    # success.
    case $::operatingsystem {
        'centos': {
            include ssh::package::openssh-clients
            $ok = true
        }
        'debian','fedora','redhat','ubuntu': {
            class { 'ssh::package::openssh-client': }
            $ok = true
        }

        # It may feel like a kludge but it works quite well as SSH is included
        # in the OpenBSD and FreeBSD operating systems and doesn't require an
        # actual package.
        'freebsd','openbsd': {
            $ok = true
        }

        'opensuse','sles': {
            include ssh::package::openssh
            $ok = true
        }

        default: {
            notify { "ssh_client_package_${::operatingsystem}_unknown":
                loglevel => 'alert',
                message  => "Unknown OS '${::operatingsystem}', skipping package install",
            }
            $ok = false
        }
    }

    if $ok {
        # Path to the ssh_config file
        $ssh_config = $::operatingsystem ? {
            default => '/etc/ssh/ssh_config',
        }

        # Path to the ssh_known_hosts file
        $ssh_known_hosts = $::operatingsystem ? {
            default => '/etc/ssh/ssh_known_hosts',
        }

        # Set permissions on the /etc/ssh directory
        file { '/etc/ssh':
            ensure  => 'directory',
            mode    => '0755',
            owner   => $ssh::user,
            group   => $ssh::group,
            require => Package['ssh-client-package'],
        }

        # Copy the /etc/ssh/ssh_config file
        file { $ssh_config:
            mode    => '0444',
            owner   => $ssh::user,
            group   => $ssh::group,
            content => template( "${module_name}/${ssh_config}" ),
            require => Package['ssh-client-package'],
        }

        # Copy the ssh_known_hosts file
        file { $ssh_known_hosts:
            mode    => '0444',
            owner   => $ssh::user,
            group   => $ssh::group,
            content => inline_template(
                file(
                    "${settings::vardir}/${ssh::private_mount}/${::fqdn}/${ssh_known_hosts}",
                    "${settings::vardir}/${ssh::private_path}/${::fqdn}/${ssh_known_hosts}",
                    '/dev/null'
                )
            )
        }
    }
}
