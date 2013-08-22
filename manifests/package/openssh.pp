# == Class: ssh::package::openssh
#
#   Simple class to install the 'openssh' package.
#
#   Some operating systems have seperate client and server packages
#   while others use a singular package.  This class will be included
#   by declaring either ssh::client or calls to ssh::server.  Separating
#   the package installation into simple classes allows the ssh::client
#   class and ssh::server define to install the appropriate package
#   without having to worry about duplicate resource errors.
#
# === Parameters
#
# None
#
# === Variables
#
# None
#
# === Example
#
#   include ssh::package::openssh
#
#   Note: There should be no reason to declare this class directly as it
#         will be included by declaring ssh::client and ssh::server.
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
class ssh::package::openssh {
    package { 'openssh':
        ensure => 'latest',
        before => [
            Package['ssh-client-package'],
            Package['ssh-server-package'],
        ],
    }
}
