# == Class: ssh
#
#   The ssh class is a comman variable declaration class which allows
#   variables common to all other ssh related classes to be organized
#   in a single location.
#
# === Parameters
#
#   None
#
# === Variables
#
#   [*group*]
#       Group name to be used for file ownership
#
#   [*private_path*]
#
#   [*private_mount*]
#
#   [*user*]
#       User name to be used for file ownership
#
# === Examples
#
#   This class should not be called directly but rather the variables
#   within will be referenced by the other ssh classes.
#
#   $rsakey = file ( "${ssh::private_path}/etc/ssh/ssh_host_rsa_key" )
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
class ssh {

    # Private path and fileserver mount based on the current environment.
    $private_path  = regsubst( $::environment, '_', '/' )
    $private_mount = "${environment}_private}"

    # Set the user for file ownership
    $user = $::operatingssytem ? {
        default => 'root',
    }

    # Set the group for file ownership
    $group = $::operatingsystem ? {
        'freebsd' => 'wheel',
        'openbsd' => 'wheel',
        default   => 'root',
    }

}
