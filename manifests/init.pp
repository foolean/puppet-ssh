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
#   [*site_path*]
#       Path to the location of the module directory based on the environment
#       we're in.  For example; the environment 'production' would resolve to
#       the site_path '/var/lib/puppet/sites/default/production' whereas the
#       environment 'foolean_production' would resolve to the site_path
#       '/var/lib/puppet/sites/foolean/production'.
#
#   [*site_private_path*]
#       Path to the host specific files (e.g. private).  It is essentially
#       '${site_path}/private'.  It is in this directory that puppet will
#       look for files specific to each host.  Specifially; this module
#       expect to find host speicific files in a $::fqdn directory inside
#       this one.
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

    # Private path based on the current environment.
    $get_site_name = regsubst( $::environment, '(\w+)_(\w+)', '\1' )
    $site_env      = regsubst( $::environment, '(\w+)_(\w+)', '\2' )

    # If site_name is the same as site_env
    # then we are actually in the default site.  
    if ( $get_site_name == $site_env ) {
        $site_name = 'default'
    } else {
        $site_name = $get_site_name
    }
    $site_path         = "${settings::vardir}/sites/${site_name}/${site_env}"
    $site_private_path = "${site_path}/private/${::fqdn}"

    # Default host keys
    $default_rsakey = '/etc/ssh/ssh_host_rsa_key'
    $default_dsakey = '/etc/ssh/ssh_host_dsa_key'

    $default_compression = 'delayed'

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
