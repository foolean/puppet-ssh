# == Define: ssh::server
#
#   Define to create or remove a ssh daemon.  This differes from previous
#   methods of managing the ssh daemon in that it facilitates daemons that
#   run on alternate ports as well as the default daemon.
#
# === Parameters
#
# The following parameters are recognized by ssh::server
#
# [*acceptenv*]
#   Specifies what environment variables sent by the client will be copied
#   into the session's environ(7).  See SendEnv in ssh_config(5) for how
#   to configure the client.  Note that environment passing is only supported
#   for protocol 2.  Variables are specified by name, which may contain the
#   wildcard characters ‘*’ and ‘?’.  Multiple environment variables may be
#   separated by whitespace or spread across multiple AcceptEnv directives.
#   Be warned that some environment variables could be used to bypass
#   restricted user environments.  For this reason, care should be taken
#   in the use of this directive.  The default is not to accept any environment
#   variables.
#
# [*addressfamily*]
#   Specifies which address family should be used by sshd(8).
#   Valid arguments are "any", "inet" (use IPv4 only),  or
#   "inet6" (use IPv6 only).  The default is "any"
#
# [*allowgroups*]
#   This keyword can be followed by an array of group name patterns
#   If specified, login is allowed only for users whose primary group
#   or supplementary group list matches one of the patterns.  '*' and
#   '?' can be used as wildcards in the patterns.  Only group names
#   are valid; a numerical group ID is not recognized.  By default,
#   login is allowed for all groups.
#
# [*allowtcpforwarding*]
#   Specifies whether TCP forwarding is permitted.
#   Note that disabling TCP forwarding does not improve security
#   unless users are also denied shell access, as they can always
#   install their own forwarders.  The default is not to permit
#   TCP forwarding.
#
# [*allowhosts*]
#   This keyword can be followed by an array of host and/or network
#   patterns.  If specified, iptables rules are created to restrict
#   access to be only from the defined sources.
#   Note: the iptables class must be defined before
#         this will be enforced.
#
# [*allowusers*]
#   This keyword can be followed by an array of user name patterns.
#   If specified, login is allowed only for user names that match
#   one of the patterns.  Only user names are valid; a numerical
#   user ID is not recognized.  By default, login is allowed for
#   all users.  If the pattern takes the form USER@HOST then USER
#   and HOST are separately checked, restricting logins to particular
#   users from particular hosts.  The allow/deny directives are
#   processed in the following order:
#   DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.
#
# [*authorizedkeysfile*]
#   Specifies the file that contains the public keys that can be used
#   for user authentication.  The format is described in the
#   AUTHORIZED_KEYS FILE FORMAT section of sshd(8).
#   AuthorizedKeysFile may contain tokens of the form %T which are
#   substituted during connection setup.  The following tokens are
#   defined: %% is replaced by a literal '%', %h is replaced by the
#   home directory of the user being authenticated, and %u is
#   replaced by the username of that user.  After expansion,
#   AuthorizedKeysFile is taken to be an absolute path or one
#   relative to the user's home directory.  Multiple files may be
#   listed, separated by whitespace.  The default will resolve to
#   '.ssh/authorized_keys .ssh/authorized_keys2'.
#
# [*banner*]
#   The contents of the specified file are sent to the remote user
#   before authentication is allowed.  If the argument is 'none'
#   then no banner is displayed.  This option is only available for
#   protocol version 2.  By default, no banner is displayed.
#   The default is to use /etc/issue.
#
# [*challengeresponseauthentication*]
#   Specifies whether challenge response authentication is allowed.
#   All authentication styles from login.conf(5) are supported.  The
#   default is "true".
#
# [*chrootdirectory*]
#   Specifies the pathname of a directory to chroot(2) to after
#   authentication.  All components of the pathname must be root-
#   owned directories that are not writable by any other user or
#   group.  After the chroot, sshd(8) changes the working directory
#   to the user's home directory.
#
#   The pathname may contain the following tokens that are expanded
#   at runtime once the connecting user has been authenticated: %% is
#   replaced by a literal '%', %h is replaced by the home directory
#   of the user being authenticated, and %u is replaced by the
#   username of that user.
#
#   The ChrootDirectory must contain the necessary files and
#   directories to support the user's session.  For an interactive
#   session this requires at least a shell, typically sh(1), and
#   basic /dev nodes such as null(4), zero(4), stdin(4), stdout(4),
#   stderr(4), arandom(4) and tty(4) devices.  For file transfer
#   sessions using 'sftp', no additional configuration of the
#   environment is necessary if the in-process sftp server is used,
#   though sessions which use logging do require /dev/log inside the
#   chroot directory (see sftp-server(8) for details).
#
#   The default is not to chroot(2).
#
# [*ciphers*]
#   Specifies the ciphers allowed for protocol version 2.  Multiple
#   ciphers must be comma-separated.  The supported ciphers are
#   '3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
#   'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'arcfour128',
#   'arcfour256', 'arcfour', 'blowfish-cbc', and
#   'cast128-cbc'.
#
#   The default is: 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'
#
# [*clientalivecountmax*]
#   Sets the number of client alive messages (see below) which may be
#   sent without sshd(8) receiving any messages back from the client.
#   If this threshold is reached while client alive messages are
#   being sent, sshd will disconnect the client, terminating the
#   session.  It is important to note that the use of client alive
#   messages is very different from TCPKeepAlive (below).  The client
#   alive messages are sent through the encrypted channel and
#   therefore will not be spoofable.  The TCP keepalive option
#   enabled by TCPKeepAlive is spoofable.  The client alive mechanism
#   is valuable when the client or server depend on knowing when a
#   connection has become inactive.
#
#   The default value is 0.  If ClientAliveInterval (see below) is
#   set to 15, and ClientAliveCountMax is left at the default,
#   unresponsive SSH clients will be disconnected after approximately
#   45 seconds.  This option applies to protocol version 2 only.
#
# [*clientaliveinterval*]
#   Sets a timeout interval in seconds after which if no data has
#   been received from the client, sshd(8) will send a message
#   through the encrypted channel to request a response from the
#   client.  The default is 0, indicating that these messages will
#   not be sent to the client.  This option applies to protocol
#   version 2 only.  The default is 300.
#
# [*denygroups*]
#   This keyword can be followed by an array of group name patterns.
#   Login is disallowed for users whose primary group or supplementary
#   group list matches one of the patterns. '*' and '?' can be used
#   as wildcards in the patterns.  Only group names are valid; a numerical
#   group ID is not recognized.  By default, login is allowed for all groups.
#
# [*denyusers*]
#   This keyword can be followed by a list of user name patterns,
#   Login is disallowed for user names that match one of the patterns.
#   '*' and '?' can be used as wildcards in the patterns.  Only user
#   names are valid; a numerical user ID is not recognized.  By default,
#   login is allowed for all users. If the pattern takes the form
#   USER@HOST then USER and HOST are separately checked, restricting
#   logins to particular users from particular hosts.  Specifying a
#   command of "internal-sftp" will force the use of an in-process sftp
#   server that requires no support files when used with ChrootDirectory.
#
#   Default: 'adm',       'admin',       'administrator', 'Administrator',
#            'anonymous', 'apache',      'at',            'avahi',
#            'backup',    'beagleindex', 'bin',           'cvs',
#            'daemon',    'demo',        'dnsmasq',       'fax',
#            'fetchmail', 'files',       'ftp',           'ftpuser',
#            'games',     'gdm',         'git-daemon',    'gnats',
#            'guest',     'haldaemon',   'icecream',      'info',
#            'irc',       'libuuid',     'list',          'lp',
#            'mail',      'man',         'messagebus',    'mysql',
#            'nagios',    'news',        'nobody',        'ntp',
#            'oprofile',  'oracle',      'polkituser',    'postfix',
#            'postgres',  'proxy',       'pulse',         'puppet',
#            'sshd',      'support',     'suse-ncc',      'sync',
#            'sys',       'test',        'testuser',      'user',
#            'uucp',      'uuidd',       'webmaster',     'www',
#            'www-data',  'wwwrun'
#
# [*dsakey*]
#   NOTE: This parameter has been temporarily disabled
#   Default: /etc/ssh/ssh_host_dsa_key
#
# [*ensure*]
#   Specifies whether to enable or disable the ssh daemon.  The possible
#   values are 'present' and 'absent'.  If the value is 'absent' all
#   related files for the instance are removed.  The default is 'present'
#
# [*forcecommand*]
#   Forces the execution of the command specified by ForceCommand,
#   ignoring any command supplied by the client and ~/.ssh/rc if
#   present.  The command is invoked by using the user's login shell
#   with the -c option.  This applies to shell, command, or subsystem
#   execution.  It is most useful inside a Match block.  The command
#   originally supplied by the client is available in the
#   SSH_ORIGINAL_COMMAND environment variable.  Specifying a command
#   of 'internal-sftp' will force the use of an in-process sftp
#   server that requires no support files when used with
#   ChrootDirectory.
#
# [*listenaddress*]
#   Specifies the local addresses sshd(8) should listen on.  The
#   following forms may be used:
#
#   listenaddress => host|IPv4_addr|IPv6_addr
#   listenaddress => host|IPv4_addr:port
#   listenaddress => [host|IPv6_addr]:port
#
#   If port is not specified, sshd will listen on the address and all
#   prior Port options specified.  The default is to listen on all
#   local addresses.  Multiple ListenAddress options are permitted.
#   Additionally, any Port options must precede this option for non-
#   port qualified addresses.
#
# [*log_level*]
#   Gives the verbosity level that is used when logging messages from
#   sshd(8).  The possible values are: QUIET, FATAL, ERROR, INFO,
#   VERBOSE, DEBUG, DEBUG1, DEBUG2, and DEBUG3.  The default is VERBOSE.
#   DEBUG and DEBUG1 are equivalent.  DEBUG2 and DEBUG3 each specify
#   higher levels of debugging output.  Logging with a DEBUG level
#   violates the privacy of users and is not recommended.
#
# [*match_users*]
#   Default: empty
#
# [*maxsessions*]
#   Specifies the maximum number of open sessions permitted per
#   network connection.  The default is 1.
#
# [*maxstartups*]
#   Specifies the maximum number of concurrent unauthenticated
#   connections to the SSH daemon.  Additional connections will
#   be dropped until authentication succeeds or the LoginGraceTime
#   expires for a connection.  The default is 10:30:100.
#
#   Alternatively, random early drop can be enabled by specifying
#   the three colon separated values “start:rate:full” (e.g. "10:30:60").
#   sshd(8) will refuse connection attempts with a probability of
#   “rate/100” (30%) if there are currently “start” (10) unauthenticated
#   connections.  The probability increases linearly and all connection
#   attempts are refused if the number of unauthenticated connections
#   reaches “full” (60).
#
# [*pamradiusauth*]
#   Specifies whether RADIUS authentication is to be included in the
#   PAM authentication file.  The default is 'false'.
#
# [*passwordauthentication*]
#   Specifies whether password authentication is allowed.  The
#   default is 'true'.
#
# [*permitopen*]
#   Specifies the destinations to which TCP port forwarding is
#   permitted.  The forwarding specification must be one of the
#   following forms:
#
#       permitopen => [ host:port ]
#       permitopen => [ IPv4_addr:port ]
#       permitopen => [ [IPv6_addr]:port ]
#
#   Multiple forwards may be specified by separating them with
#   whitespace.  An argument of 'any' can be used to remove all
#   restrictions and permit any forwarding requests.  An argument of
#   'none' can be used to prohibit all forwarding requests.  By
#   default all port forwarding requests are permitted.
#
# [*permitrootlogin*]
#   Specifies whether root can log in using ssh(1).  The argument
#   Specifies whether root can log in using ssh(1).  The argument
#   must be “yes”, “without-password”, “forced-commands-only”, or
#   “no”.  The default is “yes”.
#
#   If this option is set to “without-password”, password authentication
#   is disabled for root. If this option is set to “forced-commands-only”,
#   root login with public key authentication will be allowed, but only
#   if the command option has been specified (which may be useful for
#   taking remote backups even if root login is normally not allowed).
#   All other authentication methods are disabled for root.
#
#   If this option is set to “no”, root is not allowed to log in.
#
# [*port*]
#   Specifies the port number that sshd(8) listens on.  The default
#   is 22.  Multiple options of this type are permitted.  See also
#   listenaddress..
#
# [*printlastlog*]
#   Specifies whether sshd should print the date and time of the last
#   user login when a user logs in interactively.  The default is
#   "true".
#
# [*printmotd*]
#   Specifies whether sshd should print /etc/motd when a user logs in
#   interactively.  (On some systems it is also printed by the shell,
#   /etc/profile, or equivalent.)  The default is "true".
#
# [*protocol*]
#   Specifies the protocol versions sshd supports.  The possible val-
#   ues are "1" and "2".  Multiple versions must be comma-separated.
#   The default is "2".  Note that the order of the protocol list
#   does not indicate preference, because the client selects among
#   multiple protocol versions offered by the server.  Specifying
#   "2,1" is identical to "1,2".
#
# [*pubkeyauthentication*]
#   Specifies whether public key authentication is allowed.  The
#   default is 'false'.  Note that this option applies to protocol
#   version 2 only.
#
# [*rsakey*]
#   NOTE: This parameter has been temporarily disabled
#   Default: /etc/ssh/ssh_host_rsa_key
#
# [*syslogfacility*]
#   Gives the facility code that is used when logging messages from
#   sshd(8).  The possible values are: DAEMON, USER, AUTH, LOCAL0,
#   LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5, LOCAL6, LOCAL7.  The
#   default is AUTH.
#
# [*tcpkeepalive*]
#   Specifies whether the system should send TCP keepalive messages
#   to the other side.  If they are sent, death of the connection or
#   crash of one of the machines will be properly noticed.  However,
#   this means that connections will die if the route is down tem-
#   porarily, and some people find it annoying.  On the other hand,
#   if TCP keepalives are not sent, sessions may hang indefinitely on
#   the server, leaving "ghost" users and consuming server resources.
#
#   The default is "true" (to send TCP keepalive messages), and the
#   server will notice if the network goes down or the client host
#   crashes.  This avoids infinitely hanging sessions.
#
#   To disable TCP keepalive messages, the value should be set to
#   "false".
#
# [*titlesuffix*]
#   Specifies whether the title should be used as the suffix.  If set to
#   'true' the title will be used otherwise the port number will be used.
#   The default is 'false'.
#
# [*usepam*]
#   Enables the Pluggable Authentication Module interface.  If set to 'true'
#   this will enable PAM authentication using ChallengeResponseAuthentication
#   and PasswordAuthentication in addition to PAM account and session module
#   processing for all authentication types.  The default is 'true'.
#
# [*x11forwarding*]
#   Specifies whether X11 forwarding is permitted.  The argument must
#   be 'true' or 'false'.  The default is 'false'.
#
# === Variables
#
# [*deny_users*]
#
# [*os*]
#   Lowercase operating system name used to ensure that
#   referenced filenames which are OS specific remain
#   constant even if Puppet and Facter change case over
#   time.
#
# [*sftp_server*]
#   Full path to the sftp-server binary
#
# [*ssh_add_runlevel_cmd*]
#   Command to add the daemon to the appropriate runlevels
#
# [*sshd_binary*]
#   Full path to the sshd binary
#
# [*sshd_config*]
#   Full path to the sshd_config file
#
# [*ssh_default*]
#   Full path to the options file
#
# [*ssh_del_runlevel_cmd*]
#   Command to remove the daemon from all runlevels
#
# [*sshd_name*]
#   Name of the sshd_binary without the path
#
# [*sshd_pam*]
#   Full path to the pam.d file
#
# [*sshd_privdir*]
#
# [*sshd_rcfile*]
#   Full path to the rc file for running the daemon at boot
#
# [*sshd_service*]
#   Name of the sshd service
#
# [*ssh_hasrestart*]
#   Whethere or not the service honors the restart argument
#
# [*ssh_init*]
#   Full path to the init.d file
#
# [*ssh_norun*]
#   Full path to the file which indicates that the daemon
#   should not be started.
#
# [*ssh_start*]
#   Command to be used to start the service
#
# [*ssh_status*]
#   Command to be used to check the status of the service
#
# [*ssh_stop*]
#   Command to be used to stop the service
#
# === Examples
#
#   node myhost {
#       # default ssh running on port 22
#       ssh::server { 'ssh.": }
#
#       # Remove the daemon running on port 222
#       ssh::server { 'defunct':
#           ensure => 'absent',
#           port   => 222,
#       }
#
#       # ssh daemon running on port 2222
#       ssh::server { 'internal': port => 2222 }
#
#       # ssh daemon running on port 22223 which also
#       # permits root to log in.
#       ssh::server { 'special':
#           port            => 22223,
#           permitrootlogin => true,
#       }
#
#       # ssh daemon running on port 1234 which uses
#       # the Match directive.
#       ssh::server { 'chroot':
#           port      => 1234,
#           matchuser => {
#               'user1' => {
#                   'ChrootDirectory' => '/home/chroot/user1'
#               },
#               'user2' => {
#                   'ChrootDirectory'    => '/home/chroot/user2',
#                   'AllowTCPForwarding' => 'yes'
#               },
#           }
#       }
#   }
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
# === Diagnostics
#
# [*non-fatal errors*]
#   Aside from any parse errors resulting from changes in OS releases, an
#   error messages that will be displayed in red when the operating system
#   isn't known to ssh::server.
#
# [*fatal errors*]
#   ssh::server will issue a fatal error when one of the boolen parameters
#   or 'enable' contains an invalid value.
#
# === Alternate ports
#
#   Daemons listening on alternate ports are suffixed with the port number for
#   clarity.
#
#   example:
#       /etc/ssh/sshd_config_2222
#       /usr/sbin/sshd_2222
#       /etc/init.d/ssh_2222
#
# === SSH Host Keys
#
#   ssh::server handles the server host keys in the following fashion:
#
#       * generate RSA and DSA keys if they don't exist
#       * copy RSA and DSA keys from the client 'private' area if they exist
#       * ensure permission and ownership of RSA and DSA keys
#
#   All instances of sshd will use the same set of host keys.  You will need
#   to specify the host key parameters If you want to use a different set of
#   keys for a daemon listening on an alternate port.
#
# === SELinux
#
#   ssh::server will ensure that the listening ports are added to the selinux
#   policy.  This is accomplished by using the semanage(8) command which MUST
#   be installed on the system.  If semanage(8) is not installed ssh::server
#   will not attempt to add the port and incomming connections will fail.
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
define ssh::server (
    $ensure                         = 'present',
    $port                           = '22',
    $maxsessions                    = '1',
    $protocol                       = '2',
    $banner                         = '/etc/issue.net',
    $addressfamily                  = 'any',
    $allowusers                     = false,
    $allowhosts                     = false,
    $allowgroups                    = false,
    $authorizedkeysfile             = false,
    $allowtcpforwarding             = false,
    $chrootdirectory                = false,
    $denygroups                     = false,
    $permitrootlogin                = 'no',
    $forcecommand                   = false,
    $x11forwarding                  = false,
    $maxstartups                    = '10:30:100',
    $passwordauthentication         = true,
    $pubkeyauthentication           = false,
    $challengresponseauthentication = false,
    $remove                         = false,
    $printmotd                      = false,
    $titlesuffix                    = false,
    $tcpkeepalive                   = true,
    $printlastlog                   = true,
    $usepam                         = true,
    $pamradiusauth                  = false,
    $syslogfacility                 = 'AUTH',
    $log_level                      = 'VERBOSE',
    $acceptenv                      = [ 'LANG', 'LC_*' ],
    $ciphers                        = [ 'aes256-ctr', 'aes192-ctr', 'aes128-ctr' ],
    $clientalivecountmax            = '0',
    $clientaliveinterval            = '300',
    $listenaddress                  = [],
    $permitopen                     = [],
    $match_users                    = [],
    $denyusers                      = [
        'adm',       'admin',       'administrator', 'Administrator',
        'anonymous', 'apache',      'at',            'avahi',
        'backup',    'beagleindex', 'bin',           'cvs',
        'daemon',    'demo',        'dnsmasq',       'fax',
        'fetchmail', 'files',       'ftp',           'ftpuser',
        'games',     'gdm',         'git-daemon',    'gnats',
        'guest',     'haldaemon',   'icecream',      'info',
        'irc',       'libuuid',     'list',          'lp',
        'mail',      'man',         'messagebus',    'mysql',
        'nagios',    'news',        'nobody',        'ntp',
        'oprofile',  'oracle',      'polkituser',    'postfix',
        'postgres',  'proxy',       'pulse',         'puppet',
        'sshd',      'support',     'suse-ncc',      'sync',
        'sys',       'test',        'testuser',      'user',
        'uucp',      'uuidd',       'webmaster',     'www',
        'www-data',  'wwwrun'
    ]
)
{
    # Make sure the client is installed
    require ssh::client

    # Make sure the package is installed
    require ssh::package

    # Parameter validation
    # NOTE: Configuration file directive validation is handled
    #       within the templates.  This validation is for flow
    #       related parameters.
    if ! ( $ensure in [ 'absent','present' ] ) {
        fail( 'ensure must be "absent" or "present"' )
    }

    # These used to be parameters.  For the moment they will be defaults
    $rsakey = '/etc/ssh/ssh_host_rsa_key'
    $dsakey = '/etc/ssh/ssh_host_dsa_key'

    # For port tcp/22, use the standard filenames.  For any other port
    # append the port number to the filenames
    if $port == 22 {
        $suffix = ''
    } else {
        if $titlesuffix {
            $tag = $title
        } else {
            $tag = $port
        }

        # FreeBSD and OpenBSD's rc.d system doesn't like the
        # extra '_' character that we use in the suffix
        $suffix = $::operatingsystem ? {
            'freebsd' => $tag,
            'openbsd' => $tag,
            default   => "_${tag}"
        }
    }

    # We need to make sure our operating system is defined
    # and we don't want to do anything if the package hasn't
    # been defined either.
    if $ssh::package::os_defined {
        $ok = $::operatingsystem ? {
            'centos'   => true,
            'debian'   => true,
            'fedora'   => true,
            'freebsd'  => true,
            'openbsd'  => true,
            'opensuse' => true,
            'redhat'   => true,
            'sles'     => true,
            'ubuntu'   => true,
            default    => false,
        }
    } else {
        $ok = false
    }

    # ... and if not, throw an error and skip the rest
    if ! $ok {
        notify { "${title}_${::operatingsystem}_unknown":
            loglevel => 'alert',
            message  => "Unknown OS '${::operatingsystem}', skipping server configuration",
        }
    } else {

        # Path to the defaults file
        $ssh_default = $::operatingsystem ? {
            'centos'   => '/etc/sysconfig/sshd',
            'debian'   => '/etc/default/ssh',
            'fedora'   => '/etc/sysconfig/sshd',
            'opensuse' => '/etc/sysconfig/ssh',
            'redhat'   => '/etc/sysconfig/sshd',
            'sles'     => '/etc/sysconfig/sshd',
            'ubuntu'   => '/etc/default/ssh',
            default    => '',
        }

        # Path to the init file
        $ssh_init = $::operatingsystem ? {
            'centos'   => '/etc/init.d/sshd',
            'debian'   => '/etc/init.d/ssh',
            'fedora'   => '/etc/init.d/sshd',
            'freebsd'  => '/etc/rc.d/sshd',
            'openbsd'  => '/etc/rc.d/sshd',
            'opensuse' => '/etc/init.d/sshd',
            'redhat'   => '/etc/init.d/sshd',
            'sles'     => '/etc/init.d/sshd',
            'ubuntu'   => '/etc/init.d/ssh',
            default    => '',
        }

        # Path to chrooted init file ( so far only Ubuntu uses this )
        $ssh_conf = $::operatingsystem ? {
            'ubuntu' => "/etc/init/ssh${suffix}.conf",
            default  => '',
        }

        # Tickler file to tell sshd not to run ( mostly a Debian/Ubuntu thing )
        $ssh_norun = $::operatingsystem ? {
            'debian' => '/etc/ssh/sshd_not_to_be_run',
            'ubuntu' => '/etc/ssh/sshd_not_to_be_run',
            default  => '',
        }

        # Name of the sshd binary
        $sshd_name = $::operatingsystem ? {
            default => 'sshd',
        }

        # Path to the sshd binary
        $sshd_binary = $::operatingsystem ? {
            default => '/usr/sbin/sshd',
        }

        # Path to the sshd configuration file
        $sshd_config = $::operatingsystem ? {
            default => '/etc/ssh/sshd_config',
        }

        # Path to the PAM file for sshd
        $sshd_pam = $::operatingsystem ? {
            'freebsd' => '',
            'openbsd' => '',
            default   => '/etc/pam.d/sshd',
        }

        # Path to the privilege separation director
        $sshd_privdir = $::operatingsystem ? {
            'debian' => '/var/run/ssh',
            'ubuntu' => '/var/run/sshd',
            default  => '',
        }

        # Path to the deny_users file (for pam_listfile)
        $deny_users = $::operatingsystem ? {
            'freebsd' => '',
            'openbsd' => '',
            default   => '/etc/ssh/deny_users',
        }

        # Service name
        $sshd_service = $::operatingsystem ? {
            'centos'   => 'sshd',
            'debian'   => 'ssh',
            'fedora'   => 'sshd',
            'freebsd'  => 'sshd',
            'openbsd'  => 'sshd',
            'opensuse' => 'sshd',
            'redhat'   => 'sshd',
            'sles'     => 'sshd',
            'ubuntu'   => 'ssh',
            default    => '',
        }

        # Service start argument
        $ssh_start = $::operatingsystem ? {
            'freebsd' => 'onestart',
            default   => 'start',
        }

        # Service stop argument
        $ssh_stop = $::operatingsystem ? {
            'freebsd' => 'onestop',
            default   => 'stop',
        }

        # Service status argument
        $ssh_status = $::operatingsystem ? {
            'freebsd' => 'onestatus',
            'openbsd' => 'check',
            default   => 'status',
        }

        # Does the service honor the restart command
        $ssh_hasrestart = $::operatingsystem ? {
            'openbsd' => false,
            default   => true,
        }

        # SELinux port context
        $seport_context = $::operatingsystem ? {
            'freebsd' => '',
            'openbsd' => '',
            default   => 'ssh_port_t',
        }

        # Path to the SFTP server
        $sftp_server = $::operatingsystem ? {
            'centos'   => '/usr/lib/openssh/sftp-server',
            'debian'   => '/usr/lib/openssh/sftp-server',
            'fedora'   => '/usr/lib/openssh/sftp-server',
            'freebsd'  => '/usr/libexec/sftp-server',
            'openbsd'  => '/usr/libexec/sftp-server',
            'opensuse' => '/usr/lib/ssh/sftp-server',
            'redhat'   => '/usr/lib/openssh/sftp-server',
            'sles'     =>  $::architecture ? {
                'x86_64' => '/usr/lib64/ssh/sftp-server',
                default  => '/usr/lib/ssh/sftp-server',
            },
            'ubuntu'   => '/usr/lib/openssh/sftp-server',
            default    => '',
        }

        # Command to enable sshd at boot
        $ssh_add_runlevel_cmd = $::operatingsystem ? {
            'centos'   => "chkconfig --add ${sshd_service}${suffix}",
            'debian'   => "update-rc.d ${sshd_service}${suffix} defaults",
            'fedora'   => "chkconfig --add ${sshd_service}${suffix}",
            'opensuse' => "chkconfig --add ${sshd_service}${suffix}",
            'redhat'   => "chkconfig --add ${sshd_service}${suffix}",
            'sles'     => "chkconfig --add ${sshd_service}${suffix}",
            'ubuntu'   => "update-rc.d ${sshd_service}${suffix} defaults",
            default    => '',
        }

        # Command to disable sshd from starting at boot
        $ssh_del_runlevel_cmd = $::operatingsystem ? {
            'centos'   => "chkconfig --del ${sshd_service}${suffix}",
            'debian'   => "update-rc.d ${sshd_service}${suffix} remove",
            'fedora'   => "chkconfig --del ${sshd_service}${suffix}",
            'redhat'   => "chkconfig --del ${sshd_service}${suffix}",
            'opensuse' => "chkconfig --del ${sshd_service}${suffix}",
            'sles'     => "chkconfig --del ${sshd_service}${suffix}",
            'ubuntu'   => "update-rc.d ${sshd_service}${suffix} remove",
            default    => '',
        }

        # rc file used to determin if sshd is enabled at boot or not
        $sshd_rcfile = $::operatingsystem ? {
            'centos'   => '/etc/rc2.d/S55sshd',
            'debian'   => '/etc/rc2.d/S03ssh',
            'fedora'   => '/etc/rc2.d/S55sshd',
            'redhat'   => '/etc/rc2.d/S55sshd',
            'opensuse' => '/etc/init.d/rc3.d/S07sshd',
            'sles'     => '/etc/init.d/rc3.d/S07sshd',
            'ubuntu'   => '/etc/rc2.d/S20ssh',
            default    => '',
        }

        # Lowercase copy of operating system
        $os = $::operatingsystem ? {
            'centos'   => 'centos',
            'debian'   => 'debian',
            'fedora'   => 'fedora',
            'redhat'   => 'redhat',
            'freebsd'  => 'freebsd',
            'openbsd'  => 'openbsd',
            'opensuse' => 'opensuse',
            'sles'     => 'sles',
            'ubuntu'   => 'ubuntu',
            default    => '',
        }

        # If we're creating the daemon (e.g. not removing it)...
        if $ensure == 'present' {
            if ( defined( File['/etc/iptables.d'] ) ) {
                file { "/etc/iptables.d/80_${sshd_service}${suffix}_${port}":
                    owner   => 'root',
                    group   => 'root',
                    mode    => '0400',
                    content => template( "${module_name}/etc/iptables.d/80_sshd" ),
                    notify  => Exec['reload-iptables'],
                }
            }

            # Create the sshd_config for this server
            file { "${sshd_config}${suffix}":
                ensure   => present,
                mode     => '0444',
                owner    => $ssh::user,
                group    => $ssh::group,
                content  => template( "${module_name}/etc/ssh/sshd_config" ),
                notify   => Service["${sshd_service}${suffix}"],
                require  => Package['ssh-server-package'],
            }

            # Create a defaults file
            case $::operatingsystem {
                'centos','debian','fedora','opensuse','redhat', 'sles','ubuntu': {
                    file { "${ssh_default}${suffix}":
                        mode     => '0444',
                        owner    => $ssh::user,
                        group    => $ssh::group,
                        content  => template( "${module_name}/${ssh_default}" ),
                        notify   => Service["${sshd_service}${suffix}"],
                        require  => Package['ssh-server-package'],
                    }
                }
                default: {}
            }

            # Create an init script
            file { "${ssh_init}${suffix}":
                mode     => '0555',
                owner    => $ssh::user,
                group    => $ssh::group,
                content  => template( "${module_name}/${ssh_init}-${os}" ),
                notify   => Service["${sshd_service}${suffix}"],
                require  => Package['ssh-server-package'],
            }

            # Ubuntu uses /etc/init/ssh for chrooted environments
            case $::operatingsystem {
                'ubuntu': {
                    file { $ssh_conf:
                        mode     => '0444',
                        owner    => $ssh::user,
                        group    => $ssh::group,
                        content  => template( "${module_name}/etc/init/ssh.conf" ),
                        before   => Service["${sshd_service}${suffix}"],
                        require  => Package['ssh-server-package'],
                    }
                }
                default: {}
            }

            # Create a PAM configuration
            case $::operatingsystem {
                'centos','debian','fedora','opensuse','redhat','sles','ubuntu': {
                    file { "${sshd_pam}${suffix}":
                        mode     => '0444',
                        owner    => $ssh::user,
                        group    => $ssh::group,
                        content  => template( "${module_name}/${sshd_pam}-${os}" ),
                        before   => Service["${sshd_service}${suffix}"],
                        require  => Package['ssh-server-package'],
                    }
                }
                default: {}
            }

            # Create a deny_users file for pam_listfile
            case $::operatingsystem {
                'centos','debian','fedora','opensuse','redhat','sles','ubuntu': {
                    file { "${deny_users}${suffix}":
                        mode     => '0444',
                        owner    => $ssh::user,
                        group    => $ssh::group,
                        content  => template( "${module_name}/etc/ssh/deny_users" ),
                        before   => Service["${sshd_service}${suffix}"],
                        require  => Package['ssh-server-package'],
                    }
                }
                default: {}
            }

            # Symlink to the real sshd or set the permissions on the binary
            if $port != '22' {
                file { "${sshd_binary}${suffix}":
                    ensure   => 'link',
                    target   => '/usr/sbin/sshd',
                    before   => Service["${sshd_service}${suffix}"],
                    require  => Package['ssh-server-package'],
                }
            } else {
                file { "${sshd_binary}${suffix}":
                    mode     => '0755',
                    owner    => $ssh::user,
                    group    => $ssh::group,
                    before   => Service["${sshd_service}${suffix}"],
                    require  => Package['ssh-server-package'],
                }
            }

            # Generate the RSA key if it doesn't exist
            exec { "generate-${rsakey}${suffix}":
                path    => [ '/usr/bin' ],
                command => "ssh-keygen -t rsa -b 2048 -f ${rsakey}${suffix}",
                creates => "${rsakey}",
                notify  => Service["${sshd_service}${suffix}"],
                require => Package['ssh-server-package'],
            }

            # Generate the DSA key if it doesn't exist
            exec { "generate-${dsakey}${suffix}":
                path    => [ '/usr/bin' ],
                command => "ssh-keygen -t dsa -b 1024 -f ${dsakey}${suffix}",
                creates => "${dsakey}",
                notify  => Service["${sshd_service}${suffix}"],
                require => Package['ssh-server-package'],
            }

            # Copy the RSA host private key
            $rsa_pri_key = file(
                "${ssh::site_private_path}/${rsakey}${suffix}",
                "${settings::vardir}/private/${::fqdn}/${rsakey}${suffix}",
                "${settings::vardir}/hosts/${::fqdn}/${rsakey}${suffix}",
                "${settings::vardir}/nodefile/${::fqdn}/${rsakey}${suffix}",
                "${settings::vardir}/dist/${::fqdn}/${rsakey}${suffix}",
                '/dev/null'
            )
            if ( $rsa_pri_key ) {
                file { $rsakey:
                    mode    => '0400',
                    owner   => $ssh::user,
                    group   => $ssh::group,
                    content => $rsa_pri_key,
                    notify  => Service["${sshd_service}${suffix}"],
                    require => [
                        Package['ssh-server-package'],
                        Exec["generate-${rsakey}${suffix}"],
                    ],
                }
            } else {
                file { "${rsakey}${suffix}":
                    mode  => '0400',
                    owner => $ssh::user,
                    group => $ssh::group,
                }
            }

            # Copy the RSA host public key
            $rsa_pub_key = file(
                "${ssh::site_private_path}/${rsakey}${suffix}.pub",
                "${settings::vardir}/private/${::fqdn}/${rsakey}${suffix}.pub",
                "${settings::vardir}/hosts/${::fqdn}/${rsakey}${suffix}.pub",
                "${settings::vardir}/nodefile/${::fqdn}/${rsakey}${suffix}.pub",
                "${settings::vardir}/dist/${::fqdn}/${rsakey}${suffix}.pub",
                '/dev/null'
            )
            if ( $rsa_pub_key ) {
                file { "${rsakey}${suffix}.pub":
                    mode    => '0444',
                    owner   => $ssh::user,
                    group   => $ssh::group,
                    content => $rsa_pub_key,
                    notify  => Service["${sshd_service}${suffix}"],
                    require => [
                        Package['ssh-server-package'],
                        Exec["generate-${rsakey}${suffix}"],
                    ],
                }
            } else {
                file { "${rsakey}${suffix}.pub":
                    mode  => '0444',
                    owner => $ssh::user,
                    group => $ssh::group,
                }
            }

            # Copy the DSA host private key
            $dsa_pri_key = file(
                "${ssh::site_private_path}/${dsakey}${suffix}",
                "${settings::vardir}/private/${::fqdn}/${dsakey}${suffix}",
                "${settings::vardir}/hosts/${::fqdn}/${dsakey}${suffix}",
                "${settings::vardir}/nodefile/${::fqdn}/${dsakey}${suffix}",
                "${settings::vardir}/dist/${::fqdn}/${dsakey}${suffix}",
                '/dev/null'
            )
            if ( $dsa_pri_key ) {
                file { "$dsakey}${suffix}":
                    mode    => '0400',
                    owner   => $ssh::user,
                    group   => $ssh::group,
                    content => $dsa_pri_key,
                    notify  => Service["${sshd_service}${suffix}"],
                    require => [
                        Package['ssh-server-package'],
                        Exec["generate-${dsakey}${suffix}"],
                    ],
                }
            } else {
                file { "${dsakey}${suffix}":
                    mode  => '0400',
                    owner => $ssh::user,
                    group => $ssh::group,
                }
            }

            # Copy the DSA host public key
            $dsa_pub_key = file(
                "${ssh::site_private_path}/${dsakey}${suffix}.pub",
                "${settings::vardir}/private/${::fqdn}/${dsakey}${suffix}.pub",
                "${settings::vardir}/hosts/${::fqdn}/${dsakey}${suffix}.pub",
                "${settings::vardir}/nodefile/${::fqdn}/${dsakey}${suffix}.pub",
                "${settings::vardir}/dist/${::fqdn}/${dsakey}${suffix}.pub",
                '/dev/null'
            )
            if ( $dsa_pub_key ) {
                file { "${dsakey}${suffix}.pub":
                    mode    => '0444',
                    owner   => $ssh::user,
                    group   => $ssh::group,
                    content => $dsa_pub_key,
                    notify  => Service["${sshd_service}${suffix}"],
                    require => [
                        Package['ssh-server-package'],
                        Exec["generate-${dsakey}${suffix}"],
                    ],
                }
            } else {
                file { "${dsakey}${suffix}.pub":
                    mode  => '0444',
                    owner => $ssh::user,
                    group => $ssh::group,
                }
            }

            # Add this port to selinux.
            # The unless stanza checks for three things:
            #   * semanage exists
            #   * sestatus doesn't report disabled
            #   * semanage doesn't show that the context already exists
            exec { "add-semanage-port-${port}":
                path    => [ '/sbin', '/usr/sbin', '/bin', '/usr/bin' ],
                command => "semanage port -a -t ${seport_context} -p tcp ${port}",
                unless  => "test ! -f /usr/sbin/semanage || sestatus | grep -i 'disabled' || semanage port -l | grep \"^${seport_context}.*${port}\"",
                notify  => Service["${sshd_service}${suffix}"],
            }

            # Add this daemon to the run levels
            case $::operatingsystem {
                'centos','debian','fedora','opensuse','redhat','sles','ubuntu': {
                    exec { "add-runlevels-${sshd_service}${suffix}":
                        path     => '/sbin:/usr/sbin:/bin:/usr/bin',
                        command  => $ssh_add_runlevel_cmd,
                        notify   => Service["${sshd_service}${suffix}"],
                        unless   => "ls /etc/rc2.d/S[0-9][0-9]${sshd_service}",
                        require  => [
                                Package['ssh-server-package'],
                                File["${ssh_init}${suffix}"],
                        ],
                    }
                }

                'freebsd': {
                    exec { "enable-${sshd_service}${suffix}":
                        command => "/bin/cat /etc/rc.conf | /usr/bin/awk '{ if ( /^${sshd_service}${suffix}_enable.*/ ) { found=1; print \"${sshd_service}${suffix}_enable=\\\"YES\\\"\"; } else { print; } } END { if (!found) { print \"${sshd_service}${suffix}_enable=\\\"YES\\\"\" }}' > /etc/rc.conf.puppet && /bin/mv /etc/rc.conf.puppet /etc/rc.conf",
                        unless  => "/usr/bin/grep \"^${sshd_service}${suffix}_enable=\" /etc/rc.conf",
                        before  => Exec["add-runlevels-${sshd_service}${suffix}"],
                    }
                    exec { "add-runlevels-${sshd_service}${suffix}":
                        command => "/bin/cat /etc/rc.conf.local | /usr/bin/awk '{ if ( /^${sshd_service}${suffix}_flags.*/ ) { found=1; print \"${sshd_service}${suffix}_flags=\\\"-f ${sshd_config}${suffix}\\\"\"; } else { print; } } END { if (!found) { print \"${sshd_service}${suffix}_flags=\\\"-f ${sshd_config}${suffix}\\\"\" }}' > /etc/rc.conf.local.puppet && /bin/mv /etc/rc.conf.local.puppet /etc/rc.conf.local",
                        unless  => "/usr/bin/grep \"^${sshd_service}${suffix}_flags=\\\"-f ${sshd_config}${suffix}\\\"\" /etc/rc.conf.local",
                        before  => Service["${sshd_service}${suffix}"],
                        require => Exec["enable-${sshd_service}${suffix}"],
                    }
                }

                'openbsd': {
                    # OpenBSD manages services using rc.conf.local
                    exec { "add-runlevels-${sshd_service}${suffix}":
                        command => "/bin/cat /etc/rc.conf.local | /usr/bin/awk '{ if ( /^${sshd_service}${suffix}_.*/ ) { found=1; print \"${sshd_service}${suffix}_flags=\\\"-f ${sshd_config}${suffix}\\\"\"; } else { print; } } END { if (!found) { print \"${sshd_service}${suffix}_flags=\\\"-f ${sshd_config}${suffix}\\\"\" }}' > /etc/rc.conf.local.puppet && /bin/mv /etc/rc.conf.local.puppet /etc/rc.conf.local",
                        unless  => "/usr/bin/grep \"^${sshd_service}${suffix}_flags=\\\"-f ${sshd_config}${suffix}\\\"\" /etc/rc.conf.local",
                    }
                }
                default: {}
            }

            # Make sure the service is running.
            service { "${sshd_service}${suffix}":
                ensure     => 'running',
                enable     => true,
                path       => [ '/etc/init.d/', '/etc/rc.d' ],
                hasrestart => $ssh_hasrestart,
                start      => "${ssh_init}${suffix} ${ssh_start}",
                stop       => "${ssh_init}${suffix} ${$ssh_stop}",
                status     => "${ssh_init}${suffix} ${ssh_status}",
                require    => [ Package['ssh-server-package'],
                                File["${sshd_config}${suffix}"],
                                File["${sshd_binary}${suffix}"],
                                Exec["add-runlevels-${sshd_service}${suffix}"],
                                Exec["generate-${rsakey}${suffix}"],
                                Exec["generate-${dsakey}${suffix}"],
                            ],
            }
        } else {
            # Stop the daemon
            service { "${sshd_service}${suffix}":
                ensure     => 'stopped',
                enable     => false,
                path       => [ '/etc/init.d/', '/etc/rc.d' ],
                hasrestart => $ssh_hasrestart,
                stop       => "${ssh_init}${suffix} ${$ssh_stop}",
                status     => "${ssh_init}${suffix} ${ssh_status}",
            }

            # Remove the init script for this server
            file { "${ssh_init}${suffix}":
                ensure  => 'absent',
                require => Service["${sshd_service}${suffix}"],
                before  => Exec["del-runlevels-${sshd_service}${suffix}"],
            }

            # Remove the daemon from the run levels
            case $::operatingsystem {
                'centos','debian','fedora','opensuse','redhat','sles','ubuntu': {
                    exec { "del-runlevels-${sshd_service}${suffix}":
                        path    => '/sbin:/usr/sbin:/bin:/usr/bin',
                        command => $ssh_del_runlevel_cmd,
                        onlyif  => "ls /etc/rc2.d/S[0-9][0-9]${sshd_service}",
                        before  => File["${sshd_config}${suffix}"],
                        require => [
                            File["${ssh_init}${suffix}"],
                            Service["${sshd_service}${suffix}"],
                        ],
                    }
                }
                'freebsd': {
                    # FreeBSD manages services using rc.conf and rc.conf.local
                    exec { "disable-${sshd_service}${suffix}":
                        command => "/usr/bin/grep -v \"^${sshd_service}${suffix}_\" /etc/rc.conf > /etc/rc.conf.puppet && /bin/mv /etc/rc.conf.puppet /etc/rc.conf",
                        onlyif  => "/usr/bin/grep \"^${sshd_service}${suffix}_enable=\" /etc/rc.conf",
                    }
                    exec { "del-runlevels-${sshd_service}${suffix}":
                        command => "/usr/bin/grep -v \"^${sshd_service}${suffix}_\" /etc/rc.conf.local > /etc/rc.conf.local.puppet && /bin/mv /etc/rc.conf.local.puppet /etc/rc.conf.local",
                        onlyif  => "/usr/bin/grep \"^${sshd_service}${suffix}_flags=\\\"-f ${sshd_config}${suffix}\\\"\" /etc/rc.conf.local",
                        require => Exec["disable-${sshd_service}${suffix}"],
                    }
                }

                'openbsd': {
                    # OpenBSD manages services using rc.conf.local
                    exec { "del-runlevels-${sshd_service}${suffix}":
                        command => "/usr/bin/grep -v \"^${sshd_service}${suffix}_\" /etc/rc.conf.local > /etc/rc.conf.local.puppet && /bin/mv /etc/rc.conf.local.puppet /etc/rc.conf.local",
                        onlyif  => "/usr/bin/grep \"^${sshd_service}${suffix}_flags=\\\"-f ${sshd_config}${suffix}\\\"\" /etc/rc.conf.local",
                    }
                }
                default: { fail( "can't disable runlevels for ${::operatingsystem}" ) }
            }

            # Remove this port from selinux
            exec { "del-semanage-port-${port}":
                path    => [ '/sbin', '/bin' ],
                command => "semanage port -d -t ${seport_context} -p tcp ${port}",
                onlyif  => "test -f /usr/sbin/semanage && sestatus | grep -i 'enabled' && semanage port -l | grep \"^${seport_context}.*${port}\"",
                require => [
                    Exec["del-runlevels-${sshd_service}${suffix}"],
                    Service["${sshd_service}${suffix}"],
                ],
            }

            # Remove the /etc/default file for this server
            case $::operatingsystem {
                'centos','debian','fedora','opensuse','redhat','sles','ubuntu': {
                    file { "${ssh_default}${suffix}":
                        ensure  => 'absent',
                        require => [
                            Exec["del-runlevels-${sshd_service}${suffix}"],
                            Service["${sshd_service}${suffix}"],
                        ],
                    }
                }
                default: {}
            }

            # Remove the sshd_config for this server
            file { "${sshd_config}${suffix}":
                ensure  => 'absent',
                require => [
                    Exec["del-runlevels-${sshd_service}${suffix}"],
                    Service["${sshd_service}${suffix}"],
                ],
            }

            # Remove Ubuntu's other init script
            case $::operatingsystem {
                'ubuntu': {
                    file { $ssh_conf:
                        ensure  => 'absent',
                        require => [
                            Exec["del-runlevels-${sshd_service}${suffix}"],
                            Service["${sshd_service}${suffix}"],
                        ],
                    }
                }
                default: {}
            }

            # Remove the PAM configuration for this server
            case $::operatingsystem {
                'centos','debian','fedora','opensuse','redhat','sles','ubuntu': {
                    file { "${sshd_pam}${suffix}":
                        ensure  => 'absent',
                        require => [
                            Exec["del-runlevels-${sshd_service}${suffix}"],
                            Service["${sshd_service}${suffix}"],
                        ],
                    }
                }
                default: {}
            }

            # Remove the deny_users file for this server
            case $::operatingsystem {
                'centos','debian','fedora','opensuse','redhat','sles','ubuntu': {
                    file { "${deny_users}${suffix}":
                        ensure  => 'absent',
                        require => [
                            Exec["del-runlevels-${sshd_service}${suffix}"],
                            Service["${sshd_service}${suffix}"],
                        ],
                    }
                }
                default: {}
            }

            # Remove the PID file for this server
            file { "/var/run/${sshd_name}${suffix}.pid":
                ensure  => 'absent',
                require => [
                    Exec["del-runlevels-${sshd_service}${suffix}"],
                    Service["${sshd_service}${suffix}"],
                ],
            }

            # Remove the privilege separation directory
            if $sshd_privdir != '' {
                file { "${sshd_privdir}${suffix}":
                    ensure  => 'absent',
                    require => [
                        Exec["del-runlevels-${sshd_service}${suffix}"],
                        Service["${sshd_service}${suffix}"],
                    ],
                }
            }

            # Remove the sshd_symlink if we were using an alternate port
            if $port != 22 {
                file { "${sshd_binary}${suffix}":
                    ensure  => 'absent',
                    require => [
                        Exec["del-runlevels-${sshd_service}${suffix}"],
                        Service["${sshd_service}${suffix}"],
                    ],
                }
            }
        }
    }
}
