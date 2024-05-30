<!-- markdownlint-disable MD013 MD041 -->
[![ansible-lint](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/ansible-lint.yml) [![Publish to Ansible Galaxy](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/release.yml/badge.svg)](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/release.yml) [![markdown link check](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/markdown-link-check.yml/badge.svg)](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/markdown-link-check.yml) [![markdownlint](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/markdownlint.yml/badge.svg)](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/markdownlint.yml) [![pyspelling](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/pyspelling.yml/badge.svg)](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/pyspelling.yml) [![gitleaks](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/sscheib/ansible-role-openwrt_base/actions/workflows/gitleaks.yml)

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit) [![gitleaks](https://img.shields.io/badge/gitleaks-enabled-blue.svg)](https://github.com/gitleaks/gitleaks) [![renovate](https://img.shields.io/badge/renovate-enabled-brightgreen?logo=renovatebot)](https://github.com/apps/renovate) [![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org) [![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
<!-- markdownlint-disable MD013 MD041 -->

## openwrt_base

This role deploys a "base" configuration on `OpenWrt` devices.

Namely, it is able to perform the following things:

- Set and delete [`UCI`](https://openwrt.org/docs/techref/uci) keys
- Create a [`hosts file`](https://en.wikipedia.org/wiki/Hosts_(file)) that contains the device's `hostname` and `IP address`
- Set [`sysctl`](https://linux.die.net/man/8/sysctl) keys
- Install and enable [`chrony`](https://chrony-project.org) in favor of `ntpd`
- Set a [`hostname`](https://linux.die.net/man/1/hostname)
- Configure a `rc.local` file that is executed on boot
- Configure mounts that are mounted on boot (including network file systems, e.g. `NFS`)
- Transfer and [`template`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/template_module.html) files
- Install [`shadow`](https://man7.org/linux/man-pages/man5/shadow.5.html) so you can make use of [`su`](https://man7.org/linux/man-pages/man1/su.1.html)
  and [`sudo`](https://man7.org/linux/man-pages/man8/sudo.8.html)
- Change the default encryption for passwords
- Set a `root` password
- Set a default `shell` for the `root` user
- Install and configure [`vim`](https://www.vim.org)
- Configure [`profile.d`](https://man.cx/profile) by deploying scripts to it
- Configure [`cron`](https://man7.org/linux/man-pages/man8/cron.8.html) jobs
- Create users and groups
- Configure password-less `sudo` for privileged groups
- Transfer SSH keys for users (only relevant when using `SSHd`; If you are using `dropbear`, refer to the role
  [`ansible-role-openwrt_dropbear`](https://github.com/sscheib/ansible-role-openwrt_dropbear), which can configure `dropbear` and deploy SSH keys for `dropbear`)

**Please note**:

- This role requires Python to be installed on your `OpenWrt` device. If you are looking for a role to bootstrap Python on your `OpenWrt` device, the role
  [`openwrt_bootstrap`](https://github.com/sscheib/ansible-role-openwrt_bootstrap) might be of interest to you.
- The role further validates *all* parameters and has a "longer" start time. Validation of the parameters happens on the **control node** and not the node you are
  automating
- Although all parameters are **optional**, this role validates their existence and type.
- By default this role **does nothing**, which requires you to enable each feature individually. This is done to avoid an accidental misconfiguration of the `OpenWrt`
  device.

## Requirements

This role requires the collection [`ansible.posix`](https://github.com/ansible-collections/ansible.posix). The collection is specified via
`collections/requirements.yml`.

## Role Variables

| variable                                 | default                      | required | description                                                                         |
| :--------------------------------------- | :--------------------------- | :------- | :---------------------------------------------------------------------------------- |
| `owb_authorized_keys_enable`             | `false`                      | false    | Whether to enable transferring of `authorized_keys` defined in `owb_users`          |
| `owb_authorized_keys_no_log`             | `true`                       | false    | Whether to set `no_log` for `authorized_keys` tasks                                 |
| `owb_base_packages_enable`               | `false`                      | false    | Whether to install base packages                                                    |
| `owb_base_packages`                      | see `defaults/main.yml`      | false    | List of packages to install                                                         |
| `owb_chrony_enable`                      | `false`                      | false    | Whether to enable the installation and configuration of `chrony`                    |
| `owb_chrony_check_sources_enable`        | `false`                      | false    | Whether to run `chronyc sources` to check if they are reachable                     |
| `owb_chrony_conf_dest`                   | `/etc/config/chrony`         | false    | Path to the `UCI` configuration file for `chrony`                                   |
| `owb_chrony_conf_group`                  | `root`                       | false    | Group of the configuration file of `chrony`                                         |
| `owb_chrony_conf_mode`                   | `0600`                       | false    | Mode of the configuration file of `chrony`                                          |
| `owb_chrony_conf_owner`                  | `root`                       | false    | Owner of the configuration file of `chrony`                                         |
| `owb_chrony_conf_src_file`               | `chrony.j2`                  | false    | `chrony` source `Jinja2` template file                                              |
| `owb_chrony_disable_ipv6`                | `false`                      | false    | Whether to disable IPv6 in `chrony`                                                 |
| `owb_chrony_initd_file`                  | `/etc/config/chrony`         | false    | Path to the `init.d` file of `chrony`                                               |
| `owb_chrony_package_name`                | `chrony`                     | false    | `chrony` package name in `opkg`                                                     |
| `owb_chrony_service_name`                | `chronyd`                    | false    | Name of the `init.d` service of `chrony`                                            |
| `owb_cron_enable`                        | `false`                      | false    | Whether to enable configuration of `cron`                                           |
| `owb_cron_jobs`                          | see `defaults/main.yml`      | false    | `cron` jobs to create                                                               |
| `owb_hostname_enable`                    | `false`                      | false    | Whether to create the `hostname` file                                               |
| `owb_hostname_group`                     | `root`                       | false    | Group of the `hostname` file                                                        |
| `owb_hostname_mode`                      | `0644`                       | false    | Mode of the `hostname` file                                                         |
| `owb_hostname`                           | `{{ inventory_hostname }}`   | false    | `hostname` to set                                                                   |
| `owb_hostname_owner`                     | `root`                       | false    | Owner of the `hostname` file                                                        |
| `owb_hostname_path`                      | `/etc/hostname`              | false    | Path to the `hostname` file                                                         |
| `owb_hostname_proc_path`                 | `/proc/sys/kernel/hostname`  | false    | Path to the `/proc` item that holds the `hostname`                                  |
| `owb_hosts_file_enable`                  | `false`                      | false    | Whether to enable generation of the hosts file                                      |
| `owb_hosts_file_group`                   | `root`                       | false    | Group of the hosts file                                                             |
| `owb_hosts_file_mode`                    | `0644`                       | false    | Mode of the hosts file                                                              |
| `owb_hosts_file_owner`                   | `root`                       | false    | Owner of the hosts file                                                             |
| `owb_hosts_file_path`                    | `/etc/hosts`                 | false    | Path to the hosts file                                                              |
| `owb_lan_interface_name`                 | `br-lan`                     | false    | Interface name of the `LAN` device to detect the `LAN IP`                           |
| `owb_login_defs_encrypt_method`          | `SHA512`                     | false    | Encryption and hash to be used for user account passwords (including `root`)        |
| `owb_login_defs_file`                    | `/etc/login.defs`            | false    | Path to the `login.defs` file where the change is implemented                       |
| `owb_mounts_enable`                      | `false`                      | false    | Whether to enable configuration of mounts                                           |
| `owb_mounts`                             | unset                        | false    | Mounts to configure                                                                 |
| `owb_mounts_required_packages`           | unset                        | false    | Packages to install prior to mounting (e.g. kernel modules for `NFS`)               |
| `owb_ntpd_package_name`                  | `ntpd`                       | false    | Package name of the `ntp` package in `opkg`                                         |
| `owb_password_hash_encryption_enable`    | `false`                      | false    | Whether to enable the password hash/encryption method configuration                 |
| `owb_password_hash`                      | `bcrypt`                     | false    | Password hash to use when generating a `root` password [^encryption]                |
| `owb_profile_d_configuration_enable`     | `false`                      | false    | Whether `profile.d` files and templates should be transferred                       |
| `owb_profile_d_creation_enable`          | `false`                      | false    | Whether the `profile.d` directory should be created                                 |
| `owb_profile_d_files`                    | see `defaults/main.yml`      | false    | Files to place in the `profile.d` path                                              |
| `owb_profile_d_path_group`               | `root`                       | false    | Group of the `profile.d` directory                                                  |
| `owb_profile_d_path_mode`                | `0755`                       | false    | Mode of the `profile.d` directory                                                   |
| `owb_profile_d_path`                     | `/etc/profile.d`             | false    | Path to the `profile.d` directory                                                   |
| `owb_profile_d_path_owner`               | `root`                       | false    | Owner of the `profile.d` directory                                                  |
| `owb_quiet_assert`                       | `false`                      | false    | Whether to quiet `assert` statements                                                |
| `owb_rc_local_dest`                      | `/etc/rc.local`              | false    | Path to the `rc.local` file                                                         |
| `owb_rc_local_enable_mwan3_restart`      | `false`                      | false    | Whether to restart `mwan3` when executing `rc.local`                                |
| `owb_rc_local_enable`                    | `false`                      | false    | Whether to enable generation of an `rc.local` file                                  |
| `owb_rc_local_enable_redirect_dev_null`  | `false`                      | false    | Whether to redirect command output to `/dev/null` to not clutter `syslog`           |
| `owb_rc_local_enable_restore_iptables`   | `false`                      | false    | Whether to enable restoring `iptables` within `rc.local`                            |
| `owb_rc_local_enable_sleep`              | `false`                      | false    | Whether to sleep before applying `iptables` and mounting [^sleep]                   |
| `owb_rc_local_enable_write_to_serial`    | `false`                      | false    | Whether to write messages to a serial device within `rc.local`                      |
| `owb_rc_local_group`                     | `root`                       | false    | Group of the `rc.local` file                                                        |
| `owb_rc_local_iptables_rules_file_path`  | unset                        | false    | Path to an executable (e.g. `/etc/iptables.sh`) to apply `iptables` rules           |
| `owb_rc_local_mode`                      | `0755`                       | false    | Owner of the `rc.local` file                                                        |
| `owb_rc_local_mwan3_initd_path`          | `/etc/init.d/mwan3`          | false    | Path to the `init.d` file of `mwan3`                                                |
| `owb_rc_local_owner`                     | `root`                       | false    | Owner of the `rc.local` file                                                        |
| `owb_rc_local_serial_device`             | `/dev/ttyS0`                 | false    | Serial device to write to in `rc.local`                                             |
| `owb_rc_local_sleep_seconds`             | `15`                         | false    | Number of seconds to sleep                                                          |
| `owb_rc_local_template`                  | `rc.local.j2`                | false    | Source `Jinja2` template for the `rc.local` file                                    |
| `owb_root_password_enable`               | `false`                      | false    | Whether to enable setting the `root` password                                       |
| `owb_root_password`                      | unset                        | false    | `root` password to set                                                              |
| `owb_root_shell_enable`                  | `false`                      | false    | Whether to enable setting the `shell` for the `root` user                           |
| `owb_root_shell`                         | `/bin/bash`                  | false    | Path to an alternative `shell` to use for the `root` user                           |
| `owb_shadow_enable`                      | `false`                      | false    | Whether to enable the installation of packages associated with the `shadow` package |
| `owb_shadow_packages`                    | `['shadow', 'sudo']`         | false    | List of packages to install to provide `shadow` functionality                       |
| `owb_shell_packages`                     | `['bash']`                   | false    | List of packages to install prior to setting the `shell` for the `root` user        |
| `owb_skip_assert`                        | `false`                      | false    | Whether to skip the initial `assert` [^assert]                                      |
| `owb_sysctl_enable`                      | `false`                      | false    | Whether to set `sysctl` keys                                                        |
| `owb_sysctl_keys`                        | see `defaults/main.yml`      | false    | Keys to set in the `sysctl` configuration files                                     |
| `owb_transfer_files`                     | unset                        | false    | Files to transfer                                                                   |
| `owb_uci_keys_enable`                    | `false`                      | false    | Whether to enable the setting of `UCI` keys                                         |
| `owb_uci_keys`                           | see `defaults/main.yml`      | false    | `UCI` keys to set                                                                   |
| `owb_uci_keys_removal_enable`            | `false`                      | false    | Whether to enable the removal of `UCI` keys                                         |
| `owb_uci_keys_remove`                    | see `defaults/main.yml`      | false    | `UCI` keys to delete                                                                |
| `owb_users_enable`                       | `false`                      | false    | Whether to deploy users                                                             |
| `owb_users`                              | unset                        | false    | List of users to deploy                                                             |
| `owb_users_required_packages`            | `['shadow', 'sudo']`         | false    | Packages required to install prior to adding users                                  |
| `owb_vim_enable`                         | `false`                      | false    | Whether to configure `vim`                                                          |
| `owb_vim_package_match_list`             | see `defaults/main.yml`      | false    | `vim` packages to remove prior to installing the desired `vim` package [^delete]    |
| `owb_vim_package_name`                   | `vim-fuller`                 | false    | Package name of `vim` to install via `opkg`                                         |
| `owb_vimrc_default_conf_dest_path`       | `/usr/share/vim/vimrc`       | false    | Where to place the default `vimrc` configuration file                               |
| `owb_vimrc_default_conf_group`           | `root`                       | false    | Group of the `vimrc` configuration file                                             |
| `owb_vimrc_default_configuration_enable` | `false`                      | false    | Whether to deploy a default configuration for `vim`                                 |
| `owb_vimrc_default_conf_mode`            | `0644`                       | false    | Mode of the `vimrc` configuration file                                              |
| `owb_vimrc_default_conf_owner`           | `root`                       | false    | Owner of the `vimrc` configuration file                                             |
| `owb_vimrc_default_conf_src`             | `vimrc`                      | false    | Source file of the default `vimrc` configuration file                               |
| `owb_vimrc_simplistic_content`           | `set clipboard=unnamed`      | false    | Content to add to the simplistic user `.vimrc` file                                 |
| `owb_vimrc_simplistic_mode`              | `0600`                       | false    | Mode of the simplistic user `.vimrc` [^permissions]                                 |
| `owb_vimrc_simplistic_user_vimrc_enable` | `false`                      | false    | Whether to place a simplistic `.vimrc` in user directories (including `root` user)  |
| `owb_vimrc_users`                        | unset                        | false    | Users to add a simplistic `.vimrc` into their home directory (other than `root`)    |

## Variable `owb_cron_jobs`

An extended example of only the `owb_cron_jobs` variable is illustrated down below:

```yaml
owb_cron_jobs:
  - name: 'Refresh opkg lists once a day'
    minute: 0
    hour: 4
    day: 1
    job: '/bin/opkg update 2>&1 > /dev/null'
```

Only the `name` attribute is required and validated. All other attributes can be mixed and matched.

This role supports all module options of [`ansible.builtin.cron`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/cron_module.html) as of this date
(25.05.2024).

## Variable `owb_mounts`

An extended example of only the `owb_mounts` variable is illustrated down below:

```yaml
owb_mounts:
  - path: '/backup'
    src: 'nfs.example.com:/share/{{ inventory_hostname }}'
    state: 'mounted'
    backup: false
    boot: true
    dump: 0
    fstab: '/etc/fstab'
    fstype: 'nfs4'
    opts: 'rw,nolock'
    passno: 0
    owner: 'root'
    group: 'root'
    mode: '0755'
```

This role uses [`ansible.posix.mount`](https://docs.ansible.com/ansible/latest/collections/ansible/posix/mount_module.html) to mount file systems. It supports all module
options as of this date (25.05.2024).

With the attributes `owner`, `group` and `mode` the *directory* permissions are specified. In the above example the directory `/backup` will be created with `owner` and
`group` set to `root` and adjust the `mode` to `0755`.

Further `path`, `src` and `state` are required parameters.

The above example will mount the `NFS` share `nfs.example.com:/share/{{ inventory_hostname }}` to `/backup` and ensures the state is
[`mounted`](https://docs.ansible.com/ansible/latest/collections/ansible/posix/mount_module.html#parameter-state).

Required arguments are:

- `owner`
- `group`
- `mode`
- `path`
- `src`
- `state`

**Note**: `owner`, `group` and `mode` are enforced (although default permissions would be applied when not specified) to set to prevent insecure permissions.

All other module options of [`ansible.builtin.posix`](https://docs.ansible.com/ansible/latest/collections/ansible/posix/mount_module.html) can be mixed and matched.

## Variable `owb_profile_d_files`

An extended example of only the `owb_profile_d_files` variable is illustrated down below:

```yaml
  - src: 'history.j2'
    owner: 'root'
    group: 'root'
    mode: '0644'
    template: true
    destination_suffix: 'sh'

  - src: 'aliases.j2'
    owner: 'root'
    group: 'root'
    mode: '0644'
    template: true
    destination_suffix: 'sh'

  - src: 'general.j2'
    owner: 'root'
    group: 'root'
    mode: '0644'
    template: true
    destination_suffix: 'sh'

  - src: 'ps1.j2'
    owner: 'root'
    group: 'root'
    mode: '0644'
    template: true
    destination_suffix: 'sh'
```

Required attributes are:

- `src`
- `owner`
- `group`
- `mode`

The files and templates will be placed in `owb_profile_d_path`.

By default the [`ansible.builtin.copy`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/copy_module.html) is used to transfer files as they are.

If you are looking to apply `Jinja2` templating, ensure to set `template: true` for files that should be templated. These files will then be templated with the
[`ansible.builtin.template`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/template_module.html) module.

Please remember, that `ansible.builtin.copy` will look for files in `files/` and `ansible.builtin.template` will look for templates in `templates/`.

Specifying `destination_suffix` allows to specify a new suffix for the destination file. This is especially helpful when saving templates with a `.j2` suffix within the
`template/` directory while the file is actually a different type (such as a `.sh` file, as in the above example)

## Variable `owb_sysctl_keys`

An extended example of only the `owb_sysctl_keys` variable is illustrated down below:

```yaml
owb_sysctl_keys:
  - name: 'net.ipv6.conf.all.disable_ipv6'
    reload: true
    state: 'present'
    sysctl_file: '/etc/sysctl.d/99-disable_ipv6.conf'
    sysctl_set: true
    value: 1

  - name: 'net.ipv6.conf.default.disable_ipv6'
    reload: true
    state: 'present'
    sysctl_file: '/etc/sysctl.d/99-disable_ipv6.conf'
    sysctl_set: true
    value: 1
```

The role uses [`ansible.posix.sysctl`](https://docs.ansible.com/ansible/latest/collections/ansible/posix/sysctl_module.html) to apply `sysctl` keys on the destination
managed node.

Required attributes are only `name` and `value`. `value` is only validated for its existence, as `value` can be virtually any data type.

All supported module options of [`ansible.posix.sysctl`] as of today (25.05.2024) are supported.

## Variable `owb_uci_keys`

An extended example of only the `owb_uci_keys` variable is illustrated down below:

```yaml
  # host name
  - key: 'system.@system[0].hostname'
    value: 'openwrt'

  # cron log level
  - key: 'system.@system[0].cronloglevel'
    value: 5

  # kernel log connection log level to console
  - key: 'system.@system[0].klogconloglevel'
    value: 8

  # timezone
  - key: 'system.@system[0].timezone'
    value: 'CET-1CEST,M3.5.0,M10.5.0/3'
  - key: 'system.@system[0].zonename'
    value: 'Europe/Berlin'

  # disable IPv6 delegation
  - key: 'network.lan.delegate'
    value: 0

  # disable rebind protection of dnsmasq to be able to resolve all internal hosts
  - key: 'dhcp.@dnsmasq[0].rebind_protection'
    value: 0

  # disable IPv6 on WAN and LAN interface
  - key: 'network.@device[0].ipv6'
    value: 0

  - key: 'network.@device[1].ipv6'
    value: 0

  - key: 'network.wan.ipv6'
    value: 0

  - key: 'network.lan.ipv6'
    value: 0

  # disable IPv6 on loopback
  - key: 'network.loopback.ipv6'
    value: 0
```

Both `key` and `value` are required attributes. `value` is only validated for its existence, as `value` can be virtually any data type.

## Variable `owb_users`

An extended example of only the `owb_users` variable is illustrated down below:

```yaml
owb_users:
  - name: 'bob'
    group: 'bob'
    privileged: true
    shell: '/bin/bash'
    home: '/home/bob'
    password: !vault |
          $ANSIBLE_VAULT;1.2;AES256
          [..]
    additional_groups:
      - name: 'privileged_group'
        privileged: true

      - name: 'unprivileged_group'
        privileged: false

      - name: 'unprivileged_group2'

    remove_unspecified_ssh_keys: true
    authorized_keys:
      - !vault |
          $ANSIBLE_VAULT;1.2;AES256
          [..]

      - 'id_ecdsa.pub'
```

Only the `name` is required when specifying no additional groups. When specifying additional groups, each group needs to have the `name` attribute set.

When specifying `group`, `group` will be used set as the primary group for the user. Additional groups specified via `additional_groups` are supplementary groups where
the user gets added to.

All groups will be created if they don't exist.

By specifying `privileged: true` (for both the primary as well as for each individual supplementary group) and additionally setting `owb_sudoers_d_enable: true`,
privileged groups will get a `sudoers.d` file generated with the following content:

When specifying `password`, it will be hashed with `owb_password_hash`.

`authorized_keys` can be specified either by referencing a file or simply by adding in-line `SSH` public keys to the list. Please note that if a file does not exist,
it will *automatically* interpret the SSH key as in-line key and add it to the `authorized_keys` file.

```plaintext
%MY_GROUP ALL=(ALL) NOPASSWD: ALL
```

SSH keys can be specified as both in-line SSH keys or by specifying a file that has to exist on the *control* node where the playbook is run. Setting
`remove_unspecified_ssh_keys: true` will remove all keys that are not specified for each individual user.

## Variable `owb_vimrc_users`

An extended example of only the `owb_vimrc_users` variable is illustrated down below:

```yaml
owb_vimrc_users:
  - name: 'bob'
    home: '/custom/home/bob'

  - name: 'alice'
```

Only `name` is required. It is assumed a default home directory (e.g. `/home/alice`) if `home` is not specified as an attribute for the user.

## Dependencies

None

## Example Playbook

```yaml
---
- name: 'Deploy files'
  hosts: 'all'
  gather_facts: false
  vars:
    # whether to enable generation of the hosts file
    owb_hosts_file_enable: true

    # the interface name of the LAN device to detect the LAN ip
    # which will be written to /etc/hosts along with the hostname
    owb_lan_interface_name: 'br-lan'

    # path and permissions of the hosts file (usually /etc/hosts)
    owb_hosts_file_path: '/etc/hosts'
    owb_hosts_file_owner: 'root'
    owb_hosts_file_group: 'root'
    owb_hosts_file_mode: '0644'
    # whether to enable sysctl configuration
    owb_sysctl_enable: true

    # keys to set in the sysctl config file
    # disable IPv6 on all interfaces
    owb_sysctl_keys:
      - name: 'net.ipv6.conf.all.disable_ipv6'
        reload: true
        state: 'present'
        sysctl_file: '/etc/sysctl.d/99-disable_ipv6.conf'
        sysctl_set: true
        value: 1

      - name: 'net.ipv6.conf.default.disable_ipv6'
        reload: true
        state: 'present'
        sysctl_file: '/etc/sysctl.d/99-disable_ipv6.conf'
        sysctl_set: true
        value: 1
    # whether to enable the installation and configuration of chrony
    owb_chrony_enable: true

    # chrony package name
    owb_chrony_package_name: 'chrony'

    # ntpd package name to remove
    owb_ntpd_package_name: 'ntpd'

    # chrony service name
    owb_chrony_service_name: 'chronyd'

    # chrony source Jinja2 template file
    owb_chrony_conf_src_file: 'chrony.j2'

    # chrony configuration file path and permissions
    owb_chrony_conf_dest: '/etc/config/chrony'
    owb_chrony_conf_owner: 'root'
    owb_chrony_conf_group: 'root'
    owb_chrony_conf_mode: '0600'

    # chrony init.d script path
    owb_chrony_initd_file: '/etc/init.d/chronyd'

    # whether to disable IPv6 in chrony
    owb_chrony_disable_ipv6: true

    # whether to run chronyc sources to check if they are reachable
    # note: chronyc sources exits with a return code greater than 0
    #       if an issue is encountered while reaching the defined
    #       servers
    owb_chrony_check_sources_enable: true
    # whether to create the host name file
    owb_hostname_enable: true

    # hostname to set
    owb_hostname: '{{ inventory_hostname }}'

    # path to the /proc item that holds the hostname
    # this is used in the rc.local to apply the hostname on each boot
    owb_hostname_proc_path: '/proc/sys/kernel/hostname'

    # path and permissions to the hostname file
    owb_hostname_path: '/etc/hostname'
    owb_hostname_owner: 'root'
    owb_hostname_group: 'root'
    owb_hostname_mode: '0644'
    # whether to enable configuration of mounts
    owb_mounts_enable: true

    # packages required to install before attempting to mount
    # begin nospell
    # for NFS, e.g.:
    # - 'kmod-fs-nfs-v4'
    # - 'nfs-utils'
    # - 'kmod-fs-nfs'
    # end nospell
    owb_mounts_required_packages:
      - 'kmod-fs-nfs-v4'
      - 'nfs-utils'
      - 'kmod-fs-nfs'

    # mount points to create and mount
    owb_mounts:
      - path: '/backup'
        src: '172.31.4.100:/volume1/{{ inventory_hostname }}'
        state: 'mounted'
        backup: false
        boot: true
        dump: 0
        fstab: '/etc/fstab'
        fstype: 'nfs4'
        opts: 'rw,nolock'
        passno: 0
        owner: 'root'
        group: 'root'
        mode: '0755'
    # whether to enable generation of an rc.local file
    owb_rc_local_enable: true

    # source Jinja2 template for the rc.local file
    owb_rc_local_template: 'rc.local.j2'

    # path of the rc.local file and permissions
    owb_rc_local_dest: '/etc/rc.local'
    owb_rc_local_owner: 'root'
    owb_rc_local_group: 'root'
    owb_rc_local_mode: '0755'

    # whether to write messages to serial device within rc.local
    owb_rc_local_enable_write_to_serial: true

    # serial device to write to in rc.local
    owb_rc_local_serial_device: '/dev/ttyS0'

    # whether to restart mwan3 when executing rc.local
    owb_rc_local_enable_mwan3_restart: true

    # path to the init.d file for mwan3
    owb_rc_local_mwan3_initd_path: '/etc/init.d/mwan3'

    # whether to sleep before applying iptables and mounting (potentially network storage paths)
    # to allow networking to come up
    owb_rc_local_enable_sleep: true

    # number of seconds to sleep
    owb_rc_local_sleep_seconds: 15

    # whether to enable restoring iptables within rc.local
    owb_rc_local_enable_restore_iptables: true

    # path to an executable (e.g. /etc/iptables.sh) to apply iptables rules
    owb_rc_local_iptables_rules_file_path: '/etc/iptables.rules'

    # whether to redirect command output to /dev/null in rc.local to not clutter the syslog
    owb_rc_local_enable_redirect_dev_null: true
    # files to transfer
    owb_transfer_files:
      # /etc/inputrc
      - src: 'inputrc'
        dest: '/etc/inputrc'
        owner: 'root'
        group: 'root'
        mode: '0644'
        become: true
        template: true
    #
    # root user
    #

    # whether to enable setting the root password
    owb_root_password_enable: true

    # root password
    owb_root_password: !vault |
              $ANSIBLE_VAULT;1.2;AES256
              [..]

    # password hash to use when generating a root password
    # by default OpenWrt 21.02 - 23.05 uses 'bcrypt'
    owb_password_hash: 'sha512_crypt'

    # whether to enable changing the root shell (default '/bin/sh')  # nospell
    owb_root_shell_enable: true

    # list of packages to install prior to setting the shell for the root user
    owb_shell_packages:
      - 'bash'

    # path to an alternative shell to use
    # e.g.: '/bin/bash'  # nospell
    owb_root_shell: '/bin/bash'

    #
    # shadow
    #

    # whether to enable the installation of the shadow package
    owb_shadow_enable: true

    # list of packages to install to provide shadow functionality
    owb_shadow_packages:
      - 'shadow'
      - 'sudo'

    #
    # password hash/encryption method
    #

    # whether to enable the password hash/encryption method changing
    # note: this *requires* enabling configuration of shadow, which provides
    # the file '/etc/login.defs'  # nospell
    owb_password_hash_encryption_enable: true

    # encryption and hash to be used for user account passwords (including root)
    # the default in OpenWrt 21.02 - 23.05 is BCRYPT
    # important note:
    #   if changing the default encryption, *all* existing user passwords need to be set again, as otherwise
    #   *nobody* will be able to login
    owb_login_defs_encrypt_method: 'SHA512'

    # path to the login defaults file where the change is implemented
    owb_login_defs_file: '/etc/login.defs'
    #
    # sudoers.d
    #

    # whether to enable the creation of sudoers.d configuration files
    #
    # for every group that is defined as 'privilged' in owb_users
    # a configuration file is generated with the following content:
    #   %MY_GROUP ALL=(ALL) NOPASSWD: ALL
    #
    # this applies to both primary groups, which are defined as 'group' and
    # additional_groups that have set the privileged flag
    #
    owb_sudoers_d_enable: true

    # path and permissions to the sudoers.d directory
    owb_sudoers_d_path: '/etc/sudoers.d'
    owb_sudoers_d_owner: 'root'
    owb_sudoers_d_group: 'root'
    owb_sudoers_d_mode: '0755'

    # permissions for files placed in sudoers.d
    owb_sudoers_d_files_owner: 'root'
    owb_sudoers_d_files_group: 'root'
    owb_sudoers_d_files_mode: '0440'

    #
    # users
    #

    # whether to enable the creation of users
    owb_users_enable: true

    # packages required to install prior to adding users
    owb_users_required_packages:
      - 'shadow'
      - 'sudo'

    # whether to enable transferring of authorized_keys defined in owb_users
    owb_authorized_keys_enable: true

    # whether to set no_log for authorized_keys tasks
    owb_authorized_keys_no_log: false

    # users to create
    owb_users:
      - name: 'steffen'
        group: 'steffen'
        privileged: true
        shell: '/bin/bash'
        home: '/home/steffen'
        remove_unspecified_ssh_keys: true
        authorized_keys:
          - !vault |
              $ANSIBLE_VAULT;1.2;AES256
              [..]

          - !vault |
              $ANSIBLE_VAULT;1.2;AES256
              [..]
          - 'id_ecdsa.pub'

    # whether to install base packages
    owb_base_packages_enable: true

    # list of packages to install
    owb_base_packages:
      - 'git-http'
      - 'htop'
      - 'rsync'
    # whether to configure vim
    owb_vim_enable: true

    # whether to deploy a default configuration
    owb_vimrc_default_configuratino_enable: true

    # source file of the default vimrc configuration file
    owb_vimrc_default_conf_src: 'vimrc'

    # where to place the default vimrc configuration file
    owb_vimrc_default_conf_dest_path: '/usr/share/vim/vimrc'

    # owner, group and permissions of the vimrc default configuration file
    owb_vimrc_default_conf_owner: 'root'
    owb_vimrc_default_conf_group: 'root'
    owb_vimrc_default_conf_mode: '0644'

    # whether to place a simplistic .vimrc in user directories (including /root)
    owb_vimrc_simplistic_user_vimrc_enable: true

    # content to add to the simplistic .vimrc file
    # the below content allows for copying from the clipboard
    owb_vimrc_simplistic_content: 'set clipboard=unnamed'

    # mode of the simplistic .vimrc
    # note: owner and group will be each user in whose home directory it is deployed to (including root as user)
    owb_vimrc_simplistic_mode: '0600'

    # list of users to apply the simplistic vimrc to
    owb_vimrc_users:
      - 'steffen'

    # package name of vim to install
    owb_vim_package_name: 'vim-fuller'

    # prior to installing above package the below packages should be removed to avoid conflicts while installing
    owb_vim_package_match_list:
      - 'vim-full'
      - 'vim-help'
      - 'vim-runtime'
      - 'vim'
    # whether profile.d files and templates should be transferred
    owb_profile_d_configuration_enable: true

    # whether the profile.d directory should be created
    owb_profile_d_creation_enable: true

    # path and permissions to the profile.d directory where below BASH related scripts are placed
    owb_profile_d_path: '/etc/profile.d'
    owb_profile_d_path_owner: 'root'
    owb_profile_d_path_group: 'root'
    owb_profile_d_path_mode: '0755'

    # files to place in the profile.d path
    owb_profile_d_files:
      - src: 'history.j2'
        owner: 'root'
        group: 'root'
        mode: '0644'
        template: true
        destination_suffix: 'sh'

      - src: 'aliases.j2'
        owner: 'root'
        group: 'root'
        mode: '0644'
        template: true
        destination_suffix: 'sh'

      - src: 'general.j2'
        owner: 'root'
        group: 'root'
        mode: '0644'
        template: true
        destination_suffix: 'sh'

      - src: 'ps1.j2'
        owner: 'root'
        group: 'root'
        mode: '0644'
        template: true
        destination_suffix: 'sh'
    # whether to enable configuration of cron
    owb_cron_enable: true

    # cron jobs to create
    owb_cron_jobs:
      - name: 'Refresh opkg lists once a day'
        minute: 0
        hour: 4
        day: 1
        job: '/bin/opkg update 2>&1 > /dev/null'
  roles:
    - role: 'file_deployment'
...
```

## Contributing

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued.
Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for different ways to help and details about how this project handles contributions.

## License

[`GPL-2.0-or-later`](LICENSE)

[^encryption]: If changing the default encryption from `bcrypt`, *all* existing user passwords need to be set again, as otherwise *nobody* will be able to login. You need
               to further ensure that `owb_login_defs_encrypt_method` and `owb_password_hash` specify the same hash algorithm.
               As an example for `sha512`: `owb_login_defs_encrypt_method: 'SHA512'`, `owb_password_hash: 'sha512_crypt'`
[^sleep]: This helps to allow networking to come up prior to restoring `iptables` and mounting potentially network file systems like `NFS`.
[^assert]: Disabling the `assert` is only advised, once validated every variable is defined properly.
[^delete]: Prior to installing the desired `vim` package, all other `vim` packages should be removed to avoid conflicts while installing.
[^permissions]: Only the mode can be specified because the owner and group will always be the user that is specified to receive the simplistic `.vimrc` configuration file.
