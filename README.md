# nagios-scripts

Custom Nagios plugins used by [ansible_nagios_project](https://github.com/dorancemc/ansible_nagios_project).

Every file here is ready to copy: download it into the plugins directory, give it mode
`0755`, and it runs. There is no build or install step.

| Plugin | Checks | Needs |
|---|---|---|
| `check_await.sh` | Disk I/O await time | `iostat` |
| `check_connss.py` | Socket connections by state | `ss` |
| `check_cpu.sh` | CPU usage | `mpstat` |
| `check_date.sh` | Days left until a given date, for contract or licence expiry | — |
| `check_expiration.sh` | Domain name expiry over whois | `whois` |
| `check_iops.sh` | Disk IOPS | `iostat` |
| `check_loadwhm.php` | Server load through the WHM API | `php-cli` |
| `check_mem.py` | Memory usage from `/proc/meminfo` | `python3` |
| `check_netint.pl` | Network interface traffic and errors | `perl` |
| `check_query_mysql.sh` | Row count returned by a MySQL query | `mysql` |
| `check_smtp_cert.sh` | Certificate expiry on SMTP port 25 | `openssl` |
| `check_users_ip.pl` | Logged in users and their source IP | `perl` |

## Installing

The Ansible role downloads these with `get_url`, one entry per plugin:

```yaml
nagios_extra_plugins:
  check_expiration.sh:
    url: https://raw.githubusercontent.com/dorancemc/nagios-scripts/<commit-sha>/check_expiration.sh
    checksum: sha256:<hex>
```

Point the URL at a commit SHA, never at a branch. Nagios runs these files as commands, so
anyone who can change what the URL serves can run code on the monitoring server. The commit
SHA keeps the source fixed and the checksum verifies the bytes that arrive.

## Origin

Moved from `gitlab.com/dorancemc/checks`. `check_mem.py` was ported from Python 2, and
`check_connss.py` had its shebang changed to `python3`.
