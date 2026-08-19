# nagios-scripts

Custom Nagios plugins.

Every file here is ready to copy: download it into the plugins directory, give it mode
`0755`, and it runs. There is no build or install step.

| Plugin | Checks | Needs |
|---|---|---|
| `check_await.sh` | Disk I/O await time | `iostat` |
| `check_connss.py` | Socket connections by state | `ss` |
| `check_cpu.sh` | CPU usage | `mpstat` |
| `check_date.sh` | Days left until a given date, for contract or licence expiry | — |
| `check_domain_expiration.py` | Domain name expiry: asks RDAP first, falls back to whois | `python3`, `whois` |
| `check_iops.sh` | Disk IOPS | `iostat` |
| `check_loadwhm.php` | Server load through the WHM API | `php-cli` |
| `check_mem.py` | Memory usage from `/proc/meminfo` | `python3` |
| `check_netint.py` | Local network interfaces: link state, traffic, errors | `python3`, `netint_common.py` |
| `check_query_mysql.sh` | Row count returned by a MySQL query | `mysql` |
| `check_smtp_cert.sh` | Certificate expiry on SMTP port 25 | `openssl` |
| `check_snmp_netint.py` | Remote network interfaces over SNMP, with Cisco and STP support | `python3`, `net-snmp-utils`, `netint_common.py` |
| `check_users_ip.py` | Logged-in users, counted once per source address | `python3` |
