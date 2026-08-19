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
| `check_expiration.sh` | Domain name expiry over whois | `whois` |
| `check_iops.sh` | Disk IOPS | `iostat` |
| `check_loadwhm.php` | Server load through the WHM API | `php-cli` |
| `check_mem.py` | Memory usage from `/proc/meminfo` | `python3` |
| `check_query_mysql.sh` | Row count returned by a MySQL query | `mysql` |
| `check_smtp_cert.sh` | Certificate expiry on SMTP port 25 | `openssl` |
