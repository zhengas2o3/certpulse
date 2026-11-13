# certpulse

Know which TLS certificates are about to expire — before your users do.

```console
$ certpulse github.com example.org:443 127.0.0.1:48443@localhost
TARGET                     STATUS      DAYS  EXPIRES (UTC)     ISSUER / ERROR
127.0.0.1:48443@localhost  CRITICAL       5  2026-11-18 09:01  localhost (verification failed: self-signed certificate)
example.org:443            OK            43  2026-12-25 22:13  Cloudflare TLS Issuing ECC CA 3
github.com                 OK            76  2027-01-27 23:59  Sectigo Public Server Authentication CA DV E36
```

- Checks dozens of hosts concurrently
- Still reports expiry date for broken / self-signed / expired chains
- Custom ports, IPv6, raw URLs and explicit SNI (`10.0.0.5:443@api.internal`)
- `table`, `json` or `csv` output
- Nagios-style exit codes for cron jobs and monitoring
- Python standard library only

## Install

```bash
pip install git+https://github.com/zhengas2o3/certpulse
```

## Usage

```bash
certpulse example.com api.example.com:8443
certpulse -f hosts.txt --format json
cat hosts.txt | certpulse -f - -w 21 -c 5
```

`hosts.txt`:

```text
# production
example.com
https://shop.example.com/login
10.0.0.5:443@internal.example.com   # connect to IP, send SNI
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-w, --warn` | 30 | days before expiry that count as WARNING |
| `-c, --crit` | 7 | days before expiry that count as CRITICAL |
| `-t, --timeout` | 8 | seconds per connection |
| `-j, --workers` | 16 | parallel checks |
| `--format` | table | `table`, `json`, `csv` |
| `--sort` | days | `days` (soonest first) or `input` |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | everything OK |
| 1 | at least one WARNING |
| 2 | at least one CRITICAL, EXPIRED or unreachable host |
| 3 | no targets / usage error |

### Cron example

```cron
0 9 * * * certpulse -f /etc/certpulse/hosts.txt --no-color > /tmp/certs.txt || mail -s "certs expiring" ops@example.com < /tmp/certs.txt
```

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT
