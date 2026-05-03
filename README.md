# 🎯 DirFinder v1.0

> Fast, feature-rich directory and file brute-forcer for bug bounty hunting.
> **by RedNeutron**

---

## 🚀 Install

```bash
pip install requests rich colorama
```

## ⚡ Quick Start

```bash
# Basic scan (uses built-in wordlist)
python dirfinder.py -u https://target.com

# Custom wordlist + extensions
python dirfinder.py -u https://target.com -w wordlist.txt -e php bak html

# Fast scan, 50 threads, HEAD method
python dirfinder.py -u https://target.com -t 50 -X HEAD

# Authenticated + save results
python dirfinder.py -u https://target.com -c "session=abc123" -o results.txt

# Full power
python dirfinder.py -u https://target.com -w custom.txt -e php bak -t 30 --recurse --resume -o out.txt
```

---

## 🛠️ Options

| Flag | Description | Default |
|---|---|---|
| `-u URL` | Target URL | required |
| `-w FILE` | Custom wordlist (combines with built-in) | — |
| `--no-builtin` | Disable built-in wordlist | off |
| `-e EXT` | Extensions to append (php html bak) | — |
| `-t N` | Threads | 20 |
| `-X METHOD` | HTTP method: GET HEAD POST | GET |
| `--timeout SEC` | Request timeout | 5s |
| `-H HEADER` | Custom header | — |
| `-c COOKIE` | Cookie string | — |
| `-a TOKEN` | Authorization header | — |
| `--user-agent UA` | Custom User-Agent | — |
| `--follow-redirects` | Follow HTTP redirects | off |
| `-d MIN MAX` | Random delay between requests | — |
| `--recurse` | Scan found directories recursively | off |
| `-mc CODE` | Only show these status codes | — |
| `-o FILE` | Output file | auto |
| `--resume` | Resume interrupted scan | off |
| `-q` | Quiet mode | off |

---

## 📋 Built-in Wordlist

300+ critical paths curated from real-world breaches:

- Source control: `.git/`, `.svn/`, `.env`
- Config files: `wp-config.php`, `database.yml`, `secrets.json`
- Admin panels: `admin/`, `phpmyadmin/`, `adminer.php`
- Debug endpoints: `phpinfo.php`, `actuator/env`, `swagger.json`
- Backup files: `backup.zip`, `db.sql`, `*.bak`
- And much more...

> *Big respect for Mr Net0*

---

## ⚠️ Legal

Only use on targets you have **explicit permission** to test.
