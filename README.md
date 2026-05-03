# 🎯 DirFinder

> Fast and simple directory & file brute-forcer for web applications, APIs, and more.
> **by RedNeutron**

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/RedNeutron-git/DirFinder?label=Latest&color=cyan)](https://github.com/RedNeutron-git/DirFinder/releases/latest)

---

## 📖 About

DirFinder is a lightweight directory brute-forcing tool designed for bug bounty hunters and security researchers. Point it at a target, give it a wordlist, and it will discover hidden paths, files, and endpoints.

> ⚠️ *For educational purpose only. Only use on targets you have explicit permission to test.*

---

## 📦 Requirements

- Python 3.x *(tested on Python 3.10.4)*

```bash
pip install requests
```

---

## 🚀 Quick Start

```bash
python3 dirfinder.py
```

Then follow the prompts:

```
Target URL: http://localhost:99
Wordlist: wordlist.txt
```

---

## 📺 Example Output

```
┌──(kali㉿kali)-[~/Documents/DirFinder]
└─$ python3 dirfinder.py
--------------------------
DirFinder V0.0.1
Author: RedNeutron
--------------------------

Target URL: http://localhost:99
Wordlist: wordlist.txt

404 : http://localhost:99 / a
404 : http://localhost:99 / ab
404 : http://localhost:99 / abc
404 : http://localhost:99 / 1
404 : http://localhost:99 / 2
404 : http://localhost:99 / 45c48cce2e2d7fbdea1afc51c7c6ad26
200 : http://localhost:99 / admin   ← found!
```

> 💡 `wordlist.txt` is just a sample — you can use any wordlist you want.

---

## 📂 Wordlist Tips

| Wordlist | Description |
|---|---|
| `wordlist.txt` | Basic sample wordlist |
| [SecLists](https://github.com/danielmiessler/SecLists) | Huge collection of wordlists |
| [dirb](https://github.com/v0re/dirb) | Classic dirb wordlists |

---

## 🔗 Latest Version

A newer version with more features is available:

**[⬇ Download Latest Release →](https://github.com/RedNeutron-git/DirFinder/releases/latest)**

New in v1.0:
- Multi-threading (20x faster)
- Built-in wordlist (300+ critical paths)
- Color output + progress bar
- Export results to TXT
- Resume interrupted scans
- Custom headers, cookies, auth
- Recursive scanning
- And much more...

---

> *Big respect for Mr Net0*
