# subdir

**subdir** is a versatile recon tool for passive and active subdomain and directory enumeration, featuring:

- **Passive & Active** subdomain enumeration
- **Passive & Active** directory enumeration
- HTTP **alive scan** with status code filtering
- **Brute-force** via DNS and HTTP
- **Stealth mode** with custom User-Agent
- **Proxy support**
- **Multithreading** for faster scans

---

## 🚀 Features

- **Passive Subdomain Enumeration** using crt.sh, ThreatCrowd, and Wayback Machine
- **Active Subdomain Brute-force** via DNS resolver
- **HTTP Alive Scan** to check which hosts are live
- **Passive Directory Enumeration** via Wayback Machine
- **Active Directory Brute-force** with BFS-style recursion
- **Custom User-Agent** and **Proxy** support

---

## 📋 Requirements

- Python 3.6 or higher
- A Linux distro (Ubuntu/Debian, Fedora, CentOS, Arch, etc.)

### Python Dependencies

- requests
- tqdm
- colorama
- dnspython

---

## ⚙️ Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/FalconLKy/subdir.git
   cd subdir
   ```

2. **Install system prerequisites** (Debian/Ubuntu example)

   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   ```

3. **Install Python dependencies**

   ```bash
   pip3 install -r requirements.txt
   ```

> **Note:** On other distros, use the equivalent package manager:
> - Fedora/CentOS: `sudo dnf install python3 python3-pip`
> - Arch: `sudo pacman -S python python-pip`

---

## 🏁 Usage

The entrypoint is the `subdir` script:

```bash
python3 subdir.py [options]
```

### Basic Examples

- **Passive subdomain enumeration**:
  ```bash
  python3 subdir.py -t example.com --sub
  ```

- **Active directory brute-force**:
  ```bash
  python3 subdir.py -t example.com --dir --dir-mode active -w wordlist.txt
  ```

- **Run both**:
  ```bash
  python3 subdir.py -t example.com --all -w wordlist.txt
  ```

- **Filter HTTP codes & use proxy**:
  ```bash
  python3 subdir.py -t example.com --sub -c 200,301 --proxy http://127.0.0.1:8080
  ```

- **Stealth mode & custom User-Agent**:
  ```bash
  python3 subdir.py -t example.com --all --stealth --user-agent "MyScanner/1.0"
  ```

### Options

| Flag                  | Description                                         |
|-----------------------|-----------------------------------------------------|
| `-t`, `--target`      | Target domain (e.g., example.com) **(required)**    |
| `-o`, `--output`      | Path to output file                                 |
| `--sub`               | Run subdomain enumeration                           |
| `--dir`               | Run directory enumeration                           |
| `--all`               | Run both subdomain & directory enumeration          |
| `-m`, `--mode`        | Subdomain mode: `passive`, `active`, `both`         |
| `--dir-mode`          | Directory mode: `passive`, `active`, `both`, `none` |
| `-w`, `--wordlist`    | Wordlist file for brute-force                      |
| `-T`, `--threads`     | Number of threads (default: 50)                     |
| `-c`, `--codes`       | Filter HTTP codes (e.g., `200,403`)                 |
| `--stealth`           | Enable stealth mode (realistic headers)             |
| `--user-agent`        | Custom User-Agent header                            |
| `-P`, `--proxy`       | Proxy URL (e.g., `http://127.0.0.1:8080`)           |
| `--depth`             | Max recursion depth for directory brute-force       |

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file.

