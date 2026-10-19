=== LINUX PERMISSIONS ===
ls -l = read permissions. Format: [type][owner:rwx][group:rwx][others:rwx]
chmod 600 = owner rw only. chmod 700 = owner rwx only. chmod 777 = everyone everything
4=read, 2=write, 1=execute — add them per group to get the digit
Directory x = can enter/cd. File x = can execute as program

chown user:group file = change owner and group (needs sudo to change to different user)
chmod 750 deploy.sh        # numeric: owner=7(rwx), group=5(r-x), others=0(---)
chmod u+x deploy.sh        # symbolic: add execute for user
chmod go-w deploy.sh       # remove write for group and others

chown chinez deploy.sh           # change owner
chown chinez:devteam deploy.sh   # change owner and group

change owner (and optionally group)
chown newowner file.txt              # change owner only
chown newowner:newgroup file.txt     # change owner AND group at once
chown :newgroup file.txt             # change group only (alternate syntax)

change group only
chgrp newgroup file.txt

=== SPECIAL BITS ===
SUID (4000) = program runs as file owner not you — s in owner execute slot
SGID on file (2000) = program runs as file's group
SGID on directory = new files auto-inherit directory's group — s in group execute slot
S (capital) = special bit set but execute missing — broken, fix it
find /usr/bin -perm -4000 -type f 2>/dev/null = audit for SUID binaries
Suspicious SUID: bash, python, vim, find, cp — any general purpose tool = red flag

=== AUDIT PATTERNS ===
secrets/keys = chmod 600 (owner read/write only)
shared team scripts = chmod 770 (owner+group full, others nothing)
cron scripts = chmod 700 (owner only — prevents script injection)
world-writable file run by root = critical finding (attacker can inject commands)

=== NETWORKING ===
ip addr = show your IP addresses and network interfaces
127.0.0.1 = loopback (machine talks to itself). 0.0.0.0 = all interfaces (danger if exposed)
ping 8.8.8.8 -c 4 = test connectivity. TTL shows how many routers packet passed through
ss -tulnp = show all open ports and listening services. Look for unexpected 0.0.0.0 entries
curl -I https://site.com = show response headers (check for server version leaks, weak TLS)
curl -v https://site.com = full verbose — shows TLS version, cipher, full handshake
TLSv1.3 + AES-256 = good. TLSv1.0/1.1 = finding. X-Powered-By header = information leak
Port 22=SSH, 80=HTTP, 443=HTTPS, 3306=MySQL, 5432=PostgreSQL

=== DNS ===
DNS = phone book of internet. Translates domain names to IP addresses.

RECORD TYPES:
A     = domain → IPv4 address (e.g. google.com → 192.178.173.100)
AAAA  = domain → IPv6 address
MX    = where email is delivered (Google Workspace vs Microsoft 365)
TXT   = email security policies (SPF, DKIM, DMARC) + domain verification
CNAME = alias — this domain points to another domain
NS    = which DNS servers are authoritative for this domain
PTR   = reverse lookup — IP address → domain name (useful for log analysis)

COMMANDS:
dig A google.com @8.8.8.8       = query A records via Google DNS
dig MX gmail.com @8.8.8.8       = query mail servers
dig TXT gmail.com @8.8.8.8      = query email security policies
dig NS google.com @8.8.8.8      = query nameservers

SECURITY RELEVANCE:
MX records    = reveals which email provider a company uses
TXT/SPF       = if misconfigured, attacker can spoof the domain in phishing
NS + zone transfer = if misconfigured, attacker pulls entire server map
PTR lookup    = identify suspicious IPs in server logs
Low TTL       = domain rotating IPs frequently (DDoS protection technique)

WSL WORKAROUND:
Local DNS (10.255.255.254) times out for MX/TXT queries
Use @8.8.8.8 to query Google DNS directly
If network blocks port 53 outbound, external DNS queries will fail


=== BASH SCRIPTING ===
#!/bin/bash = shebang — tells Linux to run file using bash interpreter
chmod 700 script.sh = make script executable by owner only (needs r AND x to run)

VARIABLES:
USERNAME=$(whoami)     = capture command output into variable
echo "$USERNAME"       = use variable with $ prefix
No spaces around = when assigning

CONDITIONALS:
if [ condition ]; then
    echo "true"
else
    echo "false"
fi

TEST FLAGS:
-f = is a regular file
-d = is a directory
-e = exists (file or directory)
-r = readable by current user
-w = writable by current user
-x = executable by current user
-z = string/variable is empty
-s = file exists and is not empty

LOOPS:
for FILE in /tmp /etc/passwd /etc/shadow; do
    echo "$FILE"
done
Items separated by spaces — missing space joins them into one path (common bug)

GREP IN SCRIPTS:
echo "$VARIABLE" | grep -q "searchterm"
-q = quiet mode, returns true/false without printing
Used to check if a value exists inside another variable

=== AUDIT SCRIPT TECHNIQUES ===
SUID_FILES=$(find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null)
KNOWN_GOOD="/usr/bin/passwd /usr/bin/su ..."
if echo "$KNOWN_GOOD" | grep -q "$BIN"; then echo "OK" else echo "WARNING" fi

KEY LESSONS:
- Script needs both r AND x to run (x alone = permission denied)
- $(find) with no args searches current directory — always specify paths
- Two find commands in script = bug, merge into one SUID_FILES=$() line
- Missing space in for loop joins paths: /tmp/etc/passwd instead of /tmp + /etc/passwd
- KNOWN_GOOD variable missing = everything shows WARNING (grep never matches)

=== LOGS AND MONITORING ===

KEY LOG FILES:
/var/log/auth.log     = logins, sudo usage, authentication failures — first place to check in incident
/var/log/syslog       = general system activity
/var/log/kern.log     = kernel messages
/var/log/dpkg.log     = packages installed/removed (attacker installing tools shows here)
/var/log/wtmp         = binary login history — read with 'last' command, not cat
.gz files             = compressed rotated old logs (dmesg.1.gz = yesterday etc)

KEY COMMANDS:
cat /var/log/auth.log | tail -20          = last 20 lines of auth log
grep -E "Failed|Invalid|sudo" /var/log/auth.log   = search for security events
last                                       = login history (not available in WSL)

JOURNALCTL:
journalctl -n 20 --no-pager               = last 20 journal entries
journalctl -p err --no-pager -n 20        = errors and above only
journalctl -u ssh --no-pager              = filter by service
journalctl --since "2026-06-28 15:00"     = filter by time
journalctl -f                             = follow live (like tail -f)

WHAT TO LOOK FOR IN AUTH.LOG:
"Failed password"     = failed login attempt
"Invalid user"        = brute force — trying nonexistent usernames
"sudo"                = who ran sudo, what command, from where, when
Logins at unusual hours or from unexpected IPs

LOG ANALYSIS SKILL:
Most errors are noise — NTP failures at boot, WSL quirks, shutdown unmount errors
Real findings = unknown process names, repeated auth failures, unexpected sudo, unfamiliar services starting
Goal = distinguish expected noise from genuine signals

SUDO AUDIT TRAIL FORMAT:
sudo: chinez : TTY=/dev/pts/0 ; PWD=/home/chinez ; USER=root ; COMMAND=/usr/bin/chown
= who ran it, from where, as which user, exact command

## Git & GitHub

**Git** = version control tool (tracks changes locally). **GitHub** = hosting service for Git repos (adds collaboration, remote backup, portfolio visibility). Git works with no internet; GitHub needs it.

### Setup
```bash
git init                          # start tracking a folder as a repo
git clone <url>                   # copy an existing remote repo locally
```

### The daily loop
```bash
git status                        # what's changed / staged / untracked
git add <file>                    # stage a specific file
git add .                         # stage everything changed
git commit -m "message"           # save a snapshot (-m is required for inline message)
git push                          # send commits to GitHub
git pull                          # bring down others' commits
```

### Connecting to GitHub
```bash
git remote add origin <url>       # link local repo to a GitHub repo
git branch -M main                # rename current branch to "main"
git push -u origin main           # first push; sets upstream tracking
git push                          # every push after that — no args needed
```

### Auth
- GitHub no longer accepts your account password over HTTPS — use a **Personal Access Token (PAT)** instead, pasted at the password prompt.
- Generate one: GitHub → profile pic → Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token → check `repo` scope → copy immediately (shown once).
- Save yourself from re-entering it every time:
```bash
git config --global credential.helper store
```

### Branches
Branches = parallel workspaces. Work on something new without touching the working `main` version until it's ready.
```bash
git branch                        # list branches
git checkout -b <name>            # create + switch to new branch
git checkout main                 # switch back to main
git merge <name>                  # merge a branch into the one you're on
```
Typical flow: branch → make changes → commit → checkout main → merge → push.

### .gitignore
A file listing patterns Git should never track — critical for keeping secrets/credentials/junk out of a repo (once committed, they stay in history even if deleted later).
```bash
nano .gitignore
```
Example contents:
```
*.env
*.log
id_rsa*
.DS_Store
```
Then `git add .gitignore && git commit -m "Add gitignore" && git push` like any other file.

### Useful extras
```bash
git log                           # commit history
git diff                          # see exact changes before staging
git remote -v                     # confirm which URL origin points to
pwd                                # confirm which folder you're in before running git commands
```

### Common mistakes I hit (and fixes)
- Running git commands from the wrong folder (e.g. `~` instead of the actual repo folder) → always `cd` into the repo first, confirm with `pwd`.
- Forgetting `-m` on `git commit` → gives a "pathspec did not match" or similar error; always `git commit -m "message"`.
- `git add` with no argument → "Nothing specified, nothing added." Use `git add <file>` or `git add .`.
- Entering GitHub password instead of a PAT → always fails now; PAT is mandatory.
