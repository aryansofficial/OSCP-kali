
# 🧠 Git Folder Enumeration (Shell Access) - OSCP Cheatsheet

## 📁 Check Repo Validity
- `git status`  
  Confirm it's a valid Git repo.

---

## ⚙️ Config & Remotes
- `cat .git/config`
- Look for remote URLs (e.g., GitHub, internal Git servers)
- Check for credentials in URLs: `https://user:pass@host`

---

## 🕵️ Commit History
- `git log --oneline --all`  
  View all commits.
- `git log -p | grep -i "password\|key"`  
- `git log -p`  
  Search for sensitive strings in history.
- `git show <commit_id>`  
  View specific commit content.

---

## 📄 Tracked Files & Secrets
- `git ls-files`  
  Show all tracked files.
- `grep -iR "password\|secret\|api\|key" .`  
  Search for secrets in current content.

---

## 🔁 Recover Deleted Files
- `git log --diff-filter=D --summary`  
  Find deleted files in commit history.
- `git checkout <commit_id>^ -- path/to/file`  
  Restore deleted files from history.

---

## 🧱 Git Objects & Pack Files
- `ls .git/objects/pack`  
  Check for packed object files.
- `git fsck --full`  
  Validate and list objects.
- `git cat-file -p <hash>`  
  Read Git objects.
- Dump and search all objects:
  ```bash
  for obj in $(find ../objects -type f | grep -v 'pack'); do
    git cat-file -p $(basename $(dirname $obj))$(basename $obj) 2>/dev/null
  done | grep -i "password\|secret\|api\|key"
  ```

---

## 🔎 .git/index Inspection
- `strings .git/index`
- `grep -i "password\|secret\|api\|key"`  
  Find secrets in binary index file.

---

## 🔐 Git Credentials
- `cat ~/.git-credentials`
- `cat /root/.git-credentials`
- `git config --global --list`  
  Look for stored Git credentials or tokens.
