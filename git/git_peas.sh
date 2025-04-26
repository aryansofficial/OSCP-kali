#!/bin/bash
# Git Folder Enumeration Script (OSCP-style, concise with colors)
# Usage: ./git_enum.sh /path/to/.git

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'  # No Color

# Secret pattern (expanded)
SECRET_PATTERN="*user*|password|pass|passwd|secret|api[_-]?key|token|auth|credential|session|bearer|access[_-]?key|private[_-]?key|aws[_-]?key"

if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: $0 /path/to/.git${NC}"
    exit 1
fi

GIT_DIR="$1"
if [[ "$GIT_DIR" != */.git ]]; then
    echo -e "${RED}[!] Path must end with .git${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Git Directory: $GIT_DIR${NC}"
cd "$GIT_DIR" || { echo -e "${RED}[!] Cannot access directory${NC}"; exit 1; }

echo -e "${YELLOW}[*] Checking if it's a valid git repo...${NC}"
git status &>/dev/null && echo -e "${GREEN}[+] Valid Git repo${NC}" || echo -e "${RED}[!] Not a Git repo${NC}"

echo -e "${YELLOW}[*] Remote URLs:${NC}"
grep -i url config 2>/dev/null || echo -e "${RED}[!] No remotes found${NC}"

echo -e "${YELLOW}[*] Recent commits:${NC}"
git --no-pager log --oneline --max-count=5 2>/dev/null || echo -e "${RED}[!] No commits found${NC}"

echo -e "${YELLOW}[*] Secrets in commits:${NC}"
git log -p -n 10 2>/dev/null | grep -iE "$SECRET_PATTERN" | head -n 10 || echo -e "${RED}[!] No secrets found in commit history${NC}"

echo -e "${YELLOW}[*] Tracked files:${NC}"
git ls-files 2>/dev/null | head -n 10 || echo -e "${RED}[!] No files found${NC}"

echo -e "${YELLOW}[*] Secrets in current files:${NC}"
cd .. || exit
grep -iRE "$SECRET_PATTERN" . 2>/dev/null | head -n 10 || echo -e "${RED}[!] No secrets found in current files${NC}"

echo -e "${YELLOW}[*] Deleted files (last 5):${NC}"
git log --diff-filter=D --summary 2>/dev/null | head -n 10 || echo -e "${RED}[!] No deleted files found${NC}"

echo -e "${YELLOW}[*] .git/index secrets (strings):${NC}"
strings .git/index 2>/dev/null | grep -iE "$SECRET_PATTERN" | head -n 10 || echo -e "${RED}[!] No secrets found in index${NC}"

echo -e "${YELLOW}[*] Git object secrets (top 10 matches):${NC}"
COUNT=0
for obj in $(find .git/objects -type f | grep -Ev 'pack|info'); do
  [ "$COUNT" -ge 10 ] && break
  hash=$(basename $(dirname $obj))$(basename $obj)
  git cat-file -p "$hash" 2>/dev/null | grep -iE "$SECRET_PATTERN" && ((COUNT++))
done || echo -e "${RED}[!] No secrets found in git objects${NC}"

echo -e "${YELLOW}[*] Git credentials:${NC}"
[ -f ~/.git-credentials ] && head -n 3 ~/.git-credentials || echo -e "${RED}[!] No credentials file found${NC}"
[ -f /root/.git-credentials ] && head -n 3 /root/.git-credentials || echo -e "${RED}[!] No root credentials file found${NC}"
git config --global --list 2>/dev/null | grep credential || echo -e "${RED}[!] No global git credentials found${NC}"

echo -e "${GREEN}[*] Done.${NC}"
