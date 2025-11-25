# server_storage.py
# Cross-platform safe JSON storage without external deps.
# Uses msvcrt on Windows and fcntl on Linux/Mac for file locking.
import json
import os
import sys
from datetime import datetime, timezone

DB_FILE = "server_data.json"
BACKUP_SUFFIX = ".broken"

# Cross-platform locking
if os.name == "nt":
    import msvcrt
    def lock_file(fp):
        try:
            # Lock 1 byte (works as advisory lock)
            msvcrt.locking(fp.fileno(), msvcrt.LK_LOCK, 1)
        except Exception:
            pass
    def unlock_file(fp):
        try:
            msvcrt.locking(fp.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
else:
    import fcntl
    def lock_file(fp):
        try:
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass
    def unlock_file(fp):
        try:
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass

def _clean_db():
    return {"users": {}, "messages": []}

def load_db():
    """Load DB safely. If missing/empty/corrupted -> return clean db."""
    if not os.path.exists(DB_FILE):
        return _clean_db()

    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            lock_file(f)
            raw = f.read()
            unlock_file(f)
            if not raw or raw.strip() == "":
                return _clean_db()
            data = json.loads(raw)
            # Basic sanity check
            if not isinstance(data, dict) or "users" not in data or "messages" not in data:
                raise ValueError("DB missing expected keys")
            return data
    except Exception as exc:
        # Backup corrupted file for inspection and return clean DB
        try:
            bak = DB_FILE + BACKUP_SUFFIX
            if not os.path.exists(bak):
                os.replace(DB_FILE, bak)
            else:
                ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                os.replace(DB_FILE, f"{DB_FILE}{BACKUP_SUFFIX}.{ts}")
        except Exception:
            pass
        print("server_storage.load_db: corrupted DB detected, auto-repairing:", exc)
        return _clean_db()

def save_db(data):
    """Write DB atomically (write to temp file then replace)."""
    tmp = DB_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as tf:
            lock_file(tf)
            json.dump(data, tf, indent=2, ensure_ascii=False)
            tf.flush()
            os.fsync(tf.fileno())
            unlock_file(tf)
        # Atomic replace
        os.replace(tmp, DB_FILE)
    except Exception as exc:
        print("server_storage.save_db: error saving DB:", exc)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

# Conveniences
def register_user(username, public_key_pem, address=""):
    db = load_db()
    db["users"][username] = {
        "public_key_pem": public_key_pem,
        "address": address,
        "registered_at": datetime.now(timezone.utc).isoformat()
    }
    save_db(db)

def get_user_public_key(username):
    db = load_db()
    u = db.get("users", {}).get(username)
    return u.get("public_key_pem") if u else None

def list_users():
    db = load_db()
    return list(db.get("users", {}).keys())

def store_message(message_obj):
    db = load_db()
    msgs = db.get("messages", [])
    msgs.append(message_obj)
    db["messages"] = msgs
    save_db(db)

def fetch_and_delete_messages_for(username):
    db = load_db()
    msgs = db.get("messages", [])
    inbox = [m for m in msgs if m.get("to") == username]
    db["messages"] = [m for m in msgs if m.get("to") != username]
    save_db(db)
    return inbox
