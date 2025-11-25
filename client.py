# client.py
import sys, os, json, base64, uuid, traceback
from datetime import datetime, timezone
import requests
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import pyqtSignal, QTimer
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2

# Config
SERVER_URL = "http://127.0.0.1:5000"
LOCAL_KEYFILE = "client_keys.json"
POLL_INTERVAL = 2.0
REQUEST_TIMEOUT = 6.0

# ---------------------
# Helpers
# ---------------------
def b64(b: bytes) -> str: return base64.b64encode(b).decode()
def ub64(s: str) -> bytes: return base64.b64decode(s.encode())

# ---------------------
# Crypto
# ---------------------
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key.export_key().decode(), key.publickey().export_key().decode()

def rsa_encrypt_with_pem(public_pem, data_bytes):
    return PKCS1_OAEP.new(RSA.import_key(public_pem)).encrypt(data_bytes)

def rsa_decrypt_with_pem(private_pem, cipher_bytes):
    return PKCS1_OAEP.new(RSA.import_key(private_pem)).decrypt(cipher_bytes)

def rsa_sign(private_pem, data_bytes):
    h = SHA256.new(data_bytes)
    return pkcs1_15.new(RSA.import_key(private_pem)).sign(h)

def rsa_verify(public_pem, data_bytes, signature_bytes):
    h = SHA256.new(data_bytes)
    try:
        pkcs1_15.new(RSA.import_key(public_pem)).verify(h, signature_bytes)
        return True
    except Exception:
        return False

def aes_encrypt(key, plaintext_bytes):
    iv = get_random_bytes(16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext_bytes, AES.block_size))
    return iv, ct

def aes_decrypt(key, iv, ciphertext):
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)

# ---------------------
# Key storage
# ---------------------
def save_keys_local(username, private_pem, public_pem, password=None):
    data = {"username": username, "public_pem": public_pem}
    if password:
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=200000)
        iv = get_random_bytes(16)
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(private_pem.encode(), AES.block_size))
        data.update({"private_encrypted": b64(enc), "salt": b64(salt), "iv": b64(iv), "enc": True})
    else:
        data.update({"private_pem": private_pem, "enc": False})
    with open(LOCAL_KEYFILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_keys_local(password=None):
    if not os.path.exists(LOCAL_KEYFILE): return None
    with open(LOCAL_KEYFILE, "r", encoding="utf-8") as f: data = json.load(f)
    if data.get("enc"):
        if not password: raise ValueError("Password required")
        salt = ub64(data["salt"]); iv = ub64(data["iv"]); enc = ub64(data["private_encrypted"])
        key = PBKDF2(password, salt, dkLen=32, count=200000)
        private_pem = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(enc), AES.block_size).decode()
    else:
        private_pem = data.get("private_pem")
    return data["username"], private_pem, data["public_pem"]

# ---------------------
# Server wrappers
# ---------------------
def _safe_post(path, body):
    try:
        r = requests.post(SERVER_URL + path, json=body, timeout=REQUEST_TIMEOUT)
        try: return r.json()
        except Exception: return {"ok": False, "error": "invalid_json", "text": r.text}
    except Exception as exc:
        return {"ok": False, "error": "request_failed", "exc": str(exc)}

def _safe_get(path, params=None):
    try:
        r = requests.get(SERVER_URL + path, params=params, timeout=REQUEST_TIMEOUT)
        try: return r.json()
        except Exception: return {"ok": False, "error": "invalid_json", "text": r.text}
    except Exception as exc:
        return {"ok": False, "error": "request_failed", "exc": str(exc)}

def server_register(username, public_pem, address=""):
    return _safe_post("/register", {"username": username, "public_key_pem": public_pem, "address": address})

def server_get_public_key(username):
    res = _safe_get("/public_key/" + username)
    return res.get("public_key_pem") if res.get("ok") else None

def server_list_users():
    res = _safe_get("/users")
    return [u for u in res.get("users", []) if u] if res.get("ok") else []

def server_send_message(frm, to, mtype, payload, meta=None):
    return _safe_post("/send_message", {"from": frm, "to": to, "type": mtype, "payload": payload, "meta": meta or {}})

def server_fetch_messages(username):
    res = _safe_get("/fetch_messages", {"username": username})
    return res.get("messages", []) if res.get("ok") else []

# ---------------------
# QThread workers
# ---------------------
class PollerThread(QtCore.QThread):
    new_messages = pyqtSignal(list)
    error = pyqtSignal(str)
    def __init__(self, username_getter, poll_interval=POLL_INTERVAL):
        super().__init__()
        self.username_getter = username_getter
        self.poll_interval = poll_interval
        self._running = True
    def run(self):
        while self._running:
            try:
                username = self.username_getter()
                if username:
                    msgs = server_fetch_messages(username)
                    if msgs: self.new_messages.emit(msgs)
            except Exception as exc:
                self.error.emit(str(exc))
            self.msleep(int(self.poll_interval*1000))
    def stop(self):
        self._running = False
        self.quit()
        self.wait(2000)

class SendWorker(QtCore.QThread):
    finished = pyqtSignal(dict)
    def __init__(self, frm, to, mtype, payload):
        super().__init__()
        self.frm = frm; self.to = to; self.mtype = mtype; self.payload = payload
    def run(self):
        try: self.finished.emit(server_send_message(self.frm, self.to, self.mtype, self.payload))
        except Exception as exc: self.finished.emit({"ok": False, "error": str(exc)})

# ---------------------
# MainWindow
# ---------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureMessenger - PyQt")
        self.resize(900,600)
        self.username = None
        self.private_pem = None
        self.public_pem = None
        self.sessions = {}
        self.active_chat = None
        self.per_msg_key = False
        self._workers = []
        self._build_ui()
        self.poller = PollerThread(lambda: self.username)
        self.poller.new_messages.connect(self.on_new_messages)
        self.poller.error.connect(self.on_error)
        self.poller.start()

    # ---------------------
    # UI
    # ---------------------
    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QHBoxLayout(); central.setLayout(layout)
        # Left panel
        left = QtWidgets.QVBoxLayout()
        btn_reg = QtWidgets.QPushButton("Register / Create Keypair"); btn_reg.clicked.connect(self.register_dialog)
        btn_load = QtWidgets.QPushButton("Load Keys"); btn_load.clicked.connect(self.load_keys_dialog)
        btn_refresh = QtWidgets.QPushButton("Refresh Contacts"); btn_refresh.clicked.connect(self.refresh_contacts)
        self.permsg_cb = QtWidgets.QCheckBox("Per-message session key"); self.permsg_cb.stateChanged.connect(lambda s: setattr(self, "per_msg_key", s==2))
        left.addWidget(btn_reg); left.addWidget(btn_load); left.addWidget(btn_refresh); left.addWidget(self.permsg_cb)
        left.addWidget(QtWidgets.QLabel("Contacts"))
        self.contacts = QtWidgets.QListWidget(); self.contacts.itemDoubleClicked.connect(self.start_chat)
        left.addWidget(self.contacts, stretch=1)
        # Right panel
        right = QtWidgets.QVBoxLayout()
        self.chat_label = QtWidgets.QLabel("No chat selected"); right.addWidget(self.chat_label)
        self.chat_view = QtWidgets.QTextEdit(); self.chat_view.setReadOnly(True); right.addWidget(self.chat_view, stretch=1)
        h = QtWidgets.QHBoxLayout(); self.msg_edit = QtWidgets.QLineEdit(); send_btn = QtWidgets.QPushButton("Send"); send_btn.clicked.connect(self.on_send_clicked)
        h.addWidget(self.msg_edit); h.addWidget(send_btn); right.addLayout(h)
        layout.addLayout(left, stretch=0); layout.addLayout(right, stretch=1)
        self.status = self.statusBar(); self.status.showMessage("Ready")

    # ---------------------
    # Register / Load keys
    # ---------------------
    def register_dialog(self):
        dlg = QtWidgets.QDialog(self); dlg.setWindowTitle("Register")
        v = QtWidgets.QVBoxLayout(); dlg.setLayout(v)
        uline = QtWidgets.QLineEdit(); uline.setPlaceholderText("Username")
        pwd = QtWidgets.QLineEdit(); pwd.setPlaceholderText("Local password (optional)"); pwd.setEchoMode(QtWidgets.QLineEdit.Password)
        v.addWidget(QtWidgets.QLabel("Username")); v.addWidget(uline); v.addWidget(QtWidgets.QLabel("Password (optional)")); v.addWidget(pwd)
        ok = QtWidgets.QPushButton("Create"); cancel = QtWidgets.QPushButton("Cancel")
        h = QtWidgets.QHBoxLayout(); h.addWidget(ok); h.addWidget(cancel); v.addLayout(h)
        def do_create():
            username = uline.text().strip(); password = pwd.text().strip() or None
            if not username: QtWidgets.QMessageBox.warning(self, "Error", "Username required"); return
            priv, pub = generate_rsa_keypair()
            try: save_keys_local(username, priv, pub, password)
            except Exception as exc: QtWidgets.QMessageBox.critical(self, "Failed", f"Could not save keys: {exc}"); return
            res = server_register(username, pub)
            if not res.get("ok"): QtWidgets.QMessageBox.warning(self, "Warning", f"Server response: {res}")
            self._finish_register_local(username, priv, pub); dlg.accept()
        ok.clicked.connect(do_create); cancel.clicked.connect(dlg.reject); dlg.exec_()

    def load_keys_dialog(self):
        if not os.path.exists(LOCAL_KEYFILE): QtWidgets.QMessageBox.warning(self, "No keys", f"{LOCAL_KEYFILE} not found"); return
        try: uname, priv, pub = load_keys_local(password=None); self._finish_register_local(uname, priv, pub); QtWidgets.QMessageBox.information(self, "Loaded", f"Loaded keys for {uname}"); return
        except Exception: pass
        pwd, ok = QtWidgets.QInputDialog.getText(self, "Password", "Enter password", QtWidgets.QLineEdit.Password)
        if not ok: return
        try: uname, priv, pub = load_keys_local(password=pwd); self._finish_register_local(uname, priv, pub); QtWidgets.QMessageBox.information(self, "Loaded", f"Loaded keys for {uname}")
        except Exception as exc: QtWidgets.QMessageBox.critical(self, "Failed", f"Could not load keys: {exc}")

    def _finish_register_local(self, username, private_pem, public_pem):
        self.username, self.private_pem, self.public_pem = username, private_pem, public_pem
        self.setWindowTitle(f"SecureMessenger - {username}")
        self.status.showMessage(f"Logged in as {username}")
        try: server_register(username, public_pem); self.refresh_contacts()
        except Exception: pass

    # ---------------------
    # Contacts
    # ---------------------
    def refresh_contacts(self):
        try: users = server_list_users(); self.contacts.clear(); [self.contacts.addItem(u) for u in users if u!=self.username]; self.status.showMessage("Contacts refreshed")
        except Exception: self.status.showMessage("Contacts refresh failed")

    def start_chat(self, item):
        peer = item.text(); self.active_chat = peer; self.chat_label.setText(f"Chat — {peer}"); self.append_chat("SYSTEM", f"Chat started with {peer}"); self.initiate_handshake(peer)

    # ---------------------
    # Chat
    # ---------------------
    def append_chat(self, who, text, verified=False):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S"); tag = " [VERIFIED]" if verified else ""; self.chat_view.append(f"{ts} {who}: {text}{tag}")

    def initiate_handshake(self, peer):
        pub = server_get_public_key(peer)
        if not pub: self.append_chat("SYSTEM", f"No public key for {peer}"); return
        sid, aes_key = str(uuid.uuid4()), get_random_bytes(32)
        try:
            enc = rsa_encrypt_with_pem(pub, aes_key)
            payload = {"enc_session_key": b64(enc), "session_id": sid}
            worker = SendWorker(self.username, peer, "handshake", payload)
            worker.finished.connect(lambda r: self.on_send_result(r, f"handshake->{peer}")); self._spawn_worker(worker)
            self.sessions[(peer, sid)] = aes_key
            self.append_chat("SYSTEM", f"Handshake sent to {peer}")
        except Exception as exc:
            self.append_chat("SYSTEM", f"Handshake failed: {exc}")

    def on_send_clicked(self):
        if not self.username or not self.private_pem: QtWidgets.QMessageBox.warning(self, "Not logged in", "Register or load keys first"); return
        if not self.active_chat: QtWidgets.QMessageBox.warning(self, "No chat", "Open a chat first"); return
        plain = self.msg_edit.text().strip(); 
        if not plain: return
        # Get session key
        sid = None
        for (peer, ssid) in self.sessions.keys():
            if peer == self.active_chat: sid = ssid; break
        if not sid: self.initiate_handshake(self.active_chat); QTimer.singleShot(50, lambda: self.on_send_clicked()); return
        key = self.sessions.get((self.active_chat, sid))
        iv, ct = aes_encrypt(key, plain.encode()); sig = rsa_sign(self.private_pem, plain.encode())
        payload = {"iv": b64(iv), "ciphertext": b64(ct), "signature": b64(sig), "session_id": sid, "plain_hash": b64(SHA256.new(plain.encode()).digest())}
        worker = SendWorker(self.username, self.active_chat, "message", payload); worker.finished.connect(lambda r: self.on_send_result(r, "message")); self._spawn_worker(worker)
        self.append_chat("Me", plain, verified=True); self.msg_edit.clear()

    def _spawn_worker(self, worker):
        self._workers.append(worker); worker.finished.connect(lambda _: self._workers.remove(worker)); worker.start()

    def on_new_messages(self, messages):
        for m in messages:
            try:
                mtype = m.get("type")
                frm = m.get("from")
                payload = m.get("payload", {})

                if mtype == "handshake":
                    enc_b64 = payload.get("enc_session_key")
                    sid = payload.get("session_id")
                    if not enc_b64 or not sid:
                        continue
                    try:
                        aes_key = rsa_decrypt_with_pem(self.private_pem, ub64(enc_b64))
                        self.sessions[(frm, sid)] = aes_key
                        self.append_chat("SYSTEM", f"Received handshake from {frm}")
                    except Exception as exc:
                        self.append_chat("SYSTEM", f"Handshake decryption failed from {frm}: {exc}")

                elif mtype == "message":
                    sid = payload.get("session_id")
                    iv_b64 = payload.get("iv")
                    ct_b64 = payload.get("ciphertext")
                    sig_b64 = payload.get("signature")
                    plain_hash = payload.get("plain_hash")

                    if not all([sid, iv_b64, ct_b64, sig_b64]):
                        self.append_chat("SYSTEM", f"Incomplete message received from {frm}")
                        continue

                    key = self.sessions.get((frm, sid))
                    if not key:
                        self.append_chat("SYSTEM", f"Message from {frm} but no session key (sid={sid})")
                        continue

                    try:
                        iv = ub64(iv_b64)
                        ct = ub64(ct_b64)
                        sig = ub64(sig_b64)

                        pt_bytes = aes_decrypt(key, iv, ct)
                        pt_text = pt_bytes.decode()

                        sender_pub = server_get_public_key(frm)
                        verified = rsa_verify(sender_pub, pt_bytes, sig)
                        if plain_hash and b64(SHA256.new(pt_bytes).digest()) != plain_hash:
                            verified = False

                        self.append_chat(frm, pt_text, verified=verified)

                    except Exception as exc:
                        self.append_chat("SYSTEM", f"Failed to decrypt/verify message from {frm}: {exc}")

                else:
                    self.append_chat("SYSTEM", f"Unknown message type: {mtype}")

            except Exception:
                self.append_chat("SYSTEM", "Error processing incoming message")
                traceback.print_exc()



    def on_send_result(self, res, tag="send"):
        if not res.get("ok"): self.status.showMessage(f"Send failed: {res.get('error') or res.get('exc') or res}"); return
        self.status.showMessage("Send succeeded")

    def on_error(self, msg): self.status.showMessage("Poller error: " + str(msg))

    def closeEvent(self, ev):
        try: self.poller.stop()
        except Exception: pass
        super().closeEvent(ev)

def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow(); w.show()
    sys.exit(app.exec_())

if __name__ == "__main__": main()
