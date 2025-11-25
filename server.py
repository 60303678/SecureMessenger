# server_app.py
from flask import Flask, request, jsonify
from datetime import datetime, timezone
import uuid
import server_storage

app = Flask(__name__)

def ok(payload=None):
    payload = payload or {}
    base = {"ok": True}
    base.update(payload)
    return jsonify(base), 200

def err(msg, code=400):
    return jsonify({"ok": False, "error": str(msg)}), code

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json(force=True)
    except Exception:
        return err("invalid json", 400)
    username = data.get("username")
    public_key_pem = data.get("public_key_pem")
    address = data.get("address", "")
    if not username or not public_key_pem:
        return err("username and public_key_pem required", 400)
    try:
        server_storage.register_user(username, public_key_pem, address)
        return ok()
    except Exception as e:
        return err("server error: " + str(e), 500)

@app.route("/users", methods=["GET"])
def users():
    try:
        users = server_storage.list_users()
        return ok({"users": users})
    except Exception as e:
        return err("server error: " + str(e), 500)

@app.route("/public_key/<username>", methods=["GET"])
def public_key(username):
    try:
        pk = server_storage.get_user_public_key(username)
        if not pk:
            return err("no such user", 404)
        return ok({"public_key_pem": pk})
    except Exception as e:
        return err("server error: " + str(e), 500)

@app.route("/send_message", methods=["POST"])
def send_message():
    try:
        payload = request.get_json(force=True)
    except Exception:
        return err("invalid json", 400)
    required = ["from", "to", "type", "payload"]
    if not all(k in payload for k in required):
        return err("missing fields", 400)
    try:
        msg = {
            "id": str(uuid.uuid4()),
            "from": payload["from"],
            "to": payload["to"],
            "type": payload["type"],
            "payload": payload["payload"],
            "meta": payload.get("meta", {}),
            "ts": datetime.now(timezone.utc).isoformat()
        }
        server_storage.store_message(msg)
        return ok({"message_id": msg["id"]})
    except Exception as e:
        return err("server error: " + str(e), 500)

@app.route("/fetch_messages", methods=["GET"])
def fetch_messages():
    username = request.args.get("username")
    if not username:
        return err("username required", 400)
    try:
        inbox = server_storage.fetch_and_delete_messages_for(username)
        return ok({"messages": inbox})
    except Exception as e:
        return err("server error: " + str(e), 500)

if __name__ == "__main__":
    print("Starting Flask server on http://127.0.0.1:5000")
    app.run(debug=True, threaded=True)
