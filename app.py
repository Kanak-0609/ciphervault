from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from crypto_utils import encrypt_file, decrypt_file
from key_manager import create_key, get_usable_key, revoke_key, log_action
from models import Session, KeyRecord, AccessLog
import io

app = Flask(__name__)
CORS(app)


@app.route("/api/keys", methods=["POST"])
def new_key():
    data = request.get_json(silent=True) or {}
    expires_at = data.get("expires_at")  # optional ISO timestamp string, or None
    key_id, _ = create_key(expires_at=expires_at)
    return jsonify({"key_id": key_id})


@app.route("/api/keys", methods=["GET"])
def list_keys():
    session = Session()
    keys = session.query(KeyRecord).order_by(KeyRecord.created_at.desc()).all()
    result = [{
        "key_id": k.key_id,
        "created_at": k.created_at.isoformat(),
        "expires_at": k.expires_at.isoformat() if k.expires_at else None,
        "revoked": k.revoked
    } for k in keys]
    session.close()
    return jsonify(result)


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    key_id = request.form.get("key_id")
    file = request.files.get("file")

    if not key_id or not file:
        return jsonify({"error": "key_id and file are required"}), 400

    usable_key, error = get_usable_key(key_id)
    if error:
        return jsonify({"error": error}), 400

    encrypted = encrypt_file(file.read(), usable_key)
    log_action(key_id, "encrypt")

    return send_file(io.BytesIO(encrypted), download_name="encrypted.bin", as_attachment=True)


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    key_id = request.form.get("key_id")
    file = request.files.get("file")

    if not key_id or not file:
        return jsonify({"error": "key_id and file are required"}), 400

    usable_key, error = get_usable_key(key_id)
    if error:
        return jsonify({"error": error}), 400

    try:
        decrypted = decrypt_file(file.read(), usable_key)
    except Exception:
        log_action(key_id, "denied", detail="decryption failed - wrong key or tampered data")
        return jsonify({"error": "Decryption failed - wrong key or corrupted/tampered file"}), 400

    log_action(key_id, "decrypt")
    return send_file(io.BytesIO(decrypted), download_name="decrypted_output", as_attachment=True)


@app.route("/api/keys/<key_id>/revoke", methods=["POST"])
def revoke(key_id):
    success = revoke_key(key_id)
    if not success:
        return jsonify({"error": "Key not found"}), 404
    return jsonify({"status": "revoked", "key_id": key_id})


@app.route("/api/logs", methods=["GET"])
def get_logs():
    key_id = request.args.get("key_id")
    session = Session()
    query = session.query(AccessLog).order_by(AccessLog.timestamp.desc())
    if key_id:
        query = query.filter_by(key_id=key_id)
    logs = query.limit(100).all()
    result = [{
        "key_id": l.key_id,
        "action": l.action,
        "detail": l.detail,
        "timestamp": l.timestamp.isoformat()
    } for l in logs]
    session.close()
    return jsonify(result)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=5001)