import uuid
from datetime import datetime
from crypto_utils import generate_symmetric_key, wrap_key, unwrap_key
from models import Session, KeyRecord, AccessLog


def create_key(expires_at=None):
    """
    Generates a new Fernet key, wraps it with the RSA public key,
    and stores the wrapped version in the database. The raw key is
    returned once here but never stored in plain form.
    """
    session = Session()
    fernet_key = generate_symmetric_key()
    wrapped = wrap_key(fernet_key)
    key_id = str(uuid.uuid4())

    record = KeyRecord(key_id=key_id, wrapped_key=wrapped, expires_at=expires_at)
    session.add(record)
    session.add(AccessLog(key_id=key_id, action="generate"))
    session.commit()
    session.close()

    return key_id, fernet_key


def get_usable_key(key_id):
    """
    Looks up a key by ID and returns the unwrapped (usable) Fernet key,
    but only if it exists, hasn't been revoked, and hasn't expired.
    Logs every attempt - including denied ones - for the audit trail.
    Returns (fernet_key, None) on success, or (None, error_message) on failure.
    """
    session = Session()
    record = session.query(KeyRecord).filter_by(key_id=key_id).first()

    if not record:
        session.add(AccessLog(key_id=key_id, action="denied", detail="key not found"))
        session.commit()
        session.close()
        return None, "Key not found"

    if record.revoked:
        session.add(AccessLog(key_id=key_id, action="denied", detail="key revoked"))
        session.commit()
        session.close()
        return None, "Key has been revoked"

    if record.expires_at and datetime.utcnow() > record.expires_at:
        session.add(AccessLog(key_id=key_id, action="denied", detail="key expired"))
        session.commit()
        session.close()
        return None, "Key has expired"

    fernet_key = unwrap_key(record.wrapped_key)
    session.close()
    return fernet_key, None


def revoke_key(key_id):
    session = Session()
    record = session.query(KeyRecord).filter_by(key_id=key_id).first()
    if not record:
        session.close()
        return False
    record.revoked = True
    session.add(AccessLog(key_id=key_id, action="revoke"))
    session.commit()
    session.close()
    return True


def log_action(key_id, action, detail=None):
    """Helper for logging encrypt/decrypt actions from app.py."""
    session = Session()
    session.add(AccessLog(key_id=key_id, action=action, detail=detail))
    session.commit()
    session.close()