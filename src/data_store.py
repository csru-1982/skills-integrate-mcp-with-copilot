import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

DATA_FILE = Path(__file__).parent / "data.json"
SESSION_DURATION_MINUTES = 240
RESET_TOKEN_DURATION_MINUTES = 30

DEFAULT_DATA = {
    "activities": {
        "Chess Club": {
            "description": "Learn strategies and compete in chess tournaments",
            "schedule": "Fridays, 3:30 PM - 5:00 PM",
            "max_participants": 12,
            "participants": [
                "michael@mergington.edu",
                "daniel@mergington.edu"
            ]
        },
        "Programming Class": {
            "description": "Learn programming fundamentals and build software projects",
            "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
            "max_participants": 20,
            "participants": [
                "emma@mergington.edu",
                "sophia@mergington.edu"
            ]
        },
        "Gym Class": {
            "description": "Physical education and sports activities",
            "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
            "max_participants": 30,
            "participants": [
                "john@mergington.edu",
                "olivia@mergington.edu"
            ]
        },
        "Soccer Team": {
            "description": "Join the school soccer team and compete in matches",
            "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
            "max_participants": 22,
            "participants": [
                "liam@mergington.edu",
                "noah@mergington.edu"
            ]
        },
        "Basketball Team": {
            "description": "Practice and play basketball with the school team",
            "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
            "max_participants": 15,
            "participants": [
                "ava@mergington.edu",
                "mia@mergington.edu"
            ]
        },
        "Art Club": {
            "description": "Explore your creativity through painting and drawing",
            "schedule": "Thursdays, 3:30 PM - 5:00 PM",
            "max_participants": 15,
            "participants": [
                "amelia@mergington.edu",
                "harper@mergington.edu"
            ]
        },
        "Drama Club": {
            "description": "Act, direct, and produce plays and performances",
            "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
            "max_participants": 20,
            "participants": [
                "ella@mergington.edu",
                "scarlett@mergington.edu"
            ]
        },
        "Math Club": {
            "description": "Solve challenging problems and participate in math competitions",
            "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
            "max_participants": 10,
            "participants": [
                "james@mergington.edu",
                "benjamin@mergington.edu"
            ]
        },
        "Debate Team": {
            "description": "Develop public speaking and argumentation skills",
            "schedule": "Fridays, 4:00 PM - 5:30 PM",
            "max_participants": 12,
            "participants": [
                "charlotte@mergington.edu",
                "henry@mergington.edu"
            ]
        }
    },
    "users": {
        "admin@mergington.edu": {
            "password_hash": "6e09f6a966c61c2b21d809ef114c920a0d47e64b75fd33a3187dec0aaff5bed2",
            "salt": "004d6aadfd6fb86574ef4d8f68e50959",
            "role": "teacher"
        }
    },
    "sessions": {},
    "reset_tokens": {}
}


def _serialize_datetime(value):
    return value.isoformat()


def _deserialize_datetime(value):
    return datetime.fromisoformat(value)


def _read_data():
    if not DATA_FILE.exists():
        DATA_FILE.write_text(json.dumps(DEFAULT_DATA, indent=2))
    with DATA_FILE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_data(data):
    with DATA_FILE.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def load_data():
    return _read_data()


def save_data(data):
    _write_data(data)


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        100000
    ).hex()


def create_salt() -> str:
    return os.urandom(16).hex()


def create_session(email: str):
    data = load_data()
    token = uuid.uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=SESSION_DURATION_MINUTES)
    data["sessions"][token] = {
        "email": email,
        "expires_at": _serialize_datetime(expires_at)
    }
    save_data(data)
    return token


def validate_session(token: str):
    data = load_data()
    session = data["sessions"].get(token)
    if not session:
        return None
    expires_at = _deserialize_datetime(session["expires_at"])
    if datetime.utcnow() >= expires_at:
        data["sessions"].pop(token, None)
        save_data(data)
        return None
    return session["email"]


def invalidate_session(token: str):
    data = load_data()
    if token in data["sessions"]:
        data["sessions"].pop(token)
        save_data(data)


def create_reset_token(email: str):
    data = load_data()
    token = uuid.uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_DURATION_MINUTES)
    data["reset_tokens"][token] = {
        "email": email,
        "expires_at": _serialize_datetime(expires_at)
    }
    save_data(data)
    return token


def validate_reset_token(token: str):
    data = load_data()
    reset_data = data["reset_tokens"].get(token)
    if not reset_data:
        return None
    expires_at = _deserialize_datetime(reset_data["expires_at"])
    if datetime.utcnow() >= expires_at:
        data["reset_tokens"].pop(token, None)
        save_data(data)
        return None
    return reset_data["email"]


def consume_reset_token(token: str):
    data = load_data()
    data["reset_tokens"].pop(token, None)
    save_data(data)
