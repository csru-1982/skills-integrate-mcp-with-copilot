"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from data_store import (
    create_reset_token,
    create_salt,
    consume_reset_token,
    create_session as create_session_token,
    hash_password,
    invalidate_session,
    load_data,
    save_data,
    validate_reset_token,
    validate_session,
)

app = FastAPI(
    title="Mergington High School API",
    description="API for viewing and signing up for extracurricular activities",
)

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount(
    "/static",
    StaticFiles(directory=current_dir / "static"),
    name="static",
)


def get_current_user(
    x_session_token: Optional[str] = Header(None, alias="X-Session-Token"),
):
    if not x_session_token:
        raise HTTPException(status_code=401, detail="Missing session token")

    email = validate_session(x_session_token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")

    data = load_data()
    user = data["users"].get(email)
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")

    return {
        "email": email,
        "role": user["role"],
        "token": x_session_token,
    }


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    data = load_data()
    return data["activities"]


@app.post("/register")
def register(email: str, password: str, role: str = "student"):
    if role not in {"student", "teacher"}:
        raise HTTPException(status_code=400, detail="Role must be either 'student' or 'teacher'")

    data = load_data()
    if email in data["users"]:
        raise HTTPException(status_code=400, detail="User already exists")

    salt = create_salt()
    data["users"][email] = {
        "password_hash": hash_password(password, salt),
        "salt": salt,
        "role": role,
    }
    save_data(data)
    return {"message": "Registration successful", "email": email, "role": role}


@app.post("/login")
def login(email: str, password: str):
    data = load_data()
    user = data["users"].get(email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if hash_password(password, user["salt"]) != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_session_token(email)
    return {"token": token, "email": email, "role": user["role"]}


@app.post("/logout")
def logout(current_user=Depends(get_current_user)):
    invalidate_session(current_user["token"])
    return {"message": "Logged out successfully"}


@app.post("/password-reset/request")
def request_password_reset(email: str):
    data = load_data()
    if email not in data["users"]:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_reset_token(email)
    return {
        "message": "Password reset token created",
        "reset_token": token,
        "expires_in_minutes": 30,
    }


@app.post("/password-reset/confirm")
def confirm_password_reset(token: str, new_password: str):
    email = validate_reset_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    data = load_data()
    user = data["users"].get(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    salt = create_salt()
    user["salt"] = salt
    user["password_hash"] = hash_password(new_password, salt)
    consume_reset_token(token)
    save_data(data)
    return {"message": "Password reset complete"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    current_user=Depends(get_current_user),
):
    if current_user["email"] != email and current_user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only the student or a teacher may sign up this email")

    data = load_data()
    activities = data["activities"]
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]
    if email in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is already signed up")

    activity["participants"].append(email)
    save_data(data)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    current_user=Depends(get_current_user),
):
    if current_user["email"] != email and current_user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only the student or a teacher may unregister this email")

    data = load_data()
    activities = data["activities"]
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]
    if email not in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is not signed up for this activity")

    activity["participants"].remove(email)
    save_data(data)
    return {"message": f"Unregistered {email} from {activity_name}"}
