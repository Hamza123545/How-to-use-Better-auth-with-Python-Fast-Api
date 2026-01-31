import json
from typing import List, Optional
from models import UserInDB

DB_FILE = "users.json"

def get_users() -> List[dict]:
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def get_user_by_username(username: str) -> Optional[UserInDB]:
    users = get_users()
    for user in users:
        if user["username"] == username:
            return UserInDB(**user)
    return None

def save_user(user: UserInDB):
    users = get_users()
    users.append(user.dict())
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=4)