# A mock database for users and their roles
users = {
    "user1": {"password": "password1", "role": "admin"},
    "user2": {"password": "password2", "role": "user"},
    "user3": {"password": "password3", "role": "guest"}
}

def authenticate(username, password):
    user = users.get(username)
    if user and user['password'] == password:
        return {"username": username, "role": user["role"]}
    return None
