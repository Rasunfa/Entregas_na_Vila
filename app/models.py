from flask_login import UserMixin
from app import mysql, login_manager

class User(UserMixin):
    def __init__(self, id, username, email, user_type, location):
        self.id = id
        self.username = username
        self.email = email
        self.user_type = user_type
        self.location = location

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    if user:
        return User(*user[:5])
    return None
