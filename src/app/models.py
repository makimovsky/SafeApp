import sqlite3
from flask_login import UserMixin

DATABASE = "./sqlite3.db"


class User(UserMixin):
    pass


def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "SELECT username, password, totp_secret FROM user WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    if not row:
        return None

    username, password, totp = row
    user = User()
    user.id = username
    user.password = password
    user.totp = totp
    return user
