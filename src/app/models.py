import sqlite3
from flask_login import UserMixin
from base64 import b64decode

DATABASE = "./sqlite3.db"


class User(UserMixin):
    pass


def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "SELECT username, password, salt, totp_secret, pub_key, prv_key FROM user WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    if not row:
        return None

    username, password, salt, totp, pub_key, prv_key = row
    user = User()
    user.id = username
    user.password = password
    user.salt = salt
    user.totp = totp
    user.pub_key = pub_key
    user.prv_key = prv_key
    return user
