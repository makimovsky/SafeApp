from app import create_app, login_manager
from app.models import user_loader, DATABASE
import sqlite3


app = create_app()


@login_manager.user_loader
def load_user(username):
    return user_loader(username)


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()

    sql.execute(
        "CREATE TABLE IF NOT EXISTS user "
        "(username TEXT PRIMARY KEY,"
        "password TEXT,"
        "salt BLOB,"
        "totp_secret BLOB,"
        "pub_key TEXT,"
        "prv_key BLOB);"
    )

    sql.execute(
        "CREATE TABLE IF NOT EXISTS feeds "
        "(id INTEGER PRIMARY KEY,"
        "username TEXT,"
        "feed TEXT,"
        "sign BLOB,"
        "hashed_feed BLOB,"
        "feed_date DATETIME DEFAULT CURRENT_TIMESTAMP);"
    )
    db.commit()

    app.run("0.0.0.0", 8080)
