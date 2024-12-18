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
        "(username VARCHAR(32) PRIMARY KEY,"
        "password VARCHAR(128),"
        "totp_secret VARCHAR(32));"
    )

    sql.execute(
        "CREATE TABLE IF NOT EXISTS feeds "
        "(id INTEGER PRIMARY KEY,"
        "username VARCHAR(32),"
        "feed VARCHAR(256),"
        "feed_date DATETIME DEFAULT CURRENT_TIMESTAMP);"
    )
    db.commit()

    app.run("0.0.0.0", 8080)
