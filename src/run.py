from flask import Flask, render_template, request, redirect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from passlib.hash import sha256_crypt
import sqlite3
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

DATABASE = "./sqlite3.db"


class User(UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db_user_loader = sqlite3.connect(DATABASE)
    sql_user_loader = db_user_loader.cursor()
    sql_user_loader.execute(f"SELECT username, password, totp_secret FROM user WHERE username = ?", (username,))
    row = sql_user_loader.fetchone()
    try:
        username, password, totp = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    user.totp = totp
    return user


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = user_loader(username)

        if user is None or not sha256_crypt.verify(password, user.password):
            return "Invalid username or password", 401

        code = request.form.get("code")

        totp = pyotp.TOTP(user.totp)
        if totp.verify(code):
            login_user(user)
            return redirect("/hello")
        else:
            return "Invalid 2FA code", 401


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route("/hello", methods=['GET'])
@login_required
def hello():
    if request.method == 'GET':
        username = current_user.id

        db_hello = sqlite3.connect(DATABASE)
        sql_hello = db_hello.cursor()

        sql_hello.execute("SELECT username, feed, feed_date FROM feeds ORDER BY feed_date DESC")
        all_feeds = sql_hello.fetchall()

        return render_template("hello.html", username=username, all_feeds=all_feeds)


@app.route("/render", methods=['POST'])
@login_required
def render():
    md = request.form.get("markdown", "")
    rendered = markdown.markdown(md)
    username = current_user.id
    db_render = sqlite3.connect(DATABASE)
    sql_render = db_render.cursor()
    sql_render.execute(f"INSERT INTO feeds (username, feed) VALUES (?, ?)", (username, rendered))
    db_render.commit()
    return render_template("markdown.html", rendered=rendered)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return "Username and password are required", 403

        hashed_password = sha256_crypt.hash(password)
        totp_secret = pyotp.random_base32()

        db_register = sqlite3.connect(DATABASE)
        sql_register = db_register.cursor()

        try:
            sql_register.execute("INSERT INTO user (username, password, totp_secret) VALUES (?, ?, ?)",
                                 (username, hashed_password, totp_secret))
            db_register.commit()
        except:
            return "User already exists", 403

        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(username, issuer_name="SafeAPP")
        qr_img = qrcode.make(provisioning_uri)

        buffer = io.BytesIO()
        qr_img.save(buffer, format="PNG")
        buffer.seek(0)
        qr_code_base64 = base64.b64encode(buffer.read()).decode('utf-8')

        return render_template("qr_code.html", qr_code=qr_code_base64, totp_secret=totp_secret)


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("CREATE TABLE IF NOT EXISTS user "
                "(username VARCHAR(32) PRIMARY KEY,"
                "password VARCHAR(128),"
                "totp_secret VARCHAR(32));")

    sql.execute("CREATE TABLE IF NOT EXISTS feeds "
                "(id INTEGER PRIMARY KEY,"
                "username VARCHAR(32),"
                "feed VARCHAR(256),"
                "feed_date DATETIME DEFAULT CURRENT_TIMESTAMP);")
    db.commit()

    app.run("0.0.0.0", 8080)
