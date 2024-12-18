from flask import Flask, render_template, request, redirect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from passlib.hash import sha256_crypt
import sqlite3

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
    sql_user_loader.execute(f"SELECT username, password FROM user WHERE username = ?", (username,))
    row = sql_user_loader.fetchone()
    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    return user


@login_manager.request_loader
def request_loader(login_request):
    username = login_request.form.get('username')
    user = user_loader(username)
    return user


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = user_loader(username)
        if user is None:
            return "Nieprawidłowy login lub hasło", 401
        if sha256_crypt.verify(password, user.password):
            login_user(user)
            return redirect('/hello')
        else:
            return "Nieprawidłowy login lub hasło", 401


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

        db_register = sqlite3.connect(DATABASE)
        sql_register = db_register.cursor()
        sql_register.execute("SELECT * FROM user WHERE username = ?", (username,))
        if sql_register.fetchone():
            return "User already exists", 403

        sql_register.execute("INSERT INTO user (username, password) VALUES (?, ?)", (username, hashed_password))
        db_register.commit()
        return redirect("/")


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute("CREATE TABLE user "
                "(username VARCHAR(32),"
                "password VARCHAR(128));")
    sql.execute("DELETE FROM user;")
    sql.execute("INSERT INTO user (username, password) VALUES "
                "('bach', '$5$rounds=535000$ZJ4umOqZwQkWULPh$LwyaABcGgVyOvJwualNZ5/qM4XcxxPpkm9TKh4Zm4w4');")
    sql.execute("INSERT INTO user (username, password) VALUES "
                "('john', '$5$rounds=535000$AO6WA6YC49CefLFE$dsxygCJDnLn5QNH/V8OBr1/aEjj22ls5zel8gUh4fw9');")
    sql.execute("INSERT INTO user (username, password) VALUES "
                "('bob', '$5$rounds=535000$.ROSR8G85oGIbzaj$u653w8l1TjlIj4nQkkt3sMYRF7NAhUJ/ZMTdSPyH737');")

    sql.execute("DROP TABLE IF EXISTS feeds;")
    sql.execute("CREATE TABLE feeds "
                "(id INTEGER PRIMARY KEY,"
                "username VARCHAR(32),"
                "feed VARCHAR(256),"
                "feed_date DATETIME DEFAULT CURRENT_TIMESTAMP);")
    sql.execute("DELETE FROM feeds;")
    sql.execute("INSERT INTO feeds (username, feed, id) VALUES ('bob', 'To jest sekret!', 1);")
    db.commit()

    app.run("0.0.0.0", 8080)
