from flask import Blueprint, render_template, request, redirect
from flask_login import login_user, logout_user, login_required, current_user
from passlib.hash import sha256_crypt
import pyotp
import qrcode
import io
import base64
from ..models import user_loader, DATABASE
import sqlite3

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")

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
    return "Invalid 2FA code", 401


@auth_bp.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@auth_bp.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")

    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    code = request.form.get("code")

    user = current_user

    if not sha256_crypt.verify(current_password, user.password):
        return "Current password is incorrect", 403

    totp = pyotp.TOTP(user.totp)
    if totp.verify(code):
        hashed_password = sha256_crypt.hash(new_password)

        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        cursor.execute(
            "UPDATE user SET password = ? WHERE username = ?", (hashed_password, user.id)
        )
        db.commit()

        return redirect("/hello")

    return "Invalid 2FA token", 403


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return "Username and password are required", 403

    hashed_password = sha256_crypt.hash(password)
    totp_secret = pyotp.random_base32()

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    try:
        cursor.execute(
            "INSERT INTO user (username, password, totp_secret) VALUES (?, ?, ?)",
            (username, hashed_password, totp_secret),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return "User already exists", 403

    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(username, issuer_name="SafeAPP")
    qr_img = qrcode.make(provisioning_uri)

    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.read()).decode("utf-8")

    return render_template("qr_code.html", qr_code=qr_code_base64, totp_secret=totp_secret)
