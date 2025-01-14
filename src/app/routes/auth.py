from flask import Blueprint, render_template, request, redirect
from flask_login import login_user, logout_user, login_required, current_user
from passlib.hash import sha256_crypt
import pyotp
import qrcode
import io
import base64
from ..models import user_loader, DATABASE
from ..helpers import is_input_valid, count_entropy
import sqlite3
import time
from ..auth_limits import is_locked_out, reset_attempts, record_failed_attempt, DELAY_TIME
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")

    username = request.form.get("username")
    password = request.form.get("password")
    client_ip = request.remote_addr

    if is_locked_out(client_ip):
        return "Too many failed attempts. Try again later.", 403

    if not is_input_valid(username, val='username'):
        record_failed_attempt(client_ip)
        return "Invalid input for username", 401

    user = user_loader(username)

    if user is None or not sha256_crypt.verify(password, user.password):
        time.sleep(DELAY_TIME)
        record_failed_attempt(client_ip)
        return "Invalid username or password", 401

    code = request.form.get("code")
    if not is_input_valid(code, val='code'):
        time.sleep(DELAY_TIME)
        record_failed_attempt(client_ip)
        return "Invalid input for 2FA", 401

    totp_enc = user.totp
    iv = totp_enc[:AES.block_size]
    key = PBKDF2(password, user.salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    totp_dec = cipher.decrypt(totp_enc[AES.block_size:]).decode('utf-8')

    totp = pyotp.TOTP(totp_dec)
    if not totp.verify(code):
        time.sleep(DELAY_TIME)
        record_failed_attempt(client_ip)
        return "Invalid 2FA code", 401

    reset_attempts(client_ip)
    login_user(user)
    return redirect("/hello")


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

    if not is_input_valid(code, val='code'):
        return "Invalid input for 2FA", 403

    user = current_user

    if not sha256_crypt.verify(current_password, user.password):
        time.sleep(DELAY_TIME)
        return "Current password is incorrect", 403

    totp_enc = user.totp
    iv = totp_enc[:AES.block_size]
    key = PBKDF2(current_password, user.salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    totp_dec = cipher.decrypt(totp_enc[AES.block_size:]).decode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    prv_key_dec = unpad(cipher.decrypt(user.prv_key), AES.block_size)

    totp = pyotp.TOTP(totp_dec)
    if not totp.verify(code):
        time.sleep(DELAY_TIME)
        return "Invalid 2FA token", 403

    hashed_password = sha256_crypt.hash(new_password)

    new_key = PBKDF2(new_password, user.salt)
    cipher = AES.new(new_key, AES.MODE_CBC, iv)
    totp_enc = iv + cipher.encrypt(totp_dec.encode())
    cipher = AES.new(new_key, AES.MODE_CBC, iv)
    prv_key_enc = cipher.encrypt(pad(prv_key_dec, AES.block_size))

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
         "UPDATE user SET password = ?, totp_secret = ?, prv_key = ? WHERE username = ?",
        (hashed_password, totp_enc, prv_key_enc, user.id)
    )
    db.commit()

    return redirect("/hello")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if not is_input_valid(username, val='username'):
        return "Invalid input for username", 401

    if count_entropy(password) < 60:
        return "Your password is too weak.", 401

    hashed_password = sha256_crypt.hash(password)
    totp_secret = pyotp.random_base32()

    iv = Random.new().read(AES.block_size)
    salt = Random.new().read(16)
    key = PBKDF2(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    totp_enc = iv + cipher.encrypt(totp_secret.encode())

    rsa_keys = RSA.generate(2048)
    pub_key = rsa_keys.public_key().exportKey()
    prv_key = pad(rsa_keys.exportKey(), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    prv_key_enc = cipher.encrypt(prv_key)

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    try:
        cursor.execute(
            "INSERT INTO user (username, password, salt, totp_secret, pub_key, prv_key) VALUES (?, ?, ?, ?, ?, ?)",
            (username, hashed_password, salt, totp_enc, pub_key, prv_key_enc)
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

    return render_template(
        "qr_code.html", qr_code=qr_code_base64, totp_secret=totp_secret
    )
