from base64 import b64encode
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
import sqlite3
import markdown
from ..models import DATABASE
import bleach
from ..helpers import is_input_valid
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from passlib.hash import sha256_crypt
from Crypto.Util.Padding import unpad
from ..auth_limits import DELAY_TIME
import time
from .auth import GLOBAL_SECRET

main_bp = Blueprint("main", __name__)

ALLOWED_TAGS = {
    "h1",
    "h2",
    "h3",
    "p",
    "img",
    "a",
    "b",
    "blockquote",
    "code",
    "em",
    "i",
    "li",
    "ol",
    "strong",
    "ul",
    'br'
}
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "img": ["src", "alt", "title"],
}


@main_bp.route("/hello", methods=["GET"])
@login_required
def hello():
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "SELECT username, feed, sign, hashed_feed, feed_date FROM feeds ORDER BY feed_date DESC"
    )
    all_feeds = cursor.fetchall()

    sanitized_feeds = [
        (
            feed[0],
            bleach.clean(feed[1], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES),
            feed[2],
            feed[3],
            feed[4],
        )
        for feed in all_feeds
    ]

    return render_template("hello.html", username=username, all_feeds=sanitized_feeds)


@main_bp.route("/render", methods=["POST"])
@login_required
def render():
    md = request.form.get("markdown", "")
    password = request.form.get("password")

    if not sha256_crypt.verify(password, current_user.password):
        time.sleep(DELAY_TIME)
        return "Incorrect password", 403

    if not is_input_valid(md):
        return "Invalid input.", 401

    rendered = markdown.markdown(md, extensions=['nl2br'])
    username = current_user.id

    rendered_safe = bleach.clean(
        rendered, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES
    )

    prv_key = current_user.prv_key
    iv = current_user.totp[:AES.block_size]
    key = PBKDF2(password, current_user.salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    prv_key_dec_1 = cipher.decrypt(prv_key)
    cipher = AES.new(GLOBAL_SECRET, AES.MODE_CBC, iv)
    prv_key_dec_2 = unpad(cipher.decrypt(prv_key_dec_1), AES.block_size)

    rsa_keys = RSA.importKey(prv_key_dec_2)

    rendered_hash = SHA256.new(rendered_safe.encode())
    sign = pkcs1_15.new(rsa_keys).sign(rendered_hash)
    sign_b64 = b64encode(sign)
    rendered_hash_b64 = b64encode(rendered_hash.digest())

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO feeds (username, feed, sign, hashed_feed) VALUES (?, ?, ?, ?)",
        (username, rendered_safe, sign_b64, rendered_hash_b64)
    )
    db.commit()
    return render_template("markdown.html", rendered=rendered_safe)
