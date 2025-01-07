import base64

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
        "SELECT username, feed, sign, feed_date FROM feeds ORDER BY feed_date DESC"
    )
    all_feeds = cursor.fetchall()
    return render_template("hello.html", username=username, all_feeds=all_feeds)


@main_bp.route("/render", methods=["POST"])
@login_required
def render():
    md = request.form.get("markdown", "")
    password = request.form.get("password")

    if not sha256_crypt.verify(password, current_user.password):
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
    prv_key_dec = unpad(cipher.decrypt(prv_key), AES.block_size)
    rsa_keys = RSA.importKey(prv_key_dec)

    rendered_hash = SHA256.new(rendered_safe.encode())
    sign = pkcs1_15.new(rsa_keys).sign(rendered_hash)

    # TODO: find a way to verify sign by user
    pub_key = RSA.importKey(current_user.pub_key)
    print(pub_key.export_key())
    pkcs1_15.new(pub_key).verify(rendered_hash, sign)

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO feeds (username, feed, sign) VALUES (?, ?, ?)", (username, rendered_safe, sign)
    )
    db.commit()
    return render_template("markdown.html", rendered=rendered_safe)
