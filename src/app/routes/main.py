from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
import sqlite3
import markdown
from ..models import DATABASE
import bleach

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
        "SELECT username, feed, feed_date FROM feeds ORDER BY feed_date DESC"
    )
    all_feeds = cursor.fetchall()
    return render_template("hello.html", username=username, all_feeds=all_feeds)


@main_bp.route("/render", methods=["POST"])
@login_required
def render():
    md = request.form.get("markdown", "")
    rendered = markdown.markdown(md)
    username = current_user.id

    rendered_safe = bleach.clean(
        rendered, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES
    )

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO feeds (username, feed) VALUES (?, ?)", (username, rendered_safe)
    )
    db.commit()
    return render_template("markdown.html", rendered=rendered_safe)
