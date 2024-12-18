from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
import sqlite3
import markdown
from ..models import DATABASE

main_bp = Blueprint("main", __name__)


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

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO feeds (username, feed) VALUES (?, ?)", (username, rendered)
    )
    db.commit()
    return render_template("markdown.html", rendered=rendered)
