from flask import Blueprint, render_template
from ..models import DATABASE
import sqlite3

user_bp = Blueprint("user_page", __name__)


@user_bp.route("/user/<user_id>", methods=["GET"])
def user_page(user_id):
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "SELECT username, feed, feed_date FROM feeds WHERE username == ? ORDER BY feed_date DESC",
        (user_id,)
    )
    user_feeds = cursor.fetchall()

    return render_template("user_page.html", username=user_id, user_feeds=user_feeds)
