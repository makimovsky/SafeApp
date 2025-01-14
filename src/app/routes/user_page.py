from flask import Blueprint, render_template
from ..models import DATABASE
import sqlite3
from .main import ALLOWED_TAGS, ALLOWED_ATTRIBUTES
import bleach

user_bp = Blueprint("user_page", __name__)


@user_bp.route("/user/<user_id>", methods=["GET"])
def user_page(user_id):
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        "SELECT username, feed, sign, hashed_feed, feed_date FROM feeds WHERE username == ? ORDER BY feed_date DESC",
        (user_id,)
    )
    user_feeds = cursor.fetchall()

    sanitized_feeds = [
        (
            feed[0],
            bleach.clean(feed[1], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES),
            feed[2],
            feed[3],
            feed[4],
        )
        for feed in user_feeds
    ]

    print(user_feeds)

    cursor.execute(
        "SELECT pub_key FROM user WHERE username == ?",
        (user_id,)
    )
    pub_key = cursor.fetchall()[0][0]

    return render_template("user_page.html", username=user_id, user_feeds=sanitized_feeds, pub_key=pub_key)
