from flask import Blueprint, session, redirect, render_template, url_for
from profiles.db import get_db

bp = Blueprint('profile', __name__)


@bp.route('/')
def index():
    user_id = session.get('user_id')

    if user_id is None:
        return redirect(url_for('auth.login'))
    else:
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE id = :id",
            {'id': user_id}
        ).fetchone()
        return render_template('index.html', user=user)
