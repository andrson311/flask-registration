import functools

from flask import Blueprint, g, request, session, redirect, render_template, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from profiles.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        
        # form data
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']

        db = get_db()
        error = None

        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'

        if error is None:
            try:
                db.execute(
                    """INSERT INTO users (username, first_name, last_name, password) 
                    VALUES (:username, :first_name, :last_name, :password)""",
                    {
                        'username': username,
                        'first_name': first_name,
                        'last_name': last_name,
                        'password': generate_password_hash(password)
                    }
                )
                db.commit()
            except db.IntegrityError:
                error = f"Username {username} is already in use"
            else:
                db = get_db()
                user = db.execute(
                    "SELECT * FROM users WHERE username = :username",
                    {'username': username}
                ).fetchone()
                session['user_id'] = user['id']
                return redirect(url_for("index"))

        flash(error)
    
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        
        # form data
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        error = None

        user = db.execute(
            "SELECT * FROM users WHERE username = :username", 
            {'username': username}).fetchone()

        if user is None:
            error = 'Username is not valid'
        elif not check_password_hash(user['password'], password):
            error = 'Password is not valid'
        
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        
        flash(error)
    
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            "SELECT * FROM users WHERE id = :id",
            {'id': user_id}
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        
        return view(**kwargs)
    
    return wrapped_view


