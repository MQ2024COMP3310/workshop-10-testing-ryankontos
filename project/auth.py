from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_user, login_required, logout_user
from sqlalchemy import text
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from bleach import clean

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = clean(request.form.get('email'))
    password = clean(request.form.get('password'))
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()


    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        current_app.logger.warning("User login failed")
        return redirect(url_for('auth.login'))

    
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup2')
def signup2():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = clean(request.form.get('email'))
    name = clean(request.form.get('name'))
    password = clean(request.form.get('password'))

    
    user = db.session.execute(text('SELECT * FROM user WHERE email = :email'), {'email': email}).all()
    if len(user) > 0:
        flash('Email address already exists')
        current_app.logger.debug("User email already exists")
        return redirect(url_for('auth.signup'))

    
    new_user = User(email=email, name=name, password=generate_password_hash(password))

    
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
