from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app import mysql
from app.models import User
from app.forms import RegistrationForm, LoginForm

bp = Blueprint('main', __name__)

@bp.route("/")
def home():
    return render_template("home.html")

@bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (username, email, password_hash, user_type, location) VALUES (%s, %s, %s, %s, %s)",
                       (form.username.data, form.email.data, hashed_pw, form.user_type.data, form.location.data))
        mysql.connection.commit()
        cursor.close()
        flash("Conta criada com sucesso!", "success")
        return redirect(url_for("main.login"))
    return render_template("register.html", form=form)

@bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (form.email.data,))
        user = cursor.fetchone()
        cursor.close()
        if user and check_password_hash(user[3], form.password.data):
            user_obj = User(*user[:5])
            login_user(user_obj)
            return redirect(url_for("main.dashboard"))
        else:
            flash("Login inválido.", "danger")
    return render_template("login.html", form=form)

@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.home"))
