from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app import mysql
from app.models import User
from app.forms import RegistrationForm, LoginForm
from forms import MenuForm, OrderForm

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

@bp.route("/restaurant/menus")
@login_required
def manage_menus():
    if current_user.user_type != 'restaurant':
        return "Acesso Negado", 403
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM menus WHERE restaurant_id = %s", (current_user.id,))
    menus = cursor.fetchall()
    cursor.close()
    return render_template("manage_menus.html", menus=menus)

@bp.route("/restaurant/menus/create", methods=["GET", "POST"])
@login_required
def create_menu():
    if current_user.user_type != 'restaurant':
        return "Acesso Negado", 403
    form = MenuForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO menus (restaurant_id, name, description, price) VALUES (%s, %s, %s, %s)",
                       (current_user.id, form.name.data, form.description.data, form.price.data))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for("main.manage_menus"))
    return render_template("menu_form.html", form=form)

@bp.route("/restaurant/menus/<int:menu_id>/edit", methods=["GET", "POST"])
@login_required
def edit_menu(menu_id):
    if current_user.user_type != 'restaurant':
        return "Acesso Negado", 403
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM menus WHERE id = %s AND restaurant_id = %s", (menu_id, current_user.id))
    menu = cursor.fetchone()
    if not menu:
        return "Menu não encontrado", 404
    form = MenuForm(data={"name": menu[2], "description": menu[3], "price": menu[4]})
    if form.validate_on_submit():
        cursor.execute("UPDATE menus SET name=%s, description=%s, price=%s WHERE id=%s AND restaurant_id=%s",
                       (form.name.data, form.description.data, form.price.data, menu_id, current_user.id))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for("main.manage_menus"))
    return render_template("menu_form.html", form=form)

@bp.route("/restaurant/menus/<int:menu_id>/delete", methods=["POST"])
@login_required
def delete_menu(menu_id):
    if current_user.user_type != 'restaurant':
        return "Acesso Negado", 403
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM menus WHERE id=%s AND restaurant_id=%s", (menu_id, current_user.id))
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for("main.manage_menus"))

@bp.route("/restaurants")
@login_required
def list_restaurants():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, username, location FROM users WHERE user_type = 'restaurant'")
    restaurants = cursor.fetchall()
    cursor.close()
    return render_template("restaurants.html", restaurants=restaurants)

@bp.route("/restaurants/<int:restaurant_id>/menus", methods=["GET", "POST"])
@login_required
def view_menus(restaurant_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM menus WHERE restaurant_id = %s", (restaurant_id,))
    menus = cursor.fetchall()
    cursor.close()

    form = OrderForm()
    form.menu_id.choices = [(menu[0], menu[2]) for menu in menus]
    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO orders (client_id, restaurant_id, menu_id, notes) VALUES (%s, %s, %s, %s)",
            (current_user.id, restaurant_id, form.menu_id.data, form.notes.data)
        )
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for("main.order_history"))
    return render_template("view_menus.html", menus=menus, form=form)

@bp.route("/orders/history")
@login_required
def order_history():
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT o.id, m.name, o.notes, o.status, o.created_at "
        "FROM orders o JOIN menus m ON o.menu_id = m.id "
        "WHERE o.client_id = %s ORDER BY o.created_at DESC", (current_user.id,)
    )
    orders = cursor.fetchall()
    cursor.close()
    return render_template("order_history.html", orders=orders)

@bp.route("/restaurant/orders")
@login_required
def restaurant_orders():
    if current_user.user_type != 'restaurant':
        return "Acesso Negado", 403
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT o.id, u.username, m.name, o.notes, o.status, o.created_at "
        "FROM orders o "
        "JOIN users u ON o.client_id = u.id "
        "JOIN menus m ON o.menu_id = m.id "
        "WHERE o.restaurant_id = %s ORDER BY o.created_at DESC", (current_user.id,)
    )
    orders = cursor.fetchall()
    cursor.close()
    return render_template("restaurant_orders.html", orders=orders)

@bp.route("/restaurant/orders/<int:order_id>/update", methods=["POST"])
@login_required
def update_order_status(order_id):
    if current_user.user_type != 'restaurant':
        return "Acesso Negado", 403
    new_status = request.form.get("status")
    cursor = mysql.connection.cursor()
    cursor.execute(
        "UPDATE orders SET status=%s WHERE id=%s AND restaurant_id=%s",
        (new_status, order_id, current_user.id)
    )
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for("main.restaurant_orders"))
