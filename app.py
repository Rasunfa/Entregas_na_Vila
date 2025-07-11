from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import secrets
import re
import uuid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
from PIL import Image

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

RECAPTCHA_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
RECAPTCHA_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"  # Test site key

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
# Use a strong, random secret key. In production, load from environment variable.
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload size
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production (requires HTTPS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Database initialization
def init_db():
    conn = sqlite3.connect('delivery_system.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        user_type TEXT NOT NULL CHECK (user_type IN ('customer', 'restaurant')),
        phone TEXT,
        address TEXT,
        restaurant_name TEXT,
        restaurant_description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Menu items table
    c.execute('''CREATE TABLE IF NOT EXISTS menu_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        category TEXT,
        available BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (restaurant_id) REFERENCES users (id)
    )''')
    
    # Orders table
    c.execute('''CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        restaurant_id INTEGER NOT NULL,
        total_amount REAL NOT NULL,
        status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'preparing', 'out_for_delivery', 'delivered', 'cancelled')),
        delivery_address TEXT NOT NULL,
        observations TEXT,
        order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES users (id),
        FOREIGN KEY (restaurant_id) REFERENCES users (id)
    )''')
    
    # Order items table
    c.execute('''CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        menu_item_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price REAL NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders (id),
        FOREIGN KEY (menu_item_id) REFERENCES menu_items (id)
    )''')
    
    # Add observations column if it doesn't exist (migration)
    try:
        c.execute('ALTER TABLE orders ADD COLUMN observations TEXT')
    except sqlite3.OperationalError:
        # Column already exists
        pass
    
    # Add image_path column to users if it doesn't exist (migration)
    try:
        c.execute('ALTER TABLE users ADD COLUMN image_path TEXT')
    except sqlite3.OperationalError:
        pass
    # Add image_path column to menu_items if it doesn't exist (migration)
    try:
        c.execute('ALTER TABLE menu_items ADD COLUMN image_path TEXT')
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect('delivery_system.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

# Authentication decorator
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def restaurant_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = get_user_by_id(session['user_id'])
        if user['user_type'] != 'restaurant':
            flash('Access denied. Restaurant account required.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_user_by_id(user_id)

# Routes
@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/index')
def index():
    # This is the original index logic
    if 'user_id' in session:
        if session.get('user_type') == 'restaurant':
            return redirect(url_for('restaurant_dashboard'))
        else:
            return redirect(url_for('customer_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        restaurant_name = request.form.get('restaurant_name', '')
        restaurant_description = request.form.get('restaurant_description', '')

        # Validation
        if not username or not email or not password:
            flash('All fields are required!')
            return render_template('register.html')
        # Username rules: 3-20 chars, alphanumeric and underscores only
        if not re.match(r'^[A-Za-z0-9_]{3,20}$', username):
            flash('Username must be 3-20 characters and contain only letters, numbers, and underscores.')
            return render_template('register.html')
        # Email format
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            flash('Invalid email address!')
            return render_template('register.html')
        # Password strength: min 8 chars, at least one letter and one number
        if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
            flash('Password must be at least 8 characters long and contain both letters and numbers.')
            return render_template('register.html')
        
        # Check if user already exists
        if get_user_by_username(username):
            flash('Username already exists!')
            return render_template('register.html')
        
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Please complete the CAPTCHA.')
            return render_template('register.html')
        recaptcha_verify = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': recaptcha_response}
        )
        if not recaptcha_verify.json().get('success'):
            flash('CAPTCHA verification failed. Please try again.')
            return render_template('register.html')

        # Create new user
        conn = get_db_connection()
        try:
            conn.execute('''INSERT INTO users 
                           (username, email, password_hash, user_type, phone, address, restaurant_name, restaurant_description)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                        (username, email, generate_password_hash(password), user_type, 
                         phone, address, restaurant_name, restaurant_description))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists!')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Please complete the CAPTCHA.')
            return render_template('login.html')
        recaptcha_verify = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': recaptcha_response}
        )
        if not recaptcha_verify.json().get('success'):
            flash('CAPTCHA verification failed. Please try again.')
            return render_template('login.html')
        # Now proceed with username/password logic
        username = request.form['username']
        password = request.form['password']
        
        user = get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_type'] = user['user_type']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('welcome'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_by_id(session['user_id'])
    if user['user_type'] == 'restaurant':
        return redirect(url_for('restaurant_dashboard'))
    else:
        return redirect(url_for('customer_dashboard'))

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    conn = get_db_connection()
    restaurants = conn.execute('''SELECT id, username, restaurant_name, restaurant_description, image_path 
                                 FROM users WHERE user_type = 'restaurant' ''').fetchall()
    conn.close()
    return render_template('customer_dashboard.html', restaurants=restaurants)

@app.route('/restaurant/<int:restaurant_id>')
@login_required
def view_restaurant(restaurant_id):
    conn = get_db_connection()
    restaurant = conn.execute('SELECT * FROM users WHERE id = ? AND user_type = "restaurant"', 
                             (restaurant_id,)).fetchone()
    menu_items = conn.execute('''SELECT * FROM menu_items 
                                WHERE restaurant_id = ? AND available = 1 
                                ORDER BY category, name''', (restaurant_id,)).fetchall()
    conn.close()
    
    if not restaurant:
        flash('Restaurant not found!')
        return redirect(url_for('customer_dashboard'))
    
    return render_template('restaurant_menu.html', restaurant=restaurant, menu_items=menu_items)

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    if 'cart' not in session:
        session['cart'] = []
    
    menu_item_id = int(request.form['menu_item_id'])
    quantity = int(request.form['quantity'])
    
    # Get menu item details
    conn = get_db_connection()
    menu_item = conn.execute('SELECT * FROM menu_items WHERE id = ?', (menu_item_id,)).fetchone()
    conn.close()
    
    if menu_item:
        # Check if item already in cart
        found = False
        for item in session['cart']:
            if item['menu_item_id'] == menu_item_id:
                item['quantity'] += quantity
                found = True
                break
        
        if not found:
            session['cart'].append({
                'menu_item_id': menu_item_id,
                'name': menu_item['name'],
                'price': menu_item['price'],
                'quantity': quantity,
                'restaurant_id': menu_item['restaurant_id']
            })
        
        session.modified = True
        flash('Item added to cart!')
    
    return redirect(url_for('view_restaurant', restaurant_id=menu_item['restaurant_id']))

@app.route('/cart')
@login_required
def view_cart():
    cart = session.get('cart', [])
    total = sum(item['price'] * item['quantity'] for item in cart)
    
    # Get user's saved address
    user = get_user_by_id(session['user_id'])
    user_address = user['address'] if user else ''
    
    return render_template('cart.html', cart=cart, total=total, user_address=user_address)

@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    cart = session.get('cart', [])
    if not cart:
        flash('Your cart is empty!')
        return redirect(url_for('customer_dashboard'))
    
    delivery_address = request.form['delivery_address']
    observations = request.form.get('observations', '')
    if not delivery_address:
        flash('Delivery address is required!')
        return redirect(url_for('view_cart'))
    
    # Group cart items by restaurant
    restaurant_orders = {}
    for item in cart:
        restaurant_id = item['restaurant_id']
        if restaurant_id not in restaurant_orders:
            restaurant_orders[restaurant_id] = []
        restaurant_orders[restaurant_id].append(item)
    
    conn = get_db_connection()
    try:
        for restaurant_id, items in restaurant_orders.items():
            # Calculate total for this restaurant
            total_amount = sum(item['price'] * item['quantity'] for item in items)
            
            # Create order
            cursor = conn.execute('''INSERT INTO orders 
                                   (customer_id, restaurant_id, total_amount, delivery_address, observations)
                                   VALUES (?, ?, ?, ?, ?)''',
                                 (session['user_id'], restaurant_id, total_amount, delivery_address, observations))
            order_id = cursor.lastrowid
            
            # Add order items
            for item in items:
                conn.execute('''INSERT INTO order_items 
                               (order_id, menu_item_id, quantity, price)
                               VALUES (?, ?, ?, ?)''',
                            (order_id, item['menu_item_id'], item['quantity'], item['price']))
        
        conn.commit()
        session.pop('cart', None)
        flash('Order placed successfully!')
        return redirect(url_for('order_history'))
    except Exception as e:
        conn.rollback()
        flash('Error placing order. Please try again.')
        return redirect(url_for('view_cart'))
    finally:
        conn.close()

@app.route('/order_history')
@login_required
def order_history():
    conn = get_db_connection()
    orders = conn.execute('''SELECT o.*, u.restaurant_name, u.username as restaurant_username
                            FROM orders o
                            JOIN users u ON o.restaurant_id = u.id
                            WHERE o.customer_id = ?
                            ORDER BY o.order_date DESC''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('order_history.html', orders=orders)

@app.route('/restaurant_dashboard')
@restaurant_required
def restaurant_dashboard():
    conn = get_db_connection()
    
    # Get restaurant's menu items
    menu_items = conn.execute('''SELECT * FROM menu_items 
                                WHERE restaurant_id = ? 
                                ORDER BY category, name''', (session['user_id'],)).fetchall()
    
    # Get pending orders
    orders = conn.execute('''SELECT o.*, u.username as customer_username
                            FROM orders o
                            JOIN users u ON o.customer_id = u.id
                            WHERE o.restaurant_id = ?
                            ORDER BY o.order_date DESC''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('restaurant_dashboard.html', menu_items=menu_items, orders=orders)

@app.route('/add_menu_item', methods=['GET', 'POST'])
@restaurant_required
def add_menu_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                # Randomize filename
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                # Check MIME type using Pillow
                try:
                    with Image.open(filepath) as img:
                        if not img.format or img.format.lower() not in ALLOWED_EXTENSIONS:
                            os.remove(filepath)
                            flash('Invalid image file!')
                            return render_template('add_menu_item.html')
                except Exception:
                    os.remove(filepath)
                    flash('Invalid image file!')
                    return render_template('add_menu_item.html')
                image_path = filepath.replace('static/', '', 1)
        conn = get_db_connection()
        conn.execute('''INSERT INTO menu_items (restaurant_id, name, description, price, category, image_path)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (session['user_id'], name, description, price, category, image_path))
        conn.commit()
        conn.close()
        flash('Menu item added successfully!')
        return redirect(url_for('restaurant_dashboard'))
    return render_template('add_menu_item.html')

@app.route('/edit_menu_item/<int:item_id>', methods=['GET', 'POST'])
@restaurant_required
def edit_menu_item(item_id):
    conn = get_db_connection()
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        available = 'available' in request.form
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                # Randomize filename
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                # Check MIME type using Pillow
                try:
                    with Image.open(filepath) as img:
                        if not img.format or img.format.lower() not in ALLOWED_EXTENSIONS:
                            os.remove(filepath)
                            flash('Invalid image file!')
                            return render_template('edit_menu_item.html')
                except Exception:
                    os.remove(filepath)
                    flash('Invalid image file!')
                    return render_template('edit_menu_item.html')
                image_path = filepath.replace('static/', '', 1)
        if image_path:
            conn.execute('''UPDATE menu_items SET name = ?, description = ?, price = ?, category = ?, available = ?, image_path = ?
                            WHERE id = ? AND restaurant_id = ?''',
                        (name, description, price, category, available, image_path, item_id, session['user_id']))
        else:
            conn.execute('''UPDATE menu_items SET name = ?, description = ?, price = ?, category = ?, available = ?
                            WHERE id = ? AND restaurant_id = ?''',
                        (name, description, price, category, available, item_id, session['user_id']))
        conn.commit()
        conn.close()
        flash('Menu item updated successfully!')
        return redirect(url_for('restaurant_dashboard'))
    menu_item = conn.execute('SELECT * FROM menu_items WHERE id = ? AND restaurant_id = ?',
                            (item_id, session['user_id'])).fetchone()
    conn.close()
    if not menu_item:
        flash('Menu item not found!')
        return redirect(url_for('restaurant_dashboard'))
    return render_template('edit_menu_item.html', menu_item=menu_item)

@app.route('/delete_menu_item/<int:item_id>')
@restaurant_required
def delete_menu_item(item_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM menu_items WHERE id = ? AND restaurant_id = ?',
                (item_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Menu item deleted successfully!')
    return redirect(url_for('restaurant_dashboard'))

@app.route('/update_order_status/<int:order_id>/<status>')
@restaurant_required
def update_order_status(order_id, status):
    valid_statuses = ['pending', 'confirmed', 'preparing', 'out_for_delivery', 'delivered', 'cancelled']
    if status not in valid_statuses:
        flash('Invalid status!')
        return redirect(url_for('restaurant_dashboard'))
    
    conn = get_db_connection()
    conn.execute('UPDATE orders SET status = ? WHERE id = ? AND restaurant_id = ?',
                (status, order_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash(f'Order status updated to {status}!')
    return redirect(url_for('restaurant_dashboard'))

@app.route('/order_details/<int:order_id>')
@login_required
def order_details(order_id):
    conn = get_db_connection()
    
    # Get order details
    order = conn.execute('''SELECT o.*, u.restaurant_name, u.username as restaurant_username,
                           c.username as customer_username
                           FROM orders o
                           JOIN users u ON o.restaurant_id = u.id
                           JOIN users c ON o.customer_id = c.id
                           WHERE o.id = ?''', (order_id,)).fetchone()
    
    # Get order items
    order_items = conn.execute('''SELECT oi.*, mi.name as menu_item_name
                                 FROM order_items oi
                                 JOIN menu_items mi ON oi.menu_item_id = mi.id
                                 WHERE oi.order_id = ?''', (order_id,)).fetchall()
    
    conn.close()
    
    if not order:
        flash('Order not found!')
        return redirect(url_for('dashboard'))
    
    # Check if user has permission to view this order
    if session['user_type'] == 'customer' and order['customer_id'] != session['user_id']:
        flash('Access denied!')
        return redirect(url_for('dashboard'))
    elif session['user_type'] == 'restaurant' and order['restaurant_id'] != session['user_id']:
        flash('Access denied!')
        return redirect(url_for('dashboard'))
    
    return render_template('order_details.html', order=order, order_items=order_items)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found!')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        if user['user_type'] == 'restaurant':
            # Delete order items for this restaurant's orders
            conn.execute('DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE restaurant_id = ?)', (user_id,))
            # Delete menu items
            conn.execute('DELETE FROM menu_items WHERE restaurant_id = ?', (user_id,))
            # Delete orders
            conn.execute('DELETE FROM orders WHERE restaurant_id = ?', (user_id,))
        else:
            # Customer: delete order items for their orders
            conn.execute('DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE customer_id = ?)', (user_id,))
            # Delete orders
            conn.execute('DELETE FROM orders WHERE customer_id = ?', (user_id,))
        # Delete user
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        session.clear()
        flash('Your account and all related data have been deleted.')
        return redirect(url_for('welcome'))
    except Exception as e:
        conn.rollback()
        flash('Error deleting account. Please try again.')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

@app.route('/upload_restaurant_image', methods=['POST'])
@restaurant_required
def upload_restaurant_image():
    if 'image' not in request.files:
        flash('No file part')
        return redirect(url_for('restaurant_dashboard'))
    file = request.files['image']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('restaurant_dashboard'))
    if file and file.filename and allowed_file(file.filename):
        # Randomize filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        # Check MIME type using Pillow
        try:
            with Image.open(filepath) as img:
                if not img.format or img.format.lower() not in ALLOWED_EXTENSIONS:
                    os.remove(filepath)
                    flash('Invalid image file!')
                    return render_template('restaurant_dashboard')
        except Exception:
            os.remove(filepath)
            flash('Invalid image file!')
            return redirect(url_for('restaurant_dashboard'))
        image_path = filepath.replace('static/', '', 1)
        conn = get_db_connection()
        conn.execute('UPDATE users SET image_path = ? WHERE id = ?', (image_path, session['user_id']))
        conn.commit()
        conn.close()
        flash('Restaurant image updated!')
    else:
        flash('Invalid file type!')
    return redirect(url_for('restaurant_dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)