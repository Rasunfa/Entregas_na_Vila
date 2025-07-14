from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
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
from urllib.parse import urlparse, urljoin

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

RECAPTCHA_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
RECAPTCHA_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"  # Test site key

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_safe_redirect():
    next_url = request.args.get('next')
    if next_url and urlparse(next_url).netloc == '':
        return next_url
    referer = request.headers.get('Referer')
    if referer and urlparse(referer).netloc == '':
        return referer
    return None

app = Flask(__name__)
# Use a strong, random secret key. In production, load from environment variable.
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload size
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production (requires HTTPS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "200 per hour"])

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
        image_path TEXT,
        cuisine_type TEXT,
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
        image_path TEXT,
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
        estimated_delivery_time TIMESTAMP,
        actual_delivery_time TIMESTAMP,
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
    
    # Ratings and Reviews table
    c.execute('''CREATE TABLE IF NOT EXISTS ratings_reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        restaurant_id INTEGER NOT NULL,
        menu_item_id INTEGER,
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        review_text TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES users (id),
        FOREIGN KEY (restaurant_id) REFERENCES users (id),
        FOREIGN KEY (menu_item_id) REFERENCES menu_items (id),
        UNIQUE(customer_id, restaurant_id, menu_item_id)
    )''')
    
    # Favorites table
    c.execute('''CREATE TABLE IF NOT EXISTS favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        restaurant_id INTEGER,
        menu_item_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES users (id),
        FOREIGN KEY (restaurant_id) REFERENCES users (id),
        FOREIGN KEY (menu_item_id) REFERENCES menu_items (id),
        UNIQUE(customer_id, restaurant_id, menu_item_id)
    )''')
    
    # Order tracking table
    c.execute('''CREATE TABLE IF NOT EXISTS order_tracking (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        status_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders (id)
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
    
    # Add estimated_delivery_time and actual_delivery_time to orders if they don't exist
    try:
        c.execute('ALTER TABLE orders ADD COLUMN estimated_delivery_time TIMESTAMP')
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute('ALTER TABLE orders ADD COLUMN actual_delivery_time TIMESTAMP')
    except sqlite3.OperationalError:
        pass
    
    # Add cuisine_type column to users if it doesn't exist (migration)
    try:
        c.execute('ALTER TABLE users ADD COLUMN cuisine_type TEXT')
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
            flash('Acesso negado. Conta de restaurante necessária.')
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
        cuisine_type = request.form.get('cuisine_type', '')

        # Validação
        if not username or not email or not password:
            flash('Todos os campos são obrigatórios!')
            return render_template('register.html')
        # Nome de utilizador: 3-20 caracteres, alfanumérico e underscores
        if not re.match(r'^[A-Za-z0-9_]{3,20}$', username):
            flash('O nome de utilizador deve ter entre 3 e 20 caracteres e conter apenas letras, números e underscores.')
            return render_template('register.html')
        # Email
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            flash('Endereço de email inválido!')
            return render_template('register.html')
        # Palavra-passe: min 8 chars, pelo menos uma letra e um número
        if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
            flash('A palavra-passe deve ter pelo menos 8 caracteres e conter letras e números.')
            return render_template('register.html')
        # Já existe utilizador?
        if get_user_by_username(username):
            flash('O nome de utilizador já existe!')
            return render_template('register.html')
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Por favor, complete o CAPTCHA.')
            return render_template('register.html')
        recaptcha_verify = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': recaptcha_response}
        )
        if not recaptcha_verify.json().get('success'):
            flash('Falha na verificação do CAPTCHA. Tente novamente.')
            return render_template('register.html')
        # Criar novo utilizador
        conn = get_db_connection()
        try:
            if user_type == 'restaurant':
                conn.execute('''INSERT INTO users 
                               (username, email, password_hash, user_type, phone, address, restaurant_name, restaurant_description, cuisine_type)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (username, email, generate_password_hash(password), user_type, 
                             phone, address, restaurant_name, restaurant_description, cuisine_type))
            else:
                conn.execute('''INSERT INTO users 
                               (username, email, password_hash, user_type, phone, address)
                               VALUES (?, ?, ?, ?, ?, ?)''',
                            (username, email, generate_password_hash(password), user_type, phone, address))
            conn.commit()
            flash('Registo efetuado com sucesso! Por favor, faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('O email já existe!')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Por favor, complete o CAPTCHA.')
            return render_template('login.html')
        recaptcha_verify = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': recaptcha_response}
        )
        if not recaptcha_verify.json().get('success'):
            flash('Falha na verificação do CAPTCHA. Tente novamente.')
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
            flash('Nome de utilizador ou palavra-passe inválidos!')
    
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
    restaurants = conn.execute('''SELECT u.id, u.username, u.restaurant_name, u.restaurant_description, u.image_path,
                                        AVG(rr.rating) as avg_rating, COUNT(rr.id) as review_count
                                 FROM users u
                                 LEFT JOIN ratings_reviews rr ON u.id = rr.restaurant_id AND rr.menu_item_id IS NULL
                                 WHERE u.user_type = 'restaurant'
                                 GROUP BY u.id
                                 ORDER BY avg_rating DESC NULLS LAST''').fetchall()
    conn.close()
    return render_template('customer_dashboard.html', restaurants=restaurants)

@app.route('/restaurant/<int:restaurant_id>')
@login_required
def view_restaurant(restaurant_id):
    conn = get_db_connection()
    restaurant = conn.execute('SELECT * FROM users WHERE id = ? AND user_type = "restaurant"', 
                             (restaurant_id,)).fetchone()
    
    if not restaurant:
        flash('Restaurante não encontrado!')
        return redirect(url_for('customer_dashboard'))
    
    # Get menu items with ratings
    menu_items = conn.execute('''SELECT mi.*, AVG(rr.rating) as avg_rating, COUNT(rr.id) as review_count
                                FROM menu_items mi
                                LEFT JOIN ratings_reviews rr ON mi.id = rr.menu_item_id
                                WHERE mi.restaurant_id = ? AND mi.available = 1
                                GROUP BY mi.id
                                ORDER BY mi.category, mi.name''', (restaurant_id,)).fetchall()
    
    # Get restaurant rating
    restaurant_rating = conn.execute('''SELECT AVG(rating) as avg_rating, COUNT(id) as review_count
                                      FROM ratings_reviews 
                                      WHERE restaurant_id = ? AND menu_item_id IS NULL''', 
                                   (restaurant_id,)).fetchone()
    
    # Check if restaurant is in user's favorites
    is_favorite = False
    if session['user_type'] == 'customer':
        favorite = conn.execute('''SELECT id FROM favorites 
                                 WHERE customer_id = ? AND restaurant_id = ? AND menu_item_id IS NULL''',
                              (session['user_id'], restaurant_id)).fetchone()
        is_favorite = favorite is not None
    
    # Get user's ratings for this restaurant and its menu items
    user_ratings = {}
    if session['user_type'] == 'customer':
        # Restaurant rating
        user_restaurant_rating = conn.execute('''SELECT rating, review_text 
                                               FROM ratings_reviews 
                                               WHERE customer_id = ? AND restaurant_id = ? AND menu_item_id IS NULL''',
                                            (session['user_id'], restaurant_id)).fetchone()
        if user_restaurant_rating:
            user_ratings['restaurant'] = user_restaurant_rating
        
        # Menu item ratings
        menu_item_ratings = conn.execute('''SELECT menu_item_id, rating, review_text 
                                          FROM ratings_reviews 
                                          WHERE customer_id = ? AND restaurant_id = ? AND menu_item_id IS NOT NULL''',
                                       (session['user_id'], restaurant_id)).fetchall()
        for rating in menu_item_ratings:
            user_ratings[f"menu_item_{rating['menu_item_id']}"] = rating
    
    # Cart context
    cart_items = [item for item in session.get('cart', []) if item['restaurant_id'] == restaurant_id]
    cart_total = sum(item['price'] * item['quantity'] for item in cart_items)
    
    # Get user favorites for menu items
    user_favorites = set()
    if session['user_type'] == 'customer':
        favorites = conn.execute('''SELECT menu_item_id FROM favorites 
                                  WHERE customer_id = ? AND menu_item_id IS NOT NULL''',
                               (session['user_id'],)).fetchall()
        user_favorites = {fav['menu_item_id'] for fav in favorites}
    
    # Get recent reviews
    recent_reviews = conn.execute('''SELECT rr.*, u.username as customer_username
                                    FROM ratings_reviews rr
                                    JOIN users u ON rr.customer_id = u.id
                                    WHERE rr.restaurant_id = ? AND rr.menu_item_id IS NULL
                                    ORDER BY rr.created_at DESC
                                    LIMIT 5''', (restaurant_id,)).fetchall()
    
    conn.close()
    
    return render_template('restaurant_menu.html', restaurant=restaurant, menu_items=menu_items,
                         restaurant_rating=restaurant_rating, is_favorite=is_favorite, user_ratings=user_ratings,
                         cart_items=cart_items, cart_total=cart_total, user_favorites=user_favorites,
                         recent_reviews=recent_reviews)

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    if 'cart' not in session:
        session['cart'] = []
    
    try:
        menu_item_id = int(request.form['menu_item_id'])
        quantity = int(request.form['quantity'])
        
        if quantity < 1 or quantity > 99:
            flash('Quantidade deve ser entre 1 e 99!')
            return redirect(request.referrer or url_for('customer_dashboard'))
        
        # Get menu item details
        conn = get_db_connection()
        menu_item = conn.execute('SELECT * FROM menu_items WHERE id = ? AND available = 1', (menu_item_id,)).fetchone()
        conn.close()
        
        if not menu_item:
            flash('Item não encontrado ou indisponível!')
            return redirect(request.referrer or url_for('customer_dashboard'))
        
        # Check if item already in cart
        cart = session['cart']
        item_found = False
        
        for item in cart:
            if item['menu_item_id'] == menu_item_id:
                new_quantity = item['quantity'] + quantity
                if new_quantity > 99:
                    flash('Quantidade máxima por item é 99!')
                    return redirect(request.referrer or url_for('customer_dashboard'))
                item['quantity'] = new_quantity
                item_found = True
                break
        
        if not item_found:
            cart.append({
                'menu_item_id': menu_item_id,
                'name': menu_item['name'],
                'price': float(menu_item['price']),
                'quantity': quantity,
                'restaurant_id': menu_item['restaurant_id']
            })
        
        session['cart'] = cart
        session.modified = True
        flash('Item adicionado ao carrinho!')
        
        # Redirect back to the restaurant page
        return redirect(url_for('view_restaurant', restaurant_id=menu_item['restaurant_id']))
        
    except (ValueError, KeyError) as e:
        flash('Dados inválidos!')
        return redirect(request.referrer or url_for('customer_dashboard'))

@app.route('/remove_from_cart/<int:item_id>')
@login_required
def remove_from_cart(item_id):
    cart = session.get('cart', [])
    
    # Find and remove the item
    for i, item in enumerate(cart):
        if item['menu_item_id'] == item_id:
            cart.pop(i)
            session['cart'] = cart
            session.modified = True
            flash('Item removido do carrinho!')
            break
    
    return redirect(url_for('view_cart'))

@app.route('/update_cart_quantity/<int:item_id>/<int:quantity>')
@login_required
def update_cart_quantity(item_id, quantity):
    if quantity < 1:
        flash('Quantidade deve ser pelo menos 1!')
        return redirect(url_for('view_cart'))
    
    if quantity > 99:
        flash('Quantidade máxima por item é 99!')
        return redirect(url_for('view_cart'))
    
    cart = session.get('cart', [])
    item_found = False
    
    # Find and update the item
    for item in cart:
        if item['menu_item_id'] == item_id:
            item['quantity'] = quantity
            item_found = True
            break
    
    if item_found:
        session['cart'] = cart
        session.modified = True
        flash('Quantidade atualizada!')
    else:
        flash('Item não encontrado no carrinho!')
    
    return redirect(url_for('view_cart'))

@app.route('/cart')
@login_required
def view_cart():
    cart_items = session.get('cart', [])
    
    # Fetch image information for cart items
    if cart_items:
        conn = get_db_connection()
        menu_item_ids = [item['menu_item_id'] for item in cart_items]
        placeholders = ','.join(['?' for _ in menu_item_ids])
        menu_items_with_images = conn.execute(f'SELECT id, image_path FROM menu_items WHERE id IN ({placeholders})', menu_item_ids).fetchall()
        conn.close()
        
        # Create a dictionary for quick lookup
        image_lookup = {item['id']: item['image_path'] for item in menu_items_with_images}
        
        # Add image information to cart items
        for item in cart_items:
            item['image_path'] = image_lookup.get(item['menu_item_id'])
    
    subtotal = sum(item['price'] * item['quantity'] for item in cart_items)
    delivery_fee = 2.50  # Fixed delivery fee
    total = subtotal + delivery_fee
    
    # Get user's saved address
    user = get_user_by_id(session['user_id'])
    user_address = user['address'] if user else ''
    
    return render_template('cart.html', cart_items=cart_items, subtotal=subtotal, 
                         delivery_fee=delivery_fee, total=total, user_address=user_address)

@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    cart = session.get('cart', [])
    if not cart:
        flash('O seu carrinho está vazio!')
        return redirect(url_for('customer_dashboard'))
    
    delivery_address = request.form['delivery_address']
    observations = request.form.get('observations', '')
    if not delivery_address:
        flash('O endereço de entrega é obrigatório!')
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
        flash('Pedido efetuado com sucesso!')
        return redirect(url_for('order_history'))
    except Exception as e:
        conn.rollback()
        flash('Erro ao efetuar pedido. Por favor, tente novamente.')
        return redirect(url_for('view_cart'))
    finally:
        conn.close()

@app.route('/order_history')
@login_required
def order_history():
    conn = get_db_connection()
    orders = conn.execute('''SELECT o.*, u.restaurant_name, u.username as restaurant_username, u.id as restaurant_id
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
                            flash('Ficheiro de imagem inválido!')
                            return render_template('add_menu_item.html')
                except Exception:
                    os.remove(filepath)
                    flash('Ficheiro de imagem inválido!')
                    return render_template('add_menu_item.html')
                image_path = os.path.relpath(filepath, 'static')
                # Ensure forward slashes are used
                image_path = image_path.replace('\\', '/')
        conn = get_db_connection()
        conn.execute('''INSERT INTO menu_items (restaurant_id, name, description, price, category, image_path)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (session['user_id'], name, description, price, category, image_path))
        conn.commit()
        conn.close()
        flash('Item do menu adicionado com sucesso!')
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
                            flash('Ficheiro de imagem inválido!')
                            return render_template('edit_menu_item.html')
                except Exception:
                    os.remove(filepath)
                    flash('Ficheiro de imagem inválido!')
                    return render_template('edit_menu_item.html')
                image_path = os.path.relpath(filepath, 'static')
                # Ensure forward slashes are used
                image_path = image_path.replace('\\', '/')
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
        flash('Item do menu atualizado com sucesso!')
        return redirect(url_for('restaurant_dashboard'))
    menu_item = conn.execute('SELECT * FROM menu_items WHERE id = ? AND restaurant_id = ?',
                            (item_id, session['user_id'])).fetchone()
    conn.close()
    if not menu_item:
        flash('Item do menu não encontrado!')
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
    
    flash('Item do menu eliminado com sucesso!')
    return redirect(url_for('restaurant_dashboard'))

@app.route('/update_order_status/<int:order_id>', methods=['POST'])
@restaurant_required
def update_order_status(order_id):
    status = request.form.get('status')
    valid_statuses = ['pending', 'confirmed', 'preparing', 'out_for_delivery', 'delivered', 'cancelled']
    status_messages = {
        'pending': 'Pedido pendente',
        'confirmed': 'Pedido confirmado pelo restaurante',
        'preparing': 'Pedido em preparação',
        'out_for_delivery': 'Pedido saiu para entrega',
        'delivered': 'Pedido entregue',
        'cancelled': 'Pedido cancelado pelo restaurante'
    }
    if status not in valid_statuses:
        flash('Estado inválido!')
        return redirect(url_for('restaurant_orders'))
    
    conn = get_db_connection()
    conn.execute('UPDATE orders SET status = ? WHERE id = ? AND restaurant_id = ?',
                (status, order_id, session['user_id']))
    # Add tracking entry
    conn.execute('INSERT INTO order_tracking (order_id, status, status_message) VALUES (?, ?, ?)',
                (order_id, status, status_messages.get(status, status)))
    conn.commit()
    conn.close()
    
    flash(f'Estado do pedido atualizado para {status}!')
    return redirect(url_for('restaurant_orders'))

@app.route('/order_details/<int:order_id>')
@login_required
def order_details(order_id):
    conn = get_db_connection()
    
    # Get order details with phone numbers
    order = conn.execute('''SELECT o.*, u.restaurant_name, u.username as restaurant_username, u.phone as restaurant_phone,
                           c.username as customer_username, c.phone as customer_phone
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
        flash('Pedido não encontrado!')
        return redirect(url_for('dashboard'))
    
    # Check if user has permission to view this order
    if session['user_type'] == 'customer' and order['customer_id'] != session['user_id']:
        flash('Acesso negado!')
        return redirect(url_for('dashboard'))
    elif session['user_type'] == 'restaurant' and order['restaurant_id'] != session['user_id']:
        flash('Acesso negado!')
        return redirect(url_for('dashboard'))
    
    return render_template('order_details.html', order=order, order_items=order_items)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    if not user:
        flash('Utilizador não encontrado!')
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
        flash('A sua conta e todos os dados relacionados foram eliminados.')
        return redirect(url_for('welcome'))
    except Exception as e:
        conn.rollback()
        flash('Erro ao eliminar conta. Por favor, tente novamente.')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

@app.route('/upload_restaurant_image', methods=['POST'])
@restaurant_required
def upload_restaurant_image():
    if 'image' not in request.files:
        flash('Nenhum ficheiro selecionado')
        return redirect(url_for('restaurant_dashboard'))
    file = request.files['image']
    if file.filename == '':
        flash('Nenhum ficheiro selecionado')
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
                    flash('Ficheiro de imagem inválido!')
                    return render_template('restaurant_dashboard')
        except Exception:
            os.remove(filepath)
            flash('Ficheiro de imagem inválido!')
            return redirect(url_for('restaurant_dashboard'))
        image_path = os.path.relpath(filepath, 'static')
        # Ensure forward slashes are used
        image_path = image_path.replace('\\', '/')
        conn = get_db_connection()
        conn.execute('UPDATE users SET image_path = ? WHERE id = ?', (image_path, session['user_id']))
        conn.commit()
        conn.close()
        flash('Imagem do restaurante atualizada!')
    else:
        flash('Tipo de ficheiro inválido!')
    return redirect(url_for('restaurant_dashboard'))

@app.route('/edit_restaurant_profile')
@restaurant_required
def edit_restaurant_profile():
    return render_template('edit_restaurant_profile.html')

@app.route('/update_restaurant_profile', methods=['POST'])
@restaurant_required
def update_restaurant_profile():
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    address = request.form.get('address', '').strip()
    restaurant_name = request.form.get('restaurant_name', '').strip()
    restaurant_description = request.form.get('restaurant_description', '').strip()
    cuisine_type = request.form.get('cuisine_type', '').strip()
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    # Validation
    if not email:
        flash('O email é obrigatório!')
        return redirect(url_for('edit_restaurant_profile'))
    
    if not restaurant_name:
        flash('O nome do restaurante é obrigatório!')
        return redirect(url_for('edit_restaurant_profile'))
    
    if not cuisine_type:
        flash('O tipo de cozinha é obrigatório!')
        return redirect(url_for('edit_restaurant_profile'))
    
    conn = get_db_connection()
    try:
        # Check if user wants to change password
        if current_password and new_password:
            if new_password != confirm_password:
                flash('As palavras-passe não coincidem!')
                return redirect(url_for('edit_restaurant_profile'))
            
            # Validate current password
            user = conn.execute('SELECT password_hash FROM users WHERE id = ?', 
                              (session['user_id'],)).fetchone()
            if not check_password_hash(user['password_hash'], current_password):
                flash('Palavra-passe atual incorreta!')
                return redirect(url_for('edit_restaurant_profile'))
            
            # Validate new password
            if len(new_password) < 8 or not re.search(r'[A-Za-z]', new_password) or not re.search(r'\d', new_password):
                flash('A nova palavra-passe deve ter pelo menos 8 caracteres e conter letras e números.')
                return redirect(url_for('edit_restaurant_profile'))
            
            # Update with new password
            conn.execute('''UPDATE users 
                           SET email = ?, phone = ?, address = ?, restaurant_name = ?, 
                               restaurant_description = ?, cuisine_type = ?, password_hash = ?
                           WHERE id = ?''',
                        (email, phone, address, restaurant_name, restaurant_description, 
                         cuisine_type, generate_password_hash(new_password), session['user_id']))
        else:
            # Update without password change
            conn.execute('''UPDATE users 
                           SET email = ?, phone = ?, address = ?, restaurant_name = ?, 
                               restaurant_description = ?, cuisine_type = ?
                           WHERE id = ?''',
                        (email, phone, address, restaurant_name, restaurant_description, 
                         cuisine_type, session['user_id']))
        
        # Handle image upload if provided
        if 'image' in request.files and request.files['image'].filename:
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
                            flash('Ficheiro de imagem inválido!')
                            return redirect(url_for('edit_restaurant_profile'))
                except Exception:
                    os.remove(filepath)
                    flash('Ficheiro de imagem inválido!')
                    return redirect(url_for('edit_restaurant_profile'))
                
                image_path = os.path.relpath(filepath, 'static')
                image_path = image_path.replace('\\', '/')
                
                # Update image path
                conn.execute('UPDATE users SET image_path = ? WHERE id = ?', 
                           (image_path, session['user_id']))
        
        conn.commit()
        flash('Perfil do restaurante atualizado com sucesso!')
    except Exception as e:
        flash('Erro ao atualizar perfil do restaurante!')
        print(f"Error updating restaurant profile: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('restaurant_dashboard'))

@app.route('/edit_customer_profile')
@login_required
def edit_customer_profile():
    return render_template('edit_customer_profile.html')

@app.route('/update_customer_profile', methods=['POST'])
@login_required
def update_customer_profile():
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    address = request.form.get('address', '').strip()
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    # Validation
    if not email:
        flash('O email é obrigatório!')
        return redirect(url_for('edit_customer_profile'))
    
    conn = get_db_connection()
    try:
        # Check if user wants to change password
        if current_password and new_password:
            if new_password != confirm_password:
                flash('As palavras-passe não coincidem!')
                return redirect(url_for('edit_customer_profile'))
            
            # Validate current password
            user = conn.execute('SELECT password_hash FROM users WHERE id = ?', 
                              (session['user_id'],)).fetchone()
            if not check_password_hash(user['password_hash'], current_password):
                flash('Palavra-passe atual incorreta!')
                return redirect(url_for('edit_customer_profile'))
            
            # Validate new password
            if len(new_password) < 8 or not re.search(r'[A-Za-z]', new_password) or not re.search(r'\d', new_password):
                flash('A nova palavra-passe deve ter pelo menos 8 caracteres e conter letras e números.')
                return redirect(url_for('edit_customer_profile'))
            
            # Update with new password
            conn.execute('''UPDATE users 
                           SET email = ?, phone = ?, address = ?, password_hash = ?
                           WHERE id = ?''',
                        (email, phone, address, generate_password_hash(new_password), session['user_id']))
        else:
            # Update without password change
            conn.execute('''UPDATE users 
                           SET email = ?, phone = ?, address = ?
                           WHERE id = ?''',
                        (email, phone, address, session['user_id']))
        
        conn.commit()
        flash('Perfil atualizado com sucesso!')
    except Exception as e:
        flash('Erro ao atualizar perfil!')
        print(f"Error updating customer profile: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('customer_dashboard'))

@app.route('/update_restaurant_info', methods=['POST'])
@restaurant_required
def update_restaurant_info():
    restaurant_name = request.form.get('restaurant_name', '').strip()
    restaurant_description = request.form.get('restaurant_description', '').strip()
    cuisine_type = request.form.get('cuisine_type', '').strip()
    
    # Validation
    if not restaurant_name:
        flash('O nome do restaurante é obrigatório!')
        return redirect(url_for('restaurant_dashboard'))
    
    if not cuisine_type:
        flash('O tipo de cozinha é obrigatório!')
        return redirect(url_for('restaurant_dashboard'))
    
    conn = get_db_connection()
    try:
        conn.execute('''UPDATE users 
                       SET restaurant_name = ?, restaurant_description = ?, cuisine_type = ?
                       WHERE id = ?''',
                    (restaurant_name, restaurant_description, cuisine_type, session['user_id']))
        conn.commit()
        flash('Informações do restaurante atualizadas com sucesso!')
    except Exception as e:
        flash('Erro ao atualizar informações do restaurante!')
        print(f"Error updating restaurant info: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('restaurant_dashboard'))

@app.route('/restaurant_orders')
@restaurant_required
def restaurant_orders():
    conn = get_db_connection()
    
    # Get all orders for this restaurant
    orders = conn.execute('''SELECT o.*, u.username as customer_username
                            FROM orders o
                            JOIN users u ON o.customer_id = u.id
                            WHERE o.restaurant_id = ?
                            ORDER BY o.order_date DESC''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('restaurant_orders.html', orders=orders)

# Ratings and Reviews Routes
@app.route('/rate_restaurant/<int:restaurant_id>', methods=['POST'])
@login_required
def rate_restaurant(restaurant_id):
    rating = int(request.form.get('rating', 0))
    review_text = request.form.get('review_text', '').strip()
    
    if rating < 1 or rating > 5:
        flash('Avaliação inválida!')
        return redirect(url_for('view_restaurant', restaurant_id=restaurant_id))
    
    conn = get_db_connection()
    
    # Check if user has ordered from this restaurant and order is delivered
    has_ordered = conn.execute('''SELECT COUNT(*) FROM orders 
                                 WHERE customer_id = ? AND restaurant_id = ? AND status = 'delivered' ''',
                              (session['user_id'], restaurant_id)).fetchone()[0]
    
    if has_ordered == 0:
        flash('Só pode avaliar restaurantes onde já fez encomendas entregues!')
        return redirect(url_for('view_restaurant', restaurant_id=restaurant_id))
    
    # Check if user already rated this restaurant
    existing = conn.execute('SELECT id FROM ratings_reviews WHERE customer_id = ? AND restaurant_id = ? AND menu_item_id IS NULL',
                          (session['user_id'], restaurant_id)).fetchone()
    
    if existing:
        # Update existing rating
        conn.execute('''UPDATE ratings_reviews SET rating = ?, review_text = ?, created_at = CURRENT_TIMESTAMP
                       WHERE customer_id = ? AND restaurant_id = ? AND menu_item_id IS NULL''',
                    (rating, review_text, session['user_id'], restaurant_id))
    else:
        # Insert new rating
        conn.execute('''INSERT INTO ratings_reviews (customer_id, restaurant_id, rating, review_text)
                       VALUES (?, ?, ?, ?)''',
                    (session['user_id'], restaurant_id, rating, review_text))
    
    conn.commit()
    conn.close()
    
    flash('Obrigado pela sua avaliação!')
    return redirect(url_for('view_restaurant', restaurant_id=restaurant_id))

@app.route('/rate_menu_item/<int:menu_item_id>', methods=['POST'])
@login_required
def rate_menu_item(menu_item_id):
    rating = int(request.form.get('rating', 0))
    review_text = request.form.get('review_text', '').strip()
    
    if rating < 1 or rating > 5:
        flash('Avaliação inválida!')
        return redirect(url_for('customer_dashboard'))
    
    conn = get_db_connection()
    
    # Get restaurant_id for this menu item
    menu_item = conn.execute('SELECT restaurant_id FROM menu_items WHERE id = ?', (menu_item_id,)).fetchone()
    if not menu_item:
        flash('Item do menu não encontrado!')
        return redirect(url_for('customer_dashboard'))
    
    # Check if user has ordered this menu item and order is delivered
    has_ordered_item = conn.execute('''SELECT COUNT(*) FROM order_items oi
                                      JOIN orders o ON oi.order_id = o.id
                                      WHERE o.customer_id = ? AND oi.menu_item_id = ? AND o.status = 'delivered' ''',
                                   (session['user_id'], menu_item_id)).fetchone()[0]
    
    if has_ordered_item == 0:
        flash('Só pode avaliar itens do menu que já encomendou e foram entregues!')
        return redirect(url_for('view_restaurant', restaurant_id=menu_item['restaurant_id']))
    
    # Check if user already rated this menu item
    existing = conn.execute('SELECT id FROM ratings_reviews WHERE customer_id = ? AND menu_item_id = ?',
                          (session['user_id'], menu_item_id)).fetchone()
    
    if existing:
        # Update existing rating
        conn.execute('''UPDATE ratings_reviews SET rating = ?, review_text = ?, created_at = CURRENT_TIMESTAMP
                       WHERE customer_id = ? AND menu_item_id = ?''',
                    (rating, review_text, session['user_id'], menu_item_id))
    else:
        # Insert new rating
        conn.execute('''INSERT INTO ratings_reviews (customer_id, restaurant_id, menu_item_id, rating, review_text)
                       VALUES (?, ?, ?, ?, ?)''',
                    (session['user_id'], menu_item['restaurant_id'], menu_item_id, rating, review_text))
    
    conn.commit()
    conn.close()
    
    flash('Obrigado pela sua avaliação!')
    return redirect(url_for('view_restaurant', restaurant_id=menu_item['restaurant_id']))

# Favorites Routes
@app.route('/add_to_favorites/<int:restaurant_id>')
@login_required
def add_restaurant_to_favorites(restaurant_id):
    conn = get_db_connection()
    
    # Check if already in favorites
    existing = conn.execute('SELECT id FROM favorites WHERE customer_id = ? AND restaurant_id = ? AND menu_item_id IS NULL',
                          (session['user_id'], restaurant_id)).fetchone()
    
    if not existing:
        conn.execute('INSERT INTO favorites (customer_id, restaurant_id) VALUES (?, ?)',
                    (session['user_id'], restaurant_id))
        conn.commit()
        flash('Restaurante adicionado aos favoritos!')
    else:
        flash('O restaurante já está nos seus favoritos!')
    
    conn.close()
    redirect_url = get_safe_redirect()
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('view_restaurant', restaurant_id=restaurant_id))

@app.route('/remove_from_favorites/<int:restaurant_id>')
@login_required
def remove_restaurant_from_favorites(restaurant_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM favorites WHERE customer_id = ? AND restaurant_id = ? AND menu_item_id IS NULL',
                (session['user_id'], restaurant_id))
    conn.commit()
    conn.close()
    
    flash('Restaurante removido dos favoritos!')
    redirect_url = get_safe_redirect()
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('view_restaurant', restaurant_id=restaurant_id))

@app.route('/add_menu_item_to_favorites/<int:menu_item_id>')
@login_required
def add_menu_item_to_favorites(menu_item_id):
    conn = get_db_connection()
    
    # Get restaurant_id for this menu item
    menu_item = conn.execute('SELECT restaurant_id FROM menu_items WHERE id = ?', (menu_item_id,)).fetchone()
    if not menu_item:
        flash('Item do menu não encontrado!')
        return redirect(url_for('customer_dashboard'))
    
    # Check if already in favorites
    existing = conn.execute('SELECT id FROM favorites WHERE customer_id = ? AND menu_item_id = ?',
                          (session['user_id'], menu_item_id)).fetchone()
    
    if not existing:
        conn.execute('INSERT INTO favorites (customer_id, restaurant_id, menu_item_id) VALUES (?, ?, ?)',
                    (session['user_id'], menu_item['restaurant_id'], menu_item_id))
        conn.commit()
        flash('Item do menu adicionado aos favoritos!')
    else:
        flash('O item do menu já está nos seus favoritos!')
    
    conn.close()
    redirect_url = get_safe_redirect()
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('view_restaurant', restaurant_id=menu_item['restaurant_id']))

@app.route('/remove_menu_item_from_favorites/<int:menu_item_id>')
@login_required
def remove_menu_item_from_favorites(menu_item_id):
    conn = get_db_connection()
    
    # Get restaurant_id for this menu item
    menu_item = conn.execute('SELECT restaurant_id FROM menu_items WHERE id = ?', (menu_item_id,)).fetchone()
    if not menu_item:
        flash('Item do menu não encontrado!')
        return redirect(url_for('customer_dashboard'))
    
    conn.execute('DELETE FROM favorites WHERE customer_id = ? AND menu_item_id = ?',
                (session['user_id'], menu_item_id))
    conn.commit()
    conn.close()
    
    flash('Item do menu removido dos favoritos!')
    redirect_url = get_safe_redirect()
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('view_restaurant', restaurant_id=menu_item['restaurant_id']))

@app.route('/favorites')
@login_required
def view_favorites():
    conn = get_db_connection()
    
    # Get favorite restaurants
    favorite_restaurants = conn.execute('''SELECT u.id, u.restaurant_name, u.restaurant_description, u.image_path,
                                         AVG(rr.rating) as avg_rating, COUNT(rr.id) as review_count
                                         FROM favorites f
                                         JOIN users u ON f.restaurant_id = u.id
                                         LEFT JOIN ratings_reviews rr ON u.id = rr.restaurant_id
                                         WHERE f.customer_id = ? AND f.menu_item_id IS NULL
                                         GROUP BY u.id''', (session['user_id'],)).fetchall()
    
    # Get favorite menu items
    favorite_menu_items = conn.execute('''SELECT mi.id, mi.name, mi.description, mi.price, mi.category, mi.image_path,
                                        u.restaurant_name, u.id as restaurant_id,
                                        AVG(rr.rating) as avg_rating, COUNT(rr.id) as review_count
                                        FROM favorites f
                                        JOIN menu_items mi ON f.menu_item_id = mi.id
                                        JOIN users u ON mi.restaurant_id = u.id
                                        LEFT JOIN ratings_reviews rr ON mi.id = rr.menu_item_id
                                        WHERE f.customer_id = ? AND f.menu_item_id IS NOT NULL
                                        GROUP BY mi.id''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('favorites.html', favorite_restaurants=favorite_restaurants, 
                         favorite_menu_items=favorite_menu_items)



# Analytics Routes
@app.route('/restaurant_analytics')
@restaurant_required
def restaurant_analytics():
    conn = get_db_connection()
    
    # Get basic stats
    total_orders = conn.execute('SELECT COUNT(*) FROM orders WHERE restaurant_id = ?', 
                               (session['user_id'],)).fetchone()[0]
    
    total_revenue = conn.execute('SELECT COALESCE(SUM(total_amount), 0) FROM orders WHERE restaurant_id = ? AND status = "delivered"', 
                                (session['user_id'],)).fetchone()[0]
    
    avg_order_value = conn.execute('SELECT COALESCE(AVG(total_amount), 0) FROM orders WHERE restaurant_id = ? AND status = "delivered"', 
                                  (session['user_id'],)).fetchone()[0]
    
    # Get orders by status
    orders_by_status = conn.execute('''SELECT status, COUNT(*) as count
                                      FROM orders WHERE restaurant_id = ?
                                      GROUP BY status''', (session['user_id'],)).fetchall()
    
    # Get popular menu items
    popular_items = conn.execute('''SELECT mi.name, mi.price, SUM(oi.quantity) as total_ordered,
                                   SUM(oi.quantity * oi.price) as total_revenue
                                   FROM order_items oi
                                   JOIN menu_items mi ON oi.menu_item_id = mi.id
                                   JOIN orders o ON oi.order_id = o.id
                                   WHERE mi.restaurant_id = ? AND o.status = "delivered"
                                   GROUP BY mi.id
                                   ORDER BY total_ordered DESC
                                   LIMIT 10''', (session['user_id'],)).fetchall()
    
    # Get recent orders
    recent_orders = conn.execute('''SELECT o.*, u.username as customer_username
                                   FROM orders o
                                   JOIN users u ON o.customer_id = u.id
                                   WHERE o.restaurant_id = ?
                                   ORDER BY o.order_date DESC
                                   LIMIT 10''', (session['user_id'],)).fetchall()
    
    # Get average rating
    avg_rating = conn.execute('''SELECT COALESCE(AVG(rating), 0) 
                                FROM ratings_reviews 
                                WHERE restaurant_id = ? AND menu_item_id IS NULL''', 
                             (session['user_id'],)).fetchone()[0]
    
    total_reviews = conn.execute('''SELECT COUNT(*) 
                                   FROM ratings_reviews 
                                   WHERE restaurant_id = ? AND menu_item_id IS NULL''', 
                                (session['user_id'],)).fetchone()[0]
    
    conn.close()
    
    return render_template('restaurant_analytics.html', 
                         total_orders=total_orders,
                         total_revenue=total_revenue,
                         avg_order_value=avg_order_value,
                         orders_by_status=orders_by_status,
                         popular_items=popular_items,
                         recent_orders=recent_orders,
                         avg_rating=avg_rating,
                         total_reviews=total_reviews)

@app.route('/search')
@login_required
def search():
    cuisine_type = request.args.get('cuisine_type', '')
    conn = get_db_connection()
    base_query = '''
        SELECT u.id, u.restaurant_name, u.restaurant_description, u.image_path, u.cuisine_type,
               AVG(rr.rating) as avg_rating, COUNT(rr.id) as review_count
        FROM users u
        LEFT JOIN ratings_reviews rr ON u.id = rr.restaurant_id AND rr.menu_item_id IS NULL
        WHERE u.user_type = 'restaurant'
    '''
    params = []
    if cuisine_type:
        base_query += " AND u.cuisine_type = ?"
        params.append(cuisine_type)
    base_query += " GROUP BY u.id ORDER BY avg_rating DESC NULLS LAST"
    restaurantes = conn.execute(base_query, params).fetchall()
    # Get user favorites
    user_favorites = set()
    if session['user_type'] == 'customer':
        favs = conn.execute('SELECT restaurant_id FROM favorites WHERE customer_id = ? AND menu_item_id IS NULL', (session['user_id'],)).fetchall()
        user_favorites = set(f['restaurant_id'] for f in favs)
    conn.close()
    return render_template('search.html', restaurants=restaurantes, cuisine_type=cuisine_type, user_favorites=user_favorites)

@app.route('/clear_cart')
@login_required
def clear_cart():
    session.pop('cart', None)
    session.modified = True
    flash('Carrinho limpo!')
    return redirect(url_for('customer_dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)