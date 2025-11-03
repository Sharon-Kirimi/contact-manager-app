import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import secrets
import sqlite3
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key-123')
app.config['DATABASE'] = 'contact_app.db'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*")

def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mobile TEXT NOT NULL,
            email TEXT NOT NULL,
            address TEXT NOT NULL,
            registration_number TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, registration_number)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        user_data = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data['id'], user_data['username'], user_data['email'])
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db()
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?', 
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists', 'error')
            conn.close()
        else:
            hashed_password = generate_password_hash(password)
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hashed_password)
            )
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = get_db()
        user_data = conn.execute(
            'SELECT id FROM users WHERE email = ?', (email,)
        ).fetchone()
        
        if user_data:
            token = secrets.token_urlsafe(32)
            conn.execute(
                'INSERT INTO password_resets (email, token) VALUES (?, ?)',
                (email, token)
            )
            conn.commit()
            conn.close()
            
            flash(f'Password reset token: {token}', 'info')
        else:
            conn.close()
            flash('If email exists, reset link will be sent', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db()
    reset_data = conn.execute(
        'SELECT * FROM password_resets WHERE token = ?', (token,)
    ).fetchone()
    
    if not reset_data:
        flash('Invalid token', 'error')
        conn.close()
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        conn.execute(
            'UPDATE users SET password = ? WHERE email = ?',
            (hashed_password, reset_data['email'])
        )
        conn.execute(
            'DELETE FROM password_resets WHERE token = ?', (token,)
        )
        conn.commit()
        conn.close()
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))
    
    conn.close()
    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/add-contact', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        conn = get_db()
        
        existing = conn.execute(
            'SELECT id FROM contacts WHERE user_id = ? AND registration_number = ?',
            (current_user.id, request.form['registration_number'])
        ).fetchone()
        
        if existing:
            flash('Registration number already exists', 'error')
            conn.close()
        else:
            conn.execute(
                '''INSERT INTO contacts 
                (user_id, mobile, email, address, registration_number) 
                VALUES (?, ?, ?, ?, ?)''',
                (current_user.id, request.form['mobile'], request.form['email'], 
                 request.form['address'], request.form['registration_number'])
            )
            conn.commit()
            conn.close()
            flash('Contact added successfully!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('contact_form.html')

@app.route('/search-contact', methods=['GET', 'POST'])
@login_required
def search_contact():
    contact = None
    if request.method == 'POST':
        conn = get_db()
        contact = conn.execute(
            '''SELECT mobile, email, address, registration_number 
            FROM contacts WHERE user_id = ? AND registration_number = ?''',
            (current_user.id, request.form['registration_number'])
        ).fetchone()
        conn.close()
        
        if not contact:
            flash('Contact not found', 'error')
    
    return render_template('search.html', contact=contact)

@app.route('/websocket-demo')
def websocket_demo():
    return render_template('websocket_demo.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    emit('server_response', {'data': 'Connected to WebSocket server'})

@socketio.on('client_message')
def handle_client_message(data):
    emit('server_response', {'data': f'Server received: {data["message"]}'})

@socketio.on('search_contact_ws')
def handle_search_contact_ws(data):
    reg_number = data.get('registration_number')
    if reg_number and current_user.is_authenticated:
        conn = get_db()
        contact = conn.execute(
            '''SELECT mobile, email, address, registration_number 
            FROM contacts WHERE user_id = ? AND registration_number = ?''',
            (current_user.id, reg_number)
        ).fetchone()
        conn.close()
        
        if contact:
            emit('search_result', {
                'found': True,
                'contact': {
                    'mobile': contact['mobile'],
                    'email': contact['email'],
                    'address': contact['address'],
                    'registration_number': contact['registration_number']
                }
            })
        else:
            emit('search_result', {'found': False})

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
