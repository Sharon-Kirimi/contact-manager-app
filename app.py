import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import secrets
from datetime import datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# MongoDB Setup
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
mongo = PyMongo(app)

# Email Setup
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# WebSocket
socketio = SocketIO(app, cors_allowed_origins="*")

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({'_id': user_id})
    return User(user_data) if user_data else None

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = mongo.db.users.find_one({'username': username})
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
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
        
        if mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]}):
            flash('Username or email already exists', 'error')
        else:
            hashed_password = generate_password_hash(password)
            mongo.db.users.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
                'created_at': datetime.utcnow()
            })
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user_data = mongo.db.users.find_one({'email': email})
        
        if user_data:
            token = secrets.token_urlsafe(32)
            mongo.db.password_resets.insert_one({
                'email': email,
                'token': token,
                'created_at': datetime.utcnow()
            })
            
            # For demo purposes, we'll just show the token
            flash(f'Password reset token: {token} (In real app, this would be emailed)', 'info')
        else:
            flash('If email exists, reset link will be sent', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_data = mongo.db.password_resets.find_one({'token': token})
    
    if not reset_data:
        flash('Invalid token', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        mongo.db.users.update_one(
            {'email': reset_data['email']},
            {'$set': {'password': hashed_password}}
        )
        mongo.db.password_resets.delete_one({'token': token})
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/add-contact', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        contact_data = {
            'user_id': current_user.id,
            'mobile': request.form['mobile'],
            'email': request.form['email'],
            'address': request.form['address'],
            'registration_number': request.form['registration_number'],
            'created_at': datetime.utcnow()
        }
        
        if mongo.db.contacts.find_one({
            'user_id': current_user.id,
            'registration_number': contact_data['registration_number']
        }):
            flash('Registration number already exists', 'error')
        else:
            mongo.db.contacts.insert_one(contact_data)
            flash('Contact added successfully!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('contact_form.html')

@app.route('/search-contact', methods=['GET', 'POST'])
@login_required
def search_contact():
    contact = None
    if request.method == 'POST':
        reg_number = request.form['registration_number']
        contact = mongo.db.contacts.find_one({
            'user_id': current_user.id,
            'registration_number': reg_number
        })
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

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('server_response', {'data': 'Connected to WebSocket server'})

@socketio.on('client_message')
def handle_client_message(data):
    emit('server_response', {'data': f'Server received: {data["message"]}'})

@socketio.on('search_contact_ws')
def handle_search_contact_ws(data):
    reg_number = data.get('registration_number')
    if reg_number and current_user.is_authenticated:
        contact = mongo.db.contacts.find_one({
            'user_id': current_user.id,
            'registration_number': reg_number
        })
        if contact:
            emit('search_result', {
                'found': True,
                'contact': {
                    'mobile': contact.get('mobile'),
                    'email': contact.get('email'),
                    'address': contact.get('address'),
                    'registration_number': contact.get('registration_number')
                }
            })
        else:
            emit('search_result', {'found': False})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
