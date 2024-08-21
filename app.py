from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import os
from dotenv import load_dotenv
import requests
import time

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

API_KEY = os.getenv('ANTHROPIC_API_KEY')
API_URL = 'https://api.anthropic.com/v1/completions'
RATE_LIMIT = 5  # requests per minute

last_request_time = 0

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    chats = db.relationship('Chat', backref='user', lazy='dynamic')

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def make_api_request(prompt, max_tokens):
    global last_request_time
    current_time = time.time()
    if current_time - last_request_time < 60 / RATE_LIMIT:
        time.sleep(60 / RATE_LIMIT - (current_time - last_request_time))

    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
    }
    data = {
        'model': 'claude-v1',
        'prompt': prompt,
        'max_tokens_to_sample': max_tokens,
        'temperature': 0.7,
    }
    response = requests.post(API_URL, json=data, headers=headers)
    last_request_time = time.time()

    if response.status_code == 200:
        return response.json()['completion'].strip()
    else:
        raise Exception(f"API request failed with status code {response.status_code}")

def summarize_text(text):
    prompt = f"Please summarize the following text:\n\n{text}\n\nSummary:"
    return make_api_request(prompt, 300)

def generate_essay(topic):
    prompt = f'Please generate a 500-word essay on the topic of "{topic}".'
    return make_api_request(prompt, 1500)

@app.route('/')
@login_required
def index():
    return render_template('index.html', chats=current_user.chats)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Debug: Check input values during signup
        print(f"Signup attempt: Username={username}, Email={email}")

        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Debug: Verify user creation
        print(f"User created: Username={username}, Email={email}, PasswordHash={hashed_password}")
        
        flash('Signup successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Debug: Check input values during login
        print(f"Login attempt: Username={username}")

        if not username or not password:
            flash('Please provide both username and password.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user:
            # Debug: User found, checking password
            print(f"User found: Username={user.username}, PasswordHash={user.password}")

            if check_password_hash(user.password, password):
                login_user(user)
                flash('Logged in successfully.', 'success')
                print(f"Login successful for user: {username}")
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password.', 'danger')
                print(f"Password check failed for user: {username}")
        else:
            flash('Invalid username or password.', 'danger')
            print(f"User not found: {username}")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/summarize', methods=['POST'])
@login_required
def summarize():
    text = request.form['text']
    try:
        summary = summarize_text(text)
        return jsonify({'summary': summary})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/write_essay', methods=['POST'])
@login_required
def write_essay():
    topic = request.form['topic']
    try:
        essay = generate_essay(topic)
        return jsonify({'essay': essay})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_chat_history/<int:chat_id>')
@login_required
def get_chat_history(chat_id):
    chat = Chat.query.get(chat_id)
    if chat and chat.user == current_user:
        return jsonify({'content': chat.content})
    return jsonify({'error': 'Chat not found'}), 404

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@socketio.on('send_message')
def handle_message(data):
    message = data['message']
    chat_id = data['chat_id']

    chat = Chat.query.get(chat_id)
    if chat and chat.user == current_user:
        chat.content += f"\nUser: {message}"
        db.session.commit()

        try:
            response = make_api_request(f"User: {message}\nAI:", 300)
            chat.content += f"\nAI: {response}"
            db.session.commit()

            emit('receive_message', {'message': response, 'chat_id': chat_id})
        except Exception as e:
            emit('error', {'message': str(e)})

@socketio.on('create_chat')
def handle_create_chat(data):
    title = data['title']
    new_chat = Chat(title=title, content="", user=current_user, timestamp=datetime.utcnow())
    db.session.add(new_chat)
    db.session.commit()
    emit('chat_created', {'id': new_chat.id, 'title': new_chat.title})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
