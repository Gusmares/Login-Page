from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_session import Session
import sqlite3
import bcrypt
import uuid
import os

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
Session(app)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        print(f"Tentativa de login: username={username}")  # Log pra debug
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        if result:
            stored_password = result[0]
            print(f"Senha encontrada no banco: {stored_password}")  # Log pra debug
            try:
                if isinstance(stored_password, str):
                    stored_password = stored_password.encode('utf-8')
                if bcrypt.checkpw(password, stored_password):
                    session['username'] = username
                    flash('Login realizado com sucesso!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Senha incorreta.', 'error')
            except Exception as e:
                print(f"Erro no bcrypt: {e}")  # Log pra debug
                flash('Erro ao verificar a senha.', 'error')
        else:
            flash('Usuário não encontrado.', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                          (username, email, hashed_password))
            conn.commit()
            conn.close()
            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuário ou email já existe.', 'error')
    return render_template('signup.html')

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE email = ?', (email,))
        result = cursor.fetchone()
        conn.close()
        if result:
            flash('Um email de recuperação foi enviado (simulação).', 'success')
        else:
            flash('Email não encontrado.', 'error')
    return render_template('recover.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Faça login para acessar o dashboard.', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)