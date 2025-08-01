from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from datetime import datetime
import os
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev_key_' + ''.join(
    random.choices(string.ascii_letters + string.digits, k=16))
app.config['DATABASE'] = os.environ.get('DATABASE') or 'vexa.db'

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                server_id TEXT NOT NULL,
                FOREIGN KEY (server_id) REFERENCES servers (id)
            )''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                channel_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (channel_id) REFERENCES channels (id)
            )''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS server_members (
                user_id INTEGER NOT NULL,
                server_id TEXT NOT NULL,
                rank TEXT NOT NULL DEFAULT 'member',
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (server_id) REFERENCES servers (id),
                PRIMARY KEY (user_id, server_id)
            )''')
        db.commit()

init_db()

def generate_id(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

@app.template_filter('format_time')
def format_time_filter(timestamp):
    if isinstance(timestamp, str):
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.strftime('%H:%M')
        except ValueError:
            return timestamp
    elif isinstance(timestamp, datetime):
        return timestamp.strftime('%H:%M')
    return str(timestamp)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            flash('Kullanıcı adı ve şifre gereklidir')
            return redirect(url_for('register'))

        try:
            db = get_db()
            db.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            flash('Kayıt başarılı. Giriş yapabilirsiniz.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Bu kullanıcı adı zaten alınmış')

    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('home'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre')

    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        servers = db.execute('''
            SELECT s.id, s.name, u.username as owner 
            FROM servers s
            JOIN users u ON s.owner_id = u.id
        ''').fetchall()
        return render_template('home.html', servers=servers)
    finally:
        db.close()

@app.route('/create_server', methods=['POST'])
def create_server():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    server_name = request.form.get('server_name', '').strip()
    if server_name:
        server_id = generate_id()
        db = get_db()
        try:
            db.execute(
                'INSERT INTO servers (id, name, owner_id) VALUES (?, ?, ?)',
                (server_id, server_name, session['user_id'])
            )
            db.execute(
                'INSERT INTO server_members (user_id, server_id, rank) VALUES (?, ?, ?)',
                (session['user_id'], server_id, 'owner')
            )
            db.execute(
                'INSERT INTO channels (id, name, type, server_id) VALUES (?, ?, ?, ?)',
                ('genel', 'genel', 'text', server_id)
            )
            db.execute(
                'INSERT INTO channels (id, name, type, server_id) VALUES (?, ?, ?, ?)',
                ('ses', 'sesli-sohbet', 'voice', server_id)
            )
            db.commit()
        finally:
            db.close()

    return redirect(url_for('home'))

@app.route('/server/<server_id>')
def server(server_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        server = db.execute(
            '''SELECT s.id, s.name, s.owner_id, u.username as owner 
               FROM servers s JOIN users u ON s.owner_id = u.id 
               WHERE s.id = ?''',
            (server_id,)
        ).fetchone()

        if not server:
            return redirect(url_for('home'))

        members = db.execute('''
            SELECT u.id as user_id, u.username, sm.rank 
            FROM server_members sm
            JOIN users u ON sm.user_id = u.id
            WHERE sm.server_id = ?
            UNION
            SELECT id as user_id, username, 'owner' as rank
            FROM users WHERE id = ?
        ''', (server_id, server['owner_id'])).fetchall()

        is_owner_or_admin = False
        if session['user_id'] == server['owner_id']:
            is_owner_or_admin = True
        else:
            user_rank = db.execute(
                'SELECT rank FROM server_members WHERE user_id = ? AND server_id = ?',
                (session['user_id'], server_id)
            ).fetchone()
            if user_rank and user_rank['rank'] in ['admin', 'owner']:
                is_owner_or_admin = True

        channels = db.execute(
            'SELECT * FROM channels WHERE server_id = ?', (server_id,)
        ).fetchall()

        return render_template('server.html',
                               server=server,
                               channels=channels,
                               members=members,
                               is_owner_or_admin=is_owner_or_admin)
    finally:
        db.close()

@app.route('/server/<server_id>/create_channel', methods=['POST'])
def create_channel(server_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        server = db.execute(
            'SELECT owner_id FROM servers WHERE id = ?',
            (server_id,)
        ).fetchone()

        if not server:
            flash('Sunucu bulunamadı')
            return redirect(url_for('home'))

        if session['user_id'] != server['owner_id']:
            member = db.execute(
                'SELECT rank FROM server_members WHERE user_id = ? AND server_id = ?',
                (session['user_id'], server_id)
            ).fetchone()

            if not member or member['rank'] not in ['admin', 'owner']:
                flash('Bu işlem için yetkiniz yok')
                return redirect(url_for('server', server_id=server_id))

        channel_name = request.form.get('channel_name', '').strip().lower()
        channel_type = request.form.get('channel_type', 'text')

        if channel_name:
            channel_id = channel_name.replace(' ', '-')
            db.execute(
                'INSERT INTO channels (id, name, type, server_id) VALUES (?, ?, ?, ?)',
                (channel_id, channel_name, channel_type, server_id)
            )
            db.commit()
            flash('Kanal başarıyla oluşturuldu')

    except sqlite3.Error as e:
        flash('Veritabanı hatası: ' + str(e))
    finally:
        db.close()

    return redirect(url_for('server', server_id=server_id))

@app.route('/server/<server_id>/set_rank', methods=['POST'])
def set_rank(server_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    target_user = request.form.get('user_id')
    new_rank = request.form.get('rank')

    if not target_user or not new_rank:
        flash('Geçersiz istek')
        return redirect(url_for('server', server_id=server_id))

    db = get_db()
    try:
        server = db.execute(
            'SELECT owner_id FROM servers WHERE id = ?',
            (server_id,)
        ).fetchone()

        if not server or session['user_id'] != server['owner_id']:
            flash('Bu işlem için yetkiniz yok')
            return redirect(url_for('server', server_id=server_id))

        db.execute(
            '''INSERT OR REPLACE INTO server_members 
               (user_id, server_id, rank) VALUES (?, ?, ?)''',
            (target_user, server_id, new_rank)
        )
        db.commit()
        flash('Rank başarıyla güncellendi')

    except sqlite3.Error as e:
        flash('Veritabanı hatası: ' + str(e))
    finally:
        db.close()

    return redirect(url_for('server', server_id=server_id))

@app.route('/server/<server_id>/add_member', methods=['POST'])
def add_member(server_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    username = request.form.get('username')
    if not username:
        flash('Kullanıcı adı gerekli')
        return redirect(url_for('server', server_id=server_id))

    db = get_db()
    try:
        server = db.execute(
            'SELECT owner_id FROM servers WHERE id = ?',
            (server_id,)
        ).fetchone()

        if not server or session['user_id'] != server['owner_id']:
            flash('Bu işlem için yetkiniz yok')
            return redirect(url_for('server', server_id=server_id))

        user = db.execute(
            'SELECT id FROM users WHERE username = ?',
            (username,)
        ).fetchone()

        if not user:
            flash('Kullanıcı bulunamadı')
            return redirect(url_for('server', server_id=server_id))

        db.execute(
            'INSERT OR IGNORE INTO server_members (user_id, server_id, rank) VALUES (?, ?, ?)',
            (user['id'], server_id, 'member')
        )
        db.commit()
        flash('Kullanıcı başarıyla eklendi')

    except sqlite3.Error as e:
        flash('Veritabanı hatası: ' + str(e))
    finally:
        db.close()

    return redirect(url_for('server', server_id=server_id))

@app.route('/server/<server_id>/channel/<channel_id>')
def channel(server_id, channel_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        server = db.execute(
            'SELECT id, name, owner_id FROM servers WHERE id = ?', (server_id,)
        ).fetchone()

        if not server:
            return redirect(url_for('home'))

        is_member = False
        if session['user_id'] == server['owner_id']:
            is_member = True
        else:
            member = db.execute(
                'SELECT 1 FROM server_members WHERE user_id = ? AND server_id = ?',
                (session['user_id'], server_id)
            ).fetchone()
            if member:
                is_member = True

        if not is_member:
            flash('Bu sunucuya erişim izniniz yok')
            return redirect(url_for('home'))

        channels = db.execute(
            'SELECT id, name, type FROM channels WHERE server_id = ?', (server_id,)
        ).fetchall()

        current_channel = db.execute(
            'SELECT id, name, type FROM channels WHERE id = ? AND server_id = ?',
            (channel_id, server_id)
        ).fetchone()

        if not current_channel:
            return redirect(url_for('server', server_id=server_id))

        messages = db.execute('''
            SELECT m.content, m.timestamp, u.username 
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.channel_id = ?
            ORDER BY m.timestamp DESC
            LIMIT 50
        ''', (channel_id,)).fetchall()

        return render_template('channel.html',
                               server=dict(server),
                               server_id=server_id,
                               channels=[dict(ch) for ch in channels],
                               current_channel=dict(current_channel),
                               messages=list(reversed(messages)))
    finally:
        db.close()

@socketio.on('join')
def handle_join(data):
    if 'user_id' not in session:
        return

    server_id = data.get('server_id')
    channel_id = data.get('channel_id')

    if server_id and channel_id:
        room = f"{server_id}_{channel_id}"
        join_room(room)
        emit('system_message', {
            'text': f"{session['username']} sohbete katıldı",
            'timestamp': datetime.now().strftime('%H:%M')
        }, room=room)

@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return

    server_id = data.get('server_id')
    channel_id = data.get('channel_id')
    content = data.get('content', '').strip()[:2000]

    if server_id and channel_id and content:
        room = f"{server_id}_{channel_id}"
        message_id = generate_id(12)
        db = get_db()
        try:
            db.execute(
                'INSERT INTO messages (id, content, user_id, channel_id) VALUES (?, ?, ?, ?)',
                (message_id, content, session['user_id'], channel_id)
            )
            db.commit()
            emit('new_message', {
                'id': message_id,
                'content': content,
                'username': session['username'],
                'timestamp': datetime.now().strftime('%H:%M')
            }, room=room)
        finally:
            db.close()

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        emit('system_message', {
            'text': f"{session['username']} sohbetten ayrıldı",
            'timestamp': datetime.now().strftime('%H:%M')
        })

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
