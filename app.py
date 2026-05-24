# ⚠️ ВАЖНО: Удалите старый demochat.db перед запуском!
import os, re, sqlite3, secrets, time, json, logging, threading
from flask import Flask, request, jsonify, send_from_directory, render_template, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
DOWNLOAD_FOLDER = os.path.join('static', 'downloads')
DB_PATH = 'demochat.db'
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

PASSWORD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900
MSG_RETENTION_DAYS = 30

def init_db():
    with sqlite3.connect(DB_PATH, timeout=5) as conn:
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA synchronous=NORMAL;')
        conn.execute('PRAGMA cache_size=-64000;')
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, token TEXT UNIQUE,
            created_at REAL DEFAULT (cast(strftime('%s', 'now') as real)))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY, sender TEXT NOT NULL, recipient TEXT NOT NULL,
            ciphertext TEXT NOT NULL, created_at REAL DEFAULT (cast(strftime('%s', 'now') as real)))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
            ip TEXT PRIMARY KEY, count INTEGER DEFAULT 0, locked_until REAL DEFAULT 0)''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_msg_recip ON messages(recipient, created_at DESC);')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_msg_time ON messages(created_at);')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_user_token ON users(token);')
        conn.commit()
init_db()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=5)
        g.db.row_factory = sqlite3.Row
        # ✅ ИСПРАВЛЕНО: каждая PRAGMA отдельно
        g.db.execute('PRAGMA journal_mode=WAL;')
        g.db.execute('PRAGMA synchronous=NORMAL;')
        g.db.execute('PRAGMA cache_size=-4000;')
        g.db.execute('PRAGMA busy_timeout=5000;')
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db: db.close()

def get_client_ip():
    return request.headers.get('CF-Connecting-IP') or \
           request.headers.get('X-Real-IP') or \
           request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or \
           request.remote_addr

@app.after_request
def set_security_headers(response):
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    return response

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({"error": "Отсутствует токен"}), 401
        token = auth[7:]
        db = get_db()
        user = db.execute('SELECT id, username FROM users WHERE token=?', (token,)).fetchone()
        if not user:
            return jsonify({"error": "Недействительный токен"}), 401
        request.user = {'id': user['id'], 'username': user['username']}
        return f(*args, **kwargs)
    return decorated

def check_ip_lockout(ip):
    db = get_db()
    att = db.execute('SELECT locked_until FROM login_attempts WHERE ip=?', (ip,)).fetchone()
    return int(att['locked_until'] - time.time()) if att and att['locked_until'] > time.time() else 0

def record_login_attempt(ip, success=False):
    db = get_db()
    if success:
        db.execute('DELETE FROM login_attempts WHERE ip=?', (ip,))
    else:
        now = time.time()
        att = db.execute('SELECT count FROM login_attempts WHERE ip=?', (ip,)).fetchone()
        cnt = (att['count'] + 1) if att else 1
        lock_until = now + LOCKOUT_DURATION if cnt >= MAX_LOGIN_ATTEMPTS else 0
        db.execute('INSERT OR REPLACE INTO login_attempts (ip, count, locked_until) VALUES (?, ?, ?)', (ip, cnt, lock_until))
    db.commit()

def cleanup_old_messages():
    while True:
        try:
            cutoff = time.time() - (MSG_RETENTION_DAYS * 86400)
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                conn.execute('PRAGMA busy_timeout=5000;')
                res = conn.execute('DELETE FROM messages WHERE created_at < ?', (cutoff,))
                if res.rowcount > 0:
                    logger.info(f"🗑️ Удалено {res.rowcount} старых сообщений")
                conn.commit()
        except Exception as e:
            logger.error(f"Ошибка очистки: {e}")
        time.sleep(3600)

threading.Thread(target=cleanup_old_messages, daemon=True).start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    if '..' in filename or '/' in filename or '\\' in filename:
        return jsonify({"error": "Доступ запрещён"}), 404
    return send_from_directory(DOWNLOAD_FOLDER, filename, as_attachment=True)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username', '').strip().lstrip('@').lower()
    password = data.get('password', '')
    if not re.match(r'^[a-z0-9_]{3,20}$', username):
        return jsonify({"error": "Юзернейм: 3-20 символов (a-z, 0-9, _)"}), 400
    if not PASSWORD_RE.match(password):
        return jsonify({"error": "Пароль: мин. 8, A-Z, a-z, 0-9, спецсимвол (!@#$%)"}), 400
    db = get_db()
    if db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
        return jsonify({"error": "Юзернейм занят"}), 409
    token = secrets.token_urlsafe(32)
    db.execute('INSERT INTO users (username, password_hash, token) VALUES (?, ?, ?)',
               (username, generate_password_hash(password, method='pbkdf2:sha256', salt_length=16), token))
    db.commit()
    logger.info(f"✅ Регистрация: @{username}")
    return jsonify({"message": "Аккаунт создан", "token": token}), 201

@app.route('/api/login', methods=['POST'])
def login():
    ip = get_client_ip()
    lockout_sec = check_ip_lockout(ip)
    if lockout_sec > 0:
        return jsonify({"error": f"IP заблокирован. Попробуйте через {lockout_sec // 60} мин."}), 403
    data = request.json or {}
    username = data.get('username', '').strip().lstrip('@').lower()
    password = data.get('password', '')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        record_login_attempt(ip, success=False)
        att = db.execute('SELECT count FROM login_attempts WHERE ip=?', (ip,)).fetchone()
        left = max(0, MAX_LOGIN_ATTEMPTS - (att['count'] if att else 0))
        return jsonify({"error": f"Неверные данные. Осталось попыток: {left}"}), 401
    record_login_attempt(ip, success=True)
    new_token = secrets.token_urlsafe(32)
    db.execute('UPDATE users SET token=? WHERE id=?', (new_token, user['id']))
    db.commit()
    logger.info(f"🔑 Вход: @{username}")
    return jsonify({"message": "Вход выполнен", "token": new_token, "username": username})

@app.route('/api/send', methods=['POST'])
@require_auth
def send_message():
    if not request.is_json:
        return jsonify({"error": "Ожидается JSON"}), 400
    data = request.json
    to = data.get('to', '').strip().lstrip('@').lower()
    text = data.get('text', '').strip()
    if not to or not text:
        return jsonify({"error": "Укажите получателя и текст"}), 400
    if len(text) > 8192:
        return jsonify({"error": "Сообщение >8KB"}), 400
    if to == request.user['username']:
        return jsonify({"error": "Нельзя писать себе"}), 400
    db = get_db()
    if not db.execute('SELECT id FROM users WHERE username=?', (to,)).fetchone():
        return jsonify({"error": "Пользователь не найден"}), 404
    db.execute('INSERT INTO messages (sender, recipient, ciphertext) VALUES (?, ?, ?)',
               (request.user['username'], to, text))
    db.commit()
    return jsonify({"message": "Отправлено"}), 200

@app.route('/api/messages', methods=['GET'])
@require_auth
def get_messages():
    db = get_db()
    rows = db.execute('''SELECT sender, ciphertext, created_at FROM messages
                         WHERE recipient=? ORDER BY created_at DESC LIMIT 100''',
                      (request.user['username'],)).fetchall()
    result = [{"sender": r['sender'], "text": r['ciphertext'], "ts": r['created_at']} for r in rows]
    return jsonify(result[::-1])

@app.route('/api/users/search', methods=['GET'])
def search_users():
    q = request.args.get('q', '').strip().lstrip('@').lower()
    if len(q) < 2:
        return jsonify([]), 200
    db = get_db()
    rows = db.execute('SELECT username FROM users WHERE username LIKE ? LIMIT 20', (f'%{q}%',)).fetchall()
    return jsonify([r['username'] for r in rows])

@app.route('/api/status')
def status():
    return jsonify({"status": "ok", "version": "0.2", "security": "HSTS+CSP+AES+IP-Lockout"})

@app.errorhandler(404)
def not_found(e): return jsonify({"error": "Ресурс не найден"}), 404
@app.errorhandler(500)
def server_error(e):
    logger.error(f"Internal Error: {e}")
    return jsonify({"error": "Внутренняя ошибка сервера"}), 500

if __name__ == '__main__':
    logger.info("🚀 DemoChat Server v0.2 запущен: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, threaded=True, debug=False)
