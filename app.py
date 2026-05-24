# ⚠️ ВАЖНО: Удалите старый demochat.db перед запуском!
# DemoChat Server v0.3 - High Security & Stability Edition
import os, re, sqlite3, secrets, time, json, logging, threading, hashlib
from flask import Flask, request, jsonify, send_from_directory, render_template, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from collections import defaultdict
import signal
import sys

# --- Конфигурация ---
LOG_LEVEL = logging.INFO
DB_PATH = 'demochat.db'
DOWNLOAD_FOLDER = os.path.join('static', 'downloads')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
MSG_RETENTION_DAYS = 30
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 30

logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

rate_limit_lock = threading.Lock()
rate_limit_data = defaultdict(list)

PASSWORD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
USERNAME_RE = re.compile(r'^[a-z0-9_]{3,20}$')

def init_db():
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA synchronous=NORMAL;')
            conn.execute('PRAGMA cache_size=-64000;')
            conn.execute('PRAGMA busy_timeout=5000;')
            conn.execute('PRAGMA temp_store=MEMORY;')
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, 
                token_hash TEXT UNIQUE,
                token_created_at REAL DEFAULT 0,
                created_at REAL DEFAULT (cast(strftime('%s', 'now') as real)))''')
            conn.execute('''CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                sender TEXT NOT NULL, 
                recipient TEXT NOT NULL,
                ciphertext TEXT NOT NULL, 
                created_at REAL DEFAULT (cast(strftime('%s', 'now') as real)),
                is_read INTEGER DEFAULT 0)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
                ip TEXT PRIMARY KEY, 
                count INTEGER DEFAULT 0, 
                locked_until REAL DEFAULT 0)''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_msg_recip_time ON messages(recipient, created_at DESC);')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_user_token_hash ON users(token_hash);')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username);')
            conn.commit()
        logger.info("✅ База данных инициализирована (WAL mode)")
    except Exception as e:
        logger.error(f"❌ Ошибка БД: {e}")
        sys.exit(1)

db_local = threading.local()

def get_db():
    if not hasattr(db_local, 'db') or db_local.db is None:
        db_local.db = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        db_local.db.row_factory = sqlite3.Row
        db_local.db.execute('PRAGMA journal_mode=WAL;')
        db_local.db.execute('PRAGMA synchronous=NORMAL;')
        db_local.db.execute('PRAGMA cache_size=-4000;')
        db_local.db.execute('PRAGMA busy_timeout=5000;')
    return db_local.db

@app.teardown_appcontext
def close_db(exception):
    if hasattr(db_local, 'db') and db_local.db:
        db_local.db.close()
        db_local.db = None

def get_client_ip():
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()

def check_rate_limit(ip):
    now = time.time()
    with rate_limit_lock:
        rate_limit_data[ip] = [t for t in rate_limit_data[ip] if now - t < RATE_LIMIT_WINDOW]
        if len(rate_limit_data[ip]) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        rate_limit_data[ip].append(now)
        return True

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({"error": "Отсутствует токен"}), 401
        token = auth[7:]
        token_hash = hash_token(token)
        db = get_db()
        try:
            user = db.execute('SELECT id, username FROM users WHERE token_hash=?', (token_hash,)).fetchone()
            if not user:
                return jsonify({"error": "Недействительный токен"}), 401
            request.user = {'id': user['id'], 'username': user['username']}
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return jsonify({"error": "Ошибка авторизации"}), 500
    return decorated

def ip_lockout_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = get_client_ip()
        if not check_rate_limit(ip):
            return jsonify({"error": "Слишком много запросов"}), 429
        db = get_db()
        att = db.execute('SELECT locked_until FROM login_attempts WHERE ip=?', (ip,)).fetchone()
        if att and att['locked_until'] > time.time():
            wait_time = int(att['locked_until'] - time.time())
            return jsonify({"error": f"IP заблокирован на {wait_time // 60} мин."}), 403
        return f(*args, **kwargs)
    return wrapper

@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self';"
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

def cleanup_old_messages():
    while True:
        try:
            time.sleep(3600)
            cutoff = time.time() - (MSG_RETENTION_DAYS * 86400)
            conn = sqlite3.connect(DB_PATH, timeout=10)
            conn.execute('PRAGMA busy_timeout=5000;')
            res = conn.execute('DELETE FROM messages WHERE created_at < ?', (cutoff,))
            conn.commit()
            if res.rowcount > 0:
                logger.info(f"🗑️ Удалено {res.rowcount} старых сообщений")
            conn.close()
        except Exception as e:
            logger.error(f"Ошибка очистки: {e}")

def cleanup_rate_limit():
    while True:
        time.sleep(300)
        now = time.time()
        with rate_limit_lock:
            keys_to_delete = []
            for ip, times in rate_limit_data.items():
                rate_limit_data[ip] = [t for t in times if now - t < RATE_LIMIT_WINDOW]
                if not rate_limit_data[ip]:
                    keys_to_delete.append(ip)
            for k in keys_to_delete:
                del rate_limit_data[k]

threading.Thread(target=cleanup_old_messages, daemon=True).start()
threading.Thread(target=cleanup_rate_limit, daemon=True).start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    if '..' in filename or '/' in filename or '\\' in filename:
        logger.warning(f"Попытка доступа: {filename}")
        return jsonify({"error": "Доступ запрещён"}), 403
    return send_from_directory(DOWNLOAD_FOLDER, filename, as_attachment=True)

@app.route('/api/register', methods=['POST'])
@ip_lockout_required
def register():
    if not request.is_json:
        return jsonify({"error": "Требуется JSON"}), 400
    data = request.json
    username = data.get('username', '').strip().lstrip('@').lower()
    password = data.get('password', '')
    if not USERNAME_RE.match(username):
        return jsonify({"error": "Юзернейм: 3-20 символов (a-z, 0-9, _)"}), 400
    if not PASSWORD_RE.match(password):
        return jsonify({"error": "Пароль слишком слабый"}), 400
    db = get_db()
    try:
        if db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
            return jsonify({"error": "Юзернейм занят"}), 409
        token = secrets.token_urlsafe(32)
        token_hash = hash_token(token)
        now = time.time()
        db.execute('INSERT INTO users (username, password_hash, token_hash, token_created_at) VALUES (?, ?, ?, ?)',
                   (username, generate_password_hash(password, method='pbkdf2:sha256', salt_length=16), token_hash, now))
        db.commit()
        logger.info(f"✅ Регистрация: @{username}")
        return jsonify({"message": "Аккаунт создан", "token": token}), 201
    except Exception as e:
        logger.error(f"Ошибка регистрации: {e}")
        return jsonify({"error": "Ошибка сервера"}), 500

@app.route('/api/login', methods=['POST'])
@ip_lockout_required
def login():
    ip = get_client_ip()
    data = request.json or {}
    username = data.get('username', '').strip().lstrip('@').lower()
    password = data.get('password', '')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        now = time.time()
        att = db.execute('SELECT count FROM login_attempts WHERE ip=?', (ip,)).fetchone()
        cnt = (att['count'] + 1) if att else 1
        lock_until = now + LOCKOUT_DURATION if cnt >= MAX_LOGIN_ATTEMPTS else 0
        db.execute('INSERT OR REPLACE INTO login_attempts (ip, count, locked_until) VALUES (?, ?, ?)', (ip, cnt, lock_until))
        db.commit()
        left = max(0, MAX_LOGIN_ATTEMPTS - cnt)
        msg = f"Неверные данные." + (f" Осталось попыток: {left}" if left > 0 else " IP заблокирован.")
        return jsonify({"error": msg}), 401
    db.execute('DELETE FROM login_attempts WHERE ip=?', (ip,))
    new_token = secrets.token_urlsafe(32)
    new_token_hash = hash_token(new_token)
    db.execute('UPDATE users SET token_hash=?, token_created_at=? WHERE id=?', (new_token_hash, time.time(), user['id']))
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
    try:
        with db:
            if not db.execute('SELECT id FROM users WHERE username=?', (to,)).fetchone():
                return jsonify({"error": "Пользователь не найден"}), 404
            db.execute('INSERT INTO messages (sender, recipient, ciphertext) VALUES (?, ?, ?)',
                       (request.user['username'], to, text))
        return jsonify({"message": "Отправлено"}), 200
    except Exception as e:
        logger.error(f"Ошибка отправки: {e}")
        return jsonify({"error": "Ошибка при отправке"}), 500

@app.route('/api/messages', methods=['GET'])
@require_auth
def get_messages():
    db = get_db()
    try:
        rows = db.execute('''SELECT sender, ciphertext, created_at FROM messages
                             WHERE recipient=? ORDER BY created_at DESC LIMIT 100''',
                          (request.user['username'],)).fetchall()
        result = [{"sender": r['sender'], "text": r['ciphertext'], "ts": r['created_at']} for r in rows]
        return jsonify(result[::-1])
    except Exception as e:
        logger.error(f"Ошибка получения: {e}")
        return jsonify({"error": "Ошибка загрузки"}), 500

@app.route('/api/users/search', methods=['GET'])
@ip_lockout_required
def search_users():
    q = request.args.get('q', '').strip().lstrip('@').lower()
    if len(q) < 2:
        return jsonify([]), 200
    db = get_db()
    rows = db.execute('SELECT username FROM users WHERE username LIKE ? LIMIT 20', (f'%{q}%',)).fetchall()
    return jsonify([r['username'] for r in rows])

@app.route('/api/status')
def status():
    return jsonify({
        "status": "ok", 
        "version": "0.3-secure", 
        "security": "HSTS+CSP+TokenHash+RateLimit+WAL",
        "uptime": time.time() - app.config.get('START_TIME', time.time())
    })

@app.errorhandler(404)
def not_found(e): 
    return jsonify({"error": "Ресурс не найден"}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Запрос слишком большой"}), 413

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Internal Error: {e}")
    return jsonify({"error": "Внутренняя ошибка сервера"}), 500

def signal_handler(sig, frame):
    logger.info("🛑 Остановка сервера...")
    if hasattr(db_local, 'db') and db_local.db:
        db_local.db.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    app.config['START_TIME'] = time.time()
    init_db()
    logger.info("🚀 DemoChat Secure Server v0.3 запущен: http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
