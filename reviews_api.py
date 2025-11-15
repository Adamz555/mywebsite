import sqlite3
import secrets
import time
from flask import Blueprint, request, jsonify, current_app, g, make_response

bp = Blueprint('reviews_api', __name__, url_prefix='/api/reviews')
DB = 'reviews.db'
CAPTCHA_TTL = 300  # seconds

def get_db():
    db = getattr(g, '_reviews_db', None)
    if db is None:
        db = sqlite3.connect(DB, check_same_thread=False)
        db.row_factory = sqlite3.Row
        g._reviews_db = db
    return db

def init_db():
    db = get_db()
    db.executescript("""
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      text TEXT NOT NULL,
      ts INTEGER NOT NULL,
      client_id TEXT,
      delete_token TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS captchas (
      cid TEXT PRIMARY KEY,
      answer TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_reviews_ts ON reviews(ts DESC);
    """)
    db.commit()

@bp.route('/health', methods=['GET'])
def health():
    return jsonify({'ok': True})

@bp.route('/captcha', methods=['GET'])
def get_captcha():
    """
    Server-side simple math captcha.
    Returns: { cid, question }.
    """
    db = get_db()
    a = secrets.randbelow(8) + 2
    b = secrets.randbelow(8) + 1
    ans = str(a + b)
    cid = secrets.token_hex(12)
    expires = int(time.time()) + CAPTCHA_TTL
    db.execute("INSERT OR REPLACE INTO captchas(cid,answer,expires_at) VALUES (?,?,?)", (cid, ans, expires))
    db.commit()
    return jsonify({'cid': cid, 'question': f"{a} + {b} = ?"}), 200

def verify_captcha(db, cid, answer):
    if not cid:
        return False
    row = db.execute("SELECT answer, expires_at FROM captchas WHERE cid=?",(cid,)).fetchone()
    if not row:
        return False
    if int(time.time()) > row['expires_at']:
        db.execute("DELETE FROM captchas WHERE cid=?", (cid,))
        db.commit()
        return False
    if str(answer).strip() != str(row['answer']).strip():
        return False
    # consume captcha
    db.execute("DELETE FROM captchas WHERE cid=?", (cid,))
    db.commit()
    return True

@bp.route('', methods=['GET'])
def list_reviews():
    """
    GET /api/reviews?limit=200
    Returns: { reviews: [ {id,name,text,ts} ... ] }
    """
    limit = int(request.args.get('limit', '200')[:4]) if request.args.get('limit') else 200
    db = get_db()
    rows = db.execute("SELECT id,name,text,ts FROM reviews ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    reviews = []
    for r in rows:
        reviews.append({'id': r['id'], 'name': r['name'], 'text': r['text'], 'ts': r['ts']})
    return jsonify({'reviews': reviews})

@bp.route('', methods=['POST'])
def create_review():
    """
    Accepts JSON: { name, text, captcha_id, captcha_answer }
    Enforces: name creation requires captcha. One name per client_id cookie.
    Returns created review and a delete_token (store client-side).
    """
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    text = (data.get('text') or '').strip()
    captcha_id = data.get('captcha_id')
    captcha_answer = data.get('captcha_answer')

    if not name:
        return jsonify({'error': 'name required'}), 400
    if not text and data.get('text') is None:
        return jsonify({'error': 'text required'}), 400

    db = get_db()

    # client identification via cookie; create if missing
    client_id = request.cookies.get('aj_client_id')
    if not client_id:
        client_id = secrets.token_hex(16)

    # check if this client already created a name (prevent multiple different names)
    row = db.execute("SELECT name FROM reviews WHERE client_id = ? ORDER BY ts DESC LIMIT 1", (client_id,)).fetchone()
    if row:
        existing_name = row['name']
        if existing_name != name:
            return jsonify({'error': 'This device/client already has a name set. Use the same name or reset locally.'}), 403

    # require captcha for creating a name (if client has no existing name)
    if not row:
        if not verify_captcha(db, captcha_id, captcha_answer):
            return jsonify({'error': 'captcha failed'}), 400

    # create review with server-generated delete_token
    delete_token = secrets.token_urlsafe(24)
    ts = int(time.time())
    cur = db.execute("INSERT INTO reviews(name, text, ts, client_id, delete_token) VALUES (?,?,?,?,?)",
                     (name, text, ts, client_id, delete_token))
    db.commit()
    review_id = cur.lastrowid

    # set client cookie so same client is recognized later
    resp = make_response(jsonify({'id': review_id, 'delete_token': delete_token, 'name': name, 'text': text, 'ts': ts}), 201)
    resp.set_cookie('aj_client_id', client_id, httponly=True, samesite='Lax')
    return resp

@bp.route('/<int:rid>', methods=['DELETE'])
def delete_review(rid):
    """
    Delete requires JSON body: { delete_token: '...' } OR cookie client match.
    If delete_token matches stored token, delete. Otherwise if request has same client_id cookie as stored, allow delete.
    """
    data = request.get_json(force=True) or {}
    token = data.get('delete_token')
    db = get_db()
    row = db.execute("SELECT delete_token, client_id FROM reviews WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404

    # check delete_token
    if token and secrets.compare_digest(token, row['delete_token']):
        db.execute("DELETE FROM reviews WHERE id=?", (rid,))
        db.commit()
        return jsonify({'ok': True}), 200

    # otherwise check client cookie
    client_id = request.cookies.get('aj_client_id')
    if client_id and client_id == row['client_id']:
        db.execute("DELETE FROM reviews WHERE id=?", (rid,))
        db.commit()
        return jsonify({'ok': True}), 200

    return jsonify({'error': 'unauthorized'}), 403

def init_reviews(app):
    app.register_blueprint(bp)
    # initialize DB on app start
    with app.app_context():
        init_db()
