#!/bin/sh
# Ready-to-paste single script — creates/overwrites necessary files to add a secure server-backed Reviews system.
# Paste this whole script into Termux or your server shell and run it (sh ./setup_reviews.sh).
# It will create: reviews_api.py, app.py (full Flask app), templates/index.html (updated), templates/base.html (if missing), templates/* dirs and static dirs.
# At the end it launches Flask (development server). If you prefer not to run automatically, remove the last two lines.

set -e

# ensure project directories
mkdir -p ~/mywebsite/templates ~/mywebsite/static/css ~/mywebsite/static/images
cd ~/mywebsite

##########
# reviews_api.py
##########
cat > reviews_api.py <<'PY'
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
PY

##########
# app.py (main Flask app)
##########
cat > app.py <<'PY'
from flask import Flask, render_template, send_from_directory, jsonify
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

# routes (main site)
@app.route('/')
def index():
    return render_template('index.html', title="AJMAL ADAM Blockchain Research & Technologies")

@app.route('/about')
def about():
    return render_template('about.html', title="About | Ajmal Adam")

@app.route('/research')
def research():
    return render_template('research.html', title="Research | Ajmal Adam")

@app.route('/knowledge')
def knowledge():
    return render_template('knowledge.html', title="History of Blockchain | Ajmal Adam")

@app.route('/blockchain-basic')
def blockchain_basic():
    return render_template('blockchain_basic.html', title="Blockchain Basic | Ajmal Adam")

@app.route('/contact')
def contact():
    return render_template('contact.html', title="Contact | Ajmal Adam")

@app.route('/labs')
def labs():
    return render_template('labs.html', title="🧪 Labs | Ajmal Adam Research")

# register reviews API
try:
    import reviews_api
    reviews_api.init_reviews(app)
except Exception as e:
    # if initialization fails, still run site; /api/reviews will be unavailable
    print("reviews_api init error:", e)

if __name__ == '__main__':
    # development server (bind to all local interfaces)
    app.run(host='0.0.0.0', port=8080)
PY

##########
# templates/index.html (updated: review modal uses server API with captcha; fallback to client-only if server down)
##########
cat > templates/index.html <<'HTML'
{% extends "base.html" %}
{% block content %}

<!-- Labs pill shown at top of content area -->
<div class="container nav-pill-row" style="max-width:980px; margin:8px auto 0; padding:0 12px;">
  <div class="nav-links-row">
    <a class="btn btn-ghost" href="{{ url_for('labs') }}">🧪 Labs</a>
  </div>
</div>

<section class="hero">
  <div class="hero-inner">
    <h1 class="hero-title">Explore Blockchain & Smart Contracts</h1>
    <p class="hero-subtitle">We build knowledge around smart contracts, security audits, and research that bridges blockchain with space innovation.</p>
    <div class="cta-row">
      <a class="btn btn-primary" href="{{ url_for('blockchain_basic') }}">Blockchain Basic</a>
      <a class="btn btn-ghost" href="javascript:void(0)" onclick="openReview()">Review</a>
    </div>
  </div>
</section>

<div class="home-cards" id="cards-root">
  <div class="card" style="cursor:pointer" onclick="showDetail('ai')">
    <h2>Ai Agents</h2>
    <p>Autonomous on-chain/off-chain agents that monitor, act and optimise smart contract systems.</p>
  </div>

  <div class="card" style="cursor:pointer" onclick="showDetail('multisign')">
    <h2>Multisign</h2>
    <p>Multi-signature wallets and workflows for safer treasury and admin operations.</p>
  </div>

  <div class="card" style="cursor:pointer" onclick="showDetail('dao')">
    <h2>DAO</h2>
    <p>Decentralized Autonomous Organizations — governance, treasury, and community coordination.</p>
  </div>

  <div class="card" style="cursor:pointer" onclick="showDetail('future')">
    <h2>Future of Blockchain Technology</h2>
    <p>Trends: Ai integration, ZK privacy, cross-chain, tokenization, and space-grade deployments.</p>
  </div>
</div>

<div id="detail-root" style="margin-top:18px; display:none;">
  <div class="card" id="detail-ai" style="display:none;">
    <a href="javascript:void(0)" onclick="hideDetail()" style="float:right; color:var(--muted); text-decoration:none;">Back</a>
    <h2>Ai Agents — Autonomous Intelligent Agents</h2>
    <p style="color:var(--muted);">Ai Agents are software entities that observe data, make decisions, and act — optionally interacting with blockchains or smart contracts. They can automate monitoring, on-chain operations, trading strategies, security scanning and governance helpers.</p>
  </div>

  <div class="card" id="detail-multisign" style="display:none;">
    <a href="javascript:void(0)" onclick="hideDetail()" style="float:right; color:var(--muted); text-decoration:none;">Back</a>
    <h2>Multisign — Multi-signature Security</h2>
    <p style="color:var(--muted);">Multisig requires multiple independent signatures to authorize transactions. It is widely used to secure treasuries, protect admin privileges, and ensure collective control over funds.</p>
  </div>

  <div class="card" id="detail-dao" style="display:none;">
    <a href="javascript:void(0)" onclick="hideDetail()" style="float:right; color:var(--muted); text-decoration:none;">Back</a>
    <h2>DAO — Decentralized Autonomous Organization</h2>
    <p style="color:var(--muted);">A DAO is an on-chain governed collective where rules and treasury actions are enforced by smart contracts. Members propose and vote; successful proposals execute automatically when conditions are met.</p>
  </div>

  <div class="card" id="detail-future" style="display:none;">
    <a href="javascript:void(0)" onclick="hideDetail()" style="float:right; color:var(--muted); text-decoration:none;">Back</a>
    <h2>Future of Blockchain Technology</h2>
    <p style="color:var(--muted);">The near future blends privacy (ZK), Ai, cross-chain interoperability, tokenization of real-world assets, and niche domains like space-grade decentralized systems — producing richer, privacy-preserving and highly interconnected infrastructures.</p>
  </div>
</div>

<div class="latest">
  <h2>Latest</h2>
  <p class="muted">Updates and short notes will appear here.</p>
</div>

<!-- REVIEW MODAL -->
<div id="review-modal" style="display:none; position:fixed; inset:0; z-index:9999; justify-content:center; align-items:center; background:rgba(0,0,0,0.6);">
  <div style="width:92%; max-width:520px; background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; box-shadow:var(--shadow); color:var(--text);">

    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h3 style="margin:0; font-size:16px;">Write Your Review</h3>
      <button onclick="closeReview()" style="background:transparent;border:none;color:var(--muted);font-size:18px;cursor:pointer;">✕</button>
    </div>

    <p style="margin:8px 0 12px; color:var(--muted); font-size:13px;">Type your name once (saved to this browser/device), then write your review. Captcha required to create a name.</p>

    <input id="review-name" placeholder="Type your name" style="width:100%; padding:10px; border-radius:8px; background:transparent; color:var(--text); border:1px solid rgba(255,255,255,0.04);">
    <div id="review-name-note" style="font-size:13px; color:var(--muted); margin-top:8px;">You can set name only once on this browser/device. (Server recognizes the same browser via a cookie.)</div>

    <div id="rv-captcha-row" style="display:flex; gap:8px; margin-top:10px; align-items:center;">
      <div id="rv-captcha-question" style="color:var(--muted); font-size:13px;">&nbsp;</div>
      <input id="rv-captcha-answer" placeholder="Answer" style="padding:8px; border-radius:8px; background:transparent; color:var(--text); border:1px solid rgba(255,255,255,0.04); width:120px;">
      <button id="rv-new-captcha" onclick="fetchCaptcha()" style="padding:8px; border-radius:8px; border:1px solid var(--border); background:transparent; color:var(--text);">New</button>
    </div>

    <textarea id="review-text" rows="4" placeholder="Write your review..." style="width:100%; padding:10px; border-radius:8px; margin-top:12px; background:transparent; color:var(--text); border:1px solid rgba(255,255,255,0.04);"></textarea>

    <div style="display:flex; gap:8px; margin-top:12px;">
      <button id="rv-publish" onclick="submitReview()" style="flex:1; padding:10px; border-radius:8px; background:linear-gradient(135deg,#6a5cff,#2ad1ff); color:#041028; font-weight:700; border:none;">Add your review</button>
      <button onclick="resetReviewName()" style="padding:10px; border-radius:8px; border:1px solid var(--border); background:transparent; color:var(--text);">Reset name</button>
    </div>

    <div id="review-list" style="margin-top:12px; max-height:300px; overflow:auto;"></div>
  </div>
</div>

<script>
/* Client logic: uses server API when available; falls back to client-only storage if server unreachable */
const API_BASE = '/api/reviews';
const NAME_KEY = 'aj_name_v1';
const REV_FALLBACK_KEY = 'aj_reviews_v1_local';
let serverAvailable = null;
let currentCaptchaId = null;

function showDetail(id){
  document.getElementById('cards-root').style.display='none';
  document.getElementById('detail-root').style.display='block';
  ['ai','multisign','dao','future'].forEach(k=>{
    document.getElementById('detail-'+k).style.display = (k===id?'block':'none');
  });
  window.scrollTo({top:0,behavior:'smooth'});
}
function hideDetail(){
  document.getElementById('detail-root').style.display='none';
  document.getElementById('cards-root').style.display='grid';
  window.scrollTo({top:0,behavior:'smooth'});
}

function openReview(){
  loadNameState();
  detectServerThenLoad();
  document.getElementById('review-modal').style.display='flex';
}
function closeReview(){ document.getElementById('review-modal').style.display='none'; }

function loadNameState(){
  const name = localStorage.getItem(NAME_KEY);
  const input = document.getElementById('review-name');
  const note = document.getElementById('review-name-note');
  if(name){ input.value = name; input.disabled = true; note.innerText = 'Name saved: ' + name; }
  else { input.value=''; input.disabled=false; note.innerText = 'You can set name only once on this browser/device.'; }
}

async function detectServerThenLoad(){
  try{
    const r = await fetch(API_BASE + '/health', {cache:'no-store'});
    if(r.ok){ serverAvailable = true; await fetchCaptcha(); await loadServerReviews(); return; }
  }catch(e){}
  try{
    const r = await fetch(API_BASE + '?limit=1', {cache:'no-store'});
    if(r.ok){ serverAvailable = true; await fetchCaptcha(); await loadServerReviews(); return; }
  }catch(e){}
  serverAvailable = false;
  fetchCaptchaFallback();
  loadFallbackReviews();
}

/* CAPTCHA */
async function fetchCaptcha(){
  if(!serverAvailable){ return fetchCaptchaFallback(); }
  try{
    const r = await fetch(API_BASE + '/captcha', {cache:'no-store'});
    if(!r.ok) throw new Error('no captcha');
    const j = await r.json();
    currentCaptchaId = j.cid || null;
    document.getElementById('rv-captcha-question').innerText = j.question || '';
    document.getElementById('rv-captcha-question').dataset.cid = currentCaptchaId || '';
  }catch(e){
    serverAvailable = false;
    fetchCaptchaFallback();
  }
}
function fetchCaptchaFallback(){
  const a = Math.floor(Math.random()*8)+2;
  const b = Math.floor(Math.random()*8)+1;
  currentCaptchaId = 'fallback';
  document.getElementById('rv-captcha-question').innerText = `${a} + ${b} = ?`;
  document.getElementById('rv-captcha-question').dataset.ans = String(a+b);
  document.getElementById('rv-captcha-question').dataset.cid = 'fallback';
}

/* Submit review */
async function submitReview(){
  const nameInput = document.getElementById('review-name');
  let name = localStorage.getItem(NAME_KEY);
  if(!name){
    if(!nameInput.value.trim()){ alert('Type your name'); return; }
    // require captcha to create name
    const cid = document.getElementById('rv-captcha-question').dataset.cid || '';
    const ans = document.getElementById('rv-captcha-answer').value.trim();
    if(!ans){ alert('Please answer captcha'); return; }
    // attempt server creation of name if server available
    if(serverAvailable){
      try{
        const res = await fetch(API_BASE, {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ name: nameInput.value.trim(), text: "", captcha_id: cid, captcha_answer: ans })
        });
        const j = await res.json();
        if(!res.ok){ alert(j.error || 'Server refused'); return; }
        // server accepted name creation (text empty) — store locally name
        localStorage.setItem(NAME_KEY, nameInput.value.trim());
        name = nameInput.value.trim();
        loadNameState();
        // after name creation, fetch latest reviews
        await loadServerReviews();
      }catch(e){ alert('Network/server error creating name'); serverAvailable=false; fetchCaptchaFallback(); return; }
    } else {
      // fallback client-side captcha verify
      const expected = document.getElementById('rv-captcha-question').dataset.ans;
      if(String(ans) !== String(expected)){ alert('Captcha wrong'); return; }
      localStorage.setItem(NAME_KEY, nameInput.value.trim());
      name = nameInput.value.trim();
      loadNameState();
    }
  }

  // now have name — submit review text
  const text = document.getElementById('review-text').value.trim();
  if(!text){ alert('Write review'); return; }

  document.getElementById('rv-publish').disabled = true;
  try{
    if(serverAvailable){
      const cid = document.getElementById('rv-captcha-question').dataset.cid || '';
      const ans = document.getElementById('rv-captcha-answer').value.trim();
      const res = await fetch(API_BASE, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ name, text, captcha_id: cid, captcha_answer: ans })
      });
      const j = await res.json();
      if(!res.ok){ alert(j.error || 'Publish failed'); serverAvailable=false; fetchCaptchaFallback(); return; }
      // server returns delete_token and id; save delete_token map
      if(j.delete_token && j.id){
        const map = JSON.parse(localStorage.getItem('aj_delete_map')||'{}');
        map[String(j.id)] = j.delete_token;
        localStorage.setItem('aj_delete_map', JSON.stringify(map));
      }
      document.getElementById('review-text').value = '';
      await loadServerReviews();
      await fetchCaptcha();
    } else {
      // fallback store locally
      const arr = JSON.parse(localStorage.getItem(REV_FALLBACK_KEY) || '[]');
      const rec = { id: Date.now(), name, text, ts: Date.now() };
      arr.unshift(rec);
      localStorage.setItem(REV_FALLBACK_KEY, JSON.stringify(arr.slice(0,500)));
      document.getElementById('review-text').value = '';
      loadFallbackReviews();
    }
  }catch(e){ console.error(e); alert('Error publishing'); }
  finally{ document.getElementById('rv-publish').disabled = false; }
}

/* load reviews */
async function loadServerReviews(){
  try{
    const r = await fetch(API_BASE + '?limit=200', {cache:'no-store'});
    if(!r.ok) throw new Error('no list');
    const j = await r.json();
    renderReviews(j.reviews || []);
  }catch(e){
    serverAvailable = false;
    loadFallbackReviews();
  }
}
function loadFallbackReviews(){
  const arr = JSON.parse(localStorage.getItem(REV_FALLBACK_KEY) || '[]');
  renderReviews(arr);
}

/* render */
function renderReviews(reviews){
  const root = document.getElementById('review-list');
  root.innerHTML = '';
  if(!reviews || !reviews.length){
    root.innerHTML = '<div style="color:var(--muted);font-size:13px;">No reviews yet.</div>';
    return;
  }
  const deleteMap = JSON.parse(localStorage.getItem('aj_delete_map')||'{}');
  const myName = localStorage.getItem(NAME_KEY);
  reviews.forEach(r=>{
    const id = r.id || r.ts || Date.now();
    const ts = r.ts || Date.now();
    const name = escapeHtml(r.name || 'Anon');
    const text = escapeHtml(r.text || '');
    const timeStr = new Date(ts).toLocaleString();
    // allow delete if we have a delete token or local name matches (fallback)
    const token = deleteMap[String(id)];
    let canDelete = false;
    if(token) canDelete = true;
    if(!serverAvailable && myName && myName === r.name) canDelete = true;
    const deleteButton = canDelete ? `<button data-id="${id}" class="rv-delete" style="margin-top:8px;padding:6px;border-radius:6px;background:transparent;border:1px solid var(--border);color:var(--text);">Delete</button>` : '';
    root.insertAdjacentHTML('beforeend',
      `<div style="padding:10px;border-radius:8px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.03);margin-bottom:8px;">
        <div style="display:flex;justify-content:space-between;gap:8px;">
          <div style="font-weight:700;color:var(--accent-2);">${name}</div>
          <div style="font-size:12px;color:var(--muted);">${timeStr}</div>
        </div>
        <div style="margin-top:6px;color:var(--muted);white-space:pre-wrap;">${text}</div>
        <div>${deleteButton}</div>
      </div>`
    );
  });

  // wire deletes
  Array.from(document.querySelectorAll('.rv-delete')).forEach(btn=>{
    btn.addEventListener('click', onDeleteClick);
  });
}

/* delete */
async function onDeleteClick(ev){
  const id = ev.currentTarget.getAttribute('data-id');
  if(!confirm('Delete this review?')) return;
  const map = JSON.parse(localStorage.getItem('aj_delete_map')||'{}');
  const token = map[String(id)];
  if(serverAvailable && token){
    try{
      const res = await fetch(API_BASE + '/' + encodeURIComponent(id), {
        method: 'DELETE',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ delete_token: token })
      });
      const j = await res.json();
      if(!res.ok){ alert(j.error || 'Delete failed'); return; }
      delete map[String(id)];
      localStorage.setItem('aj_delete_map', JSON.stringify(map));
      await loadServerReviews();
      return;
    }catch(e){ alert('Network error'); return; }
  }
  if(!serverAvailable){
    const arr = JSON.parse(localStorage.getItem(REV_FALLBACK_KEY)||'[]');
    const name = localStorage.getItem(NAME_KEY);
    const idx = arr.findIndex(x=>String(x.id) === String(id));
    if(idx === -1){ alert('Not found'); return; }
    if(name && arr[idx].name !== name){ alert('You can only delete your own review on this device'); return; }
    arr.splice(idx,1);
    localStorage.setItem(REV_FALLBACK_KEY, JSON.stringify(arr));
    loadFallbackReviews();
    return;
  }
  alert('Cannot delete: no token or unauthorized.');
}

/* helpers */
function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, function(m){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]; }); }
document.getElementById('rv-new-captcha').addEventListener('click', function(e){ fetchCaptcha(); });

</script>

{% endblock %}
HTML

##########
# ensure minimal base.html exists (if user already has it, do not overwrite)
##########
if [ ! -f templates/base.html ]; then
cat > templates/base.html <<'BHTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>{{ title or "AJMAL ADAM Blockchain Research & Technologies" }}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
</head>
<body style="background: linear-gradient(180deg, #0b1a2a 0%, #04070c 100%);
      background-attachment: fixed;
      color: #e0e6ed;
      margin: 0;
      min-height: 100vh;">

<header class="nav">
  <div class="container nav-inner">
    <div class="brand-block">
      <div class="brand-left">
        <div class="brand-badge" aria-hidden="true"></div>
        <div class="brand-text">
          <a href="{{ url_for('index') }}" style="text-decoration:none; color:inherit;">
            <div class="brand-line">AJMAL ADAM</div>
            <div class="brand-line small">Blockchain Research & Technologies</div>
          </a>
        </div>
      </div>
    </div>

    <nav class="nav-links">
      <a class="nav-link" href="{{ url_for('about') }}">About Developer</a>
      <a class="nav-link" href="{{ url_for('research') }}">Research Files</a>
      <a class="nav-link" href="{{ url_for('knowledge') }}">History of Blockchain</a>
      <a class="nav-link" href="{{ url_for('contact') }}">Contact</a>
    </nav>
  </div>
</header>

<main class="container">
  {% block content %}{% endblock %}
</main>

<footer class="footer" style="font-size:11px;">
  © {{ 2025 }} Ajmal Adam Software Company. All rights reserved.
</footer>

</body>
</html>
BHTML
fi

##########
# create placeholder styles if missing (won't override if exists)
##########
if [ ! -f static/css/styles.css ]; then
cat > static/css/styles.css <<'CSS'
:root{
  --bg:#0f141a; --panel:#151b23; --panel-2:#0e1220; --border:#202733;
  --text:#e5e7eb; --muted:#9aa0a6; --accent:#4b9fff; --accent-2:#6a5cff;
  --radius:12px; --shadow: 0 6px 20px rgba(0,0,0,.35);
}
*{box-sizing:border-box}
body{font-family:Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial; color:var(--text); background:var(--bg);}
main.container{ max-width:980px; margin:18px auto; padding:0 12px }
.brand-badge{ width:16px; height:32px; border-radius:8px; background: linear-gradient(135deg, var(--accent-2) 0%, var(--accent) 100%); }
.hero-inner{ padding:20px; border-radius:var(--radius); background:linear-gradient(180deg,var(--panel),var(--panel-2)); border:1px solid var(--border); }
.btn{ padding:8px 14px; border-radius:10px; font-weight:600; text-decoration:none; }
.btn-primary{ background: linear-gradient(135deg, #6a5cff 0%, #2ad1ff 100%); color:#0a0f16; border:none; }
.btn-ghost{ background:transparent; color:var(--text); border:1px solid rgba(255,255,255,0.04); }
.card{ background:var(--panel); padding:16px; border-radius:12px; border:1px solid var(--border); box-shadow:var(--shadow); }
CSS
fi

##########
# ensure other templates exist to avoid errors (minimal placeholders if missing)
##########
for t in about research knowledge blockchain_basic contact labs; do
  if [ ! -f templates/${t}.html ]; then
    cat > templates/${t}.html <<THTML
{% extends "base.html" %}
{% block content %}
<section class="section">
  <div class="card"><h2>${t}</h2><p style="color:var(--muted)">Placeholder page.</p></div>
</section>
{% endblock %}
THTML
  fi
done

##########
# run Flask
##########
echo "Setup complete. Starting Flask (development server) on 0.0.0.0:8080 ..."
# export FLASK_APP=app.py and run
export FLASK_APP=app.py
flask run --host=0.0.0.0 --port=8080
