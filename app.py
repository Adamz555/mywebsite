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
