from flask import Flask, render_template, send_from_directory
app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html', title="AJMAL ADAMZ Blockchain Research & Technologies")

@app.route('/about')
def about():
    return render_template('about.html', title="About | Ajmal Adamz")

@app.route('/research')
def research():
    return render_template('research.html', title="Research | Ajmal Adamz")

@app.route('/knowledge')
def knowledge():
    return render_template('knowledge.html', title="History of Blockchain | Ajmal Adamz")

@app.route('/blockchain-basic')
def blockchain_basic():
    return render_template('blockchain_basic.html', title="Blockchain Basic | Ajmal Adamz")

@app.route('/contact')
def contact():
    return render_template('contact.html', title="Contact | Ajmal Adamz")

@app.route('/labs')
def labs():
    return render_template('labs.html', title="🧪 Labs | Ajmal Adamz Research")

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
