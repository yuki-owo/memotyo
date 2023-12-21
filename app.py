from flask import Flask, request, render_template, redirect, url_for
from flask import make_response, session
import sqlite3
import datetime
import base64
import hashlib
import secrets


ALGORITHM = "pbkdf2_sha256"

def hash_password(password, salt=None, iterations=310000):
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(password, str)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return "{}${}${}${}".format(ALGORITHM, iterations, salt, b64_hash)


def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    algorithm, iterations, salt, _ = password_hash.split("$", 3)
    iterations = int(iterations)
    assert algorithm == ALGORITHM
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)


dt_now = datetime.datetime.now()
app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = b'opensesame'

memos =[]

def get_db():
	db = sqlite3.connect('memos.db')
	db.row_factory = sqlite3.Row
	return db

def init_db():
	with app.app_context():
		try:
			db = get_db()
			with db:
				with app.open_resource('schema.sql', mode='r') as f:
					db.cursor().executescript(f.read())
		finally:
			db.close()

init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
	try:
		db = get_db()
		if request.method == 'POST':
			username = request.form['username']
			if len(username) == 0:
				return render_template('register.html', error_user=True)
			password = request.form['password']
			if len(password) == 0:
				return render_template('register.html', error_password=True)
			confirm = request.form['confirm']
			if password != confirm:
				return render_template('register.html', error_confirm=True)

			with db:
				res = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchall()
				if len(res) != 0:
					return render_template('register.html', error_unique=True)
			
			with db:
				hashed_password = hash_password(password)
				db.execute('INSERT INTO users(username, password) VALUES (?, ?)', (username,hashed_password))
			return redirect('/login')
		
		return render_template('register.html')
	finally:
		db.close()	

@app.route('/logout')
def logout():
	session.pop('user_id', None)
	return redirect(('/'))

@app.route('/login', methods=['GET', 'POST'])
def login():
	try:
		db = get_db()
		if request.method == 'POST':
			username = request.form['username']
			if len(username) == 0:
				return render_template('login.html', error_user=True)
			password = request.form['password']
			if len(password) == 0:
				return render_template('login.html', error_password=True)

			with db:
				res = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

				if res is None:
					return render_template('login.html', error_login=True)
				if verify_password(password, res['password']):
					session['user_id'] = res['id']
					return redirect('/')
			return render_template('login.html',  error_login=True)
		
		return render_template('login.html')
	finally:
		db.close()

@app.route('/', methods=['GET', 'POST'])
def index():
	if not 'user_id' in session:
		return redirect('/login')
	try:
		db = get_db()
		with db:
			user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
			folders = db.execute('SELECT * FROM folders WHERE user_id = ?', (user['id'],)).fetchall()
			memos = db.execute('SELECT * FROM memos WHERE owner_id = ? and folder_id = ?', (user['id'], session.get('selected_folder', None))).fetchall()
			select_folder = db.execute('SELECT * FROM folders WHERE user_id = ? and id = ?', (user['id'],session.get('selected_folder', None))).fetchall()

		username = user['username']
		if request.method == 'POST':
			title = request.form['title']
			contents = request.form['contents']
			update_date = str(dt_now.year) + '年' + str(dt_now.month) + '月' + str(dt_now.day) + '日'

			with db:
				db.execute('INSERT INTO memos(title, contents, update_date, owner_id, folder_id) VALUES (?, ?, ?, ?, ?)', (title,contents,update_date,user['id'], session.get('selected_folder', None)))
				print(session.get('selected_folder', None))
			
			return redirect('/')
		

		return render_template('index.html',username=(username) ,folders=(folders), memos=(memos), select_folder=(select_folder))
	finally:
		db.close()


@app.route('/open_folder', methods=['POST'])
def open_folder():
	if not 'user_id' in session:
		return redirect('/login')

	session['selected_folder'] = request.form['folder_id'] 
	print(session['selected_folder'])
	return redirect('/')

@app.route('/folder', methods=['POST'])
def folder():
	try:
		db = get_db()
		with db:
			db.execute('INSERT INTO folders(name, user_id) VALUES (?, ?)', (request.form['folder_name'], session['user_id']))
		return redirect('/')
	finally:
		db.close()

@app.route('/delete_folder', methods=['POST'])
def delfol():
	try:
		db = get_db()
		folder_id = int(request.form['folder_id'])
		with db:
			db.execute("DELETE FROM memos WHERE folder_id = ?", (folder_id,))
			db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
		return redirect('/')
	finally:
		db.close()

@app.route('/delete', methods=['POST'])
def delete():
	try:
		db = get_db()
		memo_id = int(request.form['memo_id'])
		with db:
			db.execute("DELETE FROM memos WHERE id = ?", (memo_id,))
		return redirect('/')
	finally:
		db.close()
