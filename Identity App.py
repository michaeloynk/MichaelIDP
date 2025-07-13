from flask import Flask, request, jsonify, render_template_string, redirect, url_for
import secrets
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import pyodbc
import time
import bcrypt
import jwt
import random
import pyotp
import qrcode
import io

app = Flask(__name__)

############################################################
############################################################

server = '192.168.2.34'
database = 'OAuth2_DB'
sqlusername = 'sqladmin'
sqlpassword = 'G7!kL4#pM2@qR8%z'
connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};UID={sqlusername};PWD={sqlpassword}'
conn = pyodbc.connect(connection_string)
print("Connected to SQL!")

############################################################
############################################################

###### generate symmetric key and iv
def generate_aes_key_and_kid():
    aes_key = secrets.token_bytes(32)
    kid = secrets.token_urlsafe(16)
    return aes_key, kid

###### encrypt with aes
def encrypt_data(data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode('utf-8')

###### decrypt aes
def decrypt_data(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    try:
        encrypted_data = encrypted_data.replace(' ', '+')
        padded_data = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
        unpadded_data = unpadder.update(padded_data) + unpadder.finalize()
        return unpadded_data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to decrypt authorization code: {str(e)}")

###### update aes key and iv
def update_credentials_for_username(kid, aes_key, iv, username):
    cursor = conn.cursor()
    authorize_data = f"{base64.b64encode(aes_key).decode('utf-8')}:{base64.b64encode(iv).decode('utf-8')}"
    cursor.execute("UPDATE user_credentials SET authorize_data = ?, kids = ? WHERE username = ?", authorize_data, kid, username)
    conn.commit()

###### get aes key and iv from DB
def retrieve_credentials(username):
    cursor = conn.cursor()
    cursor.execute("SELECT authorize_data FROM user_credentials WHERE username = ?", username)
    row = cursor.fetchone()
    if row:
        aes_key_b64, iv_b64 = row[0].split(':')
        return base64.b64decode(aes_key_b64), base64.b64decode(iv_b64)
    return None, None

###### verify client id and scope
def verify_client_id_and_scope(client_id, scope):
    cursor = conn.cursor()
    cursor.execute("SELECT client_secrets FROM AppRegistrations WHERE client_ids = ?", client_id)
    row = cursor.fetchone()
    return row[0] if row else None

###### generate TOTP and QRCode
def generate_totp_and_qr(username):
    totp = pyotp.TOTP(pyotp.random_base32())
    totp_key = totp.secret
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(totp.provisioning_uri(name=username, issuer_name="MyApp"))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    img_data = base64.b64encode(img_io.getvalue()).decode('utf-8')
    return totp_key, img_data

###### update QRCode
def update_totp_key(username, totp_key):
    cursor = conn.cursor()
    cursor.execute("UPDATE user_credentials SET TOTP_keys = ? WHERE username = ?", totp_key, username)
    conn.commit()

############################################################
############################################################

####### register user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string('''
        <h3>Create your account here.</h3>
        <form method="post" action="/register">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <input type="submit" value="Submit">
        </form>
        ''')

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return 'Invalid username and password!'

    # Check if the username already exists
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM user_credentials WHERE username = ?", username)
    existing_user = cursor.fetchone()
    if existing_user:
        return 'Username already exists! Please choose a different username.'

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO user_credentials (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
    except Exception as e:
        return jsonify({'error': f'Failed to register user: {e}'}), 500

    # Redirect to the MFA recommendation page
    return redirect(url_for('recommendmfa', username=username))

############################################################
############################################################

###### recommand user register MFA
@app.route('/recommendmfa', methods=['GET', 'POST'])
def recommendmfa():
    username = request.args.get('username') or request.form.get('username')
    if not username:
        return 'Invalid username!'

    if request.method == 'GET':
        return render_template_string(f'''
        <h3>Account Setup</h3>
        <p>It's recommended to register MFA for security reasons, continue to register MFA?</p>
        <form method="post" action="/recommendmfa">
            <input type="hidden" name="username" value="{username}">
            <input type="submit" name="mfa_choice" value="Yes">
            <input type="submit" name="mfa_choice" value="No">
        </form>
        ''')

    mfa_choice = request.form.get('mfa_choice')
    if mfa_choice == 'Yes':
        return redirect(url_for('securityinfo', username=username))
    elif mfa_choice == 'No':
        return 'Account has been setup successfully!'
    else:
        return 'Invalid choice!'

############################################################
############################################################

###### MFA
@app.route('/securityinfo', methods=['GET', 'POST'])
def securityinfo():
    username = request.args.get('username') or request.form.get('username')
    if not username:
        return 'Invalid username!'

    if request.method == 'GET':
        totp_key, qr_data = generate_totp_and_qr(username)
        update_totp_key(username, totp_key)
        return render_template_string(f'''
        <h3>Security Information</h3>
        <p>You can manually enter the TOTP key or scan the QR code below to set up your TOTP.</p>
        <p>TOTP Key: {totp_key}</p>
        <img src="data:image/png;base64,{qr_data}" alt="QR Code">
        <form method="post" action="/securityinfo">
            <input type="hidden" name="username" value="{username}">
            <input type="submit" name="action" value="Refresh">
            <input type="submit" name="action" value="Complete Setup">
        </form>
        ''')

    action = request.form.get('action')
    if action == 'Refresh':
        totp_key, qr_data = generate_totp_and_qr(username)
        update_totp_key(username, totp_key)
        return render_template_string(f'''
        <h3>Security Information</h3>
        <p>You can manually enter the TOTP key or scan the QR code below to set up your TOTP.</p>
        <p>TOTP Key: {totp_key}</p>
        <img src="data:image/png;base64,{qr_data}" alt="QR Code">
        <form method="post" action="/securityinfo">
            <input type="hidden" name="username" value="{username}">
            <input type="submit" name="action" value="Refresh">
            <input type="submit" name="action" value="Complete Setup">
        </form>
        ''')
    elif action == 'Complete Setup':
        return 'Account has been setup successfully!'
    else:
        return 'Invalid session!'

############################################################
############################################################

###### Authorize endpoint
@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    username = request.form.get('username') if request.method == 'POST' else None
    password = request.form.get('password') if request.method == 'POST' else None
    totp_code = request.form.get('totp') if request.method == 'POST' else None

    if request.method == 'GET':
        return render_template_string(f'''
        <form method="post" action="/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <label for="totp">TOTP Code:</label>
            <input type="text" id="totp" name="totp" required><br>
            <input type="submit" value="Submit">
        </form>
        ''')

    if not all([client_id, redirect_uri, scope, username, password, totp_code]):
        return jsonify({'error': 'Missing required fields!'}), 400

    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, TOTP_keys FROM user_credentials WHERE username = ?", username)
    result = cursor.fetchone()

    if result is None or not bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
        return jsonify({'error': 'Invalid username or password!'}), 401

    totp = pyotp.TOTP(result[1])
    if not totp.verify(totp_code):
        return jsonify({'error': 'Invalid TOTP code!'}), 401

    aes_key, kid = generate_aes_key_and_kid()
    iv = secrets.token_bytes(16)
    expiration_time = time.time() + 600
    unencrypted_data = {
        'client_id': client_id,
        'kid': kid,
        'username': username,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'expiration_time': expiration_time
    }
    authorization_code = encrypt_data(str(unencrypted_data), aes_key, iv)
    update_credentials_for_username(kid, aes_key, iv, username)
    return redirect(f"{redirect_uri}?code={authorization_code}&username={username}")

############################################################
############################################################

###### token endpoint
@app.route('/token', methods=['POST', 'GET'])
def token():
    client_id = request.args.get('client_id')
    client_secret = request.args.get('client_secret')
    code = request.args.get('code')
    username = request.args.get('username')

    if not all([client_id, client_secret, code, username]):
        return jsonify({'error': 'Missing required fields!'}), 400

    cursor = conn.cursor()
    cursor.execute("SELECT client_secrets, redirect_uris, default_scopes FROM AppRegistrations WHERE client_ids = ?", client_id)
    result = cursor.fetchone()

    if result is None or result[0] != client_secret:
        return jsonify({'error': 'Invalid client_id or client_secret!'}), 401

    redirect_uri = result[1]

    if not redirect_uri:
        return jsonify({'error': 'Invalid client!'}), 400

    aes_key, iv = retrieve_credentials(username)
    if aes_key is None or iv is None:
        return jsonify({'error': 'Invalid authorization code!'}), 401

    try:
        decrypted_data = decrypt_data(code, aes_key, iv)
        unencrypted_data = eval(decrypted_data)
    except Exception as e:
        return jsonify({'error': f'Failed to decrypt authorization code: {str(e)}'}), 401

    if time.time() > unencrypted_data['expiration_time']:
        return jsonify({'error': 'Authorization code has expired!'}), 401

    payload = {
        "iss": "MichaelIDP",
        "aud": redirect_uri,
        "sub": username,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "scope": result[2],
        "nonce": random.SystemRandom().randint(10 ** 14, 10 ** 15 - 1)
    }
    access_token = jwt.encode(payload, "JWTSecret", algorithm="HS256")

    return redirect(f"{redirect_uri}?access_token={access_token}&username={username}")


if __name__ == '__main__':
    app.run(debug=True)
