from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, make_response
import pyodbc
import bcrypt
import jwt
import time
import requests
import secrets
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import random
import pyotp
import qrcode
import io

portal_app = Flask(__name__)

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

###### failed authorize -> redirect
def failed_verification():
    REDIRECT_authn = "http://127.0.0.1:5000/authorize?redirect_uri=http%3a%2f%2f127.0.0.1%3a5001%2fportalAuth&scope=06c9f25f-f806-4cb1-bf53-2ef28dff0843+access&client_id=06c9f25f-f806-4cb1-bf53-2ef28dff0843"
    return render_template_string('''
        <script>
            setTimeout(function(){{
                window.location.href = "{redirect_url}";
            }}, 3000);
        </script>
        <p>Token verification failed. Redirecting to authorization page in 3 seconds...</p>
    '''.format(redirect_url=REDIRECT_authn))

############################################################
############################################################

# JWT token config
JWT_SECRET = "JWTSecret"
JWT_ALGORITHM = "HS256"

# client app config
client_id = "06c9f25f-f806-4cb1-bf53-2ef28dff0843"
client_secret = "RDlzQoDi5l68K8DDBsWwGzS9TAF8BG"

# portal url
PORTAL_URL = "http://127.0.0.1:5001/portal"

# token endpoint url
TOKEN_URL = "http://127.0.0.1:5000/token"


###### Portal Auth url
@portal_app.route('/portalAuth', methods=['GET', 'POST'])
def portalAuth():
    authorization_code = request.args.get('code')
    username = request.args.get('username')

    if authorization_code and username:
        params = {
            'authorization_code': authorization_code,
            'username': username,
            'client_id': client_id,
            'client_secret': client_secret
        }

        redirect_url = f"{TOKEN_URL}?code={authorization_code}&username={username}&client_id={client_id}&client_secret={client_secret}"

        return redirect(redirect_url)

    else:
        # check if access token exist
        access_token = request.form.get('access_token')
        if access_token:
            try:
                # decrypt access token
                decoded_token = jwt.decode(access_token, "JWTSecret", algorithms="HS256", audience = "http://127.0.0.1:5001/portalAuth")

                # Validate access token lifetime
                exp_timestamp = decoded_token.get('exp')
                if exp_timestamp:
                    current_time = time.time()
                    if current_time > exp_timestamp:
                        # token expired
                         return failed_verification()
                    else:
                        # token is valid, set cookie
                        response = make_response(redirect(PORTAL_URL))
                        # set cookie 'access_token'
                        response.set_cookie('access_token', access_token, max_age=3600)  # set 1 hour lifetime
                        return response
                else:
                    return failed_verification()
            except jwt.ExpiredSignatureError:
                return failed_verification()
            except jwt.InvalidTokenError:
                return failed_verification()
        else:
            return failed_verification()

    return jsonify({
        "error": "Unknown error.",
        "message": "Invalid Patameters."
    }), 500


###### Portal
@portal_app.route('/portal', methods=['GET', 'POST'])
def portal():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return failed_verification()

    try:
        # verify JWT token
        decoded_token = jwt.decode(access_token, "JWTSecret", algorithms="HS256", audience="http://127.0.0.1:5001/portalAuth")

        exp_timestamp = decoded_token.get('exp')
        if not exp_timestamp or time.time() > exp_timestamp:
            return failed_verification()

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return failed_verification()

    if request.method == 'GET':

    # Get data from user_credentials table
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM user_credentials")
        user_credentials_data = cursor.fetchall()

        # Get data from AppRegistrations table
        cursor.execute("SELECT client_ids, client_secrets, redirect_uris, default_scopes FROM AppRegistrations")
        app_registrations_data = cursor.fetchall()

        # Render the management page template
        return render_template_string('''   
        <h3>Manage User Credentials</h3>
        <table border="1">
            <tr>
                <th>Username</th>
                <th>Actions</th>
            </tr>
            {% for row in user_credentials_data %}
            <tr>
                <td>{{ row[0] }}</td>
                <td>
                    <form method="post" action="/portal" style="display:inline;">
                        <input type="hidden" name="action" value="delete_user">
                        <input type="hidden" name="username" value="{{ row[0] }}">
                        <input type="submit" value="Delete">
                    </form>
                </td>
            </tr>
            {% endfor %}
        </table>
        <br>
        <h3>Add User Credential</h3>
        <form method="post" action="/portal">
            <input type="hidden" name="action" value="add_user">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <input type="submit" value="Add">
        </form>
        <br>
        <h3>Manage App Registrations</h3>
        <table border="1">
            <tr>
                <th>Client ID</th>
                <th>Client Secret</th>
                <th>Redirect URI</th>
                <th>Default Scope</th>
                <th>Actions</th>
            </tr>
            {% for row in app_registrations_data %}
            <tr>
                <td>{{ row[0] }}</td>
                <td>{{ row[1] }}</td>
                <td>{{ row[2] }}</td>
                <td>{{ row[3] }}</td>
                <td>
                    <form method="post" action="/portal" style="display:inline;">
                        <input type="hidden" name="action" value="delete_app">
                        <input type="hidden" name="client_id" value="{{ row[0] }}">
                        <input type="submit" value="Delete">
                    </form>
                    <form method="post" action="/portal" style="display:inline;">
                        <input type="hidden" name="action" value="edit_app">
                        <input type="hidden" name="client_id" value="{{ row[0] }}">
                        <input type="hidden" name="column" value="client_secrets">
                        <input type="text" name="value" value="{{ row[1] }}">
                        <input type="submit" value="Edit Client Secret">
                    </form>
                    <form method="post" action="/portal" style="display:inline;">
                        <input type="hidden" name="action" value="edit_app">
                        <input type="hidden" name="client_id" value="{{ row[0] }}">
                        <input type="hidden" name="column" value="redirect_uris">
                        <input type="text" name="value" value="{{ row[2] }}">
                        <input type="submit" value="Edit Redirect URI">
                    </form>
                    <form method="post" action="/portal" style="display:inline;">
                        <input type="hidden" name="action" value="edit_app">
                        <input type="hidden" name="client_id" value="{{ row[0] }}">
                        <input type="hidden" name="column" value="default_scopes">
                        <input type="text" name="value" value="{{ row[3] }}">
                        <input type="submit" value="Edit Default Scope">
                    </form>
                </td>
            </tr>
            {% endfor %}
        </table>
        <br>
        <h3>Add App Registration</h3>
        <form method="post" action="/portal">
            <input type="hidden" name="action" value="add_app">
            <label for="client_id">Client ID:</label>
            <input type="text" id="client_id" name="client_id" required><br>
            <label for="client_secret">Client Secret:</label>
            <input type="text" id="client_secret" name="client_secret" required><br>
            <label for="redirect_uri">Redirect URI:</label>
            <input type="text" id="redirect_uri" name="redirect_uri" required><br>
            <label for="default_scope">Default Scope:</label>
            <input type="text" id="default_scope" name="default_scope" required><br>
            <input type="submit" value="Add">
        </form>
        ''', user_credentials_data=user_credentials_data, app_registrations_data=app_registrations_data)

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete_user':
            username = request.form.get('username')
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_credentials WHERE username = ?", username)
            conn.commit()
        elif action == 'delete_app':
            client_id = request.form.get('client_id')
            cursor = conn.cursor()
            cursor.execute("DELETE FROM AppRegistrations WHERE client_ids = ?", client_id)
            conn.commit()
        elif action == 'add_user':
            username = request.form.get('username')
            password = request.form.get('password')
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor = conn.cursor()
            cursor.execute("INSERT INTO user_credentials (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        elif action == 'add_app':
            client_id = request.form.get('client_id')
            client_secret = request.form.get('client_secret')
            redirect_uri = request.form.get('redirect_uri')
            default_scope = request.form.get('default_scope')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO AppRegistrations (client_ids, client_secrets, redirect_uris, default_scopes) VALUES (?, ?, ?, ?)", (client_id, client_secret, redirect_uri, default_scope))
            conn.commit()
        elif action == 'edit_app':
            client_id = request.form.get('client_id')
            column = request.form.get('column')
            value = request.form.get('value')
            cursor = conn.cursor()
            cursor.execute(f"UPDATE AppRegistrations SET {column} = ? WHERE client_ids = ?", (value, client_id))
            conn.commit()
        return redirect(url_for('portal'))


if __name__ == '__main__':
    portal_app.run(host='127.0.0.1', port=5001, debug=True)