from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

keycloak_openid = KeycloakOpenID(
    server_url=app.config['KEYCLOAK_SERVER_URL'],
    client_id=app.config['KEYCLOAK_CLIENT_ID'],
    realm_name=app.config['KEYCLOAK_REALM'],
    client_secret_key=app.config['KEYCLOAK_CLIENT_SECRET'],
    verify=app.config['KEYCLOAK_VERIFY']
)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    auth_url = keycloak_openid.auth_url(redirect_uri=url_for('auth_callback', _external=True)) 
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    print("AUTHORIZATION_CODE: ", code)
    
    if not code:
        return "No authorization code found", 400

    try:
        token = keycloak_openid.token(
            code=code,
            redirect_uri=url_for('auth_callback', _external=True),
            grant_type='authorization_code'
        )
        session['access_token'] = token['access_token']
        print("ACCESS TOKEN:",session['access_token'])
        return redirect(url_for('profile'))

    except KeycloakAuthenticationError as e:
        return f"Authentication failed: {e}", 401

@app.route('/profile')
def profile():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    try:
        userinfo = keycloak_openid.userinfo(token=session['access_token'])
        print("User Info: ", userinfo)  # Log the user info
        return jsonify(userinfo)
    except KeycloakAuthenticationError as e:
        app.logger.error(f"Failed to fetch user info: {e}")
        return jsonify({'error': 'Unable to fetch user info'}), 403
    except Exception as e:
        app.logger.error(f"An error occurred: {e}")
        return jsonify({'error': str(e)}), 403

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.secret_key = 'your_secret_key'  
    app.run(debug=True)
