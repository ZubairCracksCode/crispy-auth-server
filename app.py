from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError
from config import Config
import jwt

from flask_session import Session

app = Flask(__name__)
app.config.from_object(Config)  
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

keycloak_openid = KeycloakOpenID(
    server_url=app.config['KEYCLOAK_SERVER_URL'],
    client_id=app.config['KEYCLOAK_CLIENT_ID'],
    realm_name=app.config['KEYCLOAK_REALM'],
    client_secret_key=app.config['KEYCLOAK_CLIENT_SECRET'],
    verify=app.config['KEYCLOAK_VERIFY']
)

# Routes
@app.route('/')
def home():
    """Landing page."""
    return render_template('index.html')

@app.route('/login')
def login():
    """Redirects to Keycloak login page."""
    auth_url = keycloak_openid.auth_url(redirect_uri=url_for('auth_callback', _external=True)) 
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    """Handles Keycloak callback and stores the access token."""
    code = request.args.get('code')
    print("AUTHORIZATION_CODE:", code)
    
    if not code:
        return "No authorization code found", 400

    try:
        token = keycloak_openid.token(
            code=code,
            redirect_uri=url_for('auth_callback', _external=True),
            grant_type='authorization_code'
        )
        session['access_token'] = token['access_token']
        print("ACCESS TOKEN:", session['access_token'])
        return redirect(url_for('dashboard'))

    except KeycloakAuthenticationError as e:
        return f"Authentication failed: {e}", 401

@app.route('/dashboard')
def dashboard():
    """Dashboard page - requires login."""
    if 'access_token' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/profile')
def profile():
    """User profile page - displays user information."""
    if 'access_token' not in session:
        return redirect(url_for('login'))

    try:
        access_token = session['access_token']
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        print("Decoded Token:", decoded_token)
        return render_template('profile.html', user_info=decoded_token)

    except jwt.DecodeError:
        return jsonify({'error': 'Invalid token'}), 400

@app.route('/api/profile-data')
def profile_data():
    """API endpoint to fetch user profile data as JSON."""
    if 'access_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        access_token = session['access_token']
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        return jsonify(decoded_token)

    except jwt.DecodeError:
        return jsonify({'error': 'Invalid token'}), 400
@app.route('/logout')
def logout():
    print("Before clearing session:", session)
    session.clear()
    print("After clearing session:", session)
    return redirect(url_for('home'))
if __name__ == '__main__':
    app.run(debug=True)
