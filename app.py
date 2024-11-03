from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError
from config import Config
import jwt
import os
import uuid
import requests
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

keycloak_openid_ticketing = KeycloakOpenID(
    server_url=app.config['KEYCLOAK_SERVER_URL'],
    client_id=app.config['KEYCLOAK_CLIENT_ID_TICKETING'],
    realm_name=app.config['KEYCLOAK_REALM_TICKETING'],
    client_secret_key=app.config['KEYCLOAK_CLIENT_SECRET_TICKETING'],
    verify=app.config['KEYCLOAK_VERIFY']
)

@app.route('/')
def home():
    """Landing page."""
    return render_template('index.html')

@app.route('/login')
def login():
    """Redirects to Keycloak login page."""
    state = 'abc123' 
    session['oauth_state'] = state 
    auth_url = keycloak_openid.auth_url(
        redirect_uri=url_for('auth_callback', _external=True), 
        state=state
    )
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    """Handles Keycloak callback and stores the access token."""
    code = request.args.get('code')
    state = request.args.get('state')

    if state != session.get('oauth_state'):
        return "Invalid state parameter", 400

    print("AUTHORIZATION_CODE:", code)
    
    if not code:
        return "No authorization code found", 400

    try:
        token = keycloak_openid.token(
            code=code,
            redirect_uri=url_for('auth_callback', _external=True),
            grant_type='authorization_code'
        )
        session['refresh_token'] = token['refresh_token']
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
    client_id=app.config['KEYCLOAK_CLIENT_ID']
    client_secret=app.config['KEYCLOAK_CLIENT_SECRET']
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        print("Refresh token not found in session. Redirecting to home.")
        return redirect(url_for('home'))

    session.clear()
    print("After clearing session:", session)

    redirect_uri = url_for('home', _external=True) 
    logout_url = f"{app.config['KEYCLOAK_LOGOUT_URL']}?client_id={client_id}&client_secret={client_secret}&refresh_token={refresh_token}&post_logout_redirect_uri={redirect_uri}"

    return redirect(logout_url)


@app.route('/create-ticket')
def create_ticket():
    """Initiates the authorization flow for ticketing with School as IdP."""

    state = 'abc123'
    session['ticketing_oauth_state'] = state  

    ticketing_auth_url = keycloak_openid_ticketing.auth_url(
        redirect_uri=url_for('ticketing_callback', _external=True), 
        state=state  
    )
    
    return redirect(ticketing_auth_url)

@app.route('/ticketing/callback')
def ticketing_callback():
    """Handles the School realm callback after authorization for ticketing."""
    code = request.args.get('code')
    state = session.get('oauth_state')


    if state != session.get('ticketing_oauth_state'):
        return "Invalid state parameter", 400

    if not code:
        return "Authorization code not provided", 400

    try:
        token = keycloak_openid_ticketing.token(
            code=code,
            redirect_uri=url_for('ticketing_callback', _external=True),
            grant_type='authorization_code'
        )
        session['ticketing_access_token'] = token['access_token']
        print("TICKETING ACCESS TOKEN:", session['ticketing_access_token'])

        return render_template('ticketing.html') 
    except KeycloakAuthenticationError as e:
        return f"Ticketing authorization failed: {e}", 401


@app.route('/api/client-scope', methods=['POST'])
def manage_client_scope():
    action = request.json.get('action')  # Should be "add" or "remove"
    client_id = request.json.get('client_id')
    client_scope_id = request.json.get('client_scope_id')
    
    if not action or not client_id or not client_scope_id:
        return jsonify({"error": "Missing parameters"}), 400
    
    base_url = app.config['KEYCLOAK_SERVER_URL']
    realm_name = app.config['KEYCLOAK_REALM']
    admin_username = app.config['KEYCLOAK_ADMIN_USERNAME']
    admin_password = app.config['KEYCLOAK_ADMIN_PASSWORD']
    client_secret = app.config['KEYCLOAK_ADMIN_CLIENT_SECRET']
    
    token_url = f"{base_url}/realms/{realm_name}/protocol/openid-connect/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": "admin-cli",
        "client_secret": client_secret
    }
    token_response = requests.post(token_url, data=data)
    token = token_response.json().get("access_token")
    print("TOKEN:", token)
    if not token:
        return jsonify({"error": "Failed to retrieve admin token"}), 500

    client_scope_url = (
        f"{base_url}/admin/realms/{realm_name}/clients/{client_id}/"
        f"{'default-client-scopes' if action == 'add' else 'optional-client-scopes'}/{client_scope_id}"
    )
    
    headers = {"Authorization": f"Bearer {token}"}

    if action == "add":
        response = requests.put(client_scope_url, headers=headers)
    elif action == "remove":
        response = requests.delete(client_scope_url, headers=headers)
    else:
        return jsonify({"error": "Invalid action"}), 400

    if response.status_code in (204, 201):
        return jsonify({"message": f"Client scope {action}ed successfully."}), 200
    else:
        return jsonify({"error": "Failed to manage client scope", "details": response.json()}), response.status_code


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1')
    #  app.run(host="::1", port=5000, debug=True)

