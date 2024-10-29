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
    state = 'abc123'  # Generate a unique state
    session['oauth_state'] = state  # Store state in session
    auth_url = keycloak_openid.auth_url(
        redirect_uri=url_for('auth_callback', _external=True), 
        state=state  # Pass the state to the auth URL
    )
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    """Handles Keycloak callback and stores the access token."""
    code = request.args.get('code')
    state = request.args.get('state')

    # Verify state to prevent CSRF attacks
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
        # id_token = session.get('id_token')
        # print("TOKEN: ",token['id_token'])
        # session['id_token'] = token['id_token']
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
    # Fetch the ID token from the session
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        print("Refresh token not found in session. Redirecting to home.")
        return redirect(url_for('home'))

    # Clear the Flask session
    session.clear()
    print("After clearing session:", session)

    # Prepare Keycloak logout URL with `post_logout_redirect_uri` and `id_token_hint`
    redirect_uri = url_for('home', _external=True)  # Redirect back to the home page after logout
    logout_url = f"{app.config['KEYCLOAK_LOGOUT_URL']}?client_id={client_id}&client_secret={client_secret}&refresh_token={refresh_token}&post_logout_redirect_uri={redirect_uri}"

    # Redirect the user to Keycloak's logout URL
    return redirect(logout_url)


@app.route('/create-ticket')
def create_ticket():
    """Initiates the authorization flow for ticketing with School as IdP."""
    # state = str(uuid.uuid4())  # Generate a unique state
    # state = request.args.get('state')
    state = 'abc123'
    session['ticketing_oauth_state'] = state  # Store state in session

    # Generate the authorization URL for the Ticketing system, redirecting to School as IdP
    ticketing_auth_url = keycloak_openid_ticketing.auth_url(
        redirect_uri=url_for('ticketing_callback', _external=True), 
        state=state  # Pass the state to the ticketing auth URL
    )
    
    return redirect(ticketing_auth_url)

@app.route('/ticketing/callback')
def ticketing_callback():
    """Handles the School realm callback after authorization for ticketing."""
    code = request.args.get('code')
    # state = request.args.get('state')
    state = session.get('oauth_state')


    # Verify state to prevent CSRF attacks
    if state != session.get('ticketing_oauth_state'):
        return "Invalid state parameter", 400

    if not code:
        return "Authorization code not provided", 400

    try:
        # Exchange the authorization code received from School for an access token
        token = keycloak_openid_ticketing.token(
            code=code,
            redirect_uri=url_for('ticketing_callback', _external=True),
            grant_type='authorization_code'
        )
        session['ticketing_access_token'] = token['access_token']
        print("TICKETING ACCESS TOKEN:", session['ticketing_access_token'])

        return render_template('ticketing.html')  # Load the ticketing page post-authentication

    except KeycloakAuthenticationError as e:
        return f"Ticketing authorization failed: {e}", 401

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1')
    #  app.run(host="::1", port=5000, debug=True)

