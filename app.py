from flask import Flask, jsonify, request, redirect, url_for, render_template, session
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Keycloak Configuration
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
    next_url = request.args.get('next', url_for('profile'))
    auth_url = keycloak_openid.auth_url(
        redirect_uri=url_for('callback', _external=True),
        state=next_url
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    print("Received Authorization Code: ", code)  # Log the received code

    try:
        redirect_uri = url_for('callback', _external=True)
        print("Redirect URI: ", redirect_uri)  # Log the redirect URI

        # Attempt to exchange authorization code for a token
        token = keycloak_openid.token(code=code, redirect_uri=redirect_uri)
        print("TOKEN: ", token)
        session['access_token'] = token['access_token']

        # Get the 'state' parameter to redirect to the original URL or profile
        next_url = request.args.get('state', url_for('profile'))
        return redirect(next_url)

    except KeycloakAuthenticationError as e:
        # Log the error for debugging
        app.logger.error(f"Authentication failed: {e}")
        print(f"Error during token exchange: {e}")  # Log the error details

        # Redirect back to the login page with an error message
        return redirect(url_for('login', error="Invalid credentials, please try again."))

@app.route('/profile')
def profile():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    # Fetch user info from Keycloak
    try:
        userinfo = keycloak_openid.userinfo(token=session['access_token'])
        return jsonify(userinfo)
    except KeycloakAuthenticationError as e:
        app.logger.error(f"Failed to fetch user info: {e}")
        return jsonify({'error': 'Unable to fetch user info'}), 403

@app.route('/school2-api')
def school2_api():
    if 'access_token' not in session:
        return redirect(url_for('login', next=request.url))

    userinfo = keycloak_openid.userinfo(token=session['access_token'])

    # Check if the user has the required role
    if 'school2_user' not in userinfo.get('realm_access', {}).get('roles', []):
        return jsonify({'error': 'Forbidden'}), 403

    return jsonify({
        'message': 'This is a protected API response for School 2',
        'data': 'Welcome to School 2'
    })

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    return redirect(keycloak_openid.logout(redirect_uri=url_for('home', _external=True)))

if __name__ == '__main__':
    app.run(debug=True)
