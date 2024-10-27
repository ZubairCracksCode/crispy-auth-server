import os

class Config:
    # Secret key for session management
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')

    # Keycloak configuration
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080/auth')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'Ticketing')
    KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'TicketingPortal')
    KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', 'lbbEPVbQKtpV4A7CJfL7fJnWvpoQ2E4E')
    KEYCLOAK_VERIFY = True

    # Flask-Session configuration
    SESSION_TYPE = 'filesystem'  # Use filesystem for session storage
    SESSION_PERMANENT = False     # Session is not permanent
    SESSION_USE_SIGNER = True     # Use a session signer for added security
    SESSION_FILE_DIR = os.getenv('SESSION_FILE_DIR', './flask_session')  # Directory to store session files
    SESSION_FILE_THRESHOLD = 100   # Maximum number of session files to keep (default is 100)
    SESSION_FILE_TIMEOUT = 300      # Session timeout in seconds (5 minutes)
