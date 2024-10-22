import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080/auth')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'SchoolRealm')
    KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'SchoolPortal')
    KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', '5bYO0yutN7o0iWN8lCfhQTLzLHUPlbpV')
    KEYCLOAK_VERIFY = True
