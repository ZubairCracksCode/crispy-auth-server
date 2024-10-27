import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080/auth')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'Ticketing')
    KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'TicketingPortal')
    KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', 'lbbEPVbQKtpV4A7CJfL7fJnWvpoQ2E4E')
    KEYCLOAK_VERIFY = True
