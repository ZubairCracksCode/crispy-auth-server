import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
    
    KEYCLOAK_LOGOUT_URL = os.getenv('KEYCLOAK_LOGOUT_URL', 'http://localhost:8080/realms/SchoolRealm/protocol/openid-connect/logout')
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080/auth')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'SchoolRealm')
    KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'viqarunnisa_noon_school')
    KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', 'DHbdDyQcVcO4HOY9IHPv2TqB1mWETHYX')
    KEYCLOAK_VERIFY = True

    SESSION_TYPE = 'filesystem'  
    SESSION_PERMANENT = False    
    SESSION_USE_SIGNER = True     
    SESSION_FILE_DIR = os.getenv('SESSION_FILE_DIR', './flask_session')  
    SESSION_FILE_THRESHOLD = 100   
    SESSION_FILE_TIMEOUT = 300      

    KEYCLOAK_REALM_TICKETING = os.getenv('KEYCLOAK_REALM', 'Ticketing')
    KEYCLOAK_CLIENT_ID_TICKETING = os.getenv('KEYCLOAK_CLIENT_ID', 'TicketingPortal')
    KEYCLOAK_CLIENT_SECRET_TICKETING = os.getenv('KEYCLOAK_CLIENT_SECRET', 'lbbEPVbQKtpV4A7CJfL7fJnWvpoQ2E4E')

    KEYCLOAK_ADMIN_CLIENT_SECRET = os.getenv('KEYCLOAK_ADMIN_CLIENT_SECRET', 'qfLpFlMrJZ4leXE24v8KzFT9vFBZungC')
    KEYCLOAK_ADMIN_USERNAME = os.getenv('KEYCLOAK_ADMIN_USERNAME', 'admin')
    KEYCLOAK_ADMIN_PASSWORD = os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin')