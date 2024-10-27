# Crispy Auth Server

## Overview

Crispy Auth Server is an authentication server designed to streamline user authentication and authorization processes for web applications. Built on Flask, this server integrates with Keycloak for secure identity management, allowing applications to easily manage user sessions and tokens.

## Features

- **User Authentication:** Seamless integration with Keycloak for user login and logout.
- **Token Management:** Handles access tokens and user sessions.
- **User Profile Management:** Provides an interface to display and manage user profile information.
- **Dashboard:** A user-friendly dashboard for navigating application features.
- **Modular Design:** Organized project structure for improved maintainability and scalability.

## Installation

### Prerequisites

- Python 3.x
- Flask
- Keycloak library
- Flask-Session

### Clone the Repository

```bash
git clone https://github.com/yourusername/crispy-auth-server.git
cd crispy-auth-server
```

### Set Up a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Keycloak

Make sure to configure your Keycloak settings in `config.py`. You need to provide the following:

- `KEYCLOAK_SERVER_URL`
- `KEYCLOAK_CLIENT_ID`
- `KEYCLOAK_REALM`
- `KEYCLOAK_CLIENT_SECRET`
- `KEYCLOAK_VERIFY` (True or False)

## Running the Application

To start the server, run the following command:

```bash
python app.py
```

The server will be accessible at `http://localhost:5000`.

## Usage

- Navigate to the home page to access the login option.
- After successful login, you will be redirected to the dashboard.
- Access the user profile page to view your profile information.
- Click the logout button to terminate your session.

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push to your branch.
5. Create a pull request.

## License

This project is licensed under the Apache License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Flask](https://flask.palletsprojects.com/) for the web framework.
- [Keycloak](https://www.keycloak.org/) for identity management.