# JWKS-Project-3
# Enhanced JWKS Server

A secure JWKS (JSON Web Key Set) server implementation with advanced security features including AES encryption, user management, authentication logging, and rate limiting.

## Features

### Core JWKS Functionality
- JSON Web Key Set (JWKS) endpoint providing RSA public keys
- JWT (JSON Web Token) issuance with configurable expiration
- Key rotation with support for valid and expired keys

### Enhanced Security Features
- **AES-256 Encryption** for private keys stored in the database
- **User Registration System** with secure password generation
- **Argon2 Password Hashing** with configurable parameters
- **Authentication Request Logging** with IP tracking
- **Rate Limiting** to prevent abuse (10 requests/second)

## Requirements

- Python 3.8+
- FastAPI
- Cryptography
- Python-Jose
- Argon2-cffi
- Pydantic
- SQLite3 (included in Python standard library)
- Uvicorn (for running the server)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/enhanced-jwks-server.git
cd enhanced-jwks-server
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install fastapi cryptography python-jose[cryptography] argon2-cffi pydantic uvicorn
```

## Configuration

The server requires an environment variable for AES encryption:

```bash
export NOT_MY_KEY="your-secure-encryption-key"
```

For security, this key should be at least 32 bytes (256 bits) long and kept secret.

## Running the Server

Start the server with:

```bash
uvicorn jwks_server:app --host 0.0.0.0 --port 8080
```

Or run directly with Python:

```bash
python jwks_server.py
```

## API Endpoints

### JWKS Endpoint
- **GET** `/.well-known/jwks.json`
  - Returns the public keys in JWKS format

### User Registration
- **POST** `/register`
  - Body: `{"username": "your_username", "email": "your_email@example.com"}`
  - Returns: `{"password": "generated_uuid4_password"}`
  - Status: 201 CREATED

### Authentication
- **POST** `/auth`
  - Body: `{"username": "your_username", "password": "your_password", "expired": false}`
  - Returns: `{"token": "jwt_token"}`
  - Status: 200 OK or 401 UNAUTHORIZED

## Database Schema

The server uses SQLite3 with the following tables:

### keys
- `kid` - Key ID (INTEGER PRIMARY KEY)
- `key` - Encrypted private key (BLOB)
- `exp` - Expiration timestamp (INTEGER)

### users
- `id` - User ID (INTEGER PRIMARY KEY)
- `username` - Username (TEXT UNIQUE)
- `password_hash` - Argon2 hashed password (TEXT)
- `email` - Email address (TEXT UNIQUE)
- `date_registered` - Registration timestamp (TIMESTAMP)
- `last_login` - Last login timestamp (TIMESTAMP)

### auth_logs
- `id` - Log ID (INTEGER PRIMARY KEY)
- `request_ip` - Request IP address (TEXT)
- `request_timestamp` - Request timestamp (TIMESTAMP)
- `user_id` - User ID (INTEGER FOREIGN KEY)

## Security Features

### AES Encryption
Private keys are encrypted using AES-256 in CBC mode with PKCS#7 padding before storage in the database. The encryption key is sourced from the environment variable `NOT_MY_KEY`.

### Password Management
- Passwords are automatically generated as UUIDv4 strings
- Passwords are hashed using Argon2id with secure parameters:
  - Time cost: 3 iterations
  - Memory cost: 64MB
  - Parallelism: 4 threads
  - Hash length: 32 bytes
  - Salt length: 16 bytes

### Rate Limiting
The authentication endpoint is protected by a sliding window rate limiter that allows a maximum of 10 requests per second per IP address. Requests exceeding this limit receive a 429 Too Many Requests response.

## Running Tests

The project includes a comprehensive test suite that verifies all functionality:

```bash
python -m unittest test_jwks_server.py
```

Tests cover:
- JWKS endpoint functionality
- User registration
- Authentication with valid and invalid credentials
- Rate limiting
- AES encryption/decryption
- Authentication logging

## Security Considerations

- This server is designed for educational purposes and may need additional hardening for production use
- In a production environment:
  - Use a more robust database system
  - Implement proper HTTPS/TLS
  - Add additional monitoring and alerting
  - Consider more sophisticated rate limiting strategies
  - Add protection against common attacks (CSRF, XSS, etc.)
