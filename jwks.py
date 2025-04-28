from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from jose import jwt
import time
import base64
import os
import json
import sqlite3
import uuid
import argon2
from datetime import datetime
from typing import Dict, List, Optional
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, EmailStr
import secrets
from starlette.status import HTTP_201_CREATED, HTTP_429_TOO_MANY_REQUESTS

app = FastAPI()
security = HTTPBasic()

# Database file name
DB_FILE = "totally_not_my_privateKeys.db"

# Environment variable for AES encryption key
# In a production environment, this would be securely stored and retrieved
AES_KEY = os.environ.get("NOT_MY_KEY", "fallback_key_for_development").encode()
if len(AES_KEY) < 32:
    # Ensure key is 32 bytes for AES-256
    AES_KEY = AES_KEY.ljust(32, b'\0')
elif len(AES_KEY) > 32:
    AES_KEY = AES_KEY[:32]

# Password hasher
ph = argon2.PasswordHasher(
    time_cost=3,  # Number of iterations
    memory_cost=65536,  # 64MB
    parallelism=4,  # Number of parallel threads
    hash_len=32,  # Length of the hash in bytes
    salt_len=16  # Length of the salt in bytes
)

# Rate limiter implementation
class RateLimiter:
    def __init__(self, max_requests=10, window_seconds=1):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # {ip: [(timestamp, user_id), ...]}
    
    def check_rate_limit(self, ip: str) -> bool:
        """Check if the IP has exceeded the rate limit"""
        current_time = time.time()
        
        # Initialize or clean up old requests
        if ip not in self.requests:
            self.requests[ip] = []
        else:
            # Remove requests older than the window
            self.requests[ip] = [req for req in self.requests[ip] 
                              if current_time - req[0] < self.window_seconds]
        
        # Check if rate limit is exceeded
        if len(self.requests[ip]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[ip].append((current_time, None))
        return True
    
    def update_user_id(self, ip: str, user_id: int):
        """Update the most recent request with the user ID"""
        if ip in self.requests and self.requests[ip]:
            timestamp, _ = self.requests[ip][-1]
            self.requests[ip][-1] = (timestamp, user_id)


# Initialize rate limiter
rate_limiter = RateLimiter()

# Pydantic models for request validation
class UserRegistration(BaseModel):
    username: str
    email: EmailStr

class AuthRequest(BaseModel):
    username: str
    password: str
    expired: bool = False

def pad_data(data: bytes) -> bytes:
    """Pad data to be a multiple of 16 bytes (AES block size)"""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad_data(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data"""
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_data(data: bytes) -> bytes:
    """Encrypt data using AES"""
    # In a real system, generate a random IV for each encryption
    # For simplicity, using a fixed IV here
    iv = b'\x00' * 16  # 16 bytes of zeros
    
    # Create an encryptor object
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the data to a multiple of 16 bytes (AES block size)
    padded_data = pad_data(data)
    
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data

def decrypt_data(encrypted_data: bytes) -> bytes:
    """Decrypt data using AES"""
    # Using the same IV that was used for encryption
    iv = b'\x00' * 16
    
    # Create a decryptor object
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    return unpad_data(decrypted_padded_data)

def init_db():
    """Initialize the SQLite database with all tables"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create keys table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    ''')
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    ''')
    
    # Create auth_logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')
    
    conn.commit()
    conn.close()

def generate_key_pair(expiry_hours: int = 24) -> Dict:
    """Generate a new RSA key pair with expiry"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Calculate expiry
    expiry = int(time.time() + (expiry_hours * 3600))
    
    # Convert to PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Get public key components
    public_numbers = public_key.public_numbers()
    
    # Encrypt the private key before storing
    encrypted_private_key = encrypt_data(pem_private)
    
    # Store key in database and get the kid
    kid = store_key_in_db(encrypted_private_key, expiry)
    
    # Create key entry with public key data
    key_entry = {
        "kid": str(kid),
        "expiry": expiry,
        "private_key": pem_private,  # Original unencrypted key (only in memory)
        "public_key_data": {
            "kty": "RSA",
            "kid": str(kid),
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "alg": "RS256",
            "use": "sig"
        }
    }
    
    return key_entry

def store_key_in_db(encrypted_key_data: bytes, expiry: int) -> int:
    """Store an encrypted key in the database and return the kid"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Insert the encrypted key and expiry into the database
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_key_data, expiry))
    
    # Get the kid (which is the autoincremented primary key)
    kid = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return kid

def get_key_from_db(expired: bool = False) -> Optional[Dict]:
    """Get a key from the database
    
    Args:
        expired: If True, get an expired key, otherwise get a valid key
    
    Returns:
        Dict containing the key data or None if no suitable key is found
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_time = int(time.time())
    
    if expired:
        # Get an expired key
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (current_time,))
    else:
        # Get a valid key
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (current_time,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    kid, encrypted_key_data, expiry = row
    
    # Decrypt the private key
    try:
        key_data = decrypt_data(encrypted_key_data)
    except Exception as e:
        print(f"Error decrypting key: {e}")
        return None
    
    # Deserialize the private key
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,
        backend=default_backend()
    )
    
    # Get public key components
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    # Create key entry
    key_entry = {
        "kid": str(kid),
        "expiry": expiry,
        "private_key": key_data,
        "public_key_data": {
            "kty": "RSA",
            "kid": str(kid),
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "alg": "RS256",
            "use": "sig"
        }
    }
    
    return key_entry

def get_all_valid_keys_from_db() -> List[Dict]:
    """Get all valid (non-expired) keys from the database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_time = int(time.time())
    
    # Get all valid keys
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (current_time,))
    
    rows = cursor.fetchall()
    conn.close()
    
    valid_keys = []
    
    for row in rows:
        kid, encrypted_key_data, expiry = row
        
        try:
            # Decrypt the private key
            key_data = decrypt_data(encrypted_key_data)
            
            # Deserialize the private key
            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            
            # Get public key components
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            
            # Create public key data
            public_key_data = {
                "kty": "RSA",
                "kid": str(kid),
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
                "alg": "RS256",
                "use": "sig"
            }
            
            valid_keys.append(public_key_data)
        except Exception as e:
            print(f"Error processing key {kid}: {e}")
            continue
    
    return valid_keys

def register_user(username: str, email: str) -> str:
    """Register a new user and return the generated password"""
    # Generate a secure password using UUIDv4
    password = str(uuid.uuid4())
    
    # Hash the password using Argon2
    password_hash = ph.hash(password)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        # Store the user details and hashed password
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))
    
    conn.close()
    return password

def verify_user(username: str, password: str) -> Optional[int]:
    """Verify user credentials and return user ID if valid"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Fetch user details
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return None
    
    user_id, password_hash = user
    
    try:
        # Verify the password hash
        ph.verify(password_hash, password)
        
        # Update last login timestamp
        cursor.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now().isoformat(), user_id)
        )
        conn.commit()
        
        conn.close()
        return user_id
    except argon2.exceptions.VerifyMismatchError:
        conn.close()
        return None
    except Exception as e:
        conn.close()
        print(f"Error verifying user: {e}")
        return None

def log_auth_request(request_ip: str, user_id: Optional[int] = None):
    """Log an authentication request to the database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request_ip, user_id)
        )
        conn.commit()
    except Exception as e:
        print(f"Error logging auth request: {e}")
    finally:
        conn.close()

@app.on_event("startup")
async def startup_event():
    """Initialize database and generate initial keys on startup"""
    # Initialize the database
    init_db()
    
    # Check if we have valid keys
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_time = int(time.time())
    
    # Check for valid keys
    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (current_time,))
    valid_count = cursor.fetchone()[0]
    
    # Check for expired keys
    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (current_time,))
    expired_count = cursor.fetchone()[0]
    
    conn.close()
    
    # Generate keys if needed
    if valid_count == 0:
        # Generate a valid key (1 hour validity)
        generate_key_pair(1)
    
    if expired_count == 0:
        # Generate an expired key
        generate_key_pair(-1)  # Already expired

@app.get("/.well-known/jwks.json")
async def jwks():
    """Serve the JWKS endpoint with valid keys from the database"""
    valid_keys = get_all_valid_keys_from_db()
    
    return JSONResponse({
        "keys": valid_keys
    })

@app.post("/register", status_code=HTTP_201_CREATED)
async def register(user_data: UserRegistration):
    """Register a new user and return a generated password"""
    password = register_user(user_data.username, user_data.email)
    
    return JSONResponse({
        "password": password
    })

@app.post("/auth")
async def auth(request: Request, auth_req: AuthRequest):
    """Authentication endpoint that returns a JWT
    
    Args:
        expired: If True, use an expired key to sign the JWT
    """
    # Get client IP address
    client_ip = request.client.host
    
    # Check rate limit
    if not rate_limiter.check_rate_limit(client_ip):
        return JSONResponse(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Too many requests"}
        )
    
    # Verify user credentials
    user_id = verify_user(auth_req.username, auth_req.password)
    
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Update rate limiter with user ID
    rate_limiter.update_user_id(client_ip, user_id)
    
    # Log the authentication request
    log_auth_request(client_ip, user_id)
    
    # Get a key for signing
    key = get_key_from_db(auth_req.expired)
    
    if not key:
        if auth_req.expired:
            raise HTTPException(status_code=400, detail="No expired keys available")
        else:
            raise HTTPException(status_code=500, detail="No valid keys available")
    
    # Create JWT payload
    payload = {
        "sub": str(user_id),
        "username": auth_req.username,
        "iat": int(time.time()),
        "exp": key["expiry"]
    }
    
    # Create JWT headers
    headers = {
        "kid": key["kid"]
    }
    
    # Sign the JWT
    token = jwt.encode(
        payload,
        key["private_key"] if isinstance(key["private_key"], str) else key["private_key"].decode('utf-8'),
        algorithm="RS256",
        headers=headers
    )
    
    return JSONResponse({
        "token": token
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)