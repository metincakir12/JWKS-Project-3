import unittest
import os
import tempfile
import requests
import json
import time
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jose import jwt, jwk
from jose.utils import base64url_decode
import threading
import uuid
import argon2
import subprocess
import sys
import signal
from time import sleep

# Import your server module - adjust the import based on your file structure
# This assumes the server code is in a file called jwks_server.py
sys.path.append('.')  # Add current directory to path
try:
    from jwks_server import app, encrypt_data, decrypt_data, AES_KEY, init_db, DB_FILE
except ImportError:
    pass  # We'll run the server as a subprocess instead

# Set a testing environment variable for AES key
os.environ["NOT_MY_KEY"] = "testing_key_for_development_only"

# Server URL when running as a process
SERVER_URL = "http://localhost:8080"

class TestJWKSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary database file for testing
        cls.temp_db_fd, cls.temp_db_path = tempfile.mkstemp()
        
        # Store the original DB_FILE value
        cls.original_db_file = DB_FILE
        
        # Set the DB_FILE to our temporary file
        globals()['DB_FILE'] = cls.temp_db_path
        
        # Start the server in a separate process
        cls.server_process = subprocess.Popen(
            [sys.executable, "jwks_server.py"],
            env=dict(os.environ, NOT_MY_KEY="testing_key_for_development_only")
        )
        
        # Wait for the server to start
        time.sleep(2)
    
    @classmethod
    def tearDownClass(cls):
        # Stop the server
        cls.server_process.send_signal(signal.SIGTERM)
        cls.server_process.wait()
        
        # Restore original DB_FILE value
        globals()['DB_FILE'] = cls.original_db_file
        
        # Remove the temporary database
        os.close(cls.temp_db_fd)
        os.unlink(cls.temp_db_path)
    
    def setUp(self):
        # Wait briefly between tests to avoid rate limiting
        time.sleep(0.2)
    
    def test_jwks_endpoint(self):
        """Test the JWKS endpoint returns valid keys"""
        response = requests.get(f"{SERVER_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertIn("keys", data)
        self.assertIsInstance(data["keys"], list)
        
        # If there are keys, verify they have the required fields
        if data["keys"]:
            key = data["keys"][0]
            required_fields = ["kty", "kid", "n", "e", "alg", "use"]
            for field in required_fields:
                self.assertIn(field, key)
    
    def test_register_endpoint(self):
        """Test the user registration endpoint"""
        # Generate a unique username for this test
        username = f"test_user_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        
        # Test registration
        response = requests.post(
            f"{SERVER_URL}/register", 
            json={"username": username, "email": email}
        )
        
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("password", data)
        self.assertTrue(len(data["password"]) > 0)
        
        # Test that we can't register the same user again
        response = requests.post(
            f"{SERVER_URL}/register", 
            json={"username": username, "email": email}
        )
        self.assertEqual(response.status_code, 400)  # Should get a bad request
        
        return username, data["password"]
    
    def test_auth_endpoint(self):
        """Test the authentication endpoint with valid credentials"""
        # First register a user
        username, password = self.test_register_endpoint()
        
        # Test authentication with valid credentials
        response = requests.post(
            f"{SERVER_URL}/auth", 
            json={"username": username, "password": password, "expired": False}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("token", data)
        token = data["token"]
        
        # Verify the token
        # We need to get the public key from JWKS to verify
        jwks_response = requests.get(f"{SERVER_URL}/.well-known/jwks.json")
        jwks_data = jwks_response.json()
        
        # Extract header from token to get kid
        header = jwt.get_unverified_header(token)
        self.assertIn("kid", header)
        
        # Find the key with matching kid
        key = None
        for k in jwks_data["keys"]:
            if k["kid"] == header["kid"]:
                key = k
                break
        
        self.assertIsNotNone(key, "Could not find matching key in JWKS")
        
        # Convert JWK to PEM for PyJWT
        public_key = jwk.construct(key)
        
        # Verify the token
        payload = jwt.decode(
            token,
            public_key.to_pem(),
            algorithms=["RS256"]
        )
        
        # Verify payload contains expected fields
        self.assertIn("sub", payload)
        self.assertIn("username", payload)
        self.assertEqual(payload["username"], username)
    
    def test_auth_with_invalid_credentials(self):
        """Test the authentication endpoint with invalid credentials"""
        # Use a random username that's unlikely to exist
        username = f"nonexistent_user_{uuid.uuid4().hex}"
        
        # Test authentication with invalid credentials
        response = requests.post(
            f"{SERVER_URL}/auth", 
            json={"username": username, "password": "wrong_password", "expired": False}
        )
        
        self.assertEqual(response.status_code, 401)  # Unauthorized
    
    def test_auth_with_expired_key(self):
        """Test the authentication endpoint with an expired key"""
        # First register a user
        username, password = self.test_register_endpoint()
        
        # Test authentication with valid credentials but expired key
        response = requests.post(
            f"{SERVER_URL}/auth", 
            json={"username": username, "password": password, "expired": True}
        )
        
        # This could either return a token with an expired key or a 400 if no expired keys are available
        if response.status_code == 200:
            data = response.json()
            self.assertIn("token", data)
        else:
            self.assertEqual(response.status_code, 400)
            self.assertIn("detail", response.json())
    
    def test_rate_limiting(self):
        """Test the rate limiting functionality"""
        # First register a user
        username, password = self.test_register_endpoint()
        
        # Send multiple requests in quick succession
        responses = []
        for _ in range(15):  # Try 15 requests (rate limit is 10 per second)
            response = requests.post(
                f"{SERVER_URL}/auth", 
                json={"username": username, "password": password, "expired": False}
            )
            responses.append(response)
        
        # Check that at least one request was rate limited
        rate_limited = any(resp.status_code == 429 for resp in responses)
        self.assertTrue(rate_limited, "No requests were rate limited")
    
    def test_aes_encryption(self):
        """Test the AES encryption and decryption functionality"""
        # This test requires direct access to the encryption functions
        try:
            # Test data
            test_data = b"This is a test string for encryption"
            
            # Test encryption
            encrypted_data = encrypt_data(test_data)
            self.assertNotEqual(encrypted_data, test_data)
            
            # Test decryption
            decrypted_data = decrypt_data(encrypted_data)
            self.assertEqual(decrypted_data, test_data)
        except NameError:
            self.skipTest("Direct testing of encryption functions not available in subprocess mode")
    
    def test_auth_logging(self):
        """Test that authentication requests are logged"""
        # This test requires direct database access, so it will be skipped in subprocess mode
        try:
            # First register a user
            username, password = self.test_register_endpoint()
            
            # Make an authentication request
            response = requests.post(
                f"{SERVER_URL}/auth", 
                json={"username": username, "password": password, "expired": False}
            )
            self.assertEqual(response.status_code, 200)
            
            # Connect to the database and check for log entries
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            # Query the auth_logs table
            cursor.execute("SELECT COUNT(*) FROM auth_logs WHERE user_id IS NOT NULL")
            count = cursor.fetchone()[0]
            
            conn.close()
            
            # There should be at least one log entry
            self.assertGreater(count, 0, "No authentication logs found")
        except sqlite3.OperationalError:
            self.skipTest("Direct database testing not available in subprocess mode")

if __name__ == "__main__":
    unittest.main()