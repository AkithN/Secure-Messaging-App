from flask import Flask, render_template, request
import mysql.connector
import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH

app = Flask(__name__)

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="12345",
    database="data"
)
cursor = db.cursor()

@app.route('/')
def login():
    return render_template('Signup.html')

@app.route('/dashboard', methods=['POST'])
def dashboard():
    try:
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (username, hashed_password, role))
        db.commit()

        cursor.execute('SELECT UID FROM users ORDER BY UID DESC LIMIT 1')
        UID = cursor.fetchone()
        global global_uid 
        global_uid = int(UID[0])

        return render_template('dashboard.html')
    except Exception as e:
        return f"An error occurred: {str(e)}"

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        message = request.form['original-message']
        role = request.form['role']

        # Generate ECC private key and corresponding public key
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()

        # Key exchange
        shared_secret = private_key.exchange(ECDH(), public_key)

        # Encrypt the message
        encrypted_message = encrypt_with_shared_key(message.encode('utf-8'), shared_secret)

        cursor.execute('SELECT * FROM users WHERE role = %s AND UID = %s', (role, global_uid))
        valid = cursor.fetchone()
        
        if valid:
            # Store encrypted message as base64 encoded string
            encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
            cursor.execute('INSERT INTO message (sendMessage, UID) VALUES (%s, %s)', (encrypted_message_b64, global_uid))
            db.commit()

            return render_template('dashboard.html', encrypted_message=encrypted_message_b64)
        else:
            return render_template('dashboard.html', encrypted_message="no data sent")
    except Exception as e:
        return f"An error occurred: {str(e)}"

def encrypt_with_shared_key(message, key):
    # Derive a secure key from the shared secret using HKDF
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh-encryption',
        backend=default_backend()
    )
    derived_key = kdf.derive(key)

    # Generate a random nonce
    nonce = os.urandom(12)  # Use a secure random nonce

    # Use AES in GCM mode for authenticated encryption
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    # Get the authentication tag
    tag = encryptor.tag

    # Return the concatenated nonce, ciphertext, and tag
    return nonce + ciphertext + tag

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        dusername = request.form['decryption-username']
        dpassword = request.form['decryption-password'].encode('utf-8')

        cursor.execute("SELECT password FROM users WHERE username = %s AND UID = %s", (dusername, global_uid))
        valid = cursor.fetchone()

        if valid and valid[0] == hashlib.sha256(dpassword).hexdigest():
            # Generate ECC private key and corresponding public key
            private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            public_key = private_key.public_key()

            # Key exchange
            shared_secret = private_key.exchange(ECDH(), public_key)

            cursor.execute('SELECT sendMessage FROM message WHERE UID = %s', (global_uid,))
            encrypted_message_b64 = cursor.fetchone()

            if encrypted_message_b64:
                # Decode the base64 encoded message
                encrypted_message = base64.b64decode(encrypted_message_b64[0])
                decrypted_message = decrypt_with_shared_key(encrypted_message, shared_secret)
                return render_template('dashboard.html', message=decrypted_message.decode('utf-8'))
            else:
                return render_template('dashboard.html', message="no encrypted message found")
        else:
            return render_template('dashboard.html', message="wrong user or password")
    except Exception as e:
        return f"An error occurred: {str(e)}"

def decrypt_with_shared_key(encrypted_data, key):
    try:
        # Derive a secure key from the shared secret using HKDF
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecdh-encryption',
            backend=default_backend()
        )
        derived_key = kdf.derive(key)

        # Extract the nonce, ciphertext, and tag from the encrypted data
        nonce = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]

        # Use AES in GCM mode for authenticated decryption
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_message
    except Exception as e:
        return f"An error occurred while decrypting: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
