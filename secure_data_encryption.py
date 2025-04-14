import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet, InvalidToken
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # in seconds

# === Initialize Session State ===
for key, default in {
    "authenticated_user": None,
    "failed_attempts": 0,
    "lockout_time": 0,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# === Utility Functions ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.encrypt(text.encode()).decode()
    except Exception:
        return None

def decrypt_text(encrypted_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except (InvalidToken, Exception):
        return None

# === Load Stored Data ===
stored_data = load_data()

# === UI ===
st.title("🔐 Secure Data Encryption App")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data Encryption System!")
    st.markdown("""
    - 📝 Register or 🔑 Login  
    - 📁 Store your encrypted secrets  
    - 🔓 Decrypt anytime using your passkey  
    - ⛔ Lockout after 3 failed login attempts  
    """)

elif choice == "Register":
    st.subheader("📝 Register")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Please fill both fields.")

elif choice == "Login":
    st.subheader("🔑 Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Locked out. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {remaining}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Locked out for 60 seconds.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📁 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Passkey", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                if encrypted:
                    stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    save_data(stored_data)
                    st.success("✅ Data encrypted and saved!")
                    st.code(encrypted)
                else:
                    st.error("Encryption failed.")
            else:
                st.error("Please provide both data and passkey.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No stored data found.")
        else:
            st.write("Your Encrypted Entries:")
            for i, item in enumerate(user_data, 1):
                st.code(item)

            encrypted_input = st.text_area("Paste Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                if encrypted_input and passkey:
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success("✅ Decrypted Text:")
                        st.code(result)
                    else:
                        st.error("❌ Incorrect passkey or corrupted data.")
                else:
                    st.error("Please provide both encrypted text and passkey.")
