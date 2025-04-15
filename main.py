import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # 60 seconds

# === Session State ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

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
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def verify_password(stored_password, provided_password):
    return stored_password == hash_password(provided_password)

def encrypt_text(text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.encrypt(text.encode()).decode()
    except Exception:
        return None

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === Load Data ===
stored_data = load_data()

# === Custom Title Style ===
st.markdown("""
    <h1 style='color:#4CAF50;'>🔐 Secure Data Encryption System</h1>
    <p style='color:gray;'>Protect your sensitive information with strong encryption 🔒</p>
""", unsafe_allow_html=True)

# === Menu ===
menu = ["🏠 Home", "🔑 Login", "📝 Register", "💾 Store Data", "📂 Retrieve Data"]
choice = st.sidebar.selectbox("📋 Select an Option", menu)

# === Home ===
if choice == "🏠 Home":
    st.markdown("## ✨ Welcome!")
    st.markdown("""
    <ul style='color:#333; font-size:16px;'>
        <li>🔐 <b>Encrypt</b> and store your data securely</li>
        <li>🔑 Protect access with login and a passkey</li>
        <li>⏱️ Lockout after multiple failed attempts</li>
        <li>🧠 In-memory system, no external database</li>
    </ul>
    """, unsafe_allow_html=True)

# === Register ===
elif choice == "📝 Register":
    st.markdown("## 📝 Create an Account")
    new_username = st.text_input("👤 New Username")
    new_password = st.text_input("🔒 New Password", type="password")

    if st.button("🚀 Register"):
        if new_username in stored_data:
            st.error("❗ Username already exists.")
        else:
            hashed_password = hash_password(new_password)
            stored_data[new_username] = {"password": hashed_password}
            save_data(stored_data)
            st.success("✅ Registration successful! You can now log in.")

# === Login ===
elif choice == "🔑 Login":
    st.markdown("## 🔑 Login")
    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("🔓 Login"):
        if st.session_state.lockout_time and time.time() < st.session_state.lockout_time:
            st.warning(f"⚠️ Too many failed attempts. Try again in {int(st.session_state.lockout_time - time.time())} seconds.")
        else:
            if username in stored_data and verify_password(stored_data[username]["password"], password):
                st.session_state.authenticated_user = username
                st.success(f"🎉 Welcome, {username}!")
                st.session_state.failed_attempts = 0
                st.session_state.lockout_time = 0
            else:
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.warning("🚫 Too many failed attempts. You are temporarily locked out.")
                else:
                    st.error("❌ Invalid username or password.")

# === Store Data ===
elif choice == "💾 Store Data":
    if st.session_state.authenticated_user:
        st.markdown("## 💾 Store Your Data")
        plain_text = st.text_input("📝 Enter data to encrypt")
        passkey = st.text_input("🔑 Enter encryption passkey", type="password")
        if st.button("🔐 Encrypt & Save"):
            encrypted = encrypt_text(plain_text, passkey)
            if encrypted:
                stored_data[st.session_state.authenticated_user]["data"] = encrypted
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully.")
            else:
                st.error("❌ Encryption failed.")
    else:
        st.warning("🔒 Please login to store data.")

# === Retrieve Data ===
elif choice == "📂 Retrieve Data":
    if st.session_state.authenticated_user:
        st.markdown("## 📂 Retrieve Your Data")
        passkey = st.text_input("🔑 Enter decryption passkey", type="password")
        if st.button("🔓 Decrypt & View"):
            encrypted = stored_data[st.session_state.authenticated_user].get("data", "")
            if encrypted:
                decrypted = decrypt_text(encrypted, passkey)
                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted)
                else:
                    st.error("❌ Invalid passkey or decryption failed.")
            else:
                st.info("ℹ️ No data found for your account.")
    else:
        st.warning("🔐 Please login to retrieve data.")
