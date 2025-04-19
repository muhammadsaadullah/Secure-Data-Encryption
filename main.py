import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# File to store the encryption key
KEY_FILE = "secret.key"

# Load key if it exists, otherwise generate and save it
def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

# Retrieve the encryption key from Streamlit Cloud Secrets (for deployment)
# You can comment out this line when running locally and use `load_key()` for local testing
KEY = st.secrets["encryption_key"]  # Securely stored key in Streamlit Cloud secrets
cipher = Fernet(KEY)

# File to store encrypted data
DataFile = os.path.join(os.getcwd(), "data.json")

# Initialize session state for failed attempts
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Function to get data from the file
def get_data():
    if os.path.exists(DataFile):
        with open(DataFile, "r") as f:
            return json.load(f)
    return {}

# Load data from file on startup
# In-memory data storage
# stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
stored_data = get_data()  # Load data from file on startup

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# Function to save data into the JSON file
def save_data():
    with open(DataFile, "w") as f:
        json.dump(stored_data, f, indent=4)

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# -------------------- Home --------------------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# -------------------- Store Data --------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)

            # Add to stored data with a simple incremental key schema
            data_key = f"a{len(stored_data) + 1}"  # Keys: a1, a2, ...
            stored_data[data_key] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data()

            st.success("✅ Data stored securely!")
            st.write("🔐 **Encrypted Data (copy & save it somewhere safe):**")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Both fields are required!")

# -------------------- Retrieve Data --------------------
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            try:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")

                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.rerun()
            except Exception as e:
                st.error("❌ Invalid token or corrupt data.")
        else:
            st.error("⚠️ Both fields are required!")

# -------------------- Login --------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.rerun()
        else:
            st.error("❌ Incorrect password!")
