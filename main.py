import streamlit as st
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {} 

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authenticated" not in st.session_state:
    st.session_state.authenticated = True  

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> str or None:
    hashed_passkey = hash_passkey(passkey)
    stored = st.session_state.stored_data.get(encrypted_text)

    if stored and stored["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0 
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None


st.title("Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

# Home Page
if choice == "Home":
    st.header("🏠 Welcome")
    st.markdown("Use this tool to **store and retrieve encrypted data** securely using a unique passkey.")

# Store Data Page
elif choice == "Store Data":
    st.header("Store Data Securely")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("Your data has been securely stored!")
            st.code(encrypted, language="text")
        else:
            st.warning("Please fill in both the data and passkey fields.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.authenticated:
        st.warning("Reauthentication required due to too many failed attempts.")
        st.switch_page("Login")
    else:
        st.header("Retrieve Encrypted Data")
        encrypted_text = st.text_area("Enter the encrypted data:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                result = decrypt_data(encrypted_text, passkey)
                if result:
                    st.success("Data decrypted successfully:")
                    st.code(result, language="text")
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    if attempts_left > 0:
                        st.error(f"Incorrect passkey. Attempts left: {attempts_left}")
                    else:
                        st.session_state.authenticated = False
                        st.warning("Too many failed attempts! Redirecting to Login...")
                        st.experimental_rerun()
            else:
                st.warning("Please fill in all fields.")

# Login Page
elif choice == "Login":
    st.header("Reauthorization Required")
    login_pass = st.text_input("Enter Master Password (demo: admin123):", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.success("Reauthorization successful. You may now retrieve data again.")
            st.experimental_rerun()
        else:
            st.error("Incorrect password!")
