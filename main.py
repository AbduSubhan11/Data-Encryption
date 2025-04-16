import streamlit as st
import hashlib
import base64

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {} 

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authenticated" not in st.session_state:
    st.session_state.authenticated = True  

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str, passkey: str) -> str:
    key = hash_passkey(passkey)[:32]  # Use a derived key (first 32 chars)
    combined = f"{text}|{key}"
    encoded = base64.urlsafe_b64encode(combined.encode()).decode()
    return encoded

def decrypt_data(encrypted_text: str, passkey: str) -> str or None:
    try:
        decoded = base64.urlsafe_b64decode(encrypted_text.encode()).decode()
        original_text, key = decoded.rsplit('|', 1)
        if key == hash_passkey(passkey)[:32]:
            st.session_state.failed_attempts = 0
            return original_text
        else:
            st.session_state.failed_attempts += 1
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        return None

st.title("Secure Data Encryption System (Base64 Version)")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.header("🏠 Welcome")
    st.markdown("Use this tool to **store and retrieve encoded data** securely using a passkey.")

elif choice == "Store Data":
    st.header("Store Data Securely")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data, passkey)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hash_passkey(passkey)
            }
            st.success("Your data has been securely stored!")
            st.code(encrypted, language="text")
        else:
            st.warning("Please fill in both the data and passkey fields.")

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
