# tools/hash_passwords.py
import streamlit_authenticator as stauth

plain_pw = "ChangeMe123!"

try:
    # Newer API (0.4.x+): Hasher() then hash(...)
    hasher = stauth.Hasher()
    hashed = hasher.hash(plain_pw)  # or hasher.generate(plain_pw) depending on your installed version
except TypeError:
    # Older API (0.3.x): Hasher([...]).generate()[0]
    hashed = stauth.Hasher([plain_pw]).generate()[0]

print(hashed)