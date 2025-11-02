import streamlit as st
import sqlite3
import os
import hashlib
import re

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")


# ---------- DB SETUP ----------
def init():
    """Initialize users table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            email TEXT,
            verified INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """Return SHA256 hash of password."""
    return hashlib.sha256(password.encode()).hexdigest()


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """Check all password constraints at once."""
    errors = []

    if len(password) < 8:
        errors.append("• Պետք է ունենա առնվազն 8 նիշ։")
    if not re.search(r"[A-Z]", password):
        errors.append("• Պետք է պարունակի մեծատառ։")
    if not re.search(r"[a-z]", password):
        errors.append("• Պետք է պարունակի փոքրատառ։")
    if not re.search(r"\d", password):
        errors.append("• Պետք է պարունակի թիվ։")
    if not re.search(r"[@$!%*?&#]", password):
        errors.append("• Պետք է պարունակի հատուկ նիշ (օր.` @, #, $):")

    if errors:
        return False, errors
    return True, []


def register_user(username, password, email):
    """Add new user to DB with validation."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT username FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return False, ["Օգտանունն արդեն գրանցված է։"]

    valid, errors = validate_password_strength(password)
    if not valid:
        conn.close()
        return False, errors

    c.execute(
        "INSERT INTO users (username, password_hash, email, verified) VALUES (?, ?, ?, ?)",
        (username, hash_password(password), email, 1),
    )
    conn.commit()
    conn.close()
    return True, ["Գրանցումը հաջողությամբ ավարտվեց։"]


def verify_user(username, password):
    """Verify credentials."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return False
    return row[0] == hash_password(password)


def logout_user():
    st.session_state["authenticated"] = False
    st.session_state["username"] = None


# ---------- STREAMLIT AUTH UI ----------
def show_auth_ui():
    """Render Armenian login/register UI on the main page."""
    st.title("Բարի գալուստ KarginGPT 🤙🏼")

    st.write("Խնդրում ենք մուտք գործել կամ գրանցվել՝ շարունակելու համար։")
    tab_login, tab_register = st.tabs(["🔑 Մուտք գործել", "📝 Գրանցվել"])

    # ---------------------- LOGIN TAB ----------------------
    with tab_login:
        username = st.text_input("Օգտանուն", key="login_username")
        password = st.text_input("Գաղտնաբառ", type="password", key="login_password")

        if st.button("Մուտք գործել", key="login_button"):
            if verify_user(username, password):
                st.session_state["authenticated"] = True
                st.session_state["username"] = username
                st.success("Դու հաջողությամբ մուտք գործեցիր։")
                st.rerun()
            else:
                st.error("Սխալ օգտանուն կամ գաղտնաբառ։")

    # ---------------------- REGISTER TAB ----------------------
    with tab_register:
        username = st.text_input("Նոր օգտանուն", key="register_username")
        email = st.text_input("Էլ. փոստ", key="register_email")
        password = st.text_input("Գաղտնաբառ", type="password", key="register_password")
        confirm = st.text_input("Կրկնիր գաղտնաբառը", type="password", key="register_confirm")

        # Show password rules
        st.info(
            """
            **Գաղտնաբառի պահանջներ**
            - Պետք է ունենա առնվազն 8 նիշ  
            - Պետք է պարունակի մեծատառ  
            - Պետք է պարունակի փոքրատառ  
            - Պետք է պարունակի թիվ  
            - Պետք է պարունակի հատուկ նիշ (օր.` @, #, $, և այլն)
            """
        )

        if st.button("Գրանցվել", key="register_button"):
            if password != confirm:
                st.error("Գաղտնաբառերը չեն համընկնում։")
            else:
                success, messages = register_user(username, password, email)
                if success:
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = username
                    st.success("Գրանցումը հաջողությամբ ավարտվեց։ Դուք ավտոմատ կերպով մուտք գործեցիք։")
                    st.rerun()
                else:
                    for msg in messages:
                        st.error(msg)


# ---------- MAIN ENTRY ----------
def ensure_auth():
    """
    Entry point for app.py.
    Returns (auth_status, name, username, config, authenticator)
    """
    init()

    class DummyAuthenticator:
        def logout_button(self):
            if st.sidebar.button("Դուրս գալ", key="logout_button"):
                logout_user()
                st.rerun()

    authenticator = DummyAuthenticator()

    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if not st.session_state["authenticated"]:
        show_auth_ui()

    auth_status = st.session_state.get("authenticated", False)
    username = st.session_state.get("username")
    name = username
    config = None

    return auth_status, name, username, config, authenticator
