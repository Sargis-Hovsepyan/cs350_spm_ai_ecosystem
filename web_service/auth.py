import streamlit as st
from sqlalchemy import create_engine, Column, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
import re
import os
import uuid

# ---------- DB SETUP ----------
DB_PATH = os.path.join(os.path.dirname(__file__), "kargin_users.db")

# Delete existing DB if it exists (fresh start)
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)  # unique ID for DB
    username = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    verified = Column(Boolean, default=True)


def init():
    """Create tables if not exist."""
    Base.metadata.create_all(engine)


# ---------- PASSWORD & AUTH ----------
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def validate_password(password: str) -> tuple[bool, list[str]]:
    """Check all constraints at once"""
    errors = []
    if len(password) < 8:
        errors.append("• Պետք է ունենա առնվազն 8 նիշ")
    if not re.search(r"[A-Z]", password):
        errors.append("• Պետք է պարունակի մեծատառ")
    if not re.search(r"[a-z]", password):
        errors.append("• Պետք է պարունակի փոքրատառ")
    if not re.search(r"\d", password):
        errors.append("• Պետք է պարունակի թիվ")
    if not re.search(r"[@$!%*?&#]", password):
        errors.append("• Պետք է պարունակի հատուկ նիշ (օր.` @, #, $)")
    return (len(errors) == 0, errors)


def validate_email(email: str) -> bool:
    """Simple regex to validate email format"""
    if not email:
        return False
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def register_user(username: str, password: str, email: str):
    session = SessionLocal()

    # Only email must be unique
    existing_email = session.query(User).filter_by(email=email).first()
    if existing_email:
        session.close()
        return False, ["Այս էլ. փոստը արդեն օգտագործված է։"]

    if not validate_email(email):
        session.close()
        return False, ["Մուտքագրված էլ. փոստը վավեր չէ։"]

    valid, errors = validate_password(password)
    if not valid:
        session.close()
        return False, errors

    hashed = hash_password(password)

    # Generate a unique ID for DB
    user = User(id=str(uuid.uuid4()), username=username, password_hash=hashed, email=email)
    session.add(user)
    session.commit()
    session.close()
    return True, ["Գրանցումը հաջողությամբ ավարտվեց։"]


def verify_user(username_or_email: str, password: str) -> bool:
    """Verify by username OR email"""
    session = SessionLocal()
    user = session.query(User).filter_by(username=username_or_email).first()
    if not user:
        user = session.query(User).filter_by(email=username_or_email).first()
    session.close()
    if not user:
        return False
    return verify_password(password, user.password_hash)


def logout_user():
    st.session_state["authenticated"] = False
    st.session_state["username"] = None


# ---------- STREAMLIT UI ----------
def show_auth_ui():
    st.title("Բարի գալուստ KarginGPT 🤙🏼")
    st.write("Խնդրում ենք մուտք գործել կամ գրանցվել՝ շարունակելու համար։")

    tab_login, tab_register = st.tabs(["🔑 Մուտք գործել", "📝 Գրանցվել"])

    # -------- LOGIN TAB --------
    with tab_login:
        login_input = st.text_input("Օգտանուն կամ էլ. փոստ", key="login_input")
        login_password = st.text_input("Գաղտնաբառ", type="password", key="login_password")
        if st.button("Մուտք գործել", key="login_btn"):
            if verify_user(login_input, login_password):
                st.session_state["authenticated"] = True
                st.session_state["username"] = login_input
                st.success("Դու հաջողությամբ մուտք գործեցիր։")
                st.rerun()
            else:
                st.error("Սխալ օգտանուն կամ գաղտնաբառ։")

    # -------- REGISTER TAB --------
    with tab_register:
        reg_username = st.text_input("Օգտանուն", key="register_username")
        reg_email = st.text_input("Էլ. փոստ", key="register_email")
        reg_password = st.text_input("Գաղտնաբառ", type="password", key="register_password")
        reg_confirm = st.text_input("Կրկնիր գաղտնաբառը", type="password", key="register_confirm")

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

        if st.button("Գրանցվել", key="register_btn"):
            if reg_password != reg_confirm:
                st.error("Գաղտնաբառերը չեն համընկնում։")
            else:
                success, messages = register_user(reg_username, reg_password, reg_email)
                if success:
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = reg_username
                    st.success("Գրանցումը հաջողությամբ ավարտվեց։ Դուք ավտոմատ կերպով մուտք գործեցիք։")
                    st.rerun()
                else:
                    for msg in messages:
                        st.error(msg)


# ---------- ENTRY POINT ----------
def ensure_auth():
    init()

    class DummyAuthenticator:
        def logout_button(self):
            if st.sidebar.button("Դուրս գալ", key="logout_btn"):
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