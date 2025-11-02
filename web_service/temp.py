import inspect
from streamlit_authenticator.views.authentication_view import Authenticate
print("login signature:", inspect.signature(Authenticate.login))
print("register signature:", inspect.signature(Authenticate.register_user))
print("logout signature:", inspect.signature(Authenticate.logout))