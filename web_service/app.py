import sys
import os
import streamlit as st
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from text2text.rag import chat, create_first_prompt
from auth import ensure_auth

st.set_page_config(page_title="KarginGPT", page_icon="🤙🏼", layout="wide")

auth_status, name, username, config, authenticator = ensure_auth()

if auth_status:
    st.title("KarginGPT 🤙🏼")

    with st.sidebar:
        st.caption(f"Բարի գալուստ, **{username}** 👋🏼")
        st.markdown("---")

        authenticator.logout_button()
        st.markdown("---")

        st.header("📚 Զրույցներ")
        if "conversations" not in st.session_state:
            st.session_state.conversations = {}
            st.session_state.selected_chat = None
            st.session_state.chat_objects = {}

        chat_names = list(st.session_state.conversations.keys())

        if st.button("➕ Նոր զրույց", key="new_chat"):
            new_chat_name = f"Զրույց {len(chat_names) + 1}"
            st.session_state.conversations[new_chat_name] = []
            model = chat.model
            st.session_state.chat_objects[new_chat_name] = model.start_chat(history=[])
            st.session_state.selected_chat = new_chat_name
            chat_names = list(st.session_state.conversations.keys())

        if chat_names:
            selected = st.radio(
                "Ընտրիր զրույցը",
                chat_names,
                index=chat_names.index(st.session_state.selected_chat)
                if st.session_state.selected_chat in chat_names else 0,
                key="chat_selector",
            )
            st.session_state.selected_chat = selected

    # MAIN CHAT AREA
    if not st.session_state.selected_chat:
        new_chat_name = "Զրույց 1"
        st.session_state.conversations[new_chat_name] = []
        model = chat.model
        st.session_state.chat_objects[new_chat_name] = model.start_chat(history=[])
        st.session_state.selected_chat = new_chat_name

    messages = st.session_state.conversations[st.session_state.selected_chat]
    chat_obj = st.session_state.chat_objects[st.session_state.selected_chat]

    for message in messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    user_input = st.chat_input("Գրիր մի բան…")

    if user_input:
        prompt = create_first_prompt(user_input) if not messages else user_input

        messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        response = chat_obj.send_message(prompt)
        with st.chat_message("assistant"):
            placeholder = st.empty()
            full_response = ""
            for chunk in response.text.split():
                full_response += chunk + " "
                time.sleep(0.03)
                placeholder.markdown(full_response + "▌")
            placeholder.markdown(full_response)

        messages.append({"role": "assistant", "content": response.text})

else:
    st.stop()  # Auth UI already rendered in auth.py