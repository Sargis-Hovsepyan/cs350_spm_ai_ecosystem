import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")
chat = model.start_chat(history=[])

with open('database.txt', 'r', encoding='utf-8') as f:
    jokes = f.read()


def create_first_prompt(query):
    return (f"I want to talk to you in Armenian like a bro and for that I will give you context(jokes and slang in Armenian) which you should use and "
            f"a prompt. Respond only to the prompt and try to maximize the use of the jokes and slang in Armenian that " 
            f"I am giving to you(make sure you are like native conversational Armenian speaker because my joke text contains some phonetic mistakes and"
            f"do not always cite the jokes. Be natural like talking to a bro.). Also keep the responses compact, do not write very long responses."
            f" Context:{jokes}\n\nPrompt:{query}")


if __name__ == '__main__':
    prompt = create_first_prompt("Կճեպին գիտե՞ս")
    response = chat.send_message(prompt)
    print(response.text)
