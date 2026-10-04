"""Quick connectivity check for the remote Ollama server."""
import os

from dotenv import load_dotenv
from langchain_ollama import ChatOllama

load_dotenv()
llm = ChatOllama(
    base_url=os.environ["OLLAMA_BASE_URL"],
    model=os.environ["OLLAMA_MODEL"],
)
print(llm.invoke("Say hello in five words.").content)