"""Security-assistant LangChain agent running on a remote Ollama server.

Tools:
    - python_repl: run Python code (required by the assignment)
    - wikipedia: look up background information (built-in tool)
    - check_password_strength: custom tool that scores a password
    - sha256_hash: custom tool that hashes text

Configuration comes from environment variables (see .env):
    OLLAMA_BASE_URL, OLLAMA_MODEL
"""
import hashlib
import os
import re
from pathlib import Path
import requests

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_community.tools import (
    ArxivQueryRun,
    DuckDuckGoSearchRun,
    WikipediaQueryRun,
)
from langchain_community.utilities import ArxivAPIWrapper, WikipediaAPIWrapper
from langchain_core.tools import tool
from langchain_experimental.utilities import PythonREPL
from langchain_ollama import ChatOllama

load_dotenv()

# The agent may only read/write files inside this folder.
WORKSPACE = Path(__file__).parent / "workspace"

SYSTEM_PROMPT = (
    "You are a helpful cybersecurity assistant. Use the available tools "
    "whenever they help: python_repl for calculations or code, wikipedia for "
    "background facts, duckduckgo_search for current web information, "
    "arxiv for research papers, check_password_strength to evaluate "
    "passwords, sha256_hash to hash text, and the file tools (read_file, "
    "write_file, list_directory) to save or read notes in your workspace. "
    "Explain your final answer clearly."
)

_repl = PythonREPL()


@tool
def python_repl(code: str) -> str:
    """Execute Python code and return what it prints.

    The input must be valid Python. Use print() to see any value.

    Args:
        code: The Python source code to run.

    Returns:
        The captured stdout, or the error message if execution failed.
    """
    try:
        return _repl.run(code)
    except Exception as exc:  # surface errors to the agent so it can retry
        return f"Error: {exc}"


@tool
def check_password_strength(password: str) -> str:
    """Score a password from 0 to 5 and list what is missing.

    Args:
        password: The password to evaluate.

    Returns:
        A short report with the score, a rating, and improvement tips.
    """
    checks = {
        "at least 12 characters": len(password) >= 12,
        "a lowercase letter": bool(re.search(r"[a-z]", password)),
        "an uppercase letter": bool(re.search(r"[A-Z]", password)),
        "a digit": bool(re.search(r"\d", password)),
        "a special character": bool(re.search(r"[^\w\s]", password)),
    }
    score = sum(checks.values())
    rating = ["Very weak", "Very weak", "Weak", "Fair", "Good", "Strong"][score]
    missing = [name for name, ok in checks.items() if not ok]
    tips = "none" if not missing else "add " + ", ".join(missing)
    return f"Score {score}/5 ({rating}). Improvements: {tips}."


@tool
def sha256_hash(text: str) -> str:
    """Return the SHA-256 hex digest of the given text.

    Args:
        text: The text to hash.

    Returns:
        The 64-character hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_agent():
    """Create the tool-calling agent backed by the remote Ollama model.

    Tools: PythonREPL, Wikipedia, DuckDuckGo search, Arxiv, a sandboxed
    file-management toolkit, and two custom security tools.

    Returns:
        A compiled LangChain agent ready to be invoked with messages.
    """
    llm = ChatOllama(
        base_url=os.environ["OLLAMA_BASE_URL"],
        model=os.environ["OLLAMA_MODEL"],
        temperature=0,
        client_kwargs={"timeout": 300},  # remote model can be slow
    )
    duckduckgo = DuckDuckGoSearchRun()
    arxiv = ArxivQueryRun(
        api_wrapper=ArxivAPIWrapper(top_k_results=2, doc_content_chars_max=1500)
    )

    # Sandbox the file tools: one folder, and only safe operations.
    # file_delete, move_file, and copy_file are deliberately left out.
    WORKSPACE.mkdir(exist_ok=True)
    file_tools = FileManagementToolkit(
        root_dir=str(WORKSPACE),
        selected_tools=["read_file", "write_file", "list_directory"],
    ).get_tools()

    tools = [
        python_repl,
        wikipedia,
        duckduckgo,
        arxiv,
        check_password_strength,
        sha256_hash,
        *file_tools,
    ]
    return create_agent(llm, tools, system_prompt=SYSTEM_PROMPT)

@tool
def wikipedia_search(query: str) -> str:
    """Look up a topic on Wikipedia and return a short summary.

    Use only when the user asks for factual background on a topic.

    Args:
        query: The topic to search for, for example "SHA-2".

    Returns:
        The top matching article titles with extract text, or an error message.
    """
    headers = {"User-Agent": "hw3-security-agent/1.0 (student project)"}
    params = {
        "action": "query",
        "generator": "search",
        "gsrsearch": query,
        "gsrlimit": 2,
        "prop": "extracts",
        "exintro": 1,
        "explaintext": 1,
        "format": "json",
    }
    try:
        resp = requests.get(
            "https://en.wikipedia.org/w/api.php",
            params=params,
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        pages = resp.json().get("query", {}).get("pages", {})
    except Exception as exc:  # network error or non-JSON reply
        return f"Wikipedia lookup failed: {exc}"
    if not pages:
        return "No Wikipedia results found."
    return "\n\n".join(
        f"{p['title']}: {p.get('extract', '')[:1200]}" for p in pages.values()
    )

def ask(agent, question: str) -> str:
    """Send one question to the agent, printing each tool call it makes.

    Args:
        agent: The agent returned by build_agent().
        question: The user's question.

    Returns:
        The agent's final text answer.
    """
    result = agent.invoke({"messages": [{"role": "user", "content": question}]})
    for msg in result["messages"]:
        for call in getattr(msg, "tool_calls", None) or []:
            print(f"  [tool call] {call['name']}({call['args']})")
    return result["messages"][-1].content


def main() -> None:
    """Run an interactive chat loop in the terminal."""
    agent = build_agent()
    print("Security agent ready. Type 'exit' to quit.")
    while True:
        question = input("\nYou: ").strip()
        if question.lower() in {"exit", "quit"}:
            break
        if question:
            print(f"\nAgent: {ask(agent, question)}")


if __name__ == "__main__":
    main()