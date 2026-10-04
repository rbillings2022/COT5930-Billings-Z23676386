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

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_community.tools import WikipediaQueryRun
from langchain_community.utilities import WikipediaAPIWrapper
from langchain_core.tools import tool
from langchain_experimental.utilities import PythonREPL
from langchain_ollama import ChatOllama

load_dotenv()

SYSTEM_PROMPT = (
    "You are a helpful cybersecurity assistant. Use the available tools "
    "whenever they help: python_repl for calculations or code, wikipedia for "
    "background facts, check_password_strength to evaluate passwords, and "
    "sha256_hash to hash text. Explain your final answer clearly."
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

    Returns:
        A compiled LangChain agent ready to be invoked with messages.
    """
    llm = ChatOllama(
        base_url=os.environ["OLLAMA_BASE_URL"],
        model=os.environ["OLLAMA_MODEL"],
        temperature=0,
        client_kwargs={"timeout": 300},  # remote model can be slow
    )
    wikipedia = WikipediaQueryRun(
        api_wrapper=WikipediaAPIWrapper(top_k_results=2, doc_content_chars_max=1500)
    )
    tools = [python_repl, wikipedia, check_password_strength, sha256_hash]
    return create_agent(llm, tools, system_prompt=SYSTEM_PROMPT)


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