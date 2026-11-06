import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fastmcp import FastMCP
from homework6 import analyze_email_content, analyze_submission, analyze_text_prompt, assess_chat_history, calculate_score, parse_email_message

mcp = FastMCP('social-engineering-threat-detector')


@mcp.tool()
def parse_email_file(file_path: str) -> dict:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f'Email file not found: {file_path}')
    return parse_email_message(path.read_text(encoding='utf-8', errors='ignore'))


@mcp.tool()
def analyze_message_text(message: str, relationship: str = 'Unknown Contact', source: str = 'Text', history: list[str] | None = None) -> dict:
    return analyze_text_prompt(message, relationship, source, history or [])


@mcp.tool()
def score_message(message: str, relationship: str = 'Unknown Contact', source: str = 'Text', history: list[str] | None = None) -> dict:
    return calculate_score(message, relationship, source, history or [])


@mcp.tool()
def assess_chat_context(history: list[str], latest_message: str, relationship: str = 'Unknown Contact', source: str = 'Chat') -> dict:
    return assess_chat_history(history, latest_message, relationship, source)


@mcp.tool()
def parse_email_text(raw_email: str, relationship: str = 'Unknown Contact', source: str = 'Email') -> dict:
    return analyze_email_content(raw_email, relationship, source)


@mcp.tool()
def process_submission(payload: dict) -> dict:
    return analyze_submission(payload)


def main() -> None:
    mcp.run(transport='stdio')


if __name__ == '__main__':
    main()
