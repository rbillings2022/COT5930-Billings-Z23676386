import json
from typing import Any

import ollama
from fastmcp import FastMCP

MODEL_NAME = "bonsai-2:9b"

mcp = FastMCP("social-engineering-threat-detector")


@mcp.tool()


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
