import sys
import os

HW4_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Homework4")
sys.path.insert(0, os.path.abspath(HW4_DIR))
from langchain.agents import create_agent
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
import asyncio
from langchain_ollama import ChatOllama


llm = ChatOllama(
    model="llama3.1:8b",
    base_url="http://localhost:11434",
)
prompt = f"""You are a login Pentest tool that will only run 6 attempts from 
            each tool. Perform tests with the tools and return back any vulnerabilities
            . Also, guess the logic being used for the login code based off your interactions.
            Use mcp-server-fetch a fetch tool to look up credible material about vulnerabilities and compare that
            to your interaction with the APIs of my script. Coordinate with my local MCP server along with
            mcp-server-fetch"""

# Locally ran PERSONAL MCP server
server = StdioServerParameters(command = "python",args=["mcp-server.py", "stdio"], cwd=os.path.abspath(HW4_DIR),)
mcp_market_place_server = StdioServerParameters(command="uvx", args=["mcp-server-fetch"])
async def run_agent():
    async with stdio_client(server) as (read1, write1), stdio_client(mcp_market_place_server) as (read2, write2):
        async with ClientSession(read1, write1) as session1, ClientSession(read2, write2) as session2:
            await session1.initialize()
            await session2.initialize()

            tools = await load_mcp_tools(session1) + await load_mcp_tools(session2)
            agent = create_agent(model=llm, tools=tools, system_prompt=prompt)

            while True:
                user_prompt = input("Enter Prompt>> ")
                if user_prompt:
                    try:
                        # Get result from agent
                        result = await agent.ainvoke({"messages": [("user", user_prompt)]})

                        print(f"\n RESULT FROM AGENT: {result}")
                        for tool in tools:
                            print(f"\nTools used NAME: {tools.name}")
                            print(f"Tools used Description: {tools.description}")

                        # Only extract the message key from the dictionary/JSON field
                        if "messages" in result:
                            messages = result["messages"]
                            if messages:
                                last_message = messages[-1]
                                if hasattr(last_message, 'content'):
                                    if isinstance(last_message.content, list) and isinstance(last_message.content[0], dict):
                                        print(f"{last_message.content[0]['text']}")
                                    else:
                                        print(f"{last_message.content}")
                                else:
                                    print(f"{last_message}")
                            else:
                                print("No response from agent")
                        else:
                            print(f"Agent response: {result}")
                    except Exception as e:
                        print(f"Error: {e}")
                else:
                    break

"""
    Purpose: Switch away from mcp-server-fetch and default to using my Local stdio MCP server.
    Description: This block of code is a test agent that returns it's responses in order for the pretext script
        to interact with the agent as if it were an API."""
from langchain_core.tools import tool

@tool("mcp-server-fetch")
def mcp_server_fetch(cmd: str = "", tool: str = "", **kwargs) -> str:
    """Fetch tool used for looking up vulnerability research."""
    return (
        "mcp-server-fetch is not connected in this session. "
        "Use only the tools already provided to you (login_user, create_bad_account, "
        "create_good_account, login_existed) to continue the pentest."
    )

async def pentest_agent(user_prompt: str) -> dict:
    """Runs a single prompt through the pentest agent and returns the raw result."""
    async with stdio_client(server) as (read1, write1):
        async with ClientSession(read1, write1) as session1:
            await session1.initialize()
            tools = await load_mcp_tools(session1)
            agent = create_agent(model=llm, tools=tools + [mcp_server_fetch], system_prompt=prompt)
            return await agent.ainvoke({"messages": [("user", user_prompt)]})
        
if __name__ == "__main__":
    result = asyncio.run(run_agent())
    print(result)