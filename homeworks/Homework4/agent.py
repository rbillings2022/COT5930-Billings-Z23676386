import os
import readline
from langchain.agents import create_agent
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
import asyncio


llm

server = StdioServerParameters(command = "python",args=["mcp-server.py", "stdio"])

async def run_agent():
    prompt = f"""You are a login Pentest tool that will only run 6 attempts from 
                each tool. Perform tests with the tools and return back any vulnerabilities
                . Also, guess the logic being used for the login code based off your interactions."""
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await load_mcp_tools(session)
            agent = create_agent(model=llm, tools=tools, system_prompt=prompt)

            while True:
                user_prompt = input("Enter Prompt>> ")
                if user_prompt:
                    try:
                        # Get result from agent
                        result = await agent.ainvoke({"messages": [("user", user_prompt)]})

                        print(f"\n RESULT FROM AGENT: {result}")
                        print(f"Tools used: {tools}")

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

if __name__ == "__main__":
    result = asyncio.run(run_agent())
    print(result)