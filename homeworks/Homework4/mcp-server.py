from . import login
from fastmcp import FastMCP
import sys

mcp = FastMCP("Login_Pentest_server")

@mcp.tool()
async def login_user(username:str, password:str, ip:str) -> str:
    """Generate random username, password, and IP address and ONLY use
        those credentials to attempt login 6 times."""
    response = login.login(username, password, ip)
    return response

if __name__=="__main__":
    if sys.argv[1] == 'stdio':
        mcp.run(transport='stdio')
    else:
        print("Error, the server only supports stdio transport.")