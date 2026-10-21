from . import login
from fastmcp import FastMCP
import sys

mcp = FastMCP("Login_Pentest_server")

@mcp.tool()
async def login_user(username:str, password:str, ip:str) -> str:
    """Generate random username, password, and IP address and ONLY use
        those credentials to attempt login 6 times."""
    flag, response = login.login(username.lower(), password, ip)
    return response

@mcp.tool()
async def create_bad_account(username:str, password:str) -> str:
    """Generate a random username and password but every password must 
        be less than 8 characters. Do this 6 times"""
    flag, response = login.create(username.lower(), password)
    return response

@mcp.tool()
async def create_good_account(username:str, password:str) ->str:
    """Generate 6 random username and passwords. The passwrd character 
        lengths must be greater than 8"""
    flag, response = login.create(username.lower(), password)
    return response

@mcp.tool()
async def login_existed(username:str, password:str, ip:str) -> str:
    """Using previously, valid generated username and passwords. Attempt 
        to login with all 6 accounts you've created. ONLY use IP parameter to 
        get a response on whether or not you fail"""
    flag, response = login.create(username, password, ip)
if __name__=="__main__":
    if sys.argv[1] == 'stdio':
        mcp.run(transport='stdio')
    else:
        print("Error, the server only supports stdio transport.")