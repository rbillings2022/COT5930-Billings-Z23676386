import sqlite3
import hashlib 
import datetime

con = sqlite3.connect("db_data/mcp-server.db")
cur = con.cursor()

con.execute("""CREATE TABLE IF NOT EXISTS user(
    id integer primary key autoincrement, 
    username text, 
    password text,
    time_stamp text
)""")
con.execute("""CREATE TABLE IF NOT EXISTS audit_log(
    id integer primary key autoincrement,
    ip text,
    failed_attempts integer,
    time_stamp text
)""")
con.commit()

def login(username:str, password:str, ip:str):

    time_stamp = datetime.datetime.now()
    failed_attempts = 0

    search_username = cur.execute("SELECT username FROM user where username = ?", (username,))
    search_ip = cur.execute("SELECT ip FROM audit_log WHERE ip = ?", (ip,))
    search_password = cur.execute("SELECT password FROM user WHERE password = ?",(password,))
    response_password = search_password.fetchone()
    response_username = search_username.fetchone()
    response_ip = search_ip.fetchone()

    # If the username doesn't exist and this is the machines first attempt, begin incrementing fails
    if password != response_password and response_ip == None:
        failed_attempts += 1
        cur.execute("INSERT INTO audit_log (ip, failed_attempts, time_stamp) VALUES(?,?,?)", (ip, failed_attempts, time_stamp))
        con.commit()
        return "Sorry, please try logging in again."
    
    elif ip in response_ip and password not in response_password:
        search_attempts = cur.execute("SELECT failed_attempts FROM audit_log WHERE ip = ?",(ip,))
        failed_attempts = search_attempts.fetchone()
        failed_attempts += 1
        cur.execute("UPDATE audit_log SET failed_attempts = ? WHERE ip = ?",(failed_attempts, ip))
        con.commit()
        return f"Sorry, please try again, current failed attempts {failed_attempts}"
    
    elif password in response_password  and username in response_username:
        return "Congrates! You've successfully logged in!" 

def create(username, password):
    current_time = datetime.datetime.now()

    # Hash password
    password = hashlib.sha256(password).hexdigest()

    search = cur.execute("SELECT username FROM user WHERE username = ?", (username,))
    response = search.fetchone()

    # If the username exists, return a message and do not add it to the DB
    if username in response:
        return "Sorry, username already exists. Maybe try logging in?"
    else:
        cur.execute("INSERT INTO user VALUES(?,?,?)", username, password, current_time)
        con.commit()
        return "You've successfully created your account."

# Toy user interface
def main():

    # ADD AN EXCEPTION HANDLING
    action = input("Type '1' to log-in or type '2' to create account: ")

    # Login
    if action == '1':
        username = input("Please enter a username: ").lower() # normalize any username to lowercase
        password = input("Please enter a password: ").encode('utf-8')
        password = hashlib.sha256(password).hexdigest()
        ip = input("Enter ip: ")
        response = login(username, password, ip)

        print(response)
    # Create account
    elif action == '2':
        username = input("Please enter a username: ").lower()
        password = input("Please enter a password: ").encode("utf-8")
        response = create(username, password)

        print(response)

if __name__ == "__main__":
    main()