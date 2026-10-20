import sqlite3
import hashlib 

con = sqlite3.connect("db_data/mcp-server.db")
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()

con.execute("""CREATE TABLE IF NOT EXISTS user(
    id integer primary key autoincrement, 
    username text, 
    password text
)""")
con.execute("""CREATE TABLE IF NOT EXISTS audit_log(
    id integer primary key autoincrement,
    user_id integer,
    ip text,
    failed_attempts integer,
    time_stamp text,
    FOREIGN KEY (user_id) REFERENCES user(id)
)""")
con.commit()

def login(username, password):
    password = hashlib.sha256(password).hexdigest()

    pass

def create(username, password):
    pass

# Toy user interface
def main():

    # ADD AN EXCEPTION HANDLING
    action = input("Type '1' to log-in or type '2' to create account: ")

    # Login
    if action == '1':
        username = input("Please enter a username: ")
        password = input("Please enter a password: ")
        response = login(username, password)

        print(response)
    # Create account
    elif action == '2':
        username = input("Please enter a username: ")
        password = input("Please enter a password: ").encode("utf-8")
        response = create(username, password)

        print(response)

if __main__ == "__name__":
    main()