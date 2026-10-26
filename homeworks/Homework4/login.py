import sqlite3
import hashlib 
import datetime
import hmac

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

def login(username: str, password: str, ip: str):
    """
        Description:
            This function is a toy login system where a user can validate their 
            credentials if they exist in the database. If you're a user thats attempting
            to bruteforce username and passwords into the system, it will count failed attempts

        Return:
            Flag
            Message
    """
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    time_stamp = datetime.datetime.now()

    user_row = con.execute("SELECT password FROM user WHERE username = ?",(username,)).fetchone()

    if user_row is not None and hmac.compare_digest(user_row[0], password_hash):
        return 0, "Congratulations! You've successfully logged in."

    attempt_row = con.execute("SELECT id, failed_attempts FROM audit_log WHERE ip = ? ORDER BY id DESC LIMIT 1",(ip,)).fetchone()
    if attempt_row is None:
        failed_attempts = 1
        cur.execute("INSERT INTO audit_log (ip, failed_attempts, time_stamp) VALUES (?, ?, ?)",(ip, failed_attempts, time_stamp),
        )
    else:
        failed_attempts = attempt_row[1] + 1
        cur.execute(
            "UPDATE audit_log SET failed_attempts = ? WHERE id = ?",
            (failed_attempts, attempt_row[0]),
        )

    con.commit()
    return 1, f"Sorry, please try again. Current failed attempts: {failed_attempts}"

def create(username, password):
    """
        Description:
            This is a create accoutn function which will store credentials in a database
            It will check if a username exists and if youre password characters are long enough.

        Return:
            Flag
            Message
    """
    password = password.encode('utf-8')
    current_time = datetime.datetime.now()

    # Search for username 
    search = cur.execute("SELECT username FROM user WHERE username = ?", (username,))
    response = search.fetchone()

    # If the username exists, return a message and do not add it to the DB
        # Return Error message or Success message and a flag to keep the program running
    if response == None:
        if len(password) < 8:
            return 1,"Sorry, password needs to be at least 8 chaaracters long, please try again."
        else:
            password = hashlib.sha256(password).hexdigest()
            cur.execute("INSERT INTO user (username, password, time_stamp) VALUES(?,?,?)", (username, password, current_time))
            con.commit()
            return 0, "You've successfully created your account!"
    elif username in response:     
        return 1,"Sorry, username already exists. Maybe try logging in?"


# Toy user interface
def main():
    """
        Description: 
            Main function which basically interface both login, and create account
    """
    # ADD AN EXCEPTION HANDLING
    action = input("Type '1' to log-in or type '2' to create account: ")
    try_again = 1

    # Login
    if action == '1':
        while try_again == 1:
            username = input("Please enter a username: ").lower() # normalize any username to lowercase
            password = input("Please enter a password: ")
            ip = input("Enter ip: ")
            try_again, response = login(username, password, ip)

            print(response)
    # Create account
    elif action == '2':
        while try_again == 1:
            username = input("Please enter a username: ").lower()
            password = input("Please enter a password: ")
            try_again, response = create(username, password)

            print(response)

if __name__ == "__main__":
    main()