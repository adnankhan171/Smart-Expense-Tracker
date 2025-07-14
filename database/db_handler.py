# Load/save user and expense data
import sqlite3
import bcrypt

DATABASE = "users.db"

def create_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL)
                   '''
                   )
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        # hash the passoword
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username,hashed_password.decode('utf-8')))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print(f"Error: Username '{username}' already exists.")
        return False
    finally:    
        conn.close()

def get_user(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username=?",(username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0] # return the hashed password
    return None


def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'),hashed_password.encode('utf-8'))



