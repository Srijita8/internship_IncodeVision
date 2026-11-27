import sqlite3
import hashlib
import secrets
import hmac
import time
import getpass

DB_NAME = "users.db"
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 60
ITERATIONS = 600000

def connect_db():
    return sqlite3.connect(DB_NAME)

def create_table():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until REAL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        bytes.fromhex(salt),
        ITERATIONS
    ).hex()

def register():
    print("\n--- USER REGISTRATION ---")

    username = input("Enter username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    password = getpass.getpass("Create password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)

    conn = connect_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, salt, password_hash)
            VALUES (?, ?, ?)
        """, (username, salt, password_hash))

        conn.commit()
        print("Registration successful!")

    except sqlite3.IntegrityError:
        print("Username already exists.")

    finally:
        conn.close()

def login():
    print("\n USER LOGIN ")

    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ")

    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT salt, password_hash, failed_attempts, locked_until
        FROM users WHERE username = ?
    """, (username,))

    user = cursor.fetchone()

    if user is None:
        conn.close()
        print("Invalid username or password.")
        return

    salt, stored_hash, attempts, locked_until = user

   
    remaining = locked_until - time.time()

    if remaining > 0:
        conn.close()
        print(f"Account locked. Try again in {int(remaining) + 1} seconds.")
        return

    
    entered_hash = hash_password(password, salt)

    if hmac.compare_digest(entered_hash, stored_hash):

        cursor.execute("""
            UPDATE users
            SET failed_attempts = 0, locked_until = 0
            WHERE username = ?
        """, (username,))

        conn.commit()
        conn.close()

        print("Login successful! Welcome,", username)

    else:
        attempts += 1

        if attempts >= MAX_ATTEMPTS:
            locked_until = time.time() + LOCKOUT_TIME

            cursor.execute("""
                UPDATE users
                SET failed_attempts = 0, locked_until = ?
                WHERE username = ?
            """, (locked_until, username))

            print("Too many failed attempts!")
            print("Account locked for 60 seconds.")

        else:
            cursor.execute("""
                UPDATE users
                SET failed_attempts = ?
                WHERE username = ?
            """, (attempts, username))

            print("Invalid username or password.")
            print("Attempts remaining:", MAX_ATTEMPTS - attempts)

        conn.commit()
        conn.close()

def main():
    create_table()

    while True:
        print("\n")
        print("  SECURE LOGIN SYSTEM")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            register()

        elif choice == "2":
            login()

        elif choice == "3":
            print("Exiting secure login system.")
            break

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()