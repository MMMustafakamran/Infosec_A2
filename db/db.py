"""
Database Management Module
Provides MySQL/MariaDB connection and user management functions for the secure chat system.
Uses PyMySQL for database connectivity.

Configuration via environment variables:
    DB_HOST: Database hostname (default: localhost)
    DB_USER: Database username (default: chatuser)
    DB_PASS: Database password (default: StrongPassword123!)
    DB_NAME: Database name (default: securechat)
"""
import os
import pymysql


def establish_database_connection():
    """
    Create and return a database connection using environment variables.
    
    Returns:
        pymysql.Connection object
    
    Raises:
        Exception: If connection fails
    """
    db_host = os.environ.get("DB_HOST", "localhost")
    db_user = os.environ.get("DB_USER", "chatuser")
    db_password = os.environ.get("DB_PASS", "StrongPassword123!")
    db_name = os.environ.get("DB_NAME", "securechat")
    
    print(f"Connecting to database: host={db_host}, user={db_user}, database={db_name}")
    
    try:
        connection = pymysql.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
        return connection
    except Exception as db_error:
        print(f"Database connection error: {repr(db_error)}")
        raise


def initialize_database_schema(connection=None):
    """
    Create the users table if it does not exist.
    
    Args:
        connection: Optional database connection. If None, a new connection
                   will be created and closed after use.
    """
    should_close = False
    if connection is None:
        connection = establish_database_connection()
        should_close = True
    
    try:
        with connection.cursor() as cursor:
            create_table_sql = """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) NOT NULL,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
            """
            cursor.execute(create_table_sql)
            connection.commit()
            print("Database schema initialized: users table created/verified")
    finally:
        if should_close:
            connection.close()


def insert_new_user(email: str, username: str, salt: bytes, password_hash: str) -> bool:
    """
    Insert a new user into the database.
    
    Args:
        email: User's email address
        username: Unique username
        salt: Random salt bytes (16 bytes)
        password_hash: Hexadecimal SHA-256 hash of salted password (64 chars)
    
    Returns:
        True if user was created successfully, False if username already exists
    """
    connection = establish_database_connection()
    try:
        with connection.cursor() as cursor:
            try:
                insert_sql = (
                    "INSERT INTO users (email, username, salt, pwd_hash) "
                    "VALUES (%s, %s, %s, %s)"
                )
                cursor.execute(insert_sql, (email, username, salt, password_hash))
                connection.commit()
                return True
            except pymysql.err.IntegrityError:
                # Username already exists (UNIQUE constraint violation)
                connection.rollback()
                return False
    finally:
        connection.close()


def retrieve_user_by_email(email: str):
    """
    Retrieve a user record from the database by email address.
    
    Args:
        email: User's email address to search for
    
    Returns:
        Dictionary containing user record (id, email, username, salt, pwd_hash, created_at)
        or None if no user found
    """
    connection = establish_database_connection()
    try:
        with connection.cursor() as cursor:
            select_sql = "SELECT * FROM users WHERE email = %s"
            cursor.execute(select_sql, (email,))
            user_record = cursor.fetchone()
            return user_record
    finally:
        connection.close()
