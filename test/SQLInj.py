import sqlite3

conn = sqlite3.connect('example.db')
cursor = conn.cursor()

username = input("Enter username: ")
password = input("Enter password: ")

query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
results = cursor.fetchall()
print(results)
