import mysql.connector
conn = mysql.connector.connect(
    host="db01",
    user="admin",
    password="SuperSecret123",
    database="prod"
)
